use super::*;
use crate::host::stream::{StreamItem, channel};
use crate::stream::StreamWindow;
use std::sync::atomic::{AtomicUsize, Ordering};
use xolotl_types::TaintSource;

struct CompletionDriver {
    calls: Arc<AtomicUsize>,
    taint: TaintSet,
    origin: CompletionOrigin,
}

struct ProtectedCacheRead {
    taint: TaintSet,
    malformed_record: bool,
}

impl StateRead for ProtectedCacheRead {
    type Read<'a> = core::future::Ready<StateResult<Option<TaintedValue>>>;

    fn read_tainted<'a>(&'a self, _path: &'a Path) -> Self::Read<'a> {
        core::future::ready(if self.malformed_record {
            Ok(Some(TaintedValue::new(Value::null(), self.taint.clone())))
        } else {
            Err(xolotl_state::StateFailure::new(
                StateError::Backend("read failed after observing a protected record".into()),
                self.taint.clone(),
            ))
        })
    }
}

#[tokio::test]
async fn cache_read_and_decode_failures_retain_observed_sources_in_output_and_fact()
-> anyhow::Result<()> {
    let observed = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://private/cache")?,
    });
    for malformed_record in [false, true] {
        let mut fixture = fixture(
            ReplayClass::IdempotentEffect,
            CompletionOrigin::CurrentAttempt,
        )?;
        fixture.plane.state = Backend::new().with_read(Arc::new(ProtectedCacheRead {
            taint: observed.clone(),
            malformed_record,
        }));
        let (sink, facts) = FactSink::in_memory();
        fixture.plane.facts = sink;
        let mut operation = op(fixture.handle, 7, Value::null());
        operation.output = OutputMode::Stream;
        operation.taint = TaintSet::author();
        let expected = operation.taint.clone().merged(&observed);
        let (sink, mut receiver) = channel(StreamWindow::default());
        let output = fixture
            .plane
            .execute_with_stream(
                &operation,
                InvocationOptions {
                    now_millis: 0,
                    record: false,
                },
                sink,
            )
            .await;
        ensure!(matches!(output.outcome, Outcome::Fail(_)));
        ensure!(output.taint == expected);
        ensure!(fixture.calls.load(Ordering::Acquire) == 0);
        let recorded = facts.facts_of(operation.process)?;
        ensure!(recorded.len() == 1 && recorded[0].taint == expected);
        let Some(StreamItem::End(end)) = receiver.recv().await else {
            bail!("cache failure omitted its stream terminal");
        };
        ensure!(end.taint == expected);
        ensure!(receiver.recv().await.is_none());
    }
    Ok(())
}

#[async_trait::async_trait]
impl Driver for CompletionDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if output != OutputMode::Stream {
            return Err(DriverError::UnsupportedOutput(output));
        }
        self.calls.fetch_add(1, Ordering::AcqRel);
        if self.origin == CompletionOrigin::CurrentAttempt {
            ctx.emit_tainted(TaintedValue::new(Value::integer(1), self.taint.clone()))
                .await?;
        }
        Ok(DriverOutput::new(Outcome::Done(Value::integer(2)))
            .with_taint(self.taint.clone())
            .with_origin(self.origin))
    }
}

struct Fixture {
    plane: DataPlane,
    handle: HandleId,
    calls: Arc<AtomicUsize>,
    output_taint: TaintSet,
}

fn fixture(replay: ReplayClass, origin: CompletionOrigin) -> anyhow::Result<Fixture> {
    let calls = Arc::new(AtomicUsize::new(0));
    let output_taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://private/stream-output")?,
    });
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, replay, SUPPORTS_STREAM),
        Arc::new(CompletionDriver {
            calls: calls.clone(),
            taint: output_taint.clone(),
            origin,
        }),
    );
    let mut handles = HandleTable::new();
    let handle = handles.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let plane = DataPlane::new(
        Arc::new(RwLock::new(handles)),
        FactSink::in_memory().0,
        test_state(),
    );
    Ok(Fixture {
        plane,
        handle,
        calls,
        output_taint,
    })
}

#[tokio::test]
async fn cached_stream_completion_retains_provenance_without_reexecuting_the_driver()
-> anyhow::Result<()> {
    let fixture = fixture(
        ReplayClass::IdempotentEffect,
        CompletionOrigin::CurrentAttempt,
    )?;
    let mut original = op(
        fixture.handle,
        7,
        Value::map(BTreeMap::from([(
            "_idem_key".into(),
            Value::string("one-streamed-operation".into()),
        )])),
    );
    original.output = OutputMode::Stream;
    original.taint = TaintSet::of(TaintSource::ModelOutput);
    let mut retry = original.clone();
    retry.id = original.id.retry().context("retry identity exhausted")?;
    retry.taint = TaintSet::author();
    let cached_taint = fixture.output_taint.clone().merged(&original.taint);
    for (operation, expected_origin) in [
        (&original, CompletionOrigin::CurrentAttempt),
        (&retry, CompletionOrigin::CachedOutcome),
    ] {
        let expected_output_taint = cached_taint.clone().merged(&operation.taint);
        let expected_terminal_taint = operation.taint.clone().merged(&expected_output_taint);
        let (sink, mut receiver) = channel(StreamWindow::default());
        let output = fixture
            .plane
            .execute_with_stream(
                operation,
                InvocationOptions {
                    now_millis: 0,
                    record: false,
                },
                sink,
            )
            .await;
        ensure!(output.origin == expected_origin);
        ensure!(output.taint == expected_output_taint);
        if expected_origin == CompletionOrigin::CurrentAttempt {
            ensure!(output.outcome == Outcome::Done(Value::integer(2)));
            let Some(StreamItem::Chunk(chunk)) = receiver.recv().await else {
                bail!("first execution omitted its chunk");
            };
            let expected_chunk_taint = fixture.output_taint.clone().merged(&operation.taint);
            ensure!(chunk.value == Value::integer(1));
            ensure!(chunk.taint == expected_chunk_taint);
            drop(chunk);
        } else {
            ensure!(output.outcome == Outcome::Done(Value::integer(2)));
        }
        let Some(StreamItem::End(end)) = receiver.recv().await else {
            bail!("completion must follow the live chunks without replaying historical chunks");
        };
        ensure!(end.outcome == Ok(()));
        ensure!(end.origin == expected_origin);
        ensure!(end.taint == expected_terminal_taint);
        ensure!(receiver.recv().await.is_none());
    }
    ensure!(fixture.calls.load(Ordering::Acquire) == 1);
    Ok(())
}

#[tokio::test]
async fn driver_completion_origin_survives_data_plane_output_projection() -> anyhow::Result<()> {
    let fixture = fixture(ReplayClass::Deterministic, CompletionOrigin::CachedOutcome)?;
    let mut operation = op(fixture.handle, 7, Value::null());
    operation.output = OutputMode::Stream;
    let (sink, mut receiver) = channel(StreamWindow::default());
    let output = fixture
        .plane
        .execute_with_stream(
            &operation,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
            sink,
        )
        .await;
    ensure!(fixture.calls.load(Ordering::Acquire) == 1);
    ensure!(output.outcome == Outcome::Done(Value::integer(2)));
    ensure!(output.origin == CompletionOrigin::CachedOutcome);
    let Some(StreamItem::End(end)) = receiver.recv().await else {
        bail!("cached driver outcome must not fabricate historical chunks");
    };
    ensure!(end.origin == output.origin && end.taint == fixture.output_taint);
    ensure!(receiver.recv().await.is_none());
    Ok(())
}

#[tokio::test]
async fn rejected_chunk_keeps_its_provenance_in_the_driver_failure() -> anyhow::Result<()> {
    let fixture = fixture(ReplayClass::Deterministic, CompletionOrigin::CurrentAttempt)?;
    let mut operation = op(fixture.handle, 7, Value::null());
    operation.output = OutputMode::Stream;
    operation.taint = TaintSet::author();
    let (sink, receiver) = channel(StreamWindow::default());
    drop(receiver);
    let output = fixture
        .plane
        .execute_with_stream(
            &operation,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
            sink,
        )
        .await;
    ensure!(
        matches!(output.outcome, Outcome::Fail(Failure::HandlerError { ref kind, .. }) if kind == "stream")
    );
    ensure!(output.taint == fixture.output_taint.merged(&operation.taint));
    ensure!(fixture.calls.load(Ordering::Acquire) == 1);
    Ok(())
}
