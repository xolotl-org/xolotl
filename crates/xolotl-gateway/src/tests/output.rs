use super::{TEST_TOKEN, identity_profile, schema_type};
use crate::*;
use anyhow::{Context as _, bail, ensure};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_types::{CompletionOrigin, MethodId, Purity, TaintSource, TaintedValue};

mod completion;

struct StreamingDriver {
    chunks: Vec<Value>,
    chunk_taint: TaintSet,
    completion: DriverOutput,
    calls: AtomicUsize,
    emitted: AtomicUsize,
    live: Arc<AtomicUsize>,
    ignore_rejection: bool,
    wait_after_output: bool,
}

impl StreamingDriver {
    fn new(chunks: Vec<Value>) -> Self {
        Self {
            chunks,
            chunk_taint: TaintSet::of(TaintSource::ModelOutput),
            completion: DriverOutput::new(Outcome::Done(Value::from("complete"))).with_taint(
                TaintSet::of(TaintSource::Inbound {
                    source: "driver".into(),
                    channel: "final".into(),
                }),
            ),
            calls: AtomicUsize::new(0),
            emitted: AtomicUsize::new(0),
            live: Arc::new(AtomicUsize::new(0)),
            ignore_rejection: false,
            wait_after_output: false,
        }
    }
}

struct LiveCall(Arc<AtomicUsize>);

impl Drop for LiveCall {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

#[async_trait::async_trait]
impl Driver for StreamingDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.live.fetch_add(1, Ordering::AcqRel);
        let _live = LiveCall(self.live.clone());
        for value in &self.chunks {
            let result = context
                .emit_tainted(TaintedValue::new(value.clone(), self.chunk_taint.clone()))
                .await;
            match result {
                Ok(()) => {
                    self.emitted.fetch_add(1, Ordering::AcqRel);
                }
                Err(error) if !self.ignore_rejection => return Err(error.into()),
                Err(_) => {}
            }
        }
        if self.wait_after_output {
            std::future::pending::<()>().await;
        }
        Ok(self.completion.clone())
    }
}

struct Fixture {
    gateway: GatewayRuntime,
    session: GatewaySession,
    driver: Arc<StreamingDriver>,
}

impl Fixture {
    async fn new(driver: StreamingDriver, purity: Purity) -> anyhow::Result<Self> {
        Self::with_limits(driver, purity, GatewayLimitProfile::default()).await
    }

    async fn with_limits(
        driver: StreamingDriver,
        purity: Purity,
        limits: GatewayLimitProfile,
    ) -> anyhow::Result<Self> {
        Self::with_boot(Arc::new(Bootstrap::in_memory()), driver, purity, limits).await
    }

    async fn with_boot(
        boot: Arc<Bootstrap>,
        driver: StreamingDriver,
        purity: Purity,
        limits: GatewayLimitProfile,
    ) -> anyhow::Result<Self> {
        let driver = Arc::new(driver);
        let target = boot.register_effect(
            "effect://test/output",
            &[MethodSpec::new(
                "invoke",
                purity,
                MethodSpec::STREAM_ASYNC | MethodSpec::SINK_ASYNC,
            )],
            driver.clone(),
        )?;
        let profile = identity_profile()?
            .with_limits(limits)
            .with_surface(
                GatewaySurface::effect_invoke("output", target)
                    .with_schema(None, Some(schema_type("string")))
                    .with_output_stream_schema(schema_type("integer")),
            )
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["output"],
                ["perform://effect/test/output"],
            ));
        let gateway = GatewayRuntime::new(boot, profile)?;
        let session = gateway
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await?;
        Ok(Self {
            gateway,
            session,
            driver,
        })
    }

    async fn open(&self, submission: GatewaySubmission) -> anyhow::Result<GatewayOutputStream> {
        Ok(self
            .gateway
            .submit_output_stream(&self.session, submission, window())
            .await?)
    }

    async fn complete(
        &self,
        submission: GatewaySubmission,
    ) -> anyhow::Result<(usize, GatewaySubmitResult)> {
        if submission.requested_output() == OutputMode::Stream {
            let mut stream = self.open(submission).await?;
            finish(&mut stream).await
        } else {
            Ok((0, self.gateway.submit(&self.session, submission).await?))
        }
    }
}

fn window() -> StreamWindow {
    StreamWindow {
        max_chunks: NonZeroUsize::MIN,
        max_inline_bytes: NonZeroUsize::MIN.saturating_add(4095),
    }
}

fn submission() -> GatewaySubmission {
    GatewaySubmission::direct_input("output", Value::null())
        .with_requested_output(OutputMode::Stream)
}

async fn next(stream: &mut GatewayOutputStream) -> anyhow::Result<GatewayOutputEvent> {
    Ok(
        tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await?
            .context("missing output event")??,
    )
}

async fn finish(stream: &mut GatewayOutputStream) -> anyhow::Result<(usize, GatewaySubmitResult)> {
    let mut chunks = 0;
    loop {
        match next(stream).await? {
            GatewayOutputEvent::Chunk(chunk) => {
                chunks += 1;
                drop(chunk);
            }
            GatewayOutputEvent::Complete(completion) => {
                ensure!(
                    stream.next().await.is_none(),
                    "stream emitted a second terminal"
                );
                return Ok((chunks, completion));
            }
        }
    }
}

#[tokio::test]
async fn borrowed_chunks_bound_execution_and_precede_request_completion() -> anyhow::Result<()> {
    let fixture = Fixture::new(
        StreamingDriver::new(vec![
            Value::integer(0),
            Value::integer(1),
            Value::integer(2),
        ]),
        Purity::Pure,
    )
    .await?;
    let mut stream = fixture.open(submission()).await?;
    ensure!(fixture.driver.calls.load(Ordering::Acquire) == 0);
    ensure!(stream.accepted().surface_id == "output");
    let descriptor = fixture.gateway.describe(&fixture.session)?;
    ensure!(descriptor.surfaces[0].output_stream_schema == Some(schema_type("integer")));

    for index in 0..3 {
        let GatewayOutputEvent::Chunk(chunk) = next(&mut stream).await? else {
            bail!("request completed before its chunks");
        };
        ensure!(chunk.value == Value::integer(index));
        ensure!(chunk.taint.sources().contains(&TaintSource::ModelOutput));
        ensure!(fixture.driver.emitted.load(Ordering::Acquire) == index as usize + 1);
        let mut context = Context::from_waker(Waker::noop());
        ensure!(matches!(stream.poll_next(&mut context), Poll::Pending));
        ensure!(fixture.driver.emitted.load(Ordering::Acquire) == index as usize + 1);
        ensure!(fixture.gateway.requests.inner.lock().global_running == 1);
        drop(chunk);
    }
    let GatewayOutputEvent::Complete(completion) = next(&mut stream).await? else {
        bail!("expected request completion");
    };
    ensure!(completion.output.outcome == Outcome::Done(Value::from("complete")));
    ensure!(completion.origin == CompletionOrigin::CurrentAttempt);
    ensure!(completion.output.taint.sources().iter().any(
        |source| matches!(source, TaintSource::Inbound { channel, .. } if channel == "final")
    ));
    ensure!(fixture.gateway.requests.inner.lock().global_running == 1);
    ensure!(stream.next().await.is_none());
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn ignored_chunk_schema_rejection_still_fails_the_request() -> anyhow::Result<()> {
    let mut driver = StreamingDriver::new(vec![Value::from("invalid"), Value::integer(1)]);
    driver.ignore_rejection = true;
    let rejected_taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/chunk")?,
    });
    driver.chunk_taint.union(&rejected_taint);
    let fixture = Fixture::new(driver, Purity::Effectful).await?;
    let request = submission().with_options(SubmitOptions {
        idempotency_key: Some("rejected-output-once".into()),
        ..SubmitOptions::default()
    });
    let mut stream = fixture.open(request.clone()).await?;
    let (chunks, completion) = finish(&mut stream).await?;
    ensure!(chunks == 0, "a chunk escaped the failed output boundary");
    ensure!(fixture.driver.emitted.load(Ordering::Acquire) == 0);
    ensure!(matches!(
        &completion.output.outcome,
        Outcome::Fail(Failure::Custom { kind, .. }) if kind == "gateway_output_stream_schema"
    ));
    ensure!(
        completion
            .output
            .taint
            .sources()
            .contains(&TaintSource::ModelOutput)
    );
    ensure!(completion.output.taint.has_protected());
    let mut replay = fixture.open(request).await?;
    let (chunks, replayed) = finish(&mut replay).await?;
    ensure!(chunks == 0);
    ensure!(replayed.output == completion.output);
    ensure!(replayed.origin == CompletionOrigin::CachedOutcome);
    ensure!(fixture.driver.calls.load(Ordering::Acquire) == 1);
    Ok(())
}

#[tokio::test]
async fn cancellation_before_first_poll_preserves_only_known_input_provenance() -> anyhow::Result<()>
{
    let fixture = Fixture::new(StreamingDriver::new(vec![Value::integer(1)]), Purity::Pure).await?;
    let mut stream = fixture.open(submission()).await?;
    ensure!(fixture.gateway.cancel(
        &fixture.session,
        GatewayCancelRequest {
            submission_id: stream.accepted().submission_id.clone(),
            trace_root: stream.accepted().trace_root.clone(),
            reason: None,
        },
    )?);
    let (chunks, completion) = finish(&mut stream).await?;
    ensure!(chunks == 0);
    ensure!(completion.output.outcome == Outcome::Fail(Failure::Cancelled));
    ensure!(completion.origin == CompletionOrigin::CurrentAttempt);
    ensure!(
        completion.output.taint.sources().iter().any(|source| {
            matches!(source, TaintSource::Inbound { channel, .. } if channel == "submit")
        }),
        "cancellation lost admitted input provenance"
    );
    ensure!(
        !completion.output.taint.sources().iter().any(|source| {
            matches!(source, TaintSource::Inbound { channel, .. } if channel == "final")
        }),
        "cancellation invented an unexecuted driver's provenance"
    );
    ensure!(fixture.driver.calls.load(Ordering::Acquire) == 0);
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn gateway_replay_returns_complete_provenance_without_historical_chunks() -> anyhow::Result<()>
{
    let fixture = Fixture::new(
        StreamingDriver::new(vec![Value::integer(1)]),
        Purity::Effectful,
    )
    .await?;
    let request = submission().with_options(SubmitOptions {
        idempotency_key: Some("output-once".into()),
        ..SubmitOptions::default()
    });
    let mut first = fixture.open(request.clone()).await?;
    let (count, first_completion) = finish(&mut first).await?;
    ensure!(count == 1);
    let mut replay = fixture.open(request).await?;
    ensure!(replay.accepted() == first.accepted());
    let (count, completion) = finish(&mut replay).await?;
    ensure!(count == 0);
    ensure!(completion.accepted == first_completion.accepted);
    ensure!(completion.output == first_completion.output);
    ensure!(first_completion.origin == CompletionOrigin::CurrentAttempt);
    ensure!(completion.origin == CompletionOrigin::CachedOutcome);
    ensure!(fixture.driver.calls.load(Ordering::Acquire) == 1);
    Ok(())
}

#[tokio::test]
async fn submission_modes_preserve_protected_success_and_failure_on_replay() -> anyhow::Result<()> {
    let protected = TaintSource::Protected {
        path: Path::parse("state://vault/result")?,
    };
    for mode in [OutputMode::Unary, OutputMode::Stream, OutputMode::SinkOnly] {
        for failure in [false, true] {
            let mut driver = StreamingDriver::new(if mode == OutputMode::Stream {
                vec![Value::integer(1)]
            } else {
                Vec::new()
            });
            driver.chunk_taint.add(protected.clone());
            driver.completion.taint.add(protected.clone());
            if failure {
                driver.completion.outcome = Outcome::Fail(Failure::InvalidInput {
                    reason: "protected diagnostic".into(),
                });
            }
            let expected = if mode == OutputMode::SinkOnly && !failure {
                Outcome::Done(Value::null())
            } else {
                driver.completion.outcome.clone()
            };
            let fixture = Fixture::new(driver, Purity::Effectful).await?;
            let request = submission()
                .with_requested_output(mode)
                .with_options(SubmitOptions {
                    idempotency_key: Some("protected-result-once".into()),
                    ..SubmitOptions::default()
                });
            let (chunks, first) = fixture.complete(request.clone()).await?;
            ensure!(chunks == usize::from(mode == OutputMode::Stream));
            ensure!(first.output.outcome == expected);
            ensure!(first.origin == CompletionOrigin::CurrentAttempt);
            ensure!(first.output.taint.sources().contains(&protected));
            ensure!(first.output.taint.sources().iter().any(|source| {
                matches!(source, TaintSource::Inbound { channel, .. } if channel == "submit")
            }));
            ensure!(first.output.taint.sources().iter().any(|source| {
                matches!(source, TaintSource::Inbound { channel, .. } if channel == "final")
            }));

            let (chunks, replayed) = fixture.complete(request).await?;
            ensure!(chunks == 0, "replay emitted historical output");
            ensure!(replayed.accepted == first.accepted);
            ensure!(replayed.output == first.output);
            ensure!(replayed.origin == CompletionOrigin::CachedOutcome);
            ensure!(fixture.driver.calls.load(Ordering::Acquire) == 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn final_schema_rejection_keeps_protected_provenance_on_replay() -> anyhow::Result<()> {
    for mode in [OutputMode::Unary, OutputMode::Stream] {
        let mut driver = StreamingDriver::new(Vec::new());
        driver.completion = DriverOutput::new(Outcome::Done(Value::integer(7))).with_taint(
            TaintSet::of(TaintSource::Protected {
                path: Path::parse("state://vault/invalid-output")?,
            }),
        );
        let fixture = Fixture::new(driver, Purity::Effectful).await?;
        let request = submission()
            .with_requested_output(mode)
            .with_options(SubmitOptions {
                idempotency_key: Some("invalid-final-output-once".into()),
                ..SubmitOptions::default()
            });
        let (chunks, first) = fixture.complete(request.clone()).await?;
        ensure!(chunks == 0);
        ensure!(matches!(
            &first.output.outcome,
            Outcome::Fail(Failure::Custom { kind, .. }) if kind == "gateway_output_schema"
        ));
        ensure!(first.output.taint.has_protected());
        ensure!(first.origin == CompletionOrigin::CurrentAttempt);
        let (chunks, replayed) = fixture.complete(request).await?;
        ensure!(chunks == 0);
        ensure!(replayed.output == first.output);
        ensure!(replayed.origin == CompletionOrigin::CachedOutcome);
        ensure!(fixture.driver.calls.load(Ordering::Acquire) == 1);
    }
    Ok(())
}

#[tokio::test]
async fn kernel_replay_preserves_provenance_within_a_current_gateway_attempt() -> anyhow::Result<()>
{
    let fixture = Fixture::new(
        StreamingDriver::new(vec![Value::integer(1)]),
        Purity::Idempotent,
    )
    .await?;
    let request = GatewaySubmission::direct_input(
        "output",
        Value::map(BTreeMap::from([(
            "_idem_key".into(),
            Value::from("kernel-output-once"),
        )])),
    )
    .with_requested_output(OutputMode::Stream);
    let mut first = fixture.open(request.clone()).await?;
    let (count, first_completion) = finish(&mut first).await?;
    ensure!(count == 1);
    let mut replay = fixture.open(request).await?;
    ensure!(replay.accepted() != first.accepted());
    let (count, completion) = finish(&mut replay).await?;
    ensure!(count == 0);
    ensure!(completion.origin == CompletionOrigin::CurrentAttempt);
    ensure!(completion.output == first_completion.output);
    ensure!(fixture.driver.calls.load(Ordering::Acquire) == 1);
    Ok(())
}

#[tokio::test]
async fn cancellation_keeps_resident_output_reserved_until_owner_drop() -> anyhow::Result<()> {
    let mut driver = StreamingDriver::new(vec![Value::integer(1)]);
    driver.wait_after_output = true;
    let fixture = Fixture::with_limits(
        driver,
        Purity::Pure,
        GatewayLimitProfile {
            max_in_flight_requests: 1,
            ..GatewayLimitProfile::default()
        },
    )
    .await?;
    let mut stream = fixture.open(submission()).await?;
    let GatewayOutputEvent::Chunk(chunk) = next(&mut stream).await? else {
        bail!("missing output chunk");
    };
    drop(chunk);
    let accepted = stream.accepted();
    ensure!(fixture.gateway.cancel(
        &fixture.session,
        GatewayCancelRequest {
            submission_id: accepted.submission_id.clone(),
            trace_root: accepted.trace_root.clone(),
            reason: None,
        },
    )?);
    ensure!(fixture.gateway.requests.inner.lock().global_running == 1);
    ensure!(matches!(
        fixture
            .gateway
            .submit_output_stream(&fixture.session, submission(), window())
            .await,
        Err(GatewayError::LimitExceeded(_))
    ));
    ensure!(fixture.driver.live.load(Ordering::Acquire) == 1);
    drop(stream);
    ensure!(fixture.driver.live.load(Ordering::Acquire) == 0);
    let requests = fixture.gateway.requests.inner.lock();
    ensure!(requests.global_running == 0);
    ensure!(requests.budget_running.stream_items == 0);
    ensure!(requests.budget_running.bytes_out == 0);
    Ok(())
}

#[tokio::test]
async fn borrowed_chunks_keep_capacity_after_response_drop() -> anyhow::Result<()> {
    for transfer_to_caller in [false, true] {
        let mut driver = StreamingDriver::new(vec![Value::integer(1)]);
        driver.wait_after_output = true;
        let fixture = Fixture::with_limits(
            driver,
            Purity::Pure,
            GatewayLimitProfile {
                budget: GatewayBudgetProfile {
                    max_bytes_out: Some(4096),
                    max_stream_items: Some(1),
                    ..GatewayBudgetProfile::default()
                },
                ..GatewayLimitProfile::default()
            },
        )
        .await?;
        let mut stream = fixture.open(submission()).await?;
        let GatewayOutputEvent::Chunk(chunk) = next(&mut stream).await? else {
            bail!("missing output chunk");
        };
        let process = fixture.gateway.requests.inner.lock().entries
            [&stream.accepted().submission_id]
            .request_process;
        drop(stream);
        ensure!(fixture.driver.live.load(Ordering::Acquire) == 0);
        ensure!(
            fixture.gateway.boot.kernel.processes.status(process) == Some(ProcessStatus::Cancelled)
        );
        {
            let requests = fixture.gateway.requests.inner.lock();
            ensure!(requests.global_running == 1);
            ensure!(requests.budget_running.stream_items == 1);
            ensure!(requests.budget_running.bytes_out == 4096);
        }
        ensure!(matches!(
            fixture
                .gateway
                .submit_output_stream(&fixture.session, submission(), window())
                .await,
            Err(GatewayError::LimitExceeded(_))
        ));
        let caller_owned = if transfer_to_caller {
            Some(chunk.into_value())
        } else {
            drop(chunk);
            None
        };
        {
            let requests = fixture.gateway.requests.inner.lock();
            ensure!(requests.global_running == 0);
            ensure!(requests.budget_running == GatewayBudgetCharge::default());
        }
        let retry = fixture.open(submission()).await?;
        if let Some(value) = caller_owned {
            ensure!(value.value == Value::integer(1));
        }
        drop(retry);
    }
    Ok(())
}

#[tokio::test]
async fn interruption_discards_queued_chunks_and_keeps_borrowed_capacity() -> anyhow::Result<()> {
    for expire in [false, true] {
        let mut driver = StreamingDriver::new(vec![
            Value::integer(0),
            Value::integer(1),
            Value::integer(2),
        ]);
        driver.wait_after_output = true;
        let fixture = Fixture::new(driver, Purity::Pure).await?;
        let deadline = now_millis().saturating_add(60_000);
        let request = submission().with_options(SubmitOptions {
            deadline_ms: Some(u64::try_from(deadline)?),
            idempotency_key: Some("interrupted-output".into()),
            ..SubmitOptions::default()
        });
        let mut stream = fixture
            .gateway
            .submit_output_stream(
                &fixture.session,
                request.clone(),
                StreamWindow {
                    max_chunks: NonZeroUsize::MIN.saturating_add(1),
                    ..window()
                },
            )
            .await?;
        let GatewayOutputEvent::Chunk(chunk) = next(&mut stream).await? else {
            bail!("missing output chunk");
        };
        ensure!(chunk.value == Value::integer(0));
        ensure!(fixture.driver.emitted.load(Ordering::Acquire) == 2);
        let failure = if expire {
            let deadline = fixture.gateway.requests.inner.lock().entries
                [&stream.accepted().submission_id]
                .deadline
                .context("missing deadline")?;
            let expired = fixture.gateway.requests.expire_deadlines(deadline);
            ensure!(expired.len() == 1);
            fixture
                .gateway
                .boot
                .cancel_process(expired[0].request_process)?;
            Failure::Timeout
        } else {
            ensure!(fixture.gateway.cancel(
                &fixture.session,
                GatewayCancelRequest {
                    submission_id: stream.accepted().submission_id.clone(),
                    trace_root: stream.accepted().trace_root.clone(),
                    reason: None,
                },
            )?);
            Failure::Cancelled
        };
        let (remaining_chunks, completion) = finish(&mut stream).await?;
        ensure!(remaining_chunks == 0, "queued output escaped interruption");
        ensure!(completion.output.outcome == Outcome::Fail(failure));
        ensure!(fixture.driver.emitted.load(Ordering::Acquire) == 2);
        ensure!(fixture.driver.live.load(Ordering::Acquire) == 0);
        let (replayed_chunks, replayed) = fixture.complete(request).await?;
        ensure!(replayed_chunks == 0);
        ensure!(replayed.output == completion.output);
        ensure!(replayed.origin == CompletionOrigin::CachedOutcome);
        ensure!(fixture.driver.calls.load(Ordering::Acquire) == 1);
        drop(stream);
        {
            let requests = fixture.gateway.requests.inner.lock();
            ensure!(requests.global_running == 1);
            ensure!(requests.budget_running.stream_items == 2);
        }
        drop(chunk);
        let requests = fixture.gateway.requests.inner.lock();
        ensure!(requests.global_running == 0);
        ensure!(requests.budget_running == GatewayBudgetCharge::default());
    }
    Ok(())
}

#[tokio::test]
async fn finished_requests_preserve_queued_output_after_the_task_deadline() -> anyhow::Result<()> {
    for fail_schema in [false, true] {
        let mut values = vec![Value::integer(0), Value::integer(1)];
        if fail_schema {
            values.push(Value::from("invalid"));
        }
        let fixture = Fixture::new(StreamingDriver::new(values), Purity::Pure).await?;
        let mut stream = fixture
            .gateway
            .submit_output_stream(
                &fixture.session,
                submission(),
                StreamWindow {
                    max_chunks: NonZeroUsize::MIN.saturating_add(2),
                    ..window()
                },
            )
            .await?;
        let GatewayOutputEvent::Chunk(chunk) = next(&mut stream).await? else {
            bail!("missing output chunk");
        };
        drop(chunk);
        {
            let mut requests = fixture.gateway.requests.inner.lock();
            let entry = requests
                .entries
                .get_mut(&stream.accepted().submission_id)
                .context("missing completed request")?;
            ensure!(
                entry.state
                    == if fail_schema {
                        GatewayRequestState::Failed
                    } else {
                        GatewayRequestState::Completed
                    }
            );
            entry.deadline = Some(Instant::now());
        }
        ensure!(
            fixture
                .gateway
                .requests
                .expire_deadlines(Instant::now())
                .is_empty()
        );
        let (remaining_chunks, completion) = finish(&mut stream).await?;
        ensure!(
            remaining_chunks == 1,
            "a finished request lost valid queued output"
        );
        if fail_schema {
            ensure!(matches!(
                completion.output.outcome,
                Outcome::Fail(Failure::Custom { kind, .. }) if kind == "gateway_output_stream_schema"
            ));
        } else {
            ensure!(completion.output.outcome == Outcome::Done(Value::from("complete")));
        }
    }
    Ok(())
}

#[tokio::test]
async fn output_window_is_reserved_before_request_acceptance() -> anyhow::Result<()> {
    let fixture = Fixture::with_limits(
        StreamingDriver::new(vec![Value::integer(1)]),
        Purity::Pure,
        GatewayLimitProfile {
            budget: GatewayBudgetProfile {
                max_bytes_out: Some(4095),
                ..GatewayBudgetProfile::default()
            },
            ..GatewayLimitProfile::default()
        },
    )
    .await?;
    ensure!(matches!(
        fixture
            .gateway
            .submit_output_stream(&fixture.session, submission(), window())
            .await,
        Err(GatewayError::LimitExceeded(_))
    ));
    ensure!(fixture.driver.calls.load(Ordering::Acquire) == 0);
    ensure!(fixture.gateway.requests.inner.lock().entries.is_empty());
    let invalid_window = StreamWindow {
        max_chunks: NonZeroUsize::MAX,
        ..window()
    };
    ensure!(matches!(
        fixture
            .gateway
            .submit_output_stream(&fixture.session, submission(), invalid_window)
            .await,
        Err(GatewayError::Rejected(_))
    ));
    Ok(())
}

#[tokio::test]
async fn receipt_is_consumed_before_stream_acceptance_but_not_for_a_wrong_output_port()
-> anyhow::Result<()> {
    let mut fixture =
        Fixture::new(StreamingDriver::new(vec![Value::integer(1)]), Purity::Pure).await?;
    let directory = tempfile::tempdir()?;
    let files = xolotl_storage_fs::FileObjectStore::open(directory.path())?;
    fixture.gateway = fixture.gateway.with_object_store(files.into_object_store());
    let ticket = fixture
        .gateway
        .issue_object_upload_ticket(
            &fixture.session,
            IssueObjectUploadTicketRequest {
                surface_id: "output".into(),
                submission_token: None,
                modality: GatewayModality::Bytes,
                expected_size: None,
                expected_digest: None,
                allowed_media_types: Vec::new(),
                expires_in_ms: Some(60_000),
                single_use: true,
            },
        )
        .await?;
    let mut upload = fixture
        .gateway
        .begin_object_upload(
            &fixture.session,
            BeginObjectUploadRequest {
                ticket_id: ticket.ticket_id().into(),
                media_type: None,
                submission_token: None,
            },
        )
        .await?;
    upload.write(b"input").await?;
    let receipt = upload.commit(GatewayObjectKind::Blob).await?;
    let request = GatewaySubmission::direct_input("output", receipt.item)
        .with_provenance(receipt.provenance)
        .with_requested_output(OutputMode::Stream);
    ensure!(matches!(
        fixture
            .gateway
            .submit(&fixture.session, request.clone())
            .await,
        Err(GatewayError::Rejected(_))
    ));
    ensure!(matches!(
        fixture
            .gateway
            .submit_output_stream(
                &fixture.session,
                request.clone().with_requested_output(OutputMode::Unary),
                window(),
            )
            .await,
        Err(GatewayError::Rejected(_))
    ));
    let mut stream = fixture.open(request.clone()).await?;
    ensure!(fixture.driver.calls.load(Ordering::Acquire) == 0);
    ensure!(matches!(
        fixture
            .gateway
            .submit_output_stream(&fixture.session, request, window())
            .await,
        Err(GatewayError::Rejected(_))
    ));
    let GatewayOutputEvent::Chunk(chunk) = next(&mut stream).await? else {
        bail!("missing output chunk");
    };
    ensure!(chunk.taint.sources().iter().any(
        |source| matches!(source, TaintSource::Inbound { channel, .. } if channel == "object-upload")
    ));
    drop(chunk);
    let (_, completion) = finish(&mut stream).await?;
    ensure!(completion.output.outcome.is_success());
    Ok(())
}
