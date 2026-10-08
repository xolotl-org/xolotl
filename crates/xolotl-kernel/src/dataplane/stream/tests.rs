use super::*;
use crate::driver::StreamSendError;
use crate::fact::FactSink;
use crate::handle::HandleTable;
use crate::host::stream::ChannelSink;
use crate::stream::{StreamError, StreamSendRequest, StreamSink};
use anyhow::ensure;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use xolotl_state::{Backend, InMemoryBackend};
use xolotl_types::{IdentityRef, ProcessId, TaintSource, TaintedValue};

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn data_plane(state: Backend) -> DataPlane {
    let (facts, _) = FactSink::in_memory();
    DataPlane::new(HandleTable::new(), facts, state)
}

fn one_chunk_channel() -> (Arc<ChannelSink>, StreamReceiver) {
    channel(StreamWindow {
        max_chunks: NonZeroUsize::MIN,
        ..StreamWindow::default()
    })
}

fn context(sink: DynStreamSink, taint: TaintSet) -> DriverContext {
    DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
        .with_taint(taint)
        .with_stream_sink(sink)
}

async fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

async fn driver_stream_result(
    _dp: &DataPlane,
    call: impl Future<Output = Result<DriverOutput, DriverError>>,
    sink: DynStreamSink,
    taint: &TaintSet,
) -> InvocationResult {
    let output = async {
        match call.await {
            Ok(output) => output,
            Err(error) => {
                let error = crate::dataplane::driver_err_to_failure(error);
                DriverOutput::new(Outcome::Fail(error.failure)).with_taint(error.taint)
            }
        }
    };
    let operation = xolotl_types::OperationId::new(
        ProcessId::new(1),
        xolotl_types::ExecutionId::FIRST,
        xolotl_types::InvocationId::new(1),
        xolotl_types::CausalPosition::new(0),
        0,
    );
    run_streamed_invocation(
        output.map(InvocationResult::new),
        sink,
        operation,
        taint,
        None,
        &AtomicBool::new(false),
    )
    .await
}

async fn driver_stream(
    dp: &DataPlane,
    call: impl Future<Output = Result<DriverOutput, DriverError>>,
    sink: DynStreamSink,
    taint: &TaintSet,
) -> anyhow::Result<DriverOutput> {
    let result = driver_stream_result(dp, call, sink, taint).await;
    ensure!(result.completion_error.is_none());
    Ok(result.output)
}

struct TerminalProbe {
    finish: Poll<Result<(), StreamError>>,
    closed: Arc<parking_lot::Mutex<Option<StreamEnd>>>,
}

impl StreamSink for TerminalProbe {
    fn poll_send(
        &self,
        _: &mut Context<'_>,
        request: &mut StreamSendRequest,
    ) -> Poll<Result<(), StreamSendError<TaintedValue>>> {
        Poll::Ready(match request.take_chunk() {
            Some(value) => Err(StreamSendError::Closed(value)),
            None => Ok(()),
        })
    }

    fn cancel_send(&self, _: &mut StreamSendRequest) {}

    fn poll_finish(
        &self,
        _: &mut Context<'_>,
        end: &mut Option<StreamEnd>,
    ) -> Poll<Result<(), StreamError>> {
        assert!(end.is_some());
        if matches!(self.finish, Poll::Ready(Ok(()))) {
            *self.closed.lock() = end.take();
        }
        self.finish.clone()
    }

    fn close(&self, end: StreamEnd) {
        assert!(!matches!(self.finish, Poll::Ready(Ok(()))));
        self.closed.lock().get_or_insert(end);
    }

    fn poll_closed(&self, _: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

#[tokio::test]
async fn rejected_stream_terminal_preserves_driver_result_and_reports_completion_error()
-> anyhow::Result<()> {
    let closed = Arc::new(parking_lot::Mutex::new(None));
    let sink: DynStreamSink = Arc::new(TerminalProbe {
        finish: Poll::Ready(Err(StreamError::Failed(Failure::Timeout))),
        closed: closed.clone(),
    });
    let operation = xolotl_types::OperationId::new(
        ProcessId::new(1),
        xolotl_types::ExecutionId::FIRST,
        xolotl_types::InvocationId::new(1),
        xolotl_types::CausalPosition::new(0),
        0,
    );
    let original = DriverOutput::new(Outcome::Done(Value::integer(7)));
    let result = run_streamed_invocation(
        std::future::ready(InvocationResult::new(original.clone())),
        sink,
        operation,
        &TaintSet::pristine(),
        None,
        &AtomicBool::new(false),
    )
    .await;
    ensure!(result.output == original);
    ensure!(matches!(
        result.completion_error,
        Some(CompletionError::Output(Failure::Timeout))
    ));
    ensure!(
        *closed.lock()
            == Some(StreamEnd {
                outcome: Ok(()),
                taint: TaintSet::pristine(),
                origin: CompletionOrigin::CurrentAttempt,
            })
    );
    Ok(())
}

#[tokio::test]
async fn terminal_rejection_is_not_hidden_by_optional_fact_error() -> anyhow::Result<()> {
    let closed = Arc::new(parking_lot::Mutex::new(None));
    let sink: DynStreamSink = Arc::new(TerminalProbe {
        finish: Poll::Ready(Err(StreamError::Closed)),
        closed: closed.clone(),
    });
    let operation = xolotl_types::OperationId::new(
        ProcessId::new(1),
        xolotl_types::ExecutionId::FIRST,
        xolotl_types::InvocationId::new(2),
        xolotl_types::CausalPosition::new(0),
        0,
    );
    let original = DriverOutput::new(Outcome::Done(Value::integer(8)));
    let result = run_streamed_invocation(
        std::future::ready(InvocationResult {
            output: original.clone(),
            completion_error: Some(CompletionError::Fact(Failure::Timeout)),
            effect_may_have_started: true,
        }),
        sink,
        operation,
        &TaintSet::pristine(),
        None,
        &AtomicBool::new(false),
    )
    .await;
    ensure!(result.output == original);
    ensure!(matches!(
        result.completion_error,
        Some(CompletionError::Output(_))
    ));
    ensure!(
        result
            .completion_error
            .as_ref()
            .is_some_and(CompletionError::requires_interruption)
    );
    ensure!(
        *closed.lock()
            == Some(StreamEnd {
                outcome: Ok(()),
                taint: TaintSet::pristine(),
                origin: CompletionOrigin::CurrentAttempt,
            })
    );
    Ok(())
}

#[tokio::test]
async fn accepted_terminal_transfers_ownership_without_a_second_close() -> anyhow::Result<()> {
    let closed = Arc::new(parking_lot::Mutex::new(None));
    let sink: DynStreamSink = Arc::new(TerminalProbe {
        finish: Poll::Ready(Ok(())),
        closed: closed.clone(),
    });
    let operation = xolotl_types::OperationId::new(
        ProcessId::new(1),
        xolotl_types::ExecutionId::FIRST,
        xolotl_types::InvocationId::new(4),
        xolotl_types::CausalPosition::new(0),
        0,
    );
    let taint = TaintSet::author();
    let output = DriverOutput::new(Outcome::Fail(Failure::Timeout))
        .with_taint(taint.clone())
        .with_origin(CompletionOrigin::CachedOutcome);
    let result = run_streamed_invocation(
        std::future::ready(InvocationResult::new(output.clone())),
        sink,
        operation,
        &taint,
        None,
        &AtomicBool::new(false),
    )
    .await;
    ensure!(result.output == output && result.completion_error.is_none());
    ensure!(
        *closed.lock()
            == Some(StreamEnd {
                outcome: Err(Failure::Timeout),
                taint,
                origin: CompletionOrigin::CachedOutcome,
            })
    );
    Ok(())
}

#[tokio::test]
async fn terminal_rejection_preserves_a_required_completion_error() -> anyhow::Result<()> {
    let operation = xolotl_types::OperationId::new(
        ProcessId::new(1),
        xolotl_types::ExecutionId::FIRST,
        xolotl_types::InvocationId::new(5),
        xolotl_types::CausalPosition::new(0),
        0,
    );
    for error in [
        CompletionError::Settlement(Failure::Timeout),
        CompletionError::Dispatch(Failure::Timeout),
    ] {
        let closed = Arc::new(parking_lot::Mutex::new(None));
        let sink: DynStreamSink = Arc::new(TerminalProbe {
            finish: Poll::Ready(Err(StreamError::Closed)),
            closed: closed.clone(),
        });
        let original = DriverOutput::new(Outcome::Done(Value::integer(8)));
        let expected = error.outcome_unknown(operation);
        let result = run_streamed_invocation(
            std::future::ready(InvocationResult {
                output: original.clone(),
                completion_error: Some(error.clone()),
                effect_may_have_started: true,
            }),
            sink,
            operation,
            &TaintSet::pristine(),
            None,
            &AtomicBool::new(true),
        )
        .await;
        ensure!(result.output == original && result.completion_error == Some(error));
        ensure!(
            closed
                .lock()
                .as_ref()
                .is_some_and(|end| end.outcome == Err(expected))
        );
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_terminal_delivery_preserves_the_acquired_conclusion() -> anyhow::Result<()> {
    let operation = xolotl_types::OperationId::new(
        ProcessId::new(1),
        xolotl_types::ExecutionId::FIRST,
        xolotl_types::InvocationId::new(3),
        xolotl_types::CausalPosition::new(0),
        0,
    );
    let input_taint = TaintSet::author();
    let output_taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://terminal/source")?,
    });
    let origin = CompletionOrigin::CachedOutcome;
    for (outcome, completion_error, expected) in [
        (Outcome::Done(Value::integer(7)), None, Ok(())),
        (Outcome::Fail(Failure::Timeout), None, Err(Failure::Timeout)),
        (
            Outcome::Done(Value::integer(7)),
            Some(CompletionError::Fact(Failure::Timeout)),
            Ok(()),
        ),
        (
            Outcome::Done(Value::integer(7)),
            Some(CompletionError::Settlement(Failure::Timeout)),
            Err(CompletionError::Settlement(Failure::Timeout).outcome_unknown(operation)),
        ),
    ] {
        let closed = Arc::new(parking_lot::Mutex::new(None));
        let sink: DynStreamSink = Arc::new(TerminalProbe {
            finish: Poll::Pending,
            closed: closed.clone(),
        });
        let dispatched = AtomicBool::new(true);
        let result = InvocationResult {
            output: DriverOutput::new(outcome)
                .with_taint(output_taint.clone())
                .with_origin(origin),
            completion_error,
            effect_may_have_started: true,
        };
        let mut execution = Box::pin(run_streamed_invocation(
            std::future::ready(result),
            sink,
            operation,
            &input_taint,
            None,
            &dispatched,
        ));
        ensure!(poll_once(execution.as_mut()).await.is_pending());
        ensure!(closed.lock().is_none());
        drop(execution);
        ensure!(
            *closed.lock()
                == Some(StreamEnd {
                    outcome: expected,
                    taint: input_taint.clone().merged(&output_taint),
                    origin,
                })
        );
    }
    Ok(())
}

#[tokio::test]
async fn stream_flows_beyond_window_without_retaining_historic_taint_or_state() -> anyhow::Result<()>
{
    let state = InMemoryBackend::new().into_backend();
    let dp = data_plane(state.clone());
    let (sink, mut receiver) = one_chunk_channel();
    let input_taint = TaintSet::of(TaintSource::ModelOutput);
    let ctx = context(sink.clone(), input_taint.clone());
    let producer = async move {
        for index in 0..1024 {
            let source = Path::parse(&format!("state://vault/source/{index}"))
                .map_err(|error| DriverError::Other(error.to_string()))?;
            ctx.emit_tainted(TaintedValue::new(
                Value::integer(index),
                TaintSet::of(TaintSource::Protected { path: source }),
            ))
            .await?;
        }
        Ok(DriverOutput::new(Outcome::Done(Value::integer(1024))))
    };
    let consumer = async {
        let mut count = 0;
        loop {
            match receiver.recv().await {
                Some(StreamItem::Chunk(chunk)) => {
                    ensure!(chunk.value == Value::integer(count));
                    ensure!(chunk.taint.has_protected());
                    ensure!(chunk.taint.sources().len() == 2);
                    count += 1;
                }
                Some(StreamItem::End(end)) => {
                    ensure!(end.outcome == Ok(()));
                    ensure!(end.taint == input_taint);
                    break;
                }
                None => anyhow::bail!("stream omitted its terminal"),
            }
        }
        ensure!(count == 1024);
        Ok::<_, anyhow::Error>(())
    };
    let (output, consumed) =
        tokio::join!(driver_stream(&dp, producer, sink, &input_taint), consumer,);
    ensure!(output?.taint == input_taint);
    consumed?;
    let page = state
        .query(&xolotl_state::StateScan::new(Path::parse(
            "state://stream",
        )?))
        .await?;
    ensure!(page.entries.is_empty());
    Ok(())
}

#[tokio::test]
async fn driver_failure_publishes_an_error_after_buffered_chunks() -> anyhow::Result<()> {
    let dp = data_plane(InMemoryBackend::new().into_backend());
    let (sink, mut receiver) = one_chunk_channel();
    let ctx = context(sink.clone(), TaintSet::pristine());
    let producer = async move {
        ctx.emit(Value::integer(1)).await?;
        Ok(DriverOutput::new(Outcome::Fail(Failure::Cancelled)))
    };
    let output = driver_stream(&dp, producer, sink, &TaintSet::pristine()).await?;
    ensure!(output.outcome == Outcome::Fail(Failure::Cancelled));
    let Some(StreamItem::Chunk(chunk)) = receiver.recv().await else {
        anyhow::bail!("missing buffered chunk");
    };
    ensure!(chunk.value == Value::integer(1));
    drop(chunk);
    ensure!(matches!(
        receiver.recv().await,
        Some(StreamItem::End(StreamEnd {
            outcome: Err(Failure::Cancelled),
            ..
        }))
    ));
    Ok(())
}

#[tokio::test]
async fn cancelling_a_stream_drops_its_producer_and_records_input_provenance() -> anyhow::Result<()>
{
    let dp = data_plane(InMemoryBackend::new().into_backend());
    let (sink, mut receiver) = one_chunk_channel();
    let input_taint = TaintSet::author();
    let ctx = context(sink.clone(), input_taint.clone());
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = DropFlag(dropped.clone());
    let producer = async move {
        let _guard = guard;
        ctx.emit(Value::integer(1)).await?;
        std::future::pending::<Result<DriverOutput, DriverError>>().await
    };
    {
        let mut execution = Box::pin(driver_stream(&dp, producer, sink.clone(), &input_taint));
        ensure!(poll_once(execution.as_mut()).await.is_pending());
        ensure!(!dropped.load(Ordering::SeqCst));
    }
    ensure!(dropped.load(Ordering::SeqCst));
    poll_fn(|cx| sink.poll_closed(cx)).await;
    drop(receiver.recv().await);
    ensure!(matches!(receiver.recv().await,
        Some(StreamItem::End(StreamEnd { outcome: Err(Failure::Cancelled), taint, origin: CompletionOrigin::CurrentAttempt })) if taint == input_taint));
    Ok(())
}

#[tokio::test]
async fn receiver_failure_cancels_a_producer_waiting_outside_emit() -> anyhow::Result<()> {
    let dp = data_plane(InMemoryBackend::new().into_backend());
    let (sink, receiver) = one_chunk_channel();
    let ctx = context(sink.clone(), TaintSet::pristine());
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = DropFlag(dropped.clone());
    let producer = async move {
        let _guard = guard;
        ctx.emit(Value::integer(1)).await?;
        std::future::pending::<Result<DriverOutput, DriverError>>().await
    };
    let taint = TaintSet::pristine();
    let mut execution = Box::pin(driver_stream_result(&dp, producer, sink, &taint));
    ensure!(poll_once(execution.as_mut()).await.is_pending());
    drop(receiver);
    let result = execution.await;
    ensure!(matches!(result.output.outcome, Outcome::Fail(_)));
    ensure!(matches!(
        result.completion_error,
        Some(CompletionError::Output(_))
    ));
    ensure!(dropped.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn collect_limit_preserves_chunk_provenance_and_drops_the_producer() -> anyhow::Result<()> {
    let (sink, receiver) = one_chunk_channel();
    let source_taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/collect-source")?,
    });
    let input_taint = TaintSet::of(TaintSource::ModelOutput);
    let expected_taint = input_taint.clone().merged(&source_taint);
    let ctx = context(sink, input_taint.clone());
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = DropFlag(dropped.clone());
    let producer = async move {
        let _guard = guard;
        ctx.emit_tainted(TaintedValue::new(Value::integer(1), source_taint))
            .await?;
        std::future::pending::<Result<DriverOutput, DriverError>>().await
    };
    let CollectedOutput::Interrupted(output) =
        collect_driver_stream(producer, receiver, 1, input_taint).await
    else {
        anyhow::bail!("the producer has not completed at the collection limit");
    };
    ensure!(output.outcome == Outcome::Short(Value::list(vec![Value::integer(1)])));
    ensure!(output.taint == expected_taint);
    ensure!(dropped.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn collect_preserves_completion_and_rejects_unexpected_closure() -> anyhow::Result<()> {
    let (sink, receiver) = one_chunk_channel();
    let taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/finite")?,
    });
    let ctx = context(sink, taint.clone());
    let producer = async move {
        ctx.emit(Value::integer(1)).await?;
        Ok(DriverOutput::new(Outcome::Done(Value::null())))
    };
    let CollectedOutput::Complete(output) =
        collect_driver_stream(producer, receiver, 2, TaintSet::pristine()).await
    else {
        anyhow::bail!("the finite producer completed below the collection limit");
    };
    ensure!(output.outcome == Outcome::Done(Value::list(vec![Value::integer(1)])));
    ensure!(output.taint == taint);

    let (_sink, receiver) = one_chunk_channel();
    let rejected = TaintedValue::new(Value::integer(2), taint);
    let producer = async {
        Err(DriverError::Stream(StreamSendError::Closed(
            rejected.clone(),
        )))
    };
    let CollectedOutput::Complete(result) =
        collect_driver_stream(producer, receiver, 2, TaintSet::pristine()).await
    else {
        anyhow::bail!("the driver returned an error before collection completed");
    };
    ensure!(
        matches!(result.outcome, Outcome::Fail(Failure::HandlerError { ref kind, .. }) if kind == "stream")
    );
    ensure!(result.taint == rejected.taint);
    Ok(())
}

#[tokio::test]
async fn collect_preserves_known_completion_at_the_limit() -> anyhow::Result<()> {
    let (sink, receiver) = one_chunk_channel();
    let ctx = context(sink, TaintSet::pristine());
    let producer = async move {
        ctx.emit(Value::integer(1)).await?;
        Ok(DriverOutput::new(Outcome::Done(Value::null())))
    };
    let CollectedOutput::Complete(output) =
        collect_driver_stream(producer, receiver, 1, TaintSet::pristine()).await
    else {
        anyhow::bail!("the driver completed before the collection limit was observed");
    };
    ensure!(output.outcome == Outcome::Short(Value::list(vec![Value::integer(1)])));
    Ok(())
}

#[tokio::test]
async fn collect_accepts_a_completed_producer_with_no_chunks() -> anyhow::Result<()> {
    let (sink, receiver) = one_chunk_channel();
    let producer = async move {
        drop(sink);
        Ok(DriverOutput::new(Outcome::Done(Value::null())))
    };
    let CollectedOutput::Complete(output) =
        collect_driver_stream(producer, receiver, 8, TaintSet::pristine()).await
    else {
        anyhow::bail!("the empty producer completed");
    };
    ensure!(output.outcome == Outcome::Done(Value::list(vec![Value::null()])));
    Ok(())
}

#[tokio::test]
async fn collect_terminal_before_driver_completion_is_an_interruption() -> anyhow::Result<()> {
    let (sink, receiver) = one_chunk_channel();
    let taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/interrupted-collection")?,
    });
    let ctx = context(sink.clone(), taint.clone());
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = DropFlag(dropped.clone());
    let producer = async move {
        let _guard = guard;
        ctx.emit(Value::integer(1)).await?;
        sink.close(StreamEnd {
            outcome: Ok(()),
            taint: TaintSet::pristine(),
            origin: CompletionOrigin::CurrentAttempt,
        });
        std::future::pending::<Result<DriverOutput, DriverError>>().await
    };
    let CollectedOutput::Interrupted(result) =
        collect_driver_stream(producer, receiver, 8, TaintSet::pristine()).await
    else {
        anyhow::bail!("a terminal cannot complete a pending producer");
    };
    ensure!(matches!(
        result.outcome,
        Outcome::Fail(Failure::HandlerError { .. })
    ));
    ensure!(result.taint == taint);
    ensure!(dropped.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn collect_driver_failure_preserves_buffered_and_collected_provenance() -> anyhow::Result<()>
{
    for yield_after_chunk in [false, true] {
        let (sink, receiver) = one_chunk_channel();
        let taint = TaintSet::of(TaintSource::Protected {
            path: Path::parse("state://vault/failed-collection")?,
        });
        let ctx = context(sink.clone(), taint.clone());
        let producer = async move {
            ctx.emit(Value::integer(1)).await?;
            if yield_after_chunk {
                tokio::task::yield_now().await;
            }
            Err(DriverError::Transport("connection failed".into()))
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            collect_driver_stream(producer, receiver, 8, TaintSet::author()),
        )
        .await?;
        let CollectedOutput::Complete(output) = result else {
            anyhow::bail!("the driver failure must complete collection");
        };
        ensure!(
            matches!(output.outcome, Outcome::Fail(Failure::HandlerError { ref kind, .. }) if kind == "transport")
        );
        ensure!(output.taint == TaintSet::author().merged(&taint));
        drop(sink);
    }
    Ok(())
}

#[tokio::test]
async fn collect_interrupted_effect_remains_pending_uncached_and_reserved() -> anyhow::Result<()> {
    use crate::driver::{Driver, DriverPlan};
    use crate::fact::FactStore;
    use crate::handle::{FastPath, Handle};
    use crate::invocation::{Billing, InvocationOptions};
    use crate::process::{ProcessEntry, ProcessTable};
    use anyhow::Context;
    use std::collections::BTreeMap;
    use std::sync::atomic::AtomicUsize;
    use xolotl_types::{
        CostModel, DriverId, ExecutionId, HandleId, InvocationId, MethodBitmap, MethodContract,
        MethodId, NodeId, OperationId, OutputModeSet, ReplayClass, ResourceId, RightFlags, Rights,
    };

    struct PendingEffect(AtomicUsize);

    #[async_trait::async_trait]
    impl Driver for PendingEffect {
        async fn call(
            &self,
            _method: MethodId,
            _input: Value,
            _output: OutputMode,
            ctx: &DriverContext,
        ) -> Result<DriverOutput, DriverError> {
            let attempt = self.0.fetch_add(1, Ordering::SeqCst) + 1;
            ctx.emit(Value::integer(attempt as i64)).await?;
            std::future::pending().await
        }
    }

    let driver = Arc::new(PendingEffect(AtomicUsize::new(0)));
    let contract = MethodContract {
        cost: CostModel {
            flat_micro_usd: 7,
            ..CostModel::FREE
        },
        ..MethodContract::new(0, ReplayClass::IdempotentEffect, OutputModeSet::STREAM)
    };
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(MethodId::new(7), contract, driver.clone());
    let process = ProcessId::new(1);
    let handles = HandleTable::new();
    let handle = handles.insert(Handle {
        open_verb: "perform".into(),
        id: HandleId::new(0, 0),
        process,
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        bound_path: None,
    })?;
    let mut entry = ProcessEntry::new(process, None, IdentityRef::ROOT);
    ensure!(entry.scope.start());
    let processes = ProcessTable::new();
    processes.insert(entry);
    let state = InMemoryBackend::new().into_backend();
    let (facts, store) = FactSink::in_memory();
    let dp = DataPlane::new(handles, facts, state.clone())
        .with_host_runtime(processes.host_runtime().clone())?
        .with_processes(processes.clone())?;
    let mut operation = Operation {
        id: OperationId::new(
            process,
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(0),
            0,
        ),
        process,
        acting: IdentityRef::ROOT,
        handle,
        method: MethodId::new(7),
        input: Value::map(BTreeMap::from([(
            "_idem_key".into(),
            Value::string("collect-effect-business-key".into()),
        )])),
        taint: TaintSet::pristine(),
        output: OutputMode::Collect { limit: 1 },
    };
    let reserved = Billing::new(&operation.input, contract).reservation();
    for attempt in 0..2 {
        operation.id.attempt = attempt;
        let output = dp
            .execute(
                &operation,
                InvocationOptions {
                    caller_identity: None,
                    now_millis: 0,
                    record: true,
                },
            )
            .await;
        ensure!(
            output.output.outcome
                == Outcome::Short(Value::list(vec![Value::integer(i64::from(attempt) + 1)]))
        );
        ensure!(driver.0.load(Ordering::SeqCst) == attempt as usize + 1);
        let fact = store
            .get(operation.id)?
            .context("missing write-ahead Fact")?;
        ensure!(fact.replay == ReplayClass::IdempotentEffect);
        ensure!(
            !fact.is_complete(),
            "an interrupted effect is still uncertain"
        );
        let budget = processes
            .budget_mut(process, |budget| budget.clone())
            .context("missing process budget")?;
        ensure!(budget.spent_micro_usd == reserved.micro_usd * (u64::from(attempt) + 1));
        ensure!(budget.inference_tokens == reserved.tokens * (u64::from(attempt) + 1));
        ensure!(budget.inflight_ops == 0);
    }
    ensure!(
        state
            .query(&xolotl_state::StateScan::new(Path::parse("state://idemp")?))
            .await?
            .entries
            .is_empty()
    );
    Ok(())
}
