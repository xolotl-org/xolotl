//! Operation-owned stream delivery, provenance, and terminal publication.

use super::{DataPlane, collect_outcome};
use crate::driver::{DriverContext, DriverError, DriverOutput};
use crate::host::stream::{DynStreamSink, StreamItem, StreamReceiver, channel};
use crate::invocation::{CompletionError, InvocationResult};
use crate::stream::{StreamEnd, StreamError, StreamWindow};
use futures_util::FutureExt;
use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, Ordering};
use xolotl_types::{
    CompletionOrigin, Failure, Operation, Outcome, OutputMode, Path, TaintSet, Value,
};

impl DataPlane {
    pub(super) fn attach_stream_sink(
        &self,
        op: &Operation,
        ctx: &mut DriverContext,
        sink: Option<DynStreamSink>,
    ) -> Result<DynStreamSink, Failure> {
        let sink = sink.ok_or_else(|| Failure::InvalidInput {
            reason: "stream output requires an explicit sink".into(),
        })?;
        let path = stream_path(op).map_err(|error| Failure::InvalidInput {
            reason: format!("stream route construction failed: {error}"),
        })?;
        let previous = std::mem::replace(
            ctx,
            DriverContext::new(op.acting, op.process).with_operation_id(op.id),
        );
        *ctx = previous.with_stream(path, sink.clone());
        Ok(sink)
    }

    pub(super) fn attach_collect_sink(&self, ctx: &mut DriverContext) -> Option<StreamReceiver> {
        let (sink, receiver) = channel(StreamWindow::default());
        let acting = ctx.acting;
        let caller = ctx.caller;
        let previous = std::mem::replace(ctx, DriverContext::new(acting, caller));
        let collect_path = match Path::try_new("state")
            .and_then(|path| path.try_push("stream"))
            .and_then(|path| path.try_push("collect"))
        {
            Ok(path) => path,
            Err(error) => {
                tracing::error!(?error, "collect stream path construction failed");
                return None;
            }
        };
        *ctx = previous.with_stream(collect_path, sink);
        Some(receiver)
    }
}

/// Own the stream around admission, cached results, dispatch, and accounting.
/// Optional Facts describe observations; terminal delivery cannot replace a
/// known driver result merely because observation completion failed.
pub(super) async fn run_streamed_invocation(
    call: impl Future<Output = InvocationResult>,
    sink: DynStreamSink,
    operation: xolotl_types::OperationId,
    input_taint: &TaintSet,
    observations: Option<&parking_lot::Mutex<TaintSet>>,
    effect_dispatched: &AtomicBool,
) -> InvocationResult {
    let mut completion = StreamCompletion {
        sink,
        end: Some(StreamEnd {
            outcome: Err(Failure::Cancelled),
            taint: input_taint.clone(),
            origin: CompletionOrigin::CurrentAttempt,
        }),
        observations,
    };
    // The invocation remains owned by this scope, including when it is waiting
    // outside emit. No producer or cancellation task can outlive this call.
    let mut result = tokio::select! {
        biased;
        output = call => output,
        () = poll_fn(|cx| completion.sink.poll_closed(cx)) => {
            let dispatched = effect_dispatched.load(Ordering::Relaxed);
            let failure = if dispatched {
                Failure::OutcomeUnknown {
                    operation_ids: vec![operation.to_string()],
                    reason: "stream_receiver_closed_after_dispatch".into(),
                }
            } else {
                Failure::HandlerError {
                    kind: "stream".into(),
                    message: "stream receiver closed".into(),
                }
            };
            InvocationResult {
                output: DriverOutput::new(Outcome::Fail(failure)),
                completion_error: None,
                effect_may_have_started: dispatched,
            }
        }
    };
    result.output = crate::invocation::complete_output(result.output, input_taint);
    if let Some(observations) = observations {
        let observed = observations.lock();
        result.output.taint.union(&observed);
        if let Some(end) = &mut completion.end {
            end.taint.union(&observed);
        }
    }
    let output = &result.output;
    let outcome = match &result.completion_error {
        Some(error @ (CompletionError::Settlement(_) | CompletionError::Output(_))) => {
            Err(error.outcome_unknown(operation))
        }
        Some(error @ CompletionError::Dispatch(_)) if result.effect_may_have_started => {
            Err(error.outcome_unknown(operation))
        }
        Some(CompletionError::Fact(_) | CompletionError::Dispatch(_)) | None => {
            match &output.outcome {
                Outcome::Fail(failure) => Err(failure.clone()),
                _ => Ok(()),
            }
        }
    };
    if let Some(end) = &mut completion.end {
        end.outcome = outcome;
        end.taint.union(&output.taint);
        end.origin = output.origin;
    }
    match poll_fn(|cx| completion.sink.poll_finish(cx, &mut completion.end)).await {
        Ok(()) => {}
        Err(error) => {
            let delivery_is_primary = match &result.completion_error {
                Some(CompletionError::Settlement(_) | CompletionError::Output(_)) => false,
                Some(CompletionError::Dispatch(_)) => !result.effect_may_have_started,
                Some(CompletionError::Fact(_)) | None => true,
            };
            if delivery_is_primary {
                if let Some(previous) = result.completion_error.take() {
                    tracing::warn!(%previous, "invocation completion diagnostic preceded stream delivery failure");
                }
                result.completion_error = Some(CompletionError::Output(match error {
                    StreamError::Failed(failure) => failure,
                    other => Failure::HandlerError {
                        kind: "stream".into(),
                        message: format!("stream terminal was not accepted: {other}"),
                    },
                }));
            } else {
                tracing::debug!(
                    ?error,
                    "stream terminal receiver unavailable after invocation commit failure"
                );
            }
        }
    }
    result
}

struct StreamCompletion<'a> {
    sink: DynStreamSink,
    end: Option<StreamEnd>,
    observations: Option<&'a parking_lot::Mutex<TaintSet>>,
}

impl Drop for StreamCompletion<'_> {
    fn drop(&mut self) {
        if let Some(mut end) = self.end.take() {
            if let Some(observations) = self.observations {
                end.taint.union(&observations.lock());
            }
            self.sink.close(end);
        }
    }
}

/// A collected response can be ready while its effect is still uncertain.
pub(super) enum CollectedOutput {
    Complete(DriverOutput),
    Interrupted(DriverOutput),
}

pub(super) async fn collect_driver_stream(
    call: impl Future<Output = Result<DriverOutput, DriverError>>,
    mut receiver: StreamReceiver,
    limit: usize,
    mut taint: TaintSet,
) -> CollectedOutput {
    let mut chunks = Vec::new();
    tokio::pin!(call);
    let result = {
        let collect = async {
            while chunks.len() < limit {
                match receiver.recv().await {
                    Some(StreamItem::Chunk(chunk)) => {
                        let chunk = chunk.into_value();
                        taint.union(&chunk.taint);
                        chunks.push(chunk.value);
                    }
                    Some(StreamItem::End(end)) => {
                        taint.union(&end.taint);
                        break;
                    }
                    None => break,
                }
            }
        };
        tokio::pin!(collect);
        tokio::select! {
            biased;
            result = &mut call => {
                if result.is_ok() {
                    collect.await;
                } else {
                    // Preserve ready buffered chunks without waiting on a retained sink.
                    let _ready: Option<()> = collect.as_mut().now_or_never();
                }
                Some(result)
            }
            () = &mut collect => None,
        }
    };
    let mut output = match result {
        Some(Ok(output)) => output,
        Some(Err(error)) => {
            let error = super::driver_err_to_failure(error);
            DriverOutput::new(Outcome::Fail(error.failure)).with_taint(error.taint)
        }
        None => {
            if chunks.len() == limit {
                return CollectedOutput::Interrupted(
                    DriverOutput::new(Outcome::Short(Value::list(chunks))).with_taint(taint),
                );
            }
            return CollectedOutput::Interrupted(
                DriverOutput::new(Outcome::Fail(Failure::HandlerError {
                    kind: "driver".into(),
                    message: "collect stream closed before driver completion".into(),
                }))
                .with_taint(taint),
            );
        }
    };
    output.taint.union(&taint);
    output.outcome = if output.outcome.is_success() && chunks.len() == limit {
        Outcome::Short(Value::list(chunks))
    } else {
        collect_outcome(output.outcome, chunks, OutputMode::Collect { limit })
    };
    CollectedOutput::Complete(output)
}

/// Logical transport address only. Streaming never persists a State sequence.
pub(super) fn stream_path(op: &Operation) -> Result<Path, xolotl_types::PathError> {
    Path::try_new("state")?
        .try_push("stream")?
        .try_push_literal(op.id.process.get().to_string())?
        .try_push_literal(op.id.execution.get().to_string())?
        .try_push_literal(op.id.invocation.get().to_string())?
        .try_push_literal(op.id.position.get().to_string())?
        .try_push_literal(op.id.attempt.to_string())
}

#[cfg(test)]
mod tests;
