//! Operation-owned stream delivery, provenance, and terminal publication.

use super::{DataPlane, collect_outcome};
use crate::driver::{DriverContext, DriverError, DriverOutput};
use crate::host::stream::{DynStreamSink, StreamItem, StreamReceiver, channel};
use crate::stream::{StreamEnd, StreamWindow};
use futures_util::FutureExt;
use std::future::{Future, poll_fn};
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
/// Facts describe effect results: cancelling a pending invocation leaves any
/// write-ahead Fact pending, and terminal delivery cannot replace a known result.
pub(super) async fn run_streamed_invocation(
    call: impl Future<Output = DriverOutput>,
    sink: DynStreamSink,
    input_taint: &TaintSet,
) -> DriverOutput {
    let mut completion = StreamCompletion {
        sink,
        taint: input_taint.clone(),
        origin: CompletionOrigin::CurrentAttempt,
        finished: false,
    };
    // The invocation remains owned by this scope, including when it is waiting
    // outside emit. No producer or cancellation task can outlive this call.
    let output = tokio::select! {
        biased;
        output = call => output,
        () = poll_fn(|cx| completion.sink.poll_closed(cx)) => {
            DriverOutput::new(Outcome::Fail(Failure::HandlerError {
                kind: "stream".into(),
                message: "stream receiver closed".into(),
            }))
        }
    };
    let output = crate::invocation::complete_output(output, input_taint);
    completion.taint.union(&output.taint);
    completion.origin = output.origin;
    let outcome = match &output.outcome {
        Outcome::Fail(failure) => Err(failure.clone()),
        _ => Ok(()),
    };
    let mut end = Some(StreamEnd {
        outcome,
        taint: completion.taint.clone(),
        origin: completion.origin,
    });
    match poll_fn(|cx| completion.sink.poll_finish(cx, &mut end)).await {
        Ok(()) => completion.finished = true,
        Err(error) => tracing::debug!(?error, "stream terminal receiver unavailable"),
    }
    output
}

struct StreamCompletion {
    sink: DynStreamSink,
    taint: TaintSet,
    origin: CompletionOrigin,
    finished: bool,
}

impl Drop for StreamCompletion {
    fn drop(&mut self) {
        if !self.finished {
            self.sink.close(StreamEnd {
                outcome: Err(Failure::Cancelled),
                taint: self.taint.clone(),
                origin: self.origin,
            });
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
