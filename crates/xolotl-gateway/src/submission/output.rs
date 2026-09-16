//! One response owns execution and the kernel's bounded output receiver.

use parking_lot::Mutex;
use std::future::poll_fn;
use std::ops::Deref;
use std::sync::Arc;
use std::task::{Context, Poll};
use xolotl_kernel::host::stream::{
    DynStreamRouter, DynStreamSink, StreamChunk, StreamItem, StreamReceiver, channel,
};
use xolotl_kernel::stream::{
    StreamEnd, StreamError, StreamRejection, StreamRouter, StreamSendError, StreamSendRequest,
    StreamSink,
};
use xolotl_types::{CompletionOrigin, Failure, OperationId, TaintedFailure, TaintedValue};

use super::{PreparedSubmission, SubmissionExecution};
use crate::schema::validate_surface_output_stream_item;
use crate::{
    CompiledGatewayProfile, GatewayAccepted, GatewayError, GatewayRequestLease,
    GatewaySubmitResult, StreamWindow,
};

/// A validated chunk retaining both kernel credits and Gateway capacity.
/// The lease may outlive the response without retaining its execution process.
pub struct GatewayOutputChunk {
    chunk: StreamChunk,
    lease: Arc<GatewayRequestLease>,
}

impl Deref for GatewayOutputChunk {
    type Target = TaintedValue;

    fn deref(&self) -> &Self::Target {
        &self.chunk
    }
}

impl GatewayOutputChunk {
    #[cfg(feature = "structured-output")]
    pub(crate) fn validate_acceptance(
        &self,
        accepted: &GatewayAccepted,
    ) -> Result<(), GatewayError> {
        self.validate_delivery()?;
        let inner = self.lease.registry.inner.lock();
        if inner
            .entries
            .get(&self.lease.submission_id)
            .is_none_or(|entry| entry.accepted != *accepted)
        {
            return Err(GatewayError::Rejected(
                "output acceptance metadata does not match its chunk".into(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "structured-output")]
    pub(crate) fn validate_delivery(&self) -> Result<(), GatewayError> {
        if self.lease.output_interruption().is_some() {
            return Err(GatewayError::Rejected(
                "output request was interrupted".into(),
            ));
        }
        let inner = self.lease.registry.inner.lock();
        let entry = inner
            .entries
            .get(&self.lease.submission_id)
            .ok_or_else(|| {
                GatewayError::Rejected("output request is no longer available".into())
            })?;
        if entry
            .deadline
            .is_some_and(|deadline| deadline <= tokio::time::Instant::now())
        {
            return Err(GatewayError::Rejected(
                "output request deadline expired".into(),
            ));
        }
        Ok(())
    }

    /// Acknowledge the chunk and transfer its envelope to the caller.
    /// Retention after this call is outside the kernel and Gateway windows.
    pub fn into_value(self) -> TaintedValue {
        let Self { chunk, lease } = self;
        let value = chunk.into_value();
        drop(lease);
        value
    }
}

/// One admitted output chunk or the request's completed lifecycle.
pub enum GatewayOutputEvent {
    /// A validated value retaining kernel and Gateway capacity until released.
    Chunk(GatewayOutputChunk),
    /// Exactly one final result after request cleanup. Cancellation or expiry
    /// discards queued values; borrowed chunks retain their capacity separately.
    Complete(GatewaySubmitResult),
}

/// An admitted request with no detached producer or cumulative output buffer.
/// Polling advances execution and delivery together. Dropping it cancels any
/// remaining execution. Admission and window capacity remain reserved while
/// the response or any borrowed output chunks still own them.
pub struct GatewayOutputStream {
    accepted: GatewayAccepted,
    execution: Option<SubmissionExecution>,
    receiver: Option<StreamReceiver>,
    result: Option<Result<GatewaySubmitResult, GatewayError>>,
    ended: bool,
    // Queued chunks must be destroyed before the response releases capacity.
    lease: Option<Arc<GatewayRequestLease>>,
}

impl GatewayOutputStream {
    pub(super) fn start(prepared: PreparedSubmission, window: StreamWindow) -> Self {
        let accepted = prepared.accepted.clone();
        let lease = prepared.request_guard.lease.clone();
        let (sink, receiver) = channel(window);
        let state = Arc::new(Mutex::new(OutputState::default()));
        let sink: DynStreamSink = Arc::new(ValidatedOutput {
            sink,
            profile: prepared.profile.clone(),
            surface_id: accepted.surface_id.clone(),
            state: state.clone(),
        });
        let port = OutputPort {
            router: Arc::new(SingleOperationRouter(Mutex::new(Some(sink)))),
            state,
        };
        Self {
            accepted,
            execution: Some(prepared.execute(Some(port))),
            receiver: Some(receiver),
            result: None,
            ended: false,
            lease: Some(lease),
        }
    }

    pub(super) fn replay(result: GatewaySubmitResult) -> Self {
        Self {
            accepted: result.accepted.clone(),
            execution: None,
            receiver: None,
            result: Some(Ok(result)),
            ended: false,
            lease: None,
        }
    }

    /// Metadata issued only after admission and input receipt consumption.
    pub fn accepted(&self) -> &GatewayAccepted {
        &self.accepted
    }

    /// Receive the next item without allocating a receive future.
    pub async fn next(&mut self) -> Option<Result<GatewayOutputEvent, GatewayError>> {
        poll_fn(|cx| self.poll_next(cx)).await
    }

    /// Advance the original execution while a borrowed chunk is being delivered,
    /// without receiving another item. Cancellation and request deadlines still
    /// wake the caller even while its encoder or disclosure policy is pending.
    ///
    /// Ready means the request interrupted output delivery. Abandon the borrowed
    /// item, then resume [`Self::poll_next`] to obtain the actual final outcome
    /// after persistence and cleanup. Ordinary execution completion is retained
    /// internally; it does not interrupt delivery or release borrowed credits.
    #[cfg(feature = "structured-output")]
    pub fn poll_interruption(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        self.advance_execution(cx);
        if self.result.as_ref().is_some_and(Result::is_err)
            || self
                .lease
                .as_ref()
                .is_some_and(|lease| lease.output_interruption().is_some())
        {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    fn advance_execution(&mut self, cx: &mut Context<'_>) {
        if self.result.is_none()
            && let Some(execution) = &mut self.execution
            && let Poll::Ready(result) = execution.poll_complete(cx)
        {
            self.result = Some(result);
        }
        if self.result.as_ref().is_some_and(Result::is_err) {
            self.receiver = None;
        }
    }

    /// Advance execution and delivery. Ordinary completion follows release of
    /// all chunks. Cancellation or expiry can complete before borrowed chunks
    /// are released, but their capacity remains reserved.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<GatewayOutputEvent, GatewayError>>> {
        if self.ended {
            self.execution = None;
            self.receiver = None;
            self.lease = None;
            return Poll::Ready(None);
        }
        self.advance_execution(cx);
        if let (Some(receiver), Some(lease)) = (&mut self.receiver, &self.lease) {
            match receiver.poll_recv(cx) {
                Poll::Ready(Some(StreamItem::Chunk(chunk))) => {
                    if lease.output_interruption().is_none() {
                        return Poll::Ready(Some(Ok(GatewayOutputEvent::Chunk(
                            GatewayOutputChunk {
                                chunk,
                                lease: lease.clone(),
                            },
                        ))));
                    }
                    drop(chunk);
                    self.receiver = None;
                }
                Poll::Ready(Some(StreamItem::End(_))) => self.receiver = None,
                Poll::Ready(None) => self.receiver = None,
                Poll::Pending if lease.output_interruption().is_none() => return Poll::Pending,
                Poll::Pending => self.receiver = None,
            }
        }
        let Some(result) = self.result.take() else {
            return Poll::Pending;
        };
        self.ended = true;
        Poll::Ready(Some(result.map(GatewayOutputEvent::Complete)))
    }
}

pub(super) struct OutputPort {
    pub(super) router: DynStreamRouter,
    state: Arc<Mutex<OutputState>>,
}

impl OutputPort {
    pub(super) fn failure(&self) -> Option<TaintedFailure> {
        self.state.lock().failure.clone()
    }
}

#[derive(Default)]
struct OutputState {
    failure: Option<TaintedFailure>,
}

struct SingleOperationRouter(Mutex<Option<DynStreamSink>>);

impl StreamRouter for SingleOperationRouter {
    type Sink = DynStreamSink;

    fn open(&self, _operation: OperationId) -> Result<Self::Sink, StreamError> {
        self.0.lock().take().ok_or_else(|| {
            StreamError::Failed(Failure::Custom {
                kind: "gateway_output_route".into(),
                message: "a surface output stream admits exactly one operation".into(),
            })
        })
    }
}

struct ValidatedOutput {
    sink: DynStreamSink,
    profile: Arc<CompiledGatewayProfile>,
    surface_id: String,
    state: Arc<Mutex<OutputState>>,
}

impl ValidatedOutput {
    fn reject(
        &self,
        request: &mut StreamSendRequest,
        failure: &Failure,
    ) -> Poll<Result<(), StreamSendError<TaintedValue>>> {
        self.sink.cancel_send(request);
        Poll::Ready(match request.take_chunk() {
            Some(value) => Err(StreamSendError::Rejected {
                value,
                reason: Box::new(StreamRejection::Validation {
                    message: failure.to_string(),
                }),
            }),
            None => Ok(()),
        })
    }
}

impl StreamSink for ValidatedOutput {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        request: &mut StreamSendRequest,
    ) -> Poll<Result<(), StreamSendError<TaintedValue>>> {
        if let Some(failure) = self.state.lock().failure.as_ref() {
            return self.reject(request, &failure.failure);
        }
        let Some(chunk) = request.chunk() else {
            return Poll::Ready(Ok(()));
        };
        let validation = self
            .profile
            .surface_by_id(&self.surface_id)
            .ok_or_else(|| GatewayError::Rejected("output surface is not available".into()))
            .and_then(|surface| validate_surface_output_stream_item(surface, &chunk.value));
        if let Err(error) = validation {
            let failure = Failure::Custom {
                kind: "gateway_output_stream_schema".into(),
                message: format!("surface {} output chunk: {error}", self.surface_id),
            };
            let failure = self
                .state
                .lock()
                .failure
                .get_or_insert_with(|| TaintedFailure::new(failure, chunk.taint.clone()))
                .clone();
            self.close(StreamEnd {
                outcome: Err(failure.failure.clone()),
                taint: failure.taint.clone(),
                origin: CompletionOrigin::CurrentAttempt,
            });
            return self.reject(request, &failure.failure);
        }
        self.sink.poll_send(cx, request)
    }

    fn cancel_send(&self, request: &mut StreamSendRequest) {
        self.sink.cancel_send(request);
    }

    fn poll_finish(
        &self,
        cx: &mut Context<'_>,
        end: &mut Option<StreamEnd>,
    ) -> Poll<Result<(), StreamError>> {
        self.sink.poll_finish(cx, end)
    }

    fn close(&self, end: StreamEnd) {
        self.sink.close(end);
    }

    fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        self.sink.poll_closed(cx)
    }
}
