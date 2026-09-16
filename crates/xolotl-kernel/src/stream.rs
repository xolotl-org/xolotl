//! Incremental output ports independent of an executor or operating system.

use alloc::{boxed::Box, string::String};
use core::future::poll_fn;
use core::num::NonZeroUsize;
use core::task::{Context, Poll, Waker};
use xolotl_types::{CompletionOrigin, Failure, OperationId, TaintSet, TaintedValue};

/// Resident data credits. Neither limit restricts a stream's total traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamWindow {
    /// Maximum accepted chunks, including chunks borrowed by the reader.
    pub max_chunks: NonZeroUsize,
    /// Maximum charged inline bytes across accepted and borrowed chunks.
    /// Adapters document their encoding; referenced object bytes are excluded.
    pub max_inline_bytes: NonZeroUsize,
}

impl Default for StreamWindow {
    fn default() -> Self {
        Self {
            max_chunks: NonZeroUsize::MIN.saturating_add(63),
            max_inline_bytes: NonZeroUsize::MIN.saturating_add(262_143),
        }
    }
}

/// One terminal outside the data window, visible after earlier chunks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamEnd {
    /// Final operation status, including structured failure context.
    pub outcome: Result<(), Failure>,
    /// Input and final-result provenance. Chunk provenance stays on each chunk.
    pub taint: TaintSet,
    /// Cached completion does not imply replay of the original stream chunks.
    pub origin: CompletionOrigin,
}

/// A chunk cannot become acceptable by waiting for window capacity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamRejection {
    /// This chunk's inline encoding exceeds the entire byte window.
    InlineBytesExceeded {
        /// Configured inline byte limit.
        limit: usize,
    },
    /// The selected adapter cannot encode the supplied value.
    Encoding {
        /// Encoding failure detail.
        message: String,
    },
    /// The value violates the selected adapter's validation contract.
    Validation {
        /// Validation failure detail.
        message: String,
    },
}

impl core::fmt::Display for StreamRejection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InlineBytesExceeded { limit } => {
                write!(f, "chunk exceeds the {limit}-byte inline window")
            }
            Self::Encoding { message } => write!(f, "chunk encoding failed: {message}"),
            Self::Validation { message } => write!(f, "chunk validation failed: {message}"),
        }
    }
}

impl core::error::Error for StreamRejection {}

/// A send retains the original envelope whenever it is rejected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamSendError<T> {
    /// A nonblocking attempt found no available data credits.
    Full(T),
    /// The reader or stream lifecycle has closed.
    Closed(T),
    /// Waiting cannot make this value acceptable to the sink.
    Rejected {
        /// The original envelope, including its provenance.
        value: T,
        /// Permanent rejection reason.
        reason: Box<StreamRejection>,
    },
}

impl<T> StreamSendError<T> {
    /// Recover the rejected envelope for an explicit retry or transformation.
    pub fn into_inner(self) -> T {
        match self {
            Self::Full(value) | Self::Closed(value) | Self::Rejected { value, .. } => value,
        }
    }
}

impl<T> core::fmt::Display for StreamSendError<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full(_) => f.write_str("stream window is full"),
            Self::Closed(_) => f.write_str("stream is closed"),
            Self::Rejected { reason, .. } => reason.fmt(f),
        }
    }
}

impl<T: core::fmt::Debug> core::error::Error for StreamSendError<T> {}

/// Opening or completing a stream failed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StreamError {
    /// The receiving edge has closed or already accepted a terminal.
    Closed,
    /// The adapter rejected a value or terminal permanently.
    Rejected(StreamRejection),
    /// A host or transport failed with structured context.
    Failed(Failure),
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Closed => f.write_str("stream is closed"),
            Self::Rejected(reason) => reason.fmt(f),
            Self::Failed(failure) => failure.fmt(f),
        }
    }
}

impl core::error::Error for StreamError {}

/// Caller-owned state for one send. Adapters register a waiter only on Pending.
/// A caller polling this directly must call [`StreamSink::cancel_send`] on drop;
/// [`send`] and [`try_send`] own this cleanup automatically.
pub struct StreamSendRequest {
    chunk: Option<TaintedValue>,
    registration: Option<u64>,
}

impl StreamSendRequest {
    /// Begin a send while retaining the full chunk until acceptance.
    pub fn new(chunk: TaintedValue) -> Self {
        Self {
            chunk: Some(chunk),
            registration: None,
        }
    }

    /// Inspect the envelope without accepting it.
    pub fn chunk(&self) -> Option<&TaintedValue> {
        self.chunk.as_ref()
    }

    /// Accept the envelope, or include it in a returned rejection.
    /// A sink must never take it when returning Pending.
    pub fn take_chunk(&mut self) -> Option<TaintedValue> {
        self.chunk.take()
    }

    /// Adapter-specific registration assigned to this request.
    pub fn registration(&self) -> Option<u64> {
        self.registration
    }

    /// Associate this request with a live waiter in the selected adapter.
    pub fn set_registration(&mut self, registration: u64) {
        self.registration = Some(registration);
    }

    /// Remove the request's registration when accepted, rejected, or cancelled.
    pub fn take_registration(&mut self) -> Option<u64> {
        self.registration.take()
    }
}

/// An incremental output edge. Thread safety belongs to the host adapter.
pub trait StreamSink {
    /// Accept one chunk or register the current waker until credits change.
    /// Pending retains the chunk. Ready consumes it, including into an error.
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        request: &mut StreamSendRequest,
    ) -> Poll<Result<(), StreamSendError<TaintedValue>>>;

    /// Remove a cancelled or completed send's waiter without accepting data.
    fn cancel_send(&self, request: &mut StreamSendRequest);

    /// Accept a terminal independently of data credits. Ready means accepted,
    /// not consumed. Pending and errors retain `end`; success takes it.
    fn poll_finish(
        &self,
        cx: &mut Context<'_>,
        end: &mut Option<StreamEnd>,
    ) -> Poll<Result<(), StreamError>>;

    /// Record cancellation synchronously. The first terminal wins; this cannot
    /// replace a terminal already accepted by `poll_finish` or another close.
    fn close(&self, end: StreamEnd);

    /// Observe receiver closure even while a driver waits outside a send.
    /// One operation owner polls this lifecycle signal per sink.
    fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()>;
}

/// Creates an independent terminal lifecycle for each streaming operation.
pub trait StreamRouter {
    /// The edge selected for this operation.
    type Sink: StreamSink;

    /// Resolve or create a sink owned by this operation's lifecycle.
    fn open(&self, operation: OperationId) -> Result<Self::Sink, StreamError>;
}

struct PendingSend<'a, S: StreamSink + ?Sized> {
    sink: &'a S,
    request: StreamSendRequest,
}

impl<S: StreamSink + ?Sized> Drop for PendingSend<'_, S> {
    fn drop(&mut self) {
        self.sink.cancel_send(&mut self.request);
    }
}

/// Wait for data credits without allocating a boxed future.
pub async fn send<S: StreamSink + ?Sized>(
    sink: &S,
    chunk: TaintedValue,
) -> Result<(), StreamSendError<TaintedValue>> {
    let mut pending = PendingSend {
        sink,
        request: StreamSendRequest::new(chunk),
    };
    poll_fn(|cx| pending.sink.poll_send(cx, &mut pending.request)).await
}

/// Attempt once and unregister immediately if the window is full.
pub fn try_send<S: StreamSink + ?Sized>(
    sink: &S,
    chunk: TaintedValue,
) -> Result<(), StreamSendError<TaintedValue>> {
    let mut pending = PendingSend {
        sink,
        request: StreamSendRequest::new(chunk),
    };
    let mut cx = Context::from_waker(Waker::noop());
    match pending.sink.poll_send(&mut cx, &mut pending.request) {
        Poll::Ready(result) => result,
        Poll::Pending => match pending.request.take_chunk() {
            Some(chunk) => Err(StreamSendError::Full(chunk)),
            None => Ok(()),
        },
    }
}
