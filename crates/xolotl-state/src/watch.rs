use crate::{StateEvent, StateResult};
use alloc::{boxed::Box, string::String};
use core::{
    future::Future,
    task::{Context, Poll},
};
use thiserror::Error;
use xolotl_types::Path;

/// Subscription lifecycle and delivery errors independent of a runtime.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum StateWatchError {
    /// The subscription ended and can no longer deliver new events.
    #[error("state subscription is closed")]
    Closed,
    /// A non-blocking receive found no event currently ready.
    #[error("state subscription has no ready event")]
    Empty,
    /// The subscriber fell behind; the count reports events lost from its buffer.
    /// Callers may reread authoritative state before continuing consumption.
    #[error("state subscription lost {0} events")]
    Lagged(u64),
    /// A storage commit may have changed State without a reliable event, or
    /// the backend could not retain a notification for this subscription.
    /// This stream is closed after the error. For notification loss alone,
    /// reread State and resubscribe. If a storage commit outcome is unknown,
    /// follow the backend's recovery contract before authoritative
    /// reconciliation or resubscribing: a live reread need not reflect the
    /// durable outcome and cannot by itself establish rollback.
    #[error(
        "state subscription invalidated by a notification gap; recover authoritative state before resubscribing"
    )]
    Invalidated,
    /// The subscription adapter failed with a backend-specific diagnostic.
    #[error("state subscription failed: {0}")]
    Backend(String),
}

/// Object-safe pull interface. Dropping it releases subscription ownership.
pub trait StateSubscription {
    /// Poll the next committed event, explicitly reporting loss or closure.
    /// `Ok(None)` ends the stream. `Pending` must arrange a wake when progress
    /// becomes possible; event order and retention are defined by the backend.
    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<StateEvent>, StateWatchError>>;
}

/// Optional subscription capability. For signal waits, registration and the
/// initial read must observe one commit domain; the shared host installs that
/// stronger pairing separately through `Backend::with_signal`.
pub trait StateWatch {
    /// Owned subscription whose destruction releases its registration.
    type Subscription: StateSubscription;
    /// Backend-owned subscription setup, without a `Send` or boxing requirement.
    type Subscribe<'a>: Future<Output = StateResult<Self::Subscription>>
    where
        Self: 'a;
    /// Register for future committed events whose paths match `pattern`.
    /// This does not return an initial snapshot of existing values.
    fn subscribe<'a>(&'a self, pattern: &'a Path) -> Self::Subscribe<'a>;
}

/// Optional erased subscription for hosts choosing shared ownership and threads.
pub struct StateStream(Box<dyn StateSubscription + Send>);

impl StateStream {
    /// Box a transferable subscription, retaining its ownership until this stream drops.
    pub fn new(subscription: impl StateSubscription + Send + 'static) -> Self {
        Self(Box::new(subscription))
    }

    /// Wait for the next event. End-of-stream becomes [`StateWatchError::Closed`];
    /// loss, invalidation, and backend errors are forwarded without being
    /// hidden as closure.
    pub async fn recv(&mut self) -> Result<StateEvent, StateWatchError> {
        core::future::poll_fn(|cx| self.poll_next(cx))
            .await?
            .ok_or(StateWatchError::Closed)
    }

    /// Poll once without waiting. Return [`StateWatchError::Empty`] if no event
    /// is ready, or [`StateWatchError::Closed`] when the subscription has ended.
    pub fn try_recv(&mut self) -> Result<StateEvent, StateWatchError> {
        match self.poll_next(&mut Context::from_waker(core::task::Waker::noop())) {
            Poll::Ready(Ok(Some(event))) => Ok(event),
            Poll::Ready(Ok(None)) => Err(StateWatchError::Closed),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(StateWatchError::Empty),
        }
    }
}

impl StateSubscription for StateStream {
    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<StateEvent>, StateWatchError>> {
        self.0.poll_next(cx)
    }
}
