//! Tokio broadcast adaptation without a forwarding task.

use crate::{StateEvent, StateStream, StateSubscription, StateWatchError};
use core::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio_stream::{
    Stream,
    wrappers::{BroadcastStream, errors::BroadcastStreamRecvError},
};

pub(super) struct BroadcastSubscription(BroadcastStream<StateEvent>);

impl BroadcastSubscription {
    pub(super) fn new(receiver: tokio::sync::broadcast::Receiver<StateEvent>) -> Self {
        Self(BroadcastStream::new(receiver))
    }
}

impl StateSubscription for BroadcastSubscription {
    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<StateEvent>, StateWatchError>> {
        match Pin::new(&mut self.0).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(Ok(None)),
            Poll::Ready(Some(Ok(event))) => Poll::Ready(Ok(Some(event))),
            Poll::Ready(Some(Err(BroadcastStreamRecvError::Lagged(count)))) => {
                Poll::Ready(Err(StateWatchError::Lagged(count)))
            }
        }
    }
}

/// Adapt a Tokio receiver with one reusable polling allocation.
pub fn broadcast_stream(receiver: tokio::sync::broadcast::Receiver<StateEvent>) -> StateStream {
    StateStream::new(BroadcastSubscription::new(receiver))
}
