//! Notification adapters shared by Console subscriptions.

use futures_util::{Stream, stream};
use tokio::sync::broadcast;
use xolotl_state::{StateEvent, StateStream, StateWatchError};

pub(crate) enum SourceError {
    Closed,
    Lagged(u64),
    Invalidated,
    Failed,
    #[cfg(feature = "http")]
    Rejected(crate::protocol::ConsoleFailure),
}

/// Sources share worker ownership and delivery, but retain their own transport.
pub(crate) trait NotificationSource: Send + 'static {
    type Event: Send + 'static;
    fn into_events(self) -> impl Stream<Item = Result<Self::Event, SourceError>> + Send;
}

impl<T: Clone + Send + 'static> NotificationSource for broadcast::Receiver<T> {
    type Event = T;

    fn into_events(self) -> impl Stream<Item = Result<T, SourceError>> + Send {
        stream::unfold(self, |mut receiver| async move {
            let event = receiver.recv().await.map_err(|error| match error {
                broadcast::error::RecvError::Closed => SourceError::Closed,
                broadcast::error::RecvError::Lagged(count) => SourceError::Lagged(count),
            });
            Some((event, receiver))
        })
    }
}

impl NotificationSource for StateStream {
    type Event = StateEvent;

    fn into_events(self) -> impl Stream<Item = Result<StateEvent, SourceError>> + Send {
        stream::unfold(self, |mut receiver| async move {
            let event = receiver.recv().await.map_err(|error| match error {
                StateWatchError::Closed => SourceError::Closed,
                StateWatchError::Lagged(count) => SourceError::Lagged(count),
                StateWatchError::Invalidated => SourceError::Invalidated,
                StateWatchError::Empty | StateWatchError::Backend(_) => SourceError::Failed,
            });
            Some((event, receiver))
        })
    }
}
