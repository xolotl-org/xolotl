//! Session-owned live subscriptions with bounded encoded event delivery.

use crate::protocol::{ConsoleEvent, ServerFrame};
use crate::state::{
    ConsoleWsConfig, HARD_MAX_WS_FRAME_BYTES, HARD_MAX_WS_PENDING_EVENT_BYTES,
    HARD_MAX_WS_SUBSCRIPTIONS, MIN_WS_MAX_PENDING_EVENT_BYTES,
};
use crate::wire::{self, FrameEncodeError};
use futures_util::{Stream, StreamExt, stream};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot};
use tokio::task::{AbortHandle, Id, JoinError, JoinSet};
use tokio::time::Instant;
use xolotl_state::{StateEvent, StateStream, StateWatchError};

const EVENT_CAPACITY: usize = 256;
const SHUTDOWN_GRACE: Duration = Duration::from_millis(200);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_CLOSE_REASON_BYTES: usize = 1024;

pub(super) enum SourceError {
    Closed,
    Lagged(u64),
    Failed(String),
}

/// Sources share worker ownership and delivery, but retain their own transport.
pub(super) trait NotificationSource: Send + 'static {
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
                other => SourceError::Failed(other.to_string()),
            });
            Some((event, receiver))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Producer {
    stream: u64,
    generation: u64,
}

struct Subscription {
    producer: Producer,
    cancel: oneshot::Sender<()>,
    abort: AbortHandle,
    deadline: Instant,
}

struct QueuedEvent {
    producer: Producer,
    bytes: Vec<u8>,
    budget: OwnedSemaphorePermit,
}

struct Completion {
    producer: Producer,
    reason: Option<String>,
}

/// The permit covers the encoded event until its transport send finishes.
pub(super) struct SubscriptionEvent {
    pub(super) stream: u64,
    pub(super) bytes: Vec<u8>,
    pub(super) budget: Option<OwnedSemaphorePermit>,
    pub(super) deadline: Option<Instant>,
}

struct Worker {
    source: &'static str,
    producer: Producer,
    event_tx: mpsc::Sender<QueuedEvent>,
    budget: Arc<Semaphore>,
    max_frame_bytes: usize,
    cancelled: oneshot::Receiver<()>,
    deadline: Instant,
}

#[derive(Debug)]
pub(super) struct ShutdownError;

impl fmt::Display for ShutdownError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("console subscription lifecycle could not complete")
    }
}

impl std::error::Error for ShutdownError {}

pub(super) struct Subscriptions {
    active: BTreeMap<u64, Subscription>,
    tasks: JoinSet<Completion>,
    pending: VecDeque<Completion>,
    event_tx: mpsc::Sender<QueuedEvent>,
    event_rx: mpsc::Receiver<QueuedEvent>,
    budget: Arc<Semaphore>,
    max_frame_bytes: usize,
    max_subscriptions: usize,
    next_generation: u64,
    failed: bool,
}

impl Subscriptions {
    pub(super) fn new(config: &ConsoleWsConfig) -> Self {
        let (event_tx, event_rx) = mpsc::channel(EVENT_CAPACITY);
        Self {
            active: BTreeMap::new(),
            tasks: JoinSet::new(),
            pending: VecDeque::new(),
            event_tx,
            event_rx,
            budget: Arc::new(Semaphore::new(config.max_pending_event_bytes.clamp(
                MIN_WS_MAX_PENDING_EVENT_BYTES,
                HARD_MAX_WS_PENDING_EVENT_BYTES,
            ))),
            max_frame_bytes: config.max_frame_bytes.min(HARD_MAX_WS_FRAME_BYTES),
            max_subscriptions: config.max_subscriptions.clamp(1, HARD_MAX_WS_SUBSCRIPTIONS),
            next_generation: 0,
            failed: false,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.active.len()
    }

    pub(super) fn contains(&self, stream: u64) -> bool {
        self.active.contains_key(&stream)
    }

    pub(super) fn failed(&self) -> bool {
        self.failed
    }

    pub(super) fn reap_finished(&mut self) {
        while let Some(result) = self.tasks.try_join_next_with_id() {
            self.completed(result);
        }
    }

    pub(super) async fn replace<S, P>(
        &mut self,
        stream: u64,
        receiver: S,
        project: P,
        source: &'static str,
        deadline: Instant,
    ) -> Result<(), ShutdownError>
    where
        S: NotificationSource,
        P: FnMut(S::Event) -> Result<Option<ConsoleEvent>, String> + Send + 'static,
    {
        if self.failed || (self.len() >= self.max_subscriptions && !self.contains(stream)) {
            return Err(ShutdownError);
        }
        self.stop(stream).await?;
        if self.failed {
            return Err(ShutdownError);
        }
        let Some(generation) = self.next_generation.checked_add(1) else {
            self.failed = true;
            return Err(ShutdownError);
        };
        self.next_generation = generation;
        let producer = Producer { stream, generation };
        let (cancel, cancelled) = oneshot::channel();
        let abort = self.tasks.spawn(run(
            receiver.into_events(),
            project,
            Worker {
                source,
                producer,
                event_tx: self.event_tx.clone(),
                budget: self.budget.clone(),
                max_frame_bytes: self.max_frame_bytes,
                cancelled,
                deadline,
            },
        ));
        self.active.insert(
            stream,
            Subscription {
                producer,
                cancel,
                abort,
                deadline,
            },
        );
        Ok(())
    }

    pub(super) async fn stop(&mut self, stream: u64) -> Result<(), ShutdownError> {
        self.pending
            .retain(|completion| completion.producer.stream != stream);
        let Some(subscription) = self.active.remove(&stream) else {
            return if self.failed {
                Err(ShutdownError)
            } else {
                Ok(())
            };
        };
        let target = subscription.abort.id();
        let _closed = subscription.cancel.send(());
        let started = Instant::now();
        if self.wait_for(Some(target), started + SHUTDOWN_GRACE).await {
            return Ok(());
        }
        subscription.abort.abort();
        if self
            .wait_for(Some(target), started + SHUTDOWN_TIMEOUT)
            .await
        {
            return Ok(());
        }
        self.failed = true;
        self.tasks.abort_all();
        tracing::warn!(
            ?target,
            "console subscription did not stop before its deadline"
        );
        Err(ShutdownError)
    }

    pub(super) async fn shutdown(&mut self) {
        let started = Instant::now();
        for (_, subscription) in std::mem::take(&mut self.active) {
            let _closed = subscription.cancel.send(());
        }
        self.pending.clear();
        while self.event_rx.try_recv().is_ok() {}
        if !self.wait_for(None, started + SHUTDOWN_GRACE).await {
            self.tasks.abort_all();
            if !self.wait_for(None, started + SHUTDOWN_TIMEOUT).await {
                self.failed = true;
                tracing::warn!(
                    remaining = self.tasks.len(),
                    "console subscription shutdown expired"
                );
            }
        }
        while self.event_rx.try_recv().is_ok() {}
    }

    pub(super) async fn next(&mut self) -> Result<SubscriptionEvent, FrameEncodeError> {
        loop {
            self.reap_finished();
            while let Some(completion) = self.pending.pop_front() {
                if self.active.contains_key(&completion.producer.stream) {
                    continue;
                }
                let Some(reason) = completion.reason else {
                    continue;
                };
                let stream = completion.producer.stream;
                let bytes = wire::encode_server_frame(
                    &ServerFrame::Event {
                        stream,
                        event: ConsoleEvent::SubscriptionClosed { reason },
                    },
                    self.max_frame_bytes,
                )?;
                return Ok(SubscriptionEvent {
                    stream,
                    bytes,
                    budget: None,
                    deadline: None,
                });
            }
            tokio::select! {
                Some(result) = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => {
                    self.completed(result);
                }
                Some(event) = self.event_rx.recv() => {
                    self.reap_finished();
                    if let Some(subscription) = self.active.get(&event.producer.stream)
                        && subscription.producer == event.producer
                    {
                        if subscription.deadline <= Instant::now() {
                            subscription.abort.abort();
                            continue;
                        }
                        return Ok(SubscriptionEvent {
                            stream: event.producer.stream,
                            bytes: event.bytes,
                            budget: Some(event.budget),
                            deadline: Some(subscription.deadline),
                        });
                    }
                }
            }
        }
    }

    async fn wait_for(&mut self, target: Option<Id>, deadline: Instant) -> bool {
        loop {
            let result =
                match tokio::time::timeout_at(deadline, self.tasks.join_next_with_id()).await {
                    Ok(Some(result)) => result,
                    Ok(None) => return true,
                    Err(_elapsed) => return false,
                };
            let id = match &result {
                Ok((id, _)) => *id,
                Err(error) => error.id(),
            };
            self.completed(result);
            if target == Some(id) {
                return true;
            }
        }
    }

    fn completed(&mut self, result: Result<(Id, Completion), JoinError>) {
        let completion = match result {
            Ok((_, completion)) => completion,
            Err(error) => {
                if error.is_panic() {
                    tracing::warn!(?error, "console subscription task panicked");
                }
                let Some(subscription) = self
                    .active
                    .values()
                    .find(|subscription| subscription.abort.id() == error.id())
                else {
                    return;
                };
                Completion {
                    producer: subscription.producer,
                    reason: Some(if subscription.deadline <= Instant::now() {
                        "subscription visibility expired".into()
                    } else {
                        "subscription worker stopped unexpectedly; subscribe again".into()
                    }),
                }
            }
        };
        let producer = completion.producer;
        if !self
            .active
            .get(&producer.stream)
            .is_some_and(|subscription| subscription.producer == producer)
        {
            return;
        }
        self.active.remove(&producer.stream);
        if self.pending.len() >= self.max_subscriptions {
            self.failed = true;
            self.tasks.abort_all();
            return;
        }
        self.pending.push_back(completion);
    }
}

async fn run<T, P>(
    receiver: impl Stream<Item = Result<T, SourceError>> + Send,
    mut project: P,
    worker: Worker,
) -> Completion
where
    T: Send + 'static,
    P: FnMut(T) -> Result<Option<ConsoleEvent>, String> + Send + 'static,
{
    let Worker {
        source,
        producer,
        event_tx,
        budget,
        max_frame_bytes,
        mut cancelled,
        deadline,
    } = worker;
    let expires = tokio::time::sleep_until(deadline);
    tokio::pin!(expires, receiver);
    let reason = loop {
        let notification = tokio::select! {
            biased;
            _ = &mut cancelled => return Completion { producer, reason: None },
            _ = &mut expires => break "subscription visibility expired".into(),
            notification = receiver.next() => notification,
        };
        let event = match notification {
            Some(Ok(notification)) => match project(notification) {
                Ok(Some(event)) => event,
                Ok(None) => continue,
                Err(reason) => break reason,
            },
            Some(Err(SourceError::Lagged(skipped))) => {
                break format!(
                    "{source} stream lagged by {skipped} notifications; resynchronize and subscribe again"
                );
            }
            Some(Err(SourceError::Closed)) | None => {
                break format!("{source} notification source closed");
            }
            Some(Err(SourceError::Failed(reason))) => {
                break format!("{source} notification failed: {reason}");
            }
        };
        let bytes = match wire::encode_server_frame(
            &ServerFrame::Event {
                stream: producer.stream,
                event,
            },
            max_frame_bytes,
        ) {
            Ok(bytes) => bytes,
            Err(error) => break format!("subscription event could not be encoded: {error}"),
        };
        let Ok(permits) = u32::try_from(bytes.len()) else {
            break "subscription event exceeds the pending byte budget".into();
        };
        let Ok(budget) = budget.clone().try_acquire_many_owned(permits) else {
            break "subscription pending byte budget exhausted; resynchronize and subscribe again"
                .into();
        };
        if event_tx
            .try_send(QueuedEvent {
                producer,
                bytes,
                budget,
            })
            .is_err()
        {
            break "subscription event queue is full or closed; resynchronize and subscribe again"
                .into();
        }
    };
    Completion {
        producer,
        reason: Some(bounded_reason(reason)),
    }
}

fn bounded_reason(mut reason: String) -> String {
    if reason.len() > MAX_CLOSE_REASON_BYTES {
        let mut end = MAX_CLOSE_REASON_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
        reason.shrink_to_fit();
    }
    reason
}

pub(super) fn state_event(event: StateEvent) -> Result<Option<ConsoleEvent>, String> {
    Ok(Some(match event {
        StateEvent::Set { path, value, .. } => ConsoleEvent::StateSet { path, value },
        StateEvent::Append { path, item, .. } => ConsoleEvent::StateAppend { path, item },
        StateEvent::Delete { path, .. } => ConsoleEvent::StateDelete { path },
    }))
}

#[cfg(test)]
mod tests;
