//! Session-owned live subscriptions with bounded encoded event delivery.

use crate::http::{
    ConsoleWsConfig, HARD_MAX_WS_FRAME_BYTES, HARD_MAX_WS_PENDING_EVENT_BYTES,
    HARD_MAX_WS_SUBSCRIPTIONS, MIN_WS_MAX_PENDING_EVENT_BYTES,
};
use crate::protocol::{ConsoleEvent, ServerFrame};
use crate::wire::{self, FrameEncodeError};
use futures_util::{Stream, StreamExt, stream};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::{AbortHandle, Id, JoinError, JoinSet};
use tokio::time::Instant;
#[cfg(test)]
use xolotl_state::StateEvent;

#[cfg(test)]
use tokio::sync::broadcast;

const EVENT_CAPACITY: usize = 256;
const SHUTDOWN_GRACE: Duration = Duration::from_millis(200);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_CLOSE_REASON_BYTES: usize = 1024;

use crate::service::subscriptions::source::{NotificationSource, SourceError};

impl NotificationSource for crate::ConsoleSubscription {
    type Event = ConsoleEvent;

    fn into_events(self) -> impl Stream<Item = Result<ConsoleEvent, SourceError>> + Send {
        stream::unfold(self, |mut subscription| async move {
            match subscription.recv().await {
                Ok(Some(event)) => Some((Ok(event), subscription)),
                Ok(None) => None,
                Err(error) => Some((Err(SourceError::Rejected(error)), subscription)),
            }
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
    delivered: u64,
    completion: Option<Completion>,
    delivery: Option<crate::ConsoleDelivery>,
}

struct QueuedEvent {
    producer: Producer,
    bytes: Vec<u8>,
    budget: OwnedSemaphorePermit,
    entry: OwnedSemaphorePermit,
}

struct Completion {
    producer: Producer,
    reason: Option<String>,
    sent: u64,
    /// Normal EOF and a structured service terminal keep accepted events ordered.
    /// Source loss, queue pressure, and worker failure invalidate the unsent tail.
    drain_queued: bool,
    failure: Option<Box<crate::ConsoleFailure>>,
    delivery: Option<crate::ConsoleDelivery>,
}

/// Permits cover the encoded event until its transport send finishes.
/// The entry bound is shared by channel, retained, and in-flight frames,
/// including terminal frames. Terminal frames retain their existing byte policy.
pub(super) struct SubscriptionEvent {
    pub(super) stream: u64,
    pub(super) bytes: Vec<u8>,
    pub(super) budget: Option<OwnedSemaphorePermit>,
    pub(super) entry: OwnedSemaphorePermit,
    pub(super) deadline: Option<Instant>,
    pub(super) delivery: Option<crate::ConsoleDelivery>,
}

struct Worker {
    source: &'static str,
    producer: Producer,
    event_tx: mpsc::Sender<QueuedEvent>,
    budget: Arc<Semaphore>,
    entries: Arc<Semaphore>,
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
    retained: VecDeque<QueuedEvent>,
    budget: Arc<Semaphore>,
    entries: Arc<Semaphore>,
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
            retained: VecDeque::new(),
            budget: Arc::new(Semaphore::new(config.max_pending_event_bytes.clamp(
                MIN_WS_MAX_PENDING_EVENT_BYTES,
                HARD_MAX_WS_PENDING_EVENT_BYTES,
            ))),
            entries: Arc::new(Semaphore::new(EVENT_CAPACITY)),
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
        delivery: Option<crate::ConsoleDelivery>,
    ) -> Result<(), ShutdownError>
    where
        S: NotificationSource,
        P: FnMut(S::Event) -> Result<Option<ConsoleEvent>, &'static str> + Send + 'static,
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
                entries: self.entries.clone(),
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
                delivered: 0,
                completion: None,
                delivery,
            },
        );
        Ok(())
    }

    pub(super) async fn stop(&mut self, stream: u64) -> Result<(), ShutdownError> {
        self.pending
            .retain(|completion| completion.producer.stream != stream);
        let Some(subscription) = self.active.remove(&stream) else {
            self.discard_stream_events(stream);
            return if self.failed {
                Err(ShutdownError)
            } else {
                Ok(())
            };
        };
        let target = subscription.abort.id();
        let _closed = subscription.cancel.send(());
        self.discard_stream_events(stream);
        let started = Instant::now();
        if self.wait_for(Some(target), started + SHUTDOWN_GRACE).await {
            self.discard_stream_events(stream);
            return Ok(());
        }
        subscription.abort.abort();
        if self
            .wait_for(Some(target), started + SHUTDOWN_TIMEOUT)
            .await
        {
            self.discard_stream_events(stream);
            return Ok(());
        }
        self.failed = true;
        self.tasks.abort_all();
        self.discard_stream_events(stream);
        tracing::warn!(
            ?target,
            "console subscription did not stop before its deadline"
        );
        Err(ShutdownError)
    }

    fn discard_stream_events(&mut self, stream: u64) {
        self.retained
            .retain(|event| event.producer.stream != stream);
        for _ in 0..EVENT_CAPACITY {
            let Ok(event) = self.event_rx.try_recv() else {
                break;
            };
            if event.producer.stream != stream {
                self.retained.push_back(event);
            }
        }
    }

    pub(super) async fn shutdown(&mut self) {
        let started = Instant::now();
        for (_, subscription) in std::mem::take(&mut self.active) {
            let _closed = subscription.cancel.send(());
        }
        self.pending.clear();
        self.retained.clear();
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
        self.retained.clear();
    }

    pub(super) async fn next(&mut self) -> Result<SubscriptionEvent, FrameEncodeError> {
        loop {
            self.reap_finished();
            let drained: Vec<_> = self
                .active
                .iter()
                .filter_map(|(id, subscription)| {
                    subscription
                        .completion
                        .as_ref()
                        .filter(|completion| {
                            completion.sent == subscription.delivered
                                || subscription.deadline <= Instant::now()
                        })
                        .map(|_| *id)
                })
                .collect();
            for id in drained {
                if let Some(subscription) = self.active.remove(&id)
                    && let Some(mut completion) = subscription.completion
                {
                    if subscription.deadline <= Instant::now() {
                        completion.reason = Some("subscription visibility expired".into());
                        completion.failure = None;
                    }
                    self.discard_stream_events(id);
                    self.queue_completion(completion);
                }
            }
            while let Some(completion) = self.pending.pop_front() {
                if self.active.contains_key(&completion.producer.stream) {
                    continue;
                }
                if completion.reason.is_none() {
                    continue;
                }
                let Ok(entry) = self.entries.clone().try_acquire_owned() else {
                    self.pending.push_front(completion);
                    break;
                };
                let Some(reason) = completion.reason else {
                    continue;
                };
                let stream = completion.producer.stream;
                let bytes = wire::encode_server_frame(
                    &ServerFrame::Event {
                        stream,
                        event: ConsoleEvent::SubscriptionClosed {
                            reason,
                            failure: completion.failure,
                        },
                    },
                    self.max_frame_bytes,
                )?;
                return Ok(SubscriptionEvent {
                    stream,
                    bytes,
                    budget: None,
                    entry,
                    deadline: None,
                    delivery: completion.delivery,
                });
            }
            let event = match self.retained.pop_front() {
                Some(event) => event,
                None => tokio::select! {
                    Some(result) = self.tasks.join_next_with_id(), if !self.tasks.is_empty() => {
                        self.completed(result);
                        continue;
                    }
                    permit = self.entries.clone().acquire_owned(), if !self.pending.is_empty() => {
                        drop(permit);
                        continue;
                    }
                    Some(event) = self.event_rx.recv() => event,
                },
            };
            self.reap_finished();
            if let Some(subscription) = self.active.get_mut(&event.producer.stream)
                && subscription.producer == event.producer
            {
                if subscription.deadline <= Instant::now() {
                    subscription.abort.abort();
                    continue;
                }
                subscription.delivered += 1;
                return Ok(SubscriptionEvent {
                    stream: event.producer.stream,
                    bytes: event.bytes,
                    budget: Some(event.budget),
                    entry: event.entry,
                    deadline: Some(subscription.deadline),
                    delivery: subscription.delivery.clone(),
                });
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
        let mut completion = match result {
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
                    sent: 0,
                    drain_queued: false,
                    failure: None,
                    delivery: None,
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
        if completion
            .failure
            .as_ref()
            .is_some_and(|failure| failure.runtime_completion.is_some())
        {
            completion.delivery = self
                .active
                .get(&producer.stream)
                .and_then(|subscription| subscription.delivery.clone());
        }
        if completion.drain_queued {
            if let Some(subscription) = self.active.get_mut(&producer.stream) {
                subscription.completion = Some(completion);
            }
            return;
        }
        self.active.remove(&producer.stream);
        self.discard_stream_events(producer.stream);
        self.queue_completion(completion);
    }

    fn queue_completion(&mut self, completion: Completion) {
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
    P: FnMut(T) -> Result<Option<ConsoleEvent>, &'static str> + Send + 'static,
{
    let Worker {
        source,
        producer,
        event_tx,
        budget,
        entries,
        max_frame_bytes,
        mut cancelled,
        deadline,
    } = worker;
    let expires = tokio::time::sleep_until(deadline);
    tokio::pin!(expires, receiver);
    let mut sent = 0;
    let mut drain_queued = false;
    let mut failure = None;
    let reason = loop {
        let notification = tokio::select! {
            biased;
            _ = &mut cancelled => return Completion { producer, reason: None, sent, drain_queued: false, failure: None, delivery: None },
            _ = &mut expires => break "subscription visibility expired".into(),
            notification = receiver.next() => notification,
        };
        let event = match notification {
            Some(Ok(notification)) => match project(notification) {
                Ok(Some(event)) => event,
                Ok(None) => continue,
                Err(reason) => break reason.into(),
            },
            Some(Err(SourceError::Lagged(skipped))) => {
                break format!(
                    "{source} stream lagged by {skipped} notifications; resynchronize and subscribe again"
                );
            }
            Some(Err(SourceError::Invalidated)) => {
                break format!(
                    "{source} state changed with an uncertain commit; reread and subscribe again"
                );
            }
            None => {
                drain_queued = true;
                break "subscription completed".into();
            }
            Some(Err(SourceError::Closed)) => {
                break format!("{source} notification source closed");
            }
            Some(Err(SourceError::Failed)) => {
                break format!("{source} notification failed; resynchronize and subscribe again");
            }
            Some(Err(SourceError::Rejected(error))) => {
                // Accepted events precede this terminal failure on the source.
                // Keep their delivery order even if the worker finishes first.
                drain_queued = true;
                failure = Some(Box::new(error));
                break "subscription failed".into();
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
            Err(_error) => break "subscription event could not be encoded".into(),
        };
        let Ok(permits) = u32::try_from(bytes.len()) else {
            break "subscription event exceeds the pending byte budget".into();
        };
        let Ok(entry) = entries.clone().try_acquire_owned() else {
            break "subscription event queue is full or closed; resynchronize and subscribe again"
                .into();
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
                entry,
            })
            .is_err()
        {
            break "subscription event queue is full or closed; resynchronize and subscribe again"
                .into();
        }
        sent += 1;
    };
    Completion {
        producer,
        reason: Some(bounded_reason(reason)),
        sent,
        drain_queued,
        failure,
        delivery: None,
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

#[cfg(test)]
pub(super) fn state_event(event: StateEvent) -> Result<Option<ConsoleEvent>, &'static str> {
    Ok(Some(ConsoleEvent::from(event)))
}

#[cfg(test)]
mod tests;
