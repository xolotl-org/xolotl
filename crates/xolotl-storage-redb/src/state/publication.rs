//! One commit domain for redb State writes, Source sinks, and subscriptions.
//!
//! The database serializes writers, but it does not serialize subscribers
//! with the interval between a durable commit and its notification. This
//! coordinator covers that interval and queues delivery in commit order.

use super::{StateEvent, Subscriptions};
use crate::database::WriteTransaction;
use redb::CommitError;
use std::collections::{HashSet, VecDeque};
use std::io::{self, Write};
use std::mem::size_of;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use xolotl_types::{
    StreamMarker, Value, ValueView,
    value::traversal::{ValueNodeKey, ValuePostorder},
};

const MAX_OUTSTANDING_NOTIFICATIONS: usize = 1024;
const MAX_OUTSTANDING_NOTIFICATION_BYTES: usize = 8 * 1024 * 1024;
const MAX_NOTIFICATION_GRAPH_NODES: usize = 262_144;
const MAX_NOTIFICATION_GRAPH_DEPTH: usize = 8_192;

pub(crate) enum PublishFailure {
    /// The transaction was not committed because publication capacity was full.
    Backpressure,
    /// Commit failed; non-poisoned failures may already be durable.
    Commit(CommitError),
}

struct Notification {
    event: StateEvent,
    targets: Vec<tokio::sync::broadcast::Sender<StateEvent>>,
    charge: usize,
}

#[derive(Default)]
struct DeliveryQueue {
    pending: VecDeque<Notification>,
    outstanding: usize,
    outstanding_bytes: usize,
    draining: bool,
}

/// Counts the lossless event encoding without retaining a second payload.
/// The value graph has already passed a separate bounded, borrowed walk:
/// tagged-value serialization builds its complete node index before writing.
struct BoundedCount {
    bytes: usize,
    limit: usize,
}

impl Write for BoundedCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= self.limit)
            .ok_or_else(|| io::Error::other("notification exceeds byte budget"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Skip the serializer's complete node-index allocation for obviously large
/// events. This walks shared resident nodes once and stops before its own
/// scratch set or nesting frames can grow without bound. Its byte check counts
/// only material that must be carried by the event; final admission still uses
/// the complete lossless encoding below.
fn preflight_value(value: &Value) -> bool {
    if !matches!(value.view(), ValueView::List(_) | ValueView::Map(_)) {
        return leaf_bytes(value) <= MAX_OUTSTANDING_NOTIFICATION_BYTES;
    }
    let mut completed = HashSet::new();
    let mut walk = ValuePostorder::new(value);
    let mut entered = 0usize;
    let mut raw_bytes = 0usize;
    loop {
        let next = walk.try_next(
            |key| completed.contains(&key),
            |node, depth| {
                entered += 1;
                if entered > MAX_NOTIFICATION_GRAPH_NODES || depth > MAX_NOTIFICATION_GRAPH_DEPTH {
                    return Err(());
                }
                if let ValueView::Map(entries) = node.view() {
                    for (key, _) in entries.iter() {
                        raw_bytes = raw_bytes.saturating_add(key.len());
                        if raw_bytes > MAX_OUTSTANDING_NOTIFICATION_BYTES {
                            return Err(());
                        }
                    }
                }
                raw_bytes = raw_bytes.saturating_add(leaf_bytes(node));
                (raw_bytes <= MAX_OUTSTANDING_NOTIFICATION_BYTES)
                    .then_some(())
                    .ok_or(())
            },
        );
        match next {
            Ok(Some(node)) => {
                if completed.try_reserve(1).is_err() {
                    return false;
                }
                completed.insert(ValueNodeKey::of(node));
            }
            Ok(None) => return true,
            Err(()) => return false,
        }
    }
}

fn leaf_bytes(value: &Value) -> usize {
    match value.view() {
        ValueView::Str(text) => text.len(),
        ValueView::Bytes(bytes) => bytes.len(),
        ValueView::Blob(blob) => blob
            .hash
            .len()
            .saturating_add(blob.mime.as_ref().map_or(0, String::len)),
        ValueView::Tensor(tensor) => tensor
            .blob
            .hash
            .len()
            .saturating_add(tensor.blob.mime.as_ref().map_or(0, String::len)),
        ValueView::Frame(frame) => frame
            .blob
            .hash
            .len()
            .saturating_add(frame.blob.mime.as_ref().map_or(0, String::len)),
        ValueView::StreamEnd(StreamMarker::Error { message }) => message.len(),
        ValueView::Null
        | ValueView::Bool(_)
        | ValueView::Int(_)
        | ValueView::Float(_)
        | ValueView::List(_)
        | ValueView::Map(_)
        | ValueView::StreamEnd(StreamMarker::Done) => 0,
    }
}

fn preflight_event(event: &StateEvent) -> bool {
    match event {
        StateEvent::Set { value, .. } => preflight_value(value),
        StateEvent::Append { item, .. } => preflight_value(item),
        StateEvent::DropPrefixAppend { item, .. } => preflight_value(item),
        StateEvent::Delete { .. } => true,
    }
}

fn notification_charge(
    event: &StateEvent,
    targets: &Vec<tokio::sync::broadcast::Sender<StateEvent>>,
) -> Option<usize> {
    let overhead = size_of::<Notification>().checked_add(
        targets
            .capacity()
            .checked_mul(size_of::<tokio::sync::broadcast::Sender<StateEvent>>())?,
    )?;
    let limit = MAX_OUTSTANDING_NOTIFICATION_BYTES.checked_sub(overhead)?;
    preflight_event(event).then_some(())?;
    let mut counter = BoundedCount { bytes: 0, limit };
    serde_json::to_writer(&mut counter, event).ok()?;
    overhead.checked_add(counter.bytes)
}

/// Shared by every State adapter created from one `RedbStore`.
#[derive(Default)]
pub(crate) struct Publication {
    commit_order: Mutex<()>,
    subscriptions: Arc<Subscriptions>,
    delivery: parking_lot::Mutex<DeliveryQueue>,
}

impl Publication {
    pub(crate) async fn registration_lock(&self) -> MutexGuard<'_, ()> {
        self.commit_order.lock().await
    }

    pub(crate) fn subscriptions(&self) -> &Subscriptions {
        &self.subscriptions
    }

    /// Commit a prepared transaction and record its notification atomically
    /// with respect to registration and other State-producing commits.
    /// Called only from an admitted blocking worker.
    pub(crate) fn commit(
        &self,
        mut txn: WriteTransaction,
        event: StateEvent,
    ) -> Result<(), PublishFailure> {
        let _notification = txn.defer_notifications();
        let order = self.commit_order.blocking_lock();
        let targets = self.subscriptions.matching(event.path());
        let charge = (!targets.is_empty())
            .then(|| notification_charge(&event, &targets))
            .flatten();
        if let Some(charge) = charge {
            let mut delivery = self.delivery.lock();
            if delivery.outstanding >= MAX_OUTSTANDING_NOTIFICATIONS
                || delivery
                    .outstanding_bytes
                    .checked_add(charge)
                    .is_none_or(|bytes| bytes > MAX_OUTSTANDING_NOTIFICATION_BYTES)
                || delivery.pending.try_reserve(1).is_err()
            {
                return Err(PublishFailure::Backpressure);
            }
        }

        // An I/O error may occur after the new redb root is durable. A panic
        // in the storage backend is equally unresolvable for an observer.
        let committed = catch_unwind(AssertUnwindSafe(|| txn.commit()));
        match committed {
            Ok(Ok(())) => {
                let invalidation = if let Some(charge) = charge {
                    let mut delivery = self.delivery.lock();
                    delivery.outstanding += 1;
                    delivery.outstanding_bytes += charge;
                    delivery.pending.push_back(Notification {
                        event,
                        targets,
                        charge,
                    });
                    None
                } else if targets.is_empty() {
                    None
                } else {
                    // This event cannot fit even in an empty queue. The State
                    // commit is still valid; old observers must resnapshot.
                    Some(self.subscriptions.invalidate_matching(event.path()))
                };
                drop(order);
                if let Some(invalidation) = invalidation {
                    invalidation.finish();
                }
                self.drain();
                Ok(())
            }
            Ok(Err(error)) => {
                drop(order);
                self.drain();
                Err(PublishFailure::Commit(error))
            }
            Err(payload) => {
                drop(order);
                self.drain();
                resume_unwind(payload)
            }
        }
    }

    fn drain(&self) {
        {
            let mut delivery = self.delivery.lock();
            if delivery.draining || delivery.pending.is_empty() {
                return;
            }
            delivery.draining = true;
        }
        let mut reset = DrainReset {
            publication: self,
            active: true,
        };
        loop {
            let next = {
                let mut delivery = self.delivery.lock();
                match delivery.pending.pop_front() {
                    Some(notification) => Some(notification),
                    None => {
                        delivery.draining = false;
                        reset.active = false;
                        None
                    }
                }
            };
            let Some(notification) = next else { return };
            let _reservation = DeliveryReservation {
                publication: self,
                charge: notification.charge,
            };
            deliver(notification);
        }
    }
}

fn deliver(notification: Notification) {
    for target in notification.targets {
        // A subscriber's custom waker must not prevent later targets or commits
        // from being published.
        let _sent = catch_unwind(AssertUnwindSafe(|| target.send(notification.event.clone())));
    }
}

/// The active delivery counts against the budget until it releases its event,
/// including when a caller-controlled waker reenters publication or panics.
struct DeliveryReservation<'a> {
    publication: &'a Publication,
    charge: usize,
}

impl Drop for DeliveryReservation<'_> {
    fn drop(&mut self) {
        let mut delivery = self.publication.delivery.lock();
        delivery.outstanding -= 1;
        delivery.outstanding_bytes -= self.charge;
    }
}

struct DrainReset<'a> {
    publication: &'a Publication,
    active: bool,
}

impl Drop for DrainReset<'_> {
    fn drop(&mut self) {
        if self.active {
            self.publication.delivery.lock().draining = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RedbStore;
    use anyhow::{Context as _, ensure};
    use std::future::Future;
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::task::{Context, Wake, Waker};
    use std::time::Duration;
    use xolotl_state::{StateError, StateReadExt, StateWatch, StateWatchError, StateWriteExt};
    use xolotl_types::{Path, TaintSet, Value};

    struct BlockingWake {
        entered: mpsc::Sender<()>,
        release: StdMutex<mpsc::Receiver<()>>,
        entered_once: AtomicBool,
    }

    impl Wake for BlockingWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            if !self.entered_once.swap(true, Ordering::SeqCst) {
                let _sent = self.entered.send(());
                let _released = self
                    .release
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv();
            }
        }
    }

    #[test]
    fn notification_charge_stops_at_the_event_byte_limit() -> anyhow::Result<()> {
        let path = Path::parse("state://publication/size")?;
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);
        let targets = vec![sender];
        let small = StateEvent::Set {
            path: path.clone(),
            value: Value::string("small".into()),
            taint: TaintSet::pristine(),
        };
        let large = StateEvent::Set {
            path,
            value: Value::string("x".repeat(MAX_OUTSTANDING_NOTIFICATION_BYTES)),
            taint: TaintSet::pristine(),
        };
        ensure!(notification_charge(&small, &targets).is_some());
        ensure!(notification_charge(&large, &targets).is_none());
        Ok(())
    }

    #[test]
    fn preflight_shares_nodes_and_stops_before_indexing_large_graphs() -> anyhow::Result<()> {
        let leaf = Value::string("x".repeat(4 * 1024 * 1024));
        let shared = Value::list(vec![leaf.clone(), leaf.clone(), leaf]);
        ensure!(preflight_value(&shared));
        let path = Path::parse("state://publication/shared")?;
        let (sender, _receiver) = tokio::sync::broadcast::channel(1);
        let event = StateEvent::Set {
            path,
            value: shared,
            taint: TaintSet::pristine(),
        };
        ensure!(notification_charge(&event, &vec![sender]).is_some());

        // Each integer is a distinct resident node. The preflight limit is
        // independent of the eventual serialized byte count.
        let too_many = Value::list(
            (0..MAX_NOTIFICATION_GRAPH_NODES)
                .map(|_| Value::integer(0))
                .collect(),
        );
        ensure!(!preflight_value(&too_many));
        Ok(())
    }

    #[tokio::test]
    async fn oversized_event_commits_and_invalidates_only_its_followers() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let backend = RedbStore::open(directory.path().join("oversized.redb"))?.state_backend();
        let path = Path::parse("state://publication/oversized")?;
        let other = Path::parse("state://publication/other")?;
        let mut affected = backend.subscribe(&path).await?;
        let mut unrelated = backend.subscribe(&other).await?;
        backend
            .write_set(
                &path,
                Value::string("x".repeat(MAX_OUTSTANDING_NOTIFICATION_BYTES)),
            )
            .await?;
        ensure!(
            backend
                .read(&path)
                .await?
                .as_ref()
                .and_then(Value::as_str)
                .map(str::len)
                == Some(MAX_OUTSTANDING_NOTIFICATION_BYTES)
        );
        ensure!(matches!(
            affected.try_recv(),
            Err(StateWatchError::Invalidated)
        ));
        ensure!(matches!(affected.try_recv(), Err(StateWatchError::Closed)));
        ensure!(matches!(unrelated.try_recv(), Err(StateWatchError::Empty)));

        let mut fresh = backend.subscribe(&path).await?;
        backend.write_set(&path, Value::integer(7)).await?;
        ensure!(
            matches!(fresh.try_recv()?, StateEvent::Set { value, .. } if value.as_int() == Some(7))
        );
        ensure!(matches!(unrelated.try_recv(), Err(StateWatchError::Empty)));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outstanding_byte_limit_rejects_before_commit_and_recovers() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let backend =
            Arc::new(RedbStore::open(directory.path().join("backlog.redb"))?.state_backend());
        let path = Path::parse("state://publication/backlog")?;
        let mut watcher = backend.subscribe(&path).await?;
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let waker = Waker::from(Arc::new(BlockingWake {
            entered: entered_tx,
            release: StdMutex::new(release_rx),
            entered_once: AtomicBool::new(false),
        }));
        {
            let mut receive = std::pin::pin!(watcher.recv());
            ensure!(
                receive
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending()
            );
        }

        let value = Value::string("x".repeat(3 * 1024 * 1024));
        let first_backend = Arc::clone(&backend);
        let first_path = path.clone();
        let first_value = value.clone();
        let first =
            tokio::spawn(async move { first_backend.write_set(&first_path, first_value).await });
        tokio::time::timeout(
            Duration::from_secs(10),
            tokio::task::spawn_blocking(move || entered_rx.recv()),
        )
        .await???;

        let first_charge = backend.publication.delivery.lock().outstanding_bytes;
        ensure!(first_charge > 3 * 1024 * 1024);
        backend.write_set(&path, value.clone()).await?;
        let second_charge = backend.publication.delivery.lock().outstanding_bytes;
        ensure!(
            second_charge > first_charge && second_charge <= MAX_OUTSTANDING_NOTIFICATION_BYTES
        );
        let failure = backend
            .write_set(&path, Value::string("third".repeat(1024 * 1024)))
            .await
            .err()
            .context("third write exceeded the byte budget")?;
        ensure!(
            matches!(failure.error, StateError::Backend(message) if message.contains("notification backlog"))
        );
        ensure!(backend.publication.delivery.lock().outstanding_bytes == second_charge);
        ensure!(
            backend
                .read(&path)
                .await?
                .as_ref()
                .and_then(Value::as_str)
                .map(str::len)
                == Some(3 * 1024 * 1024)
        );

        release_tx.send(())?;
        first.await??;
        ensure!(backend.publication.delivery.lock().outstanding_bytes == 0);
        for _ in 0..2 {
            ensure!(
                matches!(watcher.try_recv()?, StateEvent::Set { value, .. } if value.as_str().is_some_and(|text| text.len() == 3 * 1024 * 1024))
            );
        }
        ensure!(matches!(watcher.try_recv(), Err(StateWatchError::Empty)));
        backend.write_set(&path, Value::integer(4)).await?;
        ensure!(
            matches!(watcher.try_recv()?, StateEvent::Set { value, .. } if value.as_int() == Some(4))
        );
        Ok(())
    }
}
