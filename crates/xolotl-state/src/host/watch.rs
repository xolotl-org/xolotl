//! Lazy subscription registration owned by each returned subscription.

use super::broadcast::BroadcastSubscription;
use crate::{StateError, StateEvent, StateResult, StateStream, StateSubscription, StateWatchError};
use core::{
    num::NonZeroUsize,
    task::{Context, Poll, Waker},
};
use parking_lot::Mutex;
use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, OnceLock, Weak},
};
use tokio::sync::broadcast;
use xolotl_types::Path;

struct Subscriber {
    pattern: Path,
    sender: broadcast::Sender<StateEvent>,
    invalidation: Arc<Mutex<InvalidationState>>,
}

#[derive(Default)]
struct InvalidationState {
    invalidated: bool,
    waiter: Option<Waker>,
}

/// Detached subscriptions awaiting wakeup after the caller releases its
/// commit-order lock. Old streams have already been marked invalid when this
/// token is returned; `finish` drops their senders and wakes pending polls.
#[must_use = "call finish after releasing the commit-order lock"]
pub struct WatchInvalidation {
    detached: Vec<Subscriber>,
    waiters: Vec<Waker>,
}

impl WatchInvalidation {
    /// Number of subscriptions invalidated by the notification gap.
    pub fn len(&self) -> usize {
        self.detached.len()
    }

    /// Whether no subscription matched the affected path.
    pub fn is_empty(&self) -> bool {
        self.detached.is_empty()
    }

    /// Drop detached senders and wake old streams outside the commit-order lock.
    /// Each old stream reports one explicit backend error, then closes.
    pub fn finish(self) {
        for subscriber in self.detached {
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(subscriber))) {
                discard_panic(payload);
            }
        }
        for waiter in self.waiters {
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| waiter.wake())) {
                discard_panic(payload);
            }
        }
    }
}

fn discard_panic(payload: Box<dyn std::any::Any + Send>) {
    if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        let _secondary = std::mem::ManuallyDrop::new(secondary);
    }
}

#[derive(Default)]
struct Registry {
    next: u64,
    entries: BTreeMap<u64, Subscriber>,
}

/// Shared host registrations. The first subscription initializes storage.
/// Dropping the registry closes its subscriptions; dropping a subscription
/// immediately removes its registration, without waiting for another write.
#[derive(Default)]
pub struct WatchRegistry {
    inner: OnceLock<Arc<Mutex<Registry>>>,
}

impl WatchRegistry {
    /// Whether any subscription has initialized registration storage.
    pub fn is_initialized(&self) -> bool {
        self.inner.get().is_some()
    }

    /// Number of currently owned registrations, without initializing empty storage.
    pub fn len(&self) -> usize {
        self.inner
            .get()
            .map_or(0, |registry| registry.lock().entries.len())
    }

    /// Whether no subscription currently owns a registration.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Register a path pattern with a bounded broadcast buffer. The returned
    /// stream owns registration removal; slow consumers receive explicit lag.
    /// Invalid buffer capacity or exhausted registration identifiers return an error.
    pub fn subscribe(&self, pattern: Path, capacity: NonZeroUsize) -> StateResult<StateStream> {
        if capacity.get() > usize::MAX / 2 {
            return Err(
                StateError::Backend("state subscription capacity is too large".into()).into(),
            );
        }
        let shared = self
            .inner
            .get_or_init(|| Arc::new(Mutex::new(Registry::default())));
        let mut registry = shared.lock();
        let id = registry.next;
        registry.next = id.checked_add(1).ok_or_else(|| {
            StateError::Backend("state subscription identifiers exhausted".into())
        })?;
        let (sender, receiver) = broadcast::channel(capacity.get());
        let invalidation = Arc::new(Mutex::new(InvalidationState::default()));
        registry.entries.insert(
            id,
            Subscriber {
                pattern,
                sender,
                invalidation: Arc::clone(&invalidation),
            },
        );
        drop(registry);
        Ok(StateStream::new(RegisteredSubscription {
            stream: BroadcastSubscription::new(receiver),
            invalidation,
            invalidation_reported: false,
            _registration: Registration {
                registry: Arc::downgrade(shared),
                id,
            },
        }))
    }

    /// Capture delivery targets while the caller holds its commit-order lock.
    /// Sending happens after all caller and registry locks have been released.
    pub fn matching(&self, path: &Path) -> Vec<broadcast::Sender<StateEvent>> {
        let Some(registry) = self.inner.get() else {
            return Vec::new();
        };
        registry
            .lock()
            .entries
            .values()
            .filter(|subscriber| path.matches(&subscriber.pattern))
            .map(|subscriber| subscriber.sender.clone())
            .collect()
    }

    /// Invalidate subscriptions observing a path after delivery becomes
    /// unreliable. The caller holds its commit-order lock while calling this
    /// method, then releases that lock before calling `finish` on the token.
    /// Matching registrations are atomically detached; later subscriptions are
    /// unaffected. Captured senders from earlier publications cannot make an
    /// invalidated stream deliver another event.
    pub fn invalidate_matching(&self, path: &Path) -> WatchInvalidation {
        let Some(registry) = self.inner.get() else {
            return WatchInvalidation {
                detached: Vec::new(),
                waiters: Vec::new(),
            };
        };
        let mut registry = registry.lock();
        let matching: Vec<_> = registry
            .entries
            .iter()
            .filter(|(_, subscriber)| path.matches(&subscriber.pattern))
            .map(|(id, _)| *id)
            .collect();
        let mut detached = Vec::with_capacity(matching.len());
        for id in matching {
            let Some(subscriber) = registry.entries.remove(&id) else {
                continue;
            };
            detached.push(subscriber);
        }
        Self::invalidate_subscribers(detached)
    }

    /// Detach every current registration after a shared backend recovery failure.
    /// Later registrations remain possible; the backend owns their admission.
    /// Release caller locks before finishing the returned wakeup token.
    pub fn invalidate_all(&self) -> WatchInvalidation {
        let Some(registry) = self.inner.get() else {
            return WatchInvalidation {
                detached: Vec::new(),
                waiters: Vec::new(),
            };
        };
        let subscribers = std::mem::take(&mut registry.lock().entries)
            .into_values()
            .collect();
        Self::invalidate_subscribers(subscribers)
    }

    fn invalidate_subscribers(detached: Vec<Subscriber>) -> WatchInvalidation {
        let mut waiters = Vec::with_capacity(detached.len());
        for subscriber in &detached {
            let mut state = subscriber.invalidation.lock();
            state.invalidated = true;
            if let Some(waiter) = state.waiter.take() {
                waiters.push(waiter);
            }
        }
        WatchInvalidation { detached, waiters }
    }
}

struct Registration {
    registry: Weak<Mutex<Registry>>,
    id: u64,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            let removed = registry.lock().entries.remove(&self.id);
            drop(removed);
        }
    }
}

struct RegisteredSubscription {
    stream: BroadcastSubscription,
    invalidation: Arc<Mutex<InvalidationState>>,
    invalidation_reported: bool,
    _registration: Registration,
}

impl StateSubscription for RegisteredSubscription {
    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<StateEvent>, StateWatchError>> {
        if self.invalidation_reported {
            return Poll::Ready(Ok(None));
        }
        {
            let mut state = self.invalidation.lock();
            if state.invalidated {
                self.invalidation_reported = true;
                return Poll::Ready(Err(StateWatchError::Invalidated));
            }
            state.waiter = Some(cx.waker().clone());
        }
        let result = self.stream.poll_next(cx);
        {
            let mut state = self.invalidation.lock();
            if state.invalidated {
                self.invalidation_reported = true;
                return Poll::Ready(Err(StateWatchError::Invalidated));
            }
            if result.is_ready() {
                state.waiter = None;
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Wake;

    struct CountingWake(AtomicUsize);

    impl Wake for CountingWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct PanickingWake;

    impl Wake for PanickingWake {
        fn wake(self: Arc<Self>) {
            std::panic::resume_unwind(Box::new("subscriber waker failed"));
        }

        fn wake_by_ref(self: &Arc<Self>) {
            std::panic::resume_unwind(Box::new("subscriber waker failed"));
        }
    }

    fn event(path: &Path) -> StateEvent {
        StateEvent::Set {
            path: path.clone(),
            value: xolotl_types::Value::integer(1),
            taint: xolotl_types::TaintSet::pristine(),
        }
    }

    #[tokio::test]
    async fn registration_lifetime_does_not_depend_on_later_writes() -> anyhow::Result<()> {
        let registry = WatchRegistry::default();
        ensure!(!registry.is_initialized());
        let path = Path::parse("state://watch")?;
        for _ in 0..128 {
            let subscription = registry.subscribe(path.clone(), NonZeroUsize::MIN)?;
            ensure!(registry.len() == 1);
            drop(subscription);
            ensure!(registry.is_empty());
            ensure!(registry.matching(&path).is_empty());
        }
        let mut subscription = registry.subscribe(path, NonZeroUsize::MIN)?;
        drop(registry);
        ensure!(matches!(
            subscription.recv().await,
            Err(StateWatchError::Closed)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn uncertain_commit_invalidates_only_old_matching_streams() -> anyhow::Result<()> {
        let registry = WatchRegistry::default();
        let pattern = Path::parse("state://watch/**")?;
        let path = Path::parse("state://watch/item")?;
        let unrelated_path = Path::parse("state://else/item")?;
        let mut old = registry.subscribe(pattern.clone(), NonZeroUsize::MIN)?;
        let mut unrelated = registry.subscribe(unrelated_path.clone(), NonZeroUsize::MIN)?;
        let retained_sender = registry.matching(&path);
        ensure!(retained_sender.len() == 1);

        let wakes = Arc::new(CountingWake(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&wakes));
        ensure!(matches!(
            old.poll_next(&mut Context::from_waker(&waker)),
            Poll::Pending
        ));
        let invalidation = registry.invalidate_matching(&path);
        ensure!(invalidation.len() == 1 && registry.len() == 1);
        let mut fresh = registry.subscribe(pattern, NonZeroUsize::MIN)?;
        ensure!(wakes.0.load(Ordering::SeqCst) == 0);
        invalidation.finish();
        ensure!(wakes.0.load(Ordering::SeqCst) != 0);

        // A publication captured before invalidation may still hold a sender.
        ensure!(retained_sender[0].send(event(&path)).is_ok());
        ensure!(matches!(old.try_recv(), Err(StateWatchError::Invalidated)));
        ensure!(matches!(old.try_recv(), Err(StateWatchError::Closed)));
        ensure!(matches!(unrelated.try_recv(), Err(StateWatchError::Empty)));

        let current = registry.matching(&path);
        ensure!(current.len() == 1 && current[0].send(event(&path)).is_ok());
        ensure!(matches!(fresh.try_recv(), Ok(StateEvent::Set { .. })));
        let other = registry.matching(&unrelated_path);
        ensure!(other.len() == 1 && other[0].send(event(&unrelated_path)).is_ok());
        ensure!(matches!(unrelated.try_recv(), Ok(StateEvent::Set { .. })));
        Ok(())
    }

    #[tokio::test]
    async fn panicking_waker_cannot_hide_other_invalidations() -> anyhow::Result<()> {
        let registry = WatchRegistry::default();
        let path = Path::parse("state://watch/wake")?;
        let mut bad = registry.subscribe(path.clone(), NonZeroUsize::MIN)?;
        let mut good = registry.subscribe(path.clone(), NonZeroUsize::MIN)?;
        let bad_waker = Waker::from(Arc::new(PanickingWake));
        let wakes = Arc::new(CountingWake(AtomicUsize::new(0)));
        let good_waker = Waker::from(Arc::clone(&wakes));
        ensure!(matches!(
            bad.poll_next(&mut Context::from_waker(&bad_waker)),
            Poll::Pending
        ));
        ensure!(matches!(
            good.poll_next(&mut Context::from_waker(&good_waker)),
            Poll::Pending
        ));

        registry.invalidate_matching(&path).finish();
        ensure!(wakes.0.load(Ordering::SeqCst) != 0);
        ensure!(matches!(bad.try_recv(), Err(StateWatchError::Invalidated)));
        ensure!(matches!(good.try_recv(), Err(StateWatchError::Invalidated)));
        Ok(())
    }
}
