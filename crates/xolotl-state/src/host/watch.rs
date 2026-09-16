//! Lazy subscription registration owned by each returned subscription.

use super::broadcast::BroadcastSubscription;
use crate::{StateError, StateEvent, StateResult, StateStream, StateSubscription, StateWatchError};
use core::{
    num::NonZeroUsize,
    task::{Context, Poll},
};
use parking_lot::Mutex;
use std::{
    collections::BTreeMap,
    sync::{Arc, OnceLock, Weak},
};
use tokio::sync::broadcast;
use xolotl_types::Path;

struct Subscriber {
    pattern: Path,
    sender: broadcast::Sender<StateEvent>,
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
        registry.entries.insert(id, Subscriber { pattern, sender });
        drop(registry);
        Ok(StateStream::new(RegisteredSubscription {
            stream: BroadcastSubscription::new(receiver),
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
    _registration: Registration,
}

impl StateSubscription for RegisteredSubscription {
    fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<StateEvent>, StateWatchError>> {
        self.stream.poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

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
}
