//! Host-owned execution scopes, independent of interpreter request tickets.
//!
//! Sources reserve disjoint ranges before returning them. Persistent sources
//! retain reservations even when execution checkpoints and facts are removed.

use parking_lot::Mutex;
use std::num::NonZeroU64;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use thiserror::Error;
use xolotl_types::ExecutionId;

/// Failure to reserve an execution scope before any work is dispatched.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExecutionIdError {
    /// Every identifier in the source namespace has been reserved.
    #[error("execution identifiers exhausted")]
    Exhausted,
    /// A source returned a range outside the requested bounds.
    #[error("invalid execution identifier range")]
    InvalidRange,
    /// The host could not retain the reservation.
    #[error("execution identifier reservation failed: {0}")]
    Backend(String),
}

/// An inclusive, nonempty range of reserved execution identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionIdRange {
    first: ExecutionId,
    last: ExecutionId,
}

impl ExecutionIdRange {
    /// Describe `count` consecutive identifiers starting at `first`, rejecting overflow.
    /// This validates the range only; the source is responsible for reserving it.
    pub fn new(first: ExecutionId, count: NonZeroU64) -> Result<Self, ExecutionIdError> {
        let last = first
            .get()
            .checked_add(count.get() - 1)
            .and_then(ExecutionId::new)
            .ok_or(ExecutionIdError::InvalidRange)?;
        Ok(Self { first, last })
    }

    /// First reserved identifier.
    pub const fn first(self) -> ExecutionId {
        self.first
    }

    /// Last reserved identifier, included in this range.
    pub const fn last(self) -> ExecutionId {
        self.last
    }

    /// Number of reserved identifiers. A range is never empty.
    pub const fn len(self) -> NonZeroU64 {
        NonZeroU64::MIN.saturating_add(self.last.get() - self.first.get())
    }

    /// A reserved range is always nonempty.
    pub const fn is_empty(self) -> bool {
        false
    }
}

/// Source of unique ranges within one retained identity namespace.
///
/// All hosts sharing that namespace must use this source. Checkpoint restoration
/// reuses the originally reserved identifier. An unrelated source cannot own
/// the same retained checkpoints or externally visible effects.
pub trait ExecutionIdSource: Send + Sync + 'static {
    /// Reserve a nonempty range of at most `count` consecutive identifiers.
    /// A shorter range is allowed at exhaustion. Persistent adapters must durably
    /// retain the reservation before returning; a failed call must issue no ids.
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError>;
}

#[derive(Default)]
struct CachedRange {
    next: Option<ExecutionId>,
    last: u64,
}

struct Allocator {
    source: Arc<dyn ExecutionIdSource>,
    cached: Mutex<CachedRange>,
}

/// Cloneable host adapter that amortizes source reservations across 256 executions.
/// Clones share one cache; independent adapters over the same source reserve
/// disjoint ranges. The interpreter allocates once per execution scope; dynamic
/// request tickets never touch this allocator.
#[derive(Clone)]
pub struct ExecutionIds {
    inner: Arc<Allocator>,
}

impl ExecutionIds {
    /// Wrap a source without allocating an identifier or performing storage I/O.
    pub fn new(source: Arc<dyn ExecutionIdSource>) -> Self {
        Self {
            inner: Arc::new(Allocator {
                source,
                cached: Mutex::new(CachedRange::default()),
            }),
        }
    }

    /// Allocate a fresh scope. Exhaustion and storage failures never wrap or reuse ids.
    pub fn allocate(&self) -> Result<ExecutionId, ExecutionIdError> {
        const BLOCK: NonZeroU64 = NonZeroU64::MIN.saturating_add(255);
        let mut cached = self.inner.cached.lock();
        if cached.next.is_none() {
            let range = self.inner.source.reserve(BLOCK)?;
            if range.len() > BLOCK {
                return Err(ExecutionIdError::InvalidRange);
            }
            cached.next = Some(range.first());
            cached.last = range.last().get();
        }
        let id = cached.next.ok_or(ExecutionIdError::InvalidRange)?;
        cached.next = if id.get() == cached.last {
            None
        } else {
            id.get().checked_add(1).and_then(ExecutionId::new)
        };
        Ok(id)
    }
}

/// In-memory namespace for ephemeral hosts and custom test/storage adapters.
/// The host must retain this source while any of its scopes remain externally visible.
#[derive(Default)]
pub struct InMemoryExecutionIdSource {
    high_water: AtomicU64,
}

impl InMemoryExecutionIdSource {
    /// Create a new, empty namespace.
    pub const fn new() -> Self {
        Self::from_high_water(0)
    }

    /// Start strictly after an externally retained reservation high-water mark.
    /// This is construction-time configuration, not an operation for importing ids
    /// into a source that is already issuing ranges.
    pub const fn from_high_water(high_water: u64) -> Self {
        Self {
            high_water: AtomicU64::new(high_water),
        }
    }
}

impl ExecutionIdSource for InMemoryExecutionIdSource {
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        let first = self
            .high_water
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                (last != u64::MAX).then(|| last.saturating_add(count.get()))
            })
            .map_err(|_last| ExecutionIdError::Exhausted)?
            .checked_add(1)
            .and_then(ExecutionId::new)
            .ok_or(ExecutionIdError::Exhausted)?;
        let available = u64::MAX - first.get() + 1;
        let actual = count.min(NonZeroU64::new(available).ok_or(ExecutionIdError::InvalidRange)?);
        ExecutionIdRange::new(first, actual)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use std::collections::BTreeSet;

    #[test]
    fn ranges_cannot_wrap_and_the_final_identifier_is_usable() -> anyhow::Result<()> {
        let last = ExecutionId::new(u64::MAX).context("missing final id")?;
        ensure!(ExecutionIdRange::new(last, NonZeroU64::MIN)?.last() == last);
        ensure!(ExecutionIdRange::new(last, NonZeroU64::MIN.saturating_add(1)).is_err());
        let ids = ExecutionIds::new(Arc::new(InMemoryExecutionIdSource::from_high_water(
            u64::MAX - 1,
        )));
        ensure!(ids.allocate()? == last);
        ensure!(ids.allocate() == Err(ExecutionIdError::Exhausted));
        Ok(())
    }

    #[test]
    fn concurrent_caches_and_clones_never_overlap() -> anyhow::Result<()> {
        let source = Arc::new(InMemoryExecutionIdSource::new());
        let first = ExecutionIds::new(source.clone());
        let second = ExecutionIds::new(source);
        let results = std::thread::scope(|scope| {
            [first.clone(), first, second.clone(), second]
                .into_iter()
                .map(|ids| {
                    scope.spawn(move || {
                        (0..700)
                            .map(|_| ids.allocate())
                            .collect::<Result<Vec<_>, _>>()
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|task| {
                    task.join()
                        .map_err(|_error| anyhow::anyhow!("allocator worker panicked"))?
                        .map_err(Into::into)
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })?;
        let all: BTreeSet<_> = results.into_iter().flatten().collect();
        ensure!(all.len() == 2800);
        Ok(())
    }

    #[test]
    fn a_failed_reservation_can_be_retried_without_issuing_an_id() -> anyhow::Result<()> {
        struct FailsOnce {
            failed: std::sync::atomic::AtomicBool,
            source: InMemoryExecutionIdSource,
        }
        impl ExecutionIdSource for FailsOnce {
            fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
                if !self.failed.swap(true, Ordering::Relaxed) {
                    return Err(ExecutionIdError::Backend("unavailable".into()));
                }
                self.source.reserve(count)
            }
        }
        let ids = ExecutionIds::new(Arc::new(FailsOnce {
            failed: std::sync::atomic::AtomicBool::new(false),
            source: InMemoryExecutionIdSource::new(),
        }));
        ensure!(matches!(ids.allocate(), Err(ExecutionIdError::Backend(_))));
        ensure!(ids.allocate()? == ExecutionId::FIRST);
        Ok(())
    }
}
