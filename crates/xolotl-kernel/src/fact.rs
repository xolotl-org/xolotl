//! `FactSink` records operation Facts with ReplayClass-graded persistence barriers.

use crate::execution_ids::{
    ExecutionIdError, ExecutionIdRange, ExecutionIdSource, ExecutionIds, InMemoryExecutionIdSource,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;
use xolotl_types::{Fact, OperationId};

mod lookup;
mod scan;
pub use lookup::{FactLookup, FactLookupResult};
pub use scan::{FactOrder, FactPage, FactQuery};

/// A fact-store failure, including persistence, corruption and read-budget errors.
/// The kernel maps a **pre-effect** write failure to a denied operation —
/// prevents the effect and logs a **post-effect** failure for crash recovery to
/// reconcile from the fsync'd pending record. Read failures propagate so recovery
/// cannot mistake unavailable data for an empty stream.
#[derive(Debug, Error)]
#[error("fact store failed: {0}")]
pub struct FactError(pub String);

/// Push subscription to new facts and outcome updates after subscription creation.
pub type FactStream = broadcast::Receiver<Arc<Fact>>;

/// Capacity of the in-memory fact broadcast channel.
pub const FACT_BROADCAST_CAPACITY: usize = 256;

/// Pluggable durable sink. The in-memory impl is the default; redb provides a
/// persistent one. The kernel speaks only this trait. Read failures are
/// surfaced so corrupted Fact storage is never treated as an empty stream.
pub trait FactStore: ExecutionIdSource {
    /// Append a (possibly pending) fact once per full `OperationId`.
    /// Repeated appends return the original slot and retain its record without
    /// publishing another notification, including when it has completed. Use
    /// `complete` to add an outcome. Only distinct ids advance the append cursor;
    /// failed writes leave the cursor unchanged.
    fn append(&self, fact: Fact) -> Result<u64, FactError>;
    /// Store an outcome in the existing slot, or append if no begin was recorded.
    fn complete(&self, fact: Fact) -> Result<(), FactError>;
    /// Force durability up to the current cursor (fsync). Called for
    /// write-ahead barriers.
    fn sync(&self) -> Result<(), FactError>;
    /// Read in the requested append order, bounding candidates, returned records
    /// and encoded bytes before cloning or decoding, without materializing history.
    /// See [`FactQuery`] for cursor, filtering and concurrent-update semantics.
    fn scan(&self, query: FactQuery) -> Result<FactPage, FactError>;
    /// Indexed lookup that filters the current caller before checking encoded
    /// size or cloning/decoding. All decisions use one storage view.
    /// Missing and nonmatching records are distinct; oversized matches error.
    fn lookup(&self, query: FactLookup) -> Result<FactLookupResult, FactError>;
    /// Indexed convenience lookup for any caller with an encoded-byte budget.
    #[inline]
    fn get_bounded(
        &self,
        id: OperationId,
        max_encoded_bytes: NonZeroUsize,
    ) -> Result<Option<Fact>, FactError> {
        let query = FactLookup::new(id, max_encoded_bytes);
        let result = self.lookup(query)?;
        result.validate(query)?;
        result.into_unfiltered()
    }
    /// Indexed convenience lookup without a per-record byte limit.
    #[inline]
    fn get(&self, id: OperationId) -> Result<Option<Fact>, FactError> {
        self.get_bounded(id, NonZeroUsize::MAX)
    }
    /// All facts for one process, in append order. Materializes the full result;
    /// use [`Self::scan`] when history size is not bounded by the caller.
    fn facts_of(&self, process: xolotl_types::ProcessId) -> Result<Vec<Fact>, FactError>;
    /// All facts, in append order. Materializes the full retained history.
    fn all_facts(&self) -> Result<Vec<Fact>, FactError>;
    /// The locally observed monotonic append cursor. Independent adapters may
    /// observe different heads; [`Self::scan`] captures an authoritative head.
    /// Completion updates old slots without advancing this cursor.
    fn cursor(&self) -> u64;
    /// Subscribe to appends and outcome updates. Notifications may arrive out
    /// of commit order: treat them as invalidations and use [`Self::lookup`] for
    /// the current record, applying the caller filter before its byte budget.
    /// The receiver is bounded; after lag, rescan the entire
    /// retained interval, including old slots whose outcomes may have changed.
    /// The default returns a closed receiver, so test stores
    /// that do not exercise subscription need no override.
    fn subscribe_facts(&self) -> FactStream {
        let (_tx, rx) = broadcast::channel::<Arc<Fact>>(1);
        rx
    }
}

/// In-memory fact store. Tracks append order and a fsync counter so tests can
/// assert "only NonIdempotentEffect takes a barrier".
pub struct InMemoryFactStore {
    inner: Mutex<FactStoreInner>,
    tx: broadcast::Sender<Arc<Fact>>,
    execution_ids: InMemoryExecutionIdSource,
}

impl Default for InMemoryFactStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct FactStoreInner {
    facts: Vec<Fact>,
    /// op id → index into `facts` (for `complete`).
    index: HashMap<OperationId, usize>,
    cursor: u64,
    sync_count: u64,
}

impl InMemoryFactStore {
    /// Create an empty in-memory fact store.
    pub fn new() -> Self {
        Self::with_capacity(FACT_BROADCAST_CAPACITY)
    }

    /// Create an empty in-memory fact store with a custom broadcast capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self {
            inner: Mutex::new(FactStoreInner::default()),
            tx,
            execution_ids: InMemoryExecutionIdSource::new(),
        }
    }

    /// Number of fsyncs issued so far — used to verify the barrier discipline.
    pub fn sync_count(&self) -> u64 {
        self.inner.lock().sync_count
    }

    /// Number of facts currently retained in memory.
    pub fn len(&self) -> usize {
        self.inner.lock().facts.len()
    }

    /// Whether no facts have been appended.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn broadcast_fact(tx: &broadcast::Sender<Arc<Fact>>, fact: Arc<Fact>) {
    match tx.send(fact) {
        Ok(_receivers) => {}
        Err(_error) => {
            // No active receiver kept the fact; storage has already accepted it.
        }
    }
}

impl ExecutionIdSource for InMemoryFactStore {
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        self.execution_ids.reserve(count)
    }
}

impl FactStore for InMemoryFactStore {
    fn append(&self, fact: Fact) -> Result<u64, FactError> {
        let shared = Arc::new(fact);
        let pos = {
            let mut inner = self.inner.lock();
            if let Some(&index) = inner.index.get(&shared.id) {
                return u64::try_from(index)
                    .map_err(|_error| FactError("fact cursor overflow".into()));
            }
            let pos = inner.cursor;
            inner.cursor = inner
                .cursor
                .checked_add(1)
                .ok_or_else(|| FactError("fact cursor overflow".into()))?;
            let idx = inner.facts.len();
            inner.index.insert(shared.id, idx);
            inner.facts.push((*shared).clone());
            pos
        };
        broadcast_fact(&self.tx, shared);
        Ok(pos)
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        let shared = Arc::new(fact);
        {
            let mut inner = self.inner.lock();
            if let Some(&idx) = inner.index.get(&shared.id) {
                inner.facts[idx] = (*shared).clone();
            } else {
                inner.cursor = inner
                    .cursor
                    .checked_add(1)
                    .ok_or_else(|| FactError("fact cursor overflow".into()))?;
                let idx = inner.facts.len();
                inner.index.insert(shared.id, idx);
                inner.facts.push((*shared).clone());
            }
        }
        broadcast_fact(&self.tx, shared);
        Ok(())
    }

    fn sync(&self) -> Result<(), FactError> {
        self.inner.lock().sync_count += 1;
        Ok(())
    }

    fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        let inner = self.inner.lock();
        scan::scan_memory(&inner.facts, inner.cursor, query)
    }

    fn lookup(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        let inner = self.inner.lock();
        let Some(&slot) = inner.index.get(&query.id) else {
            return Ok(FactLookupResult::Missing);
        };
        let fact = &inner.facts[slot];
        if query.process.is_some_and(|process| process != fact.caller) {
            return Ok(FactLookupResult::FilteredOut);
        }
        if query.max_encoded_bytes != NonZeroUsize::MAX
            && scan::encoded_size(fact, query.max_encoded_bytes.get())?.is_none()
        {
            return Err(FactError(format!(
                "fact at slot {slot} exceeds encoded byte limit {}",
                query.max_encoded_bytes
            )));
        }
        Ok(FactLookupResult::Found(fact.clone()))
    }

    fn facts_of(&self, process: xolotl_types::ProcessId) -> Result<Vec<Fact>, FactError> {
        Ok(self
            .inner
            .lock()
            .facts
            .iter()
            .filter(|f| f.caller == process)
            .cloned()
            .collect())
    }

    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        Ok(self.inner.lock().facts.clone())
    }

    fn cursor(&self) -> u64 {
        self.inner.lock().cursor
    }

    fn subscribe_facts(&self) -> FactStream {
        self.tx.subscribe()
    }
}

/// Shared fact store handle.
pub type SharedFactStore = Arc<dyn FactStore>;

/// The kernel-facing sink: wraps a [`FactStore`] and applies the
/// ReplayClass-graded barrier discipline.
#[derive(Clone)]
pub struct FactSink {
    store: SharedFactStore,
    execution_ids: ExecutionIds,
}

impl FactSink {
    /// Wrap a shared fact store in the kernel-facing sink.
    pub fn new(store: SharedFactStore) -> Self {
        Self {
            execution_ids: ExecutionIds::new(store.clone()),
            store,
        }
    }

    /// Create a sink backed by an in-memory fact store and return both handles.
    pub fn in_memory() -> (Self, Arc<InMemoryFactStore>) {
        let store = Arc::new(InMemoryFactStore::new());
        (Self::new(store.clone()), store)
    }

    /// Shared execution allocator for hosts using this fact store's identity namespace.
    pub fn execution_ids(&self) -> ExecutionIds {
        self.execution_ids.clone()
    }

    /// Begin recording an operation *before* the driver call.
    /// For `NonIdempotentEffect` this writes-ahead and fsyncs (the only class
    /// that does); other classes append in memory. A failure here is reported to
    /// the caller, which **must not** issue the effect.
    pub fn begin(&self, pending: Fact) -> Result<(), FactError> {
        validate_fact_schema(&pending)?;
        let needs_barrier = pending.replay.needs_write_ahead_barrier();
        self.store.append(pending)?;
        if needs_barrier {
            self.store.sync()?;
        }
        Ok(())
    }

    /// Complete an operation's record after the driver returns.
    /// `NonIdempotentEffect` fsyncs again; others ride group commit.
    pub fn complete(&self, fact: Fact) -> Result<(), FactError> {
        validate_fact_schema(&fact)?;
        let needs_barrier = fact.replay.needs_write_ahead_barrier();
        self.store.complete(fact)?;
        if needs_barrier {
            self.store.sync()?;
        }
        Ok(())
    }

    /// Access the underlying shared fact store.
    pub fn store(&self) -> &SharedFactStore {
        &self.store
    }

    /// Read a page subject to its record, candidate and encoded-byte limits.
    /// Rejects structurally invalid pages returned by a custom adapter.
    pub fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        let page = self.store.scan(query)?;
        page.validate(query)?;
        Ok(page)
    }

    /// Read one current record by its full operation identity, without a byte limit.
    #[inline]
    pub fn get(&self, id: OperationId) -> Result<Option<Fact>, FactError> {
        self.get_bounded(id, NonZeroUsize::MAX)
    }

    /// Read one indexed record with a current-caller filter and byte budget.
    /// Rejects nonmatching records or invalid absence states from an adapter.
    #[inline]
    pub fn lookup(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        let result = self.store.lookup(query)?;
        result.validate(query)?;
        Ok(result)
    }

    /// Indexed lookup with an encoded-byte budget enforced before allocation.
    #[inline]
    pub fn get_bounded(
        &self,
        id: OperationId,
        max_encoded_bytes: NonZeroUsize,
    ) -> Result<Option<Fact>, FactError> {
        self.lookup(FactLookup::new(id, max_encoded_bytes))?
            .into_unfiltered()
    }

    /// Materialize all facts for `process` in append order, without a size limit.
    pub fn facts_of(&self, process: xolotl_types::ProcessId) -> Result<Vec<Fact>, FactError> {
        self.store.facts_of(process)
    }

    /// Materialize all retained facts in append order, without a size limit.
    pub fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        self.store.all_facts()
    }

    /// Current append cursor of the underlying fact store.
    pub fn cursor(&self) -> u64 {
        self.store.cursor()
    }
}

fn validate_fact_schema(fact: &Fact) -> Result<(), FactError> {
    if fact.schema_version == Fact::SCHEMA_VERSION {
        Ok(())
    } else {
        Err(FactError(format!(
            "unsupported Fact schema_version {} (current {})",
            fact.schema_version,
            Fact::SCHEMA_VERSION
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{bail, ensure};
    use xolotl_types::{
        DecisionTag, ExecutionId, HandleId, IdentityRef, InvocationId, MethodId, NodeId, ProcessId,
        ReplayClass, ResourceId, Timestamp, Value,
    };

    pub(super) fn fact(process: u64, pos: u32, replay: ReplayClass) -> Fact {
        Fact {
            id: OperationId::new(
                ProcessId::new(process),
                ExecutionId::FIRST,
                InvocationId::new(1),
                NodeId::new(pos),
                0,
            ),
            schema_version: Fact::SCHEMA_VERSION,
            caller: ProcessId::new(process),
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(1),
            method: MethodId::new(0),
            input: Value::null(),
            taint: xolotl_types::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome: Some(Value::integer(1)),
            batch: None,
            replay,
            timestamp: Timestamp::millis(0),
        }
    }

    #[test]
    fn only_non_idempotent_effect_fsyncs() -> anyhow::Result<()> {
        let (sink, store) = FactSink::in_memory();
        // Deterministic / Observation / Idempotent: no barrier.
        sink.begin(fact(1, 0, ReplayClass::Deterministic))?;
        sink.complete(fact(1, 0, ReplayClass::Deterministic))?;
        sink.begin(fact(1, 1, ReplayClass::Observation))?;
        sink.complete(fact(1, 1, ReplayClass::Observation))?;
        sink.begin(fact(1, 2, ReplayClass::IdempotentEffect))?;
        sink.complete(fact(1, 2, ReplayClass::IdempotentEffect))?;
        ensure!(
            store.sync_count() == 0,
            "replay-safe classes should not fsync"
        );

        // NonIdempotentEffect: fsync at begin and complete.
        sink.begin(fact(1, 3, ReplayClass::NonIdempotentEffect))?;
        sink.complete(fact(1, 3, ReplayClass::NonIdempotentEffect))?;
        ensure!(
            store.sync_count() == 2,
            "non-idempotent effect fsync count mismatch"
        );
        Ok(())
    }

    #[test]
    fn facts_of_filters_by_process() -> anyhow::Result<()> {
        let (sink, _) = FactSink::in_memory();
        sink.begin(fact(1, 0, ReplayClass::Deterministic))?;
        sink.begin(fact(2, 0, ReplayClass::Deterministic))?;
        let facts = sink.facts_of(ProcessId::new(1))?;
        ensure!(
            facts.len() == 1,
            "unexpected process fact count: {}",
            facts.len()
        );
        Ok(())
    }

    #[test]
    fn fact_sink_rejects_unknown_schema_version() -> anyhow::Result<()> {
        let (sink, _) = FactSink::in_memory();
        let mut f = fact(1, 0, ReplayClass::Deterministic);
        f.schema_version = Fact::SCHEMA_VERSION + 1;
        let err = match sink.begin(f) {
            Ok(()) => bail!("expected schema error"),
            Err(err) => err,
        };
        ensure!(
            err.0.contains("unsupported Fact schema_version"),
            "unexpected FactSink error: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn subscribe_facts_delivers_appended_facts() -> anyhow::Result<()> {
        let store = Arc::new(InMemoryFactStore::new());
        let mut rx = store.subscribe_facts();
        store.append(fact(1, 0, ReplayClass::Deterministic))?;
        store.append(fact(1, 1, ReplayClass::Observation))?;
        let first = rx
            .recv()
            .await
            .map_err(|e| anyhow::anyhow!("recv1: {e:?}"))?;
        let second = rx
            .recv()
            .await
            .map_err(|e| anyhow::anyhow!("recv2: {e:?}"))?;
        ensure!(
            first.id == fact(1, 0, ReplayClass::Deterministic).id,
            "first fact mismatch"
        );
        ensure!(
            second.id == fact(1, 1, ReplayClass::Observation).id,
            "second fact mismatch"
        );
        ensure!(store.cursor() == 2, "cursor should have advanced twice");
        Ok(())
    }

    #[test]
    fn dropped_fact_subscription_does_not_fail_writes() -> anyhow::Result<()> {
        let store = InMemoryFactStore::new();
        let rx = store.subscribe_facts();
        drop(rx);
        store.append(fact(1, 0, ReplayClass::Deterministic))?;
        store.complete(fact(1, 1, ReplayClass::Observation))?;
        ensure!(
            store.cursor() == 2,
            "fresh complete should advance the cursor"
        );
        ensure!(store.len() == 2, "facts should still be retained");
        Ok(())
    }

    #[test]
    fn independent_sinks_over_one_store_reserve_disjoint_execution_ranges() -> anyhow::Result<()> {
        let store = Arc::new(InMemoryFactStore::new());
        let first = FactSink::new(store.clone());
        let second = FactSink::new(store.clone());
        let shared = first.clone();
        let a = first.execution_ids().allocate()?;
        let b = shared.execution_ids().allocate()?;
        let c = second.execution_ids().allocate()?;
        ensure!(a.get() == 1 && b.get() == 2 && c.get() == 257);
        ensure!(store.is_empty(), "reserving scopes should not create facts");
        Ok(())
    }

    #[test]
    fn repeated_append_retains_the_original_slot_and_never_downgrades_completion()
    -> anyhow::Result<()> {
        let store = InMemoryFactStore::new();
        let mut events = store.subscribe_facts();
        let completed = fact(1, 0, ReplayClass::IdempotentEffect);
        let mut pending = completed.clone();
        pending.outcome = None;
        ensure!(store.append(pending.clone())? == 0);
        ensure!(*events.try_recv()? == pending);
        let mut refreshed = pending.clone();
        refreshed.timestamp = Timestamp::millis(100);
        ensure!(store.append(refreshed.clone())? == 0);
        ensure!(
            events.try_recv().is_err(),
            "duplicate append published an event"
        );
        ensure!(store.all_facts()? == [pending]);
        store.complete(completed.clone())?;
        ensure!(*events.try_recv()? == completed);
        ensure!(store.append(refreshed)? == 0);
        ensure!(
            events.try_recv().is_err(),
            "pending replay published after completion"
        );
        let next = fact(1, 1, ReplayClass::IdempotentEffect);
        ensure!(store.append(next.clone())? == 1);
        ensure!(store.all_facts()? == [completed, next]);
        ensure!(store.cursor() == 2);
        Ok(())
    }
}
