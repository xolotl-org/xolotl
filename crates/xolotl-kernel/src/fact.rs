//! `FactSink` records optional operation observations using the backend's commit policy.

use crate::execution_ids::{
    ExecutionIdError, ExecutionIdRange, ExecutionIdSource, ExecutionIds, InMemoryExecutionIdSource,
};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;
use tokio::sync::broadcast;
use xolotl_types::{Fact, OperationId};

mod disabled;
mod lookup;
mod scan;
#[cfg(test)]
pub(crate) mod testing;
pub use lookup::{FactLookup, FactLookupResult};
pub use scan::{FactOrder, FactPage, FactQuery};

/// A fact-store failure, including persistence, corruption and read-budget errors.
/// For explicitly recorded calls, a pre-effect write failure prevents dispatch.
/// A post-effect failure is reported separately from the actual driver outcome;
/// the selected backend determines whether the observation committed.
/// Read failures never become an empty observation stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactErrorKind {
    /// A generic failure; this category alone does not prove an effect absent.
    Other,
    /// A commit returned an error after it may have become durable.
    CommitOutcomeUnknown,
    /// The adapter is closed until a new instance reconciles an earlier commit.
    ReopenRequired,
}

/// A Fact failure with a machine-readable recovery category and diagnostic text.
#[derive(Debug, Error)]
#[error("fact store failed: {message}")]
pub struct FactError {
    kind: FactErrorKind,
    message: String,
}

impl FactError {
    /// Construct a generic failure without a specialized recovery category.
    pub fn new(message: String) -> Self {
        Self {
            kind: FactErrorKind::Other,
            message,
        }
    }

    /// Report that a commit may have become durable despite its error.
    pub fn commit_outcome_unknown(message: String) -> Self {
        Self {
            kind: FactErrorKind::CommitOutcomeUnknown,
            message,
        }
    }

    /// Reject use of an adapter whose previous commit requires reconciliation.
    pub fn reopen_required(message: String) -> Self {
        Self {
            kind: FactErrorKind::ReopenRequired,
            message,
        }
    }

    /// Recovery action indicated by this failure.
    pub const fn kind(&self) -> FactErrorKind {
        self.kind
    }

    /// Diagnostic text; public adapters must not expose it to untrusted clients.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Push subscription to new facts and outcome updates after subscription creation.
pub type FactStream = broadcast::Receiver<Arc<Fact>>;

/// Capacity of the in-memory fact broadcast channel.
pub const FACT_BROADCAST_CAPACITY: usize = 256;

/// Pluggable, explicitly installed observation sink. The kernel speaks only
/// this trait. Read failures are
/// surfaced so corrupted Fact storage is never treated as an empty stream.
pub trait FactStore: Send + Sync + 'static {
    /// Whether observation storage is installed. Disabled stores reject writes
    /// and checked reads; they must not report a successful empty history.
    fn is_enabled(&self) -> bool {
        true
    }
    /// Append a (possibly pending) fact once per full `OperationId`.
    /// Repeated appends return the original slot and retain its record without
    /// publishing another notification, including when it has completed. Use
    /// `complete` to add an outcome. Only distinct ids advance the append cursor;
    /// writes known not to have committed leave the cursor unchanged. If the
    /// commit outcome is unknown, the returned error does not prove absence;
    /// a backend may refresh its locally observed cursor from storage.
    fn append(&self, fact: Fact) -> Result<u64, FactError>;
    /// Store an outcome in the existing slot, or append if no begin was recorded.
    fn complete(&self, fact: Fact) -> Result<(), FactError>;
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
    /// Return the local append cursor only while this adapter can certify that
    /// it has not lost a commit outcome. Callers using the cursor as a response
    /// revision must propagate an error rather than present a stale hint.
    /// This is still an append cursor, not a completion revision or snapshot.
    /// Persistent adapters with indeterminate commits must override the default.
    fn observed_cursor(&self) -> Result<u64, FactError> {
        Ok(self.cursor())
    }
    /// Subscribe to appends and outcome updates. Notifications may arrive out
    /// of commit order: treat them as invalidations and use [`Self::lookup`] for
    /// the current record, applying the caller filter before its byte budget.
    /// The receiver is bounded; after lag, rescan the entire
    /// retained interval, including old slots whose outcomes may have changed.
    /// A backend may close the stream after an uncertain commit; consumers
    /// must reopen the store and rescan instead of waiting for another event.
    /// The default returns a closed receiver, so test stores
    /// that do not exercise subscription need no override.
    fn subscribe_facts(&self) -> FactStream {
        let (_tx, rx) = broadcast::channel::<Arc<Fact>>(1);
        rx
    }
}

impl dyn FactStore {
    /// Read a page and reject a backend response that violates its filter,
    /// cursor or budgets before exposing it to callers. This check cannot be
    /// overridden by a storage adapter.
    pub fn scan_checked(&self, query: FactQuery) -> Result<FactPage, FactError> {
        let page = self.scan(query)?;
        page.validate(query)?;
        Ok(page)
    }

    /// Read an indexed record and reject an adapter result that violates its
    /// identity, caller filter or byte budget.
    pub fn lookup_checked(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        let result = self.lookup(query)?;
        result.validate(query)?;
        Ok(result)
    }
}

/// Explicit observation retention limits. Charges cover encoded records, not
/// allocator capacity, indexes, shared payload residency or process RSS.
/// Capacity rejection leaves records, append positions and notifications intact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactRetentionLimits {
    /// Maximum distinct retained operation records.
    pub max_records: NonZeroUsize,
    /// Maximum aggregate JSON-encoded size of retained records.
    pub max_encoded_bytes: NonZeroUsize,
    /// Maximum JSON-encoded size of one record, including completion.
    pub max_record_bytes: NonZeroUsize,
}

impl Default for FactRetentionLimits {
    fn default() -> Self {
        Self {
            max_records: NonZeroUsize::MIN.saturating_add(4095),
            max_encoded_bytes: NonZeroUsize::MIN.saturating_add(64 * 1024 * 1024 - 1),
            max_record_bytes: NonZeroUsize::MIN.saturating_add(1024 * 1024 - 1),
        }
    }
}

impl FactRetentionLimits {
    /// Reject a single-record budget larger than its aggregate budget.
    pub fn validate(self) -> Result<(), FactError> {
        if self.max_record_bytes > self.max_encoded_bytes {
            return Err(FactError::new(
                "fact record limit exceeds retention budget".into(),
            ));
        }
        Ok(())
    }
}

/// Retention charge from one consistent store view; excludes indexes and RSS.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FactRetentionUsage {
    /// Distinct retained operation records.
    pub records: usize,
    /// Aggregate JSON-encoded size of those records.
    pub encoded_bytes: usize,
}

/// Bounded in-memory observation storage. Existing identities remain readable
/// and duplicate begins do not recharge capacity. Completion replaces a record
/// atomically and must fit the retained-byte budget before publishing.
pub struct InMemoryFactStore {
    inner: Mutex<FactStoreInner>,
    tx: broadcast::Sender<Arc<Fact>>,
    execution_ids: InMemoryExecutionIdSource,
    limits: FactRetentionLimits,
}

impl Default for InMemoryFactStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Default)]
struct FactStoreInner {
    facts: Vec<Fact>,
    sizes: Vec<usize>,
    encoded_bytes: usize,
    /// op id → index into `facts` (for `complete`).
    index: HashMap<OperationId, usize>,
    cursor: u64,
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
            limits: FactRetentionLimits::default(),
        }
    }

    /// Create empty observation storage with validated explicit retention limits.
    pub fn with_limits(limits: FactRetentionLimits) -> Result<Self, FactError> {
        limits.validate()?;
        Ok(Self {
            limits,
            ..Self::new()
        })
    }

    /// Retention limits fixed for this store's lifetime.
    pub fn limits(&self) -> FactRetentionLimits {
        self.limits
    }

    /// Current retained charge from one consistent view.
    pub fn usage(&self) -> FactRetentionUsage {
        let inner = self.inner.lock();
        FactRetentionUsage {
            records: inner.facts.len(),
            encoded_bytes: inner.encoded_bytes,
        }
    }

    fn record_size(&self, fact: &Fact) -> Result<usize, FactError> {
        scan::encoded_size(fact, self.limits.max_record_bytes.get())?
            .ok_or_else(|| FactError::new("fact record capacity exceeded".into()))
    }

    fn admit_size(
        &self,
        inner: &FactStoreInner,
        size: usize,
        previous: Option<usize>,
    ) -> Result<usize, FactError> {
        if previous.is_none() && inner.facts.len() >= self.limits.max_records.get() {
            return Err(FactError::new("fact record capacity exceeded".into()));
        }
        inner
            .encoded_bytes
            .checked_sub(previous.unwrap_or(0))
            .and_then(|bytes| bytes.checked_add(size))
            .filter(|bytes| *bytes <= self.limits.max_encoded_bytes.get())
            .ok_or_else(|| FactError::new("fact retained byte capacity exceeded".into()))
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

fn broadcast_fact(tx: &broadcast::Sender<Arc<Fact>>, fact: Option<Arc<Fact>>) {
    let Some(fact) = fact else {
        return;
    };
    // Delivery follows the storage commit and runs outside its lock. A receiver
    // registered in between may see this older invalidation; subscribers must
    // look up current storage state rather than infer commit order from delivery.
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
        if let Some(index) = self.inner.lock().index.get(&fact.id).copied() {
            return u64::try_from(index)
                .map_err(|_error| FactError::new("fact cursor overflow".into()));
        }
        let size = self.record_size(&fact)?;
        let (pos, notification) = {
            let mut inner = self.inner.lock();
            if let Some(&index) = inner.index.get(&fact.id) {
                return u64::try_from(index)
                    .map_err(|_error| FactError::new("fact cursor overflow".into()));
            }
            let encoded_bytes = self.admit_size(&inner, size, None)?;
            let pos = inner.cursor;
            inner.cursor = inner
                .cursor
                .checked_add(1)
                .ok_or_else(|| FactError::new("fact cursor overflow".into()))?;
            let idx = inner.facts.len();
            inner.index.insert(fact.id, idx);
            inner.sizes.push(size);
            inner.encoded_bytes = encoded_bytes;
            // Subscription takes this same lock, so a receiver that starts
            // before this write is counted and receives an invalidation.
            let notification = (self.tx.receiver_count() != 0).then(|| Arc::new(fact.clone()));
            inner.facts.push(fact);
            (pos, notification)
        };
        broadcast_fact(&self.tx, notification);
        Ok(pos)
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        let size = self.record_size(&fact)?;
        let (notification, retired) = {
            let mut inner = self.inner.lock();
            let index = inner.index.get(&fact.id).copied();
            let encoded_bytes =
                self.admit_size(&inner, size, index.map(|index| inner.sizes[index]))?;
            let notification = (self.tx.receiver_count() != 0).then(|| Arc::new(fact.clone()));
            let retired = if let Some(idx) = index {
                inner.sizes[idx] = size;
                Some(std::mem::replace(&mut inner.facts[idx], fact))
            } else {
                inner.cursor = inner
                    .cursor
                    .checked_add(1)
                    .ok_or_else(|| FactError::new("fact cursor overflow".into()))?;
                let idx = inner.facts.len();
                inner.index.insert(fact.id, idx);
                inner.sizes.push(size);
                inner.facts.push(fact);
                None
            };
            inner.encoded_bytes = encoded_bytes;
            (notification, retired)
        };
        drop(retired);
        broadcast_fact(&self.tx, notification);
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
            return Err(FactError::new(format!(
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
        // This shares the write lock's linearization point: once subscription
        // returns, every later write sees a receiver before it commits.
        let _inner = self.inner.lock();
        self.tx.subscribe()
    }
}

/// Shared fact store handle.
pub type SharedFactStore = Arc<dyn FactStore>;

/// The kernel-facing optional observation port. Explicit writes preserve their
/// commit result independently of business effects and replay classification.
#[derive(Clone)]
pub struct FactSink {
    store: SharedFactStore,
    execution_ids: ExecutionIds,
    identities: Option<crate::identity::IdentityRegistry>,
    unconfirmed_write: Arc<AtomicBool>,
}

impl FactSink {
    /// No observation storage. Explicit writes and checked reads reject rather
    /// than pretend recording succeeded. Execution IDs remain independently owned.
    pub fn disabled(execution_ids: ExecutionIds) -> Self {
        Self::from_parts(Arc::new(disabled::DisabledFactStore), execution_ids)
    }

    /// Whether the host installed observation storage; not a health check.
    pub fn is_enabled(&self) -> bool {
        self.store.is_enabled()
    }
    /// Use one backend for both facts and execution IDs. Backends that provide
    /// only facts can use [`Self::from_parts`] with an independent ID source.
    pub fn new<S>(store: Arc<S>) -> Self
    where
        S: FactStore + ExecutionIdSource,
    {
        let execution_ids = ExecutionIds::new(store.clone());
        Self::from_parts(store, execution_ids)
    }

    /// Combine independently chosen fact and execution-ID ports.
    pub fn from_parts(store: SharedFactStore, execution_ids: ExecutionIds) -> Self {
        Self {
            execution_ids,
            store,
            identities: None,
            unconfirmed_write: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn with_execution_ids(mut self, execution_ids: ExecutionIds) -> Self {
        self.execution_ids = execution_ids;
        self
    }

    /// Create a sink backed by an in-memory fact store and return both handles.
    pub fn in_memory() -> (Self, Arc<InMemoryFactStore>) {
        let store = Arc::new(InMemoryFactStore::new());
        (Self::new(store.clone()), store)
    }

    /// Shared execution allocator configured for this sink.
    pub fn execution_ids(&self) -> ExecutionIds {
        self.execution_ids.clone()
    }

    /// Validate compact identities before every append or completion in an
    /// assembled Kernel. Standalone Fact stores remain a trusted low-level port.
    pub fn with_identity_registry(mut self, identities: crate::identity::IdentityRegistry) -> Self {
        self.identities = Some(identities);
        self
    }

    fn verify_fact_identity(&self, fact: &Fact) -> Result<(), FactError> {
        let Some(identities) = &self.identities else {
            return Ok(());
        };
        if let Some(caller) = fact.caller_identity {
            identities
                .verify(caller)
                .map_err(|error| FactError::new(format!("caller identity: {error}")))?;
        }
        if fact.caller_identity != Some(fact.acting) {
            identities
                .verify(fact.acting)
                .map_err(|error| FactError::new(format!("acting identity: {error}")))?;
        }
        Ok(())
    }

    fn ensure_write_reconciled(&self) -> Result<(), FactError> {
        if self.unconfirmed_write.load(Ordering::Acquire) {
            Err(FactError::reopen_required(
                "a hosted Fact write lost its result; reopen the Fact sink and reconcile its operation ID".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn note_commit_error(&self, error: &FactError) {
        if matches!(
            error.kind(),
            FactErrorKind::CommitOutcomeUnknown | FactErrorKind::ReopenRequired
        ) {
            self.mark_host_write_unknown();
        }
    }

    /// Close all clones of this installed sink after an accepted host worker
    /// ended without a usable commit result. A newly constructed sink can
    /// reopen the backend and reconcile by the original operation ID.
    pub(crate) fn mark_host_write_unknown(&self) {
        self.unconfirmed_write.store(true, Ordering::Release);
    }

    /// Append a selected pending observation using the backend's commit policy.
    pub fn begin(&self, pending: Fact) -> Result<(), FactError> {
        self.ensure_write_reconciled()?;
        validate_fact_schema(&pending)?;
        self.verify_fact_identity(&pending)?;
        let result = self.store.append(pending).map(|_| ());
        if let Err(error) = &result {
            self.note_commit_error(error);
            return result;
        }
        self.ensure_write_reconciled()?;
        result
    }

    /// Complete an operation's record after the driver returns.
    /// The backend owns its data commit policy independently of effect class.
    pub fn complete(&self, fact: Fact) -> Result<(), FactError> {
        self.ensure_write_reconciled()?;
        validate_fact_schema(&fact)?;
        self.verify_fact_identity(&fact)?;
        let result = self.store.complete(fact);
        if let Err(error) = &result {
            self.note_commit_error(error);
            return result;
        }
        self.ensure_write_reconciled()?;
        result
    }

    /// Access the trusted low-level store. Direct callers bypass this sink's
    /// unknown-host-write fence and must reconcile uncertain writes themselves.
    pub fn store(&self) -> &SharedFactStore {
        &self.store
    }

    /// Read a page subject to its record, candidate and encoded-byte limits.
    /// Rejects structurally invalid pages returned by a custom adapter.
    pub fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        self.ensure_write_reconciled()?;
        let page = self.store.scan_checked(query)?;
        self.ensure_write_reconciled()?;
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
        self.ensure_write_reconciled()?;
        let result = self.store.lookup_checked(query)?;
        self.ensure_write_reconciled()?;
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
        self.ensure_write_reconciled()?;
        let facts = self.store.facts_of(process)?;
        self.ensure_write_reconciled()?;
        Ok(facts)
    }

    /// Materialize all retained facts in append order, without a size limit.
    pub fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        self.ensure_write_reconciled()?;
        let facts = self.store.all_facts()?;
        self.ensure_write_reconciled()?;
        Ok(facts)
    }

    /// Current append cursor of the underlying fact store.
    pub fn cursor(&self) -> u64 {
        self.store.cursor()
    }

    /// The locally observed cursor, rejecting an adapter whose commit result
    /// is unknown until that backend is reopened and reconciled.
    pub fn observed_cursor(&self) -> Result<u64, FactError> {
        self.ensure_write_reconciled()?;
        let cursor = self.store.observed_cursor()?;
        self.ensure_write_reconciled()?;
        Ok(cursor)
    }
}

fn validate_fact_schema(fact: &Fact) -> Result<(), FactError> {
    if fact.schema_version == Fact::SCHEMA_VERSION {
        Ok(())
    } else {
        Err(FactError::new(format!(
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
            caller_identity: Some(IdentityRef::ROOT),
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
            err.message().contains("unsupported Fact schema_version"),
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
    fn subscription_after_quiescent_write_starts_empty_and_sees_later_writes() -> anyhow::Result<()>
    {
        let store = InMemoryFactStore::new();
        let mut pending = fact(1, 0, ReplayClass::Observation);
        pending.outcome = None;
        store.append(pending)?;

        let mut events = store.subscribe_facts();
        ensure!(
            events.try_recv().is_err(),
            "subscription replayed a prior append"
        );
        let completed = fact(1, 0, ReplayClass::Observation);
        store.complete(completed.clone())?;
        ensure!(*events.try_recv()? == completed);

        drop(events);
        let next = fact(1, 1, ReplayClass::Observation);
        store.complete(next.clone())?;
        ensure!(store.all_facts()? == [completed, next]);

        let mut later = store.subscribe_facts();
        ensure!(
            later.try_recv().is_err(),
            "subscription replayed a write after the previous receiver dropped"
        );
        let final_fact = fact(1, 2, ReplayClass::Observation);
        store.append(final_fact.clone())?;
        ensure!(*later.try_recv()? == final_fact);
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
