//! Optional shared host composition. Capability implementations remain runtime-independent.

use crate::*;
use alloc::{boxed::Box, sync::Arc};
use core::{future::Future, num::NonZeroUsize, pin::Pin};
use xolotl_types::{MergeRule, Path, TaintSet, Value};

pub mod object;

#[cfg(feature = "tokio")]
mod broadcast;
#[cfg(feature = "tokio")]
pub use broadcast::broadcast_stream;
#[cfg(feature = "tokio")]
mod watch;
#[cfg(feature = "tokio")]
pub use watch::{WatchInvalidation, WatchRegistry};

type SendFuture<'a, T> = Pin<Box<dyn Future<Output = StateResult<T>> + Send + 'a>>;

trait ReadPort: Send + Sync {
    fn read<'a>(&'a self, path: &'a Path) -> SendFuture<'a, StateObservation>;
}
impl<T: StateRead + Send + Sync> ReadPort for T
where
    for<'a> T::Read<'a>: Send,
{
    fn read<'a>(&'a self, path: &'a Path) -> SendFuture<'a, StateObservation> {
        Box::pin(self.read_tainted(path))
    }
}

trait BoundedReadPort: Send + Sync {
    fn read<'a>(
        &'a self,
        path: &'a Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> SendFuture<'a, StateObservation>;
}
impl<T: StateBoundedRead + Send + Sync> BoundedReadPort for T
where
    for<'a> T::BoundedRead<'a>: Send,
{
    fn read<'a>(
        &'a self,
        path: &'a Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> SendFuture<'a, StateObservation> {
        Box::pin(self.read_tainted_bounded(path, max_encoded_bytes))
    }
}

trait WritePort: Send + Sync {
    fn write<'a>(
        &'a self,
        path: &'a Path,
        mutation: StateMutation,
    ) -> SendFuture<'a, crate::StateCommit>;
}

trait BoundedWritePort: Send + Sync {
    fn compare_set<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> SendFuture<'a, crate::StateCommit>;
    fn compare_delete<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: TaintSet,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> SendFuture<'a, crate::StateCommit>;
}
impl<T: StateBoundedWrite + Send + Sync> BoundedWritePort for T
where
    for<'a> T::BoundedWrite<'a>: Send,
{
    fn compare_set<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> SendFuture<'a, crate::StateCommit> {
        Box::pin(self.compare_set_bounded(path, expected, value, max_current_encoded_bytes))
    }
    fn compare_delete<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: TaintSet,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> SendFuture<'a, crate::StateCommit> {
        Box::pin(self.compare_delete_bounded(path, expected, taint, max_current_encoded_bytes))
    }
}
impl<T: StateWrite + Send + Sync> WritePort for T
where
    for<'a> T::Write<'a>: Send,
{
    fn write<'a>(
        &'a self,
        path: &'a Path,
        mutation: StateMutation,
    ) -> SendFuture<'a, crate::StateCommit> {
        Box::pin(self.mutate(path, mutation))
    }
}

trait QueryPort: Send + Sync {
    fn query<'a>(&'a self, query: &'a StateScan) -> SendFuture<'a, StatePage>;
}
impl<T: StateQuery + Send + Sync> QueryPort for T
where
    for<'a> T::Query<'a>: Send,
{
    fn query<'a>(&'a self, query: &'a StateScan) -> SendFuture<'a, StatePage> {
        Box::pin(StateQuery::query(self, query))
    }
}

trait HistoryPort: Send + Sync {
    fn history<'a>(&'a self, query: &'a StateHistoryQuery) -> SendFuture<'a, StateHistoryPage>;
    fn read_at<'a>(&'a self, path: &'a Path, at_millis: i64) -> SendFuture<'a, StateObservation>;
}
impl<T: StateHistory + Send + Sync> HistoryPort for T
where
    for<'a> T::History<'a>: Send,
    for<'a> T::At<'a>: Send,
{
    fn history<'a>(&'a self, query: &'a StateHistoryQuery) -> SendFuture<'a, StateHistoryPage> {
        Box::pin(StateHistory::history(self, query))
    }
    fn read_at<'a>(&'a self, path: &'a Path, at_millis: i64) -> SendFuture<'a, StateObservation> {
        Box::pin(StateHistory::read_at(self, path, at_millis))
    }
}

trait HistoryRetentionPort: Send + Sync {
    fn retained_from(&self) -> SendFuture<'_, i64>;
    fn trim_before(
        &self,
        floor: i64,
        limits: StateHistoryTrimLimits,
    ) -> SendFuture<'_, StateHistoryTrim>;
}
impl<T: StateHistoryRetention + Send + Sync> HistoryRetentionPort for T
where
    for<'a> T::Floor<'a>: Send,
    for<'a> T::Trim<'a>: Send,
{
    fn retained_from(&self) -> SendFuture<'_, i64> {
        Box::pin(StateHistoryRetention::retained_from(self))
    }
    fn trim_before(
        &self,
        floor: i64,
        limits: StateHistoryTrimLimits,
    ) -> SendFuture<'_, StateHistoryTrim> {
        Box::pin(StateHistoryRetention::trim_before(self, floor, limits))
    }
}

trait WatchPort: Send + Sync {
    fn subscribe<'a>(&'a self, path: &'a Path) -> SendFuture<'a, StateStream>;
}
impl<T: StateWatch + Send + Sync> WatchPort for T
where
    for<'a> T::Subscribe<'a>: Send,
    T::Subscription: Send + 'static,
{
    fn subscribe<'a>(&'a self, path: &'a Path) -> SendFuture<'a, StateStream> {
        Box::pin(async move { Ok(StateStream::new(StateWatch::subscribe(self, path).await?)) })
    }
}

trait SignalPort: Send + Sync {
    fn current<'a>(&'a self, path: &'a Path) -> SendFuture<'a, StateObservation>;
    fn observe<'a>(&'a self, path: &'a Path) -> SendFuture<'a, (StateObservation, StateStream)>;
}
impl<T: StateRead + StateWatch + Send + Sync> SignalPort for T
where
    for<'a> T::Read<'a>: Send,
    for<'a> T::Subscribe<'a>: Send,
    T::Subscription: Send + 'static,
{
    fn current<'a>(&'a self, path: &'a Path) -> SendFuture<'a, StateObservation> {
        Box::pin(StateRead::read_tainted(self, path))
    }

    fn observe<'a>(&'a self, path: &'a Path) -> SendFuture<'a, (StateObservation, StateStream)> {
        Box::pin(async move {
            // Both operations use this one port. The subscription is active
            // before the snapshot, so a committed write cannot be missed.
            let events = StateStream::new(StateWatch::subscribe(self, path).await?);
            let current = StateRead::read_tainted(self, path).await?;
            Ok((current, events))
        })
    }
}

trait FlushPort: Send + Sync {
    fn flush(&self) -> SendFuture<'_, ()>;
}
impl<T: StateFlush + Send + Sync> FlushPort for T
where
    for<'a> T::Flush<'a>: Send,
{
    fn flush(&self) -> SendFuture<'_, ()> {
        Box::pin(StateFlush::flush(self))
    }
}

/// Independently installed host capabilities. Empty or read-only compositions are valid.
/// Calling an absent capability returns [`StateError::MissingCapability`].
/// Clones share installed ports. Signal observation requires its own paired
/// port; independently supplied read and watch ports do not establish a
/// common commit domain.
#[derive(Clone, Default)]
pub struct Backend {
    read: Option<Arc<dyn ReadPort>>,
    bounded_read: Option<Arc<dyn BoundedReadPort>>,
    write: Option<Arc<dyn WritePort>>,
    bounded_write: Option<Arc<dyn BoundedWritePort>>,
    query: Option<Arc<dyn QueryPort>>,
    history: Option<Arc<dyn HistoryPort>>,
    history_retention: Option<Arc<dyn HistoryRetentionPort>>,
    watch: Option<Arc<dyn WatchPort>>,
    signal: Option<Arc<dyn SignalPort>>,
    flush: Option<Arc<dyn FlushPort>>,
}

impl Backend {
    /// Create a composition with no installed capabilities.
    pub fn new() -> Self {
        Self::default()
    }
    /// Install or replace the shared point-read capability.
    pub fn with_read<T: StateRead + Send + Sync + 'static>(mut self, port: Arc<T>) -> Self
    where
        for<'a> T::Read<'a>: Send,
    {
        self.read = Some(port);
        self
    }
    /// Install or replace an exact-path bounded read capability. This port is
    /// independent of unrestricted reads and bounded prefix queries.
    pub fn with_bounded_read<T: StateBoundedRead + Send + Sync + 'static>(
        mut self,
        port: Arc<T>,
    ) -> Self
    where
        for<'a> T::BoundedRead<'a>: Send,
    {
        self.bounded_read = Some(port);
        self
    }
    /// Install or replace the shared atomic-mutation capability.
    pub fn with_write<T: StateWrite + Send + Sync + 'static>(mut self, port: Arc<T>) -> Self
    where
        for<'a> T::Write<'a>: Send,
    {
        self.write = Some(port);
        self
    }
    /// Install or replace bounded conditional writes. The port must compare,
    /// size-check and commit against one atomic view. It is independent of
    /// unrestricted writes and bounded reads.
    pub fn with_bounded_write<T: StateBoundedWrite + Send + Sync + 'static>(
        mut self,
        port: Arc<T>,
    ) -> Self
    where
        for<'a> T::BoundedWrite<'a>: Send,
    {
        self.bounded_write = Some(port);
        self
    }
    /// Install or replace the shared bounded-query capability.
    pub fn with_query<T: StateQuery + Send + Sync + 'static>(mut self, port: Arc<T>) -> Self
    where
        for<'a> T::Query<'a>: Send,
    {
        self.query = Some(port);
        self
    }
    /// Install or replace history paging and historical point reads together.
    pub fn with_history<T: StateHistory + Send + Sync + 'static>(mut self, port: Arc<T>) -> Self
    where
        for<'a> T::History<'a>: Send,
        for<'a> T::At<'a>: Send,
    {
        self.history = Some(port);
        self
    }
    /// Install history maintenance independently of historical reads.
    /// The embedding must pair it with ports over the same commit domain.
    pub fn with_history_retention<T: StateHistoryRetention + Send + Sync + 'static>(
        mut self,
        port: Arc<T>,
    ) -> Self
    where
        for<'a> T::Floor<'a>: Send,
        for<'a> T::Trim<'a>: Send,
    {
        self.history_retention = Some(port);
        self
    }
    /// Install or replace subscription setup, erasing returned subscriptions
    /// into transferable [`StateStream`] ownership.
    pub fn with_watch<T: StateWatch + Send + Sync + 'static>(mut self, port: Arc<T>) -> Self
    where
        for<'a> T::Subscribe<'a>: Send,
        T::Subscription: Send + 'static,
    {
        self.watch = Some(port);
        self
    }
    /// Install a paired signal observation capability. The supplied port must
    /// make its point reads and subscriptions observe the same commit domain,
    /// and must deliver every matching commit after subscription registration
    /// or report loss. This capability is deliberately independent of the
    /// general read and watch ports, which may point to different stores.
    pub fn with_signal<T: StateRead + StateWatch + Send + Sync + 'static>(
        mut self,
        port: Arc<T>,
    ) -> Self
    where
        for<'a> T::Read<'a>: Send,
        for<'a> T::Subscribe<'a>: Send,
        T::Subscription: Send + 'static,
    {
        self.signal = Some(port);
        self
    }
    /// Install or replace the backend's flush or maintenance barrier.
    pub fn with_flush<T: StateFlush + Send + Sync + 'static>(mut self, port: Arc<T>) -> Self
    where
        for<'a> T::Flush<'a>: Send,
    {
        self.flush = Some(port);
        self
    }

    /// Whether point reads have been installed.
    pub fn has_read(&self) -> bool {
        self.read.is_some()
    }
    /// Whether exact-path bounded reads have been installed.
    pub fn has_bounded_read(&self) -> bool {
        self.bounded_read.is_some()
    }
    /// Whether atomic path mutations have been installed.
    pub fn has_write(&self) -> bool {
        self.write.is_some()
    }
    /// Whether bounded conditional writes have been installed.
    pub fn has_bounded_write(&self) -> bool {
        self.bounded_write.is_some()
    }
    /// Whether bounded prefix queries have been installed.
    pub fn has_query(&self) -> bool {
        self.query.is_some()
    }
    /// Whether history paging and historical point reads have been installed.
    pub fn has_history(&self) -> bool {
        self.history.is_some()
    }
    /// Whether the host installed history-retention maintenance.
    pub fn has_history_retention(&self) -> bool {
        self.history_retention.is_some()
    }
    /// Whether subscriptions have been installed.
    pub fn has_watch(&self) -> bool {
        self.watch.is_some()
    }
    /// Whether a paired signal observation capability is installed.
    pub fn has_signal(&self) -> bool {
        self.signal.is_some()
    }

    /// Read a current value and its provenance from the installed read port.
    /// `StateObservation::value` is None for an absent path; provenance is retained.
    pub async fn read_tainted(&self, path: &Path) -> StateResult<StateObservation> {
        self.read
            .as_ref()
            .ok_or(StateError::MissingCapability("read"))?
            .read(path)
            .await
    }
    /// Read a current value while discarding provenance, for trusted host metadata.
    pub async fn read(&self, path: &Path) -> StateResult<Option<Value>> {
        Ok(self.read_tainted(path).await?.value)
    }
    /// Read one exact current path within the backend's encoded record budget.
    /// This fails when the bounded read port is absent; it never falls back to
    /// an unrestricted read or a prefix query. The limit is not a bound on
    /// resident heap usage or on a later mutation of the same path.
    pub async fn read_tainted_bounded(
        &self,
        path: &Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> StateResult<StateObservation> {
        self.bounded_read
            .as_ref()
            .ok_or(StateError::MissingCapability("bounded_read"))?
            .read(path, max_encoded_bytes)
            .await
    }
    /// Bounded exact-path read that discards provenance for trusted metadata.
    pub async fn read_bounded(
        &self,
        path: &Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> StateResult<Option<Value>> {
        Ok(self
            .read_tainted_bounded(path, max_encoded_bytes)
            .await?
            .value)
    }
    /// Submit one atomic path mutation through the installed write port.
    pub async fn mutate(
        &self,
        path: &Path,
        mutation: StateMutation,
    ) -> StateResult<crate::StateCommit> {
        self.write
            .as_ref()
            .ok_or_else(|| {
                StateFailure::new(
                    StateError::MissingCapability("write"),
                    mutation.input_taint().clone(),
                )
            })?
            .write(path, mutation)
            .await
    }
    /// Replace a path's stored value and provenance with the supplied pair.
    pub async fn write_set_tainted(
        &self,
        path: &Path,
        value: Value,
        taint: TaintSet,
    ) -> StateResult<crate::StateCommit> {
        self.mutate(path, StateMutation::Set(TaintedValue::new(value, taint)))
            .await
    }
    /// Replace a path's stored value and mark its provenance pristine.
    pub async fn write_set(&self, path: &Path, value: Value) -> StateResult<crate::StateCommit> {
        self.write_set_tainted(path, value, TaintSet::pristine())
            .await
    }
    /// Append an item and union its provenance with the sequence. Missing paths
    /// start a list; an existing non-list is rejected by the write capability.
    pub async fn write_append_tainted(
        &self,
        path: &Path,
        value: Value,
        taint: TaintSet,
    ) -> StateResult<crate::StateCommit> {
        self.mutate(path, StateMutation::Append(TaintedValue::new(value, taint)))
            .await
    }
    /// Append a pristine item while preserving existing sequence provenance.
    pub async fn write_append(&self, path: &Path, value: Value) -> StateResult<crate::StateCommit> {
        self.write_append_tainted(path, value, TaintSet::pristine())
            .await
    }
    /// Atomically compare the value and replace both value and provenance.
    /// `None` matches absence; `Some(Value::null())` matches a stored null.
    /// A mismatch returns [`StateError::CasFailed`] without changing the path.
    pub async fn write_cas_tainted(
        &self,
        path: &Path,
        expected: Option<Value>,
        value: Value,
        taint: TaintSet,
    ) -> StateResult<crate::StateCommit> {
        self.mutate(
            path,
            StateMutation::CompareSet {
                expected,
                value: TaintedValue::new(value, taint),
            },
        )
        .await
    }
    /// Atomically compare the value and replace it with pristine data.
    /// The comparison distinguishes absence from a stored null.
    pub async fn write_cas(
        &self,
        path: &Path,
        expected: Option<Value>,
        value: Value,
    ) -> StateResult<crate::StateCommit> {
        self.write_cas_tainted(path, expected, value, TaintSet::pristine())
            .await
    }
    /// Compare and replace within an exact current-record byte budget.
    /// A missing bounded-write port is an error; this never falls back to an
    /// unrestricted mutation. The installed read and write ports must share a
    /// consistent commit domain when a caller relies on their relationship.
    pub async fn write_cas_bounded(
        &self,
        path: &Path,
        expected: Option<Value>,
        value: Value,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> StateResult<crate::StateCommit> {
        self.write_cas_tainted_bounded(
            path,
            expected,
            value,
            TaintSet::pristine(),
            max_current_encoded_bytes,
        )
        .await
    }
    /// Compare and replace while preserving incoming and observed provenance.
    pub async fn write_cas_tainted_bounded(
        &self,
        path: &Path,
        expected: Option<Value>,
        value: Value,
        taint: TaintSet,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> StateResult<crate::StateCommit> {
        self.bounded_write
            .as_ref()
            .ok_or(StateError::MissingCapability("bounded_write"))?
            .compare_set(
                path,
                expected,
                TaintedValue::new(value, taint),
                max_current_encoded_bytes,
            )
            .await
    }
    /// Remove a current value; deleting an absent path succeeds unchanged.
    pub async fn write_delete(&self, path: &Path) -> StateResult<crate::StateCommit> {
        self.write_delete_tainted(path, TaintSet::pristine()).await
    }
    /// Remove a value while retaining deletion input and control provenance.
    pub async fn write_delete_tainted(
        &self,
        path: &Path,
        taint: TaintSet,
    ) -> StateResult<crate::StateCommit> {
        self.mutate(path, StateMutation::Delete(taint)).await
    }
    /// Atomically remove a matching value without requiring the read capability.
    /// `None` matches absence and succeeds unchanged; a stored null requires
    /// `Some(Value::null())`. A mismatch changes no data, provenance, or events.
    pub async fn write_compare_delete(
        &self,
        path: &Path,
        expected: Option<Value>,
    ) -> StateResult<crate::StateCommit> {
        self.write_compare_delete_tainted(path, expected, TaintSet::pristine())
            .await
    }
    /// Compare and remove a value with explicit input and control provenance.
    pub async fn write_compare_delete_tainted(
        &self,
        path: &Path,
        expected: Option<Value>,
        taint: TaintSet,
    ) -> StateResult<crate::StateCommit> {
        self.mutate(path, StateMutation::CompareDelete { expected, taint })
            .await
    }
    /// Compare and delete within an exact current-record byte budget.
    pub async fn write_compare_delete_bounded(
        &self,
        path: &Path,
        expected: Option<Value>,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> StateResult<crate::StateCommit> {
        self.write_compare_delete_tainted_bounded(
            path,
            expected,
            TaintSet::pristine(),
            max_current_encoded_bytes,
        )
        .await
    }
    /// Compare and delete with input provenance and an atomic current-record byte budget.
    pub async fn write_compare_delete_tainted_bounded(
        &self,
        path: &Path,
        expected: Option<Value>,
        taint: TaintSet,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> StateResult<crate::StateCommit> {
        self.bounded_write
            .as_ref()
            .ok_or_else(|| {
                StateFailure::new(
                    StateError::MissingCapability("bounded_write"),
                    taint.clone(),
                )
            })?
            .compare_delete(path, expected, taint, max_current_encoded_bytes)
            .await
    }
    /// Merge pristine incoming data while retaining existing provenance.
    pub async fn write_merge(
        &self,
        path: &Path,
        value: Value,
        rule: MergeRule,
    ) -> StateResult<crate::StateCommit> {
        self.write_merge_tainted(path, TaintedValue::pristine(value), rule)
            .await
    }

    /// Atomically merge data and union existing and incoming provenance.
    pub async fn write_merge_tainted(
        &self,
        path: &Path,
        value: TaintedValue,
        rule: MergeRule,
    ) -> StateResult<crate::StateCommit> {
        self.mutate(path, StateMutation::Merge { value, rule })
            .await
    }
    /// Return a boxed, transferable request for one bounded prefix page.
    /// The installed query port defines key order and validates the continuation.
    pub fn query<'a>(&'a self, query: &'a StateScan) -> SendFuture<'a, StatePage> {
        match &self.query {
            Some(port) => port.query(query),
            None => Box::pin(core::future::ready(Err(StateError::MissingCapability(
                "query",
            )
            .into()))),
        }
    }
    /// Create a caller-owned pager without fetching or accumulating results yet.
    pub fn pages(&self, query: StateScan) -> StatePager<'_, Self> {
        StatePager::new(self, query)
    }
    /// Read one bounded history page for a path prefix and half-open time interval.
    pub async fn history(&self, query: &StateHistoryQuery) -> StateResult<StateHistoryPage> {
        self.history
            .as_ref()
            .ok_or(StateError::MissingCapability("history"))?
            .history(query)
            .await
    }
    /// Read a path's value and provenance at a timestamp; zero selects current state.
    /// This always requires the history port, including for zero. Historical
    /// replay may depend on the complete path history and is not page-bounded.
    pub async fn read_at(&self, path: &Path, at_millis: i64) -> StateResult<StateObservation> {
        self.history
            .as_ref()
            .ok_or(StateError::MissingCapability("history"))?
            .read_at(path, at_millis)
            .await
    }
    /// Return the earliest valid historical timestamp.
    pub async fn retained_from(&self) -> StateResult<i64> {
        self.history_retention
            .as_ref()
            .ok_or(StateError::MissingCapability("history_retention"))?
            .retained_from()
            .await
    }
    /// Atomically fold and remove history before `floor` in the installed store.
    pub async fn trim_history_before(
        &self,
        floor: i64,
        limits: StateHistoryTrimLimits,
    ) -> StateResult<StateHistoryTrim> {
        self.history_retention
            .as_ref()
            .ok_or(StateError::MissingCapability("history_retention"))?
            .trim_before(floor, limits)
            .await
    }
    /// Subscribe to future committed mutations matching the path pattern.
    /// Register before reading current state when avoiding lost wakeups matters.
    pub async fn subscribe(&self, path: &Path) -> StateResult<StateStream> {
        self.watch
            .as_ref()
            .ok_or(StateError::MissingCapability("watch"))?
            .subscribe(path)
            .await
    }
    /// Reread the authoritative current domain used by the paired Signal port.
    pub async fn observe_signal_current(&self, path: &Path) -> StateResult<StateObservation> {
        self.signal
            .as_ref()
            .ok_or(StateError::MissingCapability("signal"))?
            .current(path)
            .await
    }

    /// Register before reading the same current domain; later commits are
    /// covered by the stream or explicitly reported as lost.
    pub async fn observe_signal(
        &self,
        path: &Path,
    ) -> StateResult<(StateObservation, StateStream)> {
        self.signal
            .as_ref()
            .ok_or(StateError::MissingCapability("signal"))?
            .observe(path)
            .await
    }
    /// Await the installed backend's flush or maintenance barrier. Durability
    /// guarantees are backend-specific; an absent flush port is an error.
    pub async fn flush(&self) -> StateResult<()> {
        self.flush
            .as_ref()
            .ok_or(StateError::MissingCapability("flush"))?
            .flush()
            .await
    }
}

impl StateQuery for Backend {
    type Query<'a> = SendFuture<'a, StatePage>;
    fn query<'a>(&'a self, query: &'a StateScan) -> Self::Query<'a> {
        self.query(query)
    }
}

/// Count a borrowed lossless encoding without allocating the encoded payload.
pub fn encoded_size(value: &impl serde::Serialize) -> StateResult<usize> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("state encoding size overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}

/// Hash the lossless tagged encoding of a Source payload while counting its
/// bytes. The writer feeds BLAKE3 directly and never builds an encoded copy.
/// Built-in Source stores use this common representation for event-ID retries.
/// A conservative predescent budget bounds indexing work; the same indexed
/// table feeds an exact byte-limited writer. No full encoded buffer is built.
/// Oversized input is rejected before any Source mutation or evidence commit.
/// `Ok(None)` reports an exceeded work or exact encoding budget.
pub fn source_payload_fingerprint_bounded(
    value: &Value,
    max_encoded_bytes: usize,
) -> StateResult<Option<(usize, [u8; 32])>> {
    struct FingerprintWriter {
        bytes: usize,
        limit: usize,
        limit_exceeded: bool,
        hasher: blake3::Hasher,
    }
    impl std::io::Write for FingerprintWriter {
        fn write(&mut self, chunk: &[u8]) -> std::io::Result<usize> {
            let Some(bytes) = self
                .bytes
                .checked_add(chunk.len())
                .filter(|bytes| *bytes <= self.limit)
            else {
                self.limit_exceeded = true;
                return Err(std::io::Error::other(
                    "Source payload encoding limit exceeded",
                ));
            };
            self.bytes = bytes;
            self.hasher.update(chunk);
            Ok(chunk.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = FingerprintWriter {
        bytes: 0,
        limit: max_encoded_bytes,
        limit_exceeded: false,
        hasher: blake3::Hasher::new(),
    };
    let mut table = xolotl_types::tagged_value::ValueTableEncoder::new();
    let root = match table.intern_bounded(value, max_encoded_bytes) {
        Ok(root) => root,
        Err(xolotl_types::tagged_value::ValueTableEncodeError::BudgetExceeded) => return Ok(None),
        Err(error) => return Err(StateError::Backend(error.to_string()).into()),
    };
    if let Err(error) = serde_json::to_writer(&mut writer, &table.serializable_root(root)) {
        if writer.limit_exceeded {
            return Ok(None);
        }
        return Err(error.into());
    }
    Ok(Some((writer.bytes, *writer.hasher.finalize().as_bytes())))
}

#[cfg(test)]
mod fingerprint_tests {
    use super::*;

    #[test]
    fn bounded_fingerprint_matches_encoding_and_rejects_exact_byte_overflow() -> anyhow::Result<()>
    {
        let shared = Value::bytes(vec![255; 128]);
        for value in [
            Value::null(),
            Value::from("\"\\\n"),
            Value::list(vec![shared.clone(), shared]),
        ] {
            let bytes = serde_json::to_vec(&xolotl_types::tagged_value::serializable(&value))?;
            anyhow::ensure!(
                source_payload_fingerprint_bounded(&value, bytes.len())?
                    == Some((bytes.len(), *blake3::hash(&bytes).as_bytes()))
            );
            anyhow::ensure!(source_payload_fingerprint_bounded(&value, bytes.len() - 1)?.is_none());
            anyhow::ensure!(source_payload_fingerprint_bounded(&value, 0)?.is_none());
        }
        let mut deep = Value::null();
        for _depth in 0..4096 {
            deep = Value::list(vec![deep]);
        }
        anyhow::ensure!(source_payload_fingerprint_bounded(&deep, 16)?.is_none());
        Ok(())
    }
}
