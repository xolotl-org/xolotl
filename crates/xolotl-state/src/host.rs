//! Optional shared host composition. Capability implementations remain runtime-independent.

use crate::*;
use alloc::{boxed::Box, sync::Arc};
use core::{future::Future, pin::Pin};
use xolotl_types::{MergeRule, Path, TaintSet, Value};

pub mod object;

#[cfg(feature = "tokio")]
mod broadcast;
#[cfg(feature = "tokio")]
pub use broadcast::broadcast_stream;
#[cfg(feature = "tokio")]
mod watch;
#[cfg(feature = "tokio")]
pub use watch::WatchRegistry;

type SendFuture<'a, T> = Pin<Box<dyn Future<Output = StateResult<T>> + Send + 'a>>;

trait ReadPort: Send + Sync {
    fn read<'a>(&'a self, path: &'a Path) -> SendFuture<'a, Option<TaintedValue>>;
}
impl<T: StateRead + Send + Sync> ReadPort for T
where
    for<'a> T::Read<'a>: Send,
{
    fn read<'a>(&'a self, path: &'a Path) -> SendFuture<'a, Option<TaintedValue>> {
        Box::pin(self.read_tainted(path))
    }
}

trait WritePort: Send + Sync {
    fn write<'a>(
        &'a self,
        path: &'a Path,
        mutation: StateMutation,
    ) -> SendFuture<'a, crate::StateCommit>;
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
    fn read_at<'a>(
        &'a self,
        path: &'a Path,
        at_millis: i64,
    ) -> SendFuture<'a, Option<TaintedValue>>;
}
impl<T: StateHistory + Send + Sync> HistoryPort for T
where
    for<'a> T::History<'a>: Send,
    for<'a> T::At<'a>: Send,
{
    fn history<'a>(&'a self, query: &'a StateHistoryQuery) -> SendFuture<'a, StateHistoryPage> {
        Box::pin(StateHistory::history(self, query))
    }
    fn read_at<'a>(
        &'a self,
        path: &'a Path,
        at_millis: i64,
    ) -> SendFuture<'a, Option<TaintedValue>> {
        Box::pin(StateHistory::read_at(self, path, at_millis))
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
/// Clones share installed ports; consistency across separately supplied ports
/// remains the responsibility of their implementations and the embedding.
#[derive(Clone, Default)]
pub struct Backend {
    read: Option<Arc<dyn ReadPort>>,
    write: Option<Arc<dyn WritePort>>,
    query: Option<Arc<dyn QueryPort>>,
    history: Option<Arc<dyn HistoryPort>>,
    watch: Option<Arc<dyn WatchPort>>,
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
    /// Install or replace the shared atomic-mutation capability.
    pub fn with_write<T: StateWrite + Send + Sync + 'static>(mut self, port: Arc<T>) -> Self
    where
        for<'a> T::Write<'a>: Send,
    {
        self.write = Some(port);
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
    /// Whether atomic path mutations have been installed.
    pub fn has_write(&self) -> bool {
        self.write.is_some()
    }
    /// Whether bounded prefix queries have been installed.
    pub fn has_query(&self) -> bool {
        self.query.is_some()
    }
    /// Whether history paging and historical point reads have been installed.
    pub fn has_history(&self) -> bool {
        self.history.is_some()
    }
    /// Whether subscriptions have been installed.
    pub fn has_watch(&self) -> bool {
        self.watch.is_some()
    }

    /// Read a current value and its provenance from the installed read port.
    /// `None` denotes an absent path.
    pub async fn read_tainted(&self, path: &Path) -> StateResult<Option<TaintedValue>> {
        self.read
            .as_ref()
            .ok_or(StateError::MissingCapability("read"))?
            .read(path)
            .await
    }
    /// Read a current value while discarding provenance, for trusted host metadata.
    pub async fn read(&self, path: &Path) -> StateResult<Option<Value>> {
        Ok(self.read_tainted(path).await?.map(|value| value.value))
    }
    /// Submit one atomic path mutation through the installed write port.
    pub async fn mutate(
        &self,
        path: &Path,
        mutation: StateMutation,
    ) -> StateResult<crate::StateCommit> {
        self.write
            .as_ref()
            .ok_or(StateError::MissingCapability("write"))?
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
    /// Remove a current value; deleting an absent path succeeds unchanged.
    pub async fn write_delete(&self, path: &Path) -> StateResult<crate::StateCommit> {
        self.mutate(path, StateMutation::Delete).await
    }
    /// Atomically remove a matching value without requiring the read capability.
    /// `None` matches absence and succeeds unchanged; a stored null requires
    /// `Some(Value::null())`. A mismatch changes no data, provenance, or events.
    pub async fn write_compare_delete(
        &self,
        path: &Path,
        expected: Option<Value>,
    ) -> StateResult<crate::StateCommit> {
        self.mutate(path, StateMutation::CompareDelete { expected })
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
    pub async fn read_at(&self, path: &Path, at_millis: i64) -> StateResult<Option<TaintedValue>> {
        self.history
            .as_ref()
            .ok_or(StateError::MissingCapability("history"))?
            .read_at(path, at_millis)
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
