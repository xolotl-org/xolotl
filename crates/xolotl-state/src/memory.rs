//! Optional in-memory backend. Used for tests, the embedded SDK, and the
//! default daemon when no persistent backend is configured.
//!
//! Compact or sharded current-value storage shares one commit and notification
//! contract. History retention is independently selectable; full history is
//! unbounded, while disabled history retains only current values and provenance.

mod options;
mod storage;

pub use options::{InMemoryOptions, MemoryHistory};

use crate::prelude::*;
#[cfg(test)]
use crate::test_support::{CollectHistory, CollectState};
use crate::{
    Backend, StateCursor, StateError, StateEvent, StateHistoryEntry, StateHistoryPage,
    StateHistoryQuery, StateMutation, StatePage, StateResult, StateRowTooLarge, StateScan,
    StateStream, TaintedValue,
};
use std::collections::{BTreeMap, VecDeque};
use std::future::{Ready, ready};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use storage::Storage;
use tokio::sync::broadcast;
#[cfg(test)]
use xolotl_types::{MergeRule, Value};
use xolotl_types::{Path, TaintSet};

struct Notification {
    event: StateEvent,
    targets: Vec<broadcast::Sender<StateEvent>>,
}

#[derive(Default)]
struct MemoryState {
    values: BTreeMap<Path, TaintedValue>,
    journal: Journal,
}

#[derive(Default)]
struct Journal {
    history: Vec<StateHistoryEntry>,
    subscribers: crate::host::WatchRegistry,
    notifications: VecDeque<Notification>,
    notifying: bool,
}

/// In-process state. Stores a [`TaintedValue`] per path so provenance
/// persists with the value. Values and history commit atomically. Notifications
/// follow commit order and run outside all locks. The default uses one inline
/// map; [`Self::with_options`] selects sharded reads and optional history.
pub struct InMemoryBackend {
    inner: Storage,
    options: InMemoryOptions,
}

struct NotificationDrain<'a> {
    backend: &'a InMemoryBackend,
    active: bool,
}

impl Drop for NotificationDrain<'_> {
    fn drop(&mut self) {
        if self.active {
            // A panicking subscriber waker must not strand later notifications.
            self.backend.inner.write().notifying = false;
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

fn now_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(error) => {
            let before_epoch = i64::try_from(error.duration().as_millis()).unwrap_or(i64::MAX);
            before_epoch.saturating_neg()
        }
    }
}

impl InMemoryBackend {
    /// Create an empty in-process backend.
    ///
    /// This backend is intended for tests, embedded SDK use, and small default
    /// deployments. It retains all mutation history in memory so callers can
    /// exercise history pages and `read_at`, but it does not enforce a retention
    /// limit. Notification queues default to 256 entries; see
    /// [`Self::with_notification_capacity`] for write backpressure behavior.
    pub fn new() -> Self {
        Self {
            inner: Storage::default(),
            options: InMemoryOptions::default(),
        }
    }

    /// Bound pending notifications and select the broadcast buffer capacity.
    /// No notification storage is allocated until a subscription is used.
    ///
    /// A write with matching subscribers fails before commit if pending delivery
    /// reaches this capacity. Slow readers can independently observe broadcast
    /// lag. One writer drains notifications synchronously, so sustained concurrent
    /// writes can extend that writer's return latency. Values and history retain
    /// their separate, unbounded storage; payload sizes are not limited here.
    ///
    /// After a subscriber waker panics, a later mutation or [`StateFlush::flush`]
    /// resumes queued delivery. Flush does not wait for an active drainer and is
    /// not a delivery barrier; it does not retry the interrupted event.
    /// Capacities above [`InMemoryOptions::MAX_NOTIFICATION_CAPACITY`] return an error.
    pub fn with_notification_capacity(capacity: NonZeroUsize) -> StateResult<Self> {
        Self::with_options(InMemoryOptions {
            notification_capacity: capacity,
            ..InMemoryOptions::default()
        })
    }

    /// Select read parallelism, history retention, and notification capacity.
    ///
    /// One read shard preserves the compact layout and allocates no map storage
    /// until the first value is written. Larger counts reserve padded locks and
    /// empty maps; invalid allocation sizes and reservation failures return errors.
    /// Point reads then lock only their shard. All writes still share one commit
    /// lock, and prefix/history snapshots can delay them. No worker tasks are
    /// started. Values and notification payload sizes remain unbounded.
    pub fn with_options(options: InMemoryOptions) -> StateResult<Self> {
        if options.notification_capacity.get() > InMemoryOptions::MAX_NOTIFICATION_CAPACITY {
            return Err(StateError::Backend(format!(
                "notification capacity exceeds maximum {}",
                InMemoryOptions::MAX_NOTIFICATION_CAPACITY
            ))
            .into());
        }
        Ok(Self {
            inner: Storage::new(options.read_shards)?,
            options,
        })
    }

    fn commit(
        &self,
        map_key: Path,
        mut observed: TaintSet,
        prepare: impl FnOnce(&BTreeMap<Path, TaintedValue>) -> StateResult<Option<StateEvent>>,
    ) -> StateResult<crate::StateCommit> {
        let result = (|| -> StateResult<crate::StateCommit> {
            let wall_millis = (self.options.history == MemoryHistory::Full).then(now_millis);
            let (drain, replaced, removed, unretained) = {
                let mut guard = loop {
                    let state = self.inner.write_path(&map_key);
                    if state.notifying || state.notifications.is_empty() {
                        break state;
                    }
                    drop(state);
                    self.resume_notifications();
                };
                let (values, state) = guard.parts_mut();
                if let Some(current) = values.get(&map_key) {
                    observed.union(&current.taint);
                }
                let Some(event) = prepare(values)? else {
                    return Ok(crate::StateCommit {
                        taint: observed.clone(),
                    });
                };
                let at_millis = wall_millis
                    .map(|wall_millis| {
                        state
                            .history
                            .last()
                            .map_or(0, |entry| entry.at_millis)
                            .checked_add(1)
                            .map(|next| next.max(wall_millis))
                            .ok_or_else(|| {
                                StateError::Backend("history timestamp exhausted".into())
                            })
                    })
                    .transpose()?;
                let targets = state.subscribers.matching(event.path());
                if !targets.is_empty()
                    && state.notifications.len() >= self.options.notification_capacity.get()
                {
                    for notification in &mut state.notifications {
                        notification
                            .targets
                            .retain(|target| target.receiver_count() != 0);
                    }
                    state
                        .notifications
                        .retain(|notification| !notification.targets.is_empty());
                    if state.notifications.len() >= self.options.notification_capacity.get() {
                        return Err(StateError::Backend(format!(
                            "notification backlog capacity {} exhausted",
                            self.options.notification_capacity
                        ))
                        .into());
                    }
                }
                let mut replaced = None;
                let mut removed = None;
                match &event {
                    StateEvent::Set { value, taint, .. } => {
                        let value = TaintedValue::new(value.clone(), taint.clone());
                        if let Some(current) = values.get_mut(&map_key) {
                            replaced = Some(std::mem::replace(current, value));
                        } else {
                            replaced = values.insert(map_key, value);
                        }
                    }
                    StateEvent::Append { path, item, taint } => {
                        let appended = crate::append_value(
                            path,
                            values.get(&map_key),
                            item.clone(),
                            taint.clone(),
                        )?;
                        if let Some(current) = values.get_mut(&map_key) {
                            replaced = Some(std::mem::replace(current, appended));
                        } else {
                            replaced = values.insert(map_key, appended);
                        }
                    }
                    StateEvent::Delete { path, .. } => {
                        removed = values.remove_entry(path);
                    }
                }
                if !targets.is_empty() {
                    state.notifications.push_back(Notification {
                        event: event.clone(),
                        targets,
                    });
                }
                let unretained = if let Some(at_millis) = at_millis {
                    state.history.push(StateHistoryEntry { at_millis, event });
                    None
                } else {
                    Some(event)
                };
                let drain = !state.notifying && !state.notifications.is_empty();
                state.notifying |= drain;
                (drain, replaced, removed, unretained)
            };
            drop((replaced, removed, unretained));
            if drain {
                self.drain_notifications();
            }
            Ok(crate::StateCommit {
                taint: observed.clone(),
            })
        })();
        result.map_err(|failure| failure.with_taint(&observed))
    }

    fn resume_notifications(&self) {
        let drain = {
            let mut state = self.inner.write();
            let drain = !state.notifying && !state.notifications.is_empty();
            state.notifying |= drain;
            drain
        };
        if drain {
            self.drain_notifications();
        }
    }

    fn drain_notifications(&self) {
        let mut guard = NotificationDrain {
            backend: self,
            active: true,
        };
        loop {
            let notification = {
                let mut state = self.inner.write();
                let Some(notification) = state.notifications.pop_front() else {
                    state.notifying = false;
                    guard.active = false;
                    return;
                };
                notification
            };
            for target in notification.targets {
                let _sent = target.send(notification.event.clone());
            }
        }
    }
}

impl InMemoryBackend {
    /// Install this backend's supported capabilities in a shared host.
    pub fn into_backend(self) -> Backend {
        let history = self.options.history == MemoryHistory::Full;
        let port = Arc::new(self);
        let backend = Backend::new()
            .with_read(port.clone())
            .with_write(port.clone())
            .with_query(port.clone())
            .with_watch(port.clone())
            .with_flush(port.clone());
        if history {
            backend.with_history(port)
        } else {
            backend
        }
    }
}

impl StateRead for InMemoryBackend {
    type Read<'a> = Ready<StateResult<Option<TaintedValue>>>;
    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        ready(Ok(self.inner.get(path)))
    }
}

impl StateWrite for InMemoryBackend {
    type Write<'a> = Ready<StateResult<crate::StateCommit>>;
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        let incoming = match &mutation {
            StateMutation::Set(value)
            | StateMutation::Append(value)
            | StateMutation::CompareSet { value, .. }
            | StateMutation::Merge { value, .. } => value.taint.clone(),
            StateMutation::Delete | StateMutation::CompareDelete { .. } => TaintSet::pristine(),
        };
        ready(self.commit(path.clone(), incoming, |values| {
            let stored = values.get(path);
            let event = match mutation {
                StateMutation::Set(value) => StateEvent::Set {
                    path: path.clone(),
                    value: value.value,
                    taint: value.taint,
                },
                StateMutation::Append(mut value) => {
                    if let Some(current) = stored {
                        value.taint.union(&current.taint);
                    }
                    StateEvent::Append {
                        path: path.clone(),
                        item: value.value,
                        taint: value.taint,
                    }
                }
                StateMutation::CompareSet {
                    expected,
                    mut value,
                } => {
                    let actual = stored.map(|value| &value.value);
                    if actual != expected.as_ref() {
                        return Err(StateError::CasFailed {
                            path: path.to_string(),
                            expected: expected.map(Box::new),
                            actual: actual.cloned().map(Box::new),
                        }
                        .into());
                    }
                    if let Some(current) = stored {
                        value.taint.union(&current.taint);
                    }
                    StateEvent::Set {
                        path: path.clone(),
                        value: value.value,
                        taint: value.taint,
                    }
                }
                StateMutation::Delete => {
                    return Ok(stored.map(|value| StateEvent::Delete {
                        path: path.clone(),
                        taint: value.taint.clone(),
                    }));
                }
                StateMutation::CompareDelete { expected } => {
                    let actual = stored.map(|value| &value.value);
                    if actual != expected.as_ref() {
                        return Err(StateError::CasFailed {
                            path: path.to_string(),
                            expected: expected.map(Box::new),
                            actual: actual.cloned().map(Box::new),
                        }
                        .into());
                    }
                    return Ok(stored.map(|value| StateEvent::Delete {
                        path: path.clone(),
                        taint: value.taint.clone(),
                    }));
                }
                StateMutation::Merge { mut value, rule } => {
                    if let Some(current) = stored {
                        value.taint.union(&current.taint);
                    }
                    StateEvent::Set {
                        path: path.clone(),
                        value: crate::merge_values(
                            stored.map(|current| current.value.clone()),
                            value.value,
                            rule,
                        )?,
                        taint: value.taint,
                    }
                }
            };
            Ok(Some(event))
        }))
    }
}

impl StateWatch for InMemoryBackend {
    type Subscription = StateStream;
    type Subscribe<'a> = Ready<StateResult<StateStream>>;
    fn subscribe<'a>(&'a self, pattern: &'a Path) -> Self::Subscribe<'a> {
        ready(
            self.inner
                .write()
                .subscribers
                .subscribe(pattern.clone(), self.options.notification_capacity),
        )
    }
}

impl StateQuery for InMemoryBackend {
    type Query<'a> = Ready<StateResult<StatePage>>;
    fn query<'a>(&'a self, query: &'a StateScan) -> Self::Query<'a> {
        ready(self.inner.query(query))
    }
}

impl StateHistory for InMemoryBackend {
    type History<'a> = Ready<StateResult<StateHistoryPage>>;
    type At<'a> = Ready<StateResult<Option<TaintedValue>>>;
    fn history<'a>(&'a self, query: &'a StateHistoryQuery) -> Self::History<'a> {
        ready(self.history_page(query))
    }
    fn read_at<'a>(&'a self, path: &'a Path, at_millis: i64) -> Self::At<'a> {
        ready((|| {
            if at_millis == 0 {
                return Ok(self.inner.get(path));
            }
            if self.options.history == MemoryHistory::Disabled {
                return Err(StateError::MissingCapability("history").into());
            }
            let state = self.inner.read();
            let mut value = None;
            let mut observed = TaintSet::pristine();
            for entry in state
                .history
                .iter()
                .take_while(|entry| entry.at_millis <= at_millis)
            {
                if entry.event.path() == path {
                    observed.union(entry.event.taint());
                    crate::history::apply_event(&mut value, &entry.event)
                        .map_err(|failure| failure.with_taint(&observed))?;
                }
            }
            Ok(value)
        })())
    }
}

impl InMemoryBackend {
    fn history_page(&self, query: &StateHistoryQuery) -> StateResult<StateHistoryPage> {
        if self.options.history == MemoryHistory::Disabled {
            return Err(StateError::MissingCapability("history").into());
        }
        if query.from_millis > query.to_millis {
            return Err(crate::query::invalid_cursor("history interval is reversed"));
        }
        let start = match &query.cursor {
            None => 0,
            Some(cursor) => {
                let bytes: [u8; 8] = cursor.0.as_slice().try_into().map_err(|_error| {
                    crate::query::invalid_cursor("invalid memory history cursor")
                })?;
                usize::try_from(u64::from_be_bytes(bytes)).map_err(|_error| {
                    crate::query::invalid_cursor("history cursor exceeds address space")
                })?
            }
        };
        let state = self.inner.read();
        if start > state.history.len() {
            return Err(crate::query::invalid_cursor(
                "history cursor is past the journal",
            ));
        }
        let mut page = StateHistoryPage {
            entries: Vec::new(),
            taint: TaintSet::pristine(),
            next: None,
            examined: 0,
            encoded_bytes: 0,
        };
        let mut previous = query.cursor.clone();
        let mut rows = state.history.iter().enumerate().skip(start);
        loop {
            if page.entries.len() == query.limits.entries.get()
                || page.examined == query.limits.examined.get()
            {
                page.next = previous;
                return Ok(page);
            }
            let Some((index, entry)) = rows.next() else {
                break;
            };
            page.examined += 1;
            page.taint.union(entry.event.taint());
            let cursor = StateCursor(((index + 1) as u64).to_be_bytes().to_vec());
            let path = entry.event.path();
            if entry.at_millis >= query.from_millis
                && entry.at_millis < query.to_millis
                && (path == &query.path || query.path.is_prefix_of(path))
            {
                let bytes = crate::host::encoded_size(entry)
                    .map_err(|failure| failure.with_taint(&page.taint))?;
                if bytes > query.limits.encoded_bytes.get() - page.encoded_bytes {
                    if page.entries.is_empty() {
                        return Err(crate::StateFailure::new(
                            StateError::RowTooLarge(Box::new(StateRowTooLarge {
                                path: path.clone(),
                                encoded_bytes: bytes,
                                retry: previous,
                                resume: cursor,
                            })),
                            page.taint,
                        ));
                    }
                    page.next = previous;
                    return Ok(page);
                }
                page.encoded_bytes += bytes;
                page.entries.push(entry.clone());
            }
            previous = Some(cursor);
        }
        Ok(page)
    }
}

impl StateFlush for InMemoryBackend {
    type Flush<'a> = Ready<StateResult<()>>;
    fn flush(&self) -> Self::Flush<'_> {
        self.resume_notifications();
        ready(Ok(()))
    }
}

#[cfg(test)]
mod tests;
