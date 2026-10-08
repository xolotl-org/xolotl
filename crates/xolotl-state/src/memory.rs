//! Optional in-memory backend. Used for tests, the embedded SDK, and the
//! default daemon when no persistent backend is configured.
//!
//! Compact or sharded current-value storage shares one commit and notification
//! contract. History retention is independently selectable; full history is
//! unbounded, while disabled history retains current values and absence evidence.

mod options;
mod record;
mod source;
mod storage;

pub use options::{InMemoryOptions, MemoryHistory};

use crate::prelude::*;
#[cfg(test)]
use crate::test_support::{CollectHistory, CollectState};
use crate::{
    Backend, StateCursor, StateError, StateEvent, StateHistoryEntry, StateHistoryPage,
    StateHistoryQuery, StateHistoryRetention, StateHistoryTrim, StateMutation, StateObservation,
    StatePage, StateResult, StateRowTooLarge, StateScan, StateStream, TaintedValue,
};
use record::{AbsenceUsage, CurrentRecord};
use std::collections::{BTreeMap, VecDeque};
use std::future::{Ready, ready};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use storage::Storage;
use tokio::sync::broadcast;
#[cfg(test)]
use xolotl_types::MergeRule;
use xolotl_types::{Path, TaintSet, Value};

struct Notification {
    event: StateEvent,
    targets: Vec<broadcast::Sender<StateEvent>>,
}

#[derive(Default)]
struct MemoryState {
    values: BTreeMap<Path, CurrentRecord>,
    journal: Journal,
}

struct Journal {
    history: VecDeque<StateHistoryEntry>,
    history_baselines: BTreeMap<Path, StateObservation>,
    history_floor: i64,
    last_history_millis: i64,
    subscribers: crate::host::WatchRegistry,
    notifications: VecDeque<Notification>,
    notifying: bool,
    source: source::SourceMemory,
    absence: AbsenceUsage,
}

impl Default for Journal {
    fn default() -> Self {
        Self {
            history: VecDeque::new(),
            history_baselines: BTreeMap::new(),
            history_floor: i64::MIN,
            last_history_millis: 0,
            subscribers: crate::host::WatchRegistry::default(),
            notifications: VecDeque::new(),
            notifying: false,
            source: source::SourceMemory::default(),
            absence: AbsenceUsage::default(),
        }
    }
}

/// In-process state. Stores one live or sourced-absence record per path.
/// When history is enabled, current records and history commit
/// atomically. Notifications follow commit order and run outside all locks.
/// The default uses one inline map without historical retention;
/// [`Self::with_options`] selects sharded reads and optional full history.
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
    /// deployments. It retains current values and provenance without mutation
    /// history. Opt in to [`MemoryHistory::Full`] for history pages and
    /// historical `read_at`; full history has no retention limit. Notification
    /// queues default to 256 entries; see
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
    /// writes can extend that writer's return latency. Current values and any
    /// explicitly enabled history have no total byte limit here.
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
        if options.source_stream_limit.get() > InMemoryOptions::MAX_SOURCE_STREAM_LIMIT {
            return Err(StateError::Backend(format!(
                "Source stream limit exceeds maximum {}",
                InMemoryOptions::MAX_SOURCE_STREAM_LIMIT
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
        prepare: impl FnOnce(&BTreeMap<Path, CurrentRecord>) -> StateResult<Option<StateEvent>>,
    ) -> StateResult<crate::StateCommit> {
        let result = (|| -> StateResult<crate::StateCommit> {
            let wall_millis = (self.options.history == MemoryHistory::Full
                && crate::history_retains_path(&map_key))
            .then(now_millis);
            let (drain, replaced, unretained) = {
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
                    observed.union(current.taint());
                }
                let Some(event) = prepare(values)? else {
                    return Ok(crate::StateCommit {
                        taint: observed.clone(),
                    });
                };
                let at_millis = wall_millis
                    .map(|wall_millis| {
                        state
                            .last_history_millis
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
                let current = values.get(&map_key);
                let next = match &event {
                    StateEvent::Set { value, taint, .. } => {
                        let value = TaintedValue::new(value.clone(), taint.clone());
                        Some(CurrentRecord::Live(value))
                    }
                    StateEvent::Append { path, item, taint } => {
                        let taint = current.map_or_else(
                            || taint.clone(),
                            |current| current.taint().clone().merged(taint),
                        );
                        let appended = crate::values::append_observed_value(
                            path,
                            current.and_then(CurrentRecord::value),
                            item.clone(),
                            taint,
                        )?;
                        Some(CurrentRecord::Live(appended))
                    }
                    StateEvent::DropPrefixAppend {
                        path,
                        removed: drop_prefix,
                        item,
                        taint,
                    } => {
                        let taint = current.map_or_else(
                            || taint.clone(),
                            |current| current.taint().clone().merged(taint),
                        );
                        let appended = crate::values::drop_prefix_append_observed_value(
                            path,
                            current.and_then(CurrentRecord::value),
                            *drop_prefix,
                            item.clone(),
                            taint,
                        )?;
                        Some(CurrentRecord::Live(appended))
                    }
                    StateEvent::Delete { path, taint } => {
                        let taint = current.map_or_else(
                            || taint.clone(),
                            |current| current.taint().clone().merged(taint),
                        );
                        CurrentRecord::absent(path, taint)?
                    }
                };
                let absence = state
                    .absence
                    .replacing(current, next.as_ref(), &self.options)?;
                let replaced = if let Some(next) = next {
                    values.insert(map_key, next)
                } else {
                    values.remove(&map_key)
                };
                state.absence = absence;
                if !targets.is_empty() {
                    state.notifications.push_back(Notification {
                        event: event.clone(),
                        targets,
                    });
                }
                let unretained = if let Some(at_millis) = at_millis {
                    state.last_history_millis = at_millis;
                    state
                        .history
                        .push_back(StateHistoryEntry { at_millis, event });
                    None
                } else {
                    Some(event)
                };
                let drain = !state.notifying && !state.notifications.is_empty();
                state.notifying |= drain;
                (drain, replaced, unretained)
            };
            drop((replaced, unretained));
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
        self.into_source_parts().0
    }

    /// Install ordinary State capabilities and retain the same storage owner
    /// for the Source atomic-commit, maintenance and evidence ports. Both
    /// returned values must be kept together by the host.
    pub fn into_source_parts(self) -> (Backend, Arc<Self>) {
        let history = self.options.history == MemoryHistory::Full;
        let port = Arc::new(self);
        let backend = Backend::new()
            .with_read(port.clone())
            .with_bounded_read(port.clone())
            .with_write(port.clone())
            .with_bounded_write(port.clone())
            .with_query(port.clone())
            .with_watch(port.clone())
            .with_signal(port.clone())
            .with_flush(port.clone());
        let backend = if history {
            backend
                .with_history(port.clone())
                .with_history_retention(port.clone())
        } else {
            backend
        };
        (backend, port)
    }
}

impl StateRead for InMemoryBackend {
    type Read<'a> = Ready<StateResult<StateObservation>>;
    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        ready(Ok(self.inner.observe(path)))
    }
}

impl StateBoundedRead for InMemoryBackend {
    type BoundedRead<'a> = Ready<StateResult<StateObservation>>;
    fn read_tainted_bounded<'a>(
        &'a self,
        path: &'a Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedRead<'a> {
        ready(self.inner.get_bounded(path, max_encoded_bytes))
    }
}

impl InMemoryBackend {
    fn mutate_with_limit(
        &self,
        path: &Path,
        mutation: StateMutation,
        max_current_encoded_bytes: Option<NonZeroUsize>,
    ) -> StateResult<crate::StateCommit> {
        let incoming = mutation.input_taint().clone();
        self.commit(path.clone(), incoming, |values| {
            let stored = values.get(path);
            if let (Some(limit), Some(current)) = (max_current_encoded_bytes, stored) {
                // Measure the borrowed current value inside the commit lock,
                // before a failed comparison could clone its actual Value.
                let encoded_bytes = current.encoded_bytes(path)?;
                if encoded_bytes > limit.get() {
                    return Err(crate::StateFailure::new(
                        StateError::PointTooLarge(Box::new(crate::StatePointTooLarge {
                            path: path.clone(),
                            encoded_bytes,
                            limit_encoded_bytes: limit,
                            provenance_observed: true,
                        })),
                        current.taint().clone(),
                    ));
                }
            }
            let mut observed = mutation.input_taint().clone();
            if !matches!(&mutation, StateMutation::Set(_))
                && let Some(current) = stored
            {
                observed.union(current.taint());
            }
            mutation.prepare_event(path, stored.and_then(CurrentRecord::value), observed)
        })
    }
}

impl StateWrite for InMemoryBackend {
    type Write<'a> = Ready<StateResult<crate::StateCommit>>;
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        ready(self.mutate_with_limit(path, mutation, None))
    }
}

impl StateBoundedWrite for InMemoryBackend {
    type BoundedWrite<'a> = Ready<StateResult<crate::StateCommit>>;

    fn compare_set_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        ready(self.mutate_with_limit(
            path,
            StateMutation::CompareSet { expected, value },
            Some(max_current_encoded_bytes),
        ))
    }

    fn compare_delete_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: TaintSet,
        max_current_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        ready(self.mutate_with_limit(
            path,
            StateMutation::CompareDelete { expected, taint },
            Some(max_current_encoded_bytes),
        ))
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
    type At<'a> = Ready<StateResult<StateObservation>>;
    fn history<'a>(&'a self, query: &'a StateHistoryQuery) -> Self::History<'a> {
        ready(self.history_page(query))
    }
    fn read_at<'a>(&'a self, path: &'a Path, at_millis: i64) -> Self::At<'a> {
        ready((|| {
            if at_millis == 0 {
                return Ok(self.inner.observe(path));
            }
            if self.options.history == MemoryHistory::Disabled {
                return Err(StateError::MissingCapability("history").into());
            }
            if !crate::history_retains_path(path) {
                return Err(StateError::HistoryExcluded.into());
            }
            let state = self.inner.read();
            if at_millis < state.history_floor {
                return Err(StateError::HistoryTrimmed {
                    retained_from_millis: state.history_floor,
                }
                .into());
            }
            let entries = state
                .history
                .iter()
                .take_while(|entry| entry.at_millis <= at_millis)
                .filter(|entry| entry.event.path() == path);
            let mut entries = entries.peekable();
            let mut value = if entries
                .peek()
                .is_some_and(|entry| matches!(entry.event, StateEvent::Set { .. }))
            {
                StateObservation::default()
            } else {
                state
                    .history_baselines
                    .get(path)
                    .cloned()
                    .unwrap_or_default()
            };
            let mut observed = value.taint.clone();
            for entry in entries {
                observed.union(entry.event.taint());
                crate::history::apply_event(&mut value, &entry.event)
                    .map_err(|failure| failure.with_taint(&observed))?;
            }
            Ok(value)
        })())
    }
}

impl StateHistoryRetention for InMemoryBackend {
    type Floor<'a> = Ready<StateResult<i64>>;
    type Trim<'a> = Ready<StateResult<StateHistoryTrim>>;

    fn retained_from(&self) -> Self::Floor<'_> {
        ready(if self.options.history == MemoryHistory::Full {
            Ok(self.inner.read().history_floor)
        } else {
            Err(StateError::MissingCapability("history_retention").into())
        })
    }

    fn trim_before(&self, floor: i64, limits: crate::StateHistoryTrimLimits) -> Self::Trim<'_> {
        ready(self.trim_history_before(floor, limits))
    }
}

impl InMemoryBackend {
    fn trim_history_before(
        &self,
        floor: i64,
        limits: crate::StateHistoryTrimLimits,
    ) -> StateResult<StateHistoryTrim> {
        if self.options.history == MemoryHistory::Disabled {
            return Err(StateError::MissingCapability("history_retention").into());
        }
        let mut state = self.inner.write();
        if floor <= 0 || floor == i64::MAX || floor < state.history_floor {
            return Err(crate::query::invalid_cursor(
                "history trim floor must advance and leave room for later writes",
            ));
        }
        if floor == state.history_floor {
            return Ok(StateHistoryTrim {
                retained_from_millis: floor,
                removed_events: 0,
            });
        }
        let removed = state
            .history
            .partition_point(|entry| entry.at_millis < floor);
        if removed > limits.events.get() {
            return Err(StateError::HistoryTrimLimit {
                provenance_observed: false,
            }
            .into());
        }
        let mut staged: BTreeMap<Path, StateObservation> = BTreeMap::new();
        let mut input_bytes = 0usize;
        let mut baseline_bytes = 0usize;
        let mut observed = TaintSet::pristine();
        for entry in state.history.iter().take(removed) {
            observed.union(entry.event.taint());
            input_bytes = input_bytes
                .checked_add(
                    crate::host::encoded_size(entry)
                        .map_err(|failure| failure.with_taint(&observed))?,
                )
                .ok_or_else(|| {
                    crate::StateFailure::new(
                        StateError::HistoryTrimLimit {
                            provenance_observed: true,
                        },
                        observed.clone(),
                    )
                })?;
            if input_bytes > limits.encoded_bytes.get() {
                return Err(crate::StateFailure::new(
                    StateError::HistoryTrimLimit {
                        provenance_observed: true,
                    },
                    observed,
                ));
            }
            let path = entry.event.path();
            if !staged.contains_key(path) {
                let existing = if matches!(entry.event, StateEvent::Set { .. }) {
                    None
                } else {
                    state.history_baselines.get(path)
                };
                if let Some(existing) = existing {
                    observed.union(&existing.taint);
                }
                baseline_bytes = baseline_bytes
                    .checked_add(
                        memory_baseline_size(path, existing)
                            .map_err(|failure| failure.with_taint(&observed))?,
                    )
                    .ok_or_else(|| {
                        crate::StateFailure::new(
                            StateError::HistoryTrimLimit {
                                provenance_observed: true,
                            },
                            observed.clone(),
                        )
                    })?;
                if input_bytes.saturating_add(baseline_bytes) > limits.encoded_bytes.get() {
                    return Err(crate::StateFailure::new(
                        StateError::HistoryTrimLimit {
                            provenance_observed: true,
                        },
                        observed,
                    ));
                }
                staged.insert(path.clone(), existing.cloned().unwrap_or_default());
            }
            let current = staged
                .get_mut(path)
                .ok_or_else(|| StateError::Backend("staged history path missing".into()))?;
            let before_size = memory_baseline_size(path, Some(current))
                .map_err(|failure| failure.with_taint(&observed))?;
            crate::apply_history_event(current, &entry.event)
                .map_err(|failure| failure.with_taint(&observed))?;
            let after_size = memory_baseline_size(path, Some(current))
                .map_err(|failure| failure.with_taint(&observed))?;
            baseline_bytes = baseline_bytes
                .checked_sub(before_size)
                .and_then(|count| count.checked_add(after_size))
                .ok_or_else(|| {
                    crate::StateFailure::new(
                        StateError::HistoryTrimLimit {
                            provenance_observed: true,
                        },
                        observed.clone(),
                    )
                })?;
            if input_bytes.saturating_add(baseline_bytes) > limits.encoded_bytes.get() {
                return Err(crate::StateFailure::new(
                    StateError::HistoryTrimLimit {
                        provenance_observed: true,
                    },
                    observed,
                ));
            }
        }
        for (path, value) in staged {
            if value.value.is_some() || !value.taint.is_pristine() {
                state.history_baselines.insert(path, value);
            } else {
                state.history_baselines.remove(&path);
            }
        }
        // A prefix drain advances the deque head without moving the retained
        // suffix. Reuse capacity for small rolling trims; compact only after
        // substantial slack has accumulated, and release it when empty.
        if removed == state.history.len() {
            state.history = VecDeque::new();
        } else if removed != 0 {
            state.history.drain(..removed);
            let retained = state.history.len();
            if state.history.capacity() >= 128 && retained <= state.history.capacity() / 4 {
                state.history.shrink_to(retained.saturating_mul(2));
            }
        }
        state.history_floor = floor;
        state.last_history_millis = state.last_history_millis.max(floor - 1);
        Ok(StateHistoryTrim {
            retained_from_millis: floor,
            removed_events: removed as u64,
        })
    }

    fn history_page(&self, query: &StateHistoryQuery) -> StateResult<StateHistoryPage> {
        if self.options.history == MemoryHistory::Disabled {
            return Err(StateError::MissingCapability("history").into());
        }
        if !crate::history_retains_path(&query.path) {
            return Err(StateError::HistoryExcluded.into());
        }
        if query.from_millis > query.to_millis {
            return Err(crate::query::invalid_cursor("history interval is reversed"));
        }
        let state = self.inner.read();
        if query.from_millis < state.history_floor {
            return Err(StateError::HistoryTrimmed {
                retained_from_millis: state.history_floor,
            }
            .into());
        }
        let cursor_scope = memory_history_cursor_scope(query, state.history_floor)?;
        let start = match &query.cursor {
            None => 0,
            Some(cursor) => {
                if cursor.0.get(..8) != Some(state.history_floor.to_be_bytes().as_slice()) {
                    return Err(crate::query::invalid_cursor(
                        "history cursor was invalidated by retention",
                    ));
                }
                let offset: [u8; 8] = cursor
                    .0
                    .strip_prefix(cursor_scope.as_slice())
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| {
                        crate::query::invalid_cursor("history cursor belongs to another query")
                    })?;
                usize::try_from(u64::from_be_bytes(offset)).map_err(|_error| {
                    crate::query::invalid_cursor("history cursor exceeds address space")
                })?
            }
        };
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
        let cursor_at = |offset: usize| {
            let mut bytes = Vec::with_capacity(cursor_scope.len() + 8);
            bytes.extend_from_slice(&cursor_scope);
            bytes.extend_from_slice(&(offset as u64).to_be_bytes());
            StateCursor(bytes)
        };
        let cursor_before = |offset: usize| {
            if offset == start {
                query.cursor.clone()
            } else {
                Some(cursor_at(offset))
            }
        };
        let mut position = start;
        let mut rows = state.history.iter().enumerate().skip(start);
        loop {
            if page.entries.len() == query.limits.entries.get()
                || page.examined == query.limits.examined.get()
                || page.encoded_bytes == query.limits.encoded_bytes.get()
            {
                page.next = cursor_before(position);
                return Ok(page);
            }
            let Some((index, entry)) = rows.next() else {
                break;
            };
            page.examined += 1;
            let path = entry.event.path();
            if path != &query.path && !query.path.is_prefix_of(path) {
                position = index + 1;
                continue;
            }
            let metadata_bytes = record::provenance_size(path, entry.event.taint())
                .map_err(|failure| failure.with_taint(&page.taint))?;
            if metadata_bytes > query.limits.encoded_bytes.get() {
                if position != start {
                    page.next = cursor_before(position);
                    return Ok(page);
                }
                return Err(crate::StateFailure::new(
                    StateError::RowTooLarge(Box::new(StateRowTooLarge {
                        path: path.clone(),
                        encoded_bytes: metadata_bytes,
                        provenance_observed: false,
                        retry: cursor_before(position),
                        resume: cursor_at(index + 1),
                    })),
                    page.taint,
                ));
            }
            page.taint.union(entry.event.taint());
            let matches_time =
                entry.at_millis >= query.from_millis && entry.at_millis < query.to_millis;
            let bytes = if matches_time {
                crate::host::encoded_size(entry)
                    .map_err(|failure| failure.with_taint(&page.taint))?
            } else {
                metadata_bytes
            };
            if bytes > query.limits.encoded_bytes.get() - page.encoded_bytes {
                if position == start {
                    return Err(crate::StateFailure::new(
                        StateError::RowTooLarge(Box::new(StateRowTooLarge {
                            path: path.clone(),
                            encoded_bytes: bytes,
                            provenance_observed: true,
                            retry: cursor_before(position),
                            resume: cursor_at(index + 1),
                        })),
                        page.taint,
                    ));
                }
                page.next = cursor_before(position);
                return Ok(page);
            }
            page.encoded_bytes += bytes;
            if matches_time {
                page.entries.push(entry.clone());
            }
            position = index + 1;
        }
        Ok(page)
    }
}

fn memory_history_cursor_scope(query: &StateHistoryQuery, floor: i64) -> StateResult<Vec<u8>> {
    let path = query.path.to_string();
    let path_len = u64::try_from(path.len())
        .map_err(|_error| StateError::InvalidQuery("history path is too long".into()))?;
    let mut bytes = Vec::with_capacity(32 + path.len());
    bytes.extend_from_slice(&floor.to_be_bytes());
    bytes.extend_from_slice(&query.from_millis.to_be_bytes());
    bytes.extend_from_slice(&query.to_millis.to_be_bytes());
    bytes.extend_from_slice(&path_len.to_be_bytes());
    bytes.extend_from_slice(path.as_bytes());
    Ok(bytes)
}

fn memory_baseline_size(path: &Path, value: Option<&StateObservation>) -> StateResult<usize> {
    value.map_or(Ok(0), |value| {
        if value.value.is_none() && value.taint.is_pristine() {
            return Ok(0);
        }
        crate::host::encoded_size(value)?
            .checked_add(path.canonical_len().ok_or(StateError::HistoryTrimLimit {
                provenance_observed: true,
            })?)
            .ok_or(
                StateError::HistoryTrimLimit {
                    provenance_observed: true,
                }
                .into(),
            )
    })
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
