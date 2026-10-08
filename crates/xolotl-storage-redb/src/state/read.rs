//! Pages read provenance before payload sizing and materialize only admitted rows.

use super::*;
use crate::schema::{HISTORY_FLOOR_MILLIS, STATE_HISTORY_BASELINES_TABLE, STATE_LIST_ITEMS_TABLE};
use std::future::Future;
use std::num::NonZeroUsize;
use std::ops::Bound;
use std::pin::Pin;
use std::task::{Context, Poll};
use xolotl_kernel::host::{BlockingTask, blocking::dispatch};
use xolotl_state::{
    StateBoundedRead, StateCursor, StateHistory, StateHistoryPage, StateHistoryQuery, StatePage,
    StatePointTooLarge, StateQuery, StateRead, StateRowTooLarge, StateScan,
};

// An admitted read retains only its database and fixed history mode. It does
// not retain the spawner that owns the queued job or the subscription registry.
struct ReadOwner {
    db: Arc<Database>,
    history: RedbHistory,
}

impl ReadOwner {
    fn from_backend(backend: &RedbStateBackend) -> Self {
        Self {
            db: Arc::clone(&backend.db),
            history: backend.history,
        }
    }

    fn read_current(&self, path: &Path) -> StateResult<xolotl_state::StateObservation> {
        let key = path.to_string();
        let txn = self.db.begin_read().map_err(backend_error)?;
        let table = txn.open_table(STATE_VALUES_TABLE).map_err(backend_error)?;
        table
            .get(key.as_str())
            .map_err(backend_error)?
            .map(|guard| {
                if let Some(taint) = codec::decode_absence(guard.value())? {
                    return Ok(xolotl_state::StateObservation { value: None, taint });
                }
                if list::is_segmented(guard.value())? {
                    let items = txn
                        .open_table(STATE_LIST_ITEMS_TABLE)
                        .map_err(backend_error)?;
                    list::materialize(&items, guard.value())
                        .map(xolotl_state::StateObservation::from)
                } else {
                    decode_envelope(guard.value()).map(xolotl_state::StateObservation::from)
                }
            })
            .transpose()
            .map(Option::unwrap_or_default)
    }

    fn retained_from(&self) -> StateResult<i64> {
        if self.history == RedbHistory::CurrentOnly {
            return Err(StateError::MissingCapability("history_retention").into());
        }
        let txn = self.db.begin_read().map_err(backend_error)?;
        history_floor_in_txn(&txn)
    }

    fn read_current_bounded(
        &self,
        path: &Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> StateResult<xolotl_state::StateObservation> {
        let key = path.to_string();
        let txn = self.db.begin_read().map_err(backend_error)?;
        let table = txn.open_table(STATE_VALUES_TABLE).map_err(backend_error)?;
        let Some(guard) = table.get(key.as_str()).map_err(backend_error)? else {
            return Ok(xolotl_state::StateObservation::default());
        };
        let bytes = guard.value();
        let encoded_bytes = list::record_size(bytes, key.len())?;
        if encoded_bytes > max_encoded_bytes.get() {
            // The raw row size is known without decoding even a potentially
            // unbounded provenance header. Its sources remain unknown.
            return Err(StateError::PointTooLarge(Box::new(StatePointTooLarge {
                path: path.clone(),
                encoded_bytes,
                limit_encoded_bytes: max_encoded_bytes,
                provenance_observed: false,
            }))
            .into());
        }
        if let Some(taint) = codec::decode_absence(bytes)? {
            Ok(xolotl_state::StateObservation { value: None, taint })
        } else if list::is_segmented(bytes)? {
            let items = txn
                .open_table(STATE_LIST_ITEMS_TABLE)
                .map_err(backend_error)?;
            list::materialize(&items, bytes).map(xolotl_state::StateObservation::from)
        } else {
            decode_envelope(bytes).map(xolotl_state::StateObservation::from)
        }
    }

    fn state_page(&self, query: &StateScan) -> StateResult<StatePage> {
        let prefix = query.prefix.to_string();
        let after = query
            .cursor
            .as_ref()
            .map(|cursor| {
                let key = std::str::from_utf8(&cursor.0)
                    .map_err(|error| StateError::InvalidQuery(error.to_string()))?;
                let path = Path::parse(key)
                    .map_err(|error| StateError::InvalidQuery(error.to_string()))?;
                if (path != query.prefix && !query.prefix.is_prefix_of(&path))
                    || path.to_string() != key
                {
                    return Err(StateError::InvalidQuery(
                        "cursor is outside the prefix".into(),
                    ));
                }
                Ok(key)
            })
            .transpose()?;
        let (descendants_start, descendants_end) = descendant_bounds(&prefix, &query.prefix);
        let first_descendant = if descendants_start == prefix {
            Bound::Excluded(descendants_start.as_str())
        } else {
            Bound::Included(descendants_start.as_str())
        };
        let start = after
            .filter(|key| *key >= descendants_start.as_str())
            .map_or(first_descendant, Bound::Excluded);
        let txn = self.db.begin_read().map_err(backend_error)?;
        let table = txn.open_table(STATE_VALUES_TABLE).map_err(backend_error)?;
        let root = table
            .range::<&str>((
                Bound::Included(prefix.as_str()),
                Bound::Included(prefix.as_str()),
            ))
            .map_err(backend_error)?
            .take(usize::from(after.is_none()));
        let descendants = table
            .range::<&str>((start, Bound::Excluded(descendants_end.as_str())))
            .map_err(backend_error)?;
        let mut rows = root.chain(descendants);
        let mut page = StatePage::empty();
        let result = (|| -> StateResult<()> {
            let mut previous = query.cursor.clone();
            loop {
                if page.entries.len() == query.limits.entries.get()
                    || page.examined == query.limits.examined.get()
                    || page.encoded_bytes == query.limits.encoded_bytes.get()
                {
                    page.next = previous;
                    return Ok(());
                }
                let Some(row) = rows.next() else { break };
                let (key, bytes) = row.map_err(backend_error)?;
                let path = Path::parse(key.value()).map_err(backend_error)?;
                if path != query.prefix && !query.prefix.is_prefix_of(&path) {
                    return Err(backend_error("state index contains an out-of-scope path"));
                }
                page.examined += 1;
                let size = list::record_size(bytes.value(), key.value().len())?;
                // A deferred row still affects pagination and therefore its
                // sources. Bound its raw provenance header by this page's byte
                // budget before decoding that header, even when its payload is
                // too large to return in this page.
                let header_budget = query
                    .limits
                    .encoded_bytes
                    .get()
                    .saturating_sub(key.value().len());
                let row_taint = list::taint_if_header_fits(bytes.value(), header_budget)?;
                let Some(row_taint) = row_taint else {
                    if page.encoded_bytes != 0 {
                        page.next = previous;
                        return Ok(());
                    }
                    return Err(too_large(
                        path,
                        list::provenance_size(bytes.value(), key.value().len())?,
                        previous,
                        history_cursor(&[], key.value().as_bytes()),
                        false,
                    ));
                };
                page.taint.union(&row_taint);
                if size > query.limits.encoded_bytes.get() - page.encoded_bytes {
                    if page.encoded_bytes == 0 {
                        return Err(too_large(
                            path,
                            size,
                            previous,
                            history_cursor(&[], key.value().as_bytes()),
                            true,
                        ));
                    }
                    page.next = previous;
                    return Ok(());
                }
                if codec::validate_admitted_absence(bytes.value(), &row_taint)? {
                    page.encoded_bytes += size;
                    advance_cursor(&mut previous, &[], key.value().as_bytes());
                    continue;
                }
                let value = if list::is_segmented(bytes.value())? {
                    let items = txn
                        .open_table(STATE_LIST_ITEMS_TABLE)
                        .map_err(backend_error)?;
                    list::materialize_admitted(&items, bytes.value(), row_taint)?
                } else {
                    codec::decode_admitted_envelope(bytes.value(), row_taint)?
                };
                page.entries.push((path, value));
                page.encoded_bytes += size;
                advance_cursor(&mut previous, &[], key.value().as_bytes());
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(page),
            Err(failure) => Err(observed_failure(page.taint, failure)),
        }
    }

    fn history_page(&self, query: &StateHistoryQuery) -> StateResult<StateHistoryPage> {
        if self.history == RedbHistory::CurrentOnly {
            return Err(StateError::MissingCapability("history").into());
        }
        if !xolotl_state::history_retains_path(&query.path) {
            return Err(StateError::HistoryExcluded.into());
        }
        if query.from_millis > query.to_millis {
            return Err(StateError::InvalidQuery("history interval is reversed".into()).into());
        }
        let txn = self.db.begin_read().map_err(backend_error)?;
        let floor = history_floor_in_txn(&txn)?;
        if query.from_millis < floor {
            return Err(StateError::HistoryTrimmed {
                retained_from_millis: floor,
            }
            .into());
        }
        let cursor_scope = history_cursor_scope(query, floor)?;
        let prefix = query.path.to_string();
        let (descendants_start, descendants_end) = descendant_bounds(&prefix, &query.path);
        let mut start_key = prefix.as_bytes().to_vec();
        start_key.push(0xff);
        let end_key = history_scan_end(&query.path);
        let continuation = query
            .cursor
            .as_ref()
            .map(|cursor| history_cursor_key(cursor, &cursor_scope, floor))
            .transpose()?;
        if let Some(key) = continuation {
            let (path, _) = history_key_parts(key)
                .map_err(|_error| StateError::InvalidQuery("invalid history cursor key".into()))?;
            let separator = path.canonical_len().ok_or_else(|| {
                StateError::InvalidQuery("history cursor path length overflow".into())
            })?;
            if (path != query.path && !query.path.is_prefix_of(&path))
                || key.get(..separator) != Some(path.to_string().as_bytes())
                || !((key >= descendants_start.as_bytes() && key < descendants_end.as_bytes())
                    || (key >= start_key.as_slice() && key < end_key.as_slice()))
            {
                return Err(StateError::InvalidQuery(
                    "history cursor is outside the prefix".into(),
                )
                .into());
            }
        }
        let descendants_from = continuation
            .filter(|key| *key < descendants_end.as_bytes())
            .map_or(
                Bound::Included(descendants_start.as_bytes()),
                Bound::Excluded,
            );
        let root_from = continuation
            .filter(|key| *key >= start_key.as_slice())
            .map_or(Bound::Included(start_key.as_slice()), Bound::Excluded);
        let table = txn.open_table(STATE_HISTORY_TABLE).map_err(backend_error)?;
        let descendants = table
            .range::<&[u8]>((
                descendants_from,
                Bound::Excluded(descendants_end.as_bytes()),
            ))
            .map_err(backend_error)?
            .take(
                if continuation.is_some_and(|key| key >= start_key.as_slice()) {
                    0
                } else {
                    usize::MAX
                },
            );
        let root = table
            .range::<&[u8]>((root_from, Bound::Excluded(end_key.as_slice())))
            .map_err(backend_error)?;
        let mut rows = descendants.chain(root);
        let mut page = StateHistoryPage {
            entries: Vec::new(),
            next: None,
            examined: 0,
            encoded_bytes: 0,
            taint: TaintSet::pristine(),
        };
        let result = (|| -> StateResult<()> {
            let mut previous = query.cursor.clone();
            loop {
                if page.entries.len() == query.limits.entries.get()
                    || page.examined == query.limits.examined.get()
                    || page.encoded_bytes == query.limits.encoded_bytes.get()
                {
                    page.next = previous;
                    return Ok(());
                }
                let Some(row) = rows.next() else { break };
                let (key, bytes) = row.map_err(backend_error)?;
                page.examined += 1;
                let (path, at_millis) = history_key_parts(key.value())?;
                if path != query.path && !query.path.is_prefix_of(&path) {
                    return Err(backend_error("history index contains an out-of-scope path"));
                }
                let matches = at_millis >= query.from_millis && at_millis < query.to_millis;
                let metadata_size = codec::history_header_size(bytes.value())?
                    .checked_add(key.value().len())
                    .ok_or_else(|| backend_error("history metadata size overflow"))?;
                let size = if matches {
                    record_size(bytes.value(), key.value().len())?
                } else {
                    metadata_size
                };
                let header_budget = query
                    .limits
                    .encoded_bytes
                    .get()
                    .saturating_sub(key.value().len());
                let row_taint = codec::history_taint_if_header_fits(bytes.value(), header_budget)?;
                let Some(row_taint) = row_taint else {
                    if page.encoded_bytes != 0 {
                        page.next = previous;
                        return Ok(());
                    }
                    return Err(too_large(
                        path,
                        metadata_size,
                        previous,
                        history_cursor(&cursor_scope, key.value()),
                        false,
                    ));
                };
                page.taint.union(&row_taint);
                if size > query.limits.encoded_bytes.get() - page.encoded_bytes {
                    if page.encoded_bytes == 0 {
                        return Err(too_large(
                            path,
                            size,
                            previous,
                            history_cursor(&cursor_scope, key.value()),
                            true,
                        ));
                    }
                    page.next = previous;
                    return Ok(());
                }
                if matches {
                    let entry = codec::decode_admitted_history_entry(bytes.value(), row_taint)?;
                    page.entries
                        .push(validate_indexed_entry(entry, &path, at_millis)?);
                }
                page.encoded_bytes += size;
                advance_cursor(&mut previous, &cursor_scope, key.value());
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(page),
            Err(failure) => Err(observed_failure(page.taint, failure)),
        }
    }

    fn historical_value(
        &self,
        path: &Path,
        at_millis: i64,
    ) -> StateResult<xolotl_state::StateObservation> {
        if at_millis == 0 {
            return self.read_current(path);
        }
        if self.history == RedbHistory::CurrentOnly {
            return Err(StateError::MissingCapability("history").into());
        }
        if !xolotl_state::history_retains_path(path) {
            return Err(StateError::HistoryExcluded.into());
        }
        let txn = self.db.begin_read().map_err(backend_error)?;
        let floor = history_floor_in_txn(&txn)?;
        if at_millis < floor {
            return Err(StateError::HistoryTrimmed {
                retained_from_millis: floor,
            }
            .into());
        }
        let load_baseline = || -> StateResult<xolotl_state::StateObservation> {
            let baseline_table = txn
                .open_table(STATE_HISTORY_BASELINES_TABLE)
                .map_err(backend_error)?;
            Ok(baseline_table
                .get(path.to_string().as_str())
                .map_err(backend_error)?
                .map(|guard| codec::decode_observation(guard.value()))
                .transpose()?
                .unwrap_or_default())
        };
        // Committed history clocks start above zero. A negative instant can
        // contain only a retained baseline (and a positive floor was rejected
        // above). No later record needs to be inspected.
        if at_millis < 0 {
            return load_baseline();
        }
        let mut start = path.to_string().into_bytes();
        start.push(0xff);
        let mut end = start.clone();
        if let Some(next_millis) = at_millis.checked_add(1) {
            // A timestamp may have sequence-suffixed collision records. The
            // following timestamp is the exclusive bound for all of them.
            end.extend_from_slice(&next_millis.to_be_bytes());
        } else {
            end.push(0xff);
        }
        let table = txn.open_table(STATE_HISTORY_TABLE).map_err(backend_error)?;
        let rows = table
            .range(start.as_slice()..end.as_slice())
            .map_err(backend_error)?;
        let mut observed = TaintSet::pristine();
        let result = (|| -> StateResult<xolotl_state::StateObservation> {
            let mut current = None;
            for row in rows {
                let (key, bytes) = row.map_err(backend_error)?;
                let (stored_path, time) = history_key_parts(key.value())?;
                if stored_path != *path || time > at_millis {
                    continue;
                }
                let taint = codec::history_taint(bytes.value())?;
                observed.union(&taint);
                let entry = codec::decode_admitted_history_entry(bytes.value(), taint)?;
                let entry = validate_indexed_entry(entry, path, time)?;
                if current.is_none() {
                    let initial = if matches!(entry.event, StateEvent::Set { .. }) {
                        xolotl_state::StateObservation::default()
                    } else {
                        load_baseline()?
                    };
                    observed.union(&initial.taint);
                    current = Some(initial);
                }
                if let Some(current) = &mut current {
                    xolotl_state::apply_history_event(current, &entry.event)?;
                }
            }
            current.map_or_else(load_baseline, Ok)
        })();
        result.map_err(|failure| observed_failure(observed, failure))
    }
}

fn descendant_bounds(prefix: &str, path: &Path) -> (String, String) {
    let mut start = prefix.to_owned();
    let mut end = prefix.to_owned();
    if path.cluster().is_none() && path.segments().is_empty() {
        end.push('\u{7f}');
    } else {
        start.push('/');
        end.push('0');
    }
    (start, end)
}

pub(super) fn history_floor_in_txn(txn: &redb::ReadTransaction) -> StateResult<i64> {
    let meta = txn.open_table(STATE_META_TABLE).map_err(backend_error)?;
    meta.get(HISTORY_FLOOR_MILLIS)
        .map_err(backend_error)?
        .map(|guard| guard.value())
        .ok_or_else(|| backend_error("state history floor metadata missing"))
}

fn history_cursor(scope: &[u8], key: &[u8]) -> StateCursor {
    let mut bytes = Vec::with_capacity(scope.len() + key.len());
    bytes.extend_from_slice(scope);
    bytes.extend_from_slice(key);
    StateCursor(bytes)
}

fn advance_cursor(previous: &mut Option<StateCursor>, scope: &[u8], key: &[u8]) {
    let cursor =
        previous.get_or_insert_with(|| StateCursor(Vec::with_capacity(scope.len() + key.len())));
    cursor.0.clear();
    cursor.0.extend_from_slice(scope);
    cursor.0.extend_from_slice(key);
}

pub(super) fn history_cursor_scope(query: &StateHistoryQuery, floor: i64) -> StateResult<Vec<u8>> {
    let path = query.path.to_string();
    let path_len = u64::try_from(path.len())
        .map_err(|_error| StateError::InvalidQuery("history path is too long".into()))?;
    let mut scope = Vec::with_capacity(32 + path.len());
    scope.extend_from_slice(&floor.to_be_bytes());
    scope.extend_from_slice(&query.from_millis.to_be_bytes());
    scope.extend_from_slice(&query.to_millis.to_be_bytes());
    scope.extend_from_slice(&path_len.to_be_bytes());
    scope.extend_from_slice(path.as_bytes());
    Ok(scope)
}

fn history_cursor_key<'a>(
    cursor: &'a StateCursor,
    scope: &[u8],
    floor: i64,
) -> StateResult<&'a [u8]> {
    if cursor.0.get(..8) != Some(floor.to_be_bytes().as_slice()) {
        return Err(
            StateError::InvalidQuery("history cursor was invalidated by retention".into()).into(),
        );
    }
    cursor
        .0
        .strip_prefix(scope)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| {
            StateError::InvalidQuery("history cursor belongs to another query".into()).into()
        })
}

fn observed_failure(mut observed: TaintSet, failure: StateFailure) -> StateFailure {
    // Earlier rows and any current header that fit the page budget were
    // observed before payload decoding failed. An oversized header remains
    // explicitly unknown on RowTooLarge, not silently pristine.
    observed.union(&failure.taint);
    StateFailure::new(failure.error, observed)
}

fn record_size(bytes: &[u8], key_size: usize) -> StateResult<usize> {
    bytes
        .len()
        .checked_add(key_size)
        .ok_or_else(|| backend_error("state record size overflow"))
}

pub(super) fn decode_indexed_entry(
    bytes: &[u8],
    path: &Path,
    at_millis: i64,
) -> StateResult<StateHistoryEntry> {
    validate_indexed_entry(decode_history_entry(bytes)?, path, at_millis)
}

fn validate_indexed_entry(
    entry: StateHistoryEntry,
    path: &Path,
    at_millis: i64,
) -> StateResult<StateHistoryEntry> {
    if entry.event.path() != path || entry.at_millis != at_millis {
        return Err(backend_error("state history key does not match its record")
            .with_taint(entry.event.taint()));
    }
    Ok(entry)
}

fn too_large(
    path: Path,
    encoded_bytes: usize,
    retry: Option<StateCursor>,
    resume: StateCursor,
    provenance_observed: bool,
) -> StateFailure {
    StateError::RowTooLarge(Box::new(StateRowTooLarge {
        path,
        encoded_bytes,
        provenance_observed,
        retry,
        resume,
    }))
    .into()
}

/// A redb read which admits one owned blocking job on its first poll.
/// Constructing or dropping an unpolled future performs no storage work.
/// The job owns its input and may open a transaction after admission; dropping
/// its waiter does not cancel it.
pub struct RedbReadFuture<'a, A, O, T> {
    backend: &'a RedbStateBackend,
    phase: ReadPhase<A, T>,
    own: fn(A) -> O,
    read: fn(&ReadOwner, O) -> StateResult<T>,
}

enum ReadPhase<A, T> {
    New(A),
    Running(BlockingTask<StateResult<T>>),
    Done,
}

impl<'a, A, O, T> RedbReadFuture<'a, A, O, T> {
    fn new(
        backend: &'a RedbStateBackend,
        request: A,
        own: fn(A) -> O,
        read: fn(&ReadOwner, O) -> StateResult<T>,
    ) -> Self {
        Self {
            backend,
            phase: ReadPhase::New(request),
            own,
            read,
        }
    }
}

impl<A, O, T> Future for RedbReadFuture<'_, A, O, T>
where
    A: Unpin,
    O: Send + 'static,
    T: Send + Unpin + 'static,
{
    type Output = StateResult<T>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let mut task = match std::mem::replace(&mut this.phase, ReadPhase::Done) {
            ReadPhase::New(request) => {
                let owned = (this.own)(request);
                let owner = ReadOwner::from_backend(this.backend);
                let read = this.read;
                match dispatch(this.backend.blocking_spawner.as_ref(), move || {
                    read(&owner, owned)
                }) {
                    Ok(task) => task,
                    Err(error) => {
                        return Poll::Ready(Err(backend_error(format!(
                            "state read admission failed: {error}"
                        ))));
                    }
                }
            }
            ReadPhase::Running(task) => task,
            ReadPhase::Done => {
                return Poll::Ready(Err(backend_error("read future polled after completion")));
            }
        };
        match Pin::new(&mut task).poll(context) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(error)) => Poll::Ready(Err(backend_error(format!(
                "state read worker failed: {error}"
            )))),
            Poll::Pending => {
                this.phase = ReadPhase::Running(task);
                Poll::Pending
            }
        }
    }
}

pub(super) fn retained_from(backend: &RedbStateBackend) -> RedbReadFuture<'_, (), (), i64> {
    RedbReadFuture::new(backend, (), std::convert::identity, |owner, ()| {
        owner.retained_from()
    })
}

impl StateRead for RedbStateBackend {
    type Read<'a> = RedbReadFuture<'a, &'a Path, Path, xolotl_state::StateObservation>;
    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        RedbReadFuture::new(self, path, Path::clone, |backend, path| {
            backend.read_current(&path)
        })
    }
}
impl StateBoundedRead for RedbStateBackend {
    type BoundedRead<'a> = RedbReadFuture<
        'a,
        (&'a Path, NonZeroUsize),
        (Path, NonZeroUsize),
        xolotl_state::StateObservation,
    >;
    fn read_tainted_bounded<'a>(
        &'a self,
        path: &'a Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedRead<'a> {
        RedbReadFuture::new(
            self,
            (path, max_encoded_bytes),
            |(path, limit)| (path.clone(), limit),
            |backend, (path, limit)| backend.read_current_bounded(&path, limit),
        )
    }
}
impl StateQuery for RedbStateBackend {
    type Query<'a> = RedbReadFuture<'a, &'a StateScan, StateScan, StatePage>;
    fn query<'a>(&'a self, query: &'a StateScan) -> Self::Query<'a> {
        RedbReadFuture::new(self, query, StateScan::clone, |backend, query| {
            backend.state_page(&query)
        })
    }
}
impl StateHistory for RedbStateBackend {
    type History<'a> =
        RedbReadFuture<'a, &'a StateHistoryQuery, StateHistoryQuery, StateHistoryPage>;
    type At<'a> = RedbReadFuture<'a, (&'a Path, i64), (Path, i64), xolotl_state::StateObservation>;
    fn history<'a>(&'a self, query: &'a StateHistoryQuery) -> Self::History<'a> {
        RedbReadFuture::new(self, query, StateHistoryQuery::clone, |backend, query| {
            backend.history_page(&query)
        })
    }
    fn read_at<'a>(&'a self, path: &'a Path, at_millis: i64) -> Self::At<'a> {
        RedbReadFuture::new(
            self,
            (path, at_millis),
            |(path, at_millis)| (path.clone(), at_millis),
            |backend, (path, at_millis)| backend.historical_value(&path, at_millis),
        )
    }
}
