//! Pages read provenance before payload sizing and materialize only admitted rows.

use super::*;
use std::ops::Bound;
use xolotl_state::{
    StateCursor, StateHistory, StateHistoryPage, StateHistoryQuery, StatePage, StateQuery,
    StateRead, StateRowTooLarge, StateScan,
};

impl RedbStateBackend {
    fn read_current(&self, path: &Path) -> StateResult<Option<TaintedValue>> {
        let key = path.to_string();
        let txn = self.db.begin_read().map_err(backend_error)?;
        let table = txn.open_table(STATE_VALUES_TABLE).map_err(backend_error)?;
        table
            .get(key.as_str())
            .map_err(backend_error)?
            .map(|guard| decode_envelope(guard.value()))
            .transpose()
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
                if !key.starts_with(&prefix) || path.to_string() != key {
                    return Err(StateError::InvalidQuery(
                        "cursor is outside the prefix".into(),
                    ));
                }
                Ok(key)
            })
            .transpose()?;
        let start = after.map_or(Bound::Included(prefix.as_str()), Bound::Excluded);
        let txn = self.db.begin_read().map_err(backend_error)?;
        let table = txn.open_table(STATE_VALUES_TABLE).map_err(backend_error)?;
        let mut rows = table
            .range::<&str>((start, Bound::Unbounded))
            .map_err(backend_error)?;
        let mut page = StatePage::empty();
        let result = (|| -> StateResult<()> {
            let mut previous = query.cursor.clone();
            loop {
                if page.entries.len() == query.limits.entries.get()
                    || page.examined == query.limits.examined.get()
                {
                    page.next = previous;
                    return Ok(());
                }
                let Some(row) = rows.next() else { break };
                let (key, bytes) = row.map_err(backend_error)?;
                if !key.value().starts_with(&prefix) {
                    break;
                }
                page.examined += 1;
                page.taint.union(&codec::envelope_taint(bytes.value())?);
                let path = Path::parse(key.value()).map_err(backend_error)?;
                let cursor = StateCursor(key.value().as_bytes().to_vec());
                if path == query.prefix || query.prefix.is_prefix_of(&path) {
                    let size = record_size(bytes.value(), key.value().len())?;
                    if size > query.limits.encoded_bytes.get() - page.encoded_bytes {
                        if page.entries.is_empty() {
                            return Err(too_large(path, size, previous, cursor));
                        }
                        page.next = previous;
                        return Ok(());
                    }
                    let value = decode_envelope(bytes.value())?;
                    page.entries.push((path, value));
                    page.encoded_bytes += size;
                }
                previous = Some(cursor);
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(page),
            Err(failure) => Err(observed_failure(page.taint, failure)),
        }
    }

    fn history_page(&self, query: &StateHistoryQuery) -> StateResult<StateHistoryPage> {
        if query.from_millis > query.to_millis {
            return Err(StateError::InvalidQuery("history interval is reversed".into()).into());
        }
        let start_key = query.path.to_string().into_bytes();
        let end_key = history_scan_end(&query.path);
        if query
            .cursor
            .as_ref()
            .is_some_and(|cursor| cursor.0 < start_key || cursor.0 >= end_key)
        {
            return Err(
                StateError::InvalidQuery("history cursor is outside the prefix".into()).into(),
            );
        }
        let start = query
            .cursor
            .as_ref()
            .map_or(Bound::Included(start_key.as_slice()), |cursor| {
                Bound::Excluded(cursor.0.as_slice())
            });
        let txn = self.db.begin_read().map_err(backend_error)?;
        let table = txn.open_table(STATE_HISTORY_TABLE).map_err(backend_error)?;
        let mut rows = table
            .range::<&[u8]>((start, Bound::Excluded(end_key.as_slice())))
            .map_err(backend_error)?;
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
                {
                    page.next = previous;
                    return Ok(());
                }
                let Some(row) = rows.next() else { break };
                let (key, bytes) = row.map_err(backend_error)?;
                page.examined += 1;
                page.taint.union(&codec::history_taint(bytes.value())?);
                let (path, at_millis) = history_key_parts(key.value())?;
                let cursor = StateCursor(key.value().to_vec());
                if (path == query.path || query.path.is_prefix_of(&path))
                    && at_millis >= query.from_millis
                    && at_millis < query.to_millis
                {
                    let size = record_size(bytes.value(), key.value().len())?;
                    if size > query.limits.encoded_bytes.get() - page.encoded_bytes {
                        if page.entries.is_empty() {
                            return Err(too_large(path, size, previous, cursor));
                        }
                        page.next = previous;
                        return Ok(());
                    }
                    page.entries
                        .push(decode_indexed_entry(bytes.value(), &path, at_millis)?);
                    page.encoded_bytes += size;
                }
                previous = Some(cursor);
            }
            Ok(())
        })();
        match result {
            Ok(()) => Ok(page),
            Err(failure) => Err(observed_failure(page.taint, failure)),
        }
    }

    fn historical_value(&self, path: &Path, at_millis: i64) -> StateResult<Option<TaintedValue>> {
        if at_millis == 0 {
            return self.read_current(path);
        }
        let mut start = path.to_string().into_bytes();
        start.push(0xff);
        let mut end = start.clone();
        end.push(0xff);
        let txn = self.db.begin_read().map_err(backend_error)?;
        let table = txn.open_table(STATE_HISTORY_TABLE).map_err(backend_error)?;
        let rows = table
            .range(start.as_slice()..end.as_slice())
            .map_err(backend_error)?;
        let mut observed = TaintSet::pristine();
        let result = (|| -> StateResult<Option<TaintedValue>> {
            let mut current = None;
            for row in rows {
                let (key, bytes) = row.map_err(backend_error)?;
                observed.union(&codec::history_taint(bytes.value())?);
                let (stored_path, time) = history_key_parts(key.value())?;
                if stored_path == *path && time <= at_millis {
                    let entry = decode_indexed_entry(bytes.value(), path, time)?;
                    xolotl_state::apply_history_event(&mut current, &entry.event)?;
                }
            }
            Ok(current)
        })();
        result.map_err(|failure| observed_failure(observed, failure))
    }
}

fn observed_failure(mut observed: TaintSet, failure: StateFailure) -> StateFailure {
    // Earlier rows and the current record's header were observed before payload
    // decoding failed. Keep that order, then include any additional error sources.
    observed.union(&failure.taint);
    StateFailure::new(failure.error, observed)
}

fn record_size(bytes: &[u8], key_size: usize) -> StateResult<usize> {
    bytes
        .len()
        .checked_add(key_size)
        .ok_or_else(|| backend_error("state record size overflow"))
}

fn decode_indexed_entry(
    bytes: &[u8],
    path: &Path,
    at_millis: i64,
) -> StateResult<StateHistoryEntry> {
    let entry = decode_history_entry(bytes)?;
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
) -> StateFailure {
    StateError::RowTooLarge(Box::new(StateRowTooLarge {
        path,
        encoded_bytes,
        retry,
        resume,
    }))
    .into()
}

impl StateRead for RedbStateBackend {
    type Read<'a> = Ready<StateResult<Option<TaintedValue>>>;
    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        ready(self.read_current(path))
    }
}
impl StateQuery for RedbStateBackend {
    type Query<'a> = Ready<StateResult<StatePage>>;
    fn query<'a>(&'a self, query: &'a StateScan) -> Self::Query<'a> {
        ready(self.state_page(query))
    }
}
impl StateHistory for RedbStateBackend {
    type History<'a> = Ready<StateResult<StateHistoryPage>>;
    type At<'a> = Ready<StateResult<Option<TaintedValue>>>;
    fn history<'a>(&'a self, query: &'a StateHistoryQuery) -> Self::History<'a> {
        ready(self.history_page(query))
    }
    fn read_at<'a>(&'a self, path: &'a Path, at_millis: i64) -> Self::At<'a> {
        ready(self.historical_value(path, at_millis))
    }
}
