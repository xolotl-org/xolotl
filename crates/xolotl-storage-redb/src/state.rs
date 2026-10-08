use crate::database::Database;
use crate::schema::STATE_HISTORY_TIME_INDEX_TABLE;
use crate::{STATE_HISTORY_TABLE, STATE_META_TABLE, STATE_VALUES_TABLE};
use redb::ReadableTable;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use xolotl_kernel::host::BlockingSpawner;
use xolotl_state::{
    Backend, StateBoundedWrite, StateCommit, StateError, StateEvent, StateFailure, StateFlush,
    StateHistoryEntry, StateMutation, StatePointTooLarge, StateResult, StateStream, StateWatch,
    StateWrite, TaintedValue,
};
use xolotl_types::{Path, TaintSet, Value};

mod absence;
mod codec;
mod mutation;
pub use mutation::RedbWriteFuture;
mod publication;
pub(crate) use publication::{Publication, PublishFailure};
mod read;
pub use read::RedbReadFuture;
mod list;
mod retention;
mod source;
#[cfg(test)]
use codec::encode_envelope;
use codec::{decode_envelope, decode_history_entry, encode_history_entry};

use crate::schema::LAST_HISTORY_MILLIS;

pub(crate) type Subscriptions = xolotl_state::host::WatchRegistry;

/// State history retained by a redb database. The choice is fixed when the
/// database is created and must be repeated when it is reopened.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RedbHistory {
    /// Retain current values and provenance without historical replay.
    #[default]
    CurrentOnly,
    /// Retain mutations outside `state://vault/**` for history pages and
    /// historical point reads. Storage grows with those mutations.
    Full,
}

impl RedbHistory {
    pub(crate) const fn stored_value(self) -> i64 {
        match self {
            Self::CurrentOnly => 0,
            // Value 1 belonged to the experimental format that journaled
            // vault credentials. It must not reopen under the protected rule.
            Self::Full => 2,
        }
    }
}

/// redb-backed implementation of the Xolotl `state://` backend.
/// Persisted publisher pins protect history across feature selections. Without
/// the `federation` feature, advancing retention with any existing publisher
/// pin requires the missing `federation_history_retention` capability.
pub struct RedbStateBackend {
    db: Arc<Database>,
    publication: Arc<Publication>,
    history: RedbHistory,
    source_stream_limit: NonZeroUsize,
    source_retention_limit: NonZeroUsize,
    absence_limits: xolotl_state::AbsenceLimits,
    blocking_spawner: Arc<dyn BlockingSpawner>,
}

impl RedbStateBackend {
    /// Install the supported state capabilities over this shared database.
    pub fn into_backend(self) -> Backend {
        self.into_source_parts().0
    }

    /// Install State capabilities and retain this same database owner for
    /// Source atomic commit, maintenance and evidence inspection.
    pub fn into_source_parts(self) -> (Backend, Arc<Self>) {
        let port = Arc::new(self);
        let mut backend = Backend::new()
            .with_read(port.clone())
            .with_bounded_read(port.clone())
            .with_write(port.clone())
            .with_bounded_write(port.clone())
            .with_query(port.clone())
            .with_watch(port.clone())
            .with_signal(port.clone())
            .with_flush(port.clone());
        if port.history == RedbHistory::Full {
            backend = backend
                .with_history(port.clone())
                .with_history_retention(port.clone());
        }
        (backend, port)
    }
    pub(crate) fn new(
        db: Arc<Database>,
        publication: Arc<Publication>,
        history: RedbHistory,
        source_stream_limit: NonZeroUsize,
        source_retention_limit: NonZeroUsize,
        absence_limits: xolotl_state::AbsenceLimits,
        blocking_spawner: Arc<dyn BlockingSpawner>,
    ) -> Self {
        Self {
            db,
            publication,
            history,
            source_stream_limit,
            source_retention_limit,
            absence_limits,
            blocking_spawner,
        }
    }

    fn record_history_in_txn(txn: &redb::WriteTransaction, event: &StateEvent) -> StateResult<()> {
        let ts = next_history_millis_in_txn(txn)?;
        Self::record_history_at_millis_in_txn(txn, event, ts)
    }

    fn record_history_at_millis_in_txn(
        txn: &redb::WriteTransaction,
        event: &StateEvent,
        ts: i64,
    ) -> StateResult<()> {
        let path = event.path();
        let entry_bytes = encode_history_entry(ts, event)?;

        let mut key = path.to_string().into_bytes();
        key.push(0xFF);
        key.extend_from_slice(&ts.to_be_bytes());
        let base_len = key.len();

        let mut table = txn
            .open_table(STATE_HISTORY_TABLE)
            .map_err(|e| StateError::Backend(e.to_string()))?;
        if table
            .get(key.as_slice())
            .map_err(|e| StateError::Backend(e.to_string()))?
            .is_some()
        {
            for seq in 0u64.. {
                key.truncate(base_len);
                key.extend_from_slice(&seq.to_be_bytes());
                if table
                    .get(key.as_slice())
                    .map_err(|e| StateError::Backend(e.to_string()))?
                    .is_none()
                {
                    break;
                }
            }
        }
        table
            .insert(key.as_slice(), entry_bytes.as_slice())
            .map_err(|e| StateError::Backend(e.to_string()))?;
        // A single write transaction owns both history orders. The secondary
        // key carries the complete primary key to preserve same-ms collisions.
        let time_key = history_time_key(ts, &key);
        let mut time_index = txn
            .open_table(STATE_HISTORY_TIME_INDEX_TABLE)
            .map_err(backend_error)?;
        if time_index
            .get(time_key.as_slice())
            .map_err(backend_error)?
            .is_some()
        {
            return Err(backend_error("state history time index key already exists"));
        }
        time_index
            .insert(time_key.as_slice(), &[][..])
            .map_err(backend_error)?;
        Ok(())
    }
}

fn backend_error(error: impl ToString) -> StateFailure {
    StateError::Backend(error.to_string()).into()
}

fn commit_error(error: redb::CommitError) -> StateFailure {
    // A poisoned transaction was rolled back. Other commit failures may have
    // happened after redb made the new root durable.
    match error {
        error @ redb::CommitError::TransactionPoisoned => backend_error(error),
        error => StateError::CommitUncertain(error.to_string()).into(),
    }
}

fn next_history_millis_in_txn(txn: &redb::WriteTransaction) -> StateResult<i64> {
    let mut meta = txn
        .open_table(STATE_META_TABLE)
        .map_err(|error| StateError::Backend(error.to_string()))?;
    let observed = meta
        .get(LAST_HISTORY_MILLIS)
        .map_err(|error| StateError::Backend(error.to_string()))?
        .map(|value| value.value())
        .ok_or_else(|| StateError::Backend("state history metadata missing".into()))?;
    let next = observed
        .checked_add(1)
        .ok_or_else(|| StateError::Backend("history timestamp exhausted".into()))?
        .max(now_millis());
    meta.insert(LAST_HISTORY_MILLIS, next)
        .map_err(|error| StateError::Backend(error.to_string()))?;
    Ok(next)
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

fn history_scan_end(path: &Path) -> Vec<u8> {
    let mut end = path.to_string().into_bytes();
    end.push(0xFF);
    end.push(0xFF);
    end
}

fn history_time_key(timestamp: i64, primary_key: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(8 + primary_key.len());
    key.extend_from_slice(&(timestamp as u64 ^ (1_u64 << 63)).to_be_bytes());
    key.extend_from_slice(primary_key);
    key
}

fn history_time_bound(timestamp: i64) -> [u8; 8] {
    (timestamp as u64 ^ (1_u64 << 63)).to_be_bytes()
}

pub(crate) fn history_key_parts(key: &[u8]) -> StateResult<(Path, i64)> {
    let separator = key
        .iter()
        .position(|byte| *byte == 0xFF)
        .ok_or_else(|| StateError::Backend("history key missing path separator".into()))?;
    let path = std::str::from_utf8(&key[..separator])
        .map_err(|e| StateError::Backend(format!("history key path is invalid UTF-8: {e}")))
        .and_then(|path| {
            Path::parse(path)
                .map_err(|e| StateError::Backend(format!("history key path is invalid: {e}")))
        })?;
    let ts_start = separator + 1;
    let ts_end = ts_start + 8;
    if key.len() < ts_end {
        return Err(StateError::Backend("history key missing timestamp bytes".into()).into());
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&key[ts_start..ts_end]);
    Ok((path, i64::from_be_bytes(ts)))
}

/// Decode a time-index lookup with the same path and timestamp checks as
/// ordinary State history pages.
#[cfg(feature = "federation")]
pub(crate) fn indexed_history_entry(
    bytes: &[u8],
    path: &Path,
    at_millis: i64,
) -> StateResult<StateHistoryEntry> {
    read::decode_indexed_entry(bytes, path, at_millis)
}

impl StateWatch for RedbStateBackend {
    type Subscription = StateStream;
    type Subscribe<'a> = Pin<Box<dyn Future<Output = StateResult<StateStream>> + Send + 'a>>;
    fn subscribe<'a>(&'a self, pattern: &'a Path) -> Self::Subscribe<'a> {
        Box::pin(async move {
            self.db.ensure_open().map_err(backend_error)?;
            let _commit_order = self.publication.registration_lock().await;
            self.db.ensure_open().map_err(backend_error)?;
            let stream = self.publication.subscriptions().subscribe(
                pattern.clone(),
                std::num::NonZeroUsize::MIN.saturating_add(255),
            )?;
            self.db.ensure_open().map_err(backend_error)?;
            Ok(stream)
        })
    }
}

impl StateFlush for RedbStateBackend {
    type Flush<'a> = std::future::Ready<StateResult<()>>;
    fn flush(&self) -> Self::Flush<'_> {
        std::future::ready(self.db.ensure_open().map_err(backend_error))
    }
}

#[cfg(test)]
#[path = "state/source_commit_fault_tests.rs"]
mod source_commit_fault_tests;
#[cfg(test)]
mod tests;
