use crate::{STATE_HISTORY_TABLE, STATE_META_TABLE, STATE_VALUES_TABLE};
use redb::{Database, ReadableDatabase, ReadableTable};
use std::future::{Ready, ready};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use xolotl_state::{
    Backend, StateCommit, StateError, StateEvent, StateFailure, StateFlush, StateHistoryEntry,
    StateMutation, StateResult, StateStream, StateWatch, StateWrite, TaintedValue,
};
use xolotl_types::{Path, TaintSet, Value};

mod codec;
mod mutation;
mod read;
use codec::{decode_envelope, decode_history_entry, encode_envelope, encode_history_entry};

use crate::schema::LAST_HISTORY_MILLIS;

pub(crate) type Subscriptions = xolotl_state::host::WatchRegistry;

/// redb-backed implementation of the Xolotl `state://` backend.
pub struct RedbStateBackend {
    db: Arc<Database>,
    subs: Arc<Subscriptions>,
}

impl RedbStateBackend {
    /// Install the supported state capabilities over this shared database.
    pub fn into_backend(self) -> Backend {
        let port = Arc::new(self);
        Backend::new()
            .with_read(port.clone())
            .with_write(port.clone())
            .with_query(port.clone())
            .with_history(port.clone())
            .with_watch(port.clone())
            .with_flush(port)
    }
    pub(crate) fn new(db: Arc<Database>, subs: Arc<Subscriptions>) -> Self {
        Self { db, subs }
    }

    fn notify(&self, event: StateEvent) {
        let targets = self.subs.matching(event.path());
        for target in targets {
            let _sent = target.send(event.clone());
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

        let mut base_key = path.to_string().into_bytes();
        base_key.push(0xFF);
        base_key.extend_from_slice(&ts.to_be_bytes());

        let mut table = txn
            .open_table(STATE_HISTORY_TABLE)
            .map_err(|e| StateError::Backend(e.to_string()))?;
        let mut key = base_key.clone();
        if table
            .get(key.as_slice())
            .map_err(|e| StateError::Backend(e.to_string()))?
            .is_some()
        {
            for seq in 0u64.. {
                key.clear();
                key.extend_from_slice(&base_key);
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
        Ok(())
    }
}

fn backend_error(error: impl ToString) -> StateFailure {
    StateError::Backend(error.to_string()).into()
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

fn history_key_parts(key: &[u8]) -> StateResult<(Path, i64)> {
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

impl StateWatch for RedbStateBackend {
    type Subscription = StateStream;
    type Subscribe<'a> = Ready<StateResult<StateStream>>;
    fn subscribe<'a>(&'a self, pattern: &'a Path) -> Self::Subscribe<'a> {
        ready(self.subs.subscribe(
            pattern.clone(),
            std::num::NonZeroUsize::MIN.saturating_add(255),
        ))
    }
}

impl StateFlush for RedbStateBackend {
    type Flush<'a> = Ready<StateResult<()>>;
    fn flush(&self) -> Self::Flush<'_> {
        ready(Ok(()))
    }
}

#[cfg(test)]
mod tests;
