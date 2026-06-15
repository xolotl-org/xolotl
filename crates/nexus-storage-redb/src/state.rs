use crate::{STATE_HISTORY_TABLE, STATE_VALUES_TABLE};
use async_trait::async_trait;
use nexus_state::{
    StateBackend, StateError, StateEvent, StateHistoryEntry, StateResult, StateStream, TaintedValue,
};
use nexus_types::{MergeRule, Path, TaintSet, Value};
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable};
use std::sync::{
    Arc,
    atomic::{AtomicI64, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

#[derive(Clone, Debug)]
struct Subscriber {
    pattern: Path,
    sender: broadcast::Sender<StateEvent>,
}

/// redb-backed implementation of the Nexus `state://` backend.
pub struct RedbStateBackend {
    db: Arc<Database>,
    history_clock: Arc<AtomicI64>,
    subs: Mutex<Vec<Subscriber>>,
}

impl RedbStateBackend {
    pub(crate) fn new(db: Arc<Database>, history_clock: Arc<AtomicI64>) -> Self {
        Self {
            db,
            history_clock,
            subs: Mutex::new(Vec::new()),
        }
    }

    fn next_millis(&self) -> i64 {
        loop {
            let observed = self.history_clock.load(Ordering::Relaxed);
            let wall = now_millis();
            let next = if wall > observed { wall } else { observed + 1 };
            if self
                .history_clock
                .compare_exchange(observed, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return next;
            }
        }
    }

    fn notify(&self, event: StateEvent) {
        let target = event.path().clone();
        let subs = self.subs.lock();
        for s in subs.iter() {
            if target.matches(&s.pattern) {
                let _ = s.sender.send(event.clone());
            }
        }
    }

    fn record_history_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        event: &StateEvent,
    ) -> StateResult<()> {
        Self::record_history_at_millis_in_txn(txn, event, self.next_millis())
    }

    fn record_history_at_millis_in_txn(
        txn: &redb::WriteTransaction,
        event: &StateEvent,
        ts: i64,
    ) -> StateResult<()> {
        let path = event.path();
        let entry = StateHistoryEntry {
            at_millis: ts,
            event: event.clone(),
        };
        let entry_bytes =
            serde_json::to_vec(&serialize_history_entry(&entry)?).map_err(StateError::Serde)?;

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

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn serialize_history_entry(entry: &StateHistoryEntry) -> StateResult<serde_json::Value> {
    let event_json = match &entry.event {
        StateEvent::Set { path, value, taint } => {
            let value = value_to_json(value)?;
            let taint = serde_json::to_value(taint).map_err(StateError::Serde)?;
            serde_json::json!({
                "type": "set",
                "path": path.to_string(),
                "value": value,
                "taint": taint,
            })
        }
        StateEvent::Append { path, item, taint } => {
            let item = value_to_json(item)?;
            let taint = serde_json::to_value(taint).map_err(StateError::Serde)?;
            serde_json::json!({
                "type": "append",
                "path": path.to_string(),
                "item": item,
                "taint": taint,
            })
        }
        StateEvent::Delete { path } => serde_json::json!({
            "type": "delete",
            "path": path.to_string(),
        }),
    };
    Ok(serde_json::json!({
        "at_millis": entry.at_millis,
        "event": event_json,
    }))
}

fn value_to_json(v: &Value) -> StateResult<serde_json::Value> {
    serde_json::to_value(v).map_err(StateError::Serde)
}

fn json_to_value(j: &serde_json::Value) -> StateResult<Value> {
    serde_json::from_value(j.clone()).map_err(StateError::Serde)
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
        return Err(StateError::Backend(
            "history key missing timestamp bytes".into(),
        ));
    }
    let mut ts = [0u8; 8];
    ts.copy_from_slice(&key[ts_start..ts_end]);
    Ok((path, i64::from_be_bytes(ts)))
}

/// On-disk envelope persisting a value with its taint. Stored as JSON
/// in `STATE_VALUES_TABLE`; bare `Value` encodings are rejected so provenance is
/// never silently dropped. We build the JSON by hand (this crate doesn't depend
/// on `serde` derive directly).
fn encode_envelope(value: &Value, taint: &TaintSet) -> Result<Vec<u8>, StateError> {
    let json = serde_json::json!({
        "__nexus_env": 1,
        "value": value_to_json(value)?,
        "taint": serde_json::to_value(taint).map_err(StateError::Serde)?,
    });
    serde_json::to_vec(&json).map_err(StateError::Serde)
}

fn decode_envelope(bytes: &[u8]) -> StateResult<TaintedValue> {
    let json: serde_json::Value = serde_json::from_slice(bytes).map_err(StateError::Serde)?;
    let marker = json
        .get("__nexus_env")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| StateError::Backend("state value missing envelope marker".into()))?;
    if marker != 1 {
        return Err(StateError::Backend(format!(
            "unsupported state envelope version {marker}"
        )));
    }
    let value = json
        .get("value")
        .map(json_to_value)
        .transpose()?
        .ok_or_else(|| StateError::Backend("state envelope missing value".into()))?;
    let taint = match json.get("taint") {
        Some(t) => serde_json::from_value(t.clone()).map_err(StateError::Serde)?,
        None => TaintSet::pristine(),
    };
    Ok(TaintedValue::new(value, taint))
}

#[async_trait]
impl StateBackend for RedbStateBackend {
    async fn read_tainted(&self, path: &Path) -> StateResult<Option<TaintedValue>> {
        let key = path.to_string();
        let txn = self
            .db
            .begin_read()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        let table = txn
            .open_table(STATE_VALUES_TABLE)
            .map_err(|e| StateError::Backend(e.to_string()))?;
        match table.get(key.as_str()) {
            Ok(Some(guard)) => Ok(Some(decode_envelope(guard.value())?)),
            Ok(None) => Ok(None),
            Err(e) => Err(StateError::Backend(e.to_string())),
        }
    }

    async fn write_set_tainted(
        &self,
        path: &Path,
        value: Value,
        taint: TaintSet,
    ) -> StateResult<()> {
        let key = path.to_string();
        let bytes = encode_envelope(&value, &taint)?;
        let ev = StateEvent::Set {
            path: path.clone(),
            value,
            taint,
        };
        let txn = self
            .db
            .begin_write()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        {
            let mut table = txn
                .open_table(STATE_VALUES_TABLE)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|e| StateError::Backend(e.to_string()))?;
        }
        self.record_history_in_txn(&txn, &ev)?;
        txn.commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;

        self.notify(ev);
        Ok(())
    }

    async fn write_append_tainted(
        &self,
        path: &Path,
        item: Value,
        taint: TaintSet,
    ) -> StateResult<()> {
        let key = path.to_string();
        let ev = StateEvent::Append {
            path: path.clone(),
            item: item.clone(),
            taint: taint.clone(),
        };
        let txn = self
            .db
            .begin_write()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        {
            let mut table = txn
                .open_table(STATE_VALUES_TABLE)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            let current = match table.get(key.as_str()) {
                Ok(Some(guard)) => decode_envelope(guard.value())?,
                _ => TaintedValue::pristine(Value::List(Vec::new())),
            };
            match current.value {
                Value::List(mut xs) => {
                    xs.push(item.clone());
                    // The sequence's taint accrues every appended item's lineage.
                    let mut t = current.taint;
                    t.union(&taint);
                    let bytes = encode_envelope(&Value::List(xs), &t)?;
                    table
                        .insert(key.as_str(), bytes.as_slice())
                        .map_err(|e| StateError::Backend(e.to_string()))?;
                }
                other => {
                    return Err(StateError::Backend(format!(
                        "append on non-list at {} (current: {:?})",
                        path, other
                    )));
                }
            }
        }
        self.record_history_in_txn(&txn, &ev)?;
        txn.commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;

        self.notify(ev);
        Ok(())
    }

    async fn write_cas_tainted(
        &self,
        path: &Path,
        expected: Option<Value>,
        new: Value,
        taint: TaintSet,
    ) -> StateResult<()> {
        let key = path.to_string();
        let ev = StateEvent::Set {
            path: path.clone(),
            value: new.clone(),
            taint: taint.clone(),
        };
        let txn = self
            .db
            .begin_write()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        {
            let mut table = txn
                .open_table(STATE_VALUES_TABLE)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            let actual = match table.get(key.as_str()) {
                Ok(Some(guard)) => Some(decode_envelope(guard.value())?.value),
                Ok(None) => None,
                Err(e) => return Err(StateError::Backend(e.to_string())),
            };
            if actual != expected {
                return Err(StateError::CasFailed {
                    path: path.to_string(),
                    expected: expected.map(Box::new),
                    actual: actual.map(Box::new),
                });
            }
            let bytes = encode_envelope(&new, &taint)?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|e| StateError::Backend(e.to_string()))?;
        }
        self.record_history_in_txn(&txn, &ev)?;
        txn.commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;

        self.notify(ev);
        Ok(())
    }

    async fn write_delete(&self, path: &Path) -> StateResult<()> {
        let key = path.to_string();
        let txn = self
            .db
            .begin_write()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        let existed;
        {
            let mut table = txn
                .open_table(STATE_VALUES_TABLE)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            existed = table
                .remove(key.as_str())
                .map_err(|e| StateError::Backend(e.to_string()))?
                .is_some();
        }
        let ev = StateEvent::Delete { path: path.clone() };
        if existed {
            self.record_history_in_txn(&txn, &ev)?;
        }
        txn.commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;

        if existed {
            self.notify(ev);
        }
        Ok(())
    }

    async fn subscribe(&self, pattern: &Path) -> StateResult<StateStream> {
        let (tx, rx) = broadcast::channel(256);
        self.subs.lock().push(Subscriber {
            pattern: pattern.clone(),
            sender: tx,
        });
        Ok(rx)
    }

    async fn read_prefix(&self, prefix: &Path) -> StateResult<Vec<(Path, Value)>> {
        Ok(self
            .read_prefix_tainted(prefix)
            .await?
            .into_iter()
            .map(|(path, tv)| (path, tv.value))
            .collect())
    }

    async fn read_prefix_tainted(&self, prefix: &Path) -> StateResult<Vec<(Path, TaintedValue)>> {
        let prefix_str = prefix.to_string();
        let txn = self
            .db
            .begin_read()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        let table = txn
            .open_table(STATE_VALUES_TABLE)
            .map_err(|e| StateError::Backend(e.to_string()))?;

        let mut results = Vec::new();
        let range = table
            .range(prefix_str.as_str()..)
            .map_err(|e| StateError::Backend(e.to_string()))?;

        for entry in range {
            let (key_guard, val_guard) = entry.map_err(|e| StateError::Backend(e.to_string()))?;
            let key_str = key_guard.value();
            if !key_str.starts_with(prefix_str.as_str()) {
                break;
            }
            let path = Path::parse(key_str)
                .map_err(|e| StateError::Backend(format!("invalid path in db: {e}")))?;
            if path != *prefix && !prefix.is_prefix_of(&path) {
                continue;
            }
            let val = decode_envelope(val_guard.value())?;
            results.push((path, val));
        }
        Ok(results)
    }

    async fn read_range(
        &self,
        path: &Path,
        from_millis: i64,
        to_millis: i64,
    ) -> StateResult<Vec<StateHistoryEntry>> {
        let path_str = path.to_string();
        let prefix_start = path_str.clone().into_bytes();
        let prefix_end = history_scan_end(path);

        let txn = self
            .db
            .begin_read()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        let table = txn
            .open_table(STATE_HISTORY_TABLE)
            .map_err(|e| StateError::Backend(e.to_string()))?;

        let mut results = Vec::new();
        let range = table
            .range(prefix_start.as_slice()..prefix_end.as_slice())
            .map_err(|e| StateError::Backend(e.to_string()))?;

        for entry in range {
            let (key_guard, val_guard) = entry.map_err(|e| StateError::Backend(e.to_string()))?;
            let (event_path, at_millis) = history_key_parts(key_guard.value())?;
            if event_path != *path && !path.is_prefix_of(&event_path) {
                continue;
            }
            if at_millis < from_millis || at_millis >= to_millis {
                continue;
            }
            let json: serde_json::Value =
                serde_json::from_slice(val_guard.value()).map_err(StateError::Serde)?;
            results.push(deserialize_history_entry(&json)?);
        }
        results.sort_by_key(|entry| entry.at_millis);
        Ok(results)
    }

    async fn write_merge(&self, path: &Path, value: Value, rule: MergeRule) -> StateResult<()> {
        let current = self.read(path).await?;
        let merged = nexus_state::merge_values(current, value, rule);
        self.write_set(path, merged).await
    }

    async fn flush(&self) -> StateResult<()> {
        Ok(())
    }
}

fn deserialize_history_entry(json: &serde_json::Value) -> StateResult<StateHistoryEntry> {
    let at_millis = json
        .get("at_millis")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| StateError::Backend("history entry missing at_millis".into()))?;
    let event_json = json
        .get("event")
        .ok_or_else(|| StateError::Backend("history entry missing event".into()))?;
    let event_type = event_json
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| StateError::Backend("history event missing type".into()))?;
    let path = Path::parse(
        event_json
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| StateError::Backend("history event missing path".into()))?,
    )
    .map_err(|e| StateError::Backend(format!("history event path is invalid: {e}")))?;
    let event =
        match event_type {
            "set" => {
                let value = json_to_value(event_json.get("value").ok_or_else(|| {
                    StateError::Backend("history set event missing value".into())
                })?)?;
                let taint =
                    serde_json::from_value(event_json.get("taint").cloned().ok_or_else(|| {
                        StateError::Backend("history set event missing taint".into())
                    })?)
                    .map_err(StateError::Serde)?;
                StateEvent::Set { path, value, taint }
            }
            "append" => {
                let item = json_to_value(event_json.get("item").ok_or_else(|| {
                    StateError::Backend("history append event missing item".into())
                })?)?;
                let taint =
                    serde_json::from_value(event_json.get("taint").cloned().ok_or_else(|| {
                        StateError::Backend("history append event missing taint".into())
                    })?)
                    .map_err(StateError::Serde)?;
                StateEvent::Append { path, item, taint }
            }
            "delete" => StateEvent::Delete { path },
            _ => {
                return Err(StateError::Backend(format!(
                    "unsupported history event type {event_type:?}"
                )));
            }
        };
    Ok(StateHistoryEntry { at_millis, event })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RedbStore;
    use nexus_types::Path;

    fn p(s: &str) -> Path {
        Path::parse(s).unwrap()
    }

    fn tmp_backend() -> RedbStateBackend {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.redb");
        RedbStore::open(path).unwrap().state_backend()
    }

    #[tokio::test]
    async fn set_and_read() {
        let b = tmp_backend();
        b.write_set(&p("state://x"), Value::Int(42)).await.unwrap();
        let v = b.read(&p("state://x")).await.unwrap();
        assert_eq!(v, Some(Value::Int(42)));
    }

    #[tokio::test]
    async fn read_missing_returns_none() {
        let b = tmp_backend();
        assert_eq!(b.read(&p("state://nope")).await.unwrap(), None);
    }

    #[tokio::test]
    async fn bare_value_encoding_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.redb");
        let store = RedbStore::open(path).unwrap();
        {
            let txn = store
                .db
                .begin_write()
                .map_err(|e| StateError::Backend(e.to_string()))
                .unwrap();
            {
                let mut table = txn.open_table(crate::STATE_VALUES_TABLE).unwrap();
                let bare = serde_json::to_vec(&value_to_json(&Value::Int(7)).unwrap()).unwrap();
                table
                    .insert("state://bad-encoding", bare.as_slice())
                    .unwrap();
            }
            txn.commit().unwrap();
        }

        let b = store.state_backend();
        let err = b.read(&p("state://bad-encoding")).await.unwrap_err();
        assert!(
            matches!(&err, StateError::Backend(message) if message.contains("envelope marker")),
            "bare Value encoding must not be treated as pristine: {err:?}"
        );
    }

    #[tokio::test]
    async fn append_creates_and_grows() {
        let b = tmp_backend();
        b.write_append(&p("state://log"), Value::Int(1))
            .await
            .unwrap();
        b.write_append(&p("state://log"), Value::Int(2))
            .await
            .unwrap();
        let v = b.read(&p("state://log")).await.unwrap().unwrap();
        match v {
            Value::List(xs) => assert_eq!(xs.len(), 2),
            _ => panic!("expected list"),
        }
    }

    #[tokio::test]
    async fn history_keeps_multiple_events_for_same_path_in_one_millisecond() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.redb");
        let store = RedbStore::open(path).unwrap();
        let state_path = p("state://history/collide");
        let txn = store
            .db
            .begin_write()
            .map_err(|e| StateError::Backend(e.to_string()))
            .unwrap();
        RedbStateBackend::record_history_at_millis_in_txn(
            &txn,
            &StateEvent::Set {
                path: state_path.clone(),
                value: Value::Int(1),
                taint: TaintSet::pristine(),
            },
            1_700_000_000_000,
        )
        .unwrap();
        RedbStateBackend::record_history_at_millis_in_txn(
            &txn,
            &StateEvent::Set {
                path: state_path.clone(),
                value: Value::Int(2),
                taint: TaintSet::pristine(),
            },
            1_700_000_000_000,
        )
        .unwrap();
        txn.commit().unwrap();

        let backend = store.state_backend();
        let entries = backend.read_range(&state_path, 0, i64::MAX).await.unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[tokio::test]
    async fn history_clock_is_shared_across_state_backends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.keep().join("test.redb");
        let store = RedbStore::open(path).unwrap();
        let first = store.state_backend();
        let second = store.state_backend();
        let state_path = p("state://history/shared-clock");

        first.write_set(&state_path, Value::Int(1)).await.unwrap();
        second.write_set(&state_path, Value::Int(2)).await.unwrap();

        let entries = first.read_range(&state_path, 0, i64::MAX).await.unwrap();
        assert_eq!(entries.len(), 2);
        assert!(
            entries[0].at_millis < entries[1].at_millis,
            "history timestamps must preserve write order across backends"
        );
    }

    #[tokio::test]
    async fn cas_success_and_failure() {
        let b = tmp_backend();
        b.write_set(&p("state://k"), Value::Int(1)).await.unwrap();
        b.write_cas(&p("state://k"), Some(Value::Int(1)), Value::Int(2))
            .await
            .unwrap();
        assert_eq!(b.read(&p("state://k")).await.unwrap(), Some(Value::Int(2)));

        let err = b
            .write_cas(&p("state://k"), Some(Value::Int(99)), Value::Int(3))
            .await;
        assert!(matches!(err, Err(StateError::CasFailed { .. })));
    }

    #[tokio::test]
    async fn delete_removes() {
        let b = tmp_backend();
        b.write_set(&p("state://k"), Value::Int(1)).await.unwrap();
        b.write_delete(&p("state://k")).await.unwrap();
        assert_eq!(b.read(&p("state://k")).await.unwrap(), None);
    }

    #[tokio::test]
    async fn merge_missing_path_uses_incoming_value() {
        let b = tmp_backend();
        b.write_merge(&p("state://k"), Value::Int(7), MergeRule::Shallow)
            .await
            .unwrap();
        assert_eq!(b.read(&p("state://k")).await.unwrap(), Some(Value::Int(7)));
    }

    #[tokio::test]
    async fn prefix_scan() {
        let b = tmp_backend();
        b.write_set(
            &p("state://memory/alice/persona"),
            Value::Str("hello".into()),
        )
        .await
        .unwrap();
        b.write_set(&p("state://memory/alice/prefs"), Value::Int(1))
            .await
            .unwrap();
        b.write_set(&p("state://memory/bob/persona"), Value::Str("world".into()))
            .await
            .unwrap();
        b.write_set(&p("state://other"), Value::Int(99))
            .await
            .unwrap();

        let results = b.read_prefix(&p("state://memory/alice")).await.unwrap();
        assert_eq!(results.len(), 2);
        assert!(
            results
                .iter()
                .all(|(p, _)| p.to_string().starts_with("state://memory/alice"))
        );
    }

    #[tokio::test]
    async fn prefix_scan_is_segment_aware() {
        let b = tmp_backend();
        b.write_set(&p("state://memory/alice"), Value::Int(1))
            .await
            .unwrap();
        b.write_set(&p("state://memory/aliceevil"), Value::Int(2))
            .await
            .unwrap();
        b.write_set(&p("state://memory/alice/prefs"), Value::Int(3))
            .await
            .unwrap();

        let results = b.read_prefix(&p("state://memory/alice")).await.unwrap();
        let paths: Vec<String> = results
            .into_iter()
            .map(|(path, _)| path.to_string())
            .collect();
        assert_eq!(
            paths,
            vec!["state://memory/alice", "state://memory/alice/prefs"]
        );
    }

    #[tokio::test]
    async fn read_range_includes_descendants_but_not_string_prefix_siblings() {
        let b = tmp_backend();
        b.write_set(&p("state://memory"), Value::Int(1))
            .await
            .unwrap();
        b.write_set(&p("state://memory/alice"), Value::Int(2))
            .await
            .unwrap();
        b.write_set(&p("state://memoryevil"), Value::Int(3))
            .await
            .unwrap();

        let entries = b
            .read_range(&p("state://memory"), 0, i64::MAX)
            .await
            .unwrap();
        let paths: Vec<String> = entries
            .into_iter()
            .map(|entry| match entry.event {
                StateEvent::Set { path, .. } => path.to_string(),
                StateEvent::Append { path, .. } => path.to_string(),
                StateEvent::Delete { path } => path.to_string(),
            })
            .collect();
        assert_eq!(paths, vec!["state://memory", "state://memory/alice"]);
    }

    #[tokio::test]
    async fn subscribe_receives_events() {
        let b = tmp_backend();
        let mut rx = b.subscribe(&p("state://watched/**")).await.unwrap();
        b.write_set(&p("state://watched/a"), Value::Int(1))
            .await
            .unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .unwrap()
            .unwrap();
        match ev {
            StateEvent::Set { path, .. } => assert_eq!(path.to_string(), "state://watched/a"),
            _ => panic!("wrong event"),
        }
    }
}
