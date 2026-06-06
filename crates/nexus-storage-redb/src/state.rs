use crate::{STATE_HISTORY_TABLE, STATE_VALUES_TABLE};
use async_trait::async_trait;
use nexus_state::{
    StateBackend, StateError, StateEvent, StateHistoryEntry, StateResult, StateStream, TaintedValue,
};
use nexus_types::{MergeRule, Path, TaintSet, Value};
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

#[derive(Clone, Debug)]
struct Subscriber {
    pattern: Path,
    sender: broadcast::Sender<StateEvent>,
}

pub struct RedbStateBackend {
    db: Arc<Database>,
    subs: Mutex<Vec<Subscriber>>,
}

impl RedbStateBackend {
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            subs: Mutex::new(Vec::new()),
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

    // StateError::CasFailed carries the prior/expected Values, making the
    // error sizable; boxing the shared error type isn't worth it for an
    // internal helper.
    #[allow(clippy::result_large_err)]
    fn record_history(&self, event: &StateEvent) -> StateResult<()> {
        let path = event.path();
        let ts = now_millis();
        let entry = StateHistoryEntry {
            at_millis: ts,
            event: event.clone(),
        };
        let entry_bytes =
            serde_json::to_vec(&serialize_history_entry(&entry)).map_err(StateError::Serde)?;

        let mut key = path.to_string().into_bytes();
        key.push(0xFF);
        key.extend_from_slice(&ts.to_be_bytes());

        let txn = self
            .db
            .begin_write()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        {
            let mut table = txn
                .open_table(STATE_HISTORY_TABLE)
                .map_err(|e| StateError::Backend(e.to_string()))?;
            table
                .insert(key.as_slice(), entry_bytes.as_slice())
                .map_err(|e| StateError::Backend(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;
        Ok(())
    }
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn serialize_history_entry(entry: &StateHistoryEntry) -> serde_json::Value {
    let event_json = match &entry.event {
        StateEvent::Set { path, value, taint } => serde_json::json!({
            "type": "set",
            "path": path.to_string(),
            "value": value_to_json(value),
            "taint": serde_json::to_value(taint).unwrap_or(serde_json::Value::Null),
        }),
        StateEvent::Append { path, item, taint } => serde_json::json!({
            "type": "append",
            "path": path.to_string(),
            "item": value_to_json(item),
            "taint": serde_json::to_value(taint).unwrap_or(serde_json::Value::Null),
        }),
        StateEvent::Delete { path } => serde_json::json!({
            "type": "delete",
            "path": path.to_string(),
        }),
    };
    serde_json::json!({
        "at_millis": entry.at_millis,
        "event": event_json,
    })
}

fn value_to_json(v: &Value) -> serde_json::Value {
    serde_json::to_value(v).unwrap_or(serde_json::Value::Null)
}

fn json_to_value(j: &serde_json::Value) -> Value {
    serde_json::from_value(j.clone()).unwrap_or(Value::Null)
}

/// On-disk envelope persisting a value with its taint (§4.4/§12). Stored as JSON
/// in `STATE_VALUES_TABLE`; bare `Value` encodings are rejected so provenance is
/// never silently dropped. We build the JSON by hand (this crate doesn't depend
/// on `serde` derive directly).
#[allow(clippy::result_large_err)]
fn encode_envelope(value: &Value, taint: &TaintSet) -> Result<Vec<u8>, StateError> {
    let json = serde_json::json!({
        "__nexus_env": 1,
        "value": value_to_json(value),
        "taint": serde_json::to_value(taint).unwrap_or(serde_json::Value::Null),
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
        .ok_or_else(|| StateError::Backend("state envelope missing value".into()))?;
    let taint = match json.get("taint") {
        Some(t) => serde_json::from_value(t.clone()).unwrap_or_default(),
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
        txn.commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;

        let ev = StateEvent::Set {
            path: path.clone(),
            value,
            taint,
        };
        let _ = self.record_history(&ev);
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
        txn.commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;

        let ev = StateEvent::Append {
            path: path.clone(),
            item,
            taint,
        };
        let _ = self.record_history(&ev);
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
                    expected,
                    actual,
                });
            }
            let bytes = encode_envelope(&new, &taint)?;
            table
                .insert(key.as_str(), bytes.as_slice())
                .map_err(|e| StateError::Backend(e.to_string()))?;
        }
        txn.commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;

        let ev = StateEvent::Set {
            path: path.clone(),
            value: new,
            taint,
        };
        let _ = self.record_history(&ev);
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
        txn.commit()
            .map_err(|e| StateError::Backend(e.to_string()))?;

        if existed {
            let ev = StateEvent::Delete { path: path.clone() };
            let _ = self.record_history(&ev);
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
            let val = decode_envelope(val_guard.value())?.value;
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
        let mut prefix_start = path_str.clone().into_bytes();
        prefix_start.push(0xFF);
        prefix_start.extend_from_slice(&from_millis.to_be_bytes());

        let mut prefix_end = path_str.into_bytes();
        prefix_end.push(0xFF);
        prefix_end.extend_from_slice(&to_millis.to_be_bytes());

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
            let (_key, val_guard) = entry.map_err(|e| StateError::Backend(e.to_string()))?;
            let json: serde_json::Value =
                serde_json::from_slice(val_guard.value()).map_err(StateError::Serde)?;
            if let Some(he) = deserialize_history_entry(&json) {
                results.push(he);
            }
        }
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

fn deserialize_history_entry(json: &serde_json::Value) -> Option<StateHistoryEntry> {
    let at_millis = json["at_millis"].as_i64()?;
    let event_json = &json["event"];
    let event_type = event_json["type"].as_str()?;
    let path = Path::parse(event_json["path"].as_str()?).ok()?;
    let taint = serde_json::from_value(event_json["taint"].clone()).unwrap_or_default();
    let event = match event_type {
        "set" => StateEvent::Set {
            path,
            value: json_to_value(&event_json["value"]),
            taint,
        },
        "append" => StateEvent::Append {
            path,
            item: json_to_value(&event_json["item"]),
            taint,
        },
        "delete" => StateEvent::Delete { path },
        _ => return None,
    };
    Some(StateHistoryEntry { at_millis, event })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RedbStore;
    use nexus_types::p;

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
                let bare = serde_json::to_vec(&value_to_json(&Value::Int(7))).unwrap();
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
