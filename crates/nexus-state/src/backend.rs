//! `StateBackend` trait — the only abstraction the kernel imposes on storage.
//!
//! The kernel never deals in SQL or files. It hands `Path + Value` to a
//! backend. Backends decide how to persist, version, and notify.

use async_trait::async_trait;
use nexus_types::{MergeRule, Path, TaintSet, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::broadcast;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("CAS failed at {path}: expected {expected:?}, found {actual:?}")]
    CasFailed {
        path: String,
        expected: Option<Value>,
        actual: Option<Value>,
    },
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("backend: {0}")]
    Backend(String),
    #[error("unsupported by backend: {0}")]
    Unsupported(&'static str),
}

pub type StateResult<T> = std::result::Result<T, StateError>;

/// Event delivered to subscribers. Each variant carries an `at_millis`
/// timestamp the backend stamps at write time so `ReadMode::Range` and
/// `ReadMode::At` queries can be served from the durable history. The written
/// value's `taint` (§4.4/§21.5) travels with the event so subscribers and the
/// memory-poison gate see provenance, not just the value.
#[derive(Clone, Debug)]
pub enum StateEvent {
    Set {
        path: Path,
        value: Value,
        taint: TaintSet,
    },
    Append {
        path: Path,
        item: Value,
        taint: TaintSet,
    },
    Delete {
        path: Path,
    },
}

impl StateEvent {
    /// The path this event targets.
    pub fn path(&self) -> &Path {
        match self {
            StateEvent::Set { path, .. }
            | StateEvent::Append { path, .. }
            | StateEvent::Delete { path } => path,
        }
    }
}

/// A stored value together with its provenance (§4.4/§12). State persists the
/// taint alongside the value; cleansing taint must be an explicit rewrite, never
/// a silent drop. Backends store this envelope, not a bare `Value`.
#[derive(Clone, Debug, PartialEq)]
pub struct TaintedValue {
    pub value: Value,
    pub taint: TaintSet,
}

impl TaintedValue {
    pub fn pristine(value: Value) -> Self {
        Self {
            value,
            taint: TaintSet::pristine(),
        }
    }
    pub fn new(value: Value, taint: TaintSet) -> Self {
        Self { value, taint }
    }
}

/// Subscription handle. Backends return one of these from `subscribe`.
pub type StateStream = broadcast::Receiver<StateEvent>;

/// One historical entry returned by `read_range` / `read_at`. Backends
/// that cannot retain history return `Unsupported`.
#[derive(Clone, Debug)]
pub struct StateHistoryEntry {
    pub at_millis: i64,
    pub event: StateEvent,
}

#[async_trait]
pub trait StateBackend: Send + Sync + 'static {
    // ── taint-aware primitives (§4.4/§12) ──────────────────────────────
    // Backends implement these; the bare convenience methods below default to
    // them with pristine taint (author-trusted kernel-internal writes).

    /// Read the value at `path` together with its persisted provenance.
    async fn read_tainted(&self, path: &Path) -> StateResult<Option<TaintedValue>>;
    /// Set `path` to `value`, persisting `taint` alongside it.
    async fn write_set_tainted(
        &self,
        path: &Path,
        value: Value,
        taint: TaintSet,
    ) -> StateResult<()>;
    /// Append `item` to the sequence at `path`, persisting `taint`.
    async fn write_append_tainted(
        &self,
        path: &Path,
        item: Value,
        taint: TaintSet,
    ) -> StateResult<()>;
    /// Compare-and-set with taint. The compare is on the *value* only; on
    /// success the new value's `taint` is persisted.
    async fn write_cas_tainted(
        &self,
        path: &Path,
        expected: Option<Value>,
        new: Value,
        taint: TaintSet,
    ) -> StateResult<()>;

    async fn write_delete(&self, path: &Path) -> StateResult<()>;
    async fn subscribe(&self, pattern: &Path) -> StateResult<StateStream>;

    // ── bare convenience methods (pristine-taint defaults) ─────────────

    /// Read just the value, discarding provenance. Convenience for callers that
    /// don't track taint; prefer `read_tainted` where provenance matters.
    async fn read(&self, path: &Path) -> StateResult<Option<Value>> {
        Ok(self.read_tainted(path).await?.map(|tv| tv.value))
    }
    /// Set with pristine (author-trusted) taint.
    async fn write_set(&self, path: &Path, value: Value) -> StateResult<()> {
        self.write_set_tainted(path, value, TaintSet::pristine())
            .await
    }
    /// Append with pristine taint.
    async fn write_append(&self, path: &Path, item: Value) -> StateResult<()> {
        self.write_append_tainted(path, item, TaintSet::pristine())
            .await
    }
    /// CAS with pristine taint.
    async fn write_cas(&self, path: &Path, expected: Option<Value>, new: Value) -> StateResult<()> {
        self.write_cas_tainted(path, expected, new, TaintSet::pristine())
            .await
    }
    /// Backends that retain a history may serve range reads. The default
    /// returns `Unsupported` so the kernel surfaces a clear error rather
    /// than silently approximating.
    async fn read_range(
        &self,
        _path: &Path,
        _from_millis: i64,
        _to_millis: i64,
    ) -> StateResult<Vec<StateHistoryEntry>> {
        Err(StateError::Unsupported("read_range"))
    }
    /// Read the value as it was at `at_millis`. `0` means current.
    async fn read_at(&self, path: &Path, at_millis: i64) -> StateResult<Option<Value>> {
        if at_millis == 0 {
            return self.read(path).await;
        }
        Err(StateError::Unsupported("read_at"))
    }
    /// Merge `value` into whatever currently lives at `path`, by `rule`.
    /// Default implementation is read-modify-write atop `read` + `write_set`,
    /// which is correct for backends that don't expose a richer atomic
    /// primitive.
    async fn write_merge(&self, path: &Path, value: Value, rule: MergeRule) -> StateResult<()> {
        let current = self.read(path).await?;
        let merged = merge_values(current, value, rule);
        self.write_set(path, merged).await
    }
    /// Implementations may use this to signal cooperative shutdown / flush.
    async fn flush(&self) -> StateResult<()> {
        Ok(())
    }

    /// Return all key-value pairs whose path starts with `prefix`.
    /// Backends that use ordered storage can implement this efficiently via
    /// range scan; the default iterates nothing and returns `Unsupported`.
    async fn read_prefix(&self, _prefix: &Path) -> StateResult<Vec<(Path, Value)>> {
        Err(StateError::Unsupported("read_prefix"))
    }
}

pub type DynBackend = Arc<dyn StateBackend>;

/// Default `Merge` semantics shared by every backend (§2.3).
pub fn merge_values(current: Option<Value>, incoming: Value, rule: MergeRule) -> Value {
    match (current, incoming, rule) {
        (None, incoming, _) => incoming,
        (Some(Value::Map(mut a)), Value::Map(b), MergeRule::Shallow) => {
            for (k, v) in b {
                a.insert(k, v);
            }
            Value::Map(a)
        }
        (Some(Value::Map(a)), Value::Map(b), MergeRule::Deep) => Value::Map(merge_maps(a, b)),
        (Some(Value::List(mut a)), Value::List(b), _) => {
            a.extend(b);
            Value::List(a)
        }
        (Some(_), incoming, _) => incoming,
    }
}

fn merge_maps(
    mut a: BTreeMap<String, Value>,
    b: BTreeMap<String, Value>,
) -> BTreeMap<String, Value> {
    for (k, v) in b {
        match a.remove(&k) {
            Some(Value::Map(am)) => match v {
                Value::Map(bm) => {
                    a.insert(k, Value::Map(merge_maps(am, bm)));
                }
                other => {
                    a.insert(k, other);
                }
            },
            Some(_) | None => {
                a.insert(k, v);
            }
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_shallow_overwrites_keys() {
        let mut a = BTreeMap::new();
        a.insert("x".into(), Value::Int(1));
        a.insert("y".into(), Value::Int(2));
        let mut b = BTreeMap::new();
        b.insert("y".into(), Value::Int(20));
        b.insert("z".into(), Value::Int(3));
        let out = merge_values(Some(Value::Map(a)), Value::Map(b), MergeRule::Shallow);
        match out {
            Value::Map(m) => {
                assert_eq!(m.get("x").unwrap(), &Value::Int(1));
                assert_eq!(m.get("y").unwrap(), &Value::Int(20));
                assert_eq!(m.get("z").unwrap(), &Value::Int(3));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn merge_deep_recurses() {
        let mut inner_a = BTreeMap::new();
        inner_a.insert("k".into(), Value::Int(1));
        let mut a = BTreeMap::new();
        a.insert("nested".into(), Value::Map(inner_a));
        let mut inner_b = BTreeMap::new();
        inner_b.insert("k2".into(), Value::Int(2));
        let mut b = BTreeMap::new();
        b.insert("nested".into(), Value::Map(inner_b));
        let out = merge_values(Some(Value::Map(a)), Value::Map(b), MergeRule::Deep);
        match out {
            Value::Map(m) => match m.get("nested").unwrap() {
                Value::Map(n) => {
                    assert_eq!(n.get("k").unwrap(), &Value::Int(1));
                    assert_eq!(n.get("k2").unwrap(), &Value::Int(2));
                }
                _ => panic!(),
            },
            _ => panic!(),
        }
    }

    #[test]
    fn merge_lists_concat() {
        let a = Value::List(vec![Value::Int(1), Value::Int(2)]);
        let b = Value::List(vec![Value::Int(3)]);
        let out = merge_values(Some(a), b, MergeRule::Shallow);
        match out {
            Value::List(xs) => assert_eq!(xs.len(), 3),
            _ => panic!(),
        }
    }

    #[test]
    fn merge_missing_uses_incoming_without_synthesizing_null() {
        let out = merge_values(None, Value::Int(7), MergeRule::Shallow);
        assert_eq!(out, Value::Int(7));
    }
}
