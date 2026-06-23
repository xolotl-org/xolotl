//! In-memory backend. Always built. Used for tests, the embedded SDK, and the
//! default daemon when no persistent backend is configured.
//!
//! Retains an in-memory event history per path so `ReadMode::Range` and
//! `ReadMode::At` queries round-trip end-to-end. The history
//! grows unbounded; persistent deployments use a backend that owns its
//! retention policy.

use crate::backend::{
    StateBackend, StateError, StateEvent, StateHistoryEntry, StateResult, StateStream, TaintedValue,
};
use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use xolotl_types::{MergeRule, Path, TaintSet, Value};

#[derive(Clone, Debug)]
struct Subscriber {
    pattern: Path,
    sender: broadcast::Sender<StateEvent>,
}

/// In-process state. Stores a [`TaintedValue`] per path so provenance
/// persists with the value.
pub struct InMemoryBackend {
    map: DashMap<Path, TaintedValue>,
    /// Linear history of every event the backend has emitted, ordered by
    /// `at_millis`. Range / At queries scan it.
    history: Mutex<Vec<StateHistoryEntry>>,
    last_millis: AtomicI64,
    subs: Mutex<Vec<Subscriber>>,
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
    /// exercise `read_range` and `read_at`, but it does not enforce a retention
    /// limit.
    pub fn new() -> Self {
        Self {
            map: DashMap::new(),
            history: Mutex::new(Vec::new()),
            last_millis: AtomicI64::new(0),
            subs: Mutex::new(Vec::new()),
        }
    }

    fn next_millis(&self) -> i64 {
        loop {
            let observed = self.last_millis.load(Ordering::Relaxed);
            let wall = now_millis();
            let next = if wall > observed { wall } else { observed + 1 };
            if self
                .last_millis
                .compare_exchange(observed, next, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return next;
            }
        }
    }

    fn record(&self, event: StateEvent) -> StateEvent {
        let entry = StateHistoryEntry {
            at_millis: self.next_millis(),
            event: event.clone(),
        };
        self.history.lock().push(entry);
        event
    }

    fn notify(&self, event: StateEvent) {
        let target = event.path().clone();
        let mut subs = self.subs.lock();
        subs.retain(|s| {
            if !target.matches(&s.pattern) {
                return true;
            }
            s.sender.send(event.clone()).is_ok()
        });
    }
}

#[async_trait]
impl StateBackend for InMemoryBackend {
    async fn read_tainted(&self, path: &Path) -> StateResult<Option<TaintedValue>> {
        Ok(self.map.get(path).map(|v| v.clone()))
    }

    async fn write_set_tainted(
        &self,
        path: &Path,
        value: Value,
        taint: TaintSet,
    ) -> StateResult<()> {
        self.map.insert(
            path.clone(),
            TaintedValue::new(value.clone(), taint.clone()),
        );
        let ev = self.record(StateEvent::Set {
            path: path.clone(),
            value,
            taint,
        });
        self.notify(ev);
        Ok(())
    }

    async fn write_append_tainted(
        &self,
        path: &Path,
        item: Value,
        taint: TaintSet,
    ) -> StateResult<()> {
        let mut entry = self
            .map
            .entry(path.clone())
            .or_insert_with(|| TaintedValue::pristine(Value::List(Vec::new())));
        match &mut entry.value {
            Value::List(xs) => xs.push(item.clone()),
            other => {
                return Err(StateError::Backend(format!(
                    "append on non-list at {} (current: {:?})",
                    path, other
                )));
            }
        }
        // The sequence's taint accrues the union of every appended item's
        // lineage: a list that ever held untrusted content stays tainted.
        entry.taint.union(&taint);
        drop(entry);
        let ev = self.record(StateEvent::Append {
            path: path.clone(),
            item,
            taint,
        });
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
        let mut entry = self.map.entry(path.clone());
        let actual = match &entry {
            dashmap::mapref::entry::Entry::Occupied(o) => Some(o.get().value.clone()),
            dashmap::mapref::entry::Entry::Vacant(_) => None,
        };
        if actual != expected {
            return Err(StateError::CasFailed {
                path: path.to_string(),
                expected: expected.map(Box::new),
                actual: actual.map(Box::new),
            });
        }
        let tv = TaintedValue::new(new.clone(), taint.clone());
        match &mut entry {
            dashmap::mapref::entry::Entry::Occupied(o) => {
                o.insert(tv);
            }
            dashmap::mapref::entry::Entry::Vacant(_) => {
                drop(entry);
                self.map.insert(path.clone(), tv);
            }
        }
        let ev = self.record(StateEvent::Set {
            path: path.clone(),
            value: new,
            taint,
        });
        self.notify(ev);
        Ok(())
    }

    async fn write_delete(&self, path: &Path) -> StateResult<()> {
        let prev = self.map.remove(path);
        if prev.is_some() {
            let ev = self.record(StateEvent::Delete { path: path.clone() });
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

    async fn read_range(
        &self,
        path: &Path,
        from_millis: i64,
        to_millis: i64,
    ) -> StateResult<Vec<StateHistoryEntry>> {
        let h = self.history.lock();
        let mut out = Vec::new();
        for entry in h.iter() {
            if entry.at_millis < from_millis || entry.at_millis >= to_millis {
                continue;
            }
            let event_path = entry.event.path();
            if event_path == path || path.is_prefix_of(event_path) {
                out.push(entry.clone());
            }
        }
        Ok(out)
    }

    async fn read_at(&self, path: &Path, at_millis: i64) -> StateResult<Option<Value>> {
        if at_millis == 0 {
            return self.read(path).await;
        }
        let h = self.history.lock();
        let mut current: Option<Value> = None;
        for entry in h.iter() {
            if entry.at_millis > at_millis {
                break;
            }
            match &entry.event {
                StateEvent::Set { path: p, value, .. } if p == path => {
                    current = Some(value.clone())
                }
                StateEvent::Append { path: p, item, .. } if p == path => {
                    let list = match current.take() {
                        Some(Value::List(mut xs)) => {
                            xs.push(item.clone());
                            Value::List(xs)
                        }
                        _ => Value::List(vec![item.clone()]),
                    };
                    current = Some(list);
                }
                StateEvent::Delete { path: p } if p == path => current = None,
                _ => {}
            }
        }
        Ok(current)
    }

    async fn write_merge(&self, path: &Path, value: Value, rule: MergeRule) -> StateResult<()> {
        let current = self.read(path).await?;
        let merged = crate::backend::merge_values(current, value, rule);
        self.write_set(path, merged).await
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
        let mut results = Vec::new();
        for entry in self.map.iter() {
            if prefix.is_prefix_of(entry.key()) || entry.key() == prefix {
                results.push((entry.key().clone(), entry.value().clone()));
            }
        }
        results.sort_by(|(a, _), (b, _)| a.cmp(b));
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, anyhow, bail, ensure};
    use xolotl_types::Path;

    fn p(s: &str) -> anyhow::Result<Path> {
        Path::parse(s).map_err(|error| anyhow!("path parse failed for {s}: {error}"))
    }

    #[tokio::test]
    async fn set_and_read() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_set(&p("state://x")?, Value::Int(42)).await?;
        let v = b.read(&p("state://x")?).await?;
        ensure!(v == Some(Value::Int(42)), "unexpected value: {v:?}");
        Ok(())
    }

    #[tokio::test]
    async fn append_creates_list_then_grows() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_append(&p("state://log")?, Value::Int(1)).await?;
        b.write_append(&p("state://log")?, Value::Int(2)).await?;
        let v = b
            .read(&p("state://log")?)
            .await?
            .context("missing log value")?;
        match v {
            Value::List(xs) => ensure!(xs.len() == 2, "unexpected list length: {}", xs.len()),
            other => bail!("expected list, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn cas_succeeds_on_match() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_set(&p("state://k")?, Value::Int(1)).await?;
        b.write_cas(&p("state://k")?, Some(Value::Int(1)), Value::Int(2))
            .await?;
        let value = b.read(&p("state://k")?).await?;
        ensure!(value == Some(Value::Int(2)), "unexpected value: {value:?}");
        Ok(())
    }

    #[tokio::test]
    async fn cas_fails_on_mismatch() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_set(&p("state://k")?, Value::Int(1)).await?;
        let err = b
            .write_cas(&p("state://k")?, Some(Value::Int(99)), Value::Int(2))
            .await;
        match err {
            Err(StateError::CasFailed { .. }) => {}
            other => bail!("expected CasFailed, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn cas_creates_when_expected_none() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_cas(&p("state://k")?, None, Value::Int(7)).await?;
        let value = b.read(&p("state://k")?).await?;
        ensure!(value == Some(Value::Int(7)), "unexpected value: {value:?}");
        Ok(())
    }

    #[tokio::test]
    async fn cas_can_match_explicit_null_value() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_set(&p("state://k")?, Value::Null).await?;
        b.write_cas(&p("state://k")?, Some(Value::Null), Value::Int(9))
            .await?;
        let value = b.read(&p("state://k")?).await?;
        ensure!(value == Some(Value::Int(9)), "unexpected value: {value:?}");
        Ok(())
    }

    #[tokio::test]
    async fn cas_none_does_not_match_explicit_null_value() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_set(&p("state://k")?, Value::Null).await?;
        let err = b.write_cas(&p("state://k")?, None, Value::Int(9)).await;
        ensure!(
            matches!(err, Err(StateError::CasFailed { .. })),
            "expected CasFailed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn delete_removes() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_set(&p("state://k")?, Value::Int(1)).await?;
        b.write_delete(&p("state://k")?).await?;
        let value = b.read(&p("state://k")?).await?;
        ensure!(value.is_none(), "expected deleted value, got {value:?}");
        Ok(())
    }

    #[tokio::test]
    async fn merge_missing_path_uses_incoming_value() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_merge(&p("state://k")?, Value::Int(7), MergeRule::Shallow)
            .await?;
        let value = b.read(&p("state://k")?).await?;
        ensure!(value == Some(Value::Int(7)), "unexpected value: {value:?}");
        Ok(())
    }

    #[tokio::test]
    async fn subscribe_receives_events() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        let mut rx = b.subscribe(&p("state://watched/**")?).await?;
        b.write_set(&p("state://watched/a")?, Value::Int(1)).await?;
        let ev = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
            .await
            .map_err(|error| anyhow!("timed out waiting for event: {error}"))?
            .map_err(|error| anyhow!("event receive failed: {error}"))?;
        match ev {
            StateEvent::Set { path, .. } => ensure!(
                path.to_string() == "state://watched/a",
                "unexpected path: {path}"
            ),
            other => bail!("wrong event: {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn subscribe_filters_by_pattern() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        let mut rx = b.subscribe(&p("state://watched/specific")?).await?;
        b.write_set(&p("state://watched/other")?, Value::Int(1))
            .await?;
        let res = tokio::time::timeout(std::time::Duration::from_millis(20), rx.recv()).await;
        ensure!(res.is_err(), "unexpected event: {res:?}");
        Ok(())
    }

    #[tokio::test]
    async fn read_prefix_returns_sorted_matching_entries_only() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_set(&p("state://memory/b")?, Value::Int(2)).await?;
        b.write_set(&p("state://memory/a")?, Value::Int(1)).await?;
        b.write_set(&p("state://other/z")?, Value::Int(99)).await?;

        let rows = b.read_prefix(&p("state://memory")?).await?;
        let paths: Vec<String> = rows.into_iter().map(|(path, _)| path.to_string()).collect();
        ensure!(
            paths == vec!["state://memory/a", "state://memory/b"],
            "unexpected paths: {paths:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn read_range_includes_direct_and_descendant_paths() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        let prefix = p("state://memory")?;
        b.write_set(&p("state://memory")?, Value::Int(1)).await?;
        b.write_set(&p("state://memory/alice")?, Value::Int(2))
            .await?;
        b.write_set(&p("state://other")?, Value::Int(3)).await?;

        let entries = b.read_range(&prefix, 0, i64::MAX).await?;
        let event_paths: Vec<String> = entries
            .into_iter()
            .map(|entry| match entry.event {
                StateEvent::Set { path, .. } => path.to_string(),
                StateEvent::Append { path, .. } => path.to_string(),
                StateEvent::Delete { path } => path.to_string(),
            })
            .collect();
        ensure!(
            event_paths == vec!["state://memory", "state://memory/alice"],
            "unexpected paths: {event_paths:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn read_at_reconstructs_list_before_delete() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        let path = p("state://log")?;
        b.write_append(&path, Value::Int(1)).await?;
        let after_first = b
            .history
            .lock()
            .first()
            .context("missing first history entry")?
            .at_millis;
        b.write_append(&path, Value::Int(2)).await?;
        let before_delete = b
            .history
            .lock()
            .get(1)
            .context("missing second history entry")?
            .at_millis;
        b.write_delete(&path).await?;

        let before_value = b.read_at(&path, after_first).await?;
        let mid_value = b.read_at(&path, before_delete).await?;
        let current = b.read(&path).await?;

        ensure!(
            before_value == Some(Value::List(vec![Value::Int(1)])),
            "unexpected first historical value: {before_value:?}"
        );
        ensure!(
            mid_value == Some(Value::List(vec![Value::Int(1), Value::Int(2)])),
            "unexpected second historical value: {mid_value:?}"
        );
        ensure!(current.is_none(), "unexpected current value: {current:?}");
        Ok(())
    }

    #[tokio::test]
    async fn history_timestamps_are_strictly_increasing() -> anyhow::Result<()> {
        let b = InMemoryBackend::new();
        b.write_set(&p("state://x")?, Value::Int(1)).await?;
        b.write_set(&p("state://x")?, Value::Int(2)).await?;
        b.write_delete(&p("state://x")?).await?;

        let times: Vec<i64> = b
            .history
            .lock()
            .iter()
            .map(|entry| entry.at_millis)
            .collect();
        match times.as_slice() {
            [first, second, third] => {
                ensure!(first < second, "first timestamp order violated: {times:?}");
                ensure!(second < third, "second timestamp order violated: {times:?}");
            }
            other => bail!("expected 3 timestamps, got {other:?}"),
        }
        Ok(())
    }
}
