//! `FactSink` — write-ahead Fact recording with ReplayClass-graded persistence
//! barriers.
//!
//! The hot path writes a fixed-size record (refs + tags). Only
//! `NonIdempotentEffect` operations take a write-ahead fsync barrier before the
//! effect is issued; everything else is an in-memory append flushed by group
//! commit. The sink maintains a monotonic append cursor used **only** for
//! snapshot cut-points and archival — it is not a Fact field and plays no part
//! in identity or idempotency.

use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use xolotl_types::{Fact, OperationId};

/// A durable-write failure from the fact store (disk full, corruption, txn
/// abort). The kernel maps a **pre-effect** failure to a denied operation —
/// prevents the effect and logs a **post-effect** failure for crash recovery to
/// reconcile from the fsync'd pending record. Read failures fall back to an
/// empty result so recovery treats the data as absent.
#[derive(Debug, Error)]
#[error("fact store write failed: {0}")]
pub struct FactError(pub String);

/// Pluggable durable sink. The in-memory impl is the default; redb provides a
/// persistent one. The kernel speaks only this trait. Read failures are
/// surfaced so corrupted Fact storage is never treated as an empty stream.
pub trait FactStore: Send + Sync + 'static {
    /// Append a (possibly pending) fact. Returns the append cursor position.
    /// Errors before the cursor advances, so a retry reuses the same slot.
    fn append(&self, fact: Fact) -> Result<u64, FactError>;
    /// Mark a previously-begun fact complete (outcome filled in).
    fn complete(&self, fact: Fact) -> Result<(), FactError>;
    /// Force durability up to the current cursor (fsync). Called for
    /// write-ahead barriers.
    fn sync(&self) -> Result<(), FactError>;
    /// All facts for one process, in append order.
    fn facts_of(&self, process: xolotl_types::ProcessId) -> Result<Vec<Fact>, FactError>;
    /// All facts, in append order.
    fn all_facts(&self) -> Result<Vec<Fact>, FactError>;
    /// The current monotonic append cursor.
    fn cursor(&self) -> u64;
}

/// In-memory fact store. Tracks append order and a fsync counter so tests can
/// assert "only NonIdempotentEffect takes a barrier".
#[derive(Default)]
pub struct InMemoryFactStore {
    inner: Mutex<FactStoreInner>,
}

#[derive(Default)]
struct FactStoreInner {
    facts: Vec<Fact>,
    /// op id → index into `facts` (for `complete`).
    index: HashMap<OperationId, usize>,
    cursor: u64,
    sync_count: u64,
}

impl InMemoryFactStore {
    /// Create an empty in-memory fact store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of fsyncs issued so far — used to verify the barrier discipline.
    pub fn sync_count(&self) -> u64 {
        self.inner.lock().sync_count
    }

    /// Number of facts currently retained in memory.
    pub fn len(&self) -> usize {
        self.inner.lock().facts.len()
    }

    /// Whether no facts have been appended.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl FactStore for InMemoryFactStore {
    fn append(&self, fact: Fact) -> Result<u64, FactError> {
        let mut inner = self.inner.lock();
        let pos = inner.cursor;
        inner.cursor = inner
            .cursor
            .checked_add(1)
            .ok_or_else(|| FactError("fact cursor overflow".into()))?;
        let idx = inner.facts.len();
        inner.index.insert(fact.id, idx);
        inner.facts.push(fact);
        Ok(pos)
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        let mut inner = self.inner.lock();
        if let Some(&idx) = inner.index.get(&fact.id) {
            inner.facts[idx] = fact;
        } else {
            let idx = inner.facts.len();
            inner.index.insert(fact.id, idx);
            inner.facts.push(fact);
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), FactError> {
        self.inner.lock().sync_count += 1;
        Ok(())
    }

    fn facts_of(&self, process: xolotl_types::ProcessId) -> Result<Vec<Fact>, FactError> {
        Ok(self
            .inner
            .lock()
            .facts
            .iter()
            .filter(|f| f.caller == process)
            .cloned()
            .collect())
    }

    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        Ok(self.inner.lock().facts.clone())
    }

    fn cursor(&self) -> u64 {
        self.inner.lock().cursor
    }
}

/// Shared fact store handle.
pub type SharedFactStore = Arc<dyn FactStore>;

/// The kernel-facing sink: wraps a [`FactStore`] and applies the
/// ReplayClass-graded barrier discipline.
#[derive(Clone)]
pub struct FactSink {
    store: SharedFactStore,
}

impl FactSink {
    /// Wrap a shared fact store in the kernel-facing sink.
    pub fn new(store: SharedFactStore) -> Self {
        Self { store }
    }

    /// Create a sink backed by an in-memory fact store and return both handles.
    pub fn in_memory() -> (Self, Arc<InMemoryFactStore>) {
        let store = Arc::new(InMemoryFactStore::new());
        (
            Self {
                store: store.clone(),
            },
            store,
        )
    }

    /// Begin recording an operation *before* the driver call.
    /// For `NonIdempotentEffect` this writes-ahead and fsyncs (the only class
    /// that does); other classes append in memory. A failure here is reported to
    /// the caller, which **must not** issue the effect.
    pub fn begin(&self, pending: Fact) -> Result<(), FactError> {
        validate_fact_schema(&pending)?;
        let needs_barrier = pending.replay.needs_write_ahead_barrier();
        self.store.append(pending)?;
        if needs_barrier {
            self.store.sync()?;
        }
        Ok(())
    }

    /// Complete an operation's record after the driver returns.
    /// `NonIdempotentEffect` fsyncs again; others ride group commit.
    pub fn complete(&self, fact: Fact) -> Result<(), FactError> {
        validate_fact_schema(&fact)?;
        let needs_barrier = fact.replay.needs_write_ahead_barrier();
        self.store.complete(fact)?;
        if needs_barrier {
            self.store.sync()?;
        }
        Ok(())
    }

    /// Access the underlying shared fact store.
    pub fn store(&self) -> &SharedFactStore {
        &self.store
    }

    /// Return all facts for `process` in append order.
    pub fn facts_of(&self, process: xolotl_types::ProcessId) -> Result<Vec<Fact>, FactError> {
        self.store.facts_of(process)
    }

    /// Return all facts in append order.
    pub fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        self.store.all_facts()
    }

    /// Current append cursor of the underlying fact store.
    pub fn cursor(&self) -> u64 {
        self.store.cursor()
    }
}

fn validate_fact_schema(fact: &Fact) -> Result<(), FactError> {
    if fact.schema_version == Fact::SCHEMA_VERSION {
        Ok(())
    } else {
        Err(FactError(format!(
            "unsupported Fact schema_version {} (current {})",
            fact.schema_version,
            Fact::SCHEMA_VERSION
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{bail, ensure};
    use xolotl_types::{
        DecisionTag, HandleId, IdentityRef, MethodId, NodeId, OutcomeRef, ProcessId, ReplayClass,
        ResourceId, Timestamp, Value, ValueRef,
    };

    fn fact(process: u64, pos: u32, replay: ReplayClass) -> Fact {
        Fact {
            id: OperationId::new(ProcessId::new(process), NodeId::new(pos), 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller: ProcessId::new(process),
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(1),
            method: MethodId::new(0),
            input_ref: ValueRef::Inline(Value::Null),
            taint: xolotl_types::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome_ref: OutcomeRef::Inline(Value::Int(1)),
            batch: None,
            replay,
            timestamp: Timestamp::millis(0),
        }
    }

    #[test]
    fn only_non_idempotent_effect_fsyncs() -> anyhow::Result<()> {
        let (sink, store) = FactSink::in_memory();
        // Deterministic / Observation / Idempotent: no barrier.
        sink.begin(fact(1, 0, ReplayClass::Deterministic))?;
        sink.complete(fact(1, 0, ReplayClass::Deterministic))?;
        sink.begin(fact(1, 1, ReplayClass::Observation))?;
        sink.complete(fact(1, 1, ReplayClass::Observation))?;
        sink.begin(fact(1, 2, ReplayClass::IdempotentEffect))?;
        sink.complete(fact(1, 2, ReplayClass::IdempotentEffect))?;
        ensure!(
            store.sync_count() == 0,
            "replay-safe classes should not fsync"
        );

        // NonIdempotentEffect: fsync at begin and complete.
        sink.begin(fact(1, 3, ReplayClass::NonIdempotentEffect))?;
        sink.complete(fact(1, 3, ReplayClass::NonIdempotentEffect))?;
        ensure!(
            store.sync_count() == 2,
            "non-idempotent effect fsync count mismatch"
        );
        Ok(())
    }

    #[test]
    fn facts_of_filters_by_process() -> anyhow::Result<()> {
        let (sink, _) = FactSink::in_memory();
        sink.begin(fact(1, 0, ReplayClass::Deterministic))?;
        sink.begin(fact(2, 0, ReplayClass::Deterministic))?;
        let facts = sink.facts_of(ProcessId::new(1))?;
        ensure!(
            facts.len() == 1,
            "unexpected process fact count: {}",
            facts.len()
        );
        Ok(())
    }

    #[test]
    fn fact_sink_rejects_unknown_schema_version() -> anyhow::Result<()> {
        let (sink, _) = FactSink::in_memory();
        let mut f = fact(1, 0, ReplayClass::Deterministic);
        f.schema_version = Fact::SCHEMA_VERSION + 1;
        let err = match sink.begin(f) {
            Ok(()) => bail!("expected schema error"),
            Err(err) => err,
        };
        ensure!(
            err.0.contains("unsupported Fact schema_version"),
            "unexpected FactSink error: {err}"
        );
        Ok(())
    }
}
