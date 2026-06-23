//! Recovery and quarantine.
//!
//! Recovery is per-Process: classify the process Fact stream, build a replay
//! map for completed outcomes, and handle pending operations per their
//! [`ReplayClass`]. Idempotent ones may retry; non-idempotent ones go to
//! quarantine.

use crate::fact::FactSink;
use andrias_graph::GraphCursor;
use andrias_types::{
    DecisionTag, Fact, NodeId, OperationId, Outcome, OutcomeRef, Path, ProcessId, ReplayClass,
    Value, ValueRef,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// A replay map: `CausalPosition` (NodeId) → the recorded outcome of a
/// completed Operation. When a recovered Process re-runs its program, the
/// Executor consults this map at each Operation node; a hit returns the recorded
/// outcome **without re-issuing the side effect**, so a NonIdempotentEffect that
/// already happened is never repeated. This is how recovery "restarts the
/// Executor" safely — the program runs again, but durable steps are
/// short-circuited to their recorded results, realigned by NodeId.
#[derive(Clone, Debug, Default)]
pub struct ReplayMap {
    outcomes: HashMap<NodeId, Outcome>,
}

impl ReplayMap {
    /// Create an empty replay map for a fresh run.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether any recorded outcomes exist (an empty map ⇒ a fresh run, the
    /// Executor takes the normal path).
    pub fn is_empty(&self) -> bool {
        self.outcomes.is_empty()
    }

    /// Look up the recorded outcome for a node (its CausalPosition).
    pub fn get(&self, node: NodeId) -> Option<&Outcome> {
        self.outcomes.get(&node)
    }

    /// Build a replay map from a process's fact stream: every *completed*
    /// fact contributes its recorded outcome at its CausalPosition. Pending
    /// facts (no outcome) are not included — they re-execute (idempotent) or are
    /// quarantined (non-idempotent) per [`classify_recovery`].
    pub fn from_facts(facts: &[Fact]) -> Self {
        let mut outcomes = HashMap::new();
        for f in facts {
            if f.schema_version != Fact::SCHEMA_VERSION {
                continue;
            }
            if !f.is_complete() {
                continue;
            }
            // The latest attempt at a position wins (facts are append-ordered).
            let outcome = match &f.outcome_ref {
                andrias_types::OutcomeRef::Inline(v) => Outcome::Done(v.clone()),
                andrias_types::OutcomeRef::External { .. } => {
                    // The full value lives in blob/tensor store; recovery reuses
                    // the reference as the outcome value envelope.
                    Outcome::Done(andrias_types::Value::Null)
                }
                // A recorded failure replays as the same failure.
                andrias_types::OutcomeRef::None if !f.decision.is_ok() => Outcome::Fail(
                    andrias_types::Failure::policy("replay", format!("recorded {:?}", f.decision)),
                ),
                andrias_types::OutcomeRef::None => continue,
            };
            outcomes.insert(f.id.position, outcome);
        }
        Self { outcomes }
    }
}

/// A snapshot taken to shorten recovery for a long-running Process.
/// `at_cursor` is the FactSink append cursor at snapshot time — not a Fact
/// field. `process_state` and `bindings` let recovery resume without
/// replaying the full fact stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Process captured by this snapshot.
    pub process: ProcessId,
    /// Fact sink append cursor at snapshot time.
    pub at_cursor: u64,
    /// Graph execution cursor captured at snapshot time.
    pub graph_cursor: GraphCursor,
    /// The Process descriptor captured at snapshot time.
    #[serde(default)]
    pub process_state: Option<andrias_types::Process>,
    /// Binding values (Let-bound results) captured at snapshot time, keyed by
    /// the producer NodeId, so recovery restores the data environment.
    #[serde(default)]
    pub bindings: HashMap<NodeId, andrias_types::Value>,
}

/// What recovery decided for one process.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Completed operations skipped (already durable).
    pub skipped: usize,
    /// Pending idempotent operations scheduled for retry.
    pub retried: usize,
    /// Pending non-idempotent operations sent to quarantine.
    pub quarantined: usize,
    /// Facts whose schema version is not supported by this binary.
    pub schema_mismatched: usize,
}

/// An entry written to `state://quarantine/<process>/<op>`: an unsafe
/// replay held for an operator decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Fact that cannot be replayed automatically.
    pub fact: Fact,
    /// Suggested operator action for the quarantined fact.
    pub suggested_action: QuarantineAction,
}

/// Operator action on a quarantined op. Each is itself an Operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineAction {
    /// Run an explicit Fact schema migration before replaying this process.
    MigrateSchema,
    /// Confirm the remote effect is idempotent-safe and continue.
    ForceReplay,
    /// Write `Fail(QuarantineSkipped)`, let `OrElse` handle it.
    Skip,
    /// A human supplies the outcome; advance the graph cursor.
    ManualComplete,
    /// Abandon the process, run finalizers.
    Finalize,
}

/// Classify a process's facts on recovery. A
/// fact with no outcome is *pending*; how it is handled depends on its replay
/// class. Returns the recovery report.
pub fn classify_recovery(facts: &[Fact]) -> (RecoveryReport, Vec<QuarantineEntry>) {
    let mut report = RecoveryReport::default();
    let mut quarantine = Vec::new();
    for f in facts {
        if f.schema_version != Fact::SCHEMA_VERSION {
            report.quarantined += 1;
            report.schema_mismatched += 1;
            quarantine.push(QuarantineEntry {
                fact: f.clone(),
                suggested_action: QuarantineAction::MigrateSchema,
            });
            continue;
        }
        if f.is_complete() {
            report.skipped += 1;
            continue;
        }
        // Pending: decide by ReplayClass.
        match f.replay {
            ReplayClass::Deterministic | ReplayClass::Observation => {
                // Safe to recompute / reread on replay.
                report.retried += 1;
            }
            ReplayClass::IdempotentEffect => {
                // Retry under the idempotency key.
                report.retried += 1;
            }
            ReplayClass::NonIdempotentEffect => {
                // "Issued but unrecorded" risk: quarantine, do not auto-retry.
                report.quarantined += 1;
                quarantine.push(QuarantineEntry {
                    fact: f.clone(),
                    suggested_action: QuarantineAction::ManualComplete,
                });
            }
        }
    }
    (report, quarantine)
}

/// Recover one process from its fact stream. Returns the classification
/// report, the quarantine entries, and a [`ReplayMap`] of completed outcomes so
/// the caller can re-run the process's program with already-durable Operations
/// short-circuited.
pub fn recover_process(
    facts: &FactSink,
    process: ProcessId,
) -> Result<(RecoveryReport, Vec<QuarantineEntry>, ReplayMap), crate::FactError> {
    let facts = facts.facts_of(process)?;
    let (report, quarantine) = classify_recovery(&facts);
    let replay = ReplayMap::from_facts(&facts);
    Ok((report, quarantine, replay))
}

/// Recover one process and **persist** its quarantine entries to
/// `state://quarantine/<process>/<op-id>`, so an operator can inspect
/// and act on them. Returns the recovery report.
pub async fn recover_process_persisting(
    facts: &FactSink,
    state: &andrias_state::Backend,
    process: ProcessId,
) -> Result<RecoveryReport, crate::FactError> {
    let (report, quarantine, _replay) = recover_process(facts, process)?;
    for entry in &quarantine {
        let path = quarantine_path(process, entry.fact.id)?;
        let value = quarantine_entry_value(entry);
        state.write_set(&path, value).await.map_err(|error| {
            crate::FactError(format!("quarantine state write failed at {path}: {error}"))
        })?;
    }
    Ok(report)
}

fn quarantine_path(process: ProcessId, op_id: OperationId) -> Result<Path, crate::FactError> {
    Path::try_new("state")
        .and_then(|path| path.try_push("quarantine"))
        .and_then(|path| path.try_push_literal(process.get().to_string()))
        .and_then(|path| path.try_push_literal(op_id.process.get().to_string()))
        .and_then(|path| path.try_push_literal(op_id.position.get().to_string()))
        .and_then(|path| path.try_push_literal(op_id.attempt.to_string()))
        .map_err(|error| crate::FactError(format!("quarantine path construction failed: {error}")))
}

fn quarantine_entry_value(entry: &QuarantineEntry) -> Value {
    let fact = &entry.fact;
    let mut root = BTreeMap::new();
    root.insert("kind".into(), Value::Str("quarantine_entry".into()));
    root.insert("op_id".into(), Value::Str(fact.id.to_string()));
    root.insert(
        "suggested_action".into(),
        Value::Str(quarantine_action_name(entry.suggested_action).into()),
    );
    root.insert("pending".into(), Value::Bool(!fact.is_complete()));
    root.insert("fact".into(), fact_value(fact));
    Value::Map(root)
}

fn fact_value(fact: &Fact) -> Value {
    let mut map = BTreeMap::new();
    map.insert(
        "schema_version".into(),
        Value::Int(i64::from(fact.schema_version)),
    );
    map.insert("caller".into(), u64_value(fact.caller.get()));
    map.insert("acting".into(), u64_value(fact.acting.get()));
    map.insert(
        "handle".into(),
        handle_value(fact.handle.index, fact.handle.generation),
    );
    map.insert("resource".into(), u64_value(fact.resource.get()));
    map.insert("method".into(), u64_value(fact.method.get()));
    map.insert("input_ref".into(), value_ref_value(&fact.input_ref));
    map.insert(
        "decision".into(),
        Value::Str(decision_name(fact.decision).into()),
    );
    map.insert("outcome_ref".into(), outcome_ref_value(&fact.outcome_ref));
    map.insert("replay".into(), Value::Str(replay_name(fact.replay).into()));
    map.insert("timestamp".into(), Value::Int(fact.timestamp.get()));
    map.insert("tainted".into(), Value::Bool(!fact.taint.is_pristine()));
    map.insert("protected".into(), Value::Bool(fact.taint.has_protected()));
    Value::Map(map)
}

fn handle_value(index: u32, generation: u32) -> Value {
    Value::Map(BTreeMap::from([
        ("index".into(), Value::Int(i64::from(index))),
        ("generation".into(), Value::Int(i64::from(generation))),
    ]))
}

fn value_ref_value(value_ref: &ValueRef) -> Value {
    match value_ref {
        ValueRef::Inline(value) => Value::Map(BTreeMap::from([
            ("kind".into(), Value::Str("inline".into())),
            ("value".into(), value.clone()),
        ])),
        ValueRef::External { hash, size } => Value::Map(BTreeMap::from([
            ("kind".into(), Value::Str("external".into())),
            ("hash".into(), Value::Str(hash.clone())),
            ("size".into(), u64_value(*size)),
        ])),
    }
}

fn outcome_ref_value(outcome_ref: &OutcomeRef) -> Value {
    match outcome_ref {
        OutcomeRef::Inline(value) => Value::Map(BTreeMap::from([
            ("kind".into(), Value::Str("inline".into())),
            ("value".into(), value.clone()),
        ])),
        OutcomeRef::External { hash, size } => Value::Map(BTreeMap::from([
            ("kind".into(), Value::Str("external".into())),
            ("hash".into(), Value::Str(hash.clone())),
            ("size".into(), u64_value(*size)),
        ])),
        OutcomeRef::None => {
            Value::Map(BTreeMap::from([("kind".into(), Value::Str("none".into()))]))
        }
    }
}

fn u64_value(value: u64) -> Value {
    Value::Str(value.to_string())
}

fn decision_name(decision: DecisionTag) -> &'static str {
    match decision {
        DecisionTag::Ok => "ok",
        DecisionTag::Denied => "denied",
        DecisionTag::RejectedByPolicy => "rejected_by_policy",
        DecisionTag::DriverError => "driver_error",
        DecisionTag::Timeout => "timeout",
        DecisionTag::Cancelled => "cancelled",
        DecisionTag::Quarantined => "quarantined",
    }
}

fn replay_name(replay: ReplayClass) -> &'static str {
    match replay {
        ReplayClass::Deterministic => "deterministic",
        ReplayClass::Observation => "observation",
        ReplayClass::IdempotentEffect => "idempotent_effect",
        ReplayClass::NonIdempotentEffect => "non_idempotent_effect",
    }
}

fn quarantine_action_name(action: QuarantineAction) -> &'static str {
    match action {
        QuarantineAction::MigrateSchema => "migrate_schema",
        QuarantineAction::ForceReplay => "force_replay",
        QuarantineAction::Skip => "skip",
        QuarantineAction::ManualComplete => "manual_complete",
        QuarantineAction::Finalize => "finalize",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andrias_state::{StateBackend, StateError, StateResult, TaintedValue};
    use andrias_types::{
        DecisionTag, HandleId, IdentityRef, MethodId, NodeId, OperationId, OutcomeRef, ResourceId,
        TaintSet, Timestamp, Value, ValueRef,
    };
    use anyhow::{Context, ensure};
    use std::sync::Arc;

    struct FailingStateBackend;

    #[async_trait::async_trait]
    impl StateBackend for FailingStateBackend {
        async fn read_tainted(&self, _path: &Path) -> StateResult<Option<TaintedValue>> {
            Ok(None)
        }

        async fn write_set_tainted(
            &self,
            _path: &Path,
            _value: Value,
            _taint: TaintSet,
        ) -> StateResult<()> {
            Err(StateError::Backend("simulated state failure".into()))
        }

        async fn write_append_tainted(
            &self,
            _path: &Path,
            _item: Value,
            _taint: TaintSet,
        ) -> StateResult<()> {
            Err(StateError::Unsupported("write_append_tainted"))
        }

        async fn write_cas_tainted(
            &self,
            _path: &Path,
            _expected: Option<Value>,
            _new: Value,
            _taint: TaintSet,
        ) -> StateResult<()> {
            Err(StateError::Unsupported("write_cas_tainted"))
        }

        async fn write_delete(&self, _path: &Path) -> StateResult<()> {
            Err(StateError::Unsupported("write_delete"))
        }

        async fn subscribe(&self, _pattern: &Path) -> StateResult<andrias_state::StateStream> {
            Err(StateError::Unsupported("subscribe"))
        }

        async fn read_prefix_tainted(
            &self,
            _prefix: &Path,
        ) -> StateResult<Vec<(Path, TaintedValue)>> {
            Err(StateError::Unsupported("read_prefix_tainted"))
        }
    }

    fn fact(pos: u32, replay: ReplayClass, complete: bool) -> Fact {
        Fact {
            id: OperationId::new(ProcessId::new(1), NodeId::new(pos), 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller: ProcessId::new(1),
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(1),
            method: MethodId::new(0),
            input_ref: ValueRef::Inline(Value::Null),
            taint: andrias_types::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome_ref: if complete {
                OutcomeRef::Inline(Value::Int(1))
            } else {
                OutcomeRef::None
            },
            batch: None,
            replay,
            timestamp: Timestamp::millis(0),
        }
    }

    #[test]
    fn completed_facts_are_skipped() -> anyhow::Result<()> {
        let (r, q) = classify_recovery(&[fact(0, ReplayClass::Deterministic, true)]);
        ensure!(r.skipped == 1, "completed fact should be skipped");
        ensure!(q.is_empty(), "completed fact should not be quarantined");
        Ok(())
    }

    #[test]
    fn pending_non_idempotent_quarantines() -> anyhow::Result<()> {
        let (r, q) = classify_recovery(&[fact(0, ReplayClass::NonIdempotentEffect, false)]);
        ensure!(
            r.quarantined == 1,
            "pending non-idempotent fact should quarantine"
        );
        ensure!(q.len() == 1, "unexpected quarantine count: {}", q.len());
        let quarantine = q.first().context("missing quarantine entry")?;
        ensure!(
            quarantine.suggested_action == QuarantineAction::ManualComplete,
            "unexpected quarantine action"
        );
        Ok(())
    }

    #[test]
    fn pending_idempotent_retries() -> anyhow::Result<()> {
        let (r, q) = classify_recovery(&[fact(0, ReplayClass::IdempotentEffect, false)]);
        ensure!(r.retried == 1, "pending idempotent fact should retry");
        ensure!(q.is_empty(), "idempotent retry should not quarantine");
        Ok(())
    }

    #[test]
    fn unsupported_fact_schema_quarantines_even_completed_fact() -> anyhow::Result<()> {
        let mut f = fact(0, ReplayClass::Deterministic, true);
        f.schema_version = Fact::SCHEMA_VERSION + 1;
        let (r, q) = classify_recovery(&[f.clone()]);

        ensure!(r.skipped == 0, "unsupported schema should not be skipped");
        ensure!(r.quarantined == 1, "unsupported schema should quarantine");
        ensure!(r.schema_mismatched == 1, "schema mismatch count mismatch");
        ensure!(q.len() == 1, "unexpected quarantine count: {}", q.len());
        let quarantine = q.first().context("missing quarantine entry")?;
        ensure!(quarantine.fact == f, "quarantined fact mismatch");
        ensure!(
            quarantine.suggested_action == QuarantineAction::MigrateSchema,
            "unexpected quarantine action"
        );
        Ok(())
    }

    #[test]
    fn replay_map_ignores_unsupported_fact_schema() -> anyhow::Result<()> {
        let mut f = fact(0, ReplayClass::Deterministic, true);
        f.schema_version = Fact::SCHEMA_VERSION + 1;
        let replay = ReplayMap::from_facts(&[f]);

        ensure!(
            replay.is_empty(),
            "unsupported fact schema should not enter replay map"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovery_persists_structured_quarantine_entry() -> anyhow::Result<()> {
        let (sink, _) = FactSink::in_memory();
        let pending = fact(0, ReplayClass::NonIdempotentEffect, false);
        sink.begin(pending.clone())?;
        let state: andrias_state::Backend = Arc::new(andrias_state::InMemoryBackend::new());

        let report = recover_process_persisting(&sink, &state, ProcessId::new(1)).await?;

        ensure!(report.quarantined == 1, "unexpected report: {report:?}");
        let path = quarantine_path(ProcessId::new(1), pending.id)?;
        let value = state
            .read(&path)
            .await?
            .context("missing persisted quarantine entry")?;
        let root = value.as_map().context("quarantine entry must be a map")?;
        ensure!(
            root.get("suggested_action") == Some(&Value::Str("manual_complete".into())),
            "unexpected suggested action: {root:?}"
        );
        ensure!(
            root.get("pending") == Some(&Value::Bool(true)),
            "quarantine entry should mark pending fact"
        );
        let fact = root
            .get("fact")
            .and_then(Value::as_map)
            .context("quarantine entry missing structured fact")?;
        ensure!(
            fact.get("replay") == Some(&Value::Str("non_idempotent_effect".into())),
            "unexpected replay field: {fact:?}"
        );
        ensure!(
            fact.get("outcome_ref")
                .and_then(Value::as_map)
                .and_then(|m| m.get("kind"))
                == Some(&Value::Str("none".into())),
            "pending fact should retain empty outcome ref: {fact:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovery_returns_error_when_quarantine_state_write_fails() -> anyhow::Result<()> {
        let (sink, _) = FactSink::in_memory();
        sink.begin(fact(0, ReplayClass::NonIdempotentEffect, false))?;
        let state: andrias_state::Backend = Arc::new(FailingStateBackend);

        let error = recover_process_persisting(&sink, &state, ProcessId::new(1))
            .await
            .err()
            .context("recovery unexpectedly ignored quarantine state write failure")?;

        ensure!(
            error.0.contains("quarantine state write failed"),
            "unexpected recovery error: {error}"
        );
        Ok(())
    }
}
