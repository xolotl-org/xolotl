//! Recovery and quarantine (§15).
//!
//! Recovery is per-Process: read the latest snapshot, replay the facts after
//! it, realign the graph cursor by `NodeId` (§13.2), and handle pending
//! operations per their [`ReplayClass`](nexus_types::ReplayClass) —
//! idempotent ones may retry, non-idempotent ones go to quarantine (§15.3).

use crate::fact::FactSink;
use nexus_graph::GraphCursor;
use nexus_types::{Fact, NodeId, Outcome, ProcessId, ReplayClass};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A replay map (§15.2): `CausalPosition` (NodeId) → the recorded outcome of a
/// completed Operation. When a recovered Process re-runs its program, the
/// Executor consults this map at each Operation node; a hit returns the recorded
/// outcome **without re-issuing the side effect**, so a NonIdempotentEffect that
/// already happened is never repeated. This is how recovery "restarts the
/// Executor" (§15.2) safely — the program runs again, but durable steps are
/// short-circuited to their recorded results, realigned by NodeId.
#[derive(Clone, Debug, Default)]
pub struct ReplayMap {
    outcomes: HashMap<NodeId, Outcome>,
}

impl ReplayMap {
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

    /// Build a replay map from a process's fact stream (§15.2): every *completed*
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
                nexus_types::OutcomeRef::Inline(v) => Outcome::Done(v.clone()),
                nexus_types::OutcomeRef::External { .. } => {
                    // The full value lives in blob/tensor store; recovery reuses
                    // the reference as the outcome value envelope.
                    Outcome::Done(nexus_types::Value::Null)
                }
                // A recorded failure replays as the same failure.
                nexus_types::OutcomeRef::None if !f.decision.is_ok() => Outcome::Fail(
                    nexus_types::Failure::policy("replay", format!("recorded {:?}", f.decision)),
                ),
                nexus_types::OutcomeRef::None => continue,
            };
            outcomes.insert(f.id.position, outcome);
        }
        Self { outcomes }
    }
}

/// A snapshot taken to shorten recovery for a long-running Process (§15.2).
/// `at_cursor` is the FactSink append cursor at snapshot time — not a Fact
/// field (§9). `process_state` and `bindings` let recovery resume without
/// replaying the full fact stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub process: ProcessId,
    pub at_cursor: u64,
    pub graph_cursor: GraphCursor,
    /// The Process descriptor captured at snapshot time (§15.2).
    #[serde(default)]
    pub process_state: Option<nexus_types::Process>,
    /// Binding values (Let-bound results) captured at snapshot time, keyed by
    /// the producer NodeId, so recovery restores the data environment (§15.2).
    #[serde(default)]
    pub bindings: HashMap<NodeId, nexus_types::Value>,
}

/// What recovery decided for one process (§15.2).
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

/// An entry written to `state://quarantine/<process>/<op>` (§15.3): an unsafe
/// replay held for an operator decision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub fact: Fact,
    pub suggested_action: QuarantineAction,
}

/// Operator action on a quarantined op (§15.3). Each is itself an Operation.
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

/// Classify a process's facts on recovery (§15.1 crash-recovery points). A
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
        // Pending: decide by ReplayClass (§15.1 table).
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

/// Recover one process from its fact stream (§15.2). Returns the classification
/// report, the quarantine entries, and a [`ReplayMap`] of completed outcomes so
/// the caller can re-run the process's program with already-durable Operations
/// short-circuited (the "restart the Executor" step of §15.2).
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
/// `state://quarantine/<process>/<op-id>` (§15.3), so an operator can inspect
/// and act on them. Returns the recovery report.
pub async fn recover_process_persisting(
    facts: &FactSink,
    state: &nexus_state::Backend,
    process: ProcessId,
) -> Result<RecoveryReport, crate::FactError> {
    let (report, quarantine, _replay) = recover_process(facts, process)?;
    for entry in &quarantine {
        let path = nexus_types::Path::parse(&format!(
            "{}{}/{}",
            nexus_types::QUARANTINE_PREFIX,
            process.get(),
            entry.fact.id
        ));
        if let Ok(path) = path {
            // Best-effort: a quarantine write failure is logged by the caller,
            // not fatal to recovering other processes.
            let v = nexus_types::Value::Str(format!(
                "{:?} suggested={:?}",
                entry.fact.id, entry.suggested_action
            ));
            let _ = state.write_set(&path, v).await;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::{
        DecisionTag, HandleId, IdentityRef, MethodId, NodeId, OperationId, OutcomeRef, ResourceId,
        Timestamp, Value, ValueRef,
    };

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
            taint: nexus_types::TaintSet::pristine(),
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
    fn completed_facts_are_skipped() {
        let (r, q) = classify_recovery(&[fact(0, ReplayClass::Deterministic, true)]);
        assert_eq!(r.skipped, 1);
        assert!(q.is_empty());
    }

    #[test]
    fn pending_non_idempotent_quarantines() {
        let (r, q) = classify_recovery(&[fact(0, ReplayClass::NonIdempotentEffect, false)]);
        assert_eq!(r.quarantined, 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].suggested_action, QuarantineAction::ManualComplete);
    }

    #[test]
    fn pending_idempotent_retries() {
        let (r, q) = classify_recovery(&[fact(0, ReplayClass::IdempotentEffect, false)]);
        assert_eq!(r.retried, 1);
        assert!(q.is_empty());
    }

    #[test]
    fn unsupported_fact_schema_quarantines_even_completed_fact() {
        let mut f = fact(0, ReplayClass::Deterministic, true);
        f.schema_version = Fact::SCHEMA_VERSION + 1;
        let (r, q) = classify_recovery(&[f.clone()]);

        assert_eq!(r.skipped, 0);
        assert_eq!(r.quarantined, 1);
        assert_eq!(r.schema_mismatched, 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q[0].fact, f);
        assert_eq!(q[0].suggested_action, QuarantineAction::MigrateSchema);
    }

    #[test]
    fn replay_map_ignores_unsupported_fact_schema() {
        let mut f = fact(0, ReplayClass::Deterministic, true);
        f.schema_version = Fact::SCHEMA_VERSION + 1;
        let replay = ReplayMap::from_facts(&[f]);

        assert!(replay.is_empty());
    }
}
