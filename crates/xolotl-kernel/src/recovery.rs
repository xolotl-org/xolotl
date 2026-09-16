//! Recovery and quarantine.
//!
//! Classify retained Facts and retain uncertain effects for reconciliation.
//! Facts describe operations; they do not retain the control flow, values, or
//! scheduling state needed to resume execution. Execution resumes only from a
//! machine checkpoint.

use crate::fact::{FactQuery, FactSink};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use xolotl_types::{DecisionTag, Fact, OperationId, Path, ProcessId, ReplayClass, Value};

/// Classification of operation records. No execution is scheduled.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryReport {
    /// Completed records that require no reconciliation.
    pub skipped: usize,
    /// Pending records whose replay class permits retry from a checkpoint.
    pub retried: usize,
    /// Records held because their format or external outcome cannot be trusted.
    pub quarantined: usize,
    /// Facts whose schema version is not supported by this binary.
    pub schema_mismatched: usize,
}

/// Limits on each storage page consumed by automatic Fact reconciliation.
/// Defaults to 256 records and 1 MiB of encoded Fact data. These bound copied
/// input per page, not total storage, quarantine output or actual heap usage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryLimits {
    /// Maximum number of records read per page.
    pub page_limit: NonZeroUsize,
    /// Maximum sum of JSON-encoded record sizes per page. An oversized record
    /// stops recovery with an error; it is never skipped or truncated.
    pub max_encoded_bytes: NonZeroUsize,
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            page_limit: NonZeroUsize::new(256).unwrap_or(NonZeroUsize::MIN),
            max_encoded_bytes: NonZeroUsize::new(1024 * 1024).unwrap_or(NonZeroUsize::MIN),
        }
    }
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

/// Disposition for a quarantined operation. Classification executes no action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineAction {
    /// Retain an unsupported record without attempting to interpret or replay it.
    Hold,
    /// Confirm the remote effect is idempotent-safe and continue.
    ForceReplay,
    /// Write `Fail(QuarantineSkipped)`, let `OrElse` handle it.
    Skip,
    /// Supply a reconciled outcome before resuming the checkpoint.
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
        if let Some(suggested_action) = classify_fact(f, &mut report) {
            quarantine.push(QuarantineEntry {
                fact: f.clone(),
                suggested_action,
            });
        }
    }
    (report, quarantine)
}

fn classify_fact(fact: &Fact, report: &mut RecoveryReport) -> Option<QuarantineAction> {
    if fact.schema_version != Fact::SCHEMA_VERSION {
        report.quarantined += 1;
        report.schema_mismatched += 1;
        Some(QuarantineAction::Hold)
    } else if fact.is_complete() {
        report.skipped += 1;
        None
    } else if fact.replay == ReplayClass::NonIdempotentEffect {
        report.quarantined += 1;
        Some(QuarantineAction::ManualComplete)
    } else {
        report.retried += 1;
        None
    }
}

/// Inspect one process's fact stream without executing or reconstructing outcomes.
/// This convenience API materializes its history and quarantine output. Use
/// [`FactSink::scan`] with [`classify_recovery`] for bounded diagnostic batches.
pub fn recover_process(
    facts: &FactSink,
    process: ProcessId,
) -> Result<(RecoveryReport, Vec<QuarantineEntry>), crate::FactError> {
    let facts = facts.facts_of(process)?;
    Ok(classify_recovery(&facts))
}

/// Recover one process and **persist** its quarantine entries to
/// `state://quarantine/<process>/<op-id>`, so an operator can inspect
/// and act on them. Uses [`RecoveryLimits::default`] and returns the report.
pub async fn recover_process_persisting(
    facts: &FactSink,
    state: &xolotl_state::Backend,
    process: ProcessId,
) -> Result<RecoveryReport, crate::FactError> {
    recover_process_persisting_with_limits(facts, state, process, RecoveryLimits::default()).await
}

/// Classify all retained operation records and persist their quarantine entries.
/// Recovery remains independent of process-table retention and startup admission.
/// Uses [`RecoveryLimits::default`]; see [`recover_all_persisting_with_limits`].
pub async fn recover_all_persisting(
    facts: &FactSink,
    state: &xolotl_state::Backend,
) -> Result<RecoveryReport, crate::FactError> {
    recover_all_persisting_with_limits(facts, state, RecoveryLimits::default()).await
}

/// Reconcile one caller's records with explicit per-page read budgets.
/// Shares the consistency and partial-failure contract of
/// [`recover_all_persisting_with_limits`].
pub async fn recover_process_persisting_with_limits(
    facts: &FactSink,
    state: &xolotl_state::Backend,
    process: ProcessId,
    limits: RecoveryLimits,
) -> Result<RecoveryReport, crate::FactError> {
    recover_persisting(facts, state, Some(process), limits).await
}

/// Reconcile a fixed append interval one bounded page at a time, persisting each
/// quarantine entry before fetching another page. No full-history collection or
/// background task is required. The host must quiesce writers for a stable
/// classification, since old records can still receive outcome updates.
///
/// Errors, including oversized records, propagate after any earlier quarantine
/// writes. Retrying overwrites the same quarantine paths. Storage retention and
/// the state backend's own history remain independent of these read budgets.
pub async fn recover_all_persisting_with_limits(
    facts: &FactSink,
    state: &xolotl_state::Backend,
    limits: RecoveryLimits,
) -> Result<RecoveryReport, crate::FactError> {
    recover_persisting(facts, state, None, limits).await
}

async fn recover_persisting(
    facts: &FactSink,
    state: &xolotl_state::Backend,
    process: Option<ProcessId>,
    limits: RecoveryLimits,
) -> Result<RecoveryReport, crate::FactError> {
    let mut query = FactQuery::new(limits.page_limit, limits.max_encoded_bytes);
    query.process = process;
    let mut report = RecoveryReport::default();
    loop {
        let page = facts.scan(query)?;
        if query.before.is_some_and(|end| end != page.end) {
            return Err(crate::FactError(
                "recovery scan append bound changed".into(),
            ));
        }
        let next = query.next_page(&page);
        for fact in page.facts {
            if let Some(suggested_action) = classify_fact(&fact, &mut report) {
                persist_quarantine_entry(
                    state,
                    QuarantineEntry {
                        fact,
                        suggested_action,
                    },
                )
                .await?;
            }
        }
        let Some(next) = next else {
            return Ok(report);
        };
        query = next;
        tokio::task::yield_now().await;
    }
}

async fn persist_quarantine_entry(
    state: &xolotl_state::Backend,
    entry: QuarantineEntry,
) -> Result<(), crate::FactError> {
    let path = quarantine_path(entry.fact.caller, entry.fact.id)?;
    let value = quarantine_entry_value(&entry);
    drop(entry);
    state
        .write_set(&path, value)
        .await
        .map(|_commit| ())
        .map_err(|error| {
            crate::FactError(format!("quarantine state write failed at {path}: {error}"))
        })
}

fn quarantine_path(process: ProcessId, op_id: OperationId) -> Result<Path, crate::FactError> {
    Path::try_new("state")
        .and_then(|path| path.try_push("quarantine"))
        .and_then(|path| path.try_push_literal(process.get().to_string()))
        .and_then(|path| path.try_push_literal(op_id.process.get().to_string()))
        .and_then(|path| path.try_push_literal(op_id.execution.get().to_string()))
        .and_then(|path| path.try_push_literal(op_id.invocation.get().to_string()))
        .and_then(|path| path.try_push_literal(op_id.position.get().to_string()))
        .and_then(|path| path.try_push_literal(op_id.attempt.to_string()))
        .map_err(|error| crate::FactError(format!("quarantine path construction failed: {error}")))
}

fn quarantine_entry_value(entry: &QuarantineEntry) -> Value {
    let fact = &entry.fact;
    let mut root = BTreeMap::new();
    root.insert("kind".into(), Value::string("quarantine_entry".into()));
    root.insert("op_id".into(), Value::string(fact.id.to_string()));
    root.insert(
        "suggested_action".into(),
        Value::string(quarantine_action_name(entry.suggested_action).into()),
    );
    root.insert("pending".into(), Value::boolean(!fact.is_complete()));
    root.insert("fact".into(), fact_value(fact));
    Value::map(root)
}

fn fact_value(fact: &Fact) -> Value {
    let mut map = BTreeMap::new();
    map.insert(
        "schema_version".into(),
        Value::integer(i64::from(fact.schema_version)),
    );
    map.insert("caller".into(), u64_value(fact.caller.get()));
    map.insert("acting".into(), u64_value(fact.acting.get()));
    map.insert(
        "handle".into(),
        handle_value(fact.handle.index, fact.handle.generation),
    );
    map.insert("resource".into(), u64_value(fact.resource.get()));
    map.insert("method".into(), u64_value(fact.method.get()));
    map.insert("input".into(), fact.input.clone());
    map.insert(
        "decision".into(),
        Value::string(decision_name(fact.decision).into()),
    );
    if let Some(outcome) = &fact.outcome {
        map.insert("outcome".into(), outcome.clone());
    }
    map.insert(
        "replay".into(),
        Value::string(replay_name(fact.replay).into()),
    );
    map.insert("timestamp".into(), Value::integer(fact.timestamp.get()));
    map.insert("tainted".into(), Value::boolean(!fact.taint.is_pristine()));
    map.insert(
        "protected".into(),
        Value::boolean(fact.taint.has_protected()),
    );
    Value::map(map)
}

fn handle_value(index: u32, generation: u64) -> Value {
    Value::map(BTreeMap::from([
        ("index".into(), Value::integer(i64::from(index))),
        ("generation".into(), u64_value(generation)),
    ]))
}

fn u64_value(value: u64) -> Value {
    Value::string(value.to_string())
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
        QuarantineAction::Hold => "hold",
        QuarantineAction::ForceReplay => "force_replay",
        QuarantineAction::Skip => "skip",
        QuarantineAction::ManualComplete => "manual_complete",
        QuarantineAction::Finalize => "finalize",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use std::sync::Arc;
    use xolotl_state::{StateError, StateMutation, StateResult, StateScan, StateWrite};
    use xolotl_types::{
        DecisionTag, ExecutionId, HandleId, IdentityRef, InvocationId, MethodId, NodeId,
        OperationId, ResourceId, Timestamp, Value,
    };

    #[test]
    fn quarantine_projection_preserves_large_handle_generations() -> anyhow::Result<()> {
        let mut pending = fact(0, ReplayClass::NonIdempotentEffect, false);
        pending.handle = HandleId::new(u32::MAX, u64::MAX);
        let projected = fact_value(&pending);
        let handle = projected
            .as_map()
            .and_then(|value| value.get("handle"))
            .and_then(Value::as_map)
            .context("missing projected handle")?;
        ensure!(handle.get("index") == Some(&Value::integer(i64::from(u32::MAX))));
        ensure!(handle.get("generation") == Some(&Value::string(u64::MAX.to_string())));
        Ok(())
    }

    struct PagedOnlyStore {
        inner: crate::InMemoryFactStore,
        queries: parking_lot::Mutex<Vec<FactQuery>>,
        append_after_first: parking_lot::Mutex<Option<Fact>>,
        fail_from: Option<u64>,
        invalid_page: Option<crate::FactPage>,
    }

    impl PagedOnlyStore {
        fn new() -> Self {
            Self {
                inner: crate::InMemoryFactStore::new(),
                queries: parking_lot::Mutex::new(Vec::new()),
                append_after_first: parking_lot::Mutex::new(None),
                fail_from: None,
                invalid_page: None,
            }
        }
    }

    impl crate::ExecutionIdSource for PagedOnlyStore {
        fn reserve(
            &self,
            count: std::num::NonZeroU64,
        ) -> Result<crate::ExecutionIdRange, crate::ExecutionIdError> {
            self.inner.reserve(count)
        }
    }

    impl crate::FactStore for PagedOnlyStore {
        fn append(&self, fact: Fact) -> Result<u64, crate::FactError> {
            self.inner.append(fact)
        }

        fn complete(&self, fact: Fact) -> Result<(), crate::FactError> {
            self.inner.complete(fact)
        }

        fn sync(&self) -> Result<(), crate::FactError> {
            self.inner.sync()
        }

        fn scan(&self, query: FactQuery) -> Result<crate::FactPage, crate::FactError> {
            self.queries.lock().push(query);
            if let Some(page) = &self.invalid_page {
                return Ok(page.clone());
            }
            if self.fail_from == Some(query.from) {
                return Err(crate::FactError("simulated page read failure".into()));
            }
            let page = self.inner.scan(query)?;
            if let Some(fact) = self.append_after_first.lock().take() {
                self.inner.append(fact)?;
            }
            Ok(page)
        }

        fn lookup(
            &self,
            query: crate::FactLookup,
        ) -> Result<crate::FactLookupResult, crate::FactError> {
            self.inner.lookup(query)
        }

        fn facts_of(&self, _process: ProcessId) -> Result<Vec<Fact>, crate::FactError> {
            Err(crate::FactError("unbounded process read forbidden".into()))
        }

        fn all_facts(&self) -> Result<Vec<Fact>, crate::FactError> {
            Err(crate::FactError("unbounded history read forbidden".into()))
        }

        fn cursor(&self) -> u64 {
            self.inner.cursor()
        }
    }

    struct FailingStateBackend;

    impl StateWrite for FailingStateBackend {
        type Write<'a> = core::future::Ready<StateResult<xolotl_state::StateCommit>>;

        fn mutate<'a>(&'a self, _path: &'a Path, _mutation: StateMutation) -> Self::Write<'a> {
            core::future::ready(Err(
                StateError::Backend("simulated state failure".into()).into()
            ))
        }
    }

    fn fact(pos: u32, replay: ReplayClass, complete: bool) -> Fact {
        Fact {
            id: OperationId::new(
                ProcessId::new(1),
                ExecutionId::FIRST,
                InvocationId::new(u64::from(pos) + 1),
                NodeId::new(pos),
                0,
            ),
            schema_version: Fact::SCHEMA_VERSION,
            caller: ProcessId::new(1),
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(1),
            method: MethodId::new(0),
            input: Value::null(),
            taint: xolotl_types::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome: if complete {
                Some(Value::integer(1))
            } else {
                None
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

    #[tokio::test]
    async fn recovery_pages_all_callers_and_excludes_new_appends() -> anyhow::Result<()> {
        use crate::FactStore;

        let store = Arc::new(PagedOnlyStore::new());
        let mut retained = Vec::new();
        for index in 0..7 {
            let mut record = fact(index, ReplayClass::NonIdempotentEffect, index % 3 == 0);
            record.caller = ProcessId::new(u64::from(index % 2) + 1);
            if index == 2 {
                record.replay = ReplayClass::IdempotentEffect;
            }
            if index == 6 {
                record.schema_version = Fact::SCHEMA_VERSION + 1;
            }
            store.append(record.clone())?;
            retained.push(record);
        }
        let later = fact(7, ReplayClass::NonIdempotentEffect, false);
        *store.append_after_first.lock() = Some(later.clone());
        let sink = FactSink::new(store.clone());
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let limits = RecoveryLimits {
            page_limit: NonZeroUsize::new(2).context("page limit")?,
            ..RecoveryLimits::default()
        };
        let (expected, entries) = classify_recovery(&retained);
        let report = recover_all_persisting_with_limits(&sink, &state, limits).await?;
        ensure!(report == expected);
        for entry in entries {
            let path = quarantine_path(entry.fact.caller, entry.fact.id)?;
            ensure!(state.read(&path).await? == Some(quarantine_entry_value(&entry)));
        }
        ensure!(
            state
                .read(&quarantine_path(later.caller, later.id)?)
                .await?
                .is_none()
        );
        let queries = store.queries.lock();
        ensure!(queries.len() == 4 && queries[0].before.is_none());
        ensure!(queries[1..].iter().all(|q| q.before == Some(7)));
        ensure!(
            queries
                .iter()
                .all(|q| q.limit == limits.page_limit && q.process.is_none())
        );
        Ok(())
    }

    #[tokio::test]
    async fn process_recovery_filters_before_charging_oversized_unrelated_fact()
    -> anyhow::Result<()> {
        use crate::FactStore;

        let store = Arc::new(PagedOnlyStore::new());
        let target = fact(0, ReplayClass::NonIdempotentEffect, false);
        let mut unrelated = fact(1, ReplayClass::NonIdempotentEffect, false);
        unrelated.caller = ProcessId::new(2);
        unrelated.input = Value::string("payload".repeat(4096));
        store.append(unrelated)?;
        store.append(target.clone())?;
        let size = serde_json::to_vec(&target)?.len();
        let sink = FactSink::new(store.clone());
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let limits = RecoveryLimits {
            page_limit: NonZeroUsize::MIN,
            max_encoded_bytes: NonZeroUsize::new(size).context("encoded budget")?,
        };
        let report =
            recover_process_persisting_with_limits(&sink, &state, ProcessId::new(1), limits)
                .await?;
        ensure!(report.quarantined == 1);
        ensure!(
            store
                .queries
                .lock()
                .iter()
                .all(|q| q.process == Some(ProcessId::new(1)))
        );
        Ok(())
    }

    #[tokio::test]
    async fn page_failure_propagates_after_prior_quarantine_persistence() -> anyhow::Result<()> {
        use crate::FactStore;

        let mut store = PagedOnlyStore::new();
        store.fail_from = Some(1);
        let first = fact(0, ReplayClass::NonIdempotentEffect, false);
        let second = fact(1, ReplayClass::NonIdempotentEffect, false);
        store.append(first.clone())?;
        store.append(second.clone())?;
        let sink = FactSink::new(Arc::new(store));
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let error = recover_all_persisting_with_limits(
            &sink,
            &state,
            RecoveryLimits {
                page_limit: NonZeroUsize::MIN,
                ..RecoveryLimits::default()
            },
        )
        .await
        .err()
        .context("second page must fail")?;
        ensure!(error.0.contains("simulated page read failure"));
        ensure!(
            state
                .read(&quarantine_path(first.caller, first.id)?)
                .await?
                .is_some()
        );
        ensure!(
            state
                .read(&quarantine_path(second.caller, second.id)?)
                .await?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovery_reports_oversized_record_and_accepts_explicit_larger_budget()
    -> anyhow::Result<()> {
        let (sink, _) = FactSink::in_memory();
        let record = fact(0, ReplayClass::NonIdempotentEffect, false);
        let size = serde_json::to_vec(&record)?.len();
        sink.begin(record.clone())?;
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let mut limits = RecoveryLimits {
            page_limit: NonZeroUsize::MIN,
            max_encoded_bytes: NonZeroUsize::new(size - 1).context("small budget")?,
        };
        let error = recover_all_persisting_with_limits(&sink, &state, limits)
            .await
            .err()
            .context("oversized record must fail")?;
        ensure!(error.0.contains("byte limit"));
        ensure!(
            state
                .query(&StateScan::new(Path::parse("state://quarantine")?))
                .await?
                .entries
                .is_empty()
        );
        limits.max_encoded_bytes = NonZeroUsize::new(size).context("exact budget")?;
        let report = recover_all_persisting_with_limits(&sink, &state, limits).await?;
        ensure!(report.quarantined == 1);
        Ok(())
    }

    #[tokio::test]
    async fn recovery_rejects_malformed_adapter_pages_before_persisting() -> anyhow::Result<()> {
        let pending = fact(0, ReplayClass::NonIdempotentEffect, false);
        let valid_page = crate::FactPage {
            encoded_bytes: serde_json::to_vec(&pending)?.len(),
            facts: vec![pending],
            next: Some(1),
            end: 2,
            examined: 1,
        };
        let mut wrong_caller = valid_page.clone();
        wrong_caller.facts[0].caller = ProcessId::new(2);
        let mut no_progress = valid_page.clone();
        no_progress.next = Some(0);
        let mut past_end = valid_page.clone();
        past_end.next = Some(3);
        let mut repeated_slot = valid_page.clone();
        repeated_slot.facts.push(repeated_slot.facts[0].clone());
        let mut empty_interval = valid_page.clone();
        empty_interval.next = None;
        empty_interval.end = 0;
        let mut no_encoded_bytes = valid_page;
        no_encoded_bytes.encoded_bytes = 0;
        for page in [
            wrong_caller,
            no_progress,
            past_end,
            repeated_slot,
            empty_interval,
            no_encoded_bytes,
        ] {
            let mut store = PagedOnlyStore::new();
            store.invalid_page = Some(page);
            let sink = FactSink::new(Arc::new(store));
            let state = xolotl_state::InMemoryBackend::new().into_backend();
            let error = recover_process_persisting(&sink, &state, ProcessId::new(1))
                .await
                .err()
                .context("invalid page must fail")?;
            ensure!(error.0.contains("invalid fact scan page"));
            ensure!(
                state
                    .query(&StateScan::new(Path::parse("state://quarantine")?))
                    .await?
                    .entries
                    .is_empty()
            );
        }
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
            quarantine.suggested_action == QuarantineAction::Hold,
            "unexpected quarantine action"
        );
        Ok(())
    }

    #[test]
    fn completed_call_site_does_not_hide_another_uncertain_invocation() -> anyhow::Result<()> {
        let completed = fact(0, ReplayClass::NonIdempotentEffect, true);
        let mut repeated = completed.clone();
        repeated.id.invocation = InvocationId::new(2);
        repeated.outcome = None;
        let mut independent = repeated.clone();
        independent.id.execution = ExecutionId::new(2).context("nonzero scope")?;
        let (report, quarantine) =
            classify_recovery(&[completed, repeated.clone(), independent.clone()]);

        ensure!(report.skipped == 1 && report.quarantined == 2);
        ensure!(quarantine[0].fact == repeated);
        ensure!(quarantine[1].fact == independent);
        ensure!(
            quarantine_path(repeated.id.process, repeated.id)?
                != quarantine_path(independent.id.process, independent.id)?
        );
        independent.id.execution = repeated.id.execution;
        independent.id.invocation = InvocationId::new(3);
        ensure!(
            quarantine_path(repeated.id.process, repeated.id)?
                != quarantine_path(independent.id.process, independent.id)?
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovery_persists_structured_quarantine_entry() -> anyhow::Result<()> {
        let (sink, _) = FactSink::in_memory();
        let pending = fact(0, ReplayClass::NonIdempotentEffect, false);
        sink.begin(pending.clone())?;
        let state = xolotl_state::InMemoryBackend::new().into_backend();

        let report = recover_process_persisting(&sink, &state, ProcessId::new(1)).await?;

        ensure!(report.quarantined == 1, "unexpected report: {report:?}");
        let path = quarantine_path(ProcessId::new(1), pending.id)?;
        let value = state
            .read(&path)
            .await?
            .context("missing persisted quarantine entry")?;
        let root = value.as_map().context("quarantine entry must be a map")?;
        ensure!(
            root.get("suggested_action") == Some(&Value::string("manual_complete".into())),
            "unexpected suggested action: {root:?}"
        );
        ensure!(
            root.get("pending") == Some(&Value::boolean(true)),
            "quarantine entry should mark pending fact"
        );
        let fact = root
            .get("fact")
            .and_then(Value::as_map)
            .context("quarantine entry missing structured fact")?;
        ensure!(
            fact.get("replay") == Some(&Value::string("non_idempotent_effect".into())),
            "unexpected replay field: {fact:?}"
        );
        ensure!(
            !fact.contains_key("outcome"),
            "pending fact must not contain a completed outcome: {fact:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovery_returns_error_when_quarantine_state_write_fails() -> anyhow::Result<()> {
        let (sink, _) = FactSink::in_memory();
        sink.begin(fact(0, ReplayClass::NonIdempotentEffect, false))?;
        let state = xolotl_state::Backend::new().with_write(Arc::new(FailingStateBackend));

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

    #[tokio::test]
    async fn bootstrap_recovery_keeps_uncertain_effects_visible_after_process_reap()
    -> anyhow::Result<()> {
        let boot = crate::Bootstrap::in_memory();
        let request = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
        let process = request.id();
        let mut pending = fact(0, ReplayClass::NonIdempotentEffect, false);
        pending.caller = process;
        pending.id.process = process;
        pending.id.execution = boot.kernel.execution_ids().allocate()?;
        boot.kernel.facts.begin(pending.clone())?;
        request
            .finish(&xolotl_types::ExecutionOutput::new(
                xolotl_types::Outcome::Done(Value::null()),
                xolotl_types::TaintSet::pristine(),
            ))
            .await?;
        ensure!(boot.kernel.processes.reap_finalized(1) == 1);
        ensure!(boot.kernel.processes.status(process).is_none());

        let report = boot.recover_all().await?;
        ensure!(report.quarantined == 1 && report.skipped == 1);
        let path = quarantine_path(process, pending.id)?;
        let entry = QuarantineEntry {
            fact: pending,
            suggested_action: QuarantineAction::ManualComplete,
        };
        ensure!(boot.kernel.state.read(&path).await? == Some(quarantine_entry_value(&entry)));
        Ok(())
    }

    #[tokio::test]
    async fn fresh_kernel_recovers_all_retained_fact_owners_without_process_entries()
    -> anyhow::Result<()> {
        let (facts, _) = FactSink::in_memory();
        let mut pending = fact(0, ReplayClass::NonIdempotentEffect, false);
        pending.caller = ProcessId::new(41);
        pending.id.process = pending.caller;
        let mut unsupported = fact(1, ReplayClass::Deterministic, true);
        unsupported.caller = ProcessId::new(73);
        unsupported.id.process = unsupported.caller;
        unsupported.schema_version += 1;
        let mut retryable = fact(2, ReplayClass::IdempotentEffect, false);
        retryable.caller = ProcessId::new(99);
        retryable.id.process = retryable.caller;
        facts.begin(pending.clone())?;
        facts.store().complete(unsupported.clone())?;
        facts.begin(retryable)?;
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let boot = crate::Bootstrap::from_kernel(crate::Kernel::with_backends(state, facts));
        ensure!(boot.kernel.processes.all_ids() == [boot.root]);

        let report = boot.recover_all().await?;
        ensure!(
            report
                == RecoveryReport {
                    skipped: 0,
                    retried: 1,
                    quarantined: 2,
                    schema_mismatched: 1,
                }
        );
        for (fact, suggested_action) in [
            (pending, QuarantineAction::ManualComplete),
            (unsupported, QuarantineAction::Hold),
        ] {
            let path = quarantine_path(fact.caller, fact.id)?;
            let entry = QuarantineEntry {
                fact,
                suggested_action,
            };
            ensure!(boot.kernel.state.read(&path).await? == Some(quarantine_entry_value(&entry)));
        }
        ensure!(boot.kernel.processes.len() == 1);
        Ok(())
    }
}
