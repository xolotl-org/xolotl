//! Durable process admission, lifecycle transitions and retention barriers.

use super::*;
use crate::process::FinalizeStart;
use anyhow::{Context, ensure};
use std::num::NonZeroUsize;
use std::sync::{Arc, Barrier};
use xolotl_types::IdentityRef;

fn child(table: &ProcessTable, parent: ProcessId) -> anyhow::Result<ProcessId> {
    let id = table.fresh_id()?;
    table.admit_child(ProcessEntry::new(id, Some(parent), IdentityRef::ROOT))?;
    Ok(id)
}

fn finish(table: &ProcessTable, id: ProcessId) -> anyhow::Result<()> {
    ensure!(table.begin_finalizing(id, ProcessStatus::Completed) == FinalizeStart::Started);
    let guard = table.finalization_guard(id);
    table
        .mark_terminal_status(id, ProcessStatus::Completed)
        .context("missing process")?;
    if table.checkpoint_required(id) == Some(true) {
        let execution = table.lifecycle_execution(id).context("missing lifecycle")?;
        table
            .retain_finalization_record(id, retirement_record(id, execution), 0)
            .context("missing finalization")?;
        table.retire_checkpoint(id, execution)?;
    }
    table.complete_finalization(id).context("missing process")?;
    drop(guard);
    Ok(())
}

fn retirement_record(
    process: ProcessId,
    execution: xolotl_types::ExecutionId,
) -> xolotl_types::Fact {
    xolotl_types::Fact {
        id: xolotl_types::OperationId::new(
            process,
            execution,
            xolotl_types::InvocationId::new(0),
            xolotl_types::NodeId::new(u32::MAX),
            0,
        ),
        schema_version: xolotl_types::Fact::SCHEMA_VERSION,
        caller: process,
        acting: IdentityRef::ROOT,
        handle: xolotl_types::HandleId::new(0, 0),
        resource: xolotl_types::ResourceId::new(0),
        method: xolotl_types::MethodId::new(0),
        input: xolotl_types::Value::null(),
        taint: xolotl_types::TaintSet::pristine(),
        decision: xolotl_types::DecisionTag::Ok,
        outcome: Some(xolotl_types::Value::map(std::collections::BTreeMap::from(
            [
                (
                    "event".into(),
                    xolotl_types::Value::string("ProcessFinalized".into()),
                ),
                (
                    "status".into(),
                    xolotl_types::Value::string("completed".into()),
                ),
                ("revoked_handles".into(), xolotl_types::Value::integer(0)),
                ("released_handles".into(), xolotl_types::Value::integer(0)),
            ],
        ))),
        batch: None,
        replay: xolotl_types::ReplayClass::Observation,
        timestamp: xolotl_types::Timestamp::millis(0),
    }
}

fn saved_request(id: u64) -> ProcessSnapshot {
    ProcessSnapshot {
        id: ProcessId::new(id),
        lifecycle_execution: xolotl_types::ExecutionId::FIRST,
        parent: Some(ProcessId::new(1)),
        identity: IdentityRef::ROOT,
        grants: Vec::new(),
        status: ProcessStatus::Running,
        terminal_intent: None,
        budget: xolotl_types::BudgetState::default(),
        budget_spec: xolotl_types::BudgetSpec::default(),
    }
}

#[test]
fn rejected_lifecycle_records_preserve_terminal_state_and_cleanup_progress() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    table.initialize_root(|_| {});
    let mut saved = saved_request(10);
    table.restore_leased_request(&saved, None)?;
    ensure!(table.begin_finalizing(saved.id, ProcessStatus::Completed) == FinalizeStart::Started);
    let guard = table.finalization_guard(saved.id);
    table.mark_terminal_status(saved.id, ProcessStatus::Completed);
    let fact = retirement_record(saved.id, saved.lifecycle_execution);
    table.retain_finalization_record(saved.id, fact.clone(), 3);
    table.record_revocation(saved.id, 5);
    drop(guard);
    table.request_cleanup_tree(saved.id);
    saved.terminal_intent = Some(ProcessStatus::Completed);
    let before = serde_json::to_value(table.snapshot(saved.id))?;

    for conflict in 0..3 {
        let mut finalized = RetainedFinalization {
            fact: fact.clone(),
            status: ProcessStatus::Completed,
            released: 0,
            revoked: 3,
        };
        match conflict {
            0 => finalized.fact.timestamp = xolotl_types::Timestamp::millis(1),
            1 => finalized.revoked = 4,
            _ => finalized.status = ProcessStatus::Failed,
        }
        ensure!(
            table.restore_leased_request(&saved, Some(finalized))
                == Err(ProcessAdmissionError::CheckpointMismatch { process: saved.id })
        );
        ensure!(serde_json::to_value(table.snapshot(saved.id))? == before);
        ensure!(table.finalization_record(saved.id) == Some((fact.clone(), 3)));
        let inner = table.inner.state.read();
        let entry = inner.procs.get(&saved.id).context("missing process")?;
        ensure!(entry.scope.status() == ProcessStatus::Completed);
        ensure!(entry.checkpoint == CheckpointState::Active);
        ensure!(entry.scope.cleanup_scope() == Some(crate::CleanupScope::Tree));
        ensure!(!entry.scope.finalized() && !entry.scope.finalizer_active());
        ensure!(
            entry
                .finalization
                .as_ref()
                .context("missing cleanup")?
                .revoked
                == 5
        );
    }
    Ok(())
}

#[test]
fn conflicting_or_unknown_lifecycle_decisions_fail_for_imports_and_leased_retries()
-> anyhow::Result<()> {
    use ProcessStatus::{Cancelled, Completed, Finalizing, Running};
    let cases = [
        (Cancelled, Some(Completed), None),
        (Completed, Some(Cancelled), None),
        (Running, Some(Running), None),
        (Running, None, Some(Running)),
        (Cancelled, None, Some(Completed)),
        (Running, Some(Cancelled), Some(Completed)),
        (Finalizing, None, None),
    ];
    for (status, terminal_intent, committed) in cases {
        for (existing, mode) in [
            (false, RestoreMode::Import),
            (false, RestoreMode::Leased),
            (true, RestoreMode::Leased),
        ] {
            let table = ProcessTable::new();
            let root = table.initialize_root(|_| {});
            let mut saved = saved_request(10);
            if existing {
                table.restore_leased_request(&saved, None)?;
            }
            let before = serde_json::to_value(table.snapshot(saved.id))?;
            let children = table.children_of(root);
            let next = table.inner.state.read().next;
            saved.status = status;
            saved.terminal_intent = terminal_intent;
            let finalized = committed.map(|status| RetainedFinalization {
                fact: retirement_record(saved.id, saved.lifecycle_execution),
                status,
                released: 0,
                revoked: 0,
            });
            ensure!(
                table.checkpoint_recovery_state(&saved, finalized.as_ref())
                    == Err(ProcessAdmissionError::CheckpointMismatch { process: saved.id })
            );
            ensure!(
                table.restore_request_inner(&saved, finalized, mode)
                    == Err(ProcessAdmissionError::CheckpointMismatch { process: saved.id })
            );
            ensure!(serde_json::to_value(table.snapshot(saved.id))? == before);
            ensure!(table.children_of(root) == children);
            ensure!(table.inner.state.read().next == next);
            ensure!(table.pending_cleanup().is_empty());
        }
    }
    Ok(())
}

#[test]
fn recovery_merges_known_terminal_decisions_and_preserves_live_spending() -> anyhow::Result<()> {
    use ProcessStatus::{Cancelled, Completed, Failed, Finalizing, Running};
    let cases = [
        (Finalizing, None, Some(Completed), None, Completed),
        (Finalizing, None, None, Some(Cancelled), Cancelled),
        (Cancelled, None, None, Some(Running), Cancelled),
        (Running, None, None, Some(Failed), Failed),
        (Running, Some(Cancelled), None, None, Cancelled),
        (
            Completed,
            Some(Completed),
            Some(Completed),
            Some(Completed),
            Completed,
        ),
    ];
    for (status, terminal_intent, committed, existing, expected) in cases {
        let table = ProcessTable::new();
        table.initialize_root(|_| {});
        let mut saved = saved_request(10);
        saved.budget.spent_micro_usd = 73;
        if let Some(current) = existing {
            table.restore_leased_request(&saved, None)?;
            if current.is_terminal() {
                ensure!(table.begin_finalizing(saved.id, current) == FinalizeStart::Started);
                drop(table.finalization_guard(saved.id));
                table.request_cleanup_tree(saved.id);
            }
            table
                .inner
                .state
                .write()
                .procs
                .get_mut(&saved.id)
                .context("missing process")?
                .scope
                .budget_mut()
                .spent_micro_usd = 91;
        }
        saved.status = status;
        saved.terminal_intent = terminal_intent;
        let finalized = committed.map(|status| RetainedFinalization {
            fact: retirement_record(saved.id, saved.lifecycle_execution),
            status,
            released: 0,
            revoked: 0,
        });
        let expected_state = LeasedRequestState::Cleanup(expected);
        ensure!(table.checkpoint_recovery_state(&saved, finalized.as_ref())? == expected_state);
        ensure!(table.restore_leased_request(&saved, finalized)? == expected_state);
        ensure!(table.finalization_status(saved.id) == Some(expected));
        ensure!(child(&table, saved.id).is_err());
        let inner = table.inner.state.read();
        let entry = inner.procs.get(&saved.id).context("missing process")?;
        ensure!(entry.scope.budget().spent_micro_usd == if existing.is_some() { 91 } else { 73 });
        ensure!(entry.scope.cleanup_scope().is_some());
        if existing.is_some_and(ProcessStatus::is_terminal) {
            ensure!(entry.scope.cleanup_scope() == Some(crate::CleanupScope::Tree));
        }
    }
    Ok(())
}

#[test]
fn actual_admission_rechecks_cancellation_after_a_ready_preview() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    table.initialize_root(|_| {});
    let saved = saved_request(10);
    table.restore_leased_request(&saved, None)?;
    ensure!(table.checkpoint_recovery_state(&saved, None)? == LeasedRequestState::Ready);
    table.request_cleanup_tree(saved.id);
    ensure!(
        table.restore_leased_request(&saved, None)?
            == LeasedRequestState::Cleanup(ProcessStatus::Cancelled)
    );
    ensure!(table.finalization_status(saved.id) == Some(ProcessStatus::Cancelled));
    ensure!(child(&table, saved.id).is_err());
    Ok(())
}

#[test]
fn checkpoint_creation_can_retry_until_committed_without_releasing_cleanup() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    let root = table.initialize_root(|_| {});
    let process = child(&table, root)?;
    let lifecycle = xolotl_types::ExecutionId::FIRST;
    let different = xolotl_types::ExecutionId::new(2).context("missing alternate lifecycle")?;
    ensure!(table.initialize_lifecycle(process, lifecycle) == Some(lifecycle));
    ensure!(table.checkpoint_required(process) == Some(false));
    ensure!(table.checkpoint_committed(process) == Some(false));
    ensure!(table.checkpoint_retired(process) == Some(false));
    ensure!(
        table.confirm_checkpoint(process, lifecycle)
            == Err(ProcessAdmissionError::Unavailable { process })
    );
    ensure!(
        table.require_checkpoint(process, different)
            == Err(ProcessAdmissionError::CheckpointMismatch { process })
    );
    ensure!(table.checkpoint_required(process) == Some(false));
    for _ in 0..2 {
        table.require_checkpoint(process, lifecycle)?;
        ensure!(table.checkpoint_required(process) == Some(true));
        ensure!(table.checkpoint_committed(process) == Some(false));
        ensure!(table.complete_finalization(process).is_none());
        ensure!(table.reap_finalized(1) == 0);
    }
    ensure!(
        table.confirm_checkpoint(process, different)
            == Err(ProcessAdmissionError::CheckpointMismatch { process })
    );
    ensure!(table.checkpoint_committed(process) == Some(false));
    table.confirm_checkpoint(process, lifecycle)?;
    table.confirm_checkpoint(process, lifecycle)?;
    table.require_checkpoint(process, lifecycle)?;
    ensure!(table.checkpoint_required(process) == Some(true));
    ensure!(table.checkpoint_committed(process) == Some(true));
    ensure!(table.checkpoint_retired(process) == Some(false));
    ensure!(table.complete_finalization(process).is_none());
    Ok(())
}

#[test]
fn checkpoint_creation_can_retire_without_a_committed_payload() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    let root = table.initialize_root(|_| {});
    let process = child(&table, root)?;
    let lifecycle = xolotl_types::ExecutionId::FIRST;
    ensure!(table.initialize_lifecycle(process, lifecycle) == Some(lifecycle));
    table.require_checkpoint(process, lifecycle)?;
    ensure!(table.checkpoint_committed(process) == Some(false));
    finish(&table, process)?;
    ensure!(table.checkpoint_required(process) == Some(true));
    ensure!(table.checkpoint_committed(process) == Some(true));
    ensure!(table.checkpoint_retired(process) == Some(true));
    ensure!(
        table.confirm_checkpoint(process, lifecycle)
            == Err(ProcessAdmissionError::CheckpointRetired { process })
    );
    ensure!(table.reap_finalized(1) == 1);
    ensure!(table.checkpoint_committed(process).is_none());
    Ok(())
}

#[test]
fn leased_restore_confirms_existing_creation_without_resetting_spending() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    let root = table.initialize_root(|_| {});
    let process = child(&table, root)?;
    let lifecycle = xolotl_types::ExecutionId::FIRST;
    ensure!(table.initialize_lifecycle(process, lifecycle) == Some(lifecycle));
    let saved = table.snapshot(process).context("missing snapshot")?;
    table.require_checkpoint(process, lifecycle)?;
    table
        .inner
        .state
        .write()
        .procs
        .get_mut(&process)
        .context("missing process")?
        .scope
        .budget_mut()
        .spent_micro_usd = 73;
    ensure!(table.checkpoint_committed(process) == Some(false));
    ensure!(table.restore_leased_request(&saved, None)? == LeasedRequestState::Ready);
    ensure!(table.checkpoint_committed(process) == Some(true));
    ensure!(
        table
            .snapshot(process)
            .context("missing snapshot")?
            .budget
            .spent_micro_usd
            == 73
    );
    ensure!(table.children_of(root) == vec![process]);
    Ok(())
}

#[test]
fn checkpoint_retirement_precedes_finalization_and_keeps_the_requirement_sticky()
-> anyhow::Result<()> {
    let table = ProcessTable::new();
    table.initialize_root(|_| {});
    let saved = saved_request(10);
    table.restore_request(&saved, None)?;
    ensure!(table.checkpoint_required(saved.id) == Some(true));
    ensure!(table.checkpoint_committed(saved.id) == Some(true));
    ensure!(table.checkpoint_retired(saved.id) == Some(false));
    ensure!(table.begin_finalizing(saved.id, ProcessStatus::Completed) == FinalizeStart::Started);
    let guard = table.finalization_guard(saved.id);
    table
        .mark_terminal_status(saved.id, ProcessStatus::Completed)
        .context("missing process")?;
    ensure!(
        table
            .retire_checkpoint(saved.id, saved.lifecycle_execution)
            .is_err()
    );
    ensure!(table.complete_finalization(saved.id).is_none());
    ensure!(table.reap_finalized(1) == 0);
    ensure!(table.finalization_status(saved.id) == Some(ProcessStatus::Completed));
    table
        .retain_finalization_record(
            saved.id,
            retirement_record(saved.id, saved.lifecycle_execution),
            0,
        )
        .context("missing finalization")?;
    let different = xolotl_types::ExecutionId::new(2).context("missing alternate lifecycle")?;
    ensure!(matches!(
        table.retire_checkpoint(saved.id, different),
        Err(ProcessAdmissionError::CheckpointMismatch { .. })
    ));
    table.retire_checkpoint(saved.id, saved.lifecycle_execution)?;
    ensure!(table.checkpoint_retired(saved.id) == Some(true));
    ensure!(table.checkpoint_required(saved.id) == Some(true));
    ensure!(table.checkpoint_committed(saved.id) == Some(true));
    ensure!(
        table.require_checkpoint(saved.id, saved.lifecycle_execution)
            == Err(ProcessAdmissionError::CheckpointRetired { process: saved.id })
    );
    table
        .complete_finalization(saved.id)
        .context("retirement did not release finalization")?;
    ensure!(table.reap_finalized(1) == 0);
    drop(guard);
    ensure!(
        table.restore_leased_request(&saved, None)
            == Err(ProcessAdmissionError::CheckpointRetired { process: saved.id })
    );
    ensure!(table.reap_finalized(1) == 1);
    ensure!(table.checkpoint_required(saved.id).is_none());
    Ok(())
}

#[test]
fn leased_recovery_continues_after_reap_without_reopening_snapshot_import() -> anyhow::Result<()> {
    let table = ProcessTable::with_capacity(NonZeroUsize::MIN.saturating_add(1));
    table.initialize_root(|_| {});
    let first = saved_request(10);
    ensure!(table.restore_leased_request(&first, None)? == LeasedRequestState::Ready);
    finish(&table, first.id)?;
    ensure!(table.reap_finalized(1) == 1);
    let previously_held = saved_request(9);
    ensure!(
        table.restore_request(&previously_held, None) == Err(ProcessAdmissionError::RecoveryClosed)
    );
    ensure!(table.restore_leased_request(&previously_held, None)? == LeasedRequestState::Ready);
    ensure!(table.len() == 2);
    ensure!(table.children_of(ProcessId::new(1)) == vec![previously_held.id]);
    Ok(())
}

#[test]
fn leased_retry_preserves_spending_and_cleanup_intent_and_rejects_changed_identity()
-> anyhow::Result<()> {
    let table = ProcessTable::new();
    table.initialize_root(|_| {});
    let saved = saved_request(10);
    table.restore_leased_request(&saved, None)?;
    table
        .inner
        .state
        .write()
        .procs
        .get_mut(&saved.id)
        .context("missing process")?
        .scope
        .budget_mut()
        .spent_micro_usd = 73;
    ensure!(table.restore_leased_request(&saved, None)? == LeasedRequestState::Ready);
    ensure!(
        table
            .snapshot(saved.id)
            .context("missing snapshot")?
            .budget
            .spent_micro_usd
            == 73
    );
    let mut changed = saved.clone();
    changed.identity = IdentityRef::new(2);
    ensure!(matches!(
        table.restore_leased_request(&changed, None),
        Err(ProcessAdmissionError::CheckpointMismatch { .. })
    ));
    changed = saved.clone();
    changed.lifecycle_execution =
        xolotl_types::ExecutionId::new(2).context("missing alternate lifecycle")?;
    ensure!(matches!(
        table.restore_leased_request(&changed, None),
        Err(ProcessAdmissionError::CheckpointMismatch { .. })
    ));
    ensure!(table.begin_finalizing(saved.id, ProcessStatus::Cancelled) == FinalizeStart::Started);
    let guard = table.finalization_guard(saved.id);
    ensure!(matches!(
        table.restore_leased_request(&saved, None),
        Err(ProcessAdmissionError::Occupied { .. })
    ));
    drop(guard);
    ensure!(
        table.restore_leased_request(&saved, None)?
            == LeasedRequestState::Cleanup(ProcessStatus::Cancelled)
    );
    ensure!(table.finalization_status(saved.id) == Some(ProcessStatus::Cancelled));
    ensure!(
        table
            .snapshot(saved.id)
            .context("missing snapshot")?
            .budget
            .spent_micro_usd
            == 73
    );
    ensure!(table.children_of(ProcessId::new(1)) == vec![saved.id]);
    Ok(())
}

#[test]
fn leased_retry_checks_parent_for_body_but_can_finish_existing_cleanup() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    let root = table.initialize_root(|_| {});
    let mut cleaning = saved_request(10);
    cleaning.status = ProcessStatus::Finalizing;
    cleaning.terminal_intent = Some(ProcessStatus::Cancelled);
    ensure!(
        table.restore_leased_request(&cleaning, None)?
            == LeasedRequestState::Cleanup(ProcessStatus::Cancelled)
    );
    let running = saved_request(11);
    ensure!(table.restore_leased_request(&running, None)? == LeasedRequestState::Ready);
    ensure!(table.begin_finalizing(root, ProcessStatus::Cancelled) == FinalizeStart::Started);
    let guard = table.finalization_guard(root);
    ensure!(
        table.restore_leased_request(&running, None)
            == Err(ProcessAdmissionError::Unavailable { process: root })
    );
    ensure!(
        table.restore_leased_request(&cleaning, None)?
            == LeasedRequestState::Cleanup(ProcessStatus::Cancelled)
    );
    ensure!(table.status(running.id) == Some(ProcessStatus::Running));
    drop(guard);
    Ok(())
}

#[test]
fn failed_recovery_attachment_keeps_one_retryable_entry() -> anyhow::Result<()> {
    let table = ProcessTable::with_capacity(NonZeroUsize::MIN.saturating_add(1));
    table.initialize_root(|_| {});
    let saved = saved_request(10);
    table.restore_leased_request(&saved, None)?;
    let handles = Arc::new(parking_lot::RwLock::new(crate::HandleTable::new()));
    ensure!(
        table.spawn_recovery_task(saved.id, handles, |_owner| std::future::pending())
            == Err(crate::process::TaskAttachment::NoRuntime)
    );
    ensure!(!table.has_task(saved.id));
    ensure!(table.restore_leased_request(&saved, None)? == LeasedRequestState::Ready);
    ensure!(table.len() == 2);
    ensure!(table.children_of(ProcessId::new(1)) == vec![saved.id]);
    Ok(())
}

#[test]
fn only_actual_reaping_closes_checkpoint_admission() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    let root = table.initialize_root(|_| {});
    let current = child(&table, root)?;
    ensure!(table.reap_finalized(8) == 0);
    table.restore_request(&saved_request(10), None)?;
    finish(&table, current)?;
    ensure!(table.reap_finalized(0) == 0);
    table.restore_request(&saved_request(9), None)?;
    ensure!(table.reap_finalized(1) == 1);
    ensure!(
        table.restore_request(&saved_request(current.get()), None)
            == Err(ProcessAdmissionError::RecoveryClosed)
    );
    ensure!(
        table.restore_request(&saved_request(11), None)
            == Err(ProcessAdmissionError::RecoveryClosed)
    );
    ensure!(table.status(ProcessId::new(9)) == Some(ProcessStatus::Running));
    let next = child(&table, root)?;
    ensure!(next.get() > 10);
    Ok(())
}

#[test]
fn restoration_shares_the_same_capacity_limit() -> anyhow::Result<()> {
    let table = ProcessTable::with_capacity(NonZeroUsize::MIN.saturating_add(1));
    table.initialize_root(|_| {});
    table.restore_request(&saved_request(10), None)?;
    ensure!(
        table.restore_request(&saved_request(9), None)
            == Err(ProcessAdmissionError::Capacity { limit: 2 })
    );
    ensure!(table.len() == 2);
    ensure!(!table.exists(ProcessId::new(9)));
    Ok(())
}

#[test]
fn restoration_racing_reap_cannot_recreate_the_removed_identity() -> anyhow::Result<()> {
    let table = ProcessTable::new();
    table.initialize_root(|_| {});
    let saved = saved_request(10);
    table.restore_request(&saved, None)?;
    finish(&table, saved.id)?;
    let gate = Barrier::new(2);
    std::thread::scope(|scope| -> anyhow::Result<()> {
        let reaper = scope.spawn(|| {
            gate.wait();
            table.reap_finalized(1)
        });
        let restore = scope.spawn(|| {
            gate.wait();
            table.restore_request(&saved, None)
        });
        ensure!(
            reaper
                .join()
                .map_err(|_panic| anyhow::anyhow!("reaper panicked"))?
                == 1
        );
        let result = restore
            .join()
            .map_err(|_panic| anyhow::anyhow!("restore panicked"))?;
        ensure!(matches!(
            result,
            Err(ProcessAdmissionError::Occupied { .. } | ProcessAdmissionError::RecoveryClosed)
        ));
        Ok(())
    })?;
    ensure!(table.status(saved.id).is_none());
    ensure!(table.len() == 1);
    Ok(())
}
#[test]
fn restore_rejects_closed_parent_without_linking_child() -> anyhow::Result<()> {
    let source = ProcessTable::new();
    let parent = source.fresh_id()?;
    source.insert(ProcessEntry::new(parent, None, IdentityRef::ROOT));
    let child = source.fresh_id()?;
    let mut entry = ProcessEntry::new(child, Some(parent), IdentityRef::ROOT);
    entry.scope.initialize_lifecycle(ExecutionId::FIRST);
    source.insert(entry);
    let saved = source.snapshot(child).context("missing process snapshot")?;

    let target = ProcessTable::new();
    target.insert(ProcessEntry::new(parent, None, IdentityRef::ROOT));
    target.request_cleanup_tree(parent);
    ensure!(target.restore_request(&saved, None).is_err());
    ensure!(!target.exists(child));
    ensure!(target.children_of(parent).is_empty());
    Ok(())
}
