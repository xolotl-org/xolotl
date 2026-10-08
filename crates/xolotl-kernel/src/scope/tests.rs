use super::*;

fn scope() -> Scope {
    Scope::new(ProcessId::new(2), IdentityRef::ROOT)
}

#[test]
fn completion_preserves_local_cleanup_and_retains_the_attempt_until_release() {
    let mut owner = scope();
    assert!(owner.start());
    assert!(owner.finish_body(ProcessStatus::Completed));
    assert_eq!(owner.cleanup_scope(), Some(CleanupScope::Local));
    assert!(!owner.cancel() && !owner.accepts_children());
    assert_eq!(
        owner.begin_finalizing(ProcessStatus::Failed),
        ScopeFinalize::Started
    );
    assert_eq!(owner.terminal_intent(), Some(ProcessStatus::Completed));
    assert_eq!(
        owner.begin_finalizing(ProcessStatus::Completed),
        ScopeFinalize::AlreadyFinalizing
    );
    assert!(!owner.complete_finalization());
    assert_eq!(
        owner.mark_terminal_status(ProcessStatus::Failed),
        ProcessStatus::Completed
    );
    assert!(owner.complete_finalization());
    assert!(owner.finalized() && owner.finalizer_active());
    assert_eq!(owner.cleanup_scope(), Some(CleanupScope::Local));
    owner.release_finalizing();
    assert!(!owner.finalizer_active());
    assert_eq!(
        owner.begin_finalizing(ProcessStatus::Cancelled),
        ScopeFinalize::AlreadyTerminal
    );
}

#[test]
fn cancellation_and_tree_cleanup_cannot_be_replaced_by_a_late_body_result() {
    let mut owner = scope();
    assert!(owner.start() && owner.cancel());
    assert!(owner.request_tree_cleanup());
    assert!(owner.finish_body(ProcessStatus::Completed));
    assert_eq!(owner.terminal_intent(), Some(ProcessStatus::Cancelled));
    assert_eq!(owner.abandon(), Some(CleanupScope::Tree));
    assert_eq!(
        owner.begin_finalizing(ProcessStatus::Failed),
        ScopeFinalize::Started
    );
    owner.release_finalizing();
    assert_eq!(owner.cleanup_scope(), Some(CleanupScope::Tree));
}

#[test]
fn interrupted_normal_completion_keeps_its_cleanup_scope() {
    let mut owner = scope();
    assert!(owner.start());
    assert_eq!(
        owner.begin_finalizing(ProcessStatus::Completed),
        ScopeFinalize::Started
    );
    owner.release_finalizing();
    assert_eq!(owner.abandon(), Some(CleanupScope::Local));
    assert!(owner.request_tree_cleanup());
    assert_eq!(owner.terminal_intent(), Some(ProcessStatus::Completed));
    assert_eq!(owner.cleanup_scope(), Some(CleanupScope::Tree));
}

#[test]
fn nonterminal_finalization_requests_leave_the_owner_unchanged() {
    let mut owner = scope();
    for status in [
        ProcessStatus::Created,
        ProcessStatus::Running,
        ProcessStatus::Finalizing,
    ] {
        assert_eq!(owner.begin_finalizing(status), ScopeFinalize::InvalidStatus);
        assert_eq!(owner.status(), ProcessStatus::Created);
        assert_eq!(owner.terminal_intent(), None);
        assert_eq!(owner.cleanup_scope(), None);
        assert!(!owner.finalizer_active());
        assert!(owner.accepts_children());
    }
    assert!(owner.start());
    assert_eq!(
        owner.begin_finalizing(ProcessStatus::Running),
        ScopeFinalize::InvalidStatus
    );
    assert_eq!(owner.status(), ProcessStatus::Running);
    assert!(owner.accepts_children());
}

#[test]
fn call_admission_counts_free_operations_and_requires_a_running_owner() {
    let mut owner = scope();
    owner.set_budget_spec(BudgetSpec {
        max_inflight_ops: Some(1),
        ..BudgetSpec::default()
    });
    assert!(owner.reserve(0, 0).is_err());
    assert!(owner.reserve_finalizer(0, 0).is_err());
    assert!(owner.start());
    assert!(owner.reserve(0, 0).is_ok());
    let reserved = owner.budget().clone();
    assert!(owner.reserve(0, 0).is_err());
    assert_eq!(owner.budget(), &reserved);
    owner.settle(0, 0, 0, 0);
    assert_eq!(owner.budget().inflight_ops, 0);
    assert_eq!(
        owner.begin_finalizing(ProcessStatus::Completed),
        ScopeFinalize::Started
    );
    assert!(owner.reserve(0, 0).is_err());
    assert!(owner.reserve_finalizer(0, 0).is_ok());
    owner.release_finalizing();
    assert!(owner.reserve_finalizer(0, 0).is_err());
}

#[test]
fn an_accounting_window_cannot_overflow_its_representable_counters() {
    let mut owner = scope();
    assert!(owner.start());
    for counter in 0..3 {
        *owner.budget_mut() = BudgetState::default();
        match counter {
            0 => owner.budget_mut().inflight_ops = u32::MAX,
            1 => owner.budget_mut().spent_micro_usd = u64::MAX,
            _ => owner.budget_mut().inference_tokens = u64::MAX,
        }
        let before = owner.budget().clone();
        assert!(owner.reserve(1, 1).is_err());
        assert_eq!(owner.budget(), &before);
    }
}

#[test]
fn trusted_machine_cleanup_ends_at_lifecycle_commit() {
    let mut owner = scope();
    assert!(owner.reserve_cleanup(0, 0).is_err());
    assert!(owner.start() && owner.cancel());
    assert!(owner.reserve(0, 0).is_err());
    assert!(owner.reserve_cleanup(0, 0).is_ok());
    owner.settle(0, 0, 0, 0);
    assert!(owner.complete_finalization());
    assert!(owner.reserve_cleanup(0, 0).is_err());

    for status in [ProcessStatus::Completed, ProcessStatus::Failed] {
        let mut owner = scope();
        owner.mark_terminal_status(status);
        assert!(owner.reserve_cleanup(0, 0).is_err());
    }
}

#[test]
fn cooperative_cancellation_does_not_select_cleanup() -> anyhow::Result<()> {
    let mut owner = scope();
    anyhow::ensure!(owner.start() && owner.cancel());
    anyhow::ensure!(owner.status() == ProcessStatus::Cancelled);
    anyhow::ensure!(owner.terminal_intent().is_none());
    anyhow::ensure!(owner.cleanup_scope().is_none());
    anyhow::ensure!(owner.abandon() == Some(CleanupScope::Tree));

    Ok(())
}

#[test]
fn completed_scope_keeps_tree_selection_without_reopening_its_lifecycle() {
    let mut owner = scope();
    assert!(owner.start());
    assert_eq!(
        owner.begin_finalizing(ProcessStatus::Completed),
        ScopeFinalize::Started
    );
    assert!(owner.request_tree_cleanup());
    assert_eq!(
        owner.mark_terminal_status(ProcessStatus::Completed),
        ProcessStatus::Completed
    );
    assert!(owner.complete_finalization());
    owner.release_finalizing();
    assert!(owner.finalized());
    assert_eq!(owner.cleanup_scope(), Some(CleanupScope::Tree));
    assert_eq!(owner.terminal_intent(), None);
    assert_eq!(
        owner.begin_finalizing(ProcessStatus::Cancelled),
        ScopeFinalize::AlreadyTerminal
    );
    assert!(!owner.finish_body(ProcessStatus::Failed));
    assert!(!owner.cancel() && !owner.start() && !owner.accepts_children());
    assert_eq!(owner.status(), ProcessStatus::Completed);
    assert_eq!(owner.cleanup_scope(), Some(CleanupScope::Tree));
    assert_eq!(owner.abandon(), None);
}

#[test]
fn completed_local_scope_can_select_tree_for_surviving_descendants() {
    let mut owner = scope();
    owner.mark_terminal_status(ProcessStatus::Completed);
    assert!(owner.complete_finalization());
    assert_eq!(owner.cleanup_scope(), Some(CleanupScope::Local));
    assert!(!owner.request_tree_cleanup());
    assert_eq!(owner.cleanup_scope(), Some(CleanupScope::Tree));
    assert!(owner.finalized());
    assert_eq!(owner.status(), ProcessStatus::Completed);
    assert_eq!(owner.terminal_intent(), None);
}
