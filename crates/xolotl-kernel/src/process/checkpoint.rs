//! Durable process state and checkpoint admission.
//!
//! Storage and authority checks belong to the host. This module owns lifecycle
//! reconciliation: plan without mutation, then apply under the same table lock.

use super::{Finalization, ProcessAdmissionError, ProcessEntry, ProcessTable, ProcessTableInner};
use serde::{Deserialize, Serialize};
use xolotl_types::{
    BudgetSpec, BudgetState, ExecutionId, Fact, Grant, IdentityRef, ProcessId, ProcessStatus,
};

#[cfg(test)]
mod tests;

/// Process authority and accounting captured with the interpreter state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    /// Stable owner of operation identifiers and checkpoints.
    pub id: ProcessId,
    /// Retained scope for stable lifecycle records after restart.
    pub lifecycle_execution: ExecutionId,
    /// Authority ceiling for restart admission.
    pub parent: Option<ProcessId>,
    /// Identity under which this request was admitted.
    pub identity: IdentityRef,
    /// Request grants that must still fit the parent's authority after restart.
    pub grants: Vec<Grant>,
    /// Last observed lifecycle state.
    pub status: ProcessStatus,
    /// Chosen terminal outcome while lifecycle publication is still in progress.
    /// `Finalizing` alone does not identify an outcome.
    pub terminal_intent: Option<ProcessStatus>,
    /// Conservatively retained spending, including estimates for uncertain requests.
    pub budget: BudgetState,
    /// Resource spending limits.
    pub budget_spec: BudgetSpec,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeasedRequestState {
    Ready,
    Cleanup(ProcessStatus),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CheckpointState {
    None,
    Creating,
    Active,
    Retired,
}

pub(crate) struct RetainedFinalization {
    pub fact: Fact,
    pub status: ProcessStatus,
    pub released: usize,
    pub revoked: usize,
}

#[derive(Clone, Copy)]
enum RestoreMode {
    Import,
    Leased,
}

/// Resolve explicit lifecycle decisions; an older running snapshot cannot undo cleanup.
fn restored_terminal_status(
    saved: &ProcessSnapshot,
    finalized: Option<&RetainedFinalization>,
    existing: Option<&ProcessEntry>,
) -> Result<Option<ProcessStatus>, ProcessAdmissionError> {
    crate::scope::reconcile_terminal(
        [
            saved.status.is_terminal().then_some(saved.status),
            saved.terminal_intent,
            finalized.map(|record| record.status),
            existing.and_then(|entry| {
                entry
                    .scope
                    .status()
                    .is_terminal()
                    .then_some(entry.scope.status())
            }),
            existing.and_then(|entry| entry.scope.terminal_intent()),
        ]
        .into_iter()
        .flatten(),
    )
    .map_err(|_error| ProcessAdmissionError::CheckpointMismatch { process: saved.id })
}

impl ProcessTableInner {
    fn plan_checkpoint_restore(
        &self,
        saved: &ProcessSnapshot,
        finalized: Option<&RetainedFinalization>,
        mode: RestoreMode,
    ) -> Result<LeasedRequestState, ProcessAdmissionError> {
        if finalized.is_some_and(|record| record.released.checked_add(record.revoked).is_none()) {
            return Err(ProcessAdmissionError::CheckpointMismatch { process: saved.id });
        }
        if self.recovery_closed && matches!(mode, RestoreMode::Import) {
            return Err(ProcessAdmissionError::RecoveryClosed);
        }
        let existing = self.procs.get(&saved.id);
        if let Some(entry) = existing {
            if matches!(mode, RestoreMode::Import)
                || self.tasks.contains_key(&saved.id)
                || entry.scope.finalizer_active()
            {
                return Err(ProcessAdmissionError::Occupied { process: saved.id });
            }
            if entry.checkpoint == CheckpointState::Retired || entry.scope.finalized() {
                return Err(ProcessAdmissionError::CheckpointRetired { process: saved.id });
            }
            if entry.checkpoint == CheckpointState::None
                || entry.parent != saved.parent
                || entry.scope.identity() != saved.identity
                || entry.scope.lifecycle_execution() != Some(saved.lifecycle_execution)
                || entry.scope.budget_spec() != &saved.budget_spec
                || entry.attached_grants != saved.grants
                || !entry.on_finalize.is_empty()
                || entry.publication.is_some()
            {
                return Err(ProcessAdmissionError::CheckpointMismatch { process: saved.id });
            }
            if let Some(record) = finalized
                && entry
                    .finalization
                    .as_ref()
                    .and_then(|state| state.record.as_ref())
                    .is_some_and(|(fact, closed)| {
                        fact != &record.fact || *closed != record.released + record.revoked
                    })
            {
                return Err(ProcessAdmissionError::CheckpointMismatch { process: saved.id });
            }
        } else {
            self.check_child_admission(saved.id, saved.parent)?;
        }

        if let Some(status) = restored_terminal_status(saved, finalized, existing)? {
            return Ok(LeasedRequestState::Cleanup(status));
        }
        if saved.status == ProcessStatus::Finalizing
            || existing.is_some_and(|entry| !entry.accepts_children())
        {
            return Err(ProcessAdmissionError::CheckpointMismatch { process: saved.id });
        }
        if !saved
            .parent
            .and_then(|parent| self.procs.get(&parent))
            .is_some_and(ProcessEntry::accepts_children)
        {
            return Err(ProcessAdmissionError::Unavailable {
                process: saved.parent.unwrap_or(saved.id),
            });
        }
        Ok(LeasedRequestState::Ready)
    }
}

impl ProcessEntry {
    fn apply_checkpoint_restore(
        &mut self,
        state: LeasedRequestState,
        finalized: Option<RetainedFinalization>,
    ) -> Result<(), ProcessAdmissionError> {
        if let LeasedRequestState::Cleanup(status) = state {
            self.scope.resume_cleanup(status).map_err(|_error| {
                ProcessAdmissionError::CheckpointMismatch {
                    process: self.scope.process(),
                }
            })?;
            let finalization = self
                .finalization
                .get_or_insert_with(|| Box::new(Finalization::new()));
            if let Some(record) = finalized {
                finalization.released = finalization.released.max(record.released);
                finalization.revoked = finalization.revoked.max(record.revoked);
                if finalization.record.is_none() {
                    finalization.record = Some((record.fact, record.released + record.revoked));
                }
            }
        }
        self.checkpoint = CheckpointState::Active;
        Ok(())
    }
}

impl ProcessTable {
    pub(crate) fn snapshot(&self, id: ProcessId) -> Option<ProcessSnapshot> {
        let inner = self.inner.state.read();
        let entry = inner.procs.get(&id)?;
        let parent = inner.procs.get(&entry.parent?)?;
        if parent.parent.is_some() || !entry.on_finalize.is_empty() || entry.publication.is_some() {
            return None;
        }
        Some(ProcessSnapshot {
            id,
            lifecycle_execution: entry.scope.lifecycle_execution()?,
            parent: entry.parent,
            identity: entry.scope.identity(),
            grants: entry.attached_grants.clone(),
            status: entry.scope.status(),
            terminal_intent: entry.scope.terminal_intent(),
            budget: entry.scope.budget().clone(),
            budget_spec: entry.scope.budget_spec().clone(),
        })
    }

    pub(crate) fn reserve_ids_through(&self, id: ProcessId) {
        let mut inner = self.inner.state.write();
        inner.next = inner.next.max(id.get());
    }

    pub(crate) fn checkpoint_required(&self, id: ProcessId) -> Option<bool> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)
            .map(|entry| entry.checkpoint != CheckpointState::None)
    }

    pub(crate) fn checkpoint_committed(&self, id: ProcessId) -> Option<bool> {
        self.inner.state.read().procs.get(&id).map(|entry| {
            matches!(
                entry.checkpoint,
                CheckpointState::Active | CheckpointState::Retired
            )
        })
    }

    pub(crate) fn checkpoint_retired(&self, id: ProcessId) -> Option<bool> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)
            .map(|entry| entry.checkpoint == CheckpointState::Retired)
    }

    /// Pin this lifecycle to its journal, including after that journal is retired.
    pub(crate) fn require_checkpoint(
        &self,
        id: ProcessId,
        lifecycle: ExecutionId,
    ) -> Result<(), ProcessAdmissionError> {
        let mut inner = self.inner.state.write();
        let entry = inner
            .procs
            .get_mut(&id)
            .ok_or(ProcessAdmissionError::Unavailable { process: id })?;
        if entry.scope.lifecycle_execution() != Some(lifecycle) {
            return Err(ProcessAdmissionError::CheckpointMismatch { process: id });
        }
        if entry.checkpoint == CheckpointState::Retired {
            return Err(ProcessAdmissionError::CheckpointRetired { process: id });
        }
        if entry.scope.finalized() {
            return Err(ProcessAdmissionError::Unavailable { process: id });
        }
        if entry.checkpoint == CheckpointState::None {
            entry.checkpoint = CheckpointState::Creating;
        }
        Ok(())
    }

    /// Confirm that the leased journal was loaded or its first write committed.
    pub(crate) fn confirm_checkpoint(
        &self,
        id: ProcessId,
        lifecycle: ExecutionId,
    ) -> Result<(), ProcessAdmissionError> {
        let mut inner = self.inner.state.write();
        let entry = inner
            .procs
            .get_mut(&id)
            .ok_or(ProcessAdmissionError::Unavailable { process: id })?;
        if entry.scope.lifecycle_execution() != Some(lifecycle) {
            return Err(ProcessAdmissionError::CheckpointMismatch { process: id });
        }
        if entry.checkpoint == CheckpointState::Retired {
            return Err(ProcessAdmissionError::CheckpointRetired { process: id });
        }
        if entry.checkpoint == CheckpointState::None || entry.scope.finalized() {
            return Err(ProcessAdmissionError::Unavailable { process: id });
        }
        entry.checkpoint = CheckpointState::Active;
        Ok(())
    }

    /// The caller must durably retire the matching journal while holding its lease.
    pub(crate) fn retire_checkpoint(
        &self,
        id: ProcessId,
        lifecycle: ExecutionId,
    ) -> Result<(), ProcessAdmissionError> {
        let mut inner = self.inner.state.write();
        let entry = inner
            .procs
            .get_mut(&id)
            .ok_or(ProcessAdmissionError::Unavailable { process: id })?;
        if entry.scope.lifecycle_execution() != Some(lifecycle) {
            return Err(ProcessAdmissionError::CheckpointMismatch { process: id });
        }
        if entry.checkpoint == CheckpointState::None
            || !entry.scope.status().is_terminal()
            || (entry.checkpoint != CheckpointState::Retired
                && entry
                    .finalization
                    .as_ref()
                    .and_then(|state| state.record.as_ref())
                    .is_none())
        {
            return Err(ProcessAdmissionError::Unavailable { process: id });
        }
        entry.checkpoint = CheckpointState::Retired;
        Ok(())
    }

    /// Preview lifecycle admission before checking machine imports. The result is
    /// advisory: actual admission recomputes it under the lock that applies it.
    pub(crate) fn checkpoint_recovery_state(
        &self,
        saved: &ProcessSnapshot,
        finalized: Option<&RetainedFinalization>,
    ) -> Result<LeasedRequestState, ProcessAdmissionError> {
        self.inner
            .state
            .read()
            .plan_checkpoint_restore(saved, finalized, RestoreMode::Leased)
    }

    pub(crate) fn restore_request(
        &self,
        saved: &ProcessSnapshot,
        finalized: Option<RetainedFinalization>,
    ) -> Result<(), ProcessAdmissionError> {
        self.restore_request_inner(saved, finalized, RestoreMode::Import)
            .map(|_state| ())
    }

    /// Re-admit only a row loaded under a lease retained through execution and cleanup.
    /// Unlike arbitrary snapshot import, this path can continue after earlier rows
    /// were retired and reaped. Failed task attachment leaves the entry retryable.
    pub(crate) fn restore_leased_request(
        &self,
        saved: &ProcessSnapshot,
        finalized: Option<RetainedFinalization>,
    ) -> Result<LeasedRequestState, ProcessAdmissionError> {
        self.restore_request_inner(saved, finalized, RestoreMode::Leased)
    }

    fn restore_request_inner(
        &self,
        saved: &ProcessSnapshot,
        finalized: Option<RetainedFinalization>,
        mode: RestoreMode,
    ) -> Result<LeasedRequestState, ProcessAdmissionError> {
        let mut inner = self.inner.state.write();
        let state = inner.plan_checkpoint_restore(saved, finalized.as_ref(), mode)?;
        // Nothing below can reject admission or replace retained cleanup progress.
        let removed = if let Some(entry) = inner.procs.get_mut(&saved.id) {
            entry.apply_checkpoint_restore(state, finalized)?;
            None
        } else {
            let mut entry = ProcessEntry::new(saved.id, saved.parent, saved.identity);
            entry.scope.initialize_lifecycle(saved.lifecycle_execution);
            let terminal = match state {
                LeasedRequestState::Ready => None,
                LeasedRequestState::Cleanup(status) => Some(status),
            };
            entry
                .scope
                .restore_lifecycle(saved.status, terminal)
                .map_err(|_error| ProcessAdmissionError::CheckpointMismatch {
                    process: saved.id,
                })?;
            entry.attached_grants = saved.grants.clone();
            *entry.scope.budget_mut() = saved.budget.clone();
            // Lost futures no longer hold inflight slots. Retain spending conservatively.
            entry.scope.budget_mut().inflight_ops = 0;
            entry.scope.set_budget_spec(saved.budget_spec.clone());
            entry.apply_checkpoint_restore(state, finalized)?;
            inner.next = inner.next.max(saved.id.get());
            for grant in &entry.attached_grants {
                inner.next_attached_grant = inner
                    .next_attached_grant
                    .max(grant.id.get() & !(1u64 << 63));
            }
            inner.link_entry(entry)
        };
        drop(inner);
        drop(removed);
        self.inner.changed.notify_waiters();
        Ok(state)
    }
}
