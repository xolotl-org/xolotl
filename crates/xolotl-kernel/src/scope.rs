//! Host-independent lifecycle and accounting for one execution owner.

use alloc::string::String;
use xolotl_types::{BudgetSpec, BudgetState, ExecutionId, IdentityRef, ProcessId, ProcessStatus};

/// Authority cleanup selected by the owner, independent of its terminal result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupScope {
    /// Release local handles and preserve independently delegated descendants.
    Local,
    /// Revoke authority and stop the complete descendant tree.
    Tree,
}

/// Admission of one finalization attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeFinalize {
    /// The caller now owns finalization until it releases the attempt.
    Started,
    /// Another attempt still owns cleanup resources.
    AlreadyFinalizing,
    /// Lifecycle effects have already been committed.
    AlreadyTerminal,
    /// Finalization requires a terminal result.
    InvalidStatus,
}

/// A retained lifecycle cannot be reconstructed from inconsistent decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeRestoreError {
    /// Only a newly created scope can import an execution status.
    AlreadyStarted,
    /// A finalizing status needs a terminal intent, and all terminal choices must agree.
    InvalidTerminalIntent,
}

impl core::fmt::Display for ScopeRestoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl core::error::Error for ScopeRestoreError {}

/// Reconcile terminal evidence without mutating a live owner.
pub fn reconcile_terminal(
    choices: impl IntoIterator<Item = ProcessStatus>,
) -> Result<Option<ProcessStatus>, ScopeRestoreError> {
    let mut terminal = None;
    for choice in choices {
        if !choice.is_terminal() || terminal.is_some_and(|chosen| chosen != choice) {
            return Err(ScopeRestoreError::InvalidTerminalIntent);
        }
        terminal = Some(choice);
    }
    Ok(terminal)
}

/// Mutable state owned by one invocation scope. Scheduling, task handles,
/// finalizer programs, publications and storage are supplied by the host.
pub struct Scope {
    process: ProcessId,
    identity: IdentityRef,
    execution: Option<ExecutionId>,
    status: ProcessStatus,
    terminal: Option<ProcessStatus>,
    cleanup: Option<CleanupScope>,
    finalizer_active: bool,
    finalized: bool,
    budget: BudgetState,
    limits: BudgetSpec,
}

impl Scope {
    /// Create an unstarted owner with unbounded spending limits.
    pub fn new(process: ProcessId, identity: IdentityRef) -> Self {
        Self {
            process,
            identity,
            execution: None,
            status: ProcessStatus::Created,
            terminal: None,
            cleanup: None,
            finalizer_active: false,
            finalized: false,
            budget: BudgetState::default(),
            limits: BudgetSpec::default(),
        }
    }

    /// Stable owner of calls, capabilities and lifecycle records.
    pub fn process(&self) -> ProcessId {
        self.process
    }

    /// Identity fixed when this owner was admitted.
    pub fn identity(&self) -> IdentityRef {
        self.identity
    }

    /// Current externally observable lifecycle status.
    pub fn status(&self) -> ProcessStatus {
        self.status
    }

    /// First terminal decision retained until cleanup commits.
    pub fn terminal_intent(&self) -> Option<ProcessStatus> {
        self.terminal
    }

    /// Retained namespace for lifecycle effects.
    pub fn lifecycle_execution(&self) -> Option<ExecutionId> {
        self.execution
    }

    /// Bind the lifecycle namespace once, preserving it across retries.
    pub fn initialize_lifecycle(&mut self, execution: ExecutionId) -> ExecutionId {
        *self.execution.get_or_insert(execution)
    }

    /// Whether new child scopes or a body may be admitted.
    pub fn accepts_children(&self) -> bool {
        !self.status.is_terminal()
            && self.status != ProcessStatus::Finalizing
            && self.terminal.is_none()
            && self.cleanup.is_none()
            && !self.finalized
    }

    /// Start execution after host admission has completed.
    pub fn start(&mut self) -> bool {
        if self.status != ProcessStatus::Created || !self.accepts_children() {
            return false;
        }
        self.status = ProcessStatus::Running;
        true
    }

    /// Record a body result without replacing an earlier cancellation or completion.
    pub fn finish_body(&mut self, status: ProcessStatus) -> bool {
        if self.finalized || !status.is_terminal() {
            return false;
        }
        self.choose_terminal(status);
        self.status = ProcessStatus::Finalizing;
        self.cleanup.get_or_insert(CleanupScope::Local);
        true
    }

    /// Claim cleanup resources. The host must stop and join any attached body
    /// before running finalizer programs, and release the attempt after use.
    pub fn begin_finalizing(&mut self, status: ProcessStatus) -> ScopeFinalize {
        if !status.is_terminal() {
            return ScopeFinalize::InvalidStatus;
        }
        if self.finalized {
            return ScopeFinalize::AlreadyTerminal;
        }
        if self.finalizer_active {
            return ScopeFinalize::AlreadyFinalizing;
        }
        self.choose_terminal(status);
        self.finalizer_active = true;
        self.status = ProcessStatus::Finalizing;
        ScopeFinalize::Started
    }

    /// Release a cleanup attempt, retaining unfinished work for another host poll.
    pub fn release_finalizing(&mut self) {
        self.finalizer_active = false;
        if self.terminal.is_some() && !self.finalized {
            self.cleanup.get_or_insert(CleanupScope::Local);
        }
    }

    /// Whether a finalization attempt still owns resources, including after commit.
    pub fn finalizer_active(&self) -> bool {
        self.finalizer_active
    }

    /// Whether lifecycle effects have been fully committed.
    pub fn finalized(&self) -> bool {
        self.finalized
    }

    /// Mark the stable terminal result after its authoritative record is committed.
    pub fn mark_terminal_status(&mut self, requested: ProcessStatus) -> ProcessStatus {
        if !self.status.is_terminal() && requested.is_terminal() {
            self.status = self.terminal.unwrap_or(requested);
        }
        self.status
    }

    /// Confirm all lifecycle publications and host cleanup barriers have succeeded.
    /// The attempt owner remains active until `release_finalizing` is called.
    pub fn complete_finalization(&mut self) -> bool {
        if !self.status.is_terminal() {
            return false;
        }
        self.finalized = true;
        self.terminal = None;
        self.cleanup = None;
        true
    }

    /// Request cooperative cancellation without widening cleanup to descendants.
    pub fn cancel(&mut self) -> bool {
        if self.status.is_terminal() || self.terminal.is_some() {
            return false;
        }
        self.status = ProcessStatus::Cancelled;
        true
    }

    /// Close this scope's admission as part of an explicit tree shutdown.
    pub fn request_tree_cleanup(&mut self) -> bool {
        if self.finalized {
            return false;
        }
        if self.terminal.is_none() {
            self.status = self.choose_terminal(ProcessStatus::Cancelled);
        }
        self.cleanup = Some(CleanupScope::Tree);
        true
    }

    /// Drop ownership without widening an already chosen normal completion.
    pub fn abandon(&mut self) -> Option<CleanupScope> {
        if self.finalized {
            return None;
        }
        if self.terminal.is_some() && self.cleanup != Some(CleanupScope::Tree) {
            self.cleanup = Some(CleanupScope::Local);
        } else {
            self.request_tree_cleanup();
        }
        self.cleanup
    }

    /// Pending cleanup selected by the owner. An actively owned attempt need not be queued.
    pub fn cleanup_scope(&self) -> Option<CleanupScope> {
        self.cleanup
    }

    /// Restore lifecycle decisions into a fresh scope without restoring a live task owner.
    pub fn restore_lifecycle(
        &mut self,
        status: ProcessStatus,
        terminal: Option<ProcessStatus>,
    ) -> Result<(), ScopeRestoreError> {
        if self.status != ProcessStatus::Created || !self.accepts_children() {
            return Err(ScopeRestoreError::AlreadyStarted);
        }
        reconcile_terminal(
            [terminal, status.is_terminal().then_some(status)]
                .into_iter()
                .flatten(),
        )?;
        if status == ProcessStatus::Finalizing && terminal.is_none() {
            return Err(ScopeRestoreError::InvalidTerminalIntent);
        }
        self.status = status;
        self.terminal = terminal;
        if terminal.is_some() {
            self.cleanup = Some(CleanupScope::Local);
        }
        Ok(())
    }

    /// Resume cleanup of a validated checkpoint while keeping existing terminal status.
    pub fn resume_cleanup(&mut self, status: ProcessStatus) -> Result<(), ScopeRestoreError> {
        if self.finalized {
            return Err(ScopeRestoreError::AlreadyStarted);
        }
        reconcile_terminal(
            [
                Some(status),
                self.terminal,
                self.status.is_terminal().then_some(self.status),
            ]
            .into_iter()
            .flatten(),
        )?;
        self.terminal = Some(status);
        if !self.status.is_terminal() {
            self.status = ProcessStatus::Finalizing;
        }
        self.cleanup.get_or_insert(CleanupScope::Local);
        Ok(())
    }

    /// Current reservation and spending counters.
    pub fn budget(&self) -> &BudgetState {
        &self.budget
    }

    /// Trusted host access for checkpoint import or accounting-window maintenance.
    pub fn budget_mut(&mut self) -> &mut BudgetState {
        &mut self.budget
    }

    /// Limits currently enforced at call admission.
    pub fn budget_spec(&self) -> &BudgetSpec {
        &self.limits
    }

    /// Replace spending limits without resetting recorded spending.
    pub fn set_budget_spec(&mut self, spec: BudgetSpec) {
        self.limits = spec;
    }

    /// Reserve every call, including zero-cost calls, before dispatch.
    pub fn reserve(&mut self, micro_usd: u64, tokens: u64) -> Result<(), String> {
        if self.status != ProcessStatus::Running || !self.accepts_children() {
            return Err("process_unavailable".into());
        }
        self.budget.try_reserve(&self.limits, micro_usd, tokens)
    }

    /// Reserve under a host-owned finalization attempt. Public operations must not
    /// select this path themselves; the host verifies its finalizer context.
    pub fn reserve_finalizer(&mut self, micro_usd: u64, tokens: u64) -> Result<(), String> {
        if !self.finalizer_active || self.finalized || self.status != ProcessStatus::Finalizing {
            return Err("process_unavailable".into());
        }
        self.budget.try_reserve(&self.limits, micro_usd, tokens)
    }

    /// Reserve for a trusted machine cleanup request before lifecycle commit.
    /// The host must bind cleanup to this owner and enforce the method's
    /// finalizer permission. Ordinary calls cannot select this path.
    pub fn reserve_cleanup(&mut self, micro_usd: u64, tokens: u64) -> Result<(), String> {
        if self.finalized
            || !matches!(
                self.status,
                ProcessStatus::Running | ProcessStatus::Cancelled | ProcessStatus::Finalizing
            )
        {
            return Err("process_unavailable".into());
        }
        self.budget.try_reserve(&self.limits, micro_usd, tokens)
    }

    /// Charge an already admitted descendant against this retained account.
    /// The host validates the descendant and its parent chain. This owner's
    /// completion does not end independently delegated descendant execution.
    pub fn reserve_descendant(&mut self, micro_usd: u64, tokens: u64) -> Result<(), String> {
        self.budget.try_reserve(&self.limits, micro_usd, tokens)
    }

    /// Settle a dispatched or cancelled reservation exactly once, as decided by the host.
    pub fn settle(
        &mut self,
        reserved_micro_usd: u64,
        actual_micro_usd: u64,
        reserved_tokens: u64,
        actual_tokens: u64,
    ) {
        self.budget.settle(
            reserved_micro_usd,
            actual_micro_usd,
            reserved_tokens,
            actual_tokens,
        );
    }

    fn choose_terminal(&mut self, requested: ProcessStatus) -> ProcessStatus {
        *self.terminal.get_or_insert(if self.status.is_terminal() {
            self.status
        } else {
            requested
        })
    }
}

#[cfg(test)]
mod tests;
