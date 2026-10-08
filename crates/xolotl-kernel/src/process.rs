//! Process table, spawn, and finalize.
//!
//! A `ProcessEntry` tracks a live Process's status, parent, attached grants,
//! budget, and finalizers. Spawn attenuates capabilities (a child's grant
//! cannot exceed its parent's); finalize cancels children, runs finalizers in
//! reverse, revokes handles, and publishes lifecycle completion.

use crate::host::HostRuntime;
use crate::runtime_domain::RuntimeDomain;
use crate::scope::{CleanupScope, Scope, ScopeFinalize};
use crate::step::StepModule;
use parking_lot::RwLock;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
#[cfg(test)]
use xolotl_types::Value;
use xolotl_types::{
    ExecutionId, ExecutionOutput, Failure, Grant, GrantId, IdentityRef, ProcessId, ProcessStatus,
    TaintSet, TaintedFailure, UnresolvedOperations,
};

mod accounting;
mod cleanup;
mod path;
pub(crate) use cleanup::{CleanupAction, CleanupSelection, CleanupTicketError};
pub use cleanup::{CleanupProgress, CleanupTicket};
pub(crate) use path::state_cleanup_owner;
mod observation;
pub use observation::{ProcessObservation, ProcessPage};
mod retention;
mod task;

pub use retention::{ProcessAdmissionError, ProcessCapacityError};

pub(crate) use task::{
    ProcessPublication, current_cleanup, current_finalizer, current_process, has_finalizer_context,
    outcome_status, scope_cleanup, scope_finalizer,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskAttachment {
    Attached,
    AlreadyTerminal,
    NoSuchProcess,
    AlreadyAttached,
    NoRuntime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FinalizeStart {
    Started,
    AlreadyFinalizing,
    AlreadyTerminal,
    NoSuchProcess,
    InvalidStatus,
}

/// One completed process's live cleanup evidence, retained until its entry is reaped.
/// This is neither an audit history nor an execution recovery record. It retains
/// no body result payload, native callback, grant or finalizer program.
#[derive(Clone, Debug)]
pub struct ProcessFinalizationReport {
    /// Stable terminal status selected by the process lifecycle.
    pub status: ProcessStatus,
    /// Aggregate provenance of the body and all attempted finalizers.
    pub taint: TaintSet,
    /// Bounded host-observed effects still requiring external reconciliation.
    pub unresolved_operations: UnresolvedOperations,
    /// At most one typed failure per attempted finalizer, in execution order.
    pub finalizer_failures: Vec<(usize, TaintedFailure)>,
    /// Local handle payloads released by cleanup.
    pub released_handles: usize,
    /// Handle authority subtrees revoked by cleanup.
    pub revoked_handles: usize,
}

/// Live bookkeeping for one Process. The serializable `Process` descriptor
/// lives in `xolotl-types`; this is the runtime entry the kernel mutates.
pub(crate) struct ProcessEntry {
    /// Portable lifecycle, identity and accounting state.
    pub(crate) scope: Scope,
    /// Parent process, if this process was spawned by another process.
    pub(crate) parent: Option<ProcessId>,
    /// Position in the parent's unordered child list, for constant-time unlink.
    parent_slot: usize,
    /// Request-scoped grants attached directly to this process.
    pub(crate) attached_grants: Vec<Grant>,
    /// Finalizer programs, run in reverse order on finalize.
    pub(crate) on_finalize: Vec<xolotl_graph::DoNode>,
    /// Immutable native functions shared by body and finalizer executors.
    pub(crate) steps: StepModule,
    /// Live host request authority shared by body, descendants and finalizers.
    request_authorizer: Option<Arc<dyn crate::RequestAuthorizer>>,
    /// Retained lifecycle publication, released only after all writes succeed.
    pub(crate) publication: Option<Arc<dyn ProcessPublication>>,
    /// Progress survives errors or dropped finalization futures until committed.
    finalization: Option<Box<Finalization>>,
    finalization_report: Option<Arc<ProcessFinalizationReport>>,
    /// Deduplicates the queue of committed, inactive leaves awaiting explicit reap.
    reap_queued: bool,
    /// Host observation pins never retain their table or its publications.
    cleanup_pin: std::sync::Weak<cleanup::CleanupPin>,
    /// Managed callback captures can outlive the body task's finalization handoff.
    managed_captures: usize,
}

impl ProcessEntry {
    fn has_tree_cleanup(&self) -> bool {
        self.scope.cleanup_scope() == Some(CleanupScope::Tree)
    }

    /// Create a process entry in the `Created` state.
    pub(crate) fn new(id: ProcessId, parent: Option<ProcessId>, identity: IdentityRef) -> Self {
        Self {
            scope: Scope::new(id, identity),
            parent,
            parent_slot: 0,
            attached_grants: Vec::new(),
            on_finalize: Vec::new(),
            steps: StepModule::default(),
            request_authorizer: None,
            publication: None,
            finalization: None,
            finalization_report: None,
            reap_queued: false,
            cleanup_pin: std::sync::Weak::new(),
            managed_captures: 0,
        }
    }

    fn accepts_children(&self) -> bool {
        self.scope.accepts_children()
    }
}

#[derive(Clone)]
struct Finalization {
    attempted: usize,
    active: Option<usize>,
    failures: Vec<(usize, TaintedFailure)>,
    completed_taint: TaintSet,
    unresolved_operations: UnresolvedOperations,
    released: usize,
    revoked: usize,
    outcome: Option<Arc<ExecutionOutput>>,
}

impl Finalization {
    fn new() -> Self {
        Self {
            attempted: 0,
            active: None,
            failures: Vec::new(),
            completed_taint: TaintSet::pristine(),
            unresolved_operations: UnresolvedOperations::default(),
            released: 0,
            revoked: 0,
            outcome: None,
        }
    }
}

/// Owns one finalization attempt, including cancellation of the owning future.
pub(crate) struct FinalizationGuard {
    table: ProcessTable,
    process: ProcessId,
}

impl Drop for FinalizationGuard {
    fn drop(&mut self) {
        self.table.release_finalizing(self.process);
    }
}

#[cfg(test)]
fn finalizer_failure(index: usize, failure: &Failure) -> Value {
    Value::map(std::collections::BTreeMap::from([
        ("index".into(), Value::integer(index as i64)),
        ("failure".into(), Value::string(failure.to_string())),
    ]))
}

/// The process tree: a registry of live processes plus parent/child links,
/// carrying cancellation propagation and capability attenuation.
#[derive(Clone)]
pub struct ProcessTable {
    inner: Arc<ProcessTableShared>,
}

struct ProcessTableShared {
    /// Present only for process tables assembled into a Kernel.
    runtime_domain: Option<RuntimeDomain>,
    state: RwLock<ProcessTableInner>,
    changed: tokio::sync::Notify,
    root_initialization: OnceLock<()>,
    host_runtime: HostRuntime,
}

struct ProcessTableInner {
    procs: HashMap<ProcessId, ProcessEntry>,
    ordered_ids: BTreeSet<ProcessId>,
    children: HashMap<ProcessId, Vec<ProcessId>>,
    tasks: HashMap<ProcessId, task::TaskRecord>,
    capacity: Option<NonZeroUsize>,
    reap_ready: VecDeque<ProcessId>,
    next: u64,
    next_attached_grant: u64,
}

impl Default for ProcessTableInner {
    fn default() -> Self {
        Self {
            procs: HashMap::new(),
            ordered_ids: BTreeSet::new(),
            children: HashMap::new(),
            tasks: HashMap::new(),
            capacity: None,
            reap_ready: VecDeque::new(),
            next: 1,
            next_attached_grant: 0,
        }
    }
}

impl ProcessTableInner {
    fn subtree_post_order(&self, root: ProcessId) -> Vec<ProcessId> {
        let mut out = Vec::new();
        let mut pending = vec![root];
        while let Some(id) = pending.pop() {
            out.push(id);
            if let Some(children) = self.children.get(&id) {
                pending.extend(children.iter().copied());
            }
        }
        out.reverse();
        out
    }

    fn request_cleanup_tree(&mut self, root: ProcessId) -> Vec<ProcessId> {
        if !self.procs.contains_key(&root) {
            return Vec::new();
        }
        let mut descendants = self.subtree_post_order(root);
        descendants.retain(|id| {
            if let Some(entry) = self.procs.get_mut(id) {
                if entry.scope.request_tree_cleanup() {
                    entry
                        .finalization
                        .get_or_insert_with(|| Box::new(Finalization::new()));
                }
                true
            } else {
                false
            }
        });
        descendants
    }
}

impl ProcessTable {
    /// Create an empty process table for isolated unit tests.
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_host_runtime_and_domain(HostRuntime::default(), None)
    }

    pub(crate) fn with_host_runtime_and_domain(
        host_runtime: HostRuntime,
        runtime_domain: Option<RuntimeDomain>,
    ) -> Self {
        Self {
            inner: Arc::new(ProcessTableShared {
                runtime_domain,
                state: RwLock::new(ProcessTableInner::default()),
                changed: tokio::sync::Notify::new(),
                root_initialization: OnceLock::new(),
                host_runtime,
            }),
        }
    }

    pub(crate) fn host_runtime(&self) -> &HostRuntime {
        &self.inner.host_runtime
    }

    pub(crate) fn runtime_domain(&self) -> Option<RuntimeDomain> {
        self.inner.runtime_domain.clone()
    }

    pub(crate) fn same_table(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Allocate without ever reusing an id, including after reaping or exhaustion.
    pub(crate) fn fresh_id(&self) -> Result<ProcessId, ProcessAdmissionError> {
        let mut inner = self.inner.state.write();
        inner.next = inner
            .next
            .checked_add(1)
            .ok_or(ProcessAdmissionError::IdentifierExhausted)?;
        Ok(ProcessId::new(inner.next))
    }

    /// Allocate a process-attached grant id.
    pub(crate) fn fresh_attached_grant_id(&self) -> GrantId {
        let mut inner = self.inner.state.write();
        inner.next_attached_grant += 1;
        GrantId::new((1u64 << 63) | inner.next_attached_grant)
    }

    /// Insert a new process entry, linking it under its parent.
    #[cfg(test)]
    pub(crate) fn insert(&self, entry: ProcessEntry) {
        let removed = self.inner.state.write().link_entry(entry);
        drop(removed);
    }

    /// Recheck identity and parent admission under the lock that links a child.
    pub(crate) fn admit_child(&self, entry: ProcessEntry) -> Result<(), ProcessAdmissionError> {
        self.admit_child_inner(entry, |_, _| ())
    }

    pub(crate) fn admit_request(
        &self,
        entry: ProcessEntry,
    ) -> Result<CleanupTicket, ProcessAdmissionError> {
        self.admit_child_inner(entry, CleanupTicket::pin_entry)
    }

    fn admit_child_inner<Owner>(
        &self,
        mut entry: ProcessEntry,
        acquire: impl FnOnce(&Arc<ProcessTableShared>, &mut ProcessEntry) -> Owner,
    ) -> Result<Owner, ProcessAdmissionError> {
        self.reclaim_for_admission();
        let (removed, ticket) = {
            let mut inner = self.inner.state.write();
            inner.check_child_admission(entry.scope.process(), entry.parent)?;
            let ticket = acquire(&self.inner, &mut entry);
            let removed = inner.link_entry(entry);
            (removed, ticket)
        };
        drop(removed);
        Ok(ticket)
    }

    /// Roll back a new child whose scheduler rejected its body before attachment.
    /// A concurrent observer may have changed its lifecycle; in that case the
    /// normal cleanup path must retain and finalize the entry instead.
    pub(crate) fn discard_unstarted_child(&self, id: ProcessId, parent: ProcessId) -> bool {
        let removed = {
            let mut inner = self.inner.state.write();
            let safe = inner.procs.get(&id).is_some_and(|entry| {
                entry.parent == Some(parent)
                    && entry.scope.status() == ProcessStatus::Running
                    && entry.scope.cleanup_scope().is_none()
                    && entry.finalization.is_none()
                    && entry.managed_captures == 0
                    && entry.scope.budget().inflight_ops == 0
                    && inner.children.get(&id).is_none_or(Vec::is_empty)
                    && !inner.tasks.contains_key(&id)
            });
            if !safe {
                return false;
            }
            let Some(entry) = inner.procs.remove(&id) else {
                return false;
            };
            inner.ordered_ids.remove(&id);
            inner.unlink_from_parent(&entry);
            entry
        };
        drop(removed);
        self.inner.changed.notify_waiters();
        true
    }

    /// Register authority outside the table lock, then publish the system root.
    /// Clones wait for initialization to complete before returning that root.
    pub(crate) fn initialize_root(&self, initialize: impl FnOnce(ProcessId)) -> ProcessId {
        let root = ProcessId::new(1);
        self.inner.root_initialization.get_or_init(|| {
            initialize(root);
            let mut entry = ProcessEntry::new(root, None, IdentityRef::ROOT);
            entry.scope.start();
            let removed = self.inner.state.write().link_entry(entry);
            drop(removed);
        });
        root
    }

    /// Install finalizers only after publication, rechecking parent admission.
    pub(crate) fn activate_child(
        &self,
        id: ProcessId,
        finalizers: Vec<xolotl_graph::DoNode>,
    ) -> bool {
        let removed = {
            let mut inner = self.inner.state.write();
            let Some(child) = inner.procs.get(&id) else {
                return false;
            };
            if child.scope.status() != ProcessStatus::Created
                || !child.accepts_children()
                || !child
                    .parent
                    .and_then(|parent| inner.procs.get(&parent))
                    .is_some_and(ProcessEntry::accepts_children)
            {
                return false;
            }
            let Some(child) = inner.procs.get_mut(&id) else {
                return false;
            };
            child.scope.start();
            std::mem::replace(&mut child.on_finalize, finalizers)
        };
        drop(removed);
        self.inner.changed.notify_waiters();
        true
    }

    /// Return the current status for a process.
    pub fn status(&self, id: ProcessId) -> Option<ProcessStatus> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)
            .map(|p| p.scope.status())
    }

    /// Execution scope retained for live cleanup and business request binding.
    pub fn lifecycle_execution(&self, id: ProcessId) -> Option<ExecutionId> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)?
            .scope
            .lifecycle_execution()
    }

    pub(crate) fn initialize_lifecycle(
        &self,
        id: ProcessId,
        execution: ExecutionId,
    ) -> Option<ExecutionId> {
        let mut inner = self.inner.state.write();
        let entry = inner.procs.get_mut(&id)?;
        Some(entry.scope.initialize_lifecycle(execution))
    }

    pub(crate) fn steps(&self, id: ProcessId) -> StepModule {
        self.inner
            .state
            .read()
            .procs
            .get(&id)
            .map(|entry| entry.steps.clone())
            .unwrap_or_default()
    }

    /// Retain the host's live request boundary until this process completes cleanup.
    pub(crate) fn set_request_authorizer(
        &self,
        id: ProcessId,
        authorizer: Arc<dyn crate::RequestAuthorizer>,
    ) -> Option<()> {
        let removed = {
            let mut inner = self.inner.state.write();
            let entry = inner.procs.get_mut(&id)?;
            if entry.scope.finalized() {
                return None;
            }
            entry.request_authorizer.replace(authorizer)
        };
        drop(removed);
        Some(())
    }

    /// Share the same live boundary with a newly assembled body or finalizer executor.
    pub(crate) fn request_authorizer(
        &self,
        id: ProcessId,
    ) -> Option<Arc<dyn crate::RequestAuthorizer>> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)?
            .request_authorizer
            .clone()
    }

    /// Move a process into Finalizing if no terminal/finalizing owner exists.
    pub(crate) fn begin_finalizing(&self, id: ProcessId, status: ProcessStatus) -> FinalizeStart {
        let mut inner = self.inner.state.write();
        let Some(entry) = inner.procs.get_mut(&id) else {
            return FinalizeStart::NoSuchProcess;
        };
        match entry.scope.begin_finalizing(status) {
            ScopeFinalize::Started => {}
            ScopeFinalize::AlreadyFinalizing => return FinalizeStart::AlreadyFinalizing,
            ScopeFinalize::AlreadyTerminal => return FinalizeStart::AlreadyTerminal,
            ScopeFinalize::InvalidStatus => return FinalizeStart::InvalidStatus,
        }
        entry
            .finalization
            .get_or_insert_with(|| Box::new(Finalization::new()));
        self.inner.changed.notify_waiters();
        FinalizeStart::Started
    }

    pub(crate) fn finalization_guard(&self, process: ProcessId) -> FinalizationGuard {
        FinalizationGuard {
            table: self.clone(),
            process,
        }
    }

    /// Release the finalization owner after a failed cleanup attempt.
    fn release_finalizing(&self, id: ProcessId) {
        let mut inner = self.inner.state.write();
        if let Some(entry) = inner.procs.get_mut(&id) {
            entry.scope.release_finalizing();
            if let Some(state) = entry.finalization.as_mut()
                && let Some(index) = state.active.take()
            {
                state.failures.push((
                    index,
                    TaintedFailure::pristine(Failure::HandlerError {
                        kind: "finalizer".into(),
                        message: "finalizer interrupted; external effects may be incomplete".into(),
                    }),
                ));
            }
        }
        inner.queue_reap_if_eligible(id);
        self.inner.changed.notify_waiters();
    }

    /// Record a terminal status before lifecycle side records are committed.
    pub(crate) fn mark_terminal_status(
        &self,
        id: ProcessId,
        status: ProcessStatus,
    ) -> Option<ProcessStatus> {
        let mut inner = self.inner.state.write();
        let entry = inner.procs.get_mut(&id)?;
        Some(entry.scope.mark_terminal_status(status))
    }

    /// Mark lifecycle cleanup fully complete.
    pub(crate) fn complete_finalization(&self, id: ProcessId) -> Option<()> {
        let removed = {
            let mut inner = self.inner.state.write();
            let entry = inner.procs.get_mut(&id)?;
            if !entry.scope.complete_finalization() {
                return None;
            }
            let mut finalization = entry.finalization.take();
            if let Some(state) = finalization.as_mut() {
                if let Some(output) = &state.outcome {
                    state.completed_taint.union(&output.taint);
                }
                for (_, error) in &state.failures {
                    state.completed_taint.union(&error.taint);
                }
                entry.finalization_report = Some(Arc::new(ProcessFinalizationReport {
                    status: entry.scope.status(),
                    taint: std::mem::take(&mut state.completed_taint),
                    unresolved_operations: std::mem::take(&mut state.unresolved_operations),
                    finalizer_failures: std::mem::take(&mut state.failures),
                    released_handles: state.released,
                    revoked_handles: state.revoked,
                }));
            }
            let removed = (
                std::mem::take(&mut entry.steps),
                std::mem::take(&mut entry.attached_grants),
                std::mem::take(&mut entry.on_finalize),
                finalization,
                entry.publication.take(),
                entry.request_authorizer.take(),
            );
            inner.queue_reap_if_eligible(id);
            removed
        };
        drop(removed);
        self.inner.changed.notify_waiters();
        Some(())
    }

    /// Cancel a process unless its terminal outcome has already been chosen.
    pub(crate) fn cancel_if_non_terminal(&self, id: ProcessId) -> Option<bool> {
        let mut inner = self.inner.state.write();
        let entry = inner.procs.get_mut(&id)?;
        if !entry.scope.cancel() {
            return Some(false);
        }
        self.inner.changed.notify_waiters();
        Some(true)
    }

    pub(crate) async fn wait_for_cancellation(&self, id: ProcessId, finalizer_mode: bool) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.status(id).is_none_or(|status| {
                status.is_terminal() || (!finalizer_mode && status == ProcessStatus::Finalizing)
            }) {
                return;
            }
            changed.await;
        }
    }

    /// Mark cleanup complete and set a terminal status if one has not already
    /// won.
    #[cfg(test)]
    pub(crate) fn mark_finalized_terminal(
        &self,
        id: ProcessId,
        status: ProcessStatus,
    ) -> Option<ProcessStatus> {
        let (actual, removed) = {
            let mut inner = self.inner.state.write();
            let entry = inner.procs.get_mut(&id)?;
            let actual = entry.scope.mark_terminal_status(status);
            if !entry.scope.complete_finalization() {
                return None;
            }
            (
                actual,
                (
                    std::mem::take(&mut entry.steps),
                    std::mem::take(&mut entry.attached_grants),
                    std::mem::take(&mut entry.on_finalize),
                    entry.finalization.take(),
                    entry.publication.take(),
                ),
            )
        };
        drop(removed);
        self.inner.changed.notify_waiters();
        Some(actual)
    }

    /// Return the identity a process runs as.
    pub fn identity(&self, id: ProcessId) -> Option<IdentityRef> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)
            .map(|p| p.scope.identity())
    }

    /// Business publication retained until its commit and local cleanup complete.
    pub(crate) fn publication(&self, id: ProcessId) -> Option<Arc<dyn ProcessPublication>> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)
            .and_then(|p| p.publication.clone())
    }

    /// Request-scoped grants attached directly to a process.
    pub fn attached_grants(&self, id: ProcessId) -> Vec<Grant> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)
            .map(|p| p.attached_grants.clone())
            .unwrap_or_default()
    }

    /// New handles belong either to an open body scope or its trusted cleanup.
    /// Call while holding the handle-table write lock through installation so
    /// lifecycle cleanup cannot release the old set and miss a newly added slot.
    pub(crate) fn admits_handles(&self, id: ProcessId) -> Option<bool> {
        let inner = self.inner.state.read();
        let entry = inner.procs.get(&id)?;
        let scope = &entry.scope;
        if scope.accepts_children() {
            return Some(true);
        }
        let finalizer = current_finalizer(self) == Some(id)
            && scope.finalizer_active()
            && scope.status() == ProcessStatus::Finalizing;
        let cleanup = current_cleanup(self) == Some(id)
            && matches!(
                scope.status(),
                ProcessStatus::Running | ProcessStatus::Cancelled | ProcessStatus::Finalizing
            );
        Some(!scope.finalized() && (finalizer || cleanup))
    }

    /// All live process ids.
    pub fn all_ids(&self) -> Vec<ProcessId> {
        self.inner.state.read().procs.keys().copied().collect()
    }

    /// Direct children of a process. Their order may change after explicit reap.
    pub fn children_of(&self, id: ProcessId) -> Vec<ProcessId> {
        self.inner
            .state
            .read()
            .children
            .get(&id)
            .cloned()
            .unwrap_or_default()
    }

    pub(crate) fn is_in_tree(&self, root: ProcessId, id: ProcessId) -> bool {
        let inner = self.inner.state.read();
        let mut current = Some(id);
        while let Some(entry) = current.and_then(|id| inner.procs.get(&id)) {
            if entry.scope.process() == root {
                return true;
            }
            current = entry.parent;
        }
        false
    }

    pub(crate) fn has_finalizers(&self, id: ProcessId) -> bool {
        self.inner
            .state
            .read()
            .procs
            .get(&id)
            .is_some_and(|entry| !entry.on_finalize.is_empty())
    }

    /// Start one finalizer, retaining all unstarted programs in the process table.
    pub(crate) fn next_finalizer(&self, id: ProcessId) -> Option<xolotl_graph::DoNode> {
        let mut inner = self.inner.state.write();
        let entry = inner.procs.get_mut(&id)?;
        let state = entry.finalization.as_mut()?;
        let body = entry.on_finalize.pop()?;
        state.active = Some(state.attempted);
        state.attempted += 1;
        Some(body)
    }

    /// Finalizer failures retained across finalization retries.
    #[cfg(test)]
    pub(crate) fn finalizer_failures(&self, id: ProcessId) -> Option<Vec<Value>> {
        let inner = self.inner.state.read();
        let entry = inner.procs.get(&id)?;
        let failures = if let Some(state) = &entry.finalization {
            &state.failures
        } else {
            &entry.finalization_report.as_ref()?.finalizer_failures
        };
        Some(
            failures
                .iter()
                .map(|(index, error)| finalizer_failure(*index, &error.failure))
                .collect(),
        )
    }

    pub(crate) fn retain_finalization_control(
        &self,
        id: ProcessId,
        taint: &TaintSet,
        unresolved_operations: Option<&UnresolvedOperations>,
    ) -> Option<()> {
        let mut inner = self.inner.state.write();
        let state = inner.procs.get_mut(&id)?.finalization.as_mut()?;
        state.completed_taint.union(taint);
        if let Some(unresolved_operations) = unresolved_operations {
            state.unresolved_operations.merge(unresolved_operations);
        }
        Some(())
    }

    #[cfg(test)]
    pub(crate) fn finalization_unresolved_operations(
        &self,
        id: ProcessId,
    ) -> Option<UnresolvedOperations> {
        let inner = self.inner.state.read();
        let entry = inner.procs.get(&id)?;
        if let Some(state) = &entry.finalization {
            Some(state.unresolved_operations.clone())
        } else {
            Some(
                entry
                    .finalization_report
                    .as_ref()?
                    .unresolved_operations
                    .clone(),
            )
        }
    }

    pub(crate) fn finish_finalizer(&self, id: ProcessId, output: ExecutionOutput) -> Option<()> {
        let mut inner = self.inner.state.write();
        let state = inner.procs.get_mut(&id)?.finalization.as_mut()?;
        let index = state.active.take()?;
        let (result, unresolved_operations) = output.into_parts();
        state.unresolved_operations.merge(&unresolved_operations);
        match result {
            Ok(value) => state.completed_taint.union(&value.taint),
            Err(error) => state.failures.push((index, error)),
        }
        Some(())
    }

    pub(crate) fn finalization_status(&self, id: ProcessId) -> Option<ProcessStatus> {
        let inner = self.inner.state.read();
        let entry = inner.procs.get(&id)?;
        entry.scope.terminal_intent().or_else(|| {
            entry
                .finalization_report
                .as_ref()
                .map(|report| report.status)
        })
    }

    /// Share a completed cleanup report without retaining this table or process entry.
    /// Returns `None` before completion or after explicit reap. Existing report
    /// owners may keep its immutable evidence after the entry has been reaped.
    pub fn finalization_report(&self, id: ProcessId) -> Option<Arc<ProcessFinalizationReport>> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)?
            .finalization_report
            .clone()
    }

    pub(crate) fn retain_body_completion(
        &self,
        id: ProcessId,
        output: &ExecutionOutput,
    ) -> Option<bool> {
        let mut inner = self.inner.state.write();
        let entry = inner.procs.get_mut(&id)?;
        if !entry.scope.finish_body(outcome_status(&output.outcome)) {
            return Some(false);
        }
        let state = entry
            .finalization
            .get_or_insert_with(|| Box::new(Finalization::new()));
        state.completed_taint.union(&output.taint);
        state
            .unresolved_operations
            .merge(&output.unresolved_operations);
        drop(inner);
        self.inner.changed.notify_waiters();
        Some(true)
    }

    /// Retain the first body result without replacing an existing cleanup owner.
    pub(crate) fn retain_outcome(
        &self,
        id: ProcessId,
        outcome: ExecutionOutput,
    ) -> Option<Arc<ExecutionOutput>> {
        let outcome = Arc::new(outcome);
        let mut inner = self.inner.state.write();
        let entry = inner.procs.get_mut(&id)?;
        if !entry.scope.finish_body(outcome_status(&outcome.outcome)) {
            return None;
        }
        let state = entry
            .finalization
            .get_or_insert_with(|| Box::new(Finalization::new()));
        let retained = state.outcome.get_or_insert_with(|| outcome.clone()).clone();
        state
            .unresolved_operations
            .merge(&retained.unresolved_operations);
        self.inner.changed.notify_waiters();
        Some(retained)
    }

    pub(crate) fn finalization_outcome(&self, id: ProcessId) -> Option<Arc<ExecutionOutput>> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)?
            .finalization
            .as_ref()?
            .outcome
            .clone()
    }

    pub(crate) fn record_revocation(&self, id: ProcessId, revoked: usize) -> Option<usize> {
        self.record_handle_cleanup(id, 0, revoked)
            .map(|(_, revoked)| revoked)
    }

    pub(crate) fn record_handle_cleanup(
        &self,
        id: ProcessId,
        released: usize,
        revoked: usize,
    ) -> Option<(usize, usize)> {
        let mut inner = self.inner.state.write();
        let state = inner.procs.get_mut(&id)?.finalization.as_mut()?;
        state.released += released;
        state.revoked += revoked;
        Some((state.released, state.revoked))
    }

    /// Close request admission for the entire tree before any asynchronous cleanup.
    pub(crate) fn request_cleanup_tree(&self, root: ProcessId) -> Vec<ProcessId> {
        let descendants = self.inner.state.write().request_cleanup_tree(root);
        self.inner.changed.notify_waiters();
        descendants
    }

    /// Abandon ownership without widening an already chosen cleanup scope.
    pub(crate) fn abandon_scope(&self, id: ProcessId) -> Vec<ProcessId> {
        let descendants = {
            let mut inner = self.inner.state.write();
            let Some(entry) = inner.procs.get_mut(&id) else {
                return Vec::new();
            };
            match entry.scope.abandon() {
                None => Vec::new(),
                Some(CleanupScope::Local) => vec![id],
                Some(CleanupScope::Tree) => inner.request_cleanup_tree(id),
            }
        };
        self.inner.changed.notify_waiters();
        descendants
    }

    pub(crate) fn pending_cleanup(&self) -> Vec<ProcessId> {
        let inner = self.inner.state.read();
        inner
            .procs
            .iter()
            .filter_map(|(id, entry)| {
                entry.scope.cleanup_scope()?;
                let mut parent = entry.parent;
                while let Some(ancestor) = parent.and_then(|parent| inner.procs.get(&parent)) {
                    if ancestor.has_tree_cleanup() {
                        return None;
                    }
                    parent = ancestor.parent;
                }
                (!inner.cleanup_is_complete(*id)).then_some(*id)
            })
            .collect()
    }

    pub(crate) fn cleanup_scope(&self, id: ProcessId) -> Option<(bool, ProcessStatus)> {
        let inner = self.inner.state.read();
        let entry = inner.procs.get(&id)?;
        let status = entry
            .scope
            .terminal_intent()
            .unwrap_or(entry.scope.status());
        Some((entry.has_tree_cleanup(), status))
    }

    pub(crate) async fn wait_for_finalization(&self, id: ProcessId) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !self
                .inner
                .state
                .read()
                .procs
                .get(&id)
                .is_some_and(|entry| entry.scope.finalizer_active())
            {
                return;
            }
            changed.await;
        }
    }

    /// Collect a consistent snapshot of descendants before their parents.
    #[cfg(test)]
    pub(crate) fn subtree_post_order(&self, root: ProcessId) -> Vec<ProcessId> {
        self.inner.state.read().subtree_post_order(root)
    }

    /// Number of live process entries.
    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.inner.state.read().procs.len()
    }

    /// Whether a process id exists in the table.
    #[cfg(test)]
    pub(crate) fn exists(&self, id: ProcessId) -> bool {
        self.inner.state.read().procs.contains_key(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

    #[tokio::test]
    async fn children_share_live_request_authority_until_their_own_cleanup() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct Authorizer {
            table: std::sync::Weak<ProcessTableShared>,
            allowed: Arc<AtomicBool>,
            released_without_lock: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl crate::RequestAuthorizer for Authorizer {
            async fn authorize(&self) -> Result<(), Failure> {
                if self.allowed.load(Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err(Failure::policy("request", "revoked"))
                }
            }
        }

        impl Drop for Authorizer {
            fn drop(&mut self) {
                self.released_without_lock.store(
                    self.table
                        .upgrade()
                        .is_some_and(|table| table.state.try_read().is_some()),
                    Ordering::SeqCst,
                );
            }
        }

        let table = ProcessTable::new();
        let root = table.fresh_id()?;
        table.insert(ProcessEntry::new(root, None, IdentityRef::ROOT));
        let allowed = Arc::new(AtomicBool::new(true));
        let released_without_lock = Arc::new(AtomicBool::new(false));
        let authorizer: Arc<dyn crate::RequestAuthorizer> = Arc::new(Authorizer {
            table: Arc::downgrade(&table.inner),
            allowed: allowed.clone(),
            released_without_lock: released_without_lock.clone(),
        });
        let retained = Arc::downgrade(&authorizer);
        table
            .set_request_authorizer(root, authorizer.clone())
            .context("parent authority")?;
        let child = table.fresh_id()?;
        table.admit_child(ProcessEntry::new(child, Some(root), IdentityRef::ROOT))?;
        let child_authorizer = table
            .request_authorizer(child)
            .context("inherited authority")?;
        ensure!(Arc::ptr_eq(&authorizer, &child_authorizer));
        child_authorizer.authorize().await?;
        allowed.store(false, Ordering::SeqCst);
        ensure!(child_authorizer.authorize().await == Err(Failure::policy("request", "revoked")));
        drop(child_authorizer);
        drop(authorizer);
        ensure!(table.begin_finalizing(root, ProcessStatus::Completed) == FinalizeStart::Started);
        let guard = table.finalization_guard(root);
        table.mark_terminal_status(root, ProcessStatus::Completed);
        table
            .complete_finalization(root)
            .context("parent completion")?;
        drop(guard);
        ensure!(table.request_authorizer(root).is_none());
        ensure!(table.request_authorizer(child).is_some());
        ensure!(!released_without_lock.load(Ordering::SeqCst));
        ensure!(table.begin_finalizing(child, ProcessStatus::Completed) == FinalizeStart::Started);
        let guard = table.finalization_guard(child);
        table.mark_terminal_status(child, ProcessStatus::Completed);
        table
            .complete_finalization(child)
            .context("child completion")?;
        drop(guard);
        ensure!(table.request_authorizer(child).is_none());
        ensure!(retained.upgrade().is_none());
        ensure!(released_without_lock.load(Ordering::SeqCst));
        ensure!(table.reap_finalized(1) == 1);
        Ok(())
    }

    #[test]
    fn completed_report_preserves_control_evidence_without_retaining_body_payload()
    -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let root = table.fresh_id()?;
        table.insert(ProcessEntry::new(root, None, IdentityRef::ROOT));
        let process = table.fresh_id()?;
        let mut entry = ProcessEntry::new(process, Some(root), IdentityRef::ROOT);
        entry
            .on_finalize
            .push(xolotl_graph::DoNode::pure(Value::null()));
        table.insert(entry);
        let mut body_unknown = UnresolvedOperations::default();
        body_unknown.record("body-operation");
        let output = table
            .retain_outcome(
                process,
                ExecutionOutput::new(
                    xolotl_types::Outcome::Done(Value::bytes(vec![1; 1024])),
                    TaintSet::author(),
                )
                .with_unresolved_operations(body_unknown.clone()),
            )
            .context("body outcome")?;
        let body_payload = Arc::downgrade(&output);
        drop(output);
        ensure!(table.finalization_report(process).is_none());
        ensure!(
            table.begin_finalizing(process, ProcessStatus::Completed) == FinalizeStart::Started
        );
        let guard = table.finalization_guard(process);
        ensure!(table.next_finalizer(process).is_some());
        let failure_taint = TaintSet::of(xolotl_types::TaintSource::ModelOutput);
        let failure = Failure::OutcomeUnknown {
            operation_ids: vec!["finalizer-operation".into()],
            reason: "remote acknowledgement lost".into(),
        };
        let mut finalizer_unknown = UnresolvedOperations::default();
        finalizer_unknown.record("finalizer-operation");
        finalizer_unknown.identities_incomplete = true;
        table
            .finish_finalizer(
                process,
                ExecutionOutput::new(
                    xolotl_types::Outcome::Fail(failure.clone()),
                    failure_taint.clone(),
                )
                .with_unresolved_operations(finalizer_unknown),
            )
            .context("finalizer result")?;
        table
            .record_handle_cleanup(process, 2, 3)
            .context("cleanup counts")?;
        table.mark_terminal_status(process, ProcessStatus::Completed);
        table.complete_finalization(process).context("completion")?;
        drop(guard);
        let report = table
            .finalization_report(process)
            .context("completed report")?;
        ensure!(body_payload.upgrade().is_none());
        ensure!(report.status == ProcessStatus::Completed);
        ensure!(report.taint.contains_all(&TaintSet::author()));
        ensure!(report.taint.contains_all(&failure_taint));
        ensure!(
            report.unresolved_operations.operation_ids == ["body-operation", "finalizer-operation"]
        );
        ensure!(report.unresolved_operations.identities_incomplete);
        ensure!(report.finalizer_failures == [(0, TaintedFailure::new(failure, failure_taint))]);
        ensure!((report.released_handles, report.revoked_handles) == (2, 3));
        ensure!(
            table
                .finalization_report(process)
                .context("missing report")?
                .taint
                == report.taint
        );
        ensure!(
            table.finalization_unresolved_operations(process)
                == Some(report.unresolved_operations.clone())
        );
        ensure!(table.finalizer_failures(process).context("failures")?.len() == 1);
        ensure!(table.finalization_status(process) == Some(ProcessStatus::Completed));
        table
            .complete_finalization(process)
            .context("repeat completion")?;
        ensure!(Arc::ptr_eq(
            &report,
            &table.finalization_report(process).context("same report")?
        ));
        let retained = Arc::downgrade(&report);
        ensure!(table.reap_finalized(1) == 1);
        ensure!(table.finalization_report(process).is_none());
        ensure!(retained.upgrade().is_some());
        drop(report);
        ensure!(retained.upgrade().is_none());
        Ok(())
    }

    #[test]
    fn native_captures_are_dropped_outside_the_process_lock() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct Capture {
            table: ProcessTable,
            released: Arc<AtomicBool>,
        }
        impl Drop for Capture {
            fn drop(&mut self) {
                self.released.store(
                    self.table.inner.state.try_read().is_some(),
                    Ordering::SeqCst,
                );
            }
        }

        let table = ProcessTable::new();
        let released = Arc::new(AtomicBool::new(false));
        let capture = Capture {
            table: table.clone(),
            released: released.clone(),
        };
        let process = table.fresh_id()?;
        let mut entry = ProcessEntry::new(process, None, IdentityRef::ROOT);
        entry.steps = StepModule::single("capture", move |value, _| {
            let _lifetime = &capture;
            xolotl_graph::DoNode::pure(value)
        })?;
        table.insert(entry);
        table.mark_terminal_status(process, ProcessStatus::Completed);
        table
            .complete_finalization(process)
            .context("process disappeared")?;
        ensure!(released.load(Ordering::SeqCst));
        ensure!(table.steps(process).is_empty());
        Ok(())
    }

    #[test]
    fn publication_and_outcome_are_released_after_committed_cleanup() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use xolotl_types::{Outcome, TaintSet};

        struct Publication {
            table: ProcessTable,
            released_without_lock: Arc<AtomicBool>,
        }

        #[async_trait::async_trait]
        impl ProcessPublication for Publication {
            async fn publish(
                &self,
                _state: &xolotl_state::Backend,
                _process: ProcessId,
                _status: ProcessStatus,
                _outcome: Option<&ExecutionOutput>,
            ) -> Result<(), crate::BootstrapError> {
                Ok(())
            }
        }

        impl Drop for Publication {
            fn drop(&mut self) {
                self.released_without_lock.store(
                    self.table.inner.state.try_read().is_some(),
                    Ordering::SeqCst,
                );
            }
        }

        let table = ProcessTable::new();
        let process = table.fresh_id()?;
        let released = Arc::new(AtomicBool::new(false));
        let mut entry = ProcessEntry::new(process, None, IdentityRef::ROOT);
        entry.publication = Some(Arc::new(Publication {
            table: table.clone(),
            released_without_lock: released.clone(),
        }));
        table.insert(entry);
        let outcome = table
            .retain_outcome(
                process,
                ExecutionOutput {
                    outcome: Outcome::Done(Value::integer(7)),
                    taint: TaintSet::author(),
                    unresolved_operations: Default::default(),
                },
            )
            .context("missing retained outcome")?;
        let retained = Arc::downgrade(&outcome);
        drop(outcome);
        ensure!(
            table.begin_finalizing(process, ProcessStatus::Completed) == FinalizeStart::Started
        );
        drop(table.finalization_guard(process));
        ensure!(!released.load(Ordering::SeqCst));
        ensure!(table.publication(process).is_some());
        ensure!(retained.upgrade().is_some());
        table.mark_terminal_status(process, ProcessStatus::Completed);
        table.complete_finalization(process);
        ensure!(released.load(Ordering::SeqCst));
        ensure!(table.publication(process).is_none());
        ensure!(retained.upgrade().is_none());
        Ok(())
    }

    #[test]
    fn spawn_links_parent_child() -> anyhow::Result<()> {
        let t = ProcessTable::new();
        let root = t.fresh_id()?;
        t.insert(ProcessEntry::new(root, None, IdentityRef::ROOT));
        let child = t.fresh_id()?;
        t.insert(ProcessEntry::new(child, Some(root), IdentityRef::new(2)));
        ensure!(
            t.children_of(root) == vec![child],
            "child process was not linked to parent"
        );
        Ok(())
    }

    #[test]
    fn duplicate_child_admission_preserves_identity_and_links() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let parent = table.fresh_id()?;
        table.insert(ProcessEntry::new(parent, None, IdentityRef::ROOT));
        let other = table.fresh_id()?;
        table.insert(ProcessEntry::new(other, None, IdentityRef::ROOT));
        let child = table.fresh_id()?;
        table.admit_child(ProcessEntry::new(child, Some(parent), IdentityRef::new(2)))?;
        ensure!(
            table
                .admit_child(ProcessEntry::new(child, Some(other), IdentityRef::new(3)))
                .is_err()
        );
        ensure!(table.identity(child) == Some(IdentityRef::new(2)));
        ensure!(table.children_of(parent) == vec![child]);
        ensure!(table.children_of(other).is_empty());
        ensure!(table.is_in_tree(parent, child));
        ensure!(!table.is_in_tree(other, child));
        Ok(())
    }

    #[test]
    fn child_admission_rejects_every_closing_parent() -> anyhow::Result<()> {
        for status in [
            ProcessStatus::Completed,
            ProcessStatus::Failed,
            ProcessStatus::Cancelled,
            ProcessStatus::Finalizing,
        ] {
            let table = ProcessTable::new();
            let parent = table.fresh_id()?;
            let mut entry = ProcessEntry::new(parent, None, IdentityRef::ROOT);
            if status == ProcessStatus::Finalizing {
                ensure!(entry.scope.finish_body(ProcessStatus::Cancelled));
            } else {
                ensure!(entry.scope.finish_body(status));
                entry.scope.mark_terminal_status(status);
            }
            table.insert(entry);
            let child = table.fresh_id()?;
            ensure!(
                table
                    .admit_child(ProcessEntry::new(child, Some(parent), IdentityRef::ROOT))
                    .is_err()
            );
            ensure!(table.children_of(parent).is_empty());
            ensure!(!table.exists(child));
        }
        let table = ProcessTable::new();
        let parent = table.fresh_id()?;
        table.insert(ProcessEntry::new(parent, None, IdentityRef::ROOT));
        table.mark_terminal_status(parent, ProcessStatus::Completed);
        table.complete_finalization(parent);
        let child = table.fresh_id()?;
        ensure!(
            table
                .admit_child(ProcessEntry::new(child, Some(parent), IdentityRef::ROOT))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn activation_rechecks_parent_before_installing_finalizers() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let parent = table.fresh_id()?;
        table.insert(ProcessEntry::new(parent, None, IdentityRef::ROOT));
        let child = table.fresh_id()?;
        table.admit_child(ProcessEntry::new(child, Some(parent), IdentityRef::ROOT))?;
        ensure!(table.begin_finalizing(parent, ProcessStatus::Completed) == FinalizeStart::Started);
        ensure!(!table.activate_child(child, vec![xolotl_graph::DoNode::pure(Value::null())]));
        ensure!(table.status(child) == Some(ProcessStatus::Created));
        ensure!(!table.has_finalizers(child));
        Ok(())
    }

    #[test]
    fn activation_installs_finalizers_once() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let parent = table.fresh_id()?;
        table.insert(ProcessEntry::new(parent, None, IdentityRef::ROOT));
        let child = table.fresh_id()?;
        table.admit_child(ProcessEntry::new(child, Some(parent), IdentityRef::ROOT))?;
        ensure!(table.activate_child(child, vec![xolotl_graph::DoNode::pure(Value::integer(1))]));
        ensure!(table.status(child) == Some(ProcessStatus::Running));
        ensure!(!table.activate_child(child, vec![xolotl_graph::DoNode::pure(Value::integer(2))]));
        ensure!(table.begin_finalizing(child, ProcessStatus::Completed) == FinalizeStart::Started);
        ensure!(table.next_finalizer(child) == Some(xolotl_graph::DoNode::pure(Value::integer(1))));
        ensure!(table.next_finalizer(child).is_none());
        Ok(())
    }

    #[test]
    fn cleanup_traverses_finalized_ancestors_to_live_descendants() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let parent = table.fresh_id()?;
        table.insert(ProcessEntry::new(parent, None, IdentityRef::ROOT));
        let child = table.fresh_id()?;
        table.admit_child(ProcessEntry::new(child, Some(parent), IdentityRef::ROOT))?;
        let descendant = table.fresh_id()?;
        table.admit_child(ProcessEntry::new(
            descendant,
            Some(child),
            IdentityRef::ROOT,
        ))?;
        table.mark_finalized_terminal(parent, ProcessStatus::Completed);

        ensure!(table.request_cleanup_tree(parent) == vec![descendant, child, parent]);
        ensure!(table.status(parent) == Some(ProcessStatus::Completed));
        ensure!(table.finalization_status(child) == Some(ProcessStatus::Cancelled));
        ensure!(table.finalization_status(descendant) == Some(ProcessStatus::Cancelled));
        ensure!(table.pending_cleanup() == vec![parent]);
        ensure!(table.is_in_tree(parent, descendant));
        ensure!(table.is_in_tree(parent, parent));
        ensure!(!table.is_in_tree(parent, ProcessId::new(100)));
        Ok(())
    }

    #[test]
    fn single_process_cleanup_preserves_independent_descendant_work() -> anyhow::Result<()> {
        use xolotl_types::{Outcome, TaintSet};

        let table = ProcessTable::new();
        let parent = table.fresh_id()?;
        table.insert(ProcessEntry::new(parent, None, IdentityRef::ROOT));
        let child = table.fresh_id()?;
        table.admit_child(ProcessEntry::new(child, Some(parent), IdentityRef::ROOT))?;
        for process in [parent, child] {
            table.retain_outcome(
                process,
                ExecutionOutput {
                    outcome: Outcome::Done(Value::null()),
                    taint: TaintSet::pristine(),
                    unresolved_operations: Default::default(),
                },
            );
        }
        ensure!(table.begin_finalizing(parent, ProcessStatus::Completed) == FinalizeStart::Started);
        drop(table.finalization_guard(parent));
        let pending = table.pending_cleanup();
        ensure!(pending.len() == 2 && pending.contains(&parent) && pending.contains(&child));
        ensure!(table.cleanup_scope(parent) == Some((false, ProcessStatus::Completed)));
        ensure!(table.cleanup_scope(child) == Some((false, ProcessStatus::Completed)));

        table.request_cleanup_tree(parent);
        table.retain_outcome(
            parent,
            ExecutionOutput {
                outcome: Outcome::Done(Value::null()),
                taint: TaintSet::pristine(),
                unresolved_operations: Default::default(),
            },
        );
        ensure!(table.pending_cleanup() == vec![parent]);
        ensure!(table.cleanup_scope(parent) == Some((true, ProcessStatus::Completed)));
        ensure!(table.cleanup_scope(child) == Some((true, ProcessStatus::Completed)));
        Ok(())
    }

    #[test]
    fn abandoning_finished_scope_does_not_cancel_surviving_children() -> anyhow::Result<()> {
        use xolotl_types::{Outcome, TaintSet};

        let table = ProcessTable::new();
        let parent = table.fresh_id()?;
        table.insert(ProcessEntry::new(parent, None, IdentityRef::ROOT));
        let child = table.fresh_id()?;
        table.admit_child(ProcessEntry::new(child, Some(parent), IdentityRef::ROOT))?;
        table.retain_outcome(
            parent,
            ExecutionOutput {
                outcome: Outcome::Done(Value::null()),
                taint: TaintSet::pristine(),
                unresolved_operations: Default::default(),
            },
        );
        ensure!(table.abandon_scope(parent) == vec![parent]);
        ensure!(table.cleanup_scope(parent) == Some((false, ProcessStatus::Completed)));
        ensure!(table.status(child) == Some(ProcessStatus::Created));
        ensure!(table.finalization_status(child).is_none());

        table.mark_terminal_status(parent, ProcessStatus::Completed);
        table.complete_finalization(parent);
        ensure!(table.abandon_scope(parent).is_empty());
        ensure!(table.pending_cleanup().is_empty());
        ensure!(table.status(child) == Some(ProcessStatus::Created));
        ensure!(table.request_cleanup_tree(parent) == vec![child, parent]);
        ensure!(table.finalization_status(child) == Some(ProcessStatus::Cancelled));
        Ok(())
    }

    #[test]
    fn retained_outcome_preserves_first_result_and_cleanup_owner() -> anyhow::Result<()> {
        use xolotl_types::{Outcome, TaintSet};

        let table = ProcessTable::new();
        let process = table.fresh_id()?;
        table.insert(ProcessEntry::new(process, None, IdentityRef::ROOT));
        ensure!(
            table.begin_finalizing(process, ProcessStatus::Cancelled) == FinalizeStart::Started
        );
        let guard = table.finalization_guard(process);
        let retained = table
            .retain_outcome(
                process,
                ExecutionOutput {
                    outcome: Outcome::Done(Value::integer(7)),
                    taint: TaintSet::author(),
                    unresolved_operations: Default::default(),
                },
            )
            .context("missing retained outcome")?;
        let again = table
            .retain_outcome(
                process,
                ExecutionOutput {
                    outcome: Outcome::Done(Value::integer(8)),
                    taint: TaintSet::pristine(),
                    unresolved_operations: Default::default(),
                },
            )
            .context("missing first outcome")?;
        ensure!(Arc::ptr_eq(&retained, &again));
        ensure!(retained.outcome == Outcome::Done(Value::integer(7)));
        ensure!(retained.taint == TaintSet::author());
        ensure!(table.finalization_status(process) == Some(ProcessStatus::Cancelled));
        ensure!(table.status(process) == Some(ProcessStatus::Finalizing));
        ensure!(
            table.begin_finalizing(process, ProcessStatus::Completed)
                == FinalizeStart::AlreadyFinalizing
        );
        drop(guard);
        ensure!(table.pending_cleanup() == vec![process]);
        table.mark_terminal_status(process, ProcessStatus::Cancelled);
        table.complete_finalization(process);
        ensure!(table.finalization_outcome(process).is_none());
        Ok(())
    }

    #[test]
    fn subtree_post_order_is_deepest_first() -> anyhow::Result<()> {
        let t = ProcessTable::new();
        let a = t.fresh_id()?;
        t.insert(ProcessEntry::new(a, None, IdentityRef::ROOT));
        let b = t.fresh_id()?;
        t.insert(ProcessEntry::new(b, Some(a), IdentityRef::ROOT));
        let c = t.fresh_id()?;
        t.insert(ProcessEntry::new(c, Some(b), IdentityRef::ROOT));
        // a -> b -> c ; post-order cancels c, then b, then a.
        ensure!(
            t.subtree_post_order(a) == vec![c, b, a],
            "subtree post-order mismatch"
        );
        Ok(())
    }

    #[test]
    fn finalizers_run_in_reverse() -> anyhow::Result<()> {
        let t = ProcessTable::new();
        let p = t.fresh_id()?;
        let mut entry = ProcessEntry::new(p, None, IdentityRef::ROOT);
        entry
            .on_finalize
            .push(xolotl_graph::DoNode::pure(xolotl_types::Value::integer(1)));
        entry
            .on_finalize
            .push(xolotl_graph::DoNode::pure(xolotl_types::Value::integer(2)));
        t.insert(entry);
        ensure!(t.begin_finalizing(p, ProcessStatus::Completed) == FinalizeStart::Started);
        let guard = t.finalization_guard(p);
        // Added 1 then 2; reverse order runs 2 then 1.
        let first = t.next_finalizer(p).context("missing first finalizer")?;
        ensure!(
            first == xolotl_graph::DoNode::pure(xolotl_types::Value::integer(2)),
            "first finalizer mismatch"
        );
        t.finish_finalizer(
            p,
            ExecutionOutput::new(
                xolotl_types::Outcome::Done(Value::null()),
                TaintSet::pristine(),
            ),
        )
        .context("missing finalizer progress")?;
        let second = t.next_finalizer(p).context("missing second finalizer")?;
        ensure!(
            second == xolotl_graph::DoNode::pure(xolotl_types::Value::integer(1)),
            "second finalizer mismatch"
        );
        t.finish_finalizer(
            p,
            ExecutionOutput::new(
                xolotl_types::Outcome::Done(Value::null()),
                TaintSet::pristine(),
            ),
        )
        .context("missing finalizer progress")?;
        drop(guard);
        Ok(())
    }

    #[test]
    fn begin_finalizing_has_one_owner() -> anyhow::Result<()> {
        let t = ProcessTable::new();
        let p = t.fresh_id()?;
        let mut entry = ProcessEntry::new(p, None, IdentityRef::ROOT);
        entry.scope.start();
        t.insert(entry);

        ensure!(
            t.begin_finalizing(p, ProcessStatus::Failed) == FinalizeStart::Started,
            "running process should enter finalizing once"
        );
        ensure!(
            t.begin_finalizing(p, ProcessStatus::Failed) == FinalizeStart::AlreadyFinalizing,
            "second finalizer owner should be rejected"
        );
        let actual = t
            .mark_finalized_terminal(p, ProcessStatus::Failed)
            .context("missing process")?;
        ensure!(
            actual == ProcessStatus::Failed,
            "final status should be recorded"
        );
        ensure!(
            t.begin_finalizing(p, ProcessStatus::Failed) == FinalizeStart::AlreadyTerminal,
            "finalized process should not re-enter finalizing"
        );
        Ok(())
    }

    #[test]
    fn finalized_terminal_does_not_overwrite_existing_terminal_status() -> anyhow::Result<()> {
        let t = ProcessTable::new();
        let p = t.fresh_id()?;
        let mut entry = ProcessEntry::new(p, None, IdentityRef::ROOT);
        entry.scope.cancel();
        t.insert(entry);

        let actual = t
            .mark_finalized_terminal(p, ProcessStatus::Completed)
            .context("missing process")?;
        ensure!(
            actual == ProcessStatus::Cancelled,
            "existing terminal status should win"
        );
        ensure!(
            t.status(p) == Some(ProcessStatus::Cancelled),
            "process table status was overwritten"
        );
        Ok(())
    }

    #[test]
    fn cancelled_process_can_enter_finalizing_before_cleanup() -> anyhow::Result<()> {
        let t = ProcessTable::new();
        let p = t.fresh_id()?;
        let mut entry = ProcessEntry::new(p, None, IdentityRef::ROOT);
        entry.scope.cancel();
        t.insert(entry);

        ensure!(
            t.begin_finalizing(p, ProcessStatus::Cancelled) == FinalizeStart::Started,
            "cancelled process still needs cleanup ownership"
        );
        let actual = t
            .mark_finalized_terminal(p, ProcessStatus::Cancelled)
            .context("missing process")?;
        ensure!(
            actual == ProcessStatus::Cancelled,
            "cancelled terminal status should win"
        );
        ensure!(
            t.begin_finalizing(p, ProcessStatus::Cancelled) == FinalizeStart::AlreadyTerminal,
            "cleanup should not run twice"
        );
        Ok(())
    }
}
