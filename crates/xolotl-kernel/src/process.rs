//! Process table, spawn, and finalize.
//!
//! A `ProcessEntry` tracks a live Process's status, parent, attached grants,
//! budget, and finalizers. Spawn attenuates capabilities (a child's grant
//! cannot exceed its parent's); finalize cancels children, runs finalizers in
//! reverse, revokes handles, and writes a `ProcessFinalized` fact.

use crate::scope::{CleanupScope, Scope, ScopeFinalize};
use crate::step::StepModule;
use parking_lot::RwLock;
use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::sync::{Arc, OnceLock};
use xolotl_types::{
    ExecutionId, ExecutionOutput, Fact, Failure, Grant, GrantId, IdentityRef, ProcessId,
    ProcessStatus, TaintSet, TaintedFailure, Value,
};

mod accounting;
#[cfg(feature = "durable")]
mod checkpoint;
mod retention;
mod task;

#[cfg(feature = "durable")]
use checkpoint::CheckpointState;
#[cfg(feature = "durable")]
pub use checkpoint::ProcessSnapshot;
#[cfg(feature = "durable")]
pub(crate) use checkpoint::{LeasedRequestState, RetainedFinalization};

pub use retention::{ProcessAdmissionError, ProcessCapacityError};

#[cfg(feature = "durable")]
pub(crate) use task::TaskOwner;
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
    /// Retained lifecycle publication, released only after all writes succeed.
    pub(crate) publication: Option<Arc<dyn ProcessPublication>>,
    /// Progress survives errors or dropped finalization futures until committed.
    finalization: Option<Box<Finalization>>,
    /// Creation pins cleanup; committed or retired journals also forbid a fresh execution.
    #[cfg(feature = "durable")]
    checkpoint: CheckpointState,
    /// Deduplicates the queue of committed, inactive leaves awaiting explicit reap.
    reap_queued: bool,
}

impl ProcessEntry {
    /// Create a process entry in the `Created` state.
    pub(crate) fn new(id: ProcessId, parent: Option<ProcessId>, identity: IdentityRef) -> Self {
        Self {
            scope: Scope::new(id, identity),
            parent,
            parent_slot: 0,
            attached_grants: Vec::new(),
            on_finalize: Vec::new(),
            steps: StepModule::default(),
            publication: None,
            finalization: None,
            #[cfg(feature = "durable")]
            checkpoint: CheckpointState::None,
            reap_queued: false,
        }
    }

    fn accepts_children(&self) -> bool {
        self.scope.accepts_children()
    }
}

struct Finalization {
    attempted: usize,
    active: Option<usize>,
    failures: Vec<(usize, TaintedFailure)>,
    completed_taint: TaintSet,
    released: usize,
    revoked: usize,
    record: Option<(Fact, usize)>,
    outcome: Option<Arc<ExecutionOutput>>,
}

impl Finalization {
    fn new() -> Self {
        Self {
            attempted: 0,
            active: None,
            failures: Vec::new(),
            completed_taint: TaintSet::pristine(),
            released: 0,
            revoked: 0,
            record: None,
            outcome: None,
        }
    }
}

/// Owns one finalization attempt, including cancellation of the owning future.
pub(crate) struct FinalizationGuard<'a> {
    table: &'a ProcessTable,
    process: ProcessId,
}

impl Drop for FinalizationGuard<'_> {
    fn drop(&mut self) {
        self.table.release_finalizing(self.process);
    }
}

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
    state: RwLock<ProcessTableInner>,
    changed: tokio::sync::Notify,
    root_initialization: OnceLock<()>,
}

struct ProcessTableInner {
    procs: HashMap<ProcessId, ProcessEntry>,
    children: HashMap<ProcessId, Vec<ProcessId>>,
    tasks: HashMap<ProcessId, task::TaskRecord>,
    capacity: Option<NonZeroUsize>,
    reap_ready: VecDeque<ProcessId>,
    #[cfg(feature = "durable")]
    recovery_closed: bool,
    next: u64,
    next_attached_grant: u64,
}

impl Default for ProcessTableInner {
    fn default() -> Self {
        Self {
            procs: HashMap::new(),
            children: HashMap::new(),
            tasks: HashMap::new(),
            capacity: None,
            reap_ready: VecDeque::new(),
            #[cfg(feature = "durable")]
            recovery_closed: false,
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
                if !entry.scope.request_tree_cleanup() {
                    return false;
                }
                entry
                    .finalization
                    .get_or_insert_with(|| Box::new(Finalization::new()));
                true
            } else {
                false
            }
        });
        descendants
    }
}

impl ProcessTable {
    /// Create an empty process table.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(ProcessTableShared {
                state: RwLock::new(ProcessTableInner::default()),
                changed: tokio::sync::Notify::new(),
                root_initialization: OnceLock::new(),
            }),
        }
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
        let removed = {
            let mut inner = self.inner.state.write();
            inner.check_child_admission(entry.scope.process(), entry.parent)?;
            inner.link_entry(entry)
        };
        drop(removed);
        Ok(())
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

    /// Execution scope retained for administrative lifecycle records.
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

    pub(crate) fn finalization_guard(&self, process: ProcessId) -> FinalizationGuard<'_> {
        FinalizationGuard {
            table: self,
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
            #[cfg(feature = "durable")]
            if matches!(
                entry.checkpoint,
                CheckpointState::Creating | CheckpointState::Active
            ) {
                return None;
            }
            if !entry.scope.complete_finalization() {
                return None;
            }
            let removed = (
                std::mem::take(&mut entry.steps),
                std::mem::take(&mut entry.attached_grants),
                std::mem::take(&mut entry.on_finalize),
                entry.finalization.take(),
                entry.publication.take(),
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

    /// Publication retained until lifecycle records are fully committed.
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
    pub(crate) fn finalizer_failures(&self, id: ProcessId) -> Option<Vec<Value>> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)
            .and_then(|entry| entry.finalization.as_ref())
            .map(|state| {
                state
                    .failures
                    .iter()
                    .map(|(index, error)| finalizer_failure(*index, &error.failure))
                    .collect()
            })
    }

    /// Provenance of the body status and retained results of this finalization.
    pub(crate) fn finalization_taint(&self, id: ProcessId) -> Option<TaintSet> {
        let inner = self.inner.state.read();
        let state = inner.procs.get(&id)?.finalization.as_ref()?;
        let mut taint = state.completed_taint.clone();
        if let Some(output) = &state.outcome {
            taint.union(&output.taint);
        }
        for (_, error) in &state.failures {
            taint.union(&error.taint);
        }
        Some(taint)
    }

    pub(crate) fn retain_finalization_control(
        &self,
        id: ProcessId,
        taint: &TaintSet,
    ) -> Option<()> {
        let mut inner = self.inner.state.write();
        inner
            .procs
            .get_mut(&id)?
            .finalization
            .as_mut()?
            .completed_taint
            .union(taint);
        Some(())
    }

    pub(crate) fn finish_finalizer(&self, id: ProcessId, output: ExecutionOutput) -> Option<()> {
        let mut inner = self.inner.state.write();
        let state = inner.procs.get_mut(&id)?.finalization.as_mut()?;
        let index = state.active.take()?;
        match output.into_result() {
            Ok(value) => state.completed_taint.union(&value.taint),
            Err(error) => state.failures.push((index, error)),
        }
        Some(())
    }

    pub(crate) fn finalization_status(&self, id: ProcessId) -> Option<ProcessStatus> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)?
            .scope
            .terminal_intent()
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

    pub(crate) fn finalization_record(&self, id: ProcessId) -> Option<(Fact, usize)> {
        self.inner
            .state
            .read()
            .procs
            .get(&id)?
            .finalization
            .as_ref()?
            .record
            .clone()
    }

    pub(crate) fn retain_finalization_record(
        &self,
        id: ProcessId,
        fact: Fact,
        closed: usize,
    ) -> Option<()> {
        self.inner
            .state
            .write()
            .procs
            .get_mut(&id)?
            .finalization
            .as_mut()?
            .record = Some((fact, closed));
        Some(())
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
                    if ancestor.scope.cleanup_scope() == Some(CleanupScope::Tree) {
                        return None;
                    }
                    parent = ancestor.parent;
                }
                Some(*id)
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
        Some((
            entry.scope.cleanup_scope() == Some(CleanupScope::Tree),
            status,
        ))
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
    #[cfg(any(test, feature = "durable"))]
    pub(crate) fn exists(&self, id: ProcessId) -> bool {
        self.inner.state.read().procs.contains_key(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

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
            entry.scope.restore_lifecycle(
                status,
                (status == ProcessStatus::Finalizing).then_some(ProcessStatus::Cancelled),
            )?;
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

        ensure!(table.request_cleanup_tree(parent) == vec![descendant, child]);
        ensure!(table.status(parent) == Some(ProcessStatus::Completed));
        ensure!(table.finalization_status(child) == Some(ProcessStatus::Cancelled));
        ensure!(table.finalization_status(descendant) == Some(ProcessStatus::Cancelled));
        ensure!(table.pending_cleanup() == vec![child]);
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
        ensure!(table.request_cleanup_tree(parent) == vec![child]);
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
                },
            )
            .context("missing retained outcome")?;
        let again = table
            .retain_outcome(
                process,
                ExecutionOutput {
                    outcome: Outcome::Done(Value::integer(8)),
                    taint: TaintSet::pristine(),
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
