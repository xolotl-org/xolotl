//! Process table, spawn, and finalize.
//!
//! A [`ProcessEntry`] tracks a live Process's status, parent, attached grants,
//! budget, and finalizers. Spawn attenuates capabilities (a child's grant
//! cannot exceed its parent's); finalize cancels children, runs finalizers in
//! reverse, revokes handles, and writes a `ProcessFinalized` fact.

use andrias_types::{
    BudgetSpec, BudgetState, Grant, GrantId, IdentityRef, Path, ProcessId, ProcessStatus, Value,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::task::AbortHandle;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TaskAttachment {
    Attached,
    AlreadyTerminal,
    NoSuchProcess,
    AlreadyAttached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FinalizeStart {
    Started,
    AlreadyFinalizing,
    AlreadyTerminal,
    NoSuchProcess,
}

/// Live bookkeeping for one Process. The serializable `Process` descriptor
/// lives in `andrias-types`; this is the runtime entry the kernel mutates.
pub(crate) struct ProcessEntry {
    /// Process identifier.
    pub(crate) id: ProcessId,
    /// Parent process, if this process was spawned by another process.
    pub(crate) parent: Option<ProcessId>,
    /// Interned identity this process runs as.
    pub(crate) identity: IdentityRef,
    /// Current lifecycle state.
    pub(crate) status: ProcessStatus,
    /// Request-scoped grants attached directly to this process.
    pub(crate) attached_grants: Vec<Grant>,
    /// Current budget counters.
    pub(crate) budget: BudgetState,
    /// Per-dimension spending limits. Default is unbounded on every
    /// dimension (a process with no declared budget is unconstrained).
    pub(crate) budget_spec: BudgetSpec,
    /// Finalizer programs, run in reverse order on finalize.
    pub(crate) on_finalize: Vec<andrias_graph::DoNode>,
    /// Optional directory entry updated for named long-lived processes.
    pub(crate) directory: Option<Path>,
    /// Whether one task is currently running this Process's finalization.
    pub(crate) finalization_in_progress: bool,
    /// Finalizer failures collected before the lifecycle record is durable.
    pub(crate) finalizer_failures: Vec<Value>,
    /// Whether finalizers, handle revocation, and lifecycle recording completed.
    pub(crate) finalized: bool,
}

impl ProcessEntry {
    /// Create a process entry in the `Created` state.
    pub(crate) fn new(id: ProcessId, parent: Option<ProcessId>, identity: IdentityRef) -> Self {
        Self {
            id,
            parent,
            identity,
            status: ProcessStatus::Created,
            attached_grants: Vec::new(),
            budget: BudgetState::default(),
            budget_spec: BudgetSpec::default(),
            on_finalize: Vec::new(),
            directory: None,
            finalization_in_progress: false,
            finalizer_failures: Vec::new(),
            finalized: false,
        }
    }
}

/// The process tree: a registry of live processes plus parent/child links,
/// carrying cancellation propagation and capability attenuation.
#[derive(Clone)]
pub struct ProcessTable {
    inner: Arc<RwLock<ProcessTableInner>>,
}

#[derive(Default)]
struct ProcessTableInner {
    procs: HashMap<ProcessId, ProcessEntry>,
    children: HashMap<ProcessId, Vec<ProcessId>>,
    tasks: HashMap<ProcessId, AbortHandle>,
    next: u64,
    next_attached_grant: u64,
}

impl ProcessTable {
    /// Create an empty process table.
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(ProcessTableInner::default())),
        }
    }

    /// Allocate a fresh process id.
    pub(crate) fn fresh_id(&self) -> ProcessId {
        let mut inner = self.inner.write();
        inner.next += 1;
        ProcessId::new(inner.next)
    }

    /// Allocate a process-attached grant id.
    pub(crate) fn fresh_attached_grant_id(&self) -> GrantId {
        let mut inner = self.inner.write();
        inner.next_attached_grant += 1;
        GrantId::new((1u64 << 63) | inner.next_attached_grant)
    }

    /// Insert a new process entry, linking it under its parent.
    pub(crate) fn insert(&self, entry: ProcessEntry) {
        let mut inner = self.inner.write();
        if let Some(parent) = entry.parent {
            inner.children.entry(parent).or_default().push(entry.id);
        }
        inner.procs.insert(entry.id, entry);
    }

    /// Return the current status for a process.
    pub fn status(&self, id: ProcessId) -> Option<ProcessStatus> {
        self.inner.read().procs.get(&id).map(|p| p.status)
    }

    /// Move a process into Finalizing if no terminal/finalizing owner exists.
    pub(crate) fn begin_finalizing(&self, id: ProcessId) -> FinalizeStart {
        let mut inner = self.inner.write();
        let Some(entry) = inner.procs.get_mut(&id) else {
            return FinalizeStart::NoSuchProcess;
        };
        if entry.finalized {
            return FinalizeStart::AlreadyTerminal;
        }
        if entry.finalization_in_progress {
            return FinalizeStart::AlreadyFinalizing;
        }
        entry.finalization_in_progress = true;
        entry.status = ProcessStatus::Finalizing;
        FinalizeStart::Started
    }

    /// Release the finalization owner after a failed cleanup attempt.
    pub(crate) fn release_finalizing(&self, id: ProcessId) -> Option<()> {
        let mut inner = self.inner.write();
        let entry = inner.procs.get_mut(&id)?;
        if !entry.finalized {
            entry.finalization_in_progress = false;
        }
        Some(())
    }

    /// Record a terminal status before lifecycle side records are committed.
    pub(crate) fn mark_terminal_status(
        &self,
        id: ProcessId,
        status: ProcessStatus,
    ) -> Option<ProcessStatus> {
        let mut inner = self.inner.write();
        let entry = inner.procs.get_mut(&id)?;
        let actual = if entry.status.is_terminal() {
            entry.status
        } else if status.is_terminal() {
            entry.status = status;
            status
        } else {
            entry.status
        };
        Some(actual)
    }

    /// Mark lifecycle cleanup fully complete.
    pub(crate) fn complete_finalization(&self, id: ProcessId) -> Option<()> {
        let mut inner = self.inner.write();
        let entry = inner.procs.get_mut(&id)?;
        entry.finalization_in_progress = false;
        entry.finalizer_failures.clear();
        entry.finalized = true;
        Some(())
    }

    /// Cancel a process unless it has already reached a terminal status.
    pub(crate) fn cancel_if_non_terminal(&self, id: ProcessId) -> Option<bool> {
        let mut inner = self.inner.write();
        let entry = inner.procs.get_mut(&id)?;
        if entry.status.is_terminal() {
            return Some(false);
        }
        entry.status = ProcessStatus::Cancelled;
        Some(true)
    }

    /// Mark cleanup complete and set a terminal status if one has not already
    /// won.
    pub(crate) fn mark_finalized_terminal(
        &self,
        id: ProcessId,
        status: ProcessStatus,
    ) -> Option<ProcessStatus> {
        let mut inner = self.inner.write();
        let entry = inner.procs.get_mut(&id)?;
        let actual = if entry.status.is_terminal() {
            entry.status
        } else if status.is_terminal() {
            entry.status = status;
            status
        } else {
            entry.status
        };
        entry.finalization_in_progress = false;
        entry.finalizer_failures.clear();
        entry.finalized = true;
        Some(actual)
    }

    /// Attach a task abort handle to a running process.
    pub(crate) fn attach_task(&self, id: ProcessId, task: AbortHandle) -> TaskAttachment {
        let mut inner = self.inner.write();
        let Some(entry) = inner.procs.get(&id) else {
            return TaskAttachment::NoSuchProcess;
        };
        if entry.status.is_terminal() {
            return TaskAttachment::AlreadyTerminal;
        }
        if inner.tasks.contains_key(&id) {
            return TaskAttachment::AlreadyAttached;
        }
        inner.tasks.insert(id, task);
        TaskAttachment::Attached
    }

    /// Abort and remove the task attached to a process.
    pub(crate) fn abort_task(&self, id: ProcessId) -> bool {
        match self.inner.write().tasks.remove(&id) {
            Some(task) => {
                task.abort();
                true
            }
            None => false,
        }
    }

    /// Remove the task handle for a process that has already finished.
    pub(crate) fn remove_task(&self, id: ProcessId) -> bool {
        self.inner.write().tasks.remove(&id).is_some()
    }

    /// Return the identity a process runs as.
    pub fn identity(&self, id: ProcessId) -> Option<IdentityRef> {
        self.inner.read().procs.get(&id).map(|p| p.identity)
    }

    /// Directory entry for a named long-lived process.
    pub(crate) fn directory(&self, id: ProcessId) -> Option<Path> {
        self.inner
            .read()
            .procs
            .get(&id)
            .and_then(|p| p.directory.clone())
    }

    /// Request-scoped grants attached directly to a process.
    pub fn attached_grants(&self, id: ProcessId) -> Vec<Grant> {
        self.inner
            .read()
            .procs
            .get(&id)
            .map(|p| p.attached_grants.clone())
            .unwrap_or_default()
    }

    /// All live process ids.
    pub fn all_ids(&self) -> Vec<ProcessId> {
        self.inner.read().procs.keys().copied().collect()
    }

    /// Direct children of a process.
    pub fn children_of(&self, id: ProcessId) -> Vec<ProcessId> {
        self.inner
            .read()
            .children
            .get(&id)
            .cloned()
            .unwrap_or_default()
    }

    /// Take the finalizers for a process in reverse order.
    pub(crate) fn take_finalizers(&self, id: ProcessId) -> Vec<andrias_graph::DoNode> {
        let mut inner = self.inner.write();
        match inner.procs.get_mut(&id) {
            Some(p) => {
                let mut fs = std::mem::take(&mut p.on_finalize);
                fs.reverse();
                fs
            }
            None => Vec::new(),
        }
    }

    /// Finalizer failures retained across finalization retries.
    pub(crate) fn finalizer_failures(&self, id: ProcessId) -> Option<Vec<Value>> {
        self.inner
            .read()
            .procs
            .get(&id)
            .map(|p| p.finalizer_failures.clone())
    }

    /// Replace retained finalizer failures for a Process.
    pub(crate) fn set_finalizer_failures(&self, id: ProcessId, failures: Vec<Value>) -> Option<()> {
        let mut inner = self.inner.write();
        let entry = inner.procs.get_mut(&id)?;
        entry.finalizer_failures = failures;
        Some(())
    }

    /// Recursively collect a process and all descendants for cancel propagation,
    /// deepest first.
    pub(crate) fn subtree_post_order(&self, root: ProcessId) -> Vec<ProcessId> {
        let mut out = Vec::new();
        self.collect_post_order(root, &mut out);
        out
    }

    fn collect_post_order(&self, id: ProcessId, out: &mut Vec<ProcessId>) {
        for child in self.children_of(id) {
            self.collect_post_order(child, out);
        }
        out.push(id);
    }

    /// Mutate a process budget state under the table lock.
    #[cfg(test)]
    pub(crate) fn budget_mut<R>(
        &self,
        id: ProcessId,
        f: impl FnOnce(&mut BudgetState) -> R,
    ) -> Option<R> {
        self.inner
            .write()
            .procs
            .get_mut(&id)
            .map(|p| f(&mut p.budget))
    }

    /// Set a process's budget spec.
    #[must_use]
    pub fn set_budget_spec(&self, id: ProcessId, spec: BudgetSpec) -> bool {
        let mut inner = self.inner.write();
        let Some(p) = inner.procs.get_mut(&id) else {
            return false;
        };
        p.budget_spec = spec;
        true
    }

    /// Reserve one operation's estimated cost against `id`'s budget,
    /// pre-debiting under the lock so concurrent ops can't race past the limit.
    /// Returns `Err(dim)` naming the exhausted dimension. A process with no
    /// entry (standalone/test) is treated as unbounded → `Ok(())`.
    pub(crate) fn reserve(
        &self,
        id: ProcessId,
        est_micro_usd: u64,
        est_tokens: u64,
    ) -> Result<(), String> {
        let mut inner = self.inner.write();
        match inner.procs.get_mut(&id) {
            Some(p) => {
                let spec = p.budget_spec.clone();
                p.budget.try_reserve(&spec, est_micro_usd, est_tokens)
            }
            None => Ok(()),
        }
    }

    /// Settle a previously-reserved operation against its actual cost.
    pub(crate) fn settle(
        &self,
        id: ProcessId,
        reserved_micro_usd: u64,
        actual_micro_usd: u64,
        reserved_tokens: u64,
        actual_tokens: u64,
    ) {
        if let Some(p) = self.inner.write().procs.get_mut(&id) {
            p.budget.settle(
                reserved_micro_usd,
                actual_micro_usd,
                reserved_tokens,
                actual_tokens,
            );
        }
    }

    /// Number of live process entries.
    #[cfg(test)]
    pub(crate) fn count(&self) -> usize {
        self.inner.read().procs.len()
    }

    /// Whether a process id exists in the table.
    pub(crate) fn exists(&self, id: ProcessId) -> bool {
        self.inner.read().procs.contains_key(&id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

    #[test]
    fn spawn_links_parent_child() -> anyhow::Result<()> {
        let t = ProcessTable::new();
        let root = t.fresh_id();
        t.insert(ProcessEntry::new(root, None, IdentityRef::ROOT));
        let child = t.fresh_id();
        t.insert(ProcessEntry::new(child, Some(root), IdentityRef::new(2)));
        ensure!(
            t.children_of(root) == vec![child],
            "child process was not linked to parent"
        );
        Ok(())
    }

    #[test]
    fn subtree_post_order_is_deepest_first() -> anyhow::Result<()> {
        let t = ProcessTable::new();
        let a = t.fresh_id();
        t.insert(ProcessEntry::new(a, None, IdentityRef::ROOT));
        let b = t.fresh_id();
        t.insert(ProcessEntry::new(b, Some(a), IdentityRef::ROOT));
        let c = t.fresh_id();
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
        let p = t.fresh_id();
        let mut entry = ProcessEntry::new(p, None, IdentityRef::ROOT);
        entry
            .on_finalize
            .push(andrias_graph::DoNode::pure(andrias_types::Value::Int(1)));
        entry
            .on_finalize
            .push(andrias_graph::DoNode::pure(andrias_types::Value::Int(2)));
        t.insert(entry);
        let fs = t.take_finalizers(p);
        // Added 1 then 2; reverse order runs 2 then 1.
        let first = fs.first().context("missing first finalizer")?;
        ensure!(
            *first == andrias_graph::DoNode::pure(andrias_types::Value::Int(2)),
            "first finalizer mismatch"
        );
        let second = fs.get(1).context("missing second finalizer")?;
        ensure!(
            *second == andrias_graph::DoNode::pure(andrias_types::Value::Int(1)),
            "second finalizer mismatch"
        );
        Ok(())
    }

    #[test]
    fn begin_finalizing_has_one_owner() -> anyhow::Result<()> {
        let t = ProcessTable::new();
        let p = t.fresh_id();
        let mut entry = ProcessEntry::new(p, None, IdentityRef::ROOT);
        entry.status = ProcessStatus::Running;
        t.insert(entry);

        ensure!(
            t.begin_finalizing(p) == FinalizeStart::Started,
            "running process should enter finalizing once"
        );
        ensure!(
            t.begin_finalizing(p) == FinalizeStart::AlreadyFinalizing,
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
            t.begin_finalizing(p) == FinalizeStart::AlreadyTerminal,
            "finalized process should not re-enter finalizing"
        );
        Ok(())
    }

    #[test]
    fn finalized_terminal_does_not_overwrite_existing_terminal_status() -> anyhow::Result<()> {
        let t = ProcessTable::new();
        let p = t.fresh_id();
        let mut entry = ProcessEntry::new(p, None, IdentityRef::ROOT);
        entry.status = ProcessStatus::Cancelled;
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
        let p = t.fresh_id();
        let mut entry = ProcessEntry::new(p, None, IdentityRef::ROOT);
        entry.status = ProcessStatus::Cancelled;
        t.insert(entry);

        ensure!(
            t.begin_finalizing(p) == FinalizeStart::Started,
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
            t.begin_finalizing(p) == FinalizeStart::AlreadyTerminal,
            "cleanup should not run twice"
        );
        Ok(())
    }
}
