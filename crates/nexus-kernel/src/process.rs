//! Process table, spawn, and finalize.
//!
//! A [`ProcessEntry`] tracks a live Process's status, parent, grants, budget,
//! and finalizers. Spawn attenuates capabilities (a child's grant cannot
//! exceed its parent's); finalize cancels children, runs finalizers in
//! reverse, revokes handles, and writes a `ProcessFinalized` fact.

use nexus_types::{BudgetSpec, BudgetState, Grant, GrantId, IdentityRef, ProcessId, ProcessStatus};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Live bookkeeping for one Process. The serializable `Process` descriptor
/// lives in `nexus-types`; this is the runtime entry the kernel mutates.
pub struct ProcessEntry {
    /// Process identifier.
    pub id: ProcessId,
    /// Parent process, if this process was spawned by another process.
    pub parent: Option<ProcessId>,
    /// Interned identity this process runs as.
    pub identity: IdentityRef,
    /// Current lifecycle state.
    pub status: ProcessStatus,
    /// Grants held by this process.
    pub grants: Vec<GrantId>,
    /// Request-scoped grants attached directly to this process.
    pub attached_grants: Vec<Grant>,
    /// Current budget counters.
    pub budget: BudgetState,
    /// Per-dimension spending limits. Default is unbounded on every
    /// dimension (a process with no declared budget is unconstrained).
    pub budget_spec: BudgetSpec,
    /// Finalizer programs, run in reverse order on finalize. Stored as
    /// serialized `Do<A>` so they survive recovery; the kernel re-runs them.
    pub on_finalize: Vec<nexus_graph::DoNode>,
}

impl ProcessEntry {
    /// Create a process entry in the `Created` state.
    pub fn new(id: ProcessId, parent: Option<ProcessId>, identity: IdentityRef) -> Self {
        Self {
            id,
            parent,
            identity,
            status: ProcessStatus::Created,
            grants: Vec::new(),
            attached_grants: Vec::new(),
            budget: BudgetState::default(),
            budget_spec: BudgetSpec::default(),
            on_finalize: Vec::new(),
        }
    }
}

/// The process tree: a registry of live processes plus parent/child links,
/// carrying cancellation propagation and capability attenuation.
#[derive(Clone, Default)]
pub struct ProcessTable {
    inner: Arc<RwLock<ProcessTableInner>>,
}

#[derive(Default)]
struct ProcessTableInner {
    procs: HashMap<ProcessId, ProcessEntry>,
    children: HashMap<ProcessId, Vec<ProcessId>>,
    next: u64,
    next_attached_grant: u64,
}

impl ProcessTable {
    /// Create an empty process table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh process id.
    pub fn fresh_id(&self) -> ProcessId {
        let mut inner = self.inner.write();
        inner.next += 1;
        ProcessId::new(inner.next)
    }

    /// Allocate a process-attached grant id.
    pub fn fresh_attached_grant_id(&self) -> GrantId {
        let mut inner = self.inner.write();
        inner.next_attached_grant += 1;
        GrantId::new((1u64 << 63) | inner.next_attached_grant)
    }

    /// Insert a new process entry, linking it under its parent.
    pub fn insert(&self, entry: ProcessEntry) {
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

    /// Update a process status if the process exists.
    pub fn set_status(&self, id: ProcessId, status: ProcessStatus) {
        if let Some(p) = self.inner.write().procs.get_mut(&id) {
            p.status = status;
        }
    }

    /// Return the identity a process runs as.
    pub fn identity(&self, id: ProcessId) -> Option<IdentityRef> {
        self.inner.read().procs.get(&id).map(|p| p.identity)
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

    /// Register a finalizer program to run when `id` finalizes.
    pub fn add_finalizer(&self, id: ProcessId, body: nexus_graph::DoNode) {
        if let Some(p) = self.inner.write().procs.get_mut(&id) {
            p.on_finalize.push(body);
        }
    }

    /// Take the finalizers for a process in reverse order.
    pub fn take_finalizers(&self, id: ProcessId) -> Vec<nexus_graph::DoNode> {
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

    /// Recursively collect a process and all descendants for cancel propagation,
    /// deepest first.
    pub fn subtree_post_order(&self, root: ProcessId) -> Vec<ProcessId> {
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
    pub fn budget_mut<R>(&self, id: ProcessId, f: impl FnOnce(&mut BudgetState) -> R) -> Option<R> {
        self.inner
            .write()
            .procs
            .get_mut(&id)
            .map(|p| f(&mut p.budget))
    }

    /// Set a process's budget spec (limits). Called at spawn / from StartRecord.
    pub fn set_budget_spec(&self, id: ProcessId, spec: BudgetSpec) {
        if let Some(p) = self.inner.write().procs.get_mut(&id) {
            p.budget_spec = spec;
        }
    }

    /// Reserve one operation's estimated cost against `id`'s budget,
    /// pre-debiting under the lock so concurrent ops can't race past the limit.
    /// Returns `Err(dim)` naming the exhausted dimension. A process with no
    /// entry (standalone/test) is treated as unbounded → `Ok(())`.
    pub fn reserve(
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
    pub fn settle(
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
    pub fn count(&self) -> usize {
        self.inner.read().procs.len()
    }

    /// Whether a process id exists in the table.
    pub fn exists(&self, id: ProcessId) -> bool {
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
        t.insert(ProcessEntry::new(p, None, IdentityRef::ROOT));
        t.add_finalizer(p, nexus_graph::DoNode::pure(nexus_types::Value::Int(1)));
        t.add_finalizer(p, nexus_graph::DoNode::pure(nexus_types::Value::Int(2)));
        let fs = t.take_finalizers(p);
        // Added 1 then 2; reverse order runs 2 then 1.
        let first = fs.first().context("missing first finalizer")?;
        ensure!(
            *first == nexus_graph::DoNode::pure(nexus_types::Value::Int(2)),
            "first finalizer mismatch"
        );
        let second = fs.get(1).context("missing second finalizer")?;
        ensure!(
            *second == nexus_graph::DoNode::pure(nexus_types::Value::Int(1)),
            "second finalizer mismatch"
        );
        Ok(())
    }
}
