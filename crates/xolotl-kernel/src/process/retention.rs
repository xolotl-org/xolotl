//! Safe retirement and capacity admission for hosted process records.

use super::{ProcessEntry, ProcessTable, ProcessTableInner, ProcessTableShared};
use std::num::NonZeroUsize;
use xolotl_types::ProcessId;

/// A capacity reduction cannot discard processes or unfinished cleanup work.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("process capacity {limit} is below {retained} retained entries")]
pub struct ProcessCapacityError {
    /// Requested maximum number of retained entries.
    pub limit: usize,
    /// Entries that must first be explicitly finalized and reaped.
    pub retained: usize,
}

/// Process admission failed without replacing entries or starting new execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProcessAdmissionError {
    /// The selected parent is missing or no longer accepts new children.
    #[error("process {process} cannot admit children")]
    Unavailable {
        /// Parent that rejected admission.
        process: ProcessId,
    },
    /// An existing record already owns this process identifier.
    #[error("process {process} is already present")]
    Occupied {
        /// Identifier that cannot be replaced.
        process: ProcessId,
    },
    /// Admission would exceed the table's configured retention capacity.
    #[error("process capacity {limit} is exhausted")]
    Capacity {
        /// Configured maximum retained entries, including the system root.
        limit: usize,
    },
    /// The process identifier space has been exhausted without wrapping.
    #[error("process identifiers exhausted")]
    IdentifierExhausted,
}

impl ProcessTableInner {
    pub(super) fn check_vacancy(&self, id: ProcessId) -> Result<(), ProcessAdmissionError> {
        if self.procs.contains_key(&id) {
            return Err(ProcessAdmissionError::Occupied { process: id });
        }
        if let Some(limit) = self.capacity
            && self.procs.len() >= limit.get()
        {
            return Err(ProcessAdmissionError::Capacity { limit: limit.get() });
        }
        Ok(())
    }

    pub(super) fn check_child_admission(
        &self,
        id: ProcessId,
        parent: Option<ProcessId>,
    ) -> Result<(), ProcessAdmissionError> {
        self.check_vacancy(id)?;
        let unavailable = || ProcessAdmissionError::Unavailable {
            process: parent.unwrap_or(id),
        };
        let entry = parent
            .and_then(|parent| self.procs.get(&parent))
            .ok_or_else(unavailable)?;
        if !entry.accepts_children() {
            return Err(unavailable());
        }
        Ok(())
    }

    pub(super) fn link_entry(&mut self, mut entry: ProcessEntry) -> Option<ProcessEntry> {
        if let Some(parent) = entry.parent {
            if entry.request_authorizer.is_none() {
                entry.request_authorizer = self
                    .procs
                    .get(&parent)
                    .and_then(|entry| entry.request_authorizer.clone());
            }
            let children = self.children.entry(parent).or_default();
            entry.parent_slot = children.len();
            children.push(entry.scope.process());
        }
        self.ordered_ids.insert(entry.scope.process());
        self.procs.insert(entry.scope.process(), entry)
    }

    fn can_reap(&self, id: ProcessId) -> bool {
        self.procs.get(&id).is_some_and(|entry| {
            entry.scope.finalized()
                && entry.cleanup_pin.strong_count() == 0
                && entry.managed_captures == 0
                && entry.request_authorizer.is_none()
                && entry.publication.is_none()
                && entry.steps.is_empty()
                && entry.on_finalize.is_empty()
                && entry.scope.status().is_terminal()
                && !entry.scope.finalizer_active()
                && entry.scope.budget().inflight_ops == 0
                && entry.parent.is_some()
                && !self.tasks.contains_key(&id)
                && self.children.get(&id).is_none_or(Vec::is_empty)
        })
    }

    pub(super) fn queue_reap_if_eligible(&mut self, id: ProcessId) {
        if !self.can_reap(id) {
            return;
        }
        if let Some(entry) = self.procs.get_mut(&id)
            && !entry.reap_queued
        {
            entry.reap_queued = true;
            self.reap_ready.push_back(id);
        }
    }

    pub(super) fn unlink_from_parent(&mut self, entry: &ProcessEntry) {
        let Some(parent) = entry.parent else {
            return;
        };
        if let Some(children) = self.children.get_mut(&parent) {
            children.swap_remove(entry.parent_slot);
            if let Some(moved) = children.get(entry.parent_slot)
                && let Some(moved) = self.procs.get_mut(moved)
            {
                moved.parent_slot = entry.parent_slot;
            }
            if children.is_empty() {
                self.children.remove(&parent);
            }
        }
        self.queue_reap_if_eligible(parent);
    }
}

impl ProcessTable {
    /// Construct an isolated table for internal lifecycle tests. Production
    /// process admission and its shared clock are assembled by KernelBuilder.
    #[cfg(test)]
    pub(crate) fn with_capacity(capacity: NonZeroUsize) -> Self {
        Self::with_capacity_and_runtime(capacity, crate::host::HostRuntime::default())
    }

    #[cfg(test)]
    pub(crate) fn with_capacity_and_runtime(
        capacity: NonZeroUsize,
        host_runtime: crate::host::HostRuntime,
    ) -> Self {
        Self::with_capacity_runtime_and_domain(capacity, host_runtime, None)
    }

    pub(crate) fn with_capacity_runtime_and_domain(
        capacity: NonZeroUsize,
        host_runtime: crate::host::HostRuntime,
        runtime_domain: Option<crate::runtime_domain::RuntimeDomain>,
    ) -> Self {
        Self {
            inner: std::sync::Arc::new(ProcessTableShared {
                runtime_domain,
                state: parking_lot::RwLock::new(ProcessTableInner {
                    capacity: Some(capacity),
                    ..ProcessTableInner::default()
                }),
                changed: tokio::sync::Notify::new(),
                root_initialization: std::sync::OnceLock::new(),
                host_runtime,
            }),
        }
    }

    /// Bound all retained entries, including roots, terminal history and cleanup.
    /// Clones share this limit. Lowering it never evicts entries implicitly.
    pub fn set_capacity(&self, capacity: Option<NonZeroUsize>) -> Result<(), ProcessCapacityError> {
        let mut inner = self.inner.state.write();
        if let Some(limit) = capacity
            && inner.procs.len() > limit.get()
        {
            return Err(ProcessCapacityError {
                limit: limit.get(),
                retained: inner.procs.len(),
            });
        }
        inner.capacity = capacity;
        Ok(())
    }

    /// Maximum retained entries; `None` means no configured limit.
    pub fn capacity(&self) -> Option<NonZeroUsize> {
        self.inner.state.read().capacity
    }

    /// Number of retained entries, including terminal records and roots.
    pub fn len(&self) -> usize {
        self.inner.state.read().procs.len()
    }

    /// Whether this table retains any process entries.
    pub fn is_empty(&self) -> bool {
        self.inner.state.read().procs.is_empty()
    }

    /// Examine at most `limit` queued candidates and remove eligible terminal leaves without changing history
    /// in Fact or state storage. Roots and ancestors of retained children remain.
    ///
    /// Table allocation is retained for reuse; this does not promise an RSS reduction.
    pub fn reap_finalized(&self, limit: usize) -> usize {
        if limit == 0 {
            return 0;
        }
        let removed = {
            let mut inner = self.inner.state.write();
            let mut removed = Vec::new();
            for _ in 0..limit {
                let Some(id) = inner.reap_ready.pop_front() else {
                    break;
                };
                if let Some(entry) = inner.procs.get_mut(&id) {
                    entry.reap_queued = false;
                }
                if !inner.can_reap(id) {
                    continue;
                }
                if let Some(entry) = inner.procs.remove(&id) {
                    inner.ordered_ids.remove(&id);
                    inner.children.remove(&id);
                    inner.unlink_from_parent(&entry);
                    removed.push(entry);
                }
            }
            removed
        };
        let count = removed.len();
        drop(removed);
        if count != 0 {
            self.inner.changed.notify_waiters();
        }
        count
    }

    pub(super) fn reclaim_for_admission(&self) {
        let mut remaining = self.inner.state.read().reap_ready.len();
        while remaining != 0 {
            let examined = remaining.min(32);
            self.reap_finalized(examined);
            remaining -= examined;
            let inner = self.inner.state.read();
            if inner
                .capacity
                .is_none_or(|limit| inner.procs.len() < limit.get())
            {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::FinalizeStart;
    use anyhow::{Context, ensure};
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use xolotl_types::{IdentityRef, ProcessStatus};

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
        table.complete_finalization(id).context("missing process")?;
        drop(guard);
        Ok(())
    }

    #[test]
    fn root_initialization_is_shared_and_fits_minimum_capacity() -> anyhow::Result<()> {
        let table = ProcessTable::with_capacity(NonZeroUsize::MIN);
        ensure!(table.is_empty());
        ensure!(table.inner.state.read().procs.capacity() == 0);
        let calls = AtomicUsize::new(0);
        let ready = AtomicBool::new(false);
        let callback_readable = AtomicBool::new(false);
        let gate = Barrier::new(2);
        std::thread::scope(|scope| -> anyhow::Result<()> {
            let invoke = || {
                gate.wait();
                let shared = table.clone();
                let root = shared.initialize_root(|root| {
                    callback_readable.store(
                        table
                            .inner
                            .state
                            .try_read()
                            .is_some_and(|inner| !inner.procs.contains_key(&root)),
                        Ordering::SeqCst,
                    );
                    calls.fetch_add(1, Ordering::SeqCst);
                    ready.store(true, Ordering::SeqCst);
                });
                (root, ready.load(Ordering::SeqCst))
            };
            let first = scope.spawn(invoke);
            let second = scope.spawn(invoke);
            for task in [first, second] {
                let (root, ready) = task
                    .join()
                    .map_err(|_panic| anyhow::anyhow!("root initialization panicked"))?;
                ensure!(root == ProcessId::new(1) && ready);
            }
            Ok(())
        })?;
        ensure!(calls.load(Ordering::SeqCst) == 1);
        ensure!(callback_readable.load(Ordering::SeqCst));
        ensure!(table.len() == 1);
        let id = table.fresh_id()?;
        ensure!(id == ProcessId::new(2));
        ensure!(
            table.admit_child(ProcessEntry::new(
                id,
                Some(ProcessId::new(1)),
                IdentityRef::ROOT
            )) == Err(ProcessAdmissionError::Capacity { limit: 1 })
        );
        ensure!(table.reap_finalized(usize::MAX) == 0);
        Ok(())
    }

    #[test]
    fn root_registration_can_drop_resources_that_read_the_table() -> anyhow::Result<()> {
        struct ReadOnDrop {
            table: ProcessTable,
            readable: Arc<AtomicBool>,
        }

        impl Drop for ReadOnDrop {
            fn drop(&mut self) {
                self.readable.store(
                    self.table
                        .inner
                        .state
                        .try_read()
                        .is_some_and(|inner| inner.procs.is_empty()),
                    Ordering::SeqCst,
                );
            }
        }

        for table in [
            ProcessTable::new(),
            ProcessTable::with_capacity(NonZeroUsize::MIN),
        ] {
            let readable = Arc::new(AtomicBool::new(false));
            let capture = ReadOnDrop {
                table: table.clone(),
                readable: readable.clone(),
            };
            let root = table.initialize_root(move |_| drop(capture));
            ensure!(readable.load(Ordering::SeqCst));
            ensure!(table.status(root) == Some(ProcessStatus::Running));
            ensure!(table.len() == 1);
        }
        Ok(())
    }

    #[test]
    fn capacity_counts_terminal_custody_until_pin_release() -> anyhow::Result<()> {
        let table = ProcessTable::with_capacity(NonZeroUsize::MIN.saturating_add(1));
        let root = table.initialize_root(|_| {});
        let completed = child(&table, root)?;
        let custody = table
            .cleanup_ticket(completed)
            .map_err(|_error| anyhow::anyhow!("missing custody"))?;
        finish(&table, completed)?;
        ensure!(table.len() == 2);
        let next = table.fresh_id()?;
        ensure!(
            table.admit_child(ProcessEntry::new(next, Some(root), IdentityRef::ROOT))
                == Err(ProcessAdmissionError::Capacity { limit: 2 })
        );
        ensure!(
            table.set_capacity(Some(NonZeroUsize::MIN))
                == Err(ProcessCapacityError {
                    limit: 1,
                    retained: 2
                })
        );
        ensure!(table.capacity() == Some(NonZeroUsize::MIN.saturating_add(1)));
        drop(custody);
        table.admit_child(ProcessEntry::new(next, Some(root), IdentityRef::ROOT))?;
        ensure!(table.status(completed).is_none());
        ensure!(table.children_of(root) == vec![next]);
        ensure!(next.get() > completed.get());
        let observed = table.observe_page(None, NonZeroUsize::MIN.saturating_add(1));
        ensure!(
            observed
                .entries
                .iter()
                .map(|row| row.process)
                .collect::<Vec<_>>()
                == vec![root, next]
        );
        ensure!(observed.next.is_none());
        ensure!(observed.entries[0].child_count == 1);
        table.set_capacity(None)?;
        ensure!(table.capacity().is_none());
        Ok(())
    }

    #[test]
    fn concurrent_admission_cannot_exceed_shared_capacity() -> anyhow::Result<()> {
        let table = ProcessTable::with_capacity(NonZeroUsize::MIN.saturating_add(1));
        let root = table.initialize_root(|_| {});
        let first = table.fresh_id()?;
        let second = table.fresh_id()?;
        let gate = Barrier::new(2);
        let results = std::thread::scope(|scope| -> anyhow::Result<_> {
            let admit = |id| {
                gate.wait();
                table.admit_child(ProcessEntry::new(id, Some(root), IdentityRef::ROOT))
            };
            let first = scope.spawn(move || admit(first));
            let second = scope.spawn(move || admit(second));
            Ok([
                first
                    .join()
                    .map_err(|_panic| anyhow::anyhow!("first admission panicked"))?,
                second
                    .join()
                    .map_err(|_panic| anyhow::anyhow!("second admission panicked"))?,
            ])
        })?;
        ensure!(results.iter().filter(|result| result.is_ok()).count() == 1);
        ensure!(
            results
                .iter()
                .filter(|result| **result == Err(ProcessAdmissionError::Capacity { limit: 2 }))
                .count()
                == 1
        );
        ensure!(table.len() == 2 && table.children_of(root).len() == 1);
        Ok(())
    }

    #[test]
    fn full_capacity_examines_stale_candidates_fairly_in_bounded_batches() -> anyhow::Result<()> {
        let table = ProcessTable::with_capacity(NonZeroUsize::MIN.saturating_add(80));
        let root = table.initialize_root(|_| {});
        let members = (0..80)
            .map(|_| child(&table, root))
            .collect::<anyhow::Result<Vec<_>>>()?;
        for process in &members {
            finish(&table, *process)?;
        }
        let pins = members[..79]
            .iter()
            .map(|process| {
                table
                    .cleanup_ticket(*process)
                    .map_err(|_error| anyhow::anyhow!("missing cleanup identity"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let before = table.inner.state.read().reap_ready.len();
        ensure!(table.reap_finalized(1) == 0);
        ensure!(table.inner.state.read().reap_ready.len() == before - 1);
        let admitted = child(&table, root)?;
        ensure!(table.status(members[79]).is_none());
        ensure!(
            members[..79]
                .iter()
                .all(|process| table.status(*process).is_some())
        );
        ensure!(table.len() == 81);
        ensure!(admitted.get() > members[79].get());
        drop(pins);
        ensure!(table.status(members[0]).is_some());
        child(&table, root)?;
        ensure!(table.status(members[0]).is_none());
        Ok(())
    }

    #[test]
    fn tree_selection_pins_completed_members_across_other_admissions() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let root = table.initialize_root(|_| {});
        let parent = child(&table, root)?;
        let member = child(&table, parent)?;
        finish(&table, member)?;
        let parent_ticket = table
            .cleanup_ticket(parent)
            .map_err(|_error| anyhow::anyhow!("missing parent"))?;
        let selection = table
            .request_tree_cleanup_selection(&parent_ticket)
            .map_err(|_error| anyhow::anyhow!("missing selection"))?;
        child(&table, root)?;
        ensure!(table.status(member) == Some(ProcessStatus::Completed));
        ensure!(selection.contains(member));
        drop(selection);
        ensure!(table.status(member).is_some());
        child(&table, root)?;
        ensure!(table.status(member).is_none());
        ensure!(table.status(parent).is_some());
        Ok(())
    }

    #[test]
    fn completed_ancestors_are_reaped_only_after_all_children() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let root = table.initialize_root(|_| {});
        let parent = child(&table, root)?;
        let descendant = child(&table, parent)?;
        let leaf = child(&table, descendant)?;
        finish(&table, parent)?;
        ensure!(table.reap_finalized(usize::MAX) == 0);
        ensure!(table.is_in_tree(parent, leaf));
        finish(&table, descendant)?;
        ensure!(table.reap_finalized(usize::MAX) == 0);
        finish(&table, leaf)?;
        ensure!(table.reap_finalized(1) == 1);
        ensure!(table.status(leaf).is_none());
        ensure!(table.status(descendant).is_some());
        ensure!(table.reap_finalized(usize::MAX) == 2);
        ensure!(table.children_of(root).is_empty());
        finish(&table, root)?;
        ensure!(table.reap_finalized(usize::MAX) == 0);
        ensure!(table.len() == 1 && table.status(root) == Some(ProcessStatus::Completed));
        Ok(())
    }

    #[test]
    fn sibling_unlink_keeps_swapped_child_position_consistent() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let root = table.initialize_root(|_| {});
        let siblings = [
            child(&table, root)?,
            child(&table, root)?,
            child(&table, root)?,
            child(&table, root)?,
        ];
        for removed in [siblings[1], siblings[3], siblings[0], siblings[2]] {
            finish(&table, removed)?;
            ensure!(table.reap_finalized(1) == 1);
            let inner = table.inner.state.read();
            for (position, id) in inner.children.get(&root).into_iter().flatten().enumerate() {
                let entry = inner
                    .procs
                    .get(id)
                    .context("retained child link is stale")?;
                ensure!(entry.parent_slot == position && entry.parent == Some(root));
            }
        }
        ensure!(table.len() == 1 && table.children_of(root).is_empty());
        Ok(())
    }

    #[test]
    fn reaping_waits_for_the_committing_finalization_guard() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let root = table.initialize_root(|_| {});
        let process = child(&table, root)?;
        ensure!(
            table.begin_finalizing(process, ProcessStatus::Completed) == FinalizeStart::Started
        );
        let guard = table.finalization_guard(process);
        table.mark_terminal_status(process, ProcessStatus::Completed);
        table.complete_finalization(process);
        ensure!(table.reap_finalized(usize::MAX) == 0);
        drop(guard);
        ensure!(table.reap_finalized(usize::MAX) == 1);
        ensure!(table.reap_finalized(usize::MAX) == 0);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn task_exit_queues_a_finalized_leaf_only_after_body_drop() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let root = table.initialize_root(|_| {});
        let process = child(&table, root)?;
        let handles = crate::HandleTable::new();
        let (started, observed) = tokio::sync::oneshot::channel();
        ensure!(
            table
                .spawn_task(process, handles, move |owner| async move {
                    let _owner = owner;
                    let _sent = started.send(());
                    std::future::pending::<()>().await;
                })
                .is_ok()
        );
        observed.await?;
        finish(&table, process)?;
        ensure!(table.reap_finalized(usize::MAX) == 0);
        ensure!(table.abort_task(process));
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            table.wait_for_task_exit(process),
        )
        .await?;
        ensure!(table.reap_finalized(usize::MAX) == 1);
        Ok(())
    }

    #[test]
    fn native_captures_release_before_retirement_under_an_outer_directory_lock()
    -> anyhow::Result<()> {
        struct Capture {
            table: ProcessTable,
            released: Arc<AtomicBool>,
            directory: Arc<parking_lot::Mutex<()>>,
        }
        impl Drop for Capture {
            fn drop(&mut self) {
                self.released.store(
                    self.table.inner.state.try_read().is_some()
                        && self.directory.try_lock().is_some(),
                    Ordering::SeqCst,
                );
            }
        }
        let table = ProcessTable::new();
        let root = table.initialize_root(|_| {});
        let process = table.fresh_id()?;
        let released = Arc::new(AtomicBool::new(false));
        let directory = Arc::new(parking_lot::Mutex::new(()));
        let capture = Capture {
            table: table.clone(),
            released: released.clone(),
            directory: directory.clone(),
        };
        let mut entry = ProcessEntry::new(process, Some(root), IdentityRef::ROOT);
        entry.steps = crate::StepModule::single("capture", move |value, _| {
            let _capture = &capture;
            xolotl_graph::DoNode::pure(value)
        })?;
        table.insert(entry);
        finish(&table, process)?;
        ensure!(released.load(Ordering::SeqCst));
        let _directory = directory.lock();
        ensure!(table.reap_finalized(1) == 1);
        ensure!(released.load(Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn identifier_exhaustion_never_wraps_or_reuses_ids() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        table.inner.state.write().next = u64::MAX - 1;
        ensure!(table.fresh_id()? == ProcessId::new(u64::MAX));
        ensure!(table.fresh_id() == Err(ProcessAdmissionError::IdentifierExhausted));
        ensure!(table.fresh_id() == Err(ProcessAdmissionError::IdentifierExhausted));
        Ok(())
    }
}
