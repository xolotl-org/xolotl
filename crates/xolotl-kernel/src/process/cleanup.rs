//! Process-bound observation and retention for host cleanup custody.

use super::{
    ProcessEntry, ProcessFinalizationReport, ProcessTable, ProcessTableInner, ProcessTableShared,
};
use std::sync::{Arc, Weak};
use xolotl_types::{ProcessId, ProcessStatus};

/// Result of retrying an already selected process cleanup obligation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupProgress {
    /// Lifecycle publication, managed callback captures, body/finalizer ownership,
    /// and direct invocation reservations in the selected scope have completed.
    Completed,
    /// The process has no retained cleanup request. Its execution is unchanged.
    NotRequested,
}

/// Retain one admitted process until its host acknowledges cleanup completion.
///
/// The ticket is bound to its original process table and prevents explicit reap
/// of that entry while any clone remains. It neither retains the kernel nor
/// requests cancellation, changes cleanup scope, or grants execution authority.
/// Obtain it before giving up task ownership; a reaped id is not proof of success.
/// Dropping the last clone permits ordinary retention policy to reap the entry.
#[derive(Clone)]
pub struct CleanupTicket {
    pin: Arc<CleanupPin>,
}

impl CleanupTicket {
    /// Original process whose cleanup the host retains.
    pub fn process(&self) -> ProcessId {
        self.pin.process
    }

    /// Selected terminal result, including a retained decision whose lifecycle
    /// publication has not yet completed.
    ///
    /// This does not prove cleanup completion. A process without a terminal
    /// decision, a dropped table, or a missing identity returns `None`.
    pub fn terminal_status(&self) -> Option<ProcessStatus> {
        let table = self.pin.table.upgrade()?;
        let inner = table.state.read();
        if !self.matches_entry(&inner) {
            return None;
        }
        let scope = &inner.procs.get(&self.process())?.scope;
        scope
            .terminal_intent()
            .or_else(|| scope.status().is_terminal().then_some(scope.status()))
    }

    /// Whether the kernel has committed cleanup and released managed callback
    /// captures, body/finalizer owners, and direct invocation reservations in its
    /// selected Local or Tree scope. Independent descendants do not delay Local.
    /// Publication callbacks alone do not establish this fact. A dropped table
    /// or missing identity is false.
    pub fn is_complete(&self) -> bool {
        let Some(table) = self.pin.table.upgrade() else {
            return false;
        };
        let inner = table.state.read();
        self.matches_entry(&inner) && inner.cleanup_is_complete(self.process())
    }

    /// Clone immutable committed evidence while the original identity is pinned.
    /// The returned report does not retain the table or prevent process retirement.
    pub fn finalization_report(&self) -> Option<Arc<ProcessFinalizationReport>> {
        let table = self.pin.table.upgrade()?;
        let inner = table.state.read();
        if !self.matches_entry(&inner) {
            return None;
        }
        inner
            .procs
            .get(&self.process())?
            .finalization_report
            .clone()
    }

    /// Retain bounded uncertainty even when cleanup publication has not committed.
    /// This observation does not establish cleanup completion.
    pub fn unresolved_operations(&self) -> Option<xolotl_types::UnresolvedOperations> {
        let table = self.pin.table.upgrade()?;
        let inner = table.state.read();
        if !self.matches_entry(&inner) {
            return None;
        }
        let entry = inner.procs.get(&self.process())?;
        entry
            .finalization
            .as_ref()
            .map(|state| state.unresolved_operations.clone())
            .or_else(|| {
                entry
                    .finalization_report
                    .as_ref()
                    .map(|report| report.unresolved_operations.clone())
            })
    }

    pub(crate) fn belongs_to(&self, table: &ProcessTable) -> bool {
        self.pin.table.ptr_eq(&Arc::downgrade(&table.inner))
    }

    fn matches_entry(&self, inner: &ProcessTableInner) -> bool {
        inner
            .procs
            .get(&self.process())
            .is_some_and(|entry| entry.cleanup_pin.ptr_eq(&Arc::downgrade(&self.pin)))
    }
}

impl std::fmt::Debug for CleanupTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CleanupTicket")
            .field("process", &self.process())
            .finish_non_exhaustive()
    }
}

pub(super) struct CleanupPin {
    table: Weak<ProcessTableShared>,
    process: ProcessId,
}

impl Drop for CleanupPin {
    fn drop(&mut self) {
        let Some(table) = self.table.upgrade() else {
            return;
        };
        table.state.write().queue_reap_if_eligible(self.process);
        table.changed.notify_waiters();
    }
}

pub(crate) enum CleanupTicketError {
    Missing,
}

pub(crate) enum CleanupAction {
    Completed,
    NotRequested,
    AwaitOwners,
    Resume,
}

/// Exact retry membership retained through task cancellation.
pub(crate) struct CleanupSelection {
    tickets: Vec<CleanupTicket>,
}

impl CleanupSelection {
    pub(crate) fn tickets(&self) -> &[CleanupTicket] {
        &self.tickets
    }

    pub(crate) fn contains(&self, process: ProcessId) -> bool {
        self.tickets
            .iter()
            .any(|ticket| ticket.process() == process)
    }
}

impl ProcessTableInner {
    fn cleanup_members(&self, process: ProcessId) -> Vec<ProcessId> {
        let Some(owner) = self.procs.get(&process) else {
            return Vec::new();
        };
        if !owner.has_tree_cleanup() {
            return vec![process];
        }
        let mut selected = Vec::new();
        let mut pending = vec![process];
        while let Some(process) = pending.pop() {
            selected.push(process);
            if let Some(children) = self.children.get(&process) {
                pending.extend(children.iter().copied());
            }
        }
        selected.reverse();
        selected
    }

    pub(super) fn cleanup_is_complete(&self, process: ProcessId) -> bool {
        self.procs.contains_key(&process)
            && self.cleanup_members(process).iter().all(|id| {
                self.procs.get(id).is_some_and(|entry| {
                    entry.scope.finalized()
                        && !entry.scope.finalizer_active()
                        && entry.managed_captures == 0
                        && !self.tasks.contains_key(id)
                        && self.local_invocations_settled(*id)
                })
            })
    }

    fn local_invocations_settled(&self, process: ProcessId) -> bool {
        let Some(entry) = self.procs.get(&process) else {
            return false;
        };
        let descendants =
            self.children
                .get(&process)
                .into_iter()
                .flatten()
                .try_fold(0_u64, |total, child| {
                    total.checked_add(u64::from(
                        self.procs.get(child)?.scope.budget().inflight_ops,
                    ))
                });
        descendants == Some(u64::from(entry.scope.budget().inflight_ops))
    }

    pub(super) fn pin_cleanup(
        &mut self,
        table: &Arc<ProcessTableShared>,
        process: ProcessId,
    ) -> Result<CleanupTicket, CleanupTicketError> {
        let entry = self
            .procs
            .get_mut(&process)
            .ok_or(CleanupTicketError::Missing)?;
        Ok(CleanupTicket::pin_entry(table, entry))
    }
}

impl CleanupTicket {
    pub(super) fn pin_entry(table: &Arc<ProcessTableShared>, entry: &mut ProcessEntry) -> Self {
        let process = entry.scope.process();
        let pin = if let Some(pin) = entry.cleanup_pin.upgrade() {
            pin
        } else {
            let pin = Arc::new(CleanupPin {
                table: Arc::downgrade(table),
                process,
            });
            entry.cleanup_pin = Arc::downgrade(&pin);
            pin
        };
        Self { pin }
    }
}

impl ProcessTable {
    pub(crate) fn request_tree_cleanup_selection(
        &self,
        ticket: &CleanupTicket,
    ) -> Result<CleanupSelection, CleanupTicketError> {
        let mut inner = self.inner.state.write();
        if !ticket.matches_entry(&inner) {
            return Err(CleanupTicketError::Missing);
        }
        let members = inner.request_cleanup_tree(ticket.process());
        let mut tickets = Vec::with_capacity(members.len());
        for process in members {
            match inner.pin_cleanup(&self.inner, process) {
                Ok(ticket) => tickets.push(ticket),
                Err(error) => {
                    drop(inner);
                    return Err(error);
                }
            }
        }
        drop(inner);
        self.inner.changed.notify_waiters();
        Ok(CleanupSelection { tickets })
    }

    pub(crate) fn cleanup_ticket(
        &self,
        process: ProcessId,
    ) -> Result<CleanupTicket, CleanupTicketError> {
        self.inner.state.write().pin_cleanup(&self.inner, process)
    }

    pub(crate) fn cleanup_action(&self, ticket: &CleanupTicket) -> Option<CleanupAction> {
        let inner = self.inner.state.read();
        if !ticket.matches_entry(&inner) {
            return None;
        }
        let entry = inner.procs.get(&ticket.process())?;
        if inner.cleanup_is_complete(ticket.process()) {
            return Some(CleanupAction::Completed);
        }
        let members = inner.cleanup_members(ticket.process());
        if members.iter().all(|id| {
            inner
                .procs
                .get(id)
                .is_some_and(|entry| entry.scope.finalized())
        }) {
            return Some(CleanupAction::AwaitOwners);
        }
        let tree = entry.has_tree_cleanup();
        if !tree && entry.scope.cleanup_scope().is_none() {
            return Some(CleanupAction::NotRequested);
        }
        Some(CleanupAction::Resume)
    }

    pub(crate) async fn wait_for_cleanup_owners(&self, ticket: &CleanupTicket) {
        loop {
            let changed = self.inner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if !matches!(
                self.cleanup_action(ticket),
                Some(CleanupAction::AwaitOwners)
            ) {
                return;
            }
            changed.await;
        }
    }

    /// Retain the selected membership through a retry.
    /// Tree closes each selected descendant's admission atomically.
    pub(crate) fn cleanup_selection(
        &self,
        ticket: &CleanupTicket,
    ) -> Result<CleanupSelection, CleanupTicketError> {
        let mut inner = self.inner.state.write();
        if !ticket.matches_entry(&inner) {
            return Err(CleanupTicketError::Missing);
        }
        let members = inner.cleanup_members(ticket.process());
        let tree = inner
            .procs
            .get(&ticket.process())
            .is_some_and(|entry| entry.has_tree_cleanup());
        let inherit_tree = tree;
        let mut pins = Vec::with_capacity(members.len());
        for process in members {
            match inner.pin_cleanup(&self.inner, process) {
                Ok(pin) => pins.push(pin),
                Err(error) => {
                    drop(inner);
                    return Err(error);
                }
            }
        }
        if inherit_tree {
            // The ancestor already selected native Tree, possibly before its
            // own lifecycle completed. Materialize that selection under the
            // same lock as membership/pins, before aborting any selected task.
            for ticket in &pins {
                if let Some(entry) = inner.procs.get_mut(&ticket.process())
                    && entry.scope.request_tree_cleanup()
                {
                    entry
                        .finalization
                        .get_or_insert_with(|| Box::new(super::Finalization::new()));
                }
            }
        }
        drop(inner);
        if inherit_tree {
            self.inner.changed.notify_waiters();
        }
        Ok(CleanupSelection { tickets: pins })
    }
}

#[cfg(test)]
mod tests;
