//! Bounded metadata observations without copying process trees or grants.

use super::{ProcessEntry, ProcessTable, ProcessTableInner};
use std::{num::NonZeroUsize, ops::Bound};
use xolotl_types::{IdentityRef, ProcessId, ProcessStatus};

/// One process observed while holding a single table read lock.
#[derive(Clone, Debug)]
pub struct ProcessObservation {
    /// Stable runtime process identifier.
    pub process: ProcessId,
    /// Identity used by this process.
    pub identity: IdentityRef,
    /// Current lifecycle state.
    pub status: ProcessStatus,
    /// Parent, when present; clients can assemble trees from paged observations.
    pub parent: Option<ProcessId>,
    /// Direct child count, without allocating the child list.
    pub child_count: usize,
}

/// A live page ordered by process ID; later pages need not share its snapshot.
#[derive(Clone, Debug)]
pub struct ProcessPage {
    /// At most the requested number of metadata rows.
    pub entries: Vec<ProcessObservation>,
    /// Exclusive lower bound for the next page, or `None` at the end.
    pub next: Option<ProcessId>,
}

impl ProcessTableInner {
    fn observation(&self, entry: &ProcessEntry) -> ProcessObservation {
        let process = entry.scope.process();
        ProcessObservation {
            process,
            identity: entry.scope.identity(),
            status: entry.scope.status(),
            parent: entry.parent,
            child_count: self.children.get(&process).map_or(0, Vec::len),
        }
    }
}

impl ProcessTable {
    /// Observe one process without copying its grants, children or fact history.
    pub fn observe(&self, id: ProcessId) -> Option<ProcessObservation> {
        let inner = self.inner.state.read();
        inner.procs.get(&id).map(|entry| inner.observation(entry))
    }

    /// Read up to `limit` rows after `after`, with O(log N + limit) table work.
    pub fn observe_page(&self, after: Option<ProcessId>, limit: NonZeroUsize) -> ProcessPage {
        let inner = self.inner.state.read();
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut ids = inner.ordered_ids.range((start, Bound::Unbounded));
        let entries: Vec<_> = ids
            .by_ref()
            .take(limit.get())
            .filter_map(|id| inner.procs.get(id).map(|entry| inner.observation(entry)))
            .collect();
        let next = if ids.next().is_some() {
            entries.last().map(|row| row.process)
        } else {
            None
        };
        ProcessPage { entries, next }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

    #[test]
    fn pages_follow_ids_with_gaps_and_project_parent_without_copying_children() -> anyhow::Result<()>
    {
        let table = ProcessTable::new();
        table.insert(ProcessEntry::new(
            ProcessId::new(90),
            None,
            IdentityRef::ROOT,
        ));
        table.insert(ProcessEntry::new(
            ProcessId::new(2),
            None,
            IdentityRef::ROOT,
        ));
        table.insert(ProcessEntry::new(
            ProcessId::new(12),
            Some(ProcessId::new(2)),
            IdentityRef::ROOT,
        ));
        let first = table.observe_page(None, NonZeroUsize::new(2).context("limit")?);
        ensure!(
            first
                .entries
                .iter()
                .map(|r| r.process.get())
                .collect::<Vec<_>>()
                == [2, 12]
        );
        ensure!(first.entries[0].child_count == 1);
        ensure!(first.entries[1].parent == Some(ProcessId::new(2)));
        let second = table.observe_page(first.next, NonZeroUsize::MIN);
        ensure!(second.entries[0].process == ProcessId::new(90));
        ensure!(second.next.is_none());
        ensure!(
            table
                .observe_page(Some(ProcessId::new(100)), NonZeroUsize::MIN)
                .entries
                .is_empty()
        );
        Ok(())
    }
}
