//! The `Kernel` — the assembled runtime.
//!
//! It ties together the control plane (the six-part [`Registry`]), the data
//! plane ([`DataPlane`]: handle table + fact sink), the process table, the step
//! table, and the state backend. A [`Kernel`] is cheap to clone (everything is
//! `Arc`-shared) and is the handle every gateway / driver / console reaches the
//! runtime through.

use crate::dataplane::DataPlane;
use crate::executor::Executor;
use crate::fact::FactSink;
use crate::handle::HandleTable;
use crate::process::ProcessTable;
use crate::registry::Registry;
use crate::step::StepTable;
use nexus_state::{Backend, InMemoryBackend};
use nexus_types::ProcessId;
use parking_lot::RwLock;
use std::sync::Arc;

/// The assembled kernel. Clone-cheap; all internal state is shared.
#[derive(Clone)]
pub struct Kernel {
    /// Control-plane registry for resources, interfaces, drivers, bindings,
    /// grants, policies, and open-plan cache.
    pub registry: Registry,
    /// Shared table of open handles owned by processes.
    pub handles: Arc<RwLock<HandleTable>>,
    /// Write-ahead fact sink used by data-plane execution and recovery.
    pub facts: FactSink,
    /// Runtime process tree and per-process mutable state.
    pub processes: ProcessTable,
    /// Named pure continuation table used by graph `Step` nodes.
    pub steps: StepTable,
    /// State-plane backend serving `state://` reads, writes, and subscriptions.
    pub state: Backend,
}

impl Kernel {
    /// Build a kernel with in-memory state and fact stores. Production swaps in
    /// the redb backend via [`Kernel::with_backends`].
    pub fn in_memory() -> Self {
        let (facts, _) = FactSink::in_memory();
        Self {
            registry: Registry::new(),
            handles: Arc::new(RwLock::new(HandleTable::new())),
            facts,
            processes: ProcessTable::new(),
            steps: StepTable::new(),
            state: Arc::new(InMemoryBackend::new()),
        }
    }

    /// Build a kernel with explicit state + fact backends.
    pub fn with_backends(state: Backend, facts: FactSink) -> Self {
        Self {
            registry: Registry::new(),
            handles: Arc::new(RwLock::new(HandleTable::new())),
            facts,
            processes: ProcessTable::new(),
            steps: StepTable::new(),
            state,
        }
    }

    /// The data plane view (handle table + fact sink).
    pub fn data_plane(&self) -> DataPlane {
        DataPlane::new(self.handles.clone(), self.facts.clone(), self.state.clone())
            .with_processes(self.processes.clone())
    }

    /// An executor bound to `process`, sharing this kernel's data plane,
    /// registry, step table, and state backend. The state backend lets
    /// `Wait(Signal)` nodes resolve.
    pub fn executor_for(&self, process: ProcessId) -> Executor {
        Executor::new(
            process,
            self.data_plane(),
            self.registry.clone(),
            self.steps.clone(),
        )
        .with_state(self.state.clone())
        .with_processes(self.processes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    #[test]
    fn kernel_clone_shares_state() -> anyhow::Result<()> {
        let k = Kernel::in_memory();
        let k2 = k.clone();
        // Registering on one clone is visible on the other (shared Arc).
        let iface = k.registry.next_interface_id();
        ensure!(
            iface == nexus_types::InterfaceId::new(1),
            "unexpected first interface id: {iface:?}"
        );
        let iface2 = k2.registry.next_interface_id();
        ensure!(
            iface2 == nexus_types::InterfaceId::new(2),
            "shared id counter mismatch: {iface2:?}"
        );
        Ok(())
    }
}
