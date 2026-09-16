//! The `Kernel` — the assembled runtime.
//!
//! It ties together the control plane (the six-part [`Registry`]), the data
//! plane ([`DataPlane`]: handle table + fact sink), the process table with native
//! modules, and the state backend. A [`Kernel`] is cheap to clone (everything is
//! `Arc`-shared) and is the handle every gateway / driver / console reaches the
//! runtime through.

use crate::dataplane::DataPlane;
use crate::execution_ids::ExecutionIds;
use crate::executor::{ExecutionConfig, Executor};
use crate::fact::FactSink;
use crate::handle::HandleTable;
use crate::process::ProcessTable;
use crate::registry::Registry;
use parking_lot::RwLock;
use std::sync::Arc;
use xolotl_state::{Backend, InMemoryBackend};
use xolotl_types::ProcessId;

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
    /// State-plane backend serving `state://` reads, writes, and subscriptions.
    pub state: Backend,
    /// Host execution ceilings inherited by every executor created from this kernel.
    pub execution_config: ExecutionConfig,
    execution_ids: ExecutionIds,
    execution_ids_explicit: bool,
    /// Optional durable interpreter journal, separate from facts and state.
    #[cfg(feature = "durable")]
    pub(crate) checkpoint_store: Option<Arc<dyn crate::executor::durable::CheckpointStore>>,
    #[cfg(feature = "durable")]
    pub(crate) checkpoint_recovery: Option<Arc<crate::bootstrap::durable::RecoveryControl>>,
}

impl Kernel {
    /// Build a kernel with in-memory state and fact stores. Production swaps in
    /// the redb backend via [`Kernel::with_backends`].
    pub fn in_memory() -> Self {
        let (facts, _) = FactSink::in_memory();
        Self::with_backends(InMemoryBackend::new().into_backend(), facts)
    }

    /// Build a kernel with explicit state + fact backends.
    pub fn with_backends(state: Backend, facts: FactSink) -> Self {
        Self {
            registry: Registry::new(),
            handles: Arc::new(RwLock::new(HandleTable::new())),
            execution_ids: facts.execution_ids(),
            execution_ids_explicit: false,
            facts,
            processes: ProcessTable::new(),
            state,
            execution_config: ExecutionConfig::default(),
            #[cfg(feature = "durable")]
            checkpoint_store: None,
            #[cfg(feature = "durable")]
            checkpoint_recovery: None,
        }
    }

    /// Set interpreter admission ceilings before assembling the host.
    pub fn with_execution_config(mut self, config: ExecutionConfig) -> Self {
        self.execution_config = config;
        self
    }

    /// Select an identity namespace independently of facts and checkpoints.
    /// Configure before execution; persisted checkpoints must retain this source.
    /// An explicit source takes precedence over the checkpoint adapter's default.
    pub fn with_execution_ids(mut self, ids: ExecutionIds) -> Self {
        self.execution_ids = ids;
        self.execution_ids_explicit = true;
        self
    }

    /// Shared identity allocator used by evaluations and lifecycle events.
    pub fn execution_ids(&self) -> &ExecutionIds {
        &self.execution_ids
    }

    /// Attach durable execution storage without changing state or fact adapters.
    /// Unless explicitly overridden, its identity source serves all executions.
    /// Configure before running; hosts sharing retained data must share one source.
    #[cfg(feature = "durable")]
    pub fn with_checkpoint_store(
        mut self,
        store: Arc<dyn crate::executor::durable::CheckpointStore>,
    ) -> Self {
        if !self.execution_ids_explicit {
            self.execution_ids = ExecutionIds::new(store.clone());
        }
        self.checkpoint_store = Some(store);
        self.checkpoint_recovery.get_or_insert_with(Arc::default);
        self
    }

    /// Configure shared recovery admission before running this kernel. Ordinary
    /// requests retain their separate process and execution budgets.
    #[cfg(feature = "durable")]
    pub fn with_checkpoint_recovery_config(
        mut self,
        config: crate::bootstrap::DurableRecoveryConfig,
    ) -> Self {
        self.checkpoint_recovery = Some(Arc::new(crate::bootstrap::durable::RecoveryControl::new(
            config,
        )));
        self
    }

    /// Configured durable storage, shared by executions and recovery sessions.
    #[cfg(feature = "durable")]
    pub fn checkpoint_store(&self) -> Option<&Arc<dyn crate::executor::durable::CheckpointStore>> {
        self.checkpoint_store.as_ref()
    }

    /// The data plane view (handle table + fact sink).
    pub fn data_plane(&self) -> DataPlane {
        DataPlane::new(self.handles.clone(), self.facts.clone(), self.state.clone())
            .with_processes(self.processes.clone())
    }

    /// An executor bound to `process`, sharing this kernel's data plane,
    /// registry, immutable native module, and state backend. The state backend lets
    /// `Wait(Signal)` nodes resolve.
    pub fn executor_for(&self, process: ProcessId) -> Executor {
        let executor = Executor::new(process, self.data_plane(), self.registry.clone())
            .with_steps(self.processes.steps(process))
            .with_state(self.state.clone())
            .with_processes(self.processes.clone())
            .with_execution_config(self.execution_config)
            .with_execution_ids(self.execution_ids.clone());
        #[cfg(feature = "durable")]
        let executor = match &self.checkpoint_store {
            Some(store) => executor.with_checkpoint_store(store.clone()),
            None => executor,
        };
        executor
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
            iface == xolotl_types::InterfaceId::new(1),
            "unexpected first interface id: {iface:?}"
        );
        let iface2 = k2.registry.next_interface_id();
        ensure!(
            iface2 == xolotl_types::InterfaceId::new(2),
            "shared id counter mismatch: {iface2:?}"
        );
        Ok(())
    }
}
