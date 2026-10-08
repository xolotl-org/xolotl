//! The `Kernel` — the assembled runtime.
//!
//! It ties together the control plane (the six-part [`Registry`]), the data
//! plane ([`DataPlane`]: handle table + fact sink), the process table with native
//! modules, and the state backend. [`KernelBuilder`] selects mechanisms before
//! construction. Clones share the resulting runtime tables and ports; configuration
//! remains fixed for their lifetime.

use crate::dataplane::{DataPlane, FactIoMode};
use crate::execution_ids::ExecutionIds;
use crate::executor::{ExecutionConfig, Executor};
use crate::fact::FactSink;
use crate::handle::HandleTable;
use crate::host::HostRuntime;
use crate::identity::IdentityRegistry;
use crate::process::ProcessTable;
use crate::registry::Registry;
use std::sync::Arc;
use xolotl_state::Backend;
use xolotl_types::ProcessId;

mod builder;
pub use builder::KernelBuilder;

/// An assembled runtime with shared tables and fixed mechanism choices.
/// Use [`KernelBuilder`] to choose backends and defaults before construction.
/// Shared table operations remain available through reference accessors.
#[derive(Clone)]
pub struct Kernel {
    /// Control-plane registry for resources, interfaces, drivers, bindings,
    /// grants, policies, and open-plan cache.
    registry: Registry,
    /// Shared table of open handles owned by processes.
    handles: HandleTable,
    /// Observation sink selected by callers independently of execution authority.
    facts: FactSink,
    fact_io_mode: FactIoMode,
    /// Runtime process tree and per-process mutable state.
    processes: ProcessTable,
    /// State-plane backend serving `state://` reads, writes, and subscriptions.
    state: Backend,
    /// Default execution limits inherited by executors created from this kernel.
    execution_config: ExecutionConfig,
    execution_ids: ExecutionIds,
    identities: IdentityRegistry,
    host_runtime: HostRuntime,
    async_process_host: Option<Arc<dyn crate::host::async_process::AsyncProcessHost>>,
}

impl Kernel {
    /// Build a kernel with in-memory State and Facts using the default mechanisms.
    #[cfg(any(test, feature = "memory"))]
    pub fn in_memory() -> Self {
        KernelBuilder::in_memory().build()
    }

    /// Shared registry of resources, interfaces, drivers, bindings and authority.
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Shared table of open handles owned by processes.
    pub fn handles(&self) -> &HandleTable {
        &self.handles
    }

    /// Fact port used for selected call and security observations.
    pub fn facts(&self) -> &FactSink {
        &self.facts
    }

    /// Shared process tree, admission and lifecycle state.
    pub fn processes(&self) -> &ProcessTable {
        &self.processes
    }

    /// State port used by executors and installed providers.
    pub fn state(&self) -> &Backend {
        &self.state
    }

    /// Default limits inherited by this kernel's executors. Trusted hosts may
    /// override them on a separately composed executor; services enforce their
    /// own request ceilings before dispatch.
    pub fn execution_config(&self) -> ExecutionConfig {
        self.execution_config
    }

    /// Shared identity allocator used by evaluations and lifecycle events.
    pub fn execution_ids(&self) -> &ExecutionIds {
        &self.execution_ids
    }

    /// Shared namespace that resolves concrete identity paths to compact refs.
    pub fn identities(&self) -> &IdentityRegistry {
        &self.identities
    }

    /// Scheduler and clock installed for hosted execution and process custody.
    pub fn host_runtime(&self) -> &HostRuntime {
        &self.host_runtime
    }

    /// The data plane view (handle table + fact sink).
    pub fn data_plane(&self) -> DataPlane {
        let plane = DataPlane::new_with_host_runtime(
            self.handles.clone(),
            self.facts.clone(),
            self.state.clone(),
            self.host_runtime.clone(),
        )
        .with_kernel_processes(self.processes.clone())
        .with_fact_io_mode(self.fact_io_mode);
        match &self.async_process_host {
            Some(host) => plane.with_async_process_host(host.clone()),
            None => plane,
        }
    }

    /// An executor bound to `process`, sharing this kernel's data plane,
    /// registry and immutable native module. Signal waits use installed
    /// `subscribe` resources like other operations.
    pub fn executor_for(&self, process: ProcessId) -> Executor {
        Executor::from_kernel(process, self)
            .with_steps(self.processes.steps(process))
            .with_execution_config(self.execution_config)
            .with_execution_ids(self.execution_ids.clone())
            .with_identity_registry(self.identities.clone())
    }
}

#[cfg(test)]
mod tests;
