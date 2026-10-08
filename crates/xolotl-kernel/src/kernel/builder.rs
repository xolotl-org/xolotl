//! Construction-time mechanism selection, separate from shared runtime state.

use super::*;
use crate::runtime_domain::RuntimeDomain;
use std::num::NonZeroUsize;

/// Select mechanisms before creating a runtime's related tables and ports.
///
/// Construction starts no tasks or listeners, issues no identities and performs
/// no persistent I/O. Initialize the root separately with [`crate::Bootstrap`],
/// then install providers in the host's startup sequence.
/// Already active registries and process/handle tables cannot be spliced into
/// this assembly; trusted hosts can compose [`Executor`] and [`DataPlane`]
/// directly when they need a different execution context.
pub struct KernelBuilder {
    state: Backend,
    facts: Option<FactSink>,
    fact_io_mode: crate::dataplane::FactIoMode,
    execution_config: ExecutionConfig,
    execution_ids: Option<ExecutionIds>,
    identity_directory: Option<Arc<dyn crate::identity::IdentityDirectory>>,
    host_runtime: Option<HostRuntime>,
    process_capacity: Option<NonZeroUsize>,
    handle_slot_limit: Option<usize>,
    open_cache_capacity: Option<usize>,
    async_process_host: Option<Arc<dyn crate::host::async_process::AsyncProcessHost>>,
}

impl KernelBuilder {
    /// Start with the host-selected State ports and default execution mechanisms.
    /// Ordinary request completion needs no State write port. An empty
    /// [`Backend`] supports executions whose resources and publications need no State ports.
    pub fn new(state: Backend) -> Self {
        Self {
            state,
            facts: None,
            fact_io_mode: crate::dataplane::FactIoMode::Inline,
            execution_config: ExecutionConfig::default(),
            execution_ids: None,
            identity_directory: None,
            host_runtime: None,
            process_capacity: None,
            handle_slot_limit: None,
            open_cache_capacity: None,
            async_process_host: None,
        }
    }

    /// Start with an in-memory State backend for embedded and test hosts.
    #[cfg(any(test, feature = "memory"))]
    pub fn in_memory() -> Self {
        Self::new(xolotl_state::InMemoryBackend::new().into_backend())
    }

    /// Use an explicit fact sink.
    pub fn with_fact_sink(mut self, facts: FactSink) -> Self {
        self.facts = Some(facts);
        self
    }

    /// Select inline or bounded blocking Fact I/O for hosted calls, including
    /// accepted-replay reads. Choose blocking for a synchronous persistent Fact
    /// store. Direct calls to the storage port remain synchronous.
    pub fn with_fact_io_mode(mut self, mode: crate::dataplane::FactIoMode) -> Self {
        self.fact_io_mode = mode;
        self
    }

    /// Set the default interpreter storage and work limits inherited by executors.
    /// Trusted hosts retain per-executor overrides; services must enforce their
    /// own request ceilings.
    pub fn with_execution_config(mut self, config: ExecutionConfig) -> Self {
        self.execution_config = config;
        self
    }

    /// Limit retained processes, including the root and pending cleanup.
    /// Use [`ProcessTable::reap_finalized`] to release completed leaves, or
    /// [`ProcessTable::set_capacity`] to update this shared admission limit.
    /// Facts and state have separate retention policies.
    pub fn with_process_capacity(mut self, capacity: NonZeroUsize) -> Self {
        self.process_capacity = Some(capacity);
        self
    }

    /// Limit allocated handle slot indices across all executors sharing this
    /// Kernel. Zero admits no handles; vacant indices can be reused. The limit
    /// is fixed for the table's lifetime and does not bound captured payloads.
    pub fn with_handle_slot_limit(mut self, limit: usize) -> Self {
        self.handle_slot_limit = Some(limit);
        self
    }

    /// Bound cached open plans by entry count; zero disables the cache.
    /// This does not bound memory retained by native drivers or policies.
    pub fn with_open_cache_capacity(mut self, capacity: usize) -> Self {
        self.open_cache_capacity = Some(capacity);
        self
    }

    /// Select a shared execution ID source independently of observed Facts.
    /// Hosts exposing retained operation identities must retain their source as well.
    pub fn with_execution_ids(mut self, ids: ExecutionIds) -> Self {
        self.execution_ids = Some(ids);
        self
    }

    /// Choose the host-owned identity namespace. Persistent directories must
    /// commit a new mapping before returning it to execution or storage.
    pub fn with_identity_directory(
        mut self,
        directory: Arc<dyn crate::identity::IdentityDirectory>,
    ) -> Self {
        self.identity_directory = Some(directory);
        self
    }

    /// Choose the shared task scheduler and clock for hosted execution.
    pub fn with_host_runtime(mut self, runtime: HostRuntime) -> Self {
        self.host_runtime = Some(runtime);
        self
    }

    /// Choose ownership and publication for asynchronous child Operations.
    /// Individual executors may supply a request-specific service.
    pub fn with_async_process_host(
        mut self,
        host: Arc<dyn crate::host::async_process::AsyncProcessHost>,
    ) -> Self {
        self.async_process_host = Some(host);
        self
    }

    /// Create independent runtime tables with the chosen shared ports.
    /// IDs are independent of observation storage. Without an explicit source,
    /// select a fresh in-memory namespace; shared persistent namespaces must
    /// explicitly install their retained ID source. Observations default off.
    /// Reusing a backend in another builder shares that backend, not runtime tables.
    pub fn build(self) -> Kernel {
        let runtime_domain = RuntimeDomain::new();
        let host_runtime = self.host_runtime.unwrap_or_default();
        let identities = self
            .identity_directory
            .map_or_else(IdentityRegistry::in_memory, IdentityRegistry::new);
        let selected_ids = self.execution_ids.unwrap_or_else(|| {
            ExecutionIds::new(Arc::new(crate::InMemoryExecutionIdSource::new()))
        });
        let facts = self
            .facts
            .unwrap_or_else(|| FactSink::disabled(selected_ids.clone()))
            .with_identity_registry(identities.clone())
            .with_execution_ids(selected_ids.clone());
        let registry = self
            .open_cache_capacity
            .map_or_else(Registry::new, Registry::with_open_cache_capacity)
            .with_runtime_domain(runtime_domain.clone());
        let handles = self
            .handle_slot_limit
            .map_or_else(HandleTable::new, HandleTable::with_slot_limit)
            .with_runtime_domain(runtime_domain.clone());
        let processes = self.process_capacity.map_or_else(
            || {
                ProcessTable::with_host_runtime_and_domain(
                    host_runtime.clone(),
                    Some(runtime_domain.clone()),
                )
            },
            |capacity| {
                ProcessTable::with_capacity_runtime_and_domain(
                    capacity,
                    host_runtime.clone(),
                    Some(runtime_domain.clone()),
                )
            },
        );
        Kernel {
            registry,
            handles,
            processes,
            state: self.state,
            execution_config: self.execution_config,
            execution_ids: selected_ids,
            identities,
            host_runtime,
            facts,
            fact_io_mode: self.fact_io_mode,
            async_process_host: self.async_process_host,
        }
    }
}
