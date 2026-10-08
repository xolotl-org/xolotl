//! Host adapter for the allocation-free `xolotl-core` execution machine.
//!
//! Both [`ExecutionGraph`] and portable programs lower to the same instructions.
//! The core owns control flow; this adapter owns allocation, scheduling, I/O,
//! authority and live execution scopes.
//!
//! Per node kind:
//! - `Pure` / `Fail` yield a value / failure immediately.
//! - `Operation` issues one data-plane call (optionally records a Fact).
//! - `Step` splices its produced subgraph at the cursor (run-time `AndThen`).
//! - `Branch(OrElse)` runs its guarded arm; on failure routes into `recover`.
//! - `Finally` runs cleanup after success, failure or cooperative cancellation.
//! - `Join(Both)` runs both arms concurrently (async I/O overlap); `Join(Race)`
//!   runs both and takes the first to finish, cancelling the loser.
//! - `Acting` switches block-level identity for its arm.
//! - `Wait` blocks on a signal path or a wall-clock deadline.

use crate::dataplane::DataPlane;
use crate::execution_ids::ExecutionIds;
use crate::host::{ClockDomainError, HostDeadline, HostRuntime};
use crate::identity::IdentityRegistry;
use crate::open::OpenRequest;
use crate::registry::Registry;
use crate::runtime_domain::{RuntimeAssemblyError, check_runtime_domains};
use crate::step::StepModule;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use xolotl_graph::{
    BranchKind, DoNode, EdgeKind, ExecutionGraph, JoinKind, NodeKind, OperationTemplate, StepRef,
    WaitSpec, compile_do,
};
#[cfg(test)]
use xolotl_types::ReplayClass;
use xolotl_types::{
    DriverOutput, ExecutionId, ExecutionOutput, HandleId, IdentityRef, InvocationId, MethodBitmap,
    NodeId, Operation, OperationId, Outcome, ProcessId, ResourceName, RightFlags, Rights, TaintSet,
    TaintedValue, Value,
};

// Host assembly, admission and scheduling are separate from core control flow.
mod buffers;
mod cache;
mod config;
#[cfg(test)]
mod identity_tests;
mod image;
mod machine;
#[cfg(test)]
mod module_tests;
#[cfg(test)]
mod provenance_tests;
#[cfg(test)]
pub(crate) mod signal_tests;
pub use buffers::ExecutionBuffers;
use cache::{
    MethodHandle, MethodHandleKey, MethodHandleMap, MethodMetaKey, MethodMetaMap, OpenHandleKey,
    OpenHandleMap,
};
pub use config::{ExecutionConfig, ExecutionLayout};
pub use image::PreparedProgram;

fn machine_error(message: impl Into<String>) -> xolotl_types::Failure {
    xolotl_types::Failure::policy("executor", message)
}

/// Drives one Process's program to completion. Holds the data plane (for
/// Operation dispatch), the registry (to resolve target names → handles), and
/// an immutable module of named continuations.
pub struct Executor {
    /// Process whose graph this executor is running.
    process: ProcessId,
    /// Data-plane dispatcher used for operation nodes.
    data_plane: DataPlane,
    /// Control-plane registry used before data-plane dispatch to resolve names
    /// and method metadata.
    registry: Registry,
    /// Immutable continuation module for this executor.
    steps: StepModule,
    /// Per-invocation stream destinations supplied by the embedding host.
    streams: Option<crate::host::stream::DynStreamRouter>,
    record_facts: bool,
    /// Optional process table, used to observe cancellation at Operation
    /// boundaries. `None` for standalone executors with a caller supplied
    /// identity and no process lifecycle to honor.
    processes: Option<crate::process::ProcessTable>,
    standalone_identity: Option<IdentityRef>,
    execution_ids: ExecutionIds,
    reserved_execution: AtomicU64,
    identities: IdentityRegistry,
    /// Handles explicitly bound by host code. The acting identity is part of
    /// the key because open-time policy is identity-sensitive.
    open_handles: Arc<parking_lot::RwLock<OpenHandleMap>>,
    /// Method-specific handles opened or bound for one acting identity.
    method_handles: Arc<parking_lot::RwLock<MethodHandleMap>>,
    /// Per-(resource, method) compiled metadata cache: the data
    /// plane must not re-query the Registry on every Operation. The first op on
    /// a (target, method) resolves it once; subsequent ops read this cache, so
    /// the hot path never walks the Registry again.
    method_cache: Arc<parking_lot::RwLock<MethodMetaMap>>,
    /// Whether this executor is running process finalizers.
    finalizer_mode: bool,
    deadline: Option<HostDeadline>,
    host_runtime: HostRuntime,
    execution_config: ExecutionConfig,
}

/// Compiled, cached metadata for one (resource, method): the bit position,
/// id, replay class, supported output modes, and cost — everything the data
/// plane needs to dispatch without touching the Registry again.
struct MethodMeta {
    resource_id: xolotl_types::ResourceId,
    contract: crate::registry::ResourceContract,
    method_index: u32,
    method: xolotl_types::Method,
}

/// A host-supplied handle could not be bound to this executor's named import.
#[derive(Debug, thiserror::Error)]
pub enum HandleBindingError {
    /// The executor's process was removed before binding.
    #[error("execution process {0} no longer exists")]
    NoSuchProcess(ProcessId),
    /// The supplied generational handle has been revoked or released.
    #[error("handle {0} is not live")]
    NoSuchHandle(HandleId),
    /// A live handle belongs to a different process.
    #[error("handle {0} belongs to another process")]
    WrongOwner(HandleId),
    /// The handle resolves to a different resource or concrete path.
    #[error("handle {0} does not bind the requested concrete resource path")]
    WrongTarget(HandleId),
    /// The resolved resource has no method with the requested name.
    #[error("resource has no method named {0}")]
    NoSuchMethod(String),
    /// The handle lacks the frozen method declaration or rights.
    #[error("handle {0} does not implement the requested method contract")]
    WrongMethod(HandleId),
    /// A new binding or method contract would exceed this Executor's quota.
    #[error("executor {0} capacity exhausted")]
    Capacity(&'static str),
    /// The target name did not resolve to a resource.
    #[error(transparent)]
    Resolve(#[from] crate::registry::ResolveError),
}

#[derive(Debug, thiserror::Error)]
enum OpenForExecutorError {
    #[error(transparent)]
    Open(#[from] crate::open::OpenError),
    #[error(transparent)]
    Cache(#[from] CacheQuota),
}

#[derive(Debug, thiserror::Error)]
#[error("executor {0} budget exhausted")]
struct CacheQuota(&'static str);

impl From<CacheQuota> for xolotl_types::Failure {
    fn from(quota: CacheQuota) -> Self {
        cache_budget(quota.0)
    }
}

fn cache_budget(dim: &'static str) -> xolotl_types::Failure {
    xolotl_types::Failure::BudgetExhausted { dim: dim.into() }
}

/// Identity and provenance used at the operation boundary.
#[derive(Clone)]
struct Env {
    acting: IdentityRef,
    /// Provenance of the value flowing into the current node.
    taint: xolotl_types::TaintSet,
}

impl Env {
    fn root(acting: IdentityRef) -> Self {
        Self {
            acting,
            taint: xolotl_types::TaintSet::pristine(),
        }
    }

    /// Derive a child env carrying `taint` as the flowing value's provenance.
    fn with_taint(&self, taint: xolotl_types::TaintSet) -> Self {
        let mut e = self.clone();
        e.taint = taint;
        e
    }
}

impl Executor {
    fn check_cache_path(&self, name: &ResourceName) -> Result<(), CacheQuota> {
        if name
            .path()
            .canonical_len()
            .is_some_and(|bytes| bytes <= self.execution_config.max_cache_path_bytes)
        {
            Ok(())
        } else {
            Err(CacheQuota("executor.cache_path_bytes"))
        }
    }

    fn check_cache_method(&self, method: &str) -> Result<(), CacheQuota> {
        if method.len() <= self.execution_config.max_cache_method_name_bytes {
            Ok(())
        } else {
            Err(CacheQuota("executor.cache_method_name_bytes"))
        }
    }

    /// Create a standalone executor with an explicit process and acting identity.
    /// The trusted host owns this process's lifecycle and cancellation.
    pub fn new(
        process: ProcessId,
        identity: IdentityRef,
        data_plane: DataPlane,
        registry: Registry,
    ) -> Result<Self, RuntimeAssemblyError> {
        check_runtime_domains(&[
            data_plane.handles.runtime_domain(),
            registry.runtime_domain(),
        ])?;
        if data_plane.handles.runtime_domain().is_some() {
            return Err(RuntimeAssemblyError::PartiallyBound);
        }
        Ok(Self::assemble(
            process,
            Some(identity),
            data_plane.without_processes(),
            registry,
        ))
    }

    /// Bind an executor to the identity and lifecycle in a Kernel-owned process
    /// table. Use the associated handle table, registry, and host clock; a
    /// missing process fails closed instead of assuming a root identity.
    pub fn from_process_table(
        process: ProcessId,
        processes: crate::process::ProcessTable,
        data_plane: DataPlane,
        registry: Registry,
    ) -> Result<Self, RuntimeAssemblyError> {
        let data_plane = data_plane.with_processes(processes.clone())?;
        check_runtime_domains(&[processes.runtime_domain(), registry.runtime_domain()])?;
        Ok(Self::assemble_process_bound(
            process, processes, data_plane, registry,
        ))
    }

    pub(crate) fn from_kernel(process: ProcessId, kernel: &crate::Kernel) -> Self {
        Self::assemble_process_bound(
            process,
            kernel.processes().clone(),
            kernel.data_plane(),
            kernel.registry().clone(),
        )
    }

    fn assemble_process_bound(
        process: ProcessId,
        processes: crate::process::ProcessTable,
        data_plane: DataPlane,
        registry: Registry,
    ) -> Self {
        let mut executor = Self::assemble(process, None, data_plane, registry);
        executor.processes = Some(processes);
        executor
    }

    fn assemble(
        process: ProcessId,
        standalone_identity: Option<IdentityRef>,
        data_plane: DataPlane,
        registry: Registry,
    ) -> Self {
        let host_runtime = data_plane.host_runtime().clone();
        Self {
            process,
            execution_ids: data_plane.facts.execution_ids(),
            reserved_execution: AtomicU64::new(0),
            identities: IdentityRegistry::in_memory(),
            data_plane,
            registry,
            steps: StepModule::default(),
            streams: None,
            record_facts: false,
            processes: None,
            standalone_identity,
            open_handles: Arc::new(parking_lot::RwLock::new(OpenHandleMap::default())),
            method_handles: Arc::new(parking_lot::RwLock::new(MethodHandleMap::default())),
            method_cache: Arc::new(parking_lot::RwLock::new(MethodMetaMap::default())),
            finalizer_mode: false,
            deadline: None,
            host_runtime,
            execution_config: ExecutionConfig::default(),
        }
    }

    /// Resolve native and portable continuations in this assembled namespace.
    /// Other executors and the process's configured module remain unchanged.
    pub fn with_steps(mut self, steps: StepModule) -> Self {
        self.steps = steps;
        self
    }

    /// Open independent output ports for streamed operations in this executor.
    pub fn with_stream_router(mut self, streams: crate::host::stream::DynStreamRouter) -> Self {
        self.streams = Some(streams);
        self
    }

    /// Retain call observations for this executor. Disabled by default;
    /// authorization, accounting and unknown-effect tracking are independent.
    pub fn with_fact_recording(mut self, record: bool) -> Self {
        self.record_facts = record;
        self
    }

    /// Revalidate request ownership on every resource call, including inherited children.
    pub fn with_request_authorizer(
        mut self,
        authorizer: Arc<dyn crate::RequestAuthorizer>,
    ) -> Self {
        if let Some(processes) = &self.processes {
            processes.set_request_authorizer(self.process, authorizer.clone());
        }
        self.data_plane = self.data_plane.with_request_authorizer(authorizer);
        self
    }

    /// Route asynchronous child Operations to this request's host service.
    /// The service owns admission, live authority checks and retained results.
    pub fn with_async_process_host(
        mut self,
        host: Arc<dyn crate::host::async_process::AsyncProcessHost>,
    ) -> Self {
        self.data_plane = self.data_plane.with_async_process_host(host);
        self
    }

    /// Select a retained identity namespace independently of host storage.
    pub fn with_execution_ids(mut self, ids: ExecutionIds) -> Self {
        self.execution_ids = ids;
        self
    }

    /// Use the same identity namespace as other entry points in this host.
    pub fn with_identity_registry(mut self, identities: IdentityRegistry) -> Self {
        self.identities = identities;
        self
    }

    /// Bound interpreter storage and cooperative work before starting a program.
    /// Set cache quotas before binding handles or preparing operations; reducing
    /// a quota later does not evict already accepted frozen entries.
    pub fn with_execution_config(mut self, config: ExecutionConfig) -> Self {
        self.execution_config = config;
        self
    }

    /// Stop this evaluation at an absolute host deadline, preserving live provenance.
    /// The request owner remains responsible for asynchronous process finalization.
    /// Repeated calls may shorten that deadline but cannot extend or remove it.
    pub fn with_deadline(mut self, deadline: HostDeadline) -> Result<Self, ClockDomainError> {
        self.host_runtime.validate_deadline(deadline)?;
        let deadline = match self.deadline {
            Some(saved) => saved.earliest(deadline)?,
            None => deadline,
        };
        self.deadline = Some(deadline);
        self.data_plane = self.data_plane.with_deadline(deadline)?;
        Ok(self)
    }

    fn deadline_elapsed(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| deadline.elapsed_at(self.host_runtime.now()).unwrap_or(true))
    }

    fn failed(failure: xolotl_types::Failure, taint: TaintSet) -> ExecutionOutput {
        ExecutionOutput::new(Outcome::Fail(failure), taint)
    }

    /// A cached range is local and cheap. Only a refill can call a persistent
    /// source, so schedule that part through the host's bounded blocking port.
    async fn allocate_execution_async(&self) -> Result<ExecutionId, xolotl_types::Failure> {
        if let Some(execution) =
            ExecutionId::new(self.reserved_execution.swap(0, Ordering::Relaxed))
        {
            return Ok(execution);
        }
        let execution = if let Some(execution) = self.execution_ids.try_allocate_cached() {
            execution
        } else {
            let ids = self.execution_ids.clone();
            let worker = self
                .host_runtime
                .dispatch_blocking(move || ids.allocate())
                .map_err(|error| machine_error(format!("execution ID scheduling: {error}")))?;
            worker
                .await
                .map_err(|error| machine_error(format!("execution ID worker: {error}")))?
                .map_err(|error| machine_error(error.to_string()))?
        };
        self.initialize_execution(execution)
    }

    /// Reserve this request's live lifecycle before binding an external service.
    /// The first evaluation on this Executor consumes the same execution identity;
    /// subsequent evaluations allocate distinct identities. No call is dispatched.
    pub async fn reserve_lifecycle(&mut self) -> Result<ExecutionId, xolotl_types::Failure> {
        if let Some(execution) = ExecutionId::new(*self.reserved_execution.get_mut()) {
            return Ok(execution);
        }
        let Some(processes) = &self.processes else {
            return Err(machine_error(
                "lifecycle reservation requires a live process owner",
            ));
        };
        if processes.lifecycle_execution(self.process).is_some() || self.is_cancelled() {
            return Err(machine_error(
                "request lifecycle is already initialized or unavailable",
            ));
        }
        let execution = self.allocate_execution_async().await?;
        if self.is_cancelled() {
            return Err(xolotl_types::Failure::Cancelled);
        }
        if self
            .processes
            .as_ref()
            .and_then(|processes| processes.lifecycle_execution(self.process))
            != Some(execution)
        {
            return Err(machine_error(
                "request lifecycle was initialized by another executor",
            ));
        }
        *self.reserved_execution.get_mut() = execution.get();
        Ok(execution)
    }

    fn initialize_execution(
        &self,
        execution: ExecutionId,
    ) -> Result<ExecutionId, xolotl_types::Failure> {
        if let Some(processes) = &self.processes {
            processes
                .initialize_lifecycle(self.process, execution)
                .ok_or_else(|| machine_error("missing execution process"))?;
        }
        Ok(execution)
    }

    /// Permit Operation nodes while the owning process is in Finalizing.
    pub(crate) fn with_finalizer_mode(mut self) -> Self {
        self.finalizer_mode = true;
        self
    }

    /// Whether this process has been cancelled or moved past Running.
    /// Returns false when no process table is attached (standalone executors).
    fn is_cancelled(&self) -> bool {
        match &self.processes {
            Some(p) => match p.status(self.process) {
                Some(status) if status.is_terminal() => true,
                Some(xolotl_types::ProcessStatus::Finalizing) => !self.finalizer_mode,
                None => true,
                _ => false,
            },
            None => false,
        }
    }

    /// Bind a live, process-owned handle to its concrete resource name.
    ///
    /// The handle's open-time acting identity selects the scope. In particular,
    /// a handle opened for an `Acting` scope can be bound before entering it.
    /// Binding does not authorize entering that scope or preserve a revoked handle.
    pub fn bind_handle(
        &self,
        name: ResourceName,
        handle: HandleId,
    ) -> Result<(), HandleBindingError> {
        let acting = self.binding_acting(&name, None, handle)?;
        let mut bindings = self.open_handles.write();
        if let Some(existing) = bindings.get_mut(&OpenHandleKey {
            name: &name,
            acting,
        }) {
            *existing = handle;
            return Ok(());
        }
        if bindings.len() >= self.execution_config.max_resource_bindings {
            return Err(HandleBindingError::Capacity("resource bindings"));
        }
        self.check_cache_path(&name)
            .map_err(|quota| HandleBindingError::Capacity(quota.0))?;
        bindings.insert((ResourceName::new(name.path().clone()), acting), handle);
        Ok(())
    }

    /// Bind a live handle to one method under its open-time acting identity.
    pub fn bind_method_handle(
        &self,
        name: ResourceName,
        method: impl Into<String>,
        handle: HandleId,
    ) -> Result<(), HandleBindingError> {
        let method = method.into();
        let acting = self.binding_acting(&name, Some(&method), handle)?;
        let mut bindings = self.method_handles.write();
        if let Some(existing) = bindings.get_mut(&MethodHandleKey {
            name: &name,
            method: &method,
            acting,
        }) {
            *existing = MethodHandle::Bound(handle);
            return Ok(());
        }
        if bindings.len() >= self.execution_config.max_method_bindings {
            return Err(HandleBindingError::Capacity("method bindings"));
        }
        self.check_cache_path(&name)
            .and_then(|()| self.check_cache_method(&method))
            .map_err(|quota| HandleBindingError::Capacity(quota.0))?;
        let method = if method.capacity() <= self.execution_config.max_cache_method_name_bytes {
            method
        } else {
            method.as_str().to_owned()
        };
        bindings.insert(
            (ResourceName::new(name.path().clone()), method, acting),
            MethodHandle::Bound(handle),
        );
        Ok(())
    }

    fn binding_acting(
        &self,
        name: &ResourceName,
        method: Option<&str>,
        handle: HandleId,
    ) -> Result<IdentityRef, HandleBindingError> {
        if self
            .processes
            .as_ref()
            .is_some_and(|processes| processes.identity(self.process).is_none())
        {
            return Err(HandleBindingError::NoSuchProcess(self.process));
        }
        let resource = self.registry.resolve_resource(name)?;
        let meta = method
            .map(|method| {
                self.resolve_meta(name, method)
                    .map_err(|quota| HandleBindingError::Capacity(quota.0))?
                    .ok_or_else(|| HandleBindingError::NoSuchMethod(method.to_owned()))
            })
            .transpose()?;
        if meta
            .as_ref()
            .is_some_and(|meta| meta.resource_id != resource)
        {
            return Err(HandleBindingError::WrongTarget(handle));
        }
        let handles = self.data_plane.handles.read();
        let live = handles
            .get(handle)
            .ok_or(HandleBindingError::NoSuchHandle(handle))?;
        if !live.check_owner(self.process) {
            return Err(HandleBindingError::WrongOwner(handle));
        }
        if live.resource != resource || live.bound_path.as_ref() != Some(name.path()) {
            return Err(HandleBindingError::WrongTarget(handle));
        }
        if let Some(meta) = meta
            && (live.open_verb != meta.method.authority.verb()
                || !live.allows_method(meta.method_index)
                || !live.driver_plan.entry(meta.method.id).is_some_and(|entry| {
                    entry.contract.method_index == meta.method_index
                        && entry.declaration() == Some(&meta.method)
                }))
        {
            return Err(HandleBindingError::WrongMethod(handle));
        }
        Ok(live.acting)
    }

    fn default_acting(&self) -> Option<IdentityRef> {
        match &self.processes {
            Some(processes) => processes.identity(self.process),
            None => self.standalone_identity,
        }
    }

    /// Evaluate a whole program with its result provenance. Compiles the `Do<A>` into one
    /// [`ExecutionGraph`], then advances the graph — the Executor never
    /// interprets the source form directly.
    pub async fn eval(&self, program: &DoNode) -> ExecutionOutput {
        self.eval_tainted(program, TaintSet::pristine()).await
    }

    pub(crate) async fn eval_finalizer(
        &self,
        body: &DoNode,
        execution: ExecutionId,
    ) -> ExecutionOutput {
        if self.deadline_elapsed() {
            return Self::failed(xolotl_types::Failure::Timeout, TaintSet::pristine());
        }
        let program = compile_do(body)
            .map_err(|error| machine_error(format!("compile failed: {error}")))
            .and_then(|graph| image::MachineProgram::new(&graph, &self.execution_config));
        let program = match program {
            Ok(program) => program,
            Err(error) => return Self::failed(error, TaintSet::pristine()),
        };
        self.run_machine_with_buffers(
            std::borrow::Cow::Owned(program),
            TaintedValue::pristine(Value::null()),
            &mut ExecutionBuffers::default(),
            Some(execution),
        )
        .await
    }

    /// Advance a compiled graph from its root, preserving result provenance.
    pub async fn eval_graph(&self, graph: &ExecutionGraph) -> ExecutionOutput {
        self.eval_graph_tainted(graph, xolotl_types::TaintSet::pristine())
            .await
    }

    /// Execute a graph with caller-owned reusable mutable storage.
    pub async fn eval_graph_with_buffers(
        &self,
        graph: &ExecutionGraph,
        buffers: &mut ExecutionBuffers,
    ) -> ExecutionOutput {
        if self.deadline_elapsed() {
            return Self::failed(xolotl_types::Failure::Timeout, TaintSet::pristine());
        }
        let program = match image::MachineProgram::new(graph, &self.execution_config) {
            Ok(program) => program,
            Err(error) => return Self::failed(error, TaintSet::pristine()),
        };
        self.run_machine_with_buffers(
            std::borrow::Cow::Owned(program),
            TaintedValue::pristine(Value::null()),
            buffers,
            None,
        )
        .await
    }

    /// Evaluate a program whose entry value carries `entry_taint`.
    ///
    /// Gateways use this for externally-sourced programs, where inbound content
    /// is tainted as `Inbound` so the whole run inherits that lineage.
    pub async fn eval_tainted(
        &self,
        program: &DoNode,
        entry_taint: xolotl_types::TaintSet,
    ) -> ExecutionOutput {
        if self.deadline_elapsed() {
            return Self::failed(xolotl_types::Failure::Timeout, entry_taint);
        }
        let graph = match compile_do(program) {
            Ok(g) => g,
            Err(e) => {
                return Self::failed(machine_error(format!("compile failed: {e}")), entry_taint);
            }
        };
        self.eval_graph_tainted(&graph, entry_taint).await
    }

    /// Advance a compiled graph with a given entry taint.
    async fn eval_graph_tainted(
        &self,
        graph: &ExecutionGraph,
        entry_taint: xolotl_types::TaintSet,
    ) -> ExecutionOutput {
        if self.deadline_elapsed() {
            return Self::failed(xolotl_types::Failure::Timeout, entry_taint);
        }
        let program = match image::MachineProgram::new(graph, &self.execution_config) {
            Ok(program) => program,
            Err(error) => return Self::failed(error, entry_taint),
        };
        self.run_machine(
            std::borrow::Cow::Owned(program),
            TaintedValue::new(Value::null(), entry_taint),
        )
        .await
    }

    /// Await a deadline under the execution's cancellation scope. Signal waits
    /// are lowered to ordinary `subscribe` operations during preparation.
    async fn run_wait(&self, spec: &WaitSpec) -> xolotl_types::DriverOutput {
        match spec {
            WaitSpec::Deadline(at_millis) => {
                loop {
                    let now = self.host_runtime.now_millis();
                    if *at_millis <= now {
                        break;
                    }
                    // Host timers may have finite horizons.
                    // Re-arm distant deadlines without narrowing the wall-clock domain.
                    let dur =
                        std::time::Duration::from_millis(at_millis.abs_diff(now).min(86_400_000));
                    if let Some(deadline) = self.host_runtime.deadline_after(dur) {
                        if let Err(error) = self.host_runtime.sleep_until(deadline).await {
                            return Outcome::Fail(error.into()).into();
                        }
                    } else {
                        return Outcome::Fail(machine_error(
                            "host clock cannot represent wait deadline",
                        ))
                        .into();
                    }
                }
                Outcome::Done(Value::null()).into()
            }
            WaitSpec::Signal(_) => Outcome::Fail(machine_error(
                "signal wait was not lowered to a subscribe operation",
            ))
            .into(),
        }
    }

    /// Resolve a resource method and open its process-owned handle without invoking
    /// the driver. Hosts can preflight all imports before a program has effects.
    /// This caches the same method metadata and handle used during execution;
    /// input-dependent policies, revocation, quotas and deadlines still apply per call.
    pub fn prepare_operation(
        &self,
        template: &OperationTemplate,
    ) -> Result<(), xolotl_types::Failure> {
        if self.is_cancelled() {
            return Err(xolotl_types::Failure::Cancelled);
        }
        let acting = self.default_acting().ok_or_else(|| {
            xolotl_types::Failure::policy("open", "request process no longer exists")
        })?;
        self.prepare_operation_for(acting, template)
    }

    /// Resolve and pre-open an operation for a specific acting identity.
    ///
    /// This verifies the resource method and open-time policy. An `Acting` scope
    /// still checks its `act-as` grant against the value entering that scope;
    /// preflight does not authorize entry or skip per-call policy checks.
    pub fn prepare_operation_for(
        &self,
        acting: IdentityRef,
        template: &OperationTemplate,
    ) -> Result<(), xolotl_types::Failure> {
        if self.is_cancelled() {
            return Err(xolotl_types::Failure::Cancelled);
        }
        if self.deadline_elapsed() {
            return Err(xolotl_types::Failure::Timeout);
        }
        if self.default_acting().is_none() {
            return Err(xolotl_types::Failure::policy(
                "open",
                "request process no longer exists",
            ));
        }
        self.prepare_operation_as(template, acting).map(|_| ())
    }

    fn prepare_operation_as(
        &self,
        template: &OperationTemplate,
        acting: IdentityRef,
    ) -> Result<(HandleId, xolotl_types::MethodId), xolotl_types::Failure> {
        let meta = self
            .resolve_meta(&template.target, &template.method)?
            .ok_or_else(|| xolotl_types::Failure::NoHandler {
                path: template.target.path().clone(),
            })?;
        if !template.output.is_supported_by(meta.method.supports) {
            return Err(xolotl_types::Failure::InvalidInput {
                reason: format!(
                    "method {} does not support output mode {:?}",
                    template.method, template.output
                ),
            });
        }
        let flags = if template.output == xolotl_types::OutputMode::AsyncProcess {
            if !self.data_plane.has_async_process_host() {
                return Err(xolotl_types::Failure::policy(
                    "async-process",
                    "AsyncProcess requires a host owner",
                ));
            }
            RightFlags::SPAWN_WITH
        } else {
            RightFlags::empty()
        };
        let handle = self
            .handle_for_or_open(&template.target, &template.method, acting, &meta, flags)
            .map_err(|error| match error {
                OpenForExecutorError::Cache(quota) => quota.into(),
                OpenForExecutorError::Open(error) => xolotl_types::Failure::policy(
                    "open",
                    format!(
                        "open {} method {} failed for {}: {error}",
                        meta.method.authority.verb(),
                        template.method,
                        template.target.path()
                    ),
                ),
            })?;
        Ok((handle, meta.method.id))
    }

    /// Issue one Operation through the data plane, labelling it with its
    /// stable CausalPosition (the node's id). Resolves the target Resource →
    /// owned Handle, then dispatches. Returns the outcome and the taint that
    /// flows on with the result value.
    async fn run_operation(
        &self,
        tmpl: &OperationTemplate,
        input: Value,
        env: &Env,
        id: OperationId,
        record: bool,
        witness: Option<&std::sync::atomic::AtomicBool>,
    ) -> crate::invocation::InvocationResult {
        let (handle, method_id) = match self.prepare_operation_as(tmpl, env.acting) {
            Ok(prepared) => prepared,
            Err(failure) => {
                return crate::invocation::InvocationResult::new(
                    DriverOutput::new(Outcome::Fail(failure)).with_taint(env.taint.clone()),
                );
            }
        };
        self.dispatch_operation(
            self.operation(tmpl, input, env, id, (handle, method_id)),
            record,
            witness,
        )
        .await
    }

    fn operation(
        &self,
        tmpl: &OperationTemplate,
        input: Value,
        env: &Env,
        id: OperationId,
        prepared: (HandleId, xolotl_types::MethodId),
    ) -> Operation {
        Operation {
            id,
            process: self.process,
            acting: env.acting,
            handle: prepared.0,
            method: prepared.1,
            input: tmpl.literal_input.clone().unwrap_or(input),
            taint: env.taint.clone(),
            output: tmpl.output,
        }
    }

    async fn dispatch_operation(
        &self,
        op: Operation,
        record: bool,
        witness: Option<&std::sync::atomic::AtomicBool>,
    ) -> crate::invocation::InvocationResult {
        let options = crate::InvocationOptions {
            caller_identity: self.default_acting(),
            now_millis: self.host_runtime.now_millis(),
            record,
        };
        if matches!(op.output, xolotl_types::OutputMode::Stream) {
            match self
                .streams
                .as_ref()
                .map(|router| router.open(op.id))
                .transpose()
            {
                Ok(Some(sink)) => {
                    self.data_plane
                        .execute_stream_with_dispatch_witness(&op, options, sink, witness)
                        .await
                }
                Ok(None) => {
                    self.data_plane
                        .execute_with_dispatch_witness(&op, options, witness)
                        .await
                }
                Err(error) => crate::invocation::InvocationResult::new(
                    DriverOutput::new(Outcome::Fail(machine_error(error.to_string())))
                        .with_taint(op.taint.clone()),
                ),
            }
        } else {
            self.data_plane
                .execute_with_dispatch_witness(&op, options, witness)
                .await
        }
    }

    /// Authorize an `Acting(identity)` switch. The process must hold a
    /// grant whose selector is `act-as://<identity>` (matched structurally) and
    /// whose rights carry the `DELEGATE` flag. Selector and inherited constraints
    /// evaluate against the value entering the scope and the current time.
    /// Returns false (deny) otherwise.
    ///
    /// The omnipotent root grant (`*://**` + all flags) covers every identity,
    /// so kernel-internal Acting blocks pass; attenuated children only pass for
    /// identities they were explicitly delegated.
    fn authorize_act_as(&self, identity: &xolotl_types::Path, input: &Value) -> bool {
        let now = self.host_runtime.now_millis();
        let mut grants = self.registry.grants_of(self.process);
        if let Some(processes) = &self.processes {
            grants.extend(processes.attached_grants(self.process));
        }
        grants.into_iter().any(|g| {
            !g.expires.is_expired(now)
                && g.rights.flags.contains(xolotl_types::RightFlags::DELEGATE)
                && g.selector
                    .pattern
                    .covers_with("act-as", identity, input, now)
                && g.constraints.eval(input, now)
        })
    }

    fn handle_for(
        &self,
        name: &ResourceName,
        method: &str,
        acting: IdentityRef,
        meta: &MethodMeta,
        flags: RightFlags,
    ) -> Result<Option<xolotl_types::HandleId>, crate::open::OpenError> {
        let key = MethodHandleKey {
            name,
            method,
            acting,
        };
        let method_binding = self.method_handles.read().get(&key).copied();
        let resource_binding = self
            .open_handles
            .read()
            .get(&OpenHandleKey { name, acting })
            .copied();
        self.handle_for_candidates(method_binding, resource_binding, name, acting, meta, flags)
    }

    fn handle_for_candidates(
        &self,
        method_binding: Option<MethodHandle>,
        resource_binding: Option<HandleId>,
        name: &ResourceName,
        acting: IdentityRef,
        meta: &MethodMeta,
        flags: RightFlags,
    ) -> Result<Option<xolotl_types::HandleId>, crate::open::OpenError> {
        if let Some(MethodHandle::Bound(handle)) = method_binding
            && self.cached_handle_allows(handle, name, acting, meta, flags, false)?
        {
            return Ok(Some(handle));
        }
        if let Some(handle) = resource_binding
            && self.cached_handle_allows(handle, name, acting, meta, flags, false)?
        {
            return Ok(Some(handle));
        }
        if let Some(MethodHandle::Opened(handle)) = method_binding
            && self.cached_handle_allows(handle, name, acting, meta, flags, true)?
        {
            return Ok(Some(handle));
        }
        Ok(None)
    }

    fn cached_handle_allows(
        &self,
        handle: xolotl_types::HandleId,
        name: &ResourceName,
        acting: IdentityRef,
        meta: &MethodMeta,
        flags: RightFlags,
        may_upgrade_flags: bool,
    ) -> Result<bool, crate::open::OpenError> {
        let handles = self.data_plane.handles.read();
        let Some(live) = handles.get(handle) else {
            // Revocation and generation reuse invalidate a cached slot; current
            // authority may still admit a fresh open for this operation.
            return Ok(false);
        };
        if live.check_owner(self.process)
            && live.acting == acting
            && live.resource == meta.resource_id
            && live.bound_path.as_ref() == Some(name.path())
            && live.open_verb == meta.method.authority.verb()
            && live.allows_method(meta.method_index)
            && live.driver_plan.entry(meta.method.id).is_some_and(|entry| {
                entry.contract.method_index == meta.method_index
                    && entry.declaration() == Some(&meta.method)
            })
        {
            if live.rights.flags.contains(flags) {
                Ok(true)
            } else if may_upgrade_flags {
                Ok(false)
            } else {
                Err(crate::open::OpenError::BoundHandleMismatch(handle))
            }
        } else {
            // A live binding has a concrete meaning. Quietly opening another
            // handle would substitute authority chosen by the embedding host.
            Err(crate::open::OpenError::BoundHandleMismatch(handle))
        }
    }

    fn handle_for_or_open(
        &self,
        name: &ResourceName,
        method: &str,
        acting: IdentityRef,
        meta: &MethodMeta,
        flags: RightFlags,
    ) -> Result<xolotl_types::HandleId, OpenForExecutorError> {
        if let Some(handle) = self.handle_for(name, method, acting, meta, flags)? {
            return Ok(handle);
        }
        let key = MethodHandleKey {
            name,
            method,
            acting,
        };
        {
            let cached = self.method_handles.read();
            if !cached.contains_key(&key) {
                if cached.len() >= self.execution_config.max_method_bindings {
                    return Err(CacheQuota("executor.method_bindings").into());
                }
                self.check_cache_path(name)?;
                self.check_cache_method(method)?;
            }
        }
        // Automatic opens can re-prepare after control-plane churn. A prepared
        // plan never skips its install-time dependency check, and each attempt
        // refreshes process-attached authority and the current admission time.
        // Bound retries so a host callback that always edits the registry cannot
        // keep one request in preparation forever.
        let mut retries = 0;
        let handle = loop {
            let attached_grants = self
                .processes
                .as_ref()
                .map(|processes| processes.attached_grants(self.process))
                .unwrap_or_default();
            let prepared = crate::open::prepare_open_with_contract(
                &self.registry,
                OpenRequest {
                    process: self.process,
                    resource: meta.resource_id,
                    verb: meta.method.authority.verb().to_string(),
                    rights: Rights::new(MethodBitmap::method(meta.method_index), flags),
                    acting,
                    requested_path: Some(name.path().clone()),
                    now_millis: self.host_runtime.now_millis(),
                },
                &attached_grants,
                Some(&meta.contract),
            );
            let prepared = match prepared {
                Err(crate::open::OpenError::RegistryChanged) if retries < 2 => {
                    retries += 1;
                    continue;
                }
                result => result?,
            };
            let installed = {
                let mut handles = self.data_plane.handles.write();
                match &self.processes {
                    Some(processes) => prepared.install_for(&mut handles, processes),
                    None => prepared.install_locked(&mut handles),
                }
            };
            match installed {
                Err(crate::open::OpenError::RegistryChanged) if retries < 2 => {
                    retries += 1;
                }
                result => break result?,
            }
        };
        // Preparation can run concurrently. Publish only after rechecking
        // host bindings and another caller's automatic handle. A just-installed
        // candidate is unpublished and safe to revoke; a published predecessor
        // may already back an in-flight call or retained authority.
        let selected = (|| {
            let mut cached = self.method_handles.write();
            let resources = self.open_handles.read();
            let key = MethodHandleKey {
                name,
                method,
                acting,
            };
            let method_binding = cached.get(&key).copied();
            let resource_binding = resources.get(&OpenHandleKey { name, acting }).copied();
            if let Some(existing) = self.handle_for_candidates(
                method_binding,
                resource_binding,
                name,
                acting,
                meta,
                flags,
            )? {
                return Ok(existing);
            }
            if !cached.contains_key(&key) {
                if cached.len() >= self.execution_config.max_method_bindings {
                    return Err(CacheQuota("executor.method_bindings").into());
                }
                self.check_cache_path(name)?;
                self.check_cache_method(method)?;
            }
            if let Some(existing) = cached.get_mut(&key) {
                *existing = MethodHandle::Opened(handle);
            } else {
                cached.insert(
                    (name.clone(), method.to_string(), acting),
                    MethodHandle::Opened(handle),
                );
            }
            Ok(handle)
        })();
        if !matches!(selected, Ok(existing) if existing == handle) {
            self.data_plane.handles.revoke(handle);
        }
        selected
    }

    /// Resolve cached [`MethodMeta`] for a (target, method). A cache miss
    /// walks the Registry once and memoizes; subsequent calls are pure cache
    /// reads, so the per-Operation hot path never re-queries the Registry.
    /// Returns `None` if the resource or method does not resolve while the
    /// cache has room. A full cache rejects an uncached key before resolving
    /// it: evicting a frozen contract could change its meaning.
    fn resolve_meta(
        &self,
        target: &ResourceName,
        method_name: &str,
    ) -> Result<Option<Arc<MethodMeta>>, CacheQuota> {
        let key = MethodMetaKey {
            name: target,
            method: method_name,
        };
        {
            let cache = self.method_cache.read();
            if let Some(meta) = cache.get(&key) {
                return Ok(Some(Arc::clone(meta)));
            }
            // Avoid resolving and cloning a new method contract when this
            // cache cannot admit another key. Publication still rechecks.
            if cache.len() >= self.execution_config.max_method_metadata {
                return Err(CacheQuota("executor.method_metadata"));
            }
        }
        self.check_cache_path(target)?;
        self.check_cache_method(method_name)?;
        let resource_id = match self.registry.resolve_resource(target) {
            Ok(resource_id) => resource_id,
            Err(crate::registry::ResolveError::NoSuchResource(_)) => return Ok(None),
        };
        let Some(compiled) = self.compile_meta(resource_id, method_name) else {
            return Ok(None);
        };
        let mut cache = self.method_cache.write();
        // Concurrent first users may compile while the Registry is changing.
        // The first cached contract owns this Executor's frozen binding.
        if let Some(meta) = cache.get(&key) {
            return Ok(Some(Arc::clone(meta)));
        }
        if cache.len() >= self.execution_config.max_method_metadata {
            return Err(CacheQuota("executor.method_metadata"));
        }
        if compiled.contract.interface_count() > self.execution_config.max_cache_interfaces {
            return Err(CacheQuota("executor.cache_interfaces"));
        }
        let meta = cache
            .entry((target.clone(), method_name.to_owned()))
            .or_insert_with(|| Arc::new(compiled));
        Ok(Some(Arc::clone(meta)))
    }

    /// Compile (method_index, method_id, replay class, supported output modes,
    /// cost) for a target's method by walking the Registry (slow path, cached by
    /// [`resolve_meta`]).
    fn compile_meta(
        &self,
        resource_id: xolotl_types::ResourceId,
        method_name: &str,
    ) -> Option<MethodMeta> {
        let resolved = self
            .registry
            .resolve_method_contract(resource_id, method_name)?;
        let method = resolved.descriptor;
        Some(MethodMeta {
            resource_id,
            contract: resolved.contract,
            method_index: resolved.index,
            method,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{Driver, DriverContext, DriverDescriptor, DriverError, EchoDriver};
    use crate::fact::FactSink;
    use crate::handle::HandleTable;
    use crate::host::{AbortTask, HostClock, TaskSpawnError, TaskSpawner};
    use crate::open::{OpenRequest, open_resource};
    use anyhow::{Context, bail, ensure};
    use std::sync::atomic::{AtomicI64, Ordering};
    use xolotl_state::{Backend, InMemoryBackend};
    use xolotl_types::{
        Binding, ConstraintSet, DriverRef, Expiry, Grant, Interface, InterfaceFamily, InterfaceSet,
        Metadata, Method, MethodBitmap, MethodId, ModalitySet, OutputModeSet, Path, Purity,
        Resource, ResourceDescriptor, ResourceId, ResourceKind, ResourceSelector, RightFlags,
        Rights, SchemaId, TaintSet, TaintSource, Transport,
    };

    fn test_state() -> Backend {
        InMemoryBackend::new().into_backend()
    }

    struct ManualClock {
        origin: std::time::Instant,
        millis: AtomicI64,
    }

    impl HostClock for ManualClock {
        fn monotonic_now(&self) -> std::time::Instant {
            self.origin
                + std::time::Duration::from_millis(self.millis.load(Ordering::SeqCst) as u64)
        }

        fn unix_millis(&self) -> i64 {
            self.millis.load(Ordering::SeqCst)
        }

        fn sleep_until(
            &self,
            deadline: std::time::Instant,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                let millis = deadline.saturating_duration_since(self.origin).as_millis() as i64;
                self.millis.fetch_max(millis, Ordering::SeqCst);
            })
        }
    }

    struct NoTasks;

    impl TaskSpawner for NoTasks {
        fn spawn(
            &self,
            _future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
        ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            Err(TaskSpawnError::Unavailable)
        }
    }

    fn executor() -> Executor {
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(HandleTable::new(), facts, test_state());
        Executor::assemble(
            ProcessId::new(1),
            Some(IdentityRef::ROOT),
            dp,
            Registry::new(),
        )
    }

    fn s(name: &str) -> StepRef {
        StepRef::new(name)
    }

    fn rn(path: &str) -> anyhow::Result<ResourceName> {
        Ok(ResourceName::new(Path::parse(path)?))
    }

    #[derive(Clone)]
    struct TestStateReadDriver {
        state: Backend,
    }

    #[async_trait::async_trait]
    impl Driver for TestStateReadDriver {
        async fn call(
            &self,
            method: MethodId,
            _input: Value,
            _output: xolotl_types::OutputMode,
            ctx: &DriverContext,
        ) -> Result<crate::DriverOutput, DriverError> {
            if method.get() != 0 {
                return Err(DriverError::NoSuchMethod(method));
            }
            let path = ctx
                .target_path
                .clone()
                .ok_or_else(|| DriverError::Other("state read has no bound path".into()))?;
            let tv = self
                .state
                .read_tainted(&path)
                .await
                .map_err(|e| DriverError::Other(e.to_string()))?;
            Ok(
                crate::DriverOutput::new(Outcome::Done(tv.value.unwrap_or_else(Value::null)))
                    .with_taint(tv.taint),
            )
        }
    }

    struct TestResourceSpec {
        path: &'static str,
        kind: ResourceKind,
        addressing: xolotl_types::ResourceAddressing,
        family: InterfaceFamily,
        method_name: &'static str,
        authority: xolotl_types::MethodAuthority,
        method_id: u64,
        purity: Purity,
        replay: ReplayClass,
        driver_name: &'static str,
        selector: &'static str,
        requires_unprotected_input: bool,
    }

    fn register_test_resource(
        reg: &Registry,
        spec: TestResourceSpec,
        driver: Arc<dyn Driver>,
    ) -> anyhow::Result<(ResourceId, ResourceName)> {
        let iface_id = reg.next_interface_id();
        reg.register_interface(Interface {
            id: iface_id,
            family: spec.family,
            methods: vec![Method {
                id: MethodId::new(spec.method_id),
                name: spec.method_name.into(),
                authority: spec.authority,
                input: SchemaId::new(0),
                output: SchemaId::new(0),
                modality: ModalitySet::TEXT,
                purity: spec.purity,
                replay: spec.replay,
                supports: OutputModeSet::UNARY,
                cost: Default::default(),
                batchable: false,
                finalize_allowed: false,
                requires_unprotected_input: spec.requires_unprotected_input,
            }],
            laws: Vec::new(),
        })?;
        let driver_id = reg.next_driver_id();
        reg.register_driver(DriverDescriptor {
            id: driver_id,
            name: spec.driver_name.into(),
            implements: InterfaceSet::new(vec![iface_id]),
            transport: Transport::InProcess,
            driver,
        })?;
        let binding_id = reg.next_binding_id();
        reg.admit_binding(Binding {
            id: binding_id,
            selector: ResourceSelector::parse(spec.selector)?,
            interfaces: InterfaceSet::new(vec![iface_id]),
            driver: DriverRef {
                id: driver_id,
                name: spec.driver_name.into(),
            },
            endpoint: None,
            generation: 1,
        })
        .context("test binding admission failed")?;
        let name = rn(spec.path)?;
        let rid = reg.next_resource_id();
        reg.admit_resource(
            Resource {
                id: rid,
                descriptor: ResourceDescriptor {
                    name: name.clone(),
                    kind: spec.kind,
                    addressing: spec.addressing,
                    metadata: Metadata::default(),
                },
                interfaces: InterfaceSet::new(vec![iface_id]),
                binding: binding_id,
            },
            true,
        )
        .context("test resource admission failed")?;
        Ok((rid, name))
    }

    #[tokio::test]
    async fn pure_evaluates() -> anyhow::Result<()> {
        let ex = executor();
        let out = ex.eval(&DoNode::pure(Value::integer(5))).await;
        ensure!(
            out.outcome == Outcome::Done(Value::integer(5)),
            "pure node outcome mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn attached_missing_process_does_not_run_as_root() -> anyhow::Result<()> {
        let standalone = executor();
        let ex = Executor::from_process_table(
            ProcessId::new(1),
            crate::process::ProcessTable::with_host_runtime_and_domain(
                standalone.data_plane.host_runtime().clone(),
                None,
            ),
            standalone.data_plane,
            standalone.registry,
        )?;
        let out = ex.eval(&DoNode::pure(Value::integer(5))).await;
        ensure!(
            matches!(
                out.outcome,
                Outcome::Fail(xolotl_types::Failure::PolicyViolation {
                    ref policy,
                    ref detail,
                }) if policy == "executor" && detail.contains("unknown process 1")
            ),
            "missing process should fail closed, got {out:?}"
        );
        Ok(())
    }

    #[test]
    fn runtime_tables_reject_mixed_domains_without_restricting_independent_hosts()
    -> anyhow::Result<()> {
        let first = crate::Bootstrap::in_memory();
        let second = crate::Bootstrap::in_memory();
        let first_kernel = first.kernel();
        let second_kernel = second.kernel();
        let process = first.root();
        ensure!(process == second.root());

        ensure!(
            Executor::from_process_table(
                process,
                first_kernel.processes().clone(),
                first_kernel.data_plane(),
                first_kernel.registry().clone(),
            )
            .is_ok()
        );
        ensure!(matches!(
            Executor::new(
                process,
                IdentityRef::ROOT,
                first_kernel.data_plane(),
                first_kernel.registry().clone(),
            ),
            Err(RuntimeAssemblyError::PartiallyBound)
        ));

        ensure!(matches!(
            Executor::from_process_table(
                process,
                first_kernel.processes().clone(),
                first_kernel.data_plane(),
                second_kernel.registry().clone(),
            ),
            Err(RuntimeAssemblyError::DifferentRuntime)
        ));
        ensure!(matches!(
            Executor::new(
                process,
                IdentityRef::ROOT,
                first_kernel.data_plane(),
                second_kernel.registry().clone(),
            ),
            Err(RuntimeAssemblyError::DifferentRuntime)
        ));
        ensure!(matches!(
            Executor::from_process_table(
                process,
                first_kernel.processes().clone(),
                second_kernel.data_plane(),
                first_kernel.registry().clone(),
            ),
            Err(RuntimeAssemblyError::DifferentProcessTable)
        ));
        ensure!(matches!(
            first_kernel
                .data_plane()
                .with_processes(second_kernel.processes().clone()),
            Err(RuntimeAssemblyError::DifferentProcessTable)
        ));
        ensure!(matches!(
            DataPlane::new(
                first_kernel.handles().clone(),
                first_kernel.facts().clone(),
                first_kernel.state().clone(),
            )
            .with_processes(second_kernel.processes().clone()),
            Err(RuntimeAssemblyError::DifferentRuntime)
        ));

        let (facts, _) = FactSink::in_memory();
        let independent = DataPlane::new(HandleTable::new(), facts, test_state());
        ensure!(matches!(
            Executor::from_process_table(
                process,
                crate::process::ProcessTable::new(),
                independent,
                Registry::new(),
            ),
            Err(RuntimeAssemblyError::DifferentClockDomain)
        ));
        let (facts, _) = FactSink::in_memory();
        let independent = DataPlane::new(HandleTable::new(), facts, test_state());
        let independent_processes = crate::process::ProcessTable::with_host_runtime_and_domain(
            independent.host_runtime().clone(),
            None,
        );
        ensure!(
            Executor::from_process_table(
                process,
                independent_processes,
                independent,
                Registry::new(),
            )
            .is_ok()
        );
        let (facts, _) = FactSink::in_memory();
        let independent = DataPlane::new(HandleTable::new(), facts, test_state());
        ensure!(matches!(
            Executor::from_process_table(
                process,
                first_kernel.processes().clone(),
                independent,
                first_kernel.registry().clone(),
            ),
            Err(RuntimeAssemblyError::PartiallyBound)
        ));
        ensure!(matches!(
            DataPlane::new(
                HandleTable::new(),
                first_kernel.facts().clone(),
                test_state()
            )
            .with_processes(first_kernel.processes().clone()),
            Err(RuntimeAssemblyError::PartiallyBound)
        ));

        let upgraded = first_kernel
            .handles()
            .downgrade()
            .upgrade()
            .context("live handle table should upgrade")?;
        ensure!(
            DataPlane::new_with_host_runtime(
                upgraded,
                first_kernel.facts().clone(),
                first_kernel.state().clone(),
                first_kernel.host_runtime().clone(),
            )
            .with_processes(first_kernel.processes().clone())
            .is_ok()
        );
        Ok(())
    }

    #[tokio::test]
    async fn acting_denied_without_delegate_grant() -> anyhow::Result<()> {
        // Process 1 holds no grants (empty registry). An Acting block must be
        // denied fail-closed.
        let ex = executor();
        let prog = DoNode::acting(
            xolotl_types::Path::parse("identity://bob")?,
            DoNode::pure(Value::integer(1)),
        );
        match ex.eval(&prog).await.outcome {
            Outcome::Fail(xolotl_types::Failure::PolicyViolation { policy, .. }) => {
                ensure!(policy == "act-as", "unexpected policy: {policy}");
            }
            other => bail!("expected act-as PolicyViolation, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn acting_allowed_with_delegate_grant() -> anyhow::Result<()> {
        use xolotl_types::{Expiry, Grant, ResourceSelector, RightFlags};
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(HandleTable::new(), facts, test_state());
        let reg = Registry::new();
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("act-as://identity/bob")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::DELEGATE,
            ),
            constraints: xolotl_types::ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let identities = IdentityRegistry::in_memory();
        identities.resolve_or_register(&Path::parse("identity://bob")?)?;
        let ex = Executor::new(ProcessId::new(1), IdentityRef::ROOT, dp, reg)?
            .with_identity_registry(identities);
        let prog = DoNode::acting(
            xolotl_types::Path::parse("identity://bob")?,
            DoNode::pure(Value::integer(7)),
        );
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == Outcome::Done(Value::integer(7)),
            "delegate grant should allow acting, got {out:?}"
        );
        use xolotl_graph::portable::{Expression as E, Program};
        let compiled = Program::new(E::Catch {
            body: Box::new(E::Acting {
                identity: Path::parse("identity://bob")?,
                body: Box::new(E::Input),
            }),
            recover: Box::new(E::Input),
        })
        .compile()?;
        let bounded = ex.with_execution_config(ExecutionConfig {
            max_frames: 2,
            ..ExecutionConfig::default()
        });
        let out = bounded
            .eval_program(&compiled, TaintedValue::pristine(Value::null()))
            .await;
        ensure!(
            matches!(&out.outcome, Outcome::Done(value) if value.as_str().is_some_and(|error| error.contains("continuation capacity"))),
            "capacity rejection should reach the surrounding handler: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn host_can_prebind_a_handle_for_an_acting_scope() -> anyhow::Result<()> {
        let boot = crate::Bootstrap::in_memory();
        let target = boot.register_effect(
            "effect://acting/prebound",
            &[crate::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                crate::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let identity = Path::parse("identity://bob")?;
        let acting = boot.kernel().identities().resolve_or_register(&identity)?;
        let bound = boot.open_for_as(boot.root(), acting, &target, "perform")?;
        let executor = boot.kernel().executor_for(boot.root());
        executor.bind_method_handle(target.clone(), "invoke", bound)?;
        let operation = OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::integer(17)),
        };
        executor.prepare_operation_for(acting, &operation)?;
        let handles_before = boot.kernel().handles().len();
        let meta = executor
            .resolve_meta(&operation.target, &operation.method)?
            .context("prebound method metadata")?;
        ensure!(
            executor.handle_for(
                &operation.target,
                &operation.method,
                acting,
                &meta,
                RightFlags::empty(),
            )? == Some(bound)
        );
        let output = executor
            .eval(&DoNode::acting(identity, DoNode::op(operation)))
            .await;
        ensure!(output.outcome == Outcome::Done(Value::integer(17)));
        ensure!(boot.kernel().handles().len() == handles_before);
        Ok(())
    }

    #[test]
    fn binding_to_a_missing_process_returns_an_error() -> anyhow::Result<()> {
        let standalone = executor();
        let executor = Executor::from_process_table(
            ProcessId::new(1),
            crate::process::ProcessTable::with_host_runtime_and_domain(
                standalone.data_plane.host_runtime().clone(),
                None,
            ),
            standalone.data_plane,
            standalone.registry,
        )?;
        let target = rn("effect://acting/missing-process")?;
        ensure!(matches!(
            executor.bind_handle(target, HandleId::new(0, 1)),
            Err(HandleBindingError::NoSuchProcess(id)) if id == ProcessId::new(1)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_process_short_circuits_at_operation_boundary() -> anyhow::Result<()> {
        // A process marked Cancelled must not issue its Operation: the boundary
        // check short-circuits to Failure::Cancelled.
        use crate::process::{ProcessEntry, ProcessTable};
        use xolotl_graph::OperationTemplate;
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(HandleTable::new(), facts, test_state());
        let procs = ProcessTable::with_host_runtime_and_domain(dp.host_runtime().clone(), None);
        procs.insert(ProcessEntry::new(
            ProcessId::new(1),
            None,
            IdentityRef::ROOT,
        ));
        let cancelled = procs.cancel_if_non_terminal(ProcessId::new(1));
        ensure!(cancelled == Some(true), "process should be cancelled");
        let ex = Executor::from_process_table(ProcessId::new(1), procs, dp, Registry::new())?;
        // A bare Operation node (target need not resolve — the cancel check fires
        // before resource resolution).
        let prog = DoNode::op(OperationTemplate {
            target: rn("effect://x/post")?,
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::null()),
        });
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == Outcome::Fail(xolotl_types::Failure::Cancelled),
            "cancelled process should short-circuit, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bound_handle_must_match_target_resource() -> anyhow::Result<()> {
        let (facts, _) = FactSink::in_memory();
        let handles = HandleTable::new();
        let dp = DataPlane::new(handles.clone(), facts, test_state());
        let reg = Registry::new();
        let (first_resource, first_name) = register_test_resource(
            &reg,
            TestResourceSpec {
                path: "effect://cache/first",
                kind: ResourceKind::Effect,
                addressing: xolotl_types::ResourceAddressing::Exact,
                family: InterfaceFamily::Callable,
                method_name: "invoke",
                authority: xolotl_types::MethodAuthority::Perform,
                method_id: 0,
                purity: Purity::Effectful,
                replay: ReplayClass::NonIdempotentEffect,
                driver_name: "first",
                selector: "perform://effect/cache/first",
                requires_unprotected_input: false,
            },
            Arc::new(EchoDriver),
        )?;
        let (_, second_name) = register_test_resource(
            &reg,
            TestResourceSpec {
                path: "effect://cache/second",
                kind: ResourceKind::Effect,
                addressing: xolotl_types::ResourceAddressing::Exact,
                family: InterfaceFamily::Callable,
                method_name: "invoke",
                authority: xolotl_types::MethodAuthority::Perform,
                method_id: 0,
                purity: Purity::Effectful,
                replay: ReplayClass::NonIdempotentEffect,
                driver_name: "second",
                selector: "perform://effect/cache/second",
                requires_unprotected_input: false,
            },
            Arc::new(EchoDriver),
        )?;
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("perform://effect/cache/first")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("invoke"),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let handle = {
            open_resource(
                &reg,
                &handles,
                OpenRequest {
                    process: ProcessId::new(1),
                    resource: first_resource,
                    verb: "perform".into(),
                    rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                    acting: IdentityRef::ROOT,
                    requested_path: Some(first_name.path().clone()),
                    now_millis: 0,
                },
            )
            .context("first resource open failed")?
        };
        let ex = Executor::new(ProcessId::new(1), IdentityRef::ROOT, dp, reg)?;
        ensure!(matches!(
            ex.bind_handle(second_name.clone(), handle),
            Err(HandleBindingError::WrongTarget(id)) if id == handle
        ));

        let out = ex
            .eval(&DoNode::op(OperationTemplate {
                target: second_name,
                method: "invoke".into(),
                method_id: None,
                output: xolotl_types::OutputMode::Unary,
                literal_input: Some(Value::null()),
            }))
            .await;
        ensure!(
            matches!(
                out.outcome,
                Outcome::Fail(xolotl_types::Failure::PolicyViolation { ref policy, .. })
                    if policy == "open"
            ),
            "mismatched bound handle was accepted: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bound_handle_cannot_change_a_prefix_resources_concrete_target() -> anyhow::Result<()> {
        let state = test_state();
        let requested = Path::parse("state://application/a")?;
        let allowed = Path::parse("state://application/b")?;
        state.write_set(&requested, Value::integer(11)).await?;
        state.write_set(&allowed, Value::integer(22)).await?;

        let registry = Registry::new();
        let (resource, _) = register_test_resource(
            &registry,
            TestResourceSpec {
                path: "state://",
                kind: ResourceKind::State,
                addressing: xolotl_types::ResourceAddressing::Prefix,
                family: InterfaceFamily::Value,
                method_name: "read",
                authority: xolotl_types::MethodAuthority::Read,
                method_id: 0,
                purity: Purity::Pure,
                replay: ReplayClass::Observation,
                driver_name: "bound-state-read",
                selector: "*://state/**",
                requires_unprotected_input: false,
            },
            Arc::new(TestStateReadDriver {
                state: state.clone(),
            }),
        )?;
        registry.register_grant(Grant {
            id: registry.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("read://state/application/b")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("read"),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        // A fresh handle for `a` is authorized. A wrong explicit binding must
        // fail during host assembly without contaminating the cache.
        registry.register_grant(Grant {
            id: registry.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("read://state/application/a")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("read"),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let handles = HandleTable::new();
        let handle = open_resource(
            &registry,
            &handles,
            OpenRequest {
                process: ProcessId::new(1),
                resource,
                verb: "read".into(),
                rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                acting: IdentityRef::ROOT,
                requested_path: Some(allowed.clone()),
                now_millis: 0,
            },
        )?;
        let (facts, _) = FactSink::in_memory();
        let plane = DataPlane::new(handles, facts, state);
        let target = ResourceName::new(requested);
        let operation = OperationTemplate {
            target: target.clone(),
            method: "read".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        };
        for method_specific in [false, true] {
            let executor = Executor::new(
                ProcessId::new(1),
                IdentityRef::ROOT,
                plane.clone(),
                registry.clone(),
            )?;
            let handles_before = plane.handles.len();
            if method_specific {
                ensure!(matches!(
                    executor.bind_method_handle(target.clone(), "read", handle),
                    Err(HandleBindingError::WrongTarget(id)) if id == handle
                ));
                ensure!(executor.method_handles.read().is_empty());
            } else {
                ensure!(matches!(
                    executor.bind_handle(target.clone(), handle),
                    Err(HandleBindingError::WrongTarget(id)) if id == handle
                ));
                ensure!(executor.open_handles.read().is_empty());
            }
            executor.prepare_operation(&operation)?;
            let result = executor.eval(&DoNode::op(operation.clone())).await;
            ensure!(
                result.outcome == Outcome::Done(Value::integer(11)),
                "the rejected binding changed the target: {result:?}"
            );
            ensure!(
                plane.handles.len() == handles_before + 1,
                "a fresh handle for a was not opened"
            );
        }
        Ok(())
    }

    fn prefix_cache_executor(config: ExecutionConfig) -> anyhow::Result<Executor> {
        let state = test_state();
        let registry = Registry::new();
        register_test_resource(
            &registry,
            TestResourceSpec {
                path: "state://",
                kind: ResourceKind::State,
                addressing: xolotl_types::ResourceAddressing::Prefix,
                family: InterfaceFamily::Value,
                method_name: "read",
                authority: xolotl_types::MethodAuthority::Read,
                method_id: 0,
                purity: Purity::Pure,
                replay: ReplayClass::Observation,
                driver_name: "cache-capacity-state-read",
                selector: "*://state/**",
                requires_unprotected_input: false,
            },
            Arc::new(TestStateReadDriver {
                state: state.clone(),
            }),
        )?;
        registry.register_grant(Grant {
            id: registry.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("read://state/**")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("read"),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let (facts, _) = FactSink::in_memory();
        let plane = DataPlane::new(HandleTable::new(), facts, state);
        Ok(
            Executor::new(ProcessId::new(1), IdentityRef::ROOT, plane, registry)?
                .with_execution_config(config),
        )
    }

    fn prefix_read(path: &str) -> anyhow::Result<OperationTemplate> {
        Ok(OperationTemplate {
            target: rn(path)?,
            method: "read".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        })
    }

    #[test]
    fn cache_quotas_distinguish_missing_methods_from_exhausted_capacity() -> anyhow::Result<()> {
        let executor = prefix_cache_executor(ExecutionConfig {
            max_method_metadata: 1,
            max_method_bindings: 1,
            ..ExecutionConfig::default()
        })?;
        let first = prefix_read("state://application/first")?;
        let second = prefix_read("state://application/second")?;
        let missing = OperationTemplate {
            method: "absent".into(),
            ..second.clone()
        };
        ensure!(matches!(
            executor.prepare_operation(&missing),
            Err(xolotl_types::Failure::NoHandler { .. })
        ));
        executor.prepare_operation(&first)?;
        ensure!(matches!(
            executor.prepare_operation(&second),
            Err(xolotl_types::Failure::BudgetExhausted { dim }) if dim == "executor.method_metadata"
        ));
        ensure!(matches!(
            executor.prepare_operation_for(IdentityRef::new(42), &first),
            Err(xolotl_types::Failure::BudgetExhausted { dim }) if dim == "executor.method_bindings"
        ));
        executor.prepare_operation(&first)?;
        ensure!(executor.method_cache.read().len() == 1);
        ensure!(executor.method_handles.read().len() == 1);
        ensure!(executor.data_plane.handles.len() == 1);
        Ok(())
    }

    #[test]
    fn cache_item_size_limits_reject_new_keys_and_frozen_contracts() -> anyhow::Result<()> {
        let first = prefix_read("state://application/a")?;
        let longer = prefix_read("state://application/a/longer")?;
        let path_limit = first
            .target
            .path()
            .canonical_len()
            .context("path length overflow")?;
        let executor = prefix_cache_executor(ExecutionConfig {
            max_cache_path_bytes: path_limit,
            ..ExecutionConfig::default()
        })?;
        executor.prepare_operation(&first)?;
        ensure!(matches!(
            executor.prepare_operation(&longer),
            Err(xolotl_types::Failure::BudgetExhausted { dim }) if dim == "executor.cache_path_bytes"
        ));
        executor.prepare_operation(&first)?;
        ensure!(executor.method_cache.read().len() == 1);
        ensure!(executor.data_plane.handles.len() == 1);

        let method_limited = prefix_cache_executor(ExecutionConfig {
            max_cache_method_name_bytes: 3,
            ..ExecutionConfig::default()
        })?;
        ensure!(matches!(
            method_limited.prepare_operation(&first),
            Err(xolotl_types::Failure::BudgetExhausted { dim }) if dim == "executor.cache_method_name_bytes"
        ));
        ensure!(method_limited.method_cache.read().is_empty());
        ensure!(method_limited.data_plane.handles.len() == 0);

        let interface_limited = prefix_cache_executor(ExecutionConfig {
            max_cache_interfaces: 0,
            ..ExecutionConfig::default()
        })?;
        ensure!(matches!(
            interface_limited.prepare_operation(&first),
            Err(xolotl_types::Failure::BudgetExhausted { dim }) if dim == "executor.cache_interfaces"
        ));
        ensure!(interface_limited.method_cache.read().is_empty());
        ensure!(interface_limited.data_plane.handles.len() == 0);

        let explicit = prefix_cache_executor(ExecutionConfig {
            max_cache_path_bytes: 1,
            ..ExecutionConfig::default()
        })?;
        let resource = explicit.registry.resolve_resource(&first.target)?;
        let handle = open_resource(
            &explicit.registry,
            &explicit.data_plane.handles,
            OpenRequest {
                process: ProcessId::new(1),
                resource,
                verb: "read".into(),
                rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                acting: IdentityRef::ROOT,
                requested_path: Some(first.target.path().clone()),
                now_millis: explicit.host_runtime.now_millis(),
            },
        )?;
        ensure!(matches!(
            explicit.bind_handle(first.target, handle),
            Err(HandleBindingError::Capacity("executor.cache_path_bytes"))
        ));
        ensure!(explicit.open_handles.read().is_empty());
        Ok(())
    }

    #[test]
    fn explicit_binding_quota_allows_replacement_but_not_new_keys() -> anyhow::Result<()> {
        let executor = prefix_cache_executor(ExecutionConfig {
            max_method_metadata: 2,
            max_resource_bindings: 1,
            max_method_bindings: 1,
            ..ExecutionConfig::default()
        })?;
        let first = rn("state://application/first")?;
        let second = rn("state://application/second")?;
        let resource = executor.registry.resolve_resource(&first)?;
        let open = |target: &ResourceName| {
            open_resource(
                &executor.registry,
                &executor.data_plane.handles,
                OpenRequest {
                    process: ProcessId::new(1),
                    resource,
                    verb: "read".into(),
                    rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                    acting: IdentityRef::ROOT,
                    requested_path: Some(target.path().clone()),
                    now_millis: executor.host_runtime.now_millis(),
                },
            )
        };
        let first_handle = open(&first)?;
        let replacement = open(&first)?;
        let second_handle = open(&second)?;
        executor.bind_handle(first.clone(), first_handle)?;
        executor.bind_handle(first.clone(), replacement)?;
        ensure!(matches!(
            executor.bind_handle(second.clone(), second_handle),
            Err(HandleBindingError::Capacity("resource bindings"))
        ));
        let mut oversized_capacity = String::with_capacity(4096);
        oversized_capacity.push_str("read");
        executor.bind_method_handle(first.clone(), oversized_capacity, first_handle)?;
        ensure!(
            executor.method_handles.read().keys().all(
                |key| key.1.capacity() <= executor.execution_config.max_cache_method_name_bytes
            )
        );
        executor.bind_method_handle(first, "read", replacement)?;
        ensure!(matches!(
            executor.bind_method_handle(second, "read", second_handle),
            Err(HandleBindingError::Capacity("method bindings"))
        ));
        ensure!(executor.open_handles.read().len() == 1);
        ensure!(executor.method_handles.read().len() == 1);
        Ok(())
    }

    #[test]
    fn concurrent_distinct_opens_compete_for_one_method_binding_slot() -> anyhow::Result<()> {
        let executor = prefix_cache_executor(ExecutionConfig {
            max_method_metadata: 2,
            max_method_bindings: 1,
            ..ExecutionConfig::default()
        })?;
        executor.registry.register_policy(Arc::new(MeetAtOpen {
            arrivals: std::sync::atomic::AtomicUsize::new(0),
        }));
        let first = prefix_read("state://application/first")?;
        let second = prefix_read("state://application/second")?;
        let results = std::thread::scope(|scope| {
            let a = scope.spawn(|| executor.prepare_operation(&first));
            let b = scope.spawn(|| executor.prepare_operation(&second));
            (a.join(), b.join())
        });
        let a = results
            .0
            .map_err(|_panic| anyhow::anyhow!("first open panicked"))?;
        let b = results
            .1
            .map_err(|_panic| anyhow::anyhow!("second open panicked"))?;
        ensure!(
            a.is_ok() != b.is_ok(),
            "exactly one open must publish: {a:?}, {b:?}"
        );
        let failed = a.err().or_else(|| b.err()).context("one rejection")?;
        ensure!(
            matches!(failed, xolotl_types::Failure::BudgetExhausted { dim } if dim == "executor.method_bindings")
        );
        ensure!(executor.method_handles.read().len() == 1);
        ensure!(executor.data_plane.handles.len() == 1);
        Ok(())
    }

    struct ChangeRegistryOnce {
        registry: std::sync::Weak<Registry>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl crate::policy::PolicySource for ChangeRegistryOnce {
        fn applies_to(&self, _: &crate::policy::OpenContext<'_>) -> bool {
            true
        }

        fn compile(
            &self,
            _: &crate::policy::OpenContext<'_>,
        ) -> Result<crate::policy::PolicySnapshot, crate::policy::PolicyCompileError> {
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0
                && let Some(registry) = self.registry.upgrade()
            {
                registry.register_grant(Grant {
                    id: registry.next_grant_id(),
                    holder: ProcessId::new(99),
                    selector: ResourceSelector::all(),
                    rights: xolotl_types::GrantRights::new(
                        xolotl_types::GrantMethods::all(),
                        RightFlags::all(),
                    ),
                    constraints: ConstraintSet::empty(),
                    expires: Expiry::Never,
                });
            }
            Ok(crate::policy::PolicySnapshot::empty())
        }
    }

    #[test]
    fn automatic_open_reprepares_after_one_unrelated_registry_change() -> anyhow::Result<()> {
        let boot = crate::Bootstrap::in_memory();
        let target = boot.register_effect(
            "effect://cache/reprepare",
            &[crate::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                crate::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let registry = Arc::new(boot.kernel().registry().clone());
        let policy = Arc::new(ChangeRegistryOnce {
            registry: Arc::downgrade(&registry),
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        registry.register_policy(policy.clone());
        let executor = boot.kernel().executor_for(boot.root());
        executor.prepare_operation(&OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        })?;
        ensure!(policy.calls.load(Ordering::SeqCst) == 2);
        ensure!(boot.kernel().handles().len() == 1);
        Ok(())
    }

    struct UnusedAsyncHost;

    #[async_trait::async_trait]
    impl crate::host::async_process::AsyncProcessHost for UnusedAsyncHost {
        async fn admit(
            &self,
            _: &crate::host::async_process::AsyncProcessRequest,
        ) -> Result<crate::host::async_process::AsyncProcessAdmission, xolotl_types::Failure>
        {
            Err(xolotl_types::Failure::policy("test", "unused"))
        }
    }

    struct MeetAtOpen {
        arrivals: std::sync::atomic::AtomicUsize,
    }

    impl crate::policy::PolicySource for MeetAtOpen {
        fn applies_to(&self, _: &crate::policy::OpenContext<'_>) -> bool {
            true
        }

        fn compile(
            &self,
            _: &crate::policy::OpenContext<'_>,
        ) -> Result<crate::policy::PolicySnapshot, crate::policy::PolicyCompileError> {
            use std::sync::atomic::Ordering;
            self.arrivals.fetch_add(1, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while self.arrivals.load(Ordering::SeqCst) < 2 {
                if std::time::Instant::now() >= deadline {
                    return Err(crate::policy::PolicyCompileError::DeniedAtOpen(
                        "second concurrent open did not reach policy compilation".into(),
                    ));
                }
                std::thread::yield_now();
            }
            Ok(crate::policy::PolicySnapshot::empty())
        }
    }

    fn await_open_flag(
        flag: &std::sync::atomic::AtomicBool,
    ) -> Result<(), crate::policy::PolicyCompileError> {
        use std::sync::atomic::Ordering;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !flag.load(Ordering::SeqCst) {
            if std::time::Instant::now() >= deadline {
                return Err(crate::policy::PolicyCompileError::DeniedAtOpen(
                    "concurrent open did not reach the expected phase".into(),
                ));
            }
            std::thread::yield_now();
        }
        Ok(())
    }

    struct NarrowAfterWide {
        narrow_entered: std::sync::atomic::AtomicBool,
        wide_finished: std::sync::atomic::AtomicBool,
    }

    impl crate::policy::PolicySource for NarrowAfterWide {
        fn applies_to(&self, _: &crate::policy::OpenContext<'_>) -> bool {
            true
        }

        fn compile(
            &self,
            context: &crate::policy::OpenContext<'_>,
        ) -> Result<crate::policy::PolicySnapshot, crate::policy::PolicyCompileError> {
            use std::sync::atomic::Ordering;
            if context.rights.flags.contains(RightFlags::SPAWN_WITH) {
                await_open_flag(&self.narrow_entered)?;
            } else {
                self.narrow_entered.store(true, Ordering::SeqCst);
                await_open_flag(&self.wide_finished)?;
            }
            Ok(crate::policy::PolicySnapshot::empty())
        }
    }

    struct BindAtOpen {
        executor: std::sync::Weak<Executor>,
        target: ResourceName,
        handle: HandleId,
    }

    impl crate::policy::PolicySource for BindAtOpen {
        fn applies_to(&self, _: &crate::policy::OpenContext<'_>) -> bool {
            true
        }

        fn compile(
            &self,
            _: &crate::policy::OpenContext<'_>,
        ) -> Result<crate::policy::PolicySnapshot, crate::policy::PolicyCompileError> {
            if let Some(executor) = self.executor.upgrade() {
                executor
                    .bind_handle(self.target.clone(), self.handle)
                    .map_err(|error| {
                        crate::policy::PolicyCompileError::DeniedAtOpen(error.to_string())
                    })?;
            }
            Ok(crate::policy::PolicySnapshot::empty())
        }
    }

    #[test]
    fn concurrent_automatic_opens_publish_one_reusable_handle() -> anyhow::Result<()> {
        let boot = crate::Bootstrap::in_memory();
        let target = boot.register_effect(
            "effect://cache/concurrent",
            &[crate::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                crate::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        boot.kernel()
            .registry()
            .register_policy(Arc::new(MeetAtOpen {
                arrivals: std::sync::atomic::AtomicUsize::new(0),
            }));
        let executor = boot
            .kernel()
            .executor_for(boot.root())
            .with_execution_config(ExecutionConfig {
                max_method_metadata: 1,
                max_method_bindings: 1,
                ..ExecutionConfig::default()
            });
        let operation = OperationTemplate {
            target: target.clone(),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        };
        std::thread::scope(|scope| {
            let first = scope.spawn(|| executor.prepare_operation(&operation));
            let second = scope.spawn(|| executor.prepare_operation(&operation));
            match first.join() {
                Ok(result) => result?,
                Err(_) => anyhow::bail!("first open thread panicked"),
            }
            match second.join() {
                Ok(result) => result?,
                Err(_) => anyhow::bail!("second open thread panicked"),
            }
            anyhow::Ok(())
        })?;
        let key = (target, "invoke".to_owned(), IdentityRef::ROOT);
        let cached = executor
            .method_handles
            .read()
            .get(&key)
            .copied()
            .context("published handle")?
            .id();
        ensure!(boot.kernel().handles().get(cached).is_some());
        ensure!(boot.kernel().handles().len() == 1);
        Ok(())
    }

    #[test]
    fn concurrent_narrow_and_spawn_opens_keep_the_wider_binding() -> anyhow::Result<()> {
        let boot = crate::Bootstrap::in_memory();
        let target = boot.register_effect(
            "effect://cache/concurrent-spawn",
            &[crate::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                crate::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let policy = Arc::new(NarrowAfterWide {
            narrow_entered: std::sync::atomic::AtomicBool::new(false),
            wide_finished: std::sync::atomic::AtomicBool::new(false),
        });
        boot.kernel().registry().register_policy(policy.clone());
        let executor = boot
            .kernel()
            .executor_for(boot.root())
            .with_async_process_host(Arc::new(UnusedAsyncHost));
        let unary = OperationTemplate {
            target: target.clone(),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        };
        let asynchronous = OperationTemplate {
            output: xolotl_types::OutputMode::AsyncProcess,
            ..unary.clone()
        };
        std::thread::scope(|scope| {
            let first = scope.spawn(|| executor.prepare_operation(&unary));
            let second = scope.spawn(|| {
                let result = executor.prepare_operation(&asynchronous);
                policy
                    .wide_finished
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                result
            });
            match first.join() {
                Ok(result) => result?,
                Err(_) => anyhow::bail!("unary open thread panicked"),
            }
            match second.join() {
                Ok(result) => result?,
                Err(_) => anyhow::bail!("async open thread panicked"),
            }
            anyhow::Ok(())
        })?;
        let key = (target, "invoke".to_owned(), IdentityRef::ROOT);
        let cached = executor
            .method_handles
            .read()
            .get(&key)
            .copied()
            .context("published handle")?
            .id();
        ensure!(
            boot.kernel()
                .handles()
                .get(cached)
                .context("live published handle")?
                .rights
                .flags
                .contains(RightFlags::SPAWN_WITH)
        );
        executor.prepare_operation(&unary)?;
        executor.prepare_operation(&asynchronous)?;
        ensure!(boot.kernel().handles().len() == 1);
        Ok(())
    }

    #[test]
    fn resource_binding_arriving_during_open_wins_before_publication() -> anyhow::Result<()> {
        let boot = crate::Bootstrap::in_memory();
        let target = boot.register_effect(
            "effect://cache/late-binding",
            &[crate::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                crate::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let bound = boot.open_for(boot.root(), &target, "perform")?;
        let executor = Arc::new(boot.kernel().executor_for(boot.root()));
        boot.kernel()
            .registry()
            .register_policy(Arc::new(BindAtOpen {
                executor: Arc::downgrade(&executor),
                target: target.clone(),
                handle: bound,
            }));
        let operation = OperationTemplate {
            target: target.clone(),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        };
        executor.prepare_operation(&operation)?;
        ensure!(
            executor
                .open_handles
                .read()
                .get(&(target, IdentityRef::ROOT))
                == Some(&bound)
        );
        ensure!(executor.method_handles.read().is_empty());
        ensure!(boot.kernel().handles().len() == 1);
        Ok(())
    }

    #[test]
    fn automatic_method_handle_upgrades_only_when_needed_and_explicit_binding_cannot_upgrade()
    -> anyhow::Result<()> {
        let boot = crate::Bootstrap::in_memory();
        let target = boot.register_effect(
            "effect://cache/async",
            &[crate::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                crate::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let unary = OperationTemplate {
            target: target.clone(),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        };
        let async_operation = OperationTemplate {
            output: xolotl_types::OutputMode::AsyncProcess,
            ..unary.clone()
        };
        let executor = boot
            .kernel()
            .executor_for(boot.root())
            .with_async_process_host(Arc::new(UnusedAsyncHost));
        executor.prepare_operation(&unary)?;
        let key = (target.clone(), "invoke".to_owned(), IdentityRef::ROOT);
        let first = executor
            .method_handles
            .read()
            .get(&key)
            .copied()
            .context("automatically opened unary handle")?
            .id();
        ensure!(
            !boot
                .kernel()
                .handles()
                .get(first)
                .context("live unary handle")?
                .rights
                .flags
                .contains(RightFlags::SPAWN_WITH)
        );
        executor.prepare_operation(&async_operation)?;
        let upgraded = executor
            .method_handles
            .read()
            .get(&key)
            .copied()
            .context("automatically opened async handle")?
            .id();
        ensure!(first != upgraded);
        ensure!(
            boot.kernel()
                .handles()
                .get(upgraded)
                .context("live async handle")?
                .rights
                .flags
                .contains(RightFlags::SPAWN_WITH)
        );
        executor.prepare_operation(&unary)?;
        let reused = executor
            .method_handles
            .read()
            .get(&key)
            .copied()
            .context("automatically reused unary handle")?
            .id();
        ensure!(reused == upgraded);
        ensure!(
            boot.kernel()
                .handles()
                .get(reused)
                .context("reused async handle")?
                .rights
                .flags
                .contains(RightFlags::SPAWN_WITH)
        );

        executor.bind_handle(target.clone(), first)?;
        ensure!(executor.prepare_operation(&async_operation).is_err());

        let explicit = boot
            .kernel()
            .executor_for(boot.root())
            .with_async_process_host(Arc::new(UnusedAsyncHost));
        explicit.bind_method_handle(target.clone(), "invoke", first)?;
        ensure!(explicit.prepare_operation(&async_operation).is_err());
        ensure!(boot.kernel().handles().revoke(first));
        explicit.prepare_operation(&async_operation)?;
        ensure!(matches!(
            explicit
                .method_handles
                .read()
                .get(&(target, "invoke".to_owned(), IdentityRef::ROOT)),
            Some(MethodHandle::Opened(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn acting_denied_when_grant_lacks_delegate_flag() -> anyhow::Result<()> {
        use xolotl_types::{Expiry, Grant, ResourceSelector, RightFlags};
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(HandleTable::new(), facts, test_state());
        let reg = Registry::new();
        // Selector matches act-as://identity/bob but WITHOUT the DELEGATE flag.
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("act-as://identity/bob")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::CLONE,
            ),
            constraints: xolotl_types::ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let ex = Executor::new(ProcessId::new(1), IdentityRef::ROOT, dp, reg)?;
        let prog = DoNode::acting(
            xolotl_types::Path::parse("identity://bob")?,
            DoNode::pure(Value::integer(1)),
        );
        let out = ex.eval(&prog).await;
        ensure!(
            matches!(
                out.outcome,
                Outcome::Fail(xolotl_types::Failure::PolicyViolation { .. })
            ),
            "acting without delegate flag should fail, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn and_then_runs_step() -> anyhow::Result<()> {
        let ex = executor().with_steps(StepModule::single("double", |v, _| match v.as_int() {
            Some(i) => DoNode::pure(Value::integer(i * 2)),
            _ => DoNode::pure(Value::null()),
        })?);
        let prog = DoNode::pure(Value::integer(21)).and_then(s("double"));
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == Outcome::Done(Value::integer(42)),
            "and_then output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn one_graph_resolves_steps_in_each_executing_process() -> anyhow::Result<()> {
        let ex = executor().with_steps(StepModule::single("double", |v, _| match v.as_int() {
            Some(i) => DoNode::pure(Value::integer(i * 2)),
            _ => DoNode::pure(Value::null()),
        })?);
        let graph = compile_do(&DoNode::pure(Value::integer(21)).and_then(StepRef::new("double")))?;
        let other = Executor::new(
            ProcessId::new(2),
            IdentityRef::ROOT,
            ex.data_plane.clone(),
            ex.registry.clone(),
        )?;
        let out = other.eval_graph(&graph).await;
        ensure!(
            matches!(out.outcome, Outcome::Fail(xolotl_types::Failure::PolicyViolation { ref detail, .. }) if detail.contains("not found")),
            "an unbound name must not resolve in another process: {out:?}"
        );
        let other = other.with_steps(StepModule::single("double", |_, _| DoNode::pure(99))?);
        ensure!(other.eval_graph(&graph).await.outcome == Outcome::Done(Value::integer(99)));
        ensure!(ex.eval_graph(&graph).await.outcome == Outcome::Done(Value::integer(42)));
        Ok(())
    }

    #[tokio::test]
    async fn or_else_recovers() -> anyhow::Result<()> {
        let ex = executor().with_steps(StepModule::single("fallback", |_, _| {
            DoNode::pure(Value::string("ok".into()))
        })?);
        let prog = DoNode::fail(xolotl_types::Failure::Cancelled).or_else(s("fallback"));
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == Outcome::Done(Value::string("ok".into())),
            "or_else recovery mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn or_else_passes_through_success() -> anyhow::Result<()> {
        let ex = executor().with_steps(StepModule::single("never", |_, _| {
            DoNode::pure(Value::string("recovered".into()))
        })?);
        let prog = DoNode::pure(Value::integer(1)).or_else(s("never"));
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == Outcome::Done(Value::integer(1)),
            "or_else success passthrough mismatch"
        );
        Ok(())
    }

    #[tokio::test]
    async fn let_use_binds() -> anyhow::Result<()> {
        let ex = executor();
        let prog = DoNode::r#let("x", DoNode::pure(Value::integer(7)), DoNode::use_("x"));
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == Outcome::Done(Value::integer(7)),
            "let/use output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn both_joins_pair() -> anyhow::Result<()> {
        let ex = executor();
        let prog = DoNode::both(
            DoNode::pure(Value::integer(1)),
            DoNode::pure(Value::integer(2)),
        );
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == Outcome::Done(Value::list(vec![Value::integer(1), Value::integer(2)])),
            "both output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn both_fails_if_either_arm_fails() -> anyhow::Result<()> {
        let ex = executor();
        let prog = DoNode::both(
            DoNode::pure(Value::integer(1)),
            DoNode::fail(xolotl_types::Failure::Cancelled),
        );
        let out = ex.eval(&prog).await;
        ensure!(
            matches!(out.outcome, Outcome::Fail(_)),
            "both should fail, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn race_takes_first_success() -> anyhow::Result<()> {
        let ex = executor();
        let prog = DoNode::race(
            DoNode::pure(Value::string("a".into())),
            DoNode::pure(Value::string("b".into())),
        );
        // Both are immediate; the result is one of them (deterministic select
        // bias toward the first-polled arm in tokio::select! is not guaranteed,
        // so accept either).
        let out = ex.eval(&prog).await;
        ensure!(
            matches!(&out.outcome, Outcome::Done(value) if matches!(value.as_str(), Some("a" | "b"))),
            "race output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unbound_use_fails_at_compile() -> anyhow::Result<()> {
        let ex = executor();
        // A bare Use with no enclosing Let fails to compile → executor surfaces
        // a policy failure rather than panicking.
        let out = ex.eval(&DoNode::use_("nope")).await;
        ensure!(
            matches!(out.outcome, Outcome::Fail(_)),
            "unbound use should fail, got {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn chained_and_then_keeps_threading_value() -> anyhow::Result<()> {
        let ex = executor().with_steps(StepModule::single("inc", |v, _| match v.as_int() {
            Some(i) => DoNode::pure(Value::integer(i + 1)),
            _ => DoNode::pure(Value::null()),
        })?);
        let prog = DoNode::pure(Value::integer(0))
            .and_then(s("inc"))
            .and_then(s("inc"))
            .and_then(s("inc"));
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == Outcome::Done(Value::integer(3)),
            "chained and_then output mismatch"
        );
        Ok(())
    }

    #[tokio::test]
    async fn wait_deadline_in_past_returns_immediately() -> anyhow::Result<()> {
        let ex = executor();
        let prog = DoNode::wait_deadline(0); // epoch — already passed
        let out = ex.eval(&prog).await;
        ensure!(
            out.outcome == Outcome::Done(Value::null()),
            "past deadline output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn wall_wait_uses_the_installed_host_clock() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock {
            origin: std::time::Instant::now(),
            millis: AtomicI64::new(1_000),
        });
        let runtime = HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(crate::host::TokioBlockingSpawner::default()),
        );
        let (facts, _) = FactSink::in_memory();
        let data_plane =
            DataPlane::new(HandleTable::new(), facts, test_state()).with_host_runtime(runtime)?;
        let executor = Executor::new(
            ProcessId::new(1),
            IdentityRef::ROOT,
            data_plane,
            Registry::new(),
        )?;
        let output = executor.run_wait(&WaitSpec::Deadline(1_500)).await;
        ensure!(output.outcome == Outcome::Done(Value::null()));
        ensure!(clock.unix_millis() == 1_500);
        Ok(())
    }

    #[tokio::test]
    async fn installed_host_clock_controls_open_call_and_acting_authority() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock {
            origin: std::time::Instant::now(),
            millis: AtomicI64::new(1_000),
        });
        let runtime = HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(crate::host::TokioBlockingSpawner::default()),
        );
        let (facts, _) = FactSink::in_memory();
        let data_plane =
            DataPlane::new(HandleTable::new(), facts, test_state()).with_host_runtime(runtime)?;
        let registry = Registry::new();
        let (_, target) = register_test_resource(
            &registry,
            TestResourceSpec {
                path: "effect://clock/echo",
                kind: ResourceKind::Effect,
                addressing: xolotl_types::ResourceAddressing::Exact,
                family: InterfaceFamily::Callable,
                method_name: "invoke",
                authority: xolotl_types::MethodAuthority::Perform,
                method_id: 0,
                purity: Purity::Pure,
                replay: ReplayClass::Deterministic,
                driver_name: "clock-echo",
                selector: "perform://effect/clock/echo",
                requires_unprotected_input: false,
            },
            Arc::new(EchoDriver),
        )?;
        for selector in ["perform://effect/clock/echo", "act-as://identity/bob"] {
            registry.register_grant(Grant {
                id: registry.next_grant_id(),
                holder: ProcessId::new(1),
                selector: ResourceSelector::parse(selector)?,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::all(),
                    RightFlags::DELEGATE,
                ),
                constraints: ConstraintSet::empty(),
                expires: Expiry::At(2_000),
            });
        }
        let identities = IdentityRegistry::in_memory();
        let bob = Path::parse("identity://bob")?;
        identities.resolve_or_register(&bob)?;
        let executor = Executor::new(ProcessId::new(1), IdentityRef::ROOT, data_plane, registry)?
            .with_identity_registry(identities);
        let operation = OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::integer(17)),
        };
        executor.prepare_operation(&operation)?;
        let output = executor.eval(&DoNode::op(operation)).await;
        ensure!(
            output.outcome == Outcome::Done(Value::integer(17)),
            "call should use the installed clock: {output:?}"
        );
        let acting = DoNode::acting(bob.clone(), DoNode::pure(Value::integer(23)));
        let output = executor.eval(&acting).await;
        ensure!(
            output.outcome == Outcome::Done(Value::integer(23)),
            "acting should use the installed clock: {output:?}"
        );
        clock.millis.store(2_001, Ordering::SeqCst);
        ensure!(!executor.authorize_act_as(&bob, &Value::null()));
        Ok(())
    }

    #[tokio::test]
    async fn wait_signal_resolves_on_write() -> anyhow::Result<()> {
        let boot = crate::Bootstrap::in_memory();
        let state = boot.kernel().state().clone();
        super::signal_tests::install_signal_resource(&boot, state.clone())?;
        let ex = boot.kernel().executor_for(boot.root());
        let signal = xolotl_types::Path::parse("state://stream/1/sig")?;
        // Write the signal after a short delay; the Wait must observe it.
        let writer = {
            let state = state.clone();
            let signal = signal.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                state.write_set(&signal, Value::integer(99)).await?;
                Ok::<(), anyhow::Error>(())
            })
        };
        let out = ex.eval(&DoNode::wait_signal(signal)).await;
        writer
            .await
            .context("signal writer task failed to join")??;
        ensure!(
            out.outcome == Outcome::Done(Value::integer(99)),
            "wait signal output mismatch: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn wait_signal_without_subscribe_resource_fails() -> anyhow::Result<()> {
        let ex = executor(); // no subscribe method installed
        let signal = xolotl_types::Path::parse("state://stream/1/sig")?;
        let out = ex.eval(&DoNode::wait_signal(signal)).await;
        ensure!(
            matches!(out.outcome, Outcome::Fail(_)),
            "wait without a subscribe resource should fail, got {out:?}"
        );
        Ok(())
    }

    #[test]
    fn causal_positions_match_compiled_graph() -> anyhow::Result<()> {
        // The Operations the executor issues carry the compiler's NodeIds. Here
        // we just assert the compiled graph is what the executor walks: a
        // 2-node chain (Op, Step) numbers the Op at 0 (its CausalPosition).
        use xolotl_graph::{NodeKind, compile_do};
        let prog = DoNode::op(xolotl_graph::OperationTemplate {
            target: rn("effect://x/post")?,
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        })
        .and_then(s("s"));
        let g = compile_do(&prog).context("compile_do failed")?;
        let node = g.node(NodeId::new(0)).context("missing node 0")?;
        ensure!(
            matches!(node.kind, NodeKind::Operation(_)),
            "node 0 should be an operation"
        );
        Ok(())
    }

    #[tokio::test]
    async fn protected_data_to_outbound_is_denied() -> anyhow::Result<()> {
        use xolotl_graph::OperationTemplate;
        let bootstrap = crate::Bootstrap::in_memory();
        let target = bootstrap.register_effect(
            "effect://arbitrary/capability",
            &[crate::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                crate::MethodSpec::UNARY_ASYNC,
            )
            .unprotected_input()],
            Arc::new(EchoDriver),
        )?;
        let ex = bootstrap.kernel().executor_for(bootstrap.root());
        let env = Env::root(IdentityRef::ROOT).with_taint(xolotl_types::TaintSet::of(
            xolotl_types::TaintSource::Protected {
                path: xolotl_types::Path::parse("state://vault/alice/x")?,
            },
        ));
        let tmpl = OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        };
        let out = ex
            .run_operation(
                &tmpl,
                Value::string("secret".into()),
                &env,
                OperationId::new(
                    bootstrap.root(),
                    ExecutionId::FIRST,
                    InvocationId::new(1),
                    NodeId::new(0),
                    0,
                ),
                true,
                None,
            )
            .await;
        match out.output.outcome {
            Outcome::Fail(xolotl_types::Failure::PolicyViolation { policy, .. }) => {
                ensure!(policy == "taint", "unexpected policy: {policy}");
            }
            other => bail!("expected taint PolicyViolation, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn persisted_protected_state_taint_blocks_later_outbound_op() -> anyhow::Result<()> {
        let state = test_state();
        let secret_path = Path::parse("state://memory/private")?;
        let protected = TaintSet::of(TaintSource::Protected {
            path: secret_path.clone(),
        });
        state
            .write_set_tainted(&secret_path, Value::string("secret".into()), protected)
            .await
            .context("writing tainted state failed")?;

        let reg = Registry::new();
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::all(),
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::all(),
                RightFlags::all(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let (state_resource, _) = register_test_resource(
            &reg,
            TestResourceSpec {
                path: "state://memory",
                kind: ResourceKind::State,
                addressing: xolotl_types::ResourceAddressing::Prefix,
                family: InterfaceFamily::Value,
                method_name: "read",
                authority: xolotl_types::MethodAuthority::Read,
                method_id: 0,
                purity: Purity::Pure,
                replay: ReplayClass::Observation,
                driver_name: "state-read",
                selector: "read://state/memory/**",
                requires_unprotected_input: false,
            },
            Arc::new(TestStateReadDriver {
                state: state.clone(),
            }),
        )?;
        let (post_resource, post_name) = register_test_resource(
            &reg,
            TestResourceSpec {
                path: "effect://chat_platform/post",
                kind: ResourceKind::Effect,
                addressing: xolotl_types::ResourceAddressing::Exact,
                family: InterfaceFamily::Callable,
                method_name: "invoke",
                authority: xolotl_types::MethodAuthority::Perform,
                method_id: 0,
                purity: Purity::Effectful,
                replay: ReplayClass::NonIdempotentEffect,
                driver_name: "post",
                selector: "perform://effect/chat_platform/post",
                requires_unprotected_input: true,
            },
            Arc::new(EchoDriver),
        )?;

        let (facts, _) = FactSink::in_memory();
        let handles = HandleTable::new();
        let dp = DataPlane::new(handles.clone(), facts, state);
        let ex = Executor::new(ProcessId::new(1), IdentityRef::ROOT, dp, reg.clone())?;

        let read_target = ResourceName::new(secret_path.clone());
        let read_handle = {
            open_resource(
                &reg,
                &handles,
                OpenRequest {
                    process: ProcessId::new(1),
                    resource: state_resource,
                    verb: "read".into(),
                    rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                    acting: IdentityRef::ROOT,
                    requested_path: Some(secret_path.clone()),
                    now_millis: 0,
                },
            )
            .context("state read open failed")?
        };
        ex.bind_handle(read_target.clone(), read_handle)?;

        let post_handle = {
            open_resource(
                &reg,
                &handles,
                OpenRequest {
                    process: ProcessId::new(1),
                    resource: post_resource,
                    verb: "perform".into(),
                    rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                    acting: IdentityRef::ROOT,
                    requested_path: None,
                    now_millis: 0,
                },
            )
            .context("post open failed")?
        };
        ex.bind_handle(post_name.clone(), post_handle)?;

        let post_step_target = post_name;
        let ex = ex.with_steps(StepModule::single("post", move |_, _| {
            DoNode::op(OperationTemplate {
                target: post_step_target.clone(),
                method: "invoke".into(),
                method_id: None,
                output: xolotl_types::OutputMode::Unary,
                literal_input: None,
            })
        })?);

        let prog = DoNode::op(OperationTemplate {
            target: read_target,
            method: "read".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: None,
        })
        .and_then(s("post"));

        match ex.eval(&prog).await.outcome {
            Outcome::Fail(xolotl_types::Failure::PolicyViolation { policy, .. }) => {
                ensure!(policy == "taint", "unexpected policy: {policy}");
            }
            other => bail!("expected taint PolicyViolation, got {other:?}"),
        }
        Ok(())
    }
}
