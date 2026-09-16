//! Host adapter for the allocation-free `xolotl-core` execution machine.
//!
//! Both [`ExecutionGraph`] and portable programs lower to the same instructions.
//! The core owns control flow; this adapter owns allocation, scheduling, I/O,
//! authority and optional durable barriers. Execution scopes and dynamic invocation
//! tickets survive restoration with the full checkpoint.
//!
//! Per node kind:
//! - `Pure` / `Fail` yield a value / failure immediately.
//! - `Operation` issues one data-plane call (records a Fact).
//! - `Step` splices its produced subgraph at the cursor (run-time `AndThen`).
//! - `Branch(OrElse)` runs its guarded arm; on failure routes into `recover`.
//! - `Join(Both)` runs both arms concurrently (async I/O overlap); `Join(Race)`
//!   runs both and takes the first to finish, cancelling the loser.
//! - `Acting` switches block-level identity for its arm.
//! - `Wait` blocks on a signal path or a wall-clock deadline.

use crate::dataplane::DataPlane;
use crate::execution_ids::ExecutionIds;
use crate::open::{OpenRequest, open_resource_with_attached};
use crate::registry::Registry;
use crate::step::StepModule;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use xolotl_graph::{
    BranchKind, DoNode, EdgeKind, ExecutionGraph, JoinKind, NodeKind, OperationTemplate, StepRef,
    WaitSpec, compile_do, operation_capability_verb,
};
#[cfg(any(feature = "durable", test))]
use xolotl_types::ReplayClass;
use xolotl_types::{
    DriverOutput, ExecutionId, ExecutionOutput, HandleId, IdentityRef, InvocationId, MethodBitmap,
    NodeId, Operation, OperationId, Outcome, ProcessId, ResourceName, RightFlags, Rights, TaintSet,
    TaintedValue, Value,
};

// Host assembly, admission and scheduling are separate from core control flow.
mod buffers;
mod config;
#[cfg(test)]
mod identity_tests;
mod image;
mod machine;
#[cfg(test)]
mod module_tests;
#[cfg(test)]
mod provenance_tests;
pub use buffers::ExecutionBuffers;
pub use config::{ExecutionConfig, ExecutionLayout};
pub use image::PreparedProgram;
#[cfg(feature = "durable")]
pub mod durable;

type OpenHandleMap = HashMap<(ResourceName, IdentityRef), HandleId>;
type MethodHandleMap = HashMap<(ResourceName, String, IdentityRef), HandleId>;
type MethodMetaMap = HashMap<(ResourceName, String), MethodMeta>;

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
    /// Optional state backend, used to resolve `Wait(Signal)` nodes.
    /// `None` for executors that never wait on a signal path.
    state: Option<xolotl_state::Backend>,
    /// Per-invocation stream destinations supplied by the embedding host.
    streams: Option<crate::host::stream::DynStreamRouter>,
    /// Optional process table, used to observe cancellation at Operation
    /// boundaries. `None` for standalone executors (tests) that
    /// have no process lifecycle to honor.
    processes: Option<crate::process::ProcessTable>,
    execution_ids: ExecutionIds,
    execution_ids_explicit: bool,
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
    deadline: Option<tokio::time::Instant>,
    execution_config: ExecutionConfig,
    #[cfg(feature = "durable")]
    checkpoint_store: Option<Arc<dyn durable::CheckpointStore>>,
}

/// Compiled, cached metadata for one (resource, method): the bit position,
/// id, replay class, supported output modes, and cost — everything the data
/// plane needs to dispatch without touching the Registry again.
#[derive(Clone)]
struct MethodMeta {
    resource_id: xolotl_types::ResourceId,
    method_index: u32,
    method_id: xolotl_types::MethodId,
    #[cfg(feature = "durable")]
    replay: ReplayClass,
    supports: xolotl_types::OutputModeSet,
    #[cfg(feature = "durable")]
    cost: xolotl_types::CostModel,
    #[cfg(feature = "durable")]
    batchable: bool,
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
    /// Create a standalone executor with an explicit caller and host adapters.
    /// Attach a process table with `with_processes` to enforce lifecycle cancellation.
    pub fn new(process: ProcessId, data_plane: DataPlane, registry: Registry) -> Self {
        Self {
            process,
            execution_ids: data_plane.facts.execution_ids(),
            execution_ids_explicit: false,
            data_plane,
            registry,
            steps: StepModule::default(),
            state: None,
            streams: None,
            processes: None,
            open_handles: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            method_handles: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            method_cache: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            finalizer_mode: false,
            deadline: None,
            execution_config: ExecutionConfig::default(),
            #[cfg(feature = "durable")]
            checkpoint_store: None,
        }
    }

    /// Resolve native and portable continuations in this assembled namespace.
    /// Other executors and the process's configured module remain unchanged.
    pub fn with_steps(mut self, steps: StepModule) -> Self {
        self.steps = steps;
        self
    }

    /// Attach a state backend so `Wait(Signal)` nodes can resolve.
    pub fn with_state(mut self, state: xolotl_state::Backend) -> Self {
        self.state = Some(state);
        self
    }

    /// Open independent output ports for streamed operations in this executor.
    pub fn with_stream_router(mut self, streams: crate::host::stream::DynStreamRouter) -> Self {
        self.streams = Some(streams);
        self
    }

    /// Select a retained identity namespace independently of host storage.
    /// This explicit choice takes precedence over `with_checkpoint_store`.
    pub fn with_execution_ids(mut self, ids: ExecutionIds) -> Self {
        self.execution_ids = ids;
        self.execution_ids_explicit = true;
        self
    }

    /// Attach the process table so the executor honors cancellation at each
    /// Operation boundary.
    pub fn with_processes(mut self, processes: crate::process::ProcessTable) -> Self {
        self.data_plane = self.data_plane.with_processes(processes.clone());
        self.processes = Some(processes);
        self
    }

    /// Bound interpreter storage and cooperative work before starting a program.
    pub fn with_execution_config(mut self, config: ExecutionConfig) -> Self {
        self.execution_config = config;
        self
    }

    /// Stop this evaluation at an absolute host deadline, preserving live provenance.
    /// The request owner remains responsible for asynchronous process finalization.
    pub fn with_deadline(mut self, deadline: tokio::time::Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    fn deadline_elapsed(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
    }

    fn failed(failure: xolotl_types::Failure, taint: TaintSet) -> ExecutionOutput {
        ExecutionOutput::new(Outcome::Fail(failure), taint)
    }

    /// Enable durable programs through an exclusive, write-through checkpoint store.
    /// Its identity source also serves volatile evaluations unless explicitly overridden.
    /// Configure before running, preserving the source of any retained history.
    #[cfg(feature = "durable")]
    pub fn with_checkpoint_store(mut self, store: Arc<dyn durable::CheckpointStore>) -> Self {
        if !self.execution_ids_explicit {
            self.execution_ids = ExecutionIds::new(store.clone());
        }
        self.checkpoint_store = Some(store);
        self
    }

    fn allocate_execution(&self) -> Result<ExecutionId, xolotl_types::Failure> {
        let execution = self
            .execution_ids
            .allocate()
            .map_err(|error| machine_error(error.to_string()))?;
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

    /// Pre-register a resolved handle for a resource name.
    pub fn bind_handle(&self, name: ResourceName, handle: xolotl_types::HandleId) {
        if let Some(acting) = self.default_acting() {
            self.open_handles.write().insert((name, acting), handle);
        }
    }

    /// Pre-register a resolved handle for one resource method.
    pub fn bind_method_handle(
        &self,
        name: ResourceName,
        method: impl Into<String>,
        handle: xolotl_types::HandleId,
    ) {
        if let Some(acting) = self.default_acting() {
            self.method_handles
                .write()
                .insert((name, method.into(), acting), handle);
        }
    }

    fn default_acting(&self) -> Option<IdentityRef> {
        match &self.processes {
            Some(processes) => processes.identity(self.process),
            None => Some(IdentityRef::ROOT),
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
            #[cfg(feature = "durable")]
            None,
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
            #[cfg(feature = "durable")]
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

    /// Await a deadline or a signal under the execution's cancellation scope.
    async fn run_wait(&self, spec: &WaitSpec) -> xolotl_types::DriverOutput {
        match spec {
            WaitSpec::Deadline(at_millis) => {
                loop {
                    let now = now_millis();
                    if *at_millis <= now {
                        break;
                    }
                    // Tokio's wheel and platform Instant have finite horizons.
                    // Re-arm distant deadlines without narrowing the wall-clock domain.
                    let dur =
                        std::time::Duration::from_millis(at_millis.abs_diff(now).min(86_400_000));
                    tokio::time::sleep(dur).await;
                }
                Outcome::Done(Value::null()).into()
            }
            WaitSpec::Signal(path) => match &self.state {
                Some(state) => self.wait_signal(state, path).await,
                None => Outcome::Fail(xolotl_types::Failure::policy(
                    "executor",
                    "Wait(Signal) needs a state backend (none bound)",
                ))
                .into(),
            },
        }
    }
    /// Subscribe before reading the current value so a concurrent write cannot
    /// fall between the snapshot and the live observation.
    async fn wait_signal(
        &self,
        state: &xolotl_state::Backend,
        path: &xolotl_types::Path,
    ) -> xolotl_types::DriverOutput {
        use xolotl_state::StateEvent;
        let mut rx = match state.subscribe(path).await {
            Ok(rx) => rx,
            Err(e) => {
                return DriverOutput::new(Outcome::Fail(xolotl_types::Failure::policy(
                    "executor",
                    format!("wait subscribe failed: {e}"),
                )))
                .with_taint(e.taint);
            }
        };
        match state.read_tainted(path).await {
            Ok(Some(value)) => {
                return xolotl_types::DriverOutput::new(Outcome::Done(value.value))
                    .with_taint(value.taint);
            }
            Ok(None) => {}
            Err(error) => {
                return DriverOutput::new(Outcome::Fail(machine_error(format!(
                    "wait read failed: {error}"
                ))))
                .with_taint(error.taint);
            }
        }
        loop {
            match rx.recv().await {
                Ok(StateEvent::Set {
                    path: p,
                    value,
                    taint,
                }) if &p == path => {
                    return xolotl_types::DriverOutput::new(Outcome::Done(value)).with_taint(taint);
                }
                Ok(StateEvent::Append {
                    path: p,
                    item,
                    taint,
                }) if &p == path => {
                    return xolotl_types::DriverOutput::new(Outcome::Done(item)).with_taint(taint);
                }
                Ok(_) => continue,
                Err(error) => {
                    return Outcome::Fail(machine_error(format!("wait signal failed: {error}")))
                        .into();
                }
            }
        }
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
    ) -> DriverOutput {
        let effective_input = tmpl.literal_input.clone().unwrap_or(input);

        let op_taint = env.taint.clone();

        // Resolve compiled method metadata once and cache it: the hot path
        // must not re-query the Registry per Operation. A cache miss resolves via
        // the Registry and memoizes; a hit skips it entirely.
        let Some(meta) = self.resolve_meta(&tmpl.target, &tmpl.method) else {
            return DriverOutput::new(Outcome::Fail(xolotl_types::Failure::NoHandler {
                path: tmpl.target.path().clone(),
            }))
            .with_taint(op_taint);
        };
        let MethodMeta {
            resource_id,
            method_index,
            method_id,
            supports,
            ..
        } = meta;

        // The requested OutputMode must be in the method's supported set.
        // Reject before opening a handle so invalid requests do not mutate the
        // handle table.
        if !tmpl.output.is_supported_by(supports) {
            return DriverOutput::new(Outcome::Fail(xolotl_types::Failure::InvalidInput {
                reason: format!(
                    "method {} does not support output mode {:?}",
                    tmpl.method, tmpl.output
                ),
            }))
            .with_taint(op_taint);
        }

        let handle = match self.handle_for_or_open(
            &tmpl.target,
            &tmpl.method,
            env.acting,
            resource_id,
            method_index,
        ) {
            Ok(handle) => handle,
            Err(error) => {
                return DriverOutput::new(Outcome::Fail(xolotl_types::Failure::policy(
                    "open",
                    format!(
                        "open {} method {} failed for {}: {error}",
                        operation_capability_verb(&tmpl.method),
                        tmpl.method,
                        tmpl.target.path()
                    ),
                )))
                .with_taint(op_taint);
            }
        };

        let op = Operation {
            id,
            process: self.process,
            acting: env.acting,
            handle,
            method: method_id,
            input: effective_input,
            taint: op_taint.clone(),
            output: tmpl.output,
        };

        let options = crate::InvocationOptions {
            now_millis: now_millis(),
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
                        .execute_with_stream(&op, options, sink)
                        .await
                }
                Ok(None) => self.data_plane.execute(&op, options).await,
                Err(error) => DriverOutput::new(Outcome::Fail(machine_error(error.to_string())))
                    .with_taint(op_taint),
            }
        } else {
            self.data_plane.execute(&op, options).await
        }
    }

    /// Authorize an `Acting(identity)` switch. The process must hold a
    /// grant whose selector is `act-as://<identity>` (matched structurally) and
    /// whose rights carry the `DELEGATE` flag. Returns false (deny) otherwise.
    ///
    /// The omnipotent root grant (`*://**` + all flags) covers every identity,
    /// so kernel-internal Acting blocks pass; attenuated children only pass for
    /// identities they were explicitly delegated.
    fn authorize_act_as(&self, identity: &xolotl_types::Path) -> bool {
        let now = now_millis();
        let mut grants = self.registry.grants_of(self.process);
        if let Some(processes) = &self.processes {
            grants.extend(processes.attached_grants(self.process));
        }
        grants.into_iter().any(|g| {
            !g.expires.is_expired(now)
                && g.rights.flags.contains(xolotl_types::RightFlags::DELEGATE)
                && g.selector.matches("act-as", identity)
        })
    }

    fn handle_for(
        &self,
        name: &ResourceName,
        method: &str,
        acting: IdentityRef,
        resource_id: xolotl_types::ResourceId,
        method_index: u32,
    ) -> Option<xolotl_types::HandleId> {
        let key = (name.clone(), method.to_string(), acting);
        if let Some(handle) = self.method_handles.read().get(&key).copied()
            && self.cached_handle_allows(handle, resource_id, method_index)
        {
            return Some(handle);
        }
        let handle = self
            .open_handles
            .read()
            .get(&(name.clone(), acting))
            .copied()?;
        if self.cached_handle_allows(handle, resource_id, method_index) {
            Some(handle)
        } else {
            None
        }
    }

    fn cached_handle_allows(
        &self,
        handle: xolotl_types::HandleId,
        resource_id: xolotl_types::ResourceId,
        method_index: u32,
    ) -> bool {
        self.data_plane
            .handles
            .read()
            .get(handle)
            .map(|handle| {
                handle.check_owner(self.process)
                    && handle.resource == resource_id
                    && handle.is_active()
                    && handle.allows_method(method_index)
            })
            .unwrap_or(false)
    }

    fn handle_for_or_open(
        &self,
        name: &ResourceName,
        method: &str,
        acting: IdentityRef,
        resource_id: xolotl_types::ResourceId,
        method_index: u32,
    ) -> Result<xolotl_types::HandleId, crate::open::OpenError> {
        if let Some(handle) = self.handle_for(name, method, acting, resource_id, method_index) {
            return Ok(handle);
        }
        let attached_grants = self
            .processes
            .as_ref()
            .map(|processes| processes.attached_grants(self.process))
            .unwrap_or_default();
        let handle = {
            let mut handles = self.data_plane.handles.write();
            open_resource_with_attached(
                &self.registry,
                &mut handles,
                OpenRequest {
                    process: self.process,
                    resource: resource_id,
                    verb: operation_capability_verb(method).to_string(),
                    rights: Rights::new(MethodBitmap::method(method_index), RightFlags::empty()),
                    acting,
                    requested_path: Some(name.path().clone()),
                    now_millis: now_millis(),
                },
                &attached_grants,
            )?
        };
        self.method_handles
            .write()
            .insert((name.clone(), method.to_string(), acting), handle);
        Ok(handle)
    }

    /// Resolve cached [`MethodMeta`] for a (target, method). A cache miss
    /// walks the Registry once and memoizes; subsequent calls are pure cache
    /// reads, so the per-Operation hot path never re-queries the Registry.
    /// Returns `None` if the target resource doesn't resolve.
    fn resolve_meta(&self, target: &ResourceName, method_name: &str) -> Option<MethodMeta> {
        let key = (target.clone(), method_name.to_string());
        if let Some(m) = self.method_cache.read().get(&key) {
            return Some(m.clone());
        }
        let resource_id = match self.registry.resolve_resource(target) {
            Ok(resource_id) => resource_id,
            Err(crate::registry::ResolveError::NoSuchResource(_)) => return None,
        };
        let meta = self.compile_meta(resource_id, method_name)?;
        self.method_cache.write().insert(key, meta.clone());
        Some(meta)
    }

    /// Compile (method_index, method_id, replay class, supported output modes,
    /// cost) for a target's method by walking the Registry (slow path, cached by
    /// [`resolve_meta`]).
    fn compile_meta(
        &self,
        resource_id: xolotl_types::ResourceId,
        method_name: &str,
    ) -> Option<MethodMeta> {
        if let Some(resource) = self.registry.resource(resource_id) {
            for iface_id in &resource.interfaces.interfaces {
                if let Some(iface) = self.registry.interface(*iface_id)
                    && let Some((idx, method)) = iface.method_index(method_name)
                {
                    return Some(MethodMeta {
                        resource_id,
                        method_index: idx,
                        method_id: method.id,
                        #[cfg(feature = "durable")]
                        replay: method.replay,
                        supports: method.supports,
                        #[cfg(feature = "durable")]
                        cost: method.cost,
                        #[cfg(feature = "durable")]
                        batchable: method.batchable,
                    });
                }
            }
        }
        None
    }
}

/// Intern an identity path to a stable [`IdentityRef`] by hashing. Public
/// so Gateways map a request identity to the same ref the executor uses for
/// `Acting` blocks.
pub fn intern_identity(path: &xolotl_types::Path) -> IdentityRef {
    let h = blake3::hash(path.to_string().as_bytes());
    // blake3 digests are 32 bytes, so the first 8 always exist — copy them into
    // a fixed-size array to derive the ref without a fallible slice conversion.
    let mut head = [0u8; 8];
    head.copy_from_slice(&h.as_bytes()[0..8]);
    let n = u64::from_le_bytes(head);
    // Reserve 0 for ROOT.
    IdentityRef::new(n | 1)
}

/// Current wall clock in millis since epoch.
pub fn now_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(error) => {
            let before_epoch = i64::try_from(error.duration().as_millis()).unwrap_or(i64::MAX);
            before_epoch.saturating_neg()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::{Driver, DriverContext, DriverDescriptor, DriverError, EchoDriver};
    use crate::fact::FactSink;
    use crate::handle::HandleTable;
    use crate::open::{OpenRequest, open_resource};
    use anyhow::{Context, bail, ensure};
    use parking_lot::RwLock;
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

    fn executor() -> Executor {
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(
            Arc::new(RwLock::new(HandleTable::new())),
            facts,
            test_state(),
        );
        Executor::new(ProcessId::new(1), dp, Registry::new())
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
            match tv {
                Some(tv) => {
                    Ok(crate::DriverOutput::new(Outcome::Done(tv.value)).with_taint(tv.taint))
                }
                None => Ok(crate::DriverOutput::new(Outcome::Done(Value::null()))),
            }
        }
    }

    struct TestResourceSpec {
        path: &'static str,
        kind: ResourceKind,
        family: InterfaceFamily,
        method_name: &'static str,
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
        });
        let driver_id = reg.next_driver_id();
        reg.register_driver(DriverDescriptor {
            id: driver_id,
            name: spec.driver_name.into(),
            implements: InterfaceSet::new(vec![iface_id]),
            transport: Transport::InProcess,
            driver,
        });
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
        let ex = executor().with_processes(crate::process::ProcessTable::new());
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

    #[tokio::test]
    async fn acting_denied_without_delegate_grant() -> anyhow::Result<()> {
        // Process 1 holds no grants (empty registry). An Acting block must be
        // denied fail-closed.
        let ex = executor();
        let prog = DoNode::acting(
            xolotl_types::Path::parse("process/bob")?,
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
        use xolotl_types::{Expiry, Grant, MethodBitmap, ResourceSelector, RightFlags, Rights};
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(
            Arc::new(RwLock::new(HandleTable::new())),
            facts,
            test_state(),
        );
        let reg = Registry::new();
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("act-as://process/bob")?,
            rights: Rights::new(MethodBitmap::ALL, RightFlags::DELEGATE),
            constraints: xolotl_types::ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let ex = Executor::new(ProcessId::new(1), dp, reg);
        let prog = DoNode::acting(
            xolotl_types::Path::parse("process/bob")?,
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
                identity: Path::parse("process/bob")?,
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
    async fn cancelled_process_short_circuits_at_operation_boundary() -> anyhow::Result<()> {
        // A process marked Cancelled must not issue its Operation: the boundary
        // check short-circuits to Failure::Cancelled.
        use crate::process::{ProcessEntry, ProcessTable};
        use xolotl_graph::OperationTemplate;
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(
            Arc::new(RwLock::new(HandleTable::new())),
            facts,
            test_state(),
        );
        let procs = ProcessTable::new();
        procs.insert(ProcessEntry::new(
            ProcessId::new(1),
            None,
            IdentityRef::ROOT,
        ));
        let cancelled = procs.cancel_if_non_terminal(ProcessId::new(1));
        ensure!(cancelled == Some(true), "process should be cancelled");
        let ex = Executor::new(ProcessId::new(1), dp, Registry::new()).with_processes(procs);
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
        let handles = Arc::new(RwLock::new(HandleTable::new()));
        let dp = DataPlane::new(handles.clone(), facts, test_state());
        let reg = Registry::new();
        let (first_resource, first_name) = register_test_resource(
            &reg,
            TestResourceSpec {
                path: "effect://cache/first",
                kind: ResourceKind::Effect,
                family: InterfaceFamily::Callable,
                method_name: "invoke",
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
                family: InterfaceFamily::Callable,
                method_name: "invoke",
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
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let handle = {
            let mut table = handles.write();
            open_resource(
                &reg,
                &mut table,
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
        let ex = Executor::new(ProcessId::new(1), dp, reg);
        ex.bind_handle(second_name.clone(), handle);

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
    async fn acting_denied_when_grant_lacks_delegate_flag() -> anyhow::Result<()> {
        use xolotl_types::{Expiry, Grant, MethodBitmap, ResourceSelector, RightFlags, Rights};
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(
            Arc::new(RwLock::new(HandleTable::new())),
            facts,
            test_state(),
        );
        let reg = Registry::new();
        // Selector matches act-as://process/bob but WITHOUT the DELEGATE flag.
        reg.register_grant(Grant {
            id: reg.next_grant_id(),
            holder: ProcessId::new(1),
            selector: ResourceSelector::parse("act-as://process/bob")?,
            rights: Rights::new(MethodBitmap::ALL, RightFlags::CLONE),
            constraints: xolotl_types::ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let ex = Executor::new(ProcessId::new(1), dp, reg);
        let prog = DoNode::acting(
            xolotl_types::Path::parse("process/bob")?,
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
            ex.data_plane.clone(),
            ex.registry.clone(),
        );
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
    async fn wait_signal_resolves_on_write() -> anyhow::Result<()> {
        let state = test_state();
        let (facts, _) = FactSink::in_memory();
        let dp = DataPlane::new(
            Arc::new(RwLock::new(HandleTable::new())),
            facts,
            state.clone(),
        );
        let ex = Executor::new(ProcessId::new(1), dp, Registry::new()).with_state(state.clone());
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
    async fn wait_signal_without_state_fails() -> anyhow::Result<()> {
        let ex = executor(); // no state backend bound
        let signal = xolotl_types::Path::parse("state://stream/1/sig")?;
        let out = ex.eval(&DoNode::wait_signal(signal)).await;
        ensure!(
            matches!(out.outcome, Outcome::Fail(_)),
            "wait without state should fail, got {out:?}"
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
            &[crate::MethodSpec::unary_async("invoke", Purity::Effectful).unprotected_input()],
            Arc::new(EchoDriver),
        )?;
        let ex = bootstrap.kernel.executor_for(bootstrap.root);
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
                    bootstrap.root,
                    ExecutionId::FIRST,
                    InvocationId::new(1),
                    NodeId::new(0),
                    0,
                ),
                true,
            )
            .await;
        match out.outcome {
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
            rights: Rights::new(MethodBitmap::ALL, RightFlags::all()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        let (state_resource, _) = register_test_resource(
            &reg,
            TestResourceSpec {
                path: "state://memory",
                kind: ResourceKind::State,
                family: InterfaceFamily::Value,
                method_name: "read",
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
                family: InterfaceFamily::Callable,
                method_name: "invoke",
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
        let handles = Arc::new(RwLock::new(HandleTable::new()));
        let dp = DataPlane::new(handles.clone(), facts, state);
        let ex = Executor::new(ProcessId::new(1), dp, reg.clone());

        let read_target = ResourceName::new(secret_path.clone());
        let read_handle = {
            let mut table = handles.write();
            open_resource(
                &reg,
                &mut table,
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
        ex.bind_handle(read_target.clone(), read_handle);

        let post_handle = {
            let mut table = handles.write();
            open_resource(
                &reg,
                &mut table,
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
        ex.bind_handle(post_name.clone(), post_handle);

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
