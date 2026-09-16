#![forbid(unsafe_code)]

//! `xolotl-sdk` — embedded façade.
//!
//! Re-exports the embedded kernel surface and provides [`XolotlBuilder`] plus a
//! small [`Xolotl`] wrapper for applications embedding the kernel in-process.

use crate::CompiledProgram;
pub use xolotl_graph::{
    ActorSpec, CapabilityQueryError, DoNode, ExecutionGraph, NodeKind, OperationTemplate, StepRef,
    compile_do, lint_actor,
};
#[cfg(feature = "durable")]
pub use xolotl_kernel::bootstrap::{DurableRecovery, DurableRecoveryConfig, DurableRecoveryReport};
#[cfg(feature = "durable")]
pub use xolotl_kernel::executor::durable::{
    CheckpointInfo, CheckpointJournal, CheckpointQuery, CheckpointStore, ExecutionCheckpoint,
    ExecutionSnapshot,
};
pub use xolotl_kernel::{
    Bootstrap, BootstrapError, DataPlane, Driver, DriverContext, DriverError, DriverPlan,
    ExecutionBuffers, ExecutionConfig, ExecutionIdError, ExecutionIdRange, ExecutionIdSource,
    ExecutionIds, ExecutionLayout, Executor, FactError, FactLookup, FactLookupResult, FactOrder,
    FactPage, FactQuery, FactSink, FactStore, Handle, HandleTable, InMemoryExecutionIdSource,
    Kernel, LoaderRevision, OpenError, PreparedProgram, ProcessAdmissionError,
    ProcessCapacityError, ProcessCleanupFailure, ProcessCleanupReport, ProcessTable, ProgramLoader,
    RecoveryLimits, RecoveryReport, Registry, RequestProcess, SpawnedActor, StepBinding, StepFn,
    StepModule, StepModuleError,
};
#[cfg(feature = "plan")]
pub use xolotl_plan::{
    Plan, PlanError, Step, WriteModeSpec, compile as compile_plan, parse_json, parse_yaml,
};
#[cfg(feature = "standard")]
pub use xolotl_standard::{
    EchoBackend, InferenceBackend, InferenceMethodSupport, InstallError, ModelCapabilities,
    StandardConfig, StandardModule, StandardModules, install_standard,
};
pub use xolotl_state::{
    Backend, InMemoryBackend, InMemoryOptions, MemoryHistory, StateCommit, StateCursor, StateError,
    StateEvent, StateFailure, StateFlush, StateHistory, StateHistoryExt, StateHistoryPage,
    StateHistoryQuery, StateMutation, StatePage, StatePageLimits, StateQuery, StateQueryExt,
    StateRead, StateReadExt, StateResult, StateScan, StateStream, StateSubscription, StateWatch,
    StateWatchError, StateWrite, StateWriteExt, TaintedValue, merge_values,
};
pub use xolotl_types::{
    BlobRef, BudgetSpec, CapSet, Capability, ConstraintSet, ExecutionId, ExecutionOutput, Expiry,
    Fact, Failure, Grant, IdentityRef, InvocationId, MergeRule, Operation, OperationId, Outcome,
    Path, PathError, ProcessId, Purity, ReplayClass, Resource, ResourceName, Rights, TaintSet,
    TaintedFailure, Value, ValueError,
};

use std::error::Error;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Build a minimal in-memory [`Bootstrap`].
pub fn xolotl() -> Bootstrap {
    XolotlBuilder::new().build_bootstrap()
}

#[cfg(feature = "standard")]
/// Build an in-memory [`Bootstrap`] and install the standard in-process package.
pub fn xolotl_with_standard(config: &StandardConfig) -> Result<Bootstrap, InstallError> {
    XolotlBuilder::new().build_bootstrap_with_standard(config)
}

/// Errors returned by embedded program execution helpers.
#[derive(Debug)]
pub enum XolotlError {
    /// A resource path supplied to [`Xolotl::run`] was malformed.
    Path {
        /// Resource string supplied by the caller.
        resource: String,
        /// Path parser error.
        source: PathError,
    },
    /// Opening a requested resource failed.
    Open {
        /// Resource string supplied by the caller.
        resource: String,
        /// Open failure.
        source: OpenError,
    },
    /// A resource path cannot be converted into a request capability.
    Resource {
        /// Resource string supplied by the caller.
        resource: String,
        /// Rejection reason.
        reason: String,
    },
    /// Request process admission or lifecycle cleanup failed.
    Bootstrap {
        /// Bootstrap failure.
        source: BootstrapError,
    },
    /// Inspecting or finalizing a durable execution failed.
    #[cfg(feature = "durable")]
    Durable {
        /// Durable host failure.
        source: Failure,
    },
    /// Plan compilation failed before execution.
    #[cfg(feature = "plan")]
    Plan {
        /// Plan compiler failure.
        source: PlanError,
    },
}

impl fmt::Display for XolotlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path { resource, source } => {
                write!(f, "invalid resource path {resource:?}: {source}")
            }
            Self::Open { resource, source } => {
                write!(f, "open resource {resource:?} failed: {source}")
            }
            Self::Resource { resource, reason } => {
                write!(f, "resource {resource:?} is not runnable: {reason}")
            }
            Self::Bootstrap { source } => write!(f, "request process lifecycle failed: {source}"),
            #[cfg(feature = "durable")]
            Self::Durable { source } => write!(f, "durable execution: {source}"),
            #[cfg(feature = "plan")]
            Self::Plan { source } => write!(f, "plan compile failed: {source}"),
        }
    }
}

impl Error for XolotlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Path { source, .. } => Some(source),
            Self::Open { source, .. } => Some(source),
            Self::Resource { .. } => None,
            Self::Bootstrap { source } => Some(source),
            #[cfg(feature = "durable")]
            Self::Durable { source } => Some(source),
            #[cfg(feature = "plan")]
            Self::Plan { source } => Some(source),
        }
    }
}

/// Builder for an embedded runtime host.
#[derive(Default)]
pub struct XolotlBuilder {
    state: Option<Backend>,
    facts: Option<FactSink>,
    execution_config: ExecutionConfig,
    execution_ids: Option<ExecutionIds>,
    process_capacity: Option<NonZeroUsize>,
    #[cfg(feature = "durable")]
    checkpoint_store: Option<Arc<dyn CheckpointStore>>,
    #[cfg(feature = "durable")]
    checkpoint_recovery_config: Option<DurableRecoveryConfig>,
}

impl XolotlBuilder {
    /// Create a builder using in-memory defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use an explicit state backend.
    pub fn with_state_backend(mut self, state: Backend) -> Self {
        self.state = Some(state);
        self
    }

    /// Use an explicit fact sink.
    pub fn with_fact_sink(mut self, facts: FactSink) -> Self {
        self.facts = Some(facts);
        self
    }

    /// Use explicit state and fact backends.
    pub fn with_backends(mut self, state: Backend, facts: FactSink) -> Self {
        self.state = Some(state);
        self.facts = Some(facts);
        self
    }

    /// Apply interpreter storage and work ceilings to the assembled kernel.
    pub fn with_execution_config(mut self, config: ExecutionConfig) -> Self {
        self.execution_config = config;
        self
    }

    /// Limit retained process entries, including the system root and pending cleanup.
    /// Admission fails at capacity; call [`ProcessTable::reap_finalized`] explicitly
    /// to release completed leaves. Facts, state and checkpoints have separate retention.
    pub fn with_process_capacity(mut self, capacity: NonZeroUsize) -> Self {
        self.process_capacity = Some(capacity);
        self
    }

    /// Share an identity namespace independently of facts and checkpoints.
    /// Retain this source whenever restoring persisted executions.
    pub fn with_execution_ids(mut self, ids: ExecutionIds) -> Self {
        self.execution_ids = Some(ids);
        self
    }

    /// Enable checkpointed programs through a persistent, exclusive journal adapter.
    /// Its identity source serves all evaluations unless `with_execution_ids` is set.
    #[cfg(feature = "durable")]
    pub fn with_checkpoint_store(mut self, store: Arc<dyn CheckpointStore>) -> Self {
        self.checkpoint_store = Some(store);
        self
    }

    /// Bound recovery loading and concurrency; optionally reap completed processes
    /// while advancing a backlog. Configure before starting application work.
    #[cfg(feature = "durable")]
    pub fn with_checkpoint_recovery_config(mut self, config: DurableRecoveryConfig) -> Self {
        self.checkpoint_recovery_config = Some(config);
        self
    }

    /// Build an assembled [`Bootstrap`].
    pub fn build_bootstrap(self) -> Bootstrap {
        Bootstrap::from_kernel(self.build_kernel())
    }

    #[cfg(feature = "standard")]
    /// Build an assembled [`Bootstrap`] and install the standard package.
    pub fn build_bootstrap_with_standard(
        self,
        config: &StandardConfig,
    ) -> Result<Bootstrap, InstallError> {
        let boot = self.build_bootstrap();
        install_standard(&boot, config)?;
        Ok(boot)
    }

    /// Build an embedded runtime wrapper.
    pub fn build(self) -> Xolotl {
        Xolotl::from_bootstrap(self.build_bootstrap())
    }

    #[cfg(feature = "standard")]
    /// Build an embedded runtime wrapper with the standard package installed.
    pub fn build_with_standard(self, config: &StandardConfig) -> Result<Xolotl, InstallError> {
        Ok(Xolotl::from_bootstrap(
            self.build_bootstrap_with_standard(config)?,
        ))
    }

    fn build_kernel(self) -> Kernel {
        let state = self
            .state
            .unwrap_or_else(|| InMemoryBackend::new().into_backend());
        let facts = self.facts.unwrap_or_else(|| FactSink::in_memory().0);
        let mut kernel =
            Kernel::with_backends(state, facts).with_execution_config(self.execution_config);
        if let Some(capacity) = self.process_capacity {
            kernel.processes = ProcessTable::with_capacity(capacity);
        }
        #[cfg(feature = "durable")]
        let kernel = match self.checkpoint_recovery_config {
            Some(config) => kernel.with_checkpoint_recovery_config(config),
            None => kernel,
        };
        #[cfg(feature = "durable")]
        let kernel = match self.checkpoint_store {
            Some(store) => kernel.with_checkpoint_store(store),
            None => kernel,
        };
        match self.execution_ids {
            Some(ids) => kernel.with_execution_ids(ids),
            None => kernel,
        }
    }
}

/// A convenience handle that runs programs against an embedded kernel.
pub struct Xolotl {
    boot: Arc<Bootstrap>,
}

impl Xolotl {
    /// Build a minimal in-memory runtime.
    pub fn new() -> Self {
        XolotlBuilder::new().build()
    }

    /// Build from an already assembled [`Bootstrap`].
    pub fn from_bootstrap(boot: Bootstrap) -> Self {
        Self {
            boot: Arc::new(boot),
        }
    }

    /// Build from an already assembled [`Kernel`].
    pub fn from_kernel(kernel: Kernel) -> Self {
        Self::from_bootstrap(Bootstrap::from_kernel(kernel))
    }

    #[cfg(feature = "standard")]
    /// Build an in-memory runtime with the standard in-process package.
    pub fn with_standard(config: &StandardConfig) -> Result<Self, InstallError> {
        XolotlBuilder::new().build_with_standard(config)
    }

    #[cfg(feature = "standard")]
    /// Install the standard in-process package into this runtime.
    pub fn install_standard(&self, config: &StandardConfig) -> Result<(), InstallError> {
        install_standard(&self.boot, config)
    }

    /// Access the embedded bootstrap and kernel handles.
    pub fn bootstrap(&self) -> &Bootstrap {
        &self.boot
    }

    /// Await asynchronous cleanup of dropped requests, retaining failures for retry.
    pub async fn drain_cleanup(&self) -> ProcessCleanupReport {
        self.boot.drain_cleanup().await
    }

    /// Run a program in a request process limited to `resources`.
    pub async fn run(
        &self,
        resources: &[&str],
        program: DoNode,
    ) -> Result<ExecutionOutput, XolotlError> {
        self.run_with_steps(resources, program, StepModule::default())
            .await
    }

    /// Run a graph with a shared native module in a fresh authorized request.
    /// Modules carry code only; operations still use the request's resource grants.
    /// The evaluation future owns the module, releasing its reference on completion or drop.
    pub async fn run_with_steps(
        &self,
        resources: &[&str],
        program: DoNode,
        steps: StepModule,
    ) -> Result<ExecutionOutput, XolotlError> {
        let grants = self.request_grants(resources)?;
        let request = self
            .boot
            .request_under(self.boot.root, IdentityRef::ROOT, &grants)
            .map_err(|source| XolotlError::Bootstrap { source })?;
        let process = request.id();
        let outcome = match program.bind_process_local_refs(process) {
            Ok(program) => {
                self.boot
                    .kernel
                    .executor_for(process)
                    .with_steps(steps)
                    .eval(&program)
                    .await
            }
            Err(error) => ExecutionOutput::new(
                Outcome::Fail(Failure::InvalidInput {
                    reason: error.to_string(),
                }),
                TaintSet::author(),
            ),
        };
        request
            .finish(&outcome)
            .await
            .map_err(|source| XolotlError::Bootstrap { source })?;
        Ok(outcome)
    }

    /// Compile and run a Plan against the named `resources`.
    #[cfg(feature = "plan")]
    pub async fn run_plan(
        &self,
        resources: &[&str],
        plan: &Plan,
    ) -> Result<ExecutionOutput, XolotlError> {
        self.run_plan_with_steps(resources, plan, StepModule::default())
            .await
    }

    /// Compile and run a Plan with an explicitly assembled native module.
    #[cfg(feature = "plan")]
    pub async fn run_plan_with_steps(
        &self,
        resources: &[&str],
        plan: &Plan,
        steps: StepModule,
    ) -> Result<ExecutionOutput, XolotlError> {
        let program = compile_plan(plan).map_err(|source| XolotlError::Plan { source })?;
        self.run_with_steps(resources, program, steps).await
    }

    /// Execute a compiled portable program with explicit identity, authority and input lineage.
    pub async fn run_program(
        &self,
        identity: IdentityRef,
        resources: &[&str],
        program: &CompiledProgram,
        input: TaintedValue,
    ) -> Result<ExecutionOutput, XolotlError> {
        let prepared = match PreparedProgram::new(program) {
            Ok(prepared) => prepared,
            Err(error) => return Ok(ExecutionOutput::new(Outcome::Fail(error), input.taint)),
        };
        self.run_prepared(identity, resources, &prepared, input)
            .await
    }

    /// Run reusable host instructions in a fresh process with attenuated authority.
    pub async fn run_prepared(
        &self,
        identity: IdentityRef,
        resources: &[&str],
        program: &PreparedProgram,
        input: TaintedValue,
    ) -> Result<ExecutionOutput, XolotlError> {
        self.run_prepared_with_buffers(
            identity,
            resources,
            program,
            input,
            &mut ExecutionBuffers::default(),
        )
        .await
    }

    /// Run a fresh authorized request while retaining empty execution allocations for reuse.
    pub async fn run_prepared_with_buffers(
        &self,
        identity: IdentityRef,
        resources: &[&str],
        program: &PreparedProgram,
        input: TaintedValue,
        buffers: &mut ExecutionBuffers,
    ) -> Result<ExecutionOutput, XolotlError> {
        let grants = self.request_grants(resources)?;
        let request = self
            .boot
            .request_under(self.boot.root, identity, &grants)
            .map_err(|source| XolotlError::Bootstrap { source })?;
        let process = request.id();
        #[cfg(feature = "durable")]
        let request = if program.is_durable() {
            let _process = request.detach();
            None
        } else {
            Some(request)
        };
        #[cfg(not(feature = "durable"))]
        let request = Some(request);
        let outcome = self
            .boot
            .kernel
            .executor_for(process)
            .eval_prepared_with_buffers(program, input, buffers)
            .await;
        #[cfg(feature = "durable")]
        if program.is_durable() {
            self.boot
                .finish_checkpointed_request(process, &outcome)
                .await
                .map_err(|source| XolotlError::Durable { source })?;
            return Ok(outcome);
        }
        if let Some(request) = request {
            request
                .finish(&outcome)
                .await
                .map_err(|source| XolotlError::Bootstrap { source })?;
        }
        Ok(outcome)
    }

    /// Spawn an Actor as a named long-lived Process under the root Process.
    pub async fn spawn_actor(
        &self,
        identity: IdentityRef,
        identity_segment: &str,
        spec: &ActorSpec,
    ) -> Result<SpawnedActor, BootstrapError> {
        self.boot
            .spawn_actor_under(self.boot.root, identity, identity_segment, spec)
            .await
    }

    /// Spawn an Actor with a shared native module for its body and finalizers.
    pub async fn spawn_actor_with_steps(
        &self,
        identity: IdentityRef,
        identity_segment: &str,
        spec: &ActorSpec,
        steps: StepModule,
    ) -> Result<SpawnedActor, BootstrapError> {
        self.boot
            .spawn_actor_under_with_steps(self.boot.root, identity, identity_segment, spec, steps)
            .await
    }

    fn request_grants(
        &self,
        resources: &[&str],
    ) -> Result<Vec<xolotl_kernel::CompiledRequestGrantTemplate>, XolotlError> {
        resources
            .iter()
            .map(|resource| {
                let path = Path::parse(resource).map_err(|source| XolotlError::Path {
                    resource: (*resource).to_string(),
                    source,
                })?;
                if path.cluster().is_some() {
                    return Err(XolotlError::Resource {
                        resource: (*resource).to_string(),
                        reason: "cluster-qualified paths cannot be converted to local request capabilities"
                            .into(),
                    });
                }
                let name = ResourceName::new(path.clone());
                let methods =
                    self.boot
                        .request_method_bitmap(&name, "perform")
                        .map_err(|source| XolotlError::Open {
                            resource: (*resource).to_string(),
                            source,
                        })?;
                let literal = capability_literal("*", &path);
                let selector = xolotl_types::ResourceSelector::parse(&literal).map_err(|source| {
                    XolotlError::Resource {
                        resource: (*resource).to_string(),
                        reason: source.to_string(),
                    }
                })?;
                Ok(xolotl_kernel::CompiledRequestGrantTemplate {
                    selector,
                    methods,
                })
            })
            .collect()
    }
}

fn capability_literal(verb: &str, path: &Path) -> String {
    let mut literal = format!("{verb}://{}", path.scheme());
    for segment in path.segments() {
        literal.push('/');
        literal.push_str(segment);
    }
    literal
}

impl Default for Xolotl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, anyhow, ensure};
    use std::sync::Arc;

    fn p(path: &str) -> anyhow::Result<Path> {
        Path::parse(path).map_err(|error| anyhow!("path parse failed for {path}: {error}"))
    }

    #[tokio::test]
    async fn requests_compose_modules_without_sharing_authority() -> anyhow::Result<()> {
        use xolotl_types::{OutputMode, Purity};
        let nx = Xolotl::new();
        let target = nx.bootstrap().register_effect(
            "effect://module/echo",
            &[xolotl_kernel::MethodSpec::new(
                "invoke",
                Purity::Pure,
                xolotl_kernel::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(xolotl_kernel::EchoDriver),
        )?;
        let library = StepModule::single("echo", move |input, _| {
            DoNode::op(OperationTemplate {
                target: target.clone(),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(input),
            })
        })?;
        let pipeline = StepModule::single("pipeline", |input, _| {
            DoNode::pure(input).and_then(StepRef::new("echo"))
        })?;
        let steps = StepModule::compose([library, pipeline])?;
        let program = DoNode::pure(42).and_then(StepRef::new("pipeline"));
        let (allowed, denied) = tokio::join!(
            nx.run_with_steps(&["effect://module/echo"], program.clone(), steps.clone()),
            nx.run_with_steps(&[], program.clone(), steps),
        );
        ensure!(allowed?.outcome == Outcome::Done(Value::integer(42)));
        ensure!(matches!(
            denied?.outcome,
            Outcome::Fail(Failure::PolicyViolation { .. })
        ));
        ensure!(matches!(
            nx.run(&[], program).await?.outcome,
            Outcome::Fail(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn request_native_module_uses_local_state_capabilities() -> anyhow::Result<()> {
        use xolotl_types::{InterfaceFamily, OutputMode, Purity};
        let nx = Xolotl::new();
        nx.bootstrap().register_subtree_resource(
            "state",
            InterfaceFamily::Value,
            &[xolotl_kernel::MethodSpec::new(
                "write",
                Purity::Idempotent,
                xolotl_kernel::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(xolotl_kernel::EchoDriver),
        )?;
        let target = ResourceName::new(p("state://process/self/scratch")?);
        let module = StepModule::single("store", move |input, _| {
            DoNode::op(OperationTemplate {
                target: target.clone(),
                method: "write".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(input),
            })
        })?;
        let output = nx
            .run_with_steps(
                &["state://process/self/scratch"],
                DoNode::pure(7).and_then(StepRef::new("store")),
                module,
            )
            .await?;
        ensure!(
            output.outcome == Outcome::Done(Value::integer(7)),
            "local request failed: {output:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn dropping_request_future_releases_native_captures() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::Poll;

        let nx = Xolotl::new();
        let entered = Arc::new(AtomicBool::new(false));
        let observed = entered.clone();
        let path = p("state://signal/native-drop")?;
        let function: StepFn = Arc::new(move |_, _| {
            observed.store(true, Ordering::SeqCst);
            DoNode::wait_signal(path.clone())
        });
        let weak = Arc::downgrade(&function);
        let module = StepModule::new([StepBinding::new("wait", function)])?;
        let mut running = Box::pin(nx.run_with_steps(
            &[],
            DoNode::pure(Value::null()).and_then(StepRef::new("wait")),
            module,
        ));
        let state = std::future::poll_fn(|cx| Poll::Ready(running.as_mut().poll(cx))).await;
        ensure!(state.is_pending() && entered.load(Ordering::SeqCst));
        ensure!(weak.upgrade().is_some());
        let process = nx
            .bootstrap()
            .kernel
            .processes
            .children_of(nx.bootstrap().root)
            .into_iter()
            .next()
            .context("missing request")?;
        drop(running);
        ensure!(weak.upgrade().is_none());
        ensure!(
            nx.bootstrap().kernel.processes.status(process)
                == Some(xolotl_types::ProcessStatus::Cancelled)
        );
        let cleanup = nx.drain_cleanup().await;
        ensure!(cleanup.failures.is_empty());
        ensure!(
            nx.bootstrap()
                .kernel
                .state
                .read(&p(&format!(
                    "state://kernel/process/{}/{}/finalized",
                    process.get(),
                    nx.bootstrap()
                        .kernel
                        .processes
                        .lifecycle_execution(process)
                        .context("missing lifecycle scope")?
                        .get()
                ))?)
                .await?
                .is_some()
        );
        Ok(())
    }

    #[cfg(feature = "plan")]
    #[tokio::test]
    async fn plan_runs_with_an_explicit_module() -> anyhow::Result<()> {
        let nx = Xolotl::new();
        let plan = parse_json(
            r#"{"id":"native","version":1,"steps":[{"kind":"pure","value":21},{"kind":"then","name":"double"}]}"#,
        )?;
        let steps = StepModule::single("double", |input, _| match input.as_int() {
            Some(value) => DoNode::pure(value * 2),
            _ => DoNode::fail(Failure::InvalidInput {
                reason: "expected integer".into(),
            }),
        })?;
        ensure!(
            nx.run_plan_with_steps(&[], &plan, steps).await?.outcome
                == Outcome::Done(Value::integer(42))
        );
        Ok(())
    }

    #[tokio::test]
    async fn minimal_constructor_does_not_install_standard_providers() -> anyhow::Result<()> {
        let nx = Xolotl::new();
        let prog = DoNode::Op(OperationTemplate {
            target: ResourceName::new(p("effect://time/now")?),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::null()),
        });
        let err = nx.run(&["effect://time/now"], prog).await;
        ensure!(
            matches!(err, Err(XolotlError::Open { .. })),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn builder_uses_supplied_state_backend() -> anyhow::Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let path = p("state://app/value")?;
        state.write_set(&path, Value::integer(7)).await?;
        let nx = XolotlBuilder::new().with_state_backend(state).build();
        let stored = nx.bootstrap().kernel.state.read(&path).await?;
        ensure!(
            stored == Some(Value::integer(7)),
            "builder did not preserve supplied state backend: {stored:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn xolotl_spawn_actor_runs_under_root() -> anyhow::Result<()> {
        let nx = Xolotl::new();
        let spec = ActorSpec {
            name: "worker".into(),
            body: DoNode::pure(Value::string("done".into())),
            ..ActorSpec::default()
        };
        let actor = nx.spawn_actor(IdentityRef::ROOT, "root", &spec).await?;
        for _ in 0..100 {
            let value = nx.boot.kernel.state.read(&actor.directory).await?;
            if value
                .as_ref()
                .and_then(Value::as_map)
                .and_then(|map| map.get("status"))
                .and_then(Value::as_str)
                == Some("completed")
            {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        anyhow::bail!("actor did not complete");
    }

    #[tokio::test]
    async fn xolotl_spawn_actor_with_steps_installs_before_run() -> anyhow::Result<()> {
        let nx = Xolotl::new();
        let spec = ActorSpec {
            name: "step_worker".into(),
            body: DoNode::pure(Value::integer(1)).and_then(StepRef::new("finish")),
            ..ActorSpec::default()
        };
        let actor = nx
            .spawn_actor_with_steps(
                IdentityRef::ROOT,
                "root",
                &spec,
                StepModule::new([StepBinding::new("finish", Arc::new(|v, _| DoNode::pure(v)))])?,
            )
            .await?;
        for _ in 0..100 {
            let value = nx.boot.kernel.state.read(&actor.directory).await?;
            if value
                .as_ref()
                .and_then(Value::as_map)
                .and_then(|map| map.get("status"))
                .and_then(Value::as_str)
                == Some("completed")
            {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        anyhow::bail!("actor with step did not complete");
    }

    #[cfg(feature = "standard")]
    #[tokio::test]
    async fn standard_constructor_installs_standard_providers() -> anyhow::Result<()> {
        let nx = Xolotl::with_standard(&StandardConfig::default())?;
        let prog = DoNode::Op(OperationTemplate {
            target: ResourceName::new(p("effect://time/now")?),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::null()),
        });
        let out = nx.run(&["effect://time/now"], prog).await?;
        ensure!(
            matches!(out.outcome, Outcome::Done(_)),
            "unexpected outcome: {out:?}"
        );
        Ok(())
    }

    #[cfg(feature = "standard")]
    #[tokio::test]
    async fn run_resources_bound_lazy_open_authority() -> anyhow::Result<()> {
        let nx = Xolotl::with_standard(&StandardConfig::default())?;
        let prog = DoNode::Op(OperationTemplate {
            target: ResourceName::new(p("effect://time/now")?),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::null()),
        });
        let out = nx.run(&["effect://approval/check"], prog).await?;
        ensure!(
            matches!(out.outcome, Outcome::Fail(Failure::PolicyViolation { .. })),
            "unlisted resource was opened by request process: {out:?}"
        );
        Ok(())
    }

    #[cfg(all(feature = "standard", feature = "plan"))]
    #[tokio::test]
    async fn plan_compiles_and_runs() -> anyhow::Result<()> {
        let nx = Xolotl::with_standard(&StandardConfig::default())?;
        let plan = Plan {
            id: "p".into(),
            version: 1,
            description: None,
            steps: vec![Step::Perform {
                target: "effect://time/now".into(),
                input: Some(serde_json::Value::Null),
            }],
        };
        let out = nx.run_plan(&["effect://time/now"], &plan).await?;
        ensure!(
            matches!(out.outcome, Outcome::Done(_)),
            "unexpected outcome: {out:?}"
        );
        Ok(())
    }

    #[cfg(all(feature = "standard", feature = "plan"))]
    #[tokio::test]
    async fn run_plan_resource_allowlist_supports_state_write() -> anyhow::Result<()> {
        let nx = Xolotl::with_standard(&StandardConfig::default())?;
        let target = p("state://app/sdk-write")?;
        let plan = Plan {
            id: "write".into(),
            version: 1,
            description: None,
            steps: vec![Step::Write {
                path: target.to_string(),
                value: serde_json::json!("stored"),
                mode: WriteModeSpec::Set,
            }],
        };
        let out = nx.run_plan(&["state://app/sdk-write"], &plan).await?;
        ensure!(
            matches!(out.outcome, Outcome::Done(_)),
            "unexpected state write outcome: {out:?}"
        );
        let stored = nx.bootstrap().kernel.state.read(&target).await?;
        ensure!(
            stored == Some(Value::string("stored".into())),
            "state write did not persist: {stored:?}"
        );
        Ok(())
    }
}
