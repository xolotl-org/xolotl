#![forbid(unsafe_code)]

//! `xolotl-sdk` — embedded façade.
//!
//! Re-exports the embedded kernel surface, including [`KernelBuilder`], plus a
//! small [`Xolotl`] wrapper for applications embedding the kernel in-process.

use crate::CompiledProgram;
pub use xolotl_graph::{
    ActorSpec, CapabilityQueryError, DoNode, ExecutionGraph, NodeKind, OperationTemplate, StepRef,
    compile_do, lint_actor,
};
pub use xolotl_kernel::{
    Bootstrap, BootstrapError, CleanupProgress, CleanupScope, CleanupTicket, DataPlane, Driver,
    DriverContext, DriverError, DriverPlan, ExecutionBuffers, ExecutionConfig, ExecutionIdError,
    ExecutionIdRange, ExecutionIdSource, ExecutionIds, ExecutionLayout, Executor, FactError,
    FactIoMode, FactLookup, FactLookupResult, FactOrder, FactPage, FactQuery, FactSink, FactStore,
    Handle, HandleTable, InMemoryExecutionIdSource, Kernel, KernelBuilder, LoaderRevision,
    OpenError, OpenRequest, PreparedOpen, PreparedProgram, ProcessAdmissionError,
    ProcessCapacityError, ProcessCleanupFailure, ProcessCleanupReport, ProcessFinalizationReport,
    ProcessTable, ProgramLoader, Registry, RequestAuthorizer, RequestFinishError, RequestProcess,
    SpawnedActor, StepBinding, StepFn, StepModule, StepModuleError, WeakHandleTable, prepare_open,
};
#[cfg(feature = "plan")]
pub use xolotl_plan::{
    CompileLimits as PlanCompileLimits, Plan, PlanError, Step, WriteModeSpec,
    compile as compile_plan, compile_with_limits as compile_plan_with_limits, parse_json,
    parse_json_with_limits, parse_yaml, parse_yaml_with_limits,
};
#[cfg(feature = "standard")]
pub use xolotl_standard::{
    EchoBackend, InferenceBackend, InferenceMethodSupport, InstallError, ModelCapabilities,
    StandardConfig, StandardModule, StandardModules, install_standard,
};
pub use xolotl_state::{
    Backend, StateCommit, StateCursor, StateError, StateEvent, StateFailure, StateFlush,
    StateHistory, StateHistoryExt, StateHistoryPage, StateHistoryQuery, StateHistoryRetention,
    StateHistoryTrim, StateHistoryTrimLimits, StateMutation, StatePage, StatePageLimits,
    StateQuery, StateQueryExt, StateRead, StateReadExt, StateResult, StateScan, StateStream,
    StateSubscription, StateWatch, StateWatchError, StateWrite, StateWriteExt, TaintedValue,
    merge_values,
};
#[cfg(feature = "memory")]
pub use xolotl_state::{InMemoryBackend, InMemoryOptions, MemoryHistory};
pub use xolotl_types::{
    BlobRef, BudgetSpec, CapSet, Capability, ConstraintSet, ExecutionId, ExecutionOutput, Expiry,
    Fact, Failure, Grant, GrantMethods, GrantRights, IdentityRef, InvocationId, MergeRule,
    Operation, OperationId, Outcome, Path, PathError, ProcessId, ProcessStatus, Purity,
    ReplayClass, Resource, ResourceName, TaintSet, TaintedFailure, Value, ValueError,
};

use std::error::Error;
use std::fmt;
use std::sync::Arc;

/// Body output and immutable cleanup evidence have independent ownership.
#[derive(Debug)]
pub struct ExecutionCompletion {
    /// Evaluation outcome, including body provenance and unresolved effects.
    pub output: ExecutionOutput,
    /// Committed cleanup evidence; absent only when preparation rejected before admission.
    pub finalization: Option<Arc<ProcessFinalizationReport>>,
}

/// Build a [`Bootstrap`] with the host-selected State backend.
pub fn xolotl(state: Backend) -> Bootstrap {
    Bootstrap::from_kernel(KernelBuilder::new(state).build())
}

/// Build an in-memory [`Bootstrap`] for embedded and test hosts.
#[cfg(feature = "memory")]
pub fn xolotl_in_memory() -> Bootstrap {
    Bootstrap::in_memory()
}

#[cfg(feature = "standard")]
/// Build a [`Bootstrap`] with a chosen State backend and install standard providers.
pub fn xolotl_with_standard(
    state: Backend,
    config: &StandardConfig,
) -> Result<Bootstrap, InstallError> {
    let boot = xolotl(state);
    install_standard(&boot, config)?;
    Ok(boot)
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
    /// Evaluation completed, but the request lifecycle could not be finalized.
    /// The original output and process remain available for live cleanup retries.
    Finalization {
        /// Request process whose cleanup remains retryable.
        process: ProcessId,
        /// Output produced before finalization failed, including its taint.
        output: Box<ExecutionOutput>,
        /// Lifecycle failure.
        source: RequestFinishError,
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
            Self::Finalization {
                process, source, ..
            } => write!(f, "request process {process} finalization failed: {source}"),
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
            Self::Finalization { source, .. } => Some(source),
            #[cfg(feature = "plan")]
            Self::Plan { source } => Some(source),
        }
    }
}

/// A convenience handle that runs programs against an embedded kernel.
pub struct Xolotl {
    boot: Arc<Bootstrap>,
}

impl Xolotl {
    /// Build a runtime with the host-selected State backend.
    pub fn new(state: Backend) -> Self {
        Self::from_kernel(KernelBuilder::new(state).build())
    }

    /// Build a runtime with in-memory State and Facts.
    #[cfg(feature = "memory")]
    pub fn in_memory() -> Self {
        Self::from_kernel(Kernel::in_memory())
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
    /// Build a runtime with a chosen State backend and standard providers.
    pub fn with_standard(state: Backend, config: &StandardConfig) -> Result<Self, InstallError> {
        Ok(Self::from_bootstrap(xolotl_with_standard(state, config)?))
    }

    #[cfg(feature = "standard")]
    /// Install the standard in-process package into this runtime.
    pub fn install_standard(&self, config: &StandardConfig) -> Result<(), InstallError> {
        install_standard(&self.boot, config)
    }

    /// Access the shared host, including independently composed cleanup and
    /// cancellation services. Cloning this Arc retains the same kernel.
    pub fn bootstrap(&self) -> &Arc<Bootstrap> {
        &self.boot
    }

    /// Await asynchronous cleanup of dropped requests, retaining failures for retry.
    pub async fn drain_cleanup(&self) -> ProcessCleanupReport {
        self.boot.drain_cleanup().await
    }

    /// Run a program for an explicit caller in a request process limited to `resources`.
    /// The identity must exist in the kernel's identity directory. The trusted
    /// host must authorize this allowlist; identity is not a grant.
    pub async fn run(
        &self,
        identity: IdentityRef,
        resources: &[&str],
        program: DoNode,
    ) -> Result<ExecutionCompletion, XolotlError> {
        self.run_with_steps(identity, resources, program, StepModule::default())
            .await
    }

    /// Run a graph for an explicit caller with a shared native module in a fresh authorized request.
    /// The identity must exist in the kernel's identity directory. The trusted
    /// host must authorize `resources`; identity is not a grant.
    /// Modules carry code only; operations still use the request's resource grants.
    /// The evaluation future owns the module, releasing its reference on completion or drop.
    pub async fn run_with_steps(
        &self,
        identity: IdentityRef,
        resources: &[&str],
        program: DoNode,
        steps: StepModule,
    ) -> Result<ExecutionCompletion, XolotlError> {
        let grants = self.request_grants(resources)?;
        let request = self
            .boot
            .request_under(self.boot.root(), identity, &grants)
            .map_err(|source| XolotlError::Bootstrap { source })?;
        let process = request.id();
        let outcome = match program.bind_process_local_refs(process) {
            Ok(program) => {
                self.boot
                    .kernel()
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
        let finalization = match request.finish(&outcome).await {
            Ok(report) => report,
            Err(source) => {
                return Err(XolotlError::Finalization {
                    process,
                    output: Box::new(outcome),
                    source,
                });
            }
        };
        Ok(ExecutionCompletion {
            output: outcome,
            finalization: Some(finalization),
        })
    }

    /// Compile and run a Plan for an explicit caller against the named `resources`.
    #[cfg(feature = "plan")]
    pub async fn run_plan(
        &self,
        identity: IdentityRef,
        resources: &[&str],
        plan: &Plan,
    ) -> Result<ExecutionCompletion, XolotlError> {
        self.run_plan_with_steps(identity, resources, plan, StepModule::default())
            .await
    }

    /// Compile and run a Plan for an explicit caller with an assembled native module.
    #[cfg(feature = "plan")]
    pub async fn run_plan_with_steps(
        &self,
        identity: IdentityRef,
        resources: &[&str],
        plan: &Plan,
        steps: StepModule,
    ) -> Result<ExecutionCompletion, XolotlError> {
        let program = compile_plan(plan).map_err(|source| XolotlError::Plan { source })?;
        self.run_with_steps(identity, resources, program, steps)
            .await
    }

    /// Execute a portable program with explicit identity, authority and input lineage.
    pub async fn run_program(
        &self,
        identity: IdentityRef,
        resources: &[&str],
        program: &CompiledProgram,
        input: TaintedValue,
    ) -> Result<ExecutionCompletion, XolotlError> {
        let prepared = match PreparedProgram::new(program) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Ok(ExecutionCompletion {
                    output: ExecutionOutput::new(Outcome::Fail(error), input.taint),
                    finalization: None,
                });
            }
        };
        self.run_prepared(identity, resources, &prepared, input)
            .await
    }

    /// Run reusable instructions in a fresh process with attenuated authority.
    pub async fn run_prepared(
        &self,
        identity: IdentityRef,
        resources: &[&str],
        program: &PreparedProgram,
        input: TaintedValue,
    ) -> Result<ExecutionCompletion, XolotlError> {
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
    ) -> Result<ExecutionCompletion, XolotlError> {
        let grants = self.request_grants(resources)?;
        let request = self
            .boot
            .request_under(self.boot.root(), identity, &grants)
            .map_err(|source| XolotlError::Bootstrap { source })?;
        let process = request.id();
        let outcome = self
            .boot
            .kernel()
            .executor_for(process)
            .eval_prepared_with_buffers(program, input, buffers)
            .await;
        let finalization = match request.finish(&outcome).await {
            Ok(report) => report,
            Err(source) => {
                return Err(XolotlError::Finalization {
                    process,
                    output: Box::new(outcome),
                    source,
                });
            }
        };
        Ok(ExecutionCompletion {
            output: outcome,
            finalization: Some(finalization),
        })
    }

    /// Spawn an Actor as a named long-lived Process under the root Process.
    pub async fn spawn_actor(
        &self,
        identity: IdentityRef,
        identity_segment: &str,
        spec: &ActorSpec,
    ) -> Result<SpawnedActor, BootstrapError> {
        self.boot
            .spawn_actor_under(self.boot.root(), identity, identity_segment, spec)
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
            .spawn_actor_under_with_steps(self.boot.root(), identity, identity_segment, spec, steps)
            .await
    }

    fn request_grants(
        &self,
        resources: &[&str],
    ) -> Result<Vec<xolotl_kernel::CompiledRequestGrantTemplate>, XolotlError> {
        let mut grants = Vec::new();
        for resource in resources {
            let path = Path::parse(resource).map_err(|source| XolotlError::Path {
                resource: (*resource).to_string(),
                source,
            })?;
            let registry = self.boot.kernel().registry();
            let resource_id = registry
                .resolve_resource(&ResourceName::new(path.clone()))
                .map_err(|source| XolotlError::Open {
                    resource: (*resource).to_string(),
                    source: source.into(),
                })?;
            let methods = registry
                .resource_methods(resource_id)
                .filter(|methods| !methods.is_empty())
                .ok_or_else(|| XolotlError::Resource {
                    resource: (*resource).to_string(),
                    reason: "resource has no callable methods".into(),
                })?;
            let mut categories = std::collections::BTreeMap::new();
            for method in &methods {
                categories
                    .entry(method.authority.verb())
                    .or_insert_with(Vec::new)
                    .push(method.name.clone());
            }
            // A resource allowlist exposes its installed methods, grouped by
            // their actual authority. It never treats perform as a wildcard.
            for (verb, names) in categories {
                let selector = xolotl_types::ResourceSelector {
                    pattern: capability_for_path(verb, &path).map_err(|source| {
                        XolotlError::Resource {
                            resource: (*resource).to_string(),
                            reason: source.to_string(),
                        }
                    })?,
                };
                grants.push(xolotl_kernel::CompiledRequestGrantTemplate {
                    selector,
                    rights: GrantRights::new(
                        GrantMethods::names(names),
                        xolotl_types::RightFlags::empty(),
                    ),
                });
            }
        }
        Ok(grants)
    }
}

fn capability_for_path(verb: &str, path: &Path) -> Result<Capability, xolotl_types::CapError> {
    let capability = Capability::try_new(
        verb,
        path.scheme(),
        path.segments().iter().map(|segment| segment.as_str()),
        None,
    )?;
    match path.cluster() {
        Some(cluster) => capability.try_with_cluster(cluster),
        None => Ok(capability),
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
    async fn native_pure_request_finishes_without_a_state_write_port() -> anyhow::Result<()> {
        for state in [
            Backend::new(),
            Backend::new().with_read(Arc::new(xolotl_state::InMemoryBackend::new())),
        ] {
            let nx = Xolotl::new(state);
            let output = nx
                .run_with_steps(
                    IdentityRef::ROOT,
                    &[],
                    DoNode::pure(23),
                    StepModule::default(),
                )
                .await?
                .output;
            ensure!(output.outcome == Outcome::Done(Value::integer(23)));
            let process = nx
                .bootstrap()
                .kernel()
                .processes()
                .children_of(nx.bootstrap().root())
                .into_iter()
                .next()
                .context("missing completed request")?;
            ensure!(nx.bootstrap().cleanup_ticket(process)?.is_complete());
            ensure!(!nx.bootstrap().kernel().facts().is_enabled());
            ensure!(nx.bootstrap().kernel().facts().facts_of(process).is_err());
            ensure!(matches!(
                nx.bootstrap()
                    .kernel()
                    .state()
                    .write_set(&p("state://application/result")?, Value::integer(23))
                    .await,
                Err(StateFailure {
                    error: StateError::MissingCapability("write"),
                    ..
                })
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn portable_pure_request_finishes_without_state_ports() -> anyhow::Result<()> {
        let nx = Xolotl::new(Backend::new());
        let program = crate::Program::new(crate::Expression::literal(37)).compile()?;
        let prepared = PreparedProgram::new(&program)?;
        let output = nx
            .run_prepared_with_buffers(
                IdentityRef::ROOT,
                &[],
                &prepared,
                TaintedValue::pristine(Value::null()),
                &mut ExecutionBuffers::default(),
            )
            .await?
            .output;
        ensure!(output.outcome == Outcome::Done(Value::integer(37)));
        let process = nx
            .bootstrap()
            .kernel()
            .processes()
            .children_of(nx.bootstrap().root())
            .into_iter()
            .next()
            .context("missing completed request")?;
        ensure!(nx.bootstrap().cleanup_ticket(process)?.is_complete());
        ensure!(
            nx.bootstrap()
                .kernel()
                .processes()
                .finalization_report(process)
                .is_some()
        );
        Ok(())
    }

    #[tokio::test]
    async fn requests_compose_modules_without_sharing_authority() -> anyhow::Result<()> {
        use xolotl_types::{OutputMode, Purity};
        let nx = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
        let target = nx.bootstrap().register_effect(
            "effect://module/echo",
            &[xolotl_kernel::MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
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
            nx.run_with_steps(
                IdentityRef::ROOT,
                &["effect://module/echo"],
                program.clone(),
                steps.clone()
            ),
            nx.run_with_steps(IdentityRef::ROOT, &[], program.clone(), steps),
        );
        ensure!(allowed?.output.outcome == Outcome::Done(Value::integer(42)));
        ensure!(matches!(
            denied?.output.outcome,
            Outcome::Fail(Failure::PolicyViolation { .. })
        ));
        ensure!(matches!(
            nx.run(IdentityRef::ROOT, &[], program)
                .await?
                .output
                .outcome,
            Outcome::Fail(_)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn graph_request_preserves_the_supplied_caller_identity_without_recording()
    -> anyhow::Result<()> {
        use xolotl_types::{MethodAuthority, OutputMode, OutputModeSet, Purity};

        type ObservedCallIdentity = (IdentityRef, Option<IdentityRef>);

        struct CallerProbe {
            processes: ProcessTable,
            calls: Arc<std::sync::Mutex<Vec<ObservedCallIdentity>>>,
        }

        #[async_trait::async_trait]
        impl Driver for CallerProbe {
            async fn call(
                &self,
                _: xolotl_types::MethodId,
                input: Value,
                _: OutputMode,
                context: &DriverContext,
            ) -> Result<xolotl_types::DriverOutput, DriverError> {
                self.calls
                    .lock()
                    .map_err(|error| DriverError::Other(error.to_string()))?
                    .push((context.acting, self.processes.identity(context.caller)));
                Ok(xolotl_types::DriverOutput::new(Outcome::Done(input)))
            }
        }

        let (sink, facts) = FactSink::in_memory();
        let nx = Xolotl::from_kernel(
            KernelBuilder::new(xolotl_state::InMemoryBackend::new().into_backend())
                .with_fact_sink(sink)
                .build(),
        );
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let path = "effect://sdk/caller";
        let target = nx.bootstrap().register_effect(
            path,
            &[xolotl_kernel::MethodSpec::new(
                "invoke",
                MethodAuthority::Perform,
                Purity::Effectful,
                OutputModeSet::UNARY,
            )],
            Arc::new(CallerProbe {
                processes: nx.bootstrap().kernel().processes().clone(),
                calls: calls.clone(),
            }),
        )?;
        let identity = nx
            .bootstrap()
            .kernel()
            .identities()
            .resolve_or_register(&Path::parse("identity://sdk/caller")?)?;
        let output = nx
            .run(
                identity,
                &[path],
                DoNode::op(OperationTemplate {
                    target,
                    method: "invoke".into(),
                    method_id: None,
                    output: OutputMode::Unary,
                    literal_input: Some(Value::integer(7)),
                }),
            )
            .await?
            .output;
        ensure!(output.outcome == Outcome::Done(Value::integer(7)));
        ensure!(
            calls
                .lock()
                .map_err(|error| anyhow!(error.to_string()))?
                .as_slice()
                == [(identity, Some(identity))],
            "the graph request did not preserve its caller at the driver boundary"
        );
        ensure!(facts.all_facts()?.is_empty());
        #[cfg(feature = "plan")]
        {
            let plan_identity = nx
                .bootstrap()
                .kernel()
                .identities()
                .resolve_or_register(&Path::parse("identity://sdk/plan-caller")?)?;
            let plan = Plan {
                id: "caller".into(),
                version: 1,
                description: None,
                steps: vec![Step::Perform {
                    target: path.into(),
                    input: Some(serde_json::json!(11)),
                }],
            };
            let result = nx.run_plan(plan_identity, &[path], &plan).await?.output;
            ensure!(result.outcome == Outcome::Done(Value::integer(11)));
            ensure!(
                calls
                    .lock()
                    .map_err(|error| anyhow!(error.to_string()))?
                    .last()
                    == Some(&(plan_identity, Some(plan_identity))),
                "the Plan request did not preserve its caller at the driver boundary"
            );
            ensure!(facts.all_facts()?.is_empty());
        }
        Ok(())
    }

    #[tokio::test]
    async fn request_native_module_uses_local_state_capabilities() -> anyhow::Result<()> {
        use xolotl_types::{InterfaceFamily, OutputMode, Purity};
        let nx = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
        nx.bootstrap().register_subtree_resource(
            "state",
            InterfaceFamily::Value,
            &[xolotl_kernel::MethodSpec::new(
                "write",
                xolotl_types::MethodAuthority::Write,
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
                IdentityRef::ROOT,
                &["state://process/self/scratch"],
                DoNode::pure(7).and_then(StepRef::new("store")),
                module,
            )
            .await?
            .output;
        ensure!(
            output.outcome == Outcome::Done(Value::integer(7)),
            "local request failed: {output:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn resource_allowlists_cover_custom_methods_with_distinct_authority() -> anyhow::Result<()>
    {
        use xolotl_kernel::MethodSpec;
        use xolotl_types::{InterfaceFamily, MethodAuthority, OutputModeSet};
        let nx = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
        nx.bootstrap().register_subtree_resource(
            "state",
            InterfaceFamily::Value,
            &[
                MethodSpec::new(
                    "load",
                    MethodAuthority::Read,
                    Purity::Pure,
                    OutputModeSet::UNARY,
                ),
                MethodSpec::new(
                    "save",
                    MethodAuthority::Write,
                    Purity::Effectful,
                    OutputModeSet::UNARY,
                ),
            ],
            Arc::new(xolotl_kernel::FnDriver(
                |method: xolotl_types::MethodId, input: Value| {
                    Ok(Value::integer(
                        input.as_int().unwrap_or(0) + 1 + method.get() as i64,
                    ))
                },
            )),
        )?;
        let target = ResourceName::new(p("state://app/data")?);
        let operation = |name: &str| {
            DoNode::op(OperationTemplate {
                target: target.clone(),
                method: name.into(),
                method_id: None,
                output: xolotl_types::OutputMode::Unary,
                literal_input: Some(Value::integer(4)),
            })
        };
        let program = DoNode::both(operation("save"), operation("load"));
        let output = nx
            .run(IdentityRef::ROOT, &["state://app/data"], program)
            .await?
            .output;
        ensure!(
            output.outcome
                == Outcome::Done(Value::list(vec![Value::integer(6), Value::integer(5)]))
        );
        Ok(())
    }

    #[tokio::test]
    async fn cluster_resource_allowlists_preserve_scope_and_method_authority() -> anyhow::Result<()>
    {
        use xolotl_kernel::MethodSpec;
        use xolotl_types::{
            InterfaceFamily, MethodAuthority, OutputMode, OutputModeSet, RightFlags,
        };

        const LOCAL: &str = "state://app/data";
        const PHONE: &str = "path://phone/state/app/data";
        const TABLET: &str = "path://tablet/state/app/data";
        let nx = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
        let methods = [
            MethodSpec::new(
                "load",
                MethodAuthority::Read,
                Purity::Pure,
                OutputModeSet::UNARY,
            ),
            MethodSpec::new(
                "save",
                MethodAuthority::Write,
                Purity::Effectful,
                OutputModeSet::UNARY,
            ),
        ];
        for (path, selector) in [
            (LOCAL, "*://state/app/data"),
            (PHONE, "*://path://phone/state/app/data"),
            (TABLET, "*://path://tablet/state/app/data"),
        ] {
            nx.bootstrap().register_subtree_resource_at(
                path,
                selector,
                InterfaceFamily::Value,
                &methods,
                Arc::new(xolotl_kernel::EchoDriver),
            )?;
        }

        let grants = nx.request_grants(&[PHONE])?;
        ensure!(grants.len() == 2);
        let read = grants
            .iter()
            .find(|grant| grant.selector.verb() == "read")
            .context("missing read grant")?;
        let write = grants
            .iter()
            .find(|grant| grant.selector.verb() == "write")
            .context("missing write grant")?;
        ensure!(read.rights.methods == GrantMethods::name("load"));
        ensure!(write.rights.methods == GrantMethods::name("save"));
        for grant in &grants {
            ensure!(grant.selector.matches(grant.selector.verb(), &p(PHONE)?));
            ensure!(!grant.selector.matches(grant.selector.verb(), &p(LOCAL)?));
            ensure!(!grant.selector.matches(grant.selector.verb(), &p(TABLET)?));
        }

        let operation = |path: &str, method: &str| -> anyhow::Result<OperationTemplate> {
            Ok(OperationTemplate {
                target: ResourceName::new(p(path)?),
                method: method.into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::integer(4)),
            })
        };
        let allowed = nx
            .run(
                IdentityRef::ROOT,
                &[PHONE],
                DoNode::both(
                    DoNode::op(operation(PHONE, "load")?),
                    DoNode::op(operation(PHONE, "save")?),
                ),
            )
            .await?
            .output;
        ensure!(
            allowed.outcome
                == Outcome::Done(Value::list(vec![Value::integer(4), Value::integer(4)])),
            "clustered methods failed: {allowed:?}"
        );
        for path in [LOCAL, TABLET] {
            let denied = nx
                .run(
                    IdentityRef::ROOT,
                    &[PHONE],
                    DoNode::op(operation(path, "load")?),
                )
                .await?
                .output;
            ensure!(
                matches!(
                    denied.outcome,
                    Outcome::Fail(Failure::PolicyViolation { .. })
                ),
                "unlisted cluster or local path was authorized: {denied:?}"
            );
        }

        let compiled = crate::Program::new(crate::Expression::Invoke {
            operation: operation(PHONE, "load")?,
        })
        .compile()?;
        let prepared = PreparedProgram::new(&compiled)?;
        let prepared_output = nx
            .run_prepared(
                IdentityRef::ROOT,
                &[PHONE],
                &prepared,
                TaintedValue::pristine(Value::null()),
            )
            .await?
            .output;
        ensure!(prepared_output.outcome == Outcome::Done(Value::integer(4)));

        let parent = nx.bootstrap().request_under(
            nx.bootstrap().root(),
            IdentityRef::ROOT,
            &[xolotl_kernel::CompiledRequestGrantTemplate {
                selector: xolotl_types::ResourceSelector::parse(
                    "read://path://phone/state/app/data",
                )?,
                rights: GrantRights::new(GrantMethods::name("read"), RightFlags::empty()),
            }],
        )?;
        let widened = nx
            .bootstrap()
            .request_under(parent.id(), IdentityRef::ROOT, &grants);
        ensure!(matches!(
            widened,
            Err(BootstrapError::CapabilityCeiling { .. })
        ));
        parent
            .finish(&ExecutionOutput::new(
                Outcome::Done(Value::null()),
                TaintSet::author(),
            ))
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn cluster_effect_registration_and_request_use_the_same_path_scope() -> anyhow::Result<()>
    {
        use xolotl_types::{MethodAuthority, OutputMode, OutputModeSet};

        const LOCAL: &str = "effect://module/echo";
        const PHONE: &str = "path://phone/effect/module/echo";
        const TABLET: &str = "path://tablet/effect/module/echo";
        let nx = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
        for path in [LOCAL, PHONE, TABLET] {
            nx.bootstrap().register_effect(
                path,
                &[xolotl_kernel::MethodSpec::new(
                    "invoke",
                    MethodAuthority::Perform,
                    Purity::Pure,
                    OutputModeSet::UNARY,
                )],
                Arc::new(xolotl_kernel::EchoDriver),
            )?;
        }
        let invoke = |path: &str| -> anyhow::Result<DoNode> {
            Ok(DoNode::op(OperationTemplate {
                target: ResourceName::new(p(path)?),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::integer(17)),
            }))
        };
        let allowed = nx
            .run(IdentityRef::ROOT, &[PHONE], invoke(PHONE)?)
            .await?
            .output;
        ensure!(
            allowed.outcome == Outcome::Done(Value::integer(17)),
            "clustered effect failed: {allowed:?}"
        );
        for path in [LOCAL, TABLET] {
            let denied = nx
                .run(IdentityRef::ROOT, &[PHONE], invoke(path)?)
                .await?
                .output;
            ensure!(
                matches!(
                    denied.outcome,
                    Outcome::Fail(Failure::PolicyViolation { .. })
                ),
                "request authorized an effect outside the named cluster: {denied:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn dropping_request_future_releases_native_captures() -> anyhow::Result<()> {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::Poll;

        let nx = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
        let entered = Arc::new(AtomicBool::new(false));
        let observed = entered.clone();
        let function: StepFn = Arc::new(move |_, _| {
            observed.store(true, Ordering::SeqCst);
            DoNode::wait_deadline(i64::MAX)
        });
        let weak = Arc::downgrade(&function);
        let module = StepModule::new([StepBinding::new("wait", function)])?;
        let mut running = Box::pin(nx.run_with_steps(
            IdentityRef::ROOT,
            &[],
            DoNode::pure(Value::null()).and_then(StepRef::new("wait")),
            module,
        ));
        let state = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            std::future::poll_fn(|cx| {
                let state = running.as_mut().poll(cx);
                if state.is_ready() || entered.load(Ordering::SeqCst) {
                    Poll::Ready(state)
                } else {
                    Poll::Pending
                }
            }),
        )
        .await
        .context("request did not reach its native step")?;
        ensure!(
            state.is_pending() && entered.load(Ordering::SeqCst),
            "request state at native step: {state:?}, entered: {}",
            entered.load(Ordering::SeqCst)
        );
        ensure!(weak.upgrade().is_some());
        let process = nx
            .bootstrap()
            .kernel()
            .processes()
            .children_of(nx.bootstrap().root())
            .into_iter()
            .next()
            .context("missing request")?;
        drop(running);
        ensure!(weak.upgrade().is_none());
        ensure!(
            nx.bootstrap().kernel().processes().status(process)
                == Some(xolotl_types::ProcessStatus::Cancelled)
        );
        let cleanup = nx.drain_cleanup().await;
        ensure!(cleanup.failures.is_empty());
        ensure!(nx.bootstrap().cleanup_ticket(process)?.is_complete());
        Ok(())
    }

    #[cfg(feature = "plan")]
    #[tokio::test]
    async fn plan_runs_with_an_explicit_module() -> anyhow::Result<()> {
        let nx = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
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
            nx.run_plan_with_steps(IdentityRef::ROOT, &[], &plan, steps)
                .await?
                .output
                .outcome
                == Outcome::Done(Value::integer(42))
        );
        Ok(())
    }

    #[tokio::test]
    async fn minimal_constructor_does_not_install_standard_providers() -> anyhow::Result<()> {
        let nx = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
        let prog = DoNode::Op(OperationTemplate {
            target: ResourceName::new(p("effect://time/now")?),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::null()),
        });
        let err = nx
            .run(IdentityRef::ROOT, &["effect://time/now"], prog)
            .await;
        ensure!(
            matches!(err, Err(XolotlError::Open { .. })),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn builder_uses_supplied_state_backend() -> anyhow::Result<()> {
        let state: Backend = xolotl_state::InMemoryBackend::new().into_backend();
        let path = p("state://app/value")?;
        state.write_set(&path, Value::integer(7)).await?;
        let nx = Xolotl::from_kernel(KernelBuilder::new(state).build());
        let stored = nx.bootstrap().kernel().state().read(&path).await?;
        ensure!(
            stored == Some(Value::integer(7)),
            "builder did not preserve supplied state backend: {stored:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn xolotl_spawn_actor_runs_under_root() -> anyhow::Result<()> {
        let nx = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
        let spec = ActorSpec {
            name: "worker".into(),
            body: DoNode::pure(Value::string("done".into())),
            ..ActorSpec::default()
        };
        let actor = nx.spawn_actor(IdentityRef::ROOT, "root", &spec).await?;
        for _ in 0..100 {
            let value = nx.boot.kernel().state().read(&actor.directory).await?;
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
        let nx = Xolotl::new(xolotl_state::InMemoryBackend::new().into_backend());
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
            let value = nx.boot.kernel().state().read(&actor.directory).await?;
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
        let nx = Xolotl::with_standard(
            xolotl_state::InMemoryBackend::new().into_backend(),
            &StandardConfig::default(),
        )?;
        let prog = DoNode::Op(OperationTemplate {
            target: ResourceName::new(p("effect://time/now")?),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::null()),
        });
        let out = nx
            .run(IdentityRef::ROOT, &["effect://time/now"], prog)
            .await?
            .output;
        ensure!(
            matches!(out.outcome, Outcome::Done(_)),
            "unexpected outcome: {out:?}"
        );
        Ok(())
    }

    #[cfg(feature = "standard")]
    #[tokio::test]
    async fn run_resources_bound_lazy_open_authority() -> anyhow::Result<()> {
        let nx = Xolotl::with_standard(
            xolotl_state::InMemoryBackend::new().into_backend(),
            &StandardConfig::default(),
        )?;
        let prog = DoNode::Op(OperationTemplate {
            target: ResourceName::new(p("effect://time/now")?),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::null()),
        });
        let out = nx
            .run(IdentityRef::ROOT, &["effect://approval/check"], prog)
            .await?
            .output;
        ensure!(
            matches!(out.outcome, Outcome::Fail(Failure::PolicyViolation { .. })),
            "unlisted resource was opened by request process: {out:?}"
        );
        Ok(())
    }

    #[cfg(all(feature = "standard", feature = "plan"))]
    #[tokio::test]
    async fn plan_compiles_and_runs() -> anyhow::Result<()> {
        let nx = Xolotl::with_standard(
            xolotl_state::InMemoryBackend::new().into_backend(),
            &StandardConfig::default(),
        )?;
        let plan = Plan {
            id: "p".into(),
            version: 1,
            description: None,
            steps: vec![Step::Perform {
                target: "effect://time/now".into(),
                input: Some(serde_json::Value::Null),
            }],
        };
        let out = nx
            .run_plan(IdentityRef::ROOT, &["effect://time/now"], &plan)
            .await?
            .output;
        ensure!(
            matches!(out.outcome, Outcome::Done(_)),
            "unexpected outcome: {out:?}"
        );
        Ok(())
    }

    #[cfg(all(feature = "standard", feature = "plan"))]
    #[tokio::test]
    async fn run_plan_resource_allowlist_supports_state_write() -> anyhow::Result<()> {
        let nx = Xolotl::with_standard(
            xolotl_state::InMemoryBackend::new().into_backend(),
            &StandardConfig::default(),
        )?;
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
        let out = nx
            .run_plan(IdentityRef::ROOT, &["state://app/sdk-write"], &plan)
            .await?
            .output;
        ensure!(
            matches!(out.outcome, Outcome::Done(_)),
            "unexpected state write outcome: {out:?}"
        );
        let stored = nx.bootstrap().kernel().state().read(&target).await?;
        ensure!(
            stored == Some(Value::string("stored".into())),
            "state write did not persist: {stored:?}"
        );
        Ok(())
    }
}
