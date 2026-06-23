#![forbid(unsafe_code)]

//! `xolotl-sdk` — embedded façade.
//!
//! Re-exports the embedded kernel surface and provides [`XolotlBuilder`] plus a
//! small [`Xolotl`] wrapper for applications embedding the kernel in-process.

pub use xolotl_graph::{
    ActorSpec, CapabilityQueryError, DoNode, ExecutionGraph, GraphCursor, NodeKind,
    OperationTemplate, StepRef, compile_do, lint_actor,
};
pub use xolotl_kernel::{
    Bootstrap, BootstrapError, DataPlane, Driver, DriverContext, DriverError, DriverPlan, Executor,
    FactSink, FactStore, Handle, HandleTable, Kernel, OpenError, ProcessStepBinding, Registry,
    SpawnedActor, StepFn, StepInstallError,
};
pub use xolotl_plan::{Plan, PlanError, Step, WriteModeSpec, compile_for, parse_json, parse_yaml};
#[cfg(feature = "standard")]
pub use xolotl_standard::{
    EchoBackend, InferenceBackend, InferenceMethodSupport, InstallError, ModelCapabilities,
    StandardConfig, StandardModule, StandardModules, install_standard,
};
pub use xolotl_state::{
    Backend, InMemoryBackend, StateBackend, StateError, StateEvent, StateResult, merge_values,
};
pub use xolotl_types::{
    BlobRef, BudgetSpec, CapSet, Capability, ConstraintSet, Expiry, Fact, Failure, Grant,
    IdentityRef, MergeRule, Operation, OperationId, Outcome, Path, PathError, Purity, ReplayClass,
    Resource, ResourceName, Rights, Value, ValueError,
};

use std::error::Error;
use std::fmt;
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
    /// Request process setup failed.
    Bootstrap {
        /// Bootstrap failure.
        source: BootstrapError,
    },
    /// Plan compilation failed before execution.
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
            Self::Bootstrap { source } => write!(f, "request process setup failed: {source}"),
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
            Self::Plan { source } => Some(source),
        }
    }
}

/// Builder for an embedded runtime host.
#[derive(Default)]
pub struct XolotlBuilder {
    state: Option<Backend>,
    facts: Option<FactSink>,
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
            .unwrap_or_else(|| Arc::new(InMemoryBackend::new()));
        let facts = self.facts.unwrap_or_else(|| FactSink::in_memory().0);
        Kernel::with_backends(state, facts)
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

    /// Run a program in a request process limited to `resources`.
    pub async fn run(&self, resources: &[&str], program: DoNode) -> Result<Outcome, XolotlError> {
        let grants = self.request_grants(resources)?;
        let process = self
            .boot
            .spawn_request_process_under_with_compiled_request_grants(
                self.boot.root,
                IdentityRef::ROOT,
                &grants,
            )
            .map_err(|source| XolotlError::Bootstrap { source })?;
        let outcome = self.boot.kernel.executor_for(process).eval(&program).await;
        self.boot
            .finish_request_process(process, &outcome)
            .await
            .map_err(|source| XolotlError::Bootstrap { source })?;
        Ok(outcome)
    }

    /// Compile and run a Plan against the named `resources`.
    pub async fn run_plan(&self, resources: &[&str], plan: &Plan) -> Result<Outcome, XolotlError> {
        let grants = self.request_grants(resources)?;
        let program =
            compile_for(self.boot.root, plan).map_err(|source| XolotlError::Plan { source })?;
        let process = self
            .boot
            .spawn_request_process_under_with_compiled_request_grants(
                self.boot.root,
                IdentityRef::ROOT,
                &grants,
            )
            .map_err(|source| XolotlError::Bootstrap { source })?;
        let program =
            program
                .bind_process_local_refs(process)
                .map_err(|source| XolotlError::Resource {
                    resource: "process-local refs".into(),
                    reason: source.to_string(),
                })?;
        let outcome = self.boot.kernel.executor_for(process).eval(&program).await;
        self.boot
            .finish_request_process(process, &outcome)
            .await
            .map_err(|source| XolotlError::Bootstrap { source })?;
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

    /// Spawn an Actor with process-local steps installed before its body runs.
    pub async fn spawn_actor_with_steps<I>(
        &self,
        identity: IdentityRef,
        identity_segment: &str,
        spec: &ActorSpec,
        steps: I,
    ) -> Result<SpawnedActor, BootstrapError>
    where
        I: IntoIterator<Item = ProcessStepBinding>,
    {
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
    use anyhow::{anyhow, ensure};
    use std::sync::Arc;

    fn p(path: &str) -> anyhow::Result<Path> {
        Path::parse(path).map_err(|error| anyhow!("path parse failed for {path}: {error}"))
    }

    #[tokio::test]
    async fn minimal_constructor_does_not_install_standard_providers() -> anyhow::Result<()> {
        let nx = Xolotl::new();
        let prog = DoNode::Op(OperationTemplate {
            target: ResourceName::new(p("effect://time/now")?),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(Value::Null),
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
        let state: Backend = Arc::new(InMemoryBackend::new());
        let path = p("state://app/value")?;
        state.write_set(&path, Value::Int(7)).await?;
        let nx = XolotlBuilder::new().with_state_backend(state).build();
        let stored = nx.bootstrap().kernel.state.read(&path).await?;
        ensure!(
            stored == Some(Value::Int(7)),
            "builder did not preserve supplied state backend: {stored:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn xolotl_spawn_actor_runs_under_root() -> anyhow::Result<()> {
        let nx = Xolotl::new();
        let spec = ActorSpec {
            name: "worker".into(),
            body: DoNode::pure(Value::Str("done".into())),
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
            body: DoNode::pure(Value::Int(1)).and_then(StepRef::new(nx.boot.root, "finish")),
            ..ActorSpec::default()
        };
        let actor = nx
            .spawn_actor_with_steps(
                IdentityRef::ROOT,
                "root",
                &spec,
                [ProcessStepBinding::new(
                    "finish",
                    Arc::new(|v, _| DoNode::pure(v)),
                )],
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
            literal_input: Some(Value::Null),
        });
        let out = nx.run(&["effect://time/now"], prog).await?;
        ensure!(
            matches!(out, Outcome::Done(_)),
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
            literal_input: Some(Value::Null),
        });
        let out = nx.run(&["effect://approval/check"], prog).await?;
        ensure!(
            matches!(out, Outcome::Fail(Failure::PolicyViolation { .. })),
            "unlisted resource was opened by request process: {out:?}"
        );
        Ok(())
    }

    #[cfg(feature = "standard")]
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
            matches!(out, Outcome::Done(_)),
            "unexpected outcome: {out:?}"
        );
        Ok(())
    }

    #[cfg(feature = "standard")]
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
            matches!(out, Outcome::Done(_)),
            "unexpected state write outcome: {out:?}"
        );
        let stored = nx.bootstrap().kernel.state.read(&target).await?;
        ensure!(
            stored == Some(Value::Str("stored".into())),
            "state write did not persist: {stored:?}"
        );
        Ok(())
    }
}
