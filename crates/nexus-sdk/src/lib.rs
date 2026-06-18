#![forbid(unsafe_code)]

//! `nexus-sdk` — embedded façade.
//!
//! Re-exports the embedded kernel surface and provides [`NexusBuilder`] plus a
//! small [`Nexus`] wrapper for applications embedding the kernel in-process.

pub use nexus_graph::{
    DoNode, ExecutionGraph, GraphCursor, NodeKind, OperationTemplate, StepRef, compile_do,
};
pub use nexus_kernel::{
    Bootstrap, DataPlane, Driver, DriverContext, DriverError, DriverPlan, Executor, FactSink,
    FactStore, Handle, HandleTable, Kernel, OpenError, Registry,
};
pub use nexus_plan::{Plan, PlanError, Step, WriteModeSpec, compile_for, parse_json, parse_yaml};
#[cfg(feature = "standard")]
pub use nexus_standard::{InstallError, StandardConfig, install_standard};
pub use nexus_state::{
    Backend, InMemoryBackend, StateBackend, StateError, StateEvent, StateResult, merge_values,
};
pub use nexus_types::{
    BlobRef, BudgetSpec, CapSet, Capability, ConstraintSet, Expiry, Fact, Failure, Grant,
    MergeRule, Operation, OperationId, Outcome, Path, PathError, Purity, ReplayClass, Resource,
    ResourceName, Rights, Value, ValueError,
};

use std::error::Error;
use std::fmt;
use std::sync::Arc;

/// Build a minimal in-memory [`Bootstrap`].
pub fn nexus() -> Bootstrap {
    NexusBuilder::new().build_bootstrap()
}

#[cfg(feature = "standard")]
/// Build an in-memory [`Bootstrap`] and install the standard in-process package.
pub fn nexus_with_standard(config: &StandardConfig) -> Result<Bootstrap, InstallError> {
    NexusBuilder::new().build_bootstrap_with_standard(config)
}

/// Errors returned by embedded program execution helpers.
#[derive(Debug)]
pub enum NexusError {
    /// A resource path supplied to [`Nexus::run`] was malformed.
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
    /// Plan compilation failed before execution.
    Plan {
        /// Plan compiler failure.
        source: PlanError,
    },
}

impl fmt::Display for NexusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Path { resource, source } => {
                write!(f, "invalid resource path {resource:?}: {source}")
            }
            Self::Open { resource, source } => {
                write!(f, "open resource {resource:?} failed: {source}")
            }
            Self::Plan { source } => write!(f, "plan compile failed: {source}"),
        }
    }
}

impl Error for NexusError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Path { source, .. } => Some(source),
            Self::Open { source, .. } => Some(source),
            Self::Plan { source } => Some(source),
        }
    }
}

/// Builder for an embedded runtime host.
#[derive(Default)]
pub struct NexusBuilder {
    state: Option<Backend>,
    facts: Option<FactSink>,
}

impl NexusBuilder {
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
    pub fn build(self) -> Nexus {
        Nexus::from_bootstrap(self.build_bootstrap())
    }

    #[cfg(feature = "standard")]
    /// Build an embedded runtime wrapper with the standard package installed.
    pub fn build_with_standard(self, config: &StandardConfig) -> Result<Nexus, InstallError> {
        Ok(Nexus::from_bootstrap(
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

/// A convenience handle that runs programs against an embedded kernel. Opens
/// resources lazily and binds their handles on a shared executor.
pub struct Nexus {
    boot: Arc<Bootstrap>,
}

impl Nexus {
    /// Build a minimal in-memory runtime.
    pub fn new() -> Self {
        NexusBuilder::new().build()
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
        NexusBuilder::new().build_with_standard(config)
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

    /// Run a program that performs operations on `resources` (opened with the
    /// `perform` verb for the root process).
    pub async fn run(&self, resources: &[&str], program: DoNode) -> Result<Outcome, NexusError> {
        let ex = self.boot.kernel.executor_for(self.boot.root);
        for r in resources {
            let name = ResourceName::new(match Path::parse(r) {
                Ok(p) => p,
                Err(e) => {
                    return Err(NexusError::Path {
                        resource: (*r).to_string(),
                        source: e,
                    });
                }
            });
            let handle = self
                .boot
                .open_for(self.boot.root, &name, "perform")
                .map_err(|source| NexusError::Open {
                    resource: (*r).to_string(),
                    source,
                })?;
            ex.bind_handle(name, handle);
        }
        Ok(ex.eval(&program).await)
    }

    /// Compile and run a Plan against the named `resources`.
    pub async fn run_plan(&self, resources: &[&str], plan: &Plan) -> Result<Outcome, NexusError> {
        let program =
            compile_for(self.boot.root, plan).map_err(|source| NexusError::Plan { source })?;
        self.run(resources, program).await
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
        let nx = Nexus::new();
        let prog = DoNode::Op(OperationTemplate {
            target: ResourceName::new(p("effect://time/now")?),
            method: "invoke".into(),
            method_id: None,
            output: nexus_types::OutputMode::Unary,
            literal_input: Some(Value::Null),
        });
        let err = nx.run(&["effect://time/now"], prog).await;
        ensure!(
            matches!(err, Err(NexusError::Open { .. })),
            "unexpected result: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn builder_uses_supplied_state_backend() -> anyhow::Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let path = p("state://app/value")?;
        state.write_set(&path, Value::Int(7)).await?;
        let nx = NexusBuilder::new().with_state_backend(state).build();
        let stored = nx.bootstrap().kernel.state.read(&path).await?;
        ensure!(
            stored == Some(Value::Int(7)),
            "builder did not preserve supplied state backend: {stored:?}"
        );
        Ok(())
    }

    #[cfg(feature = "standard")]
    #[tokio::test]
    async fn standard_constructor_installs_standard_providers() -> anyhow::Result<()> {
        let nx = Nexus::with_standard(&StandardConfig::default())?;
        let prog = DoNode::Op(OperationTemplate {
            target: ResourceName::new(p("effect://time/now")?),
            method: "invoke".into(),
            method_id: None,
            output: nexus_types::OutputMode::Unary,
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
    async fn plan_compiles_and_runs() -> anyhow::Result<()> {
        let nx = Nexus::with_standard(&StandardConfig::default())?;
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
}
