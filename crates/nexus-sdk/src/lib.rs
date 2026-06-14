#![forbid(unsafe_code)]

//! `nexus-sdk` — embedded façade.
//!
//! Re-exports the public surface and provides a one-call [`nexus`] constructor
//! for applications embedding the kernel in-process, plus [`Nexus`] — a thin
//! wrapper that opens a resource, binds it, and runs a program.

pub use nexus_actors::{InstallError, StandardConfig, install_standard};
pub use nexus_gateway::{
    BearerToken, BearerTokenHash, CommitObjectUploadRequest, CommitObjectUploadResponse, Gateway,
    GatewayAuthMethod, GatewayCredential, GatewayCredentialKind, GatewayDescriptor,
    GatewayDirectInput, GatewayError, GatewayIdentityMapping, GatewayLimitProfile, GatewayModality,
    GatewayObjectUploadTicket, GatewayPayloadProvenance, GatewayPrincipalSurfaceBinding,
    GatewayProfile, GatewayProfileRev, GatewayRuntime, GatewaySession, GatewayStreamChunk,
    GatewayStreamDirection, GatewayStreamEnd, GatewayStreamOpenRequest, GatewaySubmission,
    GatewaySubmissionBody, GatewaySurface, GatewaySurfaceDescriptor, GatewaySurfaceKind,
    IssueObjectUploadTicketRequest, ObjectStoreProof, PresentedCredential, ProgramInspection,
    ProgramSubmission, SubmitOptions, VerifiedPrincipal,
};
pub use nexus_graph::{
    DoNode, ExecutionGraph, GraphCursor, NodeKind, OperationTemplate, StepRef, compile_do,
};
pub use nexus_kernel::{
    Bootstrap, DataPlane, Driver, DriverContext, DriverError, DriverPlan, Executor, FactSink,
    FactStore, Handle, HandleTable, Kernel, OpenError, Registry,
};
pub use nexus_plan::{Plan, PlanError, Step, WriteModeSpec, compile_for, parse_json, parse_yaml};
pub use nexus_state::{
    Backend, InMemoryBackend, StateBackend, StateError, StateEvent, StateResult, merge_values,
};
pub use nexus_types::{
    BlobRef, BudgetSpec, CapSet, Capability, ConstraintSet, Expiry, Fact, Failure, Grant,
    MergeRule, Operation, OperationId, Outcome, Path, PathError, Purity, ReplayClass, Resource,
    ResourceName, Rights, Value, ValueError,
};

use std::sync::Arc;

/// One-call constructor: a [`Bootstrap`] with the standard provider set
/// installed (inference, memory, time, blob, approval, events, lock,
/// deliberation). fs/terminal/fetch are opt-in via [`StandardConfig`].
pub fn nexus() -> Result<Bootstrap, InstallError> {
    let boot = Bootstrap::in_memory();
    install_standard(&boot, &StandardConfig::default())?;
    Ok(boot)
}

/// A convenience handle that runs programs against an embedded kernel. Opens
/// resources lazily and binds their handles on a shared executor.
pub struct Nexus {
    boot: Arc<Bootstrap>,
}

impl Nexus {
    /// Build with the standard provider set installed.
    pub fn new() -> Result<Self, InstallError> {
        Ok(Self {
            boot: Arc::new(nexus()?),
        })
    }

    /// Access the embedded bootstrap and kernel handles.
    pub fn bootstrap(&self) -> &Bootstrap {
        &self.boot
    }

    /// Run a program that performs operations on `resources` (opened with the
    /// `perform` verb for the root process). Returns the outcome.
    pub async fn run(&self, resources: &[&str], program: DoNode) -> Outcome {
        let ex = self.boot.kernel.executor_for(self.boot.root);
        for r in resources {
            let name = ResourceName::new(match Path::parse(r) {
                Ok(p) => p,
                Err(e) => {
                    return Outcome::Fail(Failure::InvalidInput {
                        reason: format!("invalid resource path {r:?}: {e}"),
                    });
                }
            });
            if let Ok(handle) = self.boot.open_for(self.boot.root, &name, "perform") {
                ex.bind_handle(name, handle);
            }
        }
        ex.eval(&program).await
    }

    /// Compile and run a Plan against the named `resources`.
    pub async fn run_plan(&self, resources: &[&str], plan: &Plan) -> Result<Outcome, PlanError> {
        let program = compile_for(self.boot.root, plan)?;
        Ok(self.run(resources, program).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn one_call_constructor_has_standard_providers() {
        let Ok(nx) = Nexus::new() else {
            panic!("Nexus::new should install standard providers");
        };
        let prog = DoNode::Op(OperationTemplate {
            target: ResourceName::new(Path::parse("effect://inference/infer").unwrap()),
            method: "invoke".into(),
            method_id: None,
            output: nexus_types::OutputMode::Unary,
            literal_input: Some(Value::Str("hello".into())),
        });
        let out = nx.run(&["effect://inference/infer"], prog).await;
        assert!(matches!(out, Outcome::Done(_)));
    }

    #[tokio::test]
    async fn plan_compiles_and_runs() {
        let Ok(nx) = Nexus::new() else {
            panic!("Nexus::new should install standard providers");
        };
        let plan = Plan {
            id: "p".into(),
            version: 1,
            description: None,
            steps: vec![Step::Perform {
                target: "effect://inference/infer".into(),
                input: Some(serde_json::json!("greet me")),
            }],
        };
        let out = nx
            .run_plan(&["effect://inference/infer"], &plan)
            .await
            .unwrap();
        assert!(matches!(out, Outcome::Done(_)));
    }
}
