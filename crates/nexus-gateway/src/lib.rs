//! `nexus-gateway` — the Gateway abstraction (§18.1).
//!
//! A Gateway is a `Source` (InProcess·Full): it adapts an external protocol to
//! the kernel in five steps (§18.1): validate auth → map to an identity →
//! create a request Process → translate inbound frames to Operations → translate
//! outcomes back. It introduces **no new primitive** — it is an ordinary
//! Process issuing capability-bound Operations.
//!
//! This crate defines the shared [`Gateway`] trait and an [`InProcessGateway`]
//! that runs a submitted program through the kernel. Protocol crates
//! (`nexus-gateway-grpc/-websocket/-mcp`) wrap network transports around it.

use async_trait::async_trait;
use nexus_graph::DoNode;
use nexus_kernel::{Bootstrap, Executor, intern_identity};
use nexus_types::{Outcome, Path, ProcessId, ResourceName, TaintSet, TaintSource, Value};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("authentication failed")]
    Unauthenticated,
    #[error("identity {0} is not authorized for this gateway")]
    Unauthorized(String),
    #[error("request rejected: {0}")]
    Rejected(String),
}

/// The identity a request runs as, resolved from gateway auth (§18.1 step 2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestIdentity {
    /// The mapped identity path, e.g. `process://alice`.
    pub identity: String,
}

/// Credentials presented by an inbound connection (protocol-specific; the
/// gateway validates them). Treated as untrusted until validated.
#[derive(Clone, Debug)]
pub struct AuthToken(pub String);

/// The shared gateway contract (§18.1). Implementors validate auth, map to an
/// identity, and run a request, returning the outcome.
#[async_trait]
pub trait Gateway: Send + Sync {
    /// Step 1-2: validate `token` and map it to a request identity.
    async fn authenticate(&self, token: &AuthToken) -> Result<RequestIdentity, GatewayError>;

    /// Step 3-5: run `program` as `identity`, returning the outcome.
    async fn submit(
        &self,
        identity: &RequestIdentity,
        program: DoNode,
    ) -> Result<Outcome, GatewayError>;
}

/// An in-process gateway over a [`Bootstrap`]. Each request runs as an
/// **attenuated child Process** spawned per identity (§18.1 step 3), holding
/// only the gateway's `declared_capabilities` as its capability ceiling
/// (§21.5(2)).
/// Externally-submitted programs run with `Inbound` taint so any protected data
/// they touch cannot flow back out (§21.5).
pub struct InProcessGateway {
    boot: Arc<Bootstrap>,
    /// Allowed identities (auth allowlist). Empty = allow any authenticated.
    allowed: Vec<String>,
    /// Resources exposed to requests. Handles are opened per request Process
    /// after attenuation, so a child never uses a root-owned Handle (§5/§18.1).
    handles: Vec<(ResourceName, String)>,
    /// The task-level capability ceiling: capability literals a request Process
    /// may reach (§21.5(2)). Empty = the request gets no grants.
    declared_capabilities: Vec<String>,
    /// Source label for the `Inbound` taint stamped on submitted programs.
    source_label: String,
}

impl InProcessGateway {
    pub fn new(boot: Arc<Bootstrap>) -> Self {
        Self {
            boot,
            allowed: vec![],
            handles: vec![],
            declared_capabilities: vec![],
            source_label: "gateway".into(),
        }
    }

    /// Restrict to a set of identity paths.
    pub fn with_allowed(mut self, allowed: Vec<String>) -> Self {
        self.allowed = allowed;
        self
    }

    /// Declare the capabilities a request may reach — the per-task capability
    /// ceiling (§21.5(2)). Without this, request Processes get no grants.
    pub fn with_declared_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.declared_capabilities = capabilities;
        self
    }

    /// Label used for the `Inbound` taint source (e.g. the platform name).
    pub fn with_source_label(mut self, label: impl Into<String>) -> Self {
        self.source_label = label.into();
        self
    }

    /// Expose a resource for requests. The actual Handle is opened for each
    /// attenuated request Process, preserving Handle ownership (§5.3).
    pub fn open(&mut self, name: ResourceName, verb: &str) -> Result<(), GatewayError> {
        self.boot
            .kernel
            .registry
            .resolve_resource(&name)
            .map_err(|e| GatewayError::Rejected(e.to_string()))?;
        self.handles.push((name, verb.to_string()));
        Ok(())
    }

    /// Spawn the attenuated request Process for `identity` (§18.1 step 3).
    fn spawn_request_process(&self, identity: &RequestIdentity) -> ProcessId {
        let id_ref = Path::parse(&identity.identity)
            .ok()
            .map(|p| intern_identity(&p))
            .unwrap_or(nexus_types::IdentityRef::ROOT);
        let declared: Vec<&str> = self
            .declared_capabilities
            .iter()
            .map(|s| s.as_str())
            .collect();
        self.boot.spawn_request_process(id_ref, &declared)
    }

    fn executor_for(&self, identity: &RequestIdentity) -> Result<Executor, GatewayError> {
        let proc = self.spawn_request_process(identity);
        let ex = self.boot.kernel.executor_for(proc);
        for (name, verb) in &self.handles {
            let handle = self
                .boot
                .open_for(proc, name, verb)
                .map_err(|e| GatewayError::Rejected(e.to_string()))?;
            ex.bind_handle(name.clone(), handle);
        }
        Ok(ex)
    }
}

#[async_trait]
impl Gateway for InProcessGateway {
    async fn authenticate(&self, token: &AuthToken) -> Result<RequestIdentity, GatewayError> {
        if token.0.is_empty() {
            return Err(GatewayError::Unauthenticated);
        }
        // Map the token to an identity (here: the token *is* the identity path;
        // a real gateway looks it up in a credential store).
        let identity = token.0.clone();
        if !self.allowed.is_empty() && !self.allowed.contains(&identity) {
            return Err(GatewayError::Unauthorized(identity));
        }
        Ok(RequestIdentity { identity })
    }

    async fn submit(
        &self,
        identity: &RequestIdentity,
        program: DoNode,
    ) -> Result<Outcome, GatewayError> {
        let ex = self.executor_for(identity)?;
        // Externally-submitted programs carry Inbound taint: anything they read
        // from a protected source cannot flow back out (§21.5). The gateway is
        // the source boundary; `submit` is its event stream (§16.3.3).
        let entry_taint = TaintSet::of(TaintSource::Inbound {
            source_projection_key: self.source_label.as_str().into(),
            event_stream: "submit".into(),
        });
        Ok(ex.eval_tainted(&program, entry_taint).await)
    }
}

/// Helper: a trivial program returning a fixed value (health checks).
pub fn pure_program(v: Value) -> DoNode {
    DoNode::pure(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_token_is_unauthenticated() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = InProcessGateway::new(boot);
        assert!(matches!(
            gw.authenticate(&AuthToken("".into())).await,
            Err(GatewayError::Unauthenticated)
        ));
    }

    #[tokio::test]
    async fn allowlist_rejects_unknown_identity() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = InProcessGateway::new(boot).with_allowed(vec!["process://alice".into()]);
        assert!(matches!(
            gw.authenticate(&AuthToken("process://mallory".into()))
                .await,
            Err(GatewayError::Unauthorized(_))
        ));
        assert!(
            gw.authenticate(&AuthToken("process://alice".into()))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn submit_runs_program() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = InProcessGateway::new(boot);
        let id = gw
            .authenticate(&AuthToken("process://alice".into()))
            .await
            .unwrap();
        let out = gw.submit(&id, DoNode::pure(Value::Int(7))).await.unwrap();
        assert_eq!(out, Outcome::Done(Value::Int(7)));
    }

    #[tokio::test]
    async fn request_runs_as_attenuated_child_not_root() {
        // Each request spawns its own Process under root; two requests get
        // distinct Process ids, and neither is the root (§18.1 step 3).
        let boot = Arc::new(Bootstrap::in_memory());
        let root = boot.root;
        let gw = InProcessGateway::new(boot.clone());
        let id = gw
            .authenticate(&AuthToken("process://alice".into()))
            .await
            .unwrap();
        let p1 = gw.spawn_request_process(&id);
        let p2 = gw.spawn_request_process(&id);
        assert_ne!(p1, root);
        assert_ne!(p2, root);
        assert_ne!(p1, p2, "each request gets its own attenuated Process");
    }

    #[tokio::test]
    async fn submitted_operation_uses_child_owned_handle() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot.register_effect(
            "effect://echo/say",
            &[nexus_kernel::MethodSpec::new(
                "invoke",
                nexus_types::Purity::Pure,
                nexus_kernel::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(nexus_kernel::EchoDriver),
        );
        let mut gw = InProcessGateway::new(boot)
            .with_declared_capabilities(vec!["perform://effect/echo/say".into()]);
        gw.open(name.clone(), "perform").unwrap();

        let id = gw
            .authenticate(&AuthToken("process://alice".into()))
            .await
            .unwrap();
        let program = DoNode::op(nexus_graph::OperationTemplate {
            target: name,
            method: "invoke".into(),
            method_id: None,
            output: nexus_types::OutputMode::Unary,
            literal_input: Some(Value::Str("via-gateway".into())),
        });
        let out = gw.submit(&id, program).await.unwrap();
        assert_eq!(out, Outcome::Done(Value::Str("via-gateway".into())));
    }
}
