#![forbid(unsafe_code)]

//! `nexus-gateway-mcp` — MCP server-side Gateway adapter (§18.2).
//!
//! This crate covers **Nexus as MCP server**: selected Nexus effects are
//! published as MCP tools only when each tool is bound to an explicit capability
//! set. The host-side projection (**Nexus as MCP host**, MCP server as sandboxed
//! Provider under `effect://mcp-tool/<server>/<tool>`) lives in
//! `nexus-actors`, because that side is an in-process Driver.
//!
//! The adapter is transport-neutral: stdio/SSE framing can wrap
//! [`McpGateway::call_tool`]. The actual execution still goes through the shared
//! [`nexus_gateway::Gateway`] path, so auth, request Process creation, taint,
//! policy, budget, Fact recording, and Handle ownership are the same as every
//! other Gateway (§18.1).

use nexus_gateway::{AuthToken, Gateway, GatewayError};
use nexus_graph::{DoNode, OperationTemplate};
use nexus_types::{CapError, Capability, Outcome, OutputMode, Path, ResourceName, Value};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum McpGatewayError {
    #[error("tool name is empty or contains '/'")]
    BadToolName,
    #[error("bad effect path: {0}")]
    BadEffectPath(#[from] nexus_types::PathError),
    #[error("bad capability: {0}")]
    BadCapability(#[from] CapError),
    #[error("capability {capability} does not cover perform on {effect_path}")]
    CapabilityDoesNotCover {
        capability: String,
        effect_path: String,
    },
    #[error("unknown MCP tool {0}")]
    UnknownTool(String),
    #[error("gateway rejected MCP request: {0}")]
    Gateway(#[from] GatewayError),
}

/// A Nexus effect published as an MCP tool (§18.2).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpToolSpec {
    pub name: String,
    pub target: ResourceName,
    /// Method to invoke on `target`; usually `invoke`, but kept explicit because
    /// Nexus Interface methods are named.
    pub method: String,
    /// Capability literal required before this effect may be exposed as an MCP
    /// tool. This is a publishing guard; per-call authorization still happens
    /// through Gateway-created request Processes and kernel policy.
    pub required_capability: String,
    pub input_schema: Option<Value>,
    pub output_schema: Option<Value>,
}

impl McpToolSpec {
    pub fn new(
        name: impl Into<String>,
        effect_path: &str,
        method: impl Into<String>,
        required_capability: &str,
    ) -> Result<Self, McpGatewayError> {
        let name = name.into();
        validate_tool_name(&name)?;
        let path = Path::parse(effect_path)?;
        let capability = Capability::parse(required_capability)?;
        if !capability.covers("perform", &path) {
            return Err(McpGatewayError::CapabilityDoesNotCover {
                capability: required_capability.into(),
                effect_path: effect_path.into(),
            });
        }
        Ok(Self {
            name,
            target: ResourceName::new(path),
            method: method.into(),
            required_capability: required_capability.into(),
            input_schema: None,
            output_schema: None,
        })
    }

    pub fn with_schema(mut self, input: Option<Value>, output: Option<Value>) -> Self {
        self.input_schema = input;
        self.output_schema = output;
        self
    }
}

/// Minimal descriptor shape a transport layer can render into MCP `tools/list`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpToolDescriptor {
    pub name: String,
    pub effect_path: String,
    pub required_capability: String,
    pub input_schema: Option<Value>,
    pub output_schema: Option<Value>,
}

/// Transport-neutral MCP server adapter over a shared Nexus Gateway.
pub struct McpGateway<G: Gateway> {
    gateway: Arc<G>,
    tools: BTreeMap<String, McpToolSpec>,
}

impl<G: Gateway> McpGateway<G> {
    pub fn new(gateway: Arc<G>) -> Self {
        Self {
            gateway,
            tools: BTreeMap::new(),
        }
    }

    pub fn register_tool(&mut self, spec: McpToolSpec) -> Result<(), McpGatewayError> {
        validate_tool_name(&spec.name)?;
        let capability = Capability::parse(&spec.required_capability)?;
        if !capability.covers("perform", spec.target.path()) {
            return Err(McpGatewayError::CapabilityDoesNotCover {
                capability: spec.required_capability.clone(),
                effect_path: spec.target.path().to_string(),
            });
        }
        self.tools.insert(spec.name.clone(), spec);
        Ok(())
    }

    pub fn descriptors(&self) -> Vec<McpToolDescriptor> {
        self.tools
            .values()
            .map(|t| McpToolDescriptor {
                name: t.name.clone(),
                effect_path: t.target.path().to_string(),
                required_capability: t.required_capability.clone(),
                input_schema: t.input_schema.clone(),
                output_schema: t.output_schema.clone(),
            })
            .collect()
    }

    /// Translate one MCP `tools/call` into an ordinary Gateway submission.
    pub async fn call_tool(
        &self,
        auth_token: impl Into<String>,
        tool: &str,
        args: Value,
    ) -> Result<Outcome, McpGatewayError> {
        let spec = self
            .tools
            .get(tool)
            .ok_or_else(|| McpGatewayError::UnknownTool(tool.into()))?;
        let identity = self
            .gateway
            .authenticate(&AuthToken(auth_token.into()))
            .await?;
        let program = DoNode::op(OperationTemplate {
            target: spec.target.clone(),
            method: spec.method.clone(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(args),
        });
        Ok(self.gateway.submit(&identity, program).await?)
    }
}

fn validate_tool_name(name: &str) -> Result<(), McpGatewayError> {
    if name.is_empty() || name.contains('/') {
        return Err(McpGatewayError::BadToolName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_gateway::InProcessGateway;
    use nexus_kernel::{Bootstrap, EchoDriver};

    #[test]
    fn registration_requires_capability_covering_effect() {
        let ok = McpToolSpec::new(
            "search",
            "effect://search/run",
            "invoke",
            "perform://effect/search/run",
        );
        assert!(ok.is_ok());
        let bad = McpToolSpec::new(
            "search",
            "effect://search/run",
            "invoke",
            "perform://effect/other",
        );
        assert!(matches!(
            bad,
            Err(McpGatewayError::CapabilityDoesNotCover { .. })
        ));
    }

    #[tokio::test]
    async fn tool_call_runs_through_gateway() {
        let boot = Arc::new(Bootstrap::in_memory());
        let target = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(EchoDriver),
            )
            .unwrap();
        let mut inner = InProcessGateway::new(boot)
            .with_declared_capabilities(vec!["perform://effect/echo/say".into()]);
        inner.open(target, "perform").unwrap();

        let mut mcp = McpGateway::new(Arc::new(inner));
        mcp.register_tool(
            McpToolSpec::new(
                "echo",
                "effect://echo/say",
                "invoke",
                "perform://effect/echo/say",
            )
            .unwrap(),
        )
        .unwrap();

        let out = mcp
            .call_tool("process://alice", "echo", Value::Str("from-mcp".into()))
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Str("from-mcp".into())));
    }
}
