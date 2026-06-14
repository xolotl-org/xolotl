#![forbid(unsafe_code)]

//! `nexus-gateway-mcp` — MCP server-side Gateway adapter.
//!
//! This crate covers **Nexus as MCP server**: selected Nexus effects are
//! published as MCP tools only when each tool is bound to an explicit publishing
//! capability. The host-side projection (**Nexus as MCP host**, MCP server as sandboxed
//! Provider under `effect://external-provider/<server>/<tool>`) lives in
//! `nexus-actors`, because that side is an in-process Driver.
//!
//! The adapter is transport-neutral: stdio/SSE framing can wrap the JSON-RPC
//! handler or the direct Rust methods. The actual execution still goes through the shared
//! [`nexus_gateway::Gateway`] path, so auth, request Process creation, taint,
//! policy, budget, Fact recording, and Handle ownership are the same as every
//! other Gateway.

use nexus_gateway::{
    Gateway, GatewayError, GatewaySession, GatewaySubmission, GatewaySurfaceKind,
    PresentedCredential,
};
use nexus_kernel::GatewayAudit;
use nexus_types::{CapError, Capability, Outcome, Path, ResourceName, Value};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;

const JSONRPC_VERSION: &str = "2.0";
const JSONRPC_PARSE_ERROR: i64 = -32700;
const JSONRPC_INVALID_REQUEST: i64 = -32600;
const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
const JSONRPC_INVALID_PARAMS: i64 = -32602;
const JSONRPC_GATEWAY_ERROR: i64 = -32000;

/// Errors raised while publishing Nexus effects as MCP tools or serving calls.
#[derive(Debug, Error)]
pub enum McpGatewayError {
    /// Tool names must be stable ASCII path segments.
    #[error("tool name must be one ASCII path segment")]
    BadToolName,
    /// The configured effect path was not a valid Nexus path.
    #[error("bad effect path: {0}")]
    BadEffectPath(#[from] nexus_types::PathError),
    /// MCP tools can only publish effect method surfaces.
    #[error("MCP tool target must use effect://")]
    ToolTargetMustBeEffect,
    /// MCP tools require a named Nexus method.
    #[error("MCP tool method must not be empty")]
    BadToolMethod,
    /// The publishing guard capability literal could not be parsed.
    #[error("bad publish capability: {0}")]
    BadCapability(#[from] CapError),
    /// The publishing guard does not cover `publish` on the target effect.
    #[error("publish capability {capability} does not cover publish on {effect_path}")]
    CapabilityDoesNotCover {
        /// Capability literal supplied by the publisher.
        capability: String,
        /// Effect path the tool would expose.
        effect_path: String,
    },
    /// The MCP client requested a tool that has not been registered.
    #[error("unknown MCP tool {0}")]
    UnknownTool(String),
    /// The shared Nexus gateway rejected authentication or execution.
    #[error("gateway rejected MCP request")]
    Gateway(#[from] GatewayError),
}

/// A Nexus effect published as an MCP tool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolSpec {
    /// MCP-visible tool name.
    pub name: String,
    /// Nexus resource invoked by this tool.
    pub target: ResourceName,
    /// Method to invoke on `target`; usually `invoke`, but kept explicit because
    /// Nexus Interface methods are named.
    pub method: String,
    /// Capability literal required before this effect may be published as an
    /// MCP tool.
    pub publish_capability: String,
}

impl McpToolSpec {
    /// Create a tool specification and validate that `publish_capability`
    /// authorizes publishing `effect_path`.
    pub fn new(
        name: impl Into<String>,
        effect_path: &str,
        method: impl Into<String>,
        publish_capability: &str,
    ) -> Result<Self, McpGatewayError> {
        let name = name.into();
        let method = method.into();
        validate_tool_name(&name)?;
        let path = Path::parse(effect_path)?;
        validate_tool_target_and_method(&path, &method)?;
        let capability = Capability::parse(publish_capability)?;
        if !capability.covers("publish", &path) {
            return Err(McpGatewayError::CapabilityDoesNotCover {
                capability: publish_capability.into(),
                effect_path: effect_path.into(),
            });
        }
        Ok(Self {
            name,
            target: ResourceName::new(path),
            method,
            publish_capability: publish_capability.into(),
        })
    }
}

/// Minimal descriptor shape a transport layer can render into MCP `tools/list`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpToolDescriptor {
    /// MCP-visible tool name.
    pub name: String,
    /// Nexus effect path the tool invokes.
    pub effect_path: String,
    /// Capability literal required for publication.
    pub publish_capability: String,
    /// Optional input schema descriptor.
    pub input_schema: Option<Value>,
    /// Optional output schema descriptor.
    pub output_schema: Option<Value>,
}

/// JSON-RPC request accepted by the MCP server adapter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpJsonRpcRequest {
    /// JSON-RPC protocol version. Must be `2.0`.
    pub jsonrpc: String,
    /// Request id echoed in the response.
    #[serde(default)]
    pub id: Option<serde_json::Value>,
    /// MCP method name.
    pub method: String,
    /// Method parameters.
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC response returned by the MCP server adapter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpJsonRpcResponse {
    /// JSON-RPC protocol version.
    pub jsonrpc: &'static str,
    /// Request id, or null when the request could not be parsed.
    pub id: serde_json::Value,
    /// Successful method result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error result.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpJsonRpcError>,
}

/// JSON-RPC error object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpJsonRpcError {
    /// JSON-RPC error code.
    pub code: i64,
    /// Redacted error message.
    pub message: String,
}

/// Transport-neutral MCP server adapter over a shared Nexus Gateway.
pub struct McpGateway<G: Gateway> {
    gateway: Arc<G>,
    tools: BTreeMap<String, McpToolSpec>,
}

impl<G: Gateway> McpGateway<G> {
    /// Create an adapter over an existing authenticated Nexus gateway.
    pub fn new(gateway: Arc<G>) -> Self {
        Self {
            gateway,
            tools: BTreeMap::new(),
        }
    }

    /// Register a tool after validating its name and publishing guard.
    pub fn register_tool(&mut self, spec: McpToolSpec) -> Result<(), McpGatewayError> {
        validate_tool_name(&spec.name)?;
        validate_tool_target_and_method(spec.target.path(), &spec.method)?;
        let capability = Capability::parse(&spec.publish_capability)?;
        if !capability.covers("publish", spec.target.path()) {
            return Err(McpGatewayError::CapabilityDoesNotCover {
                capability: spec.publish_capability.clone(),
                effect_path: spec.target.path().to_string(),
            });
        }
        self.tools.insert(spec.name.clone(), spec);
        Ok(())
    }

    /// Return authenticated tool descriptors suitable for MCP `tools/list`.
    ///
    /// The returned tools are the intersection of locally registered MCP tools
    /// and the active Gateway profile surface catalog for the caller. This
    /// avoids leaking unpublished effects and avoids advertising tools that the
    /// gateway would reject at call time.
    pub async fn descriptors(
        &self,
        bearer_token: impl Into<String>,
    ) -> Result<Vec<McpToolDescriptor>, McpGatewayError> {
        let session = match self
            .gateway
            .authenticate(PresentedCredential::bearer(bearer_token.into()))
            .await
        {
            Ok(session) => session,
            Err(e) => {
                record_mcp_audit(&*self.gateway, None, e.audit_outcome());
                return Err(e.into());
            }
        };
        let descriptor = match self.gateway.describe(&session) {
            Ok(descriptor) => descriptor,
            Err(e) => {
                record_mcp_audit(&*self.gateway, Some(&session), e.audit_outcome());
                return Err(e.into());
            }
        };
        record_mcp_audit(&*self.gateway, Some(&session), "describe_ok");
        Ok(self
            .tools
            .values()
            .filter_map(|tool| {
                descriptor
                    .surfaces
                    .iter()
                    .find(|surface| surface_publish_allows_tool(surface, tool))
                    .map(|surface| McpToolDescriptor {
                        name: tool.name.clone(),
                        effect_path: surface.target.path().to_string(),
                        publish_capability: tool.publish_capability.clone(),
                        input_schema: surface.input_schema.clone(),
                        output_schema: surface.output_schema.clone(),
                    })
            })
            .collect())
    }

    /// Translate one MCP `tools/call` into a standard Gateway submission.
    pub async fn call_tool(
        &self,
        bearer_token: impl Into<String>,
        tool: &str,
        args: Value,
    ) -> Result<Outcome, McpGatewayError> {
        let identity = match self
            .gateway
            .authenticate(PresentedCredential::bearer(bearer_token.into()))
            .await
        {
            Ok(identity) => identity,
            Err(e) => {
                record_mcp_audit(&*self.gateway, None, e.audit_outcome());
                return Err(e.into());
            }
        };
        let Some(spec) = self.tools.get(tool) else {
            record_mcp_audit(&*self.gateway, Some(&identity), "unknown_tool");
            return Err(McpGatewayError::UnknownTool(tool.into()));
        };
        let descriptor = match self.gateway.describe(&identity) {
            Ok(descriptor) => descriptor,
            Err(e) => {
                record_mcp_audit(&*self.gateway, Some(&identity), e.audit_outcome());
                return Err(e.into());
            }
        };
        let Some(surface) = descriptor
            .surfaces
            .iter()
            .find(|surface| surface_publish_allows_tool(surface, spec))
        else {
            record_mcp_audit(&*self.gateway, Some(&identity), "surface_denied");
            return Err(GatewayError::Rejected("tool surface denied".into()).into());
        };
        match self
            .gateway
            .submit(
                &identity,
                GatewaySubmission::direct_input(surface.surface_id.clone(), args),
            )
            .await
        {
            Ok(result) => Ok(result.outcome),
            Err(e) => {
                record_mcp_audit(&*self.gateway, Some(&identity), e.audit_outcome());
                Err(e.into())
            }
        }
    }

    /// Handle one parsed MCP JSON-RPC request.
    pub async fn handle_jsonrpc_value(
        &self,
        bearer_token: impl Into<String>,
        request: serde_json::Value,
    ) -> McpJsonRpcResponse {
        let request = match serde_json::from_value::<McpJsonRpcRequest>(request) {
            Ok(request) => request,
            Err(_) => return jsonrpc_error(serde_json::Value::Null, JSONRPC_INVALID_REQUEST),
        };
        self.handle_jsonrpc_request(bearer_token, request).await
    }

    /// Handle one serialized MCP JSON-RPC request.
    pub async fn handle_jsonrpc_str(
        &self,
        bearer_token: impl Into<String>,
        request: &str,
    ) -> McpJsonRpcResponse {
        let request = match serde_json::from_str::<McpJsonRpcRequest>(request) {
            Ok(request) => request,
            Err(error) if error.is_syntax() || error.is_eof() => {
                return jsonrpc_error(serde_json::Value::Null, JSONRPC_PARSE_ERROR);
            }
            Err(_) => return jsonrpc_error(serde_json::Value::Null, JSONRPC_INVALID_REQUEST),
        };
        self.handle_jsonrpc_request(bearer_token, request).await
    }

    /// Handle one decoded MCP JSON-RPC request.
    pub async fn handle_jsonrpc_request(
        &self,
        bearer_token: impl Into<String>,
        request: McpJsonRpcRequest,
    ) -> McpJsonRpcResponse {
        let id = request.id.clone().unwrap_or(serde_json::Value::Null);
        if request.jsonrpc != JSONRPC_VERSION {
            return jsonrpc_error(id, JSONRPC_INVALID_REQUEST);
        }
        let bearer_token = bearer_token.into();
        match request.method.as_str() {
            "tools/list" => {
                if !jsonrpc_params_absent_or_empty_object(&request.params) {
                    return jsonrpc_error(id, JSONRPC_INVALID_PARAMS);
                }
                match self.descriptors(bearer_token).await {
                    Ok(descriptors) => match mcp_tools_json(descriptors) {
                        Ok(tools) => jsonrpc_ok(id, json!({ "tools": tools })),
                        Err(_) => jsonrpc_error(id, JSONRPC_GATEWAY_ERROR),
                    },
                    Err(_) => jsonrpc_error(id, JSONRPC_GATEWAY_ERROR),
                }
            }
            "tools/call" => match parse_tools_call_params(request.params) {
                Ok((tool, args)) => match self.call_tool(bearer_token, &tool, args).await {
                    Ok(outcome) => match outcome.into_value() {
                        Ok(value) => match mcp_tool_result_json(value) {
                            Ok(result) => jsonrpc_ok(id, result),
                            Err(_) => jsonrpc_error(id, JSONRPC_GATEWAY_ERROR),
                        },
                        Err(_) => jsonrpc_error(id, JSONRPC_GATEWAY_ERROR),
                    },
                    Err(McpGatewayError::UnknownTool(_)) => {
                        jsonrpc_error(id, JSONRPC_INVALID_PARAMS)
                    }
                    Err(_) => jsonrpc_error(id, JSONRPC_GATEWAY_ERROR),
                },
                Err(_) => jsonrpc_error(id, JSONRPC_INVALID_PARAMS),
            },
            _ => jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND),
        }
    }
}

fn jsonrpc_ok(id: serde_json::Value, result: serde_json::Value) -> McpJsonRpcResponse {
    McpJsonRpcResponse {
        jsonrpc: JSONRPC_VERSION,
        id,
        result: Some(result),
        error: None,
    }
}

fn jsonrpc_error(id: serde_json::Value, code: i64) -> McpJsonRpcResponse {
    McpJsonRpcResponse {
        jsonrpc: JSONRPC_VERSION,
        id,
        result: None,
        error: Some(McpJsonRpcError {
            code,
            message: jsonrpc_error_message(code).into(),
        }),
    }
}

fn jsonrpc_error_message(code: i64) -> &'static str {
    match code {
        JSONRPC_PARSE_ERROR => "parse error",
        JSONRPC_INVALID_REQUEST => "invalid request",
        JSONRPC_METHOD_NOT_FOUND => "method not found",
        JSONRPC_INVALID_PARAMS => "invalid params",
        JSONRPC_GATEWAY_ERROR => "gateway request rejected",
        _ => "gateway request rejected",
    }
}

fn jsonrpc_params_absent_or_empty_object(params: &Option<serde_json::Value>) -> bool {
    match params {
        None => true,
        Some(serde_json::Value::Object(map)) => map.is_empty(),
        Some(_) => false,
    }
}

fn mcp_tools_json(
    descriptors: Vec<McpToolDescriptor>,
) -> Result<Vec<serde_json::Value>, serde_json::Error> {
    descriptors
        .into_iter()
        .map(|descriptor| {
            let mut tool = serde_json::Map::new();
            tool.insert("name".into(), serde_json::Value::String(descriptor.name));
            if let Some(schema) = descriptor.input_schema {
                tool.insert("inputSchema".into(), serde_json::to_value(schema)?);
            }
            if let Some(schema) = descriptor.output_schema {
                tool.insert("outputSchema".into(), serde_json::to_value(schema)?);
            }
            Ok(serde_json::Value::Object(tool))
        })
        .collect()
}

fn parse_tools_call_params(params: Option<serde_json::Value>) -> Result<(String, Value), ()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ToolCallParams {
        name: String,
        #[serde(default)]
        arguments: serde_json::Value,
    }

    let params: ToolCallParams = serde_json::from_value(
        params.unwrap_or_else(|| serde_json::Value::Object(Default::default())),
    )
    .map_err(|_| ())?;
    if !is_mcp_tool_segment(&params.name) {
        return Err(());
    }
    let args = serde_json::from_value::<Value>(params.arguments).map_err(|_| ())?;
    Ok((params.name, args))
}

fn mcp_tool_result_json(value: Value) -> Result<serde_json::Value, serde_json::Error> {
    let structured = serde_json::to_value(&value)?;
    Ok(json!({
        "content": [{
            "type": "text",
            "text": mcp_result_text(&value, &structured)
        }],
        "structuredContent": structured,
        "isError": false
    }))
}

fn mcp_result_text(value: &Value, structured: &serde_json::Value) -> String {
    match value {
        Value::Str(text) => text.clone(),
        _ => serde_json::to_string(structured).unwrap_or_else(|_| "null".into()),
    }
}

fn surface_publish_allows_tool(
    surface: &nexus_gateway::GatewaySurfaceDescriptor,
    tool: &McpToolSpec,
) -> bool {
    if surface.kind != GatewaySurfaceKind::EffectMethod {
        return false;
    }
    if surface.target != tool.target || surface.method != tool.method {
        return false;
    }
    let Some(surface_publish) = &surface.publish_capability else {
        return false;
    };
    let Ok(surface_publish) = Capability::parse(surface_publish) else {
        return false;
    };
    let Ok(tool_publish) = Capability::parse(&tool.publish_capability) else {
        return false;
    };
    surface_publish.covers_cap(&tool_publish)
}

fn record_mcp_audit<G: Gateway>(
    gateway: &G,
    session: Option<&GatewaySession>,
    outcome: &'static str,
) {
    let _ = gateway.record_gateway_audit(GatewayAudit {
        event: "gateway_mcp",
        username: session.map(|s| s.identity_path.as_str()),
        source_addr: None,
        outcome,
        mfa_level: None,
        details: None,
    });
}

fn validate_tool_name(name: &str) -> Result<(), McpGatewayError> {
    if !is_mcp_tool_segment(name) {
        return Err(McpGatewayError::BadToolName);
    }
    Ok(())
}

fn validate_tool_target_and_method(path: &Path, method: &str) -> Result<(), McpGatewayError> {
    if path.scheme() != "effect" {
        return Err(McpGatewayError::ToolTargetMustBeEffect);
    }
    if method.trim().is_empty() {
        return Err(McpGatewayError::BadToolMethod);
    }
    Ok(())
}

fn is_mcp_tool_segment(name: &str) -> bool {
    if name == "*" || name == "**" {
        return false;
    }
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' || c == ':')
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_gateway::{
        GatewayPrincipalSurfaceBinding, GatewayProfile, GatewayRuntime, GatewaySurface,
    };
    use nexus_kernel::{Bootstrap, EchoDriver};
    use nexus_types::OutcomeRef;

    const TEST_TOKEN: &str = "mcp-token-for-alice-0001";

    fn schema_type(kind: &str) -> Value {
        Value::Map(BTreeMap::from([("type".into(), Value::from(kind))]))
    }

    fn audit_outcomes(boot: &Bootstrap, event: &str) -> Vec<String> {
        boot.kernel
            .facts
            .all_facts()
            .unwrap()
            .into_iter()
            .filter_map(|fact| match fact.outcome_ref {
                OutcomeRef::Inline(Value::Map(m))
                    if m.get("event").and_then(Value::as_str) == Some(event) =>
                {
                    m.get("outcome").and_then(Value::as_str).map(str::to_string)
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn registration_requires_publish_capability_covering_effect() {
        let ok = McpToolSpec::new(
            "search",
            "effect://search/run",
            "invoke",
            "publish://effect/search/run",
        );
        assert!(ok.is_ok());
        let bad = McpToolSpec::new(
            "search",
            "effect://search/run",
            "invoke",
            "publish://effect/other",
        );
        assert!(matches!(
            bad,
            Err(McpGatewayError::CapabilityDoesNotCover { .. })
        ));
    }

    #[test]
    fn registration_requires_effect_target_and_named_method() {
        assert!(matches!(
            McpToolSpec::new(
                "events",
                "state://events/gateway",
                "append",
                "publish://state/events/gateway"
            ),
            Err(McpGatewayError::ToolTargetMustBeEffect)
        ));
        assert!(matches!(
            McpToolSpec::new(
                "search",
                "effect://search/run",
                " ",
                "publish://effect/search/run"
            ),
            Err(McpGatewayError::BadToolMethod)
        ));

        let mut mcp = McpGateway::new(Arc::new(
            GatewayRuntime::new(
                Arc::new(Bootstrap::in_memory()),
                GatewayProfile::new("program-mcp"),
            )
            .unwrap(),
        ));
        let bypassed = McpToolSpec {
            name: "events".into(),
            target: ResourceName::new(Path::parse("state://events/gateway").unwrap()),
            method: "append".into(),
            publish_capability: "publish://state/events/gateway".into(),
        };
        assert!(matches!(
            mcp.register_tool(bypassed),
            Err(McpGatewayError::ToolTargetMustBeEffect)
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
        let profile = GatewayProfile::new("program-mcp")
            .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")
            .unwrap()
            .with_surface(
                GatewaySurface::operation(
                    "echo",
                    target,
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_publish_capability("publish://effect/echo/say"),
            )
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["echo"],
                ["perform://effect/echo/say"],
            ));
        let inner = GatewayRuntime::new(boot, profile).unwrap();

        let mut mcp = McpGateway::new(Arc::new(inner));
        mcp.register_tool(
            McpToolSpec::new(
                "echo",
                "effect://echo/say",
                "invoke",
                "publish://effect/echo/say",
            )
            .unwrap(),
        )
        .unwrap();

        let out = mcp
            .call_tool(TEST_TOKEN, "echo", Value::Str("from-mcp".into()))
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Str("from-mcp".into())));
    }

    #[tokio::test]
    async fn descriptors_are_authenticated_and_profile_filtered() {
        let boot = Arc::new(Bootstrap::in_memory());
        let echo = boot
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
        boot.register_effect(
            "effect://hidden/run",
            &[nexus_kernel::MethodSpec::new(
                "invoke",
                nexus_types::Purity::Pure,
                nexus_kernel::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )
        .unwrap();
        let profile = GatewayProfile::new("program-mcp")
            .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")
            .unwrap()
            .with_surface(
                GatewaySurface::operation(
                    "echo",
                    echo,
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_publish_capability("publish://effect/echo/say")
                .with_schema(Some(schema_type("string")), Some(schema_type("string"))),
            )
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["echo"],
                ["perform://effect/echo/say"],
            ));
        let inner = GatewayRuntime::new(boot.clone(), profile).unwrap();
        let mut mcp = McpGateway::new(Arc::new(inner));
        mcp.register_tool(
            McpToolSpec::new(
                "echo",
                "effect://echo/say",
                "invoke",
                "publish://effect/echo/say",
            )
            .unwrap(),
        )
        .unwrap();
        mcp.register_tool(
            McpToolSpec::new(
                "hidden",
                "effect://hidden/run",
                "invoke",
                "publish://effect/hidden/run",
            )
            .unwrap(),
        )
        .unwrap();

        let descriptors = mcp.descriptors(TEST_TOKEN).await.unwrap();
        assert_eq!(descriptors.len(), 1);
        assert_eq!(descriptors[0].name, "echo");
        assert_eq!(descriptors[0].input_schema, Some(schema_type("string")));
        assert_eq!(descriptors[0].output_schema, Some(schema_type("string")));
        assert!(audit_outcomes(&boot, "gateway_mcp").contains(&"describe_ok".into()));
        assert!(mcp.descriptors("wrong-token-for-alice-0001").await.is_err());
    }

    #[tokio::test]
    async fn jsonrpc_tools_list_is_authenticated_and_profile_filtered() {
        let boot = Arc::new(Bootstrap::in_memory());
        let echo = boot
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
        boot.register_effect(
            "effect://hidden/run",
            &[nexus_kernel::MethodSpec::new(
                "invoke",
                nexus_types::Purity::Pure,
                nexus_kernel::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )
        .unwrap();
        let profile = GatewayProfile::new("program-mcp")
            .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")
            .unwrap()
            .with_surface(
                GatewaySurface::operation(
                    "echo",
                    echo,
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_publish_capability("publish://effect/echo/say")
                .with_schema(Some(schema_type("string")), Some(schema_type("string"))),
            )
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["echo"],
                ["perform://effect/echo/say"],
            ));
        let inner = GatewayRuntime::new(boot, profile).unwrap();
        let mut mcp = McpGateway::new(Arc::new(inner));
        mcp.register_tool(
            McpToolSpec::new(
                "echo",
                "effect://echo/say",
                "invoke",
                "publish://effect/echo/say",
            )
            .unwrap(),
        )
        .unwrap();
        mcp.register_tool(
            McpToolSpec::new(
                "hidden",
                "effect://hidden/run",
                "invoke",
                "publish://effect/hidden/run",
            )
            .unwrap(),
        )
        .unwrap();

        let response = mcp
            .handle_jsonrpc_value(
                TEST_TOKEN,
                json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}),
            )
            .await;
        assert!(response.error.is_none());
        let tools = response.result.unwrap()["tools"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "echo");
        assert_eq!(
            tools[0]["inputSchema"],
            serde_json::to_value(schema_type("string")).unwrap()
        );

        let denied = mcp
            .handle_jsonrpc_value(
                "wrong-token-for-alice-0001",
                json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
            )
            .await;
        assert_eq!(denied.error.unwrap().code, JSONRPC_GATEWAY_ERROR);
    }

    #[tokio::test]
    async fn jsonrpc_tools_call_runs_through_gateway() {
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
        let profile = GatewayProfile::new("program-mcp")
            .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")
            .unwrap()
            .with_surface(
                GatewaySurface::operation(
                    "echo",
                    target,
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_publish_capability("publish://effect/echo/say"),
            )
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["echo"],
                ["perform://effect/echo/say"],
            ));
        let inner = GatewayRuntime::new(boot, profile).unwrap();
        let mut mcp = McpGateway::new(Arc::new(inner));
        mcp.register_tool(
            McpToolSpec::new(
                "echo",
                "effect://echo/say",
                "invoke",
                "publish://effect/echo/say",
            )
            .unwrap(),
        )
        .unwrap();

        let response = mcp
            .handle_jsonrpc_value(
                TEST_TOKEN,
                json!({
                    "jsonrpc": "2.0",
                    "id": "call-1",
                    "method": "tools/call",
                    "params": {
                        "name": "echo",
                        "arguments": "from-jsonrpc"
                    }
                }),
            )
            .await;
        assert!(response.error.is_none());
        let result = response.result.unwrap();
        assert_eq!(result["structuredContent"], "from-jsonrpc");
        assert_eq!(result["content"][0]["text"], "from-jsonrpc");
        assert_eq!(result["isError"], false);
    }

    #[tokio::test]
    async fn jsonrpc_rejects_unknown_method_and_in_body_credentials() {
        let boot = Arc::new(Bootstrap::in_memory());
        let profile = GatewayProfile::new("program-mcp")
            .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")
            .unwrap();
        let mcp = McpGateway::new(Arc::new(GatewayRuntime::new(boot, profile).unwrap()));

        let unknown = mcp
            .handle_jsonrpc_value(
                TEST_TOKEN,
                json!({"jsonrpc":"2.0","id":1,"method":"resources/list"}),
            )
            .await;
        assert_eq!(unknown.error.unwrap().code, JSONRPC_METHOD_NOT_FOUND);

        let credential_in_body = mcp
            .handle_jsonrpc_value(
                TEST_TOKEN,
                json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "credential": "must-not-be-here"
                }),
            )
            .await;
        assert_eq!(
            credential_in_body.error.unwrap().code,
            JSONRPC_INVALID_REQUEST
        );
    }

    #[test]
    fn tool_names_are_stable_ascii_segments() {
        for name in ["", "two/segments", " two", "*", "**", "工具"] {
            assert!(matches!(
                McpToolSpec::new(
                    name,
                    "effect://echo/say",
                    "invoke",
                    "publish://effect/echo/say"
                ),
                Err(McpGatewayError::BadToolName)
            ));
        }
        assert!(
            McpToolSpec::new(
                "echo.search-v1",
                "effect://echo/say",
                "invoke",
                "publish://effect/echo/say"
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn callable_surface_without_publish_capability_is_not_mcp_visible_or_callable() {
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
        let profile = GatewayProfile::new("program-mcp")
            .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")
            .unwrap()
            .with_surface(GatewaySurface::operation(
                "echo",
                target,
                "invoke",
                "perform",
                "perform://effect/echo/say",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["echo"],
                ["perform://effect/echo/say"],
            ));
        let inner = GatewayRuntime::new(boot, profile).unwrap();
        let mut mcp = McpGateway::new(Arc::new(inner));
        mcp.register_tool(
            McpToolSpec::new(
                "echo",
                "effect://echo/say",
                "invoke",
                "publish://effect/echo/say",
            )
            .unwrap(),
        )
        .unwrap();

        assert!(mcp.descriptors(TEST_TOKEN).await.unwrap().is_empty());
        assert!(matches!(
            mcp.call_tool(TEST_TOKEN, "echo", Value::Null).await,
            Err(McpGatewayError::Gateway(GatewayError::Rejected(_)))
        ));
    }

    #[tokio::test]
    async fn auth_failure_is_redacted_and_audited() {
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
        let profile = GatewayProfile::new("program-mcp")
            .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")
            .unwrap()
            .with_surface(
                GatewaySurface::operation(
                    "echo",
                    target,
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_publish_capability("publish://effect/echo/say"),
            )
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["echo"],
                ["perform://effect/echo/say"],
            ));
        let inner = GatewayRuntime::new(boot.clone(), profile).unwrap();
        let mut mcp = McpGateway::new(Arc::new(inner));
        mcp.register_tool(
            McpToolSpec::new(
                "echo",
                "effect://echo/say",
                "invoke",
                "publish://effect/echo/say",
            )
            .unwrap(),
        )
        .unwrap();

        let err = mcp
            .call_tool("wrong-token-for-alice-0001", "echo", Value::Null)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "gateway rejected MCP request");
        assert!(audit_outcomes(&boot, "gateway_mcp").contains(&"auth_failed".into()));
    }

    #[tokio::test]
    async fn unauthenticated_unknown_tool_does_not_leak_catalog() {
        let boot = Arc::new(Bootstrap::in_memory());
        let profile = GatewayProfile::new("program-mcp")
            .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")
            .unwrap();
        let inner = GatewayRuntime::new(boot.clone(), profile).unwrap();
        let mcp = McpGateway::new(Arc::new(inner));

        let err = mcp
            .call_tool("wrong-token-for-alice-0001", "hidden", Value::Null)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "gateway rejected MCP request");
        let outcomes = audit_outcomes(&boot, "gateway_mcp");
        assert!(outcomes.contains(&"auth_failed".into()));
        assert!(!outcomes.contains(&"unknown_tool".into()));
    }
}
