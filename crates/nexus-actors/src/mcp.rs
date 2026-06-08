//! MCP bidirectional interoperability (§18.2).
//!
//! * **Nexus as host**: an MCP server is a *sandboxed Provider* exposing
//!   `effect://mcp-tool/<server>/<tool>`. The MCP tool schema maps to
//!   `EffectCapability.input/output_schema`; purity defaults to Effectful;
//!   streaming tools are registered with stream-capable output support.
//!   Redaction / Audit / taint still apply because every tool call is an
//!   ordinary Operation.
//! * **Nexus as server**: [`expose_as_mcp_tool`] turns a Nexus effect into an
//!   MCP tool descriptor — and *requires* a bound capability set before
//!   exposure, so an effect is never published wider than its capability.
//!
//! A real MCP transport (stdio / SSE) is wired by implementing [`McpClient`];
//! the offline spine ships a deterministic echo client so the projection and
//! capability binding are testable without a network.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{MethodId, Outcome, OutputMode, Purity, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Method names for one concrete `effect://mcp-tool/<server>/<tool>` Provider.
/// MCP tools default to Effectful (§16.3.7 / §18.2) unless the server declares
/// otherwise.
pub const MCP_TOOL_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "invoke",
    Purity::Effectful,
    MethodSpec::UNARY_ASYNC,
)];

/// Method table for an MCP tool whose server advertises streaming output.
pub const MCP_STREAM_TOOL_METHODS: &[MethodSpec] = &[MethodSpec::new(
    "invoke",
    Purity::Effectful,
    MethodSpec::STREAM_ASYNC,
)];

/// The transport seam to a real MCP server. Production implements this over
/// stdio / SSE; the spine uses [`EchoMcpClient`].
#[async_trait]
pub trait McpClient: Send + Sync + 'static {
    /// Invoke `tool` with `args`, returning the tool's result value.
    async fn call_tool(&self, tool: &str, args: &Value) -> Result<Value, String>;

    /// Invoke a streaming MCP tool. Non-streaming clients may normalize their
    /// unary result into one chunk; only stream-capable tool registrations
    /// expose `OutputMode::Stream` to callers.
    async fn stream_tool(
        &self,
        tool: &str,
        args: &Value,
        ctx: &DriverContext,
    ) -> Result<Value, String> {
        let result = self.call_tool(tool, args).await?;
        ctx.emit(result.clone());
        Ok(result)
    }
}

/// Deterministic offline MCP client: echoes a structured acknowledgement so the
/// host-side projection is exercised without a network.
pub struct EchoMcpClient;

#[async_trait]
impl McpClient for EchoMcpClient {
    async fn call_tool(&self, tool: &str, args: &Value) -> Result<Value, String> {
        let mut m = BTreeMap::new();
        m.insert("tool".into(), Value::Str(tool.into()));
        m.insert("echo".into(), args.clone());
        Ok(Value::Map(m))
    }
}

/// Drives one concrete `effect://mcp-tool/<server>/<tool>` Resource (Nexus as
/// MCP host, §18.2). Sandboxed: it is registered under the
/// `effect://mcp-tool/<server>/` namespace and can only reach the bound MCP
/// server.
pub struct McpToolDriver {
    tool: String,
    client: Arc<dyn McpClient>,
}

impl McpToolDriver {
    /// Create an MCP tool driver backed by `client`.
    pub fn new(tool: impl Into<String>, client: Arc<dyn McpClient>) -> Self {
        Self {
            tool: tool.into(),
            client,
        }
    }

    /// The offline echo host.
    pub fn echo(tool: impl Into<String>) -> Self {
        Self {
            tool: tool.into(),
            client: Arc::new(EchoMcpClient),
        }
    }
}

#[async_trait]
impl Driver for McpToolDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let result = if matches!(output, OutputMode::Stream) {
            self.client
                .stream_tool(&self.tool, &input, ctx)
                .await
                .map_err(DriverError::Other)?
        } else {
            self.client
                .call_tool(&self.tool, &input)
                .await
                .map_err(DriverError::Other)?
        };
        Ok(Outcome::Done(result))
    }
}

/// An MCP tool descriptor exposed by Nexus (Nexus as MCP server, §18.2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct McpToolDescriptor {
    /// MCP tool name exposed to clients.
    pub name: String,
    /// Nexus effect path backing the tool.
    pub effect_path: String,
    /// The capability set required to call this tool — the exposure is rejected
    /// without it (§18.2 "暴露前必须绑定 capability set").
    pub required_capability: String,
    /// Optional MCP input schema.
    pub input_schema: Option<Value>,
    /// Optional MCP output schema.
    pub output_schema: Option<Value>,
}

/// Expose a Nexus effect as an MCP tool (§18.2). Returns `Err` if no capability
/// is bound — an effect is never published wider than its capability.
pub fn expose_as_mcp_tool(
    name: &str,
    effect_path: &str,
    required_capability: &str,
    input_schema: Option<Value>,
    output_schema: Option<Value>,
) -> Result<McpToolDescriptor, String> {
    if required_capability.trim().is_empty() {
        return Err(
            "refusing to expose an effect as an MCP tool without a bound capability".into(),
        );
    }
    Ok(McpToolDescriptor {
        name: name.into(),
        effect_path: effect_path.into(),
        required_capability: required_capability.into(),
        input_schema,
        output_schema,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_types::{IdentityRef, ProcessId};

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    #[tokio::test]
    async fn host_calls_tool_through_client() {
        let d = McpToolDriver::echo("search");
        let out = d
            .call(
                MethodId::new(0),
                Value::Str("query".into()),
                OutputMode::Unary,
                &ctx(),
            )
            .await
            .unwrap();
        match out {
            Outcome::Done(Value::Map(r)) => {
                assert_eq!(r.get("tool").and_then(|v| v.as_str()), Some("search"));
                assert_eq!(r.get("echo"), Some(&Value::Str("query".into())));
            }
            _ => panic!("expected echo map"),
        }
    }

    #[tokio::test]
    async fn streaming_tool_emits_to_driver_context() {
        let d = McpToolDriver::echo("search");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let ctx = ctx().with_stream(nexus_types::Path::parse("state://stream/mcp").unwrap(), tx);
        let out = d
            .call(
                MethodId::new(0),
                Value::Str("query".into()),
                OutputMode::Stream,
                &ctx,
            )
            .await
            .unwrap();
        let chunk = rx.recv().await.unwrap();
        assert_eq!(out, Outcome::Done(chunk));
    }

    #[test]
    fn server_exposure_requires_capability() {
        // §18.2: exposing without a capability is rejected.
        assert!(expose_as_mcp_tool("t", "effect://x/y", "", None, None).is_err());
        let d = expose_as_mcp_tool(
            "search",
            "effect://search/run",
            "perform://effect/search/run",
            None,
            None,
        )
        .unwrap();
        assert_eq!(d.required_capability, "perform://effect/search/run");
    }
}
