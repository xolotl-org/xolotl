use serde::{Deserialize, Serialize};
use serde_json::json;

pub(crate) const JSONRPC_VERSION: &str = "2.0";
pub(crate) const JSONRPC_PARSE_ERROR: i64 = -32700;
pub(crate) const JSONRPC_INVALID_REQUEST: i64 = -32600;
pub(crate) const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
pub(crate) const JSONRPC_INVALID_PARAMS: i64 = -32602;
pub(crate) const JSONRPC_RESOURCE_NOT_FOUND: i64 = -32002;
pub(crate) const JSONRPC_GATEWAY_ERROR: i64 = -32000;

const MCP_PROTOCOL_VERSION: &str = "2025-11-25";
const MCP_SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

/// JSON-RPC request or notification accepted by the MCP server adapter.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpJsonRpcRequest {
    /// JSON-RPC protocol version. Must be `2.0`.
    pub jsonrpc: String,
    /// Request id echoed in responses. Missing id means notification.
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

pub(crate) fn jsonrpc_ok(id: serde_json::Value, result: serde_json::Value) -> McpJsonRpcResponse {
    McpJsonRpcResponse {
        jsonrpc: JSONRPC_VERSION,
        id,
        result: Some(result),
        error: None,
    }
}

pub(crate) fn jsonrpc_error(id: serde_json::Value, code: i64) -> McpJsonRpcResponse {
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

pub(crate) fn jsonrpc_invalid_request(
    id: serde_json::Value,
    label: &'static str,
    error: impl std::fmt::Debug,
) -> McpJsonRpcResponse {
    tracing::debug!(
        label,
        error = ?error,
        "mcp json-rpc invalid request"
    );
    jsonrpc_error(id, JSONRPC_INVALID_REQUEST)
}

pub(crate) fn jsonrpc_invalid_params(
    id: serde_json::Value,
    label: &'static str,
    error: impl std::fmt::Debug,
) -> McpJsonRpcResponse {
    tracing::debug!(
        label,
        error = ?error,
        "mcp json-rpc invalid params"
    );
    jsonrpc_error(id, JSONRPC_INVALID_PARAMS)
}

pub(crate) fn jsonrpc_gateway_error(
    id: serde_json::Value,
    label: &'static str,
    error: impl std::fmt::Debug,
) -> McpJsonRpcResponse {
    tracing::warn!(
        label,
        error = ?error,
        "mcp json-rpc gateway error"
    );
    jsonrpc_error(id, JSONRPC_GATEWAY_ERROR)
}

fn jsonrpc_error_message(code: i64) -> &'static str {
    match code {
        JSONRPC_PARSE_ERROR => "parse error",
        JSONRPC_INVALID_REQUEST => "invalid request",
        JSONRPC_METHOD_NOT_FOUND => "method not found",
        JSONRPC_INVALID_PARAMS => "invalid params",
        JSONRPC_RESOURCE_NOT_FOUND => "resource not found",
        JSONRPC_GATEWAY_ERROR => "gateway request rejected",
        _ => "gateway request rejected",
    }
}

pub(crate) fn select_mcp_protocol_version(client_version: Option<&str>) -> &'static str {
    match client_version {
        Some(version) if MCP_SUPPORTED_PROTOCOL_VERSIONS.contains(&version) => {
            for supported in MCP_SUPPORTED_PROTOCOL_VERSIONS {
                if *supported == version {
                    return supported;
                }
            }
            MCP_PROTOCOL_VERSION
        }
        _ => MCP_PROTOCOL_VERSION,
    }
}

pub(crate) fn mcp_initialize_result(protocol_version: &'static str) -> serde_json::Value {
    json!({
        "protocolVersion": protocol_version,
        "capabilities": {
            "tools": {
                "listChanged": false
            },
            "resources": {
                "subscribe": false,
                "listChanged": false
            },
            "prompts": {
                "listChanged": false
            },
            "completions": {}
        },
        "serverInfo": {
            "name": "nexus-gateway-mcp",
            "version": env!("CARGO_PKG_VERSION")
        }
    })
}
