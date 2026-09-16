#![forbid(unsafe_code)]

//! `xolotl-gateway-mcp` - MCP server-side Gateway adapter.
//!
//! This crate covers Xolotl as an MCP server. Gateway publications for the
//! `mcp` protocol are rendered as MCP tools, resources, resource templates, and
//! prompts. Each publication points at one Gateway surface whose target carries
//! an explicit publishing capability.
//!
//! The adapter is transport-neutral: stdio, SSE, or Streamable HTTP framing can
//! wrap the JSON-RPC message handler or the direct Rust methods. Execution
//! still goes through [`xolotl_gateway::Gateway`], so authentication, Process
//! creation, schema checks, policy, taint, Fact recording, budget, and audit use
//! the shared Gateway path.
//!
//! JSON-RPC responses project typed values into ordinary JSON under configurable
//! [`McpOutputLimits`]. Admission accounts for shared descendants before JSON
//! expansion, counts generated JSON nodes before materialization, and checks
//! the encoded response including escaping and envelopes.
//! Ordinary JSON does not preserve every resident type or non-finite float.
//! Use typed calls or Xolotl's tagged format when those distinctions matter;
//! finite MCP response budgets do not constrain cumulative kernel streams.

mod content;
mod error;
mod jsonrpc;
mod output;
mod params;
mod publication;
mod render;
mod runtime;
mod uri_template;
mod validation;

pub use error::McpGatewayError;
pub use jsonrpc::{McpJsonRpcError, McpJsonRpcRequest, McpJsonRpcResponse};
pub use output::{MAX_MCP_JSON_VALUE_DEPTH, McpOutputLimits};
pub use publication::{
    MCP_PUBLICATION_KIND_PROMPT, MCP_PUBLICATION_KIND_RESOURCE,
    MCP_PUBLICATION_KIND_RESOURCE_TEMPLATE, MCP_PUBLICATION_KIND_TOOL, MCP_PUBLICATION_PROTOCOL,
    McpPromptArgumentDescriptor, McpPromptDescriptor, McpResourceDescriptor,
    McpResourceTemplateDescriptor, McpToolDescriptor, mcp_prompt_publication,
    mcp_resource_publication, mcp_resource_template_publication, mcp_tool_publication,
};
pub use runtime::McpGateway;
