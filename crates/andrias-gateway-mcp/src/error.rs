use andrias_gateway::GatewayError;
use thiserror::Error;

/// Errors raised while rendering Gateway publications as MCP objects or serving calls.
#[derive(Debug, Error)]
pub enum McpGatewayError {
    /// The MCP client requested a tool that is not published for the session.
    #[error("unknown MCP tool {0}")]
    UnknownTool(String),
    /// The MCP client requested a resource that is not published for the session.
    #[error("unknown MCP resource {0}")]
    UnknownResource(String),
    /// The MCP client requested a prompt that is not published for the session.
    #[error("unknown MCP prompt {0}")]
    UnknownPrompt(String),
    /// The Gateway descriptor contained an invalid MCP publication.
    #[error("bad MCP publication: {0}")]
    BadPublication(String),
    /// A Gateway result could not be rendered as an MCP result.
    #[error("bad MCP result: {0}")]
    BadResult(String),
    /// The shared Andrias gateway rejected authentication or execution.
    #[error("gateway rejected MCP request")]
    Gateway(#[from] GatewayError),
    /// JSON serialization failed while rendering an MCP response.
    #[error("MCP serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
    /// Gateway audit recording failed.
    #[error("gateway audit failed: {0}")]
    Audit(String),
}
