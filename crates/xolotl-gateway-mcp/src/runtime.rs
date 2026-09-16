use crate::jsonrpc::{
    JSONRPC_INVALID_PARAMS, JSONRPC_INVALID_REQUEST, JSONRPC_METHOD_NOT_FOUND, JSONRPC_PARSE_ERROR,
    JSONRPC_RESOURCE_NOT_FOUND, JSONRPC_VERSION, McpJsonRpcRequest, McpJsonRpcResponse,
    jsonrpc_error, jsonrpc_gateway_error, jsonrpc_invalid_params, jsonrpc_invalid_request,
    jsonrpc_ok, mcp_initialize_result, select_mcp_protocol_version,
};
use crate::params::{
    McpCompletionReference, jsonrpc_cancelled_params_valid, jsonrpc_params_absent_or_empty_object,
    parse_completion_complete_params, parse_initialize_protocol_version, parse_list_params,
    parse_prompts_get_params, parse_resources_read_params, parse_tools_call_params,
};
use crate::publication::{
    McpPromptDescriptor, McpResourceRoute, mcp_prompt_descriptors_from_gateway,
    mcp_resource_descriptors_from_gateway, mcp_resource_template_descriptors_from_gateway,
    mcp_tool_descriptors_from_gateway, resolve_mcp_prompt_descriptor, resolve_mcp_resource_route,
    resolve_mcp_resource_template_descriptor, resolve_mcp_tool_surface_id,
};
use crate::render::{
    mcp_completion_result_json, mcp_prompt_result_json, mcp_prompts_page_json,
    mcp_resource_result_json, mcp_resource_templates_page_json, mcp_resources_page_json,
    mcp_tool_outcome_result_json, mcp_tools_page_json,
};
use crate::{
    McpGatewayError, McpResourceDescriptor, McpResourceTemplateDescriptor, McpToolDescriptor,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use xolotl_gateway::{
    Gateway, GatewayDescriptor, GatewaySession, GatewaySubmission, PresentedCredential,
};
use xolotl_kernel::GatewayAudit;
use xolotl_types::{Outcome, Value};

/// Transport-neutral MCP server adapter over a shared Xolotl Gateway.
pub struct McpGateway<G: Gateway> {
    gateway: Arc<G>,
    output_limits: crate::McpOutputLimits,
}

impl<G: Gateway> McpGateway<G> {
    /// Create an adapter over an existing authenticated Xolotl gateway.
    pub fn new(gateway: Arc<G>) -> Self {
        Self {
            gateway,
            output_limits: crate::McpOutputLimits::default(),
        }
    }

    /// Configure finite ordinary-JSON response budgets for this adapter.
    /// Kernel execution and direct typed return values keep their own policies.
    /// A response can exceed its delivery budget after execution has completed;
    /// rejection does not roll back effects already performed by that call.
    pub fn with_output_limits(
        mut self,
        limits: crate::McpOutputLimits,
    ) -> Result<Self, McpGatewayError> {
        limits.validate()?;
        self.output_limits = limits;
        Ok(self)
    }

    /// Return authenticated tool descriptors suitable for MCP `tools/list`.
    pub async fn list_tools(
        &self,
        bearer_token: impl Into<String>,
    ) -> Result<Vec<McpToolDescriptor>, McpGatewayError> {
        let session = self.authenticate_session(bearer_token.into()).await?;
        let descriptor = self.describe_session(&session)?;
        record_mcp_audit(&*self.gateway, Some(&session), "describe_ok")?;
        mcp_tool_descriptors_from_gateway(&descriptor)
    }

    /// Return authenticated resource descriptors suitable for MCP `resources/list`.
    pub async fn list_resources(
        &self,
        bearer_token: impl Into<String>,
    ) -> Result<Vec<McpResourceDescriptor>, McpGatewayError> {
        let session = self.authenticate_session(bearer_token.into()).await?;
        let descriptor = self.describe_session(&session)?;
        record_mcp_audit(&*self.gateway, Some(&session), "describe_ok")?;
        mcp_resource_descriptors_from_gateway(&descriptor)
    }

    /// Return authenticated resource templates for MCP `resources/templates/list`.
    pub async fn list_resource_templates(
        &self,
        bearer_token: impl Into<String>,
    ) -> Result<Vec<McpResourceTemplateDescriptor>, McpGatewayError> {
        let session = self.authenticate_session(bearer_token.into()).await?;
        let descriptor = self.describe_session(&session)?;
        record_mcp_audit(&*self.gateway, Some(&session), "describe_ok")?;
        mcp_resource_template_descriptors_from_gateway(&descriptor)
    }

    /// Return authenticated prompt descriptors suitable for MCP `prompts/list`.
    pub async fn list_prompts(
        &self,
        bearer_token: impl Into<String>,
    ) -> Result<Vec<McpPromptDescriptor>, McpGatewayError> {
        let session = self.authenticate_session(bearer_token.into()).await?;
        let descriptor = self.describe_session(&session)?;
        record_mcp_audit(&*self.gateway, Some(&session), "describe_ok")?;
        mcp_prompt_descriptors_from_gateway(&descriptor)
    }

    /// Translate one MCP `tools/call` into a standard Gateway submission.
    pub async fn call_tool(
        &self,
        bearer_token: impl Into<String>,
        tool: &str,
        args: Value,
    ) -> Result<Outcome, McpGatewayError> {
        let identity = self.authenticate_session(bearer_token.into()).await?;
        let descriptor = self.describe_session(&identity)?;
        let surface_id = match resolve_mcp_tool_surface_id(&descriptor, tool) {
            Ok(surface_id) => surface_id,
            Err(McpGatewayError::UnknownTool(_)) => {
                record_mcp_audit(&*self.gateway, Some(&identity), "unknown_tool")?;
                return Err(McpGatewayError::UnknownTool(tool.into()));
            }
            Err(error) => return Err(error),
        };
        self.submit_direct(&identity, surface_id, args, "mcp_tool_call")
            .await
    }

    /// Translate one MCP `resources/read` into a standard Gateway submission.
    pub async fn read_resource(
        &self,
        bearer_token: impl Into<String>,
        uri: &str,
    ) -> Result<Outcome, McpGatewayError> {
        self.read_resource_with_route(bearer_token.into(), uri)
            .await
            .map(|(outcome, _)| outcome)
    }

    async fn read_resource_with_route(
        &self,
        bearer_token: String,
        uri: &str,
    ) -> Result<(Outcome, McpResourceRoute), McpGatewayError> {
        let identity = self.authenticate_session(bearer_token).await?;
        let descriptor = self.describe_session(&identity)?;
        let route = match resolve_mcp_resource_route(&descriptor, uri) {
            Ok(route) => route,
            Err(McpGatewayError::UnknownResource(_)) => {
                record_mcp_audit(&*self.gateway, Some(&identity), "unknown_resource")?;
                return Err(McpGatewayError::UnknownResource(uri.into()));
            }
            Err(error) => return Err(error),
        };
        let input = mcp_resource_read_input(uri, route.uri_template.as_deref());
        let outcome = self
            .submit_direct(
                &identity,
                route.surface_id.clone(),
                input,
                "mcp_resource_read",
            )
            .await?;
        Ok((outcome, route))
    }

    /// Translate one MCP `prompts/get` into a standard Gateway submission.
    pub async fn get_prompt(
        &self,
        bearer_token: impl Into<String>,
        prompt: &str,
        args: Value,
    ) -> Result<Outcome, McpGatewayError> {
        self.get_prompt_with_descriptor(bearer_token.into(), prompt, args)
            .await
            .map(|(outcome, _)| outcome)
    }

    async fn get_prompt_with_descriptor(
        &self,
        bearer_token: String,
        prompt: &str,
        args: Value,
    ) -> Result<(Outcome, McpPromptDescriptor), McpGatewayError> {
        let identity = self.authenticate_session(bearer_token).await?;
        let descriptor = self.describe_session(&identity)?;
        let prompt_descriptor = match resolve_mcp_prompt_descriptor(&descriptor, prompt) {
            Ok(prompt_descriptor) => prompt_descriptor,
            Err(McpGatewayError::UnknownPrompt(_)) => {
                record_mcp_audit(&*self.gateway, Some(&identity), "unknown_prompt")?;
                return Err(McpGatewayError::UnknownPrompt(prompt.into()));
            }
            Err(error) => return Err(error),
        };
        let input = Value::map(BTreeMap::from([
            ("name".into(), Value::from(prompt)),
            ("arguments".into(), args),
        ]));
        let outcome = self
            .submit_direct(
                &identity,
                prompt_descriptor.surface_id.clone(),
                input,
                "mcp_prompt_get",
            )
            .await?;
        Ok((outcome, prompt_descriptor))
    }

    async fn complete(
        &self,
        bearer_token: String,
        reference: McpCompletionReference,
        argument_name: String,
        argument_value: String,
    ) -> Result<serde_json::Value, McpGatewayError> {
        let identity = self.authenticate_session(bearer_token).await?;
        let descriptor = self.describe_session(&identity)?;
        let completions = match reference {
            McpCompletionReference::Prompt { name } => {
                resolve_mcp_prompt_descriptor(&descriptor, &name)?.completions
            }
            McpCompletionReference::ResourceTemplate { uri_template } => {
                resolve_mcp_resource_template_descriptor(&descriptor, &uri_template)?.completions
            }
        };
        Ok(mcp_completion_result_json(
            completions.get(&argument_name),
            &argument_value,
        ))
    }

    /// Handle one parsed MCP JSON-RPC request. Notifications are rejected.
    pub async fn handle_jsonrpc_value(
        &self,
        bearer_token: impl Into<String>,
        request: serde_json::Value,
    ) -> McpJsonRpcResponse {
        let request = match serde_json::from_value::<McpJsonRpcRequest>(request) {
            Ok(request) => request,
            Err(error) => {
                return jsonrpc_invalid_request(
                    serde_json::Value::Null,
                    "mcp_jsonrpc_value_decode",
                    error,
                );
            }
        };
        self.handle_jsonrpc_request(bearer_token, request).await
    }

    /// Handle one serialized MCP JSON-RPC request. Notifications are rejected.
    pub async fn handle_jsonrpc_str(
        &self,
        bearer_token: impl Into<String>,
        request: &str,
    ) -> McpJsonRpcResponse {
        let request = match serde_json::from_str::<McpJsonRpcRequest>(request) {
            Ok(request) => request,
            Err(error) if error.is_syntax() || error.is_eof() => {
                tracing::debug!(
                    error = ?error,
                    "mcp json-rpc request parse failed"
                );
                return jsonrpc_error(serde_json::Value::Null, JSONRPC_PARSE_ERROR);
            }
            Err(error) => {
                return jsonrpc_invalid_request(
                    serde_json::Value::Null,
                    "mcp_jsonrpc_str_decode",
                    error,
                );
            }
        };
        self.handle_jsonrpc_request(bearer_token, request).await
    }

    /// Handle one parsed MCP JSON-RPC message. Notifications return no response.
    pub async fn handle_jsonrpc_message_value(
        &self,
        bearer_token: impl Into<String>,
        message: serde_json::Value,
    ) -> Option<McpJsonRpcResponse> {
        let request = match serde_json::from_value::<McpJsonRpcRequest>(message) {
            Ok(request) => request,
            Err(error) => {
                return Some(jsonrpc_invalid_request(
                    serde_json::Value::Null,
                    "mcp_jsonrpc_message_value_decode",
                    error,
                ));
            }
        };
        self.handle_jsonrpc_message_request(bearer_token, request)
            .await
    }

    /// Handle one serialized MCP JSON-RPC message. Notifications return no response.
    pub async fn handle_jsonrpc_message_str(
        &self,
        bearer_token: impl Into<String>,
        message: &str,
    ) -> Option<McpJsonRpcResponse> {
        let request = match serde_json::from_str::<McpJsonRpcRequest>(message) {
            Ok(request) => request,
            Err(error) if error.is_syntax() || error.is_eof() => {
                tracing::debug!(
                    error = ?error,
                    "mcp json-rpc message parse failed"
                );
                return Some(jsonrpc_error(serde_json::Value::Null, JSONRPC_PARSE_ERROR));
            }
            Err(error) => {
                return Some(jsonrpc_invalid_request(
                    serde_json::Value::Null,
                    "mcp_jsonrpc_message_str_decode",
                    error,
                ));
            }
        };
        self.handle_jsonrpc_message_request(bearer_token, request)
            .await
    }

    /// Handle one decoded MCP JSON-RPC request.
    pub async fn handle_jsonrpc_request(
        &self,
        bearer_token: impl Into<String>,
        request: McpJsonRpcRequest,
    ) -> McpJsonRpcResponse {
        let response = self.dispatch_jsonrpc_request(bearer_token, request).await;
        if let Err(error) = self.output_limits.check_message(&response) {
            let mut rejected = jsonrpc_gateway_error(response.id, "mcp_output_budget", error);
            if self.output_limits.check_message(&rejected).is_err() {
                rejected.id = serde_json::Value::Null;
            }
            return rejected;
        }
        response
    }

    async fn dispatch_jsonrpc_request(
        &self,
        bearer_token: impl Into<String>,
        request: McpJsonRpcRequest,
    ) -> McpJsonRpcResponse {
        let Some(id) = request.id else {
            return jsonrpc_error(serde_json::Value::Null, JSONRPC_INVALID_REQUEST);
        };
        if !matches!(
            id,
            serde_json::Value::String(_) | serde_json::Value::Number(_)
        ) {
            return jsonrpc_error(serde_json::Value::Null, JSONRPC_INVALID_REQUEST);
        }
        if request.jsonrpc != JSONRPC_VERSION {
            return jsonrpc_error(id, JSONRPC_INVALID_REQUEST);
        }
        let bearer_token = bearer_token.into();
        match request.method.as_str() {
            "initialize" => match parse_initialize_protocol_version(request.params) {
                Ok(client_version) => jsonrpc_ok(
                    id,
                    mcp_initialize_result(select_mcp_protocol_version(client_version.as_deref())),
                ),
                Err(error) => jsonrpc_invalid_params(id, "mcp_initialize_params", error),
            },
            "ping" => {
                if !jsonrpc_params_absent_or_empty_object(&request.params) {
                    return jsonrpc_error(id, JSONRPC_INVALID_PARAMS);
                }
                jsonrpc_ok(id, json!({}))
            }
            "tools/list" => {
                let cursor = match parse_list_params(request.params) {
                    Ok(cursor) => cursor,
                    Err(error) => {
                        return jsonrpc_invalid_params(id, "mcp_tools_list_params", error);
                    }
                };
                match self.list_tools(bearer_token).await {
                    Ok(descriptors) => {
                        match mcp_tools_page_json(descriptors, cursor, self.output_limits) {
                            Ok(result) => jsonrpc_ok(id, result),
                            Err(error) => {
                                jsonrpc_gateway_error(id, "mcp_tools_list_serialize", error)
                            }
                        }
                    }
                    Err(error) => jsonrpc_gateway_error(id, "mcp_tools_list", error),
                }
            }
            "tools/call" => match parse_tools_call_params(request.params) {
                Ok((tool, args)) => match self.call_tool(bearer_token, &tool, args).await {
                    Ok(outcome) => {
                        match mcp_tool_outcome_result_json(outcome, self.output_limits) {
                            Ok(result) => jsonrpc_ok(id, result),
                            Err(error) => {
                                jsonrpc_gateway_error(id, "mcp_tool_result_serialize", error)
                            }
                        }
                    }
                    Err(McpGatewayError::UnknownTool(_)) => {
                        jsonrpc_error(id, JSONRPC_INVALID_PARAMS)
                    }
                    Err(error) => jsonrpc_gateway_error(id, "mcp_tool_call", error),
                },
                Err(error) => jsonrpc_invalid_params(id, "mcp_tool_call_params", error),
            },
            "resources/list" => {
                let cursor = match parse_list_params(request.params) {
                    Ok(cursor) => cursor,
                    Err(error) => {
                        return jsonrpc_invalid_params(id, "mcp_resources_list_params", error);
                    }
                };
                match self.list_resources(bearer_token).await {
                    Ok(descriptors) => {
                        match mcp_resources_page_json(descriptors, cursor, self.output_limits) {
                            Ok(result) => jsonrpc_ok(id, result),
                            Err(error) => {
                                jsonrpc_gateway_error(id, "mcp_resources_list_serialize", error)
                            }
                        }
                    }
                    Err(error) => jsonrpc_gateway_error(id, "mcp_resources_list", error),
                }
            }
            "resources/templates/list" => {
                let cursor = match parse_list_params(request.params) {
                    Ok(cursor) => cursor,
                    Err(error) => {
                        return jsonrpc_invalid_params(
                            id,
                            "mcp_resource_templates_list_params",
                            error,
                        );
                    }
                };
                match self.list_resource_templates(bearer_token).await {
                    Ok(descriptors) => {
                        match mcp_resource_templates_page_json(
                            descriptors,
                            cursor,
                            self.output_limits,
                        ) {
                            Ok(result) => jsonrpc_ok(id, result),
                            Err(error) => jsonrpc_gateway_error(
                                id,
                                "mcp_resource_templates_list_serialize",
                                error,
                            ),
                        }
                    }
                    Err(error) => jsonrpc_gateway_error(id, "mcp_resource_templates_list", error),
                }
            }
            "resources/read" => match parse_resources_read_params(request.params) {
                Ok(uri) => match self.read_resource_with_route(bearer_token, &uri).await {
                    Ok((Outcome::Done(value), route)) | Ok((Outcome::Short(value), route)) => {
                        match mcp_resource_result_json(
                            value,
                            &uri,
                            route.mime_type.as_deref(),
                            self.output_limits,
                        ) {
                            Ok(result) => jsonrpc_ok(id, result),
                            Err(error) => {
                                jsonrpc_gateway_error(id, "mcp_resource_read_serialize", error)
                            }
                        }
                    }
                    Ok((Outcome::Fail(failure), _)) => {
                        jsonrpc_gateway_error(id, "mcp_resource_read_outcome", failure)
                    }
                    Err(McpGatewayError::UnknownResource(_)) => {
                        jsonrpc_error(id, JSONRPC_RESOURCE_NOT_FOUND)
                    }
                    Err(error) => jsonrpc_gateway_error(id, "mcp_resource_read", error),
                },
                Err(error) => jsonrpc_invalid_params(id, "mcp_resource_read_params", error),
            },
            "prompts/list" => {
                let cursor = match parse_list_params(request.params) {
                    Ok(cursor) => cursor,
                    Err(error) => {
                        return jsonrpc_invalid_params(id, "mcp_prompts_list_params", error);
                    }
                };
                match self.list_prompts(bearer_token).await {
                    Ok(descriptors) => {
                        match mcp_prompts_page_json(descriptors, cursor, self.output_limits) {
                            Ok(result) => jsonrpc_ok(id, result),
                            Err(error) => {
                                jsonrpc_gateway_error(id, "mcp_prompts_list_serialize", error)
                            }
                        }
                    }
                    Err(error) => jsonrpc_gateway_error(id, "mcp_prompts_list", error),
                }
            }
            "prompts/get" => match parse_prompts_get_params(request.params) {
                Ok((prompt, args)) => match self
                    .get_prompt_with_descriptor(bearer_token, &prompt, args)
                    .await
                {
                    Ok((Outcome::Done(value), prompt_descriptor))
                    | Ok((Outcome::Short(value), prompt_descriptor)) => {
                        match mcp_prompt_result_json(value, &prompt_descriptor, self.output_limits)
                        {
                            Ok(result) => jsonrpc_ok(id, result),
                            Err(error) => {
                                jsonrpc_gateway_error(id, "mcp_prompt_get_serialize", error)
                            }
                        }
                    }
                    Ok((Outcome::Fail(failure), _)) => {
                        jsonrpc_gateway_error(id, "mcp_prompt_get_outcome", failure)
                    }
                    Err(McpGatewayError::UnknownPrompt(_)) => {
                        jsonrpc_error(id, JSONRPC_INVALID_PARAMS)
                    }
                    Err(error) => jsonrpc_gateway_error(id, "mcp_prompt_get", error),
                },
                Err(error) => jsonrpc_invalid_params(id, "mcp_prompt_get_params", error),
            },
            "completion/complete" => match parse_completion_complete_params(request.params) {
                Ok((reference, argument_name, argument_value)) => match self
                    .complete(bearer_token, reference, argument_name, argument_value)
                    .await
                {
                    Ok(result) => jsonrpc_ok(id, result),
                    Err(McpGatewayError::UnknownPrompt(_))
                    | Err(McpGatewayError::UnknownResource(_)) => {
                        jsonrpc_error(id, JSONRPC_INVALID_PARAMS)
                    }
                    Err(error) => jsonrpc_gateway_error(id, "mcp_completion_complete", error),
                },
                Err(error) => jsonrpc_invalid_params(id, "mcp_completion_complete_params", error),
            },
            _ => jsonrpc_error(id, JSONRPC_METHOD_NOT_FOUND),
        }
    }

    async fn handle_jsonrpc_message_request(
        &self,
        bearer_token: impl Into<String>,
        request: McpJsonRpcRequest,
    ) -> Option<McpJsonRpcResponse> {
        if request.id.is_some() {
            return Some(self.handle_jsonrpc_request(bearer_token, request).await);
        }
        if request.jsonrpc != JSONRPC_VERSION {
            tracing::debug!("mcp json-rpc notification used invalid version");
            return None;
        }
        match request.method.as_str() {
            "notifications/initialized" => {
                if !jsonrpc_params_absent_or_empty_object(&request.params) {
                    tracing::debug!("mcp initialized notification carried invalid params");
                }
                None
            }
            "notifications/cancelled" => {
                if !jsonrpc_cancelled_params_valid(&request.params) {
                    tracing::debug!("mcp cancelled notification carried invalid params");
                }
                None
            }
            _ => {
                tracing::debug!(method = request.method, "mcp json-rpc notification ignored");
                None
            }
        }
    }

    async fn authenticate_session(
        &self,
        bearer_token: String,
    ) -> Result<GatewaySession, McpGatewayError> {
        match self
            .gateway
            .authenticate(PresentedCredential::bearer(bearer_token))
            .await
        {
            Ok(session) => Ok(session),
            Err(error) => {
                record_mcp_audit(&*self.gateway, None, error.audit_outcome())?;
                Err(error.into())
            }
        }
    }

    fn describe_session(
        &self,
        session: &GatewaySession,
    ) -> Result<GatewayDescriptor, McpGatewayError> {
        match self.gateway.describe(session) {
            Ok(descriptor) => Ok(descriptor),
            Err(error) => {
                record_mcp_audit(&*self.gateway, Some(session), error.audit_outcome())?;
                Err(error.into())
            }
        }
    }

    async fn submit_direct(
        &self,
        session: &GatewaySession,
        surface_id: String,
        input: Value,
        audit_label: &'static str,
    ) -> Result<Outcome, McpGatewayError> {
        match self
            .gateway
            .submit(session, GatewaySubmission::direct_input(surface_id, input))
            .await
        {
            Ok(result) => Ok(result.output.outcome),
            Err(error) => {
                record_mcp_audit(&*self.gateway, Some(session), error.audit_outcome())?;
                tracing::debug!(audit_label, error = ?error, "mcp gateway submission failed");
                Err(error.into())
            }
        }
    }
}

fn mcp_resource_read_input(uri: &str, uri_template: Option<&str>) -> Value {
    let mut map = BTreeMap::from([("uri".into(), Value::from(uri))]);
    if let Some(uri_template) = uri_template {
        map.insert("uriTemplate".into(), Value::from(uri_template));
    }
    Value::map(map)
}

fn record_mcp_audit<G: Gateway>(
    gateway: &G,
    session: Option<&GatewaySession>,
    outcome: &'static str,
) -> Result<(), McpGatewayError> {
    gateway
        .record_gateway_audit(GatewayAudit {
            event: "gateway_mcp",
            username: session.map(GatewaySession::identity_path),
            source_addr: None,
            outcome,
            mfa_level: None,
            details: None,
        })
        .map_err(McpGatewayError::Audit)
}
