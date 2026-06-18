use crate::validation::{is_mcp_name_segment, is_mcp_uri};
use nexus_types::Value;
use serde::Deserialize;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum McpCompletionReference {
    Prompt { name: String },
    ResourceTemplate { uri_template: String },
}

#[derive(Debug)]
pub(crate) enum McpParamError {
    BadShape,
    BadName,
    BadArguments,
    BadCursor,
    BadUri,
    BadMeta,
    BadReference,
    UnsupportedTask,
}

pub(crate) fn jsonrpc_params_absent_or_empty_object(params: &Option<serde_json::Value>) -> bool {
    match params {
        None => true,
        Some(serde_json::Value::Object(map)) => map.is_empty(),
        Some(_) => false,
    }
}

pub(crate) fn jsonrpc_cancelled_params_valid(params: &Option<serde_json::Value>) -> bool {
    let Some(serde_json::Value::Object(map)) = params else {
        return false;
    };
    if !matches!(
        map.get("requestId"),
        Some(serde_json::Value::String(_) | serde_json::Value::Number(_))
    ) {
        return false;
    }
    match map.get("reason") {
        Some(serde_json::Value::String(_)) | None => {}
        Some(_) => return false,
    }
    map.keys().all(|key| key == "requestId" || key == "reason")
}

pub(crate) fn parse_initialize_protocol_version(
    params: Option<serde_json::Value>,
) -> Result<Option<String>, McpParamError> {
    let Some(params) = params else {
        return Ok(None);
    };
    let serde_json::Value::Object(map) = params else {
        return Err(McpParamError::BadShape);
    };
    match map.get("protocolVersion") {
        Some(serde_json::Value::String(version)) => Ok(Some(version.clone())),
        Some(_) => Err(McpParamError::BadShape),
        None => Ok(None),
    }
}

fn empty_object_json() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
}

fn validate_request_metadata(metadata: Option<serde_json::Value>) -> Result<(), McpParamError> {
    match metadata {
        Some(serde_json::Value::Object(_)) | None => Ok(()),
        Some(_) => Err(McpParamError::BadMeta),
    }
}

pub(crate) fn parse_list_params(params: Option<serde_json::Value>) -> Result<usize, McpParamError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ListParams {
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default, rename = "_meta")]
        metadata: Option<serde_json::Value>,
    }

    let value = match params {
        Some(value) => value,
        None => empty_object_json(),
    };
    let params: ListParams = serde_json::from_value(value).map_err(|_| McpParamError::BadShape)?;
    validate_request_metadata(params.metadata)?;
    match params.cursor {
        Some(cursor) => cursor
            .parse::<usize>()
            .map_err(|_| McpParamError::BadCursor),
        None => Ok(0),
    }
}

pub(crate) fn parse_tools_call_params(
    params: Option<serde_json::Value>,
) -> Result<(String, Value), McpParamError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ToolCallParams {
        name: String,
        #[serde(default)]
        arguments: Option<serde_json::Value>,
        #[serde(default)]
        task: Option<serde_json::Value>,
        #[serde(default, rename = "_meta")]
        metadata: Option<serde_json::Value>,
    }

    let value = match params {
        Some(value) => value,
        None => empty_object_json(),
    };
    let params: ToolCallParams =
        serde_json::from_value(value).map_err(|_| McpParamError::BadShape)?;
    if !is_mcp_name_segment(&params.name) {
        return Err(McpParamError::BadName);
    }
    if params.task.is_some() {
        return Err(McpParamError::UnsupportedTask);
    }
    validate_request_metadata(params.metadata)?;
    let arguments = match params.arguments {
        Some(arguments) => arguments,
        None => empty_object_json(),
    };
    if !arguments.is_object() {
        return Err(McpParamError::BadArguments);
    }
    let args =
        serde_json::from_value::<Value>(arguments).map_err(|_| McpParamError::BadArguments)?;
    Ok((params.name, args))
}

pub(crate) fn parse_resources_read_params(
    params: Option<serde_json::Value>,
) -> Result<String, McpParamError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ResourceReadParams {
        uri: String,
        #[serde(default, rename = "_meta")]
        metadata: Option<serde_json::Value>,
    }

    let value = match params {
        Some(value) => value,
        None => empty_object_json(),
    };
    let params: ResourceReadParams =
        serde_json::from_value(value).map_err(|_| McpParamError::BadShape)?;
    validate_request_metadata(params.metadata)?;
    if !is_mcp_uri(&params.uri) {
        return Err(McpParamError::BadUri);
    }
    Ok(params.uri)
}

pub(crate) fn parse_prompts_get_params(
    params: Option<serde_json::Value>,
) -> Result<(String, Value), McpParamError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PromptGetParams {
        name: String,
        #[serde(default)]
        arguments: Option<serde_json::Value>,
        #[serde(default, rename = "_meta")]
        metadata: Option<serde_json::Value>,
    }

    let value = match params {
        Some(value) => value,
        None => empty_object_json(),
    };
    let params: PromptGetParams =
        serde_json::from_value(value).map_err(|_| McpParamError::BadShape)?;
    if !is_mcp_name_segment(&params.name) {
        return Err(McpParamError::BadName);
    }
    validate_request_metadata(params.metadata)?;
    let arguments = match params.arguments {
        Some(arguments) => arguments,
        None => empty_object_json(),
    };
    if !arguments.is_object() {
        return Err(McpParamError::BadArguments);
    }
    let args =
        serde_json::from_value::<Value>(arguments).map_err(|_| McpParamError::BadArguments)?;
    Ok((params.name, args))
}

pub(crate) fn parse_completion_complete_params(
    params: Option<serde_json::Value>,
) -> Result<(McpCompletionReference, String, String), McpParamError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CompletionParams {
        #[serde(rename = "ref")]
        reference: CompletionReferenceParam,
        argument: CompletionArgumentParam,
        #[serde(default)]
        context: Option<serde_json::Value>,
        #[serde(default, rename = "_meta")]
        metadata: Option<serde_json::Value>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CompletionReferenceParam {
        #[serde(rename = "type")]
        kind: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        uri: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CompletionArgumentParam {
        name: String,
        value: String,
    }

    let value = match params {
        Some(value) => value,
        None => empty_object_json(),
    };
    let params: CompletionParams =
        serde_json::from_value(value).map_err(|_| McpParamError::BadShape)?;
    validate_request_metadata(params.metadata)?;
    if let Some(context) = params.context
        && !context.is_object()
    {
        return Err(McpParamError::BadShape);
    }
    if !is_mcp_name_segment(&params.argument.name) {
        return Err(McpParamError::BadName);
    }
    let reference = match params.reference.kind.as_str() {
        "ref/prompt" => {
            let Some(name) = params.reference.name else {
                return Err(McpParamError::BadReference);
            };
            if params.reference.uri.is_some() || !is_mcp_name_segment(&name) {
                return Err(McpParamError::BadReference);
            }
            McpCompletionReference::Prompt { name }
        }
        "ref/resource" => {
            let Some(uri_template) = params.reference.uri else {
                return Err(McpParamError::BadReference);
            };
            if params.reference.name.is_some() || !is_mcp_uri(&uri_template) {
                return Err(McpParamError::BadReference);
            }
            McpCompletionReference::ResourceTemplate { uri_template }
        }
        _ => return Err(McpParamError::BadReference),
    };
    Ok((reference, params.argument.name, params.argument.value))
}
