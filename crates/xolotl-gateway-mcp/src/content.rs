use crate::McpGatewayError;

pub(crate) fn validate_mcp_tool_result(value: &serde_json::Value) -> Result<(), McpGatewayError> {
    let map = json_object(value, "tool result")?;
    let content = map
        .get("content")
        .ok_or_else(|| McpGatewayError::BadResult("tool result content is required".into()))?;
    for item in json_array(content, "tool result content")? {
        validate_mcp_content_block(item)?;
    }
    if let Some(structured) = map.get("structuredContent")
        && !structured.is_object()
    {
        return Err(McpGatewayError::BadResult(
            "tool result structuredContent must be an object".into(),
        ));
    }
    if let Some(is_error) = map.get("isError")
        && !is_error.is_boolean()
    {
        return Err(McpGatewayError::BadResult(
            "tool result isError must be a bool".into(),
        ));
    }
    validate_optional_object(map, "_meta", "tool result _meta")
}

pub(crate) fn validate_mcp_resource_result(
    value: &serde_json::Value,
) -> Result<(), McpGatewayError> {
    let map = json_object(value, "resource result")?;
    let contents = map
        .get("contents")
        .ok_or_else(|| McpGatewayError::BadResult("resource result contents is required".into()))?;
    for content in json_array(contents, "resource result contents")? {
        validate_mcp_resource_contents(content)?;
    }
    validate_optional_object(map, "_meta", "resource result _meta")
}

pub(crate) fn validate_mcp_prompt_result(value: &serde_json::Value) -> Result<(), McpGatewayError> {
    let map = json_object(value, "prompt result")?;
    if let Some(description) = map.get("description")
        && !description.is_string()
    {
        return Err(McpGatewayError::BadResult(
            "prompt result description must be a string".into(),
        ));
    }
    let messages = map
        .get("messages")
        .ok_or_else(|| McpGatewayError::BadResult("prompt result messages is required".into()))?;
    for message in json_array(messages, "prompt result messages")? {
        validate_mcp_prompt_message(message)?;
    }
    validate_optional_object(map, "_meta", "prompt result _meta")
}

pub(crate) fn validate_mcp_prompt_message(
    value: &serde_json::Value,
) -> Result<(), McpGatewayError> {
    let map = json_object(value, "prompt message")?;
    match map.get("role").and_then(serde_json::Value::as_str) {
        Some("user" | "assistant") => {}
        _ => {
            return Err(McpGatewayError::BadResult(
                "prompt message role must be user or assistant".into(),
            ));
        }
    }
    let content = map
        .get("content")
        .ok_or_else(|| McpGatewayError::BadResult("prompt message content is required".into()))?;
    validate_mcp_content_block(content)?;
    Ok(())
}

fn validate_mcp_content_block(value: &serde_json::Value) -> Result<(), McpGatewayError> {
    let map = json_object(value, "content block")?;
    match map.get("type").and_then(serde_json::Value::as_str) {
        Some("text") => {
            require_json_string(map, "text", "text content text")?;
        }
        Some("image") => {
            require_json_string(map, "data", "image content data")?;
            require_json_string(map, "mimeType", "image content mimeType")?;
        }
        Some("audio") => {
            require_json_string(map, "data", "audio content data")?;
            require_json_string(map, "mimeType", "audio content mimeType")?;
        }
        Some("resource") => {
            let resource = map.get("resource").ok_or_else(|| {
                McpGatewayError::BadResult("embedded resource content resource is required".into())
            })?;
            validate_mcp_resource_contents(resource)?;
        }
        Some("resource_link") => {
            require_json_string(map, "uri", "resource link uri")?;
            require_json_string(map, "name", "resource link name")?;
            validate_optional_string(map, "title", "resource link title")?;
            validate_optional_string(map, "description", "resource link description")?;
            validate_optional_string(map, "mimeType", "resource link mimeType")?;
            validate_optional_non_negative_integer(map, "size", "resource link size")?;
            if let Some(icons) = map.get("icons") {
                validate_mcp_icons(icons, "resource link icons")?;
            }
        }
        Some(other) => {
            return Err(McpGatewayError::BadResult(format!(
                "unsupported MCP content type {other}"
            )));
        }
        None => {
            return Err(McpGatewayError::BadResult(
                "content block type is required".into(),
            ));
        }
    }
    validate_optional_object(map, "annotations", "content block annotations")?;
    validate_optional_object(map, "_meta", "content block _meta")
}

pub(crate) fn validate_mcp_resource_contents(
    value: &serde_json::Value,
) -> Result<(), McpGatewayError> {
    let map = json_object(value, "resource contents")?;
    require_json_string(map, "uri", "resource contents uri")?;
    validate_optional_string(map, "mimeType", "resource contents mimeType")?;
    let has_text = match map.get("text") {
        Some(serde_json::Value::String(_)) => true,
        Some(_) => {
            return Err(McpGatewayError::BadResult(
                "resource contents text must be a string".into(),
            ));
        }
        None => false,
    };
    let has_blob = match map.get("blob") {
        Some(serde_json::Value::String(_)) => true,
        Some(_) => {
            return Err(McpGatewayError::BadResult(
                "resource contents blob must be a string".into(),
            ));
        }
        None => false,
    };
    match (has_text, has_blob) {
        (true, false) | (false, true) => {}
        (true, true) => {
            return Err(McpGatewayError::BadResult(
                "resource contents must not contain both text and blob".into(),
            ));
        }
        (false, false) => {
            return Err(McpGatewayError::BadResult(
                "resource contents text or blob is required".into(),
            ));
        }
    }
    validate_optional_object(map, "_meta", "resource contents _meta")
}

pub(crate) fn validate_mcp_icons(
    value: &serde_json::Value,
    label: &str,
) -> Result<(), McpGatewayError> {
    for icon in json_array(value, label)? {
        let map = json_object(icon, "icon")?;
        require_json_string(map, "src", "icon src")?;
        validate_optional_string(map, "mimeType", "icon mimeType")?;
        validate_optional_string(map, "sizes", "icon sizes")?;
    }
    Ok(())
}

fn json_object<'a>(
    value: &'a serde_json::Value,
    label: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>, McpGatewayError> {
    value
        .as_object()
        .ok_or_else(|| McpGatewayError::BadResult(format!("{label} must be a JSON object")))
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    label: &str,
) -> Result<&'a Vec<serde_json::Value>, McpGatewayError> {
    value
        .as_array()
        .ok_or_else(|| McpGatewayError::BadResult(format!("{label} must be a JSON array")))
}

fn require_json_string(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &'static str,
    label: &'static str,
) -> Result<(), McpGatewayError> {
    match map.get(key) {
        Some(serde_json::Value::String(_)) => Ok(()),
        Some(_) => Err(McpGatewayError::BadResult(format!(
            "{label} must be a string"
        ))),
        None => Err(McpGatewayError::BadResult(format!("{label} is required"))),
    }
}

fn validate_optional_string(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &'static str,
    label: &'static str,
) -> Result<(), McpGatewayError> {
    match map.get(key) {
        Some(serde_json::Value::String(_)) | None => Ok(()),
        Some(_) => Err(McpGatewayError::BadResult(format!(
            "{label} must be a string"
        ))),
    }
}

fn validate_optional_object(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &'static str,
    label: &'static str,
) -> Result<(), McpGatewayError> {
    match map.get(key) {
        Some(serde_json::Value::Object(_)) | None => Ok(()),
        Some(_) => Err(McpGatewayError::BadResult(format!(
            "{label} must be an object"
        ))),
    }
}

fn validate_optional_non_negative_integer(
    map: &serde_json::Map<String, serde_json::Value>,
    key: &'static str,
    label: &'static str,
) -> Result<(), McpGatewayError> {
    match map.get(key) {
        Some(serde_json::Value::Number(number)) if number.as_u64().is_some() => Ok(()),
        Some(_) => Err(McpGatewayError::BadResult(format!(
            "{label} must be a non-negative integer"
        ))),
        None => Ok(()),
    }
}
