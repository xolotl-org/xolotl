use crate::McpGatewayError;
use crate::content::{
    validate_mcp_prompt_message, validate_mcp_prompt_result, validate_mcp_resource_contents,
    validate_mcp_resource_result, validate_mcp_tool_result,
};
use crate::publication::{
    McpPromptDescriptor, McpResourceDescriptor, McpResourceTemplateDescriptor, McpToolDescriptor,
};
use base64::Engine as _;
use nexus_types::{Outcome, Value};
use serde_json::json;

const DEFAULT_LIST_PAGE_SIZE: usize = 128;
const MCP_COMPLETION_MAX_VALUES: usize = 100;

fn page_result_json(
    key: &'static str,
    values: Vec<serde_json::Value>,
    next_cursor: Option<String>,
) -> serde_json::Value {
    let mut result = serde_json::Map::new();
    result.insert(key.into(), serde_json::Value::Array(values));
    if let Some(cursor) = next_cursor {
        result.insert("nextCursor".into(), serde_json::Value::String(cursor));
    }
    serde_json::Value::Object(result)
}

pub(crate) fn mcp_tools_page_json(
    descriptors: Vec<McpToolDescriptor>,
    cursor: usize,
) -> Result<serde_json::Value, McpGatewayError> {
    let (items, next_cursor) = paginate(descriptors, cursor);
    let tools = items
        .into_iter()
        .map(mcp_tool_descriptor_json)
        .collect::<Result<Vec<_>, McpGatewayError>>()?;
    Ok(page_result_json("tools", tools, next_cursor))
}

pub(crate) fn mcp_resources_page_json(
    descriptors: Vec<McpResourceDescriptor>,
    cursor: usize,
) -> Result<serde_json::Value, McpGatewayError> {
    let (items, next_cursor) = paginate(descriptors, cursor);
    let resources = items
        .into_iter()
        .map(mcp_resource_descriptor_json)
        .collect::<Result<Vec<_>, McpGatewayError>>()?;
    Ok(page_result_json("resources", resources, next_cursor))
}

pub(crate) fn mcp_resource_templates_page_json(
    descriptors: Vec<McpResourceTemplateDescriptor>,
    cursor: usize,
) -> Result<serde_json::Value, McpGatewayError> {
    let (items, next_cursor) = paginate(descriptors, cursor);
    let templates = items
        .into_iter()
        .map(mcp_resource_template_descriptor_json)
        .collect::<Result<Vec<_>, McpGatewayError>>()?;
    Ok(page_result_json(
        "resourceTemplates",
        templates,
        next_cursor,
    ))
}

pub(crate) fn mcp_prompts_page_json(
    descriptors: Vec<McpPromptDescriptor>,
    cursor: usize,
) -> Result<serde_json::Value, McpGatewayError> {
    let (items, next_cursor) = paginate(descriptors, cursor);
    let prompts = items
        .into_iter()
        .map(mcp_prompt_descriptor_json)
        .collect::<Result<Vec<_>, McpGatewayError>>()?;
    Ok(page_result_json("prompts", prompts, next_cursor))
}

fn paginate<T>(items: Vec<T>, cursor: usize) -> (Vec<T>, Option<String>) {
    if cursor > items.len() {
        return (Vec::new(), None);
    }
    let end = cursor
        .saturating_add(DEFAULT_LIST_PAGE_SIZE)
        .min(items.len());
    let next_cursor = if end < items.len() {
        Some(end.to_string())
    } else {
        None
    };
    let page = items
        .into_iter()
        .skip(cursor)
        .take(DEFAULT_LIST_PAGE_SIZE)
        .collect();
    (page, next_cursor)
}

fn mcp_tool_descriptor_json(
    descriptor: McpToolDescriptor,
) -> Result<serde_json::Value, McpGatewayError> {
    let mut tool = serde_json::Map::new();
    tool.insert("name".into(), serde_json::Value::String(descriptor.name));
    insert_optional_string(&mut tool, "title", descriptor.title);
    insert_optional_string(&mut tool, "description", descriptor.description);
    insert_optional_value(&mut tool, "icons", descriptor.icons)?;
    tool.insert(
        "inputSchema".into(),
        match descriptor.input_schema {
            Some(schema) => serde_json::to_value(schema)?,
            None => json!({
                "type": "object",
                "additionalProperties": true
            }),
        },
    );
    insert_optional_value(&mut tool, "outputSchema", descriptor.output_schema)?;
    insert_optional_value(&mut tool, "annotations", descriptor.annotations)?;
    insert_optional_value(&mut tool, "execution", descriptor.execution)?;
    insert_optional_value(&mut tool, "_meta", descriptor.metadata)?;
    Ok(serde_json::Value::Object(tool))
}

fn mcp_resource_descriptor_json(
    descriptor: McpResourceDescriptor,
) -> Result<serde_json::Value, McpGatewayError> {
    let mut resource = serde_json::Map::new();
    resource.insert("uri".into(), serde_json::Value::String(descriptor.uri));
    resource.insert("name".into(), serde_json::Value::String(descriptor.name));
    insert_optional_string(&mut resource, "title", descriptor.title);
    insert_optional_string(&mut resource, "description", descriptor.description);
    insert_optional_value(&mut resource, "icons", descriptor.icons)?;
    insert_optional_string(&mut resource, "mimeType", descriptor.mime_type);
    if let Some(size) = descriptor.size {
        resource.insert("size".into(), serde_json::Value::Number(size.into()));
    }
    insert_optional_value(&mut resource, "annotations", descriptor.annotations)?;
    insert_optional_value(&mut resource, "_meta", descriptor.metadata)?;
    Ok(serde_json::Value::Object(resource))
}

fn mcp_resource_template_descriptor_json(
    descriptor: McpResourceTemplateDescriptor,
) -> Result<serde_json::Value, McpGatewayError> {
    let mut template = serde_json::Map::new();
    template.insert(
        "uriTemplate".into(),
        serde_json::Value::String(descriptor.uri_template),
    );
    template.insert("name".into(), serde_json::Value::String(descriptor.name));
    insert_optional_string(&mut template, "title", descriptor.title);
    insert_optional_string(&mut template, "description", descriptor.description);
    insert_optional_value(&mut template, "icons", descriptor.icons)?;
    insert_optional_string(&mut template, "mimeType", descriptor.mime_type);
    insert_optional_value(&mut template, "annotations", descriptor.annotations)?;
    insert_optional_value(&mut template, "_meta", descriptor.metadata)?;
    Ok(serde_json::Value::Object(template))
}

fn mcp_prompt_descriptor_json(
    descriptor: McpPromptDescriptor,
) -> Result<serde_json::Value, McpGatewayError> {
    let mut prompt = serde_json::Map::new();
    prompt.insert("name".into(), serde_json::Value::String(descriptor.name));
    insert_optional_string(&mut prompt, "title", descriptor.title);
    insert_optional_string(&mut prompt, "description", descriptor.description);
    insert_optional_value(&mut prompt, "icons", descriptor.icons)?;
    if !descriptor.arguments.is_empty() {
        prompt.insert(
            "arguments".into(),
            serde_json::to_value(descriptor.arguments)?,
        );
    }
    insert_optional_value(&mut prompt, "_meta", descriptor.metadata)?;
    Ok(serde_json::Value::Object(prompt))
}

fn insert_optional_string(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &'static str,
    value: Option<String>,
) {
    if let Some(value) = value {
        map.insert(key.into(), serde_json::Value::String(value));
    }
}

fn insert_optional_value(
    map: &mut serde_json::Map<String, serde_json::Value>,
    key: &'static str,
    value: Option<Value>,
) -> Result<(), McpGatewayError> {
    if let Some(value) = value {
        map.insert(key.into(), serde_json::to_value(value)?);
    }
    Ok(())
}

pub(crate) fn mcp_completion_result_json(
    values: Option<&Vec<String>>,
    prefix: &str,
) -> serde_json::Value {
    let mut total = 0usize;
    let mut selected = Vec::new();
    if let Some(values) = values {
        for value in values.iter().filter(|value| value.starts_with(prefix)) {
            total = total.saturating_add(1);
            if selected.len() < MCP_COMPLETION_MAX_VALUES {
                selected.push(serde_json::Value::String(value.clone()));
            }
        }
    }
    json!({
        "completion": {
            "values": selected,
            "total": total,
            "hasMore": total > MCP_COMPLETION_MAX_VALUES
        }
    })
}

fn mcp_tool_result_json(value: Value) -> Result<serde_json::Value, McpGatewayError> {
    if let Some(native) = mcp_native_tool_result(&value)? {
        return Ok(native);
    }
    let structured = serde_json::to_value(&value)?;
    let text = mcp_result_text(&value, &structured)?;
    let mut result = serde_json::Map::new();
    result.insert(
        "content".into(),
        json!([{
            "type": "text",
            "text": text
        }]),
    );
    if structured.is_object() {
        result.insert("structuredContent".into(), structured);
    }
    result.insert("isError".into(), serde_json::Value::Bool(false));
    Ok(serde_json::Value::Object(result))
}

pub(crate) fn mcp_tool_outcome_result_json(
    outcome: Outcome,
) -> Result<serde_json::Value, McpGatewayError> {
    match outcome {
        Outcome::Done(value) | Outcome::Short(value) => mcp_tool_result_json(value),
        Outcome::Fail(failure) => {
            let structured = serde_json::to_value(&failure)?;
            let text = serde_json::to_string(&structured)?;
            let mut result = serde_json::Map::new();
            result.insert(
                "content".into(),
                json!([{
                    "type": "text",
                    "text": text
                }]),
            );
            if structured.is_object() {
                result.insert("structuredContent".into(), structured);
            }
            result.insert("isError".into(), serde_json::Value::Bool(true));
            Ok(serde_json::Value::Object(result))
        }
    }
}

fn mcp_native_tool_result(value: &Value) -> Result<Option<serde_json::Value>, McpGatewayError> {
    let Value::Map(map) = value else {
        return Ok(None);
    };
    if !map.contains_key("content") {
        return Ok(None);
    }
    let native = serde_json::to_value(value)?;
    validate_mcp_tool_result(&native)?;
    Ok(Some(native))
}

fn mcp_result_text(
    value: &Value,
    structured: &serde_json::Value,
) -> Result<String, McpGatewayError> {
    match value {
        Value::Str(text) => Ok(text.clone()),
        _ => Ok(serde_json::to_string(structured)?),
    }
}

pub(crate) fn mcp_resource_result_json(
    value: Value,
    uri: &str,
    default_mime_type: Option<&str>,
) -> Result<serde_json::Value, McpGatewayError> {
    if let Some(native) = mcp_native_resource_result(&value)? {
        return Ok(native);
    }
    let contents = match value {
        Value::List(values) => values
            .into_iter()
            .map(|value| mcp_resource_content_json(value, uri, default_mime_type))
            .collect::<Result<Vec<_>, McpGatewayError>>()?,
        value => vec![mcp_resource_content_json(value, uri, default_mime_type)?],
    };
    Ok(json!({ "contents": contents }))
}

fn mcp_native_resource_result(value: &Value) -> Result<Option<serde_json::Value>, McpGatewayError> {
    let Value::Map(map) = value else {
        return Ok(None);
    };
    if !map.contains_key("contents") {
        return Ok(None);
    }
    match map.get("contents") {
        Some(Value::List(_)) => {
            let native = serde_json::to_value(value)?;
            validate_mcp_resource_result(&native)?;
            Ok(Some(native))
        }
        Some(_) | None => Err(McpGatewayError::BadResult(
            "resource result contents must be a list".into(),
        )),
    }
}

fn mcp_resource_content_json(
    value: Value,
    uri: &str,
    default_mime_type: Option<&str>,
) -> Result<serde_json::Value, McpGatewayError> {
    if let Some(native) = mcp_native_resource_content(&value)? {
        return Ok(native);
    }
    let mut content = serde_json::Map::new();
    content.insert("uri".into(), serde_json::Value::String(uri.into()));
    if let Some(mime_type) = default_mime_type {
        content.insert(
            "mimeType".into(),
            serde_json::Value::String(mime_type.into()),
        );
    }
    match value {
        Value::Str(text) => {
            content.insert("text".into(), serde_json::Value::String(text));
        }
        Value::Bytes(bytes) => {
            content.insert(
                "blob".into(),
                serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(bytes)),
            );
        }
        other => {
            let structured = serde_json::to_value(other)?;
            content.insert(
                "text".into(),
                serde_json::Value::String(serde_json::to_string(&structured)?),
            );
        }
    }
    Ok(serde_json::Value::Object(content))
}

fn mcp_native_resource_content(
    value: &Value,
) -> Result<Option<serde_json::Value>, McpGatewayError> {
    let Value::Map(map) = value else {
        return Ok(None);
    };
    let has_content = map.contains_key("text") || map.contains_key("blob");
    if !has_content {
        return Ok(None);
    }
    let native = serde_json::to_value(value)?;
    validate_mcp_resource_contents(&native)?;
    Ok(Some(native))
}

pub(crate) fn mcp_prompt_result_json(
    value: Value,
    descriptor: &McpPromptDescriptor,
) -> Result<serde_json::Value, McpGatewayError> {
    if let Some(native) = mcp_native_prompt_result(&value, descriptor)? {
        return Ok(native);
    }
    let messages = match value {
        Value::List(values) => values
            .into_iter()
            .map(mcp_prompt_message_from_value)
            .collect::<Result<Vec<_>, McpGatewayError>>()?,
        value => vec![mcp_prompt_message_from_value(value)?],
    };
    let mut result = serde_json::Map::new();
    if let Some(description) = &descriptor.description {
        result.insert(
            "description".into(),
            serde_json::Value::String(description.clone()),
        );
    }
    result.insert("messages".into(), serde_json::Value::Array(messages));
    Ok(serde_json::Value::Object(result))
}

fn mcp_native_prompt_result(
    value: &Value,
    descriptor: &McpPromptDescriptor,
) -> Result<Option<serde_json::Value>, McpGatewayError> {
    let Value::Map(map) = value else {
        return Ok(None);
    };
    if !map.contains_key("messages") {
        return Ok(None);
    }
    match map.get("messages") {
        Some(Value::List(_)) => {
            let mut result = match serde_json::to_value(value)? {
                serde_json::Value::Object(map) => map,
                _ => {
                    return Err(McpGatewayError::BadResult(
                        "prompt result must be an object".into(),
                    ));
                }
            };
            if !result.contains_key("description")
                && let Some(description) = &descriptor.description
            {
                result.insert(
                    "description".into(),
                    serde_json::Value::String(description.clone()),
                );
            }
            let native = serde_json::Value::Object(result);
            validate_mcp_prompt_result(&native)?;
            Ok(Some(native))
        }
        Some(_) | None => Err(McpGatewayError::BadResult(
            "prompt result messages must be a list".into(),
        )),
    }
}

fn mcp_prompt_message_from_value(value: Value) -> Result<serde_json::Value, McpGatewayError> {
    if let Some(native) = mcp_native_prompt_message(&value)? {
        return Ok(native);
    }
    let text = match value {
        Value::Str(text) => text,
        other => {
            let structured = serde_json::to_value(other)?;
            serde_json::to_string(&structured)?
        }
    };
    Ok(json!({
        "role": "user",
        "content": {
            "type": "text",
            "text": text
        }
    }))
}

fn mcp_native_prompt_message(value: &Value) -> Result<Option<serde_json::Value>, McpGatewayError> {
    let Value::Map(map) = value else {
        return Ok(None);
    };
    let native = matches!(map.get("role"), Some(Value::Str(_))) && map.contains_key("content");
    if native {
        let native = serde_json::to_value(value)?;
        validate_mcp_prompt_message(&native)?;
        Ok(Some(native))
    } else {
        Ok(None)
    }
}
