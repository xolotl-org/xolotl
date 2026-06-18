use crate::McpGatewayError;
use crate::content::validate_mcp_icons;
use crate::uri_template::{
    mcp_uri_template_matches, mcp_uri_template_specificity, mcp_uri_template_variable_names,
    validate_mcp_uri_template,
};
use crate::validation::{is_mcp_name_segment, validate_mcp_name, validate_mcp_uri};
use nexus_gateway::{
    GatewayDescriptor, GatewayPublication, GatewayPublicationDescriptor, GatewaySurfaceDescriptor,
};
use nexus_types::Value;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Gateway publication protocol for MCP server objects.
pub const MCP_PUBLICATION_PROTOCOL: &str = "mcp";
/// Gateway publication kind for MCP tools.
pub const MCP_PUBLICATION_KIND_TOOL: &str = "tool";
/// Gateway publication kind for MCP resources.
pub const MCP_PUBLICATION_KIND_RESOURCE: &str = "resource";
/// Gateway publication kind for MCP resource templates.
pub const MCP_PUBLICATION_KIND_RESOURCE_TEMPLATE: &str = "resource_template";
/// Gateway publication kind for MCP prompts.
pub const MCP_PUBLICATION_KIND_PROMPT: &str = "prompt";

/// Create a Gateway publication for one MCP tool.
pub fn mcp_tool_publication(
    name: impl Into<String>,
    surface_id: impl Into<String>,
) -> GatewayPublication {
    GatewayPublication::new(
        MCP_PUBLICATION_PROTOCOL,
        MCP_PUBLICATION_KIND_TOOL,
        name,
        surface_id,
    )
}

/// Create a Gateway publication for one MCP resource.
pub fn mcp_resource_publication(
    name: impl Into<String>,
    uri: impl Into<String>,
    surface_id: impl Into<String>,
) -> GatewayPublication {
    GatewayPublication::new(
        MCP_PUBLICATION_PROTOCOL,
        MCP_PUBLICATION_KIND_RESOURCE,
        name,
        surface_id,
    )
    .with_address(uri)
}

/// Create a Gateway publication for one MCP resource template.
pub fn mcp_resource_template_publication(
    name: impl Into<String>,
    uri_template: impl Into<String>,
    surface_id: impl Into<String>,
) -> GatewayPublication {
    GatewayPublication::new(
        MCP_PUBLICATION_PROTOCOL,
        MCP_PUBLICATION_KIND_RESOURCE_TEMPLATE,
        name,
        surface_id,
    )
    .with_address(uri_template)
}

/// Create a Gateway publication for one MCP prompt.
pub fn mcp_prompt_publication(
    name: impl Into<String>,
    surface_id: impl Into<String>,
) -> GatewayPublication {
    GatewayPublication::new(
        MCP_PUBLICATION_PROTOCOL,
        MCP_PUBLICATION_KIND_PROMPT,
        name,
        surface_id,
    )
}

/// Tool descriptor rendered into MCP `tools/list`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpToolDescriptor {
    /// MCP tool name.
    pub name: String,
    /// Gateway surface invoked by this tool.
    pub surface_id: String,
    /// Nexus effect path the tool invokes.
    pub effect_path: String,
    /// Optional display title.
    pub title: Option<String>,
    /// Optional tool description.
    pub description: Option<String>,
    /// Optional MCP icon descriptors.
    pub icons: Option<Value>,
    /// Optional input schema descriptor.
    pub input_schema: Option<Value>,
    /// Optional output schema descriptor.
    pub output_schema: Option<Value>,
    /// Optional MCP annotations.
    pub annotations: Option<Value>,
    /// Optional MCP execution descriptor.
    pub execution: Option<Value>,
    /// Optional MCP `_meta` value.
    pub metadata: Option<Value>,
}

/// Resource descriptor rendered into MCP `resources/list`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpResourceDescriptor {
    /// MCP resource URI.
    pub uri: String,
    /// MCP resource name.
    pub name: String,
    /// Gateway surface invoked by this resource.
    pub surface_id: String,
    /// Nexus effect path the resource invokes.
    pub effect_path: String,
    /// Optional display title.
    pub title: Option<String>,
    /// Optional resource description.
    pub description: Option<String>,
    /// Optional MCP icon descriptors.
    pub icons: Option<Value>,
    /// Optional resource MIME type.
    pub mime_type: Option<String>,
    /// Optional resource size.
    pub size: Option<u64>,
    /// Optional MCP annotations.
    pub annotations: Option<Value>,
    /// Optional MCP `_meta` value.
    pub metadata: Option<Value>,
}

/// Resource template descriptor rendered into MCP `resources/templates/list`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpResourceTemplateDescriptor {
    /// MCP resource URI template.
    pub uri_template: String,
    /// MCP resource template name.
    pub name: String,
    /// Gateway surface invoked by resources matching this template.
    pub surface_id: String,
    /// Nexus effect path the template invokes.
    pub effect_path: String,
    /// Optional display title.
    pub title: Option<String>,
    /// Optional resource template description.
    pub description: Option<String>,
    /// Optional MCP icon descriptors.
    pub icons: Option<Value>,
    /// Optional MIME type for resources produced by this template.
    pub mime_type: Option<String>,
    /// Optional MCP annotations.
    pub annotations: Option<Value>,
    /// Optional MCP `_meta` value.
    pub metadata: Option<Value>,
    /// Static completion values keyed by URI template argument name.
    #[serde(default, skip_serializing, skip_deserializing)]
    pub completions: BTreeMap<String, Vec<String>>,
}

/// Prompt argument descriptor rendered into MCP `prompts/list`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpPromptArgumentDescriptor {
    /// Argument name.
    pub name: String,
    /// Optional display title.
    pub title: Option<String>,
    /// Optional argument description.
    pub description: Option<String>,
    /// Whether the argument is required.
    pub required: bool,
}

/// Prompt descriptor rendered into MCP `prompts/list`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct McpPromptDescriptor {
    /// MCP prompt name.
    pub name: String,
    /// Gateway surface invoked by this prompt.
    pub surface_id: String,
    /// Nexus effect path the prompt invokes.
    pub effect_path: String,
    /// Optional display title.
    pub title: Option<String>,
    /// Optional prompt description.
    pub description: Option<String>,
    /// Optional MCP icon descriptors.
    pub icons: Option<Value>,
    /// Optional argument descriptors.
    pub arguments: Vec<McpPromptArgumentDescriptor>,
    /// Optional MCP `_meta` value.
    pub metadata: Option<Value>,
    /// Static completion values keyed by prompt argument name.
    #[serde(default, skip_serializing, skip_deserializing)]
    pub completions: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct McpResourceRoute {
    pub(crate) surface_id: String,
    pub(crate) uri_template: Option<String>,
    pub(crate) mime_type: Option<String>,
}

fn mcp_surfaces_by_id(descriptor: &GatewayDescriptor) -> BTreeMap<&str, &GatewaySurfaceDescriptor> {
    descriptor
        .surfaces
        .iter()
        .map(|surface| (surface.surface_id.as_str(), surface))
        .collect()
}

fn mcp_publications<'a>(
    descriptor: &'a GatewayDescriptor,
    kind: &'static str,
) -> impl Iterator<Item = &'a GatewayPublicationDescriptor> {
    descriptor.publications.iter().filter(move |publication| {
        publication.protocol == MCP_PUBLICATION_PROTOCOL && publication.kind == kind
    })
}

pub(crate) fn mcp_tool_descriptors_from_gateway(
    descriptor: &GatewayDescriptor,
) -> Result<Vec<McpToolDescriptor>, McpGatewayError> {
    let surfaces = mcp_surfaces_by_id(descriptor);
    mcp_publications(descriptor, MCP_PUBLICATION_KIND_TOOL)
        .map(|publication| {
            let surface = mcp_surface_for_publication(publication, &surfaces)?;
            mcp_tool_descriptor_from_publication(publication, surface)
        })
        .collect()
}

pub(crate) fn mcp_resource_descriptors_from_gateway(
    descriptor: &GatewayDescriptor,
) -> Result<Vec<McpResourceDescriptor>, McpGatewayError> {
    let surfaces = mcp_surfaces_by_id(descriptor);
    mcp_publications(descriptor, MCP_PUBLICATION_KIND_RESOURCE)
        .map(|publication| {
            let surface = mcp_surface_for_publication(publication, &surfaces)?;
            mcp_resource_descriptor_from_publication(publication, surface)
        })
        .collect()
}

pub(crate) fn mcp_resource_template_descriptors_from_gateway(
    descriptor: &GatewayDescriptor,
) -> Result<Vec<McpResourceTemplateDescriptor>, McpGatewayError> {
    let surfaces = mcp_surfaces_by_id(descriptor);
    mcp_publications(descriptor, MCP_PUBLICATION_KIND_RESOURCE_TEMPLATE)
        .map(|publication| {
            let surface = mcp_surface_for_publication(publication, &surfaces)?;
            mcp_resource_template_descriptor_from_publication(publication, surface)
        })
        .collect()
}

pub(crate) fn mcp_prompt_descriptors_from_gateway(
    descriptor: &GatewayDescriptor,
) -> Result<Vec<McpPromptDescriptor>, McpGatewayError> {
    let surfaces = mcp_surfaces_by_id(descriptor);
    mcp_publications(descriptor, MCP_PUBLICATION_KIND_PROMPT)
        .map(|publication| {
            let surface = mcp_surface_for_publication(publication, &surfaces)?;
            mcp_prompt_descriptor_from_publication(publication, surface)
        })
        .collect()
}

fn mcp_surface_for_publication<'a>(
    publication: &GatewayPublicationDescriptor,
    surfaces: &'a BTreeMap<&str, &GatewaySurfaceDescriptor>,
) -> Result<&'a GatewaySurfaceDescriptor, McpGatewayError> {
    match surfaces.get(publication.surface_id.as_str()) {
        Some(surface) => Ok(surface),
        None => Err(McpGatewayError::BadPublication(format!(
            "publication {}:{}:{} references non-visible surface {}",
            publication.protocol, publication.kind, publication.name, publication.surface_id
        ))),
    }
}

fn mcp_tool_descriptor_from_publication(
    publication: &GatewayPublicationDescriptor,
    surface: &GatewaySurfaceDescriptor,
) -> Result<McpToolDescriptor, McpGatewayError> {
    validate_mcp_name(&publication.name, "tool name")?;
    if publication.address.is_some() {
        return Err(McpGatewayError::BadPublication(format!(
            "tool publication {} must not set address",
            publication.name
        )));
    }
    Ok(McpToolDescriptor {
        name: publication.name.clone(),
        surface_id: surface.surface_id.clone(),
        effect_path: surface.target.path().to_string(),
        title: publication.title.clone(),
        description: publication.description.clone(),
        icons: publication_icons(publication)?,
        input_schema: surface.input_schema.clone(),
        output_schema: surface.output_schema.clone(),
        annotations: publication.annotations.clone(),
        execution: publication_execution(publication)?,
        metadata: publication.metadata.clone(),
    })
}

fn mcp_resource_descriptor_from_publication(
    publication: &GatewayPublicationDescriptor,
    surface: &GatewaySurfaceDescriptor,
) -> Result<McpResourceDescriptor, McpGatewayError> {
    validate_mcp_name(&publication.name, "resource name")?;
    let uri = required_publication_address(publication)?;
    validate_mcp_uri(uri, "resource uri")?;
    Ok(McpResourceDescriptor {
        uri: uri.to_string(),
        name: publication.name.clone(),
        surface_id: surface.surface_id.clone(),
        effect_path: surface.target.path().to_string(),
        title: publication.title.clone(),
        description: publication.description.clone(),
        icons: publication_icons(publication)?,
        mime_type: publication_property_string(publication, "mimeType")?,
        size: publication_property_u64(publication, "size")?,
        annotations: publication.annotations.clone(),
        metadata: publication.metadata.clone(),
    })
}

fn mcp_resource_template_descriptor_from_publication(
    publication: &GatewayPublicationDescriptor,
    surface: &GatewaySurfaceDescriptor,
) -> Result<McpResourceTemplateDescriptor, McpGatewayError> {
    validate_mcp_name(&publication.name, "resource template name")?;
    let uri_template = required_publication_address(publication)?;
    validate_mcp_uri_template(uri_template)?;
    let completions = publication_completion_values(publication)?;
    validate_completion_keys_for_template(uri_template, &completions)?;
    Ok(McpResourceTemplateDescriptor {
        uri_template: uri_template.to_string(),
        name: publication.name.clone(),
        surface_id: surface.surface_id.clone(),
        effect_path: surface.target.path().to_string(),
        title: publication.title.clone(),
        description: publication.description.clone(),
        icons: publication_icons(publication)?,
        mime_type: publication_property_string(publication, "mimeType")?,
        annotations: publication.annotations.clone(),
        metadata: publication.metadata.clone(),
        completions,
    })
}

fn mcp_prompt_descriptor_from_publication(
    publication: &GatewayPublicationDescriptor,
    surface: &GatewaySurfaceDescriptor,
) -> Result<McpPromptDescriptor, McpGatewayError> {
    validate_mcp_name(&publication.name, "prompt name")?;
    if publication.address.is_some() {
        return Err(McpGatewayError::BadPublication(format!(
            "prompt publication {} must not set address",
            publication.name
        )));
    }
    let arguments = publication_prompt_arguments(publication)?;
    let completions = publication_completion_values(publication)?;
    validate_completion_keys_for_prompt(&arguments, &completions)?;
    Ok(McpPromptDescriptor {
        name: publication.name.clone(),
        surface_id: surface.surface_id.clone(),
        effect_path: surface.target.path().to_string(),
        title: publication.title.clone(),
        description: publication.description.clone(),
        icons: publication_icons(publication)?,
        arguments,
        metadata: publication.metadata.clone(),
        completions,
    })
}

fn required_publication_address(
    publication: &GatewayPublicationDescriptor,
) -> Result<&str, McpGatewayError> {
    match publication.address.as_deref() {
        Some(address) => Ok(address),
        None => Err(McpGatewayError::BadPublication(format!(
            "publication {}:{}:{} requires address",
            publication.protocol, publication.kind, publication.name
        ))),
    }
}

fn publication_property_string(
    publication: &GatewayPublicationDescriptor,
    key: &str,
) -> Result<Option<String>, McpGatewayError> {
    match publication.properties.get(key) {
        Some(Value::Str(value)) => Ok(Some(value.clone())),
        Some(_) => Err(McpGatewayError::BadPublication(format!(
            "publication {}:{} property {key} must be a string",
            publication.kind, publication.name
        ))),
        None => Ok(None),
    }
}

fn publication_property_u64(
    publication: &GatewayPublicationDescriptor,
    key: &str,
) -> Result<Option<u64>, McpGatewayError> {
    match publication.properties.get(key) {
        Some(Value::Int(value)) if *value >= 0 => u64::try_from(*value).map(Some).map_err(|_| {
            McpGatewayError::BadPublication(format!(
                "publication {}:{} property {key} is out of range",
                publication.kind, publication.name
            ))
        }),
        Some(_) => Err(McpGatewayError::BadPublication(format!(
            "publication {}:{} property {key} must be a non-negative integer",
            publication.kind, publication.name
        ))),
        None => Ok(None),
    }
}

fn publication_icons(
    publication: &GatewayPublicationDescriptor,
) -> Result<Option<Value>, McpGatewayError> {
    let Some(value) = publication.properties.get("icons") else {
        return Ok(None);
    };
    let json = serde_json::to_value(value)?;
    validate_mcp_icons(
        &json,
        &format!(
            "publication {}:{} icons",
            publication.kind, publication.name
        ),
    )?;
    Ok(Some(value.clone()))
}

fn publication_execution(
    publication: &GatewayPublicationDescriptor,
) -> Result<Option<Value>, McpGatewayError> {
    let Some(value) = publication.properties.get("execution") else {
        return Ok(None);
    };
    let Value::Map(map) = value else {
        return Err(McpGatewayError::BadPublication(format!(
            "publication {}:{} execution must be a map",
            publication.kind, publication.name
        )));
    };
    if map.contains_key("taskSupport") {
        return Err(McpGatewayError::BadPublication(format!(
            "publication {}:{} execution taskSupport is not supported by this adapter",
            publication.kind, publication.name
        )));
    }
    Ok(Some(value.clone()))
}

fn publication_completion_values(
    publication: &GatewayPublicationDescriptor,
) -> Result<BTreeMap<String, Vec<String>>, McpGatewayError> {
    let Some(value) = publication.properties.get("completions") else {
        return Ok(BTreeMap::new());
    };
    let Value::Map(map) = value else {
        return Err(McpGatewayError::BadPublication(format!(
            "publication {}:{} completions must be a map",
            publication.kind, publication.name
        )));
    };
    let mut out = BTreeMap::new();
    for (name, values) in map {
        if !is_mcp_name_segment(name) {
            return Err(McpGatewayError::BadPublication(format!(
                "publication {}:{} completion key must be one stable ASCII segment",
                publication.kind, publication.name
            )));
        }
        let Value::List(items) = values else {
            return Err(McpGatewayError::BadPublication(format!(
                "publication {}:{} completion values for {name} must be a list",
                publication.kind, publication.name
            )));
        };
        let mut strings = Vec::with_capacity(items.len());
        for item in items {
            match item {
                Value::Str(value) => strings.push(value.clone()),
                _ => {
                    return Err(McpGatewayError::BadPublication(format!(
                        "publication {}:{} completion value for {name} must be a string",
                        publication.kind, publication.name
                    )));
                }
            }
        }
        out.insert(name.clone(), strings);
    }
    Ok(out)
}

fn validate_completion_keys_for_prompt(
    arguments: &[McpPromptArgumentDescriptor],
    completions: &BTreeMap<String, Vec<String>>,
) -> Result<(), McpGatewayError> {
    let argument_names = arguments
        .iter()
        .map(|argument| argument.name.as_str())
        .collect::<BTreeSet<_>>();
    for key in completions.keys() {
        if !argument_names.contains(key.as_str()) {
            return Err(McpGatewayError::BadPublication(format!(
                "prompt completion key {key} does not match a prompt argument"
            )));
        }
    }
    Ok(())
}

fn validate_completion_keys_for_template(
    uri_template: &str,
    completions: &BTreeMap<String, Vec<String>>,
) -> Result<(), McpGatewayError> {
    let variables = mcp_uri_template_variable_names(uri_template)?;
    for key in completions.keys() {
        if !variables.contains(key) {
            return Err(McpGatewayError::BadPublication(format!(
                "resource template completion key {key} does not match a URI template variable"
            )));
        }
    }
    Ok(())
}

fn publication_prompt_arguments(
    publication: &GatewayPublicationDescriptor,
) -> Result<Vec<McpPromptArgumentDescriptor>, McpGatewayError> {
    let Some(value) = publication.properties.get("arguments") else {
        return Ok(Vec::new());
    };
    let Value::List(items) = value else {
        return Err(McpGatewayError::BadPublication(format!(
            "publication {}:{} arguments must be a list",
            publication.kind, publication.name
        )));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::Map(map) = item else {
            return Err(McpGatewayError::BadPublication(format!(
                "publication {}:{} argument must be a map",
                publication.kind, publication.name
            )));
        };
        let name = match map.get("name") {
            Some(Value::Str(name)) => {
                validate_mcp_name(name, "prompt argument name")?;
                name.clone()
            }
            Some(_) | None => {
                return Err(McpGatewayError::BadPublication(format!(
                    "publication {}:{} argument name must be a string",
                    publication.kind, publication.name
                )));
            }
        };
        let title = optional_map_string(map, "title", "prompt argument title")?;
        let description = optional_map_string(map, "description", "prompt argument description")?;
        let required = match map.get("required") {
            Some(Value::Bool(required)) => *required,
            Some(_) => {
                return Err(McpGatewayError::BadPublication(format!(
                    "publication {}:{} argument required must be a bool",
                    publication.kind, publication.name
                )));
            }
            None => false,
        };
        out.push(McpPromptArgumentDescriptor {
            name,
            title,
            description,
            required,
        });
    }
    Ok(out)
}

fn optional_map_string(
    map: &BTreeMap<String, Value>,
    key: &'static str,
    label: &'static str,
) -> Result<Option<String>, McpGatewayError> {
    match map.get(key) {
        Some(Value::Str(value)) => {
            if value.trim().is_empty() {
                return Err(McpGatewayError::BadPublication(format!(
                    "{label} must not be empty"
                )));
            }
            Ok(Some(value.clone()))
        }
        Some(_) => Err(McpGatewayError::BadPublication(format!(
            "{label} must be a string"
        ))),
        None => Ok(None),
    }
}

pub(crate) fn resolve_mcp_tool_surface_id(
    descriptor: &GatewayDescriptor,
    tool: &str,
) -> Result<String, McpGatewayError> {
    let tools = mcp_tool_descriptors_from_gateway(descriptor)?;
    tools
        .into_iter()
        .find(|descriptor| descriptor.name == tool)
        .map(|descriptor| descriptor.surface_id)
        .ok_or_else(|| McpGatewayError::UnknownTool(tool.into()))
}

pub(crate) fn resolve_mcp_resource_route(
    descriptor: &GatewayDescriptor,
    uri: &str,
) -> Result<McpResourceRoute, McpGatewayError> {
    let resources = mcp_resource_descriptors_from_gateway(descriptor)?;
    if let Some(resource) = resources.into_iter().find(|resource| resource.uri == uri) {
        return Ok(McpResourceRoute {
            surface_id: resource.surface_id,
            uri_template: None,
            mime_type: resource.mime_type,
        });
    }

    let templates = mcp_resource_template_descriptors_from_gateway(descriptor)?;
    let mut best: Option<(usize, McpResourceTemplateDescriptor)> = None;
    for template in templates {
        if mcp_uri_template_matches(&template.uri_template, uri)? {
            let specificity = mcp_uri_template_specificity(&template.uri_template)?;
            let replace = match &best {
                Some((best_specificity, _)) => specificity > *best_specificity,
                None => true,
            };
            if replace {
                best = Some((specificity, template));
            }
        }
    }

    match best {
        Some((_, template)) => Ok(McpResourceRoute {
            surface_id: template.surface_id,
            uri_template: Some(template.uri_template),
            mime_type: template.mime_type,
        }),
        None => Err(McpGatewayError::UnknownResource(uri.into())),
    }
}

pub(crate) fn resolve_mcp_resource_template_descriptor(
    descriptor: &GatewayDescriptor,
    uri_template: &str,
) -> Result<McpResourceTemplateDescriptor, McpGatewayError> {
    let templates = mcp_resource_template_descriptors_from_gateway(descriptor)?;
    templates
        .into_iter()
        .find(|descriptor| descriptor.uri_template == uri_template)
        .ok_or_else(|| McpGatewayError::UnknownResource(uri_template.into()))
}

pub(crate) fn resolve_mcp_prompt_descriptor(
    descriptor: &GatewayDescriptor,
    prompt: &str,
) -> Result<McpPromptDescriptor, McpGatewayError> {
    let prompts = mcp_prompt_descriptors_from_gateway(descriptor)?;
    prompts
        .into_iter()
        .find(|descriptor| descriptor.name == prompt)
        .ok_or_else(|| McpGatewayError::UnknownPrompt(prompt.into()))
}
