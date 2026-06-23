use crate::{CompiledGatewayProfile, CompiledSurfaceDescriptor, GatewayError, GatewayModality};
use std::collections::{BTreeMap, BTreeSet};
use xolotl_graph::DoNode;
use xolotl_types::{Failure, Outcome, OutputMode, Value};

const MAX_VALUE_SCHEMA_DEPTH: usize = 32;
const MAX_VALUE_SCHEMA_NODES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CompiledValueSchema {
    kind: ValueSchemaKind,
    required: BTreeSet<String>,
    properties: BTreeMap<String, CompiledValueSchema>,
    items: Option<Box<CompiledValueSchema>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValueSchemaKind {
    Any,
    Null,
    Bool,
    Int,
    Number,
    Str,
    List,
    Map,
    Bytes,
    Blob,
    Tensor,
    Frame,
    StreamEnd,
}

pub(super) fn compile_value_schema(
    schema: &Value,
    label: &str,
) -> Result<CompiledValueSchema, GatewayError> {
    let mut nodes = 0usize;
    compile_value_schema_inner(schema, label, 0, &mut nodes)
}

fn compile_value_schema_inner(
    schema: &Value,
    label: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<CompiledValueSchema, GatewayError> {
    if depth > MAX_VALUE_SCHEMA_DEPTH {
        return Err(GatewayError::InvalidProfile(format!(
            "{label} exceeds max schema depth"
        )));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_VALUE_SCHEMA_NODES {
        return Err(GatewayError::InvalidProfile(format!(
            "{label} exceeds max schema nodes"
        )));
    }
    let map = schema
        .as_map()
        .ok_or_else(|| GatewayError::InvalidProfile(format!("{label} must be a schema object")))?;
    for key in map.keys() {
        if !matches!(key.as_str(), "type" | "required" | "properties" | "items") {
            return Err(GatewayError::InvalidProfile(format!(
                "{label} contains unsupported schema key {key}"
            )));
        }
    }
    let kind = match map.get("type").and_then(Value::as_str) {
        Some("any") | None => ValueSchemaKind::Any,
        Some("null") => ValueSchemaKind::Null,
        Some("boolean") | Some("bool") => ValueSchemaKind::Bool,
        Some("integer") | Some("int") => ValueSchemaKind::Int,
        Some("number") => ValueSchemaKind::Number,
        Some("string") | Some("str") => ValueSchemaKind::Str,
        Some("array") | Some("list") => ValueSchemaKind::List,
        Some("object") | Some("map") => ValueSchemaKind::Map,
        Some("bytes") => ValueSchemaKind::Bytes,
        Some("blob") => ValueSchemaKind::Blob,
        Some("tensor") => ValueSchemaKind::Tensor,
        Some("frame") => ValueSchemaKind::Frame,
        Some("stream_end") => ValueSchemaKind::StreamEnd,
        Some(other) => {
            return Err(GatewayError::InvalidProfile(format!(
                "{label} has unsupported schema type {other}"
            )));
        }
    };

    let mut required = BTreeSet::new();
    match map.get("required") {
        Some(Value::List(items)) if matches!(kind, ValueSchemaKind::Map | ValueSchemaKind::Any) => {
            for item in items {
                let Some(field) = item.as_str() else {
                    return Err(GatewayError::InvalidProfile(format!(
                        "{label} required entries must be strings"
                    )));
                };
                if field.trim().is_empty() {
                    return Err(GatewayError::InvalidProfile(format!(
                        "{label} required entries must not be empty"
                    )));
                }
                required.insert(field.to_string());
            }
        }
        Some(_) => {
            return Err(GatewayError::InvalidProfile(format!(
                "{label} required is only valid for object schemas"
            )));
        }
        None => {}
    }

    let mut properties = BTreeMap::new();
    match map.get("properties") {
        Some(Value::Map(entries))
            if matches!(kind, ValueSchemaKind::Map | ValueSchemaKind::Any) =>
        {
            for (field, child) in entries {
                if field.trim().is_empty() {
                    return Err(GatewayError::InvalidProfile(format!(
                        "{label} property names must not be empty"
                    )));
                }
                properties.insert(
                    field.clone(),
                    compile_value_schema_inner(
                        child,
                        &format!("{label}.properties.{field}"),
                        depth.saturating_add(1),
                        nodes,
                    )?,
                );
            }
        }
        Some(_) => {
            return Err(GatewayError::InvalidProfile(format!(
                "{label} properties is only valid for object schemas"
            )));
        }
        None => {}
    }

    let items = match map.get("items") {
        Some(child) if matches!(kind, ValueSchemaKind::List | ValueSchemaKind::Any) => {
            Some(Box::new(compile_value_schema_inner(
                child,
                &format!("{label}.items"),
                depth.saturating_add(1),
                nodes,
            )?))
        }
        Some(_) => {
            return Err(GatewayError::InvalidProfile(format!(
                "{label} items is only valid for array schemas"
            )));
        }
        None => None,
    };

    Ok(CompiledValueSchema {
        kind,
        required,
        properties,
        items,
    })
}

pub(super) fn validate_surface_input(
    surface: &CompiledSurfaceDescriptor,
    value: &Value,
) -> Result<(), GatewayError> {
    if let Some(schema) = &surface.input_schema_validator {
        validate_value_schema(schema, value, "input", "surface input_schema")?;
    }
    Ok(())
}

fn validate_surface_output(
    surface: &CompiledSurfaceDescriptor,
    value: &Value,
) -> Result<(), GatewayError> {
    if let Some(schema) = &surface.output_schema_validator {
        validate_value_schema(schema, value, "output", "surface output_schema")?;
    }
    Ok(())
}

pub(super) fn validate_surface_stream_item(
    surface: &CompiledSurfaceDescriptor,
    modality: GatewayModality,
    item: &Value,
) -> Result<(), GatewayError> {
    let Some(schema) = stream_item_schema(surface, modality) else {
        return Ok(());
    };
    validate_value_schema(schema, item, "stream item", "surface input_schema")
}

fn stream_item_schema(
    surface: &CompiledSurfaceDescriptor,
    modality: GatewayModality,
) -> Option<&CompiledValueSchema> {
    let schema = surface.input_schema_validator.as_ref()?;
    match modality {
        GatewayModality::Value | GatewayModality::Event => schema.items.as_deref().or(Some(schema)),
        _ => Some(schema),
    }
}

fn validate_value_schema(
    schema: &CompiledValueSchema,
    value: &Value,
    path: &str,
    schema_label: &str,
) -> Result<(), GatewayError> {
    let matches_kind = match schema.kind {
        ValueSchemaKind::Any => true,
        ValueSchemaKind::Null => matches!(value, Value::Null),
        ValueSchemaKind::Bool => matches!(value, Value::Bool(_)),
        ValueSchemaKind::Int => matches!(value, Value::Int(_)),
        ValueSchemaKind::Number => matches!(value, Value::Int(_) | Value::Float(_)),
        ValueSchemaKind::Str => matches!(value, Value::Str(_)),
        ValueSchemaKind::List => matches!(value, Value::List(_)),
        ValueSchemaKind::Map => matches!(value, Value::Map(_)),
        ValueSchemaKind::Bytes => matches!(value, Value::Bytes(_)),
        ValueSchemaKind::Blob => matches!(value, Value::Blob(_)),
        ValueSchemaKind::Tensor => matches!(value, Value::Tensor(_)),
        ValueSchemaKind::Frame => matches!(value, Value::Frame(_)),
        ValueSchemaKind::StreamEnd => matches!(value, Value::StreamEnd(_)),
    };
    if !matches_kind {
        return Err(GatewayError::Rejected(format!(
            "{path} does not match {schema_label}"
        )));
    }
    if let Value::Map(map) = value {
        for required in &schema.required {
            if !map.contains_key(required) {
                return Err(GatewayError::Rejected(format!(
                    "{path} is missing required field {required}"
                )));
            }
        }
        for (field, field_schema) in &schema.properties {
            if let Some(field_value) = map.get(field) {
                validate_value_schema(
                    field_schema,
                    field_value,
                    &format!("{path}.{field}"),
                    schema_label,
                )?;
            }
        }
    }
    if let (Value::List(items), Some(item_schema)) = (value, &schema.items) {
        for (index, item) in items.iter().enumerate() {
            validate_value_schema(item_schema, item, &format!("{path}[{index}]"), schema_label)?;
        }
    }
    Ok(())
}

pub(super) fn enforce_surface_output_schema(
    profile: &CompiledGatewayProfile,
    principal_id: &str,
    program: &DoNode,
    outcome: Outcome,
) -> Outcome {
    let Some(surface) = output_schema_surface_for_program(profile, principal_id, program) else {
        return outcome;
    };
    match outcome {
        Outcome::Done(value) => match validate_surface_output(surface, &value) {
            Ok(()) => Outcome::Done(value),
            Err(error) => Outcome::Fail(output_schema_failure(&surface.surface_id, error)),
        },
        Outcome::Short(value) => match validate_surface_output(surface, &value) {
            Ok(()) => Outcome::Short(value),
            Err(error) => Outcome::Fail(output_schema_failure(&surface.surface_id, error)),
        },
        Outcome::Fail(failure) => Outcome::Fail(failure),
    }
}

fn output_schema_surface_for_program<'a>(
    profile: &'a CompiledGatewayProfile,
    principal_id: &str,
    program: &DoNode,
) -> Option<&'a CompiledSurfaceDescriptor> {
    let DoNode::Op(tmpl) = program else {
        return None;
    };
    if tmpl.output == OutputMode::SinkOnly {
        return None;
    }
    profile.operation_surface_for_principal(principal_id, &tmpl.target, &tmpl.method)
}

fn output_schema_failure(surface_id: &str, error: GatewayError) -> Failure {
    Failure::Custom {
        kind: "gateway_output_schema".into(),
        message: format!("surface {surface_id} output did not match declared schema: {error}"),
    }
}
