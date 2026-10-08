//! Validate invocation metadata before an action can perform side effects.

use super::ConsoleError;
#[cfg(test)]
use crate::protocol;
use crate::{
    protocol::{ActionCall, SchemaDescriptor, StreamCall},
    registry::DescriptorRegistry,
};
use xolotl_types::{Path, Value};

pub(crate) fn validate_call(
    registry: &DescriptorRegistry,
    call: &ActionCall,
) -> Result<(), ConsoleError> {
    let descriptor = validate_call_header(registry, call)?;
    validate_input(&descriptor.input, &call.input)
}

pub(crate) fn validate_call_header<'a>(
    registry: &'a DescriptorRegistry,
    call: &ActionCall,
) -> Result<&'a crate::protocol::ActionDescriptor, ConsoleError> {
    // Report a stale descriptor contract before interpreting the action name.
    if call
        .registry_rev
        .is_some_and(|revision| revision != registry.current_rev())
    {
        return Err(ConsoleError::RegistryChanged {
            current_registry_rev: registry.current_rev(),
        });
    }
    registry
        .action_by_id(&call.action)
        .ok_or_else(|| ConsoleError::BadRequest(format!("unknown console action: {}", call.action)))
}

pub(crate) fn validate_stream(
    registry: &DescriptorRegistry,
    call: &StreamCall,
) -> Result<(), ConsoleError> {
    let descriptor = validate_stream_header(registry, call)?;
    validate_input(&descriptor.input, &call.input)
}

pub(crate) fn validate_stream_header<'a>(
    registry: &'a DescriptorRegistry,
    call: &StreamCall,
) -> Result<&'a crate::protocol::StreamDescriptor, ConsoleError> {
    registry
        .stream_by_id(&call.stream)
        .ok_or_else(|| ConsoleError::BadRequest("unknown console stream".into()))
}

fn validate_input(schema: &SchemaDescriptor, input: &Value) -> Result<(), ConsoleError> {
    // Omitted top-level input is the empty argument set for an optional map.
    if input.is_null()
        && schema.value_kind == "map"
        && schema.discriminator.is_none()
        && !schema.fields.iter().any(|field| field.required)
    {
        return Ok(());
    }
    validate_schema(schema, input, &[], "input", 0)
}

const MAX_SCHEMA_DEPTH: usize = 32;

fn validate_schema(
    schema: &SchemaDescriptor,
    input: &Value,
    inherited: &[&SchemaDescriptor],
    at: &str,
    depth: usize,
) -> Result<(), ConsoleError> {
    check_depth(depth)?;
    let definitions: Vec<_> = inherited
        .iter()
        .copied()
        .chain(&schema.definitions)
        .collect();
    if schema.value_kind != "map" {
        return validate_kind(&schema.value_kind, input, &definitions, at, depth + 1);
    }
    let map = input.as_map().ok_or_else(|| invalid_type(at, "map"))?;
    if let Some(discriminator) = &schema.discriminator {
        let tag = map
            .get(discriminator)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ConsoleError::BadRequest(format!("{at}.{discriminator} must select a variant"))
            })?;
        let variant = schema.variants.get(tag).ok_or_else(|| {
            ConsoleError::BadRequest(format!("unknown {at}.{discriminator} variant: {tag}"))
        })?;
        let variant = resolve_schema(&definitions, variant).ok_or_else(|| {
            ConsoleError::Operation("descriptor references an unknown variant schema".into())
        })?;
        return validate_schema(variant, input, &definitions, at, depth + 1);
    }
    for key in map.keys() {
        if !schema.fields.iter().any(|field| field.name == key) {
            return Err(ConsoleError::BadRequest(format!(
                "unknown input field: {at}.{key}"
            )));
        }
    }
    for field in &schema.fields {
        let Some(value) = map.get(&field.name) else {
            if field.required {
                return Err(ConsoleError::BadRequest(format!(
                    "missing input field: {at}.{}",
                    field.name
                )));
            }
            continue;
        };
        let at = format!("{at}.{}", field.name);
        if let Some(max_items) = field.max_items
            && value
                .as_list()
                .is_some_and(|items| items.len() > max_items as usize)
        {
            return Err(ConsoleError::BadRequest(format!(
                "{at} accepts at most {max_items} entries"
            )));
        }
        validate_kind(&field.kind, value, &definitions, &at, depth + 1)?;
    }
    Ok(())
}

fn validate_kind(
    kind: &str,
    value: &Value,
    definitions: &[&SchemaDescriptor],
    at: &str,
    depth: usize,
) -> Result<(), ConsoleError> {
    check_depth(depth)?;
    if let Some(inner) = kind.strip_suffix("|null") {
        return if value.is_null() {
            Ok(())
        } else {
            validate_kind(inner, value, definitions, at, depth + 1)
        };
    }
    if let Some(inner) = kind.strip_prefix("list<").and_then(|s| s.strip_suffix('>')) {
        let items = value.as_list().ok_or_else(|| invalid_type(at, kind))?;
        for (index, item) in items.iter().enumerate() {
            validate_kind(
                inner,
                item,
                definitions,
                &format!("{at}[{index}]"),
                depth + 1,
            )?;
        }
        return Ok(());
    }
    if let Some(valid) = valid_scalar_kind(kind, value) {
        return if valid {
            Ok(())
        } else {
            Err(invalid_type(at, kind))
        };
    }
    let schema = resolve_schema(definitions, kind).ok_or_else(|| {
        ConsoleError::Operation(format!("unsupported descriptor input kind: {kind}"))
    })?;
    validate_schema(schema, value, definitions, at, depth + 1)
}

fn resolve_schema<'a>(
    definitions: &[&'a SchemaDescriptor],
    id: &str,
) -> Option<&'a SchemaDescriptor> {
    definitions
        .iter()
        .rev()
        .copied()
        .find(|schema| schema.schema_id == id)
}

fn check_depth(depth: usize) -> Result<(), ConsoleError> {
    if depth > MAX_SCHEMA_DEPTH {
        Err(ConsoleError::BadRequest(
            "input schema nesting exceeds limit".into(),
        ))
    } else {
        Ok(())
    }
}

fn invalid_type(at: &str, kind: &str) -> ConsoleError {
    ConsoleError::BadRequest(format!("{at} must be {kind}"))
}

fn valid_scalar_kind(kind: &str, value: &Value) -> Option<bool> {
    Some(match kind {
        "value" => true,
        "null" => value.is_null(),
        "string" => value.as_str().is_some_and(|s| !s.is_empty()),
        "path" | "path-pattern" => value.as_str().is_some_and(|s| Path::parse(s).is_ok()),
        "operation_id" => value
            .as_str()
            .is_some_and(|s| super::parse_operation_id(s).is_ok()),
        "bool" => value.as_bool().is_some(),
        "u64" => value.as_int().is_some_and(|v| v >= 0),
        "usize" => value.as_int().is_some_and(|v| usize::try_from(v).is_ok()),
        "positive_usize" => value
            .as_int()
            .is_some_and(|v| v > 0 && usize::try_from(v).is_ok()),
        "u8" => value.as_int().is_some_and(|v| u8::try_from(v).is_ok()),
        "u32" => value.as_int().is_some_and(|v| u32::try_from(v).is_ok()),
        "decimal_u64" => {
            value.as_int().is_some_and(|v| v >= 0)
                || value.as_str().is_some_and(|s| {
                    !s.is_empty()
                        && s.bytes().all(|b| b.is_ascii_digit())
                        && s.parse::<u64>().is_ok()
                })
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_contract_is_rejected_before_action_lookup() {
        let registry = DescriptorRegistry::new();
        let mut call = ActionCall {
            action: protocol::ACTION_PROTOCOL_DESCRIBE.into(),
            ..Default::default()
        };
        call.registry_rev = Some(registry.current_rev());
        assert!(validate_call(&registry, &call).is_ok());
        call.registry_rev = Some(registry.current_rev() ^ 1);
        assert!(matches!(
            validate_call(&registry, &call),
            Err(ConsoleError::RegistryChanged { .. })
        ));
        call.action = "removed.action".into();
        assert!(matches!(
            validate_call(&registry, &call),
            Err(ConsoleError::RegistryChanged { .. })
        ));
        call.registry_rev = Some(registry.current_rev());
        assert!(matches!(
            validate_call(&registry, &call),
            Err(ConsoleError::BadRequest(_))
        ));
    }
}

#[cfg(test)]
mod contract_tests {
    use super::super::map_value;
    use super::*;

    #[test]
    fn pairing_expiry_is_optional_and_non_negative() {
        let registry = DescriptorRegistry::new();
        let input = |expiry: Option<Value>| {
            let mut fields = vec![
                ("pairing_id", Value::string("sensor-1".into())),
                ("installation_id", Value::string("sensor-hub".into())),
            ];
            if let Some(expiry) = expiry {
                fields.push(("expires_at", expiry));
            }
            ActionCall {
                action: protocol::ACTION_PAIRING_CREATE.into(),
                input: map_value(fields),
                ..Default::default()
            }
        };
        assert!(validate_call(&registry, &input(None)).is_ok());
        assert!(validate_call(&registry, &input(Some(Value::integer(0)))).is_ok());
        assert!(validate_call(&registry, &input(Some(Value::integer(i64::MAX)))).is_ok());
        assert!(validate_call(&registry, &input(Some(Value::integer(-1)))).is_err());
        assert!(validate_call(&registry, &input(Some(Value::string("1".into())))).is_err());
    }

    #[test]
    fn admission_rejects_unknown_required_and_mistyped_fields_before_dispatch() {
        let registry = DescriptorRegistry::new();
        for input in [
            Value::null(),
            map_value([("path", Value::boolean(true))]),
            map_value([
                ("path", Value::string("state://kernel/x".into())),
                ("expected_version", Value::integer(4)),
            ]),
        ] {
            let call = ActionCall {
                action: protocol::ACTION_CONFIG_READ.into(),
                input,
                ..Default::default()
            };
            assert!(validate_call(&registry, &call).is_err());
        }
    }

    #[test]
    fn snapshot_nested_options_are_validated_before_any_sections_execute() {
        let registry = DescriptorRegistry::new();
        let call = ActionCall {
            action: protocol::ACTION_STATE_SNAPSHOT.into(),
            input: map_value([(
                "sections",
                Value::list(vec![map_value([
                    ("kind", Value::string("sessions".into())),
                    ("limti", Value::integer(1)),
                ])]),
            )]),
            ..Default::default()
        };
        assert!(validate_call(&registry, &call).is_err());
    }

    #[test]
    fn nested_admission_uses_discovered_variants_and_list_limits() -> anyhow::Result<()> {
        use anyhow::{Context, ensure};
        let registry = DescriptorRegistry::new();
        let mut schema = registry
            .action_by_id(protocol::ACTION_STATE_SNAPSHOT)
            .context("snapshot")?
            .input
            .clone();
        let union = schema.definitions.first_mut().context("section union")?;
        ensure!(union.discriminator.as_deref() == Some("kind"));
        let target = union
            .variants
            .remove("sessions")
            .context("sessions variant")?;
        union.variants.insert("sessions_preview".into(), target);
        schema.fields[0].max_items = Some(1);
        let section = map_value([("kind", Value::string("sessions_preview".into()))]);
        let input = |sections| map_value([("sections", Value::list(sections))]);
        validate_input(&schema, &input(vec![section.clone()]))?;
        ensure!(validate_input(&schema, &input(vec![section.clone(), section])).is_err());
        ensure!(
            validate_input(
                &schema,
                &input(vec![map_value([(
                    "kind",
                    Value::string("sessions".into())
                )])])
            )
            .is_err()
        );
        let malformed = input(vec![map_value([
            ("kind", Value::string("runtime".into())),
            ("include_recent_facts", Value::string("yes".into())),
        ])]);
        let error = validate_input(&schema, &malformed)
            .err()
            .context("nested type error")?;
        ensure!(
            error
                .to_string()
                .contains("input.sections[0].include_recent_facts")
        );
        Ok(())
    }

    #[test]
    fn executable_descriptors_have_resolvable_input_contracts() -> anyhow::Result<()> {
        use anyhow::{Context, ensure};
        fn check_kind(kind: &str, definitions: &[&SchemaDescriptor]) -> anyhow::Result<()> {
            if let Some(inner) = kind.strip_suffix("|null") {
                return check_kind(inner, definitions);
            }
            if let Some(inner) = kind.strip_prefix("list<").and_then(|s| s.strip_suffix('>')) {
                return check_kind(inner, definitions);
            }
            ensure!(
                valid_scalar_kind(kind, &Value::null()).is_some()
                    || resolve_schema(definitions, kind).is_some(),
                "unresolved kind: {kind}"
            );
            Ok(())
        }
        fn check_schema(
            schema: &SchemaDescriptor,
            inherited: &[&SchemaDescriptor],
        ) -> anyhow::Result<()> {
            let definitions: Vec<_> = inherited
                .iter()
                .copied()
                .chain(&schema.definitions)
                .collect();
            ensure!(matches!(schema.value_kind.as_str(), "map" | "null"));
            let mut ids = std::collections::BTreeSet::new();
            for definition in &schema.definitions {
                ensure!(ids.insert(&definition.schema_id), "duplicate definition");
                check_schema(definition, &definitions)?;
            }
            let mut fields = std::collections::BTreeSet::new();
            for field in &schema.fields {
                ensure!(fields.insert(&field.name), "duplicate input field");
                check_kind(&field.kind, &definitions)?;
                ensure!(field.max_items.is_none() || field.kind.starts_with("list<"));
            }
            if let Some(discriminator) = &schema.discriminator {
                ensure!(!schema.variants.is_empty());
                for variant in schema.variants.values() {
                    let variant = resolve_schema(&definitions, variant)
                        .context("missing variant definition")?;
                    ensure!(
                        variant
                            .fields
                            .iter()
                            .any(|field| &field.name == discriminator
                                && field.required
                                && field.kind == "string")
                    );
                }
            } else {
                ensure!(schema.variants.is_empty());
            }
            Ok(())
        }
        for action in protocol::action_descriptors() {
            check_schema(&action.input, &[]).with_context(|| action.id.clone())?;
        }
        for stream in protocol::stream_descriptors() {
            check_schema(&stream.input, &[]).with_context(|| stream.id.clone())?;
        }
        Ok(())
    }
}
