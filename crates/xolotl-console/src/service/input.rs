//! Request arguments and response projections shared by management domains.

use super::*;
use crate::auth::SessionSummary;
use serde::Serialize;
use xolotl_types::{ExternalInstallationDef, OperationId, ValueMap, ValueView};

pub(crate) fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub(crate) fn entries_value(page: mgmt::ManagementPage) -> Value {
    map_value([
        (
            "next_cursor",
            page.next_cursor.map(Value::string).unwrap_or(Value::null()),
        ),
        (
            "entries",
            Value::list(
                page.entries
                    .into_iter()
                    .map(|(path, value)| {
                        let mut m = BTreeMap::new();
                        m.insert("path".into(), Value::string(path));
                        m.insert("value".into(), value);
                        Value::map(m)
                    })
                    .collect(),
            ),
        ),
    ])
}

pub(crate) fn list_request(input: &Value) -> Result<mgmt::ListRequest, ConsoleError> {
    let mut input = input_map(input.clone())?;
    Ok(mgmt::ListRequest {
        limit: optional_usize_arg(&mut input, "limit")?,
        cursor: optional_string_arg(&mut input, "cursor")?,
        max_bytes: optional_usize_arg(&mut input, "max_bytes")?,
    })
}

pub(crate) fn sessions_value(sessions: &[SessionSummary]) -> Value {
    Value::list(
        sessions
            .iter()
            .map(|s| {
                let mut m = BTreeMap::new();
                m.insert("sid".into(), Value::string(s.sid.clone()));
                m.insert("username".into(), Value::string(s.username.clone()));
                m.insert(
                    "identity_path".into(),
                    Value::string(s.identity_path.clone()),
                );
                m.insert("issued_at".into(), Value::integer(s.issued_at));
                m.insert("authentication".into(), s.authentication.to_value());
                m.insert(
                    "authenticated_at".into(),
                    s.authentication
                        .authenticated_at()
                        .map_or(Value::null(), Value::integer),
                );
                m.insert("expires_at".into(), Value::integer(s.expires_at));
                m.insert("idle_expires_at".into(), Value::integer(s.idle_expires_at));
                m.insert(
                    "mfa_level".into(),
                    Value::integer(s.authentication.mfa_level() as i64),
                );
                m.insert("last_seen".into(), Value::integer(s.last_seen));
                m.insert("source_addr".into(), Value::string(s.source_addr.clone()));
                Value::map(m)
            })
            .collect(),
    )
}

pub(crate) fn registry_counts_value(counts: xolotl_kernel::registry::RegistryCounts) -> Value {
    map_value([
        ("resources", Value::integer(counts.resources as i64)),
        ("interfaces", Value::integer(counts.interfaces as i64)),
        ("drivers", Value::integer(counts.drivers as i64)),
        ("endpoints", Value::integer(counts.endpoints as i64)),
        ("bindings", Value::integer(counts.bindings as i64)),
        ("grants", Value::integer(counts.grants as i64)),
        ("policies", Value::integer(counts.policies as i64)),
        ("names", Value::integer(counts.names as i64)),
        (
            "open_cache_entries",
            Value::integer(counts.open_cache_entries as i64),
        ),
        (
            "open_cache_hits",
            Value::integer(counts.open_cache_hits as i64),
        ),
        (
            "open_cache_misses",
            Value::integer(counts.open_cache_misses as i64),
        ),
    ])
}

pub(crate) fn validate_path_segment(raw: &str, label: &str) -> Result<(), ConsoleError> {
    if !xolotl_types::path::is_simple_id_segment(raw) {
        return Err(ConsoleError::BadRequest(format!("invalid {label}")));
    }
    Ok(())
}

pub(crate) fn reject_secret_fields(input: &Value) -> Result<(), ConsoleError> {
    use std::collections::BTreeSet;
    use xolotl_types::value::traversal::{ValueNodeKey, ValuePostorder};
    if !matches!(input.view(), ValueView::Map(_) | ValueView::List(_)) {
        return Ok(());
    }
    let denied = ["pairing_secret", "secret", "raw_secret", "sas_verified"];
    let mut visited = BTreeSet::new();
    let mut walk = ValuePostorder::new(input);
    while let Some(node) = walk.next(|key| visited.contains(&key)) {
        if let Some(map) = node.as_map() {
            for key in map.keys() {
                if denied.contains(&key) {
                    return Err(ConsoleError::BadRequest(format!(
                        "{key} is not accepted in console pairing input"
                    )));
                }
            }
        }
        visited.insert(ValueNodeKey::of(node));
    }
    Ok(())
}

pub(crate) fn map_value(items: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::map(
        items
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

pub(crate) fn serde_value<T: Serialize>(value: T) -> Result<Value, ConsoleError> {
    let json = serde_json::to_value(value).map_err(|error| {
        ConsoleError::Operation(format!(
            "console value projection serialization failed: {error}"
        ))
    })?;
    serde_json::from_value(json).map_err(|error| {
        ConsoleError::Operation(format!(
            "console value projection conversion failed: {error}"
        ))
    })
}

pub(crate) fn input_value(input: &Value) -> Result<Value, ConsoleError> {
    Ok(input.clone())
}

pub(crate) fn input_map(input: Value) -> Result<ValueMap, ConsoleError> {
    if input.is_null() {
        return Ok(ValueMap::new());
    }
    input
        .into_map()
        .ok_or_else(|| ConsoleError::BadRequest("console action input must be a map".into()))
}

pub(crate) fn string_arg(input: &mut ValueMap, name: &str) -> Result<String, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Str(s)) if !s.is_empty() => Ok(s.to_owned()),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a non-empty string"
        ))),
        None => Err(ConsoleError::BadRequest(format!("{name} is required"))),
    }
}

pub(crate) fn optional_string_arg(
    input: &mut ValueMap,
    name: &str,
) -> Result<Option<String>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Null) | None => Ok(None),
        Some(ValueView::Str(s)) if !s.is_empty() => Ok(Some(s.to_owned())),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a non-empty string"
        ))),
    }
}

pub(crate) fn value_arg(input: &mut ValueMap, name: &str) -> Result<Value, ConsoleError> {
    input
        .remove(name)
        .ok_or_else(|| ConsoleError::BadRequest(format!("{name} is required")))
}

pub(crate) fn parse_operation_id(raw: &str) -> Result<OperationId, ConsoleError> {
    raw.parse()
        .map_err(|error| ConsoleError::BadRequest(format!("invalid op_id: {error}")))
}

pub(crate) fn optional_u64_arg(
    input: &mut ValueMap,
    name: &str,
) -> Result<Option<u64>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Null) | None => Ok(None),
        Some(ValueView::Int(i)) if i >= 0 => Ok(Some(i as u64)),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a non-negative integer"
        ))),
    }
}

pub(crate) fn optional_i64_arg(
    input: &mut ValueMap,
    name: &str,
) -> Result<Option<i64>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Null) | None => Ok(None),
        Some(ValueView::Int(i)) => Ok(Some(i)),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be an integer"
        ))),
    }
}

pub(crate) fn optional_usize_arg(
    input: &mut ValueMap,
    name: &str,
) -> Result<Option<usize>, ConsoleError> {
    optional_u64_arg(input, name)?
        .map(|v| {
            usize::try_from(v)
                .map_err(|_error| ConsoleError::BadRequest(format!("{name} is too large")))
        })
        .transpose()
}

pub(crate) fn validate_external_installation_def(
    id: &str,
    value: &Value,
    source_admission: Option<&dyn xolotl_source::SourceDeclarationAdmission>,
) -> Result<ExternalInstallationDef, ConsoleError> {
    let json = serde_json::to_value(value).map_err(|e| {
        ConsoleError::BadRequest(format!("ExternalInstallationDef serialization failed: {e}"))
    })?;
    let def: ExternalInstallationDef = serde_json::from_value(json).map_err(|e| {
        ConsoleError::BadRequest(format!("ExternalInstallationDef is malformed: {e}"))
    })?;
    if def.id != id {
        return Err(ConsoleError::BadRequest(
            "ExternalInstallationDef id does not match requested installation id".into(),
        ));
    }
    def.validate_admission().map_err(|e| {
        ConsoleError::BadRequest(format!("ExternalInstallationDef admission failed: {e}"))
    })?;
    validate_source_installation(&def, source_admission)?;
    Ok(def)
}

pub(crate) fn validate_source_installation(
    def: &ExternalInstallationDef,
    source_admission: Option<&dyn xolotl_source::SourceDeclarationAdmission>,
) -> Result<(), ConsoleError> {
    for projection in &def.projections {
        let Some(source) = projection.emits.as_ref() else {
            continue;
        };
        let admission = source_admission.ok_or_else(|| {
            ConsoleError::BadRequest("Source declaration admission is not installed".into())
        })?;
        admission
            .validate_source(&def.id, &projection.id, source)
            .map_err(|error| {
                ConsoleError::BadRequest(format!(
                    "Source projection {:?} admission failed: {error}",
                    projection.id
                ))
            })?;
    }
    Ok(())
}

pub(crate) fn optional_bool_arg(
    input: &mut ValueMap,
    name: &str,
) -> Result<Option<bool>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::Null) | None => Ok(None),
        Some(ValueView::Bool(b)) => Ok(Some(b)),
        Some(_) => Err(ConsoleError::BadRequest(format!("{name} must be a bool"))),
    }
}

pub(crate) fn string_list_arg(
    input: &mut ValueMap,
    name: &str,
) -> Result<Vec<String>, ConsoleError> {
    match input.remove(name).as_ref().map(Value::view) {
        Some(ValueView::List(items)) => items
            .iter()
            .map(|item| match item.view() {
                ValueView::Str(s) if !s.is_empty() => Ok(s.to_owned()),
                _ => Err(ConsoleError::BadRequest(format!(
                    "{name} must be a list of non-empty strings"
                ))),
            })
            .collect(),
        Some(_) => Err(ConsoleError::BadRequest(format!(
            "{name} must be a list of strings"
        ))),
        None => Err(ConsoleError::BadRequest(format!("{name} is required"))),
    }
}

pub(crate) fn exact_resource_selector(
    verb: &str,
    path: &Path,
) -> Result<xolotl_types::ResourceSelector, xolotl_types::CapError> {
    let pattern = xolotl_types::Capability::try_new(
        verb,
        path.scheme(),
        path.segments().iter().map(|segment| segment.as_str()),
        None,
    )?;
    let pattern = if let Some(cluster) = path.cluster() {
        pattern.try_with_cluster(cluster)?
    } else {
        pattern
    };
    Ok(xolotl_types::ResourceSelector { pattern })
}

pub(crate) fn bearer_sid(bearer: Option<&str>) -> Option<&str> {
    bearer?.split_once('.').map(|(sid, _)| sid)
}

#[cfg(test)]
mod path_tests {
    use super::*;

    #[test]
    fn named_management_ids_follow_the_type_admission_rule() -> anyhow::Result<()> {
        for id in ["_bridge", "-bridge"] {
            anyhow::ensure!(external_installation_path(id).is_err());
            anyhow::ensure!(inference_backend_path(id).is_err());
            anyhow::ensure!(projection_status_path(id).is_err());
        }
        anyhow::ensure!(external_installation_path("bridge_1")?.ends_with("/bridge_1"));
        Ok(())
    }
}

#[cfg(test)]
mod source_admission_tests {
    use super::*;
    use xolotl_types::external::{
        EventSource, ExternalProjectionDef, OverflowPolicy, SourceRateLimit, StreamCapacity,
        Transport, TrustLevel,
    };
    use xolotl_types::{Path, Purity, Role};

    fn source_installation() -> anyhow::Result<ExternalInstallationDef> {
        Ok(ExternalInstallationDef {
            id: "bridge".into(),
            platform: "test".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Full,
            config_schema: Value::null(),
            config: Value::null(),
            projections: vec![ExternalProjectionDef {
                id: "source".into(),
                role: Role::Source,
                namespace: None,
                provides: Vec::new(),
                emits: Some(EventSource {
                    sink: Path::parse("state://events/bridge/source")?,
                    purity: Purity::Effectful,
                    event_schema: None,
                    max_inline_payload_bytes: 1024,
                    capacity: StreamCapacity {
                        max_events: 10,
                        on_overflow: OverflowPolicy::DropOldest,
                    },
                    rate_limit: None,
                    commands: false,
                    command_schema: None,
                    command_result_schema: None,
                }),
                version: 1,
            }],
            version: 1,
        })
    }

    fn validate(
        def: &ExternalInstallationDef,
        admission: Option<&dyn xolotl_source::SourceDeclarationAdmission>,
    ) -> anyhow::Result<Result<(), ConsoleError>> {
        let value = serde_json::from_value(serde_json::to_value(def)?)?;
        Ok(validate_external_installation_def(&def.id, &value, admission).map(|_| ()))
    }

    #[test]
    fn source_installation_checks_the_installed_storage_owner() -> anyhow::Result<()> {
        let storage = xolotl_state::InMemoryBackend::new();
        let mut def = source_installation()?;
        anyhow::ensure!(matches!(
            validate(&def, None)?,
            Err(ConsoleError::BadRequest(_))
        ));
        anyhow::ensure!(validate(&def, Some(&storage))?.is_ok());

        def.projections[0]
            .emits
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("source declaration missing"))?
            .rate_limit = Some(SourceRateLimit {
            window_ms: 1000,
            max_events: 65_537,
        });
        anyhow::ensure!(matches!(
            validate(&def, Some(&storage))?,
            Err(ConsoleError::BadRequest(_))
        ));

        def.projections[0]
            .emits
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("source declaration missing"))?
            .rate_limit = None;
        def.id = "b".repeat(257);
        anyhow::ensure!(matches!(
            validate(&def, Some(&storage))?,
            Err(ConsoleError::BadRequest(_))
        ));
        Ok(())
    }

    struct WiderSourceStore;

    impl xolotl_source::SourceDeclarationAdmission for WiderSourceStore {
        fn validate_source(
            &self,
            _installation_id: &str,
            _projection_id: &str,
            _source: &EventSource,
        ) -> Result<(), xolotl_source::SourceAdmissionError> {
            Ok(())
        }
    }

    #[test]
    fn a_custom_source_store_can_accept_wider_declarations() -> anyhow::Result<()> {
        let mut def = source_installation()?;
        def.projections[0]
            .emits
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("source declaration missing"))?
            .rate_limit = Some(SourceRateLimit {
            window_ms: 1000,
            max_events: 65_537,
        });
        anyhow::ensure!(validate(&def, Some(&WiderSourceStore))?.is_ok());
        Ok(())
    }
}
