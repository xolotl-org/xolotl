//! Daemon-owned admission for installed kernel configuration documents.

use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use thiserror::Error;
use xolotl_console::ConfigNamespaceAdmission;
use xolotl_gateway::{GatewayProfileDocument, gateway_profile_id};
use xolotl_types::external::ManifestDef;
use xolotl_types::in_process_projection::{
    InProcessProjectionDef, in_process_projection_declaration_id,
};
use xolotl_types::inference::{
    InferenceBackendDef, InferenceDeclarationKind, InferenceGroupDef, InferenceModelDef,
    InferenceRoutingDef,
};
use xolotl_types::{Path, TrustLevel, Value, ValueView};

/// Assemble the declaration owners installed by the stock daemon. Other hosts
/// can register their own namespaces without changing Console.
pub(crate) fn console_config_admissions() -> anyhow::Result<Vec<ConfigNamespaceAdmission>> {
    [
        "state://kernel/gateway/profiles",
        "state://kernel/manifests",
        "state://kernel/projections/in-process",
        "state://kernel/inference",
        "state://kernel/routing/inference",
    ]
    .into_iter()
    .map(|namespace| {
        Ok(ConfigNamespaceAdmission::new(
            Path::parse(namespace)?,
            |path, value| admit_kernel_config(path, value).map_err(public_error),
        ))
    })
    .collect()
}

/// Errors raised by shared kernel config admission.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum KernelConfigAdmissionError {
    /// The path was not a local kernel state path.
    #[error("path is not a state://kernel path: {0}")]
    NotKernelState(String),
    /// A namespace owner did not recognize a child path.
    #[error("no daemon config admission rule for {0}")]
    UnknownPath(String),
    /// A required path segment was missing.
    #[error("missing {0}")]
    MissingSegment(&'static str),
    /// A value could not be decoded as the expected config declaration.
    #[error("{label} is malformed: {message}")]
    Decode {
        /// Expected declaration type.
        label: &'static str,
        /// Decode error message.
        message: String,
    },
    /// A declaration field did not match the state path.
    #[error("{label}.{field} {value:?} does not match path segment {path:?}")]
    PathMismatch {
        /// Declaration type.
        label: &'static str,
        /// Field name.
        field: &'static str,
        /// Value from the declaration.
        value: String,
        /// Value from the path.
        path: String,
    },
    /// A declaration failed its own admission rule.
    #[error("{label} admission failed: {message}")]
    Rejected {
        /// Declaration type.
        label: &'static str,
        /// Rejection message.
        message: String,
    },
}

/// Admit a shared kernel config declaration.
///
/// Console-owned paths such as `state://kernel/console/*` are intentionally
/// left to the console crate.
pub fn admit_kernel_config(path: &Path, value: &Value) -> Result<(), KernelConfigAdmissionError> {
    let segs = path.segments();
    if path.scheme() != "state"
        || path.cluster().is_some()
        || segs.first().map(|s| s.as_str()) != Some("kernel")
    {
        return Err(KernelConfigAdmissionError::NotKernelState(path.to_string()));
    }

    // The namespace pair selects the declaration family, including malformed
    // children. Each owner then checks the exact, local, direct-child address.
    // A failed check must not fall through as an unrelated config path.
    let namespace = segs.get(1).map(|segment| segment.as_str());
    let collection = segs.get(2).map(|segment| segment.as_str());
    match (namespace, collection) {
        (Some("gateway"), Some("profiles")) => {
            let name = gateway_profile_id(path)
                .ok_or_else(|| invalid_declaration_path("GatewayProfileDocument", path))?;
            admit_gateway_profile(name, value)?;
            Ok(())
        }
        (Some("manifests"), _) => {
            let platform = segs
                .get(2)
                .ok_or(KernelConfigAdmissionError::MissingSegment(
                    "manifest platform",
                ))?
                .as_str();
            if segs.len() != 3 || !xolotl_types::path::is_simple_id_segment(platform) {
                return Err(invalid_declaration_path("ManifestDef", path));
            }
            admit_manifest(platform, value)?;
            Ok(())
        }
        (Some("projections"), Some("in-process")) => {
            let id = in_process_projection_declaration_id(path)
                .ok_or_else(|| invalid_declaration_path("InProcessProjectionDef", path))?;
            admit_in_process_projection(id, value)?;
            Ok(())
        }
        (Some("inference"), Some("backends")) => {
            let id = InferenceDeclarationKind::Backend
                .id(path)
                .ok_or_else(|| invalid_declaration_path("InferenceBackendDef", path))?;
            admit_inference_backend(id, value)?;
            Ok(())
        }
        (Some("inference"), Some("models")) => {
            let id = InferenceDeclarationKind::Model
                .id(path)
                .ok_or_else(|| invalid_declaration_path("InferenceModelDef", path))?;
            admit_inference_model(id, value)?;
            Ok(())
        }
        (Some("inference"), Some("groups")) => {
            let name = InferenceDeclarationKind::Group
                .id(path)
                .ok_or_else(|| invalid_declaration_path("InferenceGroupDef", path))?;
            admit_inference_group(name, value)?;
            Ok(())
        }
        (Some("routing"), Some("inference")) if segs.len() == 3 => {
            admit_inference_routing(value)?;
            Ok(())
        }
        (Some("routing"), Some("inference")) => {
            Err(invalid_declaration_path("InferenceRoutingDef", path))
        }
        _ => Err(KernelConfigAdmissionError::UnknownPath(path.to_string())),
    }
}

// Do not reflect document contents or serde values through Console failures.
fn public_error(error: KernelConfigAdmissionError) -> String {
    match error {
        KernelConfigAdmissionError::NotKernelState(_) => "invalid kernel config path".into(),
        KernelConfigAdmissionError::UnknownPath(_) => "unknown kernel config path".into(),
        KernelConfigAdmissionError::MissingSegment(label) => format!("missing {label}"),
        KernelConfigAdmissionError::Decode { label, .. } => format!("{label} is malformed"),
        KernelConfigAdmissionError::PathMismatch { label, field, .. } => {
            format!("{label}.{field} does not match the config path")
        }
        KernelConfigAdmissionError::Rejected { label, .. } => {
            format!("{label} admission failed")
        }
    }
}

fn invalid_declaration_path(label: &'static str, path: &Path) -> KernelConfigAdmissionError {
    rejected(label, format!("invalid direct declaration path {path}"))
}

fn decode_config_value<T: DeserializeOwned>(
    value: &Value,
    label: &'static str,
) -> Result<T, KernelConfigAdmissionError> {
    let json = serde_json::to_value(value).map_err(|error| KernelConfigAdmissionError::Decode {
        label,
        message: error.to_string(),
    })?;
    serde_json::from_value(json).map_err(|error| KernelConfigAdmissionError::Decode {
        label,
        message: error.to_string(),
    })
}

fn admit_gateway_profile(path_name: &str, value: &Value) -> Result<(), KernelConfigAdmissionError> {
    let document: GatewayProfileDocument = decode_config_value(value, "GatewayProfileDocument")?;
    ensure_path_match(
        "GatewayProfileDocument",
        "profile_name",
        document.profile_name(),
        path_name,
    )?;
    document
        .validate_admission(path_name)
        .map_err(|error| rejected("GatewayProfileDocument", error.to_string()))
}

fn admit_manifest(path_platform: &str, value: &Value) -> Result<(), KernelConfigAdmissionError> {
    let def: ManifestDef = decode_config_value(value, "ManifestDef")?;
    ensure_path_match("ManifestDef", "platform", &def.platform, path_platform)?;
    if def.platform.trim().is_empty() {
        return Err(rejected("ManifestDef", "platform must not be empty"));
    }
    if def.version == 0 {
        return Err(rejected(
            "ManifestDef",
            "version must be a positive config revision",
        ));
    }
    admit_json_schema(&def.config_schema, "ManifestDef.config_schema")?;
    if def.supported_transports.is_empty() {
        return Err(rejected(
            "ManifestDef",
            "supported_transports must not be empty",
        ));
    }
    if !def
        .supported_transports
        .iter()
        .any(|transport| transport == &def.default_transport)
    {
        return Err(rejected(
            "ManifestDef",
            "default_transport must be listed in supported_transports",
        ));
    }
    if def.projections.is_empty() {
        return Err(rejected("ManifestDef", "projections must not be empty"));
    }
    let mut seen = BTreeSet::new();
    for projection in &def.projections {
        if !seen.insert(projection.id.clone()) {
            return Err(rejected(
                "ManifestDef",
                format!("duplicate projection id {:?}", projection.id),
            ));
        }
        projection
            .validate_admission(&def.platform, TrustLevel::Sandboxed, &def.default_transport)
            .map_err(|error| KernelConfigAdmissionError::Rejected {
                label: "ManifestDef",
                message: format!("projection admission failed: {error}"),
            })?;
        for cap in &projection.provides {
            admit_manifest_effect(&cap.effect_path)?;
        }
    }
    Ok(())
}

fn admit_in_process_projection(
    path_id: &str,
    value: &Value,
) -> Result<(), KernelConfigAdmissionError> {
    let def: InProcessProjectionDef = decode_config_value(value, "InProcessProjectionDef")?;
    def.validate_admission(path_id)
        .map_err(|error| KernelConfigAdmissionError::Rejected {
            label: "InProcessProjectionDef",
            message: error.to_string(),
        })
}

fn admit_inference_backend(path_id: &str, value: &Value) -> Result<(), KernelConfigAdmissionError> {
    let def: InferenceBackendDef = decode_config_value(value, "InferenceBackendDef")?;
    def.validate_admission(path_id)
        .map_err(|error| KernelConfigAdmissionError::Rejected {
            label: "InferenceBackendDef",
            message: error.to_string(),
        })
}

fn admit_inference_model(path_id: &str, value: &Value) -> Result<(), KernelConfigAdmissionError> {
    let def: InferenceModelDef = decode_config_value(value, "InferenceModelDef")?;
    def.validate_admission(path_id)
        .map_err(|error| KernelConfigAdmissionError::Rejected {
            label: "InferenceModelDef",
            message: error.to_string(),
        })
}

fn admit_inference_group(path_name: &str, value: &Value) -> Result<(), KernelConfigAdmissionError> {
    let def: InferenceGroupDef = decode_config_value(value, "InferenceGroupDef")?;
    def.validate_admission(path_name)
        .map_err(|error| KernelConfigAdmissionError::Rejected {
            label: "InferenceGroupDef",
            message: error.to_string(),
        })
}

fn admit_inference_routing(value: &Value) -> Result<(), KernelConfigAdmissionError> {
    let def: InferenceRoutingDef = decode_config_value(value, "InferenceRoutingDef")?;
    def.validate_admission()
        .map_err(|error| KernelConfigAdmissionError::Rejected {
            label: "InferenceRoutingDef",
            message: error.to_string(),
        })
}

fn ensure_path_match(
    label: &'static str,
    field: &'static str,
    value: &str,
    path: &str,
) -> Result<(), KernelConfigAdmissionError> {
    if value == path {
        Ok(())
    } else {
        Err(KernelConfigAdmissionError::PathMismatch {
            label,
            field,
            value: value.to_string(),
            path: path.to_string(),
        })
    }
}

fn admit_json_schema(
    schema: &Value,
    label: &'static str,
) -> Result<(), KernelConfigAdmissionError> {
    match schema.view() {
        ValueView::Null | ValueView::Map(_) => Ok(()),
        _ => Err(rejected(label, "must be null or a JSON object")),
    }
}

fn admit_manifest_effect(effect_path: &str) -> Result<(), KernelConfigAdmissionError> {
    let effect =
        Path::parse(effect_path).map_err(|error| KernelConfigAdmissionError::Rejected {
            label: "ManifestDef",
            message: format!("projection effect path is malformed: {error}"),
        })?;
    if effect.scheme() != "effect" || effect.segments().is_empty() {
        return Err(rejected(
            "ManifestDef",
            "projection effects must be effect:// paths",
        ));
    }
    if effect.segments().first().map(|s| s.as_str()) == Some("kernel") {
        return Err(rejected(
            "ManifestDef",
            "projection effects must not target effect://kernel/*",
        ));
    }
    Ok(())
}

fn rejected(label: &'static str, message: impl Into<String>) -> KernelConfigAdmissionError {
    KernelConfigAdmissionError::Rejected {
        label,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use xolotl_types::{EffectCapability, Purity, Role};

    fn value_from(value: &impl serde::Serialize) -> anyhow::Result<Value> {
        Ok(serde_json::from_value(serde_json::to_value(value)?)?)
    }

    #[test]
    fn stock_host_installs_all_declaration_owners() -> anyhow::Result<()> {
        let owners = console_config_admissions()?;
        let inference = Path::parse("state://kernel/inference")?;
        ensure!(owners.len() == 5);
        ensure!(owners.iter().any(|owner| owner.namespace() == &inference));
        Ok(())
    }

    #[test]
    fn gateway_profile_is_validated_against_its_path() -> anyhow::Result<()> {
        let profile = value_from(&serde_json::json!({
            "profile_name": "app", "version": 1,
            "surfaces": [{"surface_id": "inspect", "target": "effect://blob/stat"}]
        }))?;
        admit_kernel_config(
            &Path::parse("state://kernel/gateway/profiles/app")?,
            &profile,
        )?;
        ensure!(matches!(
            admit_kernel_config(
                &Path::parse("state://kernel/gateway/profiles/other")?,
                &profile
            ),
            Err(KernelConfigAdmissionError::PathMismatch { .. })
        ));
        Ok(())
    }

    #[test]
    fn projection_and_routing_documents_keep_their_owner_checks() -> anyhow::Result<()> {
        let projection = value_from(&InProcessProjectionDef {
            id: "fetch".into(),
            role: Role::Provider,
            implementation: "standard.fetch".into(),
            provides: vec![EffectCapability::new(
                "effect://fetch/get",
                Purity::Effectful,
            )],
            emits: None,
            config: Value::null(),
            version: 1,
        })?;
        admit_kernel_config(
            &Path::parse("state://kernel/projections/in-process/fetch")?,
            &projection,
        )?;
        ensure!(
            admit_kernel_config(
                &Path::parse("state://kernel/projections/in-process/other")?,
                &projection
            )
            .is_err()
        );
        let routing = value_from(&InferenceRoutingDef {
            default_group: "primary".into(),
            max_retries: None,
            version: 1,
        })?;
        admit_kernel_config(&Path::parse("state://kernel/routing/inference")?, &routing)?;
        ensure!(
            admit_kernel_config(
                &Path::parse("state://kernel/routing/inference/extra")?,
                &routing
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn unknown_children_and_invalid_documents_fail_closed_without_echoing_values()
    -> anyhow::Result<()> {
        ensure!(matches!(
            admit_kernel_config(
                &Path::parse("state://kernel/inference/unknown/x")?,
                &Value::null()
            ),
            Err(KernelConfigAdmissionError::UnknownPath(_))
        ));
        ensure!(matches!(
            admit_kernel_config(
                &Path::parse("state://kernel/manifests/bad.id")?,
                &Value::null()
            ),
            Err(KernelConfigAdmissionError::Rejected { .. })
        ));
        let message = public_error(KernelConfigAdmissionError::Decode {
            label: "ManifestDef",
            message: "secret-value".into(),
        });
        ensure!(!message.contains("secret-value"));
        Ok(())
    }
}
