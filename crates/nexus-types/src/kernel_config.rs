//! Admission for declared `state://kernel/*` runtime configuration.

use crate::external::{ExternalInstallationDef, ManifestDef};
use crate::in_process_projection::InProcessProjectionDef;
use crate::inference::{
    InferenceBackendDef, InferenceGroupDef, InferenceModelDef, InferenceRoutingDef,
};
use crate::{Path, TrustLevel, Value};
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;
use thiserror::Error;

/// Result of checking a kernel config path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelConfigAdmission {
    /// The path is known and the value passed admission.
    Admitted,
    /// The path is not handled by this shared registry.
    Unhandled,
}

/// Errors raised by shared kernel config admission.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum KernelConfigAdmissionError {
    /// The path was not a local kernel state path.
    #[error("path is not a state://kernel path: {0}")]
    NotKernelState(String),
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
pub fn admit_kernel_config(
    path: &Path,
    value: &Value,
) -> Result<KernelConfigAdmission, KernelConfigAdmissionError> {
    let segs = path.segments();
    if path.scheme() != "state" || segs.first().map(|s| s.as_str()) != Some("kernel") {
        return Err(KernelConfigAdmissionError::NotKernelState(path.to_string()));
    }

    match segs {
        s if is_path(s, &["kernel", "external-installations"]) => {
            let id = required_tail(s, "external installation id")?;
            admit_external_installation(id, value)?;
            Ok(KernelConfigAdmission::Admitted)
        }
        s if is_path(s, &["kernel", "manifests"]) => {
            let platform = required_tail(s, "manifest platform")?;
            admit_manifest(platform, value)?;
            Ok(KernelConfigAdmission::Admitted)
        }
        s if is_path(s, &["kernel", "projections", "in-process"]) => {
            let id = required_tail(s, "in-process projection id")?;
            admit_in_process_projection(id, value)?;
            Ok(KernelConfigAdmission::Admitted)
        }
        s if is_path(s, &["kernel", "inference", "backends"]) => {
            let id = required_tail(s, "inference backend id")?;
            admit_inference_backend(id, value)?;
            Ok(KernelConfigAdmission::Admitted)
        }
        s if is_path(s, &["kernel", "inference", "models"]) => {
            let id = required_tail(s, "inference model id")?;
            admit_inference_model(id, value)?;
            Ok(KernelConfigAdmission::Admitted)
        }
        s if is_path(s, &["kernel", "inference", "groups"]) => {
            let name = required_tail(s, "inference group name")?;
            admit_inference_group(name, value)?;
            Ok(KernelConfigAdmission::Admitted)
        }
        s if is_exact_path(s, &["kernel", "routing", "inference"]) => {
            admit_inference_routing(value)?;
            Ok(KernelConfigAdmission::Admitted)
        }
        _ => Ok(KernelConfigAdmission::Unhandled),
    }
}

fn is_path<S: AsRef<str>>(segs: &[S], prefix: &[&str]) -> bool {
    segs.len() == prefix.len() + 1
        && segs
            .iter()
            .take(prefix.len())
            .zip(prefix.iter())
            .all(|(actual, expected)| actual.as_ref() == *expected)
}

fn is_exact_path<S: AsRef<str>>(segs: &[S], expected: &[&str]) -> bool {
    segs.len() == expected.len()
        && segs
            .iter()
            .zip(expected.iter())
            .all(|(actual, expected)| actual.as_ref() == *expected)
}

fn required_tail<'a, S: AsRef<str>>(
    segs: &'a [S],
    label: &'static str,
) -> Result<&'a str, KernelConfigAdmissionError> {
    segs.last()
        .map(|s| s.as_ref())
        .filter(|s| !s.is_empty())
        .ok_or(KernelConfigAdmissionError::MissingSegment(label))
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

fn admit_external_installation(
    path_id: &str,
    value: &Value,
) -> Result<(), KernelConfigAdmissionError> {
    let def: ExternalInstallationDef = decode_config_value(value, "ExternalInstallationDef")?;
    ensure_path_match("ExternalInstallationDef", "id", &def.id, path_id)?;
    admit_json_schema(&def.config_schema, "ExternalInstallationDef.config_schema")?;
    def.validate_admission()
        .map_err(|error| KernelConfigAdmissionError::Rejected {
            label: "ExternalInstallationDef",
            message: error.to_string(),
        })
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
    match schema {
        Value::Null | Value::Map(_) => Ok(()),
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
    use crate::external::ExternalProjectionDef;
    use crate::{
        EffectCapability, InProcessProjectionDef, InferenceApiDialect, InferenceAuthRef, Purity,
        Role, Transport,
    };
    use anyhow::{Context, Result, bail, ensure};
    use std::collections::BTreeMap;

    fn path(value: &str) -> Result<Path> {
        Path::parse(value).with_context(|| format!("parse {value}"))
    }

    fn value_from<T: serde::Serialize>(value: &T) -> Result<Value> {
        let json = serde_json::to_value(value).context("serialize value")?;
        serde_json::from_value(json).context("convert value")
    }

    fn backend(id: &str) -> Result<Value> {
        value_from(&InferenceBackendDef {
            id: id.into(),
            dialect: InferenceApiDialect::OpenAiChatCompletions,
            base_url: "https://api.deepseek.com".into(),
            auth: InferenceAuthRef::BearerToken {
                token_ref: path("state://vault/inference/deepseek/api_key")?,
            },
            default_headers: BTreeMap::new(),
            request_overrides: BTreeMap::new(),
            api_version: None,
            version: 1,
        })
    }

    fn installation(id: &str) -> Result<Value> {
        value_from(&ExternalInstallationDef {
            id: id.into(),
            platform: id.into(),
            transport: Transport::Stdio {
                command: Some(format!("{id}-plugin")),
                args: Vec::new(),
            },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![ExternalProjectionDef {
                id: "provider".into(),
                role: Role::Provider,
                namespace: Some(path(&format!("effect://external-provider/{id}"))?),
                provides: vec![EffectCapability::new(
                    format!("effect://external-provider/{id}/search"),
                    Purity::Idempotent,
                )],
                emits: None,
                version: 1,
            }],
            version: 1,
        })
    }

    fn in_process_projection(id: &str) -> Result<Value> {
        value_from(&InProcessProjectionDef {
            id: id.into(),
            role: Role::Provider,
            implementation: "standard.fetch".into(),
            provides: vec![EffectCapability::new(
                "effect://fetch/get",
                Purity::Effectful,
            )],
            emits: None,
            config: Value::Null,
            version: 1,
        })
    }

    #[test]
    fn admits_inference_backend_declaration() -> Result<()> {
        let result = admit_kernel_config(
            &path("state://kernel/inference/backends/deepseek")?,
            &backend("deepseek")?,
        )
        .context("admit inference backend")?;

        ensure!(
            result == KernelConfigAdmission::Admitted,
            "admission result: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn rejects_unknown_inference_backend_fields() -> Result<()> {
        let Value::Map(mut value) = backend("deepseek")? else {
            bail!("backend helper must return a map");
        };
        value.insert("anthropic_version".into(), Value::Str("2023-06-01".into()));
        let result = admit_kernel_config(
            &path("state://kernel/inference/backends/deepseek")?,
            &Value::Map(value),
        );

        ensure!(
            matches!(
                result,
                Err(KernelConfigAdmissionError::Decode {
                    label: "InferenceBackendDef",
                    ..
                })
            ),
            "expected decode rejection, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn rejects_inference_path_mismatch() -> Result<()> {
        let result = admit_kernel_config(
            &path("state://kernel/inference/backends/other")?,
            &backend("deepseek")?,
        );

        ensure!(
            matches!(
                result,
                Err(KernelConfigAdmissionError::Rejected {
                    label: "InferenceBackendDef",
                    ..
                })
            ),
            "expected path mismatch rejection, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn admits_external_installation_declaration() -> Result<()> {
        let result = admit_kernel_config(
            &path("state://kernel/external-installations/acme")?,
            &installation("acme")?,
        )
        .context("admit external installation")?;

        ensure!(
            result == KernelConfigAdmission::Admitted,
            "admission result: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn admits_in_process_projection_declaration() -> Result<()> {
        let result = admit_kernel_config(
            &path("state://kernel/projections/in-process/fetch")?,
            &in_process_projection("fetch")?,
        )
        .context("admit in-process projection")?;

        ensure!(
            result == KernelConfigAdmission::Admitted,
            "admission result: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn rejects_in_process_projection_path_mismatch() -> Result<()> {
        let result = admit_kernel_config(
            &path("state://kernel/projections/in-process/other")?,
            &in_process_projection("fetch")?,
        );

        ensure!(
            matches!(
                result,
                Err(KernelConfigAdmissionError::Rejected {
                    label: "InProcessProjectionDef",
                    ..
                })
            ),
            "expected path mismatch rejection, got {result:?}"
        );
        Ok(())
    }

    #[test]
    fn leaves_console_paths_to_console() -> Result<()> {
        let result = admit_kernel_config(
            &path("state://kernel/console/users/root")?,
            &Value::Map(BTreeMap::new()),
        )
        .context("admit console path")?;

        ensure!(
            result == KernelConfigAdmission::Unhandled,
            "admission result: {result:?}"
        );
        Ok(())
    }
}
