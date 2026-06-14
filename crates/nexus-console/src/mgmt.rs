//! Kernel management helpers used by the Console Protocol host.
//!
//! These functions are the read/write projection for manageable
//! `state://kernel/*` configuration. Broader protocol actions such as
//! visibility, authority inspection, lineage, health, pairing, and stream
//! dispatch live in `ws`/`protocol` and call into this module for kernel
//! management state.

use crate::auth::{self, ConsolePrincipal};
use crate::state::ConsoleState;
use nexus_types::{
    AuditRules, ExternalInstallationDef, ExternalProjectionDef, ManifestDef, Path, TrustLevel,
    Value,
};
use serde::de::DeserializeOwned;
use std::sync::Arc;
use thiserror::Error;

/// Errors raised by console management state helpers.
#[derive(Debug, Error)]
pub enum MgmtError {
    /// Path is outside the console-manageable kernel state prefix.
    #[error("path is not under the manageable state://kernel/ prefix: {0}")]
    NotManageable(String),
    /// Path parsing failed.
    #[error("path error: {0}")]
    Path(#[from] nexus_types::PathError),
    /// Authorization failed.
    #[error("auth error: {0}")]
    Auth(#[from] auth::AuthError),
    /// Optimistic concurrency check failed.
    #[error("version conflict (optimistic concurrency): expected {expected:?}")]
    Conflict {
        /// Version expected by the caller.
        expected: Option<u64>,
    },
    /// Config admission rejected the proposed value.
    #[error("config admission rejected: {0}")]
    Admission(String),
    /// Underlying state operation failed.
    #[error("operation failed: {0}")]
    Operation(String),
}

/// Only `state://kernel/*` is manageable from the console. The vault and fact
/// prefixes are never writable here.
fn ensure_manageable(path: &Path) -> Result<(), MgmtError> {
    let s = path.to_string();
    if !s.starts_with("state://kernel/") {
        return Err(MgmtError::NotManageable(s));
    }
    if nexus_types::is_vault_reserved(path) {
        return Err(MgmtError::NotManageable(s));
    }
    Ok(())
}

/// Read a management config value.
pub async fn inspect(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: &str,
) -> Result<Option<Value>, MgmtError> {
    let p = Path::parse(path)?;
    ensure_manageable(&p)?;
    auth::authorize_path(&state.state, principal, "read", &p, None).await?;
    state
        .state
        .read(&p)
        .await
        .map_err(|error| MgmtError::Operation(error.to_string()))
}

/// List the keys under a management prefix (inspect a subtree).
pub async fn inspect_prefix(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    prefix: &str,
) -> Result<Vec<(String, Value)>, MgmtError> {
    let p = Path::parse(prefix)?;
    ensure_manageable(&p)?;
    auth::authorize_path(&state.state, principal, "read", &p, None).await?;
    let entries = state
        .state
        .read_prefix(&p)
        .await
        .map_err(|error| MgmtError::Operation(error.to_string()))?;
    Ok(entries
        .into_iter()
        .map(|(path, value)| (path.to_string(), value))
        .collect())
}

/// Change config with a CAS state write on the expected prior version.
/// `expected_version` of `None` means "create if absent" (install);
/// `Some(v)` means "update only if current version == v" (reconfigure). The
/// value's `version` field is bumped on write.
pub async fn write_config(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: &str,
    mut value: Value,
    expected_version: Option<u64>,
) -> Result<(), MgmtError> {
    let p = Path::parse(path)?;
    ensure_manageable(&p)?;
    auth::authorize_path(&state.state, principal, "write", &p, Some(&value)).await?;

    let current = state
        .state
        .read(&p)
        .await
        .map_err(|error| MgmtError::Operation(error.to_string()))?;
    let current_version = current.as_ref().and_then(value_version);
    if current_version != expected_version {
        return Err(MgmtError::Conflict {
            expected: expected_version,
        });
    }

    // Bump the version on the new value so the next edit must match it.
    let next = match expected_version {
        Some(v) => v
            .checked_add(1)
            .ok_or_else(|| MgmtError::Admission("config version overflow".into()))?,
        None => 1,
    };
    set_version(&mut value, next)?;
    admit_kernel_config(state, &p, &mut value).await?;

    match state.state.write_cas(&p, current, value).await {
        Ok(_) => {}
        Err(nexus_state::StateError::CasFailed { .. }) => {
            return Err(MgmtError::Conflict {
                expected: expected_version,
            });
        }
        Err(error) => return Err(MgmtError::Operation(error.to_string())),
    }
    Ok(())
}

fn value_version(v: &Value) -> Option<u64> {
    v.as_map()
        .and_then(|m| m.get("version"))
        .and_then(|x| x.as_int())
        .and_then(|i| u64::try_from(i).ok())
}

fn set_version(v: &mut Value, version: u64) -> Result<(), MgmtError> {
    if let Value::Map(m) = v {
        let version = i64::try_from(version)
            .map_err(|_| MgmtError::Admission("config version exceeds i64".into()))?;
        m.insert("version".into(), Value::Int(version));
    }
    Ok(())
}

async fn admit_kernel_config(
    _state: &Arc<ConsoleState>,
    path: &Path,
    value: &mut Value,
) -> Result<(), MgmtError> {
    let segs = path.segments();
    if path.scheme() != "state" || segs.first().map(|s| s.as_str()) != Some("kernel") {
        return Err(MgmtError::NotManageable(path.to_string()));
    }

    match segs {
        s if is_path(s, &["kernel", "external-installations"]) => {
            let id = required_tail(s, "external installation id")?;
            admit_extension_installation(id, value)
        }
        s if is_path_with_tail(s, &["kernel", "external-projections"], 2) => {
            admit_extension_projection(s, value)
        }
        s if is_path(s, &["kernel", "manifests"]) => {
            let platform = required_tail(s, "manifest platform")?;
            admit_manifest_def(platform, value)
        }
        s if is_path(s, &["kernel", "console", "users"]) => {
            let username = required_tail(s, "console username")?;
            auth::validate_username(username)
                .map_err(|e| MgmtError::Admission(format!("invalid console user path: {e}")))?;
            require_map(value, "console user")
        }
        s if is_path(s, &["kernel", "console", "roles"]) => {
            let role = required_tail(s, "console role")?;
            auth::validate_username(role)
                .map_err(|e| MgmtError::Admission(format!("invalid console role path: {e}")))?;
            require_map(value, "console role")
        }
        s if is_exact_path(s, &["kernel", "audit", "rules"]) => {
            let _: AuditRules = decode_config_value(value, "AuditRules")?;
            Ok(())
        }
        _ => Err(MgmtError::Admission(format!(
            "no console write admission rule for {path}"
        ))),
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

fn is_path_with_tail<S: AsRef<str>>(segs: &[S], prefix: &[&str], tail_len: usize) -> bool {
    segs.len() == prefix.len() + tail_len
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

fn required_tail<'a, S: AsRef<str>>(segs: &'a [S], label: &str) -> Result<&'a str, MgmtError> {
    segs.last()
        .map(|s| s.as_ref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MgmtError::Admission(format!("missing {label}")))
}

fn require_map(value: &Value, label: &str) -> Result<(), MgmtError> {
    if value.as_map().is_some() {
        Ok(())
    } else {
        Err(MgmtError::Admission(format!("{label} must be an object")))
    }
}

fn decode_config_value<T: DeserializeOwned>(value: &Value, label: &str) -> Result<T, MgmtError> {
    let json = serde_json::to_value(value)
        .map_err(|e| MgmtError::Admission(format!("{label} serialization failed: {e}")))?;
    serde_json::from_value(json)
        .map_err(|e| MgmtError::Admission(format!("{label} is malformed: {e}")))
}

fn admit_extension_installation(path_id: &str, value: &Value) -> Result<(), MgmtError> {
    let def: ExternalInstallationDef = decode_config_value(value, "ExternalInstallationDef")?;
    if def.id != path_id {
        return Err(MgmtError::Admission(format!(
            "ExternalInstallationDef.id {:?} does not match path id {:?}",
            def.id, path_id
        )));
    }
    admit_json_schema(&def.config_schema, "ExternalInstallationDef.config_schema")?;
    def.validate_admission()
        .map_err(|e| MgmtError::Admission(format!("ExternalInstallationDef admission failed: {e}")))
}

fn admit_extension_projection<S: AsRef<str>>(segs: &[S], value: &Value) -> Result<(), MgmtError> {
    let installation_id = segs
        .get(2)
        .map(|s| s.as_ref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MgmtError::Admission("missing external installation id".into()))?;
    let projection_id = segs
        .get(3)
        .map(|s| s.as_ref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MgmtError::Admission("missing external projection id".into()))?;
    let def: ExternalProjectionDef = decode_config_value(value, "ExternalProjectionDef")?;
    if def.id != projection_id {
        return Err(MgmtError::Admission(format!(
            "ExternalProjectionDef.id {:?} does not match path projection {:?}",
            def.id, projection_id
        )));
    }
    def.validate_admission(
        installation_id,
        TrustLevel::Sandboxed,
        &nexus_types::Transport::Grpc { endpoint: None },
    )
    .map_err(|e| MgmtError::Admission(format!("ExternalProjectionDef admission failed: {e}")))
}

fn admit_manifest_def(path_platform: &str, value: &Value) -> Result<(), MgmtError> {
    let def: ManifestDef = decode_config_value(value, "ManifestDef")?;
    if def.platform != path_platform {
        return Err(MgmtError::Admission(format!(
            "ManifestDef.platform {:?} does not match path platform {:?}",
            def.platform, path_platform
        )));
    }
    if def.platform.trim().is_empty() {
        return Err(MgmtError::Admission(
            "ManifestDef.platform must not be empty".into(),
        ));
    }
    if def.version == 0 {
        return Err(MgmtError::Admission(
            "ManifestDef.version must be a positive config revision".into(),
        ));
    }
    admit_json_schema(&def.config_schema, "ManifestDef.config_schema")?;
    if def.supported_transports.is_empty() {
        return Err(MgmtError::Admission(
            "ManifestDef.supported_transports must not be empty".into(),
        ));
    }
    if !def
        .supported_transports
        .iter()
        .any(|t| t == &def.default_transport)
    {
        return Err(MgmtError::Admission(
            "ManifestDef.default_transport must be listed in supported_transports".into(),
        ));
    }
    if def.projections.is_empty() {
        return Err(MgmtError::Admission(
            "ManifestDef.projections must not be empty".into(),
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for projection in &def.projections {
        if !seen.insert(projection.id.clone()) {
            return Err(MgmtError::Admission(format!(
                "ManifestDef contains duplicate projection id {:?}",
                projection.id
            )));
        }
        projection
            .validate_admission(&def.platform, TrustLevel::Sandboxed, &def.default_transport)
            .map_err(|e| {
                MgmtError::Admission(format!("ManifestDef projection admission failed: {e}"))
            })?;
        for cap in &projection.provides {
            admit_manifest_effect(&cap.effect_path)?;
        }
    }
    Ok(())
}

fn admit_json_schema(schema: &Value, label: &str) -> Result<(), MgmtError> {
    match schema {
        Value::Null | Value::Map(_) => Ok(()),
        _ => Err(MgmtError::Admission(format!(
            "{label} must be null or a JSON object"
        ))),
    }
}

fn admit_manifest_effect(effect_path: &str) -> Result<(), MgmtError> {
    let effect = Path::parse(effect_path).map_err(|e| {
        MgmtError::Admission(format!(
            "ManifestDef projection effect path is malformed: {e}"
        ))
    })?;
    if effect.scheme() != "effect" || effect.segments().is_empty() {
        return Err(MgmtError::Admission(
            "ManifestDef projection effects must be effect:// paths".into(),
        ));
    }
    if effect.segments().first().map(|s| s.as_str()) == Some("kernel") {
        return Err(MgmtError::Admission(
            "ManifestDef projection effects must not target effect://kernel/*".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{BootstrapOutcome, LoginRequest, RootProvisioning, bootstrap_root_account};
    use nexus_actors::{StandardConfig, install_standard};
    use nexus_kernel::Bootstrap;
    use nexus_types::{EffectCapability, Purity, Role, Transport, TrustLevel};
    use std::collections::BTreeMap;

    fn console_state() -> Arc<ConsoleState> {
        let boot = Arc::new(Bootstrap::in_memory());
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());
        ConsoleState::shared(boot)
    }

    fn obj(version: Option<u64>) -> Value {
        let mut m = BTreeMap::new();
        m.insert("transport".into(), Value::Str("stdio".into()));
        if let Some(v) = version {
            m.insert("version".into(), Value::Int(v as i64));
        }
        Value::Map(m)
    }

    fn extension_installation(id: &str, version: u64) -> Value {
        let def = ExternalInstallationDef {
            id: id.into(),
            platform: id.into(),
            transport: Transport::Stdio {
                command: Some(format!("{id}-plugin")),
                args: vec![],
            },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![ExternalProjectionDef {
                id: "provider".into(),
                role: Role::Provider,
                namespace: Some(Path::parse(&format!("effect://external-provider/{id}")).unwrap()),
                provides: vec![EffectCapability::new(
                    format!("effect://external-provider/{id}/search"),
                    Purity::Idempotent,
                )],
                emits: None,
                version: 1,
            }],
            version,
        };
        serde_json::from_value(serde_json::to_value(def).unwrap()).unwrap()
    }

    fn instant_messaging_platform_installation(version: u64) -> Value {
        let def = nexus_types::ExternalInstallationDef {
            id: "instant_messaging_platform".into(),
            platform: "instant_messaging_platform".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![
                nexus_types::ExternalProjectionDef {
                    id: "source".into(),
                    role: Role::Source,
                    namespace: None,
                    provides: vec![],
                    emits: Some(nexus_types::EventSource {
                        sink: nexus_types::sandboxed_source_event_sink_path(
                            "instant_messaging_platform",
                            "source",
                        )
                        .unwrap(),
                        purity: Purity::Effectful,
                        event_schema: None,
                        max_inline_payload_bytes: 65_536,
                        capacity: nexus_types::external::StreamCapacity {
                            max_events: 1024,
                            on_overflow: nexus_types::external::OverflowPolicy::DropOldest,
                        },
                        rate_limit: None,
                        commands: false,
                        command_schema: None,
                        command_result_schema: None,
                    }),
                    version: 1,
                },
                nexus_types::ExternalProjectionDef {
                    id: "provider".into(),
                    role: Role::Provider,
                    namespace: Some(
                        Path::parse("effect://external-provider/instant_messaging_platform")
                            .unwrap(),
                    ),
                    provides: vec![EffectCapability::new(
                        "effect://external-provider/instant_messaging_platform/send_text",
                        Purity::Effectful,
                    )],
                    emits: None,
                    version: 1,
                },
            ],
            version,
        };
        serde_json::from_value(serde_json::to_value(def).unwrap()).unwrap()
    }

    async fn root_principal(st: &Arc<ConsoleState>) -> ConsolePrincipal {
        let outcome = bootstrap_root_account(&st.boot, RootProvisioning::default())
            .await
            .unwrap();
        let BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
            panic!("expected root bootstrap");
        };
        let login = st
            .auth
            .login(
                &st.boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    totp_code: None,
                },
                "test".into(),
            )
            .await
            .unwrap();
        st.auth
            .authenticate_token(&st.boot, &login.token)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn non_kernel_paths_are_rejected() {
        let st = console_state();
        let root = root_principal(&st).await;
        assert!(matches!(
            inspect(&st, &root, "state://memory/alice").await,
            Err(MgmtError::NotManageable(_))
        ));
        assert!(matches!(
            write_config(&st, &root, "state://vault/secret", obj(None), None).await,
            Err(MgmtError::NotManageable(_))
        ));
    }

    #[tokio::test]
    async fn install_then_reconfigure_with_cas() {
        let st = console_state();
        let root = root_principal(&st).await;
        let path = "state://kernel/external-installations/acme";
        write_config(&st, &root, path, extension_installation("acme", 0), None)
            .await
            .unwrap();
        let v = inspect(&st, &root, path).await.unwrap().unwrap();
        assert_eq!(value_version(&v), Some(1));
        write_config(&st, &root, path, extension_installation("acme", 1), Some(1))
            .await
            .unwrap();
        let v = inspect(&st, &root, path).await.unwrap().unwrap();
        assert_eq!(value_version(&v), Some(2));
        assert!(matches!(
            write_config(&st, &root, path, extension_installation("acme", 1), Some(1)).await,
            Err(MgmtError::Conflict { .. })
        ));
    }

    #[tokio::test]
    async fn extension_installation_admission_supports_multi_projection_package() {
        let st = console_state();
        let root = root_principal(&st).await;
        let path = "state://kernel/external-installations/instant_messaging_platform";
        write_config(
            &st,
            &root,
            path,
            instant_messaging_platform_installation(0),
            None,
        )
        .await
        .unwrap();
        let v = inspect(&st, &root, path).await.unwrap().unwrap();
        assert_eq!(value_version(&v), Some(1));

        let mut bad = instant_messaging_platform_installation(0);
        let Value::Map(ref mut m) = bad else {
            panic!("expected object");
        };
        let Value::List(projections) = m.get_mut("projections").unwrap() else {
            panic!("expected projections");
        };
        let Value::Map(provider) = &mut projections[1] else {
            panic!("expected provider projection");
        };
        provider.insert(
            "provides".into(),
            Value::List(vec![
                serde_json::from_value(serde_json::json!({
                    "effect_path": "effect://external-provider/other/send_text",
                    "purity": "effectful"
                }))
                .unwrap(),
            ]),
        );
        assert!(matches!(
            write_config(&st, &root, path, bad, Some(1)).await,
            Err(MgmtError::Admission(_))
        ));
    }

    #[tokio::test]
    async fn removed_external_config_prefix_is_rejected() {
        let st = console_state();
        let root = root_principal(&st).await;
        assert!(matches!(
            write_config(
                &st,
                &root,
                "state://kernel/external/acme",
                extension_installation("acme", 0),
                None,
            )
            .await,
            Err(MgmtError::Admission(_))
        ));
    }

    #[tokio::test]
    async fn unknown_kernel_config_paths_are_rejected() {
        let st = console_state();
        let root = root_principal(&st).await;
        assert!(matches!(
            write_config(&st, &root, "state://kernel/unknown/x", obj(None), None).await,
            Err(MgmtError::Admission(_))
        ));
    }
}
