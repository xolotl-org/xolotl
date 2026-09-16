//! Kernel management helpers used by the Console Protocol host.
//!
//! These functions are the read/write projection for manageable
//! `state://kernel/*` configuration. Broader protocol actions such as
//! visibility, authority inspection, lineage, health, pairing, and stream
//! dispatch live in `ws`/`protocol` and call into this module for kernel
//! management state.

use crate::auth::{self, ConsolePrincipal};
use crate::state::ConsoleState;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use thiserror::Error;
use xolotl_types::{AuditRules, Capability, Path, Value, ValueMap, ValueView};

mod config;
use config::{KernelConfigAdmission, admit_kernel_config as admit_declared_config};

/// Errors raised by console management state helpers.
#[derive(Debug, Error)]
pub(crate) enum MgmtError {
    /// Path is outside the console-manageable kernel state prefix.
    #[error("path is not under the manageable state://kernel/ prefix: {0}")]
    NotManageable(String),
    /// Path parsing failed.
    #[error("path error: {0}")]
    Path(#[from] xolotl_types::PathError),
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
    if !is_local_kernel_state_subtree(path) {
        return Err(MgmtError::NotManageable(path.to_string()));
    }
    if xolotl_types::is_vault_reserved(path) {
        return Err(MgmtError::NotManageable(path.to_string()));
    }
    Ok(())
}

fn is_local_kernel_state_subtree(path: &Path) -> bool {
    let segs = path.segments();
    path.scheme() == "state"
        && path.cluster().is_none()
        && segs.first().map(|s| s.as_str()) == Some("kernel")
        && segs.len() > 1
}

/// Read a management config value.
pub(crate) async fn inspect(
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

/// Read a config value through the generic config action family.
pub(crate) async fn inspect_config(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: &str,
) -> Result<Option<Value>, MgmtError> {
    let p = Path::parse(path)?;
    reject_dedicated_runtime_config_path(&p)?;
    inspect(state, principal, path).await
}

/// List the keys under a management prefix (inspect a subtree).
pub(crate) async fn inspect_prefix(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    prefix: &str,
) -> Result<Vec<(String, Value)>, MgmtError> {
    let p = Path::parse(prefix)?;
    ensure_manageable(&p)?;
    auth::authorize_path(&state.state, principal, "read", &p, None).await?;
    let mut pages = state.state.pages(xolotl_state::StateScan::new(p));
    let mut entries = Vec::new();
    while let Some(page) = pages
        .next()
        .await
        .map_err(|error| MgmtError::Operation(error.to_string()))?
    {
        entries.extend(
            page.entries
                .into_iter()
                .map(|(path, value)| (path.to_string(), value.value)),
        );
    }
    Ok(entries)
}

/// List config values through the generic config action family.
pub(crate) async fn inspect_config_prefix(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    prefix: &str,
) -> Result<Vec<(String, Value)>, MgmtError> {
    let p = Path::parse(prefix)?;
    reject_dedicated_runtime_config_prefix(&p)?;
    inspect_prefix(state, principal, prefix).await
}

/// Change config with a CAS state write on the expected prior version.
/// `expected_version` of `None` means "create if absent" (install);
/// `Some(v)` means "update only if current version == v" (reconfigure). The
/// value's `version` field is bumped on write.
pub(crate) async fn write_config(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: &str,
    value: Value,
    expected_version: Option<u64>,
) -> Result<(), MgmtError> {
    let p = Path::parse(path)?;
    if is_dedicated_runtime_config_path(&p) {
        return Err(MgmtError::Admission(
            "runtime config path must use its dedicated console action".into(),
        ));
    }
    write_config_inner(state, principal, p, value, expected_version).await
}

/// Change config for a path owned by a dedicated Console action family.
pub(crate) async fn write_dedicated_config(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: &str,
    value: Value,
    expected_version: Option<u64>,
) -> Result<(), MgmtError> {
    let p = Path::parse(path)?;
    if !is_dedicated_runtime_config_path(&p) {
        return Err(MgmtError::Admission(
            "dedicated console action cannot write generic config path".into(),
        ));
    }
    write_config_inner(state, principal, p, value, expected_version).await
}

async fn write_config_inner(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    p: Path,
    mut value: Value,
    expected_version: Option<u64>,
) -> Result<(), MgmtError> {
    ensure_manageable(&p)?;
    auth::authorize_path(&state.state, principal, "write", &p, Some(&value)).await?;

    let current = state
        .state
        .read(&p)
        .await
        .map_err(|error| MgmtError::Operation(error.to_string()))?;
    let current_version = current.as_ref().map(value_version).transpose()?.flatten();
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
        Err(xolotl_state::StateFailure {
            error: xolotl_state::StateError::CasFailed { .. },
            ..
        }) => {
            return Err(MgmtError::Conflict {
                expected: expected_version,
            });
        }
        Err(error) => return Err(MgmtError::Operation(error.to_string())),
    }
    Ok(())
}

pub(crate) fn is_dedicated_runtime_config_path(path: &Path) -> bool {
    let segs = path.segments();
    if path.scheme() != "state"
        || path.cluster().is_some()
        || segs.first().map(|s| s.as_str()) != Some("kernel")
    {
        return false;
    }
    matches!(
        segs.get(1).map(|s| s.as_str()),
        Some(
            "console"
                | "external-installations"
                | "external-pairings"
                | "external-sessions"
                | "external-credential-revocations"
                | "inference"
                | "manifests"
                | "projection-status"
                | "procs"
        )
    ) || (segs.get(1).map(|s| s.as_str()) == Some("routing")
        && segs.get(2).map(|s| s.as_str()) == Some("inference"))
}

fn reject_dedicated_runtime_config_path(path: &Path) -> Result<(), MgmtError> {
    if is_dedicated_runtime_config_path(path) {
        return Err(MgmtError::Admission(
            "runtime config path must use its dedicated console action".into(),
        ));
    }
    Ok(())
}

fn reject_dedicated_runtime_config_prefix(path: &Path) -> Result<(), MgmtError> {
    let segs = path.segments();
    let contains_dedicated_subtree = if path.scheme() == "state" && path.cluster().is_none() {
        match segs {
            [kernel] => kernel.as_str() == "kernel",
            [kernel, routing] => kernel.as_str() == "kernel" && routing.as_str() == "routing",
            _ => false,
        }
    } else {
        false
    };
    if contains_dedicated_subtree {
        return Err(MgmtError::Admission(
            "runtime config path must use its dedicated console action".into(),
        ));
    }
    reject_dedicated_runtime_config_path(path)
}

fn value_version(v: &Value) -> Result<Option<u64>, MgmtError> {
    let Some(version) = v.as_map().and_then(|m| m.get("version")) else {
        return Ok(None);
    };
    let Some(version) = version.as_int() else {
        return Err(MgmtError::Admission(
            "config version must be an integer".into(),
        ));
    };
    let version = u64::try_from(version)
        .map_err(|_error| MgmtError::Admission("config version must be nonnegative".into()))?;
    Ok(Some(version))
}

fn set_version(v: &mut Value, version: u64) -> Result<(), MgmtError> {
    if let Some(mut m) = v.as_map().cloned() {
        let version = i64::try_from(version)
            .map_err(|_error| MgmtError::Admission("config version exceeds i64".into()))?;
        m.insert("version".into(), Value::integer(version))
            .map_err(|error| MgmtError::Admission(error.to_string()))?;
        *v = Value::from(m);
    }
    Ok(())
}

async fn admit_kernel_config(
    _state: &Arc<ConsoleState>,
    path: &Path,
    value: &mut Value,
) -> Result<(), MgmtError> {
    let segs = path.segments();
    if path.scheme() != "state"
        || path.cluster().is_some()
        || segs.first().map(|s| s.as_str()) != Some("kernel")
    {
        return Err(MgmtError::NotManageable(path.to_string()));
    }

    match admit_declared_config(path, value) {
        Ok(KernelConfigAdmission::Admitted) => return Ok(()),
        Ok(KernelConfigAdmission::Unhandled) => {}
        Err(error) => return Err(MgmtError::Admission(error.to_string())),
    }

    match segs {
        s if is_path(s, &["kernel", "console", "users"]) => {
            let username = required_tail(s, "console username")?;
            auth::validate_username(username)
                .map_err(|e| MgmtError::Admission(format!("invalid console user path: {e}")))?;
            admit_console_user(username, value)
        }
        s if is_path(s, &["kernel", "console", "roles"]) => {
            let role = required_tail(s, "console role")?;
            auth::validate_username(role)
                .map_err(|e| MgmtError::Admission(format!("invalid console role path: {e}")))?;
            admit_console_role(value)
        }
        s if is_exact_path(s, &["kernel", "audit", "rules"]) => {
            decode_config_value::<AuditRules>(value, "AuditRules")?;
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

fn require_map_ref<'a>(value: &'a Value, label: &str) -> Result<&'a ValueMap, MgmtError> {
    value
        .as_map()
        .ok_or_else(|| MgmtError::Admission(format!("{label} must be an object")))
}

fn admit_console_user(_username: &str, value: &Value) -> Result<(), MgmtError> {
    let map = require_map_ref(value, "console user")?;
    validate_known_fields(
        map,
        &[
            "version",
            "identity_path",
            "status",
            "authn",
            "roles",
            "grants",
            "authority_ceiling",
            "created_by",
            "created_at",
            "password_changed_at",
        ],
        "console user",
    )?;
    optional_nonnegative_int(map, "version", "console user")?;
    let identity_path = required_string(map, "identity_path", "console user")?;
    let path = Path::parse(identity_path)
        .map_err(|e| MgmtError::Admission(format!("console user identity_path: {e}")))?;
    if path.cluster().is_some()
        || path.scheme() != "identity"
        || path.segments().is_empty()
        || !path.is_concrete()
    {
        return Err(MgmtError::Admission(
            "console user identity_path must be a concrete identity path".into(),
        ));
    }
    let status = required_string(map, "status", "console user")?;
    if !matches!(status, "active" | "disabled" | "locked") {
        return Err(MgmtError::Admission(
            "console user status must be active, disabled, or locked".into(),
        ));
    }
    admit_console_user_authn(required_value(map, "authn", "console user")?)?;
    for role in required_string_list(map, "roles", "console user")? {
        auth::validate_username(role)
            .map_err(|e| MgmtError::Admission(format!("console user role: {e}")))?;
    }
    validate_required_capability_list(map, "grants", "console user")?;
    validate_required_capability_list(map, "authority_ceiling", "console user")?;
    required_string(map, "created_by", "console user")?;
    required_nonnegative_int(map, "created_at", "console user")?;
    required_nonnegative_int(map, "password_changed_at", "console user")?;
    Ok(())
}

fn admit_console_user_authn(value: &Value) -> Result<(), MgmtError> {
    let map = require_map_ref(value, "console user authn")?;
    validate_known_fields(map, &["password", "totp", "pubkeys"], "console user authn")?;
    let password = required_map(map, "password", "console user authn")?;
    validate_known_fields(password, &["hash_ref"], "console user password authn")?;
    optional_string(password, "hash_ref", "console user password authn")?;
    let totp = required_map(map, "totp", "console user authn")?;
    validate_known_fields(
        totp,
        &["enabled", "seed_ref", "last_step"],
        "console user totp authn",
    )?;
    optional_bool(totp, "enabled", "console user totp authn")?;
    optional_string(totp, "seed_ref", "console user totp authn")?;
    optional_nonnegative_int(totp, "last_step", "console user totp authn")?;
    required_string_list(map, "pubkeys", "console user authn")?;
    Ok(())
}

fn admit_console_role(value: &Value) -> Result<(), MgmtError> {
    let map = require_map_ref(value, "console role")?;
    validate_known_fields(map, &["version", "grants", "frozen"], "console role")?;
    optional_nonnegative_int(map, "version", "console role")?;
    validate_capability_list(map, "grants", "console role")?;
    optional_bool(map, "frozen", "console role")?;
    Ok(())
}

fn validate_known_fields(map: &ValueMap, allowed: &[&str], label: &str) -> Result<(), MgmtError> {
    for key in map.keys() {
        if !allowed.contains(&key) {
            return Err(MgmtError::Admission(format!(
                "{label} has unknown field '{key}'"
            )));
        }
    }
    Ok(())
}

fn optional_string<'a>(
    map: &'a ValueMap,
    name: &str,
    label: &str,
) -> Result<Option<&'a str>, MgmtError> {
    match map.get(name).map(Value::view) {
        Some(ValueView::Str(value)) => Ok(Some(value)),
        Some(_) => Err(MgmtError::Admission(format!(
            "{label}.{name} must be a string"
        ))),
        None => Ok(None),
    }
}

fn required_value<'a>(map: &'a ValueMap, name: &str, label: &str) -> Result<&'a Value, MgmtError> {
    map.get(name)
        .ok_or_else(|| MgmtError::Admission(format!("{label}.{name} is required")))
}

fn required_string<'a>(map: &'a ValueMap, name: &str, label: &str) -> Result<&'a str, MgmtError> {
    match map.get(name).map(Value::view) {
        Some(ValueView::Str(value)) if !value.is_empty() => Ok(value),
        Some(ValueView::Str(_)) => Err(MgmtError::Admission(format!(
            "{label}.{name} must not be empty"
        ))),
        Some(_) => Err(MgmtError::Admission(format!(
            "{label}.{name} must be a string"
        ))),
        None => Err(MgmtError::Admission(format!("{label}.{name} is required"))),
    }
}

fn required_map<'a>(map: &'a ValueMap, name: &str, label: &str) -> Result<&'a ValueMap, MgmtError> {
    match map.get(name).map(Value::view) {
        Some(ValueView::Map(value)) => Ok(value),
        Some(_) => Err(MgmtError::Admission(format!(
            "{label}.{name} must be an object"
        ))),
        None => Err(MgmtError::Admission(format!("{label}.{name} is required"))),
    }
}

fn optional_bool(map: &ValueMap, name: &str, label: &str) -> Result<Option<bool>, MgmtError> {
    match map.get(name).map(Value::view) {
        Some(ValueView::Bool(value)) => Ok(Some(value)),
        Some(_) => Err(MgmtError::Admission(format!(
            "{label}.{name} must be a bool"
        ))),
        None => Ok(None),
    }
}

fn optional_nonnegative_int(
    map: &ValueMap,
    name: &str,
    label: &str,
) -> Result<Option<i64>, MgmtError> {
    match map.get(name).map(Value::view) {
        Some(ValueView::Int(value)) if value >= 0 => Ok(Some(value)),
        Some(ValueView::Int(_)) => Err(MgmtError::Admission(format!(
            "{label}.{name} must be non-negative"
        ))),
        Some(_) => Err(MgmtError::Admission(format!(
            "{label}.{name} must be an integer"
        ))),
        None => Ok(None),
    }
}

fn required_nonnegative_int(map: &ValueMap, name: &str, label: &str) -> Result<i64, MgmtError> {
    match map.get(name).map(Value::view) {
        Some(ValueView::Int(value)) if value >= 0 => Ok(value),
        Some(ValueView::Int(_)) => Err(MgmtError::Admission(format!(
            "{label}.{name} must be non-negative"
        ))),
        Some(_) => Err(MgmtError::Admission(format!(
            "{label}.{name} must be an integer"
        ))),
        None => Err(MgmtError::Admission(format!("{label}.{name} is required"))),
    }
}

fn optional_string_list<'a>(
    map: &'a ValueMap,
    name: &str,
    label: &str,
) -> Result<Vec<&'a str>, MgmtError> {
    match map.get(name).map(Value::view) {
        Some(ValueView::List(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let Some(value) = item.as_str() else {
                    return Err(MgmtError::Admission(format!(
                        "{label}.{name} must be a list of strings"
                    )));
                };
                if value.is_empty() {
                    return Err(MgmtError::Admission(format!(
                        "{label}.{name} entries must be non-empty"
                    )));
                }
                out.push(value);
            }
            Ok(out)
        }
        Some(_) => Err(MgmtError::Admission(format!(
            "{label}.{name} must be a list of strings"
        ))),
        None => Ok(Vec::new()),
    }
}

fn required_string_list<'a>(
    map: &'a ValueMap,
    name: &str,
    label: &str,
) -> Result<Vec<&'a str>, MgmtError> {
    if !map.contains_key(name) {
        return Err(MgmtError::Admission(format!("{label}.{name} is required")));
    }
    optional_string_list(map, name, label)
}

fn validate_capability_list(map: &ValueMap, name: &str, label: &str) -> Result<(), MgmtError> {
    for capability in optional_string_list(map, name, label)? {
        Capability::parse(capability)
            .map_err(|e| MgmtError::Admission(format!("{label}.{name}: {e}")))?;
    }
    Ok(())
}

fn validate_required_capability_list(
    map: &ValueMap,
    name: &str,
    label: &str,
) -> Result<(), MgmtError> {
    for capability in required_string_list(map, name, label)? {
        Capability::parse(capability)
            .map_err(|e| MgmtError::Admission(format!("{label}.{name}: {e}")))?;
    }
    Ok(())
}

fn decode_config_value<T: DeserializeOwned>(value: &Value, label: &str) -> Result<T, MgmtError> {
    let json = serde_json::to_value(value)
        .map_err(|e| MgmtError::Admission(format!("{label} serialization failed: {e}")))?;
    serde_json::from_value(json)
        .map_err(|e| MgmtError::Admission(format!("{label} is malformed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{BootstrapOutcome, LoginRequest, RootProvisioning, bootstrap_root_account};
    use anyhow::{Context, bail, ensure};
    use std::collections::BTreeMap;
    use xolotl_kernel::Bootstrap;
    use xolotl_standard::{StandardConfig, install_standard};
    use xolotl_types::{
        EffectCapability, ExternalInstallationDef, ExternalProjectionDef, InProcessProjectionDef,
        InferenceApiDialect, InferenceAuthRef, InferenceBackendDef, Purity, Role, Transport,
        TrustLevel,
    };

    fn console_state() -> anyhow::Result<Arc<ConsoleState>> {
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default())?;
        Ok(ConsoleState::shared(boot)?)
    }

    fn obj(version: Option<u64>) -> Value {
        let mut m = BTreeMap::new();
        m.insert("transport".into(), Value::string("stdio".into()));
        if let Some(v) = version {
            m.insert("version".into(), Value::integer(v as i64));
        }
        Value::map(m)
    }

    fn complete_console_user(username: &str) -> anyhow::Result<Value> {
        let password_ref = Path::try_new("state")
            .and_then(|path| path.try_push("vault"))
            .and_then(|path| path.try_push("console"))
            .and_then(|path| path.try_push_literal(username))
            .and_then(|path| path.try_push("password"))
            .map(|path| path.to_string())?;
        let mut password = BTreeMap::new();
        password.insert("hash_ref".into(), Value::string(password_ref));
        let mut totp = BTreeMap::new();
        totp.insert("enabled".into(), Value::boolean(false));
        let mut authn = BTreeMap::new();
        authn.insert("password".into(), Value::map(password));
        authn.insert("totp".into(), Value::map(totp));
        authn.insert("pubkeys".into(), Value::list(Vec::new()));

        let mut user = BTreeMap::new();
        user.insert(
            "identity_path".into(),
            Value::string(format!("identity://console/{username}")),
        );
        user.insert("status".into(), Value::string("active".into()));
        user.insert("authn".into(), Value::map(authn));
        user.insert("roles".into(), Value::list(Vec::new()));
        user.insert("grants".into(), Value::list(Vec::new()));
        user.insert("authority_ceiling".into(), Value::list(Vec::new()));
        user.insert("created_by".into(), Value::string("test".into()));
        user.insert("created_at".into(), Value::integer(1));
        user.insert("password_changed_at".into(), Value::integer(1));
        Ok(Value::map(user))
    }

    fn extension_installation(id: &str, version: u64) -> anyhow::Result<Value> {
        let provider_namespace = Path::try_new("effect")?
            .try_push("external-provider")?
            .try_push_literal(id)?;
        let search_effect = provider_namespace.clone().try_push("search")?.to_string();
        let def = ExternalInstallationDef {
            id: id.into(),
            platform: id.into(),
            transport: Transport::Stdio {
                command: Some(format!("{id}-plugin")),
                args: vec![],
            },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::null(),
            config: Value::null(),
            projections: vec![ExternalProjectionDef {
                id: "provider".into(),
                role: Role::Provider,
                namespace: Some(provider_namespace),
                provides: vec![EffectCapability::new(search_effect, Purity::Idempotent)],
                emits: None,
                version: 1,
            }],
            version,
        };
        Ok(serde_json::from_value(serde_json::to_value(def)?)?)
    }

    fn value_from<T: serde::Serialize>(value: &T) -> anyhow::Result<Value> {
        Ok(serde_json::from_value(serde_json::to_value(value)?)?)
    }

    fn inference_backend(id: &str) -> anyhow::Result<Value> {
        value_from(&InferenceBackendDef {
            id: id.into(),
            dialect: InferenceApiDialect::OpenAiChatCompletions,
            base_url: "https://api.deepseek.com".into(),
            auth: InferenceAuthRef::BearerToken {
                token_ref: Path::parse("state://vault/inference/deepseek/api_key")?,
            },
            default_headers: BTreeMap::new(),
            request_overrides: BTreeMap::new(),
            api_version: None,
            io_window_bytes: None,
            response_limits: Default::default(),
            version: 0,
        })
    }

    fn in_process_projection(id: &str, version: u64) -> anyhow::Result<Value> {
        value_from(&InProcessProjectionDef {
            id: id.into(),
            role: Role::Provider,
            implementation: "standard.fetch".into(),
            provides: vec![EffectCapability::new(
                "effect://fetch/get",
                Purity::Idempotent,
            )],
            emits: None,
            config: Value::null(),
            version,
        })
    }

    fn instant_messaging_platform_installation(version: u64) -> anyhow::Result<Value> {
        let def = xolotl_types::ExternalInstallationDef {
            id: "instant_messaging_platform".into(),
            platform: "instant_messaging_platform".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::null(),
            config: Value::null(),
            projections: vec![
                xolotl_types::ExternalProjectionDef {
                    id: "source".into(),
                    role: Role::Source,
                    namespace: None,
                    provides: vec![],
                    emits: Some(xolotl_types::EventSource {
                        sink: xolotl_types::sandboxed_source_event_sink_path(
                            "instant_messaging_platform",
                            "source",
                        )?,
                        purity: Purity::Effectful,
                        event_schema: None,
                        max_inline_payload_bytes: 65_536,
                        capacity: xolotl_types::external::StreamCapacity {
                            max_events: 1024,
                            on_overflow: xolotl_types::external::OverflowPolicy::DropOldest,
                        },
                        rate_limit: None,
                        commands: false,
                        command_schema: None,
                        command_result_schema: None,
                    }),
                    version: 1,
                },
                xolotl_types::ExternalProjectionDef {
                    id: "provider".into(),
                    role: Role::Provider,
                    namespace: Some(Path::parse(
                        "effect://external-provider/instant_messaging_platform",
                    )?),
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
        Ok(serde_json::from_value(serde_json::to_value(def)?)?)
    }

    async fn root_principal(st: &Arc<ConsoleState>) -> anyhow::Result<ConsolePrincipal> {
        let outcome = bootstrap_root_account(&st.boot, RootProvisioning::default()).await?;
        let BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
            bail!("expected root bootstrap, got {outcome:?}");
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
            .await?;
        Ok(st.auth.authenticate_token(&st.boot, &login.token).await?)
    }

    fn expect_admission_message<T>(
        result: Result<T, MgmtError>,
        expected: &str,
    ) -> anyhow::Result<()> {
        match result {
            Err(MgmtError::Admission(message)) if message == expected => Ok(()),
            Err(err) => bail!("expected admission error {expected:?}, got {err:?}"),
            Ok(_) => bail!("expected admission error {expected:?}, got success"),
        }
    }

    fn expect_admission<T>(result: Result<T, MgmtError>) -> anyhow::Result<()> {
        match result {
            Err(MgmtError::Admission(_)) => Ok(()),
            Err(err) => bail!("expected admission error, got {err:?}"),
            Ok(_) => bail!("expected admission error, got success"),
        }
    }

    fn expect_not_manageable<T>(result: Result<T, MgmtError>) -> anyhow::Result<()> {
        match result {
            Err(MgmtError::NotManageable(_)) => Ok(()),
            Err(err) => bail!("expected not-manageable error, got {err:?}"),
            Ok(_) => bail!("expected not-manageable error, got success"),
        }
    }

    #[tokio::test]
    async fn non_kernel_paths_are_rejected() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        expect_not_manageable(inspect(&st, &root, "state://memory/alice").await)?;
        expect_not_manageable(
            inspect_config(
                &st,
                &root,
                "path://remote/state/kernel/projections/in-process/fetch",
            )
            .await,
        )?;
        expect_not_manageable(
            write_config(&st, &root, "state://vault/secret", obj(None), None).await,
        )?;
        expect_not_manageable(
            write_config(
                &st,
                &root,
                "path://remote/state/kernel/projections/in-process/fetch",
                in_process_projection("fetch", 0)?,
                None,
            )
            .await,
        )?;
        Ok(())
    }

    #[test]
    fn console_user_admission_rejects_unknown_fields() -> anyhow::Result<()> {
        let mut user = BTreeMap::new();
        user.insert("unknown".into(), Value::boolean(true));

        let err = match admit_console_user("ops", &Value::map(user)) {
            Ok(()) => bail!("console user with unknown field was admitted"),
            Err(err) => err,
        };
        ensure!(
            matches!(err, MgmtError::Admission(ref message) if message.contains("unknown field")),
            "unexpected console user admission error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn console_user_admission_requires_complete_record_shape() -> anyhow::Result<()> {
        let complete = complete_console_user("ops")?;
        admit_console_user("ops", &complete).context("complete console user was rejected")?;

        let mut map = (complete_console_user("ops")?)
            .into_map()
            .context("expected map")?;
        map.remove("status");
        let missing_status = Value::from(map);
        let err = match admit_console_user("ops", &missing_status) {
            Ok(()) => bail!("console user missing status was admitted"),
            Err(err) => err,
        };
        ensure!(
            matches!(err, MgmtError::Admission(ref message) if message.contains("status")),
            "unexpected missing status admission error: {err:?}"
        );

        let mut map = (complete_console_user("ops")?)
            .into_map()
            .context("expected map")?;
        map.remove("authn");
        let missing_authn = Value::from(map);
        let err = match admit_console_user("ops", &missing_authn) {
            Ok(()) => bail!("console user missing authn was admitted"),
            Err(err) => err,
        };
        ensure!(
            matches!(err, MgmtError::Admission(ref message) if message.contains("authn")),
            "unexpected missing authn admission error: {err:?}"
        );

        let mut map = (complete_console_user("ops")?)
            .into_map()
            .context("expected map")?;
        map.insert(
            "identity_path".into(),
            Value::string("identity://console/**".into()),
        )?;
        let wildcard_identity = Value::from(map);
        ensure!(
            admit_console_user("ops", &wildcard_identity).is_err(),
            "wildcard console identity path was admitted"
        );

        let mut map = (complete_console_user("ops")?)
            .into_map()
            .context("expected map")?;
        map.insert(
            "identity_path".into(),
            Value::string("path://remote/identity/console/ops".into()),
        )?;
        let clustered_identity = Value::from(map);
        ensure!(
            admit_console_user("ops", &clustered_identity).is_err(),
            "clustered console identity path was admitted"
        );

        let mut map = (complete_console_user("ops")?)
            .into_map()
            .context("expected map")?;
        map.insert("status".into(), Value::string("locked".into()))?;
        let locked = Value::from(map);
        admit_console_user("ops", &locked).context("locked console user status was rejected")?;
        Ok(())
    }

    #[test]
    fn console_role_admission_rejects_malformed_grants() -> anyhow::Result<()> {
        let mut role = BTreeMap::new();
        role.insert(
            "grants".into(),
            Value::list(vec![Value::string("not-a-capability".into())]),
        );

        let err = match admit_console_role(&Value::map(role)) {
            Ok(()) => bail!("console role with malformed grant was admitted"),
            Err(err) => err,
        };
        ensure!(
            matches!(err, MgmtError::Admission(ref message) if message.contains("console role.grants")),
            "unexpected console role admission error: {err:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn generic_config_write_rejects_dedicated_runtime_paths() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        expect_admission_message(
            write_config(
                &st,
                &root,
                "state://kernel/external-installations/acme",
                extension_installation("acme", 0)?,
                None,
            )
            .await,
            "runtime config path must use its dedicated console action",
        )?;
        expect_admission_message(
            write_config(
                &st,
                &root,
                "state://kernel/projection-status/in-process/fetch",
                obj(None),
                None,
            )
            .await,
            "runtime config path must use its dedicated console action",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn generic_config_manages_in_process_projection_declarations() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let path = "state://kernel/projections/in-process/fetch";
        write_config(&st, &root, path, in_process_projection("fetch", 0)?, None).await?;
        let value = inspect_config(&st, &root, path)
            .await?
            .context("in-process projection config missing")?;
        ensure!(
            value_version(&value)? == Some(1),
            "projection config version was not initialized"
        );
        let entries = inspect_config_prefix(&st, &root, "state://kernel/projections").await?;
        ensure!(
            entries.iter().any(|(entry_path, _)| entry_path == path),
            "projection config prefix did not include written declaration"
        );
        Ok(())
    }

    #[tokio::test]
    async fn generic_config_read_rejects_dedicated_runtime_paths() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        expect_admission_message(
            inspect_config(&st, &root, "state://kernel/external-installations/acme").await,
            "runtime config path must use its dedicated console action",
        )?;
        expect_admission_message(
            inspect_config_prefix(&st, &root, "state://kernel/inference/backends").await,
            "runtime config path must use its dedicated console action",
        )?;
        expect_admission_message(
            inspect_config_prefix(&st, &root, "state://kernel").await,
            "runtime config path must use its dedicated console action",
        )?;
        expect_admission_message(
            inspect_config_prefix(&st, &root, "state://kernel/routing").await,
            "runtime config path must use its dedicated console action",
        )?;
        expect_admission_message(
            inspect_config_prefix(&st, &root, "state://kernel/projection-status").await,
            "runtime config path must use its dedicated console action",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_config_write_rejects_generic_paths() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        expect_admission_message(
            write_dedicated_config(&st, &root, "state://kernel/audit/rules", obj(None), None).await,
            "dedicated console action cannot write generic config path",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn install_then_reconfigure_with_cas() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let path = "state://kernel/external-installations/acme";
        write_dedicated_config(&st, &root, path, extension_installation("acme", 0)?, None).await?;
        let v = inspect(&st, &root, path)
            .await?
            .context("installed config missing")?;
        ensure!(
            value_version(&v)? == Some(1),
            "initial install did not advance version to 1"
        );
        write_dedicated_config(
            &st,
            &root,
            path,
            extension_installation("acme", 1)?,
            Some(1),
        )
        .await?;
        let v = inspect(&st, &root, path)
            .await?
            .context("reconfigured config missing")?;
        ensure!(
            value_version(&v)? == Some(2),
            "reconfigure did not advance version to 2"
        );
        let stale = write_dedicated_config(
            &st,
            &root,
            path,
            extension_installation("acme", 1)?,
            Some(1),
        )
        .await;
        ensure!(
            matches!(stale, Err(MgmtError::Conflict { .. })),
            "stale CAS write did not conflict"
        );
        Ok(())
    }

    #[tokio::test]
    async fn write_rejects_existing_negative_config_version() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let path = Path::parse("state://kernel/external-installations/acme")?;
        let mut map = (extension_installation("acme", 0)?)
            .into_map()
            .context("expected map")?;
        map.insert("version".into(), Value::integer(-1))?;
        let existing = Value::from(map);
        st.state.write_cas(&path, None, existing).await?;
        let path = path.to_string();

        expect_admission_message(
            write_dedicated_config(
                &st,
                &root,
                &path,
                extension_installation("acme", 1)?,
                Some(1),
            )
            .await,
            "config version must be nonnegative",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn extension_installation_admission_supports_multi_projection_package()
    -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let path = "state://kernel/external-installations/instant_messaging_platform";
        write_dedicated_config(
            &st,
            &root,
            path,
            instant_messaging_platform_installation(0)?,
            None,
        )
        .await?;
        let v = inspect(&st, &root, path)
            .await?
            .context("multi-projection installation missing")?;
        ensure!(
            value_version(&v)? == Some(1),
            "multi-projection install did not advance version"
        );

        let mut map = instant_messaging_platform_installation(0)?
            .into_map()
            .context("installation map")?;
        let mut projections = map
            .remove("projections")
            .and_then(Value::into_list)
            .context("projections")?;
        let mut provider = projections
            .get(1)
            .and_then(Value::as_map)
            .cloned()
            .context("provider projection")?;
        provider.insert(
            "provides".into(),
            Value::list(vec![serde_json::from_value(serde_json::json!({
                "effect_path": "effect://external-provider/other/send_text",
                "purity": "effectful"
            }))?]),
        )?;
        projections.set(1, Value::from(provider))?;
        map.insert("projections".into(), Value::from(projections))?;
        let bad = Value::from(map);
        expect_admission(write_dedicated_config(&st, &root, path, bad, Some(1)).await)?;
        Ok(())
    }

    #[tokio::test]
    async fn inference_backend_admission_requires_path_id_and_vault_secret_ref()
    -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        write_dedicated_config(
            &st,
            &root,
            "state://kernel/inference/backends/deepseek",
            inference_backend("deepseek")?,
            None,
        )
        .await?;

        expect_admission(
            write_dedicated_config(
                &st,
                &root,
                "state://kernel/inference/backends/other",
                inference_backend("deepseek")?,
                None,
            )
            .await,
        )?;

        let mut map = inference_backend("bad")?
            .into_map()
            .context("backend map")?;
        map.insert(
            "auth".into(),
            serde_json::from_value(serde_json::json!({
                "kind": "bearer_token",
                "token_ref": "state://kernel/inference/bad/api_key"
            }))?,
        )?;
        let bad = Value::from(map);
        expect_admission(
            write_dedicated_config(
                &st,
                &root,
                "state://kernel/inference/backends/bad",
                bad,
                None,
            )
            .await,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn unknown_kernel_config_paths_are_rejected() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        expect_admission(
            write_config(&st, &root, "state://kernel/unknown/x", obj(None), None).await,
        )?;
        Ok(())
    }
}
