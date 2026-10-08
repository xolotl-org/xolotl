//! Kernel management helpers used by the Console Protocol host.
//!
//! These functions are the read/write projection for manageable
//! `state://kernel/*` configuration. Broader protocol actions such as
//! visibility, authority inspection, lineage, health, pairing, and stream
//! dispatch live in `service`/`protocol` and call into this module for kernel
//! management state.

use crate::auth::{self, ConsolePrincipal};
use crate::paths as resource_paths;
use crate::state::ConsoleState;
use serde::de::DeserializeOwned;
use std::sync::Arc;
use thiserror::Error;
use xolotl_types::{AuditRules, Capability, Path, Value, ValueMap, ValueView};

mod config;
mod page;
mod paths;

pub(crate) use config::ConfigAdmissionRegistry;
pub use config::{ConfigAdmissionConfigError, ConfigNamespaceAdmission};
pub(crate) use page::{ListRequest, ManagementPage, encode_cursor, state_scan};
pub(crate) use paths::is_dedicated_management_path;

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
        /// Version observed by the comparison, when representable.
        current_version: Option<u64>,
    },
    /// An installation incarnation or its declaration version changed.
    #[error("installation revision conflict: expected {expected:?}, current {current:?}")]
    InstallationConflict {
        /// Complete revision expected by the caller; `None` means absent.
        expected: Option<xolotl_source::ExternalInstallationRevision>,
        /// Complete revision observed by the storage owner.
        current: Option<xolotl_source::ExternalInstallationRevision>,
    },
    /// Config admission rejected the proposed value.
    #[error("config admission rejected: {0}")]
    Admission(String),
    /// No blocking-work slot was available before host validation started.
    #[error("config validation capacity exceeded")]
    ValidationAtCapacity,
    /// Invalid or over-budget management query.
    #[error("management query rejected: {0}")]
    Query(String),
    /// Underlying state operation failed.
    #[error("operation failed: {0}")]
    Operation(String),
}

/// Only local descendants of `state://kernel` are manageable here.
fn ensure_manageable(path: &Path) -> Result<(), MgmtError> {
    if !paths::is_local_kernel_state_subtree(path) {
        return Err(MgmtError::NotManageable(path.to_string()));
    }
    Ok(())
}

/// Read a management config value.
pub(crate) async fn inspect(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: &Path,
) -> Result<Option<Value>, MgmtError> {
    ensure_manageable(path)?;
    auth::authorize_path(&state.state, principal, "read", path, None).await?;
    state
        .state
        .read(path)
        .await
        .map_err(|error| MgmtError::Operation(error.to_string()))
}

/// Read a config value through the generic config action family.
pub(crate) async fn inspect_config(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: &Path,
) -> Result<Option<Value>, MgmtError> {
    reject_dedicated_management_path(path)?;
    inspect(state, principal, path).await
}

/// List the keys under a management prefix (inspect a subtree).
pub(crate) async fn inspect_prefix(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    prefix: Path,
    request: ListRequest,
) -> Result<ManagementPage, MgmtError> {
    ensure_manageable(&prefix)?;
    auth::authorize_prefix_read(&state.state, principal, &prefix).await?;
    page::read(state, principal, prefix, request).await
}

/// List config values through the generic config action family.
pub(crate) async fn inspect_config_prefix(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    prefix: Path,
    request: ListRequest,
) -> Result<ManagementPage, MgmtError> {
    reject_dedicated_management_prefix(&prefix)?;
    inspect_prefix(state, principal, prefix, request).await
}

/// Change config with a CAS state write on the expected prior version.
/// `expected_version` of `None` means "create if absent" (install);
/// `Some(v)` means "update only if current version == v" (reconfigure). The
/// value's `version` field is bumped on write.
pub(crate) async fn write_config(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: Path,
    value: Value,
    expected_version: Option<u64>,
) -> Result<(), MgmtError> {
    if is_dedicated_management_path(&path) {
        return Err(MgmtError::Admission(
            "management path must use its dedicated console action".into(),
        ));
    }
    write_config_inner(state, principal, path, value, expected_version).await
}

/// Change config for a path owned by a dedicated Console action family.
pub(crate) async fn write_dedicated_config(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: Path,
    value: Value,
    expected_version: Option<u64>,
) -> Result<(), MgmtError> {
    if paths::is_external_installation_subtree(&path) {
        return Err(MgmtError::Admission(
            "external installations are owned by the storage catalog".into(),
        ));
    }
    if !is_dedicated_management_path(&path) {
        return Err(MgmtError::Admission(
            "dedicated console action cannot write generic config path".into(),
        ));
    }
    write_config_inner(state, principal, path, value, expected_version).await
}

async fn write_config_inner(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    p: Path,
    mut value: Value,
    expected_version: Option<u64>,
) -> Result<(), MgmtError> {
    ensure_manageable(&p)?;
    auth::authorize_path(&state.state, principal, "write", &p, None).await?;

    let current = state
        .state
        .read(&p)
        .await
        .map_err(|error| MgmtError::Operation(error.to_string()))?;
    // Host-installed records without a Console version start at revision zero.
    // Create-only calls must not overwrite an existing record.
    let current_version = current
        .as_ref()
        .map(|value| value_version(value).map(|version| version.unwrap_or(0)))
        .transpose()?;
    if current_version != expected_version {
        return Err(MgmtError::Conflict {
            expected: expected_version,
            current_version,
        });
    }

    auth::prepare_user_config(
        &p,
        current.as_ref(),
        &mut value,
        principal,
        state.boot.kernel().host_runtime().now_millis(),
    )?;
    auth::authorize_path(&state.state, principal, "write", &p, Some(&value)).await?;

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
            error: xolotl_state::StateError::CasFailed { actual, .. },
            ..
        }) => {
            return Err(MgmtError::Conflict {
                expected: expected_version,
                // Use the commit's observation, never a later read. Malformed
                // versions must not mask the conflict or expose the raw value.
                current_version: actual
                    .as_deref()
                    .and_then(|value| value_version(value).ok().map(|v| v.unwrap_or(0))),
            });
        }
        Err(error) => return Err(MgmtError::Operation(error.to_string())),
    }
    Ok(())
}

fn reject_dedicated_management_path(path: &Path) -> Result<(), MgmtError> {
    if is_dedicated_management_path(path) {
        return Err(MgmtError::Admission(
            "management path must use its dedicated console action".into(),
        ));
    }
    Ok(())
}

fn reject_dedicated_management_prefix(path: &Path) -> Result<(), MgmtError> {
    if paths::contains_dedicated_management_subtree(path) {
        return Err(MgmtError::Admission(
            "management path must use its dedicated console action".into(),
        ));
    }
    Ok(())
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
    let mut map = v
        .as_map()
        .cloned()
        .ok_or_else(|| MgmtError::Admission("versioned config must be an object".into()))?;
    let version = i64::try_from(version)
        .map_err(|_error| MgmtError::Admission("config version exceeds i64".into()))?;
    map.insert("version".into(), Value::integer(version))
        .map_err(|error| MgmtError::Admission(error.to_string()))?;
    *v = Value::from(map);
    Ok(())
}

async fn admit_kernel_config(
    state: &Arc<ConsoleState>,
    path: &Path,
    value: &mut Value,
) -> Result<(), MgmtError> {
    let segs = path.segments();
    if !resource_paths::is_local_kernel_path(path) {
        return Err(MgmtError::NotManageable(path.to_string()));
    }

    match segs {
        s if resource_paths::is_user_record_path(path) => {
            let username = required_tail(s, "console username")?;
            auth::validate_username(username)
                .map_err(|e| MgmtError::Admission(format!("invalid console user path: {e}")))?;
            admit_console_user(username, value)
        }
        s if resource_paths::is_role_record_path(path) => {
            let role = required_tail(s, "console role")?;
            auth::validate_username(role)
                .map_err(|e| MgmtError::Admission(format!("invalid console role path: {e}")))?;
            admit_console_role(value)
        }
        s if is_exact_path(s, &["kernel", "audit", "rules"]) => {
            decode_config_value::<AuditRules>(value, "AuditRules")?;
            Ok(())
        }
        _ => {
            let validator = state
                .config_admissions
                .validator(path)
                .map_err(MgmtError::Admission)?;
            // Value clones share their immutable representation. The accepted
            // worker owns its inputs even if this caller stops waiting; only
            // this async path can perform the subsequent State CAS.
            let owned_path = path.clone();
            let owned_value = value.clone();
            let validation =
                xolotl_kernel::host::blocking::dispatch(state.blocking_spawner(), move || {
                    validator(&owned_path, &owned_value)
                })
                .map_err(|error| match error {
                    xolotl_kernel::host::BlockingSpawnError::AtCapacity => {
                        MgmtError::ValidationAtCapacity
                    }
                    xolotl_kernel::host::BlockingSpawnError::Unavailable => {
                        MgmtError::Operation("config validation worker is unavailable".into())
                    }
                })?;
            validation
                .await
                .map_err(|error| {
                    MgmtError::Operation(format!("config validation worker failed: {error}"))
                })?
                .map_err(MgmtError::Admission)
        }
    }
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
            "account_id",
            "bootstrap_owner",
            "status",
            "roles",
            "grants",
            "authority_ceiling",
            "created_by",
            "created_at",
        ],
        "console user",
    )?;
    optional_nonnegative_int(map, "version", "console user")?;
    required_string(map, "account_id", "console user")?;
    if !matches!(
        map.get("bootstrap_owner").map(Value::view),
        Some(ValueView::Bool(_))
    ) {
        return Err(MgmtError::Admission(
            "console user.bootstrap_owner must be a bool".into(),
        ));
    }
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
    for role in required_string_list(map, "roles", "console user")? {
        auth::validate_username(role)
            .map_err(|e| MgmtError::Admission(format!("console user role: {e}")))?;
    }
    validate_required_capability_list(map, "grants", "console user")?;
    validate_required_capability_list(map, "authority_ceiling", "console user")?;
    required_string(map, "created_by", "console user")?;
    required_nonnegative_int(map, "created_at", "console user")?;
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
    use std::sync::Mutex;
    use std::time::Duration;
    use tokio::sync::Notify;
    use xolotl_kernel::Bootstrap;
    use xolotl_kernel::host::{BlockingJob, BlockingSpawnError, BlockingSpawner};
    use xolotl_standard::{StandardConfig, install_standard};
    use xolotl_types::{
        EffectCapability, InProcessProjectionDef, InferenceApiDialect, InferenceAuthRef,
        InferenceBackendDef, Purity, Role,
    };

    struct RejectBlockingWork;

    impl BlockingSpawner for RejectBlockingWork {
        fn spawn(&self, _job: BlockingJob) -> Result<(), BlockingSpawnError> {
            Err(BlockingSpawnError::AtCapacity)
        }
    }

    fn console_state() -> anyhow::Result<Arc<ConsoleState>> {
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default())?;
        let config = crate::ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            config_admissions: vec![
                ConfigNamespaceAdmission::new(
                    Path::parse("state://kernel/projections/in-process")?,
                    |path, value| {
                        let id = xolotl_types::in_process_projection::in_process_projection_declaration_id(path)
                            .ok_or_else(|| "invalid projection path".to_string())?;
                        let document: InProcessProjectionDef = serde_json::from_value(
                            serde_json::to_value(value)
                                .map_err(|error| format!("malformed projection: {error}"))?,
                        )
                        .map_err(|error| format!("malformed projection: {error}"))?;
                        document
                            .validate_admission(id)
                            .map_err(|error| format!("invalid projection: {error}"))
                    },
                ),
                ConfigNamespaceAdmission::new(
                    Path::parse("state://kernel/inference/backends")?,
                    |path, value| {
                        let id = xolotl_types::inference::InferenceDeclarationKind::Backend
                            .id(path)
                            .ok_or_else(|| "invalid inference backend path".to_string())?;
                        let document: InferenceBackendDef = serde_json::from_value(
                            serde_json::to_value(value)
                                .map_err(|error| format!("malformed inference backend: {error}"))?,
                        )
                        .map_err(|error| format!("malformed inference backend: {error}"))?;
                        document
                            .validate_admission(id)
                            .map_err(|error| format!("invalid inference backend: {error}"))
                    },
                ),
            ],
            ..Default::default()
        };
        Ok(ConsoleState::with_config(boot, config)?)
    }

    fn obj(version: Option<u64>) -> Value {
        let mut m = BTreeMap::new();
        m.insert("transport".into(), Value::string("stdio".into()));
        if let Some(v) = version {
            m.insert("version".into(), Value::integer(v as i64));
        }
        Value::map(m)
    }

    fn complete_console_user(_username: &str) -> anyhow::Result<Value> {
        let mut user = BTreeMap::new();
        user.insert("account_id".into(), Value::string("test-account".into()));
        user.insert("bootstrap_owner".into(), Value::boolean(false));
        user.insert(
            "identity_path".into(),
            Value::string("identity://console/accounts/test-account".into()),
        );
        user.insert("status".into(), Value::string("active".into()));
        user.insert("roles".into(), Value::list(Vec::new()));
        user.insert("grants".into(), Value::list(Vec::new()));
        user.insert("authority_ceiling".into(), Value::list(Vec::new()));
        user.insert("created_by".into(), Value::string("test".into()));
        user.insert("created_at".into(), Value::integer(1));
        Ok(Value::map(user))
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

    async fn root_principal(st: &Arc<ConsoleState>) -> anyhow::Result<ConsolePrincipal> {
        let outcome =
            bootstrap_root_account(&st.boot, st.blocking_spawner(), RootProvisioning::default())
                .await?;
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
                    second_factor: None,
                },
                "test".into(),
            )
            .await?
            .into_session()
            .ok()
            .context("authenticated session")?;
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
        expect_not_manageable(inspect(&st, &root, &Path::parse("state://memory/alice")?).await)?;
        expect_not_manageable(
            inspect_config(
                &st,
                &root,
                &Path::parse("path://remote/state/kernel/projections/in-process/fetch")?,
            )
            .await,
        )?;
        expect_not_manageable(
            write_config(
                &st,
                &root,
                Path::parse("state://vault/secret")?,
                obj(None),
                None,
            )
            .await,
        )?;
        expect_not_manageable(
            write_config(
                &st,
                &root,
                Path::parse("path://remote/state/kernel/projections/in-process/fetch")?,
                in_process_projection("fetch", 0)?,
                None,
            )
            .await,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn exact_prefix_read_cannot_list_descendants_or_receive_a_cursor() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let prefix = Path::parse("state://kernel/config/list-boundary")?;
        let child = Path::parse("state://kernel/config/list-boundary/private")?;
        st.state
            .write_set(&prefix, Value::string("public".into()))
            .await?;
        st.state
            .write_set(&child, Value::string("private".into()))
            .await?;

        let mut exact = root.clone();
        exact.grants =
            xolotl_types::CapSet::from_strs(["read://state/kernel/config/list-boundary"])?;
        ensure!(inspect(&st, &exact, &prefix).await? == Some(Value::string("public".into())));
        ensure!(matches!(
            inspect(&st, &exact, &child).await,
            Err(MgmtError::Auth(auth::AuthError::PermissionDenied))
        ));
        ensure!(matches!(
            inspect_config_prefix(
                &st,
                &exact,
                prefix.clone(),
                ListRequest {
                    limit: Some(1),
                    ..Default::default()
                },
            )
            .await,
            Err(MgmtError::Auth(auth::AuthError::PermissionDenied))
        ));

        let mut subtree = root;
        subtree.grants =
            xolotl_types::CapSet::from_strs(["read://state/kernel/config/list-boundary/**"])?;
        let page = inspect_config_prefix(&st, &subtree, prefix, ListRequest::default()).await?;
        ensure!(
            page.entries
                .iter()
                .any(|(path, _)| path == &child.to_string())
        );
        ensure!(page.next_cursor.is_none());
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
        map.insert("authn".into(), Value::map(BTreeMap::new()))?;
        let injected_credentials = Value::from(map);
        ensure!(
            admit_console_user("ops", &injected_credentials).is_err(),
            "credential data must not be accepted by account metadata writes"
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
                Path::parse("state://kernel/external-installations/acme")?,
                obj(None),
                None,
            )
            .await,
            "management path must use its dedicated console action",
        )?;
        expect_admission_message(
            write_config(
                &st,
                &root,
                Path::parse("state://kernel/projection-status/in-process/fetch")?,
                obj(None),
                None,
            )
            .await,
            "management path must use its dedicated console action",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn generic_config_manages_in_process_projection_declarations() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let path = "state://kernel/projections/in-process/fetch";
        write_config(
            &st,
            &root,
            Path::parse(path)?,
            in_process_projection("fetch", 0)?,
            None,
        )
        .await?;
        let value = inspect_config(&st, &root, &Path::parse(path)?)
            .await?
            .context("in-process projection config missing")?;
        ensure!(
            value_version(&value)? == Some(1),
            "projection config version was not initialized"
        );
        let entries = inspect_config_prefix(
            &st,
            &root,
            Path::parse("state://kernel/projections")?,
            ListRequest::default(),
        )
        .await?;
        ensure!(
            entries
                .entries
                .iter()
                .any(|(entry_path, _)| entry_path == path),
            "projection config prefix did not include written declaration"
        );
        Ok(())
    }

    #[tokio::test]
    async fn embedding_host_can_admit_its_own_config_namespace() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default())?;
        let st = ConsoleState::with_config(
            boot,
            crate::ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                config_admissions: vec![ConfigNamespaceAdmission::new(
                    Path::parse("state://kernel/config/example")?,
                    |path, value| {
                        if path.segments().len() != 4 {
                            return Err("expected a direct config child".into());
                        }
                        if value
                            .as_map()
                            .and_then(|map| map.get("enabled"))
                            .and_then(Value::as_bool)
                            != Some(true)
                        {
                            return Err("enabled must be true".into());
                        }
                        Ok(())
                    },
                )],
                ..crate::ConsoleConfig {
                    session_store: Some(std::sync::Arc::new(
                        crate::session_store::MemoryConsoleSessionStore::new(
                            crate::session_store::ConsoleSessionPolicy::default(),
                        ),
                    )),
                    ..Default::default()
                }
            },
        )?;
        let root = root_principal(&st).await?;
        let path = Path::parse("state://kernel/config/example/feature")?;
        let value = Value::map(BTreeMap::from([("enabled".into(), Value::boolean(true))]));
        write_config(&st, &root, path.clone(), value.clone(), None).await?;
        ensure!(
            inspect_config(&st, &root, &path)
                .await?
                .and_then(|value| value_version(&value).ok().flatten())
                == Some(1)
        );
        expect_admission_message(
            write_config(
                &st,
                &root,
                Path::parse("state://kernel/config/example/feature/child")?,
                value.clone(),
                None,
            )
            .await,
            "expected a direct config child",
        )?;
        expect_admission_message(
            write_config(
                &st,
                &root,
                Path::parse("state://kernel/config/other/feature")?,
                value,
                None,
            )
            .await,
            "no console write admission rule for state://kernel/config/other/feature",
        )?;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn host_config_validation_does_not_block_async_calls_or_write_on_rejection()
    -> anyhow::Result<()> {
        let base = console_state()?;
        let root = root_principal(&base).await?;
        let entered = Arc::new(Notify::new());
        let (release, wait_for_release) = std::sync::mpsc::channel::<()>();
        let wait_for_release = Mutex::new(wait_for_release);
        let signaller = Arc::clone(&entered);
        let state = ConsoleState::with_config(
            Arc::clone(&base.boot),
            crate::ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                config_admissions: vec![ConfigNamespaceAdmission::new(
                    Path::parse("state://kernel/config/example")?,
                    move |_path, _value| {
                        signaller.notify_one();
                        wait_for_release
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .recv_timeout(Duration::from_secs(2))
                            .map_err(|_error| "validation gate closed".to_string())?;
                        Err("host rejected the value".into())
                    },
                )],
                ..crate::ConsoleConfig {
                    session_store: Some(std::sync::Arc::new(
                        crate::session_store::MemoryConsoleSessionStore::new(
                            crate::session_store::ConsoleSessionPolicy::default(),
                        ),
                    )),
                    ..Default::default()
                }
            },
        )?;
        let path = Path::parse("state://kernel/config/example/feature")?;
        let write = tokio::spawn({
            let state = Arc::clone(&state);
            let path = path.clone();
            async move { write_config(&state, &root, path, Value::map(BTreeMap::new()), None).await }
        });
        tokio::time::timeout(Duration::from_secs(3), entered.notified()).await?;
        // This test has one async worker. Both the timer and a concurrent State
        // read must still progress while the host's synchronous validator waits.
        ensure!(
            tokio::time::timeout(Duration::from_secs(1), state.state.read(&path))
                .await??
                .is_none()
        );
        release.send(())?;
        let result = tokio::time::timeout(Duration::from_secs(3), write).await??;
        ensure!(
            matches!(result, Err(MgmtError::Admission(reason)) if reason == "host rejected the value")
        );
        ensure!(state.state.read(&path).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn rejected_config_validation_dispatch_does_not_write_state() -> anyhow::Result<()> {
        let base = console_state()?;
        let root = root_principal(&base).await?;
        let state = ConsoleState::with_config(
            Arc::clone(&base.boot),
            crate::ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                blocking_spawner: Some(Arc::new(RejectBlockingWork)),
                config_admissions: vec![ConfigNamespaceAdmission::new(
                    Path::parse("state://kernel/config/example")?,
                    |_path, _value| Ok(()),
                )],
                ..crate::ConsoleConfig {
                    session_store: Some(std::sync::Arc::new(
                        crate::session_store::MemoryConsoleSessionStore::new(
                            crate::session_store::ConsoleSessionPolicy::default(),
                        ),
                    )),
                    ..Default::default()
                }
            },
        )?;
        let path = Path::parse("state://kernel/config/example/feature")?;
        let result = write_config(
            &state,
            &root,
            path.clone(),
            Value::map(BTreeMap::new()),
            None,
        )
        .await;
        ensure!(matches!(result, Err(MgmtError::ValidationAtCapacity)));
        ensure!(state.state.read(&path).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn generic_config_read_rejects_dedicated_runtime_paths() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        expect_admission_message(
            inspect_config(
                &st,
                &root,
                &Path::parse("state://kernel/external-installations/acme")?,
            )
            .await,
            "management path must use its dedicated console action",
        )?;
        expect_admission_message(
            inspect_config_prefix(
                &st,
                &root,
                Path::parse("state://kernel/inference/backends")?,
                ListRequest::default(),
            )
            .await,
            "management path must use its dedicated console action",
        )?;
        expect_admission_message(
            inspect_config_prefix(
                &st,
                &root,
                Path::parse("state://kernel")?,
                ListRequest::default(),
            )
            .await,
            "management path must use its dedicated console action",
        )?;
        expect_admission_message(
            inspect_config_prefix(
                &st,
                &root,
                Path::parse("state://kernel/routing")?,
                ListRequest::default(),
            )
            .await,
            "management path must use its dedicated console action",
        )?;
        expect_admission_message(
            inspect_config_prefix(
                &st,
                &root,
                Path::parse("state://kernel/projection-status")?,
                ListRequest::default(),
            )
            .await,
            "management path must use its dedicated console action",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_config_write_rejects_generic_paths() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        expect_admission_message(
            write_dedicated_config(
                &st,
                &root,
                Path::parse("state://kernel/audit/rules")?,
                obj(None),
                None,
            )
            .await,
            "dedicated console action cannot write generic config path",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn install_then_reconfigure_with_cas() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let path = "state://kernel/projections/in-process/fetch";
        write_config(
            &st,
            &root,
            Path::parse(path)?,
            in_process_projection("fetch", 0)?,
            None,
        )
        .await?;
        let v = inspect(&st, &root, &Path::parse(path)?)
            .await?
            .context("installed config missing")?;
        ensure!(
            value_version(&v)? == Some(1),
            "initial install did not advance version to 1"
        );
        write_config(
            &st,
            &root,
            Path::parse(path)?,
            in_process_projection("fetch", 1)?,
            Some(1),
        )
        .await?;
        let v = inspect(&st, &root, &Path::parse(path)?)
            .await?
            .context("reconfigured config missing")?;
        ensure!(
            value_version(&v)? == Some(2),
            "reconfigure did not advance version to 2"
        );
        let stale = write_config(
            &st,
            &root,
            Path::parse(path)?,
            in_process_projection("fetch", 1)?,
            Some(1),
        )
        .await;
        ensure!(
            matches!(
                stale,
                Err(MgmtError::Conflict {
                    current_version: Some(2),
                    ..
                })
            ),
            "stale CAS write did not conflict"
        );
        Ok(())
    }

    #[tokio::test]
    async fn conflict_uses_commit_observation_even_if_record_changes_again() -> anyhow::Result<()> {
        use xolotl_state::{
            Backend, InMemoryBackend, StateCommit, StateMutation, StateResult, StateWrite,
            StateWriteExt,
        };

        struct ConcurrentWriter {
            inner: Arc<InMemoryBackend>,
            observed: Option<Value>,
        }

        impl StateWrite for ConcurrentWriter {
            type Write<'a> = std::pin::Pin<
                Box<dyn std::future::Future<Output = StateResult<StateCommit>> + Send + 'a>,
            >;

            fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
                Box::pin(async move {
                    if path.to_string() == "state://kernel/projections/in-process/fetch"
                        && matches!(&mutation, StateMutation::CompareSet { .. })
                    {
                        match &self.observed {
                            Some(value) => {
                                self.inner.write_set(path, value.clone()).await?;
                            }
                            None => {
                                self.inner.write_delete(path).await?;
                            }
                        }
                        let comparison = self.inner.mutate(path, mutation).await;
                        self.inner.write_set(path, obj(Some(99))).await?;
                        comparison
                    } else {
                        self.inner.mutate(path, mutation).await
                    }
                })
            }
        }

        let malformed = Value::map(BTreeMap::from([(
            "version".into(),
            Value::string("private malformed value".into()),
        )]));
        for (observed, expected_hint) in [
            (Some(obj(Some(2))), Some(2)),
            (Some(obj(None)), Some(0)),
            (None, None),
            (Some(malformed), None),
        ] {
            let writer = Arc::new(ConcurrentWriter {
                inner: Arc::new(InMemoryBackend::default()),
                observed,
            });
            let backend = Backend::new()
                .with_read(writer.inner.clone())
                .with_bounded_read(writer.inner.clone())
                .with_write(writer.clone())
                .with_bounded_write(writer.inner.clone())
                .with_query(writer.inner.clone());
            let (facts, _) = xolotl_kernel::FactSink::in_memory();
            let boot = Arc::new(Bootstrap::from_kernel(
                xolotl_kernel::KernelBuilder::new(backend)
                    .with_fact_sink(facts)
                    .build(),
            ));
            install_standard(&boot, &StandardConfig::default())?;
            let st = ConsoleState::with_config(
                boot,
                crate::ConsoleConfig {
                    session_store: Some(std::sync::Arc::new(
                        crate::session_store::MemoryConsoleSessionStore::new(
                            crate::session_store::ConsoleSessionPolicy::default(),
                        ),
                    )),
                    config_admissions: vec![ConfigNamespaceAdmission::new(
                        Path::parse("state://kernel/projections/in-process")?,
                        |_path, _value| Ok(()),
                    )],
                    ..crate::ConsoleConfig {
                        session_store: Some(std::sync::Arc::new(
                            crate::session_store::MemoryConsoleSessionStore::new(
                                crate::session_store::ConsoleSessionPolicy::default(),
                            ),
                        )),
                        ..Default::default()
                    }
                },
            )?;
            let root = root_principal(&st).await?;
            let path = Path::parse("state://kernel/projections/in-process/fetch")?;
            st.state
                .write_set(&path, in_process_projection("fetch", 1)?)
                .await?;
            let error = write_config(
                &st,
                &root,
                path.clone(),
                in_process_projection("fetch", 1)?,
                Some(1),
            )
            .await
            .err()
            .context("expected commit conflict")?;
            let failure = crate::ConsoleFailure::from(crate::service::ConsoleError::from(error));
            ensure!(failure.code == crate::ConsoleErrorCode::Conflict);
            ensure!(failure.current_version == expected_hint);
            ensure!(
                value_version(&st.state.read(&path).await?.context("later write")?)? == Some(99)
            );
            ensure!(!serde_json::to_string(&failure)?.contains("private malformed value"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn create_only_cannot_overwrite_unversioned_record() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let path = Path::parse("state://kernel/console/users/alice")?;
        let existing = complete_console_user("alice")?;
        st.state.write_cas(&path, None, existing.clone()).await?;
        let result = write_dedicated_config(&st, &root, path.clone(), existing.clone(), None).await;
        ensure!(matches!(
            result,
            Err(MgmtError::Conflict {
                current_version: Some(0),
                ..
            })
        ));
        ensure!(st.state.read(&path).await? == Some(existing.clone()));
        write_dedicated_config(&st, &root, path.clone(), existing, Some(0)).await?;
        let value = st.state.read(&path).await?.context("missing user")?;
        ensure!(value_version(&value)? == Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn management_pages_resume_without_loading_the_whole_prefix() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let prefix = "state://kernel/paging-test";
        for id in 0..5 {
            st.state
                .write_set(&Path::parse(&format!("{prefix}/{id}"))?, obj(Some(1)))
                .await?;
        }
        let mut cursor = None;
        let mut paths = Vec::new();
        loop {
            let page = inspect_config_prefix(
                &st,
                &root,
                Path::parse(prefix)?,
                ListRequest {
                    limit: Some(2),
                    cursor,
                    ..Default::default()
                },
            )
            .await?;
            ensure!(page.entries.len() <= 2);
            paths.extend(page.entries.into_iter().map(|(path, _)| path));
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        ensure!(
            paths
                == (0..5)
                    .map(|id| format!("{prefix}/{id}"))
                    .collect::<Vec<_>>()
        );
        for request in [
            ListRequest {
                limit: Some(0),
                ..Default::default()
            },
            ListRequest {
                max_bytes: Some(0),
                ..Default::default()
            },
            ListRequest {
                cursor: Some("%%%".into()),
                ..Default::default()
            },
        ] {
            ensure!(matches!(
                inspect_config_prefix(&st, &root, Path::parse(prefix)?, request).await,
                Err(MgmtError::Query(_))
            ));
        }
        let first = inspect_config_prefix(
            &st,
            &root,
            Path::parse(prefix)?,
            ListRequest {
                limit: Some(1),
                ..Default::default()
            },
        )
        .await?;
        ensure!(matches!(
            inspect_config_prefix(
                &st,
                &root,
                Path::parse("state://kernel/another-prefix")?,
                ListRequest {
                    cursor: first.next_cursor,
                    ..Default::default()
                }
            )
            .await,
            Err(MgmtError::Query(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn management_pages_enforce_byte_budget() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let prefix = "state://kernel/paging-bytes";
        st.state
            .write_set(
                &Path::parse(&format!("{prefix}/large"))?,
                Value::string("x".repeat(4096)),
            )
            .await?;
        ensure!(matches!(
            inspect_config_prefix(
                &st,
                &root,
                Path::parse(prefix)?,
                ListRequest {
                    max_bytes: Some(128),
                    ..Default::default()
                }
            )
            .await,
            Err(MgmtError::Query(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn write_rejects_existing_negative_config_version() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let path = Path::parse("state://kernel/projections/in-process/fetch")?;
        let mut map = (in_process_projection("fetch", 0)?)
            .into_map()
            .context("expected map")?;
        map.insert("version".into(), Value::integer(-1))?;
        let existing = Value::from(map);
        st.state.write_cas(&path, None, existing).await?;
        expect_admission_message(
            write_config(
                &st,
                &root,
                path,
                in_process_projection("fetch", 1)?,
                Some(1),
            )
            .await,
            "config version must be nonnegative",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn legacy_state_installation_write_is_rejected() -> anyhow::Result<()> {
        let st = console_state()?;
        let root = root_principal(&st).await?;
        let path = "state://kernel/external-installations/instant_messaging_platform";
        expect_admission_message(
            write_dedicated_config(&st, &root, Path::parse(path)?, Value::null(), None).await,
            "external installations are owned by the storage catalog",
        )?;
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
            Path::parse("state://kernel/inference/backends/deepseek")?,
            inference_backend("deepseek")?,
            None,
        )
        .await?;

        expect_admission(
            write_dedicated_config(
                &st,
                &root,
                Path::parse("state://kernel/inference/backends/other")?,
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
                Path::parse("state://kernel/inference/backends/bad")?,
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
            write_config(
                &st,
                &root,
                Path::parse("state://kernel/unknown/x")?,
                obj(None),
                None,
            )
            .await,
        )?;
        Ok(())
    }
}
