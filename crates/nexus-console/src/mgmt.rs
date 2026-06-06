//! Management operations (§18.4): the three actions the Web Console performs,
//! all as ordinary capability-bound Operations — no privileged backdoor.
//!
//! | console action      | operation                                            |
//! |---------------------|------------------------------------------------------|
//! | change config       | `Value.write` + `Cas` on `state://kernel/*`          |
//! | inspect runtime     | read `state://kernel/*` / process inspect            |
//! | subscribe to changes| `Sequence.subscribe` on a `state://kernel/*` stream  |
//!
//! Three iron rules (§18.4): no dedicated wire protocol; no non-privileged
//! backdoor (config writes go through CAS so concurrent edits don't silently
//! clobber); the console cannot grant itself an acting identity it wasn't
//! given.

use crate::auth::{self, ConsolePrincipal};
use crate::state::ConsoleState;
use nexus_graph::{DoNode, OperationTemplate};
use nexus_types::{
    AuditRules, ExtensionInstallationDef, ExtensionProjectionDef, IdentityRef, ManifestDef,
    Outcome, OutputMode, Path, ResourceName, TaintSet, TrustLevel, Value,
};
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MgmtError {
    #[error("path is not under the manageable state://kernel/ prefix: {0}")]
    NotManageable(String),
    #[error("path error: {0}")]
    Path(#[from] nexus_types::PathError),
    #[error("auth error: {0}")]
    Auth(#[from] auth::AuthError),
    #[error("version conflict (optimistic concurrency): expected {expected:?}")]
    Conflict { expected: Option<u64> },
    #[error("config admission rejected: {0}")]
    Admission(String),
    #[error("operation failed: {0}")]
    Operation(String),
}

/// Only `state://kernel/*` is manageable from the console (Layer 1 config,
/// §12). The vault and fact prefixes are never writable here (§21.6 / §9.4).
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

/// Read a management config value (inspect, §18.4).
pub async fn inspect(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: &str,
) -> Result<Option<Value>, MgmtError> {
    let p = Path::parse(path)?;
    ensure_manageable(&p)?;
    auth::authorize_path(&state.state, principal, "read", &p, None).await?;
    match run_state_op(state, principal, p, "read", Value::Null).await? {
        Value::Null => Ok(None),
        v => Ok(Some(v)),
    }
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
    let out = run_state_op(state, principal, p, "list", Value::Null).await?;
    let Value::List(entries) = out else {
        return Err(MgmtError::Operation(
            "state list returned non-list outcome".into(),
        ));
    };
    entries
        .into_iter()
        .map(|entry| {
            let Value::Map(mut m) = entry else {
                return Err(MgmtError::Operation("state list entry is not a map".into()));
            };
            let path = match m.remove("path") {
                Some(Value::Str(s)) => s,
                _ => return Err(MgmtError::Operation("state list entry has no path".into())),
            };
            let value = m.remove("value").unwrap_or(Value::Null);
            Ok((path, value))
        })
        .collect()
}

/// Change config: a `Value.write` with `Cas` on the expected prior version
/// (§16.3.5 / §18.4). `expected_version` of `None` means "create if absent"
/// (install); `Some(v)` means "update only if current version == v"
/// (reconfigure). The value's `version` field is bumped on write.
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

    // Read current to verify the optimistic-concurrency version (§24.3).
    let current = match run_state_op(state, principal, p.clone(), "read", Value::Null).await? {
        Value::Null => None,
        v => Some(v),
    };
    let current_version = current.as_ref().and_then(value_version);
    if current_version != expected_version {
        return Err(MgmtError::Conflict {
            expected: expected_version,
        });
    }

    // Bump the version on the new value so the next edit must match it.
    let next = expected_version.map(|v| v + 1).unwrap_or(1);
    set_version(&mut value, next);
    admit_kernel_config(&p, &value)?;

    let mut cas = BTreeMap::new();
    cas.insert("cas".into(), Value::Bool(true));
    cas.insert("expected".into(), current.unwrap_or(Value::Null));
    cas.insert("value".into(), value);
    match run_state_op(state, principal, p, "write", Value::Map(cas)).await {
        Ok(_) => {}
        Err(MgmtError::Operation(msg)) if msg.contains("CAS failed") => {
            return Err(MgmtError::Conflict {
                expected: expected_version,
            });
        }
        Err(e) => return Err(e),
    }
    Ok(())
}

async fn run_state_op(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    path: Path,
    method: &str,
    input: Value,
) -> Result<Value, MgmtError> {
    let target = ResourceName::new(path.clone());
    let identity = Path::parse(&principal.identity_path)
        .ok()
        .map(|p| nexus_kernel::intern_identity(&p))
        .unwrap_or(IdentityRef::ROOT);
    let verb = capability_verb_for_state_method(method);
    let cap = format!("{verb}://{}", capability_target(&path));
    let process = state.boot.spawn_request_process(identity, &[&cap]);
    let handle = state
        .boot
        .open_for(process, &target, verb)
        .map_err(|e| MgmtError::Operation(e.to_string()))?;
    let ex = state.boot.kernel.executor_for(process);
    ex.bind_handle(target.clone(), handle);
    let op = DoNode::Op(OperationTemplate {
        target,
        method: method.into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(input),
    });
    match ex.eval_tainted(&op, TaintSet::author()).await {
        Outcome::Done(v) => Ok(v),
        Outcome::Fail(f) => Err(MgmtError::Operation(f.to_string())),
        Outcome::Short(v) => Ok(v),
    }
}

fn capability_target(path: &Path) -> String {
    path.to_string().replacen("://", "/", 1)
}

fn capability_verb_for_state_method(method: &str) -> &'static str {
    match method {
        "read" | "list" => "read",
        "write" | "append" | "delete" => "write",
        "subscribe" => "subscribe",
        _ => "perform",
    }
}

fn value_version(v: &Value) -> Option<u64> {
    v.as_map()
        .and_then(|m| m.get("version"))
        .and_then(|x| x.as_int())
        .map(|i| i as u64)
}

fn set_version(v: &mut Value, version: u64) {
    if let Value::Map(m) = v {
        m.insert("version".into(), Value::Int(version as i64));
    }
}

fn admit_kernel_config(path: &Path, value: &Value) -> Result<(), MgmtError> {
    let segs = path.segments();
    if path.scheme() != "state" || segs.first().map(|s| s.as_str()) != Some("kernel") {
        return Err(MgmtError::NotManageable(path.to_string()));
    }

    match segs {
        s if is_path(s, &["kernel", "extension-installations"]) => {
            let id = required_tail(s, "extension installation id")?;
            admit_extension_installation(id, value)
        }
        s if is_path_with_tail(s, &["kernel", "extension-projections"], 2) => {
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
    let def: ExtensionInstallationDef = decode_config_value(value, "ExtensionInstallationDef")?;
    if def.id != path_id {
        return Err(MgmtError::Admission(format!(
            "ExtensionInstallationDef.id {:?} does not match path id {:?}",
            def.id, path_id
        )));
    }
    admit_json_schema(
        &def.config_schema,
        "ExtensionInstallationDef.config_schema",
    )?;
    def.validate_admission().map_err(|e| {
        MgmtError::Admission(format!("ExtensionInstallationDef admission failed: {e}"))
    })
}

fn admit_extension_projection<S: AsRef<str>>(segs: &[S], value: &Value) -> Result<(), MgmtError> {
    let installation_id = segs
        .get(2)
        .map(|s| s.as_ref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MgmtError::Admission("missing extension installation id".into()))?;
    let projection_id = segs
        .get(3)
        .map(|s| s.as_ref())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| MgmtError::Admission("missing extension projection id".into()))?;
    let def: ExtensionProjectionDef = decode_config_value(value, "ExtensionProjectionDef")?;
    if def.id != projection_id {
        return Err(MgmtError::Admission(format!(
            "ExtensionProjectionDef.id {:?} does not match path projection {:?}",
            def.id, projection_id
        )));
    }
    def.validate_admission(
        installation_id,
        TrustLevel::Sandboxed,
        &nexus_types::Transport::Grpc { endpoint: None },
    )
    .map_err(|e| MgmtError::Admission(format!("ExtensionProjectionDef admission failed: {e}")))
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
        install_standard(&boot, &StandardConfig::default());
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
        let def = ExtensionInstallationDef {
            id: id.into(),
            platform: id.into(),
            transport: Transport::Stdio {
                command: Some(format!("{id}-plugin")),
                args: vec![],
            },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![ExtensionProjectionDef {
                id: "provider".into(),
                role: Role::Provider,
                namespace: Some(Path::parse(&format!("effect://plugin/{id}")).unwrap()),
                provides: vec![EffectCapability::new(
                    format!("effect://plugin/{id}/search"),
                    Purity::Idempotent,
                )],
                emits: None,
                version: 1,
            }],
            version,
        };
        serde_json::from_value(serde_json::to_value(def).unwrap()).unwrap()
    }

    fn wechat_installation(version: u64) -> Value {
        let def = nexus_types::ExtensionInstallationDef {
            id: "wechat".into(),
            platform: "wechat".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Sandboxed,
            config_schema: Value::Null,
            config: Value::Null,
            projections: vec![
                nexus_types::ExtensionProjectionDef {
                    id: "source".into(),
                    role: Role::Source,
                    namespace: None,
                    provides: vec![],
                    emits: Some(nexus_types::EventSource {
                        sink: Path::parse("state://wechat/events").unwrap(),
                        purity: Purity::Effectful,
                        event_schema: None,
                    }),
                    version: 1,
                },
                nexus_types::ExtensionProjectionDef {
                    id: "provider".into(),
                    role: Role::Provider,
                    namespace: Some(Path::parse("effect://plugin/wechat").unwrap()),
                    provides: vec![EffectCapability::new(
                        "effect://plugin/wechat/send_text",
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
        let path = "state://kernel/extension-installations/acme";
        let before = st
            .boot
            .kernel
            .processes
            .all_ids()
            .into_iter()
            .map(|pid| st.boot.kernel.facts.facts_of(pid).len())
            .sum::<usize>();
        // install: expected None ⇒ creates version 1.
        write_config(&st, &root, path, extension_installation("acme", 0), None)
            .await
            .unwrap();
        let after = st
            .boot
            .kernel
            .processes
            .all_ids()
            .into_iter()
            .map(|pid| st.boot.kernel.facts.facts_of(pid).len())
            .sum::<usize>();
        assert!(
            after > before,
            "management write must execute through Operation/Fact, not backend side channel"
        );
        let v = inspect(&st, &root, path).await.unwrap().unwrap();
        assert_eq!(value_version(&v), Some(1));
        // reconfigure: expected 1 ⇒ bumps to 2.
        write_config(&st, &root, path, extension_installation("acme", 1), Some(1))
            .await
            .unwrap();
        let v = inspect(&st, &root, path).await.unwrap().unwrap();
        assert_eq!(value_version(&v), Some(2));
        // stale expected ⇒ conflict, no silent clobber.
        assert!(matches!(
            write_config(&st, &root, path, extension_installation("acme", 1), Some(1)).await,
            Err(MgmtError::Conflict { .. })
        ));
    }

    #[tokio::test]
    async fn extension_installation_admission_supports_multi_projection_package() {
        let st = console_state();
        let root = root_principal(&st).await;
        let path = "state://kernel/extension-installations/wechat";
        write_config(&st, &root, path, wechat_installation(0), None)
            .await
            .unwrap();
        let v = inspect(&st, &root, path).await.unwrap().unwrap();
        assert_eq!(value_version(&v), Some(1));

        let mut bad = wechat_installation(0);
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
            Value::List(vec![serde_json::from_value(
                serde_json::json!({
                    "effect_path": "effect://plugin/other/send_text",
                    "purity": "effectful"
                }),
            )
            .unwrap()]),
        );
        assert!(matches!(
            write_config(&st, &root, path, bad, Some(1)).await,
            Err(MgmtError::Admission(_))
        ));
    }

    #[tokio::test]
    async fn removed_extension_config_prefix_is_rejected() {
        let st = console_state();
        let root = root_principal(&st).await;
        assert!(matches!(
            write_config(
                &st,
                &root,
                "state://kernel/extensions/acme",
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
