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
use nexus_types::{IdentityRef, Outcome, OutputMode, Path, ResourceName, TaintSet, Value};
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{BootstrapOutcome, LoginRequest, RootProvisioning, bootstrap_root_account};
    use nexus_actors::{StandardConfig, install_standard};
    use nexus_kernel::Bootstrap;
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
        let path = "state://kernel/extensions/telegram";
        let before = st
            .boot
            .kernel
            .processes
            .all_ids()
            .into_iter()
            .map(|pid| st.boot.kernel.facts.facts_of(pid).len())
            .sum::<usize>();
        // install: expected None ⇒ creates version 1.
        write_config(&st, &root, path, obj(None), None)
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
        write_config(&st, &root, path, obj(Some(1)), Some(1))
            .await
            .unwrap();
        let v = inspect(&st, &root, path).await.unwrap().unwrap();
        assert_eq!(value_version(&v), Some(2));
        // stale expected ⇒ conflict, no silent clobber.
        assert!(matches!(
            write_config(&st, &root, path, obj(Some(1)), Some(1)).await,
            Err(MgmtError::Conflict { .. })
        ));
    }
}
