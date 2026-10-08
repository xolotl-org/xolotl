//! Console-owned State locations and capability targets.
//!
//! Keep path identity here so authentication, protocol discovery and service
//! dispatch use the same v1 addresses. Management action selection is owned by
//! `mgmt`; request-specific validation stays with each caller.

use xolotl_types::{Path, PathError, inference::InferenceDeclarationKind};

pub(crate) const USERS_PREFIX: &str = "state://kernel/console/users";
pub(crate) const ROLES_PREFIX: &str = "state://kernel/console/roles";
pub(crate) const SESSIONS_PREFIX: &str = "state://kernel/console/sessions";
pub(crate) const VAULT_CREDENTIALS_PREFIX: &str = "state://vault/console/credentials";
pub(crate) const VAULT_SESSIONS_PREFIX: &str = "state://vault/console/sessions";
pub(crate) const VAULT_LOCKOUTS_PREFIX: &str = "state://vault/console/lockouts";
pub(crate) const VAULT_CHALLENGES_PATH: &str = "state://vault/console/challenges";

pub(crate) const CONSOLE_AUTHORITY: &str = "state://kernel/console/**";
pub(crate) const USERS_AUTHORITY: &str = "state://kernel/console/users/**";
pub(crate) const ROLES_AUTHORITY: &str = "state://kernel/console/roles/**";
pub(crate) const SESSIONS_AUTHORITY: &str = "state://kernel/console/sessions/**";
pub(crate) const MANAGE_USERS_EFFECT: &str = "effect://kernel/console/users";
pub(crate) const VAULT_CREDENTIAL_RESOURCE: &str = "state://vault/console/credentials/*/*";
pub(crate) const SESSION_STORE_RESOURCE: &str = "console.session_store";

pub(crate) const EXTERNAL_INSTALLATIONS_PREFIX: &str = "state://kernel/external-installations";
pub(crate) const EXTERNAL_INSTALLATIONS_AUTHORITY: &str =
    "state://kernel/external-installations/**";
pub(crate) const MANIFESTS_PREFIX: &str = "state://kernel/manifests";
pub(crate) const MANIFESTS_AUTHORITY: &str = "state://kernel/manifests/**";
pub(crate) const PROJECTION_STATUS_PREFIX: &str =
    xolotl_types::in_process_projection::IN_PROCESS_PROJECTION_STATUS_PREFIX;
pub(crate) const PROJECTION_STATUS_AUTHORITY: &str =
    "state://kernel/projection-status/in-process/**";
pub(crate) const INFERENCE_BACKENDS_PREFIX: &str =
    xolotl_types::inference::INFERENCE_BACKENDS_PREFIX;
pub(crate) const INFERENCE_MODELS_PREFIX: &str = xolotl_types::inference::INFERENCE_MODELS_PREFIX;
pub(crate) const INFERENCE_GROUPS_PREFIX: &str = xolotl_types::inference::INFERENCE_GROUPS_PREFIX;
pub(crate) const INFERENCE_ROUTING_PATH: &str = xolotl_types::inference::INFERENCE_ROUTING_PATH;
pub(crate) const INFERENCE_AUTHORITY: &str = "state://kernel/inference/**";
pub(crate) const INFERENCE_BACKENDS_AUTHORITY: &str = "state://kernel/inference/backends/**";
pub(crate) const INFERENCE_MODELS_AUTHORITY: &str = "state://kernel/inference/models/**";
pub(crate) const INFERENCE_GROUPS_AUTHORITY: &str = "state://kernel/inference/groups/**";
pub(crate) const FACT_PREFIX: &str = "state://fact";
pub(crate) const PROCESS_INSPECT_EFFECT: &str =
    xolotl_types::effect_targets::KERNEL_PROCESS_INSPECT;
pub(crate) const PROCESS_SPAWN_EFFECT: &str = xolotl_types::effect_targets::PROC_SPAWN;
pub(crate) const PROCESS_KILL_EFFECT: &str = xolotl_types::effect_targets::PROC_KILL;
pub(crate) const EXTERNAL_REVOKE_EFFECT: &str = xolotl_types::effect_targets::EXTERNAL_REVOKE;
pub(crate) const PAIRING_CREATE_EFFECT: &str = xolotl_types::effect_targets::PAIRING_CREATE;
pub(crate) const PAIRING_APPROVE_EFFECT: &str = xolotl_types::effect_targets::PAIRING_APPROVE;
pub(crate) const PAIRING_DENY_EFFECT: &str = xolotl_types::effect_targets::PAIRING_DENY;
pub(crate) const PAIRING_AUTHORITY: &str = "effect://external/pairing/**";
/// Authority labels for the federation catalog. The rows themselves belong
/// to the installed federation store, never to ordinary Kernel State.
pub(crate) const FEDERATION_PEERS_PREFIX: &str = "state://kernel/federation/peers";
pub(crate) const FEDERATION_PEERS_AUTHORITY: &str = "state://kernel/federation/peers/**";

fn child(prefix: &str, id: &str) -> Result<Path, PathError> {
    if id.is_empty() {
        return Err(PathError::EmptySegment);
    }
    if !xolotl_types::path::is_simple_id_segment(id) {
        return Err(PathError::BadSegmentChar(id.into()));
    }
    Path::parse(prefix)?.try_push_literal(id)
}

pub(crate) fn user_path(username: &str) -> Result<Path, PathError> {
    child(USERS_PREFIX, username)
}

pub(crate) fn role_path(role: &str) -> Result<Path, PathError> {
    child(ROLES_PREFIX, role)
}

pub(crate) fn session_path(sid: &str) -> Result<Path, PathError> {
    child(SESSIONS_PREFIX, sid)
}

pub(crate) fn stored_session_path(sid: &str) -> Result<Path, PathError> {
    child(VAULT_SESSIONS_PREFIX, sid)
}

pub(crate) fn lockout_path(username: &str) -> Result<Path, PathError> {
    child(VAULT_LOCKOUTS_PREFIX, username)
}

pub(crate) fn account_lockout_path(
    authority_id: &str,
    instance_id: &str,
) -> Result<Path, PathError> {
    child(VAULT_LOCKOUTS_PREFIX, authority_id)?.try_push_literal(instance_id)
}

pub(crate) fn credential_path(authority_id: &str, instance_id: &str) -> Result<Path, PathError> {
    child(VAULT_CREDENTIALS_PREFIX, authority_id)?.try_push_literal(instance_id)
}

pub(crate) fn external_installation_path(id: &str) -> Result<Path, PathError> {
    child(EXTERNAL_INSTALLATIONS_PREFIX, id)
}

pub(crate) fn federation_peer_path(node_id: &str) -> Result<Path, PathError> {
    child(FEDERATION_PEERS_PREFIX, node_id)
}

pub(crate) fn federation_export_path(node_id: &str) -> Result<Path, PathError> {
    federation_peer_path(node_id)?.try_push_literal("exports")
}

pub(crate) fn federation_online_admission_path(node_id: &str) -> Result<Path, PathError> {
    federation_peer_path(node_id)?.try_push_literal("online-admission")
}

pub(crate) fn external_manifest_path(platform: &str) -> Result<Path, PathError> {
    child(MANIFESTS_PREFIX, platform)
}

pub(crate) fn projection_status_path(id: &str) -> Result<Path, PathError> {
    xolotl_types::in_process_projection::in_process_projection_status_path(id)
}

pub(crate) fn inference_backend_path(id: &str) -> Result<Path, PathError> {
    InferenceDeclarationKind::Backend.path(id)
}

pub(crate) fn inference_model_path(id: &str) -> Result<Path, PathError> {
    InferenceDeclarationKind::Model.path(id)
}

pub(crate) fn inference_group_path(name: &str) -> Result<Path, PathError> {
    InferenceDeclarationKind::Group.path(name)
}

pub(crate) fn fact_path(process: u64) -> Result<Path, PathError> {
    child(FACT_PREFIX, &process.to_string())
}

pub(crate) fn is_local_kernel_path(path: &Path) -> bool {
    path.scheme() == "state"
        && path.cluster().is_none()
        && path
            .segments()
            .first()
            .is_some_and(|segment| segment == "kernel")
}

pub(crate) fn is_console_descendant(path: &Path) -> bool {
    is_local_kernel_path(path)
        && path
            .segments()
            .get(1)
            .is_some_and(|segment| segment == "console")
        && path.segments().len() > 2
}

pub(crate) fn is_user_descendant(path: &Path) -> bool {
    is_console_descendant(path)
        && path
            .segments()
            .get(2)
            .is_some_and(|segment| segment == "users")
        && path.segments().len() > 3
}

pub(crate) fn is_role_descendant(path: &Path) -> bool {
    is_console_descendant(path)
        && path
            .segments()
            .get(2)
            .is_some_and(|segment| segment == "roles")
        && path.segments().len() > 3
}

pub(crate) fn is_user_record_path(path: &Path) -> bool {
    is_user_descendant(path) && path.segments().len() == 4
}

pub(crate) fn is_role_record_path(path: &Path) -> bool {
    is_role_descendant(path) && path.segments().len() == 4
}

/// Only a direct, valid child of the session collection is a session row.
pub(crate) fn stored_session_id_from_path(path: &Path) -> Option<&str> {
    let segments = path.segments();
    (path.scheme() == "state"
        && path.cluster().is_none()
        && segments.first().is_some_and(|segment| segment == "vault")
        && segments.get(1).is_some_and(|segment| segment == "console")
        && segments.len() == 4
        && segments.get(2).is_some_and(|segment| segment == "sessions"))
    .then(|| segments[3].as_str())
    .filter(|sid| xolotl_types::path::is_simple_id_segment(sid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    #[test]
    fn path_classification_uses_local_segments() -> anyhow::Result<()> {
        ensure!(is_user_record_path(&user_path("alice")?));
        ensure!(is_user_descendant(&Path::parse(
            "state://kernel/console/users/alice/details"
        )?));
        ensure!(!is_user_record_path(&Path::parse(
            "state://kernel/console/users/alice/details"
        )?));
        ensure!(!is_console_descendant(&Path::parse(
            "state://kernel/console"
        )?));
        ensure!(!is_user_descendant(&Path::parse(
            "state://kernel/console/users-extra/alice"
        )?));
        ensure!(user_path("bad.id").is_err());
        ensure!(stored_session_id_from_path(&stored_session_path("sid-1")?) == Some("sid-1"));
        ensure!(stored_session_id_from_path(&session_path("sid-1")?).is_none());
        ensure!(
            stored_session_id_from_path(&Path::parse(
                "state://vault/console/sessions/nested/sid-1"
            )?)
            .is_none()
        );
        Ok(())
    }
}
