//! External installation, role-session, and credential authority.

use super::*;

#[derive(Clone)]
pub(super) struct ExternalAuthority {
    pub(super) context: SessionContext,
    pub(super) projection: ExternalProjectionDef,
    pub(super) provider_capabilities: BTreeMap<Path, EffectCapability>,
    pub(super) key_epoch: u64,
}

struct ExternalSessionState {
    credential_generation: u64,
    key_epoch: u64,
}

fn external_registry_hash_value(
    installation: &ExternalInstallationDef,
    projection: &ExternalProjectionDef,
) -> Result<String, serde_json::Error> {
    let bytes = serde_json::to_vec(&(installation, projection))?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

pub(super) async fn load_external_authority(
    state: &Backend,
    installation_id: &str,
    projection_id: &str,
    role: Role,
    source_store: &dyn SourceStore,
) -> Result<ExternalAuthority, tonic::Status> {
    let record = load_external_installation(source_store, installation_id).await?;
    let installation = &record.definition;
    let role_session =
        load_external_session(state, installation_id, role, record.installation_epoch).await?;
    let projection = installation
        .projection(projection_id)
        .cloned()
        .ok_or_else(|| tonic::Status::not_found("external projection not found"))?;
    if projection.role != role {
        return Err(tonic::Status::permission_denied(
            "external projection role mismatch",
        ));
    }
    if let Some(source) = projection.emits.as_ref() {
        source_store
            .validate_source(&installation.id, &projection.id, source)
            .map_err(|error| {
                tonic::Status::failed_precondition(format!(
                    "Source projection admission failed: {error}"
                ))
            })?;
    }
    let provider_capabilities = provider_capability_index(&projection)?;
    let registry_hash = external_registry_hash(installation, &projection)?;
    Ok(ExternalAuthority {
        context: SessionContext {
            installation_id: installation.id.clone(),
            projection_id: projection.id.clone(),
            role: projection.role,
            registry_hash,
            credential_generation: role_session.credential_generation,
            binding_generation: projection.version,
            installation_config_version: installation.version,
            projection_version: projection.version,
            presentation_config_generation: 0,
            alias_catalog_generation: 0,
            session_id: String::new(),
            key_epoch: role_session.key_epoch,
            installation_epoch: record.installation_epoch,
            scope_epoch: if role == Role::Source {
                record.scope_epoch(projection_id).ok_or_else(|| {
                    tonic::Status::failed_precondition("Source scope is not active")
                })?
            } else {
                0
            },
        },
        projection,
        provider_capabilities,
        key_epoch: role_session.key_epoch,
    })
}

fn provider_capability_index(
    projection: &ExternalProjectionDef,
) -> Result<BTreeMap<Path, EffectCapability>, tonic::Status> {
    if projection.role != Role::Provider {
        return Ok(BTreeMap::new());
    }
    let mut capabilities = BTreeMap::new();
    for capability in &projection.provides {
        let path = Path::parse(&capability.effect_path).map_err(|error| {
            tonic::Status::failed_precondition(format!("external projection is invalid: {error}"))
        })?;
        if capabilities.insert(path, capability.clone()).is_some() {
            return Err(tonic::Status::failed_precondition(
                "external projection is invalid",
            ));
        }
    }
    Ok(capabilities)
}

async fn load_external_installation(
    source_store: &dyn SourceStore,
    installation_id: &str,
) -> Result<xolotl_source::ExternalInstallationRecord, tonic::Status> {
    validate_external_path_segment(installation_id, "external installation id")?;
    let Some(record) = source_store
        .load_installation(installation_id)
        .await
        .map_err(|error| {
            tonic::Status::unavailable(format!(
                "external installation authority read failed: {error}"
            ))
        })?
    else {
        return Err(tonic::Status::not_found("external installation not found"));
    };
    if record.definition.id != installation_id {
        return Err(tonic::Status::failed_precondition(
            "external installation id mismatch",
        ));
    }
    record.definition.validate_admission().map_err(|error| {
        tonic::Status::failed_precondition(format!(
            "external installation admission failed: {error}"
        ))
    })?;
    Ok(record)
}

async fn load_external_session(
    state: &Backend,
    installation_id: &str,
    role: Role,
    installation_epoch: u64,
) -> Result<ExternalSessionState, tonic::Status> {
    validate_external_path_segment(installation_id, "external installation id")?;
    let path =
        xolotl_types::external::external_session_path(installation_id, role).map_err(|error| {
            tonic::Status::invalid_argument(format!("external session id is invalid: {error}"))
        })?;
    let role = role.as_str();
    let Some(value) = state.read(&path).await.map_err(|error| {
        tonic::Status::unavailable(format!("external session state read failed: {error}"))
    })?
    else {
        return Err(tonic::Status::unauthenticated(
            "external session is not approved",
        ));
    };
    let record = value
        .as_map()
        .ok_or_else(|| tonic::Status::failed_precondition("external session is invalid"))?;
    if record.get("installation_id").and_then(Value::as_str) != Some(installation_id)
        || record.get("role").and_then(Value::as_str) != Some(role)
    {
        return Err(tonic::Status::failed_precondition(
            "external session mismatch",
        ));
    }
    if record.get("state").and_then(Value::as_str) != Some("ready") {
        return Err(tonic::Status::unauthenticated(
            "external session is not ready",
        ));
    }
    if record.get("installation_epoch").and_then(Value::as_str)
        != Some(installation_epoch.to_string().as_str())
    {
        return Err(tonic::Status::unauthenticated(
            "external session belongs to a different installation activation",
        ));
    }
    let generation = credential_generation_from_record(record)?;
    let pairing_id = record
        .get("pairing_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            tonic::Status::unauthenticated("external session has no pairing authority")
        })?;
    validate_external_path_segment(pairing_id, "external pairing id")?;
    let pairing_path =
        xolotl_types::external::external_pairing_path(pairing_id).map_err(|error| {
            tonic::Status::failed_precondition(format!("external pairing id is invalid: {error}"))
        })?;
    let pairing = state
        .read(&pairing_path)
        .await
        .map_err(|error| {
            tonic::Status::unavailable(format!("external pairing state read failed: {error}"))
        })?
        .ok_or_else(|| tonic::Status::unauthenticated("external pairing is unavailable"))?;
    let pairing = pairing
        .as_map()
        .ok_or_else(|| tonic::Status::failed_precondition("external pairing state is invalid"))?;
    if pairing.get("pairing_id").and_then(Value::as_str) != Some(pairing_id)
        || pairing.get("installation_id").and_then(Value::as_str) != Some(installation_id)
        || pairing.get("state").and_then(Value::as_str) != Some("approved")
        || pairing.get("installation_epoch").and_then(Value::as_str)
            != Some(installation_epoch.to_string().as_str())
        || pairing.get("credential_generation").and_then(Value::as_int)
            != i64::try_from(generation).ok()
        || !pairing
            .get("approved_roles")
            .and_then(Value::as_list)
            .is_some_and(|roles| roles.iter().any(|approved| approved.as_str() == Some(role)))
    {
        return Err(tonic::Status::unauthenticated(
            "external pairing authority mismatch",
        ));
    }
    ensure_external_not_revoked(state, installation_id, generation).await?;
    let key_epoch = key_epoch_from_record(record)?;
    Ok(ExternalSessionState {
        credential_generation: generation,
        key_epoch,
    })
}

pub(super) async fn ensure_external_not_revoked(
    state: &Backend,
    installation_id: &str,
    credential_generation: u64,
) -> Result<(), tonic::Status> {
    validate_external_path_segment(installation_id, "external installation id")?;
    let path = xolotl_types::external::external_credential_revocation_path(installation_id)
        .map_err(|error| {
            tonic::Status::invalid_argument(format!("external revocation id is invalid: {error}"))
        })?;
    let Some(value) = state.read(&path).await.map_err(|error| {
        tonic::Status::unavailable(format!("external revocation state read failed: {error}"))
    })?
    else {
        return Ok(());
    };
    let record = value.as_map().ok_or_else(|| {
        tonic::Status::failed_precondition("external revocation state is invalid")
    })?;
    if record.get("installation_id").and_then(Value::as_str) != Some(installation_id) {
        return Err(tonic::Status::failed_precondition(
            "external revocation id mismatch",
        ));
    }
    if record.get("state").and_then(Value::as_str) != Some("revoked") {
        return Err(tonic::Status::failed_precondition(
            "external revocation state is invalid",
        ));
    }
    let floor = record
        .get("credential_generation_floor")
        .and_then(Value::as_int)
        .ok_or_else(|| {
            tonic::Status::failed_precondition("external revocation floor is invalid")
        })?;
    if floor <= 0 {
        return Err(tonic::Status::failed_precondition(
            "external revocation floor is invalid",
        ));
    }
    if credential_generation <= floor as u64 {
        return Err(tonic::Status::unauthenticated(
            "external credential revoked",
        ));
    }
    Ok(())
}

fn external_registry_hash(
    installation: &ExternalInstallationDef,
    projection: &ExternalProjectionDef,
) -> Result<String, tonic::Status> {
    external_registry_hash_value(installation, projection).map_err(|error| {
        tonic::Status::failed_precondition(format!("external registry is invalid: {error}"))
    })
}

fn credential_generation_from_record(
    record: &xolotl_types::ValueMap,
) -> Result<u64, tonic::Status> {
    let generation = record
        .get("credential_generation")
        .and_then(Value::as_int)
        .ok_or_else(|| {
            tonic::Status::failed_precondition("external session generation is invalid")
        })?;
    if generation <= 0 {
        return Err(tonic::Status::failed_precondition(
            "external session generation is invalid",
        ));
    }
    Ok(generation as u64)
}

fn key_epoch_from_record(record: &xolotl_types::ValueMap) -> Result<u64, tonic::Status> {
    let Some(value) = record.get("key_epoch") else {
        return Ok(0);
    };
    let Some(epoch) = value.as_int() else {
        return Err(tonic::Status::failed_precondition(
            "external session key epoch is invalid",
        ));
    };
    if epoch < 0 {
        return Err(tonic::Status::failed_precondition(
            "external session key epoch is invalid",
        ));
    }
    Ok(epoch as u64)
}

fn validate_external_path_segment(segment: &str, label: &'static str) -> Result<(), tonic::Status> {
    if xolotl_types::path::is_simple_id_segment(segment) {
        Ok(())
    } else {
        Err(tonic::Status::invalid_argument(format!(
            "{label} is invalid"
        )))
    }
}

pub(super) fn context_matches_authority(
    authority: &SessionContext,
    context: &SessionContext,
) -> bool {
    !context.session_id.trim().is_empty()
        && authority.installation_id == context.installation_id
        && authority.projection_id == context.projection_id
        && authority.role == context.role
        && authority.registry_hash == context.registry_hash
        && authority.credential_generation == context.credential_generation
        && authority.binding_generation == context.binding_generation
        && authority.installation_config_version == context.installation_config_version
        && authority.projection_version == context.projection_version
        && authority.presentation_config_generation == context.presentation_config_generation
        && authority.alias_catalog_generation == context.alias_catalog_generation
        && authority.installation_epoch == context.installation_epoch
        && authority.scope_epoch == context.scope_epoch
}

pub(super) fn new_external_session_id() -> Result<String, tonic::Status> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| {
        tonic::Status::unavailable(format!("external session id unavailable: {error}"))
    })?;
    Ok(format!("s_{}", hex_lower(&bytes)))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
