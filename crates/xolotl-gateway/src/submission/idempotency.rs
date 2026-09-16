//! Submission idempotency reservations and retained complete execution results.

use xolotl_kernel::Bootstrap;
use xolotl_types::{ExecutionOutput, Path, ProcessId, ProcessStatus, ReplayClass, Value};

use crate::{
    CompiledGatewayProfile, GATEWAY_EFFECT_METHOD, GatewayAccepted, GatewayError,
    GatewayPayloadProvenance, GatewaySession, GatewaySubmission, GatewaySubmissionBody,
    GatewaySubmitResult, SubmitOptions, normalize_optional_string, operation_replay_class,
    random_gateway_id, state_path, validate_content_hash, validate_idempotency_key,
    validate_submission_token,
};

mod record;

pub(crate) enum SubmissionIdempotency {
    Reserved(Box<GatewayIdempotencyReservation>),
    Replay(Box<GatewaySubmitResult>),
}

pub(crate) struct GatewayIdempotencyReservation {
    path: Path,
    pending_record: Value,
    fingerprint: SubmissionIdempotencyFingerprint,
}

struct SubmissionIdempotencyFingerprint {
    effective_key_hash: String,
    submission_hash: String,
    caller_material_kind: &'static str,
    caller_material_hash: String,
    profile_name: String,
    profile_rev: String,
    principal_id: String,
    surface_id: String,
}

pub(crate) async fn reserve_submission_idempotency_if_present(
    state: &xolotl_state::Backend,
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    submission: &GatewaySubmission,
    material: Option<(&'static str, String)>,
    now_ms: i64,
) -> Result<Option<SubmissionIdempotency>, GatewayError> {
    let Some((caller_material_kind, caller_material)) = material else {
        return Ok(None);
    };
    let submission_hash = submission_hash(submission)?;
    let caller_material_hash = hash_idempotency_material(caller_material_kind, &caller_material);
    let effective_key_hash = effective_idempotency_hash(
        profile,
        session,
        submission,
        &submission_hash,
        caller_material_kind,
        &caller_material_hash,
    );
    let fingerprint = SubmissionIdempotencyFingerprint {
        effective_key_hash,
        submission_hash,
        caller_material_kind,
        caller_material_hash,
        profile_name: profile.profile_name.clone(),
        profile_rev: profile.revision.to_string(),
        principal_id: session.principal.principal_id.clone(),
        surface_id: submission.surface_id.clone(),
    };
    let path = idempotency_path(&fingerprint.effective_key_hash)?;
    let pending_record = record::pending(
        &fingerprint,
        now_ms,
        random_gateway_id("gw-idempotency", profile.revision)?,
    );
    match state.write_cas(&path, None, pending_record.clone()).await {
        Ok(_commit) => {}
        Err(xolotl_state::StateFailure {
            error: xolotl_state::StateError::CasFailed { actual, .. },
            taint,
        }) => {
            let Some(current) = actual else {
                return Err(GatewayError::Rejected(
                    "idempotency comparison failed without an observed record".into(),
                ));
            };
            let current = xolotl_types::TaintedValue::new(*current, taint);
            return record::replay(current, &fingerprint).map(Some);
        }
        Err(e) => {
            return Err(GatewayError::Rejected(format!(
                "idempotency reservation failed: {e}"
            )));
        }
    }
    Ok(Some(SubmissionIdempotency::Reserved(Box::new(
        GatewayIdempotencyReservation {
            path,
            pending_record,
            fingerprint,
        },
    ))))
}

pub(crate) async fn commit_submission_idempotency_output(
    state: &xolotl_state::Backend,
    reservation: Option<&GatewayIdempotencyReservation>,
    accepted: &GatewayAccepted,
    output: &ExecutionOutput,
) -> Result<(), GatewayError> {
    let Some(reservation) = reservation else {
        return Ok(());
    };
    let committed = record::committed(&reservation.fingerprint, accepted, &output.outcome)?;
    state
        .write_cas_tainted(
            &reservation.path,
            Some(reservation.pending_record.clone()),
            committed,
            output.taint.clone(),
        )
        .await
        .map(|_commit| ())
        .map_err(|e| match e {
            xolotl_state::StateFailure {
                error: xolotl_state::StateError::CasFailed { .. },
                ..
            } => GatewayError::Rejected("idempotency record changed during execution".into()),
            other => GatewayError::Rejected(format!("idempotency commit failed: {other}")),
        })
}

pub(crate) async fn commit_submission_idempotency_and_finish_request(
    boot: &Bootstrap,
    process: ProcessId,
    reservation: Option<&GatewayIdempotencyReservation>,
    accepted: &GatewayAccepted,
    output: &ExecutionOutput,
) -> Result<(), GatewayError> {
    let commit =
        commit_submission_idempotency_output(&boot.kernel.state, reservation, accepted, output)
            .await;
    let finish = boot
        .finish_request_process(process, output)
        .await
        .map_err(|error| GatewayError::Rejected(error.to_string()));
    match (commit, finish) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(commit_error), Ok(())) => Err(commit_error),
        (Ok(()), Err(finish_error)) => Err(finish_error),
        (Err(commit_error), Err(finish_error)) => Err(GatewayError::Rejected(format!(
            "{commit_error}; request cleanup failed: {finish_error}"
        ))),
    }
}

pub(crate) async fn release_submission_idempotency_reservation(
    state: &xolotl_state::Backend,
    reservation: Option<&GatewayIdempotencyReservation>,
) -> Result<(), GatewayError> {
    let Some(reservation) = reservation else {
        return Ok(());
    };
    // Only known pre-dispatch failures may release their own pending reservation.
    state
        .write_compare_delete(&reservation.path, Some(reservation.pending_record.clone()))
        .await
        .map(|_commit| ())
        .map_err(|error| match error {
            xolotl_state::StateFailure {
                error: xolotl_state::StateError::CasFailed { .. },
                ..
            } => GatewayError::Rejected("idempotency record changed before release".into()),
            other => GatewayError::Rejected(format!("idempotency release failed: {other}")),
        })
}

pub(crate) async fn release_submission_idempotency_reservation_and_fail<T>(
    state: &xolotl_state::Backend,
    reservation: Option<&GatewayIdempotencyReservation>,
    error: GatewayError,
) -> Result<T, GatewayError> {
    release_submission_idempotency_reservation(state, reservation).await?;
    Err(error)
}

pub(crate) async fn finish_request_release_idempotency_and_fail<T>(
    boot: &Bootstrap,
    process: ProcessId,
    reservation: Option<&GatewayIdempotencyReservation>,
    error: GatewayError,
) -> Result<T, GatewayError> {
    let original = error.to_string();
    match finish_request_and_release_idempotency(boot, process, reservation).await {
        Ok(()) => Err(error),
        Err(cleanup_error) => Err(GatewayError::Rejected(format!(
            "{original}; request cleanup failed: {cleanup_error}"
        ))),
    }
}

pub(crate) async fn finish_request_without_idempotency_and_fail<T>(
    boot: &Bootstrap,
    process: ProcessId,
    error: GatewayError,
) -> Result<T, GatewayError> {
    let original = error.to_string();
    match boot.finish_process_as(process, ProcessStatus::Failed).await {
        Ok(()) => Err(error),
        Err(cleanup_error) => Err(GatewayError::Rejected(format!(
            "{original}; request cleanup failed: {cleanup_error}"
        ))),
    }
}

pub(crate) async fn finish_request_and_release_idempotency(
    boot: &Bootstrap,
    process: ProcessId,
    reservation: Option<&GatewayIdempotencyReservation>,
) -> Result<(), GatewayError> {
    let finish = boot.finish_process_as(process, ProcessStatus::Failed).await;
    let release = release_submission_idempotency_reservation(&boot.kernel.state, reservation).await;
    match (finish, release) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(finish_error), Ok(())) => Err(GatewayError::Rejected(finish_error.to_string())),
        (Ok(()), Err(release_error)) => Err(release_error),
        (Err(finish_error), Err(release_error)) => Err(GatewayError::Rejected(format!(
            "{finish_error}; {release_error}"
        ))),
    }
}

pub(crate) fn initial_idempotency_material(
    boot: &Bootstrap,
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    submission: &GatewaySubmission,
) -> Result<Option<(&'static str, String)>, GatewayError> {
    if let Some(material) = idempotency_key_material(submission)? {
        return Ok(Some(material));
    }
    if direct_input_requires_idempotency(boot, profile, session, submission)? {
        return submission_token_material(&submission.options);
    }
    Ok(None)
}

pub(crate) fn required_idempotency_material(
    submission: &GatewaySubmission,
) -> Result<Option<(&'static str, String)>, GatewayError> {
    if let Some(material) = idempotency_key_material(submission)? {
        return Ok(Some(material));
    }
    submission_token_material(&submission.options)
}

fn idempotency_key_material(
    submission: &GatewaySubmission,
) -> Result<Option<(&'static str, String)>, GatewayError> {
    if let Some(key) = normalize_optional_string(submission.options.idempotency_key.clone()) {
        validate_idempotency_key(&key)?;
        return Ok(Some(("idempotency_key", key)));
    }
    Ok(None)
}

fn submission_token_material(
    options: &SubmitOptions,
) -> Result<Option<(&'static str, String)>, GatewayError> {
    if let Some(token) = normalize_optional_string(options.submission_token.clone()) {
        validate_submission_token(&token)?;
        Ok(Some(("submission_token", token)))
    } else {
        Ok(None)
    }
}

fn direct_input_requires_idempotency(
    boot: &Bootstrap,
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    submission: &GatewaySubmission,
) -> Result<bool, GatewayError> {
    let GatewaySubmissionBody::DirectInput(_) = &submission.body else {
        return Ok(false);
    };
    if submission.surface_id.trim().is_empty() {
        return Ok(false);
    }
    let Some(surface) = profile.surface_by_id(&submission.surface_id) else {
        return Ok(false);
    };
    if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
        return Ok(false);
    }
    let replay = operation_replay_class(boot, &surface.target, GATEWAY_EFFECT_METHOD)?;
    Ok(matches!(replay, ReplayClass::NonIdempotentEffect))
}

pub(crate) fn submission_hash(submission: &GatewaySubmission) -> Result<String, GatewayError> {
    let mut hasher = blake3::Hasher::new();
    update_hash_str(&mut hasher, "xolotl-gateway-submission-v1");
    update_hash_str(&mut hasher, &submission.surface_id);
    update_hash_json(&mut hasher, &submission.requested_output)?;
    match &submission.body {
        GatewaySubmissionBody::DirectInput(input) => {
            update_hash_str(&mut hasher, "direct_input");
            update_hash_bytes(&mut hasher, &input.payload.semantic_digest());
            update_hash_provenance(&mut hasher, input.provenance.as_ref());
        }
        GatewaySubmissionBody::InputStream(open) => {
            update_hash_str(&mut hasher, "input_stream");
            update_hash_str(&mut hasher, &open.stream_id);
            update_hash_str(&mut hasher, open.direction.as_str());
            update_hash_str(&mut hasher, open.modality.as_str());
            update_hash_str(&mut hasher, &open.item_schema_id);
            update_hash_u64(&mut hasher, open.max_inline_item_bytes);
            update_hash_optional_u64(&mut hasher, open.max_items);
            update_hash_optional_u64(&mut hasher, open.max_bytes);
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn effective_idempotency_hash(
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    submission: &GatewaySubmission,
    submission_hash: &str,
    caller_material_kind: &str,
    caller_material_hash: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    update_hash_str(&mut hasher, "xolotl-gateway-idempotency-v1");
    update_hash_str(&mut hasher, &profile.profile_name);
    update_hash_u64(&mut hasher, profile.revision);
    update_hash_str(&mut hasher, &session.principal.principal_id);
    update_hash_str(&mut hasher, &session.identity_path);
    update_hash_str(&mut hasher, &submission.surface_id);
    update_hash_str(&mut hasher, submission_hash);
    update_hash_str(&mut hasher, caller_material_kind);
    update_hash_str(&mut hasher, caller_material_hash);
    hasher.finalize().to_hex().to_string()
}

fn hash_idempotency_material(kind: &str, material: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    update_hash_str(&mut hasher, "xolotl-gateway-idempotency-material-v1");
    update_hash_str(&mut hasher, kind);
    update_hash_str(&mut hasher, material);
    hasher.finalize().to_hex().to_string()
}

fn update_hash_json<T: ?Sized + serde::Serialize>(
    hasher: &mut blake3::Hasher,
    value: &T,
) -> Result<(), GatewayError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| GatewayError::Rejected(format!("submission hash failed: {e}")))?;
    update_hash_bytes(hasher, &bytes);
    Ok(())
}

fn update_hash_provenance(
    hasher: &mut blake3::Hasher,
    provenance: Option<&GatewayPayloadProvenance>,
) {
    let Some(provenance) = provenance else {
        update_hash_str(hasher, "provenance:none");
        return;
    };
    update_hash_str(hasher, "provenance:some");
    update_hash_optional_str(hasher, provenance.upload_ticket.as_deref());
    if let Some(proof) = provenance.store_proof.as_ref() {
        update_hash_str(hasher, "store_proof:some");
        update_hash_str(hasher, &proof.store_id);
        update_hash_str(hasher, &proof.proof);
    } else {
        update_hash_str(hasher, "store_proof:none");
    }
}

fn update_hash_optional_str(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            update_hash_str(hasher, "some");
            update_hash_str(hasher, value);
        }
        None => update_hash_str(hasher, "none"),
    }
}

fn update_hash_optional_u64(hasher: &mut blake3::Hasher, value: Option<u64>) {
    match value {
        Some(value) => {
            update_hash_str(hasher, "some");
            update_hash_u64(hasher, value);
        }
        None => update_hash_str(hasher, "none"),
    }
}

fn update_hash_u64(hasher: &mut blake3::Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn update_hash_str(hasher: &mut blake3::Hasher, value: &str) {
    update_hash_bytes(hasher, value.as_bytes());
}

fn update_hash_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

pub(crate) fn idempotency_path(effective_key_hash: &str) -> Result<Path, GatewayError> {
    validate_content_hash(effective_key_hash)?;
    state_path(&["gateway", "idempotency", effective_key_hash])
        .map_err(|e| GatewayError::Rejected(format!("invalid idempotency path: {e}")))
}

#[cfg(test)]
mod tests;
