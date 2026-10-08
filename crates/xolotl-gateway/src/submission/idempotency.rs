//! Submission idempotency reservations and retained complete execution results.

use std::sync::Arc;
use xolotl_kernel::process::ProcessFinalizationReport;
use xolotl_kernel::{Bootstrap, CleanupTicket};
use xolotl_types::{
    ExecutionOutput, ProcessId, ProcessStatus, ReplayClass, UnresolvedOperations, Value,
};

use crate::{
    CompiledGatewayProfile, GATEWAY_EFFECT_METHOD, GatewayAccepted, GatewayError,
    GatewayIdempotencyStore, GatewayPayloadProvenance, GatewayRequestEvidence,
    GatewayRequestIdentity, GatewayRequestLookup, GatewayRuntime, GatewaySession,
    GatewaySubmission, GatewaySubmissionBody, GatewaySubmitResult, SubmitOptions,
    normalize_optional_string, operation_replay_class, random_gateway_id, validate_idempotency_key,
    validate_submission_token,
};

mod record;

pub(crate) enum SubmissionIdempotency {
    Reserved(Box<GatewayIdempotencyReservation>),
    Replay(Box<GatewaySubmitResult>),
}

pub(crate) struct GatewayIdempotencyReservation {
    store: Arc<dyn GatewayIdempotencyStore>,
    key: String,
    pending_record: Value,
    fingerprint: SubmissionIdempotencyFingerprint,
}

impl GatewayIdempotencyReservation {
    /// Stable, submission-fingerprinted identity used only as a consumption
    /// marker. A pending reservation still gates concurrent execution.
    pub(crate) fn effect_identity(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"gateway-object-consumption-v1");
        hasher.update(self.fingerprint.effective_key_hash.as_bytes());
        hasher.update(self.fingerprint.submission_hash.as_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

struct SubmissionIdempotencyFingerprint {
    retry_epoch: u64,
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
    store: &Arc<dyn GatewayIdempotencyStore>,
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    submission: &GatewaySubmission,
    material: Option<(&'static str, String)>,
    now_ms: i64,
) -> Result<Option<SubmissionIdempotency>, GatewayError> {
    let Some((caller_material_kind, caller_material)) = material else {
        return Ok(None);
    };
    let retry_epoch = submission.options.retry_epoch;
    let submission_hash = submission_hash(submission)?;
    let caller_material_hash = hash_idempotency_material(caller_material_kind, &caller_material);
    let effective_key_hash = effective_idempotency_hash(
        profile,
        session,
        &submission.surface_id,
        retry_epoch,
        caller_material_kind,
        &caller_material_hash,
    );
    let fingerprint = SubmissionIdempotencyFingerprint {
        retry_epoch,
        effective_key_hash,
        submission_hash,
        caller_material_kind,
        caller_material_hash,
        profile_name: profile.profile_name.clone(),
        profile_rev: profile.revision.to_string(),
        principal_id: session.principal.principal_id.clone(),
        surface_id: submission.surface_id.clone(),
    };
    let pending_record = record::pending(
        &fingerprint,
        now_ms,
        random_gateway_id("gw-idempotency", profile.revision)?,
    );
    if let Some(current) = store
        .reserve(
            &fingerprint.effective_key_hash,
            xolotl_types::TaintedValue::new(pending_record.clone(), Default::default()),
        )
        .await?
    {
        return record::replay(current, &fingerprint).map(Some);
    }
    Ok(Some(SubmissionIdempotency::Reserved(Box::new(
        GatewayIdempotencyReservation {
            store: store.clone(),
            key: fingerprint.effective_key_hash.clone(),
            pending_record,
            fingerprint,
        },
    ))))
}

/// `now_ms` is the owning Kernel's host wall clock, kept explicit so record
/// encoding never chooses a separate time authority.
pub(crate) async fn commit_submission_idempotency_output(
    reservation: &GatewayIdempotencyReservation,
    accepted: &GatewayAccepted,
    output: &ExecutionOutput,
    now_ms: i64,
) -> Result<(), GatewayError> {
    let committed =
        record::committed(&reservation.fingerprint, accepted, output, now_ms).map_err(|error| {
            GatewayError::Indeterminate(format!(
                "idempotency result could not be recorded after execution: {error}"
            ))
        })?;
    reservation
        .store
        .complete(
            &reservation.key,
            reservation.pending_record.clone(),
            xolotl_types::TaintedValue::new(committed, output.taint.clone()),
        )
        .await
        .map_err(|error| {
            GatewayError::Indeterminate(format!(
                "idempotency commit failed after execution: {error}"
            ))
        })
}

pub(crate) async fn commit_submission_idempotency_and_finish_request(
    boot: &Bootstrap,
    process: ProcessId,
    reservation: Option<&GatewayIdempotencyReservation>,
    accepted: &GatewayAccepted,
    output: &mut ExecutionOutput,
) -> Result<(), GatewayError> {
    finish_request_output(boot, process, output).await?;
    if let Some(reservation) = reservation {
        commit_submission_idempotency_output(
            reservation,
            accepted,
            output,
            boot.kernel().host_runtime().now_millis(),
        )
        .await?;
    }
    Ok(())
}

fn confirmed_finalization_report(
    ticket: &CleanupTicket,
) -> Result<Arc<ProcessFinalizationReport>, GatewayError> {
    if !ticket.is_complete() {
        return Err(GatewayError::Indeterminate(
            "request cleanup custody is not complete".into(),
        ));
    }
    ticket.finalization_report().ok_or_else(|| {
        GatewayError::Indeterminate(
            "request cleanup completed without a committed finalization report".into(),
        )
    })
}

pub(crate) async fn finish_request_output(
    boot: &Bootstrap,
    process: ProcessId,
    output: &mut ExecutionOutput,
) -> Result<Arc<ProcessFinalizationReport>, GatewayError> {
    let ticket = boot.cleanup_ticket(process).map_err(|error| {
        output.unresolved_operations.identities_incomplete = true;
        GatewayError::Indeterminate(error.to_string())
    })?;
    let finish = boot.finish_request_process(process, output).await;
    if let Some(unresolved) = ticket.unresolved_operations() {
        output.unresolved_operations.merge(&unresolved);
    }
    if let Some(report) = ticket.finalization_report() {
        merge_finalization_report(output, &report);
    } else {
        output.unresolved_operations.identities_incomplete = true;
    }
    finish.map_err(|error| {
        output.unresolved_operations.identities_incomplete = true;
        GatewayError::Indeterminate(error.to_string())
    })?;
    confirmed_finalization_report(&ticket).inspect_err(|_error| {
        output.unresolved_operations.identities_incomplete = true;
    })
}

fn merge_finalization_report(output: &mut ExecutionOutput, report: &ProcessFinalizationReport) {
    output.taint.union(&report.taint);
    output
        .unresolved_operations
        .merge(&report.unresolved_operations);
}

async fn finish_failed_request(
    boot: &Bootstrap,
    process: ProcessId,
    unresolved: &mut UnresolvedOperations,
) -> Result<Arc<ProcessFinalizationReport>, GatewayError> {
    let ticket = boot.cleanup_ticket(process).map_err(|error| {
        unresolved.identities_incomplete = true;
        GatewayError::Indeterminate(error.to_string())
    })?;
    let finish = boot.finish_process_as(process, ProcessStatus::Failed).await;
    if let Some(observed) = ticket.unresolved_operations() {
        unresolved.merge(&observed);
    }
    finish.map_err(|error| {
        unresolved.identities_incomplete = true;
        GatewayError::Indeterminate(error.to_string())
    })?;
    confirmed_finalization_report(&ticket).inspect_err(|_error| {
        unresolved.identities_incomplete = true;
    })
}

pub(crate) async fn release_submission_idempotency_reservation(
    reservation: Option<&GatewayIdempotencyReservation>,
) -> Result<(), GatewayError> {
    let Some(reservation) = reservation else {
        return Ok(());
    };
    // Only known pre-dispatch failures may release their own pending reservation.
    reservation
        .store
        .release(&reservation.key, reservation.pending_record.clone())
        .await
}

pub(crate) async fn release_submission_idempotency_reservation_and_fail<T>(
    reservation: Option<&GatewayIdempotencyReservation>,
    error: GatewayError,
) -> Result<T, GatewayError> {
    if error.is_indeterminate() {
        return Err(error);
    }
    release_submission_idempotency_reservation(reservation).await?;
    Err(error)
}

pub(crate) async fn finish_request_release_idempotency_and_fail<T>(
    boot: &Bootstrap,
    process: ProcessId,
    reservation: Option<&GatewayIdempotencyReservation>,
    error: GatewayError,
) -> Result<T, GatewayError> {
    if error.is_indeterminate() {
        return finish_request_without_idempotency_and_fail(boot, process, error).await;
    }
    let original = error.to_string();
    match finish_request_and_release_idempotency(boot, process, reservation).await {
        Ok(()) => Err(error),
        Err(cleanup_error) => Err(GatewayError::Indeterminate(format!(
            "{original}; request cleanup failed: {cleanup_error}"
        ))),
    }
}

pub(crate) async fn finish_request_without_idempotency_and_fail<T>(
    boot: &Bootstrap,
    process: ProcessId,
    mut error: GatewayError,
) -> Result<T, GatewayError> {
    let mut unresolved = UnresolvedOperations::default();
    let finish = finish_failed_request(boot, process, &mut unresolved).await;
    if let GatewayError::SubmissionIndeterminate(evidence) = &mut error {
        evidence.unresolved_operations.merge(&unresolved);
    }
    match finish {
        Ok(_) => {
            if error.is_indeterminate() || unresolved.is_empty() {
                Err(error)
            } else {
                Err(error.with_request_cleanup_failure("cleanup has unresolved effects".into()))
            }
        }
        Err(cleanup_error) => Err(error.with_request_cleanup_failure(cleanup_error.to_string())),
    }
}

pub(crate) async fn finish_request_and_release_idempotency(
    boot: &Bootstrap,
    process: ProcessId,
    reservation: Option<&GatewayIdempotencyReservation>,
) -> Result<(), GatewayError> {
    let mut unresolved = UnresolvedOperations::default();
    finish_failed_request(boot, process, &mut unresolved).await?;
    if !unresolved.is_empty() {
        return Err(GatewayError::Indeterminate(
            "request cleanup has unresolved effects".into(),
        ));
    }
    release_submission_idempotency_reservation(reservation).await
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
    surface_id: &str,
    retry_epoch: u64,
    caller_material_kind: &str,
    caller_material_hash: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    update_hash_str(&mut hasher, "xolotl-gateway-idempotency-v1");
    if retry_epoch != 0 {
        update_hash_str(&mut hasher, "retry-epoch");
        update_hash_u64(&mut hasher, retry_epoch);
    }
    update_hash_str(&mut hasher, &profile.profile_name);
    update_hash_u64(&mut hasher, profile.revision);
    update_hash_str(&mut hasher, &session.principal.principal_id);
    update_hash_str(&mut hasher, &session.identity_path);
    update_hash_str(&mut hasher, surface_id);
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

pub(crate) async fn lookup_request(
    runtime: &GatewayRuntime,
    session: &GatewaySession,
    lookup: GatewayRequestLookup,
) -> Result<GatewayRequestEvidence, GatewayError> {
    observe_request(runtime, session, lookup, false)
        .await
        .map(|(evidence, _)| evidence)
}

pub(crate) async fn read_retained_request_result(
    runtime: &GatewayRuntime,
    session: &GatewaySession,
    lookup: GatewayRequestLookup,
) -> Result<crate::GatewayRetainedRequestResult, GatewayError> {
    use crate::GatewayRetainedRequestResult;
    let (evidence, result) = observe_request(runtime, session, lookup, true).await?;
    if let Some(result) = result {
        return Ok(GatewayRetainedRequestResult::Available(result));
    }
    match evidence {
        GatewayRequestEvidence::Unproven => Ok(GatewayRetainedRequestResult::Unproven),
        GatewayRequestEvidence::Reserved => Ok(GatewayRetainedRequestResult::Reserved),
        GatewayRequestEvidence::Retired => Ok(GatewayRetainedRequestResult::Retired),
        GatewayRequestEvidence::Settled(_) => {
            Err(GatewayError::Rejected("retained result missing".into()))
        }
    }
}

async fn observe_request(
    runtime: &GatewayRuntime,
    session: &GatewaySession,
    lookup: GatewayRequestLookup,
    retain_result: bool,
) -> Result<
    (
        GatewayRequestEvidence,
        Option<Box<crate::GatewaySubmitResult>>,
    ),
    GatewayError,
> {
    let GatewayRequestLookup {
        surface_id,
        expected_request_scope,
        retry_epoch,
        identity,
    } = lookup;
    let options = SubmitOptions {
        expected_request_scope: Some(expected_request_scope),
        ..Default::default()
    };
    let validate = |profile: &CompiledGatewayProfile| {
        GatewayRuntime::validate_submission_profile_access(profile, session, &surface_id)?;
        let surface = profile
            .surface_by_id(&surface_id)
            .ok_or_else(|| GatewayError::Rejected("request surface is unavailable".into()))?;
        crate::request_scope::validate(
            profile,
            session,
            surface,
            runtime.idempotency.as_ref(),
            &options,
        )
    };
    let profile = runtime.profile_snapshot();
    validate(&profile)?;
    let (caller_material_kind, raw) = match identity {
        GatewayRequestIdentity::IdempotencyKey(raw) => ("idempotency_key", raw),
        GatewayRequestIdentity::SubmissionToken(raw) => ("submission_token", raw),
    };
    let material = normalize_optional_string(Some(raw))
        .ok_or_else(|| GatewayError::Rejected("request identity is empty".into()))?;
    match caller_material_kind {
        "idempotency_key" => validate_idempotency_key(&material)?,
        _ => validate_submission_token(&material)?,
    }
    let caller_material_hash = hash_idempotency_material(caller_material_kind, &material);
    drop(material);
    let effective_key_hash = effective_idempotency_hash(
        &profile,
        session,
        &surface_id,
        retry_epoch,
        caller_material_kind,
        &caller_material_hash,
    );
    let observed = runtime.idempotency.observe(&effective_key_hash).await;
    validate(&runtime.profile_snapshot())?;
    let Some(record) = observed? else {
        return Ok((GatewayRequestEvidence::Unproven, None));
    };
    let fingerprint = SubmissionIdempotencyFingerprint {
        submission_hash: record::submission_hash(&record)?,
        retry_epoch,
        effective_key_hash,
        caller_material_kind,
        caller_material_hash,
        profile_name: profile.profile_name.clone(),
        profile_rev: profile.revision.to_string(),
        principal_id: session.principal.principal_id.clone(),
        surface_id,
    };
    record::decode(record, &fingerprint, retain_result)
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

#[cfg(test)]
mod tests;
