//! Folded input streams enter the same owned execution as direct submissions.

use super::idempotency::{
    SubmissionIdempotency, finish_request_output, finish_request_release_idempotency_and_fail,
    required_idempotency_material, reserve_submission_idempotency_if_present,
};
use super::{PreparedSubmission, entry_taint};
use crate::{
    GatewayAcceptedInputStream, GatewayDirectInput, GatewayError, GatewayPayloadProvenance,
    GatewayRuntime, GatewaySubmission, GatewaySubmissionBody, GatewaySubmitResult,
    LoweredSubmission, Value, inspect_lowered_submission, lower_submission,
};

pub(crate) async fn complete_input_stream(
    runtime: &GatewayRuntime,
    stream: GatewayAcceptedInputStream,
    payload: Value,
    provenance: Option<GatewayPayloadProvenance>,
) -> Result<GatewaySubmitResult, GatewayError> {
    let delivery = stream.request_guard.lease.delivery.clone();
    let result = complete_input_stream_inner(runtime, stream, payload, provenance).await;
    delivery.validate()?;
    result
}

async fn complete_input_stream_inner(
    runtime: &GatewayRuntime,
    stream: GatewayAcceptedInputStream,
    payload: Value,
    provenance: Option<GatewayPayloadProvenance>,
) -> Result<GatewaySubmitResult, GatewayError> {
    runtime.validate_input_stream_owner(&stream)?;
    let GatewayAcceptedInputStream {
        accepted,
        profile,
        session,
        surface_id,
        requested_output,
        options,
        deadline,
        mut request_guard,
        request_process,
        executor,
        ..
    } = stream;
    let submission = GatewaySubmission {
        surface_id,
        body: GatewaySubmissionBody::DirectInput(GatewayDirectInput {
            payload,
            provenance,
        }),
        requested_output,
        options,
        // The stream-open admission already froze and stored the combined deadline.
        server_deadline: None,
    };
    // Stream-open admission cannot authorize a later replay after its request
    // expires or is cancelled while the transport folds input chunks.
    request_guard.ensure_live(runtime, deadline)?;
    // Only the folded submission has the complete payload fingerprint. The
    // stream-open declaration cannot authorize a cached result on its own.
    let material = match required_idempotency_material(&submission) {
        Ok(material) => material,
        Err(error) => {
            return finish_request_release_idempotency_and_fail(
                &runtime.boot,
                request_process,
                None,
                error,
            )
            .await;
        }
    };
    let idempotency = match reserve_submission_idempotency_if_present(
        &runtime.idempotency,
        &profile,
        &session,
        &submission,
        material,
        runtime.boot.kernel().host_runtime().now_millis(),
    )
    .await
    {
        Ok(Some(SubmissionIdempotency::Replay(mut result))) => {
            request_guard.ensure_live(runtime, deadline)?;
            finish_request_output(&runtime.boot, request_process, &mut result.output).await?;
            request_guard.finish()?;
            return Ok(*result);
        }
        Ok(Some(SubmissionIdempotency::Reserved(reservation))) => Some(reservation),
        Ok(None) => None,
        Err(error) => {
            return finish_request_release_idempotency_and_fail(
                &runtime.boot,
                request_process,
                None,
                error,
            )
            .await;
        }
    };
    let LoweredSubmission {
        program,
        surface,
        objects,
    } = match lower_submission(submission.clone(), &profile, runtime, &session).await {
        Ok(lowered) => lowered,
        Err(e) => {
            return finish_request_release_idempotency_and_fail(
                &runtime.boot,
                request_process,
                idempotency.as_deref(),
                e,
            )
            .await;
        }
    };
    let admission = match inspect_lowered_submission(
        &program,
        &profile,
        &session.principal.principal_id,
        surface,
        &runtime.boot,
        true,
    ) {
        Ok(admission) => admission,
        Err(e) => {
            return finish_request_release_idempotency_and_fail(
                &runtime.boot,
                request_process,
                idempotency.as_deref(),
                e,
            )
            .await;
        }
    };
    if (admission.requires_idempotency || objects.requires_idempotency()) && idempotency.is_none() {
        return finish_request_release_idempotency_and_fail(
            &runtime.boot,
            request_process,
            idempotency.as_deref(),
            GatewayError::Rejected(
                "idempotency_key or submission_token is required for non-idempotent effects and single-use objects".into(),
            ),
        )
        .await;
    }
    let object_identity = idempotency
        .as_deref()
        .map(|reservation| reservation.effect_identity());
    let object_taint = match request_guard
        .commit_objects(
            runtime,
            &session,
            objects,
            deadline,
            object_identity.as_deref(),
        )
        .await
    {
        Ok(taint) => taint,
        Err(error) => {
            return finish_request_release_idempotency_and_fail(
                &runtime.boot,
                request_process,
                idempotency.as_deref(),
                error,
            )
            .await;
        }
    };
    let entry_taint = entry_taint(&profile, &object_taint);
    PreparedSubmission {
        boot: runtime.boot.clone(),
        profile,
        accepted,
        requested_output,
        deadline,
        idempotency,
        request_guard,
        request_process,
        executor,
        program,
        entry_taint,
    }
    .execute(None)?
    .complete()
    .await
}
