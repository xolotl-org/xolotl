//! Folded input streams enter the same owned execution as direct submissions.

use super::idempotency::finish_request_release_idempotency_and_fail;
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
    runtime.validate_input_stream_owner(&stream)?;
    let GatewayAcceptedInputStream {
        accepted,
        profile,
        session,
        surface_id,
        requested_output,
        options,
        deadline,
        idempotency,
        request_guard,
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
    if admission.requires_idempotency && idempotency.is_none() {
        return finish_request_release_idempotency_and_fail(
            &runtime.boot,
            request_process,
            idempotency.as_deref(),
            GatewayError::Rejected(
                "idempotency_key or submission_token is required for non-idempotent effects".into(),
            ),
        )
        .await;
    }
    let object_taint = match request_guard
        .commit_objects(runtime, &session, objects, deadline)
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
    .execute(None)
    .complete()
    .await
}
