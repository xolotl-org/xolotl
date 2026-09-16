//! Projection of already published, explicitly authorized output objects.

use xolotl_gateway::{GatewayExternalizedOutput, GatewayOutputKind};

use super::*;

pub(in crate::application) fn event_to_pb(
    output: &GatewayExternalizedOutput,
    max_frame_bytes: usize,
) -> Result<pb::SubmitOutputResponse, Status> {
    output.validate().map_err(super::super::gateway_status)?;
    let mut budget = ConversionBudget::new(max_frame_bytes);
    let object = object_to_pb(output, &mut budget)?;
    let taint = Some(budget.taint(output.taint())?);
    let event = if output.kind() == GatewayOutputKind::Chunk {
        pb::submit_output_response::Event::Chunk(pb::OutputChunk {
            item: Some(object_value(object)),
            taint,
        })
    } else {
        pb::submit_output_response::Event::Completed(completion(output, object, taint)?)
    };
    bounded_response(
        pb::SubmitOutputResponse { event: Some(event) },
        max_frame_bytes,
    )
}

pub(in crate::application) fn submit_to_pb(
    output: &GatewayExternalizedOutput,
    max_frame_bytes: usize,
) -> Result<pb::SubmitResponse, Status> {
    output.validate().map_err(super::super::gateway_status)?;
    let GatewayOutputEvent::Complete(result) = output.original_event() else {
        return Err(Status::internal(
            "unary externalization returned an incremental item",
        ));
    };
    let mut budget = ConversionBudget::new(max_frame_bytes);
    let accepted = Some(budget.accepted(&result.accepted)?);
    let object = object_to_pb(output, &mut budget)?;
    let taint = Some(budget.taint(output.taint())?);
    bounded_response(
        pb::SubmitResponse {
            accepted,
            completion: Some(completion(output, object, taint)?),
        },
        max_frame_bytes,
    )
}

fn completion(
    output: &GatewayExternalizedOutput,
    object: pb::EncodedOutputObject,
    taint: Option<common::TaintSet>,
) -> Result<pb::SubmissionCompletion, Status> {
    use pb::output_outcome::Kind;
    let kind = match output.kind() {
        GatewayOutputKind::Done => Kind::Done(object_value(object)),
        GatewayOutputKind::Short => Kind::Short(object_value(object)),
        GatewayOutputKind::Fail => Kind::Fail(pb::OutputFailure {
            content: Some(pb::output_failure::Content::Object(object)),
        }),
        GatewayOutputKind::Chunk => return Err(Status::internal("chunk has no final outcome")),
    };
    let origin = match output.origin() {
        Some(CompletionOrigin::CurrentAttempt) => pb::CompletionOrigin::CurrentAttempt,
        Some(CompletionOrigin::CachedOutcome) => pb::CompletionOrigin::CachedOutcome,
        None => return Err(Status::internal("completion origin is missing")),
    } as i32;
    Ok(pb::SubmissionCompletion {
        outcome: Some(pb::OutputOutcome { kind: Some(kind) }),
        origin,
        taint,
    })
}

fn object_to_pb(
    output: &GatewayExternalizedOutput,
    budget: &mut ConversionBudget,
) -> Result<pb::EncodedOutputObject, Status> {
    let reference = output.reference();
    Ok(pb::EncodedOutputObject {
        encoding: budget.string(reference.encoding.as_str())?,
        blob: Some(common::BlobRef {
            hash: budget.string(&reference.blob.hash)?,
            size: reference.blob.size,
            mime: budget.optional_string(reference.blob.mime.as_deref())?,
        }),
        read_grant_id: budget.string(output.grant().grant_id())?,
        expires_at_ms: output.grant().expires_at_ms(),
    })
}

fn object_value(object: pb::EncodedOutputObject) -> pb::OutputValue {
    pb::OutputValue {
        content: Some(pb::output_value::Content::Object(object)),
    }
}

#[cfg(test)]
mod tests;
