//! Typed application protocol conversion. Gateway owns admission and receipts.

use prost::Message as _;
use tonic::Status;
use xolotl_gateway::{
    BeginObjectUploadRequest, CommitObjectUploadResponse, GatewayAccepted, GatewayDescriptor,
    GatewayLimitProfile, GatewayModality, GatewayObjectKind, GatewayObjectUploadTicket,
    GatewayOutputEvent, GatewayPayloadProvenance, GatewayPublicationDescriptor, GatewaySubmission,
    GatewaySubmitResult, IssueObjectUploadTicketRequest, ObjectStoreProof, SubmitOptions,
};
use xolotl_proto::{
    MAX_VALUE_ENCODE_DEPTH, ValueEncodeLimits, dtype_from_str, failure_to_pb_bounded,
    frame_kind_from_str, output_mode_from_pb, value_from_pb_checked, value_to_pb_bounded,
    xolotl::v1 as common,
};
use xolotl_types::{CompletionOrigin, Outcome, OutputMode, Path, TaintSet, TaintSource, Value};

use common::application as pb;

pub(super) mod download;

#[cfg(feature = "structured-output")]
pub(super) mod structured;

pub(super) fn descriptor_to_pb(
    descriptor: &GatewayDescriptor,
    max_frame_bytes: usize,
) -> Result<pb::DescribeResponse, Status> {
    let mut budget = ConversionBudget::new(max_frame_bytes);
    budget.entries(descriptor.surfaces.len())?;
    budget.entries(descriptor.publications.len())?;
    let response = pb::DescribeResponse {
        profile_name: budget.string(&descriptor.profile_name)?,
        profile_rev: descriptor.profile_rev,
        surfaces: descriptor
            .surfaces
            .iter()
            .map(|surface| {
                Ok(pb::SurfaceDescriptor {
                    surface_id: budget.string(&surface.surface_id)?,
                    target: Some(budget.path(surface.target.path())?),
                    input_schema: budget.optional_value(surface.input_schema.as_ref())?,
                    output_schema: budget.optional_value(surface.output_schema.as_ref())?,
                    output_stream_schema: budget
                        .optional_value(surface.output_stream_schema.as_ref())?,
                })
            })
            .collect::<Result<_, Status>>()?,
        publications: descriptor
            .publications
            .iter()
            .map(|publication| publication_to_pb(publication, &mut budget))
            .collect::<Result<_, _>>()?,
        limits: Some(limits_to_pb(&descriptor.limits)?),
    };
    bounded_response(response, max_frame_bytes)
}

fn publication_to_pb(
    publication: &GatewayPublicationDescriptor,
    budget: &mut ConversionBudget,
) -> Result<pb::PublicationDescriptor, Status> {
    budget.entries(publication.properties.len())?;
    Ok(pb::PublicationDescriptor {
        protocol: budget.string(&publication.protocol)?,
        kind: budget.string(&publication.kind)?,
        name: budget.string(&publication.name)?,
        address: budget.optional_string(publication.address.as_deref())?,
        surface_id: budget.string(&publication.surface_id)?,
        title: budget.optional_string(publication.title.as_deref())?,
        description: budget.optional_string(publication.description.as_deref())?,
        properties: publication
            .properties
            .iter()
            .map(|(key, value)| Ok((budget.string(key)?, budget.value(value)?)))
            .collect::<Result<_, Status>>()?,
        annotations: budget.optional_value(publication.annotations.as_ref())?,
        metadata: budget.optional_value(publication.metadata.as_ref())?,
    })
}

fn limits_to_pb(limits: &GatewayLimitProfile) -> Result<pb::LimitProfile, Status> {
    fn count(value: usize) -> Result<u64, Status> {
        u64::try_from(value).map_err(|_error| Status::internal("gateway limit exceeds uint64"))
    }
    Ok(pb::LimitProfile {
        max_literal_bytes: count(limits.max_literal_bytes)?,
        max_collect_limit: count(limits.max_collect_limit)?,
        max_deadline_ms_from_now: limits.max_deadline_ms_from_now,
        max_in_flight_requests: count(limits.max_in_flight_requests)?,
        max_principal_in_flight_requests: count(limits.max_principal_in_flight_requests)?,
        max_surface_in_flight_requests: count(limits.max_surface_in_flight_requests)?,
        max_risk_class_in_flight_requests: count(limits.max_risk_class_in_flight_requests)?,
        budget: Some(pb::BudgetProfile {
            max_inflight_ops: limits.budget.max_inflight_ops,
            max_wall_ms: limits.budget.max_wall_ms,
            max_bytes_in: limits.budget.max_bytes_in,
            max_bytes_out: limits.budget.max_bytes_out,
            max_inline_value_bytes: limits.budget.max_inline_value_bytes,
            max_stream_items: limits.budget.max_stream_items,
            max_estimated_cost_micro_usd: limits.budget.max_estimated_cost_micro_usd,
        }),
        max_stream_items: count(limits.max_stream_items)?,
        max_stream_bytes: count(limits.max_stream_bytes)?,
        max_stream_inline_item_bytes: count(limits.max_stream_inline_item_bytes)?,
    })
}

pub(super) fn issue_upload_ticket_from_pb(
    request: pb::IssueUploadTicketRequest,
) -> Result<IssueObjectUploadTicketRequest, Status> {
    let modality = match pb::Modality::try_from(request.modality) {
        Ok(pb::Modality::Value) => GatewayModality::Value,
        Ok(pb::Modality::Text) => GatewayModality::Text,
        Ok(pb::Modality::Bytes) => GatewayModality::Bytes,
        Ok(pb::Modality::Tensor) => GatewayModality::Tensor,
        Ok(pb::Modality::AudioFrame) => GatewayModality::AudioFrame,
        Ok(pb::Modality::VideoFrame) => GatewayModality::VideoFrame,
        Ok(pb::Modality::PoseFrame) => GatewayModality::PoseFrame,
        Ok(pb::Modality::SensorFrame) => GatewayModality::SensorFrame,
        Ok(pb::Modality::Event) => GatewayModality::Event,
        Ok(pb::Modality::Control) => GatewayModality::Control,
        Ok(pb::Modality::Unspecified) | Err(_) => {
            return Err(Status::invalid_argument(
                "upload modality is missing or unknown",
            ));
        }
    };
    Ok(IssueObjectUploadTicketRequest {
        surface_id: request.surface_id,
        submission_token: request.submission_token,
        modality,
        expected_size: request.expected_size,
        expected_digest: request.expected_digest,
        allowed_media_types: request.allowed_media_types,
        expires_in_ms: request.expires_in_ms,
        single_use: request.single_use,
    })
}

pub(super) fn upload_ticket_to_pb(
    ticket: &GatewayObjectUploadTicket,
) -> pb::IssueUploadTicketResponse {
    pb::IssueUploadTicketResponse {
        ticket_id: ticket.ticket_id().to_owned(),
        expires_at_ms: ticket.expires_at_ms(),
        single_use: ticket.is_single_use(),
    }
}

pub(super) fn begin_upload_from_pb(request: pb::BeginObjectUpload) -> BeginObjectUploadRequest {
    BeginObjectUploadRequest {
        ticket_id: request.ticket_id,
        media_type: request.media_type,
        submission_token: request.submission_token,
    }
}

pub(super) fn finish_upload_from_pb(
    request: pb::FinishObjectUpload,
) -> Result<GatewayObjectKind, Status> {
    use pb::finish_object_upload::Kind;
    match request.kind {
        Some(Kind::Blob(_)) => Ok(GatewayObjectKind::Blob),
        Some(Kind::Tensor(tensor)) => {
            let dtype = dtype_from_str(&tensor.dtype)
                .ok_or_else(|| Status::invalid_argument("unknown tensor dtype"))?;
            Ok(GatewayObjectKind::Tensor {
                dtype,
                shape: tensor.shape,
            })
        }
        Some(Kind::Frame(frame)) => {
            let kind = frame_kind_from_str(&frame.kind)
                .ok_or_else(|| Status::invalid_argument("unknown frame kind"))?;
            Ok(GatewayObjectKind::Frame {
                ts_nanos: frame.ts_nanos,
                kind,
            })
        }
        None => Err(Status::invalid_argument("upload finish kind is required")),
    }
}

pub(super) fn upload_response_to_pb(
    response: &CommitObjectUploadResponse,
    max_frame_bytes: usize,
) -> Result<pb::UploadObjectResponse, Status> {
    let mut budget = ConversionBudget::new(max_frame_bytes);
    let response = pb::UploadObjectResponse {
        item: Some(budget.value(&response.item)?),
        provenance: Some(provenance_to_pb(&response.provenance, &mut budget)?),
        digest: budget.string(&response.digest)?,
        size: response.size,
    };
    bounded_response(response, max_frame_bytes)
}

pub(super) fn submission_from_pb(request: pb::SubmitRequest) -> Result<GatewaySubmission, Status> {
    decode_submission(request, SubmissionRpc::Submit)
}

pub(super) fn output_submission_from_pb(
    request: pb::SubmitRequest,
) -> Result<GatewaySubmission, Status> {
    decode_submission(request, SubmissionRpc::SubmitOutput)
}

enum SubmissionRpc {
    Submit,
    SubmitOutput,
}

fn decode_submission(
    request: pb::SubmitRequest,
    rpc: SubmissionRpc,
) -> Result<GatewaySubmission, Status> {
    let output = request
        .output
        .as_ref()
        .map(output_mode_from_pb)
        .transpose()
        .map_err(|error| Status::invalid_argument(error.to_string()))?
        .unwrap_or(OutputMode::Unary);
    match (rpc, output) {
        (SubmissionRpc::Submit, OutputMode::Unary | OutputMode::Collect { .. })
        | (SubmissionRpc::SubmitOutput, OutputMode::Stream) => {}
        (SubmissionRpc::Submit, OutputMode::Stream) => {
            return Err(Status::invalid_argument(
                "Submit does not support Stream output",
            ));
        }
        (SubmissionRpc::Submit, OutputMode::AsyncProcess | OutputMode::SinkOnly) => {
            return Err(Status::invalid_argument(
                "Submit supports only Unary and Collect output",
            ));
        }
        (SubmissionRpc::SubmitOutput, _) => {
            return Err(Status::invalid_argument(
                "SubmitOutput requires Stream output",
            ));
        }
    }
    let payload = request
        .payload
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("Submit payload is required"))?;
    let payload = value_from_pb_checked(payload)
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    let options = request.options.unwrap_or_default();
    let mut submission = GatewaySubmission::direct_input(request.surface_id, payload)
        .with_requested_output(output)
        .with_options(SubmitOptions {
            idempotency_key: options.idempotency_key,
            submission_token: options.submission_token,
            deadline_ms: options.deadline_ms,
            requested_encoding: options.requested_encoding,
        });
    if let Some(provenance) = request.provenance {
        submission = submission.with_provenance(provenance_from_pb(provenance));
    }
    Ok(submission)
}

pub(super) fn submit_response_to_pb(
    response: &GatewaySubmitResult,
    max_frame_bytes: usize,
) -> Result<pb::SubmitResponse, Status> {
    let mut budget = ConversionBudget::new(max_frame_bytes);
    bounded_response(
        pb::SubmitResponse {
            accepted: Some(budget.accepted(&response.accepted)?),
            completion: Some(submission_completion_to_pb(response, &mut budget)?),
        },
        max_frame_bytes,
    )
}

pub(super) fn output_accepted_to_pb(
    accepted: &GatewayAccepted,
    max_frame_bytes: usize,
) -> Result<pb::SubmitOutputResponse, Status> {
    let mut budget = ConversionBudget::new(max_frame_bytes);
    bounded_response(
        pb::SubmitOutputResponse {
            event: Some(pb::submit_output_response::Event::Accepted(
                budget.accepted(accepted)?,
            )),
        },
        max_frame_bytes,
    )
}

pub(super) fn output_event_to_pb(
    event: &GatewayOutputEvent,
    max_frame_bytes: usize,
) -> Result<pb::SubmitOutputResponse, Status> {
    use pb::submit_output_response::Event;
    let mut budget = ConversionBudget::new(max_frame_bytes);
    let event = match event {
        GatewayOutputEvent::Chunk(chunk) => Event::Chunk(pb::OutputChunk {
            item: Some(budget.output_value(&chunk.value)?),
            taint: Some(budget.taint(&chunk.taint)?),
        }),
        GatewayOutputEvent::Complete(completion) => {
            Event::Completed(submission_completion_to_pb(completion, &mut budget)?)
        }
    };
    bounded_response(
        pb::SubmitOutputResponse { event: Some(event) },
        max_frame_bytes,
    )
}

fn submission_completion_to_pb(
    response: &GatewaySubmitResult,
    budget: &mut ConversionBudget,
) -> Result<pb::SubmissionCompletion, Status> {
    Ok(pb::SubmissionCompletion {
        outcome: Some(budget.outcome(&response.output.outcome)?),
        origin: match response.origin {
            CompletionOrigin::CurrentAttempt => pb::CompletionOrigin::CurrentAttempt,
            CompletionOrigin::CachedOutcome => pb::CompletionOrigin::CachedOutcome,
        } as i32,
        taint: Some(budget.taint(&response.output.taint)?),
    })
}

fn provenance_from_pb(provenance: common::PayloadProvenance) -> GatewayPayloadProvenance {
    GatewayPayloadProvenance {
        upload_ticket: provenance.upload_ticket,
        store_proof: provenance.store_proof.map(|proof| ObjectStoreProof {
            store_id: proof.store_id,
            proof: proof.proof,
        }),
    }
}

fn provenance_to_pb(
    provenance: &GatewayPayloadProvenance,
    budget: &mut ConversionBudget,
) -> Result<common::PayloadProvenance, Status> {
    Ok(common::PayloadProvenance {
        upload_ticket: budget.optional_string(provenance.upload_ticket.as_deref())?,
        store_proof: provenance
            .store_proof
            .as_ref()
            .map(|proof| -> Result<_, Status> {
                Ok(common::ObjectStoreProof {
                    store_id: budget.string(&proof.store_id)?,
                    proof: budget.string(&proof.proof)?,
                })
            })
            .transpose()?,
    })
}

fn bounded_response<T: prost::Message>(response: T, max_frame_bytes: usize) -> Result<T, Status> {
    if response.encoded_len() > max_frame_bytes {
        return Err(response_too_large());
    }
    Ok(response)
}

fn response_too_large() -> Status {
    Status::resource_exhausted("application response exceeds the configured frame budget")
}

// All variable-sized fields share one allowance before cloning. Length prefixes
// and fixed scalars are checked by the final exact encoded-length check.
struct ConversionBudget {
    remaining: usize,
}

impl ConversionBudget {
    fn new(limit: usize) -> Self {
        Self { remaining: limit }
    }

    fn charge(&mut self, bytes: usize) -> Result<(), Status> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or_else(response_too_large)?;
        Ok(())
    }

    fn entries(&mut self, count: usize) -> Result<(), Status> {
        // Even an empty repeated message or string needs a tag and a length.
        self.charge(count.checked_mul(2).ok_or_else(response_too_large)?)
    }

    fn string(&mut self, text: &str) -> Result<String, Status> {
        self.charge(text.len())?;
        Ok(text.to_owned())
    }

    fn optional_string(&mut self, text: Option<&str>) -> Result<Option<String>, Status> {
        text.map(|text| self.string(text)).transpose()
    }

    fn path(&mut self, path: &Path) -> Result<common::Path, Status> {
        self.entries(path.segments().len())?;
        Ok(common::Path {
            cluster: self.optional_string(path.cluster())?,
            scheme: self.string(path.scheme())?,
            segments: path
                .segments()
                .iter()
                .map(|segment| self.string(segment))
                .collect::<Result<_, _>>()?,
        })
    }

    fn value(&mut self, value: &Value) -> Result<common::Value, Status> {
        let encoded = value_to_pb_bounded(
            value,
            ValueEncodeLimits {
                max_nodes: self.remaining,
                max_depth: MAX_VALUE_ENCODE_DEPTH,
                // Packed uint64 dimensions can occupy one wire byte but eight
                // copied bytes. Keep conversion bounded without narrowing the
                // configured wire limit for compact tensor shapes.
                max_inline_bytes: self.remaining.saturating_mul(size_of::<u64>()),
            },
        )
        .map_err(|_error| response_too_large())?;
        self.charge(encoded.encoded_len())?;
        Ok(encoded)
    }

    fn optional_value(&mut self, value: Option<&Value>) -> Result<Option<common::Value>, Status> {
        value.map(|value| self.value(value)).transpose()
    }

    fn accepted(&mut self, accepted: &GatewayAccepted) -> Result<pb::GatewayAccepted, Status> {
        Ok(pb::GatewayAccepted {
            submission_id: self.string(&accepted.submission_id)?,
            trace_root: self.string(&accepted.trace_root)?,
            profile_rev: accepted.profile_rev,
            surface_id: self.string(&accepted.surface_id)?,
        })
    }

    fn output_value(&mut self, value: &Value) -> Result<pb::OutputValue, Status> {
        Ok(pb::OutputValue {
            content: Some(pb::output_value::Content::Inline(self.value(value)?)),
        })
    }

    fn outcome(&mut self, outcome: &Outcome) -> Result<pb::OutputOutcome, Status> {
        use pb::output_outcome::Kind;
        let kind = match outcome {
            Outcome::Done(value) => Kind::Done(self.output_value(value)?),
            Outcome::Short(value) => Kind::Short(self.output_value(value)?),
            Outcome::Fail(failure) => {
                let encoded = failure_to_pb_bounded(failure, self.remaining)
                    .map_err(|_error| response_too_large())?;
                self.charge(encoded.encoded_len())?;
                Kind::Fail(pb::OutputFailure {
                    content: Some(pb::output_failure::Content::Inline(encoded)),
                })
            }
        };
        Ok(pb::OutputOutcome { kind: Some(kind) })
    }

    fn taint(&mut self, taint: &TaintSet) -> Result<common::TaintSet, Status> {
        use common::taint_source::{Inbound, Kind, Marker};
        self.entries(taint.sources().len())?;
        let sources = taint
            .sources()
            .iter()
            .map(|source| {
                let kind = match source {
                    TaintSource::AuthorConstant => Kind::AuthorConstant(Marker {}),
                    TaintSource::ModelOutput => Kind::ModelOutput(Marker {}),
                    TaintSource::Inbound { source, channel } => Kind::Inbound(Inbound {
                        source: self.string(source)?,
                        channel: self.string(channel)?,
                    }),
                    TaintSource::Fetched { host } => Kind::FetchedHost(self.string(host)?),
                    TaintSource::Protected { path } => Kind::ProtectedPath(self.path(path)?),
                };
                Ok(common::TaintSource { kind: Some(kind) })
            })
            .collect::<Result<_, Status>>()?;
        Ok(common::TaintSet { sources })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod output_tests;
