use anyhow::{Context as _, Result, ensure};
use xolotl_gateway::{GatewayAccepted, GatewayBudgetProfile};
use xolotl_types::{BlobRef, DType, ExecutionOutput, Failure, FloatBits, FrameKind};

use super::*;

const FRAME_LIMIT: usize = 64 * 1024;

fn input_request() -> pb::SubmitRequest {
    pb::SubmitRequest {
        surface_id: "infer".into(),
        payload: Some(common::Value::default()),
        ..Default::default()
    }
}

fn result(outcome: Outcome) -> GatewaySubmitResult {
    GatewaySubmitResult {
        accepted: GatewayAccepted {
            submission_id: "submission".into(),
            trace_root: "trace".into(),
            profile_rev: u64::MAX,
            surface_id: "infer".into(),
        },
        output: ExecutionOutput::new(outcome, TaintSet::pristine()),
        origin: CompletionOrigin::CurrentAttempt,
    }
}

fn blob() -> BlobRef {
    BlobRef {
        hash: "a".repeat(64),
        size: u64::MAX,
        mime: Some("x/y".into()),
    }
}

fn publication(metadata: Option<Value>) -> GatewayPublicationDescriptor {
    GatewayPublicationDescriptor {
        protocol: "grpc".into(),
        kind: "surface".into(),
        name: "inference".into(),
        address: None,
        surface_id: "infer".into(),
        title: None,
        description: None,
        properties: Default::default(),
        annotations: None,
        metadata,
    }
}

fn descriptor(publications: Vec<GatewayPublicationDescriptor>) -> GatewayDescriptor {
    GatewayDescriptor {
        profile_name: "application".into(),
        profile_rev: u64::MAX,
        surfaces: Vec::new(),
        publications,
        limits: GatewayLimitProfile::default(),
    }
}

#[test]
fn submission_accepts_unary_collect_and_preserves_options() -> Result<()> {
    ensure!(submission_from_pb(input_request())?.requested_output() == OutputMode::Unary);
    for mode in [
        OutputMode::Unary,
        OutputMode::Collect { limit: 0 },
        OutputMode::Collect { limit: usize::MAX },
    ] {
        let mut request = input_request();
        request.output = Some(xolotl_proto::output_mode_to_pb(mode));
        request.options = Some(pb::SubmitOptions {
            idempotency_key: Some("retry-key".into()),
            submission_token: Some("token".into()),
            deadline_ms: Some(u64::MAX),
            requested_encoding: Some("protobuf".into()),
        });
        let request = pb::SubmitRequest::decode(request.encode_to_vec().as_slice())?;
        let submission = submission_from_pb(request)?;
        ensure!(submission.surface_id() == "infer");
        ensure!(submission.requested_output() == mode);
        ensure!(
            submission.options()
                == &SubmitOptions {
                    idempotency_key: Some("retry-key".into()),
                    submission_token: Some("token".into()),
                    deadline_ms: Some(u64::MAX),
                    requested_encoding: Some("protobuf".into()),
                }
        );
    }
    Ok(())
}

#[test]
fn submission_rejects_unsupported_or_unknown_output() -> Result<()> {
    for kind in [
        common::OutputModeKind::Stream as i32,
        common::OutputModeKind::AsyncProcess as i32,
        common::OutputModeKind::SinkOnly as i32,
        common::OutputModeKind::Unspecified as i32,
        99,
    ] {
        let mut request = input_request();
        request.output = Some(common::OutputMode {
            kind,
            collect_limit: 1,
        });
        ensure!(
            matches!(submission_from_pb(request), Err(status) if status.code() == tonic::Code::InvalidArgument)
        );
    }
    Ok(())
}

#[test]
fn submission_requires_outer_payload_and_checks_nested_values() -> Result<()> {
    let request = pb::SubmitRequest {
        payload: None,
        ..input_request()
    };
    ensure!(
        matches!(submission_from_pb(request), Err(status) if status.code() == tonic::Code::InvalidArgument)
    );
    let request = pb::SubmitRequest {
        payload: Some(common::Value {
            kind: Some(common::value::Kind::ListVal(common::ListValue {
                items: vec![common::Value {
                    kind: Some(common::value::Kind::TensorVal(common::TensorRef {
                        blob: Some(common::BlobRef {
                            hash: "a".repeat(64),
                            size: 4,
                            mime: None,
                        }),
                        dtype: "unknown".into(),
                        shape: vec![1],
                    })),
                }],
            })),
        }),
        ..input_request()
    };
    ensure!(
        matches!(submission_from_pb(request), Err(status) if status.code() == tonic::Code::InvalidArgument)
    );
    Ok(())
}

#[test]
fn ticket_constraints_keep_unsigned_values_and_unknown_modality_is_rejected() -> Result<()> {
    let request = pb::IssueUploadTicketRequest {
        surface_id: "infer".into(),
        submission_token: Some("token".into()),
        modality: pb::Modality::Tensor as i32,
        expected_size: Some(u64::MAX),
        expected_digest: Some("a".repeat(64)),
        allowed_media_types: vec!["application/*".into()],
        expires_in_ms: Some(u64::MAX),
        single_use: true,
    };
    let request = pb::IssueUploadTicketRequest::decode(request.encode_to_vec().as_slice())?;
    let ticket = issue_upload_ticket_from_pb(request)?;
    ensure!(ticket.surface_id == "infer" && ticket.modality == GatewayModality::Tensor);
    ensure!(ticket.submission_token.as_deref() == Some("token"));
    ensure!(ticket.expected_size == Some(u64::MAX) && ticket.expires_in_ms == Some(u64::MAX));
    ensure!(ticket.expected_digest == Some("a".repeat(64)) && ticket.single_use);
    ensure!(ticket.allowed_media_types == ["application/*"]);
    for modality in [pb::Modality::Unspecified as i32, -1, 99] {
        let request = pb::IssueUploadTicketRequest {
            modality,
            ..Default::default()
        };
        ensure!(
            matches!(issue_upload_ticket_from_pb(request), Err(status) if status.code() == tonic::Code::InvalidArgument)
        );
    }
    Ok(())
}

#[test]
fn finish_keeps_canonical_dtypes_shapes_and_timestamps() -> Result<()> {
    for (name, dtype) in [
        ("f16", DType::F16),
        ("bf16", DType::Bf16),
        ("f32", DType::F32),
        ("f64", DType::F64),
        ("i8", DType::I8),
        ("i16", DType::I16),
        ("i32", DType::I32),
        ("i64", DType::I64),
        ("u8", DType::U8),
        ("bool", DType::Bool),
    ] {
        let finish = pb::FinishObjectUpload {
            kind: Some(pb::finish_object_upload::Kind::Tensor(pb::TensorUpload {
                dtype: name.into(),
                shape: vec![0, 1, u64::MAX],
            })),
        };
        let finish = pb::FinishObjectUpload::decode(finish.encode_to_vec().as_slice())?;
        ensure!(
            finish_upload_from_pb(finish)?
                == GatewayObjectKind::Tensor {
                    dtype,
                    shape: vec![0, 1, u64::MAX]
                }
        );
    }
    for (name, kind) in [
        ("audio", FrameKind::Audio),
        ("video", FrameKind::Video),
        ("pose", FrameKind::Pose),
        ("sensor", FrameKind::Sensor),
    ] {
        let finish = pb::FinishObjectUpload {
            kind: Some(pb::finish_object_upload::Kind::Frame(pb::FrameUpload {
                ts_nanos: i64::MIN,
                kind: name.into(),
            })),
        };
        let finish = pb::FinishObjectUpload::decode(finish.encode_to_vec().as_slice())?;
        ensure!(
            finish_upload_from_pb(finish)?
                == GatewayObjectKind::Frame {
                    ts_nanos: i64::MIN,
                    kind
                }
        );
    }
    Ok(())
}

#[test]
fn finish_requires_known_interpretation() -> Result<()> {
    for finish in [
        pb::FinishObjectUpload::default(),
        pb::FinishObjectUpload {
            kind: Some(pb::finish_object_upload::Kind::Tensor(pb::TensorUpload {
                dtype: "F32".into(),
                shape: vec![1],
            })),
        },
        pb::FinishObjectUpload {
            kind: Some(pb::finish_object_upload::Kind::Frame(pb::FrameUpload {
                ts_nanos: 0,
                kind: "unknown".into(),
            })),
        },
    ] {
        ensure!(
            matches!(finish_upload_from_pb(finish), Err(status) if status.code() == tonic::Code::InvalidArgument)
        );
    }
    Ok(())
}

#[test]
fn upload_receipt_keeps_typed_content_and_common_provenance() -> Result<()> {
    let provenance = GatewayPayloadProvenance {
        upload_ticket: None,
        store_proof: Some(ObjectStoreProof {
            store_id: "gateway-upload-ticket-v1".into(),
            proof: "receipt".into(),
        }),
    };
    for item in [
        Value::blob(blob()),
        Value::tensor(blob(), DType::Bf16, vec![u64::MAX, 1]),
        Value::frame(blob(), i64::MIN, FrameKind::Sensor),
    ] {
        let response = CommitObjectUploadResponse {
            item,
            provenance: provenance.clone(),
            digest: "a".repeat(64),
            size: u64::MAX,
        };
        let wire = upload_response_to_pb(&response, FRAME_LIMIT)?;
        let decoded = pb::UploadObjectResponse::decode(wire.encode_to_vec().as_slice())?;
        ensure!(decoded.size == u64::MAX && decoded.digest == response.digest);
        ensure!(
            value_from_pb_checked(decoded.item.as_ref().context("missing typed receipt")?)?
                == response.item
        );
        ensure!(
            provenance_from_pb(decoded.provenance.context("missing provenance")?) == provenance
        );
    }
    Ok(())
}

#[test]
fn outcomes_keep_exact_numbers_and_common_failure_contract() -> Result<()> {
    let value = Value::list(vec![
        Value::integer(i64::MIN),
        Value::integer(i64::MAX),
        Value::float(FloatBits(-0.0)),
        Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_1234))),
        Value::bytes(vec![0, 255]),
    ]);
    for outcome in [Outcome::Done(value.clone()), Outcome::Short(value.clone())] {
        let response = result(outcome);
        let wire = submit_response_to_pb(&response, FRAME_LIMIT)?;
        let decoded = pb::SubmitResponse::decode(wire.encode_to_vec().as_slice())?;
        ensure!(decoded.accepted.context("missing acceptance")?.profile_rev == u64::MAX);
        let completed = decoded.completion.context("missing completion")?;
        ensure!(
            completed
                .taint
                .context("missing lineage")?
                .sources
                .is_empty()
        );
        let encoded_value = match completed.outcome.and_then(|outcome| outcome.kind) {
            Some(
                pb::output_outcome::Kind::Done(value) | pb::output_outcome::Kind::Short(value),
            ) => {
                let Some(pb::output_value::Content::Inline(value)) = value.content else {
                    anyhow::bail!("expected inline value");
                };
                value
            }
            other => anyhow::bail!("unexpected outcome {other:?}"),
        };
        ensure!(value_from_pb_checked(&encoded_value)? == value);
    }
    for failure in [
        Failure::Timeout,
        Failure::InvalidInput {
            reason: "bad input".into(),
        },
    ] {
        let response = result(Outcome::Fail(failure));
        let wire = submit_response_to_pb(&response, FRAME_LIMIT)?;
        let completed = wire.completion.context("missing completion")?;
        let Some(pb::output_outcome::Kind::Fail(failure)) =
            completed.outcome.and_then(|outcome| outcome.kind)
        else {
            anyhow::bail!("expected failure");
        };
        let Some(pb::output_failure::Content::Inline(failure)) = failure.content else {
            anyhow::bail!("expected inline failure");
        };
        ensure!(Outcome::Fail(xolotl_proto::failure_from_pb(&failure)?) == response.output.outcome);
        ensure!(
            completed
                .taint
                .context("missing failure lineage")?
                .sources
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn discovery_keeps_full_width_limits_and_typed_publication_metadata() -> Result<()> {
    let value = Value::list(vec![
        Value::integer(i64::MIN),
        Value::float(FloatBits(-0.0)),
    ]);
    let mut descriptor = descriptor(vec![publication(Some(value.clone()))]);
    descriptor.limits = GatewayLimitProfile {
        max_literal_bytes: usize::MAX,
        max_deadline_ms_from_now: i64::MAX,
        budget: GatewayBudgetProfile {
            max_bytes_in: Some(u64::MAX),
            max_wall_ms: Some(0),
            max_bytes_out: None,
            ..Default::default()
        },
        ..Default::default()
    };
    let wire = descriptor_to_pb(&descriptor, FRAME_LIMIT)?;
    let decoded = pb::DescribeResponse::decode(wire.encode_to_vec().as_slice())?;
    ensure!(decoded.profile_rev == u64::MAX);
    let limits = decoded.limits.context("missing limits")?;
    ensure!(limits.max_literal_bytes == u64::try_from(usize::MAX)?);
    ensure!(limits.max_deadline_ms_from_now == i64::MAX);
    let budget = limits.budget.context("missing budget")?;
    ensure!(budget.max_bytes_in == Some(u64::MAX));
    ensure!(budget.max_wall_ms == Some(0) && budget.max_bytes_out.is_none());
    let publication = decoded
        .publications
        .first()
        .context("missing publication")?;
    ensure!(
        value_from_pb_checked(publication.metadata.as_ref().context("missing metadata")?)? == value
    );
    Ok(())
}

#[test]
fn response_limit_covers_envelope_and_acceptance_fields() -> Result<()> {
    let response = result(Outcome::Done(Value::string("x".repeat(100))));
    let wire = submit_response_to_pb(&response, FRAME_LIMIT)?;
    let exact = wire.encoded_len();
    ensure!(submit_response_to_pb(&response, exact)? == wire);
    ensure!(
        matches!(submit_response_to_pb(&response, exact - 1), Err(status) if status.code() == tonic::Code::ResourceExhausted)
    );
    let response = result(Outcome::Fail(Failure::InvalidInput {
        reason: "x".repeat(FRAME_LIMIT),
    }));
    ensure!(
        matches!(submit_response_to_pb(&response, 128), Err(status) if status.code() == tonic::Code::ResourceExhausted)
    );
    Ok(())
}

#[test]
fn discovery_fields_and_repeated_items_share_one_budget() -> Result<()> {
    let descriptor = descriptor(vec![publication(Some(Value::string("x".repeat(80)))); 2]);
    ensure!(
        matches!(descriptor_to_pb(&descriptor, 128), Err(status) if status.code() == tonic::Code::ResourceExhausted)
    );
    let mut budget = ConversionBudget::new(32);
    ensure!(
        matches!(budget.entries(usize::MAX), Err(status) if status.code() == tonic::Code::ResourceExhausted)
    );
    let path = Path::parse("effect://inference/infer")?;
    let path = ConversionBudget::new(FRAME_LIMIT).path(&path)?;
    ensure!(xolotl_proto::path_from_pb(&path)? == Path::parse("effect://inference/infer")?);
    Ok(())
}

#[test]
fn outbound_value_depth_and_nodes_are_bounded() -> Result<()> {
    let value =
        (0..MAX_VALUE_ENCODE_DEPTH).fold(Value::null(), |child, _| Value::list(vec![child]));
    ensure!(
        matches!(submit_response_to_pb(&result(Outcome::Done(value)), FRAME_LIMIT), Err(status) if status.code() == tonic::Code::ResourceExhausted)
    );
    let value = Value::list(vec![Value::null(); 1024]);
    ensure!(
        matches!(submit_response_to_pb(&result(Outcome::Done(value)), 128), Err(status) if status.code() == tonic::Code::ResourceExhausted)
    );
    Ok(())
}

#[test]
fn packed_tensor_shapes_obey_the_encoded_frame_limit() -> Result<()> {
    let response = result(Outcome::Done(Value::tensor(
        blob(),
        DType::F32,
        vec![0; 1024],
    )));
    let wire = submit_response_to_pb(&response, FRAME_LIMIT)?;
    let exact = wire.encoded_len();
    ensure!(exact < 2048);
    ensure!(submit_response_to_pb(&response, exact)? == wire);
    ensure!(
        matches!(submit_response_to_pb(&response, exact - 1), Err(status) if status.code() == tonic::Code::ResourceExhausted)
    );
    Ok(())
}
