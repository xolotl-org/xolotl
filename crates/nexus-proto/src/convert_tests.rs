//! Round-trip tests for the wire conversions. Every `Value` variant and the
//! Path / Capability / Outcome mappings must survive a `to_pb`/`from_pb` cycle.

use crate::convert::*;
use anyhow::{Context, anyhow, bail, ensure};
use nexus_graph::{DoNode, OperationTemplate, StepRef};
use nexus_types::{
    BlobRef, Capability, DType, Failure, FloatBits, FrameKind, Outcome, OutputMode, Path,
    Predicate, ProcessId, ResourceName, StreamMarker, TensorRef, Value,
};
use std::collections::BTreeMap;

fn p(path: &str) -> anyhow::Result<Path> {
    Path::parse(path).map_err(|error| anyhow!("path parse failed for {path}: {error}"))
}

fn pb_path(path: &str) -> anyhow::Result<crate::nexus::v1::Path> {
    Ok(path_to_pb(&p(path)?))
}

fn op_template(
    path: &str,
    output: OutputMode,
    literal_input: Option<Value>,
) -> anyhow::Result<OperationTemplate> {
    Ok(OperationTemplate {
        target: ResourceName::new(p(path)?),
        method: "invoke".into(),
        method_id: None,
        output,
        literal_input,
    })
}

fn blob() -> BlobRef {
    BlobRef {
        hash: "abc123".into(),
        size: 42,
        mime: Some("image/png".into()),
    }
}

fn pb_blob() -> crate::nexus::v1::BlobRef {
    let blob = blob();
    crate::nexus::v1::BlobRef {
        hash: blob.hash,
        size: blob.size,
        mime: blob.mime,
    }
}

fn composite_value() -> Value {
    let mut m = BTreeMap::new();
    m.insert("null".into(), Value::Null);
    m.insert("bool".into(), Value::Bool(true));
    m.insert("int".into(), Value::Int(-7));
    m.insert("float".into(), Value::Float(FloatBits(3.5)));
    m.insert("str".into(), Value::Str("héllo".into()));
    m.insert("bytes".into(), Value::Bytes(vec![0, 1, 2, 255]));
    m.insert(
        "list".into(),
        Value::List(vec![Value::Int(1), Value::Str("x".into()), Value::Null]),
    );
    m.insert("blob".into(), Value::Blob(blob()));
    m.insert(
        "tensor".into(),
        Value::Tensor(TensorRef {
            blob: blob(),
            dtype: DType::F32,
            shape: vec![1, 8],
        }),
    );
    m.insert(
        "frame".into(),
        Value::frame(blob(), 123_456, FrameKind::Video),
    );
    m.insert("stream_done".into(), Value::StreamEnd(StreamMarker::Done));
    m.insert(
        "stream_err".into(),
        Value::StreamEnd(StreamMarker::Error {
            message: "boom".into(),
        }),
    );
    Value::Map(m)
}

#[test]
fn value_round_trips_every_variant() {
    let v = composite_value();
    let back = value_from_pb(&value_to_pb(&v));
    assert_eq!(v, back, "structural Value mapping must be lossless");
}

#[test]
fn every_dtype_round_trips() {
    for d in [
        DType::F16,
        DType::Bf16,
        DType::F32,
        DType::F64,
        DType::I8,
        DType::I16,
        DType::I32,
        DType::I64,
        DType::U8,
        DType::Bool,
    ] {
        let v = Value::Tensor(TensorRef {
            blob: blob(),
            dtype: d,
            shape: vec![2],
        });
        assert_eq!(v, value_from_pb(&value_to_pb(&v)), "dtype {d:?}");
    }
}

#[test]
fn every_frame_kind_round_trips() {
    for k in [
        FrameKind::Audio,
        FrameKind::Video,
        FrameKind::Pose,
        FrameKind::Sensor,
    ] {
        let v = Value::frame(blob(), 1, k);
        assert_eq!(v, value_from_pb(&value_to_pb(&v)), "frame kind {k:?}");
    }
}

#[test]
fn empty_pb_value_is_null() {
    let pb = crate::nexus::v1::Value { kind: None };
    assert_eq!(value_from_pb(&pb), Value::Null);
}

#[test]
fn malformed_multimodal_refs_do_not_synthesize_empty_blob() {
    use crate::nexus::v1 as pb;
    let tensor = pb::Value {
        kind: Some(pb::value::Kind::TensorVal(pb::TensorRef {
            blob: None,
            dtype: "f32".into(),
            shape: vec![1],
        })),
    };
    let frame = pb::Value {
        kind: Some(pb::value::Kind::FrameVal(pb::FrameRef {
            blob: None,
            ts_nanos: 1,
            kind: "video".into(),
        })),
    };
    assert_eq!(value_from_pb(&tensor), Value::Null);
    assert_eq!(value_from_pb(&frame), Value::Null);
}

#[test]
fn malformed_multimodal_enums_do_not_default_to_valid_variants() {
    use crate::nexus::v1 as pb;
    let tensor = pb::Value {
        kind: Some(pb::value::Kind::TensorVal(pb::TensorRef {
            blob: Some(pb_blob()),
            dtype: "complex64".into(),
            shape: vec![1],
        })),
    };
    let frame = pb::Value {
        kind: Some(pb::value::Kind::FrameVal(pb::FrameRef {
            blob: Some(pb_blob()),
            ts_nanos: 1,
            kind: "depth".into(),
        })),
    };
    assert_eq!(value_from_pb(&tensor), Value::Null);
    assert_eq!(value_from_pb(&frame), Value::Null);
}

#[test]
fn malformed_stream_markers_do_not_default_to_done() {
    use crate::nexus::v1 as pb;
    let missing_kind = pb::Value {
        kind: Some(pb::value::Kind::StreamEndVal(pb::StreamMarker {
            kind: None,
        })),
    };
    let false_done = pb::Value {
        kind: Some(pb::value::Kind::StreamEndVal(pb::StreamMarker {
            kind: Some(pb::stream_marker::Kind::Done(false)),
        })),
    };
    assert_eq!(value_from_pb(&missing_kind), Value::Null);
    assert_eq!(value_from_pb(&false_done), Value::Null);
}

#[test]
fn checked_value_rejects_malformed_multimodal_refs() {
    use crate::nexus::v1 as pb;
    let null_bad_enum = pb::Value {
        kind: Some(pb::value::Kind::NullVal(99)),
    };
    let tensor_missing_blob = pb::Value {
        kind: Some(pb::value::Kind::TensorVal(pb::TensorRef {
            blob: None,
            dtype: "f32".into(),
            shape: vec![1],
        })),
    };
    let tensor_bad_dtype = pb::Value {
        kind: Some(pb::value::Kind::TensorVal(pb::TensorRef {
            blob: Some(pb_blob()),
            dtype: "complex64".into(),
            shape: vec![1],
        })),
    };
    let frame_bad_kind = pb::Value {
        kind: Some(pb::value::Kind::FrameVal(pb::FrameRef {
            blob: Some(pb_blob()),
            ts_nanos: 1,
            kind: "depth".into(),
        })),
    };
    let stream_marker_missing_kind = pb::Value {
        kind: Some(pb::value::Kind::StreamEndVal(pb::StreamMarker {
            kind: None,
        })),
    };
    let stream_marker_false_done = pb::Value {
        kind: Some(pb::value::Kind::StreamEndVal(pb::StreamMarker {
            kind: Some(pb::stream_marker::Kind::Done(false)),
        })),
    };

    assert!(value_from_pb_checked(&null_bad_enum).is_err());
    assert!(value_from_pb_checked(&tensor_missing_blob).is_err());
    assert!(value_from_pb_checked(&tensor_bad_dtype).is_err());
    assert!(value_from_pb_checked(&frame_bad_kind).is_err());
    assert!(value_from_pb_checked(&stream_marker_missing_kind).is_err());
    assert!(value_from_pb_checked(&stream_marker_false_done).is_err());
}

#[test]
fn external_value_frames_reject_malformed_multimodal_refs() -> anyhow::Result<()> {
    use crate::nexus::v1 as pb;
    use crate::nexus::v1::external as ext;

    fn malformed_tensor() -> pb::Value {
        pb::Value {
            kind: Some(pb::value::Kind::TensorVal(pb::TensorRef {
                blob: Some(pb_blob()),
                dtype: "complex64".into(),
                shape: vec![1],
            })),
        }
    }

    ensure!(
        role_session_client_hello_from_pb(&ext::RoleSessionClientHello {
            role: ext::ExternalRole::Source as i32,
            installation_id: "install-1".into(),
            projection_id: "source".into(),
            registry_hash: "registry".into(),
            observed: Some(ext::ObservedGenerations::default()),
            config_schema: Some(malformed_tensor()),
        })
        .is_err(),
        "malformed config schema should be rejected"
    );

    ensure!(
        inbound_event_from_pb(&ext::InboundEvent {
            id: "event-1".into(),
            payload: Some(malformed_tensor()),
            timestamp_ms: 1,
            observed: Some(ext::ObservedGenerations::default()),
            stream_id: None,
            seq: None,
        })
        .is_err(),
        "malformed inbound event should be rejected"
    );

    ensure!(
        invoke_from_pb(&ext::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: Some(pb_path("effect://external-provider/acme/search")?),
            input: Some(malformed_tensor()),
            deadline_ms: None,
            output_stream_to: None,
            method_id: Some(7),
        })
        .is_err(),
        "malformed invoke input should be rejected"
    );

    ensure!(
        invoke_result_from_pb(&ext::InvokeResult {
            invocation_id: "invoke-1".into(),
            outcome: Some(ext::invoke_result::Outcome::Success(malformed_tensor())),
        })
        .is_err(),
        "malformed invoke result should be rejected"
    );

    ensure!(
        outbound_command_from_pb(&ext::OutboundCommand {
            id: "cmd-1".into(),
            action: Some(malformed_tensor()),
            observed: Some(ext::ObservedGenerations::default()),
        })
        .is_err(),
        "malformed outbound command should be rejected"
    );

    ensure!(
        command_result_from_pb(&ext::CommandResult {
            id: "cmd-1".into(),
            outcome: Some(ext::command_result::Outcome::Success(malformed_tensor())),
        })
        .is_err(),
        "malformed command result should be rejected"
    );

    ensure!(
        control_frame_from_pb(&ext::ControlFrame {
            kind: Some(ext::control_frame::Kind::PresentationProfileUpdate(
                ext::PresentationProfileUpdate {
                    profile_generation: 1,
                    profile_hash: "profile".into(),
                    profile: Some(malformed_tensor()),
                },
            )),
        })
        .is_err(),
        "malformed presentation profile should be rejected"
    );

    ensure!(
        control_frame_from_pb(&ext::ControlFrame {
            kind: Some(ext::control_frame::Kind::InstallationConfigUpdate(
                ext::InstallationConfigUpdate {
                    config_version: 1,
                    config: Some(malformed_tensor()),
                },
            )),
        })
        .is_err(),
        "malformed installation config should be rejected"
    );

    ensure!(
        control_frame_from_pb(&ext::ControlFrame {
            kind: Some(ext::control_frame::Kind::PresentationConfigUpdate(
                ext::PresentationConfigUpdate {
                    generation: 1,
                    profile_hash: "profile".into(),
                    config: Some(malformed_tensor()),
                },
            )),
        })
        .is_err(),
        "malformed presentation config should be rejected"
    );
    Ok(())
}

#[test]
fn external_value_frames_require_explicit_value_fields() -> anyhow::Result<()> {
    use crate::nexus::v1::external as ext;

    ensure!(
        inbound_event_from_pb(&ext::InboundEvent {
            id: "event-1".into(),
            payload: None,
            timestamp_ms: 1,
            observed: Some(ext::ObservedGenerations::default()),
            stream_id: None,
            seq: None,
        })
        .is_err(),
        "missing inbound payload should be rejected"
    );

    ensure!(
        invoke_from_pb(&ext::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: Some(pb_path("effect://external-provider/acme/search")?),
            input: None,
            deadline_ms: None,
            output_stream_to: None,
            method_id: Some(7),
        })
        .is_err(),
        "missing invoke input should be rejected"
    );

    ensure!(
        invoke_result_from_pb(&ext::InvokeResult {
            invocation_id: "invoke-1".into(),
            outcome: None,
        })
        .is_err(),
        "missing invoke result outcome should be rejected"
    );

    ensure!(
        outbound_command_from_pb(&ext::OutboundCommand {
            id: "cmd-1".into(),
            action: None,
            observed: Some(ext::ObservedGenerations::default()),
        })
        .is_err(),
        "missing outbound action should be rejected"
    );

    ensure!(
        command_result_from_pb(&ext::CommandResult {
            id: "cmd-1".into(),
            outcome: None,
        })
        .is_err(),
        "missing command result outcome should be rejected"
    );

    ensure!(
        control_frame_from_pb(&ext::ControlFrame {
            kind: Some(ext::control_frame::Kind::PresentationProfileUpdate(
                ext::PresentationProfileUpdate {
                    profile_generation: 1,
                    profile_hash: "profile".into(),
                    profile: None,
                },
            )),
        })
        .is_err(),
        "missing presentation profile should be rejected"
    );
    Ok(())
}

#[test]
fn program_from_pb_rejects_malformed_literal_value() {
    use crate::nexus::v1 as pb;
    let program = pb::Program {
        root: Some(pb::DoNode {
            kind: Some(pb::do_node::Kind::Pure(pb::Value {
                kind: Some(pb::value::Kind::TensorVal(pb::TensorRef {
                    blob: Some(pb_blob()),
                    dtype: "complex64".into(),
                    shape: vec![1],
                })),
            })),
        }),
        provenance: None,
    };

    assert!(program_from_pb(&program).is_err());
}

#[test]
fn path_round_trips_with_cluster() -> anyhow::Result<()> {
    let path = p("path://pc-home/effect/inference/infer")?;
    let back = path_from_pb(&path_to_pb(&path))?;
    ensure!(
        path.scheme() == back.scheme(),
        "scheme changed: {} != {}",
        path.scheme(),
        back.scheme()
    );
    ensure!(
        path.segments() == back.segments(),
        "segments changed: {:?} != {:?}",
        path.segments(),
        back.segments()
    );
    ensure!(
        path.cluster() == back.cluster(),
        "cluster changed: {:?} != {:?}",
        path.cluster(),
        back.cluster()
    );
    Ok(())
}

#[test]
fn path_params_are_not_wire_api() {
    assert!(Path::parse("effect://inference/infer@model=fast").is_err());
}

#[test]
fn capability_round_trips() -> anyhow::Result<()> {
    let c = Capability {
        verb: "read".into(),
        scheme: "state".into(),
        segments: vec!["kernel".into(), "config".into()],
        predicate: Predicate::parse("size<100").ok(),
    };
    let back = capability_from_pb(&capability_to_pb(&c))?;
    ensure!(c.verb == back.verb, "verb changed: {}", back.verb);
    ensure!(c.scheme == back.scheme, "scheme changed: {}", back.scheme);
    ensure!(
        c.segments == back.segments,
        "segments changed: {:?}",
        back.segments
    );
    ensure!(
        c.predicate.map(|p| p.to_string()) == back.predicate.map(|p| p.to_string()),
        "predicate changed"
    );
    Ok(())
}

#[test]
fn program_round_trips_structurally() -> anyhow::Result<()> {
    let op = op_template(
        "effect://x/post",
        OutputMode::Collect { limit: 8 },
        Some(Value::Str("hello".into())),
    )?;
    let program = DoNode::Both(
        Box::new(DoNode::Pure(Value::Int(1))),
        Box::new(DoNode::Op(op)),
    );
    let back = program_from_pb(&program_to_pb(&program))?;
    ensure!(program == back, "program changed: {back:?}");
    Ok(())
}

#[test]
fn program_explicit_unspecified_output_mode_fails_closed() -> anyhow::Result<()> {
    let mut program = program_to_pb(&DoNode::Op(op_template(
        "effect://x/post",
        OutputMode::Unary,
        None,
    )?));
    let root = program.root.as_mut().context("missing program root")?;
    let crate::nexus::v1::do_node::Kind::Op(op) =
        root.kind.as_mut().context("missing root kind")?
    else {
        bail!("expected op node");
    };
    op.output = Some(crate::nexus::v1::OutputMode {
        kind: crate::nexus::v1::OutputModeKind::Unspecified as i32,
        collect_limit: 0,
    });

    ensure!(
        program_from_pb(&program).is_err(),
        "unspecified output mode should fail closed"
    );
    Ok(())
}

#[test]
fn program_missing_output_mode_fails_closed() -> anyhow::Result<()> {
    let mut program = program_to_pb(&DoNode::Op(op_template(
        "effect://x/post",
        OutputMode::Unary,
        None,
    )?));
    let root = program.root.as_mut().context("missing program root")?;
    let crate::nexus::v1::do_node::Kind::Op(op) =
        root.kind.as_mut().context("missing root kind")?
    else {
        bail!("expected op node");
    };
    op.output = None;

    ensure!(
        program_from_pb(&program).is_err(),
        "missing output mode should fail closed"
    );
    Ok(())
}

#[test]
fn program_blank_operation_method_fails_closed() -> anyhow::Result<()> {
    let mut program = program_to_pb(&DoNode::Op(op_template(
        "effect://x/post",
        OutputMode::Unary,
        None,
    )?));
    let root = program.root.as_mut().context("missing program root")?;
    let crate::nexus::v1::do_node::Kind::Op(op) =
        root.kind.as_mut().context("missing root kind")?
    else {
        bail!("expected op node");
    };
    op.method = "  ".into();

    ensure!(
        program_from_pb(&program).is_err(),
        "blank operation method should fail closed"
    );

    let mut padded = program_to_pb(&DoNode::Op(op_template(
        "effect://x/post",
        OutputMode::Unary,
        None,
    )?));
    let root = padded.root.as_mut().context("missing program root")?;
    let crate::nexus::v1::do_node::Kind::Op(op) =
        root.kind.as_mut().context("missing root kind")?
    else {
        bail!("expected op node");
    };
    op.method = " invoke ".into();
    ensure!(
        program_from_pb(&padded).is_err(),
        "padded operation method should fail closed"
    );
    Ok(())
}

#[test]
fn program_blank_step_and_binding_names_fail_closed() -> anyhow::Result<()> {
    let blank_step = DoNode::pure(Value::Null).and_then(StepRef::new(ProcessId::new(1), " "));
    ensure!(
        program_from_pb(&program_to_pb(&blank_step)).is_err(),
        "blank step name should fail closed"
    );

    let blank_let = DoNode::Let {
        name: String::new(),
        value: Box::new(DoNode::pure(Value::Int(1))),
        body: Box::new(DoNode::Use("x".into())),
    };
    ensure!(
        program_from_pb(&program_to_pb(&blank_let)).is_err(),
        "blank let binding name should fail closed"
    );

    let blank_use = DoNode::Use("  ".into());
    ensure!(
        program_from_pb(&program_to_pb(&blank_use)).is_err(),
        "blank use name should fail closed"
    );
    Ok(())
}

#[test]
fn program_blank_failure_kind_fails_closed() -> anyhow::Result<()> {
    let mut program = program_to_pb(&DoNode::Fail(Failure::Timeout));
    let root = program.root.as_mut().context("missing program root")?;
    let crate::nexus::v1::do_node::Kind::Fail(failure) =
        root.kind.as_mut().context("missing root kind")?
    else {
        bail!("expected fail node");
    };
    failure.kind = String::new();

    ensure!(
        program_from_pb(&program).is_err(),
        "blank failure kind should fail closed"
    );
    Ok(())
}

#[test]
fn program_missing_root_fails_closed() {
    let program = crate::nexus::v1::Program {
        root: None,
        provenance: None,
    };
    assert!(program_from_pb(&program).is_err());
}

#[test]
fn outcome_done_and_fail_map() -> anyhow::Result<()> {
    let done = Outcome::Done(Value::Int(5));
    let pb = outcome_to_pb(&done);
    ensure!(
        matches!(pb.result, Some(crate::nexus::v1::outcome::Result::Done(_))),
        "done outcome encoded incorrectly"
    );

    let fail = Outcome::Fail(Failure::Timeout);
    let pb = outcome_to_pb(&fail);
    match pb.result {
        Some(crate::nexus::v1::outcome::Result::Fail(f)) => {
            ensure!(f.kind == "timeout", "unexpected failure kind: {}", f.kind);
        }
        other => bail!("expected fail, got {other:?}"),
    }
    Ok(())
}

#[test]
fn value_survives_protobuf_encode_decode() -> anyhow::Result<()> {
    use prost::Message;
    let pb = value_to_pb(&composite_value());
    let bytes = pb.encode_to_vec();
    let decoded = crate::nexus::v1::Value::decode(&bytes[..])?;
    ensure!(pb == decoded, "protobuf value changed: {decoded:?}");
    let value = value_from_pb(&decoded);
    ensure!(
        value == composite_value(),
        "decoded value changed: {value:?}"
    );
    Ok(())
}

#[test]
fn external_handshake_frames_survive_wire() -> anyhow::Result<()> {
    use crate::nexus::v1::external as ext;
    use prost::Message;
    let hello = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::RoleSessionClientHello(
            ext::RoleSessionClientHello {
                role: ext::ExternalRole::Source as i32,
                installation_id: "install-1".into(),
                projection_id: "source".into(),
                registry_hash: "abc".into(),
                observed: Some(ext::ObservedGenerations {
                    presentation_config_generation: 1,
                    alias_catalog_generation: 2,
                }),
                config_schema: Some(value_to_pb(&Value::Null)),
            },
        )),
    };
    let bytes = hello.encode_to_vec();
    let back = ext::ExternalFrame::decode(&bytes[..])?;
    ensure!(hello == back, "hello frame changed: {back:?}");

    let context = ext::SessionContext {
        installation_id: "install-1".into(),
        projection_id: "source".into(),
        role: ext::ExternalRole::Source as i32,
        registry_hash: "abc".into(),
        credential_generation: 3,
        binding_generation: 4,
        installation_config_version: 5,
        projection_version: 6,
        presentation_config_generation: 7,
        alias_catalog_generation: 8,
        session_id: "session-1".into(),
    };
    let ready = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::RoleReady(ext::RoleReady {
            accepted_context: Some(context),
        })),
    };
    let bytes = ready.encode_to_vec();
    let back = ext::ExternalFrame::decode(&bytes[..])?;
    ensure!(ready == back, "ready frame changed: {back:?}");
    Ok(())
}

#[test]
fn external_session_typed_frames_roundtrip() -> anyhow::Result<()> {
    use crate::convert::{
        event_ack_from_pb, event_ack_to_pb, inbound_event_from_pb, inbound_event_to_pb,
        role_ready_from_pb, role_ready_to_pb, role_session_client_hello_from_pb,
        role_session_client_hello_to_pb, session_context_from_pb, session_context_to_pb,
    };
    use nexus_types::Value;
    use nexus_types::external::{
        AckStatus, EventAck, InboundEvent, ObservedGenerations, Role, RoleReady,
        RoleSessionClientHello, SessionContext,
    };

    let observed = ObservedGenerations {
        presentation_config_generation: 11,
        alias_catalog_generation: 12,
    };
    let hello = RoleSessionClientHello {
        role: Role::Source,
        installation_id: "install-1".into(),
        projection_id: "source".into(),
        registry_hash: "registry-abc".into(),
        observed,
        config_schema: Some(Value::Map(Default::default())),
    };
    let back = role_session_client_hello_from_pb(&role_session_client_hello_to_pb(&hello))?;
    ensure!(back == hello, "hello changed: {back:?}");

    let context = SessionContext {
        installation_id: "install-1".into(),
        projection_id: "source".into(),
        role: Role::Source,
        registry_hash: "registry-abc".into(),
        credential_generation: 1,
        binding_generation: 2,
        installation_config_version: 3,
        projection_version: 4,
        presentation_config_generation: 5,
        alias_catalog_generation: 6,
        session_id: "session-1".into(),
    };
    let back = session_context_from_pb(&session_context_to_pb(&context))?;
    ensure!(back == context, "context changed: {back:?}");

    let ready = RoleReady {
        accepted_context: context,
    };
    let back = role_ready_from_pb(&role_ready_to_pb(&ready))?;
    ensure!(back == ready, "ready changed: {back:?}");

    let event = InboundEvent {
        id: "event-1".into(),
        payload: Value::Str("hello".into()),
        observed,
        timestamp_ms: 1234,
        stream_id: Some("stream-1".into()),
        seq: Some(7),
    };
    let back = inbound_event_from_pb(&inbound_event_to_pb(&event))?;
    ensure!(back == event, "event changed: {back:?}");

    let ack = EventAck {
        id: "event-1".into(),
        status: AckStatus::Rejected,
        reject_reason: Some("schema".into()),
    };
    let back = event_ack_from_pb(&event_ack_to_pb(&ack))?;
    ensure!(back == ack, "ack changed: {back:?}");
    Ok(())
}

#[test]
fn external_secure_envelope_survives_wire() -> anyhow::Result<()> {
    use crate::nexus::v1::external as ext;
    use prost::Message;
    let frame = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::SecureEnvelope(
            ext::SecureEnvelope {
                installation_id: "install-1".into(),
                generation: 7,
                aad: Some(ext::EnvelopeAad {
                    version: 1,
                    projection_id: "provider".into(),
                    role: "provider".into(),
                    session_id: "session-1".into(),
                    seq: 42,
                    frame_type: "invoke_result".into(),
                    binding_generation: 8,
                    credential_generation: 7,
                    transcript_hash: vec![0x42; 32],
                    key_epoch: 2,
                }),
                nonce_prefix: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
                ciphertext: vec![0xaa, 0xbb, 0xcc],
            },
        )),
    };
    let bytes = frame.encode_to_vec();
    let back = ext::ExternalFrame::decode(&bytes[..])?;
    ensure!(frame == back, "secure envelope changed: {back:?}");
    Ok(())
}

#[test]
fn control_frame_config_ack_survives_wire() -> anyhow::Result<()> {
    use crate::nexus::v1::external as ext;
    use prost::Message;
    let frame = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::Control(ext::ControlFrame {
            kind: Some(ext::control_frame::Kind::ConfigAck(ext::ConfigAck {
                axis: ext::ConfigAxis::InstallationConfig as i32,
                version: 42,
                status: ext::ApplyStatus::Rejected as i32,
                reject_reason: Some(ext::RejectReason::GenerationStale as i32),
            })),
        })),
    };
    let bytes = frame.encode_to_vec();
    let back = ext::ExternalFrame::decode(&bytes[..])?;
    ensure!(frame == back, "config ack frame changed: {back:?}");
    match back.frame {
        Some(ext::external_frame::Frame::Control(c)) => {
            ensure!(
                matches!(c.kind, Some(ext::control_frame::Kind::ConfigAck(_))),
                "config ack payload missing"
            );
        }
        other => bail!("expected Control/ConfigAck, got {other:?}"),
    }
    Ok(())
}

#[test]
fn external_control_frames_roundtrip_through_pb() -> anyhow::Result<()> {
    use crate::convert::{control_frame_from_pb, control_frame_to_pb};
    use nexus_types::Value;
    use nexus_types::external::{ApplyStatus, ConfigAxis, ControlFrame, FlowSignal, RejectReason};

    let frames = vec![
        ControlFrame::Heartbeat { timestamp_ms: 10 },
        ControlFrame::Shutdown {
            graceful: true,
            timeout_ms: 500,
        },
        ControlFrame::FlowControl(FlowSignal::Pause),
        ControlFrame::FlowControl(FlowSignal::Resume),
        ControlFrame::ProviderCancel {
            invocation_id: "invoke-1".into(),
            reason: "deadline_exceeded".into(),
        },
        ControlFrame::PresentationProfileUpdate {
            profile_generation: 2,
            profile_hash: "profile-hash".into(),
            profile: Value::Map(Default::default()),
        },
        ControlFrame::InstallationConfigUpdate {
            config_version: 3,
            config: Value::Str("cfg".into()),
        },
        ControlFrame::PresentationConfigUpdate {
            generation: 4,
            profile_hash: "profile-hash".into(),
            config: Value::Bool(true),
        },
        ControlFrame::ConfigAck {
            axis: ConfigAxis::InstallationConfig,
            version: 5,
            status: ApplyStatus::Applied,
        },
        ControlFrame::ConfigAck {
            axis: ConfigAxis::PresentationConfig,
            version: 6,
            status: ApplyStatus::Rejected {
                reason: RejectReason::GenerationStale,
            },
        },
    ];

    for frame in frames {
        let back = control_frame_from_pb(&control_frame_to_pb(&frame))?;
        ensure!(back == frame, "control frame changed: {back:?}");
    }
    Ok(())
}

#[test]
fn service_names_and_method_paths_are_correct() {
    assert_eq!(
        crate::nexus::v1::external::external_service_server::SERVICE_NAME,
        "nexus.v1.external.ExternalService"
    );
}

#[test]
fn invoke_frame_types_roundtrip_through_pb() -> anyhow::Result<()> {
    use crate::convert::{invoke_from_pb, invoke_to_pb};
    use nexus_types::external::Invoke;
    use nexus_types::{MethodId, Value};
    let inv = Invoke {
        invocation_id: "inv-1".into(),
        effect_path: p("effect://x/post")?,
        method_id: MethodId::new(7),
        input: Value::Str("hello".into()),
        deadline_ms: Some(5000),
        output_stream_to: Some(p("state://chat/out")?),
    };
    let back = invoke_from_pb(&invoke_to_pb(&inv))?;
    ensure!(
        back.invocation_id == inv.invocation_id,
        "invocation id changed"
    );
    ensure!(back.effect_path == inv.effect_path, "effect path changed");
    ensure!(back.method_id == inv.method_id, "method id changed");
    ensure!(back.input == inv.input, "input changed");
    ensure!(back.deadline_ms == inv.deadline_ms, "deadline changed");
    ensure!(
        back.output_stream_to == inv.output_stream_to,
        "output stream target changed"
    );
    Ok(())
}

#[test]
fn malformed_wire_paths_and_capabilities_fail_closed() -> anyhow::Result<()> {
    use crate::convert::{
        capability_from_pb, control_frame_from_pb, event_ack_from_pb, inbound_event_from_pb,
        invoke_from_pb, outbound_command_from_pb, path_from_pb, role_ready_from_pb,
        role_session_client_hello_from_pb, session_context_from_pb,
    };
    use crate::nexus::v1 as pb;
    use crate::nexus::v1::external as ext;

    let bad_path = pb::Path {
        scheme: "effect".into(),
        segments: vec!["bad space".into()],
        cluster: None,
    };
    ensure!(path_from_pb(&bad_path).is_err(), "bad path should fail");
    let injected_path_segment = pb::Path {
        scheme: "effect".into(),
        segments: vec!["x/post".into()],
        cluster: None,
    };
    ensure!(
        path_from_pb(&injected_path_segment).is_err(),
        "path segment containing delimiter should fail"
    );
    let injected_path_cluster = pb::Path {
        scheme: "effect".into(),
        segments: vec!["post".into()],
        cluster: Some("bad/cluster".into()),
    };
    ensure!(
        path_from_pb(&injected_path_cluster).is_err(),
        "path cluster containing delimiter should fail"
    );

    let bad_capability = pb::Capability {
        verb: "effect".into(),
        scheme: "x".into(),
        segments: vec!["post".into()],
        predicate: None,
    };
    ensure!(
        capability_from_pb(&bad_capability).is_err(),
        "bad capability should fail"
    );
    let injected_capability_segment = pb::Capability {
        verb: "perform".into(),
        scheme: "effect".into(),
        segments: vec!["x/post".into()],
        predicate: None,
    };
    ensure!(
        capability_from_pb(&injected_capability_segment).is_err(),
        "capability segment containing delimiter should fail"
    );
    let injected_capability_scheme = pb::Capability {
        verb: "perform".into(),
        scheme: "effect/post".into(),
        segments: vec!["x".into()],
        predicate: None,
    };
    ensure!(
        capability_from_pb(&injected_capability_scheme).is_err(),
        "capability scheme containing delimiter should fail"
    );

    let missing_effect_path = ext::Invoke {
        invocation_id: "inv-1".into(),
        effect_path: None,
        input: Some(crate::convert::value_to_pb(&Value::Null)),
        deadline_ms: None,
        output_stream_to: None,
        method_id: Some(0),
    };
    ensure!(
        invoke_from_pb(&missing_effect_path).is_err(),
        "missing effect path should fail"
    );

    let missing_method = ext::Invoke {
        invocation_id: "inv-1".into(),
        effect_path: Some(pb_path("effect://x/post")?),
        input: Some(crate::convert::value_to_pb(&Value::Null)),
        deadline_ms: None,
        output_stream_to: None,
        method_id: None,
    };
    ensure!(
        invoke_from_pb(&missing_method).is_err(),
        "missing method should fail"
    );

    let bad_context = ext::SessionContext {
        role: ext::ExternalRole::Unspecified as i32,
        ..Default::default()
    };
    ensure!(
        session_context_from_pb(&bad_context).is_err(),
        "bad context should fail"
    );

    let missing_context = ext::RoleReady {
        accepted_context: None,
    };
    ensure!(
        role_ready_from_pb(&missing_context).is_err(),
        "missing context should fail"
    );

    let missing_hello_observed = ext::RoleSessionClientHello {
        role: ext::ExternalRole::Source as i32,
        installation_id: "install-1".into(),
        projection_id: "source".into(),
        registry_hash: "registry-abc".into(),
        observed: None,
        config_schema: None,
    };
    ensure!(
        role_session_client_hello_from_pb(&missing_hello_observed).is_err(),
        "missing hello observed generations should fail"
    );

    let missing_event_observed = ext::InboundEvent {
        id: "event-1".into(),
        payload: Some(crate::convert::value_to_pb(&Value::Null)),
        timestamp_ms: 1,
        observed: None,
        stream_id: None,
        seq: None,
    };
    ensure!(
        inbound_event_from_pb(&missing_event_observed).is_err(),
        "missing event observed generations should fail"
    );

    let missing_command_observed = ext::OutboundCommand {
        id: "cmd-1".into(),
        action: Some(crate::convert::value_to_pb(&Value::Null)),
        observed: None,
    };
    ensure!(
        outbound_command_from_pb(&missing_command_observed).is_err(),
        "missing command observed generations should fail"
    );

    let bad_ack = ext::EventAck {
        id: "event-1".into(),
        status: ext::AckStatus::Unspecified as i32,
        reject_reason: None,
    };
    ensure!(event_ack_from_pb(&bad_ack).is_err(), "bad ack should fail");

    ensure!(
        control_frame_from_pb(&ext::ControlFrame { kind: None }).is_err(),
        "missing control frame kind should fail"
    );
    let bad_flow = ext::ControlFrame {
        kind: Some(ext::control_frame::Kind::FlowControl(ext::FlowControl {
            signal: ext::FlowSignal::Unspecified as i32,
        })),
    };
    ensure!(
        control_frame_from_pb(&bad_flow).is_err(),
        "bad flow signal should fail"
    );

    let rejected_without_reason = ext::ControlFrame {
        kind: Some(ext::control_frame::Kind::ConfigAck(ext::ConfigAck {
            axis: ext::ConfigAxis::InstallationConfig as i32,
            version: 1,
            status: ext::ApplyStatus::Rejected as i32,
            reject_reason: None,
        })),
    };
    ensure!(
        control_frame_from_pb(&rejected_without_reason).is_err(),
        "rejected ack without reason should fail"
    );
    Ok(())
}

#[test]
fn invoke_result_ok_and_err_roundtrip() -> anyhow::Result<()> {
    use crate::convert::{invoke_result_from_pb, invoke_result_to_pb};
    use crate::nexus::v1::external as ext;
    use nexus_types::Value;
    use nexus_types::external::{ErrorInfo, InvokeResult};
    let ok = InvokeResult {
        invocation_id: "r1".into(),
        outcome: Ok(Value::Int(42)),
    };
    let back = invoke_result_from_pb(&invoke_result_to_pb(&ok))?;
    ensure!(back.invocation_id == "r1", "unexpected invocation id");
    ensure!(
        back.outcome == Ok(Value::Int(42)),
        "unexpected ok outcome: {:?}",
        back.outcome
    );

    let err = InvokeResult {
        invocation_id: "r2".into(),
        outcome: Err(ErrorInfo {
            kind: "rate_limit".into(),
            message: "429".into(),
        }),
    };
    let back = invoke_result_from_pb(&invoke_result_to_pb(&err))?;
    match back.outcome {
        Err(e) => {
            ensure!(e.kind == "rate_limit", "unexpected error kind: {}", e.kind);
            ensure!(
                e.message == "429",
                "unexpected error message: {}",
                e.message
            );
        }
        Ok(value) => bail!("expected error outcome, got {value:?}"),
    }
    let missing_code = ext::InvokeResult {
        invocation_id: "r3".into(),
        outcome: Some(ext::invoke_result::Outcome::Error(ext::ErrorInfo {
            code: "  ".into(),
            message: "missing stable class".into(),
            details: Default::default(),
        })),
    };
    ensure!(
        invoke_result_from_pb(&missing_code).is_err(),
        "invoke error without code should fail"
    );
    let padded_code = ext::InvokeResult {
        invocation_id: "r4".into(),
        outcome: Some(ext::invoke_result::Outcome::Error(ext::ErrorInfo {
            code: " remote ".into(),
            message: "padded stable class".into(),
            details: Default::default(),
        })),
    };
    ensure!(
        invoke_result_from_pb(&padded_code).is_err(),
        "invoke error with padded code should fail"
    );
    Ok(())
}

#[test]
fn source_command_frames_roundtrip() -> anyhow::Result<()> {
    use crate::convert::{
        command_result_from_pb, command_result_to_pb, outbound_command_from_pb,
        outbound_command_to_pb,
    };
    use crate::nexus::v1::external as ext;
    use nexus_types::Value;
    use nexus_types::external::{CommandResult, ErrorInfo, ObservedGenerations, OutboundCommand};

    let command = OutboundCommand {
        id: "cmd-1".into(),
        action: Value::Str("send".into()),
        observed: ObservedGenerations {
            presentation_config_generation: 4,
            alias_catalog_generation: 2,
        },
    };
    let back = outbound_command_from_pb(&outbound_command_to_pb(&command))?;
    ensure!(back == command, "command changed: {back:?}");

    let ok = CommandResult {
        id: "cmd-1".into(),
        outcome: Ok(Value::Bool(true)),
    };
    let back = command_result_from_pb(&command_result_to_pb(&ok))?;
    ensure!(back == ok, "ok result changed: {back:?}");

    let err = CommandResult {
        id: "cmd-2".into(),
        outcome: Err(ErrorInfo {
            kind: "bridge_error".into(),
            message: "failed".into(),
        }),
    };
    let back = command_result_from_pb(&command_result_to_pb(&err))?;
    ensure!(back == err, "error result changed: {back:?}");
    let missing_code = ext::CommandResult {
        id: "cmd-3".into(),
        outcome: Some(ext::command_result::Outcome::Error(ext::ErrorInfo {
            code: String::new(),
            message: "missing stable class".into(),
            details: Default::default(),
        })),
    };
    ensure!(
        command_result_from_pb(&missing_code).is_err(),
        "command error without code should fail"
    );
    let padded_code = ext::CommandResult {
        id: "cmd-4".into(),
        outcome: Some(ext::command_result::Outcome::Error(ext::ErrorInfo {
            code: " remote ".into(),
            message: "padded stable class".into(),
            details: Default::default(),
        })),
    };
    ensure!(
        command_result_from_pb(&padded_code).is_err(),
        "command error with padded code should fail"
    );
    Ok(())
}
