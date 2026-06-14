//! Round-trip tests for the wire conversions. Every `Value` variant and the
//! Path / Capability / Outcome mappings must survive a `to_pb`/`from_pb` cycle.

use crate::convert::*;
use nexus_graph::{DoNode, OperationTemplate};
use nexus_types::{
    BlobRef, Capability, DType, Failure, FloatBits, FrameKind, Outcome, OutputMode, Path,
    Predicate, ResourceName, StreamMarker, TensorRef, Value,
};
use std::collections::BTreeMap;

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
fn external_value_frames_reject_malformed_multimodal_refs() {
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

    assert!(
        role_session_client_hello_from_pb(&ext::RoleSessionClientHello {
            role: ext::ExternalRole::Source as i32,
            installation_id: "install-1".into(),
            projection_id: "source".into(),
            registry_hash: "registry".into(),
            observed: Some(ext::ObservedGenerations::default()),
            config_schema: Some(malformed_tensor()),
        })
        .is_err()
    );

    assert!(
        inbound_event_from_pb(&ext::InboundEvent {
            id: "event-1".into(),
            payload: Some(malformed_tensor()),
            timestamp_ms: 1,
            observed: Some(ext::ObservedGenerations::default()),
            stream_id: None,
            seq: None,
        })
        .is_err()
    );

    assert!(
        invoke_from_pb(&ext::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: Some(path_to_pb(
                &Path::parse("effect://external-provider/acme/search").unwrap()
            )),
            input: Some(malformed_tensor()),
            deadline_ms: None,
            output_stream_to: None,
            method_id: Some(7),
        })
        .is_err()
    );

    assert!(
        invoke_result_from_pb(&ext::InvokeResult {
            invocation_id: "invoke-1".into(),
            outcome: Some(ext::invoke_result::Outcome::Success(malformed_tensor())),
        })
        .is_err()
    );

    assert!(
        outbound_command_from_pb(&ext::OutboundCommand {
            id: "cmd-1".into(),
            action: Some(malformed_tensor()),
            observed: Some(ext::ObservedGenerations::default()),
        })
        .is_err()
    );

    assert!(
        command_result_from_pb(&ext::CommandResult {
            id: "cmd-1".into(),
            outcome: Some(ext::command_result::Outcome::Success(malformed_tensor())),
        })
        .is_err()
    );

    assert!(
        control_frame_from_pb(&ext::ControlFrame {
            kind: Some(ext::control_frame::Kind::PresentationProfileUpdate(
                ext::PresentationProfileUpdate {
                    profile_generation: 1,
                    profile_hash: "profile".into(),
                    profile: Some(malformed_tensor()),
                },
            )),
        })
        .is_err()
    );

    assert!(
        control_frame_from_pb(&ext::ControlFrame {
            kind: Some(ext::control_frame::Kind::InstallationConfigUpdate(
                ext::InstallationConfigUpdate {
                    config_version: 1,
                    config: Some(malformed_tensor()),
                },
            )),
        })
        .is_err()
    );

    assert!(
        control_frame_from_pb(&ext::ControlFrame {
            kind: Some(ext::control_frame::Kind::PresentationConfigUpdate(
                ext::PresentationConfigUpdate {
                    generation: 1,
                    profile_hash: "profile".into(),
                    config: Some(malformed_tensor()),
                },
            )),
        })
        .is_err()
    );
}

#[test]
fn external_value_frames_require_explicit_value_fields() {
    use crate::nexus::v1::external as ext;

    assert!(
        inbound_event_from_pb(&ext::InboundEvent {
            id: "event-1".into(),
            payload: None,
            timestamp_ms: 1,
            observed: Some(ext::ObservedGenerations::default()),
            stream_id: None,
            seq: None,
        })
        .is_err()
    );

    assert!(
        invoke_from_pb(&ext::Invoke {
            invocation_id: "invoke-1".into(),
            effect_path: Some(path_to_pb(
                &Path::parse("effect://external-provider/acme/search").unwrap()
            )),
            input: None,
            deadline_ms: None,
            output_stream_to: None,
            method_id: Some(7),
        })
        .is_err()
    );

    assert!(
        invoke_result_from_pb(&ext::InvokeResult {
            invocation_id: "invoke-1".into(),
            outcome: None,
        })
        .is_err()
    );

    assert!(
        outbound_command_from_pb(&ext::OutboundCommand {
            id: "cmd-1".into(),
            action: None,
            observed: Some(ext::ObservedGenerations::default()),
        })
        .is_err()
    );

    assert!(
        command_result_from_pb(&ext::CommandResult {
            id: "cmd-1".into(),
            outcome: None,
        })
        .is_err()
    );

    assert!(
        control_frame_from_pb(&ext::ControlFrame {
            kind: Some(ext::control_frame::Kind::PresentationProfileUpdate(
                ext::PresentationProfileUpdate {
                    profile_generation: 1,
                    profile_hash: "profile".into(),
                    profile: None,
                },
            )),
        })
        .is_err()
    );
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
fn path_round_trips_with_cluster() {
    let p = Path::parse("path://pc-home/effect/inference/infer").unwrap();
    let back = path_from_pb(&path_to_pb(&p)).unwrap();
    assert_eq!(p.scheme(), back.scheme());
    assert_eq!(p.segments(), back.segments());
    assert_eq!(p.cluster(), back.cluster());
}

#[test]
fn path_params_are_not_wire_api() {
    assert!(Path::parse("effect://inference/infer@model=fast").is_err());
}

#[test]
fn capability_round_trips() {
    let c = Capability {
        verb: "read".into(),
        scheme: "state".into(),
        segments: vec!["kernel".into(), "config".into()],
        predicate: Predicate::parse("size<100").ok(),
    };
    let back = capability_from_pb(&capability_to_pb(&c)).unwrap();
    assert_eq!(c.verb, back.verb);
    assert_eq!(c.scheme, back.scheme);
    assert_eq!(c.segments, back.segments);
    assert_eq!(
        c.predicate.map(|p| p.to_string()),
        back.predicate.map(|p| p.to_string())
    );
}

#[test]
fn program_round_trips_structurally() {
    let op = OperationTemplate {
        target: ResourceName::new(Path::parse("effect://x/post").unwrap()),
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Collect { limit: 8 },
        literal_input: Some(Value::Str("hello".into())),
    };
    let program = DoNode::Both(
        Box::new(DoNode::Pure(Value::Int(1))),
        Box::new(DoNode::Op(op)),
    );
    let back = program_from_pb(&program_to_pb(&program)).unwrap();
    assert_eq!(program, back);
}

#[test]
fn program_explicit_unspecified_output_mode_fails_closed() {
    let mut program = program_to_pb(&DoNode::Op(OperationTemplate {
        target: ResourceName::new(Path::parse("effect://x/post").unwrap()),
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    }));
    let root = program.root.as_mut().unwrap();
    let crate::nexus::v1::do_node::Kind::Op(op) = root.kind.as_mut().unwrap() else {
        panic!("expected op node");
    };
    op.output = Some(crate::nexus::v1::OutputMode {
        kind: crate::nexus::v1::OutputModeKind::Unspecified as i32,
        collect_limit: 0,
    });

    assert!(program_from_pb(&program).is_err());
}

#[test]
fn program_missing_output_mode_defaults_to_unary() {
    let mut program = program_to_pb(&DoNode::Op(OperationTemplate {
        target: ResourceName::new(Path::parse("effect://x/post").unwrap()),
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    }));
    let root = program.root.as_mut().unwrap();
    let crate::nexus::v1::do_node::Kind::Op(op) = root.kind.as_mut().unwrap() else {
        panic!("expected op node");
    };
    op.output = None;

    let back = program_from_pb(&program).unwrap();
    let DoNode::Op(op) = back else {
        panic!("expected op node");
    };
    assert_eq!(op.output, OutputMode::Unary);
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
fn outcome_done_and_fail_map() {
    let done = Outcome::Done(Value::Int(5));
    let pb = outcome_to_pb(&done);
    assert!(matches!(
        pb.result,
        Some(crate::nexus::v1::outcome::Result::Done(_))
    ));

    let fail = Outcome::Fail(Failure::Timeout);
    let pb = outcome_to_pb(&fail);
    match pb.result {
        Some(crate::nexus::v1::outcome::Result::Fail(f)) => assert_eq!(f.kind, "timeout"),
        _ => panic!("expected fail"),
    }
}

// Prost wire-encoding round trips.
// These prove the hand-vendored `#[prost(...)]` field tags / oneofs / maps
// encode and decode correctly on the wire (not just that they compile).

#[test]
fn value_survives_protobuf_encode_decode() {
    use prost::Message;
    let pb = value_to_pb(&composite_value());
    let bytes = pb.encode_to_vec();
    let decoded = crate::nexus::v1::Value::decode(&bytes[..]).expect("decode");
    assert_eq!(pb, decoded);
    // …and the structural meaning survives the full wire trip.
    assert_eq!(value_from_pb(&decoded), composite_value());
}

#[test]
fn external_handshake_frames_survive_wire() {
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
    let back = ext::ExternalFrame::decode(&bytes[..]).unwrap();
    assert_eq!(hello, back);

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
    let back = ext::ExternalFrame::decode(&bytes[..]).unwrap();
    assert_eq!(ready, back);
}

#[test]
fn external_session_typed_frames_roundtrip() {
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
    assert_eq!(
        role_session_client_hello_from_pb(&role_session_client_hello_to_pb(&hello)).unwrap(),
        hello
    );

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
    assert_eq!(
        session_context_from_pb(&session_context_to_pb(&context)).unwrap(),
        context
    );

    let ready = RoleReady {
        accepted_context: context,
    };
    assert_eq!(
        role_ready_from_pb(&role_ready_to_pb(&ready)).unwrap(),
        ready
    );

    let event = InboundEvent {
        id: "event-1".into(),
        payload: Value::Str("hello".into()),
        observed,
        timestamp_ms: 1234,
        stream_id: Some("stream-1".into()),
        seq: Some(7),
    };
    assert_eq!(
        inbound_event_from_pb(&inbound_event_to_pb(&event)).unwrap(),
        event
    );

    let ack = EventAck {
        id: "event-1".into(),
        status: AckStatus::Rejected,
        reject_reason: Some("schema".into()),
    };
    assert_eq!(event_ack_from_pb(&event_ack_to_pb(&ack)).unwrap(), ack);
}

#[test]
fn external_secure_envelope_survives_wire() {
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
    let back = ext::ExternalFrame::decode(&bytes[..]).unwrap();
    assert_eq!(frame, back);
}

#[test]
fn control_frame_config_ack_survives_wire() {
    // Regression: ConfigAck is oneof tag 7. The oneof field's `tags`
    // list previously omitted 7, so ConfigAck silently failed to round-trip.
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
    let back = ext::ExternalFrame::decode(&bytes[..]).unwrap();
    assert_eq!(
        frame, back,
        "ConfigAck (tag 7) must round-trip through the wire"
    );
    // And specifically that the ConfigAck payload survived (not dropped to None).
    match back.frame {
        Some(ext::external_frame::Frame::Control(c)) => {
            assert!(matches!(
                c.kind,
                Some(ext::control_frame::Kind::ConfigAck(_))
            ));
        }
        other => panic!("expected Control/ConfigAck, got {other:?}"),
    }
}

#[test]
fn external_control_frames_roundtrip_through_pb() {
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
        assert_eq!(
            control_frame_from_pb(&control_frame_to_pb(&frame)).unwrap(),
            frame
        );
    }
}

#[test]
fn external_provider_ready_roundtrips_through_pb() {
    use crate::convert::{provider_ready_from_pb, provider_ready_to_pb};
    use nexus_types::Purity;
    use nexus_types::external::{EffectHandlerSpec, ProviderReady};

    let ready = ProviderReady {
        provides: vec![
            EffectHandlerSpec {
                path: "effect://external-provider/acme/search".into(),
                purity: Purity::Idempotent,
                description: Some("search".into()),
            },
            EffectHandlerSpec {
                path: "effect://external-provider/acme/send".into(),
                purity: Purity::Effectful,
                description: None,
            },
        ],
    };

    assert_eq!(
        provider_ready_from_pb(&provider_ready_to_pb(&ready)).unwrap(),
        ready
    );
}

#[test]
fn service_names_and_method_paths_are_correct() {
    assert_eq!(
        crate::nexus::v1::external::external_service_server::SERVICE_NAME,
        "nexus.v1.external.ExternalService"
    );
}

#[test]
fn invoke_frame_types_roundtrip_through_pb() {
    // The Invoke business frame maps losslessly between types and proto.
    use crate::convert::{invoke_from_pb, invoke_to_pb};
    use nexus_types::external::Invoke;
    use nexus_types::{MethodId, Path, Value};
    let inv = Invoke {
        invocation_id: "inv-1".into(),
        effect_path: Path::parse("effect://x/post").unwrap(),
        method_id: MethodId::new(7),
        input: Value::Str("hello".into()),
        deadline_ms: Some(5000),
        output_stream_to: Some(Path::parse("state://chat/out").unwrap()),
    };
    let back = invoke_from_pb(&invoke_to_pb(&inv)).unwrap();
    assert_eq!(back.invocation_id, inv.invocation_id);
    assert_eq!(back.effect_path, inv.effect_path);
    assert_eq!(back.method_id, inv.method_id);
    assert_eq!(back.input, inv.input);
    assert_eq!(back.deadline_ms, inv.deadline_ms);
    assert_eq!(back.output_stream_to, inv.output_stream_to);
}

#[test]
fn malformed_wire_paths_and_capabilities_fail_closed() {
    use crate::convert::{
        capability_from_pb, control_frame_from_pb, event_ack_from_pb, invoke_from_pb, path_from_pb,
        role_ready_from_pb, session_context_from_pb,
    };
    use crate::nexus::v1 as pb;
    use crate::nexus::v1::external as ext;

    let bad_path = pb::Path {
        scheme: "effect".into(),
        segments: vec!["bad space".into()],
        cluster: None,
    };
    assert!(path_from_pb(&bad_path).is_err());

    let bad_capability = pb::Capability {
        verb: "effect".into(),
        scheme: "x".into(),
        segments: vec!["post".into()],
        predicate: None,
    };
    assert!(capability_from_pb(&bad_capability).is_err());

    let missing_effect_path = ext::Invoke {
        invocation_id: "inv-1".into(),
        effect_path: None,
        input: Some(crate::convert::value_to_pb(&Value::Null)),
        deadline_ms: None,
        output_stream_to: None,
        method_id: Some(0),
    };
    assert!(invoke_from_pb(&missing_effect_path).is_err());

    let missing_method = ext::Invoke {
        invocation_id: "inv-1".into(),
        effect_path: Some(crate::convert::path_to_pb(
            &Path::parse("effect://x/post").unwrap(),
        )),
        input: Some(crate::convert::value_to_pb(&Value::Null)),
        deadline_ms: None,
        output_stream_to: None,
        method_id: None,
    };
    assert!(invoke_from_pb(&missing_method).is_err());

    let bad_context = ext::SessionContext {
        role: ext::ExternalRole::Unspecified as i32,
        ..Default::default()
    };
    assert!(session_context_from_pb(&bad_context).is_err());

    let missing_context = ext::RoleReady {
        accepted_context: None,
    };
    assert!(role_ready_from_pb(&missing_context).is_err());

    let bad_ack = ext::EventAck {
        id: "event-1".into(),
        status: ext::AckStatus::Unspecified as i32,
        reject_reason: None,
    };
    assert!(event_ack_from_pb(&bad_ack).is_err());

    assert!(control_frame_from_pb(&ext::ControlFrame { kind: None }).is_err());
    let bad_flow = ext::ControlFrame {
        kind: Some(ext::control_frame::Kind::FlowControl(ext::FlowControl {
            signal: ext::FlowSignal::Unspecified as i32,
        })),
    };
    assert!(control_frame_from_pb(&bad_flow).is_err());

    let rejected_without_reason = ext::ControlFrame {
        kind: Some(ext::control_frame::Kind::ConfigAck(ext::ConfigAck {
            axis: ext::ConfigAxis::InstallationConfig as i32,
            version: 1,
            status: ext::ApplyStatus::Rejected as i32,
            reject_reason: None,
        })),
    };
    assert!(control_frame_from_pb(&rejected_without_reason).is_err());

    let bad_provider_ready = ext::ProviderReady {
        provides: vec![ext::EffectHandlerSpec {
            path: "effect://external-provider/acme/search".into(),
            purity: crate::nexus::v1::Purity::Unspecified as i32,
            description: None,
        }],
    };
    assert!(crate::convert::provider_ready_from_pb(&bad_provider_ready).is_err());
}

#[test]
fn invoke_result_ok_and_err_roundtrip() {
    use crate::convert::{invoke_result_from_pb, invoke_result_to_pb};
    use nexus_types::Value;
    use nexus_types::external::{ErrorInfo, InvokeResult};
    let ok = InvokeResult {
        invocation_id: "r1".into(),
        outcome: Ok(Value::Int(42)),
    };
    let back = invoke_result_from_pb(&invoke_result_to_pb(&ok)).unwrap();
    assert_eq!(back.invocation_id, "r1");
    assert_eq!(back.outcome, Ok(Value::Int(42)));

    let err = InvokeResult {
        invocation_id: "r2".into(),
        outcome: Err(ErrorInfo {
            kind: "rate_limit".into(),
            message: "429".into(),
        }),
    };
    let back = invoke_result_from_pb(&invoke_result_to_pb(&err)).unwrap();
    match back.outcome {
        Err(e) => {
            assert_eq!(e.kind, "rate_limit");
            assert_eq!(e.message, "429");
        }
        Ok(_) => panic!("expected error outcome"),
    }
}

#[test]
fn source_command_frames_roundtrip() {
    use crate::convert::{
        command_result_from_pb, command_result_to_pb, outbound_command_from_pb,
        outbound_command_to_pb,
    };
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
    let back = outbound_command_from_pb(&outbound_command_to_pb(&command)).unwrap();
    assert_eq!(back, command);

    let ok = CommandResult {
        id: "cmd-1".into(),
        outcome: Ok(Value::Bool(true)),
    };
    let back = command_result_from_pb(&command_result_to_pb(&ok)).unwrap();
    assert_eq!(back, ok);

    let err = CommandResult {
        id: "cmd-2".into(),
        outcome: Err(ErrorInfo {
            kind: "bridge_error".into(),
            message: "failed".into(),
        }),
    };
    let back = command_result_from_pb(&command_result_to_pb(&err)).unwrap();
    assert_eq!(back, err);
}
