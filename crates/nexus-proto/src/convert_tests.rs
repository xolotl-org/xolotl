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

fn rich_value() -> Value {
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
    let v = rich_value();
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
fn program_missing_root_fails_closed() {
    let program = crate::nexus::v1::Program { root: None };
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

// ─── prost wire-encoding round-trips ──────────────────────────────────────────
// These prove the hand-vendored `#[prost(...)]` field tags / oneofs / maps
// encode and decode correctly on the wire (not just that they compile).

#[test]
fn value_survives_protobuf_encode_decode() {
    use prost::Message;
    let pb = value_to_pb(&rich_value());
    let bytes = pb.encode_to_vec();
    let decoded = crate::nexus::v1::Value::decode(&bytes[..]).expect("decode");
    assert_eq!(pb, decoded);
    // …and the structural meaning survives the full wire trip.
    assert_eq!(value_from_pb(&decoded), rich_value());
}

#[test]
fn gateway_messages_survive_wire() {
    use prost::Message;
    let req = crate::nexus::v1::SubmitRequest {
        auth_token: "tok".into(),
        program: Some(program_to_pb(&DoNode::Pure(Value::Null))),
    };
    let bytes = req.encode_to_vec();
    let back = crate::nexus::v1::SubmitRequest::decode(&bytes[..]).unwrap();
    assert_eq!(req, back);

    let resp = crate::nexus::v1::SubmitResponse {
        outcome: Some(outcome_to_pb(&Outcome::Done(Value::Str("ok".into())))),
    };
    let bytes = resp.encode_to_vec();
    assert_eq!(
        resp,
        crate::nexus::v1::SubmitResponse::decode(&bytes[..]).unwrap()
    );
}

#[test]
fn extension_handshake_frames_survive_wire() {
    use crate::nexus::v1::extension as ext;
    use prost::Message;
    let hello = ext::ExtensionFrame {
        frame: Some(ext::extension_frame::Frame::RoleSessionClientHello(
            ext::RoleSessionClientHello {
                role: ext::ExtensionRole::Source as i32,
                installation_id: "install-1".into(),
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
    let back = ext::ExtensionFrame::decode(&bytes[..]).unwrap();
    assert_eq!(hello, back);

    let context = ext::SessionContext {
        extension_def_id: "ext-1".into(),
        role: ext::ExtensionRole::Source as i32,
        registry_hash: "abc".into(),
        credential_generation: 3,
        binding_generation: 4,
        extension_config_version: 5,
        presentation_config_generation: 6,
        alias_catalog_generation: 7,
    };
    let ready = ext::ExtensionFrame {
        frame: Some(ext::extension_frame::Frame::RoleReady(ext::RoleReady {
            accepted_context: Some(context),
        })),
    };
    let bytes = ready.encode_to_vec();
    let back = ext::ExtensionFrame::decode(&bytes[..]).unwrap();
    assert_eq!(ready, back);
}

#[test]
fn control_frame_config_ack_survives_wire() {
    // Regression: ConfigAck is oneof tag 7 (§16.3.3). The oneof field's `tags`
    // list previously omitted 7, so ConfigAck silently failed to round-trip.
    use crate::nexus::v1::extension as ext;
    use prost::Message;
    let frame = ext::ExtensionFrame {
        frame: Some(ext::extension_frame::Frame::Control(ext::ControlFrame {
            kind: Some(ext::control_frame::Kind::ConfigAck(ext::ConfigAck {
                axis: ext::ConfigAxis::ExtensionConfig as i32,
                version: 42,
                status: ext::ApplyStatus::Rejected as i32,
                reject_reason: Some(ext::RejectReason::GenerationStale as i32),
            })),
        })),
    };
    let bytes = frame.encode_to_vec();
    let back = ext::ExtensionFrame::decode(&bytes[..]).unwrap();
    assert_eq!(
        frame, back,
        "ConfigAck (tag 7) must round-trip through the wire"
    );
    // And specifically that the ConfigAck payload survived (not dropped to None).
    match back.frame {
        Some(ext::extension_frame::Frame::Control(c)) => {
            assert!(matches!(
                c.kind,
                Some(ext::control_frame::Kind::ConfigAck(_))
            ));
        }
        other => panic!("expected Control/ConfigAck, got {other:?}"),
    }
}

#[test]
fn service_names_and_method_paths_are_correct() {
    assert_eq!(
        crate::nexus::v1::gateway_service_server::SERVICE_NAME,
        "nexus.v1.GatewayService"
    );
    assert_eq!(
        crate::nexus::v1::extension::extension_service_server::SERVICE_NAME,
        "nexus.v1.extension.ExtensionService"
    );
}

#[test]
fn invoke_frame_types_roundtrip_through_pb() {
    // §16.3.3: the Invoke business frame maps losslessly types ⇄ proto.
    use crate::convert::{invoke_from_pb, invoke_to_pb};
    use nexus_types::extension::Invoke;
    use nexus_types::{Path, Value};
    let inv = Invoke {
        invocation_id: "inv-1".into(),
        effect_path: Path::parse("effect://x/post").unwrap(),
        input: Value::Str("hello".into()),
        deadline_ms: Some(5000),
        output_stream_to: Some(Path::parse("state://chat/out").unwrap()),
    };
    let back = invoke_from_pb(&invoke_to_pb(&inv)).unwrap();
    assert_eq!(back.invocation_id, inv.invocation_id);
    assert_eq!(back.effect_path, inv.effect_path);
    assert_eq!(back.input, inv.input);
    assert_eq!(back.deadline_ms, inv.deadline_ms);
    assert_eq!(back.output_stream_to, inv.output_stream_to);
}

#[test]
fn malformed_wire_paths_and_capabilities_fail_closed() {
    use crate::convert::{capability_from_pb, invoke_from_pb, path_from_pb};
    use crate::nexus::v1 as pb;
    use crate::nexus::v1::extension as ext;

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
    };
    assert!(invoke_from_pb(&missing_effect_path).is_err());
}

#[test]
fn invoke_result_ok_and_err_roundtrip() {
    use crate::convert::{invoke_result_from_pb, invoke_result_to_pb};
    use nexus_types::Value;
    use nexus_types::extension::{ErrorInfo, InvokeResult};
    let ok = InvokeResult {
        invocation_id: "r1".into(),
        outcome: Ok(Value::Int(42)),
    };
    let back = invoke_result_from_pb(&invoke_result_to_pb(&ok));
    assert_eq!(back.invocation_id, "r1");
    assert_eq!(back.outcome, Ok(Value::Int(42)));

    let err = InvokeResult {
        invocation_id: "r2".into(),
        outcome: Err(ErrorInfo {
            kind: "rate_limit".into(),
            message: "429".into(),
        }),
    };
    let back = invoke_result_from_pb(&invoke_result_to_pb(&err));
    match back.outcome {
        Err(e) => {
            assert_eq!(e.kind, "rate_limit");
            assert_eq!(e.message, "429");
        }
        Ok(_) => panic!("expected error outcome"),
    }
}
