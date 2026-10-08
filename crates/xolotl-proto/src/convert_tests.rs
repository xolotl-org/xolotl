//! Round-trip tests for the wire conversions. Every `Value` variant and the
//! Path / Capability / Outcome mappings must survive a `to_pb`/`from_pb` cycle.

use crate::convert::*;
use anyhow::{Context, anyhow, bail, ensure};
use std::collections::BTreeMap;
use xolotl_graph::{DoNode, OperationTemplate, StepRef};
use xolotl_types::{
    BlobRef, Capability, DType, Failure, FloatBits, FrameKind, Outcome, OutputMode, Path,
    Predicate, ResourceName, StreamMarker, TensorRef, Value,
};

fn p(path: &str) -> anyhow::Result<Path> {
    Path::parse(path).map_err(|error| anyhow!("path parse failed for {path}: {error}"))
}

fn pb_path(path: &str) -> anyhow::Result<crate::xolotl::v1::Path> {
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

fn pb_blob() -> crate::xolotl::v1::BlobRef {
    let blob = blob();
    crate::xolotl::v1::BlobRef {
        hash: blob.hash,
        size: blob.size,
        mime: blob.mime,
    }
}

fn composite_value() -> Value {
    let mut m = BTreeMap::new();
    m.insert("null".into(), Value::null());
    m.insert("bool".into(), Value::boolean(true));
    m.insert("int".into(), Value::integer(-7));
    m.insert("float".into(), Value::float(FloatBits(3.5)));
    m.insert("str".into(), Value::string("héllo".into()));
    m.insert("bytes".into(), Value::bytes(vec![0, 1, 2, 255]));
    m.insert(
        "list".into(),
        Value::list(vec![
            Value::integer(1),
            Value::string("x".into()),
            Value::null(),
        ]),
    );
    m.insert("blob".into(), Value::blob(blob()));
    m.insert(
        "tensor".into(),
        Value::from(TensorRef {
            blob: blob(),
            dtype: DType::F32,
            shape: vec![1, 8],
        }),
    );
    m.insert(
        "frame".into(),
        Value::frame(blob(), 123_456, FrameKind::Video),
    );
    m.insert("stream_done".into(), Value::stream_end(StreamMarker::Done));
    m.insert(
        "stream_err".into(),
        Value::stream_end(StreamMarker::Error {
            message: "boom".into(),
        }),
    );
    Value::map(m)
}

#[test]
fn value_round_trips_every_variant() -> anyhow::Result<()> {
    let v = composite_value();
    let back = value_from_pb(&value_to_pb(&v))?;
    ensure!(v == back, "structural Value mapping must be lossless");
    Ok(())
}

#[test]
fn protobuf_wire_round_trip_preserves_exact_float_bits() -> anyhow::Result<()> {
    use prost::Message;
    for bits in [
        0,
        1,
        1u64 << 63,
        f64::INFINITY.to_bits(),
        f64::NEG_INFINITY.to_bits(),
        0x7ff0_0000_0000_0001,
        0x7ff8_0000_0000_1234,
        u64::MAX,
    ] {
        let value = Value::float(FloatBits(f64::from_bits(bits)));
        let bytes = value_to_pb(&value).encode_to_vec();
        let wire = crate::xolotl::v1::Value::decode(bytes.as_slice())?;
        let decoded = value_from_pb(&wire)?;
        ensure!(decoded == value, "protobuf changed float bits {bits:016x}");
    }
    Ok(())
}

#[test]
fn protobuf_map_encoding_is_stable_across_reconstruction() -> anyhow::Result<()> {
    use prost::Message;

    let nested = Value::map(BTreeMap::from([
        ("z".into(), Value::integer(3)),
        ("a".into(), Value::string("same".into())),
    ]));
    let value = Value::map(BTreeMap::from([
        ("origin".into(), Value::string("current_attempt".into())),
        ("nested".into(), nested),
        ("failure".into(), Value::null()),
    ]));
    let expected = value_to_pb(&value).encode_to_vec();
    for _ in 0..64 {
        let rebuilt = value_to_pb(&value).encode_to_vec();
        ensure!(
            rebuilt == expected,
            "map encoding changed across reconstruction"
        );
        let decoded = crate::xolotl::v1::Value::decode(rebuilt.as_slice())?;
        ensure!(value_to_pb(&value_from_pb(&decoded)?).encode_to_vec() == expected);
    }
    Ok(())
}

#[test]
fn protobuf_error_details_encoding_is_stable() -> anyhow::Result<()> {
    use crate::xolotl::v1::external as ext;
    use prost::Message;

    let make = |keys: &[(&str, &str)]| ext::ErrorInfo {
        code: "remote".into(),
        message: "failed".into(),
        details: keys
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect(),
    };
    let entries = [("zeta", "3"), ("alpha", "1"), ("beta", "2")];
    let expected = make(&entries).encode_to_vec();
    for _ in 0..64 {
        ensure!(
            make(&[("beta", "2"), ("alpha", "1"), ("zeta", "3")]).encode_to_vec() == expected,
            "error details map wire order changed"
        );
    }
    Ok(())
}

#[test]
fn every_dtype_round_trips() -> anyhow::Result<()> {
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
        let v = Value::from(TensorRef {
            blob: blob(),
            dtype: d,
            shape: vec![2],
        });
        ensure!(v == value_from_pb(&value_to_pb(&v))?, "dtype {d:?}");
    }
    Ok(())
}

#[test]
fn every_frame_kind_round_trips() -> anyhow::Result<()> {
    for k in [
        FrameKind::Audio,
        FrameKind::Video,
        FrameKind::Pose,
        FrameKind::Sensor,
    ] {
        let v = Value::frame(blob(), 1, k);
        ensure!(v == value_from_pb(&value_to_pb(&v))?, "frame kind {k:?}");
    }
    Ok(())
}

#[test]
fn empty_pb_value_is_null() -> anyhow::Result<()> {
    let pb = crate::xolotl::v1::Value { kind: None };
    ensure!(value_from_pb(&pb)? == Value::null());
    Ok(())
}

#[test]
fn value_rejects_malformed_multimodal_refs() {
    use crate::xolotl::v1 as pb;
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

    assert!(value_from_pb(&null_bad_enum).is_err());
    assert!(value_from_pb(&tensor_missing_blob).is_err());
    assert!(value_from_pb(&tensor_bad_dtype).is_err());
    assert!(value_from_pb(&frame_bad_kind).is_err());
    assert!(value_from_pb(&stream_marker_missing_kind).is_err());
    assert!(value_from_pb(&stream_marker_false_done).is_err());
    let nested_invalid = pb::Value {
        kind: Some(pb::value::Kind::ListVal(pb::ListValue {
            items: vec![pb::Value {
                kind: Some(pb::value::Kind::MapVal(pb::MapValue {
                    entries: [("bad".into(), tensor_bad_dtype)].into(),
                })),
            }],
        })),
    };
    assert!(value_from_pb(&nested_invalid).is_err());
}

#[test]
fn external_value_frames_reject_malformed_multimodal_refs() -> anyhow::Result<()> {
    use crate::xolotl::v1 as pb;
    use crate::xolotl::v1::external as ext;

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
            stream_epoch: None,
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
    use crate::xolotl::v1::external as ext;

    ensure!(
        inbound_event_from_pb(&ext::InboundEvent {
            id: "event-1".into(),
            payload: None,
            timestamp_ms: 1,
            observed: Some(ext::ObservedGenerations::default()),
            stream_id: None,
            seq: None,
            stream_epoch: None,
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
    use crate::xolotl::v1 as pb;
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
        cluster: Some("phone".into()),
        scheme: "state".into(),
        segments: vec!["kernel".into(), "config".into()],
        method: Some("read_secret".into()),
        predicate: Predicate::parse("size<100").ok(),
    };
    let back = capability_from_pb(&capability_to_pb(&c))?;
    ensure!(c.verb == back.verb, "verb changed: {}", back.verb);
    ensure!(
        c.cluster == back.cluster,
        "cluster changed: {:?}",
        back.cluster
    );
    ensure!(c.scheme == back.scheme, "scheme changed: {}", back.scheme);
    ensure!(c.method == back.method, "method changed: {:?}", back.method);
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
        Some(Value::string("hello".into())),
    )?;
    let program = DoNode::Both(
        Box::new(DoNode::Pure(Value::integer(1))),
        Box::new(DoNode::Op(op)),
    );
    let back = program_from_pb(&program_to_pb(&program)?)?;
    ensure!(program == back, "program changed: {back:?}");
    Ok(())
}

#[test]
fn program_finally_round_trips_structurally() -> anyhow::Result<()> {
    let program = DoNode::pure(7).finally(DoNode::pure(Value::null()));
    let back = program_from_pb(&program_to_pb(&program)?)?;
    ensure!(program == back, "finally changed: {back:?}");
    Ok(())
}

#[test]
fn native_wire_depth_is_bounded_on_both_conversion_paths() -> anyhow::Result<()> {
    use crate::xolotl::v1 as pb;
    use prost::Message;

    let mut program = DoNode::pure(7);
    for _ in 1..MAX_WIRE_DO_DEPTH {
        program = program.and_then(StepRef::new("next"));
    }
    let mut wire = program_to_pb(&program)?;
    let encoded = wire.encode_to_vec();
    let decoded = pb::Program::decode(encoded.as_slice())?;
    ensure!(program_from_pb(&decoded)? == program);

    program = program.and_then(StepRef::new("next"));
    ensure!(xolotl_graph::compile_do(&program).is_ok());
    ensure!(matches!(
        program_to_pb(&program),
        Err(ConvertError::ProgramDepth {
            max: MAX_WIRE_DO_DEPTH
        })
    ));

    wire.root = Some(pb::DoNode {
        kind: Some(pb::do_node::Kind::AndThen(pb::AndThen {
            d: wire.root.take().map(Box::new),
            then: Some(pb::StepRef {
                name: "next".into(),
                arg: None,
            }),
        })),
    });
    ensure!(matches!(
        program_from_pb(&wire),
        Err(ConvertError::ProgramDepth {
            max: MAX_WIRE_DO_DEPTH
        })
    ));
    Ok(())
}

#[test]
fn native_wire_depth_counts_nested_values() -> anyhow::Result<()> {
    use crate::xolotl::v1 as pb;

    let nested = Value::list(vec![Value::list(vec![Value::integer(7)])]);
    let mut program = DoNode::pure(nested.clone());
    for _ in 1..MAX_WIRE_DO_DEPTH {
        program = program.and_then(StepRef::new("next"));
    }
    ensure!(matches!(
        program_to_pb(&program),
        Err(ConvertError::MessageDepth { max: 100 })
    ));

    let mut wire = program_to_pb(&DoNode::pure(nested))?;
    for _ in 1..MAX_WIRE_DO_DEPTH {
        wire.root = Some(pb::DoNode {
            kind: Some(pb::do_node::Kind::AndThen(pb::AndThen {
                d: wire.root.take().map(Box::new),
                then: Some(pb::StepRef {
                    name: "next".into(),
                    arg: None,
                }),
            })),
        });
    }
    ensure!(matches!(
        program_from_pb(&wire),
        Err(ConvertError::MessageDepth { max: 100 })
    ));
    Ok(())
}

#[test]
fn program_explicit_unspecified_output_mode_fails_closed() -> anyhow::Result<()> {
    let mut program = program_to_pb(&DoNode::Op(op_template(
        "effect://x/post",
        OutputMode::Unary,
        None,
    )?))?;
    let root = program.root.as_mut().context("missing program root")?;
    let crate::xolotl::v1::do_node::Kind::Op(op) =
        root.kind.as_mut().context("missing root kind")?
    else {
        bail!("expected op node");
    };
    op.output = Some(crate::xolotl::v1::OutputMode {
        kind: crate::xolotl::v1::OutputModeKind::Unspecified as i32,
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
    )?))?;
    let root = program.root.as_mut().context("missing program root")?;
    let crate::xolotl::v1::do_node::Kind::Op(op) =
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
    )?))?;
    let root = program.root.as_mut().context("missing program root")?;
    let crate::xolotl::v1::do_node::Kind::Op(op) =
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
    )?))?;
    let root = padded.root.as_mut().context("missing program root")?;
    let crate::xolotl::v1::do_node::Kind::Op(op) =
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
    let blank_step = DoNode::pure(Value::null()).and_then(StepRef::new(" "));
    ensure!(
        program_from_pb(&program_to_pb(&blank_step)?).is_err(),
        "blank step name should fail closed"
    );

    let blank_let = DoNode::Let {
        name: String::new(),
        value: Box::new(DoNode::pure(Value::integer(1))),
        body: Box::new(DoNode::Use("x".into())),
    };
    ensure!(
        program_from_pb(&program_to_pb(&blank_let)?).is_err(),
        "blank let binding name should fail closed"
    );

    let blank_use = DoNode::Use("  ".into());
    ensure!(
        program_from_pb(&program_to_pb(&blank_use)?).is_err(),
        "blank use name should fail closed"
    );
    Ok(())
}

#[test]
fn named_steps_round_trip_through_protobuf_bytes() -> anyhow::Result<()> {
    use prost::Message;
    let program = DoNode::pure(Value::integer(21))
        .and_then(StepRef::new("math/double").with_arg(composite_value()))
        .or_else(StepRef::new("recover"));
    let bytes = program_to_pb(&program)?.encode_to_vec();
    let decoded = crate::xolotl::v1::Program::decode(bytes.as_slice())?;
    ensure!(program_from_pb(&decoded)? == program);
    Ok(())
}

#[test]
fn program_missing_failure_kind_fails_closed() -> anyhow::Result<()> {
    let mut program = program_to_pb(&DoNode::Fail(Failure::Timeout))?;
    let root = program.root.as_mut().context("missing program root")?;
    let crate::xolotl::v1::do_node::Kind::Fail(failure) =
        root.kind.as_mut().context("missing root kind")?
    else {
        bail!("expected fail node");
    };
    failure.kind = None;

    ensure!(
        program_from_pb(&program).is_err(),
        "missing failure kind should fail closed"
    );
    Ok(())
}

#[test]
fn program_missing_root_fails_closed() {
    let program = crate::xolotl::v1::Program {
        root: None,
        provenance: None,
    };
    assert!(program_from_pb(&program).is_err());
}

#[test]
fn outcome_done_and_fail_map() -> anyhow::Result<()> {
    let done = Outcome::Done(Value::integer(5));
    let pb = outcome_to_pb(&done);
    ensure!(
        matches!(pb.result, Some(crate::xolotl::v1::outcome::Result::Done(_))),
        "done outcome encoded incorrectly"
    );

    let fail = Outcome::Fail(Failure::Timeout);
    let pb = outcome_to_pb(&fail);
    match pb.result {
        Some(crate::xolotl::v1::outcome::Result::Fail(f)) => {
            ensure!(failure_from_pb(&f)? == Failure::Timeout);
        }
        other => bail!("expected fail, got {other:?}"),
    }
    Ok(())
}

#[test]
fn outcome_unknown_failure_keeps_all_operation_identities() -> anyhow::Result<()> {
    use crate::xolotl::v1 as pb;
    use prost::Message;

    let failure = Failure::OutcomeUnknown {
        operation_ids: vec![
            "process/7/execution/11/invocation/3".into(),
            "process/7/execution/11/invocation/4".into(),
        ],
        reason: "source command acknowledgement missing".into(),
    };
    ensure!(failure_kind(&failure) == "outcome_unknown");
    let encoded = failure_to_pb(&failure).encode_to_vec();
    let wire = pb::Failure::decode(encoded.as_slice())?;
    ensure!(matches!(
        &wire.kind,
        Some(pb::failure::Kind::OutcomeUnknown(detail))
            if detail.operation_ids == [
                "process/7/execution/11/invocation/3",
                "process/7/execution/11/invocation/4",
            ]
    ));
    ensure!(failure_from_pb(&wire)? == failure);
    Ok(())
}

#[test]
fn value_survives_protobuf_encode_decode() -> anyhow::Result<()> {
    use prost::Message;
    let pb = value_to_pb(&composite_value());
    let bytes = pb.encode_to_vec();
    let decoded = crate::xolotl::v1::Value::decode(&bytes[..])?;
    ensure!(pb == decoded, "protobuf value changed: {decoded:?}");
    let value = value_from_pb(&decoded)?;
    ensure!(
        value == composite_value(),
        "decoded value changed: {value:?}"
    );
    Ok(())
}

#[test]
fn external_handshake_frames_survive_wire() -> anyhow::Result<()> {
    use crate::xolotl::v1::external as ext;
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
                config_schema: Some(value_to_pb(&Value::null())),
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
        scope_epoch: 9,
        installation_epoch: 8,
        key_epoch: 3,
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
    use xolotl_types::Value;
    use xolotl_types::external::{
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
        config_schema: Some(Value::map(Default::default())),
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
        scope_epoch: 9,
        installation_epoch: 8,
        key_epoch: 3,
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
        payload: Value::string("hello".into()),
        observed,
        timestamp_ms: 1234,
        stream_id: Some("stream-1".into()),
        seq: Some(7),
        stream_epoch: Some(9),
    };
    let back = inbound_event_from_pb(&inbound_event_to_pb(&event))?;
    ensure!(back == event, "event changed: {back:?}");

    let ack = EventAck {
        id: "event-1".into(),
        status: AckStatus::Rejected,
        reject_reason: Some("schema".into()),
        stream_epoch: Some(9),
    };
    let back = event_ack_from_pb(&event_ack_to_pb(&ack))?;
    ensure!(back == ack, "ack changed: {back:?}");
    let unknown = EventAck {
        id: "event-1".into(),
        status: AckStatus::OutcomeUnknown,
        reject_reason: None,
        stream_epoch: Some(9),
    };
    let unknown_pb = event_ack_to_pb(&unknown);
    ensure!(
        unknown_pb.status == crate::xolotl::v1::external::AckStatus::OutcomeUnknown as i32,
        "indeterminate commit must have a distinct wire status"
    );
    ensure!(event_ack_from_pb(&unknown_pb)? == unknown);
    Ok(())
}

#[test]
fn external_secure_envelope_survives_wire() -> anyhow::Result<()> {
    use crate::xolotl::v1::external as ext;
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
                    direction: "client_to_daemon".into(),
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
    use crate::xolotl::v1::external as ext;
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
    use xolotl_types::Value;
    use xolotl_types::external::{ApplyStatus, ConfigAxis, ControlFrame, FlowSignal, RejectReason};

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
            profile: Value::map(Default::default()),
        },
        ControlFrame::InstallationConfigUpdate {
            config_version: 3,
            config: Value::string("cfg".into()),
        },
        ControlFrame::PresentationConfigUpdate {
            generation: 4,
            profile_hash: "profile-hash".into(),
            config: Value::boolean(true),
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
#[cfg(feature = "grpc")]
fn service_names_and_method_paths_are_correct() {
    assert_eq!(
        crate::xolotl::v1::external::external_service_server::SERVICE_NAME,
        "xolotl.v1.external.ExternalService"
    );
}

#[test]
fn invoke_frame_types_roundtrip_through_pb() -> anyhow::Result<()> {
    use crate::convert::{invoke_from_pb, invoke_to_pb};
    use xolotl_types::external::Invoke;
    use xolotl_types::{MethodId, Value};
    let inv = Invoke {
        invocation_id: "inv-1".into(),
        effect_path: p("effect://x/post")?,
        method_id: MethodId::new(7),
        input: Value::string("hello".into()),
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
    use crate::xolotl::v1 as pb;
    use crate::xolotl::v1::external as ext;

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
        cluster: None,
        scheme: "x".into(),
        segments: vec!["post".into()],
        method: None,
        predicate: None,
    };
    ensure!(
        capability_from_pb(&bad_capability).is_err(),
        "bad capability should fail"
    );
    let injected_capability_segment = pb::Capability {
        verb: "perform".into(),
        cluster: None,
        scheme: "effect".into(),
        segments: vec!["x/post".into()],
        method: None,
        predicate: None,
    };
    ensure!(
        capability_from_pb(&injected_capability_segment).is_err(),
        "capability segment containing delimiter should fail"
    );
    let injected_capability_scheme = pb::Capability {
        verb: "perform".into(),
        cluster: None,
        scheme: "effect/post".into(),
        segments: vec!["x".into()],
        method: None,
        predicate: None,
    };
    ensure!(
        capability_from_pb(&injected_capability_scheme).is_err(),
        "capability scheme containing delimiter should fail"
    );
    let injected_capability_cluster = pb::Capability {
        verb: "perform".into(),
        cluster: Some("bad/cluster".into()),
        scheme: "effect".into(),
        segments: vec!["post".into()],
        method: None,
        predicate: None,
    };
    ensure!(
        capability_from_pb(&injected_capability_cluster).is_err(),
        "capability cluster containing delimiter should fail"
    );

    let missing_effect_path = ext::Invoke {
        invocation_id: "inv-1".into(),
        effect_path: None,
        input: Some(crate::convert::value_to_pb(&Value::null())),
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
        input: Some(crate::convert::value_to_pb(&Value::null())),
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
    let missing_source_epoch = ext::SessionContext {
        role: ext::ExternalRole::Source as i32,
        session_id: "session-1".into(),
        installation_epoch: 8,
        scope_epoch: 0,
        ..Default::default()
    };
    ensure!(
        session_context_from_pb(&missing_source_epoch).is_err(),
        "Source context without a storage-issued scope epoch should fail"
    );
    let provider_with_source_epoch = ext::SessionContext {
        role: ext::ExternalRole::Provider as i32,
        session_id: "session-1".into(),
        installation_epoch: 8,
        scope_epoch: 9,
        ..Default::default()
    };
    ensure!(
        session_context_from_pb(&provider_with_source_epoch).is_err(),
        "Provider context must not claim a Source scope epoch"
    );
    let missing_installation_epoch = ext::SessionContext {
        role: ext::ExternalRole::Provider as i32,
        session_id: "session-1".into(),
        installation_epoch: 0,
        scope_epoch: 0,
        ..Default::default()
    };
    ensure!(
        session_context_from_pb(&missing_installation_epoch).is_err(),
        "every role requires a storage-issued installation epoch"
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
        payload: Some(crate::convert::value_to_pb(&Value::null())),
        timestamp_ms: 1,
        observed: None,
        stream_id: None,
        seq: None,
        stream_epoch: None,
    };
    ensure!(
        inbound_event_from_pb(&missing_event_observed).is_err(),
        "missing event observed generations should fail"
    );

    let missing_command_observed = ext::OutboundCommand {
        id: "cmd-1".into(),
        action: Some(crate::convert::value_to_pb(&Value::null())),
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
        stream_epoch: None,
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
    use crate::xolotl::v1::external as ext;
    use xolotl_types::Value;
    use xolotl_types::external::{ErrorInfo, InvokeResult};
    let ok = InvokeResult {
        invocation_id: "r1".into(),
        outcome: Ok(Value::integer(42)),
    };
    let back = invoke_result_from_pb(&invoke_result_to_pb(&ok))?;
    ensure!(back.invocation_id == "r1", "unexpected invocation id");
    ensure!(
        back.outcome == Ok(Value::integer(42)),
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
    use crate::xolotl::v1::external as ext;
    use xolotl_types::Value;
    use xolotl_types::external::{CommandResult, ErrorInfo, ObservedGenerations, OutboundCommand};

    let command = OutboundCommand {
        id: "cmd-1".into(),
        action: Value::string("send".into()),
        observed: ObservedGenerations {
            presentation_config_generation: 4,
            alias_catalog_generation: 2,
        },
    };
    let back = outbound_command_from_pb(&outbound_command_to_pb(&command))?;
    ensure!(back == command, "command changed: {back:?}");

    let ok = CommandResult {
        id: "cmd-1".into(),
        outcome: Ok(Value::boolean(true)),
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

#[test]
fn console_frame_carries_action_call_with_kernel_value() -> anyhow::Result<()> {
    use crate::xolotl::v1::console as con;
    use prost::Message;

    let input = composite_value();
    let frame = con::ConsoleFrame {
        frame: Some(con::console_frame::Frame::Call(con::ActionCall {
            id: 42,
            action: "config.write_cas".into(),
            input: Some(value_to_pb(&input)),
            scope: Some("state://kernel/config".into()),
            justification: Some("rotating key".into()),
            ttl_ms: Some(5_000),
            registry_rev: Some(3),
        })),
    };
    let bytes = frame.encode_to_vec();
    let decoded = con::ConsoleFrame::decode(&bytes[..])?;
    ensure!(
        frame == decoded,
        "console frame changed on the wire: {decoded:?}"
    );

    let call = match decoded.frame {
        Some(con::console_frame::Frame::Call(call)) => call,
        other => bail!("expected Call frame, got {other:?}"),
    };
    ensure!(call.id == 42, "correlation id lost");
    let round = value_from_pb(
        call.input
            .as_ref()
            .ok_or_else(|| anyhow!("input value missing"))?,
    )?;
    ensure!(round == input, "action input value changed: {round:?}");
    Ok(())
}

#[test]
fn console_error_codes_round_trip_every_variant() -> anyhow::Result<()> {
    use crate::xolotl::v1::console as con;
    use prost::Message;

    let codes = [
        con::ConsoleErrorCode::Unauthenticated,
        con::ConsoleErrorCode::Forbidden,
        con::ConsoleErrorCode::StepUpRequired,
        con::ConsoleErrorCode::RateLimited,
        con::ConsoleErrorCode::ValidationFailed,
        con::ConsoleErrorCode::AdmissionRejected,
        con::ConsoleErrorCode::VersionConflict,
        con::ConsoleErrorCode::RegistryChanged,
        con::ConsoleErrorCode::OutcomeUnknown,
        con::ConsoleErrorCode::Internal,
    ];
    for code in codes {
        let wire = con::ConsoleErrorCode::from_str_name(code.as_str_name());
        ensure!(
            wire == Some(code),
            "code {} did not round-trip its str name",
            code.as_str_name()
        );
        let err = con::ConsoleError {
            code: code as i32,
            message: "redacted".into(),
            request_id: Some(99),
            retry_after_ms: Some(250),
            required_mfa_level: Some(2),
            current_version: Some(13),
            current_registry_rev: Some(5),
            mfa: Some(con::MfaOptions {
                factors: vec![
                    con::MfaFactor {
                        factor_id: "factor-phone".into(),
                        provider_id: "totp".into(),
                        label: "Phone".into(),
                        created_at: 1_700_000_000_000,
                        last_used_at: Some(1_700_000_030_000),
                        availability: con::FactorAvailability::Available as i32,
                    },
                    con::MfaFactor {
                        factor_id: "factor-device".into(),
                        provider_id: "custom-device".into(),
                        label: "Device".into(),
                        created_at: 1_700_000_000_001,
                        last_used_at: None,
                        availability: con::FactorAvailability::ProviderNotInstalled as i32,
                    },
                    con::MfaFactor {
                        factor_id: "factor-paused".into(),
                        provider_id: "push".into(),
                        label: "Paused by host".into(),
                        created_at: 1_700_000_000_002,
                        last_used_at: None,
                        availability: con::FactorAvailability::AuthenticationDisabled as i32,
                    },
                ],
                recovery_code_available: true,
            }),
            execution: Some(con::ExecutionReference {
                execution_id: Some("execution-42".into()),
                process_id: "456".into(),
                program_id: "ab".repeat(32),
            }),
            outcome_unknown: (code == con::ConsoleErrorCode::OutcomeUnknown).then(|| {
                con::OutcomeUnknownDetail {
                    operation_ids: vec!["1/2/3/4/0".into(), "1/2/4/5/0".into()],
                    reason: "delivery_or_session_lost".into(),
                }
            }),
            unresolved_operations: Some(crate::xolotl::v1::UnresolvedOperations {
                operation_ids: vec!["1/2/3/4/0".into()],
                identities_incomplete: false,
            }),
            runtime_completion: Some(Box::new(value_to_pb(&Value::integer(37)))),
        };
        let bytes = err.encode_to_vec();
        let decoded = con::ConsoleError::decode(&bytes[..])?;
        ensure!(
            err == decoded,
            "console error changed on the wire: {decoded:?}"
        );
    }
    Ok(())
}
#[test]
fn portable_program_wire_preserves_composition_identity_and_rejects_tampering() -> anyhow::Result<()>
{
    use prost::Message;
    use xolotl_graph::portable::{Expression, Program, Transform};
    let source = Program::new(
        Expression::Input
            .then(Expression::Transform {
                operation: Transform::Add { value: 1 },
            })
            .both(Expression::Constant {
                value: Value::bytes(vec![1, 2, 255]),
            }),
    );
    let wire = portable_program_to_pb(&source)?;
    let source_document: serde_json::Value = serde_json::from_slice(&wire.json_source)?;
    anyhow::ensure!(source_document.get("durable").is_none());
    let encoded = wire.encode_to_vec();
    let mut decoded = crate::xolotl::v1::PortableProgram::decode(encoded.as_slice())?;
    let back = portable_program_from_pb(&decoded)?;
    anyhow::ensure!(back == source && back.compile()?.id() == source.compile()?.id());
    decoded.program_id[0] ^= 1;
    anyhow::ensure!(portable_program_from_pb(&decoded).is_err());
    decoded.json_source = vec![b' '; 1024 * 1024 + 1];
    anyhow::ensure!(portable_program_from_pb(&decoded).is_err());
    Ok(())
}

#[test]
fn source_stream_v1_roundtrip_and_rejects_missing_operation() -> anyhow::Result<()> {
    use crate::xolotl::v1::external as ext;
    use crate::{
        source_stream_request_from_pb, source_stream_request_to_pb, source_stream_result_from_pb,
        source_stream_result_to_pb,
    };
    use xolotl_types::external::{
        SourceStreamOperation, SourceStreamOutcome, SourceStreamRejectCode, SourceStreamRejected,
        SourceStreamRequest, SourceStreamResult, SourceStreamSnapshot, SourceStreamState,
    };

    for operation in [
        SourceStreamOperation::Inspect,
        SourceStreamOperation::Open {
            expected_revision: 7,
        },
        SourceStreamOperation::Retire { stream_epoch: 11 },
    ] {
        let request = SourceStreamRequest {
            request_id: "operation-1".into(),
            stream_id: "records".into(),
            operation,
        };
        ensure!(source_stream_request_from_pb(&source_stream_request_to_pb(&request))? == request);
    }
    ensure!(
        source_stream_request_from_pb(&ext::SourceStreamRequest {
            request_id: "missing".into(),
            stream_id: "records".into(),
            operation: None,
        })
        .is_err()
    );

    let active = SourceStreamState {
        stream_epoch: 11,
        last_seq: 4,
        open_id: "operation-1".into(),
        opened_at_revision: 7,
    };
    for outcome in [
        SourceStreamOutcome::Inspected(SourceStreamSnapshot {
            revision: 8,
            active: Some(active.clone()),
        }),
        SourceStreamOutcome::Opened(SourceStreamSnapshot {
            revision: 8,
            active: Some(active),
        }),
        SourceStreamOutcome::Retired { revision: 9 },
        SourceStreamOutcome::Rejected(SourceStreamRejected {
            code: SourceStreamRejectCode::RevisionConflict,
            current_revision: Some(9),
            active_epoch: None,
            current: None,
        }),
    ] {
        let result = SourceStreamResult {
            request_id: "operation-1".into(),
            stream_id: "records".into(),
            outcome,
        };
        ensure!(source_stream_result_from_pb(&source_stream_result_to_pb(&result))? == result);
    }
    ensure!(
        source_stream_result_from_pb(&ext::SourceStreamResult {
            request_id: "operation-1".into(),
            stream_id: "records".into(),
            outcome: Some(ext::source_stream_result::Outcome::Rejected(
                ext::SourceStreamRejected {
                    code: ext::SourceStreamRejectCode::Unspecified as i32,
                    current_revision: None,
                    active_epoch: None,
                    current: None,
                },
            )),
        })
        .is_err()
    );
    Ok(())
}
