use anyhow::{Result, ensure};
use prost::Message as _;
use xolotl_types::{DType, FloatBits, FrameKind};

use super::*;

const LIMITS: ValueEncodeLimits = ValueEncodeLimits {
    max_nodes: 1024,
    max_depth: MAX_VALUE_ENCODE_DEPTH,
    max_inline_bytes: 4096,
};

fn blob() -> BlobRef {
    BlobRef {
        hash: "abc".into(),
        size: u64::MAX,
        mime: Some("x/y".into()),
    }
}

fn nested_map(depth: usize, leaf: Value) -> Value {
    (1..depth).fold(leaf, |value, _| {
        Value::map([("".into(), value)].into_iter().collect())
    })
}

fn check_inline_boundary(value: &Value, bytes: usize) -> Result<()> {
    let limits = ValueEncodeLimits {
        max_inline_bytes: bytes,
        ..LIMITS
    };
    ensure!(
        value_to_pb_bounded(value, limits)? == value_to_pb(value),
        "bounded conversion changed the canonical value"
    );
    if bytes > 0 {
        ensure!(
            value_to_pb_bounded(
                value,
                ValueEncodeLimits {
                    max_inline_bytes: bytes - 1,
                    ..limits
                },
            ) == Err(ValueEncodeError::InlineBytes { limit: bytes - 1 }),
            "conversion accepted an inline budget one byte too small"
        );
    }
    Ok(())
}

#[test]
fn bounded_conversion_preserves_every_variant_and_inline_boundary() -> Result<()> {
    for (value, bytes) in [
        (Value::null(), 0),
        (Value::boolean(false), 0),
        (Value::integer(i64::MIN), 0),
        (Value::float(FloatBits(-0.0)), 0),
        (Value::string("h\u{00e9}llo".into()), 6),
        (Value::bytes(vec![0, 1, 2, 255]), 4),
        (Value::list(Vec::new()), 0),
        (Value::map(Default::default()), 0),
        (Value::blob(blob()), 6),
        (Value::tensor(blob(), DType::Bf16, vec![0, 1, u64::MAX]), 34),
        (Value::frame(blob(), i64::MIN, FrameKind::Video), 11),
        (Value::stream_end(StreamMarker::Done), 0),
        (
            Value::stream_end(StreamMarker::Error {
                message: "ended".into(),
            }),
            5,
        ),
    ] {
        check_inline_boundary(&value, bytes)?;
    }
    Ok(())
}

#[test]
fn inline_budget_accumulates_nested_payloads_and_map_keys() -> Result<()> {
    let value = Value::map(
        [
            ("".into(), Value::string("abc".into())),
            (
                "key".into(),
                Value::list(vec![Value::bytes(vec![1, 2]), Value::blob(blob())]),
            ),
        ]
        .into_iter()
        .collect(),
    );
    check_inline_boundary(&value, 14)
}

#[test]
fn every_dtype_and_frame_kind_charges_its_canonical_metadata() -> Result<()> {
    for (dtype, bytes) in [
        (DType::F16, 3),
        (DType::Bf16, 4),
        (DType::F32, 3),
        (DType::F64, 3),
        (DType::I8, 2),
        (DType::I16, 3),
        (DType::I32, 3),
        (DType::I64, 3),
        (DType::U8, 2),
        (DType::Bool, 4),
    ] {
        check_inline_boundary(&Value::tensor(blob(), dtype, Vec::new()), 6 + bytes)?;
    }
    for (kind, bytes) in [
        (FrameKind::Audio, 5),
        (FrameKind::Video, 5),
        (FrameKind::Pose, 4),
        (FrameKind::Sensor, 6),
    ] {
        check_inline_boundary(&Value::frame(blob(), 0, kind), 6 + bytes)?;
    }
    Ok(())
}

#[test]
fn external_blob_size_does_not_consume_inline_budget() -> Result<()> {
    check_inline_boundary(
        &Value::blob(BlobRef {
            hash: String::new(),
            size: u64::MAX,
            mime: None,
        }),
        0,
    )
}

#[test]
fn root_and_empty_collections_each_consume_one_node() {
    for value in [
        Value::null(),
        Value::list(Vec::new()),
        Value::map(Default::default()),
    ] {
        assert!(
            value_to_pb_bounded(
                &value,
                ValueEncodeLimits {
                    max_nodes: 1,
                    max_depth: 1,
                    max_inline_bytes: 0,
                },
            )
            .is_ok()
        );
        assert_eq!(
            value_to_pb_bounded(
                &value,
                ValueEncodeLimits {
                    max_nodes: 0,
                    ..LIMITS
                },
            ),
            Err(ValueEncodeError::Nodes { limit: 0 })
        );
    }
}

#[test]
fn collection_node_budget_includes_every_child() {
    let value = Value::list(vec![
        Value::list(Vec::new()),
        Value::map([("".into(), Value::null())].into_iter().collect()),
    ]);
    assert!(
        value_to_pb_bounded(
            &value,
            ValueEncodeLimits {
                max_nodes: 4,
                max_inline_bytes: 0,
                ..LIMITS
            },
        )
        .is_ok()
    );
    assert_eq!(
        value_to_pb_bounded(
            &value,
            ValueEncodeLimits {
                max_nodes: 3,
                ..LIMITS
            },
        ),
        Err(ValueEncodeError::Nodes { limit: 3 })
    );
}

#[test]
fn broad_collections_fail_before_inspecting_child_payloads() {
    for value in [
        Value::list(vec![Value::bytes(vec![1]), Value::bytes(vec![2])]),
        Value::map(
            [
                ("a".into(), Value::bytes(vec![1])),
                ("b".into(), Value::bytes(vec![2])),
            ]
            .into_iter()
            .collect(),
        ),
    ] {
        assert_eq!(
            value_to_pb_bounded(
                &value,
                ValueEncodeLimits {
                    max_nodes: 2,
                    max_inline_bytes: 0,
                    ..LIMITS
                },
            ),
            Err(ValueEncodeError::Nodes { limit: 2 })
        );
    }
}

#[test]
fn depth_budget_counts_root_as_one_for_lists_and_maps() {
    for value in [
        Value::list(vec![Value::list(vec![Value::null()])]),
        nested_map(3, Value::null()),
    ] {
        assert!(
            value_to_pb_bounded(
                &value,
                ValueEncodeLimits {
                    max_depth: 3,
                    ..LIMITS
                },
            )
            .is_ok()
        );
        assert_eq!(
            value_to_pb_bounded(
                &value,
                ValueEncodeLimits {
                    max_depth: 2,
                    ..LIMITS
                },
            ),
            Err(ValueEncodeError::Depth { limit: 2 })
        );
    }
    assert_eq!(
        value_to_pb_bounded(
            &Value::null(),
            ValueEncodeLimits {
                max_depth: 0,
                ..LIMITS
            },
        ),
        Err(ValueEncodeError::Depth { limit: 0 })
    );
}

#[test]
fn caller_cannot_raise_the_hard_depth_limit() {
    let limits = ValueEncodeLimits {
        max_depth: usize::MAX,
        ..LIMITS
    };
    assert!(
        value_to_pb_bounded(&nested_map(MAX_VALUE_ENCODE_DEPTH, Value::null()), limits).is_ok()
    );
    assert_eq!(
        value_to_pb_bounded(
            &nested_map(MAX_VALUE_ENCODE_DEPTH + 1, Value::null()),
            limits
        ),
        Err(ValueEncodeError::Depth {
            limit: MAX_VALUE_ENCODE_DEPTH,
        })
    );
}

#[test]
fn deepest_map_in_console_frame_decodes_with_prost_default_limit() -> Result<()> {
    use pb::console;

    let value = nested_map(
        MAX_VALUE_ENCODE_DEPTH,
        Value::tensor(blob(), DType::F32, vec![u64::MAX]),
    );
    let frame = console::ConsoleFrame {
        frame: Some(console::console_frame::Frame::Event(console::Event {
            stream: u64::MAX,
            event: Some(console::ConsoleEvent {
                kind: Some(console::console_event::Kind::StateSet(console::StateSet {
                    path: Some(pb::Path {
                        cluster: None,
                        scheme: "state".into(),
                        segments: vec!["test".into()],
                    }),
                    value: Some(value_to_pb_bounded(&value, LIMITS)?),
                })),
                state_rev: 0,
                fact_cursor: 0,
                coalesced: false,
            }),
        })),
    };
    let encoded = frame.encode_to_vec();
    ensure!(
        console::ConsoleFrame::decode(encoded.as_slice())? == frame,
        "deepest accepted value did not round-trip through its frame envelope"
    );
    Ok(())
}

#[test]
fn inline_budget_does_not_wrap_at_usize_max() -> Result<()> {
    let mut budget = ValueEncodeBudget::new(ValueEncodeLimits {
        max_inline_bytes: usize::MAX,
        ..LIMITS
    });
    budget.charge_bytes(usize::MAX - 1)?;
    ensure!(
        budget.charge_bytes(2) == Err(ValueEncodeError::InlineBytes { limit: usize::MAX }),
        "cumulative inline byte accounting wrapped"
    );
    budget.charge_bytes(1)?;
    ensure!(
        budget.charge_bytes(1) == Err(ValueEncodeError::InlineBytes { limit: usize::MAX }),
        "an exhausted inline byte budget accepted another byte"
    );
    Ok(())
}

#[test]
fn tensor_shape_storage_overflow_is_rejected() {
    let mut budget = ValueEncodeBudget::new(ValueEncodeLimits {
        max_inline_bytes: usize::MAX,
        ..LIMITS
    });
    assert_eq!(
        budget.charge_tensor_shape(usize::MAX / size_of::<u64>() + 1),
        Err(ValueEncodeError::InlineBytes { limit: usize::MAX })
    );
}
