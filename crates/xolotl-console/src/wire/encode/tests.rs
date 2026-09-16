use super::*;
use crate::protocol::ActionResult;
use anyhow::{Result, ensure};

fn reply(value: Value) -> ServerFrame {
    ServerFrame::Reply {
        id: u64::MAX,
        result: ActionResult::value(value, u64::MAX),
    }
}

#[test]
fn exact_frame_size_includes_envelopes_and_varints() -> Result<()> {
    for value in [
        Value::null(),
        Value::integer(i64::MIN),
        Value::integer(127),
        Value::integer(128),
        Value::string("abc".into()),
    ] {
        let frame = reply(value);
        let pb = server_frame_to_pb(&frame, 4096)?;
        let size = pb.encoded_len();
        let bytes = encode_bounded(&pb, size)?;
        ensure!(bytes.len() == size);
        ensure!(
            matches!(encode_bounded(&pb, size - 1), Err(FrameEncodeError::FrameBytes { actual, limit }) if actual == size && limit == size - 1)
        );
        ensure!(pb::ConsoleFrame::decode(bytes.as_slice())? == pb);
    }
    Ok(())
}

#[test]
fn tiny_values_still_have_bounded_node_cost() -> Result<()> {
    let frame = reply(Value::list(vec![Value::null(); MAX_VALUE_NODES]));
    ensure!(matches!(
        encode_server_frame(&frame, HARD_MAX_WS_FRAME_BYTES),
        Err(FrameEncodeError::Value(ValueEncodeError::Nodes {
            limit: MAX_VALUE_NODES
        }))
    ));
    Ok(())
}

#[test]
fn principal_fields_share_one_inline_budget() -> Result<()> {
    let principal = PrincipalSummary {
        username: "abc".into(),
        identity_path: "def".into(),
        mfa_level: 1,
    };
    ensure!(principal_to_pb(&principal, &mut ConversionBudget::new(6))?.username == "abc");
    ensure!(matches!(
        principal_to_pb(&principal, &mut ConversionBudget::new(5)),
        Err(FrameEncodeError::FieldBytes {
            field: "principal.identity_path",
            limit: 5
        })
    ));
    Ok(())
}

#[test]
fn all_event_payloads_and_messages_are_checked_before_cloning() -> Result<()> {
    let path = Path::parse("state://a")?;
    for frame in [
        reply(Value::bytes(vec![0; 1025])),
        ServerFrame::Event {
            stream: 1,
            event: ConsoleEvent::StateSet {
                path: path.clone(),
                value: Value::string("x".repeat(1025)),
            },
        },
        ServerFrame::Event {
            stream: 1,
            event: ConsoleEvent::StateAppend {
                path,
                item: Value::string("x".repeat(1025)),
            },
        },
        ServerFrame::Event {
            stream: 1,
            event: ConsoleEvent::Audit {
                fact: Value::string("x".repeat(1025)),
            },
        },
    ] {
        ensure!(matches!(
            encode_server_frame(&frame, 1024),
            Err(FrameEncodeError::Value(
                ValueEncodeError::InlineBytes { .. }
            ))
        ));
    }
    for frame in [
        ServerFrame::Error {
            id: Some(1),
            code: ConsoleErrorCode::BadRequest,
            message: "x".repeat(1025),
        },
        ServerFrame::Event {
            stream: 1,
            event: ConsoleEvent::SubscriptionClosed {
                reason: "x".repeat(1025),
            },
        },
    ] {
        ensure!(matches!(
            encode_server_frame(&frame, 1024),
            Err(FrameEncodeError::FieldBytes { .. })
        ));
    }
    Ok(())
}

#[test]
fn typed_paths_bound_bytes_and_component_allocations() -> Result<()> {
    let path = Path::parse("path://east/state/a/b")?;
    ensure!(ConversionBudget::new(11).path(&path)? == path_to_pb(&path));
    ensure!(matches!(
        ConversionBudget::new(10).path(&path),
        Err(FrameEncodeError::FieldBytes { .. })
    ));

    let frame = ServerFrame::Event {
        stream: 1,
        event: ConsoleEvent::StateDelete {
            path: Path::parse(&format!("state://{}", "a/".repeat(MAX_PATH_SEGMENTS) + "a"))?,
        },
    };
    ensure!(matches!(
        encode_server_frame(&frame, 16_384),
        Err(FrameEncodeError::PathSegments {
            limit: MAX_PATH_SEGMENTS
        })
    ));
    Ok(())
}

#[test]
fn path_and_value_share_the_inline_budget() -> Result<()> {
    let event = ConsoleEvent::StateSet {
        path: Path::parse("state://a")?,
        value: Value::string("abc".into()),
    };
    let pb = console_event_to_pb(&event, ConversionBudget::new(9))?;
    ensure!(pb.kind.is_some());
    ensure!(matches!(
        console_event_to_pb(&event, ConversionBudget::new(8)),
        Err(FrameEncodeError::Value(ValueEncodeError::InlineBytes {
            limit: 2
        }))
    ));
    Ok(())
}

#[test]
fn deepest_supported_map_roundtrips_inside_a_real_event() -> Result<()> {
    let path = Path::parse("state://a")?;
    let nested = |depth| {
        (1..depth).fold(Value::integer(i64::MIN), |value, _| {
            Value::map([("key".into(), value)].into_iter().collect())
        })
    };
    let frame = |depth| ServerFrame::Event {
        stream: u64::MAX,
        event: ConsoleEvent::StateSet {
            path: path.clone(),
            value: nested(depth),
        },
    };
    let bytes = encode_server_frame(&frame(MAX_VALUE_ENCODE_DEPTH), 16_384)?;
    let decoded = pb::ConsoleFrame::decode(bytes.as_slice())?;
    ensure!(matches!(
        decoded.frame,
        Some(pb::console_frame::Frame::Event(_))
    ));
    ensure!(matches!(
        encode_server_frame(&frame(MAX_VALUE_ENCODE_DEPTH + 1), 16_384),
        Err(FrameEncodeError::Value(ValueEncodeError::Depth {
            limit: MAX_VALUE_ENCODE_DEPTH
        }))
    ));
    Ok(())
}

#[test]
fn configured_frame_limit_cannot_bypass_backend_hard_limit() -> Result<()> {
    ensure!(matches!(
        encode_server_frame(
            &reply(Value::bytes(vec![0; HARD_MAX_WS_FRAME_BYTES + 1])),
            usize::MAX
        ),
        Err(FrameEncodeError::Value(ValueEncodeError::InlineBytes {
            limit: HARD_MAX_WS_FRAME_BYTES
        }))
    ));
    Ok(())
}
