//! The protocol codec is usable by adapters without the HTTP feature.

use anyhow::{Context, ensure};
use prost::Message;
use xolotl_console::{
    ActionResult, ClientFrame, ConsoleErrorCode, ConsoleFailure, ExecutionReference,
    OutcomeUnknownDetail, ServerFrame,
    wire::{FrameDecodeError, decode_client_frame, delivery_failure, encode_server_frame},
};
use xolotl_console_protocol::pb;
use xolotl_types::{UnresolvedOperations, Value};

const FRAME_VALUE_NODES: usize = 16_384;

fn put_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn message_field(number: u64, payload: &[u8]) -> Vec<u8> {
    let mut field = Vec::with_capacity(payload.len() + 12);
    put_varint((number << 3) | 2, &mut field);
    put_varint(payload.len() as u64, &mut field);
    field.extend_from_slice(payload);
    field
}

fn call_frame(input: &[u8]) -> Vec<u8> {
    let mut call = message_field(2, b"protocol.describe");
    call.extend(message_field(4, input));
    message_field(3, &call)
}

fn subscribe_frame(input: &[u8]) -> Vec<u8> {
    let mut stream = message_field(2, b"state.watch");
    stream.extend(message_field(3, input));
    message_field(4, &stream)
}

fn list_items(items: usize) -> Vec<u8> {
    // An empty Value message is Null and costs only two wire bytes as an item.
    let mut list = Vec::with_capacity(items * 2);
    for _ in 0..items {
        list.extend_from_slice(&[0x0a, 0x00]);
    }
    list
}

fn list_value(items: usize) -> Vec<u8> {
    message_field(7, &list_items(items))
}

#[test]
fn inbound_value_nodes_are_checked_before_prost_allocation() -> anyhow::Result<()> {
    let exact = call_frame(&list_value(FRAME_VALUE_NODES - 1));
    let ClientFrame::Call { call, .. } = decode_client_frame(&exact, exact.len())? else {
        anyhow::bail!("expected call frame");
    };
    ensure!(call.input.as_list().context("list input")?.len() == FRAME_VALUE_NODES - 1);

    let excess = call_frame(&list_value(FRAME_VALUE_NODES));
    ensure!(matches!(
        decode_client_frame(&excess, excess.len()),
        Err(FrameDecodeError::ValueNodes {
            limit: FRAME_VALUE_NODES
        })
    ));

    let nearly_full = call_frame(&list_value((4 * 1024 * 1024 - 64) / 2));
    ensure!(nearly_full.len() > 4 * 1024 * 1024 - 128);
    ensure!(nearly_full.len() <= 4 * 1024 * 1024);
    ensure!(matches!(
        decode_client_frame(&nearly_full, 4 * 1024 * 1024),
        Err(FrameDecodeError::ValueNodes {
            limit: FRAME_VALUE_NODES
        })
    ));
    Ok(())
}

#[test]
fn inbound_value_depth_matches_outbound_depth() -> anyhow::Result<()> {
    let nested = |depth| {
        let mut value = Vec::new();
        for _ in 1..depth {
            value = message_field(7, &message_field(1, &value));
        }
        call_frame(&value)
    };
    let allowed = nested(30);
    ensure!(matches!(
        decode_client_frame(&allowed, allowed.len())?,
        ClientFrame::Call { .. }
    ));
    let too_deep = nested(31);
    ensure!(matches!(
        decode_client_frame(&too_deep, too_deep.len()),
        Err(FrameDecodeError::ValueDepth { limit: 30 })
    ));
    Ok(())
}

#[test]
fn subscription_input_uses_the_same_predecode_node_limit() {
    let frame = subscribe_frame(&list_value(FRAME_VALUE_NODES));
    assert!(matches!(
        decode_client_frame(&frame, frame.len()),
        Err(FrameDecodeError::ValueNodes {
            limit: FRAME_VALUE_NODES
        })
    ));
}

#[test]
fn preflight_counts_replaced_inputs_and_implicit_map_values() {
    let input = list_value(9_000);
    let mut call = message_field(4, &input);
    call.extend(message_field(4, &input));
    let repeated_input = message_field(3, &call);
    assert!(matches!(
        decode_client_frame(&repeated_input, repeated_input.len()),
        Err(FrameDecodeError::ValueNodes {
            limit: FRAME_VALUE_NODES
        })
    ));

    let mut repeated_frame = call_frame(&input);
    repeated_frame.extend(call_frame(&input));
    assert!(matches!(
        decode_client_frame(&repeated_frame, repeated_frame.len()),
        Err(FrameDecodeError::ValueNodes {
            limit: FRAME_VALUE_NODES
        })
    ));

    let mut map = Vec::with_capacity(FRAME_VALUE_NODES * 2);
    for _ in 0..FRAME_VALUE_NODES {
        map.extend_from_slice(&[0x0a, 0x00]); // entry without a value field
    }
    let missing_values = call_frame(&message_field(8, &map));
    assert!(matches!(
        decode_client_frame(&missing_values, missing_values.len()),
        Err(FrameDecodeError::ValueNodes {
            limit: FRAME_VALUE_NODES
        })
    ));

    let explicit_entry = message_field(1, &message_field(2, &[]));
    let mut explicit_map = Vec::with_capacity(explicit_entry.len() * (FRAME_VALUE_NODES - 1));
    for _ in 0..FRAME_VALUE_NODES - 1 {
        explicit_map.extend_from_slice(&explicit_entry);
    }
    let exact_explicit_values = call_frame(&message_field(8, &explicit_map));
    assert!(decode_client_frame(&exact_explicit_values, exact_explicit_values.len()).is_ok());

    let mut list_variants = message_field(7, &list_items(9_000));
    list_variants.extend(message_field(7, &list_items(9_000)));
    let repeated_oneof = call_frame(&list_variants);
    assert!(matches!(
        decode_client_frame(&repeated_oneof, repeated_oneof.len()),
        Err(FrameDecodeError::ValueNodes {
            limit: FRAME_VALUE_NODES
        })
    ));

    let mut map_entry = Vec::with_capacity(FRAME_VALUE_NODES * 2);
    for _ in 0..FRAME_VALUE_NODES {
        map_entry.extend_from_slice(&[0x12, 0x00]); // repeated value field
    }
    let repeated_entry_value = call_frame(&message_field(8, &message_field(1, &map_entry)));
    assert!(matches!(
        decode_client_frame(&repeated_entry_value, repeated_entry_value.len()),
        Err(FrameDecodeError::ValueNodes {
            limit: FRAME_VALUE_NODES
        })
    ));
}

#[test]
fn preflight_checks_lengths_wire_types_and_unknown_fields() -> anyhow::Result<()> {
    let truncated = message_field(3, &[0x22, 0x05]);
    ensure!(matches!(
        decode_client_frame(&truncated, truncated.len()),
        Err(FrameDecodeError::MalformedWire)
    ));
    let wrong_type = call_frame(&[0x38, 0x00]); // list_val must be a message
    ensure!(matches!(
        decode_client_frame(&wrong_type, wrong_type.len()),
        Err(FrameDecodeError::MalformedWire)
    ));
    ensure!(matches!(
        decode_client_frame(&[0x0b], 1),
        Err(FrameDecodeError::MalformedWire)
    ));
    ensure!(matches!(
        decode_client_frame(&[0x1a, 0x80], 2),
        Err(FrameDecodeError::MalformedWire)
    ));

    let mut call = message_field(4, &[]);
    call.extend_from_slice(&[0xf9, 0x07]); // unknown fixed64 field 127
    call.extend_from_slice(&[0; 8]);
    let with_unknown = message_field(3, &call);
    ensure!(matches!(
        decode_client_frame(&with_unknown, with_unknown.len())?,
        ClientFrame::Call { .. }
    ));
    Ok(())
}

#[test]
fn inbound_limit_precedes_parsing_and_rejects_server_responses() -> anyhow::Result<()> {
    ensure!(matches!(
        decode_client_frame(&[0xff; 2], 1),
        Err(FrameDecodeError::FrameBytes {
            actual: 2,
            limit: 1
        })
    ));
    let ping = pb::ConsoleFrame {
        frame: Some(pb::console_frame::Frame::Ping(19)),
    }
    .encode_to_vec();
    ensure!(decode_client_frame(&ping, ping.len())? == ClientFrame::Ping { nonce: 19 });

    let response = encode_server_frame(&ServerFrame::Pong { nonce: 19 }, 64)?;
    ensure!(matches!(
        decode_client_frame(&response, response.len()),
        Err(FrameDecodeError::ServerOnly)
    ));
    Ok(())
}

#[test]
fn oversized_reply_keeps_execution_and_unresolved_effect_identities() -> anyhow::Result<()> {
    let execution = ExecutionReference {
        execution_id: Some("retained-run".into()),
        process_id: "27".into(),
        program_id: "a".repeat(64),
    };
    let mut unresolved = UnresolvedOperations::default();
    ensure!(unresolved.record("provider-ticket-42"));
    let reply = ServerFrame::Reply {
        id: 14,
        result: ActionResult {
            output: Some(Value::bytes(vec![0; 2048])),
            execution: Some(Box::new(execution.clone())),
            unresolved_operations: Some(Box::new(unresolved.clone())),
            ..ActionResult::empty(1, 2)
        },
    };
    ensure!(encode_server_frame(&reply, 1024).is_err());
    let failure = delivery_failure(&reply, 1024)?;
    let ServerFrame::Error {
        id,
        failure: evidence,
    } = &failure
    else {
        anyhow::bail!("delivery failure lost its error envelope");
    };
    ensure!(*id == Some(14));
    ensure!(evidence.code == ConsoleErrorCode::Internal);
    ensure!(evidence.execution.as_deref() == Some(&execution));
    ensure!(evidence.unresolved_operations.as_deref() == Some(&unresolved));
    let encoded = encode_server_frame(&failure, 1024)?;
    let decoded = pb::ConsoleFrame::decode(encoded.as_slice())?;
    let Some(pb::console_frame::Frame::Error(error)) = decoded.frame else {
        anyhow::bail!("error frame did not survive encoding");
    };
    ensure!(error.request_id == Some(14));
    ensure!(error.execution.is_some());
    ensure!(
        error
            .unresolved_operations
            .context("effect identities")?
            .operation_ids
            == ["provider-ticket-42"]
    );
    Ok(())
}

#[test]
fn oversized_error_retains_full_uncertain_outcome_and_other_effects() -> anyhow::Result<()> {
    let unknown = OutcomeUnknownDetail {
        operation_ids: vec!["operation-a".into()],
        reason: "delivery_or_session_lost".into(),
    };
    let mut unresolved = UnresolvedOperations::default();
    ensure!(unresolved.record("operation-b"));
    let original = ServerFrame::Error {
        id: Some(23),
        failure: ConsoleFailure {
            outcome_unknown: Some(Box::new(unknown.clone())),
            unresolved_operations: Some(Box::new(unresolved.clone())),
            ..ConsoleFailure::new(ConsoleErrorCode::OutcomeUnknown, "x".repeat(2048))
        },
    };
    ensure!(encode_server_frame(&original, 1024).is_err());
    let fallback = delivery_failure(&original, 1024)?;
    let ServerFrame::Error { id, failure } = &fallback else {
        anyhow::bail!("delivery fallback was not an error");
    };
    ensure!(*id == Some(23));
    ensure!(failure.code == ConsoleErrorCode::OutcomeUnknown);
    ensure!(failure.outcome_unknown.as_deref() == Some(&unknown));
    ensure!(failure.unresolved_operations.as_deref() == Some(&unresolved));
    let encoded = encode_server_frame(&fallback, 1024)?;
    let decoded = pb::ConsoleFrame::decode(encoded.as_slice())?;
    let Some(pb::console_frame::Frame::Error(error)) = decoded.frame else {
        anyhow::bail!("delivery fallback did not survive encoding");
    };
    ensure!(
        error
            .outcome_unknown
            .context("unknown outcome")?
            .operation_ids
            == ["operation-a"]
    );
    ensure!(
        error
            .unresolved_operations
            .context("other effects")?
            .operation_ids
            == ["operation-b"]
    );
    Ok(())
}

#[test]
fn small_fallback_compacts_and_marks_omitted_effect_identities() -> anyhow::Result<()> {
    let mut unresolved = UnresolvedOperations::default();
    ensure!(unresolved.record("operation-30"));
    let original = ServerFrame::Error {
        id: Some(41),
        failure: ConsoleFailure {
            outcome_unknown: Some(Box::new(OutcomeUnknownDetail {
                operation_ids: vec!["operation-10".into(), "operation-20".into()],
                reason: "delivery_or_session_lost".into(),
            })),
            unresolved_operations: Some(Box::new(unresolved)),
            ..ConsoleFailure::new(ConsoleErrorCode::OutcomeUnknown, "x".repeat(2048))
        },
    };

    let full = delivery_failure(&original, 4096)?;
    let full_len = encode_server_frame(&full, 4096)?.len();
    let compact = delivery_failure(&original, full_len - 1)?;
    let ServerFrame::Error { failure, .. } = &compact else {
        anyhow::bail!("compact fallback was not an error");
    };
    ensure!(failure.outcome_unknown.is_none());
    ensure!(failure.code == ConsoleErrorCode::OutcomeUnknown);
    let all = failure
        .unresolved_operations
        .as_deref()
        .context("compact identities")?;
    ensure!(all.operation_ids == ["operation-10", "operation-20", "operation-30"]);
    ensure!(!all.identities_incomplete);
    let compact_len = encode_server_frame(&compact, full_len - 1)?.len();

    let truncated = delivery_failure(&original, compact_len - 1)?;
    let ServerFrame::Error { failure, .. } = &truncated else {
        anyhow::bail!("truncated fallback was not an error");
    };
    ensure!(failure.outcome_unknown.is_none());
    let partial = failure
        .unresolved_operations
        .as_deref()
        .context("partial identities")?;
    ensure!(partial.identities_incomplete);
    ensure!(partial.operation_ids.len() < 3);
    ensure!(partial.operation_ids == all.operation_ids[..partial.operation_ids.len()]);
    let encoded = encode_server_frame(&truncated, compact_len - 1)?;
    let decoded = pb::ConsoleFrame::decode(encoded.as_slice())?;
    let Some(pb::console_frame::Frame::Error(error)) = decoded.frame else {
        anyhow::bail!("truncated fallback did not survive encoding");
    };
    ensure!(error.request_id == Some(41));
    ensure!(
        error
            .unresolved_operations
            .context("wire incompleteness")?
            .identities_incomplete
    );

    let mut without_effects = truncated;
    let ServerFrame::Error { failure, .. } = &mut without_effects else {
        anyhow::bail!("fallback was not an error");
    };
    failure.unresolved_operations = None;
    let base_len = encode_server_frame(&without_effects, 4096)?.len();
    ensure!(delivery_failure(&original, base_len).is_err());
    Ok(())
}
