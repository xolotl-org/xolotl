//! Protobuf `ConsoleFrame` conversion helpers.

mod encode;

pub(crate) use encode::{FrameEncodeError, encode_server_frame};

use prost::Message as _;
use xolotl_console_protocol::pb;
use xolotl_proto::value_from_pb_checked;
#[cfg(test)]
use xolotl_proto::value_to_pb;
use xolotl_proto::xolotl::v1 as pbv;

use crate::protocol::{ActionCall, ClientFrame, ClientHello, StreamCall};

/// Decode a binary protobuf `ConsoleFrame` into a server-side client frame.
pub(crate) fn decode_client_frame(bytes: &[u8]) -> Result<ClientFrame, String> {
    let frame = pb::ConsoleFrame::decode(bytes).map_err(|e| format!("bad protobuf frame: {e}"))?;
    let frame = frame
        .frame
        .ok_or_else(|| "empty console frame".to_string())?;
    match frame {
        pb::console_frame::Frame::Hello(hello) => Ok(ClientFrame::Hello {
            hello: ClientHello {
                protocol_version: u16::try_from(hello.protocol_version).unwrap_or(u16::MAX),
                client_name: non_empty(hello.client_name),
                accepted_encodings: hello.accepted_encodings,
            },
        }),
        pb::console_frame::Frame::AuthToken(token) => {
            let token = String::from_utf8(token)
                .map_err(|error| format!("auth token is not utf-8: {error}"))?;
            Ok(ClientFrame::Auth { token })
        }
        pb::console_frame::Frame::Call(call) => Ok(ClientFrame::Call {
            id: call.id,
            call: action_call_from_pb(call)?,
        }),
        pb::console_frame::Frame::Subscribe(sub) => Ok(ClientFrame::Subscribe {
            id: sub.id,
            stream: stream_call_from_pb(sub)?,
        }),
        pb::console_frame::Frame::Unsubscribe(id) => Ok(ClientFrame::Unsubscribe { id }),
        pb::console_frame::Frame::Ping(nonce) => Ok(ClientFrame::Ping { nonce }),
        _ => Err("client sent a server-only console frame".into()),
    }
}

fn action_call_from_pb(call: pb::ActionCall) -> Result<ActionCall, String> {
    Ok(ActionCall {
        action: call.action,
        action_code: call.action_code,
        input: input_value(call.input)?,
        scope: call.scope,
        justification: call.justification,
        ttl_ms: call.ttl_ms,
        registry_rev: call.registry_rev,
        idempotency_key: call.idempotency_key,
    })
}

fn stream_call_from_pb(sub: pb::StreamCall) -> Result<StreamCall, String> {
    Ok(StreamCall {
        stream: sub.stream,
        input: input_value(sub.input)?,
        scope: sub.scope,
        justification: sub.justification,
        ttl_ms: sub.ttl_ms,
        since_rev: sub.since_rev,
        max_batch: sub.max_batch,
    })
}

fn input_value(value: Option<pbv::Value>) -> Result<xolotl_types::Value, String> {
    match value {
        Some(value) => {
            value_from_pb_checked(&value).map_err(|e| format!("invalid input value: {e}"))
        }
        None => Ok(xolotl_types::Value::null()),
    }
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// Re-encode a client frame to protobuf wire bytes (test/diagnostic helper).
#[cfg(test)]
pub(crate) fn encode_client_frame(frame: &ClientFrame) -> Vec<u8> {
    let inner = match frame {
        ClientFrame::Hello { hello } => pb::console_frame::Frame::Hello(pb::ClientHello {
            protocol_version: u32::from(hello.protocol_version),
            client_name: hello.client_name.clone().unwrap_or_default(),
            accepted_encodings: hello.accepted_encodings.clone(),
            registry_rev: None,
        }),
        ClientFrame::Auth { token } => {
            pb::console_frame::Frame::AuthToken(token.clone().into_bytes())
        }
        ClientFrame::Call { id, call } => pb::console_frame::Frame::Call(pb::ActionCall {
            id: *id,
            action: call.action.clone(),
            action_code: call.action_code,
            input: Some(value_to_pb(&call.input)),
            scope: call.scope.clone(),
            justification: call.justification.clone(),
            ttl_ms: call.ttl_ms,
            registry_rev: call.registry_rev,
            idempotency_key: call.idempotency_key.clone(),
        }),
        ClientFrame::Subscribe { id, stream } => {
            pb::console_frame::Frame::Subscribe(pb::StreamCall {
                id: *id,
                stream: stream.stream.clone(),
                input: Some(value_to_pb(&stream.input)),
                scope: stream.scope.clone(),
                justification: stream.justification.clone(),
                ttl_ms: stream.ttl_ms,
                since_rev: stream.since_rev,
                max_batch: stream.max_batch,
            })
        }
        ClientFrame::Unsubscribe { id } => pb::console_frame::Frame::Unsubscribe(*id),
        ClientFrame::Ping { nonce } => pb::console_frame::Frame::Ping(*nonce),
    };
    pb::ConsoleFrame { frame: Some(inner) }.encode_to_vec()
}

/// Decode a server frame from protobuf wire bytes (test/diagnostic helper).
#[cfg(test)]
pub(crate) fn decode_server_frame(bytes: &[u8]) -> Result<pb::ConsoleFrame, String> {
    pb::ConsoleFrame::decode(bytes).map_err(|e| format!("bad protobuf frame: {e}"))
}
