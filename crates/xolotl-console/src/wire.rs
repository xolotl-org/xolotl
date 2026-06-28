//! Protobuf `ConsoleFrame` conversion helpers.

use prost::Message as _;
use xolotl_console_protocol::{SERVER_NAME, WIRE_ENCODING, pb};
use xolotl_proto::xolotl::v1 as pbv;
use xolotl_proto::{path_to_pb, value_from_pb_checked, value_to_pb};
use xolotl_types::Path;

use crate::protocol::{
    ActionCall, ClientFrame, ClientHello, ConsoleErrorCode, ConsoleEvent, PrincipalSummary,
    ProtocolMetadata, ServerFrame, StreamCall,
};

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

/// Encode a server-side frame into binary protobuf wire bytes.
pub(crate) fn encode_server_frame(frame: &ServerFrame) -> Vec<u8> {
    server_frame_to_pb(frame).encode_to_vec()
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
        None => Ok(xolotl_types::Value::Null),
    }
}

fn server_frame_to_pb(frame: &ServerFrame) -> pb::ConsoleFrame {
    let inner = match frame {
        ServerFrame::HelloAccepted { metadata } => {
            pb::console_frame::Frame::HelloAccepted(pb::HelloAccepted {
                metadata: Some(metadata_to_pb(metadata)),
            })
        }
        ServerFrame::Authenticated {
            principal,
            metadata,
        } => pb::console_frame::Frame::Authenticated(pb::Authenticated {
            principal: Some(principal_to_pb(principal)),
            metadata: Some(metadata_to_pb(metadata)),
        }),
        ServerFrame::Reply { id, result } => pb::console_frame::Frame::Reply(pb::Reply {
            id: *id,
            result: Some(pb::ActionResult {
                output: result.output.as_ref().map(value_to_pb),
                server_rev: result.server_rev,
                registry_rev: None,
            }),
        }),
        ServerFrame::Event { stream, event } => pb::console_frame::Frame::Event(pb::Event {
            stream: *stream,
            event: Some(console_event_to_pb(event)),
        }),
        ServerFrame::Pong { nonce } => pb::console_frame::Frame::Pong(*nonce),
        ServerFrame::Error { id, code, message } => {
            pb::console_frame::Frame::Error(pb::ConsoleError {
                code: error_code_to_pb(*code) as i32,
                message: message.clone(),
                request_id: *id,
                retry_after_ms: None,
                required_mfa_level: None,
                current_version: None,
                current_registry_rev: None,
                correlation_id: None,
            })
        }
    };
    pb::ConsoleFrame { frame: Some(inner) }
}

fn metadata_to_pb(metadata: &ProtocolMetadata) -> pb::ProtocolMetadata {
    pb::ProtocolMetadata {
        protocol_version: u32::from(metadata.protocol_version),
        server_name: SERVER_NAME.into(),
        wire_encoding: WIRE_ENCODING.into(),
        server_rev: metadata.server_rev,
        registry_rev: metadata.registry_rev,
        server_time_ms: u64::try_from(xolotl_kernel::now_millis()).unwrap_or(0),
        capabilities: Vec::new(),
    }
}

fn principal_to_pb(principal: &PrincipalSummary) -> pb::PrincipalSummary {
    pb::PrincipalSummary {
        username: principal.username.clone(),
        identity_path: principal.identity_path.clone(),
        mfa_level: u32::from(principal.mfa_level),
        grants: Vec::new(),
    }
}

fn console_event_to_pb(event: &ConsoleEvent) -> pb::ConsoleEvent {
    let kind = match event {
        ConsoleEvent::StateSet { path, value } => pb::console_event::Kind::StateSet(pb::StateSet {
            path: Some(path_to_pb_lossy(path)),
            value: Some(value_to_pb(value)),
        }),
        ConsoleEvent::StateAppend { path, item } => {
            pb::console_event::Kind::StateAppend(pb::StateAppend {
                path: Some(path_to_pb_lossy(path)),
                item: Some(value_to_pb(item)),
            })
        }
        ConsoleEvent::StateDelete { path } => {
            pb::console_event::Kind::StateDelete(pb::StateDelete {
                path: Some(path_to_pb_lossy(path)),
            })
        }
        ConsoleEvent::Audit { fact } => pb::console_event::Kind::Fact(pb::FactEvent {
            fact: Some(value_to_pb(fact)),
        }),
        ConsoleEvent::SubscriptionClosed { reason } => {
            pb::console_event::Kind::Closed(pb::SubscriptionClosed {
                reason: reason.clone(),
                last_rev: None,
            })
        }
    };
    pb::ConsoleEvent {
        kind: Some(kind),
        state_rev: 0,
        fact_cursor: 0,
        coalesced: false,
    }
}

fn path_to_pb_lossy(raw: &str) -> pbv::Path {
    match Path::parse(raw) {
        Ok(path) => path_to_pb(&path),
        Err(_) => pbv::Path {
            cluster: None,
            scheme: "state".into(),
            segments: vec![raw.to_string()],
        },
    }
}

fn error_code_to_pb(code: ConsoleErrorCode) -> pb::ConsoleErrorCode {
    match code {
        ConsoleErrorCode::BadFrame | ConsoleErrorCode::BadRequest => {
            pb::ConsoleErrorCode::ValidationFailed
        }
        ConsoleErrorCode::NotAuthenticated => pb::ConsoleErrorCode::Unauthenticated,
        ConsoleErrorCode::Unauthorized | ConsoleErrorCode::Forbidden => {
            pb::ConsoleErrorCode::Forbidden
        }
        ConsoleErrorCode::Conflict => pb::ConsoleErrorCode::VersionConflict,
        ConsoleErrorCode::RateLimited => pb::ConsoleErrorCode::RateLimited,
        ConsoleErrorCode::Internal => pb::ConsoleErrorCode::Internal,
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
