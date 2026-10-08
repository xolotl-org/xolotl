//! Bounded protobuf conversion for Console adapters.
//!
//! These codecs are available without the `http` feature, so custom transports
//! can reuse the same protocol conversion and delivery-failure semantics. The
//! caller selects a byte ceiling for each frame. Encoding also bounds value
//! depth and node count before cloning payloads.

mod encode;
mod preflight;

pub(crate) use encode::validate_event;
pub use encode::{FrameEncodeError, encode_server_frame};

use prost::Message as _;
use xolotl_console_protocol::pb;
use xolotl_proto::value_from_pb;
#[cfg(all(test, feature = "http"))]
use xolotl_proto::value_to_pb;
use xolotl_proto::xolotl::v1 as pbv;
use xolotl_types::UnresolvedOperations;

use crate::protocol::{ActionCall, ClientFrame, ClientHello, StreamCall};

/// v1 protobuf Value conversion-work ceiling, independent of the service's
/// runtime input budget and the Kernel's process budget.
const MAX_FRAME_VALUE_NODES: usize = 16_384;

/// Preserve execution and reconciliation identities when a frame cannot be encoded.
///
/// The fallback must fit the same byte ceiling as the original frame. An unknown
/// outcome is never published with only a prefix of its identities: when its
/// detail does not fit, its identities move to the unresolved sidecar, which can
/// explicitly report incomplete retention. If even the execution or
/// incomplete-identity marker cannot be delivered, return an encoding error.
pub fn delivery_failure(
    frame: &crate::ServerFrame,
    max_frame_bytes: usize,
) -> Result<crate::ServerFrame, FrameEncodeError> {
    use crate::{ConsoleErrorCode, ConsoleFailure, ServerFrame};
    let mut failure = ConsoleFailure::new(
        ConsoleErrorCode::Internal,
        "console response exceeds encoding limits; effects may have occurred".into(),
    );
    let id = match frame {
        ServerFrame::Reply { id, result } => {
            failure.execution = result.execution.clone();
            failure.unresolved_operations = result.unresolved_operations.clone();
            Some(*id)
        }
        ServerFrame::Error {
            id,
            failure: original,
        } => {
            if original.code == ConsoleErrorCode::OutcomeUnknown {
                failure.code = ConsoleErrorCode::OutcomeUnknown;
            }
            failure.execution = original.execution.clone();
            failure.outcome_unknown = original.outcome_unknown.clone();
            failure.unresolved_operations = original.unresolved_operations.clone();
            *id
        }
        _ => None,
    };
    if fits_failure(id, &failure, max_frame_bytes)? {
        return Ok(ServerFrame::Error { id, failure });
    }

    // These identities come from the original frame, not from an untrusted
    // diagnostic. Retain them before removing the oversized optional detail.
    let mut unresolved = UnresolvedOperations::default();
    if let Some(attached) = &failure.unresolved_operations {
        unresolved.merge(attached);
    }
    if let Some(unknown) = &failure.outcome_unknown {
        if unknown.operation_ids.is_empty() {
            unresolved.identities_incomplete = true;
        }
        for operation_id in &unknown.operation_ids {
            unresolved.record(operation_id);
        }
    }
    failure.outcome_unknown = None;
    failure.unresolved_operations = None;

    // Receipt and execution facts are indivisible. Never make the frame fit by
    // silently omitting either one.
    encode::encode_error_frame(id, &failure, max_frame_bytes)?;
    if unresolved.is_empty() {
        return Ok(ServerFrame::Error { id, failure });
    }

    failure.unresolved_operations = Some(Box::new(unresolved));
    if fits_failure(id, &failure, max_frame_bytes)? {
        return Ok(ServerFrame::Error { id, failure });
    }

    // The sidecar is the only v1 field that can say some identities were lost.
    // Find the largest prefix that fits, keeping the original sorted order.
    let sidecar = failure
        .unresolved_operations
        .get_or_insert_with(|| Box::new(UnresolvedOperations::default()));
    let identities = std::mem::take(&mut sidecar.operation_ids);
    sidecar.identities_incomplete = true;
    encode::encode_error_frame(id, &failure, max_frame_bytes)?;

    let mut fitting = 0;
    let mut too_many = identities.len();
    while fitting < too_many {
        let candidate = fitting + (too_many - fitting).div_ceil(2);
        failure
            .unresolved_operations
            .get_or_insert_with(|| Box::new(UnresolvedOperations::default()))
            .operation_ids = identities[..candidate].to_vec();
        if fits_failure(id, &failure, max_frame_bytes)? {
            fitting = candidate;
        } else {
            too_many = candidate - 1;
        }
    }
    failure
        .unresolved_operations
        .get_or_insert_with(|| Box::new(UnresolvedOperations::default()))
        .operation_ids = identities[..fitting].to_vec();
    Ok(ServerFrame::Error { id, failure })
}

fn fits_failure(
    id: Option<u64>,
    failure: &crate::ConsoleFailure,
    max_frame_bytes: usize,
) -> Result<bool, FrameEncodeError> {
    match encode::encode_error_frame(id, failure, max_frame_bytes) {
        Ok(_) => Ok(true),
        Err(FrameEncodeError::FieldBytes { .. } | FrameEncodeError::FrameBytes { .. }) => Ok(false),
        Err(error) => Err(error),
    }
}

/// A rejected inbound frame. Decoding does not authenticate or dispatch it.
#[derive(Debug, thiserror::Error)]
pub enum FrameDecodeError {
    /// The supplied buffer exceeds the caller's ceiling, checked before decoding.
    #[error("inbound frame has {actual} bytes, exceeding limit {limit}")]
    FrameBytes {
        /// Size of the supplied encoded buffer.
        actual: usize,
        /// Maximum encoded size selected by the adapter.
        limit: usize,
    },
    /// The buffer is not a valid protobuf Console frame.
    #[error("bad protobuf frame: {0}")]
    Protobuf(#[from] prost::DecodeError),
    /// The envelope contains no frame payload.
    #[error("empty console frame")]
    Empty,
    /// A client attempted to send a server response.
    #[error("client sent a server-only console frame")]
    ServerOnly,
    /// Authentication token bytes must represent UTF-8 text.
    #[error("auth token is not utf-8: {0}")]
    AuthToken(#[from] std::string::FromUtf8Error),
    /// A malformed field prevents bounded protobuf preflight.
    #[error("malformed protobuf field framing")]
    MalformedWire,
    /// The frame contains too many input Value nodes, including discarded fields.
    #[error("inbound value node limit exceeded: {limit}")]
    ValueNodes {
        /// Maximum input Value nodes across the frame.
        limit: usize,
    },
    /// An input Value exceeds the wire-safe nesting depth.
    #[error("inbound value depth limit exceeded: {limit}")]
    ValueDepth {
        /// Maximum input Value nesting depth.
        limit: usize,
    },
    /// An input value violates the protocol's field or value contract.
    #[error("invalid input value: {0}")]
    Value(#[from] xolotl_proto::ConvertError),
}

/// Decode one client frame, checking its byte ceiling before protobuf parsing.
/// A zero-allocation preflight bounds input Value nodes and nesting before
/// Prost allocates decoded messages. Protobuf parsing applies Prost's recursion
/// limit; decoded input values also pass the shared decoder's validity checks.
/// The adapter still owns framing, authentication and service admission.
pub fn decode_client_frame(
    bytes: &[u8],
    max_frame_bytes: usize,
) -> Result<ClientFrame, FrameDecodeError> {
    if bytes.len() > max_frame_bytes {
        return Err(FrameDecodeError::FrameBytes {
            actual: bytes.len(),
            limit: max_frame_bytes,
        });
    }
    preflight::scan_client_frame(bytes)?;
    let frame = pb::ConsoleFrame::decode(bytes)?;
    let frame = frame.frame.ok_or(FrameDecodeError::Empty)?;
    match frame {
        pb::console_frame::Frame::Hello(hello) => Ok(ClientFrame::Hello {
            hello: ClientHello {
                protocol_version: u16::try_from(hello.protocol_version).unwrap_or(u16::MAX),
                client_name: non_empty(hello.client_name),
            },
        }),
        pb::console_frame::Frame::AuthToken(token) => {
            let token = String::from_utf8(token)?;
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
        _ => Err(FrameDecodeError::ServerOnly),
    }
}

fn action_call_from_pb(call: pb::ActionCall) -> Result<ActionCall, FrameDecodeError> {
    Ok(ActionCall {
        action: call.action,
        input: input_value(call.input)?,
        scope: call.scope,
        justification: call.justification,
        ttl_ms: call.ttl_ms,
        registry_rev: call.registry_rev,
    })
}

fn stream_call_from_pb(sub: pb::StreamCall) -> Result<StreamCall, FrameDecodeError> {
    Ok(StreamCall {
        stream: sub.stream,
        input: input_value(sub.input)?,
        scope: sub.scope,
        justification: sub.justification,
        ttl_ms: sub.ttl_ms,
        registry_rev: sub.registry_rev,
    })
}

fn input_value(value: Option<pbv::Value>) -> Result<xolotl_types::Value, FrameDecodeError> {
    match value {
        Some(value) => Ok(value_from_pb(&value)?),
        None => Ok(xolotl_types::Value::null()),
    }
}

fn non_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

/// Re-encode a client frame to protobuf wire bytes (test/diagnostic helper).
#[cfg(all(test, feature = "http"))]
pub(crate) fn encode_client_frame(frame: &ClientFrame) -> Vec<u8> {
    let inner = match frame {
        ClientFrame::Hello { hello } => pb::console_frame::Frame::Hello(pb::ClientHello {
            protocol_version: u32::from(hello.protocol_version),
            client_name: hello.client_name.clone().unwrap_or_default(),
        }),
        ClientFrame::Auth { token } => {
            pb::console_frame::Frame::AuthToken(token.clone().into_bytes())
        }
        ClientFrame::Call { id, call } => pb::console_frame::Frame::Call(pb::ActionCall {
            id: *id,
            action: call.action.clone(),
            input: Some(value_to_pb(&call.input)),
            scope: call.scope.clone(),
            justification: call.justification.clone(),
            ttl_ms: call.ttl_ms,
            registry_rev: call.registry_rev,
        }),
        ClientFrame::Subscribe { id, stream } => {
            pb::console_frame::Frame::Subscribe(pb::StreamCall {
                id: *id,
                stream: stream.stream.clone(),
                input: Some(value_to_pb(&stream.input)),
                scope: stream.scope.clone(),
                justification: stream.justification.clone(),
                ttl_ms: stream.ttl_ms,
                registry_rev: stream.registry_rev,
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
