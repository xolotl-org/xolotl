//! Bounded conversion and allocation for outbound Console frames.

use prost::Message as _;
use xolotl_console_protocol::{SERVER_NAME, WIRE_ENCODING, pb};
use xolotl_proto::{
    MAX_VALUE_ENCODE_DEPTH, ValueEncodeError, ValueEncodeLimits, path_to_pb, value_to_pb_bounded,
    xolotl::v1 as pbv,
};
use xolotl_types::{Path, Value};

use crate::protocol::{
    ConsoleErrorCode, ConsoleEvent, PrincipalSummary, ProtocolMetadata, ServerFrame,
};
use crate::state::HARD_MAX_WS_FRAME_BYTES;

const MAX_VALUE_NODES: usize = 16_384;
const MAX_PATH_SEGMENTS: usize = 256;

#[derive(Debug, thiserror::Error)]
pub(crate) enum FrameEncodeError {
    #[error("outbound value exceeds conversion budget: {0}")]
    Value(#[from] ValueEncodeError),
    #[error("outbound {field} exceeds cumulative inline byte limit {limit}")]
    FieldBytes { field: &'static str, limit: usize },
    #[error("outbound path exceeds segment limit {limit}")]
    PathSegments { limit: usize },
    #[error("outbound frame has {actual} bytes, exceeding limit {limit}")]
    FrameBytes { actual: usize, limit: usize },
    #[error("outbound frame allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    #[error("outbound frame encoding failed: {0}")]
    Encode(#[from] prost::EncodeError),
}

/// Check conversion work before cloning payloads, then exact wire size before
/// allocating the encoded output. Limits apply to each frame independently.
pub(crate) fn encode_server_frame(
    frame: &ServerFrame,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, FrameEncodeError> {
    let limit = max_frame_bytes.min(HARD_MAX_WS_FRAME_BYTES);
    let frame = server_frame_to_pb(frame, limit)?;
    encode_bounded(&frame, limit)
}

fn encode_bounded(frame: &pb::ConsoleFrame, limit: usize) -> Result<Vec<u8>, FrameEncodeError> {
    let actual = frame.encoded_len();
    if actual > limit {
        return Err(FrameEncodeError::FrameBytes { actual, limit });
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(actual)?;
    frame.encode(&mut bytes)?;
    Ok(bytes)
}

struct ConversionBudget {
    limit: usize,
    remaining: usize,
}

impl ConversionBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            remaining: limit,
        }
    }

    fn bytes(&mut self, field: &'static str, bytes: usize) -> Result<(), FrameEncodeError> {
        self.remaining = self
            .remaining
            .checked_sub(bytes)
            .ok_or(FrameEncodeError::FieldBytes {
                field,
                limit: self.limit,
            })?;
        Ok(())
    }

    fn path(&mut self, path: &Path) -> Result<pbv::Path, FrameEncodeError> {
        if path.segments().len() > MAX_PATH_SEGMENTS {
            return Err(FrameEncodeError::PathSegments {
                limit: MAX_PATH_SEGMENTS,
            });
        }
        self.bytes("path.scheme", path.scheme().len())?;
        if let Some(cluster) = path.cluster() {
            self.bytes("path.cluster", cluster.len())?;
        }
        for segment in path.segments() {
            self.bytes("path.segments", segment.len())?;
        }
        Ok(path_to_pb(path))
    }

    // Each Console frame contains at most one Value. Consuming the budget
    // prevents a later payload from silently reusing its conversion allowance.
    fn value(self, value: &Value) -> Result<pbv::Value, FrameEncodeError> {
        Ok(value_to_pb_bounded(
            value,
            ValueEncodeLimits {
                max_nodes: MAX_VALUE_NODES.min(self.limit),
                max_depth: MAX_VALUE_ENCODE_DEPTH,
                max_inline_bytes: self.remaining,
            },
        )?)
    }
}

fn server_frame_to_pb(
    frame: &ServerFrame,
    limit: usize,
) -> Result<pb::ConsoleFrame, FrameEncodeError> {
    let mut budget = ConversionBudget::new(limit);
    let inner = match frame {
        ServerFrame::HelloAccepted { metadata } => {
            pb::console_frame::Frame::HelloAccepted(pb::HelloAccepted {
                metadata: Some(metadata_to_pb(metadata, &mut budget)?),
            })
        }
        ServerFrame::Authenticated {
            principal,
            metadata,
        } => pb::console_frame::Frame::Authenticated(pb::Authenticated {
            principal: Some(principal_to_pb(principal, &mut budget)?),
            metadata: Some(metadata_to_pb(metadata, &mut budget)?),
        }),
        ServerFrame::Reply { id, result } => pb::console_frame::Frame::Reply(pb::Reply {
            id: *id,
            result: Some(pb::ActionResult {
                output: result
                    .output
                    .as_ref()
                    .map(|value| budget.value(value))
                    .transpose()?,
                server_rev: result.server_rev,
                registry_rev: None,
            }),
        }),
        ServerFrame::Event { stream, event } => pb::console_frame::Frame::Event(pb::Event {
            stream: *stream,
            event: Some(console_event_to_pb(event, budget)?),
        }),
        ServerFrame::Pong { nonce } => pb::console_frame::Frame::Pong(*nonce),
        ServerFrame::Error { id, code, message } => {
            budget.bytes("error.message", message.len())?;
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
    Ok(pb::ConsoleFrame { frame: Some(inner) })
}

fn metadata_to_pb(
    metadata: &ProtocolMetadata,
    budget: &mut ConversionBudget,
) -> Result<pb::ProtocolMetadata, FrameEncodeError> {
    budget.bytes("metadata.server_name", SERVER_NAME.len())?;
    budget.bytes("metadata.wire_encoding", WIRE_ENCODING.len())?;
    Ok(pb::ProtocolMetadata {
        protocol_version: u32::from(metadata.protocol_version),
        server_name: SERVER_NAME.into(),
        wire_encoding: WIRE_ENCODING.into(),
        server_rev: metadata.server_rev,
        registry_rev: metadata.registry_rev,
        server_time_ms: u64::try_from(xolotl_kernel::now_millis()).unwrap_or(0),
        capabilities: Vec::new(),
    })
}

fn principal_to_pb(
    principal: &PrincipalSummary,
    budget: &mut ConversionBudget,
) -> Result<pb::PrincipalSummary, FrameEncodeError> {
    budget.bytes("principal.username", principal.username.len())?;
    budget.bytes("principal.identity_path", principal.identity_path.len())?;
    Ok(pb::PrincipalSummary {
        username: principal.username.clone(),
        identity_path: principal.identity_path.clone(),
        mfa_level: u32::from(principal.mfa_level),
        grants: Vec::new(),
    })
}

fn console_event_to_pb(
    event: &ConsoleEvent,
    mut budget: ConversionBudget,
) -> Result<pb::ConsoleEvent, FrameEncodeError> {
    let kind = match event {
        ConsoleEvent::StateSet { path, value } => pb::console_event::Kind::StateSet(pb::StateSet {
            path: Some(budget.path(path)?),
            value: Some(budget.value(value)?),
        }),
        ConsoleEvent::StateAppend { path, item } => {
            pb::console_event::Kind::StateAppend(pb::StateAppend {
                path: Some(budget.path(path)?),
                item: Some(budget.value(item)?),
            })
        }
        ConsoleEvent::StateDelete { path } => {
            pb::console_event::Kind::StateDelete(pb::StateDelete {
                path: Some(budget.path(path)?),
            })
        }
        ConsoleEvent::Audit { fact } => pb::console_event::Kind::Fact(pb::FactEvent {
            fact: Some(budget.value(fact)?),
        }),
        ConsoleEvent::SubscriptionClosed { reason } => {
            budget.bytes("closed.reason", reason.len())?;
            pb::console_event::Kind::Closed(pb::SubscriptionClosed {
                reason: reason.clone(),
                last_rev: None,
            })
        }
    };
    Ok(pb::ConsoleEvent {
        kind: Some(kind),
        state_rev: 0,
        fact_cursor: 0,
        coalesced: false,
    })
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

#[cfg(test)]
mod tests;
