//! Bounded conversion and allocation for outbound Console frames.

use prost::Message as _;
use xolotl_console_protocol::pb;
use xolotl_proto::{
    MAX_VALUE_ENCODE_DEPTH, ValueEncodeError, ValueEncodeLimits, path_to_pb, value_to_pb_bounded,
    xolotl::v1 as pbv,
};
use xolotl_types::{Path, UnresolvedOperations, Value};

use crate::protocol::{
    ConsoleErrorCode, ConsoleEvent, ConsoleFailure, ExecutionReference, PrincipalSummary,
    ProtocolGreeting, ServerFrame, StateSourceSummary, TransportSecuritySummary,
};

const MAX_VALUE_NODES: usize = super::MAX_FRAME_VALUE_NODES;
const MAX_PATH_SEGMENTS: usize = 256;

/// Validate the canonical event envelope without allocating its encoded buffer.
pub(crate) fn validate_event(
    event: &ConsoleEvent,
    max_bytes: usize,
) -> Result<(), FrameEncodeError> {
    let frame = pb::ConsoleFrame {
        frame: Some(pb::console_frame::Frame::Event(pb::Event {
            stream: u64::MAX,
            event: Some(console_event_to_pb(
                event,
                ConversionBudget::new(max_bytes),
            )?),
        })),
    };
    let actual = frame.encoded_len();
    if actual > max_bytes {
        return Err(FrameEncodeError::FrameBytes {
            actual,
            limit: max_bytes,
        });
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
/// An outbound frame rejected before delivery.
pub enum FrameEncodeError {
    /// The value exceeds the bounded conversion's depth, nodes or inline bytes.
    #[error("outbound value exceeds conversion budget: {0}")]
    Value(#[from] ValueEncodeError),
    /// A metadata field exhausts the cumulative inline byte budget.
    #[error("outbound {field} exceeds cumulative inline byte limit {limit}")]
    FieldBytes {
        /// Name of the field being converted.
        field: &'static str,
        /// Maximum cumulative inline bytes.
        limit: usize,
    },
    /// A path has too many segments for bounded conversion.
    #[error("outbound path exceeds segment limit {limit}")]
    PathSegments {
        /// Maximum segment count.
        limit: usize,
    },
    /// The converted protobuf frame exceeds the encoded byte ceiling.
    #[error("outbound frame has {actual} bytes, exceeding limit {limit}")]
    FrameBytes {
        /// Exact encoded length of the frame.
        actual: usize,
        /// Maximum encoded size selected by the adapter.
        limit: usize,
    },
    /// Allocation of the bounded output buffer failed.
    #[error("outbound frame allocation failed: {0}")]
    Allocation(#[from] std::collections::TryReserveError),
    /// Protobuf serialization into the output buffer failed.
    #[error("outbound frame encoding failed: {0}")]
    Encode(#[from] prost::EncodeError),
}

/// Check conversion work before cloning payloads, then exact wire size before
/// allocating the encoded output. Limits apply to each frame independently.
pub fn encode_server_frame(
    frame: &ServerFrame,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, FrameEncodeError> {
    let frame = server_frame_to_pb(frame, max_frame_bytes)?;
    encode_bounded(&frame, max_frame_bytes)
}

pub(super) fn encode_error_frame(
    id: Option<u64>,
    failure: &crate::ConsoleFailure,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, FrameEncodeError> {
    let budget = ConversionBudget::new(max_frame_bytes);
    let frame = pb::ConsoleFrame {
        frame: Some(pb::console_frame::Frame::Error(failure_to_pb(
            failure, id, budget,
        )?)),
    };
    encode_bounded(&frame, max_frame_bytes)
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
        ServerFrame::HelloAccepted {
            metadata,
            transport,
        } => pb::console_frame::Frame::HelloAccepted(pb::HelloAccepted {
            metadata: Some(metadata_to_pb(metadata, &mut budget)?),
            transport: Some(transport_to_pb(transport, &mut budget)?),
        }),
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
                execution: result
                    .execution
                    .as_deref()
                    .map(|execution| execution_to_pb(execution, &mut budget))
                    .transpose()?,
                unresolved_operations: result
                    .unresolved_operations
                    .as_deref()
                    .map(|unresolved| {
                        unresolved_to_pb(unresolved, "result.unresolved_operations", &mut budget)
                    })
                    .transpose()?,
                output: result
                    .output
                    .as_ref()
                    .map(|value| budget.value(value))
                    .transpose()?,
                server_rev: result.server_rev,
                registry_rev: Some(result.registry_rev),
            }),
        }),
        ServerFrame::Event { stream, event } => pb::console_frame::Frame::Event(pb::Event {
            stream: *stream,
            event: Some(console_event_to_pb(event, budget)?),
        }),
        ServerFrame::Pong { nonce } => pb::console_frame::Frame::Pong(*nonce),
        ServerFrame::Error { id, failure } => {
            pb::console_frame::Frame::Error(failure_to_pb(failure, *id, budget)?)
        }
    };
    Ok(pb::ConsoleFrame { frame: Some(inner) })
}

fn execution_to_pb(
    execution: &ExecutionReference,
    budget: &mut ConversionBudget,
) -> Result<pb::ExecutionReference, FrameEncodeError> {
    budget.bytes("execution.process_id", execution.process_id.len())?;
    budget.bytes("execution.program_id", execution.program_id.len())?;
    if let Some(id) = &execution.execution_id {
        budget.bytes("execution.execution_id", id.len())?;
    }
    Ok(pb::ExecutionReference {
        execution_id: execution.execution_id.clone(),
        process_id: execution.process_id.clone(),
        program_id: execution.program_id.clone(),
    })
}

fn unresolved_to_pb(
    unresolved: &UnresolvedOperations,
    field: &'static str,
    budget: &mut ConversionBudget,
) -> Result<pbv::UnresolvedOperations, FrameEncodeError> {
    budget.bytes(field, 1 + unresolved.operation_ids.len())?;
    for operation_id in &unresolved.operation_ids {
        budget.bytes(field, operation_id.len())?;
    }
    Ok(pbv::UnresolvedOperations {
        operation_ids: unresolved.operation_ids.clone(),
        identities_incomplete: unresolved.identities_incomplete,
    })
}

fn failure_to_pb(
    failure: &ConsoleFailure,
    request_id: Option<u64>,
    mut budget: ConversionBudget,
) -> Result<pb::ConsoleError, FrameEncodeError> {
    budget.bytes("error.message", failure.message.len())?;
    Ok(pb::ConsoleError {
        code: error_code_to_pb(failure.code) as i32,
        message: failure.message.to_string(),
        request_id,
        retry_after_ms: failure.retry_after_ms,
        required_mfa_level: failure.required_mfa_level.map(u32::from),
        current_version: failure.current_version,
        current_registry_rev: failure.current_registry_rev,
        mfa: failure
            .mfa
            .as_deref()
            .map(|options| mfa_options_to_pb(options, &mut budget))
            .transpose()?,
        execution: failure
            .execution
            .as_deref()
            .map(|execution| execution_to_pb(execution, &mut budget))
            .transpose()?,
        outcome_unknown: failure
            .outcome_unknown
            .as_deref()
            .map(|detail| -> Result<_, FrameEncodeError> {
                budget.bytes(
                    "error.outcome_unknown.operation_ids",
                    detail.operation_ids.len(),
                )?;
                for operation_id in &detail.operation_ids {
                    budget.bytes("error.outcome_unknown.operation_ids", operation_id.len())?;
                }
                budget.bytes("error.outcome_unknown.reason", detail.reason.len())?;
                Ok(pb::OutcomeUnknownDetail {
                    operation_ids: detail.operation_ids.clone(),
                    reason: detail.reason.clone(),
                })
            })
            .transpose()?,
        unresolved_operations: failure
            .unresolved_operations
            .as_deref()
            .map(|unresolved| {
                unresolved_to_pb(unresolved, "error.unresolved_operations", &mut budget)
            })
            .transpose()?,
        runtime_completion: failure
            .runtime_completion
            .as_deref()
            .map(|value| budget.value(value).map(Box::new))
            .transpose()?,
    })
}

fn mfa_options_to_pb(
    options: &crate::mfa::MfaOptions,
    budget: &mut ConversionBudget,
) -> Result<pb::MfaOptions, FrameEncodeError> {
    // Charge each metadata node before allocating, including factors with empty
    // strings and present optional fields.
    budget.bytes("error.mfa", 1)?;
    budget.bytes("error.mfa.factors", options.factors.len())?;
    for factor in &options.factors {
        budget.bytes("error.mfa.factors.factor_id", factor.factor_id.len())?;
        budget.bytes("error.mfa.factors.provider_id", factor.provider_id.len())?;
        budget.bytes("error.mfa.factors.label", factor.label.len())?;
        if factor.last_used_at.is_some() {
            budget.bytes("error.mfa.factors.last_used_at", 1)?;
        }
    }
    Ok(pb::MfaOptions {
        factors: options
            .factors
            .iter()
            .map(|factor| pb::MfaFactor {
                factor_id: factor.factor_id.clone(),
                provider_id: factor.provider_id.clone(),
                label: factor.label.clone(),
                created_at: factor.created_at,
                last_used_at: factor.last_used_at,
                availability: match factor.availability {
                    crate::mfa::FactorAvailability::ProviderNotInstalled => {
                        pb::FactorAvailability::ProviderNotInstalled as i32
                    }
                    crate::mfa::FactorAvailability::AuthenticationDisabled => {
                        pb::FactorAvailability::AuthenticationDisabled as i32
                    }
                    crate::mfa::FactorAvailability::Available => {
                        pb::FactorAvailability::Available as i32
                    }
                },
            })
            .collect(),
        recovery_code_available: options.recovery_code_available,
    })
}

fn metadata_to_pb(
    metadata: &ProtocolGreeting,
    budget: &mut ConversionBudget,
) -> Result<pb::ProtocolGreeting, FrameEncodeError> {
    budget.bytes("metadata.server_name", metadata.server_name.len())?;
    budget.bytes("metadata.wire_encoding", metadata.encoding.len())?;
    Ok(pb::ProtocolGreeting {
        protocol_version: u32::from(metadata.protocol_version),
        server_name: metadata.server_name.clone(),
        wire_encoding: metadata.encoding.clone(),
        server_rev: metadata.server_rev,
        registry_rev: metadata.registry_rev,
        server_time_ms: metadata.server_time_ms,
    })
}

fn transport_to_pb(
    transport: &TransportSecuritySummary,
    budget: &mut ConversionBudget,
) -> Result<pb::TransportSecuritySummary, FrameEncodeError> {
    budget.bytes("transport.mode", transport.mode.len())?;
    for relaxation in &transport.relaxations {
        budget.bytes("transport.relaxations", relaxation.len())?;
    }
    Ok(pb::TransportSecuritySummary {
        mode: transport.mode.clone(),
        unsafe_transport: transport.unsafe_transport,
        relaxations: transport.relaxations.clone(),
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
    })
}

fn console_event_to_pb(
    event: &ConsoleEvent,
    mut budget: ConversionBudget,
) -> Result<pb::ConsoleEvent, FrameEncodeError> {
    let kind = match event {
        ConsoleEvent::StateSet {
            path,
            value,
            source,
        } => pb::console_event::Kind::StateSet(pb::StateSet {
            path: Some(budget.path(path)?),
            value: Some(budget.value(value)?),
            source: Some(state_source_to_pb(*source)),
        }),
        ConsoleEvent::StateAppend { path, item, source } => {
            pb::console_event::Kind::StateAppend(pb::StateAppend {
                path: Some(budget.path(path)?),
                item: Some(budget.value(item)?),
                source: Some(state_source_to_pb(*source)),
            })
        }
        ConsoleEvent::StateDropPrefixAppend {
            path,
            removed,
            item,
            source,
        } => pb::console_event::Kind::StateDropPrefixAppend(pb::StateDropPrefixAppend {
            path: Some(budget.path(path)?),
            removed: *removed,
            item: Some(budget.value(item)?),
            source: Some(state_source_to_pb(*source)),
        }),
        ConsoleEvent::StateDelete { path, source } => {
            pb::console_event::Kind::StateDelete(pb::StateDelete {
                path: Some(budget.path(path)?),
                source: Some(state_source_to_pb(*source)),
            })
        }
        ConsoleEvent::Audit { fact } => pb::console_event::Kind::Fact(pb::FactEvent {
            fact: Some(budget.value(fact)?),
        }),
        ConsoleEvent::Runtime { event } => pb::console_event::Kind::Runtime(pb::RuntimeEvent {
            event: Some(budget.value(event)?),
        }),
        ConsoleEvent::SubscriptionClosed { reason, failure } => {
            budget.bytes("closed.reason", reason.len())?;
            pb::console_event::Kind::Closed(pb::SubscriptionClosed {
                reason: reason.clone(),
                failure: failure
                    .as_deref()
                    .map(|failure| failure_to_pb(failure, None, budget))
                    .transpose()?,
            })
        }
    };
    Ok(pb::ConsoleEvent { kind: Some(kind) })
}

fn state_source_to_pb(source: StateSourceSummary) -> pb::StateSourceSummary {
    pb::StateSourceSummary {
        tainted: source.tainted,
        author_constant: source.author_constant,
        model_output: source.model_output,
        inbound: source.inbound,
        fetched: source.fetched,
        protected: source.protected,
    }
}

fn error_code_to_pb(code: ConsoleErrorCode) -> pb::ConsoleErrorCode {
    match code {
        ConsoleErrorCode::BadFrame | ConsoleErrorCode::BadRequest => {
            pb::ConsoleErrorCode::ValidationFailed
        }
        ConsoleErrorCode::NotAuthenticated => pb::ConsoleErrorCode::Unauthenticated,
        ConsoleErrorCode::Forbidden => pb::ConsoleErrorCode::Forbidden,
        ConsoleErrorCode::StepUpRequired => pb::ConsoleErrorCode::StepUpRequired,
        ConsoleErrorCode::RegistryChanged => pb::ConsoleErrorCode::RegistryChanged,
        ConsoleErrorCode::AdmissionRejected => pb::ConsoleErrorCode::AdmissionRejected,
        ConsoleErrorCode::Conflict => pb::ConsoleErrorCode::VersionConflict,
        ConsoleErrorCode::RateLimited => pb::ConsoleErrorCode::RateLimited,
        ConsoleErrorCode::OutcomeUnknown => pb::ConsoleErrorCode::OutcomeUnknown,
        ConsoleErrorCode::Internal => pb::ConsoleErrorCode::Internal,
    }
}

#[cfg(test)]
mod tests;
