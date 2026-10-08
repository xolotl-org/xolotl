//! External Provider and Source session admission API.
//!
//! Transport adapters and the daemon use this module to share one session
//! state machine. Application submissions enter through [`GatewaySubmission`](crate::GatewaySubmission).
use thiserror::Error;
use xolotl_proto::xolotl::v1::external as external_pb;
use xolotl_proto::{
    command_result_from_pb, control_frame_from_pb, inbound_event_from_pb, invoke_result_from_pb,
    source_stream_request_from_pb,
};
use xolotl_types::external::{
    CommandResult, ControlFrame, InboundEvent, InvokeResult, Role as ExternalRole,
    SessionContext as ExternalSessionContext, SourceStreamRequest,
};

mod lifecycle;
mod secure_envelope;
mod session;

pub use lifecycle::{ExternalCancellationSender, ExternalSessionScope};

pub use secure_envelope::{
    CLIENT_TO_DAEMON, DAEMON_TO_CLIENT, DEFAULT_SECURE_ENVELOPE_REPLAY_WINDOW, EnvelopeAad,
    EnvelopeError, ExternalCredential, SecureEnvelope, SecureEnvelopeEpochGate,
    SecureEnvelopeReplayWindow,
};
pub use session::{
    DEFAULT_SOURCE_COMMAND_LIMIT, EndpointSession, ExternalSessionHandler, ExternalSessionOutbound,
    ProviderInvocationError, ProviderInvocationRegister, ProviderInvocationRegistry,
    ProviderInvocationResolve, SessionPhase, SessionReject, SourceCommandError,
    SourceCommandMaintenanceReport, SourceCommandRegister, SourceCommandRegistry,
    SourceCommandResolve, SourceIngest, SourceIngestError, external_session_transcript_hash,
    ingest_source_event, operate_source_stream, validate_json_schema,
};

/// Error returned while validating external protocol frames.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExternalFrameError {
    /// The frame has no active oneof variant.
    #[error("empty external frame")]
    EmptyFrame,
    /// The control frame has no active kind.
    #[error("bad external control frame")]
    BadControlFrame,
    /// The secure envelope is malformed.
    #[error("bad secure envelope")]
    BadSecureEnvelope,
    /// A protobuf frame payload could not be converted into the runtime type.
    #[error("bad external frame payload")]
    BadFramePayload,
    /// The frame is not accepted from an external endpoint in this direction.
    #[error("external frame direction rejected")]
    ExternalFrameDirectionRejected,
    /// Business frames must be authenticated before conversion or dispatch.
    #[error("plaintext external business frame rejected")]
    PlaintextBusinessRejected,
    /// The frame is not accepted for the ready external role.
    #[error("external role frame rejected")]
    ExternalRoleFrameRejected,
    /// The secure envelope does not match the ready session context.
    #[error("secure envelope context rejected")]
    SecureEnvelopeContextRejected,
    /// The secure envelope frame type does not match its payload frame.
    #[error("secure envelope frame type mismatch")]
    SecureEnvelopeFrameTypeMismatch,
    /// The secure envelope payload is not accepted as an inbound frame.
    #[error("secure envelope payload rejected")]
    SecureEnvelopePayloadRejected,
}

/// Runtime frame received from an external Provider or Source after handshake.
#[derive(Clone, Debug, PartialEq)]
pub enum ExternalInboundFrame {
    /// Source-to-daemon event frame.
    InboundEvent(InboundEvent),
    /// Source-to-daemon ordered-stream lifecycle request.
    SourceStreamRequest(SourceStreamRequest),
    /// Source-to-daemon command result frame.
    CommandResult(CommandResult),
    /// Provider-to-daemon invocation result frame.
    InvokeResult(InvokeResult),
    /// Provider/Source-to-daemon control frame.
    Control(ControlFrame),
}

/// Convert a verified secure-envelope payload into its runtime frame.
///
/// Transport adapters must reject plaintext business frames and authenticate
/// the envelope before passing its inner frame here.
pub fn authenticated_external_inbound_frame_from_pb(
    frame: external_pb::external_frame::Frame,
) -> Result<ExternalInboundFrame, ExternalFrameError> {
    Ok(match frame {
        external_pb::external_frame::Frame::InboundEvent(frame) => {
            ExternalInboundFrame::InboundEvent(
                inbound_event_from_pb(&frame)
                    .map_err(|_error| ExternalFrameError::BadFramePayload)?,
            )
        }
        external_pb::external_frame::Frame::SourceStreamRequest(frame) => {
            ExternalInboundFrame::SourceStreamRequest(
                source_stream_request_from_pb(&frame)
                    .map_err(|_error| ExternalFrameError::BadFramePayload)?,
            )
        }
        external_pb::external_frame::Frame::CommandResult(frame) => {
            ExternalInboundFrame::CommandResult(
                command_result_from_pb(&frame)
                    .map_err(|_error| ExternalFrameError::BadFramePayload)?,
            )
        }
        external_pb::external_frame::Frame::InvokeResult(frame) => {
            ExternalInboundFrame::InvokeResult(
                invoke_result_from_pb(&frame)
                    .map_err(|_error| ExternalFrameError::BadFramePayload)?,
            )
        }
        external_pb::external_frame::Frame::Control(frame) => ExternalInboundFrame::Control(
            control_frame_from_pb(&frame).map_err(|_error| ExternalFrameError::BadFramePayload)?,
        ),
        _ => return Err(ExternalFrameError::SecureEnvelopePayloadRejected),
    })
}

/// Borrow the daemon-selected context after Hello, including while awaiting Ready.
pub fn selected_external_session_context(
    session: &EndpointSession,
) -> Result<&ExternalSessionContext, SessionReject> {
    session.context().ok_or(SessionReject::NotReady)
}

/// Validate that a frame is accepted for the ready external role.
pub fn require_external_role(
    context: &ExternalSessionContext,
    expected: ExternalRole,
) -> Result<(), ExternalFrameError> {
    if context.role == expected {
        Ok(())
    } else {
        Err(ExternalFrameError::ExternalRoleFrameRejected)
    }
}

/// Convert a protobuf secure envelope into the runtime envelope type.
pub fn secure_external_envelope_from_pb(
    envelope: external_pb::SecureEnvelope,
) -> Result<SecureEnvelope, ExternalFrameError> {
    let aad = envelope.aad.ok_or(ExternalFrameError::BadSecureEnvelope)?;
    let nonce_prefix: [u8; 12] = envelope
        .nonce_prefix
        .try_into()
        .map_err(|_error| ExternalFrameError::BadSecureEnvelope)?;
    Ok(SecureEnvelope::from_parts(
        envelope.installation_id,
        envelope.generation,
        EnvelopeAad {
            version: aad.version,
            projection_id: aad.projection_id,
            role: aad.role,
            session_id: aad.session_id,
            seq: aad.seq,
            frame_type: aad.frame_type,
            binding_generation: aad.binding_generation,
            credential_generation: aad.credential_generation,
            transcript_hash: aad.transcript_hash,
            key_epoch: aad.key_epoch,
            direction: aad.direction,
        },
        nonce_prefix,
        envelope.ciphertext,
    ))
}

/// Convert a sealed external envelope to its v1 wire representation.
pub fn secure_external_envelope_to_pb(envelope: SecureEnvelope) -> external_pb::SecureEnvelope {
    let (installation_id, generation, aad, nonce_prefix, ciphertext) = envelope.into_parts();
    external_pb::SecureEnvelope {
        installation_id,
        generation,
        aad: Some(external_pb::EnvelopeAad {
            version: aad.version,
            projection_id: aad.projection_id,
            role: aad.role,
            session_id: aad.session_id,
            seq: aad.seq,
            frame_type: aad.frame_type,
            binding_generation: aad.binding_generation,
            credential_generation: aad.credential_generation,
            transcript_hash: aad.transcript_hash,
            key_epoch: aad.key_epoch,
            direction: aad.direction,
        }),
        nonce_prefix: nonce_prefix.to_vec(),
        ciphertext,
    }
}

/// Build the transport-owned fields for one daemon-to-endpoint v1 envelope.
///
/// The sealing authority must validate these fields and replace `key_epoch`
/// with the current authoritative epoch before encrypting the payload.
pub fn secure_external_outbound_aad(
    context: &ExternalSessionContext,
    transcript_hash: &[u8; 32],
    seq: u64,
    frame_type: &str,
) -> EnvelopeAad {
    EnvelopeAad {
        version: 1,
        projection_id: context.projection_id.clone(),
        role: context.role.as_str().to_string(),
        session_id: context.session_id.clone(),
        seq,
        frame_type: frame_type.to_string(),
        binding_generation: context.binding_generation,
        credential_generation: context.credential_generation,
        transcript_hash: transcript_hash.to_vec(),
        key_epoch: context.key_epoch,
        direction: DAEMON_TO_CLIENT.to_string(),
    }
}

/// Validate that an inbound secure envelope is bound to the selected context.
pub fn validate_secure_external_envelope_context(
    envelope: &SecureEnvelope,
    context: &ExternalSessionContext,
) -> Result<(), ExternalFrameError> {
    let aad = envelope.aad();
    if envelope.installation_id() != context.installation_id
        || envelope.generation() != context.credential_generation
        || aad.projection_id != context.projection_id
        || aad.role != context.role.as_str()
        || aad.binding_generation != context.binding_generation
        || aad.credential_generation != context.credential_generation
        || aad.version != 1
        || aad.session_id != context.session_id
        || aad.frame_type.trim().is_empty()
        || aad.transcript_hash.len() != 32
        || aad.direction != CLIENT_TO_DAEMON
        || aad.key_epoch < context.key_epoch
    {
        return Err(ExternalFrameError::SecureEnvelopeContextRejected);
    }
    Ok(())
}

/// Validate an inbound envelope against the selected context and transcript.
/// This also applies to the first authenticated `role_ready` envelope.
pub fn validate_secure_external_envelope_session(
    envelope: &SecureEnvelope,
    session: &EndpointSession,
) -> Result<(), ExternalFrameError> {
    let context = session
        .context()
        .ok_or(ExternalFrameError::SecureEnvelopeContextRejected)?;
    validate_secure_external_envelope_context(envelope, context)?;
    if session.phase() == SessionPhase::AwaitingReady
        && envelope.aad().key_epoch != context.key_epoch
    {
        return Err(ExternalFrameError::SecureEnvelopeContextRejected);
    }
    if session.transcript_hash().map(|hash| hash.as_slice())
        != Some(envelope.aad().transcript_hash.as_slice())
    {
        return Err(ExternalFrameError::SecureEnvelopeContextRejected);
    }
    Ok(())
}

/// Validate that a secure envelope payload matches its AAD frame type.
pub fn validate_secure_external_inner_frame_type(
    frame: &external_pb::ExternalFrame,
    expected: &str,
) -> Result<(), ExternalFrameError> {
    let frame = frame.frame.as_ref().ok_or(ExternalFrameError::EmptyFrame)?;
    let actual = secure_external_inner_frame_type(frame)?;
    if actual == expected {
        Ok(())
    } else {
        Err(ExternalFrameError::SecureEnvelopeFrameTypeMismatch)
    }
}

/// Return the AAD frame type for an inbound secure external payload.
pub(crate) fn secure_external_inner_frame_type(
    frame: &external_pb::external_frame::Frame,
) -> Result<&'static str, ExternalFrameError> {
    Ok(match frame {
        external_pb::external_frame::Frame::InboundEvent(_) => "inbound_event",
        external_pb::external_frame::Frame::SourceStreamRequest(_) => "source_stream_request",
        external_pb::external_frame::Frame::CommandResult(_) => "command_result",
        external_pb::external_frame::Frame::InvokeResult(_) => "invoke_result",
        external_pb::external_frame::Frame::Control(control) => {
            external_control_frame_type(control)?
        }
        external_pb::external_frame::Frame::RoleReady(_) => "role_ready",
        external_pb::external_frame::Frame::RoleSessionClientHello(_)
        | external_pb::external_frame::Frame::SessionContext(_)
        | external_pb::external_frame::Frame::OutboundCommand(_)
        | external_pb::external_frame::Frame::EventAck(_)
        | external_pb::external_frame::Frame::Invoke(_)
        | external_pb::external_frame::Frame::SecureEnvelope(_) => {
            return Err(ExternalFrameError::SecureEnvelopePayloadRejected);
        }
        external_pb::external_frame::Frame::SourceStreamResult(_) => {
            return Err(ExternalFrameError::SecureEnvelopePayloadRejected);
        }
    })
}

/// Return the canonical AAD frame type for a daemon-to-endpoint payload.
pub fn secure_external_outbound_frame_type(
    frame: &external_pb::external_frame::Frame,
) -> Result<&'static str, ExternalFrameError> {
    Ok(match frame {
        external_pb::external_frame::Frame::Invoke(_) => "invoke",
        external_pb::external_frame::Frame::OutboundCommand(_) => "outbound_command",
        external_pb::external_frame::Frame::EventAck(_) => "event_ack",
        external_pb::external_frame::Frame::SourceStreamResult(_) => "source_stream_result",
        external_pb::external_frame::Frame::Control(control) => {
            external_control_frame_type(control)?
        }
        _ => return Err(ExternalFrameError::ExternalFrameDirectionRejected),
    })
}

/// Return the AAD frame type for a secure external control payload.
pub(crate) fn external_control_frame_type(
    frame: &external_pb::ControlFrame,
) -> Result<&'static str, ExternalFrameError> {
    let kind = frame
        .kind
        .as_ref()
        .ok_or(ExternalFrameError::BadControlFrame)?;
    Ok(match kind {
        external_pb::control_frame::Kind::Heartbeat(_) => "control.heartbeat",
        external_pb::control_frame::Kind::Shutdown(_) => "control.shutdown",
        external_pb::control_frame::Kind::FlowControl(_) => "control.flow_control",
        external_pb::control_frame::Kind::PresentationProfileUpdate(_) => {
            "control.presentation_profile_update"
        }
        external_pb::control_frame::Kind::InstallationConfigUpdate(_) => {
            "control.installation_config_update"
        }
        external_pb::control_frame::Kind::PresentationConfigUpdate(_) => {
            "control.presentation_config_update"
        }
        external_pb::control_frame::Kind::ConfigAck(_) => "control.config_ack",
        external_pb::control_frame::Kind::ProviderCancel(_) => "control.provider_cancel",
    })
}
