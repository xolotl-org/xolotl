//! External Provider and Source session admission API.
//!
//! Transport adapters and the daemon use this module to share one session
//! state machine. Application submissions enter through [`GatewaySubmission`].
use nexus_proto::nexus::v1::external as external_pb;
use nexus_proto::{
    command_result_from_pb, control_frame_from_pb, inbound_event_from_pb, invoke_result_from_pb,
};
use nexus_types::external::{
    CommandResult, ControlFrame, InboundEvent, InvokeResult, Role as ExternalRole,
    SessionContext as ExternalSessionContext,
};
use thiserror::Error;

mod secure_envelope;
mod session;

pub use secure_envelope::{
    DEFAULT_SECURE_ENVELOPE_REPLAY_WINDOW, EnvelopeAad, EnvelopeError, ExternalCredential,
    SecureEnvelope, SecureEnvelopeEpochGate, SecureEnvelopeReplayWindow,
};
pub use session::{
    EndpointSession, ExternalSessionHandler, ExternalSessionOutbound, ProviderInvocationError,
    ProviderInvocationRegister, ProviderInvocationRegistry, ProviderInvocationResolve,
    SessionPhase, SessionReject, SourceCommandError, SourceCommandRegister, SourceCommandRegistry,
    SourceCommandResolve, SourceIngest, SourceIngestError, ingest_source_event,
    validate_json_schema,
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

/// Return the stable string bound into secure envelope AAD for an external role.
pub(crate) fn external_role_slug(role: ExternalRole) -> &'static str {
    match role {
        ExternalRole::Provider => "provider",
        ExternalRole::Source => "source",
    }
}

/// Where an inbound external frame was carried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalFrameOrigin {
    /// The frame was received directly from the transport.
    Plain,
    /// The frame was decoded from a secure envelope payload.
    SecureEnvelope,
}

/// Runtime frame received from an external Provider or Source after handshake.
#[derive(Clone, Debug, PartialEq)]
pub enum ExternalInboundFrame {
    /// Source-to-daemon event frame.
    InboundEvent(InboundEvent),
    /// Source-to-daemon command result frame.
    CommandResult(CommandResult),
    /// Provider-to-daemon invocation result frame.
    InvokeResult(InvokeResult),
    /// Provider/Source-to-daemon control frame.
    Control(ControlFrame),
}

/// Convert an inbound external protobuf oneof into its runtime frame.
pub fn external_inbound_frame_from_pb(
    frame: external_pb::external_frame::Frame,
    origin: ExternalFrameOrigin,
) -> Result<ExternalInboundFrame, ExternalFrameError> {
    Ok(match frame {
        external_pb::external_frame::Frame::InboundEvent(frame) => {
            ExternalInboundFrame::InboundEvent(
                inbound_event_from_pb(&frame).map_err(|_| ExternalFrameError::BadFramePayload)?,
            )
        }
        external_pb::external_frame::Frame::CommandResult(frame) => {
            ExternalInboundFrame::CommandResult(
                command_result_from_pb(&frame).map_err(|_| ExternalFrameError::BadFramePayload)?,
            )
        }
        external_pb::external_frame::Frame::InvokeResult(frame) => {
            ExternalInboundFrame::InvokeResult(
                invoke_result_from_pb(&frame).map_err(|_| ExternalFrameError::BadFramePayload)?,
            )
        }
        external_pb::external_frame::Frame::Control(frame) => ExternalInboundFrame::Control(
            control_frame_from_pb(&frame).map_err(|_| ExternalFrameError::BadFramePayload)?,
        ),
        _ => {
            return Err(match origin {
                ExternalFrameOrigin::Plain => ExternalFrameError::ExternalFrameDirectionRejected,
                ExternalFrameOrigin::SecureEnvelope => {
                    ExternalFrameError::SecureEnvelopePayloadRejected
                }
            });
        }
    })
}

/// Return the ready context for an external endpoint session.
pub fn ready_external_session_context(
    session: &EndpointSession,
) -> Result<ExternalSessionContext, SessionReject> {
    session.context().cloned().ok_or(SessionReject::NotReady)
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
        .map_err(|_| ExternalFrameError::BadSecureEnvelope)?;
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
        },
        nonce_prefix,
        envelope.ciphertext,
    ))
}

/// Validate that a secure envelope is bound to a ready external session.
pub fn validate_secure_external_envelope_context(
    envelope: &SecureEnvelope,
    context: &ExternalSessionContext,
) -> Result<(), ExternalFrameError> {
    let aad = envelope.aad();
    if envelope.installation_id() != context.installation_id
        || envelope.generation() != context.credential_generation
        || aad.projection_id != context.projection_id
        || aad.role != external_role_slug(context.role)
        || aad.binding_generation != context.binding_generation
        || aad.credential_generation != context.credential_generation
        || aad.version != 1
        || aad.session_id != context.session_id
        || aad.frame_type.trim().is_empty()
        || aad.transcript_hash.len() != 32
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
        external_pb::external_frame::Frame::CommandResult(_) => "command_result",
        external_pb::external_frame::Frame::InvokeResult(_) => "invoke_result",
        external_pb::external_frame::Frame::Control(control) => {
            external_control_frame_type(control)?
        }
        external_pb::external_frame::Frame::RoleSessionClientHello(_)
        | external_pb::external_frame::Frame::SessionContext(_)
        | external_pb::external_frame::Frame::RoleReady(_)
        | external_pb::external_frame::Frame::OutboundCommand(_)
        | external_pb::external_frame::Frame::EventAck(_)
        | external_pb::external_frame::Frame::Invoke(_)
        | external_pb::external_frame::Frame::SecureEnvelope(_) => {
            return Err(ExternalFrameError::SecureEnvelopePayloadRejected);
        }
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
