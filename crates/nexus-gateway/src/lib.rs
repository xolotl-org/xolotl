#![forbid(unsafe_code)]

//! `nexus-gateway` - the shared Gateway runtime.
//!
//! A Gateway adapts an external protocol to the kernel in five steps: verify a
//! presented credential, map the verified principal to a Nexus identity, create
//! a request Process, admit a typed submission, and run the admitted program
//! through the executor.
//!
//! Protocol crates (`nexus-gateway-grpc/-websocket/-mcp`) stay thin. They parse
//! transport frames and credentials, then call this crate so authentication,
//! profile mapping, exposed surfaces, limits, taint, audit, and Handle ownership
//! remain one shared boundary.

use async_trait::async_trait;
use nexus_actors::endpoint::{EndpointSession, SessionReject};
use nexus_actors::pairing::{EnvelopeAad, SecureEnvelope};
use nexus_graph::{DoNode, OperationTemplate, StepRef, WaitSpec};
use nexus_kernel::{
    Bootstrap, CompiledRequestGrantTemplate, Executor, GatewayAudit, intern_identity,
};
use nexus_proto::nexus::v1::external as external_pb;
use nexus_proto::{
    command_result_from_pb, control_frame_from_pb, inbound_event_from_pb, invoke_result_from_pb,
    provider_ready_from_pb,
};
use nexus_types::external::{
    CommandResult, ControlFrame, InboundEvent, InvokeResult, ProviderReady, Role as ExternalRole,
    SessionContext as ExternalSessionContext,
};
use nexus_types::{
    BlobRef, Capability, CostModel, Failure, MethodBitmap, Outcome, OutputMode, Path, ProcessId,
    ProcessStatus, ReplayClass, ResourceName, ResourceSelector, StreamMarker, TaintSet,
    TaintSource, Value,
};
use parking_lot::{Mutex, RwLock};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Gateway profile revision bound to sessions and submissions.
pub type GatewayProfileRev = u64;
/// Monotonic generation for credential and principal state.
pub type GatewayGeneration = u64;

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
pub fn external_role_slug(role: ExternalRole) -> &'static str {
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
    /// Provider-to-daemon readiness frame.
    ProviderReady(ProviderReady),
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
        external_pb::external_frame::Frame::ProviderReady(frame) => {
            ExternalInboundFrame::ProviderReady(
                provider_ready_from_pb(&frame).map_err(|_| ExternalFrameError::BadFramePayload)?,
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
    Ok(SecureEnvelope {
        installation_id: envelope.installation_id,
        generation: envelope.generation,
        aad: EnvelopeAad {
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
        ciphertext: envelope.ciphertext,
    })
}

/// Validate that a secure envelope is bound to a ready external session.
pub fn validate_secure_external_envelope_context(
    envelope: &SecureEnvelope,
    context: &ExternalSessionContext,
) -> Result<(), ExternalFrameError> {
    if envelope.installation_id != context.installation_id
        || envelope.generation != context.credential_generation
        || envelope.aad.projection_id != context.projection_id
        || envelope.aad.role != external_role_slug(context.role)
        || envelope.aad.binding_generation != context.binding_generation
        || envelope.aad.credential_generation != context.credential_generation
        || envelope.aad.version != 1
        || envelope.aad.session_id != context.session_id
        || envelope.aad.frame_type.trim().is_empty()
        || envelope.aad.transcript_hash.len() != 32
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
pub fn secure_external_inner_frame_type(
    frame: &external_pb::external_frame::Frame,
) -> Result<&'static str, ExternalFrameError> {
    Ok(match frame {
        external_pb::external_frame::Frame::InboundEvent(_) => "inbound_event",
        external_pb::external_frame::Frame::CommandResult(_) => "command_result",
        external_pb::external_frame::Frame::InvokeResult(_) => "invoke_result",
        external_pb::external_frame::Frame::ProviderReady(_) => "provider_ready",
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
pub fn external_control_frame_type(
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

/// Browser origin registered for a gateway listener.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GatewayAllowedOrigin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl GatewayAllowedOrigin {
    /// Parse an HTTP(S) origin without path, query, or fragment.
    pub fn parse(origin: &str) -> Result<Self, GatewayError> {
        let origin = origin.trim();
        let (scheme, rest) = origin
            .split_once("://")
            .ok_or_else(|| GatewayError::InvalidProfile("origin must include scheme".into()))?;
        if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err(GatewayError::InvalidProfile(
                "origin must not include path, query, or fragment".into(),
            ));
        }
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https") {
            return Err(GatewayError::InvalidProfile(
                "origin scheme must be http or https".into(),
            ));
        }
        let (host, port) = parse_origin_authority(rest)?;
        let host = host.to_ascii_lowercase();
        if host.trim().is_empty() {
            return Err(GatewayError::InvalidProfile(
                "origin host must not be empty".into(),
            ));
        }
        let port = normalize_origin_port(&scheme, port);
        Ok(Self { scheme, host, port })
    }

    /// Return true when `origin` matches this registered origin.
    pub fn matches(&self, origin: &str, ignore_port: bool) -> bool {
        let Ok(candidate) = Self::parse(origin) else {
            return false;
        };
        self.scheme == candidate.scheme
            && self.host == candidate.host
            && (ignore_port || self.port == candidate.port)
    }

    /// Return true when this origin is a loopback/localhost HTTP(S) origin.
    pub fn is_local_trusted(&self) -> bool {
        matches!(self.scheme.as_str(), "http" | "https")
            && (self.host == "localhost"
                || self
                    .host
                    .parse::<IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false))
    }

    /// Return the canonical string form used in diagnostics.
    pub fn as_str(&self) -> String {
        match self.port {
            Some(port) => format!("{}://{}:{port}", self.scheme, self.host),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// Return true when an Origin header matches the registered origin set.
pub fn browser_origin_allowed(
    origin: &str,
    registered_origins: &[GatewayAllowedOrigin],
    ignore_port: bool,
) -> bool {
    registered_origins
        .iter()
        .any(|registered| registered.matches(origin, ignore_port))
}

/// Return true when an Origin header is acceptable for a local trust boundary.
pub fn local_trusted_browser_origin(origin: &str) -> bool {
    GatewayAllowedOrigin::parse(origin).is_ok_and(|origin| origin.is_local_trusted())
}

/// Gateway Host/SNI authority registered for a listener profile.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GatewayAllowedHost {
    host: String,
    port: Option<u16>,
}

impl GatewayAllowedHost {
    /// Parse a host authority without scheme, path, query, or fragment.
    pub fn parse(authority: &str) -> Result<Self, GatewayError> {
        let authority = authority.trim();
        if authority.is_empty()
            || authority.contains("://")
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
        {
            return Err(GatewayError::InvalidProfile(
                "gateway host must be host[:port] without scheme, path, or userinfo".into(),
            ));
        }
        let (host, port) = parse_origin_authority(authority)?;
        let host = host.to_ascii_lowercase();
        if host.trim().is_empty()
            || host.chars().any(|ch| ch.is_ascii_whitespace())
            || host.contains('*')
            || (host.contains(':') && host.parse::<Ipv6Addr>().is_err())
        {
            return Err(GatewayError::InvalidProfile(
                "gateway host authority is invalid".into(),
            ));
        }
        Ok(Self { host, port })
    }

    /// Return true when `authority` matches this registered Host/SNI authority.
    pub fn matches(&self, authority: &str) -> bool {
        let Ok(candidate) = Self::parse(authority) else {
            return false;
        };
        self.host == candidate.host && self.port == candidate.port
    }

    /// Return the canonical string form used in diagnostics.
    pub fn as_str(&self) -> String {
        let host = if self.host.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }
}

/// Return true when a Host/SNI authority matches the registered host set.
pub fn gateway_host_allowed(authority: &str, registered_hosts: &[GatewayAllowedHost]) -> bool {
    registered_hosts
        .iter()
        .any(|registered| registered.matches(authority))
}

fn parse_origin_authority(authority: &str) -> Result<(&str, Option<u16>), GatewayError> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err(GatewayError::InvalidProfile(
            "origin authority must not be empty".into(),
        ));
    }
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, rest) = stripped.split_once(']').ok_or_else(|| {
            GatewayError::InvalidProfile("origin IPv6 host is missing closing bracket".into())
        })?;
        let port = match rest.strip_prefix(':') {
            Some(port) if !port.is_empty() => Some(parse_origin_port(port)?),
            Some(_) => {
                return Err(GatewayError::InvalidProfile(
                    "origin port must not be empty".into(),
                ));
            }
            None if rest.is_empty() => None,
            None => {
                return Err(GatewayError::InvalidProfile(
                    "origin authority has invalid IPv6 suffix".into(),
                ));
            }
        };
        return Ok((host, port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(parse_origin_port(port)?)),
        _ => (authority, None),
    };
    Ok((host, port))
}

fn parse_origin_port(port: &str) -> Result<u16, GatewayError> {
    port.parse::<u16>()
        .map_err(|_| GatewayError::InvalidProfile("origin port is invalid".into()))
}

fn normalize_origin_port(scheme: &str, port: Option<u16>) -> Option<u16> {
    match (scheme, port) {
        ("http", Some(80)) | ("https", Some(443)) => None,
        (_, port) => port,
    }
}

/// Transport boundary declared for a gateway listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayTransportSecurityMode {
    /// The listener terminates TLS itself.
    ProductionTls,
    /// The listener terminates TLS and verifies client certificates.
    MutualTls,
    /// TLS terminates at a configured reverse proxy.
    TrustedReverseProxy,
    /// Plain transport is accepted only across a local trust boundary.
    LocalTrusted,
    /// Plain transport is explicitly accepted for this listener.
    UnsafePlaintext,
    /// Transport checks are disabled for tests.
    DisabledForTest,
}

impl GatewayTransportSecurityMode {
    /// Return the stable configuration name for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProductionTls => "production_tls",
            Self::MutualTls => "mtls",
            Self::TrustedReverseProxy => "trusted_reverse_proxy",
            Self::LocalTrusted => "local_trusted",
            Self::UnsafePlaintext => "unsafe_plaintext",
            Self::DisabledForTest => "disabled_for_test",
        }
    }
}

/// Explicit transport-security relaxations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayUnsafeTransportRelaxation {
    /// Accept a plain HTTP/WS or HTTP/2 backend hop.
    AllowPlaintext,
    /// Ignore the port component when checking browser origins.
    IgnoreOriginPort,
    /// Disable browser Origin matching.
    RelaxedOrigin,
}

impl GatewayUnsafeTransportRelaxation {
    /// Return the stable configuration name for this relaxation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowPlaintext => "allow_plaintext",
            Self::IgnoreOriginPort => "ignore_origin_port",
            Self::RelaxedOrigin => "relaxed_origin",
        }
    }
}

/// Trusted reverse-proxy handling for gateway transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayTrustedProxyConfig {
    /// Direct peer IP addresses allowed to supply forwarded headers.
    pub peers: Vec<IpAddr>,
    /// Whether `X-Forwarded-Proto` is accepted from trusted peers.
    pub honor_x_forwarded_proto: bool,
    /// Whether `X-Forwarded-Host` is accepted from trusted peers.
    pub honor_x_forwarded_host: bool,
    /// Whether `X-Forwarded-For` and `X-Real-IP` are accepted from trusted peers.
    pub honor_x_forwarded_for: bool,
}

impl Default for GatewayTrustedProxyConfig {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            honor_x_forwarded_proto: true,
            honor_x_forwarded_host: true,
            honor_x_forwarded_for: true,
        }
    }
}

/// Transport security and proxy policy for gateway listeners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayTransportSecurityConfig {
    /// Declared transport boundary mode.
    pub mode: GatewayTransportSecurityMode,
    /// Trusted proxy peers and forwarded-header policy.
    pub trusted_proxy: GatewayTrustedProxyConfig,
    /// Explicit unsafe transport relaxations.
    pub unsafe_relaxations: Vec<GatewayUnsafeTransportRelaxation>,
}

impl Default for GatewayTransportSecurityConfig {
    fn default() -> Self {
        Self {
            mode: GatewayTransportSecurityMode::LocalTrusted,
            trusted_proxy: GatewayTrustedProxyConfig::default(),
            unsafe_relaxations: Vec::new(),
        }
    }
}

impl GatewayTransportSecurityConfig {
    /// Normalize set-like fields.
    pub fn bounded(mut self) -> Self {
        self.unsafe_relaxations.sort_by_key(|r| r.as_str());
        self.unsafe_relaxations.dedup();
        self.trusted_proxy.peers.sort();
        self.trusted_proxy.peers.dedup();
        self
    }

    /// Return true when this config explicitly accepts unsafe transport state.
    pub fn is_unsafe(&self) -> bool {
        matches!(self.mode, GatewayTransportSecurityMode::UnsafePlaintext)
            || !self.unsafe_relaxations.is_empty()
    }

    /// Return true when `peer` is allowed to supply forwarded headers.
    pub fn trusts_peer(&self, peer: Option<IpAddr>) -> bool {
        matches!(self.mode, GatewayTransportSecurityMode::TrustedReverseProxy)
            && peer.is_some_and(|ip| self.trusted_proxy.peers.contains(&ip))
    }

    /// Return true when browser Origin checks may ignore port mismatches.
    pub fn ignore_origin_port(&self) -> bool {
        self.unsafe_relaxations
            .contains(&GatewayUnsafeTransportRelaxation::IgnoreOriginPort)
    }

    /// Return true when browser Origin checks are disabled.
    pub fn relaxed_origin(&self) -> bool {
        self.unsafe_relaxations
            .contains(&GatewayUnsafeTransportRelaxation::RelaxedOrigin)
    }

    /// Return stable names for configured unsafe relaxations.
    pub fn unsafe_relaxation_names(&self) -> Vec<String> {
        self.unsafe_relaxations
            .iter()
            .map(|r| r.as_str().to_string())
            .collect()
    }
}

const DEFAULT_MAX_PROGRAM_NODES: usize = 4096;
const DEFAULT_MAX_PROGRAM_DEPTH: usize = 128;
const DEFAULT_MAX_LITERAL_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_COLLECT_LIMIT: usize = 1024;
const DEFAULT_MAX_DEADLINE_MS_FROM_NOW: i64 = 5 * 60 * 1000;
const DEFAULT_MAX_IN_FLIGHT_REQUESTS: usize = 1024;
const DEFAULT_MAX_PRINCIPAL_IN_FLIGHT_REQUESTS: usize = 512;
const DEFAULT_MAX_SURFACE_IN_FLIGHT_REQUESTS: usize = 512;
const DEFAULT_MAX_RISK_CLASS_IN_FLIGHT_REQUESTS: usize = 512;
const DEFAULT_MAX_STREAM_ITEMS: usize = 4096;
const DEFAULT_MAX_STREAM_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_STREAM_INLINE_ITEM_BYTES: usize = 1024 * 1024;
const DEFAULT_BUDGET_MAX_INFLIGHT_OPS: u64 = 8192;
const DEFAULT_BUDGET_MAX_BYTES_IN: u64 = 64 * 1024 * 1024;
const DEFAULT_BUDGET_MAX_INLINE_VALUE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_BUDGET_MAX_STREAM_ITEMS: u64 = 64 * 1024;
const MIN_BEARER_TOKEN_BYTES: usize = 16;
const OBJECT_UPLOAD_TICKET_RANDOM_BYTES: usize = 16;
const GATEWAY_REQUEST_ID_RANDOM_BYTES: usize = 16;
const COMPLETED_REQUEST_RETENTION_MS: i64 = 60_000;
const DEADLINE_SWEEP_INTERVAL_MS: u64 = 50;
const GATEWAY_COMMITTED_OBJECT_STORE_ID: &str = "gateway-upload-ticket-v1";

/// Errors surfaced by gateway authentication, authorization, profile
/// compilation, request admission, and kernel setup.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Credentials were absent or failed validation.
    #[error("authentication failed")]
    Unauthenticated,
    /// Authenticated principal is not allowed to use this gateway.
    #[error("principal {0} is not authorized for this gateway")]
    Unauthorized(String),
    /// Gateway profile is malformed or references unavailable runtime state.
    #[error("gateway profile invalid: {0}")]
    InvalidProfile(String),
    /// The request was rejected by gateway admission or kernel setup.
    #[error("request rejected: {0}")]
    Rejected(String),
    /// The request could not start because a bounded gateway resource is full.
    #[error("gateway limit exceeded: {0}")]
    LimitExceeded(String),
}

impl GatewayError {
    /// Redacted message suitable for returning to an external client.
    pub fn public_message(&self) -> &'static str {
        match self {
            GatewayError::Unauthenticated => "authentication failed",
            GatewayError::Unauthorized(_) => "authorization failed",
            GatewayError::InvalidProfile(_)
            | GatewayError::Rejected(_)
            | GatewayError::LimitExceeded(_) => "request rejected",
        }
    }

    /// Stable audit outcome tag for this error.
    pub fn audit_outcome(&self) -> &'static str {
        match self {
            GatewayError::Unauthenticated => "auth_failed",
            GatewayError::Unauthorized(_) => "permission_denied",
            GatewayError::InvalidProfile(_) => "profile_invalid",
            GatewayError::Rejected(_) => "request_rejected",
            GatewayError::LimitExceeded(_) => "limit_exceeded",
        }
    }

    /// Stable lower-snake wire error code.
    pub fn code(&self) -> &'static str {
        match self {
            GatewayError::Unauthenticated => "unauthenticated",
            GatewayError::Unauthorized(_) => "permission_denied",
            GatewayError::InvalidProfile(_) => "profile_invalid",
            GatewayError::Rejected(_) => "request_rejected",
            GatewayError::LimitExceeded(_) => "limit_exceeded",
        }
    }
}

/// Credentials presented by an inbound protocol adapter. They are untrusted
/// until [`Gateway::authenticate`] verifies them against the compiled profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PresentedCredential {
    /// A bearer secret presented through a transport credential channel.
    Bearer(BearerToken),
    /// A TLS client certificate verified by the listener and matched by DER
    /// SHA-256 fingerprint.
    ClientCertificate(ClientCertificateCredential),
}

impl PresentedCredential {
    /// Build a presented bearer credential.
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer(BearerToken::new(token))
    }

    /// Build a presented client certificate credential from the leaf DER.
    pub fn client_certificate_der(der: impl AsRef<[u8]>) -> Self {
        Self::ClientCertificate(ClientCertificateCredential::from_der(der))
    }
}

/// Raw bearer token material. `Debug` is deliberately redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct BearerToken(String);

impl BearerToken {
    /// Wrap raw bearer token material.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

/// Hashed bearer token material stored in a gateway profile.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct BearerTokenHash(String);

impl BearerTokenHash {
    /// Hash a high-entropy bearer token for storage in a profile.
    pub fn from_token(token: &str) -> Result<Self, GatewayError> {
        if token.len() < MIN_BEARER_TOKEN_BYTES {
            return Err(GatewayError::InvalidProfile(format!(
                "bearer tokens must be at least {MIN_BEARER_TOKEN_BYTES} bytes"
            )));
        }
        Ok(Self(hash_bearer_token(token)))
    }

    /// Use a precomputed lowercase hex BLAKE3 hash from deployment config.
    pub fn from_hex(hash: impl Into<String>) -> Result<Self, GatewayError> {
        let hash = hash.into();
        let ok = hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(GatewayError::InvalidProfile(
                "bearer token hash must be a 64-character lowercase hex string".into(),
            ));
        }
        Ok(Self(hash))
    }
}

fn hash_bearer_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

impl std::fmt::Debug for BearerTokenHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerTokenHash(<redacted>)")
    }
}

/// TLS client certificate credential material presented by a transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientCertificateCredential {
    der_sha256: ClientCertificateDerSha256,
}

impl ClientCertificateCredential {
    /// Hash a leaf certificate DER to its profile matcher.
    pub fn from_der(der: impl AsRef<[u8]>) -> Self {
        Self {
            der_sha256: ClientCertificateDerSha256::from_der(der),
        }
    }
}

/// SHA-256 fingerprint of a client certificate DER.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClientCertificateDerSha256(String);

impl ClientCertificateDerSha256 {
    /// Hash certificate DER bytes for use in a gateway profile.
    pub fn from_der(der: impl AsRef<[u8]>) -> Self {
        let digest = sha2::Sha256::digest(der.as_ref());
        Self(hex_lower(&digest))
    }

    /// Use a precomputed lowercase hex SHA-256 fingerprint from deployment config.
    pub fn from_hex(hash: impl Into<String>) -> Result<Self, GatewayError> {
        let hash = hash.into();
        let ok = hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(GatewayError::InvalidProfile(
                "client certificate DER SHA-256 must be a 64-character lowercase hex string".into(),
            ));
        }
        Ok(Self(hash))
    }
}

impl std::fmt::Debug for ClientCertificateDerSha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientCertificateDerSha256(<redacted>)")
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// A credential accepted by a gateway profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayCredential {
    /// Stable redacted credential identifier used for admin display and audit
    /// correlation. It is not the raw secret.
    pub credential_id: String,
    /// Principal produced when this credential verifies.
    pub principal_id: String,
    /// Whether this credential is active in the profile snapshot.
    pub enabled: bool,
    /// Monotonic credential generation used to invalidate existing sessions.
    pub generation: GatewayGeneration,
    /// Credential verifier material.
    pub kind: GatewayCredentialKind,
}

impl GatewayCredential {
    /// Accept a bearer token by hashing it immediately.
    pub fn bearer_token(
        credential_id: impl Into<String>,
        principal_id: impl Into<String>,
        token: &str,
    ) -> Result<Self, GatewayError> {
        Ok(Self::bearer_hash(
            credential_id,
            principal_id,
            BearerTokenHash::from_token(token)?,
        ))
    }

    /// Accept a precomputed bearer token hash.
    pub fn bearer_hash(
        credential_id: impl Into<String>,
        principal_id: impl Into<String>,
        token_hash: BearerTokenHash,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            principal_id: principal_id.into(),
            enabled: true,
            generation: 1,
            kind: GatewayCredentialKind::Bearer { token_hash },
        }
    }

    /// Accept a TLS client certificate by DER SHA-256 fingerprint.
    pub fn client_certificate_der_sha256(
        credential_id: impl Into<String>,
        principal_id: impl Into<String>,
        der_sha256: ClientCertificateDerSha256,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            principal_id: principal_id.into(),
            enabled: true,
            generation: 1,
            kind: GatewayCredentialKind::ClientCertificate { der_sha256 },
        }
    }

    /// Mark whether this credential is active.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set the credential generation.
    pub fn with_generation(mut self, generation: GatewayGeneration) -> Self {
        self.generation = generation;
        self
    }
}

/// Credential verifier material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewayCredentialKind {
    /// Bearer token checked by hash.
    Bearer {
        /// BLAKE3 hash of the high-entropy bearer token.
        token_hash: BearerTokenHash,
    },
    /// TLS client certificate checked by DER SHA-256 fingerprint.
    ClientCertificate {
        /// SHA-256 fingerprint of the leaf certificate DER.
        der_sha256: ClientCertificateDerSha256,
    },
}

/// Maps a verified external principal to the Nexus identity path a request
/// Process runs as.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayIdentityMapping {
    /// Verified external principal id.
    pub principal_id: String,
    /// Nexus identity path, usually `process://<account-or-agent>`.
    pub identity_path: String,
    /// Whether this principal mapping is active in the profile snapshot.
    pub enabled: bool,
    /// Monotonic principal generation used to invalidate existing sessions.
    pub generation: GatewayGeneration,
}

impl GatewayIdentityMapping {
    /// Create a principal-to-identity mapping.
    pub fn new(principal_id: impl Into<String>, identity_path: impl Into<String>) -> Self {
        Self {
            principal_id: principal_id.into(),
            identity_path: identity_path.into(),
            enabled: true,
            generation: 1,
        }
    }

    /// Mark whether this principal mapping is active.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set the principal generation.
    pub fn with_generation(mut self, generation: GatewayGeneration) -> Self {
        self.generation = generation;
        self
    }
}

/// Authentication method that verified a principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayAuthMethod {
    /// Bearer token auth.
    Bearer,
    /// TLS client certificate auth.
    ClientCertificate,
}

/// Principal verified from a presented credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPrincipal {
    /// External principal id after credential verification.
    pub principal_id: String,
    /// Redacted credential id used to correlate audit without storing secrets.
    pub credential_id: String,
    /// Credential generation that was current at authentication.
    pub credential_generation: GatewayGeneration,
    /// Principal generation that was current at authentication.
    pub principal_generation: GatewayGeneration,
    /// Auth method used for the credential.
    pub auth_method: GatewayAuthMethod,
}

/// Authenticated gateway session. Protocol adapters may cache this for a
/// connection, but every submission still carries the profile snapshot id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySession {
    /// Verified principal.
    pub principal: VerifiedPrincipal,
    /// Nexus identity path the request Process will run as.
    pub identity_path: String,
    /// Gateway profile name used for this session.
    pub profile_name: String,
    /// Gateway profile revision used for this session.
    pub profile_rev: GatewayProfileRev,
}

/// One resource surface exposed by a gateway profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySurface {
    /// Stable surface id within the profile.
    pub surface_id: String,
    /// Surface kind.
    pub kind: GatewaySurfaceKind,
    /// Resource target exposed through this surface.
    pub target: ResourceName,
    /// Method name accepted by this surface.
    pub method: String,
    /// Verb used when opening a Process-owned Handle for this resource.
    pub handle_verb: String,
    /// Capability literal used as the request Process grant template.
    pub grant_template: String,
    /// Capability literal required before this surface may be published.
    pub publish_capability: Option<String>,
    /// Input schema descriptor advertised for this surface.
    pub input_schema: Option<Value>,
    /// Output schema descriptor advertised for this surface.
    pub output_schema: Option<Value>,
}

impl GatewaySurface {
    /// Expose one operation target and method.
    pub fn operation(
        surface_id: impl Into<String>,
        target: ResourceName,
        method: impl Into<String>,
        handle_verb: impl Into<String>,
        grant_template: impl Into<String>,
    ) -> Self {
        Self {
            surface_id: surface_id.into(),
            kind: GatewaySurfaceKind::EffectMethod,
            target,
            method: method.into(),
            handle_verb: handle_verb.into(),
            grant_template: grant_template.into(),
            publish_capability: None,
            input_schema: None,
            output_schema: None,
        }
    }

    /// Expose one state append target as a typed surface.
    pub fn state_append(
        surface_id: impl Into<String>,
        stream: ResourceName,
        grant_template: impl Into<String>,
    ) -> Self {
        Self {
            surface_id: surface_id.into(),
            kind: GatewaySurfaceKind::StateAppend,
            target: stream,
            method: "append".into(),
            handle_verb: "append".into(),
            grant_template: grant_template.into(),
            publish_capability: None,
            input_schema: None,
            output_schema: None,
        }
    }

    /// Set the publishing capability for protocol directories.
    pub fn with_publish_capability(mut self, publish_capability: impl Into<String>) -> Self {
        self.publish_capability = Some(publish_capability.into());
        self
    }

    /// Attach optional input and output schema descriptors.
    pub fn with_schema(
        mut self,
        input_schema: Option<Value>,
        output_schema: Option<Value>,
    ) -> Self {
        self.input_schema = input_schema;
        self.output_schema = output_schema;
        self
    }
}

/// Surfaces a principal can see and submit through.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPrincipalSurfaceBinding {
    /// Authenticated principal id.
    pub principal_id: String,
    /// Surfaces returned by authenticated discovery for this principal.
    pub visible_surfaces: Vec<String>,
    /// Surfaces this principal may submit through.
    pub submit_surfaces: Vec<String>,
    /// Capability ceiling for submissions admitted through this binding.
    pub capability_ceiling: Vec<String>,
}

impl GatewayPrincipalSurfaceBinding {
    /// Bind a principal to explicit visible and callable surface ids.
    pub fn new(
        principal_id: impl Into<String>,
        visible_surfaces: impl IntoIterator<Item = impl Into<String>>,
        submit_surfaces: impl IntoIterator<Item = impl Into<String>>,
        capability_ceiling: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            principal_id: principal_id.into(),
            visible_surfaces: visible_surfaces.into_iter().map(Into::into).collect(),
            submit_surfaces: submit_surfaces.into_iter().map(Into::into).collect(),
            capability_ceiling: capability_ceiling.into_iter().map(Into::into).collect(),
        }
    }

    /// Bind a principal to the same visible and callable surface ids.
    pub fn allow(
        principal_id: impl Into<String>,
        surface_ids: impl IntoIterator<Item = impl Into<String>>,
        capability_ceiling: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        let surface_ids: Vec<String> = surface_ids.into_iter().map(Into::into).collect();
        Self {
            principal_id: principal_id.into(),
            visible_surfaces: surface_ids.clone(),
            submit_surfaces: surface_ids,
            capability_ceiling: capability_ceiling.into_iter().map(Into::into).collect(),
        }
    }
}

/// Gateway surface class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewaySurfaceKind {
    /// A single effect method exposed as a typed surface.
    EffectMethod,
    /// A single state stream append exposed as a typed surface.
    StateAppend,
}

impl GatewaySurfaceKind {
    /// Stable lower-snake surface kind string for descriptors and audit.
    pub fn as_str(self) -> &'static str {
        match self {
            GatewaySurfaceKind::EffectMethod => "effect_method",
            GatewaySurfaceKind::StateAppend => "state_append",
        }
    }
}

/// Request and Program limits applied before a request Process runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayLimitProfile {
    /// Maximum `DoNode` count in one submitted program.
    pub max_program_nodes: usize,
    /// Maximum structural depth in one submitted program.
    pub max_program_depth: usize,
    /// Maximum inline literal bytes in one submitted program.
    pub max_literal_bytes: usize,
    /// Maximum `OutputMode::Collect` limit.
    pub max_collect_limit: usize,
    /// Maximum future deadline accepted for `Wait(Deadline)`.
    pub max_deadline_ms_from_now: i64,
    /// Maximum concurrently executing submissions for this runtime.
    pub max_in_flight_requests: usize,
    /// Maximum concurrently executing submissions for one principal.
    pub max_principal_in_flight_requests: usize,
    /// Maximum concurrently executing submissions for one surface.
    pub max_surface_in_flight_requests: usize,
    /// Maximum concurrently executing submissions for one risk class.
    pub max_risk_class_in_flight_requests: usize,
    /// Aggregate request budget reserved before request Process creation.
    pub budget: GatewayBudgetProfile,
    /// Maximum items accepted in one client-to-kernel input stream.
    pub max_stream_items: usize,
    /// Maximum folded inline bytes accepted in one client-to-kernel input stream.
    pub max_stream_bytes: usize,
    /// Maximum inline bytes accepted for one input stream item.
    pub max_stream_inline_item_bytes: usize,
    /// Whether externally submitted `Acting` nodes are admitted.
    pub allow_acting: bool,
    /// Whether externally submitted `StepRef` continuations are admitted.
    pub allow_step_refs: bool,
    /// Whether externally submitted `Wait(Signal)` nodes are admitted.
    pub allow_wait_signal: bool,
    /// Whether externally submitted `Wait(Deadline)` nodes are admitted.
    pub allow_wait_deadline: bool,
}

impl Default for GatewayLimitProfile {
    fn default() -> Self {
        Self {
            max_program_nodes: DEFAULT_MAX_PROGRAM_NODES,
            max_program_depth: DEFAULT_MAX_PROGRAM_DEPTH,
            max_literal_bytes: DEFAULT_MAX_LITERAL_BYTES,
            max_collect_limit: DEFAULT_MAX_COLLECT_LIMIT,
            max_deadline_ms_from_now: DEFAULT_MAX_DEADLINE_MS_FROM_NOW,
            max_in_flight_requests: DEFAULT_MAX_IN_FLIGHT_REQUESTS,
            max_principal_in_flight_requests: DEFAULT_MAX_PRINCIPAL_IN_FLIGHT_REQUESTS,
            max_surface_in_flight_requests: DEFAULT_MAX_SURFACE_IN_FLIGHT_REQUESTS,
            max_risk_class_in_flight_requests: DEFAULT_MAX_RISK_CLASS_IN_FLIGHT_REQUESTS,
            budget: GatewayBudgetProfile::default(),
            max_stream_items: DEFAULT_MAX_STREAM_ITEMS,
            max_stream_bytes: DEFAULT_MAX_STREAM_BYTES,
            max_stream_inline_item_bytes: DEFAULT_MAX_STREAM_INLINE_ITEM_BYTES,
            allow_acting: false,
            allow_step_refs: false,
            allow_wait_signal: false,
            allow_wait_deadline: false,
        }
    }
}

/// Aggregate request budget reserved during Gateway admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayBudgetProfile {
    /// Maximum outstanding operation leaves admitted across running requests.
    pub max_inflight_ops: Option<u64>,
    /// Maximum outstanding requested wall-clock milliseconds.
    pub max_wall_ms: Option<u64>,
    /// Maximum outstanding ingress bytes estimated from payload metadata.
    pub max_bytes_in: Option<u64>,
    /// Maximum outstanding egress bytes when a protocol can estimate them.
    pub max_bytes_out: Option<u64>,
    /// Maximum outstanding inline `Value` bytes.
    pub max_inline_value_bytes: Option<u64>,
    /// Maximum outstanding admitted client-to-kernel stream items.
    pub max_stream_items: Option<u64>,
    /// Maximum outstanding estimated method cost in micro-USD.
    pub max_estimated_cost_micro_usd: Option<u64>,
}

impl Default for GatewayBudgetProfile {
    fn default() -> Self {
        Self {
            max_inflight_ops: Some(DEFAULT_BUDGET_MAX_INFLIGHT_OPS),
            max_wall_ms: None,
            max_bytes_in: Some(DEFAULT_BUDGET_MAX_BYTES_IN),
            max_bytes_out: None,
            max_inline_value_bytes: Some(DEFAULT_BUDGET_MAX_INLINE_VALUE_BYTES),
            max_stream_items: Some(DEFAULT_BUDGET_MAX_STREAM_ITEMS),
            max_estimated_cost_micro_usd: None,
        }
    }
}

/// Gateway profile loaded by the host. Profiles are explicit: credentials,
/// identity mapping, exposed surfaces, and request limits all live here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayProfile {
    /// Stable profile name.
    pub profile_name: String,
    /// Host-assigned profile revision.
    pub revision: GatewayProfileRev,
    /// Accepted credentials.
    pub credentials: Vec<GatewayCredential>,
    /// Credentials with generation less than or equal to this floor are revoked.
    pub credential_revocation_floor: GatewayGeneration,
    /// Principal-to-Nexus identity mappings.
    pub identity_mappings: Vec<GatewayIdentityMapping>,
    /// Resource surfaces exposed to submitted programs.
    pub surfaces: Vec<GatewaySurface>,
    /// Process whose grants bound request Process grants. `None` uses the
    /// kernel root Process.
    pub authority_anchor: Option<ProcessId>,
    /// Principal-scoped visible/callable surface bindings.
    pub principal_surface_bindings: Vec<GatewayPrincipalSurfaceBinding>,
    /// Host/SNI authorities allowed to select this gateway listener profile.
    pub registered_hosts: Vec<GatewayAllowedHost>,
    /// Browser origins allowed to initiate browser-capable transports.
    pub registered_origins: Vec<GatewayAllowedOrigin>,
    /// Admission and resource limits.
    pub limits: GatewayLimitProfile,
}

impl GatewayProfile {
    /// Create an empty profile. Without credentials it authenticates nobody;
    /// without surfaces it admits only pure inert programs.
    pub fn new(profile_name: impl Into<String>) -> Self {
        Self {
            profile_name: profile_name.into(),
            revision: 1,
            credentials: Vec::new(),
            credential_revocation_floor: 0,
            identity_mappings: Vec::new(),
            surfaces: Vec::new(),
            authority_anchor: None,
            principal_surface_bindings: Vec::new(),
            registered_hosts: Vec::new(),
            registered_origins: Vec::new(),
            limits: GatewayLimitProfile::default(),
        }
    }

    /// Explicit closed profile for listeners that should start but reject all
    /// clients until deployment config supplies credentials and surfaces.
    pub fn closed(profile_name: impl Into<String>) -> Self {
        Self::new(profile_name)
    }

    /// Set the profile revision.
    pub fn with_revision(mut self, revision: GatewayProfileRev) -> Self {
        self.revision = revision;
        self
    }

    /// Set the credential revocation floor.
    pub fn with_credential_revocation_floor(mut self, floor: GatewayGeneration) -> Self {
        self.credential_revocation_floor = floor;
        self
    }

    /// Add an accepted credential.
    pub fn with_credential(mut self, credential: GatewayCredential) -> Self {
        self.credentials.push(credential);
        self
    }

    /// Add a principal-to-identity mapping.
    pub fn with_identity_mapping(mut self, mapping: GatewayIdentityMapping) -> Self {
        self.identity_mappings.push(mapping);
        self
    }

    /// Add a bearer token and identity mapping in one call.
    pub fn with_bearer_identity(
        self,
        credential_id: impl Into<String>,
        principal_id: impl Into<String>,
        token: &str,
        identity_path: impl Into<String>,
    ) -> Result<Self, GatewayError> {
        let principal_id = principal_id.into();
        Ok(self
            .with_credential(GatewayCredential::bearer_token(
                credential_id,
                principal_id.clone(),
                token,
            )?)
            .with_identity_mapping(GatewayIdentityMapping::new(principal_id, identity_path)))
    }

    /// Add an exposed surface.
    pub fn with_surface(mut self, surface: GatewaySurface) -> Self {
        self.surfaces.push(surface);
        self
    }

    /// Use `anchor` as the parent authority for request Processes.
    pub fn with_authority_anchor(mut self, anchor: ProcessId) -> Self {
        self.authority_anchor = Some(anchor);
        self
    }

    /// Add a principal-to-surface binding.
    pub fn with_principal_surface_binding(
        mut self,
        binding: GatewayPrincipalSurfaceBinding,
    ) -> Self {
        self.principal_surface_bindings.push(binding);
        self
    }

    /// Register a gateway Host/SNI authority for this listener profile.
    pub fn with_registered_host(mut self, authority: &str) -> Result<Self, GatewayError> {
        self.registered_hosts
            .push(GatewayAllowedHost::parse(authority)?);
        Ok(self)
    }

    /// Register a browser origin for browser-capable transports.
    pub fn with_registered_origin(mut self, origin: &str) -> Result<Self, GatewayError> {
        self.registered_origins
            .push(GatewayAllowedOrigin::parse(origin)?);
        Ok(self)
    }

    /// Replace the limit profile.
    pub fn with_limits(mut self, limits: GatewayLimitProfile) -> Self {
        self.limits = limits;
        self
    }
}

#[derive(Clone, Debug)]
struct CompiledSurfaceDescriptor {
    surface_id: String,
    kind: GatewaySurfaceKind,
    target: ResourceName,
    method: String,
    method_bitmap: MethodBitmap,
    handle_verb: String,
    grant_template: String,
    grant_capability: Capability,
    grant_selector: ResourceSelector,
    publish_capability: Option<String>,
    input_schema: Option<Value>,
    input_schema_validator: Option<CompiledValueSchema>,
    output_schema: Option<Value>,
    output_schema_validator: Option<CompiledValueSchema>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CompiledValueSchema {
    kind: ValueSchemaKind,
    required: BTreeSet<String>,
    properties: BTreeMap<String, CompiledValueSchema>,
    items: Option<Box<CompiledValueSchema>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ValueSchemaKind {
    Any,
    Null,
    Bool,
    Int,
    Number,
    Str,
    List,
    Map,
    Bytes,
    Blob,
    Tensor,
    Frame,
    StreamEnd,
}

#[derive(Clone, Debug)]
struct CompiledIdentityMapping {
    identity_path: String,
    enabled: bool,
    generation: GatewayGeneration,
}

#[derive(Clone, Debug, Default)]
struct CompiledPrincipalSurfaceBinding {
    visible: BTreeSet<String>,
    submit: BTreeSet<String>,
    capability_ceiling: Vec<Capability>,
    request_grants_by_surface: BTreeMap<String, CompiledRequestGrantTemplate>,
}

#[derive(Clone, Debug)]
struct CompiledGatewayProfile {
    profile_name: String,
    revision: GatewayProfileRev,
    credential_revocation_floor: GatewayGeneration,
    bearer_credentials: Vec<(BearerTokenHash, VerifiedPrincipal)>,
    client_certificate_credentials: Vec<(ClientCertificateDerSha256, VerifiedPrincipal)>,
    identity_by_principal: BTreeMap<String, CompiledIdentityMapping>,
    surfaces_by_id: BTreeMap<String, CompiledSurfaceDescriptor>,
    surface_bindings_by_principal: BTreeMap<String, CompiledPrincipalSurfaceBinding>,
    authority_anchor: Option<ProcessId>,
    surface_descriptors: Vec<CompiledSurfaceDescriptor>,
    registered_hosts: Vec<GatewayAllowedHost>,
    registered_origins: Vec<GatewayAllowedOrigin>,
    limits: GatewayLimitProfile,
}

fn collect_binding_surface_ids(
    surfaces_by_id: &BTreeMap<String, CompiledSurfaceDescriptor>,
    ids: &[String],
    field: &'static str,
) -> Result<BTreeSet<String>, GatewayError> {
    let mut set = BTreeSet::new();
    for id in ids {
        if id.trim().is_empty() {
            return Err(GatewayError::InvalidProfile(format!(
                "{field} must not contain an empty surface id"
            )));
        }
        if !surfaces_by_id.contains_key(id) {
            return Err(GatewayError::InvalidProfile(format!(
                "{field} references unknown surface {id}"
            )));
        }
        set.insert(id.clone());
    }
    Ok(set)
}

fn validate_gateway_budget_profile(budget: &GatewayBudgetProfile) -> Result<(), GatewayError> {
    validate_optional_budget_limit(budget.max_inflight_ops, "budget.max_inflight_ops")?;
    validate_optional_budget_limit(budget.max_wall_ms, "budget.max_wall_ms")?;
    validate_optional_budget_limit(budget.max_bytes_in, "budget.max_bytes_in")?;
    validate_optional_budget_limit(budget.max_bytes_out, "budget.max_bytes_out")?;
    validate_optional_budget_limit(
        budget.max_inline_value_bytes,
        "budget.max_inline_value_bytes",
    )?;
    validate_optional_budget_limit(budget.max_stream_items, "budget.max_stream_items")?;
    validate_optional_budget_limit(
        budget.max_estimated_cost_micro_usd,
        "budget.max_estimated_cost_micro_usd",
    )?;
    Ok(())
}

fn validate_optional_budget_limit(value: Option<u64>, name: &str) -> Result<(), GatewayError> {
    if value == Some(0) {
        return Err(GatewayError::InvalidProfile(format!(
            "{name} must be positive"
        )));
    }
    Ok(())
}

impl CompiledGatewayProfile {
    fn compile(profile: GatewayProfile) -> Result<Self, GatewayError> {
        if profile.profile_name.trim().is_empty() {
            return Err(GatewayError::InvalidProfile(
                "profile_name must not be empty".into(),
            ));
        }
        if profile.revision == 0 {
            return Err(GatewayError::InvalidProfile(
                "profile revision must be positive".into(),
            ));
        }
        if profile.limits.max_program_nodes == 0
            || profile.limits.max_program_depth == 0
            || profile.limits.max_in_flight_requests == 0
            || profile.limits.max_principal_in_flight_requests == 0
            || profile.limits.max_surface_in_flight_requests == 0
            || profile.limits.max_risk_class_in_flight_requests == 0
            || profile.limits.max_stream_items == 0
            || profile.limits.max_stream_bytes == 0
            || profile.limits.max_stream_inline_item_bytes == 0
        {
            return Err(GatewayError::InvalidProfile(
                "program, depth, in-flight, fair-queue, and stream limits must be positive".into(),
            ));
        }
        validate_gateway_budget_profile(&profile.limits.budget)?;
        if profile.limits.max_deadline_ms_from_now < 0 {
            return Err(GatewayError::InvalidProfile(
                "max_deadline_ms_from_now must not be negative".into(),
            ));
        }
        let mut registered_host_set = BTreeSet::new();
        for host in profile.registered_hosts {
            if !registered_host_set.insert(host.clone()) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate registered host {}",
                    host.as_str()
                )));
            }
        }
        let registered_hosts = registered_host_set.into_iter().collect();

        let mut registered_origin_set = BTreeSet::new();
        for origin in profile.registered_origins {
            if !registered_origin_set.insert(origin.clone()) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate registered origin {}",
                    origin.as_str()
                )));
            }
        }
        let registered_origins = registered_origin_set.into_iter().collect();

        let credential_revocation_floor = profile.credential_revocation_floor;
        let mut identity_by_principal = BTreeMap::new();
        for mapping in profile.identity_mappings {
            if mapping.principal_id.trim().is_empty() {
                return Err(GatewayError::InvalidProfile(
                    "principal_id in identity mapping must not be empty".into(),
                ));
            }
            if mapping.generation == 0 {
                return Err(GatewayError::InvalidProfile(
                    "principal generation must be positive".into(),
                ));
            }
            parse_identity_path(&mapping.identity_path)?;
            if identity_by_principal
                .insert(
                    mapping.principal_id.clone(),
                    CompiledIdentityMapping {
                        identity_path: mapping.identity_path.clone(),
                        enabled: mapping.enabled,
                        generation: mapping.generation,
                    },
                )
                .is_some()
            {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate identity mapping for principal {}",
                    mapping.principal_id
                )));
            }
        }

        let mut credential_ids = BTreeSet::new();
        let mut bearer_hashes = BTreeSet::new();
        let mut bearer_credentials = Vec::new();
        let mut client_certificate_hashes = BTreeSet::new();
        let mut client_certificate_credentials = Vec::new();
        for credential in profile.credentials {
            if credential.credential_id.trim().is_empty() {
                return Err(GatewayError::InvalidProfile(
                    "credential_id must not be empty".into(),
                ));
            }
            if !credential_ids.insert(credential.credential_id.clone()) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate credential_id {}",
                    credential.credential_id
                )));
            }
            if credential.principal_id.trim().is_empty() {
                return Err(GatewayError::InvalidProfile(
                    "credential principal_id must not be empty".into(),
                ));
            }
            if credential.generation == 0 {
                return Err(GatewayError::InvalidProfile(
                    "credential generation must be positive".into(),
                ));
            }
            if !identity_by_principal.contains_key(&credential.principal_id) {
                return Err(GatewayError::InvalidProfile(format!(
                    "credential {} references unmapped principal {}",
                    credential.credential_id, credential.principal_id
                )));
            }
            match credential.kind {
                GatewayCredentialKind::Bearer { token_hash } => {
                    let principal = VerifiedPrincipal {
                        principal_id: credential.principal_id,
                        credential_id: credential.credential_id,
                        credential_generation: credential.generation,
                        principal_generation: 0,
                        auth_method: GatewayAuthMethod::Bearer,
                    };
                    if !bearer_hashes.insert(token_hash.clone()) {
                        return Err(GatewayError::InvalidProfile(
                            "duplicate bearer token hash".into(),
                        ));
                    }
                    if credential.enabled && credential.generation > credential_revocation_floor {
                        bearer_credentials.push((token_hash, principal));
                    }
                }
                GatewayCredentialKind::ClientCertificate { der_sha256 } => {
                    let principal = VerifiedPrincipal {
                        principal_id: credential.principal_id,
                        credential_id: credential.credential_id,
                        credential_generation: credential.generation,
                        principal_generation: 0,
                        auth_method: GatewayAuthMethod::ClientCertificate,
                    };
                    if !client_certificate_hashes.insert(der_sha256.clone()) {
                        return Err(GatewayError::InvalidProfile(
                            "duplicate client certificate DER SHA-256".into(),
                        ));
                    }
                    if credential.enabled && credential.generation > credential_revocation_floor {
                        client_certificate_credentials.push((der_sha256, principal));
                    }
                }
            }
        }

        let mut surface_ids = BTreeSet::new();
        let mut surface_descriptors = Vec::new();
        for surface in profile.surfaces {
            if surface.surface_id.trim().is_empty()
                || surface.method.trim().is_empty()
                || surface.handle_verb.trim().is_empty()
                || surface.grant_template.trim().is_empty()
            {
                return Err(GatewayError::InvalidProfile(
                    "surface id, method, handle verb, and grant template must not be empty".into(),
                ));
            }
            if !surface_ids.insert(surface.surface_id.clone()) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate surface_id {}",
                    surface.surface_id
                )));
            }
            validate_surface_shape(&surface)?;
            let grant_template = Capability::parse(&surface.grant_template)
                .map_err(|e| GatewayError::InvalidProfile(e.to_string()))?;
            if !grant_template.covers(&surface.handle_verb, surface.target.path()) {
                return Err(GatewayError::InvalidProfile(format!(
                    "surface {} grant template does not cover {} on {}",
                    surface.surface_id,
                    surface.handle_verb,
                    surface.target.path()
                )));
            }
            if let Some(publish_capability) = &surface.publish_capability {
                if publish_capability.trim().is_empty() {
                    return Err(GatewayError::InvalidProfile(format!(
                        "surface {} publish_capability must not be empty",
                        surface.surface_id
                    )));
                }
                let publish_capability = Capability::parse(publish_capability)
                    .map_err(|e| GatewayError::InvalidProfile(e.to_string()))?;
                if !publish_capability.covers("publish", surface.target.path()) {
                    return Err(GatewayError::InvalidProfile(format!(
                        "surface {} publish_capability does not cover publish on {}",
                        surface.surface_id,
                        surface.target.path()
                    )));
                }
            }

            let descriptor = CompiledSurfaceDescriptor {
                surface_id: surface.surface_id.clone(),
                kind: surface.kind,
                target: surface.target.clone(),
                method: surface.method.clone(),
                method_bitmap: MethodBitmap::empty(),
                handle_verb: surface.handle_verb.clone(),
                grant_template: surface.grant_template.clone(),
                grant_capability: grant_template.clone(),
                grant_selector: ResourceSelector {
                    pattern: grant_template,
                },
                publish_capability: surface.publish_capability.clone(),
                input_schema: surface.input_schema.clone(),
                input_schema_validator: match &surface.input_schema {
                    Some(schema) => Some(compile_value_schema(
                        schema,
                        &format!("surface {} input_schema", surface.surface_id),
                    )?),
                    None => None,
                },
                output_schema: surface.output_schema.clone(),
                output_schema_validator: match &surface.output_schema {
                    Some(schema) => Some(compile_value_schema(
                        schema,
                        &format!("surface {} output_schema", surface.surface_id),
                    )?),
                    None => None,
                },
            };
            surface_descriptors.push(descriptor.clone());
        }
        let surfaces_by_id: BTreeMap<String, CompiledSurfaceDescriptor> = surface_descriptors
            .iter()
            .map(|surface| (surface.surface_id.clone(), surface.clone()))
            .collect();

        let mut surface_bindings_by_principal = BTreeMap::new();
        for binding in profile.principal_surface_bindings {
            if binding.principal_id.trim().is_empty() {
                return Err(GatewayError::InvalidProfile(
                    "principal surface binding principal_id must not be empty".into(),
                ));
            }
            if !identity_by_principal.contains_key(&binding.principal_id) {
                return Err(GatewayError::InvalidProfile(format!(
                    "surface binding references unmapped principal {}",
                    binding.principal_id
                )));
            }
            if surface_bindings_by_principal.contains_key(&binding.principal_id) {
                return Err(GatewayError::InvalidProfile(format!(
                    "duplicate surface binding for principal {}",
                    binding.principal_id
                )));
            }

            let visible = collect_binding_surface_ids(
                &surfaces_by_id,
                &binding.visible_surfaces,
                "visible_surfaces",
            )?;
            let submit = collect_binding_surface_ids(
                &surfaces_by_id,
                &binding.submit_surfaces,
                "submit_surfaces",
            )?;
            if !submit.is_subset(&visible) {
                return Err(GatewayError::InvalidProfile(format!(
                    "submit_surfaces for principal {} must be a subset of visible_surfaces",
                    binding.principal_id
                )));
            }
            if !submit.is_empty() && binding.capability_ceiling.is_empty() {
                return Err(GatewayError::InvalidProfile(format!(
                    "capability_ceiling for principal {} must not be empty when submit_surfaces is not empty",
                    binding.principal_id
                )));
            }
            let mut capability_ceiling = Vec::new();
            for literal in &binding.capability_ceiling {
                if literal.trim().is_empty() {
                    return Err(GatewayError::InvalidProfile(format!(
                        "capability_ceiling for principal {} must not contain an empty capability",
                        binding.principal_id
                    )));
                }
                capability_ceiling.push(Capability::parse(literal).map_err(|e| {
                    GatewayError::InvalidProfile(format!(
                        "capability_ceiling for principal {} contains invalid capability: {e}",
                        binding.principal_id
                    ))
                })?);
            }
            for surface_id in &submit {
                let Some(surface) = surfaces_by_id.get(surface_id) else {
                    continue;
                };
                if !capability_ceiling
                    .iter()
                    .any(|ceiling| ceiling.covers_cap(&surface.grant_capability))
                {
                    return Err(GatewayError::InvalidProfile(format!(
                        "capability_ceiling for principal {} does not cover surface {} grant template {}",
                        binding.principal_id, surface.surface_id, surface.grant_template
                    )));
                }
            }
            surface_bindings_by_principal.insert(
                binding.principal_id,
                CompiledPrincipalSurfaceBinding {
                    visible,
                    submit,
                    capability_ceiling,
                    request_grants_by_surface: BTreeMap::new(),
                },
            );
        }

        Ok(Self {
            profile_name: profile.profile_name,
            revision: profile.revision,
            credential_revocation_floor,
            bearer_credentials,
            client_certificate_credentials,
            identity_by_principal,
            surfaces_by_id,
            surface_bindings_by_principal,
            authority_anchor: profile.authority_anchor,
            surface_descriptors,
            registered_hosts,
            registered_origins,
            limits: profile.limits,
        })
    }

    fn binding_for_principal(&self, principal_id: &str) -> CompiledPrincipalSurfaceBinding {
        self.surface_bindings_by_principal
            .get(principal_id)
            .cloned()
            .unwrap_or_default()
    }

    fn principal_can_submit(&self, principal_id: &str, surface_id: &str) -> bool {
        self.surface_bindings_by_principal
            .get(principal_id)
            .is_some_and(|binding| binding.submit.contains(surface_id))
    }

    fn operation_surface_for_principal(
        &self,
        principal_id: &str,
        target: &ResourceName,
        method: &str,
    ) -> Option<&CompiledSurfaceDescriptor> {
        let binding = self.surface_bindings_by_principal.get(principal_id)?;
        binding
            .submit
            .iter()
            .filter_map(|surface_id| self.surface_by_id(surface_id))
            .find(|surface| surface.target == *target && surface.method == method)
    }

    fn has_operation_surface(&self, target: &ResourceName, method: &str) -> bool {
        self.surface_descriptors
            .iter()
            .any(|surface| surface.target == *target && surface.method == method)
    }

    fn surface_by_id(&self, surface_id: &str) -> Option<&CompiledSurfaceDescriptor> {
        self.surfaces_by_id.get(surface_id)
    }

    fn surface_descriptors_for_ids<'a>(
        &'a self,
        surface_ids: &BTreeSet<String>,
    ) -> Result<Vec<&'a CompiledSurfaceDescriptor>, GatewayError> {
        let mut surfaces = Vec::new();
        for surface_id in surface_ids {
            let Some(surface) = self.surface_by_id(surface_id) else {
                return Err(GatewayError::Rejected(format!(
                    "unknown gateway surface {surface_id}"
                )));
            };
            surfaces.push(surface);
        }
        Ok(surfaces)
    }

    fn verify_bearer(&self, token: &BearerToken) -> Result<VerifiedPrincipal, GatewayError> {
        let hash = hash_bearer_token(token.as_str());
        let mut verified = None;
        for (stored_hash, principal) in &self.bearer_credentials {
            if stored_hash.0.as_bytes().ct_eq(hash.as_bytes()).into() {
                let Some(mapping) = self.identity_by_principal.get(&principal.principal_id) else {
                    continue;
                };
                if mapping.enabled {
                    let mut principal = principal.clone();
                    principal.principal_generation = mapping.generation;
                    verified = Some(principal);
                }
            }
        }
        verified.ok_or(GatewayError::Unauthenticated)
    }

    fn verify_client_certificate(
        &self,
        credential: &ClientCertificateCredential,
    ) -> Result<VerifiedPrincipal, GatewayError> {
        let mut verified = None;
        for (stored_hash, principal) in &self.client_certificate_credentials {
            if stored_hash
                .0
                .as_bytes()
                .ct_eq(credential.der_sha256.0.as_bytes())
                .into()
            {
                let Some(mapping) = self.identity_by_principal.get(&principal.principal_id) else {
                    continue;
                };
                if mapping.enabled {
                    let mut principal = principal.clone();
                    principal.principal_generation = mapping.generation;
                    verified = Some(principal);
                }
            }
        }
        verified.ok_or(GatewayError::Unauthenticated)
    }

    fn has_authenticating_credentials(&self) -> bool {
        !self.bearer_credentials.is_empty() || !self.client_certificate_credentials.is_empty()
    }

    fn session_identity_path(&self, session: &GatewaySession) -> Result<&str, GatewayError> {
        let mapping = self
            .identity_by_principal
            .get(&session.principal.principal_id)
            .ok_or_else(|| GatewayError::Unauthorized(session.principal.principal_id.clone()))?;
        if !mapping.enabled
            || session.principal.principal_generation != mapping.generation
            || session.identity_path != mapping.identity_path
        {
            return Err(GatewayError::Rejected(
                "gateway session principal generation is stale".into(),
            ));
        }
        if session.principal.credential_generation <= self.credential_revocation_floor {
            return Err(GatewayError::Rejected(
                "gateway session credential generation is revoked".into(),
            ));
        }
        let credential_still_active = match session.principal.auth_method {
            GatewayAuthMethod::Bearer => self.bearer_credentials.iter().any(|(_, principal)| {
                principal.credential_id == session.principal.credential_id
                    && principal.credential_generation == session.principal.credential_generation
                    && principal.principal_id == session.principal.principal_id
            }),
            GatewayAuthMethod::ClientCertificate => {
                self.client_certificate_credentials
                    .iter()
                    .any(|(_, principal)| {
                        principal.credential_id == session.principal.credential_id
                            && principal.credential_generation
                                == session.principal.credential_generation
                            && principal.principal_id == session.principal.principal_id
                    })
            }
        };
        if !credential_still_active {
            return Err(GatewayError::Rejected(
                "gateway session credential generation is stale".into(),
            ));
        }
        Ok(mapping.identity_path.as_str())
    }
}

fn validate_surface_shape(surface: &GatewaySurface) -> Result<(), GatewayError> {
    match surface.kind {
        GatewaySurfaceKind::EffectMethod => {
            if surface.target.path().scheme() != "effect" {
                return Err(GatewayError::InvalidProfile(format!(
                    "effect_method surface {} must target effect://",
                    surface.surface_id
                )));
            }
        }
        GatewaySurfaceKind::StateAppend => {
            if surface.target.path().scheme() != "state" {
                return Err(GatewayError::InvalidProfile(format!(
                    "state_append surface {} must target state://",
                    surface.surface_id
                )));
            }
            if surface.method != "append" || surface.handle_verb != "append" {
                return Err(GatewayError::InvalidProfile(format!(
                    "state_append surface {} must use append method and handle verb",
                    surface.surface_id
                )));
            }
        }
    }
    Ok(())
}

/// Authenticated, redacted profile descriptor returned by gateway discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDescriptor {
    /// Active profile name.
    pub profile_name: String,
    /// Active profile revision.
    pub profile_rev: GatewayProfileRev,
    /// Profile surfaces visible to the authenticated session.
    pub surfaces: Vec<GatewaySurfaceDescriptor>,
    /// Effective Program admission limits for this profile.
    pub limits: GatewayLimitProfile,
}

/// Readiness state for a gateway runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayReadiness {
    /// The active profile can authenticate clients.
    Ready,
    /// The active profile is serving as the last known good snapshot.
    DegradedLastKnownGood,
    /// The active profile is closed and authenticates nobody.
    NotReadyClosed,
}

impl GatewayReadiness {
    /// Return the stable status label for this readiness state.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::DegradedLastKnownGood => "degraded_lkg",
            Self::NotReadyClosed => "not_ready_closed",
        }
    }
}

/// Redacted metadata for the most recent failed profile reload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayProfileReloadFailure {
    /// Profile revision supplied by the failed reload attempt.
    pub attempted_profile_rev: GatewayProfileRev,
    /// Stable low-cardinality failure code.
    pub code: String,
    /// Public failure summary.
    pub public_message: String,
}

/// Redacted runtime status for health and diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRuntimeStatus {
    /// Active profile name.
    pub profile_name: String,
    /// Active profile revision.
    pub profile_rev: GatewayProfileRev,
    /// True when the runtime can authenticate at least one client.
    pub ready: bool,
    /// Current readiness class.
    pub readiness: GatewayReadiness,
    /// True when a failed reload left the previous snapshot active.
    pub lkg_active: bool,
    /// Consecutive failed reload attempts since the last successful swap.
    pub consecutive_failed_reloads: u64,
    /// Most recent redacted reload failure, if any.
    pub last_reload_failure: Option<GatewayProfileReloadFailure>,
}

/// One profile surface visible through authenticated discovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySurfaceDescriptor {
    /// Stable surface id within the profile.
    pub surface_id: String,
    /// Surface kind.
    pub kind: GatewaySurfaceKind,
    /// Resource target exposed through this surface.
    pub target: ResourceName,
    /// Method name accepted by this surface.
    pub method: String,
    /// Verb used when opening a Process-owned Handle for this resource.
    pub handle_verb: String,
    /// Capability literal used as the request Process grant template.
    pub grant_template: String,
    /// Capability literal required before this surface may be published.
    pub publish_capability: Option<String>,
    /// Input schema descriptor advertised for this surface.
    pub input_schema: Option<Value>,
    /// Output schema descriptor advertised for this surface.
    pub output_schema: Option<Value>,
}

/// Client options attached to one Gateway submission.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubmitOptions {
    /// Client supplied idempotency key for non-idempotent retry boundaries.
    pub idempotency_key: Option<String>,
    /// Server-issued token for retry-safe non-idempotent submission.
    pub submission_token: Option<String>,
    /// Client requested deadline in milliseconds since unix epoch. The server
    /// clamps this against the profile; clients cannot extend server limits.
    pub deadline_ms: Option<u64>,
    /// Requested transport encoding. Runtime admission records it but does not
    /// trust it as an authorization input.
    pub requested_encoding: Option<String>,
}

/// A typed submission accepted by the gateway runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySubmission {
    /// Surface boundary selected by the client. For direct input this is
    /// mandatory and determines target/method/output/capability.
    pub surface_id: String,
    /// Submitted body.
    pub body: GatewaySubmissionBody,
    /// Requested output mode for direct input lowering.
    pub requested_output: OutputMode,
    /// Retry/deadline/encoding options.
    pub options: SubmitOptions,
}

impl GatewaySubmission {
    /// Submit a full program. A non-empty `surface_id` is validated as an
    /// existing surface, but program internals are still inspected operation by
    /// operation. An empty surface id is accepted for pure/inert programs.
    pub fn program(surface_id: impl Into<String>, program: DoNode) -> Self {
        Self {
            surface_id: surface_id.into(),
            body: GatewaySubmissionBody::Program(ProgramSubmission::new(program)),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
        }
    }

    /// Submit one direct `Value` through an effect-method surface.
    pub fn direct_input(surface_id: impl Into<String>, payload: Value) -> Self {
        Self {
            surface_id: surface_id.into(),
            body: GatewaySubmissionBody::DirectInput(GatewayDirectInput {
                payload,
                provenance: None,
            }),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
        }
    }

    /// Attach provenance to a direct input or program submission.
    pub fn with_provenance(mut self, provenance: GatewayPayloadProvenance) -> Self {
        match &mut self.body {
            GatewaySubmissionBody::DirectInput(input) => input.provenance = Some(provenance),
            GatewaySubmissionBody::Program(program) => program.provenance = Some(provenance),
            GatewaySubmissionBody::InputStream(_) => {}
        }
        self
    }

    /// Set the requested output mode.
    pub fn with_requested_output(mut self, output: OutputMode) -> Self {
        self.requested_output = output;
        self
    }

    /// Replace submission options.
    pub fn with_options(mut self, options: SubmitOptions) -> Self {
        self.options = options;
        self
    }
}

/// Server-generated acceptance metadata for one Gateway submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAccepted {
    /// Collision-resistant server authority for cancellation and replay.
    pub submission_id: String,
    /// Trace identity generated independently from `submission_id`.
    pub trace_root: String,
    /// Profile revision that admitted the request.
    pub profile_rev: GatewayProfileRev,
    /// Surface boundary used for admission, if one was selected.
    pub surface_id: String,
}

/// Result of a completed Gateway submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySubmitResult {
    /// Server acceptance metadata for the request.
    pub accepted: GatewayAccepted,
    /// Kernel execution outcome.
    pub outcome: Outcome,
}

/// Result of admitting the first `SubmitStream` frame.
pub enum GatewayInputStreamStart {
    /// A new stream request was admitted and chunks may now be delivered.
    Accepted(Box<GatewayAcceptedInputStream>),
    /// The idempotency record was already completed; no chunks are needed.
    Replay(Box<GatewaySubmitResult>),
}

/// Runtime-owned admission context for one accepted client input stream.
pub struct GatewayAcceptedInputStream {
    accepted: GatewayAccepted,
    open: GatewayStreamOpenRequest,
    limits: GatewayLimitProfile,
    profile: Arc<CompiledGatewayProfile>,
    session: GatewaySession,
    surface_id: String,
    requested_output: OutputMode,
    options: SubmitOptions,
    idempotency: Option<Box<GatewayIdempotencyReservation>>,
    request_guard: GatewayRequestGuard,
    request_process: ProcessId,
    executor: Executor,
}

impl GatewayAcceptedInputStream {
    /// Return the server acceptance metadata bound to this stream.
    pub fn accepted(&self) -> &GatewayAccepted {
        &self.accepted
    }

    /// Return the admitted stream declaration.
    pub fn open_request(&self) -> &GatewayStreamOpenRequest {
        &self.open
    }

    /// Return the profile limits that bound the stream chunks.
    pub fn limits(&self) -> &GatewayLimitProfile {
        &self.limits
    }

    /// Validate one decoded input stream item against the admitted surface.
    pub fn validate_chunk_item(&self, item: &Value) -> Result<(), GatewayError> {
        let surface = self
            .profile
            .surface_by_id(&self.surface_id)
            .ok_or_else(|| {
                GatewayError::Rejected("stream surface is no longer available".into())
            })?;
        validate_surface_stream_item(surface, self.open.modality, item)
    }
}

impl PartialEq<Outcome> for GatewaySubmitResult {
    fn eq(&self, other: &Outcome) -> bool {
        self.outcome == *other
    }
}

impl PartialEq<GatewaySubmitResult> for Outcome {
    fn eq(&self, other: &GatewaySubmitResult) -> bool {
        *self == other.outcome
    }
}

/// Cancellation request scoped to the authenticated principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayCancelRequest {
    /// Server-generated submission id returned by `submit`.
    pub submission_id: String,
    /// Trace root returned with the same submission.
    pub trace_root: String,
    /// Optional caller-visible reason for audit or transport delivery.
    pub reason: Option<String>,
}

/// Runtime state tracked for a Gateway request registry entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayRequestState {
    /// The request is admitted and its Process may still execute.
    Running,
    /// The request completed with `Outcome::Done` or `Outcome::Short`.
    Completed,
    /// The request completed with `Outcome::Fail`.
    Failed,
    /// The request was cancelled by its owner.
    Cancelled,
}

/// Large-value metadata retained by the request registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayLargeValueRefSummary {
    /// BLAKE3 content hash.
    pub hash: String,
    /// Declared byte size.
    pub size: u64,
    /// Optional media type.
    pub mime: Option<String>,
}

/// In-memory request registry entry used for cancellation and short retention.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRequestEntry {
    /// Server acceptance metadata.
    pub accepted: GatewayAccepted,
    /// Request Process created for this submission.
    pub request_process: ProcessId,
    /// Gateway identifier for authorization checks.
    pub gateway_id: String,
    /// Authenticated principal id.
    pub principal_id: String,
    /// Request state.
    pub state: GatewayRequestState,
    /// Server-clock deadline, when one was supplied.
    pub deadline_at_ms: Option<i64>,
    /// Internal budget reservation held while the request is running.
    pub budget_reservation_id: u64,
    /// Short retention cutoff after terminal state.
    pub retained_until_ms: i64,
    /// Risk class used by fair admission counters.
    pub risk_class: String,
    /// Surfaces charged by fair admission.
    pub surface_ids: Vec<String>,
    /// Large-value references summarized without storing bytes.
    pub large_value_refs: Vec<GatewayLargeValueRefSummary>,
    admission_released: bool,
}

/// The body of a Gateway submission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GatewaySubmissionBody {
    /// Full structured execution submission.
    Program(ProgramSubmission),
    /// Direct kernel `Value` input lowered by the selected surface.
    DirectInput(GatewayDirectInput),
    /// Stream-open request admitted before transport chunks are folded into a
    /// direct input payload.
    InputStream(GatewayStreamOpenRequest),
}

/// Direct input payload. The payload is exactly the kernel `Value`; large refs
/// are expressed as `Value::{Blob,Tensor,Frame}` and require provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayDirectInput {
    /// Kernel value supplied by the client.
    pub payload: Value,
    /// Provenance for inbound large refs.
    pub provenance: Option<GatewayPayloadProvenance>,
}

/// Source proof for inbound `Value::{Blob,Tensor,Frame}` refs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayPayloadProvenance {
    /// Upload ticket issued by this Gateway/profile.
    pub upload_ticket: Option<String>,
    /// Trusted object-store proof.
    pub store_proof: Option<ObjectStoreProof>,
}

/// Opaque proof returned by a trusted object store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectStoreProof {
    /// Store identity.
    pub store_id: String,
    /// Store-generated proof blob, token, or receipt id.
    pub proof: String,
}

/// Request to issue a short-lived object upload ticket for one surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueObjectUploadTicketRequest {
    /// Surface the future object reference will be submitted through.
    pub surface_id: String,
    /// Optional submission token the ticket is bound to.
    pub submission_token: Option<String>,
    /// Expected object modality.
    pub modality: GatewayModality,
    /// Optional expected byte size.
    pub expected_size: Option<u64>,
    /// Optional expected lowercase BLAKE3 digest.
    pub expected_digest: Option<String>,
    /// Optional allowed media type patterns, for example `image/*`.
    pub allowed_media_types: Vec<String>,
    /// Requested TTL from server issue time.
    pub expires_in_ms: Option<u64>,
    /// Whether the ticket is consumed by the first successful commit/use.
    pub single_use: bool,
}

/// Request to commit bytes against an issued object upload ticket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitObjectUploadRequest {
    /// Ticket id returned by [`Gateway::issue_object_upload_ticket`].
    pub ticket_id: String,
    /// Bytes to store under `state://blob/<blake3>`.
    pub bytes: Vec<u8>,
    /// Optional media type for generated `Value::Blob` refs.
    pub media_type: Option<String>,
    /// Optional typed large-object value. If omitted, a `Value::Blob` is returned.
    pub item: Option<Value>,
    /// Optional submission token that must match a token-bound ticket.
    pub submission_token: Option<String>,
}

/// Response returned after object bytes have been committed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitObjectUploadResponse {
    /// Typed item to use as direct input provenance.
    pub item: Value,
    /// Store proof bound to the committed item, principal, and surface.
    pub provenance: GatewayPayloadProvenance,
    /// Lowercase BLAKE3 digest of committed bytes.
    pub digest: String,
    /// Committed byte size.
    pub size: u64,
}

/// Stream-open request carried on streaming transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayStreamOpenRequest {
    /// Client stream id, scoped to a single submission.
    pub stream_id: String,
    /// Declared direction.
    pub direction: GatewayStreamDirection,
    /// Declared modality.
    pub modality: GatewayModality,
    /// Profile-selected stream item schema id; client requests leave it empty.
    pub item_schema_id: String,
    /// Maximum inline item bytes requested by the client.
    pub max_inline_item_bytes: u64,
    /// Optional item cap.
    pub max_items: Option<u64>,
    /// Optional byte cap.
    pub max_bytes: Option<u64>,
}

/// Gateway stream direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayStreamDirection {
    /// Client sends items to kernel.
    ClientToKernel,
    /// Kernel sends items to client.
    KernelToClient,
    /// State subscription delivery to client.
    StateSubscriptionToClient,
}

/// Transport modality aligned to kernel `Value`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayModality {
    Value,
    Text,
    Bytes,
    Tensor,
    AudioFrame,
    VideoFrame,
    PoseFrame,
    SensorFrame,
    Event,
    Control,
}

/// One stream item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayStreamChunk {
    pub stream_id: String,
    pub seq: u64,
    pub item: Value,
    pub provenance: Option<GatewayPayloadProvenance>,
}

/// Terminal stream marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayStreamEnd {
    pub stream_id: String,
    pub seq: u64,
    pub marker: StreamMarker,
}

/// A typed program body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramSubmission {
    /// Submitted program.
    pub program: DoNode,
    /// Provenance for inbound large refs embedded in the program.
    pub provenance: Option<GatewayPayloadProvenance>,
    /// Client supplied idempotency key for non-idempotent retry boundaries.
    pub idempotency_key: Option<String>,
    /// Client supplied submission id for correlation. It is not authority.
    pub client_submission_id: Option<String>,
}

impl ProgramSubmission {
    /// Create a submission for one program.
    pub fn new(program: DoNode) -> Self {
        Self {
            program,
            provenance: None,
            idempotency_key: None,
            client_submission_id: None,
        }
    }
}

impl From<DoNode> for ProgramSubmission {
    fn from(program: DoNode) -> Self {
        Self::new(program)
    }
}

impl From<ProgramSubmission> for GatewaySubmission {
    fn from(submission: ProgramSubmission) -> Self {
        Self {
            surface_id: String::new(),
            body: GatewaySubmissionBody::Program(submission),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
        }
    }
}

/// Static inspection result for an admitted program.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProgramInspection {
    /// Number of `DoNode` nodes.
    pub node_count: usize,
    /// Maximum structural depth.
    pub max_depth: usize,
    /// Estimated inline literal bytes.
    pub literal_bytes: usize,
    /// Number of operation leaves.
    pub operation_count: usize,
    /// Estimated operation cost in micro-USD.
    pub estimated_cost_micro_usd: u64,
    /// Number of `Acting` nodes.
    pub acting_count: usize,
    /// Number of `StepRef` continuations.
    pub step_ref_count: usize,
    /// Number of `Wait(Signal)` nodes.
    pub wait_signal_count: usize,
    /// Number of `Wait(Deadline)` nodes.
    pub wait_deadline_count: usize,
}

/// The shared gateway contract. Implementors verify credentials, map them to a
/// session, and run typed submissions through a profile-bound runtime.
#[async_trait]
pub trait Gateway: Send + Sync {
    /// Return redacted runtime status for transport handshakes and health.
    fn status(&self) -> GatewayRuntimeStatus;

    /// Return Host/SNI authorities currently registered for this listener.
    fn registered_gateway_hosts(&self) -> Vec<GatewayAllowedHost> {
        Vec::new()
    }

    /// Return browser origins currently registered for browser transports.
    fn registered_browser_origins(&self) -> Vec<GatewayAllowedOrigin> {
        Vec::new()
    }

    /// Verify a credential and create a Gateway session.
    async fn authenticate(
        &self,
        credential: PresentedCredential,
    ) -> Result<GatewaySession, GatewayError>;

    /// Describe the active profile for an authenticated session.
    ///
    /// This is intentionally authenticated: unauthenticated discovery must not
    /// expose resource paths, effect names, capability literals, or limits.
    fn describe(&self, session: &GatewaySession) -> Result<GatewayDescriptor, GatewayError>;

    /// Admit and run one Gateway submission as the session identity.
    async fn submit(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        self.submit_with_acceptance(session, submission, None).await
    }

    /// Admit and run one submission, optionally notifying the transport as soon
    /// as the request registry entry exists.
    async fn submit_with_acceptance(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
        accepted: Option<tokio::sync::oneshot::Sender<GatewayAccepted>>,
    ) -> Result<GatewaySubmitResult, GatewayError>;

    /// Admit a stream-open submission before accepting stream chunks.
    async fn accept_input_stream_submission(
        &self,
        _session: &GatewaySession,
        _submission: GatewaySubmission,
    ) -> Result<GatewayInputStreamStart, GatewayError> {
        Err(GatewayError::Rejected(
            "input stream submissions are not supported by this gateway".into(),
        ))
    }

    /// Complete an admitted input stream with the folded payload.
    async fn complete_input_stream_submission(
        &self,
        _stream: GatewayAcceptedInputStream,
        _payload: Value,
        _provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        Err(GatewayError::Rejected(
            "input stream submissions are not supported by this gateway".into(),
        ))
    }

    /// Mark an admitted input stream failed before dispatch.
    async fn fail_input_stream_submission(
        &self,
        _stream: GatewayAcceptedInputStream,
        _reason: &str,
    ) -> Result<(), GatewayError> {
        Ok(())
    }

    /// Cancel an admitted request owned by the authenticated principal.
    fn cancel(
        &self,
        session: &GatewaySession,
        request: GatewayCancelRequest,
    ) -> Result<bool, GatewayError>;

    /// Issue a ticket for a subsequent object upload/commit.
    async fn issue_object_upload_ticket(
        &self,
        _session: &GatewaySession,
        _request: IssueObjectUploadTicketRequest,
    ) -> Result<GatewayObjectUploadTicket, GatewayError> {
        Err(GatewayError::Rejected(
            "object upload tickets are not supported by this gateway".into(),
        ))
    }

    /// Commit uploaded object bytes and return the typed large-object value.
    async fn commit_object_upload(
        &self,
        _session: &GatewaySession,
        _request: CommitObjectUploadRequest,
    ) -> Result<CommitObjectUploadResponse, GatewayError> {
        Err(GatewayError::Rejected(
            "object upload commit is not supported by this gateway".into(),
        ))
    }

    /// Record gateway-local audit metadata for an inbound request.
    ///
    /// The default implementation is a no-op for test gateways. Production
    /// gateways should forward the record to the kernel audit path so protocol
    /// authentication and admission decisions remain visible.
    fn record_gateway_audit(&self, _audit: GatewayAudit<'_>) -> Result<(), String> {
        Ok(())
    }
}

/// Profile-driven in-process Gateway runtime over a [`Bootstrap`].
///
/// Every submitted program is statically admitted, stamped with inbound taint,
/// then executed as a fresh attenuated child Process. Handles are opened per
/// request Process from profile surfaces, preserving Handle ownership.
pub struct GatewayRuntime {
    boot: Arc<Bootstrap>,
    state: RwLock<GatewayRuntimeState>,
    requests: Arc<GatewayRequestRegistry>,
}

struct GatewayRuntimeState {
    profile: Arc<CompiledGatewayProfile>,
    lkg_active: bool,
    consecutive_failed_reloads: u64,
    last_reload_failure: Option<GatewayProfileReloadFailure>,
}

#[derive(Debug, Default)]
struct GatewayRequestRegistry {
    inner: Mutex<GatewayRequestRegistryInner>,
}

#[derive(Debug, Default)]
struct GatewayRequestRegistryInner {
    entries: BTreeMap<String, GatewayRequestEntry>,
    global_running: usize,
    principal_running: BTreeMap<String, usize>,
    surface_running: BTreeMap<String, usize>,
    risk_running: BTreeMap<String, usize>,
    budget_running: GatewayBudgetCharge,
    budget_reservations: BTreeMap<u64, GatewayBudgetCharge>,
    next_budget_reservation_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GatewayExpiredRequest {
    request_process: ProcessId,
}

#[derive(Debug)]
struct GatewayAdmissionGuard {
    registry: Arc<GatewayRequestRegistry>,
    principal_id: String,
    surface_ids: Vec<String>,
    risk_class: String,
    released: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct GatewayBudgetCharge {
    inflight_ops: u64,
    wall_ms: u64,
    bytes_in: u64,
    bytes_out: u64,
    inline_value_bytes: u64,
    stream_items: u64,
    estimated_cost_micro_usd: u64,
}

#[derive(Debug)]
struct GatewayBudgetGuard {
    registry: Arc<GatewayRequestRegistry>,
    reservation_id: u64,
    released: bool,
}

#[derive(Debug)]
struct GatewayRequestGuard {
    registry: Arc<GatewayRequestRegistry>,
    submission_id: String,
    admission: Option<GatewayAdmissionGuard>,
    budget: Option<GatewayBudgetGuard>,
    finished: bool,
}

impl GatewayRequestRegistry {
    fn new() -> Self {
        Self::default()
    }

    fn new_acceptance(
        &self,
        profile_rev: GatewayProfileRev,
        surface_id: String,
    ) -> Result<GatewayAccepted, GatewayError> {
        for _ in 0..8 {
            let accepted = GatewayAccepted {
                submission_id: random_gateway_id("gw-submission", profile_rev)?,
                trace_root: random_gateway_id("gw-trace", profile_rev)?,
                profile_rev,
                surface_id: surface_id.clone(),
            };
            if !self
                .inner
                .lock()
                .entries
                .contains_key(&accepted.submission_id)
            {
                return Ok(accepted);
            }
        }
        Err(GatewayError::LimitExceeded(
            "submission id collision retry limit exceeded".into(),
        ))
    }

    fn try_reserve_budget(
        self: &Arc<Self>,
        budget: &GatewayBudgetProfile,
        charge: GatewayBudgetCharge,
    ) -> Result<GatewayBudgetGuard, GatewayError> {
        let mut inner = self.inner.lock();
        ensure_budget_capacity(
            budget.max_inflight_ops,
            inner.budget_running.inflight_ops,
            charge.inflight_ops,
            "gateway budget in-flight ops",
        )?;
        ensure_budget_capacity(
            budget.max_wall_ms,
            inner.budget_running.wall_ms,
            charge.wall_ms,
            "gateway budget wall-ms",
        )?;
        ensure_budget_capacity(
            budget.max_bytes_in,
            inner.budget_running.bytes_in,
            charge.bytes_in,
            "gateway budget bytes-in",
        )?;
        ensure_budget_capacity(
            budget.max_bytes_out,
            inner.budget_running.bytes_out,
            charge.bytes_out,
            "gateway budget bytes-out",
        )?;
        ensure_budget_capacity(
            budget.max_inline_value_bytes,
            inner.budget_running.inline_value_bytes,
            charge.inline_value_bytes,
            "gateway budget inline value bytes",
        )?;
        ensure_budget_capacity(
            budget.max_stream_items,
            inner.budget_running.stream_items,
            charge.stream_items,
            "gateway budget stream items",
        )?;
        ensure_budget_capacity(
            budget.max_estimated_cost_micro_usd,
            inner.budget_running.estimated_cost_micro_usd,
            charge.estimated_cost_micro_usd,
            "gateway budget estimated cost",
        )?;

        inner.next_budget_reservation_id = inner.next_budget_reservation_id.saturating_add(1);
        let reservation_id = inner.next_budget_reservation_id;
        inner.budget_running = add_budget_charge(inner.budget_running, charge);
        inner.budget_reservations.insert(reservation_id, charge);
        Ok(GatewayBudgetGuard {
            registry: self.clone(),
            reservation_id,
            released: false,
        })
    }

    fn try_admit(
        self: &Arc<Self>,
        limits: &GatewayLimitProfile,
        principal_id: String,
        surface_ids: Vec<String>,
        risk_class: String,
    ) -> Result<GatewayAdmissionGuard, GatewayError> {
        let mut inner = self.inner.lock();
        if inner.global_running >= limits.max_in_flight_requests {
            return Err(GatewayError::LimitExceeded(
                "global in-flight request limit".into(),
            ));
        }
        let principal_limit = effective_fair_counter_limit(
            limits.max_principal_in_flight_requests,
            limits.max_in_flight_requests,
        );
        if counter_value(&inner.principal_running, &principal_id) >= principal_limit {
            return Err(GatewayError::LimitExceeded(
                "principal in-flight request limit".into(),
            ));
        }
        let surface_limit = effective_fair_counter_limit(
            limits.max_surface_in_flight_requests,
            limits.max_in_flight_requests,
        );
        for surface_id in &surface_ids {
            if counter_value(&inner.surface_running, surface_id) >= surface_limit {
                return Err(GatewayError::LimitExceeded(
                    "surface in-flight request limit".into(),
                ));
            }
        }
        let risk_limit = effective_fair_counter_limit(
            limits.max_risk_class_in_flight_requests,
            limits.max_in_flight_requests,
        );
        if counter_value(&inner.risk_running, &risk_class) >= risk_limit {
            return Err(GatewayError::LimitExceeded(
                "risk-class in-flight request limit".into(),
            ));
        }

        inner.global_running = inner.global_running.saturating_add(1);
        increment_counter(&mut inner.principal_running, &principal_id);
        for surface_id in &surface_ids {
            increment_counter(&mut inner.surface_running, surface_id);
        }
        increment_counter(&mut inner.risk_running, &risk_class);

        Ok(GatewayAdmissionGuard {
            registry: self.clone(),
            principal_id,
            surface_ids,
            risk_class,
            released: false,
        })
    }

    fn insert_running(
        self: &Arc<Self>,
        entry: GatewayRequestEntry,
        admission: GatewayAdmissionGuard,
        budget: GatewayBudgetGuard,
    ) -> Result<GatewayRequestGuard, GatewayError> {
        let submission_id = entry.accepted.submission_id.clone();
        let mut inner = self.inner.lock();
        prune_completed_requests(&mut inner, now_millis());
        if inner.entries.contains_key(&submission_id) {
            return Err(GatewayError::LimitExceeded(
                "submission id collision".into(),
            ));
        }
        inner.entries.insert(submission_id.clone(), entry);
        Ok(GatewayRequestGuard {
            registry: self.clone(),
            submission_id,
            admission: Some(admission),
            budget: Some(budget),
            finished: false,
        })
    }

    fn finish(&self, submission_id: &str, state: GatewayRequestState, now_ms: i64) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.entries.get_mut(submission_id) {
            if entry.state == GatewayRequestState::Running {
                entry.state = state;
            }
            entry.retained_until_ms = now_ms.saturating_add(COMPLETED_REQUEST_RETENTION_MS);
        }
        prune_completed_requests(&mut inner, now_ms);
    }

    fn cancel(
        &self,
        session: &GatewaySession,
        request: &GatewayCancelRequest,
        boot: &Bootstrap,
    ) -> Result<bool, GatewayError> {
        if request.submission_id.trim().is_empty() || request.trace_root.trim().is_empty() {
            return Ok(false);
        }
        let process = {
            let mut inner = self.inner.lock();
            let Some(entry) = inner.entries.get_mut(&request.submission_id) else {
                return Ok(false);
            };
            if entry.principal_id != session.principal.principal_id
                || entry.gateway_id != session.profile_name
                || entry.accepted.trace_root != request.trace_root
            {
                return Ok(false);
            }
            if entry.state != GatewayRequestState::Running {
                return Ok(matches!(entry.state, GatewayRequestState::Cancelled));
            }
            entry.state = GatewayRequestState::Cancelled;
            entry.retained_until_ms = now_millis().saturating_add(COMPLETED_REQUEST_RETENTION_MS);
            let process = entry.request_process;
            let budget_reservation_id = entry.budget_reservation_id;
            release_entry_admission(&mut inner, &request.submission_id);
            release_budget_reservation(&mut inner, budget_reservation_id);
            process
        };
        boot.kernel
            .processes
            .set_status(process, ProcessStatus::Cancelled);
        Ok(true)
    }

    fn release_admission(&self, admission: &GatewayAdmissionGuard) {
        let mut inner = self.inner.lock();
        decrement_admission_counters(
            &mut inner,
            &admission.principal_id,
            &admission.surface_ids,
            &admission.risk_class,
        );
    }

    fn release_entry_admission(&self, submission_id: &str, _admission: &GatewayAdmissionGuard) {
        let mut inner = self.inner.lock();
        release_entry_admission(&mut inner, submission_id);
    }

    fn release_budget(&self, reservation_id: u64) {
        let mut inner = self.inner.lock();
        release_budget_reservation(&mut inner, reservation_id);
    }

    fn expire_deadlines(&self, now_ms: i64) -> Vec<GatewayExpiredRequest> {
        let mut inner = self.inner.lock();
        let mut expired = Vec::new();
        let mut budget_reservations = Vec::new();
        let mut admission_submissions = Vec::new();
        for (submission_id, entry) in inner.entries.iter_mut() {
            if entry.state != GatewayRequestState::Running {
                continue;
            }
            let Some(deadline_at_ms) = entry.deadline_at_ms else {
                continue;
            };
            if deadline_at_ms > now_ms {
                continue;
            }
            entry.state = GatewayRequestState::Failed;
            entry.retained_until_ms = now_ms.saturating_add(COMPLETED_REQUEST_RETENTION_MS);
            expired.push(GatewayExpiredRequest {
                request_process: entry.request_process,
            });
            admission_submissions.push(submission_id.clone());
            budget_reservations.push(entry.budget_reservation_id);
        }
        for submission_id in admission_submissions {
            release_entry_admission(&mut inner, &submission_id);
        }
        for reservation_id in budget_reservations {
            release_budget_reservation(&mut inner, reservation_id);
        }
        prune_completed_requests(&mut inner, now_ms);
        expired
    }
}

impl GatewayAdmissionGuard {
    fn release(&mut self) {
        if self.released {
            return;
        }
        self.registry.release_admission(self);
        self.released = true;
    }

    fn release_for_submission(&mut self, submission_id: &str) {
        if self.released {
            return;
        }
        self.registry.release_entry_admission(submission_id, self);
        self.released = true;
    }
}

impl Drop for GatewayAdmissionGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl GatewayBudgetGuard {
    fn release(&mut self) {
        if self.released {
            return;
        }
        self.registry.release_budget(self.reservation_id);
        self.released = true;
    }
}

impl Drop for GatewayBudgetGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl GatewayRequestGuard {
    fn finish(mut self, outcome: &Outcome) {
        let state = match outcome {
            Outcome::Done(_) | Outcome::Short(_) => GatewayRequestState::Completed,
            Outcome::Fail(_) => GatewayRequestState::Failed,
        };
        self.registry
            .finish(&self.submission_id, state, now_millis());
        self.finished = true;
        if let Some(mut admission) = self.admission.take() {
            admission.release_for_submission(&self.submission_id);
        }
        if let Some(mut budget) = self.budget.take() {
            budget.release();
        }
    }
}

impl Drop for GatewayRequestGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.registry.finish(
                &self.submission_id,
                GatewayRequestState::Failed,
                now_millis(),
            );
        }
        if let Some(mut admission) = self.admission.take() {
            admission.release_for_submission(&self.submission_id);
        }
        if let Some(mut budget) = self.budget.take() {
            budget.release();
        }
    }
}

fn effective_fair_counter_limit(configured_limit: usize, global_limit: usize) -> usize {
    configured_limit.min(fair_counter_limit(global_limit))
}

fn fair_counter_limit(global_limit: usize) -> usize {
    match global_limit {
        0 | 1 => global_limit,
        n => n.saturating_sub(1).max(1),
    }
}

fn counter_value(map: &BTreeMap<String, usize>, key: &str) -> usize {
    map.get(key).copied().unwrap_or(0)
}

fn increment_counter(map: &mut BTreeMap<String, usize>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
}

fn decrement_counter(map: &mut BTreeMap<String, usize>, key: &str) {
    let Some(count) = map.get_mut(key) else {
        return;
    };
    *count = count.saturating_sub(1);
    if *count == 0 {
        map.remove(key);
    }
}

fn decrement_admission_counters(
    inner: &mut GatewayRequestRegistryInner,
    principal_id: &str,
    surface_ids: &[String],
    risk_class: &str,
) {
    inner.global_running = inner.global_running.saturating_sub(1);
    decrement_counter(&mut inner.principal_running, principal_id);
    for surface_id in surface_ids {
        decrement_counter(&mut inner.surface_running, surface_id);
    }
    decrement_counter(&mut inner.risk_running, risk_class);
}

fn release_entry_admission(inner: &mut GatewayRequestRegistryInner, submission_id: &str) -> bool {
    let Some(entry) = inner.entries.get_mut(submission_id) else {
        return false;
    };
    if entry.admission_released {
        return false;
    }
    entry.admission_released = true;
    let principal_id = entry.principal_id.clone();
    let surface_ids = entry.surface_ids.clone();
    let risk_class = entry.risk_class.clone();
    decrement_admission_counters(inner, &principal_id, &surface_ids, &risk_class);
    true
}

fn release_budget_reservation(
    inner: &mut GatewayRequestRegistryInner,
    reservation_id: u64,
) -> bool {
    let Some(charge) = inner.budget_reservations.remove(&reservation_id) else {
        return false;
    };
    inner.budget_running = subtract_budget_charge(inner.budget_running, charge);
    true
}

fn ensure_budget_capacity(
    limit: Option<u64>,
    current: u64,
    charge: u64,
    label: &'static str,
) -> Result<(), GatewayError> {
    let Some(limit) = limit else {
        return Ok(());
    };
    if current.saturating_add(charge) > limit {
        return Err(GatewayError::LimitExceeded(format!("{label} limit")));
    }
    Ok(())
}

fn add_budget_charge(left: GatewayBudgetCharge, right: GatewayBudgetCharge) -> GatewayBudgetCharge {
    GatewayBudgetCharge {
        inflight_ops: left.inflight_ops.saturating_add(right.inflight_ops),
        wall_ms: left.wall_ms.saturating_add(right.wall_ms),
        bytes_in: left.bytes_in.saturating_add(right.bytes_in),
        bytes_out: left.bytes_out.saturating_add(right.bytes_out),
        inline_value_bytes: left
            .inline_value_bytes
            .saturating_add(right.inline_value_bytes),
        stream_items: left.stream_items.saturating_add(right.stream_items),
        estimated_cost_micro_usd: left
            .estimated_cost_micro_usd
            .saturating_add(right.estimated_cost_micro_usd),
    }
}

fn subtract_budget_charge(
    left: GatewayBudgetCharge,
    right: GatewayBudgetCharge,
) -> GatewayBudgetCharge {
    GatewayBudgetCharge {
        inflight_ops: left.inflight_ops.saturating_sub(right.inflight_ops),
        wall_ms: left.wall_ms.saturating_sub(right.wall_ms),
        bytes_in: left.bytes_in.saturating_sub(right.bytes_in),
        bytes_out: left.bytes_out.saturating_sub(right.bytes_out),
        inline_value_bytes: left
            .inline_value_bytes
            .saturating_sub(right.inline_value_bytes),
        stream_items: left.stream_items.saturating_sub(right.stream_items),
        estimated_cost_micro_usd: left
            .estimated_cost_micro_usd
            .saturating_sub(right.estimated_cost_micro_usd),
    }
}

fn prune_completed_requests(inner: &mut GatewayRequestRegistryInner, now_ms: i64) {
    inner.entries.retain(|_, entry| {
        entry.state == GatewayRequestState::Running || entry.retained_until_ms > now_ms
    });
}

fn spawn_deadline_sweeper(boot: &Arc<Bootstrap>, registry: &Arc<GatewayRequestRegistry>) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    let boot = Arc::downgrade(boot);
    let registry = Arc::downgrade(registry);
    handle.spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_millis(DEADLINE_SWEEP_INTERVAL_MS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let (Some(boot), Some(registry)) = (boot.upgrade(), registry.upgrade()) else {
                break;
            };
            for expired in registry.expire_deadlines(now_millis()) {
                boot.kernel
                    .processes
                    .set_status(expired.request_process, ProcessStatus::Cancelled);
            }
        }
    });
}

impl GatewayRuntime {
    /// Create a runtime backed by `boot` and an explicit profile.
    pub fn new(boot: Arc<Bootstrap>, profile: GatewayProfile) -> Result<Self, GatewayError> {
        let profile = Arc::new(Self::compile_profile(&boot, profile)?);
        let requests = Arc::new(GatewayRequestRegistry::new());
        spawn_deadline_sweeper(&boot, &requests);
        Ok(Self {
            boot,
            state: RwLock::new(GatewayRuntimeState {
                profile,
                lkg_active: false,
                consecutive_failed_reloads: 0,
                last_reload_failure: None,
            }),
            requests,
        })
    }

    /// Replace the active profile snapshot.
    ///
    /// Compilation and resource resolution happen before the swap. If the new
    /// profile is malformed, the current snapshot remains active and the error
    /// is returned.
    pub fn replace_profile(
        &self,
        profile: GatewayProfile,
    ) -> Result<GatewayProfileRev, GatewayError> {
        let attempted_rev = profile.revision;
        let profile = match Self::compile_profile(&self.boot, profile) {
            Ok(profile) => Arc::new(profile),
            Err(error) => {
                self.record_reload_failure(attempted_rev, reload_failure_code(&error));
                return Err(error);
            }
        };
        let revision = profile.revision;
        let mut state = self.state.write();
        if revision <= state.profile.revision {
            state.record_reload_failure(attempted_rev, "stale_revision");
            return Err(GatewayError::InvalidProfile(format!(
                "profile revision must increase above active revision {}",
                state.profile.revision
            )));
        }
        *state = GatewayRuntimeState {
            profile,
            lkg_active: false,
            consecutive_failed_reloads: 0,
            last_reload_failure: None,
        };
        Ok(revision)
    }

    /// Return the profile name served by this runtime.
    pub fn profile_name(&self) -> String {
        self.profile_snapshot().profile_name.clone()
    }

    /// Return the profile revision served by this runtime.
    pub fn profile_rev(&self) -> GatewayProfileRev {
        self.profile_snapshot().revision
    }

    /// Whether the active profile can authenticate at least one credential.
    ///
    /// Closed profiles compile successfully so listeners can start fail-closed,
    /// but they should not report production readiness.
    pub fn is_ready(&self) -> bool {
        self.profile_snapshot().has_authenticating_credentials()
    }

    /// Return redacted runtime status.
    pub fn status(&self) -> GatewayRuntimeStatus {
        self.state.read().status()
    }

    /// Reclaim running request registry entries whose server deadline expired.
    pub fn sweep_deadline_expired_requests(&self) -> usize {
        let expired = self.requests.expire_deadlines(now_millis());
        let count = expired.len();
        for request in expired {
            self.boot
                .kernel
                .processes
                .set_status(request.request_process, ProcessStatus::Cancelled);
        }
        count
    }

    /// Inspect and admit a program against this runtime profile.
    pub fn inspect(&self, program: &DoNode) -> Result<ProgramInspection, GatewayError> {
        let profile = self.profile_snapshot();
        Ok(inspect_program(program, &profile, None, None, now_millis(), true)?.inspection)
    }

    /// Describe the active profile for an authenticated session.
    ///
    /// This is intentionally authenticated: unauthenticated discovery must not
    /// expose resource paths, effect names, capability literals, or limits.
    pub fn describe(&self, session: &GatewaySession) -> Result<GatewayDescriptor, GatewayError> {
        let profile = self.profile_snapshot();
        if session.profile_name != profile.profile_name || session.profile_rev != profile.revision {
            return Err(GatewayError::Rejected(
                "gateway session was issued by a different profile snapshot".into(),
            ));
        }
        profile.session_identity_path(session)?;
        let binding = profile.binding_for_principal(&session.principal.principal_id);
        Ok(GatewayDescriptor {
            profile_name: profile.profile_name.clone(),
            profile_rev: profile.revision,
            surfaces: profile
                .surface_descriptors
                .iter()
                .filter(|surface| binding.visible.contains(&surface.surface_id))
                .map(|surface| GatewaySurfaceDescriptor {
                    surface_id: surface.surface_id.clone(),
                    kind: surface.kind,
                    target: surface.target.clone(),
                    method: surface.method.clone(),
                    handle_verb: surface.handle_verb.clone(),
                    grant_template: surface.grant_template.clone(),
                    publish_capability: surface.publish_capability.clone(),
                    input_schema: surface.input_schema.clone(),
                    output_schema: surface.output_schema.clone(),
                })
                .collect(),
            limits: profile.limits.clone(),
        })
    }

    /// Admit a `SubmitStream` stream-open request before any input chunk is
    /// consumed.
    pub async fn accept_input_stream_submission(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<GatewayInputStreamStart, GatewayError> {
        let profile = self.profile_snapshot();
        validate_current_session(&profile, session)?;
        let now_ms = now_millis();
        let mut idempotency = match reserve_submission_idempotency_if_present(
            &self.boot.kernel.state,
            &profile,
            session,
            &submission,
            initial_idempotency_material(&self.boot, &profile, session, &submission)?,
            now_ms,
        )
        .await?
        {
            Some(SubmissionIdempotency::Replay(result)) => {
                return Ok(GatewayInputStreamStart::Replay(result));
            }
            Some(SubmissionIdempotency::Reserved(reservation)) => Some(reservation),
            None => None,
        };
        if let Err(e) = validate_submit_options(&submission.options, &profile.limits, now_ms) {
            return release_submission_idempotency_reservation_and_fail(
                &self.boot.kernel.state,
                idempotency.as_deref(),
                e,
            )
            .await;
        }

        let GatewaySubmission {
            surface_id,
            body,
            requested_output,
            options,
        } = submission.clone();
        let GatewaySubmissionBody::InputStream(open) = body else {
            return release_submission_idempotency_reservation_and_fail(
                &self.boot.kernel.state,
                idempotency.as_deref(),
                GatewayError::Rejected("stream admission requires a stream_open body".into()),
            )
            .await;
        };
        let surface =
            match validate_input_stream_open_request(&profile, session, &surface_id, &open) {
                Ok(surface) => surface,
                Err(e) => {
                    return release_submission_idempotency_reservation_and_fail(
                        &self.boot.kernel.state,
                        idempotency.as_deref(),
                        e,
                    )
                    .await;
                }
            };
        let mut surface_ids = BTreeSet::new();
        surface_ids.insert(surface.surface_id.clone());
        let program = stream_open_admission_program(surface, requested_output);
        let admission = match inspect_program(
            &program,
            &profile,
            Some(&session.principal.principal_id),
            Some(&self.boot),
            now_ms,
            false,
        ) {
            Ok(admission) => admission,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        if admission.requires_idempotency && idempotency.is_none() {
            idempotency = match reserve_submission_idempotency_if_present(
                &self.boot.kernel.state,
                &profile,
                session,
                &submission,
                required_idempotency_material(&submission)?,
                now_ms,
            )
            .await?
            {
                Some(SubmissionIdempotency::Replay(result)) => {
                    return Ok(GatewayInputStreamStart::Replay(result));
                }
                Some(SubmissionIdempotency::Reserved(reservation)) => Some(reservation),
                None => {
                    return Err(GatewayError::Rejected(
                        "idempotency_key or submission_token is required for non-idempotent effects"
                            .into(),
                    ));
                }
            };
        }
        let risk_class = request_risk_class(&admission);
        surface_ids.extend(admission.surface_ids.iter().cloned());
        let fair_surface_ids = request_surface_ids(&surface_ids);
        let budget_charge = match gateway_budget_charge_for_stream_open(
            &admission,
            surface,
            &self.boot,
            &open,
            &profile.limits,
            &options,
            now_ms,
        ) {
            Ok(charge) => charge,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        let budget_guard = match self
            .requests
            .try_reserve_budget(&profile.limits.budget, budget_charge)
        {
            Ok(guard) => guard,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        let admission_guard = match self.requests.try_admit(
            &profile.limits,
            session.principal.principal_id.clone(),
            fair_surface_ids.clone(),
            risk_class.clone(),
        ) {
            Ok(guard) => guard,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        let accepted = match self.requests.new_acceptance(
            profile.revision,
            accepted_surface_id(&submission, &surface_ids),
        ) {
            Ok(accepted) => accepted,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        let (request_process, executor) = match self.executor_for(&profile, session, &surface_ids) {
            Ok(ex) => ex,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        let entry = GatewayRequestEntry {
            accepted: accepted.clone(),
            request_process,
            gateway_id: profile.profile_name.clone(),
            principal_id: session.principal.principal_id.clone(),
            state: GatewayRequestState::Running,
            deadline_at_ms: request_deadline_at_ms(&options),
            budget_reservation_id: budget_guard.reservation_id,
            retained_until_ms: i64::MAX,
            risk_class,
            surface_ids: fair_surface_ids,
            large_value_refs: Vec::new(),
            admission_released: false,
        };
        let request_guard = match self
            .requests
            .insert_running(entry, admission_guard, budget_guard)
        {
            Ok(guard) => guard,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        Ok(GatewayInputStreamStart::Accepted(Box::new(
            GatewayAcceptedInputStream {
                accepted,
                open,
                limits: profile.limits.clone(),
                profile,
                session: session.clone(),
                surface_id,
                requested_output,
                options,
                idempotency,
                request_guard,
                request_process,
                executor,
            },
        )))
    }

    /// Complete an accepted input stream and run it through the same request
    /// registry entry that admitted the stream-open frame.
    pub async fn complete_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        let GatewayAcceptedInputStream {
            accepted,
            profile,
            session,
            surface_id,
            requested_output,
            options,
            idempotency,
            request_guard,
            request_process,
            executor,
            ..
        } = stream;
        let submission = GatewaySubmission {
            surface_id,
            body: GatewaySubmissionBody::DirectInput(GatewayDirectInput {
                payload,
                provenance,
            }),
            requested_output,
            options,
        };
        let lowered = match lower_submission(
            submission.clone(),
            &profile,
            &self.boot.kernel.state,
            &session,
        )
        .await
        {
            Ok(lowered) => lowered,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        let admission = match inspect_program(
            &lowered.program,
            &profile,
            Some(&session.principal.principal_id),
            Some(&self.boot),
            now_millis(),
            true,
        ) {
            Ok(admission) => admission,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_deref(),
                    e,
                )
                .await;
            }
        };
        if lowered.validate_program_payloads
            && let Err(e) = reject_invalid_program_values(
                &lowered.program,
                lowered.program_provenance.as_ref(),
                &self.boot.kernel.state,
                &session,
                &profile,
                lowered.surface_ids.iter().next().map(String::as_str),
                &submission.options,
            )
            .await
        {
            return release_submission_idempotency_reservation_and_fail(
                &self.boot.kernel.state,
                idempotency.as_deref(),
                e,
            )
            .await;
        }
        if admission.requires_idempotency && idempotency.is_none() {
            return Err(GatewayError::Rejected(
                "idempotency_key or submission_token is required for non-idempotent effects".into(),
            ));
        }
        let entry_taint = TaintSet::of(TaintSource::Inbound {
            source: Self::source_label(&profile).into(),
            channel: "submit".into(),
        });
        let outcome = eval_tainted_with_deadline(
            &self.boot,
            request_process,
            &executor,
            &lowered.program,
            entry_taint,
            request_deadline_at_ms(&submission.options),
        )
        .await;
        let outcome = enforce_surface_output_schema(
            &profile,
            &session.principal.principal_id,
            &lowered.program,
            outcome,
        );
        commit_submission_idempotency_outcome(
            &self.boot.kernel.state,
            idempotency.as_deref(),
            &accepted,
            &outcome,
        )
        .await?;
        request_guard.finish(&outcome);
        Ok(GatewaySubmitResult { accepted, outcome })
    }

    /// Mark an accepted input stream failed before dispatch.
    pub async fn fail_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        _reason: &str,
    ) -> Result<(), GatewayError> {
        release_submission_idempotency_reservation(
            &self.boot.kernel.state,
            stream.idempotency.as_deref(),
        )
        .await
    }

    fn compile_profile(
        boot: &Bootstrap,
        profile: GatewayProfile,
    ) -> Result<CompiledGatewayProfile, GatewayError> {
        let mut profile = CompiledGatewayProfile::compile(profile)?;
        for surface in &mut profile.surface_descriptors {
            surface.method_bitmap = surface_method_bitmap(boot, &surface.target, &surface.method)
                .map_err(|e| {
                GatewayError::InvalidProfile(format!(
                    "surface {} references missing method {} on {}: {e}",
                    surface.surface_id,
                    surface.method,
                    surface.target.path()
                ))
            })?;
        }
        profile.surfaces_by_id = profile
            .surface_descriptors
            .iter()
            .map(|surface| (surface.surface_id.clone(), surface.clone()))
            .collect();
        for (principal_id, binding) in &mut profile.surface_bindings_by_principal {
            binding.request_grants_by_surface.clear();
            for surface_id in &binding.submit {
                let Some(surface) = profile.surfaces_by_id.get(surface_id) else {
                    return Err(GatewayError::InvalidProfile(format!(
                        "submit surface {surface_id} for principal {principal_id} is unavailable"
                    )));
                };
                if !binding
                    .capability_ceiling
                    .iter()
                    .any(|ceiling| ceiling.covers_cap(&surface.grant_capability))
                {
                    return Err(GatewayError::InvalidProfile(format!(
                        "capability_ceiling for principal {principal_id} does not cover surface {} grant template {}",
                        surface.surface_id, surface.grant_template
                    )));
                }
                binding.request_grants_by_surface.insert(
                    surface.surface_id.clone(),
                    CompiledRequestGrantTemplate {
                        selector: surface.grant_selector.clone(),
                        methods: surface.method_bitmap,
                    },
                );
            }
        }
        if let Some(anchor) = profile.authority_anchor {
            if boot.kernel.processes.identity(anchor).is_none() {
                return Err(GatewayError::InvalidProfile(format!(
                    "authority anchor process {anchor} does not exist"
                )));
            }
            let anchor_grants = boot.kernel.registry.grants_of(anchor);
            for surface in &profile.surface_descriptors {
                if !anchor_grants.iter().any(|grant| {
                    surface.method_bitmap.is_subset_of(grant.rights.methods)
                        && grant.selector.pattern.covers_cap(&surface.grant_capability)
                }) {
                    return Err(GatewayError::InvalidProfile(format!(
                        "authority anchor does not cover surface {} grant template {}",
                        surface.surface_id, surface.grant_template
                    )));
                }
            }
        }
        Ok(profile)
    }

    fn profile_snapshot(&self) -> Arc<CompiledGatewayProfile> {
        self.state.read().profile.clone()
    }

    /// Record a failed dynamic profile reload while keeping the active snapshot.
    pub fn record_reload_failure(&self, attempted_rev: GatewayProfileRev, code: &'static str) {
        self.state
            .write()
            .record_reload_failure(attempted_rev, code);
    }

    fn spawn_gateway_request_process(
        &self,
        profile: &CompiledGatewayProfile,
        session: &GatewaySession,
        surface_ids: &BTreeSet<String>,
    ) -> Result<ProcessId, GatewayError> {
        let identity_path = profile.session_identity_path(session)?;
        let id_path = parse_identity_path(identity_path)?;
        let id_ref = intern_identity(&id_path);
        let surfaces = profile.surface_descriptors_for_ids(surface_ids)?;
        let binding = if surface_ids.is_empty() {
            None
        } else {
            Some(
                profile
                    .surface_bindings_by_principal
                    .get(&session.principal.principal_id)
                    .ok_or_else(|| {
                        GatewayError::Rejected("principal has no callable surfaces".into())
                    })?,
            )
        };
        let mut grant_templates = BTreeMap::<String, (ResourceSelector, MethodBitmap)>::new();
        for surface in surfaces {
            let Some(binding) = binding else {
                continue;
            };
            if !binding.submit.contains(&surface.surface_id) {
                return Err(GatewayError::Rejected(format!(
                    "surface {} is not callable by principal",
                    surface.surface_id
                )));
            }
            let Some(request_grant) = binding.request_grants_by_surface.get(&surface.surface_id)
            else {
                return Err(GatewayError::Rejected(format!(
                    "surface {} has no compiled request grant",
                    surface.surface_id
                )));
            };
            grant_templates
                .entry(surface.grant_template.clone())
                .and_modify(|(_, methods)| *methods |= request_grant.methods)
                .or_insert((request_grant.selector.clone(), request_grant.methods));
        }
        let declared: Vec<CompiledRequestGrantTemplate> = grant_templates
            .iter()
            .map(|(_, (selector, methods))| CompiledRequestGrantTemplate {
                selector: selector.clone(),
                methods: *methods,
            })
            .collect();
        let anchor = profile.authority_anchor.unwrap_or(self.boot.root);
        self.boot
            .spawn_request_process_under_with_compiled_request_grants(anchor, id_ref, &declared)
            .map_err(|e| GatewayError::Rejected(e.to_string()))
    }

    fn executor_for(
        &self,
        profile: &CompiledGatewayProfile,
        session: &GatewaySession,
        surface_ids: &BTreeSet<String>,
    ) -> Result<(ProcessId, Executor), GatewayError> {
        let proc = self.spawn_gateway_request_process(profile, session, surface_ids)?;
        let ex = self.boot.kernel.executor_for(proc);
        let surfaces = profile.surface_descriptors_for_ids(surface_ids)?;
        let mut opened = BTreeSet::new();
        for surface in surfaces {
            let key = format!("{}\0{}", surface.target.path(), surface.handle_verb);
            if !opened.insert(key) {
                continue;
            }
            let opened = self
                .boot
                .open_for(proc, &surface.target, &surface.handle_verb)
                .map_err(|e| GatewayError::Rejected(e.to_string()))?;
            ex.bind_handle(surface.target.clone(), opened);
        }
        Ok((proc, ex))
    }

    fn source_label(profile: &CompiledGatewayProfile) -> String {
        format!("gateway/{}", profile.profile_name)
    }
}

impl GatewayRuntimeState {
    fn record_reload_failure(&mut self, attempted_rev: GatewayProfileRev, code: &'static str) {
        self.lkg_active = true;
        self.consecutive_failed_reloads = self.consecutive_failed_reloads.saturating_add(1);
        self.last_reload_failure = Some(GatewayProfileReloadFailure {
            attempted_profile_rev: attempted_rev,
            code: code.into(),
            public_message: "profile reload rejected".into(),
        });
    }

    fn status(&self) -> GatewayRuntimeStatus {
        let ready = self.profile.has_authenticating_credentials();
        let readiness = if self.lkg_active && ready {
            GatewayReadiness::DegradedLastKnownGood
        } else if ready {
            GatewayReadiness::Ready
        } else {
            GatewayReadiness::NotReadyClosed
        };
        GatewayRuntimeStatus {
            profile_name: self.profile.profile_name.clone(),
            profile_rev: self.profile.revision,
            ready,
            readiness,
            lkg_active: self.lkg_active,
            consecutive_failed_reloads: self.consecutive_failed_reloads,
            last_reload_failure: self.last_reload_failure.clone(),
        }
    }
}

fn reload_failure_code(error: &GatewayError) -> &'static str {
    match error {
        GatewayError::InvalidProfile(_) => "invalid_profile",
        GatewayError::Unauthenticated => "auth_failed",
        GatewayError::Unauthorized(_) => "permission_denied",
        GatewayError::Rejected(_) => "request_rejected",
        GatewayError::LimitExceeded(_) => "limit_exceeded",
    }
}

#[async_trait]
impl Gateway for GatewayRuntime {
    fn status(&self) -> GatewayRuntimeStatus {
        GatewayRuntime::status(self)
    }

    fn registered_gateway_hosts(&self) -> Vec<GatewayAllowedHost> {
        self.profile_snapshot().registered_hosts.clone()
    }

    fn registered_browser_origins(&self) -> Vec<GatewayAllowedOrigin> {
        self.profile_snapshot().registered_origins.clone()
    }

    async fn authenticate(
        &self,
        credential: PresentedCredential,
    ) -> Result<GatewaySession, GatewayError> {
        let profile = self.profile_snapshot();
        let principal = match credential {
            PresentedCredential::Bearer(token) => profile.verify_bearer(&token)?,
            PresentedCredential::ClientCertificate(credential) => {
                profile.verify_client_certificate(&credential)?
            }
        };
        let mapping = profile
            .identity_by_principal
            .get(&principal.principal_id)
            .ok_or_else(|| GatewayError::Unauthorized(principal.principal_id.clone()))?;
        if !mapping.enabled || principal.principal_generation != mapping.generation {
            return Err(GatewayError::Unauthenticated);
        }
        Ok(GatewaySession {
            principal,
            identity_path: mapping.identity_path.clone(),
            profile_name: profile.profile_name.clone(),
            profile_rev: profile.revision,
        })
    }

    fn describe(&self, session: &GatewaySession) -> Result<GatewayDescriptor, GatewayError> {
        GatewayRuntime::describe(self, session)
    }

    async fn submit_with_acceptance(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
        accepted_sender: Option<tokio::sync::oneshot::Sender<GatewayAccepted>>,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        let profile = self.profile_snapshot();
        validate_current_session(&profile, session)?;
        let now_ms = now_millis();
        let mut idempotency = match reserve_submission_idempotency_if_present(
            &self.boot.kernel.state,
            &profile,
            session,
            &submission,
            initial_idempotency_material(&self.boot, &profile, session, &submission)?,
            now_ms,
        )
        .await?
        {
            Some(SubmissionIdempotency::Replay(result)) => return Ok(*result),
            Some(SubmissionIdempotency::Reserved(reservation)) => Some(*reservation),
            None => None,
        };
        if let Err(e) = validate_submit_options(&submission.options, &profile.limits, now_ms) {
            return release_submission_idempotency_reservation_and_fail(
                &self.boot.kernel.state,
                idempotency.as_ref(),
                e,
            )
            .await;
        }
        let lowered = match lower_submission(
            submission.clone(),
            &profile,
            &self.boot.kernel.state,
            session,
        )
        .await
        {
            Ok(lowered) => lowered,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_ref(),
                    e,
                )
                .await;
            }
        };
        let admission = match inspect_program(
            &lowered.program,
            &profile,
            Some(&session.principal.principal_id),
            Some(&self.boot),
            now_ms,
            true,
        ) {
            Ok(admission) => admission,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_ref(),
                    e,
                )
                .await;
            }
        };
        if lowered.validate_program_payloads
            && let Err(e) = reject_invalid_program_values(
                &lowered.program,
                lowered.program_provenance.as_ref(),
                &self.boot.kernel.state,
                session,
                &profile,
                lowered.surface_ids.iter().next().map(String::as_str),
                &submission.options,
            )
            .await
        {
            return release_submission_idempotency_reservation_and_fail(
                &self.boot.kernel.state,
                idempotency.as_ref(),
                e,
            )
            .await;
        }
        if admission.requires_idempotency && idempotency.is_none() {
            idempotency = match reserve_submission_idempotency_if_present(
                &self.boot.kernel.state,
                &profile,
                session,
                &submission,
                required_idempotency_material(&submission)?,
                now_ms,
            )
            .await?
            {
                Some(SubmissionIdempotency::Replay(result)) => return Ok(*result),
                Some(SubmissionIdempotency::Reserved(reservation)) => Some(*reservation),
                None => {
                    return Err(GatewayError::Rejected(
                        "idempotency_key or submission_token is required for non-idempotent effects"
                            .into(),
                    ));
                }
            };
        }
        let risk_class = request_risk_class(&admission);
        let mut surface_ids = lowered.surface_ids;
        surface_ids.extend(admission.surface_ids.iter().cloned());
        let fair_surface_ids = request_surface_ids(&surface_ids);
        let budget_guard = match self.requests.try_reserve_budget(
            &profile.limits.budget,
            gateway_budget_charge_for_submit(&admission, &submission.options, now_ms),
        ) {
            Ok(guard) => guard,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_ref(),
                    e,
                )
                .await;
            }
        };
        let admission_guard = match self.requests.try_admit(
            &profile.limits,
            session.principal.principal_id.clone(),
            fair_surface_ids.clone(),
            risk_class.clone(),
        ) {
            Ok(guard) => guard,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_ref(),
                    e,
                )
                .await;
            }
        };
        let accepted = match self.requests.new_acceptance(
            profile.revision,
            accepted_surface_id(&submission, &surface_ids),
        ) {
            Ok(accepted) => accepted,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_ref(),
                    e,
                )
                .await;
            }
        };
        let (request_process, ex) = match self.executor_for(&profile, session, &surface_ids) {
            Ok(ex) => ex,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_ref(),
                    e,
                )
                .await;
            }
        };
        let entry = GatewayRequestEntry {
            accepted: accepted.clone(),
            request_process,
            gateway_id: profile.profile_name.clone(),
            principal_id: session.principal.principal_id.clone(),
            state: GatewayRequestState::Running,
            deadline_at_ms: request_deadline_at_ms(&submission.options),
            budget_reservation_id: budget_guard.reservation_id,
            retained_until_ms: i64::MAX,
            risk_class,
            surface_ids: fair_surface_ids,
            large_value_refs: program_large_value_ref_summaries(&lowered.program),
            admission_released: false,
        };
        let request_guard = match self
            .requests
            .insert_running(entry, admission_guard, budget_guard)
        {
            Ok(guard) => guard,
            Err(e) => {
                return release_submission_idempotency_reservation_and_fail(
                    &self.boot.kernel.state,
                    idempotency.as_ref(),
                    e,
                )
                .await;
            }
        };
        if let Some(sender) = accepted_sender {
            let _ = sender.send(accepted.clone());
        }
        let source_label = Self::source_label(&profile);
        let entry_taint = TaintSet::of(TaintSource::Inbound {
            source: source_label.into(),
            channel: "submit".into(),
        });
        let outcome = eval_tainted_with_deadline(
            &self.boot,
            request_process,
            &ex,
            &lowered.program,
            entry_taint,
            request_deadline_at_ms(&submission.options),
        )
        .await;
        let outcome = enforce_surface_output_schema(
            &profile,
            &session.principal.principal_id,
            &lowered.program,
            outcome,
        );
        commit_submission_idempotency_outcome(
            &self.boot.kernel.state,
            idempotency.as_ref(),
            &accepted,
            &outcome,
        )
        .await?;
        request_guard.finish(&outcome);
        Ok(GatewaySubmitResult { accepted, outcome })
    }

    async fn accept_input_stream_submission(
        &self,
        session: &GatewaySession,
        submission: GatewaySubmission,
    ) -> Result<GatewayInputStreamStart, GatewayError> {
        GatewayRuntime::accept_input_stream_submission(self, session, submission).await
    }

    async fn complete_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        payload: Value,
        provenance: Option<GatewayPayloadProvenance>,
    ) -> Result<GatewaySubmitResult, GatewayError> {
        GatewayRuntime::complete_input_stream_submission(self, stream, payload, provenance).await
    }

    async fn fail_input_stream_submission(
        &self,
        stream: GatewayAcceptedInputStream,
        reason: &str,
    ) -> Result<(), GatewayError> {
        GatewayRuntime::fail_input_stream_submission(self, stream, reason).await
    }

    fn cancel(
        &self,
        session: &GatewaySession,
        request: GatewayCancelRequest,
    ) -> Result<bool, GatewayError> {
        self.requests.cancel(session, &request, &self.boot)
    }

    async fn issue_object_upload_ticket(
        &self,
        session: &GatewaySession,
        request: IssueObjectUploadTicketRequest,
    ) -> Result<GatewayObjectUploadTicket, GatewayError> {
        let profile = self.profile_snapshot();
        validate_current_session(&profile, session)?;
        let surface = profile
            .surface_by_id(&request.surface_id)
            .ok_or_else(|| GatewayError::Rejected("unknown gateway surface".into()))?;
        if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
            return Err(GatewayError::Rejected(
                "surface is not callable by principal".into(),
            ));
        }
        validate_ticket_issue_request(&request, &profile.limits)?;
        let ticket_id = new_upload_ticket_id()?;
        let ttl_ms = request
            .expires_in_ms
            .map(i64::try_from)
            .transpose()
            .map_err(|_| GatewayError::Rejected("object upload ticket ttl is out of range".into()))?
            .unwrap_or(profile.limits.max_deadline_ms_from_now);
        let ticket = GatewayObjectUploadTicket {
            ticket_id,
            principal_id: session.principal.principal_id.clone(),
            surface_id: surface.surface_id.clone(),
            submission_token: normalize_optional_string(request.submission_token),
            modality: request.modality,
            expected_size: request.expected_size,
            expected_digest: normalize_optional_string(request.expected_digest),
            allowed_media_types: request
                .allowed_media_types
                .into_iter()
                .map(|media_type| media_type.trim().to_string())
                .collect(),
            expires_at_ms: now_millis().saturating_add(ttl_ms),
            single_use: request.single_use,
            committed: false,
            used: false,
        };
        let path = upload_ticket_path(&ticket.ticket_id)?;
        self.boot
            .kernel
            .state
            .write_cas(&path, None, ticket.to_value())
            .await
            .map_err(|e| GatewayError::Rejected(format!("upload ticket issue failed: {e}")))?;
        Ok(ticket)
    }

    async fn commit_object_upload(
        &self,
        session: &GatewaySession,
        request: CommitObjectUploadRequest,
    ) -> Result<CommitObjectUploadResponse, GatewayError> {
        let profile = self.profile_snapshot();
        validate_current_session(&profile, session)?;
        commit_object_upload_with_profile(
            &self.boot.kernel.state,
            &profile,
            session,
            request,
            Self::source_label(&profile),
        )
        .await
    }

    fn record_gateway_audit(&self, audit: GatewayAudit<'_>) -> Result<(), String> {
        self.boot
            .record_gateway_audit(audit)
            .map_err(|e| e.to_string())
    }
}

fn parse_identity_path(identity: &str) -> Result<Path, GatewayError> {
    let path = Path::parse(identity)
        .map_err(|e| GatewayError::InvalidProfile(format!("invalid identity path: {e}")))?;
    if path.scheme() != "process" {
        return Err(GatewayError::InvalidProfile(
            "identity path must use the process:// scheme".into(),
        ));
    }
    if path.segments().is_empty() {
        return Err(GatewayError::InvalidProfile(
            "identity path must include at least one segment".into(),
        ));
    }
    Ok(path)
}

fn surface_method_bitmap(
    boot: &Bootstrap,
    target: &ResourceName,
    method: &str,
) -> Result<MethodBitmap, GatewayError> {
    let resource_id = boot
        .kernel
        .registry
        .resolve_resource(target)
        .map_err(|e| GatewayError::InvalidProfile(e.to_string()))?;
    let Some(resource) = boot.kernel.registry.resource(resource_id) else {
        return Err(GatewayError::InvalidProfile("resource missing".into()));
    };
    let mut methods = MethodBitmap::empty();
    for interface in &resource.interfaces.interfaces {
        if let Some((index, _)) = boot.kernel.registry.method_index(*interface, method) {
            methods |= MethodBitmap::method(index);
        }
    }
    if methods.is_empty() {
        return Err(GatewayError::InvalidProfile("method missing".into()));
    }
    Ok(methods)
}

fn operation_replay_class(
    boot: &Bootstrap,
    target: &ResourceName,
    method: &str,
) -> Result<ReplayClass, GatewayError> {
    Ok(operation_method_metadata(boot, target, method)?.replay)
}

#[derive(Clone, Copy, Debug)]
struct GatewayMethodMetadata {
    replay: ReplayClass,
    cost: CostModel,
    batchable: bool,
}

fn operation_method_metadata(
    boot: &Bootstrap,
    target: &ResourceName,
    method: &str,
) -> Result<GatewayMethodMetadata, GatewayError> {
    let resource_id = boot
        .kernel
        .registry
        .resolve_resource(target)
        .map_err(|e| GatewayError::Rejected(e.to_string()))?;
    let Some(resource) = boot.kernel.registry.resource(resource_id) else {
        return Err(GatewayError::Rejected(format!(
            "operation target {} is unavailable",
            target.path()
        )));
    };
    for interface_id in &resource.interfaces.interfaces {
        let Some(interface) = boot.kernel.registry.interface(*interface_id) else {
            continue;
        };
        if let Some((_, method)) = interface.method_index(method) {
            return Ok(GatewayMethodMetadata {
                replay: method.replay,
                cost: method.cost,
                batchable: method.batchable,
            });
        }
    }
    Err(GatewayError::Rejected(format!(
        "operation method {} is unavailable on {}",
        method,
        target.path()
    )))
}

fn estimate_gateway_operation_cost(
    cost: &CostModel,
    batchable: bool,
    input: Option<&Value>,
) -> u64 {
    let Some(input) = input else {
        return cost.estimate_micro_usd(1, 1);
    };
    let in_tokens = match (batchable, input) {
        (true, Value::List(items)) => items.iter().map(Value::approx_tokens).sum::<u64>().max(1),
        _ => input.approx_tokens(),
    };
    let out_tokens = in_tokens;
    match (batchable, input) {
        (true, Value::List(items)) => {
            let flat = cost.flat_micro_usd.saturating_mul(items.len() as u64);
            let variable = CostModel {
                flat_micro_usd: 0,
                ..*cost
            }
            .estimate_micro_usd(in_tokens, out_tokens);
            flat.saturating_add(variable)
        }
        _ => cost.estimate_micro_usd(in_tokens, out_tokens),
    }
}

async fn lower_submission(
    submission: GatewaySubmission,
    profile: &CompiledGatewayProfile,
    state: &nexus_state::Backend,
    session: &GatewaySession,
) -> Result<LoweredSubmission, GatewayError> {
    match submission.body {
        GatewaySubmissionBody::Program(program) => {
            let mut surface_ids = BTreeSet::new();
            if !submission.surface_id.is_empty() {
                if profile.surface_by_id(&submission.surface_id).is_none() {
                    return Err(GatewayError::Rejected(format!(
                        "unknown gateway surface {}",
                        submission.surface_id
                    )));
                }
                if !profile
                    .principal_can_submit(&session.principal.principal_id, &submission.surface_id)
                {
                    return Err(GatewayError::Rejected(format!(
                        "surface {} is not callable by principal",
                        submission.surface_id
                    )));
                }
                surface_ids.insert(submission.surface_id);
            }
            Ok(LoweredSubmission {
                program: program.program,
                surface_ids,
                program_provenance: program.provenance,
                validate_program_payloads: true,
            })
        }
        GatewaySubmissionBody::DirectInput(input) => {
            if submission.surface_id.trim().is_empty() {
                return Err(GatewayError::Rejected(
                    "direct input requires a surface_id".into(),
                ));
            }
            let surface = profile
                .surface_by_id(&submission.surface_id)
                .ok_or_else(|| {
                    GatewayError::Rejected(format!(
                        "unknown gateway surface {}",
                        submission.surface_id
                    ))
                })?;
            if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
                return Err(GatewayError::Rejected(format!(
                    "surface {} is not callable by principal",
                    surface.surface_id
                )));
            }
            reject_invalid_direct_value(
                &input.payload,
                input.provenance.as_ref(),
                state,
                session,
                surface,
                &profile.limits,
                &submission.options,
            )
            .await?;
            let mut surface_ids = BTreeSet::new();
            surface_ids.insert(surface.surface_id.clone());
            match surface.kind {
                GatewaySurfaceKind::EffectMethod | GatewaySurfaceKind::StateAppend => {
                    Ok(LoweredSubmission {
                        program: DoNode::op(OperationTemplate {
                            target: surface.target.clone(),
                            method: surface.method.clone(),
                            method_id: None,
                            output: submission.requested_output,
                            literal_input: Some(input.payload),
                        }),
                        surface_ids,
                        program_provenance: None,
                        validate_program_payloads: false,
                    })
                }
            }
        }
        GatewaySubmissionBody::InputStream(open) => {
            if open.stream_id.trim().is_empty() {
                return Err(GatewayError::Rejected(
                    "stream_open requires a stream_id".into(),
                ));
            }
            Err(GatewayError::Rejected(
                "stream input must be completed by a streaming transport before dispatch".into(),
            ))
        }
    }
}

fn validate_input_stream_open_request<'a>(
    profile: &'a CompiledGatewayProfile,
    session: &GatewaySession,
    surface_id: &str,
    open: &GatewayStreamOpenRequest,
) -> Result<&'a CompiledSurfaceDescriptor, GatewayError> {
    if surface_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "stream input requires a surface_id".into(),
        ));
    }
    if open.stream_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "stream_open requires a stream_id".into(),
        ));
    }
    if open.direction != GatewayStreamDirection::ClientToKernel {
        return Err(GatewayError::Rejected(
            "stream input requires CLIENT_TO_KERNEL direction".into(),
        ));
    }
    if open.modality == GatewayModality::Control {
        return Err(GatewayError::Rejected(
            "CONTROL modality cannot be submitted as operation input".into(),
        ));
    }
    if !open.item_schema_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "stream item schema is selected by the gateway profile".into(),
        ));
    }
    if open.max_inline_item_bytes == 0 {
        return Err(GatewayError::Rejected(
            "stream_open max_inline_item_bytes must be non-zero".into(),
        ));
    }
    let profile_max_inline_item_bytes =
        u64::try_from(profile.limits.max_stream_inline_item_bytes).unwrap_or(u64::MAX);
    if open.max_inline_item_bytes > profile_max_inline_item_bytes {
        return Err(GatewayError::Rejected(format!(
            "stream_open max_inline_item_bytes exceeds max_stream_inline_item_bytes ({})",
            profile.limits.max_stream_inline_item_bytes
        )));
    }
    let profile_max_items = u64::try_from(profile.limits.max_stream_items).unwrap_or(u64::MAX);
    if let Some(max_items) = open.max_items {
        if max_items == 0 {
            return Err(GatewayError::Rejected(
                "stream_open max_items must be non-zero".into(),
            ));
        }
        if max_items > profile_max_items {
            return Err(GatewayError::Rejected(format!(
                "stream_open max_items exceeds max_stream_items ({})",
                profile.limits.max_stream_items
            )));
        }
    }
    let profile_max_bytes = u64::try_from(profile.limits.max_stream_bytes).unwrap_or(u64::MAX);
    if let Some(max_bytes) = open.max_bytes {
        if max_bytes == 0 {
            return Err(GatewayError::Rejected(
                "stream_open max_bytes must be non-zero".into(),
            ));
        }
        if max_bytes > profile_max_bytes {
            return Err(GatewayError::Rejected(format!(
                "stream_open max_bytes exceeds max_stream_bytes ({})",
                profile.limits.max_stream_bytes
            )));
        }
    }
    let surface = profile
        .surface_by_id(surface_id)
        .ok_or_else(|| GatewayError::Rejected(format!("unknown gateway surface {surface_id}")))?;
    if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
        return Err(GatewayError::Rejected(format!(
            "surface {} is not callable by principal",
            surface.surface_id
        )));
    }
    Ok(surface)
}

fn stream_open_admission_program(
    surface: &CompiledSurfaceDescriptor,
    requested_output: OutputMode,
) -> DoNode {
    DoNode::op(OperationTemplate {
        target: surface.target.clone(),
        method: surface.method.clone(),
        method_id: None,
        output: requested_output,
        literal_input: Some(Value::Null),
    })
}

struct LoweredSubmission {
    program: DoNode,
    surface_ids: BTreeSet<String>,
    program_provenance: Option<GatewayPayloadProvenance>,
    validate_program_payloads: bool,
}

fn request_deadline_at_ms(options: &SubmitOptions) -> Option<i64> {
    options
        .deadline_ms
        .and_then(|deadline| i64::try_from(deadline).ok())
}

async fn eval_tainted_with_deadline(
    boot: &Bootstrap,
    request_process: ProcessId,
    executor: &Executor,
    program: &DoNode,
    entry_taint: TaintSet,
    deadline_at_ms: Option<i64>,
) -> Outcome {
    let Some(deadline_at_ms) = deadline_at_ms else {
        return executor.eval_tainted(program, entry_taint).await;
    };
    let remaining_ms = deadline_at_ms.saturating_sub(now_millis());
    if remaining_ms <= 0 {
        boot.kernel
            .processes
            .set_status(request_process, ProcessStatus::Cancelled);
        return Outcome::Fail(Failure::Timeout);
    }
    let remaining_ms = u64::try_from(remaining_ms).unwrap_or(u64::MAX);
    match tokio::time::timeout(
        std::time::Duration::from_millis(remaining_ms),
        executor.eval_tainted(program, entry_taint),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            boot.kernel
                .processes
                .set_status(request_process, ProcessStatus::Cancelled);
            Outcome::Fail(Failure::Timeout)
        }
    }
}

fn request_surface_ids(surface_ids: &BTreeSet<String>) -> Vec<String> {
    if surface_ids.is_empty() {
        vec!["<inert>".into()]
    } else {
        surface_ids.iter().cloned().collect()
    }
}

fn accepted_surface_id(submission: &GatewaySubmission, surface_ids: &BTreeSet<String>) -> String {
    if !submission.surface_id.trim().is_empty() {
        return submission.surface_id.clone();
    }
    surface_ids.iter().next().cloned().unwrap_or_default()
}

fn request_risk_class(admission: &ProgramAdmission) -> String {
    if admission.requires_idempotency {
        "non_idempotent_effect".into()
    } else if admission.inspection.operation_count > 0 {
        "effect".into()
    } else if admission.inspection.wait_deadline_count > 0
        || admission.inspection.wait_signal_count > 0
    {
        "wait".into()
    } else {
        "inert".into()
    }
}

fn gateway_budget_charge_for_submit(
    admission: &ProgramAdmission,
    options: &SubmitOptions,
    now_ms: i64,
) -> GatewayBudgetCharge {
    let literal_bytes = admission.inspection.literal_bytes as u64;
    GatewayBudgetCharge {
        inflight_ops: admission.inspection.operation_count as u64,
        wall_ms: request_wall_ms(options, now_ms),
        bytes_in: literal_bytes,
        bytes_out: 0,
        inline_value_bytes: literal_bytes,
        stream_items: 0,
        estimated_cost_micro_usd: admission.inspection.estimated_cost_micro_usd,
    }
}

fn gateway_budget_charge_for_stream_open(
    admission: &ProgramAdmission,
    surface: &CompiledSurfaceDescriptor,
    boot: &Bootstrap,
    open: &GatewayStreamOpenRequest,
    limits: &GatewayLimitProfile,
    options: &SubmitOptions,
    now_ms: i64,
) -> Result<GatewayBudgetCharge, GatewayError> {
    let stream_items = open.max_items.unwrap_or(limits.max_stream_items as u64);
    let bytes_in = open.max_bytes.unwrap_or(limits.max_stream_bytes as u64);
    let declared_inline = stream_items.saturating_mul(open.max_inline_item_bytes);
    let estimated_cost_micro_usd =
        estimate_gateway_stream_cost(boot, surface, bytes_in, stream_items)?;
    Ok(GatewayBudgetCharge {
        inflight_ops: admission.inspection.operation_count as u64,
        wall_ms: request_wall_ms(options, now_ms),
        bytes_in,
        bytes_out: 0,
        inline_value_bytes: declared_inline.min(bytes_in),
        stream_items,
        estimated_cost_micro_usd,
    })
}

fn estimate_gateway_stream_cost(
    boot: &Bootstrap,
    surface: &CompiledSurfaceDescriptor,
    bytes_in: u64,
    stream_items: u64,
) -> Result<u64, GatewayError> {
    let metadata = operation_method_metadata(boot, &surface.target, &surface.method)?;
    let in_tokens = (bytes_in / 4).max(1);
    let out_tokens = in_tokens;
    if metadata.batchable {
        let flat = metadata
            .cost
            .flat_micro_usd
            .saturating_mul(stream_items.max(1));
        let variable = CostModel {
            flat_micro_usd: 0,
            ..metadata.cost
        }
        .estimate_micro_usd(in_tokens, out_tokens);
        return Ok(flat.saturating_add(variable));
    }
    Ok(metadata.cost.estimate_micro_usd(in_tokens, out_tokens))
}

fn request_wall_ms(options: &SubmitOptions, now_ms: i64) -> u64 {
    options
        .deadline_ms
        .and_then(|deadline| i64::try_from(deadline).ok())
        .map(|deadline| deadline.saturating_sub(now_ms) as u64)
        .unwrap_or(0)
}

fn program_large_value_ref_summaries(program: &DoNode) -> Vec<GatewayLargeValueRefSummary> {
    let mut summaries = Vec::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec![program];
    while let Some(node) = stack.pop() {
        match node {
            DoNode::Pure(value) => push_large_value_summaries(value, &mut seen, &mut summaries),
            DoNode::AndThen { d, then } => {
                if let Some(arg) = &then.arg {
                    push_large_value_summaries(arg, &mut seen, &mut summaries);
                }
                stack.push(d);
            }
            DoNode::OrElse { d, or } => {
                if let Some(arg) = &or.arg {
                    push_large_value_summaries(arg, &mut seen, &mut summaries);
                }
                stack.push(d);
            }
            DoNode::Both(left, right) | DoNode::Race(left, right) => {
                stack.push(left);
                stack.push(right);
            }
            DoNode::Let { value, body, .. } => {
                stack.push(value);
                stack.push(body);
            }
            DoNode::Acting { body, .. } => stack.push(body),
            DoNode::Op(tmpl) => {
                if let Some(input) = &tmpl.literal_input {
                    push_large_value_summaries(input, &mut seen, &mut summaries);
                }
            }
            DoNode::Use(_) | DoNode::Fail(_) | DoNode::Wait(_) => {}
        }
    }
    summaries
}

fn push_large_value_summaries(
    value: &Value,
    seen: &mut BTreeSet<(String, u64, Option<String>)>,
    summaries: &mut Vec<GatewayLargeValueRefSummary>,
) {
    for blob in collect_large_value_refs(value) {
        let key = (blob.hash.clone(), blob.size, blob.mime.clone());
        if seen.insert(key.clone()) {
            summaries.push(GatewayLargeValueRefSummary {
                hash: key.0,
                size: key.1,
                mime: key.2,
            });
        }
    }
}

fn validate_submit_options(
    options: &SubmitOptions,
    limits: &GatewayLimitProfile,
    now_ms: i64,
) -> Result<(), GatewayError> {
    if let Some(key) = normalize_optional_string(options.idempotency_key.clone()) {
        validate_idempotency_key(&key)?;
    }
    if let Some(token) = normalize_optional_string(options.submission_token.clone()) {
        validate_submission_token(&token)?;
    }
    if let Some(deadline_ms) = options.deadline_ms {
        let deadline_ms = i64::try_from(deadline_ms)
            .map_err(|_| GatewayError::Rejected("deadline_ms is out of range".into()))?;
        if deadline_ms <= now_ms {
            return Err(GatewayError::Rejected(
                "deadline_ms has already expired".into(),
            ));
        }
        if deadline_ms.saturating_sub(now_ms) > limits.max_deadline_ms_from_now {
            return Err(GatewayError::Rejected(format!(
                "deadline_ms exceeds max_deadline_ms_from_now ({})",
                limits.max_deadline_ms_from_now
            )));
        }
    }
    Ok(())
}

fn validate_current_session(
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
) -> Result<(), GatewayError> {
    if session.profile_name != profile.profile_name || session.profile_rev != profile.revision {
        return Err(GatewayError::Rejected(
            "gateway session was issued by a different profile snapshot".into(),
        ));
    }
    profile.session_identity_path(session)?;
    Ok(())
}

fn validate_ticket_issue_request(
    request: &IssueObjectUploadTicketRequest,
    limits: &GatewayLimitProfile,
) -> Result<(), GatewayError> {
    if request.surface_id.trim().is_empty() {
        return Err(GatewayError::Rejected(
            "object upload ticket requires a surface_id".into(),
        ));
    }
    if let Some(size) = request.expected_size
        && size > i64::MAX as u64
    {
        return Err(GatewayError::Rejected(
            "object upload expected_size is out of range".into(),
        ));
    }
    if let Some(digest) = normalize_optional_string(request.expected_digest.clone()) {
        validate_content_hash(&digest)?;
    }
    if let Some(token) = normalize_optional_string(request.submission_token.clone()) {
        validate_submission_token(&token)?;
    }
    let ttl = request
        .expires_in_ms
        .map(i64::try_from)
        .transpose()
        .map_err(|_| GatewayError::Rejected("object upload ticket ttl is out of range".into()))?;
    if let Some(ttl) = ttl {
        if ttl <= 0 {
            return Err(GatewayError::Rejected(
                "object upload ticket ttl must be positive".into(),
            ));
        }
        if ttl > limits.max_deadline_ms_from_now {
            return Err(GatewayError::Rejected(
                "object upload ticket ttl exceeds profile deadline window".into(),
            ));
        }
    } else if limits.max_deadline_ms_from_now <= 0 {
        return Err(GatewayError::Rejected(
            "object upload tickets require a positive profile deadline window".into(),
        ));
    }
    for media_type in &request.allowed_media_types {
        validate_media_type_pattern(media_type)?;
    }
    Ok(())
}

fn validate_submission_token(token: &str) -> Result<(), GatewayError> {
    let ok = !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected("invalid submission token".into()))
    }
}

fn validate_idempotency_key(key: &str) -> Result<(), GatewayError> {
    let ok = !key.is_empty()
        && key.len() <= 256
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected("invalid idempotency key".into()))
    }
}

fn validate_media_type_pattern(media_type: &str) -> Result<(), GatewayError> {
    let media_type = media_type.trim();
    if media_type.is_empty()
        || media_type.len() > 128
        || media_type.bytes().any(|b| b.is_ascii_control())
    {
        return Err(GatewayError::Rejected(
            "object upload media type pattern is invalid".into(),
        ));
    }
    let Some((ty, sub)) = media_type.split_once('/') else {
        return Err(GatewayError::Rejected(
            "object upload media type pattern must contain '/'".into(),
        ));
    };
    if ty.is_empty() || sub.is_empty() || ty.contains('*') {
        return Err(GatewayError::Rejected(
            "object upload media type pattern is invalid".into(),
        ));
    }
    if sub.contains('*') && sub != "*" {
        return Err(GatewayError::Rejected(
            "object upload media type wildcard must cover a full subtype".into(),
        ));
    }
    Ok(())
}

enum SubmissionIdempotency {
    Reserved(Box<GatewayIdempotencyReservation>),
    Replay(Box<GatewaySubmitResult>),
}

struct GatewayIdempotencyReservation {
    path: Path,
    pending_record: Value,
    fingerprint: SubmissionIdempotencyFingerprint,
}

struct SubmissionIdempotencyFingerprint {
    effective_key_hash: String,
    submission_hash: String,
    caller_material_kind: &'static str,
    caller_material_hash: String,
    profile_name: String,
    profile_rev: String,
    principal_id: String,
    surface_id: String,
}

async fn reserve_submission_idempotency_if_present(
    state: &nexus_state::Backend,
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    submission: &GatewaySubmission,
    material: Option<(&'static str, String)>,
    now_ms: i64,
) -> Result<Option<SubmissionIdempotency>, GatewayError> {
    let Some((caller_material_kind, caller_material)) = material else {
        return Ok(None);
    };
    let submission_hash = submission_hash(submission)?;
    let caller_material_hash = hash_idempotency_material(caller_material_kind, &caller_material);
    let effective_key_hash = effective_idempotency_hash(
        profile,
        session,
        submission,
        &submission_hash,
        caller_material_kind,
        &caller_material_hash,
    );
    let fingerprint = SubmissionIdempotencyFingerprint {
        effective_key_hash,
        submission_hash,
        caller_material_kind,
        caller_material_hash,
        profile_name: profile.profile_name.clone(),
        profile_rev: profile.revision.to_string(),
        principal_id: session.principal.principal_id.clone(),
        surface_id: submission.surface_id.clone(),
    };
    let path = idempotency_path(&fingerprint.effective_key_hash)?;
    let pending_record = idempotency_pending_record(&fingerprint, now_ms);
    match state.write_cas(&path, None, pending_record.clone()).await {
        Ok(()) => Ok(Some(SubmissionIdempotency::Reserved(Box::new(
            GatewayIdempotencyReservation {
                path,
                pending_record,
                fingerprint,
            },
        )))),
        Err(nexus_state::StateError::CasFailed { .. }) => {
            let current = state
                .read(&path)
                .await
                .map_err(|e| GatewayError::Rejected(format!("idempotency lookup failed: {e}")))?;
            let Some(current) = current else {
                return Err(GatewayError::Rejected(
                    "idempotency record disappeared during reservation".into(),
                ));
            };
            replay_submission_idempotency(&current, &fingerprint).map(Some)
        }
        Err(e) => Err(GatewayError::Rejected(format!(
            "idempotency reservation failed: {e}"
        ))),
    }
}

async fn commit_submission_idempotency_outcome(
    state: &nexus_state::Backend,
    reservation: Option<&GatewayIdempotencyReservation>,
    accepted: &GatewayAccepted,
    outcome: &Outcome,
) -> Result<(), GatewayError> {
    let Some(reservation) = reservation else {
        return Ok(());
    };
    let committed =
        idempotency_committed_outcome_record(&reservation.fingerprint, accepted, outcome)?;
    state
        .write_cas(
            &reservation.path,
            Some(reservation.pending_record.clone()),
            committed,
        )
        .await
        .map_err(|e| match e {
            nexus_state::StateError::CasFailed { .. } => {
                GatewayError::Rejected("idempotency record changed during execution".into())
            }
            other => GatewayError::Rejected(format!("idempotency commit failed: {other}")),
        })
}

async fn release_submission_idempotency_reservation(
    state: &nexus_state::Backend,
    reservation: Option<&GatewayIdempotencyReservation>,
) -> Result<(), GatewayError> {
    let Some(reservation) = reservation else {
        return Ok(());
    };
    state
        .write_delete(&reservation.path)
        .await
        .map_err(|e| GatewayError::Rejected(format!("idempotency release failed: {e}")))
}

async fn release_submission_idempotency_reservation_and_fail<T>(
    state: &nexus_state::Backend,
    reservation: Option<&GatewayIdempotencyReservation>,
    error: GatewayError,
) -> Result<T, GatewayError> {
    release_submission_idempotency_reservation(state, reservation).await?;
    Err(error)
}

fn initial_idempotency_material(
    boot: &Bootstrap,
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    submission: &GatewaySubmission,
) -> Result<Option<(&'static str, String)>, GatewayError> {
    if let Some(material) = idempotency_key_material(submission)? {
        return Ok(Some(material));
    }
    if direct_input_requires_idempotency(boot, profile, session, submission)? {
        return submission_token_material(&submission.options);
    }
    Ok(None)
}

fn required_idempotency_material(
    submission: &GatewaySubmission,
) -> Result<Option<(&'static str, String)>, GatewayError> {
    if let Some(material) = idempotency_key_material(submission)? {
        return Ok(Some(material));
    }
    submission_token_material(&submission.options)
}

fn idempotency_key_material(
    submission: &GatewaySubmission,
) -> Result<Option<(&'static str, String)>, GatewayError> {
    if let Some(key) = normalize_optional_string(submission.options.idempotency_key.clone()) {
        validate_idempotency_key(&key)?;
        return Ok(Some(("idempotency_key", key)));
    }
    if let GatewaySubmissionBody::Program(program) = &submission.body
        && let Some(key) = normalize_optional_string(program.idempotency_key.clone())
    {
        validate_idempotency_key(&key)?;
        return Ok(Some(("idempotency_key", key)));
    }
    Ok(None)
}

fn submission_token_material(
    options: &SubmitOptions,
) -> Result<Option<(&'static str, String)>, GatewayError> {
    if let Some(token) = normalize_optional_string(options.submission_token.clone()) {
        validate_submission_token(&token)?;
        Ok(Some(("submission_token", token)))
    } else {
        Ok(None)
    }
}

fn direct_input_requires_idempotency(
    boot: &Bootstrap,
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    submission: &GatewaySubmission,
) -> Result<bool, GatewayError> {
    let GatewaySubmissionBody::DirectInput(_) = &submission.body else {
        return Ok(false);
    };
    if submission.surface_id.trim().is_empty() {
        return Ok(false);
    }
    let Some(surface) = profile.surface_by_id(&submission.surface_id) else {
        return Ok(false);
    };
    if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
        return Ok(false);
    }
    let replay = operation_replay_class(boot, &surface.target, &surface.method)?;
    Ok(matches!(replay, ReplayClass::NonIdempotentEffect))
}

fn submission_hash(submission: &GatewaySubmission) -> Result<String, GatewayError> {
    let mut hasher = blake3::Hasher::new();
    update_hash_str(&mut hasher, "nexus-gateway-submission-v1");
    update_hash_str(&mut hasher, &submission.surface_id);
    update_hash_json(&mut hasher, &submission.requested_output)?;
    match &submission.body {
        GatewaySubmissionBody::Program(program) => {
            update_hash_str(&mut hasher, "program");
            update_hash_json(&mut hasher, &program.program)?;
            update_hash_provenance(&mut hasher, program.provenance.as_ref());
        }
        GatewaySubmissionBody::DirectInput(input) => {
            update_hash_str(&mut hasher, "direct_input");
            update_hash_json(&mut hasher, &input.payload)?;
            update_hash_provenance(&mut hasher, input.provenance.as_ref());
        }
        GatewaySubmissionBody::InputStream(open) => {
            update_hash_str(&mut hasher, "input_stream");
            update_hash_str(&mut hasher, &open.stream_id);
            update_hash_str(&mut hasher, open.direction.as_str());
            update_hash_str(&mut hasher, open.modality.as_str());
            update_hash_str(&mut hasher, &open.item_schema_id);
            update_hash_u64(&mut hasher, open.max_inline_item_bytes);
            update_hash_optional_u64(&mut hasher, open.max_items);
            update_hash_optional_u64(&mut hasher, open.max_bytes);
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn effective_idempotency_hash(
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    submission: &GatewaySubmission,
    submission_hash: &str,
    caller_material_kind: &str,
    caller_material_hash: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    update_hash_str(&mut hasher, "nexus-gateway-idempotency-v1");
    update_hash_str(&mut hasher, &profile.profile_name);
    update_hash_u64(&mut hasher, profile.revision);
    update_hash_str(&mut hasher, &session.principal.principal_id);
    update_hash_str(&mut hasher, &session.identity_path);
    update_hash_str(&mut hasher, &submission.surface_id);
    update_hash_str(&mut hasher, submission_hash);
    update_hash_str(&mut hasher, caller_material_kind);
    update_hash_str(&mut hasher, caller_material_hash);
    hasher.finalize().to_hex().to_string()
}

fn hash_idempotency_material(kind: &str, material: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    update_hash_str(&mut hasher, "nexus-gateway-idempotency-material-v1");
    update_hash_str(&mut hasher, kind);
    update_hash_str(&mut hasher, material);
    hasher.finalize().to_hex().to_string()
}

fn update_hash_json<T: ?Sized + serde::Serialize>(
    hasher: &mut blake3::Hasher,
    value: &T,
) -> Result<(), GatewayError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| GatewayError::Rejected(format!("submission hash failed: {e}")))?;
    update_hash_bytes(hasher, &bytes);
    Ok(())
}

fn update_hash_provenance(
    hasher: &mut blake3::Hasher,
    provenance: Option<&GatewayPayloadProvenance>,
) {
    let Some(provenance) = provenance else {
        update_hash_str(hasher, "provenance:none");
        return;
    };
    update_hash_str(hasher, "provenance:some");
    update_hash_optional_str(hasher, provenance.upload_ticket.as_deref());
    if let Some(proof) = provenance.store_proof.as_ref() {
        update_hash_str(hasher, "store_proof:some");
        update_hash_str(hasher, &proof.store_id);
        update_hash_str(hasher, &proof.proof);
    } else {
        update_hash_str(hasher, "store_proof:none");
    }
}

fn update_hash_optional_str(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(value) => {
            update_hash_str(hasher, "some");
            update_hash_str(hasher, value);
        }
        None => update_hash_str(hasher, "none"),
    }
}

fn update_hash_optional_u64(hasher: &mut blake3::Hasher, value: Option<u64>) {
    match value {
        Some(value) => {
            update_hash_str(hasher, "some");
            update_hash_u64(hasher, value);
        }
        None => update_hash_str(hasher, "none"),
    }
}

fn update_hash_u64(hasher: &mut blake3::Hasher, value: u64) {
    hasher.update(&value.to_le_bytes());
}

fn update_hash_str(hasher: &mut blake3::Hasher, value: &str) {
    update_hash_bytes(hasher, value.as_bytes());
}

fn update_hash_bytes(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn idempotency_pending_record(
    fingerprint: &SubmissionIdempotencyFingerprint,
    now_ms: i64,
) -> Value {
    let mut map = idempotency_base_record(fingerprint);
    map.insert("state".into(), Value::Str("pending".into()));
    map.insert("created_at_ms".into(), Value::Int(now_ms));
    Value::Map(map)
}

fn idempotency_committed_outcome_record(
    fingerprint: &SubmissionIdempotencyFingerprint,
    accepted: &GatewayAccepted,
    outcome: &Outcome,
) -> Result<Value, GatewayError> {
    let mut map = idempotency_base_record(fingerprint);
    map.insert("state".into(), Value::Str("committed".into()));
    map.insert("committed_at_ms".into(), Value::Int(now_millis()));
    map.insert(
        "accepted_submission_id".into(),
        Value::Str(accepted.submission_id.clone()),
    );
    map.insert(
        "accepted_trace_root".into(),
        Value::Str(accepted.trace_root.clone()),
    );
    map.insert(
        "accepted_profile_rev".into(),
        Value::Int(i64::try_from(accepted.profile_rev).map_err(|_| {
            GatewayError::Rejected("idempotency accepted profile rev is out of range".into())
        })?),
    );
    map.insert(
        "accepted_surface_id".into(),
        Value::Str(accepted.surface_id.clone()),
    );
    match outcome {
        Outcome::Done(value) => {
            map.insert("outcome_status".into(), Value::Str("done".into()));
            map.insert("outcome_value".into(), value.clone());
        }
        Outcome::Short(value) => {
            map.insert("outcome_status".into(), Value::Str("short".into()));
            map.insert("outcome_value".into(), value.clone());
        }
        Outcome::Fail(failure) => {
            map.insert("outcome_status".into(), Value::Str("fail".into()));
            map.insert(
                "failure_json".into(),
                Value::Str(serde_json::to_string(failure).map_err(|e| {
                    GatewayError::Rejected(format!("idempotency outcome encode failed: {e}"))
                })?),
            );
        }
    }
    Ok(Value::Map(map))
}

fn idempotency_base_record(
    fingerprint: &SubmissionIdempotencyFingerprint,
) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("schema".into(), Value::Str("gateway-idempotency-v2".into())),
        (
            "effective_key_hash".into(),
            Value::Str(fingerprint.effective_key_hash.clone()),
        ),
        (
            "submission_hash".into(),
            Value::Str(fingerprint.submission_hash.clone()),
        ),
        (
            "caller_material_kind".into(),
            Value::Str(fingerprint.caller_material_kind.into()),
        ),
        (
            "caller_material_hash".into(),
            Value::Str(fingerprint.caller_material_hash.clone()),
        ),
        (
            "profile_name".into(),
            Value::Str(fingerprint.profile_name.clone()),
        ),
        (
            "profile_rev".into(),
            Value::Str(fingerprint.profile_rev.clone()),
        ),
        (
            "principal_id".into(),
            Value::Str(fingerprint.principal_id.clone()),
        ),
        (
            "surface_id".into(),
            Value::Str(fingerprint.surface_id.clone()),
        ),
    ])
}

fn replay_submission_idempotency(
    record: &Value,
    fingerprint: &SubmissionIdempotencyFingerprint,
) -> Result<SubmissionIdempotency, GatewayError> {
    let map = record
        .as_map()
        .ok_or_else(|| GatewayError::Rejected("idempotency record must be a map".into()))?;
    validate_idempotency_record_fingerprint(map, fingerprint)?;
    match required_str(map, "state")? {
        "pending" => Err(GatewayError::LimitExceeded(
            "idempotent submission is already in flight".into(),
        )),
        "committed" => {
            let accepted = replay_accepted(map)?;
            let outcome = match required_str(map, "outcome_status")? {
                "done" => {
                    let value = map.get("outcome_value").cloned().ok_or_else(|| {
                        GatewayError::Rejected("idempotency record is missing outcome value".into())
                    })?;
                    Outcome::Done(value)
                }
                "short" => {
                    let value = map.get("outcome_value").cloned().ok_or_else(|| {
                        GatewayError::Rejected("idempotency record is missing outcome value".into())
                    })?;
                    Outcome::Short(value)
                }
                "fail" => {
                    let Some(failure_json) = optional_str(map, "failure_json") else {
                        return Err(GatewayError::Rejected(
                            "idempotent submission previously failed".into(),
                        ));
                    };
                    let failure = serde_json::from_str::<Failure>(failure_json).map_err(|e| {
                        GatewayError::Rejected(format!("idempotency failure decode failed: {e}"))
                    })?;
                    Outcome::Fail(failure)
                }
                _ => {
                    return Err(GatewayError::Rejected(
                        "idempotency record has invalid outcome status".into(),
                    ));
                }
            };
            Ok(SubmissionIdempotency::Replay(Box::new(
                GatewaySubmitResult { accepted, outcome },
            )))
        }
        _ => Err(GatewayError::Rejected(
            "idempotency record has invalid state".into(),
        )),
    }
}

fn replay_accepted(map: &BTreeMap<String, Value>) -> Result<GatewayAccepted, GatewayError> {
    let profile_rev = required_i64(map, "accepted_profile_rev")?;
    if profile_rev < 0 {
        return Err(GatewayError::Rejected(
            "idempotency accepted profile rev is invalid".into(),
        ));
    }
    Ok(GatewayAccepted {
        submission_id: required_str(map, "accepted_submission_id")?.to_string(),
        trace_root: required_str(map, "accepted_trace_root")?.to_string(),
        profile_rev: profile_rev as u64,
        surface_id: required_str(map, "accepted_surface_id")?.to_string(),
    })
}

fn validate_idempotency_record_fingerprint(
    map: &BTreeMap<String, Value>,
    fingerprint: &SubmissionIdempotencyFingerprint,
) -> Result<(), GatewayError> {
    let matches = required_str(map, "schema")? == "gateway-idempotency-v2"
        && required_str(map, "effective_key_hash")? == fingerprint.effective_key_hash
        && required_str(map, "submission_hash")? == fingerprint.submission_hash
        && required_str(map, "caller_material_kind")? == fingerprint.caller_material_kind
        && required_str(map, "caller_material_hash")? == fingerprint.caller_material_hash
        && required_str(map, "profile_name")? == fingerprint.profile_name
        && required_str(map, "profile_rev")? == fingerprint.profile_rev
        && required_str(map, "principal_id")? == fingerprint.principal_id
        && required_str(map, "surface_id")? == fingerprint.surface_id;
    if matches {
        Ok(())
    } else {
        Err(GatewayError::Rejected(
            "idempotency record fingerprint mismatch".into(),
        ))
    }
}

async fn reject_invalid_direct_value(
    value: &Value,
    provenance: Option<&GatewayPayloadProvenance>,
    state: &nexus_state::Backend,
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    limits: &GatewayLimitProfile,
    options: &SubmitOptions,
) -> Result<(), GatewayError> {
    if value_contains_stream_end(value) {
        return Err(GatewayError::Rejected(
            "direct input cannot be StreamEnd".into(),
        ));
    }
    validate_surface_input(surface, value)?;
    validate_inline_value_bytes(value, limits, "direct input")?;
    reject_invalid_large_values(&[value], provenance, state, session, surface, options).await
}

const MAX_VALUE_SCHEMA_DEPTH: usize = 32;
const MAX_VALUE_SCHEMA_NODES: usize = 1024;

fn compile_value_schema(schema: &Value, label: &str) -> Result<CompiledValueSchema, GatewayError> {
    let mut nodes = 0usize;
    compile_value_schema_inner(schema, label, 0, &mut nodes)
}

fn compile_value_schema_inner(
    schema: &Value,
    label: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<CompiledValueSchema, GatewayError> {
    if depth > MAX_VALUE_SCHEMA_DEPTH {
        return Err(GatewayError::InvalidProfile(format!(
            "{label} exceeds max schema depth"
        )));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_VALUE_SCHEMA_NODES {
        return Err(GatewayError::InvalidProfile(format!(
            "{label} exceeds max schema nodes"
        )));
    }
    let map = schema
        .as_map()
        .ok_or_else(|| GatewayError::InvalidProfile(format!("{label} must be a schema object")))?;
    for key in map.keys() {
        if !matches!(key.as_str(), "type" | "required" | "properties" | "items") {
            return Err(GatewayError::InvalidProfile(format!(
                "{label} contains unsupported schema key {key}"
            )));
        }
    }
    let kind = match map.get("type").and_then(Value::as_str) {
        Some("any") | None => ValueSchemaKind::Any,
        Some("null") => ValueSchemaKind::Null,
        Some("boolean") | Some("bool") => ValueSchemaKind::Bool,
        Some("integer") | Some("int") => ValueSchemaKind::Int,
        Some("number") => ValueSchemaKind::Number,
        Some("string") | Some("str") => ValueSchemaKind::Str,
        Some("array") | Some("list") => ValueSchemaKind::List,
        Some("object") | Some("map") => ValueSchemaKind::Map,
        Some("bytes") => ValueSchemaKind::Bytes,
        Some("blob") => ValueSchemaKind::Blob,
        Some("tensor") => ValueSchemaKind::Tensor,
        Some("frame") => ValueSchemaKind::Frame,
        Some("stream_end") => ValueSchemaKind::StreamEnd,
        Some(other) => {
            return Err(GatewayError::InvalidProfile(format!(
                "{label} has unsupported schema type {other}"
            )));
        }
    };

    let mut required = BTreeSet::new();
    match map.get("required") {
        Some(Value::List(items)) if matches!(kind, ValueSchemaKind::Map | ValueSchemaKind::Any) => {
            for item in items {
                let Some(field) = item.as_str() else {
                    return Err(GatewayError::InvalidProfile(format!(
                        "{label} required entries must be strings"
                    )));
                };
                if field.trim().is_empty() {
                    return Err(GatewayError::InvalidProfile(format!(
                        "{label} required entries must not be empty"
                    )));
                }
                required.insert(field.to_string());
            }
        }
        Some(_) => {
            return Err(GatewayError::InvalidProfile(format!(
                "{label} required is only valid for object schemas"
            )));
        }
        None => {}
    }

    let mut properties = BTreeMap::new();
    match map.get("properties") {
        Some(Value::Map(entries))
            if matches!(kind, ValueSchemaKind::Map | ValueSchemaKind::Any) =>
        {
            for (field, child) in entries {
                if field.trim().is_empty() {
                    return Err(GatewayError::InvalidProfile(format!(
                        "{label} property names must not be empty"
                    )));
                }
                properties.insert(
                    field.clone(),
                    compile_value_schema_inner(
                        child,
                        &format!("{label}.properties.{field}"),
                        depth.saturating_add(1),
                        nodes,
                    )?,
                );
            }
        }
        Some(_) => {
            return Err(GatewayError::InvalidProfile(format!(
                "{label} properties is only valid for object schemas"
            )));
        }
        None => {}
    }

    let items = match map.get("items") {
        Some(child) if matches!(kind, ValueSchemaKind::List | ValueSchemaKind::Any) => {
            Some(Box::new(compile_value_schema_inner(
                child,
                &format!("{label}.items"),
                depth.saturating_add(1),
                nodes,
            )?))
        }
        Some(_) => {
            return Err(GatewayError::InvalidProfile(format!(
                "{label} items is only valid for array schemas"
            )));
        }
        None => None,
    };

    Ok(CompiledValueSchema {
        kind,
        required,
        properties,
        items,
    })
}

fn validate_surface_input(
    surface: &CompiledSurfaceDescriptor,
    value: &Value,
) -> Result<(), GatewayError> {
    if let Some(schema) = &surface.input_schema_validator {
        validate_value_schema(schema, value, "input", "surface input_schema")?;
    }
    Ok(())
}

fn validate_surface_output(
    surface: &CompiledSurfaceDescriptor,
    value: &Value,
) -> Result<(), GatewayError> {
    if let Some(schema) = &surface.output_schema_validator {
        validate_value_schema(schema, value, "output", "surface output_schema")?;
    }
    Ok(())
}

fn validate_surface_stream_item(
    surface: &CompiledSurfaceDescriptor,
    modality: GatewayModality,
    item: &Value,
) -> Result<(), GatewayError> {
    let Some(schema) = stream_item_schema(surface, modality) else {
        return Ok(());
    };
    validate_value_schema(schema, item, "stream item", "surface input_schema")
}

fn stream_item_schema(
    surface: &CompiledSurfaceDescriptor,
    modality: GatewayModality,
) -> Option<&CompiledValueSchema> {
    let schema = surface.input_schema_validator.as_ref()?;
    match modality {
        GatewayModality::Value | GatewayModality::Event => schema.items.as_deref().or(Some(schema)),
        _ => Some(schema),
    }
}

fn validate_value_schema(
    schema: &CompiledValueSchema,
    value: &Value,
    path: &str,
    schema_label: &str,
) -> Result<(), GatewayError> {
    let matches_kind = match schema.kind {
        ValueSchemaKind::Any => true,
        ValueSchemaKind::Null => matches!(value, Value::Null),
        ValueSchemaKind::Bool => matches!(value, Value::Bool(_)),
        ValueSchemaKind::Int => matches!(value, Value::Int(_)),
        ValueSchemaKind::Number => matches!(value, Value::Int(_) | Value::Float(_)),
        ValueSchemaKind::Str => matches!(value, Value::Str(_)),
        ValueSchemaKind::List => matches!(value, Value::List(_)),
        ValueSchemaKind::Map => matches!(value, Value::Map(_)),
        ValueSchemaKind::Bytes => matches!(value, Value::Bytes(_)),
        ValueSchemaKind::Blob => matches!(value, Value::Blob(_)),
        ValueSchemaKind::Tensor => matches!(value, Value::Tensor(_)),
        ValueSchemaKind::Frame => matches!(value, Value::Frame(_)),
        ValueSchemaKind::StreamEnd => matches!(value, Value::StreamEnd(_)),
    };
    if !matches_kind {
        return Err(GatewayError::Rejected(format!(
            "{path} does not match {schema_label}"
        )));
    }
    if let Value::Map(map) = value {
        for required in &schema.required {
            if !map.contains_key(required) {
                return Err(GatewayError::Rejected(format!(
                    "{path} is missing required field {required}"
                )));
            }
        }
        for (field, field_schema) in &schema.properties {
            if let Some(field_value) = map.get(field) {
                validate_value_schema(
                    field_schema,
                    field_value,
                    &format!("{path}.{field}"),
                    schema_label,
                )?;
            }
        }
    }
    if let (Value::List(items), Some(item_schema)) = (value, &schema.items) {
        for (index, item) in items.iter().enumerate() {
            validate_value_schema(item_schema, item, &format!("{path}[{index}]"), schema_label)?;
        }
    }
    Ok(())
}

fn enforce_surface_output_schema(
    profile: &CompiledGatewayProfile,
    principal_id: &str,
    program: &DoNode,
    outcome: Outcome,
) -> Outcome {
    let Some(surface) = output_schema_surface_for_program(profile, principal_id, program) else {
        return outcome;
    };
    match outcome {
        Outcome::Done(value) => match validate_surface_output(surface, &value) {
            Ok(()) => Outcome::Done(value),
            Err(_) => Outcome::Fail(output_schema_failure(&surface.surface_id)),
        },
        Outcome::Short(value) => match validate_surface_output(surface, &value) {
            Ok(()) => Outcome::Short(value),
            Err(_) => Outcome::Fail(output_schema_failure(&surface.surface_id)),
        },
        Outcome::Fail(failure) => Outcome::Fail(failure),
    }
}

fn output_schema_surface_for_program<'a>(
    profile: &'a CompiledGatewayProfile,
    principal_id: &str,
    program: &DoNode,
) -> Option<&'a CompiledSurfaceDescriptor> {
    let DoNode::Op(tmpl) = program else {
        return None;
    };
    if tmpl.output == OutputMode::SinkOnly {
        return None;
    }
    profile.operation_surface_for_principal(principal_id, &tmpl.target, &tmpl.method)
}

fn output_schema_failure(surface_id: &str) -> Failure {
    Failure::Custom {
        kind: "gateway_output_schema".into(),
        message: format!("surface {surface_id} output did not match declared schema"),
    }
}

async fn reject_invalid_large_values(
    values: &[&Value],
    provenance: Option<&GatewayPayloadProvenance>,
    state: &nexus_state::Backend,
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    options: &SubmitOptions,
) -> Result<(), GatewayError> {
    let refs: Vec<&BlobRef> = values
        .iter()
        .flat_map(|value| collect_large_value_refs(value))
        .collect();
    if refs.is_empty() {
        return Ok(());
    }
    if !has_provenance(provenance) {
        return Err(GatewayError::Rejected(
            "large object references require upload ticket or store proof".into(),
        ));
    }
    let mut checked = HashSet::new();
    for blob in refs {
        if checked.insert((blob.hash.as_str(), blob.size)) {
            verify_blob_ref_in_state(blob, state).await?;
        }
    }
    if let Some(ticket_id) = provenance.and_then(|provenance| provenance.upload_ticket.as_deref()) {
        consume_upload_ticket(
            ticket_id,
            values,
            state,
            session,
            surface,
            options.submission_token.as_deref(),
        )
        .await?;
    }
    if let Some(proof) = provenance.and_then(|provenance| provenance.store_proof.as_ref()) {
        verify_store_proof(
            proof,
            values,
            state,
            session,
            surface,
            options.submission_token.as_deref(),
        )
        .await?;
    }
    Ok(())
}

struct ProgramLargeValueAdmission<'a> {
    surface: &'a CompiledSurfaceDescriptor,
    values: Vec<&'a Value>,
}

async fn reject_invalid_program_values(
    program: &DoNode,
    provenance: Option<&GatewayPayloadProvenance>,
    state: &nexus_state::Backend,
    session: &GatewaySession,
    profile: &CompiledGatewayProfile,
    default_surface_id: Option<&str>,
    options: &SubmitOptions,
) -> Result<(), GatewayError> {
    let default_surface = match default_surface_id {
        Some(surface_id) => Some(profile.surface_by_id(surface_id).ok_or_else(|| {
            GatewayError::Rejected(format!("unknown gateway surface {surface_id}"))
        })?),
        None => None,
    };
    let mut admissions: BTreeMap<String, ProgramLargeValueAdmission<'_>> = BTreeMap::new();
    let mut stack = vec![program];
    while let Some(node) = stack.pop() {
        match node {
            DoNode::Pure(value) => {
                add_program_large_value_admission(&mut admissions, value, default_surface)?;
            }
            DoNode::AndThen { d, then } => {
                if let Some(arg) = &then.arg {
                    add_program_large_value_admission(&mut admissions, arg, default_surface)?;
                }
                stack.push(d);
            }
            DoNode::OrElse { d, or } => {
                if let Some(arg) = &or.arg {
                    add_program_large_value_admission(&mut admissions, arg, default_surface)?;
                }
                stack.push(d);
            }
            DoNode::Both(left, right) | DoNode::Race(left, right) => {
                stack.push(left);
                stack.push(right);
            }
            DoNode::Let { value, body, .. } => {
                stack.push(value);
                stack.push(body);
            }
            DoNode::Acting { body, .. } => stack.push(body),
            DoNode::Op(tmpl) => {
                if let Some(input) = &tmpl.literal_input {
                    let surface = profile
                        .operation_surface_for_principal(
                            &session.principal.principal_id,
                            &tmpl.target,
                            &tmpl.method,
                        )
                        .ok_or_else(|| {
                            GatewayError::Rejected(format!(
                                "operation {}.{} is not callable by principal",
                                tmpl.target.path(),
                                tmpl.method
                            ))
                        })?;
                    add_program_large_value_admission(&mut admissions, input, Some(surface))?;
                }
            }
            DoNode::Use(_) | DoNode::Fail(_) | DoNode::Wait(_) => {}
        }
    }
    if admissions.len() > 1 && has_provenance(provenance) {
        return Err(GatewayError::Rejected(
            "program large object references require one callable surface".into(),
        ));
    }
    for admission in admissions.values() {
        reject_invalid_large_values(
            &admission.values,
            provenance,
            state,
            session,
            admission.surface,
            options,
        )
        .await?;
    }
    Ok(())
}

fn add_program_large_value_admission<'a>(
    admissions: &mut BTreeMap<String, ProgramLargeValueAdmission<'a>>,
    value: &'a Value,
    surface: Option<&'a CompiledSurfaceDescriptor>,
) -> Result<(), GatewayError> {
    if value_contains_stream_end(value) {
        return Err(GatewayError::Rejected(
            "program literals cannot contain StreamEnd".into(),
        ));
    }
    if collect_large_value_refs(value).is_empty() {
        return Ok(());
    }
    let Some(surface) = surface else {
        return Err(GatewayError::Rejected(
            "program large object references require a callable surface".into(),
        ));
    };
    admissions
        .entry(surface.surface_id.clone())
        .or_insert_with(|| ProgramLargeValueAdmission {
            surface,
            values: Vec::new(),
        })
        .values
        .push(value);
    Ok(())
}

async fn commit_object_upload_with_profile(
    state: &nexus_state::Backend,
    profile: &CompiledGatewayProfile,
    session: &GatewaySession,
    request: CommitObjectUploadRequest,
    source_label: String,
) -> Result<CommitObjectUploadResponse, GatewayError> {
    validate_ticket_id(&request.ticket_id)?;
    let submission_token = normalize_optional_string(request.submission_token);
    if let Some(token) = submission_token.as_deref() {
        validate_submission_token(token)?;
    }
    let path = upload_ticket_path(&request.ticket_id)?;
    let current = state
        .read(&path)
        .await
        .map_err(|e| GatewayError::Rejected(format!("upload ticket lookup failed: {e}")))?;
    let Some(current_value) = current else {
        return Err(GatewayError::Rejected("upload ticket not found".into()));
    };
    let mut ticket = GatewayObjectUploadTicket::from_value(&current_value)?;
    if ticket.committed {
        return Err(GatewayError::Rejected(
            "upload ticket was already committed".into(),
        ));
    }
    let surface = profile.surface_by_id(&ticket.surface_id).ok_or_else(|| {
        GatewayError::Rejected("upload ticket surface is no longer available".into())
    })?;
    if !profile.principal_can_submit(&session.principal.principal_id, &surface.surface_id) {
        return Err(GatewayError::Rejected(
            "upload ticket surface is not callable by principal".into(),
        ));
    }

    let size = u64::try_from(request.bytes.len())
        .map_err(|_| GatewayError::Rejected("object upload size is out of range".into()))?;
    if size > i64::MAX as u64 {
        return Err(GatewayError::Rejected(
            "object upload size is out of range".into(),
        ));
    }
    let digest = blake3::hash(&request.bytes).to_hex().to_string();
    let media_type = normalize_optional_string(request.media_type);
    if let Some(media_type) = media_type.as_deref() {
        validate_media_type_pattern(media_type)?;
    }
    let item = commit_item_from_request(request.item, &digest, size, media_type)?;
    validate_upload_ticket(
        &request.ticket_id,
        &ticket,
        &item,
        session,
        surface,
        submission_token.as_deref(),
        now_millis(),
    )?;

    let taint = TaintSet::of(TaintSource::Inbound {
        source: source_label.into(),
        channel: "object-upload".into(),
    });
    write_blob_if_absent(state, &digest, &request.bytes, taint).await?;
    if ticket.expected_size.is_none() {
        ticket.expected_size = Some(size);
    }
    if ticket.expected_digest.is_none() {
        ticket.expected_digest = Some(digest.clone());
    }
    ticket.committed = true;
    state
        .write_cas(&path, Some(current_value), ticket.to_value())
        .await
        .map_err(|e| match e {
            nexus_state::StateError::CasFailed { .. } => {
                GatewayError::Rejected("upload ticket was already consumed".into())
            }
            other => GatewayError::Rejected(format!("upload ticket consume failed: {other}")),
        })?;
    Ok(CommitObjectUploadResponse {
        item,
        provenance: committed_object_provenance(&request.ticket_id),
        digest,
        size,
    })
}

fn committed_object_provenance(ticket_id: &str) -> GatewayPayloadProvenance {
    GatewayPayloadProvenance {
        upload_ticket: None,
        store_proof: Some(ObjectStoreProof {
            store_id: GATEWAY_COMMITTED_OBJECT_STORE_ID.into(),
            proof: ticket_id.into(),
        }),
    }
}

async fn verify_store_proof(
    proof: &ObjectStoreProof,
    values: &[&Value],
    state: &nexus_state::Backend,
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    submission_token: Option<&str>,
) -> Result<(), GatewayError> {
    if proof.store_id != GATEWAY_COMMITTED_OBJECT_STORE_ID {
        return Err(GatewayError::Rejected(
            "object store proof store_id is not trusted".into(),
        ));
    }
    validate_ticket_id(&proof.proof)?;
    let path = upload_ticket_path(&proof.proof)?;
    let current = state
        .read(&path)
        .await
        .map_err(|e| GatewayError::Rejected(format!("object store proof lookup failed: {e}")))?;
    let Some(current_value) = current else {
        return Err(GatewayError::Rejected(
            "object store proof not found".into(),
        ));
    };
    let mut ticket = GatewayObjectUploadTicket::from_value(&current_value)?;
    validate_committed_ticket_proof(
        &proof.proof,
        &ticket,
        values,
        session,
        surface,
        submission_token,
        now_millis(),
    )?;
    if ticket.single_use {
        ticket.used = true;
        state
            .write_cas(&path, Some(current_value), ticket.to_value())
            .await
            .map_err(|e| match e {
                nexus_state::StateError::CasFailed { .. } => {
                    GatewayError::Rejected("object store proof was already consumed".into())
                }
                other => {
                    GatewayError::Rejected(format!("object store proof consume failed: {other}"))
                }
            })?;
    }
    Ok(())
}

fn validate_committed_ticket_proof(
    ticket_id: &str,
    ticket: &GatewayObjectUploadTicket,
    values: &[&Value],
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    submission_token: Option<&str>,
    now_ms: i64,
) -> Result<(), GatewayError> {
    if ticket.ticket_id != ticket_id {
        return Err(GatewayError::Rejected(
            "object store proof id mismatch".into(),
        ));
    }
    if !ticket.committed {
        return Err(GatewayError::Rejected(
            "object store proof has not been committed".into(),
        ));
    }
    if ticket.used {
        return Err(GatewayError::Rejected(
            "object store proof already used".into(),
        ));
    }
    if ticket.expires_at_ms <= now_ms {
        return Err(GatewayError::Rejected("object store proof expired".into()));
    }
    if ticket.principal_id != session.principal.principal_id {
        return Err(GatewayError::Rejected(
            "object store proof principal mismatch".into(),
        ));
    }
    if ticket.surface_id != surface.surface_id {
        return Err(GatewayError::Rejected(
            "object store proof surface mismatch".into(),
        ));
    }
    if let Some(bound) = ticket.submission_token.as_deref()
        && Some(bound) != submission_token
    {
        return Err(GatewayError::Rejected(
            "object store proof submission token mismatch".into(),
        ));
    }
    validate_ticket_values_binding(ticket, values)
}

fn commit_item_from_request(
    item: Option<Value>,
    digest: &str,
    size: u64,
    media_type: Option<String>,
) -> Result<Value, GatewayError> {
    let Some(item) = item else {
        return Ok(Value::Blob(BlobRef {
            hash: digest.to_string(),
            size,
            mime: media_type,
        }));
    };
    let Some(blob) = backing_blob(&item) else {
        return Err(GatewayError::Rejected(
            "object upload item must be Blob, Tensor, or Frame".into(),
        ));
    };
    if blob.hash != digest || blob.size != size {
        return Err(GatewayError::Rejected(
            "object upload item does not match committed bytes".into(),
        ));
    }
    if let Some(media_type) = media_type.as_deref()
        && blob.mime.as_deref() != Some(media_type)
    {
        return Err(GatewayError::Rejected(
            "object upload item media type mismatch".into(),
        ));
    }
    Ok(item)
}

async fn write_blob_if_absent(
    state: &nexus_state::Backend,
    digest: &str,
    bytes: &[u8],
    taint: TaintSet,
) -> Result<(), GatewayError> {
    let path = blob_path(digest)?;
    match state
        .read(&path)
        .await
        .map_err(|e| GatewayError::Rejected(format!("blob store lookup failed: {e}")))?
    {
        Some(Value::Bytes(existing)) if existing == bytes => return Ok(()),
        Some(Value::Bytes(_)) => {
            return Err(GatewayError::Rejected(
                "blob store bytes do not match content hash".into(),
            ));
        }
        Some(_) => {
            return Err(GatewayError::Rejected(
                "blob store path contains a non-bytes value".into(),
            ));
        }
        None => {}
    }

    match state
        .write_cas_tainted(&path, None, Value::Bytes(bytes.to_vec()), taint)
        .await
    {
        Ok(()) => Ok(()),
        Err(nexus_state::StateError::CasFailed { .. }) => {
            let value = state
                .read(&path)
                .await
                .map_err(|e| GatewayError::Rejected(format!("blob store lookup failed: {e}")))?;
            match value {
                Some(Value::Bytes(existing)) if existing == bytes => Ok(()),
                _ => Err(GatewayError::Rejected(
                    "blob store bytes do not match content hash".into(),
                )),
            }
        }
        Err(e) => Err(GatewayError::Rejected(format!(
            "blob store write failed: {e}"
        ))),
    }
}

fn value_contains_stream_end(value: &Value) -> bool {
    value_any(value, |value| matches!(value, Value::StreamEnd(_)))
}

fn collect_large_value_refs(value: &Value) -> Vec<&BlobRef> {
    let mut refs = Vec::new();
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Blob(blob) => refs.push(blob),
            Value::Tensor(tensor) => refs.push(&tensor.blob),
            Value::Frame(frame) => refs.push(&frame.blob),
            Value::List(items) => {
                for item in items {
                    stack.push(item);
                }
            }
            Value::Map(map) => {
                for value in map.values() {
                    stack.push(value);
                }
            }
            _ => {}
        }
    }
    refs
}

async fn verify_blob_ref_in_state(
    blob: &BlobRef,
    state: &nexus_state::Backend,
) -> Result<(), GatewayError> {
    validate_content_hash(&blob.hash)?;
    let path = Path::parse(&format!("state://blob/{}", blob.hash)).map_err(|e| {
        GatewayError::Rejected(format!("large object reference has invalid blob path: {e}"))
    })?;
    let value = state
        .read(&path)
        .await
        .map_err(|e| GatewayError::Rejected(format!("blob store lookup failed: {e}")))?;
    let Some(Value::Bytes(bytes)) = value else {
        return Err(GatewayError::Rejected(
            "large object reference is not present in the blob store".into(),
        ));
    };
    if bytes.len() as u64 != blob.size {
        return Err(GatewayError::Rejected(
            "large object reference size does not match blob store bytes".into(),
        ));
    }
    let actual = blake3::hash(&bytes).to_hex().to_string();
    if actual != blob.hash {
        return Err(GatewayError::Rejected(
            "large object reference hash does not match blob store bytes".into(),
        ));
    }
    Ok(())
}

fn validate_content_hash(hash: &str) -> Result<(), GatewayError> {
    let ok = hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected(
            "large object reference hash must be lowercase hex blake3".into(),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayObjectUploadTicket {
    pub ticket_id: String,
    pub principal_id: String,
    pub surface_id: String,
    pub submission_token: Option<String>,
    pub modality: GatewayModality,
    pub expected_size: Option<u64>,
    pub expected_digest: Option<String>,
    pub allowed_media_types: Vec<String>,
    pub expires_at_ms: i64,
    pub single_use: bool,
    pub committed: bool,
    pub used: bool,
}

impl GatewayObjectUploadTicket {
    fn from_value(value: &Value) -> Result<Self, GatewayError> {
        let map = value
            .as_map()
            .ok_or_else(|| GatewayError::Rejected("upload ticket record must be a map".into()))?;
        let ticket = Self {
            ticket_id: required_str(map, "ticket_id")?.to_string(),
            principal_id: required_str(map, "principal_id")?.to_string(),
            surface_id: required_str(map, "surface_id")?.to_string(),
            submission_token: optional_str(map, "submission_token").map(str::to_string),
            modality: parse_modality(required_str(map, "modality")?)?,
            expected_size: optional_u64(map, "expected_size")?,
            expected_digest: optional_str(map, "expected_digest").map(str::to_string),
            allowed_media_types: optional_string_list(map, "allowed_media_types")?,
            expires_at_ms: required_i64(map, "expires_at_ms")?,
            single_use: optional_bool(map, "single_use").unwrap_or(true),
            committed: optional_bool(map, "committed").unwrap_or(false),
            used: optional_bool(map, "used").unwrap_or(false),
        };
        validate_ticket_id(&ticket.ticket_id)?;
        if let Some(digest) = &ticket.expected_digest {
            validate_content_hash(digest)?;
        }
        Ok(ticket)
    }

    fn to_value(&self) -> Value {
        let mut map = BTreeMap::new();
        map.insert("ticket_id".into(), Value::Str(self.ticket_id.clone()));
        map.insert("principal_id".into(), Value::Str(self.principal_id.clone()));
        map.insert("surface_id".into(), Value::Str(self.surface_id.clone()));
        if let Some(submission_token) = &self.submission_token {
            map.insert(
                "submission_token".into(),
                Value::Str(submission_token.clone()),
            );
        }
        map.insert("modality".into(), Value::Str(self.modality.as_str().into()));
        if let Some(size) = self.expected_size {
            map.insert("expected_size".into(), Value::Int(size as i64));
        }
        if let Some(digest) = &self.expected_digest {
            map.insert("expected_digest".into(), Value::Str(digest.clone()));
        }
        map.insert(
            "allowed_media_types".into(),
            Value::List(
                self.allowed_media_types
                    .iter()
                    .cloned()
                    .map(Value::Str)
                    .collect(),
            ),
        );
        map.insert("expires_at_ms".into(), Value::Int(self.expires_at_ms));
        map.insert("single_use".into(), Value::Bool(self.single_use));
        map.insert("committed".into(), Value::Bool(self.committed));
        map.insert("used".into(), Value::Bool(self.used));
        Value::Map(map)
    }
}

async fn consume_upload_ticket(
    ticket_id: &str,
    values: &[&Value],
    state: &nexus_state::Backend,
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    submission_token: Option<&str>,
) -> Result<(), GatewayError> {
    validate_ticket_id(ticket_id)?;
    let path = upload_ticket_path(ticket_id)?;
    let current = state
        .read(&path)
        .await
        .map_err(|e| GatewayError::Rejected(format!("upload ticket lookup failed: {e}")))?;
    let Some(current_value) = current else {
        return Err(GatewayError::Rejected("upload ticket not found".into()));
    };
    let mut ticket = GatewayObjectUploadTicket::from_value(&current_value)?;
    validate_upload_ticket_values(
        ticket_id,
        &ticket,
        values,
        session,
        surface,
        submission_token,
        now_millis(),
    )?;
    if ticket.single_use {
        ticket.used = true;
        state
            .write_cas(&path, Some(current_value), ticket.to_value())
            .await
            .map_err(|e| match e {
                nexus_state::StateError::CasFailed { .. } => {
                    GatewayError::Rejected("upload ticket was already consumed".into())
                }
                other => GatewayError::Rejected(format!("upload ticket consume failed: {other}")),
            })?;
    }
    Ok(())
}

fn validate_upload_ticket(
    ticket_id: &str,
    ticket: &GatewayObjectUploadTicket,
    value: &Value,
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    submission_token: Option<&str>,
    now_ms: i64,
) -> Result<(), GatewayError> {
    validate_upload_ticket_values(
        ticket_id,
        ticket,
        &[value],
        session,
        surface,
        submission_token,
        now_ms,
    )
}

fn validate_upload_ticket_values(
    ticket_id: &str,
    ticket: &GatewayObjectUploadTicket,
    values: &[&Value],
    session: &GatewaySession,
    surface: &CompiledSurfaceDescriptor,
    submission_token: Option<&str>,
    now_ms: i64,
) -> Result<(), GatewayError> {
    if ticket.ticket_id != ticket_id {
        return Err(GatewayError::Rejected("upload ticket id mismatch".into()));
    }
    if ticket.used {
        return Err(GatewayError::Rejected("upload ticket already used".into()));
    }
    if ticket.expires_at_ms <= now_ms {
        return Err(GatewayError::Rejected("upload ticket expired".into()));
    }
    if ticket.principal_id != session.principal.principal_id {
        return Err(GatewayError::Rejected(
            "upload ticket principal mismatch".into(),
        ));
    }
    if ticket.surface_id != surface.surface_id {
        return Err(GatewayError::Rejected(
            "upload ticket surface mismatch".into(),
        ));
    }
    if let Some(bound) = ticket.submission_token.as_deref()
        && Some(bound) != submission_token
    {
        return Err(GatewayError::Rejected(
            "upload ticket submission token mismatch".into(),
        ));
    }
    validate_ticket_values_binding(ticket, values)
}

fn validate_ticket_values_binding(
    ticket: &GatewayObjectUploadTicket,
    values: &[&Value],
) -> Result<(), GatewayError> {
    let mut found_ref = false;
    for value in values {
        for item in collect_large_ref_values(value) {
            found_ref = true;
            if !modality_allows_value(ticket.modality, item) {
                return Err(GatewayError::Rejected(
                    "upload ticket modality mismatch".into(),
                ));
            }
            let Some(blob) = backing_blob(item) else {
                return Err(GatewayError::Rejected(
                    "upload ticket requires a large object reference".into(),
                ));
            };
            if let Some(size) = ticket.expected_size
                && blob.size != size
            {
                return Err(GatewayError::Rejected("upload ticket size mismatch".into()));
            }
            if let Some(digest) = ticket.expected_digest.as_deref()
                && blob.hash != digest
            {
                return Err(GatewayError::Rejected(
                    "upload ticket digest mismatch".into(),
                ));
            }
            if !ticket.allowed_media_types.is_empty() {
                let Some(mime) = blob.mime.as_deref() else {
                    return Err(GatewayError::Rejected(
                        "upload ticket requires media type".into(),
                    ));
                };
                if !ticket
                    .allowed_media_types
                    .iter()
                    .any(|allowed| media_type_matches(allowed, mime))
                {
                    return Err(GatewayError::Rejected(
                        "upload ticket media type mismatch".into(),
                    ));
                }
            }
        }
    }
    if !found_ref {
        return Err(GatewayError::Rejected(
            "upload ticket requires a large object reference".into(),
        ));
    }
    Ok(())
}

fn collect_large_ref_values(value: &Value) -> Vec<&Value> {
    let mut refs = Vec::new();
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Blob(_) | Value::Tensor(_) | Value::Frame(_) => refs.push(value),
            Value::List(items) => {
                for item in items {
                    stack.push(item);
                }
            }
            Value::Map(map) => {
                for value in map.values() {
                    stack.push(value);
                }
            }
            _ => {}
        }
    }
    refs
}

fn backing_blob(value: &Value) -> Option<&BlobRef> {
    match value {
        Value::Blob(blob) => Some(blob),
        Value::Tensor(tensor) => Some(&tensor.blob),
        Value::Frame(frame) => Some(&frame.blob),
        _ => None,
    }
}

fn modality_allows_value(modality: GatewayModality, value: &Value) -> bool {
    match (modality, value) {
        (GatewayModality::Value, _) => true,
        (GatewayModality::Bytes, Value::Blob(_)) => true,
        (GatewayModality::Tensor, Value::Tensor(_)) => true,
        (GatewayModality::AudioFrame, Value::Frame(frame)) => {
            frame.kind == nexus_types::FrameKind::Audio
        }
        (GatewayModality::VideoFrame, Value::Frame(frame)) => {
            frame.kind == nexus_types::FrameKind::Video
        }
        (GatewayModality::PoseFrame, Value::Frame(frame)) => {
            frame.kind == nexus_types::FrameKind::Pose
        }
        (GatewayModality::SensorFrame, Value::Frame(frame)) => {
            frame.kind == nexus_types::FrameKind::Sensor
        }
        _ => false,
    }
}

fn media_type_matches(allowed: &str, actual: &str) -> bool {
    allowed == actual
        || allowed == "*/*"
        || allowed.strip_suffix("/*").is_some_and(|prefix| {
            actual.starts_with(prefix) && actual[prefix.len()..].starts_with('/')
        })
}

fn upload_ticket_path(ticket_id: &str) -> Result<Path, GatewayError> {
    validate_ticket_id(ticket_id)?;
    Path::parse(&format!("state://gateway/upload-ticket/{ticket_id}"))
        .map_err(|e| GatewayError::Rejected(format!("invalid upload ticket path: {e}")))
}

fn idempotency_path(effective_key_hash: &str) -> Result<Path, GatewayError> {
    validate_content_hash(effective_key_hash)?;
    Path::parse(&format!("state://gateway/idempotency/{effective_key_hash}"))
        .map_err(|e| GatewayError::Rejected(format!("invalid idempotency path: {e}")))
}

fn blob_path(hash: &str) -> Result<Path, GatewayError> {
    validate_content_hash(hash)?;
    Path::parse(&format!("state://blob/{hash}"))
        .map_err(|e| GatewayError::Rejected(format!("invalid blob path: {e}")))
}

fn validate_ticket_id(ticket_id: &str) -> Result<(), GatewayError> {
    let ok = !ticket_id.is_empty()
        && ticket_id.len() <= 128
        && ticket_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if ok {
        Ok(())
    } else {
        Err(GatewayError::Rejected("invalid upload ticket id".into()))
    }
}

fn new_upload_ticket_id() -> Result<String, GatewayError> {
    let mut bytes = [0u8; OBJECT_UPLOAD_TICKET_RANDOM_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|e| GatewayError::Rejected(format!("upload ticket entropy failed: {e}")))?;
    let mut id = String::with_capacity(4 + OBJECT_UPLOAD_TICKET_RANDOM_BYTES * 2);
    id.push_str("uot_");
    for byte in bytes {
        push_hex_byte(&mut id, byte);
    }
    Ok(id)
}

fn random_gateway_id(prefix: &str, profile_rev: GatewayProfileRev) -> Result<String, GatewayError> {
    let mut bytes = [0u8; GATEWAY_REQUEST_ID_RANDOM_BYTES];
    getrandom::fill(&mut bytes)
        .map_err(|e| GatewayError::Rejected(format!("gateway request entropy failed: {e}")))?;
    let mut id = String::with_capacity(prefix.len() + 1 + 20 + 1 + bytes.len() * 2);
    id.push_str(prefix);
    id.push('-');
    id.push_str(&profile_rev.to_string());
    id.push('-');
    for byte in bytes {
        push_hex_byte(&mut id, byte);
    }
    Ok(id)
}

fn push_hex_byte(out: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(HEX[(byte >> 4) as usize] as char);
    out.push(HEX[(byte & 0x0f) as usize] as char);
}

fn normalize_optional_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}

fn required_str<'a>(
    map: &'a BTreeMap<String, Value>,
    key: &'static str,
) -> Result<&'a str, GatewayError> {
    optional_str(map, key)
        .ok_or_else(|| GatewayError::Rejected(format!("upload ticket missing {key}")))
}

fn optional_str<'a>(map: &'a BTreeMap<String, Value>, key: &'static str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

fn required_i64(map: &BTreeMap<String, Value>, key: &'static str) -> Result<i64, GatewayError> {
    map.get(key)
        .and_then(Value::as_int)
        .ok_or_else(|| GatewayError::Rejected(format!("upload ticket missing {key}")))
}

fn optional_u64(
    map: &BTreeMap<String, Value>,
    key: &'static str,
) -> Result<Option<u64>, GatewayError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Int(n)) if *n >= 0 => Ok(Some(*n as u64)),
        _ => Err(GatewayError::Rejected(format!(
            "upload ticket {key} must be a non-negative integer"
        ))),
    }
}

fn optional_bool(map: &BTreeMap<String, Value>, key: &'static str) -> Option<bool> {
    map.get(key).and_then(Value::as_bool)
}

fn optional_string_list(
    map: &BTreeMap<String, Value>,
    key: &'static str,
) -> Result<Vec<String>, GatewayError> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::List(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_string).ok_or_else(|| {
                    GatewayError::Rejected(format!("upload ticket {key} must contain strings"))
                })
            })
            .collect(),
        _ => Err(GatewayError::Rejected(format!(
            "upload ticket {key} must be a list"
        ))),
    }
}

fn parse_modality(value: &str) -> Result<GatewayModality, GatewayError> {
    match value {
        "value" | "VALUE" => Ok(GatewayModality::Value),
        "text" | "TEXT" => Ok(GatewayModality::Text),
        "bytes" | "BYTES" => Ok(GatewayModality::Bytes),
        "tensor" | "TENSOR" => Ok(GatewayModality::Tensor),
        "audio_frame" | "AUDIO_FRAME" => Ok(GatewayModality::AudioFrame),
        "video_frame" | "VIDEO_FRAME" => Ok(GatewayModality::VideoFrame),
        "pose_frame" | "POSE_FRAME" => Ok(GatewayModality::PoseFrame),
        "sensor_frame" | "SENSOR_FRAME" => Ok(GatewayModality::SensorFrame),
        "event" | "EVENT" => Ok(GatewayModality::Event),
        "control" | "CONTROL" => Ok(GatewayModality::Control),
        _ => Err(GatewayError::Rejected(
            "upload ticket modality is invalid".into(),
        )),
    }
}

impl GatewayModality {
    fn as_str(self) -> &'static str {
        match self {
            GatewayModality::Value => "value",
            GatewayModality::Text => "text",
            GatewayModality::Bytes => "bytes",
            GatewayModality::Tensor => "tensor",
            GatewayModality::AudioFrame => "audio_frame",
            GatewayModality::VideoFrame => "video_frame",
            GatewayModality::PoseFrame => "pose_frame",
            GatewayModality::SensorFrame => "sensor_frame",
            GatewayModality::Event => "event",
            GatewayModality::Control => "control",
        }
    }
}

impl GatewayStreamDirection {
    fn as_str(self) -> &'static str {
        match self {
            GatewayStreamDirection::ClientToKernel => "client_to_kernel",
            GatewayStreamDirection::KernelToClient => "kernel_to_client",
            GatewayStreamDirection::StateSubscriptionToClient => "state_subscription_to_client",
        }
    }
}

fn value_any(value: &Value, pred: impl Fn(&Value) -> bool) -> bool {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        if pred(value) {
            return true;
        }
        match value {
            Value::List(items) => {
                for item in items {
                    stack.push(item);
                }
            }
            Value::Map(map) => {
                for value in map.values() {
                    stack.push(value);
                }
            }
            _ => {}
        }
    }
    false
}

fn has_provenance(provenance: Option<&GatewayPayloadProvenance>) -> bool {
    let Some(provenance) = provenance else {
        return false;
    };
    provenance
        .upload_ticket
        .as_ref()
        .is_some_and(|ticket| !ticket.trim().is_empty())
        || provenance.store_proof.as_ref().is_some_and(|proof| {
            !proof.store_id.trim().is_empty() && !proof.proof.trim().is_empty()
        })
}

fn inspect_program(
    program: &DoNode,
    profile: &CompiledGatewayProfile,
    principal_id: Option<&str>,
    boot: Option<&Bootstrap>,
    now_ms: i64,
    validate_input_schema: bool,
) -> Result<ProgramAdmission, GatewayError> {
    let limits = &profile.limits;
    let mut admission = ProgramAdmission::default();
    let mut stack = vec![(program, 1usize)];
    while let Some((node, depth)) = stack.pop() {
        admission.inspection.node_count = admission.inspection.node_count.saturating_add(1);
        if admission.inspection.node_count > limits.max_program_nodes {
            return Err(GatewayError::Rejected(format!(
                "program exceeds max_program_nodes ({})",
                limits.max_program_nodes
            )));
        }
        admission.inspection.max_depth = admission.inspection.max_depth.max(depth);
        if depth > limits.max_program_depth {
            return Err(GatewayError::Rejected(format!(
                "program exceeds max_program_depth ({})",
                limits.max_program_depth
            )));
        }

        match node {
            DoNode::Pure(value) => add_value_bytes(&mut admission.inspection, value, limits)?,
            DoNode::AndThen { d, then } => {
                inspect_step_ref(&mut admission.inspection, then, limits)?;
                stack.push((d, depth.saturating_add(1)));
            }
            DoNode::OrElse { d, or } => {
                inspect_step_ref(&mut admission.inspection, or, limits)?;
                stack.push((d, depth.saturating_add(1)));
            }
            DoNode::Both(a, b) | DoNode::Race(a, b) => {
                stack.push((a, depth.saturating_add(1)));
                stack.push((b, depth.saturating_add(1)));
            }
            DoNode::Let { name, value, body } => {
                add_literal_bytes(&mut admission.inspection, name.len(), limits)?;
                stack.push((value, depth.saturating_add(1)));
                stack.push((body, depth.saturating_add(1)));
            }
            DoNode::Use(name) => {
                add_literal_bytes(&mut admission.inspection, name.len(), limits)?;
            }
            DoNode::Acting { body, .. } => {
                admission.inspection.acting_count =
                    admission.inspection.acting_count.saturating_add(1);
                if !limits.allow_acting {
                    return Err(GatewayError::Rejected(
                        "external submissions cannot contain Acting by default".into(),
                    ));
                }
                stack.push((body, depth.saturating_add(1)));
            }
            DoNode::Fail(failure) => {
                add_literal_bytes(
                    &mut admission.inspection,
                    failure_literal_bytes(failure),
                    limits,
                )?;
            }
            DoNode::Wait(spec) => inspect_wait(&mut admission.inspection, spec, limits, now_ms)?,
            DoNode::Op(tmpl) => inspect_operation(
                &mut admission,
                tmpl,
                profile,
                principal_id,
                boot,
                limits,
                validate_input_schema,
            )?,
        }
    }
    Ok(admission)
}

#[derive(Default)]
struct ProgramAdmission {
    inspection: ProgramInspection,
    surface_ids: BTreeSet<String>,
    requires_idempotency: bool,
}

fn inspect_step_ref(
    inspection: &mut ProgramInspection,
    step: &StepRef,
    limits: &GatewayLimitProfile,
) -> Result<(), GatewayError> {
    inspection.step_ref_count = inspection.step_ref_count.saturating_add(1);
    if !limits.allow_step_refs {
        return Err(GatewayError::Rejected(
            "external submissions cannot contain StepRef by default".into(),
        ));
    }
    add_literal_bytes(inspection, step.name.len(), limits)?;
    if let Some(arg) = &step.arg {
        add_value_bytes(inspection, arg, limits)?;
    }
    Ok(())
}

fn inspect_wait(
    inspection: &mut ProgramInspection,
    spec: &WaitSpec,
    limits: &GatewayLimitProfile,
    now_ms: i64,
) -> Result<(), GatewayError> {
    match spec {
        WaitSpec::Signal(_) => {
            inspection.wait_signal_count = inspection.wait_signal_count.saturating_add(1);
            if !limits.allow_wait_signal {
                return Err(GatewayError::Rejected(
                    "external submissions cannot contain Wait(Signal) by default".into(),
                ));
            }
        }
        WaitSpec::Deadline(at_ms) => {
            inspection.wait_deadline_count = inspection.wait_deadline_count.saturating_add(1);
            if !limits.allow_wait_deadline {
                return Err(GatewayError::Rejected(
                    "external submissions cannot contain Wait(Deadline) by default".into(),
                ));
            }
            if at_ms.saturating_sub(now_ms) > limits.max_deadline_ms_from_now {
                return Err(GatewayError::Rejected(format!(
                    "deadline exceeds max_deadline_ms_from_now ({})",
                    limits.max_deadline_ms_from_now
                )));
            }
        }
    }
    Ok(())
}

fn inspect_operation(
    admission: &mut ProgramAdmission,
    tmpl: &OperationTemplate,
    profile: &CompiledGatewayProfile,
    principal_id: Option<&str>,
    boot: Option<&Bootstrap>,
    limits: &GatewayLimitProfile,
    validate_input_schema: bool,
) -> Result<(), GatewayError> {
    admission.inspection.operation_count = admission.inspection.operation_count.saturating_add(1);
    match principal_id {
        Some(principal_id) => {
            let Some(surface) =
                profile.operation_surface_for_principal(principal_id, &tmpl.target, &tmpl.method)
            else {
                return Err(GatewayError::Rejected(format!(
                    "operation {}.{} is not callable by principal",
                    tmpl.target.path(),
                    tmpl.method
                )));
            };
            if let Some(boot) = boot {
                let metadata = operation_method_metadata(boot, &surface.target, &surface.method)?;
                let replay = metadata.replay;
                if matches!(replay, ReplayClass::NonIdempotentEffect) {
                    admission.requires_idempotency = true;
                }
                admission.inspection.estimated_cost_micro_usd = admission
                    .inspection
                    .estimated_cost_micro_usd
                    .saturating_add(estimate_gateway_operation_cost(
                        &metadata.cost,
                        metadata.batchable,
                        tmpl.literal_input.as_ref(),
                    ));
            }
            if validate_input_schema && let Some(input) = &tmpl.literal_input {
                validate_surface_input(surface, input)?;
            }
            admission.surface_ids.insert(surface.surface_id.clone());
        }
        None => {
            if !profile.has_operation_surface(&tmpl.target, &tmpl.method) {
                return Err(GatewayError::Rejected(format!(
                    "operation {}.{} is not exposed by gateway profile",
                    tmpl.target.path(),
                    tmpl.method
                )));
            }
        }
    }
    if let OutputMode::Collect { limit } = tmpl.output
        && limit > limits.max_collect_limit
    {
        return Err(GatewayError::Rejected(format!(
            "collect limit exceeds max_collect_limit ({})",
            limits.max_collect_limit
        )));
    }
    if let Some(input) = &tmpl.literal_input {
        add_value_bytes(&mut admission.inspection, input, limits)?;
    }
    Ok(())
}

fn add_value_bytes(
    inspection: &mut ProgramInspection,
    value: &Value,
    limits: &GatewayLimitProfile,
) -> Result<(), GatewayError> {
    add_value_bytes_with_label(inspection, value, limits, "program")
}

fn validate_inline_value_bytes(
    value: &Value,
    limits: &GatewayLimitProfile,
    label: &str,
) -> Result<(), GatewayError> {
    let mut inspection = ProgramInspection::default();
    add_value_bytes_with_label(&mut inspection, value, limits, label)
}

fn add_value_bytes_with_label(
    inspection: &mut ProgramInspection,
    value: &Value,
    limits: &GatewayLimitProfile,
    label: &str,
) -> Result<(), GatewayError> {
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            Value::Null | Value::Bool(_) => {
                add_literal_bytes_with_label(inspection, 1, limits, label)?
            }
            Value::Int(_) | Value::Float(_) => {
                add_literal_bytes_with_label(inspection, 8, limits, label)?
            }
            Value::Str(s) => add_literal_bytes_with_label(inspection, s.len(), limits, label)?,
            Value::Bytes(b) => add_literal_bytes_with_label(inspection, b.len(), limits, label)?,
            Value::List(items) => {
                add_literal_bytes_with_label(inspection, items.len(), limits, label)?;
                for item in items {
                    stack.push(item);
                }
            }
            Value::Map(m) => {
                add_literal_bytes_with_label(inspection, m.len(), limits, label)?;
                for (key, value) in m {
                    add_literal_bytes_with_label(inspection, key.len(), limits, label)?;
                    stack.push(value);
                }
            }
            Value::Blob(blob) => {
                add_literal_bytes_with_label(inspection, blob.hash.len() + 16, limits, label)?;
                if let Some(mime) = &blob.mime {
                    add_literal_bytes_with_label(inspection, mime.len(), limits, label)?;
                }
            }
            Value::Tensor(tensor) => {
                add_literal_bytes_with_label(
                    inspection,
                    tensor.blob.hash.len() + tensor.shape.len().saturating_mul(8) + 16,
                    limits,
                    label,
                )?;
                if let Some(mime) = &tensor.blob.mime {
                    add_literal_bytes_with_label(inspection, mime.len(), limits, label)?;
                }
            }
            Value::Frame(frame) => {
                add_literal_bytes_with_label(
                    inspection,
                    frame.blob.hash.len() + 24,
                    limits,
                    label,
                )?;
                if let Some(mime) = &frame.blob.mime {
                    add_literal_bytes_with_label(inspection, mime.len(), limits, label)?;
                }
            }
            Value::StreamEnd(marker) => match marker {
                nexus_types::StreamMarker::Done => {
                    add_literal_bytes_with_label(inspection, 1, limits, label)?
                }
                nexus_types::StreamMarker::Error { message } => {
                    add_literal_bytes_with_label(inspection, message.len(), limits, label)?
                }
            },
        }
    }
    Ok(())
}

fn add_literal_bytes(
    inspection: &mut ProgramInspection,
    bytes: usize,
    limits: &GatewayLimitProfile,
) -> Result<(), GatewayError> {
    add_literal_bytes_with_label(inspection, bytes, limits, "program")
}

fn add_literal_bytes_with_label(
    inspection: &mut ProgramInspection,
    bytes: usize,
    limits: &GatewayLimitProfile,
    label: &str,
) -> Result<(), GatewayError> {
    inspection.literal_bytes = inspection.literal_bytes.saturating_add(bytes);
    if inspection.literal_bytes > limits.max_literal_bytes {
        return Err(GatewayError::Rejected(format!(
            "{label} exceeds max_literal_bytes ({})",
            limits.max_literal_bytes
        )));
    }
    Ok(())
}

fn failure_literal_bytes(failure: &Failure) -> usize {
    failure.to_string().len()
}

fn now_millis() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(now.as_millis()).unwrap_or(i64::MAX)
}

/// Helper: a trivial program returning a fixed value (health checks).
pub fn pure_program(v: Value) -> DoNode {
    DoNode::pure(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    const TEST_TOKEN: &str = "test-token-for-alice-0001";

    #[test]
    fn secure_external_frame_types_are_canonical() {
        assert_eq!(
            secure_external_inner_frame_type(&external_pb::external_frame::Frame::InboundEvent(
                external_pb::InboundEvent::default()
            ))
            .unwrap(),
            "inbound_event"
        );
        assert_eq!(
            secure_external_inner_frame_type(&external_pb::external_frame::Frame::CommandResult(
                external_pb::CommandResult::default()
            ))
            .unwrap(),
            "command_result"
        );
        assert_eq!(
            secure_external_inner_frame_type(&external_pb::external_frame::Frame::InvokeResult(
                external_pb::InvokeResult::default()
            ))
            .unwrap(),
            "invoke_result"
        );
        assert_eq!(
            secure_external_inner_frame_type(&external_pb::external_frame::Frame::ProviderReady(
                external_pb::ProviderReady::default()
            ))
            .unwrap(),
            "provider_ready"
        );
        assert_eq!(
            secure_external_inner_frame_type(&external_pb::external_frame::Frame::Control(
                external_pb::ControlFrame {
                    kind: Some(external_pb::control_frame::Kind::ConfigAck(
                        external_pb::ConfigAck::default()
                    )),
                }
            ))
            .unwrap(),
            "control.config_ack"
        );
    }

    #[test]
    fn secure_external_envelope_context_must_match_session() {
        let context = ExternalSessionContext {
            installation_id: "install".into(),
            projection_id: "source".into(),
            role: ExternalRole::Source,
            registry_hash: "hash".into(),
            credential_generation: 2,
            binding_generation: 3,
            installation_config_version: 4,
            projection_version: 5,
            presentation_config_generation: 6,
            alias_catalog_generation: 7,
            session_id: "session".into(),
        };
        let mut envelope = SecureEnvelope {
            installation_id: context.installation_id.clone(),
            generation: context.credential_generation,
            aad: EnvelopeAad {
                version: 1,
                projection_id: context.projection_id.clone(),
                role: external_role_slug(context.role).into(),
                session_id: context.session_id.clone(),
                frame_type: "inbound_event".into(),
                binding_generation: context.binding_generation,
                credential_generation: context.credential_generation,
                transcript_hash: vec![0; 32],
                ..EnvelopeAad::default()
            },
            nonce_prefix: [0; 12],
            ciphertext: Vec::new(),
        };
        validate_secure_external_envelope_context(&envelope, &context).unwrap();

        envelope.aad.role = "provider".into();
        assert_eq!(
            validate_secure_external_envelope_context(&envelope, &context).unwrap_err(),
            ExternalFrameError::SecureEnvelopeContextRejected
        );
    }

    struct BlockingCountingDriver {
        count: Arc<AtomicUsize>,
        released: Arc<AtomicBool>,
        release: Arc<tokio::sync::Notify>,
    }

    #[async_trait::async_trait]
    impl nexus_kernel::Driver for BlockingCountingDriver {
        async fn call(
            &self,
            _method: nexus_types::MethodId,
            input: Value,
            _output: OutputMode,
            _ctx: &nexus_kernel::DriverContext,
        ) -> Result<Outcome, nexus_kernel::DriverError> {
            self.count.fetch_add(1, Ordering::AcqRel);
            while !self.released.load(Ordering::Acquire) {
                self.release.notified().await;
            }
            Ok(Outcome::Done(input))
        }
    }

    struct TestStateAppendDriver {
        state: nexus_state::Backend,
    }

    #[async_trait::async_trait]
    impl nexus_kernel::Driver for TestStateAppendDriver {
        async fn call(
            &self,
            method: nexus_types::MethodId,
            input: Value,
            _output: OutputMode,
            ctx: &nexus_kernel::DriverContext,
        ) -> Result<Outcome, nexus_kernel::DriverError> {
            if method.get() != 0 {
                return Err(nexus_kernel::DriverError::NoSuchMethod(method));
            }
            let path = ctx
                .target_path
                .clone()
                .ok_or_else(|| nexus_kernel::DriverError::Other("missing target path".into()))?;
            self.state
                .write_append_tainted(&path, input, ctx.taint.clone())
                .await
                .map_err(|e| nexus_kernel::DriverError::Other(e.to_string()))?;
            Ok(Outcome::Done(Value::Null))
        }
    }

    fn identity_profile() -> GatewayProfile {
        GatewayProfile::new("program")
            .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")
            .unwrap()
    }

    fn client_certificate_profile() -> GatewayProfile {
        GatewayProfile::new("program")
            .with_credential(GatewayCredential::client_certificate_der_sha256(
                "cert-alice",
                "alice",
                ClientCertificateDerSha256::from_der(b"alice-client-cert-der"),
            ))
            .with_identity_mapping(GatewayIdentityMapping::new("alice", "process://alice"))
    }

    #[test]
    fn gateway_host_matching_requires_exact_host_and_port() {
        let registered = vec![
            GatewayAllowedHost::parse("Api.Example.com").unwrap(),
            GatewayAllowedHost::parse("[2001:db8::10]:7443").unwrap(),
        ];
        assert!(gateway_host_allowed("api.example.com", &registered));
        assert!(gateway_host_allowed("[2001:db8::10]:7443", &registered));
        assert!(!gateway_host_allowed("api.example.com:443", &registered));
        assert!(!gateway_host_allowed("other.example.com", &registered));
        assert!(!gateway_host_allowed(
            "https://api.example.com",
            &registered
        ));
        assert!(GatewayAllowedHost::parse("api.example.com:443:bad").is_err());
        assert!(GatewayAllowedHost::parse("*.example.com").is_err());
    }

    #[test]
    fn browser_origin_matching_is_exact_except_configured_port_relaxation() {
        let registered = vec![GatewayAllowedOrigin::parse("https://App.Example.com:443").unwrap()];
        assert!(browser_origin_allowed(
            "https://app.example.com",
            &registered,
            false
        ));
        assert!(!browser_origin_allowed(
            "https://app.example.com:8443",
            &registered,
            false
        ));
        assert!(browser_origin_allowed(
            "https://app.example.com:8443",
            &registered,
            true
        ));
        assert!(!browser_origin_allowed(
            "http://app.example.com:8443",
            &registered,
            true
        ));
        assert!(!browser_origin_allowed(
            "https://evil.example.com:8443",
            &registered,
            true
        ));
        assert!(!browser_origin_allowed(
            "https://app.example.com/path",
            &registered,
            true
        ));
    }

    #[test]
    fn profile_rejects_duplicate_registered_origins() {
        let profile = GatewayProfile::new("program")
            .with_registered_origin("https://app.example.com")
            .unwrap()
            .with_registered_origin("https://APP.example.com:443")
            .unwrap();
        let err = match GatewayRuntime::new(Arc::new(Bootstrap::in_memory()), profile) {
            Ok(_) => panic!("duplicate origin should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, GatewayError::InvalidProfile(_)));
    }

    #[test]
    fn profile_rejects_duplicate_registered_hosts() {
        let profile = GatewayProfile::new("program")
            .with_registered_host("api.example.com")
            .unwrap()
            .with_registered_host("API.example.com")
            .unwrap();
        let err = match GatewayRuntime::new(Arc::new(Bootstrap::in_memory()), profile) {
            Ok(_) => panic!("duplicate host should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, GatewayError::InvalidProfile(_)));
    }

    fn op(path: &str, input: Value) -> DoNode {
        DoNode::op(OperationTemplate {
            target: ResourceName::new(Path::parse(path).unwrap()),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(input),
        })
    }

    fn program_submission(program: DoNode) -> GatewaySubmission {
        GatewaySubmission::from(ProgramSubmission::new(program))
    }

    fn schema_type(kind: &str) -> Value {
        Value::Map(BTreeMap::from([("type".into(), Value::from(kind))]))
    }

    fn array_schema(item: Value) -> Value {
        Value::Map(BTreeMap::from([
            ("type".into(), Value::from("array")),
            ("items".into(), item),
        ]))
    }

    fn text_object_schema() -> Value {
        Value::Map(BTreeMap::from([
            ("type".into(), Value::from("object")),
            ("required".into(), Value::List(vec![Value::from("text")])),
            (
                "properties".into(),
                Value::Map(BTreeMap::from([("text".into(), schema_type("string"))])),
            ),
        ]))
    }

    fn direct_input_with_provenance(
        surface_id: &str,
        payload: Value,
        provenance: GatewayPayloadProvenance,
    ) -> GatewaySubmission {
        GatewaySubmission {
            surface_id: surface_id.into(),
            body: GatewaySubmissionBody::DirectInput(GatewayDirectInput {
                payload,
                provenance: Some(provenance),
            }),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
        }
    }

    fn direct_input_with_ticket(
        surface_id: &str,
        payload: Value,
        ticket_id: &str,
    ) -> GatewaySubmission {
        GatewaySubmission {
            surface_id: surface_id.into(),
            body: GatewaySubmissionBody::DirectInput(GatewayDirectInput {
                payload,
                provenance: Some(GatewayPayloadProvenance {
                    upload_ticket: Some(ticket_id.into()),
                    store_proof: None,
                }),
            }),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
        }
    }

    fn input_stream_submission(surface_id: &str) -> GatewaySubmission {
        GatewaySubmission {
            surface_id: surface_id.into(),
            body: GatewaySubmissionBody::InputStream(GatewayStreamOpenRequest {
                stream_id: "input".into(),
                direction: GatewayStreamDirection::ClientToKernel,
                modality: GatewayModality::Text,
                item_schema_id: String::new(),
                max_inline_item_bytes: 16,
                max_items: Some(4),
                max_bytes: Some(64),
            }),
            requested_output: OutputMode::Unary,
            options: SubmitOptions::default(),
        }
    }

    fn echo_profile(name: ResourceName) -> GatewayProfile {
        identity_profile()
            .with_surface(GatewaySurface::operation(
                "echo",
                name,
                "invoke",
                "perform",
                "perform://effect/echo/say",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["echo"],
                ["perform://effect/echo/say"],
            ))
    }

    fn bind_alice_to_echo(profile: GatewayProfile) -> GatewayProfile {
        profile.with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/echo/say"],
        ))
    }

    fn assert_limit_contains(err: GatewayError, needle: &str) {
        match err {
            GatewayError::LimitExceeded(message) => assert!(
                message.contains(needle),
                "limit message {message:?} did not contain {needle:?}"
            ),
            other => panic!("expected limit error, got {other:?}"),
        }
    }

    fn restricted_anchor(boot: &Bootstrap, selector: &str) -> ProcessId {
        let anchor = boot.kernel.processes.fresh_id();
        let mut entry = nexus_kernel::ProcessEntry::new(
            anchor,
            Some(boot.root),
            nexus_types::IdentityRef::ROOT,
        );
        entry.status = nexus_types::ProcessStatus::Running;
        boot.kernel.processes.insert(entry);
        boot.kernel.registry.register_grant(nexus_types::Grant {
            id: boot.kernel.registry.next_grant_id(),
            holder: anchor,
            selector: nexus_types::ResourceSelector::parse(selector).unwrap(),
            rights: nexus_types::Rights::new(
                nexus_types::MethodBitmap::ALL,
                nexus_types::RightFlags::empty(),
            ),
            constraints: nexus_types::ConstraintSet::empty(),
            expires: nexus_types::Expiry::Never,
        });
        anchor
    }

    #[tokio::test]
    async fn unknown_bearer_is_unauthenticated() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, identity_profile()).unwrap();
        assert!(matches!(
            gw.authenticate(PresentedCredential::bearer("unknown-token-for-test"))
                .await,
            Err(GatewayError::Unauthenticated)
        ));
    }

    #[tokio::test]
    async fn bearer_maps_to_profile_identity() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, identity_profile()).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        assert_eq!(session.principal.principal_id, "alice");
        assert_eq!(session.identity_path, "process://alice");
    }

    #[tokio::test]
    async fn client_certificate_fingerprint_maps_to_profile_identity() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, client_certificate_profile()).unwrap();
        assert!(gw.is_ready());
        let session = gw
            .authenticate(PresentedCredential::client_certificate_der(
                b"alice-client-cert-der",
            ))
            .await
            .unwrap();
        assert_eq!(session.principal.principal_id, "alice");
        assert_eq!(
            session.principal.auth_method,
            GatewayAuthMethod::ClientCertificate
        );
        assert_eq!(session.identity_path, "process://alice");
    }

    #[tokio::test]
    async fn unknown_client_certificate_is_unauthenticated() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, client_certificate_profile()).unwrap();
        assert!(matches!(
            gw.authenticate(PresentedCredential::client_certificate_der(
                b"unknown-client-cert-der",
            ))
            .await,
            Err(GatewayError::Unauthenticated)
        ));
    }

    #[test]
    fn public_error_messages_are_redacted() {
        assert_eq!(
            GatewayError::Unauthorized("alice".into()).public_message(),
            "authorization failed"
        );
        assert_eq!(
            GatewayError::Rejected("reserved path state://vault/console/root/password".into())
                .public_message(),
            "request rejected"
        );
    }

    #[test]
    fn credential_debug_output_is_redacted() {
        let token_hash = BearerTokenHash::from_token(TEST_TOKEN).unwrap();
        let debug_hash = format!("{token_hash:?}");
        assert!(debug_hash.contains("<redacted>"));
        assert!(!debug_hash.contains(TEST_TOKEN));
        assert!(!debug_hash.contains(&hash_bearer_token(TEST_TOKEN)));

        let credential =
            GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN).unwrap();
        let debug_credential = format!("{credential:?}");
        assert!(debug_credential.contains("<redacted>"));
        assert!(!debug_credential.contains(TEST_TOKEN));
        assert!(!debug_credential.contains(&hash_bearer_token(TEST_TOKEN)));
    }

    #[tokio::test]
    async fn submit_runs_pure_program() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, identity_profile()).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let out = gw
            .submit(&session, program_submission(DoNode::pure(Value::Int(7))))
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Int(7)));
        assert!(out.accepted.submission_id.starts_with("gw-submission-"));
        assert!(out.accepted.trace_root.starts_with("gw-trace-"));
        assert_ne!(out.accepted.submission_id, out.accepted.trace_root);
        assert_eq!(out.accepted.profile_rev, 1);
    }

    #[tokio::test]
    async fn cancel_requires_owner_and_trace_root() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://slow/echo",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Effectful,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(BlockingCountingDriver {
                    count: Arc::new(AtomicUsize::new(0)),
                    released: Arc::new(AtomicBool::new(false)),
                    release: Arc::new(tokio::sync::Notify::new()),
                }),
            )
            .unwrap();
        let profile = identity_profile()
            .with_surface(GatewaySurface::operation(
                "slow",
                name,
                "invoke",
                "perform",
                "perform://effect/slow/echo",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["slow"],
                ["perform://effect/slow/echo"],
            ));
        let gw = Arc::new(GatewayRuntime::new(boot.clone(), profile).unwrap());
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let running = {
            let gw = gw.clone();
            let session = session.clone();
            tokio::spawn(async move {
                gw.submit(
                    &session,
                    GatewaySubmission::direct_input("slow", Value::Str("work".into()))
                        .with_options(SubmitOptions {
                            idempotency_key: Some("slow-cancel".into()),
                            ..SubmitOptions::default()
                        }),
                )
                .await
            })
        };
        let entry = loop {
            if let Some(entry) = gw
                .requests
                .inner
                .lock()
                .entries
                .values()
                .find(|entry| entry.state == GatewayRequestState::Running)
                .cloned()
            {
                break entry;
            }
            tokio::task::yield_now().await;
        };

        let mut wrong_owner = session.clone();
        wrong_owner.principal.principal_id = "bob".into();
        assert!(
            !gw.cancel(
                &wrong_owner,
                GatewayCancelRequest {
                    submission_id: entry.accepted.submission_id.clone(),
                    trace_root: entry.accepted.trace_root.clone(),
                    reason: None,
                },
            )
            .unwrap()
        );
        assert!(
            !gw.cancel(
                &session,
                GatewayCancelRequest {
                    submission_id: entry.accepted.submission_id.clone(),
                    trace_root: "wrong-trace-root".into(),
                    reason: None,
                },
            )
            .unwrap()
        );
        assert!(
            gw.cancel(
                &session,
                GatewayCancelRequest {
                    submission_id: entry.accepted.submission_id.clone(),
                    trace_root: entry.accepted.trace_root.clone(),
                    reason: Some("client_cancel".into()),
                },
            )
            .unwrap()
        );
        assert_eq!(
            boot.kernel.processes.status(entry.request_process),
            Some(ProcessStatus::Cancelled)
        );
        assert_eq!(
            gw.requests
                .inner
                .lock()
                .entries
                .get(&entry.accepted.submission_id)
                .map(|entry| entry.state),
            Some(GatewayRequestState::Cancelled)
        );

        running.abort();
    }

    #[tokio::test]
    async fn cancel_releases_admission_and_budget_before_driver_returns() {
        let boot = Arc::new(Bootstrap::in_memory());
        let count = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let slow = boot
            .register_effect(
                "effect://cancel/slow",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Effectful,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(BlockingCountingDriver {
                    count: count.clone(),
                    released: released.clone(),
                    release: release.clone(),
                }),
            )
            .unwrap();
        let fast = boot
            .register_effect(
                "effect://cancel/fast",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let limits = GatewayLimitProfile {
            max_in_flight_requests: 1,
            budget: GatewayBudgetProfile {
                max_inflight_ops: Some(1),
                ..GatewayBudgetProfile::default()
            },
            ..GatewayLimitProfile::default()
        };
        let profile = identity_profile()
            .with_limits(limits)
            .with_surface(GatewaySurface::operation(
                "slow",
                slow,
                "invoke",
                "perform",
                "perform://effect/cancel/slow",
            ))
            .with_surface(GatewaySurface::operation(
                "fast",
                fast,
                "invoke",
                "perform",
                "perform://effect/cancel/fast",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["slow", "fast"],
                [
                    "perform://effect/cancel/slow",
                    "perform://effect/cancel/fast",
                ],
            ));
        let gw = Arc::new(GatewayRuntime::new(boot.clone(), profile).unwrap());
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let running = {
            let gw = gw.clone();
            let session = session.clone();
            tokio::spawn(async move {
                gw.submit(
                    &session,
                    GatewaySubmission::direct_input("slow", Value::Str("work".into()))
                        .with_options(SubmitOptions {
                            idempotency_key: Some("cancel-slow-once".into()),
                            ..SubmitOptions::default()
                        }),
                )
                .await
            })
        };
        while count.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        let entry = gw
            .requests
            .inner
            .lock()
            .entries
            .values()
            .find(|entry| entry.state == GatewayRequestState::Running)
            .cloned()
            .expect("running request entry");

        assert!(matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fast", Value::Str("before".into()))
            )
            .await,
            Err(GatewayError::LimitExceeded(_))
        ));
        assert!(
            gw.cancel(
                &session,
                GatewayCancelRequest {
                    submission_id: entry.accepted.submission_id,
                    trace_root: entry.accepted.trace_root,
                    reason: Some("client_cancel".into()),
                },
            )
            .unwrap()
        );

        let out = gw
            .submit(
                &session,
                GatewaySubmission::direct_input("fast", Value::Str("after".into())),
            )
            .await
            .unwrap();
        assert_eq!(out.outcome, Outcome::Done(Value::Str("after".into())));

        released.store(true, Ordering::Release);
        release.notify_waiters();
        let _ = running.await.unwrap();
    }

    #[tokio::test]
    async fn request_runs_as_attenuated_child_not_root() {
        let boot = Arc::new(Bootstrap::in_memory());
        let root = boot.root;
        let gw = GatewayRuntime::new(boot.clone(), identity_profile()).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let profile = gw.profile_snapshot();
        let p1 = gw
            .spawn_gateway_request_process(&profile, &session, &BTreeSet::new())
            .unwrap();
        let p2 = gw
            .spawn_gateway_request_process(&profile, &session, &BTreeSet::new())
            .unwrap();
        assert_ne!(p1, root);
        assert_ne!(p2, root);
        assert_ne!(p1, p2, "each request gets its own attenuated Process");
    }

    #[test]
    fn malformed_profile_rejects_unmapped_principal() {
        let profile = GatewayProfile::new("program").with_credential(
            GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN).unwrap(),
        );
        assert!(matches!(
            GatewayRuntime::new(Arc::new(Bootstrap::in_memory()), profile),
            Err(GatewayError::InvalidProfile(_))
        ));
    }

    #[test]
    fn malformed_identity_path_rejects_profile() {
        let profile = GatewayProfile::new("program")
            .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "state://alice")
            .unwrap();
        assert!(matches!(
            GatewayRuntime::new(Arc::new(Bootstrap::in_memory()), profile),
            Err(GatewayError::InvalidProfile(_))
        ));
    }

    #[test]
    fn malformed_profile_rejects_zero_revision() {
        let profile = identity_profile().with_revision(0);
        assert!(matches!(
            GatewayRuntime::new(Arc::new(Bootstrap::in_memory()), profile),
            Err(GatewayError::InvalidProfile(_))
        ));
    }

    #[test]
    fn malformed_profile_rejects_duplicate_names() {
        let duplicate_credential = GatewayProfile::new("program")
            .with_identity_mapping(GatewayIdentityMapping::new("alice", "process://alice"))
            .with_credential(
                GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN).unwrap(),
            )
            .with_credential(
                GatewayCredential::bearer_token("cred-alice", "alice", "other-token-for-alice-01")
                    .unwrap(),
            );
        assert!(matches!(
            GatewayRuntime::new(Arc::new(Bootstrap::in_memory()), duplicate_credential),
            Err(GatewayError::InvalidProfile(_))
        ));

        let target = ResourceName::new(Path::parse("effect://echo/say").unwrap());
        let duplicate_surface = identity_profile()
            .with_surface(GatewaySurface::operation(
                "echo",
                target.clone(),
                "invoke",
                "perform",
                "perform://effect/echo/say",
            ))
            .with_surface(GatewaySurface::operation(
                "echo",
                target,
                "invoke",
                "perform",
                "perform://effect/echo/say",
            ));
        assert!(matches!(
            GatewayRuntime::new(Arc::new(Bootstrap::in_memory()), duplicate_surface),
            Err(GatewayError::InvalidProfile(_))
        ));
    }

    #[test]
    fn malformed_profile_rejects_surface_with_missing_method() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = identity_profile().with_surface(GatewaySurface::operation(
            "echo",
            name,
            "missing",
            "perform",
            "perform://effect/echo/say",
        ));
        assert!(matches!(
            GatewayRuntime::new(boot, profile),
            Err(GatewayError::InvalidProfile(_))
        ));
    }

    #[test]
    fn malformed_profile_rejects_surface_exceeding_authority_anchor() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let anchor = restricted_anchor(&boot, "perform://effect/inference/**");
        let profile = echo_profile(name).with_authority_anchor(anchor);
        assert!(matches!(
            GatewayRuntime::new(boot, profile),
            Err(GatewayError::InvalidProfile(_))
        ));
    }

    #[test]
    fn malformed_profile_rejects_surface_exceeding_principal_ceiling() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = identity_profile()
            .with_surface(GatewaySurface::operation(
                "echo",
                name,
                "invoke",
                "perform",
                "perform://effect/echo/say",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["echo"],
                ["perform://effect/inference/**"],
            ));
        assert!(matches!(
            GatewayRuntime::new(boot, profile),
            Err(GatewayError::InvalidProfile(_))
        ));
    }

    #[test]
    fn malformed_profile_rejects_invalid_surface_schemas() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = bind_alice_to_echo(
            identity_profile().with_surface(
                GatewaySurface::operation(
                    "echo",
                    name,
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_schema(Some(Value::from("not-a-schema-object")), None),
            ),
        );
        assert!(matches!(
            GatewayRuntime::new(boot, profile),
            Err(GatewayError::InvalidProfile(_))
        ));

        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = bind_alice_to_echo(
            identity_profile().with_surface(
                GatewaySurface::operation(
                    "echo",
                    name,
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_schema(None, Some(Value::from("not-a-schema-object"))),
            ),
        );
        assert!(matches!(
            GatewayRuntime::new(boot, profile),
            Err(GatewayError::InvalidProfile(_))
        ));
    }

    #[tokio::test]
    async fn submit_uses_restricted_authority_anchor_when_configured() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let anchor = restricted_anchor(&boot, "perform://effect/echo/**");
        let profile = echo_profile(name.clone()).with_authority_anchor(anchor);
        let gw = GatewayRuntime::new(boot.clone(), profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let result = gw
            .submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::Str("ok".into())),
            )
            .await
            .unwrap();
        assert_eq!(result, Outcome::Done(Value::Str("ok".into())));

        let children = boot.kernel.processes.children_of(anchor);
        assert_eq!(children.len(), 1);
        assert!(boot.kernel.registry.grants_of(children[0]).is_empty());
        assert_eq!(boot.kernel.processes.attached_grants(children[0]).len(), 1);
    }

    #[tokio::test]
    async fn submit_narrows_request_grant_to_surface_method() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.register_subtree_resource_at(
            "state://events",
            "append://state/events/**",
            nexus_types::InterfaceFamily::Sequence,
            &[
                nexus_kernel::MethodSpec::new(
                    "write",
                    nexus_types::Purity::Effectful,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                ),
                nexus_kernel::MethodSpec::new(
                    "append",
                    nexus_types::Purity::Effectful,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                ),
            ],
            Arc::new(nexus_kernel::EchoDriver),
        )
        .unwrap();
        let anchor = restricted_anchor(&boot, "append://state/events/**");
        let profile = identity_profile()
            .with_surface(GatewaySurface::state_append(
                "events",
                ResourceName::new(Path::parse("state://events/gateway").unwrap()),
                "append://state/events/gateway",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["events"],
                ["append://state/events/gateway"],
            ))
            .with_authority_anchor(anchor);
        let gw = GatewayRuntime::new(boot.clone(), profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        let result = gw
            .submit(
                &session,
                GatewaySubmission::direct_input("events", Value::Str("ok".into())).with_options(
                    SubmitOptions {
                        idempotency_key: Some("append-grant-method-narrowing".into()),
                        ..SubmitOptions::default()
                    },
                ),
            )
            .await
            .unwrap();
        assert_eq!(result, Outcome::Done(Value::Str("ok".into())));

        let children = boot.kernel.processes.children_of(anchor);
        assert_eq!(children.len(), 1);
        let grants = boot.kernel.processes.attached_grants(children[0]);
        assert_eq!(grants.len(), 1);
        assert!(!grants[0].rights.methods.allows(0));
        assert!(grants[0].rights.methods.allows(1));
    }

    #[tokio::test]
    async fn profile_replace_rejects_old_session_and_keeps_bad_reload_closed() {
        const NEW_TOKEN: &str = "test-token-for-bob-000002";
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot.clone(), identity_profile()).unwrap();
        let old_session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        let new_profile = GatewayProfile::new("program")
            .with_revision(2)
            .with_bearer_identity("cred-bob", "bob", NEW_TOKEN, "process://bob")
            .unwrap();
        assert_eq!(gw.replace_profile(new_profile).unwrap(), 2);
        assert_eq!(gw.profile_rev(), 2);

        assert!(matches!(
            gw.submit(
                &old_session,
                program_submission(DoNode::pure(Value::Int(1)))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
        assert!(matches!(
            gw.authenticate(PresentedCredential::bearer(TEST_TOKEN))
                .await,
            Err(GatewayError::Unauthenticated)
        ));
        let new_session = gw
            .authenticate(PresentedCredential::bearer(NEW_TOKEN))
            .await
            .unwrap();
        assert_eq!(new_session.identity_path, "process://bob");

        let bad_profile = GatewayProfile::new("program")
            .with_revision(3)
            .with_bearer_identity(
                "cred-eve",
                "eve",
                "test-token-for-eve-000003",
                "state://eve",
            )
            .unwrap();
        assert!(matches!(
            gw.replace_profile(bad_profile),
            Err(GatewayError::InvalidProfile(_))
        ));
        assert_eq!(gw.profile_rev(), 2);
        assert!(
            gw.authenticate(PresentedCredential::bearer(NEW_TOKEN))
                .await
                .is_ok()
        );
        let status = gw.status();
        assert_eq!(status.profile_rev, 2);
        assert!(status.ready);
        assert_eq!(status.readiness, GatewayReadiness::DegradedLastKnownGood);
        assert!(status.lkg_active);
        assert_eq!(status.consecutive_failed_reloads, 1);
        assert_eq!(
            status.last_reload_failure.as_ref().map(|failure| {
                (
                    failure.attempted_profile_rev,
                    failure.code.as_str(),
                    failure.public_message.as_str(),
                )
            }),
            Some((3, "invalid_profile", "profile reload rejected"))
        );
    }

    #[tokio::test]
    async fn profile_replace_requires_monotonic_revision() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, identity_profile().with_revision(2)).unwrap();
        assert!(matches!(
            gw.replace_profile(identity_profile().with_revision(2)),
            Err(GatewayError::InvalidProfile(_))
        ));
        assert!(matches!(
            gw.replace_profile(identity_profile().with_revision(1)),
            Err(GatewayError::InvalidProfile(_))
        ));
        assert_eq!(
            gw.replace_profile(identity_profile().with_revision(3))
                .unwrap(),
            3
        );
        let status = gw.status();
        assert_eq!(status.profile_rev, 3);
        assert_eq!(status.readiness, GatewayReadiness::Ready);
        assert!(!status.lkg_active);
        assert_eq!(status.consecutive_failed_reloads, 0);
        assert!(status.last_reload_failure.is_none());
    }

    #[tokio::test]
    async fn disabled_credentials_and_principals_do_not_authenticate() {
        let boot = Arc::new(Bootstrap::in_memory());
        let disabled_credential = GatewayProfile::new("program")
            .with_identity_mapping(GatewayIdentityMapping::new("alice", "process://alice"))
            .with_credential(
                GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN)
                    .unwrap()
                    .with_enabled(false),
            );
        let gw = GatewayRuntime::new(boot.clone(), disabled_credential).unwrap();
        assert!(matches!(
            gw.authenticate(PresentedCredential::bearer(TEST_TOKEN))
                .await,
            Err(GatewayError::Unauthenticated)
        ));

        let disabled_principal = GatewayProfile::new("program")
            .with_identity_mapping(
                GatewayIdentityMapping::new("alice", "process://alice").with_enabled(false),
            )
            .with_credential(
                GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN).unwrap(),
            );
        let gw = GatewayRuntime::new(boot, disabled_principal).unwrap();
        assert!(matches!(
            gw.authenticate(PresentedCredential::bearer(TEST_TOKEN))
                .await,
            Err(GatewayError::Unauthenticated)
        ));
    }

    #[tokio::test]
    async fn credential_revocation_floor_blocks_revoked_generations() {
        let boot = Arc::new(Bootstrap::in_memory());
        let revoked = identity_profile().with_credential_revocation_floor(1);
        let gw = GatewayRuntime::new(boot.clone(), revoked).unwrap();
        assert!(matches!(
            gw.authenticate(PresentedCredential::bearer(TEST_TOKEN))
                .await,
            Err(GatewayError::Unauthenticated)
        ));
        assert_eq!(gw.status().readiness, GatewayReadiness::NotReadyClosed);

        let rotated = GatewayProfile::new("program")
            .with_credential_revocation_floor(1)
            .with_identity_mapping(GatewayIdentityMapping::new("alice", "process://alice"))
            .with_credential(
                GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN)
                    .unwrap()
                    .with_generation(2),
            );
        let gw = GatewayRuntime::new(boot, rotated).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        assert_eq!(session.principal.credential_generation, 2);
        assert_eq!(gw.status().readiness, GatewayReadiness::Ready);
    }

    #[tokio::test]
    async fn generation_bump_invalidates_existing_session() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, identity_profile()).unwrap();
        let old_session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        let bumped = GatewayProfile::new("program")
            .with_revision(2)
            .with_identity_mapping(
                GatewayIdentityMapping::new("alice", "process://alice").with_generation(2),
            )
            .with_credential(
                GatewayCredential::bearer_token("cred-alice", "alice", TEST_TOKEN)
                    .unwrap()
                    .with_generation(2),
            );
        gw.replace_profile(bumped).unwrap();

        assert!(matches!(
            gw.submit(
                &old_session,
                program_submission(DoNode::pure(Value::Int(1)))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
        let new_session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        assert_eq!(new_session.principal.credential_generation, 2);
        assert_eq!(new_session.principal.principal_generation, 2);
        assert!(
            gw.submit(
                &new_session,
                program_submission(DoNode::pure(Value::Int(2)))
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn submitted_operation_uses_profile_owned_surface_handle() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile =
            bind_alice_to_echo(identity_profile().with_surface(GatewaySurface::operation(
                "echo",
                name.clone(),
                "invoke",
                "perform",
                "perform://effect/echo/say",
            )));
        let gw = GatewayRuntime::new(boot, profile).unwrap();

        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let out = gw
            .submit(
                &session,
                program_submission(op("effect://echo/say", Value::Str("via-gateway".into()))),
            )
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Str("via-gateway".into())));
    }

    #[tokio::test]
    async fn direct_input_lowers_through_surface_not_client_target() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile =
            bind_alice_to_echo(identity_profile().with_surface(GatewaySurface::operation(
                "echo",
                name,
                "invoke",
                "perform",
                "perform://effect/echo/say",
            )));
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        let out = gw
            .submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::Str("direct text".into())),
            )
            .await
            .unwrap();

        assert_eq!(out, Outcome::Done(Value::Str("direct text".into())));
    }

    #[tokio::test]
    async fn surface_input_schema_validates_direct_input_and_program_literals() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = bind_alice_to_echo(
            identity_profile().with_surface(
                GatewaySurface::operation(
                    "echo",
                    name,
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_schema(Some(text_object_schema()), None),
            ),
        );
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let valid = Value::Map(BTreeMap::from([(
            "text".into(),
            Value::Str("schema-ok".into()),
        )]));

        let out = gw
            .submit(
                &session,
                GatewaySubmission::direct_input("echo", valid.clone()),
            )
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(valid));

        assert!(matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::Map(BTreeMap::new()))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
        assert!(matches!(
            gw.submit(
                &session,
                program_submission(op("effect://echo/say", Value::Map(BTreeMap::new())))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn surface_output_schema_rejects_success_payload_and_replays_failure() {
        let boot = Arc::new(Bootstrap::in_memory());
        let count = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(true));
        let release = Arc::new(tokio::sync::Notify::new());
        let name = boot
            .register_effect(
                "effect://payment/charge",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Effectful,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(BlockingCountingDriver {
                    count: count.clone(),
                    released,
                    release,
                }),
            )
            .unwrap();
        let profile = identity_profile()
            .with_surface(
                GatewaySurface::operation(
                    "charge",
                    name,
                    "invoke",
                    "perform",
                    "perform://effect/payment/charge",
                )
                .with_schema(Some(schema_type("any")), Some(schema_type("string"))),
            )
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["charge"],
                ["perform://effect/payment/charge"],
            ));
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let submission =
            GatewaySubmission::direct_input("charge", Value::Int(42)).with_options(SubmitOptions {
                idempotency_key: Some("charge-output-schema".into()),
                ..SubmitOptions::default()
            });

        let first = gw.submit(&session, submission.clone()).await.unwrap();
        assert!(matches!(
            first.outcome,
            Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "gateway_output_schema"
        ));
        assert_eq!(count.load(Ordering::Acquire), 1);

        let replay = gw.submit(&session, submission).await.unwrap();
        assert!(matches!(
            replay.outcome,
            Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "gateway_output_schema"
        ));
        assert_eq!(count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn surface_output_schema_does_not_validate_sink_only_delivery() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::SINK_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = bind_alice_to_echo(
            identity_profile().with_surface(
                GatewaySurface::operation(
                    "echo",
                    name,
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_schema(Some(schema_type("any")), Some(schema_type("string"))),
            ),
        );
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let submission = GatewaySubmission {
            surface_id: "echo".into(),
            body: GatewaySubmissionBody::DirectInput(GatewayDirectInput {
                payload: Value::Int(42),
                provenance: None,
            }),
            requested_output: OutputMode::SinkOnly,
            options: SubmitOptions::default(),
        };

        let out = gw.submit(&session, submission).await.unwrap();
        assert_eq!(out, Outcome::Done(Value::Null));
    }

    #[tokio::test]
    async fn direct_input_state_append_surface_writes_declared_stream() {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.register_subtree_resource_at(
            "state://events",
            "append://state/events/**",
            nexus_types::InterfaceFamily::Sequence,
            &[nexus_kernel::MethodSpec::new(
                "append",
                nexus_types::Purity::Effectful,
                nexus_kernel::MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(TestStateAppendDriver {
                state: boot.kernel.state.clone(),
            }),
        )
        .unwrap();
        let stream_path = Path::parse("state://events/gateway").unwrap();
        let stream = ResourceName::new(stream_path.clone());
        let profile = identity_profile()
            .with_surface(GatewaySurface::state_append(
                "events",
                stream,
                "append://state/events/gateway",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["events"],
                ["append://state/events/gateway"],
            ));
        let gw = GatewayRuntime::new(boot.clone(), profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        let out = gw
            .submit(
                &session,
                GatewaySubmission::direct_input("events", Value::Str("event-1".into()))
                    .with_options(SubmitOptions {
                        idempotency_key: Some("append-event-1".into()),
                        ..SubmitOptions::default()
                    }),
            )
            .await
            .unwrap();

        assert!(matches!(out.outcome, Outcome::Done(_) | Outcome::Short(_)));
        let stored = boot.kernel.state.read(&stream_path).await.unwrap();
        assert_eq!(
            stored,
            Some(Value::List(vec![Value::Str("event-1".into())]))
        );
    }

    #[tokio::test]
    async fn input_stream_open_registers_request_before_chunks() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let gw = GatewayRuntime::new(boot, echo_profile(name)).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        let stream = match gw
            .accept_input_stream_submission(&session, input_stream_submission("echo"))
            .await
            .unwrap()
        {
            GatewayInputStreamStart::Accepted(stream) => stream,
            GatewayInputStreamStart::Replay(_) => panic!("expected fresh stream admission"),
        };
        let accepted = stream.accepted().clone();

        assert!(accepted.submission_id.starts_with("gw-submission-"));
        assert!(accepted.trace_root.starts_with("gw-trace-"));
        assert_eq!(accepted.surface_id, "echo");
        assert_eq!(stream.open_request().stream_id, "input");
        assert!(
            gw.cancel(
                &session,
                GatewayCancelRequest {
                    submission_id: accepted.submission_id,
                    trace_root: accepted.trace_root,
                    reason: Some("test".into()),
                },
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn deadline_sweep_releases_stream_admission_once() {
        let boot = Arc::new(Bootstrap::in_memory());
        let count = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let slow = boot
            .register_effect(
                "effect://deadline/slow",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(BlockingCountingDriver {
                    count: count.clone(),
                    released: released.clone(),
                    release: release.clone(),
                }),
            )
            .unwrap();
        let fast = boot
            .register_effect(
                "effect://deadline/fast",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let limits = GatewayLimitProfile {
            max_in_flight_requests: 1,
            budget: GatewayBudgetProfile {
                max_inflight_ops: Some(1),
                ..GatewayBudgetProfile::default()
            },
            ..GatewayLimitProfile::default()
        };
        let profile = identity_profile()
            .with_limits(limits)
            .with_surface(GatewaySurface::operation(
                "slow",
                slow,
                "invoke",
                "perform",
                "perform://effect/deadline/slow",
            ))
            .with_surface(GatewaySurface::operation(
                "fast",
                fast,
                "invoke",
                "perform",
                "perform://effect/deadline/fast",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["slow", "fast"],
                [
                    "perform://effect/deadline/slow",
                    "perform://effect/deadline/fast",
                ],
            ));
        let gw = Arc::new(GatewayRuntime::new(boot.clone(), profile).unwrap());
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let deadline_ms = now_millis().saturating_add(25);
        let stream = match gw
            .accept_input_stream_submission(
                &session,
                input_stream_submission("slow").with_options(SubmitOptions {
                    deadline_ms: Some(u64::try_from(deadline_ms).unwrap()),
                    ..SubmitOptions::default()
                }),
            )
            .await
            .unwrap()
        {
            GatewayInputStreamStart::Accepted(stream) => stream,
            GatewayInputStreamStart::Replay(_) => panic!("expected fresh stream admission"),
        };
        let stream_process = stream.request_process;

        assert!(matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fast", Value::Str("before".into()))
            )
            .await,
            Err(GatewayError::LimitExceeded(_))
        ));
        tokio::time::sleep(std::time::Duration::from_millis(35)).await;
        let _ = gw.sweep_deadline_expired_requests();
        assert_eq!(
            boot.kernel.processes.status(stream_process),
            Some(ProcessStatus::Cancelled)
        );

        let running = {
            let gw = gw.clone();
            let session = session.clone();
            tokio::spawn(async move {
                gw.submit(
                    &session,
                    GatewaySubmission::direct_input("slow", Value::Str("running".into())),
                )
                .await
            })
        };
        while count.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        drop(stream);
        assert!(matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("fast", Value::Str("still-limited".into()))
            )
            .await,
            Err(GatewayError::LimitExceeded(_))
        ));

        released.store(true, Ordering::Release);
        release.notify_waiters();
        let out = running.await.unwrap().unwrap();
        assert_eq!(out.outcome, Outcome::Done(Value::Str("running".into())));
    }

    #[tokio::test]
    async fn input_stream_open_rejects_client_item_schema_selection() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let gw = GatewayRuntime::new(boot.clone(), echo_profile(name)).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let mut submission = input_stream_submission("echo");
        if let GatewaySubmissionBody::InputStream(open) = &mut submission.body {
            open.item_schema_id = "client-schema".into();
        }
        let before = boot.kernel.processes.all_ids().len();

        assert!(matches!(
            gw.accept_input_stream_submission(&session, submission)
                .await,
            Err(GatewayError::Rejected(_))
        ));
        assert_eq!(boot.kernel.processes.all_ids().len(), before);
    }

    #[tokio::test]
    async fn input_stream_open_rejects_profile_stream_budget_overrun_before_process_spawn() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let limits = GatewayLimitProfile {
            max_stream_items: 2,
            max_stream_bytes: 32,
            max_stream_inline_item_bytes: 8,
            ..GatewayLimitProfile::default()
        };
        let gw = GatewayRuntime::new(boot.clone(), echo_profile(name).with_limits(limits)).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let before = boot.kernel.processes.all_ids().len();

        assert!(matches!(
            gw.accept_input_stream_submission(&session, input_stream_submission("echo"))
                .await,
            Err(GatewayError::Rejected(_))
        ));
        assert_eq!(boot.kernel.processes.all_ids().len(), before);
    }

    #[tokio::test]
    async fn input_stream_chunks_use_profile_item_schema() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = identity_profile()
            .with_surface(
                GatewaySurface::operation(
                    "echo",
                    name,
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_schema(
                    Some(array_schema(schema_type("string"))),
                    Some(schema_type("any")),
                ),
            )
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["echo"],
                ["perform://effect/echo/say"],
            ));
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let mut submission = input_stream_submission("echo");
        if let GatewaySubmissionBody::InputStream(open) = &mut submission.body {
            open.modality = GatewayModality::Value;
        }
        let stream = match gw
            .accept_input_stream_submission(&session, submission)
            .await
            .unwrap()
        {
            GatewayInputStreamStart::Accepted(stream) => stream,
            GatewayInputStreamStart::Replay(_) => panic!("expected fresh stream admission"),
        };

        assert!(
            stream
                .validate_chunk_item(&Value::Str("chunk".into()))
                .is_ok()
        );
        assert!(matches!(
            stream.validate_chunk_item(&Value::Int(1)),
            Err(GatewayError::Rejected(_))
        ));

        gw.fail_input_stream_submission(*stream, "test")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn input_stream_completion_reuses_accepted_request() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let gw = GatewayRuntime::new(boot, echo_profile(name)).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        let stream = match gw
            .accept_input_stream_submission(&session, input_stream_submission("echo"))
            .await
            .unwrap()
        {
            GatewayInputStreamStart::Accepted(stream) => stream,
            GatewayInputStreamStart::Replay(_) => panic!("expected fresh stream admission"),
        };
        let accepted = stream.accepted().clone();
        let result = gw
            .complete_input_stream_submission(*stream, Value::Str("stream text".into()), None)
            .await
            .unwrap();

        assert_eq!(result.accepted, accepted);
        assert_eq!(
            result.outcome,
            Outcome::Done(Value::Str("stream text".into()))
        );
    }

    #[tokio::test]
    async fn surface_without_principal_binding_is_not_callable() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = identity_profile().with_surface(GatewaySurface::operation(
            "echo",
            name,
            "invoke",
            "perform",
            "perform://effect/echo/say",
        ));
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        let descriptor = gw.describe(&session).unwrap();
        assert!(descriptor.surfaces.is_empty());
        assert!(matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::Str("denied".into()))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
        assert!(matches!(
            gw.submit(
                &session,
                program_submission(op("effect://echo/say", Value::Str("denied".into())))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn submit_deadline_is_clamped_by_server_profile() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, identity_profile()).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let options = SubmitOptions {
            deadline_ms: Some(
                u64::try_from(
                    now_millis().saturating_add(
                        GatewayLimitProfile::default()
                            .max_deadline_ms_from_now
                            .saturating_add(60_000),
                    ),
                )
                .unwrap(),
            ),
            ..SubmitOptions::default()
        };

        assert!(matches!(
            gw.submit(
                &session,
                GatewaySubmission::program(String::new(), DoNode::pure(Value::Int(1)))
                    .with_options(options)
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn submit_deadline_timeout_is_recorded_for_idempotency_replay() {
        let boot = Arc::new(Bootstrap::in_memory());
        let count = Arc::new(AtomicUsize::new(0));
        let name = boot
            .register_effect(
                "effect://slow/charge",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Effectful,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(BlockingCountingDriver {
                    count: count.clone(),
                    released: Arc::new(AtomicBool::new(false)),
                    release: Arc::new(tokio::sync::Notify::new()),
                }),
            )
            .unwrap();
        let profile = identity_profile()
            .with_surface(GatewaySurface::operation(
                "charge",
                name,
                "invoke",
                "perform",
                "perform://effect/slow/charge",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["charge"],
                ["perform://effect/slow/charge"],
            ));
        let gw = GatewayRuntime::new(boot.clone(), profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let submission = GatewaySubmission::direct_input("charge", Value::Str("42".into()))
            .with_options(SubmitOptions {
                idempotency_key: Some("charge-deadline-timeout".into()),
                deadline_ms: Some(u64::try_from(now_millis().saturating_add(100)).unwrap()),
                ..SubmitOptions::default()
            });

        let first = gw.submit(&session, submission.clone()).await.unwrap();
        assert!(matches!(first.outcome, Outcome::Fail(Failure::Timeout)));
        let entry = gw
            .requests
            .inner
            .lock()
            .entries
            .get(&first.accepted.submission_id)
            .cloned()
            .expect("retained request entry");
        assert_eq!(
            boot.kernel.processes.status(entry.request_process),
            Some(ProcessStatus::Cancelled)
        );
        assert_eq!(count.load(Ordering::Acquire), 1);

        let replay = gw.submit(&session, submission).await.unwrap();
        assert_eq!(replay.outcome, first.outcome);
        assert_eq!(count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn non_idempotent_effect_requires_submission_idempotency() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://payment/charge",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Effectful,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = identity_profile()
            .with_surface(GatewaySurface::operation(
                "charge",
                name,
                "invoke",
                "perform",
                "perform://effect/payment/charge",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["charge"],
                ["perform://effect/payment/charge"],
            ));
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        assert!(matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("charge", Value::Str("42".into()))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));

        let out = gw
            .submit(
                &session,
                GatewaySubmission::direct_input("charge", Value::Str("42".into())).with_options(
                    SubmitOptions {
                        idempotency_key: Some("charge-42".into()),
                        ..SubmitOptions::default()
                    },
                ),
            )
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::Str("42".into())));
    }

    #[tokio::test]
    async fn idempotency_key_replays_without_reexecuting_non_idempotent_effect() {
        let boot = Arc::new(Bootstrap::in_memory());
        let count = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let name = boot
            .register_effect(
                "effect://payment/charge",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Effectful,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(BlockingCountingDriver {
                    count: count.clone(),
                    released: released.clone(),
                    release: release.clone(),
                }),
            )
            .unwrap();
        let profile = identity_profile()
            .with_surface(GatewaySurface::operation(
                "charge",
                name,
                "invoke",
                "perform",
                "perform://effect/payment/charge",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["charge"],
                ["perform://effect/payment/charge"],
            ));
        let gw = Arc::new(GatewayRuntime::new(boot, profile).unwrap());
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let submission = GatewaySubmission::direct_input("charge", Value::Str("42".into()))
            .with_options(SubmitOptions {
                idempotency_key: Some("charge-42-once".into()),
                ..SubmitOptions::default()
            });

        let first_gw = gw.clone();
        let first_session = session.clone();
        let first_submission = submission.clone();
        let first = tokio::spawn(async move {
            first_gw
                .submit(&first_session, first_submission)
                .await
                .unwrap()
        });
        while count.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }

        let second = gw.submit(&session, submission.clone()).await.unwrap_err();
        assert!(matches!(second, GatewayError::LimitExceeded(_)));
        assert_eq!(count.load(Ordering::Acquire), 1);

        released.store(true, Ordering::Release);
        release.notify_waiters();
        assert_eq!(first.await.unwrap(), Outcome::Done(Value::Str("42".into())));
        assert_eq!(count.load(Ordering::Acquire), 1);

        let replay = gw.submit(&session, submission).await.unwrap();
        assert_eq!(replay, Outcome::Done(Value::Str("42".into())));
        assert_eq!(count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn idempotency_key_replays_fail_outcome_variant() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, identity_profile()).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let submission = GatewaySubmission::program(
            String::new(),
            DoNode::fail(Failure::InvalidInput {
                reason: "bad input".into(),
            }),
        )
        .with_options(SubmitOptions {
            idempotency_key: Some("fail-once".into()),
            ..SubmitOptions::default()
        });

        let first = gw.submit(&session, submission.clone()).await.unwrap();
        let replay = gw.submit(&session, submission).await.unwrap();

        assert_eq!(first, replay);
        assert!(matches!(
            replay.outcome,
            Outcome::Fail(Failure::InvalidInput { ref reason }) if reason == "bad input"
        ));
    }

    #[tokio::test]
    async fn idempotency_reservation_is_released_after_admission_rejection() {
        let boot = Arc::new(Bootstrap::in_memory());
        let limits = GatewayLimitProfile {
            max_literal_bytes: 4,
            ..GatewayLimitProfile::default()
        };
        let gw = GatewayRuntime::new(boot.clone(), identity_profile().with_limits(limits)).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let submission =
            GatewaySubmission::program(String::new(), DoNode::pure(Value::Str("too-large".into())))
                .with_options(SubmitOptions {
                    idempotency_key: Some("reject-and-release".into()),
                    ..SubmitOptions::default()
                });
        let prefix = Path::parse("state://gateway/idempotency").unwrap();
        let before = boot.kernel.processes.all_ids().len();

        assert!(matches!(
            gw.submit(&session, submission.clone()).await,
            Err(GatewayError::Rejected(_))
        ));
        assert!(
            boot.kernel
                .state
                .read_prefix(&prefix)
                .await
                .unwrap()
                .is_empty(),
            "admission rejection must release the idempotency reservation"
        );
        assert_eq!(boot.kernel.processes.all_ids().len(), before);

        assert!(matches!(
            gw.submit(&session, submission).await,
            Err(GatewayError::Rejected(_))
        ));
        assert!(
            boot.kernel
                .state
                .read_prefix(&prefix)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn direct_input_large_ref_requires_provenance() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile =
            bind_alice_to_echo(identity_profile().with_surface(GatewaySurface::operation(
                "echo",
                name,
                "invoke",
                "perform",
                "perform://effect/echo/say",
            )));
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let blob = Value::Blob(nexus_types::BlobRef {
            hash: "abc".into(),
            size: 3,
            mime: Some("text/plain".into()),
        });
        let mut nested = BTreeMap::new();
        nested.insert("file".into(), blob.clone());

        assert!(matches!(
            gw.submit(&session, GatewaySubmission::direct_input("echo", blob))
                .await,
            Err(GatewayError::Rejected(_))
        ));
        assert!(matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", Value::Map(nested))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn direct_input_large_ref_requires_blob_store_match() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let bytes = b"stored image bytes".to_vec();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        let profile = echo_profile(name);
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let ticket = gw
            .issue_object_upload_ticket(
                &session,
                IssueObjectUploadTicketRequest {
                    surface_id: "echo".into(),
                    submission_token: None,
                    modality: GatewayModality::Bytes,
                    expected_size: Some(bytes.len() as u64),
                    expected_digest: Some(hash.clone()),
                    allowed_media_types: vec!["image/png".into()],
                    expires_in_ms: Some(60_000),
                    single_use: false,
                },
            )
            .await
            .unwrap();
        let committed = gw
            .commit_object_upload(
                &session,
                CommitObjectUploadRequest {
                    ticket_id: ticket.ticket_id,
                    bytes,
                    media_type: Some("image/png".into()),
                    item: None,
                    submission_token: None,
                },
            )
            .await
            .unwrap();
        let blob = committed.item.clone();

        let out = gw
            .submit(
                &session,
                direct_input_with_provenance("echo", blob.clone(), committed.provenance.clone()),
            )
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(blob));

        let wrong_size = Value::Blob(BlobRef {
            hash,
            size: 999,
            mime: None,
        });
        assert!(matches!(
            gw.submit(
                &session,
                direct_input_with_provenance("echo", wrong_size, committed.provenance)
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn program_large_ref_requires_and_uses_provenance() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let bytes = b"program object bytes".to_vec();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        let profile = echo_profile(name);
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let ticket = gw
            .issue_object_upload_ticket(
                &session,
                IssueObjectUploadTicketRequest {
                    surface_id: "echo".into(),
                    submission_token: None,
                    modality: GatewayModality::Bytes,
                    expected_size: Some(bytes.len() as u64),
                    expected_digest: Some(hash),
                    allowed_media_types: vec!["application/octet-stream".into()],
                    expires_in_ms: Some(60_000),
                    single_use: false,
                },
            )
            .await
            .unwrap();
        let committed = gw
            .commit_object_upload(
                &session,
                CommitObjectUploadRequest {
                    ticket_id: ticket.ticket_id,
                    bytes,
                    media_type: Some("application/octet-stream".into()),
                    item: None,
                    submission_token: None,
                },
            )
            .await
            .unwrap();
        let program = op("effect://echo/say", committed.item.clone());

        assert!(matches!(
            gw.submit(&session, program_submission(program.clone()))
                .await,
            Err(GatewayError::Rejected(_))
        ));

        let out = gw
            .submit(
                &session,
                GatewaySubmission::program(String::new(), program)
                    .with_provenance(committed.provenance),
            )
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(committed.item));
    }

    #[tokio::test]
    async fn program_store_proof_is_consumed_once_for_repeated_large_ref() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let bytes = b"program repeated object bytes".to_vec();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        let profile = echo_profile(name);
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let ticket = gw
            .issue_object_upload_ticket(
                &session,
                IssueObjectUploadTicketRequest {
                    surface_id: "echo".into(),
                    submission_token: None,
                    modality: GatewayModality::Bytes,
                    expected_size: Some(bytes.len() as u64),
                    expected_digest: Some(hash),
                    allowed_media_types: vec!["application/octet-stream".into()],
                    expires_in_ms: Some(60_000),
                    single_use: true,
                },
            )
            .await
            .unwrap();
        let committed = gw
            .commit_object_upload(
                &session,
                CommitObjectUploadRequest {
                    ticket_id: ticket.ticket_id,
                    bytes,
                    media_type: Some("application/octet-stream".into()),
                    item: None,
                    submission_token: None,
                },
            )
            .await
            .unwrap();
        let program = DoNode::both(
            op("effect://echo/say", committed.item.clone()),
            op(
                "effect://echo/say",
                Value::List(vec![committed.item.clone()]),
            ),
        );
        let submission = GatewaySubmission::program(String::new(), program)
            .with_provenance(committed.provenance.clone());

        gw.submit(&session, submission.clone()).await.unwrap();
        assert!(matches!(
            gw.submit(&session, submission).await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn direct_input_upload_ticket_is_bound_and_single_use() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let bytes = b"ticketed bytes".to_vec();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        boot.kernel
            .state
            .write_set(
                &Path::parse(&format!("state://blob/{hash}")).unwrap(),
                Value::Bytes(bytes.clone()),
            )
            .await
            .unwrap();
        let ticket_id = "ticket_1";
        let ticket = GatewayObjectUploadTicket {
            ticket_id: ticket_id.into(),
            principal_id: "alice".into(),
            surface_id: "echo".into(),
            submission_token: None,
            modality: GatewayModality::Bytes,
            expected_size: Some(bytes.len() as u64),
            expected_digest: Some(hash.clone()),
            allowed_media_types: vec!["image/*".into()],
            expires_at_ms: now_millis().saturating_add(60_000),
            single_use: true,
            committed: false,
            used: false,
        };
        boot.kernel
            .state
            .write_set(&upload_ticket_path(ticket_id).unwrap(), ticket.to_value())
            .await
            .unwrap();
        let blob = Value::Blob(BlobRef {
            hash,
            size: bytes.len() as u64,
            mime: Some("image/png".into()),
        });
        let profile = echo_profile(name);
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        let out = gw
            .submit(
                &session,
                direct_input_with_ticket("echo", blob.clone(), ticket_id),
            )
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(blob.clone()));
        assert!(matches!(
            gw.submit(&session, direct_input_with_ticket("echo", blob, ticket_id))
                .await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn direct_input_upload_ticket_rejects_expired_or_wrong_surface() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let bytes = b"rejected ticket bytes".to_vec();
        let hash = blake3::hash(&bytes).to_hex().to_string();
        boot.kernel
            .state
            .write_set(
                &Path::parse(&format!("state://blob/{hash}")).unwrap(),
                Value::Bytes(bytes.clone()),
            )
            .await
            .unwrap();
        let mut ticket = GatewayObjectUploadTicket {
            ticket_id: "ticket_expired".into(),
            principal_id: "alice".into(),
            surface_id: "echo".into(),
            submission_token: None,
            modality: GatewayModality::Bytes,
            expected_size: Some(bytes.len() as u64),
            expected_digest: Some(hash.clone()),
            allowed_media_types: Vec::new(),
            expires_at_ms: now_millis().saturating_sub(1),
            single_use: true,
            committed: false,
            used: false,
        };
        boot.kernel
            .state
            .write_set(
                &upload_ticket_path(&ticket.ticket_id).unwrap(),
                ticket.to_value(),
            )
            .await
            .unwrap();
        ticket.ticket_id = "ticket_surface".into();
        ticket.expires_at_ms = now_millis().saturating_add(60_000);
        ticket.surface_id = "other".into();
        boot.kernel
            .state
            .write_set(
                &upload_ticket_path(&ticket.ticket_id).unwrap(),
                ticket.to_value(),
            )
            .await
            .unwrap();
        let blob = Value::Blob(BlobRef {
            hash,
            size: bytes.len() as u64,
            mime: None,
        });
        let profile = echo_profile(name);
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        assert!(matches!(
            gw.submit(
                &session,
                direct_input_with_ticket("echo", blob.clone(), "ticket_expired")
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
        assert!(matches!(
            gw.submit(
                &session,
                direct_input_with_ticket("echo", blob, "ticket_surface")
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn object_upload_issue_commit_returns_bound_single_use_store_proof() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = echo_profile(name);
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let bytes = b"committed image bytes".to_vec();
        let digest = blake3::hash(&bytes).to_hex().to_string();
        let ticket = gw
            .issue_object_upload_ticket(
                &session,
                IssueObjectUploadTicketRequest {
                    surface_id: "echo".into(),
                    submission_token: None,
                    modality: GatewayModality::Bytes,
                    expected_size: Some(bytes.len() as u64),
                    expected_digest: Some(digest.clone()),
                    allowed_media_types: vec!["image/*".into()],
                    expires_in_ms: Some(60_000),
                    single_use: true,
                },
            )
            .await
            .unwrap();

        let committed = gw
            .commit_object_upload(
                &session,
                CommitObjectUploadRequest {
                    ticket_id: ticket.ticket_id,
                    bytes,
                    media_type: Some("image/png".into()),
                    item: None,
                    submission_token: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(committed.digest, digest);
        let out = gw
            .submit(
                &session,
                GatewaySubmission::direct_input("echo", committed.item.clone())
                    .with_provenance(committed.provenance.clone()),
            )
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(committed.item.clone()));
        assert!(matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("echo", committed.item)
                    .with_provenance(committed.provenance),
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn describe_requires_current_session_and_returns_redacted_surface_catalog() {
        let boot = Arc::new(Bootstrap::in_memory());
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = bind_alice_to_echo(
            identity_profile().with_revision(7).with_surface(
                GatewaySurface::operation(
                    "echo",
                    name.clone(),
                    "invoke",
                    "perform",
                    "perform://effect/echo/say",
                )
                .with_schema(Some(schema_type("string")), Some(schema_type("string"))),
            ),
        );
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let descriptor = gw.describe(&session).unwrap();
        assert_eq!(descriptor.profile_name, "program");
        assert_eq!(descriptor.profile_rev, 7);
        assert_eq!(descriptor.surfaces.len(), 1);
        assert_eq!(descriptor.surfaces[0].surface_id, "echo");
        assert_eq!(
            descriptor.surfaces[0].kind,
            GatewaySurfaceKind::EffectMethod
        );
        assert_eq!(descriptor.surfaces[0].target, name);
        assert_eq!(descriptor.surfaces[0].method, "invoke");
        assert_eq!(
            descriptor.surfaces[0].grant_template,
            "perform://effect/echo/say"
        );
        assert_eq!(descriptor.surfaces[0].publish_capability, None);
        assert_eq!(
            descriptor.surfaces[0].input_schema,
            Some(schema_type("string"))
        );
        assert_eq!(
            descriptor.surfaces[0].output_schema,
            Some(schema_type("string"))
        );
        assert_eq!(
            descriptor.limits.max_program_nodes,
            GatewayLimitProfile::default().max_program_nodes
        );

        let mut stale = session;
        stale.profile_rev = 6;
        assert!(matches!(
            gw.describe(&stale),
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn operation_not_exposed_by_profile_is_rejected() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, identity_profile()).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        assert!(matches!(
            gw.submit(
                &session,
                program_submission(op("effect://echo/say", Value::Null))
            )
            .await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn external_acting_is_rejected_by_default() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, identity_profile()).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let program = DoNode::acting(
            Path::parse("process://bob").unwrap(),
            DoNode::pure(Value::Int(1)),
        );
        assert!(matches!(
            gw.submit(&session, program_submission(program)).await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn external_step_ref_is_rejected_by_default() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = GatewayRuntime::new(boot, identity_profile()).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let program = DoNode::pure(Value::Int(1)).and_then(StepRef::new(ProcessId::new(1), "x"));
        assert!(matches!(
            gw.submit(&session, program_submission(program)).await,
            Err(GatewayError::Rejected(_))
        ));
    }

    #[tokio::test]
    async fn deep_program_is_rejected_before_process_spawn() {
        let boot = Arc::new(Bootstrap::in_memory());
        let before = boot.kernel.processes.all_ids().len();
        let limits = GatewayLimitProfile {
            max_program_depth: 8,
            ..GatewayLimitProfile::default()
        };
        let gw = GatewayRuntime::new(boot.clone(), identity_profile().with_limits(limits)).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let mut program = DoNode::pure(Value::Int(0));
        for _ in 0..16 {
            program = DoNode::both(program, DoNode::pure(Value::Int(1)));
        }
        assert!(matches!(
            gw.submit(&session, program_submission(program)).await,
            Err(GatewayError::Rejected(_))
        ));
        assert_eq!(
            boot.kernel.processes.all_ids().len(),
            before,
            "admission must run before request Process creation"
        );
    }

    #[tokio::test]
    async fn large_literal_is_rejected_before_process_spawn() {
        let boot = Arc::new(Bootstrap::in_memory());
        let before = boot.kernel.processes.all_ids().len();
        let limits = GatewayLimitProfile {
            max_literal_bytes: 16,
            ..GatewayLimitProfile::default()
        };
        let gw = GatewayRuntime::new(boot.clone(), identity_profile().with_limits(limits)).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let program = DoNode::pure(Value::Str("this literal is too large".into()));
        assert!(matches!(
            gw.submit(&session, program_submission(program)).await,
            Err(GatewayError::Rejected(_))
        ));
        assert_eq!(boot.kernel.processes.all_ids().len(), before);
    }

    #[tokio::test]
    async fn direct_input_large_literal_is_rejected_before_process_spawn() {
        let boot = Arc::new(Bootstrap::in_memory());
        let limits = GatewayLimitProfile {
            max_literal_bytes: 16,
            ..GatewayLimitProfile::default()
        };
        let name = boot
            .register_effect(
                "effect://echo/say",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let profile = bind_alice_to_echo(identity_profile().with_limits(limits).with_surface(
            GatewaySurface::operation(
                "echo",
                name,
                "invoke",
                "perform",
                "perform://effect/echo/say",
            ),
        ));
        let gw = GatewayRuntime::new(boot.clone(), profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let before = boot.kernel.processes.all_ids().len();
        let prefix = Path::parse("state://gateway/idempotency").unwrap();
        let submission = GatewaySubmission::direct_input(
            "echo",
            Value::Str("this direct input is too large".into()),
        )
        .with_options(SubmitOptions {
            idempotency_key: Some("direct-input-too-large".into()),
            ..SubmitOptions::default()
        });

        assert!(matches!(
            gw.submit(&session, submission).await,
            Err(GatewayError::Rejected(_))
        ));
        assert_eq!(boot.kernel.processes.all_ids().len(), before);
        assert!(
            boot.kernel
                .state
                .read_prefix(&prefix)
                .await
                .unwrap()
                .is_empty(),
            "direct input admission rejection must release the idempotency reservation"
        );
    }

    #[tokio::test]
    async fn gateway_budget_rejects_inflight_ops_and_releases() {
        let boot = Arc::new(Bootstrap::in_memory());
        let count = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let name = boot
            .register_effect(
                "effect://budget/slow",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(BlockingCountingDriver {
                    count: count.clone(),
                    released: released.clone(),
                    release: release.clone(),
                }),
            )
            .unwrap();
        let limits = GatewayLimitProfile {
            max_in_flight_requests: 4,
            budget: GatewayBudgetProfile {
                max_inflight_ops: Some(1),
                ..GatewayBudgetProfile::default()
            },
            ..GatewayLimitProfile::default()
        };
        let profile = identity_profile()
            .with_limits(limits)
            .with_surface(GatewaySurface::operation(
                "budget",
                name,
                "invoke",
                "perform",
                "perform://effect/budget/slow",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["budget"],
                ["perform://effect/budget/slow"],
            ));
        let gw = Arc::new(GatewayRuntime::new(boot, profile).unwrap());
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let running = {
            let gw = gw.clone();
            let session = session.clone();
            tokio::spawn(async move {
                gw.submit(
                    &session,
                    GatewaySubmission::direct_input("budget", Value::Str("one".into())),
                )
                .await
            })
        };
        while count.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }

        let retry = GatewaySubmission::direct_input("budget", Value::Str("two".into()));
        assert!(matches!(
            gw.submit(&session, retry.clone()).await,
            Err(GatewayError::LimitExceeded(message))
                if message == "gateway budget in-flight ops limit"
        ));

        released.store(true, Ordering::Release);
        release.notify_waiters();
        running.await.unwrap().unwrap();

        let out = gw.submit(&session, retry).await.unwrap();
        assert_eq!(out.outcome, Outcome::Done(Value::Str("two".into())));
    }

    #[tokio::test]
    async fn gateway_budget_rejects_estimated_cost_before_dispatch() {
        let boot = Arc::new(Bootstrap::in_memory());
        let count = Arc::new(AtomicUsize::new(0));
        let name = boot
            .register_effect_with_cost(
                "effect://budget/costed",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(BlockingCountingDriver {
                    count: count.clone(),
                    released: Arc::new(AtomicBool::new(true)),
                    release: Arc::new(tokio::sync::Notify::new()),
                }),
                CostModel {
                    flat_micro_usd: 500,
                    per_1k_in_micro_usd: 0,
                    per_1k_out_micro_usd: 0,
                },
            )
            .unwrap();
        let limits = GatewayLimitProfile {
            budget: GatewayBudgetProfile {
                max_estimated_cost_micro_usd: Some(499),
                ..GatewayBudgetProfile::default()
            },
            ..GatewayLimitProfile::default()
        };
        let profile = identity_profile()
            .with_limits(limits)
            .with_surface(GatewaySurface::operation(
                "budget",
                name,
                "invoke",
                "perform",
                "perform://effect/budget/costed",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["budget"],
                ["perform://effect/budget/costed"],
            ));
        let gw = GatewayRuntime::new(boot, profile).unwrap();
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        assert!(matches!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("budget", Value::Str("costed".into()))
            )
            .await,
            Err(GatewayError::LimitExceeded(message))
                if message == "gateway budget estimated cost limit"
        ));
        assert_eq!(count.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn profile_replace_keeps_global_in_flight_limit() {
        let boot = Arc::new(Bootstrap::in_memory());
        let limits = GatewayLimitProfile {
            max_in_flight_requests: 2,
            allow_wait_deadline: true,
            ..GatewayLimitProfile::default()
        };
        let gw =
            Arc::new(GatewayRuntime::new(boot, identity_profile().with_limits(limits)).unwrap());
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let deadline = now_millis().saturating_add(200);
        let running = {
            let gw = gw.clone();
            let session = session.clone();
            tokio::spawn(async move {
                gw.submit(
                    &session,
                    program_submission(DoNode::wait_deadline(deadline)),
                )
                .await
            })
        };
        tokio::task::yield_now().await;

        let limits = GatewayLimitProfile {
            max_in_flight_requests: 1,
            allow_wait_deadline: true,
            ..GatewayLimitProfile::default()
        };
        let new_profile = identity_profile().with_revision(2).with_limits(limits);
        assert_eq!(gw.replace_profile(new_profile).unwrap(), 2);
        let new_session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        assert!(matches!(
            gw.submit(
                &new_session,
                program_submission(DoNode::pure(Value::Int(1)))
            )
            .await,
            Err(GatewayError::LimitExceeded(_))
        ));

        assert!(running.await.unwrap().is_ok());
        assert!(
            gw.submit(
                &new_session,
                program_submission(DoNode::pure(Value::Int(2)))
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn fair_admission_enforces_principal_limit() {
        let boot = Arc::new(Bootstrap::in_memory());
        let count = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let name_a = boot
            .register_effect(
                "effect://slow/a",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(BlockingCountingDriver {
                    count: count.clone(),
                    released: released.clone(),
                    release: release.clone(),
                }),
            )
            .unwrap();
        let name_b = boot
            .register_effect(
                "effect://slow/b",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();
        let limits = GatewayLimitProfile {
            max_in_flight_requests: 4,
            max_principal_in_flight_requests: 1,
            max_surface_in_flight_requests: 4,
            max_risk_class_in_flight_requests: 4,
            ..GatewayLimitProfile::default()
        };
        let profile = identity_profile()
            .with_limits(limits)
            .with_surface(GatewaySurface::operation(
                "slow-a",
                name_a,
                "invoke",
                "perform",
                "perform://effect/slow/a",
            ))
            .with_surface(GatewaySurface::operation(
                "slow-b",
                name_b,
                "invoke",
                "perform",
                "perform://effect/slow/b",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["slow-a", "slow-b"],
                ["perform://effect/slow/a", "perform://effect/slow/b"],
            ));
        let gw = Arc::new(GatewayRuntime::new(boot, profile).unwrap());
        let session = gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();

        let running = {
            let gw = gw.clone();
            let session = session.clone();
            tokio::spawn(async move {
                gw.submit(
                    &session,
                    GatewaySubmission::direct_input("slow-a", Value::Str("one".into())),
                )
                .await
            })
        };
        while count.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }

        let err = gw
            .submit(
                &session,
                GatewaySubmission::direct_input("slow-b", Value::Str("two".into())),
            )
            .await
            .unwrap_err();
        assert_limit_contains(err, "principal");

        released.store(true, Ordering::Release);
        release.notify_waiters();
        assert!(running.await.unwrap().is_ok());
        assert!(
            gw.submit(
                &session,
                GatewaySubmission::direct_input("slow-b", Value::Str("after".into())),
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn fair_admission_enforces_surface_and_risk_limits() {
        let boot = Arc::new(Bootstrap::in_memory());
        let count = Arc::new(AtomicUsize::new(0));
        let released = Arc::new(AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let name_a = boot
            .register_effect(
                "effect://fair/a",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(BlockingCountingDriver {
                    count: count.clone(),
                    released: released.clone(),
                    release: release.clone(),
                }),
            )
            .unwrap();
        let name_b = boot
            .register_effect(
                "effect://fair/b",
                &[nexus_kernel::MethodSpec::new(
                    "invoke",
                    nexus_types::Purity::Pure,
                    nexus_kernel::MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(nexus_kernel::EchoDriver),
            )
            .unwrap();

        let surface_limits = GatewayLimitProfile {
            max_in_flight_requests: 4,
            max_principal_in_flight_requests: 4,
            max_surface_in_flight_requests: 1,
            max_risk_class_in_flight_requests: 4,
            ..GatewayLimitProfile::default()
        };
        let surface_profile = identity_profile()
            .with_limits(surface_limits)
            .with_surface(GatewaySurface::operation(
                "fair-a",
                name_a.clone(),
                "invoke",
                "perform",
                "perform://effect/fair/a",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["fair-a"],
                ["perform://effect/fair/a"],
            ));
        let surface_gw = Arc::new(GatewayRuntime::new(boot.clone(), surface_profile).unwrap());
        let surface_session = surface_gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let running = {
            let gw = surface_gw.clone();
            let session = surface_session.clone();
            tokio::spawn(async move {
                gw.submit(
                    &session,
                    GatewaySubmission::direct_input("fair-a", Value::Str("one".into())),
                )
                .await
            })
        };
        while count.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        let err = surface_gw
            .submit(
                &surface_session,
                GatewaySubmission::direct_input("fair-a", Value::Str("two".into())),
            )
            .await
            .unwrap_err();
        assert_limit_contains(err, "surface");
        released.store(true, Ordering::Release);
        release.notify_waiters();
        assert!(running.await.unwrap().is_ok());

        count.store(0, Ordering::Release);
        released.store(false, Ordering::Release);
        let risk_limits = GatewayLimitProfile {
            max_in_flight_requests: 4,
            max_principal_in_flight_requests: 4,
            max_surface_in_flight_requests: 4,
            max_risk_class_in_flight_requests: 1,
            ..GatewayLimitProfile::default()
        };
        let risk_profile = identity_profile()
            .with_limits(risk_limits)
            .with_surface(GatewaySurface::operation(
                "fair-a",
                name_a,
                "invoke",
                "perform",
                "perform://effect/fair/a",
            ))
            .with_surface(GatewaySurface::operation(
                "fair-b",
                name_b,
                "invoke",
                "perform",
                "perform://effect/fair/b",
            ))
            .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                "alice",
                ["fair-a", "fair-b"],
                ["perform://effect/fair/a", "perform://effect/fair/b"],
            ));
        let risk_gw = Arc::new(GatewayRuntime::new(boot, risk_profile).unwrap());
        let risk_session = risk_gw
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await
            .unwrap();
        let running = {
            let gw = risk_gw.clone();
            let session = risk_session.clone();
            tokio::spawn(async move {
                gw.submit(
                    &session,
                    GatewaySubmission::direct_input("fair-a", Value::Str("one".into())),
                )
                .await
            })
        };
        while count.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        let err = risk_gw
            .submit(
                &risk_session,
                GatewaySubmission::direct_input("fair-b", Value::Str("two".into())),
            )
            .await
            .unwrap_err();
        assert_limit_contains(err, "risk-class");
        released.store(true, Ordering::Release);
        release.notify_waiters();
        assert!(running.await.unwrap().is_ok());
        assert!(
            risk_gw
                .submit(
                    &risk_session,
                    GatewaySubmission::direct_input("fair-b", Value::Str("after".into())),
                )
                .await
                .is_ok()
        );
    }
}
