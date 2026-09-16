// @generated — hand-maintained to match `tonic-prost-build` output for
// `proto/xolotl/v1/external.proto` (package `xolotl.v1.external`). `include!`d
// into the `xolotl::v1::external` module. Keep in sync with the `.proto` spec.

/// Top-level frame envelope.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExternalFrame {
    /// Handshake, role-specific business, control, or encrypted frame body.
    /// The receiver rejects an envelope without a selected variant.
    #[prost(
        oneof = "external_frame::Frame",
        tags = "1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12"
    )]
    pub frame: ::core::option::Option<external_frame::Frame>,
}
/// Nested message and enum types in `ExternalFrame`.
pub mod external_frame {
    /// Frame discriminator for one bidirectional external session.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Frame {
        /// Client proposal opening a Provider or Source role session.
        #[prost(message, tag = "1")]
        RoleSessionClientHello(super::RoleSessionClientHello),
        /// Daemon-selected identity, registry hash, and generation context.
        #[prost(message, tag = "2")]
        SessionContext(super::SessionContext),
        /// Client confirmation of the exact daemon-selected context.
        #[prost(message, tag = "3")]
        RoleReady(super::RoleReady),
        /// Source-to-daemon event for the projection's declared event sink.
        #[prost(message, tag = "4")]
        InboundEvent(super::InboundEvent),
        /// Daemon-to-Source action for a projection that enables commands.
        #[prost(message, tag = "5")]
        OutboundCommand(super::OutboundCommand),
        /// Source-to-daemon result correlated with an outbound command.
        #[prost(message, tag = "6")]
        CommandResult(super::CommandResult),
        /// Daemon acknowledgement of a Source event's admission or duplication.
        #[prost(message, tag = "7")]
        EventAck(super::EventAck),
        /// Daemon-to-Provider invocation of a projected effect method.
        #[prost(message, tag = "8")]
        Invoke(super::Invoke),
        /// Provider-to-daemon result for a registered pending invocation.
        #[prost(message, tag = "9")]
        InvokeResult(super::InvokeResult),
        /// Liveness, configuration, flow-control, or cancellation message.
        #[prost(message, tag = "11")]
        Control(super::ControlFrame),
        /// Authenticated and encrypted business or control frame.
        #[prost(message, tag = "12")]
        SecureEnvelope(super::SecureEnvelope),
    }
}
/// AEAD-protected business/control frame envelope.
/// Handshake frames remain outside this envelope while session context is selected.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SecureEnvelope {
    /// Installation whose credential seals the frame; must match the ready session.
    #[prost(string, tag = "1")]
    pub installation_id: ::prost::alloc::string::String,
    /// Credential generation used to seal the frame, matching the session and AAD.
    #[prost(uint64, tag = "2")]
    pub generation: u64,
    /// Required authenticated metadata binding the encrypted body to its session.
    #[prost(message, optional, tag = "3")]
    pub aad: ::core::option::Option<EnvelopeAad>,
    /// Twelve-byte random prefix combined with the AAD sequence to form the nonce.
    #[prost(bytes = "vec", tag = "4")]
    pub nonce_prefix: ::prost::alloc::vec::Vec<u8>,
    /// Encrypted serialized `ExternalFrame` body, including its authentication tag.
    #[prost(bytes = "vec", tag = "5")]
    pub ciphertext: ::prost::alloc::vec::Vec<u8>,
}
/// Additional authenticated data for one secure external frame.
/// These fields are checked against the ready session before admitting its body.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EnvelopeAad {
    /// Envelope format version; the current gateway accepts version 1.
    #[prost(uint32, tag = "1")]
    pub version: u32,
    /// Projection within the installation, bound to the ready role session.
    #[prost(string, tag = "2")]
    pub projection_id: ::prost::alloc::string::String,
    /// Canonical role name, `source` or `provider`, selected for the session.
    #[prost(string, tag = "3")]
    pub role: ::prost::alloc::string::String,
    /// Daemon-selected role connection identity, preventing cross-session reuse.
    #[prost(string, tag = "4")]
    pub session_id: ::prost::alloc::string::String,
    /// Envelope sequence used for nonce derivation and bounded replay protection.
    /// This is independent of an inbound event's stream-local sequence.
    #[prost(uint64, tag = "5")]
    pub seq: u64,
    /// Authenticated frame discriminator. Control frames use `control.<kind>`,
    /// for example `control.config_ack`.
    #[prost(string, tag = "6")]
    pub frame_type: ::prost::alloc::string::String,
    /// Binding generation that must match the daemon-selected session context.
    #[prost(uint64, tag = "7")]
    pub binding_generation: u64,
    /// Credential generation that must match the envelope and ready session.
    #[prost(uint64, tag = "8")]
    pub credential_generation: u64,
    /// Thirty-two-byte hash binding the frame to the negotiated session transcript.
    #[prost(bytes = "vec", tag = "9")]
    pub transcript_hash: ::prost::alloc::vec::Vec<u8>,
    /// Session key epoch used to seal the frame and checked during key rotation.
    #[prost(uint64, tag = "10")]
    pub key_epoch: u64,
}
/// Role client hello with identity plus locally observed generations/hash.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RoleSessionClientHello {
    /// Requested projection role, encoded as an `ExternalRole` discriminant.
    #[prost(enumeration = "ExternalRole", tag = "1")]
    pub role: i32,
    /// Installation claimed by the endpoint, subject to daemon admission.
    #[prost(string, tag = "2")]
    pub installation_id: ::prost::alloc::string::String,
    /// Projection claimed within that installation, subject to daemon admission.
    #[prost(string, tag = "3")]
    pub projection_id: ::prost::alloc::string::String,
    /// Registry hash observed by the endpoint; the daemon selects the authority.
    #[prost(string, tag = "4")]
    pub registry_hash: ::prost::alloc::string::String,
    /// Locally observed presentation and alias generations, not authority grants.
    #[prost(message, optional, tag = "5")]
    pub observed: ::core::option::Option<ObservedGenerations>,
    /// Optional configuration schema reported by a self-describing endpoint.
    #[prost(message, optional, tag = "6")]
    pub config_schema: ::core::option::Option<super::Value>,
}
/// Daemon-adjudicated registry hash and generations.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SessionContext {
    /// Installation identity accepted by the daemon.
    #[prost(string, tag = "1")]
    pub installation_id: ::prost::alloc::string::String,
    /// Projection identity accepted within the installation.
    #[prost(string, tag = "2")]
    pub projection_id: ::prost::alloc::string::String,
    /// Accepted Provider or Source role, encoded as an `ExternalRole` discriminant.
    #[prost(enumeration = "ExternalRole", tag = "3")]
    pub role: i32,
    /// Authoritative registry hash selected by the daemon.
    #[prost(string, tag = "4")]
    pub registry_hash: ::prost::alloc::string::String,
    /// Credential generation selected for authenticating this session.
    #[prost(uint64, tag = "5")]
    pub credential_generation: u64,
    /// Binding generation selected for the projection's authorized routing.
    #[prost(uint64, tag = "6")]
    pub binding_generation: u64,
    /// Authoritative installation configuration version.
    #[prost(uint64, tag = "7")]
    pub installation_config_version: u64,
    /// Authoritative projection declaration version.
    #[prost(uint64, tag = "8")]
    pub projection_version: u64,
    /// Presentation configuration generation the endpoint must observe.
    #[prost(uint64, tag = "9")]
    pub presentation_config_generation: u64,
    /// Alias catalog generation the endpoint must observe.
    #[prost(uint64, tag = "10")]
    pub alias_catalog_generation: u64,
    /// Daemon-selected identity for this role connection, distinct from a Process id.
    #[prost(string, tag = "11")]
    pub session_id: ::prost::alloc::string::String,
}
/// Role client acknowledgement of the daemon-selected context.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RoleReady {
    /// Required echo of the selected context; any identity or generation mismatch
    /// prevents the session from becoming ready for business frames.
    #[prost(message, optional, tag = "1")]
    pub accepted_context: ::core::option::Option<SessionContext>,
}
/// Source client to daemon: source event occurred.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InboundEvent {
    /// Event identity used for acknowledgement and deduplication within the
    /// installation and projection's configured retention window.
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    /// Event body validated against the Source projection before sink admission.
    #[prost(message, optional, tag = "2")]
    pub payload: ::core::option::Option<super::Value>,
    /// Source-reported event time in milliseconds since the Unix epoch.
    #[prost(int64, tag = "3")]
    pub timestamp_ms: i64,
    /// Lightweight presentation/alias generation tags.
    #[prost(message, optional, tag = "4")]
    pub observed: ::core::option::Option<ObservedGenerations>,
    /// Optional ordered-stream identity scoped to this installation and projection.
    /// Supply together with `seq`; it is not a State read cursor.
    #[prost(string, optional, tag = "5")]
    pub stream_id: ::core::option::Option<::prost::alloc::string::String>,
    /// Stream-local sequence paired with `stream_id`. Current ingest starts at 1,
    /// admits only the next number, and rejects values above `i64::MAX`.
    #[prost(uint64, optional, tag = "6")]
    pub seq: ::core::option::Option<u64>,
}
/// Daemon to Source client: execute this action through the connector.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutboundCommand {
    /// Command identity used for deduplication and matching its result.
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    /// Source action body validated against the projection's command schema.
    #[prost(message, optional, tag = "2")]
    pub action: ::core::option::Option<super::Value>,
    /// Presentation and alias generations attached by the daemon.
    #[prost(message, optional, tag = "3")]
    pub observed: ::core::option::Option<ObservedGenerations>,
}
/// The two lightweight generation axes carried on each Source frame.
/// Session-level generations live in SessionContext instead.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ObservedGenerations {
    /// Presentation configuration generation observed by the sender.
    #[prost(uint64, tag = "1")]
    pub presentation_config_generation: u64,
    /// Alias catalog generation observed by the sender.
    #[prost(uint64, tag = "2")]
    pub alias_catalog_generation: u64,
}
/// Source client to daemon: command execution result.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommandResult {
    /// Identity of the outbound command whose result is being reported.
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    /// Successful command output or endpoint-reported failure.
    #[prost(oneof = "command_result::Outcome", tags = "2, 3")]
    pub outcome: ::core::option::Option<command_result::Outcome>,
}
/// Nested message and enum types in `CommandResult`.
pub mod command_result {
    /// Mutually exclusive success and error bodies for a Source command result.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Outcome {
        /// Command output, validated against the declared result schema.
        #[prost(message, tag = "2")]
        Success(super::super::Value),
        /// Endpoint-reported command failure.
        #[prost(message, tag = "3")]
        Error(super::ErrorInfo),
    }
}
/// Daemon to Source client: event acknowledgment.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EventAck {
    /// Identity of the inbound event being acknowledged.
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    /// Event admission status, encoded as an `AckStatus` discriminant.
    #[prost(enumeration = "AckStatus", tag = "2")]
    pub status: i32,
    /// Redacted explanation when the event is rejected.
    #[prost(string, optional, tag = "3")]
    pub reject_reason: ::core::option::Option<::prost::alloc::string::String>,
}
/// Daemon to Provider client: invoke an effect.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Invoke {
    /// Stable request correlation identity; kernel calls use the full OperationId.
    /// Business idempotency keys are applied separately from this identity.
    #[prost(string, tag = "1")]
    pub invocation_id: ::prost::alloc::string::String,
    /// Projected effect Resource selected by the daemon for this invocation.
    #[prost(message, optional, tag = "2")]
    pub effect_path: ::core::option::Option<super::Path>,
    /// Operation input, validated against the Provider projection's input schema.
    #[prost(message, optional, tag = "3")]
    pub input: ::core::option::Option<super::Value>,
    /// Optional absolute deadline in milliseconds since the Unix epoch.
    #[prost(int64, optional, tag = "4")]
    pub deadline_ms: ::core::option::Option<i64>,
    /// Optional serialized output route for a streaming invocation.
    /// A route names the destination; it does not itself grant authority.
    #[prost(string, optional, tag = "5")]
    pub output_stream_to: ::core::option::Option<::prost::alloc::string::String>,
    /// Concrete Resource method identity, preserved for endpoint dispatch.
    /// The runtime converter requires this field even though protobuf makes it optional.
    #[prost(uint64, optional, tag = "6")]
    pub method_id: ::core::option::Option<u64>,
}
/// Provider client to daemon: invocation result.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InvokeResult {
    /// Invocation identity matching a pending call on the same ready Provider session.
    #[prost(string, tag = "1")]
    pub invocation_id: ::prost::alloc::string::String,
    /// Successful invocation output or endpoint-reported failure.
    #[prost(oneof = "invoke_result::Outcome", tags = "2, 3")]
    pub outcome: ::core::option::Option<invoke_result::Outcome>,
}
/// Nested message and enum types in `InvokeResult`.
pub mod invoke_result {
    /// Mutually exclusive success and error bodies for a Provider invocation result.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Outcome {
        /// Effect output, subject to the registered result schema and size limit.
        #[prost(message, tag = "2")]
        Success(super::super::Value),
        /// Endpoint-reported invocation failure.
        #[prost(message, tag = "3")]
        Error(super::ErrorInfo),
    }
}
/// Role-session control message whose permitted direction depends on its variant.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ControlFrame {
    /// Selected liveness, configuration, flow-control, or cancellation operation.
    #[prost(oneof = "control_frame::Kind", tags = "1, 2, 3, 4, 5, 6, 7, 8")]
    pub kind: ::core::option::Option<control_frame::Kind>,
}
/// Nested message and enum types in `ControlFrame`.
pub mod control_frame {
    /// Control operation exchanged after the role session is ready.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// Liveness report carrying the sender's timestamp.
        #[prost(message, tag = "1")]
        Heartbeat(super::Heartbeat),
        /// Daemon request to shut down the connected role endpoint.
        #[prost(message, tag = "2")]
        Shutdown(super::Shutdown),
        /// Daemon-issued pause or resume signal, without numeric credit grants.
        #[prost(message, tag = "3")]
        FlowControl(super::FlowControl),
        /// Endpoint report of its rendering capabilities and local entry points.
        #[prost(message, tag = "4")]
        PresentationProfileUpdate(super::PresentationProfileUpdate),
        /// Daemon-selected update to the installation's authority configuration.
        #[prost(message, tag = "5")]
        InstallationConfigUpdate(super::InstallationConfigUpdate),
        /// Daemon-selected presentation update that cannot grant capabilities.
        #[prost(message, tag = "6")]
        PresentationConfigUpdate(super::PresentationConfigUpdate),
        /// Endpoint acknowledgement of an installation or presentation update.
        #[prost(message, tag = "7")]
        ConfigAck(super::ConfigAck),
        /// Daemon request to cooperatively cancel one pending Provider invocation.
        #[prost(message, tag = "8")]
        ProviderCancel(super::ProviderCancel),
    }
}
/// Role client to daemon: report what this end can render.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PresentationProfileUpdate {
    /// Generation of the rendering profile reported by the endpoint.
    #[prost(uint64, tag = "1")]
    pub profile_generation: u64,
    /// Hash identifying the reported profile for later presentation updates.
    #[prost(string, tag = "2")]
    pub profile_hash: ::prost::alloc::string::String,
    /// Profile body whose schema is defined by the connector, not this envelope.
    #[prost(message, optional, tag = "3")]
    pub profile: ::core::option::Option<super::Value>,
}
/// Daemon to role client: authority config update, via CAS.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InstallationConfigUpdate {
    /// New installation configuration version committed through daemon-side CAS.
    #[prost(uint64, tag = "1")]
    pub config_version: u64,
    /// Configuration body for the authority axis; changes may advance binding generation.
    #[prost(message, optional, tag = "2")]
    pub config: ::core::option::Option<super::Value>,
}
/// Daemon to role client: presentation-only config, never grants capability.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PresentationConfigUpdate {
    /// New presentation-only configuration generation.
    #[prost(uint64, tag = "1")]
    pub generation: u64,
    /// Endpoint profile hash this presentation configuration targets.
    #[prost(string, tag = "2")]
    pub profile_hash: ::prost::alloc::string::String,
    /// Rendering and entry-point settings bounded by the profile and local overrides.
    #[prost(message, optional, tag = "3")]
    pub config: ::core::option::Option<super::Value>,
}
/// Role client to daemon: how a config/presentation update was applied.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConfigAck {
    /// Installation or presentation axis, encoded as a `ConfigAxis` discriminant.
    #[prost(enumeration = "ConfigAxis", tag = "1")]
    pub axis: i32,
    /// Installation version or presentation generation being acknowledged.
    #[prost(uint64, tag = "2")]
    pub version: u64,
    /// Update application result, encoded as an `ApplyStatus` discriminant.
    #[prost(enumeration = "ApplyStatus", tag = "3")]
    pub status: i32,
    /// Set only when `status == Rejected`.
    #[prost(enumeration = "RejectReason", optional, tag = "4")]
    pub reject_reason: ::core::option::Option<i32>,
}
/// Liveness report for a ready role session.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Heartbeat {
    /// Sender's heartbeat time in milliseconds since the Unix epoch.
    #[prost(int64, tag = "1")]
    pub timestamp_ms: i64,
}
/// Daemon request for graceful or forced endpoint shutdown.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Shutdown {
    /// Whether the endpoint should attempt graceful shutdown.
    #[prost(bool, tag = "1")]
    pub graceful: bool,
    /// Requested shutdown timeout in milliseconds.
    #[prost(uint64, tag = "2")]
    pub timeout_ms: u64,
}
/// Daemon-issued pause or resume signal for the role connection.
/// This message carries no numeric byte or message credits and is not an event acknowledgement.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FlowControl {
    /// Requested delivery state, encoded as a `FlowSignal` discriminant.
    #[prost(enumeration = "FlowSignal", tag = "1")]
    pub signal: i32,
}
/// Daemon to Provider client: cancel a pending invocation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProviderCancel {
    /// Identity of the pending Provider invocation to cancel.
    #[prost(string, tag = "1")]
    pub invocation_id: ::prost::alloc::string::String,
    /// Redacted cancellation explanation; cancellation cannot undo completed effects.
    #[prost(string, tag = "2")]
    pub reason: ::prost::alloc::string::String,
}
/// Endpoint error classification and diagnostic text for a command or invocation.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ErrorInfo {
    /// Stable endpoint error class, mapped to runtime `ErrorInfo::kind`.
    #[prost(string, tag = "1")]
    pub code: ::prost::alloc::string::String,
    /// Human-readable failure description.
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
    /// Additional wire diagnostics; the current runtime error conversion discards them.
    #[prost(map = "string, string", tag = "3")]
    pub details:
        ::std::collections::HashMap<::prost::alloc::string::String, ::prost::alloc::string::String>,
}
/// Role projected by an external program, orthogonal to transport and trust.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ExternalRole {
    /// Protobuf default; runtime admission requires an explicit Source or Provider role.
    Unspecified = 0,
    /// Source: provides a state:// inbound event stream.
    Source = 1,
    /// Provider: serves effect:// capabilities declared by its projection.
    Provider = 2,
}
impl ExternalRole {
    /// Return the exact role enum name declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "EXTERNAL_ROLE_UNSPECIFIED",
            Self::Source => "EXTERNAL_ROLE_SOURCE",
            Self::Provider => "EXTERNAL_ROLE_PROVIDER",
        }
    }
    /// Parse an exact protobuf role enum name, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "EXTERNAL_ROLE_UNSPECIFIED" => Some(Self::Unspecified),
            "EXTERNAL_ROLE_SOURCE" => Some(Self::Source),
            "EXTERNAL_ROLE_PROVIDER" => Some(Self::Provider),
            _ => None,
        }
    }
}
/// Daemon's admission decision for one Source event, not a flow-credit grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum AckStatus {
    /// Protobuf default; runtime conversion requires an explicit acknowledgement status.
    Unspecified = 0,
    /// The event was admitted and appended to its declared sink.
    Accepted = 1,
    /// The event identity already has a committed entry in the deduplication window.
    Duplicate = 2,
    /// The event was rejected; the acknowledgement may include a redacted reason.
    Rejected = 3,
}
impl AckStatus {
    /// Return the exact acknowledgement enum name declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "ACK_STATUS_UNSPECIFIED",
            Self::Accepted => "ACK_STATUS_ACCEPTED",
            Self::Duplicate => "ACK_STATUS_DUPLICATE",
            Self::Rejected => "ACK_STATUS_REJECTED",
        }
    }
    /// Parse an exact protobuf acknowledgement name, returning `None` if unknown.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ACK_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "ACK_STATUS_ACCEPTED" => Some(Self::Accepted),
            "ACK_STATUS_DUPLICATE" => Some(Self::Duplicate),
            "ACK_STATUS_REJECTED" => Some(Self::Rejected),
            _ => None,
        }
    }
}
/// Pause/resume state requested by the daemon, independent of transport windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum FlowSignal {
    /// Protobuf default; runtime conversion requires an explicit delivery signal.
    Unspecified = 0,
    /// Pause delivery on the role connection until a resume signal.
    Pause = 1,
    /// Resume paused delivery; this carries no numeric byte or message allowance.
    Resume = 2,
}
impl FlowSignal {
    /// Return the exact flow-signal enum name declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "FLOW_SIGNAL_UNSPECIFIED",
            Self::Pause => "FLOW_SIGNAL_PAUSE",
            Self::Resume => "FLOW_SIGNAL_RESUME",
        }
    }
    /// Parse an exact protobuf flow-signal name, returning `None` if unknown.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "FLOW_SIGNAL_UNSPECIFIED" => Some(Self::Unspecified),
            "FLOW_SIGNAL_PAUSE" => Some(Self::Pause),
            "FLOW_SIGNAL_RESUME" => Some(Self::Resume),
            _ => None,
        }
    }
}
/// Which config axis a [`ConfigAck`] answers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ConfigAxis {
    /// Protobuf default; a configuration acknowledgement must select an axis.
    Unspecified = 0,
    /// Installation configuration, whose version belongs to the authority axis.
    InstallationConfig = 1,
    /// Presentation configuration, whose generation cannot grant capabilities.
    PresentationConfig = 2,
}
/// Result of applying a config/presentation update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ApplyStatus {
    /// Protobuf default; a configuration acknowledgement must state its result.
    Unspecified = 0,
    /// The endpoint applied the acknowledged version or generation.
    Applied = 1,
    /// The endpoint rejected the update and must supply a rejection reason.
    Rejected = 2,
}
/// Why a role client rejected an update.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RejectReason {
    /// Protobuf default; runtime conversion requires a concrete rejection reason.
    Unspecified = 0,
    /// The presentation update targets a different endpoint profile hash.
    ProfileMismatch = 1,
    /// The configuration body does not satisfy its schema.
    SchemaInvalid = 2,
    /// The update's version or generation is stale.
    GenerationStale = 3,
    /// The endpoint does not implement the requested update.
    Unsupported = 4,
}
/// Tonic server binding for the bidirectional external role-session RPC.
pub mod external_service_server {
    use tonic::codegen::*;
    /// Server implementation of the Provider/Source session protocol.
    #[async_trait]
    pub trait ExternalService: std::marker::Send + std::marker::Sync + 'static {
        /// Daemon-to-client frames for one session; stream errors terminate the RPC.
        type SessionStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::ExternalFrame, tonic::Status>,
            > + std::marker::Send
            + 'static;
        /// Accept a bidirectional role connection.
        /// Implementations admit the client's `RoleSessionClientHello`, return
        /// `SessionContext`, and require a matching `RoleReady` before business frames.
        async fn session(
            &self,
            request: tonic::Request<tonic::Streaming<super::ExternalFrame>>,
        ) -> std::result::Result<tonic::Response<Self::SessionStream>, tonic::Status>;
    }
    /// External gRPC service for Provider and Source sessions.
    #[derive(Debug)]
    pub struct ExternalServiceServer<T> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    impl<T> ExternalServiceServer<T> {
        /// Wrap an owned session implementation in a tonic service.
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        /// Wrap a shared session implementation without creating another instance.
        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        /// Intercept each incoming RPC request before session handling.
        /// The interceptor does not validate individual frames inside the stream.
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Accept and decompress request messages using this encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        /// Enable response compression when the client advertises this encoding.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        /// Limit the decoded bytes of each incoming gRPC message.
        /// This is a per-frame limit, independent of cumulative session traffic.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Limit the encoded bytes of each outgoing gRPC message.
        /// This does not grant flow credits or bound total session traffic.
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for ExternalServiceServer<T>
    where
        T: ExternalService,
        B: Body + std::marker::Send + 'static,
        B::Error: Into<StdError> + std::marker::Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = std::convert::Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(
            &mut self,
            _cx: &mut Context<'_>,
        ) -> Poll<std::result::Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            match req.uri().path() {
                "/xolotl.v1.external.ExternalService/Session" => {
                    struct SessionSvc<T: ExternalService>(pub Arc<T>);
                    impl<T: ExternalService> tonic::server::StreamingService<super::ExternalFrame> for SessionSvc<T> {
                        type Response = super::ExternalFrame;
                        type ResponseStream = T::SessionStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<tonic::Streaming<super::ExternalFrame>>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as ExternalService>::session(&inner, request).await
                            };
                            Box::pin(fut)
                        }
                    }
                    let accept_compression_encodings = self.accept_compression_encodings;
                    let send_compression_encodings = self.send_compression_encodings;
                    let max_decoding_message_size = self.max_decoding_message_size;
                    let max_encoding_message_size = self.max_encoding_message_size;
                    let inner = self.inner.clone();
                    let fut = async move {
                        let method = SessionSvc(inner);
                        let codec = tonic_prost::ProstCodec::default();
                        let mut grpc = tonic::server::Grpc::new(codec)
                            .apply_compression_config(
                                accept_compression_encodings,
                                send_compression_encodings,
                            )
                            .apply_max_message_size_config(
                                max_decoding_message_size,
                                max_encoding_message_size,
                            );
                        let res = grpc.streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    let mut response = http::Response::new(tonic::body::Body::default());
                    let headers = response.headers_mut();
                    headers.insert(
                        tonic::Status::GRPC_STATUS,
                        (tonic::Code::Unimplemented as i32).into(),
                    );
                    headers.insert(
                        http::header::CONTENT_TYPE,
                        tonic::metadata::GRPC_CONTENT_TYPE,
                    );
                    Ok(response)
                }),
            }
        }
    }
    impl<T> Clone for ExternalServiceServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self {
                inner,
                accept_compression_encodings: self.accept_compression_encodings,
                send_compression_encodings: self.send_compression_encodings,
                max_decoding_message_size: self.max_decoding_message_size,
                max_encoding_message_size: self.max_encoding_message_size,
            }
        }
    }
    /// Fully qualified protobuf service name used for tonic routing.
    pub const SERVICE_NAME: &str = "xolotl.v1.external.ExternalService";
    impl<T> tonic::server::NamedService for ExternalServiceServer<T> {
        const NAME: &'static str = SERVICE_NAME;
    }
}
/// Tonic client binding for the bidirectional external role-session RPC.
pub mod external_service_client {
    use tonic::codegen::http::Uri;
    use tonic::codegen::*;
    /// Client for a daemon's external Provider/Source session service.
    #[derive(Debug, Clone)]
    pub struct ExternalServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl ExternalServiceClient<tonic::transport::Channel> {
        /// Attempt to create a new client by connecting to a given endpoint.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> ExternalServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        /// Create a client over an existing tonic-compatible gRPC transport.
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        /// Create a client with an explicit URI origin for outgoing RPC requests.
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        /// Intercept outgoing RPC metadata before sending the session request.
        /// Individual stream frames still require the protocol handshake and validation.
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> ExternalServiceClient<InterceptedService<T, F>>
        where
            F: tonic::service::Interceptor,
            T::ResponseBody: Default,
            T: tonic::codegen::Service<
                    http::Request<tonic::body::Body>,
                    Response = http::Response<
                        <T as tonic::client::GrpcService<tonic::body::Body>>::ResponseBody,
                    >,
                >,
            <T as tonic::codegen::Service<http::Request<tonic::body::Body>>>::Error:
                Into<StdError> + std::marker::Send + std::marker::Sync,
        {
            ExternalServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress outgoing request messages with the selected encoding.
        /// The daemon must accept that encoding.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Advertise support for responses compressed with this encoding.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Limit the decoded bytes of each daemon-to-client gRPC message.
        /// The limit does not accumulate across frames in the session.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Limit the encoded bytes of each client-to-daemon gRPC message.
        /// This is separate from protocol flow-control signals.
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// Open the bidirectional external session RPC and return daemon frames.
        /// Send `RoleSessionClientHello` first, then echo the returned `SessionContext`
        /// in `RoleReady` before business frames. RPC establishment alone is not readiness.
        pub async fn session(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::ExternalFrame>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::ExternalFrame>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/xolotl.v1.external.ExternalService/Session");
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "xolotl.v1.external.ExternalService",
                "Session",
            ));
            self.inner.streaming(req, path, codec).await
        }
    }
}
