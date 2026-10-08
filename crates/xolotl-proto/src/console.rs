// @generated — hand-maintained to match `tonic-prost-build` output for
// `proto/xolotl/v1/console.proto` (package `xolotl.v1.console`). `include!`d
// into the `xolotl::v1::console` module. Keep in sync with the `.proto` spec.

/// Top-level console envelope shared by WebSocket and HTTP single-call adapters.
/// Client messages use tags 1-6; server messages use tags 11-16.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsoleFrame {
    /// Exactly one directional message; an absent body is an invalid console frame.
    #[prost(
        oneof = "console_frame::Frame",
        tags = "1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15, 16"
    )]
    pub frame: ::core::option::Option<console_frame::Frame>,
}
/// Nested message and enum types in `ConsoleFrame`.
pub mod console_frame {
    /// Client requests and server responses carried by a console session.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Frame {
        /// Client protocol version handshake.
        #[prost(message, tag = "1")]
        Hello(super::ClientHello),
        /// Opaque bearer session token.
        #[prost(bytes, tag = "2")]
        AuthToken(::prost::alloc::vec::Vec<u8>),
        /// Client action invocation correlated by its request id.
        #[prost(message, tag = "3")]
        Call(super::ActionCall),
        /// Client request to start a named subscription.
        #[prost(message, tag = "4")]
        Subscribe(super::StreamCall),
        /// Subscription id.
        #[prost(uint64, tag = "5")]
        Unsubscribe(u64),
        /// Nonce.
        #[prost(uint64, tag = "6")]
        Ping(u64),
        /// Server acceptance of the protocol handshake, before authentication.
        #[prost(message, tag = "11")]
        HelloAccepted(super::HelloAccepted),
        /// Server confirmation of the authenticated principal and metadata.
        #[prost(message, tag = "12")]
        Authenticated(super::Authenticated),
        /// Server result for one action invocation.
        #[prost(message, tag = "13")]
        Reply(super::Reply),
        /// Server delivery on an existing subscription.
        #[prost(message, tag = "14")]
        Event(super::Event),
        /// Echoes ping.
        #[prost(uint64, tag = "15")]
        Pong(u64),
        /// Server error, optionally associated with a request id.
        #[prost(message, tag = "16")]
        Error(super::ConsoleError),
    }
}

/// Client handshake declaring the console protocol version.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientHello {
    /// Must equal CONSOLE_PROTOCOL_VERSION.
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    /// Human-readable client id; an empty string means it was not supplied.
    #[prost(string, tag = "2")]
    pub client_name: ::prost::alloc::string::String,
}

/// Successful protocol handshake; it does not authenticate the client.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HelloAccepted {
    /// Negotiated server metadata, present in a successful handshake response.
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<ProtocolGreeting>,
    /// Declared policy for the connected adapter; does not attest end-to-end TLS.
    #[prost(message, optional, tag = "2")]
    pub transport: ::core::option::Option<TransportSecuritySummary>,
}

/// Successful authentication of a console session.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Authenticated {
    /// Authenticated identity summary, present in a successful response.
    #[prost(message, optional, tag = "1")]
    pub principal: ::core::option::Option<PrincipalSummary>,
    /// Server metadata observed when authentication completed.
    #[prost(message, optional, tag = "2")]
    pub metadata: ::core::option::Option<ProtocolGreeting>,
}

/// Negotiated protocol identity, registry revision and observed server state.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtocolGreeting {
    /// Console protocol version accepted by the server.
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    /// "xolotl-console".
    #[prost(string, tag = "2")]
    pub server_name: ::prost::alloc::string::String,
    /// "protobuf+xolotl-console-v1".
    #[prost(string, tag = "3")]
    pub wire_encoding: ::prost::alloc::string::String,
    /// Observed append head; completion updates do not advance it.
    #[prost(uint64, tag = "4")]
    pub server_rev: u64,
    /// Descriptor registry revision.
    #[prost(uint64, tag = "5")]
    pub registry_rev: u64,
    /// Wall clock for client skew detection.
    #[prost(uint64, tag = "6")]
    pub server_time_ms: u64,
}

/// Adapter-owned policy summary, independent of Console service discovery.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TransportSecuritySummary {
    /// Host-declared transport policy; not a TLS attestation.
    #[prost(string, tag = "1")]
    pub mode: ::prost::alloc::string::String,
    /// Whether explicit unsafe transport relaxations are enabled.
    #[prost(bool, tag = "2")]
    pub unsafe_transport: bool,
    /// Enabled relaxation names without private configuration.
    #[prost(string, repeated, tag = "3")]
    pub relaxations: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}

/// Public identity and authority summary for the authenticated principal.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrincipalSummary {
    /// Console account name associated with the authenticated session.
    #[prost(string, tag = "1")]
    pub username: ::prost::alloc::string::String,
    /// `identity://console/accounts/<account-incarnation>`.
    #[prost(string, tag = "2")]
    pub identity_path: ::prost::alloc::string::String,
    /// 1 = single-factor, 2 = verified.
    #[prost(uint32, tag = "3")]
    pub mfa_level: u32,
}

/// One descriptor-named management action and its admission context.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActionCall {
    /// Client correlation id.
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// Action id, e.g. "config.write_cas".
    #[prost(string, tag = "2")]
    pub action: ::prost::alloc::string::String,
    /// Action input; the console decoder treats absence as the Xolotl null value.
    #[prost(message, optional, tag = "4")]
    pub input: ::core::option::Option<super::Value>,
    /// Optional target scope, required by visibility-gated actions.
    #[prost(string, optional, tag = "5")]
    pub scope: ::core::option::Option<::prost::alloc::string::String>,
    /// Optional operator justification, required by visibility-gated actions.
    #[prost(string, optional, tag = "6")]
    pub justification: ::core::option::Option<::prost::alloc::string::String>,
    /// Requested visibility duration in milliseconds, subject to server admission.
    /// Visibility-gated actions require a positive, bounded value.
    #[prost(uint64, optional, tag = "7")]
    pub ttl_ms: ::core::option::Option<u64>,
    /// Client's descriptor rev (RegistryChanged detection).
    #[prost(uint64, optional, tag = "8")]
    pub registry_rev: ::core::option::Option<u64>,
}

/// Request to subscribe to a descriptor-named console event stream.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamCall {
    /// Subscription id.
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// Stream id, e.g. "state.watch".
    #[prost(string, tag = "2")]
    pub stream: ::prost::alloc::string::String,
    /// Stream input or filter; absence decodes as the Xolotl null value.
    #[prost(message, optional, tag = "3")]
    pub input: ::core::option::Option<super::Value>,
    /// Optional target scope, required by visibility-gated subscriptions.
    #[prost(string, optional, tag = "4")]
    pub scope: ::core::option::Option<::prost::alloc::string::String>,
    /// Optional operator justification for access to sensitive stream data.
    #[prost(string, optional, tag = "5")]
    pub justification: ::core::option::Option<::prost::alloc::string::String>,
    /// Requested visibility duration in milliseconds; gated streams close on expiry.
    #[prost(uint64, optional, tag = "6")]
    pub ttl_ms: ::core::option::Option<u64>,
    /// Optional descriptor and host-module contract precondition.
    #[prost(uint64, optional, tag = "9")]
    pub registry_rev: ::core::option::Option<u64>,
}

/// Successful action response associated with the caller's request id.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Reply {
    /// Echoes ActionCall.id.
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// Action result, present in a successful reply; failures use `ConsoleError`.
    #[prost(message, optional, tag = "2")]
    pub result: ::core::option::Option<ActionResult>,
}

/// Action output together with revisions observed after execution.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActionResult {
    /// Optional action output; absence means no value was returned, distinct from null.
    #[prost(message, optional, tag = "1")]
    pub output: ::core::option::Option<super::Value>,
    /// Observed Fact append head after this action; outcome updates do not advance it.
    #[prost(uint64, tag = "2")]
    pub server_rev: u64,
    /// Descriptor registry revision, populated by the host for every reply, including empty results.
    #[prost(uint64, optional, tag = "3")]
    pub registry_rev: ::core::option::Option<u64>,
    /// Allocated runtime execution; does not grant observation authority.
    #[prost(message, optional, tag = "5")]
    pub execution: ::core::option::Option<ExecutionReference>,
    /// Effects that remain uncertain even if this action succeeded.
    #[prost(message, optional, tag = "6")]
    pub unresolved_operations: ::core::option::Option<super::UnresolvedOperations>,
}

/// Kernel execution allocated for a call or subscription.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ExecutionReference {
    /// Opaque Console execution ID for a service-owned record.
    #[prost(string, optional, tag = "3")]
    pub execution_id: ::core::option::Option<::prost::alloc::string::String>,
    /// Decimal kernel process ID.
    #[prost(string, tag = "1")]
    pub process_id: ::prost::alloc::string::String,
    /// Lowercase hexadecimal content-addressed program ID.
    #[prost(string, tag = "2")]
    pub program_id: ::prost::alloc::string::String,
}

/// Delivery envelope identifying the subscription that produced an event.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Event {
    /// Subscription id.
    #[prost(uint64, tag = "1")]
    pub stream: u64,
    /// Delivered event body, present in a valid server event frame.
    #[prost(message, optional, tag = "2")]
    pub event: ::core::option::Option<ConsoleEvent>,
}

/// Projected state, Fact or lifecycle notification on a console subscription.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsoleEvent {
    /// Event-specific payload; a valid event selects exactly one variant.
    #[prost(oneof = "console_event::Kind", tags = "1, 2, 3, 4, 5, 6, 7")]
    pub kind: ::core::option::Option<console_event::Kind>,
}
/// Nested message and enum types in `ConsoleEvent`.
pub mod console_event {
    /// State changes, projected Facts, summaries and subscription termination.
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        /// A state path was assigned a replacement value.
        #[prost(message, tag = "1")]
        StateSet(super::StateSet),
        /// An item was appended at a state path.
        #[prost(message, tag = "2")]
        StateAppend(super::StateAppend),
        /// A state path was deleted.
        #[prost(message, tag = "3")]
        StateDelete(super::StateDelete),
        /// A Fact was appended or its recorded outcome was updated.
        #[prost(message, tag = "4")]
        Fact(super::FactEvent),
        /// Remove a sequence prefix and append one item.
        #[prost(message, tag = "5")]
        StateDropPrefixAppend(super::StateDropPrefixAppend),
        /// The server terminated this subscription with a reason.
        #[prost(message, tag = "6")]
        Closed(super::SubscriptionClosed),
        /// Live execution output or terminal result.
        #[prost(message, tag = "7")]
        Runtime(super::RuntimeEvent),
    }
}

/// Discriminated lossless runtime execution event.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RuntimeEvent {
    /// Envelope with kind, execution identity and event-specific fields.
    #[prost(message, optional, tag = "1")]
    pub event: ::core::option::Option<super::Value>,
}

/// Projected notification that a state value was replaced.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateSet {
    /// Changed state path, present in a valid set notification.
    #[prost(message, optional, tag = "1")]
    pub path: ::core::option::Option<super::Path>,
    /// Replacement value after visibility projection.
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<super::Value>,
    /// Coarse lineage categories without source labels or protected paths.
    #[prost(message, optional, tag = "3")]
    pub source: ::core::option::Option<StateSourceSummary>,
}

/// Projected notification that an item was appended to state.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateAppend {
    /// State path receiving the append, present in a valid notification.
    #[prost(message, optional, tag = "1")]
    pub path: ::core::option::Option<super::Path>,
    /// Appended item after visibility projection.
    #[prost(message, optional, tag = "2")]
    pub item: ::core::option::Option<super::Value>,
    /// Coarse lineage categories without source labels or protected paths.
    #[prost(message, optional, tag = "3")]
    pub source: ::core::option::Option<StateSourceSummary>,
}

/// Replayable list window update after a Source capacity overflow.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateDropPrefixAppend {
    /// State path receiving the update, present in a valid notification.
    #[prost(message, optional, tag = "1")]
    pub path: ::core::option::Option<super::Path>,
    /// Exact number of existing members removed from the front.
    #[prost(uint64, tag = "2")]
    pub removed: u64,
    /// Appended item after visibility projection.
    #[prost(message, optional, tag = "3")]
    pub item: ::core::option::Option<super::Value>,
    /// Coarse lineage categories without private labels or protected paths.
    #[prost(message, optional, tag = "4")]
    pub source: ::core::option::Option<StateSourceSummary>,
}

/// Notification that a visible state path was deleted.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateDelete {
    /// Deleted state path, present in a valid delete notification.
    #[prost(message, optional, tag = "1")]
    pub path: ::core::option::Option<super::Path>,
    /// Coarse lineage categories without source labels or protected paths.
    #[prost(message, optional, tag = "2")]
    pub source: ::core::option::Option<StateSourceSummary>,
}

/// Fixed State watch lineage categories; no private source labels are serialized.
#[derive(Clone, Copy, PartialEq, Eq, ::prost::Message)]
pub struct StateSourceSummary {
    /// Whether any lineage was recorded.
    #[prost(bool, tag = "1")]
    pub tainted: bool,
    /// Whether program-authored data contributed.
    #[prost(bool, tag = "2")]
    pub author_constant: bool,
    /// Whether model output contributed.
    #[prost(bool, tag = "3")]
    pub model_output: bool,
    /// Whether an inbound payload contributed.
    #[prost(bool, tag = "4")]
    pub inbound: bool,
    /// Whether fetched content contributed.
    #[prost(bool, tag = "5")]
    pub fetched: bool,
    /// Whether protected data contributed, without revealing its path.
    #[prost(bool, tag = "6")]
    pub protected: bool,
}

/// Visibility-filtered representation of a new or updated Fact.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FactEvent {
    /// Projected Fact (redacted per visibility tier).
    #[prost(message, optional, tag = "1")]
    pub fact: ::core::option::Option<super::Value>,
}

/// Terminal event explaining why a subscription stopped delivering events.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscriptionClosed {
    /// Server-provided closure reason, such as expiry, revocation or backpressure.
    #[prost(string, tag = "1")]
    pub reason: ::prost::alloc::string::String,
    /// Structured service failure; absent on normal completion.
    #[prost(message, optional, tag = "2")]
    pub failure: ::core::option::Option<ConsoleError>,
}

/// Redacted console failure with optional context for client recovery.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsoleError {
    /// Error category encoded as a `ConsoleErrorCode` discriminant.
    #[prost(enumeration = "ConsoleErrorCode", tag = "1")]
    pub code: i32,
    /// Redacted; never contains secrets/tokens/raw policy.
    #[prost(string, tag = "2")]
    pub message: ::prost::alloc::string::String,
    /// Correlation id when known.
    #[prost(uint64, optional, tag = "3")]
    pub request_id: ::core::option::Option<u64>,
    /// Known retry delay only; does not guarantee retrying a mutation is safe.
    #[prost(uint64, optional, tag = "4")]
    pub retry_after_ms: ::core::option::Option<u64>,
    /// STEP_UP_REQUIRED.
    #[prost(uint32, optional, tag = "5")]
    pub required_mfa_level: ::core::option::Option<u32>,
    /// Version observed by the failed comparison, when a usable version was present.
    #[prost(uint64, optional, tag = "6")]
    pub current_version: ::core::option::Option<u64>,
    /// REGISTRY_CHANGED.
    #[prost(uint64, optional, tag = "7")]
    pub current_registry_rev: ::core::option::Option<u64>,
    /// Account factor choices, returned only after successful primary authentication.
    #[prost(message, optional, tag = "9")]
    pub mfa: ::core::option::Option<MfaOptions>,
    /// Allocated execution, including preparation and timeout failures.
    #[prost(message, optional, tag = "11")]
    pub execution: ::core::option::Option<ExecutionReference>,
    /// Host-authored identity and cause for an uncertain effect.
    #[prost(message, optional, tag = "12")]
    pub outcome_unknown: ::core::option::Option<OutcomeUnknownDetail>,
    /// Other unresolved effects retained through this failure.
    #[prost(message, optional, tag = "13")]
    pub unresolved_operations: ::core::option::Option<super::UnresolvedOperations>,
    /// Retained body and lifecycle evidence when a runtime reply fails.
    #[prost(message, optional, boxed, tag = "14")]
    pub runtime_completion: ::core::option::Option<::prost::alloc::boxed::Box<super::Value>>,
}

/// Host-authored effect identity and bounded cause, never a remote diagnostic.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutcomeUnknownDetail {
    /// Opaque stable operation or outbound command identities.
    #[prost(string, repeated, tag = "1")]
    pub operation_ids: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Classified host cause.
    #[prost(string, tag = "2")]
    pub reason: ::prost::alloc::string::String,
}

/// Account-specific second-factor choices following primary authentication.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MfaOptions {
    /// Enrolled factor instances, including unavailable providers.
    #[prost(message, repeated, tag = "1")]
    pub factors: ::prost::alloc::vec::Vec<MfaFactor>,
    /// Whether an unconsumed recovery code can satisfy the challenge.
    #[prost(bool, tag = "2")]
    pub recovery_code_available: bool,
}

/// Public metadata for one enrolled second-factor instance.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MfaFactor {
    /// Opaque enrollment identity, independent of its provider.
    #[prost(string, tag = "1")]
    pub factor_id: ::prost::alloc::string::String,
    /// Stable identifier of the verifying provider.
    #[prost(string, tag = "2")]
    pub provider_id: ::prost::alloc::string::String,
    /// User-supplied display label.
    #[prost(string, tag = "3")]
    pub label: ::prost::alloc::string::String,
    /// Enrollment time in milliseconds since the Unix epoch.
    #[prost(int64, tag = "4")]
    pub created_at: i64,
    /// Most recent successful verification time, when available.
    #[prost(int64, optional, tag = "5")]
    pub last_used_at: ::core::option::Option<i64>,
    /// Installation and authentication-use status on the current host.
    #[prost(enumeration = "FactorAvailability", tag = "6")]
    pub availability: i32,
}

/// Current host readiness to dispatch authentication for an enrolled factor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum FactorAvailability {
    /// No status was supplied; the protobuf zero value.
    Unspecified = 0,
    /// The host does not have this factor's provider installed.
    ProviderNotInstalled = 1,
    /// The provider is installed but host policy forbids new authentication.
    AuthenticationDisabled = 2,
    /// The host allows authentication; external dependency health is not implied.
    Available = 3,
}
impl FactorAvailability {
    /// Return the exact enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "FACTOR_AVAILABILITY_UNSPECIFIED",
            Self::ProviderNotInstalled => "PROVIDER_NOT_INSTALLED",
            Self::AuthenticationDisabled => "AUTHENTICATION_DISABLED",
            Self::Available => "AVAILABLE",
        }
    }
    /// Parse an exact protobuf enum spelling, rejecting unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "FACTOR_AVAILABILITY_UNSPECIFIED" => Some(Self::Unspecified),
            "PROVIDER_NOT_INSTALLED" => Some(Self::ProviderNotInstalled),
            "AUTHENTICATION_DISABLED" => Some(Self::AuthenticationDisabled),
            "AVAILABLE" => Some(Self::Available),
            _ => None,
        }
    }
}

/// Stable wire categories for console authentication, admission and execution failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ConsoleErrorCode {
    /// No error category was supplied; the protobuf zero value.
    Unspecified = 0,
    /// A valid authenticated console session is required.
    Unauthenticated = 1,
    /// The principal lacks authority for the requested operation.
    Forbidden = 2,
    /// The session must satisfy the reported MFA level before retrying.
    StepUpRequired = 3,
    /// Request rate exceeded the server's admission limit.
    RateLimited = 4,
    /// Request fields or values failed validation.
    ValidationFailed = 5,
    /// Kernel policy or resource admission rejected the operation.
    AdmissionRejected = 6,
    /// The expected version did not match the current value.
    VersionConflict = 7,
    /// The client's descriptor registry revision is stale.
    RegistryChanged = 9,
    /// An internal failure occurred; diagnostic details remain server-side.
    Internal = 16,
    /// An effect may have started, but its outcome cannot be established.
    OutcomeUnknown = 17,
}
impl ConsoleErrorCode {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "CONSOLE_ERROR_CODE_UNSPECIFIED",
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::Forbidden => "FORBIDDEN",
            Self::StepUpRequired => "STEP_UP_REQUIRED",
            Self::RateLimited => "RATE_LIMITED",
            Self::ValidationFailed => "VALIDATION_FAILED",
            Self::AdmissionRejected => "ADMISSION_REJECTED",
            Self::VersionConflict => "VERSION_CONFLICT",
            Self::RegistryChanged => "REGISTRY_CHANGED",
            Self::Internal => "INTERNAL",
            Self::OutcomeUnknown => "OUTCOME_UNKNOWN",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CONSOLE_ERROR_CODE_UNSPECIFIED" => Some(Self::Unspecified),
            "UNAUTHENTICATED" => Some(Self::Unauthenticated),
            "FORBIDDEN" => Some(Self::Forbidden),
            "STEP_UP_REQUIRED" => Some(Self::StepUpRequired),
            "RATE_LIMITED" => Some(Self::RateLimited),
            "VALIDATION_FAILED" => Some(Self::ValidationFailed),
            "ADMISSION_REJECTED" => Some(Self::AdmissionRejected),
            "VERSION_CONFLICT" => Some(Self::VersionConflict),
            "REGISTRY_CHANGED" => Some(Self::RegistryChanged),
            "INTERNAL" => Some(Self::Internal),
            "OUTCOME_UNKNOWN" => Some(Self::OutcomeUnknown),
            _ => None,
        }
    }
}
