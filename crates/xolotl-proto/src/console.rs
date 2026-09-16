// @generated — hand-maintained to match `tonic-prost-build` output for
// `proto/xolotl/v1/console.proto` (package `xolotl.v1.console`). `include!`d
// into the `xolotl::v1::console` module. Keep in sync with the `.proto` spec.

/// Top-level console envelope shared by WebSocket and gRPC transports.
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
        /// Client protocol and encoding negotiation.
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
        /// Server acceptance of protocol negotiation, before authentication.
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

/// Client handshake declaring the console protocol and supported encodings.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientHello {
    /// Must equal CONSOLE_PROTOCOL_VERSION.
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    /// Human-readable client id; an empty string means it was not supplied.
    #[prost(string, tag = "2")]
    pub client_name: ::prost::alloc::string::String,
    /// Accepted wire encodings.
    #[prost(string, repeated, tag = "3")]
    pub accepted_encodings: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Client's last-known descriptor rev.
    #[prost(uint64, optional, tag = "4")]
    pub registry_rev: ::core::option::Option<u64>,
}

/// Successful protocol negotiation; it does not authenticate the client.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HelloAccepted {
    /// Negotiated server metadata, present in a successful handshake response.
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<ProtocolMetadata>,
}

/// Successful authentication of a console session.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Authenticated {
    /// Authenticated identity summary, present in a successful response.
    #[prost(message, optional, tag = "1")]
    pub principal: ::core::option::Option<PrincipalSummary>,
    /// Server metadata observed when authentication completed.
    #[prost(message, optional, tag = "2")]
    pub metadata: ::core::option::Option<ProtocolMetadata>,
}

/// Negotiated protocol identity, registry revision and observed server state.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtocolMetadata {
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
    /// Optional feature flags.
    #[prost(string, repeated, tag = "7")]
    pub capabilities: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}

/// Public identity and authority summary for the authenticated principal.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrincipalSummary {
    /// Console account name associated with the authenticated session.
    #[prost(string, tag = "1")]
    pub username: ::prost::alloc::string::String,
    /// `identity://console/<user>`.
    #[prost(string, tag = "2")]
    pub identity_path: ::prost::alloc::string::String,
    /// 1 = single-factor, 2 = verified.
    #[prost(uint32, tag = "3")]
    pub mfa_level: u32,
    /// Effective kernel capability selectors (redacted summary).
    #[prost(string, repeated, tag = "4")]
    pub grants: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
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
    /// Compact code fast-path; if set, `action` may be empty.
    #[prost(uint32, optional, tag = "3")]
    pub action_code: ::core::option::Option<u32>,
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
    /// Client-supplied idempotency key.
    #[prost(string, optional, tag = "9")]
    pub idempotency_key: ::core::option::Option<::prost::alloc::string::String>,
}

/// Request to subscribe to a descriptor-named console event stream.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamCall {
    /// Subscription id.
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// Stream id, e.g. "state.diff".
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
    /// Reserved; current live-only streams reject this field.
    #[prost(uint64, optional, tag = "7")]
    pub since_rev: ::core::option::Option<u64>,
    /// Requested maximum events per server flush; absence leaves batching to the server.
    #[prost(uint32, optional, tag = "8")]
    pub max_batch: ::core::option::Option<u32>,
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
    /// Descriptor registry revision.
    #[prost(uint64, optional, tag = "3")]
    pub registry_rev: ::core::option::Option<u64>,
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
    #[prost(oneof = "console_event::Kind", tags = "1, 2, 3, 4, 5, 6")]
    pub kind: ::core::option::Option<console_event::Kind>,
    /// Reserved; current live-only streams emit zero.
    #[prost(uint64, tag = "10")]
    pub state_rev: u64,
    /// Reserved; append positions cannot resume outcome updates.
    #[prost(uint64, tag = "11")]
    pub fact_cursor: u64,
    /// True if events were merged under backpressure.
    #[prost(bool, tag = "12")]
    pub coalesced: bool,
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
        /// VolatileSummary coalesced.
        #[prost(message, tag = "5")]
        Summary(super::Summary),
        /// The server terminated this subscription with a reason.
        #[prost(message, tag = "6")]
        Closed(super::SubscriptionClosed),
    }
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
}

/// Notification that a visible state path was deleted.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateDelete {
    /// Deleted state path, present in a valid delete notification.
    #[prost(message, optional, tag = "1")]
    pub path: ::core::option::Option<super::Path>,
}

/// Visibility-filtered representation of a new or updated Fact.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FactEvent {
    /// Projected Fact (redacted per visibility tier).
    #[prost(message, optional, tag = "1")]
    pub fact: ::core::option::Option<super::Value>,
}

/// Latest aggregate value for a coalesced volatile subscription.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Summary {
    /// Coalesced volatile summary value.
    #[prost(message, optional, tag = "1")]
    pub payload: ::core::option::Option<super::Value>,
}

/// Terminal event explaining why a subscription stopped delivering events.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscriptionClosed {
    /// Server-provided closure reason, such as expiry, revocation or backpressure.
    #[prost(string, tag = "1")]
    pub reason: ::prost::alloc::string::String,
    /// Reserved; current live-only streams leave this absent.
    #[prost(uint64, optional, tag = "2")]
    pub last_rev: ::core::option::Option<u64>,
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
    /// RATE_LIMITED / BACKPRESSURE.
    #[prost(uint64, optional, tag = "4")]
    pub retry_after_ms: ::core::option::Option<u64>,
    /// STEP_UP_REQUIRED.
    #[prost(uint32, optional, tag = "5")]
    pub required_mfa_level: ::core::option::Option<u32>,
    /// VERSION_CONFLICT.
    #[prost(uint64, optional, tag = "6")]
    pub current_version: ::core::option::Option<u64>,
    /// REGISTRY_CHANGED.
    #[prost(uint64, optional, tag = "7")]
    pub current_registry_rev: ::core::option::Option<u64>,
    /// Approval / policy id.
    #[prost(string, optional, tag = "8")]
    pub correlation_id: ::core::option::Option<::prost::alloc::string::String>,
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
    /// The requested resource or descriptor could not be found.
    NotFound = 8,
    /// The client's descriptor registry revision is stale.
    RegistryChanged = 9,
    /// The client must recover missed history before continuing, when supported.
    ReplayRequired = 10,
    /// Required visibility scope, justification or duration is missing.
    VisibilityRequired = 11,
    /// The index needed to answer the request is unavailable.
    IndexUnavailable = 12,
    /// A request, result or event exceeds the applicable payload bound.
    PayloadTooLarge = 13,
    /// Delivery or processing capacity cannot keep up with demand.
    Backpressure = 14,
    /// The requested console protocol version is unsupported.
    UnsupportedVersion = 15,
    /// An internal failure occurred; diagnostic details remain server-side.
    Internal = 16,
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
            Self::NotFound => "NOT_FOUND",
            Self::RegistryChanged => "REGISTRY_CHANGED",
            Self::ReplayRequired => "REPLAY_REQUIRED",
            Self::VisibilityRequired => "VISIBILITY_REQUIRED",
            Self::IndexUnavailable => "INDEX_UNAVAILABLE",
            Self::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            Self::Backpressure => "BACKPRESSURE",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::Internal => "INTERNAL",
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
            "NOT_FOUND" => Some(Self::NotFound),
            "REGISTRY_CHANGED" => Some(Self::RegistryChanged),
            "REPLAY_REQUIRED" => Some(Self::ReplayRequired),
            "VISIBILITY_REQUIRED" => Some(Self::VisibilityRequired),
            "INDEX_UNAVAILABLE" => Some(Self::IndexUnavailable),
            "PAYLOAD_TOO_LARGE" => Some(Self::PayloadTooLarge),
            "BACKPRESSURE" => Some(Self::Backpressure),
            "UNSUPPORTED_VERSION" => Some(Self::UnsupportedVersion),
            "INTERNAL" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// Discoverable action contract describing schemas, admission and execution semantics.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActionDescriptor {
    /// Stable action name, for example `config.write_cas`.
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    /// Optional compact code accepted in `ActionCall::action_code`.
    #[prost(uint32, optional, tag = "2")]
    pub code: ::core::option::Option<u32>,
    /// Management domain grouping, for example `config`.
    #[prost(string, tag = "3")]
    pub domain: ::prost::alloc::string::String,
    /// Descriptor schema version.
    #[prost(uint32, tag = "4")]
    pub version: u32,
    /// Compatibility maturity encoded as a `Stability` discriminant.
    #[prost(enumeration = "Stability", tag = "5")]
    pub stability: i32,
    /// Input schema when supplied by the registry; absence does not imply null input.
    #[prost(message, optional, tag = "6")]
    pub input: ::core::option::Option<SchemaDescriptor>,
    /// Output schema when supplied by the registry; absence leaves its shape unspecified.
    #[prost(message, optional, tag = "7")]
    pub output: ::core::option::Option<SchemaDescriptor>,
    /// Kernel capability selectors.
    #[prost(string, repeated, tag = "8")]
    pub required_grants: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Minimum authenticated MFA level advertised for this action.
    #[prost(uint32, tag = "9")]
    pub required_mfa_level: u32,
    /// Operational risk encoded as a `RiskLevel` discriminant.
    #[prost(enumeration = "RiskLevel", tag = "10")]
    pub risk: i32,
    /// Advertised retry and deduplication model encoded as an `IdempotencyClass`.
    #[prost(enumeration = "IdempotencyClass", tag = "11")]
    pub idempotency: i32,
    /// Advertised read and write consistency encoded as a `ConsistencyClass`.
    #[prost(enumeration = "ConsistencyClass", tag = "12")]
    pub consistency: i32,
    /// Optional audit category associated with executions of this action.
    #[prost(string, optional, tag = "13")]
    pub audit_tag: ::core::option::Option<::prost::alloc::string::String>,
    /// Output projection policy encoded as a `RedactionProfile` discriminant.
    #[prost(enumeration = "RedactionProfile", tag = "14")]
    pub redaction: i32,
    /// Optional special-display policy; absence makes no display-edge declaration.
    #[prost(enumeration = "DisplayEdgeKind", optional, tag = "15")]
    pub display_edge: ::core::option::Option<i32>,
    /// Kernel operation pattern encoded as a `RecipeKind` discriminant.
    #[prost(enumeration = "RecipeKind", tag = "16")]
    pub recipe_kind: i32,
    /// Optional page-size and cursor contract for actions that expose pagination.
    #[prost(message, optional, tag = "17")]
    pub pagination: ::core::option::Option<PaginationSpec>,
    /// Stream ids this action can emit on.
    #[prost(string, repeated, tag = "18")]
    pub stream_emits: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Whether the advertised action is executable, planned or otherwise unavailable.
    #[prost(enumeration = "ImplementationStatus", tag = "19")]
    pub status: i32,
    /// Required data visibility tier encoded as a `VisibilityTier` discriminant.
    #[prost(enumeration = "VisibilityTier", tag = "20")]
    pub visibility: i32,
    /// Optional custody classification encoded as a `SecretClass` discriminant.
    #[prost(enumeration = "SecretClass", optional, tag = "21")]
    pub secret_class: ::core::option::Option<i32>,
    /// Whether invocation requires the session to pass the server's step-up gate.
    #[prost(bool, tag = "22")]
    pub requires_step_up: bool,
}

/// Discoverable subscription contract describing event shape, admission and delivery.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamDescriptor {
    /// Stable stream name, for example `state.diff`.
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    /// Management domain that owns this stream.
    #[prost(string, tag = "2")]
    pub domain: ::prost::alloc::string::String,
    /// Availability encoded as an `ImplementationStatus` discriminant.
    #[prost(enumeration = "ImplementationStatus", tag = "3")]
    pub status: i32,
    /// Data access tier encoded as a `VisibilityTier` discriminant.
    #[prost(enumeration = "VisibilityTier", tag = "4")]
    pub visibility: i32,
    /// Whether subscription admission requires the server's step-up gate.
    #[prost(bool, tag = "5")]
    pub requires_step_up: bool,
    /// Kernel capability selectors.
    #[prost(string, repeated, tag = "6")]
    pub required_grants: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Subscription filter schema when supplied by the registry.
    #[prost(message, optional, tag = "7")]
    pub input: ::core::option::Option<SchemaDescriptor>,
    /// Delivered event schema when supplied by the registry.
    #[prost(message, optional, tag = "8")]
    pub event: ::core::option::Option<SchemaDescriptor>,
    /// ReliableLog / StateDiff / VolatileSummary.
    #[prost(enumeration = "StreamClass", tag = "9")]
    pub class: i32,
    /// Advertised resume semantics; current live-only streams do not support cursors.
    #[prost(enumeration = "ResumeMode", tag = "10")]
    pub resume: i32,
    /// Monotonicity guarantee.
    #[prost(enumeration = "OrderingMode", tag = "11")]
    pub ordering: i32,
    /// Optional advertised batch size when the subscriber omits `max_batch`.
    #[prost(uint32, optional, tag = "12")]
    pub default_max_batch: ::core::option::Option<u32>,
}

/// Descriptive schema for the Xolotl value carried by an action or stream.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SchemaDescriptor {
    /// Stable schema identity used by registry consumers.
    #[prost(string, tag = "1")]
    pub schema_id: ::prost::alloc::string::String,
    /// "map" / "list" / "string" / ...
    #[prost(string, tag = "2")]
    pub value_kind: ::prost::alloc::string::String,
    /// Known fields of map-shaped values; other value kinds may leave this empty.
    #[prost(message, repeated, tag = "3")]
    pub fields: ::prost::alloc::vec::Vec<FieldDescriptor>,
    /// Human-readable constraints and qualifications beyond the listed field shapes.
    #[prost(string, repeated, tag = "4")]
    pub notes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}

/// Shape and semantic metadata for one field of a map-shaped value.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FieldDescriptor {
    /// Field key in the containing Xolotl map.
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    /// Expected value kind for this field.
    #[prost(string, tag = "2")]
    pub kind: ::prost::alloc::string::String,
    /// Whether values conforming to this schema must include the field.
    #[prost(bool, tag = "3")]
    pub required: bool,
    /// Optional semantic identity retained across schema revisions.
    #[prost(string, optional, tag = "4")]
    pub stable_id: ::core::option::Option<::prost::alloc::string::String>,
    /// Optional meaning independent of value shape or any particular UI widget.
    #[prost(string, optional, tag = "5")]
    pub semantic_kind: ::core::option::Option<::prost::alloc::string::String>,
    /// Optional resource type referenced by this field when it contains a reference.
    #[prost(string, optional, tag = "6")]
    pub ref_target_type: ::core::option::Option<::prost::alloc::string::String>,
    /// Persistence, logging and display classification as a `Sensitivity` discriminant.
    #[prost(enumeration = "Sensitivity", tag = "7")]
    pub sensitivity: i32,
    /// Whether clients must treat this field as non-editable.
    #[prost(bool, tag = "8")]
    pub read_only: bool,
    /// Whether the server derives the field's value.
    #[prost(bool, tag = "9")]
    pub computed: bool,
}

/// Advertised pagination parameters; cursor interpretation belongs to the action.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PaginationSpec {
    /// Cursor representation, for example `offset`, `rev` or opaque `cursor`.
    /// This label alone does not guarantee a stable snapshot across pages.
    #[prost(string, tag = "1")]
    pub cursor_kind: ::prost::alloc::string::String,
    /// Page size advertised when the caller omits the action's limit argument.
    #[prost(uint32, tag = "2")]
    pub default_limit: u32,
    /// Advertised upper bound on page size, validated by the action implementation.
    #[prost(uint32, tag = "3")]
    pub max_limit: u32,
}

/// Kernel operation pattern advertised by an action descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RecipeKind {
    /// No recipe was declared; the protobuf zero value.
    Unspecified = 0,
    /// Read the current value at a state path.
    StateRead = 1,
    /// Enumerate state entries matching a query.
    StateList = 2,
    /// Replace state only when its current value matches an expected value.
    StateWriteCas = 3,
    /// Append an item at a state path.
    StateAppend = 4,
    /// Remove a state entry.
    StateDelete = 5,
    /// Invoke a registered effect method.
    EffectInvoke = 6,
    /// Read a retained Fact or a bounded Fact query result.
    FactRead = 7,
    /// Consume a tail of Fact records under the action's declared cursor semantics.
    FactTail = 8,
    /// Establish an event subscription.
    Subscribe = 9,
    /// Inspect runtime state or resource metadata.
    Inspect = 10,
    /// Compose multiple kernel operations into one action.
    Composite = 11,
    /// Deliver sensitive data through a dedicated display edge.
    DisplayEdge = 12,
}
impl RecipeKind {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "RECIPE_KIND_UNSPECIFIED",
            Self::StateRead => "RECIPE_STATE_READ",
            Self::StateList => "RECIPE_STATE_LIST",
            Self::StateWriteCas => "RECIPE_STATE_WRITE_CAS",
            Self::StateAppend => "RECIPE_STATE_APPEND",
            Self::StateDelete => "RECIPE_STATE_DELETE",
            Self::EffectInvoke => "RECIPE_EFFECT_INVOKE",
            Self::FactRead => "RECIPE_FACT_READ",
            Self::FactTail => "RECIPE_FACT_TAIL",
            Self::Subscribe => "RECIPE_SUBSCRIBE",
            Self::Inspect => "RECIPE_INSPECT",
            Self::Composite => "RECIPE_COMPOSITE",
            Self::DisplayEdge => "RECIPE_DISPLAY_EDGE",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "RECIPE_KIND_UNSPECIFIED" => Some(Self::Unspecified),
            "RECIPE_STATE_READ" => Some(Self::StateRead),
            "RECIPE_STATE_LIST" => Some(Self::StateList),
            "RECIPE_STATE_WRITE_CAS" => Some(Self::StateWriteCas),
            "RECIPE_STATE_APPEND" => Some(Self::StateAppend),
            "RECIPE_STATE_DELETE" => Some(Self::StateDelete),
            "RECIPE_EFFECT_INVOKE" => Some(Self::EffectInvoke),
            "RECIPE_FACT_READ" => Some(Self::FactRead),
            "RECIPE_FACT_TAIL" => Some(Self::FactTail),
            "RECIPE_SUBSCRIBE" => Some(Self::Subscribe),
            "RECIPE_INSPECT" => Some(Self::Inspect),
            "RECIPE_COMPOSITE" => Some(Self::Composite),
            "RECIPE_DISPLAY_EDGE" => Some(Self::DisplayEdge),
            _ => None,
        }
    }
}

/// Maturity advertised for an action contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Stability {
    /// No stability level was supplied; the protobuf zero value.
    Unspecified = 0,
    /// Experimental contract whose shape and semantics may change.
    Experimental = 1,
    /// Pre-stable contract available for evaluation and integration.
    Beta = 2,
    /// Contract advertised as stable for supported consumers.
    Stable = 3,
}
impl Stability {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "STABILITY_UNSPECIFIED",
            Self::Experimental => "STABILITY_EXPERIMENTAL",
            Self::Beta => "STABILITY_BETA",
            Self::Stable => "STABILITY_STABLE",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "STABILITY_UNSPECIFIED" => Some(Self::Unspecified),
            "STABILITY_EXPERIMENTAL" => Some(Self::Experimental),
            "STABILITY_BETA" => Some(Self::Beta),
            "STABILITY_STABLE" => Some(Self::Stable),
            _ => None,
        }
    }
}

/// Operational impact category advertised for management actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RiskLevel {
    /// No risk assessment was supplied; the protobuf zero value.
    Unspecified = 0,
    /// Routine action with low operational impact.
    Low = 1,
    /// Elevated management action with moderate operational impact.
    Medium = 2,
    /// Sensitive or broadly consequential management action.
    High = 3,
    /// Exceptional access governed by explicit break-glass admission.
    BreakGlass = 4,
}
impl RiskLevel {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "RISK_LEVEL_UNSPECIFIED",
            Self::Low => "RISK_LEVEL_LOW",
            Self::Medium => "RISK_LEVEL_MEDIUM",
            Self::High => "RISK_LEVEL_HIGH",
            Self::BreakGlass => "RISK_LEVEL_BREAK_GLASS",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "RISK_LEVEL_UNSPECIFIED" => Some(Self::Unspecified),
            "RISK_LEVEL_LOW" => Some(Self::Low),
            "RISK_LEVEL_MEDIUM" => Some(Self::Medium),
            "RISK_LEVEL_HIGH" => Some(Self::High),
            "RISK_LEVEL_BREAK_GLASS" => Some(Self::BreakGlass),
            _ => None,
        }
    }
}

/// Advertised strategy for preventing duplicate effects when an action is retried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum IdempotencyClass {
    /// No idempotency contract was supplied; the protobuf zero value.
    Unspecified = 0,
    /// No deduplication guarantee is advertised.
    None = 1,
    /// Retries are associated through a client-supplied idempotency key.
    ClientKey = 2,
    /// The server derives the identity used to associate retries.
    ServerDerived = 3,
    /// A compare-and-set precondition guards mutation without general request deduplication.
    CasOnly = 4,
}
impl IdempotencyClass {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "IDEMPOTENCY_CLASS_UNSPECIFIED",
            Self::None => "IDEMPOTENCY_NONE",
            Self::ClientKey => "IDEMPOTENCY_CLIENT_KEY",
            Self::ServerDerived => "IDEMPOTENCY_SERVER_DERIVED",
            Self::CasOnly => "IDEMPOTENCY_CAS_ONLY",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "IDEMPOTENCY_CLASS_UNSPECIFIED" => Some(Self::Unspecified),
            "IDEMPOTENCY_NONE" => Some(Self::None),
            "IDEMPOTENCY_CLIENT_KEY" => Some(Self::ClientKey),
            "IDEMPOTENCY_SERVER_DERIVED" => Some(Self::ServerDerived),
            "IDEMPOTENCY_CAS_ONLY" => Some(Self::CasOnly),
            _ => None,
        }
    }
}

/// Read and write visibility guarantees advertised by an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ConsistencyClass {
    /// No consistency guarantee was supplied; the protobuf zero value.
    Unspecified = 0,
    /// The expected-value check and replacement form one atomic compare-and-set.
    StrongCas = 1,
    /// A caller's subsequent reads observe its completed writes within the stated scope.
    ReadYourWrite = 2,
    /// Reads may lag writes until the underlying projection converges.
    Eventual = 3,
}
impl ConsistencyClass {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "CONSISTENCY_CLASS_UNSPECIFIED",
            Self::StrongCas => "CONSISTENCY_STRONG_CAS",
            Self::ReadYourWrite => "CONSISTENCY_READ_YOUR_WRITE",
            Self::Eventual => "CONSISTENCY_EVENTUAL",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "CONSISTENCY_CLASS_UNSPECIFIED" => Some(Self::Unspecified),
            "CONSISTENCY_STRONG_CAS" => Some(Self::StrongCas),
            "CONSISTENCY_READ_YOUR_WRITE" => Some(Self::ReadYourWrite),
            "CONSISTENCY_EVENTUAL" => Some(Self::Eventual),
            _ => None,
        }
    }
}

/// Availability of an action or stream listed in the descriptor registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ImplementationStatus {
    /// Availability was not supplied; the protobuf zero value.
    Unspecified = 0,
    /// The action or stream has an implementation, subject to admission.
    Implemented = 1,
    /// The contract is discoverable but is not yet executable.
    Planned = 2,
    /// Secret custody requirements prevent execution through this interface.
    BlockedByCustody = 3,
    /// The capability is outside the console's management responsibilities.
    NotConsoleManaged = 4,
}
impl ImplementationStatus {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "IMPLEMENTATION_STATUS_UNSPECIFIED",
            Self::Implemented => "IMPLEMENTED",
            Self::Planned => "PLANNED",
            Self::BlockedByCustody => "BLOCKED_BY_CUSTODY",
            Self::NotConsoleManaged => "NOT_CONSOLE_MANAGED",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "IMPLEMENTATION_STATUS_UNSPECIFIED" => Some(Self::Unspecified),
            "IMPLEMENTED" => Some(Self::Implemented),
            "PLANNED" => Some(Self::Planned),
            "BLOCKED_BY_CUSTODY" => Some(Self::BlockedByCustody),
            "NOT_CONSOLE_MANAGED" => Some(Self::NotConsoleManaged),
            _ => None,
        }
    }
}

/// Data exposure level used when admitting and projecting console operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum VisibilityTier {
    /// No visibility tier was supplied; the protobuf zero value.
    Unspecified = 0,
    /// Control or resource metadata without business payloads.
    Metadata = 1,
    /// Aggregated or redacted data that omits the underlying full payload.
    RedactedSummary = 2,
    /// Business payloads within the caller's admitted scope.
    Payload = 3,
    /// Protected or user-private payloads requiring additional visibility admission.
    ProtectedPayload = 4,
    /// Secret material governed by a separate custody policy.
    Secret = 5,
}
impl VisibilityTier {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "VISIBILITY_TIER_UNSPECIFIED",
            Self::Metadata => "VISIBILITY_METADATA",
            Self::RedactedSummary => "VISIBILITY_REDACTED_SUMMARY",
            Self::Payload => "VISIBILITY_PAYLOAD",
            Self::ProtectedPayload => "VISIBILITY_PROTECTED_PAYLOAD",
            Self::Secret => "VISIBILITY_SECRET",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "VISIBILITY_TIER_UNSPECIFIED" => Some(Self::Unspecified),
            "VISIBILITY_METADATA" => Some(Self::Metadata),
            "VISIBILITY_REDACTED_SUMMARY" => Some(Self::RedactedSummary),
            "VISIBILITY_PAYLOAD" => Some(Self::Payload),
            "VISIBILITY_PROTECTED_PAYLOAD" => Some(Self::ProtectedPayload),
            "VISIBILITY_SECRET" => Some(Self::Secret),
            _ => None,
        }
    }
}

/// Custody classification for secret material exposed by an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SecretClass {
    /// No custody classification was supplied; the protobuf zero value.
    Unspecified = 0,
    /// The action declares no secret material.
    None = 1,
    /// Secret material can be revealed when custody policy permits it.
    Revealable = 2,
    /// Secret material is stored in a form that cannot be recovered for display.
    NonRecoverable = 3,
    /// Secret material is available only at a one-time display edge.
    OneTime = 4,
}
impl SecretClass {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "SECRET_CLASS_UNSPECIFIED",
            Self::None => "SECRET_CLASS_NONE",
            Self::Revealable => "SECRET_CLASS_REVEALABLE",
            Self::NonRecoverable => "SECRET_CLASS_NON_RECOVERABLE",
            Self::OneTime => "SECRET_CLASS_ONE_TIME",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "SECRET_CLASS_UNSPECIFIED" => Some(Self::Unspecified),
            "SECRET_CLASS_NONE" => Some(Self::None),
            "SECRET_CLASS_REVEALABLE" => Some(Self::Revealable),
            "SECRET_CLASS_NON_RECOVERABLE" => Some(Self::NonRecoverable),
            "SECRET_CLASS_ONE_TIME" => Some(Self::OneTime),
            _ => None,
        }
    }
}

/// Field classification for persistence, logging and display policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Sensitivity {
    /// No sensitivity classification was supplied; the protobuf zero value.
    Unspecified = 0,
    /// Data classified for public exposure by its schema.
    Public = 1,
    /// Data intended for internal management use.
    Internal = 2,
    /// Data restricted to explicitly admitted viewers.
    Restricted = 3,
    /// Secret material requiring custody-aware handling.
    Secret = 4,
}
impl Sensitivity {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "SENSITIVITY_UNSPECIFIED",
            Self::Public => "SENSITIVITY_PUBLIC",
            Self::Internal => "SENSITIVITY_INTERNAL",
            Self::Restricted => "SENSITIVITY_RESTRICTED",
            Self::Secret => "SENSITIVITY_SECRET",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "SENSITIVITY_UNSPECIFIED" => Some(Self::Unspecified),
            "SENSITIVITY_PUBLIC" => Some(Self::Public),
            "SENSITIVITY_INTERNAL" => Some(Self::Internal),
            "SENSITIVITY_RESTRICTED" => Some(Self::Restricted),
            "SENSITIVITY_SECRET" => Some(Self::Secret),
            _ => None,
        }
    }
}

/// Special delivery boundary used to display sensitive action results.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum DisplayEdgeKind {
    /// No display-edge policy was supplied; the protobuf zero value.
    Unspecified = 0,
    /// The action uses ordinary result delivery without a special display edge.
    None = 1,
    /// Pairing secret / secret.reveal.
    OneTime = 2,
}
impl DisplayEdgeKind {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "DISPLAY_EDGE_KIND_UNSPECIFIED",
            Self::None => "DISPLAY_EDGE_NONE",
            Self::OneTime => "DISPLAY_EDGE_ONE_TIME",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "DISPLAY_EDGE_KIND_UNSPECIFIED" => Some(Self::Unspecified),
            "DISPLAY_EDGE_NONE" => Some(Self::None),
            "DISPLAY_EDGE_ONE_TIME" => Some(Self::OneTime),
            _ => None,
        }
    }
}

/// Projection policy advertised for action outputs and their retained records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RedactionProfile {
    /// No redaction policy was supplied; the protobuf zero value.
    Unspecified = 0,
    /// No additional redaction is declared by this profile.
    None = 1,
    /// Truncate / aggregate.
    Summary = 2,
    /// Drop payload, keep metadata.
    MetadataOnly = 3,
    /// Never in Fact/outcome, DisplayEdge only.
    Secret = 4,
}
impl RedactionProfile {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "REDACTION_PROFILE_UNSPECIFIED",
            Self::None => "REDACTION_NONE",
            Self::Summary => "REDACTION_SUMMARY",
            Self::MetadataOnly => "REDACTION_METADATA_ONLY",
            Self::Secret => "REDACTION_SECRET",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "REDACTION_PROFILE_UNSPECIFIED" => Some(Self::Unspecified),
            "REDACTION_NONE" => Some(Self::None),
            "REDACTION_SUMMARY" => Some(Self::Summary),
            "REDACTION_METADATA_ONLY" => Some(Self::MetadataOnly),
            "REDACTION_SECRET" => Some(Self::Secret),
            _ => None,
        }
    }
}

/// Event retention and backpressure category advertised for a subscription.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum StreamClass {
    /// No delivery category was supplied; the protobuf zero value.
    Unspecified = 0,
    /// Log-oriented delivery, such as a Fact tail or audit log.
    /// Cursor support is declared separately by `ResumeMode`.
    ReliableLog = 1,
    /// State subscribe (coalesceable).
    StateDiff = 2,
    /// Health / counters (drop-old).
    VolatileSummary = 3,
}
impl StreamClass {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "STREAM_CLASS_UNSPECIFIED",
            Self::ReliableLog => "STREAM_RELIABLE_LOG",
            Self::StateDiff => "STREAM_STATE_DIFF",
            Self::VolatileSummary => "STREAM_VOLATILE_SUMMARY",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "STREAM_CLASS_UNSPECIFIED" => Some(Self::Unspecified),
            "STREAM_RELIABLE_LOG" => Some(Self::ReliableLog),
            "STREAM_STATE_DIFF" => Some(Self::StateDiff),
            "STREAM_VOLATILE_SUMMARY" => Some(Self::VolatileSummary),
            _ => None,
        }
    }
}

/// Recovery mode advertised by a stream; current console streams are live-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ResumeMode {
    /// No recovery contract was supplied; the protobuf zero value.
    Unspecified = 0,
    /// A new subscription starts live without replaying missed events.
    None = 1,
    /// The stream advertises resumption from a retained event cursor.
    Cursor = 2,
    /// The stream advertises a snapshot followed by events from its continuation cursor.
    SnapshotThenCursor = 3,
}
impl ResumeMode {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "RESUME_MODE_UNSPECIFIED",
            Self::None => "RESUME_NONE",
            Self::Cursor => "RESUME_CURSOR",
            Self::SnapshotThenCursor => "RESUME_SNAPSHOT_THEN_CURSOR",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "RESUME_MODE_UNSPECIFIED" => Some(Self::Unspecified),
            "RESUME_NONE" => Some(Self::None),
            "RESUME_CURSOR" => Some(Self::Cursor),
            "RESUME_SNAPSHOT_THEN_CURSOR" => Some(Self::SnapshotThenCursor),
            _ => None,
        }
    }
}

/// Ordering scope advertised by a stream descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum OrderingMode {
    /// No ordering guarantee was supplied; the protobuf zero value.
    Unspecified = 0,
    /// No global order, per-subscription monotonic.
    MonotonicPerSubscription = 1,
}
impl OrderingMode {
    /// Return the exact, stable enum spelling declared in the protobuf schema.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "ORDERING_MODE_UNSPECIFIED",
            Self::MonotonicPerSubscription => "ORDERING_MONOTONIC_PER_SUBSCRIPTION",
        }
    }
    /// Parse an exact protobuf enum spelling, returning `None` for unknown names.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "ORDERING_MODE_UNSPECIFIED" => Some(Self::Unspecified),
            "ORDERING_MONOTONIC_PER_SUBSCRIPTION" => Some(Self::MonotonicPerSubscription),
            _ => None,
        }
    }
}

/// Generated server implementations.
pub mod console_service_server {
    use tonic::codegen::*;
    /// Application implementation of the bidirectional console gRPC service.
    #[async_trait]
    pub trait ConsoleService: std::marker::Send + std::marker::Sync + 'static {
        /// Outbound session frames; a stream error terminates the RPC with a status.
        type SessionStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::ConsoleFrame, tonic::Status>,
            > + std::marker::Send
            + 'static;
        /// Handle one bidirectional `Session` RPC.
        /// The implementation owns protocol negotiation, authentication and dispatch.
        /// Application failures can be sent as `ConsoleError` frames; RPC failures use `Status`.
        async fn session(
            &self,
            request: tonic::Request<tonic::Streaming<super::ConsoleFrame>>,
        ) -> std::result::Result<tonic::Response<Self::SessionStream>, tonic::Status>;
    }
    /// Control-plane gateway service for management consoles.
    #[derive(Debug)]
    pub struct ConsoleServiceServer<T> {
        inner: Arc<T>,
        accept_compression_encodings: EnabledCompressionEncodings,
        send_compression_encodings: EnabledCompressionEncodings,
        max_decoding_message_size: Option<usize>,
        max_encoding_message_size: Option<usize>,
    }
    impl<T> ConsoleServiceServer<T> {
        /// Wrap an owned service with compression disabled and tonic's default size limits.
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        /// Wrap a shared service; cloned servers retain the same application instance.
        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        /// Wrap a service with an interceptor applied to each RPC's metadata.
        /// Interception occurs before dispatch, not separately for each streamed frame.
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        /// Accept request messages compressed with this encoding, in addition to uncompressed ones.
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
        /// Set the byte limit for each incoming frame, including decompressed payloads.
        /// The default is 4 MiB; this does not bound total session traffic or application memory.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
        /// Set the encoded byte limit for each outgoing frame, excluding its gRPC header.
        /// The default is `usize::MAX`; gRPC's message-length bound still applies.
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.max_encoding_message_size = Some(limit);
            self
        }
    }
    impl<T, B> tonic::codegen::Service<http::Request<B>> for ConsoleServiceServer<T>
    where
        T: ConsoleService,
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
                "/xolotl.v1.console.ConsoleService/Session" => {
                    struct SessionSvc<T: ConsoleService>(pub Arc<T>);
                    impl<T: ConsoleService> tonic::server::StreamingService<super::ConsoleFrame> for SessionSvc<T> {
                        type Response = super::ConsoleFrame;
                        type ResponseStream = T::SessionStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<tonic::Streaming<super::ConsoleFrame>>,
                        ) -> Self::Future {
                            let inner = Arc::clone(&self.0);
                            let fut = async move {
                                <T as ConsoleService>::session(&inner, request).await
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
    impl<T> Clone for ConsoleServiceServer<T> {
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
    /// Generated gRPC service name
    pub const SERVICE_NAME: &str = "xolotl.v1.console.ConsoleService";
    impl<T> tonic::server::NamedService for ConsoleServiceServer<T> {
        const NAME: &'static str = SERVICE_NAME;
    }
}
/// Generated client implementations.
pub mod console_service_client {
    use tonic::codegen::http::Uri;
    use tonic::codegen::*;
    /// Client transport for a bidirectional console gRPC session.
    #[derive(Debug, Clone)]
    pub struct ConsoleServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl ConsoleServiceClient<tonic::transport::Channel> {
        /// Connect to a gRPC endpoint and construct a client transport.
        /// Console protocol negotiation and authentication occur through `session` frames.
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }
    impl<T> ConsoleServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        /// Wrap an existing gRPC transport with tonic's default message settings.
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        /// Wrap a transport using the origin's scheme and authority for RPC requests.
        /// Each RPC supplies its own path, so the origin's path and query are ignored.
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
        /// Wrap a transport with an interceptor for each outbound RPC's metadata.
        /// The interceptor does not process individual streamed console frames.
        pub fn with_interceptor<F>(
            inner: T,
            interceptor: F,
        ) -> ConsoleServiceClient<InterceptedService<T, F>>
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
            ConsoleServiceClient::new(InterceptedService::new(inner, interceptor))
        }
        /// Compress request messages with this encoding; the server must accept it.
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        /// Advertise support for responses compressed with this encoding.
        /// The server may still send uncompressed response messages.
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        /// Set the byte limit for each received frame, including decompressed payloads.
        /// The default is 4 MiB; the limit applies per frame rather than per session.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        /// Set the encoded byte limit for each sent frame, excluding its gRPC header.
        /// The default is `usize::MAX`; gRPC's message-length bound still applies.
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
        /// Open the bidirectional `Session` RPC with a caller-provided frame stream.
        /// The caller sends handshake, authentication and request frames, and consumes
        /// correlated replies and events. Protocol errors arrive as `ConsoleError` frames;
        /// transport and RPC failures are reported through `tonic::Status`.
        pub async fn session(
            &mut self,
            request: impl tonic::IntoStreamingRequest<Message = super::ConsoleFrame>,
        ) -> std::result::Result<
            tonic::Response<tonic::codec::Streaming<super::ConsoleFrame>>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path =
                http::uri::PathAndQuery::from_static("/xolotl.v1.console.ConsoleService/Session");
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "xolotl.v1.console.ConsoleService",
                "Session",
            ));
            self.inner.streaming(req, path, codec).await
        }
    }
}
