// @generated — hand-maintained to match `tonic-prost-build` output for
// `proto/xolotl/v1/console.proto` (package `xolotl.v1.console`). `include!`d
// into the `xolotl::v1::console` module. Keep in sync with the `.proto` spec.

/// Top-level frame envelope.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsoleFrame {
    #[prost(oneof = "console_frame::Frame", tags = "1, 2, 3, 4, 5, 6, 11, 12, 13, 14, 15, 16")]
    pub frame: ::core::option::Option<console_frame::Frame>,
}
/// Nested message and enum types in `ConsoleFrame`.
pub mod console_frame {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Frame {
        #[prost(message, tag = "1")]
        Hello(super::ClientHello),
        /// Opaque bearer session token.
        #[prost(bytes, tag = "2")]
        AuthToken(::prost::alloc::vec::Vec<u8>),
        #[prost(message, tag = "3")]
        Call(super::ActionCall),
        #[prost(message, tag = "4")]
        Subscribe(super::StreamCall),
        /// Subscription id.
        #[prost(uint64, tag = "5")]
        Unsubscribe(u64),
        /// Nonce.
        #[prost(uint64, tag = "6")]
        Ping(u64),
        #[prost(message, tag = "11")]
        HelloAccepted(super::HelloAccepted),
        #[prost(message, tag = "12")]
        Authenticated(super::Authenticated),
        #[prost(message, tag = "13")]
        Reply(super::Reply),
        #[prost(message, tag = "14")]
        Event(super::Event),
        /// Echoes ping.
        #[prost(uint64, tag = "15")]
        Pong(u64),
        #[prost(message, tag = "16")]
        Error(super::ConsoleError),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientHello {
    /// Must equal CONSOLE_PROTOCOL_VERSION.
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    /// Optional human-readable client id.
    #[prost(string, tag = "2")]
    pub client_name: ::prost::alloc::string::String,
    /// Accepted wire encodings.
    #[prost(string, repeated, tag = "3")]
    pub accepted_encodings: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// Client's last-known descriptor rev.
    #[prost(uint64, optional, tag = "4")]
    pub registry_rev: ::core::option::Option<u64>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct HelloAccepted {
    #[prost(message, optional, tag = "1")]
    pub metadata: ::core::option::Option<ProtocolMetadata>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Authenticated {
    #[prost(message, optional, tag = "1")]
    pub principal: ::core::option::Option<PrincipalSummary>,
    #[prost(message, optional, tag = "2")]
    pub metadata: ::core::option::Option<ProtocolMetadata>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProtocolMetadata {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    /// "xolotl-console".
    #[prost(string, tag = "2")]
    pub server_name: ::prost::alloc::string::String,
    /// "protobuf+xolotl-console-v1".
    #[prost(string, tag = "3")]
    pub wire_encoding: ::prost::alloc::string::String,
    /// Fact cursor (advances on every Fact).
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

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PrincipalSummary {
    #[prost(string, tag = "1")]
    pub username: ::prost::alloc::string::String,
    /// identity://console/<user>.
    #[prost(string, tag = "2")]
    pub identity_path: ::prost::alloc::string::String,
    /// 1 = single-factor, 2 = verified.
    #[prost(uint32, tag = "3")]
    pub mfa_level: u32,
    /// Effective kernel capability selectors (redacted summary).
    #[prost(string, repeated, tag = "4")]
    pub grants: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}

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
    /// Action input.
    #[prost(message, optional, tag = "4")]
    pub input: ::core::option::Option<super::Value>,
    /// Visibility scope.
    #[prost(string, optional, tag = "5")]
    pub scope: ::core::option::Option<::prost::alloc::string::String>,
    /// Visibility justification.
    #[prost(string, optional, tag = "6")]
    pub justification: ::core::option::Option<::prost::alloc::string::String>,
    /// Visibility TTL.
    #[prost(uint64, optional, tag = "7")]
    pub ttl_ms: ::core::option::Option<u64>,
    /// Client's descriptor rev (RegistryChanged detection).
    #[prost(uint64, optional, tag = "8")]
    pub registry_rev: ::core::option::Option<u64>,
    /// Client-supplied idempotency key.
    #[prost(string, optional, tag = "9")]
    pub idempotency_key: ::core::option::Option<::prost::alloc::string::String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamCall {
    /// Subscription id.
    #[prost(uint64, tag = "1")]
    pub id: u64,
    /// Stream id, e.g. "state.diff".
    #[prost(string, tag = "2")]
    pub stream: ::prost::alloc::string::String,
    /// Stream input / filter.
    #[prost(message, optional, tag = "3")]
    pub input: ::core::option::Option<super::Value>,
    #[prost(string, optional, tag = "4")]
    pub scope: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "5")]
    pub justification: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(uint64, optional, tag = "6")]
    pub ttl_ms: ::core::option::Option<u64>,
    /// Resume cursor (state_rev or fact_cursor).
    #[prost(uint64, optional, tag = "7")]
    pub since_rev: ::core::option::Option<u64>,
    /// Max events per server flush.
    #[prost(uint32, optional, tag = "8")]
    pub max_batch: ::core::option::Option<u32>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Reply {
    /// Echoes ActionCall.id.
    #[prost(uint64, tag = "1")]
    pub id: u64,
    #[prost(message, optional, tag = "2")]
    pub result: ::core::option::Option<ActionResult>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActionResult {
    /// Action output.
    #[prost(message, optional, tag = "1")]
    pub output: ::core::option::Option<super::Value>,
    /// Fact cursor after this action.
    #[prost(uint64, tag = "2")]
    pub server_rev: u64,
    /// Descriptor registry revision.
    #[prost(uint64, optional, tag = "3")]
    pub registry_rev: ::core::option::Option<u64>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Event {
    /// Subscription id.
    #[prost(uint64, tag = "1")]
    pub stream: u64,
    #[prost(message, optional, tag = "2")]
    pub event: ::core::option::Option<ConsoleEvent>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsoleEvent {
    #[prost(oneof = "console_event::Kind", tags = "1, 2, 3, 4, 5, 6")]
    pub kind: ::core::option::Option<console_event::Kind>,
    /// Per-subscription monotonic cursor.
    #[prost(uint64, tag = "10")]
    pub state_rev: u64,
    /// ReliableLog resume cursor.
    #[prost(uint64, tag = "11")]
    pub fact_cursor: u64,
    /// True if events were merged under backpressure.
    #[prost(bool, tag = "12")]
    pub coalesced: bool,
}
/// Nested message and enum types in `ConsoleEvent`.
pub mod console_event {
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Kind {
        #[prost(message, tag = "1")]
        StateSet(super::StateSet),
        #[prost(message, tag = "2")]
        StateAppend(super::StateAppend),
        #[prost(message, tag = "3")]
        StateDelete(super::StateDelete),
        #[prost(message, tag = "4")]
        Fact(super::FactEvent),
        /// VolatileSummary coalesced.
        #[prost(message, tag = "5")]
        Summary(super::Summary),
        #[prost(message, tag = "6")]
        Closed(super::SubscriptionClosed),
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateSet {
    #[prost(message, optional, tag = "1")]
    pub path: ::core::option::Option<super::Path>,
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<super::Value>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateAppend {
    #[prost(message, optional, tag = "1")]
    pub path: ::core::option::Option<super::Path>,
    #[prost(message, optional, tag = "2")]
    pub item: ::core::option::Option<super::Value>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StateDelete {
    #[prost(message, optional, tag = "1")]
    pub path: ::core::option::Option<super::Path>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FactEvent {
    /// Projected Fact (redacted per visibility tier).
    #[prost(message, optional, tag = "1")]
    pub fact: ::core::option::Option<super::Value>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Summary {
    /// Coalesced volatile summary value.
    #[prost(message, optional, tag = "1")]
    pub payload: ::core::option::Option<super::Value>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SubscriptionClosed {
    #[prost(string, tag = "1")]
    pub reason: ::prost::alloc::string::String,
    /// Last cursor delivered (for replay).
    #[prost(uint64, optional, tag = "2")]
    pub last_rev: ::core::option::Option<u64>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsoleError {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ConsoleErrorCode {
    Unspecified = 0,
    Unauthenticated = 1,
    Forbidden = 2,
    StepUpRequired = 3,
    RateLimited = 4,
    ValidationFailed = 5,
    AdmissionRejected = 6,
    VersionConflict = 7,
    NotFound = 8,
    RegistryChanged = 9,
    ReplayRequired = 10,
    VisibilityRequired = 11,
    IndexUnavailable = 12,
    PayloadTooLarge = 13,
    Backpressure = 14,
    UnsupportedVersion = 15,
    Internal = 16,
}
impl ConsoleErrorCode {
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

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActionDescriptor {
    /// "config.write_cas".
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    /// Compact fast-path code.
    #[prost(uint32, optional, tag = "2")]
    pub code: ::core::option::Option<u32>,
    /// "config".
    #[prost(string, tag = "3")]
    pub domain: ::prost::alloc::string::String,
    /// Descriptor schema version.
    #[prost(uint32, tag = "4")]
    pub version: u32,
    #[prost(enumeration = "Stability", tag = "5")]
    pub stability: i32,
    #[prost(message, optional, tag = "6")]
    pub input: ::core::option::Option<SchemaDescriptor>,
    #[prost(message, optional, tag = "7")]
    pub output: ::core::option::Option<SchemaDescriptor>,
    /// Kernel capability selectors.
    #[prost(string, repeated, tag = "8")]
    pub required_grants: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(uint32, tag = "9")]
    pub required_mfa_level: u32,
    #[prost(enumeration = "RiskLevel", tag = "10")]
    pub risk: i32,
    #[prost(enumeration = "IdempotencyClass", tag = "11")]
    pub idempotency: i32,
    #[prost(enumeration = "ConsistencyClass", tag = "12")]
    pub consistency: i32,
    #[prost(string, optional, tag = "13")]
    pub audit_tag: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(enumeration = "RedactionProfile", tag = "14")]
    pub redaction: i32,
    #[prost(enumeration = "DisplayEdgeKind", optional, tag = "15")]
    pub display_edge: ::core::option::Option<i32>,
    #[prost(enumeration = "RecipeKind", tag = "16")]
    pub recipe_kind: i32,
    #[prost(message, optional, tag = "17")]
    pub pagination: ::core::option::Option<PaginationSpec>,
    /// Stream ids this action can emit on.
    #[prost(string, repeated, tag = "18")]
    pub stream_emits: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(enumeration = "ImplementationStatus", tag = "19")]
    pub status: i32,
    #[prost(enumeration = "VisibilityTier", tag = "20")]
    pub visibility: i32,
    #[prost(enumeration = "SecretClass", optional, tag = "21")]
    pub secret_class: ::core::option::Option<i32>,
    #[prost(bool, tag = "22")]
    pub requires_step_up: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamDescriptor {
    /// "state.diff".
    #[prost(string, tag = "1")]
    pub id: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub domain: ::prost::alloc::string::String,
    #[prost(enumeration = "ImplementationStatus", tag = "3")]
    pub status: i32,
    #[prost(enumeration = "VisibilityTier", tag = "4")]
    pub visibility: i32,
    #[prost(bool, tag = "5")]
    pub requires_step_up: bool,
    /// Kernel capability selectors.
    #[prost(string, repeated, tag = "6")]
    pub required_grants: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "7")]
    pub input: ::core::option::Option<SchemaDescriptor>,
    #[prost(message, optional, tag = "8")]
    pub event: ::core::option::Option<SchemaDescriptor>,
    /// ReliableLog / StateDiff / VolatileSummary.
    #[prost(enumeration = "StreamClass", tag = "9")]
    pub class: i32,
    /// Resume semantics.
    #[prost(enumeration = "ResumeMode", tag = "10")]
    pub resume: i32,
    /// Monotonicity guarantee.
    #[prost(enumeration = "OrderingMode", tag = "11")]
    pub ordering: i32,
    #[prost(uint32, optional, tag = "12")]
    pub default_max_batch: ::core::option::Option<u32>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SchemaDescriptor {
    #[prost(string, tag = "1")]
    pub schema_id: ::prost::alloc::string::String,
    /// "map" / "list" / "string" / ...
    #[prost(string, tag = "2")]
    pub value_kind: ::prost::alloc::string::String,
    #[prost(message, repeated, tag = "3")]
    pub fields: ::prost::alloc::vec::Vec<FieldDescriptor>,
    #[prost(string, repeated, tag = "4")]
    pub notes: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FieldDescriptor {
    #[prost(string, tag = "1")]
    pub name: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub kind: ::prost::alloc::string::String,
    #[prost(bool, tag = "3")]
    pub required: bool,
    #[prost(string, optional, tag = "4")]
    pub stable_id: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "5")]
    pub semantic_kind: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "6")]
    pub ref_target_type: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(enumeration = "Sensitivity", tag = "7")]
    pub sensitivity: i32,
    #[prost(bool, tag = "8")]
    pub read_only: bool,
    #[prost(bool, tag = "9")]
    pub computed: bool,
    #[prost(bool, tag = "10")]
    pub deprecated: bool,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PaginationSpec {
    /// "offset" / "rev" / "cursor".
    #[prost(string, tag = "1")]
    pub cursor_kind: ::prost::alloc::string::String,
    #[prost(uint32, tag = "2")]
    pub default_limit: u32,
    #[prost(uint32, tag = "3")]
    pub max_limit: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RecipeKind {
    Unspecified = 0,
    StateRead = 1,
    StateList = 2,
    StateWriteCas = 3,
    StateAppend = 4,
    StateDelete = 5,
    EffectInvoke = 6,
    FactRead = 7,
    FactTail = 8,
    Subscribe = 9,
    Inspect = 10,
    Composite = 11,
    DisplayEdge = 12,
}
impl RecipeKind {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Stability {
    Unspecified = 0,
    Experimental = 1,
    Beta = 2,
    Stable = 3,
    Deprecated = 4,
}
impl Stability {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "STABILITY_UNSPECIFIED",
            Self::Experimental => "STABILITY_EXPERIMENTAL",
            Self::Beta => "STABILITY_BETA",
            Self::Stable => "STABILITY_STABLE",
            Self::Deprecated => "STABILITY_DEPRECATED",
        }
    }
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "STABILITY_UNSPECIFIED" => Some(Self::Unspecified),
            "STABILITY_EXPERIMENTAL" => Some(Self::Experimental),
            "STABILITY_BETA" => Some(Self::Beta),
            "STABILITY_STABLE" => Some(Self::Stable),
            "STABILITY_DEPRECATED" => Some(Self::Deprecated),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RiskLevel {
    Unspecified = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    BreakGlass = 4,
}
impl RiskLevel {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "RISK_LEVEL_UNSPECIFIED",
            Self::Low => "RISK_LEVEL_LOW",
            Self::Medium => "RISK_LEVEL_MEDIUM",
            Self::High => "RISK_LEVEL_HIGH",
            Self::BreakGlass => "RISK_LEVEL_BREAK_GLASS",
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum IdempotencyClass {
    Unspecified = 0,
    None = 1,
    ClientKey = 2,
    ServerDerived = 3,
    CasOnly = 4,
}
impl IdempotencyClass {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "IDEMPOTENCY_CLASS_UNSPECIFIED",
            Self::None => "IDEMPOTENCY_NONE",
            Self::ClientKey => "IDEMPOTENCY_CLIENT_KEY",
            Self::ServerDerived => "IDEMPOTENCY_SERVER_DERIVED",
            Self::CasOnly => "IDEMPOTENCY_CAS_ONLY",
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ConsistencyClass {
    Unspecified = 0,
    StrongCas = 1,
    ReadYourWrite = 2,
    Eventual = 3,
}
impl ConsistencyClass {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "CONSISTENCY_CLASS_UNSPECIFIED",
            Self::StrongCas => "CONSISTENCY_STRONG_CAS",
            Self::ReadYourWrite => "CONSISTENCY_READ_YOUR_WRITE",
            Self::Eventual => "CONSISTENCY_EVENTUAL",
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ImplementationStatus {
    Unspecified = 0,
    Implemented = 1,
    Planned = 2,
    BlockedByCustody = 3,
    NotConsoleManaged = 4,
}
impl ImplementationStatus {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "IMPLEMENTATION_STATUS_UNSPECIFIED",
            Self::Implemented => "IMPLEMENTED",
            Self::Planned => "PLANNED",
            Self::BlockedByCustody => "BLOCKED_BY_CUSTODY",
            Self::NotConsoleManaged => "NOT_CONSOLE_MANAGED",
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum VisibilityTier {
    Unspecified = 0,
    Metadata = 1,
    RedactedSummary = 2,
    Payload = 3,
    ProtectedPayload = 4,
    Secret = 5,
}
impl VisibilityTier {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum SecretClass {
    Unspecified = 0,
    None = 1,
    Revealable = 2,
    NonRecoverable = 3,
    OneTime = 4,
}
impl SecretClass {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "SECRET_CLASS_UNSPECIFIED",
            Self::None => "SECRET_CLASS_NONE",
            Self::Revealable => "SECRET_CLASS_REVEALABLE",
            Self::NonRecoverable => "SECRET_CLASS_NON_RECOVERABLE",
            Self::OneTime => "SECRET_CLASS_ONE_TIME",
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum Sensitivity {
    Unspecified = 0,
    Public = 1,
    Internal = 2,
    Restricted = 3,
    Secret = 4,
}
impl Sensitivity {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "SENSITIVITY_UNSPECIFIED",
            Self::Public => "SENSITIVITY_PUBLIC",
            Self::Internal => "SENSITIVITY_INTERNAL",
            Self::Restricted => "SENSITIVITY_RESTRICTED",
            Self::Secret => "SENSITIVITY_SECRET",
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum DisplayEdgeKind {
    Unspecified = 0,
    None = 1,
    /// Pairing secret / secret.reveal.
    OneTime = 2,
}
impl DisplayEdgeKind {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "DISPLAY_EDGE_KIND_UNSPECIFIED",
            Self::None => "DISPLAY_EDGE_NONE",
            Self::OneTime => "DISPLAY_EDGE_ONE_TIME",
        }
    }
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "DISPLAY_EDGE_KIND_UNSPECIFIED" => Some(Self::Unspecified),
            "DISPLAY_EDGE_NONE" => Some(Self::None),
            "DISPLAY_EDGE_ONE_TIME" => Some(Self::OneTime),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum RedactionProfile {
    Unspecified = 0,
    None = 1,
    /// Truncate / aggregate.
    Summary = 2,
    /// Drop payload, keep metadata.
    MetadataOnly = 3,
    /// Never in Fact/outcome, DisplayEdge only.
    Secret = 4,
}
impl RedactionProfile {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "REDACTION_PROFILE_UNSPECIFIED",
            Self::None => "REDACTION_NONE",
            Self::Summary => "REDACTION_SUMMARY",
            Self::MetadataOnly => "REDACTION_METADATA_ONLY",
            Self::Secret => "REDACTION_SECRET",
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum StreamClass {
    Unspecified = 0,
    /// Fact tail / audit log (resumable by cursor).
    ReliableLog = 1,
    /// State subscribe (coalesceable).
    StateDiff = 2,
    /// Health / counters (drop-old).
    VolatileSummary = 3,
}
impl StreamClass {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "STREAM_CLASS_UNSPECIFIED",
            Self::ReliableLog => "STREAM_RELIABLE_LOG",
            Self::StateDiff => "STREAM_STATE_DIFF",
            Self::VolatileSummary => "STREAM_VOLATILE_SUMMARY",
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum ResumeMode {
    Unspecified = 0,
    None = 1,
    Cursor = 2,
    SnapshotThenCursor = 3,
}
impl ResumeMode {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "RESUME_MODE_UNSPECIFIED",
            Self::None => "RESUME_NONE",
            Self::Cursor => "RESUME_CURSOR",
            Self::SnapshotThenCursor => "RESUME_SNAPSHOT_THEN_CURSOR",
        }
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum OrderingMode {
    Unspecified = 0,
    /// No global order, per-subscription monotonic.
    MonotonicPerSubscription = 1,
}
impl OrderingMode {
    pub fn as_str_name(&self) -> &'static str {
        match self {
            Self::Unspecified => "ORDERING_MODE_UNSPECIFIED",
            Self::MonotonicPerSubscription => "ORDERING_MONOTONIC_PER_SUBSCRIPTION",
        }
    }
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
    /// Generated trait containing gRPC methods for ConsoleServiceServer.
    #[async_trait]
    pub trait ConsoleService: std::marker::Send + std::marker::Sync + 'static {
        /// Server streaming response type for the Session method.
        type SessionStream: tonic::codegen::tokio_stream::Stream<
                Item = std::result::Result<super::ConsoleFrame, tonic::Status>,
            > + std::marker::Send
            + 'static;
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
        pub fn new(inner: T) -> Self {
            Self::from_arc(Arc::new(inner))
        }
        pub fn from_arc(inner: Arc<T>) -> Self {
            Self {
                inner,
                accept_compression_encodings: Default::default(),
                send_compression_encodings: Default::default(),
                max_decoding_message_size: None,
                max_encoding_message_size: None,
            }
        }
        pub fn with_interceptor<F>(inner: T, interceptor: F) -> InterceptedService<Self, F>
        where
            F: tonic::service::Interceptor,
        {
            InterceptedService::new(Self::new(inner), interceptor)
        }
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.accept_compression_encodings.enable(encoding);
            self
        }
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.send_compression_encodings.enable(encoding);
            self
        }
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.max_decoding_message_size = Some(limit);
            self
        }
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
                    impl<T: ConsoleService>
                        tonic::server::StreamingService<super::ConsoleFrame> for SessionSvc<T>
                    {
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
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;
    /// ConsoleService client.
    #[derive(Debug, Clone)]
    pub struct ConsoleServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }
    impl ConsoleServiceClient<tonic::transport::Channel> {
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
    impl<T> ConsoleServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }
        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }
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
        #[must_use]
        pub fn send_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.send_compressed(encoding);
            self
        }
        #[must_use]
        pub fn accept_compressed(mut self, encoding: CompressionEncoding) -> Self {
            self.inner = self.inner.accept_compressed(encoding);
            self
        }
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }
        #[must_use]
        pub fn max_encoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_encoding_message_size(limit);
            self
        }
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
            let path = http::uri::PathAndQuery::from_static(
                "/xolotl.v1.console.ConsoleService/Session",
            );
            let mut req = request.into_streaming_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "xolotl.v1.console.ConsoleService",
                "Session",
            ));
            self.inner.streaming(req, path, codec).await
        }
    }
}
