//! Console Protocol DTOs and static registry descriptors.
//!
//! `nexus-console` is the control-plane protocol host. Web UI and third-party
//! panels consume this registry, then issue descriptor-named actions. The
//! descriptor registry is the public protocol surface.

use nexus_types::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current Console Protocol major wire version.
pub const PROTOCOL_VERSION: u16 = 1;
/// Canonical server name returned in protocol metadata.
pub const SERVER_NAME: &str = "nexus-console";
/// Default compact frame encoding advertised by the server.
pub const WIRE_ENCODING: &str = "msgpack+nexus-console-v1";

/// Describe protocol metadata and descriptors.
pub const ACTION_PROTOCOL_DESCRIBE: &str = "protocol.describe";
/// Return a registry snapshot for clients that cache descriptors.
pub const ACTION_PROTOCOL_REGISTRY_SNAPSHOT: &str = "protocol.registry.snapshot";
/// Return one action descriptor by action id.
pub const ACTION_PROTOCOL_SCHEMA_GET: &str = "protocol.schema.get";
/// Return one action descriptor by action id.
pub const ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET: &str = "protocol.action_descriptor.get";
/// Return action/stream coverage status by domain.
pub const ACTION_REGISTRY_COVERAGE_REPORT: &str = "registry.coverage.report";
/// List resource types with semantic edit descriptors.
pub const ACTION_RESOURCE_TYPE_LIST: &str = "resource.type.list";
/// Describe one resource type for schema-driven clients.
pub const ACTION_RESOURCE_TYPE_DESCRIBE: &str = "resource.type.describe";
/// Describe one resource view for tables, pickers, timelines, and graph projections.
pub const ACTION_RESOURCE_VIEW_DESCRIBE: &str = "resource.view.describe";
/// Create a semantic change-set draft.
pub const ACTION_CHANGE_SET_CREATE: &str = "change_set.create";
/// Update a semantic change-set draft.
pub const ACTION_CHANGE_SET_UPDATE: &str = "change_set.update";
/// Validate a semantic change-set draft.
pub const ACTION_CHANGE_SET_VALIDATE: &str = "change_set.validate";
/// Return the redacted diff for a semantic change-set draft.
pub const ACTION_CHANGE_SET_DIFF: &str = "change_set.diff";
/// Dry-run a semantic change-set draft.
pub const ACTION_CHANGE_SET_DRY_RUN: &str = "change_set.dry_run";
/// Apply a semantic change-set draft.
pub const ACTION_CHANGE_SET_APPLY: &str = "change_set.apply";
/// Discard a semantic change-set draft.
pub const ACTION_CHANGE_SET_DISCARD: &str = "change_set.discard";
/// Describe one graph type for semantic graph projections.
pub const ACTION_GRAPH_TYPE_DESCRIBE: &str = "graph.type.describe";
/// Return the caller's effective principal and authority.
pub const ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE: &str = "authority.principal.effective";
/// Return the authority matrix for visible actions.
pub const ACTION_AUTHORITY_ACTION_MATRIX: &str = "authority.action.matrix";
/// Explain resource access for one target.
pub const ACTION_AUTHORITY_RESOURCE_ACCESS: &str = "authority.resource.access";
/// Explain why an action or resource operation was denied.
pub const ACTION_AUTHORITY_WHY_DENIED: &str = "authority.why_denied";
/// Describe root data authority and visibility rules.
pub const ACTION_VISIBILITY_AUTHORITY_DESCRIBE: &str = "visibility.authority.describe";
/// Read a state value through visibility gates.
pub const ACTION_VISIBILITY_STATE_READ: &str = "visibility.state.read";
/// List state children through visibility gates.
pub const ACTION_VISIBILITY_STATE_LIST: &str = "visibility.state.list";
/// Return secret custody catalog metadata.
pub const ACTION_SECRET_CATALOG: &str = "secret.catalog";
/// Reveal a revealable secret through custody gates.
pub const ACTION_SECRET_REVEAL: &str = "secret.reveal";
/// Return a state snapshot view.
pub const ACTION_STATE_SNAPSHOT: &str = "state.snapshot";
/// Read one configuration value.
pub const ACTION_CONFIG_READ: &str = "config.read";
/// List configuration entries.
pub const ACTION_CONFIG_LIST: &str = "config.list";
/// Compare-and-swap a configuration value.
pub const ACTION_CONFIG_WRITE_CAS: &str = "config.write_cas";
/// Read one console user record.
pub const ACTION_ACCESS_USER_READ: &str = "access.user.read";
/// List console user records.
pub const ACTION_ACCESS_USER_LIST: &str = "access.user.list";
/// Compare-and-swap a console user record.
pub const ACTION_ACCESS_USER_WRITE_CAS: &str = "access.user.write_cas";
/// Disable a console user.
pub const ACTION_ACCESS_USER_DISABLE: &str = "access.user.disable";
/// Read one console role record.
pub const ACTION_ACCESS_ROLE_READ: &str = "access.role.read";
/// List console role records.
pub const ACTION_ACCESS_ROLE_LIST: &str = "access.role.list";
/// Compare-and-swap a console role record.
pub const ACTION_ACCESS_ROLE_WRITE_CAS: &str = "access.role.write_cas";
/// Logout the current session.
pub const ACTION_ACCESS_SESSION_CURRENT_LOGOUT: &str = "access.session.current.logout";
/// List console sessions visible to the caller.
pub const ACTION_ACCESS_SESSION_LIST: &str = "access.session.list";
/// Revoke one console session.
pub const ACTION_ACCESS_SESSION_REVOKE: &str = "access.session.revoke";
/// Revoke all sessions for one user.
pub const ACTION_ACCESS_SESSION_REVOKE_USER: &str = "access.session.revoke_user";
/// Inspect one runtime process.
pub const ACTION_RUNTIME_PROCESS_INSPECT: &str = "runtime.process.inspect";
/// Return recent audit facts.
pub const ACTION_AUDIT_FACTS_RECENT: &str = "audit.facts.recent";
/// Read trace lineage data.
pub const ACTION_LINEAGE_TRACE_READ: &str = "lineage.trace.read";
/// Read one Fact by id.
pub const ACTION_LINEAGE_FACT_READ: &str = "lineage.fact.read";
/// Read a Fact by operation id.
pub const ACTION_LINEAGE_FACT_BY_OPERATION: &str = "lineage.fact.by_operation";
/// Return high-level daemon/runtime health.
pub const ACTION_HEALTH_SUMMARY: &str = "health.summary";
/// Install an external installation descriptor.
pub const ACTION_EXTERNAL_INSTALLATION_INSTALL: &str = "external.installation.install";
/// Update an external installation descriptor.
pub const ACTION_EXTERNAL_INSTALLATION_UPDATE: &str = "external.installation.update";
/// Start an external installation.
pub const ACTION_EXTERNAL_INSTALLATION_START: &str = "external.installation.start";
/// Stop a running external installation.
pub const ACTION_EXTERNAL_INSTALLATION_STOP: &str = "external.installation.stop";
/// Revoke an external installation and its projected authority.
pub const ACTION_EXTERNAL_INSTALLATION_REVOKE: &str = "external.installation.revoke";
/// Create a pairing flow.
pub const ACTION_PAIRING_CREATE: &str = "pairing.create";
/// Approve a pending pairing flow.
pub const ACTION_PAIRING_APPROVE: &str = "pairing.approve";
/// Deny a pending pairing flow.
pub const ACTION_PAIRING_DENY: &str = "pairing.deny";
/// Replace pairing credentials.
pub const ACTION_PAIRING_REPLACE: &str = "pairing.replace";

/// Stream id for state watch events.
pub const STREAM_STATE_WATCH: &str = "state.watch";
/// Stream id for audit Fact events.
pub const STREAM_AUDIT_FACTS: &str = "audit.facts.stream";

/// Initial client hello used to negotiate protocol version and encoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientHello {
    /// Client-supported protocol version.
    pub protocol_version: u16,
    /// Optional client application name for audit and diagnostics.
    #[serde(default)]
    pub client_name: Option<String>,
    /// Encodings the client accepts, in preference order.
    #[serde(default)]
    pub accepted_encodings: Vec<String>,
}

impl Default for ClientHello {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            client_name: None,
            accepted_encodings: vec![WIRE_ENCODING.into()],
        }
    }
}

/// One descriptor-named action invocation from a console client.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionCall {
    /// Action id, usually one of the `ACTION_*` constants.
    pub action: String,
    /// JSON-encoded Nexus value passed as action input.
    #[serde(default)]
    pub input: JsonBytes,
    /// Optional target scope for break-glass or visibility-gated actions.
    #[serde(default)]
    pub scope: Option<String>,
    /// Operator justification for high-risk actions.
    #[serde(default)]
    pub justification: Option<String>,
    /// Optional temporary authority duration for scoped access.
    #[serde(default)]
    pub ttl_ms: Option<u64>,
}

/// One stream subscription request from a console client.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StreamCall {
    /// Stream id, usually one of the `STREAM_*` constants.
    pub stream: String,
    /// JSON-encoded stream input/filter value.
    #[serde(default)]
    pub input: JsonBytes,
    /// Optional target scope for visibility-gated streams.
    #[serde(default)]
    pub scope: Option<String>,
    /// Operator justification for sensitive streams.
    #[serde(default)]
    pub justification: Option<String>,
    /// Optional temporary authority duration for scoped streaming.
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    /// Reserved revision cursor; current console streams are live-only.
    #[serde(default)]
    pub since_rev: Option<u64>,
}

/// Compact identity summary returned after authentication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrincipalSummary {
    /// Console username.
    pub username: String,
    /// Nexus identity path for the principal.
    pub identity_path: String,
    /// Authenticated MFA level.
    pub mfa_level: u8,
}

/// Frames sent by the console client over the management WebSocket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ClientFrame {
    /// Protocol negotiation frame.
    Hello {
        /// Client protocol preferences.
        hello: ClientHello,
    },
    /// Present a bearer session token.
    Auth {
        /// Console session token.
        token: String,
    },
    /// Invoke one action.
    Call {
        /// Client-chosen correlation id.
        id: u64,
        /// Action invocation payload.
        call: ActionCall,
    },
    /// Subscribe to one stream.
    Subscribe {
        /// Client-chosen subscription id.
        id: u64,
        /// Stream subscription payload.
        stream: StreamCall,
    },
    /// Cancel an existing subscription.
    Unsubscribe {
        /// Subscription id to cancel.
        id: u64,
    },
    /// Keepalive probe.
    Ping {
        /// Client nonce echoed by the server.
        nonce: u64,
    },
}

/// JSON-encoded [`Value`] string. The outer frame is MessagePack; this inner
/// value envelope keeps Nexus's untagged `Value` representation explicit for
/// clients in any language.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonBytes(
    /// JSON string encoding a Nexus [`Value`].
    pub String,
);

impl Eq for JsonBytes {}

impl Default for JsonBytes {
    fn default() -> Self {
        Self::from_value(&Value::Null)
    }
}

impl JsonBytes {
    /// Serialize a Nexus value into the inner JSON string.
    pub fn from_value(v: &Value) -> Self {
        Self(serde_json::to_string(v).unwrap_or_default())
    }

    /// Decode the inner JSON string into a Nexus value.
    pub fn try_to_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::from_str(&self.0)
    }

    /// Decode the inner JSON string, returning [`Value::Null`] on malformed
    /// input for tolerant projection paths.
    pub fn to_value(&self) -> Value {
        self.try_to_value().unwrap_or(Value::Null)
    }
}

/// Result of one action invocation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionResult {
    /// Optional JSON-encoded Nexus value output.
    pub output: Option<JsonBytes>,
    /// Server revision after the action.
    pub server_rev: u64,
}

impl ActionResult {
    /// Construct an action result with no output body.
    pub fn empty(server_rev: u64) -> Self {
        Self {
            output: None,
            server_rev,
        }
    }

    /// Construct an action result carrying one Nexus value.
    pub fn value(value: Value, server_rev: u64) -> Self {
        Self {
            output: Some(JsonBytes::from_value(&value)),
            server_rev,
        }
    }
}

/// Frames sent by the console server over the management WebSocket.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ServerFrame {
    /// Protocol negotiation succeeded.
    HelloAccepted {
        /// Server metadata and descriptor registry.
        metadata: ProtocolMetadata,
    },
    /// Authentication succeeded.
    Authenticated {
        /// Authenticated principal summary.
        principal: PrincipalSummary,
        /// Server metadata and descriptor registry.
        metadata: ProtocolMetadata,
    },
    /// Reply to an action call.
    Reply {
        /// Client correlation id.
        id: u64,
        /// Action result.
        result: ActionResult,
    },
    /// Stream event delivery.
    Event {
        /// Subscription id.
        stream: u64,
        /// Event payload.
        event: ConsoleEvent,
    },
    /// Keepalive response.
    Pong {
        /// Echoed client nonce.
        nonce: u64,
    },
    /// Protocol or action error.
    Error {
        /// Optional client correlation id.
        id: Option<u64>,
        /// Stable error code.
        code: ConsoleErrorCode,
        /// Human-readable error message.
        message: String,
    },
}

/// Event delivered on a subscribed console stream.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ConsoleEvent {
    /// A state value was set.
    StateSet {
        /// State path that changed.
        path: String,
        /// New JSON-encoded value.
        value: JsonBytes,
    },
    /// An item was appended to a state sequence.
    StateAppend {
        /// State sequence path that changed.
        path: String,
        /// Appended JSON-encoded item.
        item: JsonBytes,
    },
    /// A state value was deleted.
    StateDelete {
        /// State path that was deleted.
        path: String,
    },
    /// An audit Fact event was observed.
    Audit {
        /// JSON-encoded Fact projection.
        fact: JsonBytes,
    },
    /// Server closed the subscription.
    SubscriptionClosed {
        /// Closure reason.
        reason: String,
    },
}

impl Eq for ConsoleEvent {}

/// Stable error codes returned by the Console Protocol.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConsoleErrorCode {
    /// Frame was malformed or out of sequence.
    BadFrame,
    /// Session is missing or invalid.
    NotAuthenticated,
    /// Caller lacks required authority.
    Unauthorized,
    /// Request is explicitly forbidden by policy or visibility rules.
    Forbidden,
    /// Compare-and-swap or revision conflict.
    Conflict,
    /// Request input failed validation.
    BadRequest,
    /// Request exceeded rate limits.
    RateLimited,
    /// Server-side failure.
    Internal,
}

/// Complete protocol metadata advertised to console clients.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolMetadata {
    /// Wire protocol version served by this instance.
    pub protocol_version: u16,
    /// Server name.
    pub server_name: String,
    /// Selected wire encoding.
    pub encoding: String,
    /// Current server state revision.
    pub server_rev: u64,
    /// Current descriptor registry revision.
    pub registry_rev: u64,
    /// Root visibility authority contract.
    pub root_data_authority: RootDataAuthority,
    /// Action descriptors visible through the protocol registry.
    pub actions: Vec<ActionDescriptor>,
    /// Stream descriptors visible through the protocol registry.
    pub streams: Vec<StreamDescriptor>,
    /// Visibility tiers known to the protocol.
    pub visibility_tiers: Vec<VisibilityTier>,
    /// Secret custody classes known to the protocol.
    pub secret_classes: Vec<SecretClass>,
    /// Low-leak transport security mode summary.
    pub transport_security_mode: String,
    /// Whether the listener is running with explicit unsafe transport relaxations.
    pub unsafe_transport: bool,
    /// Explicit unsafe transport relaxations enabled for this listener.
    pub unsafe_transport_relaxations: Vec<String>,
}

/// Root-data-authority invariants exposed by the Console Protocol.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RootDataAuthority {
    /// Whether root can view all business payloads through visibility gates.
    pub root_can_view_all_business_data: bool,
    /// Whether step-up is an audit/confirmation gate, not a permission denial.
    pub visibility_step_up_is_gate_not_permission_denial: bool,
    /// Whether root bypasses Operation/Fact/policy flow.
    pub bypasses_operation_fact_policy: bool,
    /// Whether vault secret custody is separate from non-secret data visibility.
    pub vault_secret_custody_is_separate: bool,
}

/// Discoverable descriptor for one mutation action or observability view.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionDescriptor {
    /// Stable action id.
    pub id: String,
    /// Protocol domain grouping the action.
    pub domain: String,
    /// Action class.
    pub kind: ActionKind,
    /// Operational risk level.
    pub risk: RiskLevel,
    /// Implementation status.
    pub status: ImplementationStatus,
    /// Maximum visibility tier touched by the action.
    pub visibility: VisibilityTier,
    /// Secret class if the action handles secret material.
    pub secret_class: Option<SecretClass>,
    /// Whether the action requires MFA/step-up.
    pub requires_step_up: bool,
    /// Authority predicates required to invoke the action.
    pub required_authority: Vec<RequiredAuthority>,
    /// Input schema descriptor.
    pub input: SchemaDescriptor,
    /// Output schema descriptor.
    pub output: SchemaDescriptor,
}

/// Discoverable descriptor for one subscription stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StreamDescriptor {
    /// Stable stream id.
    pub id: String,
    /// Protocol domain grouping the stream.
    pub domain: String,
    /// Implementation status.
    pub status: ImplementationStatus,
    /// Maximum visibility tier emitted by the stream.
    pub visibility: VisibilityTier,
    /// Whether the stream requires MFA/step-up.
    pub requires_step_up: bool,
    /// Authority predicates required to subscribe.
    pub required_authority: Vec<RequiredAuthority>,
    /// Stream input/filter schema descriptor.
    pub input: SchemaDescriptor,
    /// Stream event schema descriptor.
    pub event: SchemaDescriptor,
}

/// One authority predicate required by a descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequiredAuthority {
    /// Capability verb, such as `read`, `write`, or `subscribe`.
    pub verb: String,
    /// Target path or path pattern.
    pub target: String,
}

/// Language-neutral schema descriptor used for action and stream discovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchemaDescriptor {
    /// Stable schema id.
    pub schema_id: String,
    /// High-level value kind (`map`, `list`, `null`, etc.).
    pub value_kind: String,
    /// Known fields for map-like values.
    #[serde(default)]
    pub fields: Vec<FieldDescriptor>,
    /// Human-readable schema notes and constraints.
    #[serde(default)]
    pub notes: Vec<String>,
}

/// One field in a map-like schema descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldDescriptor {
    /// Field name.
    pub name: String,
    /// Field kind.
    pub kind: String,
    /// Whether the field is required.
    pub required: bool,
    /// Stable semantic field identity used across schema revisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_id: Option<String>,
    /// Shape-independent semantic kind, never a concrete UI component name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_kind: Option<String>,
    /// Resource type referenced by this field when it is a resource reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ref_target_type: Option<String>,
    /// Sensitivity marker for persistence, logging, and display policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    /// Whether clients must treat the field as read-only.
    #[serde(default, skip_serializing_if = "is_false")]
    pub read_only: bool,
    /// Whether the field is computed by the server.
    #[serde(default, skip_serializing_if = "is_false")]
    pub computed: bool,
    /// Whether the field remains accepted but should not be used for new edits.
    #[serde(default, skip_serializing_if = "is_false")]
    pub deprecated: bool,
}

/// High-level descriptor kind for Console Protocol actions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Protocol discovery action.
    Protocol,
    /// Read-only observability view.
    View,
    /// Mutating management action.
    Mutation,
    /// Secret custody action.
    Secret,
    /// Data visibility action.
    Visibility,
}

/// Operational risk level used by descriptors and UI policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Low-risk read or discovery.
    Low,
    /// Elevated management action.
    Elevated,
    /// Break-glass or sensitive data access.
    BreakGlass,
}

/// Implementation state exposed by Console Protocol descriptors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    /// Action/stream is implemented.
    Implemented,
    /// Descriptor is discoverable but not yet executable.
    Planned,
    /// Descriptor is intentionally unavailable because custody rules block it.
    BlockedByCustody,
}

/// Data visibility tier exposed by Console Protocol descriptors.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityTier {
    /// Public control-plane metadata.
    PublicControl,
    /// Management state without business payloads.
    ManagementState,
    /// Business payload data.
    BusinessData,
    /// Protected or user-private payload data.
    ProtectedPayload,
    /// Secret metadata without plaintext.
    SecretMetadata,
    /// Secret plaintext, only through custody gates.
    SecretPlaintext,
}

/// Secret custody class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretClass {
    /// Secret can be revealed under custody policy.
    RevealableSecret,
    /// Secret is stored in non-recoverable form.
    NonRecoverableSecret,
    /// Secret is available only at a display edge and then consumed.
    OneTimeSecret,
}

/// Build protocol metadata for the given server and registry revisions.
pub fn protocol_metadata(server_rev: u64, registry_rev: u64) -> ProtocolMetadata {
    ProtocolMetadata {
        protocol_version: PROTOCOL_VERSION,
        server_name: SERVER_NAME.into(),
        encoding: WIRE_ENCODING.into(),
        server_rev,
        registry_rev,
        root_data_authority: RootDataAuthority {
            root_can_view_all_business_data: true,
            visibility_step_up_is_gate_not_permission_denial: true,
            bypasses_operation_fact_policy: false,
            vault_secret_custody_is_separate: true,
        },
        actions: action_descriptors(),
        streams: stream_descriptors(),
        visibility_tiers: vec![
            VisibilityTier::PublicControl,
            VisibilityTier::ManagementState,
            VisibilityTier::BusinessData,
            VisibilityTier::ProtectedPayload,
            VisibilityTier::SecretMetadata,
            VisibilityTier::SecretPlaintext,
        ],
        secret_classes: vec![
            SecretClass::RevealableSecret,
            SecretClass::NonRecoverableSecret,
            SecretClass::OneTimeSecret,
        ],
        transport_security_mode: "production_tls".into(),
        unsafe_transport: false,
        unsafe_transport_relaxations: Vec::new(),
    }
}

/// Build protocol metadata for a concrete console listener.
pub fn protocol_metadata_for_transport(
    server_rev: u64,
    registry_rev: u64,
    transport: &crate::state::ConsoleTransportSecurityConfig,
) -> ProtocolMetadata {
    let mut metadata = protocol_metadata(server_rev, registry_rev);
    metadata.transport_security_mode = transport.mode.as_str().into();
    metadata.unsafe_transport = transport.is_unsafe();
    metadata.unsafe_transport_relaxations = transport.unsafe_relaxation_names();
    metadata
}

/// Build protocol metadata and convert it into a Nexus [`Value`].
pub fn protocol_metadata_value(server_rev: u64, registry_rev: u64) -> Value {
    to_value(protocol_metadata(server_rev, registry_rev))
}

/// Build concrete-listener protocol metadata and convert it into a Nexus [`Value`].
pub fn protocol_metadata_value_for_transport(
    server_rev: u64,
    registry_rev: u64,
    transport: &crate::state::ConsoleTransportSecurityConfig,
) -> Value {
    to_value(protocol_metadata_for_transport(
        server_rev,
        registry_rev,
        transport,
    ))
}

/// Convert protocol metadata into a Nexus [`Value`].
pub fn protocol_metadata_to_value(metadata: ProtocolMetadata) -> Value {
    to_value(metadata)
}

/// Build the coverage report view described by the console protocol contract.
pub fn coverage_report_value(server_rev: u64, registry_rev: u64) -> Value {
    let actions = action_descriptors();
    let streams = stream_descriptors();
    let mut domains: BTreeMap<String, (usize, usize, usize, usize)> = BTreeMap::new();
    for action in &actions {
        let entry = domains.entry(action.domain.clone()).or_default();
        entry.0 += 1;
        match action.status {
            ImplementationStatus::Implemented => entry.1 += 1,
            ImplementationStatus::Planned => entry.2 += 1,
            ImplementationStatus::BlockedByCustody => entry.3 += 1,
        }
    }
    for stream in &streams {
        let entry = domains.entry(stream.domain.clone()).or_default();
        entry.0 += 1;
        if stream.status == ImplementationStatus::Implemented {
            entry.1 += 1;
        }
    }
    let domain_rows = domains
        .into_iter()
        .map(
            |(domain, (declared, implemented, planned, custody_blocked))| {
                let mut row = BTreeMap::new();
                row.insert("domain".into(), Value::Str(domain));
                row.insert("declared".into(), Value::Int(declared as i64));
                row.insert("implemented".into(), Value::Int(implemented as i64));
                row.insert("planned".into(), Value::Int(planned as i64));
                row.insert("custody_blocked".into(), Value::Int(custody_blocked as i64));
                Value::Map(row)
            },
        )
        .collect();
    let mut root = BTreeMap::new();
    root.insert(
        "protocol_version".into(),
        Value::Int(PROTOCOL_VERSION as i64),
    );
    root.insert("server_rev".into(), Value::Int(server_rev as i64));
    root.insert("registry_rev".into(), Value::Int(registry_rev as i64));
    root.insert("action_count".into(), Value::Int(actions.len() as i64));
    root.insert("stream_count".into(), Value::Int(streams.len() as i64));
    root.insert("domains".into(), Value::List(domain_rows));
    root.insert(
        "root_data_authority".into(),
        to_value(protocol_metadata(server_rev, registry_rev).root_data_authority),
    );
    root.insert(
        "invariants".into(),
        Value::List(vec![
            Value::Str("no_raw_shell".into()),
            Value::Str("all_calls_use_operation_fact_policy".into()),
            Value::Str("root_views_all_business_data".into()),
            Value::Str("vault_secret_custody_separate".into()),
        ]),
    );
    Value::Map(root)
}

/// Return one action descriptor encoded as a Nexus value.
pub fn descriptor_value(action_id: &str) -> Option<Value> {
    action_descriptors()
        .into_iter()
        .find(|d| d.id == action_id)
        .map(to_value)
}

/// Return resource type summaries visible through the semantic edit contract.
pub fn resource_type_list_value() -> Value {
    Value::List(
        [
            resource_type_summary(
                "config.entry",
                "Config entry",
                "config.entries",
                ACTION_CONFIG_READ,
                Some(ACTION_CONFIG_WRITE_CAS),
                ImplementationStatus::Implemented,
            ),
            resource_type_summary(
                "access.user",
                "Console user",
                "access.users",
                ACTION_ACCESS_USER_READ,
                Some(ACTION_ACCESS_USER_WRITE_CAS),
                ImplementationStatus::Implemented,
            ),
            resource_type_summary(
                "access.role",
                "Console role",
                "access.roles",
                ACTION_ACCESS_ROLE_READ,
                Some(ACTION_ACCESS_ROLE_WRITE_CAS),
                ImplementationStatus::Implemented,
            ),
            resource_type_summary(
                "access.session",
                "Console session",
                "access.sessions",
                ACTION_ACCESS_SESSION_LIST,
                Some(ACTION_ACCESS_SESSION_REVOKE),
                ImplementationStatus::Implemented,
            ),
            resource_type_summary(
                "external.installation",
                "External installation",
                "external.installations",
                ACTION_CONFIG_READ,
                Some(ACTION_EXTERNAL_INSTALLATION_UPDATE),
                ImplementationStatus::Implemented,
            ),
            resource_type_summary(
                "plan.workflow",
                "Plan workflow",
                "plan.workflows",
                "plans.plan.read",
                Some("plans.plan.write_cas"),
                ImplementationStatus::Planned,
            ),
        ]
        .into_iter()
        .collect(),
    )
}

/// Return one resource type descriptor encoded as a Nexus value.
pub fn resource_type_descriptor_value(resource_type: &str) -> Option<Value> {
    match resource_type {
        "config.entry" => Some(resource_type_descriptor(
            "config.entry",
            "Config entry",
            "config.entries",
            ACTION_CONFIG_READ,
            Some(ACTION_CONFIG_LIST),
            Some(ACTION_CONFIG_WRITE_CAS),
            None,
            ImplementationStatus::Implemented,
            vec![
                semantic_contract_field("path", "path", true, "path", "management_state", false),
                semantic_contract_field(
                    "value",
                    "value",
                    true,
                    "json_value",
                    "management_state",
                    false,
                ),
                semantic_contract_field(
                    "expected_version",
                    "u64|null",
                    false,
                    "revision",
                    "public_control",
                    false,
                ),
            ],
            vec!["path", "expected_version"],
        )),
        "access.user" => Some(resource_type_descriptor(
            "access.user",
            "Console user",
            "access.users",
            ACTION_ACCESS_USER_READ,
            Some(ACTION_ACCESS_USER_LIST),
            Some(ACTION_ACCESS_USER_WRITE_CAS),
            None,
            ImplementationStatus::Implemented,
            vec![
                semantic_contract_field(
                    "username",
                    "string",
                    true,
                    "resource_ref",
                    "management_state",
                    false,
                ),
                semantic_contract_field(
                    "status",
                    "string",
                    false,
                    "enum",
                    "management_state",
                    false,
                ),
                semantic_contract_field(
                    "roles",
                    "list<string>",
                    false,
                    "resource_ref",
                    "management_state",
                    false,
                ),
                semantic_contract_field(
                    "grants",
                    "list<string>",
                    false,
                    "json_value",
                    "management_state",
                    false,
                ),
                semantic_contract_field(
                    "authn",
                    "map",
                    false,
                    "json_value",
                    "secret_metadata",
                    false,
                ),
            ],
            vec!["username", "status"],
        )),
        "access.role" => Some(resource_type_descriptor(
            "access.role",
            "Console role",
            "access.roles",
            ACTION_ACCESS_ROLE_READ,
            Some(ACTION_ACCESS_ROLE_LIST),
            Some(ACTION_ACCESS_ROLE_WRITE_CAS),
            None,
            ImplementationStatus::Implemented,
            vec![
                semantic_contract_field(
                    "role",
                    "string",
                    true,
                    "resource_ref",
                    "management_state",
                    false,
                ),
                semantic_contract_field(
                    "grants",
                    "list<string>",
                    false,
                    "json_value",
                    "management_state",
                    false,
                ),
                semantic_contract_field("frozen", "bool", false, "enum", "management_state", false),
            ],
            vec!["role", "frozen"],
        )),
        "access.session" => Some(resource_type_descriptor(
            "access.session",
            "Console session",
            "access.sessions",
            ACTION_ACCESS_SESSION_LIST,
            Some(ACTION_ACCESS_SESSION_LIST),
            Some(ACTION_ACCESS_SESSION_REVOKE),
            None,
            ImplementationStatus::Implemented,
            vec![
                semantic_contract_field(
                    "sid",
                    "string",
                    true,
                    "resource_ref",
                    "management_state",
                    true,
                ),
                semantic_contract_field(
                    "username",
                    "string",
                    false,
                    "resource_ref",
                    "management_state",
                    true,
                ),
                semantic_contract_field("mfa_level", "u8", false, "enum", "public_control", true),
                semantic_contract_field(
                    "expires_at_ms",
                    "i64",
                    false,
                    "duration",
                    "public_control",
                    true,
                ),
            ],
            vec!["sid", "username", "mfa_level"],
        )),
        "external.installation" => Some(resource_type_descriptor(
            "external.installation",
            "External installation",
            "external.installations",
            ACTION_CONFIG_READ,
            None,
            Some(ACTION_EXTERNAL_INSTALLATION_UPDATE),
            None,
            ImplementationStatus::Implemented,
            vec![
                semantic_contract_field(
                    "id",
                    "string",
                    true,
                    "resource_ref",
                    "management_state",
                    false,
                ),
                semantic_contract_field(
                    "def",
                    "value",
                    true,
                    "json_value",
                    "management_state",
                    false,
                ),
                semantic_contract_field(
                    "expected_version",
                    "u64|null",
                    false,
                    "revision",
                    "public_control",
                    false,
                ),
            ],
            vec!["id"],
        )),
        "plan.workflow" => Some(resource_type_descriptor(
            "plan.workflow",
            "Plan workflow",
            "plan.workflows",
            "plans.plan.read",
            Some("plans.plan.list"),
            Some("plans.plan.write_cas"),
            Some("plans.plan.validate"),
            ImplementationStatus::Planned,
            vec![
                semantic_contract_field(
                    "plan",
                    "string",
                    true,
                    "resource_ref",
                    "management_state",
                    false,
                ),
                semantic_contract_field(
                    "graph",
                    "graph",
                    true,
                    "graph_model",
                    "management_state",
                    false,
                ),
                semantic_contract_field(
                    "expected_version",
                    "u64|null",
                    false,
                    "revision",
                    "public_control",
                    false,
                ),
            ],
            vec!["plan"],
        )),
        _ => None,
    }
}

/// Return one fixed resource view descriptor encoded as a Nexus value.
pub fn resource_view_descriptor_value(view: &str) -> Option<Value> {
    match view {
        "config.entries" => Some(resource_view_descriptor(
            "config.entries",
            "config.entry",
            ACTION_CONFIG_LIST,
            STREAM_STATE_WATCH,
            vec!["path", "value_kind", "revision"],
        )),
        "access.users" => Some(resource_view_descriptor(
            "access.users",
            "access.user",
            ACTION_ACCESS_USER_LIST,
            STREAM_STATE_WATCH,
            vec!["username", "status", "mfa_level", "roles"],
        )),
        "access.roles" => Some(resource_view_descriptor(
            "access.roles",
            "access.role",
            ACTION_ACCESS_ROLE_LIST,
            STREAM_STATE_WATCH,
            vec!["role", "grant_count", "frozen"],
        )),
        "access.sessions" => Some(resource_view_descriptor(
            "access.sessions",
            "access.session",
            ACTION_ACCESS_SESSION_LIST,
            STREAM_AUDIT_FACTS,
            vec!["sid", "username", "mfa_level", "expires_at_ms"],
        )),
        "external.installations" => Some(resource_view_descriptor(
            "external.installations",
            "external.installation",
            ACTION_CONFIG_LIST,
            STREAM_STATE_WATCH,
            vec!["id", "status", "proc", "generation"],
        )),
        "plan.workflows" => Some(resource_view_descriptor(
            "plan.workflows",
            "plan.workflow",
            "plans.plan.list",
            STREAM_STATE_WATCH,
            vec!["plan", "status", "revision"],
        )),
        _ => None,
    }
}

/// Return one graph type descriptor encoded as a Nexus value.
pub fn graph_type_descriptor_value(graph_type: &str) -> Option<Value> {
    if graph_type != "plan.workflow" {
        return None;
    }
    let node_types = Value::List(vec![
        graph_node_type("input", vec![], vec!["value"], "plans.plan.validate"),
        graph_node_type(
            "approval",
            vec!["request"],
            vec!["approved", "denied"],
            "approval.respond",
        ),
        graph_node_type(
            "action",
            vec!["input"],
            vec!["output"],
            "plans.plan.validate",
        ),
        graph_node_type(
            "condition",
            vec!["input"],
            vec!["true", "false"],
            "plans.plan.validate",
        ),
        graph_node_type("export", vec!["input"], vec![], "artifacts.export.create"),
    ]);
    Some(value_map([
        ("graph_type", Value::Str("plan.workflow".into())),
        ("resource_type", Value::Str("plan.workflow".into())),
        ("status", to_value(ImplementationStatus::Planned)),
        ("node_types", node_types),
        (
            "edge_types",
            Value::List(vec![value_map([
                ("edge_type", Value::Str("data".into())),
                ("compatible_ports", Value::List(vec![Value::Str("value".into()), Value::Str("input".into())])),
            ])]),
        ),
        ("validation_action", Value::Str("plans.plan.validate".into())),
        ("compile_action", Value::Null),
        ("apply_action", Value::Str("plans.plan.write_cas".into())),
        (
            "notes",
            Value::List(vec![
                Value::Str("graph.type.describe is a descriptor only; graph execution still uses fixed actions".into()),
                Value::Str("no raw operation, raw effect, or raw state node type is allowed".into()),
            ]),
        ),
    ]))
}

/// Return the secret custody catalog exposed by `secret.catalog`.
pub fn secret_catalog_value() -> Value {
    let rows = vec![
        secret_row(
            "state://vault/console/*/password",
            SecretClass::NonRecoverableSecret,
            "password hashes are verifiable, not reversible; root may reset credentials",
        ),
        secret_row(
            "state://vault/console/sessions/*",
            SecretClass::NonRecoverableSecret,
            "session token hashes are revocable, not revealable",
        ),
        secret_row(
            "state://vault/console/*/totp",
            SecretClass::NonRecoverableSecret,
            "TOTP seeds are custody secrets; root may rotate/reset",
        ),
        secret_row(
            "pairing.display_secret",
            SecretClass::OneTimeSecret,
            "pairing display secrets are available only on the create/replace edge",
        ),
    ];
    Value::List(rows)
}

/// Return root data authority and visibility-gate metadata.
pub fn visibility_authority_value() -> Value {
    let mut root = BTreeMap::new();
    root.insert("root_can_view_all_business_data".into(), Value::Bool(true));
    root.insert(
        "requires_step_up_for_protected_payload".into(),
        Value::Bool(true),
    );
    root.insert("bypasses_operation_fact_policy".into(), Value::Bool(false));
    root.insert("business_prefix".into(), Value::Str("state://**".into()));
    root.insert(
        "secret_prefix".into(),
        Value::Str("state://vault/**".into()),
    );
    root.insert(
        "secret_prefix_rule".into(),
        Value::Str("use secret.* custody actions; generic visibility reads reject vault".into()),
    );
    Value::Map(root)
}

/// Return the static stream descriptor registry.
pub fn stream_descriptors() -> Vec<StreamDescriptor> {
    vec![
        StreamDescriptor {
            id: STREAM_STATE_WATCH.into(),
            domain: "visibility".into(),
            status: ImplementationStatus::Implemented,
            visibility: VisibilityTier::BusinessData,
            requires_step_up: true,
            required_authority: vec![authority("subscribe", "state://**")],
            input: schema(
                "stream.state_watch.input",
                "map",
                vec![field("pattern", "path-pattern", true)],
                vec![
                    "vault patterns are rejected and must use secret custody actions",
                    "business-data streams require StreamCall.scope, justification, and ttl_ms",
                    "StreamCall.since_rev is reserved; current streams are live-only",
                ],
            ),
            event: schema("stream.state_watch.event", "console_event", vec![], vec![]),
        },
        StreamDescriptor {
            id: STREAM_AUDIT_FACTS.into(),
            domain: "audit".into(),
            status: ImplementationStatus::Implemented,
            visibility: VisibilityTier::ProtectedPayload,
            requires_step_up: true,
            required_authority: vec![authority("read", "state://fact/**")],
            input: schema(
                "stream.audit_facts.input",
                "map",
                vec![field("process", "u64", false)],
                vec![
                    "audit/fact streams require StreamCall.scope, justification, and ttl_ms",
                    "StreamCall.since_rev is reserved; current streams are live-only",
                ],
            ),
            event: schema("stream.audit_facts.event", "console_event", vec![], vec![]),
        },
    ]
}

/// Return the static action descriptor registry.
pub fn action_descriptors() -> Vec<ActionDescriptor> {
    vec![
        action(
            ACTION_PROTOCOL_DESCRIBE,
            "protocol",
            ActionKind::Protocol,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::PublicControl, false),
            vec![],
            schema("protocol.empty", "null", vec![], vec![]),
            schema("protocol.metadata", "map", vec![], vec![]),
        ),
        action(
            ACTION_PROTOCOL_REGISTRY_SNAPSHOT,
            "protocol",
            ActionKind::Protocol,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::PublicControl, false),
            vec![],
            schema("protocol.empty", "null", vec![], vec![]),
            schema("protocol.metadata", "map", vec![], vec![]),
        ),
        action(
            ACTION_PROTOCOL_SCHEMA_GET,
            "protocol",
            ActionKind::Protocol,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::PublicControl, false),
            vec![],
            schema(
                "protocol.schema_get.input",
                "map",
                vec![field("action", "string", true)],
                vec![
                    "compatibility alias for protocol.action_descriptor.get",
                    "returns an action descriptor, not an arbitrary schema id",
                ],
            ),
            schema("protocol.action_descriptor", "map", vec![], vec![]),
        ),
        action(
            ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET,
            "protocol",
            ActionKind::Protocol,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::PublicControl, false),
            vec![],
            schema(
                "protocol.action_descriptor_get.input",
                "map",
                vec![field("action", "string", true)],
                vec!["returns an action descriptor for the supplied action id"],
            ),
            schema("protocol.action_descriptor", "map", vec![], vec![]),
        ),
        action(
            ACTION_REGISTRY_COVERAGE_REPORT,
            "registry",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema("registry.coverage.input", "null", vec![], vec![]),
            schema("registry.coverage.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_RESOURCE_TYPE_LIST,
            "resource",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema("resource.type_list.input", "null", vec![], vec![]),
            schema("resource.type_list.output", "list", vec![], vec![]),
        ),
        action(
            ACTION_RESOURCE_TYPE_DESCRIBE,
            "resource",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "resource.type_describe.input",
                "map",
                vec![semantic_field(
                    "resource_type",
                    "string",
                    true,
                    "resource_ref",
                )],
                vec!["returns semantic edit metadata for one resource type"],
            ),
            schema("resource.type_descriptor.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_RESOURCE_VIEW_DESCRIBE,
            "resource",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "resource.view_describe.input",
                "map",
                vec![semantic_field("view", "string", true, "resource_ref")],
                vec!["returns query/projection metadata for one fixed resource view"],
            ),
            schema("resource.view_descriptor.output", "map", vec![], vec![]),
        ),
        planned_action(
            ACTION_CHANGE_SET_CREATE,
            "change_set",
            ActionKind::Mutation,
            vec![
                semantic_field("base_snapshot_rev", "u64", false, "revision"),
                semantic_field("registry_rev", "u64", true, "revision"),
            ],
            "change_set.create is planned; use domain validate/write_cas actions until it is implemented",
        ),
        planned_action(
            ACTION_CHANGE_SET_UPDATE,
            "change_set",
            ActionKind::Mutation,
            vec![
                semantic_field("change_set", "value", true, "json_value"),
                semantic_field("ops", "list<change_op>", true, "json_value"),
            ],
            "change_set.update is planned; clients must not treat local drafts as server facts",
        ),
        planned_action(
            ACTION_CHANGE_SET_VALIDATE,
            "change_set",
            ActionKind::View,
            vec![semantic_field("change_set", "value", true, "json_value")],
            "change_set.validate is planned; use domain-specific validate actions until available",
        ),
        planned_action(
            ACTION_CHANGE_SET_DIFF,
            "change_set",
            ActionKind::View,
            vec![semantic_field("change_set", "value", true, "json_value")],
            "change_set.diff is planned; clients should compute local redacted diffs as a UX aid",
        ),
        planned_action(
            ACTION_CHANGE_SET_DRY_RUN,
            "change_set",
            ActionKind::View,
            vec![semantic_field("change_set", "value", true, "json_value")],
            "change_set.dry_run is planned; dry-run results cannot replace apply-time authorization",
        ),
        planned_action(
            ACTION_CHANGE_SET_APPLY,
            "change_set",
            ActionKind::Mutation,
            vec![semantic_field("change_set", "value", true, "json_value")],
            "change_set.apply is planned; apply must re-run every action gate, MFA, CAS, policy, and audit check",
        ),
        planned_action(
            ACTION_CHANGE_SET_DISCARD,
            "change_set",
            ActionKind::Mutation,
            vec![semantic_field("change_set", "value", true, "json_value")],
            "change_set.discard is planned; local drafts remain client-side until server support lands",
        ),
        action(
            ACTION_GRAPH_TYPE_DESCRIBE,
            "graph",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "graph.type_describe.input",
                "map",
                vec![semantic_field("graph_type", "string", true, "resource_ref")],
                vec!["returns node/port/edge metadata for one fixed graph type"],
            ),
            schema("graph.type_descriptor.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE,
            "authority",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "authority.principal_effective.input",
                "null",
                vec![],
                vec![],
            ),
            schema(
                "authority.principal_effective.output",
                "map",
                vec![],
                vec![],
            ),
        ),
        action(
            ACTION_AUTHORITY_ACTION_MATRIX,
            "authority",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "authority.action_matrix.input",
                "map",
                vec![field("domain", "string", false)],
                vec![
                    "explains current principal only",
                    "visibility-gated actions may be authority-ok but still require per-call scope, justification, and ttl_ms",
                ],
            ),
            schema("authority.action_matrix.output", "list", vec![], vec![]),
        ),
        action(
            ACTION_AUTHORITY_RESOURCE_ACCESS,
            "authority",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "authority.resource_access.input",
                "map",
                vec![field("target", "path", true), field("verb", "string", true)],
                vec!["single-resource explanation; broad scans must use a paged/artifact action"],
            ),
            schema("authority.resource_access.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_AUTHORITY_WHY_DENIED,
            "authority",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![],
            schema(
                "authority.why_denied.input",
                "map",
                vec![field("action", "string", true)],
                vec!["explains action gate outcome for the current principal"],
            ),
            schema("authority.why_denied.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_VISIBILITY_AUTHORITY_DESCRIBE,
            "visibility",
            ActionKind::Visibility,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::PublicControl, false),
            vec![],
            schema("visibility.authority.input", "null", vec![], vec![]),
            schema("visibility.authority.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_VISIBILITY_STATE_READ,
            "visibility",
            ActionKind::Visibility,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::BusinessData, true),
            vec![authority("read", "state://**")],
            schema(
                "visibility.state_read.input",
                "map",
                vec![field("path", "path", true)],
                vec![
                    "rejects state://vault/**; use secret.*",
                    "requires ActionCall.scope, justification, and ttl_ms",
                ],
            ),
            schema("visibility.state_read.output", "value", vec![], vec![]),
        ),
        action(
            ACTION_VISIBILITY_STATE_LIST,
            "visibility",
            ActionKind::Visibility,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::BusinessData, true),
            vec![authority("read", "state://**")],
            schema(
                "visibility.state_list.input",
                "map",
                vec![
                    field("prefix", "path", true),
                    field("limit", "usize", false),
                ],
                vec![
                    "rejects state://vault/**; use secret.*",
                    "requires ActionCall.scope, justification, and ttl_ms",
                ],
            ),
            schema("visibility.state_list.output", "list", vec![], vec![]),
        ),
        secret_action(
            ACTION_SECRET_CATALOG,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::SecretMetadata, false),
            None,
            ImplementationStatus::Implemented,
        ),
        secret_action(
            ACTION_SECRET_REVEAL,
            ActionPolicy::new(RiskLevel::BreakGlass, VisibilityTier::SecretPlaintext, true),
            Some(SecretClass::RevealableSecret),
            ImplementationStatus::BlockedByCustody,
        ),
        action(
            ACTION_STATE_SNAPSHOT,
            "state",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, false),
            vec![
                authority("read", "state://kernel/**"),
                authority("perform", "effect://kernel/console/users"),
                authority("perform", "effect://kernel/process/inspect"),
                authority("read", "state://fact/**"),
            ],
            schema(
                "state.snapshot.input",
                "map",
                vec![
                    field("sections", "list<snapshot_section>", false),
                    field("since_rev", "u64", false),
                ],
                vec![
                    "runtime.include_recent_facts defaults to false",
                    "runtime.include_recent_facts=true requires ActionCall.scope, justification, and ttl_ms",
                ],
            ),
            schema("state.snapshot.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_CONFIG_READ,
            "config",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![authority("read", "state://kernel/**")],
            schema(
                "config.read.input",
                "map",
                vec![field("path", "path", true)],
                vec![],
            ),
            schema("config.read.output", "value", vec![], vec![]),
        ),
        action(
            ACTION_CONFIG_LIST,
            "config",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![authority("read", "state://kernel/**")],
            schema(
                "config.list.input",
                "map",
                vec![field("prefix", "path", true)],
                vec![],
            ),
            schema("config.list.output", "list", vec![], vec![]),
        ),
        action(
            ACTION_CONFIG_WRITE_CAS,
            "config",
            ActionKind::Mutation,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, false),
            vec![authority("write", "state://kernel/**")],
            schema(
                "config.write_cas.input",
                "map",
                vec![
                    field("path", "path", true),
                    field("value", "value", true),
                    field("expected_version", "u64|null", false),
                ],
                vec![
                    "state://kernel/{console,external,external-installations,external-projections,external-pairings,external-sessions,external-credential-revocations,procs}/** requires MFA step-up",
                    "prefer dedicated access.*, external.installation.*, and pairing.* actions for typed management writes",
                ],
            ),
            schema("protocol.empty", "null", vec![], vec![]),
        ),
        access_action(
            ACTION_ACCESS_USER_READ,
            ActionKind::View,
            false,
            vec![field("username", "string", true)],
        ),
        access_action(ACTION_ACCESS_USER_LIST, ActionKind::View, false, vec![]),
        access_action(
            ACTION_ACCESS_USER_WRITE_CAS,
            ActionKind::Mutation,
            true,
            vec![
                field("username", "string", true),
                field("value", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        access_action(
            ACTION_ACCESS_USER_DISABLE,
            ActionKind::Mutation,
            true,
            vec![
                field("username", "string", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        access_action(
            ACTION_ACCESS_ROLE_READ,
            ActionKind::View,
            false,
            vec![field("role", "string", true)],
        ),
        access_action(ACTION_ACCESS_ROLE_LIST, ActionKind::View, false, vec![]),
        access_action(
            ACTION_ACCESS_ROLE_WRITE_CAS,
            ActionKind::Mutation,
            true,
            vec![
                field("role", "string", true),
                field("value", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        access_action(
            ACTION_ACCESS_SESSION_CURRENT_LOGOUT,
            ActionKind::Mutation,
            false,
            vec![],
        ),
        access_action(ACTION_ACCESS_SESSION_LIST, ActionKind::View, false, vec![]),
        access_action(
            ACTION_ACCESS_SESSION_REVOKE,
            ActionKind::Mutation,
            true,
            vec![field("sid", "string", true)],
        ),
        access_action(
            ACTION_ACCESS_SESSION_REVOKE_USER,
            ActionKind::Mutation,
            true,
            vec![field("username", "string", true)],
        ),
        action(
            ACTION_RUNTIME_PROCESS_INSPECT,
            "runtime",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ProtectedPayload, true),
            vec![authority("perform", "effect://kernel/process/inspect")],
            schema(
                "runtime.process_inspect.input",
                "map",
                vec![
                    field("process", "u64", false),
                    field("include_recent_facts", "bool", false),
                    field("limit", "usize", false),
                ],
                vec![],
            ),
            schema("runtime.process_inspect.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_AUDIT_FACTS_RECENT,
            "audit",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ProtectedPayload, true),
            vec![authority("read", "state://fact/**")],
            schema(
                "audit.facts_recent.input",
                "map",
                vec![
                    field("process", "u64", false),
                    field("limit", "usize", false),
                ],
                vec![],
            ),
            schema("audit.facts_recent.output", "list", vec![], vec![]),
        ),
        action(
            ACTION_LINEAGE_TRACE_READ,
            "lineage",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ProtectedPayload, true),
            vec![authority("read", "state://fact/**")],
            schema(
                "lineage.trace_read.input",
                "map",
                vec![
                    field("process", "u64", true),
                    field("from", "usize", false),
                    field("limit", "usize", false),
                ],
                vec![],
            ),
            schema(
                "lineage.trace_read.output",
                "map",
                vec![],
                vec![
                    "output includes partial/partial_reason because v1 exposes a fact-order projection",
                ],
            ),
        ),
        action(
            ACTION_LINEAGE_FACT_READ,
            "lineage",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ProtectedPayload, true),
            vec![authority("read", "state://fact/**")],
            schema(
                "lineage.fact_read.input",
                "map",
                vec![field("op_id", "operation_id", true)],
                vec!["requires ActionCall.scope, justification, and ttl_ms"],
            ),
            schema(
                "lineage.fact_read.output",
                "map",
                vec![],
                vec![
                    "output includes partial/partial_reason when lineage projections are not fully materialized",
                ],
            ),
        ),
        action(
            ACTION_LINEAGE_FACT_BY_OPERATION,
            "lineage",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ProtectedPayload, true),
            vec![authority("read", "state://fact/**")],
            schema(
                "lineage.fact_by_operation.input",
                "map",
                vec![field("op_id", "operation_id", true)],
                vec!["alias of lineage.fact.read for operation-centric clients"],
            ),
            schema(
                "lineage.fact_by_operation.output",
                "map",
                vec![],
                vec![
                    "output includes partial/partial_reason when lineage projections are not fully materialized",
                ],
            ),
        ),
        action(
            ACTION_HEALTH_SUMMARY,
            "health",
            ActionKind::View,
            ActionPolicy::new(RiskLevel::Low, VisibilityTier::ManagementState, false),
            vec![authority("read", "state://kernel/**")],
            schema("health.summary.input", "null", vec![], vec![]),
            schema("health.summary.output", "map", vec![], vec![]),
        ),
        extension_action(
            ACTION_EXTERNAL_INSTALLATION_INSTALL,
            true,
            vec![
                field("id", "string", true),
                field("def", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        extension_action(
            ACTION_EXTERNAL_INSTALLATION_UPDATE,
            true,
            vec![
                field("id", "string", true),
                field("def", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        extension_action(
            ACTION_EXTERNAL_INSTALLATION_START,
            true,
            vec![field("id", "string", true)],
        ),
        extension_action(
            ACTION_EXTERNAL_INSTALLATION_STOP,
            true,
            vec![field("id", "string", true)],
        ),
        extension_action(
            ACTION_EXTERNAL_INSTALLATION_REVOKE,
            true,
            vec![
                field("installation_id", "string", true),
                field("credential_generation_floor", "i64", false),
            ],
        ),
        pairing_action(
            ACTION_PAIRING_CREATE,
            vec![
                field("input", "value", true),
                field("reveal_display_secret", "bool", false),
            ],
        ),
        pairing_action(
            ACTION_PAIRING_APPROVE,
            vec![
                field("pairing_id", "string", true),
                field("approved_roles", "list<string>", true),
            ],
        ),
        pairing_action(
            ACTION_PAIRING_DENY,
            vec![field("pairing_id", "string", true)],
        ),
        pairing_action(
            ACTION_PAIRING_REPLACE,
            vec![
                field("input", "value", true),
                field("reveal_display_secret", "bool", false),
            ],
        ),
    ]
}

#[derive(Clone)]
struct ActionPolicy {
    risk: RiskLevel,
    visibility: VisibilityTier,
    requires_step_up: bool,
}

impl ActionPolicy {
    const fn new(risk: RiskLevel, visibility: VisibilityTier, requires_step_up: bool) -> Self {
        Self {
            risk,
            visibility,
            requires_step_up,
        }
    }
}

fn access_action(
    id: &str,
    kind: ActionKind,
    requires_step_up: bool,
    fields: Vec<FieldDescriptor>,
) -> ActionDescriptor {
    let required_authority = access_authority(id, &kind);
    action(
        id,
        "access",
        kind,
        ActionPolicy::new(
            if requires_step_up {
                RiskLevel::Elevated
            } else {
                RiskLevel::Low
            },
            VisibilityTier::ManagementState,
            requires_step_up,
        ),
        required_authority,
        schema(&format!("{id}.input"), "map", fields, vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    )
}

fn access_authority(id: &str, kind: &ActionKind) -> Vec<RequiredAuthority> {
    let user_mgmt = authority("perform", "effect://kernel/console/users");
    match id {
        ACTION_ACCESS_SESSION_CURRENT_LOGOUT => vec![],
        ACTION_ACCESS_USER_READ | ACTION_ACCESS_USER_LIST => {
            vec![
                authority("read", "state://kernel/console/users/**"),
                user_mgmt,
            ]
        }
        ACTION_ACCESS_USER_WRITE_CAS | ACTION_ACCESS_USER_DISABLE => {
            vec![
                authority("write", "state://kernel/console/users/**"),
                user_mgmt,
            ]
        }
        ACTION_ACCESS_ROLE_READ | ACTION_ACCESS_ROLE_LIST => {
            vec![
                authority("read", "state://kernel/console/roles/**"),
                user_mgmt,
            ]
        }
        ACTION_ACCESS_ROLE_WRITE_CAS => {
            vec![
                authority("write", "state://kernel/console/roles/**"),
                user_mgmt,
            ]
        }
        ACTION_ACCESS_SESSION_LIST => {
            vec![
                authority("read", "state://kernel/console/sessions/**"),
                user_mgmt,
            ]
        }
        ACTION_ACCESS_SESSION_REVOKE => {
            vec![
                authority("write", "state://kernel/console/sessions/**"),
                user_mgmt,
            ]
        }
        ACTION_ACCESS_SESSION_REVOKE_USER => {
            vec![
                authority("write", "state://kernel/console/users/**"),
                user_mgmt,
            ]
        }
        _ if matches!(kind, ActionKind::Mutation) => {
            vec![authority("write", "state://kernel/console/**"), user_mgmt]
        }
        _ => vec![authority("read", "state://kernel/console/**"), user_mgmt],
    }
}

fn extension_action(
    id: &str,
    requires_step_up: bool,
    fields: Vec<FieldDescriptor>,
) -> ActionDescriptor {
    let required_authority = extension_authority(id);
    action(
        id,
        "external",
        ActionKind::Mutation,
        ActionPolicy::new(
            RiskLevel::Elevated,
            VisibilityTier::ManagementState,
            requires_step_up,
        ),
        required_authority,
        schema(&format!("{id}.input"), "map", fields, vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    )
}

fn extension_authority(id: &str) -> Vec<RequiredAuthority> {
    match id {
        ACTION_EXTERNAL_INSTALLATION_INSTALL | ACTION_EXTERNAL_INSTALLATION_UPDATE => {
            vec![authority(
                "write",
                "state://kernel/external-installations/**",
            )]
        }
        ACTION_EXTERNAL_INSTALLATION_START => vec![
            authority("read", "state://kernel/external-installations/**"),
            authority("perform", "effect://proc/spawn"),
        ],
        ACTION_EXTERNAL_INSTALLATION_STOP => {
            vec![authority("perform", "effect://proc/kill")]
        }
        ACTION_EXTERNAL_INSTALLATION_REVOKE => {
            vec![authority("perform", "effect://external/revoke")]
        }
        _ => vec![authority(
            "write",
            "state://kernel/external-installations/**",
        )],
    }
}

fn pairing_action(id: &str, fields: Vec<FieldDescriptor>) -> ActionDescriptor {
    action(
        id,
        "pairing",
        ActionKind::Mutation,
        ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, true),
        pairing_authority(id),
        schema(&format!("{id}.input"), "map", fields, vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    )
}

fn pairing_authority(id: &str) -> Vec<RequiredAuthority> {
    let target = match id {
        ACTION_PAIRING_CREATE => "effect://external/pairing/create",
        ACTION_PAIRING_APPROVE => "effect://external/pairing/approve",
        ACTION_PAIRING_DENY => "effect://external/pairing/deny",
        ACTION_PAIRING_REPLACE => "effect://external/pairing/replace",
        _ => "effect://external/pairing/**",
    };
    vec![authority("perform", target)]
}

fn secret_action(
    id: &str,
    policy: ActionPolicy,
    secret_class: Option<SecretClass>,
    status: ImplementationStatus,
) -> ActionDescriptor {
    let mut d = action(
        id,
        "secret",
        ActionKind::Secret,
        policy,
        vec![],
        schema(&format!("{id}.input"), "map", vec![], vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    );
    d.secret_class = secret_class;
    d.status = status;
    d
}

fn planned_action(
    id: &str,
    domain: &str,
    kind: ActionKind,
    fields: Vec<FieldDescriptor>,
    note: &str,
) -> ActionDescriptor {
    let mut d = action(
        id,
        domain,
        kind,
        ActionPolicy::new(RiskLevel::Elevated, VisibilityTier::ManagementState, false),
        vec![],
        schema(&format!("{id}.input"), "map", fields, vec![note]),
        schema(&format!("{id}.output"), "map", vec![], vec![note]),
    );
    d.status = ImplementationStatus::Planned;
    d
}

fn action(
    id: &str,
    domain: &str,
    kind: ActionKind,
    policy: ActionPolicy,
    required_authority: Vec<RequiredAuthority>,
    input: SchemaDescriptor,
    output: SchemaDescriptor,
) -> ActionDescriptor {
    ActionDescriptor {
        id: id.into(),
        domain: domain.into(),
        kind,
        risk: policy.risk,
        status: ImplementationStatus::Implemented,
        visibility: policy.visibility,
        secret_class: None,
        requires_step_up: policy.requires_step_up,
        required_authority,
        input,
        output,
    }
}

fn authority(verb: &str, target: &str) -> RequiredAuthority {
    RequiredAuthority {
        verb: verb.into(),
        target: target.into(),
    }
}

fn schema(
    schema_id: &str,
    value_kind: &str,
    fields: Vec<FieldDescriptor>,
    notes: Vec<&str>,
) -> SchemaDescriptor {
    SchemaDescriptor {
        schema_id: schema_id.into(),
        value_kind: value_kind.into(),
        fields,
        notes: notes.into_iter().map(str::to_string).collect(),
    }
}

fn field(name: &str, kind: &str, required: bool) -> FieldDescriptor {
    FieldDescriptor {
        name: name.into(),
        kind: kind.into(),
        required,
        stable_id: None,
        semantic_kind: None,
        ref_target_type: None,
        sensitivity: None,
        read_only: false,
        computed: false,
        deprecated: false,
    }
}

fn semantic_field(name: &str, kind: &str, required: bool, semantic_kind: &str) -> FieldDescriptor {
    FieldDescriptor {
        semantic_kind: Some(semantic_kind.into()),
        stable_id: Some(name.into()),
        sensitivity: Some("public_control".into()),
        ..field(name, kind, required)
    }
}

fn secret_row(path: &str, class: SecretClass, policy: &str) -> Value {
    let mut row = BTreeMap::new();
    row.insert("path".into(), Value::Str(path.into()));
    row.insert("class".into(), to_value(class));
    row.insert("policy".into(), Value::Str(policy.into()));
    Value::Map(row)
}

fn resource_type_summary(
    resource_type: &str,
    title: &str,
    default_view: &str,
    read_action: &str,
    update_action: Option<&str>,
    status: ImplementationStatus,
) -> Value {
    value_map([
        ("resource_type", Value::Str(resource_type.into())),
        ("title", Value::Str(title.into())),
        ("default_view", Value::Str(default_view.into())),
        ("read_action", Value::Str(read_action.into())),
        (
            "update_action",
            update_action.map_or(Value::Null, |action| Value::Str(action.into())),
        ),
        ("status", to_value(status)),
    ])
}

fn resource_type_descriptor(
    resource_type: &str,
    title: &str,
    default_view: &str,
    read_action: &str,
    list_action: Option<&str>,
    update_action: Option<&str>,
    validate_action: Option<&str>,
    status: ImplementationStatus,
    fields: Vec<Value>,
    display_fields: Vec<&str>,
) -> Value {
    value_map([
        ("resource_type", Value::Str(resource_type.into())),
        ("title", Value::Str(title.into())),
        ("status", to_value(status)),
        ("default_view", Value::Str(default_view.into())),
        ("read_action", Value::Str(read_action.into())),
        (
            "list_action",
            list_action.map_or(Value::Null, |action| Value::Str(action.into())),
        ),
        (
            "update_action",
            update_action.map_or(Value::Null, |action| Value::Str(action.into())),
        ),
        (
            "validate_action",
            validate_action.map_or(Value::Null, |action| Value::Str(action.into())),
        ),
        ("revision_field", Value::Str("expected_version".into())),
        ("fields", Value::List(fields)),
        (
            "display_fields",
            Value::List(
                display_fields
                    .into_iter()
                    .map(|field| Value::Str(field.into()))
                    .collect(),
            ),
        ),
        (
            "notes",
            Value::List(vec![Value::Str(
                "descriptor supplies semantic edit metadata only; every write still calls the fixed action descriptor".into(),
            )]),
        ),
    ])
}

fn semantic_contract_field(
    name: &str,
    kind: &str,
    required: bool,
    semantic_kind: &str,
    sensitivity: &str,
    read_only: bool,
) -> Value {
    value_map([
        ("name", Value::Str(name.into())),
        ("kind", Value::Str(kind.into())),
        ("required", Value::Bool(required)),
        ("stable_id", Value::Str(name.into())),
        ("semantic_kind", Value::Str(semantic_kind.into())),
        ("sensitivity", Value::Str(sensitivity.into())),
        ("read_only", Value::Bool(read_only)),
        ("computed", Value::Bool(false)),
        ("deprecated", Value::Bool(false)),
    ])
}

fn resource_view_descriptor(
    view: &str,
    resource_type: &str,
    read_action: &str,
    refresh_stream: &str,
    projection_fields: Vec<&str>,
) -> Value {
    value_map([
        ("view", Value::Str(view.into())),
        ("resource_type", Value::Str(resource_type.into())),
        ("read_action", Value::Str(read_action.into())),
        ("query_schema", Value::Str(format!("{view}.query"))),
        (
            "projection_schema",
            Value::Str(format!("{view}.projection")),
        ),
        ("pagination", Value::Str("offset_or_cursor".into())),
        (
            "filtering",
            Value::List(vec![
                Value::Str("domain_fixed".into()),
                Value::Str("text".into()),
            ]),
        ),
        (
            "sorting",
            Value::List(vec![Value::Str("stable_display_field".into())]),
        ),
        ("refresh_stream", Value::Str(refresh_stream.into())),
        (
            "projection_fields",
            Value::List(
                projection_fields
                    .into_iter()
                    .map(|field| Value::Str(field.into()))
                    .collect(),
            ),
        ),
    ])
}

fn graph_node_type(
    node_type: &str,
    input_ports: Vec<&str>,
    output_ports: Vec<&str>,
    backing_action: &str,
) -> Value {
    value_map([
        ("node_type", Value::Str(node_type.into())),
        (
            "params_schema",
            Value::Str(format!("graph.plan_workflow.{node_type}.params")),
        ),
        (
            "input_ports",
            Value::List(
                input_ports
                    .into_iter()
                    .map(|port| graph_port(port, "input"))
                    .collect(),
            ),
        ),
        (
            "output_ports",
            Value::List(
                output_ports
                    .into_iter()
                    .map(|port| graph_port(port, "output"))
                    .collect(),
            ),
        ),
        ("backing_action", Value::Str(backing_action.into())),
        ("risk", to_value(RiskLevel::Elevated)),
    ])
}

fn graph_port(name: &str, direction: &str) -> Value {
    value_map([
        ("name", Value::Str(name.into())),
        ("direction", Value::Str(direction.into())),
        ("value_type", Value::Str("value".into())),
        ("cardinality", Value::Str("one".into())),
        ("required", Value::Bool(direction == "input")),
    ])
}

fn value_map(items: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Map(
        items
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn to_value<T: Serialize>(value: T) -> Value {
    serde_json::from_value(serde_json::to_value(value).unwrap_or(serde_json::Value::Null))
        .unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn descriptors_include_root_visibility_and_no_raw_shell() {
        let meta = protocol_metadata(1, 1);
        assert!(meta.root_data_authority.root_can_view_all_business_data);
        assert!(!meta.root_data_authority.bypasses_operation_fact_policy);
        assert!(
            meta.actions
                .iter()
                .any(|a| a.id == ACTION_VISIBILITY_STATE_READ)
        );
        assert!(
            meta.actions
                .iter()
                .all(|a| !a.id.contains("raw") && !a.id.contains("shell"))
        );
    }

    #[test]
    fn secret_reveal_is_declared_but_custody_blocked() {
        let reveal = action_descriptors()
            .into_iter()
            .find(|a| a.id == ACTION_SECRET_REVEAL)
            .unwrap();
        assert_eq!(reveal.status, ImplementationStatus::BlockedByCustody);
        assert_eq!(reveal.secret_class, Some(SecretClass::RevealableSecret));
    }

    #[test]
    fn descriptors_are_unique_and_cover_core_domains() {
        let actions = action_descriptors();
        let streams = stream_descriptors();
        let mut ids = BTreeSet::new();
        for action in &actions {
            assert!(
                ids.insert(action.id.clone()),
                "duplicate action {}",
                action.id
            );
        }
        for stream in &streams {
            assert!(
                ids.insert(stream.id.clone()),
                "duplicate stream {}",
                stream.id
            );
        }

        let mut domains = BTreeSet::new();
        for action in &actions {
            domains.insert(action.domain.as_str());
        }
        for stream in &streams {
            domains.insert(stream.domain.as_str());
        }
        for required in [
            "protocol",
            "registry",
            "visibility",
            "secret",
            "state",
            "config",
            "access",
            "runtime",
            "audit",
            "lineage",
            "health",
            "external",
            "pairing",
            "resource",
            "change_set",
            "graph",
        ] {
            assert!(domains.contains(required), "missing domain {required}");
        }
    }

    #[test]
    fn edit_descriptors_are_shape_independent() {
        let Some(Value::Map(descriptor)) = resource_type_descriptor_value("access.user") else {
            panic!("missing access.user resource descriptor")
        };
        let Some(Value::List(fields)) = descriptor.get("fields") else {
            panic!("resource descriptor must include fields")
        };
        assert!(fields.iter().any(|field| {
            field.as_map().is_some_and(|map| {
                matches!(map.get("semantic_kind"), Some(Value::Str(kind)) if kind == "resource_ref")
            })
        }));
        let Some(Value::Map(graph)) = graph_type_descriptor_value("plan.workflow") else {
            panic!("missing plan.workflow graph descriptor")
        };
        assert_eq!(
            graph.get("status"),
            Some(&to_value(ImplementationStatus::Planned))
        );
        assert!(matches!(graph.get("node_types"), Some(Value::List(nodes)) if !nodes.is_empty()));
    }

    #[test]
    fn change_set_actions_are_discoverable_but_planned() {
        let actions = action_descriptors();
        for id in [
            ACTION_CHANGE_SET_CREATE,
            ACTION_CHANGE_SET_UPDATE,
            ACTION_CHANGE_SET_VALIDATE,
            ACTION_CHANGE_SET_DIFF,
            ACTION_CHANGE_SET_DRY_RUN,
            ACTION_CHANGE_SET_APPLY,
            ACTION_CHANGE_SET_DISCARD,
        ] {
            let Some(action) = actions.iter().find(|action| action.id == id) else {
                panic!("missing descriptor {id}")
            };
            assert_eq!(action.status, ImplementationStatus::Planned);
            assert!(
                action
                    .input
                    .fields
                    .iter()
                    .all(|field| field.semantic_kind.is_some())
            );
        }
    }

    #[test]
    fn protected_payload_descriptors_require_step_up() {
        for action in action_descriptors() {
            if matches!(
                action.visibility,
                VisibilityTier::BusinessData
                    | VisibilityTier::ProtectedPayload
                    | VisibilityTier::SecretPlaintext
            ) {
                assert!(
                    action.requires_step_up,
                    "{} exposes {:?} without step-up",
                    action.id, action.visibility
                );
            }
        }
        for stream in stream_descriptors() {
            if matches!(
                stream.visibility,
                VisibilityTier::BusinessData
                    | VisibilityTier::ProtectedPayload
                    | VisibilityTier::SecretPlaintext
            ) {
                assert!(
                    stream.requires_step_up,
                    "{} exposes {:?} without step-up",
                    stream.id, stream.visibility
                );
            }
        }
    }

    #[test]
    fn access_descriptors_match_runtime_authority_boundaries() {
        let actions = action_descriptors();
        let find = |id: &str| {
            actions
                .iter()
                .find(|action| action.id == id)
                .unwrap_or_else(|| panic!("missing descriptor {id}"))
        };

        let user_write = find(ACTION_ACCESS_USER_WRITE_CAS);
        assert!(user_write.required_authority.iter().any(|required| {
            required.verb == "write" && required.target == "state://kernel/console/users/**"
        }));
        let role_write = find(ACTION_ACCESS_ROLE_WRITE_CAS);
        assert!(role_write.required_authority.iter().any(|required| {
            required.verb == "write" && required.target == "state://kernel/console/roles/**"
        }));
        let session_revoke = find(ACTION_ACCESS_SESSION_REVOKE);
        assert!(session_revoke.required_authority.iter().any(|required| {
            required.verb == "write" && required.target == "state://kernel/console/sessions/**"
        }));
        assert!(
            find(ACTION_ACCESS_SESSION_CURRENT_LOGOUT)
                .required_authority
                .is_empty()
        );
    }

    #[test]
    fn extension_descriptors_match_runtime_authority_boundaries() {
        let actions = action_descriptors();
        let find = |id: &str| {
            actions
                .iter()
                .find(|action| action.id == id)
                .unwrap_or_else(|| panic!("missing descriptor {id}"))
        };

        let install = find(ACTION_EXTERNAL_INSTALLATION_INSTALL);
        assert!(install.required_authority.iter().any(|required| {
            required.verb == "write"
                && required.target == "state://kernel/external-installations/**"
        }));
        let start = find(ACTION_EXTERNAL_INSTALLATION_START);
        assert!(start.required_authority.iter().any(|required| {
            required.verb == "read" && required.target == "state://kernel/external-installations/**"
        }));
        assert!(start.required_authority.iter().any(|required| {
            required.verb == "perform" && required.target == "effect://proc/spawn"
        }));
        let stop = find(ACTION_EXTERNAL_INSTALLATION_STOP);
        assert!(stop.required_authority.iter().any(|required| {
            required.verb == "perform" && required.target == "effect://proc/kill"
        }));
        let revoke = find(ACTION_EXTERNAL_INSTALLATION_REVOKE);
        assert!(revoke.required_authority.iter().any(|required| {
            required.verb == "perform" && required.target == "effect://external/revoke"
        }));
    }

    #[test]
    fn pairing_descriptors_use_specific_effect_authority() {
        let actions = action_descriptors();
        for (id, target) in [
            (ACTION_PAIRING_CREATE, "effect://external/pairing/create"),
            (ACTION_PAIRING_APPROVE, "effect://external/pairing/approve"),
            (ACTION_PAIRING_DENY, "effect://external/pairing/deny"),
            (ACTION_PAIRING_REPLACE, "effect://external/pairing/replace"),
        ] {
            let action = actions
                .iter()
                .find(|action| action.id == id)
                .unwrap_or_else(|| panic!("missing descriptor {id}"));
            assert_eq!(action.required_authority.len(), 1);
            assert_eq!(action.required_authority[0].verb, "perform");
            assert_eq!(action.required_authority[0].target, target);
        }
    }
}
