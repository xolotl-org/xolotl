//! Console Protocol DTOs and static registry descriptors.
//!
//! `nexus-console` is the control-plane protocol host. Web UI and third-party
//! panels consume this registry, then issue descriptor-named actions; they do
//! not bind to Rust enum variants or backend internals.

use nexus_types::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: u16 = 1;
pub const SERVER_NAME: &str = "nexus-console";
pub const WIRE_ENCODING: &str = "msgpack+nexus-console-v1";

pub const ACTION_PROTOCOL_DESCRIBE: &str = "protocol.describe";
pub const ACTION_PROTOCOL_REGISTRY_SNAPSHOT: &str = "protocol.registry.snapshot";
pub const ACTION_PROTOCOL_SCHEMA_GET: &str = "protocol.schema.get";
pub const ACTION_REGISTRY_COVERAGE_REPORT: &str = "registry.coverage.report";
pub const ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE: &str = "authority.principal.effective";
pub const ACTION_AUTHORITY_ACTION_MATRIX: &str = "authority.action.matrix";
pub const ACTION_AUTHORITY_RESOURCE_ACCESS: &str = "authority.resource.access";
pub const ACTION_AUTHORITY_WHY_DENIED: &str = "authority.why_denied";
pub const ACTION_VISIBILITY_AUTHORITY_DESCRIBE: &str = "visibility.authority.describe";
pub const ACTION_VISIBILITY_STATE_READ: &str = "visibility.state.read";
pub const ACTION_VISIBILITY_STATE_LIST: &str = "visibility.state.list";
pub const ACTION_SECRET_CATALOG: &str = "secret.catalog";
pub const ACTION_SECRET_REVEAL: &str = "secret.reveal";
pub const ACTION_STATE_SNAPSHOT: &str = "state.snapshot";
pub const ACTION_CONFIG_READ: &str = "config.read";
pub const ACTION_CONFIG_LIST: &str = "config.list";
pub const ACTION_CONFIG_WRITE_CAS: &str = "config.write_cas";
pub const ACTION_ACCESS_USER_READ: &str = "access.user.read";
pub const ACTION_ACCESS_USER_LIST: &str = "access.user.list";
pub const ACTION_ACCESS_USER_WRITE_CAS: &str = "access.user.write_cas";
pub const ACTION_ACCESS_USER_DISABLE: &str = "access.user.disable";
pub const ACTION_ACCESS_ROLE_READ: &str = "access.role.read";
pub const ACTION_ACCESS_ROLE_LIST: &str = "access.role.list";
pub const ACTION_ACCESS_ROLE_WRITE_CAS: &str = "access.role.write_cas";
pub const ACTION_ACCESS_SESSION_CURRENT_LOGOUT: &str = "access.session.current.logout";
pub const ACTION_ACCESS_SESSION_LIST: &str = "access.session.list";
pub const ACTION_ACCESS_SESSION_REVOKE: &str = "access.session.revoke";
pub const ACTION_ACCESS_SESSION_REVOKE_USER: &str = "access.session.revoke_user";
pub const ACTION_RUNTIME_PROCESS_INSPECT: &str = "runtime.process.inspect";
pub const ACTION_AUDIT_FACTS_RECENT: &str = "audit.facts.recent";
pub const ACTION_LINEAGE_TRACE_READ: &str = "lineage.trace.read";
pub const ACTION_LINEAGE_FACT_READ: &str = "lineage.fact.read";
pub const ACTION_LINEAGE_FACT_BY_OPERATION: &str = "lineage.fact.by_operation";
pub const ACTION_HEALTH_SUMMARY: &str = "health.summary";
pub const ACTION_EXTENSIONS_INSTALLATION_INSTALL: &str = "extensions.installation.install";
pub const ACTION_EXTENSIONS_INSTALLATION_UPDATE: &str = "extensions.installation.update";
pub const ACTION_EXTENSIONS_INSTALLATION_START: &str = "extensions.installation.start";
pub const ACTION_EXTENSIONS_INSTALLATION_STOP: &str = "extensions.installation.stop";
pub const ACTION_EXTENSIONS_INSTALLATION_REVOKE: &str = "extensions.installation.revoke";
pub const ACTION_PAIRING_CREATE: &str = "pairing.create";
pub const ACTION_PAIRING_APPROVE: &str = "pairing.approve";
pub const ACTION_PAIRING_DENY: &str = "pairing.deny";
pub const ACTION_PAIRING_REPLACE: &str = "pairing.replace";

pub const STREAM_STATE_WATCH: &str = "state.watch";
pub const STREAM_AUDIT_FACTS: &str = "audit.facts.stream";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClientHello {
    pub protocol_version: u16,
    #[serde(default)]
    pub client_name: Option<String>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionCall {
    pub action: String,
    #[serde(default)]
    pub input: JsonBytes,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StreamCall {
    pub stream: String,
    #[serde(default)]
    pub input: JsonBytes,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    #[serde(default)]
    pub since_rev: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrincipalSummary {
    pub username: String,
    pub identity_path: String,
    pub mfa_level: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ClientFrame {
    Hello { hello: ClientHello },
    Auth { token: String },
    Call { id: u64, call: ActionCall },
    Subscribe { id: u64, stream: StreamCall },
    Unsubscribe { id: u64 },
    Ping { nonce: u64 },
}

/// JSON-encoded [`Value`] string. The outer frame is MessagePack; this inner
/// value envelope keeps Nexus's untagged `Value` representation explicit for
/// clients in any language.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonBytes(pub String);

impl Eq for JsonBytes {}

impl Default for JsonBytes {
    fn default() -> Self {
        Self::from_value(&Value::Null)
    }
}

impl JsonBytes {
    pub fn from_value(v: &Value) -> Self {
        Self(serde_json::to_string(v).unwrap_or_default())
    }

    pub fn try_to_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::from_str(&self.0)
    }

    pub fn to_value(&self) -> Value {
        self.try_to_value().unwrap_or(Value::Null)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionResult {
    pub output: Option<JsonBytes>,
    pub server_rev: u64,
}

impl ActionResult {
    pub fn empty(server_rev: u64) -> Self {
        Self {
            output: None,
            server_rev,
        }
    }

    pub fn value(value: Value, server_rev: u64) -> Self {
        Self {
            output: Some(JsonBytes::from_value(&value)),
            server_rev,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ServerFrame {
    HelloAccepted {
        metadata: ProtocolMetadata,
    },
    Authenticated {
        principal: PrincipalSummary,
        metadata: ProtocolMetadata,
    },
    Reply {
        id: u64,
        result: ActionResult,
    },
    Event {
        stream: u64,
        event: ConsoleEvent,
    },
    Pong {
        nonce: u64,
    },
    Error {
        id: Option<u64>,
        code: ConsoleErrorCode,
        message: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ConsoleEvent {
    StateSet { path: String, value: JsonBytes },
    StateAppend { path: String, item: JsonBytes },
    StateDelete { path: String },
    Audit { fact: JsonBytes },
    SubscriptionClosed { reason: String },
}

impl Eq for ConsoleEvent {}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ConsoleErrorCode {
    BadFrame,
    NotAuthenticated,
    Unauthorized,
    Forbidden,
    Conflict,
    BadRequest,
    RateLimited,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolMetadata {
    pub protocol_version: u16,
    pub server_name: String,
    pub encoding: String,
    pub server_rev: u64,
    pub registry_rev: u64,
    pub root_data_authority: RootDataAuthority,
    pub actions: Vec<ActionDescriptor>,
    pub streams: Vec<StreamDescriptor>,
    pub visibility_tiers: Vec<VisibilityTier>,
    pub secret_classes: Vec<SecretClass>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RootDataAuthority {
    pub root_can_view_all_business_data: bool,
    pub visibility_step_up_is_gate_not_permission_denial: bool,
    pub bypasses_operation_fact_policy: bool,
    pub vault_secret_custody_is_separate: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActionDescriptor {
    pub id: String,
    pub domain: String,
    pub kind: ActionKind,
    pub risk: RiskLevel,
    pub status: ImplementationStatus,
    pub visibility: VisibilityTier,
    pub secret_class: Option<SecretClass>,
    pub requires_step_up: bool,
    pub required_authority: Vec<RequiredAuthority>,
    pub input: SchemaDescriptor,
    pub output: SchemaDescriptor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StreamDescriptor {
    pub id: String,
    pub domain: String,
    pub status: ImplementationStatus,
    pub visibility: VisibilityTier,
    pub requires_step_up: bool,
    pub required_authority: Vec<RequiredAuthority>,
    pub input: SchemaDescriptor,
    pub event: SchemaDescriptor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequiredAuthority {
    pub verb: String,
    pub target: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SchemaDescriptor {
    pub schema_id: String,
    pub value_kind: String,
    #[serde(default)]
    pub fields: Vec<FieldDescriptor>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldDescriptor {
    pub name: String,
    pub kind: String,
    pub required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Protocol,
    View,
    Mutation,
    Secret,
    Visibility,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Elevated,
    BreakGlass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatus {
    Implemented,
    Declared,
    BlockedByCustody,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VisibilityTier {
    PublicControl,
    ManagementState,
    BusinessData,
    ProtectedPayload,
    SecretMetadata,
    SecretPlaintext,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretClass {
    RevealableSecret,
    NonRecoverableSecret,
    OneTimeSecret,
}

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
    }
}

pub fn protocol_metadata_value(server_rev: u64, registry_rev: u64) -> Value {
    to_value(protocol_metadata(server_rev, registry_rev))
}

pub fn coverage_report_value(server_rev: u64, registry_rev: u64) -> Value {
    let actions = action_descriptors();
    let streams = stream_descriptors();
    let mut domains: BTreeMap<String, (usize, usize, usize)> = BTreeMap::new();
    for action in &actions {
        let entry = domains.entry(action.domain.clone()).or_default();
        entry.0 += 1;
        if action.status == ImplementationStatus::Implemented {
            entry.1 += 1;
        }
        if action.status == ImplementationStatus::BlockedByCustody {
            entry.2 += 1;
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
        .map(|(domain, (declared, implemented, custody_blocked))| {
            let mut row = BTreeMap::new();
            row.insert("domain".into(), Value::Str(domain));
            row.insert("declared".into(), Value::Int(declared as i64));
            row.insert("implemented".into(), Value::Int(implemented as i64));
            row.insert("custody_blocked".into(), Value::Int(custody_blocked as i64));
            Value::Map(row)
        })
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

pub fn descriptor_value(action_id: &str) -> Option<Value> {
    action_descriptors()
        .into_iter()
        .find(|d| d.id == action_id)
        .map(to_value)
}

pub fn secret_catalog_value() -> Value {
    let mut rows = Vec::new();
    rows.push(secret_row(
        "state://vault/console/*/password",
        SecretClass::NonRecoverableSecret,
        "password hashes are verifiable, not reversible; root may reset credentials",
    ));
    rows.push(secret_row(
        "state://vault/console/sessions/*",
        SecretClass::NonRecoverableSecret,
        "session token hashes are revocable, not revealable",
    ));
    rows.push(secret_row(
        "state://vault/console/*/totp",
        SecretClass::NonRecoverableSecret,
        "TOTP seeds are custody secrets; root may rotate/reset",
    ));
    rows.push(secret_row(
        "pairing.display_secret",
        SecretClass::OneTimeSecret,
        "pairing display secrets are available only on the create/replace edge",
    ));
    Value::List(rows)
}

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
                vec!["audit/fact streams require StreamCall.scope, justification, and ttl_ms"],
            ),
            event: schema("stream.audit_facts.event", "console_event", vec![], vec![]),
        },
    ]
}

pub fn action_descriptors() -> Vec<ActionDescriptor> {
    vec![
        action(
            ACTION_PROTOCOL_DESCRIBE,
            "protocol",
            ActionKind::Protocol,
            RiskLevel::Low,
            VisibilityTier::PublicControl,
            false,
            vec![],
            schema("protocol.empty", "null", vec![], vec![]),
            schema("protocol.metadata", "map", vec![], vec![]),
        ),
        action(
            ACTION_PROTOCOL_REGISTRY_SNAPSHOT,
            "protocol",
            ActionKind::Protocol,
            RiskLevel::Low,
            VisibilityTier::PublicControl,
            false,
            vec![],
            schema("protocol.empty", "null", vec![], vec![]),
            schema("protocol.metadata", "map", vec![], vec![]),
        ),
        action(
            ACTION_PROTOCOL_SCHEMA_GET,
            "protocol",
            ActionKind::Protocol,
            RiskLevel::Low,
            VisibilityTier::PublicControl,
            false,
            vec![],
            schema(
                "protocol.schema_get.input",
                "map",
                vec![field("action", "string", true)],
                vec![],
            ),
            schema("protocol.action_descriptor", "map", vec![], vec![]),
        ),
        action(
            ACTION_REGISTRY_COVERAGE_REPORT,
            "registry",
            ActionKind::View,
            RiskLevel::Low,
            VisibilityTier::ManagementState,
            false,
            vec![],
            schema("registry.coverage.input", "null", vec![], vec![]),
            schema("registry.coverage.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE,
            "authority",
            ActionKind::View,
            RiskLevel::Low,
            VisibilityTier::ManagementState,
            false,
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
            RiskLevel::Low,
            VisibilityTier::ManagementState,
            false,
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
            RiskLevel::Low,
            VisibilityTier::ManagementState,
            false,
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
            RiskLevel::Low,
            VisibilityTier::ManagementState,
            false,
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
            RiskLevel::Low,
            VisibilityTier::PublicControl,
            false,
            vec![],
            schema("visibility.authority.input", "null", vec![], vec![]),
            schema("visibility.authority.output", "map", vec![], vec![]),
        ),
        action(
            ACTION_VISIBILITY_STATE_READ,
            "visibility",
            ActionKind::Visibility,
            RiskLevel::Elevated,
            VisibilityTier::BusinessData,
            true,
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
            RiskLevel::Elevated,
            VisibilityTier::BusinessData,
            true,
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
            RiskLevel::Low,
            VisibilityTier::SecretMetadata,
            false,
            None,
            ImplementationStatus::Implemented,
        ),
        secret_action(
            ACTION_SECRET_REVEAL,
            RiskLevel::BreakGlass,
            VisibilityTier::SecretPlaintext,
            true,
            Some(SecretClass::RevealableSecret),
            ImplementationStatus::BlockedByCustody,
        ),
        action(
            ACTION_STATE_SNAPSHOT,
            "state",
            ActionKind::View,
            RiskLevel::Elevated,
            VisibilityTier::ManagementState,
            false,
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
            RiskLevel::Low,
            VisibilityTier::ManagementState,
            false,
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
            RiskLevel::Low,
            VisibilityTier::ManagementState,
            false,
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
            RiskLevel::Elevated,
            VisibilityTier::ManagementState,
            false,
            vec![authority("write", "state://kernel/**")],
            schema(
                "config.write_cas.input",
                "map",
                vec![
                    field("path", "path", true),
                    field("value", "value", true),
                    field("expected_version", "u64|null", false),
                ],
                vec![],
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
            RiskLevel::Elevated,
            VisibilityTier::ProtectedPayload,
            true,
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
            RiskLevel::Elevated,
            VisibilityTier::ProtectedPayload,
            true,
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
            RiskLevel::Elevated,
            VisibilityTier::ProtectedPayload,
            true,
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
            RiskLevel::Elevated,
            VisibilityTier::ProtectedPayload,
            true,
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
            RiskLevel::Elevated,
            VisibilityTier::ProtectedPayload,
            true,
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
            RiskLevel::Low,
            VisibilityTier::ManagementState,
            false,
            vec![authority("read", "state://kernel/**")],
            schema("health.summary.input", "null", vec![], vec![]),
            schema("health.summary.output", "map", vec![], vec![]),
        ),
        extension_action(
            ACTION_EXTENSIONS_INSTALLATION_INSTALL,
            true,
            vec![
                field("id", "string", true),
                field("def", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        extension_action(
            ACTION_EXTENSIONS_INSTALLATION_UPDATE,
            true,
            vec![
                field("id", "string", true),
                field("def", "value", true),
                field("expected_version", "u64|null", false),
            ],
        ),
        extension_action(
            ACTION_EXTENSIONS_INSTALLATION_START,
            true,
            vec![field("id", "string", true)],
        ),
        extension_action(
            ACTION_EXTENSIONS_INSTALLATION_STOP,
            true,
            vec![field("id", "string", true)],
        ),
        extension_action(
            ACTION_EXTENSIONS_INSTALLATION_REVOKE,
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
        if requires_step_up {
            RiskLevel::Elevated
        } else {
            RiskLevel::Low
        },
        VisibilityTier::ManagementState,
        requires_step_up,
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
        "extensions",
        ActionKind::Mutation,
        RiskLevel::Elevated,
        VisibilityTier::ManagementState,
        requires_step_up,
        required_authority,
        schema(&format!("{id}.input"), "map", fields, vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    )
}

fn extension_authority(id: &str) -> Vec<RequiredAuthority> {
    match id {
        ACTION_EXTENSIONS_INSTALLATION_INSTALL | ACTION_EXTENSIONS_INSTALLATION_UPDATE => {
            vec![authority(
                "write",
                "state://kernel/extension-installations/**",
            )]
        }
        ACTION_EXTENSIONS_INSTALLATION_START => vec![
            authority("read", "state://kernel/extension-installations/**"),
            authority("perform", "effect://proc/spawn"),
        ],
        ACTION_EXTENSIONS_INSTALLATION_STOP => {
            vec![authority("perform", "effect://proc/kill")]
        }
        ACTION_EXTENSIONS_INSTALLATION_REVOKE => {
            vec![authority("perform", "effect://extension/revoke")]
        }
        _ => vec![authority(
            "write",
            "state://kernel/extension-installations/**",
        )],
    }
}

fn pairing_action(id: &str, fields: Vec<FieldDescriptor>) -> ActionDescriptor {
    action(
        id,
        "pairing",
        ActionKind::Mutation,
        RiskLevel::Elevated,
        VisibilityTier::ManagementState,
        true,
        pairing_authority(id),
        schema(&format!("{id}.input"), "map", fields, vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    )
}

fn pairing_authority(id: &str) -> Vec<RequiredAuthority> {
    let target = match id {
        ACTION_PAIRING_CREATE => "effect://extension/pairing/create",
        ACTION_PAIRING_APPROVE => "effect://extension/pairing/approve",
        ACTION_PAIRING_DENY => "effect://extension/pairing/deny",
        ACTION_PAIRING_REPLACE => "effect://extension/pairing/replace",
        _ => "effect://extension/pairing/**",
    };
    vec![authority("perform", target)]
}

fn secret_action(
    id: &str,
    risk: RiskLevel,
    visibility: VisibilityTier,
    requires_step_up: bool,
    secret_class: Option<SecretClass>,
    status: ImplementationStatus,
) -> ActionDescriptor {
    let mut d = action(
        id,
        "secret",
        ActionKind::Secret,
        risk,
        visibility,
        requires_step_up,
        vec![],
        schema(&format!("{id}.input"), "map", vec![], vec![]),
        schema(&format!("{id}.output"), "value", vec![], vec![]),
    );
    d.secret_class = secret_class;
    d.status = status;
    d
}

fn action(
    id: &str,
    domain: &str,
    kind: ActionKind,
    risk: RiskLevel,
    visibility: VisibilityTier,
    requires_step_up: bool,
    required_authority: Vec<RequiredAuthority>,
    input: SchemaDescriptor,
    output: SchemaDescriptor,
) -> ActionDescriptor {
    ActionDescriptor {
        id: id.into(),
        domain: domain.into(),
        kind,
        risk,
        status: ImplementationStatus::Implemented,
        visibility,
        secret_class: None,
        requires_step_up,
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
    }
}

fn secret_row(path: &str, class: SecretClass, policy: &str) -> Value {
    let mut row = BTreeMap::new();
    row.insert("path".into(), Value::Str(path.into()));
    row.insert("class".into(), to_value(class));
    row.insert("policy".into(), Value::Str(policy.into()));
    Value::Map(row)
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
            "extensions",
            "pairing",
        ] {
            assert!(domains.contains(required), "missing domain {required}");
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

        let install = find(ACTION_EXTENSIONS_INSTALLATION_INSTALL);
        assert!(install.required_authority.iter().any(|required| {
            required.verb == "write"
                && required.target == "state://kernel/extension-installations/**"
        }));
        let start = find(ACTION_EXTENSIONS_INSTALLATION_START);
        assert!(start.required_authority.iter().any(|required| {
            required.verb == "read"
                && required.target == "state://kernel/extension-installations/**"
        }));
        assert!(start.required_authority.iter().any(|required| {
            required.verb == "perform" && required.target == "effect://proc/spawn"
        }));
        let stop = find(ACTION_EXTENSIONS_INSTALLATION_STOP);
        assert!(stop.required_authority.iter().any(|required| {
            required.verb == "perform" && required.target == "effect://proc/kill"
        }));
        let revoke = find(ACTION_EXTENSIONS_INSTALLATION_REVOKE);
        assert!(revoke.required_authority.iter().any(|required| {
            required.verb == "perform" && required.target == "effect://extension/revoke"
        }));
    }

    #[test]
    fn pairing_descriptors_use_specific_effect_authority() {
        let actions = action_descriptors();
        for (id, target) in [
            (ACTION_PAIRING_CREATE, "effect://extension/pairing/create"),
            (ACTION_PAIRING_APPROVE, "effect://extension/pairing/approve"),
            (ACTION_PAIRING_DENY, "effect://extension/pairing/deny"),
            (ACTION_PAIRING_REPLACE, "effect://extension/pairing/replace"),
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
