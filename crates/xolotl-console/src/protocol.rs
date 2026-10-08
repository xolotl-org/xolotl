//! Console Protocol DTOs and static registry descriptors.

mod failure;
pub use failure::{ConsoleFailure, ConsoleFinalizationError, OutcomeUnknownDetail};
mod execution_reference;
pub use execution_reference::ExecutionReference;

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::OnceLock};
use xolotl_types::{TaintSet, TaintSource, UnresolvedOperations, Value};

/// Current Console Protocol major wire version.
pub const PROTOCOL_VERSION: u16 = xolotl_console_protocol::CONSOLE_PROTOCOL_VERSION as u16;
// Protocol identifiers have one owner; keep the host-facing API as re-exports.
pub use xolotl_console_protocol::{
    ACTION_ACCESS_ROLE_LIST, ACTION_ACCESS_ROLE_READ, ACTION_ACCESS_ROLE_WRITE_CAS,
    ACTION_ACCESS_SESSION_CURRENT_LOGOUT, ACTION_ACCESS_SESSION_LIST, ACTION_ACCESS_SESSION_REVOKE,
    ACTION_ACCESS_SESSION_REVOKE_USER, ACTION_ACCESS_USER_DISABLE, ACTION_ACCESS_USER_LIST,
    ACTION_ACCESS_USER_READ, ACTION_ACCESS_USER_WRITE_CAS, ACTION_AUDIT_FACTS_RECENT,
    ACTION_AUTHORITY_ACTION_EXPLAIN, ACTION_AUTHORITY_ACTION_MATRIX,
    ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE, ACTION_AUTHORITY_RESOURCE_ACCESS, ACTION_CONFIG_LIST,
    ACTION_CONFIG_READ, ACTION_CONFIG_WRITE_CAS, ACTION_EXTERNAL_INSTALLATION_INSTALL,
    ACTION_EXTERNAL_INSTALLATION_LIST, ACTION_EXTERNAL_INSTALLATION_READ,
    ACTION_EXTERNAL_INSTALLATION_REVOKE, ACTION_EXTERNAL_INSTALLATION_START,
    ACTION_EXTERNAL_INSTALLATION_STOP, ACTION_EXTERNAL_INSTALLATION_UNINSTALL,
    ACTION_EXTERNAL_INSTALLATION_UPDATE, ACTION_EXTERNAL_MANIFEST_LIST,
    ACTION_EXTERNAL_MANIFEST_READ, ACTION_EXTERNAL_MANIFEST_WRITE_CAS,
    ACTION_EXTERNAL_SOURCE_CLAIM_INSPECT, ACTION_EXTERNAL_SOURCE_EVENT_DECISION_INSPECT,
    ACTION_FEDERATION_EXPORT_LIST, ACTION_FEDERATION_EXPORT_READ,
    ACTION_FEDERATION_EXPORT_WRITE_CAS, ACTION_FEDERATION_PEER_ADMISSION_READ,
    ACTION_FEDERATION_PEER_ADMISSION_WRITE_CAS, ACTION_FEDERATION_PEER_LIST,
    ACTION_FEDERATION_PEER_READ, ACTION_FEDERATION_PEER_WRITE_CAS, ACTION_HEALTH_SUMMARY,
    ACTION_INFERENCE_BACKEND_LIST, ACTION_INFERENCE_BACKEND_READ,
    ACTION_INFERENCE_BACKEND_WRITE_CAS, ACTION_INFERENCE_GROUP_LIST, ACTION_INFERENCE_GROUP_READ,
    ACTION_INFERENCE_GROUP_WRITE_CAS, ACTION_INFERENCE_MODEL_LIST, ACTION_INFERENCE_MODEL_READ,
    ACTION_INFERENCE_MODEL_WRITE_CAS, ACTION_INFERENCE_ROUTING_READ,
    ACTION_INFERENCE_ROUTING_WRITE_CAS, ACTION_LINEAGE_FACT_READ, ACTION_LINEAGE_TRACE_READ,
    ACTION_PAIRING_APPROVE, ACTION_PAIRING_CREATE, ACTION_PAIRING_DENY,
    ACTION_PROJECTION_IN_PROCESS_STATUS_LIST, ACTION_PROJECTION_IN_PROCESS_STATUS_READ,
    ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET, ACTION_PROTOCOL_DESCRIBE,
    ACTION_PROTOCOL_REGISTRY_SNAPSHOT, ACTION_RESOURCE_TYPE_DESCRIBE, ACTION_RESOURCE_TYPE_LIST,
    ACTION_RESOURCE_VIEW_DESCRIBE, ACTION_RUNTIME_DESCRIBE, ACTION_RUNTIME_EXECUTION_CANCEL,
    ACTION_RUNTIME_EXECUTION_FORGET, ACTION_RUNTIME_EXECUTION_GET, ACTION_RUNTIME_EXECUTION_LIST,
    ACTION_RUNTIME_EXECUTION_OUTPUT_READ, ACTION_RUNTIME_EXECUTION_RESULT,
    ACTION_RUNTIME_OPERATION_INVOKE, ACTION_RUNTIME_OPERATION_SUBMIT,
    ACTION_RUNTIME_PROCESS_INSPECT, ACTION_RUNTIME_PROGRAM_RUN, ACTION_RUNTIME_PROGRAM_SUBMIT,
    ACTION_RUNTIME_RESOURCE_DESCRIBE, ACTION_RUNTIME_SUBMISSION_LOOKUP, ACTION_SECRET_CATALOG,
    ACTION_STATE_SNAPSHOT, ACTION_VISIBILITY_AUTHORITY_DESCRIBE, ACTION_VISIBILITY_STATE_LIST,
    ACTION_VISIBILITY_STATE_READ, SERVER_NAME, STREAM_AUDIT_FACTS, STREAM_RUNTIME_OPERATION,
    STREAM_RUNTIME_PROGRAM, STREAM_STATE_WATCH, SUBPROTOCOL, WIRE_ENCODING,
};

/// Initial client hello identifying the Console protocol version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello {
    /// Client-supported protocol version.
    pub protocol_version: u16,
    /// Optional client application name for audit and diagnostics.
    pub client_name: Option<String>,
}

impl Default for ClientHello {
    fn default() -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            client_name: None,
        }
    }
}

/// One descriptor-named action invocation from a console client.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActionCall {
    /// Action id, usually one of the `ACTION_*` constants.
    pub action: String,
    /// Xolotl value passed as action input.
    pub input: Value,
    /// Optional target scope for break-glass or visibility-gated actions.
    pub scope: Option<String>,
    /// Operator justification for high-risk actions.
    pub justification: Option<String>,
    /// Optional temporary authority duration for scoped access.
    pub ttl_ms: Option<u64>,
    /// Optional descriptor revision precondition; stale revisions are rejected.
    pub registry_rev: Option<u64>,
}

/// One stream subscription request from a console client.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StreamCall {
    /// Stream id, usually one of the `STREAM_*` constants.
    pub stream: String,
    /// Stream input/filter value.
    pub input: Value,
    /// Optional target scope for visibility-gated streams.
    pub scope: Option<String>,
    /// Operator justification for sensitive streams.
    pub justification: Option<String>,
    /// Optional temporary authority duration for scoped streaming.
    pub ttl_ms: Option<u64>,
    /// Optional precondition on descriptors, host module revisions and budgets.
    pub registry_rev: Option<u64>,
}

/// Compact identity summary returned after authentication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrincipalSummary {
    /// Console username.
    pub username: String,
    /// Xolotl identity path for the principal.
    pub identity_path: String,
    /// Authenticated MFA level.
    pub mfa_level: u8,
}

/// Frames sent by the console client over the management WebSocket.
#[derive(Clone, Debug, Eq, PartialEq)]
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

/// Result of one action invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionResult {
    /// Optional Xolotl value output.
    pub output: Option<Value>,
    /// Observed Fact append cursor, or zero when observation storage is absent.
    /// Availability is reflected by the host's action and stream discovery.
    pub server_rev: u64,
    /// Descriptor registry used for this response.
    pub registry_rev: u64,
    /// Allocated runtime execution, when this action executed a program.
    /// A guarded root submission retry retains the original reference, including
    /// after its job metadata or output is retired; it never allocates a new job.
    pub execution: Option<Box<ExecutionReference>>,
    /// Host-observed effects that may still need external reconciliation.
    /// Program success does not imply this set is empty.
    pub unresolved_operations: Option<Box<UnresolvedOperations>>,
}

impl ActionResult {
    /// Construct an action result with no output body.
    pub fn empty(server_rev: u64, registry_rev: u64) -> Self {
        Self {
            output: None,
            server_rev,
            registry_rev,
            execution: None,
            unresolved_operations: None,
        }
    }

    /// Construct an action result carrying one Xolotl value.
    pub fn value(value: Value, server_rev: u64, registry_rev: u64) -> Self {
        Self {
            output: Some(value),
            server_rev,
            registry_rev,
            execution: None,
            unresolved_operations: None,
        }
    }
}

/// Frames sent by the console server over the management WebSocket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerFrame {
    /// Protocol negotiation succeeded.
    HelloAccepted {
        /// Compact server metadata and the revision for catalog discovery.
        metadata: ProtocolGreeting,
        /// Configured policy for this adapter, independent of service discovery.
        transport: TransportSecuritySummary,
    },
    /// Authentication succeeded.
    Authenticated {
        /// Authenticated principal summary.
        principal: PrincipalSummary,
        /// Refreshed compact server metadata and catalog revision.
        metadata: ProtocolGreeting,
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
        /// Safe failure, including any known recovery information.
        failure: ConsoleFailure,
    },
}

/// Coarse State lineage categories. Labels and protected source paths are
/// deliberately omitted: subscribing to a business path does not authorize
/// inspection of the paths or installation names that contributed to it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StateSourceSummary {
    /// At least one source was recorded; false means the event is pristine.
    pub tainted: bool,
    /// Program-authored data contributed to the mutation.
    pub author_constant: bool,
    /// Model output contributed to the mutation.
    pub model_output: bool,
    /// An admitted inbound payload contributed to the mutation.
    pub inbound: bool,
    /// Fetched content contributed to the mutation.
    pub fetched: bool,
    /// A protected source contributed; its path is never disclosed here.
    pub protected: bool,
}

impl From<&TaintSet> for StateSourceSummary {
    fn from(taint: &TaintSet) -> Self {
        let mut summary = Self {
            tainted: !taint.is_pristine(),
            ..Self::default()
        };
        for source in taint.sources() {
            match source {
                TaintSource::AuthorConstant => summary.author_constant = true,
                TaintSource::ModelOutput => summary.model_output = true,
                TaintSource::Inbound { .. } => summary.inbound = true,
                TaintSource::Fetched { .. } => summary.fetched = true,
                TaintSource::Protected { .. } => summary.protected = true,
            }
        }
        summary
    }
}

/// Event delivered on a subscribed console stream.
#[derive(Clone, Debug, PartialEq)]
pub enum ConsoleEvent {
    /// A state value was set.
    StateSet {
        /// State path that changed.
        path: xolotl_types::Path,
        /// New value.
        value: Value,
        /// Source categories without private labels or protected paths.
        source: StateSourceSummary,
    },
    /// An item was appended to a state sequence.
    StateAppend {
        /// State sequence path that changed.
        path: xolotl_types::Path,
        /// Appended item.
        item: Value,
        /// Source categories without private labels or protected paths.
        source: StateSourceSummary,
    },
    /// An exact prefix was removed from a state sequence before one append.
    StateDropPrefixAppend {
        /// State sequence path that changed.
        path: xolotl_types::Path,
        /// Number of leading members removed.
        removed: u64,
        /// Appended item.
        item: Value,
        /// Source categories of the resulting sequence.
        source: StateSourceSummary,
    },
    /// A state value was deleted.
    StateDelete {
        /// State path that was deleted.
        path: xolotl_types::Path,
        /// Source categories without private labels or protected paths.
        source: StateSourceSummary,
    },
    /// A current Fact projection was observed after an append or outcome update.
    Audit {
        /// Fact projection value; replace the client's row with the same op_id.
        fact: Value,
    },
    /// A runtime execution event with a discriminated, lossless value envelope.
    Runtime {
        /// `kind` selects started, output, operation_finished, or finished.
        event: Value,
    },
    /// Server closed the subscription.
    SubscriptionClosed {
        /// Closure reason.
        reason: String,
        /// Structured service failure when closure follows a failed subscription.
        failure: Option<Box<ConsoleFailure>>,
    },
}

impl Eq for ConsoleEvent {}

impl From<xolotl_state::StateEvent> for ConsoleEvent {
    fn from(event: xolotl_state::StateEvent) -> Self {
        match event {
            xolotl_state::StateEvent::Set { path, value, taint } => Self::StateSet {
                path,
                value,
                source: StateSourceSummary::from(&taint),
            },
            xolotl_state::StateEvent::Append { path, item, taint } => Self::StateAppend {
                path,
                item,
                source: StateSourceSummary::from(&taint),
            },
            xolotl_state::StateEvent::DropPrefixAppend {
                path,
                removed,
                item,
                taint,
            } => Self::StateDropPrefixAppend {
                path,
                removed,
                item,
                source: StateSourceSummary::from(&taint),
            },
            xolotl_state::StateEvent::Delete { path, taint } => Self::StateDelete {
                path,
                source: StateSourceSummary::from(&taint),
            },
        }
    }
}

/// Stable error codes returned by the Console Protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleErrorCode {
    /// Frame was malformed or out of sequence.
    BadFrame,
    /// Session is missing or invalid.
    NotAuthenticated,
    /// Request is explicitly forbidden by policy or visibility rules.
    Forbidden,
    /// Caller must complete MFA/step-up before this action can run.
    StepUpRequired,
    /// Compare-and-swap or revision conflict.
    Conflict,
    /// Request input failed validation.
    BadRequest,
    /// Domain validation rejected a proposed management change.
    AdmissionRejected,
    /// Supplied registry revision is stale; refresh discovery before retrying.
    RegistryChanged,
    /// Request exceeded rate limits.
    RateLimited,
    /// An effect may have started, but the host cannot establish its outcome.
    OutcomeUnknown,
    /// Server-side failure.
    Internal,
}

/// Compact negotiation and host metadata. Fetch `protocol.registry.snapshot`
/// for action and stream schemas; a greeting never implies catalog delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolGreeting {
    /// Accepted wire protocol version.
    pub protocol_version: u16,
    /// Server identifier.
    pub server_name: String,
    /// Selected wire encoding.
    pub encoding: String,
    /// Observed Fact append cursor, or zero when observation storage is absent.
    /// This is not a State or execution revision.
    pub server_rev: u64,
    /// Revision used for descriptor preconditions.
    pub registry_rev: u64,
    /// Observation time in milliseconds since the Unix epoch.
    pub server_time_ms: u64,
}

/// Adapter-owned, low-leak transport policy, shared by HTTP manifests and WS Hello.
/// This describes configured admission; it does not attest end-to-end TLS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransportSecuritySummary {
    /// Host-declared transport security mode.
    pub mode: String,
    /// Whether explicit unsafe transport relaxations are enabled.
    pub unsafe_transport: bool,
    /// Names of enabled relaxations, without proxy addresses or other private config.
    pub relaxations: Vec<String>,
}

/// Complete authenticated catalog returned by `protocol.registry.snapshot`.
/// Descriptor values use the same schemas as server-side input validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistrySnapshot {
    /// Protocol identity, current revisions and observed service state.
    #[serde(flatten)]
    pub protocol: ProtocolGreeting,
    /// Root visibility authority contract.
    pub root_data_authority: RootDataAuthority,
    /// Discoverable action contracts.
    pub actions: Vec<ActionDescriptor>,
    /// Discoverable stream contracts.
    pub streams: Vec<StreamDescriptor>,
    /// Known visibility tiers.
    pub visibility_tiers: Vec<VisibilityTier>,
    /// Known secret custody classes.
    pub secret_classes: Vec<SecretClass>,
}

/// Root-data-authority invariants exposed by the Console Protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    /// Default visibility tier; optional payload expansions declare additional gates in input notes.
    pub visibility: VisibilityTier,
    /// Whether the action requires MFA/step-up.
    pub requires_step_up: bool,
    /// Authority templates; concrete targets and optional sections are resolved at invocation.
    pub authority_templates: Vec<AuthorityTemplate>,
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
    /// Maximum visibility tier emitted by the stream.
    pub visibility: VisibilityTier,
    /// Whether the stream requires MFA/step-up.
    pub requires_step_up: bool,
    /// Authority templates; concrete stream targets are authorized at subscription time.
    pub authority_templates: Vec<AuthorityTemplate>,
    /// Stream input/filter schema descriptor.
    pub input: SchemaDescriptor,
    /// Stream event schema descriptor.
    pub event: SchemaDescriptor,
}

/// One authority template associated with a descriptor, including optional reads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorityTemplate {
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
    /// Referenced schemas (for example snapshot sections or execution records).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub definitions: Vec<SchemaDescriptor>,
    /// Map field selecting a variant; its string value indexes `variants`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<String>,
    /// Discriminator value to schema id in the enclosing definition scope.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub variants: BTreeMap<String, String>,
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
    /// Maximum list length, enforced before validating its entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u32>,
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
}

/// Secret custody class.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretClass {
    /// Secret is stored in non-recoverable form.
    NonRecoverableSecret,
    /// Secret is available only at a display edge and then consumed.
    OneTimeSecret,
}

/// Build compact negotiation metadata from the host's revision and clock snapshot.
pub fn protocol_greeting(
    server_rev: u64,
    registry_rev: u64,
    server_time_ms: u64,
) -> ProtocolGreeting {
    ProtocolGreeting {
        protocol_version: PROTOCOL_VERSION,
        server_name: SERVER_NAME.into(),
        encoding: WIRE_ENCODING.into(),
        server_rev,
        registry_rev,
        server_time_ms,
    }
}

/// Build the complete registry snapshot for the supplied revisions.
pub fn registry_snapshot(
    server_rev: u64,
    registry_rev: u64,
    server_time_ms: u64,
) -> RegistrySnapshot {
    RegistrySnapshot {
        protocol: protocol_greeting(server_rev, registry_rev, server_time_ms),
        root_data_authority: root_data_authority(),
        actions: action_descriptors().to_vec(),
        streams: stream_descriptors().to_vec(),
        visibility_tiers: vec![
            VisibilityTier::PublicControl,
            VisibilityTier::ManagementState,
            VisibilityTier::BusinessData,
            VisibilityTier::ProtectedPayload,
            VisibilityTier::SecretMetadata,
        ],
        secret_classes: vec![
            SecretClass::NonRecoverableSecret,
            SecretClass::OneTimeSecret,
        ],
    }
}

pub(crate) const fn root_data_authority() -> RootDataAuthority {
    RootDataAuthority {
        root_can_view_all_business_data: true,
        visibility_step_up_is_gate_not_permission_denial: true,
        bypasses_operation_fact_policy: false,
        vault_secret_custody_is_separate: true,
    }
}

/// Convert the complete descriptor registry into a Xolotl [`Value`].
pub(crate) fn registry_snapshot_to_value(snapshot: RegistrySnapshot) -> Value {
    to_value(snapshot)
}

/// Serialize one action descriptor for wire output.
pub(crate) fn action_descriptor_to_value(descriptor: &ActionDescriptor) -> Value {
    to_value(descriptor)
}

mod actions;
pub(crate) use actions::MAX_SNAPSHOT_SECTIONS;
pub use actions::action_descriptors;

mod resources;
pub(crate) use resources::{
    resource_type_registry, resource_type_summaries, resource_view_registry, secret_catalog_value,
    visibility_authority_value,
};

mod streams;
pub use streams::stream_descriptors;

fn is_false(value: &bool) -> bool {
    !*value
}

fn to_value<T: Serialize>(value: T) -> Value {
    let json = match serde_json::to_value(value) {
        Ok(json) => json,
        Err(error) => {
            tracing::error!(?error, "console protocol descriptor serialization failed");
            return Value::null();
        }
    };
    match serde_json::from_value(json) {
        Ok(value) => value,
        Err(error) => {
            tracing::error!(
                ?error,
                "console protocol descriptor value conversion failed"
            );
            Value::null()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, bail, ensure};
    use std::collections::BTreeSet;

    fn find_action<'a>(
        actions: &'a [ActionDescriptor],
        id: &str,
    ) -> anyhow::Result<&'a ActionDescriptor> {
        actions
            .iter()
            .find(|action| action.id == id)
            .with_context(|| format!("missing descriptor {id}"))
    }

    #[test]
    fn descriptors_include_root_visibility_and_no_raw_shell() -> anyhow::Result<()> {
        let meta = registry_snapshot(1, 1, 0);
        ensure!(
            meta.root_data_authority.root_can_view_all_business_data,
            "root data authority did not include business data visibility"
        );
        ensure!(
            !meta.root_data_authority.bypasses_operation_fact_policy,
            "root data authority bypassed operation/fact policy"
        );
        ensure!(
            meta.actions
                .iter()
                .any(|a| a.id == ACTION_VISIBILITY_STATE_READ),
            "visibility state read action is missing"
        );
        ensure!(
            meta.actions
                .iter()
                .all(|a| !a.id.contains("raw") && !a.id.contains("shell")),
            "descriptor list exposed a raw or shell action"
        );
        Ok(())
    }

    #[test]
    fn descriptors_are_unique_and_cover_core_domains() -> anyhow::Result<()> {
        let actions = action_descriptors();
        let streams = stream_descriptors();
        let mut ids = BTreeSet::new();
        for action in actions {
            ensure!(
                ids.insert(action.id.clone()),
                "duplicate action {}",
                action.id
            );
        }
        for stream in streams {
            ensure!(
                ids.insert(stream.id.clone()),
                "duplicate stream {}",
                stream.id
            );
        }

        let mut domains = BTreeSet::new();
        for action in actions {
            domains.insert(action.domain.as_str());
        }
        for stream in streams {
            domains.insert(stream.domain.as_str());
        }
        for required in [
            "protocol",
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
            "projection",
            "inference",
            "pairing",
            "resource",
        ] {
            ensure!(domains.contains(required), "missing domain {required}");
        }
        Ok(())
    }

    #[test]
    fn edit_descriptors_are_shape_independent() -> anyhow::Result<()> {
        let Some(descriptor) = resource_type_registry()
            .get("access.user")
            .cloned()
            .and_then(Value::into_map)
        else {
            bail!("missing access.user resource descriptor");
        };
        let Some(fields) = descriptor.get("fields").and_then(Value::as_list) else {
            bail!("resource descriptor must include fields");
        };
        ensure!(
            fields.iter().any(|field| {
                field.as_map().is_some_and(|map| {
                    map.get("semantic_kind").and_then(Value::as_str) == Some("resource_ref")
                })
            }),
            "resource descriptor did not include resource_ref field"
        );
        Ok(())
    }

    #[test]
    fn registry_has_no_placeholder_change_set_contracts() {
        assert!(
            action_descriptors()
                .iter()
                .all(|action| !action.id.starts_with("change_set."))
        );
    }

    #[test]
    fn protected_payload_descriptors_require_step_up() -> anyhow::Result<()> {
        for action in action_descriptors() {
            if matches!(
                action.visibility,
                VisibilityTier::BusinessData | VisibilityTier::ProtectedPayload
            ) {
                ensure!(
                    action.requires_step_up,
                    "{} exposes {:?} without step-up",
                    action.id,
                    action.visibility
                );
            }
        }
        for stream in stream_descriptors() {
            if matches!(
                stream.visibility,
                VisibilityTier::BusinessData | VisibilityTier::ProtectedPayload
            ) {
                ensure!(
                    stream.requires_step_up,
                    "{} exposes {:?} without step-up",
                    stream.id,
                    stream.visibility
                );
            }
        }
        Ok(())
    }

    #[test]
    fn access_descriptors_match_runtime_authority_boundaries() -> anyhow::Result<()> {
        let actions = action_descriptors();

        let user_write = find_action(actions, ACTION_ACCESS_USER_WRITE_CAS)?;
        ensure!(
            user_write.authority_templates.iter().any(|required| {
                required.verb == "write" && required.target == "state://kernel/console/users/**"
            }),
            "user write descriptor missing user write authority"
        );
        let role_write = find_action(actions, ACTION_ACCESS_ROLE_WRITE_CAS)?;
        ensure!(
            role_write.authority_templates.iter().any(|required| {
                required.verb == "write" && required.target == "state://kernel/console/roles/**"
            }),
            "role write descriptor missing role write authority"
        );
        let session_revoke = find_action(actions, ACTION_ACCESS_SESSION_REVOKE)?;
        ensure!(
            session_revoke.authority_templates.iter().any(|required| {
                required.verb == "write" && required.target == "state://kernel/console/sessions/**"
            }),
            "session revoke descriptor missing session write authority"
        );
        ensure!(
            find_action(actions, ACTION_ACCESS_SESSION_CURRENT_LOGOUT)?
                .authority_templates
                .is_empty(),
            "current-session logout should not require explicit authority"
        );
        Ok(())
    }

    #[test]
    fn external_descriptors_match_runtime_authority_boundaries() -> anyhow::Result<()> {
        let actions = action_descriptors();

        let install = find_action(actions, ACTION_EXTERNAL_INSTALLATION_INSTALL)?;
        ensure!(
            install.authority_templates.iter().any(|required| {
                required.verb == "write"
                    && required.target == "state://kernel/external-installations/**"
            }),
            "external install missing installation write authority"
        );
        let installation_read = find_action(actions, ACTION_EXTERNAL_INSTALLATION_READ)?;
        ensure!(
            installation_read
                .authority_templates
                .iter()
                .any(|required| {
                    required.verb == "read"
                        && required.target == "state://kernel/external-installations/**"
                }),
            "external installation read missing installation read authority"
        );
        let manifest_write = find_action(actions, ACTION_EXTERNAL_MANIFEST_WRITE_CAS)?;
        ensure!(
            manifest_write.authority_templates.iter().any(|required| {
                required.verb == "write" && required.target == "state://kernel/manifests/**"
            }),
            "external manifest write missing manifest write authority"
        );
        let start = find_action(actions, ACTION_EXTERNAL_INSTALLATION_START)?;
        ensure!(
            start.authority_templates.iter().any(|required| {
                required.verb == "read"
                    && required.target == "state://kernel/external-installations/**"
            }),
            "external start missing installation read authority"
        );
        ensure!(
            start.authority_templates.iter().any(|required| {
                required.verb == "perform" && required.target == "effect://proc/spawn"
            }),
            "external start missing proc spawn authority"
        );
        let stop = find_action(actions, ACTION_EXTERNAL_INSTALLATION_STOP)?;
        ensure!(
            stop.authority_templates.iter().any(|required| {
                required.verb == "perform" && required.target == "effect://proc/kill"
            }),
            "external stop missing proc kill authority"
        );
        let revoke = find_action(actions, ACTION_EXTERNAL_INSTALLATION_REVOKE)?;
        ensure!(
            revoke.authority_templates.iter().any(|required| {
                required.verb == "read"
                    && required.target == "state://kernel/external-installations/**"
            }),
            "external revoke missing installation read authority"
        );
        ensure!(
            revoke.authority_templates.iter().any(|required| {
                required.verb == "perform" && required.target == "effect://external/revoke"
            }),
            "external revoke missing external revoke authority"
        );
        Ok(())
    }

    #[test]
    fn inference_descriptors_match_runtime_authority_boundaries() -> anyhow::Result<()> {
        let actions = action_descriptors();

        let backend = find_action(actions, ACTION_INFERENCE_BACKEND_WRITE_CAS)?;
        ensure!(
            backend.authority_templates.iter().any(|required| {
                required.verb == "write"
                    && required.target == "state://kernel/inference/backends/**"
            }),
            "inference backend write missing backend authority"
        );
        let model = find_action(actions, ACTION_INFERENCE_MODEL_WRITE_CAS)?;
        ensure!(
            model.authority_templates.iter().any(|required| {
                required.verb == "write" && required.target == "state://kernel/inference/models/**"
            }),
            "inference model write missing model authority"
        );
        let group = find_action(actions, ACTION_INFERENCE_GROUP_WRITE_CAS)?;
        ensure!(
            group.authority_templates.iter().any(|required| {
                required.verb == "write" && required.target == "state://kernel/inference/groups/**"
            }),
            "inference group write missing group authority"
        );
        let routing = find_action(actions, ACTION_INFERENCE_ROUTING_WRITE_CAS)?;
        ensure!(
            routing.authority_templates.iter().any(|required| {
                required.verb == "write" && required.target == "state://kernel/routing/inference"
            }),
            "inference routing write missing routing authority"
        );
        Ok(())
    }

    #[test]
    fn pairing_descriptors_use_specific_effect_authority() -> anyhow::Result<()> {
        let actions = action_descriptors();
        let create = find_action(actions, ACTION_PAIRING_CREATE)?;
        ensure!(
            create
                .input
                .fields
                .iter()
                .any(|field| field.name == "pairing_id" && field.required)
                && create
                    .input
                    .fields
                    .iter()
                    .any(|field| field.name == "installation_id" && field.required)
                && !create
                    .input
                    .fields
                    .iter()
                    .any(|field| field.name == "input"),
            "pairing create must expose its required identity fields"
        );
        ensure!(
            create
                .input
                .fields
                .iter()
                .any(|field| field.name == "expires_at" && field.kind == "u64" && !field.required),
            "pairing expiry must use the non-negative integer admission contract"
        );
        for (id, target) in [
            (ACTION_PAIRING_CREATE, "effect://external/pairing/create"),
            (ACTION_PAIRING_APPROVE, "effect://external/pairing/approve"),
            (ACTION_PAIRING_DENY, "effect://external/pairing/deny"),
        ] {
            let action = find_action(actions, id)?;
            ensure!(
                action.authority_templates.len() == 1,
                "pairing action {id} should have exactly one authority"
            );
            let authority = action
                .authority_templates
                .first()
                .context("pairing authority missing")?;
            ensure!(
                authority.verb == "perform",
                "pairing action {id} should require perform"
            );
            ensure!(
                authority.target == target,
                "pairing action {id} target mismatch"
            );
        }
        Ok(())
    }
}
