#![forbid(unsafe_code)]

//! Console Protocol DTO exports, action ids, stream ids, and compact action codes.
//!
//! An identifier reserves a protocol name; it does not guarantee that a host
//! implements or authorizes that operation. Query the host's registry descriptors
//! for schemas and admission requirements.

pub use xolotl_proto::xolotl::v1::console as pb;

pub use pb::{
    ActionCall, ActionResult, Authenticated, ClientHello, ConsoleError, ConsoleErrorCode,
    ConsoleEvent, ConsoleFrame, Event, ExecutionReference, FactEvent, HelloAccepted,
    OutcomeUnknownDetail, PrincipalSummary, ProtocolGreeting, Reply, RuntimeEvent, StateAppend,
    StateDelete, StateDropPrefixAppend, StateSet, StateSourceSummary, StreamCall,
    SubscriptionClosed,
};

/// Protocol revision sent during the Console handshake.
pub const CONSOLE_PROTOCOL_VERSION: u32 = 1;
/// Server identifier advertised by the Console endpoint.
pub const SERVER_NAME: &str = "xolotl-console";
/// Payload encoding used by the Console v1 wire contract.
pub const WIRE_ENCODING: &str = "protobuf+xolotl-console-v1";
/// WebSocket subprotocol identifying the Console v1 transport.
pub const SUBPROTOCOL: &str = "xolotl-console-v1";

/// Retrieve protocol metadata and revisions.
pub const ACTION_PROTOCOL_DESCRIBE: &str = "protocol.describe";
/// Retrieve the registered action and stream descriptors.
pub const ACTION_PROTOCOL_REGISTRY_SNAPSHOT: &str = "protocol.registry.snapshot";
/// Retrieve the descriptor for one action identifier.
pub const ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET: &str = "protocol.action_descriptor.get";
/// Enumerate resource types exposed by the management registry.
pub const ACTION_RESOURCE_TYPE_LIST: &str = "resource.type.list";
/// Describe one managed resource type and its schema.
pub const ACTION_RESOURCE_TYPE_DESCRIBE: &str = "resource.type.describe";
/// Describe the registered presentation of a managed resource.
pub const ACTION_RESOURCE_VIEW_DESCRIBE: &str = "resource.view.describe";
/// Inspect the effective authority of a principal.
pub const ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE: &str = "authority.principal.effective";
/// Inspect advisory authority templates and known gates for registered actions.
pub const ACTION_AUTHORITY_ACTION_MATRIX: &str = "authority.action.matrix";
/// Inspect a principal's authority for a resource.
pub const ACTION_AUTHORITY_RESOURCE_ACCESS: &str = "authority.resource.access";
/// Explain known gates for one action; input-dependent authority remains advisory.
pub const ACTION_AUTHORITY_ACTION_EXPLAIN: &str = "authority.action.explain";
/// Describe the caller's visibility boundary.
pub const ACTION_VISIBILITY_AUTHORITY_DESCRIBE: &str = "visibility.authority.describe";
/// Read state through the caller's visibility rules.
pub const ACTION_VISIBILITY_STATE_READ: &str = "visibility.state.read";
/// List state entries through the caller's visibility rules.
pub const ACTION_VISIBILITY_STATE_LIST: &str = "visibility.state.list";
/// Enumerate secret metadata without revealing secret values.
pub const ACTION_SECRET_CATALOG: &str = "secret.catalog";
/// Read a snapshot of authorized state.
pub const ACTION_STATE_SNAPSHOT: &str = "state.snapshot";
/// Read one runtime configuration value.
pub const ACTION_CONFIG_READ: &str = "config.read";
/// List runtime configuration entries.
pub const ACTION_CONFIG_LIST: &str = "config.list";
/// Compare and replace a runtime configuration value.
pub const ACTION_CONFIG_WRITE_CAS: &str = "config.write_cas";
/// Read a managed Console user record.
pub const ACTION_ACCESS_USER_READ: &str = "access.user.read";
/// List managed Console users.
pub const ACTION_ACCESS_USER_LIST: &str = "access.user.list";
/// Compare and replace a managed user record.
pub const ACTION_ACCESS_USER_WRITE_CAS: &str = "access.user.write_cas";
/// Disable a managed Console user.
pub const ACTION_ACCESS_USER_DISABLE: &str = "access.user.disable";
/// Read a managed Console role definition.
pub const ACTION_ACCESS_ROLE_READ: &str = "access.role.read";
/// List managed Console roles.
pub const ACTION_ACCESS_ROLE_LIST: &str = "access.role.list";
/// Compare and replace a managed role definition.
pub const ACTION_ACCESS_ROLE_WRITE_CAS: &str = "access.role.write_cas";
/// Log out the session issuing the action.
pub const ACTION_ACCESS_SESSION_CURRENT_LOGOUT: &str = "access.session.current.logout";
/// List sessions visible to the caller.
pub const ACTION_ACCESS_SESSION_LIST: &str = "access.session.list";
/// Revoke a selected Console session.
pub const ACTION_ACCESS_SESSION_REVOKE: &str = "access.session.revoke";
/// Revoke a user's Console sessions.
pub const ACTION_ACCESS_SESSION_REVOKE_USER: &str = "access.session.revoke_user";
/// Inspect the runtime state of a process.
pub const ACTION_RUNTIME_PROCESS_INSPECT: &str = "runtime.process.inspect";
/// Discover host runtime exposure and execution limits.
pub const ACTION_RUNTIME_DESCRIBE: &str = "runtime.describe";
/// Resolve installed resource method contracts visible to this caller.
pub const ACTION_RUNTIME_RESOURCE_DESCRIBE: &str = "runtime.resource.describe";
/// Invoke an installed resource through a request Process.
pub const ACTION_RUNTIME_OPERATION_INVOKE: &str = "runtime.operation.invoke";
/// Execute a bounded portable program through a request Process.
pub const ACTION_RUNTIME_PROGRAM_RUN: &str = "runtime.program.run";
/// Submit an independent operation.
pub const ACTION_RUNTIME_OPERATION_SUBMIT: &str = "runtime.operation.submit";
/// Submit an independent portable program.
pub const ACTION_RUNTIME_PROGRAM_SUBMIT: &str = "runtime.program.submit";
/// Read owned volatile evidence for an explicitly guarded root submission.
pub const ACTION_RUNTIME_SUBMISSION_LOOKUP: &str = "runtime.submission.lookup";
/// Read owned execution metadata.
pub const ACTION_RUNTIME_EXECUTION_GET: &str = "runtime.execution.get";
/// List owned execution metadata.
pub const ACTION_RUNTIME_EXECUTION_LIST: &str = "runtime.execution.list";
/// Read an owned execution result with current authority.
pub const ACTION_RUNTIME_EXECUTION_RESULT: &str = "runtime.execution.result";
/// Read or briefly wait for an owned volatile execution's bounded Stream output.
pub const ACTION_RUNTIME_EXECUTION_OUTPUT_READ: &str = "runtime.execution.output.read";
/// Request cancellation of an owned execution.
pub const ACTION_RUNTIME_EXECUTION_CANCEL: &str = "runtime.execution.cancel";
/// Forget an owned terminal execution record.
pub const ACTION_RUNTIME_EXECUTION_FORGET: &str = "runtime.execution.forget";
/// Query recently retained audit facts.
pub const ACTION_AUDIT_FACTS_RECENT: &str = "audit.facts.recent";
/// Read lineage information for a trace.
pub const ACTION_LINEAGE_TRACE_READ: &str = "lineage.trace.read";
/// Read lineage information for an individual fact.
pub const ACTION_LINEAGE_FACT_READ: &str = "lineage.fact.read";
/// Retrieve a runtime health summary.
pub const ACTION_HEALTH_SUMMARY: &str = "health.summary";
/// Install an external program declaration.
pub const ACTION_EXTERNAL_INSTALLATION_INSTALL: &str = "external.installation.install";
/// Update an external installation declaration.
pub const ACTION_EXTERNAL_INSTALLATION_UPDATE: &str = "external.installation.update";
/// Retire an installation and all its Source scopes with an exact version precondition.
pub const ACTION_EXTERNAL_INSTALLATION_UNINSTALL: &str = "external.installation.uninstall";
/// Request startup of an external installation.
pub const ACTION_EXTERNAL_INSTALLATION_START: &str = "external.installation.start";
/// Request shutdown of an external installation.
pub const ACTION_EXTERNAL_INSTALLATION_STOP: &str = "external.installation.stop";
/// Revoke an external installation's runtime access.
pub const ACTION_EXTERNAL_INSTALLATION_REVOKE: &str = "external.installation.revoke";
/// List external installation records.
pub const ACTION_EXTERNAL_INSTALLATION_LIST: &str = "external.installation.list";
/// Read one external installation record.
pub const ACTION_EXTERNAL_INSTALLATION_READ: &str = "external.installation.read";
/// Inspect one exact Source claim through a privileged, audited host port.
pub const ACTION_EXTERNAL_SOURCE_CLAIM_INSPECT: &str = "external.source.claim.inspect";
/// Inspect the retained decision for one Source event through the audited host port.
pub const ACTION_EXTERNAL_SOURCE_EVENT_DECISION_INSPECT: &str =
    "external.source.event.decision.inspect";
/// List registered external program manifests.
pub const ACTION_EXTERNAL_MANIFEST_LIST: &str = "external.manifest.list";
/// Read one external program manifest.
pub const ACTION_EXTERNAL_MANIFEST_READ: &str = "external.manifest.read";
/// Compare and replace an external program manifest.
pub const ACTION_EXTERNAL_MANIFEST_WRITE_CAS: &str = "external.manifest.write_cas";
/// List status records for in-process projections.
pub const ACTION_PROJECTION_IN_PROCESS_STATUS_LIST: &str = "projection.in_process.status.list";
/// Read the status of one in-process projection.
pub const ACTION_PROJECTION_IN_PROCESS_STATUS_READ: &str = "projection.in_process.status.read";
/// List inference backend declarations.
pub const ACTION_INFERENCE_BACKEND_LIST: &str = "inference.backend.list";
/// Read an inference backend declaration.
pub const ACTION_INFERENCE_BACKEND_READ: &str = "inference.backend.read";
/// Compare and replace an inference backend declaration.
pub const ACTION_INFERENCE_BACKEND_WRITE_CAS: &str = "inference.backend.write_cas";
/// List configured model declarations.
pub const ACTION_INFERENCE_MODEL_LIST: &str = "inference.model.list";
/// Read one configured model declaration.
pub const ACTION_INFERENCE_MODEL_READ: &str = "inference.model.read";
/// Compare and replace a model declaration.
pub const ACTION_INFERENCE_MODEL_WRITE_CAS: &str = "inference.model.write_cas";
/// List model group declarations.
pub const ACTION_INFERENCE_GROUP_LIST: &str = "inference.group.list";
/// Read one model group declaration.
pub const ACTION_INFERENCE_GROUP_READ: &str = "inference.group.read";
/// Compare and replace a model group declaration.
pub const ACTION_INFERENCE_GROUP_WRITE_CAS: &str = "inference.group.write_cas";
/// Read the configured inference routing rules.
pub const ACTION_INFERENCE_ROUTING_READ: &str = "inference.routing.read";
/// Compare and replace inference routing rules.
pub const ACTION_INFERENCE_ROUTING_WRITE_CAS: &str = "inference.routing.write_cas";
/// Create an external pairing request.
pub const ACTION_PAIRING_CREATE: &str = "pairing.create";
/// Approve an external pairing request.
pub const ACTION_PAIRING_APPROVE: &str = "pairing.approve";
/// Deny an external pairing request.
pub const ACTION_PAIRING_DENY: &str = "pairing.deny";
/// Read one locally managed federation peer admission row.
pub const ACTION_FEDERATION_PEER_READ: &str = "federation.peer.read";
/// Enumerate locally managed federation peer admission rows.
pub const ACTION_FEDERATION_PEER_LIST: &str = "federation.peer.list";
/// Compare and replace one locally managed federation peer admission row.
pub const ACTION_FEDERATION_PEER_WRITE_CAS: &str = "federation.peer.write_cas";
/// Read one peer's accepted online-key generations and authorization digests.
pub const ACTION_FEDERATION_PEER_ADMISSION_READ: &str = "federation.peer_admission.read";
/// Compare and replace one peer's accepted online-key admission.
pub const ACTION_FEDERATION_PEER_ADMISSION_WRITE_CAS: &str = "federation.peer_admission.write_cas";
/// Read a peer's directional access to one local federation export.
pub const ACTION_FEDERATION_EXPORT_READ: &str = "federation.export.read";
/// Enumerate a peer's directional local export decisions.
pub const ACTION_FEDERATION_EXPORT_LIST: &str = "federation.export.list";
/// Compare and replace a peer's directional access to one local export.
pub const ACTION_FEDERATION_EXPORT_WRITE_CAS: &str = "federation.export.write_cas";

/// Subscribe to authorized state mutations.
pub const STREAM_STATE_WATCH: &str = "state.watch";
/// Subscribe to audit fact events.
pub const STREAM_AUDIT_FACTS: &str = "audit.facts.stream";
/// Subscribe to runtime operation observations.
pub const STREAM_RUNTIME_OPERATION: &str = "runtime.operation.stream";
/// Execute a portable program and receive its live output and final result.
pub const STREAM_RUNTIME_PROGRAM: &str = "runtime.program.stream";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subprotocol_is_stable() {
        assert_eq!(CONSOLE_PROTOCOL_VERSION, 1);
        assert_eq!(SUBPROTOCOL, "xolotl-console-v1");
        assert_eq!(WIRE_ENCODING, "protobuf+xolotl-console-v1");
    }

    #[test]
    fn submission_lookup_identifier_is_stable() {
        assert_eq!(
            ACTION_RUNTIME_SUBMISSION_LOOKUP,
            "runtime.submission.lookup"
        );
    }
}
