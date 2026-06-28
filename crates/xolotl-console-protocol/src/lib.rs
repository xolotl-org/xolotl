#![forbid(unsafe_code)]

//! Console Protocol DTO exports, action ids, stream ids, and compact action codes.

pub use xolotl_proto::xolotl::v1::console as pb;

pub use pb::{
    ActionCall, ActionDescriptor, ActionResult, Authenticated, ClientHello, ConsoleError,
    ConsoleErrorCode, ConsoleEvent, ConsoleFrame, Event, FactEvent, FieldDescriptor, HelloAccepted,
    PaginationSpec, PrincipalSummary, ProtocolMetadata, RecipeKind, Reply, SchemaDescriptor,
    StateAppend, StateDelete, StateSet, StreamCall, StreamDescriptor, SubscriptionClosed, Summary,
};

pub const CONSOLE_PROTOCOL_VERSION: u32 = 1;
pub const SERVER_NAME: &str = "xolotl-console";
pub const WIRE_ENCODING: &str = "protobuf+xolotl-console-v1";
pub const SUBPROTOCOL: &str = "xolotl-console-v1";

pub fn accepted_encodings() -> &'static [&'static str] {
    &[WIRE_ENCODING]
}

pub const ACTION_PROTOCOL_DESCRIBE: &str = "protocol.describe";
pub const ACTION_PROTOCOL_REGISTRY_SNAPSHOT: &str = "protocol.registry.snapshot";
pub const ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET: &str = "protocol.action_descriptor.get";
pub const ACTION_REGISTRY_COVERAGE_REPORT: &str = "registry.coverage.report";
pub const ACTION_RESOURCE_TYPE_LIST: &str = "resource.type.list";
pub const ACTION_RESOURCE_TYPE_DESCRIBE: &str = "resource.type.describe";
pub const ACTION_RESOURCE_VIEW_DESCRIBE: &str = "resource.view.describe";
pub const ACTION_CHANGE_SET_CREATE: &str = "change_set.create";
pub const ACTION_CHANGE_SET_UPDATE: &str = "change_set.update";
pub const ACTION_CHANGE_SET_VALIDATE: &str = "change_set.validate";
pub const ACTION_CHANGE_SET_DIFF: &str = "change_set.diff";
pub const ACTION_CHANGE_SET_DRY_RUN: &str = "change_set.dry_run";
pub const ACTION_CHANGE_SET_APPLY: &str = "change_set.apply";
pub const ACTION_CHANGE_SET_DISCARD: &str = "change_set.discard";
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
pub const ACTION_HEALTH_SUMMARY: &str = "health.summary";
pub const ACTION_EXTERNAL_INSTALLATION_INSTALL: &str = "external.installation.install";
pub const ACTION_EXTERNAL_INSTALLATION_UPDATE: &str = "external.installation.update";
pub const ACTION_EXTERNAL_INSTALLATION_START: &str = "external.installation.start";
pub const ACTION_EXTERNAL_INSTALLATION_STOP: &str = "external.installation.stop";
pub const ACTION_EXTERNAL_INSTALLATION_REVOKE: &str = "external.installation.revoke";
pub const ACTION_EXTERNAL_INSTALLATION_LIST: &str = "external.installation.list";
pub const ACTION_EXTERNAL_INSTALLATION_READ: &str = "external.installation.read";
pub const ACTION_EXTERNAL_MANIFEST_LIST: &str = "external.manifest.list";
pub const ACTION_EXTERNAL_MANIFEST_READ: &str = "external.manifest.read";
pub const ACTION_EXTERNAL_MANIFEST_WRITE_CAS: &str = "external.manifest.write_cas";
pub const ACTION_PROJECTION_IN_PROCESS_STATUS_LIST: &str = "projection.in_process.status.list";
pub const ACTION_PROJECTION_IN_PROCESS_STATUS_READ: &str = "projection.in_process.status.read";
pub const ACTION_INFERENCE_BACKEND_LIST: &str = "inference.backend.list";
pub const ACTION_INFERENCE_BACKEND_READ: &str = "inference.backend.read";
pub const ACTION_INFERENCE_BACKEND_WRITE_CAS: &str = "inference.backend.write_cas";
pub const ACTION_INFERENCE_MODEL_LIST: &str = "inference.model.list";
pub const ACTION_INFERENCE_MODEL_READ: &str = "inference.model.read";
pub const ACTION_INFERENCE_MODEL_WRITE_CAS: &str = "inference.model.write_cas";
pub const ACTION_INFERENCE_GROUP_LIST: &str = "inference.group.list";
pub const ACTION_INFERENCE_GROUP_READ: &str = "inference.group.read";
pub const ACTION_INFERENCE_GROUP_WRITE_CAS: &str = "inference.group.write_cas";
pub const ACTION_INFERENCE_ROUTING_READ: &str = "inference.routing.read";
pub const ACTION_INFERENCE_ROUTING_WRITE_CAS: &str = "inference.routing.write_cas";
pub const ACTION_PAIRING_CREATE: &str = "pairing.create";
pub const ACTION_PAIRING_APPROVE: &str = "pairing.approve";
pub const ACTION_PAIRING_DENY: &str = "pairing.deny";
pub const ACTION_PAIRING_REPLACE: &str = "pairing.replace";

pub const ACTION_ACCESS_CREDENTIAL_PASSKEY_LIST: &str = "access.credential.passkey.list";
pub const ACTION_ACCESS_CREDENTIAL_PASSKEY_REGISTER: &str = "access.credential.passkey.register";
pub const ACTION_ACCESS_CREDENTIAL_PASSKEY_RENAME: &str = "access.credential.passkey.rename";
pub const ACTION_ACCESS_CREDENTIAL_PASSKEY_REVOKE: &str = "access.credential.passkey.revoke";
pub const ACTION_ACCESS_CREDENTIAL_TOTP_ENROLL: &str = "access.credential.totp.enroll";
pub const ACTION_ACCESS_CREDENTIAL_TOTP_DISABLE: &str = "access.credential.totp.disable";
pub const ACTION_ACCESS_CREDENTIAL_RECOVERY_REGENERATE: &str =
    "access.credential.recovery.regenerate";
pub const ACTION_ACCESS_CREDENTIAL_PASSWORD_SET: &str = "access.credential.password.set";
pub const ACTION_ACCESS_CREDENTIAL_PASSWORD_CHANGE: &str = "access.credential.password.change";
pub const ACTION_ACCESS_CREDENTIAL_PASSWORD_DISABLE: &str = "access.credential.password.disable";

pub const STREAM_STATE_WATCH: &str = "state.watch";
pub const STREAM_STATE_DIFF: &str = "state.diff";
pub const STREAM_AUDIT_FACTS: &str = "audit.facts.stream";
pub const STREAM_AUDIT_TAIL: &str = "audit.tail";
pub const STREAM_LINEAGE_FACT: &str = "lineage.fact";
pub const STREAM_RUNTIME_PROCESS: &str = "runtime.process";
pub const STREAM_ACCESS_SESSION: &str = "access.session";
pub const STREAM_CONFIG_DIFF: &str = "config.diff";
pub const STREAM_RUNTIME_OPERATION: &str = "runtime.operation";
pub const STREAM_RUNTIME_HEALTH: &str = "runtime.health";
pub const STREAM_APPROVAL_PENDING: &str = "approval.pending";
pub const STREAM_EXTERNAL_LIFECYCLE: &str = "external.lifecycle";

/// Returns the compact fast-path code for an action id, if registered.
/// Codes are grouped by domain (high byte) so new actions in a domain do not
/// shift existing codes.
pub fn action_code(id: &str) -> Option<u32> {
    Some(match id {
        ACTION_PROTOCOL_DESCRIBE => 0x0101,
        ACTION_PROTOCOL_REGISTRY_SNAPSHOT => 0x0102,
        ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET => 0x0103,
        ACTION_REGISTRY_COVERAGE_REPORT => 0x0201,
        ACTION_RESOURCE_TYPE_LIST => 0x0301,
        ACTION_RESOURCE_TYPE_DESCRIBE => 0x0302,
        ACTION_RESOURCE_VIEW_DESCRIBE => 0x0303,
        ACTION_CHANGE_SET_CREATE => 0x0401,
        ACTION_CHANGE_SET_UPDATE => 0x0402,
        ACTION_CHANGE_SET_VALIDATE => 0x0403,
        ACTION_CHANGE_SET_DIFF => 0x0404,
        ACTION_CHANGE_SET_DRY_RUN => 0x0405,
        ACTION_CHANGE_SET_APPLY => 0x0406,
        ACTION_CHANGE_SET_DISCARD => 0x0407,
        ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE => 0x0501,
        ACTION_AUTHORITY_ACTION_MATRIX => 0x0502,
        ACTION_AUTHORITY_RESOURCE_ACCESS => 0x0503,
        ACTION_AUTHORITY_WHY_DENIED => 0x0504,
        ACTION_VISIBILITY_AUTHORITY_DESCRIBE => 0x0601,
        ACTION_VISIBILITY_STATE_READ => 0x0602,
        ACTION_VISIBILITY_STATE_LIST => 0x0603,
        ACTION_SECRET_CATALOG => 0x0701,
        ACTION_SECRET_REVEAL => 0x0702,
        ACTION_STATE_SNAPSHOT => 0x0801,
        ACTION_CONFIG_READ => 0x0901,
        ACTION_CONFIG_LIST => 0x0902,
        ACTION_CONFIG_WRITE_CAS => 0x0903,
        ACTION_ACCESS_USER_READ => 0x0A01,
        ACTION_ACCESS_USER_LIST => 0x0A02,
        ACTION_ACCESS_USER_WRITE_CAS => 0x0A03,
        ACTION_ACCESS_USER_DISABLE => 0x0A04,
        ACTION_ACCESS_ROLE_READ => 0x0A05,
        ACTION_ACCESS_ROLE_LIST => 0x0A06,
        ACTION_ACCESS_ROLE_WRITE_CAS => 0x0A07,
        ACTION_ACCESS_SESSION_CURRENT_LOGOUT => 0x0A08,
        ACTION_ACCESS_SESSION_LIST => 0x0A09,
        ACTION_ACCESS_SESSION_REVOKE => 0x0A0A,
        ACTION_ACCESS_SESSION_REVOKE_USER => 0x0A0B,
        ACTION_RUNTIME_PROCESS_INSPECT => 0x0B01,
        ACTION_AUDIT_FACTS_RECENT => 0x0C01,
        ACTION_LINEAGE_TRACE_READ => 0x0D01,
        ACTION_LINEAGE_FACT_READ => 0x0D02,
        ACTION_HEALTH_SUMMARY => 0x0E01,
        ACTION_EXTERNAL_INSTALLATION_INSTALL => 0x0F01,
        ACTION_EXTERNAL_INSTALLATION_UPDATE => 0x0F02,
        ACTION_EXTERNAL_INSTALLATION_START => 0x0F03,
        ACTION_EXTERNAL_INSTALLATION_STOP => 0x0F04,
        ACTION_EXTERNAL_INSTALLATION_REVOKE => 0x0F05,
        ACTION_EXTERNAL_INSTALLATION_LIST => 0x0F06,
        ACTION_EXTERNAL_INSTALLATION_READ => 0x0F07,
        ACTION_EXTERNAL_MANIFEST_LIST => 0x1001,
        ACTION_EXTERNAL_MANIFEST_READ => 0x1002,
        ACTION_EXTERNAL_MANIFEST_WRITE_CAS => 0x1003,
        ACTION_PROJECTION_IN_PROCESS_STATUS_LIST => 0x1101,
        ACTION_PROJECTION_IN_PROCESS_STATUS_READ => 0x1102,
        ACTION_INFERENCE_BACKEND_LIST => 0x1201,
        ACTION_INFERENCE_BACKEND_READ => 0x1202,
        ACTION_INFERENCE_BACKEND_WRITE_CAS => 0x1203,
        ACTION_INFERENCE_MODEL_LIST => 0x1204,
        ACTION_INFERENCE_MODEL_READ => 0x1205,
        ACTION_INFERENCE_MODEL_WRITE_CAS => 0x1206,
        ACTION_INFERENCE_GROUP_LIST => 0x1207,
        ACTION_INFERENCE_GROUP_READ => 0x1208,
        ACTION_INFERENCE_GROUP_WRITE_CAS => 0x1209,
        ACTION_INFERENCE_ROUTING_READ => 0x120A,
        ACTION_INFERENCE_ROUTING_WRITE_CAS => 0x120B,
        ACTION_PAIRING_CREATE => 0x1301,
        ACTION_PAIRING_APPROVE => 0x1302,
        ACTION_PAIRING_DENY => 0x1303,
        ACTION_PAIRING_REPLACE => 0x1304,
        ACTION_ACCESS_CREDENTIAL_PASSKEY_LIST => 0x1401,
        ACTION_ACCESS_CREDENTIAL_PASSKEY_REGISTER => 0x1402,
        ACTION_ACCESS_CREDENTIAL_PASSKEY_RENAME => 0x1403,
        ACTION_ACCESS_CREDENTIAL_PASSKEY_REVOKE => 0x1404,
        ACTION_ACCESS_CREDENTIAL_TOTP_ENROLL => 0x1405,
        ACTION_ACCESS_CREDENTIAL_TOTP_DISABLE => 0x1406,
        ACTION_ACCESS_CREDENTIAL_RECOVERY_REGENERATE => 0x1407,
        ACTION_ACCESS_CREDENTIAL_PASSWORD_SET => 0x1408,
        ACTION_ACCESS_CREDENTIAL_PASSWORD_CHANGE => 0x1409,
        ACTION_ACCESS_CREDENTIAL_PASSWORD_DISABLE => 0x140A,
        _ => return None,
    })
}

/// Returns the action id for a compact code, if registered.
pub fn action_id(code: u32) -> Option<&'static str> {
    Some(match code {
        0x0101 => ACTION_PROTOCOL_DESCRIBE,
        0x0102 => ACTION_PROTOCOL_REGISTRY_SNAPSHOT,
        0x0103 => ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET,
        0x0201 => ACTION_REGISTRY_COVERAGE_REPORT,
        0x0301 => ACTION_RESOURCE_TYPE_LIST,
        0x0302 => ACTION_RESOURCE_TYPE_DESCRIBE,
        0x0303 => ACTION_RESOURCE_VIEW_DESCRIBE,
        0x0401 => ACTION_CHANGE_SET_CREATE,
        0x0402 => ACTION_CHANGE_SET_UPDATE,
        0x0403 => ACTION_CHANGE_SET_VALIDATE,
        0x0404 => ACTION_CHANGE_SET_DIFF,
        0x0405 => ACTION_CHANGE_SET_DRY_RUN,
        0x0406 => ACTION_CHANGE_SET_APPLY,
        0x0407 => ACTION_CHANGE_SET_DISCARD,
        0x0501 => ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE,
        0x0502 => ACTION_AUTHORITY_ACTION_MATRIX,
        0x0503 => ACTION_AUTHORITY_RESOURCE_ACCESS,
        0x0504 => ACTION_AUTHORITY_WHY_DENIED,
        0x0601 => ACTION_VISIBILITY_AUTHORITY_DESCRIBE,
        0x0602 => ACTION_VISIBILITY_STATE_READ,
        0x0603 => ACTION_VISIBILITY_STATE_LIST,
        0x0701 => ACTION_SECRET_CATALOG,
        0x0702 => ACTION_SECRET_REVEAL,
        0x0801 => ACTION_STATE_SNAPSHOT,
        0x0901 => ACTION_CONFIG_READ,
        0x0902 => ACTION_CONFIG_LIST,
        0x0903 => ACTION_CONFIG_WRITE_CAS,
        0x0A01 => ACTION_ACCESS_USER_READ,
        0x0A02 => ACTION_ACCESS_USER_LIST,
        0x0A03 => ACTION_ACCESS_USER_WRITE_CAS,
        0x0A04 => ACTION_ACCESS_USER_DISABLE,
        0x0A05 => ACTION_ACCESS_ROLE_READ,
        0x0A06 => ACTION_ACCESS_ROLE_LIST,
        0x0A07 => ACTION_ACCESS_ROLE_WRITE_CAS,
        0x0A08 => ACTION_ACCESS_SESSION_CURRENT_LOGOUT,
        0x0A09 => ACTION_ACCESS_SESSION_LIST,
        0x0A0A => ACTION_ACCESS_SESSION_REVOKE,
        0x0A0B => ACTION_ACCESS_SESSION_REVOKE_USER,
        0x0B01 => ACTION_RUNTIME_PROCESS_INSPECT,
        0x0C01 => ACTION_AUDIT_FACTS_RECENT,
        0x0D01 => ACTION_LINEAGE_TRACE_READ,
        0x0D02 => ACTION_LINEAGE_FACT_READ,
        0x0E01 => ACTION_HEALTH_SUMMARY,
        0x0F01 => ACTION_EXTERNAL_INSTALLATION_INSTALL,
        0x0F02 => ACTION_EXTERNAL_INSTALLATION_UPDATE,
        0x0F03 => ACTION_EXTERNAL_INSTALLATION_START,
        0x0F04 => ACTION_EXTERNAL_INSTALLATION_STOP,
        0x0F05 => ACTION_EXTERNAL_INSTALLATION_REVOKE,
        0x0F06 => ACTION_EXTERNAL_INSTALLATION_LIST,
        0x0F07 => ACTION_EXTERNAL_INSTALLATION_READ,
        0x1001 => ACTION_EXTERNAL_MANIFEST_LIST,
        0x1002 => ACTION_EXTERNAL_MANIFEST_READ,
        0x1003 => ACTION_EXTERNAL_MANIFEST_WRITE_CAS,
        0x1101 => ACTION_PROJECTION_IN_PROCESS_STATUS_LIST,
        0x1102 => ACTION_PROJECTION_IN_PROCESS_STATUS_READ,
        0x1201 => ACTION_INFERENCE_BACKEND_LIST,
        0x1202 => ACTION_INFERENCE_BACKEND_READ,
        0x1203 => ACTION_INFERENCE_BACKEND_WRITE_CAS,
        0x1204 => ACTION_INFERENCE_MODEL_LIST,
        0x1205 => ACTION_INFERENCE_MODEL_READ,
        0x1206 => ACTION_INFERENCE_MODEL_WRITE_CAS,
        0x1207 => ACTION_INFERENCE_GROUP_LIST,
        0x1208 => ACTION_INFERENCE_GROUP_READ,
        0x1209 => ACTION_INFERENCE_GROUP_WRITE_CAS,
        0x120A => ACTION_INFERENCE_ROUTING_READ,
        0x120B => ACTION_INFERENCE_ROUTING_WRITE_CAS,
        0x1301 => ACTION_PAIRING_CREATE,
        0x1302 => ACTION_PAIRING_APPROVE,
        0x1303 => ACTION_PAIRING_DENY,
        0x1304 => ACTION_PAIRING_REPLACE,
        0x1401 => ACTION_ACCESS_CREDENTIAL_PASSKEY_LIST,
        0x1402 => ACTION_ACCESS_CREDENTIAL_PASSKEY_REGISTER,
        0x1403 => ACTION_ACCESS_CREDENTIAL_PASSKEY_RENAME,
        0x1404 => ACTION_ACCESS_CREDENTIAL_PASSKEY_REVOKE,
        0x1405 => ACTION_ACCESS_CREDENTIAL_TOTP_ENROLL,
        0x1406 => ACTION_ACCESS_CREDENTIAL_TOTP_DISABLE,
        0x1407 => ACTION_ACCESS_CREDENTIAL_RECOVERY_REGENERATE,
        0x1408 => ACTION_ACCESS_CREDENTIAL_PASSWORD_SET,
        0x1409 => ACTION_ACCESS_CREDENTIAL_PASSWORD_CHANGE,
        0x140A => ACTION_ACCESS_CREDENTIAL_PASSWORD_DISABLE,
        _ => return None,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageReport {
    pub registry_rev: u64,
    pub domains: Vec<CoverageDomain>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageDomain {
    pub domain: String,
    pub actions: CoverageCounts,
    pub streams: CoverageCounts,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoverageCounts {
    pub implemented: u32,
    pub planned: u32,
    pub blocked_by_custody: u32,
    pub not_console_managed: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

    #[test]
    fn action_code_mapping_is_bijective() -> anyhow::Result<()> {
        let ids = [
            ACTION_PROTOCOL_DESCRIBE,
            ACTION_CONFIG_WRITE_CAS,
            ACTION_ACCESS_CREDENTIAL_PASSWORD_CHANGE,
            ACTION_PAIRING_REPLACE,
            ACTION_INFERENCE_ROUTING_WRITE_CAS,
        ];
        for id in ids {
            let code = action_code(id).with_context(|| format!("action {id} has no code"))?;
            ensure!(
                action_id(code) == Some(id),
                "code {code:#x} must map back to {id}"
            );
        }
        ensure!(
            action_code("no.such.action").is_none(),
            "unknown action must have no code"
        );
        ensure!(
            action_id(0xFFFF).is_none(),
            "unknown code must map to no action"
        );
        Ok(())
    }

    #[test]
    fn action_codes_are_unique() -> anyhow::Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for id in known_action_ids() {
            let code = action_code(id).with_context(|| format!("action {id} has no code"))?;
            ensure!(seen.insert(code), "duplicate code {code:#x} for {id}");
        }
        Ok(())
    }

    #[test]
    fn subprotocol_is_stable() {
        assert_eq!(SUBPROTOCOL, "xolotl-console-v1");
        assert_eq!(WIRE_ENCODING, "protobuf+xolotl-console-v1");
        assert_eq!(accepted_encodings(), &[WIRE_ENCODING]);
    }

    fn known_action_ids() -> Vec<&'static str> {
        [
            ACTION_PROTOCOL_DESCRIBE,
            ACTION_PROTOCOL_REGISTRY_SNAPSHOT,
            ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET,
            ACTION_REGISTRY_COVERAGE_REPORT,
            ACTION_RESOURCE_TYPE_LIST,
            ACTION_RESOURCE_TYPE_DESCRIBE,
            ACTION_RESOURCE_VIEW_DESCRIBE,
            ACTION_CHANGE_SET_CREATE,
            ACTION_CHANGE_SET_UPDATE,
            ACTION_CHANGE_SET_VALIDATE,
            ACTION_CHANGE_SET_DIFF,
            ACTION_CHANGE_SET_DRY_RUN,
            ACTION_CHANGE_SET_APPLY,
            ACTION_CHANGE_SET_DISCARD,
            ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE,
            ACTION_AUTHORITY_ACTION_MATRIX,
            ACTION_AUTHORITY_RESOURCE_ACCESS,
            ACTION_AUTHORITY_WHY_DENIED,
            ACTION_VISIBILITY_AUTHORITY_DESCRIBE,
            ACTION_VISIBILITY_STATE_READ,
            ACTION_VISIBILITY_STATE_LIST,
            ACTION_SECRET_CATALOG,
            ACTION_SECRET_REVEAL,
            ACTION_STATE_SNAPSHOT,
            ACTION_CONFIG_READ,
            ACTION_CONFIG_LIST,
            ACTION_CONFIG_WRITE_CAS,
            ACTION_ACCESS_USER_READ,
            ACTION_ACCESS_USER_LIST,
            ACTION_ACCESS_USER_WRITE_CAS,
            ACTION_ACCESS_USER_DISABLE,
            ACTION_ACCESS_ROLE_READ,
            ACTION_ACCESS_ROLE_LIST,
            ACTION_ACCESS_ROLE_WRITE_CAS,
            ACTION_ACCESS_SESSION_CURRENT_LOGOUT,
            ACTION_ACCESS_SESSION_LIST,
            ACTION_ACCESS_SESSION_REVOKE,
            ACTION_ACCESS_SESSION_REVOKE_USER,
            ACTION_RUNTIME_PROCESS_INSPECT,
            ACTION_AUDIT_FACTS_RECENT,
            ACTION_LINEAGE_TRACE_READ,
            ACTION_LINEAGE_FACT_READ,
            ACTION_HEALTH_SUMMARY,
            ACTION_EXTERNAL_INSTALLATION_INSTALL,
            ACTION_EXTERNAL_INSTALLATION_UPDATE,
            ACTION_EXTERNAL_INSTALLATION_START,
            ACTION_EXTERNAL_INSTALLATION_STOP,
            ACTION_EXTERNAL_INSTALLATION_REVOKE,
            ACTION_EXTERNAL_INSTALLATION_LIST,
            ACTION_EXTERNAL_INSTALLATION_READ,
            ACTION_EXTERNAL_MANIFEST_LIST,
            ACTION_EXTERNAL_MANIFEST_READ,
            ACTION_EXTERNAL_MANIFEST_WRITE_CAS,
            ACTION_PROJECTION_IN_PROCESS_STATUS_LIST,
            ACTION_PROJECTION_IN_PROCESS_STATUS_READ,
            ACTION_INFERENCE_BACKEND_LIST,
            ACTION_INFERENCE_BACKEND_READ,
            ACTION_INFERENCE_BACKEND_WRITE_CAS,
            ACTION_INFERENCE_MODEL_LIST,
            ACTION_INFERENCE_MODEL_READ,
            ACTION_INFERENCE_MODEL_WRITE_CAS,
            ACTION_INFERENCE_GROUP_LIST,
            ACTION_INFERENCE_GROUP_READ,
            ACTION_INFERENCE_GROUP_WRITE_CAS,
            ACTION_INFERENCE_ROUTING_READ,
            ACTION_INFERENCE_ROUTING_WRITE_CAS,
            ACTION_PAIRING_CREATE,
            ACTION_PAIRING_APPROVE,
            ACTION_PAIRING_DENY,
            ACTION_PAIRING_REPLACE,
            ACTION_ACCESS_CREDENTIAL_PASSKEY_LIST,
            ACTION_ACCESS_CREDENTIAL_PASSKEY_REGISTER,
            ACTION_ACCESS_CREDENTIAL_PASSKEY_RENAME,
            ACTION_ACCESS_CREDENTIAL_PASSKEY_REVOKE,
            ACTION_ACCESS_CREDENTIAL_TOTP_ENROLL,
            ACTION_ACCESS_CREDENTIAL_TOTP_DISABLE,
            ACTION_ACCESS_CREDENTIAL_RECOVERY_REGENERATE,
            ACTION_ACCESS_CREDENTIAL_PASSWORD_SET,
            ACTION_ACCESS_CREDENTIAL_PASSWORD_CHANGE,
            ACTION_ACCESS_CREDENTIAL_PASSWORD_DISABLE,
        ]
        .into_iter()
        .collect()
    }
}
