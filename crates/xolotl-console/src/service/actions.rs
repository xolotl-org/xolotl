//! Transport-independent action routing; each domain owns its input handling.

use super::{
    ConsoleError, VisibilityAuditDetails, action_needs_visibility_gate, authority_why,
    authorize_fact_read, blocked_visibility_target, ensure_observable_state_path_str,
    entries_value, external_manifest_path, fact_path, facts, inference_backend_path,
    inference_group_path, inference_model_path, input_map, input_value, list_request, map_value,
    optional_bool_arg, optional_i64_arg, optional_string_arg, optional_u64_arg, optional_usize_arg,
    parse_operation_id, projection_status_path, record_visibility_audit, registry_rev,
    registry_snapshot, reject_secret_fields, require_config_write_safety, require_step_up,
    require_visibility_access, required_capability, serde_value, server_rev_hint, string_arg,
    string_list_arg, validate_authority_verb, validate_external_installation_def,
    validate_path_segment, validate_source_installation, value_arg,
};
use crate::auth::{self, ConsolePrincipal};
use crate::mgmt;
use crate::protocol::{
    self, ACTION_ACCESS_ROLE_LIST, ACTION_ACCESS_ROLE_READ, ACTION_ACCESS_ROLE_WRITE_CAS,
    ACTION_ACCESS_SESSION_LIST, ACTION_ACCESS_USER_DISABLE, ACTION_ACCESS_USER_LIST,
    ACTION_ACCESS_USER_READ, ACTION_ACCESS_USER_WRITE_CAS, ACTION_AUDIT_FACTS_RECENT,
    ACTION_AUTHORITY_ACTION_EXPLAIN, ACTION_AUTHORITY_ACTION_MATRIX,
    ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE, ACTION_AUTHORITY_RESOURCE_ACCESS, ACTION_CONFIG_LIST,
    ACTION_CONFIG_READ, ACTION_CONFIG_WRITE_CAS, ACTION_EXTERNAL_INSTALLATION_INSTALL,
    ACTION_EXTERNAL_INSTALLATION_LIST, ACTION_EXTERNAL_INSTALLATION_READ,
    ACTION_EXTERNAL_INSTALLATION_REVOKE, ACTION_EXTERNAL_INSTALLATION_START,
    ACTION_EXTERNAL_INSTALLATION_STOP, ACTION_EXTERNAL_INSTALLATION_UNINSTALL,
    ACTION_EXTERNAL_INSTALLATION_UPDATE, ACTION_EXTERNAL_MANIFEST_LIST,
    ACTION_EXTERNAL_MANIFEST_READ, ACTION_EXTERNAL_MANIFEST_WRITE_CAS, ACTION_HEALTH_SUMMARY,
    ACTION_INFERENCE_BACKEND_LIST, ACTION_INFERENCE_BACKEND_READ,
    ACTION_INFERENCE_BACKEND_WRITE_CAS, ACTION_INFERENCE_GROUP_LIST, ACTION_INFERENCE_GROUP_READ,
    ACTION_INFERENCE_GROUP_WRITE_CAS, ACTION_INFERENCE_MODEL_LIST, ACTION_INFERENCE_MODEL_READ,
    ACTION_INFERENCE_MODEL_WRITE_CAS, ACTION_INFERENCE_ROUTING_READ,
    ACTION_INFERENCE_ROUTING_WRITE_CAS, ACTION_LINEAGE_FACT_READ, ACTION_LINEAGE_TRACE_READ,
    ACTION_PAIRING_APPROVE, ACTION_PAIRING_CREATE, ACTION_PAIRING_DENY,
    ACTION_PROJECTION_IN_PROCESS_STATUS_LIST, ACTION_PROJECTION_IN_PROCESS_STATUS_READ,
    ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET, ACTION_PROTOCOL_DESCRIBE,
    ACTION_PROTOCOL_REGISTRY_SNAPSHOT, ACTION_RESOURCE_TYPE_DESCRIBE, ACTION_RESOURCE_TYPE_LIST,
    ACTION_RESOURCE_VIEW_DESCRIBE, ACTION_RUNTIME_PROCESS_INSPECT, ACTION_SECRET_CATALOG,
    ACTION_STATE_SNAPSHOT, ACTION_VISIBILITY_AUTHORITY_DESCRIBE, ACTION_VISIBILITY_STATE_LIST,
    ACTION_VISIBILITY_STATE_READ, ActionCall, ActionDescriptor, ActionResult, AuthorityTemplate,
};
use crate::recipes;
use crate::state::ConsoleState;
use std::{collections::BTreeMap, sync::Arc};
use xolotl_types::{
    ExternalInstallationDef, Path, ProcSpec, ProcessId, RestartPolicy, Transport, Value,
};

mod access;
mod catalog;
mod external;
mod federation;
mod inference;
mod observe;
mod visibility;
pub(crate) use observe::process_inspect;
use observe::{
    health_summary, session_list, snapshot, visibility_state_list, visibility_state_read,
};

/// Authenticated invocation context, independent of transport connection ownership.
pub(crate) struct ActionContext<'a> {
    pub state: &'a Arc<ConsoleState>,
    pub source_addr: Option<&'a str>,
    pub session_id: &'a str,
    pub delivery: Option<&'a super::delivery::DeliveryCollector>,
}

pub(crate) async fn dispatch_call(
    context: &ActionContext<'_>,
    principal: &ConsolePrincipal,
    call: ActionCall,
) -> Result<ActionResult, ConsoleError> {
    match call.action.as_str() {
        protocol::ACTION_EXTERNAL_SOURCE_CLAIM_INSPECT => Ok(value(
            context,
            super::source::inspect_claim(context, principal, &call).await?,
        )),
        protocol::ACTION_EXTERNAL_SOURCE_EVENT_DECISION_INSPECT => Ok(value(
            context,
            super::source::inspect_event(context, principal, &call).await?,
        )),
        protocol::ACTION_FEDERATION_PEER_READ
        | protocol::ACTION_FEDERATION_PEER_LIST
        | protocol::ACTION_FEDERATION_PEER_WRITE_CAS
        | protocol::ACTION_FEDERATION_PEER_ADMISSION_READ
        | protocol::ACTION_FEDERATION_PEER_ADMISSION_WRITE_CAS
        | protocol::ACTION_FEDERATION_EXPORT_READ
        | protocol::ACTION_FEDERATION_EXPORT_LIST
        | protocol::ACTION_FEDERATION_EXPORT_WRITE_CAS => Ok(value(
            context,
            federation::dispatch(context, principal, &call).await?,
        )),
        protocol::ACTION_RUNTIME_DESCRIBE => Ok(value(
            context,
            super::runtime::describe(context.state, principal)?,
        )),
        protocol::ACTION_RUNTIME_RESOURCE_DESCRIBE => Ok(value(
            context,
            super::runtime::resource(context.state, principal, call.input)?,
        )),
        protocol::ACTION_RUNTIME_OPERATION_INVOKE | protocol::ACTION_RUNTIME_PROGRAM_RUN => {
            return super::runtime::run(context, principal, &call, None).await;
        }
        protocol::ACTION_RUNTIME_OPERATION_SUBMIT | protocol::ACTION_RUNTIME_PROGRAM_SUBMIT => {
            return super::runtime::submit(context, principal, &call, None).await;
        }
        protocol::ACTION_RUNTIME_SUBMISSION_LOOKUP => Ok(value(
            context,
            super::runtime::lookup_submission(context, principal, &call).await?,
        )),
        protocol::ACTION_RUNTIME_EXECUTION_GET
        | protocol::ACTION_RUNTIME_EXECUTION_LIST
        | protocol::ACTION_RUNTIME_EXECUTION_RESULT
        | protocol::ACTION_RUNTIME_EXECUTION_OUTPUT_READ
        | protocol::ACTION_RUNTIME_EXECUTION_CANCEL
        | protocol::ACTION_RUNTIME_EXECUTION_FORGET => Ok(value(
            context,
            super::runtime::access_execution(context, principal, &call).await?,
        )),
        ACTION_PROTOCOL_DESCRIBE
        | ACTION_PROTOCOL_REGISTRY_SNAPSHOT
        | ACTION_PROTOCOL_ACTION_DESCRIPTOR_GET
        | ACTION_RESOURCE_TYPE_LIST
        | ACTION_RESOURCE_TYPE_DESCRIBE
        | ACTION_RESOURCE_VIEW_DESCRIBE
        | ACTION_AUTHORITY_PRINCIPAL_EFFECTIVE
        | ACTION_AUTHORITY_ACTION_MATRIX
        | ACTION_AUTHORITY_RESOURCE_ACCESS
        | ACTION_AUTHORITY_ACTION_EXPLAIN => catalog::dispatch(context, principal, &call).await,
        ACTION_VISIBILITY_AUTHORITY_DESCRIBE
        | ACTION_SECRET_CATALOG
        | ACTION_VISIBILITY_STATE_READ
        | ACTION_VISIBILITY_STATE_LIST
        | ACTION_STATE_SNAPSHOT
        | ACTION_RUNTIME_PROCESS_INSPECT
        | ACTION_AUDIT_FACTS_RECENT
        | ACTION_LINEAGE_TRACE_READ
        | ACTION_LINEAGE_FACT_READ
        | ACTION_HEALTH_SUMMARY => visibility::dispatch(context, principal, &call).await,
        ACTION_CONFIG_READ
        | ACTION_CONFIG_LIST
        | ACTION_CONFIG_WRITE_CAS
        | ACTION_ACCESS_USER_READ
        | ACTION_ACCESS_USER_LIST
        | ACTION_ACCESS_USER_WRITE_CAS
        | ACTION_ACCESS_USER_DISABLE
        | ACTION_ACCESS_ROLE_READ
        | ACTION_ACCESS_ROLE_LIST
        | ACTION_ACCESS_ROLE_WRITE_CAS
        | ACTION_ACCESS_SESSION_LIST => access::dispatch(context, principal, &call).await,
        ACTION_EXTERNAL_INSTALLATION_LIST
        | ACTION_EXTERNAL_INSTALLATION_READ
        | ACTION_EXTERNAL_INSTALLATION_INSTALL
        | ACTION_EXTERNAL_INSTALLATION_UPDATE
        | ACTION_EXTERNAL_INSTALLATION_UNINSTALL
        | ACTION_EXTERNAL_INSTALLATION_START
        | ACTION_EXTERNAL_INSTALLATION_STOP
        | ACTION_EXTERNAL_INSTALLATION_REVOKE
        | ACTION_EXTERNAL_MANIFEST_LIST
        | ACTION_EXTERNAL_MANIFEST_READ
        | ACTION_EXTERNAL_MANIFEST_WRITE_CAS
        | ACTION_PROJECTION_IN_PROCESS_STATUS_LIST
        | ACTION_PROJECTION_IN_PROCESS_STATUS_READ
        | ACTION_PAIRING_CREATE
        | ACTION_PAIRING_APPROVE
        | ACTION_PAIRING_DENY => external::dispatch(context, principal, &call).await,
        ACTION_INFERENCE_BACKEND_LIST
        | ACTION_INFERENCE_BACKEND_READ
        | ACTION_INFERENCE_BACKEND_WRITE_CAS
        | ACTION_INFERENCE_MODEL_LIST
        | ACTION_INFERENCE_MODEL_READ
        | ACTION_INFERENCE_MODEL_WRITE_CAS
        | ACTION_INFERENCE_GROUP_LIST
        | ACTION_INFERENCE_GROUP_READ
        | ACTION_INFERENCE_GROUP_WRITE_CAS
        | ACTION_INFERENCE_ROUTING_READ
        | ACTION_INFERENCE_ROUTING_WRITE_CAS => {
            inference::dispatch(context, principal, &call).await
        }
        other => Err(ConsoleError::BadRequest(format!(
            "unknown console action: {other}"
        ))),
    }
}

fn value(context: &ActionContext<'_>, out: Value) -> ActionResult {
    ActionResult::value(
        out,
        server_rev_hint(context.state),
        registry_rev(context.state),
    )
}
