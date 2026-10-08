//! Redacted management and transport audit records.

use super::*;
use crate::auth::audit::authentication_summary;
use crate::mgmt::MgmtError;

pub(crate) fn record_console_error_audit(
    state: &Arc<ConsoleState>,
    principal: Option<&ConsolePrincipal>,
    source_addr: Option<&str>,
    err: &ConsoleError,
) {
    match err.kind() {
        ConsoleError::StepUpRequired => {
            record_call_audit(state, principal, source_addr, "step_up_required")
        }
        ConsoleError::Auth(auth::AuthError::PermissionDenied) => {
            record_call_audit(state, principal, source_addr, "permission_denied")
        }
        ConsoleError::Mgmt(MgmtError::Auth(auth::AuthError::PermissionDenied))
        | ConsoleError::Mgmt(MgmtError::NotManageable(_)) => {
            record_call_audit(state, principal, source_addr, "permission_denied")
        }
        ConsoleError::NotAuthenticated => {
            record_call_audit(state, principal, source_addr, "not_authenticated")
        }
        ConsoleError::RateLimited | ConsoleError::Mgmt(MgmtError::ValidationAtCapacity) => {
            record_call_audit(state, principal, source_addr, "rate_limited")
        }
        ConsoleError::BadRequest(_)
        | ConsoleError::Mgmt(MgmtError::Path(_))
        | ConsoleError::Mgmt(MgmtError::Admission(_)) => {
            record_call_audit(state, principal, source_addr, "bad_request")
        }
        _ => {}
    }
}

/// Connection attribution may come from a cached username, never a current
/// authentication claim. Verified calls record their context separately.
#[cfg(feature = "http")]
pub(crate) fn record_boundary_audit(
    state: &Arc<ConsoleState>,
    username: Option<&str>,
    source_addr: Option<&str>,
    event: &'static str,
    outcome: &'static str,
) {
    record_event(
        state,
        xolotl_kernel::GatewayAudit {
            event,
            username,
            source_addr,
            outcome,
            details: None,
        },
    );
}

fn record_event(state: &ConsoleState, audit: xolotl_kernel::GatewayAudit<'_>) {
    let (event, outcome, username, source_addr) = (
        audit.event,
        audit.outcome,
        audit.username,
        audit.source_addr,
    );
    if let Err(error) = state.boot.record_optional_gateway_audit(audit) {
        tracing::warn!(
            ?error,
            event,
            outcome,
            username = username.unwrap_or("<anonymous>"),
            source_addr = source_addr.unwrap_or("unknown"),
            "console call audit record failed"
        );
    }
}

pub(crate) struct VisibilityAuditDetails<'a> {
    scope: Option<&'a str>,
    justification: Option<&'a str>,
    ttl_ms: Option<u64>,
    target: Option<&'a str>,
}

impl<'a> VisibilityAuditDetails<'a> {
    pub(crate) fn action(call: &'a ActionCall, target: Option<&'a str>) -> Self {
        Self {
            scope: call.scope.as_deref(),
            justification: call.justification.as_deref(),
            ttl_ms: call.ttl_ms,
            target,
        }
    }

    pub(crate) fn stream(stream: &'a StreamCall, target: Option<&'a str>) -> Self {
        Self {
            scope: stream.scope.as_deref(),
            justification: stream.justification.as_deref(),
            ttl_ms: stream.ttl_ms,
            target,
        }
    }
}

pub(crate) fn record_visibility_audit(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    source_addr: Option<&str>,
    outcome: &'static str,
    audit: VisibilityAuditDetails<'_>,
) -> Result<(), ConsoleError> {
    if !state.boot.kernel().facts().is_enabled() {
        return Ok(());
    }
    let mut details = BTreeMap::new();
    details.insert(
        "authentication".into(),
        authentication_summary(&principal.authentication),
    );
    if let Some(scope) = audit.scope {
        details.insert("scope".into(), Value::string(scope.to_string()));
    }
    if let Some(justification) = audit.justification {
        details.insert(
            "justification".into(),
            Value::string(justification.to_string()),
        );
    }
    if let Some(ttl_ms) = audit.ttl_ms {
        details.insert(
            "ttl_ms".into(),
            Value::integer(u64_to_i64_saturating(ttl_ms)),
        );
    }
    if let Some(target) = audit.target {
        details.insert("target".into(), Value::string(target.to_string()));
    }
    state
        .boot
        .record_gateway_audit(xolotl_kernel::GatewayAudit {
            event: "console_visibility",
            username: Some(principal.username.as_str()),
            source_addr,
            outcome,
            details: Some(Value::map(details)),
        })?;
    Ok(())
}

fn record_call_audit(
    state: &Arc<ConsoleState>,
    principal: Option<&ConsolePrincipal>,
    source: Option<&str>,
    outcome: &'static str,
) {
    if !state.boot.kernel().facts().is_enabled() {
        return;
    }
    record_event(
        state,
        xolotl_kernel::GatewayAudit {
            event: "console_call",
            username: principal.map(|principal| principal.username.as_str()),
            source_addr: source,
            outcome,
            details: principal.map(|principal| {
                map_value([(
                    "authentication",
                    authentication_summary(&principal.authentication),
                )])
            }),
        },
    );
}

#[cfg(test)]
mod tests;
