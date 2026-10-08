//! Capability, identity and protected-data admission.

use super::*;
use crate::protocol::{ActionDescriptor, AuthorityTemplate};
use xolotl_types::{Capability, MethodAuthority};

pub(crate) fn ensure_observable_state_path(path: &Path) -> Result<(), ConsoleError> {
    if path.scheme() != "state" || path.cluster().is_some() {
        return Err(ConsoleError::BadRequest(
            "visibility.state actions require local state:// paths".into(),
        ));
    }
    if xolotl_types::is_vault_reserved(path) {
        return Err(ConsoleError::BadRequest(
            "state://vault/* is governed by secret.* custody actions".into(),
        ));
    }
    let first = path
        .segments()
        .first()
        .map(|s| s.as_str())
        .ok_or_else(|| ConsoleError::BadRequest("state path must name a subtree".into()))?;
    if matches!(first, "*" | "**") {
        return Err(ConsoleError::BadRequest(
            "wildcard first-segment visibility reads could include state://vault; use concrete business prefixes".into(),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_observable_state_path_str(raw: &str) -> Result<(), ConsoleError> {
    let path = Path::parse(raw)?;
    ensure_observable_state_path(&path)
}

pub(crate) fn blocked_visibility_target(raw: &str) -> String {
    let Ok(path) = Path::parse(raw) else {
        return "invalid_state_target".into();
    };
    if path.scheme() != "state" {
        return "non_state_target".into();
    }
    if path.cluster().is_some() {
        return "non_local_state_target".into();
    }
    if xolotl_types::is_vault_reserved(&path) {
        return "state://vault/**".into();
    }
    if path
        .segments()
        .first()
        .is_some_and(|segment| matches!(segment.as_str(), "*" | "**"))
    {
        return "state://**".into();
    }
    path.to_string()
}

pub(crate) fn require_process_inspect(principal: &ConsolePrincipal) -> Result<(), ConsoleError> {
    let path = Path::parse(crate::paths::PROCESS_INSPECT_EFFECT)?;
    if principal.grants.contains("perform", &path) {
        Ok(())
    } else {
        Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
    }
}

pub(crate) fn authorize_fact_read(
    principal: &ConsolePrincipal,
    process: Option<u64>,
) -> Result<(), ConsoleError> {
    let path = match process {
        Some(process) => fact_path(process)?,
        None => Path::parse("state://fact")?,
    };
    if principal.grants.contains("read", &path) {
        Ok(())
    } else {
        Err(ConsoleError::Auth(auth::AuthError::PermissionDenied))
    }
}

pub(crate) fn require_step_up(principal: &ConsolePrincipal) -> Result<(), ConsoleError> {
    if principal.authentication.mfa_level() >= 2 {
        Ok(())
    } else {
        Err(ConsoleError::StepUpRequired)
    }
}

pub(crate) fn require_visibility_access(
    principal: &ConsolePrincipal,
    call: &ActionCall,
) -> Result<(), ConsoleError> {
    require_visibility_gate(
        principal,
        call.scope.as_deref(),
        call.justification.as_deref(),
        call.ttl_ms,
    )
}

pub(crate) fn require_stream_visibility_access(
    principal: &ConsolePrincipal,
    stream: &StreamCall,
) -> Result<(), ConsoleError> {
    require_visibility_gate(
        principal,
        stream.scope.as_deref(),
        stream.justification.as_deref(),
        stream.ttl_ms,
    )
}

pub(crate) fn require_visibility_gate(
    principal: &ConsolePrincipal,
    scope: Option<&str>,
    justification: Option<&str>,
    ttl_ms: Option<u64>,
) -> Result<(), ConsoleError> {
    require_step_up(principal)?;
    validate_principal_identity(principal)?;
    let Some(scope) = scope else {
        return Err(ConsoleError::BadRequest(
            "visibility access requires a scope".into(),
        ));
    };
    if scope.len() > MAX_VISIBILITY_TEXT_BYTES || scope.trim().is_empty() {
        return Err(ConsoleError::BadRequest(format!(
            "visibility scope must be 1..={MAX_VISIBILITY_TEXT_BYTES} bytes"
        )));
    }
    let Some(justification) = justification else {
        return Err(ConsoleError::BadRequest(
            "visibility access requires a justification".into(),
        ));
    };
    if justification.len() > MAX_VISIBILITY_TEXT_BYTES || justification.trim().is_empty() {
        return Err(ConsoleError::BadRequest(format!(
            "visibility justification must be 1..={MAX_VISIBILITY_TEXT_BYTES} bytes"
        )));
    }
    let Some(ttl_ms) = ttl_ms else {
        return Err(ConsoleError::BadRequest(
            "visibility access requires ttl_ms".into(),
        ));
    };
    if ttl_ms == 0 || ttl_ms > MAX_VISIBILITY_TTL_MS {
        return Err(ConsoleError::BadRequest(format!(
            "visibility ttl_ms must be between 1 and {MAX_VISIBILITY_TTL_MS}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_principal_identity(
    principal: &ConsolePrincipal,
) -> Result<(), ConsoleError> {
    principal_identity_path(principal).map(|_| ())
}

pub(crate) fn principal_identity_path(principal: &ConsolePrincipal) -> Result<Path, ConsoleError> {
    let identity_path = Path::parse(&principal.identity_path)
        .map_err(|e| ConsoleError::InvalidPrincipalIdentity(e.to_string()))?;
    if identity_path.cluster().is_some()
        || identity_path.scheme() != "identity"
        || identity_path.segments().is_empty()
        || !identity_path.is_concrete()
    {
        return Err(ConsoleError::InvalidPrincipalIdentity(
            "identity path must be a concrete local identity path".into(),
        ));
    }
    Ok(identity_path)
}

pub(crate) fn require_config_write_safety(
    principal: &ConsolePrincipal,
    path: &Path,
) -> Result<(), ConsoleError> {
    if crate::mgmt::is_dedicated_management_path(path) {
        return Err(ConsoleError::BadRequest(
            "management path must use its dedicated console action".into(),
        ));
    }
    require_step_up(principal)?;
    Ok(())
}

pub(crate) fn action_needs_visibility_gate(descriptor: &ActionDescriptor) -> bool {
    matches!(
        descriptor.visibility,
        protocol::VisibilityTier::BusinessData | protocol::VisibilityTier::ProtectedPayload
    )
}

pub(crate) fn authority_why(status: &str, descriptor: &ActionDescriptor) -> Vec<String> {
    let mut why = Vec::new();
    match status {
        "input_required" => why.push("templates are not fully covered; concrete targets, predicates and optional sections require action input".into()),
        "step_up_required" => why.push("mfa_level >= 2 is required".into()),
        "visibility_gate_required" => {
            why.push("scope, justification, and ttl_ms are required per call".into())
        }
        _ => {}
    }
    why.push("template coverage is advisory; it neither grants nor denies a concrete call".into());
    if descriptor.requires_step_up {
        why.push("action is marked step-up sensitive".into());
    }
    why
}

pub(crate) fn required_capability(
    required: &AuthorityTemplate,
) -> Result<Capability, ConsoleError> {
    let path = Path::parse(&required.target)?;
    Ok(Capability {
        verb: required.verb.clone(),
        cluster: path.cluster().map(str::to_string),
        scheme: path.scheme().to_string(),
        segments: path.segments().to_vec(),
        method: None,
        predicate: None,
    })
}

pub(crate) fn validate_authority_verb(verb: &str) -> Result<(), ConsoleError> {
    if MethodAuthority::ALL
        .iter()
        .any(|authority| authority.verb() == verb)
        || matches!(verb, "spawn-with" | "act-as" | "delegate")
    {
        Ok(())
    } else {
        Err(ConsoleError::BadRequest(format!(
            "unsupported authority verb: {verb}"
        )))
    }
}
