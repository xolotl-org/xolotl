//! Console-owned authentication context in generic gateway audit details.
//!
//! A context summary describes the session used by an admitted request or a
//! successfully issued session. It is not evidence that this event performed
//! another authentication. Account ownership alone cannot create this summary.

use super::AuthError;
use crate::AuthenticationEvidence;
use std::collections::BTreeMap;
use xolotl_kernel::{Bootstrap, GatewayAudit};
use xolotl_types::Value;

/// Project verified provenance and the current derived admission classification.
/// No proof, verifier, recovery code or bearer secret enters this summary.
pub(crate) fn authentication_summary(authentication: &AuthenticationEvidence) -> Value {
    let mut summary = authentication.to_map();
    summary.insert(
        "mfa_level".into(),
        Value::integer(i64::from(authentication.mfa_level())),
    );
    summary.insert(
        "authenticated_at".into(),
        authentication
            .authenticated_at()
            .map_or(Value::null(), Value::integer),
    );
    Value::map(summary)
}

pub(super) fn record_auth_audit(
    boot: &Bootstrap,
    event: &str,
    username: Option<&str>,
    source_addr: Option<&str>,
    outcome: &str,
    authentication: Option<&AuthenticationEvidence>,
) -> Result<(), AuthError> {
    if !boot.kernel().facts().is_enabled() {
        return Ok(());
    }
    boot.record_gateway_audit(GatewayAudit {
        event,
        username,
        source_addr,
        outcome,
        details: authentication.map(|evidence| {
            Value::map(BTreeMap::from([(
                "authentication".into(),
                authentication_summary(evidence),
            )]))
        }),
    })
    .map_err(|e| AuthError::State(e.to_string()))
}

pub(super) fn audit_outcome(err: &AuthError) -> &'static str {
    match err {
        AuthError::ExternalAuthenticationNotConfigured => "external_authentication_not_configured",
        AuthError::ExternalAuthenticationUnavailable => "external_authentication_unavailable",
        AuthError::AccountAuthorityNotConfigured => "account_authority_not_configured",
        AuthError::AccountAuthorityUnavailable => "account_authority_unavailable",
        AuthError::LocalAuthenticationUnavailable => "local_authentication_unavailable",
        AuthError::InvalidUsername => "invalid_username",
        AuthError::MfaRequired { .. } => "mfa_required",
        AuthError::ReauthenticationRequired => "reauthentication_required",
        AuthError::InvalidMfaRequest => "invalid_mfa_request",
        AuthError::MfaUsageDenied => "mfa_usage_denied",
        AuthError::MfaOperationUnavailable => "mfa_operation_unavailable",
        AuthError::InvalidCredentialRequest => "invalid_credential_request",
        AuthError::CredentialConflict => "credential_conflict",
        AuthError::LastPrimaryCredential => "last_primary_credential",
        AuthError::InvalidCredentials => "invalid_credentials",
        AuthError::AccountUnavailable => "account_unavailable",
        AuthError::InvalidSession => "invalid_session",
        AuthError::InvalidChallenge => "invalid_challenge",
        AuthError::MissingBearer => "missing_bearer",
        AuthError::PermissionDenied => "permission_denied",
        AuthError::RateLimited { .. } | AuthError::CapacityExceeded => "rate_limited",
        AuthError::State(_) => "state_error",
        AuthError::Query(_) => "invalid_query",
        AuthError::SessionCommitUnknown => "session_outcome_unknown",
        AuthError::SessionAdmissionRejected => "session_admission_rejected",
        AuthError::Crypto(_) => "crypto_error",
    }
}
