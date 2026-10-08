//! Trusted host extension for exchanging a verified external primary assertion.
//!
//! The public service accepts only opaque assertion bytes. Only an installed
//! verifier can produce identity facts. The separately installed account
//! authority resolves those facts to one current account instance.
//! A single host permit covers preparation until session or bounded continuation
//! admission; verifier completion alone does not release that capacity.

use super::*;
use std::{future::Future, pin::Pin, sync::Arc};

/// An asynchronous host verification or binding lookup.
pub type ExternalAuthFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ExternalAuthError>> + Send + 'a>>;

/// A rejected assertion or an unavailable trusted identity system.
#[derive(Debug, Error)]
pub enum ExternalAuthError {
    /// Signature, issuer, audience, binding, or policy validation rejected the assertion.
    #[error("external assertion rejected")]
    Rejected,
    /// The trusted host extension could not complete its check.
    #[error("external authentication unavailable")]
    Unavailable,
}

/// Facts established by the installed verifier, never accepted as service input.
#[derive(Clone, Debug)]
pub struct VerifiedExternalIdentity {
    /// Stable host-selected mechanism identifier (for example, an OIDC provider).
    pub provider: String,
    /// Validated issuer, including tenant where needed to avoid subject collision.
    pub issuer: String,
    /// Stable subject within that issuer; display names and email are unsuitable.
    pub subject: String,
    /// Time this particular assertion was verified, in Unix milliseconds.
    pub verified_at: i64,
    /// Proven user authentication time, if the mechanism can establish it.
    /// Token issue time and exchange time must not be substituted for this field.
    pub authenticated_at: Option<i64>,
    /// Absolute expiry of the verified assertion, in Unix milliseconds.
    pub valid_until: i64,
    /// Assurance assessed by the verifier. Console currently admits every
    /// external primary at level 1; this fact does not bypass enrolled factors.
    pub assurance: ExternalAssurance,
}

/// The verifier's descriptive assurance, separate from Console MFA policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalAssurance {
    /// The verifier established one primary authentication.
    Primary,
    /// The verifier established multiple factors, without an automatic local MFA mapping.
    MultiFactor,
}

/// Trusted host verifier. Implementations must validate signatures, issuer,
/// audience, expiry and replay policy before returning verified facts.
pub trait ExternalPrimaryAuthentication: Send + Sync + 'static {
    /// Verify an opaque bearer assertion using the trusted host mechanism.
    fn verify<'a>(
        &'a self,
        assertion: &'a [u8],
    ) -> ExternalAuthFuture<'a, VerifiedExternalIdentity>;
}

pub(super) type InstalledExternalAuthentication = Option<Arc<dyn ExternalPrimaryAuthentication>>;

const MAX_ASSERTION_BYTES: usize = 64 * 1024;
const MAX_IDENTITY_BYTES: usize = 1024;
const MAX_VERIFICATION_AGE_MS: i64 = 30_000;

impl ConsoleAuth {
    pub(crate) async fn exchange_external(
        &self,
        boot: &Bootstrap,
        assertion: &[u8],
        source: String,
    ) -> Result<AuthenticationResponse, AuthError> {
        let result = self
            .exchange_external_inner(boot.kernel().state(), assertion, &source)
            .await;
        let (event, username, outcome, evidence) = match &result {
            Ok((AuthenticationResponse::Authenticated { session }, username)) => (
                "console_login",
                Some(username.as_str()),
                "ok",
                Some(&session.authentication),
            ),
            Ok((AuthenticationResponse::Continue(_), username)) => (
                "console_credential",
                Some(username.as_str()),
                "authentication_pending",
                None,
            ),
            Err(error) => ("console_login_failed", None, audit_outcome(error), None),
        };
        record_auth_audit(boot, event, username, Some(&source), outcome, evidence)?;
        result.map(|(response, _)| response)
    }

    async fn exchange_external_inner(
        &self,
        state: &Backend,
        assertion: &[u8],
        source: &str,
    ) -> Result<(AuthenticationResponse, String), AuthError> {
        let installed = self
            .external
            .as_ref()
            .ok_or(AuthError::ExternalAuthenticationNotConfigured)?;
        if assertion.is_empty() || assertion.len() > MAX_ASSERTION_BYTES {
            return Err(AuthError::InvalidCredentials);
        }
        self.check_rate_limits("external", source, self.host_runtime.now_millis())?;
        let _permit = self
            .external_verifications
            .try_acquire()
            .map_err(|_error| AuthError::CapacityExceeded)?;
        let deadline = crate::host_time::after(&self.host_runtime, Duration::from_secs(10))
            .map_err(|_error| AuthError::ExternalAuthenticationUnavailable)?;
        let identity =
            crate::host_time::timeout_at(&self.host_runtime, deadline, installed.verify(assertion))
                .await
                .map_err(|_error| AuthError::ExternalAuthenticationUnavailable)?
                .map_err(external_error)?;
        validate_identity(&identity, self.host_runtime.now_millis())?;
        let account = self.resolve_external_account(state, &identity).await?;
        if !account.active {
            return Err(AuthError::AccountUnavailable);
        }
        let credentials =
            credentials::read_by_key(state, &account.key, self.credential_sealer()?).await?;
        validate_identity(&identity, self.host_runtime.now_millis())?;
        let username = account.display_name.clone();
        let response = self
            .start_authentication(
                state,
                AuthenticationStart {
                    account: &account,
                    credentials,
                    primary: PrimaryAuthentication::External {
                        provider: identity.provider,
                        issuer: identity.issuer,
                        subject: identity.subject,
                        verified_at: identity.verified_at,
                        authenticated_at: identity.authenticated_at,
                        valid_until: identity.valid_until,
                        assurance: identity.assurance,
                    },
                    purpose: AuthenticationPurpose::Login,
                    proof: None,
                    bearer: None,
                    source,
                    authority_ceiling: None,
                },
            )
            .await?;
        Ok((response, username))
    }
}

fn external_error(error: ExternalAuthError) -> AuthError {
    match error {
        ExternalAuthError::Rejected => AuthError::InvalidCredentials,
        ExternalAuthError::Unavailable => AuthError::ExternalAuthenticationUnavailable,
    }
}

fn validate_identity(identity: &VerifiedExternalIdentity, now: i64) -> Result<(), AuthError> {
    let valid = [&identity.provider, &identity.issuer, &identity.subject]
        .into_iter()
        .all(|value| {
            !value.is_empty()
                && value.len() <= MAX_IDENTITY_BYTES
                && !value.chars().any(char::is_control)
        });
    if !valid
        || identity.verified_at < 0
        || identity.verified_at > now
        || now.saturating_sub(identity.verified_at) > MAX_VERIFICATION_AGE_MS
        || identity.valid_until <= now
        || identity
            .authenticated_at
            .is_some_and(|at| at < 0 || at > identity.verified_at)
    {
        return Err(AuthError::InvalidCredentials);
    }
    Ok(())
}
