//! Management failures and safe client projections.

use super::*;
use crate::mgmt::MgmtError;
use crate::protocol::{ConsoleErrorCode, ExecutionReference, OutcomeUnknownDetail};
use std::fmt;
use xolotl_types::UnresolvedOperations;

#[derive(Debug)]
pub(crate) enum ConsoleError {
    Auth(auth::AuthError),
    Mgmt(MgmtError),
    Federation(xolotl_federation::FederationError),
    NotAuthenticated,
    StepUpRequired,
    RateLimited,
    RegistryChanged {
        current_registry_rev: u64,
    },
    BadRequest(String),
    InvalidPrincipalIdentity(String),
    Operation(String),
    Runtime(xolotl_types::Failure),
    Finalization(xolotl_kernel::RequestFinishError),
    Context {
        source: Box<Self>,
        execution: Option<Box<ExecutionReference>>,
        unresolved_operations: Option<Box<UnresolvedOperations>>,
        runtime_completion: Option<Box<Value>>,
        cleanup_error: Option<Box<Self>>,
        session_invalidated: bool,
    },
}

impl From<xolotl_kernel::host::ClockDomainError> for ConsoleError {
    fn from(error: xolotl_kernel::host::ClockDomainError) -> Self {
        Self::Runtime(error.into())
    }
}

impl ConsoleError {
    pub(crate) fn with_execution(self, reference: ExecutionReference) -> Self {
        Self::Context {
            source: Box::new(self),
            execution: Some(Box::new(reference)),
            unresolved_operations: None,
            runtime_completion: None,
            cleanup_error: None,
            session_invalidated: false,
        }
    }

    pub(crate) fn with_unresolved_operations(self, unresolved: UnresolvedOperations) -> Self {
        if unresolved.is_empty() {
            return self;
        }
        Self::Context {
            source: Box::new(self),
            execution: None,
            unresolved_operations: Some(Box::new(unresolved)),
            runtime_completion: None,
            cleanup_error: None,
            session_invalidated: false,
        }
    }

    pub(crate) fn with_runtime_completion(self, completion: Value) -> Self {
        Self::Context {
            source: Box::new(self),
            execution: None,
            unresolved_operations: None,
            runtime_completion: Some(Box::new(completion)),
            cleanup_error: None,
            session_invalidated: false,
        }
    }

    pub(crate) fn with_cleanup_error(self, error: Self) -> Self {
        Self::Context {
            source: Box::new(self),
            execution: None,
            unresolved_operations: None,
            runtime_completion: None,
            cleanup_error: Some(Box::new(error)),
            session_invalidated: false,
        }
    }

    pub(crate) fn with_session_invalidation(self) -> Self {
        Self::Context {
            source: Box::new(self),
            execution: None,
            unresolved_operations: None,
            runtime_completion: None,
            cleanup_error: None,
            session_invalidated: true,
        }
    }

    pub(crate) fn session_invalidated(&self) -> bool {
        match self {
            Self::Context {
                source,
                session_invalidated,
                ..
            } => *session_invalidated || source.session_invalidated(),
            _ => false,
        }
    }

    pub(crate) fn kind(&self) -> &Self {
        match self {
            Self::Context { source, .. } => source.kind(),
            _ => self,
        }
    }
}

impl fmt::Display for ConsoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsoleError::Auth(err) => write!(f, "auth error: {err}"),
            ConsoleError::Mgmt(err) => write!(f, "management error: {err:?}"),
            ConsoleError::Federation(err) => write!(f, "federation management error: {err}"),
            ConsoleError::NotAuthenticated => f.write_str("not authenticated"),
            ConsoleError::StepUpRequired => f.write_str("step-up required"),
            ConsoleError::RateLimited => f.write_str("rate limited"),
            ConsoleError::RegistryChanged { .. } => {
                f.write_str("descriptor registry changed; refresh metadata before retrying")
            }
            ConsoleError::BadRequest(message) | ConsoleError::Operation(message) => {
                f.write_str(message)
            }
            ConsoleError::InvalidPrincipalIdentity(message) => {
                write!(f, "invalid principal identity path: {message}")
            }
            ConsoleError::Runtime(failure) => write!(f, "runtime execution: {failure}"),
            ConsoleError::Finalization(error) => error.fmt(f),
            ConsoleError::Context { source, .. } => source.fmt(f),
        }
    }
}

impl std::error::Error for ConsoleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Finalization(error) => Some(error),
            Self::Context { source, .. } => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<auth::AuthError> for ConsoleError {
    fn from(e: auth::AuthError) -> Self {
        Self::Auth(e)
    }
}

impl From<MgmtError> for ConsoleError {
    fn from(e: MgmtError) -> Self {
        Self::Mgmt(e)
    }
}

impl From<xolotl_federation::FederationError> for ConsoleError {
    fn from(error: xolotl_federation::FederationError) -> Self {
        Self::Federation(error)
    }
}

impl From<xolotl_types::PathError> for ConsoleError {
    fn from(e: xolotl_types::PathError) -> Self {
        Self::BadRequest(e.to_string())
    }
}

impl From<xolotl_state::StateFailure> for ConsoleError {
    fn from(e: xolotl_state::StateFailure) -> Self {
        Self::Operation(e.to_string())
    }
}

impl From<xolotl_kernel::FactError> for ConsoleError {
    fn from(e: xolotl_kernel::FactError) -> Self {
        Self::Operation(e.to_string())
    }
}

impl From<auth::AuthError> for ConsoleFailure {
    fn from(error: auth::AuthError) -> Self {
        use auth::AuthError;
        let code = match &error {
            AuthError::MissingBearer
            | AuthError::InvalidSession
            | AuthError::InvalidChallenge
            | AuthError::InvalidCredentials => ConsoleErrorCode::NotAuthenticated,
            AuthError::ExternalAuthenticationNotConfigured
            | AuthError::AccountAuthorityNotConfigured
            | AuthError::LocalAuthenticationUnavailable => ConsoleErrorCode::AdmissionRejected,
            AuthError::AccountUnavailable
            | AuthError::PermissionDenied
            | AuthError::MfaUsageDenied => ConsoleErrorCode::Forbidden,
            AuthError::RateLimited { .. } | AuthError::CapacityExceeded => {
                ConsoleErrorCode::RateLimited
            }
            AuthError::MfaRequired { .. } => ConsoleErrorCode::StepUpRequired,
            AuthError::ReauthenticationRequired => ConsoleErrorCode::NotAuthenticated,
            AuthError::InvalidMfaRequest | AuthError::InvalidCredentialRequest => {
                ConsoleErrorCode::BadRequest
            }
            AuthError::CredentialConflict => ConsoleErrorCode::Conflict,
            AuthError::LastPrimaryCredential | AuthError::MfaOperationUnavailable => {
                ConsoleErrorCode::AdmissionRejected
            }
            AuthError::SessionAdmissionRejected => ConsoleErrorCode::AdmissionRejected,
            AuthError::SessionCommitUnknown => ConsoleErrorCode::OutcomeUnknown,
            AuthError::InvalidUsername | AuthError::Query(_) => ConsoleErrorCode::BadRequest,
            AuthError::State(_)
            | AuthError::Crypto(_)
            | AuthError::AccountAuthorityUnavailable
            | AuthError::ExternalAuthenticationUnavailable => ConsoleErrorCode::Internal,
        };
        let message = if code == ConsoleErrorCode::Internal {
            "internal authentication error".into()
        } else {
            error.to_string()
        };
        let mut failure = Self::new(code, message);
        match error {
            AuthError::MfaRequired { options } => {
                failure.required_mfa_level = Some(2);
                failure.mfa = options.map(Box::new);
            }
            AuthError::RateLimited { retry_after_ms } => {
                failure.retry_after_ms = u64::try_from(retry_after_ms).ok();
            }
            _ => {}
        }
        failure
    }
}

impl ConsoleFailure {
    pub(crate) fn from_runtime_failure(failure: &xolotl_types::Failure) -> Self {
        use xolotl_types::Failure;
        let (code, message) = match failure {
            Failure::OutcomeUnknown {
                operation_ids,
                reason,
            } => {
                // Failure is host-authored, but only the small published
                // cause vocabulary may cross the Console boundary.
                let reason = match reason.as_str() {
                    "delivery_or_session_lost" => "delivery_or_session_lost",
                    "deadline_exceeded" => "deadline_exceeded",
                    "execution_cancelled" => "execution_cancelled",
                    "settlement_timeout" => "settlement_timeout",
                    "result_identity_mismatch" => "result_identity_mismatch",
                    _ => "unclassified",
                };
                // A trusted driver may still return an arbitrarily large
                // list. Project it into the same bounded evidence set as
                // execution results before retaining or encoding it.
                let mut bounded = UnresolvedOperations::default();
                for operation_id in operation_ids {
                    bounded.record(operation_id);
                }
                let unresolved_operations = bounded
                    .identities_incomplete
                    .then(|| Box::new(bounded.clone()));
                return Self {
                    outcome_unknown: Some(Box::new(OutcomeUnknownDetail {
                        operation_ids: bounded.operation_ids,
                        reason: reason.into(),
                    })),
                    unresolved_operations,
                    ..Self::new(
                        ConsoleErrorCode::OutcomeUnknown,
                        "runtime effect outcome is unknown; reconcile before retrying".into(),
                    )
                };
            }
            Failure::PermissionDenied { .. }
            | Failure::PolicyViolation { .. }
            | Failure::KernelNamespaceProtected => (
                ConsoleErrorCode::Forbidden,
                "runtime policy denied the operation".into(),
            ),
            Failure::InvalidInput { .. }
            | Failure::PathInvalid { .. }
            | Failure::NoHandler { .. } => (
                ConsoleErrorCode::BadRequest,
                "runtime resource, method, input or output mode is invalid".into(),
            ),
            Failure::RateLimited | Failure::BudgetExhausted { .. } => (
                ConsoleErrorCode::RateLimited,
                "runtime budget exceeded".into(),
            ),
            Failure::Timeout => (
                ConsoleErrorCode::Internal,
                "runtime deadline exceeded; effects may have occurred".into(),
            ),
            Failure::Cancelled => (
                ConsoleErrorCode::Internal,
                "runtime execution was cancelled; effects may have occurred".into(),
            ),
            _ => (
                ConsoleErrorCode::Internal,
                "runtime execution failed; effects may have occurred".into(),
            ),
        };
        Self::new(code, message)
    }
}

impl From<ConsoleError> for ConsoleFailure {
    fn from(error: ConsoleError) -> Self {
        let (code, message) = match error {
            ConsoleError::Finalization(error) => {
                return Self {
                    finalization_error: Some(crate::protocol::ConsoleFinalizationError {
                        error: std::sync::Arc::new(error),
                    }),
                    ..Self::new(
                        ConsoleErrorCode::Internal,
                        "runtime lifecycle cleanup remains pending".into(),
                    )
                };
            }
            ConsoleError::Context {
                source,
                execution,
                unresolved_operations,
                runtime_completion,
                cleanup_error,
                session_invalidated: _,
            } => {
                let mut failure = Self::from(*source);
                if execution.is_some() {
                    failure.execution = execution;
                }
                if runtime_completion.is_some() {
                    failure.runtime_completion = runtime_completion;
                }
                if let Some(cleanup_error) = cleanup_error {
                    failure.finalization_error = Self::from(*cleanup_error).finalization_error;
                }
                if let Some(unresolved) = unresolved_operations {
                    match failure.unresolved_operations.as_deref_mut() {
                        Some(existing) => existing.merge(&unresolved),
                        None => failure.unresolved_operations = Some(unresolved),
                    }
                }
                return failure;
            }
            ConsoleError::Auth(error) | ConsoleError::Mgmt(MgmtError::Auth(error)) => {
                return error.into();
            }
            ConsoleError::Mgmt(error) => match error {
                MgmtError::Conflict {
                    expected,
                    current_version,
                } => {
                    return Self {
                        current_version,
                        ..Self::new(
                            ConsoleErrorCode::Conflict,
                            format!(
                                "version conflict (optimistic concurrency): expected {expected:?}"
                            ),
                        )
                    };
                }
                MgmtError::InstallationConflict { expected, current } => {
                    return Self {
                        current_version: current.map(|revision| revision.version),
                        ..Self::new(
                            ConsoleErrorCode::Conflict,
                            format!(
                                "installation revision conflict: expected {expected:?}, current {current:?}"
                            ),
                        )
                    };
                }
                MgmtError::NotManageable(_) => (
                    ConsoleErrorCode::Forbidden,
                    "management path is not allowed".into(),
                ),
                MgmtError::Path(_) => (
                    ConsoleErrorCode::BadRequest,
                    "invalid management path".into(),
                ),
                MgmtError::Admission(reason) => (
                    ConsoleErrorCode::AdmissionRejected,
                    format!("config admission rejected: {reason}"),
                ),
                MgmtError::ValidationAtCapacity => (
                    ConsoleErrorCode::RateLimited,
                    "config validation capacity exceeded".into(),
                ),
                MgmtError::Query(reason) => (ConsoleErrorCode::BadRequest, reason),
                MgmtError::Operation(_) => (
                    ConsoleErrorCode::Internal,
                    "management operation failed".into(),
                ),
                MgmtError::Auth(error) => return error.into(),
            },
            ConsoleError::Federation(error) => {
                use xolotl_federation::FederationError;
                match error {
                    FederationError::RevisionConflict => (
                        ConsoleErrorCode::Conflict,
                        "federation catalog revision changed; read the row before retrying".into(),
                    ),
                    FederationError::Conflict => (
                        ConsoleErrorCode::AdmissionRejected,
                        "federation catalog ownership or authority conflict".into(),
                    ),
                    FederationError::Unauthorized => (
                        ConsoleErrorCode::Forbidden,
                        "federation management denied".into(),
                    ),
                    FederationError::Invalid(_) | FederationError::NotFound => (
                        ConsoleErrorCode::BadRequest,
                        "invalid federation management target or value".into(),
                    ),
                    FederationError::Capacity => (
                        ConsoleErrorCode::RateLimited,
                        "federation management capacity exceeded".into(),
                    ),
                    FederationError::Indeterminate => (
                        ConsoleErrorCode::OutcomeUnknown,
                        "federation catalog commit outcome is unknown; read the exact row before retrying".into(),
                    ),
                    FederationError::Gap { .. }
                    | FederationError::ResyncRequired { .. }
                    | FederationError::TrustedTimeUnavailable
                    | FederationError::ClockRollback
                    | FederationError::Corrupt
                    | FederationError::Storage(_) => (
                        ConsoleErrorCode::Internal,
                        "federation management failed".into(),
                    ),
                }
            }
            ConsoleError::NotAuthenticated => (
                ConsoleErrorCode::NotAuthenticated,
                "not authenticated".into(),
            ),
            ConsoleError::StepUpRequired => {
                return Self {
                    required_mfa_level: Some(2),
                    ..Self::new(ConsoleErrorCode::StepUpRequired, "step-up required".into())
                };
            }
            ConsoleError::RegistryChanged {
                current_registry_rev,
            } => {
                return Self {
                    current_registry_rev: Some(current_registry_rev),
                    ..Self::new(
                        ConsoleErrorCode::RegistryChanged,
                        "descriptor registry changed; refresh metadata before retrying".into(),
                    )
                };
            }
            ConsoleError::RateLimited => (
                ConsoleErrorCode::RateLimited,
                "console capacity exceeded".into(),
            ),
            ConsoleError::BadRequest(message) => (ConsoleErrorCode::BadRequest, message),
            ConsoleError::InvalidPrincipalIdentity(_) => (
                ConsoleErrorCode::Internal,
                "invalid console principal".into(),
            ),
            ConsoleError::Runtime(failure) => return Self::from_runtime_failure(&failure),
            ConsoleError::Operation(_) => (
                ConsoleErrorCode::Internal,
                "console operation failed".into(),
            ),
        };
        Self::new(code, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn unresolved_effects_do_not_change_the_program_failure_category() {
        let mut unresolved = UnresolvedOperations::default();
        assert!(unresolved.record("1/2/3/4/0"));
        let failure = ConsoleFailure::from(
            ConsoleError::Runtime(xolotl_types::Failure::InvalidInput {
                reason: "later branch failed".into(),
            })
            .with_unresolved_operations(unresolved.clone()),
        );
        assert_eq!(failure.code, ConsoleErrorCode::BadRequest);
        assert_eq!(failure.unresolved_operations.as_deref(), Some(&unresolved));
        assert!(failure.outcome_unknown.is_none());
    }

    #[test]
    fn oversized_unknown_identity_list_has_bounded_public_projection() -> anyhow::Result<()> {
        let operation_ids = (0..=xolotl_types::execution::MAX_UNRESOLVED_OPERATION_IDS)
            .map(|index| format!("effect-{index:04}"))
            .collect();
        let failure = ConsoleFailure::from(ConsoleError::Runtime(
            xolotl_types::Failure::OutcomeUnknown {
                operation_ids,
                reason: "deadline_exceeded".into(),
            },
        ));
        let detail = failure
            .outcome_unknown
            .as_deref()
            .context("missing outcome-unknown detail")?;
        anyhow::ensure!(
            detail.operation_ids.len() == xolotl_types::execution::MAX_UNRESOLVED_OPERATION_IDS
        );
        let unresolved = failure
            .unresolved_operations
            .as_deref()
            .context("missing unresolved operations")?;
        anyhow::ensure!(unresolved.identities_incomplete);
        anyhow::ensure!(detail.operation_ids == unresolved.operation_ids);
        anyhow::ensure!(unresolved.validate());
        Ok(())
    }
}
