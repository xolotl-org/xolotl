//! Structured execution failures, independent of resident data ownership.

use crate::Path;
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// Outcome failure. Failure values are carried in `Outcome::Fail` and may be
/// handled by `OrElse`.
///
/// This closed vocabulary is shared by execution and lossless wire adapters.
/// Application-specific categories use `Custom`; adding a core variant requires
/// every structural adapter to handle it explicitly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Failure {
    /// The caller lacked one or more required capabilities or rights.
    PermissionDenied {
        /// Required capability/right labels.
        required: Vec<String>,
        /// Capability/right labels actually held by the caller.
        actual: Vec<String>,
    },
    /// No driver or binding handles the target path.
    NoHandler {
        /// Target path that could not be handled.
        path: Path,
    },
    /// A cost, token, or inflight budget was exhausted.
    BudgetExhausted {
        /// Budget dimension that failed.
        dim: String,
    },
    /// The target rejected work due to rate limits.
    RateLimited,
    /// The operation is suspended pending human approval. Unlike a
    /// hard denial, this is *retryable*: once the approval is granted (the
    /// broker records `approved`), re-executing the operation passes. Carries
    /// the approval key to wait on and a human-readable reason.
    ApprovalPending {
        /// State key or broker key the process waits on.
        approval_key: String,
        /// Human-readable approval reason.
        reason: String,
    },
    /// Operation exceeded its time budget.
    Timeout,
    /// Operation or process was cancelled.
    Cancelled,
    /// Recovery refused to replay the operation without operator action.
    Quarantined {
        /// Operation id held in quarantine.
        op_id: String,
        /// Quarantine reason.
        reason: String,
    },
    /// Input failed validation before reaching the handler.
    InvalidInput {
        /// Validation failure detail.
        reason: String,
    },
    /// Driver or external handler returned an error.
    HandlerError {
        /// Stable handler error class.
        kind: String,
        /// Handler error detail safe to surface.
        message: String,
    },
    /// A non-kernel caller attempted to mutate a reserved namespace.
    KernelNamespaceProtected,
    /// A residual policy check (CompiledCheck) rejected an Operation because it
    /// violates a safety policy (injection guard, redaction, namespace
    /// protection).
    PolicyViolation {
        /// Policy name or identifier.
        policy: String,
        /// Policy failure detail.
        detail: String,
    },
    /// The Operation target path is syntactically valid but semantically
    /// invalid (e.g. `state://` with zero segments, or `effect://` with only
    /// one segment).
    PathInvalid {
        /// Path that failed semantic validation.
        path: Path,
        /// Validation failure detail.
        reason: String,
    },
    /// Fallback for errors not represented by a stable variant yet.
    Custom {
        /// Stable custom error class.
        kind: String,
        /// Error detail safe to surface.
        message: String,
    },
}

impl core::fmt::Display for Failure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Failure::PermissionDenied { required, .. } => {
                write!(f, "permission denied (required: {:?})", required)
            }
            Failure::NoHandler { path } => write!(f, "no handler for {}", path),
            Failure::BudgetExhausted { dim } => write!(f, "budget exhausted: {}", dim),
            Failure::RateLimited => write!(f, "rate limited"),
            Failure::ApprovalPending {
                approval_key,
                reason,
            } => write!(f, "approval pending ({approval_key}): {reason}"),
            Failure::Timeout => write!(f, "timeout"),
            Failure::Cancelled => write!(f, "cancelled"),
            Failure::Quarantined { reason, .. } => write!(f, "quarantined: {}", reason),
            Failure::InvalidInput { reason } => write!(f, "invalid input: {}", reason),
            Failure::HandlerError { message, .. } => write!(f, "handler: {}", message),
            Failure::KernelNamespaceProtected => write!(f, "kernel namespace protected"),
            Failure::PolicyViolation { policy, detail } => {
                write!(f, "policy violation ({policy}): {detail}")
            }
            Failure::PathInvalid { path, reason } => write!(f, "invalid path ({path}): {reason}"),
            Failure::Custom { message, .. } => f.write_str(message),
        }
    }
}

impl core::error::Error for Failure {}

impl Failure {
    /// Construct a policy violation failure.
    pub fn policy(policy: impl Into<String>, detail: impl Into<String>) -> Self {
        Failure::PolicyViolation {
            policy: policy.into(),
            detail: detail.into(),
        }
    }

    /// Construct a semantic path validation failure.
    pub fn path_invalid(path: Path, reason: impl Into<String>) -> Self {
        Failure::PathInvalid {
            path,
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use anyhow::ensure;

    #[test]
    fn failure_display() -> anyhow::Result<()> {
        let f = Failure::NoHandler {
            path: crate::path::p("effect://x/post")?,
        };
        ensure!(
            f.to_string().contains("effect://x/post"),
            "failure display omitted path"
        );
        Ok(())
    }
}
