//! Safe failure data shared by the service and every transport adapter.

use super::{ConsoleErrorCode, ExecutionReference};
use crate::mfa::MfaOptions;
use serde::{Deserialize, Serialize};
use std::fmt;
use xolotl_types::UnresolvedOperations;

/// Host-authored identity and cause for an effect whose outcome is unknown.
/// Reconcile the operation with its target before issuing another effect.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutcomeUnknownDetail {
    /// Opaque stable operation or outbound command identities assigned by the host.
    pub operation_ids: Vec<String>,
    /// Bounded host-classified cause; never copied from a remote error message.
    pub reason: String,
}

/// A sanitized failure with optional facts that help a caller recover.
/// Recovery hints do not guarantee that retrying a mutation is safe.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsoleFailure {
    /// Machine-readable category.
    pub code: ConsoleErrorCode,
    /// Safe diagnostic without credentials or backend details.
    pub message: Box<str>,
    /// Known delay before another attempt; absent when no delay is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// MFA level required by the failed admission check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_mfa_level: Option<u8>,
    /// Account-specific choices, disclosed only after primary or bearer authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa: Option<Box<MfaOptions>>,
    /// Config version observed by the failed comparison. Absence means no usable
    /// version was observed; it does not prove the record is still absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version: Option<u64>,
    /// Current registry revision when the caller supplied a stale contract.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_registry_rev: Option<u64>,
    /// Host-authored uncertain effect; absent for remote handler errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome_unknown: Option<Box<OutcomeUnknownDetail>>,
    /// Other unresolved effects retained even when a later failure was caught.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unresolved_operations: Option<Box<UnresolvedOperations>>,
    /// Allocated execution, including failures during preparation or finalization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<Box<ExecutionReference>>,
    /// Bounded known body and separate cleanup projection after lifecycle or delivery failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_completion: Option<Box<xolotl_types::Value>>,
    /// Native-only typed lifecycle cause and cleanup custody, never serialized to a peer.
    #[serde(skip)]
    pub finalization_error: Option<ConsoleFinalizationError>,
}

/// Clones share one failed lifecycle attempt and its original cleanup pin.
#[derive(Clone, Debug)]
pub struct ConsoleFinalizationError {
    /// Typed failure retained for a trusted native host's cleanup retry.
    pub error: std::sync::Arc<xolotl_kernel::RequestFinishError>,
}

impl PartialEq for ConsoleFinalizationError {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.error, &other.error)
    }
}

impl Eq for ConsoleFinalizationError {}

impl ConsoleFailure {
    /// Construct a failure without inventing recovery hints.
    pub fn new(code: ConsoleErrorCode, message: String) -> Self {
        Self {
            code,
            message: message.into_boxed_str(),
            retry_after_ms: None,
            required_mfa_level: None,
            mfa: None,
            current_version: None,
            current_registry_rev: None,
            outcome_unknown: None,
            unresolved_operations: None,
            execution: None,
            runtime_completion: None,
            finalization_error: None,
        }
    }
}

impl fmt::Display for ConsoleFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConsoleFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.finalization_error
            .as_ref()
            .map(|failure| failure.error.as_ref() as &(dyn std::error::Error + 'static))
    }
}
