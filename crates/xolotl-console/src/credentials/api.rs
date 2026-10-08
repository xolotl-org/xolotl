//! Transport-independent primary credential lifecycle.

use crate::LoginResponse;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Manage the caller's credentials, or an explicitly authorized account.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequest {
    /// Defaults to the authenticated account. Another account requires recent
    /// MFA level 2, user-management authority and authority over that account.
    #[serde(default)]
    pub username: Option<String>,
    /// A single atomic change or metadata query.
    pub operation: CredentialOperation,
}

/// Credential operations. Passkey enrollment uses its own WebAuthn ceremony;
/// second-factor self-service uses [`crate::mfa::MfaRequest`].
#[derive(Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum CredentialOperation {
    /// List metadata, never password hashes or WebAuthn verifier material.
    Status {},
    /// Set or replace the password, enforcing the built-in password policy.
    SetPassword {
        /// New plaintext password. Consumed only at the authentication boundary.
        password: String,
    },
    /// Disable password login. At least one other primary credential must remain.
    DisablePassword {},
    /// Register an ML-DSA-65 public key for signed-challenge login.
    AddPublicKey {
        /// `ml-dsa-65:` followed by the base64url-encoded raw public key.
        key: String,
    },
    /// Remove a registered public-key descriptor.
    RemovePublicKey {
        /// Exact canonical descriptor returned by Status.
        key: String,
    },
    /// Update a passkey label without invalidating sessions.
    RenamePasskey {
        /// Base64url credential identifier returned by Status or registration.
        credential_id: String,
        /// Human-readable label, 1–128 UTF-8 bytes, without control characters.
        label: String,
    },
    /// Revoke a passkey and invalidate sessions and pending ceremonies.
    RevokePasskey {
        /// Base64url credential identifier returned by Status or registration.
        credential_id: String,
    },
    /// Administrative recovery for another account: remove its independent
    /// factors, pending enrollment and recovery codes, retaining primary credentials.
    /// Requires the same recent MFA and target authority as administrative resets.
    ResetSecondFactors {},
}

impl fmt::Debug for CredentialOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Status {} => "Status",
            Self::SetPassword { .. } => "SetPassword",
            Self::DisablePassword {} => "DisablePassword",
            Self::AddPublicKey { .. } => "AddPublicKey",
            Self::RemovePublicKey { .. } => "RemovePublicKey",
            Self::RenamePasskey { .. } => "RenamePasskey",
            Self::RevokePasskey { .. } => "RevokePasskey",
            Self::ResetSecondFactors {} => "ResetSecondFactors",
        };
        f.debug_struct(name).finish_non_exhaustive()
    }
}

/// Safe passkey metadata; timestamps are Unix milliseconds.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PasskeySummary {
    /// Identifier accepted by rename and revoke.
    pub credential_id: String,
    /// Label selected at registration or rename.
    pub label: String,
    /// Registration time.
    pub created_at: i64,
    /// Most recent successful assertion time, if any.
    pub last_used_at: Option<i64>,
}

/// Credential metadata or the result of a committed change.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CredentialResponse {
    /// Current primary credential metadata.
    Current {
        /// Account whose credentials were queried.
        username: String,
        /// Whether password authentication is available.
        password_enabled: bool,
        /// Last password set/disable time in Unix milliseconds.
        password_changed_at: Option<i64>,
        /// Canonical ML-DSA-65 public-key descriptors.
        public_keys: Vec<String>,
        /// Bounded passkey metadata, ordered by credential identifier.
        passkeys: Vec<PasskeySummary>,
        /// Per-account passkey limit.
        max_passkeys: usize,
        /// Per-account public-key limit.
        max_public_keys: usize,
    },
    /// The mutation committed. A lost response is not a rollback; use a fresh
    /// login and read Status before retrying.
    Updated {
        /// Credential changes invalidate every old token, SID and challenge for
        /// this account. Label-only changes leave sessions valid.
        sessions_invalidated: bool,
        /// Replacement session for a change to the caller's own credentials.
        /// Never issued for another account or for label-only changes.
        session: Option<LoginResponse>,
    },
}
