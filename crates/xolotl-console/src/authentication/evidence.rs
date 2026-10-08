//! Authentication facts retained independently of session issuance and credentials.

use crate::ExternalAssurance;
use serde::{Deserialize, Serialize};

/// The successful verifications underlying a Console session.
///
/// Account instance, account revision and credential epoch belong to the session
/// envelope. Credential references describe past verification; a later authorized
/// credential change does not rewrite this history. Resource grants are separate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationEvidence {
    /// The primary verification, retained unchanged by step-up and management.
    pub primary: PrimaryAuthentication,
    /// The latest independent proof, if one was verified. Null explicitly means none.
    #[serde(deserialize_with = "Option::deserialize")]
    pub secondary: Option<SecondaryAuthentication>,
}

/// A primary credential that the service actually verified.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrimaryAuthentication {
    /// Verification of the account's unique password slot.
    Password {
        /// Verification completion time in milliseconds since the Unix epoch.
        verified_at: i64,
    },
    /// Verification with the selected registered ML-DSA-65 key.
    PublicKey {
        /// Canonical public-key descriptor selected by the verifier.
        credential_key: String,
        /// Verification completion time in milliseconds since the Unix epoch.
        verified_at: i64,
    },
    /// WebAuthn authentication with successful user verification (UV).
    ///
    /// Registration and assertions without UV cannot produce this evidence.
    PasskeyUv {
        /// The verified credential's existing base64url ID, without padding.
        credential_id: String,
        /// Verification completion time in milliseconds since the Unix epoch.
        verified_at: i64,
    },
    /// A trusted host verifier checked an external bearer assertion and the
    /// host resolved its stable identity to this exact local account instance.
    External {
        /// Installed mechanism identity.
        provider: String,
        /// Validated issuer or tenant namespace.
        issuer: String,
        /// Stable subject within the issuer.
        subject: String,
        /// Time this assertion was verified, distinct from user authentication.
        verified_at: i64,
        /// Proven user authentication time; absent when the assertion has none.
        authenticated_at: Option<i64>,
        /// Absolute expiry of the external assertion.
        valid_until: i64,
        /// Verifier-assessed assurance, not a local MFA enrollment assertion.
        assurance: ExternalAssurance,
    },
}

/// An independent proof verified after primary authentication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
pub enum SecondaryAuthentication {
    /// Authentication using an enrolled factor instance.
    Factor {
        /// The account-scoped factor instance selected by the service.
        factor_id: String,
        /// Verification mechanism resolved from that stored factor.
        provider_id: String,
        /// Verification completion time in milliseconds since the Unix epoch.
        verified_at: i64,
    },
    /// A one-time recovery code whose consumption was committed.
    RecoveryCode {
        /// Verification completion time in milliseconds since the Unix epoch.
        verified_at: i64,
    },
}

impl PrimaryAuthentication {
    /// Actual proof verification time, independent of later state writes or issuance.
    /// For external assertions this is not necessarily user authentication time.
    pub fn verified_at(&self) -> i64 {
        match self {
            Self::Password { verified_at }
            | Self::PublicKey { verified_at, .. }
            | Self::PasskeyUv { verified_at, .. }
            | Self::External { verified_at, .. } => *verified_at,
        }
    }

    /// An externally imposed hard session deadline, when present.
    pub fn valid_until(&self) -> Option<i64> {
        match self {
            Self::External { valid_until, .. } => Some(*valid_until),
            _ => None,
        }
    }
}

impl SecondaryAuthentication {
    /// Actual verification time, independent of later state writes or issuance.
    pub fn verified_at(&self) -> i64 {
        match self {
            Self::Factor { verified_at, .. } | Self::RecoveryCode { verified_at } => *verified_at,
        }
    }
}

impl AuthenticationEvidence {
    /// Current Console admission classification derived from verified facts.
    ///
    /// UV-verified Passkeys and primary authentication followed by an independent
    /// proof satisfy level 2. This summary does not imply phishing resistance or
    /// exclude recovery authentication; those policies must inspect the evidence.
    pub fn mfa_level(&self) -> u8 {
        if matches!(self.primary, PrimaryAuthentication::PasskeyUv { .. })
            || self.secondary.is_some()
        {
            2
        } else {
            1
        }
    }

    /// Latest proven user authentication time under Console's recent-auth policy.
    ///
    /// External assertion verification alone cannot establish user recency.
    /// A local secondary proof can establish it even when external user time is
    /// unknown. Refresh and credential management do not advance this timestamp.
    pub fn authenticated_at(&self) -> Option<i64> {
        let primary = match &self.primary {
            PrimaryAuthentication::External {
                authenticated_at, ..
            } => *authenticated_at,
            _ => Some(self.primary.verified_at()),
        };
        match (primary, self.secondary.as_ref()) {
            (Some(primary), Some(secondary)) => Some(primary.max(secondary.verified_at())),
            (None, Some(secondary)) => Some(secondary.verified_at()),
            (primary, None) => primary,
        }
    }
}
