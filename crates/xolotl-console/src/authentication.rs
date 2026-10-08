//! Authentication results and bounded continuation requests, independent of transport.

mod evidence;
pub use evidence::{AuthenticationEvidence, PrimaryAuthentication, SecondaryAuthentication};

use crate::{
    LoginResponse,
    mfa::{MfaOptions, MfaProof},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// An opaque bearer assertion encoded as unpadded base64url for HTTP exchange.
/// Its verification semantics belong to the installed trusted host provider.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAssertionRequest {
    /// Assertion bytes, unpadded base64url encoded. Never log this field.
    pub assertion: String,
}

impl fmt::Debug for ExternalAssertionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExternalAssertionRequest")
            .finish_non_exhaustive()
    }
}

/// A completed authentication or a limited continuation of verified primary proof.
/// A continuation is not a session and cannot authorize ordinary Console calls.
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AuthenticationResponse {
    /// All required proofs have committed and a bearer session has been issued.
    Authenticated {
        /// Newly issued authenticated session.
        session: LoginResponse,
    },
    /// Authentication requires another bounded step.
    Continue(AuthenticationContinuation),
}

impl AuthenticationResponse {
    /// Extract a completed session, or retain the continuation for its next step.
    /// The continuation is boxed only on this conversion's incomplete path.
    pub fn into_session(self) -> Result<LoginResponse, Box<AuthenticationContinuation>> {
        match self {
            Self::Authenticated { session } => Ok(session),
            Self::Continue(next) => Err(Box::new(next)),
        }
    }
}

impl fmt::Debug for AuthenticationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authenticated { .. } => f.debug_struct("Authenticated").finish_non_exhaustive(),
            Self::Continue(next) => f.debug_tuple("Continue").field(next).finish(),
        }
    }
}

/// A one-use continuation and its public next step. Retain it like a secret.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticationContinuation {
    /// Opaque secret, rotated after every consumed step. Never log this value.
    pub continuation: String,
    /// Original absolute deadline in Unix milliseconds; continuing never extends it.
    pub expires_at: i64,
    /// Input or waiting action currently accepted by the service.
    pub step: AuthenticationStep,
}

impl fmt::Debug for AuthenticationContinuation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticationContinuation")
            .field("expires_at", &self.expires_at)
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

/// Public progress of one authentication. Provider payloads are bounded, opaque data.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticationStep {
    /// Select an interactive factor, or submit a direct factor/recovery proof.
    ChooseFactor {
        /// Account factors disclosed only after primary or bearer authentication.
        options: MfaOptions,
    },
    /// Submit a response matching this challenge round's response schema.
    Challenge {
        /// Credential instance fixed for this interaction.
        factor_id: String,
        /// Installed mechanism used by the selected instance.
        provider_id: String,
        /// Public challenge; may be sensitive and must not be logged.
        challenge: Value,
        /// JSON Schema for the response accepted by this challenge round.
        response_schema: Value,
    },
    /// Wait for external approval, then send an explicit poll.
    Pending {
        /// Credential instance fixed for this interaction.
        factor_id: String,
        /// Installed mechanism used by the selected instance.
        provider_id: String,
        /// Bounded provider status, not private verification state.
        status: Value,
        /// Earliest useful poll, in milliseconds from this response.
        retry_after_ms: i64,
    },
}

impl fmt::Debug for AuthenticationStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChooseFactor { .. } => f.debug_struct("ChooseFactor").finish_non_exhaustive(),
            Self::Challenge {
                factor_id,
                provider_id,
                ..
            } => f
                .debug_struct("Challenge")
                .field("factor_id", factor_id)
                .field("provider_id", provider_id)
                .finish_non_exhaustive(),
            Self::Pending {
                factor_id,
                provider_id,
                retry_after_ms,
                ..
            } => f
                .debug_struct("Pending")
                .field("factor_id", factor_id)
                .field("provider_id", provider_id)
                .field("retry_after_ms", retry_after_ms)
                .finish_non_exhaustive(),
        }
    }
}

/// Continue exactly the operation bound to this opaque token.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinueAuthenticationRequest {
    /// Current secret returned by an authentication continuation.
    pub continuation: String,
    /// Input allowed by the current step; cannot change account, purpose or SID.
    pub input: AuthenticationInput,
}

/// One explicitly selected client action in a bounded authentication.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticationInput {
    /// Complete factor selection with a direct factor or account recovery proof.
    Proof {
        /// Secret proof; the host resolves the credential's provider.
        proof: MfaProof,
    },
    /// Start interactive authentication for one enrolled credential.
    SelectFactor {
        /// Enrolled factor offering interactive authentication.
        factor_id: String,
    },
    /// Answer the currently published provider challenge.
    Response {
        /// Provider-specific secret response.
        #[serde(deserialize_with = "Value::deserialize")]
        response: Value,
    },
    /// Check a pending external result after its advertised waiting interval.
    Poll {},
}

/// Cancel a ready or in-flight authentication continuation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelAuthenticationRequest {
    /// Current token; step-up additionally requires the original SID's valid bearer.
    pub continuation: String,
}

impl fmt::Debug for ContinueAuthenticationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContinueAuthenticationRequest")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for CancelAuthenticationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CancelAuthenticationRequest")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for AuthenticationInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Proof { .. } => "Proof",
            Self::SelectFactor { .. } => "SelectFactor",
            Self::Response { .. } => "Response",
            Self::Poll {} => "Poll",
        };
        f.debug_struct(name).finish_non_exhaustive()
    }
}
