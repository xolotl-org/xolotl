//! Extensible second-factor contracts. Providers verify proofs; the Console host
//! owns enrollment, atomic replay-state updates, recovery codes and session policy.

#[cfg(test)]
mod tests;
mod totp;
#[cfg(test)]
pub(crate) use totp::code_at;
pub use totp::{TotpAlgorithm, TotpConfig, TotpProvider};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt, future::Future, pin::Pin, sync::Arc};

/// Proof for one enrolled factor, or an account-owned recovery code.
/// The host resolves a factor's provider from its retained record.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MfaProof {
    /// Verify one explicitly selected credential instance.
    Factor {
        /// Opaque account-bound identifier returned by enrollment or factor discovery.
        factor_id: String,
        /// Secret payload matching that factor provider's advertised proof schema.
        #[serde(deserialize_with = "Value::deserialize")]
        response: Value,
    },
    /// Consume one single-use account recovery code. This path never dispatches
    /// through a provider, regardless of any installed provider's name.
    RecoveryCode {
        /// Secret code returned once during enrollment or regeneration.
        code: String,
    },
}

impl fmt::Debug for MfaProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Factor { factor_id, .. } => f
                .debug_struct("MfaProof::Factor")
                .field("factor_id", factor_id)
                .finish_non_exhaustive(),
            Self::RecoveryCode { .. } => f
                .debug_struct("MfaProof::RecoveryCode")
                .finish_non_exhaustive(),
        }
    }
}

/// Implementation capabilities of a second factor. Each operation declares its
/// own client-facing JSON Schema contract; host usage policy is separate.
/// At installation the host requires an object or boolean declaration within
/// size and depth limits; it does not validate full JSON Schema syntax or
/// evaluate request values against it. The provider must publish a coherent
/// schema and validate the shape and meaning of each value it receives.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MfaProviderDescriptor {
    /// Stable persisted identifier; changing it does not migrate existing factors.
    /// A provider name does not select a proof kind or replace account recovery.
    pub provider_id: String,
    /// Human-readable label for the validation mechanism.
    pub label: String,
    /// Registration capability and round inputs; absent when not supported.
    pub enrollment: Option<MfaEnrollmentDescriptor>,
    /// At least one of direct proof or interactive authentication must be declared.
    pub authentication: MfaAuthenticationDescriptor,
}

/// Client contracts for a bounded, account-bound enrollment ceremony.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MfaEnrollmentDescriptor {
    /// JSON Schema for provider-specific begin input. Absent means enrollment
    /// takes no input; when present, the field is required (including when the
    /// schema permits JSON null). The provider validates the input's meaning.
    pub begin_schema: Option<Value>,
    /// JSON Schema for setup payloads returned during enrollment.
    pub setup_schema: Value,
    /// JSON Schema for pending status; absent when the provider cannot be polled.
    pub pending_schema: Option<Value>,
}

/// Independent authentication paths supported by an installed provider.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MfaAuthenticationDescriptor {
    /// JSON Schema for [`MfaProvider::verify_proof`], absent when unsupported.
    pub proof_schema: Option<Value>,
    /// Interactive challenge contract, absent when unsupported. Each challenge
    /// step supplies its own response schema.
    pub interaction: Option<MfaInteractionDescriptor>,
}

/// Client-facing challenge shape for a bounded interactive authentication process.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MfaInteractionDescriptor {
    /// JSON Schema for provider challenge payloads returned to the client.
    pub challenge_schema: Value,
}

/// Independent host permissions for an installed provider's declared operations.
/// These permissions cannot install a provider or add an undeclared capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MfaProviderUsage {
    /// Permit enrollment begin and every round, including factor replacement.
    pub allow_enrollment: bool,
    /// Permit direct and interactive verification for login and step-up.
    pub allow_authentication: bool,
}

impl Default for MfaProviderUsage {
    fn default() -> Self {
        Self {
            allow_enrollment: true,
            allow_authentication: true,
        }
    }
}

/// Installed implementation capabilities and this host's frozen usage policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MfaProviderSummary {
    /// Validated declaration read once when the implementation is installed.
    pub descriptor: MfaProviderDescriptor,
    /// Host permissions, independent of the implementation's declared capabilities.
    pub usage: MfaProviderUsage,
}

/// Whether this host can dispatch authentication for a retained factor.
/// This does not predict availability of the provider's external dependencies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorAvailability {
    /// The factor is retained, but this host has no matching implementation.
    ProviderNotInstalled,
    /// The implementation is installed, but host policy forbids authentication.
    AuthenticationDisabled,
    /// Host policy permits the installed implementation's declared authentication paths.
    Available,
}

/// Public metadata for an account's enrolled credential; contains no verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FactorSummary {
    /// Opaque identifier of this credential instance.
    pub factor_id: String,
    /// Stable identifier of its validation mechanism.
    pub provider_id: String,
    /// User-supplied display label, independent of the credential identity.
    pub label: String,
    /// Confirmation time in milliseconds since the Unix epoch.
    pub created_at: i64,
    /// Most recent committed authentication, excluding enrollment activation.
    pub last_used_at: Option<i64>,
    /// Installation and authentication permission at the current host.
    pub availability: FactorAvailability,
}

/// Account-specific options disclosed only after primary or bearer authentication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MfaOptions {
    /// Enrolled factors, including retained instances whose provider is unavailable.
    pub factors: Vec<FactorSummary>,
    /// Whether the account retains any unconsumed recovery codes.
    pub recovery_code_available: bool,
}

/// Host-selected use of an enrolled factor; proof bodies cannot override it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MfaPurpose {
    /// Enrollment of a new credential, including replacement.
    Enrollment,
    /// Independent-factor verification following successful primary login.
    Login,
    /// Fresh verification bound to an existing bearer session.
    StepUp,
}

/// Verified account and host context; never taken from the proof body.
pub struct MfaContext<'a> {
    /// Display label of the verified account; not an identity key.
    pub username: &'a str,
    /// Stable source that owns this account instance.
    pub authority_id: &'a str,
    /// Immutable account instance within the authority.
    pub account_id: &'a str,
    /// Host-generated credential instance. During begin this is provisional;
    /// only a committed pending enrollment retains it through removal.
    pub factor_id: &'a str,
    /// Mutable display label; do not use it as a security identity.
    pub label: &'a str,
    /// Verified reason for invoking the provider.
    pub purpose: MfaPurpose,
    /// Host-configured display name used by enrollment tools and authenticators.
    pub issuer: &'a str,
    /// Host clock in milliseconds since the Unix epoch.
    pub now_ms: i64,
}

/// Host-established context for one round of interactive authentication.
/// The ceremony identity is stable; continuations rotate independently.
pub struct MfaInteractionContext<'a> {
    /// Verified account, factor and purpose; interactive authentication uses
    /// [`MfaPurpose::Login`] or [`MfaPurpose::StepUp`].
    pub factor: MfaContext<'a>,
    /// Stable host-generated identity for provider correlation or idempotency.
    pub ceremony_id: &'a str,
    /// Host-controlled provider invocation number, beginning at one.
    pub round: u16,
    /// Original absolute deadline in milliseconds; continuing never extends it.
    pub expires_at: i64,
}

/// Client input to one enrollment or authentication round. Only a waiting challenge
/// accepts a response; only a pending external result accepts a poll.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MfaInteractionInput {
    /// Answer the provider's current challenge.
    Response {
        /// Secret provider-specific response matching the current challenge's response schema.
        #[serde(deserialize_with = "Value::deserialize")]
        response: Value,
    },
    /// Request an update after the host's advertised minimum waiting interval.
    Poll {},
}

impl fmt::Debug for MfaInteractionInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Response { .. } => f
                .debug_struct("MfaInteractionInput::Response")
                .finish_non_exhaustive(),
            Self::Poll {} => f.write_str("MfaInteractionInput::Poll {}"),
        }
    }
}

/// Provider result for one bounded round. Private state is retained only in the
/// host's vault; successful verification still requires the host's credential CAS.
pub enum MfaInteractionStep {
    /// Wait for a client response; no active credential state has changed.
    Challenge {
        /// Provider-private continuation state; never return this to the client.
        private_state: Value,
        /// Client challenge matching the installed challenge schema.
        challenge: Value,
        /// JSON Schema for the response accepted by this challenge round.
        response_schema: Value,
    },
    /// Wait for an external result without classifying it as an invalid proof.
    Pending {
        /// Provider-private continuation state; never return this to the client.
        private_state: Value,
        /// Client-visible progress information, potentially containing sensitive data.
        status: Value,
        /// Requested delay in milliseconds, bounded by host policy and the deadline.
        retry_after_ms: i64,
    },
    /// Verification succeeded, but no session may be issued until host CAS succeeds.
    Verified {
        /// Complete next credential verifier, including replay state.
        next_verifier: Value,
    },
}

impl fmt::Debug for MfaInteractionStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Challenge { .. } => f
                .debug_struct("MfaInteractionStep::Challenge")
                .finish_non_exhaustive(),
            Self::Pending { retry_after_ms, .. } => f
                .debug_struct("MfaInteractionStep::Pending")
                .field("retry_after_ms", retry_after_ms)
                .finish_non_exhaustive(),
            Self::Verified { .. } => f
                .debug_struct("MfaInteractionStep::Verified")
                .finish_non_exhaustive(),
        }
    }
}

/// Host-established identity and limits for an enrollment provider call.
/// The ceremony is bound to one current account, bearer SID and factor instance.
pub struct MfaEnrollmentContext<'a> {
    /// Verified account and provisional factor identity.
    pub factor: MfaContext<'a>,
    /// Stable identity for provider correlation. This is the provisional factor id.
    pub ceremony_id: &'a str,
    /// Provider invocation number, beginning at one.
    pub round: u16,
    /// Original absolute deadline; advancing cannot extend it.
    pub expires_at: i64,
}

/// One provider result. Only `Verified` can activate a factor, after account CAS.
pub enum MfaEnrollmentStep {
    /// Await a client response. Setup may contain a secret and is never logged.
    Challenge {
        /// Provider-private continuation state retained by the host.
        private_state: Value,
        /// Public setup data returned to the enrolling client.
        setup: Value,
        /// JSON Schema for the response accepted by this enrollment round.
        response_schema: Value,
    },
    /// Await an external result; only this state accepts polling.
    Pending {
        /// Provider-private continuation state retained by the host.
        private_state: Value,
        /// Public status returned while approval is pending.
        status: Value,
        /// Provider-suggested minimum delay before polling, in milliseconds.
        retry_after_ms: i64,
    },
    /// Complete verifier to install atomically with the policy epoch change.
    Verified {
        /// Provider-owned verifier persisted with the new factor instance.
        verifier: Value,
    },
}

impl fmt::Debug for MfaEnrollmentStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Challenge { .. } => f.write_str("MfaEnrollmentStep::Challenge { .. }"),
            Self::Pending { retry_after_ms, .. } => f
                .debug_struct("MfaEnrollmentStep::Pending")
                .field("retry_after_ms", retry_after_ms)
                .finish_non_exhaustive(),
            Self::Verified { .. } => f.write_str("MfaEnrollmentStep::Verified { .. }"),
        }
    }
}

/// Public progress returned by the host, without provider-private state.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MfaEnrollmentProgress {
    /// The host has reserved the account slot and is preparing the first step.
    Starting {},
    /// A provider call is in flight; read current progress again after it settles.
    InFlight {},
    /// Supply a response to advance the ceremony.
    Challenge {
        /// Public setup data for the current enrollment round.
        setup: Value,
        /// JSON Schema for the response accepted by this enrollment round.
        response_schema: Value,
    },
    /// Poll after the advertised delay.
    Pending {
        /// Public status while the provider awaits an external result.
        status: Value,
        /// Minimum delay before polling again, in milliseconds.
        retry_after_ms: i64,
    },
}

impl fmt::Debug for MfaEnrollmentProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Starting {} => f.write_str("MfaEnrollmentProgress::Starting {}"),
            Self::InFlight {} => f.write_str("MfaEnrollmentProgress::InFlight {}"),
            Self::Challenge { .. } => f.write_str("MfaEnrollmentProgress::Challenge { .. }"),
            Self::Pending { retry_after_ms, .. } => f
                .debug_struct("MfaEnrollmentProgress::Pending")
                .field("retry_after_ms", retry_after_ms)
                .finish_non_exhaustive(),
        }
    }
}

/// Provider failures are intentionally data-free to avoid exposing secret state.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum MfaProviderError {
    /// Provider-specific enrollment input is invalid. From `begin_enrollment`,
    /// this promises no external enrollment was accepted. From
    /// `continue_enrollment`, this promises no enrollment completed and the
    /// supplied private state remains safe for another attempt.
    #[error("invalid second-factor enrollment input")]
    InvalidInput,
    /// The proof is malformed, incorrect, expired, or already consumed. From
    /// `continue_enrollment`, this promises no enrollment completed and the
    /// supplied private state remains safe for another attempt.
    #[error("invalid second-factor proof")]
    InvalidProof,
    /// A provider dependency is unavailable; no successful verification is claimed.
    #[error("second-factor provider unavailable")]
    Unavailable,
    /// Stored verifier state or provider configuration cannot be used safely.
    #[error("invalid second-factor verifier state")]
    InvalidState,
}

/// Cancellable provider work; the host applies a timeout to each call.
pub type MfaFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, MfaProviderError>> + Send + 'a>>;

/// Trusted host extension for an independent second factor. Never register a
/// password recheck as a second factor. A successful verification returns the
/// complete next verifier state, which the host commits with CAS before issuing
/// a session. Providers must enforce freshness/replay protection in this state or
/// in their own service. Verification may be cancelled; no host transaction spans
/// an external provider. Provider ids must remain stable for persisted enrollments.
/// Implement every operation advertised by the descriptor; default methods fail
/// closed with [`MfaProviderError::Unavailable`]. Enrollment, direct proofs and
/// interactive authentication are separate protocols, with no implicit fallback.
pub trait MfaProvider: Send + Sync + 'static {
    /// Stable identity and client-facing metadata. The host calls this once during
    /// assembly, validates it and freezes it for discovery and enrollment admission.
    /// Keep this fast and deterministic; changing the implementation's later return
    /// value does not change an installed host's declaration.
    fn descriptor(&self) -> MfaProviderDescriptor;
    /// Prepare enrollment without changing the active factor; return public
    /// setup or pending status and private state for continuation. The host
    /// first reserves a unique account claim, then calls this method. A
    /// concurrent change, revoked session, timeout or cancellation can still
    /// discard the result. Any external preparation must be safe to abandon
    /// (for example, a bounded-lifetime reservation tied to `context.factor_id`);
    /// only the final account CAS activates a factor.
    /// The host checks input presence, byte size and nesting depth; the provider
    /// validates its shape and meaning. Input is borrowed for this call only.
    fn begin_enrollment<'a>(
        &'a self,
        _context: MfaEnrollmentContext<'a>,
        _input: Option<&'a Value>,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async { Err(MfaProviderError::Unavailable) })
    }
    /// Advance only the host-authorized round, using a response or poll. Return
    /// the complete verifier to activate only after the host commits the account.
    /// Return `InvalidInput` or `InvalidProof` only if no enrollment completed
    /// and the private round state can be safely retried. If a dependency may have
    /// accepted the attempt despite an error, return `Unavailable` or
    /// `InvalidState`; the host retains an in-flight claim and never replays it.
    fn continue_enrollment<'a>(
        &'a self,
        _context: MfaEnrollmentContext<'a>,
        _private_state: &'a Value,
        _input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async { Err(MfaProviderError::Unavailable) })
    }
    /// Verify one direct proof and return the complete next verifier. The host
    /// commits replay state before issuing a session; enrollment never calls this.
    fn verify_proof<'a>(
        &'a self,
        _context: MfaContext<'a>,
        _verifier: &'a Value,
        _proof: &'a Value,
    ) -> MfaFuture<'a, Value> {
        Box::pin(async { Err(MfaProviderError::Unavailable) })
    }
    /// Start authentication against the selected active verifier. Do not mutate
    /// the credential; pending work returns separate private continuation state.
    fn begin_authentication<'a>(
        &'a self,
        _context: MfaInteractionContext<'a>,
        _verifier: &'a Value,
    ) -> MfaFuture<'a, MfaInteractionStep> {
        Box::pin(async { Err(MfaProviderError::Unavailable) })
    }
    /// Continue exactly the host-authorized round. The context and active
    /// verifier remain bound to the original ceremony; client input cannot
    /// change the factor, account, purpose, deadline or round.
    fn continue_authentication<'a>(
        &'a self,
        _context: MfaInteractionContext<'a>,
        _verifier: &'a Value,
        _private_state: &'a Value,
        _input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaInteractionStep> {
        Box::pin(async { Err(MfaProviderError::Unavailable) })
    }
}

/// Host MFA installation and management policy. Recovery codes remain account-owned
/// and usable independently of installed providers.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleMfaConfig {
    /// Display name embedded in enrollment setup; defaults to `Xolotl Console`.
    pub issuer: String,
    /// Pending enrollment lifetime in milliseconds, clamped to 30 seconds–15 minutes.
    pub enrollment_ttl_ms: i64,
    /// Credential-management freshness window in milliseconds, clamped to 30 seconds–15 minutes.
    pub recent_auth_ttl_ms: i64,
    /// Authentication ceremony lifetime in milliseconds; defaults to 120 seconds,
    /// clamped by the host to 30 seconds–5 minutes without renewal on continuation.
    pub authentication_ttl_ms: i64,
    /// Total provider calls per authentication, including begin; defaults to 16,
    /// clamped by the host to 1–32.
    pub max_authentication_steps: u16,
    /// Total provider calls per enrollment, including begin; defaults to 16,
    /// clamped by the host to 2–32.
    pub max_enrollment_steps: u16,
    /// Minimum polling interval in milliseconds; defaults to 500, clamped by the
    /// host to 100–30,000. Provider-requested waits may be longer.
    pub min_poll_interval_ms: i64,
    /// Install the built-in TOTP implementation; defaults to true. Disabling it
    /// preserves existing factors and their MFA requirement, but makes those factors
    /// unavailable unless a compatible provider is explicitly installed in `providers`.
    pub install_totp: bool,
    /// New-enrollment parameters for the built-in TOTP implementation. Validated
    /// when installed; existing factors retain their original parameters.
    pub totp: TotpConfig,
    /// Per-provider usage overrides; unspecified entries permit both purposes.
    /// Valid ids may name uninstalled providers without installing them. Policy is
    /// frozen with each installed implementation and does not change old evidence,
    /// retained factors, recovery codes or the account's second-factor requirement.
    pub provider_usage: BTreeMap<String, MfaProviderUsage>,
    /// Trusted Rust extensions with distinct stable ids. Not deserialized from configuration.
    /// Duplicate ids, including `totp` when the built-in is installed, reject assembly.
    /// Reusing a persisted id requires an implementation compatible with its existing
    /// verifiers. Recovery codes use a separate proof type.
    #[serde(skip)]
    pub providers: Vec<Arc<dyn MfaProvider>>,
}

impl Default for ConsoleMfaConfig {
    fn default() -> Self {
        Self {
            issuer: "Xolotl Console".into(),
            enrollment_ttl_ms: 300_000,
            recent_auth_ttl_ms: 300_000,
            authentication_ttl_ms: 120_000,
            max_authentication_steps: 16,
            max_enrollment_steps: 16,
            min_poll_interval_ms: 500,
            install_totp: true,
            totp: TotpConfig::default(),
            provider_usage: BTreeMap::new(),
            providers: Vec::new(),
        }
    }
}

impl fmt::Debug for ConsoleMfaConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConsoleMfaConfig")
            .field("issuer", &self.issuer)
            .field("enrollment_ttl_ms", &self.enrollment_ttl_ms)
            .field("recent_auth_ttl_ms", &self.recent_auth_ttl_ms)
            .field("authentication_ttl_ms", &self.authentication_ttl_ms)
            .field("max_authentication_steps", &self.max_authentication_steps)
            .field("max_enrollment_steps", &self.max_enrollment_steps)
            .field("min_poll_interval_ms", &self.min_poll_interval_ms)
            .field("install_totp", &self.install_totp)
            .field("totp", &self.totp)
            .field("provider_usage", &self.provider_usage)
            .field("additional_providers", &self.providers.len())
            .finish()
    }
}

// `Option<Value>` ordinarily maps both an omitted field and explicit JSON null
// to None. A provider may legitimately accept null, so preserve field presence.
fn present_json<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

/// MFA self-service operations. Each enrollment creates a distinct instance.
/// Pending replacement leaves its selected old factor active until activation.
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum MfaRequest {
    /// Read providers, enrolled instances, limits and the remaining recovery-code count.
    Status {},
    /// Read this session's pending enrollment, including its current public step.
    /// Requires the same recent authentication as enrollment management.
    Current {},
    /// Start enrollment, bound to the current session, account and deadline.
    /// A live enrollment claim must be explicitly canceled before replacement.
    Begin {
        /// Discovered provider whose metadata permits enrollment.
        provider_id: String,
        /// Display label for the new factor.
        label: String,
        /// Existing factor to replace atomically after final verification. Omission
        /// creates an additional factor; replacement requires the same provider.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        replace_factor_id: Option<String>,
        /// Provider-specific selection input, required only when the installed
        /// enrollment descriptor declares `begin_schema`. An explicit JSON null
        /// is present input and remains distinct from an omitted field.
        #[serde(
            default,
            deserialize_with = "present_json",
            skip_serializing_if = "Option::is_none"
        )]
        input: Option<Value>,
    },
    /// Advance one pending enrollment round; each successful round rotates its id.
    Continue {
        /// Current enrollment id returned by [`MfaResponse::Enrollment`].
        challenge_id: String,
        /// A response to a challenge, or a poll while pending.
        input: MfaInteractionInput,
    },
    /// Explicitly abandon pending enrollment, including an in-flight round.
    /// A concurrent provider result then cannot activate the factor.
    Cancel {
        /// Pending enrollment id owned by the current session.
        challenge_id: String,
    },
    /// Change one factor's display label without rotating the credential epoch.
    Rename {
        /// Enrolled credential instance to rename.
        factor_id: String,
        /// New display label.
        label: String,
    },
    /// Remove an active factor and invalidate sessions using the old MFA policy.
    Remove {
        /// Enrolled credential instance to remove; recovery codes are account-owned.
        factor_id: String,
    },
    /// Replace all recovery codes and invalidate sessions using the old MFA policy.
    RegenerateRecoveryCodes {},
}

/// Result of MFA self-service. Challenge setup can contain secrets; recovery codes
/// are returned only when issued by a committed activation or regeneration;
/// successful policy changes replace the caller's session and invalidate old ones.
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum MfaResponse {
    /// Current discovery and enrollment summary, without verifier material.
    Status {
        /// Host-installed providers, their schemas and this host's usage permissions.
        providers: Vec<MfaProviderSummary>,
        /// Active credential instances, including unavailable providers.
        factors: Vec<FactorSummary>,
        /// Maximum number of enrolled instances, independent of provider count.
        max_factors: usize,
        /// Number of unconsumed single-use recovery codes.
        recovery_codes_remaining: usize,
    },
    /// No enrollment is pending for this session.
    NoEnrollment,
    /// Pending enrollment round, using the same session and original deadline.
    Enrollment {
        /// Opaque identifier required by continue and cancel requests.
        challenge_id: String,
        /// New credential identity, including when replacing an existing factor.
        factor_id: String,
        /// Provider selected for the new credential.
        provider_id: String,
        /// Display label retained until activation.
        label: String,
        /// Expiry in milliseconds since the Unix epoch.
        expires_at: i64,
        /// Current challenge or pending status, with no private provider state.
        step: MfaEnrollmentProgress,
    },
    /// A factor-policy change has committed; use the replacement bearer from now on.
    Updated {
        /// New session for the committed MFA epoch. Previous sessions are invalid.
        session: crate::LoginResponse,
        /// Newly generated recovery codes, present only when issued by this operation.
        recovery_codes: Option<Vec<String>>,
    },
    /// Metadata changed; existing sessions and pending enrollment remain valid.
    Renamed {
        /// Current public metadata of the renamed factor.
        factor: FactorSummary,
    },
    /// Pending enrollment was removed; existing factors and sessions are unchanged.
    Canceled,
}

impl fmt::Debug for MfaRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status {} => f.write_str("MfaRequest::Status"),
            Self::Current {} => f.write_str("MfaRequest::Current"),
            Self::Begin {
                provider_id,
                label,
                replace_factor_id,
                ..
            } => f
                .debug_struct("MfaRequest::Begin")
                .field("provider_id", provider_id)
                .field("label", label)
                .field("replace_factor_id", replace_factor_id)
                .finish(),
            Self::Continue { .. } => f
                .debug_struct("MfaRequest::Continue")
                .finish_non_exhaustive(),
            Self::Cancel { .. } => f.debug_struct("MfaRequest::Cancel").finish_non_exhaustive(),
            Self::Rename { factor_id, label } => f
                .debug_struct("MfaRequest::Rename")
                .field("factor_id", factor_id)
                .field("label", label)
                .finish(),
            Self::Remove { factor_id } => f
                .debug_struct("MfaRequest::Remove")
                .field("factor_id", factor_id)
                .finish(),
            Self::RegenerateRecoveryCodes {} => f.write_str("MfaRequest::RegenerateRecoveryCodes"),
        }
    }
}

impl fmt::Debug for MfaResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status {
                factors,
                recovery_codes_remaining,
                ..
            } => f
                .debug_struct("MfaResponse::Status")
                .field("factors", factors)
                .field("recovery_codes_remaining", recovery_codes_remaining)
                .finish_non_exhaustive(),
            Self::NoEnrollment => f.write_str("MfaResponse::NoEnrollment"),
            Self::Enrollment {
                factor_id,
                provider_id,
                expires_at,
                ..
            } => f
                .debug_struct("MfaResponse::Enrollment")
                .field("factor_id", factor_id)
                .field("provider_id", provider_id)
                .field("expires_at", expires_at)
                .finish_non_exhaustive(),
            Self::Updated { session, .. } => f
                .debug_struct("MfaResponse::Updated")
                .field("session", session)
                .finish_non_exhaustive(),
            Self::Renamed { factor } => f
                .debug_struct("MfaResponse::Renamed")
                .field("factor", factor)
                .finish(),
            Self::Canceled => f.write_str("MfaResponse::Canceled"),
        }
    }
}
