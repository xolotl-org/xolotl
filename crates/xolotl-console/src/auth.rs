//! Console authentication and authorization.
//!
//! Account metadata lives under `state://kernel/console/*`;
//! credential verifiers and lockouts live under `state://vault/console/*`.
//! Sessions are private typed aggregates owned by the injected session store.

use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::signature::{ML_DSA_65, ML_DSA_65_SIGNING, ParsedPublicKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use subtle::ConstantTimeEq;
use thiserror::Error;
use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Url, Uuid,
    Webauthn, WebauthnBuilder,
};
use xolotl_kernel::Bootstrap;
use xolotl_state::{Backend, StateFailure};
use xolotl_types::{CapSet, Capability, Path, Value};
use xolotl_types::{ValueMap, ValueView};

use crate::credentials::{LockoutState, lockout_until_ms};
use crate::{AuthenticationEvidence, AuthenticationResponse, PrimaryAuthentication};
mod account;
pub(crate) mod audit;
use account::LOCAL_AUTHORITY_ID;
use account::local_identity_path;
pub use account::{
    AccountAuthority, AccountAuthorityError, AccountFuture, AccountKey, AccountSnapshot,
};
mod authorization;
use audit::{audit_outcome, record_auth_audit};
pub(crate) use authorization::{
    authorize_path, authorize_prefix_read, compile_principal_propagation_grants,
    compile_principal_request_grants, prepare_user_config, principal_request_selectors,
};
use authorization::{capset_from_strings, effective_grants, effective_session_grants};
mod ceremonies;
use ceremonies::{AuthenticationPurpose, AuthenticationStart};
mod bootstrap;
pub use bootstrap::{bootstrap_root_account, root_random_password_needed};
mod challenges;
pub use challenges::ConsoleChallengeConfig;
mod credential_sealer;
pub use credential_sealer::CredentialSealer;
mod credentials;
mod debug;
mod evidence;
mod execution;
pub(crate) use execution::ExecutionOwner;
mod external;
use external::InstalledExternalAuthentication;
pub use external::{
    ExternalAssurance, ExternalAuthError, ExternalAuthFuture, ExternalPrimaryAuthentication,
    VerifiedExternalIdentity,
};
mod mfa;
mod passkeys;
mod password;
#[cfg(test)]
mod test_key;
use passkeys::passkey_credential_id;
mod paths;
pub(crate) use crate::paths::{ROLES_PREFIX, SESSIONS_PREFIX, USERS_PREFIX};
use paths::{lockout_path, session_path};
pub(crate) use paths::{role_path, user_path};

const ROOT_USERNAME: &str = "root";
const MAX_SESSION_CEILING_CAPABILITIES: usize = 128;
const MAX_SESSION_CEILING_BYTES: usize = 8 * 1024;
const MAX_SESSION_CAPABILITY_BYTES: usize = 2048;
/// Default absolute session lifetime, in milliseconds.
pub const DEFAULT_SESSION_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// Default idle session lifetime, in milliseconds.
pub const DEFAULT_IDLE_TTL_MS: i64 = 2 * 60 * 60 * 1000;
/// Minimum accepted absolute session lifetime, in milliseconds.
pub const MIN_SESSION_TTL_MS: i64 = 60 * 1000;
/// Maximum accepted absolute session lifetime, in milliseconds.
pub const MAX_SESSION_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Minimum accepted idle session lifetime, in milliseconds.
pub const MIN_IDLE_TTL_MS: i64 = 60 * 1000;
/// Maximum accepted idle session lifetime, in milliseconds.
pub const MAX_IDLE_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// Minimum Argon2 password-work concurrency.
pub const MIN_ARGON2_CONCURRENCY: usize = 1;
/// Hard upper bound for Argon2 password-work concurrency.
pub const HARD_ARGON2_CONCURRENCY: usize = 256;
const KEY_CHALLENGE_TTL_MS: i64 = 60_000;

/// Default Argon2 password-work concurrency based on available CPU parallelism.
pub fn default_argon2_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(MIN_ARGON2_CONCURRENCY)
}

/// Optional root-account material supplied at daemon bootstrap.
#[derive(Clone)]
#[cfg_attr(not(test), derive(Default))]
pub struct RootProvisioning {
    /// Host-owned secret used to encrypt the root credential record.
    pub credential_sealer: Option<Arc<CredentialSealer>>,
    /// Optional precomputed Argon2 PHC string for the root password.
    pub password_hash: Option<String>,
    /// Optional plaintext root password consumed only during bootstrap.
    /// Mutually exclusive with `password_hash`.
    pub password: Option<String>,
    /// Optional public-key descriptors for key login.
    pub pubkeys: Vec<String>,
    /// Host-granted capabilities added to the default root authority at initial
    /// provisioning. They also extend its delegation ceiling. This never updates
    /// an existing account; later changes use the normal authorized user actions.
    pub additional_grants: Vec<String>,
}

// Unit tests use a shared sealer by default; production hosts must supply one.
#[cfg(test)]
impl Default for RootProvisioning {
    fn default() -> Self {
        Self {
            credential_sealer: Some(test_credential_sealer()),
            password_hash: None,
            password: None,
            pubkeys: Vec::new(),
            additional_grants: Vec::new(),
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "fixed test key and identifier are valid"
)]
fn test_credential_sealer() -> Arc<CredentialSealer> {
    static SEALER: std::sync::OnceLock<Arc<CredentialSealer>> = std::sync::OnceLock::new();
    SEALER
        .get_or_init(|| Arc::new(CredentialSealer::new("unit", &[0x71; 32]).unwrap()))
        .clone()
}

/// WebAuthn relying-party configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsoleWebAuthnConfig {
    /// Explicit opt-in to classical WebAuthn/passkey signatures.
    pub enabled: bool,
    /// Stable relying-party id, usually the console hostname.
    pub rp_id: String,
    /// Externally visible relying-party origin.
    pub rp_origin: String,
    /// Human-readable relying-party name shown by authenticators.
    pub rp_name: String,
    /// Ceremony lifetime in milliseconds.
    pub challenge_ttl_ms: i64,
}

impl Default for ConsoleWebAuthnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rp_id: "localhost".into(),
            rp_origin: "https://localhost".into(),
            rp_name: "Xolotl Console".into(),
            challenge_ttl_ms: KEY_CHALLENGE_TTL_MS,
        }
    }
}

impl ConsoleWebAuthnConfig {
    /// Clamp timing values and preserve caller-supplied relying-party identity.
    pub fn bounded(self) -> Self {
        Self {
            enabled: self.enabled,
            rp_id: self.rp_id,
            rp_origin: self.rp_origin,
            rp_name: self.rp_name,
            challenge_ttl_ms: self.challenge_ttl_ms.clamp(10_000, 300_000),
        }
    }
}

/// Console authentication tuning.
#[derive(Clone, Debug)]
pub struct ConsoleAuthConfig {
    /// Host-owned secret used to decrypt and encrypt persistent credentials.
    pub credential_sealer: Option<Arc<CredentialSealer>>,
    /// Absolute session TTL in milliseconds.
    pub session_ttl_ms: i64,
    /// Idle session TTL in milliseconds.
    pub idle_ttl_ms: i64,
    /// Maximum concurrent Argon2 hashing and verification tasks.
    pub argon2_concurrency: usize,
    /// Maximum concurrent external authentication preparations, from assertion
    /// verification through account lookup and session or continuation admission.
    /// The permit is released on completion or cancellation, not at a stage handoff.
    pub max_external_verifications: usize,
    /// Shared bounded storage for public-key and WebAuthn ceremonies.
    pub challenges: ConsoleChallengeConfig,
    /// Passkey/WebAuthn relying-party settings.
    pub webauthn: ConsoleWebAuthnConfig,
    /// Second-factor providers and enrollment policy.
    pub mfa: crate::mfa::ConsoleMfaConfig,
}

impl Default for ConsoleAuthConfig {
    fn default() -> Self {
        Self {
            credential_sealer: {
                #[cfg(test)]
                {
                    Some(test_credential_sealer())
                }
                #[cfg(not(test))]
                {
                    None
                }
            },
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
            idle_ttl_ms: DEFAULT_IDLE_TTL_MS,
            argon2_concurrency: default_argon2_concurrency(),
            max_external_verifications: 32,
            challenges: ConsoleChallengeConfig::default(),
            webauthn: ConsoleWebAuthnConfig::default(),
            mfa: crate::mfa::ConsoleMfaConfig::default(),
        }
    }
}

impl ConsoleAuthConfig {
    /// Clamp all tuning values into hard safety bounds.
    pub fn bounded(self) -> Self {
        let session_ttl_ms = self
            .session_ttl_ms
            .clamp(MIN_SESSION_TTL_MS, MAX_SESSION_TTL_MS);
        let idle_ttl_ms = self
            .idle_ttl_ms
            .clamp(MIN_IDLE_TTL_MS, MAX_IDLE_TTL_MS)
            .min(session_ttl_ms);
        Self {
            credential_sealer: self.credential_sealer,
            session_ttl_ms,
            idle_ttl_ms,
            argon2_concurrency: self
                .argon2_concurrency
                .clamp(MIN_ARGON2_CONCURRENCY, HARD_ARGON2_CONCURRENCY),
            max_external_verifications: self.max_external_verifications.clamp(1, 256),
            webauthn: self.webauthn.bounded(),
            challenges: self.challenges.bounded(),
            mfa: self.mfa,
        }
    }
}

/// Result of root-account bootstrap.
#[derive(Clone, Eq, PartialEq)]
pub enum BootstrapOutcome {
    /// A root account already exists.
    AlreadyPresent,
    /// Root was created with a one-time random password for display.
    CreatedRandomPassword {
        /// Created username.
        username: String,
        /// One-time generated password.
        password: String,
    },
    /// Root was created from a provisioned plaintext password (validated and hashed).
    CreatedFromProvisionedPassword {
        /// Created username.
        username: String,
    },
    /// Root was created from preseeded password or key material.
    CreatedPreseeded {
        /// Created username.
        username: String,
    },
}

/// Password login request.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    /// Console username.
    pub username: String,
    /// Plaintext password, consumed only by the auth boundary.
    pub password: String,
    /// Independent second-factor proof; required when the account has MFA enrolled.
    #[serde(default)]
    pub second_factor: Option<crate::mfa::MfaProof>,
}

/// Login or step-up response carrying a new bearer token.
#[derive(Serialize, Deserialize)]
pub struct LoginResponse {
    /// Session id.
    pub sid: String,
    /// Bearer token in `sid.secret` form.
    pub token: String,
    /// Absolute expiry timestamp in millis since epoch.
    pub expires_at: i64,
    /// Idle expiry timestamp in millis since epoch.
    pub idle_expires_at: i64,
    /// Committed authentication proofs retained by this session.
    pub authentication: AuthenticationEvidence,
}

/// Request to upgrade an existing session's MFA level.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepUpRequest {
    /// An enrolled independent factor or one-time recovery code. Repeating a
    /// password alone cannot raise the MFA level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<crate::mfa::MfaProof>,
}

/// Request to start public-key login.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyChallengeRequest {
    /// Console username.
    pub username: String,
    /// Client origin bound into the signed transcript.
    pub origin: String,
}

/// One public-key login challenge.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyChallengeResponse {
    /// Challenge id used by the finish request.
    pub challenge_id: String,
    /// Random nonce to sign.
    pub nonce: String,
    /// Origin bound to the challenge.
    pub origin: String,
    /// Challenge expiry timestamp in millis since epoch.
    pub expires_at: i64,
    /// Canonical transcript the client must sign.
    pub transcript: String,
}

/// Request to finish public-key login.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyLoginRequest {
    /// Console username.
    pub username: String,
    /// Challenge id returned by [`KeyChallengeResponse`].
    pub challenge_id: String,
    /// Signature over the challenge transcript.
    pub signature: String,
    /// Client origin; must match the challenge.
    pub origin: String,
    /// Exact registered ML-DSA-65 key descriptor. Selects one verifier.
    pub key: String,
    /// Required when this account has an independent second factor enrolled.
    #[serde(default)]
    pub second_factor: Option<crate::mfa::MfaProof>,
}

/// Request to begin passkey registration for the bearer principal.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRegisterBeginRequest {
    /// Local credential label, 1–128 UTF-8 bytes without control characters.
    pub label: String,
    /// Optional display name sent to the authenticator.
    #[serde(default)]
    pub display_name: Option<String>,
}

/// Passkey registration options and server-side ceremony id.
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegisterBeginResponse {
    /// Single-use server-side ceremony id.
    pub challenge_id: String,
    /// Browser `navigator.credentials.create` options.
    pub public_key: CreationChallengeResponse,
}

/// Request to finish passkey registration.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyRegisterFinishRequest {
    /// Ceremony id returned by registration begin.
    pub challenge_id: String,
    /// Browser credential response.
    pub credential: RegisterPublicKeyCredential,
}

/// Passkey registration result.
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyRegisterFinishResponse {
    /// Stored credential id, base64url encoded by the WebAuthn library.
    pub credential_id: String,
    /// Replacement session. Registration invalidates every old token and SID.
    pub session: LoginResponse,
}

/// Request to begin passkey login.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyLoginBeginRequest {
    /// Console username.
    pub username: String,
}

/// Passkey authentication options and server-side ceremony id.
#[derive(Debug, Serialize, Deserialize)]
pub struct PasskeyLoginBeginResponse {
    /// Single-use server-side ceremony id.
    pub challenge_id: String,
    /// Browser `navigator.credentials.get` options.
    pub public_key: RequestChallengeResponse,
}

/// Request to finish passkey login.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasskeyLoginFinishRequest {
    /// Console username.
    pub username: String,
    /// Ceremony id returned by login begin.
    pub challenge_id: String,
    /// Browser assertion response.
    pub credential: PublicKeyCredential,
}

/// Authenticated console principal used by management actions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ConsolePrincipal {
    /// Console username.
    pub(crate) username: String,
    /// Authority that owns the account instance.
    pub(crate) authority_id: String,
    /// Immutable instance identifier within the authority.
    pub(crate) account_id: String,
    /// Xolotl identity path associated with the user.
    pub(crate) identity_path: String,
    /// Effective grants after roles and direct grants are combined.
    pub(crate) grants: CapSet,
    /// Maximum authority captured when an external assertion was exchanged.
    pub(crate) authority_ceiling: Option<CapSet>,
    /// Committed authentication proofs retained by this session.
    pub(crate) authentication: AuthenticationEvidence,
}

struct SessionView {
    principal: ConsolePrincipal,
    username: String,
    revocation_epoch: String,
    credential_epoch: String,
}

impl ConsolePrincipal {
    pub(crate) fn account_key(&self) -> AccountKey {
        AccountKey::from_parts(&self.authority_id, &self.account_id)
    }
}

/// Public session metadata returned by session-list actions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct SessionSummary {
    /// Session id.
    pub(crate) sid: String,
    /// Owning username.
    pub(crate) username: String,
    /// Identity path active for this session.
    pub(crate) identity_path: String,
    /// Time this session was issued, in milliseconds since the Unix epoch.
    pub(crate) issued_at: i64,
    /// Absolute expiry timestamp in millis since epoch.
    pub(crate) expires_at: i64,
    /// Idle expiry timestamp in millis since epoch.
    pub(crate) idle_expires_at: i64,
    /// Committed authentication proofs retained by this session.
    pub(crate) authentication: AuthenticationEvidence,
    /// Last-seen timestamp in millis since epoch.
    pub(crate) last_seen: i64,
    /// Source address recorded when the session was issued.
    pub(crate) source_addr: String,
}

pub(crate) struct SessionPage {
    pub entries: Vec<SessionSummary>,
    pub next: Option<xolotl_state::StateCursor>,
}

/// Authentication and authorization errors returned by the console boundary.
#[derive(Debug, Error)]
pub enum AuthError {
    /// No trusted external verifier was installed on this Console host.
    #[error("external authentication is not configured")]
    ExternalAuthenticationNotConfigured,
    /// The trusted external verifier could not complete its check.
    #[error("external authentication is unavailable")]
    ExternalAuthenticationUnavailable,
    /// Externally authenticated accounts require a configured account authority.
    #[error("account authority is not configured")]
    AccountAuthorityNotConfigured,
    /// The account authority could not establish current account state.
    #[error("account authority is temporarily unavailable")]
    AccountAuthorityUnavailable,
    /// This Console uses a host account authority and has no local primary login.
    #[error("local account authentication is unavailable in this Console")]
    LocalAuthenticationUnavailable,
    /// Login/step-up needs an enrolled independent factor.
    #[error(
        "an enrolled second factor is required; enroll a factor after primary login if none exists"
    )]
    MfaRequired {
        /// Account-specific choices, disclosed only after authentication.
        options: Option<crate::mfa::MfaOptions>,
    },
    /// A credential-management operation needs a newly authenticated session.
    #[error("a recent login or second-factor verification is required")]
    ReauthenticationRequired,
    /// Unknown factor, malformed lifecycle request, or exceeded limits.
    #[error("invalid second-factor management request")]
    InvalidMfaRequest,
    /// This host forbids the requested use of an installed second-factor provider.
    /// This is a policy decision, not a failed credential proof.
    #[error("second-factor provider use is forbidden by host policy")]
    MfaUsageDenied,
    /// This host has no installed provider supporting the requested factor operation.
    /// Installation or capability mismatch does not prove a credential is invalid.
    #[error("second-factor operation is unavailable on this host")]
    MfaOperationUnavailable,
    /// Malformed credential identifier, unsupported key or rejected password policy.
    #[error("invalid credential request or password rejected by policy")]
    InvalidCredentialRequest,
    /// A concurrent credential change won the shared vault CAS.
    #[error("credentials changed concurrently; authenticate again and inspect current credentials")]
    CredentialConflict,
    /// Removing the final primary credential would make the account unusable.
    #[error("at least one primary login credential must remain")]
    LastPrimaryCredential,
    /// Username failed syntax validation.
    #[error("invalid username")]
    InvalidUsername,
    /// Password, key signature, or TOTP proof was invalid.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// Account is disabled, locked, or otherwise unavailable.
    #[error("account is disabled or locked")]
    AccountUnavailable,
    /// Session token or id is missing, expired, revoked, or malformed.
    #[error("session is missing, expired, or revoked")]
    InvalidSession,
    /// Authentication challenge is missing, expired, already used, or mismatched.
    #[error("authentication challenge is missing, expired, or already used")]
    InvalidChallenge,
    /// Bearer token was required but absent.
    #[error("authorization bearer token is required")]
    MissingBearer,
    /// Principal does not hold authority for the requested target.
    #[error("permission denied")]
    PermissionDenied,
    /// Login attempt is temporarily rate limited.
    #[error("rate limited; retry after {retry_after_ms} ms")]
    RateLimited {
        /// Milliseconds until the next allowed attempt.
        retry_after_ms: i64,
    },
    /// All password-verification slots are occupied; no work was queued.
    #[error("authentication capacity exceeded")]
    CapacityExceeded,
    /// Invalid or over-budget session page query.
    #[error("session query rejected: {0}")]
    Query(String),
    /// An accepted session mutation cannot be proved committed or rejected.
    #[error("session mutation outcome is unknown")]
    SessionCommitUnknown,
    /// The injected storage domain rejected a new retained aggregate.
    #[error("session storage capacity or policy rejected admission")]
    SessionAdmissionRejected,
    /// State backend error.
    #[error("state error: {0}")]
    State(String),
    /// Cryptographic parsing, hashing, or verification error.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<StateFailure> for AuthError {
    fn from(e: StateFailure) -> Self {
        AuthError::State(e.to_string())
    }
}

impl From<xolotl_types::PathError> for AuthError {
    fn from(e: xolotl_types::PathError) -> Self {
        AuthError::State(e.to_string())
    }
}

#[derive(Debug, Default)]
struct RateState {
    by_user: HashMap<String, FailureBucket>,
    by_source: HashMap<String, FailureBucket>,
    global: FailureBucket,
}

// Limit attacker-controlled usernames and peer names retained by the local
// backoff. Existing buckets are never evicted while their rate window is live.
const MAX_RATE_BUCKETS: usize = 4_096;
const RATE_WINDOW_MS: i64 = 60_000;

#[derive(Clone, Copy, Debug, Default)]
struct FailureBucket {
    failures: u32,
    next_allowed_at: i64,
    window_started_at: i64,
}

/// Console authentication service.
pub(crate) struct ConsoleAuth {
    pub(crate) session_store: Arc<dyn crate::session_store::ConsoleSessionStore>,
    config: ConsoleAuthConfig,
    decoy_phc: String,
    passwords: password::PasswordVerifier,
    rate: Mutex<RateState>,
    mfa_providers: BTreeMap<String, mfa::InstalledProvider>,
    #[cfg(feature = "http")]
    mfa_provider_json: std::sync::Arc<[u8]>,
    external: InstalledExternalAuthentication,
    account_authority: Option<Arc<dyn AccountAuthority>>,
    external_verifications: tokio::sync::Semaphore,
    host_runtime: xolotl_kernel::host::HostRuntime,
}

impl ConsoleAuth {
    fn credential_sealer(&self) -> Result<&CredentialSealer, AuthError> {
        self.config.credential_sealer.as_deref().ok_or_else(|| {
            AuthError::Crypto("console credential encryption key is required".into())
        })
    }

    /// Create an auth service with bounded tuning and a decoy password hash.
    #[cfg(test)]
    pub(crate) fn new(config: ConsoleAuthConfig) -> Result<Self, AuthError> {
        Self::with_external(
            config,
            Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
                crate::session_store::ConsoleSessionPolicy::default(),
            )),
            None,
            None,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            xolotl_kernel::host::HostRuntime::default(),
        )
    }

    pub(crate) fn with_external(
        config: ConsoleAuthConfig,
        session_store: Arc<dyn crate::session_store::ConsoleSessionStore>,
        external: InstalledExternalAuthentication,
        account_authority: Option<Arc<dyn AccountAuthority>>,
        blocking_spawner: Arc<dyn xolotl_kernel::host::BlockingSpawner>,
        host_runtime: xolotl_kernel::host::HostRuntime,
    ) -> Result<Self, AuthError> {
        if external.is_some() && account_authority.is_none() {
            return Err(AuthError::AccountAuthorityNotConfigured);
        }
        if let Some(authority) = &account_authority {
            let id = authority.authority_id();
            if id == LOCAL_AUTHORITY_ID || AccountKey::new(id, "probe").is_err() {
                return Err(AuthError::State(
                    "invalid external account authority id".into(),
                ));
            }
        }
        let config = config.bounded();
        if config.credential_sealer.is_none() {
            return Err(AuthError::Crypto(
                "console credential encryption key is required".into(),
            ));
        }
        let mfa_providers = mfa::providers(&config)?;
        #[cfg(feature = "http")]
        let mfa_provider_json = mfa::provider_catalog_json(&mfa_providers)?;
        let decoy_phc = hash_password_with_salt("invalid-password", &[0x42; 16])?;
        let external_verifications = tokio::sync::Semaphore::new(config.max_external_verifications);
        Ok(Self {
            session_store,
            passwords: password::PasswordVerifier::new(config.argon2_concurrency, blocking_spawner),
            config,
            decoy_phc,
            rate: Mutex::new(RateState::default()),
            mfa_providers,
            #[cfg(feature = "http")]
            mfa_provider_json,
            external,
            account_authority,
            external_verifications,
            host_runtime,
        })
    }

    /// Authenticate with password/TOTP and issue a new session.
    ///
    /// Records a console auth audit fact for both success and failure.
    pub(crate) async fn login(
        &self,
        boot: &Bootstrap,
        req: LoginRequest,
        source_addr: String,
    ) -> Result<AuthenticationResponse, AuthError> {
        if self.external_accounts() {
            return Err(AuthError::LocalAuthenticationUnavailable);
        }
        let username = req.username.trim().to_string();
        let result = self
            .login_inner(boot.kernel().state(), req, source_addr.clone())
            .await;
        match &result {
            Ok(AuthenticationResponse::Authenticated { session: response }) => record_auth_audit(
                boot,
                "console_login",
                Some(&username),
                Some(&source_addr),
                "ok",
                Some(&response.authentication),
            )?,
            Ok(AuthenticationResponse::Continue(_)) => record_auth_audit(
                boot,
                "console_credential",
                Some(&username),
                Some(&source_addr),
                "authentication_pending",
                None,
            )?,
            Err(err) => record_auth_audit(
                boot,
                "console_login_failed",
                Some(&username),
                Some(&source_addr),
                audit_outcome(err),
                None,
            )?,
        }
        result
    }

    async fn login_inner(
        &self,
        state: &Backend,
        req: LoginRequest,
        source_addr: String,
    ) -> Result<AuthenticationResponse, AuthError> {
        let username = req.username.trim().to_string();
        validate_username(&username)?;
        self.check_rate_limits(&username, &source_addr, self.host_runtime.now_millis())?;
        let now = self.host_runtime.now_millis();
        let lockout = read_lockout(state, &username).await?;
        if lockout.is_locked(now) {
            return Err(AuthError::RateLimited {
                retry_after_ms: lockout.remaining_ms(now),
            });
        }

        let user = read_user(state, &username).await?;
        let credentials = credentials::read(state, &username, self.credential_sealer()?).await?;
        let password_enabled = credentials.password.is_some();
        let phc = credentials
            .password
            .clone()
            .unwrap_or_else(|| self.decoy_phc.clone());

        let password_ok = self.passwords.verify(phc, req.password).await?;
        let verified_at = self.host_runtime.now_millis();

        let Some(user) = user else {
            self.record_login_failure(&username, &source_addr, now);
            // A name with no account must not create permanent vault state.
            // The decoy password verification and local backoff still apply.
            return Err(AuthError::InvalidCredentials);
        };
        if !matches!(user.status.as_str(), "active") {
            self.record_login_failure(&username, &source_addr, now);
            record_account_lockout_failure(state, &username, now).await?;
            return Err(AuthError::AccountUnavailable);
        }
        if !password_enabled || !password_ok {
            self.record_login_failure(&username, &source_addr, now);
            record_account_lockout_failure(state, &username, now).await?;
            return Err(AuthError::InvalidCredentials);
        }

        let account = self.local_snapshot(state, &user).await?;
        self.start_authentication(
            state,
            AuthenticationStart {
                account: &account,
                credentials,
                primary: PrimaryAuthentication::Password { verified_at },
                purpose: AuthenticationPurpose::Login,
                proof: req.second_factor.as_ref(),
                bearer: None,
                source: &source_addr,
                authority_ceiling: None,
            },
        )
        .await
    }

    /// Start public-key login by creating a single-use signed challenge.
    ///
    /// The returned transcript is bound to username, challenge id, nonce, and
    /// origin. Records a credential audit fact.
    pub(crate) async fn begin_key_login(
        &self,
        boot: &Bootstrap,
        req: KeyChallengeRequest,
        source_addr: String,
    ) -> Result<KeyChallengeResponse, AuthError> {
        if self.external_accounts() {
            return Err(AuthError::LocalAuthenticationUnavailable);
        }
        let username = req.username.trim().to_string();
        let result = self
            .begin_key_login_inner(boot.kernel().state(), req, &source_addr)
            .await;
        match &result {
            Ok(_) => record_auth_audit(
                boot,
                "console_credential",
                Some(&username),
                Some(&source_addr),
                "key_challenge",
                None,
            )?,
            Err(err) => record_auth_audit(
                boot,
                "console_credential",
                Some(&username),
                Some(&source_addr),
                audit_outcome(err),
                None,
            )?,
        }
        result
    }

    async fn begin_key_login_inner(
        &self,
        state: &Backend,
        req: KeyChallengeRequest,
        source_addr: &str,
    ) -> Result<KeyChallengeResponse, AuthError> {
        let username = req.username.trim().to_string();
        validate_username(&username)?;
        let origin = validate_origin(req.origin.trim())?;
        let nonce = random_token(32)?;
        let now = self.host_runtime.now_millis();
        let expires_at = now.saturating_add(KEY_CHALLENGE_TTL_MS);
        let challenge = KeyChallengeRecord {
            credential_epoch: credentials::epoch(state, &username, self.credential_sealer()?)
                .await?,
            nonce: nonce.clone(),
        };
        let challenge_id = challenges::issue(
            &self.host_runtime,
            state,
            &self.config.challenges,
            challenges::Binding::PublicKey {
                username: username.clone(),
                origin: origin.clone(),
            },
            source_addr,
            expires_at,
            &challenge,
        )
        .await?;
        let transcript = key_login_transcript(&username, &challenge_id, &nonce, &origin);
        Ok(KeyChallengeResponse {
            challenge_id,
            nonce,
            origin,
            expires_at,
            transcript,
        })
    }

    /// Verify a public-key challenge signature and issue a new session.
    ///
    /// Challenges are single-use: the challenge is revoked before signature
    /// validation completes.
    pub(crate) async fn finish_key_login(
        &self,
        boot: &Bootstrap,
        req: KeyLoginRequest,
        source_addr: String,
    ) -> Result<AuthenticationResponse, AuthError> {
        if self.external_accounts() {
            return Err(AuthError::LocalAuthenticationUnavailable);
        }
        let username = req.username.trim().to_string();
        let result = self
            .finish_key_login_inner(boot.kernel().state(), req, source_addr.clone())
            .await;
        match &result {
            Ok(AuthenticationResponse::Authenticated { session: response }) => record_auth_audit(
                boot,
                "console_login",
                Some(&username),
                Some(&source_addr),
                "ok",
                Some(&response.authentication),
            )?,
            Ok(AuthenticationResponse::Continue(_)) => record_auth_audit(
                boot,
                "console_credential",
                Some(&username),
                Some(&source_addr),
                "authentication_pending",
                None,
            )?,
            Err(err) => record_auth_audit(
                boot,
                "console_login_failed",
                Some(&username),
                Some(&source_addr),
                audit_outcome(err),
                None,
            )?,
        }
        result
    }

    async fn finish_key_login_inner(
        &self,
        state: &Backend,
        req: KeyLoginRequest,
        source_addr: String,
    ) -> Result<AuthenticationResponse, AuthError> {
        let username = req.username.trim().to_string();
        validate_username(&username)?;
        validate_session_id(&req.challenge_id).map_err(|_error| AuthError::InvalidChallenge)?;
        let origin = validate_origin(req.origin.trim())?;

        let challenge: KeyChallengeRecord = challenges::take(
            &self.host_runtime,
            state,
            &req.challenge_id,
            &challenges::Binding::PublicKey {
                username: username.clone(),
                origin: origin.clone(),
            },
        )
        .await?;

        let user = read_user(state, &username)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        if !matches!(user.status.as_str(), "active") {
            return Err(AuthError::AccountUnavailable);
        }
        let transcript =
            key_login_transcript(&username, &req.challenge_id, &challenge.nonce, &origin);
        let credentials = credentials::read(state, &username, self.credential_sealer()?).await?;
        if credentials.epoch != challenge.credential_epoch {
            return Err(AuthError::InvalidChallenge);
        }
        let credential_key = verify_key_login(
            &credentials.public_keys,
            &req.key,
            &req.signature,
            &transcript,
        )?
        .ok_or(AuthError::InvalidCredentials)?
        .to_owned();
        let verified_at = self.host_runtime.now_millis();
        let account = self.local_snapshot(state, &user).await?;
        self.start_authentication(
            state,
            AuthenticationStart {
                account: &account,
                credentials,
                primary: PrimaryAuthentication::PublicKey {
                    credential_key,
                    verified_at,
                },
                purpose: AuthenticationPurpose::Login,
                proof: req.second_factor.as_ref(),
                bearer: None,
                source: &source_addr,
                authority_ceiling: None,
            },
        )
        .await
    }

    /// Upgrade an existing bearer session to MFA level 2.
    ///
    /// Requires an independent enrolled factor or an unused recovery code.
    pub(crate) async fn step_up(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        req: StepUpRequest,
        source_addr: String,
    ) -> Result<AuthenticationResponse, AuthError> {
        let audit_username = match self
            .authenticate_token_inner(boot.kernel().state(), bearer)
            .await
        {
            Ok(principal) => Some(principal.username),
            Err(AuthError::InvalidCredentials | AuthError::InvalidSession) => None,
            Err(error) => {
                tracing::warn!(?error, "console step-up audit username lookup failed");
                None
            }
        };
        let result = self
            .step_up_inner(boot.kernel().state(), bearer, req, source_addr.clone())
            .await;
        match &result {
            Ok(AuthenticationResponse::Authenticated { session: response }) => record_auth_audit(
                boot,
                "console_credential",
                audit_username.as_deref(),
                Some(&source_addr),
                "step_up",
                Some(&response.authentication),
            )?,
            Ok(AuthenticationResponse::Continue(_)) => record_auth_audit(
                boot,
                "console_credential",
                audit_username.as_deref(),
                Some(&source_addr),
                "authentication_pending",
                None,
            )?,
            Err(err) => record_auth_audit(
                boot,
                "console_credential",
                audit_username.as_deref(),
                Some(&source_addr),
                audit_outcome(err),
                None,
            )?,
        }
        result
    }

    async fn step_up_inner(
        &self,
        state: &Backend,
        bearer: &str,
        req: StepUpRequest,
        source_addr: String,
    ) -> Result<AuthenticationResponse, AuthError> {
        let principal = self.authenticate_token_inner(state, bearer).await?;
        let account = self
            .current_account(state, &principal.account_key(), Some(&principal.username))
            .await?;
        if !account.active {
            return Err(AuthError::AccountUnavailable);
        }

        self.start_authentication(
            state,
            AuthenticationStart {
                account: &account,
                credentials: credentials::read_by_key(
                    state,
                    &account.key,
                    self.credential_sealer()?,
                )
                .await?,
                primary: principal.authentication.primary,
                purpose: AuthenticationPurpose::StepUp {
                    sid: bearer
                        .split_once('.')
                        .ok_or(AuthError::InvalidSession)?
                        .0
                        .into(),
                },
                proof: req.proof.as_ref(),
                bearer: Some(bearer),
                source: &source_addr,
                authority_ceiling: principal.authority_ceiling,
            },
        )
        .await
    }

    /// Authenticate a bearer token in `sid.secret` form.
    pub(crate) async fn authenticate_token(
        &self,
        boot: &Bootstrap,
        bearer: &str,
    ) -> Result<ConsolePrincipal, AuthError> {
        self.authenticate_token_inner(boot.kernel().state(), bearer)
            .await
    }

    /// Authenticate by session id without a bearer secret.
    ///
    /// This is intended for trusted management paths that already validated
    /// access to the session id.
    #[cfg(any(feature = "http", test))]
    pub(crate) async fn authenticate_sid(
        &self,
        boot: &Bootstrap,
        sid: &str,
    ) -> Result<ConsolePrincipal, AuthError> {
        self.session_principal(boot, sid, true).await
    }

    /// Check an already authenticated SID without renewing idle time or writing
    /// State. Event delivery must not recursively trigger State subscriptions.
    pub(crate) async fn validate_sid(
        &self,
        boot: &Bootstrap,
        sid: &str,
    ) -> Result<ConsolePrincipal, AuthError> {
        self.session_principal(boot, sid, false).await
    }

    async fn session_principal(
        &self,
        boot: &Bootstrap,
        sid: &str,
        touch: bool,
    ) -> Result<ConsolePrincipal, AuthError> {
        self.session_view(boot, sid, touch)
            .await
            .map(|view| view.principal)
    }

    async fn session_view(
        &self,
        boot: &Bootstrap,
        sid: &str,
        touch: bool,
    ) -> Result<SessionView, AuthError> {
        validate_session_id(sid)?;
        let state = boot.kernel().state();
        let session_path = session_path(sid)?;
        let Some(mut session) = read_session(self.session_store.as_ref(), &session_path).await?
        else {
            return Err(AuthError::InvalidSession);
        };
        let now = self.host_runtime.now_millis();
        if !session.is_live_at(now) {
            if touch {
                retire_expired_session(self.session_store.as_ref(), &session, now).await?;
            }
            return Err(AuthError::InvalidSession);
        }

        let account = self
            .current_account(state, &session.account_key(), Some(&session.username))
            .await?;
        if !account.active {
            return Err(AuthError::AccountUnavailable);
        }

        if session.revocation_epoch != account.revocation_epoch
            || session.identity_path != account.identity.to_string()
            || session.credential_epoch
                != credentials::epoch_by_key(state, &account.key, self.credential_sealer()?).await?
        {
            return Err(AuthError::InvalidSession);
        }
        if touch {
            session.renew_activity(now, self.config.idle_ttl_ms);
            if !session.is_live_at(self.host_runtime.now_millis()) {
                return Err(AuthError::InvalidSession);
            }
            session = write_session(self.session_store.as_ref(), &session_path, &session).await?;
        } else {
            let current = read_session(self.session_store.as_ref(), &session_path)
                .await?
                .ok_or(AuthError::InvalidSession)?;
            if !current.has_same_authority_as(&session) {
                return Err(AuthError::InvalidSession);
            }
            session = current;
        }

        let grants = effective_session_grants(
            &account.grants,
            session
                .authority_ceiling
                .as_ref()
                .ok_or(AuthError::InvalidSession)?,
        )?;
        if !session.is_live_at(self.host_runtime.now_millis()) {
            return Err(AuthError::InvalidSession);
        }
        Ok(SessionView {
            username: session.username,
            revocation_epoch: session.revocation_epoch,
            credential_epoch: session.credential_epoch,
            principal: ConsolePrincipal {
                username: account.display_name,
                authority_id: account.key.authority_id().into(),
                account_id: account.key.instance_id().into(),
                identity_path: account.identity.to_string(),
                grants,
                authority_ceiling: session.authority_ceiling,
                authentication: session.authentication,
            },
        })
    }

    async fn authenticate_token_inner(
        &self,
        state: &Backend,
        bearer: &str,
    ) -> Result<ConsolePrincipal, AuthError> {
        let (sid, token) = bearer.split_once('.').ok_or(AuthError::InvalidSession)?;
        validate_session_id(sid)?;
        let session_path = session_path(sid)?;
        let Some(mut session) = read_session(self.session_store.as_ref(), &session_path).await?
        else {
            return Err(AuthError::InvalidSession);
        };
        let now = self.host_runtime.now_millis();
        if !session.is_live_at(now) {
            retire_expired_session(self.session_store.as_ref(), &session, now).await?;
            return Err(AuthError::InvalidSession);
        }
        let token_hash = token_hash(token);
        if session
            .token_hash
            .as_bytes()
            .ct_eq(token_hash.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(AuthError::InvalidSession);
        }

        let account = self
            .current_account(state, &session.account_key(), Some(&session.username))
            .await?;
        if !account.active {
            return Err(AuthError::AccountUnavailable);
        }

        if session.revocation_epoch != account.revocation_epoch
            || session.identity_path != account.identity.to_string()
            || session.credential_epoch
                != credentials::epoch_by_key(state, &account.key, self.credential_sealer()?).await?
        {
            return Err(AuthError::InvalidSession);
        }
        session.renew_activity(now, self.config.idle_ttl_ms);
        if !session.is_live_at(self.host_runtime.now_millis()) {
            return Err(AuthError::InvalidSession);
        }
        session = write_session(self.session_store.as_ref(), &session_path, &session).await?;

        let grants = effective_session_grants(
            &account.grants,
            session
                .authority_ceiling
                .as_ref()
                .ok_or(AuthError::InvalidSession)?,
        )?;
        if !session.is_live_at(self.host_runtime.now_millis()) {
            return Err(AuthError::InvalidSession);
        }
        Ok(ConsolePrincipal {
            username: account.display_name,
            authority_id: account.key.authority_id().into(),
            account_id: account.key.instance_id().into(),
            identity_path: account.identity.to_string(),
            grants,
            authority_ceiling: session.authority_ceiling,
            authentication: session.authentication,
        })
    }

    /// Rotate a session's bearer token: validate the presented token, issue a
    /// fresh secret (invalidating the old hash), and extend the idle window.
    /// The session id is preserved; only the secret changes.
    pub(crate) async fn refresh_session(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        source_addr: Option<&str>,
    ) -> Result<LoginResponse, AuthError> {
        let result = self
            .refresh_session_inner(boot.kernel().state(), bearer)
            .await;
        let (outcome, username, authentication) = match &result {
            Ok((response, username)) => (
                "token_refresh",
                Some(username.as_str()),
                Some(&response.authentication),
            ),
            Err(error) => (audit_outcome(error), None, None),
        };
        record_auth_audit(
            boot,
            "console_credential",
            username,
            source_addr,
            outcome,
            authentication,
        )?;
        result.map(|(response, _)| response)
    }

    async fn refresh_session_inner(
        &self,
        state: &Backend,
        bearer: &str,
    ) -> Result<(LoginResponse, String), AuthError> {
        let (sid, token) = bearer.split_once('.').ok_or(AuthError::InvalidSession)?;
        validate_session_id(sid)?;
        let session_path = session_path(sid)?;
        let Some(mut session) = read_session(self.session_store.as_ref(), &session_path).await?
        else {
            return Err(AuthError::InvalidSession);
        };
        let now = self.host_runtime.now_millis();
        if !session.is_live_at(now) {
            retire_expired_session(self.session_store.as_ref(), &session, now).await?;
            return Err(AuthError::InvalidSession);
        }
        if session
            .token_hash
            .as_bytes()
            .ct_eq(token_hash(token).as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(AuthError::InvalidSession);
        }

        let account = self
            .current_account(state, &session.account_key(), Some(&session.username))
            .await?;
        if !account.active {
            return Err(AuthError::AccountUnavailable);
        }

        if session.revocation_epoch != account.revocation_epoch
            || session.identity_path != account.identity.to_string()
            || session.credential_epoch
                != credentials::epoch_by_key(state, &account.key, self.credential_sealer()?).await?
        {
            return Err(AuthError::InvalidSession);
        }
        session.renew_activity(now, self.config.idle_ttl_ms);
        if !session.is_live_at(self.host_runtime.now_millis()) {
            return Err(AuthError::InvalidSession);
        }
        let new_secret = random_token(32)?;
        let new_token = format!("{sid}.{new_secret}");
        session.token_hash = token_hash(&new_secret);
        session = write_session(self.session_store.as_ref(), &session_path, &session).await?;
        let completed_at = self.host_runtime.now_millis();
        if !session.is_live_at(completed_at) {
            retire_expired_session(self.session_store.as_ref(), &session, completed_at).await?;
            return Err(AuthError::InvalidSession);
        }

        Ok((
            LoginResponse {
                sid: sid.to_string(),
                token: new_token,
                expires_at: session.expires_at,
                idle_expires_at: session.idle_expires_at,
                authentication: session.authentication,
            },
            account.display_name,
        ))
    }

    /// Revoke one session id and record its account attribution. Reading a target
    /// session is not authentication; this event does not claim assurance.
    pub(crate) async fn logout_sid_from_source(
        &self,
        boot: &Bootstrap,
        sid: &str,
        source_addr: Option<&str>,
    ) -> Result<(), AuthError> {
        validate_session_id(sid)?;
        let session = read_session(self.session_store.as_ref(), &session_path(sid)?).await?;
        let username = session.as_ref().map(|s| s.username.as_str());
        let result = revoke_session(self.session_store.as_ref(), sid).await;
        match &result {
            Ok(()) => {
                record_auth_audit(
                    boot,
                    "console_credential",
                    username,
                    source_addr,
                    "logout",
                    None,
                )?;
            }
            Err(err) => {
                record_auth_audit(
                    boot,
                    "console_credential",
                    username,
                    source_addr,
                    audit_outcome(err),
                    None,
                )?;
            }
        }
        result
    }

    /// Read one live session page without mutating or sweeping expired records.
    pub(crate) async fn list_sessions(
        &self,
        boot: &Bootstrap,
        principal: &ConsolePrincipal,
        query: &xolotl_state::StateScan,
    ) -> Result<SessionPage, AuthError> {
        let sessions_root = Path::parse(SESSIONS_PREFIX)?;
        authorize_prefix_read(boot.kernel().state(), principal, &sessions_root).await?;
        if query.prefix != sessions_root {
            return Err(AuthError::Query(
                "expected the console session prefix".into(),
            ));
        }
        let after = query
            .cursor
            .as_ref()
            .map(|cursor| {
                let bytes = cursor
                    .0
                    .strip_prefix(b"console-session-v1:")
                    .ok_or_else(|| AuthError::Query("invalid session cursor".into()))?;
                std::str::from_utf8(bytes)
                    .map_err(|_invalid_utf8| AuthError::Query("invalid session cursor".into()))
            })
            .transpose()?;
        let page = self
            .session_store
            .list(
                after,
                crate::session_store::SessionPageLimits {
                    rows: query.limits.entries.get().min(query.limits.examined.get()),
                    bytes: query.limits.encoded_bytes.get(),
                },
            )
            .await
            .map_err(|error| match error {
                crate::session_store::SessionStoreError::Rejected(reason) => {
                    AuthError::Query(reason)
                }
                error => session_store_error(error),
            })?;
        let now = self.host_runtime.now_millis();
        let mut sessions = Vec::new();
        for row in page.entries {
            let target = crate::paths::session_path(row.sid())?;
            authorize_path(boot.kernel().state(), principal, "read", &target, None).await?;
            if row.record.is_live_at(now) {
                sessions.push(SessionSummary::from(row.record));
            }
        }
        Ok(SessionPage {
            entries: sessions,
            next: page.next.map(|sid| {
                xolotl_state::StateCursor(
                    [b"console-session-v1:".as_slice(), sid.as_bytes()].concat(),
                )
            }),
        })
    }

    /// Revoke one session and record an optional source address.
    pub(crate) async fn revoke_session_by_id_from_source(
        &self,
        boot: &Bootstrap,
        principal: &ConsolePrincipal,
        sid: &str,
        source_addr: Option<&str>,
    ) -> Result<(), AuthError> {
        validate_session_id(sid)?;
        let path = crate::paths::session_path(sid)?;
        authorize_path(boot.kernel().state(), principal, "write", &path, None).await?;
        let result = revoke_session(self.session_store.as_ref(), sid).await;
        match &result {
            Ok(()) => record_auth_audit(
                boot,
                "console_credential",
                Some(&principal.username),
                source_addr,
                "session_revoke",
                Some(&principal.authentication),
            )?,
            Err(err) => record_auth_audit(
                boot,
                "console_credential",
                Some(&principal.username),
                source_addr,
                audit_outcome(err),
                Some(&principal.authentication),
            )?,
        }
        result
    }

    /// Revoke all active sessions for `username` and record an optional source.
    pub(crate) async fn revoke_user_sessions_from_source(
        &self,
        boot: &Bootstrap,
        principal: &ConsolePrincipal,
        username: &str,
        source_addr: Option<&str>,
    ) -> Result<usize, AuthError> {
        validate_username(username)?;
        let user_path = user_path(username)?;
        authorize_path(boot.kernel().state(), principal, "write", &user_path, None).await?;
        let account = read_user(boot.kernel().state(), username)
            .await?
            .ok_or(AuthError::AccountUnavailable)?;
        let mut revoked = 0usize;
        for _ in 0..self.session_store.policy().per_account() {
            let count = self
                .session_store
                .revoke_account(
                    account.account_key().authority_id(),
                    account.account_key().instance_id(),
                )
                .await
                .map_err(session_store_error)?;
            revoked += count;
            if count == 0 || revoked >= self.session_store.policy().per_account() {
                break;
            }
        }
        record_auth_audit(
            boot,
            "console_credential",
            Some(&principal.username),
            source_addr,
            "user_sessions_revoke",
            Some(&principal.authentication),
        )?;
        Ok(revoked)
    }

    async fn issue_session(
        &self,
        state: &Backend,
        account: &AccountSnapshot,
        source_addr: String,
        authentication: AuthenticationEvidence,
        credential_epoch: String,
        authority_ceiling: Option<CapSet>,
    ) -> Result<LoginResponse, AuthError> {
        authentication.validate()?;
        if authentication
            .primary
            .valid_until()
            .is_some_and(|until| until <= self.host_runtime.now_millis())
        {
            return Err(AuthError::InvalidCredentials);
        }
        let current = self
            .current_account(state, &account.key, Some(&account.display_name))
            .await?;
        if !current.active {
            return Err(AuthError::AccountUnavailable);
        }
        if current.revocation_epoch != account.revocation_epoch
            || current.identity != account.identity
            || credentials::epoch_by_key(state, &account.key, self.credential_sealer()?).await?
                != credential_epoch
        {
            return Err(AuthError::InvalidCredentials);
        }
        let authority_ceiling = match authority_ceiling {
            Some(requested) => effective_session_grants(&current.grants, &requested)?,
            None => current.grants,
        };
        validate_issued_authority_ceiling(&authority_ceiling)?;

        let sid = random_token(18)?;
        let token_secret = random_token(32)?;
        let token = format!("{sid}.{token_secret}");
        let now = self.host_runtime.now_millis();
        let expires_at = authentication
            .primary
            .valid_until()
            .map_or(now.saturating_add(self.config.session_ttl_ms), |until| {
                until.min(now.saturating_add(self.config.session_ttl_ms))
            });
        if expires_at <= now {
            return Err(AuthError::InvalidCredentials);
        }
        let idle_expires_at = now.saturating_add(self.config.idle_ttl_ms).min(expires_at);
        let session = SessionRecord {
            persisted: None,
            sid: sid.clone(),
            token_hash: token_hash(&token_secret),
            username: current.display_name,
            authority_id: account.key.authority_id().into(),
            account_id: account.key.instance_id().into(),
            revocation_epoch: account.revocation_epoch.clone(),
            identity_path: account.identity.to_string(),
            issued_at: now,
            expires_at,
            idle_expires_at,
            authentication,
            credential_epoch,
            authority_ceiling: Some(authority_ceiling),
            last_seen: now,
            source_addr,
        };
        let session =
            write_session(self.session_store.as_ref(), &session_path(&sid)?, &session).await?;
        let completed_at = self.host_runtime.now_millis();
        if !session.is_live_at(completed_at) {
            retire_expired_session(self.session_store.as_ref(), &session, completed_at).await?;
            return Err(AuthError::InvalidCredentials);
        }

        Ok(LoginResponse {
            sid,
            token,
            expires_at,
            idle_expires_at,
            authentication: session.authentication,
        })
    }

    fn check_rate_limits(
        &self,
        username: &str,
        source_addr: &str,
        now: i64,
    ) -> Result<(), AuthError> {
        let mut rate = self.rate();
        prune_bucket(&mut rate.global, now);
        if let Some(retry) = retry_after(rate.global, now) {
            return Err(AuthError::RateLimited {
                retry_after_ms: retry,
            });
        }
        check_rate_bucket(&mut rate.by_user, username, now)?;
        check_rate_bucket(&mut rate.by_source, source_addr, now)?;
        Ok(())
    }

    fn record_login_failure(&self, username: &str, source_addr: &str, now: i64) {
        let mut rate = self.rate();
        mark_rate_failure(&mut rate.by_user, username, now);
        mark_rate_failure(&mut rate.by_source, source_addr, now);
        mark_failure(&mut rate.global, now);
    }

    fn clear_login_failures(&self, username: &str, source_addr: &str, _now: i64) {
        let mut rate = self.rate();
        rate.by_user.remove(username);
        rate.by_source.remove(source_addr);
    }

    fn rate(&self) -> MutexGuard<'_, RateState> {
        match self.rate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Validate console username syntax.
pub(crate) fn validate_username(username: &str) -> Result<(), AuthError> {
    if username.is_empty() || username.len() > 63 {
        return Err(AuthError::InvalidUsername);
    }
    let mut chars = username.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphanumeric() => {}
        _ => return Err(AuthError::InvalidUsername),
    }
    if chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        Ok(())
    } else {
        Err(AuthError::InvalidUsername)
    }
}

fn validate_issued_authority_ceiling(ceiling: &CapSet) -> Result<(), AuthError> {
    if ceiling.len() > MAX_SESSION_CEILING_CAPABILITIES {
        return Err(AuthError::State(
            "session authority ceiling exceeds limit".into(),
        ));
    }
    let mut total_bytes = 0usize;
    for capability in ceiling.iter() {
        let literal = capability.to_string();
        total_bytes = total_bytes.saturating_add(literal.len());
        if literal.len() > MAX_SESSION_CAPABILITY_BYTES
            || total_bytes > MAX_SESSION_CEILING_BYTES
            || !matches!(Capability::parse(&literal), Ok(parsed) if parsed == *capability)
        {
            return Err(AuthError::State(
                "session authority ceiling exceeds limit".into(),
            ));
        }
    }
    Ok(())
}

fn read_authority_ceiling(value: &Value) -> Result<Option<CapSet>, AuthError> {
    if value.is_null() {
        return Ok(None);
    }
    let items = value.as_list().ok_or(AuthError::InvalidSession)?;
    if items.len() > MAX_SESSION_CEILING_CAPABILITIES {
        return Err(AuthError::InvalidSession);
    }
    if items
        .iter()
        .map(|item| item.as_str().map_or(0, str::len))
        .sum::<usize>()
        > MAX_SESSION_CEILING_BYTES
    {
        return Err(AuthError::InvalidSession);
    }
    let caps = items
        .iter()
        .map(|item| {
            let text = item.as_str().ok_or(AuthError::InvalidSession)?;
            if text.len() > MAX_SESSION_CAPABILITY_BYTES {
                return Err(AuthError::InvalidSession);
            }
            Capability::parse(text).map_err(|_error| AuthError::InvalidSession)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(CapSet(caps)))
}

#[derive(Clone, Debug)]
struct UserRecord {
    // Exact state observed at read time, used to serialize authentication and
    // administrative edits through the same CAS boundary.
    persisted: Option<Value>,
    username: String,
    account_id: String,
    bootstrap_owner: bool,
    identity_path: String,
    status: String,
    roles: Vec<String>,
    grants: Vec<String>,
    authority_ceiling: Vec<String>,
    created_by: String,
    created_at: i64,
}

impl UserRecord {
    fn account_key(&self) -> AccountKey {
        AccountKey::local(&self.account_id)
    }

    fn version(&self) -> i64 {
        self.persisted
            .as_ref()
            .and_then(Value::as_map)
            .and_then(|map| map.get("version"))
            .and_then(Value::as_int)
            .unwrap_or(0)
    }

    fn from_value(username: &str, value: &Value) -> Result<Self, AuthError> {
        let m = value.as_map().ok_or(AuthError::InvalidCredentials)?;
        let account_id = required_str_field(m, "account_id", "console user")?;
        let identity_path = required_str_field(m, "identity_path", "console user")?;
        validate_console_identity_path(&identity_path)?;
        if identity_path != local_identity_path(&account_id)? {
            return Err(AuthError::AccountUnavailable);
        }
        let bootstrap_owner = m
            .get("bootstrap_owner")
            .and_then(Value::as_bool)
            .ok_or_else(|| AuthError::State("console user.bootstrap_owner is invalid".into()))?;
        if bootstrap_owner && username != ROOT_USERNAME {
            return Err(AuthError::AccountUnavailable);
        }
        let status = required_str_field(m, "status", "console user")?;
        if !matches!(
            status.as_str(),
            "active" | "disabled" | "locked" | "provisioning"
        ) {
            return Err(AuthError::State("console user.status is invalid".into()));
        }
        let created_at = required_nonnegative_int_field(m, "created_at", "console user")?;
        Ok(Self {
            persisted: Some(value.clone()),
            username: username.to_string(),
            account_id,
            bootstrap_owner,
            identity_path,
            status,
            roles: required_string_list_field(m, "roles", "console user")?,
            grants: required_string_list_field(m, "grants", "console user")?,
            authority_ceiling: required_string_list_field(m, "authority_ceiling", "console user")?,
            created_by: required_str_field(m, "created_by", "console user")?,
            created_at,
        })
    }

    fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("account_id".into(), Value::string(self.account_id.clone()));
        m.insert(
            "bootstrap_owner".into(),
            Value::boolean(self.bootstrap_owner),
        );
        m.insert(
            "identity_path".into(),
            Value::string(self.identity_path.clone()),
        );
        m.insert("status".into(), Value::string(self.status.clone()));
        m.insert("roles".into(), string_values(&self.roles));
        m.insert("grants".into(), string_values(&self.grants));
        m.insert(
            "authority_ceiling".into(),
            string_values(&self.authority_ceiling),
        );
        m.insert("created_by".into(), Value::string(self.created_by.clone()));
        m.insert("created_at".into(), Value::integer(self.created_at));
        Value::map(m)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct SessionRecord {
    pub(crate) persisted: Option<Value>,
    pub(crate) sid: String,
    pub(crate) token_hash: String,
    pub(crate) username: String,
    pub(crate) authority_id: String,
    pub(crate) account_id: String,
    pub(crate) revocation_epoch: String,
    pub(crate) identity_path: String,
    pub(crate) issued_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) idle_expires_at: i64,
    pub(crate) authentication: AuthenticationEvidence,
    pub(crate) credential_epoch: String,
    pub(crate) authority_ceiling: Option<CapSet>,
    pub(crate) last_seen: i64,
    pub(crate) source_addr: String,
}

impl SessionRecord {
    fn is_live_at(&self, now: i64) -> bool {
        self.expires_at > now && self.idle_expires_at > now
    }

    fn renew_activity(&mut self, admitted_at: i64, idle_ttl_ms: i64) {
        self.last_seen = admitted_at;
        self.idle_expires_at = admitted_at.saturating_add(idle_ttl_ms).min(self.expires_at);
    }

    fn has_same_authority_as(&self, observed: &Self) -> bool {
        self.sid == observed.sid
            && self.username == observed.username
            && self.authority_id == observed.authority_id
            && self.account_id == observed.account_id
            && self.identity_path == observed.identity_path
            && self.issued_at == observed.issued_at
            && self.expires_at == observed.expires_at
            && self.authentication == observed.authentication
            && self.revocation_epoch == observed.revocation_epoch
            && self.credential_epoch == observed.credential_epoch
            && self.authority_ceiling == observed.authority_ceiling
            && self.source_addr == observed.source_addr
    }

    fn account_key(&self) -> AccountKey {
        AccountKey::from_parts(&self.authority_id, &self.account_id)
    }

    pub(crate) fn from_value(sid: &str, value: &Value) -> Result<Self, AuthError> {
        let m = value.as_map().ok_or(AuthError::InvalidSession)?;
        let token_hash = str_field(m, "token_hash").ok_or(AuthError::InvalidSession)?;
        if token_hash.len() != 43
            || URL_SAFE_NO_PAD
                .decode(&token_hash)
                .ok()
                .is_none_or(|digest| {
                    digest.len() != 32 || URL_SAFE_NO_PAD.encode(digest) != token_hash
                })
        {
            return Err(AuthError::InvalidSession);
        }
        let username = str_field(m, "username").ok_or(AuthError::InvalidSession)?;
        if username.is_empty() || username.len() > 256 || username.chars().any(char::is_control) {
            return Err(AuthError::InvalidSession);
        }
        let authority_id = str_field(m, "authority_id").ok_or(AuthError::InvalidSession)?;
        let account_id = str_field(m, "account_id").ok_or(AuthError::InvalidSession)?;
        AccountKey::new(&authority_id, &account_id).map_err(|_error| AuthError::InvalidSession)?;
        let revocation_epoch = str_field(m, "revocation_epoch").ok_or(AuthError::InvalidSession)?;
        if revocation_epoch.is_empty()
            || revocation_epoch.len() > 128
            || revocation_epoch.chars().any(char::is_control)
        {
            return Err(AuthError::InvalidSession);
        }
        let identity_path = str_field(m, "identity_path").ok_or(AuthError::InvalidSession)?;
        validate_console_identity_path(&identity_path)?;
        if authority_id == LOCAL_AUTHORITY_ID
            && identity_path
                != local_identity_path(&account_id).map_err(|_error| AuthError::InvalidSession)?
        {
            return Err(AuthError::InvalidSession);
        }
        let expires_at = int_field(m, "expires_at").ok_or(AuthError::InvalidSession)?;
        let idle_expires_at = int_field(m, "idle_expires_at").ok_or(AuthError::InvalidSession)?;
        let authentication = AuthenticationEvidence::from_value(
            m.get("authentication").ok_or(AuthError::InvalidSession)?,
        )?;
        if idle_expires_at > expires_at
            || authentication
                .primary
                .valid_until()
                .is_some_and(|until| expires_at > until)
        {
            return Err(AuthError::InvalidSession);
        }
        Ok(Self {
            persisted: Some(value.clone()),
            sid: sid.to_string(),
            token_hash,
            username,
            authority_id,
            account_id,
            revocation_epoch,
            identity_path,
            issued_at: int_field(m, "issued_at").ok_or(AuthError::InvalidSession)?,
            expires_at,
            idle_expires_at,
            authentication,
            credential_epoch: str_field(m, "credential_epoch").ok_or(AuthError::InvalidSession)?,
            authority_ceiling: read_authority_ceiling(
                m.get("authority_ceiling")
                    .ok_or(AuthError::InvalidSession)?,
            )?
            .ok_or(AuthError::InvalidSession)
            .map(Some)?,
            last_seen: optional_int_field(m, "last_seen", "console session", 0)?,
            source_addr: optional_str_field(m, "source_addr", "console session", "")?,
        })
    }

    pub(crate) fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert(
            "authority_id".into(),
            Value::string(self.authority_id.clone()),
        );
        m.insert("token_hash".into(), Value::string(self.token_hash.clone()));
        m.insert("account_id".into(), Value::string(self.account_id.clone()));
        m.insert(
            "revocation_epoch".into(),
            Value::string(self.revocation_epoch.clone()),
        );
        m.insert("username".into(), Value::string(self.username.clone()));
        m.insert(
            "identity_path".into(),
            Value::string(self.identity_path.clone()),
        );
        m.insert("issued_at".into(), Value::integer(self.issued_at));
        m.insert("expires_at".into(), Value::integer(self.expires_at));
        m.insert(
            "idle_expires_at".into(),
            Value::integer(self.idle_expires_at),
        );
        m.insert("authentication".into(), self.authentication.to_value());
        m.insert(
            "credential_epoch".into(),
            Value::string(self.credential_epoch.clone()),
        );
        m.insert(
            "authority_ceiling".into(),
            self.authority_ceiling
                .as_ref()
                .map_or(Value::null(), |ceiling| {
                    Value::list(
                        ceiling
                            .iter()
                            .map(|cap| Value::string(cap.to_string()))
                            .collect(),
                    )
                }),
        );
        m.insert("last_seen".into(), Value::integer(self.last_seen));
        m.insert(
            "source_addr".into(),
            Value::string(self.source_addr.clone()),
        );
        Value::map(m)
    }
}

impl From<SessionRecord> for SessionSummary {
    fn from(s: SessionRecord) -> Self {
        Self {
            sid: s.sid,
            username: s.username,
            identity_path: s.identity_path,
            issued_at: s.issued_at,
            expires_at: s.expires_at,
            idle_expires_at: s.idle_expires_at,
            authentication: s.authentication,
            last_seen: s.last_seen,
            source_addr: s.source_addr,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyChallengeRecord {
    credential_epoch: String,
    nonce: String,
}

async fn read_user(state: &Backend, username: &str) -> Result<Option<UserRecord>, AuthError> {
    let path = user_path(username)?;
    state
        .read(&path)
        .await?
        .map(|v| UserRecord::from_value(username, &v))
        .transpose()
}

async fn write_user(state: &Backend, user: &UserRecord) -> Result<Value, AuthError> {
    let path = user_path(&user.username)?;
    let mut value = user
        .to_value()
        .into_map()
        .ok_or_else(|| AuthError::State("console user must be an object".into()))?;
    let version = user
        .persisted
        .as_ref()
        .map(|current| {
            let map = current.as_map().ok_or(AuthError::InvalidCredentials)?;
            optional_int_field(map, "version", "console user", 0)
        })
        .transpose()?
        .unwrap_or(0);
    let next = version
        .checked_add(1)
        .filter(|_| version >= 0)
        .ok_or_else(|| AuthError::State("console user version is out of range".into()))?;
    value
        .insert("version".into(), Value::integer(next))
        .map_err(|error| AuthError::State(error.to_string()))?;
    let value = Value::from(value);
    match state
        .write_cas(&path, user.persisted.clone(), value.clone())
        .await
    {
        Ok(_) => {}
        Err(xolotl_state::StateFailure {
            error: xolotl_state::StateError::CasFailed { .. },
            ..
        }) => {
            // A consumed TOTP or concurrent account edit invalidates this
            // authentication attempt; never restore stale grants or status.
            return Err(AuthError::InvalidCredentials);
        }
        Err(error) => return Err(error.into()),
    }
    Ok(value)
}

async fn read_session(
    store: &dyn crate::session_store::ConsoleSessionStore,
    path: &Path,
) -> Result<Option<SessionRecord>, AuthError> {
    let sid = crate::paths::stored_session_id_from_path(path).ok_or(AuthError::InvalidSession)?;
    store
        .get(sid)
        .await
        .map_err(session_store_error)?
        .map(|row| {
            let mut record = row.record;
            record.persisted = Some(record.to_value());
            Ok(record)
        })
        .transpose()
}

fn session_store_error(error: crate::session_store::SessionStoreError) -> AuthError {
    match error {
        crate::session_store::SessionStoreError::Conflict => AuthError::InvalidSession,
        crate::session_store::SessionStoreError::Rejected(_) => AuthError::SessionAdmissionRejected,
        crate::session_store::SessionStoreError::Unknown(_) => AuthError::SessionCommitUnknown,
        error => AuthError::State(error.to_string()),
    }
}

async fn write_session(
    store: &dyn crate::session_store::ConsoleSessionStore,
    path: &Path,
    session: &SessionRecord,
) -> Result<SessionRecord, AuthError> {
    use crate::session_store::{ConsoleSession, SessionStoreError};
    let mut expected = session.persisted.clone();
    let observed_token_hash = expected
        .as_ref()
        .map(|value| SessionRecord::from_value(&session.sid, value).map(|record| record.token_hash))
        .transpose()?;
    let mut updated = session.clone();
    for _ in 0..8 {
        let row = ConsoleSession::from_record(updated.clone());
        let result = match &expected {
            Some(value) => {
                store
                    .compare_replace(
                        ConsoleSession::from_record(SessionRecord::from_value(
                            &session.sid,
                            value,
                        )?),
                        row,
                    )
                    .await
            }
            None => store.create(row).await,
        };
        match result {
            Ok(()) => {
                let current = read_session(store, path)
                    .await?
                    .ok_or(AuthError::InvalidSession)?;
                if !current.has_same_authority_as(&updated)
                    || current.token_hash != updated.token_hash
                {
                    return Err(AuthError::InvalidSession);
                }
                return Ok(current);
            }
            Err(SessionStoreError::Unknown(_)) if expected.is_none() => {
                let current = read_session(store, path)
                    .await
                    .map_err(|_read_error| AuthError::SessionCommitUnknown)?;
                if let Some(current) = current {
                    if current.has_same_authority_as(session)
                        && current.token_hash == session.token_hash
                    {
                        return Ok(current);
                    }
                    return Err(AuthError::InvalidSession);
                }
                return Err(AuthError::SessionCommitUnknown);
            }
            Err(SessionStoreError::Conflict) if session.persisted.is_some() => {}
            Err(error) => return Err(session_store_error(error)),
        }
        let current = read_session(store, path)
            .await?
            .ok_or(AuthError::InvalidSession)?;
        if !current.has_same_authority_as(session)
            || Some(current.token_hash.as_str()) != observed_token_hash.as_deref()
        {
            return Err(AuthError::InvalidSession);
        }
        updated.last_seen = updated.last_seen.max(current.last_seen);
        updated.idle_expires_at = updated
            .idle_expires_at
            .max(current.idle_expires_at)
            .min(updated.expires_at);
        expected = current.persisted;
    }
    Err(AuthError::RateLimited { retry_after_ms: 10 })
}

async fn revoke_session(
    store: &dyn crate::session_store::ConsoleSessionStore,
    sid: &str,
) -> Result<(), AuthError> {
    store.delete(sid, None).await.map_err(session_store_error)
}

async fn retire_expired_session(
    store: &dyn crate::session_store::ConsoleSessionStore,
    session: &SessionRecord,
    now: i64,
) -> Result<(), AuthError> {
    if session.is_live_at(now) {
        return Ok(());
    }
    let expected = session
        .persisted
        .as_ref()
        .ok_or(AuthError::InvalidSession)?;
    let expected = crate::session_store::ConsoleSession::from_record(SessionRecord::from_value(
        &session.sid,
        expected,
    )?);
    match store.delete(&session.sid, Some(expected)).await {
        Ok(()) | Err(crate::session_store::SessionStoreError::Conflict) => Ok(()),
        Err(error) => Err(session_store_error(error)),
    }
}

fn root_grants() -> Vec<String> {
    vec![
        "perform://effect/kernel/**".into(),
        "perform://effect/external/**".into(),
        "perform://effect/proc/**".into(),
        "read://state/**".into(),
        "write://state/kernel/**".into(),
        "subscribe://state/**".into(),
        "read://state/fact/**".into(),
        "perform://effect/kernel/console/users/**".into(),
    ]
}

async fn prefix_has_entries(state: &Backend, prefix: Path) -> Result<bool, AuthError> {
    let mut query = xolotl_state::StateScan::new(prefix);
    query.limits.entries = std::num::NonZeroUsize::MIN;
    let mut pages = state.pages(query);
    while let Some(page) = pages.next().await? {
        if !page.entries.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

const LOCKOUT_THRESHOLD: u32 = 5;
const LOCKOUT_BASE_MS: i64 = 1_000;
const LOCKOUT_MAX_MS: i64 = 60_000;

async fn read_lockout(state: &Backend, username: &str) -> Result<LockoutState, AuthError> {
    read_lockout_at(state, &lockout_path(username)?).await
}

async fn read_account_lockout(
    state: &Backend,
    key: &AccountKey,
) -> Result<LockoutState, AuthError> {
    read_lockout_at(
        state,
        &crate::paths::account_lockout_path(key.authority_id(), key.instance_id())?,
    )
    .await
}

async fn read_lockout_at(state: &Backend, path: &Path) -> Result<LockoutState, AuthError> {
    let Some(value) = state.read(path).await? else {
        return Ok(LockoutState::default());
    };
    let Some(map) = value.as_map() else {
        return Ok(LockoutState::default());
    };
    let consecutive_failures = map
        .get("consecutive_failures")
        .and_then(Value::as_int)
        .map(|i| i.max(0) as u32)
        .unwrap_or(0);
    let locked_until_ms = map
        .get("locked_until_ms")
        .and_then(Value::as_int)
        .unwrap_or(0);
    Ok(LockoutState {
        consecutive_failures,
        locked_until_ms,
    })
}

async fn write_lockout(
    state: &Backend,
    username: &str,
    lockout: &LockoutState,
) -> Result<(), AuthError> {
    write_lockout_at(state, &lockout_path(username)?, lockout).await
}

async fn write_lockout_at(
    state: &Backend,
    path: &Path,
    lockout: &LockoutState,
) -> Result<(), AuthError> {
    let mut map = BTreeMap::new();
    map.insert(
        "consecutive_failures".into(),
        Value::integer(lockout.consecutive_failures as i64),
    );
    map.insert(
        "locked_until_ms".into(),
        Value::integer(lockout.locked_until_ms),
    );
    state.write_set(path, Value::map(map)).await?;
    Ok(())
}

async fn clear_lockout(state: &Backend, username: &str) -> Result<(), AuthError> {
    let path = lockout_path(username)?;
    state.write_delete(&path).await?;
    Ok(())
}

async fn clear_account_lockout(state: &Backend, key: &AccountKey) -> Result<(), AuthError> {
    let path = crate::paths::account_lockout_path(key.authority_id(), key.instance_id())?;
    state.write_delete(&path).await?;
    Ok(())
}

async fn record_account_lockout_failure(
    state: &Backend,
    username: &str,
    now: i64,
) -> Result<(), AuthError> {
    let mut lockout = read_lockout(state, username).await?;
    lockout.consecutive_failures = lockout.consecutive_failures.saturating_add(1);
    lockout.locked_until_ms = lockout_until_ms(
        lockout.consecutive_failures,
        LOCKOUT_THRESHOLD,
        LOCKOUT_BASE_MS,
        LOCKOUT_MAX_MS,
        now,
    );
    write_lockout(state, username, &lockout).await
}

async fn record_factor_lockout_failure(
    state: &Backend,
    key: &AccountKey,
    now: i64,
) -> Result<(), AuthError> {
    let path = crate::paths::account_lockout_path(key.authority_id(), key.instance_id())?;
    let mut lockout = read_lockout_at(state, &path).await?;
    lockout.consecutive_failures = lockout.consecutive_failures.saturating_add(1);
    lockout.locked_until_ms = lockout_until_ms(
        lockout.consecutive_failures,
        LOCKOUT_THRESHOLD,
        LOCKOUT_BASE_MS,
        LOCKOUT_MAX_MS,
        now,
    );
    write_lockout_at(state, &path, &lockout).await
}

fn hash_password(password: &str) -> Result<String, AuthError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| AuthError::Crypto(e.to_string()))?;
    hash_password_with_salt(password, &salt)
}

fn hash_password_with_salt(password: &str, salt: &[u8]) -> Result<String, AuthError> {
    let params = argon2_params()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    Ok(argon2
        .hash_password_with_salt(password.as_bytes(), salt)
        .map_err(|e| AuthError::Crypto(e.to_string()))?
        .to_string())
}

fn verify_password(phc: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    let Ok(params) = argon2_params() else {
        return false;
    };
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2.verify_password(password.as_bytes(), &parsed).is_ok()
}

#[cfg(not(test))]
fn argon2_params() -> Result<Params, AuthError> {
    Params::new(65_536, 3, 2, None).map_err(|e| AuthError::Crypto(e.to_string()))
}

#[cfg(test)]
fn argon2_params() -> Result<Params, AuthError> {
    Params::new(256, 1, 1, None).map_err(|e| AuthError::Crypto(e.to_string()))
}

fn random_token(bytes: usize) -> Result<String, AuthError> {
    let mut buf = vec![0u8; bytes];
    getrandom::fill(&mut buf).map_err(|e| AuthError::Crypto(e.to_string()))?;
    Ok(format!("t{}", URL_SAFE_NO_PAD.encode(buf)))
}

fn token_hash(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn validate_origin(origin: &str) -> Result<String, AuthError> {
    if origin.is_empty()
        || origin.len() > 256
        || origin.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(AuthError::InvalidChallenge);
    }
    Ok(origin.to_string())
}

fn key_login_transcript(username: &str, challenge_id: &str, nonce: &str, origin: &str) -> String {
    format!("xolotl-console-ml-dsa-65-v1\n{username}\n{challenge_id}\n{nonce}\n{origin}")
}

fn verify_key_login<'a>(
    descriptors: &'a [String],
    requested_key: &str,
    signature_b64: &str,
    transcript: &str,
) -> Result<Option<&'a str>, AuthError> {
    if signature_b64.len() != (ML_DSA_65_SIGNING.signature_len() * 8).div_ceil(6) {
        return Err(AuthError::InvalidCredentials);
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .map_err(|_error| AuthError::InvalidCredentials)?;
    if signature_bytes.len() != ML_DSA_65_SIGNING.signature_len()
        || URL_SAFE_NO_PAD.encode(&signature_bytes) != signature_b64
    {
        return Err(AuthError::InvalidCredentials);
    }

    let Some(descriptor) = descriptors.iter().find(|key| key.as_str() == requested_key) else {
        return Ok(None);
    };
    let key = parse_ml_dsa_65_key_descriptor(descriptor)?;
    if key
        .verify_sig(transcript.as_bytes(), &signature_bytes)
        .is_ok()
    {
        return Ok(Some(descriptor));
    }
    Ok(None)
}

fn parse_ml_dsa_65_key_descriptor(descriptor: &str) -> Result<ParsedPublicKey, AuthError> {
    let Some(encoded) = descriptor.strip_prefix("ml-dsa-65:") else {
        return Err(AuthError::Crypto("unsupported key descriptor".into()));
    };
    if encoded.len() != (1952usize * 8).div_ceil(6) {
        return Err(AuthError::Crypto("invalid ML-DSA-65 key length".into()));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_error| AuthError::Crypto("invalid ML-DSA-65 key encoding".into()))?;
    // FIPS 204's raw ML-DSA-65 public key is exactly 1952 bytes. Reject
    // alternate DER encodings so descriptors have a single wire form.
    if bytes.len() != 1952 || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(AuthError::Crypto("invalid ML-DSA-65 key encoding".into()));
    }
    ParsedPublicKey::new(&ML_DSA_65, bytes)
        .map_err(|_error| AuthError::Crypto("invalid ML-DSA-65 public key".into()))
}

pub(crate) fn validate_session_id(sid: &str) -> Result<(), AuthError> {
    if xolotl_types::path::is_simple_id_segment(sid) {
        Ok(())
    } else {
        Err(AuthError::InvalidSession)
    }
}

fn prune_bucket(bucket: &mut FailureBucket, now: i64) {
    if bucket.window_started_at == 0
        || now.saturating_sub(bucket.window_started_at) > RATE_WINDOW_MS
    {
        *bucket = FailureBucket {
            window_started_at: now,
            ..Default::default()
        };
    }
}

fn rate_capacity_retry(
    buckets: &mut HashMap<String, FailureBucket>,
    key: &str,
    now: i64,
) -> Option<i64> {
    if buckets.contains_key(key) || buckets.len() < MAX_RATE_BUCKETS {
        return None;
    }
    buckets.retain(|_, bucket| {
        bucket.window_started_at != 0
            && now.saturating_sub(bucket.window_started_at) <= RATE_WINDOW_MS
    });
    if buckets.len() < MAX_RATE_BUCKETS {
        return None;
    }
    // Fail closed instead of evicting a live penalty to admit another name.
    buckets
        .values()
        .map(|bucket| {
            bucket
                .window_started_at
                .saturating_add(RATE_WINDOW_MS + 1)
                .saturating_sub(now)
                .max(1)
        })
        .min()
}

fn check_rate_bucket(
    buckets: &mut HashMap<String, FailureBucket>,
    key: &str,
    now: i64,
) -> Result<(), AuthError> {
    if let Some(bucket) = buckets.get_mut(key) {
        prune_bucket(bucket, now);
        if let Some(retry) = retry_after(*bucket, now) {
            return Err(AuthError::RateLimited {
                retry_after_ms: retry,
            });
        }
    }
    if let Some(retry) = rate_capacity_retry(buckets, key, now) {
        return Err(AuthError::RateLimited {
            retry_after_ms: retry,
        });
    }
    Ok(())
}

fn mark_rate_failure(buckets: &mut HashMap<String, FailureBucket>, key: &str, now: i64) {
    // An already admitted attempt may finish after its slot expires. Keep the
    // hard bound; the global bucket still charges it.
    if rate_capacity_retry(buckets, key, now).is_none() {
        mark_failure(buckets.entry(key.to_string()).or_default(), now);
    }
}

fn retry_after(bucket: FailureBucket, now: i64) -> Option<i64> {
    if bucket.next_allowed_at > now {
        Some(bucket.next_allowed_at - now)
    } else {
        None
    }
}

fn mark_failure(bucket: &mut FailureBucket, now: i64) {
    prune_bucket(bucket, now);
    bucket.failures = bucket.failures.saturating_add(1);
    let shift = bucket.failures.min(8);
    let delay = (1_i64 << shift).saturating_mul(1000).min(300_000);
    bucket.next_allowed_at = now.saturating_add(delay);
}

fn str_field(m: &ValueMap, key: &str) -> Option<String> {
    m.get(key).and_then(Value::as_str).map(str::to_string)
}

fn int_field(m: &ValueMap, key: &str) -> Option<i64> {
    m.get(key).and_then(Value::as_int)
}

fn required_str_field(m: &ValueMap, key: &str, label: &str) -> Result<String, AuthError> {
    match m.get(key).map(Value::view) {
        Some(ValueView::Str(value)) if !value.is_empty() => Ok(value.to_owned()),
        Some(ValueView::Str(_)) => {
            Err(AuthError::State(format!("{label}.{key} must not be empty")))
        }
        Some(_) => Err(AuthError::State(format!("{label}.{key} must be a string"))),
        None => Err(AuthError::State(format!("{label}.{key} is required"))),
    }
}

fn required_nonnegative_int_field(m: &ValueMap, key: &str, label: &str) -> Result<i64, AuthError> {
    match m.get(key).map(Value::view) {
        Some(ValueView::Int(value)) if value >= 0 => Ok(value),
        Some(ValueView::Int(_)) => Err(AuthError::State(format!(
            "{label}.{key} must be non-negative"
        ))),
        Some(_) => Err(AuthError::State(format!(
            "{label}.{key} must be an integer"
        ))),
        None => Err(AuthError::State(format!("{label}.{key} is required"))),
    }
}

fn required_string_list_field(
    m: &ValueMap,
    key: &str,
    label: &str,
) -> Result<Vec<String>, AuthError> {
    match m.get(key) {
        Some(value) => string_list(value, &format!("{label}.{key}")),
        None => Err(AuthError::State(format!("{label}.{key} is required"))),
    }
}

fn validate_console_identity_path(identity_path: &str) -> Result<(), AuthError> {
    let path = Path::parse(identity_path)?;
    if path.cluster().is_some()
        || path.scheme() != "identity"
        || path.segments().is_empty()
        || !path.is_concrete()
    {
        return Err(AuthError::State(
            "console user.identity_path must be a concrete identity path".into(),
        ));
    }
    Ok(())
}

fn optional_str_field(
    m: &ValueMap,
    key: &str,
    label: &str,
    default: &str,
) -> Result<String, AuthError> {
    match m.get(key).map(Value::view) {
        Some(ValueView::Str(value)) => Ok(value.to_owned()),
        Some(_) => Err(AuthError::State(format!("{label}.{key} must be a string"))),
        None => Ok(default.to_string()),
    }
}

fn optional_int_field(
    m: &ValueMap,
    key: &str,
    label: &str,
    default: i64,
) -> Result<i64, AuthError> {
    match m.get(key).map(Value::view) {
        Some(ValueView::Int(value)) => Ok(value),
        Some(_) => Err(AuthError::State(format!(
            "{label}.{key} must be an integer"
        ))),
        None => Ok(default),
    }
}

fn optional_bool_field(m: &ValueMap, key: &str, label: &str) -> Result<bool, AuthError> {
    match m.get(key).map(Value::view) {
        Some(ValueView::Bool(value)) => Ok(value),
        Some(_) => Err(AuthError::State(format!("{label}.{key} must be a bool"))),
        None => Ok(false),
    }
}

fn optional_string_list_field(
    m: &ValueMap,
    key: &str,
    label: &str,
) -> Result<Vec<String>, AuthError> {
    match m.get(key) {
        Some(value) => string_list(value, &format!("{label}.{key}")),
        None => Ok(Vec::new()),
    }
}

fn string_list(v: &Value, label: &str) -> Result<Vec<String>, AuthError> {
    match v.view() {
        ValueView::List(xs) => xs
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| AuthError::State(format!("{label}[{idx}] must be a string")))
            })
            .collect(),
        _ => Err(AuthError::State(format!("{label} must be a list"))),
    }
}

fn string_values(items: &[String]) -> Value {
    Value::list(items.iter().map(|s| Value::string(s.clone())).collect())
}

#[cfg(test)]
mod crypto_tests;

#[cfg(test)]
mod request_tests;

#[cfg(test)]
mod tests;
