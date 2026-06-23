//! Console authentication and authorization.
//!
//! Credentials stay outside Operation input and Facts. Account records live
//! under `state://kernel/console/*`; password/session/TOTP secrets live under
//! `state://vault/console/*`.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, MutexGuard};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::Semaphore;
use xolotl_kernel::{Bootstrap, GatewayAudit};
use xolotl_state::{Backend, StateError};
use xolotl_types::{CapSet, Capability, Path, Value};

const USERS_PREFIX: &str = "state://kernel/console/users";
const SESSIONS_PREFIX: &str = "state://kernel/console/sessions";
const CHALLENGES_PREFIX: &str = "state://kernel/console/challenges";
const ROOT_USERNAME: &str = "root";
/// Default absolute session lifetime, in milliseconds.
pub const DEFAULT_SESSION_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// Default idle session lifetime, in milliseconds.
pub const DEFAULT_IDLE_TTL_MS: i64 = 2 * 60 * 60 * 1000;
/// Default number of active sessions allowed per user.
pub const DEFAULT_MAX_SESSIONS_PER_USER: usize = 5;
/// Default total number of active sessions allowed globally.
pub const DEFAULT_GLOBAL_SESSION_LIMIT: usize = 10_000;
/// Minimum accepted absolute session lifetime, in milliseconds.
pub const MIN_SESSION_TTL_MS: i64 = 60 * 1000;
/// Maximum accepted absolute session lifetime, in milliseconds.
pub const MAX_SESSION_TTL_MS: i64 = 7 * 24 * 60 * 60 * 1000;
/// Minimum accepted idle session lifetime, in milliseconds.
pub const MIN_IDLE_TTL_MS: i64 = 60 * 1000;
/// Maximum accepted idle session lifetime, in milliseconds.
pub const MAX_IDLE_TTL_MS: i64 = 24 * 60 * 60 * 1000;
/// Minimum accepted per-user session limit.
pub const MIN_MAX_SESSIONS_PER_USER: usize = 1;
/// Hard upper bound for per-user session limit.
pub const HARD_MAX_SESSIONS_PER_USER: usize = 1_000;
/// Minimum accepted global session limit.
pub const MIN_GLOBAL_SESSION_LIMIT: usize = 1;
/// Hard upper bound for global session limit.
pub const HARD_GLOBAL_SESSION_LIMIT: usize = 100_000;
/// Minimum Argon2 verification concurrency.
pub const MIN_ARGON2_CONCURRENCY: usize = 1;
/// Hard upper bound for Argon2 verification concurrency.
pub const HARD_ARGON2_CONCURRENCY: usize = 256;
const TOTP_PERIOD_SECS: i64 = 30;
const KEY_CHALLENGE_TTL_MS: i64 = 60_000;

/// Default Argon2 verification concurrency based on available CPU parallelism.
pub fn default_argon2_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(MIN_ARGON2_CONCURRENCY)
}

type HmacSha1 = Hmac<Sha1>;

/// Optional root-account material supplied at daemon bootstrap.
#[derive(Clone, Debug, Default)]
pub struct RootProvisioning {
    /// Optional precomputed Argon2 PHC string for the root password.
    pub password_hash: Option<String>,
    /// Optional public-key descriptors for key login.
    pub pubkeys: Vec<String>,
}

/// Console authentication tuning.
#[derive(Clone, Debug)]
pub struct ConsoleAuthConfig {
    /// Absolute session TTL in milliseconds.
    pub session_ttl_ms: i64,
    /// Idle session TTL in milliseconds.
    pub idle_ttl_ms: i64,
    /// Maximum active sessions per user.
    pub max_sessions_per_user: usize,
    /// Maximum active sessions across all users.
    pub global_session_limit: usize,
    /// Maximum concurrent Argon2 verifications.
    pub argon2_concurrency: usize,
}

impl Default for ConsoleAuthConfig {
    fn default() -> Self {
        Self {
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
            idle_ttl_ms: DEFAULT_IDLE_TTL_MS,
            max_sessions_per_user: DEFAULT_MAX_SESSIONS_PER_USER,
            global_session_limit: DEFAULT_GLOBAL_SESSION_LIMIT,
            argon2_concurrency: default_argon2_concurrency(),
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
            session_ttl_ms,
            idle_ttl_ms,
            max_sessions_per_user: self
                .max_sessions_per_user
                .clamp(MIN_MAX_SESSIONS_PER_USER, HARD_MAX_SESSIONS_PER_USER),
            global_session_limit: self
                .global_session_limit
                .clamp(MIN_GLOBAL_SESSION_LIMIT, HARD_GLOBAL_SESSION_LIMIT),
            argon2_concurrency: self
                .argon2_concurrency
                .clamp(MIN_ARGON2_CONCURRENCY, HARD_ARGON2_CONCURRENCY),
        }
    }
}

/// Result of root-account bootstrap.
#[derive(Debug, Clone, Eq, PartialEq)]
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
    /// Root was created from preseeded password or key material.
    CreatedPreseeded {
        /// Created username.
        username: String,
    },
}

/// Return whether bootstrap would need to generate a random root password.
pub async fn root_random_password_needed(
    boot: &Bootstrap,
    provisioning: &RootProvisioning,
) -> Result<bool, AuthError> {
    if provisioning.password_hash.is_some() || !provisioning.pubkeys.is_empty() {
        return Ok(false);
    }
    let users = boot
        .kernel
        .state
        .read_prefix(&Path::parse(USERS_PREFIX)?)
        .await?;
    Ok(users.is_empty())
}

/// Password login request.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// Console username.
    pub username: String,
    /// Plaintext password, consumed only by the auth boundary.
    pub password: String,
    /// Optional TOTP code when the user has TOTP enabled.
    #[serde(default)]
    pub totp_code: Option<String>,
}

/// Login or step-up response carrying a new bearer token.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// Session id.
    pub sid: String,
    /// Bearer token in `sid.secret` form.
    pub token: String,
    /// Absolute expiry timestamp in millis since epoch.
    pub expires_at: i64,
    /// Idle expiry timestamp in millis since epoch.
    pub idle_expires_at: i64,
    /// MFA level attached to the session.
    pub mfa_level: u8,
}

/// Request to upgrade an existing session's MFA level.
#[derive(Debug, Deserialize)]
pub struct StepUpRequest {
    /// Password proof for accounts without TOTP.
    #[serde(default)]
    pub password: Option<String>,
    /// TOTP code for accounts with TOTP enabled.
    #[serde(default)]
    pub totp_code: Option<String>,
}

/// Request to start public-key login.
#[derive(Debug, Deserialize)]
pub struct KeyChallengeRequest {
    /// Console username.
    pub username: String,
    /// Client origin bound into the signed transcript.
    pub origin: String,
}

/// One public-key login challenge.
#[derive(Debug, Serialize)]
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
#[derive(Debug, Deserialize)]
pub struct KeyLoginRequest {
    /// Console username.
    pub username: String,
    /// Challenge id returned by [`KeyChallengeResponse`].
    pub challenge_id: String,
    /// Signature over the challenge transcript.
    pub signature: String,
    /// Client origin; must match the challenge.
    pub origin: String,
    /// Optional public-key descriptor selecting a registered key.
    #[serde(default)]
    pub key: Option<String>,
}

/// Authenticated console principal used by management actions.
#[derive(Clone, Debug)]
pub(crate) struct ConsolePrincipal {
    /// Console username.
    pub(crate) username: String,
    /// Xolotl identity path associated with the user.
    pub(crate) identity_path: String,
    /// Effective grants after roles and direct grants are combined.
    pub(crate) grants: CapSet,
    /// Session MFA level.
    pub(crate) mfa_level: u8,
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
    /// Issue timestamp in millis since epoch.
    pub(crate) issued_at: i64,
    /// Absolute expiry timestamp in millis since epoch.
    pub(crate) expires_at: i64,
    /// Idle expiry timestamp in millis since epoch.
    pub(crate) idle_expires_at: i64,
    /// Session MFA level.
    pub(crate) mfa_level: u8,
    /// Last-seen timestamp in millis since epoch.
    pub(crate) last_seen: i64,
    /// Source address recorded when the session was issued.
    pub(crate) source_addr: String,
}

/// Authentication and authorization errors returned by the console boundary.
#[derive(Debug, Error)]
pub enum AuthError {
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
    /// Key-login challenge is missing, expired, already used, or mismatched.
    #[error("key challenge is missing, expired, or already used")]
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
    /// State backend error.
    #[error("state error: {0}")]
    State(String),
    /// Cryptographic parsing, hashing, or verification error.
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<StateError> for AuthError {
    fn from(e: StateError) -> Self {
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

#[derive(Clone, Copy, Debug, Default)]
struct FailureBucket {
    failures: u32,
    next_allowed_at: i64,
    window_started_at: i64,
}

/// Console authentication service.
pub(crate) struct ConsoleAuth {
    config: ConsoleAuthConfig,
    decoy_phc: String,
    argon2_slots: Semaphore,
    rate: Mutex<RateState>,
}

impl ConsoleAuth {
    /// Create an auth service with bounded tuning and a decoy password hash.
    pub(crate) fn new(config: ConsoleAuthConfig) -> Result<Self, AuthError> {
        let config = config.bounded();
        let decoy_phc = hash_password_with_salt("invalid-password", &[0x42; 16])?;
        Ok(Self {
            argon2_slots: Semaphore::new(config.argon2_concurrency),
            config,
            decoy_phc,
            rate: Mutex::new(RateState::default()),
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
    ) -> Result<LoginResponse, AuthError> {
        let username = req.username.trim().to_string();
        let result = self
            .login_inner(&boot.kernel.state, req, source_addr.clone())
            .await;
        match &result {
            Ok(response) => record_auth_audit(
                boot,
                "console_login",
                Some(&username),
                Some(&source_addr),
                "ok",
                Some(response.mfa_level),
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
    ) -> Result<LoginResponse, AuthError> {
        let username = req.username.trim().to_string();
        validate_username(&username)?;
        self.check_rate_limits(&username, &source_addr, now_millis())?;

        let user = read_user(state, &username).await?;
        let password_ref = user.as_ref().and_then(|u| u.password_hash_ref());
        let phc = match password_ref {
            Some(path) => read_string(state, &path)
                .await?
                .unwrap_or_else(|| self.decoy_phc.clone()),
            None => self.decoy_phc.clone(),
        };

        let _permit = self
            .argon2_slots
            .acquire()
            .await
            .map_err(|_error| AuthError::Crypto("argon2 semaphore closed".into()))?;
        let password_ok = verify_password(&phc, &req.password);
        drop(_permit);

        let Some(mut user) = user else {
            self.record_login_failure(&username, &source_addr, now_millis());
            return Err(AuthError::InvalidCredentials);
        };
        if !matches!(user.status.as_str(), "active") {
            self.record_login_failure(&username, &source_addr, now_millis());
            return Err(AuthError::AccountUnavailable);
        }
        if !password_ok {
            self.record_login_failure(&username, &source_addr, now_millis());
            return Err(AuthError::InvalidCredentials);
        }

        let mut mfa_level = 1u8;
        if user.totp_enabled {
            let Some(code) = req.totp_code.as_deref() else {
                self.record_login_failure(&username, &source_addr, now_millis());
                return Err(AuthError::InvalidCredentials);
            };
            let seed_ref = user
                .totp_seed_ref
                .clone()
                .ok_or(AuthError::InvalidCredentials)?;
            let seed = read_string(state, &seed_ref)
                .await?
                .ok_or(AuthError::InvalidCredentials)?;
            let step = verify_totp(&seed, code, user.totp_last_step, now_millis())?
                .ok_or(AuthError::InvalidCredentials)?;
            user.totp_last_step = Some(step);
            write_user(state, &user).await?;
            mfa_level = 2;
        }

        self.clear_login_failures(&username, &source_addr, now_millis());
        self.issue_session(state, &user, source_addr, mfa_level)
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
        let username = req.username.trim().to_string();
        let result = self.begin_key_login_inner(&boot.kernel.state, req).await;
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
    ) -> Result<KeyChallengeResponse, AuthError> {
        let username = req.username.trim().to_string();
        validate_username(&username)?;
        let origin = validate_origin(req.origin.trim())?;
        let challenge_id = random_token(18)?;
        let nonce = random_token(32)?;
        let now = now_millis();
        sweep_expired_key_challenges(state, now).await?;
        let expires_at = now.saturating_add(KEY_CHALLENGE_TTL_MS);
        let challenge = KeyChallengeRecord {
            challenge_id: challenge_id.clone(),
            username: username.clone(),
            nonce: nonce.clone(),
            origin: origin.clone(),
            issued_at: now,
            expires_at,
        };
        write_key_challenge(state, &challenge).await?;
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
    ) -> Result<LoginResponse, AuthError> {
        let username = req.username.trim().to_string();
        let result = self
            .finish_key_login_inner(&boot.kernel.state, req, source_addr.clone())
            .await;
        match &result {
            Ok(response) => record_auth_audit(
                boot,
                "console_login",
                Some(&username),
                Some(&source_addr),
                "ok",
                Some(response.mfa_level),
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
    ) -> Result<LoginResponse, AuthError> {
        let username = req.username.trim().to_string();
        validate_username(&username)?;
        validate_session_id(&req.challenge_id).map_err(|_error| AuthError::InvalidChallenge)?;
        let origin = validate_origin(req.origin.trim())?;

        let Some(challenge) = read_key_challenge(state, &req.challenge_id).await? else {
            return Err(AuthError::InvalidChallenge);
        };
        if challenge.expires_at <= now_millis()
            || challenge.username != username
            || challenge.origin != origin
        {
            revoke_key_challenge(state, &req.challenge_id).await?;
            return Err(AuthError::InvalidChallenge);
        }

        // Single-use challenge: once a client attempts verification, the nonce
        // cannot be replayed even if the signature is wrong.
        revoke_key_challenge(state, &req.challenge_id).await?;

        let user = read_user(state, &username)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        if !matches!(user.status.as_str(), "active") {
            return Err(AuthError::AccountUnavailable);
        }
        let transcript = key_login_transcript(
            &username,
            &challenge.challenge_id,
            &challenge.nonce,
            &origin,
        );
        if !verify_key_login(
            &user.pubkeys,
            req.key.as_deref(),
            &req.signature,
            &transcript,
        )? {
            return Err(AuthError::InvalidCredentials);
        }

        self.issue_session(state, &user, source_addr, 1).await
    }

    /// Upgrade an existing bearer session to MFA level 2.
    ///
    /// Uses TOTP when enabled for the user, otherwise rechecks the password.
    pub(crate) async fn step_up(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        req: StepUpRequest,
        source_addr: String,
    ) -> Result<LoginResponse, AuthError> {
        let audit_username = match self
            .authenticate_token_inner(&boot.kernel.state, bearer)
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
            .step_up_inner(&boot.kernel.state, bearer, req, source_addr.clone())
            .await;
        match &result {
            Ok(response) => record_auth_audit(
                boot,
                "console_credential",
                audit_username.as_deref(),
                Some(&source_addr),
                "step_up",
                Some(response.mfa_level),
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
    ) -> Result<LoginResponse, AuthError> {
        let principal = self.authenticate_token_inner(state, bearer).await?;
        let mut user = read_user(state, &principal.username)
            .await?
            .ok_or(AuthError::InvalidSession)?;
        if !matches!(user.status.as_str(), "active") {
            return Err(AuthError::AccountUnavailable);
        }

        if user.totp_enabled {
            let code = req
                .totp_code
                .as_deref()
                .ok_or(AuthError::InvalidCredentials)?;
            let seed_ref = user
                .totp_seed_ref
                .clone()
                .ok_or(AuthError::InvalidCredentials)?;
            let seed = read_string(state, &seed_ref)
                .await?
                .ok_or(AuthError::InvalidCredentials)?;
            let step = verify_totp(&seed, code, user.totp_last_step, now_millis())?
                .ok_or(AuthError::InvalidCredentials)?;
            user.totp_last_step = Some(step);
            write_user(state, &user).await?;
        } else {
            let password = req
                .password
                .as_deref()
                .ok_or(AuthError::InvalidCredentials)?;
            self.check_rate_limits(&user.username, &source_addr, now_millis())?;
            let phc = match user.password_hash_ref() {
                Some(path) => read_string(state, &path)
                    .await?
                    .unwrap_or_else(|| self.decoy_phc.clone()),
                None => self.decoy_phc.clone(),
            };
            let _permit = self
                .argon2_slots
                .acquire()
                .await
                .map_err(|_error| AuthError::Crypto("argon2 semaphore closed".into()))?;
            let ok = verify_password(&phc, password);
            drop(_permit);
            if !ok {
                self.record_login_failure(&user.username, &source_addr, now_millis());
                return Err(AuthError::InvalidCredentials);
            }
            self.clear_login_failures(&user.username, &source_addr, now_millis());
        }

        self.issue_session(state, &user, source_addr, 2).await
    }

    /// Authenticate a bearer token in `sid.secret` form.
    pub(crate) async fn authenticate_token(
        &self,
        boot: &Bootstrap,
        bearer: &str,
    ) -> Result<ConsolePrincipal, AuthError> {
        self.authenticate_token_inner(&boot.kernel.state, bearer)
            .await
    }

    /// Authenticate by session id without a bearer secret.
    ///
    /// This is intended for trusted management paths that already validated
    /// access to the session id.
    pub(crate) async fn authenticate_sid(
        &self,
        boot: &Bootstrap,
        sid: &str,
    ) -> Result<ConsolePrincipal, AuthError> {
        validate_session_id(sid)?;
        let state = &boot.kernel.state;
        let session_path = session_path(sid)?;
        let Some(mut session) = read_session(state, &session_path).await? else {
            return Err(AuthError::InvalidSession);
        };
        let now = now_millis();
        if session.expires_at <= now || session.idle_expires_at <= now {
            revoke_session(state, sid).await?;
            return Err(AuthError::InvalidSession);
        }

        let user = read_user(state, &session.username)
            .await?
            .ok_or(AuthError::InvalidSession)?;
        if !matches!(user.status.as_str(), "active") {
            return Err(AuthError::AccountUnavailable);
        }

        session.last_seen = now;
        session.idle_expires_at = now.saturating_add(self.config.idle_ttl_ms);
        write_session(state, &session_path, &session).await?;

        let grants = effective_grants(state, &user).await?;
        Ok(ConsolePrincipal {
            username: user.username,
            identity_path: user.identity_path,
            grants,
            mfa_level: session.mfa_level,
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
        let Some(mut session) = read_session(state, &session_path).await? else {
            return Err(AuthError::InvalidSession);
        };
        let now = now_millis();
        if session.expires_at <= now || session.idle_expires_at <= now {
            revoke_session(state, sid).await?;
            return Err(AuthError::InvalidSession);
        }
        let token_hash = token_hash(token);
        let expected_hash = read_string(state, &session_token_path(sid)?)
            .await?
            .ok_or(AuthError::InvalidSession)?;
        if expected_hash
            .as_bytes()
            .ct_eq(token_hash.as_bytes())
            .unwrap_u8()
            != 1
        {
            return Err(AuthError::InvalidSession);
        }

        let user = read_user(state, &session.username)
            .await?
            .ok_or(AuthError::InvalidSession)?;
        if !matches!(user.status.as_str(), "active") {
            return Err(AuthError::AccountUnavailable);
        }

        session.last_seen = now;
        session.idle_expires_at = now.saturating_add(self.config.idle_ttl_ms);
        write_session(state, &session_path, &session).await?;

        let grants = effective_grants(state, &user).await?;
        Ok(ConsolePrincipal {
            username: user.username,
            identity_path: user.identity_path,
            grants,
            mfa_level: session.mfa_level,
        })
    }

    /// Revoke one session id and record an optional source address.
    pub(crate) async fn logout_sid_from_source(
        &self,
        boot: &Bootstrap,
        sid: &str,
        source_addr: Option<&str>,
    ) -> Result<(), AuthError> {
        validate_session_id(sid)?;
        let session = read_session(&boot.kernel.state, &session_path(sid)?).await?;
        let username = session.as_ref().map(|s| s.username.as_str());
        let mfa_level = session.as_ref().map(|s| s.mfa_level);
        let result = revoke_session(&boot.kernel.state, sid).await;
        match &result {
            Ok(()) => {
                record_auth_audit(
                    boot,
                    "console_credential",
                    username,
                    source_addr,
                    "logout",
                    mfa_level,
                )?;
            }
            Err(err) => {
                record_auth_audit(
                    boot,
                    "console_credential",
                    username,
                    source_addr,
                    audit_outcome(err),
                    mfa_level,
                )?;
            }
        }
        result
    }

    /// List all visible console sessions for `principal`.
    pub(crate) async fn list_sessions(
        &self,
        boot: &Bootstrap,
        principal: &ConsolePrincipal,
    ) -> Result<Vec<SessionSummary>, AuthError> {
        let sessions_root = Path::parse(SESSIONS_PREFIX)?;
        authorize_path(&boot.kernel.state, principal, "read", &sessions_root, None).await?;
        let now = now_millis();
        sweep_expired_sessions(&boot.kernel.state, now).await?;
        let mut sessions = boot
            .kernel
            .state
            .read_prefix(&sessions_root)
            .await?
            .into_iter()
            .map(|(path, value)| {
                let sid = path_leaf(&path, "console session id")?;
                let session = SessionRecord::from_value(&sid, &value)?;
                Ok(SessionSummary::from(session))
            })
            .collect::<Result<Vec<_>, AuthError>>()?;
        sessions.sort_by_key(|s| (s.username.clone(), s.issued_at));
        Ok(sessions)
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
        let path = Path::parse(&session_path(sid)?)?;
        authorize_path(&boot.kernel.state, principal, "write", &path, None).await?;
        let result = revoke_session(&boot.kernel.state, sid).await;
        match &result {
            Ok(()) => record_auth_audit(
                boot,
                "console_credential",
                Some(&principal.username),
                source_addr,
                "session_revoke",
                Some(principal.mfa_level),
            )?,
            Err(err) => record_auth_audit(
                boot,
                "console_credential",
                Some(&principal.username),
                source_addr,
                audit_outcome(err),
                Some(principal.mfa_level),
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
        let user_path = Path::parse(&user_path(username)?)?;
        authorize_path(&boot.kernel.state, principal, "write", &user_path, None).await?;
        let sessions = boot
            .kernel
            .state
            .read_prefix(&Path::parse(SESSIONS_PREFIX)?)
            .await?;
        let mut revoked = 0usize;
        for (path, value) in sessions {
            let sid = path_leaf(&path, "console session id")?;
            let session = SessionRecord::from_value(&sid, &value)?;
            if session.username == username {
                revoke_session(&boot.kernel.state, &sid).await?;
                revoked += 1;
            }
        }
        record_auth_audit(
            boot,
            "console_credential",
            Some(&principal.username),
            source_addr,
            "user_sessions_revoke",
            Some(principal.mfa_level),
        )?;
        Ok(revoked)
    }

    async fn issue_session(
        &self,
        state: &Backend,
        user: &UserRecord,
        source_addr: String,
        mfa_level: u8,
    ) -> Result<LoginResponse, AuthError> {
        sweep_expired_sessions(state, now_millis()).await?;
        enforce_session_limits(
            state,
            &user.username,
            self.config.max_sessions_per_user,
            self.config.global_session_limit,
        )
        .await?;

        let sid = random_token(18)?;
        let token_secret = random_token(32)?;
        let token = format!("{sid}.{token_secret}");
        let now = now_millis();
        let expires_at = now.saturating_add(self.config.session_ttl_ms);
        let idle_expires_at = now.saturating_add(self.config.idle_ttl_ms);
        let session = SessionRecord {
            sid: sid.clone(),
            username: user.username.clone(),
            identity_path: user.identity_path.clone(),
            issued_at: now,
            expires_at,
            idle_expires_at,
            mfa_level,
            last_seen: now,
            source_addr,
        };
        write_session(state, &session_path(&sid)?, &session).await?;
        write_string(state, &session_token_path(&sid)?, token_hash(&token_secret)).await?;

        Ok(LoginResponse {
            sid,
            token,
            expires_at,
            idle_expires_at,
            mfa_level,
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
        let user = rate.by_user.entry(username.to_string()).or_default();
        prune_bucket(user, now);
        if let Some(retry) = retry_after(*user, now) {
            return Err(AuthError::RateLimited {
                retry_after_ms: retry,
            });
        }
        let source = rate.by_source.entry(source_addr.to_string()).or_default();
        prune_bucket(source, now);
        if let Some(retry) = retry_after(*source, now) {
            return Err(AuthError::RateLimited {
                retry_after_ms: retry,
            });
        }
        Ok(())
    }

    fn record_login_failure(&self, username: &str, source_addr: &str, now: i64) {
        let mut rate = self.rate();
        mark_failure(rate.by_user.entry(username.to_string()).or_default(), now);
        mark_failure(
            rate.by_source.entry(source_addr.to_string()).or_default(),
            now,
        );
        mark_failure(&mut rate.global, now);
    }

    fn clear_login_failures(&self, username: &str, source_addr: &str, now: i64) {
        let mut rate = self.rate();
        rate.by_user.insert(
            username.to_string(),
            FailureBucket {
                window_started_at: now,
                ..Default::default()
            },
        );
        rate.by_source.insert(
            source_addr.to_string(),
            FailureBucket {
                window_started_at: now,
                ..Default::default()
            },
        );
    }

    fn rate(&self) -> MutexGuard<'_, RateState> {
        match self.rate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Create the root account if no console users exist.
///
/// A random password is generated only when no password hash or public keys are
/// preseeded. Successful creation records a bootstrap audit fact.
pub async fn bootstrap_root_account(
    boot: &Bootstrap,
    provisioning: RootProvisioning,
) -> Result<BootstrapOutcome, AuthError> {
    let outcome = bootstrap_root_account_inner(&boot.kernel.state, provisioning).await?;
    if !matches!(outcome, BootstrapOutcome::AlreadyPresent) {
        record_auth_audit(
            boot,
            "console_bootstrap",
            Some(ROOT_USERNAME),
            None,
            "ok",
            None,
        )?;
    }
    Ok(outcome)
}

async fn bootstrap_root_account_inner(
    state: &Backend,
    provisioning: RootProvisioning,
) -> Result<BootstrapOutcome, AuthError> {
    if let Some(phc) = &provisioning.password_hash {
        PasswordHash::new(phc)
            .map_err(|_error| AuthError::Crypto("invalid root password PHC string".into()))?;
    }
    let supported_key = has_valid_ed25519_pubkey(&provisioning.pubkeys)?;
    if provisioning.password_hash.is_none() && !provisioning.pubkeys.is_empty() && !supported_key {
        return Err(AuthError::Crypto(
            "root pubkey provisioning requires at least one supported ed25519 key".into(),
        ));
    }

    let users = state.read_prefix(&Path::parse(USERS_PREFIX)?).await?;
    if !users.is_empty() {
        return Ok(BootstrapOutcome::AlreadyPresent);
    }

    let now = now_millis();
    let root_grants = root_grants();
    let (password_hash_ref, outcome) = if let Some(phc) = provisioning.password_hash {
        let hash_ref = password_hash_path(ROOT_USERNAME)?;
        write_string(state, &hash_ref, phc).await?;
        (
            Some(hash_ref),
            BootstrapOutcome::CreatedPreseeded {
                username: ROOT_USERNAME.into(),
            },
        )
    } else if provisioning.pubkeys.is_empty() {
        let password = random_token(36)?;
        let phc = hash_password(&password)?;
        let hash_ref = password_hash_path(ROOT_USERNAME)?;
        write_string(state, &hash_ref, phc).await?;
        (
            Some(hash_ref),
            BootstrapOutcome::CreatedRandomPassword {
                username: ROOT_USERNAME.into(),
                password,
            },
        )
    } else {
        (
            None,
            BootstrapOutcome::CreatedPreseeded {
                username: ROOT_USERNAME.into(),
            },
        )
    };

    let user = UserRecord {
        username: ROOT_USERNAME.into(),
        identity_path: "identity://console/root".into(),
        status: "active".into(),
        password_hash_ref,
        totp_enabled: false,
        totp_seed_ref: None,
        totp_last_step: None,
        pubkeys: provisioning.pubkeys,
        roles: Vec::new(),
        grants: root_grants.clone(),
        authority_ceiling: root_grants,
        created_by: "bootstrap".into(),
        created_at: now,
        password_changed_at: now,
    };
    write_user(state, &user).await?;
    Ok(outcome)
}

/// Extract a `Bearer ...` token from HTTP headers.
pub(crate) fn bearer_from_headers(headers: &axum::http::HeaderMap) -> Result<&str, AuthError> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or(AuthError::MissingBearer)?;
    let raw = header.to_str().map_err(|_error| AuthError::MissingBearer)?;
    raw.strip_prefix("Bearer ").ok_or(AuthError::MissingBearer)
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

/// Authorize a principal for a state path and optional replacement value.
///
/// Console management paths require both direct path authority and the console
/// management effect authority; user/role writes are additionally checked so a
/// non-root admin cannot grant authority above their ceiling.
pub(crate) async fn authorize_path(
    state: &Backend,
    principal: &ConsolePrincipal,
    verb: &str,
    path: &Path,
    new_value: Option<&Value>,
) -> Result<(), AuthError> {
    if !principal.grants.contains(verb, path) {
        return Err(AuthError::PermissionDenied);
    }
    let path_s = path.to_string();
    if path_s.starts_with("state://kernel/console/") {
        let user_mgmt = Path::parse("effect://kernel/console/users")?;
        if !principal.grants.contains("perform", &user_mgmt) {
            return Err(AuthError::PermissionDenied);
        }
    }
    if verb == "write" && path_s.starts_with("state://kernel/console/users/") {
        authorize_user_target(state, principal, path, new_value).await?;
    }
    if verb == "write" && path_s.starts_with("state://kernel/console/roles/") {
        authorize_role_target(state, principal, path, new_value).await?;
    }
    Ok(())
}

async fn authorize_user_target(
    state: &Backend,
    principal: &ConsolePrincipal,
    path: &Path,
    new_value: Option<&Value>,
) -> Result<(), AuthError> {
    let Some(username) = path.segments().last().map(|s| s.to_string()) else {
        return Err(AuthError::PermissionDenied);
    };
    validate_username(&username)?;

    if username == ROOT_USERNAME && principal.username != ROOT_USERNAME {
        return Err(AuthError::PermissionDenied);
    }

    if let Some(existing) = read_user(state, &username).await? {
        let target = effective_grants(state, &existing).await?;
        if !capset_covers(&principal.grants, &target) {
            return Err(AuthError::PermissionDenied);
        }
    }
    if let Some(value) = new_value {
        let candidate = UserRecord::from_value(&username, value)?;
        let candidate_ceiling = capset_from_strings(&candidate.authority_ceiling)?;
        let candidate_effective = effective_grants(state, &candidate).await?;
        if !capset_covers(&principal.grants, &candidate_ceiling)
            || !capset_covers(&principal.grants, &candidate_effective)
        {
            return Err(AuthError::PermissionDenied);
        }
        if username == ROOT_USERNAME {
            enforce_root_invariants(&candidate, &candidate_effective)?;
        }
    }
    Ok(())
}

async fn authorize_role_target(
    state: &Backend,
    principal: &ConsolePrincipal,
    path: &Path,
    new_value: Option<&Value>,
) -> Result<(), AuthError> {
    let Some(role) = path.segments().last().map(|s| s.to_string()) else {
        return Err(AuthError::PermissionDenied);
    };
    validate_username(&role)?;

    let role_path = role_path(&role)?;
    if let Some(existing) = state.read(&Path::parse(&role_path)?).await? {
        let existing_grants = capset_from_strings(&role_grants(&existing)?)?;
        if !capset_covers(&principal.grants, &existing_grants) {
            return Err(AuthError::PermissionDenied);
        }
        if role_frozen(&existing)? && principal.username != ROOT_USERNAME {
            return Err(AuthError::PermissionDenied);
        }
    }

    if let Some(value) = new_value {
        let candidate_grants = capset_from_strings(&role_grants(value)?)?;
        if !capset_covers(&principal.grants, &candidate_grants) {
            return Err(AuthError::PermissionDenied);
        }
        if role_frozen(value)? && principal.username != ROOT_USERNAME {
            return Err(AuthError::PermissionDenied);
        }
    }
    Ok(())
}

fn enforce_root_invariants(user: &UserRecord, effective: &CapSet) -> Result<(), AuthError> {
    if !matches!(user.status.as_str(), "active") {
        return Err(AuthError::PermissionDenied);
    }
    if user.password_hash_ref.is_none() && !has_valid_ed25519_pubkey(&user.pubkeys)? {
        return Err(AuthError::PermissionDenied);
    }
    let user_mgmt = Path::parse("effect://kernel/console/users")?;
    let root_user = Path::parse("state://kernel/console/users/root")?;
    if !effective.contains("perform", &user_mgmt) || !effective.contains("write", &root_user) {
        return Err(AuthError::PermissionDenied);
    }
    Ok(())
}

fn capset_covers(parent: &CapSet, child: &CapSet) -> bool {
    child.iter().all(|c| parent.iter().any(|p| p.covers_cap(c)))
}

async fn effective_grants(state: &Backend, user: &UserRecord) -> Result<CapSet, AuthError> {
    let mut grants = user.grants.clone();
    for role in &user.roles {
        let role_path = role_path(role)?;
        if let Some(v) = state.read(&Path::parse(&role_path)?).await? {
            grants.extend(role_grants(&v)?);
        }
    }
    let requested = capset_from_strings(&grants)?;
    let ceiling = capset_from_strings(&user.authority_ceiling)?;
    Ok(ceiling.intersect(&requested))
}

fn capset_from_strings(items: &[String]) -> Result<CapSet, AuthError> {
    let caps = items
        .iter()
        .map(|s| Capability::parse(s).map_err(|e| AuthError::State(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CapSet(caps))
}

fn role_grants(value: &Value) -> Result<Vec<String>, AuthError> {
    let map = value
        .as_map()
        .ok_or_else(|| AuthError::State("console role must be a map".into()))?;
    optional_string_list_field(map, "grants", "console role")
}

fn role_frozen(value: &Value) -> Result<bool, AuthError> {
    let map = value
        .as_map()
        .ok_or_else(|| AuthError::State("console role must be a map".into()))?;
    optional_bool_field(map, "frozen", "console role")
}

#[derive(Clone, Debug)]
struct UserRecord {
    username: String,
    identity_path: String,
    status: String,
    password_hash_ref: Option<String>,
    totp_enabled: bool,
    totp_seed_ref: Option<String>,
    totp_last_step: Option<i64>,
    pubkeys: Vec<String>,
    roles: Vec<String>,
    grants: Vec<String>,
    authority_ceiling: Vec<String>,
    created_by: String,
    created_at: i64,
    password_changed_at: i64,
}

impl UserRecord {
    fn password_hash_ref(&self) -> Option<String> {
        self.password_hash_ref.clone()
    }

    fn from_value(username: &str, value: &Value) -> Result<Self, AuthError> {
        let m = value.as_map().ok_or(AuthError::InvalidCredentials)?;
        let identity_path = required_str_field(m, "identity_path", "console user")?;
        validate_console_identity_path(&identity_path)?;
        let status = required_str_field(m, "status", "console user")?;
        if !matches!(status.as_str(), "active" | "disabled" | "locked") {
            return Err(AuthError::State("console user.status is invalid".into()));
        }
        let authn = required_map_field(m, "authn", "console user")?;
        let password = required_map_field(authn, "password", "console user.authn")?;
        let totp = required_map_field(authn, "totp", "console user.authn")?;
        let created_at = required_nonnegative_int_field(m, "created_at", "console user")?;
        let password_changed_at =
            required_nonnegative_int_field(m, "password_changed_at", "console user")?;
        Ok(Self {
            username: username.to_string(),
            identity_path,
            status,
            password_hash_ref: optional_string_field(
                password,
                "hash_ref",
                "console user.password",
            )?,
            totp_enabled: optional_bool_field(totp, "enabled", "console user.totp")?,
            totp_seed_ref: optional_string_field(totp, "seed_ref", "console user.totp")?,
            totp_last_step: optional_nonnegative_int_field(totp, "last_step", "console user.totp")?,
            pubkeys: required_string_list_field(authn, "pubkeys", "console user.authn")?,
            roles: required_string_list_field(m, "roles", "console user")?,
            grants: required_string_list_field(m, "grants", "console user")?,
            authority_ceiling: required_string_list_field(m, "authority_ceiling", "console user")?,
            created_by: required_str_field(m, "created_by", "console user")?,
            created_at,
            password_changed_at,
        })
    }

    fn to_value(&self) -> Value {
        let mut authn = BTreeMap::new();
        let mut password = BTreeMap::new();
        if let Some(hash_ref) = &self.password_hash_ref {
            password.insert("hash_ref".into(), Value::Str(hash_ref.clone()));
        }
        authn.insert("password".into(), Value::Map(password));
        let mut totp = BTreeMap::new();
        totp.insert("enabled".into(), Value::Bool(self.totp_enabled));
        if let Some(seed_ref) = &self.totp_seed_ref {
            totp.insert("seed_ref".into(), Value::Str(seed_ref.clone()));
        }
        if let Some(step) = self.totp_last_step {
            totp.insert("last_step".into(), Value::Int(step));
        }
        authn.insert("totp".into(), Value::Map(totp));
        authn.insert("pubkeys".into(), string_values(&self.pubkeys));

        let mut m = BTreeMap::new();
        m.insert(
            "identity_path".into(),
            Value::Str(self.identity_path.clone()),
        );
        m.insert("status".into(), Value::Str(self.status.clone()));
        m.insert("authn".into(), Value::Map(authn));
        m.insert("roles".into(), string_values(&self.roles));
        m.insert("grants".into(), string_values(&self.grants));
        m.insert(
            "authority_ceiling".into(),
            string_values(&self.authority_ceiling),
        );
        m.insert("created_by".into(), Value::Str(self.created_by.clone()));
        m.insert("created_at".into(), Value::Int(self.created_at));
        m.insert(
            "password_changed_at".into(),
            Value::Int(self.password_changed_at),
        );
        Value::Map(m)
    }
}

#[derive(Clone, Debug)]
struct SessionRecord {
    sid: String,
    username: String,
    identity_path: String,
    issued_at: i64,
    expires_at: i64,
    idle_expires_at: i64,
    mfa_level: u8,
    last_seen: i64,
    source_addr: String,
}

impl SessionRecord {
    fn from_value(sid: &str, value: &Value) -> Result<Self, AuthError> {
        let m = value.as_map().ok_or(AuthError::InvalidSession)?;
        let mfa_level = optional_int_field(m, "mfa_level", "console session", 1)?;
        let mfa_level = u8::try_from(mfa_level).map_err(|_error| {
            AuthError::State("console session.mfa_level is out of range".into())
        })?;
        let username = str_field(m, "username").ok_or(AuthError::InvalidSession)?;
        validate_username(&username)?;
        let identity_path = str_field(m, "identity_path").ok_or(AuthError::InvalidSession)?;
        validate_console_identity_path(&identity_path)?;
        Ok(Self {
            sid: sid.to_string(),
            username,
            identity_path,
            issued_at: int_field(m, "issued_at").ok_or(AuthError::InvalidSession)?,
            expires_at: int_field(m, "expires_at").ok_or(AuthError::InvalidSession)?,
            idle_expires_at: int_field(m, "idle_expires_at").ok_or(AuthError::InvalidSession)?,
            mfa_level,
            last_seen: optional_int_field(m, "last_seen", "console session", 0)?,
            source_addr: optional_str_field(m, "source_addr", "console session", "")?,
        })
    }

    fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("username".into(), Value::Str(self.username.clone()));
        m.insert(
            "identity_path".into(),
            Value::Str(self.identity_path.clone()),
        );
        m.insert("issued_at".into(), Value::Int(self.issued_at));
        m.insert("expires_at".into(), Value::Int(self.expires_at));
        m.insert("idle_expires_at".into(), Value::Int(self.idle_expires_at));
        m.insert("mfa_level".into(), Value::Int(self.mfa_level as i64));
        m.insert("last_seen".into(), Value::Int(self.last_seen));
        m.insert("source_addr".into(), Value::Str(self.source_addr.clone()));
        Value::Map(m)
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
            mfa_level: s.mfa_level,
            last_seen: s.last_seen,
            source_addr: s.source_addr,
        }
    }
}

#[derive(Clone, Debug)]
struct KeyChallengeRecord {
    challenge_id: String,
    username: String,
    nonce: String,
    origin: String,
    issued_at: i64,
    expires_at: i64,
}

impl KeyChallengeRecord {
    fn from_value(challenge_id: &str, value: &Value) -> Result<Self, AuthError> {
        let m = value.as_map().ok_or(AuthError::InvalidChallenge)?;
        Ok(Self {
            challenge_id: challenge_id.to_string(),
            username: str_field(m, "username").ok_or(AuthError::InvalidChallenge)?,
            nonce: str_field(m, "nonce").ok_or(AuthError::InvalidChallenge)?,
            origin: str_field(m, "origin").ok_or(AuthError::InvalidChallenge)?,
            issued_at: int_field(m, "issued_at").ok_or(AuthError::InvalidChallenge)?,
            expires_at: int_field(m, "expires_at").ok_or(AuthError::InvalidChallenge)?,
        })
    }

    fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("username".into(), Value::Str(self.username.clone()));
        m.insert("nonce".into(), Value::Str(self.nonce.clone()));
        m.insert("origin".into(), Value::Str(self.origin.clone()));
        m.insert("issued_at".into(), Value::Int(self.issued_at));
        m.insert("expires_at".into(), Value::Int(self.expires_at));
        Value::Map(m)
    }
}

async fn read_user(state: &Backend, username: &str) -> Result<Option<UserRecord>, AuthError> {
    let path = Path::parse(&user_path(username)?)?;
    state
        .read(&path)
        .await?
        .map(|v| UserRecord::from_value(username, &v))
        .transpose()
}

async fn write_user(state: &Backend, user: &UserRecord) -> Result<(), AuthError> {
    let path = Path::parse(&user_path(&user.username)?)?;
    state.write_set(&path, user.to_value()).await?;
    Ok(())
}

async fn read_session(state: &Backend, path: &str) -> Result<Option<SessionRecord>, AuthError> {
    let sid = path.rsplit('/').next().ok_or(AuthError::InvalidSession)?;
    state
        .read(&Path::parse(path)?)
        .await?
        .map(|v| SessionRecord::from_value(sid, &v))
        .transpose()
}

async fn write_session(
    state: &Backend,
    path: &str,
    session: &SessionRecord,
) -> Result<(), AuthError> {
    state
        .write_set(&Path::parse(path)?, session.to_value())
        .await?;
    Ok(())
}

async fn read_key_challenge(
    state: &Backend,
    challenge_id: &str,
) -> Result<Option<KeyChallengeRecord>, AuthError> {
    validate_session_id(challenge_id).map_err(|_error| AuthError::InvalidChallenge)?;
    let path = key_challenge_path(challenge_id)?;
    state
        .read(&Path::parse(&path)?)
        .await?
        .map(|v| KeyChallengeRecord::from_value(challenge_id, &v))
        .transpose()
}

async fn write_key_challenge(
    state: &Backend,
    challenge: &KeyChallengeRecord,
) -> Result<(), AuthError> {
    state
        .write_set(
            &Path::parse(&key_challenge_path(&challenge.challenge_id)?)?,
            challenge.to_value(),
        )
        .await?;
    Ok(())
}

async fn revoke_key_challenge(state: &Backend, challenge_id: &str) -> Result<(), AuthError> {
    state
        .write_delete(&Path::parse(&key_challenge_path(challenge_id)?)?)
        .await?;
    Ok(())
}

async fn sweep_expired_key_challenges(state: &Backend, now: i64) -> Result<(), AuthError> {
    let challenges = state.read_prefix(&Path::parse(CHALLENGES_PREFIX)?).await?;
    for (path, value) in challenges {
        let challenge_id = path_leaf(&path, "console key challenge id")?;
        let challenge = KeyChallengeRecord::from_value(&challenge_id, &value)?;
        if challenge.expires_at <= now {
            revoke_key_challenge(state, &challenge_id).await?;
        }
    }
    Ok(())
}

async fn revoke_session(state: &Backend, sid: &str) -> Result<(), AuthError> {
    state
        .write_delete(&Path::parse(&session_path(sid)?)?)
        .await?;
    state
        .write_delete(&Path::parse(&session_token_path(sid)?)?)
        .await?;
    Ok(())
}

async fn sweep_expired_sessions(state: &Backend, now: i64) -> Result<(), AuthError> {
    let sessions = state.read_prefix(&Path::parse(SESSIONS_PREFIX)?).await?;
    for (path, value) in sessions {
        let sid = path_leaf(&path, "console session id")?;
        let session = SessionRecord::from_value(&sid, &value)?;
        if session.expires_at <= now || session.idle_expires_at <= now {
            revoke_session(state, &sid).await?;
        }
    }
    Ok(())
}

async fn enforce_session_limits(
    state: &Backend,
    username: &str,
    max_per_user: usize,
    global_limit: usize,
) -> Result<(), AuthError> {
    let mut sessions = state
        .read_prefix(&Path::parse(SESSIONS_PREFIX)?)
        .await?
        .into_iter()
        .map(|(path, value)| {
            let sid = path_leaf(&path, "console session id")?;
            SessionRecord::from_value(&sid, &value)
        })
        .collect::<Result<Vec<_>, AuthError>>()?;
    sessions.sort_by_key(|s| s.issued_at);

    let mut user_sessions: Vec<_> = sessions
        .iter()
        .filter(|s| s.username == username)
        .cloned()
        .collect();
    while user_sessions.len() >= max_per_user {
        if let Some(oldest) = user_sessions.first().cloned() {
            revoke_session(state, &oldest.sid).await?;
            user_sessions.remove(0);
        } else {
            break;
        }
    }

    while sessions.len() >= global_limit {
        if let Some(oldest) = sessions.first().cloned() {
            revoke_session(state, &oldest.sid).await?;
            sessions.remove(0);
        } else {
            break;
        }
    }
    Ok(())
}

async fn read_string(state: &Backend, path: &str) -> Result<Option<String>, AuthError> {
    Ok(state
        .read(&Path::parse(path)?)
        .await?
        .and_then(|v| v.as_str().map(str::to_string)))
}

async fn write_string(state: &Backend, path: &str, value: String) -> Result<(), AuthError> {
    state
        .write_set(&Path::parse(path)?, Value::Str(value))
        .await?;
    Ok(())
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

fn state_path_string(segments: &[&str]) -> Result<String, AuthError> {
    let mut path = Path::try_new("state")?;
    for segment in segments {
        path = path.try_push_literal(segment)?;
    }
    Ok(path.to_string())
}

fn user_path(username: &str) -> Result<String, AuthError> {
    validate_username(username)?;
    state_path_string(&["kernel", "console", "users", username])
}

fn role_path(role: &str) -> Result<String, AuthError> {
    validate_username(role)?;
    state_path_string(&["kernel", "console", "roles", role])
}

fn password_hash_path(username: &str) -> Result<String, AuthError> {
    validate_username(username)?;
    state_path_string(&["vault", "console", username, "password"])
}

fn session_path(sid: &str) -> Result<String, AuthError> {
    validate_session_id(sid)?;
    state_path_string(&["kernel", "console", "sessions", sid])
}

fn session_token_path(sid: &str) -> Result<String, AuthError> {
    validate_session_id(sid)?;
    state_path_string(&["vault", "console", "sessions", sid])
}

fn key_challenge_path(challenge_id: &str) -> Result<String, AuthError> {
    validate_session_id(challenge_id).map_err(|_error| AuthError::InvalidChallenge)?;
    state_path_string(&["kernel", "console", "challenges", challenge_id])
}

fn path_leaf(path: &Path, label: &str) -> Result<String, AuthError> {
    path.segments()
        .last()
        .map(|segment| segment.as_str())
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .ok_or_else(|| AuthError::State(format!("missing {label} in path {path}")))
}

fn hash_password(password: &str) -> Result<String, AuthError> {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| AuthError::Crypto(e.to_string()))?;
    hash_password_with_salt(password, &salt)
}

fn hash_password_with_salt(password: &str, salt: &[u8]) -> Result<String, AuthError> {
    let salt = SaltString::encode_b64(salt).map_err(|e| AuthError::Crypto(e.to_string()))?;
    let params = argon2_params()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)
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
    format!("xolotl-console-ed25519-v1\n{username}\n{challenge_id}\n{nonce}\n{origin}")
}

fn verify_key_login(
    descriptors: &[String],
    requested_key: Option<&str>,
    signature_b64: &str,
    transcript: &str,
) -> Result<bool, AuthError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .map_err(|_error| AuthError::InvalidCredentials)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_error| AuthError::InvalidCredentials)?;

    for descriptor in descriptors {
        if requested_key.is_some_and(|key| key != descriptor) {
            continue;
        }
        let key = parse_ed25519_key_descriptor(descriptor)?;
        if key.verify(transcript.as_bytes(), &signature).is_ok() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_ed25519_key_descriptor(descriptor: &str) -> Result<VerifyingKey, AuthError> {
    let Some(encoded) = descriptor.strip_prefix("ed25519:") else {
        return Err(AuthError::Crypto("unsupported key descriptor".into()));
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_error| AuthError::Crypto("invalid ed25519 key encoding".into()))?;
    let key_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_error| AuthError::Crypto("invalid ed25519 key length".into()))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_error| AuthError::Crypto("invalid ed25519 public key".into()))?;
    if key.is_weak() {
        return Err(AuthError::Crypto("weak ed25519 public key".into()));
    }
    Ok(key)
}

fn has_valid_ed25519_pubkey(pubkeys: &[String]) -> Result<bool, AuthError> {
    let mut has_key = false;
    for key in pubkeys {
        parse_ed25519_key_descriptor(key)?;
        has_key = true;
    }
    Ok(has_key)
}

fn verify_totp(
    seed_b64: &str,
    code: &str,
    last_step: Option<i64>,
    now_ms: i64,
) -> Result<Option<i64>, AuthError> {
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Ok(None);
    }
    let seed = URL_SAFE_NO_PAD
        .decode(seed_b64.as_bytes())
        .map_err(|_error| AuthError::Crypto("invalid TOTP seed encoding".into()))?;
    let current_step = (now_ms / 1000) / TOTP_PERIOD_SECS;
    for step in [current_step - 1, current_step, current_step + 1] {
        if last_step.is_some_and(|last| step <= last) {
            continue;
        }
        let expected = totp_at_step(&seed, step)?;
        if expected.as_bytes().ct_eq(code.as_bytes()).unwrap_u8() == 1 {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

fn totp_at_step(seed: &[u8], step: i64) -> Result<String, AuthError> {
    let mut mac = HmacSha1::new_from_slice(seed)
        .map_err(|_error| AuthError::Crypto("invalid TOTP seed".into()))?;
    mac.update(&(step as u64).to_be_bytes());
    let out = mac.finalize().into_bytes();
    let offset = (out[19] & 0x0f) as usize;
    let binary = (((out[offset] & 0x7f) as u32) << 24)
        | ((out[offset + 1] as u32) << 16)
        | ((out[offset + 2] as u32) << 8)
        | (out[offset + 3] as u32);
    Ok(format!("{:06}", binary % 1_000_000))
}

fn validate_session_id(sid: &str) -> Result<(), AuthError> {
    if sid
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && sid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(())
    } else {
        Err(AuthError::InvalidSession)
    }
}

fn now_millis() -> i64 {
    xolotl_kernel::now_millis()
}

fn prune_bucket(bucket: &mut FailureBucket, now: i64) {
    if bucket.window_started_at == 0 || now.saturating_sub(bucket.window_started_at) > 60_000 {
        *bucket = FailureBucket {
            window_started_at: now,
            ..Default::default()
        };
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

fn str_field(m: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    m.get(key).and_then(Value::as_str).map(str::to_string)
}

fn int_field(m: &BTreeMap<String, Value>, key: &str) -> Option<i64> {
    m.get(key).and_then(Value::as_int)
}

fn required_str_field(
    m: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<String, AuthError> {
    match m.get(key) {
        Some(Value::Str(value)) if !value.is_empty() => Ok(value.clone()),
        Some(Value::Str(_)) => Err(AuthError::State(format!("{label}.{key} must not be empty"))),
        Some(_) => Err(AuthError::State(format!("{label}.{key} must be a string"))),
        None => Err(AuthError::State(format!("{label}.{key} is required"))),
    }
}

fn required_map_field<'a>(
    m: &'a BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<&'a BTreeMap<String, Value>, AuthError> {
    match m.get(key) {
        Some(Value::Map(value)) => Ok(value),
        Some(_) => Err(AuthError::State(format!("{label}.{key} must be an object"))),
        None => Err(AuthError::State(format!("{label}.{key} is required"))),
    }
}

fn required_nonnegative_int_field(
    m: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<i64, AuthError> {
    match m.get(key) {
        Some(Value::Int(value)) if *value >= 0 => Ok(*value),
        Some(Value::Int(_)) => Err(AuthError::State(format!(
            "{label}.{key} must be non-negative"
        ))),
        Some(_) => Err(AuthError::State(format!(
            "{label}.{key} must be an integer"
        ))),
        None => Err(AuthError::State(format!("{label}.{key} is required"))),
    }
}

fn required_string_list_field(
    m: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<Vec<String>, AuthError> {
    match m.get(key) {
        Some(value) => string_list(value, &format!("{label}.{key}")),
        None => Err(AuthError::State(format!("{label}.{key} is required"))),
    }
}

fn optional_string_field(
    m: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<Option<String>, AuthError> {
    match m.get(key) {
        Some(Value::Str(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(Value::Str(_)) => Err(AuthError::State(format!("{label}.{key} must not be empty"))),
        Some(_) => Err(AuthError::State(format!("{label}.{key} must be a string"))),
        None => Ok(None),
    }
}

fn optional_nonnegative_int_field(
    m: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<Option<i64>, AuthError> {
    match m.get(key) {
        Some(Value::Int(value)) if *value >= 0 => Ok(Some(*value)),
        Some(Value::Int(_)) => Err(AuthError::State(format!(
            "{label}.{key} must be non-negative"
        ))),
        Some(_) => Err(AuthError::State(format!(
            "{label}.{key} must be an integer"
        ))),
        None => Ok(None),
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
    m: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
    default: &str,
) -> Result<String, AuthError> {
    match m.get(key) {
        Some(Value::Str(value)) => Ok(value.clone()),
        Some(_) => Err(AuthError::State(format!("{label}.{key} must be a string"))),
        None => Ok(default.to_string()),
    }
}

fn optional_int_field(
    m: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
    default: i64,
) -> Result<i64, AuthError> {
    match m.get(key) {
        Some(Value::Int(value)) => Ok(*value),
        Some(_) => Err(AuthError::State(format!(
            "{label}.{key} must be an integer"
        ))),
        None => Ok(default),
    }
}

fn optional_bool_field(
    m: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<bool, AuthError> {
    match m.get(key) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(AuthError::State(format!("{label}.{key} must be a bool"))),
        None => Ok(false),
    }
}

fn optional_string_list_field(
    m: &BTreeMap<String, Value>,
    key: &str,
    label: &str,
) -> Result<Vec<String>, AuthError> {
    match m.get(key) {
        Some(value) => string_list(value, &format!("{label}.{key}")),
        None => Ok(Vec::new()),
    }
}

fn string_list(v: &Value, label: &str) -> Result<Vec<String>, AuthError> {
    match v {
        Value::List(xs) => xs
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
    Value::List(items.iter().map(|s| Value::Str(s.clone())).collect())
}

fn record_auth_audit(
    boot: &Bootstrap,
    event: &str,
    username: Option<&str>,
    source_addr: Option<&str>,
    outcome: &str,
    mfa_level: Option<u8>,
) -> Result<(), AuthError> {
    boot.record_gateway_audit(GatewayAudit {
        event,
        username,
        source_addr,
        outcome,
        mfa_level,
        details: None,
    })
    .map_err(|e| AuthError::State(e.to_string()))
}

fn audit_outcome(err: &AuthError) -> &'static str {
    match err {
        AuthError::InvalidUsername => "invalid_username",
        AuthError::InvalidCredentials => "invalid_credentials",
        AuthError::AccountUnavailable => "account_unavailable",
        AuthError::InvalidSession => "invalid_session",
        AuthError::InvalidChallenge => "invalid_challenge",
        AuthError::MissingBearer => "missing_bearer",
        AuthError::PermissionDenied => "permission_denied",
        AuthError::RateLimited { .. } => "rate_limited",
        AuthError::State(_) => "state_error",
        AuthError::Crypto(_) => "crypto_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, bail, ensure};
    use ed25519_dalek::{Signer, SigningKey};
    use xolotl_kernel::Bootstrap;
    use xolotl_types::{Fact, OutcomeRef};

    fn auth_boot() -> Bootstrap {
        Bootstrap::in_memory()
    }

    fn test_auth() -> anyhow::Result<ConsoleAuth> {
        Ok(ConsoleAuth::new(ConsoleAuthConfig::default())?)
    }

    async fn bootstrap_root_password(boot: &Bootstrap) -> anyhow::Result<String> {
        match bootstrap_root_account(boot, RootProvisioning::default()).await? {
            BootstrapOutcome::CreatedRandomPassword { password, .. } => Ok(password),
            outcome => bail!("expected generated root password, got {outcome:?}"),
        }
    }

    fn audit_facts(boot: &Bootstrap) -> anyhow::Result<Vec<Fact>> {
        let mut facts = Vec::new();
        for pid in boot.kernel.processes.all_ids() {
            facts.extend(
                boot.kernel
                    .facts
                    .facts_of(pid)
                    .with_context(|| format!("read audit facts for process {pid:?}"))?,
            );
        }
        Ok(facts
            .into_iter()
            .filter(|fact| match &fact.outcome_ref {
                OutcomeRef::Inline(Value::Map(m)) => m.contains_key("event"),
                _ => false,
            })
            .collect())
    }

    fn audit_events(boot: &Bootstrap) -> anyhow::Result<Vec<String>> {
        Ok(audit_facts(boot)?
            .into_iter()
            .filter_map(|fact| match fact.outcome_ref {
                OutcomeRef::Inline(Value::Map(m)) => {
                    m.get("event").and_then(Value::as_str).map(str::to_string)
                }
                _ => None,
            })
            .collect())
    }

    fn audit_outcomes(boot: &Bootstrap, event: &str) -> anyhow::Result<Vec<String>> {
        Ok(audit_facts(boot)?
            .into_iter()
            .filter_map(|fact| match fact.outcome_ref {
                OutcomeRef::Inline(Value::Map(m))
                    if m.get("event").and_then(Value::as_str) == Some(event) =>
                {
                    m.get("outcome").and_then(Value::as_str).map(str::to_string)
                }
                _ => None,
            })
            .collect())
    }

    #[test]
    fn auth_config_is_bounded_by_backend() {
        let cfg = ConsoleAuthConfig {
            session_ttl_ms: i64::MAX,
            idle_ttl_ms: i64::MAX,
            max_sessions_per_user: 0,
            global_session_limit: usize::MAX,
            argon2_concurrency: 0,
        }
        .bounded();
        assert_eq!(cfg.session_ttl_ms, MAX_SESSION_TTL_MS);
        assert_eq!(cfg.idle_ttl_ms, MAX_IDLE_TTL_MS);
        assert_eq!(cfg.max_sessions_per_user, 1);
        assert_eq!(cfg.global_session_limit, HARD_GLOBAL_SESSION_LIMIT);
        assert_eq!(cfg.argon2_concurrency, MIN_ARGON2_CONCURRENCY);

        let cfg = ConsoleAuthConfig {
            session_ttl_ms: 30_000,
            idle_ttl_ms: MAX_SESSION_TTL_MS,
            max_sessions_per_user: 10,
            global_session_limit: 100,
            argon2_concurrency: 2,
        }
        .bounded();
        assert_eq!(cfg.session_ttl_ms, MIN_SESSION_TTL_MS);
        assert_eq!(cfg.idle_ttl_ms, MIN_SESSION_TTL_MS);
    }

    fn fact_contains_string(fact: &Fact, needle: &str) -> anyhow::Result<bool> {
        Ok(serde_json::to_string(fact)?.contains(needle))
    }

    fn facts_contain_string(facts: &[Fact], needle: &str) -> anyhow::Result<bool> {
        for fact in facts {
            if fact_contains_string(fact, needle)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn role_value(grants: Vec<&str>, frozen: bool) -> Value {
        let mut m = BTreeMap::new();
        m.insert(
            "grants".into(),
            Value::List(
                grants
                    .into_iter()
                    .map(|grant| Value::Str(grant.into()))
                    .collect(),
            ),
        );
        m.insert("frozen".into(), Value::Bool(frozen));
        Value::Map(m)
    }

    #[tokio::test]
    async fn random_root_password_preflight_tracks_empty_user_store() -> anyhow::Result<()> {
        let boot = auth_boot();
        ensure!(
            root_random_password_needed(&boot, &RootProvisioning::default()).await?,
            "empty user store should require a random root password"
        );
        ensure!(
            !root_random_password_needed(
                &boot,
                &RootProvisioning {
                    password_hash: None,
                    pubkeys: vec!["ssh-ed25519 unsupported".into()],
                },
            )
            .await?,
            "preseeded key material should skip random root password"
        );

        bootstrap_root_account(&boot, RootProvisioning::default()).await?;
        ensure!(
            !root_random_password_needed(&boot, &RootProvisioning::default()).await?,
            "existing root account should skip random root password"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bootstraps_root_and_logs_in() -> anyhow::Result<()> {
        let boot = auth_boot();
        let password = bootstrap_root_password(&boot).await?;
        let auth = test_auth()?;
        let login = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    totp_code: None,
                },
                "test".into(),
            )
            .await?;
        let principal = auth.authenticate_token(&boot, &login.token).await?;
        ensure!(
            principal.username == "root",
            "unexpected principal username"
        );
        ensure!(
            principal
                .grants
                .contains("write", &Path::parse("state://kernel/x")?),
            "root principal should have kernel state write access"
        );
        ensure!(
            principal
                .grants
                .contains("perform", &Path::parse("effect://external/pairing/create")?),
            "root principal should be able to create pairings"
        );
        ensure!(
            principal
                .grants
                .contains("perform", &Path::parse("effect://proc/spawn")?),
            "root principal should be able to spawn processes"
        );
        let events = audit_events(&boot)?;
        ensure!(
            events.iter().any(|event| event == "console_bootstrap"),
            "missing console bootstrap audit event"
        );
        ensure!(
            events.iter().any(|event| event == "console_login"),
            "missing console login audit event"
        );
        Ok(())
    }

    #[test]
    fn random_tokens_are_valid_path_segments() -> anyhow::Result<()> {
        for _ in 0..128 {
            let token = random_token(18)?;
            validate_session_id(&token)?;
            Path::parse(&session_path(&token)?)?;
        }
        ensure!(
            validate_session_id("-bad").is_err(),
            "leading '-' was accepted"
        );
        ensure!(
            validate_session_id("_bad").is_err(),
            "leading '_' was accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn username_validation_is_strict() {
        assert!(validate_username("alice_1").is_ok());
        assert!(validate_username("bad/name").is_err());
        assert!(validate_username(".bad").is_err());
        assert!(validate_username("\u{542b}").is_err());
    }

    #[test]
    fn malformed_user_records_do_not_default_to_active() -> anyhow::Result<()> {
        let user = UserRecord {
            username: "alice".into(),
            identity_path: "identity://console/alice".into(),
            status: "active".into(),
            password_hash_ref: None,
            totp_enabled: false,
            totp_seed_ref: None,
            totp_last_step: None,
            pubkeys: Vec::new(),
            roles: Vec::new(),
            grants: Vec::new(),
            authority_ceiling: Vec::new(),
            created_by: "test".into(),
            created_at: 1,
            password_changed_at: 1,
        };

        let mut missing_status = user.to_value();
        let Value::Map(map) = &mut missing_status else {
            bail!("user record must be a map");
        };
        map.remove("status");
        ensure!(
            UserRecord::from_value("alice", &missing_status).is_err(),
            "missing status defaulted to active"
        );

        let mut missing_identity = user.to_value();
        let Value::Map(map) = &mut missing_identity else {
            bail!("user record must be a map");
        };
        map.remove("identity_path");
        ensure!(
            UserRecord::from_value("alice", &missing_identity).is_err(),
            "missing identity_path was synthesized"
        );

        let mut bad_hash = user.to_value();
        let Value::Map(map) = &mut bad_hash else {
            bail!("user record must be a map");
        };
        let Some(Value::Map(authn)) = map.get_mut("authn") else {
            bail!("authn must be a map");
        };
        let Some(Value::Map(password)) = authn.get_mut("password") else {
            bail!("password authn must be a map");
        };
        password.insert("hash_ref".into(), Value::Int(7));
        ensure!(
            UserRecord::from_value("alice", &bad_hash).is_err(),
            "malformed password hash ref was ignored"
        );

        let mut wildcard_identity = user.to_value();
        let Value::Map(map) = &mut wildcard_identity else {
            bail!("user record must be a map");
        };
        map.insert(
            "identity_path".into(),
            Value::Str("identity://console/**".into()),
        );
        ensure!(
            UserRecord::from_value("alice", &wildcard_identity).is_err(),
            "wildcard identity_path was accepted"
        );

        let mut clustered_identity = user.to_value();
        let Value::Map(map) = &mut clustered_identity else {
            bail!("user record must be a map");
        };
        map.insert(
            "identity_path".into(),
            Value::Str("path://remote/identity/console/alice".into()),
        );
        ensure!(
            UserRecord::from_value("alice", &clustered_identity).is_err(),
            "clustered identity_path was accepted"
        );

        let mut locked = user.to_value();
        let Value::Map(map) = &mut locked else {
            bail!("user record must be a map");
        };
        map.insert("status".into(), Value::Str("locked".into()));
        let locked = UserRecord::from_value("alice", &locked)?;
        ensure!(
            locked.status == "locked",
            "locked status did not round-trip"
        );
        Ok(())
    }

    #[tokio::test]
    async fn bearer_logout_revokes_session() -> anyhow::Result<()> {
        let boot = auth_boot();
        let password = bootstrap_root_password(&boot).await?;
        let auth = test_auth()?;
        let login = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    totp_code: None,
                },
                "test".into(),
            )
            .await?;
        auth.logout_sid_from_source(&boot, &login.sid, Some("203.0.113.10"))
            .await?;
        ensure!(
            matches!(
                auth.authenticate_token(&boot, &login.token).await,
                Err(AuthError::InvalidSession)
            ),
            "revoked bearer token still authenticated"
        );
        let events = audit_events(&boot)?;
        ensure!(
            events.iter().any(|event| event == "console_credential"),
            "missing console credential audit event"
        );
        let facts = audit_facts(&boot)?;
        ensure!(
            facts.into_iter().any(|fact| {
                let OutcomeRef::Inline(Value::Map(m)) = fact.outcome_ref else {
                    return false;
                };
                m.get("event").and_then(Value::as_str) == Some("console_credential")
                    && m.get("outcome").and_then(Value::as_str) == Some("logout")
                    && m.get("username").and_then(Value::as_str) == Some("root")
                    && m.get("source_addr").and_then(Value::as_str) == Some("203.0.113.10")
            }),
            "missing logout audit fact with source address"
        );
        Ok(())
    }

    #[tokio::test]
    async fn step_up_issues_new_session_without_reusing_token() -> anyhow::Result<()> {
        let boot = auth_boot();
        let password = bootstrap_root_password(&boot).await?;
        let auth = test_auth()?;
        let login = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password: password.clone(),
                    totp_code: None,
                },
                "test".into(),
            )
            .await?;
        ensure!(
            login.mfa_level == 1,
            "initial login should have MFA level 1"
        );
        let elevated = auth
            .step_up(
                &boot,
                &login.token,
                StepUpRequest {
                    password: Some(password),
                    totp_code: None,
                },
                "test".into(),
            )
            .await?;
        ensure!(
            elevated.sid != login.sid,
            "step-up should issue a new session id"
        );
        ensure!(
            elevated.token != login.token,
            "step-up should issue a new bearer token"
        );
        ensure!(elevated.mfa_level == 2, "step-up should raise MFA level");
        ensure!(
            auth.authenticate_token(&boot, &login.token)
                .await?
                .mfa_level
                == 1,
            "original session MFA level changed"
        );
        ensure!(
            auth.authenticate_token(&boot, &elevated.token)
                .await?
                .mfa_level
                == 2,
            "elevated session did not authenticate at MFA level 2"
        );
        let facts = audit_facts(&boot)?;
        ensure!(
            !facts_contain_string(&facts, &login.token)?,
            "audit facts leaked original bearer token"
        );
        ensure!(
            !facts_contain_string(&facts, &elevated.token)?,
            "audit facts leaked elevated bearer token"
        );
        Ok(())
    }

    #[tokio::test]
    async fn root_can_list_and_revoke_console_sessions() -> anyhow::Result<()> {
        let boot = auth_boot();
        let password = bootstrap_root_password(&boot).await?;
        let auth = test_auth()?;
        let login1 = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password: password.clone(),
                    totp_code: None,
                },
                "test-a".into(),
            )
            .await?;
        let login2 = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    totp_code: None,
                },
                "test-b".into(),
            )
            .await?;
        let principal = auth.authenticate_token(&boot, &login1.token).await?;
        let sessions = auth.list_sessions(&boot, &principal).await?;
        ensure!(
            sessions.iter().any(|s| s.sid == login1.sid),
            "first session missing from session list"
        );
        ensure!(
            sessions.iter().any(|s| s.sid == login2.sid),
            "second session missing from session list"
        );

        auth.revoke_session_by_id_from_source(&boot, &principal, &login2.sid, None)
            .await?;
        ensure!(
            matches!(
                auth.authenticate_token(&boot, &login2.token).await,
                Err(AuthError::InvalidSession)
            ),
            "revoked session still authenticated"
        );
        let events = audit_events(&boot)?;
        ensure!(
            events.iter().any(|event| event == "console_credential"),
            "missing console credential audit event"
        );
        Ok(())
    }

    #[tokio::test]
    async fn malformed_console_session_state_is_rejected() -> anyhow::Result<()> {
        let boot = auth_boot();
        let password = bootstrap_root_password(&boot).await?;
        let auth = test_auth()?;
        let login = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    totp_code: None,
                },
                "test".into(),
            )
            .await?;
        let principal = auth.authenticate_token(&boot, &login.token).await?;
        boot.kernel
            .state
            .write_set(
                &Path::parse(&session_path("malformed")?)?,
                Value::Map(BTreeMap::new()),
            )
            .await?;

        ensure!(
            matches!(
                auth.list_sessions(&boot, &principal).await,
                Err(AuthError::InvalidSession)
            ),
            "malformed session state was accepted"
        );

        let malformed_identity = SessionRecord {
            sid: "malformed-identity".into(),
            username: "root".into(),
            identity_path: "identity://console/**".into(),
            issued_at: 1,
            expires_at: i64::MAX,
            idle_expires_at: i64::MAX,
            mfa_level: 1,
            last_seen: 1,
            source_addr: "test".into(),
        }
        .to_value();
        ensure!(
            SessionRecord::from_value("malformed-identity", &malformed_identity).is_err(),
            "wildcard session identity was accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn root_can_revoke_all_sessions_for_user() -> anyhow::Result<()> {
        let boot = auth_boot();
        let password = bootstrap_root_password(&boot).await?;
        let auth = test_auth()?;
        let login1 = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password: password.clone(),
                    totp_code: None,
                },
                "test-a".into(),
            )
            .await?;
        let login2 = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    totp_code: None,
                },
                "test-b".into(),
            )
            .await?;
        let principal = auth.authenticate_token(&boot, &login1.token).await?;
        let revoked = auth
            .revoke_user_sessions_from_source(&boot, &principal, "root", None)
            .await?;
        ensure!(revoked >= 2, "expected at least two revoked sessions");
        ensure!(
            matches!(
                auth.authenticate_token(&boot, &login1.token).await,
                Err(AuthError::InvalidSession)
            ),
            "first revoked session still authenticated"
        );
        ensure!(
            matches!(
                auth.authenticate_token(&boot, &login2.token).await,
                Err(AuthError::InvalidSession)
            ),
            "second revoked session still authenticated"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pubkey_only_root_can_use_single_use_challenge_login() -> anyhow::Result<()> {
        let boot = auth_boot();
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let descriptor = format!(
            "ed25519:{}",
            URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes())
        );
        let outcome = bootstrap_root_account(
            &boot,
            RootProvisioning {
                password_hash: None,
                pubkeys: vec![descriptor.clone()],
            },
        )
        .await?;
        let expected = BootstrapOutcome::CreatedPreseeded {
            username: "root".into(),
        };
        ensure!(
            outcome == expected,
            "unexpected bootstrap outcome: {outcome:?}"
        );

        let auth = test_auth()?;
        let challenge = auth
            .begin_key_login(
                &boot,
                KeyChallengeRequest {
                    username: "root".into(),
                    origin: "https://console.local".into(),
                },
                "test".into(),
            )
            .await?;
        let outcomes = audit_outcomes(&boot, "console_credential")?;
        ensure!(
            outcomes.iter().any(|outcome| outcome == "key_challenge"),
            "missing key challenge audit outcome"
        );
        let signature = signing_key.sign(challenge.transcript.as_bytes());
        let login = auth
            .finish_key_login(
                &boot,
                KeyLoginRequest {
                    username: "root".into(),
                    challenge_id: challenge.challenge_id.clone(),
                    signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                    origin: "https://console.local".into(),
                    key: Some(descriptor),
                },
                "test".into(),
            )
            .await?;
        let principal = auth.authenticate_token(&boot, &login.token).await?;
        ensure!(
            principal.username == "root",
            "unexpected principal username"
        );

        let reused = signing_key.sign(challenge.transcript.as_bytes());
        ensure!(
            matches!(
                auth.finish_key_login(
                    &boot,
                    KeyLoginRequest {
                        username: "root".into(),
                        challenge_id: challenge.challenge_id,
                        signature: URL_SAFE_NO_PAD.encode(reused.to_bytes()),
                        origin: "https://console.local".into(),
                        key: None,
                    },
                    "test".into(),
                )
                .await,
                Err(AuthError::InvalidChallenge)
            ),
            "single-use key challenge was accepted twice"
        );
        let events = audit_events(&boot)?;
        ensure!(
            events.iter().any(|event| event == "console_login"),
            "missing key login audit event"
        );
        ensure!(
            events.iter().any(|event| event == "console_login_failed"),
            "missing replay failure audit event"
        );
        Ok(())
    }

    #[tokio::test]
    async fn root_cannot_self_lock_or_self_demote() -> anyhow::Result<()> {
        let boot = auth_boot();
        let state = &boot.kernel.state;
        let password = bootstrap_root_password(&boot).await?;
        let auth = test_auth()?;
        let login = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password,
                    totp_code: None,
                },
                "test".into(),
            )
            .await?;
        let principal = auth.authenticate_token(&boot, &login.token).await?;
        let path = Path::parse("state://kernel/console/users/root")?;
        let mut root = read_user(state, "root")
            .await?
            .context("root user missing after bootstrap")?;

        root.status = "disabled".into();
        ensure!(
            matches!(
                authorize_path(state, &principal, "write", &path, Some(&root.to_value())).await,
                Err(AuthError::PermissionDenied)
            ),
            "root was allowed to self-lock"
        );

        let mut root = read_user(state, "root")
            .await?
            .context("root user missing after disabled self-lock check")?;
        root.status = "locked".into();
        ensure!(
            matches!(
                authorize_path(state, &principal, "write", &path, Some(&root.to_value())).await,
                Err(AuthError::PermissionDenied)
            ),
            "root was allowed to self-lock with locked status"
        );

        let mut root = read_user(state, "root")
            .await?
            .context("root user missing after self-lock check")?;
        root.grants = vec!["read://state/kernel/**".into()];
        root.authority_ceiling = root.grants.clone();
        ensure!(
            matches!(
                authorize_path(state, &principal, "write", &path, Some(&root.to_value())).await,
                Err(AuthError::PermissionDenied)
            ),
            "root was allowed to self-demote"
        );

        let mut root = read_user(state, "root")
            .await?
            .context("root user missing after self-demote check")?;
        root.password_hash_ref = None;
        root.pubkeys.clear();
        ensure!(
            matches!(
                authorize_path(state, &principal, "write", &path, Some(&root.to_value())).await,
                Err(AuthError::PermissionDenied)
            ),
            "root was allowed to remove all login methods"
        );
        Ok(())
    }

    #[tokio::test]
    async fn locked_user_cannot_login() -> anyhow::Result<()> {
        let boot = auth_boot();
        let state = &boot.kernel.state;
        let password = bootstrap_root_password(&boot).await?;
        let mut root = read_user(state, "root")
            .await?
            .context("root user missing after bootstrap")?;
        root.status = "locked".into();
        write_user(state, &root).await?;

        let auth = test_auth()?;
        ensure!(
            matches!(
                auth.login(
                    &boot,
                    LoginRequest {
                        username: "root".into(),
                        password,
                        totp_code: None,
                    },
                    "test".into(),
                )
                .await,
                Err(AuthError::AccountUnavailable)
            ),
            "locked user was able to login"
        );
        Ok(())
    }

    #[tokio::test]
    async fn frozen_roles_and_role_grants_are_enforced() -> anyhow::Result<()> {
        let boot = auth_boot();
        let state = boot.kernel.state.clone();
        let admin = ConsolePrincipal {
            username: "admin".into(),
            identity_path: "identity://console/admin".into(),
            grants: CapSet::from_strs([
                "write://state/kernel/console/roles/**",
                "perform://effect/kernel/console/users/**",
            ])?,
            mfa_level: 1,
        };

        let role_path = Path::parse("state://kernel/console/roles/ops")?;
        state
            .write_set(&role_path, role_value(vec![], true))
            .await?;
        ensure!(
            matches!(
                authorize_path(
                    &state,
                    &admin,
                    "write",
                    &role_path,
                    Some(&role_value(vec![], false))
                )
                .await,
                Err(AuthError::PermissionDenied)
            ),
            "frozen role was mutable"
        );

        let new_role = Path::parse("state://kernel/console/roles/newrole")?;
        ensure!(
            matches!(
                authorize_path(
                    &state,
                    &admin,
                    "write",
                    &new_role,
                    Some(&role_value(vec![], true))
                )
                .await,
                Err(AuthError::PermissionDenied)
            ),
            "caller created a frozen role"
        );
        ensure!(
            matches!(
                authorize_path(
                    &state,
                    &admin,
                    "write",
                    &new_role,
                    Some(&role_value(vec!["write://state/kernel/**"], false))
                )
                .await,
                Err(AuthError::PermissionDenied)
            ),
            "caller exceeded role grant authority"
        );
        Ok(())
    }

    #[tokio::test]
    async fn malformed_role_grants_are_rejected() -> anyhow::Result<()> {
        let boot = auth_boot();
        let state = boot.kernel.state.clone();
        let admin = ConsolePrincipal {
            username: "root".into(),
            identity_path: "identity://console/root".into(),
            grants: CapSet::from_strs(["*://**"])?,
            mfa_level: 2,
        };
        let mut role = BTreeMap::new();
        role.insert(
            "grants".into(),
            Value::List(vec![
                Value::Str("read://state/kernel/**".into()),
                Value::Int(7),
            ]),
        );
        role.insert("frozen".into(), Value::Bool(false));

        ensure!(
            matches!(
            authorize_path(
                &state,
                &admin,
                "write",
                &Path::parse("state://kernel/console/roles/bad")?,
                Some(&Value::Map(role))
            )
            .await,
            Err(AuthError::State(message)) if message.contains("console role.grants[1]")
            ),
            "malformed role grant was accepted"
        );
        Ok(())
    }

    #[tokio::test]
    async fn auth_audit_facts_are_redacted() -> anyhow::Result<()> {
        let boot = auth_boot();
        let password = bootstrap_root_password(&boot).await?;
        let auth = test_auth()?;
        let login = auth
            .login(
                &boot,
                LoginRequest {
                    username: "root".into(),
                    password: password.clone(),
                    totp_code: None,
                },
                "audit-source".into(),
            )
            .await?;

        let facts = audit_facts(&boot)?;
        ensure!(
            facts_contain_string(&facts, "console_login")?,
            "missing console login audit fact"
        );
        ensure!(
            !facts_contain_string(&facts, &password)?,
            "audit facts leaked password"
        );
        ensure!(
            !facts_contain_string(&facts, &login.token)?,
            "audit facts leaked bearer token"
        );
        ensure!(
            !facts_contain_string(&facts, "password")?,
            "audit facts included password field"
        );
        ensure!(
            !facts_contain_string(&facts, "token")?,
            "audit facts included token field"
        );
        Ok(())
    }
}
