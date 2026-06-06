//! Console authentication and authorization (§18.5).
//!
//! Credentials stay outside Operation input and Facts. Account records live
//! under `state://kernel/console/*`; password/session/TOTP secrets live under
//! `state://vault/console/*`.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, KeyInit, Mac};
use nexus_kernel::{Bootstrap, GatewayAudit};
use nexus_state::{Backend, StateError};
use nexus_types::{CapSet, Capability, Path, Value};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::sync::Semaphore;

const USERS_PREFIX: &str = "state://kernel/console/users";
const ROLES_PREFIX: &str = "state://kernel/console/roles";
const SESSIONS_PREFIX: &str = "state://kernel/console/sessions";
const CHALLENGES_PREFIX: &str = "state://kernel/console/challenges";
const VAULT_PREFIX: &str = "state://vault/console";
const ROOT_USERNAME: &str = "root";
const DEFAULT_SESSION_TTL_MS: i64 = 24 * 60 * 60 * 1000;
const DEFAULT_IDLE_TTL_MS: i64 = 2 * 60 * 60 * 1000;
const TOTP_PERIOD_SECS: i64 = 30;
const KEY_CHALLENGE_TTL_MS: i64 = 60_000;

type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Debug, Default)]
pub struct RootProvisioning {
    pub password_hash: Option<String>,
    pub pubkeys: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ConsoleAuthConfig {
    pub session_ttl_ms: i64,
    pub idle_ttl_ms: i64,
    pub max_sessions_per_user: usize,
    pub global_session_limit: usize,
    pub argon2_concurrency: usize,
}

impl Default for ConsoleAuthConfig {
    fn default() -> Self {
        Self {
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
            idle_ttl_ms: DEFAULT_IDLE_TTL_MS,
            max_sessions_per_user: 5,
            global_session_limit: 10_000,
            argon2_concurrency: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
                .max(1),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BootstrapOutcome {
    AlreadyPresent,
    CreatedRandomPassword { username: String, password: String },
    CreatedPreseeded { username: String },
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub totp_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub sid: String,
    pub token: String,
    pub expires_at: i64,
    pub idle_expires_at: i64,
    pub mfa_level: u8,
}

#[derive(Debug, Deserialize)]
pub struct KeyChallengeRequest {
    pub username: String,
    pub origin: String,
}

#[derive(Debug, Serialize)]
pub struct KeyChallengeResponse {
    pub challenge_id: String,
    pub nonce: String,
    pub origin: String,
    pub expires_at: i64,
    pub transcript: String,
}

#[derive(Debug, Deserialize)]
pub struct KeyLoginRequest {
    pub username: String,
    pub challenge_id: String,
    pub signature: String,
    pub origin: String,
    #[serde(default)]
    pub key: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ConsolePrincipal {
    pub username: String,
    pub identity_path: String,
    pub grants: CapSet,
    pub mfa_level: u8,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid username")]
    InvalidUsername,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("account is disabled or locked")]
    AccountUnavailable,
    #[error("session is missing, expired, or revoked")]
    InvalidSession,
    #[error("key challenge is missing, expired, or already used")]
    InvalidChallenge,
    #[error("authorization bearer token is required")]
    MissingBearer,
    #[error("permission denied")]
    PermissionDenied,
    #[error("rate limited; retry after {retry_after_ms} ms")]
    RateLimited { retry_after_ms: i64 },
    #[error("state error: {0}")]
    State(String),
    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<StateError> for AuthError {
    fn from(e: StateError) -> Self {
        AuthError::State(e.to_string())
    }
}

impl From<nexus_types::PathError> for AuthError {
    fn from(e: nexus_types::PathError) -> Self {
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

pub struct ConsoleAuth {
    config: ConsoleAuthConfig,
    decoy_phc: String,
    argon2_slots: Semaphore,
    rate: Mutex<RateState>,
}

impl Default for ConsoleAuth {
    fn default() -> Self {
        Self::new(ConsoleAuthConfig::default())
    }
}

impl ConsoleAuth {
    pub fn new(config: ConsoleAuthConfig) -> Self {
        let decoy_phc = hash_password_with_salt("invalid-password", &[0x42; 16])
            .expect("argon2 decoy hash can be created");
        Self {
            argon2_slots: Semaphore::new(config.argon2_concurrency),
            config,
            decoy_phc,
            rate: Mutex::new(RateState::default()),
        }
    }

    pub async fn login(
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
            .map_err(|_| AuthError::Crypto("argon2 semaphore closed".into()))?;
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
            let step = verify_totp(&seed, code, user.totp_last_step, now_millis())
                .ok_or(AuthError::InvalidCredentials)?;
            user.totp_last_step = Some(step);
            write_user(state, &user).await?;
            mfa_level = 2;
        }

        self.clear_login_failures(&username, &source_addr, now_millis());
        self.issue_session(state, &user, source_addr, mfa_level)
            .await
    }

    pub async fn begin_key_login(
        &self,
        boot: &Bootstrap,
        req: KeyChallengeRequest,
    ) -> Result<KeyChallengeResponse, AuthError> {
        self.begin_key_login_inner(&boot.kernel.state, req).await
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

    pub async fn finish_key_login(
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
        validate_session_id(&req.challenge_id).map_err(|_| AuthError::InvalidChallenge)?;
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

    pub async fn authenticate_token(
        &self,
        boot: &Bootstrap,
        bearer: &str,
    ) -> Result<ConsolePrincipal, AuthError> {
        self.authenticate_token_inner(&boot.kernel.state, bearer)
            .await
    }

    async fn authenticate_token_inner(
        &self,
        state: &Backend,
        bearer: &str,
    ) -> Result<ConsolePrincipal, AuthError> {
        let (sid, token) = bearer.split_once('.').ok_or(AuthError::InvalidSession)?;
        validate_session_id(sid)?;
        let session_path = session_path(sid);
        let Some(mut session) = read_session(state, &session_path).await? else {
            return Err(AuthError::InvalidSession);
        };
        let now = now_millis();
        if session.expires_at <= now || session.idle_expires_at <= now {
            revoke_session(state, sid).await?;
            return Err(AuthError::InvalidSession);
        }
        let token_hash = token_hash(token);
        let expected_hash = read_string(state, &session_token_path(sid))
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

    pub async fn logout(&self, boot: &Bootstrap, bearer: &str) -> Result<(), AuthError> {
        let (sid, _) = bearer.split_once('.').ok_or(AuthError::InvalidSession)?;
        validate_session_id(sid)?;
        let result = revoke_session(&boot.kernel.state, sid).await;
        match &result {
            Ok(()) => {
                record_auth_audit(boot, "console_credential", None, None, "logout", None)?;
            }
            Err(err) => {
                record_auth_audit(
                    boot,
                    "console_credential",
                    None,
                    None,
                    audit_outcome(err),
                    None,
                )?;
            }
        }
        result
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
        write_session(state, &session_path(&sid), &session).await?;
        write_string(state, &session_token_path(&sid), token_hash(&token_secret)).await?;

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
        let mut rate = self.rate.lock().expect("rate mutex poisoned");
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
        let mut rate = self.rate.lock().expect("rate mutex poisoned");
        mark_failure(rate.by_user.entry(username.to_string()).or_default(), now);
        mark_failure(
            rate.by_source.entry(source_addr.to_string()).or_default(),
            now,
        );
        mark_failure(&mut rate.global, now);
    }

    fn clear_login_failures(&self, username: &str, source_addr: &str, now: i64) {
        let mut rate = self.rate.lock().expect("rate mutex poisoned");
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
}

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
            .map_err(|_| AuthError::Crypto("invalid root password PHC string".into()))?;
    }
    let supported_key = provisioning
        .pubkeys
        .iter()
        .any(|key| parse_ed25519_key_descriptor(key).is_ok());
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
        let hash_ref = password_hash_path(ROOT_USERNAME);
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
        let hash_ref = password_hash_path(ROOT_USERNAME);
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

pub fn bearer_from_headers(headers: &axum::http::HeaderMap) -> Result<&str, AuthError> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or(AuthError::MissingBearer)?;
    raw.strip_prefix("Bearer ").ok_or(AuthError::MissingBearer)
}

pub fn validate_username(username: &str) -> Result<(), AuthError> {
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

pub async fn authorize_path(
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

    let role_path = format!("{ROLES_PREFIX}/{role}");
    if let Some(existing) = state.read(&Path::parse(&role_path)?).await? {
        let existing_grants = capset_from_strings(&role_grants(&existing))?;
        if !capset_covers(&principal.grants, &existing_grants) {
            return Err(AuthError::PermissionDenied);
        }
        if role_frozen(&existing) && principal.username != ROOT_USERNAME {
            return Err(AuthError::PermissionDenied);
        }
    }

    if let Some(value) = new_value {
        let candidate_grants = capset_from_strings(&role_grants(value))?;
        if !capset_covers(&principal.grants, &candidate_grants) {
            return Err(AuthError::PermissionDenied);
        }
        if role_frozen(value) && principal.username != ROOT_USERNAME {
            return Err(AuthError::PermissionDenied);
        }
    }
    Ok(())
}

fn enforce_root_invariants(user: &UserRecord, effective: &CapSet) -> Result<(), AuthError> {
    if !matches!(user.status.as_str(), "active") {
        return Err(AuthError::PermissionDenied);
    }
    if user.password_hash_ref.is_none()
        && !user
            .pubkeys
            .iter()
            .any(|key| parse_ed25519_key_descriptor(key).is_ok())
    {
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
        let role_path = format!("{ROLES_PREFIX}/{role}");
        if let Some(v) = state.read(&Path::parse(&role_path)?).await? {
            grants.extend(role_grants(&v));
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

fn role_grants(value: &Value) -> Vec<String> {
    value
        .as_map()
        .and_then(|m| m.get("grants"))
        .and_then(string_list)
        .unwrap_or_default()
}

fn role_frozen(value: &Value) -> bool {
    value
        .as_map()
        .and_then(|m| m.get("frozen"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
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
        let authn = m.get("authn").and_then(Value::as_map);
        let password = authn
            .and_then(|a| a.get("password"))
            .and_then(Value::as_map);
        let totp = authn.and_then(|a| a.get("totp")).and_then(Value::as_map);
        let pubkeys = authn
            .and_then(|a| a.get("pubkeys"))
            .and_then(string_list)
            .unwrap_or_default();
        Ok(Self {
            username: username.to_string(),
            identity_path: str_field(m, "identity_path")
                .unwrap_or_else(|| format!("identity://console/{username}")),
            status: str_field(m, "status").unwrap_or_else(|| "active".into()),
            password_hash_ref: password
                .and_then(|p| p.get("hash_ref"))
                .and_then(Value::as_str)
                .map(str::to_string),
            totp_enabled: totp
                .and_then(|t| t.get("enabled"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            totp_seed_ref: totp
                .and_then(|t| t.get("seed_ref"))
                .and_then(Value::as_str)
                .map(str::to_string),
            totp_last_step: totp
                .and_then(|t| t.get("last_step"))
                .and_then(Value::as_int),
            pubkeys,
            roles: m.get("roles").and_then(string_list).unwrap_or_default(),
            grants: m.get("grants").and_then(string_list).unwrap_or_default(),
            authority_ceiling: m
                .get("authority_ceiling")
                .and_then(string_list)
                .unwrap_or_default(),
            created_by: str_field(m, "created_by").unwrap_or_else(|| "unknown".into()),
            created_at: int_field(m, "created_at").unwrap_or(0),
            password_changed_at: int_field(m, "password_changed_at").unwrap_or(0),
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
        Ok(Self {
            sid: sid.to_string(),
            username: str_field(m, "username").ok_or(AuthError::InvalidSession)?,
            identity_path: str_field(m, "identity_path").ok_or(AuthError::InvalidSession)?,
            issued_at: int_field(m, "issued_at").ok_or(AuthError::InvalidSession)?,
            expires_at: int_field(m, "expires_at").ok_or(AuthError::InvalidSession)?,
            idle_expires_at: int_field(m, "idle_expires_at").ok_or(AuthError::InvalidSession)?,
            mfa_level: int_field(m, "mfa_level").unwrap_or(1) as u8,
            last_seen: int_field(m, "last_seen").unwrap_or(0),
            source_addr: str_field(m, "source_addr").unwrap_or_default(),
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
    validate_username(username)?;
    let path = Path::parse(&format!("{USERS_PREFIX}/{username}"))?;
    Ok(state
        .read(&path)
        .await?
        .map(|v| UserRecord::from_value(username, &v))
        .transpose()?)
}

async fn write_user(state: &Backend, user: &UserRecord) -> Result<(), AuthError> {
    validate_username(&user.username)?;
    let path = Path::parse(&format!("{USERS_PREFIX}/{}", user.username))?;
    state.write_set(&path, user.to_value()).await?;
    Ok(())
}

async fn read_session(state: &Backend, path: &str) -> Result<Option<SessionRecord>, AuthError> {
    let sid = path.rsplit('/').next().ok_or(AuthError::InvalidSession)?;
    Ok(state
        .read(&Path::parse(path)?)
        .await?
        .map(|v| SessionRecord::from_value(sid, &v))
        .transpose()?)
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
    validate_session_id(challenge_id).map_err(|_| AuthError::InvalidChallenge)?;
    let path = key_challenge_path(challenge_id);
    Ok(state
        .read(&Path::parse(&path)?)
        .await?
        .map(|v| KeyChallengeRecord::from_value(challenge_id, &v))
        .transpose()?)
}

async fn write_key_challenge(
    state: &Backend,
    challenge: &KeyChallengeRecord,
) -> Result<(), AuthError> {
    state
        .write_set(
            &Path::parse(&key_challenge_path(&challenge.challenge_id))?,
            challenge.to_value(),
        )
        .await?;
    Ok(())
}

async fn revoke_key_challenge(state: &Backend, challenge_id: &str) -> Result<(), AuthError> {
    state
        .write_delete(&Path::parse(&key_challenge_path(challenge_id))?)
        .await?;
    Ok(())
}

async fn sweep_expired_key_challenges(state: &Backend, now: i64) -> Result<(), AuthError> {
    let challenges = state.read_prefix(&Path::parse(CHALLENGES_PREFIX)?).await?;
    for (path, value) in challenges {
        let challenge_id = path
            .to_string()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        if let Ok(challenge) = KeyChallengeRecord::from_value(&challenge_id, &value)
            && challenge.expires_at <= now
        {
            revoke_key_challenge(state, &challenge_id).await?;
        }
    }
    Ok(())
}

async fn revoke_session(state: &Backend, sid: &str) -> Result<(), AuthError> {
    state
        .write_delete(&Path::parse(&session_path(sid))?)
        .await?;
    state
        .write_delete(&Path::parse(&session_token_path(sid))?)
        .await?;
    Ok(())
}

async fn sweep_expired_sessions(state: &Backend, now: i64) -> Result<(), AuthError> {
    let sessions = state.read_prefix(&Path::parse(SESSIONS_PREFIX)?).await?;
    for (path, value) in sessions {
        let sid = path
            .to_string()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        if let Ok(session) = SessionRecord::from_value(&sid, &value) {
            if session.expires_at <= now || session.idle_expires_at <= now {
                revoke_session(state, &sid).await?;
            }
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
    let mut sessions: Vec<_> = state
        .read_prefix(&Path::parse(SESSIONS_PREFIX)?)
        .await?
        .into_iter()
        .filter_map(|(path, value)| {
            let path_s = path.to_string();
            let sid = path_s.rsplit('/').next()?.to_string();
            SessionRecord::from_value(&sid, &value).ok()
        })
        .collect();
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
        "read://state/kernel/**".into(),
        "write://state/kernel/**".into(),
        "subscribe://state/kernel/**".into(),
        "perform://effect/kernel/console/users/**".into(),
    ]
}

fn password_hash_path(username: &str) -> String {
    format!("{VAULT_PREFIX}/{username}/password")
}

fn session_path(sid: &str) -> String {
    format!("{SESSIONS_PREFIX}/{sid}")
}

fn session_token_path(sid: &str) -> String {
    format!("{VAULT_PREFIX}/sessions/{sid}")
}

fn key_challenge_path(challenge_id: &str) -> String {
    format!("{CHALLENGES_PREFIX}/{challenge_id}")
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
    format!("nexus-console-ed25519-v1\n{username}\n{challenge_id}\n{nonce}\n{origin}")
}

fn verify_key_login(
    descriptors: &[String],
    requested_key: Option<&str>,
    signature_b64: &str,
    transcript: &str,
) -> Result<bool, AuthError> {
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64.as_bytes())
        .map_err(|_| AuthError::InvalidCredentials)?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .map_err(|_| AuthError::InvalidCredentials)?;

    for descriptor in descriptors {
        if requested_key.is_some_and(|key| key != descriptor) {
            continue;
        }
        let Ok(key) = parse_ed25519_key_descriptor(descriptor) else {
            continue;
        };
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
        .map_err(|_| AuthError::Crypto("invalid ed25519 key encoding".into()))?;
    let key_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::Crypto("invalid ed25519 key length".into()))?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| AuthError::Crypto("invalid ed25519 public key".into()))?;
    if key.is_weak() {
        return Err(AuthError::Crypto("weak ed25519 public key".into()));
    }
    Ok(key)
}

fn verify_totp(seed_b64: &str, code: &str, last_step: Option<i64>, now_ms: i64) -> Option<i64> {
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let seed = URL_SAFE_NO_PAD.decode(seed_b64.as_bytes()).ok()?;
    let current_step = (now_ms / 1000) / TOTP_PERIOD_SECS;
    for step in [current_step - 1, current_step, current_step + 1] {
        if last_step.is_some_and(|last| step <= last) {
            continue;
        }
        let expected = totp_at_step(&seed, step)?;
        if expected.as_bytes().ct_eq(code.as_bytes()).unwrap_u8() == 1 {
            return Some(step);
        }
    }
    None
}

fn totp_at_step(seed: &[u8], step: i64) -> Option<String> {
    let mut mac = HmacSha1::new_from_slice(seed).ok()?;
    mac.update(&(step as u64).to_be_bytes());
    let out = mac.finalize().into_bytes();
    let offset = (out[19] & 0x0f) as usize;
    let binary = (((out[offset] & 0x7f) as u32) << 24)
        | ((out[offset + 1] as u32) << 16)
        | ((out[offset + 2] as u32) << 8)
        | (out[offset + 3] as u32);
    Some(format!("{:06}", binary % 1_000_000))
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
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

fn string_list(v: &Value) -> Option<Vec<String>> {
    match v {
        Value::List(xs) => Some(
            xs.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
        ),
        _ => None,
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
    use ed25519_dalek::{Signer, SigningKey};
    use nexus_kernel::Bootstrap;
    use nexus_types::{Fact, OutcomeRef};

    fn auth_boot() -> Bootstrap {
        Bootstrap::in_memory()
    }

    fn audit_facts(boot: &Bootstrap) -> Vec<Fact> {
        boot.kernel
            .processes
            .all_ids()
            .into_iter()
            .flat_map(|pid| boot.kernel.facts.facts_of(pid))
            .filter(|fact| match &fact.outcome_ref {
                OutcomeRef::Inline(Value::Map(m)) => m.contains_key("event"),
                _ => false,
            })
            .collect()
    }

    fn audit_events(boot: &Bootstrap) -> Vec<String> {
        audit_facts(boot)
            .into_iter()
            .filter_map(|fact| match fact.outcome_ref {
                OutcomeRef::Inline(Value::Map(m)) => {
                    m.get("event").and_then(Value::as_str).map(str::to_string)
                }
                _ => None,
            })
            .collect()
    }

    fn fact_contains_string(fact: &Fact, needle: &str) -> bool {
        serde_json::to_string(fact).unwrap().contains(needle)
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
    async fn bootstraps_root_and_logs_in() {
        let boot = auth_boot();
        let outcome = bootstrap_root_account(&boot, RootProvisioning::default())
            .await
            .unwrap();
        let BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
            panic!("expected generated password");
        };
        let auth = ConsoleAuth::default();
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
            .await
            .unwrap();
        let principal = auth.authenticate_token(&boot, &login.token).await.unwrap();
        assert_eq!(principal.username, "root");
        assert!(
            principal
                .grants
                .contains("write", &Path::parse("state://kernel/x").unwrap())
        );
        let events = audit_events(&boot);
        assert!(events.contains(&"console_bootstrap".into()));
        assert!(events.contains(&"console_login".into()));
    }

    #[test]
    fn random_tokens_are_valid_path_segments() {
        for _ in 0..128 {
            let token = random_token(18).unwrap();
            validate_session_id(&token).unwrap();
            Path::parse(&format!("state://kernel/console/sessions/{token}")).unwrap();
        }
        assert!(validate_session_id("-bad").is_err());
        assert!(validate_session_id("_bad").is_err());
    }

    #[tokio::test]
    async fn username_validation_is_strict() {
        assert!(validate_username("alice_1").is_ok());
        assert!(validate_username("bad/name").is_err());
        assert!(validate_username(".bad").is_err());
        assert!(validate_username("含").is_err());
    }

    #[tokio::test]
    async fn bearer_logout_revokes_session() {
        let boot = auth_boot();
        let outcome = bootstrap_root_account(&boot, RootProvisioning::default())
            .await
            .unwrap();
        let BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
            panic!("expected generated password");
        };
        let auth = ConsoleAuth::default();
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
            .await
            .unwrap();
        auth.logout(&boot, &login.token).await.unwrap();
        assert!(matches!(
            auth.authenticate_token(&boot, &login.token).await,
            Err(AuthError::InvalidSession)
        ));
        assert!(audit_events(&boot).contains(&"console_credential".into()));
    }

    #[tokio::test]
    async fn pubkey_only_root_can_use_single_use_challenge_login() {
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
        .await
        .unwrap();
        assert_eq!(
            outcome,
            BootstrapOutcome::CreatedPreseeded {
                username: "root".into()
            }
        );

        let auth = ConsoleAuth::default();
        let challenge = auth
            .begin_key_login(
                &boot,
                KeyChallengeRequest {
                    username: "root".into(),
                    origin: "https://console.local".into(),
                },
            )
            .await
            .unwrap();
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
            .await
            .unwrap();
        let principal = auth.authenticate_token(&boot, &login.token).await.unwrap();
        assert_eq!(principal.username, "root");

        let reused = signing_key.sign(challenge.transcript.as_bytes());
        assert!(matches!(
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
        ));
        let events = audit_events(&boot);
        assert!(events.contains(&"console_login".into()));
        assert!(events.contains(&"console_login_failed".into()));
    }

    #[tokio::test]
    async fn root_cannot_self_lock_or_self_demote() {
        let boot = auth_boot();
        let state = &boot.kernel.state;
        let outcome = bootstrap_root_account(&boot, RootProvisioning::default())
            .await
            .unwrap();
        let BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
            panic!("expected generated password");
        };
        let auth = ConsoleAuth::default();
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
            .await
            .unwrap();
        let principal = auth.authenticate_token(&boot, &login.token).await.unwrap();
        let path = Path::parse("state://kernel/console/users/root").unwrap();
        let mut root = read_user(&state, "root").await.unwrap().unwrap();

        root.status = "disabled".into();
        assert!(matches!(
            authorize_path(&state, &principal, "write", &path, Some(&root.to_value())).await,
            Err(AuthError::PermissionDenied)
        ));

        let mut root = read_user(&state, "root").await.unwrap().unwrap();
        root.grants = vec!["read://state/kernel/**".into()];
        root.authority_ceiling = root.grants.clone();
        assert!(matches!(
            authorize_path(&state, &principal, "write", &path, Some(&root.to_value())).await,
            Err(AuthError::PermissionDenied)
        ));

        let mut root = read_user(&state, "root").await.unwrap().unwrap();
        root.password_hash_ref = None;
        root.pubkeys.clear();
        assert!(matches!(
            authorize_path(&state, &principal, "write", &path, Some(&root.to_value())).await,
            Err(AuthError::PermissionDenied)
        ));
    }

    #[tokio::test]
    async fn frozen_roles_and_role_grants_are_enforced() {
        let boot = auth_boot();
        let state = boot.kernel.state.clone();
        let admin = ConsolePrincipal {
            username: "admin".into(),
            identity_path: "identity://console/admin".into(),
            grants: CapSet::from_strs([
                "write://state/kernel/console/roles/**",
                "perform://effect/kernel/console/users/**",
            ])
            .unwrap(),
            mfa_level: 1,
        };

        let role_path = Path::parse("state://kernel/console/roles/ops").unwrap();
        state
            .write_set(&role_path, role_value(vec![], true))
            .await
            .unwrap();
        assert!(matches!(
            authorize_path(
                &state,
                &admin,
                "write",
                &role_path,
                Some(&role_value(vec![], false))
            )
            .await,
            Err(AuthError::PermissionDenied)
        ));

        let new_role = Path::parse("state://kernel/console/roles/newrole").unwrap();
        assert!(matches!(
            authorize_path(
                &state,
                &admin,
                "write",
                &new_role,
                Some(&role_value(vec![], true))
            )
            .await,
            Err(AuthError::PermissionDenied)
        ));
        assert!(matches!(
            authorize_path(
                &state,
                &admin,
                "write",
                &new_role,
                Some(&role_value(vec!["write://state/kernel/**"], false))
            )
            .await,
            Err(AuthError::PermissionDenied)
        ));
    }

    #[tokio::test]
    async fn auth_audit_facts_are_redacted() {
        let boot = auth_boot();
        let outcome = bootstrap_root_account(&boot, RootProvisioning::default())
            .await
            .unwrap();
        let BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
            panic!("expected generated password");
        };
        let auth = ConsoleAuth::default();
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
            .await
            .unwrap();

        let facts = audit_facts(&boot);
        assert!(
            facts
                .iter()
                .any(|fact| fact_contains_string(fact, "console_login"))
        );
        for fact in facts {
            assert!(!fact_contains_string(&fact, &password));
            assert!(!fact_contains_string(&fact, &login.token));
            assert!(!fact_contains_string(&fact, "password"));
            assert!(!fact_contains_string(&fact, "token"));
        }
    }
}
