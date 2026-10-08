//! A single bounded CAS ledger owns all pending authentication ceremonies.

use super::*;
use serde::de::DeserializeOwned;
use std::num::NonZeroUsize;
use xolotl_kernel::host::HostRuntime;

#[cfg(test)]
fn test_runtime() -> &'static HostRuntime {
    static RUNTIME: std::sync::OnceLock<HostRuntime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(HostRuntime::default)
}

mod continuations;
pub(super) use continuations::{
    Round, advance, cancel, claim, finish, inspect, inspect_owner, issue_continuation, retire,
};

const LEDGER: &str = crate::paths::VAULT_CHALLENGES_PATH;
const HARD_MAX_PENDING: usize = 1024;
const HARD_MAX_BYTES: usize = 4 * 1024 * 1024;
// The ledger is persisted as a State string. Escaping may double its encoded
// length; leave room for the path and provenance envelope as well.
const MAX_LEDGER_ROW_BYTES: NonZeroUsize = NonZeroUsize::new(HARD_MAX_BYTES * 2 + 4096).unwrap();
const MAX_PAYLOAD_BYTES: usize = 64 * 1024;
const CAS_ATTEMPTS: usize = 8;

/// Shared admission limits for public-key, WebAuthn and MFA ceremonies. Limits apply
/// to the persisted ledger, including requests from other hosts sharing State.
/// Hosts sharing a ledger must use the same policy. Expired entries are reclaimed
/// on admission; abandoned ceremonies cannot grow storage beyond these bounds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleChallengeConfig {
    /// Maximum pending ceremonies across all accounts and methods (1..=1024).
    pub max_pending_global: usize,
    /// Maximum pending ceremonies for one account across all methods (1..=1024).
    pub max_pending_per_user: usize,
    /// Maximum pending ceremonies for one verified source (1..=1024).
    pub max_pending_per_source: usize,
    /// Maximum ledger bytes, including reserved in-flight metadata (1024..=4194304).
    pub max_bytes: usize,
}

impl Default for ConsoleChallengeConfig {
    fn default() -> Self {
        Self {
            max_pending_global: 256,
            max_pending_per_user: 8,
            max_pending_per_source: 32,
            max_bytes: 1024 * 1024,
        }
    }
}

impl ConsoleChallengeConfig {
    /// Clamp tuning into hard storage and work bounds.
    pub fn bounded(self) -> Self {
        let global = self.max_pending_global.clamp(1, HARD_MAX_PENDING);
        Self {
            max_pending_global: global,
            max_pending_per_user: self.max_pending_per_user.clamp(1, global),
            max_pending_per_source: self.max_pending_per_source.clamp(1, global),
            max_bytes: self.max_bytes.clamp(1024, HARD_MAX_BYTES),
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Binding {
    PublicKey {
        username: String,
        origin: String,
    },
    PasskeyRegistration {
        username: String,
        sid: String,
    },
    PasskeyAuthentication {
        username: String,
    },
    MfaLogin {
        username: String,
        account: AccountKey,
    },
    MfaStepUp {
        username: String,
        account: AccountKey,
        sid: String,
    },
}

impl Binding {
    fn username(&self) -> &str {
        match self {
            Self::PublicKey { username, .. }
            | Self::PasskeyRegistration { username, .. }
            | Self::PasskeyAuthentication { username }
            | Self::MfaLogin { username, .. }
            | Self::MfaStepUp { username, .. } => username,
        }
    }

    fn is_mfa(&self) -> bool {
        matches!(self, Self::MfaLogin { .. } | Self::MfaStepUp { .. })
    }

    fn same_owner(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::MfaLogin { account: a, .. } | Self::MfaStepUp { account: a, .. },
                Self::MfaLogin { account: b, .. } | Self::MfaStepUp { account: b, .. },
            ) => a == b,
            (left, right) if !left.is_mfa() && !right.is_mfa() => {
                left.username() == right.username()
            }
            _ => false,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Phase {
    SingleUse,
    Ready {
        token_hash: String,
    },
    InFlight {
        token_hash: String,
        claim: String,
        cancelled: bool,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    binding: Binding,
    source_hash: String,
    expires_at: i64,
    phase: Phase,
    payload: serde_json::Value,
}

type Ledger = BTreeMap<String, Pending>;

async fn read_ledger(state: &Backend, path: &Path) -> Result<Option<Value>, AuthError> {
    Ok(state.read_bounded(path, MAX_LEDGER_ROW_BYTES).await?)
}

fn decode(value: Option<&Value>) -> Result<Ledger, AuthError> {
    let Some(value) = value else {
        return Ok(Ledger::new());
    };
    let encoded = value
        .as_str()
        .filter(|s| s.len() <= HARD_MAX_BYTES)
        .ok_or_else(|| AuthError::State("invalid challenge ledger".into()))?;
    let ledger: Ledger = serde_json::from_str(encoded)
        .map_err(|_error| AuthError::State("invalid challenge ledger".into()))?;
    if ledger.len() > HARD_MAX_PENDING
        || ledger
            .values()
            .any(|entry| entry.binding.is_mfa() == matches!(entry.phase, Phase::SingleUse))
    {
        return Err(AuthError::State("invalid challenge ledger limits".into()));
    }
    Ok(ledger)
}

fn encode(ledger: &Ledger, max_bytes: usize) -> Result<Value, AuthError> {
    let encoded = serde_json::to_string(ledger)
        .map_err(|_error| AuthError::State("challenge encoding failed".into()))?;
    // Admission reserves the exact expansion from Ready to InFlight so claim
    // does not need configuration or additional capacity after admission.
    let ready = ledger
        .values()
        .filter(|entry| matches!(entry.phase, Phase::Ready { .. }))
        .count();
    let reserved = ready * continuations::claim_reservation_bytes()?;
    if encoded.len().saturating_add(reserved) > max_bytes.min(HARD_MAX_BYTES) {
        return Err(AuthError::CapacityExceeded);
    }
    Ok(Value::string(encoded))
}

async fn commit(
    state: &Backend,
    path: &Path,
    expected: Option<Value>,
    value: Value,
) -> Result<bool, AuthError> {
    match state
        .write_cas_bounded(path, expected, value, MAX_LEDGER_ROW_BYTES)
        .await
    {
        Ok(_) => Ok(true),
        Err(StateFailure {
            error: xolotl_state::StateError::CasFailed { .. },
            ..
        }) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn issue<T: Serialize>(
    runtime: &HostRuntime,
    state: &Backend,
    config: &ConsoleChallengeConfig,
    binding: Binding,
    source: &str,
    expires_at: i64,
    payload: &T,
) -> Result<String, AuthError> {
    if binding.is_mfa() {
        return Err(AuthError::InvalidChallenge);
    }
    let pending = Pending {
        binding,
        source_hash: token_hash(source),
        expires_at,
        phase: Phase::SingleUse,
        payload: encode_payload(payload)?,
    };
    admit(runtime, state, config, pending).await
}

fn encode_payload<T: Serialize>(payload: &T) -> Result<serde_json::Value, AuthError> {
    let encoded = serde_json::to_string(payload)
        .map_err(|_error| AuthError::State("challenge encoding failed".into()))?;
    if encoded.len() > MAX_PAYLOAD_BYTES {
        return Err(AuthError::CapacityExceeded);
    }
    serde_json::from_str(&encoded).map_err(|_error| AuthError::InvalidChallenge)
}

async fn admit(
    runtime: &HostRuntime,
    state: &Backend,
    config: &ConsoleChallengeConfig,
    pending: Pending,
) -> Result<String, AuthError> {
    let id = random_token(18)?;
    let path = Path::parse(LEDGER)?;
    for _ in 0..CAS_ATTEMPTS {
        let expected = read_ledger(state, &path).await?;
        let mut ledger = decode(expected.as_ref())?;
        let now = runtime.now_millis();
        if pending.expires_at <= now {
            return Err(AuthError::InvalidChallenge);
        }
        ledger.retain(|_, entry| entry.expires_at > now);
        if ledger.len() >= config.max_pending_global
            || ledger
                .values()
                .filter(|entry| entry.binding.same_owner(&pending.binding))
                .count()
                >= config.max_pending_per_user
            || ledger
                .values()
                .filter(|entry| entry.source_hash == pending.source_hash)
                .count()
                >= config.max_pending_per_source
        {
            return Err(AuthError::CapacityExceeded);
        }
        if ledger.insert(id.clone(), pending.clone()).is_some() {
            return Err(AuthError::InvalidChallenge);
        }
        let value = encode(&ledger, config.max_bytes)?;
        if commit(state, &path, expected, value).await? {
            if pending.expires_at <= runtime.now_millis() {
                return Err(AuthError::InvalidChallenge);
            }
            return Ok(id);
        }
    }
    Err(AuthError::CapacityExceeded)
}

/// Atomically remove a ceremony only when its complete binding matches. A wrong
/// account, session, origin or purpose cannot consume another ceremony. Consuming
/// an expired matching entry also reclaims it. Concurrent finishes have one winner.
pub(super) async fn take<T: DeserializeOwned>(
    runtime: &HostRuntime,
    state: &Backend,
    id: &str,
    binding: &Binding,
) -> Result<T, AuthError> {
    if binding.is_mfa() {
        return Err(AuthError::InvalidChallenge);
    }
    validate_session_id(id).map_err(|_error| AuthError::InvalidChallenge)?;
    let path = Path::parse(LEDGER)?;
    for _ in 0..CAS_ATTEMPTS {
        let expected = read_ledger(state, &path).await?;
        let mut ledger = decode(expected.as_ref())?;
        let entry = ledger
            .remove(id)
            .filter(|entry| &entry.binding == binding && matches!(entry.phase, Phase::SingleUse))
            .ok_or(AuthError::InvalidChallenge)?;
        let value = encode(&ledger, HARD_MAX_BYTES)?;
        if commit(state, &path, expected, value).await? {
            if entry.expires_at <= runtime.now_millis() {
                return Err(AuthError::InvalidChallenge);
            }
            return serde_json::from_value(entry.payload)
                .map_err(|_error| AuthError::InvalidChallenge);
        }
    }
    Err(AuthError::CapacityExceeded)
}

#[cfg(test)]
mod tests;
