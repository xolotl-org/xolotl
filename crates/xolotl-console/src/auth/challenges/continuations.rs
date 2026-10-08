//! One ledger slot owns every round, including provider work and cancellation.

use super::*;

const ID_LENGTH: usize = 25;
const SECRET_LENGTH: usize = 44;
const TOKEN_LENGTH: usize = ID_LENGTH + 1 + SECRET_LENGTH;

pub(in crate::auth) struct Continuation<T> {
    pub binding: Binding,
    pub expires_at: i64,
    pub payload: T,
}

/// A successful claim is the sole authority to publish or retire this round.
/// The nonce stays private and no public request can construct this value.
pub(in crate::auth) struct Round<T> {
    pub payload: T,
    pub expires_at: i64,
    pub ceremony_id: String,
    binding: Binding,
    claim: String,
}

pub(super) fn claim_reservation_bytes() -> Result<usize, AuthError> {
    let ready = Phase::Ready {
        token_hash: String::new(),
    };
    let inflight = Phase::InFlight {
        token_hash: String::new(),
        claim: "x".repeat(ID_LENGTH),
        cancelled: false,
    };
    let size = |phase: &Phase| {
        serde_json::to_string(phase)
            .map(|encoded| encoded.len())
            .map_err(|_error| AuthError::State("challenge encoding failed".into()))
    };
    Ok(size(&inflight)? - size(&ready)?)
}

struct Token<'a> {
    id: &'a str,
    hash: String,
}

impl<'a> Token<'a> {
    fn parse(token: &'a str) -> Result<Self, AuthError> {
        if token.len() != TOKEN_LENGTH {
            return Err(AuthError::InvalidChallenge);
        }
        let (id, secret) = token.split_once('.').ok_or(AuthError::InvalidChallenge)?;
        if id.len() != ID_LENGTH
            || secret.len() != SECRET_LENGTH
            || !id.starts_with('t')
            || !secret.starts_with('t')
            || validate_session_id(id).is_err()
            || validate_session_id(secret).is_err()
        {
            return Err(AuthError::InvalidChallenge);
        }
        Ok(Self {
            id,
            hash: token_hash(secret),
        })
    }

    fn check(&self, entry: &Pending, now: i64) -> Result<(), AuthError> {
        let expected = match &entry.phase {
            Phase::Ready { token_hash } | Phase::InFlight { token_hash, .. } => token_hash,
            Phase::SingleUse => return Err(AuthError::InvalidChallenge),
        };
        if !entry.binding.is_mfa()
            || expected.as_bytes().ct_eq(self.hash.as_bytes()).unwrap_u8() != 1
            || entry.expires_at <= now
        {
            return Err(AuthError::InvalidChallenge);
        }
        Ok(())
    }
}

fn require_mfa(binding: &Binding) -> Result<(), AuthError> {
    if binding.is_mfa() {
        Ok(())
    } else {
        Err(AuthError::InvalidChallenge)
    }
}

fn owns<T>(entry: &Pending, round: &Round<T>) -> bool {
    entry.binding.is_mfa()
        && entry.binding == round.binding
        && matches!(&entry.phase, Phase::InFlight { claim, .. } if claim == &round.claim)
}

fn publishable<T>(entry: &Pending, round: &Round<T>, now: i64) -> bool {
    owns(entry, round)
        && entry.expires_at > now
        && matches!(
            entry.phase,
            Phase::InFlight {
                cancelled: false,
                ..
            }
        )
}

pub(in crate::auth) async fn issue_continuation<T: Serialize>(
    runtime: &HostRuntime,
    state: &Backend,
    config: &ConsoleChallengeConfig,
    binding: Binding,
    source: &str,
    expires_at: i64,
    payload: &T,
) -> Result<String, AuthError> {
    require_mfa(&binding)?;
    let secret = random_token(32)?;
    let pending = Pending {
        binding,
        source_hash: token_hash(source),
        expires_at,
        phase: Phase::Ready {
            token_hash: token_hash(&secret),
        },
        payload: encode_payload(payload)?,
    };
    let id = admit(runtime, state, config, pending).await?;
    Ok(format!("{id}.{secret}"))
}

pub(in crate::auth) async fn inspect<T: DeserializeOwned>(
    runtime: &HostRuntime,
    state: &Backend,
    token: &str,
) -> Result<Continuation<T>, AuthError> {
    let token = Token::parse(token)?;
    let stored = read_ledger(state, &Path::parse(LEDGER)?).await?;
    let mut ledger = decode(stored.as_ref())?;
    let entry = ledger.remove(token.id).ok_or(AuthError::InvalidChallenge)?;
    token.check(&entry, runtime.now_millis())?;
    if !matches!(entry.phase, Phase::Ready { .. }) {
        return Err(AuthError::InvalidChallenge);
    }
    Ok(Continuation {
        binding: entry.binding,
        expires_at: entry.expires_at,
        payload: serde_json::from_value(entry.payload)
            .map_err(|_error| AuthError::InvalidChallenge)?,
    })
}

/// Cancellation may inspect the owner while work is in flight, never its payload.
pub(in crate::auth) async fn inspect_owner(
    runtime: &HostRuntime,
    state: &Backend,
    token: &str,
) -> Result<Binding, AuthError> {
    let token = Token::parse(token)?;
    let stored = read_ledger(state, &Path::parse(LEDGER)?).await?;
    let mut ledger = decode(stored.as_ref())?;
    let entry = ledger.remove(token.id).ok_or(AuthError::InvalidChallenge)?;
    token.check(&entry, runtime.now_millis())?;
    Ok(entry.binding)
}

pub(in crate::auth) async fn claim<T: DeserializeOwned>(
    runtime: &HostRuntime,
    state: &Backend,
    token: &str,
    binding: &Binding,
) -> Result<Round<T>, AuthError> {
    require_mfa(binding)?;
    let token = Token::parse(token)?;
    let nonce = random_token(18)?;
    let path = Path::parse(LEDGER)?;
    for _ in 0..CAS_ATTEMPTS {
        let expected = read_ledger(state, &path).await?;
        let mut ledger = decode(expected.as_ref())?;
        let entry = ledger
            .get_mut(token.id)
            .ok_or(AuthError::InvalidChallenge)?;
        token.check(entry, runtime.now_millis())?;
        if &entry.binding != binding || !matches!(entry.phase, Phase::Ready { .. }) {
            return Err(AuthError::InvalidChallenge);
        }
        let payload = serde_json::from_value(entry.payload.clone())
            .map_err(|_error| AuthError::InvalidChallenge)?;
        let expires_at = entry.expires_at;
        entry.phase = Phase::InFlight {
            token_hash: token.hash.clone(),
            claim: nonce.clone(),
            cancelled: false,
        };
        let value = encode(&ledger, HARD_MAX_BYTES)?;
        if commit(state, &path, expected, value).await? {
            if expires_at <= runtime.now_millis() {
                return Err(AuthError::InvalidChallenge);
            }
            return Ok(Round {
                payload,
                expires_at,
                ceremony_id: token.id.into(),
                binding: binding.clone(),
                claim: nonce,
            });
        }
    }
    Err(AuthError::CapacityExceeded)
}

pub(in crate::auth) async fn advance<T, U: Serialize>(
    runtime: &HostRuntime,
    state: &Backend,
    config: &ConsoleChallengeConfig,
    round: &Round<T>,
    payload: &U,
) -> Result<String, AuthError> {
    let payload = encode_payload(payload)?;
    let secret = random_token(32)?;
    let hash = token_hash(&secret);
    let path = Path::parse(LEDGER)?;
    for _ in 0..CAS_ATTEMPTS {
        let expected = read_ledger(state, &path).await?;
        let mut ledger = decode(expected.as_ref())?;
        let entry = ledger
            .get_mut(&round.ceremony_id)
            .filter(|entry| publishable(entry, round, runtime.now_millis()))
            .ok_or(AuthError::InvalidChallenge)?;
        let expires_at = entry.expires_at;
        entry.phase = Phase::Ready {
            token_hash: hash.clone(),
        };
        entry.payload = payload.clone();
        let value = encode(&ledger, config.max_bytes)?;
        if commit(state, &path, expected, value).await? {
            if expires_at <= runtime.now_millis() {
                return Err(AuthError::InvalidChallenge);
            }
            return Ok(format!("{}.{secret}", round.ceremony_id));
        }
    }
    Err(AuthError::CapacityExceeded)
}

/// Winning this CAS ends cancellation's authority before the credential CAS.
pub(in crate::auth) async fn finish<T>(
    runtime: &HostRuntime,
    state: &Backend,
    round: &Round<T>,
) -> Result<(), AuthError> {
    let path = Path::parse(LEDGER)?;
    for _ in 0..CAS_ATTEMPTS {
        let expected = read_ledger(state, &path).await?;
        let mut ledger = decode(expected.as_ref())?;
        let entry = ledger
            .remove(&round.ceremony_id)
            .filter(|entry| publishable(entry, round, runtime.now_millis()))
            .ok_or(AuthError::InvalidChallenge)?;
        let value = encode(&ledger, HARD_MAX_BYTES)?;
        if commit(state, &path, expected, value).await? {
            return if entry.expires_at > runtime.now_millis() {
                Ok(())
            } else {
                Err(AuthError::InvalidChallenge)
            };
        }
    }
    Err(AuthError::CapacityExceeded)
}

/// Release a failed or cancelled call only after its provider future has stopped.
/// A stale round cannot remove a successor; repeated cleanup is harmless.
pub(in crate::auth) async fn retire<T>(state: &Backend, round: &Round<T>) -> Result<(), AuthError> {
    let path = Path::parse(LEDGER)?;
    for _ in 0..CAS_ATTEMPTS {
        let expected = read_ledger(state, &path).await?;
        let mut ledger = decode(expected.as_ref())?;
        if !ledger
            .get(&round.ceremony_id)
            .is_some_and(|entry| owns(entry, round))
        {
            return Ok(());
        }
        ledger.remove(&round.ceremony_id);
        let value = encode(&ledger, HARD_MAX_BYTES)?;
        if commit(state, &path, expected, value).await? {
            return Ok(());
        }
    }
    Err(AuthError::CapacityExceeded)
}

pub(in crate::auth) async fn cancel(
    runtime: &HostRuntime,
    state: &Backend,
    token: &str,
    binding: &Binding,
) -> Result<(), AuthError> {
    require_mfa(binding)?;
    let token = Token::parse(token)?;
    let path = Path::parse(LEDGER)?;
    for _ in 0..CAS_ATTEMPTS {
        let expected = read_ledger(state, &path).await?;
        let mut ledger = decode(expected.as_ref())?;
        let entry = ledger
            .get_mut(token.id)
            .ok_or(AuthError::InvalidChallenge)?;
        token.check(entry, runtime.now_millis())?;
        if &entry.binding != binding {
            return Err(AuthError::InvalidChallenge);
        }
        match &mut entry.phase {
            Phase::Ready { .. } => {
                ledger.remove(token.id);
            }
            Phase::InFlight { cancelled, .. } if !*cancelled => *cancelled = true,
            Phase::InFlight { .. } => return Ok(()),
            Phase::SingleUse => return Err(AuthError::InvalidChallenge),
        }
        let value = encode(&ledger, HARD_MAX_BYTES)?;
        if commit(state, &path, expected, value).await? {
            return Ok(());
        }
    }
    Err(AuthError::CapacityExceeded)
}

#[cfg(test)]
mod tests;
