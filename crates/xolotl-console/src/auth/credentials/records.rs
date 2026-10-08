//! A bounded vault record is the serialization point for all account credentials.

use super::super::*;
use serde_json::Value as JsonValue;
use std::num::NonZeroUsize;

const SEALED_PREFIX: &str = "xolotl-credential-v1:";

pub(in crate::auth) const MAX_FACTORS: usize = 8;
pub(in crate::auth) const RECOVERY_COUNT: usize = 10;
pub(in crate::auth) const MAX_PASSKEYS: usize = 32;
pub(in crate::auth) const MAX_PUBLIC_KEYS: usize = 32;
pub(in crate::auth) const MAX_CREDENTIAL_BYTES: usize = 256 * 1024;
// The bound covers base64url ciphertext and the State string envelope.
pub(in crate::auth) const MAX_CREDENTIAL_ROW_BYTES: NonZeroUsize =
    NonZeroUsize::new(MAX_CREDENTIAL_BYTES * 3 / 2 + 4096).unwrap();

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::auth) struct AccountCredentials {
    pub authority_id: String,
    pub account_id: String,
    pub epoch: String,
    pub password: Option<String>,
    pub password_changed_at: Option<i64>,
    pub public_keys: Vec<String>,
    pub passkeys: BTreeMap<String, StoredPasskey>,
    pub factors: BTreeMap<String, StoredFactor>,
    pub recovery: Vec<String>,
    pub pending: Option<PendingEnrollment>,
    #[serde(skip)]
    pub persisted: Option<Value>,
}

#[derive(Serialize, Deserialize)]
pub(in crate::auth) struct StoredPasskey {
    pub credential: Passkey,
    pub label: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::auth) struct StoredFactor {
    pub provider_id: String,
    pub label: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    pub verifier: JsonValue,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::auth) struct PendingEnrollment {
    pub id: String,
    pub sid: String,
    pub factor_id: String,
    pub provider_id: String,
    pub label: String,
    pub replace_factor_id: Option<String>,
    pub expires_at: i64,
    /// Number of provider calls already completed, including begin.
    pub round: u16,
    pub waiting: EnrollmentWaiting,
    pub phase: EnrollmentPhase,
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::auth) enum EnrollmentWaiting {
    Starting {},
    Challenge {
        private_state: JsonValue,
        setup: JsonValue,
        response_schema: JsonValue,
    },
    Pending {
        private_state: JsonValue,
        status: JsonValue,
        not_before: i64,
    },
}

impl EnrollmentWaiting {
    pub fn private_state(&self) -> Option<&JsonValue> {
        match self {
            Self::Starting {} => None,
            Self::Challenge { private_state, .. } | Self::Pending { private_state, .. } => {
                Some(private_state)
            }
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::auth) enum EnrollmentPhase {
    Ready {},
    InFlight { claim_id: String },
}

pub(in crate::auth) fn valid_provider_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

// Factor, enrollment and session identities are minted from 18 random bytes.
pub(in crate::auth) fn valid_opaque_id(id: &str) -> bool {
    id.len() == 25 && id.starts_with('t') && validate_session_id(id).is_ok()
}

fn valid_factor_metadata(factor: &StoredFactor) -> bool {
    valid_provider_id(&factor.provider_id)
        && super::validate_label(&factor.label).is_ok()
        && factor.created_at >= 0
        && factor
            .last_used_at
            .is_none_or(|last_used_at| last_used_at >= factor.created_at)
}

fn valid_pending(record: &AccountCredentials, pending: &PendingEnrollment) -> bool {
    valid_opaque_id(&pending.id)
        && valid_opaque_id(&pending.sid)
        && valid_opaque_id(&pending.factor_id)
        && !record.factors.contains_key(&pending.factor_id)
        && valid_provider_id(&pending.provider_id)
        && super::validate_label(&pending.label).is_ok()
        && pending.expires_at > 0
        && match (&pending.waiting, &pending.phase) {
            (EnrollmentWaiting::Starting {}, EnrollmentPhase::InFlight { .. }) => {
                pending.round == 0
            }
            (EnrollmentWaiting::Starting {}, EnrollmentPhase::Ready {}) => false,
            (
                EnrollmentWaiting::Challenge {
                    private_state,
                    setup,
                    response_schema,
                },
                _,
            ) => {
                (1..=32).contains(&pending.round)
                    && crate::auth::mfa::bounded_json(private_state)
                    && crate::auth::mfa::bounded_json(setup)
                    && crate::auth::mfa::valid_schema(response_schema)
            }
            (
                EnrollmentWaiting::Pending {
                    private_state,
                    status,
                    not_before,
                },
                _,
            ) => {
                (1..=32).contains(&pending.round)
                    && *not_before > 0
                    && *not_before <= pending.expires_at
                    && crate::auth::mfa::bounded_json(private_state)
                    && crate::auth::mfa::bounded_json(status)
            }
        }
        && match &pending.phase {
            EnrollmentPhase::Ready {} => true,
            EnrollmentPhase::InFlight { claim_id } => valid_opaque_id(claim_id),
        }
        && match &pending.replace_factor_id {
            Some(id) => record
                .factors
                .get(id)
                .is_some_and(|factor| factor.provider_id == pending.provider_id),
            None => record.factors.len() < MAX_FACTORS,
        }
}

impl AccountCredentials {
    pub fn has_primary(&self) -> bool {
        self.password.is_some() || !self.public_keys.is_empty() || !self.passkeys.is_empty()
    }

    pub fn rotate_epoch(&mut self) -> Result<(), AuthError> {
        self.epoch = random_token(18)?;
        self.pending = None;
        Ok(())
    }
}

fn path(key: &AccountKey) -> Result<Path, AuthError> {
    if !key.is_valid() {
        return Err(AuthError::AccountUnavailable);
    }
    Ok(crate::paths::credential_path(
        key.authority_id(),
        key.instance_id(),
    )?)
}

pub(in crate::auth) async fn read(
    state: &Backend,
    username: &str,
    sealer: &CredentialSealer,
) -> Result<AccountCredentials, AuthError> {
    validate_username(username)?;
    let Some(user) = read_user(state, username).await? else {
        return Ok(AccountCredentials::default());
    };
    read_by_key(state, &user.account_key(), sealer).await
}

pub(in crate::auth) async fn read_by_key(
    state: &Backend,
    key: &AccountKey,
    sealer: &CredentialSealer,
) -> Result<AccountCredentials, AuthError> {
    let Some(value) = state
        .read_bounded(&path(key)?, MAX_CREDENTIAL_ROW_BYTES)
        .await?
    else {
        return Ok(AccountCredentials {
            authority_id: key.authority_id().into(),
            account_id: key.instance_id().into(),
            ..Default::default()
        });
    };
    let ciphertext = value
        .as_str()
        .filter(|value| value.len() <= MAX_CREDENTIAL_ROW_BYTES.get())
        .and_then(|value| value.strip_prefix(SEALED_PREFIX))
        .ok_or_else(|| AuthError::State("invalid credential record".into()))?;
    // URL_SAFE_NO_PAD requires no padding and rejects nonzero trailing bits;
    // successful decoding has one canonical textual representation.
    let envelope = zeroize::Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(ciphertext.as_bytes())
            .map_err(|_error| AuthError::State("invalid credential record".into()))?,
    );
    let encoded = sealer.open(key.authority_id(), key.instance_id(), envelope)?;
    if encoded.len() > MAX_CREDENTIAL_BYTES {
        return Err(AuthError::State("invalid credential record".into()));
    }
    let mut record: AccountCredentials = serde_json::from_slice(&encoded)
        .map_err(|_error| AuthError::State("invalid credential record".into()))?;
    if record.authority_id != key.authority_id() || record.account_id != key.instance_id() {
        return Err(AuthError::State("credential identity mismatch".into()));
    }
    if record.factors.len() > MAX_FACTORS
        || record.recovery.len() > RECOVERY_COUNT
        || record.passkeys.len() > MAX_PASSKEYS
        || record.public_keys.len() > MAX_PUBLIC_KEYS
        || ((record.has_primary() || !record.factors.is_empty()) && record.epoch.is_empty())
        || (record.factors.is_empty() && !record.recovery.is_empty())
        || record
            .factors
            .iter()
            .any(|(id, factor)| !valid_opaque_id(id) || !valid_factor_metadata(factor))
        || record
            .pending
            .as_ref()
            .is_some_and(|pending| !valid_pending(&record, pending))
        || record
            .passkeys
            .iter()
            .any(|(id, stored)| id != &passkey_credential_id(&stored.credential))
    {
        return Err(AuthError::State(
            "invalid credential record metadata or limits".into(),
        ));
    }
    record.persisted = Some(value);
    Ok(record)
}

pub(in crate::auth) async fn write(
    state: &Backend,
    username: &str,
    record: &AccountCredentials,
    sealer: &CredentialSealer,
) -> Result<(), AuthError> {
    validate_username(username)?;
    let user = read_user(state, username)
        .await?
        .ok_or(AuthError::AccountUnavailable)?;
    if record.authority_id != user.account_key().authority_id()
        || record.account_id != user.account_id
    {
        return Err(AuthError::CredentialConflict);
    }
    write_by_key(state, &user.account_key(), record, sealer).await
}

pub(in crate::auth) async fn write_by_key(
    state: &Backend,
    key: &AccountKey,
    record: &AccountCredentials,
    sealer: &CredentialSealer,
) -> Result<(), AuthError> {
    write_with_headroom(state, key, record, 0, sealer).await
}

pub(in crate::auth) async fn write_reserving_enrollment_claim_by_key(
    state: &Backend,
    key: &AccountKey,
    record: &AccountCredentials,
    sealer: &CredentialSealer,
) -> Result<(), AuthError> {
    if !record
        .pending
        .as_ref()
        .is_some_and(|pending| matches!(pending.phase, EnrollmentPhase::Ready {}))
    {
        return Err(AuthError::InvalidMfaRequest);
    }
    let ready = serde_json::to_string(&EnrollmentPhase::Ready {})
        .map_err(|_error| AuthError::State("credential encoding failed".into()))?;
    let in_flight = serde_json::to_string(&EnrollmentPhase::InFlight {
        claim_id: "t000000000000000000000000".into(),
    })
    .map_err(|_error| AuthError::State("credential encoding failed".into()))?;
    let extra = in_flight.len() - ready.len();
    write_with_headroom(state, key, record, extra, sealer).await
}

async fn write_with_headroom(
    state: &Backend,
    key: &AccountKey,
    record: &AccountCredentials,
    extra: usize,
    sealer: &CredentialSealer,
) -> Result<(), AuthError> {
    let encoded = zeroize::Zeroizing::new(
        serde_json::to_vec(record)
            .map_err(|_error| AuthError::State("credential encoding failed".into()))?,
    );
    if encoded.len() > MAX_CREDENTIAL_BYTES.saturating_sub(extra) {
        return Err(AuthError::InvalidCredentialRequest);
    }
    let sealed = sealer.seal(key.authority_id(), key.instance_id(), encoded)?;
    let mut stored = String::with_capacity(SEALED_PREFIX.len() + sealed.len().div_ceil(3) * 4);
    stored.push_str(SEALED_PREFIX);
    URL_SAFE_NO_PAD.encode_string(&sealed, &mut stored);
    match state
        .write_cas_bounded(
            &path(key)?,
            record.persisted.clone(),
            Value::string(stored),
            MAX_CREDENTIAL_ROW_BYTES,
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(StateFailure {
            error: xolotl_state::StateError::CasFailed { .. },
            ..
        }) => Err(AuthError::CredentialConflict),
        Err(error) => Err(error.into()),
    }
}

pub(in crate::auth) async fn epoch(
    state: &Backend,
    username: &str,
    sealer: &CredentialSealer,
) -> Result<String, AuthError> {
    Ok(read(state, username, sealer).await?.epoch)
}

pub(in crate::auth) async fn epoch_by_key(
    state: &Backend,
    key: &AccountKey,
    sealer: &CredentialSealer,
) -> Result<String, AuthError> {
    Ok(read_by_key(state, key, sealer).await?.epoch)
}
