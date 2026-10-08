//! Stable account instances and the host-owned account authority port.

use super::{
    AuthError, ConsoleAuth, UserRecord, VerifiedExternalIdentity, effective_grants,
    validate_session_id,
};
use std::time::Duration;
use std::{future::Future, pin::Pin};
use thiserror::Error;
use xolotl_state::Backend;
use xolotl_types::{CapSet, Path};

pub(crate) const LOCAL_AUTHORITY_ID: &str = "local";

/// An account instance, including the authority that minted its identifier.
/// Neither a display name nor an authentication subject is an account key.
#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountKey {
    authority_id: String,
    instance_id: String,
}

impl AccountKey {
    /// Construct a stable key from two authority-owned, path-safe identifiers.
    pub fn new(
        authority_id: impl Into<String>,
        instance_id: impl Into<String>,
    ) -> Result<Self, AccountAuthorityError> {
        let key = Self {
            authority_id: authority_id.into(),
            instance_id: instance_id.into(),
        };
        if !key.is_valid() {
            return Err(AccountAuthorityError::InvalidSnapshot);
        }
        Ok(key)
    }

    pub(crate) fn local(instance_id: &str) -> Self {
        Self {
            authority_id: LOCAL_AUTHORITY_ID.into(),
            instance_id: instance_id.into(),
        }
    }

    pub(crate) fn from_parts(authority_id: &str, instance_id: &str) -> Self {
        Self {
            authority_id: authority_id.into(),
            instance_id: instance_id.into(),
        }
    }

    /// Identifier of the authority that owns this account instance.
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    /// Never-reused instance identifier within the authority.
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub(crate) fn is_valid(&self) -> bool {
        valid_key_segment(&self.authority_id) && valid_key_segment(&self.instance_id)
    }
}

fn valid_key_segment(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && xolotl_types::path::is_simple_id_segment(id)
}

/// A current, trusted account observation. Grants are account authorization,
/// independent of the primary proof and any Console-owned second factors.
#[derive(Clone, Debug)]
pub struct AccountSnapshot {
    /// Stable account instance.
    pub key: AccountKey,
    /// Human-readable audit label. It must never be used for ownership lookup.
    pub display_name: String,
    /// Concrete Kernel identity supplied by the authority.
    pub identity: Path,
    /// Whether the account currently admits new work.
    pub active: bool,
    /// Current authority before session and Console exposure ceilings.
    pub grants: CapSet,
    /// Changes whenever this account's existing sessions must be revoked.
    pub revocation_epoch: String,
}

impl AccountSnapshot {
    pub(crate) fn validate(&self, expected_authority: &str) -> Result<(), AccountAuthorityError> {
        if !self.key.is_valid()
            || self.key.authority_id() != expected_authority
            || self.display_name.is_empty()
            || self.display_name.len() > 256
            || self.display_name.chars().any(char::is_control)
            || self.revocation_epoch.is_empty()
            || self.revocation_epoch.len() > 128
            || self.revocation_epoch.chars().any(char::is_control)
            || self.identity.to_string().len() > 4096
            || self.identity.cluster().is_some()
            || xolotl_kernel::identity::validate_path(&self.identity).is_err()
            || self.grants.len() > 1024
        {
            return Err(AccountAuthorityError::InvalidSnapshot);
        }
        Ok(())
    }
}

/// A missing/revoked account is distinct from an authority that cannot be read.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AccountAuthorityError {
    /// The binding or account no longer exists.
    #[error("account was not found or has been revoked")]
    NotFound,
    /// The authority could not establish current account state.
    #[error("account authority is temporarily unavailable")]
    Unavailable,
    /// The installed authority returned malformed or inconsistent facts.
    #[error("account authority returned an invalid snapshot")]
    InvalidSnapshot,
}

/// An asynchronous account-authority query.
pub type AccountFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, AccountAuthorityError>> + Send + 'a>>;

/// Host account authority. Implementations must provide one stable source ID
/// across restarts and never reassign an instance ID to another account.
pub trait AccountAuthority: Send + Sync + 'static {
    /// Stable source ID; `local` is reserved for Console-managed accounts.
    fn authority_id(&self) -> &str;

    /// Locate the stable account key using only trusted verifier facts.
    fn resolve<'a>(&'a self, proof: &'a VerifiedExternalIdentity) -> AccountFuture<'a, AccountKey>;

    /// Read current status and grants by stable key for every authorization use.
    fn current<'a>(&'a self, key: &'a AccountKey) -> AccountFuture<'a, AccountSnapshot>;
}

impl ConsoleAuth {
    pub(crate) fn external_accounts(&self) -> bool {
        self.account_authority.is_some()
    }

    pub(super) async fn local_snapshot(
        &self,
        state: &Backend,
        user: &UserRecord,
    ) -> Result<AccountSnapshot, AuthError> {
        if self.external_accounts() {
            return Err(AuthError::AccountAuthorityNotConfigured);
        }
        let snapshot = AccountSnapshot {
            key: user.account_key(),
            display_name: user.username.clone(),
            identity: Path::parse(&user.identity_path)?,
            active: user.status == "active",
            grants: effective_grants(state, user).await?,
            revocation_epoch: user.version().to_string(),
        };
        snapshot
            .validate(LOCAL_AUTHORITY_ID)
            .map_err(map_authority_error)?;
        Ok(snapshot)
    }

    pub(super) async fn resolve_external_account(
        &self,
        state: &Backend,
        proof: &VerifiedExternalIdentity,
    ) -> Result<AccountSnapshot, AuthError> {
        let authority = self
            .account_authority
            .as_ref()
            .ok_or(AuthError::AccountAuthorityNotConfigured)?;
        let deadline = crate::host_time::after(&self.host_runtime, Duration::from_secs(10))
            .map_err(|_error| AuthError::AccountAuthorityUnavailable)?;
        let key =
            crate::host_time::timeout_at(&self.host_runtime, deadline, authority.resolve(proof))
                .await
                .map_err(|_error| AuthError::AccountAuthorityUnavailable)?
                .map_err(map_authority_error)?;
        if !key.is_valid() || key.authority_id() != authority.authority_id() {
            return Err(AuthError::State("invalid account authority key".into()));
        }
        self.current_account(state, &key, None).await
    }

    pub(super) async fn current_account(
        &self,
        state: &Backend,
        key: &AccountKey,
        local_username_hint: Option<&str>,
    ) -> Result<AccountSnapshot, AuthError> {
        if !key.is_valid() {
            return Err(AuthError::AccountUnavailable);
        }
        if key.authority_id() == LOCAL_AUTHORITY_ID {
            if self.external_accounts() {
                return Err(AuthError::AccountAuthorityUnavailable);
            }
            let username = local_username_hint.ok_or(AuthError::AccountUnavailable)?;
            let user = super::read_user(state, username)
                .await?
                .ok_or(AuthError::AccountUnavailable)?;
            if user.account_key() != *key {
                return Err(AuthError::AccountUnavailable);
            }
            return self.local_snapshot(state, &user).await;
        }
        let authority = self
            .account_authority
            .as_ref()
            .ok_or(AuthError::AccountAuthorityUnavailable)?;
        if authority.authority_id() != key.authority_id() {
            return Err(AuthError::AccountAuthorityUnavailable);
        }
        let deadline = crate::host_time::after(&self.host_runtime, Duration::from_secs(10))
            .map_err(|_error| AuthError::AccountAuthorityUnavailable)?;
        let snapshot =
            crate::host_time::timeout_at(&self.host_runtime, deadline, authority.current(key))
                .await
                .map_err(|_error| AuthError::AccountAuthorityUnavailable)?
                .map_err(map_authority_error)?;
        snapshot
            .validate(authority.authority_id())
            .map_err(map_authority_error)?;
        if snapshot.key != *key {
            return Err(AuthError::AccountUnavailable);
        }
        Ok(snapshot)
    }
}

fn map_authority_error(error: AccountAuthorityError) -> AuthError {
    match error {
        AccountAuthorityError::NotFound => AuthError::AccountUnavailable,
        AccountAuthorityError::Unavailable => AuthError::AccountAuthorityUnavailable,
        AccountAuthorityError::InvalidSnapshot => {
            AuthError::State("invalid account authority snapshot".into())
        }
    }
}

/// Managed local accounts always act through a path owned by their instance.
pub(super) fn local_identity_path(instance_id: &str) -> Result<String, AuthError> {
    if instance_id.len() > 128 {
        return Err(AuthError::AccountUnavailable);
    }
    validate_session_id(instance_id).map_err(|_error| AuthError::AccountUnavailable)?;
    Ok(format!("identity://console/accounts/{instance_id}"))
}
