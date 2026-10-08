//! Account ownership outlives a connection; authority does not outlive revocation.

use super::*;

/// Immutable account instance and authorization generation captured from a verified SID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionOwner {
    pub username: String,
    pub authority_id: String,
    pub account_id: String,
    revocation_epoch: String,
    credential_epoch: String,
    identity_path: String,
    authority_ceiling: CapSet,
}

impl ExecutionOwner {
    pub(crate) fn account_key(&self) -> AccountKey {
        AccountKey::from_parts(&self.authority_id, &self.account_id)
    }

    /// Historical ownership survives credential rotation and account edits, never recreation.
    pub fn same_account(&self, other: &Self) -> bool {
        self.account_key() == other.account_key()
    }
}

impl ConsoleAuth {
    /// The caller must have authenticated this SID's bearer on the current call.
    /// Reading by username alone would bind a stale session to a recreated account.
    pub(crate) async fn execution_owner(
        &self,
        boot: &Bootstrap,
        sid: &str,
        principal: &ConsolePrincipal,
    ) -> Result<ExecutionOwner, AuthError> {
        let view = self.session_view(boot, sid, false).await?;
        let current = view.principal;
        if current.account_key() != principal.account_key()
            || current.identity_path != principal.identity_path
            || current.authentication != principal.authentication
        {
            return Err(AuthError::InvalidSession);
        }
        Ok(ExecutionOwner {
            username: view.username,
            authority_id: current.authority_id,
            account_id: current.account_id,
            revocation_epoch: view.revocation_epoch,
            credential_epoch: view.credential_epoch,
            identity_path: current.identity_path,
            authority_ceiling: current.authority_ceiling.ok_or(AuthError::InvalidSession)?,
        })
    }

    pub(crate) async fn execution_delivery(
        &self,
        boot: &Bootstrap,
        sid: &str,
        principal: &ConsolePrincipal,
        owner: &ExecutionOwner,
    ) -> Result<ConsolePrincipal, AuthError> {
        let view = self.session_view(boot, sid, false).await?;
        let current = view.principal;
        if current != *principal
            || view.username != owner.username
            || current.authority_id != owner.authority_id
            || current.account_id != owner.account_id
            || current.identity_path != owner.identity_path
            || view.revocation_epoch != owner.revocation_epoch
            || view.credential_epoch != owner.credential_epoch
            || current.authority_ceiling.as_ref() != Some(&owner.authority_ceiling)
        {
            return Err(AuthError::PermissionDenied);
        }
        Ok(current)
    }

    /// Recheck account generation and current role grants without authenticating
    /// a session or claiming any new authentication evidence.
    pub(crate) async fn execution_grants(
        &self,
        boot: &Bootstrap,
        owner: &ExecutionOwner,
    ) -> Result<CapSet, AuthError> {
        let state = boot.kernel().state();
        let account = self
            .current_account(state, &owner.account_key(), Some(&owner.username))
            .await?;
        if !account.active
            || account.revocation_epoch != owner.revocation_epoch
            || account.identity.to_string() != owner.identity_path
            || credentials::epoch_by_key(state, &account.key, self.credential_sealer()?).await?
                != owner.credential_epoch
        {
            return Err(AuthError::AccountUnavailable);
        }
        effective_session_grants(&account.grants, &owner.authority_ceiling)
    }
}
