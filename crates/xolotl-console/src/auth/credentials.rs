//! Primary credentials and second factors share one vault CAS and policy epoch.

use super::*;
use crate::credentials::{
    CredentialOperation, CredentialRequest, CredentialResponse, PasskeySummary,
};
mod records;
pub(super) use records::*;

pub(super) fn validate_label(label: &str) -> Result<(), AuthError> {
    if label.trim().is_empty() || label.len() > 128 || label.chars().any(char::is_control) {
        return Err(AuthError::InvalidCredentialRequest);
    }
    Ok(())
}

pub(super) fn canonical_public_key(key: &str) -> Result<String, AuthError> {
    let key = parse_ml_dsa_65_key_descriptor(key)
        .map_err(|_error| AuthError::InvalidCredentialRequest)?;
    Ok(format!(
        "ml-dsa-65:{}",
        URL_SAFE_NO_PAD.encode(key.as_ref())
    ))
}

pub(super) fn public_keys(keys: &[String]) -> Result<Vec<String>, AuthError> {
    if keys.len() > MAX_PUBLIC_KEYS {
        return Err(AuthError::InvalidCredentialRequest);
    }
    let mut keys = keys
        .iter()
        .map(|key| canonical_public_key(key))
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort();
    keys.dedup();
    Ok(keys)
}

impl ConsoleAuth {
    pub(crate) async fn manage_credentials(
        &self,
        boot: &Bootstrap,
        bearer: &str,
        request: CredentialRequest,
        source: String,
    ) -> Result<CredentialResponse, AuthError> {
        if self.external_accounts() {
            return Err(AuthError::LocalAuthenticationUnavailable);
        }
        let state = boot.kernel().state();
        let principal = self.authenticate_token(boot, bearer).await?;
        let username = request.username.as_deref().unwrap_or(&principal.username);
        validate_username(username)?;
        let user = read_user(state, username)
            .await?
            .ok_or(AuthError::AccountUnavailable)?;
        let own = user.account_key() == principal.account_key();
        let modifying = !matches!(request.operation, CredentialOperation::Status {});
        if !own {
            self.recent_credential_management(state, bearer, &principal)
                .await?;
            if principal.authentication.mfa_level() < 2 {
                return Err(AuthError::MfaRequired { options: None });
            }
            // Even metadata about another account needs authority over that
            // account, including its effective grants and the root boundary.
            authorize_path(state, &principal, "write", &user_path(username)?, None).await?;
        }
        let mut record = read(state, username, self.credential_sealer()?).await?;
        if !modifying {
            return Ok(CredentialResponse::Current {
                username: username.into(),
                password_enabled: record.password.is_some(),
                password_changed_at: record.password_changed_at,
                public_keys: record.public_keys,
                passkeys: record
                    .passkeys
                    .into_iter()
                    .map(|(credential_id, stored)| PasskeySummary {
                        credential_id,
                        label: stored.label,
                        created_at: stored.created_at,
                        last_used_at: stored.last_used_at,
                    })
                    .collect(),
                max_passkeys: MAX_PASSKEYS,
                max_public_keys: MAX_PUBLIC_KEYS,
            });
        }
        let authorized_epoch = self
            .recent_credential_management(state, bearer, &principal)
            .await?;
        if own && record.epoch != authorized_epoch {
            return Err(AuthError::InvalidSession);
        }
        self.mfa_limits(state, &principal.username, &source).await?;
        let event = match &request.operation {
            CredentialOperation::Status {} => "credential_status",
            CredentialOperation::SetPassword { .. } => "password_set",
            CredentialOperation::DisablePassword {} => "password_disable",
            CredentialOperation::AddPublicKey { .. } => "public_key_add",
            CredentialOperation::RemovePublicKey { .. } => "public_key_remove",
            CredentialOperation::RenamePasskey { .. } => "passkey_rename",
            CredentialOperation::RevokePasskey { .. } => "passkey_revoke",
            CredentialOperation::ResetSecondFactors {} => "second_factors_reset",
        };
        let invalidate = !matches!(request.operation, CredentialOperation::RenamePasskey { .. });
        match request.operation {
            CredentialOperation::SetPassword { password } => {
                crate::credentials::enforce_password_strength(
                    &crate::credentials::PasswordPolicy::default().bounded(),
                    username,
                    &password,
                )
                .map_err(|_error| AuthError::InvalidCredentialRequest)?;
                record.password = Some(self.passwords.hash(password).await?);
                record.password_changed_at = Some(self.host_runtime.now_millis());
            }
            CredentialOperation::DisablePassword {} => {
                if record.password.take().is_none() {
                    return Err(AuthError::InvalidCredentialRequest);
                }
                record.password_changed_at = Some(self.host_runtime.now_millis());
            }
            CredentialOperation::AddPublicKey { key } => {
                let key = canonical_public_key(&key)?;
                if record.public_keys.len() >= MAX_PUBLIC_KEYS || record.public_keys.contains(&key)
                {
                    return Err(AuthError::InvalidCredentialRequest);
                }
                record.public_keys.push(key);
                record.public_keys.sort();
            }
            CredentialOperation::RemovePublicKey { key } => {
                let key = canonical_public_key(&key)?;
                let index = record
                    .public_keys
                    .iter()
                    .position(|entry| entry == &key)
                    .ok_or(AuthError::InvalidCredentialRequest)?;
                record.public_keys.remove(index);
            }
            CredentialOperation::RenamePasskey {
                credential_id,
                label,
            } => {
                validate_label(&label)?;
                record
                    .passkeys
                    .get_mut(&credential_id)
                    .ok_or(AuthError::InvalidCredentialRequest)?
                    .label = label;
            }
            CredentialOperation::RevokePasskey { credential_id } => {
                if record.passkeys.remove(&credential_id).is_none() {
                    return Err(AuthError::InvalidCredentialRequest);
                }
            }
            CredentialOperation::ResetSecondFactors {} => {
                if own || record.factors.is_empty() {
                    return Err(AuthError::InvalidCredentialRequest);
                }
                record.factors.clear();
                record.recovery.clear();
                record.pending = None;
            }
            CredentialOperation::Status {} => return Err(AuthError::InvalidCredentialRequest),
        }
        if !record.has_primary() {
            return Err(AuthError::LastPrimaryCredential);
        }
        if invalidate {
            record.rotate_epoch()?;
        }
        // Revalidate after asynchronous password work and before committing.
        if read_user(state, username).await?.map(|user| user.persisted)
            != Some(user.persisted.clone())
        {
            return Err(AuthError::CredentialConflict);
        }
        if !own {
            authorize_path(
                state,
                &principal,
                "write",
                &user_path(username)?,
                Some(&user.to_value()),
            )
            .await?;
        }
        // Target-authority reads can also outlive the management window.
        let current_principal = self.authenticate_token(boot, bearer).await?;
        if current_principal != principal
            || self
                .recent_credential_management(state, bearer, &current_principal)
                .await?
                != authorized_epoch
        {
            return Err(AuthError::InvalidSession);
        }
        record_auth_audit(
            boot,
            "console_credential",
            Some(&principal.username),
            Some(&source),
            &format!("{event}_started:{username}"),
            Some(&principal.authentication),
        )?;
        let result = write(state, username, &record, self.credential_sealer()?).await;
        record_auth_audit(
            boot,
            "console_credential",
            Some(&principal.username),
            Some(&source),
            &format!(
                "{event}_{}:{username}",
                if result.is_ok() {
                    "committed"
                } else {
                    "failed"
                }
            ),
            Some(&principal.authentication),
        )?;
        result?;
        let session = if own && invalidate {
            let account = self.local_snapshot(state, &user).await?;
            Some(
                self.issue_session(
                    state,
                    &account,
                    source,
                    principal.authentication,
                    record.epoch,
                    principal.authority_ceiling,
                )
                .await?,
            )
        } else {
            None
        };
        Ok(CredentialResponse::Updated {
            sessions_invalidated: invalidate,
            session,
        })
    }
}

#[cfg(test)]
mod tests;
