//! Recoverable root provisioning with one active owner and immutable incarnations.

use super::*;

/// Return whether bootstrap would need to generate a random root password.
pub async fn root_random_password_needed(
    boot: &Bootstrap,
    provisioning: &RootProvisioning,
) -> Result<bool, AuthError> {
    credentials::public_keys(&provisioning.pubkeys)?;
    if provisioning.password_hash.is_some()
        || provisioning.password.is_some()
        || !provisioning.pubkeys.is_empty()
    {
        return Ok(false);
    }
    Ok(!matches!(
        root_bootstrap_admission(boot.kernel().state()).await?,
        RootBootstrap::Existing
    ))
}

enum RootBootstrap {
    Fresh,
    Resume(Box<UserRecord>),
    Existing,
}

async fn root_bootstrap_admission(state: &Backend) -> Result<RootBootstrap, AuthError> {
    if let Some(user) = read_user(state, ROOT_USERNAME).await? {
        if !user.bootstrap_owner {
            return Err(AuthError::AccountUnavailable);
        }
        return Ok(
            if user.status == "provisioning" && user.created_by == "bootstrap" {
                RootBootstrap::Resume(Box::new(user))
            } else {
                RootBootstrap::Existing
            },
        );
    }
    Ok(
        if prefix_has_entries(state, Path::parse(USERS_PREFIX)?).await? {
            RootBootstrap::Existing
        } else {
            RootBootstrap::Fresh
        },
    )
}

/// Create the root account if no console users exist.
///
/// A random password is generated only when no password hash or public keys are
/// preseeded. Hashing uses the host's bounded blocking scheduler; dropping the
/// awaiting caller leaves accepted hashing work owned by that scheduler.
/// Successful creation records a bootstrap audit fact.
pub async fn bootstrap_root_account(
    boot: &Bootstrap,
    blocking_spawner: &dyn xolotl_kernel::host::BlockingSpawner,
    provisioning: RootProvisioning,
) -> Result<BootstrapOutcome, AuthError> {
    let sealer = provisioning
        .credential_sealer
        .clone()
        .ok_or_else(|| AuthError::Crypto("console credential encryption key is required".into()))?;
    let outcome = bootstrap_root_account_inner(
        boot.kernel().state(),
        boot.kernel().host_runtime(),
        blocking_spawner,
        provisioning,
        &sealer,
    )
    .await?;
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
    runtime: &xolotl_kernel::host::HostRuntime,
    blocking_spawner: &dyn xolotl_kernel::host::BlockingSpawner,
    provisioning: RootProvisioning,
    sealer: &CredentialSealer,
) -> Result<BootstrapOutcome, AuthError> {
    if provisioning.password_hash.is_some() && provisioning.password.is_some() {
        return Err(AuthError::Crypto(
            "root password and password_hash are mutually exclusive".into(),
        ));
    }
    if let Some(phc) = &provisioning.password_hash {
        PasswordHash::new(phc)
            .map_err(|_error| AuthError::Crypto("invalid root password PHC string".into()))?;
    }
    let public_keys = credentials::public_keys(&provisioning.pubkeys)?;

    if provisioning.additional_grants.len() > 1024
        || provisioning
            .additional_grants
            .iter()
            .any(|grant| grant.len() > 4096)
    {
        return Err(AuthError::Query(
            "root additional_grants exceeds configuration limits".into(),
        ));
    }
    capset_from_strings(&provisioning.additional_grants)?;
    let previous = match root_bootstrap_admission(state).await? {
        RootBootstrap::Existing => return Ok(BootstrapOutcome::AlreadyPresent),
        RootBootstrap::Fresh => None,
        RootBootstrap::Resume(user) => user.persisted,
    };

    let now = runtime.now_millis();
    let mut root_grants = root_grants();
    root_grants.extend(provisioning.additional_grants);
    root_grants.sort();
    root_grants.dedup();
    let (password, outcome) = if let Some(phc) = provisioning.password_hash {
        (
            Some(phc),
            BootstrapOutcome::CreatedPreseeded {
                username: ROOT_USERNAME.into(),
            },
        )
    } else if let Some(password) = provisioning.password {
        crate::credentials::enforce_password_strength(
            &crate::credentials::PasswordPolicy::default().bounded(),
            ROOT_USERNAME,
            &password,
        )
        .map_err(|error| AuthError::Crypto(format!("root password rejected by policy: {error}")))?;
        let (_, phc) = password::hash_with_spawner(blocking_spawner, password).await?;
        (
            Some(phc),
            BootstrapOutcome::CreatedFromProvisionedPassword {
                username: ROOT_USERNAME.into(),
            },
        )
    } else if provisioning.pubkeys.is_empty() {
        let password = random_token(36)?;
        let (password, phc) = password::hash_with_spawner(blocking_spawner, password).await?;
        (
            Some(phc),
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

    let account_id = random_token(18)?;
    let record = credentials::AccountCredentials {
        authority_id: LOCAL_AUTHORITY_ID.into(),
        account_id: account_id.clone(),
        epoch: random_token(18)?,
        password_changed_at: password.as_ref().map(|_| now),
        password,
        public_keys,
        ..Default::default()
    };
    let identity_path = local_identity_path(&account_id)?;
    let mut user = UserRecord {
        persisted: previous,
        username: ROOT_USERNAME.into(),
        account_id,
        bootstrap_owner: true,
        identity_path,
        status: "provisioning".into(),
        roles: Vec::new(),
        grants: root_grants.clone(),
        authority_ceiling: root_grants,
        created_by: "bootstrap".into(),
        created_at: now,
    };
    // Provisioning is never authenticated. Each takeover gets a fresh account
    // incarnation, and only that claim can activate its own credential record.
    user.persisted = Some(write_user(state, &user).await?);
    credentials::write(state, ROOT_USERNAME, &record, sealer).await?;
    user.status = "active".into();
    write_user(state, &user).await?;
    Ok(outcome)
}

#[cfg(test)]
mod tests;
