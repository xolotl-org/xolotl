//! Signed primary authentication uses the same independent factor admission.

use super::*;
use xolotl_console::{
    AuthenticationResponse, AuthenticationStep, ConsoleConfig, KeyChallengeRequest,
    KeyLoginRequest, PrimaryAuthentication, SecondaryAuthentication,
    credentials::{CredentialOperation, CredentialRequest, CredentialResponse},
};
use xolotl_types::Path;

async fn key_request(
    service: &ConsoleService,
    key: &super::pqc_key::PqcSigningKey,
    descriptor: &str,
    proof: Option<MfaProof>,
) -> anyhow::Result<KeyLoginRequest> {
    let challenge = service
        .begin_key_login(
            KeyChallengeRequest {
                username: "root".into(),
                origin: "https://console.local".into(),
            },
            "key-peer".into(),
        )
        .await?;
    Ok(KeyLoginRequest {
        username: "root".into(),
        challenge_id: challenge.challenge_id,
        signature: URL_SAFE_NO_PAD.encode(key.sign(challenge.transcript.as_bytes())),
        origin: challenge.origin,
        key: descriptor.into(),
        second_factor: proof,
    })
}

async fn retained_state(boot: &Bootstrap) -> anyhow::Result<Vec<Option<xolotl_types::Value>>> {
    let mut values = Vec::new();
    for path in [
        "state://vault/console/credentials/root",
        "state://vault/console/lockouts/root",
    ] {
        values.push(boot.kernel().state().read(&Path::parse(path)?).await?);
    }
    Ok(values)
}

async fn session_ids(config: &ConsoleConfig) -> anyhow::Result<Vec<String>> {
    let page = config
        .session_store
        .as_ref()
        .context("fixture store")?
        .list(
            None,
            xolotl_console::session_store::SessionPageLimits {
                rows: 256,
                bytes: 1024 * 1024,
            },
        )
        .await?;
    ensure!(page.next.is_none(), "fixture session page must be complete");
    Ok(page
        .entries
        .into_iter()
        .map(|row| row.sid().to_owned())
        .collect())
}

#[tokio::test]
async fn public_key_login_retains_required_factor_and_checks_current_host_usage()
-> anyhow::Result<()> {
    let (boot, config, original, provider, factor_key) = fixture().await?;
    let primary = original
        .login(login(None), "test".into())
        .await?
        .into_session()
        .ok()
        .context("primary login")?;
    let primary_key = super::pqc_key::PqcSigningKey::generate();
    let descriptor = primary_key.descriptor();
    let CredentialResponse::Updated {
        session: Some(with_key),
        ..
    } = original
        .credentials(
            &primary.token,
            CredentialRequest {
                username: None,
                operation: CredentialOperation::AddPublicKey {
                    key: descriptor.clone(),
                },
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("registered primary public key");
    };
    let (device, _, _) = enroll(
        &original,
        &with_key.token,
        &factor_key,
        "Independent factor",
    )
    .await?;
    let host = |allow_authentication| -> anyhow::Result<ConsoleService> {
        let mut config = config.clone();
        config.auth.mfa.provider_usage.insert(
            "signed_device".into(),
            MfaProviderUsage {
                allow_enrollment: false,
                allow_authentication,
            },
        );
        Ok(ConsoleService::new(ConsoleState::with_config(
            boot.clone(),
            config,
        )?))
    };
    let denied = host(false)?;
    let allowed = host(true)?;
    let request = key_request(&denied, &primary_key, &descriptor, None).await?;
    let AuthenticationResponse::Continue(pending) =
        denied.finish_key_login(request, "key-peer".into()).await?
    else {
        anyhow::bail!("disabled factor must not turn public-key login into a session");
    };
    let AuthenticationStep::ChooseFactor { options } = pending.step else {
        anyhow::bail!("verified public key must offer second-factor choices");
    };
    ensure!(options.factors.len() == 1 && options.recovery_code_available);
    ensure!(options.factors[0].factor_id == device.factor_id);
    ensure!(options.factors[0].availability == FactorAvailability::AuthenticationDisabled);

    let proof = signed_proof(&factor_key, &device, 2, MfaPurpose::Login)?;
    let before = retained_state(&boot).await?;
    let sessions = session_ids(&config).await?;
    let calls = provider
        .observations
        .lock()
        .map_err(|_error| anyhow::anyhow!("observations poisoned"))?
        .len();
    // Each primary signature owns a single-use challenge. Policy denial must
    // leave the independent factor proof unused, not revive that key challenge.
    for _ in 0..6 {
        let request = key_request(&denied, &primary_key, &descriptor, Some(proof.clone())).await?;
        let retry: KeyLoginRequest = serde_json::from_value(serde_json::to_value(&request)?)?;
        let error = denied
            .finish_key_login(request, "key-peer".into())
            .await
            .err()
            .context("host policy denies the attached second proof")?;
        ensure!(error.code == ConsoleErrorCode::Forbidden);
        let replay = denied
            .finish_key_login(retry, "key-peer".into())
            .await
            .err()
            .context("the original primary challenge remains single-use")?;
        ensure!(replay.code == ConsoleErrorCode::NotAuthenticated);
    }
    ensure!(retained_state(&boot).await? == before);
    ensure!(session_ids(&config).await? == sessions);
    ensure!(
        provider
            .observations
            .lock()
            .map_err(|_error| anyhow::anyhow!("observations poisoned"))?
            .len()
            == calls
    );
    let request = key_request(&allowed, &primary_key, &descriptor, Some(proof)).await?;
    let session = allowed
        .finish_key_login(request, "key-peer".into())
        .await?
        .into_session()
        .ok()
        .context("new primary challenge and the unconsumed factor proof authenticate")?;
    ensure!(matches!(
        &session.authentication.primary,
        PrimaryAuthentication::PublicKey { credential_key, .. } if credential_key == &descriptor
    ));
    ensure!(matches!(
        &session.authentication.secondary,
        Some(SecondaryAuthentication::Factor { factor_id, provider_id, .. })
            if factor_id == &device.factor_id && provider_id == "signed_device"
    ));
    ensure!(session.authentication.mfa_level() == 2);
    ensure!(
        provider
            .observations
            .lock()
            .map_err(|_error| anyhow::anyhow!("observations poisoned"))?
            .len()
            == calls + 1
    );
    Ok(())
}
