//! External hosts use only public APIs, without an HTTP router or WS session.

#[path = "support/console_config.rs"]
mod console_config;
#[path = "support/sealer.rs"]
mod sealer;

use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[path = "support/pqc_key.rs"]
mod pqc_key;
use pqc_key::PqcSigningKey;
use std::sync::Arc;
use xolotl_console::{
    ActionCall, AuthenticationResponse, ConsoleConfig, ConsoleErrorCode, ConsoleService,
    ConsoleState, KeyChallengeRequest, KeyChallengeResponse, KeyLoginRequest, RootProvisioning,
    bootstrap_root_account,
};
use xolotl_console_protocol::{ACTION_PROTOCOL_DESCRIBE, ACTION_RESOURCE_TYPE_LIST};
use xolotl_kernel::Bootstrap;
use xolotl_standard::{StandardConfig, install_standard};

#[path = "service/admission.rs"]
mod admission;

#[tokio::test]
async fn local_console_rejects_missing_host_credential_key() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    ensure!(ConsoleState::with_config(boot.clone(), ConsoleConfig::default()).is_err());
    ensure!(
        bootstrap_root_account(
            &boot,
            &xolotl_kernel::host::TokioBlockingSpawner::default(),
            RootProvisioning::default(),
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn custom_host_composes_key_authentication_discovery_and_refresh() -> anyhow::Result<()> {
    let key = PqcSigningKey::generate();
    let descriptor = key.descriptor();
    let boot = Arc::new(Bootstrap::in_memory());
    install_standard(&boot, &StandardConfig::default())?;
    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            credential_sealer: Some(crate::sealer::sealer()),
            pubkeys: vec![descriptor.clone()],
            ..Default::default()
        },
    )
    .await?;
    let state = ConsoleState::with_config(boot, crate::console_config::console_config())?;
    let service = ConsoleService::new(state);
    let request = KeyChallengeRequest {
        username: "root".into(),
        origin: "https://console.example".into(),
    };
    // A custom adapter can encode requests and decode responses using the public DTOs.
    let request = serde_json::from_slice(&serde_json::to_vec(&request)?)?;
    let challenge = service
        .begin_key_login(request, "trusted-peer".into())
        .await?;
    let challenge: KeyChallengeResponse = serde_json::from_slice(&serde_json::to_vec(&challenge)?)?;
    let request = KeyLoginRequest {
        username: "root".into(),
        challenge_id: challenge.challenge_id,
        signature: URL_SAFE_NO_PAD.encode(key.sign(challenge.transcript.as_bytes())),
        origin: challenge.origin,
        key: descriptor,
        second_factor: None,
    };
    let serialized_request = serde_json::to_vec(&request)?;
    let login = service
        .finish_key_login(request, "trusted-peer".into())
        .await?;
    let login = serde_json::from_slice::<AuthenticationResponse>(&serde_json::to_vec(&login)?)?
        .into_session()
        .ok()
        .context("authenticated session")?;
    let replay = service
        .finish_key_login(
            serde_json::from_slice(&serialized_request)?,
            "trusted-peer".into(),
        )
        .await
        .err()
        .context("single-use challenge")?;
    ensure!(replay.code == ConsoleErrorCode::NotAuthenticated);
    let metadata = service
        .call(
            &login.token,
            Some("trusted-peer"),
            ActionCall {
                action: ACTION_PROTOCOL_DESCRIBE.into(),
                ..Default::default()
            },
        )
        .await?;
    let resources = service
        .call(
            &login.token,
            Some("trusted-peer"),
            ActionCall {
                action: ACTION_RESOURCE_TYPE_LIST.into(),
                registry_rev: Some(metadata.registry_rev),
                ..Default::default()
            },
        )
        .await?;
    ensure!(resources.registry_rev == metadata.registry_rev);
    ensure!(resources.output.is_some());
    let refreshed = service.refresh(&login.token, "trusted-peer".into()).await?;
    ensure!(refreshed.sid == login.sid);
    ensure!(refreshed.token != login.token);
    Ok(())
}
