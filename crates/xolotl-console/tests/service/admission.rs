//! Custom adapters reserve the same service capacity before frame decoding.

use super::*;
use xolotl_console::{LoginRequest, wire};

async fn fixture() -> anyhow::Result<(ConsoleService, String)> {
    const PASSWORD: &str = "Ar7!cVN23#pxQe$Lr9";
    let boot = Arc::new(Bootstrap::in_memory());
    install_standard(&boot, &StandardConfig::default())?;
    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            credential_sealer: Some(crate::sealer::sealer()),
            password: Some(PASSWORD.into()),
            ..Default::default()
        },
    )
    .await?;
    let state = ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                xolotl_console::session_store::MemoryConsoleSessionStore::new(
                    xolotl_console::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            auth: crate::console_config::auth(),
            max_concurrent_calls: 1,
            max_concurrent_authentications: 1,
            ..Default::default()
        },
    )?;
    let service = ConsoleService::new(state);
    let token = service
        .login(
            LoginRequest {
                username: "root".into(),
                password: PASSWORD.into(),
                second_factor: None,
            },
            "trusted-peer".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("primary login")?
        .token;
    Ok((service, token))
}

fn describe() -> ActionCall {
    ActionCall {
        action: ACTION_PROTOCOL_DESCRIBE.into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn authentication_reservation_transfers_capacity_one_without_reacquiring()
-> anyhow::Result<()> {
    let (service, token) = fixture().await?;
    let reservation = service.admit_authentication()?;
    let error = service
        .clone()
        .admit_authentication()
        .err()
        .context("service clones share authentication capacity")?;
    ensure!(error.code == ConsoleErrorCode::RateLimited);
    let rejected = service
        .refresh(&token, "trusted-peer".into())
        .await
        .err()
        .context("native authentication must not bypass retained capacity")?;
    ensure!(rejected.code == ConsoleErrorCode::RateLimited);
    let refreshed = reservation.refresh(&token, "trusted-peer".into()).await?;
    ensure!(refreshed.token != token);
    ensure!(service.admit_authentication().is_ok());
    Ok(())
}

#[tokio::test]
async fn authentication_reservation_dispatches_only_through_its_issuing_service()
-> anyhow::Result<()> {
    let (first, first_token) = fixture().await?;
    let (second, second_token) = fixture().await?;
    let reservation = first.admit_authentication()?;
    let second_session = second.refresh(&second_token, "second-peer".into()).await?;
    let rejected = reservation
        .refresh(&second_session.token, "first-peer".into())
        .await
        .err()
        .context("the reservation must not authenticate another service's session")?;
    ensure!(rejected.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(first.admit_authentication().is_ok());
    first
        .admit_authentication()?
        .refresh(&first_token, "first-peer".into())
        .await?;
    second
        .refresh(&second_session.token, "second-peer".into())
        .await?;
    Ok(())
}

#[tokio::test]
async fn dropped_authentication_future_releases_admission_without_rotating_token()
-> anyhow::Result<()> {
    let (service, token) = fixture().await?;
    let pending = service
        .admit_authentication()?
        .refresh(&token, "trusted-peer".into());
    let rejected = service
        .admit_authentication()
        .err()
        .context("an unpolled admitted future still owns its reservation")?;
    ensure!(rejected.code == ConsoleErrorCode::RateLimited);
    drop(pending);
    let refreshed = service.refresh(&token, "trusted-peer".into()).await?;
    ensure!(refreshed.token != token);
    ensure!(service.admit_authentication().is_ok());
    Ok(())
}

#[tokio::test]
async fn malformed_transport_frame_releases_its_public_call_reservation() -> anyhow::Result<()> {
    let (service, token) = fixture().await?;
    let admitted: xolotl_console::ConsoleCallAdmission<'_> = service.admit_call()?;
    let saturated = service
        .admit_call()
        .err()
        .context("call capacity is held")?;
    ensure!(saturated.code == ConsoleErrorCode::RateLimited);
    let direct = service
        .call(&token, Some("trusted-peer"), describe())
        .await
        .err()
        .context("direct service call shares the same slot")?;
    ensure!(direct.code == ConsoleErrorCode::RateLimited);
    ensure!(wire::decode_client_frame(&[0xff], 128).is_err());
    drop(admitted);

    let admitted = service.admit_call()?;
    let result = admitted
        .call(&token, Some("trusted-peer"), describe())
        .await?;
    ensure!(result.output.is_some());
    // A consumed reservation has released its capacity, too.
    ensure!(service.admit_call().is_ok());
    Ok(())
}

#[tokio::test]
async fn reservation_dispatches_only_on_its_originating_service() -> anyhow::Result<()> {
    let (first, first_token) = fixture().await?;
    let (second, second_token) = fixture().await?;
    ensure!(first_token != second_token);
    let first_admitted = first.admit_call()?;
    // The other host has separate admission and credentials. The public
    // reservation has no API accepting a different ConsoleService.
    let other_result = second
        .call(&second_token, Some("other-peer"), describe())
        .await?;
    ensure!(other_result.output.is_some());
    let error = first_admitted
        .call(&second_token, Some("other-peer"), describe())
        .await
        .err()
        .context("foreign bearer cannot use the admitted host")?;
    ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    let own_result = first
        .call(&first_token, Some("trusted-peer"), describe())
        .await?;
    ensure!(own_result.output.is_some());
    Ok(())
}
