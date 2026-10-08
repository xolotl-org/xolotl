//! Host usage permissions constrain dispatch without changing retained credentials.

use super::*;
use xolotl_types::Path;

fn observations(provider: &SignedFactor) -> anyhow::Result<usize> {
    Ok(provider
        .observations
        .lock()
        .map_err(|_error| anyhow::anyhow!("observations poisoned"))?
        .len())
}

async fn credential_state(boot: &Bootstrap) -> anyhow::Result<Vec<Option<xolotl_types::Value>>> {
    let mut values = Vec::new();
    for path in [
        "state://vault/console/credentials/root",
        "state://vault/console/lockouts/root",
        "state://vault/console/challenges",
    ] {
        values.push(boot.kernel().state().read(&Path::parse(path)?).await?);
    }
    Ok(values)
}

fn restricted(
    boot: &Arc<Bootstrap>,
    config: &ConsoleConfig,
    usage: MfaProviderUsage,
) -> anyhow::Result<ConsoleService> {
    let mut config = config.clone();
    config
        .auth
        .mfa
        .provider_usage
        .insert("signed_device".into(), usage);
    Ok(ConsoleService::new(ConsoleState::with_config(
        boot.clone(),
        config,
    )?))
}

#[tokio::test]
async fn independent_usage_decisions_preserve_capabilities_history_and_recovery()
-> anyhow::Result<()> {
    for allow_enrollment in [false, true] {
        for allow_authentication in [false, true] {
            let (boot, config, original, provider, key) = fixture().await?;
            let primary = original
                .login(login(None), "test".into())
                .await?
                .into_session()
                .ok()
                .context("primary login")?;
            let (device, mut session, codes) =
                enroll(&original, &primary.token, &key, "Existing device").await?;
            let history = session.authentication.clone();
            let before_installation = credential_state(&boot).await?;
            let usage = MfaProviderUsage {
                allow_enrollment,
                allow_authentication,
            };
            let service = restricted(&boot, &config, usage)?;
            ensure!(credential_state(&boot).await? == before_installation);
            let discovered = service
                .mfa_providers()
                .into_iter()
                .find(|summary| summary.descriptor.provider_id == "signed_device")
                .context("installed provider")?;
            ensure!(discovered.usage == usage);
            ensure!(
                serde_json::to_value(&discovered.descriptor)?
                    == serde_json::to_value(provider.descriptor())?,
                "host permissions must not hide supported schemas"
            );
            let options = factor_choices(service.login(login(None), "test".into()).await?)?;
            let expected = if allow_authentication {
                FactorAvailability::Available
            } else {
                FactorAvailability::AuthenticationDisabled
            };
            ensure!(options.factors.len() == 1 && options.recovery_code_available);
            ensure!(options.factors[0].availability == expected);

            if allow_enrollment {
                let (_, updated, _) =
                    enroll(&service, &session.token, &key, "New permitted device").await?;
                ensure!(updated.authentication == history);
                session = updated;
            } else {
                let before = credential_state(&boot).await?;
                let calls = observations(&provider)?;
                for replace_factor_id in [None, Some(device.factor_id.clone())] {
                    let denied = service
                        .mfa(
                            &session.token,
                            MfaRequest::Begin {
                                provider_id: "signed_device".into(),
                                label: "Disabled enrollment".into(),
                                replace_factor_id,
                                input: None,
                            },
                            "test".into(),
                        )
                        .await
                        .err()
                        .context("new and replacement enrollments are denied")?;
                    ensure!(denied.code == ConsoleErrorCode::Forbidden);
                }
                ensure!(observations(&provider)? == calls);
                ensure!(credential_state(&boot).await? == before);
            }

            let proof = signed_proof(&key, &device, 2, MfaPurpose::Login)?;
            if allow_authentication {
                let authenticated = service
                    .login(login(Some(proof)), "test".into())
                    .await?
                    .into_session()
                    .ok()
                    .context("existing device remains permitted")?;
                let elevated = service
                    .step_up(
                        &authenticated.token,
                        StepUpRequest {
                            proof: Some(signed_proof(&key, &device, 3, MfaPurpose::StepUp)?),
                        },
                        "test".into(),
                    )
                    .await?
                    .into_session()
                    .ok()
                    .context("step-up uses the same authentication permission")?;
                ensure!(elevated.authentication.primary == authenticated.authentication.primary);
                ensure!(matches!(
                    elevated.authentication.secondary,
                    Some(xolotl_console::SecondaryAuthentication::Factor { ref factor_id, .. })
                        if *factor_id == device.factor_id
                ));
            } else {
                let before = credential_state(&boot).await?;
                let calls = observations(&provider)?;
                let denied = service
                    .login(login(Some(proof.clone())), "test".into())
                    .await
                    .err()
                    .context("disabled direct login")?;
                ensure!(denied.code == ConsoleErrorCode::Forbidden);
                let denied = service
                    .step_up(
                        &session.token,
                        StepUpRequest {
                            proof: Some(signed_proof(&key, &device, 2, MfaPurpose::StepUp)?),
                        },
                        "test".into(),
                    )
                    .await
                    .err()
                    .context("disabled direct step-up")?;
                ensure!(denied.code == ConsoleErrorCode::Forbidden);
                ensure!(observations(&provider)? == calls);
                ensure!(credential_state(&boot).await? == before);
                let refreshed = service.refresh(&session.token, "test".into()).await?;
                ensure!(refreshed.authentication == history);
                ensure!(refreshed.sid == session.sid && refreshed.expires_at == session.expires_at);
                // Another host's policy remains independent; the same valid proof
                // has not been consumed or turned into an account lockout.
                original
                    .login(login(Some(proof)), "allowed-host".into())
                    .await?
                    .into_session()
                    .ok()
                    .context("allowed host accepts the unconsumed proof")?;
                let code = codes
                    .as_ref()
                    .and_then(|codes| codes.first())
                    .context("retained recovery code")?;
                let recovered = service
                    .login(
                        login(Some(MfaProof::RecoveryCode { code: code.clone() })),
                        "recovery".into(),
                    )
                    .await?
                    .into_session()
                    .ok()
                    .context("provider policy does not disable account recovery")?;
                ensure!(matches!(
                    recovered.authentication.secondary,
                    Some(xolotl_console::SecondaryAuthentication::RecoveryCode { .. })
                ));
                let replay = service
                    .login(
                        login(Some(MfaProof::RecoveryCode { code: code.clone() })),
                        "recovery-replay".into(),
                    )
                    .await
                    .err()
                    .context("recovery still requires single consumption")?;
                ensure!(replay.code == ConsoleErrorCode::NotAuthenticated);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn pending_confirmation_rechecks_current_host_policy_and_disabled_factors_remain_manageable()
-> anyhow::Result<()> {
    let (boot, config, original, provider, key) = fixture().await?;
    let primary = original
        .login(login(None), "test".into())
        .await?
        .into_session()
        .ok()
        .context("primary login")?;
    let (device, session, _) = enroll(&original, &primary.token, &key, "Retained").await?;
    let disabled = restricted(
        &boot,
        &config,
        MfaProviderUsage {
            allow_enrollment: false,
            allow_authentication: false,
        },
    )?;
    let MfaResponse::Enrollment {
        challenge_id,
        factor_id,
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = original
        .mfa(
            &session.token,
            MfaRequest::Begin {
                provider_id: "signed_device".into(),
                label: "Pending replacement".into(),
                replace_factor_id: Some(device.factor_id.clone()),
                input: None,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("pending replacement");
    };
    let pending = Device {
        factor_id,
        label: "Pending replacement".into(),
        setup,
    };
    let response = signed_response(&key, &pending, 1, MfaPurpose::Enrollment)?;
    let before = credential_state(&boot).await?;
    let calls = observations(&provider)?;
    let denied = disabled
        .mfa(
            &session.token,
            MfaRequest::Continue {
                challenge_id: challenge_id.clone(),
                input: MfaInteractionInput::Response {
                    response: response.clone(),
                },
            },
            "test".into(),
        )
        .await
        .err()
        .context("pending setup cannot override current host policy")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    ensure!(observations(&provider)? == calls);
    ensure!(credential_state(&boot).await? == before);
    let MfaResponse::Updated {
        session: replacement,
        ..
    } = original
        .mfa(
            &session.token,
            MfaRequest::Continue {
                challenge_id,
                input: MfaInteractionInput::Response { response },
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("allowed host still owns the unconsumed pending replacement");
    };
    ensure!(replacement.authentication == session.authentication);

    let MfaResponse::Enrollment { challenge_id, .. } = original
        .mfa(
            &replacement.token,
            MfaRequest::Begin {
                provider_id: "signed_device".into(),
                label: "Cancelable setup".into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("cancelable setup");
    };
    let calls = observations(&provider)?;
    ensure!(matches!(
        disabled
            .mfa(
                &replacement.token,
                MfaRequest::Cancel { challenge_id },
                "test".into()
            )
            .await?,
        MfaResponse::Canceled
    ));
    let MfaResponse::Renamed { factor } = disabled
        .mfa(
            &replacement.token,
            MfaRequest::Rename {
                factor_id: pending.factor_id.clone(),
                label: "Disabled but retained".into(),
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("disabled factors remain renameable");
    };
    ensure!(factor.availability == FactorAvailability::AuthenticationDisabled);
    let MfaResponse::Updated {
        session: renewed,
        recovery_codes,
    } = disabled
        .mfa(
            &replacement.token,
            MfaRequest::RegenerateRecoveryCodes {},
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("account recovery management remains available");
    };
    ensure!(renewed.authentication == replacement.authentication);
    ensure!(recovery_codes.context("new codes")?.len() == 10);
    let MfaResponse::Updated {
        session: removed, ..
    } = disabled
        .mfa(
            &renewed.token,
            MfaRequest::Remove {
                factor_id: pending.factor_id,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("disabled factor remains removable");
    };
    ensure!(removed.authentication == renewed.authentication);
    ensure!(observations(&provider)? == calls);
    let MfaResponse::Status {
        factors,
        recovery_codes_remaining,
        ..
    } = disabled
        .mfa(&removed.token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("final account status");
    };
    ensure!(factors.is_empty() && recovery_codes_remaining == 0);
    Ok(())
}
