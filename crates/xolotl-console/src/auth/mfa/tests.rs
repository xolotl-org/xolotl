use super::*;
use anyhow::{Context, ensure};

mod installation;
mod instances;
mod management;
mod providers;

async fn local_account_key(boot: &Bootstrap, username: &str) -> anyhow::Result<AccountKey> {
    Ok(super::super::read_user(boot.kernel().state(), username)
        .await?
        .context("local account")?
        .account_key())
}

fn set_authentication_time(authentication: &mut AuthenticationEvidence, now: i64) {
    match &mut authentication.primary {
        PrimaryAuthentication::Password { verified_at }
        | PrimaryAuthentication::PublicKey { verified_at, .. }
        | PrimaryAuthentication::PasskeyUv { verified_at, .. }
        | PrimaryAuthentication::External { verified_at, .. } => *verified_at = now,
    }
    match &mut authentication.secondary {
        Some(SecondaryAuthentication::Factor { verified_at, .. })
        | Some(SecondaryAuthentication::RecoveryCode { verified_at }) => *verified_at = now,
        None => {}
    }
}

// This helper is deliberately limited to fixtures with one TOTP instance.
// Multi-device tests keep and address the IDs returned by enrollment.
async fn only_totp_id(boot: &Bootstrap, username: &str) -> anyhow::Result<String> {
    let record = read(
        boot.kernel().state(),
        username,
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let mut factors = record
        .factors
        .iter()
        .filter(|(_, factor)| factor.provider_id == "totp");
    let id = factors.next().context("single TOTP fixture")?.0.clone();
    ensure!(
        factors.next().is_none(),
        "single-factor helper used for multiple devices"
    );
    Ok(id)
}

impl ConsoleAuth {
    pub(crate) async fn enroll_test_totp(
        &self,
        boot: &Bootstrap,
        bearer: &str,
    ) -> anyhow::Result<LoginResponse> {
        let response = self
            .manage_mfa(
                boot,
                bearer,
                MfaRequest::Begin {
                    provider_id: "totp".into(),
                    label: "Test authenticator".into(),
                    replace_factor_id: None,
                    input: None,
                },
                "test".into(),
            )
            .await?;
        let MfaResponse::Enrollment {
            challenge_id,
            step: MfaEnrollmentProgress::Challenge { setup, .. },
            ..
        } = response
        else {
            anyhow::bail!("enrollment");
        };
        let secret = data_encoding::BASE32_NOPAD
            .decode(setup["secret"].as_str().context("secret")?.as_bytes())?;
        let step = self.host_runtime.now_millis() as u64
            / 1000
            / u64::from(self.config.mfa.totp.period_seconds);
        let response =
            serde_json::json!({"code":crate::mfa::code_at(&secret, step, &self.config.mfa.totp)?});
        let response = self
            .manage_mfa(
                boot,
                bearer,
                MfaRequest::Continue {
                    challenge_id,
                    input: MfaInteractionInput::Response { response },
                },
                "test".into(),
            )
            .await?;
        let MfaResponse::Updated {
            session,
            recovery_codes,
        } = response
        else {
            anyhow::bail!("confirmation");
        };
        if session.authentication.mfa_level() >= 2 {
            return Ok(session);
        }
        // Confirmation installs a credential; a separate recovery proof gives
        // the fixture a verified second factor without consuming a TOTP step.
        let code = recovery_codes
            .context("first enrollment recovery codes")?
            .pop()
            .context("recovery proof")?;
        self.step_up(
            boot,
            &session.token,
            StepUpRequest {
                proof: Some(MfaProof::RecoveryCode { code }),
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("verified test session"))
    }

    pub(crate) async fn next_test_totp(
        &self,
        boot: &Bootstrap,
        username: &str,
    ) -> anyhow::Result<MfaProof> {
        let record = read(
            boot.kernel().state(),
            username,
            crate::auth::test_credential_sealer().as_ref(),
        )
        .await?;
        let factor_id = only_totp_id(boot, username).await?;
        let verifier = &record
            .factors
            .get(&factor_id)
            .context("TOTP factor")?
            .verifier;
        let secret = data_encoding::BASE32_NOPAD
            .decode(verifier["secret"].as_str().context("secret")?.as_bytes())?;
        let step = xolotl_kernel::host::system_now_millis() as u64
            / 1000
            / u64::from(self.config.mfa.totp.period_seconds)
            + 1;
        Ok(MfaProof::Factor {
            factor_id,
            response: serde_json::json!({"code":crate::mfa::code_at(&secret, step, &self.config.mfa.totp)?}),
        })
    }
}

#[tokio::test]
async fn password_recheck_cannot_be_used_as_an_independent_factor() -> anyhow::Result<()> {
    let (state, service, token, password) = crate::service::tests::fixture().await?;
    let error = service
        .step_up(
            &token,
            StepUpRequest {
                proof: Some(MfaProof::Factor {
                    factor_id: "password".into(),
                    response: serde_json::json!({"password":password}),
                }),
            },
            "test".into(),
        )
        .await
        .err()
        .context("MFA rejection")?;
    ensure!(error.code == crate::ConsoleErrorCode::StepUpRequired);
    ensure!(error.required_mfa_level == Some(2));
    ensure!(
        state
            .auth
            .authenticate_token(&state.boot, &token)
            .await?
            .authentication
            .mfa_level()
            == 1
    );
    Ok(())
}

use crate::{ConsoleErrorCode, ConsoleService, ConsoleState};

fn factor_choices(response: crate::AuthenticationResponse) -> anyhow::Result<MfaOptions> {
    let crate::AuthenticationResponse::Continue(next) = response else {
        anyhow::bail!("missing second factor must not issue a session");
    };
    ensure!(
        !next.continuation.is_empty() && next.expires_at > xolotl_kernel::host::system_now_millis()
    );
    let crate::AuthenticationStep::ChooseFactor { options } = next.step else {
        anyhow::bail!("expected factor selection after primary authentication");
    };
    Ok(options)
}

async fn begin(service: &ConsoleService, token: &str) -> anyhow::Result<(String, JsonValue)> {
    let MfaResponse::Enrollment {
        challenge_id,
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = service
        .mfa(
            token,
            MfaRequest::Begin {
                provider_id: "totp".into(),
                label: "Test authenticator".into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("expected enrollment");
    };
    Ok((challenge_id, setup))
}

fn setup_response(setup: &JsonValue, offset: u64) -> anyhow::Result<JsonValue> {
    let secret = data_encoding::BASE32_NOPAD
        .decode(setup["secret"].as_str().context("secret")?.as_bytes())?;
    let config = crate::mfa::TotpConfig {
        algorithm: serde_json::from_value(setup["algorithm"].clone())?,
        digits: setup["digits"].as_u64().context("digits")? as u8,
        period_seconds: setup["period_seconds"].as_u64().context("period")? as u32,
        ..Default::default()
    };
    let step =
        xolotl_kernel::host::system_now_millis() as u64 / 1000 / u64::from(config.period_seconds)
            + offset;
    Ok(serde_json::json!({"code": crate::mfa::code_at(&secret, step, &config)?}))
}

async fn enroll(
    service: &ConsoleService,
    token: &str,
) -> anyhow::Result<(LoginResponse, Vec<String>, JsonValue)> {
    let (challenge_id, setup) = begin(service, token).await?;
    let MfaResponse::Updated {
        session,
        recovery_codes,
    } = service
        .mfa(
            token,
            MfaRequest::Continue {
                challenge_id,
                input: MfaInteractionInput::Response {
                    response: setup_response(&setup, 0)?,
                },
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("expected confirmed enrollment");
    };
    let mut codes = recovery_codes.context("first recovery codes")?;
    let code = codes.pop().context("recovery proof")?;
    let session = service
        .step_up(
            &session.token,
            StepUpRequest {
                proof: Some(MfaProof::RecoveryCode { code }),
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("verified enrollment session"))?;
    Ok((session, codes, setup))
}

fn password_request(password: &str, proof: Option<MfaProof>) -> LoginRequest {
    LoginRequest {
        username: "root".into(),
        password: password.into(),
        second_factor: proof,
    }
}

fn recovery_proof(code: &str) -> MfaProof {
    MfaProof::RecoveryCode { code: code.into() }
}

async fn assert_invalid_session(state: &ConsoleState, token: &str) -> anyhow::Result<()> {
    let sid = token.split_once('.').context("bearer")?.0;
    ensure!(matches!(
        state.auth.authenticate_token(&state.boot, token).await,
        Err(AuthError::InvalidSession)
    ));
    ensure!(matches!(
        state.auth.authenticate_sid(&state.boot, sid).await,
        Err(AuthError::InvalidSession)
    ));
    ensure!(matches!(
        state
            .auth
            .refresh_session(&state.boot, token, Some("test"))
            .await,
        Err(AuthError::InvalidSession)
    ));
    Ok(())
}

#[tokio::test]
async fn pending_enrollment_requires_proof_originating_session_and_unexpired_challenge()
-> anyhow::Result<()> {
    let (state, service, token, password) = crate::service::tests::fixture().await?;
    let (challenge_id, setup) = begin(&service, &token).await?;
    ensure!(
        read(
            state.boot.kernel().state(),
            "root",
            crate::auth::test_credential_sealer().as_ref()
        )
        .await?
        .factors
        .is_empty()
    );
    let wrong = service
        .mfa(
            &token,
            MfaRequest::Continue {
                challenge_id: challenge_id.clone(),
                input: MfaInteractionInput::Response {
                    response: serde_json::json!({"code":"invalid"}),
                },
            },
            "test".into(),
        )
        .await;
    ensure!(wrong.err().context("bad proof")?.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(
        read(
            state.boot.kernel().state(),
            "root",
            crate::auth::test_credential_sealer().as_ref()
        )
        .await?
        .factors
        .is_empty()
    );
    *state.auth.rate() = RateState::default();
    let another = service
        .login(password_request(&password, None), "test".into())
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let wrong_sid = service
        .mfa(
            &another.token,
            MfaRequest::Continue {
                challenge_id: challenge_id.clone(),
                input: MfaInteractionInput::Response {
                    response: setup_response(&setup, 0)?,
                },
            },
            "test".into(),
        )
        .await;
    ensure!(wrong_sid.is_err());
    let mut record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    record.pending.as_mut().context("pending")?.expires_at =
        xolotl_kernel::host::system_now_millis() - 1;
    write(
        state.boot.kernel().state(),
        "root",
        &record,
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(
        service
            .mfa(
                &token,
                MfaRequest::Continue {
                    challenge_id: challenge_id.clone(),
                    input: MfaInteractionInput::Response {
                        response: setup_response(&setup, 0)?
                    }
                },
                "test".into()
            )
            .await
            .is_err()
    );
    ensure!(matches!(
        service
            .mfa(
                &token,
                MfaRequest::Cancel {
                    challenge_id: challenge_id.clone()
                },
                "test".into()
            )
            .await?,
        MfaResponse::Canceled
    ));
    ensure!(
        service
            .mfa(
                &token,
                MfaRequest::Continue {
                    challenge_id,
                    input: MfaInteractionInput::Response {
                        response: setup_response(&setup, 0)?
                    }
                },
                "test".into()
            )
            .await
            .is_err()
    );
    ensure!(
        read(
            state.boot.kernel().state(),
            "root",
            crate::auth::test_credential_sealer().as_ref()
        )
        .await?
        .pending
        .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn enrollment_enforces_two_factors_and_invalidates_every_old_session_entry()
-> anyhow::Result<()> {
    let (state, service, token, password) = crate::service::tests::fixture().await?;
    let (session, codes, _) = enroll(&service, &token).await?;
    ensure!(session.authentication.mfa_level() == 2 && codes.len() == RECOVERY_COUNT - 1);
    assert_invalid_session(&state, &token).await?;
    let denied = service
        .login(password_request("wrong-primary", None), "test".into())
        .await
        .err()
        .context("wrong password")?;
    ensure!(denied.code == ConsoleErrorCode::NotAuthenticated && denied.mfa.is_none());
    *state.auth.rate() = RateState::default();
    let options = factor_choices(
        service
            .login(password_request(&password, None), "test".into())
            .await?,
    )?;
    ensure!(options.recovery_code_available && options.factors.len() == 1);
    ensure!(
        options.factors[0].provider_id == "totp"
            && options.factors[0].availability == FactorAvailability::Available
    );
    let step_up_options = factor_choices(
        service
            .step_up(&session.token, StepUpRequest { proof: None }, "test".into())
            .await?,
    )?;
    ensure!(step_up_options == options);
    let MfaResponse::Status {
        factors,
        max_factors,
        recovery_codes_remaining,
        ..
    } = service
        .mfa(&session.token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("status")
    };
    ensure!(factors.len() == 1 && factors[0].provider_id == "totp");
    ensure!(factors[0].factor_id == options.factors[0].factor_id);
    ensure!(max_factors == MAX_FACTORS && recovery_codes_remaining == codes.len());
    Ok(())
}

#[tokio::test]
async fn concurrent_totp_proofs_issue_at_most_one_session_and_replay_is_rejected()
-> anyhow::Result<()> {
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let (session, _, _) = enroll(&service, &token).await?;
    let proof = state.auth.next_test_totp(&state.boot, "root").await?;
    let (a, b) = tokio::join!(
        service.step_up(
            &session.token,
            StepUpRequest {
                proof: Some(proof.clone()),
            },
            "test".into()
        ),
        service.step_up(
            &session.token,
            StepUpRequest {
                proof: Some(proof.clone()),
            },
            "test".into()
        )
    );
    ensure!(usize::from(a.is_ok()) + usize::from(b.is_ok()) == 1);
    for response in [a, b].into_iter().filter_map(Result::ok) {
        let session = response
            .into_session()
            .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
        ensure!(session.authentication.mfa_level() == 2);
    }
    ensure!(
        service
            .step_up(
                &session.token,
                StepUpRequest { proof: Some(proof) },
                "test".into()
            )
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn recovery_codes_are_consumed_atomically_and_only_hashes_are_persisted() -> anyhow::Result<()>
{
    let (state, service, token, password) = crate::service::tests::fixture().await?;
    let (_, codes, _) = enroll(&service, &token).await?;
    let record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let persisted = serde_json::to_string(&record)?;
    for code in &codes {
        ensure!(!persisted.contains(code));
        ensure!(record.recovery.contains(&token_hash(code)));
    }
    let proof = recovery_proof(&codes[0]);
    let verified_after = xolotl_kernel::host::system_now_millis();
    let (a, b) = tokio::join!(
        service.login(
            password_request(&password, Some(proof.clone())),
            "test".into()
        ),
        service.login(
            password_request(&password, Some(proof.clone())),
            "test".into()
        )
    );
    ensure!(usize::from(a.is_ok()) + usize::from(b.is_ok()) == 1);
    for response in [a, b].into_iter().filter_map(Result::ok) {
        let session = response
            .into_session()
            .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
        ensure!(session.authentication.mfa_level() == 2);
        ensure!(matches!(
            session.authentication.secondary,
            Some(SecondaryAuthentication::RecoveryCode { verified_at })
                if verified_at >= verified_after && verified_at <= xolotl_kernel::host::system_now_millis()
        ));
        let evidence = serde_json::to_string(&session.authentication)?;
        ensure!(!evidence.contains(&codes[0]));
        ensure!(!evidence.contains(&token_hash(&codes[0])));
    }
    ensure!(
        service
            .login(password_request(&password, Some(proof)), "test".into())
            .await
            .is_err()
    );
    ensure!(
        read(
            state.boot.kernel().state(),
            "root",
            crate::auth::test_credential_sealer().as_ref()
        )
        .await?
        .recovery
        .len()
            == codes.len() - 1
    );
    Ok(())
}

#[tokio::test]
async fn recovery_regeneration_and_last_factor_removal_rotate_policy_epoch() -> anyhow::Result<()> {
    let (state, service, token, password) = crate::service::tests::fixture().await?;
    let (enrolled, old_codes, _) = enroll(&service, &token).await?;
    let MfaResponse::Updated {
        session,
        recovery_codes,
    } = service
        .mfa(
            &enrolled.token,
            MfaRequest::RegenerateRecoveryCodes {},
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("regenerated")
    };
    let new_codes = recovery_codes.context("new codes")?;
    assert_invalid_session(&state, &enrolled.token).await?;
    ensure!(
        service
            .login(
                password_request(&password, Some(recovery_proof(&old_codes[0]))),
                "test".into()
            )
            .await
            .is_err()
    );
    *state.auth.rate() = RateState::default();
    let recovered = service
        .login(
            password_request(&password, Some(recovery_proof(&new_codes[0]))),
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(recovered.authentication.mfa_level() == 2);
    let MfaResponse::Updated {
        session: primary,
        recovery_codes,
    } = service
        .mfa(
            &session.token,
            MfaRequest::Remove {
                factor_id: only_totp_id(&state.boot, "root").await?,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("removed")
    };
    ensure!(primary.authentication == session.authentication && recovery_codes.is_none());
    assert_invalid_session(&state, &session.token).await?;
    assert_invalid_session(&state, &recovered.token).await?;
    let record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(record.factors.is_empty() && record.recovery.is_empty() && record.pending.is_none());
    ensure!(
        service
            .login(password_request(&password, None), "test".into())
            .await?
            .into_session()
            .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?
            .authentication
            .mfa_level()
            == 1
    );
    Ok(())
}

#[tokio::test]
async fn replacing_totp_changes_active_verifier_only_after_confirmation() -> anyhow::Result<()> {
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let (enrolled, _, old_setup) = enroll(&service, &token).await?;
    let old_id = only_totp_id(&state.boot, "root").await?;
    let MfaResponse::Enrollment {
        challenge_id,
        factor_id,
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = service
        .mfa(
            &enrolled.token,
            MfaRequest::Begin {
                provider_id: "totp".into(),
                label: "Replacement authenticator".into(),
                replace_factor_id: Some(old_id.clone()),
                input: None,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("replacement enrollment")
    };
    ensure!(factor_id != old_id);
    let record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(record.factors[&old_id].verifier["secret"] == old_setup["secret"]);
    let old_proof = state.auth.next_test_totp(&state.boot, "root").await?;
    service
        .step_up(
            &enrolled.token,
            StepUpRequest {
                proof: Some(old_proof),
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let MfaResponse::Updated {
        session,
        recovery_codes,
    } = service
        .mfa(
            &enrolled.token,
            MfaRequest::Continue {
                challenge_id,
                input: MfaInteractionInput::Response {
                    response: setup_response(&setup, 0)?,
                },
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("replaced")
    };
    ensure!(recovery_codes.is_none());
    let record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(!record.factors.contains_key(&old_id));
    ensure!(record.factors[&factor_id].verifier["secret"] == setup["secret"]);
    assert_invalid_session(&state, &enrolled.token).await?;
    service
        .step_up(
            &session.token,
            StepUpRequest {
                proof: Some(state.auth.next_test_totp(&state.boot, "root").await?),
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    Ok(())
}

#[tokio::test]
async fn refresh_does_not_restore_recent_authentication_for_credential_changes()
-> anyhow::Result<()> {
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let (enrolled, _, _) = enroll(&service, &token).await?;
    let session_path = session_path(&enrolled.sid)?;
    let mut session = read_session(state.auth.session_store.as_ref(), &session_path)
        .await?
        .context("session")?;
    set_authentication_time(
        &mut session.authentication,
        xolotl_kernel::host::system_now_millis() - state.auth.config.mfa.recent_auth_ttl_ms - 1000,
    );
    write_session(state.auth.session_store.as_ref(), &session_path, &session).await?;
    let refreshed = service.refresh(&enrolled.token, "test".into()).await?;
    for operation in [
        MfaRequest::Begin {
            provider_id: "totp".into(),
            label: "Test authenticator".into(),
            replace_factor_id: None,
            input: None,
        },
        MfaRequest::Remove {
            factor_id: only_totp_id(&state.boot, "root").await?,
        },
        MfaRequest::RegenerateRecoveryCodes {},
    ] {
        let error = service
            .mfa(&refreshed.token, operation, "test".into())
            .await
            .err()
            .context("recent auth")?;
        ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    }
    service
        .mfa(&refreshed.token, MfaRequest::Status {}, "test".into())
        .await?;
    let renewed = service
        .step_up(
            &refreshed.token,
            StepUpRequest {
                proof: Some(state.auth.next_test_totp(&state.boot, "root").await?),
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    begin(&service, &renewed.token).await?;
    Ok(())
}

#[tokio::test]
async fn invalid_factor_attempts_are_throttled_across_sources() -> anyhow::Result<()> {
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let (enrolled, _, _) = enroll(&service, &token).await?;
    let key = local_account_key(&state.boot, "root").await?;
    let mut limited = false;
    for i in 0..12 {
        let error = service
            .step_up(
                &enrolled.token,
                StepUpRequest {
                    proof: Some(MfaProof::Factor {
                        factor_id: only_totp_id(&state.boot, "root").await?,
                        response: serde_json::json!({"code":"invalid"}),
                    }),
                },
                format!("peer-{i}"),
            )
            .await
            .err()
            .context("invalid proof")?;
        if error.code == ConsoleErrorCode::RateLimited {
            ensure!(error.retry_after_ms.is_some_and(|ms| ms > 0));
            limited = true;
            break;
        }
    }
    ensure!(limited);
    ensure!(
        super::super::read_account_lockout(state.boot.kernel().state(), &key)
            .await?
            .consecutive_failures
            == 1
    );
    // Model elapsed transient backoff without sleeping; persisted failures still
    // accumulate and eventually block a fresh process/source as well.
    for i in 1..LOCKOUT_THRESHOLD {
        *state.auth.rate() = RateState::default();
        let error = service
            .step_up(
                &enrolled.token,
                StepUpRequest {
                    proof: Some(MfaProof::Factor {
                        factor_id: only_totp_id(&state.boot, "root").await?,
                        response: serde_json::json!({"code":"invalid"}),
                    }),
                },
                format!("other-{i}"),
            )
            .await
            .err()
            .context("invalid proof")?;
        ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    }
    *state.auth.rate() = RateState::default();
    ensure!(
        super::super::read_account_lockout(state.boot.kernel().state(), &key)
            .await?
            .is_locked(xolotl_kernel::host::system_now_millis())
    );
    let error = service
        .step_up(
            &enrolled.token,
            StepUpRequest {
                proof: Some(state.auth.next_test_totp(&state.boot, "root").await?),
            },
            "fresh-source".into(),
        )
        .await
        .err()
        .context("persisted lockout")?;
    ensure!(error.code == ConsoleErrorCode::RateLimited);
    Ok(())
}

#[tokio::test]
async fn malformed_factor_policy_fails_closed_and_credentials_are_redacted() -> anyhow::Result<()> {
    let (state, service, token, password) = crate::service::tests::fixture().await?;
    let (session, codes, setup) = enroll(&service, &token).await?;
    let serialized_facts = serde_json::to_string(&state.boot.kernel().facts().all_facts()?)?;
    for secret in [
        password.as_str(),
        token.as_str(),
        session.token.as_str(),
        setup["secret"].as_str().context("secret")?,
        codes[0].as_str(),
    ] {
        ensure!(!serialized_facts.contains(secret));
    }
    let debug = format!(
        "{:?} {:?} {:?} {:?}",
        password_request(&password, Some(recovery_proof(&codes[0]))),
        MfaRequest::Continue {
            challenge_id: "challenge".into(),
            input: MfaInteractionInput::Response {
                response: serde_json::json!({"code": codes[0]})
            }
        },
        MfaResponse::Enrollment {
            challenge_id: "challenge".into(),
            factor_id: "factor".into(),
            provider_id: "totp".into(),
            label: "Authenticator".into(),
            expires_at: 0,
            step: MfaEnrollmentProgress::Challenge {
                setup: setup.clone(),
                response_schema: serde_json::json!({"type":"object"})
            }
        },
        MfaResponse::Updated {
            session,
            recovery_codes: Some(codes.clone())
        }
    );
    for secret in [
        password.as_str(),
        token.as_str(),
        setup["secret"].as_str().context("secret")?,
        codes[0].as_str(),
    ] {
        ensure!(!debug.contains(secret));
    }
    let mut record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    record.epoch.clear();
    write(
        state.boot.kernel().state(),
        "root",
        &record,
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let error = service
        .login(
            password_request(&password, Some(recovery_proof(&codes[1]))),
            "test".into(),
        )
        .await
        .err()
        .context("corrupt policy")?;
    ensure!(error.code == ConsoleErrorCode::Internal && !error.message.contains("vault"));
    Ok(())
}

#[tokio::test]
async fn public_key_login_continues_mfa_without_repeating_the_primary_proof() -> anyhow::Result<()>
{
    use crate::auth::test_key::TestSigningKey;
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let key = TestSigningKey::generate();
    let descriptor = key.descriptor();
    let mut record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    record.public_keys.push(descriptor.clone());
    write(
        state.boot.kernel().state(),
        "root",
        &record,
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let (_, codes, _) = enroll(&service, &token).await?;
    let challenge = || KeyChallengeRequest {
        username: "root".into(),
        origin: "https://console.local".into(),
    };
    let request = |challenge: KeyChallengeResponse, proof| KeyLoginRequest {
        username: "root".into(),
        challenge_id: challenge.challenge_id,
        signature: URL_SAFE_NO_PAD.encode(key.sign(challenge.transcript.as_bytes())),
        origin: challenge.origin,
        key: descriptor.clone(),
        second_factor: proof,
    };
    let first = service.begin_key_login(challenge(), "test".into()).await?;
    let crate::AuthenticationResponse::Continue(next) = service
        .finish_key_login(request(first, None), "test".into())
        .await?
    else {
        anyhow::bail!("public-key primary authentication must still require the enrolled factor");
    };
    let crate::AuthenticationStep::ChooseFactor { options } = &next.step else {
        anyhow::bail!("expected factor choices after public-key verification");
    };
    ensure!(options.factors.len() == 1 && options.factors[0].provider_id == "totp");
    ensure!(options.recovery_code_available);
    let login = service
        .continue_authentication(
            None,
            crate::ContinueAuthenticationRequest {
                continuation: next.continuation,
                input: crate::AuthenticationInput::Proof {
                    proof: recovery_proof(&codes[0]),
                },
            },
            "changed-source".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(login.authentication.mfa_level() == 2);
    Ok(())
}

#[test]
fn invalid_totp_host_configuration_rejects_startup() -> anyhow::Result<()> {
    for totp in [
        crate::mfa::TotpConfig {
            digits: 7,
            ..Default::default()
        },
        crate::mfa::TotpConfig {
            period_seconds: 0,
            ..Default::default()
        },
        crate::mfa::TotpConfig {
            clock_skew_steps: 3,
            ..Default::default()
        },
    ] {
        let mut config = crate::ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            ..Default::default()
        };
        config.auth.mfa.totp = totp;
        ensure!(ConsoleState::with_config(Arc::new(Bootstrap::in_memory()), config).is_err());
    }
    Ok(())
}
