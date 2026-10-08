use super::*;
use crate::mfa::{
    ConsoleMfaConfig, MfaAuthenticationDescriptor, MfaEnrollmentDescriptor, MfaFuture,
    MfaInteractionDescriptor, TotpAlgorithm, TotpConfig,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn host_with_mfa(
    base: &ConsoleState,
    mfa: ConsoleMfaConfig,
) -> anyhow::Result<(Arc<ConsoleState>, ConsoleService)> {
    let mut config = crate::ConsoleConfig {
        session_store: Some(std::sync::Arc::new(
            crate::session_store::MemoryConsoleSessionStore::new(
                crate::session_store::ConsoleSessionPolicy::default(),
            ),
        )),
        ..Default::default()
    };
    config.session_store = Some(std::sync::Arc::new(
        crate::session_store::MemoryConsoleSessionStore::new(
            crate::session_store::ConsoleSessionPolicy::new(16, 10_000)?,
        ),
    ));
    config.auth.mfa = mfa;
    config.session_store = Some(base.auth.session_store.clone());
    let state = ConsoleState::with_config(base.boot.clone(), config)?;
    let service = ConsoleService::new(state.clone());
    Ok((state, service))
}

fn disabled_totp() -> ConsoleMfaConfig {
    ConsoleMfaConfig {
        install_totp: false,
        ..Default::default()
    }
}

fn changed_totp() -> ConsoleMfaConfig {
    ConsoleMfaConfig {
        totp: TotpConfig {
            algorithm: TotpAlgorithm::Sha512,
            digits: 8,
            period_seconds: 60,
            clock_skew_steps: 2,
        },
        ..Default::default()
    }
}

struct InteractiveOnlyTotp {
    calls: AtomicUsize,
}

impl MfaProvider for InteractiveOnlyTotp {
    fn descriptor(&self) -> MfaProviderDescriptor {
        MfaProviderDescriptor {
            provider_id: "totp".into(),
            label: "Interaction-only retained factor".into(),
            enrollment: None,
            authentication: MfaAuthenticationDescriptor {
                proof_schema: None,
                interaction: Some(MfaInteractionDescriptor {
                    challenge_schema: JsonValue::Bool(true),
                }),
            },
        }
    }

    fn verify_proof<'a>(
        &'a self,
        _context: MfaContext<'a>,
        _verifier: &'a JsonValue,
        _response: &'a JsonValue,
    ) -> MfaFuture<'a, JsonValue> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(MfaProviderError::InvalidProof)
        })
    }

    fn continue_enrollment<'a>(
        &'a self,
        _context: MfaEnrollmentContext<'a>,
        _private_state: &'a JsonValue,
        _input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(MfaProviderError::InvalidProof)
        })
    }
}

#[tokio::test]
async fn undeclared_operations_do_not_validate_proofs_or_count_login_failures() -> anyhow::Result<()>
{
    let (base, original, token, _) = crate::service::tests::fixture().await?;
    let (session, _, _) = enroll(&original, &token).await?;
    let factor_id = only_totp_id(&base.boot, "root").await?;
    let (challenge_id, _) = begin(&original, &session.token).await?;
    let provider = Arc::new(InteractiveOnlyTotp {
        calls: AtomicUsize::new(0),
    });
    let (state, service) = host_with_mfa(
        &base,
        ConsoleMfaConfig {
            providers: vec![provider.clone()],
            ..disabled_totp()
        },
    )?;
    let backend = base.boot.kernel().state();
    let credentials = serde_json::to_value(
        read(
            backend,
            "root",
            crate::auth::test_credential_sealer().as_ref(),
        )
        .await?,
    )?;
    let lockout_path = lockout_path("root")?;
    let lockout = backend.read(&lockout_path).await?;
    let oversized = JsonValue::String("x".repeat(MAX_PROOF_BYTES + 1));
    for _ in 0..6 {
        let error = service
            .step_up(
                &session.token,
                StepUpRequest {
                    proof: Some(MfaProof::Factor {
                        factor_id: factor_id.clone(),
                        response: oversized.clone(),
                    }),
                },
                "test".into(),
            )
            .await
            .err()
            .context("direct authentication is not declared")?;
        ensure!(error.code == ConsoleErrorCode::AdmissionRejected);
        let error = service
            .mfa(
                &session.token,
                MfaRequest::Continue {
                    challenge_id: challenge_id.clone(),
                    input: MfaInteractionInput::Response {
                        response: oversized.clone(),
                    },
                },
                "test".into(),
            )
            .await
            .err()
            .context("enrollment is not declared")?;
        ensure!(error.code == ConsoleErrorCode::AdmissionRejected);
    }
    ensure!(provider.calls.load(Ordering::SeqCst) == 0);
    ensure!(backend.read(&lockout_path).await? == lockout);
    ensure!(
        serde_json::to_value(
            read(
                backend,
                "root",
                crate::auth::test_credential_sealer().as_ref()
            )
            .await?
        )? == credentials
    );
    {
        let rate = state.auth.rate();
        ensure!(rate.by_user.values().all(|bucket| bucket.failures == 0));
        ensure!(rate.by_source.values().all(|bucket| bucket.failures == 0));
        ensure!(rate.global.failures == 0);
    }
    ensure!(
        state
            .auth
            .authenticate_token(&state.boot, &session.token)
            .await?
            .authentication
            == session.authentication
    );
    let MfaResponse::Status { factors, .. } = service
        .mfa(&session.token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("retained factor status");
    };
    // Availability covers any declared authentication path, not only direct proof.
    ensure!(factors[0].availability == FactorAvailability::Available);
    Ok(())
}

#[tokio::test]
async fn uninstalled_provider_preserves_mfa_and_recovery_consumption_across_hosts()
-> anyhow::Result<()> {
    let (base, original, token, password) = crate::service::tests::fixture().await?;
    let (session, codes, setup) = enroll(&original, &token).await?;
    let before = read(
        base.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let snapshot = serde_json::to_value(&before)?;
    let factor_id = only_totp_id(&base.boot, "root").await?;
    let (state, service) = host_with_mfa(&base, disabled_totp())?;
    let (_, another) = host_with_mfa(&base, disabled_totp())?;
    ensure!(service.mfa_providers().is_empty());
    let MfaResponse::Status {
        providers,
        factors,
        recovery_codes_remaining,
        ..
    } = service
        .mfa(&session.token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("factor status after provider removal");
    };
    ensure!(providers.is_empty() && recovery_codes_remaining == codes.len());
    ensure!(factors.len() == 1 && factors[0].factor_id == factor_id);
    ensure!(
        factors[0].provider_id == "totp"
            && factors[0].availability == FactorAvailability::ProviderNotInstalled
    );
    ensure!(
        state
            .auth
            .authenticate_token(&state.boot, &session.token)
            .await?
            .authentication
            .mfa_level()
            == 2
    );
    let options = factor_choices(
        service
            .login(password_request(&password, None), "test".into())
            .await?,
    )?;
    ensure!(options.factors == factors && options.recovery_code_available);
    let unavailable = service
        .login(
            password_request(
                &password,
                Some(MfaProof::Factor {
                    factor_id,
                    response: setup_response(&setup, 1)?,
                }),
            ),
            "test".into(),
        )
        .await
        .err()
        .context("uninstalled provider cannot verify a factor")?;
    ensure!(unavailable.code == ConsoleErrorCode::AdmissionRejected);
    ensure!(
        serde_json::to_value(
            read(
                base.boot.kernel().state(),
                "root",
                crate::auth::test_credential_sealer().as_ref()
            )
            .await?
        )? == snapshot
    );

    let proof = recovery_proof(&codes[0]);
    let (first, second) = tokio::join!(
        service.login(
            password_request(&password, Some(proof.clone())),
            "first-host".into()
        ),
        another.login(
            password_request(&password, Some(proof.clone())),
            "second-host".into()
        )
    );
    ensure!(usize::from(first.is_ok()) + usize::from(second.is_ok()) == 1);
    for result in [first, second] {
        match result {
            Ok(response) => {
                let session = response
                    .into_session()
                    .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
                ensure!(session.authentication.mfa_level() == 2);
            }
            Err(error) => ensure!(matches!(
                error.code,
                ConsoleErrorCode::Conflict | ConsoleErrorCode::NotAuthenticated
            )),
        }
    }
    // Clear local backoff so this assertion exercises persisted one-time state.
    *state.auth.rate() = RateState::default();
    let replay = service
        .login(password_request(&password, Some(proof)), "replay".into())
        .await
        .err()
        .context("consumed recovery code")?;
    ensure!(replay.code == ConsoleErrorCode::NotAuthenticated);
    let after = read(
        base.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(after.epoch == before.epoch);
    ensure!(serde_json::to_value(&after.factors)? == serde_json::to_value(&before.factors)?);
    ensure!(after.recovery.len() == before.recovery.len() - 1);
    ensure!(!after.recovery.contains(&token_hash(&codes[0])));
    Ok(())
}

#[tokio::test]
async fn reinstalled_totp_uses_retained_parameters_and_replay_state() -> anyhow::Result<()> {
    let (base, original, token, password) = crate::service::tests::fixture().await?;
    let (session, _, setup) = enroll(&original, &token).await?;
    let factor_id = only_totp_id(&base.boot, "root").await?;
    let before = read(
        base.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let (_, disabled) = host_with_mfa(&base, disabled_totp())?;
    ensure!(disabled.mfa_providers().is_empty());
    let (_, restored) = host_with_mfa(&base, changed_totp())?;
    let MfaResponse::Status { factors, .. } = restored
        .mfa(&session.token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("restored factor status");
    };
    ensure!(
        factors.len() == 1
            && factors[0].factor_id == factor_id
            && factors[0].availability == FactorAvailability::Available
    );
    ensure!(
        serde_json::to_value(
            read(
                base.boot.kernel().state(),
                "root",
                crate::auth::test_credential_sealer().as_ref()
            )
            .await?
        )? == serde_json::to_value(&before)?
    );
    // The retained device still produces six-digit SHA-256 proofs even though
    // newly enrolled devices will use eight-digit SHA-512 proofs.
    let proof = MfaProof::Factor {
        factor_id: factor_id.clone(),
        response: setup_response(&setup, 1)?,
    };
    let login = restored
        .login(
            password_request(&password, Some(proof.clone())),
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(login.authentication.mfa_level() == 2);
    let after = read(
        base.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let original_verifier = &before.factors[&factor_id].verifier;
    let retained_verifier = &after.factors[&factor_id].verifier;
    ensure!(after.epoch == before.epoch);
    ensure!(retained_verifier["config"] == original_verifier["config"]);
    ensure!(retained_verifier["secret"] == original_verifier["secret"]);
    ensure!(
        retained_verifier["last_step"]
            .as_u64()
            .context("new step")?
            > original_verifier["last_step"]
                .as_u64()
                .context("original step")?
    );
    let (_, new_setup) = begin(&restored, &login.token).await?;
    ensure!(new_setup["algorithm"] == "SHA512");
    ensure!(new_setup["digits"] == 8 && new_setup["period_seconds"] == 60);
    let replay = restored
        .login(password_request(&password, Some(proof)), "test".into())
        .await
        .err()
        .context("retained replay protection")?;
    ensure!(replay.code == ConsoleErrorCode::NotAuthenticated);
    Ok(())
}

#[tokio::test]
async fn unavailable_confirmation_preserves_pending_until_provider_is_reinstalled()
-> anyhow::Result<()> {
    let (base, original, token, _) = crate::service::tests::fixture().await?;
    let (challenge_id, setup) = begin(&original, &token).await?;
    let before = read(
        base.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let pending = before.pending.as_ref().context("pending enrollment")?;
    let (_, disabled) = host_with_mfa(&base, disabled_totp())?;
    let unavailable = disabled
        .mfa(
            &token,
            MfaRequest::Continue {
                challenge_id: challenge_id.clone(),
                input: MfaInteractionInput::Response {
                    response: setup_response(&setup, 0)?,
                },
            },
            "test".into(),
        )
        .await
        .err()
        .context("confirmation needs its provider")?;
    ensure!(unavailable.code == ConsoleErrorCode::AdmissionRejected);
    ensure!(
        serde_json::to_value(
            read(
                base.boot.kernel().state(),
                "root",
                crate::auth::test_credential_sealer().as_ref()
            )
            .await?
        )? == serde_json::to_value(&before)?,
        "failed confirmation must retain the verifier, epoch and original deadline"
    );
    let (_, restored) = host_with_mfa(&base, changed_totp())?;
    let MfaResponse::Updated {
        session,
        recovery_codes,
    } = restored
        .mfa(
            &token,
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
        anyhow::bail!("confirmation after provider restoration");
    };
    ensure!(session.authentication.mfa_level() == 1 && recovery_codes.is_some());
    let after = read(
        base.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(after.epoch != before.epoch && after.pending.is_none());
    ensure!(after.factors.len() == 1);
    let factor = after
        .factors
        .get(&pending.factor_id)
        .context("same factor")?;
    ensure!(factor.provider_id == pending.provider_id);
    let private_state = pending
        .waiting
        .private_state()
        .context("enrollment private state")?;
    ensure!(factor.verifier["secret"] == private_state["secret"]);
    ensure!(factor.verifier["config"] == private_state["config"]);
    Ok(())
}

struct RecoveryNamedProvider {
    calls: AtomicUsize,
}

impl MfaProvider for RecoveryNamedProvider {
    fn descriptor(&self) -> MfaProviderDescriptor {
        MfaProviderDescriptor {
            provider_id: "recovery_code".into(),
            label: "Independent test factor".into(),
            enrollment: Some(MfaEnrollmentDescriptor {
                begin_schema: None,
                setup_schema: serde_json::json!(true),
                pending_schema: None,
            }),
            authentication: MfaAuthenticationDescriptor {
                proof_schema: Some(serde_json::json!({"type":"integer","minimum":0})),
                interaction: None,
            },
        }
    }

    fn begin_enrollment<'a>(
        &'a self,
        _context: MfaEnrollmentContext<'a>,
        _input: Option<&'a JsonValue>,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async {
            Ok(MfaEnrollmentStep::Challenge {
                setup: JsonValue::Null,
                response_schema: serde_json::json!({"type":"integer","minimum":0}),
                private_state: serde_json::json!({"next":0}),
            })
        })
    }

    fn continue_enrollment<'a>(
        &'a self,
        context: MfaEnrollmentContext<'a>,
        private_state: &'a JsonValue,
        input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async move {
            let MfaInteractionInput::Response { response } = input else {
                return Err(MfaProviderError::InvalidInput);
            };
            let verifier = self
                .verify_proof(context.factor, private_state, response)
                .await?;
            Ok(MfaEnrollmentStep::Verified { verifier })
        })
    }

    fn verify_proof<'a>(
        &'a self,
        _context: MfaContext<'a>,
        verifier: &'a JsonValue,
        proof: &'a JsonValue,
    ) -> MfaFuture<'a, JsonValue> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let next = verifier["next"]
                .as_u64()
                .ok_or(MfaProviderError::InvalidState)?;
            if proof.as_u64() != Some(next) {
                return Err(MfaProviderError::InvalidProof);
            }
            Ok(serde_json::json!({"next":next + 1}))
        })
    }
}

#[tokio::test]
async fn provider_name_cannot_intercept_account_recovery_proofs() -> anyhow::Result<()> {
    let (base, _, token, password) = crate::service::tests::fixture().await?;
    let provider = Arc::new(RecoveryNamedProvider {
        calls: AtomicUsize::new(0),
    });
    let (_, service) = host_with_mfa(
        &base,
        ConsoleMfaConfig {
            providers: vec![provider.clone()],
            ..disabled_totp()
        },
    )?;
    let MfaResponse::Enrollment {
        challenge_id,
        factor_id,
        ..
    } = service
        .mfa(
            &token,
            MfaRequest::Begin {
                provider_id: "recovery_code".into(),
                label: "Separate factor".into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("custom provider enrollment");
    };
    let MfaResponse::Updated { recovery_codes, .. } = service
        .mfa(
            &token,
            MfaRequest::Continue {
                challenge_id,
                input: MfaInteractionInput::Response {
                    response: serde_json::json!(0),
                },
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("custom provider confirmation");
    };
    ensure!(provider.calls.load(Ordering::Relaxed) == 1);
    let codes = recovery_codes.context("account recovery codes")?;
    let before = read(
        base.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let recovery = service
        .login(
            password_request(&password, Some(recovery_proof(&codes[0]))),
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(recovery.authentication.mfa_level() == 2);
    ensure!(matches!(
        recovery.authentication.secondary,
        Some(SecondaryAuthentication::RecoveryCode { .. })
    ));
    ensure!(provider.calls.load(Ordering::Relaxed) == 1);
    let recovered = read(
        base.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(recovered.recovery.len() == before.recovery.len() - 1);
    ensure!(recovered.factors[&factor_id].verifier == before.factors[&factor_id].verifier);
    let login = service
        .login(
            password_request(
                &password,
                Some(MfaProof::Factor {
                    factor_id: factor_id.clone(),
                    response: serde_json::json!(1),
                }),
            ),
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(login.authentication.mfa_level() == 2 && provider.calls.load(Ordering::Relaxed) == 2);
    ensure!(matches!(
        &login.authentication.secondary,
        Some(SecondaryAuthentication::Factor {
            factor_id: selected,
            provider_id,
            ..
        }) if selected == &factor_id && provider_id == "recovery_code"
    ));
    let verified = read(
        base.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(verified.factors[&factor_id].verifier["next"] == 2);
    ensure!(verified.recovery == recovered.recovery && verified.epoch == before.epoch);
    Ok(())
}
