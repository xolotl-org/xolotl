use super::*;

struct Enrollment {
    challenge_id: String,
    factor_id: String,
    setup: JsonValue,
}

async fn begin_factor(
    service: &ConsoleService,
    token: &str,
    label: &str,
    replace_factor_id: Option<String>,
) -> anyhow::Result<Enrollment> {
    let MfaResponse::Enrollment {
        challenge_id,
        factor_id,
        provider_id,
        label: returned_label,
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = service
        .mfa(
            token,
            MfaRequest::Begin {
                provider_id: "totp".into(),
                label: label.into(),
                replace_factor_id,
                input: None,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("enrollment");
    };
    ensure!(provider_id == "totp" && returned_label == label);
    Ok(Enrollment {
        challenge_id,
        factor_id,
        setup,
    })
}

async fn confirm_factor(
    service: &ConsoleService,
    token: &str,
    enrollment: &Enrollment,
) -> anyhow::Result<LoginResponse> {
    let MfaResponse::Updated {
        session,
        recovery_codes,
    } = service
        .mfa(
            token,
            MfaRequest::Continue {
                challenge_id: enrollment.challenge_id.clone(),
                input: MfaInteractionInput::Response {
                    response: setup_response(&enrollment.setup, 0)?,
                },
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("confirmed factor");
    };
    if session.authentication.mfa_level() >= 2 {
        return Ok(session);
    }
    let code = recovery_codes
        .context("first factor recovery codes")?
        .pop()
        .context("recovery proof")?;
    service
        .step_up(
            &session.token,
            StepUpRequest {
                proof: Some(MfaProof::RecoveryCode { code }),
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("verified factor management session"))
}

fn factor_proof(enrollment: &Enrollment, offset: u64) -> anyhow::Result<MfaProof> {
    Ok(MfaProof::Factor {
        factor_id: enrollment.factor_id.clone(),
        response: setup_response(&enrollment.setup, offset)?,
    })
}

#[tokio::test]
async fn same_provider_devices_keep_separate_identity_replay_state_and_lifecycles()
-> anyhow::Result<()> {
    let (base, _, token, password) = crate::service::tests::fixture().await?;
    // This lifecycle intentionally retains the enrollment bearer while two
    // independent login sessions exercise the old devices before replacement.
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
    config.session_store = Some(base.auth.session_store.clone());
    let state = ConsoleState::with_config(base.boot.clone(), config)?;
    let service = ConsoleService::new(state.clone());
    let first = begin_factor(&service, &token, "Phone", None).await?;
    let session = confirm_factor(&service, &token, &first).await?;
    let second = begin_factor(&service, &session.token, "Backup", None).await?;
    let session = confirm_factor(&service, &session.token, &second).await?;
    ensure!(first.factor_id != second.factor_id);
    let before = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(before.factors.len() == 2);
    let MfaResponse::Status { factors, .. } = service
        .mfa(&session.token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("initial instance summaries");
    };
    ensure!(factors.len() == 2);
    for summary in &factors {
        ensure!(
            summary.provider_id == "totp"
                && summary.availability == FactorAvailability::Available
                && summary.last_used_at.is_none()
        );
        ensure!(summary.created_at > 0);
        ensure!(
            summary.label
                == if summary.factor_id == first.factor_id {
                    "Phone"
                } else {
                    "Backup"
                }
        );
    }
    let replacement = begin_factor(
        &service,
        &session.token,
        "New phone",
        Some(first.factor_id.clone()),
    )
    .await?;
    ensure!(replacement.factor_id != first.factor_id && replacement.factor_id != second.factor_id);
    let MfaResponse::Renamed { factor } = service
        .mfa(
            &session.token,
            MfaRequest::Rename {
                factor_id: second.factor_id.clone(),
                label: "Safe backup".into(),
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("renamed factor");
    };
    ensure!(factor.factor_id == second.factor_id && factor.label == "Safe backup");
    ensure!(factor.provider_id == "totp" && factor.availability == FactorAvailability::Available);
    let renamed = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(renamed.epoch == before.epoch);
    ensure!(renamed.factors[&first.factor_id].label == "Phone");
    ensure!(
        renamed.factors[&second.factor_id].verifier == before.factors[&second.factor_id].verifier
    );
    state
        .auth
        .authenticate_token(&state.boot, &session.token)
        .await?;

    ensure!(
        renamed
            .pending
            .as_ref()
            .context("rename must retain pending replacement")?
            .id
            == replacement.challenge_id
    );
    let primary = service
        .login(
            password_request(&password, Some(factor_proof(&first, 1)?)),
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(
        primary.authentication.mfa_level() == 2,
        "the original device remains active until confirmation"
    );
    let second_login = service
        .login(
            password_request(&password, Some(factor_proof(&second, 1)?)),
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(second_login.authentication.mfa_level() == 2);
    let used = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(used.factors[&first.factor_id].last_used_at.is_some());
    ensure!(used.factors[&second.factor_id].last_used_at.is_some());
    let session = confirm_factor(&service, &session.token, &replacement).await?;
    state
        .auth
        .authenticate_token(&state.boot, &session.token)
        .await?;
    let replaced = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(!replaced.factors.contains_key(&first.factor_id));
    ensure!(replaced.factors.contains_key(&replacement.factor_id));
    ensure!(
        replaced.factors[&replacement.factor_id]
            .last_used_at
            .is_none()
    );
    ensure!(
        replaced.factors[&second.factor_id].verifier == used.factors[&second.factor_id].verifier
    );
    ensure!(replaced.factors[&second.factor_id].label == "Safe backup");
    assert_invalid_session(&state, &second_login.token).await?;

    let rejected = service
        .login(
            password_request(&password, Some(factor_proof(&first, 1)?)),
            "test".into(),
        )
        .await
        .err()
        .context("replaced factor id")?;
    ensure!(rejected.code == ConsoleErrorCode::NotAuthenticated);
    *state.auth.rate() = RateState::default();
    let login = service
        .login(
            password_request(&password, Some(factor_proof(&replacement, 1)?)),
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(login.authentication.mfa_level() == 2);
    let MfaResponse::Updated { session, .. } = service
        .mfa(
            &login.token,
            MfaRequest::Remove {
                factor_id: replacement.factor_id.clone(),
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("factor removal");
    };
    let retained = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(retained.factors.len() == 1 && retained.factors.contains_key(&second.factor_id));
    ensure!(!retained.recovery.is_empty());
    let options = factor_choices(
        service
            .login(password_request(&password, None), "test".into())
            .await?,
    )?;
    ensure!(options.factors.len() == 1 && options.factors[0].factor_id == second.factor_id);
    ensure!(options.factors[0].label == "Safe backup" && options.recovery_code_available);
    let MfaResponse::Updated { session, .. } = service
        .mfa(
            &session.token,
            MfaRequest::Remove {
                factor_id: second.factor_id,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("last factor removal");
    };
    ensure!(session.authentication == login.authentication);
    let retained = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(retained.factors.is_empty() && retained.recovery.is_empty());
    Ok(())
}

#[tokio::test]
async fn instance_limit_counts_devices_and_replacement_does_not_need_an_extra_slot()
-> anyhow::Result<()> {
    let (state, service, mut token, _) = crate::service::tests::fixture().await?;
    let mut ids = Vec::new();
    for index in 0..MAX_FACTORS {
        let enrolled = begin_factor(&service, &token, &format!("Device {index}"), None).await?;
        token = confirm_factor(&service, &token, &enrolled).await?.token;
        ids.push(enrolled.factor_id);
    }
    let before = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?
    .persisted;
    ensure!(
        begin_factor(&service, &token, "Overflow", None)
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
        .persisted
            == before
    );
    let replacement = begin_factor(&service, &token, "Replacement", Some(ids[0].clone())).await?;
    token = confirm_factor(&service, &token, &replacement).await?.token;
    let retained = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(retained.factors.len() == MAX_FACTORS);
    ensure!(!retained.factors.contains_key(&ids[0]));
    ensure!(retained.factors.contains_key(&replacement.factor_id));
    for id in &ids[1..] {
        ensure!(retained.factors.contains_key(id));
    }
    let MfaResponse::Status {
        max_factors,
        factors,
        ..
    } = service
        .mfa(&token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("status");
    };
    ensure!(max_factors == MAX_FACTORS && factors.len() == MAX_FACTORS);
    Ok(())
}

#[test]
fn method_keyed_and_ambiguous_proofs_are_rejected_in_v1() -> anyhow::Result<()> {
    for proof in [
        serde_json::json!({"method":"totp","response":{"code":"123456"}}),
        serde_json::json!({"kind":"factor","factor_id":"a","provider_id":"totp","response":{}}),
        serde_json::json!({"kind":"recovery_code","code":"secret","factor_id":"a"}),
        serde_json::json!({"kind":"factor","response":{"code":"123456"}}),
    ] {
        ensure!(serde_json::from_value::<MfaProof>(proof).is_err());
    }
    for request in [
        serde_json::json!({"operation":"begin","method":"totp"}),
        serde_json::json!({"operation":"remove","method":"totp"}),
        serde_json::json!({"operation":"begin","provider_id":"totp"}),
    ] {
        ensure!(serde_json::from_value::<MfaRequest>(request).is_err());
    }
    for proof in [
        MfaProof::Factor {
            factor_id: "id".into(),
            response: serde_json::json!({"private":"secret-proof"}),
        },
        MfaProof::RecoveryCode {
            code: "secret-recovery".into(),
        },
    ] {
        ensure!(!format!("{proof:?}").contains("secret-"));
    }
    Ok(())
}

#[tokio::test]
async fn invalid_metadata_and_replacement_targets_leave_the_account_unchanged() -> anyhow::Result<()>
{
    let (state, service, token, _) = crate::service::tests::fixture().await?;
    let factor = begin_factor(&service, &token, "Valid label", None).await?;
    let session = confirm_factor(&service, &token, &factor).await?;
    let original = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?
    .persisted;
    for label in [
        String::new(),
        "  ".into(),
        "bad\nlabel".into(),
        "x".repeat(129),
    ] {
        for operation in [
            MfaRequest::Begin {
                provider_id: "totp".into(),
                label: label.clone(),
                replace_factor_id: None,
                input: None,
            },
            MfaRequest::Rename {
                factor_id: factor.factor_id.clone(),
                label,
            },
        ] {
            ensure!(
                service
                    .mfa(&session.token, operation, "test".into())
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
                .persisted
                    == original
            );
        }
    }
    for operation in [
        MfaRequest::Begin {
            provider_id: "totp".into(),
            label: "Replacement".into(),
            replace_factor_id: Some("another-account-factor".into()),
            input: None,
        },
        MfaRequest::Remove {
            factor_id: "totp".into(),
        },
        MfaRequest::Rename {
            factor_id: "totp".into(),
            label: "Ambiguous provider key".into(),
        },
    ] {
        ensure!(
            service
                .mfa(&session.token, operation, "test".into())
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
            .persisted
                == original
        );
    }
    Ok(())
}

#[tokio::test]
async fn old_method_keyed_vault_records_do_not_silently_disable_mfa() -> anyhow::Result<()> {
    let (state, service, token, password) = crate::service::tests::fixture().await?;
    let (_, _, setup) = enroll(&service, &token).await?;
    let record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let mut legacy = serde_json::to_value(&record)?;
    legacy["factors"] = serde_json::json!({"totp": {"secret": setup["secret"], "last_step": 0}});
    let key = local_account_key(&state.boot, "root").await?;
    let path = crate::paths::credential_path(key.authority_id(), key.instance_id())?;
    let value = Value::string(serde_json::to_string(&legacy)?);
    state
        .boot
        .kernel()
        .state()
        .write_set(&path, value.clone())
        .await?;
    let error = service
        .login(password_request(&password, None), "test".into())
        .await
        .err()
        .context("unsupported factor record")?;
    ensure!(error.code == ConsoleErrorCode::Internal && error.mfa.is_none());
    ensure!(state.boot.kernel().state().read(&path).await? == Some(value));
    Ok(())
}
