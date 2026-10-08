//! A provider can register through several independent, single-claim rounds.

use super::*;
use std::sync::atomic::AtomicUsize;

struct MultiEnrollment {
    calls: AtomicUsize,
    begin_pause: Option<Arc<EnrollmentPause>>,
    continue_pause: Option<Arc<EnrollmentPause>>,
    begin_failure: Option<MfaProviderError>,
}

struct EnrollmentPause {
    entered: Barrier,
    release: Barrier,
}

impl MfaProvider for MultiEnrollment {
    fn descriptor(&self) -> MfaProviderDescriptor {
        MfaProviderDescriptor {
            provider_id: "multi_enrollment".into(),
            label: "Multi-round enrollment".into(),
            enrollment: Some(MfaEnrollmentDescriptor {
                begin_schema: None,
                setup_schema: json!({"type":"object"}),
                pending_schema: Some(json!({"type":"object"})),
            }),
            authentication: MfaAuthenticationDescriptor {
                proof_schema: Some(json!({"type":"string"})),
                interaction: None,
            },
        }
    }

    fn begin_enrollment<'a>(
        &'a self,
        context: MfaEnrollmentContext<'a>,
        _input: Option<&'a Value>,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ensure_context(&context)?;
            if let Some(pause) = &self.begin_pause {
                pause.entered.wait().await;
                pause.release.wait().await;
            }
            if let Some(error) = self.begin_failure {
                return Err(error);
            }
            Ok(MfaEnrollmentStep::Challenge {
                private_state: json!({"phase":0}),
                setup: json!({"prompt":"pair"}),
                response_schema: json!({"type":"string","const":"pair"}),
            })
        })
    }

    fn continue_enrollment<'a>(
        &'a self,
        context: MfaEnrollmentContext<'a>,
        private_state: &'a Value,
        input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ensure_context(&context)?;
            match (private_state["phase"].as_u64(), input) {
                (Some(0), MfaInteractionInput::Response { response })
                    if response == "pair" && context.round == 2 =>
                {
                    if let Some(pause) = &self.continue_pause {
                        pause.entered.wait().await;
                        pause.release.wait().await;
                    }
                    Ok(MfaEnrollmentStep::Pending {
                        private_state: json!({"phase":1}),
                        status: json!({"state":"waiting_for_device"}),
                        retry_after_ms: 1,
                    })
                }
                (Some(1), MfaInteractionInput::Poll {}) if context.round == 3 => {
                    Ok(MfaEnrollmentStep::Challenge {
                        private_state: json!({"phase":2}),
                        setup: json!({"prompt":"approve"}),
                        response_schema: json!({"type":"string","const":"approve"}),
                    })
                }
                (Some(2), MfaInteractionInput::Response { response })
                    if response == "approve" && context.round == 4 =>
                {
                    Ok(MfaEnrollmentStep::Verified {
                        verifier: json!({"active":true,"counter":0}),
                    })
                }
                _ => Err(MfaProviderError::InvalidProof),
            }
        })
    }

    fn verify_proof<'a>(
        &'a self,
        _context: MfaContext<'a>,
        verifier: &'a Value,
        proof: &'a Value,
    ) -> MfaFuture<'a, Value> {
        Box::pin(async move {
            if verifier["active"] != true || proof != "valid" {
                return Err(MfaProviderError::InvalidProof);
            }
            Ok(json!({"active":true,"counter":1}))
        })
    }
}

fn ensure_context(context: &MfaEnrollmentContext<'_>) -> Result<(), MfaProviderError> {
    if context.factor.purpose != MfaPurpose::Enrollment
        || context.ceremony_id != context.factor.factor_id
        || context.expires_at <= 0
    {
        return Err(MfaProviderError::InvalidState);
    }
    Ok(())
}

async fn multi_fixture(
    begin_pause: Option<Arc<EnrollmentPause>>,
    continue_pause: Option<Arc<EnrollmentPause>>,
    begin_failure: Option<MfaProviderError>,
    max_steps: u16,
) -> anyhow::Result<(ConsoleService, Arc<MultiEnrollment>, String)> {
    let (boot, mut config, _old, _signed, _key) = fixture().await?;
    let provider = Arc::new(MultiEnrollment {
        calls: AtomicUsize::new(0),
        begin_pause,
        continue_pause,
        begin_failure,
    });
    config.auth.mfa.providers = vec![provider.clone()];
    config.auth.mfa.min_poll_interval_ms = 100;
    config.auth.mfa.max_enrollment_steps = max_steps;
    let service = ConsoleService::new(ConsoleState::with_config(boot, config)?);
    let token = service
        .login(login(None), "multi-round-test".into())
        .await?
        .into_session()
        .ok()
        .context("primary session")?
        .token;
    Ok((service, provider, token))
}

fn respond(id: String, response: &str) -> MfaRequest {
    MfaRequest::Continue {
        challenge_id: id,
        input: MfaInteractionInput::Response {
            response: json!(response),
        },
    }
}

#[tokio::test]
async fn multi_round_enrollment_rotates_ids_and_reconciles_lost_final_response()
-> anyhow::Result<()> {
    let (service, provider, token) = multi_fixture(None, None, None, 16).await?;
    let MfaResponse::Enrollment {
        challenge_id: first,
        factor_id,
        step:
            MfaEnrollmentProgress::Challenge {
                setup,
                response_schema: first_schema,
            },
        ..
    } = service
        .mfa(
            &token,
            MfaRequest::Begin {
                provider_id: "multi_enrollment".into(),
                label: "Device".into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("first challenge");
    };
    ensure!(setup["prompt"] == "pair" && provider.calls.load(Ordering::SeqCst) == 1);
    ensure!(first_schema == json!({"type":"string","const":"pair"}));
    let MfaResponse::Enrollment {
        challenge_id: recovered,
        step:
            MfaEnrollmentProgress::Challenge {
                setup: recovered_setup,
                response_schema: recovered_schema,
            },
        ..
    } = service
        .mfa(&token, MfaRequest::Current {}, "test".into())
        .await?
    else {
        anyhow::bail!("recover first challenge after a lost Begin response");
    };
    ensure!(recovered == first && recovered_setup == setup && recovered_schema == first_schema);
    let MfaResponse::Enrollment {
        challenge_id: second,
        step:
            MfaEnrollmentProgress::Pending {
                status,
                retry_after_ms,
            },
        ..
    } = service
        .mfa(&token, respond(first.clone(), "pair"), "test".into())
        .await?
    else {
        anyhow::bail!("pending device");
    };
    ensure!(first != second && status["state"] == "waiting_for_device");
    ensure!(retry_after_ms >= 100 && provider.calls.load(Ordering::SeqCst) == 2);
    let MfaResponse::Enrollment {
        challenge_id: recovered,
        step:
            MfaEnrollmentProgress::Pending {
                status: recovered_status,
                ..
            },
        ..
    } = service
        .mfa(&token, MfaRequest::Current {}, "test".into())
        .await?
    else {
        anyhow::bail!("recover pending step after a lost continuation response");
    };
    ensure!(recovered == second && recovered_status == status);
    let stale = service
        .mfa(&token, respond(first, "pair"), "test".into())
        .await
        .err()
        .context("old id must be single-use")?;
    ensure!(stale.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(provider.calls.load(Ordering::SeqCst) == 2);
    let MfaResponse::Enrollment {
        challenge_id: same,
        step: MfaEnrollmentProgress::Pending { .. },
        ..
    } = service
        .mfa(
            &token,
            MfaRequest::Continue {
                challenge_id: second.clone(),
                input: MfaInteractionInput::Poll {},
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("early poll remains pending");
    };
    ensure!(same == second && provider.calls.load(Ordering::SeqCst) == 2);
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    let MfaResponse::Enrollment {
        challenge_id: third,
        step:
            MfaEnrollmentProgress::Challenge {
                setup,
                response_schema: second_schema,
            },
        ..
    } = service
        .mfa(
            &token,
            MfaRequest::Continue {
                challenge_id: second.clone(),
                input: MfaInteractionInput::Poll {},
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("second challenge");
    };
    ensure!(third != second && setup["prompt"] == "approve");
    ensure!(second_schema == json!({"type":"string","const":"approve"}));
    ensure!(second_schema != first_schema);
    let MfaResponse::Enrollment {
        challenge_id: recovered,
        step:
            MfaEnrollmentProgress::Challenge {
                setup: recovered_setup,
                response_schema: recovered_schema,
            },
        ..
    } = service
        .mfa(&token, MfaRequest::Current {}, "test".into())
        .await?
    else {
        anyhow::bail!("recover successor challenge after a lost poll response");
    };
    ensure!(recovered == third && recovered_setup == setup && recovered_schema == second_schema);
    let stale = service
        .mfa(
            &token,
            MfaRequest::Continue {
                challenge_id: second,
                input: MfaInteractionInput::Poll {},
            },
            "test".into(),
        )
        .await
        .err()
        .context("previous poll token must be spent")?;
    ensure!(stale.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(provider.calls.load(Ordering::SeqCst) == 3);
    // Deliberately discard the final response: the old bearer is invalidated,
    // and a fresh login with the newly installed factor is the reconciliation path.
    drop(
        service
            .mfa(&token, respond(third.clone(), "approve"), "test".into())
            .await?,
    );
    let stale = service
        .mfa(&token, respond(third, "approve"), "test".into())
        .await
        .err()
        .context("old bearer and final id cannot replay activation")?;
    ensure!(stale.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(provider.calls.load(Ordering::SeqCst) == 4);
    let session = service
        .login(
            login(Some(MfaProof::Factor {
                factor_id: factor_id.clone(),
                response: json!("valid"),
            })),
            "test".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("new login after lost response")?;
    let MfaResponse::Status { factors, .. } = service
        .mfa(&session.token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("factor status");
    };
    ensure!(factors.len() == 1 && factors[0].factor_id == factor_id);
    ensure!(matches!(
        service
            .mfa(&session.token, MfaRequest::Current {}, "test".into())
            .await?,
        MfaResponse::NoEnrollment
    ));
    Ok(())
}

#[tokio::test]
async fn cancel_wins_against_an_in_flight_non_final_round() -> anyhow::Result<()> {
    let pause = Arc::new(EnrollmentPause {
        entered: Barrier::new(2),
        release: Barrier::new(2),
    });
    let (service, provider, token) = multi_fixture(None, Some(pause.clone()), None, 16).await?;
    let MfaResponse::Enrollment { challenge_id, .. } = service
        .mfa(
            &token,
            MfaRequest::Begin {
                provider_id: "multi_enrollment".into(),
                label: "Device".into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("initial enrollment challenge");
    };
    let worker = service.clone();
    let worker_token = token.clone();
    let worker_id = challenge_id.clone();
    let running = tokio::spawn(async move {
        worker
            .mfa(&worker_token, respond(worker_id, "pair"), "test".into())
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), pause.entered.wait()).await?;
    let MfaResponse::Enrollment {
        challenge_id: in_flight_id,
        step: MfaEnrollmentProgress::InFlight {},
        ..
    } = service
        .mfa(&token, MfaRequest::Current {}, "test".into())
        .await?
    else {
        anyhow::bail!("current enrollment reports an in-flight continuation");
    };
    ensure!(in_flight_id == challenge_id);
    let duplicate = service
        .mfa(&token, respond(challenge_id.clone(), "pair"), "test".into())
        .await
        .err()
        .context("in-flight round cannot dispatch twice")?;
    ensure!(duplicate.code == ConsoleErrorCode::NotAuthenticated);
    ensure!(provider.calls.load(Ordering::SeqCst) == 2);
    let canceled = service
        .mfa(&token, MfaRequest::Cancel { challenge_id }, "test".into())
        .await?;
    ensure!(matches!(canceled, MfaResponse::Canceled));
    pause.release.wait().await;
    let late = running
        .await?
        .err()
        .context("canceled provider result cannot publish a successor")?;
    ensure!(late.code == ConsoleErrorCode::Conflict);
    let MfaResponse::Status { factors, .. } = service
        .mfa(&token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("factor status after cancellation");
    };
    ensure!(factors.is_empty() && provider.calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn final_call_budget_does_not_publish_an_unfinishable_round() -> anyhow::Result<()> {
    let (service, provider, token) = multi_fixture(None, None, None, 2).await?;
    let MfaResponse::Enrollment { challenge_id, .. } = service
        .mfa(
            &token,
            MfaRequest::Begin {
                provider_id: "multi_enrollment".into(),
                label: "Device".into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("initial enrollment challenge");
    };
    let exhausted = service
        .mfa(&token, respond(challenge_id.clone(), "pair"), "test".into())
        .await
        .err()
        .context("non-final last call must not publish another step")?;
    ensure!(exhausted.code == ConsoleErrorCode::Internal);
    ensure!(provider.calls.load(Ordering::SeqCst) == 2);
    let canceled = service
        .mfa(&token, MfaRequest::Cancel { challenge_id }, "test".into())
        .await?;
    ensure!(matches!(canceled, MfaResponse::Canceled));
    Ok(())
}

#[tokio::test]
async fn begin_claim_precedes_provider_work_and_can_be_canceled() -> anyhow::Result<()> {
    let pause = Arc::new(EnrollmentPause {
        entered: Barrier::new(2),
        release: Barrier::new(2),
    });
    let (service, provider, token) = multi_fixture(Some(pause.clone()), None, None, 16).await?;
    let worker = service.clone();
    let worker_token = token.clone();
    let running = tokio::spawn(async move {
        worker
            .mfa(
                &worker_token,
                MfaRequest::Begin {
                    provider_id: "multi_enrollment".into(),
                    label: "Device".into(),
                    replace_factor_id: None,
                    input: None,
                },
                "test".into(),
            )
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), pause.entered.wait()).await?;
    let MfaResponse::Enrollment {
        challenge_id,
        step: MfaEnrollmentProgress::Starting {},
        ..
    } = service
        .mfa(&token, MfaRequest::Current {}, "test".into())
        .await?
    else {
        anyhow::bail!("current enrollment exposes a cancelable begin claim");
    };
    let other_session = service
        .login(login(None), "test".into())
        .await?
        .into_session()
        .ok()
        .context("second session")?;
    ensure!(matches!(
        service
            .mfa(&other_session.token, MfaRequest::Current {}, "test".into())
            .await?,
        MfaResponse::NoEnrollment
    ));
    let foreign_cancel = service
        .mfa(
            &other_session.token,
            MfaRequest::Cancel {
                challenge_id: challenge_id.clone(),
            },
            "test".into(),
        )
        .await
        .err()
        .context("another SID cannot cancel this begin")?;
    ensure!(foreign_cancel.code == ConsoleErrorCode::NotAuthenticated);
    let duplicate = service
        .mfa(
            &token,
            MfaRequest::Begin {
                provider_id: "multi_enrollment".into(),
                label: "Duplicate".into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await
        .err()
        .context("second Begin must not reach the provider")?;
    ensure!(duplicate.code == ConsoleErrorCode::Conflict);
    ensure!(provider.calls.load(Ordering::SeqCst) == 1);
    ensure!(matches!(
        service
            .mfa(&token, MfaRequest::Cancel { challenge_id }, "test".into())
            .await?,
        MfaResponse::Canceled
    ));
    pause.release.wait().await;
    let late = running
        .await?
        .err()
        .context("canceled Begin cannot publish a first challenge")?;
    ensure!(late.code == ConsoleErrorCode::Conflict);
    ensure!(provider.calls.load(Ordering::SeqCst) == 1);
    ensure!(matches!(
        service
            .mfa(&token, MfaRequest::Current {}, "test".into())
            .await?,
        MfaResponse::NoEnrollment
    ));
    Ok(())
}

#[tokio::test]
async fn uncertain_begin_error_retains_a_discoverable_cancelable_claim() -> anyhow::Result<()> {
    let (service, provider, token) =
        multi_fixture(None, None, Some(MfaProviderError::Unavailable), 16).await?;
    let error = service
        .mfa(
            &token,
            MfaRequest::Begin {
                provider_id: "multi_enrollment".into(),
                label: "Device".into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await
        .err()
        .context("provider outcome is uncertain")?;
    ensure!(error.code == ConsoleErrorCode::Internal);
    let MfaResponse::Enrollment {
        challenge_id,
        step: MfaEnrollmentProgress::Starting {},
        ..
    } = service
        .mfa(&token, MfaRequest::Current {}, "test".into())
        .await?
    else {
        anyhow::bail!("uncertain Begin claim remains discoverable");
    };
    let duplicate = service
        .mfa(
            &token,
            MfaRequest::Begin {
                provider_id: "multi_enrollment".into(),
                label: "Duplicate".into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await
        .err()
        .context("uncertain Begin cannot be replayed")?;
    ensure!(duplicate.code == ConsoleErrorCode::Conflict);
    ensure!(provider.calls.load(Ordering::SeqCst) == 1);
    ensure!(matches!(
        service
            .mfa(&token, MfaRequest::Cancel { challenge_id }, "test".into())
            .await?,
        MfaResponse::Canceled
    ));
    Ok(())
}
