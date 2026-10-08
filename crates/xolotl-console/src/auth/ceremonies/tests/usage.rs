//! The current host admits provider work without taking custody on a policy denial.

use super::*;
use crate::ConsoleService;
use crate::mfa::{FactorAvailability, MfaProviderUsage};
use crate::protocol::ConsoleErrorCode;

fn host_with_usage(
    fixture: &Fixture,
    allow_enrollment: bool,
    allow_authentication: bool,
) -> anyhow::Result<Arc<ConsoleState>> {
    let mut config = fixture.config.clone();
    config.auth.mfa.provider_usage.insert(
        "interactive_test".into(),
        MfaProviderUsage {
            allow_enrollment,
            allow_authentication,
        },
    );
    Ok(ConsoleState::with_config(
        fixture.state.boot.clone(),
        config,
    )?)
}

async fn continue_on(
    service: &ConsoleService,
    pending: &AuthenticationContinuation,
    input: AuthenticationInput,
    bearer: Option<&str>,
) -> Result<AuthenticationResponse, crate::protocol::ConsoleFailure> {
    service
        .continue_authentication(
            bearer,
            ContinueAuthenticationRequest {
                continuation: pending.continuation.clone(),
                input,
            },
            "usage-peer".into(),
        )
        .await
}

async fn session_ids(state: &ConsoleState) -> anyhow::Result<Vec<String>> {
    let page = state
        .auth
        .session_store
        .list(
            None,
            crate::session_store::SessionPageLimits {
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

async fn assert_rejected_without_consumption(
    fixture: &Fixture,
    denied: &Arc<ConsoleState>,
    pending: &AuthenticationContinuation,
    input: impl Fn() -> AuthenticationInput,
    bearer: Option<&str>,
    expected: ConsoleErrorCode,
) -> anyhow::Result<()> {
    let ledger_path = Path::parse(LEDGER_PATH)?;
    let lockout_path = lockout_path("root")?;
    let ledger = fixture.backend().read(&ledger_path).await?;
    let lockout = fixture.backend().read(&lockout_path).await?;
    let credentials = credential_snapshot(fixture.backend()).await?;
    let sessions = session_ids(&fixture.state).await?;
    let calls = fixture.provider.calls.load(Ordering::SeqCst);
    let service = ConsoleService::new(denied.clone());
    // More than the account lockout threshold: policy denials must not become
    // password failures or make a subsequent request look rate limited.
    for _ in 0..6 {
        let error = continue_on(&service, pending, input(), bearer)
            .await
            .err()
            .context("this host cannot admit provider authentication")?;
        ensure!(error.code == expected, "{error:?}");
    }
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == calls);
    ensure!(fixture.backend().read(&ledger_path).await? == ledger);
    ensure!(fixture.backend().read(&lockout_path).await? == lockout);
    ensure!(credential_snapshot(fixture.backend()).await? == credentials);
    ensure!(session_ids(&fixture.state).await? == sessions);
    let rate = denied.auth.rate();
    ensure!(
        rate.by_user
            .values()
            .chain(rate.by_source.values())
            .chain(std::iter::once(&rate.global))
            .all(|bucket| bucket.failures == 0 && bucket.next_allowed_at == 0)
    );
    Ok(())
}

struct WithoutDirectProof(Arc<InteractiveFactor>);

impl MfaProvider for WithoutDirectProof {
    fn descriptor(&self) -> MfaProviderDescriptor {
        let mut descriptor = self.0.descriptor();
        descriptor.authentication.proof_schema = None;
        descriptor
    }

    fn verify_proof<'a>(
        &'a self,
        context: MfaContext<'a>,
        verifier: &'a JsonValue,
        response: &'a JsonValue,
    ) -> MfaFuture<'a, JsonValue> {
        // A mistakenly dispatched proof would succeed and increment the shared
        // counter, so the test observes admission rather than a default failure.
        self.0.verify_proof(context, verifier, response)
    }
}

#[tokio::test]
async fn unavailable_direct_proof_leaves_login_and_step_up_usable_on_another_host()
-> anyhow::Result<()> {
    for step_up in [false, true] {
        for installed in [false, true] {
            let fixture = Fixture::new(Behavior::Flow, |_| {}).await?;
            let mut config = fixture.config.clone();
            config.auth.mfa.providers.clear();
            if installed {
                config
                    .auth
                    .mfa
                    .providers
                    .push(Arc::new(WithoutDirectProof(fixture.provider.clone())));
            }
            let unavailable = ConsoleState::with_config(fixture.state.boot.clone(), config)?;
            let (pending, bearer) = if step_up {
                (fixture.step_up().await?, Some(fixture.token.as_str()))
            } else {
                (fixture.password_login().await?, None)
            };
            let proof = || AuthenticationInput::Proof {
                proof: MfaProof::Factor {
                    factor_id: fixture.factor_id.clone(),
                    response: json!("accepted"),
                },
            };
            assert_rejected_without_consumption(
                &fixture,
                &unavailable,
                &pending,
                proof,
                bearer,
                ConsoleErrorCode::AdmissionRejected,
            )
            .await?;
            let allowed = ConsoleService::new(fixture.state.clone());
            let session = authenticated(continue_on(&allowed, &pending, proof(), bearer).await?)?;
            ensure!(session.authentication.mfa_level() == 2);
            ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn denied_direct_proof_preserves_login_and_step_up_for_an_allowed_host() -> anyhow::Result<()>
{
    for step_up in [false, true] {
        let fixture = Fixture::new(Behavior::Flow, |_| {}).await?;
        let allowed = ConsoleService::new(host_with_usage(&fixture, false, true)?);
        let denied = host_with_usage(&fixture, true, false)?;
        let (pending, bearer) = if step_up {
            (fixture.step_up().await?, Some(fixture.token.as_str()))
        } else {
            (fixture.password_login().await?, None)
        };
        let original = challenges::inspect::<Ceremony>(
            fixture.state.boot.kernel().host_runtime(),
            fixture.backend(),
            &pending.continuation,
        )
        .await?;
        let proof = || AuthenticationInput::Proof {
            proof: MfaProof::Factor {
                factor_id: fixture.factor_id.clone(),
                response: json!("accepted"),
            },
        };
        assert_rejected_without_consumption(
            &fixture,
            &denied,
            &pending,
            proof,
            bearer,
            ConsoleErrorCode::Forbidden,
        )
        .await?;
        let session = authenticated(continue_on(&allowed, &pending, proof(), bearer).await?)?;
        ensure!(session.authentication.primary == original.payload.owner.authentication.primary);
        ensure!(matches!(
            session.authentication.secondary,
            Some(SecondaryAuthentication::Factor { factor_id, provider_id, .. })
                if factor_id == fixture.factor_id && provider_id == "interactive_test"
        ));
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
        ensure!(
            credentials::read(
                fixture.backend(),
                "root",
                crate::auth::test_credential_sealer().as_ref()
            )
            .await?
            .factors[&fixture.factor_id]
                .verifier["counter"]
                == 2
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_interactive_round_uses_current_host_policy_before_claim_or_early_poll()
-> anyhow::Result<()> {
    for step_up in [false, true] {
        let fixture = Fixture::new(Behavior::Flow, |_| {}).await?;
        let allowed = ConsoleService::new(host_with_usage(&fixture, false, true)?);
        let denied = host_with_usage(&fixture, true, false)?;
        let (pending, bearer) = if step_up {
            (fixture.step_up().await?, Some(fixture.token.as_str()))
        } else {
            (fixture.password_login().await?, None)
        };
        let select = || AuthenticationInput::SelectFactor {
            factor_id: fixture.factor_id.clone(),
        };
        assert_rejected_without_consumption(
            &fixture,
            &denied,
            &pending,
            select,
            bearer,
            ConsoleErrorCode::Forbidden,
        )
        .await?;
        let challenge = continuation(continue_on(&allowed, &pending, select(), bearer).await?)?;
        let response = || AuthenticationInput::Response {
            response: json!("accepted"),
        };
        assert_rejected_without_consumption(
            &fixture,
            &denied,
            &challenge,
            response,
            bearer,
            ConsoleErrorCode::Forbidden,
        )
        .await?;
        let waiting = continuation(continue_on(&allowed, &challenge, response(), bearer).await?)?;

        // Keep this branch observably early even on a loaded test runner. Only
        // the test clock fixture changes; the original ceremony deadline stays.
        change_ledger(fixture.backend(), &waiting.continuation, |entry| {
            entry["payload"]["state"]["waiting"]["not_before"] =
                json!(xolotl_kernel::host::system_now_millis() + 30_000);
        })
        .await?;
        assert_rejected_without_consumption(
            &fixture,
            &denied,
            &waiting,
            || AuthenticationInput::Poll {},
            bearer,
            ConsoleErrorCode::Forbidden,
        )
        .await?;
        let early = continuation(
            continue_on(&allowed, &waiting, AuthenticationInput::Poll {}, bearer).await?,
        )?;
        ensure!(early.continuation == waiting.continuation);
        ensure!(early.expires_at == pending.expires_at);
        ensure!(matches!(
            early.step,
            AuthenticationStep::Pending { retry_after_ms, .. } if retry_after_ms > 0
        ));
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 2);

        allow_poll(&fixture, &waiting).await?;
        assert_rejected_without_consumption(
            &fixture,
            &denied,
            &waiting,
            || AuthenticationInput::Poll {},
            bearer,
            ConsoleErrorCode::Forbidden,
        )
        .await?;
        let session = authenticated(
            continue_on(&allowed, &waiting, AuthenticationInput::Poll {}, bearer).await?,
        )?;
        ensure!(session.authentication.mfa_level() == 2);
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 3);
    }
    Ok(())
}

#[tokio::test]
async fn disabled_provider_does_not_block_cancelling_an_existing_interaction() -> anyhow::Result<()>
{
    for step_up in [false, true] {
        let fixture = Fixture::new(Behavior::Flow, |_| {}).await?;
        let denied = ConsoleService::new(host_with_usage(&fixture, false, false)?);
        let (pending, bearer) = if step_up {
            (fixture.step_up().await?, Some(fixture.token.as_str()))
        } else {
            (fixture.password_login().await?, None)
        };
        let challenge = continuation(fixture.select(&pending, bearer).await?)?;
        let before = credential_snapshot(fixture.backend()).await?;
        denied
            .cancel_authentication(
                bearer,
                CancelAuthenticationRequest {
                    continuation: challenge.continuation.clone(),
                },
                "usage-peer".into(),
            )
            .await?;
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
        ensure!(credential_snapshot(fixture.backend()).await? == before);
        ensure!(matches!(
            challenges::inspect::<Ceremony>(
                fixture.state.boot.kernel().host_runtime(),
                fixture.backend(),
                &challenge.continuation
            )
            .await,
            Err(AuthError::InvalidChallenge)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn disabled_provider_keeps_second_proof_required_and_allows_recovery_continuation()
-> anyhow::Result<()> {
    for step_up in [false, true] {
        let fixture = Fixture::new(Behavior::Flow, |_| {}).await?;
        let disabled = ConsoleService::new(host_with_usage(&fixture, false, false)?);
        let (pending, bearer) = if step_up {
            (
                continuation(
                    disabled
                        .step_up(
                            &fixture.token,
                            StepUpRequest { proof: None },
                            "usage-peer".into(),
                        )
                        .await?,
                )?,
                Some(fixture.token.as_str()),
            )
        } else {
            (
                continuation(
                    disabled
                        .login(
                            LoginRequest {
                                username: "root".into(),
                                password: fixture.password.clone(),
                                second_factor: None,
                            },
                            "usage-peer".into(),
                        )
                        .await?,
                )?,
                None,
            )
        };
        let AuthenticationStep::ChooseFactor { options } = &pending.step else {
            anyhow::bail!("disabled factors must not downgrade primary authentication");
        };
        ensure!(options.recovery_code_available);
        ensure!(options.factors.len() == 1);
        ensure!(options.factors[0].availability == FactorAvailability::AuthenticationDisabled);
        let before = credential_snapshot(fixture.backend()).await?;
        let session = authenticated(
            continue_on(
                &disabled,
                &pending,
                AuthenticationInput::Proof {
                    proof: MfaProof::RecoveryCode {
                        code: fixture.recovery_code.clone(),
                    },
                },
                bearer,
            )
            .await?,
        )?;
        ensure!(matches!(
            session.authentication.secondary,
            Some(SecondaryAuthentication::RecoveryCode { .. })
        ));
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 0);
        let after = credential_snapshot(fixture.backend()).await?;
        ensure!(after["epoch"] == before["epoch"] && after["factors"] == before["factors"]);
        ensure!(
            after["recovery"]
                .as_array()
                .context("remaining recovery codes")?
                .len()
                + 1
                == before["recovery"]
                    .as_array()
                    .context("original recovery codes")?
                    .len()
        );
    }
    Ok(())
}
