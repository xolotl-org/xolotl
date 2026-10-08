use super::*;
use crate::auth::credentials::MAX_CREDENTIAL_BYTES;
use crate::mfa::{MfaAuthenticationDescriptor, MfaEnrollmentDescriptor, MfaFuture};
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Notify, Semaphore};
use xolotl_state::{StateBoundedRead, StateRead, StateResult};

#[derive(Clone, Copy, Debug)]
enum Stage {
    Begin,
    Confirm,
    None,
}

struct GatedFactor {
    stage: Stage,
    entered: Notify,
    release: Semaphore,
    confirm_calls: AtomicUsize,
    confirm_error: Option<MfaProviderError>,
    invalid_begin_step: bool,
}

impl GatedFactor {
    fn new(stage: Stage) -> Self {
        Self {
            stage,
            entered: Notify::new(),
            release: Semaphore::new(0),
            confirm_calls: AtomicUsize::new(0),
            confirm_error: None,
            invalid_begin_step: false,
        }
    }

    fn with_invalid_begin_step(stage: Stage) -> Self {
        Self {
            invalid_begin_step: true,
            ..Self::new(stage)
        }
    }

    fn with_confirm_error(error: MfaProviderError) -> Self {
        Self {
            confirm_error: Some(error),
            ..Self::new(Stage::None)
        }
    }

    async fn wait(&self) -> Result<(), MfaProviderError> {
        self.entered.notify_one();
        self.release
            .acquire()
            .await
            .map_err(|_error| MfaProviderError::Unavailable)?
            .forget();
        Ok(())
    }
}

impl MfaProvider for GatedFactor {
    fn descriptor(&self) -> crate::mfa::MfaProviderDescriptor {
        crate::mfa::MfaProviderDescriptor {
            provider_id: "gated".into(),
            label: "Test factor".into(),
            enrollment: Some(MfaEnrollmentDescriptor {
                begin_schema: None,
                setup_schema: serde_json::json!(true),
                pending_schema: None,
            }),
            authentication: MfaAuthenticationDescriptor {
                proof_schema: Some(serde_json::json!({"type":"string"})),
                interaction: None,
            },
        }
    }

    fn begin_enrollment<'a>(
        &'a self,
        _context: MfaEnrollmentContext<'a>,
        _input: Option<&'a JsonValue>,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async move {
            if matches!(self.stage, Stage::Begin) {
                self.wait().await?;
            }
            Ok(MfaEnrollmentStep::Challenge {
                setup: JsonValue::Null,
                response_schema: if self.invalid_begin_step {
                    JsonValue::Null
                } else {
                    serde_json::json!({"type":"string"})
                },
                private_state: serde_json::json!({"counter":0}),
            })
        })
    }

    fn verify_proof<'a>(
        &'a self,
        _context: MfaContext<'a>,
        verifier: &'a JsonValue,
        proof: &'a JsonValue,
    ) -> MfaFuture<'a, JsonValue> {
        Box::pin(async move {
            if proof.as_str() != Some("valid") {
                return Err(MfaProviderError::InvalidProof);
            }
            let counter = verifier["counter"]
                .as_u64()
                .ok_or(MfaProviderError::InvalidState)?;
            Ok(serde_json::json!({"counter":counter + 1}))
        })
    }

    fn continue_enrollment<'a>(
        &'a self,
        _context: MfaEnrollmentContext<'a>,
        _private_state: &'a JsonValue,
        input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async move {
            self.confirm_calls.fetch_add(1, Ordering::SeqCst);
            if matches!(self.stage, Stage::Confirm) {
                self.wait().await?;
            }
            if let Some(error) = self.confirm_error {
                return Err(error);
            }
            let MfaInteractionInput::Response { response } = input else {
                return Err(MfaProviderError::InvalidInput);
            };
            if response.as_str() != Some("valid") {
                return Err(MfaProviderError::InvalidProof);
            }
            Ok(MfaEnrollmentStep::Verified {
                verifier: serde_json::json!({"counter":1}),
            })
        })
    }
}

fn another_host(
    base: &ConsoleState,
    provider: Arc<GatedFactor>,
) -> anyhow::Result<Arc<ConsoleState>> {
    let mut config = crate::ConsoleConfig {
        session_store: Some(std::sync::Arc::new(
            crate::session_store::MemoryConsoleSessionStore::new(
                crate::session_store::ConsoleSessionPolicy::default(),
            ),
        )),
        ..Default::default()
    };
    config.auth.mfa.providers.push(provider);
    config.session_store = Some(base.auth.session_store.clone());
    Ok(ConsoleState::with_config(base.boot.clone(), config)?)
}

fn valid_confirmation(challenge_id: &str) -> MfaRequest {
    MfaRequest::Continue {
        challenge_id: challenge_id.into(),
        input: MfaInteractionInput::Response {
            response: JsonValue::String("valid".into()),
        },
    }
}

#[tokio::test]
async fn begin_rejects_setup_that_would_not_fit_its_confirmation_claim() -> anyhow::Result<()> {
    let provider = Arc::new(GatedFactor::new(Stage::None));
    let (state, token) = fixture(provider).await?;
    let mut record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let id = "t000000000000000000000000";
    let sid = token.split_once('.').context("bearer")?.0;
    record.password = Some(String::new());
    record.pending = Some(PendingEnrollment {
        id: id.into(),
        sid: sid.into(),
        factor_id: id.into(),
        provider_id: "gated".into(),
        label: "Gated device".into(),
        replace_factor_id: None,
        expires_at: xolotl_kernel::host::system_now_millis() + 300_000,
        round: 1,
        waiting: EnrollmentWaiting::Challenge {
            private_state: serde_json::json!({"counter":0}),
            setup: serde_json::Value::Null,
            response_schema: serde_json::json!({"type":"string"}),
        },
        phase: EnrollmentPhase::Ready {},
    });
    let ready_len = serde_json::to_string(&record)?.len();
    record.pending.as_mut().context("pending")?.phase = EnrollmentPhase::InFlight {
        claim_id: id.into(),
    };
    let growth = serde_json::to_string(&record)?.len() - ready_len;
    record.pending = None;
    record.password = Some("x".repeat(MAX_CREDENTIAL_BYTES - growth + 1 - ready_len));
    write(
        state.boot.kernel().state(),
        "root",
        &record,
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let before = serde_json::to_value(
        &read(
            state.boot.kernel().state(),
            "root",
            crate::auth::test_credential_sealer().as_ref(),
        )
        .await?,
    )?;
    let error = state
        .auth
        .manage_mfa(
            &state.boot,
            &token,
            MfaRequest::Begin {
                provider_id: "gated".into(),
                label: "Gated device".into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await
        .err()
        .context("setup cannot be published without claim capacity")?;
    ensure!(matches!(error, AuthError::InvalidCredentialRequest));
    let after = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(serde_json::to_value(&after)? == before && after.pending.is_none());
    Ok(())
}

#[tokio::test]
async fn invalid_begin_step_restores_the_displaced_ready_round() -> anyhow::Result<()> {
    let provider = Arc::new(GatedFactor::new(Stage::None));
    let (first, token) = fixture(provider).await?;
    let MfaRequest::Continue {
        challenge_id: original_id,
        ..
    } = request(&first, &token, Stage::None).await?
    else {
        anyhow::bail!("first ready enrollment");
    };
    let before = serde_json::to_value(
        &read(
            first.boot.kernel().state(),
            "root",
            crate::auth::test_credential_sealer().as_ref(),
        )
        .await?,
    )?;
    let second = another_host(
        &first,
        Arc::new(GatedFactor::with_invalid_begin_step(Stage::None)),
    )?;
    let error = second
        .auth
        .manage_mfa(
            &second.boot,
            &token,
            request(&second, &token, Stage::Begin).await?,
            "invalid-step".into(),
        )
        .await
        .err()
        .context("provider's invalid setup response schema")?;
    ensure!(matches!(error, AuthError::State(_)));
    let retained = read(
        second.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(serde_json::to_value(&retained)? == before);
    ensure!(matches!(
        retained.pending.context("displaced round restored")?.phase,
        EnrollmentPhase::Ready {}
    ));
    let MfaResponse::Enrollment { challenge_id, .. } = first
        .auth
        .manage_mfa(
            &first.boot,
            &token,
            MfaRequest::Current {},
            "current".into(),
        )
        .await?
    else {
        anyhow::bail!("previous enrollment remains current");
    };
    ensure!(challenge_id == original_id);
    Ok(())
}

#[tokio::test]
async fn canceled_begin_is_not_resurrected_by_late_local_cleanup() -> anyhow::Result<()> {
    let provider = Arc::new(GatedFactor::new(Stage::None));
    let (first, token) = fixture(provider).await?;
    drop(request(&first, &token, Stage::None).await?);
    let invalid_provider = Arc::new(GatedFactor::with_invalid_begin_step(Stage::Begin));
    let second = another_host(&first, invalid_provider.clone())?;
    let operation = request(&second, &token, Stage::Begin).await?;
    let work = tokio::spawn({
        let second = second.clone();
        let token = token.clone();
        async move {
            second
                .auth
                .manage_mfa(&second.boot, &token, operation, "invalid-step".into())
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), invalid_provider.entered.notified()).await?;
    let claimed = read(
        first.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?
    .pending
    .context("starting claim")?;
    ensure!(matches!(claimed.phase, EnrollmentPhase::InFlight { .. }));
    ensure!(matches!(
        first
            .auth
            .manage_mfa(
                &first.boot,
                &token,
                MfaRequest::Cancel {
                    challenge_id: claimed.id
                },
                "cancel".into(),
            )
            .await?,
        MfaResponse::Canceled
    ));
    invalid_provider.release.add_permits(1);
    let error = tokio::time::timeout(Duration::from_secs(5), work)
        .await??
        .err()
        .context("late invalid step cannot publish")?;
    ensure!(matches!(error, AuthError::State(_)));
    ensure!(
        read(
            first.boot.kernel().state(),
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
async fn confirmation_claim_precedes_provider_dispatch_across_hosts() -> anyhow::Result<()> {
    let provider = Arc::new(GatedFactor::new(Stage::Confirm));
    let (first, token) = fixture(provider.clone()).await?;
    let second = another_host(&first, provider.clone())?;
    let request = request(&first, &token, Stage::Confirm).await?;
    let MfaRequest::Continue { challenge_id, .. } = &request else {
        anyhow::bail!("confirmation request");
    };
    let challenge_id = challenge_id.clone();
    let task = tokio::spawn({
        let first = first.clone();
        let token = token.clone();
        async move {
            first
                .auth
                .manage_mfa(&first.boot, &token, request, "first".into())
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), provider.entered.notified()).await?;
    let held = read(
        second.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(matches!(
        held.pending.as_ref().context("claimed pending")?.phase,
        EnrollmentPhase::InFlight { .. }
    ));
    let error = second
        .auth
        .manage_mfa(
            &second.boot,
            &token,
            valid_confirmation(&challenge_id),
            "second".into(),
        )
        .await
        .err()
        .context("second confirmation must not dispatch")?;
    ensure!(matches!(error, AuthError::InvalidChallenge));
    let begin = MfaRequest::Begin {
        provider_id: "gated".into(),
        label: "Replacement setup".into(),
        replace_factor_id: None,
        input: None,
    };
    let error = second
        .auth
        .manage_mfa(&second.boot, &token, begin, "second".into())
        .await
        .err()
        .context("new Begin cannot replace the active claim")?;
    ensure!(matches!(error, AuthError::CredentialConflict));
    ensure!(provider.confirm_calls.load(Ordering::SeqCst) == 1);
    provider.release.add_permits(1);
    ensure!(matches!(
        tokio::time::timeout(Duration::from_secs(5), task).await???,
        MfaResponse::Updated { .. }
    ));
    let current = read(
        second.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(current.pending.is_none() && current.factors.len() == 1);
    Ok(())
}

#[tokio::test]
async fn concurrent_begin_cannot_replace_an_in_flight_setup() -> anyhow::Result<()> {
    let slow_provider = Arc::new(GatedFactor::new(Stage::Begin));
    let (first, token) = fixture(slow_provider.clone()).await?;
    let fast_provider = Arc::new(GatedFactor::new(Stage::None));
    let second = another_host(&first, fast_provider)?;
    let first_begin = request(&first, &token, Stage::Begin).await?;
    let task = tokio::spawn({
        let first = first.clone();
        let token = token.clone();
        async move {
            first
                .auth
                .manage_mfa(&first.boot, &token, first_begin, "slow".into())
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), slow_provider.entered.notified()).await?;
    let error = second
        .auth
        .manage_mfa(
            &second.boot,
            &token,
            request(&second, &token, Stage::Begin).await?,
            "fast".into(),
        )
        .await
        .err()
        .context("another Begin cannot replace an in-flight setup")?;
    ensure!(matches!(error, AuthError::CredentialConflict));
    slow_provider.release.add_permits(1);
    let MfaResponse::Enrollment {
        challenge_id,
        factor_id,
        ..
    } = tokio::time::timeout(Duration::from_secs(5), task).await???
    else {
        anyhow::bail!("original enrollment setup");
    };
    let current = read(
        second.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let pending = current.pending.context("original pending setup")?;
    ensure!(pending.id == challenge_id && pending.factor_id == factor_id);
    ensure!(matches!(pending.phase, EnrollmentPhase::Ready {}));
    ensure!(current.factors.is_empty());
    Ok(())
}

#[tokio::test]
async fn cancel_explicitly_abandons_an_in_flight_confirmation() -> anyhow::Result<()> {
    let provider = Arc::new(GatedFactor::new(Stage::Confirm));
    let (first, token) = fixture(provider.clone()).await?;
    let second = another_host(&first, provider.clone())?;
    let request = request(&first, &token, Stage::Confirm).await?;
    let MfaRequest::Continue { challenge_id, .. } = &request else {
        anyhow::bail!("confirmation request");
    };
    let challenge_id = challenge_id.clone();
    let task = tokio::spawn({
        let first = first.clone();
        let token = token.clone();
        async move {
            first
                .auth
                .manage_mfa(&first.boot, &token, request, "first".into())
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), provider.entered.notified()).await?;
    ensure!(matches!(
        second
            .auth
            .manage_mfa(
                &second.boot,
                &token,
                MfaRequest::Cancel { challenge_id },
                "second".into(),
            )
            .await?,
        MfaResponse::Canceled
    ));
    provider.release.add_permits(1);
    let error = tokio::time::timeout(Duration::from_secs(5), task)
        .await??
        .err()
        .context("canceled confirmation cannot install")?;
    ensure!(matches!(error, AuthError::CredentialConflict));
    let current = read(
        second.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(current.pending.is_none() && current.factors.is_empty());
    Ok(())
}

#[tokio::test]
async fn dropped_confirmation_future_keeps_its_claim_until_explicit_cancel() -> anyhow::Result<()> {
    let provider = Arc::new(GatedFactor::new(Stage::Confirm));
    let (first, token) = fixture(provider.clone()).await?;
    let second = another_host(&first, provider.clone())?;
    let request = request(&first, &token, Stage::Confirm).await?;
    let MfaRequest::Continue { challenge_id, .. } = &request else {
        anyhow::bail!("confirmation request");
    };
    let challenge_id = challenge_id.clone();
    let task = tokio::spawn({
        let first = first.clone();
        let token = token.clone();
        async move {
            first
                .auth
                .manage_mfa(&first.boot, &token, request, "first".into())
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), provider.entered.notified()).await?;
    task.abort();
    ensure!(task.await.is_err());
    ensure!(matches!(
        read(
            second.boot.kernel().state(),
            "root",
            crate::auth::test_credential_sealer().as_ref()
        )
        .await?
        .pending
        .context("claimed enrollment")?
        .phase,
        EnrollmentPhase::InFlight { .. }
    ));
    let error = second
        .auth
        .manage_mfa(
            &second.boot,
            &token,
            valid_confirmation(&challenge_id),
            "second".into(),
        )
        .await
        .err()
        .context("dropped confirmation cannot replay")?;
    ensure!(matches!(error, AuthError::InvalidChallenge));
    ensure!(provider.confirm_calls.load(Ordering::SeqCst) == 1);
    ensure!(matches!(
        second
            .auth
            .manage_mfa(
                &second.boot,
                &token,
                MfaRequest::Cancel { challenge_id },
                "second".into(),
            )
            .await?,
        MfaResponse::Canceled
    ));
    Ok(())
}

#[tokio::test]
async fn persisted_enrollment_phase_is_required_and_strict() -> anyhow::Result<()> {
    let provider = Arc::new(GatedFactor::new(Stage::None));
    let (state, token) = fixture(provider).await?;
    let _confirmation = request(&state, &token, Stage::None).await?;
    let record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let original = serde_json::to_value(&record)?;
    let key = local_account_key(&state.boot, "root").await?;
    let path = crate::paths::credential_path(key.authority_id(), key.instance_id())?;
    for (case, phase) in [
        None,
        Some(serde_json::json!({"status":"in_flight"})),
        Some(serde_json::json!({"status":"ready","claim_id":"extra"})),
        Some(serde_json::json!({"status":"in_flight","claim_id":"bad"})),
    ]
    .into_iter()
    .enumerate()
    {
        let mut encoded = original.clone();
        let pending = encoded["pending"]
            .as_object_mut()
            .context("pending object")?;
        if let Some(phase) = phase {
            pending.insert("phase".into(), phase);
        } else {
            pending.remove("phase");
        }
        state
            .boot
            .kernel()
            .state()
            .write_set(&path, xolotl_types::Value::string(encoded.to_string()))
            .await?;
        ensure!(
            matches!(
                read(
                    state.boot.kernel().state(),
                    "root",
                    crate::auth::test_credential_sealer().as_ref()
                )
                .await,
                Err(AuthError::State(_))
            ),
            "malformed phase case {case} was accepted"
        );
    }
    Ok(())
}

#[tokio::test]
async fn rejected_confirmation_releases_claim_but_uncertain_result_does_not() -> anyhow::Result<()>
{
    let provider = Arc::new(GatedFactor::new(Stage::None));
    let (first, token) = fixture(provider.clone()).await?;
    let second = another_host(&first, provider.clone())?;
    let MfaRequest::Continue { challenge_id, .. } = request(&first, &token, Stage::None).await?
    else {
        anyhow::bail!("confirmation request");
    };
    let error = first
        .auth
        .manage_mfa(
            &first.boot,
            &token,
            MfaRequest::Continue {
                challenge_id: challenge_id.clone(),
                input: MfaInteractionInput::Response {
                    response: JsonValue::String("wrong".into()),
                },
            },
            "first".into(),
        )
        .await
        .err()
        .context("invalid proof")?;
    ensure!(matches!(error, AuthError::InvalidCredentials));
    ensure!(matches!(
        read(
            second.boot.kernel().state(),
            "root",
            crate::auth::test_credential_sealer().as_ref()
        )
        .await?
        .pending
        .context("retryable enrollment")?
        .phase,
        EnrollmentPhase::Ready {}
    ));
    ensure!(matches!(
        second
            .auth
            .manage_mfa(
                &second.boot,
                &token,
                MfaRequest::Continue {
                    challenge_id,
                    input: MfaInteractionInput::Response {
                        response: JsonValue::String("valid".into())
                    },
                },
                "second".into(),
            )
            .await?,
        MfaResponse::Updated { .. }
    ));

    let provider = Arc::new(GatedFactor::with_confirm_error(
        MfaProviderError::Unavailable,
    ));
    let (first, token) = fixture(provider.clone()).await?;
    let second = another_host(&first, provider.clone())?;
    let confirm = request(&first, &token, Stage::None).await?;
    let MfaRequest::Continue { challenge_id, .. } = &confirm else {
        anyhow::bail!("confirmation request");
    };
    let challenge_id = challenge_id.clone();
    let error = first
        .auth
        .manage_mfa(&first.boot, &token, confirm, "first".into())
        .await
        .err()
        .context("uncertain provider result")?;
    ensure!(matches!(error, AuthError::State(_)));
    ensure!(matches!(
        read(
            second.boot.kernel().state(),
            "root",
            crate::auth::test_credential_sealer().as_ref()
        )
        .await?
        .pending
        .context("claimed enrollment")?
        .phase,
        EnrollmentPhase::InFlight { .. }
    ));
    let error = second
        .auth
        .manage_mfa(
            &second.boot,
            &token,
            valid_confirmation(&challenge_id),
            "second".into(),
        )
        .await
        .err()
        .context("uncertain confirmation cannot replay")?;
    ensure!(matches!(error, AuthError::InvalidChallenge));
    ensure!(provider.confirm_calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

async fn fixture(provider: Arc<GatedFactor>) -> anyhow::Result<(Arc<ConsoleState>, String)> {
    let (base, _, token, _) = crate::service::tests::fixture().await?;
    let mut config = crate::ConsoleConfig {
        session_store: Some(std::sync::Arc::new(
            crate::session_store::MemoryConsoleSessionStore::new(
                crate::session_store::ConsoleSessionPolicy::default(),
            ),
        )),
        ..Default::default()
    };
    config.auth.mfa.providers.push(provider);
    config.session_store = Some(base.auth.session_store.clone());
    Ok((ConsoleState::with_config(base.boot.clone(), config)?, token))
}

async fn request(state: &ConsoleState, token: &str, stage: Stage) -> anyhow::Result<MfaRequest> {
    let begin = MfaRequest::Begin {
        provider_id: "gated".into(),
        label: "Gated device".into(),
        replace_factor_id: None,
        input: None,
    };
    if matches!(stage, Stage::Begin) {
        return Ok(begin);
    }
    let MfaResponse::Enrollment { challenge_id, .. } = state
        .auth
        .manage_mfa(&state.boot, token, begin, "test".into())
        .await?
    else {
        anyhow::bail!("pending enrollment");
    };
    Ok(MfaRequest::Continue {
        challenge_id,
        input: MfaInteractionInput::Response {
            response: JsonValue::String("valid".into()),
        },
    })
}

async fn change_session(
    state: &ConsoleState,
    token: &str,
    change: impl FnOnce(&mut SessionRecord),
) -> anyhow::Result<()> {
    let sid = token.split_once('.').context("bearer")?.0;
    let path = session_path(sid)?;
    let mut session = read_session(state.auth.session_store.as_ref(), &path)
        .await?
        .context("session")?;
    change(&mut session);
    // Test-only clock/expiry fixture changes; normal session updates preserve
    // these immutable fields through their existing CAS contract.
    state.auth.session_store.delete(sid, None).await?;
    state
        .auth
        .session_store
        .create(crate::session_store::ConsoleSession::from_record(session))
        .await?;
    Ok(())
}

struct GatedCredentialRead {
    state: Backend,
    credential_path: Path,
    remaining: AtomicUsize,
    entered: Notify,
    release: Notify,
}

impl StateRead for GatedCredentialRead {
    type Read<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateObservation>> + Send + 'a>>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        Box::pin(async move {
            if path == &self.credential_path
                && self
                    .remaining
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                        value.checked_sub(1)
                    })
                    == Ok(1)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.state.read_tainted(path).await
        })
    }
}

impl StateBoundedRead for GatedCredentialRead {
    type BoundedRead<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateObservation>> + Send + 'a>>;

    fn read_tainted_bounded<'a>(
        &'a self,
        path: &'a Path,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedRead<'a> {
        Box::pin(async move {
            if path == &self.credential_path
                && self
                    .remaining
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
                        value.checked_sub(1)
                    })
                    == Ok(1)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            self.state.read_tainted_bounded(path, limit).await
        })
    }
}

#[tokio::test]
async fn final_credential_read_cannot_extend_the_recent_management_window() -> anyhow::Result<()> {
    let provider = Arc::new(GatedFactor::new(Stage::Begin));
    let (base, token) = fixture(provider.clone()).await?;
    let key = local_account_key(&base.boot, "root").await?;
    let gate = Arc::new(GatedCredentialRead {
        state: base.boot.kernel().state().clone(),
        credential_path: crate::paths::credential_path(key.authority_id(), key.instance_id())?,
        remaining: AtomicUsize::new(0),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(
            gate.state
                .clone()
                .with_read(gate.clone())
                .with_bounded_read(gate.clone()),
        )
        .build(),
    ));
    let mut config = crate::ConsoleConfig {
        session_store: Some(std::sync::Arc::new(
            crate::session_store::MemoryConsoleSessionStore::new(
                crate::session_store::ConsoleSessionPolicy::default(),
            ),
        )),
        ..Default::default()
    };
    config.auth.mfa.providers.push(provider.clone());
    config.session_store = Some(base.auth.session_store.clone());
    let state = ConsoleState::with_config(boot, config)?;
    let deadline = xolotl_kernel::host::system_now_millis() + 1_000;
    change_session(&state, &token, |session| {
        set_authentication_time(
            &mut session.authentication,
            deadline - state.auth.config.mfa.recent_auth_ttl_ms,
        );
    })
    .await?;
    let before = serde_json::to_value(
        &read(
            &gate.state,
            "root",
            crate::auth::test_credential_sealer().as_ref(),
        )
        .await?,
    )?;
    let operation = request(&state, &token, Stage::Begin).await?;
    let work = tokio::spawn({
        let state = state.clone();
        async move {
            state
                .auth
                .manage_mfa(&state.boot, &token, operation, "test".into())
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), provider.entered.notified()).await?;
    // Final revalidation first reads the epoch while authenticating the bearer,
    // then reads the directory used by recent_credential_management itself.
    gate.remaining.store(2, Ordering::SeqCst);
    provider.release.add_permits(1);
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await?;
    while xolotl_kernel::host::system_now_millis() <= deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    gate.release.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(5), work)
        .await??
        .err()
        .context("expired recent authentication must reject enrollment")?;
    ensure!(matches!(error, AuthError::ReauthenticationRequired));
    let retained = read(
        &gate.state,
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(serde_json::to_value(&retained)? == before && retained.pending.is_none());
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Invalidation {
    Logout,
    Expiry,
    RecentAuthentication,
    CredentialEpoch,
}

#[tokio::test]
async fn enrollment_provider_waits_cannot_outlive_the_authorizing_session() -> anyhow::Result<()> {
    for stage in [Stage::Begin, Stage::Confirm] {
        for invalidation in [
            Invalidation::Logout,
            Invalidation::Expiry,
            Invalidation::RecentAuthentication,
            Invalidation::CredentialEpoch,
        ] {
            let provider = Arc::new(GatedFactor::new(stage));
            let (state, token) = fixture(provider.clone()).await?;
            let before = serde_json::to_value(
                &read(
                    state.boot.kernel().state(),
                    "root",
                    crate::auth::test_credential_sealer().as_ref(),
                )
                .await?,
            )?;
            let request = request(&state, &token, stage).await?;
            let task = tokio::spawn({
                let state = state.clone();
                let token = token.clone();
                async move {
                    state
                        .auth
                        .manage_mfa(&state.boot, &token, request, "test".into())
                        .await
                }
            });
            tokio::time::timeout(Duration::from_secs(5), provider.entered.notified()).await?;
            match invalidation {
                Invalidation::Logout => {
                    state
                        .auth
                        .logout_sid_from_source(
                            &state.boot,
                            token.split_once('.').context("bearer")?.0,
                            Some("test"),
                        )
                        .await?;
                }
                Invalidation::Expiry => {
                    change_session(&state, &token, |session| {
                        session.expires_at = xolotl_kernel::host::system_now_millis() - 1;
                    })
                    .await?;
                }
                Invalidation::RecentAuthentication => {
                    change_session(&state, &token, |session| {
                        set_authentication_time(
                            &mut session.authentication,
                            xolotl_kernel::host::system_now_millis()
                                - state.auth.config.mfa.recent_auth_ttl_ms
                                - 1,
                        );
                    })
                    .await?;
                }
                Invalidation::CredentialEpoch => {
                    let mut record = read(
                        state.boot.kernel().state(),
                        "root",
                        crate::auth::test_credential_sealer().as_ref(),
                    )
                    .await?;
                    record.rotate_epoch()?;
                    write(
                        state.boot.kernel().state(),
                        "root",
                        &record,
                        crate::auth::test_credential_sealer().as_ref(),
                    )
                    .await?;
                }
            }
            let expected = serde_json::to_value(
                &read(
                    state.boot.kernel().state(),
                    "root",
                    crate::auth::test_credential_sealer().as_ref(),
                )
                .await?,
            )?;
            provider.release.add_permits(1);
            let error = tokio::time::timeout(Duration::from_secs(5), task)
                .await??
                .err()
                .context("management must reject after its authority expires")?;
            ensure!(
                match invalidation {
                    Invalidation::RecentAuthentication => {
                        matches!(error, AuthError::ReauthenticationRequired)
                    }
                    Invalidation::CredentialEpoch => matches!(error, AuthError::CredentialConflict),
                    _ => matches!(error, AuthError::InvalidSession),
                },
                "{stage:?} / {invalidation:?}: {error:?}"
            );
            let retained = read(
                state.boot.kernel().state(),
                "root",
                crate::auth::test_credential_sealer().as_ref(),
            )
            .await?;
            // Begin knows its provider result, so a failed final authority
            // check clears its own Starting claim. An epoch change already
            // removed that claim through the competing credential write.
            let expected = if matches!(stage, Stage::Begin)
                && !matches!(invalidation, Invalidation::CredentialEpoch)
            {
                before
            } else {
                expected
            };
            ensure!(
                serde_json::to_value(&retained)? == expected && retained.factors.is_empty(),
                "{stage:?} / {invalidation:?}: unexpected credential state"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn enrollment_expiring_during_provider_verification_remains_uncommitted() -> anyhow::Result<()>
{
    let provider = Arc::new(GatedFactor::new(Stage::Confirm));
    let (state, token) = fixture(provider.clone()).await?;
    let request = request(&state, &token, Stage::Confirm).await?;
    let mut record = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let expires_at = xolotl_kernel::host::system_now_millis() + 1000;
    record
        .pending
        .as_mut()
        .context("pending enrollment")?
        .expires_at = expires_at;
    write(
        state.boot.kernel().state(),
        "root",
        &record,
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    let task = tokio::spawn({
        let state = state.clone();
        let token = token.clone();
        async move {
            state
                .auth
                .manage_mfa(&state.boot, &token, request, "test".into())
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), provider.entered.notified()).await?;
    let expected = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?
    .persisted;
    while xolotl_kernel::host::system_now_millis() < expires_at {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    provider.release.add_permits(1);
    let error = tokio::time::timeout(Duration::from_secs(5), task)
        .await??
        .err()
        .context("expired enrollment must not activate its factor")?;
    ensure!(
        match &error {
            AuthError::InvalidChallenge => true,
            AuthError::State(message) => message == "MFA provider timed out",
            _ => false,
        },
        "provider timeout or final expiry must reject: {error:?}"
    );
    let retained = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(retained.persisted == expected && retained.factors.is_empty());
    ensure!(
        state
            .auth
            .authenticate_token(&state.boot, &token)
            .await?
            .authentication
            .mfa_level()
            == 1,
        "an expired confirmation must leave the original session usable"
    );
    Ok(())
}

#[tokio::test]
async fn enrollment_does_not_upgrade_and_management_preserves_real_verification_history()
-> anyhow::Result<()> {
    let (state, service, token, password) = crate::service::tests::fixture().await?;
    let original_issued_at = read_session(
        state.auth.session_store.as_ref(),
        &session_path(token.split_once('.').context("bearer")?.0)?,
    )
    .await?
    .context("original session")?
    .issued_at;
    let authenticated_at = xolotl_kernel::host::system_now_millis() - 60_000;
    change_session(&state, &token, |session| {
        set_authentication_time(&mut session.authentication, authenticated_at)
    })
    .await?;
    let primary = state
        .auth
        .authenticate_token(&state.boot, &token)
        .await?
        .authentication;
    let (challenge_id, setup) = begin(&service, &token).await?;
    let MfaResponse::Updated {
        session: confirmed, ..
    } = service
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
        anyhow::bail!("confirmed first factor");
    };
    ensure!(confirmed.authentication == primary && primary.mfa_level() == 1);
    let before = read(
        state.boot.kernel().state(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?
    .persisted;
    let error = service
        .mfa(
            &confirmed.token,
            MfaRequest::RegenerateRecoveryCodes {},
            "test".into(),
        )
        .await
        .err()
        .context("enrollment cannot authorize privileged factor management")?;
    ensure!(error.code == ConsoleErrorCode::StepUpRequired);
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
    let mut session = service
        .step_up(
            &confirmed.token,
            StepUpRequest {
                proof: Some(state.auth.next_test_totp(&state.boot, "root").await?),
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("real factor authentication"))?;
    let authentication = session.authentication.clone();
    ensure!(authentication.primary == primary.primary);
    ensure!(matches!(
        &authentication.secondary,
        Some(SecondaryAuthentication::Factor { factor_id, provider_id, .. })
            if factor_id == &only_totp_id(&state.boot, "root").await? && provider_id == "totp"
    ));
    ensure!(
        authentication
            .authenticated_at()
            .context("factor authentication time")?
            > authenticated_at
    );
    for operation in [
        MfaRequest::RegenerateRecoveryCodes {},
        MfaRequest::Remove {
            factor_id: only_totp_id(&state.boot, "root").await?,
        },
    ] {
        let current = read_session(
            state.auth.session_store.as_ref(),
            &session_path(&session.sid)?,
        )
        .await?
        .context("rotated session")?;
        ensure!(current.authentication == authentication);
        ensure!(current.issued_at >= original_issued_at);
        ensure!(
            current.issued_at
                >= current
                    .authentication
                    .authenticated_at()
                    .context("factor authentication time")?
        );
        let prior = session.token;
        let MfaResponse::Updated { session: next, .. } =
            service.mfa(&prior, operation, "test".into()).await?
        else {
            anyhow::bail!("management session rotation");
        };
        ensure!(
            state
                .auth
                .authenticate_token(&state.boot, &prior)
                .await
                .is_err()
        );
        session = next;
    }
    let removed = read_session(
        state.auth.session_store.as_ref(),
        &session_path(&session.sid)?,
    )
    .await?
    .context("session after last-factor removal")?;
    ensure!(removed.authentication == authentication && authentication.mfa_level() == 2);
    ensure!(
        removed.issued_at >= original_issued_at
            && removed.issued_at
                >= removed
                    .authentication
                    .authenticated_at()
                    .context("factor authentication time")?
    );
    let login = service
        .login(password_request(&password, None), "test".into())
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let fresh = read_session(
        state.auth.session_store.as_ref(),
        &session_path(&login.sid)?,
    )
    .await?
    .context("fresh primary authentication")?;
    ensure!(
        fresh
            .authentication
            .authenticated_at()
            .context("primary authentication time")?
            > authenticated_at
    );
    ensure!(fresh.authentication.mfa_level() == 1 && fresh.authentication.secondary.is_none());
    Ok(())
}
