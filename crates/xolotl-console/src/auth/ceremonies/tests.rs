//! Real providers exercise the public authentication contract and private failure boundaries.

use super::*;
use crate::auth::test_key::TestSigningKey;
use crate::mfa::{
    MfaAuthenticationDescriptor, MfaContext, MfaEnrollmentContext, MfaEnrollmentDescriptor,
    MfaEnrollmentStep, MfaFuture, MfaInteractionDescriptor, MfaProvider, MfaProviderDescriptor,
    MfaProviderError, MfaRequest, MfaResponse,
};
use crate::{ConsoleConfig, ConsoleState};
use anyhow::{Context, ensure};
use serde_json::json;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Notify, Semaphore};
use xolotl_state::{
    StateBoundedWrite, StateCommit, StateMutation, StateResult, StateWrite, TaintedValue,
};

mod usage;

const LEDGER_PATH: &str = "state://vault/console/challenges";

#[derive(Clone, Copy)]
enum Behavior {
    Flow,
    TwoChallenges,
    Immediate,
    OversizedChallenge,
    OversizedPrivateState,
    InvalidResponseSchema,
    OversizedResponseSchema,
    OversizedStatus,
    OversizedVerifier,
    PendingForever,
}

struct Observation {
    ceremony: String,
    round: u16,
    expires_at: i64,
    purpose: MfaPurpose,
    account: String,
    factor: String,
}

struct InteractiveFactor {
    behavior: Behavior,
    calls: AtomicUsize,
    gate_call: AtomicUsize,
    active: AtomicUsize,
    entered: Notify,
    release: Semaphore,
    observations: Mutex<Vec<Observation>>,
}

struct ActiveCall<'a>(&'a AtomicUsize);

impl Drop for ActiveCall<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl InteractiveFactor {
    fn new(behavior: Behavior) -> Arc<Self> {
        Arc::new(Self {
            behavior,
            calls: AtomicUsize::new(0),
            gate_call: AtomicUsize::new(0),
            active: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Semaphore::new(0),
            observations: Mutex::new(Vec::new()),
        })
    }

    async fn invocation(
        &self,
        context: &MfaInteractionContext<'_>,
    ) -> Result<(), MfaProviderError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        self.active.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveCall(&self.active);
        self.observations
            .lock()
            .map_err(|_error| MfaProviderError::Unavailable)?
            .push(Observation {
                ceremony: context.ceremony_id.into(),
                round: context.round,
                expires_at: context.expires_at,
                purpose: context.factor.purpose,
                account: context.factor.account_id.into(),
                factor: context.factor.factor_id.into(),
            });
        if self.gate_call.load(Ordering::SeqCst) == call {
            self.entered.notify_one();
            self.release
                .acquire()
                .await
                .map_err(|_error| MfaProviderError::Unavailable)?
                .forget();
        }
        Ok(())
    }

    async fn wait_for_call(&self) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(5), self.entered.notified()).await?;
        Ok(())
    }

    fn verified(verifier: &JsonValue) -> Result<MfaInteractionStep, MfaProviderError> {
        let counter = verifier["counter"]
            .as_u64()
            .ok_or(MfaProviderError::InvalidState)?;
        Ok(MfaInteractionStep::Verified {
            next_verifier: json!({"counter":counter + 1}),
        })
    }
}

impl MfaProvider for InteractiveFactor {
    fn descriptor(&self) -> MfaProviderDescriptor {
        MfaProviderDescriptor {
            provider_id: "interactive_test".into(),
            label: "Interactive test factor".into(),
            enrollment: Some(MfaEnrollmentDescriptor {
                begin_schema: None,
                setup_schema: serde_json::json!(true),
                pending_schema: None,
            }),
            authentication: MfaAuthenticationDescriptor {
                proof_schema: Some(json!({"type":"string"})),
                interaction: Some(MfaInteractionDescriptor {
                    challenge_schema: json!({"type":"object"}),
                }),
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
                setup: json!({"confirmation":"enroll"}),
                response_schema: json!({"type":"string"}),
                private_state: json!({"counter":0}),
            })
        })
    }

    fn continue_enrollment<'a>(
        &'a self,
        _context: MfaEnrollmentContext<'a>,
        private_state: &'a JsonValue,
        input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        Box::pin(async move {
            let MfaInteractionInput::Response { response } = input else {
                return Err(MfaProviderError::InvalidInput);
            };
            if response != "enroll" || private_state != &json!({"counter":0}) {
                return Err(MfaProviderError::InvalidProof);
            }
            Ok(MfaEnrollmentStep::Verified {
                verifier: json!({"counter":1}),
            })
        })
    }

    fn begin_authentication<'a>(
        &'a self,
        context: MfaInteractionContext<'a>,
        verifier: &'a JsonValue,
    ) -> MfaFuture<'a, MfaInteractionStep> {
        Box::pin(async move {
            self.invocation(&context).await?;
            let oversized = || json!("secret".repeat(20_000));
            match self.behavior {
                Behavior::Immediate => Self::verified(verifier),
                Behavior::OversizedVerifier => Ok(MfaInteractionStep::Verified {
                    next_verifier: oversized(),
                }),
                Behavior::OversizedStatus => Ok(MfaInteractionStep::Pending {
                    private_state: json!(null),
                    status: oversized(),
                    retry_after_ms: 100,
                }),
                Behavior::PendingForever => Ok(MfaInteractionStep::Pending {
                    private_state: json!({"ceremony":context.ceremony_id}),
                    status: json!("waiting"),
                    retry_after_ms: i64::MAX,
                }),
                behavior => Ok(MfaInteractionStep::Challenge {
                    response_schema: match behavior {
                        Behavior::TwoChallenges => json!({"type":"string","const":"accepted"}),
                        Behavior::InvalidResponseSchema => JsonValue::Null,
                        Behavior::OversizedResponseSchema => {
                            json!({"description":"x".repeat(20_000)})
                        }
                        _ => json!({"type":"string"}),
                    },
                    private_state: if matches!(behavior, Behavior::OversizedPrivateState) {
                        oversized()
                    } else {
                        json!({"ceremony":context.ceremony_id,"phase":"challenge"})
                    },
                    challenge: if matches!(behavior, Behavior::OversizedChallenge) {
                        oversized()
                    } else {
                        json!({"nonce":context.ceremony_id})
                    },
                }),
            }
        })
    }

    fn verify_proof<'a>(
        &'a self,
        _context: MfaContext<'a>,
        verifier: &'a JsonValue,
        response: &'a JsonValue,
    ) -> MfaFuture<'a, JsonValue> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if response != "accepted" {
                return Err(MfaProviderError::InvalidProof);
            }
            let counter = verifier["counter"]
                .as_u64()
                .ok_or(MfaProviderError::InvalidState)?;
            Ok(json!({"counter":counter + 1}))
        })
    }

    fn continue_authentication<'a>(
        &'a self,
        context: MfaInteractionContext<'a>,
        verifier: &'a JsonValue,
        private_state: &'a JsonValue,
        input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaInteractionStep> {
        Box::pin(async move {
            self.invocation(&context).await?;
            if private_state["ceremony"] != context.ceremony_id {
                return Err(MfaProviderError::InvalidState);
            }
            match (private_state["phase"].as_str(), input) {
                (Some("challenge"), MfaInteractionInput::Response { response })
                    if matches!(self.behavior, Behavior::TwoChallenges)
                        && response == "accepted" =>
                {
                    Ok(MfaInteractionStep::Challenge {
                        private_state: json!({"ceremony":context.ceremony_id,"phase":"second_challenge"}),
                        challenge: json!({"approval":"required"}),
                        response_schema: json!({"type":"object","required":["approval"],"properties":{"approval":{"const":true}}}),
                    })
                }
                (Some("challenge"), MfaInteractionInput::Response { response })
                    if response == "accepted" =>
                {
                    Ok(MfaInteractionStep::Pending {
                        private_state: json!({"ceremony":context.ceremony_id,"phase":"pending"}),
                        status: json!({"approval":"waiting"}),
                        retry_after_ms: 1_000,
                    })
                }
                (Some("second_challenge"), MfaInteractionInput::Response { response })
                    if response == &json!({"approval":true}) =>
                {
                    Self::verified(verifier)
                }
                (Some("pending"), MfaInteractionInput::Poll {}) => Self::verified(verifier),
                _ => Err(MfaProviderError::InvalidProof),
            }
        })
    }
}

struct Fixture {
    state: Arc<ConsoleState>,
    config: ConsoleConfig,
    provider: Arc<InteractiveFactor>,
    password: String,
    token: String,
    factor_id: String,
    signing_key: TestSigningKey,
    recovery_code: String,
}

impl Fixture {
    async fn new(
        behavior: Behavior,
        configure: impl FnOnce(&mut ConsoleConfig),
    ) -> anyhow::Result<Self> {
        let (base, _, token, password) = crate::service::tests::fixture().await?;
        let provider = InteractiveFactor::new(behavior);
        let mut config = ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            ..Default::default()
        };
        config.session_store = Some(std::sync::Arc::new(
            crate::session_store::MemoryConsoleSessionStore::new(
                crate::session_store::ConsoleSessionPolicy::new(32, 10_000)?,
            ),
        ));
        config.auth.mfa.install_totp = false;
        config.auth.mfa.providers = vec![provider.clone()];
        config.auth.mfa.min_poll_interval_ms = 100;
        configure(&mut config);
        config.session_store = Some(base.auth.session_store.clone());
        let state = ConsoleState::with_config(base.boot.clone(), config.clone())?;
        let signing_key = TestSigningKey::generate();
        let updated = state
            .auth
            .manage_credentials(
                &state.boot,
                &token,
                crate::credentials::CredentialRequest {
                    username: None,
                    operation: crate::credentials::CredentialOperation::AddPublicKey {
                        key: signing_key.descriptor(),
                    },
                },
                "test".into(),
            )
            .await?;
        let crate::credentials::CredentialResponse::Updated {
            session: Some(session),
            ..
        } = updated
        else {
            anyhow::bail!("public-key installation session");
        };
        let MfaResponse::Enrollment {
            challenge_id,
            factor_id,
            ..
        } = state
            .auth
            .manage_mfa(
                &state.boot,
                &session.token,
                MfaRequest::Begin {
                    provider_id: "interactive_test".into(),
                    label: "Test device".into(),
                    replace_factor_id: None,
                    input: None,
                },
                "test".into(),
            )
            .await?
        else {
            anyhow::bail!("enrollment");
        };
        let MfaResponse::Updated {
            session,
            recovery_codes,
        } = state
            .auth
            .manage_mfa(
                &state.boot,
                &session.token,
                MfaRequest::Continue {
                    challenge_id,
                    input: MfaInteractionInput::Response {
                        response: json!("enroll"),
                    },
                },
                "test".into(),
            )
            .await?
        else {
            anyhow::bail!("enrollment confirmation");
        };
        let mut recovery_codes = recovery_codes.context("first factor recovery codes")?;
        let code = recovery_codes.pop().context("recovery proof")?;
        let session = authenticated(
            state
                .auth
                .step_up(
                    &state.boot,
                    &session.token,
                    StepUpRequest {
                        proof: Some(MfaProof::RecoveryCode { code }),
                    },
                    "test".into(),
                )
                .await?,
        )?;
        Ok(Self {
            state,
            config,
            provider,
            password,
            token: session.token,
            factor_id,
            signing_key,
            recovery_code: recovery_codes.pop().context("unused recovery proof")?,
        })
    }

    fn backend(&self) -> &Backend {
        self.state.boot.kernel().state()
    }

    async fn password_login(&self) -> anyhow::Result<AuthenticationContinuation> {
        continuation(
            self.state
                .auth
                .login(
                    &self.state.boot,
                    LoginRequest {
                        username: "root".into(),
                        password: self.password.clone(),
                        second_factor: None,
                    },
                    "primary-peer".into(),
                )
                .await?,
        )
    }

    async fn step_up(&self) -> anyhow::Result<AuthenticationContinuation> {
        continuation(
            self.state
                .auth
                .step_up(
                    &self.state.boot,
                    &self.token,
                    StepUpRequest { proof: None },
                    "primary-peer".into(),
                )
                .await?,
        )
    }

    async fn continue_with(
        &self,
        pending: &AuthenticationContinuation,
        input: AuthenticationInput,
        bearer: Option<&str>,
    ) -> Result<AuthenticationResponse, AuthError> {
        self.state
            .auth
            .continue_authentication(
                &self.state.boot,
                bearer,
                ContinueAuthenticationRequest {
                    continuation: pending.continuation.clone(),
                    input,
                },
                "changed-peer".into(),
            )
            .await
    }

    async fn select(
        &self,
        pending: &AuthenticationContinuation,
        bearer: Option<&str>,
    ) -> Result<AuthenticationResponse, AuthError> {
        self.continue_with(
            pending,
            AuthenticationInput::SelectFactor {
                factor_id: self.factor_id.clone(),
            },
            bearer,
        )
        .await
    }
}

fn continuation(response: AuthenticationResponse) -> anyhow::Result<AuthenticationContinuation> {
    match response {
        AuthenticationResponse::Continue(pending) => Ok(pending),
        _ => anyhow::bail!("continuation expected"),
    }
}

fn authenticated(response: AuthenticationResponse) -> anyhow::Result<LoginResponse> {
    response
        .into_session()
        .map_err(|_error| anyhow::anyhow!("authenticated session expected"))
}

async fn credential_snapshot(state: &Backend) -> anyhow::Result<JsonValue> {
    Ok(serde_json::to_value(
        credentials::read(
            state,
            "root",
            crate::auth::test_credential_sealer().as_ref(),
        )
        .await?,
    )?)
}

async fn root_credential_path(state: &Backend) -> anyhow::Result<Path> {
    let user = read_user(state, "root").await?.context("root account")?;
    let key = user.account_key();
    Ok(crate::paths::credential_path(
        key.authority_id(),
        key.instance_id(),
    )?)
}

// Move only test clock fixtures; production APIs never renew a deadline or alter a waiting round.
async fn change_ledger(
    state: &Backend,
    token: &str,
    change: impl FnOnce(&mut JsonValue),
) -> anyhow::Result<()> {
    let path = Path::parse(LEDGER_PATH)?;
    let value = state.read(&path).await?.context("ledger")?;
    let mut ledger: JsonValue = serde_json::from_str(value.as_str().context("encoded ledger")?)?;
    let id = token.split_once('.').context("continuation")?.0;
    let entry = ledger.get_mut(id).context("ceremony")?;
    change(entry);
    state
        .write_set(&path, Value::string(serde_json::to_string(&ledger)?))
        .await?;
    Ok(())
}

async fn allow_poll(fixture: &Fixture, pending: &AuthenticationContinuation) -> anyhow::Result<()> {
    change_ledger(fixture.backend(), &pending.continuation, |entry| {
        entry["payload"]["state"]["waiting"]["not_before"] =
            json!(xolotl_kernel::host::system_now_millis() - 1);
    })
    .await
}

#[tokio::test]
async fn password_and_public_key_primary_proofs_continue_through_real_interactive_rounds()
-> anyhow::Result<()> {
    for public_key in [false, true] {
        let fixture = Fixture::new(Behavior::Flow, |_| {}).await?;
        let pending = if public_key {
            let challenge = fixture
                .state
                .auth
                .begin_key_login(
                    &fixture.state.boot,
                    KeyChallengeRequest {
                        username: "root".into(),
                        origin: "https://console.test".into(),
                    },
                    "primary-peer".into(),
                )
                .await?;
            let request = || KeyLoginRequest {
                username: "root".into(),
                challenge_id: challenge.challenge_id.clone(),
                signature: URL_SAFE_NO_PAD
                    .encode(fixture.signing_key.sign(challenge.transcript.as_bytes())),
                origin: challenge.origin.clone(),
                key: fixture.signing_key.descriptor(),
                second_factor: None,
            };
            let pending = continuation(
                fixture
                    .state
                    .auth
                    .finish_key_login(&fixture.state.boot, request(), "primary-peer".into())
                    .await?,
            )?;
            ensure!(
                matches!(
                    fixture
                        .state
                        .auth
                        .finish_key_login(&fixture.state.boot, request(), "primary-peer".into())
                        .await,
                    Err(AuthError::InvalidChallenge)
                ),
                "primary signature challenge is consumed exactly once"
            );
            pending
        } else {
            fixture.password_login().await?
        };
        ensure!(matches!(
            pending.step,
            AuthenticationStep::ChooseFactor { .. }
        ));
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 0);
        let stored = challenges::inspect::<Ceremony>(
            fixture.state.boot.kernel().host_runtime(),
            fixture.backend(),
            &pending.continuation,
        )
        .await?;
        let primary = stored.payload.owner.authentication.primary.clone();
        ensure!(
            matches!(
                stored.payload.owner.authentication.primary,
                PrimaryAuthentication::PublicKey { .. }
            ) == public_key
        );
        let serialized = serde_json::to_string(&stored.payload)?;
        ensure!(!serialized.contains(&fixture.password));
        ensure!(
            fixture
                .state
                .auth
                .authenticate_token(&fixture.state.boot, &pending.continuation)
                .await
                .is_err()
        );
        let before = credential_snapshot(fixture.backend()).await?;
        let challenge = continuation(fixture.select(&pending, None).await?)?;
        ensure!(matches!(
            challenge.step,
            AuthenticationStep::Challenge { .. }
        ));
        ensure!(
            challenge.expires_at == pending.expires_at
                && challenge.continuation != pending.continuation
        );
        ensure!(credential_snapshot(fixture.backend()).await? == before);
        let waiting = continuation(
            fixture
                .continue_with(
                    &challenge,
                    AuthenticationInput::Response {
                        response: json!("accepted"),
                    },
                    None,
                )
                .await?,
        )?;
        ensure!(matches!(waiting.step, AuthenticationStep::Pending { .. }));
        ensure!(waiting.expires_at == pending.expires_at);
        let calls = fixture.provider.calls.load(Ordering::SeqCst);
        let early = continuation(
            fixture
                .continue_with(&waiting, AuthenticationInput::Poll {}, None)
                .await?,
        )?;
        ensure!(
            early.continuation == waiting.continuation && early.expires_at == waiting.expires_at
        );
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == calls);
        ensure!(credential_snapshot(fixture.backend()).await? == before);
        allow_poll(&fixture, &waiting).await?;
        let session = authenticated(
            fixture
                .continue_with(&waiting, AuthenticationInput::Poll {}, None)
                .await?,
        )?;
        ensure!(session.authentication.mfa_level() == 2);
        ensure!(session.authentication.primary == primary);
        ensure!(matches!(
            &session.authentication.secondary,
            Some(SecondaryAuthentication::Factor { factor_id, provider_id, .. })
                if factor_id == &fixture.factor_id && provider_id == "interactive_test"
        ));
        let record = credentials::read(
            fixture.backend(),
            "root",
            crate::auth::test_credential_sealer().as_ref(),
        )
        .await?;
        ensure!(record.factors[&fixture.factor_id].verifier["counter"] == 2);
        ensure!(record.factors[&fixture.factor_id].last_used_at.is_some());
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 3);
        ensure!(
            fixture
                .continue_with(&waiting, AuthenticationInput::Poll {}, None)
                .await
                .is_err()
        );
        let observations = fixture
            .provider
            .observations
            .lock()
            .map_err(|_error| anyhow::anyhow!("provider observations"))?;
        for (index, observed) in observations.iter().enumerate() {
            ensure!(observed.round == u16::try_from(index + 1)?);
            ensure!(observed.ceremony == pending.continuation.split_once('.').context("token")?.0);
            ensure!(
                observed.expires_at == pending.expires_at && observed.purpose == MfaPurpose::Login
            );
            ensure!(observed.factor == fixture.factor_id && observed.account == record.account_id);
        }
    }
    Ok(())
}

#[tokio::test]
async fn authentication_exposes_each_rounds_schema_across_host_recreation() -> anyhow::Result<()> {
    let fixture = Fixture::new(Behavior::TwoChallenges, |_| {}).await?;
    let selection = fixture.password_login().await?;
    let first = continuation(fixture.select(&selection, None).await?)?;
    let AuthenticationStep::Challenge {
        factor_id,
        response_schema: first_schema,
        ..
    } = &first.step
    else {
        anyhow::bail!("first authentication challenge");
    };
    ensure!(factor_id == &fixture.factor_id);
    ensure!(*first_schema == json!({"type":"string","const":"accepted"}));
    ensure!(serde_json::to_value(&first.step)?["response_schema"] == *first_schema);

    let restored = ConsoleState::with_config(fixture.state.boot.clone(), fixture.config.clone())?;
    let second = continuation(
        restored
            .auth
            .continue_authentication(
                &restored.boot,
                None,
                ContinueAuthenticationRequest {
                    continuation: first.continuation.clone(),
                    input: AuthenticationInput::Response {
                        response: json!("accepted"),
                    },
                },
                "restored-host".into(),
            )
            .await?,
    )?;
    let AuthenticationStep::Challenge {
        response_schema: second_schema,
        challenge,
        ..
    } = &second.step
    else {
        anyhow::bail!("second authentication challenge");
    };
    ensure!(challenge["approval"] == "required");
    ensure!(
        *second_schema
            == json!({"type":"object","required":["approval"],"properties":{"approval":{"const":true}}})
    );
    ensure!(second_schema != first_schema);
    ensure!(serde_json::to_value(&second.step)?["response_schema"] == *second_schema);
    ensure!(second.expires_at == first.expires_at);

    let session = authenticated(
        fixture
            .continue_with(
                &second,
                AuthenticationInput::Response {
                    response: json!({"approval":true}),
                },
                None,
            )
            .await?,
    )?;
    ensure!(session.authentication.mfa_level() == 2);
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 3);
    Ok(())
}

#[tokio::test]
async fn two_auth_hosts_share_the_unique_provider_call() -> anyhow::Result<()> {
    let fixture = Fixture::new(Behavior::Immediate, |_| {}).await?;
    fixture.provider.gate_call.store(1, Ordering::SeqCst);
    let pending = fixture.password_login().await?;
    let second = ConsoleState::with_config(fixture.state.boot.clone(), fixture.config.clone())?;
    let first = tokio::spawn({
        let state = fixture.state.clone();
        let token = pending.continuation.clone();
        let factor_id = fixture.factor_id.clone();
        async move {
            state
                .auth
                .continue_authentication(
                    &state.boot,
                    None,
                    ContinueAuthenticationRequest {
                        continuation: token,
                        input: AuthenticationInput::SelectFactor { factor_id },
                    },
                    "first-host".into(),
                )
                .await
        }
    });
    fixture.provider.wait_for_call().await?;
    ensure!(
        second
            .auth
            .continue_authentication(
                &second.boot,
                None,
                ContinueAuthenticationRequest {
                    continuation: pending.continuation.clone(),
                    input: AuthenticationInput::SelectFactor {
                        factor_id: fixture.factor_id.clone()
                    },
                },
                "second-host".into()
            )
            .await
            .is_err()
    );
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
    fixture.provider.release.add_permits(1);
    ensure!(authenticated(first.await??)?.authentication.mfa_level() == 2);
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[derive(Clone, Copy)]
enum Invalidation {
    Sid,
    Epoch,
    Verifier,
    Authentication,
}

#[tokio::test]
async fn provider_results_cannot_survive_session_evidence_epoch_or_verifier_changes()
-> anyhow::Result<()> {
    for invalidation in [
        Invalidation::Sid,
        Invalidation::Epoch,
        Invalidation::Verifier,
        Invalidation::Authentication,
    ] {
        let fixture = Fixture::new(Behavior::Immediate, |_| {}).await?;
        fixture.provider.gate_call.store(1, Ordering::SeqCst);
        let pending = fixture.step_up().await?;
        let work = tokio::spawn({
            let state = fixture.state.clone();
            let bearer = fixture.token.clone();
            let token = pending.continuation.clone();
            let factor_id = fixture.factor_id.clone();
            async move {
                state
                    .auth
                    .continue_authentication(
                        &state.boot,
                        Some(&bearer),
                        ContinueAuthenticationRequest {
                            continuation: token,
                            input: AuthenticationInput::SelectFactor { factor_id },
                        },
                        "worker".into(),
                    )
                    .await
            }
        });
        fixture.provider.wait_for_call().await?;
        match invalidation {
            Invalidation::Sid => {
                revoke_session(
                    fixture.state.auth.session_store.as_ref(),
                    fixture.token.split_once('.').context("bearer")?.0,
                )
                .await?
            }
            Invalidation::Authentication => {
                let sid = fixture.token.split_once('.').context("bearer")?.0;
                let path = session_path(sid)?;
                let mut session = read_session(fixture.state.auth.session_store.as_ref(), &path)
                    .await?
                    .context("original step-up session")?;
                let before = session.authentication.clone();
                session.authentication.secondary = Some(SecondaryAuthentication::Factor {
                    factor_id: fixture.factor_id.clone(),
                    provider_id: "interactive_test".into(),
                    verified_at: before.authenticated_at().context("local authentication")?,
                });
                ensure!(session.authentication != before);
                ensure!(session.authentication.mfa_level() == before.mfa_level());
                ensure!(session.authentication.authenticated_at() == before.authenticated_at());
                fixture.state.auth.session_store.delete(sid, None).await?;
                fixture
                    .state
                    .auth
                    .session_store
                    .create(crate::session_store::ConsoleSession::from_record(session))
                    .await?;
            }
            Invalidation::Epoch | Invalidation::Verifier => {
                let mut record = credentials::read(
                    fixture.backend(),
                    "root",
                    crate::auth::test_credential_sealer().as_ref(),
                )
                .await?;
                match invalidation {
                    Invalidation::Epoch => record.rotate_epoch()?,
                    _ => {
                        record
                            .factors
                            .get_mut(&fixture.factor_id)
                            .context("factor")?
                            .verifier = json!({"counter":99})
                    }
                }
                credentials::write(
                    fixture.backend(),
                    "root",
                    &record,
                    crate::auth::test_credential_sealer().as_ref(),
                )
                .await?;
            }
        }
        let expected = credential_snapshot(fixture.backend()).await?;
        fixture.provider.release.add_permits(1);
        ensure!(work.await?.is_err());
        ensure!(credential_snapshot(fixture.backend()).await? == expected);
        ensure!(
            challenges::inspect_owner(
                fixture.state.boot.kernel().host_runtime(),
                fixture.backend(),
                &pending.continuation
            )
            .await
            .is_err()
        );
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum AccountInvalidation {
    Instance,
    Version,
    Disabled,
}

#[tokio::test]
async fn login_provider_results_cannot_survive_account_instance_version_or_status_changes()
-> anyhow::Result<()> {
    for invalidation in [
        AccountInvalidation::Instance,
        AccountInvalidation::Version,
        AccountInvalidation::Disabled,
    ] {
        let fixture = Fixture::new(Behavior::Immediate, |_| {}).await?;
        fixture.provider.gate_call.store(1, Ordering::SeqCst);
        let pending = fixture.password_login().await?;
        let credential_path = root_credential_path(fixture.backend()).await?;
        let before = fixture.backend().read(&credential_path).await?;
        let work = tokio::spawn({
            let state = fixture.state.clone();
            let token = pending.continuation.clone();
            let factor_id = fixture.factor_id.clone();
            async move {
                state
                    .auth
                    .continue_authentication(
                        &state.boot,
                        None,
                        ContinueAuthenticationRequest {
                            continuation: token,
                            input: AuthenticationInput::SelectFactor { factor_id },
                        },
                        "worker".into(),
                    )
                    .await
            }
        });
        fixture.provider.wait_for_call().await?;
        let user_path = user_path("root")?;
        let current = fixture
            .backend()
            .read(&user_path)
            .await?
            .context("root account")?;
        let mut changed = current.clone().into_map().context("root account map")?;
        // Change one binding at a time, keeping all others fixed. In particular,
        // disabling the account must fail even without a concurrent version bump.
        match invalidation {
            AccountInvalidation::Instance => {
                let replacement = random_token(18)?;
                changed.insert("account_id".into(), Value::string(replacement.clone()))?;
                changed.insert(
                    "identity_path".into(),
                    Value::string(local_identity_path(&replacement)?),
                )?;
            }
            AccountInvalidation::Version => {
                let version = changed
                    .get("version")
                    .and_then(Value::as_int)
                    .context("account version")?;
                changed.insert("version".into(), Value::integer(version + 1))?;
            }
            AccountInvalidation::Disabled => {
                changed.insert("status".into(), Value::string("disabled".into()))?;
            }
        }
        fixture
            .backend()
            .write_cas(&user_path, Some(current), Value::from(changed))
            .await?;
        fixture.provider.release.add_permits(1);
        let result = tokio::time::timeout(Duration::from_secs(5), work).await??;
        match invalidation {
            AccountInvalidation::Instance | AccountInvalidation::Disabled => {
                ensure!(matches!(result, Err(AuthError::AccountUnavailable)))
            }
            AccountInvalidation::Version => {
                ensure!(matches!(result, Err(AuthError::InvalidChallenge)))
            }
        }
        ensure!(fixture.backend().read(&credential_path).await? == before);
        ensure!(
            challenges::inspect_owner(
                fixture.state.boot.kernel().host_runtime(),
                fixture.backend(),
                &pending.continuation
            )
            .await
            .is_err()
        );
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
        ensure!(fixture.provider.active.load(Ordering::SeqCst) == 0);
    }
    Ok(())
}

#[tokio::test]
async fn in_flight_cancel_keeps_capacity_and_discards_the_provider_result() -> anyhow::Result<()> {
    let fixture = Fixture::new(Behavior::Immediate, |config| {
        config.auth.challenges.max_pending_global = 1
    })
    .await?;
    fixture.provider.gate_call.store(1, Ordering::SeqCst);
    let pending = fixture.password_login().await?;
    let before = credential_snapshot(fixture.backend()).await?;
    let work = tokio::spawn({
        let state = fixture.state.clone();
        let token = pending.continuation.clone();
        let factor_id = fixture.factor_id.clone();
        async move {
            state
                .auth
                .continue_authentication(
                    &state.boot,
                    None,
                    ContinueAuthenticationRequest {
                        continuation: token,
                        input: AuthenticationInput::SelectFactor { factor_id },
                    },
                    "worker".into(),
                )
                .await
        }
    });
    fixture.provider.wait_for_call().await?;
    fixture
        .state
        .auth
        .cancel_authentication(
            &fixture.state.boot,
            None,
            CancelAuthenticationRequest {
                continuation: pending.continuation.clone(),
            },
            "cancel-peer".into(),
        )
        .await?;
    ensure!(fixture.provider.active.load(Ordering::SeqCst) == 1);
    ensure!(fixture.password_login().await.is_err());
    fixture.provider.release.add_permits(1);
    ensure!(work.await?.is_err());
    ensure!(fixture.provider.active.load(Ordering::SeqCst) == 0);
    ensure!(credential_snapshot(fixture.backend()).await? == before);
    fixture.password_login().await?;
    Ok(())
}

#[tokio::test]
async fn wrong_step_up_bearer_does_not_consume_the_continuation() -> anyhow::Result<()> {
    let fixture = Fixture::new(Behavior::Immediate, |_| {}).await?;
    let original = fixture
        .state
        .auth
        .authenticate_token(&fixture.state.boot, &fixture.token)
        .await?
        .authentication;
    let pending = fixture.step_up().await?;
    ensure!(fixture.select(&pending, None).await.is_err());
    ensure!(
        fixture
            .select(&pending, Some("invalid.bearer"))
            .await
            .is_err()
    );
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 0);
    let session = authenticated(fixture.select(&pending, Some(&fixture.token)).await?)?;
    ensure!(session.authentication.mfa_level() == 2);
    ensure!(session.authentication.primary == original.primary);
    ensure!(matches!(
        original.secondary,
        Some(SecondaryAuthentication::RecoveryCode { .. })
    ));
    ensure!(matches!(
        session.authentication.secondary,
        Some(SecondaryAuthentication::Factor { .. })
    ));
    ensure!(
        fixture
            .state
            .auth
            .authenticate_token(&fixture.state.boot, &fixture.token)
            .await?
            .authentication
            == original
    );
    Ok(())
}

#[tokio::test]
async fn host_rejects_oversized_outputs_unfinishable_waits_and_exhausted_steps()
-> anyhow::Result<()> {
    for behavior in [
        Behavior::OversizedChallenge,
        Behavior::OversizedPrivateState,
        Behavior::InvalidResponseSchema,
        Behavior::OversizedResponseSchema,
        Behavior::OversizedStatus,
        Behavior::OversizedVerifier,
        Behavior::PendingForever,
        Behavior::Flow,
    ] {
        let fixture = Fixture::new(behavior, |config| {
            config.auth.mfa.max_authentication_steps = 1
        })
        .await?;
        let pending = fixture.password_login().await?;
        let before = credential_snapshot(fixture.backend()).await?;
        ensure!(fixture.select(&pending, None).await.is_err());
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
        ensure!(credential_snapshot(fixture.backend()).await? == before);
        ensure!(
            challenges::inspect_owner(
                fixture.state.boot.kernel().host_runtime(),
                fixture.backend(),
                &pending.continuation
            )
            .await
            .is_err()
        );
        ensure!(fixture.select(&pending, None).await.is_err());
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
    }
    Ok(())
}

#[tokio::test]
async fn invalid_round_response_schemas_fail_before_challenge_publication() -> anyhow::Result<()> {
    for behavior in [
        Behavior::InvalidResponseSchema,
        Behavior::OversizedResponseSchema,
    ] {
        let fixture = Fixture::new(behavior, |_| {}).await?;
        let pending = fixture.password_login().await?;
        let before = credential_snapshot(fixture.backend()).await?;
        ensure!(fixture.select(&pending, None).await.is_err());
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
        ensure!(credential_snapshot(fixture.backend()).await? == before);
        ensure!(
            challenges::inspect_owner(
                fixture.state.boot.kernel().host_runtime(),
                fixture.backend(),
                &pending.continuation
            )
            .await
            .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn wrong_input_and_oversized_responses_leave_the_current_round_usable() -> anyhow::Result<()>
{
    let fixture = Fixture::new(Behavior::Flow, |_| {}).await?;
    let pending = fixture.password_login().await?;
    let challenge = continuation(fixture.select(&pending, None).await?)?;
    ensure!(
        fixture
            .continue_with(&challenge, AuthenticationInput::Poll {}, None)
            .await
            .is_err()
    );
    *fixture.state.auth.rate() = RateState::default();
    clear_lockout(fixture.backend(), "root").await?;
    ensure!(
        fixture
            .continue_with(
                &challenge,
                AuthenticationInput::Response {
                    response: json!("x".repeat(32 * 1024))
                },
                None
            )
            .await
            .is_err()
    );
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
    *fixture.state.auth.rate() = RateState::default();
    clear_lockout(fixture.backend(), "root").await?;
    let waiting = continuation(
        fixture
            .continue_with(
                &challenge,
                AuthenticationInput::Response {
                    response: json!("accepted"),
                },
                None,
            )
            .await?,
    )?;
    ensure!(matches!(waiting.step, AuthenticationStep::Pending { .. }));
    Ok(())
}

#[tokio::test]
async fn provider_timeout_uses_the_original_deadline_and_retires_the_round() -> anyhow::Result<()> {
    let fixture = Fixture::new(Behavior::Immediate, |_| {}).await?;
    fixture.provider.gate_call.store(1, Ordering::SeqCst);
    let pending = fixture.password_login().await?;
    let before = credential_snapshot(fixture.backend()).await?;
    change_ledger(fixture.backend(), &pending.continuation, |entry| {
        entry["expires_at"] = json!(xolotl_kernel::host::system_now_millis() + 1_000)
    })
    .await?;
    let result =
        tokio::time::timeout(Duration::from_secs(3), fixture.select(&pending, None)).await?;
    ensure!(matches!(result, Err(AuthError::State(_))));
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
    ensure!(fixture.provider.active.load(Ordering::SeqCst) == 0);
    ensure!(credential_snapshot(fixture.backend()).await? == before);
    ensure!(
        challenges::inspect_owner(
            fixture.state.boot.kernel().host_runtime(),
            fixture.backend(),
            &pending.continuation
        )
        .await
        .is_err()
    );
    Ok(())
}

struct ConflictCredentials {
    state: Backend,
    credential_path: Path,
    failures: AtomicUsize,
}

impl StateWrite for ConflictCredentials {
    type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            if path == &self.credential_path
                && matches!(&mutation, StateMutation::CompareSet { .. })
            {
                self.failures.fetch_add(1, Ordering::SeqCst);
                return Err(xolotl_state::StateError::CasFailed {
                    path: path.to_string(),
                    expected: None,
                    actual: None,
                }
                .into());
            }
            self.state.mutate(path, mutation).await
        })
    }
}

impl StateBoundedWrite for ConflictCredentials {
    type BoundedWrite<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn compare_set_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(async move {
            if path == &self.credential_path {
                self.failures.fetch_add(1, Ordering::SeqCst);
                return Err(xolotl_state::StateError::CasFailed {
                    path: path.to_string(),
                    expected: None,
                    actual: None,
                }
                .into());
            }
            self.state
                .write_cas_tainted_bounded(path, expected, value.value, value.taint, limit)
                .await
        })
    }

    fn compare_delete_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: xolotl_types::TaintSet,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(
            self.state
                .write_compare_delete_tainted_bounded(path, expected, taint, limit),
        )
    }
}

#[tokio::test]
async fn malformed_retained_authentication_is_rejected_before_provider_or_credential_cas()
-> anyhow::Result<()> {
    let fixture = Fixture::new(Behavior::Immediate, |_| {}).await?;
    let pending = fixture.password_login().await?;
    let before = credential_snapshot(fixture.backend()).await?;
    let fault = Arc::new(ConflictCredentials {
        state: fixture.backend().clone(),
        credential_path: root_credential_path(fixture.backend()).await?,
        failures: AtomicUsize::new(0),
    });
    let backend = fixture
        .backend()
        .clone()
        .with_write(fault.clone())
        .with_bounded_write(fault.clone());
    for primary in [
        json!({"method":"unknown", "verified_at":1}),
        json!({"method":"password", "verified_at":-1}),
        json!({"method":"public_key", "credential_key":"invalid", "verified_at":1}),
        json!({"method":"passkey_uv", "credential_id":"", "verified_at":1}),
    ] {
        change_ledger(fixture.backend(), &pending.continuation, |entry| {
            entry["payload"]["owner"]["authentication"]["primary"] = primary;
        })
        .await?;
        let result = fixture
            .state
            .auth
            .continue_authentication_inner(
                &backend,
                None,
                ContinueAuthenticationRequest {
                    continuation: pending.continuation.clone(),
                    input: AuthenticationInput::SelectFactor {
                        factor_id: fixture.factor_id.clone(),
                    },
                },
                "invalid-evidence",
            )
            .await;
        ensure!(result.is_err());
        ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 0);
        ensure!(fault.failures.load(Ordering::SeqCst) == 0);
        ensure!(credential_snapshot(fixture.backend()).await? == before);
    }
    Ok(())
}

#[tokio::test]
async fn a_post_provider_credential_conflict_never_replays_the_provider_or_returns_a_session()
-> anyhow::Result<()> {
    let fixture = Fixture::new(Behavior::Immediate, |_| {}).await?;
    let pending = fixture.password_login().await?;
    let before = credential_snapshot(fixture.backend()).await?;
    let fault = Arc::new(ConflictCredentials {
        state: fixture.backend().clone(),
        credential_path: root_credential_path(fixture.backend()).await?,
        failures: AtomicUsize::new(0),
    });
    let backend = fixture
        .backend()
        .clone()
        .with_write(fault.clone())
        .with_bounded_write(fault.clone());
    let result = fixture
        .state
        .auth
        .continue_authentication_inner(
            &backend,
            None,
            ContinueAuthenticationRequest {
                continuation: pending.continuation.clone(),
                input: AuthenticationInput::SelectFactor {
                    factor_id: fixture.factor_id.clone(),
                },
            },
            "fault-peer",
        )
        .await;
    ensure!(matches!(result, Err(AuthError::CredentialConflict)));
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
    ensure!(fault.failures.load(Ordering::SeqCst) == 1);
    ensure!(credential_snapshot(fixture.backend()).await? == before);
    ensure!(
        challenges::inspect_owner(
            fixture.state.boot.kernel().host_runtime(),
            fixture.backend(),
            &pending.continuation
        )
        .await
        .is_err()
    );
    Ok(())
}

struct GatedCredentialCommit {
    state: Backend,
    credential_path: Path,
    calls: AtomicUsize,
    entered: Notify,
    release: Semaphore,
}

impl StateWrite for GatedCredentialCommit {
    type Write<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            if path == &self.credential_path
                && matches!(&mutation, StateMutation::CompareSet { .. })
            {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_one();
                let permit = self.release.acquire().await.map_err(|_error| {
                    xolotl_state::StateError::CasFailed {
                        path: path.to_string(),
                        expected: None,
                        actual: None,
                    }
                })?;
                permit.forget();
            }
            self.state.mutate(path, mutation).await
        })
    }
}

impl StateBoundedWrite for GatedCredentialCommit {
    type BoundedWrite<'a> = Pin<Box<dyn Future<Output = StateResult<StateCommit>> + Send + 'a>>;

    fn compare_set_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(async move {
            if path == &self.credential_path {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.entered.notify_one();
                let permit = self.release.acquire().await.map_err(|_error| {
                    xolotl_state::StateError::CasFailed {
                        path: path.to_string(),
                        expected: None,
                        actual: None,
                    }
                })?;
                permit.forget();
            }
            self.state
                .write_cas_tainted_bounded(path, expected, value.value, value.taint, limit)
                .await
        })
    }

    fn compare_delete_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: xolotl_types::TaintSet,
        limit: std::num::NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(
            self.state
                .write_compare_delete_tainted_bounded(path, expected, taint, limit),
        )
    }
}

#[tokio::test]
async fn final_consumption_ends_cancellation_before_the_credential_commit() -> anyhow::Result<()> {
    let fixture = Fixture::new(Behavior::Immediate, |_| {}).await?;
    let pending = fixture.password_login().await?;
    let primary = challenges::inspect::<Ceremony>(
        fixture.state.boot.kernel().host_runtime(),
        fixture.backend(),
        &pending.continuation,
    )
    .await?
    .payload
    .owner
    .authentication
    .primary;
    let before = credential_snapshot(fixture.backend()).await?;
    let gate = Arc::new(GatedCredentialCommit {
        state: fixture.backend().clone(),
        credential_path: root_credential_path(fixture.backend()).await?,
        calls: AtomicUsize::new(0),
        entered: Notify::new(),
        release: Semaphore::new(0),
    });
    let backend = fixture
        .backend()
        .clone()
        .with_write(gate.clone())
        .with_bounded_write(gate.clone());
    let work = tokio::spawn({
        let state = fixture.state.clone();
        let token = pending.continuation.clone();
        let factor_id = fixture.factor_id.clone();
        async move {
            state
                .auth
                .continue_authentication_inner(
                    &backend,
                    None,
                    ContinueAuthenticationRequest {
                        continuation: token,
                        input: AuthenticationInput::SelectFactor { factor_id },
                    },
                    "worker",
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await?;
    let commit_entered_at = xolotl_kernel::host::system_now_millis();
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
    ensure!(fixture.provider.active.load(Ordering::SeqCst) == 0);
    ensure!(credential_snapshot(fixture.backend()).await? == before);
    ensure!(matches!(
        fixture
            .state
            .auth
            .cancel_authentication(
                &fixture.state.boot,
                None,
                CancelAuthenticationRequest {
                    continuation: pending.continuation.clone()
                },
                "cancel-peer".into(),
            )
            .await,
        Err(AuthError::InvalidChallenge)
    ));
    ensure!(fixture.select(&pending, None).await.is_err());
    ensure!(gate.calls.load(Ordering::SeqCst) == 1);
    tokio::time::sleep(Duration::from_millis(5)).await;
    gate.release.add_permits(1);
    let session = authenticated(tokio::time::timeout(Duration::from_secs(5), work).await???)?;
    ensure!(session.authentication.mfa_level() == 2);
    ensure!(session.authentication.primary == primary);
    let secondary = session
        .authentication
        .secondary
        .as_ref()
        .context("factor evidence")?;
    ensure!(secondary.verified_at() <= commit_entered_at);
    let retained = read_session(
        fixture.state.auth.session_store.as_ref(),
        &session_path(&session.sid)?,
    )
    .await?
    .context("issued session")?;
    ensure!(retained.issued_at > commit_entered_at);
    fixture
        .state
        .auth
        .authenticate_token(&fixture.state.boot, &session.token)
        .await?;
    let record = credentials::read(
        fixture.backend(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(record.factors[&fixture.factor_id].verifier["counter"] == 2);
    ensure!(record.factors[&fixture.factor_id].last_used_at.is_some());
    ensure!(fixture.select(&pending, None).await.is_err());
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 1);
    ensure!(gate.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn direct_recovery_step_up_preserves_primary_and_precommit_verification_time()
-> anyhow::Result<()> {
    let fixture = Fixture::new(Behavior::Immediate, |_| {}).await?;
    let original = fixture
        .state
        .auth
        .authenticate_token(&fixture.state.boot, &fixture.token)
        .await?
        .authentication;
    let gate = Arc::new(GatedCredentialCommit {
        state: fixture.backend().clone(),
        credential_path: root_credential_path(fixture.backend()).await?,
        calls: AtomicUsize::new(0),
        entered: Notify::new(),
        release: Semaphore::new(0),
    });
    let backend = fixture
        .backend()
        .clone()
        .with_write(gate.clone())
        .with_bounded_write(gate.clone());
    let work = tokio::spawn({
        let state = fixture.state.clone();
        let token = fixture.token.clone();
        let code = fixture.recovery_code.clone();
        async move {
            state
                .auth
                .step_up_inner(
                    &backend,
                    &token,
                    StepUpRequest {
                        proof: Some(MfaProof::RecoveryCode { code }),
                    },
                    "recovery-peer".into(),
                )
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await?;
    let commit_entered_at = xolotl_kernel::host::system_now_millis();
    let before = credentials::read(
        fixture.backend(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(
        before
            .recovery
            .contains(&token_hash(&fixture.recovery_code))
    );
    tokio::time::sleep(Duration::from_millis(5)).await;
    gate.release.add_permits(1);
    let session = authenticated(tokio::time::timeout(Duration::from_secs(5), work).await???)?;
    ensure!(session.authentication.primary == original.primary);
    ensure!(matches!(
        session.authentication.secondary,
        Some(SecondaryAuthentication::RecoveryCode { verified_at })
            if verified_at <= commit_entered_at
    ));
    let retained = read_session(
        fixture.state.auth.session_store.as_ref(),
        &session_path(&session.sid)?,
    )
    .await?
    .context("issued recovery session")?;
    ensure!(retained.issued_at > commit_entered_at);
    let after = credentials::read(
        fixture.backend(),
        "root",
        crate::auth::test_credential_sealer().as_ref(),
    )
    .await?;
    ensure!(!after.recovery.contains(&token_hash(&fixture.recovery_code)));
    ensure!(serde_json::to_value(&after.factors)? == serde_json::to_value(&before.factors)?);
    ensure!(fixture.provider.calls.load(Ordering::SeqCst) == 0);
    Ok(())
}
