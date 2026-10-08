//! A host-installed factor, implemented entirely using the public extension API.
//! Fixed signing keys below are test fixtures, not enrollment examples.

#[path = "support/console_config.rs"]
mod console_config;
#[path = "support/sealer.rs"]
mod sealer;

use anyhow::{Context, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
#[path = "support/pqc_key.rs"]
mod pqc_key;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Barrier;
use xolotl_console::{
    ConsoleConfig, ConsoleErrorCode, ConsoleService, ConsoleState, LoginRequest, LoginResponse,
    RootProvisioning, StepUpRequest, bootstrap_root_account, mfa::*,
};
use xolotl_kernel::Bootstrap;

fn factor_choices(response: xolotl_console::AuthenticationResponse) -> anyhow::Result<MfaOptions> {
    let xolotl_console::AuthenticationResponse::Continue(next) = response else {
        anyhow::bail!("missing second factor must not issue a session");
    };
    ensure!(!next.continuation.is_empty());
    let xolotl_console::AuthenticationStep::ChooseFactor { options } = next.step else {
        anyhow::bail!("expected factor selection after primary authentication");
    };
    Ok(options)
}

#[path = "mfa_provider/descriptor.rs"]
mod descriptor;

#[path = "mfa_provider/begin.rs"]
mod begin;

#[path = "mfa_provider/key_usage.rs"]
mod key_usage;

#[path = "mfa_provider/usage.rs"]
mod usage;

#[path = "mfa_provider/enrollment.rs"]
mod enrollment;

struct SignedFactor {
    key: VerifyingKey,
    racing: AtomicBool,
    concurrent_verifications: Barrier,
    observations: Mutex<Vec<(String, String, String, String)>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    counter: u64,
    expires_at: i64,
    signature: String,
}

fn purpose_name(purpose: MfaPurpose) -> &'static str {
    match purpose {
        MfaPurpose::Enrollment => "enrollment",
        MfaPurpose::Login => "login",
        MfaPurpose::StepUp => "step_up",
    }
}

fn transcript(context: &MfaContext<'_>, nonce: &str, counter: u64, expires_at: i64) -> String {
    format!(
        "test-second-factor-v1\n{}\n{}\n{}\n{}\n{}\n{nonce}\n{counter}\n{expires_at}",
        context.issuer,
        context.username,
        context.account_id,
        context.factor_id,
        purpose_name(context.purpose),
    )
}

impl SignedFactor {
    fn observe(&self, context: &MfaContext<'_>) -> Result<(), MfaProviderError> {
        if context.account_id.is_empty() || context.factor_id.is_empty() || context.label.is_empty()
        {
            return Err(MfaProviderError::InvalidState);
        }
        self.observations
            .lock()
            .map_err(|_error| MfaProviderError::Unavailable)?
            .push((
                context.account_id.into(),
                context.factor_id.into(),
                context.label.into(),
                purpose_name(context.purpose).into(),
            ));
        Ok(())
    }
}

impl MfaProvider for SignedFactor {
    fn descriptor(&self) -> MfaProviderDescriptor {
        MfaProviderDescriptor {
            provider_id: "signed_device".into(),
            label: "Signing device".into(),
            enrollment: Some(MfaEnrollmentDescriptor {
                begin_schema: None,
                setup_schema: serde_json::json!(true),
                pending_schema: None,
            }),
            authentication: MfaAuthenticationDescriptor {
                proof_schema: Some(signed_schema()),
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
            self.observe(&context.factor)?;
            if !matches!(context.factor.purpose, MfaPurpose::Enrollment) {
                return Err(MfaProviderError::InvalidState);
            }
            let mut nonce = [0; 32];
            getrandom::fill(&mut nonce).map_err(|_error| MfaProviderError::Unavailable)?;
            let nonce = URL_SAFE_NO_PAD.encode(nonce);
            Ok(MfaEnrollmentStep::Challenge {
                setup: json!({"nonce":nonce,"account_id":context.factor.account_id,"factor_id":context.factor.factor_id}),
                response_schema: signed_schema(),
                private_state: json!({"nonce":nonce,"account_id":context.factor.account_id,"factor_id":context.factor.factor_id,"counter":0}),
            })
        })
    }

    fn continue_enrollment<'a>(
        &'a self,
        context: MfaEnrollmentContext<'a>,
        private_state: &'a Value,
        input: &'a MfaInteractionInput,
    ) -> MfaFuture<'a, MfaEnrollmentStep> {
        if context.factor.purpose != MfaPurpose::Enrollment {
            return Box::pin(async { Err(MfaProviderError::InvalidState) });
        }
        Box::pin(async move {
            let MfaInteractionInput::Response { response } = input else {
                return Err(MfaProviderError::InvalidInput);
            };
            let verifier = self
                .verify_signed(context.factor, private_state, response)
                .await?;
            Ok(MfaEnrollmentStep::Verified { verifier })
        })
    }

    fn verify_proof<'a>(
        &'a self,
        context: MfaContext<'a>,
        verifier: &'a Value,
        proof: &'a Value,
    ) -> MfaFuture<'a, Value> {
        if context.purpose == MfaPurpose::Enrollment {
            return Box::pin(async { Err(MfaProviderError::InvalidState) });
        }
        self.verify_signed(context, verifier, proof)
    }
}

fn signed_schema() -> Value {
    json!({"type":"object", "required":["counter","expires_at","signature"], "additionalProperties":false, "properties":{"counter":{"type":"integer"},"expires_at":{"type":"integer"},"signature":{"type":"string"}}})
}

impl SignedFactor {
    fn verify_signed<'a>(
        &'a self,
        context: MfaContext<'a>,
        verifier: &'a Value,
        proof: &'a Value,
    ) -> MfaFuture<'a, Value> {
        Box::pin(async move {
            self.observe(&context)?;
            if verifier["account_id"] != context.account_id
                || verifier["factor_id"] != context.factor_id
            {
                return Err(MfaProviderError::InvalidState);
            }
            let counter = verifier["counter"]
                .as_u64()
                .ok_or(MfaProviderError::InvalidState)?;
            let nonce = verifier["nonce"]
                .as_str()
                .ok_or(MfaProviderError::InvalidState)?;
            let proof: Proof = serde_json::from_value(proof.clone())
                .map_err(|_error| MfaProviderError::InvalidProof)?;
            if proof.counter <= counter
                || proof.expires_at < context.now_ms
                || proof.expires_at > context.now_ms + 60_000
            {
                return Err(MfaProviderError::InvalidProof);
            }
            let bytes = URL_SAFE_NO_PAD
                .decode(proof.signature)
                .map_err(|_error| MfaProviderError::InvalidProof)?;
            let signature =
                Signature::from_slice(&bytes).map_err(|_error| MfaProviderError::InvalidProof)?;
            self.key
                .verify_strict(
                    transcript(&context, nonce, proof.counter, proof.expires_at).as_bytes(),
                    &signature,
                )
                .map_err(|_error| MfaProviderError::InvalidProof)?;
            // Both requests have read their account snapshot before either can CAS.
            if proof.counter == 2 && self.racing.load(Ordering::SeqCst) {
                self.concurrent_verifications.wait().await;
            }
            let mut next = verifier.clone();
            next["counter"] = json!(proof.counter);
            Ok(next)
        })
    }
}

struct Device {
    factor_id: String,
    label: String,
    setup: Value,
}

fn signed_response(
    key: &SigningKey,
    device: &Device,
    counter: u64,
    purpose: MfaPurpose,
) -> anyhow::Result<Value> {
    let expires_at =
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())? + 30_000;
    let context = MfaContext {
        authority_id: "local",
        username: "root",
        issuer: "Xolotl Console",
        now_ms: expires_at - 30_000,
        account_id: device.setup["account_id"]
            .as_str()
            .context("account instance")?,
        factor_id: &device.factor_id,
        label: &device.label,
        purpose,
    };
    let nonce = device.setup["nonce"].as_str().context("nonce")?;
    let signature = key.sign(transcript(&context, nonce, counter, expires_at).as_bytes());
    Ok(serde_json::to_value(Proof {
        counter,
        expires_at,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })?)
}

fn signed_proof(
    key: &SigningKey,
    device: &Device,
    counter: u64,
    purpose: MfaPurpose,
) -> anyhow::Result<MfaProof> {
    Ok(MfaProof::Factor {
        factor_id: device.factor_id.clone(),
        response: signed_response(key, device, counter, purpose)?,
    })
}

fn login(proof: Option<MfaProof>) -> LoginRequest {
    LoginRequest {
        username: "root".into(),
        password: "Ar7!cVN23#pxQe$Lr9".into(),
        second_factor: proof,
    }
}

async fn fixture() -> anyhow::Result<(
    Arc<Bootstrap>,
    ConsoleConfig,
    ConsoleService,
    Arc<SignedFactor>,
    SigningKey,
)> {
    let key = SigningKey::from_bytes(&[31; 32]);
    let boot = Arc::new(Bootstrap::in_memory());
    bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            credential_sealer: Some(crate::sealer::sealer()),
            password: Some(login(None).password),
            ..Default::default()
        },
    )
    .await?;
    let provider = Arc::new(SignedFactor {
        key: key.verifying_key(),
        racing: AtomicBool::new(false),
        concurrent_verifications: Barrier::new(2),
        observations: Mutex::new(Vec::new()),
    });
    let mut config = crate::console_config::console_config();
    config.auth.mfa.providers.push(provider.clone());
    let service = ConsoleService::new(ConsoleState::with_config(boot.clone(), config.clone())?);
    Ok((boot, config, service, provider, key))
}

async fn enroll(
    service: &ConsoleService,
    token: &str,
    key: &SigningKey,
    label: &str,
) -> anyhow::Result<(Device, LoginResponse, Option<Vec<String>>)> {
    let MfaResponse::Enrollment {
        challenge_id,
        factor_id,
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = service
        .mfa(
            token,
            MfaRequest::Begin {
                provider_id: "signed_device".into(),
                label: label.into(),
                replace_factor_id: None,
                input: None,
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("enrollment");
    };
    ensure!(setup["factor_id"] == factor_id);
    let device = Device {
        factor_id,
        label: label.into(),
        setup,
    };
    let MfaResponse::Updated {
        session,
        recovery_codes,
    } = service
        .mfa(
            token,
            MfaRequest::Continue {
                challenge_id,
                input: MfaInteractionInput::Response {
                    response: signed_response(key, &device, 1, MfaPurpose::Enrollment)?,
                },
            },
            "test".into(),
        )
        .await?
    else {
        anyhow::bail!("confirmation");
    };
    let mut session = session;
    let mut recovery_codes = recovery_codes;
    if session.authentication.mfa_level() == 1 {
        let code = recovery_codes
            .as_mut()
            .and_then(Vec::pop)
            .context("first enrollment recovery proof")?;
        session = service
            .step_up(
                &session.token,
                StepUpRequest {
                    proof: Some(MfaProof::RecoveryCode { code }),
                },
                "test".into(),
            )
            .await?
            .into_session()
            .map_err(|_continuation| anyhow::anyhow!("completed step-up"))?;
    }
    Ok((device, session, recovery_codes))
}

#[tokio::test]
async fn custom_factor_binds_context_and_concurrent_login_commits_exactly_one_proof()
-> anyhow::Result<()> {
    let (boot, config, service, provider, key) = fixture().await?;
    ensure!(
        service
            .mfa_providers()
            .iter()
            .any(|p| p.descriptor.provider_id == "signed_device")
    );
    let primary = service
        .login(login(None), "test".into())
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let (device, session, codes) =
        enroll(&service, &primary.token, &key, "Hardware signer").await?;
    ensure!(session.authentication.mfa_level() == 2 && codes.is_some());
    let mismatch = service
        .mfa(
            &session.token,
            MfaRequest::Begin {
                provider_id: "totp".into(),
                label: "Wrong mechanism".into(),
                replace_factor_id: Some(device.factor_id.clone()),
                input: None,
            },
            "test".into(),
        )
        .await
        .err()
        .context("replacement cannot change provider")?;
    ensure!(mismatch.code == ConsoleErrorCode::BadRequest);
    let MfaResponse::Status { factors, .. } = service
        .mfa(&session.token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("unchanged factor after provider mismatch");
    };
    ensure!(
        factors.len() == 1
            && factors[0].factor_id == device.factor_id
            && factors[0].provider_id == "signed_device"
    );
    let options = factor_choices(service.login(login(None), "test".into()).await?)?;
    ensure!(options.factors.len() == 1 && options.recovery_code_available);
    ensure!(
        options.factors[0].factor_id == device.factor_id
            && options.factors[0].availability == FactorAvailability::Available
    );
    provider.racing.store(true, Ordering::SeqCst);
    let proof = signed_proof(&key, &device, 2, MfaPurpose::Login)?;
    let (a, b) = tokio::join!(
        service.login(login(Some(proof.clone())), "test".into()),
        service.login(login(Some(proof.clone())), "test".into()),
    );
    provider.racing.store(false, Ordering::SeqCst);
    ensure!(usize::from(a.is_ok()) + usize::from(b.is_ok()) == 1);
    for response in [a, b].into_iter().filter_map(Result::ok) {
        let session = response
            .into_session()
            .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
        ensure!(session.authentication.mfa_level() == 2);
    }
    let authenticated = service
        .login(
            login(Some(signed_proof(&key, &device, 3, MfaPurpose::Login)?)),
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(authenticated.authentication.mfa_level() == 2);
    let upgraded = service
        .step_up(
            &authenticated.token,
            StepUpRequest {
                proof: Some(signed_proof(&key, &device, 4, MfaPurpose::StepUp)?),
            },
            "test".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(upgraded.authentication.mfa_level() == 2);
    let replay = service
        .login(login(Some(proof)), "test".into())
        .await
        .err()
        .context("replayed proof")?;
    ensure!(replay.code == ConsoleErrorCode::NotAuthenticated);
    let restarted = ConsoleService::new(ConsoleState::with_config(boot.clone(), config.clone())?);
    let wrong_key = SigningKey::from_bytes(&[32; 32]);
    let error = restarted
        .login(
            login(Some(signed_proof(
                &wrong_key,
                &device,
                5,
                MfaPurpose::Login,
            )?)),
            "test".into(),
        )
        .await
        .err()
        .context("wrong signing key")?;
    ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    {
        let observed = provider
            .observations
            .lock()
            .map_err(|_error| anyhow::anyhow!("observations poisoned"))?;
        ensure!(
            observed
                .iter()
                .all(
                    |(account, factor, label, _)| device.setup["account_id"] == *account
                        && factor == &device.factor_id
                        && label == "Hardware signer"
                )
        );
        for expected in ["enrollment", "login", "step_up"] {
            ensure!(
                observed
                    .iter()
                    .any(|(_, _, _, purpose)| purpose == expected)
            );
        }
    }
    // Removing a provider retains its instances without reducing login requirements.
    let without_provider = ConsoleService::new(ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: config.session_store.clone(),
            ..crate::console_config::console_config()
        },
    )?);
    let options = factor_choices(without_provider.login(login(None), "test".into()).await?)?;
    ensure!(options.factors.len() == 1 && options.factors[0].factor_id == device.factor_id);
    ensure!(
        options.factors[0].availability == FactorAvailability::ProviderNotInstalled
            && options.recovery_code_available
    );
    let MfaResponse::Status { factors, .. } = without_provider
        .mfa(&upgraded.token, MfaRequest::Status {}, "test".into())
        .await?
    else {
        anyhow::bail!("unavailable factor status");
    };
    ensure!(
        factors.len() == 1
            && factors[0].factor_id == device.factor_id
            && factors[0].availability == FactorAvailability::ProviderNotInstalled
    );
    let error = without_provider
        .login(
            login(Some(signed_proof(&key, &device, 5, MfaPurpose::Login)?)),
            "test".into(),
        )
        .await
        .err()
        .context("missing provider")?;
    ensure!(error.code == ConsoleErrorCode::AdmissionRejected);
    let codes = codes.context("recovery codes")?;
    let recovered = without_provider
        .login(
            login(Some(MfaProof::RecoveryCode {
                code: codes[0].clone(),
            })),
            "recovery".into(),
        )
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    ensure!(recovered.authentication.mfa_level() == 2);
    Ok(())
}

#[tokio::test]
async fn concurrent_devices_preserve_both_counters_without_overwriting_the_other_commit()
-> anyhow::Result<()> {
    let (boot, config, service, provider, key) = fixture().await?;
    let primary = service
        .login(login(None), "test".into())
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let (a, session, _) = enroll(&service, &primary.token, &key, "Signer A").await?;
    let (b, _, _) = enroll(&service, &session.token, &key, "Signer B").await?;
    ensure!(a.factor_id != b.factor_id && a.setup["account_id"] == b.setup["account_id"]);
    let pa = signed_proof(&key, &a, 2, MfaPurpose::Login)?;
    let pb = signed_proof(&key, &b, 2, MfaPurpose::Login)?;
    provider.racing.store(true, Ordering::SeqCst);
    let (ra, rb) = tokio::join!(
        service.login(login(Some(pa.clone())), "test".into()),
        service.login(login(Some(pb.clone())), "test".into()),
    );
    provider.racing.store(false, Ordering::SeqCst);
    ensure!(
        usize::from(ra.is_ok()) + usize::from(rb.is_ok()) == 1,
        "one account CAS winner must reject the stale sibling snapshot"
    );
    let (loser, winner) = if ra.is_ok() { (pb, pa) } else { (pa, pb) };
    for response in [ra, rb].into_iter().filter_map(Result::ok) {
        let session = response
            .into_session()
            .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
        ensure!(session.authentication.mfa_level() == 2);
    }
    service
        .login(login(Some(loser.clone())), "test".into())
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    // Restarting the service resets transient rate limits, while each verifier
    // remains in shared State. Both committed counters must still reject replay.
    for proof in [winner, loser] {
        let debug = format!("{proof:?}");
        ensure!(!debug.contains("signature") && !debug.contains("nonce"));
        let restarted =
            ConsoleService::new(ConsoleState::with_config(boot.clone(), config.clone())?);
        let rejected = restarted
            .login(login(Some(proof)), "test".into())
            .await
            .err()
            .context("both device proofs consumed")?;
        ensure!(rejected.code == ConsoleErrorCode::NotAuthenticated);
    }
    Ok(())
}

#[tokio::test]
async fn proofs_cannot_replace_the_host_selected_account_factor_or_purpose() -> anyhow::Result<()> {
    let (boot, config, service, _, key) = fixture().await?;
    let primary = service
        .login(login(None), "test".into())
        .await?
        .into_session()
        .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    let (a, session, _) = enroll(&service, &primary.token, &key, "Signer A").await?;
    let (b, _, _) = enroll(&service, &session.token, &key, "Signer B").await?;
    let mut forged_account = Device {
        factor_id: a.factor_id.clone(),
        label: a.label.clone(),
        setup: a.setup.clone(),
    };
    forged_account.setup["account_id"] = json!("different-account-instance");
    let proofs = [
        signed_proof(&key, &forged_account, 2, MfaPurpose::Login)?,
        MfaProof::Factor {
            factor_id: b.factor_id.clone(),
            response: signed_response(&key, &a, 2, MfaPurpose::Login)?,
        },
        signed_proof(&key, &a, 2, MfaPurpose::Enrollment)?,
    ];
    for proof in proofs {
        let restarted =
            ConsoleService::new(ConsoleState::with_config(boot.clone(), config.clone())?);
        let error = restarted
            .login(login(Some(proof)), "test".into())
            .await
            .err()
            .context("forged context")?;
        ensure!(error.code == ConsoleErrorCode::NotAuthenticated);
    }
    // Failed context substitutions never consume either legitimate verifier.
    let restarted = ConsoleService::new(ConsoleState::with_config(boot, config)?);
    for device in [&a, &b] {
        restarted
            .login(
                login(Some(signed_proof(&key, device, 2, MfaPurpose::Login)?)),
                "test".into(),
            )
            .await?
            .into_session()
            .map_err(|_error| anyhow::anyhow!("expected completed authentication"))?;
    }
    Ok(())
}
