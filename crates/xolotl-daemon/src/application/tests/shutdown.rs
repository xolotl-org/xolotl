use super::*;
use sha2::{Digest as _, Sha256, Sha384};
use std::sync::Mutex;
use tokio::sync::oneshot;
use xolotl_console::{
    BootstrapOutcome, ConsoleAuthConfig, ConsoleConfig, ConsoleExecutionConfig,
    ConsoleRuntimeConfig, ConsoleService, ConsoleState, CredentialSealer, LoginRequest,
    RootProvisioning, RuntimeCode, RuntimeRequest, StepUpRequest, bootstrap_root_account,
    mfa::{MfaEnrollmentProgress, MfaInteractionInput, MfaProof, MfaRequest, MfaResponse},
};
use xolotl_federation::{
    CallAuthorityRule, CallMethod, CallPath, CallTarget, Digest, ExportName, FederationCallStore,
    FederationError, FederationNodeId, FederationSubject, InvokeCallRequest,
    MemoryFederationCallStore, PrepareCallRequest, RequestId,
};
use xolotl_federation_kernel::{
    FederationKernelCallBridge, FederationKernelCatalog, FederationKernelMethod,
};
use xolotl_graph::portable::{Expression, Program};
use xolotl_kernel::host::TokioBlockingSpawner;
use xolotl_proto::xolotl::v1::application::{
    DescribeRequest, application_gateway_server::ApplicationGateway as _,
};

struct BlockedCatalog {
    entered: Mutex<Option<oneshot::Sender<()>>>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

impl FederationKernelCatalog for BlockedCatalog {
    fn resolve(
        &self,
        _target: &CallTarget,
    ) -> Result<Arc<FederationKernelMethod>, FederationError> {
        if let Some(entered) = self
            .entered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _sent = entered.send(());
        }
        self.release
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_error| FederationError::Invalid("test admission gate expired"))?;
        Err(FederationError::Invalid("test catalog unavailable"))
    }
}

struct ReleaseAdmission(Option<std::sync::mpsc::Sender<()>>);

impl Drop for ReleaseAdmission {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            let _sent = release.send(());
        }
    }
}

fn enrollment_code(secret: &str, now_ms: u64) -> Result<String> {
    let mut decoded = Vec::new();
    let mut accumulator = 0_u32;
    let mut bits = 0_u32;
    for character in secret.bytes() {
        let digit = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            .iter()
            .position(|candidate| *candidate == character)
            .context("invalid enrollment secret")? as u32;
        accumulator = (accumulator << 5) | digit;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            decoded.push((accumulator >> bits) as u8);
        }
    }
    ensure!(decoded.len() <= 64);
    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for (index, byte) in decoded.iter().enumerate() {
        inner_pad[index] ^= byte;
        outer_pad[index] ^= byte;
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update((now_ms / 1000 / 30).to_be_bytes());
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    let digest = outer.finalize();
    let offset = usize::from(digest[31] & 0x0f);
    let code = u32::from_be_bytes(digest[offset..offset + 4].try_into()?) & 0x7fff_ffff;
    Ok(format!("{:06}", code % 1_000_000))
}

async fn console(boot: Arc<Bootstrap>) -> Result<(ConsoleService, String)> {
    let sealer = Arc::new(CredentialSealer::new("shutdown-test", &[0x71; 32])?);
    let BootstrapOutcome::CreatedRandomPassword { password, .. } = bootstrap_root_account(
        &boot,
        &TokioBlockingSpawner::default(),
        RootProvisioning {
            credential_sealer: Some(sealer.clone()),
            ..Default::default()
        },
    )
    .await?
    else {
        anyhow::bail!("expected new root account");
    };
    let service = ConsoleService::new(ConsoleState::with_config(
        boot.clone(),
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                xolotl_console::session_store::MemoryConsoleSessionStore::new(
                    xolotl_console::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            auth: ConsoleAuthConfig {
                credential_sealer: Some(sealer),
                ..Default::default()
            },
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                executions: ConsoleExecutionConfig {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )?);
    let login = service
        .login(
            LoginRequest {
                username: "root".into(),
                password,
                second_factor: None,
            },
            "embedded".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("root session")?;
    let MfaResponse::Enrollment {
        challenge_id,
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = service
        .mfa(
            &login.token,
            MfaRequest::Begin {
                provider_id: "totp".into(),
                label: "Shutdown acceptance".into(),
                replace_factor_id: None,
                input: None,
            },
            "embedded".into(),
        )
        .await?
    else {
        anyhow::bail!("expected TOTP enrollment challenge");
    };
    let code = enrollment_code(
        setup
            .get("secret")
            .and_then(serde_json::Value::as_str)
            .context("secret")?,
        boot.kernel().host_runtime().now_millis() as u64,
    )?;
    let MfaResponse::Updated {
        session,
        recovery_codes,
    } = service
        .mfa(
            &login.token,
            MfaRequest::Continue {
                challenge_id,
                input: MfaInteractionInput::Response {
                    response: json!({"code": code}),
                },
            },
            "embedded".into(),
        )
        .await?
    else {
        anyhow::bail!("expected enrolled session");
    };
    let code = recovery_codes
        .context("recovery codes")?
        .pop()
        .context("recovery proof")?;
    let elevated = service
        .step_up(
            &session.token,
            StepUpRequest {
                proof: Some(MfaProof::RecoveryCode { code }),
            },
            "embedded".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("elevated root session")?;
    Ok((service, elevated.token))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_closes_all_admission_before_waiting_for_federation_submission() -> Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let blocking = TokioBlockingSpawner::default();
    let (console, token) = console(boot.clone()).await?;
    let request = || {
        RuntimeRequest::new(
            RuntimeCode::Program(Program::new(Expression::Input)),
            Value::null(),
            "shutdown",
            "cross-service shutdown acceptance",
            10_000,
        )
    };
    console
        .submit_runtime(&token, Some("embedded"), request())
        .await?;
    boot.kernel()
        .state()
        .write_set(&profile::profile_path("app")?, value(1)?)
        .await?;
    let application = ApplicationGateway::start_at(
        &config(),
        Some("127.0.0.1:0"),
        boot.clone(),
        ObjectStore::new(),
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default()),
    )
    .await?
    .context("application listener")?;
    let application_service = application.service.clone();
    let probe = || tonic::Request::new(DescribeRequest {});
    ensure!(
        application_service
            .describe(probe())
            .await
            .err()
            .context("unauthenticated application probe should be rejected")?
            .code()
            != tonic::Code::Unavailable
    );

    let node = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let store = Arc::new(MemoryFederationCallStore::new(node));
    let now = boot.kernel().host_runtime().now_millis() as u64;
    let target = CallTarget {
        export: ExportName::new("tools")?,
        path: CallPath::new("/echo")?,
        method: CallMethod::new("echo")?,
        contract_digest: [3; 32],
    };
    store.set_call_authority(
        None,
        CallAuthorityRule {
            subject: FederationSubject::Node(peer),
            presenter: peer,
            target: target.clone(),
            enabled: true,
            expires_ms: now + 120_000,
            max_input_bytes: 1024,
            max_prepare_window_ms: 30_000,
            max_result_retention_ms: 30_000,
        },
    )?;
    let origin_request_id = RequestId::from_bytes([4; 16]);
    let call = store
        .prepare_call(
            PrepareCallRequest {
                authenticated_origin: peer,
                subject: FederationSubject::Node(peer),
                origin_request_id,
                target,
                input_digest: Digest::from_bytes(Sha384::digest(b"input").into()),
                input_bytes: 5,
                prepare_deadline_ms: now + 30_000,
                execution_deadline_ms: now + 60_000,
                result_retention_ms: 30_000,
            },
            now,
        )?
        .call;
    let (entered, ready) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    let release = ReleaseAdmission(Some(release));
    let bridge = FederationKernelCallBridge::new(
        boot.clone(),
        store,
        Arc::new(BlockedCatalog {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(gate),
        }),
    )?;
    let invocation = {
        let bridge = bridge.clone();
        tokio::spawn(async move {
            bridge
                .invoke(
                    InvokeCallRequest {
                        authenticated_origin: peer,
                        subject: FederationSubject::Node(peer),
                        origin_request_id,
                        call,
                        input: Arc::from(b"input".as_slice()),
                    },
                    now,
                )
                .await
        })
    };
    tokio::time::timeout(Duration::from_secs(5), ready).await??;
    let mut shutdown = Box::pin(crate::host_lifecycle::supervise_host(
        &boot,
        &blocking,
        async |services| {
            services.application = Some(application);
            services.console = Some(console.clone());
            services.federation_calls = Some(bridge);
            Ok(())
        },
    ));
    ensure!(
        std::future::poll_fn(|context| Poll::Ready(shutdown.as_mut().poll(context)))
            .await
            .is_pending()
    );
    ensure!(
        !invocation.is_finished(),
        "federation admission must remain blocked"
    );
    let rejected = application_service
        .describe(probe())
        .await
        .err()
        .context("application admission remained open")?;
    ensure!(rejected.code() == tonic::Code::Unavailable);
    ensure!(rejected.message() == "application gateway is closed");
    let rejected = console
        .submit_runtime(&token, Some("embedded"), request())
        .await
        .err()
        .context("Console submission admission remained open")?;
    ensure!(
        rejected
            .message
            .contains("independent execution admission is closed"),
        "unexpected rejection: {rejected:?}"
    );
    ensure!(
        std::future::poll_fn(|context| Poll::Ready(shutdown.as_mut().poll(context)))
            .await
            .is_pending()
    );
    drop(release);
    ensure!(matches!(
        tokio::time::timeout(Duration::from_secs(5), invocation).await??,
        Err(FederationError::Invalid("test catalog unavailable"))
    ));
    tokio::time::timeout(Duration::from_secs(5), shutdown).await??;
    Ok(())
}
