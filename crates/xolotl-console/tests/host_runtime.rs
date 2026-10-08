//! A Console service hosted without an ambient Tokio runtime.

#[path = "support/console_config.rs"]
mod console_config;
#[path = "support/sealer.rs"]
mod sealer;

use anyhow::{Context as _, ensure};
use hmac::{Hmac, KeyInit as _, Mac as _};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use xolotl_console::{
    ActionCall, ConsoleConfig, ConsoleExecutionConfig, ConsoleRuntimeConfig, ConsoleService,
    ConsoleState, LoginRequest, RootProvisioning, RuntimeCode, RuntimeRequest, StepUpRequest,
    bootstrap_root_account,
    mfa::{MfaEnrollmentProgress, MfaInteractionInput, MfaProof, MfaRequest, MfaResponse},
};
use xolotl_console_protocol::{
    ACTION_PROTOCOL_DESCRIBE, ACTION_RUNTIME_EXECUTION_CANCEL, ACTION_RUNTIME_EXECUTION_GET,
    ACTION_RUNTIME_EXECUTION_RESULT,
};
use xolotl_graph::{
    OperationTemplate, WaitSpec,
    portable::{Expression, Program},
};
use xolotl_kernel::{
    Bootstrap, FnDriver, KernelBuilder, MethodSpec,
    host::{
        AbortTask, BlockingJob, BlockingSpawnError, BlockingSpawner, HostClock, HostRuntime,
        TaskSpawnError, TaskSpawner,
    },
};
use xolotl_types::{
    MethodAuthority, OutputMode, OutputModeSet, Path, Purity, ResourceName, Value, ValueMap,
};

struct TestClock;

impl HostClock for TestClock {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn unix_millis(&self) -> i64 {
        xolotl_kernel::host::system_now_millis()
    }

    fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

struct ThreadClock;

impl HostClock for ThreadClock {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn unix_millis(&self) -> i64 {
        xolotl_kernel::host::system_now_millis()
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        let (wake, receiver) = tokio::sync::oneshot::channel();
        let (cancel, cancellation) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            if matches!(
                cancellation.recv_timeout(deadline.saturating_duration_since(Instant::now())),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ) {
                let _cancelled = wake.send(()).is_err();
            }
        });
        Box::pin(async move {
            let _cancel_on_drop = cancel;
            drop(receiver.await);
        })
    }
}

struct NoAsyncTasks;

impl TaskSpawner for NoAsyncTasks {
    fn spawn(
        &self,
        _future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
        Err(TaskSpawnError::Unavailable)
    }
}

#[derive(Default)]
struct ThreadTasks {
    started: AtomicUsize,
}

struct ThreadAbort {
    aborted: Arc<AtomicBool>,
    thread: std::thread::Thread,
}

impl AbortTask for ThreadAbort {
    fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        self.thread.unpark();
    }
}

impl TaskSpawner for ThreadTasks {
    fn spawn(
        &self,
        mut future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
        let aborted = Arc::new(AtomicBool::new(false));
        let worker_abort = aborted.clone();
        let worker = std::thread::Builder::new()
            .spawn(move || {
                let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
                let mut context = Context::from_waker(&waker);
                while !worker_abort.load(Ordering::Acquire) {
                    if future.as_mut().poll(&mut context).is_ready() {
                        return;
                    }
                    std::thread::park();
                }
            })
            .map_err(|_error| TaskSpawnError::Unavailable)?;
        let thread = worker.thread().clone();
        drop(worker);
        self.started.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(ThreadAbort { aborted, thread }))
    }
}

#[derive(Default)]
struct ThreadJobs {
    in_flight: Arc<AtomicUsize>,
    accepted: AtomicUsize,
}

struct Release(Arc<AtomicUsize>);

impl Drop for Release {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl BlockingSpawner for ThreadJobs {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        self.in_flight
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |in_flight| {
                (in_flight < 4).then_some(in_flight + 1)
            })
            .map_err(|_busy| BlockingSpawnError::AtCapacity)?;
        let in_flight = self.in_flight.clone();
        if std::thread::Builder::new()
            .spawn(move || {
                let _release = Release(in_flight);
                job();
            })
            .is_err()
        {
            self.in_flight.fetch_sub(1, Ordering::AcqRel);
            return Err(BlockingSpawnError::Unavailable);
        }
        self.accepted.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct ThreadWake(std::thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn block_on<F: Future>(future: F) -> anyhow::Result<F::Output> {
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return Ok(value);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "Console future did not wake without Tokio"
        );
        std::thread::park_timeout(remaining);
    }
}

fn field<'a>(value: &'a Value, name: &str) -> anyhow::Result<&'a Value> {
    value
        .as_map()
        .and_then(|map| map.get(name))
        .with_context(|| format!("missing {name}"))
}

fn execution_input(id: &str) -> Value {
    Value::from(ValueMap::from(std::collections::BTreeMap::from([(
        "execution_id".to_owned(),
        Value::string(id.to_owned()),
    )])))
}

fn totp(setup: &serde_json::Value) -> anyhow::Result<String> {
    let secret = data_encoding::BASE32_NOPAD
        .decode(setup["secret"].as_str().context("TOTP secret")?.as_bytes())?;
    let counter = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&secret)?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = usize::from(hash[hash.len() - 1] & 15);
    let value = u32::from_be_bytes(hash[offset..offset + 4].try_into()?) & 0x7fff_ffff;
    Ok(format!("{:06}", value % 1_000_000))
}

fn finished(service: &ConsoleService, token: &str, id: &str) -> anyhow::Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let metadata = block_on(service.call(
            token,
            Some("local-test-peer"),
            ActionCall {
                action: ACTION_RUNTIME_EXECUTION_GET.into(),
                input: execution_input(id),
                ..Default::default()
            },
        ))??
        .output
        .context("execution metadata")?;
        if field(&metadata, "status")?.as_str() == Some("finished") {
            return Ok(metadata);
        }
        ensure!(
            Instant::now() < deadline,
            "thread-hosted execution did not finish"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn console_shared_inherits_kernel_blocking_port_without_tokio() -> anyhow::Result<()> {
    ensure!(tokio::runtime::Handle::try_current().is_err());
    let jobs = Arc::new(ThreadJobs::default());
    let runtime = HostRuntime::new(Arc::new(TestClock), Arc::new(NoAsyncTasks), jobs.clone());
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_host_runtime(runtime)
            .build(),
    ));
    let password = "V7$pQ2!zN9@xL4#tM8";
    block_on(bootstrap_root_account(
        &boot,
        jobs.as_ref(),
        RootProvisioning {
            credential_sealer: Some(crate::sealer::sealer()),
            password: Some(password.into()),
            ..Default::default()
        },
    ))??;

    let service = ConsoleService::new(ConsoleState::with_config(
        boot,
        crate::console_config::console_config(),
    )?);
    let login = block_on(service.login(
        LoginRequest {
            username: "root".into(),
            password: password.into(),
            second_factor: None,
        },
        "local-test-peer".into(),
    ))??
    .into_session()
    .ok()
    .context("authenticated session")?;
    let result = block_on(service.call(
        &login.token,
        Some("local-test-peer"),
        ActionCall {
            action: ACTION_PROTOCOL_DESCRIBE.into(),
            ..Default::default()
        },
    ))??;
    ensure!(result.output.is_some());
    ensure!(jobs.accepted.load(Ordering::Relaxed) >= 2);
    Ok(())
}

#[test]
fn independent_execution_uses_host_threads_without_tokio() -> anyhow::Result<()> {
    ensure!(tokio::runtime::Handle::try_current().is_err());
    let jobs = Arc::new(ThreadJobs::default());
    let tasks = Arc::new(ThreadTasks::default());
    let runtime = HostRuntime::new(Arc::new(ThreadClock), tasks.clone(), jobs.clone());
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_host_runtime(runtime)
            .build(),
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    boot.register_effect(
        "effect://jobs/echo",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            OutputModeSet::UNARY,
        )
        .finalize_allowed()],
        Arc::new(FnDriver(move |_, input: Value| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        })),
    )?;
    let password = "V7$pQ2!zN9@xL4#tM8";
    block_on(bootstrap_root_account(
        &boot,
        jobs.as_ref(),
        RootProvisioning {
            credential_sealer: Some(crate::sealer::sealer()),
            password: Some(password.into()),
            additional_grants: vec!["perform://effect/jobs/**".into()],
            ..Default::default()
        },
    ))??;
    let state = ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                xolotl_console::session_store::MemoryConsoleSessionStore::new(
                    xolotl_console::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            auth: crate::console_config::auth(),
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                capabilities: vec!["perform://effect/jobs/**".into()],
                executions: ConsoleExecutionConfig {
                    enabled: true,
                    authority_poll_ms: 50,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    let service = ConsoleService::new(state);
    let login = block_on(service.login(
        LoginRequest {
            username: "root".into(),
            password: password.into(),
            second_factor: None,
        },
        "local-test-peer".into(),
    ))??
    .into_session()
    .ok()
    .context("authenticated session")?;
    let enrollment = block_on(service.mfa(
        &login.token,
        MfaRequest::Begin {
            provider_id: "totp".into(),
            label: "Thread host test".into(),
            replace_factor_id: None,
            input: None,
        },
        "local-test-peer".into(),
    ))??;
    let MfaResponse::Enrollment {
        challenge_id,
        step: MfaEnrollmentProgress::Challenge { setup, .. },
        ..
    } = enrollment
    else {
        anyhow::bail!("TOTP enrollment challenge");
    };
    let updated = block_on(service.mfa(
        &login.token,
        MfaRequest::Continue {
            challenge_id,
            input: MfaInteractionInput::Response {
                response: serde_json::json!({"code": totp(&setup)?}),
            },
        },
        "local-test-peer".into(),
    ))??;
    let MfaResponse::Updated {
        session,
        recovery_codes: Some(recovery_codes),
    } = updated
    else {
        anyhow::bail!("TOTP enrollment completion");
    };
    let recovery_code = recovery_codes.into_iter().next().context("recovery code")?;
    let elevated = block_on(service.step_up(
        &session.token,
        StepUpRequest {
            proof: Some(MfaProof::RecoveryCode {
                code: recovery_code,
            }),
        },
        "local-test-peer".into(),
    ))??
    .into_session()
    .ok()
    .context("elevated session")?;
    ensure!(elevated.authentication.mfa_level() == 2);

    let operation = OperationTemplate {
        target: ResourceName::new(Path::parse("effect://jobs/echo")?),
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    };
    let request = |input| {
        RuntimeRequest::new(
            RuntimeCode::Operation {
                operation: operation.clone(),
            },
            Value::integer(input),
            "thread-host",
            "exercise hosted runtime",
            10_000,
        )
    };
    let attached =
        block_on(service.run_runtime(&elevated.token, Some("local-test-peer"), request(7)))??;
    ensure!(field(&attached.output.context("attached result")?, "value")? == &Value::integer(7));

    let submitted =
        block_on(service.submit_runtime(&elevated.token, Some("local-test-peer"), request(11)))??;
    let id = submitted
        .execution
        .context("accepted execution")?
        .execution_id
        .context("retained execution ID")?;
    let metadata = finished(&service, &elevated.token, &id)?;
    ensure!(field(&metadata, "outcome")?.as_str() == Some("done"));
    ensure!(field(&metadata, "cleanup_status")?.as_str() == Some("complete"));
    let result = block_on(service.call(
        &elevated.token,
        Some("local-test-peer"),
        ActionCall {
            action: ACTION_RUNTIME_EXECUTION_RESULT.into(),
            input: execution_input(&id),
            scope: Some("thread-host".into()),
            justification: Some("inspect retained result".into()),
            ttl_ms: Some(10_000),
            ..Default::default()
        },
    ))??
    .output
    .context("retained result")?;
    ensure!(field(field(&result, "output")?, "value")? == &Value::integer(11));

    let waiting = RuntimeRequest::new(
        RuntimeCode::Program(Program::new(Expression::Wait {
            wait: WaitSpec::Deadline(xolotl_kernel::host::system_now_millis() + 60_000),
        })),
        Value::null(),
        "thread-host",
        "exercise hosted cancellation",
        10_000,
    );
    let waiting_id =
        block_on(service.submit_runtime(&elevated.token, Some("local-test-peer"), waiting))??
            .execution
            .context("accepted waiting execution")?
            .execution_id
            .context("waiting execution ID")?;
    block_on(service.call(
        &elevated.token,
        Some("local-test-peer"),
        ActionCall {
            action: ACTION_RUNTIME_EXECUTION_CANCEL.into(),
            input: execution_input(&waiting_id),
            ..Default::default()
        },
    ))??;
    let cancelled = finished(&service, &elevated.token, &waiting_id)?;
    ensure!(field(&cancelled, "outcome")?.as_str() == Some("cancelled"));
    ensure!(field(&cancelled, "cleanup_status")?.as_str() == Some("complete"));
    ensure!(calls.load(Ordering::SeqCst) == 2);
    ensure!(tasks.started.load(Ordering::Relaxed) >= 1);
    ensure!(jobs.accepted.load(Ordering::Relaxed) >= 2);
    ensure!(block_on(service.shutdown_executions())?.volatile_cleanup_pending == 0);
    Ok(())
}
