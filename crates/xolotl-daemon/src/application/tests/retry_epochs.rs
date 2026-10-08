use super::*;
use crate::application::retry_epochs::Maintenance;
use async_trait::async_trait;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::Notify;
use xolotl_gateway::{
    GatewayError, GatewayEvidenceNamespace, GatewayIdempotencyLimits, GatewayIdempotencyUsage,
    GatewayPrincipalSurfaceBinding, GatewaySession, GatewaySubmission, GatewaySurface,
    MemoryGatewayIdempotencyStore, PresentedCredential, SubmitOptions,
};
use xolotl_kernel::host::{
    AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner, TokioBlockingSpawner,
};
use xolotl_kernel::{FnDriver, KernelBuilder, MethodSpec};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{MethodAuthority, Outcome, Purity, TaintedValue};

struct Clock {
    time: watch::Sender<Instant>,
}

impl Clock {
    fn advance(&self, duration: Duration) -> Result<()> {
        let next = self
            .time
            .borrow()
            .checked_add(duration)
            .context("test clock overflow")?;
        self.time.send_replace(next);
        Ok(())
    }
}

impl HostClock for Clock {
    fn monotonic_now(&self) -> Instant {
        *self.time.borrow()
    }

    fn unix_millis(&self) -> i64 {
        10_000
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let mut time = self.time.subscribe();
            while *time.borrow_and_update() < deadline {
                if time.changed().await.is_err() {
                    return;
                }
            }
        })
    }
}

struct Tasks;
struct Aborted(tokio::task::AbortHandle);

impl AbortTask for Aborted {
    fn abort(&self) {
        self.0.abort();
    }
}

impl TaskSpawner for Tasks {
    fn spawn(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> std::result::Result<Arc<dyn AbortTask>, TaskSpawnError> {
        Ok(Arc::new(Aborted(tokio::spawn(future).abort_handle())))
    }
}

fn host() -> (HostRuntime, Arc<Clock>) {
    let (time, _) = watch::channel(Instant::now());
    let clock = Arc::new(Clock { time });
    let runtime = HostRuntime::new(
        clock.clone(),
        Arc::new(Tasks),
        Arc::new(TokioBlockingSpawner::default()),
    );
    (runtime, clock)
}

#[derive(Clone, Copy)]
enum Behavior {
    HoldClosure,
    HoldRead,
    FailClosure,
    FailRead,
}

struct ControlledStore {
    inner: Arc<dyn GatewayIdempotencyStore>,
    behavior: Behavior,
    reads: AtomicUsize,
    closes: AtomicUsize,
    release: Notify,
    after_close: std::sync::Mutex<Option<(Arc<Clock>, Instant)>>,
}

impl ControlledStore {
    fn new(behavior: Behavior) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(MemoryGatewayIdempotencyStore::default()),
            behavior,
            reads: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            release: Notify::new(),
            after_close: std::sync::Mutex::new(None),
        })
    }
}

#[async_trait]
impl GatewayIdempotencyStore for ControlledStore {
    fn evidence_namespace(&self) -> std::result::Result<GatewayEvidenceNamespace, GatewayError> {
        self.inner.evidence_namespace()
    }

    fn limits(&self) -> GatewayIdempotencyLimits {
        self.inner.limits()
    }

    async fn retry_epoch(&self) -> std::result::Result<u64, GatewayError> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        match self.behavior {
            Behavior::HoldRead => self.release.notified().await,
            Behavior::FailRead => return Err(GatewayError::Rejected("read failed".into())),
            _ => {}
        }
        self.inner.retry_epoch().await
    }

    async fn close_retry_epoch(&self, expected: u64) -> std::result::Result<u64, GatewayError> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        match self.behavior {
            Behavior::HoldClosure => self.release.notified().await,
            Behavior::FailClosure => {
                return Err(GatewayError::Indeterminate(
                    "closure outcome unknown".into(),
                ));
            }
            _ => {}
        }
        let closed = self.inner.close_retry_epoch(expected).await?;
        if let Some((clock, time)) = self
            .after_close
            .lock()
            .map_err(|_poisoned| GatewayError::Rejected("test clock lock poisoned".into()))?
            .take()
        {
            clock.time.send_replace(time);
        }
        Ok(closed)
    }

    async fn reserve(
        &self,
        key: &str,
        pending: TaintedValue,
    ) -> std::result::Result<Option<TaintedValue>, GatewayError> {
        self.inner.reserve(key, pending).await
    }

    async fn complete(
        &self,
        key: &str,
        expected: Value,
        result: TaintedValue,
    ) -> std::result::Result<(), GatewayError> {
        self.inner.complete(key, expected, result).await
    }

    async fn release(&self, key: &str, expected: Value) -> std::result::Result<(), GatewayError> {
        self.inner.release(key, expected).await
    }

    async fn observe(&self, key: &str) -> std::result::Result<Option<TaintedValue>, GatewayError> {
        self.inner.observe(key).await
    }

    async fn retire(&self, key: &str, expected: Value) -> std::result::Result<(), GatewayError> {
        self.inner.retire(key, expected).await
    }

    async fn usage(&self) -> std::result::Result<GatewayIdempotencyUsage, GatewayError> {
        self.inner.usage().await
    }
}

async fn build_gateway(
    requests: Arc<dyn GatewayIdempotencyStore>,
    runtime: HostRuntime,
    calls: Arc<AtomicUsize>,
) -> Result<(GatewayRuntime, GatewaySession)> {
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_host_runtime(runtime)
            .build(),
    ));
    let target = boot.register_effect(
        "effect://retry-tests/charge",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(FnDriver(move |_, input| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        })),
    )?;
    let profile = GatewayProfile::new("app")
        .with_bearer_identity(
            "credential",
            "alice",
            "retry-tests-token-at-least-32-bytes",
            "identity://alice",
        )?
        .with_surface(GatewaySurface::effect_invoke("charge", target))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["charge"],
            ["perform://effect/retry-tests/charge"],
        ));
    let gateway = GatewayRuntime::new_manual(boot, profile, requests)?;
    let session = gateway
        .authenticate(PresentedCredential::bearer(
            "retry-tests-token-at-least-32-bytes",
        ))
        .await?;
    Ok((gateway, session))
}

async fn quota_reuse(requests: Arc<dyn GatewayIdempotencyStore>) -> Result<()> {
    let (runtime, clock) = host();
    let calls = Arc::new(AtomicUsize::new(0));
    let namespace = requests.evidence_namespace()?;
    let (gateway, session) =
        build_gateway(requests.clone(), runtime.clone(), calls.clone()).await?;
    let scope = gateway
        .describe(&session)?
        .surfaces
        .into_iter()
        .find(|surface| surface.surface_id == "charge")
        .context("charge surface missing")?
        .request_scope;
    let submission = |epoch, key: &str| {
        GatewaySubmission::direct_input("charge", Value::integer(42)).with_options(SubmitOptions {
            retry_epoch: epoch,
            idempotency_key: Some(key.into()),
            expected_request_scope: Some(scope.clone()),
            ..Default::default()
        })
    };
    let original = submission(0, "first");
    ensure!(
        gateway
            .submit(&session, original.clone())
            .await?
            .output
            .outcome
            == Outcome::Done(Value::integer(42))
    );
    ensure!(
        gateway
            .submit(&session, submission(0, "capacity"))
            .await
            .is_err()
    );
    ensure!(calls.load(Ordering::SeqCst) == 1);
    let maintenance =
        Maintenance::new(runtime, Duration::from_millis(100), Duration::from_secs(1))?;
    let task = tokio::spawn(maintenance.run(requests.clone()));
    clock.advance(Duration::from_millis(99))?;
    tokio::task::yield_now().await;
    ensure!(requests.retry_epoch().await? == 0);
    clock.advance(Duration::from_millis(901))?;
    tokio::time::timeout(Duration::from_secs(2), async {
        while requests.retry_epoch().await? != 1 {
            tokio::task::yield_now().await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    ensure!(requests.usage().await?.records == 0);
    ensure!(requests.evidence_namespace()? == namespace);
    ensure!(gateway.submit(&session, original).await.is_err());
    ensure!(
        gateway
            .submit(&session, submission(1, "second"))
            .await?
            .output
            .outcome
            == Outcome::Done(Value::integer(42))
    );
    ensure!(calls.load(Ordering::SeqCst) == 2);
    task.abort();
    ensure!(task.await.is_err_and(|error| error.is_cancelled()));
    Ok(())
}

#[tokio::test]
async fn real_keyed_requests_reuse_memory_and_redb_capacity_and_reopen_exact_barrier() -> Result<()>
{
    let limits = GatewayIdempotencyLimits {
        max_records: NonZeroUsize::MIN,
        ..Default::default()
    };
    quota_reuse(Arc::new(MemoryGatewayIdempotencyStore::new(limits)?)).await?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("retry-epochs.redb");
    let namespace = {
        let db = RedbStore::open(&path)?;
        let requests = Arc::new(db.gateway_idempotency_store(limits)?);
        let namespace = requests.evidence_namespace()?;
        quota_reuse(requests).await?;
        namespace
    };
    let db = RedbStore::open(&path)?;
    let requests = db.gateway_idempotency_store(limits)?;
    ensure!(requests.retry_epoch().await? == 1);
    ensure!(requests.evidence_namespace()? == namespace);
    ensure!(requests.usage().await?.records == 1);
    Ok(())
}

#[tokio::test]
async fn delayed_wake_closes_once_and_next_deadline_starts_after_completion() -> Result<()> {
    let (runtime, clock) = host();
    let requests = ControlledStore::new(Behavior::HoldClosure);
    ensure!(requests.inner.close_retry_epoch(0).await? == 1);
    let maintenance =
        Maintenance::new(runtime, Duration::from_millis(100), Duration::from_secs(10))?;
    let task = tokio::spawn(maintenance.run(requests.clone()));
    clock.advance(Duration::from_secs(1))?;
    until(|| requests.closes.load(Ordering::SeqCst) == 1).await?;
    clock.advance(Duration::from_millis(500))?;
    requests.release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), async {
        while requests.inner.retry_epoch().await? != 2 {
            tokio::task::yield_now().await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    clock.advance(Duration::from_millis(99))?;
    tokio::task::yield_now().await;
    ensure!(requests.closes.load(Ordering::SeqCst) == 1);
    clock.advance(Duration::from_millis(1))?;
    until(|| requests.closes.load(Ordering::SeqCst) == 2).await?;
    task.abort();
    ensure!(task.await.is_err_and(|error| error.is_cancelled()));
    ensure!(requests.inner.retry_epoch().await? == 2);
    Ok(())
}

async fn application_with_store(
    requests: Arc<ControlledStore>,
) -> Result<(ApplicationGateway, Arc<Bootstrap>, Arc<Clock>)> {
    let (runtime, clock) = host();
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_host_runtime(runtime)
            .build(),
    ));
    boot.kernel()
        .state()
        .write_set(&profile::profile_path("app")?, value(1)?)
        .await?;
    let mut config = config();
    config.application_gateway.request_storage.retry_epoch_ms = 100;
    config.application_gateway.grpc.storage_timeout_ms = 1000;
    let application = ApplicationGateway::start_at(
        &config,
        Some("127.0.0.1:0"),
        boot.clone(),
        ObjectStore::new(),
        requests,
    )
    .await?
    .context("application did not start")?;
    ensure!(application.tasks.len() == 2);
    Ok((application, boot, clock))
}

#[tokio::test]
async fn profile_reload_and_watch_loss_progress_during_stalled_closure() -> Result<()> {
    let (host, clock) = host();
    let requests = ControlledStore::new(Behavior::HoldClosure);
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_host_runtime(host.clone())
            .build(),
    ));
    let state = boot.kernel().state().clone();
    let path = profile::profile_path("app")?;
    state.write_set(&path, value(1)?).await?;
    let events = state.subscribe(&path).await?;
    let runtime = Arc::new(GatewayRuntime::new(
        boot,
        profile::load_profile(&state, &path, "app").await?,
        requests.clone(),
    )?);
    let service = ApplicationGrpcService::from_arc_with_config(
        runtime.clone(),
        ApplicationGrpcConfig::default(),
    )?;
    let (shutdown, _) = watch::channel(false);
    let watching = profile::watch_profile(
        state.clone(),
        path.clone(),
        "app".into(),
        events,
        runtime.clone(),
        service.clone(),
        shutdown.clone(),
    );
    let maintenance = Maintenance::new(
        host.clone(),
        Duration::from_millis(100),
        Duration::from_secs(10),
    )?;
    let task = tokio::spawn(crate::application::retry_epochs::supervise(
        watching,
        maintenance.run(requests.clone()),
        service.clone(),
        shutdown.clone(),
    ));
    clock.advance(Duration::from_millis(100))?;
    until(|| requests.closes.load(Ordering::SeqCst) == 1).await?;
    state.write_set(&path, value(2)?).await?;
    until(|| runtime.profile_rev() == 2).await?;
    state.write_delete(&path).await?;
    tokio::time::timeout(Duration::from_secs(2), task).await???;
    ensure!(*shutdown.borrow());
    ensure!(requests.inner.retry_epoch().await? == 0);
    let delivered = Arc::new(AtomicUsize::new(0));
    let events = StateStream::new(ScriptedEvents {
        events: [Err(StateWatchError::Lagged(1))].into(),
        delivered: delivered.clone(),
    });
    let (shutdown, _) = watch::channel(false);
    let watching = profile::watch_profile(
        state,
        path,
        "app".into(),
        events,
        runtime,
        service.clone(),
        shutdown.clone(),
    );
    let maintenance = Maintenance::new(host, Duration::from_millis(100), Duration::from_secs(10))?;
    let error = crate::application::retry_epochs::supervise(
        watching,
        maintenance.run(requests.clone()),
        service,
        shutdown.clone(),
    )
    .await
    .err()
    .context("watch loss must fail the supervisor")?;
    ensure!(error.to_string().contains("profile watch lost"));
    ensure!(*shutdown.borrow());
    ensure!(delivered.load(Ordering::SeqCst) == 1);
    ensure!(requests.closes.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn profile_delete_stops_listener_and_stalled_closure() -> Result<()> {
    let requests = ControlledStore::new(Behavior::HoldClosure);
    let (mut application, boot, clock) = application_with_store(requests.clone()).await?;
    clock.advance(Duration::from_millis(100))?;
    until(|| requests.closes.load(Ordering::SeqCst) == 1).await?;
    let path = profile::profile_path("app")?;
    boot.kernel().state().write_delete(&path).await?;
    until(|| application.tasks.iter().all(JoinHandle::is_finished)).await?;
    ensure!(*application.shutdown.borrow());
    ensure!(requests.inner.retry_epoch().await? == 0);
    clock.advance(Duration::from_secs(5))?;
    ensure!(requests.closes.load(Ordering::SeqCst) == 1);
    ensure!(
        tokio::net::TcpStream::connect(application.listen_address)
            .await
            .is_err()
    );
    application.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn native_invalid_cadence_rejects_startup_before_listener_tasks() -> Result<()> {
    for milliseconds in [0, 86_400_001, u64::MAX] {
        let boot = Arc::new(Bootstrap::in_memory());
        boot.kernel()
            .state()
            .write_set(&profile::profile_path("app")?, value(1)?)
            .await?;
        let requests = ControlledStore::new(Behavior::HoldClosure);
        let mut config = config();
        config.application_gateway.request_storage.retry_epoch_ms = milliseconds;
        let error = ApplicationGateway::start_at(
            &config,
            Some("127.0.0.1:0"),
            boot,
            ObjectStore::new(),
            requests.clone(),
        )
        .await
        .err()
        .context("native invalid retry cadence started a listener")?;
        ensure!(error.to_string().contains("retry_epoch_ms"));
        ensure!(requests.reads.load(Ordering::SeqCst) == 0);
        ensure!(requests.closes.load(Ordering::SeqCst) == 0);
    }
    Ok(())
}

#[tokio::test]
async fn store_failure_and_timeout_stop_service_listener_without_retry() -> Result<()> {
    for behavior in [
        Behavior::FailRead,
        Behavior::FailClosure,
        Behavior::HoldRead,
        Behavior::HoldClosure,
    ] {
        let requests = ControlledStore::new(behavior);
        let (mut application, _, clock) = application_with_store(requests.clone()).await?;
        clock.advance(Duration::from_millis(100))?;
        match behavior {
            Behavior::HoldRead => {
                until(|| requests.reads.load(Ordering::SeqCst) == 1).await?;
                clock.advance(Duration::from_secs(1))?;
            }
            Behavior::HoldClosure => {
                until(|| requests.closes.load(Ordering::SeqCst) == 1).await?;
                clock.advance(Duration::from_secs(1))?;
            }
            _ => {}
        }
        until(|| application.tasks.iter().all(JoinHandle::is_finished)).await?;
        ensure!(*application.shutdown.borrow());
        let failure =
            std::future::poll_fn(|context| Poll::Ready(application.poll_failure(context))).await;
        ensure!(
            matches!(failure, Poll::Ready(error) if format!("{error:#}").contains("application retry epoch"))
        );
        ensure!(requests.inner.retry_epoch().await? == 0);
        ensure!(requests.reads.load(Ordering::SeqCst) == 1);
        ensure!(requests.closes.load(Ordering::SeqCst) <= 1);
        ensure!(
            tokio::net::TcpStream::connect(application.listen_address)
                .await
                .is_err()
        );
        application.shutdown().await;
    }
    Ok(())
}

#[tokio::test]
async fn schedule_overflow_distinguishes_initial_rejection_from_committed_closure() -> Result<()> {
    let (runtime, clock) = host();
    ensure!(Maintenance::new(runtime.clone(), Duration::MAX, Duration::from_secs(1)).is_err());
    let requests = ControlledStore::new(Behavior::HoldClosure);
    let maintenance = Maintenance::new(runtime, Duration::from_secs(1), Duration::from_secs(10))?;
    let task = tokio::spawn(maintenance.run(requests.clone()));
    clock.advance(Duration::from_secs(1))?;
    until(|| requests.closes.load(Ordering::SeqCst) == 1).await?;
    let origin = clock.monotonic_now();
    let mut lower = 0_u64;
    let mut upper = u64::MAX;
    while lower < upper {
        let middle = lower + (upper - lower).div_ceil(2);
        if origin.checked_add(Duration::from_secs(middle)).is_some() {
            lower = middle;
        } else {
            upper = middle - 1;
        }
    }
    *requests
        .after_close
        .lock()
        .map_err(|_poisoned| anyhow::anyhow!("test clock lock poisoned"))? = Some((
        clock,
        origin
            .checked_add(Duration::from_secs(lower))
            .context("maximal instant missing")?,
    ));
    requests.release.notify_one();
    let error = tokio::time::timeout(Duration::from_secs(2), task)
        .await??
        .err()
        .context("schedule overflow missing")?;
    ensure!(error.to_string().contains("closed to 1"));
    ensure!(requests.inner.retry_epoch().await? == 1);
    ensure!(requests.closes.load(Ordering::SeqCst) == 1);
    Ok(())
}
