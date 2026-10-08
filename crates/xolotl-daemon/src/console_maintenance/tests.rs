use super::*;
use anyhow::ensure;
use std::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering},
    time::Instant,
};
use tokio::sync::{Notify, Semaphore};
use xolotl_console::{
    ConsoleAuthConfig, ConsoleConfig, ConsoleRuntimeConfig, ConsoleState, CredentialSealer,
    session_store::{
        ConsoleSession, ConsoleSessionPolicy, MemoryConsoleSessionStore, SessionPageLimits,
        SessionStoreError, SessionStorePage,
    },
};
use xolotl_kernel::{
    Bootstrap, KernelBuilder,
    host::{AbortTask, HostClock, TaskSpawnError, TaskSpawner, TokioBlockingSpawner},
};

struct ManualClock {
    origin: Instant,
    elapsed_ms: AtomicU64,
    wall_ms: AtomicI64,
}

impl ManualClock {
    fn advance(&self, milliseconds: u64) {
        self.elapsed_ms.fetch_add(milliseconds, Ordering::SeqCst);
    }
}

impl HostClock for ManualClock {
    fn monotonic_now(&self) -> Instant {
        self.origin + Duration::from_millis(self.elapsed_ms.load(Ordering::SeqCst))
    }

    fn unix_millis(&self) -> i64 {
        self.wall_ms.load(Ordering::SeqCst)
    }

    fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

struct NoTasks;

impl TaskSpawner for NoTasks {
    fn spawn(
        &self,
        _future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> std::result::Result<Arc<dyn AbortTask>, TaskSpawnError> {
        Err(TaskSpawnError::Unavailable)
    }
}

fn runtime() -> (HostRuntime, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock {
        origin: Instant::now(),
        elapsed_ms: AtomicU64::new(0),
        wall_ms: AtomicI64::new(10_000),
    });
    (
        HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(TokioBlockingSpawner::default()),
        ),
        clock,
    )
}

#[test]
fn not_due_then_equal_due_ignores_backward_wall_clock() -> Result<()> {
    let (runtime, clock) = runtime();
    let mut schedule = RetryEpochSchedule::new(&runtime, Duration::from_millis(100), true)?;
    let mut rotations = 0;
    clock.advance(99);
    schedule.tick(&runtime, || {
        rotations += 1;
        Ok(())
    })?;
    ensure!(rotations == 0, "not-due tick rotated");
    clock.wall_ms.store(-10_000, Ordering::SeqCst);
    clock.advance(1);
    schedule.tick(&runtime, || {
        rotations += 1;
        Ok(())
    })?;
    ensure!(rotations == 1, "equal deadline did not rotate exactly once");
    Ok(())
}

#[test]
fn delayed_tick_rotates_once_and_anchors_from_due_tick() -> Result<()> {
    let (runtime, clock) = runtime();
    let mut schedule = RetryEpochSchedule::new(&runtime, Duration::from_millis(100), true)?;
    clock.advance(1_000);
    let mut rotations = 0;
    schedule.tick(&runtime, || {
        rotations += 1;
        clock.advance(20);
        Ok(())
    })?;
    clock.advance(79);
    schedule.tick(&runtime, || {
        rotations += 1;
        Ok(())
    })?;
    ensure!(rotations == 1, "delayed tick caused catch-up rotations");
    clock.advance(1);
    schedule.tick(&runtime, || {
        rotations += 1;
        Ok(())
    })?;
    ensure!(
        rotations == 2,
        "next deadline is not anchored from due tick"
    );
    Ok(())
}

#[test]
fn disabled_schedule_never_rotates_or_constructs_deadlines() -> Result<()> {
    let (runtime, clock) = runtime();
    let mut schedule = RetryEpochSchedule::new(&runtime, Duration::MAX, false)?;
    clock.advance(1_000_000);
    schedule.tick(&runtime, || anyhow::bail!("disabled rotation invoked"))?;
    ensure!(
        schedule.deadline.is_none(),
        "disabled schedule has a deadline"
    );
    Ok(())
}

#[test]
fn rotation_and_deadline_errors_are_not_hidden() -> Result<()> {
    let (runtime, clock) = runtime();
    ensure!(
        RetryEpochSchedule::new(&runtime, Duration::MAX, true).is_err(),
        "unrepresentable initial deadline accepted"
    );
    let mut schedule = RetryEpochSchedule::new(&runtime, Duration::from_millis(100), true)?;
    let deadline = schedule.deadline;
    clock.advance(100);
    let error = schedule
        .tick(&runtime, || anyhow::bail!("retry epoch exhausted"))
        .err()
        .context("rotation error missing")?;
    ensure!(
        error.to_string() == "retry epoch exhausted",
        "rotation error changed"
    );
    ensure!(
        schedule.deadline == deadline,
        "failed rotation advanced deadline"
    );
    schedule.period = Duration::MAX;
    let mut rotations = 0;
    ensure!(
        schedule
            .tick(&runtime, || {
                rotations += 1;
                Ok(())
            })
            .is_err(),
        "unrepresentable next deadline accepted"
    );
    ensure!(rotations == 0, "deadline failure committed rotation");
    ensure!(
        schedule.deadline == deadline,
        "deadline failure advanced schedule"
    );
    Ok(())
}

#[test]
fn mismatched_clock_rejects_before_rotation() -> Result<()> {
    let (first_runtime, _) = runtime();
    let (second_runtime, _) = runtime();
    let mut schedule = RetryEpochSchedule::new(&first_runtime, Duration::from_millis(100), true)?;
    let mut rotations = 0;
    ensure!(
        schedule
            .tick(&second_runtime, || {
                rotations += 1;
                Ok(())
            })
            .is_err(),
        "mismatched clock accepted"
    );
    ensure!(rotations == 0, "mismatched clock rotated");
    Ok(())
}

struct SlowSessions {
    inner: MemoryConsoleSessionStore,
    passes: AtomicUsize,
    entered: Notify,
    release: Semaphore,
}

#[async_trait::async_trait]
impl ConsoleSessionStore for SlowSessions {
    fn policy(&self) -> ConsoleSessionPolicy {
        self.inner.policy()
    }

    async fn get(&self, sid: &str) -> Result<Option<ConsoleSession>, SessionStoreError> {
        self.inner.get(sid).await
    }

    async fn create(&self, session: ConsoleSession) -> Result<(), SessionStoreError> {
        self.inner.create(session).await
    }

    async fn compare_replace(
        &self,
        expected: ConsoleSession,
        session: ConsoleSession,
    ) -> Result<(), SessionStoreError> {
        self.inner.compare_replace(expected, session).await
    }

    async fn delete(
        &self,
        sid: &str,
        expected: Option<ConsoleSession>,
    ) -> Result<(), SessionStoreError> {
        self.inner.delete(sid, expected).await
    }

    async fn list(
        &self,
        after: Option<&str>,
        limits: SessionPageLimits,
    ) -> Result<SessionStorePage, SessionStoreError> {
        self.inner.list(after, limits).await
    }

    async fn revoke_account(
        &self,
        authority: &str,
        account: &str,
    ) -> Result<usize, SessionStoreError> {
        self.inner.revoke_account(authority, account).await
    }

    async fn maintain(&self, now: i64) -> Result<usize, SessionStoreError> {
        self.passes.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        self.release
            .acquire()
            .await
            .map_err(|error| SessionStoreError::Storage(error.to_string()))?
            .forget();
        self.inner.maintain(now).await
    }
}

fn service(runtime: HostRuntime, sessions: Arc<dyn ConsoleSessionStore>) -> Result<ConsoleService> {
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_host_runtime(runtime)
            .build(),
    ));
    let mut config = ConsoleConfig {
        session_store: Some(sessions),
        auth: ConsoleAuthConfig {
            credential_sealer: Some(Arc::new(CredentialSealer::new("test", &[17; 32])?)),
            ..Default::default()
        },
        runtime: ConsoleRuntimeConfig::default(),
        ..Default::default()
    };
    config.runtime.enabled = true;
    config.runtime.executions.enabled = true;
    Ok(ConsoleService::new(ConsoleState::with_config(
        boot, config,
    )?))
}

#[tokio::test]
async fn deadline_failure_reaches_required_task_supervisor_without_rotation() -> Result<()> {
    let (runtime, _) = runtime();
    let sessions = Arc::new(MemoryConsoleSessionStore::new(
        ConsoleSessionPolicy::default(),
    ));
    let service = service(runtime.clone(), sessions.clone())?;
    let scope = service.submission_retry_scope();
    let mut services = crate::host_lifecycle::HostedServices::default();
    services.background.serve(
        "Console maintenance test",
        start(service.clone(), sessions, runtime, Duration::MAX, true),
    );
    let error = services
        .wait_for_shutdown(std::future::pending())
        .await
        .err()
        .context("required task failure missing")?;
    ensure!(
        error.to_string().contains("Console maintenance test"),
        "supervisor lost task name"
    );
    ensure!(
        format!("{error:#}").contains("Console retry epoch deadline overflow"),
        "supervisor lost deadline error"
    );
    ensure!(
        service.submission_retry_scope() == scope,
        "deadline failure rotated service"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn real_service_rotates_before_slow_session_pass_and_shutdown_cancels_task() -> Result<()> {
    let (runtime, clock) = runtime();
    let sessions = Arc::new(SlowSessions {
        inner: MemoryConsoleSessionStore::new(ConsoleSessionPolicy::default()),
        passes: AtomicUsize::new(0),
        entered: Notify::new(),
        release: Semaphore::new(0),
    });
    let service = service(runtime.clone(), sessions.clone())?;
    let (instance, epoch) = service.submission_retry_scope();
    let mut tasks = crate::host_lifecycle::BackgroundTasks::default();
    tasks.serve(
        "Console maintenance test",
        start(
            service.clone(),
            sessions.clone(),
            runtime,
            Duration::from_secs(1),
            true,
        ),
    );
    sessions.entered.notified().await;
    clock.advance(5_000);
    tokio::time::advance(Duration::from_secs(5)).await;
    ensure!(
        service.submission_retry_scope() == (instance.clone(), epoch),
        "rotated during blocked session pass"
    );
    sessions.release.add_permits(1);
    sessions.entered.notified().await;
    ensure!(
        service.submission_retry_scope() == (instance.clone(), epoch + 1),
        "due rotation did not precede blocked session pass"
    );
    ensure!(
        sessions.passes.load(Ordering::SeqCst) == 2,
        "missed ticks accumulated session passes"
    );
    sessions.release.add_permits(1);
    tokio::task::yield_now().await;
    ensure!(
        sessions.passes.load(Ordering::SeqCst) == 2,
        "interval did not skip missed ticks"
    );
    clock.advance(1_000);
    tokio::time::advance(Duration::from_secs(1)).await;
    sessions.entered.notified().await;
    ensure!(
        service.submission_retry_scope() == (instance, epoch + 2),
        "following tick did not rotate once"
    );
    let report = tasks.shutdown().await;
    ensure!(
        report.cancelled == 1,
        "supervisor did not cancel maintenance"
    );
    ensure!(report.failed == 0, "maintenance failed during shutdown");
    clock.advance(10_000);
    tokio::time::advance(Duration::from_secs(10)).await;
    ensure!(
        sessions.passes.load(Ordering::SeqCst) == 3,
        "maintenance continued after shutdown"
    );
    Ok(())
}
