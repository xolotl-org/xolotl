//! The hosted Kernel's task and clock boundary.

use super::blocking::dispatch;
use super::{BlockingSpawnError, BlockingSpawner, BlockingTask, TokioBlockingSpawner};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// An absolute monotonic deadline obtained from the installed host clock.
/// It is local to the running host and is never persisted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostDeadline {
    instant: Instant,
    domain: u64,
}

/// A deadline was produced by a different hosted clock. Monotonic instants
/// have meaning only within the runtime that produced them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("host deadline belongs to a different clock domain")]
pub struct ClockDomainError;

impl From<ClockDomainError> for xolotl_types::Failure {
    fn from(error: ClockDomainError) -> Self {
        Self::Custom {
            kind: "clock_domain".into(),
            message: error.to_string(),
        }
    }
}

impl HostDeadline {
    /// Extend a deadline without changing its clock domain.
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.instant
            .checked_add(duration)
            .map(|instant| Self { instant, ..self })
    }

    /// Remaining time measured against another value from the same clock.
    pub fn saturating_duration_since(self, earlier: Self) -> Result<Duration, ClockDomainError> {
        self.same_domain(earlier)?;
        Ok(self.instant.saturating_duration_since(earlier.instant))
    }

    /// Select the earlier deadline within one clock domain.
    pub fn earliest(self, other: Self) -> Result<Self, ClockDomainError> {
        self.same_domain(other)?;
        Ok(if self.instant <= other.instant {
            self
        } else {
            other
        })
    }

    /// Whether this deadline has passed according to a clock in its domain.
    pub fn elapsed_at(self, now: Self) -> Result<bool, ClockDomainError> {
        self.same_domain(now)?;
        Ok(self.instant <= now.instant)
    }

    fn same_domain(self, other: Self) -> Result<(), ClockDomainError> {
        if self.domain == other.domain {
            Ok(())
        } else {
            Err(ClockDomainError)
        }
    }
}

/// A clock used for transient deadlines and retained wall-clock ceilings.
/// A host must derive monotonic values from one consistent domain for the life
/// of a Kernel. Dropping a sleep future must cancel only that wait.
pub trait HostClock: Send + Sync + 'static {
    /// Current monotonic time, including the host's simulated time in tests.
    fn monotonic_now(&self) -> Instant;

    /// Current Unix time in milliseconds for persisted deadlines and Facts.
    fn unix_millis(&self) -> i64;

    /// Wait until an instant produced by this clock.
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// An abortable task. Dropping this handle must detach, not cancel, the task.
pub trait AbortTask: Send + Sync + 'static {
    /// Request cancellation. The task's future must eventually be dropped so
    /// its Kernel-owned exit guard can acknowledge release of all captures.
    fn abort(&self);
}

/// Failure to schedule an owned task.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TaskSpawnError {
    /// No runnable scheduler is available.
    #[error("host task scheduler is unavailable")]
    Unavailable,
}

/// Starts owned Kernel tasks. Successful scheduling must keep the future alive
/// independently of the returned abort handle; dropping the handle detaches it.
pub trait TaskSpawner: Send + Sync + 'static {
    /// Schedule a task, or return the future to the caller through normal Drop
    /// before returning an error. No task may run after an error is reported.
    fn spawn(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError>;
}

/// One clock, asynchronous task scheduler and blocking-work admission domain
/// selected during Kernel assembly.
#[derive(Clone)]
pub struct HostRuntime {
    clock: Arc<dyn HostClock>,
    tasks: Arc<dyn TaskSpawner>,
    blocking: Arc<dyn BlockingSpawner>,
    tokio_tasks: Option<Arc<TokioTasks>>,
    domain: u64,
}

static NEXT_CLOCK_DOMAIN: AtomicU64 = AtomicU64::new(1);

/// Read the operating system's Unix wall clock in milliseconds.
///
/// This is for system-backed host adapters that have no installed [`HostRuntime`].
/// Execution admission, authorization and observation timestamps must read the
/// runtime selected for their Kernel instead.
pub fn system_now_millis() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(error) => i64::try_from(error.duration().as_millis())
            .unwrap_or(i64::MAX)
            .saturating_neg(),
    }
}

impl HostRuntime {
    /// Compose a custom hosted runtime. Its clock must remain stable while any
    /// process, execution or pending cleanup belongs to this Kernel.
    pub fn new(
        clock: Arc<dyn HostClock>,
        tasks: Arc<dyn TaskSpawner>,
        blocking: Arc<dyn BlockingSpawner>,
    ) -> Self {
        // Exhaustion must not wrap and make unrelated instants comparable.
        let domain =
            match NEXT_CLOCK_DOMAIN.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            }) {
                Ok(domain) => domain,
                Err(_) => std::process::abort(),
            };
        Self {
            clock,
            tasks,
            blocking,
            tokio_tasks: None,
            domain,
        }
    }

    /// The existing Tokio host mechanism, selected by default.
    pub fn tokio() -> Self {
        Self::tokio_with_blocking(Arc::new(TokioBlockingSpawner::default()))
    }

    /// Use Tokio's clock and task scheduler with a caller-owned blocking port.
    /// The task scheduler binds to the first Tokio runtime observed at assembly
    /// or dispatch; keep that runtime alive while this host runs. Retain the
    /// blocking port to drain accepted work after stopping all producers.
    pub fn tokio_with_blocking(blocking: Arc<dyn BlockingSpawner>) -> Self {
        let tasks = Arc::new(TokioTasks::default());
        tasks.bind_current();
        let mut runtime = Self::new(Arc::new(TokioClock), tasks.clone(), blocking);
        runtime.tokio_tasks = Some(tasks);
        runtime
    }

    /// Read the current monotonic clock.
    pub fn now(&self) -> HostDeadline {
        HostDeadline {
            instant: self.clock.monotonic_now(),
            domain: self.domain,
        }
    }

    /// Read the current wall clock for data and audit timestamps.
    pub fn now_millis(&self) -> i64 {
        self.clock.unix_millis()
    }

    /// Construct a deadline in this runtime's monotonic clock domain.
    pub fn deadline_after(&self, duration: Duration) -> Option<HostDeadline> {
        self.now().checked_add(duration)
    }

    /// Sleep until a deadline from this runtime's monotonic clock domain.
    pub async fn sleep_until(&self, deadline: HostDeadline) -> Result<(), ClockDomainError> {
        self.validate_deadline(deadline)?;
        self.clock.sleep_until(deadline.instant).await;
        Ok(())
    }

    /// Check a deadline before handing it to an execution or child admission.
    pub fn validate_deadline(&self, deadline: HostDeadline) -> Result<(), ClockDomainError> {
        if deadline.domain == self.domain {
            Ok(())
        } else {
            Err(ClockDomainError)
        }
    }

    /// Whether two runtime views share one monotonic clock domain.
    pub fn shares_clock_with(&self, other: &Self) -> bool {
        self.domain == other.domain
    }

    /// Schedule an owned task. A synchronous failure drops its future.
    pub fn spawn(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
        self.tasks.spawn(future)
    }

    /// Dispatch owned synchronous work through the installed blocking port.
    /// Once admitted, dropping the returned waiter does not cancel the job.
    pub fn dispatch_blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<BlockingTask<T>, BlockingSpawnError> {
        // The accepted job may run on a plain host thread. Capture the Tokio
        // scheduler at the handoff so it can start owned tasks from there.
        if let Some(tasks) = &self.tokio_tasks {
            tasks.bind_current();
        }
        dispatch(self.blocking.as_ref(), work)
    }

    /// Share this runtime's blocking admission domain with a storage adapter.
    pub fn blocking_spawner(&self) -> Arc<dyn BlockingSpawner> {
        Arc::clone(&self.blocking)
    }
}

impl Default for HostRuntime {
    fn default() -> Self {
        Self::tokio()
    }
}

struct TokioClock;

impl HostClock for TokioClock {
    fn monotonic_now(&self) -> Instant {
        tokio::time::Instant::now().into_std()
    }

    fn unix_millis(&self) -> i64 {
        system_now_millis()
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline,
        )))
    }
}

#[derive(Default)]
struct TokioTasks {
    runtime: OnceLock<tokio::runtime::Handle>,
}

impl TokioTasks {
    fn bind_current(&self) {
        if self.runtime.get().is_none()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            drop(self.runtime.set(runtime));
        }
    }
}

struct TokioAbort(tokio::task::AbortHandle);

impl AbortTask for TokioAbort {
    fn abort(&self) {
        self.0.abort();
    }
}

impl TaskSpawner for TokioTasks {
    fn spawn(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
        self.bind_current();
        let runtime = self.runtime.get().ok_or(TaskSpawnError::Unavailable)?;
        let task = runtime.spawn(future);
        Ok(Arc::new(TokioAbort(task.abort_handle())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct PlainThreads;

    impl BlockingSpawner for PlainThreads {
        fn spawn(&self, job: super::super::BlockingJob) -> Result<(), BlockingSpawnError> {
            std::thread::spawn(job);
            Ok(())
        }
    }

    struct ManualClock {
        instant: Instant,
        sleeps: AtomicUsize,
    }

    impl HostClock for ManualClock {
        fn monotonic_now(&self) -> Instant {
            self.instant
        }

        fn unix_millis(&self) -> i64 {
            0
        }

        fn sleep_until(&self, _deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.sleeps.fetch_add(1, Ordering::Relaxed);
            Box::pin(async {})
        }
    }

    struct NoTasks;

    impl TaskSpawner for NoTasks {
        fn spawn(
            &self,
            _future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            Err(TaskSpawnError::Unavailable)
        }
    }

    #[tokio::test]
    async fn deadlines_are_bound_to_the_runtime_that_created_them() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock {
            instant: Instant::now(),
            sleeps: AtomicUsize::new(0),
        });
        let tasks = Arc::new(NoTasks);
        let first = HostRuntime::new(
            clock.clone(),
            tasks.clone(),
            Arc::new(TokioBlockingSpawner::default()),
        );
        let same_clock_new_runtime = HostRuntime::new(
            clock.clone(),
            tasks,
            Arc::new(TokioBlockingSpawner::default()),
        );
        let same_domain = first.clone();
        let deadline = first
            .deadline_after(Duration::from_secs(5))
            .ok_or_else(|| anyhow::anyhow!("deadline out of range"))?;
        anyhow::ensure!(same_domain.validate_deadline(deadline) == Ok(()));
        anyhow::ensure!(same_domain.sleep_until(deadline).await == Ok(()));
        anyhow::ensure!(clock.sleeps.load(Ordering::Relaxed) == 1);

        let foreign_now = same_clock_new_runtime.now();
        anyhow::ensure!(
            same_clock_new_runtime.validate_deadline(deadline) == Err(ClockDomainError)
        );
        anyhow::ensure!(deadline.earliest(foreign_now) == Err(ClockDomainError));
        anyhow::ensure!(deadline.elapsed_at(foreign_now) == Err(ClockDomainError));
        anyhow::ensure!(deadline.saturating_duration_since(foreign_now) == Err(ClockDomainError));
        anyhow::ensure!(
            same_clock_new_runtime.sleep_until(deadline).await == Err(ClockDomainError)
        );
        anyhow::ensure!(clock.sleeps.load(Ordering::Relaxed) == 1);
        Ok(())
    }

    #[tokio::test]
    async fn tokio_tasks_start_from_a_plain_blocking_worker_after_dispatch() -> anyhow::Result<()> {
        // Runtime assembly can precede entering Tokio. The first handoff from
        // Tokio binds its scheduler for an accepted worker on a plain thread.
        let runtime =
            std::thread::spawn(|| HostRuntime::tokio_with_blocking(Arc::new(PlainThreads)))
                .join()
                .map_err(|_panic| anyhow::anyhow!("runtime assembly panicked"))?;
        let outside = runtime.clone();
        std::thread::spawn(move || {
            anyhow::ensure!(matches!(
                outside.spawn(Box::pin(async {})),
                Err(TaskSpawnError::Unavailable)
            ));
            Ok::<_, anyhow::Error>(())
        })
        .join()
        .map_err(|_panic| anyhow::anyhow!("plain-thread check panicked"))??;

        let (finished, observed) = tokio::sync::oneshot::channel();
        let worker_runtime = runtime.clone();
        let job = runtime.dispatch_blocking(move || {
            let plain_thread = tokio::runtime::Handle::try_current().is_err();
            let task = worker_runtime.spawn(Box::pin(async move {
                let _delivery = finished.send(());
            }));
            (plain_thread, task.map(|_| ()))
        })?;
        let (plain_thread, spawned) = job.await?;
        anyhow::ensure!(plain_thread);
        spawned?;
        tokio::time::timeout(Duration::from_secs(2), observed).await??;
        Ok(())
    }
}
