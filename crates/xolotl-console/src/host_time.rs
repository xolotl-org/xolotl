//! Service deadlines belong to the installed Kernel clock domain.

use std::future::Future;
use xolotl_kernel::host::{HostDeadline, HostRuntime};
use xolotl_types::Failure;

/// Bound one cancellable wait without projecting a host deadline into Tokio time.
/// The caller decides whether dropping `work` is safe at this admission boundary.
pub(crate) async fn timeout_at<F: Future>(
    runtime: &HostRuntime,
    deadline: HostDeadline,
    work: F,
) -> Result<F::Output, Failure> {
    runtime.validate_deadline(deadline).map_err(Failure::from)?;
    if deadline.elapsed_at(runtime.now()).map_err(Failure::from)? {
        return Err(Failure::Timeout);
    }
    tokio::select! {
        biased;
        value = work => Ok(value),
        _ = runtime.sleep_until(deadline) => Err(Failure::Timeout),
    }
}

pub(crate) fn elapsed(runtime: &HostRuntime, deadline: HostDeadline) -> Result<bool, Failure> {
    deadline.elapsed_at(runtime.now()).map_err(Failure::from)
}

pub(crate) fn after(
    runtime: &HostRuntime,
    duration: std::time::Duration,
) -> Result<HostDeadline, Failure> {
    runtime.deadline_after(duration).ok_or(Failure::Timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        pin::Pin,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    use tokio::sync::Notify;
    use xolotl_kernel::host::{AbortTask, HostClock, TaskSpawnError, TaskSpawner};

    struct ManualClock {
        now: Mutex<Instant>,
        changed: Notify,
    }

    impl ManualClock {
        fn advance(&self, duration: Duration) {
            let mut now = self
                .now
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *now += duration;
            drop(now);
            self.changed.notify_waiters();
        }
    }

    impl HostClock for ManualClock {
        fn monotonic_now(&self) -> Instant {
            *self
                .now
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        fn unix_millis(&self) -> i64 {
            1_000
        }

        fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                loop {
                    let notified = self.changed.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if self.monotonic_now() >= deadline {
                        return;
                    }
                    notified.await;
                }
            })
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
    async fn service_timeout_uses_installed_clock() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock {
            now: Mutex::new(Instant::now()),
            changed: Notify::new(),
        });
        let runtime = HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
        );
        let deadline = after(&runtime, Duration::from_secs(10))?;
        let waiter = tokio::spawn(async move {
            timeout_at(&runtime, deadline, std::future::pending::<()>()).await
        });
        tokio::task::yield_now().await;
        anyhow::ensure!(!waiter.is_finished());
        clock.advance(Duration::from_secs(10));
        anyhow::ensure!(waiter.await? == Err(Failure::Timeout));
        Ok(())
    }

    #[tokio::test]
    async fn foreign_deadline_rejects_before_work_is_polled() -> anyhow::Result<()> {
        let clock = Arc::new(ManualClock {
            now: Mutex::new(Instant::now()),
            changed: Notify::new(),
        });
        let first = HostRuntime::new(
            clock.clone(),
            Arc::new(NoTasks),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
        );
        let second = HostRuntime::new(
            clock,
            Arc::new(NoTasks),
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
        );
        let deadline = after(&first, Duration::from_secs(10))?;
        let mut polled = false;
        let work = async {
            polled = true;
        };
        let result = timeout_at(&second, deadline, work).await;
        anyhow::ensure!(
            matches!(result, Err(Failure::Custom { kind, .. }) if kind == "clock_domain")
        );
        anyhow::ensure!(!polled);
        Ok(())
    }
}
