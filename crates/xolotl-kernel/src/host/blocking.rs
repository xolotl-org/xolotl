//! Host-selected execution for owned synchronous work.
//!
//! Callers retain their own operation-specific capacity limits. The spawner
//! provides a shared admission boundary and moves accepted work off the async
//! worker. An accepted job owns its captures independently of its awaiter.

use std::any::Any;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

/// Maximum concurrent jobs admitted by a default Tokio blocking spawner.
pub const DEFAULT_MAX_BLOCKING_JOBS: usize = 64;

/// A synchronous job moved to the host's blocking executor.
pub type BlockingJob = Box<dyn FnOnce() + Send + 'static>;

/// The configured blocking-work capacity cannot be represented by Tokio.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("blocking-work capacity must be between 1 and Tokio's maximum permit count")]
pub struct BlockingCapacityError;

/// A blocking job was rejected before execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BlockingSpawnError {
    /// The shared blocking-work budget is full; no job was queued.
    #[error("host blocking-work capacity exceeded")]
    AtCapacity,
    /// The host has no runnable blocking executor.
    #[error("host blocking-work executor is unavailable")]
    Unavailable,
}

/// Schedules bounded synchronous work away from async workers.
///
/// `spawn` must return promptly. On success, it owns the job independently of
/// the caller's future; dropping an awaiter must not cancel a running job. On
/// error, it must not have run or retained the job and must drop its captures.
/// A host must drain accepted jobs before graceful shutdown when their effects
/// need to be durable. Queue and worker limits are the host's responsibility.
pub trait BlockingSpawner: Send + Sync + 'static {
    /// Admit exactly one job or reject it without running it.
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError>;
}

/// An accepted blocking worker ended without a usable result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum BlockingTaskError {
    /// The synchronous closure panicked after it started.
    #[error("blocking worker panicked")]
    Panicked,
    /// The host dropped the accepted job before it delivered a result.
    #[error("blocking worker was cancelled")]
    Cancelled,
}

/// A result waiter that does not own or cancel the accepted blocking work.
pub struct BlockingTask<T> {
    result: tokio::sync::oneshot::Receiver<Result<T, BlockingTaskError>>,
}

impl<T> Future for BlockingTask<T> {
    type Output = Result<T, BlockingTaskError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.result)
            .poll(context)
            .map(|received| received.unwrap_or(Err(BlockingTaskError::Cancelled)))
    }
}

/// Dispatch one owned synchronous closure through the host's blocking port.
///
/// A rejected job drops its captures before this returns. An accepted job owns
/// them until it finishes or the host discards it during shutdown. The result
/// waiter can be dropped without aborting the work.
pub fn dispatch<T: Send + 'static>(
    spawner: &dyn BlockingSpawner,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<BlockingTask<T>, BlockingSpawnError> {
    let (result, waiter) = tokio::sync::oneshot::channel();
    spawner.spawn(Box::new(move || {
        let outcome = match catch_unwind(AssertUnwindSafe(work)) {
            Ok(value) => Ok(value),
            Err(payload) => {
                discard_panic(payload);
                Err(BlockingTaskError::Panicked)
            }
        };
        if let Err(unobserved) = result.send(outcome)
            && let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(unobserved)))
        {
            // A cancelled waiter may leave an owned result with a panicking
            // destructor. Its failure must not unwind the host's worker.
            discard_panic(payload);
        }
    }))?;
    Ok(BlockingTask { result: waiter })
}

fn discard_panic(payload: Box<dyn Any + Send>) {
    if let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        let _secondary = std::mem::ManuallyDrop::new(secondary);
    }
}

/// Tokio adapter with a shared bound on queued and running blocking jobs.
///
/// The adapter uses the current Tokio runtime when `spawn` is called. Clones
/// share one admission budget. Dropping the returned Tokio task handle detaches
/// accepted jobs; the permit stays with each job until it ends or is dropped
/// during runtime shutdown.
#[derive(Clone, Debug)]
pub struct TokioBlockingSpawner {
    slots: Arc<Semaphore>,
    jobs: Arc<InFlightJobs>,
    admission: Arc<Mutex<()>>,
}

#[derive(Debug, Default)]
struct InFlightJobs {
    active: AtomicUsize,
    changed: Notify,
}

struct AcceptedJob {
    jobs: Arc<InFlightJobs>,
    work: Option<BlockingJob>,
    permit: Option<OwnedSemaphorePermit>,
}

impl Drop for AcceptedJob {
    fn drop(&mut self) {
        // Queued jobs may be discarded before their closure runs. Drop their
        // captures before publishing idle in that path as well as on unwind.
        let capture_drop = catch_unwind(AssertUnwindSafe(|| drop(self.work.take())));
        drop(self.permit.take());
        self.jobs.active.fetch_sub(1, Ordering::AcqRel);
        self.jobs.changed.notify_waiters();
        if let Err(payload) = capture_drop {
            discard_panic(payload);
        }
    }
}

impl TokioBlockingSpawner {
    /// Create one blocking executor admission domain. Invalid capacities are
    /// rejected before constructing a semaphore.
    pub fn new(max_jobs: usize) -> Result<Self, BlockingCapacityError> {
        if !(1..=Semaphore::MAX_PERMITS).contains(&max_jobs) {
            return Err(BlockingCapacityError);
        }
        Ok(Self {
            slots: Arc::new(Semaphore::new(max_jobs)),
            jobs: Arc::default(),
            admission: Arc::default(),
        })
    }

    /// Permanently reject new work in this admission domain and all clones.
    /// Already accepted jobs retain their captures and must still be drained.
    pub fn close(&self) {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.slots.close();
    }

    fn admit(&self, job: BlockingJob) -> Result<AcceptedJob, BlockingSpawnError> {
        let _admission = self
            .admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|error| match error {
                tokio::sync::TryAcquireError::Closed => BlockingSpawnError::Unavailable,
                tokio::sync::TryAcquireError::NoPermits => BlockingSpawnError::AtCapacity,
            })?;
        self.jobs.active.fetch_add(1, Ordering::AcqRel);
        Ok(AcceptedJob {
            jobs: Arc::clone(&self.jobs),
            work: Some(job),
            permit: Some(permit),
        })
    }

    /// Wait until all previously accepted blocking jobs have released their
    /// captures. The host must first stop producers; jobs admitted concurrently
    /// with this wait can make an observed idle state only a snapshot, not a
    /// global shutdown barrier. Close admission before waiting to establish
    /// a terminal barrier instead of an idle snapshot.
    pub async fn wait_idle(&self) {
        loop {
            let changed = self.jobs.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.jobs.active.load(Ordering::Acquire) == 0 {
                return;
            }
            changed.await;
        }
    }
}

impl Default for TokioBlockingSpawner {
    fn default() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(DEFAULT_MAX_BLOCKING_JOBS)),
            jobs: Arc::default(),
            admission: Arc::default(),
        }
    }
}

impl BlockingSpawner for TokioBlockingSpawner {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_error| BlockingSpawnError::Unavailable)?;
        let mut accepted = self.admit(job)?;
        runtime.spawn_blocking(move || {
            if let Some(work) = accepted.work.take() {
                work();
            }
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context as _, ensure};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[derive(Default)]
    struct HoldingSpawner(Mutex<Option<BlockingJob>>);

    impl BlockingSpawner for HoldingSpawner {
        fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
            let mut held = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if held.is_some() {
                return Err(BlockingSpawnError::AtCapacity);
            }
            *held = Some(job);
            Ok(())
        }
    }

    #[tokio::test]
    async fn accepted_work_outlives_a_dropped_result_waiter() -> anyhow::Result<()> {
        let spawner = HoldingSpawner::default();
        let ran = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&ran);
        let waiter = dispatch(&spawner, move || observed.store(true, Ordering::SeqCst))?;
        drop(waiter);
        let job = spawner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .context("accepted job")?;
        job();
        ensure!(ran.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn discarded_and_panicked_jobs_have_distinct_results() -> anyhow::Result<()> {
        let holding = HoldingSpawner::default();
        let cancelled = dispatch(&holding, || 1_u8)?;
        drop(
            holding
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take(),
        );
        ensure!(cancelled.await == Err(BlockingTaskError::Cancelled));

        let tokio = TokioBlockingSpawner::new(1)?;
        let panicked = dispatch(&tokio, || -> u8 {
            std::panic::resume_unwind(Box::new("worker panic"))
        })?;
        ensure!(panicked.await == Err(BlockingTaskError::Panicked));
        Ok(())
    }

    #[test]
    fn cancelled_waiter_does_not_unwind_its_blocking_worker() -> anyhow::Result<()> {
        struct PanickingResult;

        impl Drop for PanickingResult {
            fn drop(&mut self) {
                std::panic::resume_unwind(Box::new("unobserved result destructor"));
            }
        }

        let spawner = HoldingSpawner::default();
        let waiter = dispatch(&spawner, || PanickingResult)?;
        drop(waiter);
        let job = spawner
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .context("accepted job")?;
        ensure!(catch_unwind(AssertUnwindSafe(job)).is_ok());
        Ok(())
    }

    #[test]
    fn tokio_adapter_rejects_without_a_runtime() {
        let spawner = TokioBlockingSpawner::default();
        let ran = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&ran);
        assert_eq!(
            spawner.spawn(Box::new(move || observed.store(true, Ordering::SeqCst))),
            Err(BlockingSpawnError::Unavailable)
        );
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[test]
    fn tokio_adapter_rejects_invalid_capacity() {
        assert!(matches!(
            TokioBlockingSpawner::new(0),
            Err(BlockingCapacityError)
        ));
        assert!(matches!(
            TokioBlockingSpawner::new(usize::MAX),
            Err(BlockingCapacityError)
        ));
    }

    #[tokio::test]
    async fn tokio_adapter_bounds_running_jobs_and_keeps_capacity_until_completion()
    -> anyhow::Result<()> {
        let spawner = TokioBlockingSpawner::new(1)?;
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, finish) = std::sync::mpsc::channel();
        spawner.spawn(Box::new(move || {
            let _entered = entered.send(());
            let _released = finish.recv_timeout(Duration::from_secs(5));
        }))?;
        tokio::time::timeout(Duration::from_secs(5), started).await??;
        let excess_ran = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&excess_ran);
        ensure!(
            spawner.spawn(Box::new(move || observed.store(true, Ordering::SeqCst)))
                == Err(BlockingSpawnError::AtCapacity)
        );
        release.send(())?;
        let completed = Arc::new(AtomicBool::new(false));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let completed = Arc::clone(&completed);
                match spawner.spawn(Box::new(move || {
                    completed.store(true, Ordering::SeqCst);
                })) {
                    Ok(()) => break,
                    Err(BlockingSpawnError::AtCapacity) => tokio::task::yield_now().await,
                    Err(error) => anyhow::bail!("unexpected dispatch failure: {error}"),
                }
            }
            Ok::<(), anyhow::Error>(())
        })
        .await??;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !completed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        ensure!(!excess_ran.load(Ordering::SeqCst));
        Ok(())
    }

    #[tokio::test]
    async fn tokio_idle_waits_for_detached_job_captures_to_drop() -> anyhow::Result<()> {
        struct Released(Arc<AtomicBool>);
        impl Drop for Released {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let spawner = TokioBlockingSpawner::new(1)?;
        let released = Arc::new(AtomicBool::new(false));
        let capture = Released(Arc::clone(&released));
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, finish) = std::sync::mpsc::channel();
        let waiter = dispatch(&spawner, move || {
            let _capture = capture;
            let _entered = entered.send(());
            let _released = finish.recv_timeout(Duration::from_secs(5));
        })?;
        tokio::time::timeout(Duration::from_secs(5), started).await??;
        drop(waiter);

        let retained = spawner.clone();
        retained.close();
        spawner.close();
        let rejected_ran = Arc::new(AtomicBool::new(false));
        let rejected_capture_dropped = Arc::new(AtomicBool::new(false));
        let rejected_capture = Released(Arc::clone(&rejected_capture_dropped));
        let observed = Arc::clone(&rejected_ran);
        ensure!(
            retained.spawn(Box::new(move || {
                let _capture = rejected_capture;
                observed.store(true, Ordering::Release);
            })) == Err(BlockingSpawnError::Unavailable)
        );
        ensure!(rejected_capture_dropped.load(Ordering::Acquire));

        let idle = spawner.wait_idle();
        tokio::pin!(idle);
        ensure!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(std::future::Future::poll(idle.as_mut(), cx))
            })
            .await
            .is_pending()
        );
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(5), idle).await?;
        ensure!(released.load(Ordering::Acquire));
        ensure!(!rejected_ran.load(Ordering::Acquire));
        ensure!(dispatch(&spawner, || ()).err() == Some(BlockingSpawnError::Unavailable));
        Ok(())
    }

    #[tokio::test]
    async fn closing_counts_accepted_work_before_scheduler_submission() -> anyhow::Result<()> {
        let spawner = TokioBlockingSpawner::new(1)?;
        let (released, mut dropped) = tokio::sync::oneshot::channel::<()>();
        let accepted = spawner.admit(Box::new(move || drop(released)))?;
        let retained = spawner.clone();
        retained.close();
        let mut idle = std::pin::pin!(spawner.wait_idle());
        ensure!(
            std::future::poll_fn(|context| {
                std::task::Poll::Ready(std::future::Future::poll(idle.as_mut(), context))
            })
            .await
            .is_pending()
        );
        ensure!(matches!(
            dropped.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        ensure!(retained.spawn(Box::new(|| ())) == Err(BlockingSpawnError::Unavailable));
        drop(accepted);
        tokio::time::timeout(Duration::from_secs(5), idle).await?;
        ensure!(dropped.await.is_err());
        Ok(())
    }
}
