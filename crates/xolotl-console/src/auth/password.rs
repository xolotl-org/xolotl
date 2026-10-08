//! Bound expensive password work independently of async request lifetimes.

use super::{AuthError, hash_password, verify_password};
use std::sync::Arc;
use tokio::sync::Semaphore;
use xolotl_kernel::host::{BlockingSpawnError, BlockingSpawner, blocking::dispatch};

pub(super) struct PasswordVerifier {
    slots: Arc<Semaphore>,
    spawner: Arc<dyn BlockingSpawner>,
}

impl PasswordVerifier {
    pub(super) fn new(capacity: usize, spawner: Arc<dyn BlockingSpawner>) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(capacity)),
            spawner,
        }
    }

    pub(super) async fn verify(&self, phc: String, password: String) -> Result<bool, AuthError> {
        self.run(move || verify_password(&phc, &password)).await
    }

    pub(super) async fn hash(&self, password: String) -> Result<String, AuthError> {
        self.run(move || hash_password(&password)).await?
    }

    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, AuthError> {
        let permit = Arc::clone(&self.slots)
            .try_acquire_owned()
            .map_err(|_error| AuthError::CapacityExceeded)?;
        let task = dispatch(self.spawner.as_ref(), move || {
            // An accepted task owns its capacity even after waiter cancellation.
            let _permit = permit;
            work()
        })
        .map_err(spawn_error)?;
        task.await
            .map_err(|_error| AuthError::Crypto("password task failed".into()))
    }
}

/// Hash root provisioning material through the same bounded host work port.
/// This standalone entry has no ConsoleState or per-host verifier to borrow.
pub(super) async fn hash_with_spawner(
    spawner: &dyn BlockingSpawner,
    password: String,
) -> Result<(String, String), AuthError> {
    let task = dispatch(spawner, move || {
        let phc = hash_password(&password)?;
        Ok::<_, AuthError>((password, phc))
    })
    .map_err(spawn_error)?;
    task.await
        .map_err(|_error| AuthError::Crypto("password task failed".into()))?
}

fn spawn_error(error: BlockingSpawnError) -> AuthError {
    match error {
        BlockingSpawnError::AtCapacity => AuthError::CapacityExceeded,
        BlockingSpawnError::Unavailable => {
            AuthError::Crypto("password executor is unavailable".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    struct StdThreads;

    impl BlockingSpawner for StdThreads {
        fn spawn(&self, job: xolotl_kernel::host::BlockingJob) -> Result<(), BlockingSpawnError> {
            std::thread::Builder::new()
                .spawn(job)
                .map(|_handle| ())
                .map_err(|_error| BlockingSpawnError::Unavailable)
        }
    }

    struct Reject(BlockingSpawnError);

    impl BlockingSpawner for Reject {
        fn spawn(&self, _job: xolotl_kernel::host::BlockingJob) -> Result<(), BlockingSpawnError> {
            Err(self.0)
        }
    }

    #[tokio::test]
    async fn custom_host_scheduler_runs_password_work_off_the_async_worker() -> anyhow::Result<()> {
        let verifier = PasswordVerifier::new(1, Arc::new(StdThreads));
        let caller = std::thread::current().id();
        let worker = verifier.run(|| std::thread::current().id()).await?;
        ensure!(caller != worker);
        Ok(())
    }

    #[tokio::test]
    async fn rejected_work_does_not_run_or_retain_password_capacity() -> anyhow::Result<()> {
        for reason in [
            BlockingSpawnError::AtCapacity,
            BlockingSpawnError::Unavailable,
        ] {
            let verifier = PasswordVerifier::new(1, Arc::new(Reject(reason)));
            let ran = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&ran);
            let result = verifier
                .run(move || {
                    observed.store(true, Ordering::SeqCst);
                })
                .await;
            ensure!(
                match reason {
                    BlockingSpawnError::AtCapacity => {
                        matches!(&result, Err(AuthError::CapacityExceeded))
                    }
                    BlockingSpawnError::Unavailable => {
                        matches!(&result, Err(AuthError::Crypto(_)))
                    }
                },
                "unexpected rejection mapping: {result:?}"
            );
            ensure!(!ran.load(Ordering::SeqCst));
            ensure!(verifier.slots.available_permits() == 1);
        }
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_retains_capacity_without_blocking_async_work() -> anyhow::Result<()> {
        let verifier = PasswordVerifier::new(
            1,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
        );
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, finish) = std::sync::mpsc::channel();
        let work = verifier.run(move || {
            let _sent = entered.send(());
            finish.recv_timeout(Duration::from_secs(5)).is_ok()
        });
        let mut work = Box::pin(work);
        // This is a single-thread runtime. The readiness task can only advance
        // while password work waits if that work runs outside the async worker.
        tokio::select! {
            result = &mut work => anyhow::bail!("work finished before release: {result:?}"),
            ready = tokio::time::timeout(Duration::from_secs(5), ready) => ready??,
        }
        drop(work);
        let excess_ran = Arc::new(AtomicBool::new(false));
        let observed = excess_ran.clone();
        let rejection = verifier
            .run(move || {
                observed.store(true, Ordering::SeqCst);
                true
            })
            .await;
        ensure!(matches!(rejection, Err(AuthError::CapacityExceeded)));
        let failure = crate::protocol::ConsoleFailure::from(AuthError::CapacityExceeded);
        ensure!(failure.code == crate::protocol::ConsoleErrorCode::RateLimited);
        ensure!(failure.retry_after_ms.is_none());
        release.send(())?;
        // Observe completion through the semaphore, without timing assumptions
        // about how quickly the blocking worker receives its release signal.
        let permit = tokio::time::timeout(Duration::from_secs(5), verifier.slots.acquire())
            .await?
            .context("password capacity closed")?;
        drop(permit);
        ensure!(verifier.run(|| true).await?);
        ensure!(
            !excess_ran.load(Ordering::SeqCst),
            "excess work was dispatched"
        );
        Ok(())
    }
}
