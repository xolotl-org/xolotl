use std::sync::Arc;

use anyhow::{Context as _, Result, ensure};
use tokio::sync::Semaphore;
use xolotl_kernel::host::{BlockingSpawner, blocking::dispatch};

#[derive(Clone)]
pub(super) struct StorageWorkers {
    slots: Arc<Semaphore>,
    blocking: Arc<dyn BlockingSpawner>,
}

impl StorageWorkers {
    pub(super) fn new(capacity: usize, blocking: Arc<dyn BlockingSpawner>) -> Result<Self> {
        ensure!(
            (1..=Semaphore::MAX_PERMITS).contains(&capacity),
            "invalid federation storage worker capacity"
        );
        Ok(Self {
            slots: Arc::new(Semaphore::new(capacity)),
            blocking,
        })
    }

    pub(super) async fn run<Output, Failure>(
        &self,
        work: impl FnOnce() -> Result<Output, Failure> + Send + 'static,
    ) -> Result<Output>
    where
        Output: Send + 'static,
        Failure: Into<anyhow::Error> + Send + 'static,
    {
        let permit = Arc::clone(&self.slots).acquire_owned().await?;
        dispatch(self.blocking.as_ref(), move || {
            let _permit = permit;
            work()
        })?
        .await
        .context("federation storage worker outcome indeterminate")?
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future as _, task::Poll, time::Duration};

    use xolotl_kernel::host::{
        BlockingJob, BlockingSpawnError, BlockingTaskError, TokioBlockingSpawner,
    };

    use super::*;

    #[tokio::test]
    async fn cancelled_waiter_keeps_local_slot_and_durable_work_in_host_drain() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("accepted-storage-write");
        let blocking = Arc::new(TokioBlockingSpawner::new(1)?);
        let workers = StorageWorkers::new(1, blocking.clone())?;
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let output = path.clone();
        let mut write = Box::pin(workers.run(move || -> Result<()> {
            use std::io::Write as _;

            let _entered = entered.send(());
            gate.recv_timeout(Duration::from_secs(5))?;
            let mut file = std::fs::File::create(output)?;
            file.write_all(b"accepted work survived its waiter")?;
            file.sync_all()?;
            Ok(())
        }));
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(write.as_mut().poll(context)))
                .await
                .is_pending()
        );
        tokio::time::timeout(Duration::from_secs(5), ready).await??;
        drop(write);
        ensure!(workers.slots.available_permits() == 0);
        let same_pool = workers.clone();
        let (queued_work, mut queued_observer) = tokio::sync::oneshot::channel();
        let mut queued = Box::pin(same_pool.run(move || {
            let _queued_work = queued_work.send(());
            Ok::<_, anyhow::Error>(())
        }));
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(queued.as_mut().poll(context)))
                .await
                .is_pending()
        );
        drop(queued);
        ensure!(
            queued_observer.try_recv() == Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        );
        let independent = StorageWorkers::new(1, blocking.clone())?;
        let rejected = independent
            .run(|| Ok::<_, anyhow::Error>(()))
            .await
            .err()
            .context("storage bypassed shared host capacity")?;
        ensure!(
            rejected.downcast_ref::<BlockingSpawnError>() == Some(&BlockingSpawnError::AtCapacity)
        );
        ensure!(!rejected.to_string().contains("indeterminate"));
        ensure!(independent.slots.available_permits() == 1);
        blocking.close();
        let mut idle = std::pin::pin!(blocking.wait_idle());
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(idle.as_mut().poll(context)))
                .await
                .is_pending()
        );
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(5), idle).await?;
        ensure!(std::fs::read(path)? == b"accepted work survived its waiter");
        ensure!(workers.slots.available_permits() == 1);
        let (ran, mut observed) = tokio::sync::oneshot::channel();
        let rejected = workers
            .run(move || {
                let _ran = ran.send(());
                Ok::<_, anyhow::Error>(())
            })
            .await
            .err()
            .context("closed storage host accepted work")?;
        ensure!(
            rejected.downcast_ref::<BlockingSpawnError>() == Some(&BlockingSpawnError::Unavailable)
        );
        ensure!(observed.try_recv() == Err(tokio::sync::oneshot::error::TryRecvError::Closed));
        ensure!(workers.slots.available_permits() == 1);
        Ok(())
    }

    struct DiscardAccepted;

    impl BlockingSpawner for DiscardAccepted {
        fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
            drop(job);
            Ok(())
        }
    }

    #[tokio::test]
    async fn accepted_failures_are_unknown_and_native_business_errors_survive() -> Result<()> {
        for (blocking, expected) in [
            (
                Arc::new(TokioBlockingSpawner::new(1)?) as Arc<dyn BlockingSpawner>,
                BlockingTaskError::Panicked,
            ),
            (Arc::new(DiscardAccepted), BlockingTaskError::Cancelled),
        ] {
            let workers = StorageWorkers::new(1, blocking)?;
            let failure = workers
                .run(|| -> Result<()> {
                    std::panic::resume_unwind(Box::new("accepted storage panic"))
                })
                .await
                .err()
                .context("accepted worker failure was hidden")?;
            ensure!(failure.downcast_ref::<BlockingTaskError>() == Some(&expected));
            ensure!(failure.to_string().contains("outcome indeterminate"));
            ensure!(workers.slots.available_permits() == 1);
        }
        let workers = StorageWorkers::new(1, Arc::new(TokioBlockingSpawner::new(1)?))?;
        let failure = workers
            .run(|| -> std::io::Result<()> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "native storage policy denial",
                ))
            })
            .await
            .err()
            .context("native business failure was hidden")?;
        let original = failure
            .downcast_ref::<std::io::Error>()
            .context("native io error type lost")?;
        ensure!(original.kind() == std::io::ErrorKind::PermissionDenied);
        ensure!(original.to_string() == "native storage policy denial");
        ensure!(!failure.to_string().contains("indeterminate"));
        Ok(())
    }
}
