use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::Poll,
    time::Instant,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::{AbortHandle, JoinHandle};
use tonic::Status;
use xolotl_kernel::host::{BlockingSpawnError, BlockingSpawner, blocking::dispatch};

use crate::config::FederationGrpcConfig;

/// One host-owned Federation transport lifecycle shared by runtime clones.
///
/// `max_sessions` charges inbound and outbound sessions together, including
/// TLS and application handshakes. Admission rejects immediately at capacity
/// or after closure; failed handshakes and terminated actors release their
/// permit. A publisher's forwarding/public children share its charge until
/// they terminate, preventing cancelled children from accumulating outside
/// admission. The incoming adapter transfers its permit with the one-use TLS
/// proof, so admitting the publisher actor does not charge the session twice.
///
/// The runtime owns subscriber, publisher, forwarding and public-response task
/// handles until termination, retiring finished handles as new work arrives.
/// Host-managed object receive retries clone this same runtime: each attempt
/// charges the shared session budget and cannot reopen admission after closure.
/// Hosts close admission, stop listener/dial supervisors, then await transport
/// shutdown before draining the host blocking executor and releasing stores.
/// Cancelling a shutdown wait retains unfinished handles for a later wait.
/// Accepted blocking jobs remain owned by the host executor: closing transport
/// tasks neither cancels accepted work nor proves that its effects rolled back.
#[derive(Clone)]
pub struct FederationGrpcRuntime {
    config: FederationGrpcConfig,
    blocking: Arc<dyn BlockingSpawner>,
    tasks: Arc<SessionTasks>,
}

impl FederationGrpcRuntime {
    /// Bind transport limits without creating an independent executor.
    pub fn new(
        config: FederationGrpcConfig,
        blocking: Arc<dyn BlockingSpawner>,
    ) -> Result<Self, Status> {
        let config = config.validate()?;
        Ok(Self {
            config,
            blocking,
            tasks: Arc::new(SessionTasks {
                sessions: Arc::new(Semaphore::new(config.max_sessions)),
                handles: Mutex::new(Vec::new()),
                drain: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// Reject new sessions and interrupt owned async transport work without
    /// spawning cleanup. Accepted blocking work still requires the host drain.
    pub fn close(&self) {
        self.tasks.close();
    }

    /// Close and join transport tasks. Cancelling this wait does not detach
    /// unfinished tasks; another call resumes draining the same shared owner.
    /// Concurrent callers serialize draining without replacing task wakeups.
    pub async fn shutdown(&self) {
        self.close();
        let _drain = self.tasks.drain.lock().await;
        poll_fn(|context| {
            let mut handles = self
                .tasks
                .handles
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            handles.retain_mut(|handle| Pin::new(handle).poll(context).is_pending());
            if handles.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }

    pub(crate) fn admit(&self) -> Result<OwnedSemaphorePermit, Status> {
        self.tasks
            .sessions
            .clone()
            .try_acquire_owned()
            .map_err(|error| {
                if matches!(error, tokio::sync::TryAcquireError::Closed) {
                    Status::unavailable("federation runtime closed")
                } else {
                    Status::resource_exhausted("federation session limit reached")
                }
            })
    }

    pub(crate) fn owns_permit(&self, permit: &OwnedSemaphorePermit) -> bool {
        Arc::ptr_eq(permit.semaphore(), &self.tasks.sessions)
    }

    pub(crate) fn task_owner(&self) -> Weak<SessionTasks> {
        Arc::downgrade(&self.tasks)
    }

    /// Limits used by this host's transport instances.
    pub fn config(&self) -> FederationGrpcConfig {
        self.config
    }

    /// Share the same admission and shutdown domain with host-owned work.
    pub fn blocking_spawner(&self) -> Arc<dyn BlockingSpawner> {
        Arc::clone(&self.blocking)
    }

    pub(crate) fn worker_pool(&self) -> WorkerPool {
        WorkerPool {
            slots: Arc::new(Semaphore::new(self.config.max_blocking_verifications)),
            blocking: Arc::clone(&self.blocking),
        }
    }
}

pub(crate) struct SessionTasks {
    sessions: Arc<Semaphore>,
    handles: Mutex<Vec<JoinHandle<()>>>,
    drain: tokio::sync::Mutex<()>,
}

impl SessionTasks {
    pub(crate) fn spawn(
        owner: &Weak<Self>,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Result<AbortHandle, Status> {
        let owner = owner
            .upgrade()
            .ok_or_else(|| Status::unavailable("federation runtime dropped"))?;
        let mut handles = owner
            .handles
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if owner.sessions.is_closed() {
            return Err(Status::unavailable("federation runtime closed"));
        }
        handles.retain(|handle| !handle.is_finished());
        let task = tokio::spawn(future);
        let abort = task.abort_handle();
        handles.push(task);
        Ok(abort)
    }

    fn close(&self) {
        let handles = self
            .handles
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        self.sessions.close();
        for handle in handles.iter() {
            handle.abort();
        }
    }
}

impl Drop for SessionTasks {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) struct AbortOnDrop(pub(crate) AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct SessionChildren {
    owner: Weak<SessionTasks>,
    handles: Vec<AbortHandle>,
}

impl SessionChildren {
    pub(crate) fn new(owner: Weak<SessionTasks>) -> Self {
        Self {
            owner,
            handles: Vec::new(),
        }
    }

    pub(crate) fn spawn(
        &mut self,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Result<(), Status> {
        self.handles.retain(|handle| !handle.is_finished());
        self.handles.push(SessionTasks::spawn(&self.owner, future)?);
        Ok(())
    }
}

impl Drop for SessionChildren {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

pub(crate) struct SessionTermination(Option<tokio::sync::watch::Sender<Option<Status>>>);

impl SessionTermination {
    pub(crate) fn new(sender: tokio::sync::watch::Sender<Option<Status>>) -> Self {
        Self(Some(sender))
    }

    pub(crate) fn finish(&mut self, status: Status) {
        if let Some(sender) = self.0.take() {
            drop(sender.send_replace(Some(status)));
        }
    }
}

impl Drop for SessionTermination {
    fn drop(&mut self) {
        self.finish(Status::cancelled("federation Session interrupted"));
    }
}

#[derive(Clone)]
pub(crate) struct WorkerPool {
    slots: Arc<Semaphore>,
    blocking: Arc<dyn BlockingSpawner>,
}

impl WorkerPool {
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        deadline: Instant,
        task: impl FnOnce() -> Result<T, Status> + Send + 'static,
    ) -> Result<T, Status> {
        let deadline = tokio::time::Instant::from_std(deadline);
        let permit = tokio::time::timeout_at(deadline, Arc::clone(&self.slots).acquire_owned())
            .await
            .map_err(|_error| Status::deadline_exceeded("federation worker limit timed out"))?
            .map_err(|_error| Status::unavailable("federation worker pool closed"))?;
        if tokio::time::Instant::now() >= deadline {
            return Err(Status::deadline_exceeded(
                "federation worker admission timed out",
            ));
        }
        let work = dispatch(self.blocking.as_ref(), move || {
            let _permit = permit;
            task()
        })
        .map_err(|error| match error {
            BlockingSpawnError::AtCapacity => {
                Status::resource_exhausted("host federation worker capacity exceeded")
            }
            BlockingSpawnError::Unavailable => {
                Status::unavailable("host federation blocking executor unavailable")
            }
        })?;
        tokio::time::timeout_at(deadline, work)
            .await
            .map_err(|_error| {
                Status::unavailable("federation operation outcome indeterminate; retry identity")
            })?
            .map_err(|_error| {
                Status::unavailable("federation worker outcome indeterminate; retry identity")
            })?
    }
}

#[cfg(test)]
mod tests {
    use std::{task::Poll, time::Duration};

    use anyhow::{Context as _, Result, ensure};
    use xolotl_kernel::host::{BlockingJob, TokioBlockingSpawner};

    use super::*;

    #[tokio::test]
    async fn session_admission_is_shared_and_cancelled_drain_retains_tasks() -> Result<()> {
        let runtime = FederationGrpcRuntime::new(
            FederationGrpcConfig {
                max_sessions: 1,
                ..FederationGrpcConfig::default()
            },
            Arc::new(TokioBlockingSpawner::default()),
        )?;
        let clone = runtime.clone();
        let permit = runtime.admit()?;
        ensure!(clone.owns_permit(&permit));
        ensure!(
            clone
                .admit()
                .err()
                .context("aggregate admission bypassed")?
                .code()
                == tonic::Code::ResourceExhausted
        );
        drop(permit);
        let permit = clone.admit()?;
        let (started, ready) = tokio::sync::oneshot::channel();
        let resource = Arc::new(());
        let weak = Arc::downgrade(&resource);
        drop(SessionTasks::spawn(&runtime.task_owner(), async move {
            let _permit = permit;
            let _resource = resource;
            started.send(()).unwrap_or(());
            std::future::pending::<()>().await;
        })?);
        ready.await?;
        let mut drain = Box::pin(runtime.shutdown());
        let pending =
            poll_fn(|context| Poll::Ready(drain.as_mut().poll(context).is_pending())).await;
        ensure!(pending);
        drop(drain);
        ensure!(
            clone
                .admit()
                .err()
                .context("closed admission accepted")?
                .code()
                == tonic::Code::Unavailable
        );
        ensure!(SessionTasks::spawn(&clone.task_owner(), async {}).is_err());
        clone.shutdown().await;
        ensure!(weak.upgrade().is_none());
        ensure!(
            runtime
                .tasks
                .handles
                .lock()
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn last_runtime_drop_interrupts_owned_actor_without_a_cycle() -> Result<()> {
        let runtime = FederationGrpcRuntime::new(
            FederationGrpcConfig::default(),
            Arc::new(TokioBlockingSpawner::default()),
        )?;
        let owner = runtime.task_owner();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (resource, released) = tokio::sync::oneshot::channel::<()>();
        drop(SessionTasks::spawn(&owner, async move {
            let _resource = resource;
            started.send(()).unwrap_or(());
            std::future::pending::<()>().await;
        })?);
        ready.await?;
        drop(runtime);
        ensure!(owner.upgrade().is_none());
        ensure!(released.await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn fixed_active_budget_retires_finished_handles_across_repeated_work() -> Result<()> {
        let runtime = FederationGrpcRuntime::new(
            FederationGrpcConfig {
                max_sessions: 4,
                ..FederationGrpcConfig::default()
            },
            Arc::new(TokioBlockingSpawner::default()),
        )?;
        let owner = runtime.task_owner();
        let permit = runtime.admit()?;
        drop(SessionTasks::spawn(&owner, async move {
            let _permit = permit;
            std::future::pending::<()>().await;
        })?);
        for round in 0..128 {
            let mut completions = Vec::new();
            for _ in 0..3 {
                let permit = runtime.admit()?;
                let (finished, complete) = tokio::sync::oneshot::channel();
                drop(SessionTasks::spawn(&owner, async move {
                    let _permit = permit;
                    finished.send(()).unwrap_or(());
                })?);
                completions.push(complete);
            }
            ensure!(runtime.admit().is_err());
            for complete in completions {
                complete.await?;
            }
            let retained = runtime
                .tasks
                .handles
                .lock()
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .len();
            ensure!(
                retained <= 4,
                "retained {retained} handles after {} completed sessions",
                (round + 1) * 3
            );
        }
        runtime.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn accepted_timeout_keeps_local_capacity_and_host_drain_until_work_finishes() -> Result<()>
    {
        let blocking = Arc::new(TokioBlockingSpawner::new(1)?);
        let runtime = FederationGrpcRuntime::new(
            FederationGrpcConfig {
                max_blocking_verifications: 1,
                ..FederationGrpcConfig::default()
            },
            blocking.clone(),
        )?;
        let pool = runtime.worker_pool();
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let mut first = Box::pin(pool.run(Instant::now() + Duration::from_secs(1), move || {
            let _entered = entered.send(());
            gate.recv_timeout(Duration::from_secs(5))
                .map_err(|_error| Status::internal("test release gate failed"))?;
            Ok::<(), Status>(())
        }));
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(first.as_mut().poll(context)))
                .await
                .is_pending()
        );
        tokio::time::timeout(Duration::from_secs(5), ready).await??;
        let independent_pool = runtime.clone().worker_pool();
        let rejected = independent_pool
            .run(Instant::now() + Duration::from_secs(5), || Ok(()))
            .await
            .err()
            .context("shared host capacity was bypassed")?;
        ensure!(rejected.code() == tonic::Code::ResourceExhausted);
        ensure!(independent_pool.slots.available_permits() == 1);
        let failure = tokio::time::timeout(Duration::from_secs(5), first)
            .await?
            .err()
            .context("accepted work timeout")?;
        ensure!(failure.code() == tonic::Code::Unavailable);
        ensure!(failure.message().contains("outcome indeterminate"));
        ensure!(pool.slots.available_permits() == 0);
        let mut queued = Box::pin(pool.run(Instant::now() + Duration::from_secs(5), || Ok(())));
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(queued.as_mut().poll(context)))
                .await
                .is_pending()
        );
        blocking.close();
        let mut idle = std::pin::pin!(blocking.wait_idle());
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(idle.as_mut().poll(context)))
                .await
                .is_pending()
        );
        release.send(())?;
        tokio::time::timeout(Duration::from_secs(5), idle).await?;
        let rejected = queued
            .await
            .err()
            .context("closed host accepted queued work")?;
        ensure!(rejected.code() == tonic::Code::Unavailable);
        ensure!(rejected.message().contains("executor unavailable"));
        ensure!(pool.slots.available_permits() == 1);
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
    async fn accepted_worker_failures_are_unknown_and_business_status_details_survive() -> Result<()>
    {
        for blocking in [
            Arc::new(TokioBlockingSpawner::new(1)?) as Arc<dyn BlockingSpawner>,
            Arc::new(DiscardAccepted),
        ] {
            let pool = FederationGrpcRuntime::new(
                FederationGrpcConfig {
                    max_blocking_verifications: 1,
                    ..FederationGrpcConfig::default()
                },
                blocking,
            )?
            .worker_pool();
            let rejected = pool
                .run(
                    Instant::now() + Duration::from_secs(5),
                    || -> Result<(), Status> {
                        std::panic::resume_unwind(Box::new("accepted worker panic"))
                    },
                )
                .await
                .err()
                .context("accepted worker failure")?;
            ensure!(rejected.code() == tonic::Code::Unavailable);
            ensure!(rejected.message().contains("outcome indeterminate"));
            ensure!(pool.slots.available_permits() == 1);
        }
        let runtime = FederationGrpcRuntime::new(
            FederationGrpcConfig::default(),
            Arc::new(TokioBlockingSpawner::new(1)?),
        )?;
        let expected = Status::with_details(
            tonic::Code::DataLoss,
            "native business failure",
            b"native status evidence".as_slice().into(),
        );
        let produced = expected.clone();
        let failure = runtime
            .worker_pool()
            .run(Instant::now() + Duration::from_secs(5), move || {
                Err::<(), _>(produced)
            })
            .await
            .err()
            .context("business status")?;
        ensure!(failure.code() == expected.code());
        ensure!(failure.message() == expected.message());
        ensure!(failure.details() == expected.details());
        Ok(())
    }
}
