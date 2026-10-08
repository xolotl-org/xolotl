use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio::task::JoinHandle;
use xolotl_types::external::ControlFrame;

/// Aggregate External admission and task owner shared by transport adapters.
/// Admission charges live sessions (including handshakes), not encoded bytes
/// or RSS. Dropping the session permit releases its charge. Closing rejects
/// admission and interrupts every owned task; shutdown retains handles across
/// cancellation of the shutdown future until all tasks have terminated.
/// Concurrent shutdown waiters share this owner without replacing each other's
/// task wakeups. Completion confirms owned async task termination, not completion
/// or rollback of separately owned blocking jobs or remote effects.
pub struct ExternalSessionScope {
    admission: Arc<Semaphore>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    drain: tokio::sync::Mutex<()>,
}

impl Default for ExternalSessionScope {
    fn default() -> Self {
        Self::new(256)
    }
}

impl ExternalSessionScope {
    /// Create an aggregate scope; zero rejects all sessions.
    pub fn new(max_sessions: usize) -> Self {
        Self {
            admission: Arc::new(Semaphore::new(max_sessions)),
            tasks: Mutex::new(Vec::new()),
            drain: tokio::sync::Mutex::new(()),
        }
    }

    /// Reject immediately when closed or at capacity.
    pub fn try_admit(&self) -> Option<OwnedSemaphorePermit> {
        self.admission.clone().try_acquire_owned().ok()
    }

    /// Own a transport task until termination. Closed scopes reject spawning.
    pub fn spawn(
        &self,
        future: impl Future<Output = ()> + Send + 'static,
    ) -> Option<tokio::task::AbortHandle> {
        let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
        if self.admission.is_closed() {
            return None;
        }
        tasks.retain(|task| !task.is_finished());
        let task = tokio::spawn(future);
        let abort = task.abort_handle();
        tasks.push(task);
        Some(abort)
    }

    /// Stop admission and interrupt owned work without spawning cleanup tasks.
    pub fn close(&self) {
        let tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
        self.admission.close();
        for task in tasks.iter() {
            task.abort();
        }
    }

    /// Close and join owned tasks. Concurrent waits serialize draining; cancelling
    /// either an active or queued wait preserves task ownership for other waiters.
    pub async fn shutdown(&self) {
        self.close();
        let _drain = self.drain.lock().await;
        poll_fn(|context| {
            let mut tasks = self.tasks.lock().unwrap_or_else(|error| error.into_inner());
            tasks.retain_mut(|task| Pin::new(task).poll(context).is_pending());
            if tasks.is_empty() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
    }
}

impl Drop for ExternalSessionScope {
    fn drop(&mut self) {
        self.close();
    }
}

/// A session's bounded, best-effort cancellation notification queue.
/// One worker serializes at most 32 queued notifications. The one-second
/// delivery deadline starts at enqueue, including queue and sender waits.
/// Successful enqueue is not evidence of delivery or remote cancellation.
pub struct ExternalCancellationSender {
    tx: mpsc::Sender<(std::time::Instant, ControlFrame)>,
    abort: Option<tokio::task::AbortHandle>,
}

impl ExternalCancellationSender {
    /// Start one worker owned by the session scope. The transport closure must
    /// enforce the supplied monotonic deadline over its entire send operation.
    pub fn new<F, Fut>(scope: &ExternalSessionScope, mut send: F) -> Self
    where
        F: FnMut(std::time::Instant, ControlFrame) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (tx, mut rx) = mpsc::channel::<(std::time::Instant, ControlFrame)>(32);
        let abort = scope.spawn(async move {
            while let Some((deadline, frame)) = rx.recv().await {
                if deadline > std::time::Instant::now() {
                    send(deadline, frame).await;
                }
            }
        });
        Self { tx, abort }
    }

    /// Interrupt this session's worker; its scope retains the join handle.
    pub fn close(&self) {
        if let Some(abort) = &self.abort {
            abort.abort();
        }
    }

    /// Enqueue synchronously; full and closed queues reject immediately.
    pub fn enqueue(&self, frame: ControlFrame) -> bool {
        self.tx
            .try_send((
                std::time::Instant::now() + std::time::Duration::from_secs(1),
                frame,
            ))
            .is_ok()
    }
}

impl Drop for ExternalCancellationSender {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::task::{Context as TaskContext, Wake, Waker};

    #[derive(Default)]
    struct ShutdownWake(AtomicBool);

    impl Wake for ShutdownWake {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn concurrent_shutdown_preserves_each_waiter_and_cancelled_drain() -> anyhow::Result<()> {
        for (cancel_active, cancel_queued) in [(false, false), (true, false), (false, true)] {
            let scope = ExternalSessionScope::new(1);
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let (released_tx, released_rx) = tokio::sync::oneshot::channel();
            struct Release(Option<tokio::sync::oneshot::Sender<()>>);
            impl Drop for Release {
                fn drop(&mut self) {
                    if let Some(sender) = self.0.take() {
                        sender.send(()).unwrap_or(());
                    }
                }
            }
            let task = scope
                .spawn(async move {
                    let _release = Release(Some(released_tx));
                    started_tx.send(()).unwrap_or(());
                    std::future::pending::<()>().await;
                })
                .context("task admission")?;
            started_rx.await?;

            let first_wake = Arc::new(ShutdownWake::default());
            let second_wake = Arc::new(ShutdownWake::default());
            let first_waker = Waker::from(Arc::clone(&first_wake));
            let second_waker = Waker::from(Arc::clone(&second_wake));
            let mut first = Box::pin(scope.shutdown());
            let mut second = Box::pin(scope.shutdown());
            ensure!(
                first
                    .as_mut()
                    .poll(&mut TaskContext::from_waker(&first_waker))
                    .is_pending()
            );
            ensure!(
                second
                    .as_mut()
                    .poll(&mut TaskContext::from_waker(&second_waker))
                    .is_pending()
            );

            if cancel_queued {
                drop(second);
                second = Box::pin(scope.shutdown());
                ensure!(
                    second
                        .as_mut()
                        .poll(&mut TaskContext::from_waker(&second_waker))
                        .is_pending()
                );
            }
            if cancel_active {
                drop(first);
                ensure!(second_wake.0.swap(false, Ordering::SeqCst));
                ensure!(
                    second
                        .as_mut()
                        .poll(&mut TaskContext::from_waker(&second_waker))
                        .is_pending()
                );
                released_rx.await?;
            } else {
                released_rx.await?;
                ensure!(
                    first_wake.0.load(Ordering::SeqCst),
                    "a concurrent shutdown replaced the first waiter's wakeup"
                );
                first.await;
            }
            ensure!(task.is_finished());
            ensure!(second_wake.0.load(Ordering::SeqCst));
            second.await;
            ensure!(
                scope
                    .tasks
                    .lock()
                    .map_err(|error| anyhow::anyhow!("{error}"))?
                    .is_empty()
            );
            ensure!(scope.try_admit().is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn admission_releases_and_cancelled_shutdown_retains_tasks() -> anyhow::Result<()> {
        let scope = ExternalSessionScope::new(1);
        let permit = scope.try_admit().context("first admission")?;
        ensure!(scope.try_admit().is_none());
        drop(permit);
        let permit = scope.try_admit().context("released admission")?;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (released_tx, released_rx) = tokio::sync::oneshot::channel();
        struct Release(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Release {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    sender.send(()).unwrap_or(());
                }
            }
        }
        scope
            .spawn(async move {
                let _permit = permit;
                let _release = Release(Some(released_tx));
                started_tx.send(()).unwrap_or(());
                std::future::pending::<()>().await;
            })
            .context("task admission")?;
        started_rx.await?;
        let mut shutdown = Box::pin(scope.shutdown());
        let pending =
            poll_fn(|context| Poll::Ready(shutdown.as_mut().poll(context).is_pending())).await;
        ensure!(pending);
        drop(shutdown);
        ensure!(scope.try_admit().is_none());
        ensure!(scope.spawn(async {}).is_none());
        scope.shutdown().await;
        released_rx.await?;
        ensure!(
            scope
                .tasks
                .lock()
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancellation_queue_rejects_full_and_closed_without_spawning_per_frame()
    -> anyhow::Result<()> {
        let scope = ExternalSessionScope::default();
        let sender = ExternalCancellationSender::new(&scope, |_, _| async {
            std::future::pending::<()>().await;
        });
        for timestamp_ms in 0..32 {
            ensure!(sender.enqueue(ControlFrame::Heartbeat { timestamp_ms }));
        }
        ensure!(!sender.enqueue(ControlFrame::Heartbeat { timestamp_ms: 32 }));
        ensure!(
            scope
                .tasks
                .lock()
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .len()
                == 1
        );
        sender.close();
        scope.shutdown().await;
        ensure!(!sender.enqueue(ControlFrame::Heartbeat { timestamp_ms: 33 }));
        Ok(())
    }

    #[tokio::test]
    async fn fixed_active_budget_retires_handles_across_increasing_cumulative_work()
    -> anyhow::Result<()> {
        let scope = ExternalSessionScope::new(8);
        let permit = scope.try_admit().context("long-lived admission")?;
        scope
            .spawn(async move {
                let _permit = permit;
                std::future::pending::<()>().await;
            })
            .context("long-lived task")?;
        for round in 0..128 {
            let mut completions = Vec::new();
            for _ in 0..7 {
                let permit = scope.try_admit().context("transient admission")?;
                let (done_tx, done) = tokio::sync::oneshot::channel();
                scope
                    .spawn(async move {
                        let _permit = permit;
                        done_tx.send(()).unwrap_or(());
                    })
                    .context("transient task")?;
                completions.push(done);
            }
            ensure!(scope.try_admit().is_none());
            for done in completions {
                done.await?;
            }
            let retained = scope
                .tasks
                .lock()
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .len();
            ensure!(
                retained <= 8,
                "retained {retained} handles after {} cumulative transient tasks",
                (round + 1) * 7
            );
        }
        scope.shutdown().await;
        Ok(())
    }
}
