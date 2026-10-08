use anyhow::Result;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::task::{JoinError, JoinHandle};
use xolotl_kernel::host::TokioBlockingSpawner;
use xolotl_sdk::Bootstrap;

#[derive(Default)]
pub(super) struct BackgroundTasks {
    handles: Vec<BackgroundTask>,
}

struct BackgroundTask {
    name: &'static str,
    handle: TaskHandle,
}

enum TaskHandle {
    Worker(JoinHandle<()>),
    Service(JoinHandle<Result<()>>),
}

impl TaskHandle {
    fn abort(&self) {
        match self {
            Self::Worker(handle) => handle.abort(),
            Self::Service(handle) => handle.abort(),
        }
    }

    fn poll(&mut self, context: &mut TaskContext<'_>) -> Poll<Result<Result<()>, JoinError>> {
        match self {
            Self::Worker(handle) => Pin::new(handle).poll(context).map(|result| result.map(Ok)),
            Self::Service(handle) => Pin::new(handle).poll(context),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct BackgroundTaskShutdownReport {
    pub completed: usize,
    pub cancelled: usize,
    pub failed: usize,
}

impl BackgroundTasks {
    pub fn push(&mut self, name: &'static str, handle: JoinHandle<()>) {
        self.handles.push(BackgroundTask {
            name,
            handle: TaskHandle::Worker(handle),
        });
    }

    pub fn serve(&mut self, name: &'static str, handle: JoinHandle<Result<()>>) {
        self.handles.push(BackgroundTask {
            name,
            handle: TaskHandle::Service(handle),
        });
    }

    #[cfg(feature = "federation-grpc")]
    pub fn extend(
        &mut self,
        name: &'static str,
        handles: impl IntoIterator<Item = JoinHandle<()>>,
    ) {
        for handle in handles {
            self.push(name, handle);
        }
    }

    fn abort(&self) {
        for task in &self.handles {
            task.handle.abort();
        }
    }

    fn poll_failure(&mut self, context: &mut TaskContext<'_>) -> Poll<anyhow::Error> {
        let mut index = 0;
        while index < self.handles.len() {
            match self.handles[index].handle.poll(context) {
                Poll::Pending => index += 1,
                Poll::Ready(result) => {
                    let task = self.handles.swap_remove(index);
                    match result {
                        Ok(Ok(())) => {
                            return Poll::Ready(anyhow::anyhow!(
                                "required host task '{}' exited unexpectedly",
                                task.name
                            ));
                        }
                        Ok(Err(error)) => {
                            return Poll::Ready(
                                error.context(format!("host task '{}' failed", task.name)),
                            );
                        }
                        Err(error) => {
                            return Poll::Ready(
                                anyhow::Error::from(error)
                                    .context(format!("host task '{}' failed", task.name)),
                            );
                        }
                    }
                }
            }
        }
        Poll::Pending
    }

    pub async fn shutdown(&mut self) -> BackgroundTaskShutdownReport {
        self.abort();
        let mut report = BackgroundTaskShutdownReport::default();
        while let Some(task) = self.handles.last_mut() {
            match std::future::poll_fn(|context| task.handle.poll(context)).await {
                Ok(Ok(())) => report.completed += 1,
                Err(error) if error.is_cancelled() => report.cancelled += 1,
                result => {
                    report.failed += 1;
                    tracing::warn!(service = task.name, result = ?result, "background task failed during shutdown");
                }
            }
            self.handles.pop();
        }
        report
    }
}

impl Drop for BackgroundTasks {
    fn drop(&mut self) {
        self.abort();
    }
}

#[derive(Default)]
pub(super) struct HostedServices {
    #[cfg(feature = "terminal")]
    pub terminal: xolotl_standard::TerminalRuntime,
    #[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
    pub external_sessions: std::sync::Arc<xolotl_gateway::external::ExternalSessionScope>,
    pub background: BackgroundTasks,
    pub console: Option<xolotl_console::ConsoleService>,
    #[cfg(feature = "federation-grpc")]
    pub federation_runtime: Option<xolotl_federation_grpc::FederationGrpcRuntime>,
    #[cfg(feature = "federation-grpc")]
    pub federation_calls:
        Option<std::sync::Arc<xolotl_federation_kernel::FederationKernelCallBridge>>,
    #[cfg(feature = "application-grpc")]
    pub application: Option<crate::application::ApplicationGateway>,
}

impl HostedServices {
    fn poll_failure(&mut self, context: &mut TaskContext<'_>) -> Poll<anyhow::Error> {
        if let Poll::Ready(error) = self.background.poll_failure(context) {
            return Poll::Ready(error);
        }
        #[cfg(feature = "application-grpc")]
        if let Some(application) = self.application.as_mut() {
            return application.poll_failure(context);
        }
        Poll::Pending
    }

    pub async fn check_running(&mut self) -> Result<()> {
        std::future::poll_fn(|context| {
            Poll::Ready(match self.poll_failure(context) {
                Poll::Ready(error) => Err(error),
                Poll::Pending => Ok(()),
            })
        })
        .await
    }

    pub async fn wait_for_shutdown(
        &mut self,
        shutdown: impl Future<Output = Result<()>>,
    ) -> Result<()> {
        tokio::select! {
            biased;
            error = std::future::poll_fn(|context| self.poll_failure(context)) => Err(error),
            result = shutdown => result,
        }
    }

    async fn shutdown(&mut self, boot: &Bootstrap, blocking: &TokioBlockingSpawner) {
        #[cfg(feature = "federation-grpc")]
        if let Some(runtime) = self.federation_runtime.as_ref() {
            runtime.close();
        }
        #[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
        self.external_sessions.close();
        #[cfg(feature = "application-grpc")]
        if let Some(application) = self.application.as_ref() {
            application.close();
        }
        if let Some(console) = self.console.as_ref() {
            console.close_execution_admission();
        }
        #[cfg(feature = "federation-grpc")]
        if let Some(calls) = self.federation_calls.as_ref() {
            calls.close();
        }
        self.background.abort();
        #[cfg(feature = "terminal")]
        self.terminal.close();
        #[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
        self.external_sessions.shutdown().await;
        #[cfg(feature = "federation-grpc")]
        if let Some(runtime) = self.federation_runtime.as_ref() {
            runtime.shutdown().await;
        }
        #[cfg(feature = "federation-grpc")]
        if let Some(calls) = self.federation_calls.as_ref() {
            calls.shutdown().await;
        }
        if let Some(console) = self.console.as_ref() {
            let report = console.shutdown_executions().await;
            if report.volatile_cleanup_pending != 0 {
                tracing::warn!(
                    pending = report.volatile_cleanup_pending,
                    "Console stopped with volatile cleanup still pending"
                );
            }
        }
        #[cfg(feature = "application-grpc")]
        if let Some(application) = self.application.as_mut() {
            application.shutdown().await;
        }
        #[cfg(feature = "application-grpc")]
        {
            self.application = None;
        }
        self.console = None;
        #[cfg(feature = "terminal")]
        self.terminal.shutdown().await;
        let report = self.background.shutdown().await;
        tracing::debug!(
            completed = report.completed,
            cancelled = report.cancelled,
            failed = report.failed,
            "background task shutdown complete"
        );
        let cleanup = boot.drain_cleanup().await;
        for failure in cleanup.failures {
            tracing::warn!(process = failure.process.get(), error = %failure.error, "process cleanup remains pending");
        }
        blocking.close();
        blocking.wait_idle().await;
    }
}

pub(super) async fn supervise_host(
    boot: &Bootstrap,
    blocking: &TokioBlockingSpawner,
    run: impl AsyncFnOnce(&mut HostedServices) -> Result<()>,
) -> Result<()> {
    let mut services = HostedServices::default();
    let result = run(&mut services).await;
    services.shutdown(boot, blocking).await;
    result
}

impl Drop for HostedServices {
    fn drop(&mut self) {
        #[cfg(feature = "terminal")]
        self.terminal.close();
        #[cfg(feature = "federation-grpc")]
        if let Some(runtime) = self.federation_runtime.as_ref() {
            runtime.close();
        }
        #[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
        self.external_sessions.close();
        #[cfg(feature = "application-grpc")]
        if let Some(application) = self.application.as_ref() {
            application.close();
        }
        if let Some(console) = self.console.as_ref() {
            console.close_execution_admission();
        }
        #[cfg(feature = "federation-grpc")]
        if let Some(calls) = self.federation_calls.as_ref() {
            calls.close();
        }
        self.background.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::future::Future;

    #[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
    #[tokio::test]
    async fn dropped_host_closes_shared_external_admission_and_tasks() -> Result<()> {
        let services = HostedServices::default();
        let external = services.external_sessions.clone();
        let permit = external
            .try_admit()
            .ok_or_else(|| anyhow::anyhow!("scope unavailable"))?;
        let (sender, receiver) = oneshot::channel::<()>();
        external
            .spawn(async move {
                let _permit = permit;
                let _sender = sender;
                std::future::pending::<()>().await;
            })
            .ok_or_else(|| anyhow::anyhow!("task not accepted"))?;
        drop(services);
        ensure!(
            external.try_admit().is_none(),
            "host Drop left shared admission open"
        );
        tokio::time::timeout(Duration::from_secs(5), external.shutdown()).await?;
        ensure!(receiver.await.is_err(), "host-owned task outlived shutdown");
        Ok(())
    }
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::task::AbortHandle;

    struct Released(Option<oneshot::Sender<()>>);

    impl Drop for Released {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _sent = sender.send(());
            }
        }
    }

    async fn register_task(
        background: &mut BackgroundTasks,
    ) -> Result<(AbortHandle, oneshot::Receiver<()>)> {
        let (entered, ready) = oneshot::channel();
        let (released, finished) = oneshot::channel();
        let owned = Released(Some(released));
        let task = tokio::spawn(async move {
            let _owned = owned;
            let _sent = entered.send(());
            std::future::pending::<()>().await;
        });
        let abort = task.abort_handle();
        background.push("test producer", task);
        ready.await?;
        Ok((abort, finished))
    }

    #[tokio::test]
    async fn startup_failure_releases_started_tasks_before_preserving_the_error() -> Result<()> {
        for count in [1, 2] {
            let boot = Bootstrap::in_memory();
            let blocking = TokioBlockingSpawner::default();
            let mut observations = Vec::new();
            let result = supervise_host(&boot, &blocking, async |services| {
                for _ in 0..count {
                    observations.push(register_task(&mut services.background).await?);
                }
                anyhow::bail!("listener setup rejected");
            })
            .await;
            ensure!(result.is_err_and(|error| error.to_string() == "listener setup rejected"));
            let mut missing = 0;
            for (abort, mut released) in observations {
                if released.try_recv().is_err() {
                    missing += 1;
                    abort.abort();
                    tokio::time::timeout(Duration::from_secs(5), released).await??;
                }
            }
            ensure!(
                missing == 0,
                "startup error detached {missing} active tasks"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_shutdown_retains_handles_for_a_later_drain() -> Result<()> {
        let mut background = BackgroundTasks::default();
        let (abort, released) = register_task(&mut background).await?;
        let mut shutdown = Box::pin(background.shutdown());
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(shutdown.as_mut().poll(context)))
                .await
                .is_pending()
        );
        drop(shutdown);
        let retained = background.handles.len();
        let report = background.shutdown().await;
        abort.abort();
        tokio::time::timeout(Duration::from_secs(5), released).await??;
        ensure!(
            retained == 1 && report.cancelled == 1,
            "shutdown lost its pending handle"
        );
        Ok(())
    }

    #[tokio::test]
    async fn runtime_task_failures_drive_teardown_without_an_exit_signal() -> Result<()> {
        let mut rejected = Vec::new();
        for mode in ["completed", "error", "panic", "abort"] {
            let boot = Arc::new(Bootstrap::in_memory());
            let blocking = Arc::new(TokioBlockingSpawner::default());
            let (ready, entered) = oneshot::channel();
            let (release, gate) = oneshot::channel();
            let mut scope = tokio::spawn(async move {
                supervise_host(&boot, &blocking, async |services| {
                    let observation = register_task(&mut services.background).await?;
                    let abort = if mode == "error" {
                        let failed = tokio::spawn(async move {
                            let _released = gate.await;
                            Err::<(), anyhow::Error>(
                                std::io::Error::other("injected listener failure").into(),
                            )
                        });
                        let abort = failed.abort_handle();
                        services.background.serve("failing service", failed);
                        abort
                    } else {
                        let failed = tokio::spawn(async move {
                            let _released = gate.await;
                            match mode {
                                "panic" => {
                                    std::panic::resume_unwind(Box::new("injected runtime panic"))
                                }
                                "abort" => std::future::pending::<()>().await,
                                _ => {}
                            }
                        });
                        let abort = failed.abort_handle();
                        services.background.push("failing service", failed);
                        abort
                    };
                    let _sent = ready.send((observation, abort));
                    services
                        .wait_for_shutdown(std::future::pending::<Result<()>>())
                        .await
                })
                .await
            });
            let ((producer_abort, mut finished), failed_abort) = entered.await?;
            if mode == "abort" {
                failed_abort.abort();
            }
            let _sent = release.send(());
            let result = match tokio::time::timeout(Duration::from_secs(5), &mut scope).await {
                Ok(result) => Some(result?),
                Err(_) => {
                    scope.abort();
                    let _joined = scope.await;
                    None
                }
            };
            let released = finished.try_recv().is_ok();
            if !released {
                producer_abort.abort();
                tokio::time::timeout(Duration::from_secs(5), finished).await??;
            }
            let correct = result.is_some_and(|result| {
                result.is_err_and(|error| {
                    let message = format!("{error:#}");
                    message.contains("failing service")
                        && (mode != "error"
                            || (message.contains("injected listener failure")
                                && error.downcast_ref::<std::io::Error>().is_some_and(|cause| {
                                    cause.kind() == std::io::ErrorKind::Other
                                })))
                })
            });
            if !correct || !released {
                rejected.push(mode);
            }
        }
        ensure!(
            rejected.is_empty(),
            "runtime failure was not returned after producer release: {rejected:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn already_finished_failure_prevents_ready_and_wins_over_exit_signal() -> Result<()> {
        for check_ready in [true, false] {
            let mut services = HostedServices::default();
            let task = tokio::spawn(async { Ok(()) });
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
            services.background.serve("required listener", task);
            let result = if check_ready {
                services.check_running().await
            } else {
                services.wait_for_shutdown(async { Ok(()) }).await
            };
            services.background.shutdown().await;
            ensure!(
                result.is_err_and(|error| error.to_string().contains("required listener")),
                "finished required listener was reported healthy"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_supervision_preserves_live_ownership() -> Result<()> {
        let mut services = HostedServices::default();
        let (_abort, released) = register_task(&mut services.background).await?;
        services.check_running().await?;
        let (signal, mut received) = oneshot::channel();
        let mut waiting = Box::pin(services.wait_for_shutdown(async {
            (&mut received).await?;
            Ok(())
        }));
        let pending = std::future::poll_fn(|context| Poll::Ready(waiting.as_mut().poll(context)))
            .await
            .is_pending();
        drop(waiting);
        let mut waiting = Box::pin(services.wait_for_shutdown(async {
            (&mut received).await?;
            Ok(())
        }));
        let still_pending =
            std::future::poll_fn(|context| Poll::Ready(waiting.as_mut().poll(context)))
                .await
                .is_pending();
        drop(waiting);
        let retained = services.background.handles.len();
        signal
            .send(())
            .map_err(|()| anyhow::anyhow!("exit signal receiver lost"))?;
        services
            .wait_for_shutdown(async {
                received.await?;
                Ok(())
            })
            .await?;
        let report = services.background.shutdown().await;
        tokio::time::timeout(Duration::from_secs(5), released).await??;
        ensure!(
            pending && still_pending && retained == 1 && report.cancelled == 1,
            "supervision cancellation lost live ownership"
        );
        Ok(())
    }

    #[tokio::test]
    async fn startup_error_waits_for_accepted_blocking_work() -> Result<()> {
        let boot = Bootstrap::in_memory();
        let blocking = TokioBlockingSpawner::default();
        let (entered, ready) = oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let work = xolotl_kernel::host::blocking::dispatch(&blocking, move || {
            let _sent = entered.send(());
            let _released = gate.recv();
        })?;
        ready.await?;
        drop(work);
        let mut scope = Box::pin(supervise_host(&boot, &blocking, async |_services| {
            anyhow::bail!("listener setup rejected");
        }));
        let pending = std::future::poll_fn(|context| Poll::Ready(scope.as_mut().poll(context)))
            .await
            .is_pending();
        release.send(())?;
        let result = tokio::time::timeout(Duration::from_secs(5), scope).await?;
        ensure!(
            pending,
            "startup error returned while accepted work was still running"
        );
        ensure!(result.is_err_and(|error| error.to_string() == "listener setup rejected"));
        ensure!(
            xolotl_kernel::host::blocking::dispatch(&blocking, || ()).err()
                == Some(xolotl_kernel::host::BlockingSpawnError::Unavailable),
            "shutdown left blocking admission open"
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_host_scope_aborts_started_tasks_without_stopping_the_runtime() -> Result<()>
    {
        let boot = Arc::new(Bootstrap::in_memory());
        let blocking = Arc::new(TokioBlockingSpawner::default());
        let (ready, entered) = oneshot::channel();
        let scope = tokio::spawn(async move {
            supervise_host(&boot, &blocking, async |services| {
                let observation = register_task(&mut services.background).await?;
                let _sent = ready.send(observation);
                std::future::pending::<Result<()>>().await
            })
            .await
        });
        let (abort, mut released) = entered.await?;
        scope.abort();
        ensure!(scope.await.is_err_and(|error| error.is_cancelled()));
        let stopped = tokio::time::timeout(Duration::from_secs(5), &mut released)
            .await
            .is_ok();
        if !stopped {
            abort.abort();
            tokio::time::timeout(Duration::from_secs(5), released).await??;
        }
        ensure!(stopped, "cancelled daemon scope detached its producer");
        Ok(())
    }
}
