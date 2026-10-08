use super::wait_for_shutdown;
use anyhow::{Context, Result, bail, ensure};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::sync::watch;
use xolotl_gateway::{GatewayError, GatewayIdempotencyStore};
use xolotl_gateway_grpc::ApplicationGrpcService;
use xolotl_kernel::host::{HostDeadline, HostRuntime};

pub(super) struct Maintenance {
    runtime: HostRuntime,
    deadline: HostDeadline,
    period: Duration,
    storage_timeout: Duration,
}

impl Maintenance {
    pub(super) fn new(
        runtime: HostRuntime,
        period: Duration,
        storage_timeout: Duration,
    ) -> Result<Self> {
        ensure!(
            !period.is_zero(),
            "application retry epoch period must be positive"
        );
        ensure!(
            !storage_timeout.is_zero(),
            "application retry epoch storage timeout must be positive"
        );
        let deadline = runtime
            .deadline_after(period)
            .context("application retry epoch initial deadline is not representable")?;
        runtime
            .deadline_after(storage_timeout)
            .context("application retry epoch storage deadline is not representable")?;
        Ok(Self {
            runtime,
            deadline,
            period,
            storage_timeout,
        })
    }

    async fn store_operation<T>(
        &self,
        operation: impl Future<Output = Result<T, GatewayError>>,
        phase: &'static str,
    ) -> Result<T> {
        let deadline = self
            .runtime
            .deadline_after(self.storage_timeout)
            .with_context(|| {
                format!("application retry epoch {phase} deadline is not representable")
            })?;
        tokio::select! {
            biased;
            result = self.runtime.sleep_until(deadline) => {
                result?;
                bail!("application retry epoch {phase} timed out; store outcome may be unknown")
            }
            result = operation => result.with_context(|| format!("application retry epoch {phase} failed")),
        }
    }

    pub(super) async fn run(mut self, requests: Arc<dyn GatewayIdempotencyStore>) -> Result<()> {
        loop {
            self.runtime.sleep_until(self.deadline).await?;
            let expected = self.store_operation(requests.retry_epoch(), "read").await?;
            let closed = self
                .store_operation(requests.close_retry_epoch(expected), "closure")
                .await?;
            self.deadline = self.runtime.deadline_after(self.period).with_context(|| {
                format!(
                    "application retry epoch {expected} closed to {closed}, but next deadline is not representable"
                )
            })?;
        }
    }
}

pub(super) async fn supervise(
    watching: impl Future<Output = Result<()>>,
    maintenance: impl Future<Output = Result<()>>,
    service: ApplicationGrpcService,
    shutdown: watch::Sender<bool>,
) -> Result<()> {
    let mut stopping = shutdown.subscribe();
    let result = tokio::select! {
        biased;
        () = wait_for_shutdown(&mut stopping) => Ok(()),
        result = watching => result,
        result = maintenance => result,
    };
    service.shutdown();
    shutdown.send_replace(true);
    result
}
