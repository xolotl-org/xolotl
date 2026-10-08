//! Ownership of one profile-bound runtime, listener, and profile subscription.

pub(crate) mod config;
mod connection;
mod profile;
mod retry_epochs;

use crate::config::XolotlConfig;
use anyhow::{Context, Result};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use xolotl_gateway::{Gateway, GatewayIdempotencyStore, GatewayRuntime};
use xolotl_gateway_grpc::ApplicationGrpcService;
use xolotl_sdk::Bootstrap;
use xolotl_state::host::object::ObjectStore;

const APPLICATION_GRPC_ADDR_ENV: &str = "XOLOTL_APPLICATION_GRPC_ADDR";
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct ApplicationGateway {
    service: ApplicationGrpcService,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<Result<()>>>,
    #[cfg(test)]
    listen_address: std::net::SocketAddr,
}

impl ApplicationGateway {
    pub async fn start(
        config: &XolotlConfig,
        boot: Arc<Bootstrap>,
        objects: ObjectStore,
        requests: Arc<dyn GatewayIdempotencyStore>,
    ) -> Result<Option<Self>> {
        let address = match &config.server.application_grpc_addr {
            Some(address) => Some(address.clone()),
            None => crate::optional_env_var(APPLICATION_GRPC_ADDR_ENV)?,
        };
        Self::start_at(config, address.as_deref(), boot, objects, requests).await
    }

    async fn start_at(
        config: &XolotlConfig,
        address: Option<&str>,
        boot: Arc<Bootstrap>,
        objects: ObjectStore,
        requests: Arc<dyn GatewayIdempotencyStore>,
    ) -> Result<Option<Self>> {
        let Some(address) = address else {
            tracing::info!("application gRPC gateway disabled");
            return Ok(None);
        };
        let application = &config.application_gateway;
        let maintenance = retry_epochs::Maintenance::new(
            boot.kernel().host_runtime().clone(),
            application.request_storage.retry_epoch_period()?,
            Duration::from_millis(application.grpc.storage_timeout_ms),
        )?;
        let maintenance_requests = requests.clone();
        let name = application.profile.as_deref().context(
            "application_gateway.profile is required when the application listener is enabled",
        )?;
        let path = profile::profile_path(name)?;
        let security = application
            .grpc
            .transport_security
            .validate_grpc_listener("application gRPC gateway", address)?;
        let tls = crate::transport::grpc_tls_server_config(&security)?;
        let mut server = tonic::transport::Server::builder();
        let listener = TcpListener::bind(security.listen_addr)
            .await
            .context("bind application gRPC listener")?;
        let listen_address = listener.local_addr()?;
        let state = boot.kernel().state().clone();
        let events = state
            .subscribe(&path)
            .await
            .context("subscribe to application Gateway profile")?;
        let profile = profile::load_profile(&state, &path, name).await?;
        let runtime =
            Arc::new(GatewayRuntime::new(boot, profile, requests)?.with_object_store(objects));
        let gateway: Arc<dyn Gateway> = runtime.clone();
        let service = ApplicationGrpcService::from_arc_with_config(
            gateway,
            application.grpc.service_config(security.config.clone()),
        )
        .context("configure application gRPC service")?;
        let (shutdown, _) = watch::channel(false);
        let server_task = {
            let service = service.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                let mut stopping = shutdown.subscribe();
                let mut graceful_stop = shutdown.subscribe();
                let incoming = futures_util::stream::unfold(
                    (listener, shutdown.clone()),
                    |(listener, shutdown)| async {
                        let stream = listener.accept().await.map(|(stream, _)| {
                            connection::ApplicationConnection::new(stream, shutdown.subscribe())
                        });
                        Some((stream, (listener, shutdown)))
                    },
                );
                let incoming = crate::transport::incoming::grpc_incoming(incoming, tls);
                let serving = server
                    .add_service(service.clone().into_server())
                    .serve_with_incoming_shutdown(incoming, async move {
                        wait_for_shutdown(&mut graceful_stop).await;
                    });
                tokio::pin!(serving);
                let result = tokio::select! {
                    result = &mut serving => {
                        match result {
                            Err(error) => Err(anyhow::Error::from(error).context("application gRPC listener failed")),
                            Ok(()) if *shutdown.borrow() => Ok(()),
                            Ok(()) => Err(anyhow::anyhow!("application gRPC listener exited unexpectedly")),
                        }
                    }
                    () = wait_for_shutdown(&mut stopping) => {
                        service.shutdown();
                        match tokio::time::timeout(DRAIN_TIMEOUT, &mut serving).await {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => tracing::warn!(%error, "application gRPC listener shutdown failed"),
                            Err(_) => tracing::warn!("application gRPC listener drain timed out"),
                        }
                        Ok(())
                    }
                };
                service.shutdown();
                shutdown.send_replace(true);
                result
            })
        };
        let watching = profile::watch_profile(
            state,
            path,
            name.to_owned(),
            events,
            runtime,
            service.clone(),
            shutdown.clone(),
        );
        let profile_task = tokio::spawn(retry_epochs::supervise(
            watching,
            maintenance.run(maintenance_requests),
            service.clone(),
            shutdown.clone(),
        ));
        crate::transport::log_transport_security(
            "application gRPC gateway",
            &listen_address.to_string(),
            &security.config,
        );
        tracing::info!(addr = %listen_address, profile = name, "application gRPC gateway listening");
        Ok(Some(Self {
            service,
            shutdown,
            tasks: vec![server_task, profile_task],
            #[cfg(test)]
            listen_address,
        }))
    }

    pub async fn shutdown(&mut self) {
        self.close();
        while let Some(task) = self.tasks.last_mut() {
            match tokio::time::timeout(DRAIN_TIMEOUT, &mut *task).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => {
                    tracing::warn!(%error, "application Gateway service shutdown failed")
                }
                Ok(Err(error)) => {
                    tracing::warn!(%error, "application Gateway task shutdown failed")
                }
                Err(_) => {
                    task.abort();
                    match task.await {
                        Ok(Err(error)) => {
                            tracing::warn!(%error, "application Gateway aborted service failed")
                        }
                        Err(error) if !error.is_cancelled() => {
                            tracing::warn!(%error, "application Gateway aborted task failed")
                        }
                        _ => {}
                    }
                    tracing::warn!("application Gateway task aborted after shutdown timeout");
                }
            }
            self.tasks.pop();
        }
    }

    pub(super) fn poll_failure(&mut self, context: &mut TaskContext<'_>) -> Poll<anyhow::Error> {
        let mut index = 0;
        while index < self.tasks.len() {
            match Pin::new(&mut self.tasks[index]).poll(context) {
                Poll::Pending => index += 1,
                Poll::Ready(result) => {
                    self.tasks.swap_remove(index);
                    let failure = match result {
                        Ok(Ok(())) if *self.shutdown.borrow() => None,
                        Ok(Ok(())) => Some(anyhow::anyhow!(
                            "application Gateway task exited unexpectedly"
                        )),
                        Ok(Err(error)) => Some(error.context("application Gateway failed")),
                        Err(error) => Some(
                            anyhow::Error::from(error).context("application Gateway task failed"),
                        ),
                    };
                    if let Some(error) = failure {
                        self.close();
                        return Poll::Ready(error);
                    }
                }
            }
        }
        Poll::Pending
    }

    pub(super) fn close(&self) {
        self.service.shutdown();
        self.shutdown.send_replace(true);
    }
}

impl Drop for ApplicationGateway {
    fn drop(&mut self) {
        self.close();
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn wait_for_shutdown(receiver: &mut watch::Receiver<bool>) {
    while !*receiver.borrow_and_update() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests;
