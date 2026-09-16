//! Ownership of one profile-bound runtime, listener, and profile subscription.

pub(crate) mod config;
mod connection;
mod profile;

use crate::config::XolotlConfig;
use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use xolotl_gateway::{Gateway, GatewayRuntime};
use xolotl_gateway_grpc::ApplicationGrpcService;
use xolotl_sdk::Bootstrap;
use xolotl_state::host::object::ObjectStore;

const APPLICATION_GRPC_ADDR_ENV: &str = "XOLOTL_APPLICATION_GRPC_ADDR";
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) struct ApplicationGateway {
    service: ApplicationGrpcService,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
    #[cfg(test)]
    listen_address: std::net::SocketAddr,
}

impl ApplicationGateway {
    pub async fn start(
        config: &XolotlConfig,
        boot: Arc<Bootstrap>,
        objects: ObjectStore,
    ) -> Result<Option<Self>> {
        let address = match &config.server.application_grpc_addr {
            Some(address) => Some(address.clone()),
            None => crate::optional_env_var(APPLICATION_GRPC_ADDR_ENV)?,
        };
        Self::start_at(config, address.as_deref(), boot, objects).await
    }

    async fn start_at(
        config: &XolotlConfig,
        address: Option<&str>,
        boot: Arc<Bootstrap>,
        objects: ObjectStore,
    ) -> Result<Option<Self>> {
        let Some(address) = address else {
            tracing::info!("application gRPC gateway disabled");
            return Ok(None);
        };
        let application = &config.application_gateway;
        let name = application.profile.as_deref().context(
            "application_gateway.profile is required when the application listener is enabled",
        )?;
        let path = profile::profile_path(name)?;
        let security = application
            .grpc
            .transport_security
            .validate_grpc_listener("application gRPC gateway", address)?;
        let mut server = crate::transport::grpc_server_builder(&security)?;
        let listener = TcpListener::bind(security.listen_addr)
            .await
            .context("bind application gRPC listener")?;
        let listen_address = listener.local_addr()?;
        let state = boot.kernel.state.clone();
        let events = state
            .subscribe(&path)
            .await
            .context("subscribe to application Gateway profile")?;
        let profile = profile::load_profile(&state, &path, name).await?;
        let runtime = Arc::new(GatewayRuntime::new(boot, profile)?.with_object_store(objects));
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
                let serving = server
                    .add_service(service.clone().into_server())
                    .serve_with_incoming_shutdown(incoming, async move {
                        wait_for_shutdown(&mut graceful_stop).await;
                    });
                tokio::pin!(serving);
                tokio::select! {
                    result = &mut serving => {
                        if let Err(error) = result {
                            tracing::error!(%error, "application gRPC listener exited");
                        }
                    }
                    () = wait_for_shutdown(&mut stopping) => {
                        service.shutdown();
                        match tokio::time::timeout(DRAIN_TIMEOUT, &mut serving).await {
                            Ok(Ok(())) => {}
                            Ok(Err(error)) => tracing::warn!(%error, "application gRPC listener shutdown failed"),
                            Err(_) => tracing::warn!("application gRPC listener drain timed out"),
                        }
                    }
                }
                service.shutdown();
                shutdown.send_replace(true);
            })
        };
        let profile_task = tokio::spawn(profile::watch_profile(
            state,
            path,
            name.to_owned(),
            events,
            runtime,
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

    pub async fn shutdown(mut self) {
        self.close();
        for mut task in self.tasks.drain(..) {
            match tokio::time::timeout(DRAIN_TIMEOUT, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%error, "application Gateway task shutdown failed")
                }
                Err(_) => {
                    task.abort();
                    if let Err(error) = task.await
                        && !error.is_cancelled()
                    {
                        tracing::warn!(%error, "application Gateway aborted task failed");
                    }
                    tracing::warn!("application Gateway task aborted after shutdown timeout");
                }
            }
        }
    }

    fn close(&self) {
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
