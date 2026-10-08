//! External transport listener setup.

use super::*;
#[cfg(feature = "external-websocket")]
use xolotl_gateway_websocket::{
    ExternalWebSocketConfig, ExternalWebSocketService, OutboundQueueError,
};

#[cfg(feature = "external-websocket")]
const EXTERNAL_WEBSOCKET_ADDR_ENV: &str = "XOLOTL_EXTERNAL_WEBSOCKET_ADDR";
#[cfg(feature = "external-grpc")]
const EXTERNAL_GRPC_ADDR_ENV: &str = "XOLOTL_EXTERNAL_GRPC_ADDR";

#[cfg(feature = "external-websocket")]
pub(crate) async fn start_external_websocket(
    cfg: &XolotlConfig,
    boot: &Arc<Bootstrap>,
    source_store: Arc<dyn SourceStore>,
    pairing_credentials: PairingDisplayEdge,
    shared_source_commands: SharedSourceCommands,
    session_scope: Arc<xolotl_gateway::external::ExternalSessionScope>,
    handles: &mut crate::host_lifecycle::BackgroundTasks,
) -> Result<()> {
    let external_websocket_addr = match cfg.server.external_websocket_addr.clone() {
        Some(addr) => Some(addr),
        None => optional_env_var(EXTERNAL_WEBSOCKET_ADDR_ENV)?,
    };
    let Some(addr) = external_websocket_addr else {
        tracing::info!("{EXTERNAL_WEBSOCKET_ADDR_ENV} unset; external WebSocket gateway disabled");
        return Ok(());
    };
    let external_cfg = cfg.external_gateway.websocket.clone().bounded();
    let security = external_cfg
        .transport_security
        .validate_plain_listener("external WebSocket gateway", &addr)?;
    let listen_addr = security.listen_addr;
    transport::log_transport_security("external WebSocket gateway", &addr, &security.config);
    let listener = TcpListener::bind(listen_addr).await?;
    let handler = DaemonExternalSessionHandler::with_shared_source_commands(
        boot.kernel().state().clone(),
        source_store,
        boot.kernel().registry().clone(),
        external_cfg.session_limits(),
        pairing_credentials,
        shared_source_commands,
        {
            let runtime = boot.kernel().host_runtime().clone();
            Arc::new(move || runtime.now_millis())
        },
    );
    let mut ws_config: ExternalWebSocketConfig = external_cfg.transport.into();
    ws_config.transport_security = security.config;
    let service = Arc::new(
        ExternalWebSocketService::with_config(handler, ws_config, |error| match error {
            OutboundQueueError::Full => {
                tonic::Status::resource_exhausted("external WebSocket outbound queue full")
            }
            OutboundQueueError::Closed => {
                tonic::Status::unavailable("external WebSocket session closed")
            }
            OutboundQueueError::InvalidFrame => {
                tonic::Status::internal("external WebSocket outbound frame invalid")
            }
            OutboundQueueError::SequenceExhausted => {
                tonic::Status::resource_exhausted("external WebSocket outbound sequence exhausted")
            }
        })
        .with_session_scope(session_scope),
    );
    tracing::info!(%addr, "external WebSocket gateway listening");
    handles.serve(
        "external WebSocket listener",
        tokio::spawn(async move {
            xolotl_gateway_websocket::serve(service, listener).await?;
            Ok(())
        }),
    );
    Ok(())
}

#[cfg(feature = "external-grpc")]
pub(crate) async fn start_external_grpc(
    cfg: &XolotlConfig,
    boot: &Arc<Bootstrap>,
    source_store: Arc<dyn SourceStore>,
    pairing_credentials: PairingDisplayEdge,
    shared_source_commands: SharedSourceCommands,
    session_scope: Arc<xolotl_gateway::external::ExternalSessionScope>,
    handles: &mut crate::host_lifecycle::BackgroundTasks,
) -> Result<()> {
    let external_grpc_addr = match cfg.server.external_grpc_addr.clone() {
        Some(addr) => Some(addr),
        None => optional_env_var(EXTERNAL_GRPC_ADDR_ENV)?,
    };
    let Some(addr) = external_grpc_addr else {
        tracing::info!("{EXTERNAL_GRPC_ADDR_ENV} unset; external gRPC gateway disabled");
        return Ok(());
    };
    let external_cfg = cfg.external_gateway.grpc.clone().bounded();
    let security = external_cfg
        .transport_security
        .validate_grpc_listener("external gRPC gateway", &addr)?;
    let listen_addr = security.listen_addr;
    let tls = transport::grpc_tls_server_config(&security)?;
    let listener = TcpListener::bind(listen_addr).await?;
    transport::log_transport_security("external gRPC gateway", &addr, &security.config);
    let handler = DaemonExternalSessionHandler::with_shared_source_commands(
        boot.kernel().state().clone(),
        source_store,
        boot.kernel().registry().clone(),
        external_cfg.session_limits(),
        pairing_credentials,
        shared_source_commands,
        {
            let runtime = boot.kernel().host_runtime().clone();
            Arc::new(move || runtime.now_millis())
        },
    );
    let service = xolotl_gateway_grpc::ExternalGrpcService::with_config(
        handler,
        xolotl_gateway_grpc::ExternalGrpcConfig {
            transport_security: security.config.clone(),
        },
    )
    .with_session_scope(session_scope);
    tracing::info!(%addr, "external gRPC gateway listening");
    let mut server = tonic::transport::Server::builder();
    handles.serve(
        "external gRPC listener",
        tokio::spawn(async move {
            let incoming = futures_util::stream::unfold(listener, |listener| async {
                let accepted = listener.accept().await.map(|(stream, _)| stream);
                Some((accepted, listener))
            });
            let incoming = transport::incoming::grpc_incoming(incoming, tls);
            server
                .add_service(service.into_server())
                .serve_with_incoming(incoming)
                .await?;
            Ok(())
        }),
    );
    Ok(())
}
