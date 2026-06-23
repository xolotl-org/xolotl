#![forbid(unsafe_code)]

//! WebSocket transport adapter for external Provider and Source sessions.
//!
//! The adapter carries the same logical session frames as the external gRPC
//! transport. WebSocket is a transport choice; Provider and Source remain the
//! only external program roles.

use axum::Router;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tonic::Status;
use xolotl_gateway::external::ExternalSessionHandler;

mod session;
mod transport;
use session::drive_socket;
use transport::validate_ws_transport;
pub use transport::{
    DEFAULT_FIRST_FRAME_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_FRAME_BYTES, EXTERNAL_WS_PROTOCOL_VERSION, ExternalWebSocketConfig,
    HARD_FIRST_FRAME_TIMEOUT_MS, HARD_IDLE_TIMEOUT_MS, HARD_MAX_CONNECTIONS, HARD_MAX_FRAME_BYTES,
};

/// WebSocket adapter for external Provider/Source sessions.
#[derive(Clone)]
pub struct ExternalWebSocketService<H> {
    handler: Arc<H>,
    config: ExternalWebSocketConfig,
    connection_limiter: Arc<Semaphore>,
}

impl<H> ExternalWebSocketService<H>
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    /// Build an external WebSocket service from a handler.
    pub fn new(handler: H) -> Self {
        Self::with_config(handler, ExternalWebSocketConfig::default())
    }

    /// Build an external WebSocket service from a handler and config.
    pub fn with_config(handler: H, config: ExternalWebSocketConfig) -> Self {
        Self::from_arc_with_config(Arc::new(handler), config)
    }

    /// Build an external WebSocket service from a shared handler.
    pub fn from_arc(handler: Arc<H>) -> Self {
        Self::from_arc_with_config(handler, ExternalWebSocketConfig::default())
    }

    /// Build an external WebSocket service from a shared handler and config.
    pub fn from_arc_with_config(handler: Arc<H>, config: ExternalWebSocketConfig) -> Self {
        let config = config.bounded();
        Self {
            handler,
            connection_limiter: Arc::new(Semaphore::new(config.max_connections)),
            config,
        }
    }
}

/// Serve external WebSocket sessions on `/ws`.
pub async fn serve<H>(
    service: Arc<ExternalWebSocketService<H>>,
    listener: TcpListener,
) -> std::io::Result<()>
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    let app = Router::new()
        .route("/ws", get(ws_handler::<H>))
        .with_state(service);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

async fn ws_handler<H>(
    State(service): State<Arc<ExternalWebSocketService<H>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    if let Some(outcome) =
        validate_ws_transport(&headers, peer.ip(), &service.config.transport_security)
    {
        tracing::warn!(
            outcome,
            peer = %peer.ip(),
            "external WebSocket transport rejected"
        );
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(permit) = service.connection_limiter.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    upgrade
        .protocols(["xolotl-external-v1"])
        .on_upgrade(move |socket| drive_socket(socket, service, permit))
}
