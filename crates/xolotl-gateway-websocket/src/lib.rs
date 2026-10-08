#![forbid(unsafe_code)]

//! WebSocket transport adapter for external Provider and Source sessions.
//!
//! The adapter carries the same logical session frames as the external gRPC
//! transport. WebSocket is a transport choice; Provider and Source remain the
//! only external program roles.
//! Handlers retain their own error types. The host supplies the error returned
//! by an outbound sender when the frame cannot be sealed or queued; no gRPC
//! dependency is needed.

use axum::Router;
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use xolotl_gateway::external::{ExternalSessionHandler, ExternalSessionScope};

mod session;
mod transport;
use session::drive_socket;
use transport::validate_ws_transport;
pub use transport::{
    DEFAULT_FIRST_FRAME_TIMEOUT_MS, DEFAULT_IDLE_TIMEOUT_MS, DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_FRAME_BYTES, EXTERNAL_WS_PROTOCOL_VERSION, ExternalWebSocketConfig,
    HARD_FIRST_FRAME_TIMEOUT_MS, HARD_IDLE_TIMEOUT_MS, HARD_MAX_CONNECTIONS, HARD_MAX_FRAME_BYTES,
};

/// Why a frame could not be admitted to the bounded outbound queue.
///
/// No failure queues the submitted frame. Frames already in the queue
/// retain their order; a successful enqueue does not prove remote delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum OutboundQueueError {
    /// The live session has no free outbound queue slot.
    #[error("external WebSocket outbound queue full")]
    Full,
    /// The session writer no longer accepts frames.
    #[error("external WebSocket outbound queue closed")]
    Closed,
    /// A daemon-to-endpoint frame is oversized or has no authenticated type.
    #[error("external WebSocket outbound frame is invalid")]
    InvalidFrame,
    /// This session has exhausted its authenticated outbound sequence space.
    #[error("external WebSocket outbound sequence exhausted")]
    SequenceExhausted,
}

/// WebSocket adapter for external Provider/Source sessions.
pub struct ExternalWebSocketService<H: ExternalSessionHandler> {
    handler: Arc<H>,
    config: ExternalWebSocketConfig,
    connection_limiter: Arc<Semaphore>,
    scope: Arc<ExternalSessionScope>,
    send_error: fn(OutboundQueueError) -> H::OutboundError,
}

impl<H: ExternalSessionHandler> Clone for ExternalWebSocketService<H> {
    fn clone(&self) -> Self {
        Self {
            handler: self.handler.clone(),
            config: self.config.clone(),
            connection_limiter: self.connection_limiter.clone(),
            scope: self.scope.clone(),
            send_error: self.send_error,
        }
    }
}

impl<H> ExternalWebSocketService<H>
where
    H: ExternalSessionHandler,
{
    /// Share aggregate admission and task ownership with other External adapters.
    pub fn with_session_scope(mut self, scope: Arc<ExternalSessionScope>) -> Self {
        self.scope = scope;
        self
    }

    /// Build a service. `send_error` maps an outbound admission failure into
    /// the handler's own [`ExternalSessionHandler::OutboundError`]. Sending
    /// never waits for queue capacity, so a slow peer cannot block a caller
    /// before its response deadline or cancellation handling.
    pub fn new(handler: H, send_error: fn(OutboundQueueError) -> H::OutboundError) -> Self {
        Self::with_config(handler, ExternalWebSocketConfig::default(), send_error)
    }

    /// Build an external WebSocket service from a handler and config.
    /// `send_error` maps outbound admission failures into the handler's error.
    pub fn with_config(
        handler: H,
        config: ExternalWebSocketConfig,
        send_error: fn(OutboundQueueError) -> H::OutboundError,
    ) -> Self {
        Self::from_arc_with_config(Arc::new(handler), config, send_error)
    }

    /// Build an external WebSocket service from a shared handler.
    /// `send_error` maps outbound admission failures into the handler's error.
    pub fn from_arc(
        handler: Arc<H>,
        send_error: fn(OutboundQueueError) -> H::OutboundError,
    ) -> Self {
        Self::from_arc_with_config(handler, ExternalWebSocketConfig::default(), send_error)
    }

    /// Build an external WebSocket service from a shared handler and config.
    /// `send_error` maps outbound admission failures into the handler's error.
    pub fn from_arc_with_config(
        handler: Arc<H>,
        config: ExternalWebSocketConfig,
        send_error: fn(OutboundQueueError) -> H::OutboundError,
    ) -> Self {
        let config = config.bounded();
        Self {
            handler,
            connection_limiter: Arc::new(Semaphore::new(config.max_connections)),
            scope: Arc::new(ExternalSessionScope::default()),
            config,
            send_error,
        }
    }
}

/// Build a WebSocket session route that the host can mount at any path.
///
/// The route owns its service state and preserves the service's transport
/// security checks, shared connection limit, and session limits. Supply peer
/// addresses through [`ConnectInfo<SocketAddr>`], for example with Axum's
/// `into_make_service_with_connect_info::<SocketAddr>()` when serving a router.
///
/// ```
/// use std::sync::Arc;
/// use axum::Router;
/// use xolotl_gateway::external::{ExternalSessionHandler, ExternalSessionScope};
/// use xolotl_gateway_websocket::{ExternalWebSocketService, session_route};
///
/// fn routes<H>(service: Arc<ExternalWebSocketService<H>>) -> Router
/// where
///     H: ExternalSessionHandler,
///     H::Error: std::fmt::Debug,
/// {
///     Router::new().route("/external/session", session_route(service))
/// }
/// ```
pub fn session_route<H>(service: Arc<ExternalWebSocketService<H>>) -> MethodRouter
where
    H: ExternalSessionHandler,
    H::Error: std::fmt::Debug,
{
    get(ws_handler::<H>).with_state(service)
}

/// Serve external WebSocket sessions on `/ws` using [`session_route`].
/// Handler errors are logged locally and close the session; they are never
/// encoded as a gRPC status or exposed as an outbound protocol frame.
pub async fn serve<H>(
    service: Arc<ExternalWebSocketService<H>>,
    listener: TcpListener,
) -> std::io::Result<()>
where
    H: ExternalSessionHandler,
    H::Error: std::fmt::Debug,
{
    let app = Router::new().route("/ws", session_route(service));
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
    H: ExternalSessionHandler,
    H::Error: std::fmt::Debug,
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
    let Some(aggregate_permit) = service.scope.try_admit() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let max_frame_bytes = service.config.max_frame_bytes;
    upgrade
        .max_frame_size(max_frame_bytes)
        .max_message_size(max_frame_bytes)
        .protocols(["xolotl-external-v1"])
        .on_upgrade(move |socket| async move {
            let handler = service.handler.clone();
            let config = service.config.clone();
            let send_error = service.send_error;
            let scope = Arc::downgrade(&service.scope);
            drop(service.scope.spawn(async move {
                let _aggregate_permit = aggregate_permit;
                drive_socket(socket, handler, config, send_error, scope, permit).await;
            }));
        })
}
