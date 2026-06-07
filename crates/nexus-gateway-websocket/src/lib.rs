#![forbid(unsafe_code)]

//! `nexus-gateway-websocket` — WebSocket protocol adapter (Gateway/Source,
//! §18.1).
//!
//! A thin transport over the shared [`Gateway`](nexus_gateway::Gateway): a
//! client connects, sends an auth frame, then submits programs as JSON
//! `DoNode`s; the gateway runs each through the kernel and streams the outcome
//! back. The five §18.1 steps live in `nexus-gateway`; this crate only speaks
//! WebSocket frames.

use axum::Router;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use axum::routing::get;
use futures::{SinkExt, StreamExt};
use nexus_gateway::{AuthToken, Gateway, GatewayError, RequestIdentity};
use nexus_graph::DoNode;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;

/// Client → gateway frames.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientFrame {
    /// Present credentials (first frame).
    Auth { token: String },
    /// Submit a program to run. Boxed: `DoNode` is much larger than `Auth`.
    Submit { id: u64, program: Box<DoNode> },
}

/// Gateway → client frames.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerFrame {
    Authenticated { identity: String },
    Result { id: u64, outcome: serde_json::Value },
    Error { message: String },
}

/// A WebSocket gateway over any [`Gateway`] implementation.
pub struct WsGateway<G: Gateway> {
    gateway: Arc<G>,
}

impl<G: Gateway + 'static> WsGateway<G> {
    pub fn new(gateway: Arc<G>) -> Self {
        Self { gateway }
    }

    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/ws", get(upgrade::<G>))
            .with_state(self)
    }
}

async fn upgrade<G: Gateway + 'static>(
    ws: WebSocketUpgrade,
    State(gw): State<Arc<WsGateway<G>>>,
) -> Response {
    ws.on_upgrade(move |socket| session(socket, gw))
}

async fn session<G: Gateway + 'static>(socket: WebSocket, gw: Arc<WsGateway<G>>) {
    let (mut tx, mut rx) = socket.split();
    let mut identity: Option<RequestIdentity> = None;

    while let Some(Ok(msg)) = rx.next().await {
        let text = match msg {
            Message::Text(t) => t,
            Message::Close(_) => break,
            _ => continue,
        };
        let frame: ClientFrame = match serde_json::from_str(&text) {
            Ok(f) => f,
            Err(e) => {
                let _ = send(
                    &mut tx,
                    ServerFrame::Error {
                        message: format!("bad frame: {e}"),
                    },
                )
                .await;
                continue;
            }
        };
        match frame {
            ClientFrame::Auth { token } => match gw.gateway.authenticate(&AuthToken(token)).await {
                Ok(id) => {
                    let reply = ServerFrame::Authenticated {
                        identity: id.identity.clone(),
                    };
                    identity = Some(id);
                    let _ = send(&mut tx, reply).await;
                }
                Err(e) => {
                    let _ = send(&mut tx, auth_err(e)).await;
                }
            },
            ClientFrame::Submit { id, program } => {
                let Some(ident) = identity.clone() else {
                    let _ = send(
                        &mut tx,
                        ServerFrame::Error {
                            message: "not authenticated".into(),
                        },
                    )
                    .await;
                    continue;
                };
                let reply = match gw.gateway.submit(&ident, *program).await {
                    Ok(outcome) => match serde_json::to_value(&outcome) {
                        Ok(outcome) => ServerFrame::Result { id, outcome },
                        Err(e) => ServerFrame::Error {
                            message: format!("outcome serialization failed: {e}"),
                        },
                    },
                    Err(e) => ServerFrame::Error {
                        message: e.to_string(),
                    },
                };
                let _ = send(&mut tx, reply).await;
            }
        }
    }
}

async fn send<S>(tx: &mut S, frame: ServerFrame) -> Result<(), ()>
where
    S: SinkExt<Message> + Unpin,
{
    let text = serde_json::to_string(&frame).map_err(|_| ())?;
    tx.send(Message::Text(text.into())).await.map_err(|_| ())
}

fn auth_err(e: GatewayError) -> ServerFrame {
    ServerFrame::Error {
        message: e.to_string(),
    }
}

/// Serve a WS gateway on `listener`.
pub async fn serve<G: Gateway + 'static>(
    gateway: Arc<WsGateway<G>>,
    listener: TcpListener,
) -> std::io::Result<()> {
    let app = gateway.router();
    tracing::info!(
        addr = %listener.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into()),
        "WebSocket gateway listening"
    );
    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_gateway::InProcessGateway;
    use nexus_kernel::Bootstrap;

    #[test]
    fn router_builds_over_inprocess_gateway() {
        let boot = Arc::new(Bootstrap::in_memory());
        let gw = Arc::new(WsGateway::new(Arc::new(InProcessGateway::new(boot))));
        let _ = gw.router();
    }

    #[test]
    fn client_frame_parses() {
        let f: ClientFrame =
            serde_json::from_str(r#"{"type":"auth","token":"process://alice"}"#).unwrap();
        assert!(matches!(f, ClientFrame::Auth { .. }));
    }
}
