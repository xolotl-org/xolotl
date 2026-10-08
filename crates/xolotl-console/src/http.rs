//! Composable v1 HTTP adapters. Paths are relative to the host's mount point.
//! Each group keeps its namespace when merged; all groups must share the same
//! [`HttpState`] to share connection admission; their Console service owns shared
//! credential policy, call capacity and registry.
//!
//! ```no_run
//! # fn mount(state: std::sync::Arc<xolotl_console::http::HttpState>) -> axum::Router {
//! axum::Router::new().nest("/admin", xolotl_console::http::router(state))
//! # }
//! ```
//!
//! Serve TCP with `into_make_service_with_connect_info::<SocketAddr>()` so origin
//! admission, proxy trust, rate limits and audit use the actual connection peer.
//! A non-TCP host may instead attach a verified [`HttpPeer`] extension at its
//! trusted connection boundary. Authentication, call and WebSocket endpoints
//! reject missing or ambiguous provenance; public manifest and health do not
//! need it.
//! Hosts choose tracing, CORS and other application layers; Console always
//! enforces its own origin policy and bearer authentication. For non-browser
//! clients, an adapter may explicitly allow omission of `Origin` only when the
//! host injects a matching [`VerifiedAutomationClient`] connection verdict.
//! TCP automation hosts select `into_make_service_with_connect_info::<HttpTcpConnection>()`
//! so each accepted connection receives a distinct identity. A socket address
//! alone cannot carry an automation verdict.

mod auth;
pub(crate) mod config;
mod state;
pub use config::*;
pub use state::{HttpConfig, HttpState, OriginlessClientPolicy};
mod calls;
mod context;
mod endpoints;
pub(crate) mod peer;
mod response;
mod transport;
mod ws;
pub use endpoints::{EndpointDescriptor, HttpApi, HttpEndpoint, HttpGroup, HttpManifest};
pub use peer::{HttpPeer, HttpPeerError, HttpTcpConnection, VerifiedAutomationClient};

use auth::*;
use axum::{Router, extract::DefaultBodyLimit};
use response::{AdmittedAuthJson, AdmittedBearerJson, AdmittedKeyJson, AuthResponse, HttpFailure};
use std::{net::SocketAddr, sync::Arc};

/// Default mount point used by [`serve`]. The unpublished protocol stays v1.
pub const API_BASE_PATH: &str = "/api/console/v1";
/// Maximum encoded request or response size for a single protobuf call.
pub const MAX_CALL_BYTES: usize = 4 * 1024 * 1024;
/// Maximum JSON authentication request size, including WebAuthn ceremonies.
pub const MAX_AUTH_BYTES: usize = 64 * 1024;
/// Encoded 64 KiB external assertion plus base64url and JSON framing.
pub const MAX_EXTERNAL_ASSERTION_BODY_BYTES: usize = 96 * 1024;

/// All relative Console routes. Mount once using `Router::nest` or serve directly.
pub fn router(state: Arc<HttpState>) -> Router {
    HttpApi::all().router(state)
}

/// Serve all Console routes under [`API_BASE_PATH`] on `listener`.
/// Embedded hosts may mount [`router`] at any prefix and provide their own layers.
pub async fn serve(listener: tokio::net::TcpListener, state: Arc<HttpState>) -> anyhow::Result<()> {
    let app = axum::Router::new()
        .nest(API_BASE_PATH, router(state))
        .layer(tower_http::trace::TraceLayer::new_for_http());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
