//! Exercise connection provenance through Unix-domain HTTP connections.

use super::{fixture, verified_peer::proxy_adapter};
use anyhow::{Context, ensure};
use axum::{
    Router,
    extract::{ConnectInfo, Request, connect_info::Connected},
    http::StatusCode,
    middleware::{Next, from_fn},
    response::{IntoResponse, Response},
    serve::IncomingStream,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
use xolotl_console::http::{HttpApi, HttpGroup, HttpPeer};

#[derive(Clone)]
struct UnixIdentity(Option<HttpPeer>);

impl Connected<IncomingStream<'_, UnixListener>> for UnixIdentity {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self(stream.io().peer_cred().ok().and_then(|credentials| {
            HttpPeer::verified_source(format!("unix-uid:{}", credentials.uid())).ok()
        }))
    }
}

async fn install_verified_peer(
    ConnectInfo(identity): ConnectInfo<UnixIdentity>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(peer) = identity.0 else {
        return StatusCode::FORBIDDEN.into_response();
    };
    request.extensions_mut().insert(peer);
    next.run(request).await
}

#[tokio::test]
async fn unix_connection_identity_reaches_routes_without_trusting_forwarded_headers()
-> anyhow::Result<()> {
    let state = fixture().await?;
    let app = Router::new()
        .nest(
            "/admin",
            HttpApi::new()
                .with_group(HttpGroup::Authentication)
                .routes(proxy_adapter(&state)),
        )
        .layer(from_fn(install_verified_peer));
    let directory = tempfile::tempdir().context("create Unix-domain socket directory")?;
    let socket_path = directory.path().join("console.sock");
    let listener = UnixListener::bind(&socket_path).context("bind Unix-domain socket")?;
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<UnixIdentity>(),
        )
        .await
    });

    let mut connection = UnixStream::connect(&socket_path).await?;
    connection
        .write_all(
            b"GET /admin/auth/factor-providers HTTP/1.1\r\nHost: console.local\r\nOrigin: https://console.local\r\nX-Forwarded-Host: attacker.invalid\r\nX-Forwarded-Proto: http\r\nX-Forwarded-For: 203.0.113.9\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut received = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connection.read_to_end(&mut received),
    )
    .await??;
    ensure!(received.starts_with(b"HTTP/1.1 200"));
    ensure!(
        std::str::from_utf8(&received)?.contains("\"provider_id\":\"totp\""),
        "public provider discovery did not reach the Console route"
    );

    let mut browser_get = UnixStream::connect(&socket_path).await?;
    browser_get
        .write_all(
            b"GET /admin/auth/factor-providers HTTP/1.1\r\nHost: console.local\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut accepted = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        browser_get.read_to_end(&mut accepted),
    )
    .await??;
    ensure!(
        accepted.starts_with(b"HTTP/1.1 200"),
        "browser GET without Origin returned {}",
        std::str::from_utf8(&accepted)?
            .lines()
            .next()
            .unwrap_or_default()
    );
    ensure!(
        std::str::from_utf8(&accepted)?.contains("\"provider_id\":\"totp\""),
        "browser GET without Origin did not reach provider discovery"
    );
    let mut missing_host = UnixStream::connect(&socket_path).await?;
    missing_host
        .write_all(
            b"GET /admin/auth/factor-providers HTTP/1.0\r\nOrigin: https://console.local\r\nConnection: close\r\n\r\n",
        )
        .await?;
    let mut rejected = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        missing_host.read_to_end(&mut rejected),
    )
    .await??;
    ensure!(
        rejected.starts_with(b"HTTP/1.0 403"),
        "missing Host returned {}",
        std::str::from_utf8(&rejected)?
            .lines()
            .next()
            .unwrap_or_default()
    );
    server.abort();
    let _stopped = server.await;
    Ok(())
}
