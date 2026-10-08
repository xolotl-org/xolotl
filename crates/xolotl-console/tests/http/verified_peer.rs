//! Exercise host-verified provenance without requiring a particular listener.

use super::fixture;
use anyhow::{Context, ensure};
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Request},
    http::{HeaderValue, Method, StatusCode, header},
};
use prost::Message as _;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tower::ServiceExt;
use xolotl_console::{
    AuthenticationResponse, ConsoleTransportSecurityMode, ConsoleTrustedProxyConfig,
    http::{
        self, HttpApi, HttpConfig, HttpEndpoint, HttpGroup, HttpPeer, HttpState, HttpTcpConnection,
        OriginlessClientPolicy, VerifiedAutomationClient,
    },
};
use xolotl_console_protocol::pb;

pub(super) fn proxy_adapter(state: &Arc<HttpState>) -> Arc<HttpState> {
    HttpState::new(
        state.state().clone(),
        HttpConfig {
            transport_security: http::ConsoleTransportSecurityConfig {
                mode: ConsoleTransportSecurityMode::TrustedReverseProxy,
                trusted_proxy: ConsoleTrustedProxyConfig {
                    peers: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                    ..Default::default()
                },
                unsafe_relaxations: Vec::new(),
            },
            ..Default::default()
        },
    )
}

fn request(path: &str) -> anyhow::Result<Request> {
    Ok(Request::builder()
        .uri(path)
        .header(header::HOST, "console.local")
        .header(header::ORIGIN, "https://console.local")
        .body(axum::body::Body::empty())?)
}

#[tokio::test]
async fn missing_and_ambiguous_provenance_fail_closed() -> anyhow::Result<()> {
    let state = fixture().await?;
    let app = Router::new().nest(
        "/admin",
        HttpApi::new()
            .with_group(HttpGroup::Authentication)
            .routes(proxy_adapter(&state)),
    );
    let missing = app
        .clone()
        .oneshot(request("/admin/auth/factor-providers")?)
        .await?;
    ensure!(missing.status() == StatusCode::FORBIDDEN);

    let named = HttpPeer::verified_source("unix-uid:1000")?;
    let app = app.layer(axum::Extension(named));
    let mut forged_proxy = request("/admin/auth/factor-providers")?;
    forged_proxy
        .headers_mut()
        .insert("x-forwarded-host", "attacker.invalid".parse()?);
    forged_proxy
        .headers_mut()
        .insert("x-forwarded-proto", "http".parse()?);
    forged_proxy
        .headers_mut()
        .insert("x-forwarded-for", "203.0.113.9".parse()?);
    let accepted = app.clone().oneshot(forged_proxy).await?;
    ensure!(accepted.status() == StatusCode::OK);

    let mut forged_origin = request("/admin/auth/factor-providers")?;
    forged_origin
        .headers_mut()
        .insert(header::ORIGIN, "https://attacker.invalid".parse()?);
    forged_origin
        .headers_mut()
        .insert("x-forwarded-host", "attacker.invalid".parse()?);
    let rejected = app.clone().oneshot(forged_origin).await?;
    ensure!(rejected.status() == StatusCode::FORBIDDEN);

    let mut ambiguous = request("/admin/auth/factor-providers")?;
    ambiguous
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            8123,
        )));
    let ambiguous = app.oneshot(ambiguous).await?;
    ensure!(ambiguous.status() == StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn protobuf_calls_accept_a_verified_host_source() -> anyhow::Result<()> {
    let state = fixture().await?;
    let app = Router::new().nest(
        "/admin",
        HttpApi::new()
            .with_endpoint(HttpEndpoint::Calls)
            .routes(proxy_adapter(&state)),
    );
    let mut missing = request("/admin/calls")?;
    *missing.method_mut() = axum::http::Method::POST;
    let rejected = app.clone().oneshot(missing).await?;
    ensure!(rejected.status() == StatusCode::FORBIDDEN);

    let app = app.layer(axum::Extension(HttpPeer::verified_source("unix-uid:1000")?));
    let mut accepted = request("/admin/calls")?;
    *accepted.method_mut() = axum::http::Method::POST;
    let response = app.oneshot(accepted).await?;
    // The request passes provenance and Origin admission, then fails on media type.
    ensure!(response.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE);
    Ok(())
}

fn automation_adapter(state: &Arc<HttpState>) -> Arc<HttpState> {
    HttpState::new(
        state.state().clone(),
        HttpConfig {
            originless_clients: OriginlessClientPolicy::AllowVerifiedAutomation,
            ..Default::default()
        },
    )
}

fn originless_request(path: &str) -> anyhow::Result<Request> {
    let mut request = request(path)?;
    request.headers_mut().remove(header::ORIGIN);
    Ok(request)
}

fn originless_post(path: &str) -> anyhow::Result<Request> {
    let mut request = originless_request(path)?;
    *request.method_mut() = Method::POST;
    Ok(request)
}

#[tokio::test]
async fn originless_posts_require_policy_and_matching_host_verdict() -> anyhow::Result<()> {
    let state = fixture().await?;
    let named = HttpPeer::verified_source("unix-uid:1000")?;
    let verdict = VerifiedAutomationClient::for_host_peer(&named);
    let path = "/admin/session/refresh";
    let strict = Router::new().nest("/admin", http::router(state.clone()));
    let mut default_denied = originless_post(path)?;
    default_denied.extensions_mut().insert(named.clone());
    default_denied.extensions_mut().insert(verdict.clone());
    ensure!(strict.oneshot(default_denied).await?.status() == StatusCode::FORBIDDEN);

    let adapter = automation_adapter(&state);
    let manifest = serde_json::to_value(http::HttpApi::all().manifest(&adapter))?;
    ensure!(manifest["originless_clients"] == "allow_verified_automation");
    let app = Router::new().nest("/admin", http::router(adapter));
    let mut unmarked = originless_post(path)?;
    unmarked.extensions_mut().insert(named.clone());
    ensure!(app.clone().oneshot(unmarked).await?.status() == StatusCode::FORBIDDEN);

    let mut mismatched = originless_post(path)?;
    mismatched.extensions_mut().insert(named.clone());
    mismatched
        .extensions_mut()
        .insert(VerifiedAutomationClient::for_host_peer(
            &HttpPeer::verified_source("unix-uid:1000")?,
        ));
    ensure!(app.clone().oneshot(mismatched).await?.status() == StatusCode::FORBIDDEN);

    let mut accepted = originless_post(path)?;
    accepted.extensions_mut().insert(named.clone());
    accepted.extensions_mut().insert(verdict.clone());
    ensure!(app.clone().oneshot(accepted).await?.status() == StatusCode::UNAUTHORIZED);

    let mut bad_origin = request(path)?;
    *bad_origin.method_mut() = Method::POST;
    bad_origin.headers_mut().insert(
        header::ORIGIN,
        HeaderValue::from_static("https://attacker.invalid"),
    );
    bad_origin.extensions_mut().insert(named.clone());
    bad_origin.extensions_mut().insert(verdict.clone());
    ensure!(app.clone().oneshot(bad_origin).await?.status() == StatusCode::FORBIDDEN);

    let mut empty_origin = originless_post(path)?;
    empty_origin
        .headers_mut()
        .insert(header::ORIGIN, HeaderValue::from_static(""));
    empty_origin.extensions_mut().insert(named.clone());
    empty_origin.extensions_mut().insert(verdict.clone());
    ensure!(app.clone().oneshot(empty_origin).await?.status() == StatusCode::FORBIDDEN);

    for malformed_host in [None, Some("console.local, attacker.invalid")] {
        let mut bad_host = originless_post(path)?;
        bad_host.headers_mut().remove(header::HOST);
        if let Some(value) = malformed_host {
            bad_host
                .headers_mut()
                .insert(header::HOST, HeaderValue::from_static(value));
        }
        bad_host.extensions_mut().insert(named.clone());
        bad_host.extensions_mut().insert(verdict.clone());
        ensure!(app.clone().oneshot(bad_host).await?.status() == StatusCode::FORBIDDEN);
    }
    let mut duplicate_host = originless_post(path)?;
    duplicate_host
        .headers_mut()
        .append(header::HOST, HeaderValue::from_static("other.local"));
    duplicate_host.extensions_mut().insert(named);
    duplicate_host.extensions_mut().insert(verdict);
    ensure!(app.oneshot(duplicate_host).await?.status() == StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn verified_tcp_automation_only_relaxes_http_origin() -> anyhow::Result<()> {
    let state = fixture().await?;
    let app = Router::new().nest("/admin", http::router(automation_adapter(&state)));
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8123);
    let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8124);
    let connection = HttpTcpConnection::new(peer);
    let other_connection = HttpTcpConnection::new(other);
    let reused_address = HttpTcpConnection::new(peer);
    let attach = |request: &mut Request, marked_connection: &HttpTcpConnection| {
        request
            .extensions_mut()
            .insert(ConnectInfo(connection.clone()));
        request
            .extensions_mut()
            .insert(VerifiedAutomationClient::for_tcp_connection(
                marked_connection,
            ));
    };

    let mut mismatch = originless_request("/admin/auth/factor-providers")?;
    attach(&mut mismatch, &other_connection);
    ensure!(app.clone().oneshot(mismatch).await?.status() == StatusCode::FORBIDDEN);

    let mut reused = originless_request("/admin/auth/factor-providers")?;
    attach(&mut reused, &reused_address);
    ensure!(app.clone().oneshot(reused).await?.status() == StatusCode::FORBIDDEN);

    let mut missing_connection = originless_request("/admin/auth/factor-providers")?;
    missing_connection
        .extensions_mut()
        .insert(ConnectInfo(peer));
    missing_connection
        .extensions_mut()
        .insert(VerifiedAutomationClient::for_tcp_connection(&connection));
    ensure!(app.clone().oneshot(missing_connection).await?.status() == StatusCode::FORBIDDEN);

    let mut ambiguous = originless_request("/admin/auth/factor-providers")?;
    attach(&mut ambiguous, &connection);
    ambiguous.extensions_mut().insert(ConnectInfo(other));
    ensure!(app.clone().oneshot(ambiguous).await?.status() == StatusCode::BAD_REQUEST);

    let mut providers = originless_request("/admin/auth/factor-providers")?;
    attach(&mut providers, &connection);
    ensure!(app.clone().oneshot(providers).await?.status() == StatusCode::OK);

    let mut credentials = originless_request("/admin/credentials")?;
    attach(&mut credentials, &connection);
    ensure!(app.clone().oneshot(credentials).await?.status() == StatusCode::UNAUTHORIZED);

    let mut calls = originless_request("/admin/calls")?;
    *calls.method_mut() = Method::POST;
    attach(&mut calls, &connection);
    ensure!(app.clone().oneshot(calls).await?.status() == StatusCode::UNSUPPORTED_MEDIA_TYPE);

    let mut unmarked_calls = originless_post("/admin/calls")?;
    unmarked_calls.extensions_mut().insert(ConnectInfo(peer));
    ensure!(app.clone().oneshot(unmarked_calls).await?.status() == StatusCode::FORBIDDEN);

    let mut key = originless_request("/admin/auth/keys/challenges")?;
    *key.method_mut() = Method::POST;
    key.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    *key.body_mut() = Body::from(r#"{"username":"root","origin":"https://console.local"}"#);
    attach(&mut key, &connection);
    ensure!(app.clone().oneshot(key).await?.status() == StatusCode::FORBIDDEN);

    Ok(())
}

#[tokio::test]
async fn verified_automation_composes_login_credentials_and_calls() -> anyhow::Result<()> {
    let state = fixture().await?;
    let app = Router::new().nest("/admin", http::router(automation_adapter(&state)));
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001);
    let connection = HttpTcpConnection::new(peer);
    let attach = |request: &mut Request| {
        request
            .extensions_mut()
            .insert(ConnectInfo(connection.clone()));
        request
            .extensions_mut()
            .insert(VerifiedAutomationClient::for_tcp_connection(&connection));
    };

    let mut login = originless_request("/admin/auth/password/login")?;
    *login.method_mut() = Method::POST;
    login.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    *login.body_mut() = Body::from(r#"{"username":"root","password":"Ar7!cVN23#pxQe$Lr9"}"#);
    attach(&mut login);
    let response = app.clone().oneshot(login).await?;
    ensure!(response.status() == StatusCode::OK);
    let authentication: AuthenticationResponse =
        serde_json::from_slice(&to_bytes(response.into_body(), http::MAX_AUTH_BYTES).await?)?;
    let session = authentication
        .into_session()
        .ok()
        .context("automation login session")?;

    let mut credentials = originless_request("/admin/credentials")?;
    credentials.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", session.token))?,
    );
    attach(&mut credentials);
    ensure!(app.clone().oneshot(credentials).await?.status() == StatusCode::OK);

    let mut call = originless_request("/admin/calls")?;
    *call.method_mut() = Method::POST;
    call.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/protobuf"),
    );
    call.headers_mut().insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", session.token))?,
    );
    *call.body_mut() = Body::from(
        pb::ConsoleFrame {
            frame: Some(pb::console_frame::Frame::Call(pb::ActionCall {
                id: 42,
                action: "protocol.describe".into(),
                ..Default::default()
            })),
        }
        .encode_to_vec(),
    );
    attach(&mut call);
    let response = app.oneshot(call).await?;
    ensure!(response.status() == StatusCode::OK);
    let reply =
        pb::ConsoleFrame::decode(to_bytes(response.into_body(), http::MAX_CALL_BYTES).await?)?;
    ensure!(matches!(
        reply.frame,
        Some(pb::console_frame::Frame::Reply(_))
    ));
    Ok(())
}

#[tokio::test]
async fn browser_safe_gets_work_without_origin_but_posts_still_require_it() -> anyhow::Result<()> {
    let state = fixture().await?;
    let app = Router::new().nest("/admin", http::router(state));
    let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9002);
    let attach = |request: &mut Request| {
        request.extensions_mut().insert(ConnectInfo(peer));
    };

    let mut providers = originless_request("/admin/auth/factor-providers")?;
    attach(&mut providers);
    ensure!(app.clone().oneshot(providers).await?.status() == StatusCode::OK);

    let mut denied_post = originless_request("/admin/auth/password/login")?;
    *denied_post.method_mut() = Method::POST;
    denied_post.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    *denied_post.body_mut() = Body::from(r#"{"username":"root","password":"Ar7!cVN23#pxQe$Lr9"}"#);
    attach(&mut denied_post);
    ensure!(app.clone().oneshot(denied_post).await?.status() == StatusCode::FORBIDDEN);

    let mut login = request("/admin/auth/password/login")?;
    *login.method_mut() = Method::POST;
    login.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    *login.body_mut() = Body::from(r#"{"username":"root","password":"Ar7!cVN23#pxQe$Lr9"}"#);
    attach(&mut login);
    let response = app.clone().oneshot(login).await?;
    ensure!(response.status() == StatusCode::OK);
    let authentication: AuthenticationResponse =
        serde_json::from_slice(&to_bytes(response.into_body(), http::MAX_AUTH_BYTES).await?)?;
    let token = authentication
        .into_session()
        .ok()
        .context("browser login session")?
        .token;

    for path in ["/admin/credentials", "/admin/credentials/factors"] {
        let mut read = originless_request(path)?;
        read.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
        attach(&mut read);
        ensure!(app.clone().oneshot(read).await?.status() == StatusCode::OK);

        let mut bad_origin = request(path)?;
        bad_origin.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("https://attacker.invalid"),
        );
        bad_origin.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))?,
        );
        attach(&mut bad_origin);
        ensure!(app.clone().oneshot(bad_origin).await?.status() == StatusCode::FORBIDDEN);
    }

    let mut bad_host = originless_request("/admin/auth/factor-providers")?;
    bad_host.headers_mut().remove(header::HOST);
    attach(&mut bad_host);
    ensure!(app.clone().oneshot(bad_host).await?.status() == StatusCode::FORBIDDEN);
    let no_peer = originless_request("/admin/auth/factor-providers")?;
    ensure!(app.oneshot(no_peer).await?.status() == StatusCode::FORBIDDEN);
    Ok(())
}
