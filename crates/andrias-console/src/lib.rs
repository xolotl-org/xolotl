#![forbid(unsafe_code)]

//! `andrias-console` — the Console Protocol host and management-domain Gateway.
//!
//! HTTP is limited to bootstrap/auth. Post-login control is carried by the
//! Console WebSocket (`/ws`) using descriptor-named protocol actions. Every
//! action runs as a capability-scoped Operation or read-side
//! projection — no privileged backend handle and no raw shell.

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

mod auth;
mod mgmt;
pub mod protocol;
mod state;
mod ws;

pub use auth::{
    AuthError, BootstrapOutcome, ConsoleAuthConfig, DEFAULT_GLOBAL_SESSION_LIMIT,
    DEFAULT_IDLE_TTL_MS, DEFAULT_MAX_SESSIONS_PER_USER, DEFAULT_SESSION_TTL_MS,
    HARD_ARGON2_CONCURRENCY, HARD_GLOBAL_SESSION_LIMIT, HARD_MAX_SESSIONS_PER_USER,
    KeyChallengeRequest, KeyChallengeResponse, KeyLoginRequest, LoginRequest, LoginResponse,
    MAX_IDLE_TTL_MS, MAX_SESSION_TTL_MS, MIN_ARGON2_CONCURRENCY, MIN_GLOBAL_SESSION_LIMIT,
    MIN_IDLE_TTL_MS, MIN_MAX_SESSIONS_PER_USER, MIN_SESSION_TTL_MS, RootProvisioning,
    StepUpRequest, bootstrap_root_account, default_argon2_concurrency, root_random_password_needed,
};
pub use protocol::{
    ActionCall, ActionResult, ClientFrame, ClientHello, ConsoleErrorCode, ConsoleEvent,
    PrincipalSummary, ProtocolMetadata, ServerFrame, StreamCall,
};
pub use state::{
    ConsoleState, ConsoleTransportSecurityConfig, ConsoleTransportSecurityMode,
    ConsoleTrustedProxyConfig, ConsoleUnsafeTransportRelaxation, ConsoleWsConfig,
    DEFAULT_WS_EVENT_SEND_TIMEOUT, DEFAULT_WS_IDLE_TIMEOUT, DEFAULT_WS_MAX_BYTES_PER_SECOND,
    DEFAULT_WS_MAX_CONNECTIONS_GLOBAL, DEFAULT_WS_MAX_CONNECTIONS_PER_SOURCE,
    DEFAULT_WS_MAX_CONNECTIONS_PER_USER, DEFAULT_WS_MAX_FACT_LIMIT, DEFAULT_WS_MAX_FRAME_BYTES,
    DEFAULT_WS_MAX_FRAMES_PER_SECOND, DEFAULT_WS_MAX_STATE_LIST_LIMIT,
    DEFAULT_WS_MAX_SUBSCRIPTIONS, DEFAULT_WS_MAX_TRACE_LIMIT, HARD_MAX_WS_BYTES_PER_SECOND,
    HARD_MAX_WS_CONNECTIONS_GLOBAL, HARD_MAX_WS_CONNECTIONS_PER_SOURCE,
    HARD_MAX_WS_CONNECTIONS_PER_USER, HARD_MAX_WS_EVENT_SEND_TIMEOUT, HARD_MAX_WS_FACT_LIMIT,
    HARD_MAX_WS_FRAME_BYTES, HARD_MAX_WS_FRAMES_PER_SECOND, HARD_MAX_WS_IDLE_TIMEOUT,
    HARD_MAX_WS_STATE_LIST_LIMIT, HARD_MAX_WS_SUBSCRIPTIONS, HARD_MAX_WS_TRACE_LIMIT,
    MIN_WS_CONNECTIONS_GLOBAL, MIN_WS_CONNECTIONS_PER_SOURCE, MIN_WS_CONNECTIONS_PER_USER,
    MIN_WS_EVENT_SEND_TIMEOUT, MIN_WS_IDLE_TIMEOUT, MIN_WS_MAX_BYTES_PER_SECOND,
    MIN_WS_MAX_FACT_LIMIT, MIN_WS_MAX_FRAME_BYTES, MIN_WS_MAX_FRAMES_PER_SECOND,
    MIN_WS_MAX_STATE_LIST_LIMIT, MIN_WS_MAX_SUBSCRIPTIONS, MIN_WS_MAX_TRACE_LIMIT,
    NoPairingSecretDisplay, PairingSecretDisplay,
};

/// Build the console router.
pub fn router(state: Arc<ConsoleState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/auth/login", post(api_login))
        .route("/api/auth/key/challenge", post(api_key_challenge))
        .route("/api/auth/key/login", post(api_key_login))
        .route("/api/auth/step-up", post(api_step_up))
        .route("/ws", get(ws::upgrade))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE]),
        )
        .layer(TraceLayer::new_for_http())
}

/// Serve the console on `listener` until the process exits.
pub async fn serve(
    listener: tokio::net::TcpListener,
    state: Arc<ConsoleState>,
) -> anyhow::Result<()> {
    let app = router(state);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn api_login(
    State(st): State<Arc<ConsoleState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let source = verified_source_addr(&headers, Some(peer), &st.transport_security);
    validate_http_auth_origin(&st, &headers, Some(peer), &source)?;
    let response = st
        .auth
        .login(&st.boot, body, source)
        .await
        .map_err(auth_error)?;
    Ok(Json(response))
}

async fn api_key_challenge(
    State(st): State<Arc<ConsoleState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<KeyChallengeRequest>,
) -> Result<Json<KeyChallengeResponse>, (StatusCode, String)> {
    let source = verified_source_addr(&headers, Some(peer), &st.transport_security);
    let request_origin = validate_http_auth_origin(&st, &headers, Some(peer), &source)?;
    validate_key_login_origin(&st, &source, &body.origin, &request_origin)?;
    let response = st
        .auth
        .begin_key_login(&st.boot, body, source)
        .await
        .map_err(auth_error)?;
    Ok(Json(response))
}

async fn api_key_login(
    State(st): State<Arc<ConsoleState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<KeyLoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let source = verified_source_addr(&headers, Some(peer), &st.transport_security);
    let request_origin = validate_http_auth_origin(&st, &headers, Some(peer), &source)?;
    validate_key_login_origin(&st, &source, &body.origin, &request_origin)?;
    let response = st
        .auth
        .finish_key_login(&st.boot, body, source)
        .await
        .map_err(auth_error)?;
    Ok(Json(response))
}

async fn api_step_up(
    State(st): State<Arc<ConsoleState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<StepUpRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let source = verified_source_addr(&headers, Some(peer), &st.transport_security);
    validate_http_auth_origin(&st, &headers, Some(peer), &source)?;
    let bearer = match auth::bearer_from_headers(&headers) {
        Ok(bearer) => bearer,
        Err(e) => {
            record_http_auth_audit(&st, "console_credential", Some(&source), "missing_bearer")?;
            return Err(auth_error(e));
        }
    };
    let response = st
        .auth
        .step_up(&st.boot, bearer, body, source)
        .await
        .map_err(auth_error)?;
    Ok(Json(response))
}

pub(crate) fn verified_source_addr(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    transport: &ConsoleTransportSecurityConfig,
) -> String {
    let peer_ip = peer.map(|peer| peer.ip());
    if transport.trusts_peer(peer_ip)
        && transport.trusted_proxy.honor_x_forwarded_for
        && let Some(forwarded) = forwarded_client_addr(headers)
    {
        return forwarded;
    }
    peer_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn forwarded_client_addr(headers: &HeaderMap) -> Option<String> {
    let header = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))?;
    let value = match header.to_str() {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(?error, "forwarded source address header rejected");
            return None;
        }
    };
    value
        .split(',')
        .next()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
pub(crate) fn source_addr(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    verified_source_addr(headers, peer, &ConsoleTransportSecurityConfig::default())
}

fn record_http_auth_audit(
    st: &Arc<ConsoleState>,
    event: &'static str,
    source_addr: Option<&str>,
    outcome: &'static str,
) -> Result<(), (StatusCode, String)> {
    st.boot
        .record_gateway_audit(andrias_kernel::GatewayAudit {
            event,
            username: None,
            source_addr,
            outcome,
            mfa_level: None,
            details: None,
        })
        .map_err(|error| {
            tracing::warn!(
                ?error,
                event,
                outcome,
                source_addr = source_addr.unwrap_or("unknown"),
                "console HTTP audit record failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal authentication error".into(),
            )
        })
}

fn validate_http_auth_origin(
    st: &Arc<ConsoleState>,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    source: &str,
) -> Result<String, (StatusCode, String)> {
    match ws::validate_http_auth_headers(headers, peer, &st.transport_security) {
        Ok(origin) => Ok(origin),
        Err(message) => {
            record_http_auth_audit(st, "console_credential", Some(source), "origin_denied")?;
            Err((StatusCode::FORBIDDEN, message))
        }
    }
}

fn validate_key_login_origin(
    st: &Arc<ConsoleState>,
    source: &str,
    body_origin: &str,
    request_origin: &str,
) -> Result<(), (StatusCode, String)> {
    if body_origin.trim() == request_origin {
        Ok(())
    } else {
        record_http_auth_audit(st, "console_credential", Some(source), "origin_mismatch")?;
        Err((
            StatusCode::FORBIDDEN,
            "public-key login origin must match request origin".into(),
        ))
    }
}

pub(crate) fn auth_error(e: AuthError) -> (StatusCode, String) {
    match &e {
        AuthError::MissingBearer | AuthError::InvalidSession | AuthError::InvalidChallenge => {
            (StatusCode::UNAUTHORIZED, e.to_string())
        }
        AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, e.to_string()),
        AuthError::AccountUnavailable | AuthError::PermissionDenied => {
            (StatusCode::FORBIDDEN, e.to_string())
        }
        AuthError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, e.to_string()),
        AuthError::InvalidUsername => (StatusCode::BAD_REQUEST, e.to_string()),
        AuthError::State(_) | AuthError::Crypto(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal authentication error".into(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andrias_kernel::Bootstrap;
    use andrias_standard::{StandardConfig, install_standard};
    use andrias_types::{OutcomeRef, Value};
    use anyhow::{bail, ensure};
    use axum::http::HeaderValue;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    fn auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("console.local"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://console.local"),
        );
        headers
    }

    fn audit_outcomes(st: &ConsoleState, event: &str) -> anyhow::Result<Vec<String>> {
        Ok(st
            .boot
            .kernel
            .facts
            .all_facts()?
            .into_iter()
            .filter_map(|fact| match fact.outcome_ref {
                OutcomeRef::Inline(Value::Map(m))
                    if m.get("event").and_then(Value::as_str) == Some(event) =>
                {
                    m.get("outcome").and_then(Value::as_str).map(str::to_string)
                }
                _ => None,
            })
            .collect())
    }

    #[tokio::test]
    async fn router_builds() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default())?;
        let st = ConsoleState::shared(boot)?;
        drop(router(st));
        Ok(())
    }

    #[test]
    fn source_addr_prefers_peer_over_forwarded_headers_by_default() -> anyhow::Result<()> {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.8".parse()?);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        ensure!(
            source_addr(&headers, Some(peer)) == "127.0.0.1",
            "peer address did not take precedence"
        );
        Ok(())
    }

    #[test]
    fn source_addr_uses_forwarded_for_from_trusted_proxy() -> anyhow::Result<()> {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.8, 198.51.100.2".parse()?);
        let proxy_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let peer = SocketAddr::new(proxy_ip, 12345);
        let cfg = ConsoleTransportSecurityConfig {
            mode: ConsoleTransportSecurityMode::TrustedReverseProxy,
            trusted_proxy: ConsoleTrustedProxyConfig {
                peers: vec![proxy_ip],
                ..ConsoleTrustedProxyConfig::default()
            },
            unsafe_relaxations: Vec::new(),
        };
        ensure!(
            verified_source_addr(&headers, Some(peer), &cfg) == "203.0.113.8",
            "trusted proxy forwarded-for address was not used"
        );
        let untrusted_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 12345);
        ensure!(
            verified_source_addr(&headers, Some(untrusted_peer), &cfg) == "127.0.0.2",
            "untrusted proxy forwarded-for address was used"
        );
        Ok(())
    }

    #[test]
    fn auth_error_redacts_internal_details() -> anyhow::Result<()> {
        let (status, message) = auth_error(AuthError::State(
            "state://vault/console/root/password".into(),
        ));

        ensure!(
            status == StatusCode::INTERNAL_SERVER_ERROR,
            "internal auth error used wrong status"
        );
        ensure!(
            message == "internal authentication error",
            "internal auth error leaked details"
        );
        Ok(())
    }

    #[tokio::test]
    async fn step_up_missing_bearer_writes_gateway_audit() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        let st = ConsoleState::shared(boot)?;
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

        let result = api_step_up(
            State(st.clone()),
            ConnectInfo(peer),
            auth_headers(),
            Json(StepUpRequest {
                password: None,
                totp_code: None,
            }),
        )
        .await;
        let err = match result {
            Ok(_) => bail!("step-up without bearer unexpectedly succeeded"),
            Err(err) => err,
        };

        ensure!(
            err.0 == StatusCode::UNAUTHORIZED,
            "missing bearer used wrong status"
        );
        let outcomes = audit_outcomes(&st, "console_credential")?;
        ensure!(
            outcomes.iter().any(|outcome| outcome == "missing_bearer"),
            "missing bearer audit outcome was not recorded"
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_auth_origin_is_required() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        let st = ConsoleState::shared(boot)?;
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

        let result = api_login(
            State(st.clone()),
            ConnectInfo(peer),
            HeaderMap::new(),
            Json(LoginRequest {
                username: "root".into(),
                password: "password".into(),
                totp_code: None,
            }),
        )
        .await;
        let err = match result {
            Ok(_) => bail!("auth request without origin unexpectedly succeeded"),
            Err(err) => err,
        };

        ensure!(
            err.0 == StatusCode::FORBIDDEN,
            "missing origin used wrong status"
        );
        let outcomes = audit_outcomes(&st, "console_credential")?;
        ensure!(
            outcomes.iter().any(|outcome| outcome == "origin_denied"),
            "origin_denied audit outcome was not recorded"
        );
        Ok(())
    }

    #[tokio::test]
    async fn key_login_body_origin_must_match_request_origin() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        let st = ConsoleState::shared(boot)?;
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

        let result = api_key_challenge(
            State(st.clone()),
            ConnectInfo(peer),
            auth_headers(),
            Json(KeyChallengeRequest {
                username: "root".into(),
                origin: "https://other.local".into(),
            }),
        )
        .await;
        let err = match result {
            Ok(_) => bail!("mismatched key login origin unexpectedly succeeded"),
            Err(err) => err,
        };

        ensure!(
            err.0 == StatusCode::FORBIDDEN,
            "origin mismatch used wrong status"
        );
        let outcomes = audit_outcomes(&st, "console_credential")?;
        ensure!(
            outcomes.iter().any(|outcome| outcome == "origin_mismatch"),
            "origin_mismatch audit outcome was not recorded"
        );
        Ok(())
    }
}
