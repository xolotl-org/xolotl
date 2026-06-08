#![forbid(unsafe_code)]

//! `nexus-console` — the Console Protocol host and management-domain Gateway.
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

pub mod auth;
pub mod mgmt;
pub mod protocol;
pub mod state;
pub mod ws;

pub use auth::{
    AuthError, BootstrapOutcome, ConsoleAuthConfig, ConsolePrincipal, KeyChallengeRequest,
    KeyChallengeResponse, KeyLoginRequest, LoginRequest, LoginResponse, RootProvisioning,
    StepUpRequest, bootstrap_root_account, root_random_password_needed,
};
pub use mgmt::MgmtError;
pub use protocol::{
    ActionCall, ActionResult, ClientFrame, ClientHello, ConsoleErrorCode, ConsoleEvent,
    PrincipalSummary, ProtocolMetadata, ServerFrame, StreamCall,
};
pub use state::{ConsoleState, ConsoleWsConfig};

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
    let source = source_addr(&headers, Some(peer));
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
    let source = source_addr(&headers, Some(peer));
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
    let source = source_addr(&headers, Some(peer));
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
    let source = source_addr(&headers, Some(peer));
    let bearer = match auth::bearer_from_headers(&headers) {
        Ok(bearer) => bearer,
        Err(e) => {
            record_http_auth_audit(&st, "console_credential", Some(&source), "missing_bearer");
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

pub(crate) fn source_addr(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    if let Some(peer) = peer {
        return peer.ip().to_string();
    }
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("unknown")
        .to_string()
}

fn record_http_auth_audit(
    st: &Arc<ConsoleState>,
    event: &'static str,
    source_addr: Option<&str>,
    outcome: &'static str,
) {
    let _ = st.boot.record_gateway_audit(nexus_kernel::GatewayAudit {
        event,
        username: None,
        source_addr,
        outcome,
        mfa_level: None,
        details: None,
    });
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
    use nexus_actors::{StandardConfig, install_standard};
    use nexus_kernel::Bootstrap;
    use nexus_types::{OutcomeRef, Value};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn audit_outcomes(st: &ConsoleState, event: &str) -> Vec<String> {
        st.boot
            .kernel
            .facts
            .all_facts()
            .unwrap()
            .into_iter()
            .filter_map(|fact| match fact.outcome_ref {
                OutcomeRef::Inline(Value::Map(m))
                    if m.get("event").and_then(Value::as_str) == Some(event) =>
                {
                    m.get("outcome").and_then(Value::as_str).map(str::to_string)
                }
                _ => None,
            })
            .collect()
    }

    #[tokio::test]
    async fn router_builds() {
        let boot = Arc::new(Bootstrap::in_memory());
        assert!(install_standard(&boot, &StandardConfig::default()).is_ok());
        let st = ConsoleState::shared(boot);
        let _ = router(st);
    }

    #[test]
    fn source_addr_prefers_peer_over_forwarded_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.8".parse().unwrap());
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        assert_eq!(source_addr(&headers, Some(peer)), "127.0.0.1");
    }

    #[test]
    fn auth_error_redacts_internal_details() {
        let (status, message) = auth_error(AuthError::State(
            "state://vault/console/root/password".into(),
        ));

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(message, "internal authentication error");
    }

    #[tokio::test]
    async fn step_up_missing_bearer_writes_gateway_audit() {
        let boot = Arc::new(Bootstrap::in_memory());
        let st = ConsoleState::shared(boot);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

        let err = api_step_up(
            State(st.clone()),
            ConnectInfo(peer),
            HeaderMap::new(),
            Json(StepUpRequest {
                password: None,
                totp_code: None,
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
        assert!(audit_outcomes(&st, "console_credential").contains(&"missing_bearer".into()));
    }
}
