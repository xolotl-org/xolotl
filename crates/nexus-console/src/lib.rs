//! `nexus-console` — the Web Console backend: a management-domain Gateway
//! (§18.4 / §24.3).
//!
//! It exposes runtime management over HTTP/WS, but every action is an ordinary
//! capability-bound Operation on `state://kernel/*` (config write+CAS, inspect,
//! subscribe) — there is no bespoke management wire protocol and no privileged
//! backdoor. The web front-end (`nexus-web-console`, a Leptos/Wasm satellite
//! repo) is embedded as static assets by the daemon; this crate is the
//! engineering host.

use axum::extract::{Query, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

pub mod auth;
pub mod mgmt;
pub mod state;

pub use auth::{
    AuthError, BootstrapOutcome, ConsoleAuthConfig, ConsolePrincipal, KeyChallengeRequest,
    KeyChallengeResponse, KeyLoginRequest, LoginRequest, LoginResponse, RootProvisioning,
    bootstrap_root_account,
};
pub use mgmt::MgmtError;
pub use state::ConsoleState;

/// Build the console router.
pub fn router(state: Arc<ConsoleState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/auth/login", post(api_login))
        .route("/api/auth/key/challenge", post(api_key_challenge))
        .route("/api/auth/key/login", post(api_key_login))
        .route("/api/auth/logout", post(api_logout))
        .route("/api/inspect", get(api_inspect))
        .route("/api/config", post(api_write_config))
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
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn api_login(
    State(st): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let source = source_addr(&headers);
    let response = st
        .auth
        .login(&st.boot, body, source)
        .await
        .map_err(auth_error)?;
    Ok(Json(response))
}

async fn api_key_challenge(
    State(st): State<Arc<ConsoleState>>,
    Json(body): Json<KeyChallengeRequest>,
) -> Result<Json<KeyChallengeResponse>, (StatusCode, String)> {
    let response = st
        .auth
        .begin_key_login(&st.boot, body)
        .await
        .map_err(auth_error)?;
    Ok(Json(response))
}

async fn api_key_login(
    State(st): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    Json(body): Json<KeyLoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, String)> {
    let source = source_addr(&headers);
    let response = st
        .auth
        .finish_key_login(&st.boot, body, source)
        .await
        .map_err(auth_error)?;
    Ok(Json(response))
}

async fn api_logout(
    State(st): State<Arc<ConsoleState>>,
    headers: HeaderMap,
) -> Result<StatusCode, (StatusCode, String)> {
    let bearer = auth::bearer_from_headers(&headers).map_err(auth_error)?;
    st.auth.logout(&st.boot, bearer).await.map_err(auth_error)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct InspectQuery {
    path: String,
    #[serde(default)]
    prefix: bool,
}

async fn api_inspect(
    State(st): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    Query(q): Query<InspectQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let principal = authenticate(&st, &headers).await?;
    if q.prefix {
        let entries = mgmt::inspect_prefix(&st, &principal, &q.path)
            .await
            .map_err(bad_request)?;
        let map: BTreeMap<String, nexus_types::Value> = entries.into_iter().collect();
        Ok(Json(serde_json::to_value(map).unwrap_or_default()))
    } else {
        let v = mgmt::inspect(&st, &principal, &q.path)
            .await
            .map_err(bad_request)?;
        Ok(Json(
            serde_json::to_value(v).unwrap_or(serde_json::Value::Null),
        ))
    }
}

#[derive(Debug, Deserialize)]
struct WriteConfigBody {
    path: String,
    value: nexus_types::Value,
    #[serde(default)]
    expected_version: Option<u64>,
}

async fn api_write_config(
    State(st): State<Arc<ConsoleState>>,
    headers: HeaderMap,
    Json(body): Json<WriteConfigBody>,
) -> Result<StatusCode, (StatusCode, String)> {
    let principal = authenticate(&st, &headers).await?;
    mgmt::write_config(
        &st,
        &principal,
        &body.path,
        body.value,
        body.expected_version,
    )
    .await
    .map_err(|e| match e {
        MgmtError::Conflict { .. } => (StatusCode::CONFLICT, e.to_string()),
        MgmtError::NotManageable(_) => (StatusCode::FORBIDDEN, e.to_string()),
        MgmtError::Auth(e) => auth_error(e),
        other => (StatusCode::BAD_REQUEST, other.to_string()),
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn authenticate(
    st: &Arc<ConsoleState>,
    headers: &HeaderMap,
) -> Result<ConsolePrincipal, (StatusCode, String)> {
    let bearer = auth::bearer_from_headers(headers).map_err(auth_error)?;
    st.auth
        .authenticate_token(&st.boot, bearer)
        .await
        .map_err(auth_error)
}

fn source_addr(headers: &HeaderMap) -> String {
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

fn auth_error(e: AuthError) -> (StatusCode, String) {
    let status = match e {
        AuthError::MissingBearer | AuthError::InvalidSession | AuthError::InvalidChallenge => {
            StatusCode::UNAUTHORIZED
        }
        AuthError::InvalidCredentials => StatusCode::UNAUTHORIZED,
        AuthError::AccountUnavailable | AuthError::PermissionDenied => StatusCode::FORBIDDEN,
        AuthError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        AuthError::InvalidUsername => StatusCode::BAD_REQUEST,
        AuthError::State(_) | AuthError::Crypto(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, e.to_string())
}

fn bad_request(e: MgmtError) -> (StatusCode, String) {
    match e {
        MgmtError::NotManageable(_) => (StatusCode::FORBIDDEN, e.to_string()),
        MgmtError::Auth(e) => auth_error(e),
        other => (StatusCode::BAD_REQUEST, other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_actors::{StandardConfig, install_standard};
    use nexus_kernel::Bootstrap;
    use std::sync::Arc;

    #[tokio::test]
    async fn router_builds() {
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default());
        let st = ConsoleState::shared(boot);
        let _ = router(st);
    }
}
