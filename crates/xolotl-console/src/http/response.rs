//! Safe JSON failures and cache policy shared by HTTP adapters.

use crate::{ConsoleAuthenticationAdmission, ConsoleErrorCode, ConsoleFailure};
use axum::{
    Json,
    extract::{FromRequest, FromRequestParts, Request, rejection::JsonRejection},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use super::{HttpState, context, peer::VerifiedPeer};
use std::sync::Arc;

/// JSON authentication input with the same safe failure contract as the handler.
pub(crate) struct AuthJson<T>(pub T);

/// Verify connection provenance and Origin before reading a bounded JSON body.
/// The admission remains owned through decoding and transfers to service dispatch.
pub(crate) struct AdmittedAuthJson<T>(pub T, pub ConsoleAuthenticationAdmission);

/// Key-login transcripts require an actual Origin even for verified automation.
pub(crate) struct AdmittedKeyJson<T>(pub T, pub ConsoleAuthenticationAdmission);

/// Routes that require a bearer reject malformed or missing headers before
/// reserving authentication capacity or reading the body.
pub(crate) struct AdmittedBearerJson<T>(pub T, pub ConsoleAuthenticationAdmission);

#[derive(Clone, Copy)]
enum AuthAdmission {
    OriginOnly,
    KeyOrigin,
    Bearer,
}

async fn admit_json<T>(
    request: Request,
    state: &Arc<HttpState>,
    admission: AuthAdmission,
) -> Result<(T, ConsoleAuthenticationAdmission), HttpFailure>
where
    T: serde::de::DeserializeOwned,
{
    let (mut parts, body) = request.into_parts();
    let peer = VerifiedPeer::from_request_parts(&mut parts, state).await?;
    let source = peer.source(&parts.headers, &state.transport_security);
    match admission {
        AuthAdmission::KeyOrigin => {
            context::validate_http_key_origin(state, &parts.headers, &peer, &source)?;
        }
        AuthAdmission::OriginOnly | AuthAdmission::Bearer => {
            context::validate_http_auth_origin(state, &parts.headers, &peer, &source)?;
        }
    }
    if matches!(admission, AuthAdmission::Bearer) {
        context::bearer_or_audit(state, &parts.headers, &source)?;
    }
    let request = Request::from_parts(parts, body);
    let capacity = state
        .service()
        .admit_authentication()
        .map_err(HttpFailure::from)?;
    let AuthJson(value) = tokio::time::timeout(
        state.request_body_timeout,
        AuthJson::from_request(request, &()),
    )
    .await
    .map_err(|_elapsed| {
        HttpFailure::from((
            StatusCode::REQUEST_TIMEOUT,
            "request body timed out".to_owned(),
        ))
    })??;
    Ok((value, capacity))
}

impl<T: serde::de::DeserializeOwned> FromRequest<Arc<HttpState>> for AdmittedAuthJson<T> {
    type Rejection = HttpFailure;

    async fn from_request(
        request: Request,
        state: &Arc<HttpState>,
    ) -> Result<Self, Self::Rejection> {
        admit_json(request, state, AuthAdmission::OriginOnly)
            .await
            .map(|(value, capacity)| Self(value, capacity))
    }
}

impl<T: serde::de::DeserializeOwned> FromRequest<Arc<HttpState>> for AdmittedKeyJson<T> {
    type Rejection = HttpFailure;

    async fn from_request(
        request: Request,
        state: &Arc<HttpState>,
    ) -> Result<Self, Self::Rejection> {
        admit_json(request, state, AuthAdmission::KeyOrigin)
            .await
            .map(|(value, capacity)| Self(value, capacity))
    }
}

impl<T: serde::de::DeserializeOwned> FromRequest<Arc<HttpState>> for AdmittedBearerJson<T> {
    type Rejection = HttpFailure;

    async fn from_request(
        request: Request,
        state: &Arc<HttpState>,
    ) -> Result<Self, Self::Rejection> {
        admit_json(request, state, AuthAdmission::Bearer)
            .await
            .map(|(value, capacity)| Self(value, capacity))
    }
}

impl<S, T> FromRequest<S> for AuthJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = HttpFailure;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|error| {
                let message = match &error {
                    JsonRejection::JsonSyntaxError(_) => "invalid JSON body",
                    JsonRejection::JsonDataError(_) => "invalid authentication request",
                    JsonRejection::MissingJsonContentType(_) => "expected application/json",
                    JsonRejection::BytesRejection(_) => {
                        "authentication request body could not be read within its limit"
                    }
                    _ => "invalid authentication request",
                };
                (error.status(), message.to_owned()).into()
            })
    }
}

/// Authentication responses carry credentials and must never be cached.
pub(crate) struct AuthResponse<T>(pub T);

impl<T: serde::Serialize> IntoResponse for AuthResponse<T> {
    fn into_response(self) -> Response {
        response_headers(Json(self.0).into_response(), None)
    }
}

/// HTTP status and safe failure data for the JSON authentication routes.
#[derive(Debug)]
pub(crate) struct HttpFailure {
    pub status: StatusCode,
    pub failure: Box<ConsoleFailure>,
}

impl From<ConsoleFailure> for HttpFailure {
    fn from(failure: ConsoleFailure) -> Self {
        Self {
            status: status(failure.code),
            failure: Box::new(failure),
        }
    }
}

impl From<(StatusCode, String)> for HttpFailure {
    fn from((status, message): (StatusCode, String)) -> Self {
        let code = match status {
            StatusCode::UNAUTHORIZED => ConsoleErrorCode::NotAuthenticated,
            StatusCode::FORBIDDEN => ConsoleErrorCode::Forbidden,
            StatusCode::TOO_MANY_REQUESTS => ConsoleErrorCode::RateLimited,
            status if status.is_server_error() => ConsoleErrorCode::Internal,
            _ => ConsoleErrorCode::BadRequest,
        };
        Self {
            status,
            failure: Box::new(ConsoleFailure::new(code, message)),
        }
    }
}

impl IntoResponse for HttpFailure {
    fn into_response(self) -> Response {
        let retry_after_ms = self.failure.retry_after_ms;
        response_headers(
            (self.status, Json(self.failure)).into_response(),
            retry_after_ms,
        )
    }
}

pub(super) fn response_headers(mut response: Response, retry_after_ms: Option<u64>) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(delay) = retry_after_ms {
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from(delay.div_ceil(1000)));
    }
    response
}

pub(super) fn status(code: ConsoleErrorCode) -> StatusCode {
    match code {
        ConsoleErrorCode::BadFrame | ConsoleErrorCode::BadRequest => StatusCode::BAD_REQUEST,
        ConsoleErrorCode::NotAuthenticated => StatusCode::UNAUTHORIZED,
        ConsoleErrorCode::Forbidden | ConsoleErrorCode::StepUpRequired => StatusCode::FORBIDDEN,
        ConsoleErrorCode::Conflict | ConsoleErrorCode::RegistryChanged => StatusCode::CONFLICT,
        ConsoleErrorCode::AdmissionRejected => StatusCode::UNPROCESSABLE_ENTITY,
        ConsoleErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ConsoleErrorCode::Internal | ConsoleErrorCode::OutcomeUnknown => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use axum::body::{Body, Bytes};
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::HeaderValue;
    use futures_util::StreamExt as _;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    fn verified_request(body: Body) -> anyhow::Result<Request> {
        let mut request = Request::builder()
            .header(header::HOST, "localhost")
            .header(header::ORIGIN, "https://localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)?;
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))));
        Ok(request)
    }

    async fn capacity_one_state() -> anyhow::Result<(Arc<HttpState>, String)> {
        let (console, _, _, password) = crate::service::tests::fixture().await?;
        let console = crate::ConsoleState::with_config(
            console.boot.clone(),
            crate::ConsoleConfig {
                max_concurrent_authentications: 1,
                session_store: Some(Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                ..Default::default()
            },
        )?;
        Ok((
            HttpState::new(console, super::super::HttpConfig::default()),
            password,
        ))
    }

    async fn extract_family(
        family: AuthAdmission,
        body: Body,
        state: &Arc<HttpState>,
    ) -> Result<(serde_json::Value, ConsoleAuthenticationAdmission), HttpFailure> {
        let mut request = verified_request(body)
            .map_err(|error| HttpFailure::from((StatusCode::BAD_REQUEST, error.to_string())))?;
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );
        match family {
            AuthAdmission::OriginOnly => {
                let AdmittedAuthJson(value, admission) =
                    AdmittedAuthJson::from_request(request, state).await?;
                Ok((value, admission))
            }
            AuthAdmission::KeyOrigin => {
                let AdmittedKeyJson(value, admission) =
                    AdmittedKeyJson::from_request(request, state).await?;
                Ok((value, admission))
            }
            AuthAdmission::Bearer => {
                let AdmittedBearerJson(value, admission) =
                    AdmittedBearerJson::from_request(request, state).await?;
                Ok((value, admission))
            }
        }
    }

    #[tokio::test]
    async fn extracted_login_transfers_saturated_capacity_to_dispatch() -> anyhow::Result<()> {
        let (state, password) = capacity_one_state().await?;
        let body = crate::LoginRequest {
            username: "root".into(),
            password,
            second_factor: None,
        };
        let request = verified_request(Body::from(serde_json::to_vec(&body)?))?;
        let headers = request.headers().clone();
        let admitted = AdmittedAuthJson::<crate::LoginRequest>::from_request(request, &state)
            .await
            .map_err(|failure| anyhow::anyhow!("{failure:?}"))?;
        ensure!(state.console.authentications.available_permits() == 0);
        let failure = state
            .service()
            .login(body, "embedded".into())
            .await
            .err()
            .context("native login must remain bounded")?;
        ensure!(failure.code == ConsoleErrorCode::RateLimited);
        let failure = state
            .service()
            .refresh("token", "embedded".into())
            .await
            .err()
            .context("native refresh must remain bounded")?;
        ensure!(failure.code == ConsoleErrorCode::RateLimited);
        let rejection = AdmittedAuthJson::<crate::LoginRequest>::from_request(
            verified_request(Body::from("{"))?,
            &state,
        )
        .await
        .err()
        .context("extraction must remain saturated")?;
        ensure!(rejection.status == StatusCode::TOO_MANY_REQUESTS);
        ensure!(state.console.authentications.available_permits() == 0);
        let AuthResponse(response) = super::super::auth::api_login(
            axum::extract::State(state.clone()),
            VerifiedPeer::Tcp(SocketAddr::from(([127, 0, 0, 1], 12345))),
            headers,
            admitted,
        )
        .await
        .map_err(|failure| anyhow::anyhow!("{failure:?}"))?;
        ensure!(response.into_session().is_ok());
        ensure!(state.console.authentications.available_permits() == 1);
        Ok(())
    }

    #[tokio::test]
    async fn all_authentication_extractors_hold_and_release_admission() -> anyhow::Result<()> {
        let (state, _) = capacity_one_state().await?;
        for family in [
            AuthAdmission::OriginOnly,
            AuthAdmission::KeyOrigin,
            AuthAdmission::Bearer,
        ] {
            let (value, admission) = extract_family(family, Body::from("{}"), &state)
                .await
                .map_err(|failure| anyhow::anyhow!("{failure:?}"))?;
            ensure!(value == serde_json::json!({}));
            ensure!(state.console.authentications.available_permits() == 0);
            let failure = state
                .service()
                .admit_authentication()
                .err()
                .context("successful extraction must retain admission")?;
            ensure!(failure.code == ConsoleErrorCode::RateLimited);
            drop(admission);
            ensure!(state.console.authentications.available_permits() == 1);
            let next = state.service().admit_authentication()?;
            ensure!(state.console.authentications.available_permits() == 0);
            drop(next);
            ensure!(state.console.authentications.available_permits() == 1);
        }
        Ok(())
    }

    #[tokio::test]
    async fn all_authentication_extractors_release_on_invalid_or_oversized_body()
    -> anyhow::Result<()> {
        let (state, _) = capacity_one_state().await?;
        for family in [
            AuthAdmission::OriginOnly,
            AuthAdmission::KeyOrigin,
            AuthAdmission::Bearer,
        ] {
            for (body, status) in [
                ("{".to_owned(), StatusCode::BAD_REQUEST),
                (
                    " ".repeat(2 * 1024 * 1024 + 1),
                    StatusCode::PAYLOAD_TOO_LARGE,
                ),
            ] {
                let failure = extract_family(family, Body::from(body), &state)
                    .await
                    .err()
                    .context("invalid body must fail")?;
                ensure!(failure.status == status);
                ensure!(state.console.authentications.available_permits() == 1);
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn all_authentication_extractors_release_on_body_timeout() -> anyhow::Result<()> {
        let (state, _) = capacity_one_state().await?;
        let state = HttpState::new(
            state.console.clone(),
            super::super::HttpConfig {
                request_body_timeout: Duration::ZERO,
                ..Default::default()
            },
        );
        for family in [
            AuthAdmission::OriginOnly,
            AuthAdmission::KeyOrigin,
            AuthAdmission::Bearer,
        ] {
            let body =
                Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
            let failure = extract_family(family, body, &state)
                .await
                .err()
                .context("stalled body must time out")?;
            ensure!(failure.status == StatusCode::REQUEST_TIMEOUT);
            ensure!(state.console.authentications.available_permits() == 1);
        }
        Ok(())
    }

    #[tokio::test]
    async fn all_authentication_extractors_release_on_cancellation() -> anyhow::Result<()> {
        let (state, _) = capacity_one_state().await?;
        for family in [
            AuthAdmission::OriginOnly,
            AuthAdmission::KeyOrigin,
            AuthAdmission::Bearer,
        ] {
            let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
            let body = Body::from_stream(futures_util::stream::once(async move {
                polled_tx
                    .send(())
                    .map_err(|_error| std::io::Error::other("test receiver dropped"))?;
                std::future::pending::<Result<Bytes, std::io::Error>>().await
            }));
            let task_state = state.clone();
            let task = tokio::spawn(async move { extract_family(family, body, &task_state).await });
            tokio::time::timeout(Duration::from_secs(5), polled_rx).await??;
            ensure!(state.console.authentications.available_permits() == 0);
            task.abort();
            let failure = task.await.err().context("extraction must be cancelled")?;
            ensure!(failure.is_cancelled());
            ensure!(state.console.authentications.available_permits() == 1);
        }
        Ok(())
    }

    #[tokio::test]
    async fn authentication_body_admission_precedes_json_decoding() -> anyhow::Result<()> {
        let (console, _, _, _) = crate::service::tests::fixture().await?;
        let state = HttpState::new(console, super::super::HttpConfig::default());
        let permits = (0..state.console.authentications.available_permits())
            .map(|_| state.service().admit_authentication())
            .collect::<Result<Vec<_>, _>>()?;
        let request = verified_request(Body::from("{"))?;
        let failure = AdmittedAuthJson::<crate::LoginRequest>::from_request(request, &state)
            .await
            .err()
            .context("capacity should reject before invalid JSON")?;
        ensure!(failure.status == StatusCode::TOO_MANY_REQUESTS);
        ensure!(failure.failure.code == ConsoleErrorCode::RateLimited);
        drop(permits);
        let request = verified_request(Body::from("{"))?;
        let failure = AdmittedAuthJson::<crate::LoginRequest>::from_request(request, &state)
            .await
            .err()
            .context("JSON rejection after capacity release")?;
        ensure!(failure.status == StatusCode::BAD_REQUEST);
        ensure!(state.console.authentications.available_permits() > 0);
        Ok(())
    }

    #[tokio::test]
    async fn stalled_authentication_body_times_out_and_releases_shared_capacity()
    -> anyhow::Result<()> {
        let (console, _, _, _) = crate::service::tests::fixture().await?;
        let state = HttpState::new(
            console.clone(),
            super::super::HttpConfig {
                request_body_timeout: Duration::ZERO,
                ..Default::default()
            },
        );
        let available = state.console.authentications.available_permits();
        ensure!(available > 0);
        let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
        let body = Body::from_stream(
            futures_util::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(
                b"private-auth-sentinel",
            ))])
            .chain(futures_util::stream::once(async move {
                if polled_tx.send(()).is_err() {
                    return Err(std::io::Error::other("test receiver dropped"));
                }
                std::future::pending::<Result<Bytes, std::io::Error>>().await
            })),
        );
        let request = verified_request(body)?;
        let task = tokio::spawn(async move {
            AdmittedAuthJson::<crate::LoginRequest>::from_request(request, &state).await
        });
        tokio::time::timeout(Duration::from_secs(5), polled_rx).await??;
        ensure!(console.authentications.available_permits() == available - 1);
        let result = tokio::time::timeout(Duration::from_secs(5), task).await??;
        let response = result
            .err()
            .context("stalled authentication body should time out")?
            .into_response();
        ensure!(response.status() == StatusCode::REQUEST_TIMEOUT);
        ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
        let body = axum::body::to_bytes(response.into_body(), 4096).await?;
        let failure: ConsoleFailure = serde_json::from_slice(&body)?;
        ensure!(failure.code == ConsoleErrorCode::BadRequest);
        ensure!(&*failure.message == "request body timed out");
        ensure!(!std::str::from_utf8(&body)?.contains("private-auth-sentinel"));
        ensure!(console.authentications.available_permits() == available);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_origin_is_rejected_before_body_poll_and_capacity() -> anyhow::Result<()> {
        let (console, _, _, _) = crate::service::tests::fixture().await?;
        let state = HttpState::new(console.clone(), super::super::HttpConfig::default());
        let available = console.authentications.available_permits();
        let polled = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&polled);
        let body = Body::from_stream(futures_util::stream::once(async move {
            observed.store(true, Ordering::SeqCst);
            std::future::pending::<Result<Bytes, std::io::Error>>().await
        }));
        let mut request = verified_request(body)?;
        request.headers_mut().insert(
            header::ORIGIN,
            HeaderValue::from_static("https://another.example"),
        );
        let failure = tokio::time::timeout(
            Duration::from_millis(200),
            AdmittedAuthJson::<crate::LoginRequest>::from_request(request, &state),
        )
        .await?
        .err()
        .context("invalid Origin must fail before reading the body")?;
        ensure!(failure.status == StatusCode::FORBIDDEN);
        ensure!(!polled.load(Ordering::SeqCst));
        ensure!(console.authentications.available_permits() == available);
        Ok(())
    }

    #[tokio::test]
    async fn missing_bearer_is_rejected_before_body_poll_and_capacity() -> anyhow::Result<()> {
        let (console, _, _, _) = crate::service::tests::fixture().await?;
        let state = HttpState::new(console.clone(), super::super::HttpConfig::default());
        let available = console.authentications.available_permits();
        let polled = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&polled);
        let body = Body::from_stream(futures_util::stream::once(async move {
            observed.store(true, Ordering::SeqCst);
            std::future::pending::<Result<Bytes, std::io::Error>>().await
        }));
        let request = verified_request(body)?;
        let failure = tokio::time::timeout(
            Duration::from_millis(200),
            AdmittedBearerJson::<crate::StepUpRequest>::from_request(request, &state),
        )
        .await?
        .err()
        .context("missing bearer must fail before reading the body")?;
        ensure!(failure.status == StatusCode::UNAUTHORIZED);
        ensure!(!polled.load(Ordering::SeqCst));
        ensure!(console.authentications.available_permits() == available);
        Ok(())
    }

    #[tokio::test]
    async fn key_login_requires_origin_before_body_even_for_automation() -> anyhow::Result<()> {
        let (console, _, _, _) = crate::service::tests::fixture().await?;
        let state = HttpState::new(
            console.clone(),
            super::super::HttpConfig {
                originless_clients: super::super::OriginlessClientPolicy::AllowVerifiedAutomation,
                ..Default::default()
            },
        );
        let available = console.authentications.available_permits();
        let polled = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&polled);
        let body = Body::from_stream(futures_util::stream::once(async move {
            observed.store(true, Ordering::SeqCst);
            std::future::pending::<Result<Bytes, std::io::Error>>().await
        }));
        let connection =
            super::super::HttpTcpConnection::new(SocketAddr::from(([127, 0, 0, 1], 12345)));
        let automation = super::super::VerifiedAutomationClient::for_tcp_connection(&connection);
        let mut request = Request::builder()
            .header(header::HOST, "localhost")
            .header(header::CONTENT_TYPE, "application/json")
            .body(body)?;
        request.extensions_mut().insert(ConnectInfo(connection));
        request.extensions_mut().insert(automation);
        let failure = tokio::time::timeout(
            Duration::from_millis(200),
            AdmittedKeyJson::<crate::KeyChallengeRequest>::from_request(request, &state),
        )
        .await?
        .err()
        .context("key login must require a real Origin before reading the body")?;
        ensure!(failure.status == StatusCode::FORBIDDEN);
        ensure!(!polled.load(Ordering::SeqCst));
        ensure!(console.authentications.available_permits() == available);
        Ok(())
    }
}
