//! JSON adapters for shared authentication and credential services.

use super::context::{
    bearer_or_audit, optional_bearer_or_audit, validate_http_auth_origin, validate_http_key_origin,
    validate_http_read_origin, validate_key_login_origin,
};
use super::{
    AdmittedAuthJson, AdmittedBearerJson, AdmittedKeyJson, AuthResponse, HttpFailure, HttpState,
    peer::VerifiedPeer, response::response_headers,
};
use crate::{
    AuthenticationResponse, CancelAuthenticationRequest, ContinueAuthenticationRequest,
    ExternalAssertionRequest, KeyChallengeRequest, KeyChallengeResponse, KeyLoginRequest,
    LoginRequest, LoginResponse, PasskeyLoginBeginRequest, PasskeyLoginBeginResponse,
    PasskeyLoginFinishRequest, PasskeyRegisterBeginRequest, PasskeyRegisterBeginResponse,
    PasskeyRegisterFinishRequest, PasskeyRegisterFinishResponse, StepUpRequest, mfa,
};
use axum::{
    extract::State,
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::Arc;

pub(super) async fn api_credentials(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedBearerJson(body, admission): AdmittedBearerJson<crate::credentials::CredentialRequest>,
) -> Result<AuthResponse<crate::credentials::CredentialResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let bearer = bearer_or_audit(&st, &headers, &source)?;
    let response = admission
        .credentials(bearer, body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_credential_status(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
) -> Result<AuthResponse<crate::credentials::CredentialResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_read_origin(&st, &headers, &peer, &source)?;
    let bearer = bearer_or_audit(&st, &headers, &source)?;
    let response = st
        .service()
        .credentials(
            bearer,
            crate::credentials::CredentialRequest {
                username: None,
                operation: crate::credentials::CredentialOperation::Status {},
            },
            source,
        )
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_login(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedAuthJson(body, admission): AdmittedAuthJson<LoginRequest>,
) -> Result<AuthResponse<AuthenticationResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let response = admission
        .login(body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_external_exchange(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedAuthJson(body, admission): AdmittedAuthJson<ExternalAssertionRequest>,
) -> Result<AuthResponse<AuthenticationResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let assertion = URL_SAFE_NO_PAD.decode(body.assertion).map_err(|_error| {
        HttpFailure::from((
            axum::http::StatusCode::BAD_REQUEST,
            "invalid external assertion encoding".into(),
        ))
    })?;
    let response = admission
        .exchange_external(&assertion, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_key_challenge(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedKeyJson(body, admission): AdmittedKeyJson<KeyChallengeRequest>,
) -> Result<AuthResponse<KeyChallengeResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    let request_origin = validate_http_key_origin(&st, &headers, &peer, &source)?;
    validate_key_login_origin(&st, &source, &body.origin, &request_origin)?;
    let response = admission
        .begin_key_login(body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_key_login(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedKeyJson(body, admission): AdmittedKeyJson<KeyLoginRequest>,
) -> Result<AuthResponse<AuthenticationResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    let request_origin = validate_http_key_origin(&st, &headers, &peer, &source)?;
    validate_key_login_origin(&st, &source, &body.origin, &request_origin)?;
    let response = admission
        .finish_key_login(body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_passkey_register_begin(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedBearerJson(body, admission): AdmittedBearerJson<PasskeyRegisterBeginRequest>,
) -> Result<AuthResponse<PasskeyRegisterBeginResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let bearer = bearer_or_audit(&st, &headers, &source)?;
    let response = admission
        .begin_passkey_registration(bearer, body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_passkey_register_finish(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedBearerJson(body, admission): AdmittedBearerJson<PasskeyRegisterFinishRequest>,
) -> Result<AuthResponse<PasskeyRegisterFinishResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let bearer = bearer_or_audit(&st, &headers, &source)?;
    let response = admission
        .finish_passkey_registration(bearer, body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_passkey_login_begin(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedAuthJson(body, admission): AdmittedAuthJson<PasskeyLoginBeginRequest>,
) -> Result<AuthResponse<PasskeyLoginBeginResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let response = admission
        .begin_passkey_login(body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_passkey_login_finish(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedAuthJson(body, admission): AdmittedAuthJson<PasskeyLoginFinishRequest>,
) -> Result<AuthResponse<LoginResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let response = admission
        .finish_passkey_login(body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_step_up(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedBearerJson(body, admission): AdmittedBearerJson<StepUpRequest>,
) -> Result<AuthResponse<AuthenticationResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let bearer = bearer_or_audit(&st, &headers, &source)?;
    let response = admission
        .step_up(bearer, body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_continue_authentication(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedAuthJson(body, admission): AdmittedAuthJson<ContinueAuthenticationRequest>,
) -> Result<AuthResponse<AuthenticationResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let bearer = optional_bearer_or_audit(&st, &headers, &source)?;
    let response = admission
        .continue_authentication(bearer, body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_cancel_authentication(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedAuthJson(body, admission): AdmittedAuthJson<CancelAuthenticationRequest>,
) -> Result<AuthResponse<()>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let bearer = optional_bearer_or_audit(&st, &headers, &source)?;
    admission
        .cancel_authentication(bearer, body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(()))
}

pub(super) async fn api_refresh(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
) -> Result<AuthResponse<LoginResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let bearer = bearer_or_audit(&st, &headers, &source)?;
    let response = st
        .service()
        .refresh(bearer, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_mfa(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
    AdmittedBearerJson(body, admission): AdmittedBearerJson<mfa::MfaRequest>,
) -> Result<AuthResponse<mfa::MfaResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_auth_origin(&st, &headers, &peer, &source)?;
    let bearer = bearer_or_audit(&st, &headers, &source)?;
    let response = admission
        .mfa(bearer, body, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

pub(super) async fn api_mfa_providers(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
) -> Result<Response, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_read_origin(&st, &headers, &peer, &source)?;
    Ok(response_headers(
        (
            [(header::CONTENT_TYPE, "application/json")],
            st.mfa_provider_json.clone(),
        )
            .into_response(),
        None,
    ))
}

pub(super) async fn api_mfa_status(
    State(st): State<Arc<HttpState>>,
    peer: VerifiedPeer,
    headers: HeaderMap,
) -> Result<AuthResponse<mfa::MfaResponse>, HttpFailure> {
    let source = peer.source(&headers, &st.transport_security);
    validate_http_read_origin(&st, &headers, &peer, &source)?;
    let bearer = bearer_or_audit(&st, &headers, &source)?;
    let response = st
        .service()
        .mfa(bearer, mfa::MfaRequest::Status {}, source)
        .await
        .map_err(HttpFailure::from)?;
    Ok(AuthResponse(response))
}

#[cfg(test)]
mod tests {
    use super::super::context::auth_error;
    use super::*;
    use crate::http::transport::{source_addr, verified_source_addr};
    use crate::http::{HttpApi, HttpConfig, HttpEndpoint, router};
    use crate::{
        AuthError, ConsoleState, ConsoleTransportSecurityConfig, ConsoleTransportSecurityMode,
        ConsoleTrustedProxyConfig,
    };
    use anyhow::{Context, bail, ensure};
    use axum::http::HeaderValue;
    use axum::http::{StatusCode, header};
    use axum::{body::Body, extract::connect_info::ConnectInfo, http::Request};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tower::ServiceExt as _;
    use xolotl_kernel::Bootstrap;
    use xolotl_standard::{StandardConfig, install_standard};
    use xolotl_types::Value;

    fn auth_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static("console.local"));
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://console.local"),
        );
        headers
    }

    fn audit_outcomes(st: &HttpState, event: &str) -> anyhow::Result<Vec<String>> {
        Ok(st
            .console
            .boot
            .kernel()
            .facts()
            .all_facts()?
            .into_iter()
            .filter_map(|fact| match fact.outcome {
                Some(value)
                    if value
                        .as_map()
                        .and_then(|m| m.get("event"))
                        .and_then(Value::as_str)
                        == Some(event) =>
                {
                    value
                        .as_map()
                        .and_then(|m| m.get("outcome"))
                        .and_then(Value::as_str)
                        .map(str::to_string)
                }
                _ => None,
            })
            .collect())
    }

    #[tokio::test]
    async fn router_builds() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default())?;
        let st = HttpState::new(
            ConsoleState::shared(
                boot,
                std::sync::Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                )),
            )?,
            HttpConfig::default(),
        );
        drop(router(st));
        Ok(())
    }

    #[tokio::test]
    async fn public_factor_discovery_reuses_frozen_response_bytes() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        install_standard(&boot, &StandardConfig::default())?;
        let adapter = HttpState::new(
            ConsoleState::shared(
                boot,
                std::sync::Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                )),
            )?,
            HttpConfig::default(),
        );
        let expected = serde_json::to_vec(&adapter.service().mfa_providers())?;
        let app = HttpApi::new()
            .with_endpoint(HttpEndpoint::FactorProviders)
            .router(adapter.clone());
        let peer: SocketAddr = "127.0.0.1:12000".parse()?;

        for _ in 0..2 {
            let mut request = Request::builder()
                .method("GET")
                .uri("/auth/factor-providers")
                .header(header::HOST, "console.local")
                .body(Body::empty())?;
            request.extensions_mut().insert(ConnectInfo(peer));
            let response = app.clone().oneshot(request).await?;
            ensure!(response.status() == StatusCode::OK);
            ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
            ensure!(response.headers()[header::CONTENT_TYPE] == "application/json");
            let bytes = axum::body::to_bytes(response.into_body(), expected.len()).await?;
            ensure!(bytes.as_ref() == expected.as_slice());
            ensure!(bytes.as_ptr() == adapter.mfa_provider_json.as_ptr());
        }
        Ok(())
    }

    #[tokio::test]
    async fn external_http_exchange_uses_real_route_origin_peer_and_bearer_calls()
    -> anyhow::Result<()> {
        let (console, _, _, _) = crate::service::tests::authentication::external_fixture(
            None,
            xolotl_types::CapSet::from_strs(["*://**"])?,
            60_000,
        )
        .await?;
        let adapter = HttpState::new(console, HttpConfig::default());
        let api = HttpApi::new()
            .with_endpoint(HttpEndpoint::ExternalExchange)
            .with_endpoint(HttpEndpoint::Calls);
        ensure!(api.manifest(&adapter).endpoints.iter().any(|row| {
            row.id == HttpEndpoint::ExternalExchange && row.path == "/auth/external"
        }));
        let app = api.router(adapter);
        let peer: SocketAddr = "127.0.0.1:12000".parse()?;
        let exchange = |assertion: &[u8], with_origin: bool, with_peer: bool| {
            let body = serde_json::to_vec(&ExternalAssertionRequest {
                assertion: URL_SAFE_NO_PAD.encode(assertion),
            })?;
            let mut builder = Request::builder()
                .method("POST")
                .uri("/auth/external")
                .header(header::HOST, "console.local")
                .header(header::CONTENT_TYPE, "application/json");
            if with_origin {
                builder = builder.header(header::ORIGIN, "https://console.local");
            }
            let mut request = builder.body(Body::from(body))?;
            if with_peer {
                request.extensions_mut().insert(ConnectInfo(peer));
            }
            Ok::<_, anyhow::Error>(request)
        };
        let missing_peer = app
            .clone()
            .oneshot(exchange(b"signed-for-console", true, false)?)
            .await?;
        ensure!(missing_peer.status() != StatusCode::OK);
        let missing_origin = app
            .clone()
            .oneshot(exchange(b"signed-for-console", false, true)?)
            .await?;
        ensure!(missing_origin.status() == StatusCode::FORBIDDEN);
        let rejected = app
            .clone()
            .oneshot(exchange(b"wrong-audience", true, true)?)
            .await?;
        ensure!(rejected.status() == StatusCode::UNAUTHORIZED);
        let largest_service_assertion = app
            .clone()
            .oneshot(exchange(&vec![b'x'; 64 * 1024], true, true)?)
            .await?;
        ensure!(largest_service_assertion.status() == StatusCode::UNAUTHORIZED);
        let oversized_body = app
            .clone()
            .oneshot(exchange(&vec![b'x'; 80 * 1024], true, true)?)
            .await?;
        ensure!(oversized_body.status() == StatusCode::PAYLOAD_TOO_LARGE);
        let accepted = app
            .clone()
            .oneshot(exchange(b"signed-for-console", true, true)?)
            .await?;
        ensure!(accepted.status() == StatusCode::OK);
        ensure!(
            accepted
                .headers()
                .get(header::CACHE_CONTROL)
                .context("cache policy")?
                == "no-store"
        );
        let bytes =
            axum::body::to_bytes(accepted.into_body(), super::super::MAX_AUTH_BYTES).await?;
        let session = serde_json::from_slice::<AuthenticationResponse>(&bytes)?
            .into_session()
            .ok()
            .context("exchanged session")?;
        let body = crate::wire::encode_client_frame(&crate::ClientFrame::Call {
            id: 17,
            call: crate::ActionCall {
                action: crate::protocol::ACTION_PROTOCOL_DESCRIBE.into(),
                ..Default::default()
            },
        });
        let mut call = Request::builder()
            .method("POST")
            .uri("/calls")
            .header(header::HOST, "console.local")
            .header(header::ORIGIN, "https://console.local")
            .header(header::CONTENT_TYPE, "application/protobuf")
            .header(header::AUTHORIZATION, format!("Bearer {}", session.token))
            .body(Body::from(body))?;
        call.extensions_mut().insert(ConnectInfo(peer));
        let reply = app.oneshot(call).await?;
        ensure!(reply.status() == StatusCode::OK);
        let bytes = axum::body::to_bytes(reply.into_body(), super::super::MAX_CALL_BYTES).await?;
        let frame = crate::wire::decode_server_frame(&bytes).map_err(anyhow::Error::msg)?;
        ensure!(
            matches!(frame.frame, Some(xolotl_console_protocol::pb::console_frame::Frame::Reply(reply)) if reply.id == 17)
        );
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
            verified_source_addr(&headers, Some(peer), &cfg) == "198.51.100.2",
            "forwarded chain did not stop at its first untrusted hop"
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
        let error = auth_error(AuthError::State(
            "state://vault/console/root/password".into(),
        ));

        ensure!(
            error.status == StatusCode::INTERNAL_SERVER_ERROR,
            "internal auth error used wrong status"
        );
        ensure!(
            &*error.failure.message == "internal authentication error",
            "internal auth error leaked details"
        );
        Ok(())
    }

    #[tokio::test]
    async fn step_up_missing_bearer_writes_gateway_audit() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::in_memory()
                .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
                .build(),
        ));
        let st = HttpState::new(
            ConsoleState::shared(
                boot,
                std::sync::Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                )),
            )?,
            HttpConfig::default(),
        );
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

        let available = st.console.authentications.available_permits();
        let result = api_step_up(
            State(st.clone()),
            VerifiedPeer::Tcp(peer),
            auth_headers(),
            AdmittedBearerJson(
                StepUpRequest {
                    proof: Some(mfa::MfaProof::Factor {
                        factor_id: "factor-test".into(),
                        response: serde_json::json!({"code":"000000"}),
                    }),
                },
                st.service().admit_authentication()?,
            ),
        )
        .await;
        let err = match result {
            Ok(_) => bail!("step-up without bearer unexpectedly succeeded"),
            Err(err) => err,
        };

        ensure!(
            err.status == StatusCode::UNAUTHORIZED,
            "missing bearer used wrong status"
        );
        ensure!(st.console.authentications.available_permits() == available);
        let outcomes = audit_outcomes(&st, "console_credential")?;
        ensure!(
            outcomes.iter().any(|outcome| outcome == "missing_bearer"),
            "missing bearer audit outcome was not recorded"
        );
        Ok(())
    }

    #[tokio::test]
    async fn http_auth_origin_is_required() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::in_memory()
                .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
                .build(),
        ));
        let st = HttpState::new(
            ConsoleState::shared(
                boot,
                std::sync::Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                )),
            )?,
            HttpConfig::default(),
        );
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

        let available = st.console.authentications.available_permits();
        let result = api_login(
            State(st.clone()),
            VerifiedPeer::Tcp(peer),
            HeaderMap::new(),
            AdmittedAuthJson(
                LoginRequest {
                    username: "root".into(),
                    password: "password".into(),
                    second_factor: None,
                },
                st.service().admit_authentication()?,
            ),
        )
        .await;
        let err = match result {
            Ok(_) => bail!("auth request without origin unexpectedly succeeded"),
            Err(err) => err,
        };

        ensure!(
            err.status == StatusCode::FORBIDDEN,
            "missing origin used wrong status"
        );
        ensure!(st.console.authentications.available_permits() == available);
        let outcomes = audit_outcomes(&st, "console_credential")?;
        ensure!(
            outcomes.iter().any(|outcome| outcome == "origin_denied"),
            "origin_denied audit outcome was not recorded"
        );
        Ok(())
    }

    #[tokio::test]
    async fn key_login_body_origin_must_match_request_origin() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::in_memory()
                .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
                .build(),
        ));
        let st = HttpState::new(
            ConsoleState::shared(
                boot,
                std::sync::Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                )),
            )?,
            HttpConfig::default(),
        );
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);

        let available = st.console.authentications.available_permits();
        for origin in ["https://other.local", " https://console.local "] {
            let result = api_key_challenge(
                State(st.clone()),
                VerifiedPeer::Tcp(peer),
                auth_headers(),
                AdmittedKeyJson(
                    KeyChallengeRequest {
                        username: "root".into(),
                        origin: origin.into(),
                    },
                    st.service().admit_authentication()?,
                ),
            )
            .await;
            let err = match result {
                Ok(_) => bail!("mismatched key login origin unexpectedly succeeded"),
                Err(err) => err,
            };

            ensure!(
                err.status == StatusCode::FORBIDDEN,
                "origin mismatch used wrong status"
            );
            ensure!(st.console.authentications.available_permits() == available);
        }
        let outcomes = audit_outcomes(&st, "console_credential")?;
        ensure!(
            outcomes.iter().any(|outcome| outcome == "origin_mismatch"),
            "origin_mismatch audit outcome was not recorded"
        );
        Ok(())
    }

    #[tokio::test]
    async fn external_assertion_decode_failure_releases_transferred_admission() -> anyhow::Result<()>
    {
        let (console, _, _, _) = crate::service::tests::fixture().await?;
        let st = HttpState::new(console, HttpConfig::default());
        let available = st.console.authentications.available_permits();
        let admission = st.service().admit_authentication()?;
        ensure!(st.console.authentications.available_permits() == available - 1);
        let failure = api_external_exchange(
            State(st.clone()),
            VerifiedPeer::Tcp(SocketAddr::from(([127, 0, 0, 1], 12345))),
            auth_headers(),
            AdmittedAuthJson(
                ExternalAssertionRequest {
                    assertion: "%".into(),
                },
                admission,
            ),
        )
        .await
        .err()
        .context("invalid base64 must fail before dispatch")?;
        ensure!(failure.status == StatusCode::BAD_REQUEST);
        ensure!(st.console.authentications.available_permits() == available);
        let admissions = (0..available)
            .map(|_| st.service().admit_authentication())
            .collect::<Result<Vec<_>, _>>()?;
        ensure!(st.console.authentications.available_permits() == 0);
        ensure!(st.service().admit_authentication().is_err());
        drop(admissions);
        ensure!(st.console.authentications.available_permits() == available);
        Ok(())
    }
}
