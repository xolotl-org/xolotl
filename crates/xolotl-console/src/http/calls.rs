//! Stateless protobuf calls share the authenticated ConsoleService.

use super::{
    HttpState, MAX_CALL_BYTES,
    peer::VerifiedPeer,
    response::{response_headers, status},
};
use crate::{ClientFrame, ConsoleErrorCode, ConsoleFailure, ServerFrame};
use axum::{
    body::Bytes,
    extract::{FromRequest, Request, State, rejection::BytesRejection},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

pub(crate) async fn call(
    State(state): State<Arc<HttpState>>,
    peer: Result<VerifiedPeer, super::HttpFailure>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let peer = match peer {
        Ok(peer) => peer,
        Err(error) => return reply(error.status, None, Err(*error.failure)),
    };
    let source = peer.source(&headers, &state.transport_security);
    if let Err(error) = super::context::validate_http_auth_origin(&state, &headers, &peer, &source)
    {
        return reply(error.status, None, Err(*error.failure));
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(';').next().unwrap_or_default().trim())
        != Some("application/protobuf")
    {
        return reply(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            None,
            Err(ConsoleFailure::new(
                ConsoleErrorCode::BadFrame,
                "expected application/protobuf".into(),
            )),
        );
    }
    // A missing or malformed bearer cannot identify a caller. Reject it before
    // reserving shared action capacity or polling an untrusted request body.
    let bearer = match super::context::bearer_or_audit(&state, &headers, &source) {
        Ok(bearer) => bearer,
        Err(error) => return reply(error.status, None, Err(*error.failure)),
    };
    // Reserve the action slot before collecting a potentially 4 MiB frame.
    // The same permit stays owned through token verification and dispatch.
    let service = state.service();
    let admitted = match service.admit_call() {
        Ok(capacity) => capacity,
        Err(error) => {
            return reply(StatusCode::TOO_MANY_REQUESTS, None, Err(error));
        }
    };
    let body: Result<Bytes, BytesRejection> = match tokio::time::timeout(
        state.request_body_timeout,
        Bytes::from_request(request, &()),
    )
    .await
    {
        Ok(body) => body,
        Err(_) => {
            return reply(
                StatusCode::REQUEST_TIMEOUT,
                None,
                Err(ConsoleFailure::new(
                    ConsoleErrorCode::BadFrame,
                    "request body timed out".into(),
                )),
            );
        }
    };
    let body = match body {
        Ok(body) if body.len() <= MAX_CALL_BYTES => body,
        body => {
            let status = body
                .err()
                .map_or(StatusCode::PAYLOAD_TOO_LARGE, |error| error.status());
            return reply(
                status,
                None,
                Err(ConsoleFailure::new(
                    ConsoleErrorCode::BadFrame,
                    "Console request body could not be read within its limit".into(),
                )),
            );
        }
    };
    let (id, call) = match crate::wire::decode_client_frame(&body, MAX_CALL_BYTES) {
        Ok(ClientFrame::Call { id, call }) => (id, call),
        _ => {
            return reply(
                StatusCode::BAD_REQUEST,
                None,
                Err(ConsoleFailure::new(
                    ConsoleErrorCode::BadFrame,
                    "HTTP requires one ConsoleFrame.call".into(),
                )),
            );
        }
    };
    let (result, delivery) = match admitted.prepare_call(bearer, Some(&source), call).await {
        Ok(prepared) => prepared.into_parts(),
        Err(failure) => (Err(failure), None),
    };
    let status = result
        .as_ref()
        .err()
        .map_or(StatusCode::OK, |failure| status(failure.code));
    let evidence = crate::service::withheld(
        ConsoleFailure::new(ConsoleErrorCode::Forbidden, "delivery rejected".into()),
        &result,
    );
    let response = reply(status, Some(id), result);
    if let Some(delivery) = delivery
        && let Err(failure) = delivery.validate().await
    {
        let failure = crate::service::withheld(failure, &Err(evidence));
        return reply(
            super::response::status(failure.code),
            Some(id),
            Err(failure),
        );
    }
    response
}

fn reply(
    status: StatusCode,
    id: Option<u64>,
    result: Result<crate::ActionResult, ConsoleFailure>,
) -> Response {
    let retry_after_ms = result
        .as_ref()
        .err()
        .and_then(|failure| failure.retry_after_ms);
    let frame = match result {
        Ok(result) => ServerFrame::Reply {
            id: id.unwrap_or_default(),
            result,
        },
        Err(failure) => ServerFrame::Error { id, failure },
    };
    match crate::wire::encode_server_frame(&frame, MAX_CALL_BYTES) {
        Ok(bytes) => response_headers(
            (
                status,
                [(header::CONTENT_TYPE, "application/protobuf")],
                bytes,
            )
                .into_response(),
            retry_after_ms,
        ),
        Err(_) => {
            // A mutation may already have completed. Never imply it is safe to retry.
            let encoded = crate::wire::delivery_failure(&frame, MAX_CALL_BYTES)
                .and_then(|failure| crate::wire::encode_server_frame(&failure, MAX_CALL_BYTES));
            match encoded {
                Ok(bytes) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [
                        (header::CONTENT_TYPE, "application/protobuf"),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    bytes,
                )
                    .into_response(),
                Err(_) => response_headers(StatusCode::INTERNAL_SERVER_ERROR.into_response(), None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::response::AuthJson;
    use super::super::{AdmittedAuthJson, HttpFailure};
    use super::*;
    use anyhow::{Context, ensure};
    use axum::extract::{FromRequest, Request};
    use futures_util::StreamExt as _;
    use prost::Message as _;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use xolotl_console_protocol::pb;
    use xolotl_types::{UnresolvedOperations, Value};

    #[tokio::test]
    async fn oversized_http_reply_retains_effect_identities() -> anyhow::Result<()> {
        let mut unresolved = UnresolvedOperations::default();
        ensure!(unresolved.record("provider-ticket-42"));
        let mut result =
            crate::ActionResult::value(Value::bytes(vec![0; MAX_CALL_BYTES + 1]), 1, 2);
        result.unresolved_operations = Some(Box::new(unresolved));
        let response = reply(StatusCode::OK, Some(31), Ok(result));
        ensure!(response.status() == StatusCode::INTERNAL_SERVER_ERROR);
        ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
        let body = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
        let decoded = pb::ConsoleFrame::decode(body)?;
        let Some(pb::console_frame::Frame::Error(error)) = decoded.frame else {
            anyhow::bail!("expected bounded error frame");
        };
        ensure!(error.request_id == Some(31));
        ensure!(
            error
                .unresolved_operations
                .context("effect identities")?
                .operation_ids
                == ["provider-ticket-42"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn malformed_authentication_bodies_keep_the_safe_json_contract() -> anyhow::Result<()> {
        for (content_type, body, status) in [
            ("application/json", "{".to_owned(), StatusCode::BAD_REQUEST),
            (
                "application/json",
                "{\"username\":\"root\",\"password\":[\"private-value\"]}".to_owned(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "text/plain",
                "private-value".to_owned(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                "application/json",
                "x".repeat(2 * 1024 * 1024 + 1),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let request = Request::builder()
                .header(header::CONTENT_TYPE, content_type)
                .body(axum::body::Body::from(body))?;
            let response = AuthJson::<crate::LoginRequest>::from_request(request, &())
                .await
                .err()
                .context("invalid body")?
                .into_response();
            ensure!(response.status() == status);
            ensure!(response.headers()[header::CONTENT_TYPE] == "application/json");
            ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
            let body = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
            let failure: ConsoleFailure = serde_json::from_slice(&body)?;
            ensure!(failure.code == ConsoleErrorCode::BadRequest);
            ensure!(!failure.message.contains("private-value"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn malformed_mfa_proofs_do_not_echo_secret_body_fields() -> anyhow::Result<()> {
        for proof in [
            serde_json::json!({"kind":"private-proof-kind","response":"private-response"}),
            serde_json::json!({"kind":"recovery_code","code":["private-recovery-code"]}),
        ] {
            let request = Request::builder()
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(
                    &serde_json::json!({"proof":proof}),
                )?))?;
            let response = AuthJson::<crate::StepUpRequest>::from_request(request, &())
                .await
                .err()
                .context("malformed MFA proof")?
                .into_response();
            ensure!(response.status() == StatusCode::UNPROCESSABLE_ENTITY);
            ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
            let body = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
            let failure: ConsoleFailure = serde_json::from_slice(&body)?;
            ensure!(failure.code == ConsoleErrorCode::BadRequest);
            ensure!(&*failure.message == "invalid authentication request");
            ensure!(failure.mfa.is_none());
            ensure!(!std::str::from_utf8(&body)?.contains("private-"));
        }
        Ok(())
    }

    #[tokio::test]
    async fn recovery_facts_survive_json_and_both_protobuf_adapters() -> anyhow::Result<()> {
        use crate::service::ConsoleError;
        for failure in [
            ConsoleFailure::from(crate::AuthError::RateLimited {
                retry_after_ms: 1501,
            }),
            ConsoleFailure::from(ConsoleError::StepUpRequired),
            ConsoleFailure::from(crate::AuthError::MfaRequired { options: None }),
            ConsoleFailure::from(crate::AuthError::MfaUsageDenied),
            ConsoleFailure::from(crate::AuthError::MfaOperationUnavailable),
            ConsoleFailure::from(crate::AuthError::MfaRequired {
                options: Some(crate::mfa::MfaOptions {
                    factors: vec![
                        crate::mfa::FactorSummary {
                            factor_id: "factor-phone".into(),
                            provider_id: "totp".into(),
                            label: "Phone".into(),
                            created_at: 1_700_000_000_000,
                            last_used_at: Some(0),
                            availability: crate::mfa::FactorAvailability::Available,
                        },
                        crate::mfa::FactorSummary {
                            factor_id: "factor-backup".into(),
                            provider_id: "totp".into(),
                            label: "备用设备".into(),
                            created_at: 1_700_000_000_001,
                            last_used_at: None,
                            availability: crate::mfa::FactorAvailability::ProviderNotInstalled,
                        },
                        crate::mfa::FactorSummary {
                            factor_id: "factor-paused".into(),
                            provider_id: "push".into(),
                            label: "Paused by host".into(),
                            created_at: 1_700_000_000_002,
                            last_used_at: None,
                            availability: crate::mfa::FactorAvailability::AuthenticationDisabled,
                        },
                    ],
                    recovery_code_available: true,
                }),
            }),
            ConsoleFailure::from(ConsoleError::RegistryChanged {
                current_registry_rev: 123,
            }),
            ConsoleFailure::from(ConsoleError::Mgmt(crate::mgmt::MgmtError::Conflict {
                expected: Some(1),
                current_version: Some(2),
            })),
            ConsoleFailure::from(ConsoleError::RateLimited),
            ConsoleFailure::from(
                ConsoleError::Runtime(xolotl_types::Failure::Timeout).with_execution(
                    crate::ExecutionReference {
                        execution_id: Some("execution-42".into()),
                        process_id: "1234".into(),
                        program_id: "ab".repeat(32),
                    },
                ),
            ),
            ConsoleFailure::from(crate::AuthError::State("state://vault/secret".into())),
        ] {
            let ws = ServerFrame::Error {
                id: Some(19),
                failure: failure.clone(),
            };
            let ws = pb::ConsoleFrame::decode(
                crate::wire::encode_server_frame(&ws, MAX_CALL_BYTES)?.as_slice(),
            )?;
            let response = reply(status(failure.code), Some(19), Err(failure.clone()));
            ensure!(response.status() == status(failure.code));
            ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
            if failure.retry_after_ms.is_some() {
                ensure!(response.headers()[header::RETRY_AFTER] == "2");
            } else {
                ensure!(!response.headers().contains_key(header::RETRY_AFTER));
            }
            let body = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
            let http = pb::ConsoleFrame::decode(body)?;
            ensure!(http == ws);
            let Some(pb::console_frame::Frame::Error(error)) = http.frame else {
                anyhow::bail!("expected failure");
            };
            ensure!(error.retry_after_ms == failure.retry_after_ms);
            ensure!(error.required_mfa_level == failure.required_mfa_level.map(u32::from));
            ensure!(error.current_registry_rev == failure.current_registry_rev);
            ensure!(
                error
                    .execution
                    .as_ref()
                    .map(|reference| (&reference.process_id, &reference.program_id))
                    == failure
                        .execution
                        .as_ref()
                        .map(|reference| (&reference.process_id, &reference.program_id))
            );
            ensure!(error.current_version == failure.current_version);
            match (&error.mfa, &failure.mfa) {
                (None, None) => {}
                (Some(encoded), Some(original)) => {
                    ensure!(encoded.recovery_code_available == original.recovery_code_available);
                    ensure!(encoded.factors.len() == original.factors.len());
                    for (encoded, original) in encoded.factors.iter().zip(&original.factors) {
                        ensure!(encoded.factor_id == original.factor_id);
                        ensure!(encoded.provider_id == original.provider_id);
                        ensure!(encoded.label == original.label);
                        ensure!(encoded.created_at == original.created_at);
                        ensure!(encoded.last_used_at == original.last_used_at);
                        let expected = match original.availability {
                            crate::mfa::FactorAvailability::Available => {
                                pb::FactorAvailability::Available
                            }
                            crate::mfa::FactorAvailability::AuthenticationDisabled => {
                                pb::FactorAvailability::AuthenticationDisabled
                            }
                            crate::mfa::FactorAvailability::ProviderNotInstalled => {
                                pb::FactorAvailability::ProviderNotInstalled
                            }
                        };
                        ensure!(encoded.availability == expected as i32);
                    }
                }
                _ => anyhow::bail!("MFA options presence changed during encoding"),
            }
            ensure!(!error.message.contains("vault"));

            let json = HttpFailure::from(failure.clone()).into_response();
            ensure!(json.headers()[header::CONTENT_TYPE] == "application/json");
            ensure!(json.headers()[header::CACHE_CONTROL] == "no-store");
            if failure.retry_after_ms.is_some() {
                ensure!(json.headers()[header::RETRY_AFTER] == "2");
            } else {
                ensure!(!json.headers().contains_key(header::RETRY_AFTER));
            }
            let body = axum::body::to_bytes(json.into_body(), MAX_CALL_BYTES).await?;
            ensure!(serde_json::from_slice::<ConsoleFailure>(&body)? == failure);
            let json: serde_json::Value = serde_json::from_slice(&body)?;
            ensure!(json.get("mfa").is_some() == failure.mfa.is_some());
        }
        Ok(())
    }

    #[tokio::test]
    async fn http_refresh_uses_shared_rotation_and_noncacheable_credentials() -> anyhow::Result<()>
    {
        let (console, service, _, password) = crate::service::tests::fixture().await?;
        let state = HttpState::new(console, super::super::HttpConfig::default());
        let peer: SocketAddr = "127.0.0.1:12000".parse()?;
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "console.local".parse()?);
        headers.insert(header::ORIGIN, "https://console.local".parse()?);
        let response = crate::http::auth::api_login(
            State(state.clone()),
            VerifiedPeer::Tcp(peer),
            headers.clone(),
            AdmittedAuthJson(
                crate::LoginRequest {
                    username: "root".into(),
                    password,
                    second_factor: None,
                },
                state.service().admit_authentication()?,
            ),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{:?}", e))?
        .into_response();
        ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
        let body = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
        let login = serde_json::from_slice::<crate::AuthenticationResponse>(&body)?
            .into_session()
            .ok()
            .context("authenticated session")?;
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", login.token).parse()?,
        );
        let response = crate::http::auth::api_refresh(
            State(state.clone()),
            VerifiedPeer::Tcp(peer),
            headers.clone(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("{:?}", e))?
        .into_response();
        ensure!(response.status() == StatusCode::OK);
        ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
        let body = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
        let refreshed: crate::LoginResponse = serde_json::from_slice(&body)?;
        ensure!(refreshed.sid == login.sid && refreshed.token != login.token);
        service
            .call(
                &refreshed.token,
                None,
                crate::ActionCall {
                    action: crate::protocol::ACTION_PROTOCOL_DESCRIBE.into(),
                    ..Default::default()
                },
            )
            .await?;
        let failure =
            crate::http::auth::api_refresh(State(state.clone()), VerifiedPeer::Tcp(peer), headers)
                .await
                .err()
                .context("reusing old bearer")?
                .into_response();
        ensure!(failure.status() == StatusCode::UNAUTHORIZED);
        ensure!(failure.headers()[header::CACHE_CONTROL] == "no-store");
        let body = axum::body::to_bytes(failure.into_body(), MAX_CALL_BYTES).await?;
        ensure!(
            serde_json::from_slice::<ConsoleFailure>(&body)?.code
                == ConsoleErrorCode::NotAuthenticated
        );
        let facts = state.console.boot.kernel().facts().all_facts()?;
        let refreshed_audits: Vec<_> = facts
            .iter()
            .filter_map(|f| f.outcome.as_ref()?.as_map())
            .filter(|m| {
                m.get("event").and_then(xolotl_types::Value::as_str) == Some("console_credential")
                    && m.get("outcome").and_then(xolotl_types::Value::as_str)
                        == Some("token_refresh")
            })
            .collect();
        ensure!(refreshed_audits.len() == 1);
        ensure!(
            refreshed_audits[0]
                .get("source_addr")
                .and_then(xolotl_types::Value::as_str)
                == Some("127.0.0.1")
        );
        Ok(())
    }

    #[tokio::test]
    async fn unary_calls_share_bearer_validation_and_return_correlated_protobuf()
    -> anyhow::Result<()> {
        let (console, _, token, _) = crate::service::tests::fixture().await?;
        let state = HttpState::new(console, super::super::HttpConfig::default());
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "console.local".parse()?);
        headers.insert(header::ORIGIN, "https://console.local".parse()?);
        headers.insert(header::CONTENT_TYPE, "application/protobuf".parse()?);
        headers.insert(header::AUTHORIZATION, format!("Bearer {token}").parse()?);
        let body = crate::wire::encode_client_frame(&ClientFrame::Call {
            id: 53,
            call: crate::ActionCall {
                action: crate::protocol::ACTION_PROTOCOL_DESCRIBE.into(),
                ..Default::default()
            },
        });
        let peer: SocketAddr = "127.0.0.1:12000".parse()?;
        let response = call(
            State(state.clone()),
            Ok(VerifiedPeer::Tcp(peer)),
            headers.clone(),
            Request::new(axum::body::Body::from(body.clone())),
        )
        .await;
        ensure!(response.status() == StatusCode::OK);
        ensure!(
            response
                .headers()
                .get(header::CACHE_CONTROL)
                .context("cache policy")?
                == "no-store"
        );
        let bytes = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
        let frame = pb::ConsoleFrame::decode(bytes)?;
        let Some(pb::console_frame::Frame::Reply(reply)) = frame.frame else {
            anyhow::bail!("expected successful reply");
        };
        ensure!(reply.id == 53);
        ensure!(
            reply.result.context("result")?.registry_rev
                == Some(state.console.registry.current_rev())
        );
        for (action, input, revision, status, code) in [
            (
                crate::protocol::ACTION_PROTOCOL_DESCRIBE,
                xolotl_types::Value::null(),
                Some(state.console.registry.current_rev() ^ 1),
                StatusCode::CONFLICT,
                pb::ConsoleErrorCode::RegistryChanged,
            ),
            (
                crate::protocol::ACTION_PAIRING_DENY,
                crate::service::map_value([(
                    "pairing_id",
                    xolotl_types::Value::string("example".into()),
                )]),
                None,
                StatusCode::FORBIDDEN,
                pb::ConsoleErrorCode::StepUpRequired,
            ),
        ] {
            let body = crate::wire::encode_client_frame(&ClientFrame::Call {
                id: 54,
                call: crate::ActionCall {
                    action: action.into(),
                    input,
                    registry_rev: revision,
                    ..Default::default()
                },
            });
            let response = call(
                State(state.clone()),
                Ok(VerifiedPeer::Tcp(peer)),
                headers.clone(),
                Request::new(axum::body::Body::from(body)),
            )
            .await;
            ensure!(response.status() == status);
            let bytes = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
            let frame = pb::ConsoleFrame::decode(bytes)?;
            let Some(pb::console_frame::Frame::Error(error)) = frame.frame else {
                anyhow::bail!("expected classified error");
            };
            ensure!(error.request_id == Some(54));
            ensure!(error.code == code as i32);
            if code == pb::ConsoleErrorCode::StepUpRequired {
                ensure!(error.required_mfa_level == Some(2));
            } else if code == pb::ConsoleErrorCode::RegistryChanged {
                ensure!(error.current_registry_rev == Some(state.console.registry.current_rev()));
            }
        }
        let too_large = call(
            State(state.clone()),
            Ok(VerifiedPeer::Tcp(peer)),
            headers.clone(),
            Request::new(axum::body::Body::from(vec![0; MAX_CALL_BYTES + 1])),
        )
        .await;
        ensure!(too_large.status() == StatusCode::PAYLOAD_TOO_LARGE);
        ensure!(too_large.headers()[header::CACHE_CONTROL] == "no-store");
        let bytes = axum::body::to_bytes(too_large.into_body(), MAX_CALL_BYTES).await?;
        let frame = pb::ConsoleFrame::decode(bytes)?;
        ensure!(
            matches!(frame.frame, Some(pb::console_frame::Frame::Error(error)) if error.request_id.is_none() && error.code == pb::ConsoleErrorCode::ValidationFailed as i32)
        );
        for (authorization, expected_id) in [
            (None, None),
            (Some(b"Basic token".as_slice()), None),
            (Some(b"bearer token".as_slice()), Some(53)),
            (Some(b"Bearer\ttoken".as_slice()), None),
            (Some(b"Bearer \xff".as_slice()), None),
        ] {
            headers.remove(header::AUTHORIZATION);
            if let Some(value) = authorization {
                headers.insert(header::AUTHORIZATION, value.try_into()?);
            }
            let response = call(
                State(state.clone()),
                Ok(VerifiedPeer::Tcp(peer)),
                headers.clone(),
                Request::new(axum::body::Body::from(body.clone())),
            )
            .await;
            ensure!(response.status() == StatusCode::UNAUTHORIZED);
            let bytes = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
            let frame = pb::ConsoleFrame::decode(bytes)?;
            ensure!(
                matches!(frame.frame, Some(pb::console_frame::Frame::Error(error)) if error.request_id == expected_id && error.code == pb::ConsoleErrorCode::Unauthenticated as i32)
            );
        }
        headers.insert(header::ORIGIN, "https://different.example".parse()?);
        let response = call(
            State(state),
            Ok(VerifiedPeer::Tcp(peer)),
            headers,
            Request::new(axum::body::Body::from(body)),
        )
        .await;
        ensure!(response.status() == StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn malformed_bearer_is_rejected_before_body_poll_or_call_capacity() -> anyhow::Result<()>
    {
        let (console, _, _, _) = crate::service::tests::fixture().await?;
        let state = HttpState::new(console.clone(), super::super::HttpConfig::default());
        let available = console.calls.available_permits();
        let peer: SocketAddr = "127.0.0.1:12000".parse()?;

        for authorization in [None, Some("Basic token"), Some("Bearer   ")] {
            let polled = Arc::new(AtomicBool::new(false));
            let observed = Arc::clone(&polled);
            let body = axum::body::Body::from_stream(futures_util::stream::once(async move {
                observed.store(true, Ordering::SeqCst);
                std::future::pending::<Result<Bytes, std::io::Error>>().await
            }));
            let mut headers = HeaderMap::new();
            headers.insert(header::HOST, "console.local".parse()?);
            headers.insert(header::ORIGIN, "https://console.local".parse()?);
            headers.insert(header::CONTENT_TYPE, "application/protobuf".parse()?);
            if let Some(authorization) = authorization {
                headers.insert(header::AUTHORIZATION, authorization.parse()?);
            }

            let response = tokio::time::timeout(
                Duration::from_secs(1),
                call(
                    State(state.clone()),
                    Ok(VerifiedPeer::Tcp(peer)),
                    headers,
                    Request::new(body),
                ),
            )
            .await?;
            ensure!(response.status() == StatusCode::UNAUTHORIZED);
            ensure!(!polled.load(Ordering::SeqCst));
            ensure!(console.calls.available_permits() == available);
            let bytes = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
            let frame = pb::ConsoleFrame::decode(bytes)?;
            ensure!(
                matches!(frame.frame, Some(pb::console_frame::Frame::Error(error)) if error.request_id.is_none() && error.code == pb::ConsoleErrorCode::Unauthenticated as i32)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn call_capacity_precedes_protobuf_body_decoding() -> anyhow::Result<()> {
        let (console, _, _, _) = crate::service::tests::fixture().await?;
        let state = HttpState::new(console, super::super::HttpConfig::default());
        let capacity = state
            .console
            .calls
            .try_acquire()
            .context("action capacity")?;
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "console.local".parse()?);
        headers.insert(header::ORIGIN, "https://console.local".parse()?);
        headers.insert(header::CONTENT_TYPE, "application/protobuf".parse()?);
        headers.insert(header::AUTHORIZATION, "Bearer token".parse()?);
        let peer: SocketAddr = "127.0.0.1:12000".parse()?;
        let response = call(
            State(state.clone()),
            Ok(VerifiedPeer::Tcp(peer)),
            headers.clone(),
            Request::new(axum::body::Body::from("invalid protobuf")),
        )
        .await;
        ensure!(response.status() == StatusCode::TOO_MANY_REQUESTS);
        let body = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
        let frame = pb::ConsoleFrame::decode(body)?;
        ensure!(
            matches!(frame.frame, Some(pb::console_frame::Frame::Error(error)) if error.code == pb::ConsoleErrorCode::RateLimited as i32)
        );
        drop(capacity);
        let response = call(
            State(state),
            Ok(VerifiedPeer::Tcp(peer)),
            headers,
            Request::new(axum::body::Body::from("invalid protobuf")),
        )
        .await;
        ensure!(response.status() == StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn stalled_call_body_times_out_and_releases_shared_capacity() -> anyhow::Result<()> {
        let (console, _, _, _) = crate::service::tests::fixture().await?;
        let state = HttpState::new(
            console.clone(),
            super::super::HttpConfig {
                request_body_timeout: Duration::ZERO,
                ..Default::default()
            },
        );
        let available = console.calls.available_permits();
        ensure!(available > 0);
        let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
        let body = axum::body::Body::from_stream(
            futures_util::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(
                b"private-call-sentinel",
            ))])
            .chain(futures_util::stream::once(async move {
                if polled_tx.send(()).is_err() {
                    return Err(std::io::Error::other("test receiver dropped"));
                }
                std::future::pending::<Result<Bytes, std::io::Error>>().await
            })),
        );
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, "console.local".parse()?);
        headers.insert(header::ORIGIN, "https://console.local".parse()?);
        headers.insert(header::CONTENT_TYPE, "application/protobuf".parse()?);
        headers.insert(header::AUTHORIZATION, "Bearer token".parse()?);
        let peer: SocketAddr = "127.0.0.1:12000".parse()?;
        let task = tokio::spawn(call(
            State(state),
            Ok(VerifiedPeer::Tcp(peer)),
            headers,
            Request::new(body),
        ));
        tokio::time::timeout(Duration::from_secs(5), polled_rx).await??;
        ensure!(console.calls.available_permits() == available - 1);
        let response = tokio::time::timeout(Duration::from_secs(5), task).await??;
        ensure!(response.status() == StatusCode::REQUEST_TIMEOUT);
        ensure!(response.headers()[header::CACHE_CONTROL] == "no-store");
        let bytes = axum::body::to_bytes(response.into_body(), MAX_CALL_BYTES).await?;
        let frame = pb::ConsoleFrame::decode(bytes)?;
        let Some(pb::console_frame::Frame::Error(error)) = frame.frame else {
            anyhow::bail!("expected timeout failure");
        };
        ensure!(error.request_id.is_none());
        ensure!(error.code == pb::ConsoleErrorCode::ValidationFailed as i32);
        ensure!(error.message == "request body timed out");
        ensure!(console.calls.available_permits() == available);
        Ok(())
    }
}
