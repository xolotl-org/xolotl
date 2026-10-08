//! One HTTP/WebSocket adapter over a shared Console service.

use super::config::{
    ConsoleWsRuntime, DEFAULT_HTTP_REQUEST_BODY_TIMEOUT, HARD_HTTP_REQUEST_BODY_TIMEOUT,
    MIN_HTTP_REQUEST_BODY_TIMEOUT, console_transport_default,
};
use super::{ConsoleTransportSecurityConfig, ConsoleWsConfig};
use crate::{ConsoleService, ConsoleState, protocol::TransportSecuritySummary};
use std::sync::Arc;
use std::time::Duration;

/// Admission for HTTP POST requests without an `Origin` header. Safe GET routes
/// already accept omission; WebSocket upgrades and public-key login always
/// require a real `Origin` regardless of this setting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginlessClientPolicy {
    /// Require `Origin` on Console POST requests.
    #[default]
    RequireOrigin,
    /// Permit omission only with a matching, host-injected
    /// [`super::VerifiedAutomationClient`] extension.
    AllowVerifiedAutomation,
}

/// HTTP admission and WebSocket connection policy for one adapter.
/// Service authentication, call and execution limits belong to [`ConsoleState`].
#[derive(Clone, Debug)]
pub struct HttpConfig {
    /// Total deadline for receiving one authentication or call request body.
    /// This applies before service execution and is clamped to 1 second–5 minutes.
    pub request_body_timeout: Duration,
    /// WebSocket connection, frame and delivery limits for this adapter.
    pub ws: ConsoleWsConfig,
    /// Origin, trusted proxy and declared transport-security policy.
    pub transport_security: ConsoleTransportSecurityConfig,
    /// Whether verified automation clients may omit `Origin` on HTTP POST routes.
    pub originless_clients: OriginlessClientPolicy,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            request_body_timeout: DEFAULT_HTTP_REQUEST_BODY_TIMEOUT,
            ws: ConsoleWsConfig::default(),
            transport_security: console_transport_default(),
            originless_clients: OriginlessClientPolicy::default(),
        }
    }
}

/// Adapter-owned policy and connection counters over one shared service.
/// Cloning its `Arc` shares connection admission across mounts/listeners.
/// Separate instances share only the supplied Console service's budgets.
pub struct HttpState {
    pub(crate) console: Arc<ConsoleState>,
    pub(crate) request_body_timeout: Duration,
    pub(crate) ws: ConsoleWsRuntime,
    /// Immutable public provider discovery, shared by every response on this adapter.
    pub(crate) mfa_provider_json: axum::body::Bytes,
    pub(crate) transport_security: ConsoleTransportSecurityConfig,
    pub(crate) originless_clients: OriginlessClientPolicy,
}

impl HttpState {
    /// Assemble one adapter, bounding its transport limits independently of the service.
    pub fn new(console: Arc<ConsoleState>, config: HttpConfig) -> Arc<Self> {
        let mfa_provider_json =
            axum::body::Bytes::from_owner(console.auth.mfa_provider_json().clone());
        Arc::new(Self {
            console,
            request_body_timeout: config.request_body_timeout.clamp(
                MIN_HTTP_REQUEST_BODY_TIMEOUT,
                HARD_HTTP_REQUEST_BODY_TIMEOUT,
            ),
            ws: ConsoleWsRuntime::new(config.ws),
            mfa_provider_json,
            transport_security: config.transport_security.bounded(),
            originless_clients: config.originless_clients,
        })
    }

    /// Shared service state; contains no HTTP or WebSocket admission state.
    pub fn state(&self) -> &Arc<ConsoleState> {
        &self.console
    }

    /// Call the same authenticated service used by this adapter.
    pub fn service(&self) -> ConsoleService {
        ConsoleService::new(self.console.clone())
    }

    /// Effective, bounded WebSocket configuration for this adapter.
    pub fn websocket_config(&self) -> &ConsoleWsConfig {
        self.ws.config()
    }

    /// Effective total deadline for receiving one HTTP authentication or call body.
    pub fn request_body_timeout(&self) -> Duration {
        self.request_body_timeout
    }

    /// Low-leak configured policy; this does not attest end-to-end TLS.
    pub fn transport_summary(&self) -> TransportSecuritySummary {
        TransportSecuritySummary {
            mode: self.transport_security.mode.as_str().into(),
            unsafe_transport: self.transport_security.is_unsafe(),
            relaxations: self.transport_security.unsafe_relaxation_names(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{ConsoleTransportSecurityMode, ConsoleWsLimit, HttpApi, HttpEndpoint};
    use crate::{ActionCall, ConsoleErrorCode, protocol::ACTION_PROTOCOL_DESCRIBE};
    use anyhow::{Context, ensure};
    use std::time::Duration;

    #[tokio::test]
    async fn adapters_own_connection_policy_and_share_service_admission() -> anyhow::Result<()> {
        let (console, service, token, _) = crate::service::tests::fixture().await?;
        let left = HttpState::new(
            console.clone(),
            HttpConfig {
                request_body_timeout: Duration::ZERO,
                ws: ConsoleWsConfig {
                    max_connections_global: 1,
                    send_timeout: Duration::from_millis(1500),
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        let right = HttpState::new(
            console.clone(),
            HttpConfig {
                request_body_timeout: Duration::MAX,
                ws: ConsoleWsConfig {
                    max_connections_global: 2,
                    ..Default::default()
                },
                transport_security: ConsoleTransportSecurityConfig {
                    mode: ConsoleTransportSecurityMode::UnsafePlaintext,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        ensure!(Arc::ptr_eq(left.state(), right.state()));
        ensure!(left.request_body_timeout() == MIN_HTTP_REQUEST_BODY_TIMEOUT);
        ensure!(right.request_body_timeout() == HARD_HTTP_REQUEST_BODY_TIMEOUT);
        ensure!(left.ws.try_acquire_source("same-peer").is_ok());
        ensure!(left.clone().ws.try_acquire_source("other") == Err(ConsoleWsLimit::Global));
        ensure!(right.ws.try_acquire_source("same-peer").is_ok());
        ensure!(right.ws.try_acquire_source("other").is_ok());
        ensure!(right.ws.try_acquire_source("third") == Err(ConsoleWsLimit::Global));

        let calls = HttpApi::new().with_endpoint(HttpEndpoint::Calls);
        let manifest = serde_json::to_value(calls.manifest(&left))?;
        ensure!(manifest["transport"]["mode"] == "production_tls");
        ensure!(manifest["request_body_timeout_ms"] == 1000);
        ensure!(manifest.get("websocket").is_none());
        let streams = HttpApi::new().with_endpoint(HttpEndpoint::WebSocket);
        let manifest = serde_json::to_value(streams.manifest(&left))?;
        ensure!(manifest["websocket"]["send_timeout_ms"] == 1500);
        ensure!(manifest["websocket"]["idle_timeout_ms"] == 7_200_000);
        ensure!(manifest["websocket"].get("send_timeout").is_none());
        ensure!(streams.manifest(&right).transport.mode == "unsafe_plaintext");

        let describe = || ActionCall {
            action: ACTION_PROTOCOL_DESCRIBE.into(),
            ..Default::default()
        };
        for entry in [service, left.service(), right.service()] {
            let result = entry.call(&token, None, describe()).await?;
            let value = result.output.context("service discovery")?;
            let fields = value.as_map().context("discovery fields")?;
            ensure!(fields.len() == 6);
            ensure!(!fields.contains_key("transport_security_mode"));
            ensure!(!fields.contains_key("unsafe_transport"));
        }
        let _capacity = console
            .calls
            .clone()
            .try_acquire_many_owned(u32::try_from(console.calls.available_permits())?)?;
        for adapter in [left, right] {
            let failure = adapter
                .service()
                .call(&token, None, describe())
                .await
                .err()
                .context("shared service capacity")?;
            ensure!(failure.code == ConsoleErrorCode::RateLimited);
        }
        Ok(())
    }
}
