use axum::http::{HeaderMap, header};
use std::net::IpAddr;
use xolotl_gateway::{
    GatewayTransportSecurityConfig, GatewayTransportSecurityMode, GatewayUnsafeTransportRelaxation,
    local_trusted_browser_origin,
};

/// External WebSocket protocol version served by this adapter.
pub const EXTERNAL_WS_PROTOCOL_VERSION: u32 = 1;
/// Default maximum inbound binary frame size.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Hard cap for inbound binary frame size.
pub const HARD_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Default time allowed for the first session frame.
pub const DEFAULT_FIRST_FRAME_TIMEOUT_MS: u64 = 10_000;
/// Hard cap for first-frame timeout.
pub const HARD_FIRST_FRAME_TIMEOUT_MS: u64 = 300_000;
/// Default idle timeout after the first frame.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000;
/// Hard cap for idle timeout.
pub const HARD_IDLE_TIMEOUT_MS: u64 = 86_400_000;
/// Default maximum concurrent WebSocket sessions.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// Hard cap for concurrent WebSocket sessions.
pub const HARD_MAX_CONNECTIONS: usize = 4096;

/// WebSocket transport config for external Provider/Source sessions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalWebSocketConfig {
    /// Maximum inbound protobuf frame bytes.
    pub max_frame_bytes: usize,
    /// First-frame timeout in milliseconds.
    pub first_frame_timeout_ms: u64,
    /// Idle timeout in milliseconds.
    pub idle_timeout_ms: u64,
    /// Maximum concurrent WebSocket sessions.
    pub max_connections: usize,
    /// Transport security and trusted-proxy policy.
    pub transport_security: GatewayTransportSecurityConfig,
}

impl Default for ExternalWebSocketConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            first_frame_timeout_ms: DEFAULT_FIRST_FRAME_TIMEOUT_MS,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            transport_security: GatewayTransportSecurityConfig::default(),
        }
        .bounded()
    }
}

impl ExternalWebSocketConfig {
    /// Clamp deployment-provided values to hard bounds and non-zero defaults.
    pub fn bounded(mut self) -> Self {
        self.max_frame_bytes = clamp_or_default(
            self.max_frame_bytes,
            DEFAULT_MAX_FRAME_BYTES,
            HARD_MAX_FRAME_BYTES,
        );
        self.first_frame_timeout_ms = clamp_or_default_u64(
            self.first_frame_timeout_ms,
            DEFAULT_FIRST_FRAME_TIMEOUT_MS,
            HARD_FIRST_FRAME_TIMEOUT_MS,
        );
        self.idle_timeout_ms = clamp_or_default_u64(
            self.idle_timeout_ms,
            DEFAULT_IDLE_TIMEOUT_MS,
            HARD_IDLE_TIMEOUT_MS,
        );
        self.max_connections = clamp_or_default(
            self.max_connections,
            DEFAULT_MAX_CONNECTIONS,
            HARD_MAX_CONNECTIONS,
        );
        self.transport_security = self.transport_security.bounded();
        self
    }
}

pub(crate) fn validate_ws_transport(
    headers: &HeaderMap,
    peer: IpAddr,
    config: &GatewayTransportSecurityConfig,
) -> Option<&'static str> {
    match config.mode {
        GatewayTransportSecurityMode::LocalTrusted => {
            if !peer.is_loopback() {
                return Some("transport_not_local");
            }
            let mut origins = headers.get_all(header::ORIGIN).iter();
            if let Some(origin) = origins.next() {
                if origins.next().is_some() {
                    return Some("origin_invalid");
                }
                let origin = match origin.to_str() {
                    Ok(origin) => origin,
                    Err(_) => return Some("origin_invalid"),
                };
                if !local_trusted_browser_origin(origin) {
                    return Some("origin_denied");
                }
            }
        }
        GatewayTransportSecurityMode::TrustedReverseProxy => {
            if !config.trusted_proxy.peers.contains(&peer) {
                return Some("transport_untrusted_proxy");
            }
            if config.trusted_proxy.honor_x_forwarded_proto {
                let mut values = headers.get_all("x-forwarded-proto").iter();
                let value = match values.next() {
                    Some(value) => value,
                    None => return Some("proto_required"),
                };
                if values.next().is_some() {
                    return Some("proto_invalid");
                }
                let proto = match value.to_str() {
                    Ok(value) => value,
                    Err(_) => return Some("proto_invalid"),
                };
                if !matches!(proto, "https" | "wss") {
                    return Some("proto_denied");
                }
            }
        }
        GatewayTransportSecurityMode::UnsafePlaintext
        | GatewayTransportSecurityMode::DisabledForTest => {}
        GatewayTransportSecurityMode::ProductionTls | GatewayTransportSecurityMode::MutualTls => {
            if !config
                .unsafe_relaxations
                .contains(&GatewayUnsafeTransportRelaxation::AllowPlaintext)
            {
                return Some("transport_tls_required");
            }
        }
    }
    None
}

fn clamp_or_default(value: usize, default: usize, hard: usize) -> usize {
    if value == 0 { default } else { value.min(hard) }
}

fn clamp_or_default_u64(value: u64, default: u64, hard: u64) -> u64 {
    if value == 0 { default } else { value.min(hard) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use axum::http::HeaderValue;
    use std::net::Ipv4Addr;
    use xolotl_gateway::GatewayTrustedProxyConfig;

    #[test]
    fn trusted_proxy_requires_one_unambiguous_secure_protocol() -> anyhow::Result<()> {
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let config = GatewayTransportSecurityConfig {
            mode: GatewayTransportSecurityMode::TrustedReverseProxy,
            trusted_proxy: GatewayTrustedProxyConfig {
                peers: vec![peer],
                ..GatewayTrustedProxyConfig::default()
            },
            ..GatewayTransportSecurityConfig::default()
        };
        let cases: &[(&[&str], Option<&str>)] = &[
            (&[], Some("proto_required")),
            (&["https"], None),
            (&["wss"], None),
            (&["http"], Some("proto_denied")),
            (&["https, http"], Some("proto_denied")),
            (&["http, https"], Some("proto_denied")),
            (&["https", "http"], Some("proto_invalid")),
            (&["http", "https"], Some("proto_invalid")),
            (&["https", "https"], Some("proto_invalid")),
            (&["https", "wss"], Some("proto_invalid")),
        ];
        for (values, expected) in cases {
            let mut headers = HeaderMap::new();
            for value in *values {
                headers.append("x-forwarded-proto", HeaderValue::from_str(value)?);
            }
            let actual = validate_ws_transport(&headers, peer, &config);
            ensure!(
                actual == *expected,
                "protocol values {values:?}: got {actual:?}, expected {expected:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn local_origin_must_be_a_single_valid_loopback_origin() -> anyhow::Result<()> {
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let config = GatewayTransportSecurityConfig::default();
        let mut headers = HeaderMap::new();
        headers.append(
            header::ORIGIN,
            HeaderValue::from_static("http://localhost:3000"),
        );
        ensure!(validate_ws_transport(&headers, peer, &config).is_none());
        headers.append(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        ensure!(validate_ws_transport(&headers, peer, &config) == Some("origin_invalid"));
        headers.clear();
        headers.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        ensure!(validate_ws_transport(&headers, peer, &config) == Some("origin_denied"));
        Ok(())
    }
}
