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
            if let Some(origin) = headers.get(header::ORIGIN) {
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
                let proto = match headers.get("x-forwarded-proto") {
                    Some(value) => match value.to_str() {
                        Ok(value) => value,
                        Err(_) => return Some("proto_invalid"),
                    },
                    None => return Some("proto_required"),
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
