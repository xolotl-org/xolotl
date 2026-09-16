#[cfg(feature = "external-gateway")]
use crate::transport::GatewayTransportSecurityTuning;
use anyhow::{Context, Result};
use serde::Deserialize;
#[cfg(all(test, feature = "external-gateway"))]
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;
use xolotl_console::{
    ConsoleAuthConfig, ConsoleTransportSecurityConfig, ConsoleTransportSecurityMode,
    ConsoleTrustedProxyConfig, ConsoleUnsafeTransportRelaxation, ConsoleWebAuthnConfig,
    ConsoleWsConfig, DEFAULT_GLOBAL_SESSION_LIMIT, DEFAULT_IDLE_TTL_MS,
    DEFAULT_MAX_SESSIONS_PER_USER, DEFAULT_SESSION_TTL_MS, DEFAULT_WS_IDLE_TIMEOUT,
    DEFAULT_WS_MAX_BYTES_PER_SECOND, DEFAULT_WS_MAX_CONNECTIONS_GLOBAL,
    DEFAULT_WS_MAX_CONNECTIONS_PER_SOURCE, DEFAULT_WS_MAX_CONNECTIONS_PER_USER,
    DEFAULT_WS_MAX_FACT_LIMIT, DEFAULT_WS_MAX_FRAME_BYTES, DEFAULT_WS_MAX_FRAMES_PER_SECOND,
    DEFAULT_WS_MAX_PENDING_EVENT_BYTES, DEFAULT_WS_MAX_STATE_LIST_LIMIT,
    DEFAULT_WS_MAX_SUBSCRIPTIONS, DEFAULT_WS_MAX_TRACE_LIMIT, DEFAULT_WS_SEND_TIMEOUT,
    default_argon2_concurrency,
};
#[cfg(feature = "external-websocket")]
use xolotl_gateway::GatewayTransportSecurityConfig;
#[cfg(all(test, feature = "external-gateway"))]
use xolotl_gateway::GatewayTransportSecurityMode;
#[cfg(feature = "external-websocket")]
use xolotl_gateway_websocket::{
    DEFAULT_FIRST_FRAME_TIMEOUT_MS as DEFAULT_EXTERNAL_WS_FIRST_FRAME_TIMEOUT_MS,
    DEFAULT_IDLE_TIMEOUT_MS as DEFAULT_EXTERNAL_WS_IDLE_TIMEOUT_MS,
    DEFAULT_MAX_CONNECTIONS as DEFAULT_EXTERNAL_WS_MAX_CONNECTIONS,
    DEFAULT_MAX_FRAME_BYTES as DEFAULT_EXTERNAL_WS_MAX_FRAME_BYTES, ExternalWebSocketConfig,
};

#[cfg(feature = "external-gateway")]
pub const DEFAULT_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
#[cfg(feature = "external-gateway")]
pub const HARD_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1000;
#[cfg(feature = "external-gateway")]
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS: usize = 1024;
#[cfg(feature = "external-gateway")]
pub const HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS: usize = 65_536;
#[cfg(feature = "external-gateway")]
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY: usize = 256;
#[cfg(feature = "external-gateway")]
pub const HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY: usize = 65_536;
#[cfg(feature = "external-gateway")]
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT: usize = 256;
#[cfg(feature = "external-gateway")]
pub const HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT: usize = 65_536;
#[cfg(feature = "external-gateway")]
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES: usize = 65_536;
#[cfg(feature = "external-gateway")]
pub const HARD_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "external-gateway")]
pub const DEFAULT_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS: usize = 1024;
#[cfg(feature = "external-gateway")]
pub const HARD_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS: usize = 65_536;
#[cfg(feature = "external-gateway")]
pub const DEFAULT_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES: usize = 65_536;
#[cfg(feature = "external-gateway")]
pub const HARD_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES: usize = 16 * 1024 * 1024;
#[cfg(feature = "external-gateway")]
pub const DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
#[cfg(feature = "external-gateway")]
pub const HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS: u64 = 600_000;
#[cfg(feature = "external-gateway")]
pub const DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX: usize = 600;
#[cfg(feature = "external-gateway")]
pub const HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX: usize = 65_536;

/// Bootstrap-only config loaded by `xolotld`: storage, listeners, console root
/// bootstrap material, and bounded console auth/WebSocket resource limits.
/// Runtime config such as external Provider/Source installations, models,
/// groups, routing, bindings, process declarations, and policies lives in Xolotl
/// state.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XolotlConfig {
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub console: ConsoleConfig,
    #[cfg(feature = "external-gateway")]
    #[serde(default)]
    pub external_gateway: ExternalGatewayConfig,
    #[cfg(feature = "application-grpc")]
    #[serde(default)]
    pub application_gateway: crate::application::config::ApplicationGatewayConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default = "default_storage_kind")]
    pub kind: String,
    #[serde(default = "default_storage_path")]
    pub path: String,
    /// Object directory, independent of State rows. Defaults beside the database.
    #[serde(default)]
    pub object_path: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            kind: default_storage_kind(),
            path: default_storage_path(),
            object_path: None,
        }
    }
}

fn default_storage_kind() -> String {
    "redb".into()
}

fn default_storage_path() -> String {
    "xolotl.db".into()
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Console HTTP and Console WebSocket listener address.
    pub console_addr: Option<String>,
    /// External Provider/Source gRPC listener address.
    #[cfg(feature = "external-grpc")]
    pub external_grpc_addr: Option<String>,
    /// Authenticated application Gateway gRPC listener address.
    #[cfg(feature = "application-grpc")]
    pub application_grpc_addr: Option<String>,
    /// External Provider/Source WebSocket listener address.
    #[cfg(feature = "external-websocket")]
    pub external_websocket_addr: Option<String>,
}

#[cfg(feature = "external-gateway")]
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExternalGatewayConfig {
    #[cfg(feature = "external-grpc")]
    #[serde(default)]
    pub grpc: ExternalGatewayGrpcConfig,
    #[cfg(feature = "external-websocket")]
    #[serde(default)]
    pub websocket: ExternalGatewayWebSocketConfig,
}

#[cfg(feature = "external-gateway")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ExternalGatewaySessionLimits {
    pub source_dedupe_window_ms: u64,
    pub provider_max_in_flight_invocations: usize,
    pub provider_max_in_flight_per_identity: usize,
    pub provider_max_in_flight_per_effect: usize,
    pub provider_max_inline_result_bytes: usize,
    pub source_max_in_flight_commands: usize,
    pub source_command_max_inline_result_bytes: usize,
    pub source_command_rate_limit_window_ms: u64,
    pub source_command_rate_limit_max: usize,
}

#[cfg(feature = "external-gateway")]
impl Default for ExternalGatewaySessionLimits {
    fn default() -> Self {
        Self {
            source_dedupe_window_ms: default_external_source_dedupe_window_ms(),
            provider_max_in_flight_invocations: default_external_provider_max_in_flight_invocations(
            ),
            provider_max_in_flight_per_identity:
                default_external_provider_max_in_flight_per_identity(),
            provider_max_in_flight_per_effect: default_external_provider_max_in_flight_per_effect(),
            provider_max_inline_result_bytes: default_external_provider_max_inline_result_bytes(),
            source_max_in_flight_commands: default_external_source_max_in_flight_commands(),
            source_command_max_inline_result_bytes:
                default_external_source_command_max_inline_result_bytes(),
            source_command_rate_limit_window_ms:
                default_external_source_command_rate_limit_window_ms(),
            source_command_rate_limit_max: default_external_source_command_rate_limit_max(),
        }
        .bounded()
    }
}

#[cfg(feature = "external-gateway")]
impl ExternalGatewaySessionLimits {
    pub fn bounded(mut self) -> Self {
        self.source_dedupe_window_ms = clamp_or_default_u64(
            self.source_dedupe_window_ms,
            DEFAULT_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS,
            HARD_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS,
        );
        self.provider_max_in_flight_invocations = clamp_or_default(
            self.provider_max_in_flight_invocations,
            DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS,
            HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS,
        );
        self.provider_max_in_flight_per_identity = clamp_or_default(
            self.provider_max_in_flight_per_identity,
            DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY,
            HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY,
        );
        self.provider_max_in_flight_per_effect = clamp_or_default(
            self.provider_max_in_flight_per_effect,
            DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT,
            HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT,
        );
        self.provider_max_inline_result_bytes = clamp_or_default(
            self.provider_max_inline_result_bytes,
            DEFAULT_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES,
            HARD_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES,
        );
        self.source_max_in_flight_commands = clamp_or_default(
            self.source_max_in_flight_commands,
            DEFAULT_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS,
            HARD_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS,
        );
        self.source_command_max_inline_result_bytes = clamp_or_default(
            self.source_command_max_inline_result_bytes,
            DEFAULT_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES,
            HARD_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES,
        );
        self.source_command_rate_limit_window_ms = clamp_or_default_u64(
            self.source_command_rate_limit_window_ms,
            DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS,
            HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS,
        );
        self.source_command_rate_limit_max = clamp_or_default(
            self.source_command_rate_limit_max,
            DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX,
            HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX,
        );
        self
    }
}

#[cfg(feature = "external-grpc")]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalGatewayGrpcConfig {
    #[serde(default)]
    pub transport_security: GatewayTransportSecurityTuning,
    #[serde(default = "default_external_source_dedupe_window_ms")]
    pub source_dedupe_window_ms: u64,
    #[serde(default = "default_external_provider_max_in_flight_invocations")]
    pub provider_max_in_flight_invocations: usize,
    #[serde(default = "default_external_provider_max_in_flight_per_identity")]
    pub provider_max_in_flight_per_identity: usize,
    #[serde(default = "default_external_provider_max_in_flight_per_effect")]
    pub provider_max_in_flight_per_effect: usize,
    #[serde(default = "default_external_provider_max_inline_result_bytes")]
    pub provider_max_inline_result_bytes: usize,
    #[serde(default = "default_external_source_max_in_flight_commands")]
    pub source_max_in_flight_commands: usize,
    #[serde(default = "default_external_source_command_max_inline_result_bytes")]
    pub source_command_max_inline_result_bytes: usize,
    #[serde(default = "default_external_source_command_rate_limit_window_ms")]
    pub source_command_rate_limit_window_ms: u64,
    #[serde(default = "default_external_source_command_rate_limit_max")]
    pub source_command_rate_limit_max: usize,
}

#[cfg(feature = "external-grpc")]
impl Default for ExternalGatewayGrpcConfig {
    fn default() -> Self {
        let limits = ExternalGatewaySessionLimits::default();
        Self {
            transport_security: GatewayTransportSecurityTuning::default(),
            source_dedupe_window_ms: limits.source_dedupe_window_ms,
            provider_max_in_flight_invocations: limits.provider_max_in_flight_invocations,
            provider_max_in_flight_per_identity: limits.provider_max_in_flight_per_identity,
            provider_max_in_flight_per_effect: limits.provider_max_in_flight_per_effect,
            provider_max_inline_result_bytes: limits.provider_max_inline_result_bytes,
            source_max_in_flight_commands: limits.source_max_in_flight_commands,
            source_command_max_inline_result_bytes: limits.source_command_max_inline_result_bytes,
            source_command_rate_limit_window_ms: limits.source_command_rate_limit_window_ms,
            source_command_rate_limit_max: limits.source_command_rate_limit_max,
        }
    }
}

#[cfg(feature = "external-grpc")]
impl ExternalGatewayGrpcConfig {
    pub fn session_limits(&self) -> ExternalGatewaySessionLimits {
        ExternalGatewaySessionLimits::from(self).bounded()
    }

    pub fn bounded(mut self) -> Self {
        let limits = self.session_limits();
        self.apply_session_limits(limits);
        self
    }

    fn apply_session_limits(&mut self, limits: ExternalGatewaySessionLimits) {
        self.source_dedupe_window_ms = limits.source_dedupe_window_ms;
        self.provider_max_in_flight_invocations = limits.provider_max_in_flight_invocations;
        self.provider_max_in_flight_per_identity = limits.provider_max_in_flight_per_identity;
        self.provider_max_in_flight_per_effect = limits.provider_max_in_flight_per_effect;
        self.provider_max_inline_result_bytes = limits.provider_max_inline_result_bytes;
        self.source_max_in_flight_commands = limits.source_max_in_flight_commands;
        self.source_command_max_inline_result_bytes = limits.source_command_max_inline_result_bytes;
        self.source_command_rate_limit_window_ms = limits.source_command_rate_limit_window_ms;
        self.source_command_rate_limit_max = limits.source_command_rate_limit_max;
    }
}

#[cfg(feature = "external-websocket")]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalGatewayWebSocketConfig {
    #[serde(default)]
    pub transport: ExternalGatewayWebSocketTransportTuning,
    #[serde(default)]
    pub transport_security: GatewayTransportSecurityTuning,
    #[serde(default = "default_external_source_dedupe_window_ms")]
    pub source_dedupe_window_ms: u64,
    #[serde(default = "default_external_provider_max_in_flight_invocations")]
    pub provider_max_in_flight_invocations: usize,
    #[serde(default = "default_external_provider_max_in_flight_per_identity")]
    pub provider_max_in_flight_per_identity: usize,
    #[serde(default = "default_external_provider_max_in_flight_per_effect")]
    pub provider_max_in_flight_per_effect: usize,
    #[serde(default = "default_external_provider_max_inline_result_bytes")]
    pub provider_max_inline_result_bytes: usize,
    #[serde(default = "default_external_source_max_in_flight_commands")]
    pub source_max_in_flight_commands: usize,
    #[serde(default = "default_external_source_command_max_inline_result_bytes")]
    pub source_command_max_inline_result_bytes: usize,
    #[serde(default = "default_external_source_command_rate_limit_window_ms")]
    pub source_command_rate_limit_window_ms: u64,
    #[serde(default = "default_external_source_command_rate_limit_max")]
    pub source_command_rate_limit_max: usize,
}

#[cfg(feature = "external-websocket")]
impl Default for ExternalGatewayWebSocketConfig {
    fn default() -> Self {
        let limits = ExternalGatewaySessionLimits::default();
        Self {
            transport: ExternalGatewayWebSocketTransportTuning::default(),
            transport_security: GatewayTransportSecurityTuning::default(),
            source_dedupe_window_ms: limits.source_dedupe_window_ms,
            provider_max_in_flight_invocations: limits.provider_max_in_flight_invocations,
            provider_max_in_flight_per_identity: limits.provider_max_in_flight_per_identity,
            provider_max_in_flight_per_effect: limits.provider_max_in_flight_per_effect,
            provider_max_inline_result_bytes: limits.provider_max_inline_result_bytes,
            source_max_in_flight_commands: limits.source_max_in_flight_commands,
            source_command_max_inline_result_bytes: limits.source_command_max_inline_result_bytes,
            source_command_rate_limit_window_ms: limits.source_command_rate_limit_window_ms,
            source_command_rate_limit_max: limits.source_command_rate_limit_max,
        }
    }
}

#[cfg(feature = "external-websocket")]
impl ExternalGatewayWebSocketConfig {
    pub fn session_limits(&self) -> ExternalGatewaySessionLimits {
        ExternalGatewaySessionLimits::from(self).bounded()
    }

    pub fn bounded(mut self) -> Self {
        self.transport = self.transport.bounded();
        let limits = self.session_limits();
        self.apply_session_limits(limits);
        self
    }

    fn apply_session_limits(&mut self, limits: ExternalGatewaySessionLimits) {
        self.source_dedupe_window_ms = limits.source_dedupe_window_ms;
        self.provider_max_in_flight_invocations = limits.provider_max_in_flight_invocations;
        self.provider_max_in_flight_per_identity = limits.provider_max_in_flight_per_identity;
        self.provider_max_in_flight_per_effect = limits.provider_max_in_flight_per_effect;
        self.provider_max_inline_result_bytes = limits.provider_max_inline_result_bytes;
        self.source_max_in_flight_commands = limits.source_max_in_flight_commands;
        self.source_command_max_inline_result_bytes = limits.source_command_max_inline_result_bytes;
        self.source_command_rate_limit_window_ms = limits.source_command_rate_limit_window_ms;
        self.source_command_rate_limit_max = limits.source_command_rate_limit_max;
    }
}

#[cfg(feature = "external-grpc")]
impl From<&ExternalGatewayGrpcConfig> for ExternalGatewaySessionLimits {
    fn from(config: &ExternalGatewayGrpcConfig) -> Self {
        Self {
            source_dedupe_window_ms: config.source_dedupe_window_ms,
            provider_max_in_flight_invocations: config.provider_max_in_flight_invocations,
            provider_max_in_flight_per_identity: config.provider_max_in_flight_per_identity,
            provider_max_in_flight_per_effect: config.provider_max_in_flight_per_effect,
            provider_max_inline_result_bytes: config.provider_max_inline_result_bytes,
            source_max_in_flight_commands: config.source_max_in_flight_commands,
            source_command_max_inline_result_bytes: config.source_command_max_inline_result_bytes,
            source_command_rate_limit_window_ms: config.source_command_rate_limit_window_ms,
            source_command_rate_limit_max: config.source_command_rate_limit_max,
        }
    }
}

#[cfg(feature = "external-websocket")]
impl From<&ExternalGatewayWebSocketConfig> for ExternalGatewaySessionLimits {
    fn from(config: &ExternalGatewayWebSocketConfig) -> Self {
        Self {
            source_dedupe_window_ms: config.source_dedupe_window_ms,
            provider_max_in_flight_invocations: config.provider_max_in_flight_invocations,
            provider_max_in_flight_per_identity: config.provider_max_in_flight_per_identity,
            provider_max_in_flight_per_effect: config.provider_max_in_flight_per_effect,
            provider_max_inline_result_bytes: config.provider_max_inline_result_bytes,
            source_max_in_flight_commands: config.source_max_in_flight_commands,
            source_command_max_inline_result_bytes: config.source_command_max_inline_result_bytes,
            source_command_rate_limit_window_ms: config.source_command_rate_limit_window_ms,
            source_command_rate_limit_max: config.source_command_rate_limit_max,
        }
    }
}

#[cfg(feature = "external-websocket")]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalGatewayWebSocketTransportTuning {
    #[serde(default = "default_external_ws_max_frame_bytes")]
    pub max_frame_bytes: usize,
    #[serde(default = "default_external_ws_first_frame_timeout_ms")]
    pub first_frame_timeout_ms: u64,
    #[serde(default = "default_external_ws_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    #[serde(default = "default_external_ws_max_connections")]
    pub max_connections: usize,
}

#[cfg(feature = "external-websocket")]
impl Default for ExternalGatewayWebSocketTransportTuning {
    fn default() -> Self {
        Self {
            max_frame_bytes: default_external_ws_max_frame_bytes(),
            first_frame_timeout_ms: default_external_ws_first_frame_timeout_ms(),
            idle_timeout_ms: default_external_ws_idle_timeout_ms(),
            max_connections: default_external_ws_max_connections(),
        }
        .bounded()
    }
}

#[cfg(feature = "external-websocket")]
impl ExternalGatewayWebSocketTransportTuning {
    pub fn bounded(mut self) -> Self {
        self.max_frame_bytes = clamp_or_default(
            self.max_frame_bytes,
            DEFAULT_EXTERNAL_WS_MAX_FRAME_BYTES,
            xolotl_gateway_websocket::HARD_MAX_FRAME_BYTES,
        );
        self.first_frame_timeout_ms = clamp_or_default_u64(
            self.first_frame_timeout_ms,
            DEFAULT_EXTERNAL_WS_FIRST_FRAME_TIMEOUT_MS,
            xolotl_gateway_websocket::HARD_FIRST_FRAME_TIMEOUT_MS,
        );
        self.idle_timeout_ms = clamp_or_default_u64(
            self.idle_timeout_ms,
            DEFAULT_EXTERNAL_WS_IDLE_TIMEOUT_MS,
            xolotl_gateway_websocket::HARD_IDLE_TIMEOUT_MS,
        );
        self.max_connections = clamp_or_default(
            self.max_connections,
            DEFAULT_EXTERNAL_WS_MAX_CONNECTIONS,
            xolotl_gateway_websocket::HARD_MAX_CONNECTIONS,
        );
        self
    }
}

#[cfg(feature = "external-websocket")]
impl From<ExternalGatewayWebSocketTransportTuning> for ExternalWebSocketConfig {
    fn from(value: ExternalGatewayWebSocketTransportTuning) -> Self {
        let value = value.bounded();
        Self {
            max_frame_bytes: value.max_frame_bytes,
            first_frame_timeout_ms: value.first_frame_timeout_ms,
            idle_timeout_ms: value.idle_timeout_ms,
            max_connections: value.max_connections,
            transport_security: GatewayTransportSecurityConfig::default(),
        }
        .bounded()
    }
}

#[cfg(feature = "external-gateway")]
fn default_external_source_dedupe_window_ms() -> u64 {
    DEFAULT_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS
}

#[cfg(feature = "external-gateway")]
fn default_external_provider_max_in_flight_invocations() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS
}

#[cfg(feature = "external-gateway")]
fn default_external_provider_max_in_flight_per_identity() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY
}

#[cfg(feature = "external-gateway")]
fn default_external_provider_max_in_flight_per_effect() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT
}

#[cfg(feature = "external-gateway")]
fn default_external_provider_max_inline_result_bytes() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES
}

#[cfg(feature = "external-gateway")]
fn default_external_source_max_in_flight_commands() -> usize {
    DEFAULT_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS
}

#[cfg(feature = "external-gateway")]
fn default_external_source_command_max_inline_result_bytes() -> usize {
    DEFAULT_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES
}

#[cfg(feature = "external-gateway")]
fn default_external_source_command_rate_limit_window_ms() -> u64 {
    DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS
}

#[cfg(feature = "external-gateway")]
fn default_external_source_command_rate_limit_max() -> usize {
    DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX
}

#[cfg(feature = "external-gateway")]
fn clamp_or_default(value: usize, default: usize, hard_max: usize) -> usize {
    if value == 0 {
        default
    } else {
        value.min(hard_max)
    }
}

#[cfg(feature = "external-gateway")]
fn clamp_or_default_u64(value: u64, default: u64, hard_max: u64) -> u64 {
    if value == 0 {
        default
    } else {
        value.min(hard_max)
    }
}

#[cfg(feature = "external-websocket")]
fn default_external_ws_max_frame_bytes() -> usize {
    DEFAULT_EXTERNAL_WS_MAX_FRAME_BYTES
}

#[cfg(feature = "external-websocket")]
fn default_external_ws_first_frame_timeout_ms() -> u64 {
    DEFAULT_EXTERNAL_WS_FIRST_FRAME_TIMEOUT_MS
}

#[cfg(feature = "external-websocket")]
fn default_external_ws_idle_timeout_ms() -> u64 {
    DEFAULT_EXTERNAL_WS_IDLE_TIMEOUT_MS
}

#[cfg(feature = "external-websocket")]
fn default_external_ws_max_connections() -> usize {
    DEFAULT_EXTERNAL_WS_MAX_CONNECTIONS
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    #[serde(default)]
    pub root: ConsoleRootConfig,
    #[serde(default)]
    pub auth: ConsoleAuthTuning,
    #[serde(default)]
    pub ws: ConsoleWsTuning,
    #[serde(default)]
    pub transport_security: ConsoleTransportSecurityTuning,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleTransportSecurityTuning {
    #[serde(default = "default_console_transport_security_mode")]
    pub mode: String,
    #[serde(default)]
    pub trusted_proxy_peers: Vec<String>,
    #[serde(default = "default_true")]
    pub honor_x_forwarded_proto: bool,
    #[serde(default = "default_true")]
    pub honor_x_forwarded_host: bool,
    #[serde(default = "default_true")]
    pub honor_x_forwarded_for: bool,
    #[serde(default)]
    pub unsafe_relaxations: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ConsoleListenerSecurity {
    pub listen_addr: SocketAddr,
    pub config: ConsoleTransportSecurityConfig,
}

impl Default for ConsoleTransportSecurityTuning {
    fn default() -> Self {
        Self {
            mode: default_console_transport_security_mode(),
            trusted_proxy_peers: Vec::new(),
            honor_x_forwarded_proto: true,
            honor_x_forwarded_host: true,
            honor_x_forwarded_for: true,
            unsafe_relaxations: Vec::new(),
        }
    }
}

impl ConsoleTransportSecurityTuning {
    pub fn validate_plain_listener(
        &self,
        label: &str,
        listen_addr: &str,
    ) -> Result<ConsoleListenerSecurity> {
        self.validate_plain_listener_inner(label, listen_addr, cfg!(test))
    }

    fn validate_plain_listener_inner(
        &self,
        label: &str,
        listen_addr: &str,
        allow_disabled_for_test: bool,
    ) -> Result<ConsoleListenerSecurity> {
        let listen_addr = listen_addr.parse::<SocketAddr>().with_context(|| {
            format!("{label} listen address '{listen_addr}' must be an IP socket address")
        })?;
        let config = self.to_console_transport_security_config_inner(allow_disabled_for_test)?;
        match config.mode {
            ConsoleTransportSecurityMode::ProductionTls
            | ConsoleTransportSecurityMode::MutualTls => {
                anyhow::bail!(
                    "{label} production_tls requires a TLS listener; configure trusted_reverse_proxy, local_trusted, or unsafe_plaintext for the current plain listener"
                );
            }
            ConsoleTransportSecurityMode::TrustedReverseProxy => {
                if config.trusted_proxy.peers.is_empty() {
                    anyhow::bail!(
                        "{label} trusted_reverse_proxy requires at least one trusted_proxy_peers entry"
                    );
                }
            }
            ConsoleTransportSecurityMode::LocalTrusted => {
                if !listen_addr.ip().is_loopback() {
                    anyhow::bail!("{label} local_trusted requires a loopback listen address");
                }
            }
            ConsoleTransportSecurityMode::UnsafePlaintext => {}
            ConsoleTransportSecurityMode::DisabledForTest => {
                if !allow_disabled_for_test {
                    anyhow::bail!(
                        "{label} transport security mode disabled_for_test is only valid in tests"
                    );
                }
            }
        }
        Ok(ConsoleListenerSecurity {
            listen_addr,
            config,
        })
    }

    #[cfg(test)]
    pub fn to_console_transport_security_config(&self) -> Result<ConsoleTransportSecurityConfig> {
        self.to_console_transport_security_config_inner(cfg!(test))
    }

    fn to_console_transport_security_config_inner(
        &self,
        allow_disabled_for_test: bool,
    ) -> Result<ConsoleTransportSecurityConfig> {
        let mode = match self.mode.as_str() {
            "production_tls" => ConsoleTransportSecurityMode::ProductionTls,
            "mtls" => ConsoleTransportSecurityMode::MutualTls,
            "trusted_reverse_proxy" => ConsoleTransportSecurityMode::TrustedReverseProxy,
            "local_trusted" => ConsoleTransportSecurityMode::LocalTrusted,
            "unsafe_plaintext" => ConsoleTransportSecurityMode::UnsafePlaintext,
            "disabled_for_test" => ConsoleTransportSecurityMode::DisabledForTest,
            other => anyhow::bail!("unknown console transport security mode '{other}'"),
        };
        if matches!(mode, ConsoleTransportSecurityMode::DisabledForTest) && !allow_disabled_for_test
        {
            anyhow::bail!(
                "console transport security mode disabled_for_test is only valid in tests"
            );
        }
        let peers = self
            .trusted_proxy_peers
            .iter()
            .map(|peer| {
                peer.parse::<IpAddr>()
                    .with_context(|| format!("invalid console trusted proxy peer '{peer}'"))
            })
            .collect::<Result<Vec<_>>>()?;
        if matches!(mode, ConsoleTransportSecurityMode::TrustedReverseProxy) && peers.is_empty() {
            anyhow::bail!("trusted_reverse_proxy requires at least one trusted_proxy_peers entry");
        }
        let unsafe_relaxations = self
            .unsafe_relaxations
            .iter()
            .map(|relaxation| match relaxation.as_str() {
                "allow_plaintext" => Ok(ConsoleUnsafeTransportRelaxation::AllowPlaintext),
                "ignore_origin_port" => Ok(ConsoleUnsafeTransportRelaxation::IgnoreOriginPort),
                "relaxed_origin" => Ok(ConsoleUnsafeTransportRelaxation::RelaxedOrigin),
                other => anyhow::bail!("unknown console unsafe transport relaxation '{other}'"),
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ConsoleTransportSecurityConfig {
            mode,
            trusted_proxy: ConsoleTrustedProxyConfig {
                peers,
                honor_x_forwarded_proto: self.honor_x_forwarded_proto,
                honor_x_forwarded_host: self.honor_x_forwarded_host,
                honor_x_forwarded_for: self.honor_x_forwarded_for,
            },
            unsafe_relaxations,
        }
        .bounded())
    }
}

fn default_console_transport_security_mode() -> String {
    "production_tls".into()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ConsoleRootConfig {
    /// Optional pre-seeded Argon2id PHC string for the root Console account.
    pub password_hash: Option<String>,
    /// Optional plaintext root password, mutually exclusive with `password_hash`.
    /// The console validates and hashes it at bootstrap.
    pub password: Option<String>,
    /// Optional Ed25519/WebAuthn key descriptors for deployments that disable
    /// root password bootstrap and provision key login externally.
    #[serde(default)]
    pub pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleAuthTuning {
    #[serde(default = "default_session_ttl_ms")]
    pub session_ttl_ms: i64,
    #[serde(default = "default_idle_ttl_ms")]
    pub idle_ttl_ms: i64,
    #[serde(default = "default_max_sessions_per_user")]
    pub max_sessions_per_user: usize,
    #[serde(default = "default_global_session_limit")]
    pub global_session_limit: usize,
    #[serde(default = "default_argon2_concurrency")]
    pub argon2_concurrency: usize,
    #[serde(default)]
    pub webauthn: ConsoleWebAuthnTuning,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleWebAuthnTuning {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_webauthn_rp_id")]
    pub rp_id: String,
    #[serde(default = "default_webauthn_rp_origin")]
    pub rp_origin: String,
    #[serde(default = "default_webauthn_rp_name")]
    pub rp_name: String,
    #[serde(default = "default_webauthn_challenge_ttl_ms")]
    pub challenge_ttl_ms: i64,
}

impl Default for ConsoleWebAuthnTuning {
    fn default() -> Self {
        Self {
            enabled: false,
            rp_id: default_webauthn_rp_id(),
            rp_origin: default_webauthn_rp_origin(),
            rp_name: default_webauthn_rp_name(),
            challenge_ttl_ms: default_webauthn_challenge_ttl_ms(),
        }
    }
}

impl From<ConsoleWebAuthnTuning> for ConsoleWebAuthnConfig {
    fn from(value: ConsoleWebAuthnTuning) -> Self {
        Self {
            enabled: value.enabled,
            rp_id: value.rp_id,
            rp_origin: value.rp_origin,
            rp_name: value.rp_name,
            challenge_ttl_ms: value.challenge_ttl_ms,
        }
        .bounded()
    }
}

impl Default for ConsoleAuthTuning {
    fn default() -> Self {
        Self {
            session_ttl_ms: default_session_ttl_ms(),
            idle_ttl_ms: default_idle_ttl_ms(),
            max_sessions_per_user: default_max_sessions_per_user(),
            global_session_limit: default_global_session_limit(),
            argon2_concurrency: default_argon2_concurrency(),
            webauthn: ConsoleWebAuthnTuning::default(),
        }
    }
}

impl From<ConsoleAuthTuning> for ConsoleAuthConfig {
    fn from(value: ConsoleAuthTuning) -> Self {
        Self {
            session_ttl_ms: value.session_ttl_ms,
            idle_ttl_ms: value.idle_ttl_ms,
            max_sessions_per_user: value.max_sessions_per_user,
            global_session_limit: value.global_session_limit,
            argon2_concurrency: value.argon2_concurrency,
            webauthn: value.webauthn.into(),
        }
        .bounded()
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleWsTuning {
    #[serde(default = "default_ws_max_frame_bytes")]
    pub max_frame_bytes: usize,
    #[serde(default = "default_ws_max_connections_global")]
    pub max_connections_global: usize,
    #[serde(default = "default_ws_max_connections_per_source")]
    pub max_connections_per_source: usize,
    #[serde(default = "default_ws_max_connections_per_user")]
    pub max_connections_per_user: usize,
    #[serde(default = "default_ws_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_ws_max_frames_per_second")]
    pub max_frames_per_second: usize,
    #[serde(default = "default_ws_max_bytes_per_second")]
    pub max_bytes_per_second: usize,
    #[serde(default = "default_ws_max_subscriptions")]
    pub max_subscriptions: usize,
    #[serde(default = "default_ws_max_state_list_limit")]
    pub max_state_list_limit: usize,
    #[serde(default = "default_ws_max_fact_limit")]
    pub max_fact_limit: usize,
    #[serde(default = "default_ws_max_trace_limit")]
    pub max_trace_limit: usize,
    #[serde(default = "default_ws_max_pending_event_bytes")]
    pub max_pending_event_bytes: usize,
    #[serde(default = "default_ws_send_timeout_ms")]
    pub send_timeout_ms: u64,
}

impl Default for ConsoleWsTuning {
    fn default() -> Self {
        Self {
            max_frame_bytes: default_ws_max_frame_bytes(),
            max_connections_global: default_ws_max_connections_global(),
            max_connections_per_source: default_ws_max_connections_per_source(),
            max_connections_per_user: default_ws_max_connections_per_user(),
            idle_timeout_secs: default_ws_idle_timeout_secs(),
            max_frames_per_second: default_ws_max_frames_per_second(),
            max_bytes_per_second: default_ws_max_bytes_per_second(),
            max_subscriptions: default_ws_max_subscriptions(),
            max_state_list_limit: default_ws_max_state_list_limit(),
            max_fact_limit: default_ws_max_fact_limit(),
            max_trace_limit: default_ws_max_trace_limit(),
            max_pending_event_bytes: default_ws_max_pending_event_bytes(),
            send_timeout_ms: default_ws_send_timeout_ms(),
        }
    }
}

impl From<ConsoleWsTuning> for ConsoleWsConfig {
    fn from(value: ConsoleWsTuning) -> Self {
        Self {
            max_frame_bytes: value.max_frame_bytes,
            max_connections_global: value.max_connections_global,
            max_connections_per_source: value.max_connections_per_source,
            max_connections_per_user: value.max_connections_per_user,
            idle_timeout: Duration::from_secs(value.idle_timeout_secs),
            max_frames_per_second: value.max_frames_per_second,
            max_bytes_per_second: value.max_bytes_per_second,
            max_subscriptions: value.max_subscriptions,
            max_state_list_limit: value.max_state_list_limit,
            max_fact_limit: value.max_fact_limit,
            max_trace_limit: value.max_trace_limit,
            max_pending_event_bytes: value.max_pending_event_bytes,
            send_timeout: Duration::from_millis(value.send_timeout_ms),
        }
        .bounded()
    }
}

fn default_session_ttl_ms() -> i64 {
    DEFAULT_SESSION_TTL_MS
}

fn default_idle_ttl_ms() -> i64 {
    DEFAULT_IDLE_TTL_MS
}

fn default_max_sessions_per_user() -> usize {
    DEFAULT_MAX_SESSIONS_PER_USER
}

fn default_global_session_limit() -> usize {
    DEFAULT_GLOBAL_SESSION_LIMIT
}

fn default_webauthn_rp_id() -> String {
    "localhost".into()
}

fn default_webauthn_rp_origin() -> String {
    "https://localhost".into()
}

fn default_webauthn_rp_name() -> String {
    "Xolotl Console".into()
}

fn default_webauthn_challenge_ttl_ms() -> i64 {
    60_000
}

fn default_ws_max_frame_bytes() -> usize {
    DEFAULT_WS_MAX_FRAME_BYTES
}

fn default_ws_max_connections_global() -> usize {
    DEFAULT_WS_MAX_CONNECTIONS_GLOBAL
}

fn default_ws_max_connections_per_source() -> usize {
    DEFAULT_WS_MAX_CONNECTIONS_PER_SOURCE
}

fn default_ws_max_connections_per_user() -> usize {
    DEFAULT_WS_MAX_CONNECTIONS_PER_USER
}

fn default_ws_idle_timeout_secs() -> u64 {
    DEFAULT_WS_IDLE_TIMEOUT.as_secs()
}

fn default_ws_max_frames_per_second() -> usize {
    DEFAULT_WS_MAX_FRAMES_PER_SECOND
}

fn default_ws_max_bytes_per_second() -> usize {
    DEFAULT_WS_MAX_BYTES_PER_SECOND
}

fn default_ws_max_subscriptions() -> usize {
    DEFAULT_WS_MAX_SUBSCRIPTIONS
}

fn default_ws_max_state_list_limit() -> usize {
    DEFAULT_WS_MAX_STATE_LIST_LIMIT
}

fn default_ws_max_fact_limit() -> usize {
    DEFAULT_WS_MAX_FACT_LIMIT
}

fn default_ws_max_trace_limit() -> usize {
    DEFAULT_WS_MAX_TRACE_LIMIT
}

fn default_ws_max_pending_event_bytes() -> usize {
    DEFAULT_WS_MAX_PENDING_EVENT_BYTES
}

fn default_ws_send_timeout_ms() -> u64 {
    DEFAULT_WS_SEND_TIMEOUT.as_millis() as u64
}

impl XolotlConfig {
    pub fn load() -> Result<Option<Self>> {
        let path = std::env::var("XOLOTL_CONFIG").unwrap_or_else(|_| "xolotl.toml".into());

        let path = Path::new(&path);
        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading config from {}", path.display()))?;

        let config: XolotlConfig = toml::from_str(&content)
            .with_context(|| format!("parsing config from {}", path.display()))?;

        Ok(Some(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::bail;
    use xolotl_console::{
        HARD_GLOBAL_SESSION_LIMIT, HARD_MAX_WS_CONNECTIONS_PER_SOURCE, HARD_MAX_WS_FRAME_BYTES,
        HARD_MAX_WS_FRAMES_PER_SECOND, HARD_MAX_WS_SUBSCRIPTIONS, HARD_MAX_WS_TRACE_LIMIT,
        MIN_ARGON2_CONCURRENCY, MIN_IDLE_TTL_MS, MIN_MAX_SESSIONS_PER_USER, MIN_SESSION_TTL_MS,
        MIN_WS_CONNECTIONS_GLOBAL, MIN_WS_CONNECTIONS_PER_USER, MIN_WS_IDLE_TIMEOUT,
        MIN_WS_MAX_BYTES_PER_SECOND, MIN_WS_MAX_FACT_LIMIT, MIN_WS_MAX_PENDING_EVENT_BYTES,
        MIN_WS_MAX_STATE_LIST_LIMIT, MIN_WS_SEND_TIMEOUT,
    };

    macro_rules! assert {
        ($condition:expr $(,)?) => {
            anyhow::ensure!($condition, "assertion failed: {}", stringify!($condition));
        };
        ($condition:expr, $($arg:tt)+) => {
            anyhow::ensure!($condition, $($arg)+);
        };
    }

    macro_rules! assert_eq {
        ($left:expr, $right:expr $(,)?) => {
            match (&$left, &$right) {
                (left, right) => anyhow::ensure!(
                    left == right,
                    "assertion failed: left != right\nleft: {left:?}\nright: {right:?}"
                ),
            }
        };
        ($left:expr, $right:expr, $($arg:tt)+) => {
            anyhow::ensure!($left == $right, $($arg)+);
        };
    }

    fn assert_config_rejects_unknown_field(toml: &str, field: &str) -> anyhow::Result<()> {
        let err = match toml::from_str::<XolotlConfig>(toml) {
            Ok(config) => bail!("expected unknown-field rejection, got {config:?}"),
            Err(error) => error,
        };
        let message = err.to_string();
        assert!(
            message.contains("unknown field") && message.contains(field),
            "unexpected error for {field}: {message}"
        );
        Ok(())
    }

    #[cfg(feature = "external-gateway")]
    fn temp_config_file(name: &str, contents: &[u8]) -> anyhow::Result<String> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system time is before unix epoch")?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "xolotl-config-test-{}-{nanos}-{name}",
            std::process::id()
        ));
        fs::write(&path, contents)
            .with_context(|| format!("writing temporary config file {}", path.display()))?;
        Ok(path.to_string_lossy().into_owned())
    }

    #[test]
    fn console_tuning_defaults_match_runtime_defaults() -> anyhow::Result<()> {
        let auth: ConsoleAuthConfig = ConsoleAuthTuning::default().into();
        let default_auth = ConsoleAuthConfig::default();
        assert_eq!(auth.session_ttl_ms, default_auth.session_ttl_ms);
        assert_eq!(auth.idle_ttl_ms, default_auth.idle_ttl_ms);
        assert_eq!(
            auth.max_sessions_per_user,
            default_auth.max_sessions_per_user
        );
        assert_eq!(auth.global_session_limit, default_auth.global_session_limit);
        assert_eq!(auth.argon2_concurrency, default_auth.argon2_concurrency);

        let ws: ConsoleWsConfig = ConsoleWsTuning::default().into();
        let default_ws = ConsoleWsConfig::default();
        assert_eq!(ws.max_frame_bytes, default_ws.max_frame_bytes);
        assert_eq!(ws.max_connections_global, default_ws.max_connections_global);
        assert_eq!(
            ws.max_connections_per_source,
            default_ws.max_connections_per_source
        );
        assert_eq!(
            ws.max_connections_per_user,
            default_ws.max_connections_per_user
        );
        assert_eq!(ws.idle_timeout, default_ws.idle_timeout);
        assert_eq!(ws.max_frames_per_second, default_ws.max_frames_per_second);
        assert_eq!(ws.max_bytes_per_second, default_ws.max_bytes_per_second);
        assert_eq!(ws.max_subscriptions, default_ws.max_subscriptions);
        assert_eq!(ws.max_fact_limit, default_ws.max_fact_limit);
        assert_eq!(ws.max_trace_limit, default_ws.max_trace_limit);
        assert_eq!(
            ws.max_pending_event_bytes,
            default_ws.max_pending_event_bytes
        );
        assert_eq!(ws.send_timeout, default_ws.send_timeout);
        Ok(())
    }

    #[test]
    fn console_tuning_clamps_unreasonable_values() -> anyhow::Result<()> {
        let auth: ConsoleAuthConfig = ConsoleAuthTuning {
            session_ttl_ms: 1,
            idle_ttl_ms: -1,
            max_sessions_per_user: 0,
            global_session_limit: usize::MAX,
            argon2_concurrency: 0,
            webauthn: ConsoleWebAuthnTuning::default(),
        }
        .into();
        assert_eq!(auth.session_ttl_ms, MIN_SESSION_TTL_MS);
        assert_eq!(auth.idle_ttl_ms, MIN_IDLE_TTL_MS);
        assert_eq!(auth.max_sessions_per_user, MIN_MAX_SESSIONS_PER_USER);
        assert_eq!(auth.global_session_limit, HARD_GLOBAL_SESSION_LIMIT);
        assert_eq!(auth.argon2_concurrency, MIN_ARGON2_CONCURRENCY);

        let ws: ConsoleWsConfig = ConsoleWsTuning {
            max_frame_bytes: usize::MAX,
            max_connections_global: 0,
            max_connections_per_source: usize::MAX,
            max_connections_per_user: 0,
            idle_timeout_secs: 0,
            max_frames_per_second: usize::MAX,
            max_bytes_per_second: 1,
            max_subscriptions: usize::MAX,
            max_state_list_limit: 0,
            max_fact_limit: 0,
            max_trace_limit: usize::MAX,
            max_pending_event_bytes: 0,
            send_timeout_ms: 1,
        }
        .into();
        assert_eq!(ws.max_frame_bytes, HARD_MAX_WS_FRAME_BYTES);
        assert_eq!(ws.max_connections_global, MIN_WS_CONNECTIONS_GLOBAL);
        assert_eq!(
            ws.max_connections_per_source,
            HARD_MAX_WS_CONNECTIONS_PER_SOURCE
        );
        assert_eq!(ws.max_connections_per_user, MIN_WS_CONNECTIONS_PER_USER);
        assert_eq!(ws.idle_timeout, MIN_WS_IDLE_TIMEOUT);
        assert_eq!(ws.max_frames_per_second, HARD_MAX_WS_FRAMES_PER_SECOND);
        assert_eq!(ws.max_bytes_per_second, MIN_WS_MAX_BYTES_PER_SECOND);
        assert_eq!(ws.max_subscriptions, HARD_MAX_WS_SUBSCRIPTIONS);
        assert_eq!(ws.max_state_list_limit, MIN_WS_MAX_STATE_LIST_LIMIT);
        assert_eq!(ws.max_fact_limit, MIN_WS_MAX_FACT_LIMIT);
        assert_eq!(ws.max_trace_limit, HARD_MAX_WS_TRACE_LIMIT);
        assert_eq!(ws.max_pending_event_bytes, MIN_WS_MAX_PENDING_EVENT_BYTES);
        assert_eq!(ws.send_timeout, MIN_WS_SEND_TIMEOUT);
        Ok(())
    }

    #[test]
    fn config_file_accepts_console_transport_security() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[console.transport_security]
mode = "trusted_reverse_proxy"
trusted_proxy_peers = ["127.0.0.1"]
honor_x_forwarded_proto = true
honor_x_forwarded_host = true
honor_x_forwarded_for = true
"#,
        )?;

        let transport = cfg
            .console
            .transport_security
            .to_console_transport_security_config()?;
        assert_eq!(
            transport.mode,
            ConsoleTransportSecurityMode::TrustedReverseProxy
        );
        assert_eq!(
            transport.trusted_proxy.peers,
            vec!["127.0.0.1".parse::<IpAddr>()?]
        );
        Ok(())
    }

    #[test]
    fn console_transport_security_requires_proxy_peer() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[console.transport_security]
mode = "trusted_reverse_proxy"
"#,
        )?;

        let err = match cfg
            .console
            .transport_security
            .to_console_transport_security_config()
        {
            Ok(transport) => bail!("expected proxy peer rejection, got {transport:?}"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("trusted_proxy_peers"));
        Ok(())
    }

    #[test]
    fn console_plain_listener_rejects_production_tls() -> anyhow::Result<()> {
        let cfg = toml::from_str::<XolotlConfig>(
            r#"
[console.transport_security]
mode = "production_tls"
"#,
        )?;

        let err = match cfg
            .console
            .transport_security
            .validate_plain_listener("console", "127.0.0.1:9000")
        {
            Ok(listener) => bail!("expected production TLS rejection, got {listener:?}"),
            Err(error) => error,
        };
        let message = err.to_string();
        assert!(message.contains("production_tls requires a TLS listener"));
        Ok(())
    }

    #[test]
    fn console_local_trusted_requires_loopback_listener() -> anyhow::Result<()> {
        let cfg = toml::from_str::<XolotlConfig>(
            r#"
[console.transport_security]
mode = "local_trusted"
"#,
        )?;

        let err = match cfg
            .console
            .transport_security
            .validate_plain_listener("console", "0.0.0.0:9000")
        {
            Ok(listener) => bail!("expected local trusted rejection, got {listener:?}"),
            Err(error) => error,
        };
        let message = err.to_string();
        assert!(message.contains("local_trusted requires a loopback listen address"));
        Ok(())
    }

    #[test]
    fn config_file_accepts_explicit_console_unsafe_transport() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[console.transport_security]
mode = "unsafe_plaintext"
unsafe_relaxations = ["ignore_origin_port"]
"#,
        )?;

        let transport = cfg
            .console
            .transport_security
            .to_console_transport_security_config()?;
        assert_eq!(
            transport.mode,
            ConsoleTransportSecurityMode::UnsafePlaintext
        );
        assert!(transport.is_unsafe());
        assert!(transport.ignore_origin_port());
        Ok(())
    }

    #[test]
    fn config_file_rejects_unknown_bootstrap_fields() -> anyhow::Result<()> {
        assert_config_rejects_unknown_field(
            r#"
unknown_section = true
"#,
            "unknown_section",
        )?;
        assert_config_rejects_unknown_field(
            r#"
[server]
unknown_addr = "127.0.0.1:9100"
"#,
            "unknown_addr",
        )?;
        assert_config_rejects_unknown_field(
            r#"
[console.ws]
max_frame_bytez = 1024
"#,
            "max_frame_bytez",
        )?;
        Ok(())
    }

    #[cfg(all(feature = "external-grpc", feature = "external-websocket"))]
    #[test]
    fn example_config_uses_declared_fields() -> anyhow::Result<()> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../xolotl.toml.example");
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading example config {}", path.display()))?;
        toml::from_str::<XolotlConfig>(&content)
            .with_context(|| format!("parsing example config {}", path.display()))?;
        Ok(())
    }

    #[cfg(feature = "external-websocket")]
    #[test]
    fn gateway_transport_security_defaults_to_loopback_only() -> anyhow::Result<()> {
        let cfg = GatewayTransportSecurityTuning::default();
        let security = cfg
            .validate_plain_listener("external WebSocket gateway", "127.0.0.1:9200")
            .context("loopback listener should be accepted")?;
        assert_eq!(
            security.config.mode,
            GatewayTransportSecurityMode::LocalTrusted
        );
        assert_eq!(
            security.listen_addr,
            "127.0.0.1:9200".parse::<SocketAddr>()?
        );

        let err = match cfg.validate_plain_listener("external WebSocket gateway", "0.0.0.0:9200") {
            Ok(_security) => bail!("expected non-loopback listener rejection"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("loopback"));
        Ok(())
    }

    #[cfg(all(feature = "external-grpc", feature = "external-websocket"))]
    #[test]
    fn config_file_accepts_external_gateway_listeners() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[server]
external_grpc_addr = "127.0.0.1:9444"
external_websocket_addr = "127.0.0.1:9200"

[external_gateway.grpc]
source_dedupe_window_ms = 0
provider_max_in_flight_invocations = 0
provider_max_in_flight_per_identity = 0
provider_max_in_flight_per_effect = 0
provider_max_inline_result_bytes = 0
source_max_in_flight_commands = 0
source_command_max_inline_result_bytes = 0
source_command_rate_limit_window_ms = 0
source_command_rate_limit_max = 0

[external_gateway.grpc.transport_security]
mode = "local_trusted"

[external_gateway.websocket]
source_dedupe_window_ms = 0
provider_max_in_flight_invocations = 0
provider_max_in_flight_per_identity = 0
provider_max_in_flight_per_effect = 0
provider_max_inline_result_bytes = 0
source_max_in_flight_commands = 0
source_command_max_inline_result_bytes = 0
source_command_rate_limit_window_ms = 0
source_command_rate_limit_max = 0

[external_gateway.websocket.transport]
max_frame_bytes = 0
first_frame_timeout_ms = 0
idle_timeout_ms = 0
max_connections = 0

[external_gateway.websocket.transport_security]
mode = "local_trusted"
"#,
        )?;

        assert_eq!(
            cfg.server.external_grpc_addr.as_deref(),
            Some("127.0.0.1:9444")
        );
        assert_eq!(
            cfg.server.external_websocket_addr.as_deref(),
            Some("127.0.0.1:9200")
        );

        let grpc = cfg.external_gateway.grpc.clone().bounded();
        assert_eq!(
            grpc.session_limits(),
            ExternalGatewaySessionLimits::default()
        );

        let websocket = cfg.external_gateway.websocket.clone().bounded();
        assert_eq!(
            websocket.session_limits(),
            ExternalGatewaySessionLimits::default()
        );
        let ws_transport: ExternalWebSocketConfig = websocket.transport.into();
        assert_eq!(ws_transport, ExternalWebSocketConfig::default());

        #[cfg(feature = "external-grpc")]
        {
            let listener = cfg
                .external_gateway
                .grpc
                .transport_security
                .validate_grpc_listener(
                    "external gRPC gateway",
                    cfg.server
                        .external_grpc_addr
                        .as_deref()
                        .context("external_grpc_addr should be configured")?,
                )
                .context("gRPC listener should be accepted")?;
            assert_eq!(
                listener.config.mode,
                GatewayTransportSecurityMode::LocalTrusted
            );
        }

        let listener = cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener(
                "external WebSocket gateway",
                cfg.server
                    .external_websocket_addr
                    .as_deref()
                    .context("external_websocket_addr should be configured")?,
            )
            .context("WebSocket listener should be accepted")?;
        assert_eq!(
            listener.config.mode,
            GatewayTransportSecurityMode::LocalTrusted
        );
        Ok(())
    }

    #[cfg(feature = "external-websocket")]
    #[test]
    fn config_file_accepts_external_gateway_trusted_proxy_transport_security() -> anyhow::Result<()>
    {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[external_gateway.websocket.transport_security]
mode = "trusted_reverse_proxy"
trusted_proxy_peers = ["127.0.0.1"]
honor_x_forwarded_for = true
"#,
        )?;

        let security = cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener("external WebSocket gateway", "0.0.0.0:9200")
            .context("trusted proxy listener should be accepted")?;
        assert_eq!(
            security.config.mode,
            GatewayTransportSecurityMode::TrustedReverseProxy
        );
        assert_eq!(
            security.config.trusted_proxy.peers,
            vec!["127.0.0.1".parse::<IpAddr>()?]
        );
        Ok(())
    }

    #[cfg(feature = "external-websocket")]
    #[test]
    fn external_gateway_plain_listener_trusted_proxy_requires_peer() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[external_gateway.websocket.transport_security]
mode = "trusted_reverse_proxy"
"#,
        )?;

        let err = match cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener("external WebSocket gateway", "0.0.0.0:9200")
        {
            Ok(_security) => bail!("expected trusted proxy peer rejection"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("trusted_proxy_peers"));
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[test]
    fn external_gateway_grpc_trusted_proxy_requires_peer() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[external_gateway.grpc.transport_security]
mode = "trusted_reverse_proxy"
"#,
        )?;

        let err = match cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener("external gRPC gateway", "0.0.0.0:9444")
        {
            Ok(_listener) => bail!("expected trusted proxy peer rejection"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("trusted_proxy_peers"));
        Ok(())
    }

    #[cfg(feature = "external-websocket")]
    #[test]
    fn external_gateway_disabled_for_test_is_rejected_outside_tests() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[external_gateway.websocket.transport_security]
mode = "disabled_for_test"
"#,
        )?;

        let err = match cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener_inner("external WebSocket gateway", "127.0.0.1:9200", false)
        {
            Ok(_security) => bail!("expected disabled_for_test rejection"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("only valid in tests"));
        Ok(())
    }

    #[cfg(feature = "external-websocket")]
    #[test]
    fn external_gateway_plain_listener_tls_modes_fail_closed() -> anyhow::Result<()> {
        let cert = temp_config_file("cert.pem", b"certificate")?;
        let key = temp_config_file("key.pem", b"private-key")?;
        let root = temp_config_file("client-ca.pem", b"client-ca")?;
        let cfg: XolotlConfig = toml::from_str(&format!(
            r#"
[external_gateway.websocket.transport_security]
mode = "production_tls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
"#,
        ))?;

        let err = match cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener("external WebSocket gateway", "127.0.0.1:9200")
        {
            Ok(_security) => bail!("expected production TLS plain-listener rejection"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("requires a TLS listener"));

        let cfg: XolotlConfig = toml::from_str(&format!(
            r#"
[external_gateway.websocket.transport_security]
mode = "mtls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
client_trust_roots = ["{root}"]
"#,
        ))?;

        let err = match cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener("external WebSocket gateway", "127.0.0.1:9200")
        {
            Ok(_security) => bail!("expected mutual TLS plain-listener rejection"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("requires a TLS listener"));
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[test]
    fn external_gateway_grpc_tls_modes_require_material() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[external_gateway.grpc.transport_security]
mode = "production_tls"
"#,
        )?;

        let err = match cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
        {
            Ok(_listener) => bail!("expected certificate material rejection"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("certificate_chain_path"));

        let cert = temp_config_file("cert.pem", b"certificate")?;
        let key = temp_config_file("key.pem", b"private-key")?;
        let cfg: XolotlConfig = toml::from_str(&format!(
            r#"
[external_gateway.grpc.transport_security]
mode = "mtls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
"#,
        ))?;

        let err = match cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
        {
            Ok(_listener) => bail!("expected client trust roots rejection"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("client_trust_roots"));
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[test]
    fn external_gateway_grpc_tls_modes_load_certificate_material() -> anyhow::Result<()> {
        let cert = temp_config_file("cert.pem", b"certificate")?;
        let key = temp_config_file("key.pem", b"private-key")?;
        let cfg: XolotlConfig = toml::from_str(&format!(
            r#"
[external_gateway.grpc.transport_security]
mode = "production_tls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
"#
        ))?;

        let listener = cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
            .context("production TLS listener should load certificate material")?;
        assert_eq!(
            listener.config.mode,
            GatewayTransportSecurityMode::ProductionTls
        );
        assert!(listener.tls.is_some());
        Ok(())
    }

    #[cfg(feature = "external-grpc")]
    #[test]
    fn external_gateway_grpc_mtls_requires_and_loads_client_roots() -> anyhow::Result<()> {
        let cert = temp_config_file("cert.pem", b"certificate")?;
        let key = temp_config_file("key.pem", b"private-key")?;
        let root = temp_config_file("client-ca.pem", b"client-ca")?;
        let cfg: XolotlConfig = toml::from_str(&format!(
            r#"
[external_gateway.grpc.transport_security]
mode = "mtls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
client_trust_roots = ["{root}"]
"#
        ))?;

        let listener = cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
            .context("mutual TLS listener should load certificate material")?;
        assert_eq!(
            listener.config.mode,
            GatewayTransportSecurityMode::MutualTls
        );
        let tls = listener
            .tls
            .context("mutual TLS material should be present")?;
        assert!(!tls.client_trust_roots_pem.is_empty());
        Ok(())
    }

    #[test]
    fn config_file_accepts_console_auth_and_ws_tuning() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[console.auth]
session_ttl_ms = 120000
idle_ttl_ms = 60000
max_sessions_per_user = 2
global_session_limit = 64
argon2_concurrency = 2

[console.ws]
max_frame_bytes = 32768
max_connections_global = 8
max_connections_per_source = 4
max_connections_per_user = 2
idle_timeout_secs = 60
max_frames_per_second = 16
max_bytes_per_second = 65536
max_subscriptions = 4
max_state_list_limit = 48
max_fact_limit = 32
max_trace_limit = 64
max_pending_event_bytes = 65536
send_timeout_ms = 250
"#,
        )?;

        let auth: ConsoleAuthConfig = cfg.console.auth.into();
        assert_eq!(auth.session_ttl_ms, 120_000);
        assert_eq!(auth.max_sessions_per_user, 2);

        let ws: ConsoleWsConfig = cfg.console.ws.into();
        assert_eq!(ws.max_frame_bytes, 32_768);
        assert_eq!(ws.max_connections_global, 8);
        assert_eq!(ws.idle_timeout, Duration::from_secs(60));
        assert_eq!(ws.max_pending_event_bytes, 65_536);
        assert_eq!(ws.send_timeout, Duration::from_millis(250));
        Ok(())
    }

    #[cfg(feature = "external-websocket")]
    #[test]
    fn external_gateway_websocket_transport_config_is_bounded() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[external_gateway.websocket.transport]
max_frame_bytes = 0
first_frame_timeout_ms = 0
idle_timeout_ms = 0
max_connections = 0
"#,
        )?;

        let ws: ExternalWebSocketConfig = cfg.external_gateway.websocket.transport.into();
        assert_eq!(ws, ExternalWebSocketConfig::default());

        let cfg: XolotlConfig = toml::from_str(
            r#"
[external_gateway.websocket.transport]
max_frame_bytes = 999999999999
first_frame_timeout_ms = 999999999999
idle_timeout_ms = 999999999999
max_connections = 999999999999
"#,
        )?;
        let ws: ExternalWebSocketConfig = cfg.external_gateway.websocket.transport.into();
        assert_eq!(
            ws.max_frame_bytes,
            xolotl_gateway_websocket::HARD_MAX_FRAME_BYTES
        );
        assert_eq!(
            ws.first_frame_timeout_ms,
            xolotl_gateway_websocket::HARD_FIRST_FRAME_TIMEOUT_MS
        );
        assert_eq!(
            ws.idle_timeout_ms,
            xolotl_gateway_websocket::HARD_IDLE_TIMEOUT_MS
        );
        assert_eq!(
            ws.max_connections,
            xolotl_gateway_websocket::HARD_MAX_CONNECTIONS
        );
        Ok(())
    }

    #[cfg(all(feature = "external-grpc", feature = "external-websocket"))]
    #[test]
    fn external_gateway_limits_are_bounded() -> anyhow::Result<()> {
        let cfg: XolotlConfig = toml::from_str(
            r#"
[external_gateway.grpc]
source_dedupe_window_ms = 999999999999
provider_max_in_flight_invocations = 999999999999
provider_max_in_flight_per_identity = 999999999999
provider_max_in_flight_per_effect = 999999999999
provider_max_inline_result_bytes = 999999999999
source_max_in_flight_commands = 999999999999
source_command_max_inline_result_bytes = 999999999999
source_command_rate_limit_window_ms = 999999999999
source_command_rate_limit_max = 999999999999

[external_gateway.websocket]
source_dedupe_window_ms = 999999999999
provider_max_in_flight_invocations = 999999999999
provider_max_in_flight_per_identity = 999999999999
provider_max_in_flight_per_effect = 999999999999
provider_max_inline_result_bytes = 999999999999
source_max_in_flight_commands = 999999999999
source_command_max_inline_result_bytes = 999999999999
source_command_rate_limit_window_ms = 999999999999
source_command_rate_limit_max = 999999999999
"#,
        )?;

        let grpc = cfg.external_gateway.grpc.bounded();
        assert_eq!(
            grpc.session_limits(),
            hard_external_gateway_session_limits()
        );

        let websocket = cfg.external_gateway.websocket.bounded();
        assert_eq!(
            websocket.session_limits(),
            hard_external_gateway_session_limits()
        );
        Ok(())
    }

    #[cfg(all(feature = "external-grpc", feature = "external-websocket"))]
    fn hard_external_gateway_session_limits() -> ExternalGatewaySessionLimits {
        ExternalGatewaySessionLimits {
            source_dedupe_window_ms: HARD_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS,
            provider_max_in_flight_invocations: HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS,
            provider_max_in_flight_per_identity: HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY,
            provider_max_in_flight_per_effect: HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT,
            provider_max_inline_result_bytes: HARD_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES,
            source_max_in_flight_commands: HARD_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS,
            source_command_max_inline_result_bytes:
                HARD_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES,
            source_command_rate_limit_window_ms: HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS,
            source_command_rate_limit_max: HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX,
        }
    }
}
