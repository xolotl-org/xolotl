//! External Gateway session, maintenance, and transport limits.

use crate::transport::GatewayTransportSecurityTuning;
use serde::Deserialize;
use std::num::NonZeroUsize;
#[cfg(feature = "external-websocket")]
use xolotl_gateway::GatewayTransportSecurityConfig;
use xolotl_gateway::external::DEFAULT_SOURCE_COMMAND_LIMIT;
#[cfg(feature = "external-websocket")]
use xolotl_gateway_websocket::{
    DEFAULT_FIRST_FRAME_TIMEOUT_MS as DEFAULT_EXTERNAL_WS_FIRST_FRAME_TIMEOUT_MS,
    DEFAULT_IDLE_TIMEOUT_MS as DEFAULT_EXTERNAL_WS_IDLE_TIMEOUT_MS,
    DEFAULT_MAX_CONNECTIONS as DEFAULT_EXTERNAL_WS_MAX_CONNECTIONS,
    DEFAULT_MAX_FRAME_BYTES as DEFAULT_EXTERNAL_WS_MAX_FRAME_BYTES, ExternalWebSocketConfig,
};

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1000;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_SOURCE_MAINTENANCE_INTERVAL_MS: u64 = 10_000;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_SOURCE_MAINTENANCE_INTERVAL_MS: u64 = 60 * 60 * 1000;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_SOURCE_MAINTENANCE_BATCHES_PER_TICK: usize = 64;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_SOURCE_MAINTENANCE_BATCHES_PER_TICK: usize = 1024;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS: usize = 1024;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS: usize = 65_536;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY: usize = 256;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY: usize = 65_536;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT: usize = 256;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT: usize = 65_536;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES: usize = 65_536;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES: usize = 16 * 1024 * 1024;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS: usize = 1024;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS: usize = 65_536;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES: usize = 65_536;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES: usize = 16 * 1024 * 1024;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS: u64 = 600_000;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX: usize = 600;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub const HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX: usize = 65_536;

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalGatewayConfig {
    #[serde(default = "default_source_command_limit")]
    pub source_command_limit: NonZeroUsize,
    #[cfg(feature = "external-grpc")]
    #[serde(default)]
    pub grpc: ExternalGatewayGrpcConfig,
    #[cfg(feature = "external-websocket")]
    #[serde(default)]
    pub websocket: ExternalGatewayWebSocketConfig,
    #[serde(default)]
    pub source_maintenance: SourceMaintenanceConfig,
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
impl Default for ExternalGatewayConfig {
    fn default() -> Self {
        Self {
            source_command_limit: default_source_command_limit(),
            #[cfg(feature = "external-grpc")]
            grpc: ExternalGatewayGrpcConfig::default(),
            #[cfg(feature = "external-websocket")]
            websocket: ExternalGatewayWebSocketConfig::default(),
            source_maintenance: SourceMaintenanceConfig::default(),
        }
    }
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_source_command_limit() -> NonZeroUsize {
    DEFAULT_SOURCE_COMMAND_LIMIT
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceMaintenanceConfig {
    #[serde(default = "default_source_maintenance_interval_ms")]
    pub interval_ms: u64,
    #[serde(default = "default_source_maintenance_batches_per_tick")]
    pub max_batches_per_tick: usize,
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
impl Default for SourceMaintenanceConfig {
    fn default() -> Self {
        Self {
            interval_ms: DEFAULT_SOURCE_MAINTENANCE_INTERVAL_MS,
            max_batches_per_tick: DEFAULT_SOURCE_MAINTENANCE_BATCHES_PER_TICK,
        }
    }
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
impl SourceMaintenanceConfig {
    pub fn bounded(mut self) -> Self {
        self.interval_ms = clamp_or_default_u64(
            self.interval_ms,
            DEFAULT_SOURCE_MAINTENANCE_INTERVAL_MS,
            HARD_SOURCE_MAINTENANCE_INTERVAL_MS,
        );
        self.max_batches_per_tick = clamp_or_default(
            self.max_batches_per_tick,
            DEFAULT_SOURCE_MAINTENANCE_BATCHES_PER_TICK,
            HARD_SOURCE_MAINTENANCE_BATCHES_PER_TICK,
        );
        self
    }
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_source_maintenance_interval_ms() -> u64 {
    DEFAULT_SOURCE_MAINTENANCE_INTERVAL_MS
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_source_maintenance_batches_per_tick() -> usize {
    DEFAULT_SOURCE_MAINTENANCE_BATCHES_PER_TICK
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
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

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
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

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
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

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_external_source_dedupe_window_ms() -> u64 {
    DEFAULT_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_external_provider_max_in_flight_invocations() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_external_provider_max_in_flight_per_identity() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_external_provider_max_in_flight_per_effect() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_external_provider_max_inline_result_bytes() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_INLINE_RESULT_BYTES
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_external_source_max_in_flight_commands() -> usize {
    DEFAULT_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_external_source_command_max_inline_result_bytes() -> usize {
    DEFAULT_EXTERNAL_SOURCE_COMMAND_MAX_INLINE_RESULT_BYTES
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_external_source_command_rate_limit_window_ms() -> u64 {
    DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn default_external_source_command_rate_limit_max() -> usize {
    DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
fn clamp_or_default(value: usize, default: usize, hard_max: usize) -> usize {
    if value == 0 {
        default
    } else {
        value.min(hard_max)
    }
}

#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
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
