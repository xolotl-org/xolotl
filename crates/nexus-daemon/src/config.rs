use anyhow::{Context, Result};
use nexus_console::auth::{
    DEFAULT_GLOBAL_SESSION_LIMIT, DEFAULT_IDLE_TTL_MS, DEFAULT_MAX_SESSIONS_PER_USER,
    DEFAULT_SESSION_TTL_MS, default_argon2_concurrency,
};
use nexus_console::state::{
    DEFAULT_WS_EVENT_SEND_TIMEOUT, DEFAULT_WS_IDLE_TIMEOUT, DEFAULT_WS_MAX_BYTES_PER_SECOND,
    DEFAULT_WS_MAX_CONNECTIONS_GLOBAL, DEFAULT_WS_MAX_CONNECTIONS_PER_SOURCE,
    DEFAULT_WS_MAX_CONNECTIONS_PER_USER, DEFAULT_WS_MAX_FACT_LIMIT, DEFAULT_WS_MAX_FRAME_BYTES,
    DEFAULT_WS_MAX_FRAMES_PER_SECOND, DEFAULT_WS_MAX_STATE_LIST_LIMIT,
    DEFAULT_WS_MAX_SUBSCRIPTIONS, DEFAULT_WS_MAX_TRACE_LIMIT,
};
use nexus_console::{
    ConsoleAuthConfig, ConsoleTransportSecurityConfig, ConsoleTransportSecurityMode,
    ConsoleTrustedProxyConfig, ConsoleUnsafeTransportRelaxation, ConsoleWsConfig,
};
use nexus_gateway::{
    GatewayTransportSecurityConfig, GatewayTransportSecurityMode, GatewayTrustedProxyConfig,
    GatewayUnsafeTransportRelaxation,
};
use nexus_gateway_websocket::{
    DEFAULT_FIRST_FRAME_TIMEOUT_MS as DEFAULT_EXTERNAL_WS_FIRST_FRAME_TIMEOUT_MS,
    DEFAULT_IDLE_TIMEOUT_MS as DEFAULT_EXTERNAL_WS_IDLE_TIMEOUT_MS,
    DEFAULT_MAX_CONNECTIONS as DEFAULT_EXTERNAL_WS_MAX_CONNECTIONS,
    DEFAULT_MAX_FRAME_BYTES as DEFAULT_EXTERNAL_WS_MAX_FRAME_BYTES, ExternalWebSocketConfig,
};
use serde::Deserialize;
#[cfg(any(feature = "grpc", test))]
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;
pub const HARD_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS: u64 = 30 * 24 * 60 * 60 * 1000;
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS: usize = 1024;
pub const HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS: usize = 65_536;
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY: usize = 256;
pub const HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY: usize = 65_536;
pub const DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT: usize = 256;
pub const HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT: usize = 65_536;
pub const DEFAULT_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS: usize = 1024;
pub const HARD_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS: usize = 65_536;
pub const DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS: u64 = 60_000;
pub const HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS: u64 = 600_000;
pub const DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX: usize = 600;
pub const HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX: usize = 65_536;

/// Bootstrap-only config loaded by `nexusd`: storage, listeners, console root
/// bootstrap material, and bounded console auth/WebSocket resource limits.
/// Runtime config such as providers, models, groups, routing, bindings, and
/// policies lives in Nexus state.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NexusConfig {
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub console: ConsoleConfig,
    #[serde(default)]
    pub external_gateway: ExternalGatewayConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default = "default_storage_kind")]
    pub kind: String,
    #[serde(default = "default_storage_path")]
    pub path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            kind: default_storage_kind(),
            path: default_storage_path(),
        }
    }
}

fn default_storage_kind() -> String {
    "redb".into()
}

fn default_storage_path() -> String {
    "nexus.db".into()
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Console HTTP and Console WebSocket listener address.
    pub console_addr: Option<String>,
    /// External Provider/Source gRPC listener address.
    #[allow(dead_code)]
    pub external_grpc_addr: Option<String>,
    /// External Provider/Source WebSocket listener address.
    pub external_websocket_addr: Option<String>,
    /// Reserved for a standalone health endpoint.
    #[allow(dead_code)]
    pub health_addr: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExternalGatewayConfig {
    #[serde(default)]
    #[allow(dead_code)]
    pub grpc: ExternalGatewayGrpcConfig,
    #[serde(default)]
    pub websocket: ExternalGatewayWebSocketConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ExternalGatewaySessionLimits {
    pub source_dedupe_window_ms: u64,
    pub provider_max_in_flight_invocations: usize,
    pub provider_max_in_flight_per_identity: usize,
    pub provider_max_in_flight_per_effect: usize,
    pub source_max_in_flight_commands: usize,
    pub source_command_rate_limit_window_ms: u64,
    pub source_command_rate_limit_max: usize,
}

impl Default for ExternalGatewaySessionLimits {
    fn default() -> Self {
        Self {
            source_dedupe_window_ms: default_external_source_dedupe_window_ms(),
            provider_max_in_flight_invocations: default_external_provider_max_in_flight_invocations(
            ),
            provider_max_in_flight_per_identity:
                default_external_provider_max_in_flight_per_identity(),
            provider_max_in_flight_per_effect: default_external_provider_max_in_flight_per_effect(),
            source_max_in_flight_commands: default_external_source_max_in_flight_commands(),
            source_command_rate_limit_window_ms:
                default_external_source_command_rate_limit_window_ms(),
            source_command_rate_limit_max: default_external_source_command_rate_limit_max(),
        }
        .bounded()
    }
}

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
        self.source_max_in_flight_commands = clamp_or_default(
            self.source_max_in_flight_commands,
            DEFAULT_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS,
            HARD_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalGatewayGrpcConfig {
    #[serde(default)]
    #[cfg_attr(not(feature = "grpc"), allow(dead_code))]
    pub transport_security: GatewayTransportSecurityTuning,
    #[serde(default = "default_external_source_dedupe_window_ms")]
    pub source_dedupe_window_ms: u64,
    #[serde(default = "default_external_provider_max_in_flight_invocations")]
    pub provider_max_in_flight_invocations: usize,
    #[serde(default = "default_external_provider_max_in_flight_per_identity")]
    pub provider_max_in_flight_per_identity: usize,
    #[serde(default = "default_external_provider_max_in_flight_per_effect")]
    pub provider_max_in_flight_per_effect: usize,
    #[serde(default = "default_external_source_max_in_flight_commands")]
    pub source_max_in_flight_commands: usize,
    #[serde(default = "default_external_source_command_rate_limit_window_ms")]
    pub source_command_rate_limit_window_ms: u64,
    #[serde(default = "default_external_source_command_rate_limit_max")]
    pub source_command_rate_limit_max: usize,
}

impl Default for ExternalGatewayGrpcConfig {
    fn default() -> Self {
        let limits = ExternalGatewaySessionLimits::default();
        Self {
            transport_security: GatewayTransportSecurityTuning::default(),
            source_dedupe_window_ms: limits.source_dedupe_window_ms,
            provider_max_in_flight_invocations: limits.provider_max_in_flight_invocations,
            provider_max_in_flight_per_identity: limits.provider_max_in_flight_per_identity,
            provider_max_in_flight_per_effect: limits.provider_max_in_flight_per_effect,
            source_max_in_flight_commands: limits.source_max_in_flight_commands,
            source_command_rate_limit_window_ms: limits.source_command_rate_limit_window_ms,
            source_command_rate_limit_max: limits.source_command_rate_limit_max,
        }
    }
}

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
        self.source_max_in_flight_commands = limits.source_max_in_flight_commands;
        self.source_command_rate_limit_window_ms = limits.source_command_rate_limit_window_ms;
        self.source_command_rate_limit_max = limits.source_command_rate_limit_max;
    }
}

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
    #[serde(default = "default_external_source_max_in_flight_commands")]
    pub source_max_in_flight_commands: usize,
    #[serde(default = "default_external_source_command_rate_limit_window_ms")]
    pub source_command_rate_limit_window_ms: u64,
    #[serde(default = "default_external_source_command_rate_limit_max")]
    pub source_command_rate_limit_max: usize,
}

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
            source_max_in_flight_commands: limits.source_max_in_flight_commands,
            source_command_rate_limit_window_ms: limits.source_command_rate_limit_window_ms,
            source_command_rate_limit_max: limits.source_command_rate_limit_max,
        }
    }
}

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
        self.source_max_in_flight_commands = limits.source_max_in_flight_commands;
        self.source_command_rate_limit_window_ms = limits.source_command_rate_limit_window_ms;
        self.source_command_rate_limit_max = limits.source_command_rate_limit_max;
    }
}

impl From<&ExternalGatewayGrpcConfig> for ExternalGatewaySessionLimits {
    fn from(config: &ExternalGatewayGrpcConfig) -> Self {
        Self {
            source_dedupe_window_ms: config.source_dedupe_window_ms,
            provider_max_in_flight_invocations: config.provider_max_in_flight_invocations,
            provider_max_in_flight_per_identity: config.provider_max_in_flight_per_identity,
            provider_max_in_flight_per_effect: config.provider_max_in_flight_per_effect,
            source_max_in_flight_commands: config.source_max_in_flight_commands,
            source_command_rate_limit_window_ms: config.source_command_rate_limit_window_ms,
            source_command_rate_limit_max: config.source_command_rate_limit_max,
        }
    }
}

impl From<&ExternalGatewayWebSocketConfig> for ExternalGatewaySessionLimits {
    fn from(config: &ExternalGatewayWebSocketConfig) -> Self {
        Self {
            source_dedupe_window_ms: config.source_dedupe_window_ms,
            provider_max_in_flight_invocations: config.provider_max_in_flight_invocations,
            provider_max_in_flight_per_identity: config.provider_max_in_flight_per_identity,
            provider_max_in_flight_per_effect: config.provider_max_in_flight_per_effect,
            source_max_in_flight_commands: config.source_max_in_flight_commands,
            source_command_rate_limit_window_ms: config.source_command_rate_limit_window_ms,
            source_command_rate_limit_max: config.source_command_rate_limit_max,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayTransportSecurityTuning {
    #[serde(default = "default_gateway_transport_security_mode")]
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
    pub certificate_chain_path: Option<String>,
    pub private_key_path: Option<String>,
    #[serde(default)]
    pub client_trust_roots: Vec<String>,
}

impl Default for GatewayTransportSecurityTuning {
    fn default() -> Self {
        Self {
            mode: default_gateway_transport_security_mode(),
            trusted_proxy_peers: Vec::new(),
            honor_x_forwarded_proto: true,
            honor_x_forwarded_host: true,
            honor_x_forwarded_for: true,
            unsafe_relaxations: Vec::new(),
            certificate_chain_path: None,
            private_key_path: None,
            client_trust_roots: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GatewayListenerSecurity {
    pub listen_addr: SocketAddr,
    pub config: GatewayTransportSecurityConfig,
    #[cfg(feature = "grpc")]
    pub tls: Option<GatewayListenerTlsMaterial>,
}

#[cfg(feature = "grpc")]
#[derive(Debug, Clone)]
pub struct GatewayListenerTlsMaterial {
    pub certificate_chain_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    pub client_trust_roots_pem: Vec<u8>,
}

impl GatewayTransportSecurityTuning {
    pub fn validate_plain_listener(
        &self,
        label: &str,
        listen_addr: &str,
    ) -> Result<GatewayListenerSecurity> {
        self.validate_plain_listener_inner(label, listen_addr, cfg!(test))
    }

    #[cfg(feature = "grpc")]
    pub fn validate_grpc_listener(
        &self,
        label: &str,
        listen_addr: &str,
    ) -> Result<GatewayListenerSecurity> {
        self.validate_grpc_listener_inner(label, listen_addr, cfg!(test))
    }

    fn validate_plain_listener_inner(
        &self,
        label: &str,
        listen_addr: &str,
        allow_disabled_for_test: bool,
    ) -> Result<GatewayListenerSecurity> {
        let listen_addr = listen_addr.parse::<SocketAddr>().with_context(|| {
            format!("{label} listen address '{listen_addr}' must be an IP socket address")
        })?;
        let config = self.to_gateway_transport_security_config(label)?;
        match config.mode {
            GatewayTransportSecurityMode::ProductionTls => {
                self.validate_tls_material(label, false)?;
                anyhow::bail!(
                    "{label} production_tls requires a TLS listener; configure trusted_reverse_proxy, local_trusted, or unsafe_plaintext for the current plain listener"
                );
            }
            GatewayTransportSecurityMode::MutualTls => {
                self.validate_tls_material(label, true)?;
                anyhow::bail!(
                    "{label} mtls requires a TLS listener; configure trusted_reverse_proxy, local_trusted, or unsafe_plaintext for the current plain listener"
                );
            }
            GatewayTransportSecurityMode::TrustedReverseProxy => {
                if config.trusted_proxy.peers.is_empty() {
                    anyhow::bail!(
                        "{label} trusted_reverse_proxy requires at least one trusted_proxy_peers entry"
                    );
                }
            }
            GatewayTransportSecurityMode::LocalTrusted => {
                if !listen_addr.ip().is_loopback() {
                    anyhow::bail!("{label} local_trusted requires a loopback listen address");
                }
            }
            GatewayTransportSecurityMode::UnsafePlaintext => {}
            GatewayTransportSecurityMode::DisabledForTest => {
                if !allow_disabled_for_test {
                    anyhow::bail!(
                        "{label} transport security mode disabled_for_test is only valid in tests"
                    );
                }
            }
        }
        Ok(GatewayListenerSecurity {
            listen_addr,
            config,
            #[cfg(feature = "grpc")]
            tls: None,
        })
    }

    #[cfg(feature = "grpc")]
    fn validate_grpc_listener_inner(
        &self,
        label: &str,
        listen_addr: &str,
        allow_disabled_for_test: bool,
    ) -> Result<GatewayListenerSecurity> {
        let listen_addr = listen_addr.parse::<SocketAddr>().with_context(|| {
            format!("{label} listen address '{listen_addr}' must be an IP socket address")
        })?;
        let config = self.to_gateway_transport_security_config(label)?;
        let tls = match config.mode {
            GatewayTransportSecurityMode::ProductionTls => {
                Some(self.load_tls_material(label, false)?)
            }
            GatewayTransportSecurityMode::MutualTls => Some(self.load_tls_material(label, true)?),
            GatewayTransportSecurityMode::TrustedReverseProxy => {
                if config.trusted_proxy.peers.is_empty() {
                    anyhow::bail!(
                        "{label} trusted_reverse_proxy requires at least one trusted_proxy_peers entry"
                    );
                }
                None
            }
            GatewayTransportSecurityMode::LocalTrusted => {
                if !listen_addr.ip().is_loopback() {
                    anyhow::bail!("{label} local_trusted requires a loopback listen address");
                }
                None
            }
            GatewayTransportSecurityMode::UnsafePlaintext => None,
            GatewayTransportSecurityMode::DisabledForTest => {
                if !allow_disabled_for_test {
                    anyhow::bail!(
                        "{label} transport security mode disabled_for_test is only valid in tests"
                    );
                }
                None
            }
        };
        Ok(GatewayListenerSecurity {
            listen_addr,
            config,
            tls,
        })
    }

    fn to_gateway_transport_security_config(
        &self,
        label: &str,
    ) -> Result<GatewayTransportSecurityConfig> {
        let mode = match self.mode.as_str() {
            "production_tls" => GatewayTransportSecurityMode::ProductionTls,
            "mtls" => GatewayTransportSecurityMode::MutualTls,
            "trusted_reverse_proxy" => GatewayTransportSecurityMode::TrustedReverseProxy,
            "local_trusted" => GatewayTransportSecurityMode::LocalTrusted,
            "unsafe_plaintext" => GatewayTransportSecurityMode::UnsafePlaintext,
            "disabled_for_test" => GatewayTransportSecurityMode::DisabledForTest,
            other => anyhow::bail!("unknown transport security mode '{other}' for {label}"),
        };
        let peers = self
            .trusted_proxy_peers
            .iter()
            .map(|peer| {
                peer.parse::<IpAddr>()
                    .with_context(|| format!("invalid trusted proxy peer '{peer}' for {label}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let unsafe_relaxations = self
            .unsafe_relaxations
            .iter()
            .map(|relaxation| match relaxation.as_str() {
                "allow_plaintext" => Ok(GatewayUnsafeTransportRelaxation::AllowPlaintext),
                "ignore_origin_port" => Ok(GatewayUnsafeTransportRelaxation::IgnoreOriginPort),
                "relaxed_origin" => Ok(GatewayUnsafeTransportRelaxation::RelaxedOrigin),
                other => {
                    anyhow::bail!("unknown unsafe transport relaxation '{other}' for {label}")
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(GatewayTransportSecurityConfig {
            mode,
            trusted_proxy: GatewayTrustedProxyConfig {
                peers,
                honor_x_forwarded_proto: self.honor_x_forwarded_proto,
                honor_x_forwarded_host: self.honor_x_forwarded_host,
                honor_x_forwarded_for: self.honor_x_forwarded_for,
            },
            unsafe_relaxations,
        }
        .bounded())
    }

    fn validate_tls_material(&self, label: &str, require_client_roots: bool) -> Result<()> {
        let cert = non_empty_path(self.certificate_chain_path.as_deref())
            .ok_or_else(|| anyhow::anyhow!("{label} TLS mode requires certificate_chain_path"))?;
        let key = non_empty_path(self.private_key_path.as_deref())
            .ok_or_else(|| anyhow::anyhow!("{label} TLS mode requires private_key_path"))?;
        ensure_file(cert, &format!("{label} certificate_chain_path"))?;
        ensure_file(key, &format!("{label} private_key_path"))?;
        if require_client_roots && self.client_trust_roots.is_empty() {
            anyhow::bail!("{label} mtls requires at least one client_trust_roots entry");
        }
        for root in &self.client_trust_roots {
            let root = non_empty_path(Some(root.as_str()))
                .ok_or_else(|| anyhow::anyhow!("{label} client_trust_roots must not be empty"))?;
            ensure_file(root, &format!("{label} client_trust_roots"))?;
        }
        Ok(())
    }

    #[cfg(feature = "grpc")]
    fn load_tls_material(
        &self,
        label: &str,
        require_client_roots: bool,
    ) -> Result<GatewayListenerTlsMaterial> {
        self.validate_tls_material(label, require_client_roots)?;
        let cert = non_empty_path(self.certificate_chain_path.as_deref())
            .ok_or_else(|| anyhow::anyhow!("{label} TLS mode requires certificate_chain_path"))?;
        let key = non_empty_path(self.private_key_path.as_deref())
            .ok_or_else(|| anyhow::anyhow!("{label} TLS mode requires private_key_path"))?;
        let certificate_chain_pem = fs::read(cert)
            .with_context(|| format!("read {label} certificate_chain_path '{cert}'"))?;
        let private_key_pem =
            fs::read(key).with_context(|| format!("read {label} private_key_path '{key}'"))?;
        let mut client_trust_roots_pem = Vec::new();
        for root in &self.client_trust_roots {
            let root = non_empty_path(Some(root.as_str()))
                .ok_or_else(|| anyhow::anyhow!("{label} client_trust_roots must not be empty"))?;
            let pem = fs::read(root)
                .with_context(|| format!("read {label} client_trust_roots '{root}'"))?;
            client_trust_roots_pem.extend_from_slice(&pem);
            if !client_trust_roots_pem.ends_with(b"\n") {
                client_trust_roots_pem.push(b'\n');
            }
        }
        Ok(GatewayListenerTlsMaterial {
            certificate_chain_pem,
            private_key_pem,
            client_trust_roots_pem,
        })
    }
}

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

impl ExternalGatewayWebSocketTransportTuning {
    pub fn bounded(mut self) -> Self {
        self.max_frame_bytes = clamp_or_default(
            self.max_frame_bytes,
            DEFAULT_EXTERNAL_WS_MAX_FRAME_BYTES,
            nexus_gateway_websocket::HARD_MAX_FRAME_BYTES,
        );
        self.first_frame_timeout_ms = clamp_or_default_u64(
            self.first_frame_timeout_ms,
            DEFAULT_EXTERNAL_WS_FIRST_FRAME_TIMEOUT_MS,
            nexus_gateway_websocket::HARD_FIRST_FRAME_TIMEOUT_MS,
        );
        self.idle_timeout_ms = clamp_or_default_u64(
            self.idle_timeout_ms,
            DEFAULT_EXTERNAL_WS_IDLE_TIMEOUT_MS,
            nexus_gateway_websocket::HARD_IDLE_TIMEOUT_MS,
        );
        self.max_connections = clamp_or_default(
            self.max_connections,
            DEFAULT_EXTERNAL_WS_MAX_CONNECTIONS,
            nexus_gateway_websocket::HARD_MAX_CONNECTIONS,
        );
        self
    }
}

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

fn default_external_source_dedupe_window_ms() -> u64 {
    DEFAULT_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS
}

fn default_external_provider_max_in_flight_invocations() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS
}

fn default_external_provider_max_in_flight_per_identity() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY
}

fn default_external_provider_max_in_flight_per_effect() -> usize {
    DEFAULT_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT
}

fn default_external_source_max_in_flight_commands() -> usize {
    DEFAULT_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS
}

fn default_external_source_command_rate_limit_window_ms() -> u64 {
    DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS
}

fn default_external_source_command_rate_limit_max() -> usize {
    DEFAULT_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX
}

fn default_gateway_transport_security_mode() -> String {
    "local_trusted".into()
}

fn non_empty_path(path: Option<&str>) -> Option<&str> {
    path.map(str::trim).filter(|path| !path.is_empty())
}

fn ensure_file(path: &str, label: &str) -> Result<()> {
    if !Path::new(path).is_file() {
        anyhow::bail!("{label} '{path}' must be an existing file");
    }
    Ok(())
}

#[allow(dead_code)]
fn clamp_or_default(value: usize, default: usize, hard_max: usize) -> usize {
    if value == 0 {
        default
    } else {
        value.min(hard_max)
    }
}

#[allow(dead_code)]
fn clamp_or_default_u64(value: u64, default: u64, hard_max: u64) -> u64 {
    if value == 0 {
        default
    } else {
        value.min(hard_max)
    }
}

fn default_external_ws_max_frame_bytes() -> usize {
    DEFAULT_EXTERNAL_WS_MAX_FRAME_BYTES
}

fn default_external_ws_first_frame_timeout_ms() -> u64 {
    DEFAULT_EXTERNAL_WS_FIRST_FRAME_TIMEOUT_MS
}

fn default_external_ws_idle_timeout_ms() -> u64 {
    DEFAULT_EXTERNAL_WS_IDLE_TIMEOUT_MS
}

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
    pub fn to_console_transport_security_config(&self) -> Result<ConsoleTransportSecurityConfig> {
        let mode = match self.mode.as_str() {
            "production_tls" => ConsoleTransportSecurityMode::ProductionTls,
            "trusted_reverse_proxy" => ConsoleTransportSecurityMode::TrustedReverseProxy,
            "local_trusted" => ConsoleTransportSecurityMode::LocalTrusted,
            "unsafe_plaintext" => ConsoleTransportSecurityMode::UnsafePlaintext,
            "disabled_for_test" => ConsoleTransportSecurityMode::DisabledForTest,
            other => anyhow::bail!("unknown console transport security mode '{other}'"),
        };
        if matches!(mode, ConsoleTransportSecurityMode::DisabledForTest) && !cfg!(test) {
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
}

impl Default for ConsoleAuthTuning {
    fn default() -> Self {
        Self {
            session_ttl_ms: default_session_ttl_ms(),
            idle_ttl_ms: default_idle_ttl_ms(),
            max_sessions_per_user: default_max_sessions_per_user(),
            global_session_limit: default_global_session_limit(),
            argon2_concurrency: default_argon2_concurrency(),
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
    #[serde(default = "default_ws_event_send_timeout_ms")]
    pub event_send_timeout_ms: u64,
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
            event_send_timeout_ms: default_ws_event_send_timeout_ms(),
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
            event_send_timeout: Duration::from_millis(value.event_send_timeout_ms),
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

fn default_ws_event_send_timeout_ms() -> u64 {
    DEFAULT_WS_EVENT_SEND_TIMEOUT.as_millis() as u64
}

impl NexusConfig {
    pub fn load() -> Result<Option<Self>> {
        let path = std::env::var("NEXUS_CONFIG").unwrap_or_else(|_| "nexus.toml".into());

        let path = Path::new(&path);
        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading config from {}", path.display()))?;

        let config: NexusConfig = toml::from_str(&content)
            .with_context(|| format!("parsing config from {}", path.display()))?;

        Ok(Some(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_console::auth::{
        HARD_GLOBAL_SESSION_LIMIT, MIN_ARGON2_CONCURRENCY, MIN_IDLE_TTL_MS,
        MIN_MAX_SESSIONS_PER_USER, MIN_SESSION_TTL_MS,
    };
    use nexus_console::state::{
        HARD_MAX_WS_CONNECTIONS_PER_SOURCE, HARD_MAX_WS_FRAME_BYTES, HARD_MAX_WS_FRAMES_PER_SECOND,
        HARD_MAX_WS_SUBSCRIPTIONS, HARD_MAX_WS_TRACE_LIMIT, MIN_WS_CONNECTIONS_GLOBAL,
        MIN_WS_CONNECTIONS_PER_USER, MIN_WS_EVENT_SEND_TIMEOUT, MIN_WS_IDLE_TIMEOUT,
        MIN_WS_MAX_BYTES_PER_SECOND, MIN_WS_MAX_FACT_LIMIT, MIN_WS_MAX_STATE_LIST_LIMIT,
    };

    fn assert_config_rejects_unknown_field(toml: &str, field: &str) {
        let err = toml::from_str::<NexusConfig>(toml).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("unknown field") && message.contains(field),
            "unexpected error for {field}: {message}"
        );
    }

    fn temp_config_file(name: &str, contents: &[u8]) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "nexus-config-test-{}-{nanos}-{name}",
            std::process::id()
        ));
        fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn console_tuning_defaults_match_runtime_defaults() {
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
        assert_eq!(ws.event_send_timeout, default_ws.event_send_timeout);
    }

    #[test]
    fn console_tuning_clamps_unreasonable_values() {
        let auth: ConsoleAuthConfig = ConsoleAuthTuning {
            session_ttl_ms: 1,
            idle_ttl_ms: -1,
            max_sessions_per_user: 0,
            global_session_limit: usize::MAX,
            argon2_concurrency: 0,
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
            event_send_timeout_ms: 1,
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
        assert_eq!(ws.event_send_timeout, MIN_WS_EVENT_SEND_TIMEOUT);
    }

    #[test]
    fn config_file_accepts_console_transport_security() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[console.transport_security]
mode = "trusted_reverse_proxy"
trusted_proxy_peers = ["127.0.0.1"]
honor_x_forwarded_proto = true
honor_x_forwarded_host = true
honor_x_forwarded_for = true
"#,
        )
        .unwrap();

        let transport = cfg
            .console
            .transport_security
            .to_console_transport_security_config()
            .unwrap();
        assert_eq!(
            transport.mode,
            ConsoleTransportSecurityMode::TrustedReverseProxy
        );
        assert_eq!(
            transport.trusted_proxy.peers,
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn console_transport_security_requires_proxy_peer() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[console.transport_security]
mode = "trusted_reverse_proxy"
"#,
        )
        .unwrap();

        let err = cfg
            .console
            .transport_security
            .to_console_transport_security_config()
            .unwrap_err();
        assert!(err.to_string().contains("trusted_proxy_peers"));
    }

    #[test]
    fn config_file_accepts_explicit_console_unsafe_transport() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[console.transport_security]
mode = "unsafe_plaintext"
unsafe_relaxations = ["ignore_origin_port"]
"#,
        )
        .unwrap();

        let transport = cfg
            .console
            .transport_security
            .to_console_transport_security_config()
            .unwrap();
        assert_eq!(
            transport.mode,
            ConsoleTransportSecurityMode::UnsafePlaintext
        );
        assert!(transport.is_unsafe());
        assert!(transport.ignore_origin_port());
    }

    #[test]
    fn config_file_rejects_unknown_bootstrap_fields() {
        assert_config_rejects_unknown_field(
            r#"
unknown_section = true
"#,
            "unknown_section",
        );
        assert_config_rejects_unknown_field(
            r#"
[server]
program_rpc_addr = "127.0.0.1:9100"
"#,
            "program_rpc_addr",
        );
        assert_config_rejects_unknown_field(
            r#"
[console.ws]
max_frame_bytez = 1024
"#,
            "max_frame_bytez",
        );
    }

    #[test]
    fn example_config_uses_declared_fields() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../nexus.toml.example");
        let content = std::fs::read_to_string(&path).unwrap();
        toml::from_str::<NexusConfig>(&content).unwrap();
    }

    #[test]
    fn gateway_transport_security_defaults_to_loopback_only() {
        let cfg = GatewayTransportSecurityTuning::default();
        let security = cfg
            .validate_plain_listener("external WebSocket gateway", "127.0.0.1:9200")
            .unwrap();
        assert_eq!(
            security.config.mode,
            GatewayTransportSecurityMode::LocalTrusted
        );
        assert_eq!(
            security.listen_addr,
            "127.0.0.1:9200".parse::<SocketAddr>().unwrap()
        );

        let err = cfg
            .validate_plain_listener("external WebSocket gateway", "0.0.0.0:9200")
            .unwrap_err();
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn config_file_accepts_external_gateway_listeners() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[server]
external_grpc_addr = "127.0.0.1:9444"
external_websocket_addr = "127.0.0.1:9200"

[external_gateway.grpc]
source_dedupe_window_ms = 0
provider_max_in_flight_invocations = 0
provider_max_in_flight_per_identity = 0
provider_max_in_flight_per_effect = 0
source_max_in_flight_commands = 0
source_command_rate_limit_window_ms = 0
source_command_rate_limit_max = 0

[external_gateway.grpc.transport_security]
mode = "local_trusted"

[external_gateway.websocket]
source_dedupe_window_ms = 0
provider_max_in_flight_invocations = 0
provider_max_in_flight_per_identity = 0
provider_max_in_flight_per_effect = 0
source_max_in_flight_commands = 0
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
        )
        .unwrap();

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

        #[cfg(feature = "grpc")]
        {
            let listener = cfg
                .external_gateway
                .grpc
                .transport_security
                .validate_grpc_listener(
                    "external gRPC gateway",
                    cfg.server.external_grpc_addr.as_deref().unwrap(),
                )
                .unwrap();
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
                cfg.server.external_websocket_addr.as_deref().unwrap(),
            )
            .unwrap();
        assert_eq!(
            listener.config.mode,
            GatewayTransportSecurityMode::LocalTrusted
        );
    }

    #[test]
    fn config_file_accepts_external_gateway_trusted_proxy_transport_security() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[external_gateway.websocket.transport_security]
mode = "trusted_reverse_proxy"
trusted_proxy_peers = ["127.0.0.1"]
honor_x_forwarded_for = true
"#,
        )
        .unwrap();

        let security = cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener("external WebSocket gateway", "0.0.0.0:9200")
            .unwrap();
        assert_eq!(
            security.config.mode,
            GatewayTransportSecurityMode::TrustedReverseProxy
        );
        assert_eq!(
            security.config.trusted_proxy.peers,
            vec!["127.0.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn external_gateway_plain_listener_trusted_proxy_requires_peer() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[external_gateway.websocket.transport_security]
mode = "trusted_reverse_proxy"
"#,
        )
        .unwrap();

        let err = cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener("external WebSocket gateway", "0.0.0.0:9200")
            .unwrap_err();
        assert!(err.to_string().contains("trusted_proxy_peers"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn external_gateway_grpc_trusted_proxy_requires_peer() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[external_gateway.grpc.transport_security]
mode = "trusted_reverse_proxy"
"#,
        )
        .unwrap();

        let err = cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener("external gRPC gateway", "0.0.0.0:9444")
            .unwrap_err();
        assert!(err.to_string().contains("trusted_proxy_peers"));
    }

    #[test]
    fn external_gateway_disabled_for_test_is_rejected_outside_tests() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[external_gateway.websocket.transport_security]
mode = "disabled_for_test"
"#,
        )
        .unwrap();

        let err = cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener_inner("external WebSocket gateway", "127.0.0.1:9200", false)
            .unwrap_err();
        assert!(err.to_string().contains("only valid in tests"));
    }

    #[test]
    fn external_gateway_plain_listener_tls_modes_fail_closed() {
        let cert = temp_config_file("cert.pem", b"certificate");
        let key = temp_config_file("key.pem", b"private-key");
        let root = temp_config_file("client-ca.pem", b"client-ca");
        let cfg: NexusConfig = toml::from_str(&format!(
            r#"
[external_gateway.websocket.transport_security]
mode = "production_tls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
"#,
        ))
        .unwrap();

        let err = cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener("external WebSocket gateway", "127.0.0.1:9200")
            .unwrap_err();
        assert!(err.to_string().contains("requires a TLS listener"));

        let cfg: NexusConfig = toml::from_str(&format!(
            r#"
[external_gateway.websocket.transport_security]
mode = "mtls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
client_trust_roots = ["{root}"]
"#,
        ))
        .unwrap();

        let err = cfg
            .external_gateway
            .websocket
            .transport_security
            .validate_plain_listener("external WebSocket gateway", "127.0.0.1:9200")
            .unwrap_err();
        assert!(err.to_string().contains("requires a TLS listener"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn external_gateway_grpc_tls_modes_require_material() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[external_gateway.grpc.transport_security]
mode = "production_tls"
"#,
        )
        .unwrap();

        let err = cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
            .unwrap_err();
        assert!(err.to_string().contains("certificate_chain_path"));

        let cert = temp_config_file("cert.pem", b"certificate");
        let key = temp_config_file("key.pem", b"private-key");
        let cfg: NexusConfig = toml::from_str(&format!(
            r#"
[external_gateway.grpc.transport_security]
mode = "mtls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
"#,
        ))
        .unwrap();

        let err = cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
            .unwrap_err();
        assert!(err.to_string().contains("client_trust_roots"));
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn external_gateway_grpc_tls_modes_load_certificate_material() {
        let cert = temp_config_file("cert.pem", b"certificate");
        let key = temp_config_file("key.pem", b"private-key");
        let cfg: NexusConfig = toml::from_str(&format!(
            r#"
[external_gateway.grpc.transport_security]
mode = "production_tls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
"#
        ))
        .unwrap();

        let listener = cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
            .unwrap();
        assert_eq!(
            listener.config.mode,
            GatewayTransportSecurityMode::ProductionTls
        );
        assert!(listener.tls.is_some());
    }

    #[cfg(feature = "grpc")]
    #[test]
    fn external_gateway_grpc_mtls_requires_and_loads_client_roots() {
        let cert = temp_config_file("cert.pem", b"certificate");
        let key = temp_config_file("key.pem", b"private-key");
        let root = temp_config_file("client-ca.pem", b"client-ca");
        let cfg: NexusConfig = toml::from_str(&format!(
            r#"
[external_gateway.grpc.transport_security]
mode = "mtls"
certificate_chain_path = "{cert}"
private_key_path = "{key}"
client_trust_roots = ["{root}"]
"#
        ))
        .unwrap();

        let listener = cfg
            .external_gateway
            .grpc
            .transport_security
            .validate_grpc_listener("external gRPC gateway", "127.0.0.1:9444")
            .unwrap();
        assert_eq!(
            listener.config.mode,
            GatewayTransportSecurityMode::MutualTls
        );
        let tls = listener.tls.unwrap();
        assert!(!tls.client_trust_roots_pem.is_empty());
    }

    #[test]
    fn config_file_accepts_console_auth_and_ws_tuning() {
        let cfg: NexusConfig = toml::from_str(
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
event_send_timeout_ms = 250
"#,
        )
        .unwrap();

        let auth: ConsoleAuthConfig = cfg.console.auth.into();
        assert_eq!(auth.session_ttl_ms, 120_000);
        assert_eq!(auth.max_sessions_per_user, 2);

        let ws: ConsoleWsConfig = cfg.console.ws.into();
        assert_eq!(ws.max_frame_bytes, 32_768);
        assert_eq!(ws.max_connections_global, 8);
        assert_eq!(ws.idle_timeout, Duration::from_secs(60));
        assert_eq!(ws.event_send_timeout, Duration::from_millis(250));
    }

    #[test]
    fn external_gateway_websocket_transport_config_is_bounded() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[external_gateway.websocket.transport]
max_frame_bytes = 0
first_frame_timeout_ms = 0
idle_timeout_ms = 0
max_connections = 0
"#,
        )
        .unwrap();

        let ws: ExternalWebSocketConfig = cfg.external_gateway.websocket.transport.into();
        assert_eq!(ws, ExternalWebSocketConfig::default());

        let cfg: NexusConfig = toml::from_str(
            r#"
[external_gateway.websocket.transport]
max_frame_bytes = 999999999999
first_frame_timeout_ms = 999999999999
idle_timeout_ms = 999999999999
max_connections = 999999999999
"#,
        )
        .unwrap();
        let ws: ExternalWebSocketConfig = cfg.external_gateway.websocket.transport.into();
        assert_eq!(
            ws.max_frame_bytes,
            nexus_gateway_websocket::HARD_MAX_FRAME_BYTES
        );
        assert_eq!(
            ws.first_frame_timeout_ms,
            nexus_gateway_websocket::HARD_FIRST_FRAME_TIMEOUT_MS
        );
        assert_eq!(
            ws.idle_timeout_ms,
            nexus_gateway_websocket::HARD_IDLE_TIMEOUT_MS
        );
        assert_eq!(
            ws.max_connections,
            nexus_gateway_websocket::HARD_MAX_CONNECTIONS
        );
    }

    #[test]
    fn external_gateway_limits_are_bounded() {
        let cfg: NexusConfig = toml::from_str(
            r#"
[external_gateway.grpc]
source_dedupe_window_ms = 999999999999
provider_max_in_flight_invocations = 999999999999
provider_max_in_flight_per_identity = 999999999999
provider_max_in_flight_per_effect = 999999999999
source_max_in_flight_commands = 999999999999
source_command_rate_limit_window_ms = 999999999999
source_command_rate_limit_max = 999999999999

[external_gateway.websocket]
source_dedupe_window_ms = 999999999999
provider_max_in_flight_invocations = 999999999999
provider_max_in_flight_per_identity = 999999999999
provider_max_in_flight_per_effect = 999999999999
source_max_in_flight_commands = 999999999999
source_command_rate_limit_window_ms = 999999999999
source_command_rate_limit_max = 999999999999
"#,
        )
        .unwrap();

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
    }

    fn hard_external_gateway_session_limits() -> ExternalGatewaySessionLimits {
        ExternalGatewaySessionLimits {
            source_dedupe_window_ms: HARD_EXTERNAL_SOURCE_DEDUPE_WINDOW_MS,
            provider_max_in_flight_invocations: HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_INVOCATIONS,
            provider_max_in_flight_per_identity: HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_IDENTITY,
            provider_max_in_flight_per_effect: HARD_EXTERNAL_PROVIDER_MAX_IN_FLIGHT_PER_EFFECT,
            source_max_in_flight_commands: HARD_EXTERNAL_SOURCE_MAX_IN_FLIGHT_COMMANDS,
            source_command_rate_limit_window_ms: HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_WINDOW_MS,
            source_command_rate_limit_max: HARD_EXTERNAL_SOURCE_COMMAND_RATE_LIMIT_MAX,
        }
    }
}
