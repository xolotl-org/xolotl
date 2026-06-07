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
use nexus_console::{ConsoleAuthConfig, ConsoleWsConfig};
use serde::Deserialize;
use std::path::Path;
use std::time::Duration;

/// Bootstrap-only config: [storage] + [server].
/// Runtime config (backends, models, routing) lives in state.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NexusConfig {
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub console: ConsoleConfig,
}

#[derive(Debug, Clone, Deserialize)]
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
pub struct ServerConfig {
    pub console_addr: Option<String>,
    /// gRPC listen address; only used when the `grpc` feature is enabled.
    #[allow(dead_code)]
    pub grpc_addr: Option<String>,
    pub ws_addr: Option<String>,
    /// Reserved for a standalone health endpoint.
    #[allow(dead_code)]
    pub health_addr: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConsoleConfig {
    #[serde(default)]
    pub root: ConsoleRootConfig,
    #[serde(default)]
    pub auth: ConsoleAuthTuning,
    #[serde(default)]
    pub ws: ConsoleWsTuning,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConsoleRootConfig {
    /// Optional pre-seeded Argon2id PHC string for the root Console account.
    pub password_hash: Option<String>,
    /// Optional Ed25519/WebAuthn key descriptors for deployments that disable
    /// root password bootstrap and provision key login externally.
    #[serde(default)]
    pub pubkeys: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
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
}
