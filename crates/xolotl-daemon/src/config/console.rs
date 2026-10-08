//! Console bootstrap, authentication, and HTTP/WebSocket listener tuning.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use xolotl_console::{
    ConsoleAuthConfig, ConsoleQueryConfig, ConsoleTransportSecurityConfig,
    ConsoleTransportSecurityMode, ConsoleTrustedProxyConfig, ConsoleUnsafeTransportRelaxation,
    ConsoleWebAuthnConfig, ConsoleWsConfig, CredentialSealer, DEFAULT_GLOBAL_SESSION_LIMIT,
    DEFAULT_IDLE_TTL_MS, DEFAULT_MAX_SESSIONS_PER_ACCOUNT, DEFAULT_SESSION_TTL_MS,
    DEFAULT_WS_IDLE_TIMEOUT, DEFAULT_WS_MAX_BYTES_PER_SECOND, DEFAULT_WS_MAX_CONNECTIONS_GLOBAL,
    DEFAULT_WS_MAX_CONNECTIONS_PER_ACCOUNT, DEFAULT_WS_MAX_CONNECTIONS_PER_SOURCE,
    DEFAULT_WS_MAX_FRAME_BYTES, DEFAULT_WS_MAX_FRAMES_PER_SECOND,
    DEFAULT_WS_MAX_PENDING_EVENT_BYTES, DEFAULT_WS_MAX_SUBSCRIPTIONS, DEFAULT_WS_SEND_TIMEOUT,
    default_argon2_concurrency,
};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleConfig {
    /// Host-owned keys for encrypted credential records; required with persistent storage.
    #[serde(default)]
    pub credentials: Option<ConsoleCredentialKeys>,
    #[serde(default)]
    pub streams: xolotl_console::ConsoleStreamConfig,
    #[serde(default)]
    pub runtime: xolotl_console::ConsoleRuntimeConfig,
    #[serde(default)]
    pub root: ConsoleRootConfig,
    #[serde(default)]
    pub auth: ConsoleAuthTuning,
    #[serde(default)]
    pub ws: ConsoleWsTuning,
    #[serde(default)]
    pub queries: ConsoleQueryConfig,
    #[serde(default = "default_console_max_concurrent_calls")]
    pub max_concurrent_calls: usize,
    #[serde(default = "default_console_max_concurrent_authentications")]
    pub max_concurrent_authentications: usize,
    /// Total time to receive an HTTP authentication or protobuf call body.
    #[serde(default = "default_console_request_body_timeout_ms")]
    pub request_body_timeout_ms: u64,
    /// Host monotonic cadence for root-submission retry-range closure, separate
    /// from result retention. Defaults to 15 minutes; accepts 1..=86,400,000 ms.
    /// Enabled runtime submissions share the existing one-second Console
    /// maintenance task. A delayed tick closes at most one epoch and schedules
    /// from the actual close time, without catch-up or replay. Closure returns
    /// eligible alias slots but preserves retained records and pending cleanup;
    /// old missing identities cannot execute. Embedding hosts choose their own
    /// policy through ConsoleService, without this daemon cadence.
    /// Size directory capacities and cadence together for the submission rate;
    /// a full directory can reject work before its next scheduled closure.
    #[serde(
        default = "default_console_submission_retry_epoch_ms",
        deserialize_with = "deserialize_submission_retry_epoch_ms"
    )]
    pub submission_retry_epoch_ms: u64,
    #[serde(default)]
    pub transport_security: ConsoleTransportSecurityTuning,
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            credentials: None,
            streams: xolotl_console::ConsoleStreamConfig::default(),
            root: ConsoleRootConfig::default(),
            runtime: xolotl_console::ConsoleRuntimeConfig::default(),
            auth: ConsoleAuthTuning::default(),
            ws: ConsoleWsTuning::default(),
            queries: ConsoleQueryConfig::default(),
            max_concurrent_calls: default_console_max_concurrent_calls(),
            max_concurrent_authentications: default_console_max_concurrent_authentications(),
            request_body_timeout_ms: default_console_request_body_timeout_ms(),
            submission_retry_epoch_ms: default_console_submission_retry_epoch_ms(),
            transport_security: ConsoleTransportSecurityTuning::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleCredentialKeys {
    pub active_key_id: String,
    pub active_key_file: String,
    #[serde(default)]
    pub previous: Vec<ConsoleDecryptionKey>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleDecryptionKey {
    pub key_id: String,
    pub key_file: String,
}

impl ConsoleConfig {
    pub fn submission_retry_epoch_period(&self) -> Result<Duration> {
        validate_submission_retry_epoch_ms(self.submission_retry_epoch_ms)
    }

    pub fn load_credential_sealer(&self, persistent: bool) -> Result<Arc<CredentialSealer>> {
        let Some(keys) = &self.credentials else {
            if persistent {
                anyhow::bail!(
                    "persistent Console credentials require [console.credentials] with an active 32-byte key file"
                );
            }
            let mut key = Zeroizing::new([0u8; 32]);
            getrandom::fill(&mut *key)
                .map_err(|error| anyhow::anyhow!("generate ephemeral Console key: {error}"))?;
            return Ok(Arc::new(CredentialSealer::new("ephemeral", &key)?));
        };
        if keys.previous.len() > 7 {
            anyhow::bail!("too many Console decryption keys");
        }
        let active_key =
            super::private_key::read_private_key_file(&keys.active_key_file, "Console credential")?;
        let mut sealer = CredentialSealer::new(&keys.active_key_id, &active_key)?;
        for previous in &keys.previous {
            let key = super::private_key::read_private_key_file(
                &previous.key_file,
                "Console credential",
            )?;
            sealer.add_decryption_key(&previous.key_id, &key)?;
        }
        Ok(Arc::new(sealer))
    }
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
    /// Capabilities added to root and its delegation ceiling only at first provisioning.
    #[serde(default)]
    pub additional_grants: Vec<String>,
    /// Optional pre-seeded Argon2id PHC string for the root Console account.
    pub password_hash: Option<String>,
    /// Optional plaintext root password, mutually exclusive with `password_hash`.
    /// The console validates and hashes it at bootstrap.
    pub password: Option<String>,
    /// Optional ML-DSA-65 key descriptors for deployments that disable
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
    #[serde(default = "default_max_sessions_per_account")]
    pub max_sessions_per_account: usize,
    #[serde(default = "default_global_session_limit")]
    pub global_session_limit: usize,
    #[serde(default = "default_argon2_concurrency")]
    pub argon2_concurrency: usize,
    #[serde(default = "default_max_external_verifications")]
    pub max_external_verifications: usize,
    #[serde(default)]
    pub challenges: xolotl_console::ConsoleChallengeConfig,
    #[serde(default)]
    pub webauthn: ConsoleWebAuthnTuning,
    #[serde(default)]
    pub mfa: xolotl_console::mfa::ConsoleMfaConfig,
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
            max_sessions_per_account: default_max_sessions_per_account(),
            global_session_limit: default_global_session_limit(),
            argon2_concurrency: default_argon2_concurrency(),
            max_external_verifications: default_max_external_verifications(),
            challenges: xolotl_console::ConsoleChallengeConfig::default(),
            webauthn: ConsoleWebAuthnTuning::default(),
            mfa: xolotl_console::mfa::ConsoleMfaConfig::default(),
        }
    }
}

impl From<ConsoleAuthTuning> for ConsoleAuthConfig {
    fn from(value: ConsoleAuthTuning) -> Self {
        Self {
            credential_sealer: None,
            session_ttl_ms: value.session_ttl_ms,
            idle_ttl_ms: value.idle_ttl_ms,
            argon2_concurrency: value.argon2_concurrency,
            max_external_verifications: value.max_external_verifications,
            challenges: value.challenges,
            webauthn: value.webauthn.into(),
            mfa: value.mfa,
        }
        .bounded()
    }
}

impl ConsoleAuthTuning {
    pub fn session_policy(&self) -> Result<xolotl_console::session_store::ConsoleSessionPolicy> {
        Ok(xolotl_console::session_store::ConsoleSessionPolicy::new(
            self.max_sessions_per_account.clamp(
                xolotl_console::MIN_MAX_SESSIONS_PER_ACCOUNT,
                xolotl_console::HARD_MAX_SESSIONS_PER_ACCOUNT,
            ),
            self.global_session_limit.clamp(
                xolotl_console::MIN_GLOBAL_SESSION_LIMIT,
                xolotl_console::HARD_GLOBAL_SESSION_LIMIT,
            ),
        )?)
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
    #[serde(default = "default_ws_max_connections_per_account")]
    pub max_connections_per_account: usize,
    #[serde(default = "default_ws_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_ws_max_frames_per_second")]
    pub max_frames_per_second: usize,
    #[serde(default = "default_ws_max_bytes_per_second")]
    pub max_bytes_per_second: usize,
    #[serde(default = "default_ws_max_subscriptions")]
    pub max_subscriptions: usize,
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
            max_connections_per_account: default_ws_max_connections_per_account(),
            idle_timeout_secs: default_ws_idle_timeout_secs(),
            max_frames_per_second: default_ws_max_frames_per_second(),
            max_bytes_per_second: default_ws_max_bytes_per_second(),
            max_subscriptions: default_ws_max_subscriptions(),
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
            max_connections_per_account: value.max_connections_per_account,
            idle_timeout: Duration::from_secs(value.idle_timeout_secs),
            max_frames_per_second: value.max_frames_per_second,
            max_bytes_per_second: value.max_bytes_per_second,
            max_subscriptions: value.max_subscriptions,
            max_pending_event_bytes: value.max_pending_event_bytes,
            send_timeout: Duration::from_millis(value.send_timeout_ms),
        }
        .bounded()
    }
}

fn default_console_max_concurrent_calls() -> usize {
    64
}

fn default_console_max_concurrent_authentications() -> usize {
    64
}

fn default_session_ttl_ms() -> i64 {
    DEFAULT_SESSION_TTL_MS
}

fn default_idle_ttl_ms() -> i64 {
    DEFAULT_IDLE_TTL_MS
}

fn default_max_sessions_per_account() -> usize {
    DEFAULT_MAX_SESSIONS_PER_ACCOUNT
}

fn default_global_session_limit() -> usize {
    DEFAULT_GLOBAL_SESSION_LIMIT
}

fn default_max_external_verifications() -> usize {
    ConsoleAuthConfig::default().max_external_verifications
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

fn default_ws_max_connections_per_account() -> usize {
    DEFAULT_WS_MAX_CONNECTIONS_PER_ACCOUNT
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

fn default_ws_max_pending_event_bytes() -> usize {
    DEFAULT_WS_MAX_PENDING_EVENT_BYTES
}

fn default_ws_send_timeout_ms() -> u64 {
    DEFAULT_WS_SEND_TIMEOUT.as_millis() as u64
}

fn default_console_request_body_timeout_ms() -> u64 {
    xolotl_console::http::DEFAULT_HTTP_REQUEST_BODY_TIMEOUT.as_millis() as u64
}

fn default_console_submission_retry_epoch_ms() -> u64 {
    15 * 60 * 1000
}

fn validate_submission_retry_epoch_ms(millis: u64) -> Result<Duration> {
    anyhow::ensure!(
        (1..=24 * 60 * 60 * 1000).contains(&millis),
        "console.submission_retry_epoch_ms must be 1..=86400000"
    );
    Ok(Duration::from_millis(millis))
}

fn deserialize_submission_retry_epoch_ms<'de, Decoder>(
    decoder: Decoder,
) -> Result<u64, Decoder::Error>
where
    Decoder: serde::Deserializer<'de>,
{
    let millis = u64::deserialize(decoder)?;
    validate_submission_retry_epoch_ms(millis).map_err(serde::de::Error::custom)?;
    Ok(millis)
}
