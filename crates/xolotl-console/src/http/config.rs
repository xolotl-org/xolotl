//! Adapter-owned transport policy, bounded WebSocket configuration and admission.

use crate::auth::AccountKey;
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

/// Default total time allowed to receive one HTTP request body.
pub const DEFAULT_HTTP_REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(30);
/// Minimum effective HTTP request-body receive timeout.
pub const MIN_HTTP_REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(1);
/// Hard upper bound for an HTTP request-body receive timeout.
pub const HARD_HTTP_REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
/// Default maximum WebSocket frame size.
pub const DEFAULT_WS_MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Default global WebSocket connection limit.
pub const DEFAULT_WS_MAX_CONNECTIONS_GLOBAL: usize = 256;
/// Default WebSocket connection limit per source address.
pub const DEFAULT_WS_MAX_CONNECTIONS_PER_SOURCE: usize = 32;
/// Default WebSocket connection limit per account instance.
pub const DEFAULT_WS_MAX_CONNECTIONS_PER_ACCOUNT: usize = 8;
/// Default idle timeout for WebSocket sessions.
pub const DEFAULT_WS_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
/// Default per-session incoming frame rate limit.
pub const DEFAULT_WS_MAX_FRAMES_PER_SECOND: usize = 64;
/// Default per-session incoming byte rate limit.
pub const DEFAULT_WS_MAX_BYTES_PER_SECOND: usize = 4 * 1024 * 1024;
/// Default subscription limit per WebSocket session.
pub const DEFAULT_WS_MAX_SUBSCRIPTIONS: usize = 32;
/// Default per-session byte budget for queued and in-flight subscription data.
pub const DEFAULT_WS_MAX_PENDING_EVENT_BYTES: usize = 1024 * 1024;
/// Default timeout for sending any frame to a WebSocket session.
pub const DEFAULT_WS_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Minimum accepted WebSocket frame size.
pub const MIN_WS_MAX_FRAME_BYTES: usize = 16 * 1024;
/// Hard upper bound for WebSocket frame size.
pub const HARD_MAX_WS_FRAME_BYTES: usize = 4 * 1024 * 1024;
/// Minimum accepted global WebSocket connection limit.
pub const MIN_WS_CONNECTIONS_GLOBAL: usize = 1;
/// Hard upper bound for global WebSocket connection limit.
pub const HARD_MAX_WS_CONNECTIONS_GLOBAL: usize = 100_000;
/// Minimum accepted per-source connection limit.
pub const MIN_WS_CONNECTIONS_PER_SOURCE: usize = 1;
/// Hard upper bound for per-source connection limit.
pub const HARD_MAX_WS_CONNECTIONS_PER_SOURCE: usize = 10_000;
/// Minimum accepted per-account connection limit.
pub const MIN_WS_CONNECTIONS_PER_ACCOUNT: usize = 1;
/// Hard upper bound for per-account connection limit.
pub const HARD_MAX_WS_CONNECTIONS_PER_ACCOUNT: usize = 10_000;
/// Minimum accepted WebSocket idle timeout.
pub const MIN_WS_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard upper bound for WebSocket idle timeout.
pub const HARD_MAX_WS_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
/// Minimum accepted frame rate limit.
pub const MIN_WS_MAX_FRAMES_PER_SECOND: usize = 1;
/// Hard upper bound for frame rate limit.
pub const HARD_MAX_WS_FRAMES_PER_SECOND: usize = 10_000;
/// Minimum accepted byte rate limit.
pub const MIN_WS_MAX_BYTES_PER_SECOND: usize = 16 * 1024;
/// Hard upper bound for byte rate limit.
pub const HARD_MAX_WS_BYTES_PER_SECOND: usize = 64 * 1024 * 1024;
/// Minimum accepted subscription limit.
pub const MIN_WS_MAX_SUBSCRIPTIONS: usize = 1;
/// Hard upper bound for subscription limit.
pub const HARD_MAX_WS_SUBSCRIPTIONS: usize = 256;
/// Minimum accepted subscription queue byte budget.
pub const MIN_WS_MAX_PENDING_EVENT_BYTES: usize = 16 * 1024;
/// Hard upper bound for a session's subscription queue byte budget.
pub const HARD_MAX_WS_PENDING_EVENT_BYTES: usize = 16 * 1024 * 1024;
/// Minimum accepted frame send timeout.
pub const MIN_WS_SEND_TIMEOUT: Duration = Duration::from_millis(100);
/// Hard upper bound for frame send timeout.
pub const HARD_MAX_WS_SEND_TIMEOUT: Duration = Duration::from_secs(60);

// Console adapters use the common Gateway transport policy. Their default is
// ProductionTls; constructing a service alone does not create this policy.
pub use xolotl_gateway::{
    GatewayTransportSecurityConfig as ConsoleTransportSecurityConfig,
    GatewayTransportSecurityMode as ConsoleTransportSecurityMode,
    GatewayTrustedProxyConfig as ConsoleTrustedProxyConfig,
    GatewayUnsafeTransportRelaxation as ConsoleUnsafeTransportRelaxation,
};

/// Console transport-security default: `ProductionTls` with default trusted
/// proxy settings and no unsafe relaxations. The gateway's own `Default`
/// returns `LocalTrusted`, so console call sites that need the console default
/// use this instead of `Default::default()`.
pub(crate) fn console_transport_default() -> ConsoleTransportSecurityConfig {
    ConsoleTransportSecurityConfig {
        mode: ConsoleTransportSecurityMode::ProductionTls,
        trusted_proxy: ConsoleTrustedProxyConfig::default(),
        unsafe_relaxations: Vec::new(),
    }
    .bounded()
}

/// WebSocket runtime tuning for the Console Protocol server.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ConsoleWsConfig {
    /// Maximum incoming or outgoing encoded frame size.
    pub max_frame_bytes: usize,
    /// Maximum global active WebSocket connections.
    pub max_connections_global: usize,
    /// Maximum active WebSocket connections per source address.
    pub max_connections_per_source: usize,
    /// Maximum active WebSocket connections per account instance.
    pub max_connections_per_account: usize,
    /// Idle timeout for a session.
    #[serde(rename = "idle_timeout_ms", serialize_with = "duration_millis")]
    pub idle_timeout: Duration,
    /// Maximum incoming frames per second.
    pub max_frames_per_second: usize,
    /// Maximum incoming bytes per second.
    pub max_bytes_per_second: usize,
    /// Maximum active subscriptions per session.
    pub max_subscriptions: usize,
    /// Encoded bytes retained by queued and in-flight subscription data frames.
    /// A saturated queue closes the producing subscription. Bounded closure
    /// notifications use an independent control path.
    pub max_pending_event_bytes: usize,
    /// Timeout for delivering any frame to a session.
    #[serde(rename = "send_timeout_ms", serialize_with = "duration_millis")]
    pub send_timeout: Duration,
}

impl Default for ConsoleWsConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_WS_MAX_FRAME_BYTES,
            max_connections_global: DEFAULT_WS_MAX_CONNECTIONS_GLOBAL,
            max_connections_per_source: DEFAULT_WS_MAX_CONNECTIONS_PER_SOURCE,
            max_connections_per_account: DEFAULT_WS_MAX_CONNECTIONS_PER_ACCOUNT,
            idle_timeout: DEFAULT_WS_IDLE_TIMEOUT,
            max_frames_per_second: DEFAULT_WS_MAX_FRAMES_PER_SECOND,
            max_bytes_per_second: DEFAULT_WS_MAX_BYTES_PER_SECOND,
            max_subscriptions: DEFAULT_WS_MAX_SUBSCRIPTIONS,
            max_pending_event_bytes: DEFAULT_WS_MAX_PENDING_EVENT_BYTES,
            send_timeout: DEFAULT_WS_SEND_TIMEOUT,
        }
    }
}

impl ConsoleWsConfig {
    /// Clamp all WebSocket tuning values into hard backend bounds.
    pub fn bounded(self) -> Self {
        Self {
            max_frame_bytes: self
                .max_frame_bytes
                .clamp(MIN_WS_MAX_FRAME_BYTES, HARD_MAX_WS_FRAME_BYTES),
            max_connections_global: self
                .max_connections_global
                .clamp(MIN_WS_CONNECTIONS_GLOBAL, HARD_MAX_WS_CONNECTIONS_GLOBAL),
            max_connections_per_source: self.max_connections_per_source.clamp(
                MIN_WS_CONNECTIONS_PER_SOURCE,
                HARD_MAX_WS_CONNECTIONS_PER_SOURCE,
            ),
            max_connections_per_account: self.max_connections_per_account.clamp(
                MIN_WS_CONNECTIONS_PER_ACCOUNT,
                HARD_MAX_WS_CONNECTIONS_PER_ACCOUNT,
            ),
            idle_timeout: clamp_duration(
                self.idle_timeout,
                MIN_WS_IDLE_TIMEOUT,
                HARD_MAX_WS_IDLE_TIMEOUT,
            ),
            max_frames_per_second: self
                .max_frames_per_second
                .clamp(MIN_WS_MAX_FRAMES_PER_SECOND, HARD_MAX_WS_FRAMES_PER_SECOND),
            max_bytes_per_second: self
                .max_bytes_per_second
                .clamp(MIN_WS_MAX_BYTES_PER_SECOND, HARD_MAX_WS_BYTES_PER_SECOND),
            max_subscriptions: self
                .max_subscriptions
                .clamp(MIN_WS_MAX_SUBSCRIPTIONS, HARD_MAX_WS_SUBSCRIPTIONS),
            max_pending_event_bytes: self.max_pending_event_bytes.clamp(
                MIN_WS_MAX_PENDING_EVENT_BYTES,
                HARD_MAX_WS_PENDING_EVENT_BYTES,
            ),
            send_timeout: clamp_duration(
                self.send_timeout,
                MIN_WS_SEND_TIMEOUT,
                HARD_MAX_WS_SEND_TIMEOUT,
            ),
        }
    }
}

/// Runtime counters enforcing Console WebSocket limits.
#[derive(Debug)]
pub(crate) struct ConsoleWsRuntime {
    config: ConsoleWsConfig,
    counts: Mutex<ConsoleWsCounts>,
}

impl Default for ConsoleWsRuntime {
    fn default() -> Self {
        Self::new(ConsoleWsConfig::default())
    }
}

impl ConsoleWsRuntime {
    /// Create a runtime counter set with bounded configuration.
    pub(crate) fn new(config: ConsoleWsConfig) -> Self {
        let config = config.bounded();
        Self {
            config,
            counts: Mutex::new(ConsoleWsCounts::default()),
        }
    }

    /// Return the bounded WebSocket configuration.
    pub(crate) fn config(&self) -> &ConsoleWsConfig {
        &self.config
    }

    /// Reserve one connection for a source address.
    pub(crate) fn try_acquire_source(&self, source: &str) -> Result<(), ConsoleWsLimit> {
        let mut counts = self.counts();
        if counts.global >= self.config.max_connections_global {
            return Err(ConsoleWsLimit::Global);
        }
        if count_for(&counts.by_source, source) >= self.config.max_connections_per_source {
            return Err(ConsoleWsLimit::Source);
        }
        counts.global += 1;
        increment(&mut counts.by_source, source);
        Ok(())
    }

    /// Release a previously reserved source-address connection.
    pub(crate) fn release_source(&self, source: &str) {
        let mut counts = self.counts();
        counts.global = counts.global.saturating_sub(1);
        decrement(&mut counts.by_source, source);
    }

    /// Move a connection's per-account accounting from `current` to `next`.
    pub(crate) fn try_replace_account(
        &self,
        current: Option<&AccountKey>,
        next: &AccountKey,
    ) -> Result<(), ConsoleWsLimit> {
        if current == Some(next) {
            return Ok(());
        }
        let mut counts = self.counts();
        if counts.by_account.get(next).copied().unwrap_or_default()
            >= self.config.max_connections_per_account
        {
            return Err(ConsoleWsLimit::Account);
        }
        if let Some(current) = current {
            decrement_account(&mut counts.by_account, current);
        }
        *counts.by_account.entry(next.clone()).or_default() += 1;
        Ok(())
    }

    /// Release one account-owned connection.
    pub(crate) fn release_account(&self, account: &AccountKey) {
        let mut counts = self.counts();
        decrement_account(&mut counts.by_account, account);
    }

    fn counts(&self) -> MutexGuard<'_, ConsoleWsCounts> {
        match self.counts.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// WebSocket limit class that rejected a connection or authentication update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConsoleWsLimit {
    /// Global connection limit reached.
    Global,
    /// Per-source connection limit reached.
    Source,
    /// Per-account connection limit reached.
    Account,
}

#[derive(Debug, Default)]
struct ConsoleWsCounts {
    global: usize,
    by_source: HashMap<String, usize>,
    by_account: HashMap<AccountKey, usize>,
}

fn decrement_account(counts: &mut HashMap<AccountKey, usize>, key: &AccountKey) {
    if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(key);
        }
    }
}

fn count_for(counts: &HashMap<String, usize>, key: &str) -> usize {
    counts.get(key).copied().unwrap_or(0)
}

fn increment(counts: &mut HashMap<String, usize>, key: &str) {
    *counts.entry(key.to_string()).or_default() += 1;
}

fn decrement(counts: &mut HashMap<String, usize>, key: &str) {
    if let Some(count) = counts.get_mut(key) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            counts.remove(key);
        }
    }
}

fn clamp_duration(value: Duration, min: Duration, max: Duration) -> Duration {
    value.max(min).min(max)
}

fn duration_millis<S: serde::Serializer>(
    duration: &Duration,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let millis = u64::try_from(duration.as_millis()).map_err(serde::ser::Error::custom)?;
    serializer.serialize_u64(millis)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_config_is_bounded_by_backend() {
        let runtime = ConsoleWsRuntime::new(ConsoleWsConfig {
            max_frame_bytes: usize::MAX,
            max_connections_global: 0,
            max_connections_per_source: usize::MAX,
            max_connections_per_account: 0,
            idle_timeout: Duration::ZERO,
            max_frames_per_second: usize::MAX,
            max_bytes_per_second: 1,
            max_subscriptions: usize::MAX,
            max_pending_event_bytes: usize::MAX,
            send_timeout: Duration::ZERO,
        });
        let cfg = runtime.config();
        assert_eq!(cfg.max_frame_bytes, HARD_MAX_WS_FRAME_BYTES);
        assert_eq!(cfg.max_connections_global, MIN_WS_CONNECTIONS_GLOBAL);
        assert_eq!(
            cfg.max_connections_per_source,
            HARD_MAX_WS_CONNECTIONS_PER_SOURCE
        );
        assert_eq!(
            cfg.max_connections_per_account,
            MIN_WS_CONNECTIONS_PER_ACCOUNT
        );
        assert_eq!(cfg.idle_timeout, MIN_WS_IDLE_TIMEOUT);
        assert_eq!(cfg.max_frames_per_second, HARD_MAX_WS_FRAMES_PER_SECOND);
        assert_eq!(cfg.max_bytes_per_second, MIN_WS_MAX_BYTES_PER_SECOND);
        assert_eq!(cfg.max_subscriptions, HARD_MAX_WS_SUBSCRIPTIONS);
        assert_eq!(cfg.max_pending_event_bytes, HARD_MAX_WS_PENDING_EVENT_BYTES);
        assert_eq!(cfg.send_timeout, MIN_WS_SEND_TIMEOUT);
    }
}
