//! Console state: the kernel handle and the management-domain identity (§18.4).
//!
//! The Web Console is a **management-domain Gateway**: it maps authenticated
//! console users to a management identity and runs their actions as ordinary
//! capability-bound Operations. There is no privileged backdoor and no bespoke
//! wire protocol — every action is a `Value.write`+Cas, an inspect read, or a
//! subscribe on a `state://kernel/*` Resource (§18.4).

use nexus_kernel::Bootstrap;
use nexus_state::Backend;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::auth::{ConsoleAuth, ConsoleAuthConfig};
use nexus_actors::PairingDisplayEdge;

pub const DEFAULT_WS_MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const DEFAULT_WS_MAX_CONNECTIONS_GLOBAL: usize = 256;
pub const DEFAULT_WS_MAX_CONNECTIONS_PER_SOURCE: usize = 32;
pub const DEFAULT_WS_MAX_CONNECTIONS_PER_USER: usize = 8;
pub const DEFAULT_WS_IDLE_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);
pub const DEFAULT_WS_MAX_FRAMES_PER_SECOND: usize = 64;
pub const DEFAULT_WS_MAX_BYTES_PER_SECOND: usize = 4 * 1024 * 1024;
pub const DEFAULT_WS_MAX_SUBSCRIPTIONS: usize = 32;
pub const DEFAULT_WS_MAX_FACT_LIMIT: usize = 256;
pub const DEFAULT_WS_MAX_TRACE_LIMIT: usize = 512;
pub const DEFAULT_WS_EVENT_SEND_TIMEOUT: Duration = Duration::from_secs(5);

pub const MIN_WS_MAX_FRAME_BYTES: usize = 16 * 1024;
pub const HARD_MAX_WS_FRAME_BYTES: usize = 4 * 1024 * 1024;
pub const MIN_WS_CONNECTIONS_GLOBAL: usize = 1;
pub const HARD_MAX_WS_CONNECTIONS_GLOBAL: usize = 100_000;
pub const MIN_WS_CONNECTIONS_PER_SOURCE: usize = 1;
pub const HARD_MAX_WS_CONNECTIONS_PER_SOURCE: usize = 10_000;
pub const MIN_WS_CONNECTIONS_PER_USER: usize = 1;
pub const HARD_MAX_WS_CONNECTIONS_PER_USER: usize = 10_000;
pub const MIN_WS_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const HARD_MAX_WS_IDLE_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
pub const MIN_WS_MAX_FRAMES_PER_SECOND: usize = 1;
pub const HARD_MAX_WS_FRAMES_PER_SECOND: usize = 10_000;
pub const MIN_WS_MAX_BYTES_PER_SECOND: usize = 16 * 1024;
pub const HARD_MAX_WS_BYTES_PER_SECOND: usize = 64 * 1024 * 1024;
pub const MIN_WS_MAX_SUBSCRIPTIONS: usize = 1;
pub const HARD_MAX_WS_SUBSCRIPTIONS: usize = 256;
pub const MIN_WS_MAX_FACT_LIMIT: usize = 1;
pub const HARD_MAX_WS_FACT_LIMIT: usize = 4_096;
pub const MIN_WS_MAX_TRACE_LIMIT: usize = 1;
pub const HARD_MAX_WS_TRACE_LIMIT: usize = 8_192;
pub const MIN_WS_EVENT_SEND_TIMEOUT: Duration = Duration::from_millis(100);
pub const HARD_MAX_WS_EVENT_SEND_TIMEOUT: Duration = Duration::from_secs(60);

/// Shared console backend state.
pub struct ConsoleState {
    pub boot: Arc<Bootstrap>,
    /// The state backend the console reads/writes management config through.
    /// All management config lives under `state://kernel/*` (Layer 1, §12).
    pub state: Backend,
    pub auth: ConsoleAuth,
    pub pairing_display: PairingDisplayEdge,
    pub ws: ConsoleWsRuntime,
}

impl ConsoleState {
    pub fn new(boot: Arc<Bootstrap>) -> Self {
        Self::with_pairing_display_and_config(
            boot,
            PairingDisplayEdge::default(),
            ConsoleAuthConfig::default(),
            ConsoleWsConfig::default(),
        )
    }

    pub fn with_pairing_display(boot: Arc<Bootstrap>, pairing_display: PairingDisplayEdge) -> Self {
        Self::with_pairing_display_and_config(
            boot,
            pairing_display,
            ConsoleAuthConfig::default(),
            ConsoleWsConfig::default(),
        )
    }

    pub fn with_pairing_display_and_config(
        boot: Arc<Bootstrap>,
        pairing_display: PairingDisplayEdge,
        auth: ConsoleAuthConfig,
        ws: ConsoleWsConfig,
    ) -> Self {
        let state = boot.kernel.state.clone();
        Self {
            boot,
            state,
            auth: ConsoleAuth::new(auth),
            pairing_display,
            ws: ConsoleWsRuntime::new(ws),
        }
    }

    pub fn shared(boot: Arc<Bootstrap>) -> Arc<Self> {
        Arc::new(Self::new(boot))
    }

    pub fn shared_with_pairing_display(
        boot: Arc<Bootstrap>,
        pairing_display: PairingDisplayEdge,
    ) -> Arc<Self> {
        Arc::new(Self::with_pairing_display(boot, pairing_display))
    }

    pub fn shared_with_pairing_display_and_config(
        boot: Arc<Bootstrap>,
        pairing_display: PairingDisplayEdge,
        auth: ConsoleAuthConfig,
        ws: ConsoleWsConfig,
    ) -> Arc<Self> {
        Arc::new(Self::with_pairing_display_and_config(
            boot,
            pairing_display,
            auth,
            ws,
        ))
    }
}

#[derive(Clone, Debug)]
pub struct ConsoleWsConfig {
    pub max_frame_bytes: usize,
    pub max_connections_global: usize,
    pub max_connections_per_source: usize,
    pub max_connections_per_user: usize,
    pub idle_timeout: Duration,
    pub max_frames_per_second: usize,
    pub max_bytes_per_second: usize,
    pub max_subscriptions: usize,
    pub max_fact_limit: usize,
    pub max_trace_limit: usize,
    pub event_send_timeout: Duration,
}

impl Default for ConsoleWsConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_WS_MAX_FRAME_BYTES,
            max_connections_global: DEFAULT_WS_MAX_CONNECTIONS_GLOBAL,
            max_connections_per_source: DEFAULT_WS_MAX_CONNECTIONS_PER_SOURCE,
            max_connections_per_user: DEFAULT_WS_MAX_CONNECTIONS_PER_USER,
            idle_timeout: DEFAULT_WS_IDLE_TIMEOUT,
            max_frames_per_second: DEFAULT_WS_MAX_FRAMES_PER_SECOND,
            max_bytes_per_second: DEFAULT_WS_MAX_BYTES_PER_SECOND,
            max_subscriptions: DEFAULT_WS_MAX_SUBSCRIPTIONS,
            max_fact_limit: DEFAULT_WS_MAX_FACT_LIMIT,
            max_trace_limit: DEFAULT_WS_MAX_TRACE_LIMIT,
            event_send_timeout: DEFAULT_WS_EVENT_SEND_TIMEOUT,
        }
    }
}

impl ConsoleWsConfig {
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
            max_connections_per_user: self.max_connections_per_user.clamp(
                MIN_WS_CONNECTIONS_PER_USER,
                HARD_MAX_WS_CONNECTIONS_PER_USER,
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
            max_fact_limit: self
                .max_fact_limit
                .clamp(MIN_WS_MAX_FACT_LIMIT, HARD_MAX_WS_FACT_LIMIT),
            max_trace_limit: self
                .max_trace_limit
                .clamp(MIN_WS_MAX_TRACE_LIMIT, HARD_MAX_WS_TRACE_LIMIT),
            event_send_timeout: clamp_duration(
                self.event_send_timeout,
                MIN_WS_EVENT_SEND_TIMEOUT,
                HARD_MAX_WS_EVENT_SEND_TIMEOUT,
            ),
        }
    }
}

#[derive(Debug)]
pub struct ConsoleWsRuntime {
    config: ConsoleWsConfig,
    counts: Mutex<ConsoleWsCounts>,
}

impl Default for ConsoleWsRuntime {
    fn default() -> Self {
        Self::new(ConsoleWsConfig::default())
    }
}

impl ConsoleWsRuntime {
    pub fn new(config: ConsoleWsConfig) -> Self {
        let config = config.bounded();
        Self {
            config,
            counts: Mutex::new(ConsoleWsCounts::default()),
        }
    }

    pub fn config(&self) -> &ConsoleWsConfig {
        &self.config
    }

    pub fn try_acquire_source(&self, source: &str) -> Result<(), ConsoleWsLimit> {
        let mut counts = self.counts.lock().expect("console ws counts poisoned");
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

    pub fn release_source(&self, source: &str) {
        let mut counts = self.counts.lock().expect("console ws counts poisoned");
        counts.global = counts.global.saturating_sub(1);
        decrement(&mut counts.by_source, source);
    }

    pub fn try_replace_user(
        &self,
        current: Option<&str>,
        next: &str,
    ) -> Result<(), ConsoleWsLimit> {
        if current == Some(next) {
            return Ok(());
        }
        let mut counts = self.counts.lock().expect("console ws counts poisoned");
        if count_for(&counts.by_user, next) >= self.config.max_connections_per_user {
            return Err(ConsoleWsLimit::User);
        }
        if let Some(current) = current {
            decrement(&mut counts.by_user, current);
        }
        increment(&mut counts.by_user, next);
        Ok(())
    }

    pub fn release_user(&self, user: &str) {
        let mut counts = self.counts.lock().expect("console ws counts poisoned");
        decrement(&mut counts.by_user, user);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleWsLimit {
    Global,
    Source,
    User,
}

#[derive(Debug, Default)]
struct ConsoleWsCounts {
    global: usize,
    by_source: HashMap<String, usize>,
    by_user: HashMap<String, usize>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_config_is_bounded_by_backend() {
        let runtime = ConsoleWsRuntime::new(ConsoleWsConfig {
            max_frame_bytes: usize::MAX,
            max_connections_global: 0,
            max_connections_per_source: usize::MAX,
            max_connections_per_user: 0,
            idle_timeout: Duration::ZERO,
            max_frames_per_second: usize::MAX,
            max_bytes_per_second: 1,
            max_subscriptions: usize::MAX,
            max_fact_limit: 0,
            max_trace_limit: usize::MAX,
            event_send_timeout: Duration::ZERO,
        });
        let cfg = runtime.config();
        assert_eq!(cfg.max_frame_bytes, HARD_MAX_WS_FRAME_BYTES);
        assert_eq!(cfg.max_connections_global, MIN_WS_CONNECTIONS_GLOBAL);
        assert_eq!(
            cfg.max_connections_per_source,
            HARD_MAX_WS_CONNECTIONS_PER_SOURCE
        );
        assert_eq!(cfg.max_connections_per_user, MIN_WS_CONNECTIONS_PER_USER);
        assert_eq!(cfg.idle_timeout, MIN_WS_IDLE_TIMEOUT);
        assert_eq!(cfg.max_frames_per_second, HARD_MAX_WS_FRAMES_PER_SECOND);
        assert_eq!(cfg.max_bytes_per_second, MIN_WS_MAX_BYTES_PER_SECOND);
        assert_eq!(cfg.max_subscriptions, HARD_MAX_WS_SUBSCRIPTIONS);
        assert_eq!(cfg.max_fact_limit, MIN_WS_MAX_FACT_LIMIT);
        assert_eq!(cfg.max_trace_limit, HARD_MAX_WS_TRACE_LIMIT);
        assert_eq!(cfg.event_send_timeout, MIN_WS_EVENT_SEND_TIMEOUT);
    }
}
