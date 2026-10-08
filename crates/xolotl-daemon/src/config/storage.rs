//! Storage selection, retention, and bounded history maintenance.

use anyhow::Result;
use serde::Deserialize;
use std::num::{NonZeroU64, NonZeroUsize};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default)]
    pub kind: StorageKind,
    #[serde(default = "default_storage_path")]
    pub path: String,
    /// Retain only current State values by default, or all State mutations.
    #[serde(default)]
    pub state_history: StorageHistoryMode,
    /// Required when State history is `full`: explicitly authorizes a
    /// time-based global floor and bounds each maintenance transaction.
    #[serde(default)]
    pub history_maintenance: Option<StateHistoryMaintenanceConfig>,
    /// Optional observation history. Absence disables recording without
    /// disabling retained execution identities or application persistence.
    #[serde(default)]
    pub observations: Option<ObservationRetentionConfig>,
    /// Global retained ordered Source stream position quota for the built-in
    /// memory or redb storage owner. Existing streams continue at the limit.
    #[serde(default = "default_source_stream_limit")]
    pub source_stream_limit: NonZeroUsize,
    /// Global retained Source event/receipt pairs plus rate records.
    #[serde(default = "default_source_retention_limit")]
    pub source_retention_limit: NonZeroUsize,
    /// Retained sourced-absence records; "unlimited" removes this bound.
    #[serde(
        default = "default_absence_record_limit",
        deserialize_with = "deserialize_absence_limit"
    )]
    pub absence_record_limit: Option<usize>,
    /// Key plus full backend absence encoding; "unlimited" removes this bound.
    #[serde(
        default = "default_absence_encoded_byte_limit",
        deserialize_with = "deserialize_absence_limit"
    )]
    pub absence_encoded_byte_limit: Option<usize>,
    /// Retained Federation publication identities across all streams. Exact
    /// receipts in closed retry epochs permit explicit safe reclamation.
    #[serde(default = "default_federation_publish_id_limit")]
    pub federation_publish_id_limit: NonZeroUsize,
    /// Object directory, independent of State rows. Defaults beside the database.
    #[serde(default)]
    pub object_path: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            kind: StorageKind::Redb,
            path: default_storage_path(),
            state_history: StorageHistoryMode::CurrentOnly,
            history_maintenance: None,
            observations: None,
            source_stream_limit: default_source_stream_limit(),
            source_retention_limit: default_source_retention_limit(),
            absence_record_limit: default_absence_record_limit(),
            absence_encoded_byte_limit: default_absence_encoded_byte_limit(),
            federation_publish_id_limit: default_federation_publish_id_limit(),
            object_path: None,
        }
    }
}

/// Finite retained observation budgets. These bound encoded records, not RSS.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationRetentionConfig {
    pub max_records: NonZeroUsize,
    pub max_encoded_bytes: NonZeroUsize,
    pub max_record_bytes: NonZeroUsize,
}

impl ObservationRetentionConfig {
    pub fn limits(self) -> Result<xolotl_sdk::runtime::FactRetentionLimits> {
        let limits = xolotl_sdk::runtime::FactRetentionLimits {
            max_records: self.max_records,
            max_encoded_bytes: self.max_encoded_bytes,
            max_record_bytes: self.max_record_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }
}

pub const DEFAULT_HISTORY_MAINTENANCE_INTERVAL_MS: u64 = 10_000;
pub const MIN_HISTORY_MAINTENANCE_INTERVAL_MS: u64 = 1_000;
pub const MAX_HISTORY_MAINTENANCE_INTERVAL_MS: u64 = 3_600_000;
pub const DEFAULT_HISTORY_MAINTENANCE_ATTEMPTS_PER_TICK: usize = 16;
pub const MAX_HISTORY_MAINTENANCE_ATTEMPTS_PER_TICK: usize = 64;
pub const DEFAULT_HISTORY_MAINTENANCE_BATCHES_PER_TICK: usize = 4;
pub const MAX_HISTORY_MAINTENANCE_BATCHES_PER_TICK: usize = 16;
pub const DEFAULT_HISTORY_MAINTENANCE_EVENTS_PER_BATCH: usize = 4096;
pub const MAX_HISTORY_MAINTENANCE_EVENTS_PER_BATCH: usize = 4096;
pub const DEFAULT_HISTORY_MAINTENANCE_BYTES_PER_BATCH: usize = 16 * 1024 * 1024;
pub const MAX_HISTORY_MAINTENANCE_BYTES_PER_BATCH: usize = 16 * 1024 * 1024;

/// Optional explicit policy for the daemon's global State history floor.
/// `full` without this policy retains all history until the host trims it;
/// the daemon cannot infer how far audit or replay consumers need to look back.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateHistoryMaintenanceConfig {
    /// Retain at least this many wall-clock milliseconds of history. The
    /// backend's monotonic history clock can run ahead of wall time.
    pub retain_for_ms: NonZeroU64,
    #[serde(default = "default_history_maintenance_interval_ms")]
    pub interval_ms: NonZeroU64,
    #[serde(default = "default_history_maintenance_attempts_per_tick")]
    pub max_attempts_per_tick: NonZeroUsize,
    #[serde(default = "default_history_maintenance_batches_per_tick")]
    pub max_batches_per_tick: NonZeroUsize,
    #[serde(default = "default_history_maintenance_events_per_batch")]
    pub events_per_batch: NonZeroUsize,
    #[serde(default = "default_history_maintenance_bytes_per_batch")]
    pub encoded_bytes_per_batch: NonZeroUsize,
}

impl StorageConfig {
    pub fn absence_limits(&self) -> xolotl_state::AbsenceLimits {
        xolotl_state::AbsenceLimits {
            records: self.absence_record_limit,
            encoded_bytes: self.absence_encoded_byte_limit,
        }
    }

    pub fn history_maintenance(&self) -> Result<Option<StateHistoryMaintenanceConfig>> {
        let settings = match (self.state_history, self.history_maintenance) {
            (StorageHistoryMode::CurrentOnly, None) => return Ok(None),
            (StorageHistoryMode::CurrentOnly, Some(_)) => {
                anyhow::bail!("storage.history_maintenance requires state_history = 'full'")
            }
            (StorageHistoryMode::Full, None) => return Ok(None),
            (StorageHistoryMode::Full, Some(settings)) => settings,
        };
        anyhow::ensure!(
            settings.retain_for_ms.get() <= i64::MAX as u64,
            "storage.history_maintenance.retain_for_ms exceeds the State timestamp range"
        );
        anyhow::ensure!(
            (MIN_HISTORY_MAINTENANCE_INTERVAL_MS..=MAX_HISTORY_MAINTENANCE_INTERVAL_MS)
                .contains(&settings.interval_ms.get()),
            "storage.history_maintenance.interval_ms must be between {MIN_HISTORY_MAINTENANCE_INTERVAL_MS} and {MAX_HISTORY_MAINTENANCE_INTERVAL_MS}"
        );
        anyhow::ensure!(
            settings.max_attempts_per_tick.get() <= MAX_HISTORY_MAINTENANCE_ATTEMPTS_PER_TICK,
            "storage.history_maintenance.max_attempts_per_tick exceeds {MAX_HISTORY_MAINTENANCE_ATTEMPTS_PER_TICK}"
        );
        anyhow::ensure!(
            settings.max_batches_per_tick.get() <= MAX_HISTORY_MAINTENANCE_BATCHES_PER_TICK
                && settings.max_batches_per_tick <= settings.max_attempts_per_tick,
            "storage.history_maintenance.max_batches_per_tick must not exceed max_attempts_per_tick or {MAX_HISTORY_MAINTENANCE_BATCHES_PER_TICK}"
        );
        anyhow::ensure!(
            settings.events_per_batch.get() <= MAX_HISTORY_MAINTENANCE_EVENTS_PER_BATCH,
            "storage.history_maintenance.events_per_batch exceeds {MAX_HISTORY_MAINTENANCE_EVENTS_PER_BATCH}"
        );
        anyhow::ensure!(
            settings.encoded_bytes_per_batch.get() <= MAX_HISTORY_MAINTENANCE_BYTES_PER_BATCH,
            "storage.history_maintenance.encoded_bytes_per_batch exceeds {MAX_HISTORY_MAINTENANCE_BYTES_PER_BATCH}"
        );
        Ok(Some(settings))
    }
}

fn default_history_maintenance_interval_ms() -> NonZeroU64 {
    NonZeroU64::MIN.saturating_add(DEFAULT_HISTORY_MAINTENANCE_INTERVAL_MS - 1)
}

fn default_history_maintenance_attempts_per_tick() -> NonZeroUsize {
    NonZeroUsize::MIN.saturating_add(DEFAULT_HISTORY_MAINTENANCE_ATTEMPTS_PER_TICK - 1)
}

fn default_history_maintenance_batches_per_tick() -> NonZeroUsize {
    NonZeroUsize::MIN.saturating_add(DEFAULT_HISTORY_MAINTENANCE_BATCHES_PER_TICK - 1)
}

fn default_history_maintenance_events_per_batch() -> NonZeroUsize {
    NonZeroUsize::MIN.saturating_add(DEFAULT_HISTORY_MAINTENANCE_EVENTS_PER_BATCH - 1)
}

fn default_history_maintenance_bytes_per_batch() -> NonZeroUsize {
    NonZeroUsize::MIN.saturating_add(DEFAULT_HISTORY_MAINTENANCE_BYTES_PER_BATCH - 1)
}

fn default_source_stream_limit() -> NonZeroUsize {
    NonZeroUsize::MIN.saturating_add(4095)
}

fn default_absence_record_limit() -> Option<usize> {
    Some(65_536)
}

fn deserialize_absence_limit<'de, Deserializer>(
    deserializer: Deserializer,
) -> Result<Option<usize>, Deserializer::Error>
where
    Deserializer: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Limit {
        Bounded(usize),
        Named(String),
    }
    match Option::<Limit>::deserialize(deserializer)? {
        Some(Limit::Bounded(limit)) => Ok(Some(limit)),
        Some(Limit::Named(name)) if name == "unlimited" => Ok(None),
        None => Ok(None),
        Some(Limit::Named(_)) => Err(serde::de::Error::custom(
            "expected a nonnegative integer or 'unlimited'",
        )),
    }
}

fn default_absence_encoded_byte_limit() -> Option<usize> {
    Some(64 * 1024 * 1024)
}

fn default_source_retention_limit() -> NonZeroUsize {
    NonZeroUsize::MIN.saturating_add(65_535)
}

fn default_federation_publish_id_limit() -> NonZeroUsize {
    NonZeroUsize::MIN.saturating_add(65_535)
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageHistoryMode {
    #[default]
    CurrentOnly,
    Full,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageKind {
    #[default]
    Redb,
    Memory,
}

fn default_storage_path() -> String {
    "xolotl.db".into()
}
