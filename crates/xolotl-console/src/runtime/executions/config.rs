//! Host policy and bounds for independent execution admission.

use crate::runtime::RuntimeConfigError;
use serde::{Deserialize, Serialize};

// A stored event gains execution identity and sequence when projected into a
// delivery page. Reserve room for that projection and the page envelope so a
// valid retained event remains readable after a query-budget change.
pub(crate) const OUTPUT_EVENT_PROJECTION_RESERVE: usize = 512;
const OUTPUT_PAGE_ENVELOPE_RESERVE: usize = 1024;

/// Admission and retention for explicitly submitted, service-owned executions.
/// Submissions share live host quotas and account ownership.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleExecutionConfig {
    /// Enable independent submissions in addition to request-owned calls.
    pub enabled: bool,
    /// Maximum running executions, including finalization.
    pub max_concurrent: usize,
    /// Maximum running executions for one immutable account instance.
    pub max_concurrent_per_account: usize,
    /// Maximum logical directory entries, not RSS. A record and its associated
    /// accepted root alias charge one entry together; a preparing root lease or
    /// an open-epoch alias whose record was forgotten or expired charges one.
    /// Children and unguarded records each charge one. Admission rejects at the
    /// bound. Preparing leases release on guard drop or epoch close; accepted
    /// aliases release only after both epoch close and record removal. Open
    /// aliases retain retry evidence, without retaining a result slot. Alias
    /// metadata stores a bounded immutable account key, epoch, SHA-256 nonce
    /// hash, fingerprint, and lease or execution reference. A live reservation
    /// also owns a bounded key copy; associated accepted aliases add metadata
    /// to their charged record, not another logical entry.
    pub max_records: usize,
    /// The same logical-entry bound for one full immutable account key,
    /// including its authority. Preparing and retired aliases do not consume
    /// concurrency, result, or output budgets.
    pub max_records_per_account: usize,
    /// Maximum complete logical JSON bytes of owner, operation authority, origin,
    /// retained candidate Capabilities and actual budget per record, not RSS.
    /// Also bounds the actual combined UTF-8 bytes of authority and account
    /// identifiers before copying root alias or reservation owner keys. Nonces
    /// contain 1..=256 strict ASCII alphanumeric or `-_.:` bytes; only their
    /// fixed-size SHA-256 hashes are retained, never sessions or display names.
    /// Before acceptance, root alias metadata separately must fit this same
    /// bound: key and execution-reference UTF-8 bytes plus nonce/fingerprint
    /// hashes and epoch/sequence integers. This check precedes reference copies;
    /// it excludes allocator and container overhead and does not bound RSS.
    pub max_authority_bytes: usize,
    /// Maximum lossless protobuf bytes retained for one result.
    pub max_result_bytes: usize,
    /// Maximum encoded bytes retained for one independent finalization projection.
    pub max_finalization_bytes: usize,
    /// Maximum encoded bytes in one retained Stream event before delivery projection.
    pub max_output_event_bytes: usize,
    /// Maximum encoded bytes in one output observation page, independent of
    /// the State/Fact query page budget. Must fit one maximum-sized event.
    pub max_output_page_bytes: usize,
    /// Maximum events retained for one volatile Stream execution, including terminal.
    pub max_output_events: usize,
    /// Maximum charged bytes retained for one volatile Stream execution.
    pub max_output_bytes_per_execution: usize,
    /// Total admission-reserved Stream log bytes across active and retained executions.
    pub max_output_bytes_total: usize,
    /// Terminal records become inaccessible after this many milliseconds.
    /// Expired records remain internal evidence until cleanup and the source's
    /// receipt dependencies end.
    pub retention_ms: u64,
    /// Maximum wait for lifecycle finalization after the execution body stops.
    pub cleanup_timeout_ms: u64,
    /// Interval between live authority checks.
    pub authority_poll_ms: u64,
    /// Maximum time for one account-authority check, independent of poll frequency.
    pub authority_timeout_ms: u64,
}

impl Default for ConsoleExecutionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_concurrent: 32,
            max_concurrent_per_account: 8,
            max_records: 256,
            max_records_per_account: 64,
            max_authority_bytes: 32 * 1024,
            max_result_bytes: 256 * 1024,
            max_finalization_bytes: 64 * 1024,
            max_output_event_bytes: 16 * 1024,
            max_output_page_bytes: 128 * 1024,
            max_output_events: 1024,
            max_output_bytes_per_execution: 1024 * 1024,
            max_output_bytes_total: 32 * 1024 * 1024,
            retention_ms: 15 * 60 * 1000,
            cleanup_timeout_ms: 5_000,
            authority_poll_ms: 1_000,
            authority_timeout_ms: 1_000,
        }
    }
}

impl ConsoleExecutionConfig {
    pub(crate) fn delivery_event_limit(&self) -> usize {
        self.max_output_event_bytes
            .saturating_add(OUTPUT_EVENT_PROJECTION_RESERVE)
    }

    pub(in crate::runtime) fn validate(&self) -> Result<(), RuntimeConfigError> {
        for (name, value, max) in [
            (
                "executions.max_concurrent",
                self.max_concurrent as u64,
                1024,
            ),
            (
                "executions.max_concurrent_per_account",
                self.max_concurrent_per_account as u64,
                1024,
            ),
            ("executions.max_records", self.max_records as u64, 16_384),
            (
                "executions.max_records_per_account",
                self.max_records_per_account as u64,
                16_384,
            ),
            (
                "executions.max_authority_bytes",
                self.max_authority_bytes as u64,
                1024 * 1024,
            ),
            (
                "executions.max_result_bytes",
                self.max_result_bytes as u64,
                4 * 1024 * 1024,
            ),
            (
                "executions.max_output_event_bytes",
                self.max_output_event_bytes as u64,
                256 * 1024,
            ),
            (
                "executions.max_finalization_bytes",
                self.max_finalization_bytes as u64,
                4 * 1024 * 1024,
            ),
            (
                "executions.max_output_page_bytes",
                self.max_output_page_bytes as u64,
                1024 * 1024,
            ),
            (
                "executions.max_output_events",
                self.max_output_events as u64,
                65_536,
            ),
            (
                "executions.max_output_bytes_per_execution",
                self.max_output_bytes_per_execution as u64,
                16 * 1024 * 1024,
            ),
            (
                "executions.max_output_bytes_total",
                self.max_output_bytes_total as u64,
                256 * 1024 * 1024,
            ),
            (
                "executions.retention_ms",
                self.retention_ms,
                24 * 60 * 60 * 1000,
            ),
            (
                "executions.cleanup_timeout_ms",
                self.cleanup_timeout_ms,
                60_000,
            ),
            (
                "executions.authority_poll_ms",
                self.authority_poll_ms,
                60_000,
            ),
            (
                "executions.authority_timeout_ms",
                self.authority_timeout_ms,
                60_000,
            ),
        ] {
            if value == 0 || value > max {
                return Err(RuntimeConfigError::Limit(name));
            }
        }
        if self.max_concurrent_per_account > self.max_concurrent
            || self.max_concurrent > self.max_records
            || self.max_records_per_account > self.max_records
            || self.max_concurrent_per_account > self.max_records_per_account
        {
            return Err(RuntimeConfigError::Limit("executions.concurrency"));
        }
        if self.max_output_events < 2
            || self.max_output_event_bytes < 1024
            || self.max_output_event_bytes > self.max_output_bytes_per_execution / 2
            || self.max_output_bytes_per_execution > self.max_output_bytes_total
            || self
                .max_output_event_bytes
                .checked_add(OUTPUT_PAGE_ENVELOPE_RESERVE)
                .is_none_or(|minimum| self.max_output_page_bytes < minimum)
        {
            return Err(RuntimeConfigError::Limit("executions.output"));
        }
        if self
            .max_records
            .checked_mul(
                self.max_result_bytes
                    + self.max_finalization_bytes
                    + self.max_authority_bytes
                    // The sidecar owns both UTF-8 bytes and one String header
                    // per retained identity, independently of the result value.
                    + xolotl_types::execution::MAX_UNRESOLVED_OPERATION_TOTAL_BYTES
                    + xolotl_types::execution::MAX_UNRESOLVED_OPERATION_IDS
                        * std::mem::size_of::<String>(),
            )
            .and_then(|bytes| bytes.checked_add(self.max_output_bytes_total))
            .is_none_or(|bytes| bytes > 256 * 1024 * 1024)
        {
            return Err(RuntimeConfigError::Limit("executions.total_record_bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_page_can_hold_a_maximum_sized_event_after_projection() {
        let mut config = ConsoleExecutionConfig::default();
        config.max_output_page_bytes =
            config.max_output_event_bytes + OUTPUT_PAGE_ENVELOPE_RESERVE - 1;
        assert!(matches!(
            config.validate(),
            Err(RuntimeConfigError::Limit("executions.output"))
        ));
        config.max_output_page_bytes += 1;
        assert!(config.validate().is_ok());
    }
}
