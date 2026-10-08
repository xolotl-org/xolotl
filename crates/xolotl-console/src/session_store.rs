//! Private Console session aggregates, independent of State and its history.
//!
//! A storage domain has one immutable policy, shared by every Console host using
//! it. All retained rows (including expired rows) consume a slot until deletion.
//! Creation checks the fixed SID first, then atomically evicts at most one row:
//! the oldest `(issued_at, SID)` of the account at its limit. An account eviction
//! frees the domain slot as well. Otherwise a full domain rejects creation;
//! unrelated accounts are never evicted to admit a new session.
//! No expiry sweep is a prerequisite for admission. Updates and conditional
//! deletion must compare the complete observed aggregate in the same transaction
//! that updates SID, account issuance, global issuance and expiry indexes.
//!
//! Rows are limited to 256 KiB of encoded aggregate plus SID. Maintenance consumes
//! at most 16 rows and 256 KiB per invocation. Page budgets limit both examined
//! rows and bytes, not just live output; they are not RSS guarantees. Unknown
//! commits must be reported distinctly: callers resolve creation only by reading
//! the original SID and matching verifier, authority and liveness, never by
//! generating another SID. Stores retain neither bearer secrets nor State history.
//!
//! Hosts must drive [`ConsoleSessionStore::maintain`] at a bounded cadence;
//! creation never performs an expiry sweep. Schedule at most one batch per tick
//! and skip missed ticks rather than building a catch-up queue. Choose cadence
//! and capacities for the workload: reclamation is limited to 16 rows/256 KiB
//! per batch, and expired rows can exhaust admission until actually reclaimed.

use crate::auth::SessionRecord;
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

mod memory;
pub use memory::MemoryConsoleSessionStore;

/// Default number of retained sessions allowed per account instance.
pub const DEFAULT_MAX_SESSIONS_PER_ACCOUNT: usize = 5;
/// Default total number of retained sessions allowed globally.
pub const DEFAULT_GLOBAL_SESSION_LIMIT: usize = 10_000;
/// Minimum accepted per-account session limit.
pub const MIN_MAX_SESSIONS_PER_ACCOUNT: usize = 1;
/// Hard upper bound for per-account session limit.
pub const HARD_MAX_SESSIONS_PER_ACCOUNT: usize = 1_000;
/// Minimum accepted global session limit.
pub const MIN_GLOBAL_SESSION_LIMIT: usize = 1;
/// Hard upper bound for global session limit.
pub const HARD_GLOBAL_SESSION_LIMIT: usize = 100_000;
/// Maximum retained encoded row size, including its SID.
pub const MAX_SESSION_ROW_BYTES: usize = 256 * 1024;
/// Maximum rows consumed by one expiry-maintenance transaction.
pub const MAINTENANCE_ROWS: usize = 16;
/// Maximum encoded bytes consumed by one expiry-maintenance transaction.
pub const MAINTENANCE_BYTES: usize = 256 * 1024;

/// Immutable hard capacities of one session-storage domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsoleSessionPolicy {
    per_account: usize,
    domain: usize,
}

impl Default for ConsoleSessionPolicy {
    fn default() -> Self {
        Self {
            per_account: DEFAULT_MAX_SESSIONS_PER_ACCOUNT,
            domain: DEFAULT_GLOBAL_SESSION_LIMIT,
        }
    }
}

impl ConsoleSessionPolicy {
    /// Reject zero or unsupported capacities rather than silently clamping them.
    pub fn new(per_account: usize, domain: usize) -> Result<Self, SessionStoreError> {
        if !(MIN_MAX_SESSIONS_PER_ACCOUNT..=HARD_MAX_SESSIONS_PER_ACCOUNT).contains(&per_account)
            || !(MIN_GLOBAL_SESSION_LIMIT..=HARD_GLOBAL_SESSION_LIMIT).contains(&domain)
        {
            return Err(SessionStoreError::Rejected(
                "invalid session capacities".into(),
            ));
        }
        Ok(Self {
            per_account,
            domain,
        })
    }
    /// Maximum retained rows for each authority/account instance.
    pub fn per_account(self) -> usize {
        self.per_account
    }
    /// Maximum retained rows in the entire storage domain.
    pub fn domain(self) -> usize {
        self.domain
    }
}

/// Opaque, validated, typed session aggregate. Debug never reveals its verifier.
#[derive(Clone)]
pub struct ConsoleSession {
    pub(crate) record: SessionRecord,
}

impl std::fmt::Debug for ConsoleSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsoleSession")
            .finish_non_exhaustive()
    }
}

impl ConsoleSession {
    pub(crate) fn from_record(mut record: SessionRecord) -> Self {
        record.persisted = None;
        Self { record }
    }
    /// SID used by the primary index.
    pub fn sid(&self) -> &str {
        &self.record.sid
    }
    /// Stable authority/account index key (not the display name).
    pub fn account(&self) -> (&str, &str) {
        (&self.record.authority_id, &self.record.account_id)
    }
    /// Immutable issuance timestamp used for deterministic eviction.
    pub fn issued_at(&self) -> i64 {
        self.record.issued_at
    }
    /// Earliest absolute or idle expiry, used by incremental maintenance.
    pub fn expires_at(&self) -> i64 {
        self.record.expires_at.min(self.record.idle_expires_at)
    }
    /// Lossless storage encoding, bounded together with the SID to 256 KiB.
    pub fn encode(&self) -> Result<Vec<u8>, SessionStoreError> {
        let bytes = serde_json::to_vec(&self.record.to_value()).map_err(storage_error)?;
        if bytes.len().saturating_add(self.sid().len()) > MAX_SESSION_ROW_BYTES {
            return Err(SessionStoreError::Rejected(
                "session row exceeds 256 KiB".into(),
            ));
        }
        Ok(bytes)
    }
    /// Validate a persisted aggregate before allowing authentication to use it.
    pub fn decode(sid: &str, bytes: &[u8]) -> Result<Self, SessionStoreError> {
        if bytes.len().saturating_add(sid.len()) > MAX_SESSION_ROW_BYTES {
            return Err(SessionStoreError::Rejected(
                "session row exceeds 256 KiB".into(),
            ));
        }
        crate::auth::validate_session_id(sid).map_err(storage_error)?;
        let value = serde_json::from_slice(bytes).map_err(storage_error)?;
        let record = SessionRecord::from_value(sid, &value).map_err(storage_error)?;
        Ok(Self::from_record(record))
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        self.record == other.record
    }
}

/// Failure before commit, comparison loss, or an accepted uncertain commit.
#[derive(Debug, thiserror::Error)]
pub enum SessionStoreError {
    /// No mutation committed; the input or frozen domain policy was rejected.
    #[error("session storage rejected: {0}")]
    Rejected(String),
    /// SID already exists or the complete observed row no longer matches.
    #[error("session storage comparison failed")]
    Conflict,
    /// Storage failed before a commit was attempted.
    #[error("session storage failed: {0}")]
    Storage(String),
    /// Commit was attempted or work accepted, but its result is not known.
    #[error("session storage commit unknown: {0}")]
    Unknown(String),
}

pub(crate) fn storage_error(error: impl std::fmt::Display) -> SessionStoreError {
    SessionStoreError::Storage(error.to_string())
}

/// Independent candidate/output and encoded-input budgets for one page.
#[derive(Clone, Copy, Debug)]
pub struct SessionPageLimits {
    /// Maximum rows examined, including expired rows.
    pub rows: usize,
    /// Maximum aggregate and SID bytes consumed.
    pub bytes: usize,
}

/// SID-ordered bounded page; resume strictly after `next` when it is present.
#[derive(Debug)]
pub struct SessionStorePage {
    /// Retained aggregates, including expired aggregates.
    pub entries: Vec<ConsoleSession>,
    /// Last consumed SID; `None` means the page reached the end.
    pub next: Option<String>,
}

/// Atomic storage-domain operations. Implementations must share capacities
/// across handles and persist policy/accounting across reopen when durable.
#[async_trait]
pub trait ConsoleSessionStore: Send + Sync {
    /// Frozen policy of this storage domain.
    fn policy(&self) -> ConsoleSessionPolicy;
    /// Read one original SID without renewing liveness.
    async fn get(&self, sid: &str) -> Result<Option<ConsoleSession>, SessionStoreError>;
    /// Atomically check SID, select at most one eviction and insert the row.
    /// Rejected/duplicate creates must not evict anything.
    async fn create(&self, session: ConsoleSession) -> Result<(), SessionStoreError>;
    /// Replace exactly the observed row. Never insert after deletion.
    async fn compare_replace(
        &self,
        expected: ConsoleSession,
        session: ConsoleSession,
    ) -> Result<(), SessionStoreError>;
    /// Delete a SID, optionally only if its complete observed aggregate matches.
    async fn delete(
        &self,
        sid: &str,
        expected: Option<ConsoleSession>,
    ) -> Result<(), SessionStoreError>;
    /// Consume a bounded SID-ordered page. Invalid cursors and zero budgets fail.
    async fn list(
        &self,
        after: Option<&str>,
        limits: SessionPageLimits,
    ) -> Result<SessionStorePage, SessionStoreError>;
    /// Delete at most the maintenance row/byte budget for one account. Hosts may
    /// repeat pages; each transaction uses the account index, never a domain scan.
    async fn revoke_account(
        &self,
        authority: &str,
        account: &str,
    ) -> Result<usize, SessionStoreError>;
    /// Delete expired rows by the expiry index, at most 16 rows/256 KiB.
    async fn maintain(&self, now: i64) -> Result<usize, SessionStoreError>;
}
