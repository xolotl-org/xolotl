use std::num::NonZeroUsize;

/// Historical state retained by an in-memory backend.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MemoryHistory {
    /// Retain every mutation for history pages and historical `read_at` queries.
    /// This is unbounded and retains shared value snapshots in the history.
    Full,
    /// Retain current values and provenance only. The assembled [`crate::Backend`]
    /// omits its history capability; historical queries return `MissingCapability`.
    /// Direct `read_at(path, 0)` still reads the current value.
    /// Notifications remain ordered, but no historical timestamps are produced.
    #[default]
    Disabled,
}

/// Independent storage and delivery choices for [`super::InMemoryBackend`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InMemoryOptions {
    /// One uses an inline map and shared lock with no shard allocation. Larger
    /// counts allocate that many padded map locks for concurrent point reads.
    /// Writes remain serialized; prefix reads capture one consistent snapshot.
    /// More shards cost memory and do not help readers of the same key.
    pub read_shards: NonZeroUsize,
    /// Historical query support, independent of the number of read shards.
    pub history: MemoryHistory,
    /// Maximum pending notifications and per-subscription broadcast capacity.
    /// A full pending queue rejects matching writes before changing state.
    /// This counts events, not payload bytes; slow receivers can still lag.
    /// Must not exceed [`Self::MAX_NOTIFICATION_CAPACITY`].
    pub notification_capacity: NonZeroUsize,
    /// Maximum retained ordered Source stream positions across this storage
    /// owner. Existing streams may advance when the limit is reached; new
    /// identities are refused before their first event is committed.
    pub source_stream_limit: NonZeroUsize,
    /// Maximum retained Source event/receipt pairs plus rate records across
    /// all scopes. Replacements reuse slots; maintenance returns them.
    /// Per-record bounds remain separate; this is not an RSS limit.
    pub source_retention_limit: NonZeroUsize,
    /// Transactional retained current absence limits, independent of history.
    pub absence_limits: crate::AbsenceLimits,
}

impl InMemoryOptions {
    /// Largest supported notification queue: 1,048,576 events per subscription.
    /// This keeps broadcast buffer sizes representable independently of Tokio's
    /// private slot layout. It is not a payload byte limit or an allocation guarantee.
    pub const MAX_NOTIFICATION_CAPACITY: usize = 1 << 20;
    /// Largest selectable retained Source stream position limit.
    pub const MAX_SOURCE_STREAM_LIMIT: usize = 65_536;
}

impl Default for InMemoryOptions {
    fn default() -> Self {
        Self {
            read_shards: NonZeroUsize::MIN,
            history: MemoryHistory::Disabled,
            notification_capacity: NonZeroUsize::MIN.saturating_add(255),
            source_stream_limit: NonZeroUsize::MIN.saturating_add(4095),
            source_retention_limit: NonZeroUsize::MIN.saturating_add(65_535),
            absence_limits: crate::AbsenceLimits::default(),
        }
    }
}
