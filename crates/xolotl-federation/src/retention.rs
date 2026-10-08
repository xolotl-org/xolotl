//! Explicit, bounded deletion of delivery payloads. Positions are immutable
//! digest anchors; retirement never changes a stream's head or a receiver's
//! committed progress.

use crate::{FederationError, FederationNodeId, Position, StreamRef, SubscriptionRef};

/// Maximum records removed by one explicit maintenance call.
pub const MAX_RETIRE_RECORDS: usize = 256;
/// Maximum payload bytes removed by one explicit maintenance call.
pub const MAX_RETIRE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum explicit replica members for one publisher-owned stream.
pub const MAX_REPLICA_MEMBERS: usize = 64;
/// Maximum time-limited retention commitment, measured from enrollment or renewal.
pub const MAX_REPLICA_LEASE_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Duration of an explicit replica's publisher-side retention commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplicaRetentionTerm {
    /// Retain unconfirmed history until an operator explicitly retires the member.
    Permanent,
    /// Retain unconfirmed history until this exclusive Unix-millisecond deadline.
    /// Expiry must be committed before it can release the retention constraint.
    LeaseUntilMs(u64),
}

/// Explicit opt-in that binds one replica node to one publisher subscription.
/// A normal subscription, even with ACKs, is not a replica commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplicaMemberSpec {
    /// Publisher-owned stream whose history is protected.
    pub stream: StreamRef,
    /// Replica node that owns the bound node-self subscription.
    pub member: FederationNodeId,
    /// Exact publisher-side subscription providing verified receipt watermarks.
    pub subscription: SubscriptionRef,
    /// Permanent or explicitly time-limited retention promise.
    pub term: ReplicaRetentionTerm,
}

/// Durable member state and its current publisher-confirmed receipt frontier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplicaMemberView {
    /// Immutable stream, member and bound subscription, with current term.
    pub spec: ReplicaMemberSpec,
    /// Compare-and-swap revision, including retirement and re-enrollment.
    pub revision: u64,
    /// Open's excluded-history baseline, if it has one.
    pub baseline: Option<Position>,
    /// Highest receipt committed by the bound publisher subscription.
    pub acknowledged: Option<Position>,
    /// Highest publisher-confirmed sealed snapshot plus contiguous durable
    /// suffix coverage, kept separate from ordinary inbox acknowledgements
    /// and application projection. Missing prefix events were not accepted.
    pub snapshot_covered: Option<Position>,
    /// Whether the commitment was explicitly ended or its lease expiry committed.
    pub retired: bool,
}

/// Durable publisher port for explicit replica membership and safe history removal.
/// Implementations must decide membership, confirmed ACKs, lease expiry, snapshot
/// offer pins and payload deletion within one serialization boundary.
pub trait FederationReplicaRetentionStore: Send + Sync {
    /// Return the publisher node owned by this store.
    fn local_node(&self) -> FederationNodeId;

    /// Enroll a member against an exact live node-self subscription. `None`
    /// creates a new row; `Some(revision)` re-enrolls a retired row only.
    fn join_replica(
        &self,
        spec: ReplicaMemberSpec,
        expected_revision: Option<u64>,
        now_ms: u64,
    ) -> Result<ReplicaMemberView, FederationError>;

    /// Extend an unexpired lease or upgrade it to permanent. A permanent
    /// promise cannot be shortened or converted back into a lease.
    fn extend_replica(
        &self,
        stream: StreamRef,
        member: FederationNodeId,
        expected_revision: u64,
        term: ReplicaRetentionTerm,
        now_ms: u64,
    ) -> Result<ReplicaMemberView, FederationError>;

    /// End an exact commitment with a CAS revision, even after peer revocation.
    fn retire_replica(
        &self,
        stream: StreamRef,
        member: FederationNodeId,
        expected_revision: u64,
        now_ms: u64,
    ) -> Result<ReplicaMemberView, FederationError>;

    /// Inspect one member, including its current bound subscription ACK.
    fn replica_member(
        &self,
        stream: StreamRef,
        member: FederationNodeId,
    ) -> Result<Option<ReplicaMemberView>, FederationError>;

    /// Return at most `MAX_REPLICA_MEMBERS` entries after an exclusive member ID.
    fn scan_replica_members(
        &self,
        stream: StreamRef,
        after: Option<FederationNodeId>,
        max: usize,
    ) -> Result<Vec<ReplicaMemberView>, FederationError>;

    /// Mark expired leases and remove only a confirmed, bounded contiguous
    /// prefix. Permanent members never expire. A missing commitment does not
    /// imply any subscriber accepted the removed records.
    fn retire_replica_safe_history(
        &self,
        stream: StreamRef,
        now_ms: u64,
        max_records: usize,
    ) -> Result<PublishedRetirement, FederationError>;
}

/// Bounded publisher-log deletion result, retaining a digest-only cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedRetirement {
    /// Stream whose old payloads were removed.
    pub stream: StreamRef,
    /// Immutable committed head; retirement does not move it.
    pub head: Option<Position>,
    /// Earliest record still available. The immediately preceding position is
    /// retained as a digest-only cursor anchor.
    pub minimum_available: u64,
    /// Highest position whose payload was deleted in this operation.
    pub retired_through: Option<Position>,
    /// Number of records physically removed in this operation.
    pub removed: usize,
}

/// Bounded inbox deletion result after durable application projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InboxRetirement {
    /// Local receiver subscription whose projected payloads were removed.
    pub subscription: SubscriptionRef,
    /// Highest position durably accepted into this inbox.
    pub received: Option<Position>,
    /// Highest position committed by the application projector.
    pub projected: Option<Position>,
    /// Digest-only anchor for the latest deleted, already projected record.
    pub retired_through: Option<Position>,
    /// Number of inbox records physically removed in this operation.
    pub removed: usize,
}
