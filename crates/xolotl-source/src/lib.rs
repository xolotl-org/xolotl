#![forbid(unsafe_code)]
#![no_std]

//! A Source-specific commit boundary. Its implementation owns event-id
//! decisions, sequence and rate state, and commit evidence in the same
//! atomic domain as the declared State sink. These contracts do not grant
//! a general multi-key State transaction to callers.

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use core::{fmt, future::Future, num::NonZeroUsize, pin::Pin};
use serde::{Deserialize, Serialize};
use xolotl_types::{
    Path, TaintSet, Value,
    external::{EventSource, ExternalInstallationDef, SourceRateLimit, StreamCapacity},
};

/// A host-generated, 128-bit identity for one attempt to commit an event.
/// It is never read from a Source frame.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SourceClaimId([u8; 16]);

impl SourceClaimId {
    /// Construct an identity from host-generated entropy.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact bytes used in private storage keys.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for SourceClaimId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The accepted event and the exact attempt whose result is being inspected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceClaim<'a> {
    /// Authoritatively selected installation.
    pub installation_id: &'a str,
    /// Authoritatively selected Source projection.
    pub projection_id: &'a str,
    /// Storage-issued incarnation of this Source projection. Zero is invalid.
    pub scope_epoch: u64,
    /// Ordered-stream incarnation for this event. `None` denotes an
    /// unordered event; an ordered commit must supply its active stream epoch.
    pub stream_epoch: Option<u64>,
    /// Source-provided id after Gateway validation.
    pub event_id: &'a str,
    /// Host-generated attempt identity.
    pub claim_id: SourceClaimId,
}

/// Optional stream-local position. A successful commit advances exactly one
/// position, in the same transaction that appends the payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceStreamPosition<'a> {
    /// Stream-local id validated by the Gateway.
    pub stream_id: &'a str,
    /// Storage-issued active incarnation of this stream. Zero is invalid.
    pub stream_epoch: u64,
    /// Sequence required to be the previous committed sequence plus one.
    pub seq: u64,
}

/// One trusted host request to atomically admit a Source event.
///
/// The payload and declaration are borrowed: an implementation only retains
/// the parts needed for a committed sink value and private receipt. It must
/// decide event id, sequence, rate and capacity against one serializable view.
pub struct SourceCommit<'a> {
    /// Exact event and attempt identity.
    pub claim: SourceClaim<'a>,
    /// Documentary host receipt time, not admission or expiry time.
    pub received_at_ms: i64,
    /// Trusted host clock sampled once after acquiring the commit lock or
    /// transaction. Use the same clock for maintenance. Neither receipt time
    /// nor a Source timestamp may substitute for this decision time.
    pub decision_clock: Arc<dyn SourceClock>,
    /// Retention interval beginning at serialized decision time, fixed for
    /// this accepted event; changing host configuration later does not alter
    /// an existing decision's expiry.
    pub dedupe_window_ms: u64,
    /// Destination declared by the admitted Source projection.
    pub sink: &'a Path,
    /// Declared capacity and overflow policy.
    pub capacity: &'a StreamCapacity,
    /// Declared bound for this individual inline payload. The commit owner
    /// measures the encoded payload and enforces it before changing state;
    /// backends also use it with `max_events` to bound sink residency.
    pub max_inline_payload_bytes: usize,
    /// Already schema-checked payload.
    pub payload: &'a Value,
    /// Daemon-assigned inbound provenance.
    pub taint: &'a TaintSet,
    /// Optional ordered position; stream id and sequence are all-or-none.
    pub stream: Option<SourceStreamPosition<'a>>,
    /// Optional projection rate rule. Changing its window length starts a new
    /// counting period on the first accepted commit under the new length;
    /// changing only its maximum applies to the existing period immediately.
    pub rate_limit: Option<&'a SourceRateLimit>,
}

/// A deterministic rejection made before the atomic commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCommitRejection {
    /// This projection was retired or the host supplied a stale incarnation.
    ScopeInactive,
    /// The ordered stream was never opened or has been retired.
    StreamInactive,
    /// Another active stream incarnation owns this name.
    StreamEpochMismatch {
        /// Storage-issued epoch of the current active incarnation.
        active_epoch: u64,
    },
    /// A retained event ID names a different stream position or payload.
    /// The original accepted decision remains unchanged.
    EventIdConflict,
    /// The encoded inline payload exceeds the active declaration's limit.
    PayloadTooLarge,
    /// Transaction fields differ from the active Source declaration.
    DeclarationMismatch,
    /// Backpressure threshold was reached.
    Backpressured,
    /// Declared sink capacity was reached.
    CapacityExceeded,
    /// The storage owner's retained event/receipt pairs and rate records
    /// cannot admit this commit's net new records.
    RetentionCapacityExceeded,
    /// The declared sink currently holds a value other than a sequence.
    SinkTypeMismatch,
    /// Projection rate rule was reached.
    RateLimited,
    /// The supplied sequence has already been committed.
    SequenceReplay {
        /// Last committed sequence.
        last: u64,
        /// Requested sequence.
        seq: u64,
    },
    /// A sequence before the supplied one is missing.
    SequenceGap {
        /// Next required sequence.
        expected: u64,
        /// Requested sequence.
        seq: u64,
    },
}

/// A completed atomic admission decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceCommitOutcome {
    /// Sink, metadata and receipt committed together.
    Accepted,
    /// The same stream position and payload were already accepted under this
    /// event ID and remain retained; no second sink append occurred.
    Duplicate,
    /// Deterministic refusal with no side effects.
    Rejected(SourceCommitRejection),
}

/// A failure outside deterministic Source admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceStoreError {
    /// The operation was not accepted, or the backend proved no mutation committed.
    Aborted(String),
    /// An accepted operation lost its result and may have committed. A pure
    /// read can be repeated; mutations follow their port-specific reconciliation
    /// and retry rules. Event commits retain their event id and can inspect a
    /// private receipt through a trusted host or retry that id within the
    /// retention window.
    Indeterminate(String),
}

impl fmt::Display for SourceStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aborted(message) => write!(f, "Source operation aborted: {message}"),
            Self::Indeterminate(message) => {
                write!(f, "Source operation outcome indeterminate: {message}")
            }
        }
    }
}

impl core::error::Error for SourceStoreError {}

/// A boxed host future used only at the dynamically composed boundary.
pub type SourceFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, SourceStoreError>> + Send + 'a>>;

/// Host-owned time source, without a dependency on an execution runtime.
/// Hosts can wrap their existing clock in a closure. Storage samples it only
/// after serialization, and rejects regression below the affected scope's
/// committed time floor; it must not clamp a real rollback into acceptance.
pub trait SourceClock: Send + Sync {
    /// Current trusted host time in milliseconds.
    fn now_millis(&self) -> i64;
}

impl<T: Fn() -> i64 + Send + Sync> SourceClock for T {
    fn now_millis(&self) -> i64 {
        self()
    }
}

/// Commit exactly one Source event. Implementations must share a commit domain
/// with the State sink they mutate. Successful return means the sink, private
/// event-id decision, stream/rate state and receipt are atomically visible
/// together. Persistence across process restart depends on the chosen backend.
/// The implementation must enforce the encoded inline payload limit before
/// writing, even when called outside a Gateway adapter.
/// Deduplication, sliding-rate admission and expiry use one decision-clock
/// sample taken after serialization, never the documentary receipt timestamp.
/// The affected active scope's time floor advances with the accepted event;
/// a lower sample aborts rather than granting quota after maintenance cleanup.
/// A returned `Aborted` must prove no mutation occurred. A write attempted
/// outside this port cannot be treated as part of its atomicity guarantee.
pub trait SourceEventCommit: Send + Sync {
    /// Decide and commit one event against a single serializable view.
    fn commit<'a>(&'a self, request: SourceCommit<'a>) -> SourceFuture<'a, SourceCommitOutcome>;
}

/// An ordered stream selected within one active Source scope. A stream name
/// may be reused only after retirement and then receives a new incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceStreamScope<'a> {
    /// Authoritatively selected installation.
    pub installation_id: &'a str,
    /// Authoritatively selected Source projection.
    pub projection_id: &'a str,
    /// Storage-issued active scope incarnation.
    pub scope_epoch: u64,
    /// Source-provided stream name after Gateway validation.
    pub stream_id: &'a str,
}

/// Stored position of an explicitly opened ordered stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceStreamState {
    /// Storage-issued, globally never-reused stream incarnation.
    pub stream_epoch: u64,
    /// Scope revision compared by the Open request that created this
    /// incarnation. The pair with `open_id` identifies an exact retry.
    pub opened_at_revision: u64,
    /// Zero before its first event; otherwise the last committed sequence.
    pub last_seq: u64,
    /// Source request identity used to recover an Open response that was lost.
    pub open_id: String,
}

/// A serializable view of one stream and its scope-local control revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceStreamSnapshot {
    /// Scope-local control revision returned to compare future opens.
    pub revision: u64,
    /// Current opened stream, or `None` if this name is available.
    pub active: Option<SourceStreamState>,
}

/// Open a stream against the revision returned by `inspect_stream`. Retrying
/// the exact request while it remains active returns its original epoch.
pub struct SourceStreamOpen<'a> {
    /// Active scope and stream name.
    pub stream: SourceStreamScope<'a>,
    /// Source request identity, stable across retries of this exact Open.
    pub open_id: &'a str,
    /// Revision obtained by a prior inspection; a stale request cannot reopen.
    pub expected_revision: u64,
}

/// Close exactly one stream incarnation. Retirement and Source event commits
/// are ordered in the same store domain.
pub struct SourceStreamRetire<'a> {
    /// Active scope and stream name.
    pub stream: SourceStreamScope<'a>,
    /// Exact incarnation to close.
    pub stream_epoch: u64,
}

/// Result of comparing and opening a stream name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceStreamOpenOutcome {
    /// Newly opened or exact `(open_id, expected_revision)` retry.
    Opened(SourceStreamSnapshot),
    /// A different Open request already owns this stream name.
    AlreadyOpen(SourceStreamSnapshot),
    /// The scope control revision advanced since this Open was prepared.
    RevisionConflict {
        /// Current scope revision for a fresh explicit request.
        current_revision: u64,
    },
    /// The storage owner's active or pending retired-scope row quota is full.
    QuotaExceeded,
    /// The supplied scope incarnation is no longer active.
    ScopeInactive,
}

/// Result of retiring an exact stream incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceStreamRetireOutcome {
    /// Closed and released the activity quota at this revision.
    Retired {
        /// New scope control revision.
        revision: u64,
    },
    /// No active row remains; the requested incarnation cannot commit.
    Inactive {
        /// Current scope control revision.
        revision: u64,
    },
    /// Another incarnation now owns the name.
    Stale {
        /// Current active stream incarnation.
        active_epoch: u64,
    },
    /// The supplied scope incarnation is no longer active.
    ScopeInactive,
}

/// Ordered-stream lifecycle capability, separate from event ingestion and
/// installation management. An implementation must co-own Source commits,
/// stream positions, and scope admission in one serializable storage domain.
pub trait SourceStreamLifecycle: Send + Sync {
    /// Inspect an active Source scope. `None` means its epoch is inactive.
    fn inspect_stream<'a>(
        &'a self,
        stream: SourceStreamScope<'a>,
    ) -> SourceFuture<'a, Option<SourceStreamSnapshot>>;

    /// Compare the scope-local revision and reserve one active stream. The
    /// store, never the Source, assigns a globally never-reused stream epoch.
    fn open_stream<'a>(
        &'a self,
        request: SourceStreamOpen<'a>,
    ) -> SourceFuture<'a, SourceStreamOpenOutcome>;

    /// Atomically fence old commits and release the active stream quota.
    fn retire_stream<'a>(
        &'a self,
        request: SourceStreamRetire<'a>,
    ) -> SourceFuture<'a, SourceStreamRetireOutcome>;
}

/// One ingress owner for stream control and event admission. A host should
/// pass this combined facet to its Gateway so those operations cannot be
/// accidentally wired to different storage domains.
pub trait SourceIngress: SourceEventCommit + SourceStreamLifecycle {}

impl<T> SourceIngress for T where T: SourceEventCommit + SourceStreamLifecycle {}

/// A declaration that exceeds the installed Source storage owner's bounds.
/// Structural installation validation remains the declaration owner's job;
/// this error describes the storage profile required for atomic admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceAdmissionError {
    /// The named field is invalid for this storage owner.
    Invalid {
        /// Declaration field rejected by this storage owner.
        field: &'static str,
    },
    /// The named field exceeds this storage owner's maximum.
    LimitExceeded {
        /// Declaration field whose value exceeds the store's bound.
        field: &'static str,
        /// Maximum supported value in the field's declared units.
        max: usize,
    },
}

impl fmt::Display for SourceAdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid { field } => write!(f, "Source {field} is invalid"),
            Self::LimitExceeded { field, max } => {
                write!(f, "Source {field} exceeds maximum {max}")
            }
        }
    }
}

impl core::error::Error for SourceAdmissionError {}

/// Store-specific admission of a Source declaration before an installation is
/// made ready. This synchronous, read-only facet does not grant event commit,
/// maintenance or claim inspection. A custom store may support other bounds.
pub trait SourceDeclarationAdmission: Send + Sync {
    /// Check whether this owner can atomically admit events for the declared
    /// identity and event sink. Callers still validate the declaration's
    /// independent syntax and authorization rules.
    fn validate_source(
        &self,
        installation_id: &str,
        projection_id: &str,
        source: &EventSource,
    ) -> Result<(), SourceAdmissionError>;
}

/// One installation owned by the same atomic domain as its Source scopes.
/// Ordinary State values are never authoritative for this record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalInstallationRecord {
    /// The admitted, versioned declaration used by Ready and management.
    pub definition: ExternalInstallationDef,
    /// Storage-issued incarnation of this installation. It remains stable
    /// across updates and changes only after retirement and reinstallation.
    /// Provider sessions and pairing intents bind it; config versions are reusable.
    pub installation_epoch: u64,
    /// Storage-issued incarnation for each Source projection in the declaration.
    /// Provider projections have no entry.
    pub scope_epochs: BTreeMap<String, u64>,
}

/// Largest JSON-encoded installation record accepted by the built-in memory
/// and redb catalogs. The limit includes the storage-issued epochs as well as
/// the versioned declaration, so listing cannot return unbounded records.
pub const MAX_INSTALLATION_RECORD_BYTES: usize = 1024 * 1024;

/// Atomic-commit fields of an active Source declaration. Schema and policy
/// are evaluated by the Gateway; the storage owner fences fields that affect
/// its transaction against this record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceScopeAdmission {
    /// Storage-issued active incarnation.
    pub epoch: u64,
    /// Scope-local control revision. Opens and retirements increment this
    /// counter; event commits do not, so unrelated streams do not conflict.
    pub stream_revision: u64,
    /// Highest committed admission or maintenance decision time for this
    /// active incarnation. Kept independently of expiring receipts and rate
    /// hits; lower clock samples abort without granting fresh quota. Retiring
    /// or replacing the incarnation releases its floor along with admission.
    #[serde(default)]
    pub decision_time_floor_ms: Option<i64>,
    /// Exact destination for accepted events.
    pub sink: Path,
    /// Current sink capacity and overflow rule.
    pub capacity: StreamCapacity,
    /// Maximum inline payload size for this declaration.
    pub max_inline_payload_bytes: usize,
    /// Declared rate rule, if any.
    pub rate_limit: Option<SourceRateLimit>,
}

impl SourceScopeAdmission {
    /// Capture the fields enforced in the Source commit domain.
    pub fn from_declaration(epoch: u64, source: &EventSource) -> Self {
        Self {
            epoch,
            stream_revision: 0,
            decision_time_floor_ms: None,
            sink: source.sink.clone(),
            capacity: source.capacity.clone(),
            max_inline_payload_bytes: source.max_inline_payload_bytes,
            rate_limit: source.rate_limit.clone(),
        }
    }

    /// Check a proposed commit without copying its payload or declaration.
    pub fn matches_commit(&self, request: &SourceCommit<'_>) -> bool {
        self.epoch == request.claim.scope_epoch
            && self.sink == *request.sink
            && self.capacity == *request.capacity
            && self.max_inline_payload_bytes == request.max_inline_payload_bytes
            && self.rate_limit.as_ref() == request.rate_limit
    }
}

impl ExternalInstallationRecord {
    /// The exact catalog revision for conditional updates and retirement.
    pub fn revision(&self) -> ExternalInstallationRevision {
        ExternalInstallationRevision {
            installation_epoch: self.installation_epoch,
            version: self.definition.version,
        }
    }

    /// Return the active epoch for one Source projection, if present.
    pub fn scope_epoch(&self, projection_id: &str) -> Option<u64> {
        self.scope_epochs.get(projection_id).copied()
    }
}

/// One installation incarnation and its declaration revision. A version alone
/// can be reused after retirement and must never authorize a later incarnation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalInstallationRevision {
    /// Storage-issued installation incarnation.
    pub installation_epoch: u64,
    /// Version within that incarnation.
    pub version: u64,
}

/// A conditional installation mutation decided in the Source commit domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExternalInstallationMutation {
    /// The new authoritative record, or `None` after retirement.
    Applied(Option<ExternalInstallationRecord>),
    /// The comparison failed without changing the catalog or any scope.
    Conflict {
        /// The revision observed at the mutation's serialization point.
        current: Option<ExternalInstallationRevision>,
    },
}

/// Typed installation catalog co-owned with Source commit state.
///
/// `compare_install` assigns declaration version 1 on creation and increments
/// the compared version on replacement. Updates and retirement compare the
/// complete `(installation_epoch, version)` pair, so a stale request cannot
/// mutate a later installation of the same id. It assigns fresh, never-reused epochs
/// to the installation on creation, retains it on update, and assigns fresh
/// epochs to all Source projections on every install/replace. An update is
/// therefore a new Source activation. `compare_retire` fences old commits in
/// the same lock or transaction that removes the declaration. Reads are from
/// this catalog, never from a separately writable State mirror.
/// The built-in catalogs admit records only up to
/// [`MAX_INSTALLATION_RECORD_BYTES`] in their JSON storage encoding.
pub trait ExternalInstallationAuthority: Send + Sync {
    /// Load one authoritative installation; a retired id returns `None`.
    fn load_installation<'a>(
        &'a self,
        id: &'a str,
    ) -> SourceFuture<'a, Option<ExternalInstallationRecord>>;

    /// List records strictly after `after_id`, in installation-id order.
    fn list_installations<'a>(
        &'a self,
        after_id: Option<&'a str>,
        limit: NonZeroUsize,
    ) -> SourceFuture<'a, Vec<ExternalInstallationRecord>>;

    /// Create if `expected` is `None`, or replace exactly that incarnation and version.
    fn compare_install<'a>(
        &'a self,
        definition: ExternalInstallationDef,
        expected: Option<ExternalInstallationRevision>,
    ) -> SourceFuture<'a, ExternalInstallationMutation>;

    /// Retire exactly the expected installation incarnation and version.
    fn compare_retire<'a>(
        &'a self,
        id: &'a str,
        expected: ExternalInstallationRevision,
    ) -> SourceFuture<'a, ExternalInstallationMutation>;
}

/// Durable evidence that a particular attempt committed with its declared
/// sink. It remains meaningful even when DropOldest later removes the payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceReceipt {
    /// Installation selected by the daemon.
    pub installation_id: String,
    /// Projection selected by the daemon.
    pub projection_id: String,
    /// Scope incarnation that accepted this event.
    pub scope_epoch: u64,
    /// `None` for unordered events, otherwise the accepted stream incarnation.
    pub stream_epoch: Option<u64>,
    /// Event identity supplied by the Source.
    pub event_id: String,
    /// Attempt identity generated by the daemon.
    pub claim_id: SourceClaimId,
    /// Sink committed by the attempt.
    pub sink: Path,
    /// Daemon receipt time committed with the event.
    pub received_at_ms: i64,
}

/// An evidence lookup cannot use absence to assert that an unknown attempt
/// never committed: a record may have expired or a remote commit may still be
/// in flight. No release/replay authorization follows from `Unproven`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceClaimEvidence {
    /// The exact claim and sink were committed atomically.
    Committed(SourceReceipt),
    /// No durable receipt was found; this is not a negative commit proof.
    Unproven,
}

/// A privileged evidence inspection, never carried by Source v1 frames.
/// The host authorizes disclosure before constructing this exact-identity
/// request and revalidates current authority before delivering its result.
pub struct SourceEvidenceInspection<'a> {
    /// Claim being investigated.
    pub claim: SourceClaim<'a>,
}

/// Privileged lookup of the decision currently retained for one event ID.
///
/// Unlike an exact claim lookup, this request can recover the accepted claim
/// ID after an incident log is lost. A missing result does not prove any
/// attempt was rolled back: the decision may have expired or been cleaned.
pub struct SourceEventDecisionInspection<'a> {
    /// Installation selected by the trusted host.
    pub installation_id: &'a str,
    /// Source projection selected by the trusted host.
    pub projection_id: &'a str,
    /// Exact scope incarnation to inspect, including retired scopes.
    pub scope_epoch: u64,
    /// `None` selects unordered events; `Some(nonzero)` selects one ordered
    /// stream incarnation, so reused event IDs are unambiguous.
    pub stream_epoch: Option<u64>,
    /// Source event ID after Gateway validation.
    pub event_id: &'a str,
}

/// Privileged, read-only evidence lookup from one consistent storage view.
/// Install this port only in trusted host management code. Reads neither
/// mutate Source or State nor depend on an inspection audit write. Any
/// observation/audit requirement belongs to the host's disclosure boundary;
/// it does not require a second private Source audit. Uncertain storage must
/// reject reconciliation reads until its recovery owner has reopened it.
pub trait SourceClaimInspection: Send + Sync {
    /// Return the exact claim's evidence, including retired scope identities.
    fn inspect<'a>(
        &'a self,
        request: SourceEvidenceInspection<'a>,
    ) -> SourceFuture<'a, SourceClaimEvidence>;

    /// Return the accepted receipt for a retained event decision.
    /// This reveals only the current decision for the exact scope and event ID;
    /// it does not enumerate attempts or establish a negative commit proof.
    fn inspect_event<'a>(
        &'a self,
        request: SourceEventDecisionInspection<'a>,
    ) -> SourceFuture<'a, SourceClaimEvidence>;
}

/// One bounded, resumable cleanup step across accepted event ids, their
/// receipts, idle projection rate records, and stream positions belonging to
/// retired Source scopes. Active stream positions are never time-expired.
pub struct SourceMaintenance {
    /// Trusted host clock sampled once after acquiring the maintenance lock
    /// or transaction, from the same time domain as event admission. Cleanup
    /// advances affected scopes' time floors atomically with removing evidence
    /// or rate state, so a later rollback cannot relax admission.
    pub decision_clock: Arc<dyn SourceClock>,
    /// Maximum event-id, rate and retired-scope stream rows examined, combined.
    pub limit: NonZeroUsize,
}

/// Largest private Source cleanup step accepted by the built-in backends.
pub const MAX_MAINTENANCE_BATCH: usize = 64;

/// Maximum declared current sink payload budget for one Source projection.
/// It does not bound State history or redb's retained physical pages.
pub const MAX_DECLARED_SINK_BYTES: usize = 64 * 1024 * 1024;

/// Maximum number of current sink entries retained by the built-in adapters.
pub const MAX_SINK_EVENTS: usize = 65_536;

/// Largest inline Source payload accepted by the built-in adapters.
pub const MAX_INLINE_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Largest host-validated Source identity segment.
pub const MAX_ID_BYTES: usize = 256;

/// Largest canonical State sink path accepted by Source adapters.
pub const MAX_SINK_PATH_BYTES: usize = 4096;

/// Maximum encoded private receipt row. This exceeds the
/// worst-case JSON encoding of three 256-byte identities (including escapes),
/// a 4096-byte sink path, a claim id and an extreme signed timestamp.
pub const MAX_RECEIPT_BYTES: usize = 16 * 1024;

/// Maximum count retained in a private sliding-rate record.
pub const MAX_RATE_HITS: usize = 65_536;

/// Built-in memory and redb Source storage admission profile. It is separate
/// from the generic declaration's syntax checks and makes backend-specific
/// resource limits visible before the first event arrives.
pub fn validate_builtin_source(
    installation_id: &str,
    projection_id: &str,
    source: &EventSource,
) -> Result<(), SourceAdmissionError> {
    if installation_id.is_empty() {
        return Err(SourceAdmissionError::Invalid {
            field: "installation_id",
        });
    }
    if installation_id.len() > MAX_ID_BYTES {
        return Err(SourceAdmissionError::LimitExceeded {
            field: "installation_id bytes",
            max: MAX_ID_BYTES,
        });
    }
    if projection_id.is_empty() {
        return Err(SourceAdmissionError::Invalid {
            field: "projection_id",
        });
    }
    if projection_id.len() > MAX_ID_BYTES {
        return Err(SourceAdmissionError::LimitExceeded {
            field: "projection_id bytes",
            max: MAX_ID_BYTES,
        });
    }
    if source.sink.cluster().is_some()
        || source.sink.scheme() != "state"
        || !source.sink.is_concrete()
    {
        return Err(SourceAdmissionError::Invalid { field: "sink path" });
    }
    if source
        .sink
        .canonical_len()
        .is_none_or(|len| len > MAX_SINK_PATH_BYTES)
    {
        return Err(SourceAdmissionError::LimitExceeded {
            field: "sink path bytes",
            max: MAX_SINK_PATH_BYTES,
        });
    }
    if source.max_inline_payload_bytes == 0 {
        return Err(SourceAdmissionError::Invalid {
            field: "inline payload byte budget",
        });
    }
    if source.max_inline_payload_bytes > MAX_INLINE_PAYLOAD_BYTES {
        return Err(SourceAdmissionError::LimitExceeded {
            field: "inline payload bytes",
            max: MAX_INLINE_PAYLOAD_BYTES,
        });
    }
    let max_events = usize::try_from(source.capacity.max_events).map_err(|_error| {
        SourceAdmissionError::LimitExceeded {
            field: "sink events",
            max: MAX_SINK_EVENTS,
        }
    })?;
    if max_events == 0 {
        return Err(SourceAdmissionError::Invalid {
            field: "sink event capacity",
        });
    }
    if max_events > MAX_SINK_EVENTS {
        return Err(SourceAdmissionError::LimitExceeded {
            field: "sink events",
            max: MAX_SINK_EVENTS,
        });
    }
    if max_events
        .checked_mul(source.max_inline_payload_bytes)
        .is_none_or(|bytes| bytes > MAX_DECLARED_SINK_BYTES)
    {
        return Err(SourceAdmissionError::LimitExceeded {
            field: "declared sink bytes",
            max: MAX_DECLARED_SINK_BYTES,
        });
    }
    if let Some(rate) = source.rate_limit.as_ref() {
        if rate.window_ms == 0 {
            return Err(SourceAdmissionError::Invalid {
                field: "rate window_ms",
            });
        }
        if rate.max_events == 0 {
            return Err(SourceAdmissionError::Invalid { field: "rate hits" });
        }
        if usize::try_from(rate.max_events).map_or(true, |hits| hits > MAX_RATE_HITS) {
            return Err(SourceAdmissionError::LimitExceeded {
                field: "rate hits",
                max: MAX_RATE_HITS,
            });
        }
    }
    Ok(())
}

/// Fixed expiry from the serialized admission time and retention window.
/// A later configuration change does not shorten or extend existing evidence.
pub fn event_expires_at(decision_at_ms: i64, dedupe_window_ms: u64) -> i64 {
    (i128::from(decision_at_ms) + i128::from(dedupe_window_ms)).min(i128::from(i64::MAX)) as i64
}

/// Validate a host-selected Source claim before allocating private keys.
pub fn validate_claim(claim: SourceClaim<'_>) -> Result<(), SourceStoreError> {
    if claim.scope_epoch == 0 || claim.stream_epoch == Some(0) {
        return Err(SourceStoreError::Aborted(
            "Source scope epoch is invalid".into(),
        ));
    }
    for segment in [claim.installation_id, claim.projection_id, claim.event_id] {
        if segment.is_empty() || segment.len() > MAX_ID_BYTES {
            return Err(SourceStoreError::Aborted(
                "Source identity is invalid".into(),
            ));
        }
    }
    Ok(())
}

/// Validate a stream control identity before allocating keys or touching the
/// authoritative catalog. An inactive scope is an outcome, not invalid input.
pub fn validate_stream_scope(stream: SourceStreamScope<'_>) -> Result<(), SourceStoreError> {
    if stream.scope_epoch == 0 {
        return Err(SourceStoreError::Aborted(
            "Source scope epoch is invalid".into(),
        ));
    }
    for segment in [
        stream.installation_id,
        stream.projection_id,
        stream.stream_id,
    ] {
        if segment.is_empty() || segment.len() > MAX_ID_BYTES {
            return Err(SourceStoreError::Aborted(
                "Source stream identity is invalid".into(),
            ));
        }
    }
    Ok(())
}

/// Validate a Source commit's bounded structural inputs before constructing
/// private keys or resident sink values. Backends must separately measure the
/// actual encoded payload, current sink and final row.
pub fn validate_commit(request: &SourceCommit<'_>) -> Result<(), SourceStoreError> {
    validate_claim(request.claim)?;
    if request.claim.stream_epoch != request.stream.map(|stream| stream.stream_epoch) {
        return Err(SourceStoreError::Aborted(
            "Source claim and stream epochs differ".into(),
        ));
    }
    if let Some(stream) = request.stream
        && (stream.stream_id.is_empty() || stream.stream_id.len() > MAX_ID_BYTES)
    {
        return Err(SourceStoreError::Aborted(
            "Source stream identity is invalid".into(),
        ));
    }
    if request.sink.scheme() != "state"
        || !request.sink.is_concrete()
        || request
            .sink
            .canonical_len()
            .is_none_or(|len| len > MAX_SINK_PATH_BYTES)
    {
        return Err(SourceStoreError::Aborted(
            "Source sink path is invalid".into(),
        ));
    }
    if request.max_inline_payload_bytes == 0
        || request.max_inline_payload_bytes > MAX_INLINE_PAYLOAD_BYTES
    {
        return Err(SourceStoreError::Aborted(
            "Source inline payload budget is invalid".into(),
        ));
    }
    Ok(())
}

/// Result of one bounded cleanup step.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourceMaintenanceResult {
    /// Number of event-id, rate and stream rows examined, combined.
    pub examined: usize,
    /// Number of expired event decisions, idle rate records or obsolete stream
    /// positions removed. Each event decision also removes its matching receipt.
    pub removed: usize,
    /// The end of the private scan range was reached; the next step starts over.
    pub reached_end: bool,
}

/// Host maintenance capability, separate from Source frame admission.
pub trait SourceEventMaintenance: Send + Sync {
    /// Scan at most the requested number of event-id, rate and stream rows, preserving a
    /// backend-owned global continuation between calls. Durable backends
    /// preserve it across process restarts; in-memory backends do not.
    fn maintain<'a>(
        &'a self,
        request: SourceMaintenance,
    ) -> SourceFuture<'a, SourceMaintenanceResult>;
}

/// The management facets of one Source storage owner. A Console host can
/// install this object without retaining commit or maintenance authority, and
/// cannot validate an installation against one owner but write it to another.
pub trait SourceManagement:
    SourceDeclarationAdmission + ExternalInstallationAuthority + SourceClaimInspection
{
}

impl<T> SourceManagement for T where
    T: SourceDeclarationAdmission + ExternalInstallationAuthority + SourceClaimInspection
{
}

/// One storage owner implementing all Source-specific capabilities. Hosts may
/// give only the management facet to Console and the commit/lifecycle facets
/// to ingress while preserving one shared owner.
pub trait SourceStore: SourceIngress + SourceManagement + SourceEventMaintenance {}

impl<T> SourceStore for T where T: SourceIngress + SourceManagement + SourceEventMaintenance {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use anyhow::{Result, ensure};
    use core::fmt::Debug;
    use xolotl_types::{Purity, external::OverflowPolicy};

    fn check_eq<T: Debug + Eq>(actual: T, expected: T) -> Result<()> {
        ensure!(actual == expected, "expected {expected:?}, got {actual:?}");
        Ok(())
    }

    fn event_source(sink: Path) -> EventSource {
        EventSource {
            sink,
            purity: Purity::Effectful,
            event_schema: None,
            max_inline_payload_bytes: MAX_INLINE_PAYLOAD_BYTES,
            capacity: StreamCapacity {
                max_events: 64,
                on_overflow: OverflowPolicy::DropOldest,
            },
            rate_limit: Some(SourceRateLimit {
                window_ms: u64::MAX,
                max_events: MAX_RATE_HITS as u32,
            }),
            commands: false,
            command_schema: None,
            command_result_schema: None,
        }
    }

    fn long_sink(len: usize) -> Result<Path, xolotl_types::PathError> {
        let mut text = String::from("state://");
        text.push_str(&"x".repeat(len - text.len()));
        Path::parse(&text)
    }

    #[test]
    fn event_expiry_saturates_only_at_timestamp_maximum() {
        assert_eq!(event_expires_at(100, 1000), 1100);
        assert_eq!(event_expires_at(i64::MAX, 1), i64::MAX);
        assert_eq!(event_expires_at(i64::MIN, i64::MAX as u64 + 1), 0);
        assert_eq!(event_expires_at(i64::MIN, u64::MAX), i64::MAX);
    }

    #[test]
    fn builtin_declaration_bounds_match_commit_budgets() -> Result<()> {
        let id = "i".repeat(MAX_ID_BYTES);
        let mut source = event_source(long_sink(MAX_SINK_PATH_BYTES)?);
        check_eq(validate_builtin_source(&id, &id, &source), Ok(()))?;

        check_eq(
            validate_builtin_source(&"i".repeat(MAX_ID_BYTES + 1), &id, &source),
            Err(SourceAdmissionError::LimitExceeded {
                field: "installation_id bytes",
                max: MAX_ID_BYTES,
            }),
        )?;
        check_eq(
            validate_builtin_source(&id, &"p".repeat(MAX_ID_BYTES + 1), &source),
            Err(SourceAdmissionError::LimitExceeded {
                field: "projection_id bytes",
                max: MAX_ID_BYTES,
            }),
        )?;
        source.sink = long_sink(MAX_SINK_PATH_BYTES + 1)?;
        check_eq(
            validate_builtin_source(&id, &id, &source),
            Err(SourceAdmissionError::LimitExceeded {
                field: "sink path bytes",
                max: MAX_SINK_PATH_BYTES,
            }),
        )?;
        source.sink = long_sink(MAX_SINK_PATH_BYTES)?;

        source.max_inline_payload_bytes = MAX_INLINE_PAYLOAD_BYTES + 1;
        check_eq(
            validate_builtin_source(&id, &id, &source),
            Err(SourceAdmissionError::LimitExceeded {
                field: "inline payload bytes",
                max: MAX_INLINE_PAYLOAD_BYTES,
            }),
        )?;
        source.max_inline_payload_bytes = MAX_INLINE_PAYLOAD_BYTES;
        source.capacity.max_events = (MAX_SINK_EVENTS + 1) as u32;
        check_eq(
            validate_builtin_source(&id, &id, &source),
            Err(SourceAdmissionError::LimitExceeded {
                field: "sink events",
                max: MAX_SINK_EVENTS,
            }),
        )?;
        source.capacity.max_events = 65;
        check_eq(
            validate_builtin_source(&id, &id, &source),
            Err(SourceAdmissionError::LimitExceeded {
                field: "declared sink bytes",
                max: MAX_DECLARED_SINK_BYTES,
            }),
        )?;
        source.capacity.max_events = 64;
        source.rate_limit = Some(SourceRateLimit {
            window_ms: u64::MAX,
            max_events: (MAX_RATE_HITS + 1) as u32,
        });
        check_eq(
            validate_builtin_source(&id, &id, &source),
            Err(SourceAdmissionError::LimitExceeded {
                field: "rate hits",
                max: MAX_RATE_HITS,
            }),
        )?;
        Ok(())
    }

    #[test]
    fn receipt_bound_covers_escaped_ids_and_maximum_sink() -> Result<()> {
        let escaped_id = "\u{0000}".repeat(MAX_ID_BYTES);
        let receipt = SourceReceipt {
            installation_id: escaped_id.clone(),
            projection_id: escaped_id.clone(),
            scope_epoch: u64::MAX,
            stream_epoch: Some(u64::MAX),
            event_id: escaped_id,
            claim_id: SourceClaimId::from_bytes([u8::MAX; 16]),
            sink: long_sink(MAX_SINK_PATH_BYTES)?,
            received_at_ms: i64::MIN,
        };
        let bytes = serde_json::to_vec(&receipt)?;
        ensure!(bytes.len() <= MAX_RECEIPT_BYTES, "{} bytes", bytes.len());
        ensure!(bytes.len() > 8192, "test must exceed the former bound");
        Ok(())
    }
}
