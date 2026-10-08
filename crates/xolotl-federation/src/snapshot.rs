//! Receiver-side handoff for an application-owned, immutable snapshot.
//! A history exclusion cursor is not a snapshot receipt. The application owns
//! snapshot bytes and its durable projection; this port owns only the delivery
//! generation, installation intent, and active baseline.

use std::sync::Arc;

use crate::{
    AcceptRequest, AcceptResult, AuthorityRevision, Digest, FederationError, FederationNodeId,
    FederationSubject, InboxReadPage, InboxReadRequest, InboxRetirement, Position,
    ProjectionProgress, SchemaRevision, StreamRef, SubscriptionRef,
};
use sha2::{Digest as _, Sha384};

/// Maximum snapshot content size accepted by this first installation contract.
pub const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum application content returned by one authenticated snapshot read.
pub const MAX_SNAPSHOT_CHUNK_BYTES: usize = 1024 * 1024;

/// Stable identifier of one immutable application snapshot or install attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SnapshotId([u8; 16]);

impl SnapshotId {
    /// Wrap a caller-owned, stable identifier.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the canonical identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// An application must have durably bound these immutable bytes to the exact
/// authorized stream position before offering this manifest. A position alone
/// cannot prove that a snapshot obeys a subscriber's history restriction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotManifest {
    /// Immutable identity of the application's snapshot bytes and scope.
    pub id: SnapshotId,
    /// Already installed private receiver subscription.
    pub subscription: SubscriptionRef,
    /// Authorized single-writer stream represented by this snapshot.
    pub stream: StreamRef,
    /// Publisher subscription revision at snapshot offer time.
    pub subscription_revision: u64,
    /// Publisher peer and export revisions pinned by the Open result.
    pub publisher_authority: AuthorityRevision,
    /// Exact record whose committed state is covered by the snapshot.
    pub position: Position,
    /// Application-owned schema of the snapshot content.
    pub schema_revision: SchemaRevision,
    /// SHA-384 of the entire immutable snapshot content.
    pub content_digest: Digest,
    /// Exact content size, enforced before the application allocates staging.
    pub content_bytes: u64,
}

impl SnapshotManifest {
    /// Check structural limits without claiming the application state is valid.
    pub fn validate(&self) -> Result<(), FederationError> {
        if self.id.as_bytes() == &[0; 16]
            || self.subscription.subscriber == self.stream.publisher
            || self.subscription_revision == 0
            || self.publisher_authority.peer == 0
            || self.publisher_authority.export == 0
            || self.content_digest.as_bytes() == &[0; 48]
        {
            return Err(FederationError::Invalid("invalid snapshot binding"));
        }
        if self.content_bytes > MAX_SNAPSHOT_BYTES {
            return Err(FederationError::Capacity);
        }
        Ok(())
    }

    /// Bind every delivery and application field into one completion digest.
    pub fn binding_digest(&self) -> Digest {
        let mut hash = Sha384::new();
        hash.update(b"xolotl/federation/v1/snapshot-manifest\0");
        hash.update(self.id.as_bytes());
        hash.update(self.subscription.subscriber.as_bytes());
        hash.update(self.subscription.id.as_bytes());
        hash.update(self.stream.publisher.as_bytes());
        hash.update(self.stream.id.as_bytes());
        hash.update(self.subscription_revision.to_be_bytes());
        hash.update(self.publisher_authority.peer.to_be_bytes());
        hash.update(self.publisher_authority.export.to_be_bytes());
        hash.update(self.position.sequence().to_be_bytes());
        hash.update(self.position.digest().as_bytes());
        hash.update(self.schema_revision.as_bytes());
        hash.update(self.content_digest.as_bytes());
        hash.update(self.content_bytes.to_be_bytes());
        Digest::from_bytes(hash.finalize().into())
    }
}

/// Durable intent to replace a receiver's remote delivery baseline. An
/// archive-only install does not replace the application's projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotInstallRequest {
    /// A stable, never-reused application handoff identity.
    pub install_id: SnapshotId,
    /// Proven source-side subject; this first contract accepts only node-self.
    pub subject: FederationSubject,
    /// Immutable snapshot and exact delivery scope offered for installation.
    pub manifest: SnapshotManifest,
    /// Publisher's exact publication evidence for the offered bytes.
    pub publication_digest: Digest,
    /// The active federation generation observed before starting the install.
    /// An ordinary receiver subscription starts at generation zero.
    pub expected_generation: u64,
}

/// Produced only after the application has durably staged and sealed a new
/// projection generation. The trusted host must retrieve this evidence from
/// its application store; constructing this value is not itself a commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotProjectionCompletion {
    /// The application-staged install that produced this completion.
    pub install_id: SnapshotId,
    /// Immutable snapshot accepted by the application.
    pub snapshot_id: SnapshotId,
    /// Digest of the complete snapshot bytes verified by the application.
    pub content_digest: Digest,
    /// Digest of every field in the exact snapshot manifest.
    pub manifest_digest: Digest,
    /// Durable application projection generation sealed for this install.
    pub application_generation: u64,
    /// Digest of the application's durable completion evidence.
    pub completion_digest: Digest,
}

/// Durable receipt for sealed snapshot bytes only. This does not claim that
/// any application has interpreted or installed the snapshot's state. The
/// trusted host retrieves this from its archive; constructing it is not a
/// durable seal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotArchiveCompletion {
    /// Stable install whose bytes were sealed.
    pub install_id: SnapshotId,
    /// Immutable snapshot whose bytes were sealed.
    pub snapshot_id: SnapshotId,
    /// Verified digest of the complete sealed content.
    pub content_digest: Digest,
    /// Digest of the exact manifest governing the sealed bytes.
    pub manifest_digest: Digest,
    /// Durable archive receipt, distinct from application projection evidence.
    pub archive_digest: Digest,
}

/// Committed delivery baseline backed by sealed, uninterpreted snapshot bytes.
/// Its position is snapshot coverage, never an ordinary inbox record receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotArchiveAnchor {
    /// Stable installation identity for restart reconciliation.
    pub install_id: SnapshotId,
    /// Exact immutable content and delivery scope.
    pub manifest: SnapshotManifest,
    /// Publication evidence retained for receipt replay after restart.
    pub publication_digest: Digest,
    /// Active receiver delivery generation after archive commitment.
    pub federation_generation: u64,
    /// Durable archive receipt checked on restart.
    pub archive_digest: Digest,
}

/// Committed baseline; its position is snapshot coverage, not an event receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotAnchor {
    /// Stable installation identity for restart reconciliation.
    pub install_id: SnapshotId,
    /// Exact application-owned snapshot and stream binding.
    pub manifest: SnapshotManifest,
    /// Publication evidence retained with the accepted delivery baseline.
    pub publication_digest: Digest,
    /// New active receiver delivery generation.
    pub federation_generation: u64,
    /// Application generation selected by the durable completion evidence.
    pub application_generation: u64,
    /// Durable application's completion evidence digest.
    pub completion_digest: Digest,
}

/// Locally persisted installation state for recovery after an unknown commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotInstallView {
    /// Application-projected anchor, if the application completed installation.
    pub active: Option<SnapshotAnchor>,
    /// Durable delivery anchor, if sealed bytes were archived separately.
    /// `active` may refer to the same install after a later application commit.
    pub archived: Option<SnapshotArchiveAnchor>,
    /// Frozen in-progress install, if one exists.
    pub pending: Option<SnapshotInstallRequest>,
    /// Active receiver generation; zero means only the original Open baseline.
    pub generation: u64,
    /// Whether local authority closed this receiver permanently.
    pub closed: bool,
}

/// Application-issued authorization to retire inbox rows covered by an
/// active snapshot. The trusted host must obtain this from durable application
/// state only after all readers and workers of the older generations have
/// stopped. The digest records that decision; it is not a cryptographic proof
/// that a caller actually quiesced its readers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotReaderRelease {
    /// Receiver whose previous delivery generations were released.
    pub subscription: SubscriptionRef,
    /// Installation whose active anchor authorizes this cleanup.
    pub install_id: SnapshotId,
    /// Active federation generation observed by the application.
    pub federation_generation: u64,
    /// Active application projection generation observed by the application.
    pub application_generation: u64,
    /// Completion evidence bound to the active anchor.
    pub completion_digest: Digest,
    /// Must equal the active federation generation minus one.
    pub released_through_generation: u64,
    /// Nonzero digest of the application's durable reader-release decision.
    pub release_digest: Digest,
}

/// Result of one bounded physical inbox cleanup transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotInboxRetirement {
    /// Receiver whose old rows were examined.
    pub subscription: SubscriptionRef,
    /// Snapshot coverage limit; no active-generation row is at or below it.
    pub covered_through: Position,
    /// Number of physical inbox rows removed by this transaction.
    pub removed: usize,
    /// True when no covered inbox rows remain after this transaction.
    pub drained: bool,
}

/// Durable application evidence for one immutable, pinned publisher snapshot.
/// The trusted host obtains this from the application store after it has bound
/// exact bytes to a committed stream position. Redb verifies the position in
/// its own log but cannot prove the separate application's transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotPublicationProof {
    /// Immutable application content identity.
    pub snapshot_id: SnapshotId,
    /// Single-writer stream whose state the content represents.
    pub stream: StreamRef,
    /// Exact committed record covered by the content.
    pub position: Position,
    /// Application-owned content schema.
    pub schema_revision: SchemaRevision,
    /// SHA-384 of all immutable content bytes.
    pub content_digest: Digest,
    /// Exact content length.
    pub content_bytes: u64,
    /// Nonzero digest of the application's durable publication evidence.
    pub publication_digest: Digest,
}

impl SnapshotPublicationProof {
    /// Check bounds and identity fields, without claiming cross-store atomicity.
    pub fn validate(self) -> Result<(), FederationError> {
        if self.snapshot_id.as_bytes() == &[0; 16]
            || self.content_digest.as_bytes() == &[0; 48]
            || self.publication_digest.as_bytes() == &[0; 48]
        {
            return Err(FederationError::Invalid(
                "invalid snapshot publication proof",
            ));
        }
        if self.content_bytes > MAX_SNAPSHOT_BYTES {
            return Err(FederationError::Capacity);
        }
        Ok(())
    }
}

/// Local publisher request to disclose one application-pinned snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotOfferRequest {
    /// Subscriber authenticated by the caller's session.
    pub authenticated_subscriber: FederationNodeId,
    /// Already Open private, node-self subscription.
    pub subscription: SubscriptionRef,
    /// Evidence read from the trusted application's durable publication store.
    pub proof: SnapshotPublicationProof,
}

/// Immutable subscription-specific publisher offer retained across restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotOffer {
    /// Exact Open authority and publication position offered to the receiver.
    pub manifest: SnapshotManifest,
    /// Digest of the application's pinned publication evidence.
    pub publication_digest: Digest,
}

/// Subscriber's claim that exact offered bytes have been sealed durably.
/// This is snapshot coverage, not application projection or an event ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotReceivedRequest {
    /// Node authenticated by the current federation session.
    pub authenticated_subscriber: FederationNodeId,
    /// Exact private node-self subscription that accepted the offer.
    pub subscription: SubscriptionRef,
    /// Digest of every field of the offered manifest.
    pub manifest_digest: Digest,
    /// Publisher's pinned publication proof for that offer.
    pub publication_digest: Digest,
    /// Covered publisher log position.
    pub position: Position,
    /// Stable receiver install that sealed the content.
    pub install_id: SnapshotId,
    /// Durable receiver archive completion evidence.
    pub archive_digest: Digest,
    /// Active receiver delivery generation; zero is never an archived baseline.
    pub federation_generation: u64,
    /// Contiguous durable inbox suffix following this exact archive. This does
    /// not assert acceptance of the missing prefix or application projection.
    pub suffix: Option<SnapshotSuffixCoverage>,
}

/// Native delivery coverage rooted in a sealed archive, not a projected State.
/// The receiver may report only records accepted contiguously in the archive's
/// active generation. The publisher validates every newly covered log position
/// within the same authority/receipt transaction, bounded by
/// `MAX_SNAPSHOT_SUFFIX_RECORDS` new records and `MAX_SNAPSHOT_SUFFIX_BYTES`
/// payload bytes per request. Excess rejects without changing evidence. `after`
/// is the archive baseline or the publisher's previously confirmed frontier,
/// with its exact digest. Retried confirmations
/// never lower the frontier. No ordinary event ACK is created for the prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotSuffixCoverage {
    /// Exact archive baseline or previously confirmed coverage frontier.
    pub after: Position,
    /// Highest contiguous, durably accepted post-archive record.
    pub through: Position,
}

/// Maximum newly verified durable records in one archive-suffix confirmation.
pub const MAX_SNAPSHOT_SUFFIX_RECORDS: usize = 256;
/// Maximum newly verified record payload bytes, not an RSS bound. Records are
/// verified one at a time; no suffix payload is retained by the receipt row.
pub const MAX_SNAPSHOT_SUFFIX_BYTES: usize = 64 * 1024 * 1024;

/// Publisher-confirmed snapshot coverage, independent of ordinary event ACKs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotReceived {
    /// Subscription whose replica frontier can use this coverage.
    pub subscription: SubscriptionRef,
    /// Exact offered manifest accepted by the publisher.
    pub manifest_digest: Digest,
    /// Exact offered publication proof accepted by the publisher.
    pub publication_digest: Digest,
    /// Covered publisher log position.
    pub position: Position,
    /// Receiver installation whose archive was reported.
    pub install_id: SnapshotId,
    /// Receiver's durable archive completion evidence.
    pub archive_digest: Digest,
    /// Receiver generation bound to the archive and any accepted suffix.
    pub federation_generation: u64,
    /// Exact suffix confirmation echoed independently of ordinary event ACKs.
    pub suffix: Option<SnapshotSuffixCoverage>,
}

impl From<SnapshotReceivedRequest> for SnapshotReceived {
    fn from(request: SnapshotReceivedRequest) -> Self {
        Self {
            subscription: request.subscription,
            manifest_digest: request.manifest_digest,
            publication_digest: request.publication_digest,
            position: request.position,
            install_id: request.install_id,
            archive_digest: request.archive_digest,
            federation_generation: request.federation_generation,
            suffix: request.suffix,
        }
    }
}

/// One independent authenticated bounded content read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotReadRequest {
    /// Subscriber authenticated by the current session.
    pub authenticated_subscriber: FederationNodeId,
    /// Exact private subscription that owns the offer.
    pub subscription: SubscriptionRef,
    /// Full offer binding observed by the receiver.
    pub manifest_digest: Digest,
    /// Zero-based byte offset into immutable content.
    pub offset: u64,
    /// Positive per-call byte limit, at most `MAX_SNAPSHOT_CHUNK_BYTES`.
    pub max_bytes: usize,
}

/// One content slice; the receiver still verifies the complete SHA-384 digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotReadChunk {
    /// Exact immutable offer authorized at the final read decision.
    pub offer: SnapshotOffer,
    /// Starting byte offset of this slice.
    pub offset: u64,
    /// Exact requested bytes, shared without an extra whole-snapshot clone.
    pub bytes: Arc<[u8]>,
    /// True when the returned slice reaches the content length.
    pub complete: bool,
}

/// Trusted application-owned immutable byte source. The host must keep offered
/// bytes pinned while an offer can be read. This port must return the exact
/// requested range from the publication bound by `offer`, not a live State scan.
pub trait SnapshotContentSource: Send + Sync {
    /// Read one bounded slice; the publisher verifies the returned length.
    fn read_snapshot_chunk(
        &self,
        offer: &SnapshotOffer,
        offset: u64,
        bytes: usize,
    ) -> Result<Arc<[u8]>, FederationError>;
}

/// Publisher-side authority and durable offer port. One subscription retains
/// at most one offer. A local owner may retire that exact offer before publishing
/// another; a concurrent chunk read then fails its final authority check.
pub trait FederationSnapshotPublisherStore: Send + Sync {
    /// Revalidate a queued archive/suffix receipt at actual delivery. Check
    /// current private Node-self authority, immutable Open scope and the active
    /// archived generation. An offer may already be retired; its byte-disclosure
    /// authorization is not a substitute for this receipt check. No mutation.
    fn authorize_snapshot_receipt_delivery(
        &self,
        _peer: FederationNodeId,
        _received: SnapshotReceived,
    ) -> Result<(), FederationError> {
        Err(FederationError::Unauthorized)
    }
    /// Read-only delivery revalidation of the admitted manifest and optional
    /// publication digest against current subscription and peer/export fences.
    /// No content read, time persistence or offer mutation. Blocking backends
    /// require bounded host work; unsupported custom stores fail closed.
    fn authorize_snapshot_delivery(
        &self,
        _peer: FederationNodeId,
        _subscription: SubscriptionRef,
        _manifest: Digest,
        _publication: Option<Digest>,
    ) -> Result<(), FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Bind verified remote authority to each actual backend decision.
    /// Unsupported backends must reject, never substitute a preflight check.
    fn bind_snapshot_publisher_decision(
        &self,
        _decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationSnapshotPublisherStore>, crate::FederationError> {
        Err(crate::FederationError::Unauthorized)
    }
    /// Publisher identity owning the authoritative log and offer sidecar.
    fn local_node(&self) -> FederationNodeId;

    /// Persist an offer only after checking the exact publisher log position,
    /// Open contract, current authority and durable application proof fields.
    fn publish_snapshot_offer(
        &self,
        request: SnapshotOfferRequest,
    ) -> Result<SnapshotOffer, FederationError>;

    /// Confirm exact offered snapshot coverage in the same transaction as the
    /// authority and offer checks. Replaying an already committed receipt is
    /// idempotent even when the offer has since been retired. A suffix requires
    /// a previously confirmed archive in the same generation; validate exact
    /// scope, digests and contiguous newly covered publisher records atomically.
    fn receive_snapshot(
        &self,
        request: SnapshotReceivedRequest,
    ) -> Result<SnapshotReceived, FederationError>;

    /// Inspect the offer through current subscriber authority after a restart.
    fn snapshot_offer(
        &self,
        authenticated_subscriber: FederationNodeId,
        subscription: SubscriptionRef,
    ) -> Result<Option<SnapshotOffer>, FederationError>;

    /// Inspect local offer metadata even after subscriber access is revoked.
    /// This is a trusted host operation, never a remote disclosure endpoint.
    fn local_snapshot_offer(
        &self,
        subscription: SubscriptionRef,
    ) -> Result<Option<SnapshotOffer>, FederationError>;

    /// Atomically retire only the exact offer and its log pin. A repeated call
    /// succeeds when no offer remains; a different current offer conflicts.
    /// After an indeterminate commit, inspect locally or retry this same CAS
    /// before releasing the application's immutable content pin. Existing
    /// chunk reads recheck the offer before returning bytes.
    fn retire_snapshot_offer(&self, expected: &SnapshotOffer) -> Result<(), FederationError>;

    /// Read one content slice. The implementation must check authority and the
    /// exact offer in a first short transaction, call `source` outside that
    /// transaction, then recheck in a second short transaction before return.
    /// This final check is the disclosure decision for this one chunk; a later
    /// revocation prevents subsequent chunks.
    fn read_snapshot_chunk(
        &self,
        request: SnapshotReadRequest,
        source: &dyn SnapshotContentSource,
    ) -> Result<SnapshotReadChunk, FederationError>;
}

/// Optional storage capability for a private, installed node-self receiver.
/// All post-anchor work names the active generation. Legacy delivery methods
/// are fenced once an installation begins, so a delayed worker cannot cross
/// the baseline switch without explicitly reloading the active generation.
pub trait FederationSnapshotStore: Send + Sync {
    /// Bind verified remote authority to each actual backend decision.
    /// Unsupported backends must reject, never substitute a preflight check.
    fn bind_snapshot_decision(
        &self,
        _decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationSnapshotStore>, crate::FederationError> {
        Err(crate::FederationError::Unauthorized)
    }
    /// Read a persisted intent or active anchor without changing it.
    fn snapshot_install(
        &self,
        subscription: SubscriptionRef,
    ) -> Result<Option<SnapshotInstallView>, FederationError>;

    /// Inspect the exact durable delivery cursor without reading an inbox
    /// row. Returns the received head, snapshot baseline, or Open floor in
    /// that order. The named generation and current local receive authority
    /// are checked, including generation zero before the first snapshot.
    fn receiver_cursor_in_generation(
        &self,
        generation: u64,
        subscription: SubscriptionRef,
    ) -> Result<Option<Position>, FederationError>;

    /// Atomically freeze old receiver workers and persist one install intent.
    fn begin_snapshot_install(
        &self,
        request: SnapshotInstallRequest,
    ) -> Result<SnapshotInstallView, FederationError>;

    /// Publish a validated application generation and snapshot anchor atomically.
    fn commit_snapshot_anchor(
        &self,
        subscription: SubscriptionRef,
        completion: SnapshotProjectionCompletion,
    ) -> Result<SnapshotAnchor, FederationError>;

    /// Commit a delivery baseline after verifying a durable byte archive.
    /// Application projection progress and old-generation cleanup remain
    /// unavailable until an application completion is bound separately.
    fn commit_snapshot_archive(
        &self,
        subscription: SubscriptionRef,
        completion: SnapshotArchiveCompletion,
    ) -> Result<SnapshotArchiveAnchor, FederationError>;

    /// Bind a previously archived baseline to a separate application-store
    /// completion without changing its delivery generation or inbox rows.
    fn bind_archived_snapshot_projection(
        &self,
        subscription: SubscriptionRef,
        completion: SnapshotProjectionCompletion,
    ) -> Result<SnapshotAnchor, FederationError>;

    /// Abandon only an uncommitted intent after its outcome is known.
    fn abort_snapshot_install(
        &self,
        subscription: SubscriptionRef,
        install_id: SnapshotId,
    ) -> Result<(), FederationError>;

    /// Local trusted control after an authenticated remote Close (or an
    /// application decision to retire this receiver). It never reopens.
    fn close_snapshot_receiver(&self, subscription: SubscriptionRef)
    -> Result<(), FederationError>;

    /// Accept one post-anchor record only in the named delivery generation.
    fn accept_in_generation(
        &self,
        generation: u64,
        request: AcceptRequest,
    ) -> Result<AcceptResult, FederationError>;

    /// Read accepted inbox records only from the named active generation.
    fn read_inbox_in_generation(
        &self,
        generation: u64,
        request: InboxReadRequest,
    ) -> Result<InboxReadPage, FederationError>;

    /// Record application progress only for the named active generation.
    fn record_projection_progress_in_generation(
        &self,
        generation: u64,
        request: ProjectionProgress,
    ) -> Result<Position, FederationError>;

    /// Bounded retirement of already projected post-anchor rows. The named
    /// generation prevents a delayed worker from deleting a newer projection's
    /// inbox after another snapshot switches the receiver baseline.
    fn retire_projected_inbox_in_generation(
        &self,
        generation: u64,
        subscription: SubscriptionRef,
        max_records: usize,
    ) -> Result<InboxRetirement, FederationError>;

    /// Physically remove at most `max_records` old inbox rows, also bounded by
    /// `MAX_RETIRE_BYTES`. This does not advance receipt or projection cursors.
    /// The application must first durably release every older reader generation.
    fn retire_snapshotted_inbox(
        &self,
        release: SnapshotReaderRelease,
        max_records: usize,
    ) -> Result<SnapshotInboxRetirement, FederationError>;
}
