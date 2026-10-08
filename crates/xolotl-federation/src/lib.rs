//! Optional node federation contracts. A store owns each atomic decision;
//! transport authentication and application projection live outside this crate.

#![forbid(unsafe_code)]

mod access;
mod authentication;
mod call;
mod call_memory;
mod call_source;
mod decision;
mod guest;
mod identity;
mod inbox;
mod invite;
mod management;
mod memory;
mod object;
mod public;
mod receive;
mod record;
mod retention;
mod service;
mod snapshot;
mod subject;
mod subscription;
mod types;

pub use access::{GrantHistory, SubjectGrant, SubjectGrantEntry, SubjectGrantKey};
pub use authentication::{
    FederationOnlineKey, FederationOnlineKeyAuthorization, FederationSessionTranscript,
    VerifiedFederationPeerProof, verify_federation_peer_proof,
};
pub use call::{
    CallAuthorityEntry, CallAuthorityKey, CallAuthorityRule, CallCancelled, CallFailureCode,
    CallInspection, CallInvoked, CallKernelBinding, CallKernelView, CallMethod, CallPath,
    CallPrepared, CallRef, CallStatus, CallTarget, CancelCallRequest, FederationCallStore,
    InspectCallRequest, InvokeCallRequest, MAX_CALL_INPUT_BYTES, MAX_CALL_UNRESOLVED_EFFECT_IDS,
    PersistedCallResult, PrepareCallRequest,
};
pub use call_memory::MemoryFederationCallStore;
pub use call_source::{
    FederationOutboundCallStore, MAX_OUTBOUND_PAGE_INPUT_BYTES, MAX_OUTBOUND_RESULT_BYTES,
    MemoryFederationOutboundCallStore, OutboundCallIntent, OutboundCallRecord,
    OutboundOriginEvidence, OutboundOriginState,
};
pub use decision::{FederationAdmission, FederationDecision};
pub use guest::FederationGuestStore;
pub use identity::{
    FederationIdentityError, FederationNodeId, FederationRoot, FederationRootKey,
    RootSignaturePurpose,
};
pub use inbox::{InboxReadPage, InboxReadRequest};
pub use invite::{
    FederationInvitationStore, INVITATION_RECEIPT_RETENTION_MS, InvitationAudience, InvitationId,
    InvitationIssuerAuthority, InvitationIssuerKey, InvitationRedemption, InvitationSecret,
    InvitationSpec, InvitationView, MAX_INVITATION_ISSUERS, MAX_INVITATION_REDEMPTIONS,
    MAX_INVITATIONS, MAX_MANIFEST_PAGE, RedeemInvitationRequest,
};
pub use management::{
    AuthorityOwner, ExportAuthorityEntry, FederationManagement, MAX_MANAGEMENT_PAGE,
    PeerAdmissionEntry, PeerAuthorityEntry,
};
pub use memory::MemoryFederationStore;
pub use object::{
    FederationObjectClock, FederationObjectDisclosure, FederationObjectReadService,
    FederationObjectReadStore, MAX_OBJECT_CHUNK_BYTES, MAX_OBJECT_GRANTS, MAX_OBJECT_TRANSFERS,
    ObjectDeliveryContext, ObjectDigestVerifier, ObjectGrantId, ObjectGrantSpec, ObjectGrantView,
    ObjectReadAdmission, ObjectReadAuthority, ObjectReadDelivery, ObjectReadPage,
    ObjectReadRequest, ObjectTransferId, SystemObjectClock,
};
pub use public::{
    FederationPublicReadStore, FederationPublicService, MAX_PUBLIC_POLICIES, MAX_PUBLIC_READ_BYTES,
    MAX_PUBLIC_READ_RECORDS, PublicReadLimits, PublicReadPage, PublicReadRequest,
    PublicStreamPolicy, PublicStreamView,
};
pub use receive::{
    FederationObjectChunkSource, FederationObjectReceiveStore, FederationObjectReceiver,
    FederationObjectReferenceGuard, FederationObjectReferenceStore, MAX_OBJECT_GC_FENCES,
    MAX_OBJECT_RECEIVES, ObjectGcFence, ObjectReceivePhase, ObjectReceiveSpec, ObjectReceiveView,
    ObjectReferenceEvidence, bind_verified_object,
};
pub use record::{
    EventRef, EventType, MAX_PUBLICATION_RETIRE_IDS, PublicationReceipt, PublishRequest, Record,
    RecordParts, SchemaRevision,
};
pub use retention::{
    FederationReplicaRetentionStore, InboxRetirement, MAX_REPLICA_LEASE_MS, MAX_REPLICA_MEMBERS,
    MAX_RETIRE_BYTES, MAX_RETIRE_RECORDS, PublishedRetirement, ReplicaMemberSpec,
    ReplicaMemberView, ReplicaRetentionTerm,
};
pub use service::{FederationLimits, FederationService};
pub use snapshot::{
    FederationSnapshotPublisherStore, FederationSnapshotStore, MAX_SNAPSHOT_BYTES,
    MAX_SNAPSHOT_CHUNK_BYTES, MAX_SNAPSHOT_SUFFIX_BYTES, MAX_SNAPSHOT_SUFFIX_RECORDS,
    SnapshotAnchor, SnapshotArchiveAnchor, SnapshotArchiveCompletion, SnapshotContentSource,
    SnapshotId, SnapshotInboxRetirement, SnapshotInstallRequest, SnapshotInstallView,
    SnapshotManifest, SnapshotOffer, SnapshotOfferRequest, SnapshotProjectionCompletion,
    SnapshotPublicationProof, SnapshotReadChunk, SnapshotReadRequest, SnapshotReaderRelease,
    SnapshotReceived, SnapshotReceivedRequest, SnapshotSuffixCoverage,
};
pub use subject::{
    FederationSubject, HostedSubject, SessionSubjects, SubjectAssertion, SubjectHolderKey,
    SubjectIssuer, SubjectIssuerId, SubjectIssuerKey, SubjectIssuerPolicy, SubjectProofError,
    SubjectPurpose,
};
pub use subscription::{
    CloseSubscriptionRequest, CloseSubscriptionResult, HistoryStart, InspectSubscriptionRequest,
    SubscriptionInspection,
};
pub use types::{
    AuthorityRevision, Digest, ExportAccess, ExportName, FederationError, PeerAdmission, Position,
    RequestId, StreamId, StreamRef, SubscriptionId, SubscriptionRef,
};

use std::sync::Arc;

/// One locally owned export stream. Creating a stream does not publish domain
/// changes; production hosts must join publication to their durable change log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamSpec {
    /// Publisher-owned stream identity to declare.
    pub stream: StreamRef,
    /// Export authority name governing this stream.
    pub export: ExportName,
}

/// The receiver-generated identity and stable request for opening a subscription.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenRequest {
    /// Node authenticated by the enclosing Session.
    pub authenticated_subscriber: FederationNodeId,
    /// Stable control request ID for idempotent retries.
    pub request_id: RequestId,
    /// Subscriber-owned durable relationship being opened.
    pub subscription: SubscriptionRef,
    /// Exact publisher-owned stream selected for this relationship.
    pub stream: StreamRef,
    /// Optional CAS fence against a changed subscription control state.
    pub expected_control_revision: Option<u64>,
    /// Historical disclosure start fixed at successful Open.
    pub history: HistoryStart,
}

/// Publisher's persisted result for one Open request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenResult {
    /// Original stable control request ID.
    pub request_id: RequestId,
    /// Subscription installed at the publisher.
    pub subscription: SubscriptionRef,
    /// Immutable stream selected by the Open.
    pub stream: StreamRef,
    /// Export whose authority governs future delivery.
    pub export: ExportName,
    /// Peer and export revisions observed by the Open decision.
    pub publisher_authority: AuthorityRevision,
    /// Publisher-side control revision of this subscription.
    pub subscription_revision: u64,
    /// History exclusion baseline, not a receiver receipt.
    pub start: Option<Position>,
}

/// A receiver imports an authenticated publisher's Open result under its own
/// current local peer and export authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallSubscriptionRequest {
    /// Publisher proven by the Session that returned this Open result.
    pub authenticated_publisher: FederationNodeId,
    /// Publisher's exact durable Open result to install locally.
    pub opened: OpenResult,
}

/// A logical receiver-to-publisher read, independent of who dialed the session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadRequest {
    /// Subscriber proven by the enclosing Session.
    pub authenticated_subscriber: FederationNodeId,
    /// Durable subscription used to authorize this read.
    pub subscription: SubscriptionRef,
    /// Exact last record already held, or the Open baseline.
    pub after: Option<Position>,
    /// Maximum records to disclose in one page.
    pub max_records: usize,
    /// Maximum record payload bytes to disclose in one page.
    pub max_bytes: usize,
}

/// One bounded page and the publisher's committed stream range.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadPage {
    /// Ordered records disclosed under one current authority decision.
    pub records: Vec<Record>,
    /// Publisher's committed stream head at the read decision.
    pub head: Option<Position>,
    /// Earliest sequence whose payload is still retained.
    pub minimum_available: u64,
}

/// A receiver accepts one record. The store must atomically advance its inbox
/// position and deduplication evidence or do neither.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptRequest {
    /// Publisher proven by the Session that delivered the record.
    pub authenticated_publisher: FederationNodeId,
    /// Locally installed subscription receiving this record.
    pub subscription: SubscriptionRef,
    /// Immutable record to verify and append to the inbox.
    pub record: Record,
}

/// Durable outcome of accepting one immutable record into a receiver inbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptResult {
    /// Position durably accepted or already present with identical content.
    pub position: Position,
    /// False only for a verified idempotent replay.
    pub newly_accepted: bool,
}

/// The publisher only advances an acknowledged position after checking that it
/// matches its immutable record and the current subscription authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcknowledgeRequest {
    /// Subscriber proven by the enclosing Session.
    pub authenticated_subscriber: FederationNodeId,
    /// Subscription whose receiver persisted this record.
    pub subscription: SubscriptionRef,
    /// Exact received position, including its complete-record digest.
    pub position: Position,
}

/// The application reports a position only after its own projection commit.
/// This is not a cross-store transaction with the inbox.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionProgress {
    /// Local receiver subscription whose application state was committed.
    pub subscription: SubscriptionRef,
    /// Highest accepted position included in the application projection.
    pub position: Position,
}

/// An atomic effect port. A persistent implementation must check current peer
/// and export authority within the same decision boundary as each mutation.
/// These synchronous methods are intended to run on the host's bounded blocking
/// executor when a backend performs blocking I/O.
pub trait FederationStore: Send + Sync {
    /// Read-only final delivery check for an already admitted subscription.
    /// Reuse current peer/export/subject and original revision rules, but do
    /// not read payload, persist time, charge quota or change business state.
    /// Run potentially blocking implementations on bounded host workers.
    /// Unsupported custom stores must deny protected delivery.
    fn authorize_subscription_delivery(
        &self,
        _subject: &FederationSubject,
        _request: InspectSubscriptionRequest,
        _payload: bool,
        _now_ms: u64,
    ) -> Result<(), FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// CAS the peer's exact online-key policy in the business commit domain.
    fn set_peer_admission(
        &self,
        _peer: FederationNodeId,
        _expected_revision: Option<u64>,
        _admission: PeerAdmission,
    ) -> Result<u64, FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Bind verified remote authority to each actual backend decision.
    /// Unsupported backends must reject, never substitute a preflight check.
    fn bind_decision(
        &self,
        _decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationStore>, crate::FederationError> {
        Err(crate::FederationError::Unauthorized)
    }
    /// The constructor has already verified that this store belongs to this node.
    fn local_node(&self) -> FederationNodeId;

    /// Compare-and-set peer authority. None means create only; Some(n) requires
    /// the exact current revision. Revisions increase on every successful change.
    fn set_peer_authority(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        enabled: bool,
    ) -> Result<u64, FederationError>;

    /// Compare-and-set one export's directional permission for a peer.
    fn set_export_authority(
        &self,
        peer: FederationNodeId,
        export: ExportName,
        expected_revision: Option<u64>,
        access: ExportAccess,
    ) -> Result<u64, FederationError>;

    /// CAS on a subject's exact-view grant. Revocation or any grant revision
    /// change fences only subscriptions opened under that grant.
    fn set_subject_grant(
        &self,
        expected_revision: Option<u64>,
        grant: SubjectGrant,
    ) -> Result<u64, FederationError>;

    /// Exact management lookup; it does not authorize a remote request.
    fn subject_grant(
        &self,
        subject: &HostedSubject,
        presenter: FederationNodeId,
        stream: StreamRef,
    ) -> Result<Option<SubjectGrantEntry>, FederationError>;

    /// Return at most 256 grants after an exclusive semantic key. Disabled
    /// rows remain visible for explicit revocation and CAS reconciliation.
    fn scan_subject_grants(
        &self,
        after: Option<&SubjectGrantKey>,
        max: usize,
    ) -> Result<Vec<SubjectGrantEntry>, FederationError>;

    /// Declare a publisher-owned stream under an existing local export.
    fn declare_stream(&self, spec: StreamSpec) -> Result<(), FederationError>;

    /// Idempotent by stream, retry epoch and publish_id. A production application must
    /// call this in its domain commit or derive it from a durable change log.
    /// Payload retirement does not return identity capacity. Only explicit
    /// epoch closure followed by exact confirmed-receipt retirement does so.
    /// A head, ACK, elapsed time or removed payload alone cannot justify
    /// deleting an identity or replaying an uncertain attempt as a new identity.
    fn append_published(&self, request: PublishRequest) -> Result<Record, FederationError>;

    /// Inspect the active nonzero retry epoch of an existing stream. A new
    /// stream starts at one. Reading this never upgrades an existing attempt.
    fn publication_epoch(&self, stream: StreamRef) -> Result<u64, FederationError>;

    /// Trusted-owner CAS closing one epoch and opening its monotonic successor.
    /// Old append requests are permanently rejected, even after identity rows
    /// are reclaimed. Closure itself deletes no identity or unresolved evidence.
    /// After uncertainty, reopen and inspect, never infer closure from a head.
    fn close_publication_epoch(
        &self,
        stream: StreamRef,
        expected: u64,
    ) -> Result<u64, FederationError>;

    /// Read exact retained evidence in an active or closed retry epoch. Absence
    /// after explicit retirement is not a negative commit verdict.
    fn inspect_publication(
        &self,
        stream: StreamRef,
        retry_epoch: u64,
        publish_id: RequestId,
    ) -> Result<Option<Position>, FederationError>;

    /// Release at most `MAX_PUBLICATION_RETIRE_IDS` identities in closed epochs,
    /// only against exact owner-confirmed receipts. Validate the whole bounded
    /// batch before deleting anything. Unknown attempts remain inspectable and
    /// charged; elapsed time, payload trim and sequence heads release no slots.
    /// A repeated release of an absent identity in a closed epoch is harmless,
    /// but absence cannot authorize retry. This does not remove record payloads.
    fn retire_publication_identities(
        &self,
        receipts: &[PublicationReceipt],
    ) -> Result<usize, FederationError>;

    /// Atomically retire at most `max_records` contiguous publisher payloads
    /// through the exact position. An active-epoch replay of a retired payload
    /// remains indeterminate rather than creating a duplicate publication;
    /// closed-epoch appends remain rejected. The last
    /// deleted position is retained as a digest-only cursor anchor. At most
    /// `MAX_RETIRE_BYTES` of payload is removed per call; callers may retry a
    /// smaller through-position after `Capacity`. This is explicit maintenance,
    /// not evidence that any replica has committed the retired history.
    fn retire_published_history(
        &self,
        stream: StreamRef,
        through: Position,
        max_records: usize,
    ) -> Result<PublishedRetirement, FederationError>;

    /// Atomically authorize and persist a node-self subscription Open.
    fn open(&self, request: OpenRequest) -> Result<OpenResult, FederationError>;

    /// Open using a verified hosted or node subject at trusted local time.
    fn open_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: OpenRequest,
    ) -> Result<OpenResult, FederationError>;

    /// Read a node-self subscription's current publisher-side control state.
    fn inspect_subscription(
        &self,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError>;

    /// Inspect under a verified subject and current trusted-time authority.
    fn inspect_subscription_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError>;

    /// Idempotently close a node-self subscription under current authority.
    fn close_subscription(
        &self,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError>;

    /// Close under a verified subject with its current authority checks.
    fn close_subscription_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError>;

    /// Persist a publisher's Open result under current local receive authority.
    fn install_subscription(
        &self,
        request: InstallSubscriptionRequest,
    ) -> Result<OpenResult, FederationError>;

    /// Disclose a bounded node-self page under current publisher authority.
    fn read(&self, request: ReadRequest) -> Result<ReadPage, FederationError>;

    /// Disclose a bounded page under a verified hosted or node subject.
    fn read_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: ReadRequest,
    ) -> Result<ReadPage, FederationError>;

    /// Atomically check local receive authority and persist one verified record.
    fn accept(&self, request: AcceptRequest) -> Result<AcceptResult, FederationError>;

    /// Read accepted records locally without advancing the projection cursor.
    /// The store rechecks the receiver's current authority and verifies the
    /// exact baseline/cursor before returning a bounded page.
    fn read_inbox(&self, request: InboxReadRequest) -> Result<InboxReadPage, FederationError>;

    /// Record a node-self subscriber's durable receipt at the publisher.
    fn acknowledge(&self, request: AcknowledgeRequest) -> Result<Position, FederationError>;

    /// Record a verified subject's durable receipt under current authority.
    fn acknowledge_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: AcknowledgeRequest,
    ) -> Result<Position, FederationError>;

    /// Advance only to a locally accepted position after application commit.
    fn record_projection_progress(
        &self,
        request: ProjectionProgress,
    ) -> Result<Position, FederationError>;

    /// Delete at most `max_records` and `MAX_RETIRE_BYTES` of receiver inbox
    /// payloads at or below the durable projection position. Unprojected
    /// accepted records remain intact. A call may stop before `max_records`
    /// when it reaches the byte bound.
    fn retire_projected_inbox(
        &self,
        subscription: SubscriptionRef,
        max_records: usize,
    ) -> Result<InboxRetirement, FederationError>;
}

impl<T: FederationStore + ?Sized> FederationStore for Arc<T> {
    fn authorize_subscription_delivery(
        &self,
        subject: &FederationSubject,
        request: InspectSubscriptionRequest,
        payload: bool,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        (**self).authorize_subscription_delivery(subject, request, payload, now_ms)
    }

    fn set_peer_admission(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        admission: PeerAdmission,
    ) -> Result<u64, FederationError> {
        (**self).set_peer_admission(peer, expected_revision, admission)
    }

    fn bind_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationStore>, crate::FederationError> {
        (**self).bind_decision(decision)
    }
    fn local_node(&self) -> FederationNodeId {
        (**self).local_node()
    }

    fn set_peer_authority(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        enabled: bool,
    ) -> Result<u64, FederationError> {
        (**self).set_peer_authority(peer, expected_revision, enabled)
    }

    fn set_export_authority(
        &self,
        peer: FederationNodeId,
        export: ExportName,
        expected_revision: Option<u64>,
        access: ExportAccess,
    ) -> Result<u64, FederationError> {
        (**self).set_export_authority(peer, export, expected_revision, access)
    }

    fn set_subject_grant(
        &self,
        expected_revision: Option<u64>,
        grant: SubjectGrant,
    ) -> Result<u64, FederationError> {
        (**self).set_subject_grant(expected_revision, grant)
    }

    fn subject_grant(
        &self,
        subject: &HostedSubject,
        presenter: FederationNodeId,
        stream: StreamRef,
    ) -> Result<Option<SubjectGrantEntry>, FederationError> {
        (**self).subject_grant(subject, presenter, stream)
    }

    fn scan_subject_grants(
        &self,
        after: Option<&SubjectGrantKey>,
        max: usize,
    ) -> Result<Vec<SubjectGrantEntry>, FederationError> {
        (**self).scan_subject_grants(after, max)
    }

    fn declare_stream(&self, spec: StreamSpec) -> Result<(), FederationError> {
        (**self).declare_stream(spec)
    }

    fn append_published(&self, request: PublishRequest) -> Result<Record, FederationError> {
        (**self).append_published(request)
    }

    fn publication_epoch(&self, stream: StreamRef) -> Result<u64, FederationError> {
        (**self).publication_epoch(stream)
    }

    fn close_publication_epoch(
        &self,
        stream: StreamRef,
        expected: u64,
    ) -> Result<u64, FederationError> {
        (**self).close_publication_epoch(stream, expected)
    }

    fn inspect_publication(
        &self,
        stream: StreamRef,
        retry_epoch: u64,
        publish_id: RequestId,
    ) -> Result<Option<Position>, FederationError> {
        (**self).inspect_publication(stream, retry_epoch, publish_id)
    }

    fn retire_publication_identities(
        &self,
        receipts: &[PublicationReceipt],
    ) -> Result<usize, FederationError> {
        (**self).retire_publication_identities(receipts)
    }

    fn retire_published_history(
        &self,
        stream: StreamRef,
        through: Position,
        max_records: usize,
    ) -> Result<PublishedRetirement, FederationError> {
        (**self).retire_published_history(stream, through, max_records)
    }

    fn open(&self, request: OpenRequest) -> Result<OpenResult, FederationError> {
        (**self).open(request)
    }

    fn open_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: OpenRequest,
    ) -> Result<OpenResult, FederationError> {
        (**self).open_as(subject, now_ms, request)
    }

    fn inspect_subscription(
        &self,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError> {
        (**self).inspect_subscription(request)
    }

    fn inspect_subscription_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError> {
        (**self).inspect_subscription_as(subject, now_ms, request)
    }

    fn close_subscription(
        &self,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        (**self).close_subscription(request)
    }

    fn close_subscription_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        (**self).close_subscription_as(subject, now_ms, request)
    }

    fn install_subscription(
        &self,
        request: InstallSubscriptionRequest,
    ) -> Result<OpenResult, FederationError> {
        (**self).install_subscription(request)
    }

    fn read(&self, request: ReadRequest) -> Result<ReadPage, FederationError> {
        (**self).read(request)
    }

    fn read_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: ReadRequest,
    ) -> Result<ReadPage, FederationError> {
        (**self).read_as(subject, now_ms, request)
    }

    fn accept(&self, request: AcceptRequest) -> Result<AcceptResult, FederationError> {
        (**self).accept(request)
    }

    fn read_inbox(&self, request: InboxReadRequest) -> Result<InboxReadPage, FederationError> {
        (**self).read_inbox(request)
    }

    fn acknowledge(&self, request: AcknowledgeRequest) -> Result<Position, FederationError> {
        (**self).acknowledge(request)
    }

    fn acknowledge_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: AcknowledgeRequest,
    ) -> Result<Position, FederationError> {
        (**self).acknowledge_as(subject, now_ms, request)
    }

    fn record_projection_progress(
        &self,
        request: ProjectionProgress,
    ) -> Result<Position, FederationError> {
        (**self).record_projection_progress(request)
    }

    fn retire_projected_inbox(
        &self,
        subscription: SubscriptionRef,
        max_records: usize,
    ) -> Result<InboxRetirement, FederationError> {
        (**self).retire_projected_inbox(subscription, max_records)
    }
}
