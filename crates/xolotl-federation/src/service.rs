use std::sync::Arc;

use crate::{
    AcceptRequest, AcceptResult, AcknowledgeRequest, CloseSubscriptionRequest,
    CloseSubscriptionResult, ExportAccess, ExportName, FederationError, FederationNodeId,
    FederationStore, FederationSubject, InboxReadPage, InboxReadRequest,
    InspectSubscriptionRequest, InstallSubscriptionRequest, OpenRequest, OpenResult, Position,
    ProjectionProgress, PublishRequest, ReadPage, ReadRequest, Record, StreamSpec, SubjectGrant,
    SubjectGrantEntry, SubjectGrantKey, SubscriptionInspection,
};

/// Service-level limits checked before forwarding to the authoritative store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationLimits {
    /// Maximum payload bytes in one immutable published record.
    pub max_record_bytes: usize,
    /// Maximum records requested in one private read page.
    pub max_read_records: usize,
    /// Maximum payload bytes requested in one private read page.
    pub max_read_bytes: usize,
}

impl Default for FederationLimits {
    fn default() -> Self {
        Self {
            max_record_bytes: 1024 * 1024,
            max_read_records: 256,
            max_read_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Stateless admission and validation around one authoritative store.
/// The store remains responsible for atomic policy checks and state changes.
#[derive(Clone)]
pub struct FederationService {
    store: Arc<dyn FederationStore>,
    limits: FederationLimits,
}

impl FederationService {
    /// Bind a verified remote context; every backend decision checks live rows.
    pub fn with_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<Self, FederationError> {
        Self::new(self.store.bind_decision(decision)?, self.limits)
    }

    /// Bind a store to positive per-request limits.
    pub fn new(
        store: Arc<dyn FederationStore>,
        limits: FederationLimits,
    ) -> Result<Self, FederationError> {
        if limits.max_record_bytes == 0
            || limits.max_read_records == 0
            || limits.max_read_bytes == 0
        {
            return Err(FederationError::Invalid(
                "federation limits must be nonzero",
            ));
        }
        Ok(Self { store, limits })
    }

    /// Borrow the authority store for host composition.
    pub fn store(&self) -> &Arc<dyn FederationStore> {
        &self.store
    }

    /// Node identity owned by the bound store.
    pub fn local_node(&self) -> FederationNodeId {
        self.store.local_node()
    }

    /// Per-request limits enforced by this service facade.
    pub const fn limits(&self) -> FederationLimits {
        self.limits
    }

    /// CAS a local peer enablement decision.
    pub fn set_peer_authority(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        enabled: bool,
    ) -> Result<u64, FederationError> {
        if peer == self.local_node() {
            return Err(FederationError::Invalid("peer cannot be the local node"));
        }
        self.store
            .set_peer_authority(peer, expected_revision, enabled)
    }

    /// CAS the exact online-key policy in the bound business authority store.
    pub fn set_peer_admission(
        &self,
        peer: FederationNodeId,
        expected_revision: Option<u64>,
        admission: crate::PeerAdmission,
    ) -> Result<u64, FederationError> {
        if peer == self.local_node() {
            return Err(FederationError::Unauthorized);
        }
        admission.validate()?;
        self.store
            .set_peer_admission(peer, expected_revision, admission)
    }

    /// CAS the directional access of one peer to one export.
    pub fn set_export_authority(
        &self,
        peer: FederationNodeId,
        export: ExportName,
        expected_revision: Option<u64>,
        access: ExportAccess,
    ) -> Result<u64, FederationError> {
        if peer == self.local_node() {
            return Err(FederationError::Invalid("peer cannot be the local node"));
        }
        self.store
            .set_export_authority(peer, export, expected_revision, access)
    }

    /// CAS an exact hosted-subject grant under local publisher ownership.
    pub fn set_subject_grant(
        &self,
        expected_revision: Option<u64>,
        grant: SubjectGrant,
    ) -> Result<u64, FederationError> {
        grant.validate(self.local_node())?;
        self.store.set_subject_grant(expected_revision, grant)
    }

    /// Read the current local grant for one subject, presenter and stream.
    pub fn subject_grant(
        &self,
        subject: &crate::HostedSubject,
        presenter: FederationNodeId,
        stream: crate::StreamRef,
    ) -> Result<Option<SubjectGrantEntry>, FederationError> {
        self.store.subject_grant(subject, presenter, stream)
    }

    /// Scan a bounded page of local subject grants after an exclusive key.
    pub fn scan_subject_grants(
        &self,
        after: Option<&SubjectGrantKey>,
        max: usize,
    ) -> Result<Vec<SubjectGrantEntry>, FederationError> {
        self.store.scan_subject_grants(after, max)
    }

    /// Declare a locally owned stream under one export.
    pub fn declare_stream(&self, spec: StreamSpec) -> Result<(), FederationError> {
        if spec.stream.publisher != self.local_node() {
            return Err(FederationError::Invalid("stream has another publisher"));
        }
        self.store.declare_stream(spec)
    }

    /// Append one idempotent application event and return its committed record.
    pub fn append_published(&self, request: PublishRequest) -> Result<Record, FederationError> {
        if request.stream.publisher != self.local_node() {
            return Err(FederationError::Invalid("stream has another publisher"));
        }
        if request.payload.len() > self.limits.max_record_bytes {
            return Err(FederationError::Capacity);
        }
        self.store.append_published(request)
    }

    /// Open a private subscription as an authenticated node principal.
    pub fn open(&self, request: OpenRequest) -> Result<OpenResult, FederationError> {
        self.open_as(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
        )
    }

    /// Open under a verified subject using trusted local time.
    pub fn open_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: OpenRequest,
    ) -> Result<OpenResult, FederationError> {
        if request.stream.publisher != self.local_node()
            || request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.local_node()
        {
            return Err(FederationError::Unauthorized);
        }
        self.store.open_as(subject, now_ms, request)
    }

    /// Inspect a node-self subscription at its publisher.
    pub fn inspect_subscription(
        &self,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError> {
        self.inspect_subscription_as(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
        )
    }

    /// Inspect under a verified subject and current authority.
    pub fn inspect_subscription_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, FederationError> {
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.local_node()
        {
            return Err(FederationError::Unauthorized);
        }
        self.store.inspect_subscription_as(subject, now_ms, request)
    }

    /// Close a node-self subscription by stable control request ID.
    pub fn close_subscription(
        &self,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        self.close_subscription_as(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
        )
    }

    /// Close under a verified subject and current authority.
    pub fn close_subscription_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, FederationError> {
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.local_node()
        {
            return Err(FederationError::Unauthorized);
        }
        self.store.close_subscription_as(subject, now_ms, request)
    }

    /// Persist a publisher's Open result under local receive authority.
    pub fn install_subscription(
        &self,
        request: InstallSubscriptionRequest,
    ) -> Result<OpenResult, FederationError> {
        if request.opened.subscription.subscriber != self.local_node()
            || request.opened.stream.publisher != request.authenticated_publisher
            || request.authenticated_publisher == self.local_node()
        {
            return Err(FederationError::Unauthorized);
        }
        self.store.install_subscription(request)
    }

    /// Read a bounded private page as the authenticated subscriber node.
    pub fn read(&self, request: ReadRequest) -> Result<ReadPage, FederationError> {
        self.read_as(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
        )
    }

    /// Read a bounded private page under a verified subject.
    pub fn read_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: ReadRequest,
    ) -> Result<ReadPage, FederationError> {
        if request.authenticated_subscriber != request.subscription.subscriber
            || request.authenticated_subscriber == self.local_node()
        {
            return Err(FederationError::Unauthorized);
        }
        if request.max_records == 0
            || request.max_bytes == 0
            || request.max_records > self.limits.max_read_records
            || request.max_bytes > self.limits.max_read_bytes
        {
            return Err(FederationError::Capacity);
        }
        let max_records = request.max_records;
        let max_bytes = request.max_bytes;
        let page = self.store.read_as(subject, now_ms, request)?;
        if page.records.len() > max_records {
            return Err(FederationError::Corrupt);
        }
        let mut bytes = 0usize;
        for record in &page.records {
            bytes = bytes
                .checked_add(record.payload().len())
                .ok_or(FederationError::Corrupt)?;
        }
        if bytes > max_bytes {
            return Err(FederationError::Corrupt);
        }
        Ok(page)
    }

    /// Validate and durably accept one record into the local receiver inbox.
    pub fn accept(&self, request: AcceptRequest) -> Result<AcceptResult, FederationError> {
        if request.subscription.subscriber != self.local_node()
            || request.record.stream().publisher != request.authenticated_publisher
            || request.authenticated_publisher == self.local_node()
        {
            return Err(FederationError::Unauthorized);
        }
        if request.record.payload().len() > self.limits.max_record_bytes {
            return Err(FederationError::Capacity);
        }
        self.store.accept(request)
    }

    /// Read a bounded, verified page of already accepted local records.
    pub fn read_inbox(&self, request: InboxReadRequest) -> Result<InboxReadPage, FederationError> {
        if request.max_records == 0
            || request.max_bytes == 0
            || request.max_records > self.limits.max_read_records
            || request.max_bytes > self.limits.max_read_bytes
        {
            return Err(FederationError::Capacity);
        }
        let page = self.store.read_inbox(request)?;
        if page.records.len() > request.max_records
            || page.records.iter().try_fold(0usize, |bytes, record| {
                bytes
                    .checked_add(record.payload().len())
                    .ok_or(FederationError::Corrupt)
            })? > request.max_bytes
        {
            return Err(FederationError::Corrupt);
        }
        Ok(page)
    }

    /// Report a durable node-self receiver position to the publisher.
    pub fn acknowledge(&self, request: AcknowledgeRequest) -> Result<Position, FederationError> {
        self.acknowledge_as(
            FederationSubject::Node(request.authenticated_subscriber),
            0,
            request,
        )
    }

    /// Report a durable position under a verified subject.
    pub fn acknowledge_as(
        &self,
        subject: FederationSubject,
        now_ms: u64,
        request: AcknowledgeRequest,
    ) -> Result<Position, FederationError> {
        if request.subscription.subscriber != request.authenticated_subscriber
            || request.authenticated_subscriber == self.local_node()
        {
            return Err(FederationError::Unauthorized);
        }
        self.store.acknowledge_as(subject, now_ms, request)
    }

    /// Record application progress after its projection transaction commits.
    pub fn record_projection_progress(
        &self,
        request: ProjectionProgress,
    ) -> Result<Position, FederationError> {
        if request.subscription.subscriber != self.local_node() {
            return Err(FederationError::Unauthorized);
        }
        self.store.record_projection_progress(request)
    }
}
