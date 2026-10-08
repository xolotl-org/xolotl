//! Stateless reads of explicitly public streams. A verified node needs no
//! publisher-side peer or subscription row; private delivery keeps its own port.

use std::sync::Arc;

use crate::{ExportName, FederationError, FederationNodeId, Position, Record, StreamRef};

/// Maximum local public-policy rows, including disabled tombstones.
pub const MAX_PUBLIC_POLICIES: usize = 4096;
/// Hard maximum records returned in a public page.
pub const MAX_PUBLIC_READ_RECORDS: usize = 256;
/// Hard maximum payload bytes returned in a public page.
pub const MAX_PUBLIC_READ_BYTES: usize = 4 * 1024 * 1024;

/// One exact stream may become public only while empty. Disabling it is final;
/// publishing another public view after revocation requires a new StreamRef.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicStreamPolicy {
    /// Exact stream governed by this immutable public-view identity.
    pub stream: StreamRef,
    /// Whether new public disclosure is currently allowed.
    pub enabled: bool,
    /// Per-request record ceiling within the global hard limit.
    pub max_read_records: usize,
    /// Per-request payload-byte ceiling within the global hard limit.
    pub max_read_bytes: usize,
}

impl PublicStreamPolicy {
    /// Validate local stream ownership and bounded page limits.
    pub fn validate(&self, local_node: FederationNodeId) -> Result<(), FederationError> {
        if self.stream.publisher != local_node {
            return Err(FederationError::Invalid(
                "public stream has another publisher",
            ));
        }
        if self.max_read_records == 0
            || self.max_read_records > MAX_PUBLIC_READ_RECORDS
            || self.max_read_bytes == 0
            || self.max_read_bytes > MAX_PUBLIC_READ_BYTES
        {
            return Err(FederationError::Capacity);
        }
        Ok(())
    }
}

/// Current public view; its revision fences each subsequent stateless page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicStreamView {
    /// Exact publisher-owned stream.
    pub stream: StreamRef,
    /// Export containing the stream.
    pub export: ExportName,
    /// Policy revision that subsequent stateless reads must match.
    pub policy_revision: u64,
    /// Publisher's current committed head.
    pub head: Option<Position>,
    /// Earliest retained payload sequence.
    pub minimum_available: u64,
    /// Current per-request record ceiling.
    pub max_read_records: usize,
    /// Current per-request payload-byte ceiling.
    pub max_read_bytes: usize,
}

/// `authenticated_reader` is supplied only after channel-bound node proof.
/// This type never grants access to private Open, Read, Call or object APIs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicReadRequest {
    /// Node proven by the channel-bound peer proof.
    pub authenticated_reader: FederationNodeId,
    /// Exact stream whose policy is being invoked.
    pub stream: StreamRef,
    /// Revision returned by a prior public inspection.
    pub expected_policy_revision: u64,
    /// Exact last record held by the reader, if any.
    pub after: Option<Position>,
    /// Requested record ceiling within current policy.
    pub max_records: usize,
    /// Requested payload-byte ceiling within current policy.
    pub max_bytes: usize,
}

impl PublicReadRequest {
    /// Validate local publisher identity and global read limits before storage.
    pub fn validate(&self, local_node: FederationNodeId) -> Result<(), FederationError> {
        if self.authenticated_reader == local_node || self.stream.publisher != local_node {
            return Err(FederationError::Unauthorized);
        }
        if self.expected_policy_revision == 0
            || self.max_records == 0
            || self.max_records > MAX_PUBLIC_READ_RECORDS
            || self.max_bytes == 0
            || self.max_bytes > MAX_PUBLIC_READ_BYTES
        {
            return Err(FederationError::Capacity);
        }
        Ok(())
    }
}

/// Stateless public page fenced by the exact policy revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicReadPage {
    /// Revision applied while disclosing this page.
    pub policy_revision: u64,
    /// Ordered, bounded records from the requested stream.
    pub records: Vec<Record>,
    /// Publisher's current committed head.
    pub head: Option<Position>,
    /// Earliest sequence with retained payload.
    pub minimum_available: u64,
}

/// One store transaction must recheck the policy, explicit peer bans and the
/// cursor before releasing bytes. Implementations keep no reader-specific row.
pub trait FederationPublicReadStore: Send + Sync {
    /// Read-only delivery check under the exact admitted public-policy
    /// revision and current unconfigured-peer boundary. No payload reads or
    /// time persistence. Run blocking implementations on bounded host work;
    /// unsupported custom stores deny protected delivery.
    fn authorize_public_delivery(
        &self,
        _reader: FederationNodeId,
        _stream: StreamRef,
        _revision: u64,
    ) -> Result<(), FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Bind verified remote authority to each actual backend decision.
    /// Unsupported backends must reject, never substitute a preflight check.
    fn bind_public_decision(
        &self,
        _decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationPublicReadStore>, crate::FederationError> {
        Err(crate::FederationError::Unauthorized)
    }
    /// Publisher node owned by this local public-policy store.
    fn local_node(&self) -> FederationNodeId;

    /// Management-only view, including disabled policies. This does not grant
    /// remote read access and supports declarative host reconciliation.
    fn public_stream_policy(
        &self,
        stream: StreamRef,
    ) -> Result<Option<(PublicStreamPolicy, u64)>, FederationError>;

    /// Bounded by `MAX_PUBLIC_POLICIES`; includes disabled tombstones so a host
    /// can reconcile policies omitted from its current configuration.
    fn list_public_stream_policies(
        &self,
    ) -> Result<Vec<(PublicStreamPolicy, u64)>, FederationError>;

    /// CAS an exact stream policy; disabling it permanently closes this view.
    fn set_public_stream_policy(
        &self,
        expected_revision: Option<u64>,
        policy: PublicStreamPolicy,
    ) -> Result<PublicStreamView, FederationError>;

    /// Inspect a public view after checking the authenticated reader.
    /// The reader must have no managed peer row, whether enabled or disabled.
    fn inspect_public_stream(
        &self,
        authenticated_reader: FederationNodeId,
        stream: StreamRef,
    ) -> Result<PublicStreamView, FederationError>;

    /// In one decision, recheck policy, cursor, and bounded disclosure.
    /// Also recheck absence of a managed peer row in the same snapshot.
    fn read_public_stream(
        &self,
        request: PublicReadRequest,
    ) -> Result<PublicReadPage, FederationError>;
}

impl<T: FederationPublicReadStore + ?Sized> FederationPublicReadStore for Arc<T> {
    fn authorize_public_delivery(
        &self,
        reader: FederationNodeId,
        stream: StreamRef,
        revision: u64,
    ) -> Result<(), FederationError> {
        (**self).authorize_public_delivery(reader, stream, revision)
    }

    fn bind_public_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationPublicReadStore>, crate::FederationError> {
        (**self).bind_public_decision(decision)
    }
    fn local_node(&self) -> FederationNodeId {
        (**self).local_node()
    }

    fn public_stream_policy(
        &self,
        stream: StreamRef,
    ) -> Result<Option<(PublicStreamPolicy, u64)>, FederationError> {
        (**self).public_stream_policy(stream)
    }

    fn list_public_stream_policies(
        &self,
    ) -> Result<Vec<(PublicStreamPolicy, u64)>, FederationError> {
        (**self).list_public_stream_policies()
    }

    fn set_public_stream_policy(
        &self,
        expected_revision: Option<u64>,
        policy: PublicStreamPolicy,
    ) -> Result<PublicStreamView, FederationError> {
        (**self).set_public_stream_policy(expected_revision, policy)
    }

    fn inspect_public_stream(
        &self,
        authenticated_reader: FederationNodeId,
        stream: StreamRef,
    ) -> Result<PublicStreamView, FederationError> {
        (**self).inspect_public_stream(authenticated_reader, stream)
    }

    fn read_public_stream(
        &self,
        request: PublicReadRequest,
    ) -> Result<PublicReadPage, FederationError> {
        (**self).read_public_stream(request)
    }
}

/// Service-level public-page limit, no larger than the global hard bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicReadLimits {
    /// Maximum records allowed through this service facade.
    pub max_records: usize,
    /// Maximum payload bytes allowed through this service facade.
    pub max_bytes: usize,
}

impl Default for PublicReadLimits {
    fn default() -> Self {
        Self {
            max_records: MAX_PUBLIC_READ_RECORDS,
            max_bytes: MAX_PUBLIC_READ_BYTES,
        }
    }
}

/// Optional service facade for a transport or embedded host. Per-session and
/// concurrent request limits belong to the host's global admission semaphore.
#[derive(Clone)]
pub struct FederationPublicService {
    store: Arc<dyn FederationPublicReadStore>,
    limits: PublicReadLimits,
}

impl FederationPublicService {
    /// Bind the authenticated reader without making a preflight authorization.
    pub fn with_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<Self, FederationError> {
        Self::new(self.store.bind_public_decision(decision)?, self.limits)
    }

    /// Bind a store and validate its service-level public read limits.
    pub fn new(
        store: Arc<dyn FederationPublicReadStore>,
        limits: PublicReadLimits,
    ) -> Result<Self, FederationError> {
        if limits.max_records == 0
            || limits.max_records > MAX_PUBLIC_READ_RECORDS
            || limits.max_bytes == 0
            || limits.max_bytes > MAX_PUBLIC_READ_BYTES
        {
            return Err(FederationError::Capacity);
        }
        Ok(Self { store, limits })
    }

    /// Borrow the local authority store for host assembly and inspection.
    pub fn store(&self) -> &Arc<dyn FederationPublicReadStore> {
        &self.store
    }

    /// Inspect one explicitly public stream as a proven node.
    pub fn inspect(
        &self,
        authenticated_reader: FederationNodeId,
        stream: StreamRef,
    ) -> Result<PublicStreamView, FederationError> {
        self.store
            .inspect_public_stream(authenticated_reader, stream)
    }

    /// Read and verify a bounded page under the current public policy revision.
    pub fn read(&self, request: PublicReadRequest) -> Result<PublicReadPage, FederationError> {
        request.validate(self.store.local_node())?;
        if request.max_records > self.limits.max_records
            || request.max_bytes > self.limits.max_bytes
        {
            return Err(FederationError::Capacity);
        }
        let page = self.store.read_public_stream(request)?;
        if page.policy_revision != request.expected_policy_revision
            || page.records.len() > request.max_records
        {
            return Err(FederationError::Corrupt);
        }
        if page.minimum_available == 0 {
            return Err(FederationError::Corrupt);
        }
        let mut bytes = 0usize;
        let mut next_sequence = request.after.map_or(Some(page.minimum_available), |after| {
            after.sequence().checked_add(1)
        });
        for record in &page.records {
            if record.stream() != request.stream || Some(record.sequence()) != next_sequence {
                return Err(FederationError::Corrupt);
            }
            next_sequence = record.sequence().checked_add(1);
            bytes = bytes
                .checked_add(record.payload().len())
                .ok_or(FederationError::Corrupt)?;
        }
        if bytes > request.max_bytes {
            return Err(FederationError::Corrupt);
        }
        Ok(page)
    }
}
