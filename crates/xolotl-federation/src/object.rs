//! Exact, expiring object delivery grants. A BlobRef is content identity, never
//! authority; neither public streams nor private subscriptions imply a grant.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest as _, Sha384};
use xolotl_state::object::{ObjectMetadata, ObjectRead};
use xolotl_state::{StateError, StateFailure};
use xolotl_types::BlobRef;

use crate::{FederationError, FederationNodeId, FederationSubject, VerifiedFederationPeerProof};

/// Maximum bytes requested in one federated object read.
pub const MAX_OBJECT_CHUNK_BYTES: usize = 1024 * 1024;
/// Maximum active object grants retained by a store.
pub const MAX_OBJECT_GRANTS: usize = 4096;
/// Maximum receiver transfer identities retained by a store.
pub const MAX_OBJECT_TRANSFERS: usize = 8192;

/// Receiver-generated identity retained across reconnection and cold restart.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectTransferId([u8; 16]);

impl ObjectTransferId {
    /// Construct a receiver-generated transfer identity from bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the canonical transfer identity bytes.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Provider-local, never reused identity allocated durably by the grant store.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectGrantId(u64);

impl ObjectGrantId {
    /// Validate a nonzero provider-local grant identity.
    pub fn new(value: u64) -> Result<Self, FederationError> {
        if value == 0 {
            return Err(FederationError::Invalid("object grant ID must be positive"));
        }
        Ok(Self(value))
    }

    /// Return the provider-local grant number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Trusted host decision for one presenter, principal, immutable object and
/// half-open byte range. A new ID is required to change any immutable field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectGrantSpec {
    /// Authenticated node allowed to present this grant.
    pub presenter: FederationNodeId,
    /// Node or proven hosted principal receiving the bytes.
    pub subject: FederationSubject,
    /// Immutable content identity covered by this grant.
    pub blob: BlobRef,
    /// First allowed byte offset, inclusive.
    pub range_start: u64,
    /// Last allowed byte offset, exclusive.
    pub range_end: u64,
    /// Grant expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Includes retries; debited before backend I/O, with no refund after an
    /// uncertain or cancelled read.
    pub max_total_bytes: u64,
    /// Maximum bytes in any one read against this grant.
    pub max_chunk_bytes: usize,
}

impl ObjectGrantSpec {
    /// Validate presenter, subject, content range and disclosure budget.
    pub fn validate(&self, local_node: FederationNodeId) -> Result<(), FederationError> {
        if self.presenter == local_node
            || matches!(&self.subject, FederationSubject::Node(node) if *node != self.presenter)
        {
            return Err(FederationError::Unauthorized);
        }
        if let FederationSubject::Hosted(hosted) = &self.subject
            && (hosted.namespace.is_empty()
                || hosted.namespace.len() > 256
                || hosted.namespace.chars().any(char::is_control)
                || hosted.subject.is_empty()
                || hosted.subject.len() > 256
                || hosted.subject.chars().any(char::is_control))
        {
            return Err(FederationError::Invalid("invalid hosted object subject"));
        }
        if !BlobRef::is_valid_hash(&self.blob.hash)
            || self
                .blob
                .mime
                .as_ref()
                .is_some_and(|mime| mime.len() > 256 || mime.chars().any(char::is_control))
            || self.range_start > self.range_end
            || self.range_end > self.blob.size
            || self.expires_at_ms == 0
        {
            return Err(FederationError::Invalid("invalid object grant"));
        }
        if self.max_chunk_bytes == 0
            || self.max_chunk_bytes > MAX_OBJECT_CHUNK_BYTES
            || self.max_total_bytes < self.range_end - self.range_start
        {
            return Err(FederationError::Capacity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Current state of one provider-issued object read grant.
pub struct ObjectGrantView {
    /// Provider-local grant identity.
    pub id: ObjectGrantId,
    /// Immutable terms of this grant.
    pub spec: ObjectGrantSpec,
    /// Revision used for conditional reads and revocation.
    pub revision: u64,
    /// Whether the grant still allows reads.
    pub enabled: bool,
    /// Bytes charged to the durable disclosure budget.
    pub charged_bytes: u64,
}

/// The presenter and subject are provided only after channel-bound node and
/// per-request hosted-subject proof. The request repeats exact content identity
/// so a stale grant ID cannot silently select another object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectReadRequest {
    /// Node authenticated by the transport.
    pub authenticated_presenter: FederationNodeId,
    /// Principal proven for this read.
    pub subject: FederationSubject,
    /// Receiver-generated identity stable across read retries.
    pub transfer: ObjectTransferId,
    /// Provider-local grant authorizing the read.
    pub grant: ObjectGrantId,
    /// Grant revision observed by the receiver.
    pub expected_revision: u64,
    /// Exact immutable object identity expected by the receiver.
    pub blob: BlobRef,
    /// First requested byte offset.
    pub offset: u64,
    /// Maximum bytes requested from this offset.
    pub max_bytes: usize,
}

/// The locally verified Session path used for an object read. This is host
/// admission evidence, not a field supplied by the remote wire request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectReadAdmission {
    /// An authenticated peer admitted under a configured private peer row.
    Private,
    /// A public or Guest Session admitted only while no peer row exists.
    Unconfigured,
}

/// Non-wire authority for one object read. The peer proof can only be
/// produced by successful session signature verification; the admission path
/// is selected locally from that Session's policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectReadAuthority {
    proof: VerifiedFederationPeerProof,
    admission: ObjectReadAdmission,
}

impl ObjectReadAuthority {
    /// Bind a verified peer proof to the locally selected admission path.
    pub const fn new(proof: VerifiedFederationPeerProof, admission: ObjectReadAdmission) -> Self {
        Self { proof, admission }
    }

    /// Return the verified session proof for transactional policy checks.
    pub const fn proof(self) -> VerifiedFederationPeerProof {
        self.proof
    }

    /// Return the locally selected admission path.
    pub const fn admission(self) -> ObjectReadAdmission {
        self.admission
    }

    /// Check the request's claimed presenter and the proof's validity window.
    /// Stores call this inside their write transaction or memory lock.
    pub fn check_request(
        self,
        request: &ObjectReadRequest,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        if self.proof.node_id() != request.authenticated_presenter
            || now_ms >= self.proof.expires_ms()
        {
            return Err(FederationError::Unauthorized);
        }
        Ok(())
    }
}

impl ObjectReadRequest {
    /// Validate request identity, presenter and chunk bound.
    pub fn validate(&self, local_node: FederationNodeId) -> Result<(), FederationError> {
        if self.authenticated_presenter == local_node
            || matches!(&self.subject, FederationSubject::Node(node) if *node != self.authenticated_presenter)
        {
            return Err(FederationError::Unauthorized);
        }
        if self.expected_revision == 0
            || self.transfer.as_bytes() == [0; 16]
            || !BlobRef::is_valid_hash(&self.blob.hash)
        {
            return Err(FederationError::Invalid("invalid object read identity"));
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_OBJECT_CHUNK_BYTES {
            return Err(FederationError::Capacity);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One confirmed page of bytes under an exact object grant.
pub struct ObjectReadPage {
    /// Receiver transfer identity from the request.
    pub transfer: ObjectTransferId,
    /// Provider grant identity used for the read.
    pub grant: ObjectGrantId,
    /// Grant revision used to confirm disclosure.
    pub revision: u64,
    /// Starting byte offset of the returned bytes.
    pub offset: u64,
    /// Bytes returned by the object backend.
    pub bytes: Vec<u8>,
    /// Whether the backend reached the end of the complete object.
    pub end_of_object: bool,
    /// Whether the response reached this grant’s range end.
    pub end_of_range: bool,
}

/// Native provenance retained from a successful local object read. Wire pages
/// cannot construct this context. Preserve each checked view separately:
/// disclosure policies need not be monotonic under provenance union.
pub struct ObjectDeliveryContext {
    request: ObjectReadRequest,
    authority: ObjectReadAuthority,
    metadata: [ObjectMetadata; 3],
}

/// A locally read page and its original disclosure context. Only the page is
/// serialized; the context stays with the service-controlled delivery owner.
pub struct ObjectReadDelivery {
    /// Confirmed bytes and wire-visible identity.
    pub page: ObjectReadPage,
    /// Native metadata and authority checked while reading these bytes.
    pub context: ObjectDeliveryContext,
}

/// A persistent decision boundary. `reserve` checks identity, current peer
/// authority, range, revision, expiry and quota in one transaction. `confirm`
/// rechecks the same authority immediately before bytes leave the service.
/// Charging a failed read is conservative and prevents cancellation refunds
/// from exceeding the grant's durable disclosure budget.
pub trait FederationObjectReadStore: Send + Sync {
    /// Read-only validation of the reserved transfer and original grant at
    /// final delivery. Reuse confirm's authority/range/transfer rules without
    /// any time write, reservation, refund, quota charge or object I/O. Custom
    /// stores without this contract deny disclosure; schedule blocking stores
    /// on bounded host workers.
    fn authorize_object_delivery(
        &self,
        _request: &ObjectReadRequest,
        _authority: ObjectReadAuthority,
        _now_ms: u64,
    ) -> Result<(), FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Bind verified remote authority to each actual backend decision.
    /// Unsupported backends must reject, never substitute a preflight check.
    fn bind_object_decision(
        &self,
        _decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationObjectReadStore>, crate::FederationError> {
        Err(crate::FederationError::Unauthorized)
    }
    /// Return the provider node that owns this grant store.
    fn local_node(&self) -> FederationNodeId;
    /// Issue a grant after host policy validates its exact terms.
    fn issue_object_grant(
        &self,
        spec: ObjectGrantSpec,
        now_ms: u64,
    ) -> Result<ObjectGrantView, FederationError>;
    /// Read the current state of one grant by provider-local ID.
    fn object_grant(&self, id: ObjectGrantId) -> Result<Option<ObjectGrantView>, FederationError>;
    /// Management view, including disabled rows, for declarative host setup.
    fn list_object_grants(&self) -> Result<Vec<ObjectGrantView>, FederationError>;
    /// Revoke a grant at the caller’s expected revision.
    fn revoke_object_grant(
        &self,
        id: ObjectGrantId,
        expected_revision: u64,
    ) -> Result<ObjectGrantView, FederationError>;
    /// Atomically authorize and charge a read before backend I/O.
    fn reserve_object_read(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<ObjectGrantView, FederationError>;
    /// Recheck current authority before releasing reserved bytes.
    fn confirm_object_read(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<(), FederationError>;
    /// Remove at most `limit` expired rows, including revoked tombstones. Monotonic IDs remain
    /// durable, so retirement cannot revive a previously issued capability.
    fn retire_object_grants(&self, now_ms: u64, limit: usize) -> Result<usize, FederationError>;
}

impl<T: FederationObjectReadStore + ?Sized> FederationObjectReadStore for Arc<T> {
    fn authorize_object_delivery(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        (**self).authorize_object_delivery(request, authority, now_ms)
    }

    fn bind_object_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationObjectReadStore>, crate::FederationError> {
        (**self).bind_object_decision(decision)
    }
    fn local_node(&self) -> FederationNodeId {
        (**self).local_node()
    }
    fn issue_object_grant(
        &self,
        spec: ObjectGrantSpec,
        now_ms: u64,
    ) -> Result<ObjectGrantView, FederationError> {
        (**self).issue_object_grant(spec, now_ms)
    }
    fn object_grant(&self, id: ObjectGrantId) -> Result<Option<ObjectGrantView>, FederationError> {
        (**self).object_grant(id)
    }
    fn list_object_grants(&self) -> Result<Vec<ObjectGrantView>, FederationError> {
        (**self).list_object_grants()
    }
    fn revoke_object_grant(
        &self,
        id: ObjectGrantId,
        expected_revision: u64,
    ) -> Result<ObjectGrantView, FederationError> {
        (**self).revoke_object_grant(id, expected_revision)
    }
    fn reserve_object_read(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<ObjectGrantView, FederationError> {
        (**self).reserve_object_read(request, authority, now_ms)
    }
    fn confirm_object_read(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        now_ms: u64,
    ) -> Result<(), FederationError> {
        (**self).confirm_object_read(request, authority, now_ms)
    }
    fn retire_object_grants(&self, now_ms: u64, limit: usize) -> Result<usize, FederationError> {
        (**self).retire_object_grants(now_ms, limit)
    }
}

/// Trusted wall-clock source for grant expiry checks.
pub trait FederationObjectClock: Send + Sync {
    /// Return current Unix time in milliseconds.
    fn now_ms(&self) -> Result<u64, FederationError>;
}

impl<F: Fn() -> Result<u64, FederationError> + Send + Sync> FederationObjectClock for F {
    fn now_ms(&self) -> Result<u64, FederationError> {
        self()
    }
}

/// Wall-clock adapter backed by the host operating system.
pub struct SystemObjectClock;

impl FederationObjectClock for SystemObjectClock {
    fn now_ms(&self) -> Result<u64, FederationError> {
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_error| FederationError::ClockRollback)?
                .as_millis(),
        )
        .map_err(|_error| FederationError::Capacity)
    }
}

/// The host must decide whether the object's current provenance may cross this
/// subject boundary. The service asks both before and after backend I/O, then
/// again at delayed transport delivery using those retained metadata views.
pub trait FederationObjectDisclosure: Send + Sync {
    /// Decide whether this subject may receive the current object provenance.
    fn allows(&self, subject: &FederationSubject, metadata: &ObjectMetadata) -> bool;
}

impl<F: Fn(&FederationSubject, &ObjectMetadata) -> bool + Send + Sync> FederationObjectDisclosure
    for F
{
    fn allows(&self, subject: &FederationSubject, metadata: &ObjectMetadata) -> bool {
        self(subject, metadata)
    }
}

#[derive(Clone)]
/// Host service coordinating grants, object reads and disclosure checks.
pub struct FederationObjectReadService {
    store: Arc<dyn FederationObjectReadStore>,
    clock: Arc<dyn FederationObjectClock>,
    disclosure: Arc<dyn FederationObjectDisclosure>,
    max_chunk_bytes: usize,
}

impl FederationObjectReadService {
    /// Recheck current authority and mutable disclosure policy at final
    /// transport handoff against the exact locally retained metadata views.
    /// No payload/metadata reread, quota charge or business mutation occurs.
    /// Store reads and host clock/policy callbacks can block or perform trusted
    /// time work, so adapters run this on bounded host workers. Rejection does
    /// not undo the admitted read or refund its quota.
    pub fn authorize_delivery(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        context: &ObjectDeliveryContext,
    ) -> Result<(), FederationError> {
        if context.request != *request || context.authority != authority {
            return Err(FederationError::Unauthorized);
        }
        self.store
            .authorize_object_delivery(request, authority, self.clock.now_ms()?)?;
        if context
            .metadata
            .iter()
            .any(|metadata| !self.disclosure.allows(&request.subject, metadata))
        {
            return Err(FederationError::Unauthorized);
        }
        Ok(())
    }

    /// Carry remote authority through reservation and final disclosure checks.
    pub fn with_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<Self, FederationError> {
        Self::new(
            self.store.bind_object_decision(decision)?,
            Arc::clone(&self.clock),
            Arc::clone(&self.disclosure),
            self.max_chunk_bytes,
        )
    }

    /// Configure the service with its store, clock, policy and chunk bound.
    pub fn new(
        store: Arc<dyn FederationObjectReadStore>,
        clock: Arc<dyn FederationObjectClock>,
        disclosure: Arc<dyn FederationObjectDisclosure>,
        max_chunk_bytes: usize,
    ) -> Result<Self, FederationError> {
        if max_chunk_bytes == 0 || max_chunk_bytes > MAX_OBJECT_CHUNK_BYTES {
            return Err(FederationError::Capacity);
        }
        Ok(Self {
            store,
            clock,
            disclosure,
            max_chunk_bytes,
        })
    }

    /// Host-only issuance. The adapter must expose the exact complete metadata;
    /// an object reference alone never proves the bytes are present or readable.
    pub async fn issue<R: ObjectRead>(
        &self,
        objects: &R,
        spec: ObjectGrantSpec,
    ) -> Result<ObjectGrantView, FederationError> {
        spec.validate(self.store.local_node())?;
        let now_ms = self.clock.now_ms()?;
        if now_ms >= spec.expires_at_ms {
            return Err(FederationError::Unauthorized);
        }
        let metadata = objects
            .metadata(&spec.blob)
            .await
            .map_err(object_failure)?
            .ok_or(FederationError::NotFound)?;
        if metadata.blob != spec.blob || !self.disclosure.allows(&spec.subject, &metadata) {
            return Err(FederationError::Unauthorized);
        }
        self.store.issue_object_grant(spec, self.clock.now_ms()?)
    }

    /// Read one bounded page after charging and rechecking disclosure.
    pub async fn read<R: ObjectRead>(
        &self,
        objects: &R,
        request: ObjectReadRequest,
        authority: ObjectReadAuthority,
    ) -> Result<ObjectReadPage, FederationError> {
        Ok(self
            .read_for_delivery(objects, request, authority)
            .await?
            .page)
    }

    /// Read once and retain native disclosure evidence for delayed delivery.
    /// This has the same reservation and I/O effects as [`Self::read`]; never
    /// reconstruct its context from a remote page or object reference.
    pub async fn read_for_delivery<R: ObjectRead>(
        &self,
        objects: &R,
        request: ObjectReadRequest,
        authority: ObjectReadAuthority,
    ) -> Result<ObjectReadDelivery, FederationError> {
        request.validate(self.store.local_node())?;
        if request.max_bytes > self.max_chunk_bytes {
            return Err(FederationError::Capacity);
        }
        let grant = self
            .store
            .reserve_object_read(&request, authority, self.clock.now_ms()?)?;
        let metadata = objects
            .metadata(&request.blob)
            .await
            .map_err(object_failure)?
            .ok_or(FederationError::NotFound)?;
        if metadata.blob != request.blob || !self.disclosure.allows(&request.subject, &metadata) {
            return Err(FederationError::Unauthorized);
        }
        let mut bytes = vec![0; request.max_bytes];
        let chunk = objects
            .read_chunk(&request.blob, request.offset, &mut bytes)
            .await
            .map_err(object_failure)?;
        let next = chunk
            .checked_next_offset(request.offset, bytes.len(), request.blob.size)
            .map_err(object_failure)?;
        let chunk_metadata = ObjectMetadata {
            blob: request.blob.clone(),
            taint: chunk.taint,
        };
        if !self.disclosure.allows(&request.subject, &chunk_metadata) {
            return Err(FederationError::Unauthorized);
        }
        let current = objects
            .metadata(&request.blob)
            .await
            .map_err(object_failure)?
            .ok_or(FederationError::NotFound)?;
        if current.blob != request.blob || !self.disclosure.allows(&request.subject, &current) {
            return Err(FederationError::Unauthorized);
        }
        self.store
            .confirm_object_read(&request, authority, self.clock.now_ms()?)?;
        bytes.truncate(chunk.bytes_read);
        let page = ObjectReadPage {
            transfer: request.transfer,
            grant: request.grant,
            revision: grant.revision,
            offset: request.offset,
            bytes,
            end_of_object: chunk.end,
            end_of_range: next == grant.spec.range_end,
        };
        Ok(ObjectReadDelivery {
            page,
            context: ObjectDeliveryContext {
                request,
                authority,
                metadata: [metadata, chunk_metadata, current],
            },
        })
    }
}

pub(crate) fn object_failure(failure: StateFailure) -> FederationError {
    match failure.error {
        StateError::NotFound(_) => FederationError::NotFound,
        _ => FederationError::Storage("object backend failed".into()),
    }
}

/// Streaming receiver-side proof for the *entire* object. An arbitrary subset
/// of SHA-384 content has no independent proof without a separate chunk tree.
pub struct ObjectDigestVerifier {
    blob: BlobRef,
    next_offset: u64,
    hash: Sha384,
}

impl ObjectDigestVerifier {
    /// Begin full-object verification for a valid content reference.
    pub fn new(blob: BlobRef) -> Result<Self, FederationError> {
        if !BlobRef::is_valid_hash(&blob.hash) {
            return Err(FederationError::Invalid("invalid object digest"));
        }
        Ok(Self {
            blob,
            next_offset: 0,
            hash: Sha384::new(),
        })
    }

    /// Add the next contiguous byte span to the SHA-384 verifier.
    pub fn push(&mut self, offset: u64, bytes: &[u8]) -> Result<(), FederationError> {
        let next = offset
            .checked_add(u64::try_from(bytes.len()).map_err(|_error| FederationError::Capacity)?)
            .ok_or(FederationError::Capacity)?;
        if offset != self.next_offset || next > self.blob.size {
            return Err(FederationError::Conflict);
        }
        self.hash.update(bytes);
        self.next_offset = next;
        Ok(())
    }

    /// Finish only after all bytes match the expected object digest.
    pub fn finish(self) -> Result<BlobRef, FederationError> {
        if self.next_offset != self.blob.size {
            return Err(FederationError::Conflict);
        }
        let digest: [u8; BlobRef::HASH_BYTES] = self.hash.finalize().into();
        if BlobRef::sha384_hex(&digest) != self.blob.hash {
            return Err(FederationError::Corrupt);
        }
        Ok(self.blob)
    }
}
