//! Receiver-owned object admission. The durable ledger records immutable
//! transfer identity and verified completion, not uncommitted upload offsets.

use core::future::Future;
use std::sync::Arc;

use xolotl_state::object::{ObjectRead, ObjectWrite, UploadOptions};
use xolotl_types::{BlobRef, TaintSet, TaintSource};

use crate::{
    Digest, FederationError, FederationNodeId, FederationSubject, MAX_OBJECT_CHUNK_BYTES,
    ObjectDigestVerifier, ObjectGrantId, ObjectReadPage, ObjectReadRequest, ObjectTransferId,
};

/// Maximum durable inbound object transfer receipts per receiver store.
pub const MAX_OBJECT_RECEIVES: usize = 8192;
/// Maximum simultaneous durable GC fences for federation-received objects.
pub const MAX_OBJECT_GC_FENCES: usize = 1024;

/// A durable fence that excludes new receiver transfers for one content hash.
/// Its generation prevents a stale cleanup attempt from releasing a newer fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectGcFence {
    /// Canonical SHA-384 content hash shared by all references to these bytes.
    pub hash: String,
    /// Never-reused generation for this receiver store.
    pub generation: u64,
}

/// The application-owned source identity is an exact digest of the event,
/// result, snapshot or other durable context selecting this reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectReceiveSpec {
    /// Authenticated node expected to serve the object.
    pub provider: FederationNodeId,
    /// Node or holder-proven hosted principal requesting the object.
    pub subject: FederationSubject,
    /// Exact provider-issued read grant.
    pub grant: ObjectGrantId,
    /// Grant revision that bounds this transfer's authority.
    pub grant_revision: u64,
    /// Complete object type, hash, size and MIME metadata to verify.
    pub blob: BlobRef,
    /// Digest of the durable event, result or snapshot owning this reference.
    pub owner: Digest,
}

impl ObjectReceiveSpec {
    /// Validate the provider, local principal, grant and object binding.
    pub fn validate(&self, local_node: FederationNodeId) -> Result<(), FederationError> {
        if self.provider == local_node
            || matches!(&self.subject, FederationSubject::Node(node) if *node != local_node)
        {
            return Err(FederationError::Unauthorized);
        }
        if self.grant_revision == 0
            || self.owner.as_bytes() == &[0; 48]
            || !BlobRef::is_valid_hash(&self.blob.hash)
            || self
                .blob
                .mime
                .as_ref()
                .is_some_and(|mime| mime.len() > 256 || mime.chars().any(char::is_control))
        {
            return Err(FederationError::Invalid("invalid object receive binding"));
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
        Ok(())
    }
}

/// Progress of a single receiver-owned object transfer receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectReceivePhase {
    /// Transfer identity is durable; bytes are not yet fully verified.
    Pending,
    /// Complete local bytes passed digest and type verification.
    Verified,
    /// The application durably published a reference to those bytes.
    Bound,
}

/// Durable transfer identity, immutable spec and current handoff phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectReceiveView {
    /// Stable receiver-generated transfer ID for retry and recovery.
    pub transfer: ObjectTransferId,
    /// Immutable provider, grant, object and owner binding.
    pub spec: ObjectReceiveSpec,
    /// Current durable receiver handoff state.
    pub phase: ObjectReceivePhase,
    /// CAS revision guarding phase changes and retirement.
    pub revision: u64,
}

/// Evidence that a host reference to the exact received object was committed.
/// Only [`bind_verified_object`] creates this value after the host has returned
/// a retention guard for its durable application reference. Stores must compare
/// the complete spec and revision before advancing the receive receipt.
#[derive(Debug)]
pub struct ObjectReferenceEvidence {
    transfer: ObjectTransferId,
    spec: ObjectReceiveSpec,
    expected_revision: u64,
}

impl ObjectReferenceEvidence {
    /// Transfer whose application reference was published.
    pub fn transfer(&self) -> ObjectTransferId {
        self.transfer
    }

    /// Exact provider, subject, grant, owner, and object reference published.
    pub fn spec(&self) -> &ObjectReceiveSpec {
        &self.spec
    }

    /// Receive receipt revision observed before publication.
    pub fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
}

/// A live host retention guard for a committed application reference. The
/// host's reference removal and object GC must observe this guard before they
/// can proceed. It may be released after the receive receipt becomes `Bound`.
pub trait FederationObjectReferenceGuard {
    /// Read the exact object descriptor from the committed application record.
    fn committed_blob(&self) -> &BlobRef;
}

/// Application-owned publication port for a received object. Publication is
/// idempotent by the complete receive identity and must be durable before the
/// future succeeds. Returning a guard also excludes removal of that reference
/// until the guard is dropped; the host coordinates this with its object GC.
///
/// A crash after publication and before the receive CAS leaves `Verified`; a
/// retry republishes the same reference and completes the CAS. Failure of the
/// CAS can leave a durable application reference, which the host must retain or
/// explicitly remove under its normal reference lifecycle.
pub trait FederationObjectReferenceStore {
    /// Guard held across the receive CAS.
    type Guard<'a>: FederationObjectReferenceGuard
    where
        Self: 'a;
    /// Host-owned asynchronous publication operation.
    type Publish<'a>: Future<Output = Result<Self::Guard<'a>, FederationError>>
    where
        Self: 'a;

    /// Publish and read back the reference selected by the exact transfer.
    /// A conflicting existing reference must fail rather than be overwritten.
    fn publish_and_hold<'a>(&'a self, view: &'a ObjectReceiveView) -> Self::Publish<'a>;
}

/// Complete a verified object's handoff to a host-owned durable reference.
/// The host guard remains held through the receive-store CAS. A `Bound` receipt
/// returned on retry already records a completed handoff and is not republished.
/// A `Pending`, retired, or changed receipt cannot be bound by stale evidence.
pub async fn bind_verified_object<
    S: FederationObjectReceiveStore + ?Sized,
    R: FederationObjectReferenceStore + ?Sized,
>(
    store: &S,
    references: &R,
    transfer: ObjectTransferId,
) -> Result<ObjectReceiveView, FederationError> {
    let view = store
        .object_receive(transfer)?
        .ok_or(FederationError::NotFound)?;
    match view.phase {
        ObjectReceivePhase::Pending => return Err(FederationError::Conflict),
        ObjectReceivePhase::Bound => return Ok(view),
        ObjectReceivePhase::Verified => {}
    }
    let evidence_spec = view.spec.clone();
    let guard = references.publish_and_hold(&view).await?;
    if guard.committed_blob() != &view.spec.blob {
        return Err(FederationError::Conflict);
    }
    let evidence = ObjectReferenceEvidence {
        transfer,
        spec: evidence_spec,
        expected_revision: view.revision,
    };
    store.mark_object_bound(evidence)
}

/// `begin_receive` is idempotent by the full spec and allocates a never-reused
/// transfer ID. Pending rows retain no byte offset: after crash the receiver
/// verifies any committed local object or starts a fresh upload at zero.
pub trait FederationObjectReceiveStore: Send + Sync {
    /// Bind verified remote authority to each actual backend decision.
    /// Unsupported backends must reject, never substitute a preflight check.
    fn bind_receive_decision(
        &self,
        _decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationObjectReceiveStore>, crate::FederationError> {
        Err(crate::FederationError::Unauthorized)
    }
    /// Receiver node identity owned by this durable ledger.
    fn local_node(&self) -> FederationNodeId;
    /// Persist a never-reused transfer ID, or return the matching prior one.
    fn begin_receive(&self, spec: ObjectReceiveSpec) -> Result<ObjectReceiveView, FederationError>;
    /// Inspect the transfer after a crash or an indeterminate commit.
    fn object_receive(
        &self,
        transfer: ObjectTransferId,
    ) -> Result<Option<ObjectReceiveView>, FederationError>;
    /// CAS complete byte verification; does not claim application ownership.
    fn mark_object_verified(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
        blob: &BlobRef,
    ) -> Result<ObjectReceiveView, FederationError>;
    /// CAS the handoff after [`bind_verified_object`] confirmed the host's
    /// committed reference. The store must compare the full evidence binding.
    fn mark_object_bound(
        &self,
        evidence: ObjectReferenceEvidence,
    ) -> Result<ObjectReceiveView, FederationError>;
    /// Retire a bound receipt only after application retention ownership ends.
    fn retire_bound_object(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
    ) -> Result<(), FederationError>;
    /// Retire a transfer that never acquired an application reference. A caller
    /// must first stop its fetch job; a late commit may leave unreferenced bytes.
    fn retire_unbound_object(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
    ) -> Result<(), FederationError>;
    /// Reserve deletion against all active receiver receipts for this content
    /// hash. The reservation survives restart and excludes `begin_receive` until
    /// it is released. Other application references remain the host's authority;
    /// the host must check them before deleting bytes.
    fn reserve_receive_gc(&self, blob: &BlobRef) -> Result<ObjectGcFence, FederationError>;
    /// Inspect a fence after a crash or indeterminate commit.
    fn receive_gc_fence(&self, hash: &str) -> Result<Option<ObjectGcFence>, FederationError>;
    /// Enumerate the bounded set of active fences so a restarted host can
    /// finish or abandon deletion even if its candidate queue was lost.
    fn active_receive_gc_fences(&self) -> Result<Vec<ObjectGcFence>, FederationError>;
    /// Release only the exact fence after deletion, or after deciding not to
    /// delete. A different generation must never be released by stale work.
    fn release_receive_gc(&self, fence: &ObjectGcFence) -> Result<(), FederationError>;
}

impl<T: FederationObjectReceiveStore + ?Sized> FederationObjectReceiveStore for Arc<T> {
    fn bind_receive_decision(
        &self,
        decision: crate::FederationDecision,
    ) -> Result<std::sync::Arc<dyn FederationObjectReceiveStore>, crate::FederationError> {
        (**self).bind_receive_decision(decision)
    }
    fn local_node(&self) -> FederationNodeId {
        (**self).local_node()
    }
    fn begin_receive(&self, spec: ObjectReceiveSpec) -> Result<ObjectReceiveView, FederationError> {
        (**self).begin_receive(spec)
    }
    fn object_receive(
        &self,
        transfer: ObjectTransferId,
    ) -> Result<Option<ObjectReceiveView>, FederationError> {
        (**self).object_receive(transfer)
    }
    fn mark_object_verified(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
        blob: &BlobRef,
    ) -> Result<ObjectReceiveView, FederationError> {
        (**self).mark_object_verified(transfer, expected_revision, blob)
    }
    fn mark_object_bound(
        &self,
        evidence: ObjectReferenceEvidence,
    ) -> Result<ObjectReceiveView, FederationError> {
        (**self).mark_object_bound(evidence)
    }
    fn retire_bound_object(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
    ) -> Result<(), FederationError> {
        (**self).retire_bound_object(transfer, expected_revision)
    }
    fn retire_unbound_object(
        &self,
        transfer: ObjectTransferId,
        expected_revision: u64,
    ) -> Result<(), FederationError> {
        (**self).retire_unbound_object(transfer, expected_revision)
    }
    fn reserve_receive_gc(&self, blob: &BlobRef) -> Result<ObjectGcFence, FederationError> {
        (**self).reserve_receive_gc(blob)
    }
    fn receive_gc_fence(&self, hash: &str) -> Result<Option<ObjectGcFence>, FederationError> {
        (**self).receive_gc_fence(hash)
    }
    fn active_receive_gc_fences(&self) -> Result<Vec<ObjectGcFence>, FederationError> {
        (**self).active_receive_gc_fences()
    }
    fn release_receive_gc(&self, fence: &ObjectGcFence) -> Result<(), FederationError> {
        (**self).release_receive_gc(fence)
    }
}

/// Transport adapter on an already authenticated provider session. A hosted
/// subject adapter also supplies its per-request holder proof.
pub trait FederationObjectChunkSource {
    /// Future for one exact authorized chunk read.
    type Read<'a>: Future<Output = Result<ObjectReadPage, FederationError>>
    where
        Self: 'a;
    /// Read a range from the authenticated provider under current grant policy.
    fn read(&self, request: ObjectReadRequest) -> Self::Read<'_>;
}

/// Bounded object downloader that verifies bytes before publishing `Verified`.
/// Application reference binding remains an explicit later store transition.
pub struct FederationObjectReceiver {
    store: Arc<dyn FederationObjectReceiveStore>,
    max_chunk_bytes: usize,
}

impl FederationObjectReceiver {
    /// Bind a durable transfer store to a positive chunk limit.
    pub fn new(
        store: Arc<dyn FederationObjectReceiveStore>,
        max_chunk_bytes: usize,
    ) -> Result<Self, FederationError> {
        if max_chunk_bytes == 0 || max_chunk_bytes > MAX_OBJECT_CHUNK_BYTES {
            return Err(FederationError::Capacity);
        }
        Ok(Self {
            store,
            max_chunk_bytes,
        })
    }

    /// Borrow the transfer ledger for host recovery and inspection.
    pub fn store(&self) -> &Arc<dyn FederationObjectReceiveStore> {
        &self.store
    }

    /// Fetch a complete object. A cancelled or failed future leaves only its
    /// Pending ledger row; the ObjectWrite upload lease owns staging cleanup.
    pub async fn fetch<S: FederationObjectChunkSource, O: ObjectRead + ObjectWrite>(
        &self,
        source: &S,
        objects: &O,
        spec: ObjectReceiveSpec,
    ) -> Result<ObjectReceiveView, FederationError> {
        spec.validate(self.store.local_node())?;
        let current = self.store.begin_receive(spec)?;
        if verify_existing(objects, &current.spec.blob, self.max_chunk_bytes).await? {
            return self.store.mark_object_verified(
                current.transfer,
                current.revision,
                &current.spec.blob,
            );
        }
        let inbound = TaintSet::of(TaintSource::Inbound {
            source: "federation".into(),
            channel: "object".into(),
        });
        let upload = objects
            .begin_upload(UploadOptions {
                expected_size: Some(current.spec.blob.size),
                mime: current.spec.blob.mime.clone(),
                taint: inbound.clone(),
            })
            .await
            .map_err(super::object::object_failure)?;
        let mut verifier = ObjectDigestVerifier::new(current.spec.blob.clone())?;
        let mut offset = 0;
        while offset < current.spec.blob.size {
            let count =
                usize::try_from((current.spec.blob.size - offset).min(self.max_chunk_bytes as u64))
                    .map_err(|_error| FederationError::Capacity)?;
            let page = source
                .read(ObjectReadRequest {
                    authenticated_presenter: self.store.local_node(),
                    subject: current.spec.subject.clone(),
                    transfer: current.transfer,
                    grant: current.spec.grant,
                    expected_revision: current.spec.grant_revision,
                    blob: current.spec.blob.clone(),
                    offset,
                    max_bytes: count,
                })
                .await?;
            if page.transfer != current.transfer
                || page.grant != current.spec.grant
                || page.revision != current.spec.grant_revision
                || page.offset != offset
                || page.bytes.is_empty()
                || page.bytes.len() > count
            {
                return Err(FederationError::Corrupt);
            }
            let next = offset
                .checked_add(page.bytes.len() as u64)
                .ok_or(FederationError::Capacity)?;
            if page.end_of_object != (next == current.spec.blob.size)
                || page.end_of_range != (next == current.spec.blob.size)
            {
                return Err(FederationError::Corrupt);
            }
            verifier.push(offset, &page.bytes)?;
            let mut written = 0usize;
            while written < page.bytes.len() {
                let start = offset + written as u64;
                let ack = objects
                    .write_chunk(&upload, start, &page.bytes[written..])
                    .await
                    .map_err(super::object::object_failure)?;
                ack.checked_next_offset(start, page.bytes.len() - written)
                    .map_err(super::object::object_failure)?;
                written += ack.bytes_written;
            }
            offset = next;
        }
        verifier.finish()?;
        let receipt = objects
            .commit_upload(&upload, &inbound)
            .await
            .map_err(super::object::object_failure)?;
        if receipt.blob != current.spec.blob || !receipt.taint.contains_all(&inbound) {
            return Err(FederationError::Corrupt);
        }
        self.store
            .mark_object_verified(current.transfer, current.revision, &current.spec.blob)
    }
}

async fn verify_existing<O: ObjectRead>(
    objects: &O,
    blob: &BlobRef,
    max_chunk_bytes: usize,
) -> Result<bool, FederationError> {
    let Some(metadata) = objects
        .metadata(blob)
        .await
        .map_err(super::object::object_failure)?
    else {
        return Ok(false);
    };
    if metadata.blob != *blob {
        return Err(FederationError::Corrupt);
    }
    let mut verifier = ObjectDigestVerifier::new(blob.clone())?;
    let mut buffer = vec![0; max_chunk_bytes];
    let mut offset = 0;
    while offset < blob.size {
        let count = usize::try_from((blob.size - offset).min(max_chunk_bytes as u64))
            .map_err(|_error| FederationError::Capacity)?;
        let chunk = objects
            .read_chunk(blob, offset, &mut buffer[..count])
            .await
            .map_err(super::object::object_failure)?;
        let next = chunk
            .checked_next_offset(offset, count, blob.size)
            .map_err(super::object::object_failure)?;
        verifier.push(offset, &buffer[..chunk.bytes_read])?;
        offset = next;
    }
    verifier.finish()?;
    Ok(true)
}
