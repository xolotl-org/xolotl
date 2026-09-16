//! Optional object ports for payloads that should not be materialized as Values.

use alloc::string::String;
use core::future::Future;
use xolotl_types::{BlobRef, TaintSet};

use crate::{StateError, StateResult};

#[cfg(feature = "std")]
type SharedLease = alloc::sync::Arc<dyn Send + Sync>;
#[cfg(not(feature = "std"))]
type SharedLease = alloc::rc::Rc<dyn core::any::Any>;

/// An adapter-owned in-progress upload identity, distinct from a committed blob.
/// Stateful uploads carry a shared cleanup lease: dropping the last clone
/// releases abandoned staging without requiring the caller to await an abort.
/// Copying the identity string does not transfer that ownership.
#[derive(Clone)]
pub struct UploadId {
    id: String,
    lease: Option<SharedLease>,
}

impl UploadId {
    /// Identify an upload with no staging, reservation, or external operation
    /// that needs cleanup when abandoned. This explicitly promises that dropping
    /// the identity without an abort cannot leak adapter resources.
    /// Stateful adapters must use [`Self::with_lease`] instead.
    pub fn stateless(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            lease: None,
        }
    }

    /// Attach the adapter's cleanup owner, shared by clones of this identity.
    /// When the final clone drops, the owner's `Drop` must release abandoned
    /// staging or transfer cleanup to an adapter mechanism guaranteed to run
    /// independently of the cancelled caller. Cleanup must not depend on the
    /// caller polling another future or awaiting [`ObjectWrite::abort_upload`].
    /// Dropping the owner after a commit or explicit abort must be harmless.
    #[cfg(feature = "std")]
    pub fn with_lease(id: impl Into<String>, lease: impl Send + Sync + 'static) -> Self {
        Self {
            id: id.into(),
            lease: Some(alloc::sync::Arc::new(lease)),
        }
    }

    /// Attach a local cleanup owner without requiring `Send`, `Sync`, or atomic
    /// reference counts. The final clone's drop must release abandoned staging
    /// or transfer cleanup to an adapter mechanism guaranteed to run without
    /// further caller polling. Dropping a committed or aborted owner is harmless;
    /// an awaited [`ObjectWrite::abort_upload`] is never required for cleanup.
    #[cfg(not(feature = "std"))]
    pub fn with_lease<T: 'static>(id: impl Into<String>, lease: T) -> Self {
        Self {
            id: id.into(),
            lease: Some(alloc::rc::Rc::new(lease)),
        }
    }

    /// Borrow the adapter's identity without interpreting its contents.
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

impl core::fmt::Debug for UploadId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UploadId")
            .field("id", &self.id)
            .field("owned", &self.lease.is_some())
            .finish()
    }
}

impl PartialEq for UploadId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for UploadId {}

impl core::hash::Hash for UploadId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::hash::Hash::hash(&self.id, state);
    }
}

/// Metadata accepted before incremental upload begins.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UploadOptions {
    /// Optional declared size, validated at commit. `None` allows unknown size.
    pub expected_size: Option<u64>,
    /// Optional content type retained on the committed reference.
    pub mime: Option<String>,
    /// Initial provenance that publication must retain. Sources discovered
    /// during input are supplied to [`ObjectWrite::commit_upload`] and merged
    /// with these labels before the object becomes visible.
    pub taint: TaintSet,
}

/// An immutable committed object, represented by reference at runtime boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectMetadata {
    /// Content identity, byte count, and media type without inline content.
    pub blob: BlobRef,
    /// Provenance inherited by values that read these bytes.
    pub taint: TaintSet,
}

/// Result of filling a caller-owned buffer from an immutable object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectReadChunk {
    /// Number of initialized bytes in the requested buffer.
    pub bytes_read: usize,
    /// Whether this chunk reaches the object's end.
    pub end: bool,
    /// Provenance for the returned bytes, including protected source lineage.
    pub taint: TaintSet,
}

impl ObjectReadChunk {
    /// Validate progress against the offered window and canonical object size.
    /// Short reads are allowed. Nonempty windows must advance before EOF, and
    /// `end` must agree with reaching the full object's size, even when a caller
    /// stops earlier at the end of a selected range. Empty windows may make no
    /// progress before EOF. The returned offset never wraps or exceeds the object.
    pub fn checked_next_offset(
        &self,
        offset: u64,
        offered_len: usize,
        object_size: u64,
    ) -> StateResult<u64> {
        let next = u64::try_from(self.bytes_read)
            .ok()
            .and_then(|length| offset.checked_add(length));
        let valid = next.filter(|next| {
            self.bytes_read <= offered_len
                && *next <= object_size
                && self.end == (*next == object_size)
                && (offered_len == 0 || self.bytes_read != 0 || self.end)
        });
        valid.ok_or_else(|| {
            crate::StateFailure::new(
                StateError::Backend("object reader returned invalid progress".into()),
                self.taint.clone(),
            )
        })
    }
}

/// An upload acknowledgement independent of the total object length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectWriteChunk {
    /// Prefix of the supplied buffer accepted by the adapter. A replay may
    /// acknowledge identical bytes already accepted by an earlier request.
    pub bytes_written: usize,
    /// This request's starting offset plus `bytes_written`, where its caller
    /// should continue. This is not the upload's total staged length: a replay
    /// can end before bytes already accepted by other requests.
    pub next_offset: u64,
}

impl ObjectWriteChunk {
    /// Validate an acknowledgement against the exact offered window.
    ///
    /// Nonempty windows must acknowledge a nonempty prefix. Empty windows may
    /// acknowledge zero bytes. The next offset must match that prefix without
    /// wrapping, independently of the upload's already-staged high-watermark.
    pub fn checked_next_offset(&self, offset: u64, offered_len: usize) -> StateResult<u64> {
        let next = u64::try_from(self.bytes_written)
            .ok()
            .and_then(|length| offset.checked_add(length));
        if self.bytes_written > offered_len
            || (offered_len != 0 && self.bytes_written == 0)
            || next != Some(self.next_offset)
        {
            return Err(StateError::Backend(
                "object writer returned an invalid progress acknowledgement".into(),
            )
            .into());
        }
        Ok(self.next_offset)
    }
}

/// Object inspection and incremental reads, independent of upload support.
pub trait ObjectRead {
    /// Adapter-owned metadata request.
    type Metadata<'a>: Future<Output = StateResult<Option<ObjectMetadata>>>
    where
        Self: 'a;
    /// Adapter-owned read request borrowing the caller's destination.
    type ReadChunk<'a>: Future<Output = StateResult<ObjectReadChunk>>
    where
        Self: 'a;

    /// Look up a committed immutable content reference.
    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> Self::Metadata<'a>;

    /// Fill at most `buffer.len()` bytes starting at `offset`. Nonempty reads
    /// must make progress unless `end` is true, and `end` must agree with reaching
    /// the canonical object size. An offset past that size is an error. Empty
    /// windows may return zero bytes before EOF with `end` false.
    ///
    /// The result never contains the complete object unless the caller deliberately
    /// provided a large buffer. Adapter work and buffers must stay bounded and
    /// owned when a request is dropped; cleanup cannot require another caller poll.
    /// Separate requests do not pin an object against deletion or freeze metadata
    /// provenance. Each returned chunk carries the provenance of its bytes.
    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a>;
}

/// Incremental object creation with lease-owned staging and explicit publication.
/// Implementations bound individual chunks and resident staging buffers;
/// they must not require retaining the complete object in a `Vec`.
///
/// Cancellation is part of the adapter contract. Allocated staging and external
/// upload work must remain guarded when any request future is dropped. Before
/// delivery, the creation request owns that responsibility; after delivery, the
/// [`UploadId`] lease does. Adapter work that outlives a request must retain its
/// own cleanup owner. No caller-side async abort or scheduler is required.
pub trait ObjectWrite {
    /// Creation request owning cleanup of staging not yet delivered to the caller.
    type BeginUpload<'a>: Future<Output = StateResult<UploadId>>
    where
        Self: 'a;
    /// Adapter-owned write request borrowing one source chunk.
    type WriteChunk<'a>: Future<Output = StateResult<ObjectWriteChunk>>
    where
        Self: 'a;
    /// Adapter-owned commit request.
    type CommitUpload<'a>: Future<Output = StateResult<ObjectMetadata>>
    where
        Self: 'a;
    /// Explicit early cleanup request; cancellation must preserve lease cleanup.
    type AbortUpload<'a>: Future<Output = StateResult<()>>
    where
        Self: 'a;

    /// Create staging state without allocating the declared total object size.
    /// Every upload that allocates staging, reservations, or external work that
    /// needs cleanup must return [`UploadId::with_lease`]. Only an upload with no
    /// such resources may return [`UploadId::stateless`].
    ///
    /// The request must guard resources as soon as they are created, including
    /// before the first poll. If it fails or is dropped before delivering the
    /// identity, its owners must release those resources or transfer cleanup to
    /// an adapter mechanism guaranteed to run without further caller polling.
    fn begin_upload(&self, options: UploadOptions) -> Self::BeginUpload<'_>;

    /// Append at the acknowledged offset, rejecting gaps and conflicting
    /// retries. Nonempty successful writes must acknowledge a nonempty prefix.
    /// An accepted replay acknowledges this request's prefix and next offset,
    /// even when additional bytes are already staged beyond its end.
    /// Cancellation may leave an accepted prefix; it must not detach unfinished
    /// work from the upload's cleanup ownership.
    fn write_chunk<'a>(
        &'a self,
        upload: &'a UploadId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::WriteChunk<'a>;

    /// Seal accepted bytes and publish them with their complete source lineage.
    ///
    /// `final_taint` carries sources observed since upload creation; repeating
    /// initial labels is harmless. It cannot remove [`UploadOptions::taint`].
    /// The caller confirms actual input EOF before requesting publication. A
    /// structured document also needs complete framing and grammar validation;
    /// a claimed document-end marker alone is insufficient.
    ///
    /// After recoverable state/declared-size preflight succeeds, but before any
    /// publication I/O, the adapter atomically freezes accepted bytes and the
    /// union of initial and final sources. Further writes must fail. A retry of
    /// this sealed upload must supply the same effective source set, ignoring
    /// label order and repetitions; conflicting sources fail without changing
    /// the frozen publication. A preflight rejection may leave staging open so
    /// the caller can repair incomplete input before retrying.
    ///
    /// Published metadata must cover the frozen sources and any adapter-owned
    /// sources. Content deduplication must atomically union existing metadata's
    /// sources, preserving the canonical content reference. It must never first
    /// expose an object and attach newly observed provenance afterward. Hashing
    /// and persistence remain incremental; this operation grants no read access.
    ///
    /// Failure or cancellation can leave an uncertain publication outcome.
    /// Retrying a still-live upload follows the sealed contract above; adapters
    /// may retire an identity after delivering its successful receipt, in which
    /// case further calls report it closed. Aborting or dropping a lease only
    /// releases staging and cannot remove potentially shared published content.
    fn commit_upload<'a>(
        &'a self,
        upload: &'a UploadId,
        final_taint: &'a TaintSet,
    ) -> Self::CommitUpload<'a>;

    /// Explicitly release staging before the last owner is dropped. Repeating a
    /// completed abort is successful. A failed or cancelled abort must preserve
    /// the lease's cleanup responsibility; callers can always drop their upload
    /// owners without polling this method.
    fn abort_upload<'a>(&'a self, upload: &'a UploadId) -> Self::AbortUpload<'a>;
}

/// Optional destruction of committed content, independent of read and upload.
pub trait ObjectDelete {
    /// Adapter-owned deletion request.
    type Delete<'a>: Future<Output = StateResult<()>>
    where
        Self: 'a;

    /// Delete committed content by its canonical identity. Missing content is
    /// already deleted; adapters reject malformed identities explicitly.
    fn delete<'a>(&'a self, blob: &'a BlobRef) -> Self::Delete<'a>;
}

#[cfg(test)]
mod tests;
