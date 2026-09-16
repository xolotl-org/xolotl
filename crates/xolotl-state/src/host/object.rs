//! Optional shared object ports. No scheduler, filesystem or State backend is required.

use super::SendFuture;
use crate::object::{
    ObjectDelete, ObjectMetadata, ObjectRead, ObjectReadChunk, ObjectWrite, ObjectWriteChunk,
    UploadId, UploadOptions,
};
use crate::{StateError, StateResult};
use alloc::{boxed::Box, sync::Arc};
use core::num::NonZeroUsize;
use xolotl_types::{BlobRef, TaintSet};

trait ReadPort: Send + Sync {
    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> SendFuture<'a, Option<ObjectMetadata>>;
    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> SendFuture<'a, ObjectReadChunk>;
}

impl<T: ObjectRead + Send + Sync> ReadPort for T
where
    for<'a> T::Metadata<'a>: Send,
    for<'a> T::ReadChunk<'a>: Send,
{
    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> SendFuture<'a, Option<ObjectMetadata>> {
        Box::pin(ObjectRead::metadata(self, blob))
    }

    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> SendFuture<'a, ObjectReadChunk> {
        Box::pin(ObjectRead::read_chunk(self, blob, offset, buffer))
    }
}

trait WritePort: Send + Sync {
    fn begin_upload(&self, options: UploadOptions) -> SendFuture<'_, UploadId>;
    fn write_chunk<'a>(
        &'a self,
        upload: &'a UploadId,
        offset: u64,
        bytes: &'a [u8],
    ) -> SendFuture<'a, ObjectWriteChunk>;
    fn commit_upload<'a>(
        &'a self,
        upload: &'a UploadId,
        final_taint: &'a TaintSet,
    ) -> SendFuture<'a, ObjectMetadata>;
    fn abort_upload<'a>(&'a self, upload: &'a UploadId) -> SendFuture<'a, ()>;
}

impl<T: ObjectWrite + Send + Sync> WritePort for T
where
    for<'a> T::BeginUpload<'a>: Send,
    for<'a> T::WriteChunk<'a>: Send,
    for<'a> T::CommitUpload<'a>: Send,
    for<'a> T::AbortUpload<'a>: Send,
{
    fn begin_upload(&self, options: UploadOptions) -> SendFuture<'_, UploadId> {
        Box::pin(ObjectWrite::begin_upload(self, options))
    }

    fn write_chunk<'a>(
        &'a self,
        upload: &'a UploadId,
        offset: u64,
        bytes: &'a [u8],
    ) -> SendFuture<'a, ObjectWriteChunk> {
        Box::pin(ObjectWrite::write_chunk(self, upload, offset, bytes))
    }

    fn commit_upload<'a>(
        &'a self,
        upload: &'a UploadId,
        final_taint: &'a TaintSet,
    ) -> SendFuture<'a, ObjectMetadata> {
        Box::pin(ObjectWrite::commit_upload(self, upload, final_taint))
    }

    fn abort_upload<'a>(&'a self, upload: &'a UploadId) -> SendFuture<'a, ()> {
        Box::pin(ObjectWrite::abort_upload(self, upload))
    }
}

trait DeletePort: Send + Sync {
    fn delete<'a>(&'a self, blob: &'a BlobRef) -> SendFuture<'a, ()>;
}

impl<T: ObjectDelete + Send + Sync> DeletePort for T
where
    for<'a> T::Delete<'a>: Send,
{
    fn delete<'a>(&'a self, blob: &'a BlobRef) -> SendFuture<'a, ()> {
        Box::pin(ObjectDelete::delete(self, blob))
    }
}

/// Read, write, and delete capabilities installed independently by the host.
/// Cloning shares only installed adapters; an empty store allocates nothing.
#[derive(Clone, Default)]
pub struct ObjectStore {
    read: Option<Arc<dyn ReadPort>>,
    write: Option<Arc<dyn WritePort>>,
    delete: Option<Arc<dyn DeletePort>>,
}

impl ObjectStore {
    /// Start without any installed object capabilities.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install metadata and incremental reads without requiring upload support.
    pub fn with_read<T: ObjectRead + Send + Sync + 'static>(mut self, port: Arc<T>) -> Self
    where
        for<'a> T::Metadata<'a>: Send,
        for<'a> T::ReadChunk<'a>: Send,
    {
        self.read = Some(port);
        self
    }

    /// Install incremental uploads without requiring read access.
    pub fn with_write<T: ObjectWrite + Send + Sync + 'static>(mut self, port: Arc<T>) -> Self
    where
        for<'a> T::BeginUpload<'a>: Send,
        for<'a> T::WriteChunk<'a>: Send,
        for<'a> T::CommitUpload<'a>: Send,
        for<'a> T::AbortUpload<'a>: Send,
    {
        self.write = Some(port);
        self
    }

    /// Install committed object deletion without requiring uploads or reads.
    pub fn with_delete<T: ObjectDelete + Send + Sync + 'static>(mut self, port: Arc<T>) -> Self
    where
        for<'a> T::Delete<'a>: Send,
    {
        self.delete = Some(port);
        self
    }

    /// Whether object inspection and reads are installed.
    pub fn can_read(&self) -> bool {
        self.read.is_some()
    }

    /// Whether uploads are installed.
    pub fn can_write(&self) -> bool {
        self.write.is_some()
    }

    /// Whether committed content deletion is installed.
    pub fn can_delete(&self) -> bool {
        self.delete.is_some()
    }

    /// Inspect a committed object without reading its content.
    pub async fn metadata(&self, blob: &BlobRef) -> StateResult<Option<ObjectMetadata>> {
        ObjectRead::metadata(self, blob).await
    }

    /// Fill a caller-owned window at an absolute offset.
    pub async fn read_chunk(
        &self,
        blob: &BlobRef,
        offset: u64,
        buffer: &mut [u8],
    ) -> StateResult<ObjectReadChunk> {
        ObjectRead::read_chunk(self, blob, offset, buffer).await
    }

    /// Begin unpublished staging without reserving the entire object length.
    /// The adapter must deliver a cleanup lease for stateful uploads and keep
    /// undelivered staging owned if this request is cancelled; see
    /// [`ObjectWrite::begin_upload`].
    pub async fn begin_upload(&self, options: UploadOptions) -> StateResult<UploadId> {
        ObjectWrite::begin_upload(self, options).await
    }

    /// Append a window at its acknowledged offset. Partial writes are allowed.
    pub async fn write_chunk(
        &self,
        upload: &UploadId,
        offset: u64,
        bytes: &[u8],
    ) -> StateResult<ObjectWriteChunk> {
        ObjectWrite::write_chunk(self, upload, offset, bytes).await
    }

    /// Append all supplied bytes using borrowed windows of at most
    /// `max_chunk_bytes`, returning the next absolute upload offset.
    /// Partial writes retry only the unaccepted suffix. Empty input returns
    /// `offset` without calling the adapter, but still requires a write port.
    ///
    /// The complete offset range is checked before writing. Every successful
    /// nonempty write must acknowledge a nonempty prefix of its offered window
    /// and the matching next offset; invalid acknowledgements are backend errors.
    ///
    /// This neither commits nor aborts the upload. An error or cancellation may
    /// leave an accepted prefix in staging. The upload is only borrowed; its
    /// existing owner can recover using the adapter's retry semantics or drop the
    /// lease to trigger cleanup. No caller-side awaited abort is required.
    pub async fn write_all(
        &self,
        upload: &UploadId,
        mut offset: u64,
        mut bytes: &[u8],
        max_chunk_bytes: NonZeroUsize,
    ) -> StateResult<u64> {
        let write = self
            .write
            .as_ref()
            .ok_or(StateError::MissingCapability("object.write"))?;
        let length = u64::try_from(bytes.len())
            .map_err(|_overflow| StateError::Unsupported("object upload length exceeds u64"))?;
        offset
            .checked_add(length)
            .ok_or(StateError::Unsupported("object upload offset exceeds u64"))?;

        while !bytes.is_empty() {
            let offered = &bytes[..bytes.len().min(max_chunk_bytes.get())];
            let written = write.write_chunk(upload, offset, offered).await?;
            offset = written.checked_next_offset(offset, offered.len())?;
            bytes = &bytes[written.bytes_written..];
        }
        Ok(offset)
    }

    /// Seal accepted input and publish initial plus final source provenance.
    /// See [`ObjectWrite::commit_upload`] for EOF, retry and cancellation rules.
    pub async fn commit_upload(
        &self,
        upload: &UploadId,
        final_taint: &TaintSet,
    ) -> StateResult<ObjectMetadata> {
        ObjectWrite::commit_upload(self, upload, final_taint).await
    }

    /// Explicitly release staging before the upload's last owner is dropped.
    /// Cancelling this request preserves the adapter lease's cleanup obligation;
    /// simply dropping the upload owners also releases abandoned staging.
    pub async fn abort_upload(&self, upload: &UploadId) -> StateResult<()> {
        ObjectWrite::abort_upload(self, upload).await
    }

    /// Delete committed content by identity. An absent capability is an error.
    pub async fn delete(&self, blob: &BlobRef) -> StateResult<()> {
        ObjectDelete::delete(self, blob).await
    }
}

impl ObjectRead for ObjectStore {
    type Metadata<'a> = SendFuture<'a, Option<ObjectMetadata>>;
    type ReadChunk<'a> = SendFuture<'a, ObjectReadChunk>;

    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> Self::Metadata<'a> {
        match &self.read {
            Some(port) => port.metadata(blob),
            None => Box::pin(async { Err(StateError::MissingCapability("object.read").into()) }),
        }
    }

    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        match &self.read {
            Some(port) => port.read_chunk(blob, offset, buffer),
            None => Box::pin(async { Err(StateError::MissingCapability("object.read").into()) }),
        }
    }
}

impl ObjectWrite for ObjectStore {
    type BeginUpload<'a> = SendFuture<'a, UploadId>;
    type WriteChunk<'a> = SendFuture<'a, ObjectWriteChunk>;
    type CommitUpload<'a> = SendFuture<'a, ObjectMetadata>;
    type AbortUpload<'a> = SendFuture<'a, ()>;

    fn begin_upload(&self, options: UploadOptions) -> Self::BeginUpload<'_> {
        match &self.write {
            Some(port) => port.begin_upload(options),
            None => Box::pin(async { Err(StateError::MissingCapability("object.write").into()) }),
        }
    }

    fn write_chunk<'a>(
        &'a self,
        upload: &'a UploadId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::WriteChunk<'a> {
        match &self.write {
            Some(port) => port.write_chunk(upload, offset, bytes),
            None => Box::pin(async { Err(StateError::MissingCapability("object.write").into()) }),
        }
    }

    fn commit_upload<'a>(
        &'a self,
        upload: &'a UploadId,
        final_taint: &'a TaintSet,
    ) -> Self::CommitUpload<'a> {
        match &self.write {
            Some(port) => port.commit_upload(upload, final_taint),
            None => Box::pin(async { Err(StateError::MissingCapability("object.write").into()) }),
        }
    }

    fn abort_upload<'a>(&'a self, upload: &'a UploadId) -> Self::AbortUpload<'a> {
        match &self.write {
            Some(port) => port.abort_upload(upload),
            None => Box::pin(async { Err(StateError::MissingCapability("object.write").into()) }),
        }
    }
}

impl ObjectDelete for ObjectStore {
    type Delete<'a> = SendFuture<'a, ()>;

    fn delete<'a>(&'a self, blob: &'a BlobRef) -> Self::Delete<'a> {
        match &self.delete {
            Some(port) => port.delete(blob),
            None => Box::pin(async { Err(StateError::MissingCapability("object.delete").into()) }),
        }
    }
}
