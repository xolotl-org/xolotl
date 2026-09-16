#![forbid(unsafe_code)]

//! Bounded, incremental object storage on a local filesystem.
//!
//! Only chunk buffers cross the Tokio blocking-pool boundary. Uploads stage on
//! disk and become readable after atomic publication. [`FileObjectStore`] starts
//! no background task. The optional `value-workspace` feature supplies a separate
//! asynchronous cleanup worker for each incremental map-key workspace. State,
//! history, subscriptions and the kernel remain independent.

#[cfg(feature = "value-workspace")]
pub mod key_workspace;
mod storage;
mod upload;

use core::future::Future;
use core::pin::Pin;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};
use xolotl_state::object::{
    ObjectDelete, ObjectMetadata, ObjectRead, ObjectReadChunk, ObjectWrite, ObjectWriteChunk,
    UploadId, UploadOptions,
};
use xolotl_state::{StateError, StateFailure, StateResult};
use xolotl_types::{BlobRef, TaintSet};

type Request<'a, T> = Pin<Box<dyn Future<Output = StateResult<T>> + Send + 'a>>;

/// Independent limits on resident transfer buffers and staging records.
#[derive(Clone, Copy, Debug)]
pub struct FileObjectOptions {
    /// Maximum bytes accepted or returned by a single chunk request.
    pub chunk_bytes: NonZeroUsize,
    /// Maximum live upload records, including interrupted commits awaiting retry.
    pub max_uploads: NonZeroUsize,
    /// Maximum simultaneous filesystem jobs and their resident chunk buffers.
    pub max_io_tasks: NonZeroUsize,
    /// Maximum encoded metadata per object, including provenance.
    /// Sources decode before total-size and descriptor validation. A source
    /// header exceeding this budget is rejected without an object receipt.
    pub max_metadata_bytes: NonZeroUsize,
}

impl Default for FileObjectOptions {
    fn default() -> Self {
        Self {
            chunk_bytes: NonZeroUsize::MIN.saturating_add(64 * 1024 - 1),
            max_uploads: NonZeroUsize::MIN.saturating_add(63),
            max_io_tasks: NonZeroUsize::MIN.saturating_add(7),
            max_metadata_bytes: NonZeroUsize::MIN.saturating_add(1024 * 1024 - 1),
        }
    }
}

struct Shared {
    root: PathBuf,
    options: FileObjectOptions,
    io: Arc<tokio::sync::Semaphore>,
    uploads: Mutex<HashMap<String, Arc<UploadRecord>>>,
}

struct UploadRecord {
    cancelled: AtomicBool,
    staging: Mutex<upload::Upload>,
}

impl UploadRecord {
    fn check_active(&self) -> StateResult<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(StateError::Backend("upload was cancelled".into()).into());
        }
        Ok(())
    }
}

struct UploadLease {
    shared: Weak<Shared>,
    id: String,
}

impl Drop for UploadLease {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.upgrade() {
            let removed = {
                let mut uploads = shared.uploads.lock();
                if let Some(upload) = uploads.get(&self.id) {
                    upload.cancelled.store(true, Ordering::Release);
                }
                uploads.remove(&self.id)
            };
            // Active jobs keep their own Arc and clean the staging files when
            // they exit. Filesystem cleanup never runs under the registry lock.
            drop(removed);
        }
    }
}

/// Shared filesystem object ports. Methods require a Tokio runtime; synchronous
/// initialization creates only directories. Different instances may share a root.
#[derive(Clone)]
pub struct FileObjectStore {
    shared: Arc<Shared>,
}

impl FileObjectStore {
    /// Open or create a store with default per-operation resource limits.
    pub fn open(root: impl AsRef<Path>) -> StateResult<Self> {
        Self::with_options(root, FileObjectOptions::default())
    }

    /// Open a store without preallocating payloads, buffers or upload slots.
    pub fn with_options(root: impl AsRef<Path>, options: FileObjectOptions) -> StateResult<Self> {
        if options.max_io_tasks.get() > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(StateError::Backend(
                "object I/O concurrency limit exceeds supported range".into(),
            )
            .into());
        }
        std::fs::create_dir_all(root.as_ref().join("objects")).map_err(storage::io_error)?;
        std::fs::create_dir_all(root.as_ref().join("staging")).map_err(storage::io_error)?;
        let root = root.as_ref().canonicalize().map_err(storage::io_error)?;
        Ok(Self {
            shared: Arc::new(Shared {
                root,
                options,
                io: Arc::new(tokio::sync::Semaphore::new(options.max_io_tasks.get())),
                uploads: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Canonical storage directory containing committed objects and staging files.
    pub fn root(&self) -> &Path {
        &self.shared.root
    }

    /// Configured limits; memory depends on active jobs, never object length.
    pub fn options(&self) -> FileObjectOptions {
        self.shared.options
    }

    /// Number of uploads the caller must commit or abort.
    pub fn pending_uploads(&self) -> usize {
        self.shared.uploads.lock().len()
    }

    /// Install independent read, write and delete capabilities in the host bridge.
    pub fn into_object_store(self) -> xolotl_state::host::object::ObjectStore {
        let store = Arc::new(self);
        xolotl_state::host::object::ObjectStore::new()
            .with_read(store.clone())
            .with_write(store.clone())
            .with_delete(store)
    }

    async fn permit(&self) -> StateResult<tokio::sync::OwnedSemaphorePermit> {
        self.shared
            .io
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| StateError::Backend(error.to_string()).into())
    }

    async fn run_io<T: Send + 'static>(
        permit: tokio::sync::OwnedSemaphorePermit,
        task: impl FnOnce() -> StateResult<T> + Send + 'static,
    ) -> StateResult<T> {
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            StateError::Backend(format!("object storage requires Tokio: {error}"))
        })?;
        // The result retains the permit until polled, including when its caller
        // is cancelled while the blocking job is still using a chunk buffer.
        let (result, _permit) = runtime
            .spawn_blocking(move || (task(), permit))
            .await
            .map_err(|error| StateError::Backend(format!("object I/O task failed: {error}")))?;
        result
    }

    async fn io<T: Send + 'static>(
        &self,
        task: impl FnOnce() -> StateResult<T> + Send + 'static,
    ) -> StateResult<T> {
        Self::run_io(self.permit().await?, task).await
    }

    fn upload(&self, id: &UploadId) -> StateResult<Arc<UploadRecord>> {
        self.shared
            .uploads
            .lock()
            .get(id.as_str())
            .cloned()
            .ok_or_else(|| StateError::NotFound(format!("upload {}", id.as_str())).into())
    }
}

impl ObjectRead for FileObjectStore {
    type Metadata<'a> = Request<'a, Option<ObjectMetadata>>;
    type ReadChunk<'a> = Request<'a, ObjectReadChunk>;

    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> Self::Metadata<'a> {
        Box::pin(async move {
            let shared = self.shared.clone();
            let hash = storage::validate_hash(&blob.hash)?.to_owned();
            self.io(move || storage::metadata(&shared, &hash)).await
        })
    }

    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        Box::pin(async move {
            let shared = self.shared.clone();
            let count = buffer.len().min(shared.options.chunk_bytes.get());
            let hash = storage::validate_hash(&blob.hash)?.to_owned();
            let (chunk, bytes) = self
                .io(move || storage::read_chunk(&shared, &hash, offset, count))
                .await?;
            buffer[..chunk.bytes_read].copy_from_slice(&bytes);
            Ok(chunk)
        })
    }
}

impl ObjectWrite for FileObjectStore {
    type BeginUpload<'a> = Request<'a, UploadId>;
    type WriteChunk<'a> = Request<'a, ObjectWriteChunk>;
    type CommitUpload<'a> = Request<'a, ObjectMetadata>;
    type AbortUpload<'a> = Request<'a, ()>;

    fn begin_upload(&self, options: UploadOptions) -> Self::BeginUpload<'_> {
        Box::pin(async move {
            let sources = options.taint.clone();
            let shared = self.shared.clone();
            let upload = self
                .io(move || upload::Upload::new(&shared.root, options))
                .await
                .map_err(|failure| failure.with_taint(&sources))?;
            let id = upload.id().to_owned();
            let mut uploads = self.shared.uploads.lock();
            if uploads.len() >= self.shared.options.max_uploads.get() {
                return Err(StateFailure::new(
                    StateError::Backend("object upload capacity exhausted".into()),
                    sources,
                ));
            }
            uploads.insert(
                id.clone(),
                Arc::new(UploadRecord {
                    cancelled: AtomicBool::new(false),
                    staging: Mutex::new(upload),
                }),
            );
            Ok(UploadId::with_lease(
                id.clone(),
                UploadLease {
                    shared: Arc::downgrade(&self.shared),
                    id,
                },
            ))
        })
    }

    fn write_chunk<'a>(
        &'a self,
        id: &'a UploadId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::WriteChunk<'a> {
        Box::pin(async move {
            let upload = self.upload(id)?;
            let source_owner = upload.clone();
            let permit = self
                .permit()
                .await
                .map_err(|failure| failure.with_taint(&source_owner.staging.lock().sources()))?;
            let bytes = bytes[..bytes.len().min(self.shared.options.chunk_bytes.get())].to_vec();
            Self::run_io(permit, move || {
                let mut staging = upload.staging.lock();
                upload.check_active()?;
                staging.write(offset, &bytes)
            })
            .await
            .map_err(|failure| failure.with_taint(&source_owner.staging.lock().sources()))
        })
    }

    fn commit_upload<'a>(
        &'a self,
        id: &'a UploadId,
        final_taint: &'a TaintSet,
    ) -> Self::CommitUpload<'a> {
        Box::pin(async move {
            let upload = self
                .upload(id)
                .map_err(|failure| failure.with_taint(final_taint))?;
            let source_owner = upload.clone();
            let shared = self.shared.clone();
            let commit_taint = final_taint.clone();
            let metadata = self
                .io(move || {
                    let mut staging = upload.staging.lock();
                    upload.check_active()?;
                    staging.commit(&shared, &upload.cancelled, &commit_taint)
                })
                .await
                .map_err(|failure| {
                    failure
                        .with_taint(&source_owner.staging.lock().sources())
                        .with_taint(final_taint)
                })?;
            self.shared.uploads.lock().remove(id.as_str());
            Ok(metadata)
        })
    }

    fn abort_upload<'a>(&'a self, id: &'a UploadId) -> Self::AbortUpload<'a> {
        Box::pin(async move {
            let upload = self.shared.uploads.lock().get(id.as_str()).cloned();
            if let Some(upload) = upload {
                let source_owner = upload.clone();
                upload.cancelled.store(true, Ordering::Release);
                self.io(move || upload.staging.lock().abort())
                    .await
                    .map_err(|failure| {
                        failure.with_taint(&source_owner.staging.lock().sources())
                    })?;
                self.shared.uploads.lock().remove(id.as_str());
            }
            Ok(())
        })
    }
}

impl ObjectDelete for FileObjectStore {
    type Delete<'a> = Request<'a, ()>;

    fn delete<'a>(&'a self, blob: &'a BlobRef) -> Self::Delete<'a> {
        Box::pin(async move {
            let shared = self.shared.clone();
            let hash = storage::validate_hash(&blob.hash)?.to_owned();
            self.io(move || storage::delete(&shared, &hash)).await
        })
    }
}

#[cfg(test)]
mod tests;
