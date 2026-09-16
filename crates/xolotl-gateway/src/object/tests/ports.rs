use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{Barrier, Semaphore};
use xolotl_state::object::{
    ObjectMetadata, ObjectRead, ObjectReadChunk, ObjectWrite, ObjectWriteChunk, UploadId,
    UploadOptions,
};
use xolotl_state::{StateError, StateResult};
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{BlobRef, TaintSet};

type Request<'a, T> = Pin<Box<dyn Future<Output = StateResult<T>> + Send + 'a>>;

#[derive(Clone, Copy, Default)]
pub(super) enum MetadataReply {
    #[default]
    Stored,
    Missing,
    Error,
    WrongHash,
    WrongSize,
    WrongMime,
}

#[derive(Clone, Copy, Default)]
pub(super) enum WriteReply {
    #[default]
    Full,
    Partial(usize),
    Zero,
    Excessive,
    WrongOffset,
    Error,
}

pub(super) struct Gate {
    entered: Semaphore,
    release: Semaphore,
}

impl Gate {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
        })
    }

    pub(super) async fn enter(&self) -> StateResult<()> {
        self.entered.add_permits(1);
        self.release
            .acquire()
            .await
            .map_err(|error| StateError::Backend(error.to_string()))?
            .forget();
        Ok(())
    }

    pub(super) async fn wait(&self) -> anyhow::Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(5), self.entered.acquire())
            .await??
            .forget();
        Ok(())
    }

    pub(super) fn release(&self) {
        self.release.add_permits(1);
    }
}

pub(super) struct ProbeStore {
    inner: FileObjectStore,
    pub(super) metadata_reads: AtomicUsize,
    pub(super) writes: AtomicUsize,
    pub(super) max_write_bytes: AtomicUsize,
    pub(super) aborts: AtomicUsize,
    pub(super) metadata_reply: MetadataReply,
    pub(super) write_reply: WriteReply,
    pub(super) commit_error: bool,
    pub(super) metadata_gate: Option<Arc<Gate>>,
    pub(super) write_gate: Option<Arc<Gate>>,
    pub(super) commit_barrier: Option<Arc<Barrier>>,
}

impl ProbeStore {
    pub(super) fn new(inner: FileObjectStore) -> Self {
        Self {
            inner,
            metadata_reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            max_write_bytes: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
            metadata_reply: MetadataReply::Stored,
            write_reply: WriteReply::Full,
            commit_error: false,
            metadata_gate: None,
            write_gate: None,
            commit_barrier: None,
        }
    }
}

impl ObjectRead for ProbeStore {
    type Metadata<'a> = Request<'a, Option<ObjectMetadata>>;
    type ReadChunk<'a> = Request<'a, ObjectReadChunk>;

    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> Self::Metadata<'a> {
        Box::pin(async move {
            self.metadata_reads.fetch_add(1, Ordering::Relaxed);
            if let Some(gate) = &self.metadata_gate {
                gate.enter().await?;
            }
            match self.metadata_reply {
                MetadataReply::Missing => return Ok(None),
                MetadataReply::Error => {
                    return Err(StateError::Backend("metadata failed".into()).into());
                }
                _ => {}
            }
            let mut metadata = self.inner.metadata(blob).await?;
            if let Some(metadata) = &mut metadata {
                match self.metadata_reply {
                    MetadataReply::WrongHash => metadata.blob.hash = "a".repeat(64),
                    MetadataReply::WrongSize => metadata.blob.size += 1,
                    MetadataReply::WrongMime => metadata.blob.mime = Some("text/plain".into()),
                    _ => {}
                }
            }
            Ok(metadata)
        })
    }

    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        Box::pin(self.inner.read_chunk(blob, offset, buffer))
    }
}

impl ObjectWrite for ProbeStore {
    type BeginUpload<'a> = Request<'a, UploadId>;
    type WriteChunk<'a> = Request<'a, ObjectWriteChunk>;
    type CommitUpload<'a> = Request<'a, ObjectMetadata>;
    type AbortUpload<'a> = Request<'a, ()>;

    fn begin_upload(&self, options: UploadOptions) -> Self::BeginUpload<'_> {
        Box::pin(self.inner.begin_upload(options))
    }

    fn write_chunk<'a>(
        &'a self,
        upload: &'a UploadId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::WriteChunk<'a> {
        Box::pin(async move {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.max_write_bytes
                .fetch_max(bytes.len(), Ordering::Relaxed);
            if let Some(gate) = &self.write_gate {
                gate.enter().await?;
            }
            match self.write_reply {
                WriteReply::Zero => Ok(ObjectWriteChunk {
                    bytes_written: 0,
                    next_offset: offset,
                }),
                WriteReply::Excessive => Ok(ObjectWriteChunk {
                    bytes_written: bytes.len() + 1,
                    next_offset: offset + bytes.len() as u64 + 1,
                }),
                WriteReply::WrongOffset => Ok(ObjectWriteChunk {
                    bytes_written: bytes.len(),
                    next_offset: offset + bytes.len() as u64 + 1,
                }),
                WriteReply::Error => Err(StateError::Backend("write failed".into()).into()),
                WriteReply::Partial(limit) => {
                    self.inner
                        .write_chunk(upload, offset, &bytes[..limit.min(bytes.len())])
                        .await
                }
                WriteReply::Full => self.inner.write_chunk(upload, offset, bytes).await,
            }
        })
    }

    fn commit_upload<'a>(
        &'a self,
        upload: &'a UploadId,
        final_taint: &'a TaintSet,
    ) -> Self::CommitUpload<'a> {
        Box::pin(async move {
            if let Some(barrier) = &self.commit_barrier {
                barrier.wait().await;
            }
            if self.commit_error {
                return Err(StateError::Backend("commit failed".into()).into());
            }
            self.inner.commit_upload(upload, final_taint).await
        })
    }

    fn abort_upload<'a>(&'a self, upload: &'a UploadId) -> Self::AbortUpload<'a> {
        Box::pin(async move {
            self.aborts.fetch_add(1, Ordering::Relaxed);
            self.inner.abort_upload(upload).await
        })
    }
}
