use anyhow::{Context, ensure};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::{Barrier, Semaphore};
use xolotl_state::object::{
    ObjectMetadata, ObjectRead, ObjectReadChunk, ObjectWrite, ObjectWriteChunk, UploadId,
    UploadOptions,
};
use xolotl_state::{
    InMemoryBackend, StateError, StateMutation, StateRead, StateResult, StateWrite,
};
use xolotl_storage_fs::FileObjectStore;
use xolotl_types::{BlobRef, Path, TaintSet, Value};

type Operation<'a, T> = Pin<Box<dyn Future<Output = StateResult<T>> + Send + 'a>>;

pub struct Signal(Semaphore);

impl Signal {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(Semaphore::new(0)))
    }
    pub fn notify(&self) {
        self.0.add_permits(1);
    }
    pub async fn wait(&self) -> anyhow::Result<()> {
        tokio::time::timeout(super::harness::TEST_WAIT, self.0.acquire())
            .await??
            .forget();
        Ok(())
    }
}

pub struct ResponseProbe {
    pub completed: Arc<Signal>,
    pub dropped: Arc<Signal>,
    pub data_dropped: Arc<Signal>,
    retained_data: AtomicUsize,
}

impl ResponseProbe {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            completed: Signal::new(),
            dropped: Signal::new(),
            data_dropped: Signal::new(),
            retained_data: AtomicUsize::new(0),
        })
    }

    pub fn retained_data(&self) -> usize {
        self.retained_data.load(Ordering::Acquire)
    }

    pub fn retain_data(&self) {
        self.retained_data.fetch_add(1, Ordering::AcqRel);
    }

    pub fn release_data(&self) {
        self.retained_data.fetch_sub(1, Ordering::AcqRel);
        self.data_dropped.notify();
    }

    pub async fn wait_data_released(&self) -> anyhow::Result<()> {
        while self.retained_data() != 0 {
            self.data_dropped.wait().await?;
        }
        Ok(())
    }
}

pub struct Gate {
    entered: Arc<Signal>,
    exited: Arc<Signal>,
    release: Semaphore,
    armed: AtomicBool,
}

impl Gate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Signal::new(),
            exited: Signal::new(),
            release: Semaphore::new(0),
            armed: AtomicBool::new(true),
        })
    }
    pub async fn block(&self) -> StateResult<()> {
        if !self.armed.swap(false, Ordering::AcqRel) {
            return Ok(());
        }
        let _exit = NotifyOnDrop(self.exited.clone());
        self.entered.notify();
        self.release
            .acquire()
            .await
            .map_err(|e| StateError::Backend(e.to_string()))?
            .forget();
        Ok(())
    }
    pub async fn wait(&self) -> anyhow::Result<()> {
        self.entered.wait().await
    }
    pub async fn wait_exited(&self) -> anyhow::Result<()> {
        self.exited.wait().await
    }
    pub fn open(&self) {
        self.release.add_permits(1);
    }
}

struct NotifyOnDrop(Arc<Signal>);
impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.0.notify();
    }
}

struct TrackedLease {
    lease: Option<UploadId>,
    dropped: Arc<Signal>,
}
impl Drop for TrackedLease {
    fn drop(&mut self) {
        drop(self.lease.take());
        self.dropped.notify();
    }
}

#[derive(Clone)]
pub struct Pause {
    pub gate: Arc<Gate>,
    pub after: bool,
}

#[derive(Default)]
pub struct ProbeOptions {
    pub read: Option<Pause>,
    pub virtual_object: Option<ObjectMetadata>,
    pub write: Option<Pause>,
    pub commit: Option<Pause>,
    pub commit_barrier: Option<Arc<Barrier>>,
}

pub struct ProbeStore {
    inner: FileObjectStore,
    options: ProbeOptions,
    writes: AtomicUsize,
    reads: AtomicUsize,
    commits: AtomicUsize,
    max_write_bytes: AtomicUsize,
    max_read_bytes: AtomicUsize,
    published: Mutex<Vec<ObjectMetadata>>,
    pub dropped: Arc<Signal>,
}

impl ProbeStore {
    pub fn new(inner: FileObjectStore, options: ProbeOptions) -> Self {
        Self {
            inner,
            options,
            writes: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            max_write_bytes: AtomicUsize::new(0),
            max_read_bytes: AtomicUsize::new(0),
            published: Mutex::new(Vec::new()),
            dropped: Signal::new(),
        }
    }
    pub fn writes(&self) -> usize {
        self.writes.load(Ordering::Acquire)
    }
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::Acquire)
    }
    pub fn max_read_bytes(&self) -> usize {
        self.max_read_bytes.load(Ordering::Acquire)
    }
    pub fn commits(&self) -> usize {
        self.commits.load(Ordering::Acquire)
    }
    pub fn max_write_bytes(&self) -> usize {
        self.max_write_bytes.load(Ordering::Acquire)
    }
    pub fn published(&self) -> anyhow::Result<Vec<ObjectMetadata>> {
        Ok(self
            .published
            .lock()
            .map_err(|e| anyhow::anyhow!(e.to_string()))?
            .clone())
    }
}

impl ObjectRead for ProbeStore {
    type Metadata<'a> = Operation<'a, Option<ObjectMetadata>>;
    type ReadChunk<'a> = Operation<'a, ObjectReadChunk>;

    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> Self::Metadata<'a> {
        Box::pin(async move {
            if let Some(metadata) = &self.options.virtual_object
                && metadata.blob.hash == blob.hash
            {
                return Ok(Some(metadata.clone()));
            }
            self.inner.metadata(blob).await
        })
    }

    fn read_chunk<'a>(
        &'a self,
        blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::AcqRel);
            self.max_read_bytes
                .fetch_max(buffer.len(), Ordering::AcqRel);
            if let Some(pause) = &self.options.read
                && !pause.after
            {
                pause.gate.block().await?;
            }
            let result = if let Some(metadata) = &self.options.virtual_object
                && metadata.blob.hash == blob.hash
            {
                let remaining = metadata.blob.size.checked_sub(offset).ok_or_else(|| {
                    StateError::Backend("virtual object offset exceeds its length".into())
                })?;
                let count = buffer
                    .len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                for (index, byte) in buffer[..count].iter_mut().enumerate() {
                    *byte = ((offset % 251 + index as u64 % 251) % 251) as u8;
                }
                ObjectReadChunk {
                    bytes_read: count,
                    end: count as u64 == remaining,
                    taint: metadata.taint.clone(),
                }
            } else {
                self.inner.read_chunk(blob, offset, buffer).await?
            };
            if let Some(pause) = &self.options.read
                && pause.after
            {
                pause.gate.block().await?;
            }
            Ok(result)
        })
    }
}

impl ObjectWrite for ProbeStore {
    type BeginUpload<'a> = Operation<'a, UploadId>;
    type WriteChunk<'a> = Operation<'a, ObjectWriteChunk>;
    type CommitUpload<'a> = Operation<'a, ObjectMetadata>;
    type AbortUpload<'a> = Operation<'a, ()>;

    fn begin_upload(&self, options: UploadOptions) -> Self::BeginUpload<'_> {
        Box::pin(async move {
            let lease = self.inner.begin_upload(options).await?;
            Ok(UploadId::with_lease(
                lease.as_str(),
                TrackedLease {
                    lease: Some(lease.clone()),
                    dropped: self.dropped.clone(),
                },
            ))
        })
    }
    fn write_chunk<'a>(
        &'a self,
        upload: &'a UploadId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::WriteChunk<'a> {
        Box::pin(async move {
            self.writes.fetch_add(1, Ordering::AcqRel);
            self.max_write_bytes
                .fetch_max(bytes.len(), Ordering::AcqRel);
            if let Some(pause) = &self.options.write
                && !pause.after
            {
                pause.gate.block().await?;
            }
            let result = self.inner.write_chunk(upload, offset, bytes).await?;
            if let Some(pause) = &self.options.write
                && pause.after
            {
                pause.gate.block().await?;
            }
            Ok(result)
        })
    }
    fn commit_upload<'a>(
        &'a self,
        upload: &'a UploadId,
        final_taint: &'a TaintSet,
    ) -> Self::CommitUpload<'a> {
        Box::pin(async move {
            self.commits.fetch_add(1, Ordering::AcqRel);
            if let Some(barrier) = &self.options.commit_barrier {
                barrier.wait().await;
            }
            if let Some(pause) = &self.options.commit
                && !pause.after
            {
                pause.gate.block().await?;
            }
            let metadata = self.inner.commit_upload(upload, final_taint).await?;
            self.published
                .lock()
                .map_err(|e| StateError::Backend(e.to_string()))?
                .push(metadata.clone());
            if let Some(pause) = &self.options.commit
                && pause.after
            {
                pause.gate.block().await?;
            }
            Ok(metadata)
        })
    }
    fn abort_upload<'a>(&'a self, upload: &'a UploadId) -> Self::AbortUpload<'a> {
        Box::pin(self.inner.abort_upload(upload))
    }
}

pub struct ReceiptState {
    inner: InMemoryBackend,
    pause: Pause,
    used: bool,
}
impl ReceiptState {
    pub fn new(pause: Pause) -> Self {
        Self {
            inner: InMemoryBackend::new(),
            pause,
            used: false,
        }
    }

    pub fn consuming(pause: Pause) -> Self {
        Self {
            used: true,
            ..Self::new(pause)
        }
    }
}

impl StateRead for ReceiptState {
    type Read<'a> = <InMemoryBackend as StateRead>::Read<'a>;
    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        self.inner.read_tainted(path)
    }
}

impl StateWrite for ReceiptState {
    type Write<'a> = Operation<'a, xolotl_state::StateCommit>;
    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            let changes_receipt = matches!(&mutation, StateMutation::CompareSet { value, .. }
                if value.value.as_map().is_some_and(|map|
                    map.get("committed") == Some(&Value::boolean(true)) && map.get("used") == Some(&Value::boolean(self.used))));
            if changes_receipt && !self.pause.after {
                self.pause.gate.block().await?;
            }
            let commit = self.inner.mutate(path, mutation).await?;
            if changes_receipt && self.pause.after {
                self.pause
                    .gate
                    .block()
                    .await
                    .map_err(|failure| failure.with_taint(&commit.taint))?;
            }
            Ok(commit)
        })
    }
}

pub fn one_published(probe: &ProbeStore) -> anyhow::Result<ObjectMetadata> {
    let mut published = probe.published()?;
    ensure!(published.len() == 1);
    published.pop().context("missing published object")
}
