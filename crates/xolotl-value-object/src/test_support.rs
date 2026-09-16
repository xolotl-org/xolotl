//! Shared object-port fixtures for the writer and borrowed resident adapter.

use alloc::{sync::Arc, vec::Vec};
use anyhow::{Result as TestResult, ensure};
use core::{
    cell::Cell,
    cmp::Ordering as Comparison,
    convert::Infallible,
    future::{Future, Pending, Ready, pending, ready},
    num::NonZeroUsize,
    pin::{Pin, pin},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use std::sync::{Mutex, MutexGuard};
use xolotl_state::{
    StateError, StateFailure, StateResult,
    object::{ObjectMetadata, ObjectWrite, ObjectWriteChunk, UploadId, UploadOptions},
};
use xolotl_types::{BlobRef, TaintSet, TaintSource, value::event::KeyId};
use xolotl_value_codec::validation::{KeyStore, MemoryKeyOptions, MemoryKeyStore};

#[derive(Clone, Copy, Default)]
pub(crate) enum WriteMode {
    #[default]
    Ready,
    Pending,
    Fail,
    InvalidAck,
}

#[derive(Clone, Copy, Default)]
pub(crate) enum CommitMode {
    #[default]
    Ready,
    Pending,
    PublishedPending,
    WrongSize,
    MissingProvenance,
    Fail,
}

#[derive(Default)]
pub(crate) struct Data {
    pub(crate) staging: Vec<u8>,
    pub(crate) published: Option<Vec<u8>>,
    pub(crate) options: Option<UploadOptions>,
    pub(crate) metadata: Option<ObjectMetadata>,
    pub(crate) writes: Vec<(u64, usize, usize)>,
}

#[derive(Default)]
pub(crate) struct Shared {
    data: Mutex<Data>,
    pub(crate) live: AtomicBool,
    pub(crate) cleanups: AtomicUsize,
    pub(crate) begins: AtomicUsize,
    pub(crate) commits: AtomicUsize,
    pub(crate) aborts: AtomicUsize,
}

impl Shared {
    pub(crate) fn data(&self) -> MutexGuard<'_, Data> {
        self.data
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

struct Lease(Arc<Shared>);

impl Drop for Lease {
    fn drop(&mut self) {
        if self.0.live.swap(false, Ordering::SeqCst) {
            let mut data = self.0.data();
            data.staging = Vec::new();
            data.options = None;
            self.0.cleanups.fetch_add(1, Ordering::SeqCst);
        }
    }
}

pub(crate) struct Store {
    pub(crate) shared: Arc<Shared>,
    pub(crate) begin_pending: Cell<bool>,
    pub(crate) begin_fail: Cell<bool>,
    pub(crate) write_mode: Cell<WriteMode>,
    pub(crate) commit_mode: Cell<CommitMode>,
    pub(crate) failure_sources: TaintSet,
    max_ack: usize,
}

impl Store {
    pub(crate) fn new(max_ack: usize) -> Self {
        Self {
            shared: Arc::new(Shared::default()),
            begin_pending: Cell::new(false),
            begin_fail: Cell::new(false),
            write_mode: Cell::new(WriteMode::Ready),
            commit_mode: Cell::new(CommitMode::Ready),
            failure_sources: TaintSet::pristine(),
            max_ack,
        }
    }

    fn write(&self, offset: u64, bytes: &[u8]) -> StateResult<ObjectWriteChunk> {
        if matches!(self.write_mode.get(), WriteMode::Fail) {
            return Err(StateFailure::new(
                StateError::Backend("test write failure".into()),
                self.failure_sources.clone(),
            ));
        }
        let mut data = self.shared.data();
        if offset != data.staging.len() as u64 {
            return Err(
                StateError::Backend("test writer skipped an acknowledgement".into()).into(),
            );
        }
        let accepted = self.max_ack.min(bytes.len());
        data.staging.extend_from_slice(&bytes[..accepted]);
        data.writes.push((offset, bytes.len(), accepted));
        Ok(ObjectWriteChunk {
            bytes_written: accepted,
            next_offset: offset
                + accepted as u64
                + u64::from(matches!(self.write_mode.get(), WriteMode::InvalidAck)),
        })
    }

    fn commit(&self, final_taint: &TaintSet) -> StateResult<ObjectMetadata> {
        if matches!(self.commit_mode.get(), CommitMode::Fail) {
            return Err(StateFailure::new(
                StateError::Backend("test commit failure".into()),
                self.failure_sources.clone(),
            ));
        }
        let mut data = self.shared.data();
        let bytes = core::mem::take(&mut data.staging);
        let size =
            bytes.len() as u64 + u64::from(matches!(self.commit_mode.get(), CommitMode::WrongSize));
        data.published = Some(bytes);
        self.shared.live.store(false, Ordering::SeqCst);
        let mut taint = data
            .options
            .as_ref()
            .ok_or_else(|| StateError::Backend("missing upload options".into()))?
            .taint
            .clone();
        taint.union(final_taint);
        taint.add(TaintSource::ModelOutput);
        if matches!(self.commit_mode.get(), CommitMode::MissingProvenance) {
            taint = TaintSet::of(TaintSource::ModelOutput);
        }
        let metadata = ObjectMetadata {
            blob: BlobRef {
                hash: "sha256:test-value-object".into(),
                size,
                // Deliberately unrelated MIME: the explicit encoding controls reads.
                mime: Some("application/octet-stream".into()),
            },
            taint,
        };
        data.metadata = Some(metadata.clone());
        Ok(metadata)
    }
}

pub(crate) struct Response<T> {
    result: Option<StateResult<T>>,
    pending: bool,
}

impl<T> Response<T> {
    fn new(result: StateResult<T>, pending: bool) -> Self {
        Self {
            result: Some(result),
            pending,
        }
    }
}

impl<T: Unpin> Future for Response<T> {
    type Output = StateResult<T>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.pending {
            return Poll::Pending;
        }
        Poll::Ready(this.result.take().unwrap_or_else(|| {
            Err(StateError::Backend("test response polled after completion".into()).into())
        }))
    }
}

impl ObjectWrite for Store {
    type BeginUpload<'a> = Response<UploadId>;
    type WriteChunk<'a> = Response<ObjectWriteChunk>;
    type CommitUpload<'a> = Response<ObjectMetadata>;
    type AbortUpload<'a> = Response<()>;

    fn begin_upload(&self, options: UploadOptions) -> Self::BeginUpload<'_> {
        self.shared.begins.fetch_add(1, Ordering::SeqCst);
        if self.begin_fail.get() {
            return Response::new(
                Err(StateFailure::new(
                    StateError::Backend("test begin failure".into()),
                    self.failure_sources.clone(),
                )),
                false,
            );
        }
        self.shared.live.store(true, Ordering::SeqCst);
        self.shared.data().options = Some(options);
        Response::new(
            Ok(UploadId::with_lease(
                "test-upload",
                Lease(Arc::clone(&self.shared)),
            )),
            self.begin_pending.get(),
        )
    }

    fn write_chunk<'a>(
        &'a self,
        _upload: &'a UploadId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::WriteChunk<'a> {
        Response::new(
            self.write(offset, bytes),
            matches!(self.write_mode.get(), WriteMode::Pending),
        )
    }

    fn commit_upload<'a>(
        &'a self,
        _upload: &'a UploadId,
        final_taint: &'a TaintSet,
    ) -> Self::CommitUpload<'a> {
        self.shared.commits.fetch_add(1, Ordering::SeqCst);
        if matches!(self.commit_mode.get(), CommitMode::Pending) {
            return Response {
                result: None,
                pending: true,
            };
        }
        Response::new(
            self.commit(final_taint),
            matches!(self.commit_mode.get(), CommitMode::PublishedPending),
        )
    }

    fn abort_upload<'a>(&'a self, _upload: &'a UploadId) -> Self::AbortUpload<'a> {
        self.shared.aborts.fetch_add(1, Ordering::SeqCst);
        Response::new(Ok(()), false)
    }
}

pub(crate) struct BlockingKeys(pub(crate) Arc<AtomicUsize>);

impl Drop for BlockingKeys {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl KeyStore for BlockingKeys {
    type Error = Infallible;
    type Create<'a> = Pending<Result<(), Infallible>>;
    type ComparePrefix<'a> = Ready<Result<Comparison, Infallible>>;
    type Append<'a> = Ready<Result<(), Infallible>>;
    type Release<'a> = Ready<Result<(), Infallible>>;

    fn create(&mut self, _key: KeyId) -> Self::Create<'_> {
        pending()
    }

    fn compare_prefix<'a>(
        &'a mut self,
        _key: KeyId,
        _offset: u64,
        _bytes: &'a [u8],
    ) -> Self::ComparePrefix<'a> {
        ready(Ok(Comparison::Equal))
    }

    fn append<'a>(&'a mut self, _key: KeyId, _offset: u64, _bytes: &'a [u8]) -> Self::Append<'a> {
        ready(Ok(()))
    }

    fn release(&mut self, _key: KeyId) -> Self::Release<'_> {
        ready(Ok(()))
    }
}

pub(crate) fn keys() -> MemoryKeyStore {
    MemoryKeyStore::new(MemoryKeyOptions {
        page_bytes: NonZeroUsize::MIN,
        max_keys: None,
        max_bytes: None,
    })
}

pub(crate) fn run<F, T, E>(future: F) -> TestResult<T>
where
    F: Future<Output = Result<T, E>>,
    E: core::error::Error + Send + Sync + 'static,
{
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => Ok(result?),
        Poll::Pending => anyhow::bail!("test operation unexpectedly yielded"),
    }
}

pub(crate) fn assert_cleaned(store: &Store) -> TestResult<()> {
    ensure!(!store.shared.live.load(Ordering::SeqCst));
    ensure!(store.shared.data().staging.is_empty());
    ensure!(store.shared.cleanups.load(Ordering::SeqCst) == 1);
    ensure!(store.shared.commits.load(Ordering::SeqCst) == 0);
    ensure!(store.shared.aborts.load(Ordering::SeqCst) == 0);
    Ok(())
}
