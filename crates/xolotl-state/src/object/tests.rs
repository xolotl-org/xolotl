mod read;
mod write;

#[cfg(feature = "std")]
mod host {
    use super::super::*;
    use crate::{StateError, host::object::ObjectStore};
    use alloc::{boxed::Box, sync::Arc};
    use anyhow::{Context as _, ensure};
    use core::{
        future::{Pending, Ready, pending, ready},
        num::NonZeroUsize,
        pin::{Pin, pin},
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
        task::{Context, Poll, Waker},
    };

    #[derive(Default)]
    struct Staging {
        live: AtomicBool,
        cleanups: AtomicUsize,
        writes: AtomicUsize,
        aborts: AtomicUsize,
    }

    impl Staging {
        fn cleanup(&self) {
            if self.live.swap(false, Ordering::SeqCst) {
                self.cleanups.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    struct Lease(Arc<Staging>);

    impl Drop for Lease {
        fn drop(&mut self) {
            self.0.cleanup();
        }
    }

    struct Writer(Arc<Staging>);

    impl Writer {
        fn stage(&self) -> UploadId {
            self.0.live.store(true, Ordering::SeqCst);
            UploadId::with_lease("staging", Lease(Arc::clone(&self.0)))
        }
    }

    struct PendingBegin {
        _upload: UploadId,
    }

    impl Future for PendingBegin {
        type Output = StateResult<UploadId>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Pending
        }
    }

    impl ObjectWrite for Writer {
        type BeginUpload<'a> = PendingBegin;
        type WriteChunk<'a> = Pending<StateResult<ObjectWriteChunk>>;
        type CommitUpload<'a> = Ready<StateResult<ObjectMetadata>>;
        type AbortUpload<'a> = Ready<StateResult<()>>;

        fn begin_upload(&self, _options: UploadOptions) -> Self::BeginUpload<'_> {
            PendingBegin {
                _upload: self.stage(),
            }
        }

        fn write_chunk<'a>(
            &'a self,
            _upload: &'a UploadId,
            _offset: u64,
            _bytes: &'a [u8],
        ) -> Self::WriteChunk<'a> {
            self.0.writes.fetch_add(1, Ordering::SeqCst);
            pending()
        }

        fn commit_upload<'a>(
            &'a self,
            _upload: &'a UploadId,
            _final_taint: &'a TaintSet,
        ) -> Self::CommitUpload<'a> {
            ready(Err(StateError::Unsupported("unfinished test upload").into()))
        }

        fn abort_upload<'a>(&'a self, _upload: &'a UploadId) -> Self::AbortUpload<'a> {
            self.0.aborts.fetch_add(1, Ordering::SeqCst);
            self.0.cleanup();
            ready(Ok(()))
        }
    }

    #[test]
    fn upload_clones_share_cleanup_until_the_last_owner_drops() -> anyhow::Result<()> {
        let staging = Arc::new(Staging::default());
        let upload = Writer(Arc::clone(&staging)).stage();
        let other = upload.clone();
        ensure!(Arc::strong_count(upload.lease.as_ref().context("cleanup lease")?) == 2);

        drop(upload);
        ensure!(staging.live.load(Ordering::SeqCst));
        ensure!(staging.cleanups.load(Ordering::SeqCst) == 0);

        drop(other);
        ensure!(!staging.live.load(Ordering::SeqCst));
        ensure!(staging.cleanups.load(Ordering::SeqCst) == 1);
        Ok(())
    }

    #[test]
    fn dropping_an_unpolled_adapter_begin_releases_undelivered_staging() -> anyhow::Result<()> {
        let staging = Arc::new(Staging::default());
        let writer = Writer(Arc::clone(&staging));
        let begin = writer.begin_upload(UploadOptions::default());
        ensure!(staging.live.load(Ordering::SeqCst));

        drop(begin);
        ensure!(!staging.live.load(Ordering::SeqCst));
        ensure!(staging.cleanups.load(Ordering::SeqCst) == 1);
        Ok(())
    }

    #[test]
    fn cancelling_host_begin_releases_undelivered_staging() -> anyhow::Result<()> {
        let staging = Arc::new(Staging::default());
        let objects = ObjectStore::new().with_write(Arc::new(Writer(Arc::clone(&staging))));
        {
            let mut begin = pin!(objects.begin_upload(UploadOptions::default()));
            ensure!(
                begin
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            ensure!(staging.live.load(Ordering::SeqCst));
        }
        ensure!(!staging.live.load(Ordering::SeqCst));
        ensure!(staging.cleanups.load(Ordering::SeqCst) == 1);
        ensure!(staging.aborts.load(Ordering::SeqCst) == 0);
        Ok(())
    }

    #[test]
    fn cancelling_write_all_preserves_the_existing_owner_without_cloning_it() -> anyhow::Result<()>
    {
        let staging = Arc::new(Staging::default());
        let writer = Arc::new(Writer(Arc::clone(&staging)));
        let upload = writer.stage();
        let objects = ObjectStore::new().with_write(writer);
        let lease = upload.lease.as_ref().context("cleanup lease")?;
        {
            let mut writing = pin!(objects.write_all(&upload, 0, b"bytes", NonZeroUsize::MIN));
            ensure!(
                writing
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            ensure!(staging.writes.load(Ordering::SeqCst) == 1);
            ensure!(Arc::strong_count(lease) == 1);
        }
        ensure!(Arc::strong_count(lease) == 1);
        ensure!(staging.live.load(Ordering::SeqCst));
        ensure!(staging.cleanups.load(Ordering::SeqCst) == 0);
        ensure!(staging.aborts.load(Ordering::SeqCst) == 0);

        drop(upload);
        ensure!(!staging.live.load(Ordering::SeqCst));
        ensure!(staging.cleanups.load(Ordering::SeqCst) == 1);
        Ok(())
    }

    #[test]
    fn cancelling_the_upload_owner_cleans_staging_without_awaiting_abort() -> anyhow::Result<()> {
        let staging = Arc::new(Staging::default());
        let writer = Arc::new(Writer(Arc::clone(&staging)));
        let upload = writer.stage();
        let objects = ObjectStore::new().with_write(writer);
        let mut operation = Box::pin(async move {
            objects
                .write_all(&upload, 0, b"bytes", NonZeroUsize::MIN)
                .await
        });
        ensure!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        ensure!(staging.live.load(Ordering::SeqCst));

        drop(operation);
        ensure!(!staging.live.load(Ordering::SeqCst));
        ensure!(staging.cleanups.load(Ordering::SeqCst) == 1);
        ensure!(staging.aborts.load(Ordering::SeqCst) == 0);
        Ok(())
    }

    #[test]
    fn explicit_abort_cleans_early_and_last_owner_drop_is_harmless() -> anyhow::Result<()> {
        let staging = Arc::new(Staging::default());
        let writer = Writer(Arc::clone(&staging));
        let upload = writer.stage();
        let other = upload.clone();
        {
            let mut abort = pin!(writer.abort_upload(&upload));
            let Poll::Ready(result) = abort.as_mut().poll(&mut Context::from_waker(Waker::noop()))
            else {
                anyhow::bail!("explicit test abort must complete immediately");
            };
            result?;
        }
        ensure!(!staging.live.load(Ordering::SeqCst));
        ensure!(staging.cleanups.load(Ordering::SeqCst) == 1);

        drop(upload);
        drop(other);
        ensure!(staging.cleanups.load(Ordering::SeqCst) == 1);
        Ok(())
    }
}

#[cfg(not(feature = "std"))]
#[test]
fn local_lease_cleanup_needs_neither_send_nor_atomic_ownership() -> anyhow::Result<()> {
    use super::UploadId;
    use alloc::rc::Rc;
    use core::cell::Cell;

    struct LocalLease(Rc<Cell<usize>>);

    impl Drop for LocalLease {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    let cleanups = Rc::new(Cell::new(0));
    let upload = UploadId::with_lease("local", LocalLease(Rc::clone(&cleanups)));
    let other = upload.clone();
    drop(upload);
    anyhow::ensure!(cleanups.get() == 0);
    drop(other);
    anyhow::ensure!(cleanups.get() == 1);
    Ok(())
}
