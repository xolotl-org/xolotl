use super::*;
use anyhow::{Context, ensure};
use std::time::Duration;
use xolotl_types::{TaintSet, TaintSource};

mod commit;
mod metadata;

fn options(chunk_bytes: usize) -> anyhow::Result<FileObjectOptions> {
    Ok(FileObjectOptions {
        chunk_bytes: NonZeroUsize::new(chunk_bytes).context("chunk window must be nonzero")?,
        ..FileObjectOptions::default()
    })
}

async fn write_all(store: &FileObjectStore, upload: &UploadId, bytes: &[u8]) -> anyhow::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let chunk = store
            .write_chunk(upload, offset as u64, &bytes[offset..])
            .await?;
        ensure!(
            chunk.bytes_written > 0 && chunk.bytes_written <= store.options().chunk_bytes.get()
        );
        offset = usize::try_from(chunk.next_offset)?;
    }
    Ok(())
}

fn staged(store: &FileObjectStore) -> anyhow::Result<usize> {
    Ok(std::fs::read_dir(store.root().join("staging"))?.count())
}

async fn wait_for_io(store: &FileObjectStore) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        while store.shared.io.available_permits() != store.options().max_io_tasks.get() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn objects_publish_only_after_size_validation_and_roundtrip_after_reopen()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(root.path(), options(3)?)?;
    let upload = store
        .begin_upload(UploadOptions {
            expected_size: Some(6),
            mime: Some("application/octet-stream".into()),
            ..UploadOptions::default()
        })
        .await?;
    let blob = BlobRef {
        hash: blake3::hash(b"abcdef").to_hex().to_string(),
        size: 6,
        mime: None,
    };
    let first = store.write_chunk(&upload, 0, b"abcdef").await?;
    ensure!(first.bytes_written == 3 && first.next_offset == 3);
    ensure!(store.metadata(&blob).await?.is_none());
    ensure!(
        store
            .commit_upload(&upload, &TaintSet::pristine())
            .await
            .is_err()
    );
    ensure!(store.pending_uploads() == 1);
    store
        .write_chunk(&upload, first.next_offset, b"def")
        .await?;
    let committed = store.commit_upload(&upload, &TaintSet::pristine()).await?;
    ensure!(committed.blob.hash == blob.hash && committed.blob.size == 6);
    ensure!(committed.blob.mime.as_deref() == Some("application/octet-stream"));
    ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);
    drop(store);

    let store = FileObjectStore::with_options(root.path(), options(3)?)?;
    let mut hint = blob;
    hint.size = 0;
    ensure!(store.metadata(&hint).await? == Some(committed));
    let mut buffer = [0; 8];
    let first = store.read_chunk(&hint, 0, &mut buffer).await?;
    ensure!(first.bytes_read == 3 && !first.end && &buffer[..3] == b"abc");
    let last = store.read_chunk(&hint, 3, &mut buffer).await?;
    ensure!(last.bytes_read == 3 && last.end && &buffer[..3] == b"def");
    let end = store.read_chunk(&hint, 6, &mut buffer).await?;
    ensure!(end.bytes_read == 0 && end.end);
    ensure!(store.read_chunk(&hint, 7, &mut buffer).await.is_err());
    Ok(())
}

#[tokio::test]
async fn chunk_retries_are_idempotent_and_conflicts_leave_the_upload_intact() -> anyhow::Result<()>
{
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(root.path(), options(8)?)?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    store.write_chunk(&upload, 0, b"abc").await?;
    let replay = store.write_chunk(&upload, 0, b"abc").await?;
    ensure!(replay.next_offset == 3 && replay.bytes_written == 3);
    ensure!(store.write_chunk(&upload, 0, b"axc").await.is_err());
    ensure!(store.write_chunk(&upload, 4, b"e").await.is_err());
    let overlap = store.write_chunk(&upload, 1, b"bcdef").await?;
    ensure!(overlap.next_offset == 6 && overlap.bytes_written == 5);
    let metadata = store.commit_upload(&upload, &TaintSet::pristine()).await?;
    ensure!(
        metadata.blob.size == 6 && metadata.blob.hash == blake3::hash(b"abcdef").to_hex().as_str()
    );
    Ok(())
}

#[tokio::test]
async fn old_chunk_replays_compose_with_bounded_host_writes_and_append_once() -> anyhow::Result<()>
{
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(root.path(), options(4)?)?;
    let objects = store.clone().into_object_store();
    let upload = objects.begin_upload(UploadOptions::default()).await?;
    let window = NonZeroUsize::new(3).context("write window")?;
    ensure!(objects.write_all(&upload, 0, b"abcdefgh", window).await? == 8);

    let old = store.write_chunk(&upload, 1, b"bc").await?;
    ensure!(old.bytes_written == 2 && old.next_offset == 3);
    ensure!(
        objects
            .write_all(&upload, 0, b"abcdefghijk", window)
            .await?
            == 11
    );
    ensure!(store.write_chunk(&upload, 2, b"cx").await.is_err());
    ensure!(objects.write_all(&upload, 11, b"lm", window).await? == 13);

    let expected = b"abcdefghijklm";
    let metadata = objects
        .commit_upload(&upload, &TaintSet::pristine())
        .await?;
    ensure!(metadata.blob.size == expected.len() as u64);
    ensure!(metadata.blob.hash == blake3::hash(expected).to_hex().as_str());
    let mut buffer = [0; 3];
    let mut offset = 0;
    while offset < expected.len() {
        let chunk = objects
            .read_chunk(&metadata.blob, offset as u64, &mut buffer)
            .await?;
        ensure!(chunk.bytes_read > 0 && chunk.bytes_read <= buffer.len());
        let end = offset + chunk.bytes_read;
        ensure!(&buffer[..chunk.bytes_read] == &expected[offset..end]);
        ensure!(chunk.end == (end == expected.len()));
        offset = end;
    }
    ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);
    Ok(())
}

#[tokio::test]
async fn uploads_larger_than_the_chunk_window_use_incremental_hashing_and_reads()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(root.path(), options(4096)?)?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0;
    for index in 0..1024u64 {
        let bytes = [index as u8; 4096];
        hasher.update(&bytes);
        let chunk = store.write_chunk(&upload, offset, &bytes).await?;
        ensure!(chunk.bytes_written == bytes.len());
        offset = chunk.next_offset;
    }
    let metadata = store.commit_upload(&upload, &TaintSet::pristine()).await?;
    ensure!(metadata.blob.size == 4 * 1024 * 1024);
    ensure!(metadata.blob.hash == hasher.finalize().to_hex().as_str());
    let mut read_hash = blake3::Hasher::new();
    let mut buffer = [0; 16_384];
    let mut offset = 0;
    loop {
        let chunk = store
            .read_chunk(&metadata.blob, offset, &mut buffer)
            .await?;
        ensure!(chunk.bytes_read <= 4096);
        read_hash.update(&buffer[..chunk.bytes_read]);
        offset += chunk.bytes_read as u64;
        if chunk.end {
            break;
        }
        ensure!(chunk.bytes_read > 0);
    }
    ensure!(
        offset == metadata.blob.size
            && read_hash.finalize().to_hex().as_str() == metadata.blob.hash
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_stores_union_provenance_without_overwriting_content() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let first = FileObjectStore::open(root.path())?;
    let second = FileObjectStore::open(root.path())?;
    let protected = TaintSet::of(TaintSource::Protected {
        path: xolotl_types::Path::parse("state://private/object")?,
    });
    let model = TaintSet::of(TaintSource::ModelOutput);
    let a = first
        .begin_upload(UploadOptions {
            taint: protected.clone(),
            ..UploadOptions::default()
        })
        .await?;
    let b = second
        .begin_upload(UploadOptions {
            taint: model.clone(),
            ..UploadOptions::default()
        })
        .await?;
    write_all(&first, &a, b"same payload").await?;
    write_all(&second, &b, b"same payload").await?;
    let inbound = TaintSet::of(TaintSource::Inbound {
        source: "provider/final-response".into(),
        channel: "inference".into(),
    });
    let fetched = TaintSet::of(TaintSource::Fetched {
        host: "late-source.example".into(),
    });
    let (a, b) = tokio::join!(
        first.commit_upload(&a, &inbound),
        second.commit_upload(&b, &fetched)
    );
    let a = a?;
    let b = b?;
    ensure!(a.blob == b.blob);
    ensure!(a.taint.contains_all(&protected) && a.taint.contains_all(&inbound));
    ensure!(b.taint.contains_all(&model) && b.taint.contains_all(&fetched));
    let metadata = first
        .metadata(&a.blob)
        .await?
        .context("missing committed object")?;
    let mut expected = protected;
    expected.union(&model);
    expected.union(&inbound);
    expected.union(&fetched);
    ensure!(metadata.taint.sources().len() == expected.sources().len());
    ensure!(
        expected
            .sources()
            .iter()
            .all(|source| metadata.taint.sources().contains(source))
    );
    let mut bytes = [0; 12];
    let read = second.read_chunk(&a.blob, 0, &mut bytes).await?;
    ensure!(read.end && &bytes == b"same payload" && read.taint == metadata.taint);
    drop(first);
    drop(second);
    let reopened = FileObjectStore::open(root.path())?;
    ensure!(reopened.metadata(&a.blob).await? == Some(metadata));
    Ok(())
}

#[tokio::test]
async fn upload_ownership_cleans_staging_on_the_last_lease_drop() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    let retained = upload.clone();
    write_all(&store, &upload, b"uncommitted").await?;
    drop(upload);
    ensure!(store.pending_uploads() == 1 && staged(&store)? == 1);
    drop(retained);
    ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);

    let upload = store.begin_upload(UploadOptions::default()).await?;
    store.abort_upload(&upload).await?;
    store.abort_upload(&upload).await?;
    ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);
    ensure!(store.write_chunk(&upload, 0, b"late").await.is_err());
    Ok(())
}

#[tokio::test]
async fn cancelled_queued_io_cannot_reanimate_an_abandoned_upload() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    {
        let record = store.upload(&upload)?;
        let lock = record.staging.lock();
        let mut write = store.write_chunk(&upload, 0, b"pending");
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        ensure!(write.as_mut().poll(&mut context).is_pending());
        drop(write);
        drop(upload);
        ensure!(store.pending_uploads() == 0 && record.cancelled.load(Ordering::Acquire));
        drop(lock);
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if staged(&store)? == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    ensure!(
        std::fs::read_dir(root.path().join("objects"))?
            .next()
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn upload_capacity_is_released_by_commit_abort_and_drop() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_uploads: NonZeroUsize::MIN,
            ..FileObjectOptions::default()
        },
    )?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    ensure!(store.begin_upload(UploadOptions::default()).await.is_err());
    ensure!(staged(&store)? == 1);
    let empty = store.commit_upload(&upload, &TaintSet::pristine()).await?;
    ensure!(empty.blob.size == 0 && empty.blob.hash == blake3::hash(&[]).to_hex().as_str());
    let upload = store.begin_upload(UploadOptions::default()).await?;
    store.abort_upload(&upload).await?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    drop(upload);
    ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);
    Ok(())
}

#[tokio::test]
async fn metadata_limits_and_invalid_hashes_fail_before_publication_or_path_access()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_metadata_bytes: NonZeroUsize::new(128).context("metadata limit")?,
            ..FileObjectOptions::default()
        },
    )?;
    let upload = store
        .begin_upload(UploadOptions {
            mime: Some("x".repeat(256)),
            ..UploadOptions::default()
        })
        .await?;
    ensure!(
        store
            .commit_upload(&upload, &TaintSet::pristine())
            .await
            .is_err()
    );
    ensure!(store.pending_uploads() == 1);
    ensure!(
        std::fs::read_dir(root.path().join("objects"))?
            .next()
            .is_none()
    );
    store.abort_upload(&upload).await?;
    for hash in ["../escape", "", "/tmp/escape", "ABCDEF"] {
        let blob = BlobRef {
            hash: hash.into(),
            size: 0,
            mime: None,
        };
        ensure!(store.metadata(&blob).await.is_err());
        ensure!(store.read_chunk(&blob, 0, &mut [0; 1]).await.is_err());
    }
    Ok(())
}

#[test]
fn cancelled_begin_releases_staging_that_was_never_delivered() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_time()
        .build()?;
    runtime.block_on(async {
        let store = FileObjectStore::open(root.path())?;
        let (release, wait) = std::sync::mpsc::channel();
        let entered = Arc::new(tokio::sync::Notify::new());
        let observed = entered.clone();
        let blocker = tokio::task::spawn_blocking(move || {
            observed.notify_one();
            wait.recv()
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
        let mut begin = store.begin_upload(UploadOptions::default());
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        ensure!(begin.as_mut().poll(&mut context).is_pending());
        drop(begin);
        release.send(())?;
        blocker.await??;
        wait_for_io(&store).await?;
        ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);
        Ok(())
    })
}

#[tokio::test]
async fn interrupted_commit_can_retry_but_a_dropped_upload_cannot_publish() -> anyhow::Result<()> {
    for abandon in [false, true] {
        let root = tempfile::tempdir()?;
        let store = FileObjectStore::open(root.path())?;
        let upload = store.begin_upload(UploadOptions::default()).await?;
        write_all(&store, &upload, b"committed bytes").await?;
        let barrier = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(root.path().join("commit.lock"))?;
        barrier.lock()?;
        let final_taint = TaintSet::pristine();
        let mut commit = store.commit_upload(&upload, &final_taint);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        ensure!(commit.as_mut().poll(&mut context).is_pending());
        drop(commit);
        if abandon {
            drop(upload);
            drop(barrier);
            wait_for_io(&store).await?;
            ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);
            ensure!(
                std::fs::read_dir(root.path().join("objects"))?
                    .next()
                    .is_none()
            );
        } else {
            drop(barrier);
            wait_for_io(&store).await?;
            ensure!(store.pending_uploads() == 1);
            let metadata = store.commit_upload(&upload, &final_taint).await?;
            ensure!(metadata.blob.hash == blake3::hash(b"committed bytes").to_hex().as_str());
            ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);
            ensure!(std::fs::read_dir(root.path().join("objects"))?.count() == 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn explicit_delete_is_idempotent_and_allows_republishing_the_same_hash() -> anyhow::Result<()>
{
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    write_all(&store, &upload, b"replaceable").await?;
    let original = store.commit_upload(&upload, &TaintSet::pristine()).await?;
    store.delete(&original.blob).await?;
    store.delete(&original.blob).await?;
    ensure!(store.metadata(&original.blob).await?.is_none());
    ensure!(staged(&store)? == 0);
    let upload = store.begin_upload(UploadOptions::default()).await?;
    write_all(&store, &upload, b"replaceable").await?;
    let replaced = store.commit_upload(&upload, &TaintSet::pristine()).await?;
    ensure!(replaced == original);
    let store = store.into_object_store();
    store.delete(&original.blob).await?;
    ensure!(store.metadata(&original.blob).await?.is_none());
    Ok(())
}
