use super::*;

fn hold_cleanup(probe: Arc<IoProbe>) -> anyhow::Result<std::sync::mpsc::Sender<()>> {
    let (ready, started) = std::sync::mpsc::channel();
    let (release, waiting) = std::sync::mpsc::channel();
    let _worker = std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(move || {
            let _gate = probe.cleanup_gate.lock();
            let _ready = ready.send(());
            let _release = waiting.recv();
        })?;
    started.recv()?;
    Ok(release)
}

async fn wait_for_attempts(probe: &IoProbe, count: usize) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        while probe.cleanup_attempts.load(Ordering::Relaxed) < count {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn failed_cleanup_retains_capacity_and_lease_then_recovers() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_uploads: NonZeroUsize::MIN,
            ..FileObjectOptions::default()
        },
    )?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    let probe = &store.shared.probe;
    probe.cleanup_failures.store(usize::MAX, Ordering::Relaxed);
    drop(upload);
    wait_for_attempts(probe, 1).await?;
    ensure!(staged(&store)? == 1);
    ensure!(store.shared.upload_slots.available_permits() == 0);
    ensure!(store.begin_upload(UploadOptions::default()).await.is_err());
    let other = FileObjectStore::open(root.path())?;
    ensure!(staged(&other)? == 1);
    tokio::time::sleep(Duration::from_millis(120)).await;
    ensure!(
        probe.cleanup_attempts.load(Ordering::Relaxed) <= 3,
        "cleanup busy loop"
    );
    probe.cleanup_failures.store(0, Ordering::Relaxed);
    wait_for_cleanup(&store).await?;
    ensure!(staged(&store)? == 0);
    let upload = store.begin_upload(UploadOptions::default()).await?;
    store.abort_upload(&upload).await?;
    Ok(())
}

#[tokio::test]
async fn failed_partial_creation_keeps_its_cleanup_responsibility() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_uploads: NonZeroUsize::MIN,
            ..FileObjectOptions::default()
        },
    )?;
    let probe = &store.shared.probe;
    probe.upload_open_failures.store(1, Ordering::Relaxed);
    probe.cleanup_failures.store(usize::MAX, Ordering::Relaxed);
    ensure!(store.begin_upload(UploadOptions::default()).await.is_err());
    wait_for_attempts(probe, 1).await?;
    ensure!(staged(&store)? == 1 && store.shared.upload_slots.available_permits() == 0);
    ensure!(store.begin_upload(UploadOptions::default()).await.is_err());
    probe.cleanup_failures.store(0, Ordering::Relaxed);
    wait_for_cleanup(&store).await?;
    ensure!(staged(&store)? == 0);
    Ok(())
}

#[tokio::test]
async fn retrying_directory_does_not_block_new_cleanup() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let sender = store.shared.cleanup_sender()?;
    let failing = Arc::new(IoProbe::default());
    failing
        .cleanup_failures
        .store(usize::MAX, Ordering::Relaxed);
    let first = tempfile::Builder::new()
        .prefix("upload-")
        .tempdir_in(root.path().join("staging"))?;
    let first_path = first.path().to_owned();
    sender.enqueue(crate::cleanup::Task {
        file: None,
        directory: first,
        slot: None,
        probe: failing.clone(),
    });
    wait_for_attempts(&failing, 1).await?;
    let healthy = Arc::new(IoProbe::default());
    let second = tempfile::Builder::new()
        .prefix("upload-")
        .tempdir_in(root.path().join("staging"))?;
    let second_path = second.path().to_owned();
    sender.enqueue(crate::cleanup::Task {
        file: None,
        directory: second,
        slot: None,
        probe: healthy.clone(),
    });
    wait_for_attempts(&healthy, 1).await?;
    tokio::time::timeout(Duration::from_secs(2), async {
        while second_path.exists() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await?;
    ensure!(first_path.exists());
    failing.cleanup_failures.store(0, Ordering::Relaxed);
    Ok(())
}

#[test]
fn final_failed_cleanup_exits_and_cold_open_reclaims_leftover() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let store = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_uploads: NonZeroUsize::MIN,
            ..FileObjectOptions::default()
        },
    )?;
    let upload = runtime.block_on(store.begin_upload(UploadOptions::default()))?;
    let probe = Arc::clone(&store.shared.probe);
    probe.cleanup_failures.store(usize::MAX, Ordering::Relaxed);
    let gate = hold_cleanup(probe.clone())?;
    drop(runtime);
    drop(upload);
    drop(store);
    drop(gate);
    let started = std::time::Instant::now();
    while probe.cleanup_exits.load(Ordering::Acquire) == 0 {
        ensure!(
            started.elapsed() < Duration::from_secs(2),
            "cleanup worker did not exit"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    ensure!(probe.cleanup_attempts.load(Ordering::Relaxed) == 2);
    ensure!(std::fs::read_dir(root.path().join("staging"))?.count() == 1);
    let reopened = FileObjectStore::open(root.path())?;
    ensure!(staged(&reopened)? == 0);
    Ok(())
}

#[tokio::test]
async fn publication_retry_confirms_parent_directory_after_a_failed_sync() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    write_all(&store, &upload, b"uncertain publication").await?;
    store
        .shared
        .probe
        .objects_sync_failures
        .store(2, Ordering::Relaxed);
    ensure!(
        store
            .commit_upload(&upload, &TaintSet::author())
            .await
            .is_err()
    );
    ensure!(
        store
            .commit_upload(&upload, &TaintSet::author())
            .await
            .is_err(),
        "retry acknowledged publication without repeating the failed parent sync"
    );
    let receipt = store.commit_upload(&upload, &TaintSet::author()).await?;
    ensure!(
        store
            .shared
            .probe
            .objects_sync_calls
            .load(Ordering::Relaxed)
            == 3
    );
    ensure!(store.metadata(&receipt.blob).await? == Some(receipt));
    Ok(())
}

#[tokio::test]
async fn deletion_retry_confirms_absence_after_a_failed_parent_sync() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    let receipt = store.commit_upload(&upload, &TaintSet::pristine()).await?;
    store
        .shared
        .probe
        .objects_sync_calls
        .store(0, Ordering::Relaxed);
    store
        .shared
        .probe
        .objects_sync_failures
        .store(2, Ordering::Relaxed);
    ensure!(store.delete(&receipt.blob).await.is_err());
    ensure!(
        store.delete(&receipt.blob).await.is_err(),
        "retry acknowledged deletion without repeating the failed parent sync"
    );
    store.delete(&receipt.blob).await?;
    ensure!(
        store
            .shared
            .probe
            .objects_sync_calls
            .load(Ordering::Relaxed)
            == 3
    );
    ensure!(store.metadata(&receipt.blob).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn full_upload_capacity_rejects_before_creating_staging() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_uploads: NonZeroUsize::MIN,
            ..FileObjectOptions::default()
        },
    )?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    for _attempt in 0..4 {
        ensure!(store.begin_upload(UploadOptions::default()).await.is_err());
    }
    ensure!(
        store.shared.probe.upload_creations.load(Ordering::Relaxed) == 1,
        "capacity rejection created staging resources"
    );
    store.abort_upload(&upload).await?;
    Ok(())
}

#[tokio::test]
async fn duplicate_publication_reuses_metadata_but_confirms_failed_source_updates()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    write_all(&store, &upload, b"shared bytes").await?;
    let initial = store.commit_upload(&upload, &TaintSet::author()).await?;
    let writes = store.shared.probe.metadata_writes.load(Ordering::Relaxed);
    let duplicate = store.begin_upload(UploadOptions::default()).await?;
    write_all(&store, &duplicate, b"shared bytes").await?;
    ensure!(store.commit_upload(&duplicate, &TaintSet::author()).await? == initial);
    ensure!(store.shared.probe.metadata_writes.load(Ordering::Relaxed) == writes);
    let update = store.begin_upload(UploadOptions::default()).await?;
    write_all(&store, &update, b"shared bytes").await?;
    let sources = TaintSet::of(TaintSource::ModelOutput);
    store
        .shared
        .probe
        .metadata_sync_failures
        .store(2, Ordering::Relaxed);
    let failure = store
        .commit_upload(&update, &sources)
        .await
        .err()
        .context("source sync failure was acknowledged")?;
    ensure!(failure.taint.contains_all(&initial.taint) && failure.taint.contains_all(&sources));
    ensure!(
        store.commit_upload(&update, &sources).await.is_err(),
        "unchanged metadata bypassed the unfinished sync"
    );
    let receipt = store.commit_upload(&update, &sources).await?;
    ensure!(receipt.taint.contains_all(&initial.taint) && receipt.taint.contains_all(&sources));
    ensure!(store.shared.probe.metadata_writes.load(Ordering::Relaxed) == writes + 1);
    Ok(())
}

#[tokio::test]
async fn creating_uploads_reserve_capacity_and_cancel_without_staging() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_uploads: NonZeroUsize::MIN,
            max_io_tasks: NonZeroUsize::MIN,
            ..FileObjectOptions::default()
        },
    )?;
    let blocker = store.permit().await?;
    let mut begin = store.begin_upload(UploadOptions::default());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    ensure!(begin.as_mut().poll(&mut context).is_pending());
    ensure!(store.pending_uploads() == 0);
    ensure!(store.begin_upload(UploadOptions::default()).await.is_err());
    ensure!(store.shared.probe.upload_creations.load(Ordering::Relaxed) == 0);
    drop(begin);
    drop(blocker);
    let upload = store.begin_upload(UploadOptions::default()).await?;
    store.abort_upload(&upload).await?;
    Ok(())
}

#[tokio::test]
async fn deferred_cleanup_keeps_capacity_and_root_ownership_without_blocking_drop()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_uploads: NonZeroUsize::MIN,
            ..FileObjectOptions::default()
        },
    )?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    let gate = hold_cleanup(Arc::clone(&store.shared.probe))?;
    drop(upload);
    ensure!(store.pending_uploads() == 0);
    ensure!(store.begin_upload(UploadOptions::default()).await.is_err());
    let other = FileObjectStore::open(root.path())?;
    ensure!(
        staged(&other)? == 1,
        "another opener reclaimed owned cleanup"
    );
    drop(gate);
    wait_for_cleanup(&store).await?;
    ensure!(staged(&other)? == 0);
    let upload = store.begin_upload(UploadOptions::default()).await?;
    store.abort_upload(&upload).await?;
    Ok(())
}

#[test]
fn cleanup_survives_tokio_shutdown_and_the_last_store_drop() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = runtime.block_on(store.begin_upload(UploadOptions::default()))?;
    let probe = Arc::clone(&store.shared.probe);
    let gate = hold_cleanup(probe)?;
    drop(runtime);
    drop(store);
    drop(upload);
    let other = FileObjectStore::open(root.path())?;
    ensure!(staged(&other)? == 1);
    drop(gate);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), async {
            while staged(&other)? != 0 {
                tokio::task::yield_now().await;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await
    })??;
    Ok(())
}

#[tokio::test]
async fn creation_failure_releases_capacity_and_preserves_initial_sources() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_uploads: NonZeroUsize::MIN,
            ..FileObjectOptions::default()
        },
    )?;
    std::fs::remove_dir(store.root().join("staging"))?;
    let sources = TaintSet::author();
    let failure = store
        .begin_upload(UploadOptions {
            taint: sources.clone(),
            ..UploadOptions::default()
        })
        .await
        .err()
        .context("missing staging was accepted")?;
    ensure!(failure.taint.contains_all(&sources));
    ensure!(store.shared.upload_slots.available_permits() == 1);
    std::fs::create_dir(store.root().join("staging"))?;
    store
        .shared
        .probe
        .upload_open_failures
        .store(1, Ordering::Relaxed);
    let failure = store
        .begin_upload(UploadOptions {
            taint: sources.clone(),
            ..UploadOptions::default()
        })
        .await
        .err()
        .context("partial creation failure was acknowledged")?;
    ensure!(failure.taint.contains_all(&sources));
    wait_for_cleanup(&store).await?;
    ensure!(store.shared.upload_slots.available_permits() == 1 && staged(&store)? == 0);
    let upload = store.begin_upload(UploadOptions::default()).await?;
    store.abort_upload(&upload).await?;
    Ok(())
}

#[tokio::test]
async fn lost_receipt_keeps_its_upload_slot_until_the_original_retry() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_uploads: NonZeroUsize::MIN,
            ..FileObjectOptions::default()
        },
    )?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    let barrier = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(store.root().join("commit.lock"))?;
    barrier.lock()?;
    let sources = TaintSet::author();
    let mut commit = store.commit_upload(&upload, &sources);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    ensure!(commit.as_mut().poll(&mut context).is_pending());
    drop(commit);
    drop(barrier);
    wait_for_io(&store).await?;
    ensure!(staged(&store)? == 0 && store.pending_uploads() == 1);
    ensure!(store.begin_upload(UploadOptions::default()).await.is_err());
    store.commit_upload(&upload, &sources).await?;
    let replacement = store.begin_upload(UploadOptions::default()).await?;
    store.abort_upload(&replacement).await?;
    Ok(())
}
