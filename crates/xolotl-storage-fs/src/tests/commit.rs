use super::*;

fn protected_sources() -> anyhow::Result<TaintSet> {
    Ok(TaintSet::of(TaintSource::Protected {
        path: xolotl_types::Path::parse("state://private/final-object-source")?,
    }))
}

fn fetched_sources() -> TaintSet {
    TaintSet::of(TaintSource::Fetched {
        host: "existing.example".into(),
    })
}

async fn lose_commit_receipt(
    store: &FileObjectStore,
    upload: &UploadId,
    final_taint: &TaintSet,
) -> anyhow::Result<()> {
    let barrier = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(store.root().join("commit.lock"))?;
    barrier.lock()?;
    let mut commit = store.commit_upload(upload, final_taint);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    ensure!(commit.as_mut().poll(&mut context).is_pending());
    drop(commit);
    drop(barrier);
    wait_for_io(store).await?;
    ensure!(store.pending_uploads() == 1 && staged(store)? == 0);
    Ok(())
}

#[tokio::test]
async fn incomplete_preflight_leaves_content_and_sources_open_until_publication()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::with_options(root.path(), options(3)?)?;
    let upload = store
        .begin_upload(UploadOptions {
            expected_size: Some(6),
            taint: TaintSet::author(),
            ..UploadOptions::default()
        })
        .await?;
    store.write_chunk(&upload, 0, b"abc").await?;
    ensure!(
        store
            .commit_upload(&upload, &TaintSet::of(TaintSource::ModelOutput))
            .await
            .is_err()
    );
    ensure!(std::fs::read_dir(store.root().join("objects"))?.count() == 0);
    store.write_chunk(&upload, 3, b"def").await?;
    let final_taint = protected_sources()?;
    let expected = TaintSet::author().merged(&final_taint);
    let committed = store.commit_upload(&upload, &final_taint).await?;
    ensure!(committed.taint == expected);
    ensure!(committed.blob.hash == blake3::hash(b"abcdef").to_hex().as_str());
    drop(upload);
    drop(store);

    let reopened = FileObjectStore::with_options(root.path(), options(3)?)?;
    ensure!(reopened.metadata(&committed.blob).await? == Some(committed.clone()));
    for offset in [0, 3, 6] {
        let mut bytes = [0; 3];
        let read = reopened
            .read_chunk(&committed.blob, offset, &mut bytes)
            .await?;
        ensure!(read.taint == expected);
        ensure!(read.end == (offset >= 3));
        ensure!(read.bytes_read == if offset == 6 { 0 } else { 3 });
    }
    Ok(())
}

#[tokio::test]
async fn failed_publication_freezes_bytes_and_effective_sources_for_retry() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = store
        .begin_upload(UploadOptions {
            taint: TaintSet::author(),
            ..UploadOptions::default()
        })
        .await?;
    write_all(&store, &upload, b"frozen bytes").await?;
    let final_taint = protected_sources()?.merged(&TaintSet::of(TaintSource::ModelOutput));
    let expected = TaintSet::author().merged(&final_taint);

    // The real publication lock cannot be opened as a file, after preflight has
    // succeeded and the request has already frozen its bytes and provenance.
    let obstruction = store.root().join("commit.lock");
    std::fs::create_dir(&obstruction)?;
    let failure = store
        .commit_upload(&upload, &final_taint)
        .await
        .err()
        .context("obstructed publication succeeded")?;
    ensure!(failure.taint.contains_all(&expected));
    ensure!(store.pending_uploads() == 1 && staged(&store)? == 1);
    ensure!(
        store
            .write_chunk(&upload, 0, b"frozen bytes")
            .await
            .is_err()
    );
    let failure = store
        .write_chunk(&upload, 12, b"late")
        .await
        .err()
        .context("sealed upload accepted more bytes")?;
    ensure!(failure.taint.contains_all(&expected));
    ensure!(store.write_chunk(&upload, 12, b"").await.is_err());
    std::fs::remove_dir(obstruction)?;

    ensure!(
        store
            .commit_upload(&upload, &protected_sources()?)
            .await
            .is_err()
    );
    ensure!(
        store
            .commit_upload(&upload, &final_taint.clone().merged(&fetched_sources()))
            .await
            .is_err()
    );
    ensure!(std::fs::read_dir(store.root().join("objects"))?.count() == 0);

    let mut equivalent = TaintSet::of(TaintSource::ModelOutput).merged(&protected_sources()?);
    equivalent.union(&TaintSet::author());
    let repeated: TaintSet = serde_json::from_value(serde_json::json!({
        "sources": equivalent.sources().iter().chain(equivalent.sources()).collect::<Vec<_>>()
    }))?;
    ensure!(repeated.sources().len() == equivalent.sources().len() * 2);
    let committed = store.commit_upload(&upload, &repeated).await?;
    ensure!(
        committed.taint == expected,
        "retry changed the frozen source order"
    );
    ensure!(committed.blob.hash == blake3::hash(b"frozen bytes").to_hex().as_str());
    ensure!(store.metadata(&committed.blob).await? == Some(committed.clone()));
    ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);
    drop(upload);
    ensure!(store.metadata(&committed.blob).await? == Some(committed));
    Ok(())
}

#[tokio::test]
async fn unstarted_and_cancelled_queued_commits_leave_the_upload_writable() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = store.begin_upload(UploadOptions::default()).await?;
    let abandoned_sources = fetched_sources();
    drop(store.commit_upload(&upload, &abandoned_sources));
    store.write_chunk(&upload, 0, b"abc").await?;

    let permits = store
        .shared
        .io
        .clone()
        .acquire_many_owned(u32::try_from(store.options().max_io_tasks.get())?)
        .await?;
    let mut commit = store.commit_upload(&upload, &abandoned_sources);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    ensure!(commit.as_mut().poll(&mut context).is_pending());
    drop(commit);
    drop(permits);

    store.write_chunk(&upload, 3, b"def").await?;
    let accepted_sources = protected_sources()?;
    let metadata = store.commit_upload(&upload, &accepted_sources).await?;
    ensure!(metadata.taint == accepted_sources);
    ensure!(metadata.blob.hash == blake3::hash(b"abcdef").to_hex().as_str());
    ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);
    Ok(())
}

#[tokio::test]
async fn lost_receipts_keep_the_original_request_and_never_delete_published_content()
-> anyhow::Result<()> {
    enum Completion {
        Retry,
        Abort,
        Drop,
    }

    for deduplicated in [false, true] {
        for completion in [Completion::Retry, Completion::Abort, Completion::Drop] {
            let root = tempfile::tempdir()?;
            let store = FileObjectStore::open(root.path())?;
            let existing_sources = fetched_sources();
            if deduplicated {
                let existing = store.begin_upload(UploadOptions::default()).await?;
                write_all(&store, &existing, b"shared bytes").await?;
                store.commit_upload(&existing, &existing_sources).await?;
            }
            let upload = store
                .begin_upload(UploadOptions {
                    taint: TaintSet::author(),
                    ..UploadOptions::default()
                })
                .await?;
            write_all(&store, &upload, b"shared bytes").await?;
            let final_taint = protected_sources()?.merged(&TaintSet::of(TaintSource::ModelOutput));
            lose_commit_receipt(&store, &upload, &final_taint).await?;
            let blob = BlobRef {
                hash: blake3::hash(b"shared bytes").to_hex().to_string(),
                size: 12,
                mime: None,
            };
            let published = store.metadata(&blob).await?.context("published receipt")?;
            let mut expected = TaintSet::author().merged(&final_taint);
            if deduplicated {
                expected.union(&existing_sources);
            }
            ensure!(published.taint.contains_all(&expected));
            ensure!(expected.contains_all(&published.taint));
            ensure!(
                store
                    .write_chunk(&upload, 0, b"shared bytes")
                    .await
                    .is_err()
            );
            ensure!(
                store
                    .commit_upload(&upload, &final_taint.clone().merged(&existing_sources))
                    .await
                    .is_err(),
                "a deduplicated receipt must not widen the allowed retry request"
            );
            let failure = store
                .commit_upload(&upload, &TaintSet::pristine())
                .await
                .err()
                .context("changed retry sources were accepted")?;
            ensure!(failure.taint.contains_all(&expected));
            ensure!(store.metadata(&blob).await? == Some(published.clone()));

            match completion {
                Completion::Retry => {
                    let reordered = TaintSet::of(TaintSource::ModelOutput)
                        .merged(&protected_sources()?)
                        .merged(&TaintSet::author());
                    ensure!(store.commit_upload(&upload, &reordered).await? == published);
                    drop(upload);
                }
                Completion::Abort => {
                    store.abort_upload(&upload).await?;
                    drop(upload);
                }
                Completion::Drop => drop(upload),
            }
            ensure!(store.pending_uploads() == 0 && staged(&store)? == 0);
            drop(store);
            let reopened = FileObjectStore::open(root.path())?;
            ensure!(reopened.metadata(&blob).await? == Some(published.clone()));
            let mut bytes = [0; 12];
            let read = reopened.read_chunk(&blob, 0, &mut bytes).await?;
            ensure!(read.end && bytes == *b"shared bytes" && read.taint == published.taint);
            ensure!(std::fs::read_dir(reopened.root().join("objects"))?.count() == 1);
        }
    }
    Ok(())
}

#[tokio::test]
async fn failed_dedup_metadata_update_retains_the_previous_published_source_floor()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let original = store
        .begin_upload(UploadOptions {
            taint: TaintSet::author(),
            ..UploadOptions::default()
        })
        .await?;
    write_all(&store, &original, b"existing bytes").await?;
    let original = store
        .commit_upload(&original, &TaintSet::pristine())
        .await?;
    let object_directory = store.root().join("objects").join(&original.blob.hash);
    let encoded_size = std::fs::metadata(object_directory.join("metadata"))?.len();
    let limited = FileObjectStore::with_options(
        root.path(),
        FileObjectOptions {
            max_metadata_bytes: NonZeroUsize::new(usize::try_from(encoded_size)?)
                .context("existing metadata size")?,
            ..FileObjectOptions::default()
        },
    )?;
    let upload = limited.begin_upload(UploadOptions::default()).await?;
    write_all(&limited, &upload, b"existing bytes").await?;
    let final_taint = TaintSet::of(TaintSource::Fetched {
        host: "late-source-".repeat(100).into(),
    });
    let failure = limited
        .commit_upload(&upload, &final_taint)
        .await
        .err()
        .context("oversized metadata was published")?;
    ensure!(failure.taint.contains_all(&original.taint));
    ensure!(failure.taint.contains_all(&final_taint));
    ensure!(limited.write_chunk(&upload, 14, b"late").await.is_err());
    ensure!(
        limited
            .commit_upload(&upload, &TaintSet::pristine())
            .await
            .is_err()
    );
    ensure!(limited.metadata(&original.blob).await? == Some(original.clone()));
    ensure!(std::fs::read_dir(object_directory)?.count() == 2);
    limited.abort_upload(&upload).await?;
    ensure!(limited.pending_uploads() == 0 && staged(&limited)? == 0);
    drop(limited);
    drop(store);
    let reopened = FileObjectStore::open(root.path())?;
    ensure!(reopened.metadata(&original.blob).await? == Some(original));
    Ok(())
}

#[tokio::test]
async fn empty_objects_publish_final_sources_before_the_first_eof_read() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = store
        .begin_upload(UploadOptions {
            expected_size: Some(0),
            taint: TaintSet::author(),
            ..UploadOptions::default()
        })
        .await?;
    let final_taint = protected_sources()?;
    let expected = TaintSet::author().merged(&final_taint);
    let metadata = store.commit_upload(&upload, &final_taint).await?;
    ensure!(metadata.blob.size == 0 && metadata.taint == expected);
    let read = store.read_chunk(&metadata.blob, 0, &mut [0; 4]).await?;
    ensure!(read.bytes_read == 0 && read.end && read.taint == expected);
    drop(upload);
    ensure!(store.metadata(&metadata.blob).await? == Some(metadata));
    Ok(())
}

#[tokio::test]
async fn rejected_reads_and_corrupt_lengths_preserve_committed_metadata_sources()
-> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let store = FileObjectStore::open(root.path())?;
    let upload = store
        .begin_upload(UploadOptions {
            taint: TaintSet::author(),
            ..UploadOptions::default()
        })
        .await?;
    write_all(&store, &upload, b"protected bytes").await?;
    let committed = store.commit_upload(&upload, &protected_sources()?).await?;
    let mut bytes = [0; 4];
    let failure = store
        .read_chunk(&committed.blob, committed.blob.size + 1, &mut bytes)
        .await
        .err()
        .context("out-of-range read succeeded")?;
    ensure!(failure.taint.contains_all(&committed.taint));

    let data_path = store
        .root()
        .join("objects")
        .join(&committed.blob.hash)
        .join("data");
    std::fs::OpenOptions::new()
        .write(true)
        .open(data_path)?
        .set_len(1)?;
    let failure = store
        .metadata(&committed.blob)
        .await
        .err()
        .context("truncated committed content passed metadata validation")?;
    ensure!(failure.taint.contains_all(&committed.taint));
    let failure = store
        .read_chunk(&committed.blob, 0, &mut bytes)
        .await
        .err()
        .context("truncated committed content was read")?;
    ensure!(failure.taint.contains_all(&committed.taint));
    Ok(())
}
