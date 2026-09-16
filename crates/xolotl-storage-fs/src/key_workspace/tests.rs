use super::*;
use anyhow::{Context, ensure};
use std::{future::Future, task::Poll, time::Duration};
use xolotl_types::value::event::{
    Event, KeyCompletion, KeyEffect, Kind, ValidationStep, Validator, ValueCursor,
};
use xolotl_types::{TaintSet, Value};
use xolotl_value_codec::validation::EventValidator;

fn accept(validator: &mut Validator, event: Event<'_>) -> anyhow::Result<()> {
    let mut validation = validator.begin(event)?;
    ensure!(validation.advance(None)? == ValidationStep::Accepted);
    Ok(())
}

fn keys(count: usize) -> anyhow::Result<Vec<KeyId>> {
    let mut validator = Validator::new(None);
    accept(&mut validator, Event::Begin(Kind::Document))?;
    accept(&mut validator, Event::Begin(Kind::Taint))?;
    accept(&mut validator, Event::End(Kind::Taint))?;
    let mut keys = Vec::new();
    for _ in 0..count {
        accept(&mut validator, Event::Begin(Kind::Map))?;
        {
            let mut validation = validator.begin(Event::Begin(Kind::Key))?;
            let ValidationStep::Effect(KeyEffect::Create { key }) = validation.advance(None)?
            else {
                anyhow::bail!("validator did not allocate a key identity");
            };
            keys.push(key);
            ensure!(validation.advance(Some(KeyCompletion::Done))? == ValidationStep::Accepted);
        }
        accept(&mut validator, Event::End(Kind::Key))?;
        // The next map is this key's value, giving every fixture a fresh identity.
    }
    Ok(keys)
}

fn options(io_bytes: usize, max_keys: usize) -> anyhow::Result<FileKeyOptions> {
    Ok(FileKeyOptions {
        io_bytes: NonZeroUsize::new(io_bytes).context("nonzero fixture I/O window")?,
        max_keys: NonZeroUsize::new(max_keys).context("nonzero fixture key budget")?,
    })
}

async fn files(path: &Path) -> anyhow::Result<usize> {
    let mut entries = tokio::fs::read_dir(path).await?;
    let mut count = 0;
    while entries.next_entry().await?.is_some() {
        count += 1;
    }
    Ok(count)
}

#[tokio::test]
async fn long_keys_compare_across_small_windows_without_using_suffix_order() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let ids = keys(1)?;
    let key = ids[0];
    let mut store = FileKeyStore::open(root.path(), options(127, 2)?).await?;
    let directory = store.directory().to_owned();
    store.create(key).await?;
    let mut value = vec![b'x'; 8_193];
    value[8_192] = b'z';
    store.append(key, 0, &value).await?;
    ensure!(files(&directory).await? == 1);
    ensure!(tokio::fs::metadata(directory.join("key-0")).await?.len() == value.len() as u64);
    ensure!(store.compare_prefix(key, 0, &value).await? == Ordering::Equal);
    ensure!(store.compare_prefix(key, 0, &value[..1_024]).await? == Ordering::Equal);
    ensure!(store.compare_prefix(key, 4_091, &value[4_091..]).await? == Ordering::Equal);
    ensure!(store.compare_prefix(key, 0, b"").await? == Ordering::Equal);
    ensure!(store.compare_prefix(key, value.len() as u64, b"").await? == Ordering::Equal);
    ensure!(store.compare_prefix(key, value.len() as u64, b"a").await? == Ordering::Less);

    let mut smaller = value.clone();
    smaller[8_192] = b'y';
    ensure!(store.compare_prefix(key, 0, &smaller).await? == Ordering::Greater);
    let mut larger = value.clone();
    larger[8_192] = b'{';
    ensure!(store.compare_prefix(key, 0, &larger).await? == Ordering::Less);
    value.extend_from_slice(b"suffix");
    ensure!(store.compare_prefix(key, 0, &value).await? == Ordering::Less);
    store.close().await?;
    ensure!(!directory.try_exists()?);
    Ok(())
}

#[tokio::test]
async fn append_is_contiguous_and_release_reclaims_before_returning() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let ids = keys(32)?;
    let mut store = FileKeyStore::open(root.path(), options(3, 1)?).await?;
    let directory = store.directory().to_owned();
    for key in ids {
        store.create(key).await?;
        store.append(key, 0, b"abcde").await?;
        store.append(key, 5, b"").await?;
        store.append(key, 5, b"fghijklmnop").await?;
        ensure!(store.compare_prefix(key, 0, b"abcdefghijklmnop").await? == Ordering::Equal);
        ensure!(files(&directory).await? == 1);
        store.release(key).await?;
        ensure!(files(&directory).await? == 0);
    }
    store.close().await?;
    ensure!(!directory.try_exists()?);
    Ok(())
}

#[tokio::test]
async fn active_budget_and_reused_id_close_the_session() -> anyhow::Result<()> {
    let ids = keys(2)?;
    for release_first in [false, true] {
        let root = tempfile::tempdir()?;
        let mut store = FileKeyStore::open(root.path(), options(8, 1)?).await?;
        let directory = store.directory().to_owned();
        store.create(ids[0]).await?;
        if release_first {
            store.release(ids[0]).await?;
            ensure!(store.create(ids[0]).await.is_err());
        } else {
            ensure!(store.create(ids[1]).await.is_err());
        }
        ensure!(store.commands.is_none());
        ensure!(store.append(ids[0], 0, b"later").await.is_err());
        store.close().await?;
        ensure!(!directory.try_exists()?);
    }
    Ok(())
}

#[tokio::test]
async fn invalid_offsets_and_unknown_keys_are_not_empty_successes() -> anyhow::Result<()> {
    let ids = keys(2)?;
    for case in 0..5 {
        let root = tempfile::tempdir()?;
        let mut store = FileKeyStore::open(root.path(), options(8, 2)?).await?;
        let directory = store.directory().to_owned();
        store.create(ids[0]).await?;
        store.append(ids[0], 0, b"abc").await?;
        let rejected = match case {
            0 => store.append(ids[0], 4, b"").await.is_err(),
            1 => store.append(ids[0], 0, b"abc").await.is_err(),
            2 => store.append(ids[0], u64::MAX, b"x").await.is_err(),
            3 => store.compare_prefix(ids[1], 0, b"").await.is_err(),
            _ => store.compare_prefix(ids[0], 4, b"").await.is_err(),
        };
        ensure!(rejected && store.commands.is_none());
        store.close().await?;
        ensure!(!directory.try_exists()?);
    }
    Ok(())
}

#[tokio::test]
async fn a_physically_short_key_is_a_storage_error() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let key = keys(1)?[0];
    let mut store = FileKeyStore::open(root.path(), options(2, 2)?).await?;
    let directory = store.directory().to_owned();
    store.create(key).await?;
    store.append(key, 0, b"abcdef").await?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(directory.join("key-0"))?
        .set_len(3)?;
    ensure!(store.compare_prefix(key, 0, b"abcdef").await.is_err());
    ensure!(store.commands.is_none());
    store.close().await?;
    ensure!(!directory.try_exists()?);
    Ok(())
}

#[tokio::test]
async fn drop_transfers_cleanup_and_does_not_touch_another_session() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let key = keys(1)?[0];
    let mut first = FileKeyStore::open(root.path(), options(8, 2)?).await?;
    let mut second = FileKeyStore::open(root.path(), options(8, 2)?).await?;
    let first_directory = first.directory().to_owned();
    let second_directory = second.directory().to_owned();
    ensure!(first_directory != second_directory);
    first.create(key).await?;
    first.append(key, 0, b"first").await?;
    second.create(key).await?;
    second.append(key, 0, b"second").await?;
    let cleanup = first.worker.take().context("first cleanup owner")?;
    drop(first);
    cleanup.await??;
    ensure!(!first_directory.try_exists()? && second_directory.try_exists()?);
    ensure!(second.compare_prefix(key, 0, b"second").await? == Ordering::Equal);
    second.close().await?;
    ensure!(!second_directory.try_exists()?);
    Ok(())
}

#[tokio::test]
async fn unpolled_operation_does_not_close_or_mutate_the_session() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let key = keys(1)?[0];
    let mut store = FileKeyStore::open(root.path(), options(4, 2)?).await?;
    store.create(key).await?;
    drop(store.append(key, 0, b"not-polled"));
    ensure!(store.commands.is_some());
    store.append(key, 0, b"accepted").await?;
    ensure!(store.compare_prefix(key, 0, b"accepted").await? == Ordering::Equal);
    store.close().await?;
    Ok(())
}

#[tokio::test]
async fn event_validation_uses_file_keys_through_complete_document_cleanup() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let mut store = FileKeyStore::open(root.path(), options(13, 2)?).await?;
    let directory = store.directory().to_owned();
    let cleanup = store.worker.take().context("validation cleanup owner")?;
    let prefix = "k".repeat(2_047);
    let value = Value::map(std::collections::BTreeMap::from([
        (format!("{prefix}a"), Value::integer(1)),
        (format!("{prefix}b"), Value::integer(2)),
    ]));
    let taint = TaintSet::pristine();
    let mut cursor = ValueCursor::new(
        &value,
        &taint,
        NonZeroUsize::new(127).context("event byte window")?,
        None,
    )?;
    let mut validator = EventValidator::new(store, None);
    while let Some(event) = cursor.next_event()? {
        validator.accept(event).await?;
    }
    ensure!(files(&directory).await? == 0);
    validator.finish()?;
    ensure!(!validator.is_open());
    cleanup.await??;
    ensure!(!directory.try_exists()?);
    Ok(())
}

#[test]
fn cancelled_create_read_and_append_keep_io_owned_until_cleanup() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_time()
        .build()?;
    runtime.block_on(async {
        let ids = keys(2)?;
        for case in 0..3 {
            let root = tempfile::tempdir()?;
            let mut store = FileKeyStore::open(root.path(), options(4, 2)?).await?;
            let directory = store.directory().to_owned();
            store.create(ids[0]).await?;
            store.append(ids[0], 0, b"existing").await?;
            let (release, wait) = std::sync::mpsc::channel();
            let entered = std::sync::Arc::new(tokio::sync::Notify::new());
            let observed = entered.clone();
            let blocker = tokio::task::spawn_blocking(move || {
                observed.notify_one();
                wait.recv()
            });
            tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
            match case {
                0 => {
                    let mut operation = store.create(ids[1]);
                    ensure!(poll_once(operation.as_mut()).is_pending());
                    tokio::task::yield_now().await;
                    drop(operation);
                }
                1 => {
                    let mut operation = store.compare_prefix(ids[0], 0, b"existing");
                    ensure!(poll_once(operation.as_mut()).is_pending());
                    tokio::task::yield_now().await;
                    drop(operation);
                }
                _ => {
                    let mut operation = store.append(ids[0], 8, b"cancelled-append");
                    ensure!(poll_once(operation.as_mut()).is_pending());
                    tokio::task::yield_now().await;
                    drop(operation);
                }
            }
            ensure!(store.commands.is_none());
            let cleanup = store
                .worker
                .take()
                .context("cancelled session cleanup owner")?;
            drop(store);
            release.send(())?;
            blocker.await??;
            tokio::time::timeout(Duration::from_secs(2), cleanup).await???;
            ensure!(!directory.try_exists()?);
        }
        Ok(())
    })
}

fn poll_once<F: Future + ?Sized>(mut future: std::pin::Pin<&mut F>) -> Poll<F::Output> {
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    future.as_mut().poll(&mut context)
}

#[test]
fn cancelled_initialization_reclaims_a_directory_not_delivered_to_the_caller() -> anyhow::Result<()>
{
    let root = tempfile::tempdir()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .max_blocking_threads(1)
        .enable_time()
        .build()?;
    runtime.block_on(async {
        let (release, wait) = std::sync::mpsc::channel();
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let observed = entered.clone();
        let blocker = tokio::task::spawn_blocking(move || {
            observed.notify_one();
            wait.recv()
        });
        tokio::time::timeout(Duration::from_secs(2), entered.notified()).await?;
        let mut open = Box::pin(FileKeyStore::open(root.path(), options(8, 2)?));
        ensure!(poll_once(open.as_mut()).is_pending());
        tokio::task::yield_now().await;
        drop(open);
        release.send(())?;
        blocker.await??;
        // A later initialized session proves that the queued directory work can run.
        let live = FileKeyStore::open(root.path(), options(8, 2)?).await?;
        live.close().await?;
        tokio::time::timeout(Duration::from_secs(2), async {
            while files(root.path()).await? != 0 {
                tokio::task::yield_now().await;
            }
            anyhow::Ok(())
        })
        .await??;
        Ok(())
    })
}

#[test]
fn runtime_shutdown_leaves_only_unpublished_session_data_for_host_recovery() -> anyhow::Result<()> {
    let root = tempfile::tempdir()?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let key = keys(1)?[0];
    let store = runtime.block_on(async {
        let mut store = FileKeyStore::open(root.path(), options(8, 2)?).await?;
        store.create(key).await?;
        store.append(key, 0, b"unpublished").await?;
        anyhow::Ok(store)
    })?;
    let directory = store.directory().to_owned();
    drop(runtime);
    drop(store);
    ensure!(directory.try_exists()?);
    ensure!(directory.starts_with(root.path()));
    ensure!(
        directory
            .file_name()
            .context("session name")?
            .to_string_lossy()
            .starts_with("value-keys-")
    );
    // The host now exclusively owns this root: no old runtime or worker can use it.
    std::fs::remove_dir_all(&directory)?;
    ensure!(files_sync(root.path())? == 0);
    Ok(())
}

fn files_sync(path: &Path) -> anyhow::Result<usize> {
    Ok(std::fs::read_dir(path)?
        .collect::<Result<Vec<_>, _>>()?
        .len())
}
