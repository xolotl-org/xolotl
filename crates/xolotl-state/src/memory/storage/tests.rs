use super::*;
use crate::prelude::*;
use crate::test_support::CollectState;
use crate::{InMemoryBackend, InMemoryOptions};
use anyhow::{Context, Result, anyhow, bail, ensure};
use std::future::Future;
use std::sync::{Arc, mpsc};
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::{Duration, Instant};
use xolotl_types::Value;

fn ready<F: Future>(future: F) -> Result<F::Output> {
    match std::pin::pin!(future).poll(&mut TaskContext::from_waker(Waker::noop())) {
        Poll::Ready(output) => Ok(output),
        Poll::Pending => bail!("in-memory operation unexpectedly suspended"),
    }
}

fn path_in_other_shard(state: &Sharded, blocked: &RwLock<Values>) -> Result<Path> {
    for key in 0..1_024 {
        let path = Path::parse(&format!("state://locks/k{key}"))?;
        if !std::ptr::eq(state.shard(&path), blocked) {
            return Ok(path);
        }
    }
    bail!("could not find a key outside the blocked shard")
}

#[test]
fn point_reads_bypass_journal_and_other_shards() -> Result<()> {
    let backend = InMemoryBackend::with_options(InMemoryOptions {
        read_shards: NonZeroUsize::MIN.saturating_add(6),
        ..InMemoryOptions::default()
    })?;
    let Storage::Sharded(state) = &backend.inner else {
        bail!("expected sharded storage");
    };
    let blocked = &state.shards.first().context("missing shard")?.0;
    let path = path_in_other_shard(state, blocked)?;
    ready(backend.write_set(&path, Value::integer(7)))??;
    let (tx, rx) = mpsc::channel();
    std::thread::scope(|scope| -> Result<()> {
        let journal = state.journal.write();
        let unrelated = blocked.write();
        let reader = scope.spawn(|| tx.send(ready(backend.read(&path))));
        let read = rx.recv_timeout(Duration::from_secs(2));
        // Always release locks before joining, including a failing implementation.
        drop(unrelated);
        drop(journal);
        reader
            .join()
            .map_err(|panic| anyhow!("reader panicked: {panic:?}"))??;
        ensure!(
            read.context("point read waited on an unrelated lock")??? == Some(Value::integer(7))
        );
        Ok(())
    })
}

#[test]
fn prefix_snapshot_excludes_writes_until_all_shards_are_read() -> Result<()> {
    let backend = Arc::new(InMemoryBackend::with_options(InMemoryOptions {
        read_shards: NonZeroUsize::MIN.saturating_add(6),
        ..InMemoryOptions::default()
    })?);
    let Storage::Sharded(state) = &backend.inner else {
        bail!("expected sharded storage");
    };
    let last = &state.shards.last().context("missing shard")?.0;
    let path = path_in_other_shard(state, last)?;
    let prefix = Path::parse("state://locks")?;
    ready(backend.write_set(&path, Value::integer(0)))??;
    let (read_tx, read_rx) = mpsc::channel();
    let (write_tx, write_rx) = mpsc::channel();
    let (started_tx, started_rx) = mpsc::channel();
    // The prefix reader must keep its journal read lock while waiting for
    // the final shard, including after it has scanned earlier shards.
    let last = last.write();
    let reader_backend = backend.clone();
    let reader =
        std::thread::spawn(move || read_tx.send(ready(reader_backend.read_prefix(&prefix))));
    let deadline = Instant::now() + Duration::from_secs(2);
    let boundary_held = loop {
        if state.journal.try_write().is_none() {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::yield_now();
    };
    let writer_backend = backend.clone();
    let writer_path = path.clone();
    let writer = std::thread::spawn(move || -> Result<()> {
        started_tx.send(())?;
        write_tx.send(ready(
            writer_backend.write_set(&writer_path, Value::integer(1)),
        ))?;
        Ok(())
    });
    let started = started_rx.recv_timeout(Duration::from_secs(2));
    let premature_write = write_rx.recv_timeout(Duration::from_millis(30));
    drop(last);
    // A reversed-lock regression can deadlock workers with each other. Only
    // join after completion; a failing test must be able to drop these handles.
    let snapshot = read_rx
        .recv_timeout(Duration::from_secs(2))
        .context("prefix reader did not finish after releasing its shard")???;
    let wrote_early = premature_write.is_ok();
    match premature_write {
        Ok(result) => {
            result??;
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            write_rx
                .recv_timeout(Duration::from_secs(2))
                .context("writer did not finish after the snapshot")???;
        }
        Err(error) => return Err(error.into()),
    }
    reader
        .join()
        .map_err(|panic| anyhow!("reader panicked: {panic:?}"))??;
    writer
        .join()
        .map_err(|panic| anyhow!("writer panicked: {panic:?}"))??;
    started.context("writer did not start")?;
    ensure!(
        boundary_held,
        "prefix reader did not hold the commit boundary"
    );
    ensure!(
        !wrote_early,
        "write completed while a prefix snapshot was pending"
    );
    ensure!(snapshot == vec![(path.clone(), Value::integer(0))]);
    ensure!(ready(backend.read(&path))?? == Some(Value::integer(1)));
    Ok(())
}

#[test]
fn sharded_prefix_pages_match_compact_key_order() -> Result<()> {
    let compact = InMemoryBackend::new();
    let sharded = InMemoryBackend::with_options(InMemoryOptions {
        read_shards: NonZeroUsize::MIN.saturating_add(127),
        ..InMemoryOptions::default()
    })?;
    let prefix = Path::parse("state://ordered")?;
    let expected = (0..80)
        .map(|index| Path::parse(&format!("state://ordered/k{index:03}")))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (index, path) in expected.iter().enumerate().rev() {
        let value = Value::integer(index as i64);
        ready(compact.write_set(path, value.clone()))??;
        ready(sharded.write_set(path, value))??;
    }
    for backend in [&compact, &sharded] {
        ready(backend.write_set(&Path::parse("state://orderedish/extra")?, Value::integer(1)))??;
    }

    let collect = |backend: &InMemoryBackend| -> Result<Vec<Path>> {
        let mut scan = StateScan::new(prefix.clone());
        scan.limits.entries = NonZeroUsize::new(3).context("zero page size")?;
        let mut paths = Vec::new();
        for _ in 0..32 {
            let page = ready(backend.query(&scan))??;
            ensure!(page.entries.len() <= 3, "page exceeded its entry limit");
            paths.extend(page.entries.into_iter().map(|(path, _)| path));
            match page.next {
                Some(next) => {
                    ensure!(
                        Some(&next) != scan.cursor.as_ref(),
                        "cursor did not advance"
                    );
                    scan.cursor = Some(next);
                }
                None => return Ok(paths),
            }
        }
        bail!("prefix scan did not terminate")
    };
    ensure!(collect(&compact)? == expected);
    ensure!(collect(&sharded)? == expected);
    Ok(())
}

#[test]
fn impossible_shard_reservation_returns_an_error() -> Result<()> {
    let result = InMemoryBackend::with_options(InMemoryOptions {
        read_shards: NonZeroUsize::MAX,
        ..InMemoryOptions::default()
    });
    ensure!(
        matches!(result, Err(crate::StateFailure { error: StateError::Backend(message), .. }) if message.contains("state read shards"))
    );
    Ok(())
}

#[test]
fn notification_capacity_is_validated_before_allocation() -> Result<()> {
    for capacity in [
        InMemoryOptions::MAX_NOTIFICATION_CAPACITY + 1,
        usize::MAX / 4,
        usize::MAX,
    ] {
        let capacity = NonZeroUsize::new(capacity).context("zero test capacity")?;
        for result in [
            InMemoryBackend::with_notification_capacity(capacity),
            InMemoryBackend::with_options(InMemoryOptions {
                read_shards: NonZeroUsize::MAX,
                notification_capacity: capacity,
                ..InMemoryOptions::default()
            }),
        ] {
            ensure!(
                matches!(result, Err(crate::StateFailure { error: StateError::Backend(message), .. }) if message.contains("notification capacity"))
            );
        }
    }
    let maximum = NonZeroUsize::new(InMemoryOptions::MAX_NOTIFICATION_CAPACITY)
        .context("zero maximum capacity")?;
    let backend = InMemoryBackend::with_notification_capacity(maximum)?;
    ensure!(backend.inner.read().notifications.capacity() == 0);
    Ok(())
}
