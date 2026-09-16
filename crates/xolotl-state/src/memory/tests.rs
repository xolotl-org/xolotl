use super::*;
use anyhow::{Context, anyhow, bail, ensure};
use std::future::Future;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context as TaskContext, Poll, Wake, Waker};
use xolotl_types::{Path, TaintSource};

mod failures;

const HISTORY_MODES: [MemoryHistory; 2] = [MemoryHistory::Full, MemoryHistory::Disabled];

fn for_backends<F>(
    histories: &[MemoryHistory],
    check: impl Fn(InMemoryOptions) -> F,
) -> anyhow::Result<()>
where
    F: Future<Output = anyhow::Result<()>>,
{
    for &history in histories {
        // Exercise arbitrary shard counts, including non-powers of two.
        for read_shards in [NonZeroUsize::MIN, NonZeroUsize::MIN.saturating_add(6)] {
            let options = InMemoryOptions {
                read_shards,
                history,
                ..InMemoryOptions::default()
            };
            ready(check(options))?
                .with_context(|| format!("read_shards={read_shards}, history={history:?}"))?;
        }
    }
    Ok(())
}

fn p(s: &str) -> anyhow::Result<Path> {
    Path::parse(s).map_err(|error| anyhow!("path parse failed for {s}: {error}"))
}

fn ready<F: Future>(future: F) -> anyhow::Result<F::Output> {
    match std::pin::pin!(future).poll(&mut TaskContext::from_waker(Waker::noop())) {
        Poll::Ready(output) => Ok(output),
        Poll::Pending => bail!("in-memory operation unexpectedly suspended"),
    }
}

fn parallel_rounds<T: Send>(
    workers: usize,
    rounds: usize,
    write: impl Fn(usize, usize) -> StateResult<T> + Sync,
) -> anyhow::Result<()> {
    let barrier = std::sync::Barrier::new(workers);
    std::thread::scope(|scope| {
        let write = &write;
        let barrier = &barrier;
        let handles = (0..workers)
            .map(|worker| {
                scope.spawn(move || {
                    (0..rounds)
                        .map(|round| {
                            barrier.wait();
                            write(worker, round)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            for result in handle
                .join()
                .map_err(|panic| anyhow!("writer panicked: {panic:?}"))?
            {
                result?;
            }
        }
        Ok(())
    })
}

fn same_event(left: &StateEvent, right: &StateEvent) -> bool {
    match (left, right) {
        (
            StateEvent::Set {
                path: a,
                value: av,
                taint: at,
            },
            StateEvent::Set {
                path: b,
                value: bv,
                taint: bt,
            },
        ) => a == b && av == bv && at == bt,
        (
            StateEvent::Append {
                path: a,
                item: av,
                taint: at,
            },
            StateEvent::Append {
                path: b,
                item: bv,
                taint: bt,
            },
        ) => a == b && av == bv && at == bt,
        (StateEvent::Delete { path: a, taint: at }, StateEvent::Delete { path: b, taint: bt }) => {
            a == b && at == bt
        }
        _ => false,
    }
}

#[test]
fn concurrent_writes_have_one_history_and_notification_order() -> anyhow::Result<()> {
    for_backends(&[MemoryHistory::Full], |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let paths = [
            p("state://race/a")?,
            p("state://race/b")?,
            p("state://race/c")?,
        ];
        let mut events = ready(backend.subscribe(&p("state://race/**")?))??;
        parallel_rounds(8, 24, |worker, round| {
            let path = &paths[(worker + round) % paths.len()];
            let item = Value::string(format!("{worker}/{round}"));
            let taint = TaintSet::of(TaintSource::Fetched {
                host: format!("worker-{worker}").into(),
            });
            let result = ready(async {
                match (worker + round) % 5 {
                    0 => {
                        backend
                            .write_set_tainted(path, Value::list(vec![item]), taint)
                            .await
                    }
                    1 => backend.write_append_tainted(path, item, taint).await,
                    2 => {
                        let expected = backend.read(path).await?;
                        backend
                            .write_cas_tainted(path, expected, Value::list(vec![item]), taint)
                            .await
                    }
                    3 => backend.write_delete(path).await,
                    _ => {
                        backend
                            .write_merge(path, Value::list(vec![item]), MergeRule::Shallow)
                            .await
                    }
                }
            })
            .map_err(|error| StateError::Backend(error.to_string()))?;
            match result {
                Err(crate::StateFailure {
                    error: StateError::CasFailed { .. },
                    ..
                }) => Ok(()),
                other => other.map(|_commit| ()),
            }
        })?;

        let history = ready(backend.read_range(&p("state://race")?, 0, i64::MAX))??;
        let mut reconstructed = BTreeMap::<Path, TaintedValue>::new();
        let mut previous = 0;
        for entry in history {
            ensure!(
                entry.at_millis > previous,
                "history timestamp order regressed"
            );
            previous = entry.at_millis;
            let notified = events.try_recv()?;
            ensure!(
                same_event(&entry.event, &notified),
                "notification reordered a commit"
            );
            match &entry.event {
                StateEvent::Set { path, value, taint } => {
                    reconstructed.insert(
                        path.clone(),
                        TaintedValue::new(value.clone(), taint.clone()),
                    );
                }
                StateEvent::Append { path, item, taint } => {
                    let current = reconstructed.get(path);
                    let mut items = match current {
                        Some(current) => current
                            .value
                            .as_list()
                            .context("history appended to a non-list")?
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>(),
                        None => Vec::new(),
                    };
                    items.push(item.clone());
                    let mut combined = current
                        .map(|current| current.taint.clone())
                        .unwrap_or_default();
                    combined.union(taint);
                    reconstructed.insert(
                        path.clone(),
                        TaintedValue::new(Value::list(items), combined),
                    );
                }
                StateEvent::Delete { path, .. } => {
                    reconstructed.remove(path);
                }
            }
            let historical = ready(backend.read_at(entry.event.path(), entry.at_millis))??;
            ensure!(historical.as_ref() == reconstructed.get(entry.event.path()));
        }
        ensure!(matches!(
            events.try_recv(),
            Err(crate::StateWatchError::Empty)
        ));
        for path in paths {
            ensure!(ready(backend.read_tainted(&path))??.as_ref() == reconstructed.get(&path));
        }
        Ok(())
    })
}

#[test]
fn concurrent_merges_keep_every_update_and_existing_provenance() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let path = p("state://merge")?;
        let taint = TaintSet::of(TaintSource::Protected { path: path.clone() });
        ready(backend.write_set_tainted(&path, Value::map(Default::default()), taint.clone()))??;
        parallel_rounds(8, 32, |worker, round| {
            ready(backend.write_merge(
                &path,
                Value::map(std::collections::BTreeMap::from([(
                    format!("{worker}/{round}"),
                    Value::boolean(true),
                )])),
                MergeRule::Shallow,
            ))
            .map_err(|error| StateError::Backend(error.to_string()))?
        })?;
        let current = ready(backend.read_tainted(&path))??.context("missing merged value")?;
        ensure!(
            current
                .value
                .as_map()
                .context("merged value is not a map")?
                .len()
                == 256
        );
        ensure!(current.taint == taint);
        if options.history == MemoryHistory::Full {
            let history = ready(backend.read_range(&path, 0, i64::MAX))??;
            ensure!(history.len() == 257);
            for entry in history {
                ensure!(
                    matches!(entry.event, StateEvent::Set { taint: recorded, .. } if recorded == taint)
                );
            }
        } else {
            ensure!(backend.inner.read().history.is_empty());
        }
        ready(backend.write_merge(&path, Value::integer(9), MergeRule::Deep))??;
        ensure!(
            ready(backend.read_tainted(&path))??
                == Some(TaintedValue::new(Value::integer(9), taint))
        );
        Ok(())
    })
}

#[test]
fn exhausted_history_rejects_all_mutations_without_partial_commit() -> anyhow::Result<()> {
    for_backends(&[MemoryHistory::Full], |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let path = p("state://clock")?;
        let missing = p("state://missing")?;
        let taint = TaintSet::of(TaintSource::ModelOutput);
        ready(backend.write_set_tainted(
            &path,
            Value::list(vec![Value::integer(1)]),
            taint.clone(),
        ))??;
        backend
            .inner
            .write()
            .history
            .last_mut()
            .context("missing history")?
            .at_millis = i64::MAX - 1;
        ready(backend.write_append(&path, Value::integer(2)))??;
        let expected = Value::list(vec![Value::integer(1), Value::integer(2)]);
        ensure!(
            ready(backend.read_at(&path, i64::MAX))??
                == Some(TaintedValue::new(expected.clone(), taint.clone()))
        );
        let mut events = ready(backend.subscribe(&p("state://**")?))??;
        for path in [&path, &missing] {
            let expected = ready(backend.read(path))??;
            for result in [
                ready(backend.write_set(path, Value::null()))?,
                ready(backend.write_append(path, Value::integer(3)))?,
                ready(backend.write_cas(path, expected, Value::null()))?,
                ready(backend.write_merge(path, Value::null(), MergeRule::Shallow))?,
            ] {
                ensure!(
                    matches!(result, Err(crate::StateFailure { error: StateError::Backend(message), .. }) if message.contains("timestamp exhausted"))
                );
            }
        }
        ensure!(ready(backend.write_delete(&path))?.is_err());
        ensure!(ready(backend.write_compare_delete(&path, Some(expected.clone())))?.is_err());
        ensure!(matches!(
            ready(backend.write_compare_delete(&path, None))?,
            Err(crate::StateFailure {
                error: StateError::CasFailed { .. },
                ..
            })
        ));
        ready(backend.write_delete(&missing))??;
        ready(backend.write_compare_delete(&missing, None))??;
        ensure!(ready(backend.read_tainted(&path))?? == Some(TaintedValue::new(expected, taint)));
        ensure!(ready(backend.read(&missing))??.is_none());
        ensure!(backend.inner.read().history.len() == 2);
        ensure!(matches!(
            events.try_recv(),
            Err(crate::StateWatchError::Empty)
        ));
        Ok(())
    })
}

struct ReentrantWake {
    backend: Arc<InMemoryBackend>,
    path: Path,
    invoked: AtomicBool,
    unlocked: AtomicBool,
    results: parking_lot::Mutex<Vec<StateResult<crate::StateCommit>>>,
    subscriber: parking_lot::Mutex<Option<StateStream>>,
    panic_after: bool,
}

impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.invoked.swap(true, Ordering::SeqCst) {
            return;
        }
        let unlocked = self.backend.inner.is_unlocked();
        self.unlocked.store(unlocked, Ordering::SeqCst);
        if !unlocked {
            return;
        }
        let result = (|| -> anyhow::Result<()> {
            *self.subscriber.lock() = Some(ready(self.backend.subscribe(&self.path))??);
            for item in 1..=3 {
                let result = ready(self.backend.write_append(&self.path, Value::integer(item)))?;
                self.results.lock().push(result);
            }
            // An active drainer must allow reentrant flush without waiting on itself.
            ready(self.backend.flush())??;
            // Unobserved paths need no notification capacity.
            let result = ready(
                self.backend
                    .write_set(&p("state://unobserved")?, Value::integer(5)),
            )?;
            self.results.lock().push(result);
            Ok(())
        })();
        if let Err(error) = result {
            self.results
                .lock()
                .push(Err(StateError::Backend(error.to_string()).into()));
        }
        if self.panic_after {
            std::panic::resume_unwind(Box::new("subscriber waker panic"));
        }
    }
}

#[test]
fn reentrant_notifications_are_ordered_and_backpressure_precedes_commit() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = Arc::new(InMemoryBackend::with_options(InMemoryOptions {
            notification_capacity: NonZeroUsize::MIN.saturating_add(1),
            ..options
        })?);
        let path = p("state://observed")?;
        let mut events = ready(backend.subscribe(&path))??;
        let wake = Arc::new(ReentrantWake {
            backend: backend.clone(),
            path: path.clone(),
            invoked: AtomicBool::new(false),
            unlocked: AtomicBool::new(false),
            results: parking_lot::Mutex::new(Vec::new()),
            subscriber: parking_lot::Mutex::new(None),
            panic_after: false,
        });
        let waker = Waker::from(wake.clone());
        {
            let mut next = std::pin::pin!(events.recv());
            ensure!(
                next.as_mut()
                    .poll(&mut TaskContext::from_waker(&waker))
                    .is_pending()
            );
            ready(backend.write_append(&path, Value::integer(0)))??;
        }
        ensure!(wake.invoked.load(Ordering::SeqCst) && wake.unlocked.load(Ordering::SeqCst));
        let results = wake.results.lock();
        ensure!(
            results.len() == 4 && results[0].is_ok() && results[1].is_ok() && results[3].is_ok()
        );
        ensure!(
            matches!(&results[2], Err(crate::StateFailure { error: StateError::Backend(message), .. }) if message.contains("notification backlog"))
        );
        ensure!(
            ready(backend.read(&path))??
                == Some(Value::list(vec![
                    Value::integer(0),
                    Value::integer(1),
                    Value::integer(2)
                ]))
        );
        let expected_history = if options.history == MemoryHistory::Full {
            4
        } else {
            0
        };
        ensure!(backend.inner.read().history.len() == expected_history);
        ensure!(backend.inner.read().notifications.is_empty());
        let mut subscriber = wake
            .subscriber
            .lock()
            .take()
            .context("reentrant subscription failed")?;
        for item in 1..=2 {
            ensure!(
                matches!(subscriber.try_recv()?, StateEvent::Append { item: value, .. } if value.as_int() == Some(item))
            );
        }
        ensure!(matches!(
            subscriber.try_recv(),
            Err(crate::StateWatchError::Empty)
        ));
        ensure!(matches!(
            events.try_recv(),
            Err(crate::StateWatchError::Lagged(1))
        ));
        Ok(())
    })
}

#[test]
fn a_rejected_write_resumes_notifications_after_a_drainer_panic() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = Arc::new(InMemoryBackend::with_options(InMemoryOptions {
            notification_capacity: NonZeroUsize::MIN.saturating_add(1),
            ..options
        })?);
        let path = p("state://panic")?;
        let mut events = ready(backend.subscribe(&path))??;
        let wake = Arc::new(ReentrantWake {
            backend: backend.clone(),
            path: path.clone(),
            invoked: AtomicBool::new(false),
            unlocked: AtomicBool::new(false),
            results: parking_lot::Mutex::new(Vec::new()),
            subscriber: parking_lot::Mutex::new(None),
            panic_after: true,
        });
        let waker = Waker::from(wake.clone());
        {
            let mut next = std::pin::pin!(events.recv());
            ensure!(
                next.as_mut()
                    .poll(&mut TaskContext::from_waker(&waker))
                    .is_pending()
            );
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ready(backend.write_append(&path, Value::integer(0)))
            }));
            ensure!(panic.is_err());
        }
        ensure!(!backend.inner.read().notifying);
        ensure!(backend.inner.read().notifications.len() == 2);
        let failed = ready(backend.write_cas(&path, Some(Value::null()), Value::null()))?;
        ensure!(matches!(
            failed,
            Err(crate::StateFailure {
                error: StateError::CasFailed { .. },
                ..
            })
        ));
        ensure!(backend.inner.read().notifications.is_empty());
        let expected_history = if options.history == MemoryHistory::Full {
            4
        } else {
            0
        };
        ensure!(backend.inner.read().history.len() == expected_history);
        let mut subscriber = wake
            .subscriber
            .lock()
            .take()
            .context("missing subscriber")?;
        for item in 1..=2 {
            ensure!(
                matches!(subscriber.try_recv()?, StateEvent::Append { item: value, .. } if value.as_int() == Some(item))
            );
        }
        Ok(())
    })
}

#[test]
fn flush_resumes_notifications_without_new_mutations_after_a_drainer_panic() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = Arc::new(InMemoryBackend::with_options(InMemoryOptions {
            notification_capacity: NonZeroUsize::MIN.saturating_add(1),
            ..options
        })?);
        let path = p("state://panic")?;
        let mut events = ready(backend.subscribe(&path))??;
        let wake = Arc::new(ReentrantWake {
            backend: backend.clone(),
            path: path.clone(),
            invoked: AtomicBool::new(false),
            unlocked: AtomicBool::new(false),
            results: parking_lot::Mutex::new(Vec::new()),
            subscriber: parking_lot::Mutex::new(None),
            panic_after: true,
        });
        let waker = Waker::from(wake.clone());
        {
            let mut next = std::pin::pin!(events.recv());
            ensure!(
                next.as_mut()
                    .poll(&mut TaskContext::from_waker(&waker))
                    .is_pending()
            );
            let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ready(backend.write_append(&path, Value::integer(0)))
            }));
            ensure!(panic.is_err());
        }
        let values = ready(backend.read_prefix_tainted(&p("state://")?))??;
        let history = {
            let state = backend.inner.read();
            ensure!(!state.notifying && state.notifications.len() == 2);
            state.history.clone()
        };
        let mut late_subscriber = backend.subscribe(&path).await?;
        ready(backend.flush())??;
        {
            let state = backend.inner.read();
            ensure!(!state.notifying && state.notifications.is_empty());
            ensure!(state.history.len() == history.len());
            ensure!(state.history.iter().zip(&history).all(|(after, before)| {
                after.at_millis == before.at_millis && same_event(&after.event, &before.event)
            }));
        }
        ensure!(ready(backend.read_prefix_tainted(&p("state://")?))?? == values);
        let mut subscriber = wake
            .subscriber
            .lock()
            .take()
            .context("missing subscriber")?;
        for item in 1..=2 {
            ensure!(
                matches!(subscriber.try_recv()?, StateEvent::Append { item: value, .. } if value.as_int() == Some(item))
            );
        }
        ensure!(matches!(
            subscriber.try_recv(),
            Err(crate::StateWatchError::Empty)
        ));
        ensure!(matches!(
            late_subscriber.try_recv(),
            Err(crate::StateWatchError::Empty)
        ));
        Ok(())
    })
}

#[test]
fn default_options_keep_compact_storage_unallocated() -> anyhow::Result<()> {
    for backend in [
        InMemoryBackend::new(),
        InMemoryBackend::default(),
        InMemoryBackend::with_options(InMemoryOptions::default())?,
    ] {
        ensure!(backend.options == InMemoryOptions::default());
        let Storage::Compact(state) = &backend.inner else {
            bail!("default backend allocated read shards");
        };
        let state = state.read();
        ensure!(state.values.is_empty());
        ensure!(state.journal.history.capacity() == 0);
        ensure!(!state.journal.subscribers.is_initialized());
        ensure!(state.journal.notifications.capacity() == 0);
        ensure!(!state.journal.notifying);
    }
    Ok(())
}

#[test]
fn disabled_history_rejects_historical_queries_but_reads_current_values() -> anyhow::Result<()> {
    for_backends(&[MemoryHistory::Disabled], |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let path = p("state://current")?;
        let missing = p("state://missing")?;
        ensure!(backend.read_at(&path, 0).await?.is_none());
        backend.write_set(&path, Value::integer(1)).await?;
        backend.write_set(&path, Value::integer(2)).await?;

        for candidate in [&path, &missing] {
            ensure!(matches!(
                backend.read_range(candidate, i64::MIN, i64::MAX).await,
                Err(crate::StateFailure {
                    error: StateError::MissingCapability("history"),
                    ..
                })
            ));
            for timestamp in [i64::MIN, -1, 1, i64::MAX] {
                ensure!(matches!(
                    backend.read_at(candidate, timestamp).await,
                    Err(crate::StateFailure {
                        error: StateError::MissingCapability("history"),
                        ..
                    })
                ));
            }
            ensure!(backend.read_at(candidate, 0).await? == backend.read_tainted(candidate).await?);
        }
        ensure!(
            backend.read_at(&path, 0).await? == Some(TaintedValue::pristine(Value::integer(2)))
        );
        backend.write_delete(&path).await?;
        ensure!(backend.read_at(&path, 0).await?.is_none());
        ensure!(backend.inner.read().history.capacity() == 0);
        Ok(())
    })
}

#[test]
fn unobserved_writes_leave_notification_storage_unallocated() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        {
            let state = backend.inner.read();
            ensure!(state.history.capacity() == 0);
            ensure!(state.notifications.capacity() == 0 && !state.subscribers.is_initialized());
        }
        for value in 0..32 {
            ready(backend.write_set(&p("state://unobserved")?, Value::integer(value)))??;
        }
        let state = backend.inner.read();
        ensure!(state.notifications.capacity() == 0 && !state.subscribers.is_initialized());
        if options.history == MemoryHistory::Disabled {
            ensure!(state.history.capacity() == 0);
        } else {
            ensure!(state.history.len() == 32);
        }
        Ok(())
    })
}

#[test]
fn set_and_read() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        b.write_set(&p("state://x")?, Value::integer(42)).await?;
        let v = b.read(&p("state://x")?).await?;
        ensure!(v == Some(Value::integer(42)), "unexpected value: {v:?}");
        Ok(())
    })
}

#[test]
fn append_creates_list_then_grows() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        b.write_append(&p("state://log")?, Value::integer(1))
            .await?;
        b.write_append(&p("state://log")?, Value::integer(2))
            .await?;
        let v = b
            .read(&p("state://log")?)
            .await?
            .context("missing log value")?;
        let xs = v.as_list().context("expected list")?;
        ensure!(xs.len() == 2, "unexpected list length: {}", xs.len());
        Ok(())
    })
}

#[test]
fn cas_succeeds_on_match() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        b.write_set(&p("state://k")?, Value::integer(1)).await?;
        b.write_cas(&p("state://k")?, Some(Value::integer(1)), Value::integer(2))
            .await?;
        let value = b.read(&p("state://k")?).await?;
        ensure!(
            value == Some(Value::integer(2)),
            "unexpected value: {value:?}"
        );
        Ok(())
    })
}

#[test]
fn rejected_append_and_cas_preserve_value_taint_history_and_notifications() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        let path = p("state://k")?;
        let original = TaintedValue::new(Value::integer(1), TaintSet::of(TaintSource::ModelOutput));
        b.write_set_tainted(&path, original.value.clone(), original.taint.clone())
            .await?;
        let history = b.inner.read().history.clone();
        let mut events = b.subscribe(&path).await?;
        let incoming_taint = TaintSet::author();

        let append = b
            .write_append_tainted(&path, Value::integer(2), incoming_taint.clone())
            .await;
        ensure!(
            matches!(append, Err(crate::StateFailure { error: StateError::Backend(message), .. }) if message.contains("append on non-list"))
        );
        let cas = b
            .write_cas_tainted(
                &path,
                Some(Value::integer(99)),
                Value::integer(2),
                incoming_taint,
            )
            .await;
        ensure!(
            matches!(cas, Err(crate::StateFailure { error: StateError::CasFailed { expected, actual, .. }, .. })
            if expected.as_deref() == Some(&Value::integer(99)) && actual.as_deref() == Some(&original.value))
        );
        let delete = b
            .write_compare_delete(&path, Some(Value::integer(99)))
            .await;
        ensure!(
            matches!(delete, Err(crate::StateFailure { error: StateError::CasFailed { expected, actual, .. }, .. })
            if expected.as_deref() == Some(&Value::integer(99)) && actual.as_deref() == Some(&original.value))
        );

        ensure!(b.read_tainted(&path).await? == Some(original));
        {
            let state = b.inner.read();
            ensure!(state.history.len() == history.len());
            ensure!(state.history.iter().zip(&history).all(|(after, before)| {
                after.at_millis == before.at_millis && same_event(&after.event, &before.event)
            }));
            ensure!(state.notifications.is_empty() && !state.notifying);
        }
        ensure!(matches!(
            events.try_recv(),
            Err(crate::StateWatchError::Empty)
        ));
        Ok(())
    })
}

#[test]
fn cas_creates_when_expected_none() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        b.write_cas(&p("state://k")?, None, Value::integer(7))
            .await?;
        let value = b.read(&p("state://k")?).await?;
        ensure!(
            value == Some(Value::integer(7)),
            "unexpected value: {value:?}"
        );
        Ok(())
    })
}

#[test]
fn concurrent_cas_none_commits_one_value_and_lineage() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        const WORKERS: usize = 8;
        const ROUNDS: usize = 128;

        let backend = InMemoryBackend::with_options(options)?;
        let barrier = std::sync::Barrier::new(WORKERS);
        let paths = (0..ROUNDS)
            .map(|round| p(&format!("state://cas/{round}")))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let contenders = (0..WORKERS)
            .map(|worker| {
                TaintedValue::new(
                    Value::string(format!("worker-{worker}")),
                    TaintSet::of(xolotl_types::TaintSource::Fetched {
                        host: format!("worker-{worker}").into(),
                    }),
                )
            })
            .collect::<Vec<_>>();
        let runtimes = (0..WORKERS)
            .map(|_| tokio::runtime::Builder::new_current_thread().build())
            .collect::<std::io::Result<Vec<_>>>()?;

        let results = std::thread::scope(|scope| {
            let backend = &backend;
            let barrier = &barrier;
            let paths = &paths;
            let handles = runtimes
                .into_iter()
                .zip(&contenders)
                .map(|(runtime, contender)| {
                    scope.spawn(move || {
                        paths
                            .iter()
                            .map(|path| {
                                barrier.wait();
                                runtime.block_on(backend.write_cas_tainted(
                                    path,
                                    None,
                                    contender.value.clone(),
                                    contender.taint.clone(),
                                ))
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect::<Vec<_>>();
            handles
                .into_iter()
                .map(|handle| {
                    handle.join().map_err(|panic| {
                        let reason = panic
                            .downcast_ref::<String>()
                            .map(String::as_str)
                            .or_else(|| panic.downcast_ref::<&str>().copied())
                            .unwrap_or("non-string panic");
                        anyhow!("CAS contender panicked: {reason}")
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })?;

        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        runtime.block_on(async {
            for (round, path) in paths.iter().enumerate() {
                let mut winners = Vec::new();
                for (worker, outcomes) in results.iter().enumerate() {
                    match &outcomes[round] {
                        Ok(_) => winners.push(worker),
                        Err(crate::StateFailure {
                            error: StateError::CasFailed { .. },
                            ..
                        }) => {}
                        Err(other) => bail!("unexpected CAS error at {path}: {other}"),
                    }
                }
                ensure!(
                    winners.len() == 1,
                    "expected one CAS winner at {path}, got {winners:?}"
                );
                let winner = &contenders[winners[0]];
                let actual = backend.read_tainted(path).await?;
                ensure!(
                    actual.as_ref() == Some(winner),
                    "committed value or lineage differs from winner at {path}: {actual:?}"
                );
                if options.history == MemoryHistory::Full {
                    let history = backend.read_range(path, 0, i64::MAX).await?;
                    match history.as_slice() {
                        [
                            StateHistoryEntry {
                                event: StateEvent::Set { value, taint, .. },
                                ..
                            },
                        ] => ensure!(
                            value == &winner.value && taint == &winner.taint,
                            "history differs from winning CAS at {path}"
                        ),
                        other => bail!("expected one committed CAS at {path}, got {other:?}"),
                    }
                }
            }
            if options.history == MemoryHistory::Disabled {
                ensure!(backend.inner.read().history.capacity() == 0);
            }
            Ok(())
        })
    })
}

#[test]
fn cas_can_match_explicit_null_value() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        b.write_set(&p("state://k")?, Value::null()).await?;
        b.write_cas(&p("state://k")?, Some(Value::null()), Value::integer(9))
            .await?;
        let value = b.read(&p("state://k")?).await?;
        ensure!(
            value == Some(Value::integer(9)),
            "unexpected value: {value:?}"
        );
        Ok(())
    })
}

#[test]
fn cas_none_does_not_match_explicit_null_value() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        b.write_set(&p("state://k")?, Value::null()).await?;
        let err = b.write_cas(&p("state://k")?, None, Value::integer(9)).await;
        ensure!(
            matches!(
                err,
                Err(crate::StateFailure {
                    error: StateError::CasFailed { .. },
                    ..
                })
            ),
            "expected CasFailed"
        );
        Ok(())
    })
}

#[test]
fn delete_removes() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        b.write_set(&p("state://k")?, Value::integer(1)).await?;
        b.write_delete(&p("state://k")?).await?;
        let value = b.read(&p("state://k")?).await?;
        ensure!(value.is_none(), "expected deleted value, got {value:?}");
        Ok(())
    })
}

#[test]
fn merge_missing_path_uses_incoming_value() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        b.write_merge(&p("state://k")?, Value::integer(7), MergeRule::Shallow)
            .await?;
        let value = b.read(&p("state://k")?).await?;
        ensure!(
            value == Some(Value::integer(7)),
            "unexpected value: {value:?}"
        );
        Ok(())
    })
}

#[test]
fn subscribe_receives_events() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        let mut rx = b.subscribe(&p("state://watched/**")?).await?;
        b.write_set(&p("state://watched/a")?, Value::integer(1))
            .await?;
        let ev = rx.try_recv()?;
        match ev {
            StateEvent::Set { path, .. } => ensure!(
                path.to_string() == "state://watched/a",
                "unexpected path: {path}"
            ),
            other => bail!("wrong event: {other:?}"),
        }
        Ok(())
    })
}

#[test]
fn subscribe_filters_by_pattern() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        let mut rx = b.subscribe(&p("state://watched/specific")?).await?;
        b.write_set(&p("state://watched/other")?, Value::integer(1))
            .await?;
        let res = rx.try_recv();
        ensure!(
            matches!(res, Err(crate::StateWatchError::Empty)),
            "unexpected event: {res:?}"
        );
        Ok(())
    })
}

#[test]
fn notifications_and_prefix_reads_preserve_append_merge_and_cas_provenance() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let backend = InMemoryBackend::with_options(options)?;
        let path = p("state://watched/list")?;
        let mut events = backend.subscribe(&p("state://watched/**")?).await?;
        let first_taint = TaintSet::of(TaintSource::ModelOutput);
        let second_taint = TaintSet::of(TaintSource::Fetched {
            host: "example.test".into(),
        });
        let combined = first_taint.clone().merged(&second_taint);
        let second_event_taint = second_taint.clone().merged(&first_taint);
        backend
            .write_append_tainted(&path, Value::integer(1), first_taint.clone())
            .await?;
        backend
            .write_append_tainted(&path, Value::integer(2), second_taint.clone())
            .await?;
        ensure!(
            backend.read_tainted(&path).await?
                == Some(TaintedValue::new(
                    Value::list(vec![Value::integer(1), Value::integer(2)]),
                    combined.clone()
                ))
        );
        backend
            .write_merge(
                &path,
                Value::list(vec![Value::integer(3)]),
                MergeRule::Shallow,
            )
            .await?;
        let merged = Value::list(vec![
            Value::integer(1),
            Value::integer(2),
            Value::integer(3),
        ]);
        ensure!(
            backend.read_prefix_tainted(&p("state://watched")?).await?
                == vec![(
                    path.clone(),
                    TaintedValue::new(merged.clone(), combined.clone())
                )]
        );

        for expected in [
            StateEvent::Append {
                path: path.clone(),
                item: Value::integer(1),
                taint: first_taint,
            },
            StateEvent::Append {
                path: path.clone(),
                item: Value::integer(2),
                taint: second_event_taint,
            },
            StateEvent::Set {
                path: path.clone(),
                value: merged.clone(),
                taint: combined.clone(),
            },
        ] {
            ensure!(same_event(&events.try_recv()?, &expected));
        }

        backend
            .write_cas_tainted(&path, Some(merged), Value::integer(4), TaintSet::author())
            .await?;
        let replacement =
            TaintedValue::new(Value::integer(4), TaintSet::author().merged(&combined));
        ensure!(backend.read_tainted(&path).await? == Some(replacement.clone()));
        ensure!(same_event(
            &events.try_recv()?,
            &StateEvent::Set {
                path,
                value: replacement.value,
                taint: replacement.taint
            }
        ));
        ensure!(matches!(
            events.try_recv(),
            Err(crate::StateWatchError::Empty)
        ));
        if options.history == MemoryHistory::Disabled {
            ensure!(backend.inner.read().history.capacity() == 0);
        }
        Ok(())
    })
}

#[test]
fn read_prefix_returns_sorted_matching_entries_only() -> anyhow::Result<()> {
    for_backends(&HISTORY_MODES, |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        b.write_set(&p("state://memory/b")?, Value::integer(2))
            .await?;
        b.write_set(&p("state://memory/a")?, Value::integer(1))
            .await?;
        b.write_set(&p("state://memory")?, Value::integer(0))
            .await?;
        b.write_set(&p("state://other/z")?, Value::integer(99))
            .await?;
        b.write_set(&p("state://memory-extra/a")?, Value::integer(99))
            .await?;

        let rows = b.read_prefix(&p("state://memory")?).await?;
        ensure!(
            rows == vec![
                (p("state://memory")?, Value::integer(0)),
                (p("state://memory/a")?, Value::integer(1)),
                (p("state://memory/b")?, Value::integer(2)),
            ],
            "unexpected prefix snapshot: {rows:?}"
        );
        Ok(())
    })
}

#[test]
fn read_range_includes_direct_and_descendant_paths() -> anyhow::Result<()> {
    for_backends(&[MemoryHistory::Full], |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        let prefix = p("state://memory")?;
        b.write_set(&p("state://memory")?, Value::integer(1))
            .await?;
        b.write_set(&p("state://memory/alice")?, Value::integer(2))
            .await?;
        b.write_set(&p("state://other")?, Value::integer(3)).await?;

        let entries = b.read_range(&prefix, 0, i64::MAX).await?;
        let event_paths: Vec<String> = entries
            .into_iter()
            .map(|entry| match entry.event {
                StateEvent::Set { path, .. } => path.to_string(),
                StateEvent::Append { path, .. } => path.to_string(),
                StateEvent::Delete { path, .. } => path.to_string(),
            })
            .collect();
        ensure!(
            event_paths == vec!["state://memory", "state://memory/alice"],
            "unexpected paths: {event_paths:?}"
        );
        Ok(())
    })
}

#[test]
fn read_at_reconstructs_list_before_delete() -> anyhow::Result<()> {
    for_backends(&[MemoryHistory::Full], |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        let path = p("state://log")?;
        b.write_append(&path, Value::integer(1)).await?;
        let after_first = b
            .inner
            .read()
            .history
            .first()
            .context("missing first history entry")?
            .at_millis;
        b.write_append(&path, Value::integer(2)).await?;
        let before_delete = b
            .inner
            .read()
            .history
            .get(1)
            .context("missing second history entry")?
            .at_millis;
        b.write_delete(&path).await?;

        let before_value = b.read_at(&path, after_first).await?;
        let mid_value = b.read_at(&path, before_delete).await?;
        let current = b.read(&path).await?;

        ensure!(
            before_value == Some(TaintedValue::pristine(Value::list(vec![Value::integer(1)]))),
            "unexpected first historical value: {before_value:?}"
        );
        ensure!(
            mid_value
                == Some(TaintedValue::pristine(Value::list(vec![
                    Value::integer(1),
                    Value::integer(2)
                ]))),
            "unexpected second historical value: {mid_value:?}"
        );
        ensure!(current.is_none(), "unexpected current value: {current:?}");
        Ok(())
    })
}

#[test]
fn history_timestamps_are_strictly_increasing() -> anyhow::Result<()> {
    for_backends(&[MemoryHistory::Full], |options| async move {
        let b = InMemoryBackend::with_options(options)?;
        b.write_set(&p("state://x")?, Value::integer(1)).await?;
        b.write_set(&p("state://x")?, Value::integer(2)).await?;
        b.write_delete(&p("state://x")?).await?;

        let times: Vec<i64> = b
            .inner
            .read()
            .history
            .iter()
            .map(|entry| entry.at_millis)
            .collect();
        match times.as_slice() {
            [first, second, third] => {
                ensure!(first < second, "first timestamp order violated: {times:?}");
                ensure!(second < third, "second timestamp order violated: {times:?}");
                let range = b.read_range(&p("state://x")?, *first, *second).await?;
                ensure!(range.len() == 1 && range[0].at_millis == *first);
                ensure!(
                    b.read_range(&p("state://x")?, *second, *second)
                        .await?
                        .is_empty()
                );
                ensure!(matches!(
                    b.read_range(&p("state://x")?, *third, *first).await,
                    Err(crate::StateFailure {
                        error: StateError::InvalidQuery(_),
                        ..
                    })
                ));
            }
            other => bail!("expected 3 timestamps, got {other:?}"),
        }
        Ok(())
    })
}
