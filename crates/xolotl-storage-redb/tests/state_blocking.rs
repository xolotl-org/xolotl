use anyhow::{Context as _, ensure};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};
use xolotl_kernel::host::{BlockingJob, BlockingSpawnError, BlockingSpawner};
use xolotl_state::{
    StateBoundedRead, StateBoundedWrite, StateError, StateHistory, StateHistoryQuery,
    StateHistoryRetention, StateHistoryTrimLimits, StateQuery, StateRead, StateScan, StateWatch,
    StateWatchError, StateWrite, StateWriteExt,
};
use xolotl_storage_redb::{RedbHistory, RedbOptions, RedbStore};
use xolotl_types::{Path, TaintSet, TaintSource, Value};

struct ThreadWake(thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let wake = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&wake);
    let mut future = std::pin::pin!(future);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Poll::Ready(result) = future.as_mut().poll(&mut context) {
            return result;
        }
        let now = Instant::now();
        assert!(now < deadline, "state read worker did not finish");
        thread::park_timeout(deadline - now);
    }
}

struct Slot(Arc<AtomicUsize>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

struct ThreadSpawner {
    active: Arc<AtomicUsize>,
}

impl Default for ThreadSpawner {
    fn default() -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl BlockingSpawner for ThreadSpawner {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        let current = self.active.fetch_add(1, Ordering::AcqRel);
        if current >= 8 {
            self.active.fetch_sub(1, Ordering::Release);
            return Err(BlockingSpawnError::AtCapacity);
        }
        let slot = Slot(Arc::clone(&self.active));
        thread::Builder::new()
            .spawn(move || {
                let _slot = slot;
                job();
            })
            .map_err(|_error| BlockingSpawnError::Unavailable)?;
        Ok(())
    }
}

#[test]
fn state_reads_use_an_explicit_non_tokio_blocking_host() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open_with_options_and_spawner(
        dir.path().join("state.redb"),
        RedbOptions {
            history: RedbHistory::Full,
            ..RedbOptions::default()
        },
        Arc::new(ThreadSpawner::default()),
    )?;
    let state = store.state_backend();
    let path = Path::parse("state://blocking/read")?;
    block_on(state.write_set(&path, Value::integer(7)))?;

    ensure!(
        block_on(state.read_tainted(&path))?
            .value
            .context("point read")?
            == Value::integer(7)
    );
    ensure!(
        block_on(state.read_tainted_bounded(&path, NonZeroUsize::new(1024).context("limit")?))?
            .value
            .context("bounded point read")?
            == Value::integer(7)
    );
    ensure!(
        block_on(state.query(&StateScan::new(path.clone())))?
            .entries
            .len()
            == 1
    );
    ensure!(
        block_on(state.history(&StateHistoryQuery::new(path.clone(), 0, i64::MAX)))?
            .entries
            .len()
            == 1
    );
    ensure!(
        block_on(state.read_at(&path, i64::MAX))?
            .value
            .context("historical point")?
            == Value::integer(7)
    );
    let mut events = block_on(state.subscribe(&path))?;
    block_on(state.write_set(&path, Value::integer(8)))?;
    ensure!(matches!(
        events.try_recv()?,
        xolotl_state::StateEvent::Set { value, .. } if value == Value::integer(8)
    ));
    Ok(())
}

struct HoldingSpawner {
    held: Mutex<Option<BlockingJob>>,
    active: Arc<AtomicBool>,
    accepted: AtomicUsize,
    finished: Arc<AtomicUsize>,
}

impl Default for HoldingSpawner {
    fn default() -> Self {
        Self {
            held: Mutex::new(None),
            active: Arc::new(AtomicBool::new(false)),
            accepted: AtomicUsize::new(0),
            finished: Arc::new(AtomicUsize::new(0)),
        }
    }
}

struct HeldSlot(Arc<AtomicBool>);

impl Drop for HeldSlot {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl BlockingSpawner for HoldingSpawner {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        if self
            .active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(BlockingSpawnError::AtCapacity);
        }
        let slot = HeldSlot(Arc::clone(&self.active));
        let finished = Arc::clone(&self.finished);
        *self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Box::new(move || {
            let _slot = slot;
            job();
            finished.fetch_add(1, Ordering::Release);
        }));
        self.accepted.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[test]
fn read_admission_is_lazy_bounded_and_detached_from_its_waiter() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let spawner = Arc::new(HoldingSpawner::default());
    let store = RedbStore::open_with_options_and_spawner(
        dir.path().join("held.redb"),
        RedbOptions::default(),
        spawner.clone(),
    )?;
    let state = store.state_backend();
    let path = Path::parse("state://blocking/held")?;
    let wake = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&wake);
    let mut seed = Box::pin(state.write_set(&path, Value::integer(9)));
    ensure!(Pin::as_mut(&mut seed).poll(&mut context).is_pending());
    run_held(&spawner)?;
    block_on(seed)?;
    let baseline = spawner.accepted.load(Ordering::Relaxed);

    let untouched = state.read_tainted(&path);
    drop(untouched);
    ensure!(spawner.accepted.load(Ordering::Relaxed) == baseline);

    let mut accepted = Box::pin(state.read_tainted(&path));
    ensure!(Pin::as_mut(&mut accepted).poll(&mut context).is_pending());
    ensure!(spawner.accepted.load(Ordering::Relaxed) == baseline + 1);
    drop(accepted);

    let rejected = block_on(state.read_tainted(&path))
        .err()
        .context("full spawner must reject")?;
    ensure!(matches!(rejected.error, StateError::Backend(_)));
    ensure!(spawner.accepted.load(Ordering::Relaxed) == baseline + 1);
    ensure!(spawner.active.load(Ordering::Acquire));

    let job = spawner
        .held
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .context("accepted read job")?;
    job();
    ensure!(spawner.finished.load(Ordering::Acquire) == baseline + 1);
    ensure!(!spawner.active.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn store_idle_waits_for_cancelled_read_to_release_database() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("idle.redb");
    let spawner = Arc::new(HoldingSpawner::default());
    let store =
        RedbStore::open_with_options_and_spawner(&path, RedbOptions::default(), spawner.clone())?;
    let state = store.state_backend();
    let key = Path::parse("state://blocking/idle")?;
    let wake = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&wake);
    let mut read = Box::pin(state.read_tainted(&key));
    ensure!(read.as_mut().poll(&mut context).is_pending());
    drop(read);
    drop(state);

    // The idle future retains only the tracker. The accepted read is now the
    // sole owner of the database after the store and result waiter are gone.
    let mut idle = Box::pin(store.wait_idle());
    drop(store);
    ensure!(idle.as_mut().poll(&mut context).is_pending());
    ensure!(matches!(
        RedbStore::open(&path),
        Err(redb::DatabaseError::DatabaseAlreadyOpen)
    ));

    run_held(&spawner)?;
    block_on(idle);
    drop(RedbStore::open(&path)?);
    Ok(())
}

#[test]
fn default_read_host_without_tokio_returns_unavailable() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = RedbStore::open(dir.path().join("default.redb"))?.state_backend();
    let path = Path::parse("state://blocking/default")?;
    let failure = block_on(state.read_tainted(&path))
        .err()
        .context("Tokio runtime is absent")?;
    ensure!(matches!(failure.error, StateError::Backend(_)));
    Ok(())
}

fn run_held(spawner: &HoldingSpawner) -> anyhow::Result<()> {
    let job = spawner
        .held
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
        .context("accepted state job")?;
    job();
    Ok(())
}

#[test]
fn state_write_admission_is_lazy_bounded_and_detached() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let spawner = Arc::new(HoldingSpawner::default());
    let state = RedbStore::open_with_options_and_spawner(
        dir.path().join("write.redb"),
        RedbOptions::default(),
        spawner.clone(),
    )?
    .state_backend();
    let path = Path::parse("state://blocking/write")?;
    let mut events = block_on(state.subscribe(&path))?;

    drop(state.write_set(&path, Value::integer(1)));
    ensure!(spawner.accepted.load(Ordering::Relaxed) == 0);
    ensure!(matches!(events.try_recv(), Err(StateWatchError::Empty)));

    let wake = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut context = Context::from_waker(&wake);
    let mut accepted = Box::pin(state.write_set(&path, Value::integer(2)));
    ensure!(Pin::as_mut(&mut accepted).poll(&mut context).is_pending());
    ensure!(spawner.accepted.load(Ordering::Relaxed) == 1);
    drop(accepted);

    let rejected = block_on(state.write_set(&path, Value::integer(3)))
        .err()
        .context("full host must reject without writing")?;
    ensure!(matches!(rejected.error, StateError::Backend(_)));
    ensure!(spawner.accepted.load(Ordering::Relaxed) == 1);

    run_held(&spawner)?;
    ensure!(matches!(
        events.try_recv()?,
        xolotl_state::StateEvent::Set { value, .. } if value == Value::integer(2)
    ));
    let mut read = Box::pin(state.read_tainted(&path));
    ensure!(Pin::as_mut(&mut read).poll(&mut context).is_pending());
    run_held(&spawner)?;
    ensure!(block_on(read)?.value.context("committed write")? == Value::integer(2));
    Ok(())
}

struct DiscardingSpawner;

impl BlockingSpawner for DiscardingSpawner {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        // Simulate a host shutting down after admission but before execution.
        drop(job);
        Ok(())
    }
}

#[test]
fn discarded_accepted_writes_report_unknown_and_retain_input_sources() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = RedbStore::open_with_options_and_spawner(
        dir.path().join("discarded.redb"),
        RedbOptions {
            history: RedbHistory::Full,
            ..RedbOptions::default()
        },
        Arc::new(DiscardingSpawner),
    )?
    .state_backend();
    let path = Path::parse("state://blocking/discarded")?;
    let input = TaintSet::of(TaintSource::ModelOutput);
    for mutation in [
        xolotl_state::StateMutation::Set(xolotl_state::TaintedValue::new(
            Value::integer(1),
            input.clone(),
        )),
        xolotl_state::StateMutation::Delete(input.clone()),
        xolotl_state::StateMutation::CompareDelete {
            expected: None,
            taint: input.clone(),
        },
    ] {
        let failed = block_on(state.mutate(&path, mutation))
            .err()
            .context("accepted write lost its worker")?;
        ensure!(matches!(failed.error, StateError::CommitUncertain(_)));
        ensure!(failed.taint == input);
    }
    let failed =
        block_on(state.compare_delete_bounded(&path, None, input.clone(), NonZeroUsize::MIN))
            .err()
            .context("accepted bounded delete lost its worker")?;
    ensure!(matches!(failed.error, StateError::CommitUncertain(_)) && failed.taint == input);

    let failed_trim = block_on(state.trim_before(
        1,
        StateHistoryTrimLimits {
            events: NonZeroUsize::MIN,
            encoded_bytes: NonZeroUsize::MIN,
        },
    ))
    .err()
    .context("accepted trim lost its worker")?;
    ensure!(matches!(failed_trim.error, StateError::CommitUncertain(_)));
    Ok(())
}

#[test]
fn history_maintenance_uses_non_tokio_blocking_host() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let state = RedbStore::open_with_options_and_spawner(
        dir.path().join("trim.redb"),
        RedbOptions {
            history: RedbHistory::Full,
            ..RedbOptions::default()
        },
        Arc::new(ThreadSpawner::default()),
    )?
    .state_backend();
    let path = Path::parse("state://blocking/trim")?;
    block_on(state.write_set(&path, Value::integer(1)))?;
    ensure!(block_on(state.retained_from())? == i64::MIN);
    let trimmed = block_on(state.trim_before(
        1,
        StateHistoryTrimLimits {
            events: NonZeroUsize::new(8).context("event limit")?,
            encoded_bytes: NonZeroUsize::new(4096).context("byte limit")?,
        },
    ))?;
    ensure!(trimmed.retained_from_millis == 1);
    ensure!(block_on(state.retained_from())? == 1);
    Ok(())
}
