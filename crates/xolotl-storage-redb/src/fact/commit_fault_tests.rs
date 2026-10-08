//! Fault the actual redb file backend at the Fact commit boundary.

use super::{FactNotifications, RedbFactStore, tests::fact};
use crate::RedbStore;
use anyhow::{Context, ensure};
use redb::{Database, StorageBackend};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};
use std::task::{Context as TaskContext, Poll, Wake, Waker};
use tokio::sync::broadcast::error::TryRecvError;
use xolotl_kernel::{ExecutionIdError, ExecutionIdSource, FactErrorKind, FactStore};
use xolotl_types::ProcessId;

const NO_FAULT: u8 = 0;
const FAIL_BEFORE_WRITE: u8 = 1;
const FAIL_AFTER_SYNC: u8 = 2;

struct ReentrantWake {
    notifications: Arc<FactNotifications>,
    unlocked: AtomicBool,
    wakes: AtomicUsize,
}

impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
        let unlocked = self.notifications.tx.try_lock().is_some()
            && self.notifications.commit_gate.try_lock().is_some();
        self.unlocked.fetch_and(unlocked, Ordering::SeqCst);
        self.wakes.fetch_add(1, Ordering::SeqCst);
        if unlocked {
            drop(self.notifications.subscribe());
        }
    }
}

#[test]
fn fact_delivery_allows_reentrant_subscription() -> anyhow::Result<()> {
    let notifications = Arc::new(FactNotifications::new());
    let mut stream = notifications.subscribe();
    let mut receive = std::pin::pin!(stream.recv());
    let probe = Arc::new(ReentrantWake {
        notifications: notifications.clone(),
        unlocked: AtomicBool::new(true),
        wakes: AtomicUsize::new(0),
    });
    let waker = Waker::from(probe.clone());
    ensure!(
        std::future::Future::poll(receive.as_mut(), &mut TaskContext::from_waker(&waker),)
            .is_pending()
    );
    notifications.send(fact(1, 0, false));
    ensure!(probe.wakes.load(Ordering::SeqCst) > 0);
    ensure!(probe.unlocked.load(Ordering::SeqCst));
    ensure!(matches!(std::future::Future::poll(
        receive.as_mut(),
        &mut TaskContext::from_waker(&waker),
    ), Poll::Ready(Ok(record)) if record.id == fact(1, 0, false).id));
    Ok(())
}

#[derive(Debug, Default)]
struct FaultControl(AtomicU8);

impl FaultControl {
    fn arm(&self, mode: u8) {
        self.0.store(mode, Ordering::SeqCst);
    }

    fn fault(&self, mode: u8) -> bool {
        self.0
            .compare_exchange(mode, NO_FAULT, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    fn was_used(&self) -> bool {
        self.0.load(Ordering::SeqCst) == NO_FAULT
    }
}

#[derive(Debug)]
struct FaultingStorage {
    file: Mutex<File>,
    control: Arc<FaultControl>,
}

impl FaultingStorage {
    fn file(&self) -> io::Result<MutexGuard<'_, File>> {
        self.file
            .lock()
            .map_err(|_error| io::Error::other("fault storage mutex poisoned"))
    }
}

impl StorageBackend for FaultingStorage {
    fn len(&self) -> io::Result<u64> {
        Ok(self.file()?.metadata()?.len())
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let mut file = self.file()?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(out)
    }

    fn set_len(&self, len: u64) -> io::Result<()> {
        self.file()?.set_len(len)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.file()?.sync_data()?;
        if self.control.fault(FAIL_AFTER_SYNC) {
            return Err(io::Error::other("injected post-sync failure"));
        }
        Ok(())
    }

    fn write(&self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        if self.control.fault(FAIL_BEFORE_WRITE) {
            return Err(io::Error::other("injected pre-write failure"));
        }
        let mut file = self.file()?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)
    }
}

fn open_faulting(path: &Path, control: Arc<FaultControl>) -> anyhow::Result<RedbFactStore> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    let db = Database::builder().create_with_backend(FaultingStorage {
        file: Mutex::new(file),
        control,
    })?;
    Ok(crate::RedbStore::from_database(
        db,
        crate::RedbOptions::default(),
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?
    .fact_store()?)
}

#[test]
fn uncertain_append_closes_stream_and_requires_reopen() -> anyhow::Result<()> {
    for (mode, committed) in [(FAIL_BEFORE_WRITE, false), (FAIL_AFTER_SYNC, true)] {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("facts.redb");
        let control = Arc::new(FaultControl::default());
        {
            let store = open_faulting(&path, control.clone())?;
            let other = RedbFactStore::new(
                store.db.clone(),
                store.cursor.clone(),
                store.notifications.clone(),
            )?;
            let mut events = store.subscribe_facts();
            let mut other_events = other.subscribe_facts();
            let mut waiting_events = other.subscribe_facts();
            let mut receive = std::pin::pin!(waiting_events.recv());
            let probe = Arc::new(ReentrantWake {
                notifications: store.notifications.clone(),
                unlocked: AtomicBool::new(true),
                wakes: AtomicUsize::new(0),
            });
            let waker = Waker::from(probe.clone());
            ensure!(
                std::future::Future::poll(receive.as_mut(), &mut TaskContext::from_waker(&waker),)
                    .is_pending()
            );
            control.arm(mode);
            let error = store
                .append(fact(1, 0, false))
                .err()
                .context("faulted commit must not claim success")?;
            ensure!(control.was_used(), "storage fault was not exercised");
            ensure!(probe.wakes.load(Ordering::SeqCst) > 0);
            ensure!(probe.unlocked.load(Ordering::SeqCst));
            ensure!(matches!(
                std::future::Future::poll(receive.as_mut(), &mut TaskContext::from_waker(&waker),),
                Poll::Ready(Err(tokio::sync::broadcast::error::RecvError::Closed))
            ));
            ensure!(
                error.kind() == FactErrorKind::CommitOutcomeUnknown,
                "wrong error classification: {error}"
            );
            ensure!(
                matches!(events.try_recv(), Err(TryRecvError::Closed)),
                "uncertain commit must close existing subscribers"
            );
            ensure!(
                matches!(other_events.try_recv(), Err(TryRecvError::Closed)),
                "independent adapters must share the closed notification source"
            );
            ensure!(
                matches!(
                    store.subscribe_facts().try_recv(),
                    Err(TryRecvError::Closed)
                ),
                "new subscribers must fail closed until reopen"
            );
            // redb may retain the previous live root after a post-sync error.
            // Its local cursor is only a hint; the checked accessor must fail.
            ensure!(
                matches!(store.observed_cursor(), Err(ref error) if error.kind() == FactErrorKind::ReopenRequired)
            );
            ensure!(
                matches!(other.observed_cursor(), Err(ref error) if error.kind() == FactErrorKind::ReopenRequired)
            );
            ensure!(
                matches!(store.get(fact(1, 0, false).id), Err(ref error) if error.kind() == FactErrorKind::ReopenRequired)
            );
            ensure!(
                matches!(store.facts_of(ProcessId::new(1)), Err(ref error) if error.kind() == FactErrorKind::ReopenRequired)
            );
            ensure!(
                matches!(store.all_facts(), Err(ref error) if error.kind() == FactErrorKind::ReopenRequired)
            );
            let append_error = store
                .append(fact(1, 1, false))
                .err()
                .context("writes must remain closed until reopen")?;
            ensure!(append_error.kind() == FactErrorKind::ReopenRequired);
            let completion_error = store
                .complete(fact(1, 0, true))
                .err()
                .context("completions must remain closed until reopen")?;
            ensure!(completion_error.kind() == FactErrorKind::ReopenRequired);
            let other_error = other
                .append(fact(2, 0, false))
                .err()
                .context("other adapters must remain closed until reopen")?;
            ensure!(other_error.kind() == FactErrorKind::ReopenRequired);
            ensure!(matches!(
                store.reserve(NonZeroU64::MIN),
                Err(ExecutionIdError::Backend(_))
            ));
            ensure!(matches!(
                other.reserve(NonZeroU64::MIN),
                Err(ExecutionIdError::Backend(_))
            ));
        }

        let reopened = RedbStore::open(&path)?.fact_store()?;
        ensure!(reopened.reserve(NonZeroU64::MIN)?.first().get() == 1);
        ensure!(reopened.cursor() == u64::from(committed));
        ensure!(reopened.observed_cursor()? == u64::from(committed));
        ensure!(reopened.all_facts()?.len() == usize::from(committed));
        if committed {
            ensure!(reopened.append(fact(1, 0, false))? == 0);
        }
        ensure!(reopened.append(fact(1, 1, false))? == u64::from(committed));
    }
    Ok(())
}

#[test]
fn uncertain_completion_closes_stream_even_without_cursor_change() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("facts.redb");
    let control = Arc::new(FaultControl::default());
    {
        let store = open_faulting(&path, control.clone())?;
        store.append(fact(1, 0, false))?;
        let mut events = store.subscribe_facts();
        control.arm(FAIL_AFTER_SYNC);
        let error = store
            .complete(fact(1, 0, true))
            .err()
            .context("faulted completion must not claim success")?;
        ensure!(control.was_used());
        ensure!(error.kind() == FactErrorKind::CommitOutcomeUnknown);
        ensure!(store.cursor() == 1);
        ensure!(store.observed_cursor().is_err());
        ensure!(matches!(events.try_recv(), Err(TryRecvError::Closed)));
    }
    let reopened = RedbStore::open(&path)?.fact_store()?;
    let facts = reopened.facts_of(ProcessId::new(1))?;
    ensure!(facts.len() == 1);
    ensure!(
        facts[0].is_complete(),
        "committed outcome was not recovered"
    );
    let mut events = reopened.subscribe_facts();
    reopened.append(fact(1, 1, false))?;
    events
        .try_recv()
        .context("reopened stream did not resume")?;
    Ok(())
}
