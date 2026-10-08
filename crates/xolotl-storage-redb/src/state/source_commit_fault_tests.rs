//! Faults the actual redb storage backend during Source's write transaction.
//! No failure switch is installed in the production Source port.

use super::{RedbHistory, RedbStateBackend};
use crate::{RedbFactStore, RedbOptions, RedbStore};
use anyhow::{Context, ensure};
use redb::{Database, StorageBackend};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path as FilePath;
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicU8, AtomicUsize, Ordering},
    mpsc,
};
use std::task::{Context as TaskContext, Poll, Wake, Waker};
use std::time::Duration;
use tokio::sync::broadcast::error::TryRecvError;
use xolotl_kernel::{FactErrorKind, FactStore};
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, SourceClaim, SourceClaimEvidence,
    SourceClaimId, SourceClaimInspection, SourceCommit, SourceCommitOutcome, SourceEventCommit,
    SourceEvidenceInspection, SourceStoreError, SourceStreamLifecycle, SourceStreamOpen,
    SourceStreamOpenOutcome, SourceStreamPosition, SourceStreamScope,
};
use xolotl_state::{
    StateError, StateHistory, StateHistoryQuery, StateObservation, StateRead, StateReadExt,
    StateStream, StateSubscription, StateWatch, StateWatchError, StateWriteExt,
};
use xolotl_types::{
    DecisionTag, ExecutionId, Fact, HandleId, IdentityRef, InvocationId, MethodId, NodeId,
    OperationId, Path, ProcessId, Purity, ReplayClass, ResourceId, TaintSet, TaintSource,
    Timestamp, Transport, TrustLevel, Value,
    external::{
        EventSource, ExternalInstallationDef, ExternalProjectionDef, OverflowPolicy, Role,
        SourceRateLimit, StreamCapacity,
    },
};

const NO_FAULT: u8 = 0;
const FAIL_BEFORE_WRITE: u8 = 1;
const FAIL_AFTER_SYNC: u8 = 2;
const PANIC_AFTER_SYNC: u8 = 3;

#[derive(Debug, Default)]
struct FaultControl {
    armed: AtomicU8,
    injected: AtomicUsize,
    pause: Mutex<Option<CommitPause>>,
}

#[derive(Debug)]
struct CommitPause {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

impl FaultControl {
    fn arm(&self, mode: u8) {
        self.armed.store(mode, Ordering::SeqCst);
    }

    fn fault(&self, mode: u8) -> bool {
        if self
            .armed
            .compare_exchange(mode, NO_FAULT, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.injected.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }

    fn pause_after_sync(&self, entered: mpsc::Sender<()>, release: mpsc::Receiver<()>) {
        *self
            .pause
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(CommitPause { entered, release });
    }
}

#[derive(Debug)]
struct FaultingStorage {
    file: Mutex<File>,
    control: Arc<FaultControl>,
}

impl FaultingStorage {
    fn file(&self) -> Result<MutexGuard<'_, File>, io::Error> {
        self.file
            .lock()
            .map_err(|_error| io::Error::other("fault storage mutex poisoned"))
    }
}

impl StorageBackend for FaultingStorage {
    fn len(&self) -> Result<u64, io::Error> {
        Ok(self.file()?.metadata()?.len())
    }

    fn read(&self, offset: u64, out: &mut [u8]) -> Result<(), io::Error> {
        let mut file = self.file()?;
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(out)
    }

    fn set_len(&self, len: u64) -> Result<(), io::Error> {
        self.file()?.set_len(len)
    }

    #[expect(
        clippy::panic,
        clippy::panic_in_result_fn,
        reason = "inject a real backend unwind after sync to verify shared recovery"
    )]
    fn sync_data(&self) -> Result<(), io::Error> {
        self.file()?.sync_data()?;
        let pause = self
            .control
            .pause
            .lock()
            .map_err(|_error| io::Error::other("pause mutex poisoned"))?
            .take();
        if let Some(pause) = pause {
            pause
                .entered
                .send(())
                .map_err(|_error| io::Error::other("pause observer dropped"))?;
            pause
                .release
                .recv()
                .map_err(|_error| io::Error::other("pause release dropped"))?;
        }
        if self.control.fault(FAIL_AFTER_SYNC) {
            return Err(io::Error::other("injected post-sync failure"));
        }
        if self.control.fault(PANIC_AFTER_SYNC) {
            panic!("injected post-sync panic");
        }
        Ok(())
    }

    fn write(&self, offset: u64, bytes: &[u8]) -> Result<(), io::Error> {
        if self.control.fault(FAIL_BEFORE_WRITE) {
            return Err(io::Error::other("injected pre-write failure"));
        }
        let mut file = self.file()?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(bytes)
    }
}

fn open_faulting(
    path: &FilePath,
    history: RedbHistory,
    control: Arc<FaultControl>,
) -> anyhow::Result<RedbStateBackend> {
    Ok(open_faulting_store(path, history, control)?.state_backend())
}

fn open_faulting_store(
    path: &FilePath,
    history: RedbHistory,
    control: Arc<FaultControl>,
) -> anyhow::Result<RedbStore> {
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
    Ok(RedbStore::from_database(
        db,
        RedbOptions {
            history,
            ..RedbOptions::default()
        },
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?)
}

fn fact(position: u32) -> Fact {
    Fact {
        id: OperationId::new(
            ProcessId::new(1),
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(position),
            0,
        ),
        schema_version: Fact::SCHEMA_VERSION,
        caller: ProcessId::new(1),
        caller_identity: Some(IdentityRef::ROOT),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(1),
        method: MethodId::new(0),
        input: Value::null(),
        taint: TaintSet::pristine(),
        decision: DecisionTag::Ok,
        outcome: None,
        batch: None,
        replay: ReplayClass::NonIdempotentEffect,
        timestamp: Timestamp::millis(0),
    }
}

#[derive(Default)]
struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn pending_state(stream: &mut StateStream) -> anyhow::Result<Arc<WakeCounter>> {
    let counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(counter.clone());
    ensure!(matches!(
        stream.poll_next(&mut TaskContext::from_waker(&waker)),
        Poll::Pending
    ));
    Ok(counter)
}

fn pending_receive(
    mut receive: std::pin::Pin<&mut impl std::future::Future>,
) -> anyhow::Result<Arc<WakeCounter>> {
    let counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(counter.clone());
    ensure!(matches!(
        std::future::Future::poll(receive.as_mut(), &mut TaskContext::from_waker(&waker)),
        Poll::Pending
    ));
    Ok(counter)
}

async fn ensure_state_fenced(backend: &RedbStateBackend, path: &Path) -> anyhow::Result<()> {
    ensure!(backend.read(path).await.is_err());
    ensure!(backend.read_tainted(path).await.is_err());
    ensure!(backend.subscribe(path).await.is_err());
    Ok(())
}

fn ensure_facts_fenced(facts: &RedbFactStore) -> anyhow::Result<()> {
    ensure!(matches!(
        facts.all_facts(),
        Err(error) if error.kind() == FactErrorKind::ReopenRequired
    ));
    ensure!(matches!(
        facts.get(fact(0).id),
        Err(error) if error.kind() == FactErrorKind::ReopenRequired
    ));
    ensure!(matches!(
        facts.observed_cursor(),
        Err(error) if error.kind() == FactErrorKind::ReopenRequired
    ));
    ensure!(matches!(
        facts.subscribe_facts().try_recv(),
        Err(TryRecvError::Closed)
    ));
    Ok(())
}

struct Admission<'a> {
    sink: &'a Path,
    capacity: &'a StreamCapacity,
    taint: &'a TaintSet,
    rate: &'a SourceRateLimit,
    stream_epoch: u64,
}

impl<'a> Admission<'a> {
    fn request(
        &self,
        event_id: &'a str,
        claim_id: u8,
        payload: &'a Value,
        seq: u64,
    ) -> SourceCommit<'a> {
        SourceCommit {
            claim: SourceClaim {
                installation_id: "installation",
                projection_id: "projection",
                scope_epoch: 2,
                stream_epoch: Some(self.stream_epoch),
                event_id,
                claim_id: SourceClaimId::from_bytes([claim_id; 16]),
            },
            received_at_ms: 100,
            decision_clock: std::sync::Arc::new({
                let decision_at_ms = 100;
                move || decision_at_ms
            }),
            dedupe_window_ms: 1000,
            sink: self.sink,
            capacity: self.capacity,
            max_inline_payload_bytes: 1024,
            payload,
            taint: self.taint,
            stream: Some(SourceStreamPosition {
                stream_id: "ordered",
                stream_epoch: self.stream_epoch,
                seq,
            }),
            rate_limit: Some(self.rate),
        }
    }
}

async fn inspect(
    source: &RedbStateBackend,
    event_id: &str,
    claim_id: u8,
    stream_epoch: u64,
) -> anyhow::Result<SourceClaimEvidence> {
    Ok(source
        .inspect(SourceEvidenceInspection {
            claim: SourceClaim {
                installation_id: "installation",
                projection_id: "projection",
                scope_epoch: 2,
                stream_epoch: Some(stream_epoch),
                event_id,
                claim_id: SourceClaimId::from_bytes([claim_id; 16]),
            },
        })
        .await?)
}

#[tokio::test]
async fn source_commit_io_failure_preserves_exact_claim_and_atomic_state() -> anyhow::Result<()> {
    for (history, mode, expected_committed) in [
        (RedbHistory::CurrentOnly, FAIL_BEFORE_WRITE, false),
        (RedbHistory::CurrentOnly, FAIL_AFTER_SYNC, true),
        (RedbHistory::Full, FAIL_BEFORE_WRITE, false),
        (RedbHistory::Full, FAIL_AFTER_SYNC, true),
    ] {
        let directory = tempfile::tempdir()?;
        let db_path = directory.path().join("source-fault.redb");
        let control = Arc::new(FaultControl::default());
        let store = open_faulting_store(&db_path, history, control.clone())?;
        let facts = store.fact_store()?;
        let mut fact_events = facts.subscribe_facts();
        let backend = store.state_backend();
        let (state, source) = backend.into_source_parts();
        let sink = Path::parse("state://events/external/installation/projection")?;
        let capacity = StreamCapacity {
            max_events: 1,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let first = Value::string("first".into());
        let payload = Value::string("replacement".into());
        let taint = TaintSet::pristine();
        let rate = SourceRateLimit {
            window_ms: 1000,
            max_events: 2,
        };
        let declaration = ExternalInstallationDef {
            id: "installation".into(),
            platform: "test".into(),
            transport: Transport::Grpc { endpoint: None },
            trust: TrustLevel::Full,
            config_schema: Value::map(Default::default()),
            config: Value::null(),
            projections: vec![ExternalProjectionDef {
                id: "projection".into(),
                role: Role::Source,
                namespace: None,
                provides: vec![],
                emits: Some(EventSource {
                    sink: sink.clone(),
                    purity: Purity::Effectful,
                    event_schema: None,
                    max_inline_payload_bytes: 1024,
                    capacity: capacity.clone(),
                    rate_limit: Some(rate.clone()),
                    commands: false,
                    command_schema: None,
                    command_result_schema: None,
                }),
                version: 1,
            }],
            version: 0,
        };
        let ExternalInstallationMutation::Applied(Some(record)) =
            source.compare_install(declaration, None).await?
        else {
            anyhow::bail!("Source installation was not applied")
        };
        ensure!(record.scope_epoch("projection") == Some(2));
        let SourceStreamOpenOutcome::Opened(opened) = source
            .open_stream(SourceStreamOpen {
                stream: SourceStreamScope {
                    installation_id: "installation",
                    projection_id: "projection",
                    scope_epoch: 2,
                    stream_id: "ordered",
                },
                open_id: "fault-test",
                expected_revision: 0,
            })
            .await?
        else {
            anyhow::bail!("fault test stream did not open")
        };
        let stream_epoch = opened.active.context("opened stream missing")?.stream_epoch;
        let admission = Admission {
            sink: &sink,
            capacity: &capacity,
            taint: &taint,
            rate: &rate,
            stream_epoch,
        };

        ensure!(
            source
                .commit(admission.request("first", 1, &first, 1))
                .await?
                == SourceCommitOutcome::Accepted
        );
        let mut watcher = state.subscribe(&sink).await?;
        let unrelated_path = Path::parse("state://source-fault/unrelated")?;
        let mut unrelated = state.subscribe(&unrelated_path).await?;
        control.arm(mode);
        let error = source
            .commit(admission.request("event", 2, &payload, 2))
            .await
            .err()
            .context("injected commit unexpectedly succeeded")?;
        ensure!(
            matches!(error, SourceStoreError::Indeterminate(_)),
            "fault mode {mode} returned {error:?}"
        );
        ensure!(control.injected.load(Ordering::SeqCst) == 1);
        ensure!(matches!(
            watcher.try_recv(),
            Err(StateWatchError::Invalidated)
        ));
        ensure!(matches!(watcher.try_recv(), Err(StateWatchError::Closed)));
        ensure!(matches!(
            unrelated.try_recv(),
            Err(StateWatchError::Invalidated)
        ));
        ensure!(matches!(unrelated.try_recv(), Err(StateWatchError::Closed)));
        ensure!(state.read(&sink).await.is_err());
        ensure!(state.subscribe(&unrelated_path).await.is_err());
        ensure_state_fenced(&source, &sink).await?;
        ensure_state_fenced(&source, &unrelated_path).await?;
        ensure_facts_fenced(&facts)?;
        ensure!(matches!(fact_events.try_recv(), Err(TryRecvError::Closed)));
        ensure!(inspect(&source, "event", 2, stream_epoch).await.is_err());
        store.wait_idle().await;
        drop(source);
        drop(state);
        drop(facts);
        drop(store);

        // redb refuses another writer after failed commit. Reopen the real
        // file through the production constructor to exercise recovery.
        let recovered = RedbStore::open_with_history(&db_path, history)?;
        let (state, source) = recovered.state_backend().into_source_parts();
        let evidence = inspect(&source, "event", 2, stream_epoch).await?;
        match evidence {
            SourceClaimEvidence::Committed(receipt) if expected_committed => {
                ensure!(
                    receipt.installation_id == "installation"
                        && receipt.projection_id == "projection"
                        && receipt.event_id == "event"
                        && receipt.claim_id == SourceClaimId::from_bytes([2; 16])
                        && receipt.sink == sink
                        && receipt.received_at_ms == 100
                );
            }
            SourceClaimEvidence::Unproven if !expected_committed => {}
            other => anyhow::bail!("mode {mode} recovered unexpected evidence: {other:?}"),
        }
        ensure!(matches!(
            inspect(&source, "first", 1, stream_epoch).await?,
            SourceClaimEvidence::Committed(_)
        ));
        let observed = state.read(&sink).await?;
        ensure!(
            observed
                .as_ref()
                .and_then(Value::as_list)
                .and_then(|items| items.first())
                == Some(if expected_committed { &payload } else { &first }),
            "mode {mode} recovered partial sink: {observed:?}"
        );
        if history == RedbHistory::Full {
            let entries = state
                .history(&StateHistoryQuery::new(sink.clone(), 0, i64::MAX))
                .await?
                .entries;
            ensure!(
                entries.len() == if expected_committed { 2 } else { 1 },
                "mode {mode} recovered partial history: {entries:?}"
            );
        }
        if !expected_committed {
            let gap = source
                .commit(admission.request("next", 4, &payload, 3))
                .await?;
            ensure!(
                gap == SourceCommitOutcome::Rejected(
                    xolotl_source::SourceCommitRejection::SequenceGap {
                        expected: 2,
                        seq: 3,
                    }
                )
            );
        }
        let retry = source
            .commit(admission.request("event", 3, &payload, 2))
            .await?;
        ensure!(
            retry
                == if expected_committed {
                    SourceCommitOutcome::Duplicate
                } else {
                    SourceCommitOutcome::Accepted
                },
            "mode {mode} retry gave {retry:?}"
        );
        match inspect(&source, "event", 3, stream_epoch).await? {
            SourceClaimEvidence::Unproven if expected_committed => {}
            SourceClaimEvidence::Committed(receipt) if !expected_committed => {
                ensure!(
                    receipt.event_id == "event"
                        && receipt.claim_id == SourceClaimId::from_bytes([3; 16])
                        && receipt.sink == sink
                        && receipt.received_at_ms == 100
                );
            }
            other => anyhow::bail!("mode {mode} retry left unexpected evidence: {other:?}"),
        }
        let next = source
            .commit(admission.request("next", 4, &payload, 3))
            .await?;
        ensure!(
            next == SourceCommitOutcome::Rejected(
                xolotl_source::SourceCommitRejection::RateLimited
            )
        );
        ensure!(
            state
                .read(&sink)
                .await?
                .as_ref()
                .and_then(Value::as_list)
                .and_then(|items| items.first())
                == Some(&payload)
        );
    }
    Ok(())
}

#[tokio::test]
async fn state_uncertain_commit_fences_all_shared_adapters() -> anyhow::Result<()> {
    for mode in [FAIL_BEFORE_WRITE, FAIL_AFTER_SYNC] {
        let directory = tempfile::tempdir()?;
        let control = Arc::new(FaultControl::default());
        let db_path = directory.path().join("state-fault.redb");
        let store = open_faulting_store(&db_path, RedbHistory::CurrentOnly, control.clone())?;
        let backend = store.state_backend();
        let other_backend = store.clone().state_backend();
        let facts = store.fact_store()?;
        let other_facts = store.clone().fact_store()?;
        facts.append(fact(0))?;
        let mut fact_events = facts.subscribe_facts();
        let mut other_fact_events = other_facts.subscribe_facts();
        let mut fact_receive = std::pin::pin!(fact_events.recv());
        let fact_wakes = pending_receive(fact_receive.as_mut())?;
        let independent = RedbStore::open(directory.path().join("independent.redb"))?;
        let independent_backend = independent.state_backend();
        let independent_facts = independent.fact_store()?;
        let path = Path::parse("state://fault/affected")?;
        let other = Path::parse("state://fault/unrelated")?;
        let mut affected = backend.subscribe(&path).await?;
        let mut unrelated = backend.subscribe(&other).await?;
        let affected_wakes = pending_state(&mut affected)?;
        let unrelated_wakes = pending_state(&mut unrelated)?;
        let mut independent_watch = independent_backend.subscribe(&path).await?;
        let mut independent_events = independent_facts.subscribe_facts();
        control.arm(mode);
        let failure = backend
            .write_set(&path, Value::integer(1))
            .await
            .err()
            .context("injected State commit unexpectedly succeeded")?;
        ensure!(matches!(failure.error, StateError::CommitUncertain(_)));
        ensure!(control.injected.load(Ordering::SeqCst) == 1);
        ensure!(matches!(
            affected.try_recv(),
            Err(StateWatchError::Invalidated)
        ));
        ensure!(matches!(affected.try_recv(), Err(StateWatchError::Closed)));
        ensure!(matches!(
            unrelated.try_recv(),
            Err(StateWatchError::Invalidated)
        ));
        ensure!(matches!(unrelated.try_recv(), Err(StateWatchError::Closed)));
        ensure!(affected_wakes.0.load(Ordering::SeqCst) > 0);
        ensure!(unrelated_wakes.0.load(Ordering::SeqCst) > 0);
        ensure!(fact_wakes.0.load(Ordering::SeqCst) > 0);
        ensure!(matches!(
            tokio::time::timeout(Duration::from_secs(5), fact_receive).await?,
            Err(tokio::sync::broadcast::error::RecvError::Closed)
        ));
        ensure!(matches!(
            other_fact_events.try_recv(),
            Err(TryRecvError::Closed)
        ));
        ensure_state_fenced(&backend, &path).await?;
        ensure_state_fenced(&other_backend, &other).await?;
        ensure_facts_fenced(&facts)?;
        ensure_facts_fenced(&other_facts)?;
        independent_backend
            .write_set(&path, Value::integer(9))
            .await?;
        ensure!(independent_backend.read(&path).await? == Some(Value::integer(9)));
        ensure!(matches!(
            independent_watch.try_recv()?,
            xolotl_state::StateEvent::Set { .. }
        ));
        independent_facts.append(fact(0))?;
        ensure!(independent_events.try_recv()?.id == fact(0).id);
        ensure!(independent_facts.observed_cursor()? == 1);
        store.wait_idle().await;
        drop(backend);
        drop(other_backend);
        drop(facts);
        drop(other_facts);
        drop(store);
        let recovered = RedbStore::open(&db_path)?;
        let recovered_backend = recovered.state_backend();
        ensure!(
            recovered_backend.read(&path).await?
                == (mode == FAIL_AFTER_SYNC).then(|| Value::integer(1))
        );
        let recovered_facts = recovered.fact_store()?;
        ensure!(recovered_facts.get(fact(0).id)? == Some(fact(0)));
        ensure!(recovered_facts.observed_cursor()? == 1);
        let mut recovered_watch = recovered_backend.subscribe(&other).await?;
        let mut recovered_events = recovered_facts.subscribe_facts();
        recovered_backend
            .write_set(&other, Value::integer(2))
            .await?;
        ensure!(matches!(
            recovered_watch.try_recv()?,
            xolotl_state::StateEvent::Set { .. }
        ));
        recovered_facts.append(fact(1))?;
        ensure!(recovered_events.try_recv()?.id == fact(1).id);
    }
    Ok(())
}

#[tokio::test]
async fn fact_uncertain_commit_and_panic_fence_state_until_reopen() -> anyhow::Result<()> {
    for mode in [FAIL_BEFORE_WRITE, FAIL_AFTER_SYNC, PANIC_AFTER_SYNC] {
        let directory = tempfile::tempdir()?;
        let db_path = directory.path().join("fact-state-fault.redb");
        let control = Arc::new(FaultControl::default());
        let store = open_faulting_store(&db_path, RedbHistory::Full, control.clone())?;
        let backend = store.state_backend();
        let other_backend = store.clone().state_backend();
        let facts = store.fact_store()?;
        let path = Path::parse("state://fact-fault/value")?;
        let other = Path::parse("state://fact-fault/unrelated")?;
        backend.write_set(&path, Value::integer(7)).await?;
        facts.append(fact(0))?;
        let mut watcher = backend.subscribe(&path).await?;
        let mut unrelated = other_backend.subscribe(&other).await?;
        let watcher_wakes = pending_state(&mut watcher)?;
        let unrelated_wakes = pending_state(&mut unrelated)?;
        let mut fact_events = facts.subscribe_facts();
        let mut fact_receive = std::pin::pin!(fact_events.recv());
        let fact_wakes = pending_receive(fact_receive.as_mut())?;

        control.arm(mode);
        let result = catch_unwind(AssertUnwindSafe(|| facts.append(fact(1))));
        match result {
            Err(_) if mode == PANIC_AFTER_SYNC => {}
            Ok(Err(error)) if mode != PANIC_AFTER_SYNC => {
                ensure!(error.kind() == FactErrorKind::CommitOutcomeUnknown);
            }
            other => anyhow::bail!("fault mode {mode} returned {other:?}"),
        }
        ensure!(control.injected.load(Ordering::SeqCst) == 1);
        ensure!(watcher_wakes.0.load(Ordering::SeqCst) > 0);
        ensure!(unrelated_wakes.0.load(Ordering::SeqCst) > 0);
        ensure!(fact_wakes.0.load(Ordering::SeqCst) > 0);
        ensure!(matches!(
            tokio::time::timeout(Duration::from_secs(5), watcher.recv()).await?,
            Err(StateWatchError::Invalidated)
        ));
        ensure!(matches!(watcher.try_recv(), Err(StateWatchError::Closed)));
        ensure!(matches!(
            unrelated.try_recv(),
            Err(StateWatchError::Invalidated)
        ));
        ensure!(matches!(unrelated.try_recv(), Err(StateWatchError::Closed)));
        ensure!(matches!(
            tokio::time::timeout(Duration::from_secs(5), fact_receive).await?,
            Err(tokio::sync::broadcast::error::RecvError::Closed)
        ));
        ensure_state_fenced(&backend, &path).await?;
        ensure_state_fenced(&other_backend, &other).await?;
        ensure!(
            backend
                .history(&StateHistoryQuery::new(path.clone(), 0, i64::MAX))
                .await
                .is_err()
        );
        ensure_facts_fenced(&facts)?;
        store.wait_idle().await;
        drop(backend);
        drop(other_backend);
        drop(facts);
        drop(store);

        let recovered = RedbStore::open_with_history(&db_path, RedbHistory::Full)?;
        let recovered_backend = recovered.state_backend();
        ensure!(recovered_backend.read(&path).await? == Some(Value::integer(7)));
        ensure!(
            recovered_backend
                .history(&StateHistoryQuery::new(path.clone(), 0, i64::MAX))
                .await?
                .entries
                .len()
                == 1
        );
        let recovered_facts = recovered.fact_store()?;
        let committed = mode != FAIL_BEFORE_WRITE;
        ensure!(recovered_facts.get(fact(1).id)? == committed.then(|| fact(1)));
        ensure!(recovered_facts.observed_cursor()? == if committed { 2 } else { 1 });
        let mut recovered_watch = recovered_backend.subscribe(&other).await?;
        let mut recovered_events = recovered_facts.subscribe_facts();
        recovered_backend
            .write_set(&other, Value::integer(8))
            .await?;
        ensure!(matches!(
            recovered_watch.try_recv()?,
            xolotl_state::StateEvent::Set { .. }
        ));
        recovered_facts.append(fact(2))?;
        ensure!(recovered_events.try_recv()?.id == fact(2).id);
    }
    Ok(())
}

#[tokio::test]
#[cfg(any(feature = "console", feature = "gateway", feature = "federation"))]
async fn shared_commit_fault_fences_held_service_read_adapters() -> anyhow::Result<()> {
    #[cfg(feature = "console")]
    use xolotl_console::session_store::{ConsoleSessionPolicy, ConsoleSessionStore};
    #[cfg(feature = "federation")]
    use xolotl_federation::{
        ExportName, FederationManagement, FederationNodeId, HostedSubject, InvitationId,
        PublicStreamView, RequestId, StreamId, StreamRef, SubjectIssuerId, SubscriptionId,
        SubscriptionRef,
    };
    #[cfg(feature = "gateway")]
    use xolotl_gateway::{GatewayIdempotencyLimits, GatewayIdempotencyStore};

    for fact_origin in [false, true] {
        let directory = tempfile::tempdir()?;
        let db_path = directory.path().join("service-fault.redb");
        let control = Arc::new(FaultControl::default());
        let store = open_faulting_store(&db_path, RedbHistory::Full, control.clone())?;
        let backend = store.state_backend();
        let facts = store.fact_store()?;
        let path = Path::parse("state://service-fault/value")?;
        backend.write_set(&path, Value::integer(1)).await?;

        #[cfg(feature = "console")]
        let console = {
            let console = store.console_session_store(ConsoleSessionPolicy::default())?;
            ensure!(console.get("missing-session").await?.is_none());
            console
        };
        #[cfg(feature = "gateway")]
        let gateway = {
            let gateway = store.gateway_idempotency_store(GatewayIdempotencyLimits::default())?;
            ensure!(gateway.observe(&"a".repeat(64)).await?.is_none());
            gateway.usage().await?;
            gateway
        };
        #[cfg(feature = "federation")]
        let (federation, projection, public, guest, spec, local, stream) = {
            let local = FederationNodeId::from_bytes([1; 48]);
            let publisher = FederationNodeId::from_bytes([2; 48]);
            let stream = StreamRef {
                publisher,
                id: StreamId::from_bytes([3; 16]),
            };
            let federation = store.federation_store(local)?;
            ensure!(federation.peer(publisher)?.is_none());
            let projection = store.federation_state_projection(local)?;
            projection.high_watermark()?;
            let public = store.public_follower_store(local)?;
            public.observe(&PublicStreamView {
                stream,
                export: ExportName::new("public")?,
                policy_revision: 1,
                head: None,
                minimum_available: 1,
                max_read_records: 1,
                max_read_bytes: 512 * 1024,
            })?;
            ensure!(public.inspect(stream)?.is_some());
            ensure!(public.read_inbox(stream, None, 1, 1024)?.records.is_empty());
            let guest = store.guest_follower_store(local)?;
            let spec = crate::GuestFollowSpec {
                stream,
                subscription: SubscriptionRef {
                    subscriber: local,
                    id: SubscriptionId::from_bytes([4; 16]),
                },
                invitation: InvitationId::from_bytes([5; 16]),
                invitation_revision: 1,
                redeem_request: RequestId::from_bytes([6; 16]),
                open_request: RequestId::from_bytes([7; 16]),
                subject: HostedSubject {
                    issuer: SubjectIssuerId::from_bytes([8; 48]),
                    namespace: "people".into(),
                    subject: "guest".into(),
                },
                max_inbox_records: 2,
                max_inbox_bytes: 512 * 1024,
            };
            guest.prepare(&spec)?;
            guest.inspect(&spec)?;
            ensure!(guest.read_inbox(&spec, None, 1, 1024)?.records.is_empty());
            (federation, projection, public, guest, spec, local, stream)
        };

        control.arm(FAIL_AFTER_SYNC);
        if fact_origin {
            ensure!(matches!(
                facts.append(fact(0)),
                Err(error) if error.kind() == FactErrorKind::CommitOutcomeUnknown
            ));
        } else {
            ensure!(backend.write_set(&path, Value::integer(2)).await.is_err());
        }
        ensure!(control.injected.load(Ordering::SeqCst) == 1);
        #[cfg(feature = "console")]
        {
            ensure!(console.get("missing-session").await.is_err());
            ensure!(console.policy() == ConsoleSessionPolicy::default());
            ensure!(
                store
                    .console_session_store(ConsoleSessionPolicy::default())
                    .is_err()
            );
            drop(console);
        }
        #[cfg(feature = "gateway")]
        {
            ensure!(gateway.observe(&"a".repeat(64)).await.is_err());
            ensure!(gateway.usage().await.is_err());
            ensure!(gateway.limits() == GatewayIdempotencyLimits::default());
            ensure!(
                store
                    .gateway_idempotency_store(GatewayIdempotencyLimits::default())
                    .is_err()
            );
            drop(gateway);
        }
        #[cfg(feature = "federation")]
        {
            let local_stream = StreamRef {
                publisher: local,
                id: stream.id,
            };
            ensure!(federation.peer(stream.publisher).is_err());
            ensure!(projection.high_watermark().is_err());
            ensure!(
                projection
                    .history_page(&path, 0, i64::MAX - 1, None)
                    .is_err()
            );
            ensure!(projection.cursor(local_stream, &path).is_err());
            ensure!(public.inspect(stream).is_err());
            ensure!(public.read_inbox(stream, None, 1, 1024).is_err());
            ensure!(guest.inspect(&spec).is_err());
            ensure!(guest.read_inbox(&spec, None, 1, 1024).is_err());
            ensure!(public.local_node() == local && guest.local_node() == local);
            ensure!(store.federation_store(local).is_err());
            drop(federation);
            drop(projection);
            drop(public);
            drop(guest);
        }
        store.wait_idle().await;
        drop(backend);
        drop(facts);
        drop(store);

        let recovered = RedbStore::open_with_history(&db_path, RedbHistory::Full)?;
        #[cfg(feature = "console")]
        ensure!(
            recovered
                .console_session_store(ConsoleSessionPolicy::default())?
                .get("missing-session")
                .await?
                .is_none()
        );
        #[cfg(feature = "gateway")]
        ensure!(
            recovered
                .gateway_idempotency_store(GatewayIdempotencyLimits::default())?
                .observe(&"a".repeat(64))
                .await?
                .is_none()
        );
        #[cfg(feature = "federation")]
        {
            recovered
                .federation_state_projection(local)?
                .high_watermark()?;
            ensure!(
                recovered
                    .public_follower_store(local)?
                    .inspect(stream)?
                    .is_some()
            );
            recovered.guest_follower_store(local)?.inspect(&spec)?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn state_post_sync_failure_requires_reopen_before_reconciliation() -> anyhow::Result<()> {
    for history in [RedbHistory::CurrentOnly, RedbHistory::Full] {
        let directory = tempfile::tempdir()?;
        let db_path = directory.path().join("state-reconciliation.redb");
        let control = Arc::new(FaultControl::default());
        let backend = open_faulting(&db_path, history, control.clone())?;
        let path = Path::parse("state://fault/reconciliation")?;
        let initial = StateObservation {
            value: Some(Value::string("before".into())),
            taint: TaintSet::of(TaintSource::Protected { path: path.clone() }),
        };
        let replacement = StateObservation {
            value: Some(Value::string("after".into())),
            taint: TaintSet::of(TaintSource::ModelOutput),
        };
        backend
            .write_set_tainted(
                &path,
                initial.value.clone().context("seed value missing")?,
                initial.taint.clone(),
            )
            .await?;
        ensure!(backend.read_tainted(&path).await? == initial);

        control.arm(FAIL_AFTER_SYNC);
        let failure = backend
            .write_set_tainted(
                &path,
                replacement
                    .value
                    .clone()
                    .context("replacement value missing")?,
                replacement.taint.clone(),
            )
            .await
            .err()
            .context("post-sync State commit unexpectedly succeeded")?;
        ensure!(matches!(failure.error, StateError::CommitUncertain(_)));
        ensure!(control.injected.load(Ordering::SeqCst) == 1);
        let mut observed = replacement.taint.clone();
        observed.union(&initial.taint);
        ensure!(
            failure.taint == observed,
            "post-sync failure changed observed provenance ({history:?}): {:?}",
            failure.taint.sources()
        );

        ensure_state_fenced(&backend, &path).await?;
        drop(backend);

        let recovered = RedbStore::open_with_history(&db_path, history)?;
        ensure!(
            recovered.state_backend().read_tainted(&path).await? == replacement,
            "an uncertain post-sync commit was durable despite any older live observation"
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_and_delivery_follow_commit_order() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let control = Arc::new(FaultControl::default());
    let backend = Arc::new(open_faulting(
        &directory.path().join("state-order.redb"),
        RedbHistory::CurrentOnly,
        control.clone(),
    )?);
    let path = Path::parse("state://order/value")?;
    let mut early = backend.subscribe(&path).await?;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    control.pause_after_sync(entered_tx, release_rx);
    let first_backend = Arc::clone(&backend);
    let first_path = path.clone();
    let first = tokio::spawn(async move {
        first_backend
            .write_set(&first_path, Value::integer(1))
            .await
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || entered_rx.recv()),
    )
    .await???;

    let later_backend = Arc::clone(&backend);
    let later_path = path.clone();
    let mut later = tokio::spawn(async move { later_backend.subscribe(&later_path).await });
    ensure!(
        tokio::time::timeout(Duration::from_millis(30), &mut later)
            .await
            .is_err(),
        "registration crossed an in-progress commit"
    );
    let second_backend = Arc::clone(&backend);
    let second_path = path.clone();
    let second = tokio::spawn(async move {
        second_backend
            .write_set(&second_path, Value::integer(2))
            .await
    });
    release_tx.send(())?;
    first.await??;
    let mut later = later.await??;
    second.await??;

    let first_event = early.try_recv()?;
    let second_event = early.try_recv()?;
    ensure!(
        matches!(first_event, xolotl_state::StateEvent::Set { value, .. } if value == Value::integer(1))
    );
    ensure!(
        matches!(second_event, xolotl_state::StateEvent::Set { value, .. } if value == Value::integer(2))
    );
    ensure!(
        matches!(later.try_recv()?, xolotl_state::StateEvent::Set { value, .. } if value == Value::integer(2))
    );
    ensure!(matches!(later.try_recv(), Err(StateWatchError::Empty)));
    Ok(())
}
