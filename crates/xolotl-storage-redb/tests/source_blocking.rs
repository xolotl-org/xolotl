use anyhow::{Context as _, ensure};
use std::collections::VecDeque;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, AtomicU8, AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant};
use xolotl_kernel::host::{BlockingJob, BlockingSpawnError, BlockingSpawner};
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, SourceClaim, SourceClaimEvidence,
    SourceClaimId, SourceClaimInspection, SourceCommit, SourceCommitOutcome, SourceEventCommit,
    SourceEventDecisionInspection, SourceEventMaintenance, SourceEvidenceInspection,
    SourceMaintenance, SourceStoreError, SourceStreamLifecycle, SourceStreamOpen,
    SourceStreamOpenOutcome, SourceStreamPosition, SourceStreamRetire, SourceStreamRetireOutcome,
    SourceStreamScope,
};
use xolotl_storage_redb::{RedbOptions, RedbStateBackend, RedbStore};
use xolotl_types::{
    Path, Purity, TaintSet, Transport, TrustLevel, Value,
    external::{
        EventSource, ExternalInstallationDef, ExternalProjectionDef, OverflowPolicy, Role,
        StreamCapacity,
    },
};

#[derive(Clone, Copy)]
#[repr(u8)]
enum Mode {
    Thread,
    Reject,
    Hold,
    Discard,
}

struct ControlledSpawner {
    mode: AtomicU8,
    calls: AtomicUsize,
    held: Mutex<VecDeque<BlockingJob>>,
    worker_thread: Arc<Mutex<Option<std::thread::ThreadId>>>,
}

impl ControlledSpawner {
    fn new() -> Self {
        Self {
            mode: AtomicU8::new(Mode::Thread as u8),
            calls: AtomicUsize::new(0),
            held: Mutex::new(VecDeque::new()),
            worker_thread: Arc::new(Mutex::new(None)),
        }
    }

    fn set_mode(&self, mode: Mode) {
        self.mode.store(mode as u8, Ordering::SeqCst);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn run_held(&self) -> anyhow::Result<()> {
        let job = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop_front()
            .context("accepted Source job missing")?;
        std::thread::spawn(job)
            .join()
            .map_err(|_panic| anyhow::anyhow!("Source worker panicked"))
    }
}

impl BlockingSpawner for ControlledSpawner {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match self.mode.load(Ordering::SeqCst) {
            value if value == Mode::Thread as u8 => {
                let worker_thread = Arc::clone(&self.worker_thread);
                std::thread::spawn(move || {
                    *worker_thread
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) =
                        Some(std::thread::current().id());
                    job();
                });
                Ok(())
            }
            value if value == Mode::Reject as u8 => Err(BlockingSpawnError::AtCapacity),
            value if value == Mode::Hold as u8 => {
                self.held
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push_back(job);
                Ok(())
            }
            value if value == Mode::Discard as u8 => {
                drop(job);
                Ok(())
            }
            _ => Err(BlockingSpawnError::Unavailable),
        }
    }
}

struct ThreadWake(std::thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn poll_once<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::new(ThreadWake(std::thread::current())));
    future.poll(&mut Context::from_waker(&waker))
}

fn block_on<F: Future>(future: F) -> anyhow::Result<F::Output> {
    let mut future = Box::pin(future);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Poll::Ready(result) = poll_once(future.as_mut()) {
            return Ok(result);
        }
        ensure!(Instant::now() < deadline, "Source job did not complete");
        std::thread::park_timeout(Duration::from_millis(1));
    }
}

fn run<T>(future: impl Future<Output = Result<T, SourceStoreError>>) -> anyhow::Result<T> {
    Ok(block_on(future)??)
}

struct Fixture {
    _dir: tempfile::TempDir,
    source: Arc<RedbStateBackend>,
    sink: Path,
    capacity: StreamCapacity,
    scope_epoch: u64,
}

#[test]
fn queued_commit_samples_after_maintenance_not_when_the_host_received_it() -> anyhow::Result<()> {
    let spawner = Arc::new(ControlledSpawner::new());
    let fixture = fixture(Arc::clone(&spawner))?;
    let payload = Value::integer(42);
    let taint = TaintSet::pristine();
    let time = Arc::new(AtomicI64::new(100));
    let samples = Arc::new(AtomicUsize::new(0));
    let clock: Arc<dyn xolotl_source::SourceClock> = {
        let time = Arc::clone(&time);
        let samples = Arc::clone(&samples);
        Arc::new(move || {
            samples.fetch_add(1, Ordering::SeqCst);
            time.load(Ordering::SeqCst)
        })
    };
    let old = claim(fixture.scope_epoch, "queued", 1, None);
    let mut initial = commit(&fixture, old, &payload, &taint, None);
    initial.decision_clock = Arc::clone(&clock);
    ensure!(run(fixture.source.commit(initial))? == SourceCommitOutcome::Accepted);
    let pending_claim = claim(fixture.scope_epoch, "queued", 2, None);
    let mut pending_request = commit(&fixture, pending_claim, &payload, &taint, None);
    pending_request.decision_clock = Arc::clone(&clock);
    spawner.set_mode(Mode::Hold);
    let mut pending = fixture.source.commit(pending_request);
    ensure!(poll_once(pending.as_mut()).is_pending());
    ensure!(
        samples.load(Ordering::SeqCst) == 1,
        "queued work must not read the clock"
    );
    time.store(2000, Ordering::SeqCst);
    spawner.set_mode(Mode::Thread);
    ensure!(
        run(fixture.source.maintain(SourceMaintenance {
            decision_clock: Arc::clone(&clock),
            limit: NonZeroUsize::MIN,
        }))?
        .removed
            == 1
    );
    time.store(2100, Ordering::SeqCst);
    spawner.run_held()?;
    ensure!(run(pending)? == SourceCommitOutcome::Accepted);
    ensure!(samples.load(Ordering::SeqCst) == 3);
    ensure!(
        matches!(evidence(&fixture.source, pending_claim)?, SourceClaimEvidence::Committed(receipt) if receipt.received_at_ms == 100)
    );
    time.store(3000, Ordering::SeqCst);
    let mut retry = commit(
        &fixture,
        claim(fixture.scope_epoch, "queued", 3, None),
        &payload,
        &taint,
        None,
    );
    retry.decision_clock = Arc::clone(&clock);
    ensure!(run(fixture.source.commit(retry))? == SourceCommitOutcome::Duplicate);
    Ok(())
}

fn fixture(spawner: Arc<ControlledSpawner>) -> anyhow::Result<Fixture> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open_with_options_and_spawner(
        dir.path().join("state.redb"),
        RedbOptions::default(),
        spawner,
    )?;
    let (_state, source) = store.state_backend().into_source_parts();
    let sink = Path::parse("state://events/external/installation/source")?;
    let capacity = StreamCapacity {
        max_events: 8,
        on_overflow: OverflowPolicy::DropOldest,
    };
    let definition = ExternalInstallationDef {
        id: "installation".into(),
        platform: "test".into(),
        transport: Transport::Grpc { endpoint: None },
        trust: TrustLevel::Full,
        config_schema: Value::map(Default::default()),
        config: Value::null(),
        projections: vec![ExternalProjectionDef {
            id: "source".into(),
            role: Role::Source,
            namespace: None,
            provides: vec![],
            emits: Some(EventSource {
                sink: sink.clone(),
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 128,
                capacity: capacity.clone(),
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            version: 1,
        }],
        version: 0,
    };
    let ExternalInstallationMutation::Applied(Some(record)) =
        run(source.compare_install(definition, None))?
    else {
        anyhow::bail!("Source installation was not applied")
    };
    Ok(Fixture {
        _dir: dir,
        source,
        sink,
        capacity,
        scope_epoch: record
            .scope_epoch("source")
            .context("Source scope missing")?,
    })
}

fn stream(scope_epoch: u64) -> SourceStreamScope<'static> {
    SourceStreamScope {
        installation_id: "installation",
        projection_id: "source",
        scope_epoch,
        stream_id: "ordered",
    }
}

fn claim<'a>(
    scope_epoch: u64,
    event_id: &'a str,
    id: u8,
    stream_epoch: Option<u64>,
) -> SourceClaim<'a> {
    SourceClaim {
        installation_id: "installation",
        projection_id: "source",
        scope_epoch,
        stream_epoch,
        event_id,
        claim_id: SourceClaimId::from_bytes([id; 16]),
    }
}

fn commit<'a>(
    fixture: &'a Fixture,
    claim: SourceClaim<'a>,
    payload: &'a Value,
    taint: &'a TaintSet,
    position: Option<SourceStreamPosition<'a>>,
) -> SourceCommit<'a> {
    SourceCommit {
        claim,
        received_at_ms: 100,
        decision_clock: std::sync::Arc::new({
            let decision_at_ms = 100;
            move || decision_at_ms
        }),
        dedupe_window_ms: 1_000,
        sink: &fixture.sink,
        capacity: &fixture.capacity,
        max_inline_payload_bytes: 128,
        payload,
        taint,
        stream: position,
        rate_limit: None,
    }
}

fn evidence(
    source: &RedbStateBackend,
    claim: SourceClaim<'_>,
) -> anyhow::Result<SourceClaimEvidence> {
    run(source.inspect(SourceEvidenceInspection { claim }))
}

#[test]
fn source_ingress_runs_on_an_explicit_non_tokio_host() -> anyhow::Result<()> {
    let spawner = Arc::new(ControlledSpawner::new());
    let fixture = fixture(Arc::clone(&spawner))?;
    let baseline = spawner.calls();
    let scope = stream(fixture.scope_epoch);
    let first = run(fixture.source.inspect_stream(scope))?.context("scope inactive")?;
    let SourceStreamOpenOutcome::Opened(opened) =
        run(fixture.source.open_stream(SourceStreamOpen {
            stream: scope,
            open_id: "open-1",
            expected_revision: first.revision,
        }))?
    else {
        anyhow::bail!("stream did not open")
    };
    let epoch = opened.active.context("opened stream missing")?.stream_epoch;
    let payload = Value::string("payload".into());
    let taint = TaintSet::pristine();
    let claim = claim(fixture.scope_epoch, "event-1", 1, Some(epoch));
    ensure!(
        run(fixture.source.commit(commit(
            &fixture,
            claim,
            &payload,
            &taint,
            Some(SourceStreamPosition {
                stream_id: "ordered",
                stream_epoch: epoch,
                seq: 1
            }),
        )))? == SourceCommitOutcome::Accepted
    );
    let after = run(fixture.source.inspect_stream(scope))?.context("scope inactive")?;
    ensure!(after.active.context("stream disappeared")?.last_seq == 1);
    ensure!(matches!(
        evidence(&fixture.source, claim)?,
        SourceClaimEvidence::Committed(_)
    ));
    ensure!(matches!(
        run(fixture.source.retire_stream(SourceStreamRetire {
            stream: scope,
            stream_epoch: epoch,
        }))?,
        SourceStreamRetireOutcome::Retired { .. }
    ));
    ensure!(
        run(fixture.source.inspect_stream(scope))?
            .context("scope inactive")?
            .active
            .is_none()
    );
    ensure!(spawner.calls() == baseline + 7);
    ensure!(
        *spawner
            .worker_thread
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            != Some(std::thread::current().id())
    );
    Ok(())
}

#[test]
fn source_admission_is_lazy_and_rejection_cannot_write() -> anyhow::Result<()> {
    let spawner = Arc::new(ControlledSpawner::new());
    let fixture = fixture(Arc::clone(&spawner))?;
    let baseline = spawner.calls();
    let payload = Value::string("payload".into());
    let taint = TaintSet::pristine();
    let accepted = claim(fixture.scope_epoch, "accepted", 1, None);
    let rejected = claim(fixture.scope_epoch, "rejected", 2, None);
    let mut pending = fixture
        .source
        .commit(commit(&fixture, accepted, &payload, &taint, None));
    ensure!(spawner.calls() == baseline);
    spawner.set_mode(Mode::Hold);
    ensure!(matches!(poll_once(pending.as_mut()), Poll::Pending));
    ensure!(spawner.calls() == baseline + 1);
    spawner.set_mode(Mode::Reject);
    let rejection = block_on(
        fixture
            .source
            .commit(commit(&fixture, rejected, &payload, &taint, None)),
    )?
    .err()
    .context("capacity rejection unexpectedly succeeded")?;
    ensure!(matches!(rejection, SourceStoreError::Aborted(_)));
    spawner.set_mode(Mode::Thread);
    ensure!(evidence(&fixture.source, rejected)? == SourceClaimEvidence::Unproven);
    ensure!(evidence(&fixture.source, accepted)? == SourceClaimEvidence::Unproven);
    drop(pending);
    drop(payload);
    drop(taint);
    spawner.run_held()?;
    ensure!(matches!(
        evidence(&fixture.source, accepted)?,
        SourceClaimEvidence::Committed(_)
    ));
    Ok(())
}

#[test]
fn detached_stream_controls_complete_and_discarded_jobs_are_indeterminate() -> anyhow::Result<()> {
    let spawner = Arc::new(ControlledSpawner::new());
    let fixture = fixture(Arc::clone(&spawner))?;
    let scope = stream(fixture.scope_epoch);
    let current = run(fixture.source.inspect_stream(scope))?.context("scope inactive")?;
    spawner.set_mode(Mode::Hold);
    let mut opening = fixture.source.open_stream(SourceStreamOpen {
        stream: scope,
        open_id: "open-1",
        expected_revision: current.revision,
    });
    ensure!(matches!(poll_once(opening.as_mut()), Poll::Pending));
    drop(opening);
    spawner.run_held()?;
    spawner.set_mode(Mode::Thread);
    let opened = run(fixture.source.inspect_stream(scope))?.context("scope inactive")?;
    let epoch = opened
        .active
        .context("detached open did not commit")?
        .stream_epoch;

    spawner.set_mode(Mode::Reject);
    let rejected = block_on(fixture.source.retire_stream(SourceStreamRetire {
        stream: scope,
        stream_epoch: epoch,
    }))?
    .err()
    .context("rejected retirement unexpectedly succeeded")?;
    ensure!(matches!(rejected, SourceStoreError::Aborted(_)));
    spawner.set_mode(Mode::Thread);
    ensure!(
        run(fixture.source.inspect_stream(scope))?
            .context("scope inactive")?
            .active
            .context("rejected retirement changed the stream")?
            .stream_epoch
            == epoch
    );

    spawner.set_mode(Mode::Hold);
    let mut retiring = fixture.source.retire_stream(SourceStreamRetire {
        stream: scope,
        stream_epoch: epoch,
    });
    ensure!(matches!(poll_once(retiring.as_mut()), Poll::Pending));
    drop(retiring);
    spawner.run_held()?;
    spawner.set_mode(Mode::Thread);
    ensure!(
        run(fixture.source.inspect_stream(scope))?
            .context("scope inactive")?
            .active
            .is_none()
    );

    spawner.set_mode(Mode::Discard);
    let lost = block_on(fixture.source.open_stream(SourceStreamOpen {
        stream: scope,
        open_id: "discarded-open",
        expected_revision: opened.revision + 1,
    }))?
    .err()
    .context("discarded worker unexpectedly succeeded")?;
    ensure!(matches!(lost, SourceStoreError::Indeterminate(_)));
    let payload = Value::string("payload".into());
    let taint = TaintSet::pristine();
    let lost = block_on(fixture.source.commit(commit(
        &fixture,
        claim(fixture.scope_epoch, "discarded-event", 3, None),
        &payload,
        &taint,
        None,
    )))?
    .err()
    .context("discarded event worker unexpectedly succeeded")?;
    ensure!(matches!(lost, SourceStoreError::Indeterminate(_)));
    Ok(())
}

#[test]
fn source_management_evidence_and_maintenance_run_on_a_non_tokio_host() -> anyhow::Result<()> {
    let spawner = Arc::new(ControlledSpawner::new());
    let fixture = fixture(Arc::clone(&spawner))?;
    let baseline = spawner.calls();
    let original = run(fixture.source.load_installation("installation"))?
        .context("installed Source missing")?;
    ensure!(spawner.calls() == baseline + 1);
    ensure!(
        run(fixture.source.list_installations(None, NonZeroUsize::MIN))? == vec![original.clone()]
    );
    ensure!(spawner.calls() == baseline + 2);

    let payload = Value::string("payload".into());
    let taint = TaintSet::pristine();
    let claim = claim(fixture.scope_epoch, "audited", 9, None);
    ensure!(
        run(fixture
            .source
            .commit(commit(&fixture, claim, &payload, &taint, None)))?
            == SourceCommitOutcome::Accepted
    );
    ensure!(spawner.calls() == baseline + 3);
    ensure!(matches!(
        evidence(&fixture.source, claim)?,
        SourceClaimEvidence::Committed(_)
    ));
    ensure!(spawner.calls() == baseline + 4);
    ensure!(matches!(
        run(fixture
            .source
            .inspect_event(SourceEventDecisionInspection {
                installation_id: "installation",
                projection_id: "source",
                scope_epoch: fixture.scope_epoch,
                stream_epoch: None,
                event_id: "audited",
            }))?,
        SourceClaimEvidence::Committed(receipt) if receipt.claim_id == claim.claim_id
    ));
    ensure!(spawner.calls() == baseline + 5);

    let maintenance = run(fixture.source.maintain(SourceMaintenance {
        decision_clock: std::sync::Arc::new({
            let decision_at_ms = 2_000;
            move || decision_at_ms
        }),
        limit: NonZeroUsize::MIN,
    }))?;
    ensure!(maintenance.examined == 1 && maintenance.removed == 1);
    ensure!(spawner.calls() == baseline + 6);
    ensure!(evidence(&fixture.source, claim)? == SourceClaimEvidence::Unproven);

    let mut definition = original.definition.clone();
    definition.config = Value::string("updated".into());
    let ExternalInstallationMutation::Applied(Some(updated)) = run(fixture
        .source
        .compare_install(definition, Some(original.revision())))?
    else {
        anyhow::bail!("Source installation update was not applied")
    };
    ensure!(updated.revision().version == original.revision().version + 1);
    ensure!(updated.scope_epoch("source") != original.scope_epoch("source"));
    ensure!(run(fixture.source.load_installation("installation"))? == Some(updated.clone()));
    ensure!(
        run(fixture
            .source
            .compare_retire("installation", original.revision()))?
            == ExternalInstallationMutation::Conflict {
                current: Some(updated.revision())
            }
    );
    ensure!(
        run(fixture
            .source
            .compare_retire("installation", updated.revision()))?
            == ExternalInstallationMutation::Applied(None)
    );
    ensure!(run(fixture.source.load_installation("installation"))?.is_none());
    ensure!(run(fixture.source.list_installations(None, NonZeroUsize::MIN))?.is_empty());
    ensure!(spawner.calls() == baseline + 13);
    Ok(())
}

#[test]
fn installation_mutation_is_lazy_and_detached_writes_complete() -> anyhow::Result<()> {
    let spawner = Arc::new(ControlledSpawner::new());
    let fixture = fixture(Arc::clone(&spawner))?;
    let original = run(fixture.source.load_installation("installation"))?
        .context("installed Source missing")?;
    let baseline = spawner.calls();
    let mut definition = original.definition.clone();
    definition.config = Value::string("updated".into());
    let mut rejected = fixture
        .source
        .compare_install(definition.clone(), Some(original.revision()));
    ensure!(spawner.calls() == baseline);
    spawner.set_mode(Mode::Reject);
    let error = block_on(rejected.as_mut())?
        .err()
        .context("installation mutation rejection unexpectedly succeeded")?;
    ensure!(matches!(error, SourceStoreError::Aborted(_)));
    spawner.set_mode(Mode::Thread);
    ensure!(run(fixture.source.load_installation("installation"))? == Some(original.clone()));

    spawner.set_mode(Mode::Hold);
    let mut accepted = fixture
        .source
        .compare_install(definition, Some(original.revision()));
    ensure!(matches!(poll_once(accepted.as_mut()), Poll::Pending));
    drop(accepted);
    spawner.run_held()?;
    spawner.set_mode(Mode::Thread);
    let updated = run(fixture.source.load_installation("installation"))?
        .context("detached installation mutation did not commit")?;
    ensure!(updated.revision().version == original.revision().version + 1);
    ensure!(updated.definition.config == Value::string("updated".into()));

    spawner.set_mode(Mode::Reject);
    let error = block_on(
        fixture
            .source
            .compare_retire("installation", updated.revision()),
    )?
    .err()
    .context("installation retirement rejection unexpectedly succeeded")?;
    ensure!(matches!(error, SourceStoreError::Aborted(_)));
    spawner.set_mode(Mode::Thread);
    ensure!(run(fixture.source.load_installation("installation"))? == Some(updated.clone()));
    spawner.set_mode(Mode::Hold);
    let mut retiring = fixture
        .source
        .compare_retire("installation", updated.revision());
    ensure!(matches!(poll_once(retiring.as_mut()), Poll::Pending));
    drop(retiring);
    spawner.run_held()?;
    spawner.set_mode(Mode::Thread);
    ensure!(run(fixture.source.load_installation("installation"))?.is_none());
    Ok(())
}
