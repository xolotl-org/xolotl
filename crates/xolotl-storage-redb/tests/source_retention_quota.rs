use anyhow::{Context, ensure};
use std::{num::NonZeroUsize, sync::Arc};
use tokio::sync::Barrier;
use xolotl_source::{
    ExternalInstallationMutation, SourceClaim, SourceClaimEvidence, SourceClaimId, SourceCommit,
    SourceCommitOutcome, SourceCommitRejection, SourceEventDecisionInspection,
    SourceEvidenceInspection, SourceMaintenance, SourceStore, SourceStreamOpen,
    SourceStreamOpenOutcome, SourceStreamPosition, SourceStreamRetire, SourceStreamRetireOutcome,
    SourceStreamScope,
};
use xolotl_state::{
    Backend, InMemoryBackend, InMemoryOptions, MemoryHistory, StateEvent, StateHistoryQuery,
    StateWatchError,
};
use xolotl_storage_redb::{RedbHistory, RedbOptions, RedbStore};
use xolotl_types::{
    Path, Purity, TaintSet, Transport, TrustLevel, Value,
    external::{
        EventSource, ExternalInstallationDef, ExternalProjectionDef, OverflowPolicy, Role,
        SourceRateLimit, StreamCapacity,
    },
};

struct Fixture {
    installation: &'static str,
    epoch: u64,
    sink: Path,
    capacity: StreamCapacity,
    rate: Option<SourceRateLimit>,
    stream_epoch: Option<u64>,
}

#[derive(Clone, Copy)]
struct Event {
    id: &'static str,
    claim: u8,
    at: i64,
    seq: u64,
    payload: &'static str,
}

impl Event {
    fn new(id: &'static str, claim: u8, at: i64) -> Self {
        Self {
            id,
            claim,
            at,
            seq: u64::from(claim),
            payload: id,
        }
    }
}

impl Fixture {
    async fn install<S: SourceStore + ?Sized>(
        source: &S,
        installation: &'static str,
        rate: Option<SourceRateLimit>,
    ) -> anyhow::Result<Self> {
        let sink = Path::parse(&format!("state://events/external/{installation}/source"))?;
        let capacity = StreamCapacity {
            max_events: 1,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let definition = ExternalInstallationDef {
            id: installation.into(),
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
                    rate_limit: rate.clone(),
                    commands: false,
                    command_schema: None,
                    command_result_schema: None,
                }),
                version: 1,
            }],
            version: 0,
        };
        let ExternalInstallationMutation::Applied(Some(record)) =
            source.compare_install(definition, None).await?
        else {
            anyhow::bail!("installation was not applied")
        };
        Ok(Self {
            installation,
            epoch: record.scope_epoch("source").context("scope missing")?,
            sink,
            capacity,
            rate,
            stream_epoch: None,
        })
    }

    fn scope(&self) -> SourceStreamScope<'_> {
        SourceStreamScope {
            installation_id: self.installation,
            projection_id: "source",
            scope_epoch: self.epoch,
            stream_id: "ordered",
        }
    }

    async fn open<S: SourceStore + ?Sized>(&mut self, source: &S) -> anyhow::Result<()> {
        let current = source
            .inspect_stream(self.scope())
            .await?
            .context("scope missing")?;
        let SourceStreamOpenOutcome::Opened(snapshot) = source
            .open_stream(SourceStreamOpen {
                stream: self.scope(),
                open_id: "open",
                expected_revision: current.revision,
            })
            .await?
        else {
            anyhow::bail!("stream did not open")
        };
        self.stream_epoch = Some(snapshot.active.context("stream missing")?.stream_epoch);
        Ok(())
    }

    fn claim(&self, event: Event) -> SourceClaim<'_> {
        SourceClaim {
            installation_id: self.installation,
            projection_id: "source",
            scope_epoch: self.epoch,
            stream_epoch: self.stream_epoch,
            event_id: event.id,
            claim_id: SourceClaimId::from_bytes([event.claim; 16]),
        }
    }

    async fn commit<S: SourceStore + ?Sized>(
        &self,
        source: &S,
        event: Event,
    ) -> anyhow::Result<SourceCommitOutcome> {
        self.commit_at(source, event, event.at).await
    }

    async fn commit_at<S: SourceStore + ?Sized>(
        &self,
        source: &S,
        event: Event,
        decision_at_ms: i64,
    ) -> anyhow::Result<SourceCommitOutcome> {
        let payload = Value::string(event.payload.into());
        let taint = TaintSet::pristine();
        Ok(source
            .commit(SourceCommit {
                claim: self.claim(event),
                received_at_ms: event.at,
                decision_clock: std::sync::Arc::new(move || decision_at_ms),
                dedupe_window_ms: 9,
                sink: &self.sink,
                capacity: &self.capacity,
                max_inline_payload_bytes: 128,
                payload: &payload,
                taint: &taint,
                stream: self.stream_epoch.map(|stream_epoch| SourceStreamPosition {
                    stream_id: "ordered",
                    stream_epoch,
                    seq: event.seq,
                }),
                rate_limit: self.rate.as_ref(),
            })
            .await?)
    }

    async fn evidence<S: SourceStore + ?Sized>(
        &self,
        source: &S,
        event: Event,
    ) -> anyhow::Result<SourceClaimEvidence> {
        Ok(source
            .inspect(SourceEvidenceInspection {
                claim: self.claim(event),
            })
            .await?)
    }

    async fn proven<S: SourceStore + ?Sized>(
        &self,
        source: &S,
        event: Event,
    ) -> anyhow::Result<()> {
        let SourceClaimEvidence::Committed(receipt) = self.evidence(source, event).await? else {
            anyhow::bail!("accepted claim lost its receipt")
        };
        ensure!(receipt.claim_id == self.claim(event).claim_id);
        ensure!(receipt.event_id == event.id && receipt.sink == self.sink);
        ensure!(receipt.scope_epoch == self.epoch && receipt.stream_epoch == self.stream_epoch);
        ensure!(receipt.received_at_ms == event.at);
        Ok(())
    }
}

fn quota_rejection() -> SourceCommitOutcome {
    SourceCommitOutcome::Rejected(SourceCommitRejection::RetentionCapacityExceeded)
}

async fn maintain<S: SourceStore + ?Sized>(source: &S, now: i64) -> anyhow::Result<()> {
    for _ in 0..8 {
        source
            .maintain(SourceMaintenance {
                decision_clock: std::sync::Arc::new({
                    let decision_at_ms = now;
                    move || decision_at_ms
                }),
                limit: NonZeroUsize::MIN.saturating_add(63),
            })
            .await?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum Contract {
    IndependentEvents,
    AtomicRejection,
    Replacement,
    RateRetention,
    RetiredScopes,
    ConcurrentLastUnit,
}

async fn check<S: SourceStore + ?Sized + 'static>(
    contract: Contract,
    source: Arc<S>,
    state: &Backend,
) -> anyhow::Result<()> {
    match contract {
        Contract::IndependentEvents => independent_events(source.as_ref(), state).await,
        Contract::AtomicRejection => atomic_rejection(source.as_ref(), state).await,
        Contract::Replacement => replacement(source.as_ref()).await,
        Contract::RateRetention => rate_retention(source.as_ref()).await,
        Contract::RetiredScopes => retired_scopes(source.as_ref()).await,
        Contract::ConcurrentLastUnit => concurrent_last_unit(source, state.clone()).await,
    }
}

async fn all_backends(contract: Contract, limit: usize) -> anyhow::Result<()> {
    let limit = NonZeroUsize::new(limit).context("zero retention limit")?;
    for shards in [1, 4] {
        let (state, source) = InMemoryBackend::with_options(InMemoryOptions {
            read_shards: NonZeroUsize::new(shards).context("zero shards")?,
            history: MemoryHistory::Full,
            source_retention_limit: limit,
            ..InMemoryOptions::default()
        })?
        .into_source_parts();
        check(contract, source, &state).await?;
    }
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open_with_options(
        directory.path().join("retention.redb"),
        RedbOptions {
            history: RedbHistory::Full,
            source_retention_limit: limit,
            ..RedbOptions::default()
        },
    )?;
    let (state, source) = store.state_backend().into_source_parts();
    check(contract, source, &state).await
}

async fn concurrent_last_unit<S: SourceStore + ?Sized + 'static>(
    source: Arc<S>,
    state: Backend,
) -> anyhow::Result<()> {
    let fixture = Arc::new(Fixture::install(source.as_ref(), "installation", None).await?);
    let events = [
        Event::new("one", 1, 100),
        Event::new("two", 2, 100),
        Event::new("three", 3, 100),
    ];
    let barrier = Arc::new(Barrier::new(events.len() + 1));
    let mut watcher = state.subscribe(&fixture.sink).await?;
    let query = StateHistoryQuery::new(fixture.sink.clone(), 0, i64::MAX);
    ensure!(state.history(&query).await?.entries.is_empty());
    let contenders = events.map(|event| {
        let source = Arc::clone(&source);
        let fixture = Arc::clone(&fixture);
        let barrier = Arc::clone(&barrier);
        let state = state.clone();
        tokio::spawn(async move {
            let before = state.read(&fixture.sink).await?;
            barrier.wait().await;
            ensure!(before.is_none());
            let outcome = fixture.commit(source.as_ref(), event).await?;
            Ok::<_, anyhow::Error>((event, outcome))
        })
    });
    barrier.wait().await;
    let mut winner = None;
    let mut losers = Vec::new();
    for contender in contenders {
        let (event, outcome) = contender.await??;
        if outcome == SourceCommitOutcome::Accepted {
            ensure!(winner.replace(event).is_none(), "multiple quota winners");
        } else {
            ensure!(outcome == quota_rejection());
            losers.push(event);
        }
    }
    let winner = winner.context("no quota winner")?;
    ensure!(losers.len() == events.len() - 1);
    fixture.proven(source.as_ref(), winner).await?;
    for loser in &losers {
        ensure!(fixture.evidence(source.as_ref(), *loser).await? == SourceClaimEvidence::Unproven);
    }
    let payload = Value::string(winner.payload.into());
    let current = state.read(&fixture.sink).await?.context("sink missing")?;
    let items = current.as_list().context("sink not a list")?;
    ensure!(items.len() == 1 && items.get(0) == Some(&payload));
    let history = state.history(&query).await?.entries;
    ensure!(history.len() == 1);
    ensure!(matches!(&history[0].event, StateEvent::Append { item, .. } if item == &payload));
    ensure!(matches!(watcher.try_recv()?, StateEvent::Append { item, .. } if item == payload));
    ensure!(matches!(watcher.try_recv(), Err(StateWatchError::Empty)));
    let mut now = 110;
    for loser in losers {
        maintain(source.as_ref(), now).await?;
        let retry = Event { at: now, ..loser };
        ensure!(fixture.commit(source.as_ref(), retry).await? == SourceCommitOutcome::Accepted);
        fixture.proven(source.as_ref(), retry).await?;
        ensure!(watcher.try_recv().is_ok());
        ensure!(matches!(watcher.try_recv(), Err(StateWatchError::Empty)));
        now += 10;
    }
    Ok(())
}

async fn independent_events<S: SourceStore + ?Sized>(
    source: &S,
    state: &Backend,
) -> anyhow::Result<()> {
    let fixture = Fixture::install(source, "installation", None).await?;
    let events = [
        Event::new("one", 1, 100),
        Event::new("two", 2, 100),
        Event::new("three", 3, 100),
    ];
    for event in events {
        ensure!(fixture.commit(source, event).await? == SourceCommitOutcome::Accepted);
    }
    ensure!(
        state
            .read(&fixture.sink)
            .await?
            .context("sink missing")?
            .as_list()
            .context("sink not a list")?
            .len()
            == 1
    );
    for event in events {
        fixture.proven(source, event).await?;
        ensure!(fixture.commit(source, event).await? == SourceCommitOutcome::Duplicate);
    }
    ensure!(
        fixture
            .commit(
                source,
                Event {
                    payload: "changed",
                    ..events[0]
                }
            )
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::EventIdConflict)
    );
    ensure!(fixture.commit(source, Event::new("four", 4, 100)).await? == quota_rejection());
    fixture.proven(source, events[0]).await?;
    Ok(())
}

async fn atomic_rejection<S: SourceStore + ?Sized>(
    source: &S,
    state: &Backend,
) -> anyhow::Result<()> {
    let mut fixture = Fixture::install(
        source,
        "installation",
        Some(SourceRateLimit {
            window_ms: 1000,
            max_events: 3,
        }),
    )
    .await?;
    fixture.open(source).await?;
    let first = Event::new("one", 1, 100);
    let second = Event::new("two", 2, 101);
    let rejected = Event::new("three", 3, 102);
    for event in [first, second] {
        ensure!(fixture.commit(source, event).await? == SourceCommitOutcome::Accepted);
    }
    let before = state.read(&fixture.sink).await?;
    let query = StateHistoryQuery::new(fixture.sink.clone(), 0, i64::MAX);
    let history = state.history(&query).await?.entries;
    let position = source.inspect_stream(fixture.scope()).await?;
    let mut watcher = state.subscribe(&fixture.sink).await?;
    ensure!(fixture.commit(source, rejected).await? == quota_rejection());
    ensure!(fixture.commit(source, rejected).await? == quota_rejection());
    ensure!(state.read(&fixture.sink).await? == before);
    ensure!(state.history(&query).await?.entries == history);
    ensure!(source.inspect_stream(fixture.scope()).await? == position);
    ensure!(matches!(watcher.try_recv(), Err(StateWatchError::Empty)));
    ensure!(fixture.evidence(source, rejected).await? == SourceClaimEvidence::Unproven);
    ensure!(
        source
            .inspect_event(SourceEventDecisionInspection {
                installation_id: fixture.installation,
                projection_id: "source",
                scope_epoch: fixture.epoch,
                stream_epoch: fixture.stream_epoch,
                event_id: rejected.id,
            })
            .await?
            == SourceClaimEvidence::Unproven
    );
    fixture.proven(source, first).await?;
    fixture.proven(source, second).await?;
    maintain(source, 110).await?;
    let retry = Event {
        at: 110,
        ..rejected
    };
    ensure!(fixture.commit(source, retry).await? == SourceCommitOutcome::Accepted);
    fixture.proven(source, retry).await?;
    ensure!(
        source
            .inspect_stream(fixture.scope())
            .await?
            .context("scope missing")?
            .active
            .context("stream missing")?
            .last_seq
            == 3
    );
    ensure!(watcher.try_recv().is_ok());
    ensure!(matches!(watcher.try_recv(), Err(StateWatchError::Empty)));
    ensure!(state.history(&query).await?.entries.len() == history.len() + 1);
    Ok(())
}

async fn replacement<S: SourceStore + ?Sized>(source: &S) -> anyhow::Result<()> {
    let fixture = Fixture::install(source, "installation", None).await?;
    let original = Event::new("one", 1, 100);
    ensure!(fixture.commit(source, original).await? == SourceCommitOutcome::Accepted);
    let renewed = Event {
        claim: 2,
        at: 110,
        payload: "renewed",
        ..original
    };
    ensure!(fixture.commit(source, renewed).await? == SourceCommitOutcome::Accepted);
    ensure!(fixture.evidence(source, original).await? == SourceClaimEvidence::Unproven);
    fixture.proven(source, renewed).await?;
    ensure!(fixture.commit(source, renewed).await? == SourceCommitOutcome::Duplicate);
    ensure!(fixture.commit(source, Event::new("two", 3, 110)).await? == quota_rejection());
    Ok(())
}

async fn rate_retention<S: SourceStore + ?Sized>(source: &S) -> anyhow::Result<()> {
    let rate = SourceRateLimit {
        window_ms: 1000,
        max_events: 10,
    };
    let first = Fixture::install(source, "first", Some(rate.clone())).await?;
    let second = Fixture::install(source, "second", Some(rate)).await?;
    let event = Event::new("one", 1, 100);
    ensure!(first.commit(source, event).await? == SourceCommitOutcome::Accepted);
    ensure!(second.commit(source, event).await? == quota_rejection());
    maintain(source, 110).await?;
    ensure!(first.evidence(source, event).await? == SourceClaimEvidence::Unproven);
    ensure!(second.commit(source, Event { at: 110, ..event }).await? == quota_rejection());
    let update = Event::new("two", 2, 110);
    ensure!(first.commit(source, update).await? == SourceCommitOutcome::Accepted);
    maintain(source, 120).await?;
    ensure!(second.commit(source, Event { at: 120, ..event }).await? == quota_rejection());
    maintain(source, 1109).await?;
    ensure!(second.commit(source, Event { at: 1109, ..event }).await? == quota_rejection());
    maintain(source, 1110).await?;
    let retry = Event { at: 1110, ..event };
    ensure!(second.commit(source, retry).await? == SourceCommitOutcome::Accepted);
    second.proven(source, retry).await?;
    Ok(())
}

async fn retired_scopes<S: SourceStore + ?Sized>(source: &S) -> anyhow::Result<()> {
    let mut first = Fixture::install(source, "first", None).await?;
    first.open(source).await?;
    let original = Event::new("one", 1, 100);
    ensure!(first.commit(source, original).await? == SourceCommitOutcome::Accepted);
    ensure!(matches!(
        source
            .retire_stream(SourceStreamRetire {
                stream: first.scope(),
                stream_epoch: first.stream_epoch.context("stream missing")?,
            })
            .await?,
        SourceStreamRetireOutcome::Retired { .. }
    ));
    let second = Fixture::install(source, "second", None).await?;
    let event = Event::new("two", 2, 100);
    ensure!(second.commit(source, event).await? == quota_rejection());
    let revision = source
        .load_installation("first")
        .await?
        .context("installation missing")?
        .revision();
    ensure!(
        source.compare_retire("first", revision).await?
            == ExternalInstallationMutation::Applied(None)
    );
    let reincarnated = Fixture::install(source, "first", None).await?;
    ensure!(reincarnated.epoch != first.epoch);
    maintain(source, 109).await?;
    ensure!(reincarnated.commit(source, event).await? == quota_rejection());
    ensure!(second.commit(source, event).await? == quota_rejection());
    first.proven(source, original).await?;
    maintain(source, 110).await?;
    ensure!(first.evidence(source, original).await? == SourceClaimEvidence::Unproven);
    let retry = Event { at: 110, ..event };
    ensure!(second.commit(source, retry).await? == SourceCommitOutcome::Accepted);
    ensure!(reincarnated.commit(source, retry).await? == quota_rejection());
    Ok(())
}

#[tokio::test]
async fn independent_events_fill_retention_despite_a_one_item_sink() -> anyhow::Result<()> {
    all_backends(Contract::IndependentEvents, 3).await
}

#[tokio::test]
async fn retention_rejection_is_atomic_and_retry_does_not_spend_rate_or_sequence()
-> anyhow::Result<()> {
    all_backends(Contract::AtomicRejection, 3).await
}

#[tokio::test]
async fn expired_replacement_reuses_capacity_and_replaces_exact_claim_evidence()
-> anyhow::Result<()> {
    all_backends(Contract::Replacement, 1).await
}

#[tokio::test]
async fn rate_rows_are_charged_until_their_last_hit_expires() -> anyhow::Result<()> {
    all_backends(Contract::RateRetention, 2).await
}

#[tokio::test]
async fn shared_retention_survives_stream_and_scope_retirement() -> anyhow::Result<()> {
    all_backends(Contract::RetiredScopes, 1).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_events_have_one_last_unit_winner_and_losers_can_retry() -> anyhow::Result<()> {
    all_backends(Contract::ConcurrentLastUnit, 1).await
}

#[tokio::test]
async fn redb_reopen_with_lower_quota_preserves_evidence_and_allows_non_growing_commits()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("reopen.redb");
    let options = |limit| -> anyhow::Result<RedbOptions> {
        Ok(RedbOptions {
            history: RedbHistory::Full,
            source_retention_limit: NonZeroUsize::new(limit).context("zero retention limit")?,
            ..RedbOptions::default()
        })
    };
    let first = Event::new("one", 1, 100);
    let second = Event::new("two", 2, 101);
    let fixture;
    {
        let store = RedbStore::open_with_options(&path, options(3)?)?;
        let (state, source) = store.state_backend().into_source_parts();
        fixture = Fixture::install(
            source.as_ref(),
            "installation",
            Some(SourceRateLimit {
                window_ms: 1000,
                max_events: 10,
            }),
        )
        .await?;
        for event in [first, second] {
            ensure!(fixture.commit(source.as_ref(), event).await? == SourceCommitOutcome::Accepted);
        }
        let idle = store.wait_idle();
        drop(source);
        drop(state);
        drop(store);
        idle.await;
    }
    let store = RedbStore::open_with_options(&path, options(1)?)?;
    let (state, source) = store.state_backend().into_source_parts();
    for event in [first, second] {
        fixture.proven(source.as_ref(), event).await?;
        ensure!(
            fixture.commit_at(source.as_ref(), event, 101).await? == SourceCommitOutcome::Duplicate
        );
    }
    let renewed = Event {
        claim: 3,
        at: 110,
        payload: "renewed",
        ..first
    };
    ensure!(fixture.commit(source.as_ref(), renewed).await? == SourceCommitOutcome::Accepted);
    ensure!(fixture.evidence(source.as_ref(), first).await? == SourceClaimEvidence::Unproven);
    fixture.proven(source.as_ref(), renewed).await?;
    fixture.proven(source.as_ref(), second).await?;
    let before = state.read(&fixture.sink).await?;
    ensure!(
        fixture
            .commit(source.as_ref(), Event::new("three", 4, 110))
            .await?
            == quota_rejection()
    );
    ensure!(state.read(&fixture.sink).await? == before);
    maintain(source.as_ref(), 120).await?;
    ensure!(
        fixture
            .commit(source.as_ref(), Event::new("three", 4, 120))
            .await?
            == quota_rejection()
    );
    maintain(source.as_ref(), 1110).await?;
    let unmetered = Fixture::install(source.as_ref(), "unmetered", None).await?;
    let retry = Event::new("three", 4, 1110);
    ensure!(unmetered.commit(source.as_ref(), retry).await? == SourceCommitOutcome::Accepted);
    unmetered.proven(source.as_ref(), retry).await?;
    Ok(())
}
