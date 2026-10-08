use anyhow::{Context, ensure};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::num::NonZeroUsize;
use std::sync::Arc;
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, ExternalInstallationRevision,
    SourceAdmissionError, SourceClaim, SourceClaimEvidence, SourceClaimId, SourceClaimInspection,
    SourceCommit, SourceCommitOutcome, SourceCommitRejection, SourceDeclarationAdmission,
    SourceEventCommit, SourceEventDecisionInspection, SourceEventMaintenance,
    SourceEvidenceInspection, SourceMaintenance, SourceStreamLifecycle, SourceStreamOpen,
    SourceStreamOpenOutcome, SourceStreamPosition, SourceStreamScope,
};
use xolotl_state::{Backend, StateEvent, StateHistoryQuery, StateReadExt, StateWatchError};
use xolotl_storage_redb::{RedbHistory, RedbStateBackend, RedbStore};
use xolotl_types::{
    Path, Purity, TaintSet, TaintSource, Transport, TrustLevel, Value,
    external::{
        EventSource, ExternalInstallationDef, ExternalProjectionDef, OverflowPolicy, Role,
        SourceRateLimit, StreamCapacity,
    },
};

async fn check_serialized_time_and_read_only_evidence(
    state: &Backend,
    source: &dyn xolotl_source::SourceStore,
) -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    let path = sink()?;
    let cap = capacity(4, OverflowPolicy::DropOldest);
    let payload = Value::integer(42);
    let taint = TaintSet::pristine();
    let rate = SourceRateLimit {
        window_ms: 100,
        max_events: 1,
    };
    install_default(source, &path, &cap, Some(&rate)).await?;
    let time = Arc::new(AtomicI64::new(1000));
    let samples = Arc::new(AtomicUsize::new(0));
    let clock: Arc<dyn xolotl_source::SourceClock> = {
        let time = Arc::clone(&time);
        let samples = Arc::clone(&samples);
        Arc::new(move || {
            samples.fetch_add(1, Ordering::SeqCst);
            time.load(Ordering::SeqCst)
        })
    };
    let request = |claim_id| {
        let mut request = commit(
            "event",
            claim_id,
            &path,
            &cap,
            &payload,
            &taint,
            10,
            None,
            Some(&rate),
        );
        request.decision_clock = Arc::clone(&clock);
        request
    };
    ensure!(source.commit(request(1)).await? == SourceCommitOutcome::Accepted);
    ensure!(samples.load(Ordering::SeqCst) == 1);
    let waiting = source.commit(request(2));
    ensure!(samples.load(Ordering::SeqCst) == 1);
    time.store(2001, Ordering::SeqCst);
    let maintenance = source
        .maintain(SourceMaintenance {
            decision_clock: Arc::clone(&clock),
            limit: NonZeroUsize::new(64).context("maintenance limit")?,
        })
        .await?;
    ensure!(maintenance.removed == 2);
    ensure!(samples.load(Ordering::SeqCst) == 2);
    time.store(2100, Ordering::SeqCst);
    ensure!(waiting.await? == SourceCommitOutcome::Accepted);
    ensure!(samples.load(Ordering::SeqCst) == 3);
    let before = state.read(&path).await?;
    let mut watcher = state.subscribe(&path).await?;
    let claim = request(2).claim;
    for _ in 0..4 {
        let evidence = source.inspect(SourceEvidenceInspection { claim }).await?;
        let SourceClaimEvidence::Committed(receipt) = evidence else {
            anyhow::bail!("accepted claim must remain provable after losing its response")
        };
        ensure!(receipt.received_at_ms == 10);
        ensure!(receipt.claim_id == claim.claim_id);
        ensure!(
            source
                .inspect_event(SourceEventDecisionInspection {
                    installation_id: claim.installation_id,
                    projection_id: claim.projection_id,
                    scope_epoch: claim.scope_epoch,
                    stream_epoch: claim.stream_epoch,
                    event_id: claim.event_id,
                })
                .await?
                == SourceClaimEvidence::Committed(receipt)
        );
    }
    let unknown = SourceClaim {
        claim_id: SourceClaimId::from_bytes([9; 16]),
        ..claim
    };
    ensure!(
        source
            .inspect(SourceEvidenceInspection { claim: unknown })
            .await?
            == SourceClaimEvidence::Unproven
    );
    ensure!(state.read(&path).await? == before);
    ensure!(matches!(watcher.try_recv(), Err(StateWatchError::Empty)));
    ensure!(
        samples.load(Ordering::SeqCst) == 3,
        "inspection must not sample or update decision time"
    );
    let mut another = request(3);
    another.claim.event_id = "another";
    ensure!(
        source.commit(another).await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::RateLimited)
    );
    time.store(2500, Ordering::SeqCst);
    ensure!(
        source.commit(request(4)).await? == SourceCommitOutcome::Duplicate,
        "expiry must start at decision time, not receipt time"
    );
    time.store(3101, Ordering::SeqCst);
    ensure!(
        source
            .maintain(SourceMaintenance {
                decision_clock: Arc::clone(&clock),
                limit: NonZeroUsize::new(64).context("maintenance limit")?,
            })
            .await?
            .removed
            == 2
    );
    ensure!(
        source.inspect(SourceEvidenceInspection { claim }).await? == SourceClaimEvidence::Unproven
    );
    time.store(3000, Ordering::SeqCst);
    ensure!(
        matches!(
            source.commit(request(5)).await,
            Err(xolotl_source::SourceStoreError::Aborted(_))
        ),
        "cleanup must not erase the clock fence with the rate state"
    );
    ensure!(state.read(&path).await? == before);
    ensure!(
        source
            .maintain(SourceMaintenance {
                decision_clock: Arc::clone(&clock),
                limit: NonZeroUsize::MIN,
            })
            .await?
            .examined
            == 0
    );
    ensure!(matches!(
        source.commit(request(6)).await,
        Err(xolotl_source::SourceStoreError::Aborted(_))
    ));
    Ok(())
}

#[tokio::test]
async fn serialized_time_and_read_only_evidence_share_a_backend_contract() -> anyhow::Result<()> {
    for shards in [1, 4] {
        let (state, source) =
            xolotl_state::InMemoryBackend::with_options(xolotl_state::InMemoryOptions {
                read_shards: NonZeroUsize::new(shards).context("shards")?,
                ..Default::default()
            })?
            .into_source_parts();
        check_serialized_time_and_read_only_evidence(&state, source.as_ref()).await?;
    }
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("clock.redb"))?;
    let (state, source) = store.state_backend().into_source_parts();
    check_serialized_time_and_read_only_evidence(&state, source.as_ref()).await?;
    Ok(())
}

const FIRST_SCOPE_EPOCH: u64 = 2;

async fn check_installation_record_budget<S: ExternalInstallationAuthority + ?Sized>(
    source: &S,
) -> anyhow::Result<()> {
    let sink = sink()?;
    let capacity = capacity(4, OverflowPolicy::DropOldest);
    install_source(
        source,
        "installation",
        "source",
        &sink,
        &capacity,
        1024,
        None,
        None,
    )
    .await?;
    let original = source
        .load_installation("installation")
        .await?
        .context("initial installation missing")?;
    let original_revision = original.revision();
    let mut boundary = original.clone();
    boundary.definition.version = 2;
    boundary
        .scope_epochs
        .insert("source".into(), FIRST_SCOPE_EPOCH + 1);
    boundary.definition.platform.clear();
    let empty_bytes = serde_json::to_vec(&boundary)?.len();
    let fill = xolotl_source::MAX_INSTALLATION_RECORD_BYTES
        .checked_sub(empty_bytes)
        .context("base installation exceeds byte budget")?;
    boundary.definition.platform = "x".repeat(fill);
    ensure!(serde_json::to_vec(&boundary)?.len() == xolotl_source::MAX_INSTALLATION_RECORD_BYTES);

    let mut oversized = boundary.definition.clone();
    oversized.platform.push('x');
    let Err(error) = source
        .compare_install(oversized, Some(original_revision))
        .await
    else {
        anyhow::bail!("record one byte over the limit must be refused")
    };
    ensure!(
        matches!(error, xolotl_source::SourceStoreError::Aborted(message) if message.contains("byte maximum"))
    );
    ensure!(source.load_installation("installation").await? == Some(original));

    let ExternalInstallationMutation::Applied(Some(accepted)) = source
        .compare_install(boundary.definition.clone(), Some(original_revision))
        .await?
    else {
        anyhow::bail!("boundary-sized installation was not applied")
    };
    ensure!(
        accepted == boundary,
        "rejected write consumed an authority epoch"
    );
    ensure!(serde_json::to_vec(&accepted)?.len() == xolotl_source::MAX_INSTALLATION_RECORD_BYTES);
    Ok(())
}

#[tokio::test]
async fn installation_record_budget_is_identical_in_memory_and_redb() -> anyhow::Result<()> {
    check_installation_record_budget(&xolotl_state::InMemoryBackend::new()).await?;
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("state.redb"))?;
    let (_state, source) = store.state_backend().into_source_parts();
    check_installation_record_budget(source.as_ref()).await?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "test fixture declares one Source projection"
)]
async fn install_source<S: ExternalInstallationAuthority + ?Sized>(
    source: &S,
    installation_id: &str,
    projection_id: &str,
    sink: &Path,
    capacity: &StreamCapacity,
    max_inline_payload_bytes: usize,
    rate_limit: Option<&SourceRateLimit>,
    expected: Option<ExternalInstallationRevision>,
) -> anyhow::Result<u64> {
    let definition = ExternalInstallationDef {
        id: installation_id.into(),
        platform: "test".into(),
        transport: Transport::Grpc { endpoint: None },
        trust: TrustLevel::Full,
        config_schema: Value::map(Default::default()),
        config: Value::null(),
        projections: vec![ExternalProjectionDef {
            id: projection_id.into(),
            role: Role::Source,
            namespace: None,
            provides: vec![],
            emits: Some(EventSource {
                sink: sink.clone(),
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes,
                capacity: capacity.clone(),
                rate_limit: rate_limit.cloned(),
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            version: 1,
        }],
        version: 0,
    };
    let ExternalInstallationMutation::Applied(Some(record)) =
        source.compare_install(definition, expected).await?
    else {
        anyhow::bail!("Source test installation was not applied")
    };
    record
        .scope_epoch(projection_id)
        .context("installed Source epoch missing")
}

async fn install_default<S: ExternalInstallationAuthority + ?Sized>(
    source: &S,
    sink: &Path,
    capacity: &StreamCapacity,
    rate_limit: Option<&SourceRateLimit>,
) -> anyhow::Result<()> {
    let epoch = install_source(
        source,
        "installation",
        "source",
        sink,
        capacity,
        1024,
        rate_limit,
        None,
    )
    .await?;
    ensure!(epoch == FIRST_SCOPE_EPOCH);
    Ok(())
}

fn sink() -> anyhow::Result<Path> {
    Path::parse("state://events/external/installation/source").map_err(Into::into)
}

fn raw_state_history(path: &std::path::Path) -> anyhow::Result<(u64, i64)> {
    let database = Database::create(path)?;
    let txn = database.begin_read()?;
    let history: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state_history");
    let metadata: TableDefinition<&str, i64> = TableDefinition::new("state_meta");
    let rows = txn.open_table(history)?.len()?;
    let clock = txn
        .open_table(metadata)?
        .get("last_history_millis")?
        .context("history clock missing")?
        .value();
    Ok((rows, clock))
}

fn raw_source_meta_keys(path: &std::path::Path) -> anyhow::Result<Vec<Vec<u8>>> {
    let database = Database::create(path)?;
    let txn = database.begin_read()?;
    let source_meta: TableDefinition<&[u8], &[u8]> = TableDefinition::new("source_meta_v1");
    let table = txn.open_table(source_meta)?;
    table
        .iter()?
        .map(|row| {
            row.map(|(key, _value)| key.value().to_vec())
                .map_err(Into::into)
        })
        .collect()
}

fn raw_sink_layout(
    database: &std::path::Path,
    sink: &Path,
) -> anyhow::Result<Option<(Vec<u8>, usize, usize)>> {
    let db = Database::open(database)?;
    let txn = db.begin_read()?;
    let values = txn.open_table(TableDefinition::<&str, &[u8]>::new("state_values"))?;
    let key = sink.to_string();
    let Some(row) = values.get(key.as_str())? else {
        let items = txn.open_table(TableDefinition::<&[u8], &[u8]>::new("state_list_items_v1"))?;
        ensure!(items.is_empty()?);
        return Ok(None);
    };
    let bytes = row.value().to_vec();
    let items = txn.open_table(TableDefinition::<&[u8], &[u8]>::new("state_list_items_v1"))?;
    let mut item_count = 0usize;
    let mut physical_bytes = key.len() + bytes.len();
    for item in items.iter()? {
        let (item_key, item_value) = item?;
        item_count += 1;
        physical_bytes += item_key.value().len() + item_value.value().len();
    }
    Ok(Some((bytes, item_count, physical_bytes)))
}

async fn inspect_sink_and_reopen(
    file: &std::path::Path,
    sink: &Path,
    history: RedbHistory,
    store: RedbStore,
    state: Backend,
    source: Arc<RedbStateBackend>,
) -> anyhow::Result<(
    RedbStore,
    Backend,
    Arc<RedbStateBackend>,
    Option<(Vec<u8>, usize, usize)>,
)> {
    let idle = store.wait_idle();
    drop(source);
    drop(state);
    drop(store);
    idle.await;
    let layout = raw_sink_layout(file, sink)?;
    let store = RedbStore::open_with_history(file, history)?;
    let (state, source) = store.state_backend().into_source_parts();
    Ok((store, state, source, layout))
}

fn capacity(max_events: u32, on_overflow: OverflowPolicy) -> StreamCapacity {
    StreamCapacity {
        max_events,
        on_overflow,
    }
}

async fn open_test_stream<S: SourceStreamLifecycle + ?Sized>(
    source: &S,
    scope_epoch: u64,
    stream_id: &str,
) -> anyhow::Result<u64> {
    let stream = SourceStreamScope {
        installation_id: "installation",
        projection_id: "source",
        scope_epoch,
        stream_id,
    };
    let current = source
        .inspect_stream(stream)
        .await?
        .context("scope inactive")?;
    let SourceStreamOpenOutcome::Opened(snapshot) = source
        .open_stream(SourceStreamOpen {
            stream,
            open_id: "test-open",
            expected_revision: current.revision,
        })
        .await?
    else {
        anyhow::bail!("test stream did not open")
    };
    Ok(snapshot
        .active
        .context("opened stream missing")?
        .stream_epoch)
}

#[expect(
    clippy::too_many_arguments,
    reason = "test fixture exposes independent Source admission inputs"
)]
fn commit<'a>(
    event_id: &'a str,
    claim_id: u8,
    sink: &'a Path,
    capacity: &'a StreamCapacity,
    payload: &'a Value,
    taint: &'a TaintSet,
    now: i64,
    stream: Option<SourceStreamPosition<'a>>,
    rate_limit: Option<&'a SourceRateLimit>,
) -> SourceCommit<'a> {
    SourceCommit {
        claim: SourceClaim {
            installation_id: "installation",
            projection_id: "source",
            scope_epoch: FIRST_SCOPE_EPOCH,
            stream_epoch: stream.map(|position| position.stream_epoch),
            event_id,
            claim_id: SourceClaimId::from_bytes([claim_id; 16]),
        },
        received_at_ms: now,
        decision_clock: std::sync::Arc::new({
            let decision_at_ms = now;
            move || decision_at_ms
        }),
        dedupe_window_ms: 1000,
        sink,
        capacity,
        max_inline_payload_bytes: 1024,
        payload,
        taint,
        stream,
        rate_limit,
    }
}

#[test]
fn declaration_admission_uses_builtin_source_bounds() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("state.redb"))?;
    let (_state, source) = store.state_backend().into_source_parts();
    let mut declaration = EventSource {
        sink: sink()?,
        purity: Purity::Effectful,
        event_schema: None,
        max_inline_payload_bytes: 1024,
        capacity: capacity(4, OverflowPolicy::DropOldest),
        rate_limit: Some(SourceRateLimit {
            window_ms: 1000,
            max_events: 4,
        }),
        commands: false,
        command_schema: None,
        command_result_schema: None,
    };
    ensure!(
        source
            .validate_source("installation", "source", &declaration)
            .is_ok()
    );
    declaration
        .rate_limit
        .as_mut()
        .context("rate rule")?
        .max_events = (xolotl_source::MAX_RATE_HITS + 1) as u32;
    ensure!(
        source.validate_source("installation", "source", &declaration)
            == Err(SourceAdmissionError::LimitExceeded {
                field: "rate hits",
                max: xolotl_source::MAX_RATE_HITS,
            })
    );
    Ok(())
}

#[tokio::test]
async fn maximum_legal_receipt_encoding_survives_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("state.redb");
    let mut sink_text = String::from("state://");
    sink_text.push_str(&"x".repeat(xolotl_source::MAX_SINK_PATH_BYTES - sink_text.len()));
    let sink = Path::parse(&sink_text)?;
    let id = "a".repeat(xolotl_source::MAX_ID_BYTES);
    let event_id = "\u{0000}".repeat(xolotl_source::MAX_ID_BYTES);
    let cap = capacity(1, OverflowPolicy::DropOldest);
    let payload = Value::null();
    let taint = TaintSet::pristine();
    let claim = SourceClaim {
        installation_id: &id,
        projection_id: &id,
        scope_epoch: 2,
        stream_epoch: None,
        event_id: &event_id,
        claim_id: SourceClaimId::from_bytes([u8::MAX; 16]),
    };
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        let epoch =
            install_source(source.as_ref(), &id, &id, &sink, &cap, 1024, None, None).await?;
        ensure!(epoch == claim.scope_epoch);
        let mut request = commit(
            &event_id,
            1,
            &sink,
            &cap,
            &payload,
            &taint,
            i64::MIN,
            None,
            None,
        );
        request.claim = claim;
        ensure!(source.commit(request).await? == SourceCommitOutcome::Accepted);
    }
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        ensure!(matches!(
            source
                .inspect(SourceEvidenceInspection {
                    claim,
                })
                .await?,
            SourceClaimEvidence::Committed(receipt) if receipt.sink == sink
        ));
    }
    Ok(())
}

#[tokio::test]
async fn encoded_sink_limit_rejects_atomically_across_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("state.redb");
    let path = sink()?;
    let cap = capacity(64, OverflowPolicy::DropOldest);
    ensure!(
        cap.max_events as usize * xolotl_source::MAX_INLINE_PAYLOAD_BYTES
            == xolotl_source::MAX_DECLARED_SINK_BYTES
    );
    let rate = SourceRateLimit {
        window_ms: 1000,
        max_events: 1,
    };
    let payload = Value::null();
    let stream_epoch;
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        install_source(
            source.as_ref(),
            "installation",
            "source",
            &path,
            &cap,
            xolotl_source::MAX_INLINE_PAYLOAD_BYTES,
            Some(&rate),
            None,
        )
        .await?;
        stream_epoch = open_test_stream(source.as_ref(), FIRST_SCOPE_EPOCH, "ordered").await?;
        let stream = Some(SourceStreamPosition {
            stream_id: "ordered",
            stream_epoch,
            seq: 1,
        });
        let oversized_taint = TaintSet::of(TaintSource::Fetched {
            host: "x".repeat(xolotl_source::MAX_DECLARED_SINK_BYTES).into(),
        });
        let mut request = commit(
            "byte-budget",
            1,
            &path,
            &cap,
            &payload,
            &oversized_taint,
            100,
            stream,
            Some(&rate),
        );
        request.max_inline_payload_bytes = xolotl_source::MAX_INLINE_PAYLOAD_BYTES;
        ensure!(
            source.commit(request).await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::CapacityExceeded)
        );
    }
    ensure!(raw_sink_layout(&db, &path)?.is_none());
    ensure!(
        raw_source_meta_keys(&db)?
            .iter()
            .all(|key| key.first() == Some(&b'S'))
    );
    {
        let store = RedbStore::open(&db)?;
        let (state, source) = store.state_backend().into_source_parts();
        ensure!(state.read(&path).await?.is_none());
        ensure!(
            source
                .inspect(SourceEvidenceInspection {
                    claim: SourceClaim {
                        installation_id: "installation",
                        projection_id: "source",
                        scope_epoch: 2,
                        stream_epoch: Some(stream_epoch),
                        event_id: "byte-budget",
                        claim_id: SourceClaimId::from_bytes([1; 16]),
                    },
                })
                .await?
                == SourceClaimEvidence::Unproven
        );
        let pristine = TaintSet::pristine();
        let stream = Some(SourceStreamPosition {
            stream_id: "ordered",
            stream_epoch,
            seq: 1,
        });
        let mut retry = commit(
            "byte-budget",
            2,
            &path,
            &cap,
            &payload,
            &pristine,
            102,
            stream,
            Some(&rate),
        );
        retry.max_inline_payload_bytes = xolotl_source::MAX_INLINE_PAYLOAD_BYTES;
        ensure!(source.commit(retry).await? == SourceCommitOutcome::Accepted);
        ensure!(
            state
                .read(&path)
                .await?
                .and_then(|value| value.as_list().map(|items| items.len()))
                == Some(1)
        );
    }
    Ok(())
}

#[tokio::test]
async fn large_drop_oldest_replacements_publish_item_deltas() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("large-source.redb"))?;
    let (state, source) = store.state_backend().into_source_parts();
    let path = sink()?;
    let cap = capacity(10, OverflowPolicy::DropOldest);
    let payload_limit = 900_000;
    let payload = Value::string("x".repeat(850_000));
    let taint = TaintSet::pristine();
    install_source(
        source.as_ref(),
        "installation",
        "source",
        &path,
        &cap,
        payload_limit,
        None,
        None,
    )
    .await?;

    for index in 0..10 {
        let event_id = format!("fill-{index}");
        let mut request = commit(
            &event_id,
            index + 1,
            &path,
            &cap,
            &payload,
            &taint,
            100 + i64::from(index),
            None,
            None,
        );
        request.max_inline_payload_bytes = payload_limit;
        ensure!(source.commit(request).await? == SourceCommitOutcome::Accepted);
    }

    for index in 10..12 {
        let mut watcher = state.subscribe(&path).await?;
        let event_id = format!("replace-{index}");
        let mut request = commit(
            &event_id,
            index + 1,
            &path,
            &cap,
            &payload,
            &taint,
            100 + i64::from(index),
            None,
            None,
        );
        request.max_inline_payload_bytes = payload_limit;
        ensure!(source.commit(request).await? == SourceCommitOutcome::Accepted);
        ensure!(matches!(
            watcher.try_recv()?,
            StateEvent::DropPrefixAppend { removed: 1, item, .. } if item == payload
        ));
        ensure!(matches!(watcher.try_recv(), Err(StateWatchError::Empty)));
        ensure!(
            state
                .read(&path)
                .await?
                .as_ref()
                .and_then(Value::as_list)
                .map(xolotl_types::ValueList::len)
                == Some(10)
        );
    }
    Ok(())
}

#[tokio::test]
async fn source_receipt_survives_restart_and_maintenance_is_bounded() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("state.redb");
    let path = sink()?;
    let cap = capacity(2, OverflowPolicy::DropOldest);
    let payload = Value::string("first".into());
    let taint = TaintSet::pristine();
    {
        let store = RedbStore::open(&db)?;
        let (state, source) = store.state_backend().into_source_parts();
        install_default(source.as_ref(), &path, &cap, None).await?;
        ensure!(
            source
                .commit(commit(
                    "one", 1, &path, &cap, &payload, &taint, 100, None, None
                ))
                .await?
                == SourceCommitOutcome::Accepted
        );
        ensure!(
            source
                .commit(commit(
                    "one", 2, &path, &cap, &payload, &taint, 101, None, None
                ))
                .await?
                == SourceCommitOutcome::Duplicate
        );
        ensure!(
            state
                .read(&path)
                .await?
                .and_then(|value| value.as_list().map(|items| items.len()))
                == Some(1)
        );
    }
    {
        let store = RedbStore::open(&db)?;
        let (state, source) = store.state_backend().into_source_parts();
        let claim = SourceClaim {
            installation_id: "installation",
            projection_id: "source",
            scope_epoch: 2,
            stream_epoch: None,
            event_id: "one",
            claim_id: SourceClaimId::from_bytes([1; 16]),
        };
        let evidence = source.inspect(SourceEvidenceInspection { claim }).await?;
        ensure!(
            matches!(evidence, SourceClaimEvidence::Committed(receipt) if receipt.sink == path)
        );
        let missing = source
            .inspect(SourceEvidenceInspection {
                claim: SourceClaim {
                    claim_id: SourceClaimId::from_bytes([2; 16]),
                    ..claim
                },
            })
            .await?;
        ensure!(missing == SourceClaimEvidence::Unproven);
        let batch = source
            .maintain(SourceMaintenance {
                decision_clock: std::sync::Arc::new({
                    let decision_at_ms = 1101;
                    move || decision_at_ms
                }),
                limit: NonZeroUsize::MIN,
            })
            .await?;
        ensure!(batch.examined == 1 && batch.removed == 1 && batch.reached_end);
        let expired = source.inspect(SourceEvidenceInspection { claim }).await?;
        ensure!(expired == SourceClaimEvidence::Unproven);
        let next = Value::string("second".into());
        ensure!(
            source
                .commit(commit(
                    "one", 3, &path, &cap, &next, &taint, 1102, None, None
                ))
                .await?
                == SourceCommitOutcome::Accepted
        );
        ensure!(
            state
                .read(&path)
                .await?
                .and_then(|value| value.as_list().map(|items| items.len()))
                == Some(2)
        );
    }
    Ok(())
}

#[tokio::test]
async fn source_sequence_rate_and_capacity_reject_without_partial_commit() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("state.redb"))?;
    let (state, source) = store.state_backend().into_source_parts();
    let path = sink()?;
    let cap = capacity(1, OverflowPolicy::DisconnectBridge);
    let rate = SourceRateLimit {
        window_ms: 1000,
        max_events: 2,
    };
    let taint = TaintSet::pristine();
    let payload = Value::string("value".into());
    install_default(source.as_ref(), &path, &cap, Some(&rate)).await?;
    let stream_epoch = open_test_stream(source.as_ref(), FIRST_SCOPE_EPOCH, "ordered").await?;
    let stream = |seq| {
        Some(SourceStreamPosition {
            stream_id: "ordered",
            stream_epoch,
            seq,
        })
    };
    ensure!(
        source
            .commit(commit(
                "gap",
                1,
                &path,
                &cap,
                &payload,
                &taint,
                100,
                stream(2),
                Some(&rate)
            ))
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::SequenceGap {
                expected: 1,
                seq: 2
            })
    );
    ensure!(
        source
            .commit(commit(
                "one",
                2,
                &path,
                &cap,
                &payload,
                &taint,
                100,
                stream(1),
                Some(&rate)
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(
        source
            .commit(commit(
                "two",
                3,
                &path,
                &cap,
                &payload,
                &taint,
                101,
                stream(2),
                Some(&rate)
            ))
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::CapacityExceeded)
    );
    let drop_oldest = capacity(1, OverflowPolicy::DropOldest);
    let mut stale = commit(
        "two",
        4,
        &path,
        &drop_oldest,
        &payload,
        &taint,
        102,
        stream(2),
        Some(&rate),
    );
    ensure!(
        source.commit(stale).await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::DeclarationMismatch)
    );
    let revision = source
        .load_installation("installation")
        .await?
        .context("installation missing")?
        .revision();
    let rotated = install_source(
        source.as_ref(),
        "installation",
        "source",
        &path,
        &drop_oldest,
        1024,
        Some(&rate),
        Some(revision),
    )
    .await?;
    ensure!(rotated != FIRST_SCOPE_EPOCH);
    let rotated_stream_epoch = open_test_stream(source.as_ref(), rotated, "ordered").await?;
    stale = commit(
        "two",
        4,
        &path,
        &drop_oldest,
        &payload,
        &taint,
        102,
        Some(SourceStreamPosition {
            stream_id: "ordered",
            stream_epoch: rotated_stream_epoch,
            seq: 1,
        }),
        Some(&rate),
    );
    stale.claim.scope_epoch = rotated;
    ensure!(source.commit(stale).await? == SourceCommitOutcome::Accepted);
    let mut limited = commit(
        "three",
        5,
        &path,
        &drop_oldest,
        &payload,
        &taint,
        103,
        Some(SourceStreamPosition {
            stream_id: "ordered",
            stream_epoch: rotated_stream_epoch,
            seq: 2,
        }),
        Some(&rate),
    );
    limited.claim.scope_epoch = rotated;
    ensure!(source.commit(limited).await? == SourceCommitOutcome::Accepted);
    ensure!(
        state
            .read(&path)
            .await?
            .context("sink missing")?
            .as_list()
            .is_some_and(|items| items.len() == 1)
    );
    Ok(())
}

#[tokio::test]
async fn idle_rate_maintenance_resumes_after_restart_without_erasing_sequence() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("state.redb");
    let path = sink()?;
    let cap = capacity(4, OverflowPolicy::DropOldest);
    let payload = Value::string("event".into());
    let taint = TaintSet::pristine();
    let rate = SourceRateLimit {
        window_ms: 1000,
        max_events: 1,
    };
    let stream_epoch = {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        install_default(source.as_ref(), &path, &cap, Some(&rate)).await?;
        open_test_stream(source.as_ref(), FIRST_SCOPE_EPOCH, "ordered").await?
    };
    let stream = |seq| {
        Some(SourceStreamPosition {
            stream_id: "ordered",
            stream_epoch,
            seq,
        })
    };
    let step = |now_millis| SourceMaintenance {
        decision_clock: std::sync::Arc::new({
            let decision_at_ms = now_millis;
            move || decision_at_ms
        }),
        limit: NonZeroUsize::MIN,
    };
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        ensure!(
            source
                .commit(commit(
                    "one",
                    1,
                    &path,
                    &cap,
                    &payload,
                    &taint,
                    100,
                    stream(1),
                    Some(&rate),
                ))
                .await?
                == SourceCommitOutcome::Accepted
        );
        let first = source.maintain(step(1099)).await?;
        ensure!(first.examined == 1 && first.removed == 0 && !first.reached_end);
    }
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        let active = source.maintain(step(1099)).await?;
        ensure!(active.examined == 1 && active.removed == 0);
        ensure!(
            source
                .commit(commit(
                    "two",
                    2,
                    &path,
                    &cap,
                    &payload,
                    &taint,
                    1099,
                    stream(2),
                    Some(&rate),
                ))
                .await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::RateLimited)
        );
        let mut idle_removed = 0;
        for _ in 0..4 {
            idle_removed += source.maintain(step(1100)).await?.removed;
        }
        ensure!(idle_removed == 1);
    }
    let keys = raw_source_meta_keys(&db)?;
    ensure!(keys.iter().any(|key| key.starts_with(b"E")));
    ensure!(keys.iter().any(|key| key.starts_with(b"S")));
    ensure!(!keys.iter().any(|key| key.starts_with(b"R")));
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        ensure!(
            source
                .commit(commit(
                    "three",
                    3,
                    &path,
                    &cap,
                    &payload,
                    &taint,
                    1101,
                    stream(1),
                    Some(&rate),
                ))
                .await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::SequenceReplay {
                    last: 1,
                    seq: 1
                })
        );
        ensure!(
            source
                .commit(commit(
                    "four",
                    4,
                    &path,
                    &cap,
                    &payload,
                    &taint,
                    1101,
                    stream(2),
                    Some(&rate),
                ))
                .await?
                == SourceCommitOutcome::Accepted
        );
    }
    Ok(())
}

#[tokio::test]
async fn changing_rate_declaration_rotates_scope_and_rejects_stale_rate() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("state.redb"))?;
    let (_state, source) = store.state_backend().into_source_parts();
    let path = sink()?;
    let cap = capacity(4, OverflowPolicy::DropOldest);
    let payload = Value::string("event".into());
    let taint = TaintSet::pristine();
    let old = SourceRateLimit {
        window_ms: 1000,
        max_events: 1,
    };
    let revised = SourceRateLimit {
        window_ms: 2000,
        max_events: 1,
    };
    install_default(source.as_ref(), &path, &cap, Some(&old)).await?;
    ensure!(
        source
            .commit(commit(
                "one",
                1,
                &path,
                &cap,
                &payload,
                &taint,
                100,
                None,
                Some(&old)
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(
        source
            .commit(commit(
                "two",
                2,
                &path,
                &cap,
                &payload,
                &taint,
                101,
                None,
                Some(&revised)
            ))
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::DeclarationMismatch)
    );
    let revision = source
        .load_installation("installation")
        .await?
        .context("installation missing")?
        .revision();
    let revised_epoch = install_source(
        source.as_ref(),
        "installation",
        "source",
        &path,
        &cap,
        1024,
        Some(&revised),
        Some(revision),
    )
    .await?;
    ensure!(revised_epoch != FIRST_SCOPE_EPOCH);
    ensure!(
        source
            .commit(commit(
                "two",
                2,
                &path,
                &cap,
                &payload,
                &taint,
                101,
                None,
                Some(&old)
            ))
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::ScopeInactive)
    );
    let mut second = commit(
        "two",
        2,
        &path,
        &cap,
        &payload,
        &taint,
        101,
        None,
        Some(&revised),
    );
    second.claim.scope_epoch = revised_epoch;
    ensure!(source.commit(second).await? == SourceCommitOutcome::Accepted);
    let mut third = commit(
        "three",
        3,
        &path,
        &cap,
        &payload,
        &taint,
        102,
        None,
        Some(&revised),
    );
    third.claim.scope_epoch = revised_epoch;
    ensure!(
        source.commit(third).await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::RateLimited)
    );
    Ok(())
}

#[tokio::test]
async fn mismatched_rate_rule_does_not_change_active_rate_period() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("state.redb"))?;
    let (_state, source) = store.state_backend().into_source_parts();
    let path = sink()?;
    let cap = capacity(1, OverflowPolicy::DisconnectBridge);
    let payload = Value::string("event".into());
    let taint = TaintSet::pristine();
    let old = SourceRateLimit {
        window_ms: 1000,
        max_events: 1,
    };
    let revised = SourceRateLimit {
        window_ms: 2000,
        max_events: 1,
    };
    install_default(source.as_ref(), &path, &cap, Some(&old)).await?;
    ensure!(
        source
            .commit(commit(
                "one",
                1,
                &path,
                &cap,
                &payload,
                &taint,
                100,
                None,
                Some(&old)
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(
        source
            .commit(commit(
                "two",
                2,
                &path,
                &cap,
                &payload,
                &taint,
                101,
                None,
                Some(&revised)
            ))
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::DeclarationMismatch)
    );
    ensure!(
        source
            .commit(commit(
                "three",
                3,
                &path,
                &cap,
                &payload,
                &taint,
                102,
                None,
                Some(&old)
            ))
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::RateLimited)
    );
    Ok(())
}

#[tokio::test]
async fn rate_expiry_does_not_saturate_before_a_large_window_ends() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("state.redb"))?;
    let (_state, source) = store.state_backend().into_source_parts();
    let path = sink()?;
    let cap = capacity(4, OverflowPolicy::DropOldest);
    let payload = Value::string("event".into());
    let taint = TaintSet::pristine();
    let rate = SourceRateLimit {
        window_ms: i64::MAX as u64 + 1,
        max_events: 1,
    };
    install_default(source.as_ref(), &path, &cap, Some(&rate)).await?;
    ensure!(
        source
            .commit(commit(
                "one",
                1,
                &path,
                &cap,
                &payload,
                &taint,
                0,
                None,
                Some(&rate)
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    let maintenance = source
        .maintain(SourceMaintenance {
            decision_clock: std::sync::Arc::new({
                let decision_at_ms = i64::MAX;
                move || decision_at_ms
            }),
            limit: NonZeroUsize::new(2).context("nonzero maintenance limit")?,
        })
        .await?;
    ensure!(maintenance.examined == 2 && maintenance.removed == 1);
    ensure!(
        source
            .commit(commit(
                "two",
                2,
                &path,
                &cap,
                &payload,
                &taint,
                i64::MAX,
                None,
                Some(&rate),
            ))
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::RateLimited)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_same_event_id_has_one_atomic_winner() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("state.redb"))?;
    let (state, source) = store.state_backend().into_source_parts();
    install_default(
        source.as_ref(),
        &sink()?,
        &capacity(16, OverflowPolicy::DropOldest),
        None,
    )
    .await?;
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut tasks = Vec::new();
    for claim_id in 1..=16_u8 {
        let source = source.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            let path = sink()?;
            let cap = capacity(16, OverflowPolicy::DropOldest);
            let payload = Value::string("one logical event".into());
            let taint = TaintSet::pristine();
            barrier.wait().await;
            source
                .commit(commit(
                    "shared", claim_id, &path, &cap, &payload, &taint, 100, None, None,
                ))
                .await
                .map_err(anyhow::Error::from)
        }));
    }
    let mut accepted = 0;
    let mut duplicates = 0;
    for task in tasks {
        match task.await?? {
            SourceCommitOutcome::Accepted => accepted += 1,
            SourceCommitOutcome::Duplicate => duplicates += 1,
            other => anyhow::bail!("unexpected concurrent Source outcome: {other:?}"),
        }
    }
    ensure!(accepted == 1 && duplicates == 15);
    ensure!(
        state
            .read(&sink()?)
            .await?
            .and_then(|value| value.as_list().map(|items| items.len()))
            == Some(1)
    );
    Ok(())
}

#[tokio::test]
async fn maintenance_cursor_resumes_after_redb_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("state.redb");
    let path = sink()?;
    let cap = capacity(4, OverflowPolicy::DropOldest);
    let payload = Value::string("event".into());
    let taint = TaintSet::pristine();
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        install_default(source.as_ref(), &path, &cap, None).await?;
        for (event, claim) in [("a", 1), ("b", 2), ("c", 3)] {
            ensure!(
                source
                    .commit(commit(
                        event, claim, &path, &cap, &payload, &taint, 100, None, None
                    ))
                    .await?
                    == SourceCommitOutcome::Accepted
            );
        }
        let first = source
            .maintain(SourceMaintenance {
                decision_clock: std::sync::Arc::new({
                    let decision_at_ms = 1101;
                    move || decision_at_ms
                }),
                limit: NonZeroUsize::MIN,
            })
            .await?;
        ensure!(first.examined == 1 && first.removed == 1 && !first.reached_end);
    }
    {
        let store = RedbStore::open(&db)?;
        let (state, source) = store.state_backend().into_source_parts();
        for (event, claim) in [("b", 2), ("c", 3)] {
            let next = source
                .maintain(SourceMaintenance {
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 1101;
                        move || decision_at_ms
                    }),
                    limit: NonZeroUsize::MIN,
                })
                .await?;
            ensure!(next.examined == 1 && next.removed == 1);
            let missing = source
                .inspect(SourceEvidenceInspection {
                    claim: SourceClaim {
                        installation_id: "installation",
                        projection_id: "source",
                        scope_epoch: 2,
                        stream_epoch: None,
                        event_id: event,
                        claim_id: SourceClaimId::from_bytes([claim; 16]),
                    },
                })
                .await?;
            ensure!(missing == SourceClaimEvidence::Unproven);
        }
        ensure!(
            state
                .read(&path)
                .await?
                .and_then(|value| value.as_list().map(|items| items.len()))
                == Some(3)
        );
    }
    Ok(())
}

#[tokio::test]
async fn maintenance_scans_removed_scopes_and_revisits_keys_before_cursor() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("state.redb");
    let path = sink()?;
    let cap = capacity(8, OverflowPolicy::DropOldest);
    let payload = Value::string("event".into());
    let taint = TaintSet::pristine();
    let mut epochs = std::collections::BTreeMap::new();
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        for (installation, event, claim) in [("m", "first", 1), ("z", "last", 2)] {
            let epoch = install_source(
                source.as_ref(),
                installation,
                "source",
                &path,
                &cap,
                1024,
                None,
                None,
            )
            .await?;
            epochs.insert(installation, epoch);
            let mut request = commit(event, claim, &path, &cap, &payload, &taint, 100, None, None);
            request.claim.installation_id = installation;
            request.claim.scope_epoch = epoch;
            ensure!(source.commit(request).await? == SourceCommitOutcome::Accepted);
        }
        let first = source
            .maintain(SourceMaintenance {
                decision_clock: std::sync::Arc::new({
                    let decision_at_ms = 1101;
                    move || decision_at_ms
                }),
                limit: NonZeroUsize::MIN,
            })
            .await?;
        ensure!(first.examined == 1 && first.removed == 1 && !first.reached_end);
        // This key sorts before the persisted cursor. It is visited after the
        // current pass reaches the end and resets, even across a restart.
        let mut earlier = commit("earlier", 3, &path, &cap, &payload, &taint, 100, None, None);
        let epoch = install_source(
            source.as_ref(),
            "a",
            "source",
            &path,
            &cap,
            1024,
            None,
            None,
        )
        .await?;
        epochs.insert("a", epoch);
        earlier.claim.installation_id = "a";
        earlier.claim.scope_epoch = epoch;
        ensure!(source.commit(earlier).await? == SourceCommitOutcome::Accepted);
    }
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        let second = source
            .maintain(SourceMaintenance {
                decision_clock: std::sync::Arc::new({
                    let decision_at_ms = 1101;
                    move || decision_at_ms
                }),
                limit: NonZeroUsize::MIN,
            })
            .await?;
        ensure!(second.examined == 1 && second.removed == 1 && second.reached_end);
        let third = source
            .maintain(SourceMaintenance {
                decision_clock: std::sync::Arc::new({
                    let decision_at_ms = 1101;
                    move || decision_at_ms
                }),
                limit: NonZeroUsize::MIN,
            })
            .await?;
        ensure!(third.examined == 1 && third.removed == 1 && third.reached_end);
        for (installation, event, claim) in
            [("m", "first", 1), ("z", "last", 2), ("a", "earlier", 3)]
        {
            ensure!(
                source
                    .inspect(SourceEvidenceInspection {
                        claim: SourceClaim {
                            installation_id: installation,
                            projection_id: "source",
                            scope_epoch: *epochs
                                .get(installation)
                                .context("Source scope epoch missing")?,
                            stream_epoch: None,
                            event_id: event,
                            claim_id: SourceClaimId::from_bytes([claim; 16]),
                        },
                    })
                    .await?
                    == SourceClaimEvidence::Unproven
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn accepted_expiry_is_fixed_across_window_changes_and_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db = dir.path().join("state.redb");
    let path = sink()?;
    let cap = capacity(4, OverflowPolicy::DropOldest);
    let payload = Value::string("event".into());
    let taint = TaintSet::pristine();
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        install_default(source.as_ref(), &path, &cap, None).await?;
        ensure!(
            source
                .commit(commit(
                    "fixed", 1, &path, &cap, &payload, &taint, 100, None, None
                ))
                .await?
                == SourceCommitOutcome::Accepted
        );
    }
    {
        let store = RedbStore::open(&db)?;
        let (_state, source) = store.state_backend().into_source_parts();
        let before = source
            .maintain(SourceMaintenance {
                decision_clock: std::sync::Arc::new({
                    let decision_at_ms = 1100;
                    move || decision_at_ms
                }),
                limit: NonZeroUsize::MIN,
            })
            .await?;
        ensure!(before.examined == 1 && before.removed == 0);
        let mut shortened = commit("fixed", 2, &path, &cap, &payload, &taint, 500, None, None);
        shortened.decision_clock = Arc::new(|| 1100);
        shortened.dedupe_window_ms = 1;
        ensure!(source.commit(shortened).await? == SourceCommitOutcome::Duplicate);
        let expired = source
            .maintain(SourceMaintenance {
                decision_clock: std::sync::Arc::new({
                    let decision_at_ms = 1101;
                    move || decision_at_ms
                }),
                limit: NonZeroUsize::MIN,
            })
            .await?;
        ensure!(expired.examined == 1 && expired.removed == 1);
        let mut extended = commit("fixed", 3, &path, &cap, &payload, &taint, 1102, None, None);
        extended.dedupe_window_ms = 5000;
        ensure!(source.commit(extended).await? == SourceCommitOutcome::Accepted);
        let mut shortened_again =
            commit("fixed", 4, &path, &cap, &payload, &taint, 1200, None, None);
        shortened_again.dedupe_window_ms = 1;
        ensure!(source.commit(shortened_again).await? == SourceCommitOutcome::Duplicate);
        let still_retained = source
            .maintain(SourceMaintenance {
                decision_clock: std::sync::Arc::new({
                    let decision_at_ms = 1200;
                    move || decision_at_ms
                }),
                limit: NonZeroUsize::MIN,
            })
            .await?;
        ensure!(still_retained.examined == 1 && still_retained.removed == 0);
    }
    Ok(())
}

#[tokio::test]
async fn non_sequence_sink_rejects_without_source_reservation() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("state.redb"))?;
    let (state, source) = store.state_backend().into_source_parts();
    let path = sink()?;
    let cap = capacity(1, OverflowPolicy::DropOldest);
    let payload = Value::string("event".into());
    let taint = TaintSet::pristine();
    let rate = SourceRateLimit {
        window_ms: 1000,
        max_events: 1,
    };
    install_default(source.as_ref(), &path, &cap, Some(&rate)).await?;
    let stream_epoch = open_test_stream(source.as_ref(), FIRST_SCOPE_EPOCH, "stream").await?;
    let stream = Some(SourceStreamPosition {
        stream_id: "stream",
        stream_epoch,
        seq: 1,
    });
    state.write_set(&path, Value::integer(7)).await?;
    ensure!(
        source
            .commit(commit(
                "event",
                1,
                &path,
                &cap,
                &payload,
                &taint,
                100,
                stream,
                Some(&rate)
            ))
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::SinkTypeMismatch)
    );
    let missing = source
        .inspect(SourceEvidenceInspection {
            claim: SourceClaim {
                installation_id: "installation",
                projection_id: "source",
                scope_epoch: 2,
                stream_epoch: Some(stream_epoch),
                event_id: "event",
                claim_id: SourceClaimId::from_bytes([1; 16]),
            },
        })
        .await?;
    ensure!(missing == SourceClaimEvidence::Unproven);
    state.write_set(&path, Value::list(Vec::new())).await?;
    ensure!(
        source
            .commit(commit(
                "event",
                2,
                &path,
                &cap,
                &payload,
                &taint,
                102,
                stream,
                Some(&rate)
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(
        state
            .read(&path)
            .await?
            .and_then(|value| value.as_list().map(|items| items.len()))
            == Some(1)
    );
    Ok(())
}

#[tokio::test]
async fn drop_oldest_commits_current_value_history_and_receipts() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("state.redb");
    let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
    let (state, source) = store.state_backend().into_source_parts();
    let path = sink()?;
    let cap = capacity(1, OverflowPolicy::DropOldest);
    let first = Value::string("first".into());
    let second = Value::string("second".into());
    let taint = TaintSet::pristine();
    install_default(source.as_ref(), &path, &cap, None).await?;
    ensure!(
        source
            .commit(commit(
                "first", 1, &path, &cap, &first, &taint, 100, None, None
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(
        source
            .commit(commit(
                "second", 2, &path, &cap, &second, &taint, 101, None, None
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(
        state
            .read(&path)
            .await?
            .and_then(|value| value.as_list().and_then(|items| items.first().cloned()))
            == Some(second.clone())
    );
    let history = state
        .history(&StateHistoryQuery::new(path.clone(), 0, i64::MAX))
        .await?;
    ensure!(history.entries.len() == 2);
    ensure!(matches!(&history.entries[0].event, StateEvent::Append { item, .. } if item == &first));
    ensure!(matches!(
        &history.entries[1].event,
        StateEvent::DropPrefixAppend { removed: 1, item, .. } if item == &second
    ));
    let mut replay = xolotl_state::StateObservation::default();
    for entry in &history.entries {
        xolotl_state::apply_history_event(&mut replay, &entry.event)?;
    }
    ensure!(replay.value.as_ref() == state.read(&path).await?.as_ref());
    let old = source
        .inspect(SourceEvidenceInspection {
            claim: SourceClaim {
                installation_id: "installation",
                projection_id: "source",
                scope_epoch: 2,
                stream_epoch: None,
                event_id: "first",
                claim_id: SourceClaimId::from_bytes([1; 16]),
            },
        })
        .await?;
    ensure!(matches!(old, SourceClaimEvidence::Committed(receipt) if receipt.sink == path));
    drop(source);
    drop(state);
    drop(store);
    ensure!(raw_state_history(&file)?.0 == 2);
    Ok(())
}

#[tokio::test]
async fn drop_oldest_current_only_retains_receipts_without_state_history() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("current-source.redb");
    let path = sink()?;
    let cap = capacity(1, OverflowPolicy::DropOldest);
    let first = Value::string("first".into());
    let second = Value::string("second".into());
    let taint = TaintSet::pristine();
    {
        let store = RedbStore::open(&file)?;
        let (state, source) = store.state_backend().into_source_parts();
        install_default(source.as_ref(), &path, &cap, None).await?;
        ensure!(!state.has_history());
        for (event_id, claim_id, payload, now) in
            [("first", 1, &first, 100), ("second", 2, &second, 101)]
        {
            ensure!(
                source
                    .commit(commit(
                        event_id, claim_id, &path, &cap, payload, &taint, now, None, None
                    ))
                    .await?
                    == SourceCommitOutcome::Accepted
            );
        }
        ensure!(matches!(
            state
                .history(&StateHistoryQuery::new(path.clone(), 0, i64::MAX))
                .await,
            Err(xolotl_state::StateFailure {
                error: xolotl_state::StateError::MissingCapability("history"),
                ..
            })
        ));
    }
    ensure!(raw_state_history(&file)? == (0, 0));
    let store = RedbStore::open(&file)?;
    let (state, source) = store.state_backend().into_source_parts();
    ensure!(
        state
            .read(&path)
            .await?
            .and_then(|value| value.as_list().and_then(|items| items.first().cloned()))
            == Some(second)
    );
    let receipt = source
        .inspect(SourceEvidenceInspection {
            claim: SourceClaim {
                installation_id: "installation",
                projection_id: "source",
                scope_epoch: 2,
                stream_epoch: None,
                event_id: "first",
                claim_id: SourceClaimId::from_bytes([1; 16]),
            },
        })
        .await?;
    ensure!(matches!(receipt, SourceClaimEvidence::Committed(receipt) if receipt.sink == path));
    Ok(())
}

#[tokio::test]
async fn segmented_source_sink_is_one_bounded_logical_state_row() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("segmented-source.redb");
    let path = sink()?;
    let cap = capacity(8, OverflowPolicy::DropOldest);
    let incoming = TaintSet::of(TaintSource::ModelOutput);
    let original = TaintSet::of(TaintSource::Protected { path: path.clone() });
    let expected = Value::list(vec![
        Value::integer(1),
        Value::integer(2),
        Value::integer(3),
    ]);
    {
        let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
        let (state, source) = store.state_backend().into_source_parts();
        install_default(source.as_ref(), &path, &cap, None).await?;
        state
            .write_set_tainted(
                &path,
                Value::list(vec![Value::integer(1), Value::integer(2)]),
                original.clone(),
            )
            .await?;
        ensure!(
            source
                .commit(commit(
                    "segmented",
                    1,
                    &path,
                    &cap,
                    &Value::integer(3),
                    &incoming,
                    100,
                    None,
                    None,
                ))
                .await?
                == SourceCommitOutcome::Accepted
        );
        let (store, state, source, layout) =
            inspect_sink_and_reopen(&file, &path, RedbHistory::Full, store, state, source).await?;
        let (marker, count, physical_bytes) = layout.context("missing Source sink")?;
        ensure!(marker.starts_with(b"XSL1") && count == 3);
        ensure!(u64::from_be_bytes(marker[20..28].try_into()?) == count as u64);
        let mut taint = original.clone();
        taint.union(&incoming);
        let current = state.read_tainted(&path).await?;
        let current_value = current
            .value
            .clone()
            .context("logical Source sink missing")?;
        ensure!(current_value == expected && current.taint == taint);
        let too_small = NonZeroUsize::new(physical_bytes - 1).context("bounded size")?;
        let failure = state
            .read_tainted_bounded(&path, too_small)
            .await
            .err()
            .context("undersized read was accepted")?;
        ensure!(
            matches!(failure.error, xolotl_state::StateError::PointTooLarge(row) if row.encoded_bytes == physical_bytes && !row.provenance_observed)
        );
        ensure!(failure.taint.is_pristine());
        ensure!(
            state
                .read_tainted_bounded(&path, NonZeroUsize::new(physical_bytes).context("size")?)
                .await?
                == current
        );
        let mut scan = xolotl_state::StateScan::new(path.clone());
        scan.limits.encoded_bytes = NonZeroUsize::new(physical_bytes).context("page size")?;
        let page = state.query(&scan).await?;
        ensure!(
            page.entries
                == [(
                    path.clone(),
                    xolotl_types::TaintedValue::new(current_value, current.taint)
                )]
        );
        ensure!(page.encoded_bytes == physical_bytes);
        let history = state
            .history(&StateHistoryQuery::new(path.clone(), 0, i64::MAX))
            .await?;
        let at = history
            .entries
            .last()
            .context("missing Source history")?
            .at_millis;
        ensure!(state.read_at(&path, at).await?.value == Some(expected.clone()));
        drop(source);
        drop(state);
        drop(store);
    }
    let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
    let state = store.state_backend();
    ensure!(state.read(&path).await? == Some(expected));
    Ok(())
}

#[tokio::test]
async fn source_drop_oldest_recovers_ordinary_list_above_source_byte_limit() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("oversized-ordinary-list.redb");
    let store = RedbStore::open(&file)?;
    let (state, source) = store.state_backend().into_source_parts();
    let path = sink()?;
    let capacity_before = capacity(70, OverflowPolicy::DropOldest);
    install_default(source.as_ref(), &path, &capacity_before, None).await?;
    let resident = Value::string("x".repeat(1024 * 1024));
    state
        .write_set(&path, Value::list(vec![resident; 70]))
        .await?;
    let (store, state, source, original) =
        inspect_sink_and_reopen(&file, &path, RedbHistory::CurrentOnly, store, state, source)
            .await?;
    let original = original.context("ordinary List representation")?;
    ensure!(original.1 == 70 && original.2 > 64 * 1024 * 1024);
    let payload = Value::integer(7);
    let taint = TaintSet::pristine();
    ensure!(
        source
            .commit(commit(
                "event",
                1,
                &path,
                &capacity_before,
                &payload,
                &taint,
                100,
                None,
                None,
            ))
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::CapacityExceeded)
    );
    let (store, state, source, rejected) =
        inspect_sink_and_reopen(&file, &path, RedbHistory::CurrentOnly, store, state, source)
            .await?;
    ensure!(
        rejected == Some(original),
        "rejected pruning changed the current List"
    );
    let previous = source
        .load_installation("installation")
        .await?
        .context("installation")?;
    let capacity_after = capacity(1, OverflowPolicy::DropOldest);
    let epoch = install_source(
        source.as_ref(),
        "installation",
        "source",
        &path,
        &capacity_after,
        1024,
        None,
        Some(previous.revision()),
    )
    .await?;
    let mut request = commit(
        "event",
        2,
        &path,
        &capacity_after,
        &payload,
        &taint,
        101,
        None,
        None,
    );
    request.claim.scope_epoch = epoch;
    ensure!(source.commit(request).await? == SourceCommitOutcome::Accepted);
    ensure!(state.read(&path).await? == Some(Value::list(vec![payload])));
    let (_store, _state, _source, accepted) =
        inspect_sink_and_reopen(&file, &path, RedbHistory::CurrentOnly, store, state, source)
            .await?;
    let accepted = accepted.context("accepted sink")?;
    ensure!(accepted.1 == 1 && accepted.2 < 1024);
    Ok(())
}

#[tokio::test]
async fn ordinary_state_mutations_preserve_lists_and_clear_replaced_items() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("ordinary-source-state.redb");
    let mut store = RedbStore::open(&file)?;
    let (mut state, mut source) = store.state_backend().into_source_parts();
    let path = sink()?;
    let cap = capacity(16, OverflowPolicy::DropOldest);
    let taint = TaintSet::pristine();
    macro_rules! physical {
        () => {{
            let (next_store, next_state, next_source, layout) = inspect_sink_and_reopen(
                &file,
                &path,
                RedbHistory::CurrentOnly,
                store,
                state,
                source,
            )
            .await?;
            store = next_store;
            state = next_state;
            source = next_source;
            layout
        }};
    }
    install_default(source.as_ref(), &path, &cap, None).await?;
    state
        .write_set(
            &path,
            Value::list(vec![Value::integer(1), Value::integer(2)]),
        )
        .await?;
    for (event_id, claim_id, value) in [("one", 1, 3)] {
        ensure!(
            source
                .commit(commit(
                    event_id,
                    claim_id,
                    &path,
                    &cap,
                    &Value::integer(value),
                    &taint,
                    100,
                    None,
                    None
                ))
                .await?
                == SourceCommitOutcome::Accepted
        );
    }
    let (before_append, count, _) = physical!().context("sink")?;
    ensure!(count == 3);

    state.write_append(&path, Value::integer(4)).await?;
    let (row, items, _) = physical!().context("sink")?;
    ensure!(row.starts_with(b"XSL1") && items == 4);
    ensure!(row[4..12] == before_append[4..12]);
    ensure!(
        source
            .commit(commit(
                "two",
                2,
                &path,
                &cap,
                &Value::integer(5),
                &taint,
                101,
                None,
                None
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    let (after_source, count, _) = physical!().context("sink")?;
    ensure!(count == 5 && after_source[4..12] == row[4..12]);

    let five = Value::list((1..=5).map(Value::integer).collect());
    ensure!(
        state
            .write_cas(&path, Some(Value::null()), Value::null())
            .await
            .is_err()
    );
    let (_, count, physical_bytes) = physical!().context("sink")?;
    ensure!(count == 5);
    let failure = state
        .write_cas_bounded(
            &path,
            Some(five.clone()),
            Value::null(),
            NonZeroUsize::new(physical_bytes - 1).context("short budget")?,
        )
        .await
        .err()
        .context("undersized comparison was accepted")?;
    ensure!(
        matches!(failure.error, xolotl_state::StateError::PointTooLarge(row) if row.encoded_bytes == physical_bytes && !row.provenance_observed)
    );
    ensure!(physical!().context("sink")?.1 == 5);
    state
        .write_cas_bounded(
            &path,
            Some(five),
            Value::list(vec![Value::integer(7)]),
            NonZeroUsize::new(physical_bytes).context("exact budget")?,
        )
        .await?;
    ensure!(physical!().context("sink")?.1 == 1);
    ensure!(
        source
            .commit(commit(
                "three",
                3,
                &path,
                &cap,
                &Value::integer(8),
                &taint,
                102,
                None,
                None
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(physical!().context("sink")?.1 == 2);

    state
        .write_merge(
            &path,
            Value::list(vec![Value::integer(9)]),
            xolotl_types::MergeRule::Deep,
        )
        .await?;
    ensure!(physical!().context("sink")?.1 == 3);
    ensure!(
        state.read(&path).await?
            == Some(Value::list(vec![
                Value::integer(7),
                Value::integer(8),
                Value::integer(9)
            ]))
    );
    ensure!(
        source
            .commit(commit(
                "four",
                4,
                &path,
                &cap,
                &Value::integer(10),
                &taint,
                103,
                None,
                None
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(physical!().context("sink")?.1 == 4);

    ensure!(
        state
            .write_compare_delete(&path, Some(Value::null()))
            .await
            .is_err()
    );
    ensure!(physical!().context("sink")?.1 == 4);
    let four = Value::list((7..=10).map(Value::integer).collect());
    state.write_compare_delete(&path, Some(four)).await?;
    ensure!(physical!().is_none());
    ensure!(
        source
            .commit(commit(
                "five",
                5,
                &path,
                &cap,
                &Value::integer(11),
                &taint,
                104,
                None,
                None
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(physical!().context("sink")?.1 == 1);

    state.write_set(&path, Value::integer(12)).await?;
    ensure!(physical!().context("sink")?.1 == 0);
    ensure!(
        source
            .commit(commit(
                "one",
                1,
                &path,
                &cap,
                &Value::integer(3),
                &taint,
                105,
                None,
                None
            ))
            .await?
            == SourceCommitOutcome::Duplicate
    );
    ensure!(state.read(&path).await? == Some(Value::integer(12)));
    ensure!(physical!().context("sink")?.1 == 0);
    ensure!(
        source
            .commit(commit(
                "mismatch",
                6,
                &path,
                &cap,
                &Value::integer(13),
                &taint,
                105,
                None,
                None
            ))
            .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::SinkTypeMismatch)
    );
    state
        .write_set(&path, Value::list(vec![Value::integer(13)]))
        .await?;
    ensure!(
        source
            .commit(commit(
                "six",
                7,
                &path,
                &cap,
                &Value::integer(14),
                &taint,
                106,
                None,
                None
            ))
            .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(physical!().context("sink")?.1 == 2);
    state.write_delete(&path).await?;
    ensure!(physical!().is_none());
    drop(source);
    drop(state);
    drop(store);
    Ok(())
}

#[tokio::test]
async fn retained_event_decision_recovers_claim_without_query_audit() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("state.redb");
    {
        let store = RedbStore::open(&db_path)?;
        let (_state, source) = store.state_backend().into_source_parts();
        let path = sink()?;
        let cap = capacity(4, OverflowPolicy::DropOldest);
        let payload = Value::integer(42);
        let taint = TaintSet::pristine();
        install_default(source.as_ref(), &path, &cap, None).await?;
        ensure!(
            source
                .commit(commit(
                    "accepted", 7, &path, &cap, &payload, &taint, 100, None, None
                ))
                .await?
                == SourceCommitOutcome::Accepted
        );
        for (event_id, expected) in [("accepted", true), ("unknown", false)] {
            let evidence = source
                .inspect_event(SourceEventDecisionInspection {
                    installation_id: "installation",
                    projection_id: "source",
                    scope_epoch: FIRST_SCOPE_EPOCH,
                    stream_epoch: None,
                    event_id,
                })
                .await?;
            match evidence {
                SourceClaimEvidence::Committed(receipt) if expected => {
                    ensure!(receipt.event_id == event_id);
                    ensure!(receipt.claim_id == SourceClaimId::from_bytes([7; 16]));
                    ensure!(receipt.sink == path);
                }
                SourceClaimEvidence::Unproven if !expected => {}
                _ => anyhow::bail!("unexpected event decision inspection result"),
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn retained_event_without_receipt_is_an_error_not_negative_evidence() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("state.redb");
    {
        let store = RedbStore::open(&db_path)?;
        let (_state, source) = store.state_backend().into_source_parts();
        let path = sink()?;
        let cap = capacity(4, OverflowPolicy::DropOldest);
        let payload = Value::integer(42);
        let taint = TaintSet::pristine();
        install_default(source.as_ref(), &path, &cap, None).await?;
        ensure!(
            source
                .commit(commit(
                    "accepted", 7, &path, &cap, &payload, &taint, 100, None, None
                ))
                .await?
                == SourceCommitOutcome::Accepted
        );
    }
    {
        let db = Database::open(&db_path)?;
        let txn = db.begin_write()?;
        {
            let mut table =
                txn.open_table(TableDefinition::<&[u8], &[u8]>::new("source_receipts_v1"))?;
            let key = table
                .first()?
                .context("accepted receipt")?
                .0
                .value()
                .to_vec();
            table.remove(key.as_slice())?;
        }
        txn.commit()?;
    }
    let store = RedbStore::open(&db_path)?;
    let (state, source) = store.state_backend().into_source_parts();
    let failure = source
        .inspect_event(SourceEventDecisionInspection {
            installation_id: "installation",
            projection_id: "source",
            scope_epoch: 2,
            stream_epoch: None,
            event_id: "accepted",
        })
        .await;
    ensure!(failure.is_err());
    drop(source);
    drop(state);
    drop(store);
    let db = Database::open(&db_path)?;
    let txn = db.begin_read()?;
    ensure!(
        txn.open_table(TableDefinition::<&[u8], &[u8]>::new("source_receipts_v1"))?
            .is_empty()?
    );
    ensure!(
        txn.open_table(TableDefinition::<&[u8], &[u8]>::new("source_meta_v1"))?
            .len()?
            == 1
    );
    Ok(())
}

#[tokio::test]
async fn source_scope_epoch_fences_stale_commits_before_dedupe_and_survives_reinstall()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("source-authority.redb");
    let store = RedbStore::open(&file)?;
    let (state, source) = store.state_backend().into_source_parts();
    let path = sink()?;
    let capacity = capacity(8, OverflowPolicy::DropOldest);
    let payload = Value::integer(1);
    let taint = TaintSet::pristine();
    let first_epoch = install_source(
        source.as_ref(),
        "installation",
        "source",
        &path,
        &capacity,
        1024,
        None,
        None,
    )
    .await?;
    let first = source
        .load_installation("installation")
        .await?
        .context("installation missing")?;
    let mut original = commit(
        "same-event",
        1,
        &path,
        &capacity,
        &payload,
        &taint,
        100,
        None,
        None,
    );
    original.claim.scope_epoch = first_epoch;
    ensure!(source.commit(original).await? == SourceCommitOutcome::Accepted);

    ensure!(
        source
            .compare_install(first.definition.clone(), None)
            .await?
            == ExternalInstallationMutation::Conflict {
                current: Some(first.revision())
            }
    );
    ensure!(source.load_installation("installation").await? == Some(first.clone()));

    let second_epoch = install_source(
        source.as_ref(),
        "installation",
        "source",
        &path,
        &capacity,
        1024,
        None,
        Some(first.revision()),
    )
    .await?;
    let second = source
        .load_installation("installation")
        .await?
        .context("updated installation missing")?;
    ensure!(second.installation_epoch == first.installation_epoch && second_epoch != first_epoch);
    let mut stale = commit(
        "same-event",
        2,
        &path,
        &capacity,
        &payload,
        &taint,
        101,
        None,
        None,
    );
    stale.claim.scope_epoch = first_epoch;
    ensure!(
        source.commit(stale).await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::ScopeInactive)
    );
    let wrong_sink = Path::parse("state://events/external/wrong/sink")?;
    let mut mismatched = commit(
        "same-event",
        2,
        &wrong_sink,
        &capacity,
        &payload,
        &taint,
        101,
        None,
        None,
    );
    mismatched.claim.scope_epoch = second_epoch;
    ensure!(
        source.commit(mismatched).await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::DeclarationMismatch)
    );
    ensure!(
        state
            .read(&path)
            .await?
            .and_then(|value| value.as_list().map(|items| items.len()))
            == Some(1)
    );
    let mut admitted = commit(
        "same-event",
        2,
        &path,
        &capacity,
        &payload,
        &taint,
        101,
        None,
        None,
    );
    admitted.claim.scope_epoch = second_epoch;
    ensure!(source.commit(admitted).await? == SourceCommitOutcome::Accepted);

    ensure!(
        source
            .compare_retire(
                "installation",
                ExternalInstallationRevision {
                    version: 1,
                    ..second.revision()
                },
            )
            .await?
            == ExternalInstallationMutation::Conflict {
                current: Some(second.revision())
            }
    );
    ensure!(
        source
            .compare_retire("installation", second.revision())
            .await?
            == ExternalInstallationMutation::Applied(None)
    );
    let mut retired = commit(
        "same-event",
        3,
        &path,
        &capacity,
        &payload,
        &taint,
        102,
        None,
        None,
    );
    retired.claim.scope_epoch = second_epoch;
    ensure!(
        source.commit(retired).await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::ScopeInactive)
    );
    let third_epoch = install_source(
        source.as_ref(),
        "installation",
        "source",
        &path,
        &capacity,
        1024,
        None,
        None,
    )
    .await?;
    let third = source
        .load_installation("installation")
        .await?
        .context("reinstalled installation missing")?;
    ensure!(third.installation_epoch != first.installation_epoch && third_epoch != second_epoch);
    drop(source);
    drop(state);
    drop(store);
    let reopened = RedbStore::open(&file)?;
    let (state, source) = reopened.state_backend().into_source_parts();
    ensure!(source.load_installation("installation").await?.as_ref() == Some(&third));
    ensure!(
        source
            .compare_retire("installation", first.revision())
            .await?
            == ExternalInstallationMutation::Conflict {
                current: Some(third.revision())
            }
    );
    ensure!(
        source
            .compare_install(first.definition.clone(), Some(first.revision()))
            .await?
            == ExternalInstallationMutation::Conflict {
                current: Some(third.revision())
            }
    );
    ensure!(source.load_installation("installation").await? == Some(third));
    let mut old = commit(
        "same-event",
        4,
        &path,
        &capacity,
        &payload,
        &taint,
        103,
        None,
        None,
    );
    old.claim.scope_epoch = first_epoch;
    ensure!(
        source.commit(old).await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::ScopeInactive)
    );
    let mut current = commit(
        "same-event",
        4,
        &path,
        &capacity,
        &payload,
        &taint,
        103,
        None,
        None,
    );
    current.claim.scope_epoch = third_epoch;
    ensure!(source.commit(current).await? == SourceCommitOutcome::Accepted);
    ensure!(
        state
            .read(&path)
            .await?
            .and_then(|value| value.as_list().map(|items| items.len()))
            == Some(3)
    );
    Ok(())
}
