use anyhow::{Context, ensure};
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::{num::NonZeroUsize, sync::Arc};
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, SourceClaim, SourceClaimId,
    SourceCommit, SourceCommitOutcome, SourceCommitRejection, SourceEventCommit,
    SourceEventMaintenance, SourceMaintenance, SourceStore, SourceStreamLifecycle,
    SourceStreamOpen, SourceStreamOpenOutcome, SourceStreamPosition, SourceStreamRetire,
    SourceStreamRetireOutcome, SourceStreamScope,
};
use xolotl_state::{Backend, InMemoryBackend, InMemoryOptions};
use xolotl_storage_redb::{RedbOptions, RedbStore};
use xolotl_types::{
    Path, Purity, TaintSet, Transport, TrustLevel, Value,
    external::{
        EventSource, ExternalInstallationDef, ExternalProjectionDef, OverflowPolicy, Role,
        StreamCapacity,
    },
};

fn sink() -> anyhow::Result<Path> {
    Path::parse("state://events/external/installation/source").map_err(Into::into)
}

async fn install_source<S: ExternalInstallationAuthority + ?Sized>(
    source: &S,
) -> anyhow::Result<u64> {
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
                sink: sink()?,
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 128,
                capacity: StreamCapacity {
                    max_events: 16,
                    on_overflow: OverflowPolicy::DropOldest,
                },
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
        source.compare_install(definition, None).await?
    else {
        anyhow::bail!("Source installation was not applied")
    };
    record.scope_epoch("source").context("Source scope missing")
}

fn scope(epoch: u64, stream_id: &str) -> SourceStreamScope<'_> {
    SourceStreamScope {
        installation_id: "installation",
        projection_id: "source",
        scope_epoch: epoch,
        stream_id,
    }
}

async fn open<S: SourceStreamLifecycle + ?Sized>(
    source: &S,
    scope_epoch: u64,
    stream_id: &str,
    open_id: &str,
) -> anyhow::Result<xolotl_source::SourceStreamSnapshot> {
    let stream = scope(scope_epoch, stream_id);
    let current = source
        .inspect_stream(stream)
        .await?
        .context("Source scope inactive")?;
    let SourceStreamOpenOutcome::Opened(snapshot) = source
        .open_stream(SourceStreamOpen {
            stream,
            open_id,
            expected_revision: current.revision,
        })
        .await?
    else {
        anyhow::bail!("Source stream did not open")
    };
    Ok(snapshot)
}

async fn commit<S: SourceEventCommit + ?Sized>(
    source: &S,
    scope_epoch: u64,
    stream_id: &str,
    stream_epoch: u64,
    event_id: &str,
    seq: u64,
) -> anyhow::Result<SourceCommitOutcome> {
    commit_payload(
        source,
        scope_epoch,
        stream_id,
        stream_epoch,
        event_id,
        event_id,
        seq,
    )
    .await
}

async fn commit_payload<S: SourceEventCommit + ?Sized>(
    source: &S,
    scope_epoch: u64,
    stream_id: &str,
    stream_epoch: u64,
    event_id: &str,
    payload_text: &str,
    seq: u64,
) -> anyhow::Result<SourceCommitOutcome> {
    let sink = sink()?;
    let capacity = StreamCapacity {
        max_events: 16,
        on_overflow: OverflowPolicy::DropOldest,
    };
    let payload = Value::string(payload_text.into());
    let taint = TaintSet::pristine();
    Ok(source
        .commit(SourceCommit {
            claim: SourceClaim {
                installation_id: "installation",
                projection_id: "source",
                scope_epoch,
                stream_epoch: Some(stream_epoch),
                event_id,
                claim_id: SourceClaimId::from_bytes([seq as u8; 16]),
            },
            received_at_ms: 100,
            decision_clock: std::sync::Arc::new({
                let decision_at_ms = 100;
                move || decision_at_ms
            }),
            dedupe_window_ms: 1000,
            sink: &sink,
            capacity: &capacity,
            max_inline_payload_bytes: 128,
            payload: &payload,
            taint: &taint,
            stream: Some(SourceStreamPosition {
                stream_id,
                stream_epoch,
                seq,
            }),
            rate_limit: None,
        })
        .await?)
}

async fn commit_unordered<S: SourceEventCommit + ?Sized>(
    source: &S,
    scope_epoch: u64,
    event_id: &str,
    payload_text: &str,
) -> anyhow::Result<SourceCommitOutcome> {
    let sink = sink()?;
    let capacity = StreamCapacity {
        max_events: 16,
        on_overflow: OverflowPolicy::DropOldest,
    };
    let payload = Value::string(payload_text.into());
    let taint = TaintSet::pristine();
    Ok(source
        .commit(SourceCommit {
            claim: SourceClaim {
                installation_id: "installation",
                projection_id: "source",
                scope_epoch,
                stream_epoch: None,
                event_id,
                claim_id: SourceClaimId::from_bytes([9; 16]),
            },
            received_at_ms: 100,
            decision_clock: std::sync::Arc::new({
                let decision_at_ms = 100;
                move || decision_at_ms
            }),
            dedupe_window_ms: 1000,
            sink: &sink,
            capacity: &capacity,
            max_inline_payload_bytes: 128,
            payload: &payload,
            taint: &taint,
            stream: None,
            rate_limit: None,
        })
        .await?)
}

fn active_epoch(snapshot: &xolotl_source::SourceStreamSnapshot) -> anyhow::Result<u64> {
    Ok(snapshot
        .active
        .as_ref()
        .context("active stream missing")?
        .stream_epoch)
}

async fn event_id_conflicts_are_side_effect_free<S: SourceStore + ?Sized>(
    source: &S,
    state: &Backend,
) -> anyhow::Result<()> {
    let scope_epoch = install_source(source).await?;
    let opened = open(source, scope_epoch, "ordered", "event-id-open").await?;
    let stream_epoch = active_epoch(&opened)?;
    ensure!(
        commit_payload(
            source,
            scope_epoch,
            "ordered",
            stream_epoch,
            "shared",
            "first",
            1
        )
        .await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(
        commit_payload(
            source,
            scope_epoch,
            "ordered",
            stream_epoch,
            "shared",
            "first",
            1
        )
        .await?
            == SourceCommitOutcome::Duplicate
    );
    ensure!(
        commit_payload(
            source,
            scope_epoch,
            "ordered",
            stream_epoch,
            "shared",
            "first",
            2
        )
        .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::EventIdConflict)
    );
    ensure!(
        commit_payload(
            source,
            scope_epoch,
            "ordered",
            stream_epoch,
            "shared",
            "changed",
            1
        )
        .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::EventIdConflict)
    );
    let position = source
        .inspect_stream(scope(scope_epoch, "ordered"))
        .await?
        .context("scope missing")?;
    ensure!(position.active.as_ref().context("stream missing")?.last_seq == 1);
    ensure!(
        state
            .read(&sink()?)
            .await?
            .and_then(|value| value.as_list().map(|items| items.len()))
            == Some(1)
    );
    ensure!(
        commit_payload(
            source,
            scope_epoch,
            "ordered",
            stream_epoch,
            "next",
            "second",
            2
        )
        .await?
            == SourceCommitOutcome::Accepted
    );

    ensure!(
        commit_unordered(source, scope_epoch, "free", "same").await?
            == SourceCommitOutcome::Accepted
    );
    ensure!(
        commit_unordered(source, scope_epoch, "free", "same").await?
            == SourceCommitOutcome::Duplicate
    );
    ensure!(
        commit_unordered(source, scope_epoch, "free", "other").await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::EventIdConflict)
    );
    ensure!(
        state
            .read(&sink()?)
            .await?
            .and_then(|value| value.as_list().map(|items| items.len()))
            == Some(3)
    );
    Ok(())
}

async fn oversized_payload_is_a_deterministic_rejection<S: SourceStore + ?Sized>(
    source: &S,
    state: &Backend,
) -> anyhow::Result<()> {
    let scope_epoch = install_source(source).await?;
    let payload = "x".repeat(200);
    ensure!(
        commit_unordered(source, scope_epoch, "too-large", &payload).await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::PayloadTooLarge)
    );
    ensure!(state.read(&sink()?).await?.is_none());
    ensure!(
        commit_unordered(source, scope_epoch, "next", "small").await?
            == SourceCommitOutcome::Accepted
    );
    Ok(())
}

#[tokio::test]
async fn memory_oversized_source_payload_does_not_mutate_sink() -> anyhow::Result<()> {
    let (state, source) = InMemoryBackend::new().into_source_parts();
    oversized_payload_is_a_deterministic_rejection(source.as_ref(), &state).await
}

#[tokio::test]
async fn redb_oversized_source_payload_does_not_mutate_sink() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("payload-limit.redb"))?;
    let (state, source) = store.state_backend().into_source_parts();
    oversized_payload_is_a_deterministic_rejection(source.as_ref(), &state).await
}

#[tokio::test]
async fn memory_event_id_conflicts_do_not_relabel_accepted_events() -> anyhow::Result<()> {
    let (state, source) = InMemoryBackend::new().into_source_parts();
    event_id_conflicts_are_side_effect_free(source.as_ref(), &state).await
}

#[tokio::test]
async fn redb_event_id_conflicts_do_not_relabel_accepted_events() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("event-id.redb"))?;
    let (state, source) = store.state_backend().into_source_parts();
    event_id_conflicts_are_side_effect_free(source.as_ref(), &state).await
}

#[tokio::test]
async fn redb_event_decision_rejects_unknown_or_oversized_rows() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    for case in ["unknown", "oversized"] {
        let path = dir.path().join(format!("event-{case}.redb"));
        let scope_epoch;
        {
            let store = RedbStore::open(&path)?;
            let source = store.state_backend();
            scope_epoch = install_source(&source).await?;
            ensure!(
                commit_unordered(&source, scope_epoch, "event", "payload").await?
                    == SourceCommitOutcome::Accepted
            );
        }
        {
            let db = Database::create(&path)?;
            let txn = db.begin_write()?;
            let mut table =
                txn.open_table(TableDefinition::<&[u8], &[u8]>::new("source_meta_v1"))?;
            let (key, bytes) = {
                let mut rows = table.range::<&[u8]>(b"E".as_slice()..b"F".as_slice())?;
                let (key, row) = rows.next().context("event decision row missing")??;
                (key.value().to_vec(), row.value().to_vec())
            };
            let changed = if case == "unknown" {
                let mut record: serde_json::Value = serde_json::from_slice(&bytes)?;
                record
                    .as_object_mut()
                    .context("event row is not an object")?
                    .insert("unexpected".into(), serde_json::Value::Bool(true));
                serde_json::to_vec(&record)?
            } else {
                vec![b'x'; 2049]
            };
            table.insert(key.as_slice(), changed.as_slice())?;
            drop(table);
            txn.commit()?;
        }
        let store = RedbStore::open(&path)?;
        let source = store.state_backend();
        ensure!(
            matches!(commit_unordered(&source, scope_epoch, "event", "payload").await,
            Err(error) if error.to_string().contains("Source")),
            "case {case} was accepted"
        );
    }
    Ok(())
}

#[tokio::test]
async fn maximum_stream_name_event_decision_survives_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("large-event.redb");
    let stream_id = "\0".repeat(xolotl_source::MAX_ID_BYTES);
    let scope_epoch;
    let stream_epoch;
    {
        let store = RedbStore::open(&path)?;
        let source = store.state_backend();
        scope_epoch = install_source(&source).await?;
        stream_epoch = active_epoch(&open(&source, scope_epoch, &stream_id, "large-open").await?)?;
        ensure!(
            commit(&source, scope_epoch, &stream_id, stream_epoch, "event", 1).await?
                == SourceCommitOutcome::Accepted
        );
    }
    let store = RedbStore::open(&path)?;
    let source = store.state_backend();
    ensure!(
        commit(&source, scope_epoch, &stream_id, stream_epoch, "event", 1).await?
            == SourceCommitOutcome::Duplicate
    );
    Ok(())
}

fn redb_stream_count(path: &std::path::Path) -> anyhow::Result<u64> {
    let db = Database::create(path)?;
    let txn = db.begin_read()?;
    let table = TableDefinition::<&str, u64>::new("source_sequence_meta_v1");
    Ok(txn
        .open_table(table)?
        .get("retained_stream_count")?
        .context("Source stream count missing")?
        .value())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn memory_open_is_atomic_and_retirement_reuses_quota() -> anyhow::Result<()> {
    let source = Arc::new(InMemoryBackend::with_options(InMemoryOptions {
        source_stream_limit: NonZeroUsize::new(2).context("nonzero limit")?,
        ..InMemoryOptions::default()
    })?);
    let scope_epoch = install_source(source.as_ref()).await?;
    let first = open(source.as_ref(), scope_epoch, "first", "first-open").await?;
    let revision = first.revision;
    let candidates = ["second", "third"].map(|id| {
        let source = Arc::clone(&source);
        tokio::spawn(async move {
            source
                .open_stream(SourceStreamOpen {
                    stream: scope(scope_epoch, id),
                    open_id: id,
                    expected_revision: revision,
                })
                .await
        })
    });
    let [first, second] = candidates;
    let outcomes = [first.await??, second.await??];
    ensure!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, SourceStreamOpenOutcome::Opened(_)))
            .count()
            == 1
    );
    ensure!(
        outcomes
            .iter()
            .any(|outcome| matches!(outcome, SourceStreamOpenOutcome::RevisionConflict { .. }))
    );
    let opened_id = if matches!(outcomes[0], SourceStreamOpenOutcome::Opened(_)) {
        "second"
    } else {
        "third"
    };
    let opened = source
        .inspect_stream(scope(scope_epoch, opened_id))
        .await?
        .context("scope missing")?;
    let second_epoch = active_epoch(&opened)?;
    ensure!(
        source
            .open_stream(SourceStreamOpen {
                stream: scope(scope_epoch, "overflow"),
                open_id: "overflow",
                expected_revision: opened.revision,
            })
            .await?
            == SourceStreamOpenOutcome::QuotaExceeded
    );
    ensure!(
        source
            .retire_stream(SourceStreamRetire {
                stream: scope(scope_epoch, opened_id),
                stream_epoch: second_epoch,
            })
            .await?
            == SourceStreamRetireOutcome::Retired {
                revision: opened.revision + 1
            }
    );
    let reopened = open(source.as_ref(), scope_epoch, opened_id, "reopen").await?;
    let new_epoch = active_epoch(&reopened)?;
    ensure!(new_epoch > second_epoch);
    ensure!(
        commit(
            source.as_ref(),
            scope_epoch,
            opened_id,
            second_epoch,
            "same",
            1
        )
        .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::StreamEpochMismatch {
                active_epoch: new_epoch
            })
    );
    ensure!(
        commit(
            source.as_ref(),
            scope_epoch,
            opened_id,
            new_epoch,
            "same",
            1
        )
        .await?
            == SourceCommitOutcome::Accepted
    );
    Ok(())
}

async fn race_commit_and_retire<S>(source: Arc<S>, scope_epoch: u64) -> anyhow::Result<()>
where
    S: SourceEventCommit + SourceStreamLifecycle + Send + Sync + 'static,
{
    let opened = open(source.as_ref(), scope_epoch, "race", "race-first").await?;
    let first_epoch = active_epoch(&opened)?;
    let event_task = {
        let source = Arc::clone(&source);
        tokio::spawn(async move {
            commit(
                source.as_ref(),
                scope_epoch,
                "race",
                first_epoch,
                "same-event",
                1,
            )
            .await
        })
    };
    let retire_task = {
        let source = Arc::clone(&source);
        tokio::spawn(async move {
            source
                .retire_stream(SourceStreamRetire {
                    stream: scope(scope_epoch, "race"),
                    stream_epoch: first_epoch,
                })
                .await
        })
    };
    let committed = event_task.await??;
    let retired = retire_task.await??;
    ensure!(matches!(retired, SourceStreamRetireOutcome::Retired { .. }));
    ensure!(matches!(
        committed,
        SourceCommitOutcome::Accepted
            | SourceCommitOutcome::Rejected(SourceCommitRejection::StreamInactive)
    ));
    let reopened = open(source.as_ref(), scope_epoch, "race", "race-second").await?;
    let second_epoch = active_epoch(&reopened)?;
    ensure!(second_epoch > first_epoch);
    ensure!(
        commit(
            source.as_ref(),
            scope_epoch,
            "race",
            first_epoch,
            "same-event",
            1
        )
        .await?
            == SourceCommitOutcome::Rejected(SourceCommitRejection::StreamEpochMismatch {
                active_epoch: second_epoch
            })
    );
    ensure!(
        commit(
            source.as_ref(),
            scope_epoch,
            "race",
            second_epoch,
            "same-event",
            1
        )
        .await?
            == SourceCommitOutcome::Accepted
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn memory_commit_and_retire_have_one_linearization_order() -> anyhow::Result<()> {
    let source = Arc::new(InMemoryBackend::new());
    let scope_epoch = install_source(source.as_ref()).await?;
    race_commit_and_retire(source, scope_epoch).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redb_commit_and_retire_have_one_linearization_order() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("race.redb"))?;
    let source = Arc::new(store.state_backend());
    let scope_epoch = install_source(source.as_ref()).await?;
    race_commit_and_retire(source, scope_epoch).await
}

#[tokio::test]
async fn redb_restart_preserves_epoch_revision_and_committed_position() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("source.redb");
    let scope_epoch;
    let old_epoch;
    let opened_at_revision;
    {
        let store = RedbStore::open(&path)?;
        let source = store.state_backend();
        scope_epoch = install_source(&source).await?;
        let opened = open(&source, scope_epoch, "same", "open-a").await?;
        old_epoch = active_epoch(&opened)?;
        opened_at_revision = opened.active.context("stream missing")?.opened_at_revision;
        ensure!(
            commit(&source, scope_epoch, "same", old_epoch, "same-event", 1).await?
                == SourceCommitOutcome::Accepted
        );
    }
    ensure!(redb_stream_count(&path)? == 1);
    {
        let store = RedbStore::open(&path)?;
        let source = store.state_backend();
        let resumed = source
            .inspect_stream(scope(scope_epoch, "same"))
            .await?
            .context("scope missing")?;
        ensure!(resumed.active.as_ref().context("stream missing")?.last_seq == 1);
        let retry = source
            .open_stream(SourceStreamOpen {
                stream: scope(scope_epoch, "same"),
                open_id: "open-a",
                expected_revision: opened_at_revision,
            })
            .await?;
        ensure!(
            matches!(retry, SourceStreamOpenOutcome::Opened(snapshot) if active_epoch(&snapshot)? == old_epoch)
        );
        ensure!(
            source
                .retire_stream(SourceStreamRetire {
                    stream: scope(scope_epoch, "same"),
                    stream_epoch: old_epoch,
                })
                .await?
                == SourceStreamRetireOutcome::Retired {
                    revision: resumed.revision + 1
                }
        );
        let reopened = open(&source, scope_epoch, "same", "open-b").await?;
        let new_epoch = active_epoch(&reopened)?;
        ensure!(new_epoch > old_epoch);
        ensure!(
            commit(&source, scope_epoch, "same", old_epoch, "same-event", 1).await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::StreamEpochMismatch {
                    active_epoch: new_epoch
                })
        );
        ensure!(
            commit(&source, scope_epoch, "same", new_epoch, "same-event", 1).await?
                == SourceCommitOutcome::Accepted
        );
        let stale_retry = source
            .open_stream(SourceStreamOpen {
                stream: scope(scope_epoch, "same"),
                open_id: "open-a",
                expected_revision: opened_at_revision,
            })
            .await?;
        ensure!(
            matches!(stale_retry, SourceStreamOpenOutcome::AlreadyOpen(snapshot)
            if snapshot.revision == reopened.revision
                && snapshot.active.as_ref().is_some_and(|state|
                    state.stream_epoch == new_epoch && state.last_seq == 1))
        );
    }
    ensure!(redb_stream_count(&path)? == 1);
    Ok(())
}

#[tokio::test]
async fn retired_scope_rows_are_reclaimed_across_restart() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("retired.redb");
    let options = RedbOptions {
        source_stream_limit: NonZeroUsize::new(2).context("nonzero limit")?,
        ..RedbOptions::default()
    };
    let definition;
    let revision;
    let old_scope;
    {
        let store = RedbStore::open_with_options(&path, options)?;
        let source = store.state_backend();
        old_scope = install_source(&source).await?;
        let installed = source
            .load_installation("installation")
            .await?
            .context("installation missing")?;
        revision = installed.revision();
        definition = installed.definition;
        open(&source, old_scope, "old-a", "a").await?;
        open(&source, old_scope, "old-b", "b").await?;
        ensure!(
            source.compare_retire("installation", revision).await?
                == ExternalInstallationMutation::Applied(None)
        );
    }
    ensure!(redb_stream_count(&path)? == 2);
    let new_scope;
    {
        let store = RedbStore::open_with_options(&path, options)?;
        let source = store.state_backend();
        let ExternalInstallationMutation::Applied(Some(record)) =
            source.compare_install(definition, None).await?
        else {
            anyhow::bail!("reinstall failed")
        };
        new_scope = record.scope_epoch("source").context("scope missing")?;
        ensure!(new_scope > old_scope);
        ensure!(
            source
                .open_stream(SourceStreamOpen {
                    stream: scope(new_scope, "new"),
                    open_id: "new",
                    expected_revision: 0,
                })
                .await?
                == SourceStreamOpenOutcome::QuotaExceeded
        );
        ensure!(
            source
                .maintain(SourceMaintenance {
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 1;
                        move || decision_at_ms
                    }),
                    limit: NonZeroUsize::MIN,
                })
                .await?
                .removed
                == 1
        );
    }
    ensure!(redb_stream_count(&path)? == 1);
    {
        let store = RedbStore::open_with_options(&path, options)?;
        let source = store.state_backend();
        ensure!(
            source
                .maintain(SourceMaintenance {
                    decision_clock: std::sync::Arc::new({
                        let decision_at_ms = 1;
                        move || decision_at_ms
                    }),
                    limit: NonZeroUsize::MIN,
                })
                .await?
                .removed
                == 1
        );
        open(&source, new_scope, "new", "new").await?;
    }
    ensure!(redb_stream_count(&path)? == 1);
    Ok(())
}

#[tokio::test]
async fn memory_repeated_open_retire_keeps_only_active_rows() -> anyhow::Result<()> {
    let source = InMemoryBackend::with_options(InMemoryOptions {
        source_stream_limit: NonZeroUsize::MIN,
        ..InMemoryOptions::default()
    })?;
    let scope_epoch = install_source(&source).await?;
    for index in 0..1000 {
        let id = format!("stream-{index}");
        let snapshot = open(&source, scope_epoch, &id, &id).await?;
        ensure!(
            source
                .retire_stream(SourceStreamRetire {
                    stream: scope(scope_epoch, &id),
                    stream_epoch: active_epoch(&snapshot)?,
                })
                .await?
                == SourceStreamRetireOutcome::Retired {
                    revision: snapshot.revision + 1
                }
        );
    }
    let last = source
        .inspect_stream(scope(scope_epoch, "stream-999"))
        .await?
        .context("scope missing")?;
    ensure!(last.revision == 2000 && last.active.is_none());
    open(&source, scope_epoch, "again", "again").await?;
    Ok(())
}

#[test]
fn built_in_stream_limit_has_a_finite_upper_bound() -> anyhow::Result<()> {
    ensure!(
        InMemoryBackend::with_options(InMemoryOptions {
            source_stream_limit: NonZeroUsize::new(InMemoryOptions::MAX_SOURCE_STREAM_LIMIT + 1)
                .context("nonzero")?,
            ..InMemoryOptions::default()
        })
        .is_err()
    );
    let dir = tempfile::tempdir()?;
    ensure!(
        RedbStore::open_with_options(
            dir.path().join("invalid.redb"),
            RedbOptions {
                source_stream_limit: NonZeroUsize::new(RedbOptions::MAX_SOURCE_STREAM_LIMIT + 1)
                    .context("nonzero")?,
                ..RedbOptions::default()
            }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn redb_rejects_missing_stream_counter() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("counter.redb");
    RedbStore::open(&path)?;
    let db = Database::create(&path)?;
    let txn = db.begin_write()?;
    let meta = TableDefinition::<&str, u64>::new("source_sequence_meta_v1");
    drop(txn.open_table(meta)?.remove("retained_stream_count")?);
    txn.commit()?;
    drop(db);
    ensure!(RedbStore::open(&path).is_err());
    Ok(())
}

#[tokio::test]
async fn redb_restart_rejects_corrupt_stream_rows_and_metadata() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    for case in ["count", "zero_epoch", "short_row", "epoch_above_highwater"] {
        let path = dir.path().join(format!("{case}.redb"));
        {
            let store = RedbStore::open(&path)?;
            let source = store.state_backend();
            let epoch = install_source(&source).await?;
            open(&source, epoch, "ordered", "open").await?;
        }
        {
            let db = Database::create(&path)?;
            let txn = db.begin_write()?;
            match case {
                "count" => {
                    txn.open_table(TableDefinition::<&str, u64>::new("source_sequence_meta_v1"))?
                        .insert("retained_stream_count", 0)?;
                }
                "epoch_above_highwater" => {
                    txn.open_table(TableDefinition::<&str, u64>::new(
                        "external_installations_meta_v1",
                    ))?
                    .insert("next_authority_epoch", 2)?;
                }
                _ => {
                    let mut table =
                        txn.open_table(TableDefinition::<&[u8], &[u8]>::new("source_meta_v1"))?;
                    let (key, mut bytes) = {
                        let mut rows = table.range::<&[u8]>(b"S".as_slice()..b"T".as_slice())?;
                        let (key, value) = rows.next().context("stream row missing")??;
                        (key.value().to_vec(), value.value().to_vec())
                    };
                    if case == "zero_epoch" {
                        bytes[..8].fill(0);
                    } else {
                        bytes.truncate(8);
                    }
                    table.insert(key.as_slice(), bytes.as_slice())?;
                }
            }
            txn.commit()?;
        }
        ensure!(RedbStore::open(&path).is_err(), "case {case} was accepted");
    }
    Ok(())
}
