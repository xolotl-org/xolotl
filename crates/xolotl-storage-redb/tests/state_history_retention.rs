use anyhow::{Context, Result, ensure};
use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata, TableHandle};
use std::num::NonZeroUsize;
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, SourceClaim, SourceClaimId,
    SourceCommit, SourceCommitOutcome, SourceCommitRejection, SourceStore,
};
use xolotl_state::{
    Backend, InMemoryBackend, InMemoryOptions, MemoryHistory, StateError, StateHistoryQuery,
    StateHistoryTrimLimits, StatePageLimits, TaintedValue,
};
use xolotl_storage_redb::{RedbHistory, RedbStore};
use xolotl_types::{
    Path, Purity, TaintSet, TaintSource, Transport, TrustLevel, Value,
    external::{
        EventSource, ExternalInstallationDef, ExternalProjectionDef, OverflowPolicy, Role,
        StreamCapacity,
    },
};

fn path(text: &str) -> Result<Path> {
    Ok(Path::parse(text)?)
}

#[test]
fn missing_base_table_rejects_reopen_without_recreating_evidence() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let baseline = directory.path().join("complete.redb");
    drop(RedbStore::open_with_history(&baseline, RedbHistory::Full)?);
    let names = {
        let raw = redb::Database::open(&baseline)?;
        raw.begin_read()?
            .list_tables()?
            .map(|table| table.name().to_owned())
            .collect::<Vec<_>>()
    };
    ensure!(
        names
            .iter()
            .any(|name| name == "federation_state_projection_v1")
    );
    for name in names {
        let database = directory.path().join(format!("missing-{name}.redb"));
        std::fs::copy(&baseline, &database)?;
        {
            let raw = redb::Database::open(&database)?;
            let transaction = raw.begin_write()?;
            let table = transaction
                .list_tables()?
                .find(|table| table.name() == name)
                .context("base table")?;
            ensure!(transaction.delete_table(table)?);
            transaction.commit()?;
        }
        let failure = RedbStore::open_with_history(&database, RedbHistory::Full)
            .err()
            .with_context(|| format!("missing {name} admitted"))?;
        ensure!(
            failure
                .to_string()
                .contains(&format!("storage schema table missing: {name}"))
        );
        let raw = redb::Database::open(&database)?;
        ensure!(
            !raw.begin_read()?
                .list_tables()?
                .any(|table| table.name() == name)
        );
    }
    Ok(())
}

#[cfg(not(feature = "federation"))]
#[tokio::test]
async fn persisted_publisher_pin_blocks_trim_without_federation_support() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("unavailable-pin-owner.redb");
    let target = path("state://published/item")?;
    let floor = {
        let store = RedbStore::open_with_history(&database, RedbHistory::Full)?;
        let state = store.state_backend().into_backend();
        state.write_set(&target, Value::integer(17)).await?;
        state
            .history(&StateHistoryQuery::new(target.clone(), 0, i64::MAX))
            .await?
            .entries
            .first()
            .context("history event")?
            .at_millis
            + 1
    };
    let pins = redb::TableDefinition::<&[u8], &[u8]>::new("federation_state_projection_v1");
    {
        let raw = redb::Database::open(&database)?;
        let transaction = raw.begin_write()?;
        let prefix = "state://published";
        let mut row = Vec::new();
        row.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
        row.extend_from_slice(prefix.as_bytes());
        row.extend_from_slice(&0_i64.to_be_bytes());
        row.push(0);
        transaction
            .open_table(pins)?
            .insert([1_u8; 64].as_slice(), row.as_slice())?;
        transaction.commit()?;
    }
    {
        let store = RedbStore::open_with_history(&database, RedbHistory::Full)?;
        let state = store.state_backend().into_backend();
        ensure!(matches!(
            state
                .trim_history_before(floor, StateHistoryTrimLimits::default())
                .await,
            Err(xolotl_state::StateFailure {
                error: StateError::MissingCapability("federation_history_retention"),
                ..
            })
        ));
        ensure!(state.retained_from().await? == i64::MIN);
        ensure!(
            state
                .history(&StateHistoryQuery::new(target.clone(), 0, i64::MAX))
                .await?
                .entries
                .len()
                == 1
        );
        ensure!(state.read(&target).await? == Some(Value::integer(17)));
    }
    {
        let raw = redb::Database::open(&database)?;
        let transaction = raw.begin_write()?;
        ensure!(
            transaction
                .open_table(pins)?
                .remove([1_u8; 64].as_slice())?
                .is_some()
        );
        transaction.commit()?;
    }
    let store = RedbStore::open_with_history(&database, RedbHistory::Full)?;
    let state = store.state_backend().into_backend();
    ensure!(
        state
            .trim_history_before(floor, StateHistoryTrimLimits::default())
            .await?
            .removed_events
            == 1
    );
    Ok(())
}

#[tokio::test]
async fn first_set_replaces_large_baseline_without_charging_prior_bytes() -> Result<()> {
    let (_directory, backends) = backends()?;
    let target = path("state://history-budget/replacement")?;
    for state in backends {
        state
            .write_set_tainted(
                &target,
                Value::bytes(vec![7; 128 * 1024]),
                TaintSet::author(),
            )
            .await?;
        let first = state
            .history(&StateHistoryQuery::new(target.clone(), 0, i64::MAX))
            .await?;
        let floor = first.entries.last().context("initial Set")?.at_millis + 1;
        state
            .trim_history_before(floor, StateHistoryTrimLimits::default())
            .await?;
        state.write_set(&target, Value::integer(2)).await?;
        let replacement = state
            .history(&StateHistoryQuery::new(target.clone(), floor, i64::MAX))
            .await?;
        let timestamp = replacement
            .entries
            .last()
            .context("replacement Set")?
            .at_millis;
        let at = state.read_at(&target, timestamp).await?;
        ensure!(at.value == Some(Value::integer(2)) && at.taint.is_pristine());
        let trimmed = state
            .trim_history_before(
                timestamp + 1,
                StateHistoryTrimLimits {
                    encoded_bytes: NonZeroUsize::new(4096).context("budget")?,
                    ..Default::default()
                },
            )
            .await?;
        ensure!(trimmed.removed_events == 1);
        ensure!(state.read_at(&target, timestamp + 1).await? == at);
    }
    Ok(())
}

#[tokio::test]
async fn first_append_and_delete_still_depend_on_and_charge_large_baselines() -> Result<()> {
    for delete in [false, true] {
        let (_directory, backends) = backends()?;
        let target = path("state://history-budget/dependent")?;
        for state in backends {
            let previous = TaintSet::author();
            state
                .write_set_tainted(
                    &target,
                    Value::list(vec![Value::bytes(vec![7; 128 * 1024])]),
                    previous.clone(),
                )
                .await?;
            let initial = state
                .history(&StateHistoryQuery::new(target.clone(), 0, i64::MAX))
                .await?;
            let floor = initial.entries.last().context("initial Set")?.at_millis + 1;
            state
                .trim_history_before(floor, StateHistoryTrimLimits::default())
                .await?;
            if delete {
                state.write_delete(&target).await?;
            } else {
                state.write_append(&target, Value::integer(2)).await?;
            }
            let remaining = state
                .history(&StateHistoryQuery::new(target.clone(), floor, i64::MAX))
                .await?;
            let timestamp = remaining
                .entries
                .last()
                .context("dependent event")?
                .at_millis;
            let at = state.read_at(&target, timestamp).await?;
            ensure!(at.taint == previous && at == state.read_tainted(&target).await?);
            let failure = state
                .trim_history_before(
                    timestamp + 1,
                    StateHistoryTrimLimits {
                        encoded_bytes: NonZeroUsize::new(4096).context("budget")?,
                        ..Default::default()
                    },
                )
                .await
                .err()
                .context("dependent trim ignored baseline charge")?;
            ensure!(matches!(failure.error, StateError::HistoryTrimLimit { .. }));
            ensure!(state.retained_from().await? == floor);
            ensure!(
                state
                    .history(&StateHistoryQuery::new(target.clone(), floor, i64::MAX))
                    .await?
                    .entries
                    == remaining.entries
            );
            state
                .trim_history_before(timestamp + 1, StateHistoryTrimLimits::default())
                .await?;
            ensure!(state.read_at(&target, timestamp + 1).await? == at);
        }
    }
    Ok(())
}

#[tokio::test]
async fn first_set_never_decodes_prior_baseline_but_append_and_delete_do() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for operation in ["set", "append", "delete"] {
        let file = directory.path().join(format!("baseline-{operation}.redb"));
        let target = path("state://history-budget/corrupt")?;
        let floor;
        let timestamp;
        {
            let state = RedbStore::open_with_history(&file, RedbHistory::Full)?
                .state_backend()
                .into_backend();
            state
                .write_set_tainted(
                    &target,
                    Value::list(vec![Value::integer(1)]),
                    TaintSet::author(),
                )
                .await?;
            let initial = state
                .history(&StateHistoryQuery::new(target.clone(), 0, i64::MAX))
                .await?;
            floor = initial.entries.last().context("initial Set")?.at_millis + 1;
            state
                .trim_history_before(floor, StateHistoryTrimLimits::default())
                .await?;
            match operation {
                "set" => state.write_set(&target, Value::integer(2)).await?,
                "append" => state.write_append(&target, Value::integer(2)).await?,
                _ => state.write_delete(&target).await?,
            };
            let remaining = state
                .history(&StateHistoryQuery::new(target.clone(), floor, i64::MAX))
                .await?;
            timestamp = remaining.entries.last().context("new event")?.at_millis;
        }
        {
            let db = redb::Database::open(&file)?;
            let txn = db.begin_write()?;
            txn.open_table(redb::TableDefinition::<&str, &[u8]>::new(
                "state_history_baselines_v1",
            ))?
            .insert(target.to_string().as_str(), b"invalid baseline".as_slice())?;
            txn.commit()?;
        }
        let state = RedbStore::open_with_history(&file, RedbHistory::Full)?
            .state_backend()
            .into_backend();
        if operation == "set" {
            let at = state.read_at(&target, timestamp).await?;
            ensure!(at.value == Some(Value::integer(2)) && at.taint.is_pristine());
            state
                .trim_history_before(timestamp + 1, StateHistoryTrimLimits::default())
                .await?;
            ensure!(state.read_at(&target, timestamp + 1).await? == at);
        } else {
            ensure!(state.read_at(&target, timestamp).await.is_err());
            ensure!(
                state
                    .trim_history_before(timestamp + 1, StateHistoryTrimLimits::default())
                    .await
                    .is_err()
            );
            ensure!(state.retained_from().await? == floor);
        }
    }
    Ok(())
}

async fn install_source<S: ExternalInstallationAuthority + ?Sized>(
    source: &S,
    installation: &str,
    projection: &str,
    sink: &Path,
    capacity: &StreamCapacity,
) -> Result<u64> {
    let definition = ExternalInstallationDef {
        id: installation.into(),
        platform: "test".into(),
        transport: Transport::Grpc { endpoint: None },
        trust: TrustLevel::Full,
        config_schema: Value::map(Default::default()),
        config: Value::null(),
        projections: vec![ExternalProjectionDef {
            id: projection.into(),
            role: Role::Source,
            namespace: None,
            provides: vec![],
            emits: Some(EventSource {
                sink: sink.clone(),
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 1024,
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
        source.compare_install(definition, None).await?
    else {
        anyhow::bail!("Source test installation was not applied")
    };
    record
        .scope_epoch(projection)
        .context("Source scope epoch missing")
}

fn backends() -> Result<(tempfile::TempDir, Vec<Backend>)> {
    let directory = tempfile::tempdir()?;
    let mut result = Vec::new();
    for read_shards in [NonZeroUsize::MIN, NonZeroUsize::new(4).context("shards")?] {
        result.push(
            InMemoryBackend::with_options(InMemoryOptions {
                history: MemoryHistory::Full,
                read_shards,
                ..InMemoryOptions::default()
            })?
            .into_backend(),
        );
    }
    result.push(
        RedbStore::open_with_history(directory.path().join("retention.redb"), RedbHistory::Full)?
            .state_backend()
            .into_backend(),
    );
    Ok((directory, result))
}

#[tokio::test]
async fn deleted_observations_survive_bounded_trim_and_independent_recreation() -> Result<()> {
    let (_directory, backends) = backends()?;
    let prefix = path("state://history-absence")?;
    let deleted = path("state://history-absence/deleted")?;
    let stored_null = path("state://history-absence/null")?;
    let missing = path("state://history-absence/unwritten")?;
    let protected = TaintSet::of(TaintSource::Protected {
        path: path("state://private/delete-guard")?,
    });
    let incoming = TaintSet::of(TaintSource::ModelOutput);
    let expected = protected.clone().merged(&incoming);
    for state in backends {
        state
            .write_set_tainted(&deleted, Value::integer(1), protected.clone())
            .await?;
        let committed = state
            .write_delete_tainted(&deleted, incoming.clone())
            .await?;
        ensure!(committed.taint.contains_all(&expected));
        state.write_set(&stored_null, Value::null()).await?;
        let before = state
            .history(&StateHistoryQuery::new(prefix.clone(), 0, i64::MAX))
            .await?;
        ensure!(before.entries.len() == 3);
        let deleted_at = before
            .entries
            .iter()
            .find(|entry| matches!(entry.event, xolotl_state::StateEvent::Delete { .. }))
            .context("delete event missing")?
            .at_millis;
        let floor = before
            .entries
            .iter()
            .map(|entry| entry.at_millis)
            .max()
            .context("history empty")?
            .checked_add(1)
            .context("history clock exhausted")?;
        let observation = state.read_at(&deleted, deleted_at).await?;
        ensure!(observation.value.is_none());
        ensure!(
            observation.taint.contains_all(&expected) && expected.contains_all(&observation.taint)
        );
        let untouched = state.read_at(&missing, floor).await?;
        ensure!(untouched.value.is_none() && untouched.taint.is_pristine());
        ensure!(state.read_at(&stored_null, floor).await?.value == Some(Value::null()));
        let failure = state
            .trim_history_before(
                floor,
                StateHistoryTrimLimits {
                    encoded_bytes: NonZeroUsize::MIN,
                    ..StateHistoryTrimLimits::default()
                },
            )
            .await
            .err()
            .context("over-budget trim succeeded")?;
        ensure!(matches!(failure.error, StateError::HistoryTrimLimit { .. }));
        ensure!(state.retained_from().await? == i64::MIN);
        ensure!(
            state
                .history(&StateHistoryQuery::new(prefix.clone(), 0, i64::MAX))
                .await?
                .entries
                == before.entries
        );
        ensure!(
            state
                .trim_history_before(floor, StateHistoryTrimLimits::default())
                .await?
                .removed_events
                == 3
        );
        ensure!(state.read_at(&deleted, floor).await? == observation);
        ensure!(state.read_at(&stored_null, floor).await?.value == Some(Value::null()));
        ensure!(
            state
                .history(&StateHistoryQuery::new(prefix.clone(), floor, i64::MAX))
                .await?
                .entries
                .is_empty()
        );
        state
            .write_set(&path("state://history-absence/clock")?, Value::integer(0))
            .await?;
        state.write_set(&deleted, Value::integer(7)).await?;
        let recreated = state.read_at(&deleted, i64::MAX).await?;
        ensure!(recreated.value == Some(Value::integer(7)) && recreated.taint.is_pristine());
        ensure!(state.read_at(&deleted, floor).await? == observation);
    }
    Ok(())
}

#[tokio::test]
async fn absent_baseline_reopens_without_retaining_the_deleted_payload() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("absence-baseline.redb");
    let deleted = path("state://history-absence/deleted")?;
    let protected = TaintSet::of(TaintSource::Protected {
        path: path("state://private/delete-guard")?,
    });
    let incoming = TaintSet::of(TaintSource::ModelOutput);
    let expected = protected.clone().merged(&incoming);
    let floor;
    {
        let owner = RedbStore::open_with_history(&database, RedbHistory::Full)?;
        let state = owner.state_backend().into_backend();
        state
            .write_set_tainted(&deleted, Value::string("payload".repeat(8192)), protected)
            .await?;
        state.write_delete_tainted(&deleted, incoming).await?;
        let page = state
            .history(&StateHistoryQuery::new(deleted.clone(), 0, i64::MAX))
            .await?;
        floor = page
            .entries
            .last()
            .context("delete event missing")?
            .at_millis
            .checked_add(1)
            .context("history clock exhausted")?;
        state
            .trim_history_before(floor, StateHistoryTrimLimits::default())
            .await?;
    }
    {
        let raw = redb::Database::open(&database)?;
        let transaction = raw.begin_read()?;
        let table = transaction.open_table(redb::TableDefinition::<&str, &[u8]>::new(
            "state_history_baselines_v1",
        ))?;
        ensure!(table.len()? == 1);
        let record = table
            .get(deleted.to_string().as_str())?
            .context("absence baseline missing")?;
        ensure!(record.value().len() < 512);
        ensure!(
            transaction
                .open_table(redb::TableDefinition::<&[u8], &[u8]>::new("state_history"))?
                .len()?
                == 0
        );
    }
    let owner = RedbStore::open_with_history(&database, RedbHistory::Full)?;
    let state = owner.state_backend().into_backend();
    let observation = state.read_at(&deleted, floor).await?;
    ensure!(observation.value.is_none());
    ensure!(observation.taint.contains_all(&expected) && expected.contains_all(&observation.taint));
    ensure!(state.retained_from().await? == floor);
    state
        .write_set(&path("state://history-absence/clock")?, Value::integer(0))
        .await?;
    state.write_set(&deleted, Value::null()).await?;
    let present = state.read_at(&deleted, i64::MAX).await?;
    ensure!(present.value == Some(Value::null()) && present.taint.is_pristine());
    ensure!(state.read_at(&deleted, floor).await? == observation);
    Ok(())
}

#[test]
fn unsupported_baseline_format_is_rejected_without_creating_empty_evidence() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let current = redb::TableDefinition::<&str, &[u8]>::new("state_history_baselines_v1");
    let unsupported = redb::TableDefinition::<&str, &[u8]>::new("state_history_baselines_v2");
    for (index, history) in [RedbHistory::CurrentOnly, RedbHistory::Full]
        .into_iter()
        .enumerate()
    {
        let database = directory.path().join(format!("unsupported-{index}.redb"));
        drop(RedbStore::open_with_history(&database, history)?);
        {
            let raw = redb::Database::open(&database)?;
            let transaction = raw.begin_write()?;
            ensure!(transaction.delete_table(current)?);
            transaction
                .open_table(unsupported)?
                .insert("state://sentinel", b"retained-evidence".as_slice())?;
            transaction.commit()?;
        }
        let failure = RedbStore::open_with_history(&database, history)
            .err()
            .context("unsupported format was admitted")?;
        ensure!(
            failure
                .to_string()
                .contains("storage schema table missing: state_history_baselines_v1")
        );
        let raw = redb::Database::open(&database)?;
        let transaction = raw.begin_read()?;
        ensure!(transaction.open_table(current).is_err());
        ensure!(
            transaction
                .open_table(unsupported)?
                .get("state://sentinel")?
                .context("retained evidence was removed")?
                .value()
                == b"retained-evidence"
        );
    }
    Ok(())
}

#[tokio::test]
async fn vault_rotations_never_enter_history() -> Result<()> {
    let (_directory, backends) = backends()?;
    let vault = path("state://vault/console/credentials/alice")?;
    ensure!(!xolotl_state::history_retains_path(&vault));
    for state in backends {
        state
            .write_set(&vault, Value::string("old-verifier".into()))
            .await?;
        state
            .write_set(&vault, Value::string("new-verifier".into()))
            .await?;
        ensure!(state.read(&vault).await? == Some(Value::string("new-verifier".into())));
        ensure!(matches!(
            state.read_at(&vault, i64::MAX - 1).await,
            Err(xolotl_state::StateFailure {
                error: StateError::HistoryExcluded,
                ..
            })
        ));
        ensure!(matches!(
            state
                .history(&StateHistoryQuery::new(vault.clone(), 0, i64::MAX))
                .await,
            Err(xolotl_state::StateFailure {
                error: StateError::HistoryExcluded,
                ..
            })
        ));
        state.write_delete(&vault).await?;
        ensure!(state.read(&vault).await?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn redb_vault_writes_leave_no_physical_history_row_after_restart() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("vault-history.redb");
    let vault = path("state://vault/console/challenges")?;
    {
        let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
        let state = store.state_backend().into_backend();
        state
            .write_set(&vault, Value::string("one-time-proof".into()))
            .await?;
        state.write_delete(&vault).await?;
    }
    let db = redb::Database::create(&file)?;
    let txn = db.begin_read()?;
    let table = txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new("state_history"))?;
    ensure!(table.len()? == 0);
    let time_index = txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
        "state_history_time_index_v1",
    ))?;
    ensure!(time_index.len()? == 0);
    Ok(())
}

#[tokio::test]
async fn source_sink_cannot_journal_vault_payloads() -> Result<()> {
    async fn check(state: Backend, source: &dyn SourceStore) -> Result<()> {
        let sink = path("state://vault/source/private")?;
        let declared_sink = path("state://events/external/vault-test/private")?;
        let capacity = StreamCapacity {
            max_events: 4,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let payload = Value::string("private-payload".into());
        let taint = TaintSet::pristine();
        ensure!(
            install_source(source, "vault-test", "private", &declared_sink, &capacity).await? == 2
        );
        ensure!(
            source
                .commit(SourceCommit {
                    claim: SourceClaim {
                        installation_id: "vault-test",
                        projection_id: "private",
                        scope_epoch: 2,
                        stream_epoch: None,
                        event_id: "one",
                        claim_id: SourceClaimId::from_bytes([3; 16]),
                    },
                    received_at_ms: 1,
                    decision_clock: std::sync::Arc::new(|| 1),
                    dedupe_window_ms: 1_000,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: 1_024,
                    payload: &payload,
                    taint: &taint,
                    stream: None,
                    rate_limit: None,
                })
                .await?
                == SourceCommitOutcome::Rejected(SourceCommitRejection::DeclarationMismatch)
        );
        ensure!(state.read(&sink).await?.is_none());
        Ok(())
    }

    let memory = InMemoryBackend::with_options(InMemoryOptions {
        history: MemoryHistory::Full,
        ..InMemoryOptions::default()
    })?;
    let (state, source) = memory.into_source_parts();
    check(state, source.as_ref()).await?;

    let directory = tempfile::tempdir()?;
    let file = directory.path().join("vault-source.redb");
    {
        let redb = RedbStore::open_with_history(&file, RedbHistory::Full)?;
        let (state, source) = redb.state_backend().into_source_parts();
        check(state, source.as_ref()).await?;
    }
    let db = redb::Database::create(&file)?;
    let txn = db.begin_read()?;
    let table = txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new("state_history"))?;
    ensure!(table.len()? == 0);
    let time_index = txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
        "state_history_time_index_v1",
    ))?;
    ensure!(time_index.len()? == 0);
    Ok(())
}

#[tokio::test]
async fn trim_preserves_exact_path_value_taint_and_future_mutations() -> Result<()> {
    let (_directory, backends) = backends()?;
    for state in backends {
        ensure!(state.has_history() && state.has_history_retention());
        ensure!(state.retained_from().await? == i64::MIN);
        let prefix = path("state://trim")?;
        let list = path("state://trim/list")?;
        let deleted = path("state://trim/deleted")?;
        let recreated = path("state://trim/recreated")?;
        let first = TaintSet::of(TaintSource::Protected { path: list.clone() });
        let second = TaintSet::of(TaintSource::Protected {
            path: deleted.clone(),
        });
        let mut union = first.clone();
        union.union(&second);
        state
            .write_set_tainted(&list, Value::list(vec![Value::integer(1)]), first.clone())
            .await?;
        state
            .write_append_tainted(&list, Value::integer(2), second)
            .await?;
        state.write_set(&deleted, Value::integer(9)).await?;
        state.write_delete(&deleted).await?;
        state.write_set(&recreated, Value::integer(3)).await?;
        state.write_delete(&recreated).await?;

        let before = state
            .history(&StateHistoryQuery::new(prefix.clone(), 0, i64::MAX))
            .await?;
        ensure!(before.entries.len() == 6 && before.next.is_none());
        let floor = before
            .entries
            .iter()
            .map(|entry| entry.at_millis)
            .max()
            .context("latest mutation")?
            + 1;
        ensure!(matches!(
            state
                .trim_history_before(i64::MAX, StateHistoryTrimLimits::default())
                .await,
            Err(xolotl_state::StateFailure {
                error: StateError::InvalidQuery(_),
                ..
            })
        ));
        let mut one = StateHistoryQuery::new(prefix.clone(), 0, i64::MAX);
        one.limits = StatePageLimits {
            entries: NonZeroUsize::MIN,
            ..StatePageLimits::default()
        };
        let old_cursor = state
            .history(&one)
            .await?
            .next
            .context("first page cursor")?;
        for changed in [
            StateHistoryQuery {
                from_millis: 1,
                cursor: Some(old_cursor.clone()),
                ..one.clone()
            },
            StateHistoryQuery {
                to_millis: i64::MAX - 1,
                cursor: Some(old_cursor.clone()),
                ..one.clone()
            },
            StateHistoryQuery {
                path: path("state://t")?,
                cursor: Some(old_cursor.clone()),
                ..one.clone()
            },
        ] {
            ensure!(matches!(
                state.history(&changed).await,
                Err(xolotl_state::StateFailure {
                    error: StateError::InvalidQuery(_),
                    ..
                })
            ));
        }
        let constrained = StateHistoryTrimLimits {
            events: NonZeroUsize::MIN,
            ..StateHistoryTrimLimits::default()
        };
        let failed = state
            .trim_history_before(floor, constrained)
            .await
            .err()
            .context("trim exceeded event budget")?;
        ensure!(matches!(
            failed.error,
            StateError::HistoryTrimLimit {
                provenance_observed: false
            }
        ));
        ensure!(state.retained_from().await? == i64::MIN);
        ensure!(
            state
                .history(&StateHistoryQuery::new(prefix.clone(), 0, i64::MAX))
                .await?
                .entries
                .len()
                == 6
        );
        let byte_constrained = StateHistoryTrimLimits {
            encoded_bytes: NonZeroUsize::MIN,
            ..StateHistoryTrimLimits::default()
        };
        ensure!(matches!(
            state.trim_history_before(floor, byte_constrained).await,
            Err(xolotl_state::StateFailure {
                error: StateError::HistoryTrimLimit { .. },
                ..
            })
        ));
        ensure!(state.retained_from().await? == i64::MIN);

        let report = state
            .trim_history_before(floor, StateHistoryTrimLimits::default())
            .await?;
        ensure!(report.retained_from_millis == floor && report.removed_events == 6);
        ensure!(state.retained_from().await? == floor);
        ensure!(
            state
                .trim_history_before(floor, StateHistoryTrimLimits::default())
                .await?
                .removed_events
                == 0
        );
        ensure!(matches!(
            state
                .trim_history_before(floor - 1, StateHistoryTrimLimits::default())
                .await,
            Err(xolotl_state::StateFailure {
                error: StateError::InvalidQuery(_),
                ..
            })
        ));
        for candidate in [&list, &deleted, &recreated, &path("state://trim/never")?] {
            ensure!(matches!(
                state.read_at(candidate, floor - 1).await,
                Err(xolotl_state::StateFailure { error: StateError::HistoryTrimmed { retained_from_millis }, .. })
                    if retained_from_millis == floor
            ));
        }
        ensure!(matches!(
            state.history(&StateHistoryQuery::new(prefix.clone(), 0, floor)).await,
            Err(xolotl_state::StateFailure { error: StateError::HistoryTrimmed { retained_from_millis }, .. })
                if retained_from_millis == floor
        ));
        one.from_millis = floor;
        one.cursor = Some(old_cursor);
        ensure!(matches!(
            state.history(&one).await,
            Err(xolotl_state::StateFailure {
                error: StateError::InvalidQuery(_),
                ..
            })
        ));
        let expected = TaintedValue::new(
            Value::list(vec![Value::integer(1), Value::integer(2)]),
            union.clone(),
        );
        ensure!(
            state.read_at(&list, floor).await?
                == xolotl_state::StateObservation::from(expected.clone())
        );
        ensure!(state.read_at(&deleted, floor).await?.value.is_none());
        ensure!(state.read_at(&recreated, floor).await?.value.is_none());
        ensure!(state.read_at(&list, 0).await? == xolotl_state::StateObservation::from(expected));
        ensure!(
            state
                .history(&StateHistoryQuery::new(prefix.clone(), floor, i64::MAX))
                .await?
                .entries
                .is_empty()
        );

        state.write_append(&list, Value::integer(4)).await?;
        state.write_set(&recreated, Value::integer(5)).await?;
        let after = state
            .history(&StateHistoryQuery::new(prefix, floor, i64::MAX))
            .await?;
        ensure!(after.entries.len() == 2 && after.next.is_none());
        ensure!(
            state.read_at(&list, i64::MAX).await?
                == xolotl_state::StateObservation::from(TaintedValue::new(
                    Value::list(vec![
                        Value::integer(1),
                        Value::integer(2),
                        Value::integer(4),
                    ]),
                    union,
                ))
        );
        ensure!(state.read_at(&recreated, i64::MAX).await?.value == Some(Value::integer(5)));
        let second_floor = after
            .entries
            .iter()
            .find(|entry| entry.event.path() == &recreated)
            .context("recreated mutation")?
            .at_millis;
        ensure!(
            state
                .trim_history_before(second_floor, StateHistoryTrimLimits::default())
                .await?
                .removed_events
                == 1
        );
        ensure!(state.read_at(&list, second_floor).await? == state.read_tainted(&list).await?);
        ensure!(state.read_at(&recreated, second_floor).await?.value == Some(Value::integer(5)));
        let retained = state
            .history(&StateHistoryQuery::new(
                recreated.clone(),
                second_floor,
                i64::MAX,
            ))
            .await?;
        ensure!(retained.entries.len() == 1);
    }
    Ok(())
}

#[tokio::test]
async fn redb_retention_survives_restart_and_removes_old_rows() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("restart.redb");
    let target = path("state://trim/restart")?;
    let floor;
    {
        let state = RedbStore::open_with_history(&file, RedbHistory::Full)?
            .state_backend()
            .into_backend();
        state.write_set(&target, Value::integer(1)).await?;
        state.write_set(&target, Value::integer(2)).await?;
        let entries = state
            .history(&StateHistoryQuery::new(target.clone(), 0, i64::MAX))
            .await?
            .entries;
        floor = entries.last().context("latest mutation")?.at_millis + 1_000_000;
        state
            .trim_history_before(floor, StateHistoryTrimLimits::default())
            .await?;
    }
    {
        let raw = redb::Database::open(&file)?;
        let txn = raw.begin_read()?;
        let table: redb::TableDefinition<&[u8], &[u8]> =
            redb::TableDefinition::new("state_history");
        ensure!(txn.open_table(table)?.len()? == 0);
    }
    let state = RedbStore::open_with_history(&file, RedbHistory::Full)?
        .state_backend()
        .into_backend();
    ensure!(state.retained_from().await? == floor);
    ensure!(state.read_at(&target, floor).await?.value == Some(Value::integer(2)));
    state.write_set(&target, Value::integer(3)).await?;
    let resumed = state
        .history(&StateHistoryQuery::new(target.clone(), floor, i64::MAX))
        .await?;
    ensure!(resumed.entries.len() == 1 && resumed.entries[0].at_millis >= floor);
    ensure!(state.read_at(&target, i64::MAX).await?.value == Some(Value::integer(3)));
    Ok(())
}

#[tokio::test]
async fn time_index_trims_old_events_across_path_order_without_touching_newer_rows() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("time-index.redb");
    let older = path("state://trim/z-old")?;
    let second = path("state://trim/a-second")?;
    let newer = path("state://trim/m-new")?;
    let state = RedbStore::open_with_history(&file, RedbHistory::Full)?
        .state_backend()
        .into_backend();
    for (path, number) in [(&older, 1), (&second, 2), (&newer, 3)] {
        state.write_set(path, Value::integer(number)).await?;
    }
    let new_time = state
        .history(&StateHistoryQuery::new(newer.clone(), 0, i64::MAX))
        .await?
        .entries[0]
        .at_millis;
    let too_small = StateHistoryTrimLimits {
        events: NonZeroUsize::MIN,
        ..StateHistoryTrimLimits::default()
    };
    ensure!(matches!(
        state.trim_history_before(new_time, too_small).await,
        Err(xolotl_state::StateFailure {
            error: StateError::HistoryTrimLimit { .. },
            ..
        })
    ));
    ensure!(state.retained_from().await? == i64::MIN);
    drop(state);
    {
        let db = redb::Database::open(&file)?;
        let txn = db.begin_read()?;
        ensure!(
            txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new("state_history"))?
                .len()?
                == 3
        );
        ensure!(
            txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
                "state_history_time_index_v1"
            ))?
            .len()?
                == 3
        );
    }
    let state = RedbStore::open_with_history(&file, RedbHistory::Full)?
        .state_backend()
        .into_backend();
    let limits = StateHistoryTrimLimits {
        events: NonZeroUsize::new(2).context("two events")?,
        ..StateHistoryTrimLimits::default()
    };
    ensure!(
        state
            .trim_history_before(new_time, limits)
            .await?
            .removed_events
            == 2
    );
    ensure!(state.read_at(&older, new_time).await?.value == Some(Value::integer(1)));
    ensure!(state.read_at(&second, new_time).await?.value == Some(Value::integer(2)));
    ensure!(state.read_at(&newer, new_time).await?.value == Some(Value::integer(3)));
    drop(state);
    let db = redb::Database::open(&file)?;
    let txn = db.begin_read()?;
    let history = txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new("state_history"))?;
    let time_index = txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
        "state_history_time_index_v1",
    ))?;
    ensure!(history.len()? == 1 && time_index.len()? == 1);
    let (time_key, _) = time_index.first()?.context("missing newer time index")?;
    let primary = &time_key.value()[8..];
    ensure!(history.get(primary)?.is_some());
    drop(txn);
    drop(db);
    let reopened = RedbStore::open_with_history(&file, RedbHistory::Full)?
        .state_backend()
        .into_backend();
    ensure!(reopened.retained_from().await? == new_time);
    ensure!(
        reopened
            .history(&StateHistoryQuery::new(
                path("state://trim")?,
                new_time,
                i64::MAX
            ))
            .await?
            .entries
            .len()
            == 1
    );
    Ok(())
}

#[tokio::test]
async fn missing_time_index_never_advances_the_history_floor() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("missing-time-index.redb");
    let target = path("state://trim/index-guard")?;
    let state = RedbStore::open_with_history(&file, RedbHistory::Full)?
        .state_backend()
        .into_backend();
    state.write_set(&target, Value::integer(7)).await?;
    let timestamp = state
        .history(&StateHistoryQuery::new(target.clone(), 0, i64::MAX))
        .await?
        .entries[0]
        .at_millis;
    drop(state);
    let db = redb::Database::open(&file)?;
    let txn = db.begin_write()?;
    txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
        "state_history_time_index_v1",
    ))?
    .pop_first()?;
    txn.commit()?;
    drop(db);
    let state = RedbStore::open_with_history(&file, RedbHistory::Full)?
        .state_backend()
        .into_backend();
    ensure!(matches!(
        state
            .trim_history_before(timestamp + 1, StateHistoryTrimLimits::default())
            .await,
        Err(xolotl_state::StateFailure {
            error: StateError::Backend(_),
            ..
        })
    ));
    ensure!(state.retained_from().await? == i64::MIN);
    ensure!(state.read_at(&target, timestamp).await?.value == Some(Value::integer(7)));
    Ok(())
}

#[tokio::test]
async fn mismatched_time_index_identity_never_advances_the_history_floor() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("wrong-time-index.redb");
    let target = path("state://trim/index-identity")?;
    let state = RedbStore::open_with_history(&file, RedbHistory::Full)?
        .state_backend()
        .into_backend();
    state.write_set(&target, Value::integer(7)).await?;
    let timestamp = state
        .history(&StateHistoryQuery::new(target.clone(), 0, i64::MAX))
        .await?
        .entries[0]
        .at_millis;
    drop(state);
    let db = redb::Database::open(&file)?;
    let txn = db.begin_write()?;
    {
        let mut index = txn.open_table(redb::TableDefinition::<&[u8], &[u8]>::new(
            "state_history_time_index_v1",
        ))?;
        let (original, _) = index.pop_first()?.context("missing original index")?;
        let mut wrong = original.value().to_vec();
        let last = wrong.last_mut().context("empty index key")?;
        *last ^= 1;
        drop(original);
        index.insert(wrong.as_slice(), &[][..])?;
    }
    txn.commit()?;
    drop(db);
    let state = RedbStore::open_with_history(&file, RedbHistory::Full)?
        .state_backend()
        .into_backend();
    ensure!(matches!(
        state
            .trim_history_before(timestamp + 1, StateHistoryTrimLimits::default())
            .await,
        Err(xolotl_state::StateFailure {
            error: StateError::Backend(_),
            ..
        })
    ));
    ensure!(state.retained_from().await? == i64::MIN);
    ensure!(state.read_at(&target, timestamp).await?.value == Some(Value::integer(7)));
    Ok(())
}

#[tokio::test]
async fn current_only_does_not_install_retention() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let backends = [
        InMemoryBackend::new().into_backend(),
        RedbStore::open(directory.path().join("current-only.redb"))?
            .state_backend()
            .into_backend(),
    ];
    for state in backends {
        ensure!(!state.has_history_retention());
        ensure!(matches!(
            state.retained_from().await,
            Err(xolotl_state::StateFailure {
                error: StateError::MissingCapability("history_retention"),
                ..
            })
        ));
        ensure!(matches!(
            state
                .trim_history_before(1, StateHistoryTrimLimits::default())
                .await,
            Err(xolotl_state::StateFailure {
                error: StateError::MissingCapability("history_retention"),
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn concurrent_writes_and_trim_keep_a_replayable_commit_order() -> Result<()> {
    use std::sync::{Arc, Barrier};
    let (_directory, backends) = backends()?;
    for state in backends {
        let path = path("state://trim/concurrent")?;
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let first = runtime.block_on(async {
            state.write_set(&path, Value::integer(-1)).await?;
            Ok::<_, xolotl_state::StateFailure>(
                state
                    .history(&StateHistoryQuery::new(path.clone(), 0, i64::MAX))
                    .await?
                    .entries[0]
                    .at_millis,
            )
        })?;
        let floor = first + 1;
        let state = Arc::new(state);
        let barrier = Arc::new(Barrier::new(3));
        let writer = {
            let state = state.clone();
            let barrier = barrier.clone();
            let path = path.clone();
            std::thread::spawn(move || -> Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread().build()?;
                barrier.wait();
                for value in 0..64 {
                    runtime.block_on(state.write_set(&path, Value::integer(value)))?;
                    std::thread::yield_now();
                }
                Ok(())
            })
        };
        let trimmer = {
            let state = state.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || -> Result<()> {
                let runtime = tokio::runtime::Builder::new_current_thread().build()?;
                barrier.wait();
                runtime.block_on(
                    state.trim_history_before(floor, StateHistoryTrimLimits::default()),
                )?;
                Ok(())
            })
        };
        barrier.wait();
        writer
            .join()
            .map_err(|_panic| anyhow::anyhow!("writer panicked"))??;
        trimmer
            .join()
            .map_err(|_panic| anyhow::anyhow!("trimmer panicked"))??;
        runtime.block_on(async {
            ensure!(state.retained_from().await? == floor);
            let current = state.read_tainted(&path).await?;
            ensure!(current == state.read_at(&path, i64::MAX).await?);
            let page = state
                .history(&StateHistoryQuery::new(path.clone(), floor, i64::MAX))
                .await?;
            ensure!(page.entries.len() == 64 && page.next.is_none());
            ensure!(page.entries.iter().all(|entry| entry.at_millis >= floor));
            Ok::<_, anyhow::Error>(())
        })?;
    }
    Ok(())
}

#[tokio::test]
async fn source_sink_commit_uses_history_clock_after_trim() -> Result<()> {
    async fn check(state: Backend, source: &dyn SourceStore) -> Result<()> {
        let marker = path("state://trim/source-clock")?;
        let sink = path("state://trim/source-sink")?;
        state.write_set(&marker, Value::integer(1)).await?;
        let entries = state
            .history(&StateHistoryQuery::new(marker.clone(), 0, i64::MAX))
            .await?
            .entries;
        // Simulate a long idle interval: the floor is ahead of the last commit.
        // The trim must advance the write clock atomically with its baseline.
        let floor = entries.last().context("last marker mutation")?.at_millis + 1_000_000;
        state
            .trim_history_before(floor, StateHistoryTrimLimits::default())
            .await?;
        let capacity = StreamCapacity {
            max_events: 4,
            on_overflow: OverflowPolicy::DropOldest,
        };
        let payload = Value::integer(7);
        let taint = TaintSet::pristine();
        ensure!(install_source(source, "retention", "source", &sink, &capacity).await? == 2);
        ensure!(
            source
                .commit(SourceCommit {
                    claim: SourceClaim {
                        installation_id: "retention",
                        projection_id: "source",
                        scope_epoch: 2,
                        stream_epoch: None,
                        event_id: "after-trim",
                        claim_id: SourceClaimId::from_bytes([9; 16]),
                    },
                    received_at_ms: 1_000,
                    decision_clock: std::sync::Arc::new(|| 1_000),
                    dedupe_window_ms: 1_000,
                    sink: &sink,
                    capacity: &capacity,
                    max_inline_payload_bytes: 1_024,
                    payload: &payload,
                    taint: &taint,
                    stream: None,
                    rate_limit: None,
                })
                .await?
                == SourceCommitOutcome::Accepted
        );
        let page = state
            .history(&StateHistoryQuery::new(sink.clone(), floor, i64::MAX))
            .await?;
        ensure!(page.entries.len() == 1 && page.entries[0].at_millis >= floor);
        ensure!(
            state.read_at(&sink, page.entries[0].at_millis).await?
                == state.read_tainted(&sink).await?
        );
        ensure!(state.read_at(&sink, i64::MAX).await?.value == Some(Value::list(vec![payload])));
        Ok(())
    }

    let memory = InMemoryBackend::with_options(InMemoryOptions {
        history: MemoryHistory::Full,
        ..InMemoryOptions::default()
    })?;
    let (state, source) = memory.into_source_parts();
    check(state, source.as_ref()).await?;

    let directory = tempfile::tempdir()?;
    let redb = RedbStore::open_with_history(
        directory.path().join("source-clock.redb"),
        RedbHistory::Full,
    )?;
    let (state, source) = redb.state_backend().into_source_parts();
    check(state, source.as_ref()).await?;
    Ok(())
}
