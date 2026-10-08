use super::*;
use crate::RedbStore;
use anyhow::{Context, anyhow, bail, ensure};
use redb::ReadableTableMetadata;
use std::num::NonZeroUsize;
use xolotl_state::StateHistoryRetention;
use xolotl_state::prelude::*;
use xolotl_state::test_support::{CollectHistory, CollectState};
use xolotl_types::{MergeRule, Path};

mod observations;

fn p(s: &str) -> anyhow::Result<Path> {
    Path::parse(s).map_err(|error| anyhow!("path parse failed for {s}: {error}"))
}

fn tmp_backend() -> anyhow::Result<RedbStateBackend> {
    let dir = tempfile::tempdir()?;
    let path = dir.keep().join("test.redb");
    Ok(RedbStore::open_with_history(path, RedbHistory::Full)?.state_backend())
}

fn history_millis(db: &Database) -> anyhow::Result<i64> {
    let txn = db.begin_read()?;
    let meta = txn.open_table(STATE_META_TABLE)?;
    meta.get(LAST_HISTORY_MILLIS)?
        .map(|value| value.value())
        .context("missing history metadata")
}

fn set_history_millis(db: &Database, millis: i64) -> anyhow::Result<()> {
    let txn = db.begin_write()?;
    {
        let mut meta = txn.open_table(STATE_META_TABLE)?;
        meta.insert(LAST_HISTORY_MILLIS, millis)?;
    }
    txn.commit()?;
    Ok(())
}

fn raw_history(db: &Database) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let txn = db.begin_read()?;
    let history = txn.open_table(STATE_HISTORY_TABLE)?;
    history
        .iter()?
        .map(|entry| {
            let (key, value) = entry?;
            Ok((key.value().to_vec(), value.value().to_vec()))
        })
        .collect()
}

#[tokio::test]
async fn segmented_append_preserves_raw_members_and_recorded_source_order() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("incremental-list.redb");
    let path = p("state://list/incremental")?;
    let stored_taint = TaintSet::from_recorded_sources(vec![
        xolotl_types::TaintSource::ModelOutput,
        xolotl_types::TaintSource::AuthorConstant,
        xolotl_types::TaintSource::ModelOutput,
    ]);
    let input_taint = TaintSet::from_recorded_sources(vec![
        xolotl_types::TaintSource::AuthorConstant,
        xolotl_types::TaintSource::AuthorConstant,
    ]);
    let expected_value = Value::list((0..4).map(Value::integer).collect());
    {
        let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
        let backend = store.state_backend();
        backend
            .write_set_tainted(
                &path,
                Value::list((0..3).map(Value::integer).collect()),
                stored_taint.clone(),
            )
            .await?;
        let retained = {
            let txn = backend.db.begin_write()?;
            let mut values = txn.open_table(STATE_VALUES_TABLE)?;
            let key = path.to_string();
            let mut marker =
                list::marker(values.get(key.as_str())?.context("current marker")?.value())?
                    .context("List is not segmented")?;
            let mut items = list::item_table(&txn)?;
            let first = list::item_key(marker.id, marker.first);
            let mut padded = items
                .get(first.as_slice())?
                .context("first item")?
                .value()
                .to_vec();
            padded.extend_from_slice(b" \n");
            items.insert(first.as_slice(), padded.as_slice())?;
            marker.item_bytes += 2;
            values.insert(key.as_str(), marker.encode()?.as_slice())?;
            let retained = items
                .iter()?
                .map(|row| {
                    let (key, value) = row?;
                    Ok((key.value().to_vec(), value.value().to_vec()))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            drop(items);
            drop(values);
            txn.commit()?;
            retained
        };
        let mut events = backend.subscribe(&path).await?;
        let result = backend
            .write_append_tainted(&path, Value::integer(3), input_taint.clone())
            .await?;
        ensure!(result.taint == input_taint.clone().merged(&stored_taint));
        let observed = backend.read_tainted(&path).await?;
        ensure!(observed.value == Some(expected_value.clone()));
        ensure!(observed.taint == stored_taint.clone().merged(&input_taint));
        let event =
            tokio::time::timeout(std::time::Duration::from_secs(2), events.recv()).await??;
        ensure!(matches!(&event, StateEvent::Append { item, .. } if item == &Value::integer(3)));
        ensure!(event.taint() == &result.taint);
        let txn = backend.db.begin_read()?;
        let items = txn.open_table(crate::schema::STATE_LIST_ITEMS_TABLE)?;
        ensure!(items.len()? == 4);
        for (key, bytes) in retained {
            ensure!(
                items.get(key.as_slice())?.context("retained item")?.value() == bytes.as_slice()
            );
        }
        let entries = backend.read_range(&path, 0, i64::MAX).await?;
        ensure!(entries.len() == 2);
        ensure!(entries[1].event == event);
        let replay = backend.read_at(&path, entries[1].at_millis).await?;
        ensure!(replay == observed);
        drop(items);
        drop(txn);
        drop(events);
        let idle = store.wait_idle();
        drop(backend);
        drop(store);
        idle.await;
    }
    let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
    let observed = store.state_backend().read_tainted(&path).await?;
    ensure!(observed.value == Some(expected_value));
    ensure!(observed.taint == stored_taint.merged(&input_taint));
    Ok(())
}

#[tokio::test]
async fn list_replacement_preserves_recorded_duplicates_but_unions_observations()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("list-set-provenance.redb");
    let path = p("state://list/replacement")?;
    let earlier = TaintSet::from_recorded_sources(vec![
        xolotl_types::TaintSource::ModelOutput,
        xolotl_types::TaintSource::ModelOutput,
    ]);
    let replacement = TaintSet::from_recorded_sources(vec![
        xolotl_types::TaintSource::AuthorConstant,
        xolotl_types::TaintSource::AuthorConstant,
    ]);
    {
        let store = RedbStore::open(&file)?;
        let backend = store.state_backend();
        backend
            .write_set_tainted(&path, Value::list(vec![Value::integer(1)]), earlier.clone())
            .await?;
        let commit = backend
            .write_set_tainted(&path, Value::list(Vec::new()), replacement.clone())
            .await?;
        ensure!(commit.taint == replacement.clone().merged(&earlier));
        ensure!(commit.taint.sources().len() == 3);
        let current = backend.read_tainted(&path).await?;
        ensure!(current.taint == replacement);
        ensure!(current.value == Some(Value::list(Vec::new())));
        let idle = store.wait_idle();
        drop(backend);
        drop(store);
        idle.await;
    }
    let store = RedbStore::open(&file)?;
    let current = store.state_backend().read_tainted(&path).await?;
    ensure!(current.taint == replacement && current.taint.sources().len() == 2);
    ensure!(current.value == Some(Value::list(Vec::new())));
    Ok(())
}

#[tokio::test]
async fn empty_lists_allocate_independent_items_only_on_append_after_reopen() -> anyhow::Result<()>
{
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("empty-list-ownership.redb");
    let first = p("state://list/first")?;
    let second = p("state://list/second")?;
    {
        let store = RedbStore::open(&file)?;
        let backend = store.state_backend();
        for path in [&first, &second] {
            backend.write_set(path, Value::list(Vec::new())).await?;
        }
        let txn = backend.db.begin_read()?;
        let meta = txn.open_table(crate::schema::STATE_LIST_META_TABLE)?;
        ensure!(
            meta.get(crate::schema::NEXT_STATE_LIST_ID)?
                .context("List id counter")?
                .value()
                == 0
        );
        drop(meta);
        drop(txn);
        let idle = store.wait_idle();
        drop(backend);
        drop(store);
        idle.await;
    }
    let store = RedbStore::open(&file)?;
    let backend = store.state_backend();
    backend.write_append(&first, Value::integer(1)).await?;
    backend.write_append(&second, Value::integer(2)).await?;
    ensure!(backend.read(&first).await? == Some(Value::list(vec![Value::integer(1)])));
    ensure!(backend.read(&second).await? == Some(Value::list(vec![Value::integer(2)])));
    let txn = backend.db.begin_read()?;
    let items = txn.open_table(crate::schema::STATE_LIST_ITEMS_TABLE)?;
    ensure!(items.len()? == 2);
    Ok(())
}

#[tokio::test]
async fn ordinary_list_count_is_not_a_source_admission_limit() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("ordinary-large-list.redb");
    let path = p("state://list/ordinary-capacity")?;
    let count = xolotl_source::MAX_SINK_EVENTS + 1;
    {
        let store = RedbStore::open(&file)?;
        let backend = store.state_backend();
        backend
            .write_set(
                &path,
                Value::from(
                    (0..count)
                        .map(|value| Value::integer(value as i64))
                        .collect::<xolotl_types::ValueList>(),
                ),
            )
            .await?;
        backend
            .write_append(&path, Value::integer(count as i64))
            .await?;
        let idle = store.wait_idle();
        drop(backend);
        drop(store);
        idle.await;
    }
    let store = RedbStore::open(&file)?;
    let observed = store.state_backend().read_tainted(&path).await?;
    let values = observed
        .value
        .as_ref()
        .and_then(Value::as_list)
        .context("ordinary List")?;
    ensure!(values.len() == count + 1);
    ensure!(values.last().and_then(Value::as_int) == Some(count as i64));
    Ok(())
}

#[tokio::test]
async fn default_store_keeps_current_values_without_history() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("current-only.redb");
    let path = p("state://history/current-only")?;
    {
        let store = RedbStore::open(&file)?;
        let backend = store.state_backend();
        let state = backend.into_backend();
        ensure!(!state.has_history());
        state
            .write_set(&path, Value::list(vec![Value::integer(1)]))
            .await?;
        state.write_append(&path, Value::integer(2)).await?;
        ensure!(matches!(
            state
                .history(&xolotl_state::StateHistoryQuery::new(
                    path.clone(),
                    0,
                    i64::MAX
                ))
                .await,
            Err(xolotl_state::StateFailure {
                error: StateError::MissingCapability("history"),
                ..
            })
        ));
        ensure!(raw_history(&store.db)?.is_empty());
        ensure!(history_millis(&store.db)? == 0);
    }
    let store = RedbStore::open(&file)?;
    let direct = store.state_backend();
    ensure!(matches!(
        direct
            .history(&xolotl_state::StateHistoryQuery::new(
                path.clone(),
                0,
                i64::MAX
            ))
            .await,
        Err(xolotl_state::StateFailure {
            error: StateError::MissingCapability("history"),
            ..
        })
    ));
    ensure!(matches!(
        direct.read_at(&path, 1).await,
        Err(xolotl_state::StateFailure {
            error: StateError::MissingCapability("history"),
            ..
        })
    ));
    ensure!(
        direct.read_at(&path, 0).await?
            == xolotl_state::StateObservation::from(TaintedValue::pristine(Value::list(vec![
                Value::integer(1),
                Value::integer(2),
            ])))
    );
    ensure!(raw_history(&store.db)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn set_and_read() -> anyhow::Result<()> {
    let b = tmp_backend()?;
    b.write_set(&p("state://x")?, Value::integer(42)).await?;
    let v = b.read(&p("state://x")?).await?;
    ensure!(v == Some(Value::integer(42)), "unexpected value: {v:?}");
    Ok(())
}

#[tokio::test]
async fn read_missing_returns_none() -> anyhow::Result<()> {
    let b = tmp_backend()?;
    let value = b.read(&p("state://nope")?).await?;
    ensure!(value.is_none(), "unexpected value: {value:?}");
    Ok(())
}

#[tokio::test]
async fn bounded_point_read_rejects_raw_row_before_provenance_decode() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("bounded.redb"))?;
    let path = p("state://bounded/value")?;
    let taint = TaintSet::of(xolotl_types::TaintSource::Protected { path: path.clone() });
    let backend = store.state_backend();
    backend
        .write_set_tainted(&path, Value::bytes(vec![9; 4096]), taint.clone())
        .await?;
    let encoded_bytes = {
        let txn = store.db.begin_read()?;
        let table = txn.open_table(STATE_VALUES_TABLE)?;
        path.to_string().len()
            + table
                .get(path.to_string().as_str())?
                .context("missing persisted value")?
                .value()
                .len()
    };
    let too_small = NonZeroUsize::new(encoded_bytes - 1).context("smaller budget")?;
    let failure = backend
        .read_tainted_bounded(&path, too_small)
        .await
        .err()
        .context("oversized point read succeeded")?;
    ensure!(failure.taint.is_pristine());
    let StateError::PointTooLarge(row) = failure.error else {
        bail!("unexpected bounded point error")
    };
    ensure!(
        row.path == path
            && row.encoded_bytes == encoded_bytes
            && row.limit_encoded_bytes == too_small
            && !row.provenance_observed
    );
    let exact = NonZeroUsize::new(encoded_bytes).context("encoded size")?;
    let value = backend.read_tainted_bounded(&path, exact).await?;
    let value_value = value.value.clone().context("bounded exact read missing")?;
    ensure!(value_value == Value::bytes(vec![9; 4096]) && value.taint == taint);
    ensure!(
        backend
            .read_tainted_bounded(&p("state://bounded")?, NonZeroUsize::MIN)
            .await?
            .value
            .is_none(),
        "exact point read returned a descendant"
    );

    let corrupt = p("state://bounded/corrupt")?;
    let mut raw = vec![b'x'; 4096];
    raw[..4].copy_from_slice(b"XSV1");
    raw[4..12].copy_from_slice(&4084_u64.to_le_bytes());
    let txn = store.db.begin_write()?;
    {
        let mut table = txn.open_table(STATE_VALUES_TABLE)?;
        table.insert(corrupt.to_string().as_str(), raw.as_slice())?;
    }
    txn.commit()?;
    let failure = backend
        .read_tainted_bounded(&corrupt, NonZeroUsize::new(1024).context("budget")?)
        .await
        .err()
        .context("oversized malformed point read succeeded")?;
    ensure!(matches!(failure.error, StateError::PointTooLarge(_)));
    ensure!(failure.taint.is_pristine());
    let malformed = backend
        .read_tainted_bounded(&corrupt, NonZeroUsize::new(8192).context("larger budget")?)
        .await
        .err()
        .context("malformed record decoded")?;
    ensure!(matches!(malformed.error, StateError::Serde(_)));
    Ok(())
}

#[tokio::test]
async fn bare_value_encoding_is_rejected() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.keep().join("test.redb");
    let store = RedbStore::open_with_history(path, RedbHistory::Full)?;
    {
        let txn = store.db.begin_write()?;
        {
            let mut table = txn.open_table(crate::STATE_VALUES_TABLE)?;
            let bare = serde_json::to_vec(&Value::integer(7))?;
            table.insert("state://bad-encoding", bare.as_slice())?;
        }
        txn.commit()?;
    }

    let b = store.state_backend();
    let err = match b.read(&p("state://bad-encoding")?).await {
        Ok(value) => bail!("expected encoding error, got {value:?}"),
        Err(error) => error,
    };
    ensure!(
        matches!(&err.error, StateError::Serde(_)),
        "bare Value encoding must not be treated as pristine: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn unsupported_records_are_rejected_without_rewriting_them() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("unsupported-codec.redb");
    let path = p("state://unsupported/value")?;
    let envelope = br#"{"__xolotl_env":1,"value":{"type":"int","value":7},"taint":{"sources":[]}}"#;
    let history = br#"{"at_millis":1,"event":{"type":"set","path":"state://unsupported/value","value":7,"taint":{"sources":[]}}}"#;
    let mut history_key = path.to_string().into_bytes();
    history_key.push(0xff);
    history_key.extend_from_slice(&1_i64.to_be_bytes());
    {
        let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
        let txn = store.db.begin_write()?;
        txn.open_table(STATE_VALUES_TABLE)?
            .insert("state://unsupported/value", envelope.as_slice())?;
        txn.open_table(STATE_HISTORY_TABLE)?
            .insert(history_key.as_slice(), history.as_slice())?;
        txn.commit()?;
    }
    let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
    let backend = store.state_backend();
    ensure!(backend.read_tainted(&path).await.is_err());
    ensure!(backend.read_prefix_tainted(&path).await.is_err());
    ensure!(backend.read_range(&path, 0, i64::MAX).await.is_err());
    let txn = store.db.begin_read()?;
    let values = txn.open_table(STATE_VALUES_TABLE)?;
    ensure!(
        values
            .get("state://unsupported/value")?
            .context("unsupported value was deleted")?
            .value()
            == envelope
    );
    ensure!(raw_history(&store.db)? == [(history_key, history.to_vec())]);
    Ok(())
}

#[tokio::test]
async fn history_payload_identity_must_match_its_index() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let path = p("state://history/identity")?;
    backend.write_set(&path, Value::integer(1)).await?;
    let entries = raw_history(&backend.db)?;
    let (key, original) = entries.first().context("missing history entry")?;
    let entry = decode_history_entry(original)?;
    for (at_millis, event) in [
        (
            entry.at_millis,
            StateEvent::Delete {
                path: p("state://another/identity")?,
                taint: TaintSet::pristine(),
            },
        ),
        (entry.at_millis + 1, entry.event),
    ] {
        let malformed = encode_history_entry(at_millis, &event)?;
        let txn = backend.db.begin_write()?;
        txn.open_table(STATE_HISTORY_TABLE)?
            .insert(key.as_slice(), malformed.as_slice())?;
        txn.commit()?;
        let error = backend
            .read_range(&path, 0, i64::MAX)
            .await
            .err()
            .context("mismatched history identity accepted")?;
        ensure!(matches!(
            error.error,
            StateError::Backend(message) if message.contains("key does not match")
        ));
    }
    Ok(())
}

#[tokio::test]
async fn append_creates_and_grows() -> anyhow::Result<()> {
    let b = tmp_backend()?;
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
}

#[tokio::test]
async fn history_keeps_multiple_events_for_same_path_in_one_millisecond() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.keep().join("test.redb");
    let store = RedbStore::open_with_history(path, RedbHistory::Full)?;
    let state_path = p("state://history/collide")?;
    let txn = store.db.begin_write()?;
    RedbStateBackend::record_history_at_millis_in_txn(
        &txn,
        &StateEvent::Set {
            path: state_path.clone(),
            value: Value::integer(1),
            taint: TaintSet::pristine(),
        },
        1_700_000_000_000,
    )?;
    RedbStateBackend::record_history_at_millis_in_txn(
        &txn,
        &StateEvent::Set {
            path: state_path.clone(),
            value: Value::integer(2),
            taint: TaintSet::pristine(),
        },
        1_700_000_000_000,
    )?;
    txn.commit()?;

    let backend = store.state_backend();
    let entries = backend.read_range(&state_path, 0, i64::MAX).await?;
    ensure!(entries.len() == 2, "unexpected entries: {entries:?}");
    let mut query = xolotl_state::StateHistoryQuery::new(state_path.clone(), 0, i64::MAX);
    query.limits.entries = NonZeroUsize::MIN;
    let mut pages = backend.history_pages(query);
    let mut paged = Vec::new();
    while let Some(page) = pages.next().await? {
        ensure!(page.entries.len() <= 1);
        paged.extend(page.entries);
        ensure!(paged.len() <= 2, "collision cursor repeated records");
    }
    ensure!(paged == entries, "collision pagination changed event order");
    let floor = 1_700_000_000_001;
    let trimmed = StateHistoryRetention::trim_before(
        &backend,
        floor,
        xolotl_state::StateHistoryTrimLimits::default(),
    )
    .await?;
    ensure!(trimmed.removed_events == 2);
    ensure!(backend.read_at(&state_path, floor).await?.value == Some(Value::integer(2)));
    let txn = store.db.begin_read()?;
    ensure!(txn.open_table(STATE_HISTORY_TABLE)?.len()? == 0);
    ensure!(txn.open_table(STATE_HISTORY_TIME_INDEX_TABLE)?.len()? == 0);
    Ok(())
}

#[tokio::test]
async fn history_metadata_orders_writes_across_state_backends() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.keep().join("test.redb");
    let store = RedbStore::open_with_history(path, RedbHistory::Full)?;
    let first = store.state_backend();
    let second = store.state_backend();
    let state_path = p("state://history/shared-clock")?;

    first.write_set(&state_path, Value::integer(1)).await?;
    second.write_set(&state_path, Value::integer(2)).await?;

    let entries = first.read_range(&state_path, 0, i64::MAX).await?;
    match entries.as_slice() {
        [first, second] => {
            ensure!(
                first.at_millis < second.at_millis,
                "history timestamps must preserve write order across backends"
            );
            ensure!(history_millis(&store.db)? == second.at_millis);
        }
        other => bail!("expected 2 entries, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn history_timestamps_survive_reopen_ahead_of_wall_clock() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("history-reopen.redb");
    let path = p("state://history/reopen")?;
    let future_millis = i64::MAX - 16;
    {
        let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
        set_history_millis(&store.db, future_millis)?;
        store
            .state_backend()
            .write_set(&path, Value::integer(1))
            .await?;
        ensure!(history_millis(&store.db)? == future_millis + 1);
    }
    let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
    let backend = store.state_backend();
    ensure!(history_millis(&store.db)? == future_millis + 1);
    backend.write_set(&path, Value::integer(2)).await?;
    let history = backend.read_range(&path, 0, i64::MAX).await?;
    ensure!(
        history
            .iter()
            .map(|entry| entry.at_millis)
            .collect::<Vec<_>>()
            == [future_millis + 1, future_millis + 2]
    );
    ensure!(matches!(
        &history.first().context("missing first write")?.event,
        StateEvent::Set { value, .. } if value.as_int() == Some(1)
    ));
    ensure!(matches!(
        &history.last().context("missing second write")?.event,
        StateEvent::Set { value, .. } if value.as_int() == Some(2)
    ));
    ensure!(history_millis(&store.db)? == future_millis + 2);
    ensure!(backend.read(&path).await? == Some(Value::integer(2)));
    Ok(())
}

#[test]
fn new_and_empty_database_files_initialize_history_metadata() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    for precreated in [false, true] {
        let file = directory.path().join(format!("empty-{precreated}.redb"));
        if precreated {
            drop(crate::open_database(file.clone())?);
        }
        let store = RedbStore::open(&file)?;
        ensure!(history_millis(&store.db)? == 0);
        ensure!(raw_history(&store.db)?.is_empty());
    }
    Ok(())
}

#[test]
fn populated_partial_schema_is_rejected_without_metadata_backfill() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("partial-history.redb");
    let maximum = i64::MAX - 16;
    {
        let db = crate::open_database(file.clone())?;
        let txn = db.begin_write()?;
        {
            let mut history = txn.open_table(STATE_HISTORY_TABLE)?;
            for (path, millis) in [
                ("state://partial/a", 41_i64),
                ("state://partial/m", maximum),
                ("state://partial/z", 77),
            ] {
                let mut key = path.as_bytes().to_vec();
                key.push(0xFF);
                key.extend_from_slice(&millis.to_be_bytes());
                history.insert(key.as_slice(), b"opaque payload".as_slice())?;
                if millis == maximum {
                    key.extend_from_slice(&7_u64.to_be_bytes());
                    history.insert(key.as_slice(), b"collision payload".as_slice())?;
                }
            }
        }
        txn.commit()?;
    }
    ensure!(RedbStore::open(&file).is_err());
    let db = Database::new(crate::open_database(file)?);
    let txn = db.begin_read()?;
    ensure!(matches!(
        txn.open_table(STATE_META_TABLE),
        Err(redb::TableError::TableDoesNotExist(_))
    ));
    ensure!(raw_history(&db)?.len() == 4);
    Ok(())
}

#[test]
fn partial_schema_with_malformed_rows_is_not_initialized() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    for (index, key) in [
        b"missing-separator".as_slice(),
        b"state://short\xff\x00".as_slice(),
        b"\xfe\xff\0\0\0\0\0\0\0\0".as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let file = directory.path().join(format!("malformed-{index}.redb"));
        {
            let db = crate::open_database(file.clone())?;
            let txn = db.begin_write()?;
            {
                let mut history = txn.open_table(STATE_HISTORY_TABLE)?;
                history.insert(key, b"opaque".as_slice())?;
            }
            txn.commit()?;
        }
        match RedbStore::open(&file) {
            Ok(_store) => bail!("partial storage schema was accepted"),
            Err(error) => ensure!(error.to_string().contains("schema table missing")),
        }
        let db = Database::new(crate::open_database(file.clone())?);
        let txn = db.begin_read()?;
        ensure!(matches!(
            txn.open_table(STATE_META_TABLE),
            Err(redb::TableError::TableDoesNotExist(_))
        ));
        ensure!(raw_history(&db)?.len() == 1);
    }
    Ok(())
}

#[tokio::test]
async fn initialized_open_retains_metadata_without_decoding_history_rows() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("initialized-history.redb");
    let maximum = i64::MAX - 16;
    {
        let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
        set_history_millis(&store.db, maximum)?;
        let txn = store.db.begin_write()?;
        {
            let mut history = txn.open_table(STATE_HISTORY_TABLE)?;
            history.insert(b"bad-key".as_slice(), b"opaque".as_slice())?;
        }
        txn.commit()?;
    }
    let store = RedbStore::open_with_history(&file, RedbHistory::Full)?;
    ensure!(history_millis(&store.db)? == maximum);
    let path = p("state://fresh/value")?;
    store
        .state_backend()
        .write_set(&path, Value::integer(1))
        .await?;
    ensure!(history_millis(&store.db)? == maximum + 1);
    ensure!(raw_history(&store.db)?.len() == 2);
    Ok(())
}

#[tokio::test]
async fn missing_history_metadata_rejects_writes_without_resetting_sequence() -> anyhow::Result<()>
{
    let backend = tmp_backend()?;
    let path = p("state://history/missing-meta")?;
    backend.write_set(&path, Value::integer(1)).await?;
    let history = raw_history(&backend.db)?;
    {
        let txn = backend.db.begin_write()?;
        {
            let mut meta = txn.open_table(STATE_META_TABLE)?;
            meta.remove(LAST_HISTORY_MILLIS)?;
        }
        txn.commit()?;
    }
    ensure!(matches!(
        backend.write_set(&path, Value::integer(2)).await,
        Err(xolotl_state::StateFailure { error: StateError::Backend(message), .. }) if message.contains("metadata missing")
    ));
    ensure!(backend.read(&path).await? == Some(Value::integer(1)));
    ensure!(raw_history(&backend.db)? == history);
    let txn = backend.db.begin_read()?;
    ensure!(
        txn.open_table(STATE_META_TABLE)?
            .get(LAST_HISTORY_MILLIS)?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn history_write_failure_rolls_back_allocated_timestamp_and_value() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let path = p("state://history/write-failure")?;
    backend.write_set(&path, Value::integer(1)).await?;
    let before = history_millis(&backend.db)?;
    let incompatible: redb::TableDefinition<&str, u64> =
        redb::TableDefinition::new("state_history");
    {
        let txn = backend.db.begin_write()?;
        ensure!(txn.delete_table(STATE_HISTORY_TABLE)?);
        {
            let mut history = txn.open_table(incompatible)?;
            history.insert("sentinel", 1)?;
        }
        txn.commit()?;
    }
    let mut events = backend.subscribe(&path).await?;
    ensure!(matches!(
        backend.write_set(&path, Value::integer(2)).await,
        Err(xolotl_state::StateFailure {
            error: StateError::Backend(_),
            ..
        })
    ));
    ensure!(backend.read(&path).await? == Some(Value::integer(1)));
    ensure!(history_millis(&backend.db)? == before);
    let txn = backend.db.begin_read()?;
    let history = txn.open_table(incompatible)?;
    ensure!(
        history
            .get("sentinel")?
            .context("missing sentinel")?
            .value()
            == 1
    );
    ensure!(matches!(
        events.try_recv(),
        Err(xolotl_state::StateWatchError::Empty)
    ));
    Ok(())
}

#[tokio::test]
async fn cas_success_and_failure() -> anyhow::Result<()> {
    let b = tmp_backend()?;
    b.write_set(&p("state://k")?, Value::integer(1)).await?;
    b.write_cas(&p("state://k")?, Some(Value::integer(1)), Value::integer(2))
        .await?;
    let value = b.read(&p("state://k")?).await?;
    ensure!(
        value == Some(Value::integer(2)),
        "unexpected value: {value:?}"
    );

    let err = b
        .write_cas(
            &p("state://k")?,
            Some(Value::integer(99)),
            Value::integer(3),
        )
        .await;
    ensure!(
        matches!(
            err,
            Err(xolotl_state::StateFailure {
                error: StateError::CasFailed { .. },
                ..
            })
        ),
        "expected CasFailed"
    );
    Ok(())
}

#[tokio::test]
async fn delete_removes() -> anyhow::Result<()> {
    let b = tmp_backend()?;
    b.write_set(&p("state://k")?, Value::integer(1)).await?;
    b.write_delete(&p("state://k")?).await?;
    let value = b.read(&p("state://k")?).await?;
    ensure!(value.is_none(), "unexpected value: {value:?}");
    Ok(())
}

#[tokio::test]
async fn merge_missing_path_uses_incoming_value() -> anyhow::Result<()> {
    let b = tmp_backend()?;
    b.write_merge(&p("state://k")?, Value::integer(7), MergeRule::Shallow)
        .await?;
    let value = b.read(&p("state://k")?).await?;
    ensure!(
        value == Some(Value::integer(7)),
        "unexpected value: {value:?}"
    );
    Ok(())
}

#[test]
fn concurrent_merges_across_adapters_keep_updates_and_provenance() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store =
        RedbStore::open_with_history(directory.path().join("merge.redb"), RedbHistory::Full)?;
    let path = p("state://merge/concurrent")?;
    let taint = TaintSet::of(xolotl_types::TaintSource::Protected { path: path.clone() });
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    let backend = store.state_backend();
    runtime.block_on(backend.write_set_tainted(
        &path,
        Value::map(Default::default()),
        taint.clone(),
    ))?;
    let workers = (0..4)
        .map(|_| {
            Ok((
                store.clone().state_backend(),
                tokio::runtime::Builder::new_current_thread().build()?,
            ))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let barrier = std::sync::Barrier::new(workers.len());
    std::thread::scope(|scope| -> anyhow::Result<()> {
        let path = &path;
        let barrier = &barrier;
        let tasks = workers
            .into_iter()
            .enumerate()
            .map(|(worker, (backend, runtime))| {
                scope.spawn(move || {
                    (0..8)
                        .map(|round| {
                            barrier.wait();
                            runtime.block_on(backend.write_merge(
                                path,
                                Value::map(std::collections::BTreeMap::from([(
                                    format!("{worker}/{round}"),
                                    Value::boolean(true),
                                )])),
                                MergeRule::Shallow,
                            ))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        for task in tasks {
            for result in task
                .join()
                .map_err(|panic| anyhow!("merge writer panicked: {panic:?}"))?
            {
                result?;
            }
        }
        Ok(())
    })?;
    let current = runtime.block_on(backend.read_tainted(&path))?;
    let current_value = current.value.clone().context("missing merged value")?;
    ensure!(
        current_value
            .as_map()
            .context("merged value is not a map")?
            .len()
            == 32
    );
    ensure!(current.taint == taint);
    let history = runtime.block_on(backend.read_range(&path, 0, i64::MAX))?;
    ensure!(history.len() == 33);
    ensure!(
        history_millis(&store.db)?
            == history
                .last()
                .context("missing concurrent history")?
                .at_millis
    );
    ensure!(
        history
            .windows(2)
            .all(|pair| pair[0].at_millis < pair[1].at_millis)
    );
    for entry in history {
        ensure!(
            matches!(entry.event, StateEvent::Set { taint: recorded, .. } if recorded == taint)
        );
    }
    runtime.block_on(backend.write_merge(&path, Value::integer(9), MergeRule::Deep))?;
    ensure!(
        runtime.block_on(backend.read_tainted(&path))?
            == xolotl_state::StateObservation::from(TaintedValue::new(Value::integer(9), taint))
    );
    Ok(())
}

#[tokio::test]
async fn exhausted_history_rolls_back_value_taint_metadata_and_notifications() -> anyhow::Result<()>
{
    let backend = tmp_backend()?;
    let path = p("state://clock/exhausted")?;
    let missing = p("state://clock/missing")?;
    let value = Value::list(vec![Value::integer(1)]);
    let taint = TaintSet::of(xolotl_types::TaintSource::ModelOutput);
    backend
        .write_set_tainted(&path, value.clone(), taint.clone())
        .await?;
    set_history_millis(&backend.db, i64::MAX - 1)?;
    backend
        .write_set_tainted(&path, value.clone(), taint.clone())
        .await?;
    ensure!(history_millis(&backend.db)? == i64::MAX);
    let history = raw_history(&backend.db)?;
    ensure!(history.len() == 2);
    let mut events = backend.subscribe(&path).await?;
    for result in [
        backend.write_set(&path, Value::null()).await,
        backend.write_append(&path, Value::integer(2)).await,
        backend
            .write_cas(&path, Some(value.clone()), Value::null())
            .await,
        backend.write_delete(&path).await,
        backend
            .write_compare_delete(&path, Some(value.clone()))
            .await,
        backend
            .write_merge(
                &path,
                Value::list(vec![Value::integer(2)]),
                MergeRule::Shallow,
            )
            .await,
        backend.write_set(&missing, Value::null()).await,
        backend.write_append(&missing, Value::integer(2)).await,
        backend.write_cas(&missing, None, Value::null()).await,
        backend
            .write_merge(&missing, Value::null(), MergeRule::Shallow)
            .await,
    ] {
        ensure!(
            matches!(result, Err(xolotl_state::StateFailure { error: StateError::Backend(message), .. }) if message.contains("timestamp exhausted"))
        );
    }
    ensure!(matches!(
        backend
            .write_cas(&path, Some(Value::null()), Value::null())
            .await,
        Err(xolotl_state::StateFailure {
            error: StateError::CasFailed { .. },
            ..
        })
    ));
    backend.write_delete(&missing).await?;
    backend.write_compare_delete(&missing, None).await?;
    ensure!(matches!(
        backend.write_compare_delete(&path, None).await,
        Err(xolotl_state::StateFailure {
            error: StateError::CasFailed { .. },
            ..
        })
    ));
    ensure!(backend.read(&missing).await?.is_none());
    ensure!(
        backend.read_tainted(&path).await?
            == xolotl_state::StateObservation::from(TaintedValue::new(value, taint))
    );
    ensure!(raw_history(&backend.db)? == history);
    ensure!(history_millis(&backend.db)? == i64::MAX);
    ensure!(matches!(
        events.try_recv(),
        Err(xolotl_state::StateWatchError::Empty)
    ));
    Ok(())
}

#[tokio::test]
async fn append_rejects_corrupt_stored_values_without_creating_history() -> anyhow::Result<()> {
    let backend = tmp_backend()?;
    let path = p("state://append/corrupt")?;
    {
        let txn = backend.db.begin_write()?;
        {
            let mut values = txn.open_table(STATE_VALUES_TABLE)?;
            values.insert(path.to_string().as_str(), b"not-json".as_slice())?;
        }
        txn.commit()?;
    }
    let mut events = backend.subscribe(&path).await?;
    ensure!(matches!(
        backend.write_append(&path, Value::integer(1)).await,
        Err(xolotl_state::StateFailure {
            error: StateError::Serde(_),
            ..
        })
    ));
    ensure!(history_millis(&backend.db)? == 0);
    ensure!(raw_history(&backend.db)?.is_empty());
    let txn = backend.db.begin_read()?;
    let values = txn.open_table(STATE_VALUES_TABLE)?;
    ensure!(
        values
            .get(path.to_string().as_str())?
            .context("missing corrupt value")?
            .value()
            == b"not-json"
    );
    ensure!(matches!(
        events.try_recv(),
        Err(xolotl_state::StateWatchError::Empty)
    ));
    Ok(())
}

#[tokio::test]
async fn prefix_scan() -> anyhow::Result<()> {
    let b = tmp_backend()?;
    b.write_set(
        &p("state://memory/alice/persona")?,
        Value::string("hello".into()),
    )
    .await?;
    b.write_set(&p("state://memory/alice/prefs")?, Value::integer(1))
        .await?;
    b.write_set(
        &p("state://memory/bob/persona")?,
        Value::string("world".into()),
    )
    .await?;
    b.write_set(&p("state://other")?, Value::integer(99))
        .await?;

    let results = b.read_prefix(&p("state://memory/alice")?).await?;
    ensure!(results.len() == 2, "unexpected results: {results:?}");
    ensure!(
        results
            .iter()
            .all(|(path, _)| path.to_string().starts_with("state://memory/alice")),
        "unexpected prefix results: {results:?}"
    );
    Ok(())
}

#[tokio::test]
async fn prefix_scan_is_segment_aware() -> anyhow::Result<()> {
    let b = tmp_backend()?;
    b.write_set(&p("state://memory/alice")?, Value::integer(1))
        .await?;
    b.write_set(&p("state://memory/aliceevil")?, Value::integer(2))
        .await?;
    b.write_set(&p("state://memory/alice/prefs")?, Value::integer(3))
        .await?;

    let results = b.read_prefix(&p("state://memory/alice")?).await?;
    let paths: Vec<String> = results
        .into_iter()
        .map(|(path, _)| path.to_string())
        .collect();
    ensure!(
        paths == vec!["state://memory/alice", "state://memory/alice/prefs"],
        "unexpected paths: {paths:?}"
    );
    Ok(())
}

#[tokio::test]
async fn read_range_includes_descendants_but_not_string_prefix_siblings() -> anyhow::Result<()> {
    let b = tmp_backend()?;
    b.write_set(&p("state://memory")?, Value::integer(1))
        .await?;
    b.write_set(&p("state://memory/alice")?, Value::integer(2))
        .await?;
    b.write_set(&p("state://memoryevil")?, Value::integer(3))
        .await?;

    let entries = b.read_range(&p("state://memory")?, 0, i64::MAX).await?;
    let paths: Vec<String> = entries
        .into_iter()
        .map(|entry| match entry.event {
            StateEvent::Set { path, .. } => path.to_string(),
            StateEvent::Append { path, .. } => path.to_string(),
            StateEvent::DropPrefixAppend { path, .. } => path.to_string(),
            StateEvent::Delete { path, .. } => path.to_string(),
        })
        .collect();
    ensure!(
        paths == vec!["state://memory", "state://memory/alice"],
        "unexpected paths: {paths:?}"
    );
    Ok(())
}

#[tokio::test]
async fn subscribe_receives_events() -> anyhow::Result<()> {
    let b = tmp_backend()?;
    let mut rx = b.subscribe(&p("state://watched/**")?).await?;
    b.write_set(&p("state://watched/a")?, Value::integer(1))
        .await?;
    let ev = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
        .await
        .map_err(|error| anyhow!("timed out waiting for event: {error}"))?
        .map_err(|error| anyhow!("event receive failed: {error}"))?;
    match ev {
        StateEvent::Set { path, .. } => ensure!(
            path.to_string() == "state://watched/a",
            "unexpected path: {path}"
        ),
        other => bail!("wrong event: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn independent_adapters_share_subscriptions_after_committed_writes() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("subscriptions.redb"))?;
    let reader = store.state_backend();
    let writer = store.clone().state_backend();
    let path = p("state://watched/shared")?;
    writer.write_set(&path, Value::integer(1)).await?;
    ensure!(
        !reader.publication.subscriptions().is_initialized(),
        "a write initialized unused subscriptions"
    );
    let mut events = reader.subscribe(&p("state://watched/**")?).await?;
    writer.write_set(&path, Value::integer(2)).await?;
    match events.try_recv()? {
        StateEvent::Set {
            path: observed,
            value,
            ..
        } => {
            ensure!(observed == path && value == Value::integer(2));
        }
        other => bail!("unexpected event: {other:?}"),
    }
    ensure!(reader.read(&path).await? == Some(Value::integer(2)));
    Ok(())
}
