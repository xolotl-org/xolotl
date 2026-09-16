use super::*;
use crate::RedbStore;
use anyhow::{Context, anyhow, bail, ensure};
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
    Ok(RedbStore::open(path)?.state_backend())
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
async fn bare_value_encoding_is_rejected() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.keep().join("test.redb");
    let store = RedbStore::open(path)?;
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
        let store = RedbStore::open(&file)?;
        let txn = store.db.begin_write()?;
        txn.open_table(STATE_VALUES_TABLE)?
            .insert("state://unsupported/value", envelope.as_slice())?;
        txn.open_table(STATE_HISTORY_TABLE)?
            .insert(history_key.as_slice(), history.as_slice())?;
        txn.commit()?;
    }
    let store = RedbStore::open(&file)?;
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
    let store = RedbStore::open(path)?;
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
    Ok(())
}

#[tokio::test]
async fn history_metadata_orders_writes_across_state_backends() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.keep().join("test.redb");
    let store = RedbStore::open(path)?;
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
        let store = RedbStore::open(&file)?;
        set_history_millis(&store.db, future_millis)?;
        store
            .state_backend()
            .write_set(&path, Value::integer(1))
            .await?;
        ensure!(history_millis(&store.db)? == future_millis + 1);
    }
    let store = RedbStore::open(&file)?;
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
            drop(Database::create(&file)?);
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
        let db = Database::create(&file)?;
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
    let db = Database::create(&file)?;
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
            let db = Database::create(&file)?;
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
        let db = Database::create(&file)?;
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
        let store = RedbStore::open(&file)?;
        set_history_millis(&store.db, maximum)?;
        let txn = store.db.begin_write()?;
        {
            let mut history = txn.open_table(STATE_HISTORY_TABLE)?;
            history.insert(b"bad-key".as_slice(), b"opaque".as_slice())?;
        }
        txn.commit()?;
    }
    let store = RedbStore::open(&file)?;
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
    let store = RedbStore::open(directory.path().join("merge.redb"))?;
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
    let current = runtime
        .block_on(backend.read_tainted(&path))?
        .context("missing merged value")?;
    ensure!(
        current
            .value
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
            == Some(TaintedValue::new(Value::integer(9), taint))
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
    ensure!(backend.read_tainted(&path).await? == Some(TaintedValue::new(value, taint)));
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
        !reader.subs.is_initialized(),
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
