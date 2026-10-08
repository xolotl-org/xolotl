use anyhow::{Context, Result, ensure};
use redb::{ReadableDatabase, ReadableTable};
use std::num::NonZeroUsize;
use xolotl_state::{
    AbsenceLimits, Backend, InMemoryBackend, InMemoryOptions, MemoryHistory, StateError,
    StateHistoryQuery, StateScan, StateWatchError,
};
use xolotl_storage_redb::{RedbHistory, RedbOptions, RedbStore};
use xolotl_types::{Path, TaintSet, Value};

async fn assert_atomic_limits(state: Backend) -> Result<()> {
    let first = Path::parse("state://absence-limits/a")?;
    let second = Path::parse("state://absence-limits/b")?;
    let author = TaintSet::author();
    for path in [&first, &second] {
        state
            .write_set_tainted(path, Value::integer(1), author.clone())
            .await?;
    }
    state
        .write_compare_delete(&first, Some(Value::integer(1)))
        .await?;
    let first_before = state.read_tainted(&first).await?;
    let second_before = state.read_tainted(&second).await?;
    let query = StateHistoryQuery::new(Path::parse("state://absence-limits")?, 0, i64::MAX);
    let history_before = if state.has_history() {
        Some(state.history(&query).await?.entries)
    } else {
        None
    };
    let mut events = state
        .subscribe(&Path::parse("state://absence-limits/**")?)
        .await?;
    for bounded in [false, true] {
        let failure = if bounded {
            state
                .write_compare_delete_tainted_bounded(
                    &second,
                    Some(Value::integer(1)),
                    author.clone(),
                    NonZeroUsize::MAX,
                )
                .await
        } else {
            state
                .write_compare_delete(&second, Some(Value::integer(1)))
                .await
        }
        .err()
        .context("over-limit CAS delete succeeded")?;
        ensure!(
            matches!(failure.error, StateError::Backend(ref reason) if reason == "state absence capacity exhausted")
        );
        ensure!(failure.taint == author);
        ensure!(state.read_tainted(&first).await? == first_before);
        ensure!(state.read_tainted(&second).await? == second_before);
        ensure!(matches!(events.try_recv(), Err(StateWatchError::Empty)));
    }
    if let Some(history_before) = history_before {
        ensure!(state.history(&query).await?.entries == history_before);
    }
    ensure!(matches!(
        state
            .write_compare_delete(&second, Some(Value::null()))
            .await,
        Err(xolotl_state::StateFailure {
            error: StateError::CasFailed { .. },
            ..
        })
    ));
    state.write_set(&first, Value::null()).await?;
    state.write_delete(&second).await?;
    ensure!(state.read_tainted(&second).await?.value.is_none());
    ensure!(state.read_tainted(&second).await?.taint == author);
    Ok(())
}

#[tokio::test]
async fn absence_limits_share_atomic_cas_contract_across_backends() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let limits = AbsenceLimits {
        records: Some(1),
        encoded_bytes: None,
    };
    for history in [MemoryHistory::Full, MemoryHistory::Disabled] {
        for read_shards in [NonZeroUsize::MIN, NonZeroUsize::new(4).context("shards")?] {
            assert_atomic_limits(
                InMemoryBackend::with_options(InMemoryOptions {
                    absence_limits: limits,
                    history,
                    read_shards,
                    ..Default::default()
                })?
                .into_backend(),
            )
            .await?;
        }
    }
    for history in [RedbHistory::Full, RedbHistory::CurrentOnly] {
        let store = RedbStore::open_with_options(
            directory.path().join(format!("{history:?}.redb")),
            RedbOptions {
                history,
                absence_limits: limits,
                ..Default::default()
            },
        )?;
        assert_atomic_limits(store.state_backend().into_backend()).await?;
    }
    Ok(())
}

#[tokio::test]
async fn exact_absence_byte_budget_includes_full_encoding_and_key_across_backends() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let first = Path::parse("state://absence-byte-budget/long-canonical-key/a")?;
    let second = Path::parse("state://absence-byte-budget/long-canonical-key/b")?;
    let author = TaintSet::author();
    for history in [RedbHistory::Full, RedbHistory::CurrentOnly] {
        for shards in [None, Some(NonZeroUsize::MIN), NonZeroUsize::new(4)] {
            let make = |limits, name: &str| -> Result<Backend> {
                Ok(if let Some(read_shards) = shards {
                    InMemoryBackend::with_options(InMemoryOptions {
                        read_shards,
                        history: if history == RedbHistory::Full {
                            MemoryHistory::Full
                        } else {
                            MemoryHistory::Disabled
                        },
                        absence_limits: limits,
                        ..Default::default()
                    })?
                    .into_backend()
                } else {
                    RedbStore::open_with_options(
                        directory
                            .path()
                            .join(format!("bytes-{history:?}-{name}.redb")),
                        RedbOptions {
                            history,
                            absence_limits: limits,
                            ..Default::default()
                        },
                    )?
                    .state_backend()
                    .into_backend()
                })
            };
            let probe = make(
                AbsenceLimits {
                    records: None,
                    encoded_bytes: None,
                },
                "probe",
            )?;
            probe
                .write_set_tainted(&first, Value::integer(1), author.clone())
                .await?;
            probe.write_delete_tainted(&first, author.clone()).await?;
            let charge = probe
                .query(&StateScan::new(first.clone()))
                .await?
                .encoded_bytes;
            ensure!(charge > first.to_string().len());
            drop(probe);
            let exact = make(
                AbsenceLimits {
                    records: None,
                    encoded_bytes: Some(charge),
                },
                "exact",
            )?;
            for path in [&first, &second] {
                exact
                    .write_set_tainted(path, Value::integer(1), author.clone())
                    .await?;
            }
            exact.write_delete_tainted(&first, author.clone()).await?;
            ensure!(
                exact
                    .query(&StateScan::new(first.clone()))
                    .await?
                    .encoded_bytes
                    == charge
            );
            ensure!(
                exact
                    .write_delete_tainted(&second, author.clone())
                    .await
                    .is_err()
            );
            ensure!(exact.read(&second).await? == Some(Value::integer(1)));
            exact
                .write_cas_bounded(&first, None, Value::null(), NonZeroUsize::MAX)
                .await?;
            exact.write_delete_tainted(&second, author.clone()).await?;
            let short = make(
                AbsenceLimits {
                    records: None,
                    encoded_bytes: Some(charge - 1),
                },
                "short",
            )?;
            short
                .write_set_tainted(&first, Value::integer(1), author.clone())
                .await?;
            ensure!(
                short
                    .write_delete_tainted(&first, author.clone())
                    .await
                    .is_err()
            );
            ensure!(short.read(&first).await? == Some(Value::integer(1)));
        }
    }
    Ok(())
}

#[tokio::test]
async fn missing_absence_counters_reject_reopen_without_resetting_retained_evidence() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let first = Path::parse("state://absence-accounting/a")?;
    for missing in [
        vec!["absence_records_v1"],
        vec!["absence_encoded_bytes_v1"],
        vec!["absence_records_v1", "absence_encoded_bytes_v1"],
    ] {
        let file = directory
            .path()
            .join(format!("missing-{}.redb", missing.join("-")));
        {
            let state = RedbStore::open(&file)?.state_backend().into_backend();
            state
                .write_set_tainted(&first, Value::integer(1), TaintSet::author())
                .await?;
            state
                .write_delete_tainted(&first, TaintSet::author())
                .await?;
        }
        let retained = {
            let db = redb::Database::open(&file)?;
            let txn = db.begin_write()?;
            let retained = txn
                .open_table(redb::TableDefinition::<&str, &[u8]>::new("state_values"))?
                .get(first.to_string().as_str())?
                .context("retained absence missing")?
                .value()
                .to_vec();
            {
                let mut meta =
                    txn.open_table(redb::TableDefinition::<&str, i64>::new("state_meta"))?;
                for key in &missing {
                    meta.remove(*key)?;
                }
            }
            txn.commit()?;
            retained
        };
        let failure = RedbStore::open(&file)
            .err()
            .context("missing accounting reopened")?;
        ensure!(failure.to_string().contains("state metadata missing"));
        ensure!(missing.iter().any(|key| failure.to_string().contains(key)));
        let db = redb::Database::open(&file)?;
        let txn = db.begin_read()?;
        let values = txn.open_table(redb::TableDefinition::<&str, &[u8]>::new("state_values"))?;
        ensure!(
            values
                .get(first.to_string().as_str())?
                .context("evidence erased")?
                .value()
                == retained
        );
        let meta = txn.open_table(redb::TableDefinition::<&str, i64>::new("state_meta"))?;
        for key in missing {
            ensure!(meta.get(key)?.is_none());
        }
    }
    Ok(())
}

#[tokio::test]
async fn reopen_preserves_usage_and_allows_only_non_growing_over_limit_dimensions() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for history in [RedbHistory::Full, RedbHistory::CurrentOnly] {
        let file = directory.path().join(format!("reopen-{history:?}.redb"));
        let first = Path::parse("state://absence-limits/a")?;
        let second = Path::parse("state://absence-limits/b")?;
        let third = Path::parse("state://absence-limits/c")?;
        let author = TaintSet::author();
        let total_bytes;
        {
            let store = RedbStore::open_with_options(
                &file,
                RedbOptions {
                    history,
                    absence_limits: AbsenceLimits {
                        records: None,
                        encoded_bytes: None,
                    },
                    ..Default::default()
                },
            )?;
            let state = store.state_backend().into_backend();
            for path in [&first, &second] {
                state
                    .write_set_tainted(path, Value::integer(1), author.clone())
                    .await?;
                state.write_delete_tainted(path, author.clone()).await?;
            }
            state
                .write_set_tainted(&third, Value::integer(3), author.clone())
                .await?;
            total_bytes = state
                .query(&StateScan::new(Path::parse("state://absence-limits")?))
                .await?
                .encoded_bytes
                - state
                    .query(&StateScan::new(third.clone()))
                    .await?
                    .encoded_bytes;
        }
        {
            let store = RedbStore::open_with_options(
                &file,
                RedbOptions {
                    history,
                    absence_limits: AbsenceLimits {
                        records: Some(1),
                        encoded_bytes: Some(total_bytes - 1),
                    },
                    ..Default::default()
                },
            )?;
            let state = store.state_backend().into_backend();
            state.write_delete_tainted(&first, author.clone()).await?;
            let before = state.read_tainted(&first).await?;
            let input = TaintSet::of(xolotl_types::TaintSource::ModelOutput);
            let committed = state.write_delete_tainted(&first, input.clone()).await?;
            ensure!(committed.taint.contains_all(&author) && committed.taint.contains_all(&input));
            ensure!(state.read_tainted(&first).await? == before);
            ensure!(state.write_delete(&third).await.is_err());
            ensure!(state.read(&third).await? == Some(Value::integer(3)));
            state.write_set(&first, Value::null()).await?;
            ensure!(state.write_delete(&third).await.is_err());
            state.write_set(&second, Value::null()).await?;
            state.write_delete(&third).await?;
        }
        let store = RedbStore::open_with_options(
            &file,
            RedbOptions {
                history,
                absence_limits: AbsenceLimits {
                    records: Some(1),
                    encoded_bytes: None,
                },
                ..Default::default()
            },
        )?;
        let state = store.state_backend().into_backend();
        ensure!(state.read_tainted(&third).await?.taint == author);
        ensure!(state.write_delete_tainted(&first, author).await.is_err());
    }
    Ok(())
}
