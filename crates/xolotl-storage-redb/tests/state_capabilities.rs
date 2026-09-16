use anyhow::{Context, ensure};
use std::{collections::BTreeMap, num::NonZeroUsize};
use xolotl_state::{
    InMemoryBackend, InMemoryOptions, StateError, StateHistoryQuery, StatePageLimits, StateScan,
    TaintedValue, prelude::*,
};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{Path, TaintSet, TaintSource, Value};

async fn bounded_pages<T: StateRead + StateWrite + StateQuery + StateHistory>(
    backend: &T,
) -> anyhow::Result<()> {
    let prefix = Path::parse("state://scope")?;
    let taint = TaintSet::of(TaintSource::ModelOutput);
    let mut expected = BTreeMap::new();
    for (index, key) in [
        "state://scope",
        "state://scope/a",
        "state://scope/a/b",
        "state://scope/z",
        "state://scope-b",
        "state://scope-c",
    ]
    .into_iter()
    .enumerate()
    {
        let path = Path::parse(key)?;
        let value = TaintedValue::new(Value::integer(index as i64), taint.clone());
        backend
            .write_set_tainted(&path, value.value.clone(), value.taint.clone())
            .await?;
        if path == prefix || prefix.is_prefix_of(&path) {
            expected.insert(path, value);
        }
    }
    let limits = StatePageLimits {
        entries: NonZeroUsize::MIN.saturating_add(1),
        examined: NonZeroUsize::MIN,
        encoded_bytes: NonZeroUsize::MIN.saturating_add(4095),
    };
    let mut scan = StateScan::new(prefix.clone());
    scan.limits = limits;
    let mut pages = backend.pages(scan);
    let mut actual = BTreeMap::new();
    let mut calls = 0;
    while let Some(page) = pages.next().await? {
        calls += 1;
        ensure!(calls <= 8, "cursor failed to terminate");
        ensure!(page.examined <= limits.examined.get());
        ensure!(page.entries.len() <= limits.entries.get());
        ensure!(page.encoded_bytes <= limits.encoded_bytes.get());
        for (path, value) in page.entries {
            ensure!(
                actual.insert(path, value).is_none(),
                "duplicate row across pages"
            );
        }
    }
    ensure!(actual == expected);
    let mut query = StateHistoryQuery::new(prefix, 0, i64::MAX);
    query.limits = limits;
    let mut pages = backend.history_pages(query);
    let mut history = BTreeMap::new();
    let mut calls = 0;
    while let Some(page) = pages.next().await? {
        calls += 1;
        ensure!(calls <= 8);
        ensure!(page.examined <= limits.examined.get());
        ensure!(page.entries.len() <= limits.entries.get());
        ensure!(page.encoded_bytes <= limits.encoded_bytes.get());
        for entry in page.entries {
            let xolotl_state::StateEvent::Set { path, value, taint } = entry.event else {
                anyhow::bail!("unexpected mutation");
            };
            ensure!(
                history
                    .insert(path, TaintedValue::new(value, taint))
                    .is_none()
            );
        }
    }
    ensure!(history == expected);

    let prefix = Path::parse("state://oversized")?;
    let large = prefix.clone().try_push("a")?;
    let small = prefix.clone().try_push("b")?;
    backend
        .write_set(&large, Value::bytes(vec![7; 4096]))
        .await?;
    backend.write_set(&small, Value::null()).await?;
    let mut scan = StateScan::new(prefix);
    scan.limits.encoded_bytes = NonZeroUsize::MIN.saturating_add(255);
    let error = match backend.query(&scan).await {
        Err(xolotl_state::StateFailure {
            error: StateError::RowTooLarge(error),
            ..
        }) => error,
        other => anyhow::bail!("expected explicit oversized row diagnosis, got {other:?}"),
    };
    ensure!(error.path == large && error.retry.is_none());
    ensure!(error.encoded_bytes > scan.limits.encoded_bytes.get());
    scan.cursor = error.retry.clone();
    scan.limits.encoded_bytes = NonZeroUsize::new(error.encoded_bytes).context("zero row size")?;
    let page = backend.query(&scan).await?;
    ensure!(page.entries.first().map(|row| &row.0) == Some(&large));
    scan.cursor = Some(error.resume);
    scan.limits.encoded_bytes = NonZeroUsize::MIN.saturating_add(255);
    let page = backend.query(&scan).await?;
    ensure!(page.entries == [(small, TaintedValue::pristine(Value::null()))]);

    let sequence = Path::parse("state://sequence")?;
    let protected = TaintSet::of(TaintSource::Protected {
        path: sequence.clone(),
    });
    backend
        .write_set_tainted(
            &sequence,
            Value::list(vec![Value::integer(1)]),
            protected.clone(),
        )
        .await?;
    backend
        .write_append_tainted(&sequence, Value::integer(2), taint.clone())
        .await?;
    backend.write_delete(&sequence).await?;
    let page = backend
        .history(&StateHistoryQuery::new(sequence.clone(), 0, i64::MAX))
        .await?;
    let first = page.entries.first().context("missing first event")?;
    let second = page.entries.get(1).context("missing second event")?;
    let third = page.entries.get(2).context("missing delete event")?;
    ensure!(
        backend.read_at(&sequence, first.at_millis).await?
            == Some(TaintedValue::new(
                Value::list(vec![Value::integer(1)]),
                protected.clone()
            ))
    );
    let mut union = protected;
    union.union(&taint);
    ensure!(
        backend.read_at(&sequence, second.at_millis).await?
            == Some(TaintedValue::new(
                Value::list(vec![Value::integer(1), Value::integer(2)]),
                union
            ))
    );
    ensure!(backend.read_at(&sequence, third.at_millis).await?.is_none());

    let path = Path::parse("state://oversized-history")?;
    backend
        .write_set(&path, Value::bytes(vec![8; 4096]))
        .await?;
    backend.write_set(&path, Value::integer(3)).await?;
    let mut query = StateHistoryQuery::new(path.clone(), 0, i64::MAX);
    query.limits.encoded_bytes = NonZeroUsize::MIN.saturating_add(255);
    let error = match backend.history(&query).await {
        Err(xolotl_state::StateFailure {
            error: StateError::RowTooLarge(error),
            ..
        }) => error,
        other => anyhow::bail!("expected oversized history row, got {other:?}"),
    };
    ensure!(error.path == path);
    query.cursor = error.retry.clone();
    query.limits.encoded_bytes =
        NonZeroUsize::new(error.encoded_bytes).context("zero history size")?;
    let page = backend.history(&query).await?;
    ensure!(page.entries.len() == 1);
    query.cursor = Some(error.resume);
    query.limits.encoded_bytes = NonZeroUsize::MIN.saturating_add(255);
    let page = backend.history(&query).await?;
    ensure!(page.entries.len() == 1);
    ensure!(matches!(
        &page.entries[0].event,
        xolotl_state::StateEvent::Set { value, .. } if value.as_int() == Some(3)
    ));
    Ok(())
}

#[tokio::test]
async fn memory_capabilities_obey_bounded_contracts() -> anyhow::Result<()> {
    for read_shards in [NonZeroUsize::MIN, NonZeroUsize::MIN.saturating_add(6)] {
        bounded_pages(&InMemoryBackend::with_options(InMemoryOptions {
            read_shards,
            ..InMemoryOptions::default()
        })?)
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn redb_capabilities_obey_bounded_contracts() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("state.redb"))?;
    bounded_pages(&store.state_backend()).await
}
