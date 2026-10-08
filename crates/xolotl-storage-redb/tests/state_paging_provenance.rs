use anyhow::{Context, ensure};
use std::{collections::BTreeMap, num::NonZeroUsize};
use xolotl_state::{
    InMemoryBackend, InMemoryOptions, MemoryHistory, StateError, StateHistoryQuery, StateScan,
    TaintedValue, prelude::*,
};
use xolotl_storage_redb::{RedbHistory, RedbStore};
use xolotl_types::{Path, TaintSet, TaintSource, Value};

fn bytes_limit(bytes: usize) -> anyhow::Result<NonZeroUsize> {
    NonZeroUsize::new(bytes).context("zero page byte limit")
}

fn source(path: &Path) -> TaintSet {
    TaintSet::of(TaintSource::Protected { path: path.clone() })
}

fn oversized_source() -> anyhow::Result<TaintSet> {
    Ok(source(&Path::parse(&format!(
        "state://private/{}",
        "s".repeat(8192)
    ))?))
}

async fn scoped_pages<T: StateWrite + StateQuery + StateHistory>(
    backend: &T,
    prefix: Path,
    inside: &[&str],
    outside: &[&str],
    precise_ranges: bool,
) -> anyhow::Result<()> {
    let mut expected = BTreeMap::new();
    let mut expected_taint = TaintSet::pristine();
    for (index, raw) in inside.iter().enumerate() {
        let path = Path::parse(raw)?;
        let taint = source(&path);
        let value = Value::integer(index as i64);
        backend
            .write_set_tainted(&path, value.clone(), taint.clone())
            .await?;
        expected_taint.union(&taint);
        expected.insert(path, TaintedValue::new(value, taint));
    }
    let mut scan = StateScan::new(prefix.clone());
    scan.limits.encoded_bytes = bytes_limit(4096)?;
    let mut query = StateHistoryQuery::new(prefix, 0, i64::MAX);
    query.limits = scan.limits;
    let before_current = backend.query(&scan).await?;
    let before_history = backend.history(&query).await?;
    let mut expected_history_taint = TaintSet::pristine();
    for entry in &before_history.entries {
        expected_history_taint.union(entry.event.taint());
    }
    ensure!(expected_history_taint.contains_all(&expected_taint));
    ensure!(expected_taint.contains_all(&expected_history_taint));
    for raw in outside {
        let path = Path::parse(raw)?;
        let mut taint = oversized_source()?;
        taint.union(&source(&path));
        backend
            .write_set_tainted(&path, Value::bytes(vec![7; 128 * 1024]), taint)
            .await?;
    }
    let current = backend.query(&scan).await?;
    let history = backend.history(&query).await?;
    ensure!(current.next.is_none() && history.next.is_none());
    ensure!(current.entries == before_current.entries);
    ensure!(history.entries == before_history.entries);
    ensure!(current.encoded_bytes == before_current.encoded_bytes);
    ensure!(history.encoded_bytes == before_history.encoded_bytes);
    ensure!(current.taint == expected_taint && history.taint == expected_history_taint);
    if precise_ranges {
        ensure!(current.examined == inside.len());
        ensure!(history.examined == inside.len());
    }

    scan.limits.examined = NonZeroUsize::MIN;
    query.limits.examined = NonZeroUsize::MIN;
    let mut current_pages = backend.pages(scan);
    let mut actual = BTreeMap::new();
    let mut observed = TaintSet::pristine();
    let mut calls = 0;
    while let Some(page) = current_pages.next().await? {
        calls += 1;
        ensure!(calls <= inside.len() + outside.len() + 2);
        ensure!(page.examined <= 1 && page.encoded_bytes <= 4096);
        observed.union(&page.taint);
        for (path, value) in page.entries {
            ensure!(actual.insert(path, value).is_none(), "repeated current row");
        }
    }
    ensure!(actual == expected && observed == expected_taint);
    let mut history_pages = backend.history_pages(query);
    let mut actual = BTreeMap::new();
    let mut history_order = Vec::new();
    let mut observed = TaintSet::pristine();
    let mut calls = 0;
    while let Some(page) = history_pages.next().await? {
        calls += 1;
        ensure!(calls <= inside.len() + outside.len() + 2);
        ensure!(page.examined <= 1 && page.encoded_bytes <= 4096);
        observed.union(&page.taint);
        for entry in page.entries {
            history_order.push(entry.clone());
            let xolotl_state::StateEvent::Set { path, value, taint } = entry.event else {
                anyhow::bail!("unexpected history event");
            };
            ensure!(
                actual
                    .insert(path, TaintedValue::new(value, taint))
                    .is_none(),
                "repeated history row"
            );
        }
    }
    ensure!(actual == expected && observed == expected_history_taint);
    ensure!(
        history_order == before_history.entries,
        "history continuation changed record order"
    );
    Ok(())
}

async fn punctuation_scope<T: StateWrite + StateQuery + StateHistory>(
    backend: &T,
    precise_ranges: bool,
) -> anyhow::Result<()> {
    scoped_pages(
        backend,
        Path::parse("state://scope")?,
        &[
            "state://scope",
            "state://scope/a",
            "state://scope/a/b",
            "state://scope/z",
        ],
        &[
            "state://scope-b",
            "state://scope.b",
            "state://scope:tail",
            "state://scope0",
        ],
        precise_ranges,
    )
    .await
}

async fn root_scope<T: StateWrite + StateQuery + StateHistory>(
    backend: &T,
    precise_ranges: bool,
) -> anyhow::Result<()> {
    scoped_pages(
        backend,
        Path::parse("state://")?,
        &["state://", "state://a", "state://a/b", "state://z"],
        &["state-other://a", "path://foreign/state/a"],
        precise_ranges,
    )
    .await
}

async fn clustered_root_scope<T: StateWrite + StateQuery + StateHistory>(
    backend: &T,
    precise_ranges: bool,
) -> anyhow::Result<()> {
    scoped_pages(
        backend,
        Path::parse("path://cluster/state")?,
        &[
            "path://cluster/state",
            "path://cluster/state/a",
            "path://cluster/state/z",
        ],
        &[
            "path://cluster/state-other/a",
            "path://cluster/state0/a",
            "path://other/state/a",
            "state://a",
        ],
        precise_ranges,
    )
    .await
}

async fn sibling_cursor<T: StateWrite + StateQuery + StateHistory>(
    backend: &T,
    _precise_ranges: bool,
) -> anyhow::Result<()> {
    let sibling = Path::parse("state://scope-b")?;
    for suffix in ["a", "b"] {
        let path = sibling.clone().try_push(suffix)?;
        backend
            .write_set_tainted(&path, Value::null(), source(&path))
            .await?;
    }
    let mut scan = StateScan::new(sibling);
    scan.limits.entries = NonZeroUsize::MIN;
    let cursor = backend.query(&scan).await?.next.context("sibling cursor")?;
    let mut target = StateScan::new(Path::parse("state://scope")?);
    target.cursor = Some(cursor);
    let failure = backend
        .query(&target)
        .await
        .err()
        .context("accepted sibling cursor")?;
    ensure!(matches!(failure.error, StateError::InvalidQuery(_)));
    ensure!(failure.taint.is_pristine());
    Ok(())
}

async fn removed_cursor_key<T: StateWrite + StateQuery + StateHistory>(
    backend: &T,
    _precise_ranges: bool,
) -> anyhow::Result<()> {
    let prefix = Path::parse("state://removed-cursor")?;
    let paths = [
        prefix.clone(),
        prefix.clone().try_push("a")?,
        prefix.clone().try_push("b")?,
    ];
    for path in &paths {
        backend.write_set(path, Value::null()).await?;
    }
    let mut scan = StateScan::new(prefix);
    scan.limits.entries = NonZeroUsize::MIN;
    for path in paths {
        let page = backend.query(&scan).await?;
        ensure!(page.entries.len() == 1 && page.entries[0].0 == path);
        scan.cursor = Some(page.next.context("one-entry page continuation")?);
        backend.write_delete(&path).await?;
    }
    let page = backend.query(&scan).await?;
    ensure!(page.entries.is_empty() && page.next.is_none());
    ensure!(page.examined == 0 && page.encoded_bytes == 0 && page.taint.is_pristine());
    Ok(())
}

async fn filtered_header_bytes<T: StateHistory>(backend: &T, path: Path) -> anyhow::Result<usize> {
    let page = backend.history(&StateHistoryQuery::new(path, 0, 1)).await?;
    ensure!(page.entries.is_empty() && page.next.is_none());
    ensure!(page.encoded_bytes > 0, "filtered metadata was not charged");
    Ok(page.encoded_bytes)
}

async fn filtered_only_pages<T: StateWrite + StateQuery + StateHistory>(
    backend: &T,
    _precise_ranges: bool,
) -> anyhow::Result<()> {
    let prefix = Path::parse("state://filtered")?;
    let mut headers = Vec::new();
    let mut expected_taint = TaintSet::pristine();
    for suffix in ["a", "b", "c", "d", "e", "f"] {
        let path = prefix.clone().try_push(suffix)?;
        let taint = source(&path);
        backend
            .write_set_tainted(&path, Value::bytes(vec![9; 128 * 1024]), taint.clone())
            .await?;
        let bytes = filtered_header_bytes(backend, path).await?;
        ensure!(bytes < 4096, "filtered accounting included the payload");
        expected_taint.union(&taint);
        headers.push((taint, bytes));
    }
    let limit = headers
        .iter()
        .map(|(_, bytes)| *bytes)
        .max()
        .context("headers")?
        + 1;
    ensure!(headers.iter().all(|(_, bytes)| *bytes > limit / 2));
    let expected_bytes: usize = headers.iter().map(|(_, bytes)| bytes).sum();
    ensure!(expected_bytes > limit);
    let mut query = StateHistoryQuery::new(prefix, 0, 1);
    query.limits.encoded_bytes = bytes_limit(limit)?;
    let mut pages = backend.history_pages(query);
    let mut observed = TaintSet::pristine();
    let mut consumed = 0;
    let mut calls = 0;
    while let Some(page) = pages.next().await? {
        calls += 1;
        ensure!(
            calls <= headers.len() + 1,
            "filtered cursor did not advance"
        );
        ensure!(page.entries.is_empty());
        ensure!(page.encoded_bytes <= limit);
        let (consumed_taint, consumed_bytes) =
            headers.get(calls - 1).context("extra filtered page")?;
        ensure!(page.encoded_bytes == *consumed_bytes);
        let mut expected_page_taint = consumed_taint.clone();
        if let Some((boundary_taint, _)) = headers.get(calls) {
            ensure!(page.next.is_some(), "filtered boundary lost continuation");
            expected_page_taint.union(boundary_taint);
        }
        ensure!(
            page.taint == expected_page_taint,
            "wrong consumed/boundary sources"
        );
        let observed_bytes: usize = headers
            .iter()
            .filter(|(taint, _)| page.taint.contains_all(taint))
            .map(|(_, bytes)| bytes)
            .sum();
        ensure!(observed_bytes <= 2 * limit, "unbounded boundary provenance");
        consumed += page.encoded_bytes;
        observed.union(&page.taint);
    }
    ensure!(
        calls == headers.len(),
        "filtered rows bypassed byte pagination"
    );
    ensure!(
        consumed == expected_bytes,
        "metadata skipped or charged twice"
    );
    ensure!(observed == expected_taint);
    Ok(())
}

async fn filtered_header_rejection<T: StateWrite + StateQuery + StateHistory>(
    backend: &T,
    precise_ranges: bool,
) -> anyhow::Result<()> {
    let prefix = Path::parse("state://headers")?;
    let first = prefix.clone().try_push("a")?;
    let large = prefix.clone().try_push("b")?;
    let last = prefix.clone().try_push("c")?;
    let first_taint = source(&first);
    let large_taint = oversized_source()?;
    let last_taint = source(&last);
    for (path, taint) in [
        (&first, &first_taint),
        (&large, &large_taint),
        (&last, &last_taint),
    ] {
        backend
            .write_set_tainted(path, Value::bytes(vec![8; 128 * 1024]), taint.clone())
            .await?;
    }
    let first_bytes = filtered_header_bytes(backend, first).await?;
    let large_bytes = filtered_header_bytes(backend, large.clone()).await?;
    ensure!(large_bytes > first_bytes + 1 && large_bytes < 128 * 1024);
    let mut query = StateHistoryQuery::new(prefix, 0, 1);
    query.limits.encoded_bytes = bytes_limit(first_bytes)?;
    let page = backend.history(&query).await?;
    ensure!(page.entries.is_empty() && page.encoded_bytes == first_bytes);
    ensure!(
        page.taint == first_taint,
        "exhausted page inspected another header"
    );
    let boundary = page.next.context("exhausted page continuation")?;
    query.cursor = Some(boundary.clone());
    let failure = backend
        .history(&query)
        .await
        .err()
        .context("oversized header accepted")?;
    ensure!(failure.taint.is_pristine());
    let StateError::RowTooLarge(row) = failure.error else {
        anyhow::bail!("expected oversized header diagnosis");
    };
    ensure!(!row.provenance_observed && row.path == large);
    ensure!(row.encoded_bytes == large_bytes && row.retry == Some(boundary.clone()));

    query.cursor = None;
    query.limits.encoded_bytes = bytes_limit(first_bytes + 1)?;
    let partial = backend.history(&query).await?;
    ensure!(partial.entries.is_empty() && partial.encoded_bytes == first_bytes);
    ensure!(partial.taint == first_taint && partial.next == Some(boundary.clone()));
    query.cursor = partial.next;
    let failure = backend
        .history(&query)
        .await
        .err()
        .context("oversized boundary header accepted")?;
    ensure!(failure.taint.is_pristine(), "unioned rejected sources");
    let StateError::RowTooLarge(row) = failure.error else {
        anyhow::bail!("expected oversized boundary header diagnosis");
    };
    ensure!(!row.provenance_observed && row.path == large);
    ensure!(row.encoded_bytes == large_bytes && row.retry == Some(boundary));
    query.cursor = row.retry;
    query.limits.encoded_bytes = bytes_limit(large_bytes)?;
    let retry = backend.history(&query).await?;
    ensure!(retry.entries.is_empty() && retry.encoded_bytes == large_bytes);
    ensure!(retry.taint == large_taint && retry.next.is_some());
    query.cursor = Some(row.resume);
    query.limits.encoded_bytes = bytes_limit(first_bytes + 1)?;
    let resumed = backend.history(&query).await?;
    ensure!(resumed.entries.is_empty() && resumed.next.is_none());
    ensure!(resumed.encoded_bytes > 0 && resumed.encoded_bytes <= first_bytes + 1);
    ensure!(resumed.taint == last_taint);

    let mut matching = StateHistoryQuery::new(large.clone(), 0, i64::MAX);
    matching.limits.encoded_bytes = bytes_limit(first_bytes)?;
    if !precise_ranges {
        let progress = backend.history(&matching).await?;
        ensure!(progress.entries.is_empty() && progress.taint.is_pristine());
        ensure!(progress.encoded_bytes == 0 && progress.next.is_some());
        matching.cursor = progress.next;
    }
    let failure = backend
        .history(&matching)
        .await
        .err()
        .context("matching header accepted")?;
    ensure!(failure.taint.is_pristine());
    let StateError::RowTooLarge(header) = failure.error else {
        anyhow::bail!("expected matching header rejection");
    };
    ensure!(!header.provenance_observed && header.path == large);
    ensure!(header.encoded_bytes == large_bytes);
    matching.limits.encoded_bytes = bytes_limit(header.encoded_bytes)?;
    let failure = backend
        .history(&matching)
        .await
        .err()
        .context("oversized matching payload accepted")?;
    ensure!(failure.taint == large_taint);
    let StateError::RowTooLarge(payload) = failure.error else {
        anyhow::bail!("expected matching payload rejection");
    };
    ensure!(payload.provenance_observed && payload.encoded_bytes > large_bytes);
    matching.limits.encoded_bytes = bytes_limit(payload.encoded_bytes)?;
    let page = backend.history(&matching).await?;
    ensure!(page.entries.len() == 1 && page.entries[0].event.path() == &large);
    ensure!(page.encoded_bytes == payload.encoded_bytes && page.taint == large_taint);
    Ok(())
}

async fn current_header_rejection<T: StateWrite + StateQuery + StateHistory>(
    backend: &T,
    _precise_ranges: bool,
) -> anyhow::Result<()> {
    let prefix = Path::parse("state://current-headers")?;
    let first = prefix.clone().try_push("a")?;
    let large = prefix.clone().try_push("b")?;
    let last = prefix.clone().try_push("c")?;
    let first_taint = source(&first);
    let last_taint = source(&last);
    for (path, taint) in [
        (&first, first_taint.clone()),
        (&large, oversized_source()?),
        (&last, last_taint.clone()),
    ] {
        backend
            .write_set_tainted(path, Value::null(), taint)
            .await?;
    }
    let first_bytes = backend
        .query(&StateScan::new(first.clone()))
        .await?
        .encoded_bytes;
    let mut scan = StateScan::new(prefix);
    scan.limits.encoded_bytes = bytes_limit(first_bytes)?;
    let page = backend.query(&scan).await?;
    ensure!(page.entries.len() == 1 && page.entries[0].0 == first);
    ensure!(page.encoded_bytes == first_bytes && page.taint == first_taint);
    ensure!(page.next.is_some());

    scan.limits.encoded_bytes = bytes_limit(first_bytes + 1)?;
    let partial = backend.query(&scan).await?;
    ensure!(partial.entries == page.entries && partial.encoded_bytes == first_bytes);
    ensure!(partial.taint == first_taint && partial.next == page.next);
    scan.cursor = partial.next;
    let failure = backend
        .query(&scan)
        .await
        .err()
        .context("oversized current header accepted")?;
    ensure!(failure.taint.is_pristine());
    let StateError::RowTooLarge(row) = failure.error else {
        anyhow::bail!("expected oversized current header diagnosis");
    };
    ensure!(row.path == large && !row.provenance_observed);
    ensure!(row.encoded_bytes > first_bytes + 1 && row.retry == page.next);
    let large_bytes = backend
        .query(&StateScan::new(large.clone()))
        .await?
        .encoded_bytes;
    scan.cursor = row.retry;
    scan.limits.encoded_bytes = bytes_limit(large_bytes)?;
    let retried = backend.query(&scan).await?;
    ensure!(retried.entries.len() == 1 && retried.entries[0].0 == large);
    ensure!(retried.encoded_bytes == large_bytes && retried.next.is_some());
    ensure!(retried.taint == oversized_source()?);
    scan.cursor = Some(row.resume);
    scan.limits.encoded_bytes = bytes_limit(first_bytes + 1)?;
    let resumed = backend.query(&scan).await?;
    ensure!(resumed.entries == [(last, TaintedValue::new(Value::null(), last_taint.clone()))]);
    ensure!(resumed.taint == last_taint && resumed.next.is_none());
    ensure!(resumed.encoded_bytes <= first_bytes + 1);
    Ok(())
}

async fn history_header_progress<T: StateWrite + StateQuery + StateHistory>(
    backend: &T,
    precise_ranges: bool,
) -> anyhow::Result<()> {
    let prefix = Path::parse("state://history-header-progress")?;
    let first = prefix.clone().try_push("a")?;
    let large = prefix.clone().try_push("b")?;
    let last = prefix.clone().try_push("c")?;
    let first_taint = source(&first);
    backend
        .write_set_tainted(&first, Value::null(), first_taint.clone())
        .await?;
    backend
        .write_set_tainted(
            &large,
            Value::bytes(vec![8; 16 * 1024]),
            oversized_source()?,
        )
        .await?;
    backend.write_set(&last, Value::null()).await?;
    let mut query = StateHistoryQuery::new(prefix, 0, i64::MAX);
    query.limits.encoded_bytes = bytes_limit(1024)?;
    let partial = backend.history(&query).await?;
    ensure!(partial.entries.len() == 1 && partial.entries[0].event.path() == &first);
    ensure!(partial.taint == first_taint);
    query.cursor = partial.next;
    let failure = backend
        .history(&query)
        .await
        .err()
        .context("accepted oversized header")?;
    let StateError::RowTooLarge(row) = failure.error else {
        anyhow::bail!("expected oversized history header");
    };
    ensure!(row.path == large && !row.provenance_observed);
    ensure!(row.retry == query.cursor && failure.taint.is_pristine());
    query.cursor = Some(row.resume);
    let resumed = backend.history(&query).await?;
    ensure!(resumed.entries.len() == 1 && resumed.entries[0].event.path() == &last);
    ensure!(resumed.next.is_none() && resumed.taint.is_pristine());

    let mut exact = StateHistoryQuery::new(large.clone(), 0, i64::MAX);
    exact.limits = query.limits;
    if !precise_ranges {
        let outside = backend.history(&exact).await?;
        ensure!(outside.entries.is_empty() && outside.taint.is_pristine());
        ensure!(outside.examined == 2 && outside.encoded_bytes == 0);
        exact.cursor = Some(outside.next.context("missing out-of-scope progress")?);
    }
    let failure = backend
        .history(&exact)
        .await
        .err()
        .context("accepted exact oversized header")?;
    let StateError::RowTooLarge(row) = failure.error else {
        anyhow::bail!("expected exact oversized history header");
    };
    ensure!(row.retry == exact.cursor && !row.provenance_observed);
    ensure!(failure.taint.is_pristine());

    let mut payload = StateHistoryQuery::new(large.clone(), 0, i64::MAX);
    payload.limits.encoded_bytes = bytes_limit(filtered_header_bytes(backend, large).await?)?;
    if !precise_ranges {
        let outside = backend.history(&payload).await?;
        ensure!(outside.entries.is_empty() && outside.encoded_bytes == 0);
        ensure!(outside.taint == oversized_source()? && outside.examined == 2);
        payload.cursor = Some(outside.next.context("missing payload boundary progress")?);
    }
    let failure = backend
        .history(&payload)
        .await
        .err()
        .context("accepted oversized payload")?;
    let StateError::RowTooLarge(row) = failure.error else {
        anyhow::bail!("expected oversized history payload");
    };
    ensure!(row.provenance_observed && row.retry == payload.cursor);
    ensure!(failure.taint == oversized_source()?);
    Ok(())
}

macro_rules! shared_paging_test {
    ($memory:ident, $redb:ident, $acceptance:ident) => {
        #[tokio::test]
        async fn $memory() -> anyhow::Result<()> {
            for read_shards in [NonZeroUsize::MIN, NonZeroUsize::MIN.saturating_add(6)] {
                let backend = InMemoryBackend::with_options(InMemoryOptions {
                    read_shards,
                    history: MemoryHistory::Full,
                    ..InMemoryOptions::default()
                })?;
                $acceptance(&backend, false).await?;
            }
            Ok(())
        }

        #[tokio::test]
        async fn $redb() -> anyhow::Result<()> {
            let directory = tempfile::tempdir()?;
            let store = RedbStore::open_with_history(
                directory.path().join("state.redb"),
                RedbHistory::Full,
            )?;
            $acceptance(&store.state_backend(), true).await
        }
    };
}

shared_paging_test!(
    memory_punctuation_scope,
    redb_punctuation_scope,
    punctuation_scope
);
shared_paging_test!(memory_root_scope, redb_root_scope, root_scope);
shared_paging_test!(
    memory_clustered_root_scope,
    redb_clustered_root_scope,
    clustered_root_scope
);
shared_paging_test!(memory_sibling_cursor, redb_sibling_cursor, sibling_cursor);
shared_paging_test!(
    memory_removed_cursor_key,
    redb_removed_cursor_key,
    removed_cursor_key
);
shared_paging_test!(
    memory_filtered_only_pages,
    redb_filtered_only_pages,
    filtered_only_pages
);
shared_paging_test!(
    memory_filtered_header_rejection,
    redb_filtered_header_rejection,
    filtered_header_rejection
);
shared_paging_test!(
    memory_current_header_rejection,
    redb_current_header_rejection,
    current_header_rejection
);
shared_paging_test!(
    memory_history_header_progress,
    redb_history_header_progress,
    history_header_progress
);
