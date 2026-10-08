use anyhow::{Context, Result, ensure};
use std::num::NonZeroUsize;
use xolotl_state::{
    Backend, StateCursor, StateError, StateHistoryEntry, StateHistoryQuery, StateHistoryTrimLimits,
    StateScan, StateWatchError, TaintedValue,
};
use xolotl_storage_redb::{RedbHistory, RedbStore};
use xolotl_types::{Path, TaintSet, TaintSource, Value};

async fn history(state: &Backend, path: &Path) -> Result<Option<Vec<StateHistoryEntry>>> {
    if !state.has_history() {
        return Ok(None);
    }
    let page = state
        .history(&StateHistoryQuery::new(path.clone(), 0, i64::MAX))
        .await?;
    ensure!(page.next.is_none(), "fixture history exceeded one page");
    Ok(Some(page.entries))
}

async fn create_absence(state: &Backend, path: &Path, conditional: bool) -> Result<TaintSet> {
    let original = TaintSet::of(TaintSource::Protected { path: path.clone() });
    let incoming = TaintSet::of(TaintSource::ModelOutput);
    state
        .write_set_tainted(path, Value::null(), original.clone())
        .await?;
    let commit = if conditional {
        state
            .write_compare_delete_tainted(path, Some(Value::null()), incoming.clone())
            .await?
    } else {
        state.write_delete_tainted(path, incoming.clone()).await?
    };
    ensure!(commit.taint == incoming.clone().merged(&original));
    Ok(original.merged(&incoming))
}

async fn assert_absence(state: &Backend, path: &Path, expected: &TaintSet) -> Result<()> {
    let current = state.read_tainted(path).await?;
    ensure!(current.value.is_none() && &current.taint == expected);
    ensure!(state.read_tainted_bounded(path, NonZeroUsize::MAX).await? == current);
    let page = state.query(&StateScan::new(path.clone())).await?;
    ensure!(page.entries.is_empty() && page.next.is_none());
    ensure!(page.examined == 1 && page.encoded_bytes > path.to_string().len());
    ensure!(&page.taint == expected);
    ensure!(&state.write_compare_delete(path, None).await?.taint == expected);
    Ok(())
}

#[tokio::test]
async fn current_absence_survives_reopen_without_history_dependencies() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for mode in [RedbHistory::Full, RedbHistory::CurrentOnly] {
        let path = Path::parse("state://current-absence/reopen")?;
        for conditional in [false, true] {
            let file = directory
                .path()
                .join(format!("absence-{mode:?}-{conditional}.redb"));
            let expected;
            {
                let state = RedbStore::open_with_history(&file, mode)?
                    .state_backend()
                    .into_backend();
                expected = create_absence(&state, &path, conditional).await?;
                assert_absence(&state, &path, &expected).await?;
                if state.has_history() {
                    let entries = history(&state, &path)
                        .await?
                        .context("Full history missing")?;
                    let floor = entries
                        .iter()
                        .map(|entry| entry.at_millis)
                        .max()
                        .context("delete history missing")?
                        .checked_add(1)
                        .context("history clock exhausted")?;
                    ensure!(
                        state
                            .trim_history_before(floor, StateHistoryTrimLimits::default())
                            .await?
                            .removed_events
                            == u64::try_from(entries.len())?
                    );
                    let retained = state
                        .history(&StateHistoryQuery::new(path.clone(), floor, i64::MAX))
                        .await?;
                    ensure!(retained.entries.is_empty());
                }
            }
            let state = RedbStore::open_with_history(&file, mode)?
                .state_backend()
                .into_backend();
            assert_absence(&state, &path, &expected).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn reopened_absence_noops_only_taint_commits_and_set_replaces_sources() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for mode in [RedbHistory::Full, RedbHistory::CurrentOnly] {
        let file = directory.path().join(format!("noops-{mode:?}.redb"));
        let path = Path::parse("state://current-absence/noop")?;
        let expected;
        {
            let state = RedbStore::open_with_history(&file, mode)?
                .state_backend()
                .into_backend();
            expected = create_absence(&state, &path, false).await?;
        }
        {
            let state = RedbStore::open_with_history(&file, mode)?
                .state_backend()
                .into_backend();
            let before = history(&state, &path).await?;
            let page_before = state.query(&StateScan::new(path.clone())).await?;
            let mut events = state.subscribe(&path).await?;
            let input = TaintSet::author();
            for conditional in [false, true] {
                let commit = if conditional {
                    state
                        .write_compare_delete_tainted(&path, None, input.clone())
                        .await?
                } else {
                    state.write_delete_tainted(&path, input.clone()).await?
                };
                ensure!(commit.taint == input.clone().merged(&expected));
                assert_absence(&state, &path, &expected).await?;
                let page = state.query(&StateScan::new(path.clone())).await?;
                ensure!(page.encoded_bytes == page_before.encoded_bytes);
                ensure!(history(&state, &path).await? == before);
                ensure!(matches!(events.try_recv(), Err(StateWatchError::Empty)));
            }
        }
        {
            let state = RedbStore::open_with_history(&file, mode)?
                .state_backend()
                .into_backend();
            assert_absence(&state, &path, &expected).await?;
            let replacement = TaintSet::author();
            let commit = state
                .write_set_tainted(&path, Value::integer(7), replacement.clone())
                .await?;
            ensure!(commit.taint == replacement.clone().merged(&expected));
            ensure!(
                state.read_tainted(&path).await?
                    == xolotl_state::StateObservation::from(TaintedValue::new(
                        Value::integer(7),
                        replacement.clone()
                    ))
            );
            let page = state.query(&StateScan::new(path.clone())).await?;
            ensure!(page.entries.len() == 1 && page.taint == replacement);
        }
        let state = RedbStore::open_with_history(&file, mode)?
            .state_backend()
            .into_backend();
        ensure!(
            state.read_tainted(&path).await?
                == xolotl_state::StateObservation::from(TaintedValue::new(
                    Value::integer(7),
                    TaintSet::author()
                ))
        );
    }
    Ok(())
}

#[tokio::test]
async fn reopened_absence_charges_raw_bounds_and_empty_page_continuations() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for mode in [RedbHistory::Full, RedbHistory::CurrentOnly] {
        let file = directory.path().join(format!("pages-{mode:?}.redb"));
        let prefix = Path::parse("state://absence-page")?;
        let paths = [
            Path::parse("state://absence-page/a")?,
            Path::parse("state://absence-page/b")?,
        ];
        let mut sources = Vec::new();
        {
            let state = RedbStore::open_with_history(&file, mode)?
                .state_backend()
                .into_backend();
            for path in &paths {
                sources.push(create_absence(&state, path, false).await?);
            }
        }
        let state = RedbStore::open_with_history(&file, mode)?
            .state_backend()
            .into_backend();
        let mut sizes = Vec::new();
        for path in &paths {
            sizes.push(
                state
                    .query(&StateScan::new(path.clone()))
                    .await?
                    .encoded_bytes,
            );
        }
        ensure!(sizes[0] == sizes[1] && sizes[0] > paths[0].to_string().len());
        let mut query = StateScan::new(prefix);
        query.limits.encoded_bytes = NonZeroUsize::new(sizes[0]).context("absence record size")?;
        let page = state.query(&query).await?;
        ensure!(page.entries.is_empty() && page.examined == 1);
        ensure!(page.encoded_bytes == sizes[0]);
        ensure!(page.taint == sources[0]);
        ensure!(page.next == Some(StateCursor(paths[0].to_string().into_bytes())));
        query.cursor = page.next;
        query.limits.encoded_bytes = NonZeroUsize::MIN;
        let failure = state
            .query(&query)
            .await
            .err()
            .context("raw row bound ignored")?;
        let StateError::RowTooLarge(row) = failure.error else {
            anyhow::bail!("absence page returned the wrong rejection")
        };
        ensure!(row.path == paths[1] && row.encoded_bytes == sizes[1]);
        ensure!(!row.provenance_observed && failure.taint.is_pristine());
        ensure!(row.retry == query.cursor);
        ensure!(row.resume == StateCursor(paths[1].to_string().into_bytes()));
        query.limits.encoded_bytes = NonZeroUsize::new(sizes[1]).context("absence record size")?;
        let terminal = state.query(&query).await?;
        ensure!(terminal.entries.is_empty() && terminal.next.is_some());
        ensure!(terminal.examined == 1 && terminal.encoded_bytes == sizes[1]);
        ensure!(terminal.taint == sources[1]);
        query.cursor = terminal.next;
        let terminal = state.query(&query).await?;
        ensure!(terminal.entries.is_empty() && terminal.next.is_none());
        ensure!(terminal.examined == 0 && terminal.encoded_bytes == 0);
        ensure!(terminal.taint.is_pristine());
        query.cursor = None;
        query.limits.examined = NonZeroUsize::MIN;
        let bounded = state.query(&query).await?;
        ensure!(bounded.entries.is_empty() && bounded.examined == 1);
        ensure!(bounded.encoded_bytes == sizes[0] && bounded.taint == sources[0]);
        ensure!(bounded.next == Some(StateCursor(paths[0].to_string().into_bytes())));
        assert_raw_point_bounds(&state, &paths[0], sizes[0], &sources[0]).await?;
    }
    Ok(())
}

async fn assert_raw_point_bounds(
    state: &Backend,
    path: &Path,
    encoded_bytes: usize,
    expected: &TaintSet,
) -> Result<()> {
    let before = history(state, path).await?;
    let mut events = state.subscribe(path).await?;
    let input = TaintSet::author();
    let failure = state
        .read_tainted_bounded(path, NonZeroUsize::MIN)
        .await
        .err()
        .context("raw point bound ignored")?;
    ensure!(failure.taint.is_pristine());
    ensure!(matches!(failure.error, StateError::PointTooLarge(row)
        if row.path == *path && row.encoded_bytes == encoded_bytes
            && row.limit_encoded_bytes == NonZeroUsize::MIN && !row.provenance_observed));
    let failure = state
        .write_compare_delete_tainted_bounded(path, None, input.clone(), NonZeroUsize::MIN)
        .await
        .err()
        .context("raw comparison bound ignored")?;
    ensure!(failure.taint == input);
    ensure!(matches!(failure.error, StateError::PointTooLarge(row)
        if row.path == *path && row.encoded_bytes == encoded_bytes
            && row.limit_encoded_bytes == NonZeroUsize::MIN && !row.provenance_observed));
    let exact = NonZeroUsize::new(encoded_bytes).context("absence record size")?;
    let bounded = state.read_tainted_bounded(path, exact).await?;
    ensure!(bounded.value.is_none() && &bounded.taint == expected);
    ensure!(
        state
            .write_compare_delete_tainted_bounded(path, None, input.clone(), exact)
            .await?
            .taint
            == input.merged(expected)
    );
    assert_absence(state, path, expected).await?;
    ensure!(history(state, path).await? == before);
    ensure!(matches!(events.try_recv(), Err(StateWatchError::Empty)));
    Ok(())
}
