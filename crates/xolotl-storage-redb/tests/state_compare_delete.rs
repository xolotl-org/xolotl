use anyhow::{Context, Result, ensure};
use std::collections::BTreeMap;
use std::future::{Future, pending, poll_fn};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use xolotl_state::{
    Backend, InMemoryBackend, InMemoryOptions, MemoryHistory, StateError, StateEvent,
    StateHistoryEntry, StateHistoryQuery, StateMutation, StateResult, StateScan, StateWatchError,
    StateWrite, TaintedValue,
};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{Path, TaintSet, TaintSource, Value};

fn backends() -> Result<(tempfile::TempDir, Vec<Backend>)> {
    let directory = tempfile::tempdir()?;
    let mut backends = Vec::new();
    for history in [MemoryHistory::Full, MemoryHistory::Disabled] {
        for read_shards in [NonZeroUsize::MIN, NonZeroUsize::MIN.saturating_add(6)] {
            backends.push(
                InMemoryBackend::with_options(InMemoryOptions {
                    history,
                    read_shards,
                    ..InMemoryOptions::default()
                })?
                .into_backend(),
            );
        }
    }
    backends.push(
        RedbStore::open(directory.path().join("compare-delete.redb"))?
            .state_backend()
            .into_backend(),
    );
    Ok((directory, backends))
}

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

#[tokio::test]
async fn compare_delete_distinguishes_absence_and_null_without_partial_changes() -> Result<()> {
    let (_directory, backends) = backends()?;
    for state in backends {
        let path = Path::parse("state://compare-delete/null")?;
        let mut events = state.subscribe(&path).await?;
        let before = history(&state, &path).await?;
        state.write_compare_delete(&path, None).await?;
        ensure!(matches!(
            state.write_compare_delete(&path, Some(Value::null())).await,
            Err(xolotl_state::StateFailure { error: StateError::CasFailed { expected, actual, .. }, .. })
                if expected.as_deref() == Some(&Value::null()) && actual.is_none()
        ));
        ensure!(state.read_tainted(&path).await?.is_none());
        ensure!(history(&state, &path).await? == before);
        ensure!(matches!(events.try_recv(), Err(StateWatchError::Empty)));

        let taint = TaintSet::of(TaintSource::Protected { path: path.clone() });
        let stored = TaintedValue::new(Value::null(), taint.clone());
        state
            .write_set_tainted(&path, stored.value.clone(), taint.clone())
            .await?;
        ensure!(
            events.try_recv()?
                == StateEvent::Set {
                    path: path.clone(),
                    value: Value::null(),
                    taint,
                }
        );
        let before = history(&state, &path).await?;
        for expected in [None, Some(Value::integer(0))] {
            ensure!(matches!(
                state.write_compare_delete(&path, expected.clone()).await,
                Err(xolotl_state::StateFailure { error: StateError::CasFailed { expected: observed, actual, .. }, .. })
                    if observed.as_deref() == expected.as_ref()
                        && actual.as_deref() == Some(&Value::null())
            ));
            ensure!(state.read_tainted(&path).await? == Some(stored.clone()));
            ensure!(history(&state, &path).await? == before);
            ensure!(matches!(events.try_recv(), Err(StateWatchError::Empty)));
        }

        state
            .write_compare_delete(&path, Some(Value::null()))
            .await?;
        let deleted = StateEvent::Delete {
            path: path.clone(),
            taint: stored.taint.clone(),
        };
        ensure!(events.try_recv()? == deleted);
        ensure!(matches!(events.try_recv(), Err(StateWatchError::Empty)));
        ensure!(state.read_tainted(&path).await?.is_none());
        ensure!(
            state
                .query(&StateScan::new(path.clone()))
                .await?
                .entries
                .is_empty()
        );
        let after = history(&state, &path).await?;
        if let Some(after) = &after {
            let before = before.context("history capability changed")?;
            ensure!(after.len() == before.len() + 1);
            ensure!(after[..before.len()] == before);
            let last = after.last().context("missing delete history")?;
            ensure!(last.event == deleted);
            ensure!(state.read_at(&path, last.at_millis).await?.is_none());
        }
        state.write_compare_delete(&path, None).await?;
        ensure!(history(&state, &path).await? == after);
        ensure!(matches!(events.try_recv(), Err(StateWatchError::Empty)));
    }
    Ok(())
}

#[tokio::test]
async fn compare_delete_keeps_value_types_distinct() -> Result<()> {
    let (_directory, backends) = backends()?;
    for state in backends {
        let path = Path::parse("state://compare-delete/types")?;
        let bytes = Value::bytes(vec![1, 2]);
        let list = Value::list(vec![Value::integer(1), Value::integer(2)]);
        state.write_set(&path, bytes.clone()).await?;
        let before = history(&state, &path).await?;
        let mut events = state.subscribe(&path).await?;
        ensure!(matches!(
            state.write_compare_delete(&path, Some(list)).await,
            Err(xolotl_state::StateFailure {
                error: StateError::CasFailed { .. },
                ..
            })
        ));
        ensure!(state.read(&path).await? == Some(bytes.clone()));
        ensure!(history(&state, &path).await? == before);
        ensure!(matches!(events.try_recv(), Err(StateWatchError::Empty)));
        state.write_compare_delete(&path, Some(bytes)).await?;
        ensure!(state.read(&path).await?.is_none());
    }
    Ok(())
}

// A remote commit can remain outstanding after its client drops the write future.
#[derive(Default)]
struct DeferredWrite {
    pending: Mutex<Option<(Path, StateMutation)>>,
}

impl StateWrite for DeferredWrite {
    type Write<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            {
                let mut slot = self
                    .pending
                    .lock()
                    .map_err(|error| StateError::Backend(error.to_string()))?;
                if slot.is_some() {
                    return Err(
                        StateError::Backend("fixture already has a pending write".into()).into(),
                    );
                }
                *slot = Some((path.clone(), mutation));
            }
            pending().await
        })
    }
}

fn owner(id: &str) -> Value {
    Value::map(BTreeMap::from([
        ("reservation_id".into(), Value::string(id.into())),
        ("created_at_ms".into(), Value::integer(42)),
    ]))
}

#[tokio::test]
async fn deletion_sources_survive_subscriptions_and_later_history_pages() -> Result<()> {
    let (_directory, backends) = backends()?;
    for state in backends {
        for conditional in [false, true] {
            let path = Path::parse(if conditional {
                "state://deletion-events/conditional"
            } else {
                "state://deletion-events/unconditional"
            })?;
            let taint = TaintSet::of(TaintSource::Protected { path: path.clone() });
            state
                .write_set_tainted(&path, Value::null(), taint.clone())
                .await?;
            let mut history_query = StateHistoryQuery::new(path.clone(), 0, i64::MAX);
            if state.has_history() {
                history_query.limits.entries = NonZeroUsize::MIN;
                let page = state.history(&history_query).await?;
                ensure!(page.entries.len() == 1 && page.next.is_some());
                history_query.cursor = page.next;
            }
            let mut events = state.subscribe(&path).await?;
            let commit = if conditional {
                state
                    .write_compare_delete(&path, Some(Value::null()))
                    .await?
            } else {
                state.write_delete(&path).await?
            };
            let deleted = StateEvent::Delete {
                path: path.clone(),
                taint: taint.clone(),
            };
            ensure!(commit.taint == taint && events.try_recv()? == deleted);
            if state.has_history() {
                let page = state.history(&history_query).await?;
                ensure!(page.entries.len() == 1 && page.entries[0].event == deleted);
                ensure!(page.taint == taint);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn successful_comparisons_report_and_store_current_provenance_atomically() -> Result<()> {
    let (_directory, backends) = backends()?;
    for state in backends {
        let path = Path::parse("state://compare-delete/labels")?;
        state.write_set(&path, Value::null()).await?;
        let stale = state.read(&path).await?;
        let current_taint = TaintSet::of(TaintSource::Protected { path: path.clone() });
        // A competing write changes labels while keeping the compared Value.
        state
            .write_set_tainted(&path, Value::null(), current_taint.clone())
            .await?;
        let incoming = TaintSet::of(TaintSource::ModelOutput);
        let expected = incoming.clone().merged(&current_taint);
        let commit = state
            .write_cas_tainted(&path, stale, Value::integer(3), incoming)
            .await?;
        ensure!(commit.taint == expected);
        ensure!(
            state.read_tainted(&path).await?
                == Some(TaintedValue::new(Value::integer(3), expected.clone()))
        );
        if let Some(entries) = history(&state, &path).await? {
            let entry = entries.last().context("missing comparison history")?;
            ensure!(entry.event.taint() == &expected);
        }
        let commit = state
            .write_compare_delete(&path, Some(Value::integer(3)))
            .await?;
        ensure!(commit.taint == expected && state.read_tainted(&path).await?.is_none());
        ensure!(
            state
                .write_compare_delete(&path, None)
                .await?
                .taint
                .is_pristine()
        );

        state
            .write_set_tainted(&path, Value::null(), expected)
            .await?;
        state.write_set(&path, Value::null()).await?;
        ensure!(
            state
                .read_tainted(&path)
                .await?
                .context("replacement missing")?
                .taint
                .is_pristine()
        );
    }
    Ok(())
}

#[tokio::test]
async fn append_events_keep_current_sources_for_new_subscribers_and_history_pages() -> Result<()> {
    let (_directory, backends) = backends()?;
    for state in backends {
        let path = Path::parse("state://append-events/observed")?;
        let current = TaintSet::of(TaintSource::Protected { path: path.clone() });
        let incoming = TaintSet::of(TaintSource::ModelOutput);
        let expected_event = incoming.clone().merged(&current);
        state
            .write_set_tainted(&path, Value::list(Vec::new()), current.clone())
            .await?;
        let mut query = StateHistoryQuery::new(path.clone(), 0, i64::MAX);
        if state.has_history() {
            query.limits.entries = NonZeroUsize::MIN;
            let page = state.history(&query).await?;
            ensure!(page.entries.len() == 1 && page.next.is_some());
            query.cursor = page.next;
        }
        let mut events = state.subscribe(&path).await?;
        let commit = state
            .write_append_tainted(&path, Value::integer(2), incoming.clone())
            .await?;
        let appended = StateEvent::Append {
            path: path.clone(),
            item: Value::integer(2),
            taint: expected_event.clone(),
        };
        ensure!(commit.taint == expected_event && events.try_recv()? == appended);
        ensure!(
            state.read_tainted(&path).await?
                == Some(TaintedValue::new(
                    Value::list(vec![Value::integer(2)]),
                    current.merged(&incoming),
                ))
        );
        if state.has_history() {
            let page = state.history(&query).await?;
            ensure!(page.entries.len() == 1 && page.entries[0].event == appended);
            ensure!(page.taint == expected_event);
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_old_delete_cannot_remove_a_new_owner() -> Result<()> {
    let (_directory, backends) = backends()?;
    for state in backends {
        let path = Path::parse("state://compare-delete/owner")?;
        let previous = owner("previous");
        let current = owner("current");
        state.write_cas(&path, None, previous.clone()).await?;
        let delayed = Arc::new(DeferredWrite::default());
        let writer = Backend::new().with_write(delayed.clone());
        ensure!(!writer.has_read());
        let mut deleting = Box::pin(writer.write_compare_delete(&path, Some(previous.clone())));
        ensure!(
            poll_fn(|cx| Poll::Ready(deleting.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(deleting);
        ensure!(state.read(&path).await? == Some(previous.clone()));

        state
            .write_compare_delete(&path, Some(previous.clone()))
            .await?;
        let taint = TaintSet::of(TaintSource::ModelOutput);
        state
            .write_cas_tainted(&path, None, current.clone(), taint.clone())
            .await?;
        let before = history(&state, &path).await?;
        let mut events = state.subscribe(&path).await?;
        let (path, mutation) = delayed
            .pending
            .lock()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            .take()
            .context("missing delayed write")?;
        ensure!(matches!(
            state.mutate(&path, mutation).await,
            Err(xolotl_state::StateFailure { error: StateError::CasFailed { expected, actual, .. }, .. })
                if expected.as_deref() == Some(&previous) && actual.as_deref() == Some(&current)
        ));
        ensure!(state.read_tainted(&path).await? == Some(TaintedValue::new(current, taint)));
        ensure!(history(&state, &path).await? == before);
        ensure!(matches!(events.try_recv(), Err(StateWatchError::Empty)));
    }
    Ok(())
}

#[tokio::test]
async fn redb_compare_delete_remains_deleted_after_reopen() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("reopen.redb");
    let path = Path::parse("state://compare-delete/reopen")?;
    let expected_history;
    {
        let state = RedbStore::open(&file)?.state_backend().into_backend();
        state.write_set(&path, Value::null()).await?;
        state
            .write_compare_delete(&path, Some(Value::null()))
            .await?;
        expected_history = history(&state, &path).await?;
    }
    let state = RedbStore::open(&file)?.state_backend().into_backend();
    ensure!(state.read(&path).await?.is_none());
    ensure!(history(&state, &path).await? == expected_history);
    Ok(())
}
