//! Explicit, time-windowed maintenance for `Full` State history.

use crate::config::StateHistoryMaintenanceConfig;
use crate::now_millis;
use std::time::Duration;
use tokio::task::JoinHandle;
use xolotl_sdk::Backend;
use xolotl_state::{StateError, StateHistoryTrimLimits, StateResult};

#[derive(Default)]
struct Search {
    /// A floor that exceeded one transaction budget. Retain it across ticks
    /// so a large backlog cannot restart the same failed search indefinitely.
    failed_at: Option<i64>,
}

#[derive(Debug, Default)]
struct TickReport {
    target: i64,
    floor: i64,
    attempts: usize,
    committed_batches: usize,
    removed_events: u64,
    stalled: bool,
}

pub(super) fn start(state: Backend, settings: StateHistoryMaintenanceConfig) -> JoinHandle<()> {
    tracing::info!(
        retain_for_ms = settings.retain_for_ms.get(),
        interval_ms = settings.interval_ms.get(),
        max_attempts_per_tick = settings.max_attempts_per_tick.get(),
        max_batches_per_tick = settings.max_batches_per_tick.get(),
        events_per_batch = settings.events_per_batch.get(),
        encoded_bytes_per_batch = settings.encoded_bytes_per_batch.get(),
        "State history maintenance started"
    );
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(settings.interval_ms.get()));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut search = Search::default();
        loop {
            interval.tick().await;
            let now = now_millis();
            match maintain_tick_at(&state, settings, &mut search, now).await {
                Ok(report) if report.stalled => tracing::warn!(
                    floor = report.floor,
                    target = report.target,
                    attempts = report.attempts,
                    removed_events = report.removed_events,
                    "State history maintenance cannot advance within one batch budget"
                ),
                Ok(report) if report.committed_batches != 0 => tracing::info!(
                    floor = report.floor,
                    target = report.target,
                    attempts = report.attempts,
                    committed_batches = report.committed_batches,
                    removed_events = report.removed_events,
                    lag_ms = report.target.saturating_sub(report.floor),
                    "State history maintenance advanced"
                ),
                Ok(_) => {}
                Err(error) => {
                    tracing::error!(%error, "State history maintenance failed; retaining the previous floor")
                }
            }
        }
    })
}

async fn maintain_tick_at(
    state: &Backend,
    settings: StateHistoryMaintenanceConfig,
    search: &mut Search,
    now: i64,
) -> StateResult<TickReport> {
    let mut report = TickReport {
        target: now.saturating_sub(settings.retain_for_ms.get() as i64),
        floor: state.retained_from().await?,
        ..TickReport::default()
    };
    if report.target <= 0 || report.target <= report.floor {
        search.failed_at = None;
        return Ok(report);
    }
    search.failed_at = search
        .failed_at
        .filter(|failed| *failed > report.floor && *failed <= report.target);
    let limits = StateHistoryTrimLimits {
        events: settings.events_per_batch,
        encoded_bytes: settings.encoded_bytes_per_batch,
    };
    while report.attempts < settings.max_attempts_per_tick.get()
        && report.committed_batches < settings.max_batches_per_tick.get()
        && report.floor < report.target
    {
        let lower = report.floor.max(0);
        let probe = match search.failed_at {
            Some(failed) if failed <= lower.saturating_add(1) => {
                report.stalled = true;
                break;
            }
            Some(failed) => lower + (failed - lower) / 2,
            None => report.target,
        };
        report.attempts += 1;
        match state.trim_history_before(probe, limits).await {
            Ok(trimmed) => {
                report.floor = trimmed.retained_from_millis;
                report.removed_events =
                    report.removed_events.saturating_add(trimmed.removed_events);
                report.committed_batches += 1;
                // Only a trim that actually removes records can make the
                // formerly failed floor affordable on the next probe.
                if trimmed.removed_events != 0 || report.floor >= report.target {
                    search.failed_at = None;
                }
            }
            Err(failure) if matches!(&failure.error, StateError::HistoryTrimLimit { .. }) => {
                search.failed_at = Some(probe);
            }
            Err(failure) => return Err(failure),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use std::num::{NonZeroU64, NonZeroUsize};
    use xolotl_sdk::{InMemoryBackend, InMemoryOptions, MemoryHistory};
    use xolotl_storage_redb::{RedbHistory, RedbStore};
    use xolotl_types::{Path, Value};

    fn settings(events: usize, bytes: usize) -> StateHistoryMaintenanceConfig {
        StateHistoryMaintenanceConfig {
            retain_for_ms: NonZeroU64::MIN,
            interval_ms: NonZeroU64::MIN.saturating_add(9),
            max_attempts_per_tick: NonZeroUsize::MIN.saturating_add(15),
            max_batches_per_tick: NonZeroUsize::MIN.saturating_add(3),
            events_per_batch: NonZeroUsize::MIN.saturating_add(events - 1),
            encoded_bytes_per_batch: NonZeroUsize::MIN.saturating_add(bytes - 1),
        }
    }

    async fn check_bounded_progress(state: Backend) -> anyhow::Result<()> {
        ensure!(state.has_history_retention());
        let path = Path::parse("state://tests/history-maintenance")?;
        for value in 0..5 {
            state.write_set(&path, Value::integer(value)).await?;
        }
        let target = now_millis() + 60_000;
        let mut search = Search::default();
        let mut removed = 0;
        let mut floor = i64::MIN;
        for _ in 0..100 {
            let report = maintain_tick_at(
                &state,
                settings(1, 16 * 1024 * 1024),
                &mut search,
                target + 1,
            )
            .await?;
            ensure!(report.attempts <= 16 && report.committed_batches <= 4);
            ensure!(report.floor >= floor);
            floor = report.floor;
            removed += report.removed_events;
            if floor == target {
                break;
            }
        }
        ensure!(
            floor == target,
            "maintenance failed to catch up: floor={floor}"
        );
        ensure!(removed == 5, "removed {removed} events instead of five");
        ensure!(state.read(&path).await? == Some(Value::integer(4)));
        let earlier = match state.read_at(&path, target - 1).await {
            Ok(_) => anyhow::bail!("history before the floor remained readable"),
            Err(error) => error,
        };
        ensure!(matches!(earlier.error, StateError::HistoryTrimmed { .. }));
        ensure!(
            state
                .read_at(&path, target)
                .await?
                .value
                .context("current value missing from retained baseline")?
                == Value::integer(4)
        );
        Ok(())
    }

    #[tokio::test]
    async fn memory_history_maintenance_advances_in_bounded_batches() -> anyhow::Result<()> {
        let memory = InMemoryBackend::with_options(InMemoryOptions {
            history: MemoryHistory::Full,
            ..InMemoryOptions::default()
        })?;
        check_bounded_progress(memory.into_backend()).await
    }

    #[tokio::test]
    async fn redb_history_maintenance_advances_in_bounded_batches() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store =
            RedbStore::open_with_history(dir.path().join("history.redb"), RedbHistory::Full)?;
        check_bounded_progress(store.state_backend().into_backend()).await
    }

    #[tokio::test]
    async fn untrimable_event_preserves_history_and_reports_stall() -> anyhow::Result<()> {
        let memory = InMemoryBackend::with_options(InMemoryOptions {
            history: MemoryHistory::Full,
            ..InMemoryOptions::default()
        })?;
        let state = memory.into_backend();
        let path = Path::parse("state://tests/too-large-for-trim")?;
        state
            .write_set(&path, Value::string("large value".into()))
            .await?;
        let target = now_millis() + 60_000;
        let mut search = Search::default();
        let mut stalled = false;
        for _ in 0..100 {
            let report = maintain_tick_at(&state, settings(1, 1), &mut search, target + 1).await?;
            ensure!(report.removed_events == 0 && report.floor < target);
            if report.stalled {
                stalled = true;
                break;
            }
        }
        ensure!(stalled, "untrimable event did not report its stall");
        ensure!(state.read(&path).await? == Some(Value::string("large value".into())));
        Ok(())
    }

    #[tokio::test]
    async fn background_worker_advances_explicit_full_history() -> anyhow::Result<()> {
        let memory = InMemoryBackend::with_options(InMemoryOptions {
            history: MemoryHistory::Full,
            ..InMemoryOptions::default()
        })?;
        let state = memory.into_backend();
        let path = Path::parse("state://tests/background-history-maintenance")?;
        state.write_set(&path, Value::integer(7)).await?;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let task = start(state.clone(), settings(1, 16 * 1024 * 1024));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if state.retained_from().await? > 0 {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        ensure!(state.read(&path).await? == Some(Value::integer(7)));
        task.abort();
        ensure!(task.await.is_err_and(|error| error.is_cancelled()));
        Ok(())
    }
}
