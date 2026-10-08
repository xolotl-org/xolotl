//! Bounded, restartable scans for object authorization records.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use xolotl_kernel::Bootstrap;
use xolotl_kernel::host::{AbortTask, HostDeadline, HostRuntime};
use xolotl_state::{Backend, StateCursor, StateError, StateScan};
use xolotl_types::{Path, TaintedValue};

use crate::{GatewayError, maintenance_health::MaintenanceTracker};

type StartedObjectMaintenance = (Arc<dyn AbortTask>, MaintenanceTracker);

pub(super) const BATCH_ENTRIES: usize = 16;
pub(super) const PAGE_BYTES: usize = 256 * 1024;
const BATCH_LIMIT: NonZeroUsize = NonZeroUsize::MIN.saturating_add(BATCH_ENTRIES - 1);
pub(super) const PAGE_BUDGET: NonZeroUsize = NonZeroUsize::MIN.saturating_add(PAGE_BYTES - 1);
const MAX_CURSOR_BYTES: usize = 512;
const OBJECT_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);
const OBJECT_MAINTENANCE_WARNING_INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Default)]
pub(super) struct MaintenancePage {
    pub(super) entries: Vec<(Path, TaintedValue)>,
    pub(super) examined: usize,
    pub(super) skipped_oversized: usize,
    pub(super) next: Option<StateCursor>,
}

pub(super) async fn scan_batch(
    state: &Backend,
    prefix: Path,
    cursor: Option<StateCursor>,
    label: &'static str,
) -> Result<MaintenancePage, GatewayError> {
    let mut scan = StateScan::new(prefix);
    scan.cursor = cursor;
    scan.limits.entries = BATCH_LIMIT;
    scan.limits.examined = BATCH_LIMIT;
    scan.limits.encoded_bytes = PAGE_BUDGET;
    let page = match state.query(&scan).await {
        Ok(page) => page,
        Err(xolotl_state::StateFailure {
            error: StateError::RowTooLarge(row),
            ..
        }) => {
            validate_cursor(&scan, &row.resume, label)?;
            if row.retry != scan.cursor {
                return Err(GatewayError::Rejected(format!(
                    "{label} oversized-row retry is invalid"
                )));
            }
            return Ok(MaintenancePage {
                examined: 1,
                skipped_oversized: 1,
                next: Some(row.resume),
                ..MaintenancePage::default()
            });
        }
        Err(error) => {
            return Err(GatewayError::Rejected(format!(
                "{label} query failed: {error}"
            )));
        }
    };
    if page.examined > BATCH_ENTRIES
        || page.entries.len() > BATCH_ENTRIES
        || page.encoded_bytes > PAGE_BYTES
    {
        return Err(GatewayError::Rejected(format!(
            "{label} backend exceeded page budget"
        )));
    }
    if let Some(next) = page.next.as_ref() {
        validate_cursor(&scan, next, label)?;
    }
    let mut entries = page.entries;
    for (_, envelope) in &mut entries {
        envelope.taint.union(&page.taint);
    }
    Ok(MaintenancePage {
        entries,
        examined: page.examined,
        next: page.next,
        ..MaintenancePage::default()
    })
}

fn validate_cursor(
    scan: &StateScan,
    cursor: &StateCursor,
    label: &'static str,
) -> Result<(), GatewayError> {
    if cursor.0.is_empty()
        || cursor.0.len() > MAX_CURSOR_BYTES
        || scan.cursor.as_ref() == Some(cursor)
    {
        return Err(GatewayError::Rejected(format!("{label} cursor is invalid")));
    }
    Ok(())
}

/// The weak runtime marker makes the idle worker stop after its Gateway drops.
/// Each tick performs one bounded batch and retains its cursor across ticks.
pub(crate) fn spawn_object_maintenance(
    boot: &Arc<Bootstrap>,
    runtime_marker: &Arc<crate::GatewayRequestRegistry>,
) -> Result<Option<StartedObjectMaintenance>, GatewayError> {
    if !boot.kernel().state().has_query() || !boot.kernel().state().has_bounded_write() {
        return Ok(None);
    }
    let runtime = boot.kernel().host_runtime().clone();
    let started = runtime.now();
    let first_tick = started
        .checked_add(OBJECT_MAINTENANCE_INTERVAL)
        .ok_or_else(|| {
            GatewayError::Rejected("gateway object maintenance deadline is out of range".into())
        })?;
    let boot = Arc::downgrade(boot);
    let runtime_marker = Arc::downgrade(runtime_marker);
    let (tracker, exit) = MaintenanceTracker::owned(started);
    let task_tracker = tracker.clone();
    let handle = runtime
        .clone()
        .spawn(Box::pin(async move {
            let _exit = exit;
            let mut cursor = None;
            let mut grant_cursor = None;
            let mut last_ticket_warning = None;
            let mut last_grant_warning = None;
            let mut next_tick = first_tick;
            loop {
                if let Err(error) = runtime.sleep_until(next_tick).await {
                    tracing::error!(%error, "Gateway object maintenance clock domain changed");
                    break;
                }
                let (Some(boot), Some(_runtime_marker)) =
                    (boot.upgrade(), runtime_marker.upgrade())
                else {
                    break;
                };
                let pass = task_tracker.begin(runtime.now());
                let mut pass_succeeded = true;
                match super::ticket::maintain_upload_tickets_step(
                    boot.kernel().state(),
                    &mut cursor,
                    runtime.now_millis(),
                )
                .await
                {
                    Ok(batch) => {
                        if batch.removed != 0 {
                            tracing::info!(
                                examined = batch.examined,
                                removed = batch.removed,
                                "Gateway upload ticket maintenance advanced"
                            );
                        }
                        if batch.skipped_oversized != 0
                            && maintenance_warning_due(&runtime, &mut last_ticket_warning)
                        {
                            tracing::warn!(
                                skipped_oversized = batch.skipped_oversized,
                                "Gateway upload ticket maintenance skipped oversized record"
                            );
                        }
                    }
                    Err(error) => {
                        pass_succeeded = false;
                        if maintenance_warning_due(&runtime, &mut last_ticket_warning) {
                            tracing::warn!(%error, "Gateway upload ticket maintenance failed");
                        }
                    }
                }
                match super::read_grant::maintain_read_grants_step(
                    boot.kernel().state(),
                    &mut grant_cursor,
                    runtime.now_millis(),
                )
                .await
                {
                    Ok(batch) => {
                        if batch.removed != 0 {
                            tracing::info!(
                                examined = batch.examined,
                                removed = batch.removed,
                                "Gateway object read grant maintenance advanced"
                            );
                        }
                        if batch.skipped_oversized != 0
                            && maintenance_warning_due(&runtime, &mut last_grant_warning)
                        {
                            tracing::warn!(
                                skipped_oversized = batch.skipped_oversized,
                                "Gateway object read grant maintenance skipped oversized record"
                            );
                        }
                    }
                    Err(error) => {
                        pass_succeeded = false;
                        if maintenance_warning_due(&runtime, &mut last_grant_warning) {
                            tracing::warn!(%error, "Gateway object read grant maintenance failed");
                        }
                    }
                }
                pass.complete(runtime.now(), pass_succeeded);
                let Some(deadline) = runtime.deadline_after(OBJECT_MAINTENANCE_INTERVAL) else {
                    tracing::error!("Gateway object maintenance deadline is out of range");
                    break;
                };
                next_tick = deadline;
            }
        }))
        .map_err(|error| {
            GatewayError::Rejected(format!(
                "gateway object maintenance requires host task scheduler: {error}"
            ))
        })?;
    Ok(Some((handle, tracker)))
}

fn maintenance_warning_due(runtime: &HostRuntime, last_warning: &mut Option<HostDeadline>) -> bool {
    let now = runtime.now();
    if last_warning.as_ref().is_some_and(|last| {
        now.saturating_duration_since(*last)
            .is_ok_and(|duration| duration < OBJECT_MAINTENANCE_WARNING_INTERVAL)
    }) {
        return false;
    }
    *last_warning = Some(now);
    true
}
