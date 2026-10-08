//! Expired read authority cleanup. An invalid record is never guessed expired.

use xolotl_state::{Backend, StateCursor, StateError};
use xolotl_types::{Path, TaintedValue};

use super::{read_grant_path, record};
use crate::GatewayError;

#[derive(Default)]
pub(crate) struct ReadGrantMaintenance {
    pub(crate) examined: usize,
    pub(crate) removed: usize,
    pub(crate) skipped_oversized: usize,
    pub(crate) next: Option<StateCursor>,
}

pub(super) async fn maintain_read_grants_step(
    state: &Backend,
    cursor: &mut Option<StateCursor>,
    now_ms: i64,
) -> Result<ReadGrantMaintenance, GatewayError> {
    // A failed or uncertain delete restarts at the front. Previously completed
    // compare-deletes are idempotent, and no cursor advances past a failure.
    let result = maintain_read_grants_batch(state, cursor.take(), now_ms).await;
    if let Ok(batch) = &result {
        *cursor = batch.next.clone();
    }
    result
}

pub(super) async fn maintain_read_grants_batch(
    state: &Backend,
    cursor: Option<StateCursor>,
    now_ms: i64,
) -> Result<ReadGrantMaintenance, GatewayError> {
    let prefix = crate::paths::gateway_state_path(&["object-read-grant"])
        .map_err(|error| GatewayError::Rejected(format!("invalid read grant prefix: {error}")))?;
    let page = super::super::maintenance::scan_batch(
        state,
        prefix,
        cursor,
        "object read grant maintenance",
    )
    .await?;
    let mut result = ReadGrantMaintenance {
        examined: page.examined,
        skipped_oversized: page.skipped_oversized,
        next: page.next,
        ..ReadGrantMaintenance::default()
    };
    for (path, envelope) in page.entries {
        if prune_read_grant_entry(state, &path, envelope, now_ms).await? {
            result.removed += 1;
        }
    }
    Ok(result)
}

pub(in crate::object) async fn prune_read_grant_entry(
    state: &Backend,
    path: &Path,
    envelope: TaintedValue,
    now_ms: i64,
) -> Result<bool, GatewayError> {
    let Ok((_, grant)) = record::decode_unbound(&envelope) else {
        return Ok(false);
    };
    if read_grant_path(&grant.grant_id).ok().as_ref() != Some(path) || grant.expires_at_ms > now_ms
    {
        return Ok(false);
    }
    match state
        .write_compare_delete_tainted_bounded(
            path,
            Some(envelope.value),
            envelope.taint,
            super::super::maintenance::PAGE_BUDGET,
        )
        .await
    {
        Ok(_) => Ok(true),
        Err(xolotl_state::StateFailure {
            error: StateError::CasFailed { .. },
            ..
        }) => Ok(false),
        Err(error) => Err(GatewayError::Rejected(format!(
            "object read grant maintenance delete failed: {error}"
        ))),
    }
}
