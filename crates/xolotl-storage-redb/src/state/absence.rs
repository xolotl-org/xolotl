//! Retained absence usage commits with current State and Source records.
//! Schema initialization owns both required counters. Missing accounting is
//! rejected, never reconstructed or reset. Lower ceilings retain evidence.

use super::{STATE_META_TABLE, backend_error, codec};
use redb::ReadableTable;
use xolotl_state::{AbsenceLimits, StateError, StateResult};

const RECORDS: &str = "absence_records_v1";
const BYTES: &str = "absence_encoded_bytes_v1";

fn charge(key: &str, bytes: &[u8]) -> StateResult<(usize, usize)> {
    if !codec::is_absence(bytes) {
        return Ok((0, 0));
    }
    let size = key
        .len()
        .checked_add(bytes.len())
        .ok_or_else(|| backend_error("state absence accounting overflow"))?;
    Ok((1, size))
}

pub(super) fn replacing(
    txn: &redb::WriteTransaction,
    table: &redb::Table<'_, &str, &[u8]>,
    key: &str,
    after: Option<&[u8]>,
    limits: AbsenceLimits,
) -> StateResult<()> {
    let mut meta = txn.open_table(STATE_META_TABLE).map_err(backend_error)?;
    let records = meta
        .get(RECORDS)
        .map_err(backend_error)?
        .map(|guard| guard.value());
    let bytes = meta
        .get(BYTES)
        .map_err(backend_error)?
        .map(|guard| guard.value());
    let current = match (records, bytes) {
        (Some(records), Some(bytes)) => (
            usize::try_from(records).map_err(backend_error)?,
            usize::try_from(bytes).map_err(backend_error)?,
        ),
        _ => return Err(backend_error("state absence accounting missing")),
    };
    let before = table
        .get(key)
        .map_err(backend_error)?
        .map(|guard| charge(key, guard.value()))
        .transpose()?
        .unwrap_or_default();
    let after = after
        .map(|bytes| charge(key, bytes))
        .transpose()?
        .unwrap_or_default();
    let next = (
        current
            .0
            .checked_sub(before.0)
            .and_then(|count| count.checked_add(after.0)),
        current
            .1
            .checked_sub(before.1)
            .and_then(|count| count.checked_add(after.1)),
    );
    let next = next
        .0
        .zip(next.1)
        .ok_or_else(|| backend_error("state absence accounting overflow"))?;
    if limits
        .records
        .is_some_and(|limit| next.0 > limit && next.0 > current.0)
        || limits
            .encoded_bytes
            .is_some_and(|limit| next.1 > limit && next.1 > current.1)
    {
        return Err(StateError::Backend("state absence capacity exhausted".into()).into());
    }
    if next == current {
        return Ok(());
    }
    meta.insert(RECORDS, i64::try_from(next.0).map_err(backend_error)?)
        .map_err(backend_error)?;
    meta.insert(BYTES, i64::try_from(next.1).map_err(backend_error)?)
        .map_err(backend_error)?;
    Ok(())
}
