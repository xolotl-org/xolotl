//! First-format initialization. Existing stores must retain every metadata key.

use crate::map_db_error;
use redb::{Database, ReadableTable, TableDefinition, TableHandle};
use std::collections::BTreeSet;

pub(super) const STATE_VALUES_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("state_values");
pub(super) const STATE_HISTORY_TABLE: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("state_history");
pub(super) const STATE_META_TABLE: TableDefinition<&str, i64> = TableDefinition::new("state_meta");
pub(super) const FACTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("facts");
pub(super) const FACT_INDEX_TABLE: TableDefinition<&[u8], u64> =
    TableDefinition::new("fact_index_v2");
pub(super) const FACT_PROCESS_INDEX_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("fact_process_index");
pub(super) const FACT_META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("fact_meta");
pub(super) const EXECUTION_ID_META_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("execution_id_meta");
pub(super) const CHECKPOINTS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("execution_checkpoints_v1");
// Zero represents an unused checkpoint catalog; an observed process uses id+1.
// u128 keeps ProcessId(0) and ProcessId(u64::MAX) representable without an
// optional metadata row that could be confused with corruption.
pub(super) const CHECKPOINT_META_TABLE: TableDefinition<&str, u128> =
    TableDefinition::new("execution_checkpoint_meta");

pub(super) const LAST_HISTORY_MILLIS: &str = "last_history_millis";
pub(super) const NEXT_FACT_CURSOR: &str = "next_cursor";
pub(super) const EXECUTION_HIGH_WATER: &str = "high_water";
pub(super) const CHECKPOINT_HIGH_WATER: &str = "process_high_water";

pub(super) fn initialize(db: &Database) -> Result<(), redb::DatabaseError> {
    let txn = db.begin_write().map_err(map_db_error)?;
    let present: BTreeSet<_> = txn
        .list_tables()
        .map_err(map_db_error)?
        .map(|table| table.name().to_string())
        .collect();
    let fresh = present.is_empty()
        && txn
            .list_multimap_tables()
            .map_err(map_db_error)?
            .next()
            .is_none();
    if !fresh {
        for name in [
            STATE_VALUES_TABLE.name(),
            STATE_HISTORY_TABLE.name(),
            STATE_META_TABLE.name(),
            FACTS_TABLE.name(),
            FACT_INDEX_TABLE.name(),
            FACT_PROCESS_INDEX_TABLE.name(),
            FACT_META_TABLE.name(),
            EXECUTION_ID_META_TABLE.name(),
            CHECKPOINTS_TABLE.name(),
            CHECKPOINT_META_TABLE.name(),
        ] {
            if !present.contains(name) {
                return Err(map_db_error(format!(
                    "storage schema table missing: {name}"
                )));
            }
        }
    }

    txn.open_table(STATE_VALUES_TABLE).map_err(map_db_error)?;
    txn.open_table(STATE_HISTORY_TABLE).map_err(map_db_error)?;
    txn.open_table(FACTS_TABLE).map_err(map_db_error)?;
    txn.open_table(FACT_INDEX_TABLE).map_err(map_db_error)?;
    txn.open_table(FACT_PROCESS_INDEX_TABLE)
        .map_err(map_db_error)?;
    // The physical format is independent of which optional adapters are built.
    txn.open_table(CHECKPOINTS_TABLE).map_err(map_db_error)?;
    {
        let mut meta = txn.open_table(STATE_META_TABLE).map_err(map_db_error)?;
        if fresh {
            meta.insert(LAST_HISTORY_MILLIS, 0).map_err(map_db_error)?;
        } else if meta
            .get(LAST_HISTORY_MILLIS)
            .map_err(map_db_error)?
            .is_none()
        {
            return Err(map_db_error("state history metadata missing"));
        }
    }
    initialize_counter(&txn, FACT_META_TABLE, NEXT_FACT_CURSOR, fresh)?;
    initialize_counter(&txn, EXECUTION_ID_META_TABLE, EXECUTION_HIGH_WATER, fresh)?;
    {
        let mut meta = txn
            .open_table(CHECKPOINT_META_TABLE)
            .map_err(map_db_error)?;
        if fresh {
            meta.insert(CHECKPOINT_HIGH_WATER, 0)
                .map_err(map_db_error)?;
        } else {
            let value = meta
                .get(CHECKPOINT_HIGH_WATER)
                .map_err(map_db_error)?
                .ok_or_else(|| map_db_error("checkpoint metadata missing"))?
                .value();
            if value > u128::from(u64::MAX) + 1 {
                return Err(map_db_error(
                    "checkpoint high water exceeds process identity range",
                ));
            }
        }
    }
    txn.commit().map_err(map_db_error)
}

fn initialize_counter(
    txn: &redb::WriteTransaction,
    table: TableDefinition<&str, u64>,
    key: &str,
    fresh: bool,
) -> Result<(), redb::DatabaseError> {
    let mut meta = txn.open_table(table).map_err(map_db_error)?;
    if fresh {
        meta.insert(key, 0).map_err(map_db_error)?;
    } else if meta.get(key).map_err(map_db_error)?.is_none() {
        return Err(map_db_error(format!(
            "{} metadata missing: {key}",
            table.name()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
