//! Immediately durable execution-id reservations, independent of retained records.

use crate::EXECUTION_ID_META_TABLE;
use redb::{Database, Durability, ReadableTable};
use std::{num::NonZeroU64, sync::Arc};
use xolotl_kernel::{ExecutionIdError, ExecutionIdRange, ExecutionIdSource};
use xolotl_types::ExecutionId;

use crate::schema::EXECUTION_HIGH_WATER as HIGH_WATER_KEY;

/// Execution allocator source that can be retained independently of facts or checkpoints.
#[derive(Clone)]
pub struct RedbExecutionIdSource {
    pub(crate) db: Arc<Database>,
}

impl ExecutionIdSource for RedbExecutionIdSource {
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        reserve(&self.db, count)
    }
}

pub(crate) fn reserve(
    db: &Database,
    count: NonZeroU64,
) -> Result<ExecutionIdRange, ExecutionIdError> {
    let mut txn = db.begin_write().map_err(reservation_error)?;
    txn.set_durability(Durability::Immediate)
        .map_err(reservation_error)?;
    let range = {
        let mut meta = txn
            .open_table(EXECUTION_ID_META_TABLE)
            .map_err(reservation_error)?;
        let high_water = meta
            .get(HIGH_WATER_KEY)
            .map_err(reservation_error)?
            .map(|value| value.value())
            .ok_or_else(|| reservation_error("execution identity metadata missing"))?;
        let first = high_water
            .checked_add(1)
            .and_then(ExecutionId::new)
            .ok_or(ExecutionIdError::Exhausted)?;
        let next = high_water.saturating_add(count.get());
        let actual = NonZeroU64::new(next - high_water).ok_or(ExecutionIdError::InvalidRange)?;
        let range = ExecutionIdRange::new(first, actual)?;
        meta.insert(HIGH_WATER_KEY, next)
            .map_err(reservation_error)?;
        range
    };
    txn.commit().map_err(reservation_error)?;
    Ok(range)
}

fn reservation_error(error: impl std::fmt::Display) -> ExecutionIdError {
    ExecutionIdError::Backend(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RedbStore;
    use anyhow::ensure;
    use xolotl_kernel::{ExecutionIds, FactSink, FactStore};

    #[test]
    fn reservations_survive_reopen_without_any_facts() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("execution-ids.redb");
        let first = {
            let store = RedbStore::open(&path)?;
            let facts = Arc::new(store.fact_store()?);
            let sink = FactSink::new(facts.clone());
            let id = sink.execution_ids().allocate()?;
            ensure!(facts.all_facts()?.is_empty());
            id
        };
        let store = RedbStore::open(&path)?;
        let ids = ExecutionIds::new(Arc::new(store.execution_id_source()));
        let second = ids.allocate()?;
        ensure!(first.get() == 1 && second.get() == 257);
        Ok(())
    }

    #[test]
    fn the_final_range_is_partial_and_never_wraps() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = RedbStore::open(dir.path().join("execution-ids.redb"))?;
        let txn = store.db.begin_write()?;
        {
            let mut meta = txn.open_table(EXECUTION_ID_META_TABLE)?;
            meta.insert(HIGH_WATER_KEY, u64::MAX - 2)?;
        }
        txn.commit()?;
        let ids = ExecutionIds::new(Arc::new(store.execution_id_source()));
        ensure!(ids.allocate()?.get() == u64::MAX - 1);
        ensure!(ids.allocate()?.get() == u64::MAX);
        ensure!(ids.allocate() == Err(ExecutionIdError::Exhausted));
        Ok(())
    }

    #[cfg(feature = "durable")]
    #[test]
    fn fact_checkpoint_and_explicit_sources_share_one_namespace() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = RedbStore::open(dir.path().join("execution-ids.redb"))?;
        let facts = ExecutionIds::new(Arc::new(store.fact_store()?));
        let checkpoints = ExecutionIds::new(Arc::new(store.checkpoint_store()));
        let explicit = ExecutionIds::new(Arc::new(store.execution_id_source()));
        ensure!(facts.allocate()?.get() == 1);
        ensure!(checkpoints.allocate()?.get() == 257);
        ensure!(explicit.allocate()?.get() == 513);
        ensure!(facts.allocate()?.get() == 2);
        Ok(())
    }
}
