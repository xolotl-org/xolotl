//! redb-backed persistent storage adapters for Nexus (§24.1).
//!
//! Provides the production [`StateBackend`](nexus_state::StateBackend) (state
//! plane, `state://`) and the durable [`FactStore`](nexus_kernel::FactStore)
//! (the write-ahead source of truth, §9).

mod fact;
mod state;

pub use fact::RedbFactStore;
use redb::{Database, TableDefinition};
pub use state::RedbStateBackend;
use std::path::PathBuf;
use std::sync::Arc;

const STATE_VALUES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("state_values");
const STATE_HISTORY_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state_history");
/// Facts keyed by monotonic append cursor (§9).
const FACTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("facts");
/// OperationId key → cursor slot, so `complete` updates the begun fact.
const FACT_INDEX_TABLE: TableDefinition<&str, u64> = TableDefinition::new("fact_index");
const FACT_META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("fact_meta");

#[derive(Clone)]
pub struct RedbStore {
    db: Arc<Database>,
}

impl RedbStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, redb::DatabaseError> {
        let db = Database::create(path.into())?;
        {
            let txn = db.begin_write().map_err(map_db_error)?;
            let _ = txn.open_table(STATE_VALUES_TABLE);
            let _ = txn.open_table(STATE_HISTORY_TABLE);
            let _ = txn.open_table(FACTS_TABLE);
            let _ = txn.open_table(FACT_INDEX_TABLE);
            let _ = txn.open_table(FACT_META_TABLE);
            txn.commit().map_err(map_db_error)?;
        }
        Ok(Self { db: Arc::new(db) })
    }

    pub fn state_backend(&self) -> RedbStateBackend {
        RedbStateBackend::new(self.db.clone())
    }

    /// The durable fact store (§9).
    pub fn fact_store(&self) -> Result<RedbFactStore, redb::DatabaseError> {
        RedbFactStore::new(self.db.clone())
    }
}

fn map_db_error(e: impl ToString) -> redb::DatabaseError {
    redb::DatabaseError::Storage(redb::StorageError::Io(std::io::Error::other(e.to_string())))
}
