#![forbid(unsafe_code)]

//! redb-backed persistent storage adapters for Xolotl.
//!
//! Provides a persistent [`StateBackend`](xolotl_state::StateBackend) (state
//! plane, `state://`) and a durable [`FactStore`](xolotl_kernel::FactStore).
//!
mod fact;
mod state;

pub use fact::RedbFactStore;
use redb::{Database, TableDefinition};
pub use state::RedbStateBackend;
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicI64};

const STATE_VALUES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("state_values");
const STATE_HISTORY_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("state_history");
/// Facts keyed by monotonic append cursor.
const FACTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("facts");
/// OperationId key → cursor slot, so `complete` updates the begun fact.
const FACT_INDEX_TABLE: TableDefinition<&str, u64> = TableDefinition::new("fact_index");
/// `(caller process, cursor slot)` → cursor slot, enabling bounded range scans
/// for `facts_of(process)`.
const FACT_PROCESS_INDEX_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("fact_process_index");
const FACT_META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("fact_meta");

/// Shared redb store that can materialize both state and fact adapters.
#[derive(Clone)]
pub struct RedbStore {
    db: Arc<Database>,
    state_history_clock: Arc<AtomicI64>,
}

impl RedbStore {
    /// Open or create the redb database and initialize Xolotl tables.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, redb::DatabaseError> {
        let db = Database::create(path.into())?;
        {
            let txn = db.begin_write().map_err(map_db_error)?;
            txn.open_table(STATE_VALUES_TABLE).map_err(map_db_error)?;
            txn.open_table(STATE_HISTORY_TABLE).map_err(map_db_error)?;
            txn.open_table(FACTS_TABLE).map_err(map_db_error)?;
            txn.open_table(FACT_INDEX_TABLE).map_err(map_db_error)?;
            txn.open_table(FACT_PROCESS_INDEX_TABLE)
                .map_err(map_db_error)?;
            txn.open_table(FACT_META_TABLE).map_err(map_db_error)?;
            txn.commit().map_err(map_db_error)?;
        }
        Ok(Self {
            db: Arc::new(db),
            state_history_clock: Arc::new(AtomicI64::new(0)),
        })
    }

    /// Build a state-plane backend backed by this database.
    pub fn state_backend(&self) -> RedbStateBackend {
        RedbStateBackend::new(self.db.clone(), self.state_history_clock.clone())
    }

    /// The durable fact store.
    pub fn fact_store(&self) -> Result<RedbFactStore, redb::DatabaseError> {
        RedbFactStore::new(self.db.clone())
    }
}

fn map_db_error(e: impl ToString) -> redb::DatabaseError {
    redb::DatabaseError::Storage(redb::StorageError::Io(std::io::Error::other(e.to_string())))
}
