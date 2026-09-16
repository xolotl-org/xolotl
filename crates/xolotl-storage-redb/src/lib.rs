#![forbid(unsafe_code)]

//! redb-backed persistent storage adapters for Xolotl.
//!
//! Provides persistent [state capabilities](xolotl_state) (state
//! plane, `state://`) and a durable [`FactStore`](xolotl_kernel::FactStore).
//!
#[cfg(feature = "durable")]
mod checkpoint;
mod execution_ids;
mod fact;
mod schema;
mod state;
#[cfg(feature = "durable")]
pub use checkpoint::RedbCheckpointStore;

pub use execution_ids::RedbExecutionIdSource;
pub use fact::RedbFactStore;
use redb::Database;
pub use state::RedbStateBackend;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, atomic::AtomicU64};

#[cfg(feature = "durable")]
use schema::{CHECKPOINT_META_TABLE, CHECKPOINTS_TABLE};
use schema::{
    EXECUTION_ID_META_TABLE, FACT_INDEX_TABLE, FACT_META_TABLE, FACT_PROCESS_INDEX_TABLE,
    FACTS_TABLE, STATE_HISTORY_TABLE, STATE_META_TABLE, STATE_VALUES_TABLE,
};

/// Shared redb store that can materialize both state and fact adapters.
#[derive(Clone)]
pub struct RedbStore {
    db: Arc<Database>,
    state_subscriptions: Arc<state::Subscriptions>,
    fact_cursor: Arc<AtomicU64>,
    fact_notifications: Arc<OnceLock<tokio::sync::broadcast::Sender<Arc<xolotl_types::Fact>>>>,
    #[cfg(feature = "durable")]
    journal_leases: Arc<parking_lot::Mutex<std::collections::BTreeSet<xolotl_types::ProcessId>>>,
}

impl RedbStore {
    /// Open or create the redb database and initialize Xolotl tables.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, redb::DatabaseError> {
        let db = Database::create(path.into())?;
        schema::initialize(&db)?;
        Ok(Self {
            db: Arc::new(db),
            state_subscriptions: Arc::default(),
            fact_cursor: Arc::new(AtomicU64::new(0)),
            fact_notifications: Arc::default(),
            #[cfg(feature = "durable")]
            journal_leases: Arc::default(),
        })
    }

    /// Build a state-plane backend backed by this database.
    pub fn state_backend(&self) -> RedbStateBackend {
        RedbStateBackend::new(self.db.clone(), self.state_subscriptions.clone())
    }

    /// The durable fact store.
    pub fn fact_store(&self) -> Result<RedbFactStore, redb::DatabaseError> {
        let tx = self.fact_notifications.get_or_init(|| {
            tokio::sync::broadcast::channel(xolotl_kernel::FACT_BROADCAST_CAPACITY).0
        });
        RedbFactStore::new(self.db.clone(), self.fact_cursor.clone(), tx.clone())
    }

    /// Retained execution identity namespace shared by this database's adapters.
    pub fn execution_id_source(&self) -> RedbExecutionIdSource {
        RedbExecutionIdSource {
            db: self.db.clone(),
        }
    }

    /// Persistent interpreter checkpoints with exclusive per-process leases.
    #[cfg(feature = "durable")]
    pub fn checkpoint_store(&self) -> RedbCheckpointStore {
        RedbCheckpointStore {
            db: self.db.clone(),
            leases: self.journal_leases.clone(),
        }
    }
}

fn map_db_error(e: impl ToString) -> redb::DatabaseError {
    redb::DatabaseError::Storage(redb::StorageError::Io(std::io::Error::other(e.to_string())))
}
