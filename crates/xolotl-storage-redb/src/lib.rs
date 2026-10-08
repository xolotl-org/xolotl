#![forbid(unsafe_code)]

//! redb-backed persistent storage adapters for Xolotl.
//!
//! Provides persistent [state capabilities](xolotl_state) (state
//! plane, `state://`) and a durable [`FactStore`](xolotl_kernel::FactStore).
//! The base physical schema is independent of optional adapter features.
//! Reopening requires every base table; missing tables are rejected rather
//! than recreated as empty authority, receipt or retention evidence.
//!
mod blocking;
#[cfg(feature = "console")]
pub mod console;
mod database;
mod execution_ids;
mod fact;
#[cfg(feature = "federation")]
mod federation;
#[cfg(feature = "federation")]
mod federation_guest_follow;
#[cfg(feature = "federation")]
mod federation_projection;
#[cfg(feature = "federation")]
mod federation_public_follow;
#[cfg(feature = "gateway")]
mod gateway_idempotency;
mod schema;
mod state;

use blocking::TrackedBlockingSpawner;
pub use execution_ids::RedbExecutionIdSource;
pub use fact::RedbFactStore;
#[cfg(feature = "federation")]
pub use federation::RedbFederationStore;
#[cfg(feature = "federation")]
pub use federation_guest_follow::{
    GuestFollowInboxPage, GuestFollowSpec, GuestFollowView, MAX_GUEST_FOLLOW_INBOX_BYTES,
    MAX_GUEST_FOLLOW_INBOX_RECORDS, RedbGuestFollowerStore,
};
#[cfg(feature = "federation")]
pub use federation_projection::{
    FederationStatePublicationPage, FederationStatePublicationStatus, RedbFederationStateProjection,
};
#[cfg(feature = "federation")]
pub use federation_public_follow::{
    MAX_PUBLIC_FOLLOW_INBOX_BYTES, MAX_PUBLIC_FOLLOW_INBOX_RECORDS, PublicFollowerInboxPage,
    PublicFollowerView, RedbPublicFollowerStore,
};
#[cfg(feature = "gateway")]
pub use gateway_idempotency::RedbGatewayIdempotencyStore;
use redb::Database;
pub use state::{RedbHistory, RedbReadFuture, RedbStateBackend, RedbWriteFuture};
mod identity;
pub use identity::RedbIdentityDirectory;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicU64};
use xolotl_kernel::host::{BlockingSpawner, TokioBlockingSpawner};

use schema::{
    EXECUTION_ID_META_TABLE, FACT_INDEX_TABLE, FACT_META_TABLE, FACT_PROCESS_INDEX_TABLE,
    FACTS_TABLE, STATE_HISTORY_TABLE, STATE_META_TABLE, STATE_VALUES_TABLE,
};

/// Shared redb store that can materialize both state and fact adapters.
///
/// # Recovery after an uncertain commit
///
/// All adapters created from this store and its clones share one database
/// instance: State and Source, Facts, execution identities, the identity
/// directory, and any installed Gateway, Console or Federation stores. Their
/// operations commit independently, but a failed database commit affects the
/// recovery of the whole instance, not only the originating domain or path.
///
/// After a commit error other than `redb::CommitError::TransactionPoisoned`, or
/// a panic during commit, the host must stop using every adapter sharing this
/// instance, release its database users and reopen it before authoritative
/// reconciliation or retrying an uncertain mutation. `TransactionPoisoned`
/// alone establishes rollback; other failures may follow a durable commit.
/// Reconcile actual data and the applicable retained evidence after reopening;
/// a same-instance reread, notification or local cursor cannot prove rollback.
/// For accepted blocking jobs, [`Self::wait_idle`] provides the release barrier;
/// other database users must be released separately.
///
/// A shared recovery owner rejects new database transactions, subscriptions and
/// checked hints after uncertainty, invalidates all live State subscriptions and
/// closes Fact notification sources. The original operation retains its unknown
/// verdict; a later rejection does not resolve that operation. Already admitted
/// snapshots and confirmed immutable reservations do not become invalid, but
/// cannot establish the uncertain commit's outcome. `FactStore::cursor` remains
/// a non-authoritative local hint. [`Self::requires_reopen`] reports this terminal
/// state; only releasing the instance and reopening creates a healthy owner.
#[derive(Clone)]
pub struct RedbStore {
    db: Arc<database::Database>,
    history: RedbHistory,
    source_stream_limit: NonZeroUsize,
    source_retention_limit: NonZeroUsize,
    absence_limits: xolotl_state::AbsenceLimits,
    #[cfg(feature = "federation")]
    federation_publish_id_limit: NonZeroUsize,
    blocking_spawner: Arc<TrackedBlockingSpawner>,
    fact_cursor: Arc<AtomicU64>,
    #[cfg(feature = "console")]
    console_session_policy:
        Arc<parking_lot::Mutex<Option<xolotl_console::session_store::ConsoleSessionPolicy>>>,
}

/// Resource choices for a redb storage owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RedbOptions {
    /// Retained sourced-absence record and encoded-byte limits. Reopening with
    /// lower bounds preserves evidence and permits non-growing usage.
    pub absence_limits: xolotl_state::AbsenceLimits,
    /// Fixed State history mode. Reopening a database with another mode fails.
    pub history: RedbHistory,
    /// Maximum retained ordered Source stream positions across all scopes.
    /// A lower limit on reopen refuses new streams while existing streams
    /// continue; it does not erase their sequence positions.
    pub source_stream_limit: NonZeroUsize,
    /// Maximum retained Source event/receipt pairs plus rate records across
    /// all scopes. A lower limit on reopen preserves records and permits
    /// non-growing commits; maintenance returns slots. This is not an RSS limit.
    pub source_retention_limit: NonZeroUsize,
    /// Maximum retained publication identities across all Federation streams.
    /// Payload retirement returns no slots. Explicit retirement of exact
    /// receipts in closed retry epochs releases identities without permitting
    /// old attempts to execute again; reopening preserves retained evidence.
    pub federation_publish_id_limit: NonZeroUsize,
}

impl RedbOptions {
    /// Largest selectable retained Source stream position limit.
    pub const MAX_SOURCE_STREAM_LIMIT: usize = 65_536;
}

impl Default for RedbOptions {
    fn default() -> Self {
        Self {
            absence_limits: xolotl_state::AbsenceLimits::default(),
            history: RedbHistory::CurrentOnly,
            source_stream_limit: NonZeroUsize::MIN.saturating_add(4095),
            source_retention_limit: NonZeroUsize::MIN.saturating_add(65_535),
            federation_publish_id_limit: NonZeroUsize::MIN.saturating_add(65_535),
        }
    }
}

impl RedbStore {
    /// Open or create a redb database retaining current State values only.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, redb::DatabaseError> {
        Self::open_with_history(path, RedbHistory::CurrentOnly)
    }

    /// Open or create a database with a fixed State history mode.
    /// Reopening with another mode fails rather than exposing incomplete history.
    pub fn open_with_history(
        path: impl Into<PathBuf>,
        history: RedbHistory,
    ) -> Result<Self, redb::DatabaseError> {
        Self::open_with_options(
            path,
            RedbOptions {
                history,
                ..RedbOptions::default()
            },
        )
    }

    /// Open or create a database with explicit State and Source storage bounds.
    pub fn open_with_options(
        path: impl Into<PathBuf>,
        options: RedbOptions,
    ) -> Result<Self, redb::DatabaseError> {
        Self::open_with_options_and_spawner(
            path,
            options,
            Arc::new(TokioBlockingSpawner::default()),
        )
    }

    /// Open a database whose State reads, writes and history maintenance use
    /// the host's bounded blocking port.
    /// The same port may also be installed in the Kernel's `HostRuntime` so
    /// State transactions and Kernel jobs share one admission budget.
    pub fn open_with_options_and_spawner(
        path: impl Into<PathBuf>,
        options: RedbOptions,
        blocking_spawner: Arc<dyn BlockingSpawner>,
    ) -> Result<Self, redb::DatabaseError> {
        if options.source_stream_limit.get() > RedbOptions::MAX_SOURCE_STREAM_LIMIT {
            return Err(map_db_error(format!(
                "Source stream limit exceeds maximum {}",
                RedbOptions::MAX_SOURCE_STREAM_LIMIT
            )));
        }
        let db = open_database(path.into())?;
        Self::from_database(db, options, blocking_spawner)
    }

    pub(crate) fn from_database(
        db: Database,
        options: RedbOptions,
        blocking_spawner: Arc<dyn BlockingSpawner>,
    ) -> Result<Self, redb::DatabaseError> {
        schema::initialize(&db, options.history)?;
        Ok(Self {
            db: Arc::new(database::Database::new(db)),
            history: options.history,
            source_stream_limit: options.source_stream_limit,
            source_retention_limit: options.source_retention_limit,
            absence_limits: options.absence_limits,
            #[cfg(feature = "federation")]
            federation_publish_id_limit: options.federation_publish_id_limit,
            blocking_spawner: Arc::new(TrackedBlockingSpawner::new(blocking_spawner)),
            fact_cursor: Arc::new(AtomicU64::new(0)),
            #[cfg(feature = "console")]
            console_session_policy: Arc::default(),
        })
    }

    /// Build a state-plane backend backed by this database.
    pub fn state_backend(&self) -> RedbStateBackend {
        RedbStateBackend::new(
            self.db.clone(),
            self.db.publication(),
            self.history,
            self.source_stream_limit,
            self.source_retention_limit,
            self.absence_limits,
            self.blocking_spawner.clone(),
        )
    }

    /// Wait for accepted State, Source, and Gateway blocking jobs to release their
    /// database captures, even if their result waiters were dropped.
    ///
    /// Stop producers before taking this barrier. The returned future owns
    /// only the completion tracker, so adapters and the store can be dropped
    /// before awaiting it when the database is about to be reopened. Other
    /// database users, including synchronous Fact operations,
    /// must be stopped and released separately.
    pub fn wait_idle(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        self.blocking_spawner.wait_idle()
    }

    /// The durable Fact store with default retention limits.
    /// All adapters on this live database must select the same limits.
    pub fn fact_store(&self) -> Result<RedbFactStore, redb::DatabaseError> {
        self.db.ensure_open().map_err(map_db_error)?;
        RedbFactStore::new(
            self.db.clone(),
            self.fact_cursor.clone(),
            self.db.fact_notifications(),
        )
    }

    /// Select bounded Fact observation retention for this live database.
    /// Counts and encoded bytes commit with records. Reopen may choose different
    /// limits but preserves all retained records and their charges. Records
    /// exceeding new limits remain readable; new growth must pass admission.
    /// Initial accounting without retained counters scans existing records once;
    /// ordinary appends and completions update persistent counters incrementally.
    pub fn fact_store_with_limits(
        &self,
        limits: xolotl_kernel::FactRetentionLimits,
    ) -> Result<RedbFactStore, redb::DatabaseError> {
        self.db.ensure_open().map_err(map_db_error)?;
        RedbFactStore::new_with_limits(
            self.db.clone(),
            self.fact_cursor.clone(),
            self.db.fact_notifications(),
            limits,
        )
    }

    /// Whether a commit failure or panic requires releasing all database users
    /// and reopening before reconciliation. This state is shared by all clones.
    pub fn requires_reopen(&self) -> bool {
        self.db.requires_reopen()
    }

    /// Retained execution identity namespace shared by this database's adapters.
    pub fn execution_id_source(&self) -> RedbExecutionIdSource {
        RedbExecutionIdSource {
            db: self.db.clone(),
        }
    }

    /// Persistent identity directory shared by this database's host adapters.
    pub fn identity_directory(&self) -> RedbIdentityDirectory {
        RedbIdentityDirectory::new(self.db.clone())
    }

    /// Open the separate Gateway idempotency ledger with fixed durable limits.
    #[cfg(feature = "gateway")]
    pub fn gateway_idempotency_store(
        &self,
        limits: xolotl_gateway::GatewayIdempotencyLimits,
    ) -> Result<RedbGatewayIdempotencyStore, xolotl_gateway::GatewayError> {
        RedbGatewayIdempotencyStore::new(self.db.clone(), self.blocking_spawner.clone(), limits)
    }

    /// Open the private Console session owner with fixed storage-domain limits.
    #[cfg(feature = "console")]
    pub fn console_session_store(
        &self,
        policy: xolotl_console::session_store::ConsoleSessionPolicy,
    ) -> Result<console::RedbConsoleSessionStore, xolotl_console::session_store::SessionStoreError>
    {
        let mut bound = self.console_session_policy.lock();
        if bound.is_some_and(|current| current != policy) {
            return Err(xolotl_console::session_store::SessionStoreError::Rejected(
                "Console session policy differs from live storage owner".into(),
            ));
        }
        let sessions = console::RedbConsoleSessionStore::new(
            self.db.clone(),
            self.blocking_spawner.clone(),
            policy,
        )?;
        *bound = Some(policy);
        Ok(sessions)
    }

    /// Bind durable federation state to this database's stable node identity.
    /// A database already bound to another identity is rejected.
    #[cfg(feature = "federation")]
    pub fn federation_store(
        &self,
        node: xolotl_federation::FederationNodeId,
    ) -> Result<RedbFederationStore, xolotl_federation::FederationError> {
        RedbFederationStore::bind(self.db.clone(), node, self.federation_publish_id_limit)
    }

    /// Bind a separate, bounded local cache for public federation streams to
    /// this database's stable node identity. It creates no publisher peer or
    /// subscription authority.
    #[cfg(feature = "federation")]
    pub fn public_follower_store(
        &self,
        node: xolotl_federation::FederationNodeId,
    ) -> Result<RedbPublicFollowerStore, xolotl_federation::FederationError> {
        self.federation_store(node)?;
        Ok(RedbPublicFollowerStore::new(self.db.clone(), node))
    }

    /// Bind an invitation-only receiver inbox, independent of private peer
    /// subscriptions and public stream follows, to this database's node.
    #[cfg(feature = "federation")]
    pub fn guest_follower_store(
        &self,
        node: xolotl_federation::FederationNodeId,
    ) -> Result<RedbGuestFollowerStore, xolotl_federation::FederationError> {
        self.federation_store(node)?;
        Ok(RedbGuestFollowerStore::new(self.db.clone(), node))
    }
}

#[cfg(unix)]
fn open_database(path: PathBuf) -> Result<Database, redb::DatabaseError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    // The State database contains credentials and factor verifier material.
    // Keep the open file descriptor, so checking a pathname cannot be raced
    // with a later redb open of another file.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(map_db_error(
            "database must be a regular file inaccessible to group and others",
        ));
    }
    Database::builder().create_file(file)
}

#[cfg(not(unix))]
fn open_database(path: PathBuf) -> Result<Database, redb::DatabaseError> {
    Database::create(path)
}

fn map_db_error(e: impl ToString) -> redb::DatabaseError {
    redb::DatabaseError::Storage(redb::StorageError::Io(std::io::Error::other(e.to_string())))
}
