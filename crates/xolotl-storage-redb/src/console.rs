//! Durable private Console sessions. Each write transaction owns admission,
//! comparison, counters and index changes; ordinary State is never touched.

use crate::blocking::TrackedBlockingSpawner;
use crate::database::Database;
use async_trait::async_trait;
use redb::{ReadableTable, ReadableTableMetadata, Table, TableDefinition, TableHandle};
use std::sync::Arc;
use tokio::sync::oneshot;
use xolotl_console::session_store::{
    ConsoleSession, ConsoleSessionPolicy, ConsoleSessionStore, MAINTENANCE_BYTES, MAINTENANCE_ROWS,
    SessionPageLimits, SessionStoreError, SessionStorePage,
};
use xolotl_kernel::host::BlockingSpawner;

const ROWS: TableDefinition<&str, &[u8]> = TableDefinition::new("console_sessions_v1");
const ACCOUNTS: TableDefinition<&str, u64> = TableDefinition::new("console_session_accounts_v1");
const ACCOUNT_ISSUANCE: TableDefinition<&str, &str> =
    TableDefinition::new("console_session_account_issuance_v1");
const ISSUANCE: TableDefinition<&str, &str> = TableDefinition::new("console_session_issuance_v1");
const EXPIRY: TableDefinition<&str, &str> = TableDefinition::new("console_session_expiry_v1");
const META: TableDefinition<&str, u64> = TableDefinition::new("console_session_meta_v1");

/// Shared durable storage domain. The owning `RedbStore` freezes live policy
/// across its clones. A fresh reopened owner may change durable capacities only
/// when the retained domain count and every account counter fit the new policy.
/// This bounded scalar scan happens only on policy change; no payload is read,
/// evicted or reset. Hosts must schedule bounded expiry maintenance explicitly.
#[derive(Clone)]
pub struct RedbConsoleSessionStore {
    db: Arc<Database>,
    blocking_spawner: Arc<TrackedBlockingSpawner>,
    policy: ConsoleSessionPolicy,
}

impl RedbConsoleSessionStore {
    pub(crate) fn new(
        db: Arc<Database>,
        blocking_spawner: Arc<TrackedBlockingSpawner>,
        policy: ConsoleSessionPolicy,
    ) -> Result<Self, SessionStoreError> {
        let transaction = db.begin_write().map_err(storage_error)?;
        let names = [
            ROWS.name(),
            ACCOUNTS.name(),
            ACCOUNT_ISSUANCE.name(),
            ISSUANCE.name(),
            EXPIRY.name(),
            META.name(),
        ];
        let mut existing = 0;
        for table in transaction.list_tables().map_err(storage_error)? {
            if names.contains(&table.name()) {
                existing += 1;
            }
        }
        if existing != 0 && existing != names.len() {
            return Err(rejected("incomplete Console session tables"));
        }
        {
            let rows = transaction.open_table(ROWS).map_err(storage_error)?;
            let accounts = transaction.open_table(ACCOUNTS).map_err(storage_error)?;
            let account_issuance = transaction
                .open_table(ACCOUNT_ISSUANCE)
                .map_err(storage_error)?;
            let issuance = transaction.open_table(ISSUANCE).map_err(storage_error)?;
            let expiry = transaction.open_table(EXPIRY).map_err(storage_error)?;
            let mut meta = transaction.open_table(META).map_err(storage_error)?;
            let version = meta
                .get("version")
                .map_err(storage_error)?
                .map(|entry| entry.value());
            match version {
                None if existing == 0 => {
                    for (key, value) in [
                        ("version", 1),
                        ("per_account", policy.per_account() as u64),
                        ("domain", policy.domain() as u64),
                        ("count", 0),
                    ] {
                        meta.insert(key, value).map_err(storage_error)?;
                    }
                }
                Some(1) => {
                    let old_account_limit = counter(&meta, "per_account")?;
                    let old_domain_limit = counter(&meta, "domain")?;
                    let old_policy = ConsoleSessionPolicy::new(
                        usize::try_from(old_account_limit).map_err(storage_error)?,
                        usize::try_from(old_domain_limit).map_err(storage_error)?,
                    )?;
                    let count = counter(&meta, "count")?;
                    if count > old_domain_limit
                        || rows.len().map_err(storage_error)? != count
                        || account_issuance.len().map_err(storage_error)? != count
                        || issuance.len().map_err(storage_error)? != count
                        || expiry.len().map_err(storage_error)? != count
                        || accounts.len().map_err(storage_error)? > count
                    {
                        return Err(rejected("Console session accounting mismatch"));
                    }
                    if policy != old_policy {
                        if count > policy.domain() as u64 {
                            return Err(rejected(
                                "retained Console sessions exceed new domain capacity",
                            ));
                        }
                        let mut retained = 0u64;
                        for entry in accounts.iter().map_err(storage_error)? {
                            let (_, account_count) = entry.map_err(storage_error)?;
                            let account_count = account_count.value();
                            if account_count == 0 || account_count > policy.per_account() as u64 {
                                return Err(rejected(
                                    "retained Console sessions exceed new account capacity",
                                ));
                            }
                            retained = retained
                                .checked_add(account_count)
                                .filter(|retained| *retained <= count)
                                .ok_or_else(|| {
                                    rejected("Console session account accounting mismatch")
                                })?;
                        }
                        if retained != count {
                            return Err(rejected("Console session account accounting mismatch"));
                        }
                        meta.insert("per_account", policy.per_account() as u64)
                            .map_err(storage_error)?;
                        meta.insert("domain", policy.domain() as u64)
                            .map_err(storage_error)?;
                    }
                }
                _ => return Err(rejected("unsupported or missing Console session metadata")),
            }
        }
        transaction.commit().map_err(commit_error)?;
        Ok(Self {
            db,
            blocking_spawner,
            policy,
        })
    }

    async fn run<Output: Send + 'static>(
        &self,
        operation: impl FnOnce(Arc<Database>) -> Result<Output, SessionStoreError> + Send + 'static,
    ) -> Result<Output, SessionStoreError> {
        let db = self.db.clone();
        let (sender, receiver) = oneshot::channel();
        self.blocking_spawner
            .spawn(Box::new(move || {
                drop(sender.send(operation(db)));
            }))
            .map_err(|error| {
                rejected(&format!(
                    "Console session worker unavailable before admission: {error}"
                ))
            })?;
        receiver.await.map_err(|_worker_lost| {
            SessionStoreError::Unknown("accepted Console session worker result lost".into())
        })?
    }
}

struct Tables<'transaction> {
    rows: Table<'transaction, &'static str, &'static [u8]>,
    accounts: Table<'transaction, &'static str, u64>,
    account_issuance: Table<'transaction, &'static str, &'static str>,
    issuance: Table<'transaction, &'static str, &'static str>,
    expiry: Table<'transaction, &'static str, &'static str>,
    meta: Table<'transaction, &'static str, u64>,
}

impl<'transaction> Tables<'transaction> {
    fn open(transaction: &'transaction redb::WriteTransaction) -> Result<Self, SessionStoreError> {
        Ok(Self {
            rows: transaction.open_table(ROWS).map_err(storage_error)?,
            accounts: transaction.open_table(ACCOUNTS).map_err(storage_error)?,
            account_issuance: transaction
                .open_table(ACCOUNT_ISSUANCE)
                .map_err(storage_error)?,
            issuance: transaction.open_table(ISSUANCE).map_err(storage_error)?,
            expiry: transaction.open_table(EXPIRY).map_err(storage_error)?,
            meta: transaction.open_table(META).map_err(storage_error)?,
        })
    }
    fn get(&self, sid: &str) -> Result<Option<ConsoleSession>, SessionStoreError> {
        self.rows
            .get(sid)
            .map_err(storage_error)?
            .map(|entry| ConsoleSession::decode(sid, entry.value()))
            .transpose()
    }
    fn account_count(&self, account: &str) -> Result<u64, SessionStoreError> {
        Ok(self
            .accounts
            .get(account)
            .map_err(storage_error)?
            .map_or(0, |row| row.value()))
    }
    fn encoded_size(&self, sid: &str) -> Result<usize, SessionStoreError> {
        self.rows
            .get(sid)
            .map_err(storage_error)?
            .map(|row| row.value().len() + sid.len())
            .ok_or_else(|| rejected("indexed session SID missing"))
    }
    fn remove(&mut self, session: &ConsoleSession) -> Result<(), SessionStoreError> {
        let account = account_key(session.account().0, session.account().1);
        let count = self
            .account_count(&account)?
            .checked_sub(1)
            .ok_or_else(|| rejected("account count underflow"))?;
        if count == 0 {
            self.accounts
                .remove(account.as_str())
                .map_err(storage_error)?;
        } else {
            self.accounts
                .insert(account.as_str(), count)
                .map_err(storage_error)?;
        }
        self.rows.remove(session.sid()).map_err(storage_error)?;
        self.account_issuance
            .remove(account_issuance_key(session).as_str())
            .map_err(storage_error)?;
        self.issuance
            .remove(ordered_key(session.issued_at(), session.sid()).as_str())
            .map_err(storage_error)?;
        self.expiry
            .remove(ordered_key(session.expires_at(), session.sid()).as_str())
            .map_err(storage_error)?;
        let count = counter(&self.meta, "count")?
            .checked_sub(1)
            .ok_or_else(|| rejected("domain count underflow"))?;
        self.meta.insert("count", count).map_err(storage_error)?;
        Ok(())
    }
    fn insert(&mut self, session: &ConsoleSession, bytes: &[u8]) -> Result<(), SessionStoreError> {
        let account = account_key(session.account().0, session.account().1);
        let count = self.account_count(&account)? + 1;
        self.accounts
            .insert(account.as_str(), count)
            .map_err(storage_error)?;
        self.rows
            .insert(session.sid(), bytes)
            .map_err(storage_error)?;
        self.account_issuance
            .insert(account_issuance_key(session).as_str(), session.sid())
            .map_err(storage_error)?;
        self.issuance
            .insert(
                ordered_key(session.issued_at(), session.sid()).as_str(),
                session.sid(),
            )
            .map_err(storage_error)?;
        self.expiry
            .insert(
                ordered_key(session.expires_at(), session.sid()).as_str(),
                session.sid(),
            )
            .map_err(storage_error)?;
        let count = counter(&self.meta, "count")? + 1;
        self.meta.insert("count", count).map_err(storage_error)?;
        Ok(())
    }
    fn oldest_account(&self, account: &str) -> Result<Option<String>, SessionStoreError> {
        let mut entries = self
            .account_issuance
            .range(account..)
            .map_err(storage_error)?;
        let Some(entry) = entries.next() else {
            return Ok(None);
        };
        let (key, sid) = entry.map_err(storage_error)?;
        Ok(key
            .value()
            .starts_with(account)
            .then(|| sid.value().to_owned()))
    }
}

#[async_trait]
impl ConsoleSessionStore for RedbConsoleSessionStore {
    fn policy(&self) -> ConsoleSessionPolicy {
        self.policy
    }
    async fn get(&self, sid: &str) -> Result<Option<ConsoleSession>, SessionStoreError> {
        let sid = sid.to_owned();
        self.run(move |db| {
            let transaction = db.begin_read().map_err(storage_error)?;
            let rows = transaction.open_table(ROWS).map_err(storage_error)?;
            rows.get(sid.as_str())
                .map_err(storage_error)?
                .map(|entry| ConsoleSession::decode(&sid, entry.value()))
                .transpose()
        })
        .await
    }
    async fn create(&self, session: ConsoleSession) -> Result<(), SessionStoreError> {
        let policy = self.policy;
        self.run(move |db| {
            let transaction = db.begin_write().map_err(storage_error)?;
            {
                let mut tables = Tables::open(&transaction)?;
                if tables
                    .rows
                    .get(session.sid())
                    .map_err(storage_error)?
                    .is_some()
                {
                    return Err(SessionStoreError::Conflict);
                }
                let bytes = session.encode()?;
                let account = account_key(session.account().0, session.account().1);
                let eviction = if tables.account_count(&account)? >= policy.per_account() as u64 {
                    Some(
                        tables
                            .oldest_account(&account)?
                            .ok_or_else(|| rejected("account issuance index missing"))?,
                    )
                } else if counter(&tables.meta, "count")? >= policy.domain() as u64 {
                    return Err(rejected("session domain capacity exhausted"));
                } else {
                    None
                };
                if let Some(sid) = eviction {
                    let row = tables
                        .get(&sid)?
                        .ok_or_else(|| rejected("eviction SID missing"))?;
                    tables.remove(&row)?;
                }
                tables.insert(&session, &bytes)?;
            }
            transaction.commit().map_err(commit_error)
        })
        .await
    }
    async fn compare_replace(
        &self,
        expected: ConsoleSession,
        session: ConsoleSession,
    ) -> Result<(), SessionStoreError> {
        let bytes = session.encode()?;
        let expected_bytes = expected.encode()?;
        if session.sid() != expected.sid()
            || session.account() != expected.account()
            || session.issued_at() != expected.issued_at()
        {
            return Err(SessionStoreError::Conflict);
        }
        self.run(move |db| {
            let transaction = db.begin_write().map_err(storage_error)?;
            {
                let mut tables = Tables::open(&transaction)?;
                let matches = tables
                    .rows
                    .get(expected.sid())
                    .map_err(storage_error)?
                    .is_some_and(|row| row.value() == expected_bytes);
                if !matches {
                    return Err(SessionStoreError::Conflict);
                }
                tables.remove(&expected)?;
                tables.insert(&session, &bytes)?;
            }
            transaction.commit().map_err(commit_error)
        })
        .await
    }
    async fn delete(
        &self,
        sid: &str,
        expected: Option<ConsoleSession>,
    ) -> Result<(), SessionStoreError> {
        let sid = sid.to_owned();
        let expected = expected
            .map(|row| Ok::<_, SessionStoreError>((row.sid().to_owned(), row.encode()?)))
            .transpose()?;
        self.run(move |db| {
            let transaction = db.begin_write().map_err(storage_error)?;
            {
                let mut tables = Tables::open(&transaction)?;
                if let Some((expected_sid, bytes)) = expected
                    && (expected_sid != sid
                        || tables
                            .rows
                            .get(sid.as_str())
                            .map_err(storage_error)?
                            .is_none_or(|row| row.value() != bytes))
                {
                    return Err(SessionStoreError::Conflict);
                }
                if let Some(row) = tables.get(&sid)? {
                    tables.remove(&row)?;
                }
            }
            transaction.commit().map_err(commit_error)
        })
        .await
    }
    async fn list(
        &self,
        after: Option<&str>,
        limits: SessionPageLimits,
    ) -> Result<SessionStorePage, SessionStoreError> {
        if limits.rows == 0 || limits.bytes == 0 {
            return Err(rejected("zero session page budget"));
        }
        let after = after.map(str::to_owned);
        if let Some(sid) = &after
            && !xolotl_types::path::is_simple_id_segment(sid)
        {
            return Err(rejected("invalid session cursor"));
        }
        self.run(move |db| {
            use std::ops::Bound::{Excluded, Unbounded};
            let transaction = db.begin_read().map_err(storage_error)?;
            let rows = transaction.open_table(ROWS).map_err(storage_error)?;
            let lower = after.as_deref().map_or(Unbounded, Excluded);
            let mut entries = Vec::new();
            let mut bytes = 0;
            let mut last = None;
            for entry in rows
                .range::<&str>((lower, Unbounded))
                .map_err(storage_error)?
            {
                let (sid, encoded) = entry.map_err(storage_error)?;
                let size = sid.value().len() + encoded.value().len();
                if entries.len() == limits.rows || size > limits.bytes.saturating_sub(bytes) {
                    if last.is_none() {
                        return Err(rejected("session row exceeds page budget"));
                    }
                    return Ok(SessionStorePage {
                        entries,
                        next: last,
                    });
                }
                bytes += size;
                last = Some(sid.value().to_owned());
                entries.push(ConsoleSession::decode(sid.value(), encoded.value())?);
            }
            Ok(SessionStorePage {
                entries,
                next: None,
            })
        })
        .await
    }
    async fn revoke_account(
        &self,
        authority: &str,
        account: &str,
    ) -> Result<usize, SessionStoreError> {
        let account = account_key(authority, account);
        self.run(move |db| {
            let transaction = db.begin_write().map_err(storage_error)?;
            let mut deleted = 0;
            {
                let mut tables = Tables::open(&transaction)?;
                let mut bytes = 0;
                while deleted < MAINTENANCE_ROWS {
                    let Some(sid) = tables.oldest_account(&account)? else {
                        break;
                    };
                    let size = tables.encoded_size(&sid)?;
                    if size > MAINTENANCE_BYTES - bytes {
                        break;
                    }
                    let row = tables
                        .get(&sid)?
                        .ok_or_else(|| rejected("account SID missing"))?;
                    tables.remove(&row)?;
                    bytes += size;
                    deleted += 1;
                }
            }
            transaction.commit().map_err(commit_error)?;
            Ok(deleted)
        })
        .await
    }
    async fn maintain(&self, now: i64) -> Result<usize, SessionStoreError> {
        self.run(move |db| {
            let transaction = db.begin_write().map_err(storage_error)?;
            let mut deleted = 0;
            {
                let mut tables = Tables::open(&transaction)?;
                let mut bytes = 0;
                while deleted < MAINTENANCE_ROWS {
                    let first = tables
                        .expiry
                        .first()
                        .map_err(storage_error)?
                        .map(|(key, sid)| (key.value().to_owned(), sid.value().to_owned()));
                    let Some((key, sid)) = first else {
                        break;
                    };
                    if key.as_str() > ordered_key(now, "~").as_str() {
                        break;
                    }
                    let size = tables.encoded_size(&sid)?;
                    if size > MAINTENANCE_BYTES - bytes {
                        break;
                    }
                    let row = tables
                        .get(&sid)?
                        .ok_or_else(|| rejected("expiry SID missing"))?;
                    tables.remove(&row)?;
                    bytes += size;
                    deleted += 1;
                }
            }
            transaction.commit().map_err(commit_error)?;
            Ok(deleted)
        })
        .await
    }
}

fn ordered_key(timestamp: i64, sid: &str) -> String {
    format!("{:016x}/{sid}", (timestamp as u64) ^ (1_u64 << 63))
}
fn account_key(authority: &str, account: &str) -> String {
    format!("{authority}/{account}/")
}
fn account_issuance_key(session: &ConsoleSession) -> String {
    format!(
        "{}{}",
        account_key(session.account().0, session.account().1),
        ordered_key(session.issued_at(), session.sid())
    )
}
fn counter(table: &Table<'_, &str, u64>, key: &str) -> Result<u64, SessionStoreError> {
    table
        .get(key)
        .map_err(storage_error)?
        .map(|row| row.value())
        .ok_or_else(|| rejected("session metadata missing"))
}
fn storage_error(error: impl std::fmt::Display) -> SessionStoreError {
    SessionStoreError::Storage(error.to_string())
}
fn commit_error(error: impl std::fmt::Display) -> SessionStoreError {
    SessionStoreError::Unknown(error.to_string())
}
fn rejected(reason: &str) -> SessionStoreError {
    SessionStoreError::Rejected(reason.into())
}

#[cfg(test)]
mod tests;
