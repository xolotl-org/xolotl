//! One lock is the transaction boundary for rows, counters and all indexes.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound::{Excluded, Unbounded};

type Issuance = (i64, String);
type Account = (String, String);

#[derive(Default)]
struct Rows {
    sid: BTreeMap<String, (ConsoleSession, usize)>,
    accounts: BTreeMap<Account, BTreeSet<Issuance>>,
    issuance: BTreeSet<Issuance>,
    expiry: BTreeSet<Issuance>,
}

impl Rows {
    fn remove(&mut self, sid: &str) {
        if let Some((session, _)) = self.sid.remove(sid) {
            let account = (
                session.account().0.to_owned(),
                session.account().1.to_owned(),
            );
            let issuance = (session.issued_at(), sid.to_owned());
            if let Some(entries) = self.accounts.get_mut(&account) {
                entries.remove(&issuance);
                if entries.is_empty() {
                    self.accounts.remove(&account);
                }
            }
            self.issuance.remove(&issuance);
            self.expiry.remove(&(session.expires_at(), sid.to_owned()));
        }
    }
    fn insert(&mut self, session: ConsoleSession, bytes: usize) {
        let sid = session.sid().to_owned();
        let issuance = (session.issued_at(), sid.clone());
        let account = (
            session.account().0.to_owned(),
            session.account().1.to_owned(),
        );
        self.accounts
            .entry(account)
            .or_default()
            .insert(issuance.clone());
        self.issuance.insert(issuance);
        self.expiry.insert((session.expires_at(), sid.clone()));
        self.sid.insert(sid, (session, bytes));
    }
}

/// Shared in-memory storage domain with immutable capacities. Clones share rows,
/// indexes and the single transaction lock; constructing another store creates
/// a distinct domain, never a continuation of this one.
#[derive(Clone)]
pub struct MemoryConsoleSessionStore {
    policy: ConsoleSessionPolicy,
    rows: Arc<Mutex<Rows>>,
}

impl MemoryConsoleSessionStore {
    /// Construct an empty domain with the supplied immutable policy.
    pub fn new(policy: ConsoleSessionPolicy) -> Self {
        Self {
            policy,
            rows: Arc::new(Mutex::new(Rows::default())),
        }
    }
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Rows>, SessionStoreError> {
        self.rows
            .lock()
            .map_err(|_poisoned| SessionStoreError::Storage("session lock poisoned".into()))
    }
}

#[async_trait]
impl ConsoleSessionStore for MemoryConsoleSessionStore {
    fn policy(&self) -> ConsoleSessionPolicy {
        self.policy
    }
    async fn get(&self, sid: &str) -> Result<Option<ConsoleSession>, SessionStoreError> {
        Ok(self.lock()?.sid.get(sid).map(|(row, _)| row.clone()))
    }
    async fn create(&self, session: ConsoleSession) -> Result<(), SessionStoreError> {
        let mut rows = self.lock()?;
        if rows.sid.contains_key(session.sid()) {
            return Err(SessionStoreError::Conflict);
        }
        let bytes = session.encode()?.len() + session.sid().len();
        let account = (
            session.account().0.to_owned(),
            session.account().1.to_owned(),
        );
        let eviction = rows
            .accounts
            .get(&account)
            .filter(|entries| entries.len() >= self.policy.per_account())
            .and_then(|entries| entries.first())
            .map(|(_, sid)| sid.clone());
        if eviction.is_none() && rows.sid.len() >= self.policy.domain() {
            return Err(SessionStoreError::Rejected(
                "session domain capacity exhausted".into(),
            ));
        }
        if let Some(sid) = eviction {
            rows.remove(&sid);
        }
        rows.insert(session, bytes);
        Ok(())
    }
    async fn compare_replace(
        &self,
        expected: ConsoleSession,
        session: ConsoleSession,
    ) -> Result<(), SessionStoreError> {
        let bytes = session.encode()?.len() + session.sid().len();
        let mut rows = self.lock()?;
        if expected.sid() != session.sid()
            || expected.account() != session.account()
            || expected.issued_at() != session.issued_at()
            || rows
                .sid
                .get(expected.sid())
                .is_none_or(|(row, _)| !row.same(&expected))
        {
            return Err(SessionStoreError::Conflict);
        }
        rows.remove(session.sid());
        rows.insert(session, bytes);
        Ok(())
    }
    async fn delete(
        &self,
        sid: &str,
        expected: Option<ConsoleSession>,
    ) -> Result<(), SessionStoreError> {
        let mut rows = self.lock()?;
        if let Some(expected) = expected
            && (expected.sid() != sid
                || rows
                    .sid
                    .get(sid)
                    .is_none_or(|(row, _)| !row.same(&expected)))
        {
            return Err(SessionStoreError::Conflict);
        }
        rows.remove(sid);
        Ok(())
    }
    async fn list(
        &self,
        after: Option<&str>,
        limits: SessionPageLimits,
    ) -> Result<SessionStorePage, SessionStoreError> {
        if limits.rows == 0 || limits.bytes == 0 {
            return Err(SessionStoreError::Rejected("zero page budget".into()));
        }
        if let Some(sid) = after {
            crate::auth::validate_session_id(sid).map_err(|_invalid_sid| {
                SessionStoreError::Rejected("invalid session cursor".into())
            })?;
        }
        let rows = self.lock()?;
        let start = after.map_or(Unbounded, |sid| Excluded(sid.to_owned()));
        let mut entries = Vec::new();
        let mut bytes = 0usize;
        let mut last = None;
        for (sid, (session, size)) in rows.sid.range((start, Unbounded)) {
            if entries.len() == limits.rows || *size > limits.bytes.saturating_sub(bytes) {
                if last.is_none() {
                    return Err(SessionStoreError::Rejected(
                        "session row exceeds page budget".into(),
                    ));
                }
                return Ok(SessionStorePage {
                    entries,
                    next: last,
                });
            }
            bytes += size;
            last = Some(sid.clone());
            entries.push(session.clone());
        }
        Ok(SessionStorePage {
            entries,
            next: None,
        })
    }
    async fn revoke_account(
        &self,
        authority: &str,
        account: &str,
    ) -> Result<usize, SessionStoreError> {
        let mut rows = self.lock()?;
        let account = (authority.to_owned(), account.to_owned());
        let mut deleted = 0;
        let mut bytes = 0;
        while deleted < MAINTENANCE_ROWS {
            let Some(sid) = rows
                .accounts
                .get(&account)
                .and_then(|entries| entries.first())
                .map(|(_, sid)| sid.clone())
            else {
                break;
            };
            let size = rows.sid[&sid].1;
            if size > MAINTENANCE_BYTES - bytes {
                break;
            }
            rows.remove(&sid);
            bytes += size;
            deleted += 1;
        }
        Ok(deleted)
    }
    async fn maintain(&self, now: i64) -> Result<usize, SessionStoreError> {
        let mut rows = self.lock()?;
        let mut deleted = 0;
        let mut bytes = 0;
        while deleted < MAINTENANCE_ROWS {
            let Some((expiry, sid)) = rows.expiry.first().cloned() else {
                break;
            };
            if expiry > now {
                break;
            }
            let size = rows.sid[&sid].1;
            if size > MAINTENANCE_BYTES - bytes {
                break;
            }
            rows.remove(&sid);
            bytes += size;
            deleted += 1;
        }
        Ok(deleted)
    }
}
