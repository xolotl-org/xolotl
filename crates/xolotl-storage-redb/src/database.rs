use std::ops::{Deref, DerefMut};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use redb::{CommitError, ReadTransaction, ReadableDatabase, StorageError, TransactionError};

use crate::{fact::FactNotifications, state::Publication};

pub(crate) struct Database {
    inner: redb::Database,
    recovery: Arc<Recovery>,
}

struct Recovery {
    required: AtomicBool,
    notified: AtomicBool,
    publication: Arc<Publication>,
    facts: OnceLock<Arc<FactNotifications>>,
}

impl Recovery {
    fn notify(&self) {
        if self.required.load(Ordering::Acquire) && !self.notified.swap(true, Ordering::AcqRel) {
            let invalidation = self.publication.subscriptions().invalidate_all();
            if let Some(facts) = self.facts.get()
                && let Err(payload) = catch_unwind(AssertUnwindSafe(|| facts.close()))
                && let Err(secondary) = catch_unwind(AssertUnwindSafe(|| drop(payload)))
            {
                let _secondary = std::mem::ManuallyDrop::new(secondary);
            }
            invalidation.finish();
        }
    }
}

impl Database {
    pub(crate) fn new(inner: redb::Database) -> Self {
        Self {
            inner,
            recovery: Arc::new(Recovery {
                required: AtomicBool::new(false),
                notified: AtomicBool::new(false),
                publication: Arc::default(),
                facts: OnceLock::new(),
            }),
        }
    }

    pub(crate) fn requires_reopen(&self) -> bool {
        self.recovery.required.load(Ordering::Acquire)
    }

    pub(crate) fn ensure_open(&self) -> Result<(), StorageError> {
        if self.requires_reopen() {
            Err(StorageError::DatabaseClosed)
        } else {
            Ok(())
        }
    }

    pub(crate) fn publication(&self) -> Arc<Publication> {
        Arc::clone(&self.recovery.publication)
    }

    pub(crate) fn fact_notifications(&self) -> Arc<FactNotifications> {
        Arc::clone(
            self.recovery
                .facts
                .get_or_init(|| Arc::new(FactNotifications::new())),
        )
    }

    pub(crate) fn begin_read(&self) -> Result<ReadTransaction, TransactionError> {
        self.ensure_open()?;
        let transaction = self.inner.begin_read()?;
        self.ensure_open()?;
        Ok(transaction)
    }

    pub(crate) fn begin_write(&self) -> Result<WriteTransaction, TransactionError> {
        self.ensure_open()?;
        let inner = self.inner.begin_write()?;
        self.ensure_open()?;
        Ok(WriteTransaction {
            inner,
            recovery: Arc::clone(&self.recovery),
            deferred: false,
        })
    }
}

pub(crate) struct WriteTransaction {
    inner: redb::WriteTransaction,
    recovery: Arc<Recovery>,
    deferred: bool,
}

impl Deref for WriteTransaction {
    type Target = redb::WriteTransaction;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for WriteTransaction {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub(crate) struct RecoveryNotification(Arc<Recovery>);

impl Drop for RecoveryNotification {
    fn drop(&mut self) {
        self.0.notify();
    }
}

struct CommitGuard<'recovery> {
    recovery: &'recovery Recovery,
    completed: bool,
    deferred: bool,
}

impl Drop for CommitGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.recovery.required.store(true, Ordering::Release);
        }
        if !self.deferred {
            self.recovery.notify();
        }
    }
}

impl WriteTransaction {
    pub(crate) fn defer_notifications(&mut self) -> RecoveryNotification {
        self.deferred = true;
        RecoveryNotification(Arc::clone(&self.recovery))
    }

    pub(crate) fn commit(self) -> Result<(), CommitError> {
        let Self {
            inner,
            recovery,
            deferred,
        } = self;
        if recovery.required.load(Ordering::Acquire) {
            return Err(CommitError::TransactionPoisoned);
        }
        let mut guard = CommitGuard {
            recovery: &recovery,
            completed: false,
            deferred,
        };
        let result = inner.commit();
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, CommitError::TransactionPoisoned))
        {
            recovery.required.store(true, Ordering::Release);
        }
        guard.completed = true;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use redb::TableDefinition;
    use xolotl_state::StateWatchError;
    use xolotl_types::Path;

    #[expect(
        clippy::panic,
        reason = "fault a table mutation before commit to establish rollback"
    )]
    fn poison_predicate() -> bool {
        panic!("injected table mutation panic")
    }

    #[test]
    fn staged_write_cannot_commit_after_shared_recovery() -> anyhow::Result<()> {
        let db = Database::new(
            redb::Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?,
        );
        let table = TableDefinition::<u64, u64>::new("staged");
        let transaction = db.begin_write()?;
        transaction.open_table(table)?;
        transaction.commit()?;
        let transaction = db.begin_write()?;
        transaction.open_table(table)?.insert(1, 2)?;
        db.recovery.required.store(true, Ordering::Release);
        ensure!(matches!(
            transaction.commit(),
            Err(CommitError::TransactionPoisoned)
        ));
        ensure!(db.begin_read().is_err());
        ensure!(db.inner.begin_read()?.open_table(table)?.get(1)?.is_none());
        Ok(())
    }

    #[test]
    fn poisoned_transaction_rolls_back_without_fencing_the_database() -> anyhow::Result<()> {
        let db = Database::new(
            redb::Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?,
        );
        let definition: TableDefinition<u64, u64> = TableDefinition::new("poisoned_rollback");
        let transaction = db.begin_write()?;
        transaction.open_table(definition)?.insert(1, 1)?;
        transaction.commit()?;
        let mut stream = db.publication().subscriptions().subscribe(
            Path::parse("state://poison/**")?,
            std::num::NonZeroUsize::MIN,
        )?;
        let transaction = db.begin_write()?;
        {
            let mut table = transaction.open_table(definition)?;
            table.insert(2, 2)?;
            let panic = catch_unwind(AssertUnwindSafe(|| -> Result<(), redb::StorageError> {
                let mut extracted = table.extract_if(|_, _| poison_predicate())?;
                let _entry = extracted.next();
                Ok(())
            }));
            ensure!(panic.is_err());
        }
        ensure!(matches!(
            transaction.commit(),
            Err(CommitError::TransactionPoisoned)
        ));
        ensure!(!db.requires_reopen());
        ensure!(matches!(stream.try_recv(), Err(StateWatchError::Empty)));
        let snapshot = db.begin_read()?;
        let table = snapshot.open_table(definition)?;
        ensure!(table.get(1)?.is_some());
        ensure!(table.get(2)?.is_none());
        db.begin_write()?.commit()?;
        Ok(())
    }
}
