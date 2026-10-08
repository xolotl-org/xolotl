//! Atomic, durable two-way identity directory.

use crate::database::Database;
use crate::schema::{
    IDENTITY_HIGH_WATER, IDENTITY_META_TABLE, IDENTITY_PATH_TABLE, IDENTITY_REF_TABLE,
};
use redb::{Durability, ReadableTable, WriteTransaction};
use std::sync::Arc;
use xolotl_kernel::{IdentityDirectory, IdentityError, identity::validate_path};
use xolotl_types::{IdentityRef, Path};

/// Redb identity namespace. Clones and independently created adapters over the
/// same database serialize allocations in one transaction.
#[derive(Clone)]
pub struct RedbIdentityDirectory {
    db: Arc<Database>,
}

impl RedbIdentityDirectory {
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

fn storage(error: impl std::fmt::Display) -> IdentityError {
    IdentityError::Storage(error.to_string())
}

fn high_water(meta: &impl ReadableTable<&'static str, u64>) -> Result<u64, IdentityError> {
    meta.get(IDENTITY_HIGH_WATER)
        .map_err(storage)?
        .map(|value| value.value())
        .ok_or(IdentityError::Corrupt("identity high water is missing"))
}

/// Called during database open before any adapter can issue or verify identities.
pub(crate) fn validate_in_txn(txn: &WriteTransaction) -> Result<(), IdentityError> {
    let meta = txn.open_table(IDENTITY_META_TABLE).map_err(storage)?;
    let high = high_water(&meta)?;
    let paths = txn.open_table(IDENTITY_PATH_TABLE).map_err(storage)?;
    let refs = txn.open_table(IDENTITY_REF_TABLE).map_err(storage)?;
    validate_entries(high, &paths, &refs)
}

fn validate_entries<P, R>(high: u64, paths: &P, refs: &R) -> Result<(), IdentityError>
where
    P: ReadableTable<&'static str, u64>,
    R: ReadableTable<u64, &'static str>,
{
    for entry in paths.iter().map_err(storage)? {
        let (path, identity) = entry.map_err(storage)?;
        let text = path.value();
        let parsed =
            Path::parse(text).map_err(|_error| IdentityError::Corrupt("invalid identity path"))?;
        validate_path(&parsed).map_err(|_error| IdentityError::Corrupt("invalid identity path"))?;
        if parsed.to_string() != text {
            return Err(IdentityError::Corrupt("identity path is not canonical"));
        }
        let identity = identity.value();
        if identity == 0 || identity > high {
            return Err(IdentityError::Corrupt("identity number exceeds high water"));
        }
        let matching = refs
            .get(identity)
            .map_err(storage)?
            .is_some_and(|reverse| reverse.value() == text);
        if !matching {
            return Err(IdentityError::Corrupt("identity reverse entry is missing"));
        }
    }
    for entry in refs.iter().map_err(storage)? {
        let (identity, path) = entry.map_err(storage)?;
        let identity = identity.value();
        if identity == 0 || identity > high {
            return Err(IdentityError::Corrupt(
                "reverse identity exceeds high water",
            ));
        }
        let matching = paths
            .get(path.value())
            .map_err(storage)?
            .is_some_and(|forward| forward.value() == identity);
        if !matching {
            return Err(IdentityError::Corrupt("identity forward entry is missing"));
        }
    }
    Ok(())
}

impl IdentityDirectory for RedbIdentityDirectory {
    fn resolve_or_register(&self, path: &Path) -> Result<IdentityRef, IdentityError> {
        validate_path(path)?;
        if let Some(identity) = self.lookup(path)? {
            return Ok(identity);
        }
        let text = path.to_string();
        let mut txn = self.db.begin_write().map_err(storage)?;
        txn.set_durability(Durability::Immediate).map_err(storage)?;
        let high = high_water(&txn.open_table(IDENTITY_META_TABLE).map_err(storage)?)?;
        let existing = txn
            .open_table(IDENTITY_PATH_TABLE)
            .map_err(storage)?
            .get(text.as_str())
            .map_err(storage)?
            .map(|entry| entry.value());
        if let Some(id) = existing {
            if id == 0 || id > high {
                return Err(IdentityError::Corrupt(
                    "forward identity exceeds high water",
                ));
            }
            let matching = txn
                .open_table(IDENTITY_REF_TABLE)
                .map_err(storage)?
                .get(id)
                .map_err(storage)?
                .is_some_and(|entry| entry.value() == text);
            if !matching {
                return Err(IdentityError::Corrupt(
                    "forward identity has no reverse entry",
                ));
            }
            return Ok(IdentityRef::new(id));
        }
        let next = high.checked_add(1).ok_or(IdentityError::Exhausted)?;
        if txn
            .open_table(IDENTITY_REF_TABLE)
            .map_err(storage)?
            .get(next)
            .map_err(storage)?
            .is_some()
        {
            return Err(IdentityError::Corrupt(
                "next identity number is already present",
            ));
        }
        txn.open_table(IDENTITY_PATH_TABLE)
            .map_err(storage)?
            .insert(text.as_str(), next)
            .map_err(storage)?;
        txn.open_table(IDENTITY_REF_TABLE)
            .map_err(storage)?
            .insert(next, text.as_str())
            .map_err(storage)?;
        txn.open_table(IDENTITY_META_TABLE)
            .map_err(storage)?
            .insert(IDENTITY_HIGH_WATER, next)
            .map_err(storage)?;
        txn.commit().map_err(storage)?;
        Ok(IdentityRef::new(next))
    }

    fn lookup(&self, path: &Path) -> Result<Option<IdentityRef>, IdentityError> {
        validate_path(path)?;
        let text = path.to_string();
        let txn = self.db.begin_read().map_err(storage)?;
        let high = txn
            .open_table(IDENTITY_META_TABLE)
            .map_err(storage)?
            .get(IDENTITY_HIGH_WATER)
            .map_err(storage)?
            .ok_or(IdentityError::Corrupt("identity high water is missing"))?
            .value();
        let id = txn
            .open_table(IDENTITY_PATH_TABLE)
            .map_err(storage)?
            .get(text.as_str())
            .map_err(storage)?
            .map(|entry| entry.value());
        let Some(id) = id else {
            return Ok(None);
        };
        if id == 0 || id > high {
            return Err(IdentityError::Corrupt(
                "forward identity exceeds high water",
            ));
        }
        let matching = txn
            .open_table(IDENTITY_REF_TABLE)
            .map_err(storage)?
            .get(id)
            .map_err(storage)?
            .is_some_and(|entry| entry.value() == text);
        if !matching {
            return Err(IdentityError::Corrupt(
                "forward identity has no reverse entry",
            ));
        }
        Ok(Some(IdentityRef::new(id)))
    }

    fn path_for(&self, identity: IdentityRef) -> Result<Option<Path>, IdentityError> {
        if identity == IdentityRef::ROOT {
            return Ok(None);
        }
        let txn = self.db.begin_read().map_err(storage)?;
        let high = txn
            .open_table(IDENTITY_META_TABLE)
            .map_err(storage)?
            .get(IDENTITY_HIGH_WATER)
            .map_err(storage)?
            .ok_or(IdentityError::Corrupt("identity high water is missing"))?
            .value();
        let text = txn
            .open_table(IDENTITY_REF_TABLE)
            .map_err(storage)?
            .get(identity.get())
            .map_err(storage)?
            .map(|entry| entry.value().to_owned());
        let Some(text) = text else {
            return Ok(None);
        };
        if identity.get() > high {
            return Err(IdentityError::Corrupt(
                "reverse identity exceeds high water",
            ));
        }
        let path =
            Path::parse(&text).map_err(|_error| IdentityError::Corrupt("invalid reverse path"))?;
        validate_path(&path).map_err(|_error| IdentityError::Corrupt("invalid reverse path"))?;
        if path.to_string() != text {
            return Err(IdentityError::Corrupt("reverse path is not canonical"));
        }
        let matching = txn
            .open_table(IDENTITY_PATH_TABLE)
            .map_err(storage)?
            .get(text.as_str())
            .map_err(storage)?
            .is_some_and(|entry| entry.value() == identity.get());
        if !matching {
            return Err(IdentityError::Corrupt(
                "reverse identity has no forward entry",
            ));
        }
        Ok(Some(path))
    }

    fn verify(&self, identity: IdentityRef) -> Result<(), IdentityError> {
        if identity == IdentityRef::ROOT {
            return Ok(());
        }
        // path_for checks the reverse row, forward row, canonical path and
        // high water within one read transaction.
        self.path_for(identity)?
            .map(|_| ())
            .ok_or(IdentityError::Missing(identity))
    }

    fn validate(&self) -> Result<(), IdentityError> {
        let txn = self.db.begin_read().map_err(storage)?;
        let meta = txn.open_table(IDENTITY_META_TABLE).map_err(storage)?;
        let high = high_water(&meta)?;
        let paths = txn.open_table(IDENTITY_PATH_TABLE).map_err(storage)?;
        let refs = txn.open_table(IDENTITY_REF_TABLE).map_err(storage)?;
        validate_entries(high, &paths, &refs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use std::collections::BTreeSet;
    use std::sync::Barrier;
    use xolotl_kernel::IdentityRegistry;

    #[test]
    fn registrations_are_distinct_and_survive_reopen() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("identity.redb");
        let a = Path::parse("identity://accounts/a")?;
        let b = Path::parse("identity://accounts/b")?;
        let first;
        {
            let store = crate::RedbStore::open(&file)?;
            let identities = store.identity_directory();
            first = identities.resolve_or_register(&a)?;
            ensure!(first != identities.resolve_or_register(&b)?);
            ensure!(identities.resolve_or_register(&a)? == first);
        }
        let store = crate::RedbStore::open(&file)?;
        let identities = store.identity_directory();
        ensure!(identities.lookup(&a)? == Some(first));
        ensure!(identities.path_for(first)? == Some(a));
        ensure!(
            identities
                .lookup(&Path::parse("identity://unknown")?)?
                .is_none()
        );
        identities.validate()?;
        Ok(())
    }

    #[test]
    fn missing_reverse_entry_rejects_reopen_and_lookup() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("identity.redb");
        let store = crate::RedbStore::open(&file)?;
        let identities = store.identity_directory();
        let path = Path::parse("identity://accounts/a")?;
        let identity = identities.resolve_or_register(&path)?;
        {
            let txn = store.db.begin_write()?;
            txn.open_table(IDENTITY_REF_TABLE)?.remove(identity.get())?;
            txn.commit()?;
        }
        ensure!(matches!(
            identities.lookup(&path),
            Err(IdentityError::Corrupt(_))
        ));
        drop(identities);
        drop(store);
        ensure!(crate::RedbStore::open(&file).is_err());
        Ok(())
    }

    #[test]
    fn validation_and_missing_recovery_identity_do_not_write() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = crate::RedbStore::open(dir.path().join("identity.redb"))?;
        let identities = IdentityRegistry::new(Arc::new(store.identity_directory()));
        let path = Path::parse("identity://accounts/missing")?;
        // A read-only validation must remain available while another writer
        // holds the database's exclusive write transaction.
        let writer = store.db.begin_write()?;
        identities.validate()?;
        ensure!(matches!(
            identities.verify(IdentityRef::new(1)),
            Err(IdentityError::Missing(_))
        ));
        ensure!(identities.lookup(&path)?.is_none());
        drop(writer);
        ensure!(identities.resolve_or_register(&path)? == IdentityRef::new(1));
        Ok(())
    }

    #[test]
    fn concurrent_adapters_serialize_shared_and_distinct_registrations() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(crate::RedbStore::open(dir.path().join("identity.redb"))?);
        let start = Arc::new(Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|index| {
                let store = store.clone();
                let start = start.clone();
                std::thread::spawn(move || -> Result<_, IdentityError> {
                    let identities = store.identity_directory();
                    let shared = Path::parse("identity://accounts/shared")
                        .map_err(|_invalid| IdentityError::InvalidPath)?;
                    let own = Path::parse(&format!("identity://accounts/{index}"))
                        .map_err(|_invalid| IdentityError::InvalidPath)?;
                    start.wait();
                    Ok((
                        identities.resolve_or_register(&shared)?,
                        identities.resolve_or_register(&own)?,
                    ))
                })
            })
            .collect();
        let issued: Vec<_> = workers
            .into_iter()
            .map(|worker| -> anyhow::Result<_> {
                let registration = worker
                    .join()
                    .map_err(|_panic| anyhow::anyhow!("identity worker panicked"))?;
                Ok(registration?)
            })
            .collect::<anyhow::Result<_>>()?;
        let shared = issued[0].0;
        ensure!(issued.iter().all(|(identity, _)| *identity == shared));
        ensure!(
            issued
                .iter()
                .map(|(_, identity)| *identity)
                .collect::<BTreeSet<_>>()
                .len()
                == 8
        );
        store.identity_directory().validate()?;
        Ok(())
    }
}
