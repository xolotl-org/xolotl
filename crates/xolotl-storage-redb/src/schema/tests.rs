use super::*;
use crate::RedbStore;
use anyhow::ensure;
use redb::ReadableDatabase;

#[test]
fn reopening_an_empty_store_does_not_recreate_missing_metadata() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    for which in 0..4 {
        let path = directory.path().join(format!("missing-key-{which}.redb"));
        {
            let store = RedbStore::open(&path)?;
            let txn = store.db.begin_write()?;
            match which {
                0 => {
                    drop(
                        txn.open_table(STATE_META_TABLE)?
                            .remove(LAST_HISTORY_MILLIS)?,
                    );
                }
                1 => {
                    drop(txn.open_table(FACT_META_TABLE)?.remove(NEXT_FACT_CURSOR)?);
                }
                2 => {
                    drop(
                        txn.open_table(EXECUTION_ID_META_TABLE)?
                            .remove(EXECUTION_HIGH_WATER)?,
                    );
                }
                _ => {
                    drop(
                        txn.open_table(CHECKPOINT_META_TABLE)?
                            .remove(CHECKPOINT_HIGH_WATER)?,
                    );
                }
            }
            txn.commit()?;
        }
        match RedbStore::open(&path) {
            Ok(_store) => anyhow::bail!("missing metadata was silently recreated"),
            Err(error) => ensure!(error.to_string().contains("metadata missing")),
        }
        let db = Database::create(&path)?;
        let txn = db.begin_read()?;
        let remains_absent = match which {
            0 => txn
                .open_table(STATE_META_TABLE)?
                .get(LAST_HISTORY_MILLIS)?
                .is_none(),
            1 => txn
                .open_table(FACT_META_TABLE)?
                .get(NEXT_FACT_CURSOR)?
                .is_none(),
            2 => txn
                .open_table(EXECUTION_ID_META_TABLE)?
                .get(EXECUTION_HIGH_WATER)?
                .is_none(),
            _ => txn
                .open_table(CHECKPOINT_META_TABLE)?
                .get(CHECKPOINT_HIGH_WATER)?
                .is_none(),
        };
        ensure!(remains_absent);
    }
    Ok(())
}

#[test]
fn a_missing_table_is_rejected_without_recreating_it() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("missing-table.redb");
    {
        let store = RedbStore::open(&path)?;
        let txn = store.db.begin_write()?;
        ensure!(txn.delete_table(FACT_PROCESS_INDEX_TABLE)?);
        txn.commit()?;
    }
    ensure!(RedbStore::open(&path).is_err());
    let db = Database::create(&path)?;
    let txn = db.begin_read()?;
    ensure!(matches!(
        txn.open_table(FACT_PROCESS_INDEX_TABLE),
        Err(redb::TableError::TableDoesNotExist(_))
    ));
    Ok(())
}

#[test]
fn checkpoint_empty_zero_and_maximum_have_distinct_encodings() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("checkpoint-range.redb");
    {
        let store = RedbStore::open(&path)?;
        let txn = store.db.begin_read()?;
        ensure!(
            txn.open_table(CHECKPOINT_META_TABLE)?
                .get(CHECKPOINT_HIGH_WATER)?
                .map(|value| value.value())
                == Some(0)
        );
    }
    for encoded in [1, u128::from(u64::MAX) + 1] {
        {
            let store = RedbStore::open(&path)?;
            let txn = store.db.begin_write()?;
            txn.open_table(CHECKPOINT_META_TABLE)?
                .insert(CHECKPOINT_HIGH_WATER, encoded)?;
            txn.commit()?;
        }
        let store = RedbStore::open(&path)?;
        let txn = store.db.begin_read()?;
        ensure!(
            txn.open_table(CHECKPOINT_META_TABLE)?
                .get(CHECKPOINT_HIGH_WATER)?
                .map(|value| value.value())
                == Some(encoded)
        );
    }
    {
        let store = RedbStore::open(&path)?;
        let txn = store.db.begin_write()?;
        txn.open_table(CHECKPOINT_META_TABLE)?
            .insert(CHECKPOINT_HIGH_WATER, u128::MAX)?;
        txn.commit()?;
    }
    ensure!(RedbStore::open(&path).is_err());
    Ok(())
}
