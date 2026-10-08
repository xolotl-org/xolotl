use super::*;
use crate::{RedbHistory, RedbStore};
use anyhow::{Context, ensure};
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
                        txn.open_table(IDENTITY_META_TABLE)?
                            .remove(IDENTITY_HIGH_WATER)?,
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
                .open_table(IDENTITY_META_TABLE)?
                .get(IDENTITY_HIGH_WATER)?
                .is_none(),
        };
        ensure!(remains_absent);
    }
    Ok(())
}

#[test]
fn history_mode_is_fixed_and_missing_mode_is_not_inferred() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    for mode in [RedbHistory::CurrentOnly, RedbHistory::Full] {
        let path = directory.path().join(format!("history-{mode:?}.redb"));
        {
            let store = RedbStore::open_with_history(&path, mode)?;
            let txn = store.db.begin_read()?;
            ensure!(
                txn.open_table(STATE_META_TABLE)?
                    .get(STATE_HISTORY_MODE)?
                    .map(|value| value.value())
                    == Some(mode.stored_value())
            );
        }
        let other = match mode {
            RedbHistory::CurrentOnly => RedbHistory::Full,
            RedbHistory::Full => RedbHistory::CurrentOnly,
        };
        ensure!(RedbStore::open_with_history(&path, other).is_err());
        RedbStore::open_with_history(&path, mode)?;
        {
            let db = Database::create(&path)?;
            let txn = db.begin_write()?;
            {
                let mut meta = txn.open_table(STATE_META_TABLE)?;
                drop(meta.remove(STATE_HISTORY_MODE)?);
            }
            txn.commit()?;
        }
        for requested in [RedbHistory::CurrentOnly, RedbHistory::Full] {
            let failure = RedbStore::open_with_history(&path, requested)
                .err()
                .context("database with missing mode was accepted")?;
            ensure!(failure.to_string().contains("mode metadata missing"));
        }
    }
    Ok(())
}

#[test]
fn legacy_full_history_that_journaled_vault_paths_is_rejected() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("old-full.redb");
    {
        let store = RedbStore::open_with_history(&path, RedbHistory::Full)?;
        let txn = store.db.begin_write()?;
        txn.open_table(STATE_META_TABLE)?
            .insert(STATE_HISTORY_MODE, 1)?;
        txn.commit()?;
    }
    let failure = RedbStore::open_with_history(&path, RedbHistory::Full)
        .err()
        .context("old Full history was accepted under the protected vault rule")?;
    ensure!(failure.to_string().contains("history mode does not match"));
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
fn state_list_id_high_water_cannot_fall_behind_items() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source-sink-high-water.redb");
    {
        let store = RedbStore::open(&path)?;
        let txn = store.db.begin_write()?;
        let mut key = [0u8; 16];
        key[7] = 1;
        txn.open_table(STATE_LIST_ITEMS_TABLE)?
            .insert(key.as_slice(), b"item".as_slice())?;
        txn.commit()?;
    }
    let failure = RedbStore::open(&path)
        .err()
        .context("State List id high water fell behind without rejection")?;
    ensure!(failure.to_string().contains("State List id high water"));
    Ok(())
}

#[test]
fn source_owned_list_tables_are_rejected_without_compatibility_backfill() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source-owned-list-format.redb");
    {
        let store = RedbStore::open(&path)?;
        let txn = store.db.begin_write()?;
        ensure!(txn.delete_table(STATE_LIST_ITEMS_TABLE)?);
        txn.open_table(TableDefinition::<&[u8], &[u8]>::new(
            "state_source_sink_items_v1",
        ))?;
        txn.commit()?;
    }
    let failure = RedbStore::open(&path)
        .err()
        .context("obsolete Source-owned List tables were accepted")?;
    ensure!(failure.to_string().contains("state_list_items_v1"));
    let db = Database::open(&path)?;
    let txn = db.begin_read()?;
    ensure!(matches!(
        txn.open_table(STATE_LIST_ITEMS_TABLE),
        Err(redb::TableError::TableDoesNotExist(_))
    ));
    Ok(())
}

#[test]
fn full_history_without_time_index_is_rejected_without_backfill() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("missing-history-index.redb");
    {
        let store = RedbStore::open_with_history(&path, RedbHistory::Full)?;
        let txn = store.db.begin_write()?;
        ensure!(txn.delete_table(STATE_HISTORY_TIME_INDEX_TABLE)?);
        txn.commit()?;
    }
    let failure = RedbStore::open_with_history(&path, RedbHistory::Full)
        .err()
        .context("Full history without its time index was accepted")?;
    ensure!(failure.to_string().contains("state_history_time_index_v1"));
    let db = Database::open(&path)?;
    let txn = db.begin_read()?;
    ensure!(matches!(
        txn.open_table(STATE_HISTORY_TIME_INDEX_TABLE),
        Err(redb::TableError::TableDoesNotExist(_))
    ));
    Ok(())
}
