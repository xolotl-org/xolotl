use super::*;
use xolotl_kernel::host::TokioBlockingSpawner;

#[test]
fn incomplete_tables_and_accounting_reject_reopen() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let spawner = Arc::new(TrackedBlockingSpawner::new(Arc::new(
        TokioBlockingSpawner::default(),
    )));
    let db = Arc::new(Database::new(redb::Database::create(
        directory.path().join("partial.redb"),
    )?));
    let transaction = db.begin_write()?;
    transaction.open_table(ROWS)?;
    transaction.commit()?;
    anyhow::ensure!(matches!(
        RedbConsoleSessionStore::new(db, spawner.clone(), ConsoleSessionPolicy::default()),
        Err(SessionStoreError::Rejected(_))
    ));

    let db = Arc::new(Database::new(redb::Database::create(
        directory.path().join("counter.redb"),
    )?));
    RedbConsoleSessionStore::new(db.clone(), spawner.clone(), ConsoleSessionPolicy::default())?;
    let transaction = db.begin_write()?;
    {
        let mut meta = transaction.open_table(META)?;
        meta.insert("count", 1)?;
    }
    transaction.commit()?;
    anyhow::ensure!(matches!(
        RedbConsoleSessionStore::new(db, spawner, ConsoleSessionPolicy::default()),
        Err(SessionStoreError::Rejected(_))
    ));
    Ok(())
}

fn row(sid: &str) -> anyhow::Result<ConsoleSession> {
    let value: xolotl_types::Value = serde_json::from_value(serde_json::json!({
        "token_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "username": "owner", "authority_id": "local", "account_id": "owner",
        "revocation_epoch": "1", "identity_path": "identity://console/accounts/owner",
        "issued_at": 1, "expires_at": 100, "idle_expires_at": 100,
        "authentication": {"primary": {"method": "password", "verified_at": 1}, "secondary": null},
        "credential_epoch": "epoch", "authority_ceiling": [], "last_seen": 1, "source_addr": ""
    }))?;
    Ok(ConsoleSession::decode(sid, &serde_json::to_vec(&value)?)?)
}

#[tokio::test]
async fn failed_transaction_after_eviction_rolls_back_all_indexes_and_counts() -> anyhow::Result<()>
{
    let directory = tempfile::tempdir()?;
    let db = Arc::new(Database::new(redb::Database::create(
        directory.path().join("rollback.redb"),
    )?));
    let spawner = Arc::new(TrackedBlockingSpawner::new(Arc::new(
        TokioBlockingSpawner::default(),
    )));
    let policy = ConsoleSessionPolicy::new(1, 1)?;
    let store = RedbConsoleSessionStore::new(db.clone(), spawner.clone(), policy)?;
    store.create(row("old")?).await?;
    let failure: Result<(), SessionStoreError> = (|| {
        let transaction = db.begin_write().map_err(storage_error)?;
        let mut tables = Tables::open(&transaction)?;
        let observed = tables
            .get("old")?
            .ok_or_else(|| rejected("old session missing"))?;
        tables.remove(&observed)?;
        Err(SessionStoreError::Storage(
            "injected failure after eviction".into(),
        ))
    })();
    anyhow::ensure!(matches!(failure, Err(SessionStoreError::Storage(_))));
    RedbConsoleSessionStore::new(db, spawner, policy)?;
    anyhow::ensure!(store.get("old").await?.is_some());
    store.create(row("new")?).await?;
    anyhow::ensure!(store.get("old").await?.is_none());
    anyhow::ensure!(store.get("new").await?.is_some());
    anyhow::ensure!(store.revoke_account("local", "owner").await? == 1);
    Ok(())
}

#[tokio::test]
async fn offline_policy_change_reads_scalar_counters_not_payloads() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let db = Arc::new(Database::new(redb::Database::create(
        directory.path().join("scalar-policy.redb"),
    )?));
    let spawner = Arc::new(TrackedBlockingSpawner::new(Arc::new(
        TokioBlockingSpawner::default(),
    )));
    let store =
        RedbConsoleSessionStore::new(db.clone(), spawner.clone(), ConsoleSessionPolicy::default())?;
    store.create(row("retained")?).await?;
    drop(store);
    let transaction = db.begin_write()?;
    {
        let mut rows = transaction.open_table(ROWS)?;
        rows.insert("retained", b"opaque-invalid-payload".as_slice())?;
    }
    transaction.commit()?;
    let lowered = ConsoleSessionPolicy::new(1, 1)?;
    RedbConsoleSessionStore::new(db.clone(), spawner, lowered)?;
    let transaction = db.begin_read()?;
    anyhow::ensure!(
        transaction
            .open_table(ROWS)?
            .get("retained")?
            .ok_or_else(|| rejected("retained row missing"))?
            .value()
            == b"opaque-invalid-payload"
    );
    anyhow::ensure!(
        transaction
            .open_table(META)?
            .get("domain")?
            .ok_or_else(|| rejected("domain metadata missing"))?
            .value()
            == 1
    );
    anyhow::ensure!(
        transaction
            .open_table(META)?
            .get("count")?
            .ok_or_else(|| rejected("count metadata missing"))?
            .value()
            == 1
    );
    Ok(())
}
