use super::{tests::fact, *};
use crate::RedbStore;
use anyhow::{anyhow, ensure};
use std::num::NonZeroUsize;
use tokio::sync::broadcast::error::TryRecvError;
use xolotl_types::Value;

fn limits(
    records: usize,
    bytes: usize,
    record_bytes: usize,
) -> anyhow::Result<FactRetentionLimits> {
    Ok(FactRetentionLimits {
        max_records: NonZeroUsize::new(records).ok_or_else(|| anyhow!("zero records"))?,
        max_encoded_bytes: NonZeroUsize::new(bytes).ok_or_else(|| anyhow!("zero bytes"))?,
        max_record_bytes: NonZeroUsize::new(record_bytes)
            .ok_or_else(|| anyhow!("zero record bytes"))?,
    })
}

fn size(record: &Fact) -> anyhow::Result<usize> {
    Ok(serde_json::to_vec(record)?.len())
}

#[test]
fn default_limits_are_bounded_and_shared_policy_cannot_be_changed() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("facts.redb"))?;
    let facts = store.fact_store()?;
    ensure!(facts.limits() == FactRetentionLimits::default());
    ensure!(facts.usage()? == FactRetentionUsage::default());
    ensure!(
        store
            .fact_store_with_limits(limits(1, 4096, 4096)?)
            .is_err()
    );
    ensure!(store.fact_store()?.limits() == facts.limits());
    Ok(())
}

#[test]
fn concurrent_adapters_atomically_share_record_capacity() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("facts.redb"))?;
    let policy = limits(2, 8192, 4096)?;
    let facts = store.fact_store_with_limits(policy)?;
    let mut events = facts.subscribe_facts();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut workers = Vec::new();
    for position in 0..8 {
        let adapter = store.fact_store_with_limits(policy)?;
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            adapter.append(fact(1, position, false))
        }));
    }
    let mut accepted = 0;
    for worker in workers {
        accepted += usize::from(
            worker
                .join()
                .map_err(|_panic| anyhow!("worker panicked"))?
                .is_ok(),
        );
    }
    ensure!(accepted == 2);
    let retained = facts.all_facts()?;
    ensure!(retained.len() == 2 && facts.cursor() == 2);
    ensure!(facts.usage()?.records == 2);
    ensure!(
        facts.usage()?.encoded_bytes
            == retained
                .iter()
                .map(size)
                .collect::<anyhow::Result<Vec<_>>>()?
                .iter()
                .sum::<usize>()
    );
    ensure!(events.try_recv().is_ok() && events.try_recv().is_ok());
    ensure!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
    Ok(())
}

#[test]
fn duplicate_begin_does_not_charge_or_encode_replacement_payload() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("facts.redb"))?;
    let original = fact(1, 0, false);
    let encoded = size(&original)?;
    let facts = store.fact_store_with_limits(limits(1, encoded, encoded)?)?;
    let mut events = facts.subscribe_facts();
    ensure!(facts.append(original.clone())? == 0);
    ensure!(*events.try_recv()? == original);
    let before = facts.usage()?;
    let mut duplicate = original.clone();
    duplicate.input = Value::string("x".repeat(encoded * 2));
    ensure!(facts.append(duplicate)? == 0);
    ensure!(facts.usage()? == before && facts.cursor() == 1);
    ensure!(facts.all_facts()? == [original]);
    ensure!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
    Ok(())
}

#[test]
fn oversized_append_and_completion_preserve_records_cursor_and_notifications() -> anyhow::Result<()>
{
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("facts.redb"))?;
    let original = fact(1, 0, false);
    let encoded = size(&original)?;
    let facts = store.fact_store_with_limits(limits(4, encoded * 4, encoded)?)?;
    let mut events = facts.subscribe_facts();
    let mut oversized = fact(1, 1, false);
    oversized.input = Value::string("x".repeat(encoded));
    ensure!(facts.append(oversized.clone()).is_err());
    ensure!(facts.complete(oversized.clone()).is_err());
    ensure!(facts.usage()? == FactRetentionUsage::default() && facts.cursor() == 0);
    ensure!(facts.all_facts()?.is_empty());
    ensure!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
    facts.append(original.clone())?;
    events.try_recv()?;
    let before = facts.usage()?;
    oversized.id = original.id;
    ensure!(facts.complete(oversized).is_err());
    ensure!(facts.usage()? == before && facts.cursor() == 1);
    ensure!(facts.all_facts()? == [original]);
    ensure!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
    Ok(())
}

#[test]
fn aggregate_rejection_is_atomic_for_append_and_net_completion() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("facts.redb"))?;
    let first = fact(1, 0, false);
    let second = fact(1, 1, false);
    let budget = size(&first)? + size(&second)?;
    let facts = store.fact_store_with_limits(limits(4, budget, budget)?)?;
    let mut events = facts.subscribe_facts();
    facts.append(first.clone())?;
    facts.append(second.clone())?;
    events.try_recv()?;
    events.try_recv()?;
    let before = facts.usage()?;
    let mut grown = first.clone();
    grown.outcome = Some(Value::string("x".repeat(64)));
    ensure!(size(&grown)? <= budget);
    ensure!(facts.complete(grown).is_err());
    ensure!(facts.append(fact(1, 2, false)).is_err());
    ensure!(facts.complete(fact(1, 3, true)).is_err());
    ensure!(facts.usage()? == before && facts.cursor() == 2);
    ensure!(facts.all_facts()? == [first, second]);
    ensure!(matches!(events.try_recv(), Err(TryRecvError::Empty)));
    Ok(())
}

#[test]
fn completion_charges_net_replacement_and_shrinking_returns_bytes() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("facts.redb"))?;
    let pending = fact(1, 0, false);
    let next = fact(1, 1, false);
    let mut completed = pending.clone();
    completed.outcome = Some(Value::string("x".repeat(128)));
    let budget = size(&completed)? + size(&next)?;
    let facts = store.fact_store_with_limits(limits(2, budget, budget)?)?;
    facts.append(pending.clone())?;
    facts.append(next.clone())?;
    facts.complete(completed.clone())?;
    ensure!(
        facts.usage()?
            == FactRetentionUsage {
                records: 2,
                encoded_bytes: budget
            }
    );
    facts.complete(completed)?;
    ensure!(facts.usage()?.encoded_bytes == budget && facts.cursor() == 2);
    let mut shrunk = pending;
    shrunk.outcome = Some(Value::null());
    facts.complete(shrunk.clone())?;
    ensure!(facts.usage()?.encoded_bytes == size(&shrunk)? + size(&next)?);
    ensure!(facts.append(fact(1, 2, false)).is_err());
    ensure!(facts.complete(fact(1, 2, false)).is_err());
    ensure!(facts.cursor() == 2 && facts.usage()?.records == 2);
    ensure!(facts.all_facts()? == [shrunk, next]);
    Ok(())
}

#[test]
fn reopen_retains_usage_and_new_limits_do_not_reset_charge() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("facts.redb");
    let original = fact(1, 0, false);
    let retained_bytes;
    {
        let store = RedbStore::open(&path)?;
        let facts = store.fact_store_with_limits(limits(2, 8192, 4096)?)?;
        facts.append(original.clone())?;
        facts.complete(fact(1, 0, true))?;
        facts.complete(fact(1, 1, true))?;
        retained_bytes = facts.usage()?.encoded_bytes;
        ensure!(retained_bytes == size(&fact(1, 0, true))? + size(&fact(1, 1, true))?);
    }
    let store = RedbStore::open(&path)?;
    let facts = store.fact_store_with_limits(limits(1, 8192, 4096)?)?;
    ensure!(
        facts.usage()?
            == FactRetentionUsage {
                records: 2,
                encoded_bytes: retained_bytes
            }
    );
    ensure!(facts.cursor() == 2);
    ensure!(facts.append(original)? == 0);
    ensure!(facts.append(fact(1, 2, false)).is_err());
    ensure!(facts.complete(fact(1, 3, true)).is_err());
    ensure!(facts.usage()?.encoded_bytes == retained_bytes && facts.cursor() == 2);
    Ok(())
}

#[test]
fn missing_counters_recover_real_rows_once_and_persist_across_reopen() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("facts.redb");
    let expected;
    {
        let store = RedbStore::open(&path)?;
        let facts = store.fact_store()?;
        facts.append(fact(1, 0, false))?;
        facts.complete(fact(1, 1, true))?;
        expected = facts.usage()?;
        let txn = store.db.begin_write()?;
        {
            let mut meta = txn.open_table(FACT_META_TABLE)?;
            meta.remove(RETAINED_RECORDS_KEY)?;
            meta.remove(RETAINED_BYTES_KEY)?;
        }
        txn.commit()?;
    }
    for _ in 0..2 {
        let store = RedbStore::open(&path)?;
        let facts = store.fact_store_with_limits(limits(
            2,
            expected.encoded_bytes,
            expected.encoded_bytes,
        )?)?;
        ensure!(facts.usage()? == expected && facts.cursor() == 2);
        ensure!(facts.append(fact(1, 2, false)).is_err());
        ensure!(facts.complete(fact(1, 2, true)).is_err());
        let txn = store.db.begin_read()?;
        let meta = txn.open_table(FACT_META_TABLE)?;
        ensure!(meta.get(RETAINED_RECORDS_KEY)?.is_some());
        ensure!(meta.get(RETAINED_BYTES_KEY)?.is_some());
    }
    Ok(())
}

#[test]
fn partial_or_inconsistent_counters_fail_closed_without_resetting() -> anyhow::Result<()> {
    for corruption in 0..3 {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("facts.redb");
        {
            let store = RedbStore::open(&path)?;
            let facts = store.fact_store()?;
            facts.append(fact(1, 0, false))?;
            let txn = store.db.begin_write()?;
            {
                let mut meta = txn.open_table(FACT_META_TABLE)?;
                match corruption {
                    0 => {
                        meta.remove(RETAINED_BYTES_KEY)?;
                    }
                    1 => {
                        meta.insert(RETAINED_RECORDS_KEY, 0)?;
                    }
                    _ => {
                        meta.insert(RETAINED_BYTES_KEY, 0)?;
                    }
                }
            }
            txn.commit()?;
        }
        let store = RedbStore::open(&path)?;
        ensure!(store.fact_store().is_err());
        let txn = store.db.begin_read()?;
        ensure!(txn.open_table(FACTS_TABLE)?.len()? == 1);
        ensure!(
            txn.open_table(FACT_META_TABLE)?
                .get(NEXT_CURSOR_KEY)?
                .ok_or_else(|| anyhow!("cursor missing"))?
                .value()
                == 1
        );
    }
    Ok(())
}
