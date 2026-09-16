//! redb-backed [`FactStore`]. Facts are stored by a monotonic append cursor; a
//! secondary index maps each fact's [`OperationId`] to its cursor slot so
//! `complete` can update the pending record in place.

use crate::{
    FACT_INDEX_TABLE, FACT_META_TABLE, FACT_PROCESS_INDEX_TABLE, FACTS_TABLE, map_db_error,
};
use redb::{Database, ReadableDatabase, ReadableTable};
use std::{
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::broadcast;
use xolotl_kernel::{
    ExecutionIdError, ExecutionIdRange, ExecutionIdSource, FactError, FactLookup, FactLookupResult,
    FactPage, FactQuery, FactStore, FactStream,
};
use xolotl_types::{Fact, OperationId, ProcessId};

mod read;
use read::{decode_fact, decode_indexed_fact};

use crate::schema::NEXT_FACT_CURSOR as NEXT_CURSOR_KEY;

/// Map any error carrying a message into a [`FactError`] (the kernel-facing
/// storage failure). Mirrors `state.rs`'s `StateError::Backend` mapping.
fn fact_err(e: impl ToString) -> FactError {
    FactError(e.to_string())
}

/// Durable fact store. `cursor` is the locally observed append position, not an
/// outcome revision. Scans capture their append bound from the read transaction.
pub struct RedbFactStore {
    db: Arc<Database>,
    cursor: Arc<AtomicU64>,
    tx: broadcast::Sender<Arc<Fact>>,
}

impl RedbFactStore {
    pub(crate) fn new(
        db: Arc<Database>,
        cursor: Arc<AtomicU64>,
        tx: broadcast::Sender<Arc<Fact>>,
    ) -> Result<Self, redb::DatabaseError> {
        let observed = {
            let txn = db.begin_read().map_err(map_db_error)?;
            let table = txn.open_table(FACT_META_TABLE).map_err(map_db_error)?;
            table
                .get(NEXT_CURSOR_KEY)
                .map_err(map_db_error)?
                .map(|v| v.value())
                .ok_or_else(|| map_db_error("fact cursor metadata missing"))?
        };
        cursor.fetch_max(observed, Ordering::Relaxed);
        Ok(Self { db, cursor, tx })
    }

    fn process_prefix(process: ProcessId) -> String {
        format!("{:020}/", process.get())
    }

    fn process_key(process: ProcessId, slot: u64) -> String {
        format!("{:020}/{:020}", process.get(), slot)
    }

    fn validate_process_index(key: &str, process: ProcessId, slot: u64) -> Result<(), FactError> {
        if key != Self::process_key(process, slot) {
            return Err(FactError(format!(
                "fact process index key {key:?} does not match slot {slot}"
            )));
        }
        Ok(())
    }

    fn store_fact(
        &self,
        txn: &redb::WriteTransaction,
        slot: u64,
        fact: &Fact,
        old_caller: Option<ProcessId>,
    ) -> Result<(), FactError> {
        ensure_fact_schema(fact)?;
        let bytes = serde_json::to_vec(fact).map_err(fact_err)?;
        {
            let mut table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
            table.insert(slot, bytes.as_slice()).map_err(fact_err)?;
        };
        {
            let mut index = txn.open_table(FACT_INDEX_TABLE).map_err(fact_err)?;
            index
                .insert(fact.id.to_bytes().as_slice(), slot)
                .map_err(fact_err)?;
        }
        {
            let mut index = txn.open_table(FACT_PROCESS_INDEX_TABLE).map_err(fact_err)?;
            if let Some(old) = old_caller
                && old != fact.caller
            {
                let old_key = Self::process_key(old, slot);
                index.remove(old_key.as_str()).map_err(fact_err)?;
            }
            let process_key = Self::process_key(fact.caller, slot);
            index.insert(process_key.as_str(), slot).map_err(fact_err)?;
        }
        Ok(())
    }

    fn existing_fact_caller(
        &self,
        txn: &redb::WriteTransaction,
        slot: u64,
        id: OperationId,
    ) -> Result<ProcessId, FactError> {
        let table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        let bytes = table.get(slot).map_err(fact_err)?.ok_or_else(|| {
            FactError(format!(
                "fact operation index points to missing slot {slot}"
            ))
        })?;
        Ok(decode_indexed_fact(bytes.value(), slot, id, None)?.caller)
    }

    fn slot_of(
        &self,
        txn: &redb::WriteTransaction,
        id: &OperationId,
    ) -> Result<Option<u64>, FactError> {
        let index = txn.open_table(FACT_INDEX_TABLE).map_err(fact_err)?;
        Ok(index
            .get(id.to_bytes().as_slice())
            .map_err(fact_err)?
            .map(|slot| slot.value()))
    }

    fn broadcast_fact(&self, fact: Fact) {
        match self.tx.send(Arc::new(fact)) {
            Ok(_receivers) => {}
            Err(_error) => {
                // No active receiver kept the fact; the transaction already committed.
            }
        }
    }

    fn append_slot(txn: &redb::WriteTransaction) -> Result<(u64, u64), FactError> {
        let mut meta = txn.open_table(FACT_META_TABLE).map_err(fact_err)?;
        let slot = meta
            .get(NEXT_CURSOR_KEY)
            .map_err(fact_err)?
            .map(|value| value.value())
            .ok_or_else(|| FactError("fact cursor metadata missing".into()))?;
        let next = slot
            .checked_add(1)
            .ok_or_else(|| FactError("fact cursor overflow".into()))?;
        meta.insert(NEXT_CURSOR_KEY, next).map_err(fact_err)?;
        Ok((slot, next))
    }
}

impl ExecutionIdSource for RedbFactStore {
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        crate::execution_ids::reserve(&self.db, count)
    }
}

impl FactStore for RedbFactStore {
    fn append(&self, fact: Fact) -> Result<u64, FactError> {
        ensure_fact_schema(&fact)?;
        let txn = self.db.begin_write().map_err(fact_err)?;
        if let Some(slot) = self.slot_of(&txn, &fact.id)? {
            self.existing_fact_caller(&txn, slot, fact.id)?;
            return Ok(slot);
        }
        let (slot, next) = Self::append_slot(&txn)?;
        self.store_fact(&txn, slot, &fact, None)?;
        txn.commit().map_err(fact_err)?;
        // Advance only after a durable commit, so a failed write leaves the slot
        // reusable rather than punching a gap in the append log.
        self.cursor.fetch_max(next, Ordering::Relaxed);
        self.broadcast_fact(fact);
        Ok(slot)
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        // The lookup and append decision share the database's writer transaction,
        // including when callers use independently constructed store adapters.
        let txn = self.db.begin_write().map_err(fact_err)?;
        let (slot, next, old_caller) = match self.slot_of(&txn, &fact.id)? {
            Some(slot) => (
                slot,
                None,
                Some(self.existing_fact_caller(&txn, slot, fact.id)?),
            ),
            None => {
                let (slot, next) = Self::append_slot(&txn)?;
                (slot, Some(next), None)
            }
        };
        self.store_fact(&txn, slot, &fact, old_caller)?;
        txn.commit().map_err(fact_err)?;
        if let Some(next) = next {
            self.cursor.fetch_max(next, Ordering::Relaxed);
        }
        self.broadcast_fact(fact);
        Ok(())
    }

    fn sync(&self) -> Result<(), FactError> {
        // redb commits are durable on commit; an explicit barrier is a no-op
        // beyond what each `append`/`complete` txn already guarantees. The
        // ReplayClass discipline is enforced by the FactSink wrapper.
        Ok(())
    }

    fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        self.scan_page(query)
    }

    fn lookup(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        self.lookup_record(query)
    }

    fn facts_of(&self, process: ProcessId) -> Result<Vec<Fact>, FactError> {
        let txn = self.db.begin_read().map_err(fact_err)?;
        let process_index = txn.open_table(FACT_PROCESS_INDEX_TABLE).map_err(fact_err)?;
        let facts_table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        let prefix = Self::process_prefix(process);
        let mut facts = Vec::new();
        for item in process_index.range(prefix.as_str()..).map_err(fact_err)? {
            let (key, slot) = item.map_err(fact_err)?;
            if !key.value().starts_with(prefix.as_str()) {
                break;
            }
            let slot = slot.value();
            Self::validate_process_index(key.value(), process, slot)?;
            let bytes = facts_table.get(slot).map_err(fact_err)?.ok_or_else(|| {
                FactError(format!("fact process index points to missing slot {slot}"))
            })?;
            facts.push(decode_fact(bytes.value(), slot, Some(process))?);
        }
        Ok(facts)
    }

    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        let txn = self.db.begin_read().map_err(fact_err)?;
        let table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        let mut facts = Vec::new();
        for item in table.iter().map_err(fact_err)? {
            let (slot, bytes) = item.map_err(fact_err)?;
            facts.push(decode_fact(bytes.value(), slot.value(), None)?);
        }
        Ok(facts)
    }

    fn cursor(&self) -> u64 {
        self.cursor.load(Ordering::Relaxed)
    }

    fn subscribe_facts(&self) -> FactStream {
        self.tx.subscribe()
    }
}

fn ensure_fact_schema(fact: &Fact) -> Result<(), FactError> {
    if fact.schema_version == Fact::SCHEMA_VERSION {
        Ok(())
    } else {
        Err(FactError(format!(
            "unsupported Fact schema_version {} (current {})",
            fact.schema_version,
            Fact::SCHEMA_VERSION
        )))
    }
}

#[cfg(test)]
mod paging_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RedbStore;
    use anyhow::{anyhow, ensure};
    use xolotl_types::{
        DecisionTag, ExecutionId, HandleId, IdentityRef, InvocationId, MethodId, NodeId, ProcessId,
        ReplayClass, ResourceId, Timestamp, Value,
    };

    pub(super) fn fact(process: u64, pos: u32, complete: bool) -> Fact {
        Fact {
            id: OperationId::new(
                ProcessId::new(process),
                ExecutionId::FIRST,
                InvocationId::new(1),
                NodeId::new(pos),
                0,
            ),
            schema_version: Fact::SCHEMA_VERSION,
            caller: ProcessId::new(process),
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(1),
            method: MethodId::new(0),
            input: Value::null(),
            taint: xolotl_types::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome: if complete {
                Some(Value::integer(9))
            } else {
                None
            },
            batch: None,
            replay: ReplayClass::NonIdempotentEffect,
            timestamp: Timestamp::millis(0),
        }
    }

    #[test]
    fn append_then_complete_updates_in_place() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("facts.redb");
        let store = RedbStore::open(&path)?;
        let fs = store.fact_store()?;
        fs.append(fact(1, 0, false))?;
        fs.complete(fact(1, 0, true))?;
        let facts = fs.facts_of(ProcessId::new(1))?;
        ensure!(
            facts.len() == 1,
            "complete should update the begun slot: {facts:?}"
        );
        match facts.as_slice() {
            [fact] => ensure!(fact.is_complete(), "fact should be complete: {fact:?}"),
            other => ensure!(other.len() == 1, "unexpected facts: {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn concurrent_complete_same_new_operation_is_single_slot() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("facts.redb");
        let store = RedbStore::open(&path)?;
        let fs = store.fact_store()?;
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::new();

        for _ in 0..8 {
            let fs = store.fact_store()?;
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || -> anyhow::Result<()> {
                barrier.wait();
                fs.complete(fact(1, 0, true))?;
                Ok(())
            }));
        }
        for thread in threads {
            thread
                .join()
                .map_err(|_error| anyhow!("fact completion thread panicked"))??;
        }

        let facts = fs.facts_of(ProcessId::new(1))?;
        ensure!(facts.len() == 1, "unexpected facts: {facts:?}");
        let all = fs.all_facts()?;
        ensure!(all.len() == 1, "unexpected all facts: {all:?}");
        ensure!(fs.cursor() == 1);
        Ok(())
    }

    #[test]
    fn independent_adapters_append_without_overwriting_and_share_cursor() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = RedbStore::open(dir.path().join("facts.redb"))?;
        let first = store.fact_store()?;
        let second = store.fact_store()?;
        ensure!(first.append(fact(1, 0, true))? == 0);
        ensure!(second.append(fact(1, 1, true))? == 1);
        first.complete(fact(1, 2, true))?;
        second.complete(fact(1, 3, true))?;
        ensure!(first.cursor() == 4 && second.cursor() == 4);
        let facts = first.all_facts()?;
        ensure!(facts.iter().map(|fact| fact.id.position.get()).eq(0..4));
        Ok(())
    }

    #[test]
    fn execution_and_invocation_coordinates_are_part_of_the_index() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = RedbStore::open(dir.path().join("facts.redb"))?;
        let fs = store.fact_store()?;
        let original = fact(1, 0, false);
        let mut another_execution = original.clone();
        another_execution.id.execution =
            ExecutionId::new(2).ok_or_else(|| anyhow!("missing execution id"))?;
        let mut another_invocation = original.clone();
        another_invocation.id.invocation = InvocationId::new(u64::from(u32::MAX) + 1);
        fs.append(original.clone())?;
        fs.append(another_execution.clone())?;
        fs.append(another_invocation.clone())?;
        another_execution.outcome = Some(Value::integer(7));
        fs.complete(another_execution.clone())?;
        let facts = fs.all_facts()?;
        ensure!(facts == [original, another_execution, another_invocation]);
        ensure!(fs.cursor() == 3);
        Ok(())
    }

    #[test]
    fn repeated_append_retains_the_original_slot_and_never_downgrades_completion()
    -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = RedbStore::open(dir.path().join("facts.redb"))?;
        let first = store.fact_store()?;
        let second = store.fact_store()?;
        let mut events = first.subscribe_facts();
        let pending = fact(1, 0, false);
        ensure!(first.append(pending.clone())? == 0);
        ensure!(*events.try_recv()? == pending);
        let mut refreshed = pending.clone();
        refreshed.timestamp = Timestamp::millis(100);
        ensure!(second.append(refreshed.clone())? == 0);
        ensure!(
            events.try_recv().is_err(),
            "duplicate append published an event"
        );
        ensure!(first.all_facts()? == [pending]);
        let completed = fact(1, 0, true);
        second.complete(completed.clone())?;
        ensure!(*events.try_recv()? == completed);
        ensure!(first.append(refreshed.clone())? == 0);
        ensure!(
            events.try_recv().is_err(),
            "pending replay published after completion"
        );
        refreshed.schema_version += 1;
        ensure!(
            second.append(refreshed).is_err(),
            "duplicate bypassed schema validation"
        );
        let next = fact(1, 1, true);
        ensure!(second.append(next.clone())? == 1);
        ensure!(first.all_facts()? == [completed, next]);
        ensure!(first.cursor() == 2 && second.cursor() == 2);
        Ok(())
    }

    #[test]
    fn independent_adapters_share_append_and_completion_notifications() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = RedbStore::open(dir.path().join("facts.redb"))?;
        let shared = store.clone();
        let reader = store.fact_store()?;
        let writer = shared.fact_store()?;
        let mut events = reader.subscribe_facts();
        let pending = fact(1, 0, false);
        writer.append(pending.clone())?;
        ensure!(*events.try_recv()? == pending);
        let completed = fact(1, 0, true);
        writer.complete(completed.clone())?;
        ensure!(*events.try_recv()? == completed);
        ensure!(events.try_recv().is_err());
        Ok(())
    }

    #[test]
    fn persists_across_reopen() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("facts.redb");
        {
            let store = RedbStore::open(&path)?;
            let fs = store.fact_store()?;
            fs.append(fact(2, 0, true))?;
        }
        let store = RedbStore::open(&path)?;
        let fs = store.fact_store()?;
        let facts = fs.facts_of(ProcessId::new(2))?;
        ensure!(facts.len() == 1, "unexpected facts: {facts:?}");
        ensure!(fs.cursor() == 1, "unexpected cursor: {}", fs.cursor());
        Ok(())
    }

    #[test]
    fn all_facts_returns_append_order() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("facts.redb");
        let store = RedbStore::open(&path)?;
        let fs = store.fact_store()?;
        fs.complete(fact(1, 0, true))?;
        fs.complete(fact(2, 0, true))?;

        let facts = fs.all_facts()?;
        match facts.as_slice() {
            [first, second] => {
                ensure!(
                    first.caller == ProcessId::new(1),
                    "unexpected first caller: {:?}",
                    first.caller
                );
                ensure!(
                    second.caller == ProcessId::new(2),
                    "unexpected second caller: {:?}",
                    second.caller
                );
            }
            other => ensure!(other.len() == 2, "unexpected facts: {other:?}"),
        }
        Ok(())
    }
}
