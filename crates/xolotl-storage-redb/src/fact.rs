//! redb-backed [`FactStore`]. Facts are stored by a monotonic append cursor; a
//! secondary index maps each fact's [`OperationId`] to its cursor slot so
//! `complete` can update the pending record in place.

use crate::{
    FACT_INDEX_TABLE, FACT_META_TABLE, FACT_PROCESS_INDEX_TABLE, FACTS_TABLE, map_db_error,
};
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable};
use std::sync::Arc;
use xolotl_kernel::{FactError, FactStore};
use xolotl_types::{Fact, OperationId, ProcessId};

const NEXT_CURSOR_KEY: &str = "next_cursor";

/// Map any error carrying a message into a [`FactError`] (the kernel-facing
/// durable-write failure). Mirrors `state.rs`'s `StateError::Backend` mapping.
fn fact_err(e: impl ToString) -> FactError {
    FactError(e.to_string())
}

/// Durable fact store. `cursor` is the monotonic append position used as a
/// snapshot cut-point, not a fact field.
pub struct RedbFactStore {
    db: Arc<Database>,
    cursor: Mutex<u64>,
}

impl RedbFactStore {
    pub(crate) fn new(db: Arc<Database>) -> Result<Self, redb::DatabaseError> {
        let cursor = {
            let txn = db.begin_read().map_err(map_db_error)?;
            let table = txn.open_table(FACT_META_TABLE).map_err(map_db_error)?;
            table
                .get(NEXT_CURSOR_KEY)
                .map_err(map_db_error)?
                .map(|v| v.value())
                .unwrap_or(0)
        };
        Ok(Self {
            db,
            cursor: Mutex::new(cursor),
        })
    }

    /// Serialize an OperationId to its stable index key.
    fn op_key(id: &OperationId) -> String {
        format!("{}/{}/{}", id.process.get(), id.position.get(), id.attempt)
    }

    fn process_prefix(process: ProcessId) -> String {
        format!("{:020}/", process.get())
    }

    fn process_key(process: ProcessId, slot: u64) -> String {
        format!("{}{:020}", Self::process_prefix(process), slot)
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
                .insert(Self::op_key(&fact.id).as_str(), slot)
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

    fn caller_at_slot(
        &self,
        txn: &redb::WriteTransaction,
        slot: u64,
    ) -> Result<Option<ProcessId>, FactError> {
        let table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        table
            .get(slot)
            .map_err(fact_err)?
            .map(|bytes| serde_json::from_slice::<Fact>(bytes.value()).map(|f| f.caller))
            .transpose()
            .map_err(fact_err)
    }

    fn slot_of(&self, id: &OperationId) -> Result<Option<u64>, FactError> {
        let txn = self.db.begin_read().map_err(fact_err)?;
        let index = txn.open_table(FACT_INDEX_TABLE).map_err(fact_err)?;
        Ok(index
            .get(Self::op_key(id).as_str())
            .map_err(fact_err)?
            .map(|slot| slot.value()))
    }

    fn update_existing_slot(&self, slot: u64, fact: &Fact) -> Result<(), FactError> {
        let txn = self.db.begin_write().map_err(fact_err)?;
        let old_caller = self.caller_at_slot(&txn, slot)?;
        self.store_fact(&txn, slot, fact, old_caller)?;
        txn.commit().map_err(fact_err)
    }
}

impl FactStore for RedbFactStore {
    fn append(&self, fact: Fact) -> Result<u64, FactError> {
        let mut cursor = self.cursor.lock();
        let slot = *cursor;
        let next = slot
            .checked_add(1)
            .ok_or_else(|| FactError("fact cursor overflow".into()))?;

        let txn = self.db.begin_write().map_err(fact_err)?;
        self.store_fact(&txn, slot, &fact, None)?;
        {
            let mut meta = txn.open_table(FACT_META_TABLE).map_err(fact_err)?;
            meta.insert(NEXT_CURSOR_KEY, next).map_err(fact_err)?;
        }
        txn.commit().map_err(fact_err)?;
        // Advance only after a durable commit, so a failed write leaves the slot
        // reusable rather than punching a gap in the append log.
        *cursor = next;
        Ok(slot)
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        // Update the existing slot if the fact was begun; else append fresh.
        if let Some(slot) = self.slot_of(&fact.id)? {
            return self.update_existing_slot(slot, &fact);
        }

        // Serialize only the append decision. A second lookup under the cursor
        // lock closes the race where concurrent completes for the same new
        // OperationId would both observe no index entry and append duplicates.
        let mut cursor = self.cursor.lock();
        let slot = self.slot_of(&fact.id)?;
        match slot {
            Some(slot) => self.update_existing_slot(slot, &fact)?,
            None => {
                let txn = self.db.begin_write().map_err(fact_err)?;
                let slot = *cursor;
                let next = slot
                    .checked_add(1)
                    .ok_or_else(|| FactError("fact cursor overflow".into()))?;
                self.store_fact(&txn, slot, &fact, None)?;
                {
                    let mut meta = txn.open_table(FACT_META_TABLE).map_err(fact_err)?;
                    meta.insert(NEXT_CURSOR_KEY, next).map_err(fact_err)?;
                }
                txn.commit().map_err(fact_err)?;
                *cursor = next;
            }
        }
        Ok(())
    }

    fn sync(&self) -> Result<(), FactError> {
        // redb commits are durable on commit; an explicit barrier is a no-op
        // beyond what each `append`/`complete` txn already guarantees. The
        // ReplayClass discipline is enforced by the FactSink wrapper.
        Ok(())
    }

    fn facts_of(&self, process: ProcessId) -> Result<Vec<Fact>, FactError> {
        let txn = self.db.begin_read().map_err(fact_err)?;
        let slots = {
            let process_index = txn.open_table(FACT_PROCESS_INDEX_TABLE).map_err(fact_err)?;
            let prefix = Self::process_prefix(process);
            let mut slots = Vec::new();
            for item in process_index.range(prefix.as_str()..).map_err(fact_err)? {
                let (key, slot) = item.map_err(fact_err)?;
                if !key.value().starts_with(prefix.as_str()) {
                    break;
                }
                slots.push(slot.value());
            }
            slots
        };

        let facts_table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        let mut facts = Vec::with_capacity(slots.len());
        for slot in slots {
            if let Some(bytes) = facts_table.get(slot).map_err(fact_err)? {
                facts.push(serde_json::from_slice::<Fact>(bytes.value()).map_err(fact_err)?);
            }
        }
        Ok(facts)
    }

    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        let txn = self.db.begin_read().map_err(fact_err)?;
        let table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        let mut facts = Vec::new();
        for item in table.iter().map_err(fact_err)? {
            let (_slot, bytes) = item.map_err(fact_err)?;
            facts.push(serde_json::from_slice::<Fact>(bytes.value()).map_err(fact_err)?);
        }
        Ok(facts)
    }

    fn cursor(&self) -> u64 {
        *self.cursor.lock()
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
mod tests {
    use super::*;
    use crate::RedbStore;
    use anyhow::{anyhow, ensure};
    use xolotl_types::{
        DecisionTag, HandleId, IdentityRef, MethodId, NodeId, OutcomeRef, ProcessId, ReplayClass,
        ResourceId, Timestamp, Value, ValueRef,
    };

    fn fact(process: u64, pos: u32, complete: bool) -> Fact {
        Fact {
            id: OperationId::new(ProcessId::new(process), NodeId::new(pos), 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller: ProcessId::new(process),
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(1),
            method: MethodId::new(0),
            input_ref: ValueRef::Inline(Value::Null),
            taint: xolotl_types::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome_ref: if complete {
                OutcomeRef::Inline(Value::Int(9))
            } else {
                OutcomeRef::None
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
        let fs = Arc::new(store.fact_store()?);
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut threads = Vec::new();

        for _ in 0..8 {
            let fs = fs.clone();
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
