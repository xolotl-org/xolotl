//! redb-backed [`FactStore`] (§9 / §24.1): the durable write-ahead source of
//! truth. Facts are stored by a monotonic append cursor; a secondary index
//! maps each fact's [`OperationId`] to its cursor slot so `complete` can update
//! the pending record in place.

use crate::{FACT_INDEX_TABLE, FACT_META_TABLE, FACTS_TABLE, map_db_error};
use nexus_kernel::{FactError, FactStore};
use nexus_types::{Fact, OperationId, ProcessId};
use parking_lot::Mutex;
use redb::{Database, ReadableDatabase, ReadableTable};
use std::sync::Arc;

const NEXT_CURSOR_KEY: &str = "next_cursor";

/// Map any error carrying a message into a [`FactError`] (the kernel-facing
/// durable-write failure). Mirrors `state.rs`'s `StateError::Backend` mapping.
fn fact_err(e: impl ToString) -> FactError {
    FactError(e.to_string())
}

/// Durable fact store. `cursor` is the monotonic append position (snapshot
/// cut-point, §9) — not a fact field.
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

    fn store_fact(
        &self,
        txn: &redb::WriteTransaction,
        slot: u64,
        fact: &Fact,
    ) -> Result<(), FactError> {
        ensure_fact_schema(fact)?;
        let bytes = serde_json::to_vec(fact).map_err(fact_err)?;
        {
            let mut table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
            table.insert(slot, bytes.as_slice()).map_err(fact_err)?;
        }
        let mut index = txn.open_table(FACT_INDEX_TABLE).map_err(fact_err)?;
        index
            .insert(Self::op_key(&fact.id).as_str(), slot)
            .map_err(fact_err)?;
        Ok(())
    }

    fn slot_of(&self, id: &OperationId) -> Result<Option<u64>, FactError> {
        let txn = self.db.begin_read().map_err(fact_err)?;
        let index = txn.open_table(FACT_INDEX_TABLE).map_err(fact_err)?;
        Ok(index
            .get(Self::op_key(id).as_str())
            .map_err(fact_err)?
            .map(|slot| slot.value()))
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
        self.store_fact(&txn, slot, &fact)?;
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
        let slot = self.slot_of(&fact.id)?;
        let txn = self.db.begin_write().map_err(fact_err)?;
        match slot {
            Some(slot) => {
                self.store_fact(&txn, slot, &fact)?;
                txn.commit().map_err(fact_err)?;
            }
            None => {
                let mut cursor = self.cursor.lock();
                let slot = *cursor;
                let next = slot
                    .checked_add(1)
                    .ok_or_else(|| FactError("fact cursor overflow".into()))?;
                self.store_fact(&txn, slot, &fact)?;
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
        // ReplayClass discipline (§9.3) is enforced by the FactSink wrapper.
        Ok(())
    }

    fn facts_of(&self, process: ProcessId) -> Result<Vec<Fact>, FactError> {
        let txn = self.db.begin_read().map_err(fact_err)?;
        let table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        let mut facts = Vec::new();
        for item in table.iter().map_err(fact_err)? {
            let (_slot, bytes) = item.map_err(fact_err)?;
            let fact = serde_json::from_slice::<Fact>(bytes.value()).map_err(fact_err)?;
            if fact.caller == process {
                facts.push(fact);
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
    use nexus_types::{
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
            taint: nexus_types::TaintSet::pristine(),
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
    fn append_then_complete_updates_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("facts.redb");
        let store = RedbStore::open(&path).unwrap();
        let fs = store.fact_store().unwrap();
        fs.append(fact(1, 0, false)).unwrap();
        fs.complete(fact(1, 0, true)).unwrap();
        let facts = fs.facts_of(ProcessId::new(1)).unwrap();
        assert_eq!(
            facts.len(),
            1,
            "complete updates the begun slot, not a new one"
        );
        assert!(facts[0].is_complete());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("facts.redb");
        {
            let store = RedbStore::open(&path).unwrap();
            let fs = store.fact_store().unwrap();
            fs.append(fact(2, 0, true)).unwrap();
        }
        let store = RedbStore::open(&path).unwrap();
        let fs = store.fact_store().unwrap();
        assert_eq!(fs.facts_of(ProcessId::new(2)).unwrap().len(), 1);
        assert_eq!(fs.cursor(), 1, "cursor restored across reopen");
    }

    #[test]
    fn all_facts_returns_append_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("facts.redb");
        let store = RedbStore::open(&path).unwrap();
        let fs = store.fact_store().unwrap();
        fs.complete(fact(1, 0, true)).unwrap();
        fs.complete(fact(2, 0, true)).unwrap();

        let facts = fs.all_facts().unwrap();
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[0].caller, ProcessId::new(1));
        assert_eq!(facts[1].caller, ProcessId::new(2));
    }
}
