//! redb-backed [`FactStore`]. Facts are stored by a monotonic append cursor; a
//! secondary index maps each fact's [`OperationId`] to its cursor slot so
//! `complete` can update the pending record in place.

use crate::database::{Database, WriteTransaction};
use crate::{
    FACT_INDEX_TABLE, FACT_META_TABLE, FACT_PROCESS_INDEX_TABLE, FACTS_TABLE, map_db_error,
};
use parking_lot::Mutex;
use redb::{ReadableTable, ReadableTableMetadata};
use std::{
    io::{self, Write},
    num::NonZeroU64,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::broadcast;
use xolotl_kernel::{
    ExecutionIdError, ExecutionIdRange, ExecutionIdSource, FactError, FactLookup, FactLookupResult,
    FactPage, FactQuery, FactRetentionLimits, FactRetentionUsage, FactStore, FactStream,
};
use xolotl_types::{Fact, OperationId, ProcessId};

mod read;
use read::{decode_fact, decode_indexed_fact};

use crate::schema::NEXT_FACT_CURSOR as NEXT_CURSOR_KEY;

const RETAINED_RECORDS_KEY: &str = "retained_records_v1";
const RETAINED_BYTES_KEY: &str = "retained_encoded_bytes_v1";

struct FactEncoding {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for FactEncoding {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("fact record capacity exceeded"))?;
        if total > self.limit {
            return Err(io::Error::other("fact record capacity exceeded"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Map any error carrying a message into a [`FactError`] (the kernel-facing
/// storage failure). Mirrors `state.rs`'s `StateError::Backend` mapping.
fn fact_err(e: impl ToString) -> FactError {
    FactError::new(e.to_string())
}

fn read_cursor(db: &Database) -> Result<u64, redb::DatabaseError> {
    let txn = db.begin_read().map_err(map_db_error)?;
    let table = txn.open_table(FACT_META_TABLE).map_err(map_db_error)?;
    table
        .get(NEXT_CURSOR_KEY)
        .map_err(map_db_error)?
        .map(|value| value.value())
        .ok_or_else(|| map_db_error("fact cursor metadata missing"))
}

/// Shared by adapters from one `RedbStore`. An uncertain commit closes the
/// channel because its live event cannot be established from the error alone.
pub(crate) struct FactNotifications {
    tx: Mutex<Option<broadcast::Sender<Arc<Fact>>>>,
    commit_gate: Mutex<()>,
    retention_limits: Mutex<Option<FactRetentionLimits>>,
}

impl FactNotifications {
    pub(crate) fn new() -> Self {
        Self {
            tx: Mutex::new(Some(
                broadcast::channel(xolotl_kernel::FACT_BROADCAST_CAPACITY).0,
            )),
            commit_gate: Mutex::new(()),
            retention_limits: Mutex::new(None),
        }
    }

    fn send(&self, fact: Fact) {
        let sender = self
            .tx
            .lock()
            .as_ref()
            .filter(|sender| sender.receiver_count() != 0)
            .cloned();
        if let Some(tx) = sender {
            drop(tx.send(Arc::new(fact)));
        }
    }

    fn subscribe(&self) -> FactStream {
        if let Some(tx) = self.tx.lock().as_ref() {
            return tx.subscribe();
        }
        let (tx, rx) = broadcast::channel(1);
        drop(tx);
        rx
    }

    pub(crate) fn close(&self) {
        let sender = self.tx.lock().take();
        drop(sender);
    }
}

/// Durable fact store. `cursor` is the locally observed append position, not an
/// outcome revision. Scans capture their append bound from the read transaction.
/// Retained record counts and JSON bytes commit with each mutation. Limits are
/// shared by adapters on one live database; reopening may select new limits
/// without removing old records or resetting their charge. There is no automatic
/// retirement. These encoded-byte limits do not bound indexes, file size or RSS.
/// If both derived retention counters are absent, installation reconstructs
/// them from retained rows once. Partial counters or a mismatched record count
/// reject installation; execution and receipt identities are not reconstructed.
pub struct RedbFactStore {
    db: Arc<Database>,
    cursor: Arc<AtomicU64>,
    notifications: Arc<FactNotifications>,
    limits: FactRetentionLimits,
}

impl RedbFactStore {
    fn ensure_open(&self) -> Result<(), FactError> {
        self.db.ensure_open().map_err(|_error| {
            FactError::reopen_required(
                "shared database requires reopen after uncertain commit".into(),
            )
        })
    }

    pub(crate) fn new(
        db: Arc<Database>,
        cursor: Arc<AtomicU64>,
        notifications: Arc<FactNotifications>,
    ) -> Result<Self, redb::DatabaseError> {
        Self::new_with_limits(db, cursor, notifications, FactRetentionLimits::default())
    }

    pub(crate) fn new_with_limits(
        db: Arc<Database>,
        cursor: Arc<AtomicU64>,
        notifications: Arc<FactNotifications>,
        limits: FactRetentionLimits,
    ) -> Result<Self, redb::DatabaseError> {
        limits.validate().map_err(map_db_error)?;
        let shared = Arc::clone(&notifications);
        let mut selected = shared.retention_limits.lock();
        if selected.is_some_and(|current| current != limits) {
            return Err(map_db_error(
                "fact retention limits differ within one database",
            ));
        }
        let observed = read_cursor(&db)?;
        cursor.fetch_max(observed, Ordering::Relaxed);
        let store = Self {
            db,
            cursor,
            notifications,
            limits,
        };
        store.initialize_retention().map_err(map_db_error)?;
        *selected = Some(limits);
        Ok(store)
    }

    /// Selected limits shared by all Fact adapters on this live database.
    pub fn limits(&self) -> FactRetentionLimits {
        self.limits
    }

    /// Retained records and JSON bytes from one consistent storage view.
    pub fn usage(&self) -> Result<FactRetentionUsage, FactError> {
        self.stored_usage()?
            .ok_or_else(|| FactError::new("fact retention metadata missing".into()))
    }

    fn decode_usage(
        records: Option<u64>,
        encoded_bytes: Option<u64>,
    ) -> Result<Option<FactRetentionUsage>, FactError> {
        match (records, encoded_bytes) {
            (Some(records), Some(encoded_bytes)) if (records == 0) != (encoded_bytes == 0) => Err(
                FactError::new("inconsistent fact retention metadata".into()),
            ),
            (Some(records), Some(encoded_bytes)) => Ok(Some(FactRetentionUsage {
                records: usize::try_from(records).map_err(fact_err)?,
                encoded_bytes: usize::try_from(encoded_bytes).map_err(fact_err)?,
            })),
            (None, None) => Ok(None),
            _ => Err(FactError::new("incomplete fact retention metadata".into())),
        }
    }

    fn stored_usage(&self) -> Result<Option<FactRetentionUsage>, FactError> {
        self.ensure_open()?;
        let txn = self.db.begin_read().map_err(fact_err)?;
        let meta = txn.open_table(FACT_META_TABLE).map_err(fact_err)?;
        let usage = Self::decode_usage(
            meta.get(RETAINED_RECORDS_KEY)
                .map_err(fact_err)?
                .map(|value| value.value()),
            meta.get(RETAINED_BYTES_KEY)
                .map_err(fact_err)?
                .map(|value| value.value()),
        )?;
        if let Some(usage) = usage {
            let facts = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
            if facts.len().map_err(fact_err)? != u64::try_from(usage.records).map_err(fact_err)? {
                return Err(FactError::new(
                    "fact retention count does not match records".into(),
                ));
            }
        }
        self.ensure_open()?;
        Ok(usage)
    }

    fn initialize_retention(&self) -> Result<(), FactError> {
        if self.stored_usage()?.is_some() {
            return Ok(());
        }
        let txn = self.db.begin_write().map_err(fact_err)?;
        {
            let mut meta = txn.open_table(FACT_META_TABLE).map_err(fact_err)?;
            if Self::decode_usage(
                meta.get(RETAINED_RECORDS_KEY)
                    .map_err(fact_err)?
                    .map(|value| value.value()),
                meta.get(RETAINED_BYTES_KEY)
                    .map_err(fact_err)?
                    .map(|value| value.value()),
            )?
            .is_some()
            {
                return Ok(());
            }
            let facts = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
            let mut encoded_bytes = 0_u64;
            for entry in facts.iter().map_err(fact_err)? {
                let (_, bytes) = entry.map_err(fact_err)?;
                encoded_bytes = encoded_bytes
                    .checked_add(u64::try_from(bytes.value().len()).map_err(fact_err)?)
                    .ok_or_else(|| FactError::new("fact retained byte count overflow".into()))?;
            }
            meta.insert(RETAINED_RECORDS_KEY, facts.len().map_err(fact_err)?)
                .map_err(fact_err)?;
            meta.insert(RETAINED_BYTES_KEY, encoded_bytes)
                .map_err(fact_err)?;
        }
        self.commit(txn)
    }

    fn encode_fact(&self, fact: &Fact) -> Result<Vec<u8>, FactError> {
        ensure_fact_schema(fact)?;
        let mut encoding = FactEncoding {
            bytes: Vec::new(),
            limit: self.limits.max_record_bytes.get(),
        };
        serde_json::to_writer(&mut encoding, fact).map_err(fact_err)?;
        Ok(encoding.bytes)
    }

    fn charge(
        &self,
        txn: &redb::WriteTransaction,
        size: usize,
        previous: Option<usize>,
    ) -> Result<(), FactError> {
        if size > self.limits.max_record_bytes.get() {
            return Err(FactError::new("fact record capacity exceeded".into()));
        }
        let mut meta = txn.open_table(FACT_META_TABLE).map_err(fact_err)?;
        let usage = Self::decode_usage(
            meta.get(RETAINED_RECORDS_KEY)
                .map_err(fact_err)?
                .map(|value| value.value()),
            meta.get(RETAINED_BYTES_KEY)
                .map_err(fact_err)?
                .map(|value| value.value()),
        )?
        .ok_or_else(|| FactError::new("fact retention metadata missing".into()))?;
        let records = usage
            .records
            .checked_add(usize::from(previous.is_none()))
            .ok_or_else(|| FactError::new("fact record count overflow".into()))?;
        if previous.is_none() && records > self.limits.max_records.get() {
            return Err(FactError::new("fact record capacity exceeded".into()));
        }
        let encoded_bytes = usage
            .encoded_bytes
            .checked_sub(previous.unwrap_or(0))
            .and_then(|bytes| bytes.checked_add(size))
            .filter(|bytes| *bytes <= self.limits.max_encoded_bytes.get())
            .ok_or_else(|| FactError::new("fact retained byte capacity exceeded".into()))?;
        meta.insert(
            RETAINED_RECORDS_KEY,
            u64::try_from(records).map_err(fact_err)?,
        )
        .map_err(fact_err)?;
        meta.insert(
            RETAINED_BYTES_KEY,
            u64::try_from(encoded_bytes).map_err(fact_err)?,
        )
        .map_err(fact_err)?;
        Ok(())
    }

    fn process_prefix(process: ProcessId) -> String {
        format!("{:020}/", process.get())
    }

    fn process_key(process: ProcessId, slot: u64) -> String {
        format!("{:020}/{:020}", process.get(), slot)
    }

    fn validate_process_index(key: &str, process: ProcessId, slot: u64) -> Result<(), FactError> {
        if key != Self::process_key(process, slot) {
            return Err(FactError::new(format!(
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
        bytes: &[u8],
        old_caller: Option<ProcessId>,
    ) -> Result<(), FactError> {
        {
            let mut table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
            table.insert(slot, bytes).map_err(fact_err)?;
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

    fn existing_fact(
        &self,
        txn: &redb::WriteTransaction,
        slot: u64,
        id: OperationId,
    ) -> Result<(ProcessId, usize), FactError> {
        let table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        let bytes = table.get(slot).map_err(fact_err)?.ok_or_else(|| {
            FactError::new(format!(
                "fact operation index points to missing slot {slot}"
            ))
        })?;
        Ok((
            decode_indexed_fact(bytes.value(), slot, id, None)?.caller,
            bytes.value().len(),
        ))
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

    fn commit(&self, mut txn: WriteTransaction) -> Result<(), FactError> {
        // redb may release its writer lock before returning an I/O error.
        // Keep commit classification serialized with later adapters, without
        // holding the subscriber lock across disk I/O.
        let _notification = txn.defer_notifications();
        self.ensure_open()?;
        let _gate = self.notifications.commit_gate.lock();
        self.ensure_open()?;
        match txn.commit() {
            Ok(()) => Ok(()),
            Err(error @ redb::CommitError::TransactionPoisoned) => Err(fact_err(error)),
            Err(error) => Err(FactError::commit_outcome_unknown(format!(
                "fact commit outcome unknown: {error}"
            ))),
        }
    }

    fn append_slot(txn: &redb::WriteTransaction) -> Result<(u64, u64), FactError> {
        let mut meta = txn.open_table(FACT_META_TABLE).map_err(fact_err)?;
        let slot = meta
            .get(NEXT_CURSOR_KEY)
            .map_err(fact_err)?
            .map(|value| value.value())
            .ok_or_else(|| FactError::new("fact cursor metadata missing".into()))?;
        let next = slot
            .checked_add(1)
            .ok_or_else(|| FactError::new("fact cursor overflow".into()))?;
        meta.insert(NEXT_CURSOR_KEY, next).map_err(fact_err)?;
        Ok((slot, next))
    }
}

impl ExecutionIdSource for RedbFactStore {
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        let closed = |error: FactError| ExecutionIdError::Backend(error.to_string());
        self.ensure_open().map_err(closed)?;
        // Acquire redb's writer before the Fact commit gate. The second check
        // prevents a staged reservation from committing after Fact closure.
        crate::execution_ids::reserve_with_guard(&self.db, count, || {
            let gate = self.notifications.commit_gate.lock();
            self.ensure_open().map_err(closed)?;
            Ok(gate)
        })
    }
}

impl FactStore for RedbFactStore {
    fn append(&self, fact: Fact) -> Result<u64, FactError> {
        self.ensure_open()?;
        ensure_fact_schema(&fact)?;
        let txn = self.db.begin_write().map_err(fact_err)?;
        self.ensure_open()?;
        if let Some(slot) = self.slot_of(&txn, &fact.id)? {
            self.existing_fact(&txn, slot, fact.id)?;
            return Ok(slot);
        }
        let bytes = self.encode_fact(&fact)?;
        self.charge(&txn, bytes.len(), None)?;
        let (slot, next) = Self::append_slot(&txn)?;
        self.store_fact(&txn, slot, &fact, &bytes, None)?;
        self.commit(txn)?;
        self.cursor.fetch_max(next, Ordering::Relaxed);
        self.notifications.send(fact);
        Ok(slot)
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        self.ensure_open()?;
        let bytes = self.encode_fact(&fact)?;
        // The lookup and append decision share the database's writer transaction,
        // including when callers use independently constructed store adapters.
        let txn = self.db.begin_write().map_err(fact_err)?;
        self.ensure_open()?;
        let (slot, next, old_caller) = match self.slot_of(&txn, &fact.id)? {
            Some(slot) => {
                let (caller, previous) = self.existing_fact(&txn, slot, fact.id)?;
                self.charge(&txn, bytes.len(), Some(previous))?;
                (slot, None, Some(caller))
            }
            None => {
                self.charge(&txn, bytes.len(), None)?;
                let (slot, next) = Self::append_slot(&txn)?;
                (slot, Some(next), None)
            }
        };
        self.store_fact(&txn, slot, &fact, &bytes, old_caller)?;
        self.commit(txn)?;
        if let Some(next) = next {
            self.cursor.fetch_max(next, Ordering::Relaxed);
        }
        self.notifications.send(fact);
        Ok(())
    }

    fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        self.ensure_open()?;
        let page = self.scan_page(query)?;
        self.ensure_open()?;
        Ok(page)
    }

    fn lookup(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        self.ensure_open()?;
        let result = self.lookup_record(query)?;
        self.ensure_open()?;
        Ok(result)
    }

    fn facts_of(&self, process: ProcessId) -> Result<Vec<Fact>, FactError> {
        self.ensure_open()?;
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
                FactError::new(format!("fact process index points to missing slot {slot}"))
            })?;
            facts.push(decode_fact(bytes.value(), slot, Some(process))?);
        }
        self.ensure_open()?;
        Ok(facts)
    }

    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        self.ensure_open()?;
        let txn = self.db.begin_read().map_err(fact_err)?;
        let table = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        let mut facts = Vec::new();
        for item in table.iter().map_err(fact_err)? {
            let (slot, bytes) = item.map_err(fact_err)?;
            facts.push(decode_fact(bytes.value(), slot.value(), None)?);
        }
        self.ensure_open()?;
        Ok(facts)
    }

    fn cursor(&self) -> u64 {
        self.cursor.load(Ordering::Relaxed)
    }

    fn observed_cursor(&self) -> Result<u64, FactError> {
        self.ensure_open()?;
        Ok(self.cursor())
    }

    fn subscribe_facts(&self) -> FactStream {
        if self.ensure_open().is_err() {
            let (sender, closed) = broadcast::channel(1);
            drop(sender);
            return closed;
        }
        let stream = self.notifications.subscribe();
        if self.ensure_open().is_ok() {
            stream
        } else {
            let (sender, closed) = broadcast::channel(1);
            drop(sender);
            closed
        }
    }
}

fn ensure_fact_schema(fact: &Fact) -> Result<(), FactError> {
    if fact.schema_version == Fact::SCHEMA_VERSION {
        Ok(())
    } else {
        Err(FactError::new(format!(
            "unsupported Fact schema_version {} (current {})",
            fact.schema_version,
            Fact::SCHEMA_VERSION
        )))
    }
}

#[cfg(test)]
mod commit_fault_tests;
#[cfg(test)]
mod paging_tests;
#[cfg(test)]
mod retention_tests;

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
            caller_identity: Some(IdentityRef::ROOT),
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
