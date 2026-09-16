use crate::{CHECKPOINT_META_TABLE, CHECKPOINTS_TABLE};
use parking_lot::Mutex;
use redb::{Database, Durability, ReadableDatabase, ReadableTable};
use std::{
    collections::BTreeSet,
    io::{self, Write},
    num::NonZeroU64,
    ops::Bound,
    sync::Arc,
};
use xolotl_kernel::executor::durable::{
    CheckpointInfo, CheckpointJournal, CheckpointQuery, CheckpointStore,
    EXECUTION_CHECKPOINT_VERSION, ExecutionCheckpoint, ExecutionSnapshot,
};
use xolotl_kernel::{ExecutionIdError, ExecutionIdRange, ExecutionIdSource};
use xolotl_types::{Failure, ProcessId};

use crate::schema::CHECKPOINT_HIGH_WATER as PROCESS_HIGH_WATER;

/// Atomic, immediately durable checkpoints, independently selectable from state and facts.
#[derive(Clone)]
pub struct RedbCheckpointStore {
    pub(crate) db: Arc<Database>,
    pub(crate) leases: Arc<Mutex<BTreeSet<ProcessId>>>,
}

impl CheckpointStore for RedbCheckpointStore {
    fn try_acquire(
        &self,
        process: ProcessId,
    ) -> Result<Option<Box<dyn CheckpointJournal>>, Failure> {
        if !self.leases.lock().insert(process) {
            return Ok(None);
        }
        Ok(Some(Box::new(Journal {
            store: self.clone(),
            process,
            retired: false,
        })))
    }

    fn high_water(&self) -> Result<Option<ProcessId>, Failure> {
        let txn = self.db.begin_read().map_err(storage_error)?;
        let meta = txn
            .open_table(CHECKPOINT_META_TABLE)
            .map_err(storage_error)?;
        let encoded = meta
            .get(PROCESS_HIGH_WATER)
            .map_err(storage_error)?
            .ok_or_else(|| storage_error("checkpoint metadata missing"))?
            .value();
        encoded
            .checked_sub(1)
            .map(|value| {
                u64::try_from(value)
                    .map(ProcessId::new)
                    .map_err(storage_error)
            })
            .transpose()
    }

    fn scan(&self, query: CheckpointQuery) -> Result<Vec<CheckpointInfo>, Failure> {
        if query.after.is_some_and(|after| after > query.through) {
            return Err(storage_error(
                "checkpoint scan starts after its upper bound",
            ));
        }
        if query.after == Some(query.through) {
            return Ok(Vec::new());
        }
        let txn = self.db.begin_read().map_err(storage_error)?;
        let table = txn.open_table(CHECKPOINTS_TABLE).map_err(storage_error)?;
        let lower = query
            .after
            .map_or(Bound::Unbounded, |after| Bound::Excluded(after.get()));
        let mut entries = Vec::new();
        for entry in table
            .range((lower, Bound::Included(query.through.get())))
            .map_err(storage_error)?
            .take(query.limit.get())
        {
            let (key, value) = entry.map_err(storage_error)?;
            entries.try_reserve(1).map_err(storage_error)?;
            entries.push(CheckpointInfo {
                process: ProcessId::new(key.value()),
                encoded_bytes: value.value().len(),
            });
        }
        Ok(entries)
    }

    fn snapshots(&self) -> Result<Vec<ExecutionSnapshot>, Failure> {
        let txn = self.db.begin_read().map_err(storage_error)?;
        let table = txn.open_table(CHECKPOINTS_TABLE).map_err(storage_error)?;
        let mut snapshots = Vec::new();
        for entry in table.iter().map_err(storage_error)? {
            let (key, value) = entry.map_err(storage_error)?;
            let saved = decode(ProcessId::new(key.value()), value.value(), usize::MAX)?;
            snapshots.try_reserve(1).map_err(storage_error)?;
            snapshots.push(saved);
        }
        Ok(snapshots)
    }
}

impl ExecutionIdSource for RedbCheckpointStore {
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        crate::execution_ids::reserve(&self.db, count)
    }
}

struct Journal {
    store: RedbCheckpointStore,
    process: ProcessId,
    retired: bool,
}

impl CheckpointJournal for Journal {
    fn load(&mut self, max_bytes: usize) -> Result<Option<ExecutionSnapshot>, Failure> {
        if self.retired {
            return Ok(None);
        }
        let txn = self.store.db.begin_read().map_err(storage_error)?;
        let table = txn.open_table(CHECKPOINTS_TABLE).map_err(storage_error)?;
        table
            .get(self.process.get())
            .map_err(storage_error)?
            .map(|entry| decode(self.process, entry.value(), max_bytes))
            .transpose()
    }

    fn commit(
        &mut self,
        checkpoint: &ExecutionCheckpoint<'_>,
        max_bytes: usize,
    ) -> Result<(), Failure> {
        if self.retired {
            return Err(storage_error("cannot commit a retired journal lease"));
        }
        if checkpoint.process() != self.process {
            return Err(storage_error("checkpoint owner mismatch"));
        }
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            limit: max_bytes,
        };
        serde_json::to_writer(&mut writer, checkpoint).map_err(storage_error)?;
        let mut txn = self.store.db.begin_write().map_err(storage_error)?;
        txn.set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        {
            let mut table = txn.open_table(CHECKPOINTS_TABLE).map_err(storage_error)?;
            table
                .insert(self.process.get(), writer.bytes.as_slice())
                .map_err(storage_error)?;
        }
        preserve_high_water(&txn, self.process)?;
        txn.commit().map_err(storage_error)
    }

    fn retire(&mut self) -> Result<(), Failure> {
        if self.retired {
            return Ok(());
        }
        let mut txn = self.store.db.begin_write().map_err(storage_error)?;
        txn.set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        txn.open_table(CHECKPOINTS_TABLE)
            .map_err(storage_error)?
            .remove(self.process.get())
            .map_err(storage_error)?;
        preserve_high_water(&txn, self.process)?;
        txn.commit().map_err(storage_error)?;
        self.retired = true;
        Ok(())
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        self.store.leases.lock().remove(&self.process);
    }
}

fn storage_error(error: impl std::fmt::Display) -> Failure {
    Failure::Custom {
        kind: "checkpoint_store".into(),
        message: error.to_string(),
    }
}

fn preserve_high_water(txn: &redb::WriteTransaction, process: ProcessId) -> Result<(), Failure> {
    let mut meta = txn
        .open_table(CHECKPOINT_META_TABLE)
        .map_err(storage_error)?;
    let previous = meta
        .get(PROCESS_HIGH_WATER)
        .map_err(storage_error)?
        .ok_or_else(|| storage_error("checkpoint metadata missing"))?
        .value();
    if previous > u128::from(u64::MAX) + 1 {
        return Err(storage_error(
            "checkpoint high water exceeds process identity range",
        ));
    }
    let encoded = u128::from(process.get()) + 1;
    if encoded > previous {
        meta.insert(PROCESS_HIGH_WATER, encoded)
            .map_err(storage_error)?;
    }
    Ok(())
}

fn decode(
    process: ProcessId,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<ExecutionSnapshot, Failure> {
    if bytes.len() > max_bytes {
        return Err(storage_error(format!(
            "checkpoint for process {process} exceeds encoded byte limit {max_bytes}"
        )));
    }
    let saved: ExecutionSnapshot = serde_json::from_slice(bytes).map_err(storage_error)?;
    if saved.version != EXECUTION_CHECKPOINT_VERSION {
        return Err(storage_error("unsupported execution checkpoint version"));
    }
    if saved.process.id != process {
        return Err(storage_error("checkpoint owner mismatch"));
    }
    Ok(saved)
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::Error::other(format!(
                "checkpoint encoding exceeds byte limit {}",
                self.limit
            )));
        }
        let required = self.bytes.len() + bytes.len();
        if required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().saturating_mul(2).max(128))
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RedbStore;
    use anyhow::{Context, ensure};
    use std::num::NonZeroUsize;

    fn query(after: Option<u64>, through: u64, limit: usize) -> anyhow::Result<CheckpointQuery> {
        Ok(CheckpointQuery {
            after: after.map(ProcessId::new),
            through: ProcessId::new(through),
            limit: NonZeroUsize::new(limit).context("nonzero page limit")?,
        })
    }

    fn raw_record(db: &Database, process: u64, bytes: &[u8]) -> anyhow::Result<()> {
        let txn = db.begin_write()?;
        txn.open_table(CHECKPOINTS_TABLE)?.insert(process, bytes)?;
        preserve_high_water(&txn, ProcessId::new(process))?;
        txn.commit()?;
        Ok(())
    }

    #[test]
    fn directory_pages_do_not_decode_and_cover_sparse_boundary_keys() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let store = RedbStore::open(directory.path().join("pages.redb"))?;
        let checkpoints = store.checkpoint_store();
        ensure!(checkpoints.high_water()?.is_none());
        ensure!(checkpoints.scan(query(None, 0, usize::MAX)?)?.is_empty());
        for (process, payload) in [
            (0, b"a".as_slice()),
            (7, b"invalid"),
            (u64::MAX - 1, b"x"),
            (u64::MAX, b"last"),
        ] {
            raw_record(&store.db, process, payload)?;
        }

        let page = checkpoints.scan(query(None, u64::MAX, 2)?)?;
        ensure!(
            page == [
                CheckpointInfo {
                    process: ProcessId::new(0),
                    encoded_bytes: 1
                },
                CheckpointInfo {
                    process: ProcessId::new(7),
                    encoded_bytes: 7
                },
            ]
        );
        let page = checkpoints.scan(query(Some(7), u64::MAX, 2)?)?;
        ensure!(
            page == [
                CheckpointInfo {
                    process: ProcessId::new(u64::MAX - 1),
                    encoded_bytes: 1
                },
                CheckpointInfo {
                    process: ProcessId::new(u64::MAX),
                    encoded_bytes: 4
                },
            ]
        );
        ensure!(
            checkpoints
                .scan(query(Some(u64::MAX), u64::MAX, usize::MAX)?)?
                .is_empty()
        );
        ensure!(checkpoints.scan(query(Some(8), 7, 1)?).is_err());
        ensure!(checkpoints.snapshots().is_err());

        raw_record(&store.db, 7, b"changed size")?;
        raw_record(&store.db, 3, b"late")?;
        checkpoints
            .acquire(ProcessId::new(u64::MAX - 1))?
            .retire()?;
        ensure!(
            checkpoints
                .scan(query(Some(7), u64::MAX - 1, 1)?)?
                .is_empty()
        );
        let page = checkpoints.scan(query(None, 7, usize::MAX)?)?;
        ensure!(
            page.iter()
                .map(|entry| entry.process.get())
                .collect::<Vec<_>>()
                == [0, 3, 7]
        );
        ensure!(page[1].encoded_bytes == 4 && page[2].encoded_bytes == 12);
        Ok(())
    }

    #[test]
    fn an_empty_store_and_a_retired_zero_key_have_distinct_high_water() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("zero-key.redb");
        {
            let store = RedbStore::open(&path)?;
            ensure!(store.checkpoint_store().high_water()?.is_none());
            raw_record(&store.db, 0, b"opaque")?;
        }
        {
            let store = RedbStore::open(&path)?;
            let checkpoints = store.checkpoint_store();
            ensure!(checkpoints.high_water()? == Some(ProcessId::new(0)));
            checkpoints.acquire(ProcessId::new(0))?.retire()?;
        }
        let store = RedbStore::open(&path)?;
        let checkpoints = store.checkpoint_store();
        ensure!(checkpoints.high_water()? == Some(ProcessId::new(0)));
        ensure!(checkpoints.scan(query(None, 0, 1)?)?.is_empty());
        Ok(())
    }

    #[test]
    fn full_width_high_water_survives_retirement_and_reopen() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("high-water.redb");
        {
            let store = RedbStore::open(&path)?;
            raw_record(&store.db, 0, b"opaque payload is not decoded")?;
            raw_record(&store.db, u64::MAX, b"invalid payload")?;
        }
        {
            let store = RedbStore::open(&path)?;
            let checkpoints = store.checkpoint_store();
            ensure!(checkpoints.high_water()? == Some(ProcessId::new(u64::MAX)));
            let mut highest = checkpoints.acquire(ProcessId::new(u64::MAX))?;
            highest.retire()?;
            highest.retire()?;
            ensure!(highest.load(0)?.is_none());
            ensure!(checkpoints.try_acquire(ProcessId::new(u64::MAX))?.is_none());
            ensure!(checkpoints.high_water()? == Some(ProcessId::new(u64::MAX)));
            checkpoints.acquire(ProcessId::new(0))?.retire()?;
            ensure!(checkpoints.snapshots()?.is_empty());
        }
        let store = RedbStore::open(&path)?;
        let checkpoints = store.checkpoint_store();
        ensure!(checkpoints.high_water()? == Some(ProcessId::new(u64::MAX)));
        ensure!(
            checkpoints
                .scan(query(None, u64::MAX, usize::MAX)?)?
                .is_empty()
        );
        ensure!(
            checkpoints
                .acquire(ProcessId::new(u64::MAX))?
                .load(0)?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn bounded_load_checks_length_before_decoding_and_reports_corruption() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let store = RedbStore::open(directory.path().join("limits.redb"))?;
        let checkpoints = store.checkpoint_store();
        let process = ProcessId::new(9);
        raw_record(&store.db, process.get(), b"corrupt")?;
        let mut lease = checkpoints.acquire(process)?;
        ensure!(checkpoints.try_acquire(process)?.is_none());
        ensure!(checkpoints.acquire(process).is_err());
        let error = lease.load(6).err().context("length limit must fail")?;
        ensure!(error.to_string().contains("encoded byte limit 6"));
        let error = lease.load(7).err().context("invalid JSON must fail")?;
        ensure!(!error.to_string().contains("byte limit"));
        drop(lease);
        ensure!(checkpoints.try_acquire(process)?.is_some());
        ensure!(checkpoints.acquire(ProcessId::new(10))?.load(0)?.is_none());
        ensure!(checkpoints.high_water()? == Some(process));
        Ok(())
    }

    #[test]
    fn bounded_encoding_counts_escaping_and_rejects_before_growing_past_limit() -> anyhow::Result<()>
    {
        let value = "\"quoted\"\\\n".repeat(128);
        let expected = serde_json::to_vec(&value)?;
        for limit in [0, 1, expected.len() - 1, expected.len()] {
            let mut writer = BoundedWriter {
                bytes: Vec::new(),
                limit,
            };
            let result = serde_json::to_writer(&mut writer, &value);
            ensure!(writer.bytes.len() <= limit);
            ensure!(writer.bytes.capacity() <= limit);
            if limit == expected.len() {
                result?;
                ensure!(writer.bytes == expected);
            } else {
                ensure!(result.is_err());
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn loads_and_diagnostic_snapshots_validate_the_canonical_owner() -> anyhow::Result<()> {
        use xolotl_graph::portable::{Expression as E, Program};
        use xolotl_kernel::{Bootstrap, Kernel};
        use xolotl_types::{IdentityRef, Outcome, TaintedValue, Value};

        let directory = tempfile::tempdir()?;
        let store = RedbStore::open(directory.path().join("owner.redb"))?;
        let checkpoints = Arc::new(store.checkpoint_store());
        let boot =
            Bootstrap::from_kernel(Kernel::in_memory().with_checkpoint_store(checkpoints.clone()));
        let process = boot.spawn_request_process_under_with_compiled_request_grants(
            boot.root,
            IdentityRef::ROOT,
            &[],
        )?;
        let mut source = Program::new(E::literal(7_i64));
        source.durable = true;
        let output = boot
            .kernel
            .executor_for(process)
            .eval_program(&source.compile()?, TaintedValue::pristine(Value::null()))
            .await;
        ensure!(output.outcome == Outcome::Done(Value::integer(7)));
        let mut lease = checkpoints.acquire(process)?;
        let saved = lease.load(usize::MAX)?.context("committed snapshot")?;
        ensure!(checkpoints.snapshots()?.len() == 1);
        let mut value = serde_json::to_value(saved)?;
        value["version"] = serde_json::to_value(EXECUTION_CHECKPOINT_VERSION - 1)?;
        raw_record(&store.db, process.get(), &serde_json::to_vec(&value)?)?;
        ensure!(
            lease
                .load(usize::MAX)
                .err()
                .context("old checkpoint must fail")?
                .to_string()
                .contains("version")
        );
        value["version"] = serde_json::to_value(EXECUTION_CHECKPOINT_VERSION)?;
        value["process"]["id"] = serde_json::to_value(ProcessId::new(process.get() + 1))?;
        raw_record(&store.db, process.get(), &serde_json::to_vec(&value)?)?;
        ensure!(
            lease
                .load(usize::MAX)
                .err()
                .context("owner mismatch must fail")?
                .to_string()
                .contains("owner mismatch")
        );
        ensure!(
            checkpoints
                .snapshots()
                .err()
                .context("diagnostic owner mismatch must fail")?
                .to_string()
                .contains("owner mismatch")
        );
        let page = checkpoints.scan(query(None, process.get(), 1)?)?;
        ensure!(page.len() == 1 && page[0].process == process);
        Ok(())
    }
}
