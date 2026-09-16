//! An exclusive, encoded journal with an injectable module publication failure.

use super::*;
use crate::{ExecutionIdError, ExecutionIdRange, ExecutionIdSource, InMemoryExecutionIdSource};
use parking_lot::Mutex;
use std::{collections::BTreeSet, io::Write, num::NonZeroU64};

#[derive(Default)]
pub(super) struct Store {
    ids: InMemoryExecutionIdSource,
    state: Arc<Mutex<Records>>,
    pub reject_linked: Arc<AtomicBool>,
}

#[derive(Default)]
struct Records {
    rows: BTreeMap<ProcessId, Vec<u8>>,
    leased: BTreeSet<ProcessId>,
    high_water: Option<ProcessId>,
}

impl ExecutionIdSource for Store {
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        self.ids.reserve(count)
    }
}

impl CheckpointStore for Store {
    fn try_acquire(
        &self,
        process: ProcessId,
    ) -> Result<Option<Box<dyn CheckpointJournal>>, Failure> {
        if !self.state.lock().leased.insert(process) {
            return Ok(None);
        }
        Ok(Some(Box::new(Journal {
            process,
            state: self.state.clone(),
            reject_linked: self.reject_linked.clone(),
            retired: false,
        })))
    }

    fn high_water(&self) -> Result<Option<ProcessId>, Failure> {
        Ok(self.state.lock().high_water)
    }

    fn scan(&self, query: CheckpointQuery) -> Result<Vec<CheckpointInfo>, Failure> {
        Ok(self
            .state
            .lock()
            .rows
            .iter()
            .filter(|(process, _)| {
                query.after.is_none_or(|after| **process > after) && **process <= query.through
            })
            .take(query.limit.get())
            .map(|(process, bytes)| CheckpointInfo {
                process: *process,
                encoded_bytes: bytes.len(),
            })
            .collect())
    }
}

impl Store {
    pub fn saved(&self, process: ProcessId) -> anyhow::Result<ExecutionSnapshot> {
        self.acquire(process)?
            .load(usize::MAX)?
            .context("missing checkpoint")
    }

    pub fn bytes(&self, process: ProcessId) -> anyhow::Result<Vec<u8>> {
        self.state
            .lock()
            .rows
            .get(&process)
            .cloned()
            .context("missing checkpoint bytes")
    }

    pub fn replace(&self, process: ProcessId, bytes: Vec<u8>) {
        self.state.lock().rows.insert(process, bytes);
    }
}

struct Journal {
    process: ProcessId,
    state: Arc<Mutex<Records>>,
    reject_linked: Arc<AtomicBool>,
    retired: bool,
}

impl Drop for Journal {
    fn drop(&mut self) {
        self.state.lock().leased.remove(&self.process);
    }
}

impl CheckpointJournal for Journal {
    fn load(&mut self, max_bytes: usize) -> Result<Option<ExecutionSnapshot>, Failure> {
        let state = self.state.lock();
        let Some(bytes) = state.rows.get(&self.process) else {
            return Ok(None);
        };
        if bytes.len() > max_bytes {
            return Err(machine_error("test checkpoint byte limit"));
        }
        let saved: ExecutionSnapshot =
            serde_json::from_slice(bytes).map_err(|error| machine_error(error.to_string()))?;
        if saved.process.id != self.process {
            return Err(machine_error("test checkpoint owner mismatch"));
        }
        Ok(Some(saved))
    }

    fn commit(
        &mut self,
        checkpoint: &ExecutionCheckpoint<'_>,
        max_bytes: usize,
    ) -> Result<(), Failure> {
        if self.retired || checkpoint.process() != self.process {
            return Err(machine_error(
                "test journal is retired or belongs to another process",
            ));
        }
        if checkpoint.machine.continuations().next().is_some()
            && self.reject_linked.swap(false, Ordering::SeqCst)
        {
            return Err(machine_error("injected module publication failure"));
        }
        let mut encoded = LimitedBytes {
            bytes: Vec::new(),
            limit: max_bytes,
        };
        serde_json::to_writer(&mut encoded, checkpoint)
            .map_err(|error| machine_error(error.to_string()))?;
        let mut state = self.state.lock();
        state.rows.insert(self.process, encoded.bytes);
        state.high_water = Some(
            state
                .high_water
                .map_or(self.process, |value| value.max(self.process)),
        );
        Ok(())
    }

    fn retire(&mut self) -> Result<(), Failure> {
        self.state.lock().rows.remove(&self.process);
        self.retired = true;
        Ok(())
    }
}

struct LimitedBytes {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for LimitedBytes {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("test checkpoint byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
