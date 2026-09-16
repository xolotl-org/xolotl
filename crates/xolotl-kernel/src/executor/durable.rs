//! Optional persistence for the same execution machine used by volatile hosts.
//!
//! A store must grant exclusive ownership of each process journal and make every
//! commit durable before returning. Pending non-idempotent requests are held for
//! reconciliation; restoring a checkpoint never silently repeats them.

use super::{
    Executor, PreparedProgram,
    image::{Import, MachineProgram},
    machine_error,
};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use xolotl_core::{Checkpoint, CheckpointMeta, Execution, Frame, Task};
use xolotl_state::TaintedValue;
use xolotl_types::{ExecutionId, ExecutionOutput, Failure, ProcessId, ReplayClass, TaintedFailure};

pub use crate::process::ProcessSnapshot;

mod codec;
mod imports;
#[cfg(test)]
mod module_tests;

/// Hosted journal format, independent of the allocation-free core checkpoint version.
pub const EXECUTION_CHECKPOINT_VERSION: u32 = 1;

/// Owned storage representation of the allocation-free core checkpoint.
#[derive(Clone)]
pub struct MachineSnapshot {
    /// Version, image identity, layout and scheduling counters.
    pub meta: CheckpointMeta,
    /// Fixed task slots at the last committed boundary.
    pub tasks: Vec<Task<TaintedValue, TaintedFailure>>,
    /// Continuations, including lexical and cleanup scopes.
    pub frames: Vec<Option<Frame<TaintedValue, TaintedFailure>>>,
    /// Lexical values with exact types and provenance.
    pub bindings: Vec<Option<TaintedValue>>,
}

impl MachineSnapshot {
    /// Borrow persisted storage for validation and restoration by the core.
    pub fn checkpoint(&self) -> Checkpoint<'_, TaintedValue, TaintedFailure> {
        Checkpoint {
            meta: self.meta,
            tasks: &self.tasks,
            frames: &self.frames,
            bindings: &self.bindings,
        }
    }
}

/// A self-contained restart artifact; it contains no native closures or handles.
#[derive(Clone)]
pub struct ExecutionSnapshot {
    /// Journal format version.
    pub version: u32,
    /// Identity scope of this execution, reused by every restored request.
    pub execution: ExecutionId,
    /// Process context to re-admit before resuming.
    pub process: ProcessSnapshot,
    /// Frozen, portable instructions and host imports.
    pub program: PreparedProgram,
    /// State of every structured task.
    pub machine: MachineSnapshot,
    /// Requests that may have reached an external driver before the crash.
    pub pending: BTreeMap<u64, ReplayClass>,
    /// True after a terminal machine result was committed.
    pub finished: bool,
}

/// Borrowed write view; serialization indexes shared values without cloning payloads.
pub struct ExecutionCheckpoint<'a> {
    version: u32,
    execution: ExecutionId,
    process: ProcessSnapshot,
    program: &'a MachineProgram,
    machine: Checkpoint<'a, TaintedValue, TaintedFailure>,
    pending: &'a BTreeMap<u64, ReplayClass>,
    finished: bool,
}

impl ExecutionCheckpoint<'_> {
    /// Owner whose exclusive journal must receive this checkpoint.
    pub fn process(&self) -> ProcessId {
        self.process.id
    }
}

/// Bounded, ascending scan of active checkpoint keys in `(after, through]`.
/// The upper bound freezes a key range, not payload revisions. Late insertions
/// below the cursor are visible on the next scan from the beginning.
#[derive(Clone, Copy, Debug)]
pub struct CheckpointQuery {
    /// Exclusive lower bound; `None` starts at the first key.
    pub after: Option<ProcessId>,
    /// Inclusive upper bound, normally captured from the store's high water.
    pub through: ProcessId,
    /// Maximum number of entries to return, without decoding their payloads.
    pub limit: NonZeroUsize,
}

/// Lightweight directory entry; the leased load must recheck size and ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointInfo {
    /// Canonical storage key, independent of serialized process fields.
    pub process: ProcessId,
    /// Encoded size at enumeration time; concurrent commits may change it.
    pub encoded_bytes: usize,
}

/// Exclusive journal lease. Dropping it must release ownership.
pub trait CheckpointJournal: Send {
    /// Check encoded size before decoding or copying the last committed snapshot.
    /// The payload owner must match the leased key. Failures are never absence.
    fn load(&mut self, max_bytes: usize) -> Result<Option<ExecutionSnapshot>, Failure>;
    /// Serialize within the byte limit, then atomically persist and flush.
    /// Failure leaves the previous checkpoint and identity high water intact.
    fn commit(
        &mut self,
        checkpoint: &ExecutionCheckpoint<'_>,
        max_bytes: usize,
    ) -> Result<(), Failure>;
    /// Durably remove the active row after lifecycle publication has succeeded.
    /// Preserve identity reservations and reject further commits on this lease.
    /// Idempotent; a failed retirement must leave recovery evidence available.
    fn retire(&mut self) -> Result<(), Failure>;
}

/// Host storage contract. Implementations must exclude concurrent execution of one process.
/// Identity reservations must remain durable even after the corresponding journals are removed.
/// One live host owns the process namespace: reserve its high water before creating
/// application processes. Sharing storage with another live host requires a separate
/// process identity allocator and explicit coordination, not just journal leases.
pub trait CheckpointStore: crate::ExecutionIdSource {
    /// Try to acquire a lease. `None` means busy, not a missing checkpoint.
    fn try_acquire(
        &self,
        process: ProcessId,
    ) -> Result<Option<Box<dyn CheckpointJournal>>, Failure>;
    /// Greatest committed or retired process key, retained after every row is removed.
    fn high_water(&self) -> Result<Option<ProcessId>, Failure>;
    /// Return at most `limit` unique entries, strictly ascending within the bounds.
    /// Enumerating keys must not decode or copy complete checkpoint payloads.
    fn scan(&self, query: CheckpointQuery) -> Result<Vec<CheckpointInfo>, Failure>;

    /// Acquire an exclusive lease, reporting contention as a failure.
    fn acquire(&self, process: ProcessId) -> Result<Box<dyn CheckpointJournal>, Failure> {
        self.try_acquire(process)?
            .ok_or_else(|| machine_error("process journal is already leased"))
    }

    /// Explicit, unbounded inspection of all active records. This may fail when
    /// a record is leased. Recovery hosts must use [`Self::scan`] and bounded loads.
    fn snapshots(&self) -> Result<Vec<ExecutionSnapshot>, Failure> {
        let Some(through) = self.high_water()? else {
            return Ok(Vec::new());
        };
        let mut after = None;
        let mut snapshots = Vec::new();
        loop {
            let entries = self.scan(CheckpointQuery {
                after,
                through,
                limit: NonZeroUsize::MIN.saturating_add(63),
            })?;
            if entries.is_empty() {
                return Ok(snapshots);
            }
            for entry in entries {
                if after.is_some_and(|after| entry.process <= after) || entry.process > through {
                    return Err(machine_error("checkpoint catalog is not strictly ordered"));
                }
                after = Some(entry.process);
                if let Some(saved) = self.acquire(entry.process)?.load(usize::MAX)? {
                    snapshots.push(saved);
                }
            }
        }
    }
}

pub(crate) struct JournalRun {
    journal: Box<dyn CheckpointJournal>,
    pub execution: ExecutionId,
    pub restored: Option<ExecutionSnapshot>,
    pub pending: BTreeMap<u64, ReplayClass>,
    pub finished: bool,
}

impl JournalRun {
    pub(super) fn open(
        executor: &Executor,
        program: &MachineProgram,
    ) -> Result<Option<Self>, Failure> {
        if !program.durable {
            return Ok(None);
        }
        if !program.portable {
            return Err(machine_error("durable execution requires a portable image"));
        }
        let store = executor
            .checkpoint_store
            .as_ref()
            .ok_or_else(|| machine_error("DurableUnavailable: no checkpoint store"))?;
        let mut journal = store.acquire(executor.process)?;
        let restored = journal.load(executor.execution_config.max_checkpoint_bytes)?;
        if restored.is_none() {
            executor.validate_durable_imports(program, false)?;
        }
        Self::from_loaded(executor, program, journal, restored).map(Some)
    }

    pub(crate) fn resume(
        executor: &Executor,
        journal: Box<dyn CheckpointJournal>,
        saved: ExecutionSnapshot,
    ) -> Result<Self, Failure> {
        let program = saved.program.clone();
        executor.validate_checkpoint(&saved)?;
        Self::from_loaded(executor, &program.inner, journal, Some(saved))
    }

    fn from_loaded(
        executor: &Executor,
        program: &MachineProgram,
        journal: Box<dyn CheckpointJournal>,
        mut restored: Option<ExecutionSnapshot>,
    ) -> Result<Self, Failure> {
        if restored.is_none()
            && executor
                .processes
                .as_ref()
                .and_then(|processes| processes.checkpoint_committed(executor.process))
                == Some(true)
        {
            return Err(machine_error(
                "checkpoint is missing for an already durable process",
            ));
        }
        let execution = match &restored {
            Some(saved) => saved.execution,
            None => executor.allocate_execution()?,
        };
        if executor
            .processes
            .as_ref()
            .and_then(|processes| processes.snapshot(executor.process))
            .is_none()
            || !executor.registry.grants_of(executor.process).is_empty()
        {
            return Err(machine_error(
                "durable execution requires a root-owned request with attached grants and no native finalizers",
            ));
        }
        let pending = if let Some(saved) = &mut restored {
            if saved.version != EXECUTION_CHECKPOINT_VERSION
                || saved.program.inner.id != program.id
                || saved.process.id != executor.process
            {
                return Err(machine_error("checkpoint owner, version or image mismatch"));
            }
            executor.validate_checkpoint(saved)?;
            if !saved.finished {
                executor.validate_checkpoint_replay(saved)?;
            }
            let current = executor
                .processes
                .as_ref()
                .and_then(|processes| processes.snapshot(executor.process))
                .ok_or_else(|| machine_error("missing checkpoint process context"))?;
            if current.identity != saved.process.identity
                || current.parent != saved.process.parent
                || current.grants != saved.process.grants
                || current.lifecycle_execution != saved.process.lifecycle_execution
            {
                return Err(machine_error("checkpoint process authority mismatch"));
            }
            std::mem::take(&mut saved.pending)
        } else {
            BTreeMap::new()
        };
        let processes = executor
            .processes
            .as_ref()
            .ok_or_else(|| machine_error("missing checkpoint process table"))?;
        let lifecycle = processes
            .lifecycle_execution(executor.process)
            .ok_or_else(|| machine_error("missing checkpoint lifecycle"))?;
        processes
            .require_checkpoint(executor.process, lifecycle)
            .map_err(|error| machine_error(error.to_string()))?;
        if restored.is_some() {
            processes
                .confirm_checkpoint(executor.process, lifecycle)
                .map_err(|error| machine_error(error.to_string()))?;
        }
        let finished = restored.as_ref().is_some_and(|saved| saved.finished);
        Ok(Self {
            journal,
            execution,
            restored,
            pending,
            finished,
        })
    }

    pub(crate) fn journal(&mut self) -> &mut (dyn CheckpointJournal + 'static) {
        self.journal.as_mut()
    }

    pub(super) fn commit(
        &mut self,
        executor: &Executor,
        program: &MachineProgram,
        execution: &Execution<'_, TaintedValue, TaintedFailure>,
        finished: bool,
    ) -> Result<(), Failure> {
        let mut process = executor
            .processes
            .as_ref()
            .and_then(|processes| processes.snapshot(executor.process))
            .ok_or_else(|| machine_error("durable execution requires a live process context"))?;
        // Dispatch is journaled before the future reserves its budget. Include
        // pending estimates so a crash cannot erase spending on uncertain calls.
        // An already-reserved request may be counted twice, deliberately failing closed.
        for request in execution.pending_requests(&program.image()) {
            if let Some(Import::Operation(operation, _)) =
                program.imports.get(request.import as usize)
                && let Some(meta) = executor.resolve_meta(&operation.target, &operation.method)
                && !meta.cost.is_free()
            {
                let input = operation
                    .literal_input
                    .as_ref()
                    .unwrap_or(&request.input.value);
                let tokens = crate::invocation::billable_input_tokens(input);
                let cost = crate::invocation::estimate_cost(
                    &meta.cost,
                    input,
                    tokens,
                    tokens,
                    meta.batchable,
                );
                process.budget.spent_micro_usd =
                    process.budget.spent_micro_usd.saturating_add(cost);
                process.budget.inference_tokens =
                    process.budget.inference_tokens.saturating_add(tokens);
            }
        }
        let lifecycle = process.lifecycle_execution;
        self.journal.commit(
            &ExecutionCheckpoint {
                version: EXECUTION_CHECKPOINT_VERSION,
                execution: self.execution,
                process,
                program,
                machine: execution.checkpoint(),
                pending: &self.pending,
                finished,
            },
            executor.execution_config.max_checkpoint_bytes,
        )?;
        executor
            .processes
            .as_ref()
            .ok_or_else(|| machine_error("missing checkpoint process table"))?
            .confirm_checkpoint(executor.process, lifecycle)
            .map_err(|error| machine_error(error.to_string()))?;
        self.finished = finished;
        Ok(())
    }
}

impl Executor {
    pub(crate) fn validate_checkpoint_replay(
        &self,
        saved: &ExecutionSnapshot,
    ) -> Result<(), Failure> {
        self.validate_checkpoint_imports(&saved.program)?;
        let image = saved.program.inner.image();
        for request in saved.machine.checkpoint().pending_requests(&image) {
            let import = saved
                .program
                .inner
                .imports
                .get(request.import as usize)
                .ok_or_else(|| machine_error("missing checkpoint import"))?;
            if saved.pending.get(&request.ticket) != Some(&self.checkpoint_replay_class(import)) {
                return Err(Failure::Quarantined {
                    op_id: self
                        .request_id(saved.execution, request.ticket, request.position)?
                        .to_string(),
                    reason: "pending request replay contract changed".into(),
                });
            }
        }
        Ok(())
    }

    pub(super) fn checkpoint_replay_class(&self, import: &Import) -> ReplayClass {
        if let Import::Operation(operation, _) = import {
            self.resolve_meta(&operation.target, &operation.method)
                .map_or(ReplayClass::NonIdempotentEffect, |meta| meta.replay)
        } else {
            ReplayClass::Deterministic
        }
    }

    pub(crate) fn validate_checkpoint(&self, saved: &ExecutionSnapshot) -> Result<(), Failure> {
        let program = &saved.program.inner;
        if saved.version != EXECUTION_CHECKPOINT_VERSION
            || !program.durable
            || !program.portable
            || program
                .imports
                .iter()
                .any(|import| matches!(import, Import::Step(_, None)))
        {
            return Err(machine_error("unsupported checkpoint image or version"));
        }
        let checkpoint = saved.machine.checkpoint();
        self.execution_config
            .restored_layout(program, &checkpoint)?;
        Execution::validate_checkpoint(&program.image(), &checkpoint, true)
            .map_err(|error| machine_error(format!("checkpoint: {error:?}")))?;
        program.validate_arena_checkpoint(&checkpoint)?;
        if (saved.finished && checkpoint.result().is_none())
            || checkpoint.pending_tickets().count() != saved.pending.len()
            || checkpoint
                .pending_tickets()
                .any(|ticket| !saved.pending.contains_key(&ticket))
        {
            return Err(machine_error(
                "checkpoint result or pending requests mismatch",
            ));
        }
        Ok(())
    }

    pub(crate) async fn resume_checkpoint(
        &self,
        program: &PreparedProgram,
        journal: &mut JournalRun,
    ) -> ExecutionOutput {
        self.run_machine_with_buffers(
            std::borrow::Cow::Borrowed(&program.inner),
            TaintedValue::pristine(xolotl_types::Value::null()),
            &mut super::ExecutionBuffers::default(),
            None,
            Some(journal),
        )
        .await
    }
}
