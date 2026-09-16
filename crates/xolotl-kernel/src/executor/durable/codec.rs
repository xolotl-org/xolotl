//! One value table owns every resident root in the complete checkpoint.
//!
//! Core state is adapted through its generic mapping methods. This module never
//! duplicates private task/frame layouts, expands values into JSON trees, or
//! clones resident payloads while encoding. Decoding transfers provenance and
//! resolves all roots before publishing an owned snapshot.

use super::{
    EXECUTION_CHECKPOINT_VERSION, ExecutionCheckpoint, ExecutionSnapshot, MachineProgram,
    MachineSnapshot, PreparedProgram, ProcessSnapshot,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeMap, sync::Arc};
use xolotl_core::{Checkpoint, CheckpointMeta, Frame, Node, Task};
use xolotl_types::{
    ExecutionId, ReplayClass, TaintSet, TaintedFailure, TaintedValue, Value,
    tagged_value::{ValueRoot, ValueTableDecoder, ValueTableEncodeError, ValueTableEncoder},
};

mod imports;
use imports::ImportRecord;

#[cfg(test)]
mod tests;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ValueReference<T> {
    value: ValueRoot,
    taint: T,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramRecord<'a, V, E> {
    nodes: Vec<Node<V, E>>,
    imports: Vec<ImportRecord<'a>>,
    entry: u32,
    bindings: usize,
    portable: bool,
    durable: bool,
    id: [u8; 32],
    arena: Option<crate::executor::image::ArenaSnapshot>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MachineRecord<V, E> {
    meta: CheckpointMeta,
    tasks: Vec<Task<V, E>>,
    frames: Vec<Option<Frame<V, E>>>,
    bindings: Vec<Option<V>>,
}

#[derive(Serialize)]
struct WriteCheckpoint<'a> {
    version: u32,
    execution: ExecutionId,
    process: &'a ProcessSnapshot,
    program: ProgramRecord<'a, ValueReference<&'a TaintSet>, &'a TaintedFailure>,
    machine: MachineRecord<ValueReference<&'a TaintSet>, &'a TaintedFailure>,
    pending: &'a BTreeMap<u64, ReplayClass>,
    finished: bool,
    values: ValueTableEncoder<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadCheckpoint {
    version: u32,
    execution: ExecutionId,
    process: ProcessSnapshot,
    program: ProgramRecord<'static, ValueReference<TaintSet>, TaintedFailure>,
    machine: MachineRecord<ValueReference<TaintSet>, TaintedFailure>,
    pending: BTreeMap<u64, ReplayClass>,
    finished: bool,
    values: ValueTableDecoder,
}

impl<'a> WriteCheckpoint<'a> {
    fn new(
        version: u32,
        execution: ExecutionId,
        process: &'a ProcessSnapshot,
        program: &'a MachineProgram,
        machine: Checkpoint<'a, TaintedValue, TaintedFailure>,
        pending: &'a BTreeMap<u64, ReplayClass>,
        finished: bool,
    ) -> Result<Self, ValueTableEncodeError> {
        let mut values = ValueTableEncoder::new();
        let nodes = program
            .nodes
            .iter()
            .map(|node| node.try_map_ref(|value| reference(&mut values, value), Ok))
            .collect::<Result<_, _>>()?;
        let imports = program
            .imports
            .iter()
            .map(|import| ImportRecord::new(import, &mut values))
            .collect::<Result<_, _>>()?;
        let tasks = machine
            .tasks
            .iter()
            .map(|task| task.try_map_ref(|value| reference(&mut values, value), Ok))
            .collect::<Result<_, _>>()?;
        let frames = machine
            .frames
            .iter()
            .map(|frame| {
                frame
                    .as_ref()
                    .map(|frame| frame.try_map_ref(|value| reference(&mut values, value), Ok))
                    .transpose()
            })
            .collect::<Result<_, _>>()?;
        let bindings = machine
            .bindings
            .iter()
            .map(|value| {
                value
                    .as_ref()
                    .map(|value| reference(&mut values, value))
                    .transpose()
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            version,
            execution,
            process,
            program: ProgramRecord {
                nodes,
                imports,
                entry: program.entry,
                bindings: program.bindings,
                portable: program.portable,
                durable: program.durable,
                id: program.id,
                arena: program.arena_snapshot(),
            },
            machine: MachineRecord {
                meta: machine.meta,
                tasks,
                frames,
                bindings,
            },
            pending,
            finished,
            values,
        })
    }
}

fn reference<'a>(
    values: &mut ValueTableEncoder<'a>,
    value: &'a TaintedValue,
) -> Result<ValueReference<&'a TaintSet>, ValueTableEncodeError> {
    Ok(ValueReference {
        value: values.intern(&value.value)?,
        taint: &value.taint,
    })
}

fn resolve(values: &ValueTableDecoder, root: ValueRoot) -> Result<Value, &'static str> {
    values
        .resolve(root)
        .ok_or("checkpoint value root is outside its table")
}

fn tainted(
    values: &ValueTableDecoder,
    reference: ValueReference<TaintSet>,
) -> Result<TaintedValue, &'static str> {
    Ok(TaintedValue::new(
        resolve(values, reference.value)?,
        reference.taint,
    ))
}

impl ReadCheckpoint {
    fn restore(self) -> Result<ExecutionSnapshot, &'static str> {
        if self.version != EXECUTION_CHECKPOINT_VERSION {
            return Err("unsupported execution checkpoint version");
        }
        let nodes = self
            .program
            .nodes
            .into_iter()
            .map(|node| node.try_map_owned(|value| tainted(&self.values, value), Ok))
            .collect::<Result<_, _>>()?;
        let imports = self
            .program
            .imports
            .into_iter()
            .map(|import| import.restore(&self.values))
            .collect::<Result<_, _>>()?;
        let tasks = self
            .machine
            .tasks
            .into_iter()
            .map(|task| task.try_map_owned(|value| tainted(&self.values, value), Ok))
            .collect::<Result<_, _>>()?;
        let frames = self
            .machine
            .frames
            .into_iter()
            .map(|frame| {
                frame
                    .map(|frame| frame.try_map_owned(|value| tainted(&self.values, value), Ok))
                    .transpose()
            })
            .collect::<Result<_, _>>()?;
        let bindings = self
            .machine
            .bindings
            .into_iter()
            .map(|value| value.map(|value| tainted(&self.values, value)).transpose())
            .collect::<Result<_, _>>()?;
        let mut program = MachineProgram::from_checkpoint(
            nodes,
            imports,
            self.program.entry,
            self.program.bindings,
            self.program.portable,
            self.program.durable,
            self.program.id,
        );
        program.restore_arena(self.program.arena)?;
        Ok(ExecutionSnapshot {
            version: self.version,
            execution: self.execution,
            process: self.process,
            program: PreparedProgram {
                inner: Arc::new(program),
            },
            machine: MachineSnapshot {
                meta: self.machine.meta,
                tasks,
                frames,
                bindings,
            },
            pending: self.pending,
            finished: self.finished,
        })
    }
}

impl Serialize for ExecutionCheckpoint<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        WriteCheckpoint::new(
            self.version,
            self.execution,
            &self.process,
            self.program,
            Checkpoint {
                meta: self.machine.meta,
                tasks: self.machine.tasks,
                frames: self.machine.frames,
                bindings: self.machine.bindings,
            },
            self.pending,
            self.finished,
        )
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
    }
}

impl Serialize for ExecutionSnapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        WriteCheckpoint::new(
            self.version,
            self.execution,
            &self.process,
            &self.program.inner,
            self.machine.checkpoint(),
            &self.pending,
            self.finished,
        )
        .map_err(serde::ser::Error::custom)?
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ExecutionSnapshot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ReadCheckpoint::deserialize(deserializer)?
            .restore()
            .map_err(serde::de::Error::custom)
    }
}
