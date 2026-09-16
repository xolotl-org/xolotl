//! Bound interpreter storage before allocating host execution state.

use super::{image::MachineProgram, machine_error};
use xolotl_core::{ExecutionLimits, Task};
use xolotl_state::TaintedValue;
use xolotl_types::{Failure, TaintedFailure};

pub(super) fn buffer_bytes(tasks: usize, frames: usize, bindings: usize) -> Option<usize> {
    tasks
        .checked_mul(std::mem::size_of::<Task<TaintedValue, TaintedFailure>>())?
        .checked_add(frames.checked_mul(std::mem::size_of::<
            Option<xolotl_core::Frame<TaintedValue, TaintedFailure>>,
        >())?)?
        .checked_add(bindings.checked_mul(std::mem::size_of::<Option<TaintedValue>>())?)
}

/// Host allocation and work ceilings. Value payloads and drivers have their own budgets.
#[derive(Clone, Copy, Debug)]
pub struct ExecutionConfig {
    /// Maximum simultaneous task slots, including suspended parents.
    pub max_tasks: usize,
    /// Maximum continuation slots in each task.
    pub frames_per_task: usize,
    /// Maximum continuation slots shared by all task stacks.
    pub max_frames: usize,
    /// Maximum lexical slots in each task.
    pub bindings_per_task: usize,
    /// Maximum resident instruction address space, including active continuations.
    /// Retired code is reused; this does not limit cumulative module invocations.
    pub max_instructions: usize,
    /// Maximum bytes for task, frame and binding containers, excluding value payloads.
    pub max_storage_bytes: usize,
    /// Maximum encoded checkpoint bytes on both read and write. This bounds
    /// serialization buffers, not decoded payload heap or external driver memory.
    #[cfg(feature = "durable")]
    pub max_checkpoint_bytes: usize,
    /// Optional cumulative transition quota, separate from scheduling quantum.
    pub max_steps: Option<u64>,
    /// Additional transitions reserved for cancellation and cleanup.
    pub cleanup_steps: u64,
    /// Transitions between scheduler yields.
    pub quantum: u32,
}

/// Container sizes selected for an execution, before allocating mutable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionLayout {
    /// Task slots, including suspended parents of concurrent branches.
    pub tasks: usize,
    /// Maximum continuation depth of each task stack.
    pub frames_per_task: usize,
    /// Continuation slots shared across all tasks.
    pub frames: usize,
    /// Lexical slots reserved for each task.
    pub bindings_per_task: usize,
    /// Task, frame and binding bytes, excluding their heap-owned value payloads.
    pub storage_bytes: usize,
}

impl ExecutionLayout {
    pub(super) fn limits(self, config: &ExecutionConfig) -> ExecutionLimits {
        ExecutionLimits {
            frames_per_task: self.frames_per_task,
            bindings_per_task: self.bindings_per_task,
            max_steps: config.max_steps,
            cleanup_steps: config.cleanup_steps,
            durable: false,
        }
    }
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            max_tasks: 65,
            frames_per_task: 256,
            max_frames: 1024,
            bindings_per_task: 1024,
            max_instructions: 65_536,
            max_storage_bytes: 16 * 1024 * 1024,
            #[cfg(feature = "durable")]
            max_checkpoint_bytes: 64 * 1024 * 1024,
            max_steps: None,
            cleanup_steps: 4096,
            quantum: 256,
        }
    }
}

impl ExecutionConfig {
    pub(super) fn check_program(&self, program: &MachineProgram) -> Result<(), Failure> {
        if self.max_tasks == 0 || self.quantum == 0 || program.nodes.len() > self.max_instructions {
            return Err(machine_error(
                "invalid execution configuration or instruction limit exceeded",
            ));
        }
        if program.bindings > self.bindings_per_task {
            return Err(machine_error("binding capacity exceeded"));
        }
        Ok(())
    }

    pub(super) fn layout(&self, program: &MachineProgram) -> Result<ExecutionLayout, Failure> {
        self.check_program(program)?;
        let requirements = program.requirements()?;
        let bound = |inferred: Option<usize>, ceiling| inferred.unwrap_or(ceiling).min(ceiling);
        let tasks = bound(requirements.tasks, self.max_tasks);
        let depth = bound(requirements.frames_per_task, self.frames_per_task);
        let frames = bound(requirements.frames, self.max_frames).min(tasks.saturating_mul(depth));
        self.storage_layout(tasks, depth, frames, requirements.bindings_per_task)
    }

    pub(super) fn expanded_layout(
        &self,
        program: &MachineProgram,
        current: ExecutionLayout,
        entries: impl Iterator<Item = u32>,
    ) -> Result<ExecutionLayout, Failure> {
        let base = self.layout(program)?;
        let mut tasks = base.tasks;
        let mut depth = base.frames_per_task;
        let mut frames = base.frames;
        for entry in entries {
            let usage = program.expansion_requirements(entry)?;
            tasks = tasks
                .saturating_add(usage.tasks.unwrap_or(self.max_tasks).saturating_sub(1))
                .min(self.max_tasks);
            depth = depth
                .saturating_add(usage.frames_per_task.unwrap_or(self.frames_per_task))
                .saturating_add(1)
                .min(self.frames_per_task);
            frames = frames
                .saturating_add(usage.frames.unwrap_or(self.max_frames))
                .saturating_add(1)
                .min(self.max_frames);
        }
        let tasks = tasks.max(current.tasks);
        let depth = depth.max(current.frames_per_task);
        self.storage_layout(
            tasks,
            depth,
            frames.max(current.frames).min(tasks.saturating_mul(depth)),
            base.bindings_per_task.max(current.bindings_per_task),
        )
    }

    pub(super) fn restored_layout(
        &self,
        program: &MachineProgram,
        checkpoint: &xolotl_core::Checkpoint<'_, TaintedValue, TaintedFailure>,
    ) -> Result<ExecutionLayout, Failure> {
        self.check_program(program)?;
        let saved = checkpoint.meta.limits;
        if checkpoint.tasks.is_empty()
            || checkpoint.tasks.len() > self.max_tasks
            || saved.frames_per_task > self.frames_per_task
            || checkpoint.frames.len() > self.max_frames
            || saved.bindings_per_task > self.bindings_per_task
            || saved.bindings_per_task < program.bindings
            || self
                .max_steps
                .is_some_and(|limit| saved.max_steps.is_none_or(|saved| saved > limit))
            || saved.cleanup_steps > self.cleanup_steps
        {
            return Err(machine_error(
                "checkpoint exceeds configured execution limits",
            ));
        }
        let layout = self.storage_layout(
            checkpoint.tasks.len(),
            saved.frames_per_task,
            checkpoint.frames.len(),
            saved.bindings_per_task,
        )?;
        if checkpoint.bindings.len() != layout.tasks * layout.bindings_per_task {
            return Err(machine_error("invalid checkpoint storage layout"));
        }
        Ok(layout)
    }

    fn storage_layout(
        &self,
        tasks: usize,
        frames_per_task: usize,
        frames: usize,
        bindings_per_task: usize,
    ) -> Result<ExecutionLayout, Failure> {
        if tasks == 0 || tasks > u32::MAX as usize || frames > u32::MAX as usize {
            return Err(machine_error("execution storage index capacity exceeded"));
        }
        let bytes = bindings_per_task
            .checked_mul(tasks)
            .and_then(|bindings| buffer_bytes(tasks, frames, bindings))
            .ok_or_else(|| machine_error("execution storage size overflow"))?;
        if bytes > self.max_storage_bytes {
            return Err(machine_error("execution storage budget exceeded"));
        }
        Ok(ExecutionLayout {
            tasks,
            frames_per_task,
            frames,
            bindings_per_task,
            storage_bytes: bytes,
        })
    }
}
