//! Caller-owned execution allocations, emptied on every exit from an execution.

use super::{
    ExecutionConfig, ExecutionLayout, PreparedProgram, config::buffer_bytes, machine_error,
};
use xolotl_core::{Frame, Task};
use xolotl_state::TaintedValue;
use xolotl_types::{Failure, TaintedFailure};

/// Reusable task, shared-frame and binding allocations for sequential executions.
///
/// An execution exclusively borrows these buffers. Completion, errors and dropping
/// its Future release all stored values; only empty capacity is retained. There is
/// no global pool or lock. Use one instance per concurrent execution and [`Self::release`]
/// to return retained memory when idle. I/O futures and value payloads allocate separately.
#[derive(Default)]
pub struct ExecutionBuffers {
    pub(super) tasks: Vec<Task<TaintedValue, TaintedFailure>>,
    pub(super) frames: Vec<Option<Frame<TaintedValue, TaintedFailure>>>,
    pub(super) bindings: Vec<Option<TaintedValue>>,
}

impl ExecutionBuffers {
    /// Allocate empty capacity before entering a latency-sensitive execution path.
    pub fn reserve_for(
        &mut self,
        program: &PreparedProgram,
        config: &ExecutionConfig,
    ) -> Result<ExecutionLayout, Failure> {
        let layout = program.layout(config)?;
        self.fit(layout, config.max_storage_bytes)?;
        Ok(layout)
    }

    /// Bytes retained by the three allocations, excluding Vec headers and payloads.
    pub fn retained_bytes(&self) -> usize {
        buffer_bytes(
            self.tasks.capacity(),
            self.frames.capacity(),
            self.bindings.capacity(),
        )
        .unwrap_or(usize::MAX)
    }

    /// Return all retained capacity to the allocator.
    pub fn release(&mut self) {
        *self = Self::default();
    }

    fn clear(&mut self) {
        self.tasks.clear();
        self.frames.clear();
        self.bindings.clear();
    }

    fn fit(&mut self, layout: ExecutionLayout, max_bytes: usize) -> Result<(), Failure> {
        self.clear();
        let bindings = layout
            .tasks
            .checked_mul(layout.bindings_per_task)
            .ok_or_else(|| machine_error("execution storage size overflow"))?;
        if buffer_bytes(layout.tasks, layout.frames, bindings).is_none_or(|bytes| bytes > max_bytes)
        {
            return Err(machine_error("execution storage budget exceeded"));
        }
        if self.tasks.capacity() >= layout.tasks
            && self.frames.capacity() >= layout.frames
            && self.bindings.capacity() >= bindings
            && buffer_bytes(
                self.tasks.capacity(),
                self.frames.capacity(),
                self.bindings.capacity(),
            )
            .is_some_and(|bytes| bytes <= max_bytes)
        {
            return Ok(());
        }
        let projected = buffer_bytes(
            self.tasks.capacity().max(layout.tasks),
            self.frames.capacity().max(layout.frames),
            self.bindings.capacity().max(bindings),
        );
        if projected.is_none_or(|bytes| bytes > max_bytes) {
            self.release();
        }
        let reserved = reserve(&mut self.tasks, layout.tasks)
            .and_then(|()| reserve(&mut self.frames, layout.frames))
            .and_then(|()| reserve(&mut self.bindings, bindings));
        if let Err(error) = reserved {
            self.release();
            return Err(error);
        }
        if buffer_bytes(
            self.tasks.capacity(),
            self.frames.capacity(),
            self.bindings.capacity(),
        )
        .is_none_or(|bytes| bytes > max_bytes)
        {
            self.release();
            return Err(machine_error("execution storage budget exceeded"));
        }
        Ok(())
    }

    pub(super) fn acquire(
        &mut self,
        layout: ExecutionLayout,
        max_bytes: usize,
    ) -> Result<Lease<'_>, Failure> {
        self.fit(layout, max_bytes)?;
        self.tasks.resize_with(layout.tasks, Task::default);
        self.frames.resize_with(layout.frames, || None);
        self.bindings
            .resize_with(layout.tasks * layout.bindings_per_task, || None);
        Ok(Lease { buffers: self })
    }

    pub(super) fn grow(
        &mut self,
        current: ExecutionLayout,
        next: ExecutionLayout,
        max_bytes: usize,
    ) -> Result<(), Failure> {
        if next.tasks < current.tasks
            || next.frames < current.frames
            || next.bindings_per_task < current.bindings_per_task
        {
            return Err(machine_error("live execution storage cannot shrink"));
        }
        let bindings = next
            .tasks
            .checked_mul(next.bindings_per_task)
            .ok_or_else(|| machine_error("execution storage size overflow"))?;
        let needed = |capacity, size| if capacity < size { size } else { 0 };
        let tasks = needed(self.tasks.capacity(), next.tasks);
        let frames = needed(self.frames.capacity(), next.frames);
        let bindings_capacity = needed(self.bindings.capacity(), bindings);
        let retained = self.retained_bytes();
        let peak = buffer_bytes(tasks, frames, bindings_capacity)
            .and_then(|growth| retained.checked_add(growth));
        if peak.is_none_or(|bytes| bytes > max_bytes) {
            return Err(machine_error("execution growth storage budget exceeded"));
        }

        // Complete every fallible allocation before moving any live state.
        let mut replacement = Self::default();
        reserve(&mut replacement.tasks, tasks)?;
        reserve(&mut replacement.frames, frames)?;
        reserve(&mut replacement.bindings, bindings_capacity)?;
        if retained
            .checked_add(replacement.retained_bytes())
            .is_none_or(|bytes| bytes > max_bytes)
        {
            return Err(machine_error("execution growth storage budget exceeded"));
        }
        replace(&mut self.tasks, replacement.tasks);
        replace(&mut self.frames, replacement.frames);
        replace(&mut self.bindings, replacement.bindings);
        self.bindings.resize_with(bindings, || None);
        if next.bindings_per_task != current.bindings_per_task {
            // A wider dense stride moves rows backwards so unread sources survive.
            for task in (0..current.tasks).rev() {
                for slot in (0..current.bindings_per_task).rev() {
                    let old = task * current.bindings_per_task + slot;
                    let new = task * next.bindings_per_task + slot;
                    if old != new {
                        self.bindings[new] = self.bindings[old].take();
                    }
                }
            }
        }
        self.tasks.resize_with(next.tasks, Task::default);
        self.frames.resize_with(next.frames, || None);
        Ok(())
    }
}

fn replace<T>(current: &mut Vec<T>, mut replacement: Vec<T>) {
    if replacement.capacity() != 0 {
        replacement.append(current);
        *current = replacement;
    }
}

fn reserve<T>(buffer: &mut Vec<T>, needed: usize) -> Result<(), Failure> {
    if buffer.capacity() < needed {
        // Release the smaller allocation before growing, avoiding two live copies.
        *buffer = Vec::new();
        buffer
            .try_reserve_exact(needed)
            .map_err(|error| machine_error(format!("execution allocation failed: {error}")))?;
    }
    Ok(())
}

pub(super) struct Lease<'a> {
    pub(super) buffers: &'a mut ExecutionBuffers,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        self.buffers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Bootstrap, StepModule};
    use anyhow::{Context, ensure};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use xolotl_graph::{
        DoNode, StepRef, WaitSpec, compile_do,
        portable::{Expression as E, Program},
    };
    use xolotl_types::{Outcome, Path, Value};

    #[tokio::test]
    async fn dormant_native_imports_and_sequential_steps_use_small_layouts() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let executor = boot
            .kernel
            .executor_for(boot.root)
            .with_execution_config(ExecutionConfig {
                max_storage_bytes: 2048,
                ..ExecutionConfig::default()
            });
        let executor =
            executor.with_steps(StepModule::single("increment", |input, _| {
                match input.as_int() {
                    Some(value) => DoNode::pure(Value::integer(value + 1)),
                    _ => DoNode::fail(machine_error("expected integer")),
                }
            })?);
        let dormant =
            compile_do(&DoNode::pure(Value::integer(42)).or_else(StepRef::new("unused")))?;
        let mut buffers = ExecutionBuffers::default();
        ensure!(
            executor
                .eval_graph_with_buffers(&dormant, &mut buffers)
                .await
                .outcome
                == Outcome::Done(Value::integer(42))
        );
        ensure!(buffers.retained_bytes() == buffer_bytes(1, 2, 0).context("layout overflow")?);
        buffers.release();
        let body = (0..64).fold(DoNode::pure(Value::integer(0)), |body, _| {
            body.and_then(StepRef::new("increment"))
        });
        let graph = compile_do(&body)?;
        for _ in 0..2 {
            ensure!(
                executor
                    .eval_graph_with_buffers(&graph, &mut buffers)
                    .await
                    .outcome
                    == Outcome::Done(Value::integer(64))
            );
            ensure!(buffers.retained_bytes() == buffer_bytes(1, 1, 0).context("layout overflow")?);
            ensure!(
                buffers.tasks.is_empty()
                    && buffers.frames.is_empty()
                    && buffers.bindings.is_empty()
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn completed_native_fragments_reuse_instruction_and_binding_capacity()
    -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let graph = compile_do(&(0..64).fold(DoNode::pure(Value::integer(0)), |body, _| {
            body.and_then(StepRef::new("increment"))
        }))?;
        for bound in [false, true] {
            let steps = StepModule::single("increment", move |input, _| match input.as_int() {
                Some(value) => {
                    let output = DoNode::pure(Value::integer(value + 1));
                    if bound {
                        DoNode::r#let("value", output, DoNode::use_("value"))
                    } else {
                        output
                    }
                }
                _ => DoNode::fail(machine_error("expected integer")),
            })?;
            let executor = boot
                .kernel
                .executor_for(boot.root)
                .with_steps(steps)
                .with_execution_config(ExecutionConfig {
                    max_instructions: graph.nodes.len() + 2,
                    bindings_per_task: usize::from(bound),
                    max_storage_bytes: 2048,
                    ..ExecutionConfig::default()
                });
            let mut buffers = ExecutionBuffers::default();
            let output = executor.eval_graph_with_buffers(&graph, &mut buffers).await;
            ensure!(
                output.outcome == Outcome::Done(Value::integer(64)),
                "{output:?}"
            );
            ensure!(buffers.bindings.capacity() == usize::from(bound));
        }
        Ok(())
    }

    #[tokio::test]
    async fn retired_fragments_are_reused_while_a_later_fragment_waits() -> anyhow::Result<()> {
        for quantum in [1, 256] {
            let boot = Bootstrap::in_memory();
            let signal = Path::parse("state://signal/fragment-reuse")?;
            let completed = Arc::new(AtomicUsize::new(0));
            let count = Arc::clone(&completed);
            let increment =
                StepModule::single("increment", move |input, _| match input.as_int() {
                    Some(value) => {
                        count.fetch_add(1, Ordering::Relaxed);
                        DoNode::r#let(
                            "value",
                            DoNode::pure(Value::integer(value + 1)),
                            DoNode::use_("value"),
                        )
                    }
                    _ => DoNode::fail(machine_error("expected integer")),
                })?;
            let waiting = signal.clone();
            let wait = StepModule::single("wait", move |_, _| {
                DoNode::r#let(
                    "held",
                    DoNode::pure(Value::integer(777)),
                    DoNode::r#let(
                        "signal",
                        DoNode::wait_signal(waiting.clone()),
                        DoNode::use_("held"),
                    ),
                )
            })?;
            let graph = compile_do(&DoNode::both(
                (0..64).fold(DoNode::pure(Value::integer(0)), |body, _| {
                    body.and_then(StepRef::new("increment"))
                }),
                DoNode::pure(Value::null()).and_then(StepRef::new("wait")),
            ))?;
            let executor = boot
                .kernel
                .executor_for(boot.root)
                .with_steps(StepModule::compose([increment, wait])?)
                .with_execution_config(ExecutionConfig {
                    max_instructions: graph.nodes.len() + 5,
                    bindings_per_task: 2,
                    quantum,
                    ..ExecutionConfig::default()
                });
            let run = executor.eval_graph(&graph);
            tokio::pin!(run);
            for _ in 0..1024 {
                tokio::select! {
                    biased;
                    output = &mut run => anyhow::bail!("wait ended early: {output:?}"),
                    () = tokio::task::yield_now() => {}
                }
                if completed.load(Ordering::Relaxed) == 64 {
                    break;
                }
            }
            ensure!(completed.load(Ordering::Relaxed) == 64);
            boot.kernel
                .state
                .write_set(&signal, Value::boolean(true))
                .await?;
            let output = tokio::time::timeout(std::time::Duration::from_secs(1), run).await?;
            ensure!(
                output.outcome
                    == Outcome::Done(Value::list(vec![Value::integer(64), Value::integer(777)])),
                "live fragment changed: {output:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn native_growth_remaps_bindings_while_other_tasks_are_waiting() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let executor = boot.kernel.executor_for(boot.root);
        let signal = Path::parse("state://signal/native-growth")?;
        let observed = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&observed);
        let second = StepModule::single("second", move |_, _| {
            flag.store(true, Ordering::SeqCst);
            DoNode::r#let(
                "local",
                DoNode::pure(Value::integer(99)),
                DoNode::both(DoNode::use_("local"), DoNode::pure(Value::integer(8))),
            )
        })?;
        let waiting = signal.clone();
        let first = StepModule::single("first", move |_, _| {
            DoNode::r#let(
                "outer",
                DoNode::pure(Value::integer(7)),
                DoNode::r#let(
                    "combined",
                    DoNode::both(
                        DoNode::pure(Value::null()).and_then(StepRef::new("second")),
                        DoNode::r#let(
                            "unused",
                            DoNode::Wait(WaitSpec::Signal(waiting.clone())),
                            DoNode::use_("outer"),
                        ),
                    ),
                    DoNode::both(DoNode::use_("combined"), DoNode::use_("outer")),
                ),
            )
        })?;
        let executor = executor.with_steps(StepModule::compose([first, second])?);
        let graph = compile_do(&DoNode::pure(Value::null()).and_then(StepRef::new("first")))?;
        let mut buffers = ExecutionBuffers::default();
        {
            let run = executor.eval_graph_with_buffers(&graph, &mut buffers);
            tokio::pin!(run);
            for _ in 0..16 {
                tokio::select! {
                    biased;
                    outcome = &mut run => anyhow::bail!("waiting branch ended early: {outcome:?}"),
                    () = tokio::task::yield_now() => {}
                }
                if observed.load(Ordering::SeqCst) {
                    break;
                }
            }
            ensure!(observed.load(Ordering::SeqCst));
            boot.kernel
                .state
                .write_set(&signal, Value::boolean(true))
                .await?;
            let output = run.await;
            ensure!(
                output.outcome
                    == Outcome::Done(Value::list(vec![
                        Value::list(vec![
                            Value::list(vec![Value::integer(99), Value::integer(8)]),
                            Value::integer(7)
                        ]),
                        Value::integer(7),
                    ])),
                "native growth changed bindings: {output:?}"
            );
        }
        ensure!(buffers.tasks.capacity() == 5);
        ensure!(buffers.bindings.capacity() == 15);
        ensure!(buffers.frames.capacity() == 2);
        ensure!(
            buffers.tasks.is_empty() && buffers.frames.is_empty() && buffers.bindings.is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn growth_budget_failure_rolls_back_the_image_and_reaches_recovery() -> anyhow::Result<()>
    {
        let boot = Bootstrap::in_memory();
        let root = boot.root;
        let executor = boot
            .kernel
            .executor_for(root)
            .with_execution_config(ExecutionConfig {
                max_storage_bytes: buffer_bytes(1, 5, 0).context("layout overflow")?,
                ..ExecutionConfig::default()
            });
        let expand = StepModule::single("expand", move |_, _| {
            DoNode::pure(Value::integer(99)).or_else(StepRef::new("unused"))
        })?;
        let recover = StepModule::single("recover", |input, _| match input.as_str() {
            Some(reason) if reason.contains("growth storage budget") => {
                DoNode::pure(Value::integer(42))
            }
            _ => DoNode::fail(machine_error("unexpected recovery input")),
        })?;
        let executor = executor.with_steps(StepModule::compose([expand, recover])?);
        let graph = compile_do(
            &DoNode::pure(Value::null())
                .and_then(StepRef::new("expand"))
                .or_else(StepRef::new("recover")),
        )?;
        let mut buffers = ExecutionBuffers::default();
        let output = executor.eval_graph_with_buffers(&graph, &mut buffers).await;
        ensure!(
            output.outcome == Outcome::Done(Value::integer(42)),
            "growth recovery failed: {output:?}"
        );
        ensure!(buffers.retained_bytes() == buffer_bytes(1, 3, 0).context("layout overflow")?);
        Ok(())
    }

    #[tokio::test]
    async fn buffers_drop_all_values_on_success_failure_and_future_drop() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let executor = boot.kernel.executor_for(boot.root);
        let mut buffers = ExecutionBuffers::default();
        let pending = PreparedProgram::new(
            &Program::new(E::Let {
                name: "payload".into(),
                value: Box::new(E::Constant {
                    value: Value::bytes(vec![17; 65_536]),
                }),
                body: Box::new(E::Wait {
                    wait: WaitSpec::Signal(Path::parse("state://signal/buffers")?),
                }),
            })
            .compile()?,
        )?;
        {
            let run = executor.eval_prepared_with_buffers(
                &pending,
                TaintedValue::pristine(Value::integer(9)),
                &mut buffers,
            );
            tokio::pin!(run);
            tokio::select! {
                biased;
                result = &mut run => anyhow::bail!("wait finished early: {result:?}"),
                () = tokio::task::yield_now() => {}
            }
        }
        ensure!(buffers.retained_bytes() > 0);
        ensure!(
            buffers.tasks.is_empty() && buffers.frames.is_empty() && buffers.bindings.is_empty()
        );
        let retained = buffers.retained_bytes();
        for (body, succeeds) in [
            (E::Input, true),
            (
                E::Fail {
                    message: "failure".into(),
                },
                false,
            ),
        ] {
            let prepared = PreparedProgram::new(&Program::new(body).compile()?)?;
            let result = executor
                .eval_prepared_with_buffers(
                    &prepared,
                    TaintedValue::pristine(Value::integer(42)),
                    &mut buffers,
                )
                .await;
            ensure!(if succeeds {
                result.outcome == Outcome::Done(Value::integer(42))
            } else {
                matches!(result.outcome, Outcome::Fail(_))
            });
            ensure!(buffers.retained_bytes() == retained);
            ensure!(
                buffers.tasks.is_empty()
                    && buffers.frames.is_empty()
                    && buffers.bindings.is_empty()
            );
        }
        buffers.release();
        ensure!(buffers.retained_bytes() == 0);
        Ok(())
    }

    #[test]
    fn retained_capacity_shrinks_to_the_current_execution_budget() -> anyhow::Result<()> {
        let large = PreparedProgram::new(
            &Program::new((0..32).fold(E::Input, |body, _| body.finally(E::Input))).compile()?,
        )?;
        let small = PreparedProgram::new(&Program::new(E::Input).compile()?)?;
        let mut buffers = ExecutionBuffers::default();
        buffers.reserve_for(&large, &ExecutionConfig::default())?;
        ensure!(buffers.retained_bytes() > 1024);
        let config = ExecutionConfig {
            max_storage_bytes: 1024,
            ..ExecutionConfig::default()
        };
        let layout = buffers.reserve_for(&small, &config)?;
        ensure!(buffers.retained_bytes() == layout.storage_bytes);
        ensure!(buffers.retained_bytes() <= config.max_storage_bytes);
        Ok(())
    }
}
