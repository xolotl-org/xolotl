//! Drive the shared machine and deliver host completions through one boundary.

use super::image::{Import, MachineProgram};
use super::*;
use futures_util::{
    FutureExt, StreamExt,
    future::{AbortHandle, Abortable},
    stream::FuturesUnordered,
};
use std::borrow::Cow;
#[cfg(test)]
use xolotl_core::Values;
use xolotl_core::{Advance, Execution, HostEvent};
use xolotl_state::TaintedValue;
use xolotl_types::{Failure, TaintedFailure};

use crate::RuntimeValues as HostValues;

type Pending<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = (usize, u64, HostEvent<TaintedValue, TaintedFailure>)>
            + Send
            + 'a,
    >,
>;

impl Executor {
    fn complete_machine(
        &self,
        execution: &mut Execution<'_, TaintedValue, TaintedFailure>,
        program: &mut Cow<'_, MachineProgram>,
        task: usize,
        ticket: u64,
        event: HostEvent<TaintedValue, TaintedFailure>,
        #[cfg(feature = "durable")] journal: &mut Option<&mut super::durable::JournalRun>,
    ) -> Result<(), TaintedFailure> {
        let continuation = match &event {
            HostEvent::Continue { entry, .. } => Some(*entry),
            _ => None,
        };
        let completion = execution.complete(task, ticket, event, &program.image(), &mut HostValues);
        // A rejected continuation has not consumed its pending ticket or entered its scope.
        let completion = match completion {
            Err(xolotl_core::Fault::Frames) => {
                if let Some(entry) = continuation {
                    program.to_mut().discard(entry);
                }
                execution.complete(
                    task,
                    ticket,
                    HostEvent::Complete(
                        Err(machine_error("continuation capacity exceeded").into()),
                    ),
                    &program.image(),
                    &mut HostValues,
                )
            }
            other => other,
        };
        completion.map_err(|error| {
            TaintedFailure::new(
                machine_error(format!("completion: {error:?}")),
                execution.retain_control(&mut HostValues).taint,
            )
        })?;
        #[cfg(feature = "durable")]
        if let Some(journal) = journal {
            journal.pending.remove(&ticket);
            journal
                .commit(self, program, execution, false)
                .map_err(|error| {
                    TaintedFailure::new(error, execution.retain_control(&mut HostValues).taint)
                })?;
        }
        Ok(())
    }

    /// Execute a portable, compiled program with explicit input provenance.
    pub async fn eval_program(
        &self,
        program: &xolotl_graph::portable::CompiledProgram,
        input: TaintedValue,
    ) -> ExecutionOutput {
        if self.deadline_elapsed() {
            return Self::failed(Failure::Timeout, input.taint);
        }
        match PreparedProgram::new(program) {
            Ok(program) => self.eval_prepared(&program, input).await,
            Err(error) => Self::failed(error, input.taint),
        }
    }

    /// Reuse prepared instructions and constants with explicit input provenance.
    pub async fn eval_prepared(
        &self,
        program: &PreparedProgram,
        input: TaintedValue,
    ) -> ExecutionOutput {
        self.run_machine_with_buffers(
            Cow::Borrowed(&program.inner),
            input,
            &mut ExecutionBuffers::default(),
            None,
            #[cfg(feature = "durable")]
            None,
        )
        .await
    }

    /// Reuse both immutable instructions and caller-owned mutable allocations.
    pub async fn eval_prepared_with_buffers(
        &self,
        program: &PreparedProgram,
        input: TaintedValue,
        buffers: &mut ExecutionBuffers,
    ) -> ExecutionOutput {
        self.run_machine_with_buffers(
            Cow::Borrowed(&program.inner),
            input,
            buffers,
            None,
            #[cfg(feature = "durable")]
            None,
        )
        .await
    }

    pub(super) async fn run_machine(
        &self,
        program: Cow<'_, MachineProgram>,
        input: TaintedValue,
    ) -> ExecutionOutput {
        self.run_machine_with_buffers(
            program,
            input,
            &mut ExecutionBuffers::default(),
            None,
            #[cfg(feature = "durable")]
            None,
        )
        .await
    }

    pub(super) async fn run_machine_with_buffers(
        &self,
        mut program: Cow<'_, MachineProgram>,
        input: TaintedValue,
        buffers: &mut ExecutionBuffers,
        reserved_execution: Option<ExecutionId>,
        #[cfg(feature = "durable")] supplied_journal: Option<&mut super::durable::JournalRun>,
    ) -> ExecutionOutput {
        let entry_taint = input.taint.clone();
        let failed = |error| Self::failed(error, entry_taint.clone());
        #[cfg(feature = "durable")]
        let restoring = supplied_journal
            .as_ref()
            .is_some_and(|journal| journal.restored.is_some());
        #[cfg(not(feature = "durable"))]
        let restoring = false;
        if self.deadline_elapsed() && !restoring {
            return failed(Failure::Timeout);
        }
        let Some(acting) = self.default_acting() else {
            return failed(machine_error(format!(
                "unknown process {}",
                self.process.get()
            )));
        };
        if let Err(error) = self.execution_config.check_program(&program) {
            return failed(error);
        }
        #[cfg(feature = "durable")]
        let mut opened_journal = if supplied_journal.is_none() {
            match super::durable::JournalRun::open(self, &program) {
                Ok(journal) => journal,
                Err(error) => return failed(error),
            }
        } else {
            None
        };
        #[cfg(feature = "durable")]
        let mut journal = supplied_journal.or(opened_journal.as_mut());
        // A resumed execution owns the linked image saved with its continuation.
        // The caller's preparation identifies the root program, not its current arena.
        #[cfg(feature = "durable")]
        let (restored, restored_finished) =
            match journal.as_mut().and_then(|journal| journal.restored.take()) {
                Some(saved) => {
                    program = Cow::Owned(Arc::unwrap_or_clone(saved.program.inner));
                    (Some(saved.machine), saved.finished)
                }
                None => {
                    if journal.is_some()
                        && program
                            .imports
                            .iter()
                            .any(|import| matches!(import, Import::Step(_, None)))
                        && let Err(error) = self.bind_durable_imports(program.to_mut())
                    {
                        return failed(error);
                    }
                    (None, false)
                }
            };
        #[cfg(feature = "durable")]
        let retained_execution = journal.as_ref().map(|journal| journal.execution);
        #[cfg(not(feature = "durable"))]
        let retained_execution = None;
        let execution_id = match retained_execution
            .or(reserved_execution)
            .map_or_else(|| self.allocate_execution(), Ok)
        {
            Ok(id) => id,
            Err(error) => return failed(error),
        };
        #[cfg(feature = "durable")]
        let checkpoint = restored
            .as_ref()
            .map(super::durable::MachineSnapshot::checkpoint);
        #[cfg(not(feature = "durable"))]
        let checkpoint: Option<xolotl_core::Checkpoint<'_, TaintedValue, TaintedFailure>> = None;
        let layout = match &checkpoint {
            Some(checkpoint) => self.execution_config.restored_layout(&program, checkpoint),
            None => self.execution_config.layout(&program),
        };
        let mut layout = match layout {
            Ok(layout) => layout,
            Err(error) => return failed(error),
        };
        let limits = layout.limits(&self.execution_config);
        #[cfg(feature = "durable")]
        let limits = xolotl_core::ExecutionLimits {
            durable: journal.is_some(),
            ..limits
        };
        let storage = match buffers.acquire(layout, self.execution_config.max_storage_bytes) {
            Ok(storage) => storage,
            Err(error) => return failed(error),
        };
        let initialization = match checkpoint {
            Some(checkpoint) => Execution::restore(
                &program.image(),
                &checkpoint,
                &mut storage.buffers.tasks,
                &mut storage.buffers.frames,
                &mut storage.buffers.bindings,
                limits.durable,
            ),
            None => Execution::new(
                &program.image(),
                &mut storage.buffers.tasks,
                &mut storage.buffers.frames,
                &mut storage.buffers.bindings,
                limits,
                input,
                acting.get(),
            ),
        };
        let mut execution = match initialization {
            Ok(execution) => execution,
            Err(error) => return failed(machine_error(format!("admission: {error:?}"))),
        };
        let mut resumed: std::collections::VecDeque<_> =
            execution.pending_requests(&program.image()).collect();
        #[cfg(feature = "durable")]
        if let Some(journal) = &mut journal {
            if restored.is_some() {
                if resumed.len() != journal.pending.len()
                    || resumed
                        .iter()
                        .any(|request| !journal.pending.contains_key(&request.ticket))
                {
                    return self.execution_failure(
                        &execution,
                        machine_error("checkpoint pending requests mismatch"),
                    );
                }
                for request in &resumed {
                    if journal.pending.get(&request.ticket)
                        == Some(&ReplayClass::NonIdempotentEffect)
                    {
                        let id =
                            match self.request_id(execution_id, request.ticket, request.position) {
                                Ok(id) => id,
                                Err(error) => return self.execution_failure(&execution, error),
                            };
                        return self.execution_failure(
                            &execution,
                            Failure::Quarantined {
                                op_id: id.to_string(),
                                reason:
                                    "non-idempotent request has no committed completion checkpoint"
                                        .into(),
                            },
                        );
                    }
                }
            }
            if let Err(error) = journal.commit(self, &program, &execution, restored_finished) {
                return self.execution_failure(&execution, error);
            }
        }
        #[cfg(feature = "durable")]
        drop(restored);
        let mut values = HostValues;
        let mut pending: FuturesUnordered<Pending<'_>> = FuturesUnordered::new();
        let mut aborts = HashMap::new();
        let mut cancelling = false;
        let mut turns = 0;
        let deadline = self.deadline.map(tokio::time::sleep_until);
        tokio::pin!(deadline);
        loop {
            if self.deadline_elapsed() {
                return self.execution_failure(&execution, Failure::Timeout);
            }
            if !cancelling && self.is_cancelled() {
                execution.cancel();
                cancelling = true;
            }
            let action = if turns == self.execution_config.quantum {
                Advance::Yielded
            } else {
                turns += 1;
                resumed
                    .pop_front()
                    .map(|request| {
                        if cancelling && !request.cleanup {
                            Advance::Cancel {
                                task: request.task,
                                ticket: request.ticket,
                            }
                        } else {
                            Advance::Request(request)
                        }
                    })
                    .unwrap_or_else(|| {
                        execution.advance(
                            &program.image(),
                            &mut values,
                            self.execution_config.quantum,
                        )
                    })
            };
            if self.deadline_elapsed() {
                return self.execution_failure(&execution, Failure::Timeout);
            }
            if let Cow::Owned(program) = &mut program
                && let Err(error) = program.reclaim(&mut execution)
            {
                return self.execution_failure(&execution, error);
            }
            let completion = match action {
                Advance::Done(result) => {
                    #[cfg(feature = "durable")]
                    if let Some(journal) = &mut journal
                        && let Err(error) = journal.commit(self, &program, &execution, true)
                    {
                        let taint = match result {
                            Ok(value) => value.taint,
                            Err(error) => error.taint,
                        };
                        return Self::failed(error, taint);
                    }
                    return ExecutionOutput::from_result(result);
                }
                Advance::Cancel { task, ticket } => {
                    if let Some(abort) = aborts.get(&(task, ticket)) {
                        AbortHandle::abort(abort);
                        None
                    } else {
                        Some((
                            task,
                            ticket,
                            HostEvent::Complete(Err(Failure::Cancelled.into())),
                        ))
                    }
                }
                Advance::Request(request) => {
                    let Some(import) = program.imports.get(request.import as usize).cloned() else {
                        return self.execution_failure(&execution, machine_error("missing import"));
                    };
                    if let Import::Transform(transform) = &import {
                        let result = match transform.apply(request.input.value) {
                            Ok(value) => Ok(TaintedValue::new(value, request.input.taint)),
                            Err(error) => Err(TaintedFailure::new(error, request.input.taint)),
                        };
                        if let Err(error) = execution.complete(
                            request.task,
                            request.ticket,
                            HostEvent::Complete(result),
                            &program.image(),
                            &mut values,
                        ) {
                            return self.execution_failure(
                                &execution,
                                machine_error(format!("transform: {error:?}")),
                            );
                        }
                        continue;
                    }
                    #[cfg(feature = "durable")]
                    if let Some(journal) = &mut journal {
                        let class = self.checkpoint_replay_class(&import);
                        if journal
                            .pending
                            .get(&request.ticket)
                            .is_some_and(|saved| *saved != class)
                        {
                            let id = match self.request_id(
                                execution_id,
                                request.ticket,
                                request.position,
                            ) {
                                Ok(id) => id,
                                Err(error) => return self.execution_failure(&execution, error),
                            };
                            return self.execution_failure(
                                &execution,
                                Failure::Quarantined {
                                    op_id: id.to_string(),
                                    reason: "pending request replay contract changed".into(),
                                },
                            );
                        }
                        journal.pending.insert(request.ticket, class);
                        if let Err(error) = journal.commit(self, &program, &execution, false) {
                            return self.execution_failure(&execution, error);
                        }
                    }
                    if let Import::Step(step, revision) = import {
                        let result = self.expand_step(
                            step,
                            revision,
                            request.input.value,
                            program.to_mut(),
                            self.execution_config.bindings_per_task,
                        );
                        let result = result.and_then(|(entry, input)| {
                            match self.execution_config.expanded_layout(
                                &program,
                                layout,
                                execution
                                    .continuation_entries()
                                    .chain(std::iter::once(entry)),
                            ) {
                                Ok(next) => Ok((entry, input, next)),
                                Err(error) => {
                                    program.to_mut().discard(entry);
                                    Err(error)
                                }
                            }
                        });
                        let result = match result {
                            Ok((entry, input, next)) if next != layout => {
                                let mut meta = execution.suspend();
                                let growth = storage.buffers.grow(
                                    layout,
                                    next,
                                    self.execution_config.max_storage_bytes,
                                );
                                if growth.is_ok() {
                                    layout = next;
                                    meta.limits.frames_per_task = next.frames_per_task;
                                    meta.limits.bindings_per_task = next.bindings_per_task;
                                } else {
                                    program.to_mut().discard(entry);
                                }
                                execution = match Execution::resume(
                                    &program.image(),
                                    meta,
                                    &mut storage.buffers.tasks,
                                    &mut storage.buffers.frames,
                                    &mut storage.buffers.bindings,
                                    limits.durable,
                                ) {
                                    Ok(execution) => execution,
                                    Err(error) => {
                                        return Self::failed(
                                            machine_error(format!(
                                                "resuming execution storage: {error:?}"
                                            )),
                                            request.input.taint,
                                        );
                                    }
                                };
                                growth.map(|()| (entry, input))
                            }
                            Ok((entry, input, _next)) => Ok((entry, input)),
                            Err(error) => Err(error),
                        };
                        let event = match result {
                            Ok((entry, input)) => HostEvent::Continue {
                                entry,
                                input: TaintedValue::new(input, request.input.taint),
                            },
                            Err(error) => HostEvent::Complete(Err(TaintedFailure::new(
                                error,
                                request.input.taint,
                            ))),
                        };
                        if let Err(error) = self.complete_machine(
                            &mut execution,
                            &mut program,
                            request.task,
                            request.ticket,
                            event,
                            #[cfg(feature = "durable")]
                            &mut journal,
                        ) {
                            return Self::failed(error.failure, error.taint);
                        }
                        continue;
                    }
                    let (abort, registration) = AbortHandle::new_pair();
                    aborts.insert((request.task, request.ticket), abort);
                    pending.push(Box::pin(async move {
                        let task = request.task;
                        let ticket = request.ticket;
                        let event = Abortable::new(
                            self.machine_request(import, request, execution_id),
                            registration,
                        )
                        .await
                        .unwrap_or(HostEvent::Complete(Err(Failure::Cancelled.into())));
                        (task, ticket, event)
                    }));
                    None
                }
                Advance::Yielded => {
                    turns = 0;
                    tokio::task::yield_now().await;
                    pending.next().now_or_never().flatten()
                }
                Advance::Waiting => {
                    let event = tokio::select! {
                        biased;
                        () = async {
                            if let Some(deadline) = deadline.as_mut().as_pin_mut() {
                                deadline.await;
                            }
                        }, if self.deadline.is_some() => {
                            return self.execution_failure(&execution, Failure::Timeout);
                        }
                        event = pending.next() => event,
                        () = async {
                            if let Some(processes) = &self.processes {
                                processes.wait_for_cancellation(self.process, self.finalizer_mode).await;
                            }
                        }, if !cancelling && self.processes.is_some() => {
                            execution.cancel();
                            cancelling = true;
                            continue;
                        }
                    };
                    let Some(event) = event else {
                        return self.execution_failure(
                            &execution,
                            machine_error("execution blocked without a host request"),
                        );
                    };
                    Some(event)
                }
            };
            if let Some((task, ticket, event)) = completion {
                aborts.remove(&(task, ticket));
                if execution.is_pending(task, ticket)
                    && let Err(error) = self.complete_machine(
                        &mut execution,
                        &mut program,
                        task,
                        ticket,
                        event,
                        #[cfg(feature = "durable")]
                        &mut journal,
                    )
                {
                    return Self::failed(error.failure, error.taint);
                }
            }
        }
    }

    fn expand_step(
        &self,
        step: StepRef,
        revision: Option<crate::LoaderRevision>,
        input: Value,
        program: &mut MachineProgram,
        max_bindings: usize,
    ) -> Result<(u32, Value), Failure> {
        let continuation = self
            .steps
            .get(&step.name)
            .ok_or_else(|| machine_error(format!("step {:?} not found", step.name)))?;
        std::panic::catch_unwind(AssertUnwindSafe(|| match continuation {
            crate::step::Continuation::Native(function) => {
                if program.durable || revision.is_some() {
                    return Err(machine_error(
                        "durable loader cannot be a native continuation",
                    ));
                }
                let body = function(input, step.arg)
                    .bind_process_local_refs(self.process)
                    .map_err(|error| machine_error(error.to_string()))?;
                let graph = xolotl_graph::compile_do_at(&body, 0)
                    .map_err(|error| machine_error(error.to_string()))?;
                program
                    .append(&graph, self.execution_config.max_instructions, max_bindings)
                    .map(|entry| (entry, Value::null()))
            }
            crate::step::Continuation::Program {
                revision: current,
                loader,
            } => {
                if revision.is_some_and(|saved| saved != *current) {
                    return Err(machine_error(format!(
                        "loader {:?} revision changed",
                        step.name
                    )));
                }
                let loaded = loader(&input, step.arg.as_ref())?;
                #[cfg(feature = "durable")]
                let loaded = if program.durable {
                    let mut loaded = loaded;
                    self.bind_durable_imports(Arc::make_mut(&mut loaded.inner))?;
                    loaded
                } else {
                    loaded
                };
                program
                    .load(loaded, self.execution_config.max_instructions, max_bindings)
                    .map(|entry| (entry, input))
            }
        }))
        .map_err(|payload| Failure::HandlerError {
            kind: "panic".into(),
            message: crate::bootstrap::panic_payload_message("step", payload),
        })?
    }

    pub(super) fn request_id(
        &self,
        execution: ExecutionId,
        ticket: u64,
        position: u64,
    ) -> Result<OperationId, Failure> {
        let position =
            u32::try_from(position).map_err(|_error| machine_error("source position exhausted"))?;
        Ok(OperationId::new(
            self.process,
            execution,
            InvocationId::new(ticket),
            NodeId::new(position),
            0,
        ))
    }

    async fn machine_request(
        &self,
        import: Import,
        request: xolotl_core::Request<TaintedValue>,
        execution: ExecutionId,
    ) -> HostEvent<TaintedValue, TaintedFailure> {
        let id = self.request_id(execution, request.ticket, request.position);
        let input = request.input;
        let context = request.context;
        let output = match import {
            Import::Operation(operation, record) => {
                let id = match id {
                    Ok(id) => id,
                    Err(error) => {
                        return HostEvent::Complete(Err(TaintedFailure::new(error, input.taint)));
                    }
                };
                let env = Env::root(IdentityRef::new(context)).with_taint(input.taint);
                let call = self.run_operation(
                    &operation,
                    input.value,
                    &env,
                    id,
                    self.finalizer_mode || record,
                );
                if request.cleanup
                    && let Some(processes) = &self.processes
                {
                    crate::process::scope_cleanup(processes, self.process, call).await
                } else {
                    call.await
                }
            }
            Import::Wait(wait) => {
                let mut output = self.run_wait(&wait).await;
                output.taint.union(&input.taint);
                output
            }
            Import::Scope(identity) => {
                return if self.authorize_act_as(&identity) {
                    HostEvent::Enter(intern_identity(&identity).get())
                } else {
                    HostEvent::Complete(Err(TaintedFailure::new(
                        Failure::policy("act-as", "identity delegation denied"),
                        input.taint,
                    )))
                };
            }
            Import::Step(..) | Import::Vacant => {
                return HostEvent::Complete(Err(TaintedFailure::new(
                    machine_error("continuation was not linked"),
                    input.taint,
                )));
            }
            Import::Transform(operation) => {
                return HostEvent::Complete(match operation.apply(input.value) {
                    Ok(value) => Ok(TaintedValue::new(value, input.taint)),
                    Err(error) => Err(TaintedFailure::new(error, input.taint)),
                });
            }
        };
        HostEvent::Complete(output.into_result())
    }
}

impl Executor {
    fn execution_failure(
        &self,
        execution: &Execution<'_, TaintedValue, TaintedFailure>,
        failure: Failure,
    ) -> ExecutionOutput {
        Self::failed(failure, execution.retain_control(&mut HostValues).taint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Bootstrap, Driver, DriverContext, DriverError, MethodSpec};
    use anyhow::{Context, ensure};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use xolotl_graph::portable::{Expression as E, Program};
    use xolotl_types::{BudgetSpec, CostModel, MethodId, OutputMode, Path, Purity};

    #[tokio::test]
    async fn compact_control_keeps_protected_lineage_through_recovery() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let target = boot.register_effect(
            "effect://arbitrary/recovery",
            &[
                MethodSpec::unary_async("invoke", xolotl_types::Purity::Effectful)
                    .unprotected_input(),
            ],
            Arc::new(crate::EchoDriver),
        )?;
        let executor = boot.kernel.executor_for(boot.root);
        let program = PreparedProgram::new(
            &Program::new(E::Catch {
                body: Box::new(
                    E::Sequence {
                        steps: vec![E::Input; 64],
                    }
                    .then(E::Fail {
                        message: "failed".into(),
                    }),
                ),
                recover: Box::new(E::Invoke {
                    operation: OperationTemplate {
                        target,
                        method: "invoke".into(),
                        method_id: None,
                        output: OutputMode::Unary,
                        literal_input: Some(Value::string("recovered".into())),
                    },
                }),
            })
            .compile()?,
        )?;
        let input = TaintedValue::new(
            Value::bytes(vec![0x5a; 65_536]),
            xolotl_types::TaintSet::of(xolotl_types::TaintSource::Protected {
                path: Path::parse("state://vault/ownership")?,
            }),
        );
        let snapshot = HostValues.retain_control(&input);
        ensure!(snapshot.value == Value::null() && snapshot.taint == input.taint);
        let result = executor.eval_prepared(&program, input).await;
        ensure!(matches!(
            result.outcome,
            Outcome::Fail(Failure::PolicyViolation { policy, .. }) if policy == "taint"
        ));
        Ok(())
    }

    struct ReleaseFlag<'a>(&'a AtomicBool);
    impl Drop for ReleaseFlag<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct CleanupDriver {
        started: tokio::sync::Notify,
        released: AtomicBool,
        cleaned: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl Driver for CleanupDriver {
        async fn call(
            &self,
            _method: MethodId,
            input: Value,
            _output: OutputMode,
            _ctx: &DriverContext,
        ) -> Result<crate::DriverOutput, DriverError> {
            if input == Value::boolean(false) {
                let _release = ReleaseFlag(&self.released);
                self.started.notify_one();
                std::future::pending().await
            } else {
                if self.released.load(Ordering::SeqCst) {
                    self.cleaned.fetch_add(1, Ordering::SeqCst);
                }
                Ok(crate::DriverOutput::new(Outcome::Done(Value::null())))
            }
        }
    }

    #[tokio::test]
    async fn cancellation_releases_requests_and_budget_before_cleanup() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let driver = Arc::new(CleanupDriver {
            started: tokio::sync::Notify::new(),
            released: AtomicBool::new(false),
            cleaned: AtomicUsize::new(0),
        });
        let name = boot.register_effect_with_cost(
            "effect://cleanup/run",
            &[MethodSpec::new("invoke", Purity::Pure, MethodSpec::UNARY_ASYNC).finalize_allowed()],
            driver.clone(),
            CostModel {
                flat_micro_usd: 100,
                ..Default::default()
            },
        )?;
        ensure!(boot.kernel.processes.set_budget_spec(
            boot.root,
            BudgetSpec {
                max_inflight_ops: Some(1),
                ..Default::default()
            }
        ));
        let invoke = |cleanup| E::Invoke {
            operation: OperationTemplate {
                target: name.clone(),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::boolean(cleanup)),
            },
        };
        let program = Program::new(invoke(false).finally(invoke(true))).compile()?;
        let executor = boot.kernel.executor_for(boot.root);
        let run = executor.eval_program(&program, TaintedValue::pristine(Value::null()));
        tokio::pin!(run);
        tokio::select! {
            output = &mut run => anyhow::bail!("operation completed before cancellation: {output:?}"),
            () = driver.started.notified() => {}
        }
        boot.cancel_process(boot.root)?;
        let output = tokio::time::timeout(std::time::Duration::from_secs(1), run).await?;
        ensure!(output.outcome == Outcome::Fail(Failure::Cancelled));
        ensure!(
            driver.cleaned.load(Ordering::SeqCst) == 1,
            "cleanup ran before release or failed its budget reservation"
        );
        let budget = boot
            .kernel
            .processes
            .budget_mut(boot.root, |budget| budget.clone())
            .context("missing budget")?;
        ensure!(budget.inflight_ops == 0);
        ensure!(
            budget.spent_micro_usd == 200,
            "uncertain spending was refunded"
        );
        Ok(())
    }
}
