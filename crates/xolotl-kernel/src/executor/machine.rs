//! Drive the shared machine and deliver host completions through one boundary.

use super::image::{Import, MachineProgram};
use super::*;
use futures_util::{
    FutureExt, StreamExt,
    future::{AbortHandle, Abortable},
    stream::FuturesUnordered,
};
use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use xolotl_core::Values;
use xolotl_core::{Advance, Execution, HostEvent};
use xolotl_state::TaintedValue;
use xolotl_types::{Failure, ReplayClass, TaintedFailure, UnresolvedOperations};

use crate::RuntimeValues as HostValues;
use crate::runtime::Cooperate;

pub(super) fn initialize_machine<'a>(
    program: &MachineProgram,
    buffers: &'a mut ExecutionBuffers,
    limits: xolotl_core::ExecutionLimits,
    input: TaintedValue,
    acting: xolotl_types::IdentityRef,
) -> Result<Execution<'a, TaintedValue, TaintedFailure>, Failure> {
    Execution::new(
        &program.image(),
        &mut buffers.tasks,
        &mut buffers.frames,
        &mut buffers.bindings,
        limits,
        input,
        acting.get(),
    )
    .map_err(|error| machine_error(format!("admission: {error:?}")))
}

// Commit failures stop the driver loop without acknowledging its pending ticket.
// They are not program failures that Catch/Retry may turn into another effect.
type MachineRequestCompletion =
    Result<HostEvent<TaintedValue, TaintedFailure>, Box<MachineRequestError>>;

struct MachineRequestError {
    failure: TaintedFailure,
    unresolved_operation: Option<OperationId>,
}

struct MachineRequestCall {
    import: Import,
    request: xolotl_core::Request<TaintedValue>,
    execution: ExecutionId,
    deadline: Option<HostDeadline>,
    effectful: bool,
    dispatch_witness: Option<Arc<AtomicBool>>,
}

type Pending<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = (usize, u64, bool, MachineRequestCompletion)> + Send + 'a>,
>;

/// The host can inspect pending futures at expiry without sharing a counter or
/// cloning an identifier on every successful call. A dispatch witness separates
/// pending authorization from a started effect; ungated calls use host polling.
struct PendingHostRequest<'a> {
    future: Pending<'a>,
    operation_id: Option<OperationId>,
    effectful: bool,
    polled_pending: bool,
    dispatch_witness: Option<Arc<AtomicBool>>,
}

struct InterruptionContext<'a, 'host> {
    pending: &'a FuturesUnordered<PendingHostRequest<'host>>,
    unresolved: &'a UnresolvedOperations,
}

impl PendingHostRequest<'_> {
    fn may_have_started(&self) -> bool {
        self.effectful
            && self
                .dispatch_witness
                .as_ref()
                .map_or(self.polled_pending, |witness| {
                    witness.load(Ordering::Relaxed)
                })
    }

    fn in_flight_operation(&self) -> Option<OperationId> {
        self.may_have_started()
            .then_some(self.operation_id)
            .flatten()
    }
}

impl Future for PendingHostRequest<'_> {
    type Output = (
        usize,
        u64,
        Option<OperationId>,
        bool,
        MachineRequestCompletion,
    );

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.future.as_mut().poll(cx) {
            std::task::Poll::Pending => {
                self.polled_pending = true;
                std::task::Poll::Pending
            }
            std::task::Poll::Ready((task, ticket, aborted, event)) => std::task::Poll::Ready((
                task,
                ticket,
                self.operation_id,
                aborted && self.may_have_started(),
                event,
            )),
        }
    }
}

fn capture_operation_completion(
    operation_id: Option<OperationId>,
    aborted_after_poll: bool,
    event: &HostEvent<TaintedValue, TaintedFailure>,
    unresolved: &mut UnresolvedOperations,
) {
    let Some(operation_id) = operation_id else {
        return;
    };
    if aborted_after_poll {
        unresolved.record(&operation_id.to_string());
    }
    if let HostEvent::Complete(Err(error)) = event {
        capture_unknown_failure(&error.failure, unresolved);
    }
}

fn capture_unknown_failure(failure: &Failure, unresolved: &mut UnresolvedOperations) {
    if let Failure::OutcomeUnknown { operation_ids, .. } = failure {
        for id in operation_ids {
            unresolved.record(id);
        }
    }
}

fn may_have_external_effect(replay: ReplayClass) -> bool {
    matches!(
        replay,
        ReplayClass::IdempotentEffect | ReplayClass::NonIdempotentEffect
    )
}

impl Executor {
    fn import_may_have_external_effect(&self, import: &Import) -> bool {
        let Import::Operation { operation, .. } = import else {
            return false;
        };
        // Normal imports use the same frozen metadata cache as dispatch. If
        // resolution fails, keep the conservative effectful classification.
        match self.resolve_meta(&operation.target, &operation.method) {
            Ok(Some(meta)) => may_have_external_effect(meta.method.replay),
            _ => true,
        }
    }

    fn request_operation_id(
        &self,
        program: &MachineProgram,
        execution: ExecutionId,
        request: &xolotl_core::Request<TaintedValue>,
    ) -> Option<OperationId> {
        matches!(
            program.imports.get(request.import as usize),
            Some(Import::Operation { .. })
        )
        .then(|| {
            self.request_id(execution, request.ticket, request.position)
                .ok()
        })
        .flatten()
    }

    fn interruption_failure(
        &self,
        context: InterruptionContext<'_, '_>,
        reason: &'static str,
        otherwise: Failure,
    ) -> Failure {
        let mut operation_ids = Vec::new();
        operation_ids.extend(
            context
                .pending
                .iter()
                .filter_map(PendingHostRequest::in_flight_operation),
        );
        interruption_failure(operation_ids, context.unresolved, reason, otherwise)
    }

    async fn complete_machine(
        &self,
        execution: &mut Execution<'_, TaintedValue, TaintedFailure>,
        program: &mut Cow<'_, MachineProgram>,
        task: usize,
        ticket: u64,
        event: HostEvent<TaintedValue, TaintedFailure>,
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
        self.run_machine_with_buffers(Cow::Borrowed(&program.inner), input, buffers, None)
            .await
    }

    pub(super) async fn run_machine(
        &self,
        program: Cow<'_, MachineProgram>,
        input: TaintedValue,
    ) -> ExecutionOutput {
        self.run_machine_with_buffers(program, input, &mut ExecutionBuffers::default(), None)
            .await
    }

    pub(super) async fn run_machine_with_buffers(
        &self,
        mut program: Cow<'_, MachineProgram>,
        input: TaintedValue,
        buffers: &mut ExecutionBuffers,
        reserved_execution: Option<ExecutionId>,
    ) -> ExecutionOutput {
        let entry_taint = input.taint.clone();
        let failed = |error| Self::failed(error, entry_taint.clone());
        let mut standalone_unresolved = UnresolvedOperations::default();
        if self.deadline_elapsed() {
            return failed(Failure::Timeout);
        }
        let Some(acting) = self.default_acting() else {
            return failed(machine_error(format!(
                "unknown process {}",
                self.process.get()
            )));
        };
        if let Err(error) = self.identities.verify(acting) {
            return failed(machine_error(format!("execution identity: {error}")));
        }
        if let Err(error) = self.execution_config.check_program(&program) {
            return failed(error);
        }
        macro_rules! run_output {
            ($output:expr) => {
                ($output).with_unresolved_operations(standalone_unresolved)
            };
        }
        let effective_deadline = self.deadline;
        let deadline_elapsed = || {
            effective_deadline.is_some_and(|deadline| {
                deadline.elapsed_at(self.host_runtime.now()).unwrap_or(true)
            })
        };
        let execution_id = match reserved_execution {
            Some(execution) => Ok(execution),
            None => self.allocate_execution_async().await,
        };
        let execution_id = match execution_id {
            Ok(id) => id,
            Err(error) => return run_output!(failed(error)),
        };
        let layout = self.execution_config.layout(&program);
        let mut layout = match layout {
            Ok(layout) => layout,
            Err(error) => return run_output!(failed(error)),
        };
        let limits = layout.limits(&self.execution_config);
        let storage = match buffers.acquire(layout, self.execution_config.max_storage_bytes) {
            Ok(storage) => storage,
            Err(error) => return run_output!(failed(error)),
        };
        let initialization = initialize_machine(&program, storage.buffers, limits, input, acting);
        let mut execution = match initialization {
            Ok(execution) => execution,
            Err(error) => return run_output!(failed(error)),
        };
        if deadline_elapsed() {
            return run_output!(self.execution_failure(&execution, Failure::Timeout));
        }
        let mut values = HostValues;
        let mut pending: FuturesUnordered<PendingHostRequest<'_>> = FuturesUnordered::new();
        let mut aborts = HashMap::new();
        let mut cancelling = false;
        let mut turns = 0;
        let deadline = effective_deadline.map(|deadline| self.host_runtime.sleep_until(deadline));
        tokio::pin!(deadline);
        if deadline_elapsed() {
            let unresolved = &mut standalone_unresolved;
            let failure = self.interruption_failure(
                InterruptionContext {
                    pending: &pending,
                    unresolved,
                },
                "deadline_exceeded",
                Failure::Timeout,
            );
            return self.interruption_output(&execution, failure, unresolved);
        }
        loop {
            if deadline_elapsed() {
                let unresolved = &mut standalone_unresolved;
                let failure = self.interruption_failure(
                    InterruptionContext {
                        pending: &pending,
                        unresolved,
                    },
                    "deadline_exceeded",
                    Failure::Timeout,
                );
                return self.interruption_output(&execution, failure, unresolved);
            }
            if !cancelling && self.is_cancelled() {
                execution.cancel();
                cancelling = true;
            }
            let action = if turns == self.execution_config.quantum {
                Advance::Yielded
            } else {
                turns += 1;
                execution.advance(&program.image(), &mut values, self.execution_config.quantum)
            };
            if deadline_elapsed() {
                let unresolved = &mut standalone_unresolved;
                let failure = self.interruption_failure(
                    InterruptionContext {
                        pending: &pending,
                        unresolved,
                    },
                    "deadline_exceeded",
                    Failure::Timeout,
                );
                return self.interruption_output(&execution, failure, unresolved);
            }
            if let Cow::Owned(program) = &mut program
                && let Err(error) = program.reclaim(&mut execution)
            {
                return run_output!(self.execution_failure(&execution, error));
            }
            let completion = match action {
                Advance::Done(result) => {
                    let unresolved = &mut standalone_unresolved;
                    for operation in pending
                        .iter()
                        .filter_map(PendingHostRequest::in_flight_operation)
                    {
                        unresolved.record(&operation.to_string());
                    }
                    return ExecutionOutput::from_result(result)
                        .with_unresolved_operations(standalone_unresolved);
                }
                Advance::Cancel { task, ticket } => {
                    if let Some(abort) = aborts.get(&(task, ticket)) {
                        AbortHandle::abort(abort);
                        None
                    } else {
                        Some((
                            task,
                            ticket,
                            None,
                            false,
                            Ok(HostEvent::Complete(Err(Failure::Cancelled.into()))),
                        ))
                    }
                }
                Advance::Request(request) => {
                    let Some(import) = program.imports.get(request.import as usize).cloned() else {
                        return run_output!(
                            self.execution_failure(&execution, machine_error("missing import"))
                        );
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
                            return run_output!(self.execution_failure(
                                &execution,
                                machine_error(format!("transform: {error:?}")),
                            ));
                        }
                        continue;
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
                                ) {
                                    Ok(execution) => execution,
                                    Err(error) => {
                                        return run_output!(Self::failed(
                                            machine_error(format!(
                                                "resuming execution storage: {error:?}"
                                            )),
                                            request.input.taint,
                                        ));
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
                        if let Err(error) = self
                            .complete_machine(
                                &mut execution,
                                &mut program,
                                request.task,
                                request.ticket,
                                event,
                            )
                            .await
                        {
                            return run_output!(Self::failed(error.failure, error.taint));
                        }
                        continue;
                    }
                    let (abort, registration) = AbortHandle::new_pair();
                    aborts.insert((request.task, request.ticket), abort);
                    let operation_id = self.request_operation_id(&program, execution_id, &request);
                    let effectful = self.import_may_have_external_effect(&import);
                    let dispatch_witness = (effectful && self.data_plane.has_request_authorizer())
                        .then(|| Arc::new(AtomicBool::new(false)));
                    pending.push(PendingHostRequest {
                        operation_id,
                        effectful,
                        polled_pending: false,
                        dispatch_witness: dispatch_witness.clone(),
                        future: Box::pin(async move {
                            let task = request.task;
                            let ticket = request.ticket;
                            let (aborted, event) = match Abortable::new(
                                self.machine_request(MachineRequestCall {
                                    import,
                                    request,
                                    execution: execution_id,
                                    deadline: effective_deadline,
                                    effectful,
                                    dispatch_witness,
                                }),
                                registration,
                            )
                            .await
                            {
                                Ok(event) => (false, event),
                                Err(_) => (
                                    true,
                                    Ok(HostEvent::Complete(Err(Failure::Cancelled.into()))),
                                ),
                            };
                            (task, ticket, aborted, event)
                        }),
                    });
                    None
                }
                Advance::Yielded => {
                    turns = 0;
                    crate::runtime::Cooperative.cooperate().await;
                    pending.next().now_or_never().flatten()
                }
                Advance::Waiting => {
                    let event = tokio::select! {
                        biased;
                        deadline_result = async {
                            if let Some(deadline) = deadline.as_mut().as_pin_mut() {
                                deadline.await
                            } else {
                                Ok(())
                            }
                        }, if effective_deadline.is_some() => {
                            let unresolved = &mut standalone_unresolved;
                            let failure = self.interruption_failure(
                                InterruptionContext {
                                    pending: &pending,
                                    unresolved,
                                },
                                "deadline_exceeded",
                                deadline_result.err().map_or(Failure::Timeout, Into::into),
                            );
                            return self.interruption_output(&execution, failure, unresolved);
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
                        return run_output!(self.execution_failure(
                            &execution,
                            machine_error("execution blocked without a host request"),
                        ));
                    };
                    Some(event)
                }
            };
            if let Some((task, ticket, operation_id, aborted_after_poll, event)) = completion {
                aborts.remove(&(task, ticket));
                let event = match event {
                    Ok(event) => event,
                    Err(mut error) => {
                        if let Some(id) = error.unresolved_operation {
                            standalone_unresolved.record(&id.to_string());
                        }
                        error
                            .failure
                            .taint
                            .union(&execution.retain_control(&mut HostValues).taint);
                        return run_output!(Self::failed(
                            error.failure.failure,
                            error.failure.taint
                        ));
                    }
                };
                if execution.is_pending(task, ticket) {
                    capture_operation_completion(
                        operation_id,
                        aborted_after_poll,
                        &event,
                        &mut standalone_unresolved,
                    );
                    if let Err(error) = self
                        .complete_machine(&mut execution, &mut program, task, ticket, event)
                        .await
                    {
                        return run_output!(Self::failed(error.failure, error.taint));
                    }
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
                if revision.is_some() {
                    return Err(machine_error(
                        "revision-bound loader cannot be a native continuation",
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

    async fn machine_request(&self, call: MachineRequestCall) -> MachineRequestCompletion {
        let MachineRequestCall {
            import,
            request,
            execution,
            deadline,
            effectful,
            dispatch_witness,
        } = call;
        let expired = match deadline {
            Some(deadline) => match deadline.elapsed_at(self.host_runtime.now()) {
                Ok(expired) => expired,
                Err(error) => {
                    return Ok(HostEvent::Complete(Err(TaintedFailure::new(
                        error.into(),
                        request.input.taint,
                    ))));
                }
            },
            None => false,
        };
        if expired {
            return Ok(HostEvent::Complete(Err(TaintedFailure::new(
                Failure::Timeout,
                request.input.taint,
            ))));
        }
        let id = self.request_id(execution, request.ticket, request.position);
        let input = request.input;
        let context = request.context;
        let output = match import {
            Import::Operation { operation } => {
                let id = match id {
                    Ok(id) => id,
                    Err(error) => {
                        return Ok(HostEvent::Complete(Err(TaintedFailure::new(
                            error,
                            input.taint,
                        ))));
                    }
                };
                let env = Env::root(IdentityRef::new(context)).with_taint(input.taint);
                let call = self.run_operation(
                    &operation,
                    input.value,
                    &env,
                    id,
                    self.record_facts,
                    dispatch_witness.as_deref(),
                );
                let result = if request.cleanup
                    && let Some(processes) = &self.processes
                {
                    crate::process::scope_cleanup(processes, self.process, call).await
                } else {
                    call.await
                };
                if let Some(error) = result.completion_error {
                    match error {
                        crate::invocation::CompletionError::Fact(error) => {
                            tracing::warn!(operation = %id, %error, "selected invocation observation failed");
                        }
                        crate::invocation::CompletionError::Dispatch(_)
                            if !result.effect_may_have_started => {}
                        error => {
                            return Err(Box::new(MachineRequestError {
                                failure: TaintedFailure::new(
                                    error.outcome_unknown(id),
                                    result.output.taint,
                                ),
                                unresolved_operation: (effectful && result.effect_may_have_started)
                                    .then_some(id),
                            }));
                        }
                    }
                }
                result.output
            }
            Import::Wait(wait) => {
                let mut output = self.run_wait(&wait).await;
                output.taint.union(&input.taint);
                output
            }
            Import::Scope(identity) => {
                return Ok(if self.authorize_act_as(&identity, &input.value) {
                    match self.identities.resolve_or_register(&identity) {
                        Ok(acting) => HostEvent::Enter(acting.get()),
                        Err(error) => HostEvent::Complete(Err(TaintedFailure::new(
                            Failure::policy("identity", error.to_string()),
                            input.taint,
                        ))),
                    }
                } else {
                    HostEvent::Complete(Err(TaintedFailure::new(
                        Failure::policy("act-as", "identity delegation denied"),
                        input.taint,
                    )))
                });
            }
            Import::Step(..) | Import::Vacant => {
                return Ok(HostEvent::Complete(Err(TaintedFailure::new(
                    machine_error("continuation was not linked"),
                    input.taint,
                ))));
            }
            Import::Transform(operation) => {
                return Ok(HostEvent::Complete(match operation.apply(input.value) {
                    Ok(value) => Ok(TaintedValue::new(value, input.taint)),
                    Err(error) => Err(TaintedFailure::new(error, input.taint)),
                }));
            }
        };
        Ok(HostEvent::Complete(output.into_result()))
    }
}

fn interruption_failure(
    operation_ids: impl IntoIterator<Item = OperationId>,
    unresolved: &UnresolvedOperations,
    reason: &'static str,
    otherwise: Failure,
) -> Failure {
    let mut operation_ids: Vec<String> =
        operation_ids.into_iter().map(|id| id.to_string()).collect();
    operation_ids.extend(unresolved.operation_ids.iter().cloned());
    operation_ids.sort_unstable();
    operation_ids.dedup();
    if operation_ids.is_empty() && !unresolved.identities_incomplete {
        otherwise
    } else {
        Failure::OutcomeUnknown {
            operation_ids,
            reason: reason.into(),
        }
    }
}

impl Executor {
    fn interruption_output(
        &self,
        execution: &Execution<'_, TaintedValue, TaintedFailure>,
        failure: Failure,
        unresolved: &mut UnresolvedOperations,
    ) -> ExecutionOutput {
        capture_unknown_failure(&failure, unresolved);
        self.execution_failure(execution, failure)
            .with_unresolved_operations(std::mem::take(unresolved))
    }

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
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                xolotl_types::Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )
            .unprotected_input()],
            Arc::new(crate::EchoDriver),
        )?;
        let executor = boot.kernel().executor_for(boot.root());
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
        for allowed in [true, false] {
            cancellation_cleanup(Bootstrap::in_memory(), allowed).await?;
        }
        Ok(())
    }

    async fn cancellation_cleanup(boot: Bootstrap, allowed: bool) -> anyhow::Result<()> {
        let driver = Arc::new(CleanupDriver {
            started: tokio::sync::Notify::new(),
            released: AtomicBool::new(false),
            cleaned: AtomicUsize::new(0),
        });
        let mut method = MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        );
        if allowed {
            method = method.finalize_allowed();
        }
        let name = boot.register_effect_with_cost(
            "effect://cleanup/run",
            &[method],
            driver.clone(),
            CostModel {
                flat_micro_usd: 100,
                ..Default::default()
            },
        )?;
        let process = boot.root();
        ensure!(
            boot.kernel()
                .processes()
                .set_budget_spec(
                    process,
                    BudgetSpec {
                        max_inflight_ops: Some(1),
                        ..Default::default()
                    }
                )
                .is_ok()
        );
        let invoke = |cleanup| E::Invoke {
            operation: OperationTemplate {
                target: name.clone(),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: Some(Value::boolean(cleanup)),
            },
        };
        let source = Program::new(invoke(false).finally(invoke(true)));
        let program = source.compile()?;
        let executor = boot.kernel().executor_for(process);
        let run = executor.eval_program(&program, TaintedValue::pristine(Value::null()));
        tokio::pin!(run);
        tokio::select! {
            output = &mut run => anyhow::bail!("operation completed before cancellation: {output:?}"),
            () = driver.started.notified() => {}
        }
        boot.cancel_process(process)?;
        let output = tokio::time::timeout(std::time::Duration::from_secs(1), run).await?;
        ensure!(output.outcome == Outcome::Fail(Failure::Cancelled));
        ensure!(
            driver.cleaned.load(Ordering::SeqCst) == usize::from(allowed),
            "cleanup did not respect release, budget or method permission: {output:?}"
        );
        let budget = boot
            .kernel()
            .processes()
            .budget_mut(process, |budget| budget.clone())
            .context("missing budget")?;
        ensure!(budget.inflight_ops == 0);
        ensure!(
            budget.spent_micro_usd == if allowed { 200 } else { 100 },
            "uncertain spending was refunded"
        );
        Ok(())
    }
}
