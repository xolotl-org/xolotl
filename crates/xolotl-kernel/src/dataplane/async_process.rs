//! Adapt one operation into a managed process with explicit host ownership.

use super::*;
use crate::bootstrap::BootstrapError;
use crate::bootstrap::finalize::{acquire_finalization, commit_process_terminal};
use crate::host::async_process::{AsyncProcessOwner, AsyncProcessRequest};
use crate::process::{ProcessEntry, ProcessPublication};
use std::sync::atomic::{AtomicBool, Ordering};
use xolotl_types::{ExecutionOutput, ProcessId, ProcessStatus, UnresolvedOperations};

enum ChildExit {
    Interrupted(Failure),
    PrepareFailed(TaintedFailure),
    Completed(InvocationResult),
}

/// Retain a truthful unknown result when the scheduler drops the entire child
/// body, bypassing its normal terminal publication path.
struct ChildEffectGuard<'a> {
    processes: &'a crate::process::ProcessTable,
    operation: &'a Operation,
    dispatched: AtomicBool,
    completed: bool,
}

impl<'a> ChildEffectGuard<'a> {
    fn new(processes: &'a crate::process::ProcessTable, operation: &'a Operation) -> Self {
        Self {
            processes,
            operation,
            dispatched: AtomicBool::new(false),
            completed: false,
        }
    }

    fn was_dispatched(&self) -> bool {
        self.dispatched.load(Ordering::Relaxed)
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for ChildEffectGuard<'_> {
    fn drop(&mut self) {
        if self.completed || !self.was_dispatched() {
            return;
        }
        // This guard drops before TaskOwner, whose cleanup would otherwise
        // select cancellation only after retain_outcome chose a failed status.
        drop(self.processes.request_cleanup_tree(self.operation.process));
        let id = self.operation.id.to_string();
        let mut unresolved = UnresolvedOperations::default();
        unresolved.record(&id);
        let output = ExecutionOutput::new(
            Outcome::Fail(Failure::OutcomeUnknown {
                operation_ids: vec![id],
                reason: "task_aborted_after_dispatch".into(),
            }),
            self.operation.taint.clone(),
        )
        .with_unresolved_operations(unresolved);
        self.processes
            .retain_outcome(self.operation.process, output);
    }
}

fn process_admission_failure(error: crate::process::ProcessAdmissionError) -> Failure {
    match error {
        crate::process::ProcessAdmissionError::Unavailable { .. } => Failure::Cancelled,
        other => Failure::Custom {
            kind: "process_admission".into(),
            message: other.to_string(),
        },
    }
}

struct Publication(Arc<dyn AsyncProcessOwner>);

#[async_trait::async_trait]
impl ProcessPublication for Publication {
    fn released(&self, status: ProcessStatus, output: Option<&ExecutionOutput>) {
        self.0.released(status, output);
    }

    async fn publish(
        &self,
        _state: &xolotl_state::Backend,
        _process: ProcessId,
        status: ProcessStatus,
        outcome: Option<&ExecutionOutput>,
    ) -> Result<(), BootstrapError> {
        self.0
            .publish(status, outcome)
            .await
            .map_err(|failure| BootstrapError::Publication(Box::new(failure)))
    }
}

// A rejected kernel admission cannot strand the already-derived child handle.
struct Reservation {
    handles: HandleTable,
    process: ProcessId,
    admitted: bool,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if self.admitted {
            return;
        }
        self.handles.write().revoke_owned_by(self.process);
    }
}

fn stopped(failure: Failure) -> DriverOutput {
    DriverOutput::new(Outcome::Fail(failure))
}
async fn deadline_elapsed(
    runtime: &HostRuntime,
    deadline: Option<HostDeadline>,
) -> Result<(), Failure> {
    match deadline {
        Some(deadline) => runtime.sleep_until(deadline).await.map_err(Into::into),
        None => std::future::pending().await,
    }
}

impl DataPlane {
    pub(super) fn start_async_process<'a>(
        &'a self,
        op: &'a Operation,
        contract: xolotl_types::MethodContract,
        resolved: &'a Resolved,
        record: bool,
        dispatch_witness: Option<&'a AtomicBool>,
    ) -> futures_util::future::BoxFuture<'a, Outcome> {
        // This edge re-enters execute_inner for the child. Erase only the
        // asynchronous process adapter, keeping ordinary invocations unboxed.
        Box::pin(async move {
            let Some(host) = &self.async_process_host else {
                return Outcome::Fail(Failure::policy(
                    "async-process",
                    "AsyncProcess requires a host owner",
                ));
            };
            let Some(processes) = self.processes.clone() else {
                return Outcome::Fail(Failure::policy(
                    "async-process",
                    "AsyncProcess requires a process table",
                ));
            };
            let expired = match self.deadline {
                Some(deadline) => match deadline.elapsed_at(self.host_runtime.now()) {
                    Ok(expired) => expired,
                    Err(error) => return Outcome::Fail(error.into()),
                },
                None => false,
            };
            if expired {
                return Outcome::Fail(Failure::Timeout);
            }
            let child = match processes.fresh_id() {
                Ok(child) => child,
                Err(error) => return Outcome::Fail(process_admission_failure(error)),
            };
            let request = AsyncProcessRequest {
                source: op.id,
                process: child,
                acting: op.acting,
                resource: resolved.resource,
                target: resolved.bound_path.clone(),
                method: op.method,
                contract,
                input_taint: op.taint.clone(),
                deadline: self.deadline,
            };
            // The admission owns any host reservation across its waits. No child
            // handle or process exists until it returns; cancelling cannot strand one.
            let admission = tokio::select! {
                biased;
                () = processes.wait_for_cancellation(op.process, false) => return Outcome::Fail(Failure::Cancelled),
                result = deadline_elapsed(&self.host_runtime, self.deadline) => return Outcome::Fail(result.err().unwrap_or(Failure::Timeout)),
                admission = AssertUnwindSafe(async { host.admit(&request).await }).catch_unwind() => admission,
            };
            let mut admission = match admission {
                Ok(Ok(admission)) => admission,
                Ok(Err(failure)) => return Outcome::Fail(failure),
                Err(payload) => {
                    return Outcome::Fail(Failure::HandlerError {
                        kind: "panic".into(),
                        message: crate::bootstrap::panic_payload_message(
                            "async process admission",
                            payload,
                        ),
                    });
                }
            };
            if let Some(child) = admission.deadline
                && let Err(error) = self.host_runtime.validate_deadline(child)
            {
                return Outcome::Fail(error.into());
            }
            let deadline = match (self.deadline, admission.deadline) {
                (Some(parent), Some(child)) => match parent.earliest(child) {
                    Ok(deadline) => Some(deadline),
                    Err(error) => return Outcome::Fail(error.into()),
                },
                (parent, child) => parent.or(child),
            };
            if deadline.is_some_and(|deadline| {
                deadline.elapsed_at(self.host_runtime.now()).unwrap_or(true)
            }) {
                return Outcome::Fail(Failure::Timeout);
            }
            if processes.status(op.process) != Some(ProcessStatus::Running) {
                return Outcome::Fail(Failure::Cancelled);
            }
            if let FastPath::Conditional(snapshot) = &resolved.fast_path {
                let ctx = CheckCtx {
                    input: &op.input,
                    acting: op.acting,
                    now_millis: self.host_runtime.now_millis(),
                    target: resolved.resource,
                };
                if !snapshot.check_derivation(&ctx).await.is_allow() {
                    return Outcome::Fail(Failure::policy(
                        "grant",
                        "grant authority changed before child derivation",
                    ));
                }
            }
            if processes.status(op.process) != Some(ProcessStatus::Running) {
                return Outcome::Fail(Failure::Cancelled);
            }
            // Authority may have been revoked while the host awaited storage or
            // capacity. Re-derive under the handle lock, including for prior receipts.
            if let Err(failure) = self.authorize_request(op.process).await {
                return Outcome::Fail(failure);
            }
            let child_handle = {
                match self.handles.derive(
                    op.handle,
                    xolotl_types::Rights::new(
                        xolotl_types::MethodBitmap::method(contract.method_index),
                        xolotl_types::RightFlags::empty(),
                    ),
                    xolotl_types::DeriveKind::SpawnWith,
                    child,
                ) {
                    Ok(handle) => handle,
                    Err(_) => {
                        return Outcome::Fail(Failure::PermissionDenied {
                            required: vec!["SPAWN_WITH".into()],
                            actual: vec![],
                        });
                    }
                }
            };
            // Drop this handle before the admission guard releases the host slot.
            let mut reservation = Reservation {
                handles: self.handles.clone(),
                process: child,
                admitted: false,
            };
            let Some(host_owner) = admission.owner.as_ref().cloned() else {
                // Reservation drop revokes the unused derived handle. The host's
                // existing acceptance keeps its original process and supervisor.
                return Outcome::Done(admission.reference.clone());
            };
            let mut entry = ProcessEntry::new(child, Some(op.process), op.acting);
            entry.scope.initialize_lifecycle(op.id.execution);
            entry.scope.start();
            entry.publication = Some(Arc::new(Publication(host_owner.clone())));
            if let Err(error) = processes.admit_child(entry) {
                return Outcome::Fail(process_admission_failure(error));
            }
            // The table retains the owner until publication, including task-attachment failure.
            reservation.admitted = true;
            admission.owner = None;
            let reference = admission.reference.clone();
            let finalization_timeout = admission.finalization_timeout;
            let child_op = Operation {
                id: xolotl_types::OperationId {
                    process: child,
                    ..op.id
                },
                process: child,
                acting: op.acting,
                handle: child_handle,
                method: op.method,
                input: op.input.clone(),
                taint: op.taint.clone(),
                output: OutputMode::AsyncProcess,
            };
            let child_dp = self.clone();
            let child_processes = processes.clone();
            let child_runtime = self.host_runtime.clone();
            let child_effectful = may_have_external_effect(contract.replay);
            if let Some(witness) = dispatch_witness {
                witness.store(true, Ordering::Relaxed);
            }
            let task = processes.spawn_task(child, self.handles.clone(), move |owner| async move {
            // Complete this scope before releasing task ownership so cancellation drops the driver first.
            let mut effect = ChildEffectGuard::new(&child_processes, &child_op);
            let result = AssertUnwindSafe(async {
                tokio::select! {
                    biased;
                    () = child_processes.wait_for_cancellation(child, false) => ChildExit::Interrupted(Failure::Cancelled),
                    result = deadline_elapsed(&child_runtime, deadline) => ChildExit::Interrupted(result.err().unwrap_or(Failure::Timeout)),
                    failure = host_owner.cancelled() => ChildExit::Interrupted(failure),
                    result = async {
                        if let Err(error) = host_owner.prepare().await {
                            return ChildExit::PrepareFailed(error);
                        }
                        let result = Box::pin(child_dp.execute_inner(
                            &child_op,
                            InvocationOptions { caller_identity: Some(child_op.acting), now_millis: child_runtime.now_millis(), record },
                            true,
                            DispatchAttachments {
                                witness: Some(&effect.dispatched),
                                ..DispatchAttachments::default()
                            },
                        )).await;
                        ChildExit::Completed(result)
                    } => result,
                }
            }).catch_unwind().await;
            let mut unresolved = UnresolvedOperations::default();
            let output = match result {
                Ok(ChildExit::Interrupted(failure)) => {
                    if effect.was_dispatched() {
                        unresolved.record(&child_op.id.to_string());
                    }
                    stopped(failure)
                }
                Ok(ChildExit::PrepareFailed(error)) => stopped(error.failure).with_taint(error.taint),
                Ok(ChildExit::Completed(InvocationResult { output, completion_error, effect_may_have_started })) => {
                    if let Outcome::Fail(Failure::OutcomeUnknown { operation_ids, .. }) = &output.outcome {
                        for id in operation_ids {
                            unresolved.record(id);
                        }
                    }
                    match completion_error {
                        Some(CompletionError::Fact(error)) => {
                            tracing::warn!(operation = %child_op.id, %error, "selected invocation observation failed");
                            output
                        }
                        Some(CompletionError::Dispatch(_)) if !effect_may_have_started => output,
                        Some(error) => {
                            if child_effectful && effect_may_have_started {
                                unresolved.record(&child_op.id.to_string());
                            }
                            stopped(error.outcome_unknown(child_op.id)).with_taint(output.taint)
                        }
                        None => output,
                    }
                }
                Err(payload) => {
                    if effect.was_dispatched() {
                        unresolved.record(&child_op.id.to_string());
                    }
                    DriverOutput { outcome: Outcome::Fail(Failure::HandlerError {
                        kind: "panic".into(),
                        message: crate::bootstrap::panic_payload_message("async process", payload),
                    }), taint: TaintSet::pristine(), usage: None, origin: CompletionOrigin::CurrentAttempt }
                }
            };
            let output = crate::invocation::complete_output(output, &child_op.taint);
            let retained = owner.finish(ExecutionOutput::new(output.outcome, output.taint).with_unresolved_operations(unresolved));
            effect.complete();
            let Some(retained) = retained else {
                return;
            };
            let terminal = crate::process::outcome_status(&retained.outcome);
            let completion = async {
                let Some(guard) = acquire_finalization(&child_processes, child, terminal).await? else {
                    return Ok(());
                };
                crate::process::scope_finalizer(&child_processes, child, commit_process_terminal(
                    &child_processes,
                    &child_dp.handles,
                    &child_dp.state,
                    child,
                    guard,
                )).await
            };
            let result = match finalization_timeout {
                Some(timeout) => match child_runtime.deadline_after(timeout) {
                    Some(deadline) => tokio::select! {
                        biased;
                        result = completion => result,
                        result = child_runtime.sleep_until(deadline) => Err(BootstrapError::Publication(Box::new(result.err().map_or(Failure::Timeout, Into::into)))),
                    },
                    None => Err(BootstrapError::Publication(Box::new(Failure::Timeout))),
                },
                None => completion.await,
            };
            if let Err(error) = result {
                tracing::warn!(process = child.get(), %error, "async process completion remains pending");
            }
        });
            if let Err(error) = task {
                if error == crate::process::TaskAttachment::NoRuntime {
                    let revoked = self.handles.write().revoke_owned_by(child);
                    processes.record_revocation(child, revoked);
                    if processes.discard_unstarted_child(child, op.process) {
                        return Outcome::Fail(Failure::Cancelled);
                    }
                }
                for process in processes.request_cleanup_tree(child) {
                    processes.abort_task(process);
                    let revoked = self.handles.write().revoke_owned_by(process);
                    processes.record_revocation(process, revoked);
                }
                tracing::debug!(
                    process = child.get(),
                    ?error,
                    "async process task admission rejected"
                );
                return Outcome::Fail(Failure::Cancelled);
            }
            Outcome::Done(reference)
        })
    }
}

#[cfg(test)]
pub(super) mod tests;
