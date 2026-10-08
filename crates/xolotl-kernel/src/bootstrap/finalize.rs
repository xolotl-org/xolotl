//! Finish live process finalizers and release their owned resources.

use super::*;
use crate::process::{FinalizationGuard, FinalizeStart, ProcessTable};

#[cfg(test)]
mod tests;

impl Bootstrap {
    /// Close a process tree, aborting and awaiting its bodies before finalization.
    /// Live processes become cancelled; previously chosen outcomes are retained.
    /// Finished ancestors still close any independently running descendants.
    /// To let a body run lexical cleanup, cancel it and await its normal outcome.
    pub async fn finalize_process(&self, process: ProcessId) -> Result<(), BootstrapError> {
        let processes = self.kernel().processes();
        let ticket = self.cleanup_ticket(process)?;
        let current = processes
            .status(process)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
        reject_self_wait(processes, process, true)?;
        let status = if current.is_terminal() {
            current
        } else {
            ProcessStatus::Cancelled
        };
        // Select members and retain their cleanup owners in the same transition
        // that closes tree admission, before any cancellation observer runs.

        let selection = processes
            .request_tree_cleanup_selection(&ticket)
            .map_err(|_error| BootstrapError::NoSuchProcess { process })?;
        let descendants: Vec<_> = selection
            .tickets()
            .iter()
            .map(crate::process::CleanupTicket::process)
            .collect();
        let guard = acquire_finalization(processes, process, status).await?;
        for descendant in &descendants {
            processes.abort_task(*descendant);
        }
        for descendant in &descendants {
            processes.wait_for_task_exit(*descendant).await;
        }

        let mut failure = None;
        for descendant in descendants {
            if descendant == process {
                continue;
            }
            let result =
                match acquire_finalization(processes, descendant, ProcessStatus::Cancelled).await {
                    Ok(Some(guard)) => {
                        finish_process_terminal_attempt(self.kernel(), descendant, guard).await
                    }
                    Ok(None) => {
                        self.kernel().handles().write().revoke_owned_by(descendant);
                        Ok(())
                    }
                    Err(error) => Err(error),
                };
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        if let Some(guard) = guard {
            finish_process_terminal_attempt(self.kernel(), process, guard).await?;
        } else {
            self.kernel().handles().write().revoke_owned_by(process);
        }
        Ok(())
    }

    /// Request cancellation at the process's next execution boundary.
    /// Use tree finalization when descendants must also stop.
    pub fn cancel_process(&self, process: ProcessId) -> Result<bool, BootstrapError> {
        self.kernel()
            .processes()
            .cancel_if_non_terminal(process)
            .ok_or(BootstrapError::NoSuchProcess { process })
    }

    /// Finish the specified process after its body returns.
    /// Independently owned Actor and AsyncProcess descendants may continue.
    pub async fn finish_request_process(
        &self,
        process: ProcessId,
        output: &xolotl_types::ExecutionOutput,
    ) -> Result<(), BootstrapError> {
        self.finish_process_with_control(
            process,
            crate::process::outcome_status(&output.outcome),
            &output.taint,
            Some(&output.unresolved_operations),
        )
        .await
    }

    /// Finish one process with an explicit terminal intent.
    /// An attached body is stopped and joined before finalizers may use its resources.
    /// Reentrant completion from that body or its finalizer returns ProcessBusy.
    pub async fn finish_process_as(
        &self,
        process: ProcessId,
        status: ProcessStatus,
    ) -> Result<(), BootstrapError> {
        self.finish_process_with_control(process, status, &xolotl_types::TaintSet::pristine(), None)
            .await
    }

    async fn finish_process_with_control(
        &self,
        process: ProcessId,
        status: ProcessStatus,
        taint: &xolotl_types::TaintSet,
        unresolved_operations: Option<&xolotl_types::UnresolvedOperations>,
    ) -> Result<(), BootstrapError> {
        if !status.is_terminal() {
            return Err(BootstrapError::NonterminalStatus { process, status });
        }
        reject_self_wait(self.kernel().processes(), process, false)?;
        let Some(guard) = acquire_finalization(self.kernel().processes(), process, status).await?
        else {
            return Ok(());
        };
        self.kernel()
            .processes()
            .retain_finalization_control(process, taint, unresolved_operations)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
        self.kernel().processes().abort_task(process);
        self.kernel().processes().wait_for_task_exit(process).await;
        finish_process_terminal_attempt(self.kernel(), process, guard).await
    }
}

pub(super) fn reject_self_wait(
    processes: &ProcessTable,
    process: ProcessId,
    tree: bool,
) -> Result<(), BootstrapError> {
    let body = crate::process::current_process(processes).filter(|id| processes.has_task(*id));
    for owner in [body, crate::process::current_finalizer(processes)]
        .into_iter()
        .flatten()
    {
        if owner == process || (tree && processes.is_in_tree(process, owner)) {
            return Err(BootstrapError::ProcessBusy { process });
        }
    }
    Ok(())
}

pub(super) fn reject_cleanup_self_wait(
    processes: &ProcessTable,
    process: ProcessId,
    selection: &crate::process::CleanupSelection,
) -> Result<(), BootstrapError> {
    let body = crate::process::current_process(processes).filter(|id| processes.has_task(*id));
    if [body, crate::process::current_finalizer(processes)]
        .into_iter()
        .flatten()
        .any(|owner| selection.contains(owner))
    {
        return Err(BootstrapError::ProcessBusy { process });
    }
    Ok(())
}

/// Retry a pinned selection without selecting another native process tree.
/// Cleanup owners and identity pins outlive task termination and finalization.
pub(super) async fn finish_cleanup_selection(
    kernel: &Kernel,
    process: ProcessId,
    selection: &crate::process::CleanupSelection,
) -> Result<(), BootstrapError> {
    let processes = kernel.processes();
    reject_cleanup_self_wait(processes, process, selection)?;
    for ticket in selection.tickets() {
        processes.abort_task(ticket.process());
    }
    for ticket in selection.tickets() {
        processes.wait_for_task_exit(ticket.process()).await;
    }
    let mut failure = None;
    for ticket in selection.tickets() {
        let member = ticket.process();
        // A tree owner's lifecycle follows its selected descendants. Continue
        // cleaning siblings after a failure, but leave this owner unpublished
        // until a later retry finishes all selected descendant attempts.
        if member == process
            && let Some(error) = failure.take()
        {
            return Err(error);
        }
        let status = ticket
            .terminal_status()
            .ok_or(BootstrapError::ProcessUnavailable { process: member })?;
        let result = match acquire_finalization(processes, member, status).await {
            Ok(Some(guard)) => finish_process_terminal_attempt(kernel, member, guard).await,
            Ok(None) => {
                // A completed Local owner may since have selected Tree. Honor
                // the saved handle closure even when its lifecycle stays closed.
                close_process_handles(processes, kernel.handles(), member);
                Ok(())
            }
            Err(error) => Err(error),
        };
        if let Err(error) = result {
            failure.get_or_insert(error);
        }
    }
    failure.map_or(Ok(()), Err)
}

pub(crate) async fn acquire_finalization(
    processes: &ProcessTable,
    process: ProcessId,
    status: ProcessStatus,
) -> Result<Option<FinalizationGuard>, BootstrapError> {
    loop {
        match processes.begin_finalizing(process, status) {
            FinalizeStart::Started => {
                return Ok(Some(processes.finalization_guard(process)));
            }
            FinalizeStart::AlreadyFinalizing => {
                if crate::process::has_finalizer_context() {
                    return Err(BootstrapError::ProcessBusy { process });
                }
                processes.wait_for_finalization(process).await
            }
            FinalizeStart::AlreadyTerminal => return Ok(None),
            FinalizeStart::NoSuchProcess => return Err(BootstrapError::NoSuchProcess { process }),
            FinalizeStart::InvalidStatus => {
                return Err(BootstrapError::NonterminalStatus { process, status });
            }
        }
    }
}

pub(super) async fn finish_process_terminal_attempt(
    kernel: &Kernel,
    process: ProcessId,
    guard: FinalizationGuard,
) -> Result<(), BootstrapError> {
    crate::process::scope_finalizer(
        kernel.processes(),
        process,
        finish_terminal(kernel, process, guard),
    )
    .await
}

async fn finish_terminal(
    kernel: &Kernel,
    process: ProcessId,
    guard: FinalizationGuard,
) -> Result<(), BootstrapError> {
    let deadline = kernel
        .host_runtime()
        .deadline_after(kernel.execution_config().cleanup_timeout);
    if kernel.processes().lifecycle_execution(process).is_none() {
        let execution = kernel.execution_ids().allocate()?;
        kernel
            .processes()
            .initialize_lifecycle(process, execution)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
    }
    while kernel.processes().has_finalizers(process) {
        // Reserve before consuming the finalizer so allocation failures remain retryable.
        let execution = kernel.execution_ids().allocate()?;
        let body = kernel
            .processes()
            .next_finalizer(process)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
        let mut ex = kernel.executor_for(process).with_finalizer_mode();
        if let Some(authorizer) = kernel.processes().request_authorizer(process) {
            ex = ex.with_request_authorizer(authorizer);
        }
        let output = match deadline {
            Some(deadline) => match ex.with_deadline(deadline) {
                Ok(ex) => ex.eval_finalizer(&body, execution).await,
                Err(error) => xolotl_types::ExecutionOutput::new(
                    xolotl_types::Outcome::Fail(error.into()),
                    xolotl_types::TaintSet::pristine(),
                ),
            },
            None => xolotl_types::ExecutionOutput::new(
                xolotl_types::Outcome::Fail(xolotl_types::Failure::policy(
                    "cleanup",
                    "host clock cannot represent the configured cleanup allowance",
                )),
                xolotl_types::TaintSet::pristine(),
            ),
        };
        if let xolotl_types::Outcome::Fail(failure) = &output.outcome {
            tracing::warn!(
                process = process.get(),
                %failure,
                "process finalizer failed"
            );
        }
        kernel
            .processes()
            .finish_finalizer(process, output)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
    }
    commit_process_terminal(
        kernel.processes(),
        kernel.handles(),
        kernel.state(),
        process,
        guard,
    )
    .await
}

/// Commit terminal effects after the owning body and all finalizers have exited.
/// This path needs no registry, compiler, executor or identity allocator.
pub(crate) async fn commit_process_terminal(
    processes: &ProcessTable,
    handles: &crate::HandleTable,
    state: &xolotl_state::Backend,
    process: ProcessId,
    guard: FinalizationGuard,
) -> Result<(), BootstrapError> {
    let owned_processes = processes.clone();
    let owned_handles = handles.clone();
    let work = processes
        .host_runtime()
        .dispatch_blocking(move || {
            let record = commit_process_terminal_record(&owned_processes, &owned_handles, process);
            (guard, record)
        })
        .map_err(BootstrapError::TerminalRecordScheduling)?;
    // The accepted disposal job retains its finalization owner even if the waiter exits.
    let (_guard, record) = work.await.map_err(BootstrapError::TerminalRecordUnknown)?;
    let actual_status = record?;
    // Handle release precedes publication. Publication failure remains retryable.
    if let Some(publication) = processes.publication(process) {
        let outcome = processes.finalization_outcome(process);
        publication
            .publish(state, process, actual_status, outcome.as_deref())
            .await?;
    }
    processes
        .complete_finalization(process)
        .ok_or(BootstrapError::NoSuchProcess { process })
}

fn commit_process_terminal_record(
    processes: &ProcessTable,
    handles: &crate::HandleTable,
    process: ProcessId,
) -> Result<ProcessStatus, BootstrapError> {
    let terminal_status = processes
        .finalization_status(process)
        .ok_or(BootstrapError::NoSuchProcess { process })?;

    close_process_handles(processes, handles, process)
        .ok_or(BootstrapError::NoSuchProcess { process })?;
    let actual_status = processes
        .mark_terminal_status(process, terminal_status)
        .ok_or(BootstrapError::NoSuchProcess { process })?;

    Ok(actual_status)
}

/// Honor the retained cleanup scope even when a completion attempt is retried.
pub(super) fn close_process_handles(
    processes: &ProcessTable,
    handles: &crate::HandleTable,
    process: ProcessId,
) -> Option<(usize, usize)> {
    let (tree, _) = processes.cleanup_scope(process)?;
    let ((released, revoked), retired) = {
        let mut handles = handles.write();
        let counts = if tree {
            (0, handles.revoke_owned_by(process))
        } else {
            (handles.release_owned_by(process), 0)
        };
        (counts, handles.into_retired())
    };
    let recorded = processes.record_handle_cleanup(process, released, revoked);
    // Native payload destructors can panic. Retain the closure count first,
    // with neither HandleTable nor ProcessTable locked during their Drop.
    drop(retired);
    recorded
}
