//! Resume process finalizers and commit stable lifecycle records.

use super::*;
use crate::process::{FinalizationGuard, FinalizeStart, ProcessTable};

impl Bootstrap {
    /// Close a process tree, aborting and awaiting its bodies before finalization.
    /// Live processes become cancelled; previously chosen outcomes are retained.
    /// Finished ancestors still close any independently running descendants.
    /// To let a body run lexical cleanup, cancel it and await its normal outcome.
    pub async fn finalize_process(&self, process: ProcessId) -> Result<(), BootstrapError> {
        let processes = &self.kernel.processes;
        let current = processes
            .status(process)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
        reject_self_wait(processes, process, true)?;
        let status = if current.is_terminal() {
            current
        } else {
            ProcessStatus::Cancelled
        };
        let guard = acquire_finalization(processes, process, status).await?;
        let descendants = processes.request_cleanup_tree(process);
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
                        finish_process_terminal_attempt(&self.kernel, descendant, guard).await
                    }
                    Ok(None) => {
                        self.kernel.handles.write().revoke_owned_by(descendant);
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
            finish_process_terminal_attempt(&self.kernel, process, guard).await?;
        } else {
            self.kernel.handles.write().revoke_owned_by(process);
        }
        Ok(())
    }

    /// Request cancellation at the process's next execution boundary.
    /// Use tree finalization when descendants must also stop.
    pub fn cancel_process(&self, process: ProcessId) -> Result<bool, BootstrapError> {
        self.kernel
            .processes
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
        self.finish_process_with_control(process, status, &xolotl_types::TaintSet::pristine())
            .await
    }

    async fn finish_process_with_control(
        &self,
        process: ProcessId,
        status: ProcessStatus,
        taint: &xolotl_types::TaintSet,
    ) -> Result<(), BootstrapError> {
        if !status.is_terminal() {
            return Err(BootstrapError::NonterminalStatus { process, status });
        }
        reject_self_wait(&self.kernel.processes, process, false)?;
        let Some(guard) = acquire_finalization(&self.kernel.processes, process, status).await?
        else {
            return Ok(());
        };
        self.kernel
            .processes
            .retain_finalization_control(process, taint)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
        self.kernel.processes.abort_task(process);
        self.kernel.processes.wait_for_task_exit(process).await;
        finish_process_terminal_attempt(&self.kernel, process, guard).await
    }
}

fn reject_self_wait(
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

pub(crate) async fn acquire_finalization(
    processes: &ProcessTable,
    process: ProcessId,
    status: ProcessStatus,
) -> Result<Option<FinalizationGuard<'_>>, BootstrapError> {
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
    guard: FinalizationGuard<'_>,
) -> Result<(), BootstrapError> {
    finish_process_terminal_attempt_with_journal(
        kernel,
        process,
        guard,
        #[cfg(feature = "durable")]
        None,
    )
    .await
}

async fn finish_process_terminal_attempt_with_journal(
    kernel: &Kernel,
    process: ProcessId,
    guard: FinalizationGuard<'_>,
    #[cfg(feature = "durable")] journal: Option<
        &mut (dyn crate::executor::durable::CheckpointJournal + 'static),
    >,
) -> Result<(), BootstrapError> {
    crate::process::scope_finalizer(
        &kernel.processes,
        process,
        finish_terminal(
            kernel,
            process,
            guard,
            #[cfg(feature = "durable")]
            journal,
        ),
    )
    .await
}

async fn finish_terminal(
    kernel: &Kernel,
    process: ProcessId,
    _guard: FinalizationGuard<'_>,
    #[cfg(feature = "durable")] journal: Option<
        &mut (dyn crate::executor::durable::CheckpointJournal + 'static),
    >,
) -> Result<(), BootstrapError> {
    #[cfg(feature = "durable")]
    let mut owned_journal = if journal.is_none()
        && kernel.processes.checkpoint_required(process) == Some(true)
        && kernel.processes.checkpoint_retired(process) != Some(true)
    {
        let store = kernel.checkpoint_store.as_ref().ok_or_else(|| {
            checkpoint_error(xolotl_types::Failure::policy(
                "checkpoint",
                "missing lifecycle journal store",
            ))
        })?;
        Some(store.acquire(process).map_err(checkpoint_error)?)
    } else {
        None
    };
    #[cfg(feature = "durable")]
    let journal = match journal {
        Some(journal) => Some(journal),
        None => owned_journal.as_mut().map(|journal| journal.as_mut()),
    };
    if kernel.processes.lifecycle_execution(process).is_none() {
        let execution = kernel.execution_ids().allocate()?;
        kernel
            .processes
            .initialize_lifecycle(process, execution)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
    }
    while kernel.processes.has_finalizers(process) {
        // Reserve before consuming the finalizer so allocation failures remain retryable.
        let execution = kernel.execution_ids().allocate()?;
        let body = kernel
            .processes
            .next_finalizer(process)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
        let ex = kernel.executor_for(process).with_finalizer_mode();
        let output = ex.eval_finalizer(&body, execution).await;
        if let xolotl_types::Outcome::Fail(failure) = &output.outcome {
            tracing::warn!(
                process = process.get(),
                %failure,
                "process finalizer failed"
            );
        }
        kernel
            .processes
            .finish_finalizer(process, output)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
    }
    commit_process_terminal(
        &kernel.processes,
        &kernel.handles,
        &kernel.facts,
        &kernel.state,
        process,
        #[cfg(feature = "durable")]
        journal,
    )
    .await
}

/// Commit terminal effects after the owning body and all finalizers have exited.
/// This path needs no registry, compiler, executor or identity allocator.
pub(crate) async fn commit_process_terminal(
    processes: &ProcessTable,
    handles: &parking_lot::RwLock<crate::HandleTable>,
    facts: &crate::FactSink,
    state: &xolotl_state::Backend,
    process: ProcessId,
    #[cfg(feature = "durable")] journal: Option<
        &mut (dyn crate::executor::durable::CheckpointJournal + 'static),
    >,
) -> Result<(), BootstrapError> {
    let lifecycle_execution = processes
        .lifecycle_execution(process)
        .ok_or(BootstrapError::NoSuchProcess { process })?;
    let terminal_status = processes
        .finalization_status(process)
        .ok_or(BootstrapError::NoSuchProcess { process })?;
    let finalizer_failures = processes
        .finalizer_failures(process)
        .ok_or(BootstrapError::NoSuchProcess { process })?;
    let taint = processes
        .finalization_taint(process)
        .ok_or(BootstrapError::NoSuchProcess { process })?;

    let (released, revoked) = close_process_handles(processes, handles, process)
        .ok_or(BootstrapError::NoSuchProcess { process })?;
    let (finalized, closed) = if let Some(record) = processes.finalization_record(process) {
        record
    } else {
        let closed = released + revoked;
        let finalizer_failure_count = finalizer_failures.len();
        let finalized = Fact {
            id: xolotl_types::OperationId::new(
                process,
                lifecycle_execution,
                xolotl_types::InvocationId::new(0),
                FINALIZED_NODE,
                0,
            ),
            schema_version: Fact::SCHEMA_VERSION,
            caller: process,
            acting: processes
                .identity(process)
                .ok_or(BootstrapError::NoSuchProcess { process })?,
            handle: xolotl_types::HandleId::new(0, 0),
            resource: xolotl_types::ResourceId::new(0),
            method: xolotl_types::MethodId::new(0),
            input: xolotl_types::Value::null(),
            taint,
            decision: xolotl_types::DecisionTag::Ok,
            outcome: Some(xolotl_types::Value::map({
                let mut m = BTreeMap::new();
                m.insert(
                    "event".into(),
                    xolotl_types::Value::string("ProcessFinalized".into()),
                );
                m.insert(
                    "status".into(),
                    xolotl_types::Value::string(process_status_label(terminal_status).into()),
                );
                m.insert(
                    "released_handles".into(),
                    xolotl_types::Value::integer(released as i64),
                );
                m.insert(
                    "revoked_handles".into(),
                    xolotl_types::Value::integer(revoked as i64),
                );
                m.insert(
                    "finalizer_failure_count".into(),
                    xolotl_types::Value::integer(finalizer_failure_count as i64),
                );
                if !finalizer_failures.is_empty() {
                    m.insert(
                        "finalizer_failures".into(),
                        xolotl_types::Value::list(finalizer_failures),
                    );
                }
                m
            })),
            batch: None,
            replay: xolotl_types::ReplayClass::Observation,
            timestamp: xolotl_types::Timestamp::millis(crate::executor::now_millis()),
        };
        processes
            .retain_finalization_record(process, finalized.clone(), closed)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
        (finalized, closed)
    };
    let taint = finalized.taint.clone();
    facts.complete(finalized)?;
    let actual_status = processes
        .mark_terminal_status(process, terminal_status)
        .ok_or(BootstrapError::NoSuchProcess { process })?;

    let marker_path = finalized_marker_path(process, lifecycle_execution).map_err(|source| {
        BootstrapError::Path {
            literal: format!(
                "state://kernel/process/{}/{}/finalized",
                process.get(),
                lifecycle_execution.get()
            ),
            source,
        }
    })?;
    let marker_result = state
        .write_set_tainted(
            &marker_path,
            xolotl_types::Value::integer(closed as i64),
            taint,
        )
        .await
        .map_err(BootstrapError::from);
    let publication_result = match processes.publication(process) {
        Some(publication) => {
            let outcome = processes.finalization_outcome(process);
            publication
                .publish(state, process, actual_status, outcome.as_deref())
                .await
        }
        None => Ok(()),
    };

    match (marker_result, publication_result) {
        (Ok(_commit), Ok(())) => {
            #[cfg(feature = "durable")]
            if processes.checkpoint_required(process) == Some(true)
                && processes.checkpoint_retired(process) != Some(true)
            {
                let journal = journal.ok_or_else(|| {
                    checkpoint_error(xolotl_types::Failure::policy(
                        "checkpoint",
                        "terminal cleanup requires its journal lease",
                    ))
                })?;
                journal.retire().map_err(checkpoint_error)?;
                processes
                    .retire_checkpoint(process, lifecycle_execution)
                    .map_err(|error| {
                        checkpoint_error(xolotl_types::Failure::policy(
                            "checkpoint",
                            error.to_string(),
                        ))
                    })?;
            }
            processes
                .complete_finalization(process)
                .ok_or(BootstrapError::NoSuchProcess { process })
        }
        (Err(error), Ok(())) => Err(error),
        (Ok(_commit), Err(error)) => Err(error),
        (Err(primary), Err(secondary)) => {
            tracing::error!(
                process = process.get(),
                error = %secondary,
                "process terminal publication failed after finalize marker failure"
            );
            Err(primary)
        }
    }
}

/// Honor the retained cleanup scope even when a completion attempt is retried.
pub(super) fn close_process_handles(
    processes: &ProcessTable,
    handles: &parking_lot::RwLock<crate::HandleTable>,
    process: ProcessId,
) -> Option<(usize, usize)> {
    let (tree, _) = processes.cleanup_scope(process)?;
    let (released, revoked) = {
        let mut handles = handles.write();
        if tree {
            (0, handles.revoke_owned_by(process))
        } else {
            (handles.release_owned_by(process), 0)
        }
    };
    processes.record_handle_cleanup(process, released, revoked)
}

#[cfg(feature = "durable")]
fn checkpoint_error(error: xolotl_types::Failure) -> BootstrapError {
    BootstrapError::Checkpoint(Box::new(error))
}

#[cfg(feature = "durable")]
impl Bootstrap {
    /// The caller owns the recovery body and its journal until this attempt ends.
    /// It must finish interpreter work before entering this path; external cleanup
    /// still aborts and joins that body through the ordinary finalization entry point.
    pub(super) async fn finish_checkpoint_terminal(
        &self,
        process: ProcessId,
        status: ProcessStatus,
        taint: &xolotl_types::TaintSet,
        journal: &mut (dyn crate::executor::durable::CheckpointJournal + 'static),
    ) -> Result<(), BootstrapError> {
        let Some(guard) = acquire_finalization(&self.kernel.processes, process, status).await?
        else {
            return Ok(());
        };
        self.kernel
            .processes
            .retain_finalization_control(process, taint)
            .ok_or(BootstrapError::NoSuchProcess { process })?;
        finish_process_terminal_attempt_with_journal(&self.kernel, process, guard, Some(journal))
            .await
    }
}
