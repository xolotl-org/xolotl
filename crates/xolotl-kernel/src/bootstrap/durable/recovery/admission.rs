//! Validate a leased row and transfer its ownership into execution or cleanup.

use super::*;
use crate::executor::durable::{CheckpointJournal, JournalRun};
use crate::process::{LeasedRequestState, ProcessAdmissionError, TaskAttachment, TaskOwner};

pub(super) enum AdmissionFailure {
    Capacity,
    Rejected(Failure),
}

impl From<Failure> for AdmissionFailure {
    fn from(error: Failure) -> Self {
        Self::Rejected(error)
    }
}

impl From<ProcessAdmissionError> for AdmissionFailure {
    fn from(error: ProcessAdmissionError) -> Self {
        match error {
            ProcessAdmissionError::Capacity { .. } => Self::Capacity,
            other => Self::Rejected(recovery_error(other)),
        }
    }
}

enum RecoveryExecution {
    Machine {
        program: crate::PreparedProgram,
        journal: Box<JournalRun>,
    },
    Cleanup {
        journal: Box<dyn CheckpointJournal>,
        status: ProcessStatus,
        taint: xolotl_types::TaintSet,
    },
}

pub(super) struct RecoveryWork {
    execution: RecoveryExecution,
    boot: Arc<Bootstrap>,
    process: ProcessId,
    steps: crate::StepModule,
    attachment: LeasedRequestState,
    // Release capacity after the program, loaded state and lease have all dropped.
    _permit: RecoveryPermit,
}

impl RecoveryWork {
    pub(super) fn prepare(
        boot: Arc<Bootstrap>,
        process: ProcessId,
        saved: ExecutionSnapshot,
        journal: Box<dyn CheckpointJournal>,
        permit: RecoveryPermit,
        steps: crate::StepModule,
    ) -> Result<Self, AdmissionFailure> {
        if saved.process.id != process {
            return Err(recovery_error("checkpoint owner does not match its catalog key").into());
        }
        let finalized = boot.validate_checkpoint_process(&saved)?;
        let kernel = &boot.kernel;
        let preview = kernel
            .processes
            .checkpoint_recovery_state(&saved.process, finalized.as_ref())?;
        let executor = kernel.executor_for(process).with_steps(steps.clone());
        if preview == LeasedRequestState::Ready {
            executor.validate_checkpoint(&saved)?;
            if saved
                .pending
                .values()
                .any(|class| *class == ReplayClass::NonIdempotentEffect)
            {
                return Err(recovery_error(
                    "pending non-idempotent effect requires reconciliation",
                )
                .into());
            }
            if !saved.finished {
                executor.validate_checkpoint_replay(&saved)?;
            }
        }
        let attachment = kernel
            .processes
            .restore_leased_request(&saved.process, finalized)?;
        let terminal = match attachment {
            LeasedRequestState::Cleanup(status) => Some(status),
            LeasedRequestState::Ready => {
                saved
                    .finished
                    .then(|| match saved.machine.checkpoint().result() {
                        Some(Ok(_)) => ProcessStatus::Completed,
                        Some(Err(error))
                            if matches!(error.failure, Failure::Cancelled | Failure::Timeout) =>
                        {
                            ProcessStatus::Cancelled
                        }
                        _ => ProcessStatus::Failed,
                    })
            }
        };
        let execution = if let Some(status) = terminal {
            let taint = match saved.machine.checkpoint().result() {
                Some(Ok(value)) => value.taint.clone(),
                Some(Err(error)) => error.taint.clone(),
                None => xolotl_types::TaintSet::pristine(),
            };
            drop(saved);
            RecoveryExecution::Cleanup {
                journal,
                status,
                taint,
            }
        } else {
            let program = saved.program.clone();
            RecoveryExecution::Machine {
                program,
                journal: Box::new(JournalRun::resume(&executor, journal, saved)?),
            }
        };
        Ok(Self {
            execution,
            boot,
            process,
            steps,
            attachment,
            _permit: permit,
        })
    }

    pub(super) fn spawn(self) -> Result<(), TaskAttachment> {
        let kernel = &self.boot.clone().kernel;
        match self.attachment {
            LeasedRequestState::Ready => kernel.processes.spawn_recovery_task(
                self.process,
                kernel.handles.clone(),
                move |owner| self.run(owner),
            ),
            LeasedRequestState::Cleanup(_) => kernel.processes.spawn_checkpoint_cleanup_task(
                self.process,
                kernel.handles.clone(),
                move |owner| self.run(owner),
            ),
        }
    }

    async fn run(mut self, _owner: TaskOwner) {
        let (status, taint, journal) = match &mut self.execution {
            RecoveryExecution::Machine { program, journal } => {
                let outcome = self
                    .boot
                    .kernel
                    .executor_for(self.process)
                    .with_steps(self.steps.clone())
                    .resume_checkpoint(program, journal)
                    .await;
                if !journal.finished {
                    tracing::warn!(
                        process = self.process.get(),
                        ?outcome,
                        "checkpoint execution remains unfinished"
                    );
                    return;
                }
                (
                    crate::process::outcome_status(&outcome.outcome),
                    outcome.taint,
                    journal.journal(),
                )
            }
            RecoveryExecution::Cleanup {
                journal,
                status,
                taint,
            } => (*status, taint.clone(), journal.as_mut()),
        };
        if let Err(error) = self
            .boot
            .finish_checkpoint_terminal(self.process, status, &taint, journal)
            .await
        {
            tracing::error!(process = self.process.get(), %error, "checkpoint lifecycle completion failed");
        }
    }
}
