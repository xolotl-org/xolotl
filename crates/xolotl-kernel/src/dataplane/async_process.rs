//! Adapt one operation into a managed process with retryable result publication.

use super::*;
use crate::bootstrap::BootstrapError;
use crate::bootstrap::finalize::{acquire_finalization, commit_process_terminal};
use crate::open::derive_handle;
use crate::process::{ProcessEntry, ProcessPublication};
use xolotl_types::{ExecutionId, ExecutionOutput, HandleId, ProcessId, ProcessStatus, ResourceId};

fn process_admission_failure(error: crate::process::ProcessAdmissionError) -> Failure {
    match error {
        crate::process::ProcessAdmissionError::Unavailable { .. } => Failure::Cancelled,
        other => Failure::Custom {
            kind: "process_admission".into(),
            message: other.to_string(),
        },
    }
}

struct AsyncPublication {
    parent: ProcessId,
    process_path: Path,
    status_path: Path,
    outcome_path: Path,
    input_taint: TaintSet,
}

impl AsyncPublication {
    fn new(
        parent: ProcessId,
        child: ProcessId,
        execution: ExecutionId,
        input_taint: TaintSet,
    ) -> Result<Self, xolotl_types::PathError> {
        let state_path = Path::try_new("state")?
            .try_push("kernel")?
            .try_push("async")?
            .try_push_literal(child.get().to_string())?
            .try_push_literal(execution.get().to_string())?;
        Ok(Self {
            parent,
            process_path: Path::try_new("proc")?
                .try_push("async")?
                .try_push_literal(child.get().to_string())?
                .try_push_literal(execution.get().to_string())?,
            status_path: state_path.clone().try_push("status")?,
            outcome_path: state_path.try_push("outcome")?,
            input_taint,
        })
    }

    fn reference(
        &self,
        op: &Operation,
        child: ProcessId,
        handle: HandleId,
        resource: ResourceId,
    ) -> Value {
        Value::map(BTreeMap::from([
            ("kind".into(), Value::string("executor_resource".into())),
            ("path".into(), Value::string(self.process_path.to_string())),
            (
                "parent_process".into(),
                Value::integer(self.parent.get() as i64),
            ),
            ("process".into(), Value::integer(child.get() as i64)),
            (
                "execution".into(),
                Value::string(op.id.execution.get().to_string()),
            ),
            ("resource".into(), Value::integer(resource.get() as i64)),
            ("method".into(), Value::integer(op.method.get() as i64)),
            (
                "handle".into(),
                Value::string(format!("{}.{}", handle.index, handle.generation)),
            ),
            (
                "status_path".into(),
                Value::string(self.status_path.to_string()),
            ),
            (
                "outcome_path".into(),
                Value::string(self.outcome_path.to_string()),
            ),
        ]))
    }

    fn status_value(
        &self,
        child: ProcessId,
        status: ProcessStatus,
        outcome: Option<&Outcome>,
    ) -> Value {
        let mut value = BTreeMap::from([
            (
                "phase".into(),
                Value::string(crate::bootstrap::process_status_label(status).into()),
            ),
            ("path".into(), Value::string(self.process_path.to_string())),
            (
                "parent_process".into(),
                Value::integer(self.parent.get() as i64),
            ),
            ("process".into(), Value::integer(child.get() as i64)),
            (
                "outcome_path".into(),
                Value::string(self.outcome_path.to_string()),
            ),
        ]);
        if let Some(outcome) = outcome {
            value.insert("outcome".into(), outcome_to_value(outcome));
        }
        Value::map(value)
    }
}

#[async_trait::async_trait]
impl ProcessPublication for AsyncPublication {
    async fn publish(
        &self,
        state: &xolotl_state::Backend,
        process: ProcessId,
        status: ProcessStatus,
        outcome: Option<&ExecutionOutput>,
    ) -> Result<(), BootstrapError> {
        let cancelled = Outcome::Fail(Failure::Cancelled);
        let (outcome, taint) = outcome
            .map(|value| (&value.outcome, &value.taint))
            .unwrap_or((&cancelled, &self.input_taint));
        state
            .write_set_tainted(&self.outcome_path, outcome_to_value(outcome), taint.clone())
            .await?;
        state
            .write_set_tainted(
                &self.status_path,
                self.status_value(process, status, Some(outcome)),
                taint.clone(),
            )
            .await?;
        Ok(())
    }
}

impl DataPlane {
    pub(super) fn start_async_process(
        &self,
        op: &Operation,
        contract: xolotl_types::MethodContract,
        resolved: &Resolved,
    ) -> Outcome {
        let Some(processes) = self.processes.clone() else {
            return Outcome::Fail(Failure::policy(
                "async-process",
                "AsyncProcess requires a process table",
            ));
        };
        if tokio::runtime::Handle::try_current().is_err() {
            return Outcome::Fail(Failure::policy(
                "async-process",
                "AsyncProcess requires a Tokio runtime",
            ));
        }
        let child = match processes.fresh_id() {
            Ok(child) => child,
            Err(error) => return Outcome::Fail(process_admission_failure(error)),
        };
        let publication =
            match AsyncPublication::new(op.process, child, op.id.execution, op.taint.clone()) {
                Ok(publication) => Arc::new(publication),
                Err(error) => {
                    return Outcome::Fail(Failure::InvalidInput {
                        reason: format!(
                            "failed to construct async process resource paths: {error}"
                        ),
                    });
                }
            };
        let child_handle = {
            let mut handles = self.handles.write();
            match derive_handle(
                &mut handles,
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
        let mut entry = ProcessEntry::new(child, Some(op.process), op.acting);
        entry.scope.initialize_lifecycle(op.id.execution);
        entry.scope.start();
        entry.publication = Some(publication.clone());
        if let Err(error) = processes.admit_child(entry) {
            self.handles.write().revoke_owned_by(child);
            return Outcome::Fail(process_admission_failure(error));
        }

        let reference = publication.reference(op, child, child_handle, resolved.resource);
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
        let task = processes.spawn_task(child, self.handles.clone(), move |owner| async move {
            // Complete this scope before releasing task ownership so cancellation drops the driver first.
            let output = AssertUnwindSafe(async {
                tokio::select! {
                    biased;
                    () = child_processes.wait_for_cancellation(child, false) => DriverOutput {
                        outcome: Outcome::Fail(Failure::Cancelled),
                        taint: TaintSet::pristine(),
                        usage: None,
                        origin: CompletionOrigin::CurrentAttempt,
                    },
                    output = async {
                        if let Err(error) = child_dp.state.write_cas_tainted(
                            &publication.status_path,
                            None,
                            publication.status_value(child, ProcessStatus::Running, None),
                            child_op.taint.clone(),
                        ).await {
                            return DriverOutput {
                                outcome: Outcome::Fail(Failure::policy("async-process", format!("initial status write failed: {error}"))),
                                taint: error.taint,
                                usage: None,
                                origin: CompletionOrigin::CurrentAttempt,
                            };
                        }
                        Box::pin(child_dp.execute_inner(
                            &child_op,
                            InvocationOptions { now_millis: crate::executor::now_millis(), record: true },
                            true,
                            None,
                        )).await
                    } => output,
                }
            }).catch_unwind().await;
            let output = output.unwrap_or_else(|payload| DriverOutput { outcome: Outcome::Fail(Failure::HandlerError {
                kind: "panic".into(),
                message: crate::bootstrap::panic_payload_message("async process", payload),
            }), taint: TaintSet::pristine(), usage: None, origin: CompletionOrigin::CurrentAttempt });
            let output = crate::invocation::complete_output(output, &child_op.taint);
            let Some(retained) = owner.finish(ExecutionOutput { outcome: output.outcome, taint: output.taint }) else {
                return;
            };
            let terminal = crate::process::outcome_status(&retained.outcome);
            let completion = async {
                let Some(_guard) = acquire_finalization(&child_processes, child, terminal).await? else {
                    return Ok(());
                };
                crate::process::scope_finalizer(&child_processes, child, commit_process_terminal(
                    &child_processes,
                    &child_dp.handles,
                    &child_dp.facts,
                    &child_dp.state,
                    child,
                    #[cfg(feature = "durable")]
                    None,
                )).await
            }.await;
            if let Err(error) = completion {
                tracing::warn!(process = child.get(), %error, "async process completion remains pending");
            }
        });
        if let Err(error) = task {
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
    }
}

#[cfg(test)]
mod tests;
