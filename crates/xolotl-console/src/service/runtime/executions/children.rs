//! Volatile child ownership shares submission quotas, authority and result custody.

use super::*;
use crate::runtime::executions::{ChildRegistration, ExecutionOrigin};
use std::sync::{Mutex, Weak};
use xolotl_kernel::host::async_process::{
    AsyncProcessAdmission, AsyncProcessHost, AsyncProcessOwner, AsyncProcessRequest,
};
use xolotl_types::{ProcessId, TaintedFailure};

pub(super) struct Host {
    state: Weak<ConsoleState>,
    owner: ExecutionOwner,
    authority: Vec<(String, Path)>,
    authority_candidates: Vec<xolotl_types::Capability>,
    parent: ExecutionReference,
    deadline: HostDeadline,
}

impl Host {
    pub(super) fn new(
        state: &Arc<ConsoleState>,
        owner: ExecutionOwner,
        authority: Vec<(String, Path)>,
        authority_candidates: Vec<xolotl_types::Capability>,
        parent: ExecutionReference,
        deadline: HostDeadline,
    ) -> Self {
        Self {
            state: Arc::downgrade(state),
            owner,
            authority,
            authority_candidates,
            parent,
            deadline,
        }
    }
}

fn failure(error: ConsoleError) -> Failure {
    match error {
        ConsoleError::Runtime(failure) => failure,
        ConsoleError::RateLimited => Failure::RateLimited,
        other => Failure::policy("console-execution", other.to_string()),
    }
}

#[async_trait::async_trait]
impl AsyncProcessHost for Host {
    async fn admit(&self, request: &AsyncProcessRequest) -> Result<AsyncProcessAdmission, Failure> {
        let state = self.state.upgrade().ok_or(Failure::Cancelled)?;
        let deadline = match request.deadline {
            Some(parent) => parent.earliest(self.deadline)?,
            None => self.deadline,
        };
        let runtime = state.boot.kernel().host_runtime();
        runtime.validate_deadline(deadline)?;
        let remaining = deadline.saturating_duration_since(runtime.now())?;
        if remaining.is_zero() {
            return Err(Failure::Timeout);
        }
        let target = request.target.as_ref().ok_or_else(|| {
            Failure::policy(
                "console-execution",
                "child invocation requires a bound resource path",
            )
        })?;
        if !self
            .authority
            .iter()
            .any(|(verb, path)| verb == "spawn-with" && path == target)
        {
            return Err(Failure::policy(
                "console-execution",
                "child propagation was not admitted",
            ));
        }
        let reference = ExecutionReference {
            execution_id: None,
            process_id: request.process.get().to_string(),
            program_id: self.parent.program_id.clone(),
        };
        let wall_deadline = runtime
            .now_millis()
            .saturating_add(i64::try_from(remaining.as_millis()).unwrap_or(i64::MAX));
        let origin = ExecutionOrigin {
            execution_id: self.parent.execution_id.clone().ok_or_else(|| {
                Failure::policy(
                    "console-execution",
                    "child source has no execution identity",
                )
            })?,
            operation: request.source,
        };
        let registration = state
            .executions
            .register_child(
                self.owner.clone(),
                self.authority.clone(),
                reference,
                wall_deadline,
                origin,
            )
            .map_err(failure)?;
        let (mut registration, stop, reference) = match registration {
            ChildRegistration::Existing(reference) => {
                return Ok(AsyncProcessAdmission::already_accepted(
                    serde_value(&reference).map_err(failure)?,
                )
                .with_deadline(deadline)?);
            }
            ChildRegistration::Reserved(registration, stop, reference) => {
                (registration, stop, reference)
            }
        };
        let value = match serde_value(&reference) {
            Ok(value) => value,
            Err(error) => {
                registration.reject();
                return Err(failure(error));
            }
        };
        Ok(AsyncProcessAdmission::new(
            value,
            Arc::new(Owner {
                state: self.state.clone(),
                owner: self.owner.clone(),
                authority: self.authority.clone(),
                authority_candidates: self.authority_candidates.clone(),
                process: request.process,
                settlement: Mutex::new(Settlement {
                    registration,
                    released: false,
                    published: false,
                }),
                stop,
                reason: Mutex::new(None),
                max_result_bytes: state.runtime.config.executions.max_result_bytes,
            }),
        )
        .with_deadline(deadline)?
        .with_finalization_timeout(Duration::from_millis(
            state.runtime.config.executions.cleanup_timeout_ms,
        )))
    }
}

struct Owner {
    // The process table retains this publisher through cleanup retries. A strong
    // ConsoleState here would keep Bootstrap and the publisher alive in a cycle.
    state: Weak<ConsoleState>,
    owner: ExecutionOwner,
    authority: Vec<(String, Path)>,
    authority_candidates: Vec<xolotl_types::Capability>,
    process: ProcessId,
    settlement: Mutex<Settlement>,
    stop: watch::Receiver<Option<StopReason>>,
    reason: Mutex<Option<&'static str>>,
    max_result_bytes: usize,
}

struct Settlement {
    registration: Registration,
    released: bool,
    published: bool,
}

impl Owner {
    fn bind_cleanup(&self, settlement: &Settlement) -> Result<(), Failure> {
        let state = self.state.upgrade().ok_or(Failure::Cancelled)?;
        // Preparation normally pins the admitted process. Release also covers
        // forced abort before the first poll; the kernel still owns the task
        // record while delivering that callback, so it cannot yet be reaped.
        let ticket = state
            .boot
            .cleanup_ticket(self.process)
            .map_err(|error| Failure::policy("console-execution", error.to_string()))?;
        settlement
            .registration
            .bind_cleanup(ticket)
            .map_err(failure)
    }

    fn settle(
        &self,
        _status: ProcessStatus,
        output: Option<&ExecutionOutput>,
        published: bool,
        released: bool,
    ) {
        let reason = *self.reason.lock().unwrap_or_else(|e| e.into_inner());
        let mut settlement = self.settlement.lock().unwrap_or_else(|e| e.into_inner());
        if let Err(error) = self.bind_cleanup(&settlement) {
            tracing::debug!(%error, "child cleanup ticket could not be retained");
        }
        if !settlement.published {
            let outcome = terminal_outcome(output);
            let result = output
                .and_then(|output| result_value(output).ok())
                .map(|value| RetainedResult::encode(&value, self.max_result_bytes))
                .unwrap_or_else(|| {
                    RetainedResult::Omitted(
                        "child output is unknown; effects may have occurred".into(),
                    )
                });
            settlement.registration.record_body(Completion {
                outcome: outcome.into(),
                stop_cause: reason,
                result,
                unresolved_operations: output
                    .map(|output| output.unresolved_operations.clone())
                    .unwrap_or_else(|| xolotl_types::UnresolvedOperations {
                        identities_incomplete: true,
                        ..Default::default()
                    }),
                cleanup_complete: false,
                finalization: Default::default(),
            });
            if published {
                settlement.registration.record_terminal_outcome(outcome);
                settlement.published = true;
            }
        }
        settlement.released |= released;
        if settlement.released {
            // Publication accepts the host result but runs before the kernel
            // acknowledges finalization. The pinned ticket confirms that final
            // transition independently of this native attempt's release.
            settlement.registration.settle(false);
        }
    }
}

#[async_trait::async_trait]
impl AsyncProcessOwner for Owner {
    fn rejected(&self) {
        self.settlement
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .registration
            .reject();
    }

    fn released(&self, status: ProcessStatus, output: Option<&ExecutionOutput>) {
        self.settle(status, output, false, true);
    }

    async fn prepare(&self) -> Result<(), TaintedFailure> {
        {
            let settlement = self.settlement.lock().unwrap_or_else(|e| e.into_inner());
            self.bind_cleanup(&settlement)
                .map_err(|failure| TaintedFailure {
                    failure,
                    taint: TaintSet::author(),
                })?;
            settlement.registration.accepted();
        }
        let check = async {
            let state = self.state.upgrade().ok_or(Failure::Cancelled)?;
            let timeout =
                Duration::from_millis(state.runtime.config.executions.authority_timeout_ms);
            let runtime = state.boot.kernel().host_runtime();
            let deadline = crate::host_time::after(runtime, timeout)?;
            crate::host_time::timeout_at(
                runtime,
                deadline,
                check_authority(
                    &state,
                    &self.owner,
                    &self.authority,
                    &self.authority_candidates,
                ),
            )
            .await?
            .map_err(failure)
        };
        check.await.map_err(|failure| TaintedFailure {
            failure,
            taint: TaintSet::author(),
        })
    }

    async fn cancelled(&self) -> Failure {
        let Some(state) = self.state.upgrade() else {
            return Failure::Cancelled;
        };
        let reason = monitor(
            &state,
            &self.owner,
            &self.authority,
            &self.authority_candidates,
            &mut self.stop.clone(),
        )
        .await;
        *self.reason.lock().unwrap_or_else(|e| e.into_inner()) = Some(reason);
        Failure::Cancelled
    }

    async fn publish(
        &self,
        status: ProcessStatus,
        output: Option<&ExecutionOutput>,
    ) -> Result<(), Failure> {
        self.settle(status, output, true, false);
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/children/settlement.rs"]
mod tests;
