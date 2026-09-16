use super::*;
use crate::executor::durable::{EXECUTION_CHECKPOINT_VERSION, ExecutionSnapshot};
use crate::process::{ProcessSnapshot, RetainedFinalization};
use xolotl_types::{Failure, InvocationId, OperationId, ReplayClass, Value};

mod recovery;
#[cfg(test)]
mod tests;
pub(crate) use recovery::RecoveryControl;
pub use recovery::{DurableRecovery, DurableRecoveryConfig, DurableRecoveryReport};

fn recovery_error(error: impl std::fmt::Display) -> Failure {
    Failure::Custom {
        kind: "checkpoint_recovery".into(),
        message: error.to_string(),
    }
}

fn retained_finalization(
    facts: &crate::FactSink,
    saved: &ProcessSnapshot,
) -> Result<Option<RetainedFinalization>, Failure> {
    let id = OperationId::new(
        saved.id,
        saved.lifecycle_execution,
        InvocationId::new(0),
        FINALIZED_NODE,
        0,
    );
    let Some(fact) = facts.get(id).map_err(recovery_error)? else {
        return Ok(None);
    };
    if fact.schema_version != Fact::SCHEMA_VERSION
        || fact.caller != saved.id
        || fact.acting != saved.identity
        || fact.decision != xolotl_types::DecisionTag::Ok
        || fact.replay != ReplayClass::Observation
    {
        return Err(recovery_error("invalid committed lifecycle record"));
    }
    let Some(value) = fact.outcome.as_ref().and_then(Value::as_map) else {
        return Err(recovery_error("lifecycle record is missing its outcome"));
    };
    if value.get("event").and_then(Value::as_str) != Some("ProcessFinalized") {
        return Err(recovery_error("lifecycle record has an invalid event"));
    }
    let status = match value.get("status").and_then(Value::as_str) {
        Some("completed") => ProcessStatus::Completed,
        Some("failed") => ProcessStatus::Failed,
        Some("cancelled") => ProcessStatus::Cancelled,
        _ => return Err(recovery_error("lifecycle record has a nonterminal status")),
    };
    let count = |field: &str| match value.get(field).and_then(Value::as_int) {
        Some(count) => usize::try_from(count)
            .map_err(|error| recovery_error(format!("invalid lifecycle {field}: {error}"))),
        _ => Err(recovery_error(format!(
            "lifecycle record is missing {field}"
        ))),
    };
    let released = count("released_handles")?;
    let revoked = count("revoked_handles")?;
    released
        .checked_add(revoked)
        .ok_or_else(|| recovery_error("lifecycle handle count overflow"))?;
    Ok(Some(RetainedFinalization {
        fact,
        status,
        released,
        revoked,
    }))
}

impl Bootstrap {
    /// Reserve persisted process identifiers before spawning new application work.
    pub fn reserve_checkpoint_process_ids(&self) -> Result<(), Failure> {
        if let Some(store) = &self.kernel.checkpoint_store
            && let Some(high_water) = store.high_water()?
        {
            self.kernel.processes.reserve_ids_through(high_water);
        }
        Ok(())
    }

    /// Re-admit one trusted checkpoint under the current root authority ceiling.
    /// Existing processes are never overwritten. Changed constraints fail closed.
    /// Import before reaping any process from this kernel: once identity history is
    /// released, old checkpoints require a new kernel to prevent stale-reference reuse.
    /// The host must retain the identity source that created this checkpoint.
    /// Restore checkpoints only within their original identity namespace.
    pub fn restore_checkpoint_process(&self, saved: &ExecutionSnapshot) -> Result<(), Failure> {
        let finalized = self.validate_checkpoint_process(saved)?;
        self.kernel
            .processes
            .restore_request(&saved.process, finalized)
            .map_err(recovery_error)?;
        Ok(())
    }

    fn validate_checkpoint_process(
        &self,
        saved: &ExecutionSnapshot,
    ) -> Result<Option<RetainedFinalization>, Failure> {
        if saved.version != EXECUTION_CHECKPOINT_VERSION
            || !saved.program.is_durable()
            || saved.process.parent != Some(self.root)
            || saved.process.id == self.root
            || saved.process.id.get() == u64::MAX
        {
            return Err(recovery_error(
                "checkpoint is not a supported durable request process",
            ));
        }
        let finalized = retained_finalization(&self.kernel.facts, &saved.process)?;
        if finalized.is_some() {
            return Ok(finalized);
        }
        let requested: Vec<_> = saved
            .process
            .grants
            .iter()
            .map(|grant| ParsedRequestGrantTemplate {
                selector: grant.selector.clone(),
                methods: Some(grant.rights.methods),
            })
            .collect();
        let planned = self
            .plan_request_grants(self.root, &requested)
            .map_err(recovery_error)?;
        for (grant, current) in saved.process.grants.iter().zip(planned) {
            if grant.holder != saved.process.id
                || grant.constraints != current.constraints
                || grant.expires != current.expires
                || grant.rights != current.rights
            {
                return Err(recovery_error(
                    "checkpoint authority changed; explicit re-admission is required",
                ));
            }
        }
        Ok(None)
    }

    /// Finalize only after the interpreter's terminal state is durable.
    /// Returns false for interrupted or quarantined programs that still need recovery.
    pub async fn finish_checkpointed_request(
        &self,
        process: ProcessId,
        output: &xolotl_types::ExecutionOutput,
    ) -> Result<bool, Failure> {
        if let Some(store) = &self.kernel.checkpoint_store {
            let saved = store
                .acquire(process)?
                .load(self.kernel.execution_config.max_checkpoint_bytes)?;
            if saved.is_some_and(|saved| !saved.finished) {
                return Ok(false);
            }
        }
        self.finish_request_process(process, output)
            .await
            .map_err(recovery_error)?;
        Ok(true)
    }
}
