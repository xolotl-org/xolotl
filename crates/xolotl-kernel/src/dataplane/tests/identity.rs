use super::*;
use crate::process::{ProcessEntry, ProcessTable};

fn options(caller_identity: Option<IdentityRef>) -> InvocationOptions {
    InvocationOptions {
        caller_identity,
        now_millis: 17,
        record: true,
    }
}

#[tokio::test]
async fn standalone_host_preserves_known_and_unknown_caller_identity() -> anyhow::Result<()> {
    for identity in [
        None,
        Some(IdentityRef::ROOT),
        Some(IdentityRef::new(u64::MAX)),
    ] {
        let (plane, handle) = dataplane_with_handle(
            Rights::new(MethodBitmap::ALL, RightFlags::empty()),
            FastPath::Unconditional,
            MethodContract::new(0, ReplayClass::NonIdempotentEffect, SUPPORTS_UNARY),
        )?;
        let operation = op(handle, 7, Value::integer(3));
        let result = plane.execute(&operation, options(identity)).await;
        ensure!(result.completion_error.is_none());
        ensure!(result.output.outcome == Outcome::Done(operation.input.clone()));
        let fact = plane
            .facts
            .get(operation.id)?
            .context("missing completion")?;
        ensure!(fact.caller_identity == identity);
        ensure!(fact.acting == IdentityRef::ROOT);
    }
    Ok(())
}

#[tokio::test]
async fn process_identity_overrides_host_hint_without_following_acting() -> anyhow::Result<()> {
    let default = IdentityRef::new(91);
    for acting in [default, IdentityRef::ROOT, IdentityRef::new(92)] {
        let (plane, handle) = dataplane_with_handle(
            Rights::new(MethodBitmap::ALL, RightFlags::empty()),
            FastPath::Unconditional,
            MethodContract::new(0, ReplayClass::NonIdempotentEffect, SUPPORTS_UNARY),
        )?;
        let processes = ProcessTable::new();
        let mut entry = ProcessEntry::new(ProcessId::new(1), None, default);
        ensure!(entry.scope.start());
        processes.insert(entry);
        let plane = plane
            .with_host_runtime(processes.host_runtime().clone())?
            .with_processes(processes)?;
        let mut authority = plane.handles.get(handle).context("missing handle")?;
        authority.acting = acting;
        let handle = plane.handles.insert(authority)?;
        let mut operation = op(handle, 7, Value::integer(3));
        operation.acting = acting;
        let result = plane
            .execute(&operation, options(Some(IdentityRef::new(900))))
            .await;
        ensure!(result.completion_error.is_none());
        ensure!(result.output.outcome.is_success());
        let fact = plane
            .facts
            .get(operation.id)?
            .context("missing completion")?;
        ensure!(fact.caller_identity == Some(default));
        ensure!(fact.acting == acting);
    }
    Ok(())
}

#[tokio::test]
async fn earliest_denial_uses_only_the_authoritative_process_observation() -> anyhow::Result<()> {
    for known in [false, true] {
        let (plane, handle) = dataplane_with_handle(
            Rights::new(MethodBitmap::ALL, RightFlags::empty()),
            FastPath::Unconditional,
            MethodContract::new(0, ReplayClass::Observation, SUPPORTS_UNARY),
        )?;
        let processes = ProcessTable::new();
        if known {
            processes.insert(ProcessEntry::new(
                ProcessId::new(1),
                None,
                IdentityRef::new(91),
            ));
        }
        let plane = plane
            .with_host_runtime(processes.host_runtime().clone())?
            .with_processes(processes)?;
        ensure!(plane.handles.revoke(handle));
        let mut operation = op(handle, 7, Value::integer(3));
        operation.acting = IdentityRef::new(92);
        let result = plane
            .execute(&operation, options(Some(IdentityRef::ROOT)))
            .await;
        ensure!(matches!(result.output.outcome, Outcome::Fail(_)));
        ensure!(result.completion_error.is_none());
        let fact = plane.facts.get(operation.id)?.context("missing denial")?;
        ensure!(fact.decision == DecisionTag::Denied);
        ensure!(fact.caller_identity == known.then_some(IdentityRef::new(91)));
        ensure!(fact.acting == operation.acting);
    }
    Ok(())
}

struct ReapDuringPolicy {
    processes: ProcessTable,
    process: ProcessId,
}

#[async_trait::async_trait]
impl crate::policy::CompiledCheck for ReapDuringPolicy {
    async fn evaluate(&self, _: &crate::policy::CheckCtx) -> PolicyDecision {
        use crate::process::FinalizeStart;
        use xolotl_types::ProcessStatus;
        tokio::task::yield_now().await;
        assert_eq!(
            self.processes
                .begin_finalizing(self.process, ProcessStatus::Completed),
            FinalizeStart::Started
        );
        let guard = self.processes.finalization_guard(self.process);
        assert!(
            self.processes
                .mark_terminal_status(self.process, ProcessStatus::Completed)
                .is_some()
        );
        assert!(self.processes.complete_finalization(self.process).is_some());
        drop(guard);
        assert_eq!(self.processes.reap_finalized(1), 1);
        PolicyDecision::Deny {
            reason: "caller retired during policy callback".into(),
        }
    }

    fn name(&self) -> &'static str {
        "reap-caller"
    }
}

#[tokio::test]
async fn denial_keeps_admission_identity_after_an_async_callback_reaps_the_caller()
-> anyhow::Result<()> {
    let processes = ProcessTable::new();
    let process = ProcessId::new(1);
    let root = ProcessId::new(42);
    let identity = IdentityRef::new(91);
    processes.insert(ProcessEntry::new(root, None, IdentityRef::ROOT));
    let mut entry = ProcessEntry::new(process, Some(root), identity);
    ensure!(entry.scope.start());
    processes.insert(entry);
    let policy = crate::policy::PolicySnapshot::new(vec![Arc::new(ReapDuringPolicy {
        processes: processes.clone(),
        process,
    })]);
    let (plane, handle) = dataplane_with_handle(
        Rights::new(MethodBitmap::ALL, RightFlags::empty()),
        FastPath::Conditional(policy),
        MethodContract::new(0, ReplayClass::NonIdempotentEffect, SUPPORTS_UNARY),
    )?;
    let plane = plane
        .with_host_runtime(processes.host_runtime().clone())?
        .with_processes(processes.clone())?;
    let operation = op(handle, 7, Value::integer(3));
    let result = plane.execute(&operation, options(None)).await;
    ensure!(matches!(result.output.outcome, Outcome::Fail(_)));
    ensure!(result.completion_error.is_none());
    ensure!(processes.identity(process).is_none());
    let fact = plane.facts.get(operation.id)?.context("missing denial")?;
    ensure!(fact.caller_identity == Some(identity));
    ensure!(fact.acting == IdentityRef::ROOT);
    ensure!(fact.decision == DecisionTag::RejectedByPolicy);
    Ok(())
}
