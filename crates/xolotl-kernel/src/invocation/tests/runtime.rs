//! The portable machine and invocation adapter run as one execution boundary.

use super::*;
use crate::{LinkedExecution, PendingCall, RequestDriver};
use alloc::string::ToString;
use core::num::NonZeroU32;
use xolotl_core::{
    Execution, ExecutionLimits, Fault, Handle, HandleTable, HostEvent, ImportBinding,
    LinkedProgram, Node, NodeKind, ProgramImage, Request, Task,
};
use xolotl_types::{ExecutionOutput, Path, TaintedFailure, TaintedValue};

struct Adapter<'a> {
    body: &'a Driver,
    cleanup: &'a Driver,
    recorder: &'a Recorder,
    account: &'a Accounts,
    outbound_import: Option<u32>,
}
struct Call<'a>(Result<InvocationCall<'a, Driver, Recorder, Accounts>, Failure>);

impl Future for Call<'_> {
    type Output = crate::RequestCompletion;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = match &mut self.get_mut().0 {
            Ok(call) => {
                let operation = call.operation();
                let result = core::task::ready!(Pin::new(call).poll(cx));
                if let Some(error) = result.completion_error
                    && error.requires_interruption()
                {
                    return Poll::Ready(Err(TaintedFailure::new(
                        error.outcome_unknown(operation),
                        result.output.taint,
                    )));
                }
                result.output.into_result()
            }
            Err(failure) => Err(failure.clone().into()),
        };
        Poll::Ready(Ok(HostEvent::Complete(result)))
    }
}

impl RequestDriver for Adapter<'_> {
    type Call<'a>
        = Call<'a>
    where
        Self: 'a;
    fn collect_evidence<'a>(
        &'a self,
        call: &Self::Call<'a>,
        completion: Option<&crate::RequestCompletion>,
        unresolved: &mut xolotl_types::UnresolvedOperations,
    ) {
        if let Some(Err(failure) | Ok(HostEvent::Complete(Err(failure)))) = completion
            && let Failure::OutcomeUnknown { operation_ids, .. } = &failure.failure
        {
            for operation in operation_ids {
                unresolved.record(operation);
            }
        }
        if let Ok(invocation) = &call.0
            && (completion.is_none() || matches!(completion, Some(Err(_))))
            && invocation.effect_may_have_started()
        {
            unresolved.record(&invocation.operation().to_string());
        }
    }

    fn call<'a>(&'a self, resource: u32, request: Request<TaintedValue>) -> Self::Call<'a> {
        let result = (|| {
            if resource != 9 || request.context != IdentityRef::ROOT.get() {
                return Err(Failure::policy(
                    "adapter",
                    "unlinked resource or acting context",
                ));
            }
            let position = u32::try_from(request.position)
                .map_err(|_error| Failure::policy("position", "position overflow"))?;
            let mut operation = operation();
            operation.id = OperationId::new(
                operation.process,
                ExecutionId::FIRST,
                InvocationId::new(request.ticket),
                CausalPosition::new(position),
                0,
            );
            operation.input = request.input.value;
            operation.taint = request.input.taint;
            let mut contract = contract();
            contract.finalize_allowed = request.cleanup;
            contract.requires_unprotected_input = self.outbound_import == Some(request.import);
            invoke(
                operation,
                grant(contract),
                options(true),
                if request.cleanup {
                    CallContext::Cleanup
                } else {
                    CallContext::Body
                },
                if request.cleanup {
                    self.cleanup
                } else {
                    self.body
                },
                self.recorder,
                self.account,
            )
        })();
        Call(result)
    }
}

fn image(
    nodes: &[Node<TaintedValue, TaintedFailure>],
    imports: usize,
) -> ProgramImage<'_, TaintedValue, TaintedFailure> {
    ProgramImage {
        version: xolotl_core::IMAGE_VERSION,
        id: [23; 32],
        nodes,
        entry: 0,
        bindings: 0,
        imports,
    }
}
fn limits() -> ExecutionLimits {
    ExecutionLimits {
        frames_per_task: 16,
        bindings_per_task: 0,
        ..ExecutionLimits::default()
    }
}
fn map_fault(error: Fault) -> Failure {
    Failure::policy("test", alloc::format!("{error}"))
}

#[test]
fn dispatch_evidence_getter_survives_consumed_completion_and_rejects_barrier_denial()
-> Result<(), Failure> {
    for rejected in [false, true] {
        let events = Events::default();
        let mut accounts = Accounts::new(&events);
        accounts.fail_dispatch = rejected;
        accounts.dispatch_ready.set(false);
        let recorder = Recorder::new(&events);
        let driver = Driver::new(&events);
        driver.ready.set(false);
        let mut call = invoke(
            operation(),
            grant(contract()),
            options(false),
            CallContext::Body,
            &driver,
            &recorder,
            &accounts,
        )?;
        assert!(!call.effect_may_have_started());
        assert!(poll(&mut call).is_pending());
        assert!(!call.effect_may_have_started());
        accounts.dispatch_ready.set(true);
        let output = poll(&mut call);
        if rejected {
            assert!(output.is_ready());
            assert!(!call.effect_may_have_started());
            assert_eq!(driver.calls.get(), 0);
        } else {
            assert!(output.is_pending());
            assert!(call.effect_may_have_started());
            driver.ready.set(true);
            assert!(poll(&mut call).is_ready());
            assert!(call.effect_may_have_started());
            assert_eq!(driver.calls.get(), 1);
        }
    }
    Ok(())
}

#[test]
fn optional_fact_failure_keeps_known_result_while_unconfirmed_settlement_interrupts()
-> Result<(), Failure> {
    for settlement_failure in [false, true] {
        let events = Events::default();
        let mut account = Accounts::new(&events);
        account.fail_settle = settlement_failure;
        account.settle_ready.set(false);
        let mut recorder = Recorder::new(&events);
        recorder.fail_complete = !settlement_failure;
        let mut body = Driver::new(&events);
        body.output.taint = TaintSet::of(TaintSource::ModelOutput);
        let cleanup = Driver::new(&events);
        let adapter = Adapter {
            body: &body,
            cleanup: &cleanup,
            recorder: &recorder,
            account: &account,
            outbound_import: None,
        };
        let nodes = [
            Node::new(
                NodeKind::Finally {
                    body: 1,
                    cleanup: 4,
                },
                0,
            ),
            Node::new(
                NodeKind::Catch {
                    body: 2,
                    recover: 3,
                },
                1,
            ),
            Node::new(NodeKind::Request(0), 2),
            Node::new(NodeKind::Request(0), 3),
            Node::new(NodeKind::Request(0), 4),
        ];
        let mut slots = [Handle::default()];
        let mut handles = HandleTable::new(&mut slots);
        let handle = handles
            .install(1, 9, 1)
            .map_err(|_error| map_fault(Fault::Authority))?;
        let bindings = [ImportBinding { handle, method: 0 }];
        let linked =
            LinkedProgram::new(image(&nodes, 1), &bindings, &handles, 1).map_err(map_fault)?;
        let mut tasks = [Task::default()];
        let mut frames = core::array::from_fn::<_, 16, _>(|_| None);
        let machine = Execution::new(
            &linked.image,
            &mut tasks,
            &mut frames,
            &mut [],
            limits(),
            TaintedValue::new(Value::integer(7), TaintSet::author()),
            0,
        )
        .map_err(map_fault)?;
        let mut pending = [PendingCall::default()];
        let mut unresolved = xolotl_types::UnresolvedOperations::default();
        let mut run = LinkedExecution::new(
            machine,
            &linked,
            &mut handles,
            &adapter,
            &mut pending,
            &mut unresolved,
            NonZeroU32::MIN.saturating_add(31),
        )
        .map_err(map_fault)?;
        assert!(poll(&mut run).is_pending());
        assert_eq!(account.budget().inflight_ops, 1);
        account.settle_ready.set(true);
        let Poll::Ready(output) = poll(&mut run) else {
            return Err(Failure::policy(
                "test",
                "unconfirmed completion did not stop the machine",
            ));
        };
        if settlement_failure {
            assert!(matches!(
                output.outcome,
                Outcome::Fail(Failure::OutcomeUnknown { .. })
            ));
            assert_eq!(output.unresolved_operations.operation_ids.len(), 1);
        } else {
            assert_eq!(output.outcome, body.output.outcome);
            assert!(output.unresolved_operations.is_empty());
        }
        assert!(output.taint.contains_all(&TaintSet::author()));
        assert!(output.taint.contains_all(&body.output.taint));
        assert_eq!(run.pending_calls(), 0);
        assert_eq!(body.calls.get(), 1);
        assert_eq!(cleanup.calls.get(), usize::from(!settlement_failure));
        assert_eq!(account.budget().inflight_ops, 0);
        assert_eq!(
            recorder.facts.borrow().len(),
            if settlement_failure { 1 } else { 2 }
        );
        assert_eq!(
            account.completions.borrow().len(),
            2 * usize::from(!settlement_failure)
        );
    }
    Ok(())
}

#[test]
fn scope_cancel_then_machine_cancel_releases_body_before_accounted_finally() -> Result<(), Failure>
{
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let body = Driver::new(&events);
    let cleanup = Driver::new(&events);
    body.ready.set(false);
    let adapter = Adapter {
        body: &body,
        cleanup: &cleanup,
        recorder: &recorder,
        account: &account,
        outbound_import: None,
    };
    let nodes = [
        Node::new(
            NodeKind::Finally {
                body: 1,
                cleanup: 2,
            },
            0,
        ),
        Node::new(NodeKind::Request(0), 1),
        Node::new(NodeKind::Request(0), 2),
    ];
    let mut handles = [Handle::default()];
    let mut handles = HandleTable::new(&mut handles);
    let handle = handles
        .install(1, 9, 1)
        .map_err(|_error| map_fault(Fault::Authority))?;
    let bindings = [ImportBinding { handle, method: 0 }];
    let linked = LinkedProgram::new(image(&nodes, 1), &bindings, &handles, 1).map_err(map_fault)?;
    let mut tasks = [Task::default()];
    let mut frames = core::array::from_fn::<_, 16, _>(|_| None);
    let machine = Execution::new(
        &linked.image,
        &mut tasks,
        &mut frames,
        &mut [],
        limits(),
        TaintedValue::pristine(Value::integer(7)),
        0,
    )
    .map_err(map_fault)?;
    let mut pending = [PendingCall::default()];
    let mut unresolved = xolotl_types::UnresolvedOperations::default();
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &adapter,
        &mut pending,
        &mut unresolved,
        NonZeroU32::MIN.saturating_add(31),
    )
    .map_err(map_fault)?;
    assert!(poll(&mut run).is_pending());
    assert_eq!(account.budget().inflight_ops, 1);
    assert!(account.scopes.borrow_mut()[0].cancel());
    run.cancel();
    assert_eq!(account.budget().inflight_ops, 0);
    body.ready.set(true);
    let mut expected_evidence = xolotl_types::UnresolvedOperations::default();
    expected_evidence.record(&recorder.facts.borrow()[0].id.to_string());
    assert_eq!(
        poll(&mut run),
        Poll::Ready(
            ExecutionOutput::new(
                Outcome::Fail(Failure::Cancelled),
                cleanup.output.taint.clone(),
            )
            .with_unresolved_operations(expected_evidence)
        )
    );
    assert_eq!(body.calls.get(), 1);
    assert_eq!(cleanup.calls.get(), 1);
    assert_eq!(
        &events.borrow()[2..],
        &[
            "dispatch committed",
            "driver started",
            "driver dropped",
            "abandoned",
            "reserved",
            "intent committed",
            "dispatch committed",
            "driver started",
            "driver dropped",
            "settled",
            "outcome committed"
        ]
    );
    assert_eq!(account.budget().inflight_ops, 0);
    assert_eq!(recorder.facts.borrow().len(), 3);
    assert_ne!(recorder.facts.borrow()[0].id, recorder.facts.borrow()[1].id);
    Ok(())
}

#[test]
fn revocation_while_fact_barrier_waits_refunds_and_prevents_actual_dispatch() -> Result<(), Failure>
{
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let body = Driver::new(&events);
    let cleanup = Driver::new(&events);
    recorder.begin_ready.set(false);
    let adapter = Adapter {
        body: &body,
        cleanup: &cleanup,
        recorder: &recorder,
        account: &account,
        outbound_import: None,
    };
    let nodes = [Node::new(NodeKind::Request(0), 0)];
    let mut handles = [Handle::default()];
    let mut handles = HandleTable::new(&mut handles);
    let handle = handles
        .install(1, 9, 1)
        .map_err(|_error| map_fault(Fault::Authority))?;
    let bindings = [ImportBinding { handle, method: 0 }];
    let linked = LinkedProgram::new(image(&nodes, 1), &bindings, &handles, 1).map_err(map_fault)?;
    let mut tasks = [Task::default()];
    let mut frames = [];
    let machine = Execution::new(
        &linked.image,
        &mut tasks,
        &mut frames,
        &mut [],
        limits(),
        TaintedValue::pristine(Value::integer(7)),
        0,
    )
    .map_err(map_fault)?;
    let mut pending = [PendingCall::default()];
    let mut unresolved = xolotl_types::UnresolvedOperations::default();
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &adapter,
        &mut pending,
        &mut unresolved,
        NonZeroU32::MIN.saturating_add(31),
    )
    .map_err(map_fault)?;
    assert!(poll(&mut run).is_pending());
    assert_eq!(account.budget().inflight_ops, 1);
    run.handles_mut()
        .revoke(handle, 1)
        .map_err(|_error| map_fault(Fault::Authority))?;
    recorder.begin_ready.set(true);
    assert!(matches!(
        poll(&mut run),
        Poll::Ready(ExecutionOutput {
            outcome: Outcome::Fail(_),
            ..
        })
    ));
    assert_eq!(body.calls.get(), 0);
    assert_eq!(account.budget(), BudgetState::default());
    assert!(recorder.facts.borrow().is_empty());
    Ok(())
}

#[test]
fn protected_driver_failure_cannot_escape_through_portable_recovery() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let mut body = Driver::new(&events);
    let cleanup = Driver::new(&events);
    let protected = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/failure")
            .map_err(|error| Failure::policy("test", alloc::format!("protected path: {error}")))?,
    });
    body.output = DriverOutput::new(Outcome::Fail(Failure::InvalidInput {
        reason: "data-derived failure".into(),
    }))
    .with_taint(protected.clone());
    let adapter = Adapter {
        body: &body,
        cleanup: &cleanup,
        recorder: &recorder,
        account: &account,
        outbound_import: Some(1),
    };
    let nodes = [
        Node::new(
            NodeKind::Catch {
                body: 1,
                recover: 2,
            },
            0,
        ),
        Node::new(NodeKind::Request(0), 1),
        Node::new(NodeKind::Request(1), 2),
    ];
    let mut handles = [Handle::default()];
    let mut handles = HandleTable::new(&mut handles);
    let handle = handles
        .install(1, 9, 1)
        .map_err(|_error| map_fault(Fault::Authority))?;
    let bindings = [ImportBinding { handle, method: 0 }; 2];
    let linked = LinkedProgram::new(image(&nodes, 2), &bindings, &handles, 1).map_err(map_fault)?;
    let mut tasks = [Task::default()];
    let mut frames = core::array::from_fn::<_, 16, _>(|_| None);
    let machine = Execution::new(
        &linked.image,
        &mut tasks,
        &mut frames,
        &mut [],
        limits(),
        TaintedValue::pristine(Value::null()),
        0,
    )
    .map_err(map_fault)?;
    let mut pending = [PendingCall::default()];
    let mut unresolved = xolotl_types::UnresolvedOperations::default();
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &adapter,
        &mut pending,
        &mut unresolved,
        NonZeroU32::MIN.saturating_add(31),
    )
    .map_err(map_fault)?;
    let Poll::Ready(result) = poll(&mut run) else {
        return Err(Failure::policy("test", "ready recovery remained pending"));
    };
    assert!(matches!(
        result.outcome,
        Outcome::Fail(Failure::PolicyViolation { ref policy, .. }) if policy == "taint"
    ));
    assert_eq!(result.taint, protected);
    assert_eq!(body.calls.get(), 1);
    assert_eq!(account.budget().inflight_ops, 0);
    assert_eq!(recorder.facts.borrow().len(), 2);
    Ok(())
}
