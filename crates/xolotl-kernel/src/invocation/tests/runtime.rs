//! The portable machine and invocation adapter run as one execution boundary.

use super::*;
use crate::{LinkedExecution, PendingCall, RequestDriver};
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
    type Output = HostEvent<TaintedValue, TaintedFailure>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let result = match &mut self.get_mut().0 {
            Ok(call) => {
                let result = core::task::ready!(Pin::new(call).poll(cx));
                result.output.into_result()
            }
            Err(failure) => Err(failure.clone().into()),
        };
        Poll::Ready(HostEvent::Complete(result))
    }
}

impl RequestDriver for Adapter<'_> {
    type Call<'a>
        = Call<'a>
    where
        Self: 'a;
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
                options(false),
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
        durable: false,
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
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &adapter,
        &mut pending,
        NonZeroU32::MIN.saturating_add(31),
    )
    .map_err(map_fault)?;
    assert!(poll(&mut run).is_pending());
    assert_eq!(account.budget().inflight_ops, 1);
    assert!(account.scopes.borrow_mut()[0].cancel());
    run.cancel();
    assert_eq!(account.budget().inflight_ops, 0);
    body.ready.set(true);
    assert_eq!(
        poll(&mut run),
        Poll::Ready(ExecutionOutput::new(
            Outcome::Fail(Failure::Cancelled),
            cleanup.output.taint.clone(),
        ))
    );
    assert_eq!(body.calls.get(), 1);
    assert_eq!(cleanup.calls.get(), 1);
    assert_eq!(
        &events.borrow()[2..],
        &[
            "driver started",
            "driver dropped",
            "settled",
            "reserved",
            "intent committed",
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
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &adapter,
        &mut pending,
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
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &adapter,
        &mut pending,
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
