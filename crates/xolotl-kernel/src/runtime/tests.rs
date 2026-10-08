use super::*;
use alloc::{rc::Rc, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    future::{Ready, ready},
    task::Waker,
};
use xolotl_core::{ExecutionLimits, Handle, ImportBinding, Node, NodeKind, ProgramImage, Task};
use xolotl_types::{DriverOutput, Outcome, TaintSet, TaintSource, Value};

fn image(
    nodes: &[Node<TaintedValue, TaintedFailure>],
    imports: usize,
) -> ProgramImage<'_, TaintedValue, TaintedFailure> {
    ProgramImage {
        version: xolotl_core::IMAGE_VERSION,
        id: [17; 32],
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

fn quantum() -> NonZeroU32 {
    NonZeroU32::MIN.saturating_add(31)
}

struct EvidenceDriver {
    unknown: bool,
    interrupt: bool,
    completed: Cell<usize>,
    abandoned: Cell<usize>,
}

struct EvidenceCall<'a> {
    driver: &'a EvidenceDriver,
    immediate: bool,
    finished: bool,
    collected: Cell<bool>,
}

impl Future for EvidenceCall<'_> {
    type Output = RequestCompletion;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if !this.immediate {
            return Poll::Pending;
        }
        this.finished = true;
        let failure = TaintedFailure::from(Failure::OutcomeUnknown {
            operation_ids: alloc::vec!["completed-effect".into()],
            reason: "test".into(),
        });
        Poll::Ready(if this.driver.interrupt {
            Err(failure)
        } else if this.driver.unknown {
            Ok(HostEvent::Complete(Err(failure)))
        } else {
            Ok(HostEvent::Complete(Ok(TaintedValue::pristine(
                Value::integer(42),
            ))))
        })
    }
}

impl Drop for EvidenceCall<'_> {
    fn drop(&mut self) {
        assert!(
            self.collected.get(),
            "evidence must precede call destruction"
        );
    }
}

impl RequestDriver for EvidenceDriver {
    type Call<'a> = EvidenceCall<'a>;

    fn call<'a>(&'a self, _resource: u32, request: Request<TaintedValue>) -> Self::Call<'a> {
        EvidenceCall {
            driver: self,
            immediate: request.import == 1,
            finished: false,
            collected: Cell::new(false),
        }
    }

    fn collect_evidence<'a>(
        &'a self,
        call: &Self::Call<'a>,
        completion: Option<&RequestCompletion>,
        unresolved: &mut UnresolvedOperations,
    ) {
        assert!(!call.collected.replace(true), "each call is collected once");
        assert_eq!(completion.is_some(), call.finished);
        if completion.is_some() {
            self.completed.set(self.completed.get() + 1);
            if self.unknown || self.interrupt {
                unresolved.record("completed-effect");
            }
        } else {
            self.abandoned.set(self.abandoned.get() + 1);
            unresolved.record("pending-effect");
        }
    }
}

#[test]
fn evidence_survives_race_catch_interruption_revocation_cancel_and_drop() -> Result<(), Fault> {
    for scenario in ["race", "catch", "interrupt", "revoke", "cancel", "drop"] {
        let fork = matches!(scenario, "race" | "interrupt");
        let nodes = if fork {
            alloc::vec![
                Node::new(
                    NodeKind::Fork {
                        left: 1,
                        right: 2,
                        join: if scenario == "race" {
                            xolotl_core::Join::Race
                        } else {
                            xolotl_core::Join::All
                        },
                    },
                    0
                ),
                Node::new(NodeKind::Request(0), 1),
                Node::new(NodeKind::Request(1), 2),
            ]
        } else if scenario == "catch" {
            alloc::vec![
                Node::new(
                    NodeKind::Catch {
                        body: 1,
                        recover: 2
                    },
                    0
                ),
                Node::new(NodeKind::Request(1), 1),
                Node::new(
                    NodeKind::Literal(TaintedValue::pristine(Value::integer(42))),
                    2
                ),
            ]
        } else {
            alloc::vec![Node::new(NodeKind::Request(0), 0)]
        };
        let mut storage = [Handle::default()];
        let mut handles = HandleTable::new(&mut storage);
        let handle = handles
            .install(1, 9, 1)
            .map_err(|_error| Fault::Authority)?;
        let bindings = [ImportBinding { handle, method: 0 }; 2];
        let linked = LinkedProgram::new(image(&nodes, 2), &bindings, &handles, 1)?;
        let mut tasks = core::array::from_fn::<_, 3, _>(|_| Task::default());
        let mut frames = core::array::from_fn::<_, 48, _>(|_| None);
        let machine = Execution::new(
            &linked.image,
            &mut tasks,
            &mut frames,
            &mut [],
            limits(),
            TaintedValue::pristine(Value::null()),
            0,
        )?;
        let driver = EvidenceDriver {
            unknown: scenario == "catch",
            interrupt: scenario == "interrupt",
            completed: Cell::new(0),
            abandoned: Cell::new(0),
        };
        let mut pending = core::array::from_fn::<_, 3, _>(|_| PendingCall::default());
        let mut unresolved = UnresolvedOperations::default();
        unresolved.record("earlier-effect");
        unresolved.identities_incomplete = true;
        let mut run = LinkedExecution::new(
            machine,
            &linked,
            &mut handles,
            &driver,
            &mut pending,
            &mut unresolved,
            quantum(),
        )?;
        let mut cx = Context::from_waker(Waker::noop());
        let mut output = Pin::new(&mut run).poll(&mut cx);
        if !fork && scenario != "catch" {
            assert!(output.is_pending());
            match scenario {
                "revoke" => run
                    .handles_mut()
                    .revoke(handle, 1)
                    .map_err(|_error| Fault::Authority)?,
                "cancel" => run.cancel(),
                _ => {}
            }
            if scenario != "drop" {
                output = Pin::new(&mut run).poll(&mut cx);
            }
        }
        drop(run);
        if scenario == "drop" {
            assert_eq!(
                unresolved.operation_ids,
                alloc::vec!["earlier-effect", "pending-effect"]
            );
            assert!(unresolved.identities_incomplete);
        } else {
            let Poll::Ready(output) = output else {
                return Err(Fault::StaleEvent);
            };
            assert!(unresolved.is_empty(), "normal output moves evidence");
            let mut expected = UnresolvedOperations::default();
            expected.record("earlier-effect");
            expected.identities_incomplete = true;
            if scenario != "catch" {
                expected.record("pending-effect");
            }
            if matches!(scenario, "catch" | "interrupt") {
                expected.record("completed-effect");
            }
            assert_eq!(output.unresolved_operations, expected, "{scenario}");
            if matches!(scenario, "race" | "catch") {
                assert_eq!(output.outcome, Outcome::Done(Value::integer(42)));
            }
        }
        assert_eq!(
            driver.completed.get(),
            usize::from(fork || scenario == "catch")
        );
        assert_eq!(driver.abandoned.get(), usize::from(scenario != "catch"));
    }
    Ok(())
}

#[derive(Default)]
struct Echo(Cell<usize>);

impl RequestDriver for Echo {
    type Call<'a> = Ready<RequestCompletion>;
    fn collect_evidence<'a>(
        &'a self,
        _call: &Self::Call<'a>,
        _completion: Option<&RequestCompletion>,
        _unresolved: &mut UnresolvedOperations,
    ) {
    }

    fn call<'a>(&'a self, resource: u32, request: Request<TaintedValue>) -> Self::Call<'a> {
        assert_eq!(resource, 9);
        self.0.set(self.0.get() + 1);
        ready(Ok(HostEvent::Complete(Ok(request.input))))
    }
}

#[test]
fn ready_driver_runs_without_boxing_or_send() -> Result<(), Fault> {
    let nodes = [Node::new(NodeKind::Request(0), 0)];
    let mut handles = [Handle::default()];
    let mut handles = HandleTable::new(&mut handles);
    let key = handles
        .install(1, 9, 1)
        .map_err(|_error| Fault::Authority)?;
    let bindings = [ImportBinding {
        handle: key,
        method: 0,
    }];
    let linked = LinkedProgram::new(image(&nodes, 1), &bindings, &handles, 1)?;
    let mut tasks = [Task::default()];
    let mut frames = core::array::from_fn::<_, 16, _>(|_| None);
    let machine = Execution::new(
        &linked.image,
        &mut tasks,
        &mut frames,
        &mut [],
        limits(),
        TaintedValue::pristine(Value::integer(42)),
        0,
    )?;
    let driver = Echo::default();
    let mut pending = [PendingCall::default()];
    let mut unresolved = UnresolvedOperations::default();
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &driver,
        &mut pending,
        &mut unresolved,
        quantum(),
    )?;
    assert_eq!(
        Pin::new(&mut run).poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(ExecutionOutput::new(
            Outcome::Done(Value::integer(42)),
            TaintSet::pristine(),
        ))
    );
    assert_eq!(driver.0.get(), 1);
    Ok(())
}

struct ReportedOutput(DriverOutput);

impl RequestDriver for ReportedOutput {
    type Call<'a> = Ready<RequestCompletion>;

    fn collect_evidence<'a>(
        &'a self,
        _call: &Self::Call<'a>,
        _completion: Option<&RequestCompletion>,
        _unresolved: &mut UnresolvedOperations,
    ) {
    }

    fn call<'a>(&'a self, _resource: u32, _request: Request<TaintedValue>) -> Self::Call<'a> {
        ready(Ok(HostEvent::Complete(self.0.clone().into_result())))
    }
}

#[test]
fn portable_execution_returns_success_and_failure_with_input_and_reported_provenance()
-> Result<(), Fault> {
    let input_taint = TaintSet::of(TaintSource::Inbound {
        source: "test/portable".into(),
        channel: "request".into(),
    });
    let output_taint = TaintSet::of(TaintSource::ModelOutput);
    for outcome in [
        Outcome::Done(Value::integer(42)),
        Outcome::Fail(Failure::InvalidInput {
            reason: "derived failure".into(),
        }),
    ] {
        let nodes = [Node::new(NodeKind::Request(0), 0)];
        let mut handles = [Handle::default()];
        let mut handles = HandleTable::new(&mut handles);
        let handle = handles
            .install(1, 9, 1)
            .map_err(|_error| Fault::Authority)?;
        let bindings = [ImportBinding { handle, method: 0 }];
        let linked = LinkedProgram::new(image(&nodes, 1), &bindings, &handles, 1)?;
        let mut tasks = [Task::default()];
        let machine = Execution::new(
            &linked.image,
            &mut tasks,
            &mut [],
            &mut [],
            limits(),
            TaintedValue::new(Value::null(), input_taint.clone()),
            0,
        )?;
        let driver =
            ReportedOutput(DriverOutput::new(outcome.clone()).with_taint(output_taint.clone()));
        let mut pending = [PendingCall::default()];
        let mut unresolved = UnresolvedOperations::default();
        let mut run = LinkedExecution::new(
            machine,
            &linked,
            &mut handles,
            &driver,
            &mut pending,
            &mut unresolved,
            quantum(),
        )?;
        assert_eq!(
            Pin::new(&mut run).poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(ExecutionOutput::new(
                outcome,
                output_taint.clone().merged(&input_taint)
            ))
        );
    }
    Ok(())
}

struct ContinuationOutput(TaintedValue);

impl RequestDriver for ContinuationOutput {
    type Call<'a> = Ready<RequestCompletion>;

    fn collect_evidence<'a>(
        &'a self,
        _call: &Self::Call<'a>,
        _completion: Option<&RequestCompletion>,
        _unresolved: &mut UnresolvedOperations,
    ) {
    }

    fn call<'a>(&'a self, _resource: u32, _request: Request<TaintedValue>) -> Self::Call<'a> {
        ready(Ok(HostEvent::Continue {
            entry: 1,
            input: self.0.clone(),
        }))
    }
}

#[test]
fn rejected_portable_continuation_keeps_reported_provenance() -> Result<(), Fault> {
    let nodes = [
        Node::new(NodeKind::Request(0), 0),
        Node::new(NodeKind::Input, 1),
    ];
    let mut handles = [Handle::default()];
    let mut handles = HandleTable::new(&mut handles);
    let handle = handles
        .install(1, 9, 1)
        .map_err(|_error| Fault::Authority)?;
    let bindings = [ImportBinding { handle, method: 0 }];
    let linked = LinkedProgram::new(image(&nodes, 1), &bindings, &handles, 1)?;
    let mut tasks = [Task::default()];
    let machine = Execution::new(
        &linked.image,
        &mut tasks,
        &mut [],
        &mut [],
        ExecutionLimits {
            frames_per_task: 0,
            ..limits()
        },
        TaintedValue::pristine(Value::null()),
        0,
    )?;
    let taint = TaintSet::of(TaintSource::Protected {
        path: xolotl_types::Path::parse("state://vault/continuation")
            .map_err(|_error| Fault::Type)?,
    });
    let driver = ContinuationOutput(TaintedValue::new(Value::integer(42), taint.clone()));
    let mut pending = [PendingCall::default()];
    let mut unresolved = UnresolvedOperations::default();
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &driver,
        &mut pending,
        &mut unresolved,
        quantum(),
    )?;
    assert_eq!(
        Pin::new(&mut run).poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(ExecutionOutput::new(
            Outcome::Fail(RuntimeValues.error(Fault::Frames).failure),
            taint,
        ))
    );
    Ok(())
}

#[test]
fn revoked_after_link_is_rejected_before_dispatch() -> Result<(), Fault> {
    let nodes = [Node::new(NodeKind::Request(0), 0)];
    let mut handles = [Handle::default()];
    let mut handles = HandleTable::new(&mut handles);
    let key = handles
        .install(1, 9, 1)
        .map_err(|_error| Fault::Authority)?;
    let bindings = [ImportBinding {
        handle: key,
        method: 0,
    }];
    let linked = LinkedProgram::new(image(&nodes, 1), &bindings, &handles, 1)?;
    let mut tasks = [Task::default()];
    let mut frames = [];
    let taint = TaintSet::of(TaintSource::ModelOutput);
    let machine = Execution::new(
        &linked.image,
        &mut tasks,
        &mut frames,
        &mut [],
        limits(),
        TaintedValue::new(Value::null(), taint.clone()),
        0,
    )?;
    let driver = Echo::default();
    let mut pending = [PendingCall::default()];
    let mut unresolved = UnresolvedOperations::default();
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &driver,
        &mut pending,
        &mut unresolved,
        quantum(),
    )?;
    run.handles_mut()
        .revoke(key, 1)
        .map_err(|_error| Fault::Authority)?;
    assert_eq!(
        Pin::new(&mut run).poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(ExecutionOutput::new(
            Outcome::Fail(RuntimeValues.error(Fault::Authority).failure),
            taint,
        ))
    );
    assert_eq!(driver.0.get(), 0);
    Ok(())
}

struct BlockingDriver {
    events: Rc<RefCell<Vec<&'static str>>>,
    ready: Rc<Cell<bool>>,
}

struct BlockingCall {
    events: Rc<RefCell<Vec<&'static str>>>,
    ready: Rc<Cell<bool>>,
    cleanup: bool,
}

impl Future for BlockingCall {
    type Output = RequestCompletion;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.cleanup || self.ready.get() {
            self.events.borrow_mut().push(if self.cleanup {
                "cleanup complete"
            } else {
                "body complete"
            });
            Poll::Ready(Ok(HostEvent::Complete(Ok(TaintedValue::pristine(
                Value::null(),
            )))))
        } else {
            Poll::Pending
        }
    }
}

impl Drop for BlockingCall {
    fn drop(&mut self) {
        self.events.borrow_mut().push(if self.cleanup {
            "cleanup dropped"
        } else {
            "body dropped"
        });
    }
}

impl RequestDriver for BlockingDriver {
    type Call<'a> = BlockingCall;
    fn collect_evidence<'a>(
        &'a self,
        _call: &Self::Call<'a>,
        _completion: Option<&RequestCompletion>,
        _unresolved: &mut UnresolvedOperations,
    ) {
    }

    fn call<'a>(&'a self, _resource: u32, request: Request<TaintedValue>) -> Self::Call<'a> {
        self.events.borrow_mut().push(if request.cleanup {
            "cleanup started"
        } else {
            "body started"
        });
        BlockingCall {
            events: self.events.clone(),
            ready: self.ready.clone(),
            cleanup: request.cleanup,
        }
    }
}

#[test]
fn cancellation_drops_body_before_finally_and_ignores_late_readiness() -> Result<(), Fault> {
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
    let key = handles
        .install(1, 9, 1)
        .map_err(|_error| Fault::Authority)?;
    let bindings = [ImportBinding {
        handle: key,
        method: 0,
    }];
    let linked = LinkedProgram::new(image(&nodes, 1), &bindings, &handles, 1)?;
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
    )?;
    let driver = BlockingDriver {
        events: Rc::default(),
        ready: Rc::default(),
    };
    let mut pending = [PendingCall::default()];
    let mut unresolved = UnresolvedOperations::default();
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &driver,
        &mut pending,
        &mut unresolved,
        quantum(),
    )?;
    let mut cx = Context::from_waker(Waker::noop());
    assert!(Pin::new(&mut run).poll(&mut cx).is_pending());
    assert_eq!(run.pending_calls(), 1);
    run.cancel();
    driver.ready.set(true);
    assert_eq!(
        Pin::new(&mut run).poll(&mut cx),
        Poll::Ready(ExecutionOutput::new(
            Outcome::Fail(Failure::Cancelled),
            TaintSet::pristine(),
        ))
    );
    assert_eq!(
        &*driver.events.borrow(),
        &[
            "body started",
            "body dropped",
            "cleanup started",
            "cleanup complete",
            "cleanup dropped"
        ]
    );
    Ok(())
}

#[test]
fn drop_releases_pending_future_even_without_another_poll() -> Result<(), Fault> {
    let nodes = [Node::new(NodeKind::Request(0), 0)];
    let mut handles = [Handle::default()];
    let mut handles = HandleTable::new(&mut handles);
    let key = handles
        .install(1, 9, 1)
        .map_err(|_error| Fault::Authority)?;
    let bindings = [ImportBinding {
        handle: key,
        method: 0,
    }];
    let linked = LinkedProgram::new(image(&nodes, 1), &bindings, &handles, 1)?;
    let mut tasks = [Task::default()];
    let mut frames = [];
    let machine = Execution::new(
        &linked.image,
        &mut tasks,
        &mut frames,
        &mut [],
        limits(),
        TaintedValue::pristine(Value::null()),
        0,
    )?;
    let driver = BlockingDriver {
        events: Rc::default(),
        ready: Rc::default(),
    };
    let mut pending = [PendingCall::default()];
    let mut unresolved = UnresolvedOperations::default();
    let mut run = LinkedExecution::new(
        machine,
        &linked,
        &mut handles,
        &driver,
        &mut pending,
        &mut unresolved,
        quantum(),
    )?;
    assert!(
        Pin::new(&mut run)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(run);
    assert_eq!(&*driver.events.borrow(), &["body started", "body dropped"]);
    assert!(pending[0].future.is_none());
    Ok(())
}

#[test]
fn cooperative_hook_and_machine_work_obey_the_poll_quantum() -> Result<(), Fault> {
    struct Hook(Cell<u32>);
    impl Cooperate for Hook {
        type Yield<'a> = Ready<()>;
        fn cooperate(&self) -> Self::Yield<'_> {
            self.0.set(self.0.get() + 1);
            ready(())
        }
    }
    let mut node = Node::new(NodeKind::Input, 0);
    node.next = Some(0);
    let nodes = [node];
    let mut handles = HandleTable::new(&mut []);
    let linked = LinkedProgram::new(image(&nodes, 0), &[], &handles, 1)?;
    let mut tasks = [Task::default()];
    let mut frames = [];
    let machine = Execution::new(
        &linked.image,
        &mut tasks,
        &mut frames,
        &mut [],
        limits(),
        TaintedValue::pristine(Value::null()),
        0,
    )?;
    let driver = Echo::default();
    let hook = Hook(Cell::new(0));
    let mut pending = [PendingCall::default()];
    let mut unresolved = UnresolvedOperations::default();
    let mut run = LinkedExecution::with_cooperate(
        machine,
        &linked,
        &mut handles,
        &driver,
        &mut pending,
        &mut unresolved,
        &hook,
        NonZeroU32::MIN.saturating_add(1),
    )?;
    assert!(
        Pin::new(&mut run)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(run.machine.view().meta.steps, 2);
    assert_eq!(hook.0.get(), 1);
    assert_eq!(driver.0.get(), 0);
    assert!(
        Pin::new(&mut run)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    assert_eq!(run.machine.view().meta.steps, 4);
    assert_eq!(hook.0.get(), 2);
    Ok(())
}
