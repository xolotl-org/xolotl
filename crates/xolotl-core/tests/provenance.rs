use anyhow::{bail, ensure};
use xolotl_core::*;

const INPUT: u8 = 1;
const LEFT: u8 = 2;
const RIGHT: u8 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Tagged {
    value: i64,
    sources: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaggedFailure {
    fault: Fault,
    sources: u8,
}

type ResultValue = Result<Tagged, TaggedFailure>;

struct Provenance;

impl Values for Provenance {
    type Value = Tagged;
    type Error = TaggedFailure;

    fn unit(&mut self) -> Tagged {
        value(0, 0)
    }

    fn truth(&mut self, value: &Tagged) -> Result<bool, TaggedFailure> {
        match value.value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(failure(Fault::Type, 0)),
        }
    }

    fn pair(&mut self, left: Tagged, right: Tagged) -> ResultValue {
        Ok(value(
            left.value * 100 + right.value,
            left.sources | right.sources,
        ))
    }

    fn error(&mut self, fault: Fault) -> TaggedFailure {
        failure(fault, 0)
    }

    fn error_value(&mut self, error: TaggedFailure) -> Tagged {
        value(-1, error.sources)
    }

    fn influence(&mut self, mut value: Tagged, control: &Tagged) -> Tagged {
        value.sources |= control.sources;
        value
    }

    fn influence_result(&mut self, result: ResultValue, control: &Tagged) -> ResultValue {
        match result {
            Ok(value) => Ok(self.influence(value, control)),
            Err(mut failure) => {
                failure.sources |= control.sources;
                Err(failure)
            }
        }
    }

    fn retain_control(&mut self, input: &Tagged) -> Tagged {
        value(0, input.sources)
    }
}

fn value(value: i64, sources: u8) -> Tagged {
    Tagged { value, sources }
}

fn failure(fault: Fault, sources: u8) -> TaggedFailure {
    TaggedFailure { fault, sources }
}

fn image(nodes: &[Node<Tagged, TaggedFailure>]) -> ProgramImage<'_, Tagged, TaggedFailure> {
    ProgramImage {
        version: IMAGE_VERSION,
        id: [23; 32],
        nodes,
        entry: 0,
        bindings: 0,
        imports: 2,
        durable: false,
    }
}

fn run(
    nodes: &[Node<Tagged, TaggedFailure>],
    mut host: impl FnMut(Request<Tagged>) -> anyhow::Result<ResultValue>,
) -> anyhow::Result<ResultValue> {
    let image = image(nodes);
    let mut tasks = core::array::from_fn::<_, 3, _>(|_| Task::default());
    let mut frames = core::array::from_fn::<_, 96, _>(|_| None);
    let mut machine = Execution::new(
        &image,
        &mut tasks,
        &mut frames,
        &mut [],
        ExecutionLimits {
            frames_per_task: 32,
            bindings_per_task: 0,
            ..ExecutionLimits::default()
        },
        value(7, INPUT),
        0,
    )?;
    for _ in 0..256 {
        match machine.advance(&image, &mut Provenance, 32) {
            Advance::Done(result) => return Ok(result),
            Advance::Request(request) => {
                let task = request.task;
                let ticket = request.ticket;
                machine.complete(
                    task,
                    ticket,
                    HostEvent::Complete(host(request)?),
                    &image,
                    &mut Provenance,
                )?;
            }
            Advance::Cancel { task, ticket } => machine.complete(
                task,
                ticket,
                HostEvent::Complete(Err(failure(Fault::Cancelled, 0))),
                &image,
                &mut Provenance,
            )?,
            Advance::Yielded => {}
            Advance::Waiting => bail!("synchronous host left the machine waiting"),
        }
    }
    bail!("bounded test program did not finish")
}

#[test]
fn failure_recovery_cannot_clear_new_host_provenance() -> anyhow::Result<()> {
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
    let mut recovered = false;
    let result = run(&nodes, |request| {
        if request.import == 0 {
            return Ok(Err(failure(Fault::Type, LEFT)));
        }
        recovered = true;
        ensure!(request.input == value(-1, INPUT | LEFT));
        Ok(Err(failure(Fault::Authority, 0)))
    })?;
    ensure!(recovered);
    ensure!(result == Err(failure(Fault::Authority, INPUT | LEFT)));
    Ok(())
}

#[test]
fn implicit_next_preserves_input_before_dispatching_the_next_request() -> anyhow::Result<()> {
    let nodes = [
        Node {
            next: Some(1),
            ..Node::new(NodeKind::Request(0), 0)
        },
        Node::new(NodeKind::Request(1), 1),
    ];
    let result = run(&nodes, |request| {
        if request.import == 0 {
            return Ok(Ok(value(42, LEFT)));
        }
        ensure!(request.input == value(42, INPUT | LEFT));
        Ok(Err(failure(Fault::Type, 0)))
    })?;
    ensure!(result == Err(failure(Fault::Type, INPUT | LEFT)));
    Ok(())
}

#[test]
fn branch_and_loop_errors_keep_the_deciding_results_sources() -> anyhow::Result<()> {
    let branch = [
        Node::new(
            NodeKind::Branch {
                condition: 1,
                yes: 2,
                no: 3,
            },
            0,
        ),
        Node::new(NodeKind::Request(0), 1),
        Node::new(NodeKind::Fail(failure(Fault::Authority, 0)), 2),
        Node::new(NodeKind::Literal(value(0, 0)), 3),
    ];
    for (condition, expected) in [(1, Fault::Authority), (7, Fault::Type)] {
        let result = run(&branch, |_| Ok(Ok(value(condition, LEFT))))?;
        ensure!(result == Err(failure(expected, INPUT | LEFT)));
    }
    let loop_nodes = [
        Node::new(
            NodeKind::While {
                condition: 1,
                body: 2,
                max: 0,
            },
            0,
        ),
        Node::new(NodeKind::Request(0), 1),
        Node::new(NodeKind::Input, 2),
    ];
    ensure!(
        run(&loop_nodes, |_| Ok(Ok(value(1, LEFT))))?
            == Err(failure(Fault::Iterations, INPUT | LEFT))
    );
    Ok(())
}

#[test]
fn cleanup_selection_preserves_both_results_without_changing_cleanup_input() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::Finally {
                body: 1,
                cleanup: 2,
            },
            0,
        ),
        Node::new(NodeKind::Request(0), 1),
        Node::new(NodeKind::Request(1), 2),
    ];
    for body_failed in [false, true] {
        for cleanup_failed in [false, true] {
            let result = run(&nodes, |request| {
                ensure!(request.input == value(7, INPUT));
                let (failed, fault, source) = if request.import == 0 {
                    (body_failed, Fault::Type, LEFT)
                } else {
                    ensure!(request.cleanup);
                    (cleanup_failed, Fault::Authority, RIGHT)
                };
                Ok(if failed {
                    Err(failure(fault, source))
                } else {
                    Ok(value(42, source))
                })
            })?;
            let sources = INPUT | LEFT | RIGHT;
            let expected = if body_failed {
                Err(failure(Fault::Type, sources))
            } else if cleanup_failed {
                Err(failure(Fault::Authority, sources))
            } else {
                Ok(value(42, sources))
            };
            ensure!(
                result == expected,
                "body={body_failed}, cleanup={cleanup_failed}: {result:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn parallel_selection_retains_sources_on_success_and_failure() -> anyhow::Result<()> {
    for join in [Join::All, Join::Race] {
        let nodes = [
            Node::new(
                NodeKind::Fork {
                    left: 1,
                    right: 2,
                    join,
                },
                0,
            ),
            Node::new(NodeKind::Request(0), 1),
            Node::new(NodeKind::Request(1), 2),
        ];
        for left_failed in [false, true] {
            for right_failed in [false, true] {
                let result = run(&nodes, |request| {
                    let (failed, fault, number, source) = if request.import == 0 {
                        (left_failed, Fault::Type, 2, LEFT)
                    } else {
                        (right_failed, Fault::Authority, 3, RIGHT)
                    };
                    Ok(if failed {
                        Err(failure(fault, source))
                    } else {
                        Ok(value(number, source))
                    })
                })?;
                let sources = INPUT | LEFT | RIGHT;
                let expected = if left_failed {
                    Err(failure(Fault::Type, sources))
                } else if join == Join::All && right_failed {
                    Err(failure(Fault::Authority, sources))
                } else {
                    Ok(value(if join == Join::All { 203 } else { 2 }, sources))
                };
                ensure!(
                    result == expected,
                    "{join:?}, left={left_failed}, right={right_failed}: {result:?}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn static_and_capacity_failures_keep_current_input_control() -> anyhow::Result<()> {
    for (node, expected) in [
        (NodeKind::Fail(failure(Fault::Type, 0)), Fault::Type),
        (NodeKind::Call(0), Fault::Frames),
    ] {
        let nodes = [Node::new(node, 0)];
        ensure!(
            run(&nodes, |_| bail!("local failure dispatched a request"))?
                == Err(failure(expected, INPUT))
        );
    }
    Ok(())
}

#[test]
fn cancellation_does_not_erase_an_already_reported_result() -> anyhow::Result<()> {
    let nodes = [Node::new(NodeKind::Request(0), 0)];
    let image = image(&nodes);
    let mut tasks = [Task::default()];
    let mut machine = Execution::new(
        &image,
        &mut tasks,
        &mut [],
        &mut [],
        ExecutionLimits {
            frames_per_task: 0,
            bindings_per_task: 0,
            ..ExecutionLimits::default()
        },
        value(7, INPUT),
        0,
    )?;
    let Advance::Request(request) = machine.advance(&image, &mut Provenance, 32) else {
        bail!("missing request");
    };
    machine.complete(
        request.task,
        request.ticket,
        HostEvent::Complete(Ok(value(42, LEFT))),
        &image,
        &mut Provenance,
    )?;
    machine.cancel();
    let Advance::Done(result) = machine.advance(&image, &mut Provenance, 32) else {
        bail!("cancellation did not finish");
    };
    ensure!(result == Err(failure(Fault::Cancelled, INPUT | LEFT)));
    Ok(())
}

#[test]
fn rejected_continuations_preserve_sources_without_accepting_stale_events() -> anyhow::Result<()> {
    for (scope, entry, expected) in [
        (false, 1, Fault::Frames),
        (false, 99, Fault::InvalidNode),
        (true, 1, Fault::StaleEvent),
    ] {
        let nodes = [
            Node::new(
                if scope {
                    NodeKind::Scope { import: 0, body: 1 }
                } else {
                    NodeKind::Request(0)
                },
                0,
            ),
            Node::new(NodeKind::Input, 1),
        ];
        let program = image(&nodes);
        let mut tasks = [Task::default()];
        let mut machine = Execution::new(
            &program,
            &mut tasks,
            &mut [],
            &mut [],
            ExecutionLimits {
                frames_per_task: 0,
                bindings_per_task: 0,
                ..ExecutionLimits::default()
            },
            value(7, INPUT),
            0,
        )?;
        let Advance::Request(request) = machine.advance(&program, &mut Provenance, 32) else {
            bail!("missing request");
        };
        let mut mismatched = image(&nodes);
        mismatched.id = [29; 32];
        for (task, ticket, image, expected) in [
            (
                request.task + 1,
                request.ticket,
                &program,
                Fault::StaleEvent,
            ),
            (
                request.task,
                request.ticket + 1,
                &program,
                Fault::StaleEvent,
            ),
            (
                request.task,
                request.ticket,
                &mismatched,
                Fault::ImageMismatch,
            ),
        ] {
            ensure!(
                machine.complete(
                    task,
                    ticket,
                    HostEvent::Continue {
                        entry: 1,
                        input: value(42, RIGHT),
                    },
                    image,
                    &mut Provenance,
                ) == Err(expected)
            );
            ensure!(machine.retain_control(&mut Provenance).sources == INPUT);
        }
        ensure!(
            machine.complete(
                request.task,
                request.ticket,
                HostEvent::Continue {
                    entry,
                    input: value(42, LEFT),
                },
                &program,
                &mut Provenance,
            ) == Err(expected)
        );
        let sources = if scope { INPUT } else { INPUT | LEFT };
        ensure!(machine.is_pending(request.task, request.ticket));
        ensure!(machine.retain_control(&mut Provenance).sources == sources);
        machine.complete(
            request.task,
            request.ticket,
            HostEvent::Complete(Err(failure(Fault::Frames, 0))),
            &program,
            &mut Provenance,
        )?;
        let Advance::Done(result) = machine.advance(&program, &mut Provenance, 32) else {
            bail!("rejected continuation did not finish");
        };
        ensure!(result == Err(failure(Fault::Frames, sources)));
    }
    Ok(())
}

#[test]
fn fatal_embedding_failure_keeps_the_result_held_for_cleanup() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::Finally {
                body: 1,
                cleanup: 2,
            },
            0,
        ),
        Node::new(NodeKind::Request(0), 1),
        Node::new(NodeKind::Request(1), 2),
    ];
    let program = image(&nodes);
    let mut tasks = [Task::default()];
    let mut frames = [None, None];
    let mut machine = Execution::new(
        &program,
        &mut tasks,
        &mut frames,
        &mut [],
        ExecutionLimits {
            frames_per_task: 2,
            bindings_per_task: 0,
            ..ExecutionLimits::default()
        },
        value(7, INPUT),
        0,
    )?;
    let Advance::Request(body) = machine.advance(&program, &mut Provenance, 32) else {
        bail!("missing body request");
    };
    machine.complete(
        body.task,
        body.ticket,
        HostEvent::Complete(Ok(value(42, LEFT))),
        &program,
        &mut Provenance,
    )?;
    let Advance::Request(cleanup) = machine.advance(&program, &mut Provenance, 32) else {
        bail!("missing cleanup request");
    };
    ensure!(cleanup.cleanup && cleanup.input == value(7, INPUT));
    let mut mismatched = image(&nodes);
    mismatched.id = [29; 32];
    let Advance::Done(result) = machine.advance(&mismatched, &mut Provenance, 32) else {
        bail!("mismatched image was accepted");
    };
    ensure!(result == Err(failure(Fault::ImageMismatch, INPUT | LEFT)));
    Ok(())
}
