use xolotl_core::{AnalysisSlot, Fault, IMAGE_VERSION, Join, Node, NodeKind as N, ProgramImage};

fn image(nodes: &[Node<i64, Fault>], entry: u32) -> ProgramImage<'_, i64, Fault> {
    ProgramImage {
        version: IMAGE_VERSION,
        id: [1; 32],
        nodes,
        entry,
        bindings: 1,
        imports: 1,
        durable: false,
    }
}

#[test]
fn long_sequences_need_neither_frames_nor_recursive_analysis() -> anyhow::Result<()> {
    let nodes: Vec<_> = (0..65_536)
        .map(|index| Node {
            next: (index < 65_535).then_some(index + 1),
            ..Node::new(N::Input, u64::from(index))
        })
        .collect();
    let mut scratch = vec![AnalysisSlot::default(); nodes.len()];
    let resources = image(&nodes, 0).resource_requirements(&mut scratch)?;
    anyhow::ensure!(resources.tasks == Some(1));
    anyhow::ensure!(resources.frames_per_task == Some(0));
    Ok(())
}

#[test]
fn module_analysis_uses_local_scratch_and_rejects_cross_module_edges() -> anyhow::Result<()> {
    let mut nodes = [
        Node::new(N::Request(99), 0),
        Node::new(N::Then { first: 2, then: 3 }, 0),
        Node::new(N::Load(0), 1),
        Node::new(N::Request(0), 2),
    ];
    let local = [
        Node::new(N::Then { first: 1, then: 2 }, 0),
        nodes[2].clone(),
        nodes[3].clone(),
    ];
    let mut scratch = [AnalysisSlot::default(); 3];
    let expected = image(&local, 0).resource_requirements(&mut scratch)?;
    anyhow::ensure!(image(&nodes, 1).module_requirements(1, 1..4, &mut scratch)? == expected);
    anyhow::ensure!(
        image(&nodes, 1).resource_requirements(&mut [AnalysisSlot::default(); 4])
            == Err(Fault::InvalidImport)
    );
    anyhow::ensure!(
        image(&nodes, 1).module_requirements(1, 1..4, &mut scratch[..2])
            == Err(Fault::AnalysisCapacity)
    );
    nodes[1].next = Some(0);
    anyhow::ensure!(
        image(&nodes, 1).module_requirements(1, 1..4, &mut scratch) == Err(Fault::InvalidNode)
    );
    Ok(())
}

#[test]
fn sequential_forks_and_branches_reuse_task_capacity() -> anyhow::Result<()> {
    let fork = N::Fork {
        left: 0,
        right: 0,
        join: Join::All,
    };
    let nodes = [
        Node::new(N::Input, 0),
        Node {
            next: Some(2),
            ..Node::new(fork.clone(), 1)
        },
        Node::new(fork, 2),
        Node::new(N::If { yes: 1, no: 2 }, 3),
    ];
    let mut scratch = [AnalysisSlot::default(); 4];
    let resources = image(&nodes, 3).resource_requirements(&mut scratch)?;
    anyhow::ensure!(resources.tasks == Some(3));
    anyhow::ensure!(resources.frames_per_task == Some(1));
    Ok(())
}

#[test]
fn suspended_parent_frames_do_not_inflate_child_stacks() -> anyhow::Result<()> {
    let nodes = [
        Node::new(N::Input, 0),
        Node::new(N::Then { first: 0, then: 0 }, 1),
        Node::new(
            N::Fork {
                left: 1,
                right: 1,
                join: Join::Race,
            },
            2,
        ),
        Node::new(N::Then { first: 2, then: 0 }, 3),
    ];
    let resources = image(&nodes, 3).resource_requirements(&mut [AnalysisSlot::default(); 4])?;
    anyhow::ensure!(resources.tasks == Some(3));
    anyhow::ensure!(resources.frames_per_task == Some(2));
    anyhow::ensure!(resources.frames == Some(6));
    Ok(())
}

#[test]
fn asymmetric_stacks_share_one_frame_pool() -> anyhow::Result<()> {
    let nodes = [
        Node::new(N::Input, 0),
        Node::new(N::Then { first: 0, then: 0 }, 1),
        Node::new(N::Then { first: 1, then: 0 }, 2),
        Node::new(
            N::Fork {
                left: 2,
                right: 0,
                join: Join::All,
            },
            3,
        ),
    ];
    let resources = image(&nodes, 3).resource_requirements(&mut [AnalysisSlot::default(); 4])?;
    anyhow::ensure!(resources.tasks == Some(3));
    anyhow::ensure!(resources.frames_per_task == Some(4));
    anyhow::ensure!(resources.frames == Some(4));
    Ok(())
}

#[test]
fn shared_nonrecursive_calls_have_finite_bounds() -> anyhow::Result<()> {
    let nodes = [
        Node::new(N::Input, 0),
        Node::new(
            N::Finally {
                body: 0,
                cleanup: 0,
            },
            1,
        ),
        Node::new(N::Call(1), 2),
        Node::new(
            N::Fork {
                left: 2,
                right: 2,
                join: Join::All,
            },
            3,
        ),
    ];
    let resources = image(&nodes, 3).resource_requirements(&mut [AnalysisSlot::default(); 4])?;
    anyhow::ensure!(resources.tasks == Some(3));
    anyhow::ensure!(resources.frames_per_task == Some(3));
    Ok(())
}

#[test]
fn cycles_require_host_caps_and_unreachable_code_does_not() -> anyhow::Result<()> {
    let nodes = [
        Node::new(N::Input, 0),
        Node::new(N::Call(2), 1),
        Node::new(N::Call(1), 2),
        Node::new(
            N::Fork {
                left: 0,
                right: 1,
                join: Join::All,
            },
            3,
        ),
    ];
    let mut scratch = [AnalysisSlot::default(); 4];
    let resources = image(&nodes, 1).resource_requirements(&mut scratch)?;
    anyhow::ensure!(resources.tasks == Some(1));
    anyhow::ensure!(resources.frames_per_task.is_none());
    let resources = image(&nodes, 3).resource_requirements(&mut scratch)?;
    anyhow::ensure!(resources.tasks.is_none());
    anyhow::ensure!(resources.frames_per_task.is_none());
    let resources = image(&nodes, 0).resource_requirements(&mut scratch)?;
    anyhow::ensure!(resources.tasks == Some(1));
    anyhow::ensure!(resources.frames_per_task == Some(0));
    Ok(())
}

#[test]
fn analysis_reports_overflow_instead_of_wrapping() -> anyhow::Result<()> {
    let mut nodes = vec![Node::new(N::Input, 0)];
    for index in 1..=usize::BITS {
        nodes.push(Node::new(
            N::Fork {
                left: index - 1,
                right: index - 1,
                join: Join::All,
            },
            u64::from(index),
        ));
    }
    let resources = image(&nodes, usize::BITS)
        .resource_requirements(&mut vec![AnalysisSlot::default(); nodes.len()])?;
    anyhow::ensure!(resources.tasks.is_none());
    anyhow::ensure!(resources.frames_per_task == Some(0));
    Ok(())
}

#[test]
fn analysis_checks_scratch_capacity_and_unreachable_instructions() -> anyhow::Result<()> {
    let nodes = [Node::new(N::Input, 0), Node::new(N::Call(7), 1)];
    anyhow::ensure!(matches!(
        image(&nodes, 0).resource_requirements(&mut [AnalysisSlot::default(); 2]),
        Err(Fault::InvalidNode)
    ));
    anyhow::ensure!(matches!(
        image(&nodes[..1], 0).resource_requirements(&mut []),
        Err(Fault::AnalysisCapacity)
    ));
    Ok(())
}

#[test]
fn composed_instructions_execute_with_only_the_inferred_storage() -> anyhow::Result<()> {
    use anyhow::Context;
    use xolotl_core::{Advance, Execution, ExecutionLimits, HostEvent, Task, Values};

    struct Numbers;
    impl Values for Numbers {
        type Value = i64;
        type Error = Fault;
        fn unit(&mut self) -> i64 {
            0
        }
        fn truth(&mut self, value: &i64) -> Result<bool, Fault> {
            Ok(*value != 0)
        }
        fn pair(&mut self, _left: i64, _right: i64) -> Result<i64, Fault> {
            Ok(1)
        }
        fn error(&mut self, fault: Fault) -> Fault {
            fault
        }
        fn error_value(&mut self, _error: Fault) -> i64 {
            1
        }
    }

    let wrappers = |child| {
        [
            N::Then {
                first: child,
                then: child,
            },
            N::Catch {
                body: child,
                recover: child,
            },
            N::Finally {
                body: child,
                cleanup: child,
            },
            N::If {
                yes: child,
                no: child,
            },
            N::Branch {
                condition: 0,
                yes: child,
                no: child,
            },
            N::Let {
                slot: 0,
                value: child,
                body: child,
            },
            N::While {
                condition: 1,
                body: child,
                max: 1,
            },
            N::Fork {
                left: child,
                right: child,
                join: Join::All,
            },
            N::Fork {
                left: child,
                right: child,
                join: Join::Race,
            },
            N::Call(child),
            N::Scope {
                import: 0,
                body: child,
            },
        ]
    };
    for leaf in [N::Request(1), N::Fail(Fault::Type)] {
        for inner in wrappers(2) {
            for outer in wrappers(3) {
                let nodes = [
                    Node::new(N::Literal(1), 0),
                    Node::new(N::Literal(0), 1),
                    Node::new(leaf.clone(), 2),
                    Node::new(inner.clone(), 3),
                    Node {
                        next: Some(0),
                        ..Node::new(outer, 4)
                    },
                ];
                let image = ProgramImage {
                    imports: 2,
                    ..image(&nodes, 4)
                };
                let resources = image.resource_requirements(&mut [AnalysisSlot::default(); 5])?;
                let count = resources.tasks.context("acyclic task bound missing")?;
                let limits = ExecutionLimits {
                    frames_per_task: resources
                        .frames_per_task
                        .context("acyclic frame bound missing")?,
                    bindings_per_task: 1,
                    ..ExecutionLimits::default()
                };
                let mut tasks = vec![Task::default(); count];
                let mut frames = vec![
                    None;
                    resources
                        .frames
                        .context("acyclic frame pool bound missing")?
                ];
                let mut bindings = vec![None; count];
                let mut execution =
                    Execution::new(&image, &mut tasks, &mut frames, &mut bindings, limits, 1, 7)?;
                let mut result = None;
                for _ in 0..1000 {
                    match execution.advance(&image, &mut Numbers, 32) {
                        Advance::Done(outcome) => {
                            result = Some(outcome);
                            break;
                        }
                        Advance::Request(request) => execution.complete(
                            request.task,
                            request.ticket,
                            if request.import == 0 {
                                HostEvent::Enter(11)
                            } else {
                                HostEvent::Complete(Ok(request.input))
                            },
                            &image,
                            &mut Numbers,
                        )?,
                        Advance::Cancel { task, ticket } => execution.complete(
                            task,
                            ticket,
                            HostEvent::Complete(Err(Fault::Cancelled)),
                            &image,
                            &mut Numbers,
                        )?,
                        Advance::Yielded => {}
                        Advance::Waiting => {
                            anyhow::bail!("completed host calls left blocked tasks")
                        }
                    }
                }
                let result = result.context("finite program did not finish")?;
                anyhow::ensure!(
                    matches!(result, Ok(_) | Err(Fault::Type)),
                    "inferred storage {resources:?} failed for {nodes:?}: {result:?}"
                );
            }
        }
    }
    Ok(())
}
