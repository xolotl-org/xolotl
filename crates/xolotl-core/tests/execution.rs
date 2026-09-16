use xolotl_core::*;
macro_rules! assert {
    ($condition:expr $(,)?) => {
        anyhow::ensure!($condition, "{}", stringify!($condition));
    };
}
macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        anyhow::ensure!(
            $left == $right,
            "{} != {}",
            stringify!($left),
            stringify!($right)
        );
    };
}
macro_rules! assert_ne {
    ($left:expr, $right:expr $(,)?) => {
        anyhow::ensure!(
            $left != $right,
            "{} == {}",
            stringify!($left),
            stringify!($right)
        );
    };
}

struct Numbers;
impl Values for Numbers {
    type Value = i64;
    type Error = Fault;
    fn unit(&mut self) -> i64 {
        0
    }
    fn truth(&mut self, value: &i64) -> Result<bool, Fault> {
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Fault::Type),
        }
    }
    fn pair(&mut self, a: i64, b: i64) -> Result<i64, Fault> {
        Ok(a * 100 + b)
    }
    fn error(&mut self, error: Fault) -> Fault {
        error
    }
    fn error_value(&mut self, _error: Fault) -> i64 {
        -1
    }
}

fn image(nodes: &[Node<i64, Fault>], entry: u32) -> ProgramImage<'_, i64, Fault> {
    ProgramImage {
        version: IMAGE_VERSION,
        id: [1; 32],
        nodes,
        entry,
        bindings: 2,
        imports: 4,
        durable: false,
    }
}

fn run(
    nodes: &[Node<i64, Fault>],
    entry: u32,
    input: i64,
    host: &mut impl FnMut(Request<i64>) -> Result<i64, Fault>,
) -> Result<i64, Fault> {
    let mut tasks = core::array::from_fn::<_, 5, _>(|_| Task::default());
    let mut frames = core::array::from_fn::<_, 320, _>(|_| None);
    let mut bindings = [None; 10];
    let image = image(nodes, entry);
    let mut scratch = vec![AnalysisSlot::default(); nodes.len()];
    let requirements = image.resource_requirements(&mut scratch)?;
    let task_count = requirements.tasks.unwrap_or(5).min(5);
    let limits = ExecutionLimits {
        frames_per_task: requirements.frames_per_task.unwrap_or(64).min(64),
        bindings_per_task: 2,
        ..ExecutionLimits::default()
    };
    let mut execution = Execution::new(
        &image,
        &mut tasks[..task_count],
        &mut frames[..requirements.frames.unwrap_or(320).min(320)],
        &mut bindings[..task_count * limits.bindings_per_task],
        limits,
        input,
        7,
    )?;
    loop {
        match execution.advance(&image, &mut Numbers, 31) {
            Advance::Done(result) => return result,
            Advance::Request(request) => execution.complete(
                request.task,
                request.ticket,
                HostEvent::Complete(host(request.clone())),
                &image,
                &mut Numbers,
            )?,
            Advance::Yielded => {}
            Advance::Waiting => return Err(Fault::StaleEvent),
            Advance::Cancel { task, ticket } => execution.complete(
                task,
                ticket,
                HostEvent::Complete(Err(Fault::Cancelled)),
                &image,
                &mut Numbers,
            )?,
        }
    }
}

#[test]
fn scalar_pipeline_and_branch_preserve_original_input() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::Branch {
                condition: 1,
                yes: 2,
                no: 3,
            },
            0,
        ),
        Node::new(NodeKind::Literal(1), 1),
        Node::new(NodeKind::Input, 2),
        Node::new(NodeKind::Literal(-1), 3),
    ];
    assert_eq!(run(&nodes, 0, 42, &mut |_| Err(Fault::Type))?, 42);
    Ok(())
}

#[test]
fn loop_reuses_storage_and_has_an_iteration_bound() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::While {
                condition: 1,
                body: 2,
                max: 10_000,
            },
            0,
        ),
        Node::new(NodeKind::Request(0), 1),
        Node::new(NodeKind::Request(1), 2),
    ];
    let mut requests = 0;
    let result = run(&nodes, 0, 0, &mut |request| {
        requests += 1;
        Ok(if request.import == 0 {
            i64::from(request.input < 10_000)
        } else {
            request.input + 1
        })
    })?;
    assert_eq!(result, 10_000);
    assert_eq!(requests, 20_001);
    assert_eq!(run(&nodes, 0, 0, &mut |_| Ok(1)), Err(Fault::Iterations));
    Ok(())
}

#[test]
fn scheduling_quantum_is_not_a_lifetime_quota() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::While {
                condition: 1,
                body: 2,
                max: u64::MAX,
            },
            0,
        ),
        Node::new(NodeKind::Literal(1), 1),
        Node::new(NodeKind::Input, 2),
    ];
    let image = image(&nodes, 0);
    let mut tasks = [Task::default()];
    let mut frames = core::array::from_fn::<_, 2, _>(|_| None);
    let mut bindings = [None; 2];
    let limits = ExecutionLimits {
        bindings_per_task: 2,
        ..ExecutionLimits::default()
    };
    let mut execution =
        Execution::new(&image, &mut tasks, &mut frames, &mut bindings, limits, 1, 7)?;
    for _ in 0..16_000 {
        assert!(matches!(
            execution.advance(&image, &mut Numbers, 64),
            Advance::Yielded
        ));
    }
    assert!(execution.checkpoint().meta.steps > 1_000_000);
    execution.cancel();
    assert!(matches!(
        execution.advance(&image, &mut Numbers, 64),
        Advance::Done(Err(Fault::Cancelled))
    ));
    Ok(())
}

#[test]
fn explicit_lifetime_quota_still_cancels_execution() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::While {
                condition: 1,
                body: 2,
                max: u64::MAX,
            },
            0,
        ),
        Node::new(NodeKind::Literal(1), 1),
        Node::new(NodeKind::Input, 2),
    ];
    let image = image(&nodes, 0);
    let mut tasks = [Task::default()];
    let mut frames = core::array::from_fn::<_, 2, _>(|_| None);
    let mut bindings = [None; 2];
    let limits = ExecutionLimits {
        max_steps: Some(16),
        bindings_per_task: 2,
        ..ExecutionLimits::default()
    };
    let mut execution =
        Execution::new(&image, &mut tasks, &mut frames, &mut bindings, limits, 1, 7)?;
    assert!(matches!(
        execution.advance(&image, &mut Numbers, 64),
        Advance::Done(Err(Fault::Cancelled))
    ));
    assert_eq!(execution.checkpoint().meta.steps, 16);
    Ok(())
}

#[test]
fn finally_runs_on_failure_and_preserves_body_error() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::Finally {
                body: 1,
                cleanup: 2,
            },
            0,
        ),
        Node::new(NodeKind::Fail(Fault::Type), 1),
        Node::new(NodeKind::Request(0), 2),
    ];
    let mut cleaned = 0;
    assert_eq!(
        run(&nodes, 0, 42, &mut |request| {
            if !request.cleanup || request.input != 42 {
                return Err(Fault::Type);
            }
            cleaned += 1;
            Ok(0)
        }),
        Err(Fault::Type)
    );
    assert_eq!(cleaned, 1);
    Ok(())
}

#[test]
fn nested_bindings_restore_the_outer_value() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::Let {
                slot: 0,
                value: 1,
                body: 2,
            },
            0,
        ),
        Node::new(NodeKind::Literal(42), 1),
        Node::new(NodeKind::Then { first: 3, then: 6 }, 2),
        Node::new(
            NodeKind::Let {
                slot: 0,
                value: 4,
                body: 5,
            },
            3,
        ),
        Node::new(NodeKind::Literal(7), 4),
        Node::new(NodeKind::Load(0), 5),
        Node::new(NodeKind::Load(0), 6),
    ];
    assert_eq!(run(&nodes, 0, 0, &mut |_| Err(Fault::Type))?, 42);
    Ok(())
}

#[test]
fn parallel_branches_wait_without_spinning_and_reject_duplicate_events() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::Fork {
                left: 1,
                right: 2,
                join: Join::All,
            },
            0,
        ),
        Node::new(NodeKind::Request(0), 1),
        Node::new(NodeKind::Request(1), 2),
    ];
    let image = image(&nodes, 0);
    let mut tasks = core::array::from_fn::<_, 3, _>(|_| Task::default());
    let mut frames = core::array::from_fn::<_, 192, _>(|_| None);
    let mut bindings = [None; 6];
    let mut execution = Execution::new(
        &image,
        &mut tasks,
        &mut frames,
        &mut bindings,
        ExecutionLimits {
            bindings_per_task: 2,
            ..ExecutionLimits::default()
        },
        0,
        0,
    )?;
    let Advance::Request(a) = execution.advance(&image, &mut Numbers, 100) else {
        return Err(Fault::Type.into());
    };
    let Advance::Request(b) = execution.advance(&image, &mut Numbers, 100) else {
        return Err(Fault::Type.into());
    };
    for _ in 0..100 {
        assert!(matches!(
            execution.advance(&image, &mut Numbers, 100),
            Advance::Waiting
        ));
    }
    execution.complete(
        b.task,
        b.ticket,
        HostEvent::Complete(Ok(2)),
        &image,
        &mut Numbers,
    )?;
    assert!(matches!(
        execution.advance(&image, &mut Numbers, 100),
        Advance::Waiting
    ));
    assert_eq!(
        execution.complete(
            b.task,
            b.ticket,
            HostEvent::Complete(Ok(9)),
            &image,
            &mut Numbers
        ),
        Err(Fault::StaleEvent)
    );
    execution.complete(
        a.task,
        a.ticket,
        HostEvent::Complete(Ok(1)),
        &image,
        &mut Numbers,
    )?;
    assert!(matches!(
        execution.advance(&image, &mut Numbers, 100),
        Advance::Done(Ok(102))
    ));
    Ok(())
}

#[test]
fn race_waits_for_loser_cleanup_before_returning_winner() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::Fork {
                left: 1,
                right: 2,
                join: Join::Race,
            },
            0,
        ),
        Node::new(NodeKind::Request(0), 1),
        Node::new(
            NodeKind::Finally {
                body: 3,
                cleanup: 4,
            },
            2,
        ),
        Node::new(NodeKind::Request(1), 3),
        Node::new(NodeKind::Request(2), 4),
    ];
    let image = image(&nodes, 0);
    let mut tasks = core::array::from_fn::<_, 3, _>(|_| Task::default());
    let mut frames = core::array::from_fn::<_, 192, _>(|_| None);
    let mut bindings = [None; 6];
    let mut execution = Execution::new(
        &image,
        &mut tasks,
        &mut frames,
        &mut bindings,
        ExecutionLimits {
            bindings_per_task: 2,
            ..ExecutionLimits::default()
        },
        0,
        0,
    )?;
    let Advance::Request(a) = execution.advance(&image, &mut Numbers, 100) else {
        return Err(Fault::Type.into());
    };
    let Advance::Request(b) = execution.advance(&image, &mut Numbers, 100) else {
        return Err(Fault::Type.into());
    };
    execution.complete(
        a.task,
        a.ticket,
        HostEvent::Complete(Ok(42)),
        &image,
        &mut Numbers,
    )?;
    let Advance::Cancel { task, ticket } = execution.advance(&image, &mut Numbers, 100) else {
        return Err(Fault::Type.into());
    };
    assert_eq!((task, ticket), (b.task, b.ticket));
    execution.complete(
        task,
        ticket,
        HostEvent::Complete(Err(Fault::Cancelled)),
        &image,
        &mut Numbers,
    )?;
    let Advance::Request(cleanup) = execution.advance(&image, &mut Numbers, 100) else {
        return Err(Fault::Type.into());
    };
    assert!(cleanup.cleanup);
    assert_eq!(cleanup.import, 2);
    execution.complete(
        cleanup.task,
        cleanup.ticket,
        HostEvent::Complete(Ok(0)),
        &image,
        &mut Numbers,
    )?;
    assert!(matches!(
        execution.advance(&image, &mut Numbers, 100),
        Advance::Done(Ok(42))
    ));
    Ok(())
}

#[test]
fn recursive_calls_fail_at_frame_capacity() -> anyhow::Result<()> {
    let nodes = [Node::new(NodeKind::Call(0), 0)];
    assert_eq!(
        run(&nodes, 0, 0, &mut |_| Err(Fault::Type)),
        Err(Fault::Frames)
    );
    Ok(())
}

#[test]
fn admission_rejects_invalid_unreachable_code_and_durability() -> anyhow::Result<()> {
    let mut nodes = [
        Node::new(NodeKind::Input, 0),
        Node::new(NodeKind::Load(99), 1),
    ];
    assert_eq!(image(&nodes, 0).validate(), Err(Fault::InvalidBinding));
    nodes[1].kind = NodeKind::Request(99);
    assert_eq!(image(&nodes, 0).validate(), Err(Fault::InvalidImport));
    nodes[1].kind = NodeKind::Call(99);
    assert_eq!(image(&nodes, 0).validate(), Err(Fault::InvalidNode));
    nodes[1].kind = NodeKind::Input;
    let mut image = image(&nodes, 0);
    image.durable = true;
    let mut tasks = [Task::default()];
    let mut frames = [None];
    let mut bindings = [None; 2];
    assert!(matches!(
        Execution::new(
            &image,
            &mut tasks,
            &mut frames,
            &mut bindings,
            ExecutionLimits::default(),
            0,
            0
        ),
        Err(Fault::DurableUnavailable)
    ));
    Ok(())
}

#[test]
fn handles_enforce_ownership_attenuation_and_revocation() -> anyhow::Result<()> {
    let mut slots = [Handle::default(); 2];
    let mut handles = HandleTable::new(&mut slots);
    let parent = handles.install(1, 7, 0b11)?;
    let child = handles.derive(parent, 1, 2, 0b01)?;
    assert_eq!(handles.authorize(child, 2, 0)?, 7);
    assert_eq!(handles.authorize(child, 1, 0), Err(AuthorityError::Owner));
    assert_eq!(handles.authorize(child, 2, 1), Err(AuthorityError::Rights));
    assert_eq!(
        handles.derive(child, 2, 3, 0b10),
        Err(AuthorityError::Rights)
    );
    handles.revoke(child, 2)?;
    let replacement = handles.install(2, 8, 1)?;
    assert_ne!(replacement, child);
    assert_eq!(handles.authorize(child, 2, 0), Err(AuthorityError::Stale));
    Ok(())
}

#[test]
fn revoking_a_delegation_parent_invalidates_descendants_without_leaking_slots() -> anyhow::Result<()>
{
    let mut slots = [Handle::default(); 3];
    let mut table = HandleTable::new(&mut slots);
    let root = table.install(1, 7, 3)?;
    let child = table.derive(root, 1, 2, 1)?;
    let leaf = table.derive(child, 2, 3, 1)?;
    table.revoke(root, 1)?;
    assert_eq!(table.authorize(leaf, 3, 0), Err(AuthorityError::Stale));
    let replacement = table.install(1, 9, 3)?;
    assert_eq!(table.authorize(leaf, 3, 0), Err(AuthorityError::Stale));
    table.revoke(child, 2)?;
    table.revoke(leaf, 3)?;
    let child = table.derive(replacement, 1, 2, 1)?;
    assert_eq!(table.authorize(child, 2, 0)?, 9);
    Ok(())
}

#[test]
fn checkpoint_restores_pending_request_and_checks_image_identity() -> anyhow::Result<()> {
    let nodes = [Node::new(NodeKind::Request(0), 0)];
    let image = image(&nodes, 0);
    let limits = ExecutionLimits {
        frames_per_task: 2,
        bindings_per_task: 2,
        ..ExecutionLimits::default()
    };
    let mut tasks = [Task::default()];
    let mut frames = [None, None];
    let mut bindings = [None; 2];
    let mut saved_tasks = [Task::default()];
    let mut saved_frames = [None, None];
    let mut saved_bindings = [None; 2];
    let (meta, request) = {
        let mut execution = Execution::new(
            &image,
            &mut tasks,
            &mut frames,
            &mut bindings,
            limits,
            42,
            7,
        )?;
        let Advance::Request(request) = execution.advance(&image, &mut Numbers, 10) else {
            anyhow::bail!("missing request");
        };
        let saved = execution.checkpoint();
        saved_tasks.clone_from_slice(saved.tasks);
        saved_frames.clone_from_slice(saved.frames);
        saved_bindings.clone_from_slice(saved.bindings);
        (saved.meta, request)
    };
    let checkpoint = Checkpoint {
        meta,
        tasks: &saved_tasks,
        frames: &saved_frames,
        bindings: &saved_bindings,
    };
    Execution::validate_checkpoint(&image, &checkpoint, false)?;
    assert!(checkpoint.result().is_none());
    assert!(checkpoint.pending_tickets().eq([request.ticket]));
    let pending = checkpoint
        .pending_requests(&image)
        .next()
        .ok_or(Fault::StaleEvent)?;
    assert_eq!(
        (
            pending.ticket,
            pending.import,
            *pending.input,
            pending.context
        ),
        (request.ticket, 0, 42, 7)
    );
    {
        let mut restored = Execution::restore(
            &image,
            &checkpoint,
            &mut tasks,
            &mut frames,
            &mut bindings,
            false,
        )?;
        let pending = restored
            .pending_requests(&image)
            .next()
            .ok_or(Fault::StaleEvent)?;
        assert_eq!(
            (pending.ticket, pending.input, pending.context),
            (request.ticket, 42, 7)
        );
        restored.complete(
            pending.task,
            pending.ticket,
            HostEvent::Complete(Ok(9)),
            &image,
            &mut Numbers,
        )?;
        assert!(matches!(
            restored.advance(&image, &mut Numbers, 10),
            Advance::Done(Ok(9))
        ));
        assert_eq!(restored.checkpoint().result(), Some(&Ok(9)));
        assert_eq!(restored.checkpoint().pending_tickets().count(), 0);
    }
    let mut changed = image;
    changed.id = [2; 32];
    assert_eq!(
        Execution::validate_checkpoint(&changed, &checkpoint, false),
        Err(Fault::ImageMismatch)
    );
    assert!(matches!(
        Execution::restore(
            &changed,
            &checkpoint,
            &mut tasks,
            &mut frames,
            &mut bindings,
            false
        ),
        Err(Fault::ImageMismatch)
    ));
    Ok(())
}

#[test]
fn linked_dispatch_checks_revocation_after_admission() -> anyhow::Result<()> {
    let nodes = [Node::new(NodeKind::Request(0), 0)];
    let mut image = image(&nodes, 0);
    image.imports = 1;
    let mut slots = [Handle::default()];
    let mut table = HandleTable::new(&mut slots);
    let handle = table.install(7, 9, 1)?;
    let bindings = [ImportBinding { handle, method: 0 }];
    let linked = LinkedProgram::new(image, &bindings, &table, 7)?;
    let mut tasks = [Task::default()];
    let mut frames = [None, None];
    let mut values = [None; 2];
    let limits = ExecutionLimits {
        frames_per_task: 2,
        bindings_per_task: 2,
        ..ExecutionLimits::default()
    };
    let mut execution = Execution::new(
        &linked.image,
        &mut tasks,
        &mut frames,
        &mut values,
        limits,
        0,
        7,
    )?;
    table.revoke(handle, 7)?;
    assert!(matches!(
        execution.advance_linked(&linked, &table, &mut Numbers, 10),
        Advance::Yielded
    ));
    assert!(matches!(
        execution.advance_linked(&linked, &table, &mut Numbers, 10),
        Advance::Done(Err(Fault::Authority))
    ));
    Ok(())
}

#[test]
fn channel_backpressure_preserves_values_and_terminal_error() -> anyhow::Result<()> {
    let mut slots = [None; 2];
    let mut channel = Channel::<_, Fault>::new(&mut slots);
    assert_eq!(channel.try_send(1), Ok(()));
    assert_eq!(channel.try_send(2), Ok(()));
    assert_eq!(channel.try_send(3), Err(SendError::Full(3)));
    assert_eq!(channel.receive(), Receive::Item(1));
    assert_eq!(channel.try_send(3), Ok(()));
    channel.close(Err(Fault::Cancelled));
    channel.close(Ok(()));
    assert_eq!(channel.try_send(4), Err(SendError::Closed(4)));
    assert_eq!(channel.receive(), Receive::Item(2));
    assert_eq!(channel.receive(), Receive::Item(3));
    assert_eq!(channel.receive(), Receive::End(Err(Fault::Cancelled)));
    assert_eq!(channel.receive(), Receive::End(Err(Fault::Cancelled)));
    let mut empty = [];
    let mut channel = Channel::<_, Fault>::new(&mut empty);
    assert_eq!(channel.try_send(1), Err(SendError::Full(1)));
    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn native_continuation_checkpoints_validate_entries_before_resuming() -> anyhow::Result<()> {
    #[derive(serde::Deserialize)]
    struct Saved {
        meta: CheckpointMeta,
        tasks: Vec<Task<i64, Fault>>,
        frames: Vec<Option<Frame<i64, Fault>>>,
        bindings: Vec<Option<i64>>,
    }
    let nodes = [
        Node::new(NodeKind::Request(0), 0),
        Node::new(NodeKind::Request(1), 1),
        Node::new(NodeKind::Input, 2),
    ];
    let image = image(&nodes, 0);
    let mut tasks = [Task::default()];
    let mut frames = [None];
    let mut bindings = [None, None];
    let encoded = {
        let mut execution = Execution::new(
            &image,
            &mut tasks,
            &mut frames,
            &mut bindings,
            ExecutionLimits {
                frames_per_task: 1,
                bindings_per_task: 2,
                ..ExecutionLimits::default()
            },
            42,
            7,
        )?;
        let Advance::Request(request) = execution.advance(&image, &mut Numbers, 31) else {
            anyhow::bail!("missing initial request");
        };
        execution.complete(
            request.task,
            request.ticket,
            HostEvent::Continue { entry: 1, input: 9 },
            &image,
            &mut Numbers,
        )?;
        serde_json::to_value(execution.checkpoint())?
    };
    for case in ["valid", "entry", "caller", "version"] {
        let mut value = encoded.clone();
        let expected = match case {
            "entry" => {
                value["frames"][0]["kind"]["Continuation"]["entry"] = 99.into();
                Some(Fault::InvalidNode)
            }
            "caller" => {
                value["frames"][0]["kind"]["Continuation"]["node"] = 2.into();
                Some(Fault::InvalidCheckpoint)
            }
            "version" => {
                value["meta"]["version"] = (CHECKPOINT_VERSION - 1).into();
                Some(Fault::Version)
            }
            _ => None,
        };
        let mut saved: Saved = serde_json::from_value(value)?;
        let resumed = Execution::resume(
            &image,
            saved.meta,
            &mut saved.tasks,
            &mut saved.frames,
            &mut saved.bindings,
            false,
        );
        if let Some(expected) = expected {
            assert_eq!(resumed.err(), Some(expected));
        } else {
            let mut execution = resumed?;
            assert_eq!(execution.continuation_entries().collect::<Vec<_>>(), [1]);
            let Advance::Request(request) = execution.advance(&image, &mut Numbers, 31) else {
                anyhow::bail!("resumed body did not request its operation");
            };
            assert_eq!(request.input, 9);
            assert_eq!(request.import, 1);
            assert_eq!(request.ticket, 2);
            execution.complete(
                request.task,
                request.ticket,
                HostEvent::Complete(Ok(11)),
                &image,
                &mut Numbers,
            )?;
            assert!(matches!(
                execution.advance(&image, &mut Numbers, 31),
                Advance::Done(Ok(11))
            ));
            assert!(execution.continuation_entries().next().is_none());
        }
    }
    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn serialized_checkpoint_preserves_pending_branches_and_rejects_corruption() -> anyhow::Result<()> {
    #[derive(serde::Deserialize)]
    struct Saved {
        meta: CheckpointMeta,
        tasks: Vec<Task<i64, Fault>>,
        frames: Vec<Option<Frame<i64, Fault>>>,
        bindings: Vec<Option<i64>>,
    }
    let nodes = [
        Node::new(
            NodeKind::Fork {
                left: 1,
                right: 2,
                join: Join::All,
            },
            0,
        ),
        Node::new(NodeKind::Request(0), 1),
        Node::new(NodeKind::Request(1), 2),
    ];
    let image = image(&nodes, 0);
    let limits = ExecutionLimits {
        frames_per_task: 2,
        bindings_per_task: 2,
        ..ExecutionLimits::default()
    };
    let mut tasks = core::array::from_fn::<_, 3, _>(|_| Task::default());
    let mut frames = core::array::from_fn::<_, 6, _>(|_| None);
    let mut bindings = [None; 6];
    let encoded = {
        let mut execution = Execution::new(
            &image,
            &mut tasks,
            &mut frames,
            &mut bindings,
            limits,
            42,
            7,
        )?;
        assert!(matches!(
            execution.advance(&image, &mut Numbers, 20),
            Advance::Request(_)
        ));
        assert!(matches!(
            execution.advance(&image, &mut Numbers, 20),
            Advance::Request(_)
        ));
        serde_json::to_vec(&execution.checkpoint())?
    };
    let saved: Saved = serde_json::from_slice(&encoded)?;
    let checkpoint = Checkpoint {
        meta: saved.meta,
        tasks: &saved.tasks,
        frames: &saved.frames,
        bindings: &saved.bindings,
    };
    {
        let mut execution = Execution::restore(
            &image,
            &checkpoint,
            &mut tasks,
            &mut frames,
            &mut bindings,
            false,
        )?;
        let requests: Vec<_> = execution.pending_requests(&image).collect();
        assert_eq!(requests.len(), 2);
        for request in requests.into_iter().rev() {
            execution.complete(
                request.task,
                request.ticket,
                HostEvent::Complete(Ok(i64::from(request.import) + 1)),
                &image,
                &mut Numbers,
            )?;
        }
        assert!(matches!(
            execution.advance(&image, &mut Numbers, 20),
            Advance::Done(Ok(102))
        ));
    }
    for field in ["ticket", "parent"] {
        let mut corrupt: serde_json::Value = serde_json::from_slice(&encoded)?;
        if field == "ticket" {
            corrupt["tasks"][2]["state"]["Waiting"]["ticket"] =
                corrupt["tasks"][1]["state"]["Waiting"]["ticket"].clone();
        } else {
            corrupt["tasks"][1]["parent"] = serde_json::Value::Null;
        }
        let saved: Saved = serde_json::from_value(corrupt)?;
        let checkpoint = Checkpoint {
            meta: saved.meta,
            tasks: &saved.tasks,
            frames: &saved.frames,
            bindings: &saved.bindings,
        };
        assert!(matches!(
            Execution::restore(
                &image,
                &checkpoint,
                &mut tasks,
                &mut frames,
                &mut bindings,
                false
            ),
            Err(Fault::InvalidCheckpoint)
        ));
    }
    Ok(())
}

#[cfg(feature = "serde")]
#[test]
fn shared_frame_checkpoints_validate_owners_free_lists_and_unused_slots() -> anyhow::Result<()> {
    use anyhow::Context;
    #[derive(serde::Deserialize)]
    struct Saved {
        meta: CheckpointMeta,
        tasks: Vec<Task<i64, Fault>>,
        frames: Vec<Option<Frame<i64, Fault>>>,
        bindings: Vec<Option<i64>>,
    }
    let nodes = [
        Node::new(
            NodeKind::Fork {
                left: 1,
                right: 4,
                join: Join::All,
            },
            0,
        ),
        Node::new(
            NodeKind::Finally {
                body: 3,
                cleanup: 3,
            },
            1,
        ),
        Node::new(NodeKind::Request(0), 2),
        Node::new(NodeKind::Input, 3),
        Node::new(
            NodeKind::Finally {
                body: 2,
                cleanup: 3,
            },
            4,
        ),
    ];
    let image = ProgramImage {
        bindings: 0,
        ..image(&nodes, 0)
    };
    let limits = ExecutionLimits {
        frames_per_task: 2,
        bindings_per_task: 0,
        ..ExecutionLimits::default()
    };
    let mut tasks = core::array::from_fn::<_, 3, _>(|_| Task::default());
    let mut frames = core::array::from_fn::<_, 7, _>(|_| None);
    let mut bindings = [];
    let encoded = {
        let mut execution =
            Execution::new(&image, &mut tasks, &mut frames, &mut bindings, limits, 7, 1)?;
        assert!(matches!(
            execution.advance(&image, &mut Numbers, 64),
            Advance::Request(_)
        ));
        assert!(matches!(
            execution.advance(&image, &mut Numbers, 64),
            Advance::Waiting
        ));
        serde_json::to_value(execution.checkpoint())?
    };
    let top = encoded["tasks"][2]["stack"]["top"]
        .as_u64()
        .context("missing stack head")? as usize;
    let free = encoded["meta"]["frame_pool"]["free_head"]
        .as_u64()
        .context("missing free head")? as usize;
    assert!(free < frames.len());
    for damage in [
        "owner",
        "cycle",
        "alias",
        "orphan",
        "free_cycle",
        "free_alias",
        "unused",
        "version",
    ] {
        let mut corrupt = encoded.clone();
        match damage {
            "owner" => corrupt["frames"][top]["owner"] = 1.into(),
            "cycle" => corrupt["frames"][top]["previous"] = top.into(),
            "alias" => corrupt["tasks"][1]["stack"] = corrupt["tasks"][2]["stack"].clone(),
            "orphan" => {
                corrupt["tasks"][2]["stack"]["depth"] = 0.into();
                corrupt["tasks"][2]["stack"]["top"] = u32::MAX.into();
            }
            "free_cycle" => corrupt["frames"][free]["previous"] = free.into(),
            "free_alias" => corrupt["meta"]["frame_pool"]["free_head"] = top.into(),
            "unused" => corrupt["frames"][6] = corrupt["frames"][top].clone(),
            _ => corrupt["meta"]["version"] = (CHECKPOINT_VERSION + 1).into(),
        }
        let saved: Saved = serde_json::from_value(corrupt)?;
        let checkpoint = Checkpoint {
            meta: saved.meta,
            tasks: &saved.tasks,
            frames: &saved.frames,
            bindings: &saved.bindings,
        };
        let error = Execution::restore(
            &image,
            &checkpoint,
            &mut tasks,
            &mut frames,
            &mut bindings,
            false,
        )
        .err()
        .context("corrupted checkpoint was accepted")?;
        assert_eq!(
            error,
            if damage == "version" {
                Fault::Version
            } else {
                Fault::InvalidCheckpoint
            }
        );
    }
    let saved: Saved = serde_json::from_value(encoded)?;
    let checkpoint = Checkpoint {
        meta: saved.meta,
        tasks: &saved.tasks,
        frames: &saved.frames,
        bindings: &saved.bindings,
    };
    let mut execution = Execution::restore(
        &image,
        &checkpoint,
        &mut tasks,
        &mut frames,
        &mut bindings,
        false,
    )?;
    let pending = execution
        .pending_requests(&image)
        .next()
        .context("missing request")?;
    execution.complete(
        pending.task,
        pending.ticket,
        HostEvent::Complete(Ok(1)),
        &image,
        &mut Numbers,
    )?;
    assert!(matches!(
        execution.advance(&image, &mut Numbers, 64),
        Advance::Done(Ok(701))
    ));
    Ok(())
}
