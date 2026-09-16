use anyhow::{Context, ensure};
use std::{cell::Cell, rc::Rc};
use xolotl_core::*;

#[derive(Debug)]
struct Tracked {
    payload: Vec<u8>,
    sources: u8,
    copied_bytes: Rc<Cell<usize>>,
}

impl Clone for Tracked {
    fn clone(&self) -> Self {
        self.copied_bytes
            .set(self.copied_bytes.get() + self.payload.len());
        Self {
            payload: self.payload.clone(),
            sources: self.sources,
            copied_bytes: Rc::clone(&self.copied_bytes),
        }
    }
}

#[derive(Default)]
struct TrackedValues {
    copied_bytes: Rc<Cell<usize>>,
}

impl TrackedValues {
    fn value(&self, payload: Vec<u8>, sources: u8) -> Tracked {
        Tracked {
            payload,
            sources,
            copied_bytes: Rc::clone(&self.copied_bytes),
        }
    }
}

impl Values for TrackedValues {
    type Value = Tracked;
    type Error = Fault;

    fn unit(&mut self) -> Tracked {
        self.value(Vec::new(), 0)
    }

    fn truth(&mut self, value: &Tracked) -> Result<bool, Fault> {
        match value.payload.as_slice() {
            [0] => Ok(false),
            [1] => Ok(true),
            _ => Err(Fault::Type),
        }
    }

    fn pair(&mut self, mut left: Tracked, right: Tracked) -> Result<Tracked, Fault> {
        left.payload.extend(right.payload);
        left.sources |= right.sources;
        Ok(left)
    }

    fn error(&mut self, fault: Fault) -> Fault {
        fault
    }

    fn error_value(&mut self, _error: Fault) -> Tracked {
        self.value(vec![0xff], 0)
    }

    fn influence(&mut self, mut value: Tracked, control: &Tracked) -> Tracked {
        value.sources |= control.sources;
        value
    }

    fn retain_control(&mut self, input: &Tracked) -> Tracked {
        self.value(Vec::new(), input.sources)
    }
}

fn image(nodes: &[Node<Tracked, Fault>]) -> ProgramImage<'_, Tracked, Fault> {
    ProgramImage {
        version: IMAGE_VERSION,
        id: [3; 32],
        nodes,
        entry: 0,
        bindings: 0,
        imports: 2,
        durable: false,
    }
}

fn drive(
    execution: &mut Execution<'_, Tracked, Fault>,
    image: &ProgramImage<'_, Tracked, Fault>,
    values: &mut TrackedValues,
    mut host: impl FnMut(Request<Tracked>) -> Result<Tracked, Fault>,
) -> Result<Tracked, Fault> {
    loop {
        match execution.advance(image, values, 31) {
            Advance::Done(result) => return result,
            Advance::Request(request) => execution.complete(
                request.task,
                request.ticket,
                HostEvent::Complete(host(request)),
                image,
                values,
            )?,
            Advance::Yielded => {}
            Advance::Waiting => return Err(Fault::StaleEvent),
            Advance::Cancel { task, ticket } => execution.complete(
                task,
                ticket,
                HostEvent::Complete(Err(Fault::Cancelled)),
                image,
                values,
            )?,
        }
    }
}

#[test]
fn straight_line_payload_copies_do_not_grow_with_program_length() -> anyhow::Result<()> {
    for length in [1, 64, 2048] {
        let nodes: Vec<_> = (0..length)
            .map(|index| Node {
                next: (index + 1 < length).then_some(index + 1),
                ..Node::new(NodeKind::Input, u64::from(index))
            })
            .collect();
        let image = image(&nodes);
        let mut values = TrackedValues::default();
        let mut tasks = [Task::default()];
        let mut execution = Execution::new(
            &image,
            &mut tasks,
            &mut [],
            &mut [],
            ExecutionLimits {
                frames_per_task: 0,
                bindings_per_task: 0,
                ..ExecutionLimits::default()
            },
            values.value(vec![0x5a; 65_536], 2),
            0,
        )?;
        let output = drive(&mut execution, &image, &mut values, |_| Err(Fault::Type))?;
        ensure!(output.payload == vec![0x5a; 65_536] && output.sources == 2);
        // Done returns an owned copy while retaining a checkpointable result.
        ensure!(values.copied_bytes.get() == 65_536);
    }
    Ok(())
}

#[test]
fn joins_move_completed_branch_payloads() -> anyhow::Result<()> {
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
            Node::new(NodeKind::Input, 1),
            Node::new(NodeKind::Input, 2),
        ];
        let image = image(&nodes);
        let mut values = TrackedValues::default();
        let mut tasks = core::array::from_fn::<_, 3, _>(|_| Task::default());
        let mut execution = Execution::new(
            &image,
            &mut tasks,
            &mut [],
            &mut [],
            ExecutionLimits {
                frames_per_task: 0,
                bindings_per_task: 0,
                ..ExecutionLimits::default()
            },
            values.value(vec![0x5a; 65_536], 2),
            0,
        )?;
        let output = drive(&mut execution, &image, &mut values, |_| Err(Fault::Type))?;
        let size = if join == Join::All { 131_072 } else { 65_536 };
        ensure!(output.payload == vec![0x5a; size] && output.sources == 2);
        // One copy fans out the input; one exports the completed root result.
        ensure!(values.copied_bytes.get() == 65_536 + size);
    }
    Ok(())
}

#[test]
fn compact_control_preserves_catch_provenance_for_instruction_and_capacity_errors()
-> anyhow::Result<()> {
    for failure in [
        NodeKind::Fail(Fault::Type),
        NodeKind::If { yes: 3, no: 3 },
        NodeKind::Then { first: 3, then: 3 },
    ] {
        let nodes = [
            Node::new(
                NodeKind::Catch {
                    body: 1,
                    recover: 2,
                },
                0,
            ),
            Node::new(failure, 1),
            Node::new(NodeKind::Request(0), 2),
            Node::new(NodeKind::Input, 3),
        ];
        let image = image(&nodes);
        let mut values = TrackedValues::default();
        let mut tasks = [Task::default()];
        let mut frames = [None, None];
        let mut execution = Execution::new(
            &image,
            &mut tasks,
            &mut frames,
            &mut [],
            ExecutionLimits {
                frames_per_task: 2,
                bindings_per_task: 0,
                ..ExecutionLimits::default()
            },
            values.value(vec![0x5a; 65_536], 2),
            0,
        )?;
        let output = drive(&mut execution, &image, &mut values, |request| {
            Ok(request.input)
        })?;
        ensure!(output.payload == [0xff] && output.sources == 2);
        ensure!(values.copied_bytes.get() == 2);
    }
    Ok(())
}

#[test]
fn finally_and_restored_scopes_keep_full_inputs() -> anyhow::Result<()> {
    let nodes = [
        Node::new(
            NodeKind::Finally {
                body: 1,
                cleanup: 3,
            },
            0,
        ),
        Node::new(NodeKind::Scope { import: 0, body: 2 }, 1),
        Node::new(NodeKind::Request(1), 2),
        Node::new(NodeKind::Request(1), 3),
    ];
    let image = image(&nodes);
    let mut values = TrackedValues::default();
    let mut tasks = [Task::default()];
    let mut frames = core::array::from_fn::<_, 4, _>(|_| None);
    let mut execution = Execution::new(
        &image,
        &mut tasks,
        &mut frames,
        &mut [],
        ExecutionLimits {
            frames_per_task: 4,
            bindings_per_task: 0,
            ..ExecutionLimits::default()
        },
        values.value(vec![0x5a; 65_536], 2),
        7,
    )?;
    let Advance::Request(request) = execution.advance(&image, &mut values, 31) else {
        anyhow::bail!("scope did not request authorization");
    };
    ensure!(request.input.payload == vec![0x5a; 65_536] && request.input.sources == 2);
    let mut restored_tasks = [Task::default()];
    let mut restored_frames = core::array::from_fn::<_, 4, _>(|_| None);
    let mut restored = Execution::restore(
        &image,
        &execution.checkpoint(),
        &mut restored_tasks,
        &mut restored_frames,
        &mut [],
        false,
    )?;
    let resumed = restored
        .pending_requests(&image)
        .next()
        .context("restoration lost the pending scope")?;
    ensure!(resumed.input.payload == request.input.payload && resumed.input.sources == 2);
    restored.complete(
        resumed.task,
        resumed.ticket,
        HostEvent::Enter(9),
        &image,
        &mut values,
    )?;
    let Advance::Request(body) = restored.advance(&image, &mut values, 31) else {
        anyhow::bail!("scope body did not receive its input");
    };
    ensure!(body.input.payload == request.input.payload && body.input.sources == 2);
    ensure!(body.context == 9);
    restored.complete(
        body.task,
        body.ticket,
        HostEvent::Complete(Err(Fault::Type)),
        &image,
        &mut values,
    )?;
    let mut cleaned = false;
    let result = drive(&mut restored, &image, &mut values, |request| {
        if request.import != 1
            || request.input.payload != vec![0x5a; 65_536]
            || request.input.sources != 2
            || request.context != 7
        {
            return Err(Fault::Type);
        }
        cleaned = true;
        Ok(request.input)
    });
    ensure!(cleaned && matches!(result, Err(Fault::Type)));
    Ok(())
}

#[test]
fn rejected_continuation_retains_sources_without_cloning_its_payload() -> anyhow::Result<()> {
    let nodes = [
        Node::new(NodeKind::Request(0), 0),
        Node::new(NodeKind::Input, 1),
    ];
    let image = image(&nodes);
    let mut values = TrackedValues::default();
    let mut tasks = [Task::default()];
    let mut execution = Execution::new(
        &image,
        &mut tasks,
        &mut [],
        &mut [],
        ExecutionLimits {
            frames_per_task: 0,
            bindings_per_task: 0,
            ..ExecutionLimits::default()
        },
        values.value(vec![7], 1),
        0,
    )?;
    let Advance::Request(request) = execution.advance(&image, &mut values, 31) else {
        anyhow::bail!("missing request");
    };
    let copied = values.copied_bytes.get();
    ensure!(
        execution.complete(
            request.task,
            request.ticket,
            HostEvent::Continue {
                entry: 1,
                input: values.value(vec![0x5a; 65_536], 2),
            },
            &image,
            &mut values,
        ) == Err(Fault::Frames)
    );
    ensure!(values.copied_bytes.get() == copied);
    let control = execution.retain_control(&mut values);
    ensure!(control.payload.is_empty() && control.sources == 3);
    let input = execution
        .pending_requests(&image)
        .next()
        .context("rejected continuation consumed its request")?
        .input;
    ensure!(input.payload == [7] && input.sources == 3);
    Ok(())
}

#[test]
fn in_place_resume_preserves_values_tickets_and_active_continuations() -> anyhow::Result<()> {
    let nodes = [
        Node::new(NodeKind::Request(0), 0),
        Node::new(
            NodeKind::Fork {
                left: 2,
                right: 3,
                join: Join::All,
            },
            1,
        ),
        Node::new(NodeKind::Request(1), 2),
        Node::new(NodeKind::Input, 3),
    ];
    let image = image(&nodes);
    let mut values = TrackedValues::default();
    let mut tasks = vec![Task::default()];
    let mut frames = Vec::new();
    let mut execution = Execution::new(
        &image,
        &mut tasks,
        &mut frames,
        &mut [],
        ExecutionLimits {
            frames_per_task: 0,
            bindings_per_task: 0,
            ..ExecutionLimits::default()
        },
        values.value(vec![0x5a; 65_536], 2),
        7,
    )?;
    let Advance::Request(request) = execution.advance(&image, &mut values, 31) else {
        anyhow::bail!("missing initial request");
    };
    let mut meta = execution.suspend();
    tasks.resize_with(3, Task::default);
    frames.resize_with(1, || None);
    meta.limits.frames_per_task = 1;
    let copied = values.copied_bytes.get();
    let mut execution = Execution::resume(&image, meta, &mut tasks, &mut frames, &mut [], false)?;
    ensure!(values.copied_bytes.get() == copied);
    ensure!(execution.is_pending(request.task, request.ticket));
    execution.complete(
        request.task,
        request.ticket,
        HostEvent::Continue {
            entry: 1,
            input: request.input,
        },
        &image,
        &mut values,
    )?;
    ensure!(matches!(
        execution.advance(&image, &mut values, 1),
        Advance::Yielded
    ));
    ensure!(execution.continuation_entries().collect::<Vec<_>>() == [1]);
    let copied = values.copied_bytes.get();
    let meta = execution.suspend();
    let mut execution = Execution::resume(&image, meta, &mut tasks, &mut frames, &mut [], false)?;
    ensure!(values.copied_bytes.get() == copied);
    ensure!(execution.checkpoint().meta.steps == meta.steps);
    ensure!(execution.continuation_entries().collect::<Vec<_>>() == [1]);
    let output = drive(&mut execution, &image, &mut values, |request| {
        Ok(request.input)
    })?;
    ensure!(output.payload == vec![0x5a; 131_072] && output.sources == 2);
    ensure!(execution.continuation_entries().next().is_none());
    Ok(())
}

#[test]
fn retired_binding_values_are_released_in_every_task_without_cloning() -> anyhow::Result<()> {
    let nodes = [Node::new(NodeKind::Input, 0)];
    let image = image(&nodes);
    let values = TrackedValues::default();
    let mut tasks = vec![Task::default(); 3];
    let mut bindings = vec![None; 9];
    let execution = Execution::new(
        &image,
        &mut tasks,
        &mut [],
        &mut bindings,
        ExecutionLimits {
            bindings_per_task: 3,
            ..ExecutionLimits::default()
        },
        values.value(Vec::new(), 0),
        0,
    )?;
    let meta = execution.suspend();
    for binding in &mut bindings {
        *binding = Some(values.value(vec![1; 1024], 1));
    }
    let references = Rc::strong_count(&values.copied_bytes);
    let mut execution = Execution::resume(&image, meta, &mut tasks, &mut [], &mut bindings, false)?;
    let reversed = core::ops::Range { start: 2, end: 1 };
    for invalid in [reversed, 0..4, usize::MAX..usize::MAX] {
        ensure!(execution.clear_bindings(invalid) == Err(Fault::InvalidBinding));
        ensure!(Rc::strong_count(&values.copied_bytes) == references);
    }
    execution.clear_bindings(1..2)?;
    ensure!(Rc::strong_count(&values.copied_bytes) == references - 3);
    ensure!(values.copied_bytes.get() == 0);
    for row in execution.checkpoint().bindings.as_chunks::<3>().0 {
        ensure!(row[0].is_some() && row[1].is_none() && row[2].is_some());
    }
    execution.clear_bindings(3..3)?;
    ensure!(Rc::strong_count(&values.copied_bytes) == references - 3);
    Ok(())
}
