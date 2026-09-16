use super::*;
use crate::{RuntimeValues, executor::image::Import};
use anyhow::{Context, ensure};
use xolotl_core::{Advance, Execution, ExecutionLimits, HostEvent, NodeKind};
use xolotl_graph::{OperationTemplate, StepRef, portable::Transform};
use xolotl_types::{IdentityRef, Path, ProcessId, ProcessStatus, ResourceName, TaintSource};

fn suspended(value: Value, other: Value) -> anyhow::Result<ExecutionSnapshot> {
    let nodes = vec![
        Node::new(
            NodeKind::Let {
                slot: 0,
                value: 1,
                body: 2,
            },
            0,
        ),
        Node::new(
            NodeKind::Literal(TaintedValue::new(value.clone(), TaintSet::author())),
            1,
        ),
        Node::new(
            NodeKind::Finally {
                body: 3,
                cleanup: 4,
            },
            2,
        ),
        Node::new(NodeKind::Request(0), 3),
        Node::new(NodeKind::Input, 4),
    ];
    let imports = vec![
        Import::Operation(
            OperationTemplate {
                target: ResourceName(Path::parse("effect://codec/echo")?),
                method: "invoke".into(),
                method_id: None,
                output: Default::default(),
                literal_input: Some(other.clone()),
            },
            true,
        ),
        Import::Step(StepRef::new("unused-native-import").with_arg(value), None),
        Import::Transform(Transform::Equal { value: other }),
    ];
    let program = PreparedProgram {
        inner: Arc::new(MachineProgram::from_checkpoint(
            nodes, imports, 0, 1, true, true, [7; 32],
        )),
    };
    let image = program.inner.image();
    let mut tasks = vec![Task::default()];
    let mut frames = vec![None; 16];
    let mut bindings = vec![None];
    let input = TaintedValue::new(Value::null(), TaintSet::of(TaintSource::ModelOutput));
    let mut execution = Execution::new(
        &image,
        &mut tasks,
        &mut frames,
        &mut bindings,
        ExecutionLimits {
            frames_per_task: 16,
            bindings_per_task: 1,
            durable: true,
            ..ExecutionLimits::default()
        },
        input,
        5,
    )?;
    let Advance::Request(request) = execution.advance(&image, &mut RuntimeValues, 64) else {
        anyhow::bail!("fixture did not suspend at its imported operation");
    };
    let ticket = request.ticket;
    let meta = execution.suspend();
    Ok(ExecutionSnapshot {
        version: EXECUTION_CHECKPOINT_VERSION,
        execution: ExecutionId::FIRST,
        process: ProcessSnapshot {
            id: ProcessId::new(7),
            lifecycle_execution: ExecutionId::FIRST,
            parent: Some(ProcessId::new(1)),
            identity: IdentityRef::ROOT,
            grants: Vec::new(),
            status: ProcessStatus::Running,
            terminal_intent: None,
            budget: Default::default(),
            budget_spec: Default::default(),
        },
        program,
        machine: MachineSnapshot {
            meta,
            tasks,
            frames,
            bindings,
        },
        pending: BTreeMap::from([(ticket, ReplayClass::Deterministic)]),
        finished: false,
    })
}

fn overlapping_values() -> (Value, Value) {
    let shared = Value::list(vec![
        Value::bytes(vec![0, 128, 255]),
        Value::from("shared payload"),
    ]);
    (
        Value::map(BTreeMap::from([
            ("shared".into(), shared.clone()),
            ("side".into(), Value::integer(1)),
        ])),
        Value::map(BTreeMap::from([
            ("shared".into(), shared),
            ("side".into(), Value::integer(2)),
        ])),
    )
}

#[test]
fn complete_checkpoint_preserves_roots_descendants_and_provenance() -> anyhow::Result<()> {
    let (value, other) = overlapping_values();
    let original = suspended(value, other)?;
    let encoded = serde_json::to_vec(&original)?;
    let borrowed = ExecutionCheckpoint {
        version: original.version,
        execution: original.execution,
        process: original.process.clone(),
        program: &original.program.inner,
        machine: original.machine.checkpoint(),
        pending: &original.pending,
        finished: original.finished,
    };
    ensure!(serde_json::to_vec(&borrowed)? == encoded);
    let mut restored: ExecutionSnapshot = serde_json::from_slice(&encoded)?;
    let NodeKind::Literal(literal) = &restored.program.inner.nodes[1].kind else {
        anyhow::bail!("restored literal is missing");
    };
    let root_identity = literal.value.identity().context("resident map identity")?;
    let binding = restored.machine.bindings[0]
        .as_ref()
        .context("retained binding")?;
    ensure!(binding.value.identity() == Some(root_identity));
    let image = restored.program.inner.image();
    let checkpoint = restored.machine.checkpoint();
    let request = checkpoint
        .pending_requests(&image)
        .next()
        .context("pending input")?;
    ensure!(request.input.value.identity() == Some(root_identity));
    ensure!(request.input.taint == binding.taint);
    ensure!(
        request
            .input
            .taint
            .sources()
            .contains(&TaintSource::AuthorConstant)
    );
    ensure!(
        request
            .input
            .taint
            .sources()
            .contains(&TaintSource::ModelOutput)
    );
    let retained_input = request.input.clone();
    let ticket = request.ticket;
    let task = request.task;

    let mut frame_roots = 0;
    for frame in restored.machine.frames.iter().flatten() {
        frame.try_map_ref(
            |value| {
                ensure!(value.value.identity() == Some(root_identity));
                ensure!(value.taint == retained_input.taint);
                frame_roots += 1;
                Ok::<_, anyhow::Error>(())
            },
            |_error| Ok(()),
        )?;
    }
    ensure!(frame_roots == 1, "expected the retained Finally input");
    let Import::Operation(operation, _) = &restored.program.inner.imports[0] else {
        anyhow::bail!("operation import missing");
    };
    let other = operation
        .literal_input
        .as_ref()
        .context("literal operation input")?;
    ensure!(other.identity() != Some(root_identity));
    let child = literal
        .value
        .as_map()
        .and_then(|map| map.get("shared"))
        .context("first child")?;
    let other_child = other
        .as_map()
        .and_then(|map| map.get("shared"))
        .context("second child")?;
    ensure!(child.identity().is_some() && child.identity() == other_child.identity());
    let Import::Step(step, _) = &restored.program.inner.imports[1] else {
        anyhow::bail!("step import missing");
    };
    ensure!(step.arg.as_ref().and_then(Value::identity) == Some(root_identity));
    let Import::Transform(Transform::Equal { value }) = &restored.program.inner.imports[2] else {
        anyhow::bail!("comparison operand missing");
    };
    ensure!(value.identity() == other.identity());

    let machine = &mut restored.machine;
    let mut execution = Execution::resume(
        &image,
        machine.meta,
        &mut machine.tasks,
        &mut machine.frames,
        &mut machine.bindings,
        true,
    )?;
    execution.complete(
        task,
        ticket,
        HostEvent::Complete(Ok(retained_input.clone())),
        &image,
        &mut RuntimeValues,
    )?;
    let Advance::Done(Ok(output)) = execution.advance(&image, &mut RuntimeValues, 64) else {
        anyhow::bail!("restored continuation did not complete successfully");
    };
    ensure!(output.value.identity() == Some(root_identity));
    ensure!(output.taint == retained_input.taint);
    machine.meta = execution.suspend();
    restored.pending.clear();
    restored.finished = true;
    let completed: ExecutionSnapshot = serde_json::from_slice(&serde_json::to_vec(&restored)?)?;
    let checkpoint = completed.machine.checkpoint();
    let result = checkpoint.result().context("persisted terminal result")?;
    ensure!(result.as_ref().ok() == Some(&output));
    let NodeKind::Literal(literal) = &completed.program.inner.nodes[1].kind else {
        anyhow::bail!("completed literal missing");
    };
    ensure!(
        result
            .as_ref()
            .ok()
            .and_then(|value| value.value.identity())
            == literal.value.identity()
    );
    Ok(())
}

#[test]
fn every_checkpoint_root_is_checked_before_a_snapshot_is_returned() -> anyhow::Result<()> {
    let (value, other) = overlapping_values();
    let original = serde_json::to_value(suspended(value, other)?)?;
    let mut pointers = vec![
        "/program/nodes/1/kind/Literal/value".to_string(),
        "/program/imports/0/Operation/0/literal_input".to_string(),
        "/program/imports/1/Step/arg".to_string(),
        "/program/imports/2/Transform/value".to_string(),
        "/machine/tasks/0/input/value".to_string(),
        "/machine/bindings/0/value".to_string(),
    ];
    let frames = original["machine"]["frames"]
        .as_array()
        .context("frame slots")?;
    let frame = frames
        .iter()
        .position(|frame| frame.pointer("/kind/Finally/input/value").is_some())
        .context("Finally frame")?;
    pointers.push(format!("/machine/frames/{frame}/kind/Finally/input/value"));
    for pointer in pointers {
        let mut invalid = original.clone();
        *invalid
            .pointer_mut(&pointer)
            .with_context(|| format!("missing root {pointer}"))? = serde_json::json!(u64::MAX);
        let error = serde_json::from_value::<ExecutionSnapshot>(invalid)
            .err()
            .context("invalid root accepted")?;
        ensure!(error.to_string().contains("root"), "{pointer}: {error}");
    }
    Ok(())
}

#[test]
fn deep_checkpoint_values_encode_decode_and_release_on_a_small_stack() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(|| -> anyhow::Result<()> {
            let mut value = Value::bytes(vec![1, 2, 3]);
            for _ in 0..12_000 {
                value = Value::list(vec![value]);
            }
            let original = suspended(value.clone(), Value::list(vec![value]))?;
            let encoded = serde_json::to_vec(&original)?;
            let decoded: ExecutionSnapshot = serde_json::from_slice(&encoded)?;
            let NodeKind::Literal(literal) = &decoded.program.inner.nodes[1].kind else {
                anyhow::bail!("deep literal missing");
            };
            let binding = decoded.machine.bindings[0]
                .as_ref()
                .context("deep binding")?;
            ensure!(literal.value.identity() == binding.value.identity());
            let Import::Operation(operation, _) = &decoded.program.inner.imports[0] else {
                anyhow::bail!("deep operation missing");
            };
            let child = operation
                .literal_input
                .as_ref()
                .and_then(Value::as_list)
                .and_then(|list| list.first())
                .context("overlapping deep root")?;
            ensure!(child.identity() == literal.value.identity());
            drop(decoded);
            drop(original);
            Ok(())
        })?
        .join()
        .map_err(|_panic| anyhow::anyhow!("checkpoint worker failed"))??;
    Ok(())
}
