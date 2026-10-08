//! Index source edges once before lowering nodes into the shared instruction image.

use super::*;

#[derive(Clone, Default)]
pub(super) struct NodeLinks {
    pub next: Option<u32>,
    pub arms: [Option<u32>; 2],
}

pub(super) fn index_edges(
    graph: &ExecutionGraph,
    ids: &HashMap<NodeId, u32>,
    base: u32,
) -> Result<Vec<NodeLinks>, Failure> {
    let mut nodes = vec![NodeLinks::default(); graph.nodes.len()];
    for edge in &graph.edges {
        let from = *ids
            .get(&edge.from)
            .ok_or_else(|| machine_error("dangling graph edge"))?;
        let to = *ids
            .get(&edge.to)
            .ok_or_else(|| machine_error("dangling graph edge"))?;
        let source = (from - base) as usize;
        match edge.kind {
            EdgeKind::Then => {
                if nodes[source].next.replace(to).is_some() {
                    return Err(machine_error("multiple continuations"));
                }
            }
            EdgeKind::Arm => {
                let arm = nodes[source]
                    .arms
                    .iter_mut()
                    .find(|arm| arm.is_none())
                    .ok_or_else(|| machine_error("too many graph arms"))?;
                *arm = Some(to);
            }
            EdgeKind::Value | EdgeKind::Else => {
                return Err(machine_error("unsupported native graph edge"));
            }
        }
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;
    use xolotl_graph::{DoNode, Edge, Node};
    use xolotl_types::Value;

    #[test]
    fn native_lexical_slots_are_reused_between_finally_arms() -> anyhow::Result<()> {
        let local = |value| {
            DoNode::r#let(
                "local",
                DoNode::pure(Value::integer(value)),
                DoNode::use_("local"),
            )
        };
        let body = (1..64).fold(local(0), |body, value| body.finally(local(value)));
        let config = crate::ExecutionConfig {
            bindings_per_task: 1,
            ..Default::default()
        };
        let program = MachineProgram::new(&xolotl_graph::compile_do(&body)?, &config)?;
        ensure!(program.bindings == 1);
        ensure!(
            program
                .nodes
                .iter()
                .filter(|node| matches!(node.kind, Code::Let { slot: 0, .. }))
                .count()
                == 64
        );
        ensure!(
            program
                .nodes
                .iter()
                .filter(|node| matches!(node.kind, Code::Load(0)))
                .count()
                == 64
        );
        program.image().validate()?;
        Ok(())
    }

    #[test]
    fn native_lexical_exit_releases_bindings_before_later_host_wait() -> anyhow::Result<()> {
        use xolotl_core::{Advance, Execution, ExecutionLimits, Task};
        let body = DoNode::r#let(
            "payload",
            DoNode::pure(Value::bytes(vec![0; 1024 * 1024])),
            DoNode::r#let(
                "used",
                DoNode::use_("payload"),
                DoNode::pure(Value::integer(0)),
            ),
        )
        .and_then(StepRef::new("wait"));
        let program = MachineProgram::new(
            &xolotl_graph::compile_do(&body)?,
            &crate::ExecutionConfig::default(),
        )?;
        ensure!(program.bindings == 1);
        let image = program.image();
        let mut tasks = vec![Task::default()];
        let mut frames = vec![None; 16];
        let mut bindings = vec![None; program.bindings];
        let limits = ExecutionLimits {
            frames_per_task: 16,
            bindings_per_task: program.bindings,
            ..Default::default()
        };
        let mut execution = Execution::new(
            &image,
            &mut tasks,
            &mut frames,
            &mut bindings,
            limits,
            TaintedValue::pristine(Value::null()),
            1,
        )?;
        let mut values = crate::RuntimeValues;
        let request = match execution.advance(&image, &mut values, 128) {
            Advance::Request(request) => request,
            state => anyhow::bail!("expected later host wait, got {state:?}"),
        };
        ensure!(request.input.value == Value::integer(0));
        let _suspended = execution.suspend();
        ensure!(bindings.iter().all(Option::is_none));
        Ok(())
    }

    #[test]
    fn native_graph_admission_can_exceed_the_old_fixed_ceiling() -> anyhow::Result<()> {
        let count = 65_540u32;
        let graph = ExecutionGraph {
            nodes: (0..count)
                .map(|index| Node {
                    id: NodeId::new(index),
                    kind: NodeKind::Pure(Value::null()),
                })
                .collect(),
            edges: (1..count)
                .map(|index| Edge {
                    from: NodeId::new(index - 1),
                    to: NodeId::new(index),
                    kind: EdgeKind::Then,
                })
                .collect(),
            root: NodeId::new(0),
            graph_hash: [0; 32],
        };
        let mut config = crate::ExecutionConfig::default();
        ensure!(MachineProgram::new(&graph, &config).is_err());
        config.max_instructions = count as usize;
        let program = MachineProgram::new(&graph, &config)?;
        ensure!(program.nodes.len() == count as usize);
        ensure!(program.nodes[(count - 2) as usize].next == Some(count - 1));
        program.image().validate()?;
        Ok(())
    }
}
