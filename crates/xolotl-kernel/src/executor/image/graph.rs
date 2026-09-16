//! Index source edges once before lowering nodes into the shared instruction image.

use super::*;

#[derive(Clone, Default)]
pub(super) struct NodeLinks {
    pub next: Option<u32>,
    pub arms: [Option<u32>; 2],
    pub save: Option<u32>,
    pub load: Option<u32>,
}

pub(super) fn index_edges(
    graph: &ExecutionGraph,
    ids: &HashMap<NodeId, u32>,
    base: u32,
    bindings: &mut usize,
    max_bindings: usize,
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
        let target = (to - base) as usize;
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
            EdgeKind::Use => {
                if !matches!(graph.nodes[target].kind, NodeKind::Pure(_)) {
                    return Err(machine_error("binding target must be a value node"));
                }
                let slot = match nodes[source].save {
                    Some(slot) => slot,
                    None => {
                        if *bindings >= max_bindings.min(u32::MAX as usize) {
                            return Err(machine_error("binding capacity exceeded"));
                        }
                        let slot = *bindings as u32;
                        *bindings += 1;
                        nodes[source].save = Some(slot);
                        slot
                    }
                };
                if nodes[target].load.replace(slot).is_some() {
                    return Err(machine_error("multiple values for one binding use"));
                }
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
    use xolotl_graph::{Edge, Node};
    use xolotl_types::Value;

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
