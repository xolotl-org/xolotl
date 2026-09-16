use super::Fingerprint;
use crate::{BranchKind, ExecutionGraph, NodeKind};

pub(crate) fn graph(graph: &ExecutionGraph) -> Result<[u8; 32], serde_json::Error> {
    let mut digest = Fingerprint::new(b"xolotl-native-graph-v1");
    digest.integer(graph.nodes.len() as u64);
    for node in &graph.nodes {
        digest.integer(u64::from(node.id.get()));
        match &node.kind {
            NodeKind::Pure(value) => {
                digest.tag(0);
                digest.value(value);
            }
            NodeKind::Fail(failure) => {
                digest.tag(1);
                digest.metadata(failure)?;
            }
            NodeKind::Operation(operation) => {
                digest.tag(2);
                digest.operation(operation)?;
            }
            NodeKind::Step(step) => {
                digest.tag(3);
                digest.step(step);
            }
            NodeKind::Branch(BranchKind::OrElse { recover }) => {
                digest.tag(4);
                digest.step(recover);
            }
            NodeKind::Join(join) => {
                digest.tag(5);
                digest.metadata(join)?;
            }
            NodeKind::Acting(path) => {
                digest.tag(6);
                digest.metadata(path)?;
            }
            NodeKind::Wait(wait) => {
                digest.tag(7);
                digest.wait(wait)?;
            }
        }
    }
    digest.integer(graph.edges.len() as u64);
    for edge in &graph.edges {
        digest.integer(u64::from(edge.from.get()));
        digest.integer(u64::from(edge.to.get()));
        digest.metadata(&edge.kind)?;
    }
    digest.integer(u64::from(graph.root.get()));
    Ok(digest.finish())
}
