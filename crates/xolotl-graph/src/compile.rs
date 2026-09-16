//! Do→Graph compiler: lower a [`DoNode`] AST into one
//! [`ExecutionGraph`].
//!
//! The compiler's contract is **stable, deterministic [`NodeId`]s**: the same
//! `DoNode` always compiles to the same node ids, assigned in a fixed
//! pre-order traversal, never depending on wall clock or randomness. These are
//! source positions; execution scopes and dynamic request tickets distinguish
//! independent evaluations and repeated visits to a node.
//!
//! Compilation rules:
//!
//! ```text
//! Pure(a)                Node::Pure
//! AndThen(d, s)          d's subgraph → Then-edge → Node::Step(s)
//! OrElse(d, s)           d's subgraph → Node::Branch(OrElse{recover:s})
//! Race(a, b)             a,b subgraphs → Node::Join(Race)
//! Both(a, b)             a,b subgraphs → Node::Join(Both)
//! Let(id, v, body)       v subgraph tagged binding id; Use(id) → Use-edge
//! Use(id)                Use-edge to the Let node (no new effect node)
//! Acting(id, body)       Node::Acting wrapping body's subgraph
//! Fail(f)                Node::Pure's failure dual
//! Op(t)                  Node::Operation
//! ```

use crate::r#do::DoNode;
use crate::graph::{BranchKind, Edge, EdgeKind, ExecutionGraph, JoinKind, Node, NodeKind};
use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use thiserror::Error;
use xolotl_types::{NodeId, Value};

/// Errors produced while lowering a [`DoNode`] into an [`ExecutionGraph`].
#[derive(Debug, Error, Eq, PartialEq)]
pub enum CompileError {
    /// A `Use(name)` node referenced a name that was not bound by an enclosing
    /// `Let`.
    #[error("Use(\"{0}\") references a name not bound by any enclosing Let")]
    UnboundName(String),
    /// The program exceeded the graph size admission limit.
    #[error("graph exceeded the maximum of {max} nodes")]
    TooLarge {
        /// Maximum number of nodes accepted by the compiler.
        max: usize,
    },
    /// The explicit base and graph size exceeded the source-position namespace.
    #[error("graph causal position exhausted")]
    PositionExhausted,
    /// The graph could not be serialized for structural hashing.
    #[error("graph hash serialization failed: {message}")]
    GraphHash {
        /// Serialization error message.
        message: String,
    },
}

/// Maximum nodes in one compiled graph. This admission bound prevents
/// unbounded programs.
const MAX_NODES: usize = 1 << 20;

struct Compiler {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    /// Name → the NodeId that produces the bound value (for `Use` edges).
    bindings: BTreeMap<String, NodeId>,
    /// Explicit source id offset. Dynamic module invocations use a local base
    /// of zero; execution tickets distinguish repeated visits to their nodes.
    base: u32,
}

/// The result of compiling one subtree: its entry node and its exit node.
/// Value flows into `entry`; the subtree's result is produced at `exit`.
#[derive(Clone, Copy)]
struct Span {
    entry: NodeId,
    exit: NodeId,
}

impl Compiler {
    fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            bindings: BTreeMap::new(),
            base: 0,
        }
    }

    fn with_base(base: u32) -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            bindings: BTreeMap::new(),
            base,
        }
    }

    fn push(&mut self, kind: NodeKind) -> Result<NodeId, CompileError> {
        if self.nodes.len() >= MAX_NODES {
            return Err(CompileError::TooLarge { max: MAX_NODES });
        }
        let id = NodeId::new(
            self.base
                .checked_add(self.nodes.len() as u32)
                .ok_or(CompileError::PositionExhausted)?,
        );
        self.nodes.push(Node { id, kind });
        Ok(id)
    }

    fn edge(&mut self, from: NodeId, to: NodeId, kind: EdgeKind) {
        self.edges.push(Edge { from, to, kind });
    }

    /// Lower `node`, returning its [`Span`]. Pre-order id assignment: a node's
    /// id is allocated before its children, so ids are stable under recompile.
    fn lower(&mut self, node: &DoNode) -> Result<Span, CompileError> {
        match node {
            DoNode::Pure(v) => {
                let id = self.push(NodeKind::Pure(v.clone()))?;
                Ok(Span {
                    entry: id,
                    exit: id,
                })
            }

            DoNode::Fail(f) => {
                // Failure-dual of Pure: a dedicated node carrying the
                // Failure losslessly; the Executor propagates it to the nearest
                // enclosing Branch.
                let id = self.push(NodeKind::Fail(f.clone()))?;
                Ok(Span {
                    entry: id,
                    exit: id,
                })
            }

            DoNode::Op(tmpl) => {
                let id = self.push(NodeKind::Operation(tmpl.clone()))?;
                Ok(Span {
                    entry: id,
                    exit: id,
                })
            }

            DoNode::Wait(spec) => {
                let id = self.push(NodeKind::Wait(spec.clone()))?;
                Ok(Span {
                    entry: id,
                    exit: id,
                })
            }

            DoNode::AndThen { d, then } => {
                let inner = self.lower(d)?;
                let step = self.push(NodeKind::Step(then.clone()))?;
                self.edge(inner.exit, step, EdgeKind::Then);
                Ok(Span {
                    entry: inner.entry,
                    exit: step,
                })
            }

            DoNode::OrElse { d, or } => {
                // Branch node is the entry; the guarded subgraph hangs off an
                // Arm edge; the recover step is stored in the node. On failure
                // of the guarded arm the Executor runs `recover`.
                let branch = self.push(NodeKind::Branch(BranchKind::OrElse {
                    recover: or.clone(),
                }))?;
                let inner = self.lower(d)?;
                self.edge(branch, inner.entry, EdgeKind::Arm);
                Ok(Span {
                    entry: branch,
                    exit: branch,
                })
            }

            DoNode::Both(a, b) | DoNode::Race(a, b) => {
                let join_kind = if matches!(node, DoNode::Both(..)) {
                    JoinKind::Both
                } else {
                    JoinKind::Race
                };
                // Allocate the join node first so its id precedes its arms,
                // keeping pre-order stability.
                let join = self.push(NodeKind::Join(join_kind))?;
                let la = self.lower(a)?;
                let lb = self.lower(b)?;
                self.edge(join, la.entry, EdgeKind::Arm);
                self.edge(join, lb.entry, EdgeKind::Arm);
                Ok(Span {
                    entry: join,
                    exit: join,
                })
            }

            DoNode::Let { name, value, body } => {
                let v = self.lower(value)?;
                // Bind the name to the value's exit node for the duration of
                // the body; restore the previous binding afterward (shadowing).
                let prev = self.bindings.insert(name.clone(), v.exit);
                let b = self.lower(body)?;
                match prev {
                    Some(p) => {
                        self.bindings.insert(name.clone(), p);
                    }
                    None => {
                        self.bindings.remove(name);
                    }
                }
                // Value subgraph runs first, then the body; entry is the
                // value's entry, exit is the body's exit.
                self.edge(v.exit, b.entry, EdgeKind::Then);
                Ok(Span {
                    entry: v.entry,
                    exit: b.exit,
                })
            }

            DoNode::Use(name) => {
                let target = self
                    .bindings
                    .get(name)
                    .copied()
                    .ok_or_else(|| CompileError::UnboundName(name.clone()))?;
                // A Use is a pure pass-through node with a Use-edge back to the
                // bound producer.
                let id = self.push(NodeKind::Pure(Value::null()))?;
                self.edge(target, id, EdgeKind::Use);
                Ok(Span {
                    entry: id,
                    exit: id,
                })
            }

            DoNode::Acting { identity, body } => {
                // The Acting node carries the identity Path directly in the IR
                //; the kernel interns it to an IdentityRef when binding
                // the child Operations. Body runs as the node's single arm, and
                // the Acting node is also the span exit so the identity scope
                // does not leak into the continuation (the walker restores the
                // outer identity once the arm completes).
                let act = self.push(NodeKind::Acting(identity.clone()))?;
                let b = self.lower(body)?;
                self.edge(act, b.entry, EdgeKind::Arm);
                Ok(Span {
                    entry: act,
                    exit: act,
                })
            }
        }
    }
}

/// Compile a [`DoNode`] program into one [`ExecutionGraph`] with stable node
/// ids and a content hash.
pub fn compile_do(program: &DoNode) -> Result<ExecutionGraph, CompileError> {
    let mut c = Compiler::new();
    let span = c.lower(program)?;
    let mut graph = ExecutionGraph {
        nodes: c.nodes,
        edges: c.edges,
        root: span.entry,
        graph_hash: [0u8; 32],
    };
    graph.graph_hash = hash_graph(&graph)?;
    Ok(graph)
}

/// Compile a subgraph whose source node ids start at an explicit `base`.
/// The executor uses zero for each dynamic module; source positions are local
/// to the module, while dynamic request tickets identify individual node visits.
/// The returned graph's `graph_hash` is left zeroed: native fragments are linked
/// only for this execution and cannot be stored in portable checkpoints.
pub fn compile_do_at(program: &DoNode, base: u32) -> Result<ExecutionGraph, CompileError> {
    let mut c = Compiler::with_base(base);
    let span = c.lower(program)?;
    Ok(ExecutionGraph {
        nodes: c.nodes,
        edges: c.edges,
        root: span.entry,
        graph_hash: [0u8; 32],
    })
}

/// Content hash over the graph structure (nodes + edges + root), independent of
/// the zeroed `graph_hash` field. Two structurally identical graphs hash equal.
fn hash_graph(graph: &ExecutionGraph) -> Result<[u8; 32], CompileError> {
    crate::fingerprint::graph(graph).map_err(|e| CompileError::GraphHash {
        message: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{OperationTemplate, StepRef};
    use alloc::collections::BTreeSet;
    use anyhow::{Context, anyhow, bail, ensure};
    use xolotl_types::{OutputMode, Path, ResourceName};

    fn s(name: &str) -> StepRef {
        StepRef::new(name)
    }

    #[test]
    fn explicit_source_offsets_never_wrap() -> anyhow::Result<()> {
        let body = DoNode::pure(Value::null()).and_then(s("next"));
        let graph = compile_do_at(&body, u32::MAX - 1)?;
        ensure!(graph.nodes[0].id.get() == u32::MAX - 1);
        ensure!(graph.nodes[1].id.get() == u32::MAX);
        ensure!(matches!(
            compile_do_at(&body, u32::MAX),
            Err(CompileError::PositionExhausted)
        ));
        Ok(())
    }

    fn op(path: &str) -> anyhow::Result<OperationTemplate> {
        Ok(OperationTemplate {
            target: ResourceName::new(
                Path::parse(path)
                    .map_err(|error| anyhow!("path parse failed for {path}: {error}"))?,
            ),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        })
    }

    #[test]
    fn graph_hashes_distinguish_literal_types_and_float_bits() -> anyhow::Result<()> {
        let values = [
            Value::null(),
            Value::integer(0),
            Value::bytes(vec![1]),
            Value::list(vec![Value::integer(1)]),
            Value::float(xolotl_types::FloatBits(0.0)),
            Value::float(xolotl_types::FloatBits(-0.0)),
            Value::float(xolotl_types::FloatBits(f64::from_bits(
                0x7ff8_0000_0000_0001,
            ))),
            Value::float(xolotl_types::FloatBits(f64::from_bits(
                0x7ff8_0000_0000_0002,
            ))),
        ];
        let mut pure_hashes = BTreeSet::new();
        let mut operation_hashes = BTreeSet::new();
        let mut step_hashes = BTreeSet::new();
        for value in values {
            let pure = DoNode::pure(value.clone());
            ensure!(pure_hashes.insert(compile_do(&pure)?.graph_hash));
            let step =
                DoNode::pure(Value::null()).and_then(s("codec/step").with_arg(value.clone()));
            ensure!(step_hashes.insert(compile_do(&step)?.graph_hash));
            let mut operation = op("effect://codec/invoke")?;
            operation.literal_input = Some(value);
            ensure!(operation_hashes.insert(compile_do(&DoNode::op(operation))?.graph_hash));
        }
        let dynamic_operation = compile_do(&DoNode::op(op("effect://codec/invoke")?))?;
        ensure!(!operation_hashes.contains(&dynamic_operation.graph_hash));
        let no_argument = compile_do(&DoNode::pure(Value::null()).and_then(s("codec/step")))?;
        ensure!(!step_hashes.contains(&no_argument.graph_hash));
        Ok(())
    }

    #[test]
    fn pure_compiles_to_single_node() -> anyhow::Result<()> {
        let g = compile_do(&DoNode::pure(Value::integer(1)))?;
        ensure!(g.len() == 1, "unexpected graph length: {}", g.len());
        ensure!(g.root == NodeId::new(0), "unexpected root: {:?}", g.root);
        let root = g.node(g.root).context("missing root node")?;
        ensure!(
            matches!(&root.kind, NodeKind::Pure(_)),
            "unexpected root node: {root:?}"
        );
        Ok(())
    }

    #[test]
    fn node_ids_are_stable_across_recompiles() -> anyhow::Result<()> {
        let prog = DoNode::op(op("effect://x")?).and_then(s("s"));
        let a = compile_do(&prog)?;
        let b = compile_do(&prog)?;
        ensure!(
            a.graph_hash == b.graph_hash,
            "graph hash changed: {:?} != {:?}",
            a.graph_hash,
            b.graph_hash
        );
        ensure!(
            a.nodes.len() == b.nodes.len(),
            "node length changed: {} != {}",
            a.nodes.len(),
            b.nodes.len()
        );
        for (na, nb) in a.nodes.iter().zip(&b.nodes) {
            ensure!(na.id == nb.id, "node id changed: {na:?} != {nb:?}");
            ensure!(na.kind == nb.kind, "node kind changed: {na:?} != {nb:?}");
        }
        Ok(())
    }

    #[test]
    fn and_then_emits_step_with_then_edge() -> anyhow::Result<()> {
        let g = compile_do(&DoNode::op(op("effect://x")?).and_then(s("s")))?;
        let first = g.node(NodeId::new(0)).context("missing first node")?;
        ensure!(
            matches!(&first.kind, NodeKind::Operation(_)),
            "unexpected first node: {first:?}"
        );
        let second = g.node(NodeId::new(1)).context("missing second node")?;
        ensure!(
            matches!(&second.kind, NodeKind::Step(_)),
            "unexpected second node: {second:?}"
        );
        ensure!(
            g.edges.iter().any(|e| e.from == NodeId::new(0)
                && e.to == NodeId::new(1)
                && e.kind == EdgeKind::Then),
            "missing Then edge: {:?}",
            g.edges
        );
        Ok(())
    }

    #[test]
    fn let_use_wires_use_edge() -> anyhow::Result<()> {
        let prog = DoNode::r#let("x", DoNode::pure(Value::integer(5)), DoNode::use_("x"));
        let g = compile_do(&prog)?;
        ensure!(
            g.edges.iter().any(|e| e.kind == EdgeKind::Use),
            "missing Use edge: {:?}",
            g.edges
        );
        Ok(())
    }

    #[test]
    fn unbound_use_is_rejected() -> anyhow::Result<()> {
        let err = match compile_do(&DoNode::use_("nope")) {
            Ok(graph) => bail!("expected unbound name error, got graph {graph:?}"),
            Err(error) => error,
        };
        ensure!(
            err == CompileError::UnboundName("nope".into()),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn both_join_has_two_arms() -> anyhow::Result<()> {
        let prog = DoNode::both(DoNode::op(op("effect://a")?), DoNode::op(op("effect://b")?));
        let g = compile_do(&prog)?;
        let join = g.root;
        let node = g.node(join).context("missing join node")?;
        ensure!(
            matches!(&node.kind, NodeKind::Join(JoinKind::Both)),
            "unexpected join node: {node:?}"
        );
        let arms = g.out_edges_of(join, EdgeKind::Arm).count();
        ensure!(arms == 2, "unexpected arm count: {arms}");
        Ok(())
    }
}
