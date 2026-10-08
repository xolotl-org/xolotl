//! Do→Graph compiler: lower a [`DoNode`] AST into one
//! [`ExecutionGraph`].
//!
//! The compiler's contract is **stable, deterministic [`NodeId`]s**: the same
//! `DoNode` always compiles to the same node ids, assigned in a fixed
//! structural traversal (continuation Steps follow their source subtree), never
//! depending on wall clock or randomness. These are
//! source positions; execution scopes and dynamic request tickets distinguish
//! independent evaluations and repeated visits to a node.
//!
//! Compilation rules:
//!
//! ```text
//! Pure(a)                Node::Pure
//! AndThen(d, s)          d's subgraph → Then-edge → Node::Step(s)
//! OrElse(d, s)           d's subgraph → Node::Branch(OrElse{recover:s})
//! Finally(body, cleanup) two arms → Node::Finally
//! Race(a, b)             a,b subgraphs → Node::Join(Race)
//! Both(a, b)             a,b subgraphs → Node::Join(Both)
//! Let(id, v, body)       lexical Let with value and body arms
//! Use(id)                Load from the enclosing lexical slot
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
use xolotl_types::NodeId;

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

/// Admit the entire source before graph allocation or payload cloning.
/// Each native AST node emits exactly one graph node.
pub(crate) fn preflight(program: &DoNode, base: u32) -> Result<usize, CompileError> {
    let mut count = 0usize;
    let mut pending = alloc::vec![program];
    while let Some(node) = pending.pop() {
        if count == MAX_NODES {
            return Err(CompileError::TooLarge { max: MAX_NODES });
        }
        base.checked_add(count as u32)
            .ok_or(CompileError::PositionExhausted)?;
        count += 1;
        match node {
            DoNode::AndThen { d: child, .. }
            | DoNode::OrElse { d: child, .. }
            | DoNode::Acting { body: child, .. } => pending.push(child),
            DoNode::Finally { body, cleanup } => {
                pending.push(cleanup);
                pending.push(body);
            }
            DoNode::Let { value, body, .. } => {
                pending.push(body);
                pending.push(value);
            }
            DoNode::Both(left, right) | DoNode::Race(left, right) => {
                pending.push(right);
                pending.push(left);
            }
            DoNode::Pure(_)
            | DoNode::Use(_)
            | DoNode::Fail(_)
            | DoNode::Wait(_)
            | DoNode::Op(_) => {}
        }
    }
    Ok(count)
}

struct Compiler<'a> {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    /// Names resolved to currently live lexical slots.
    bindings: BTreeMap<&'a str, Option<u32>>,
    next_binding: u32,
    free_bindings: Vec<u32>,
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

impl<'a> Compiler<'a> {
    fn new(nodes: usize) -> Self {
        Self::with_base(0, nodes)
    }

    fn with_base(base: u32, nodes: usize) -> Self {
        Self {
            nodes: Vec::with_capacity(nodes),
            edges: Vec::with_capacity(nodes.saturating_sub(1)),
            bindings: BTreeMap::new(),
            next_binding: 0,
            free_bindings: Vec::new(),
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

    fn lower(&mut self, program: &'a DoNode) -> Result<Span, CompileError> {
        enum Frame<'node> {
            Enter(&'node DoNode),
            Then(&'node crate::graph::StepRef),
            Arm(NodeId),
            NextArm {
                parent: NodeId,
                right: &'node DoNode,
            },
            Arms {
                parent: NodeId,
                left: Span,
            },
            BindingValue {
                index: usize,
                name: &'node str,
                body: &'node DoNode,
            },
            BindingBody {
                index: usize,
                name: &'node str,
                previous: Option<Option<u32>>,
                value: Span,
            },
        }
        let mut pending = alloc::vec![Frame::Enter(program)];
        let mut output = Span {
            entry: NodeId::new(0),
            exit: NodeId::new(0),
        };
        while let Some(frame) = pending.pop() {
            match frame {
                Frame::Enter(node) => {
                    let kind = match node {
                        DoNode::Pure(value) => NodeKind::Pure(value.clone()),
                        DoNode::Fail(failure) => NodeKind::Fail(failure.clone()),
                        DoNode::Op(template) => NodeKind::Operation(template.clone()),
                        DoNode::Wait(spec) => NodeKind::Wait(spec.clone()),
                        DoNode::Use(name) => {
                            let binding = self
                                .bindings
                                .get_mut(name.as_str())
                                .ok_or_else(|| CompileError::UnboundName(name.clone()))?;
                            let slot = *binding.get_or_insert_with(|| {
                                self.free_bindings.pop().unwrap_or_else(|| {
                                    let slot = self.next_binding;
                                    self.next_binding += 1;
                                    slot
                                })
                            });
                            NodeKind::Load { slot }
                        }
                        DoNode::AndThen { d: child, then } => {
                            pending.push(Frame::Then(then));
                            pending.push(Frame::Enter(child));
                            continue;
                        }
                        DoNode::OrElse { d: child, or } => {
                            let parent = self.push(NodeKind::Branch(BranchKind::OrElse {
                                recover: or.clone(),
                            }))?;
                            pending.push(Frame::Arm(parent));
                            pending.push(Frame::Enter(child));
                            continue;
                        }
                        DoNode::Acting { identity, body } => {
                            let parent = self.push(NodeKind::Acting(identity.clone()))?;
                            pending.push(Frame::Arm(parent));
                            pending.push(Frame::Enter(body));
                            continue;
                        }
                        DoNode::Finally {
                            body: left,
                            cleanup: right,
                        }
                        | DoNode::Both(left, right)
                        | DoNode::Race(left, right) => {
                            let kind = match node {
                                DoNode::Finally { .. } => NodeKind::Finally,
                                DoNode::Both(..) => NodeKind::Join(JoinKind::Both),
                                _ => NodeKind::Join(JoinKind::Race),
                            };
                            let parent = self.push(kind)?;
                            pending.push(Frame::NextArm { parent, right });
                            pending.push(Frame::Enter(left));
                            continue;
                        }
                        DoNode::Let { name, value, body } => {
                            let index = self.nodes.len();
                            self.push(NodeKind::Sequence)?;
                            pending.push(Frame::BindingValue { index, name, body });
                            pending.push(Frame::Enter(value));
                            continue;
                        }
                    };
                    let id = self.push(kind)?;
                    output = Span {
                        entry: id,
                        exit: id,
                    };
                }
                Frame::Then(reference) => {
                    let step = self.push(NodeKind::Step(reference.clone()))?;
                    self.edge(output.exit, step, EdgeKind::Then);
                    output.exit = step;
                }
                Frame::Arm(parent) => {
                    self.edge(parent, output.entry, EdgeKind::Arm);
                    output = Span {
                        entry: parent,
                        exit: parent,
                    };
                }
                Frame::NextArm { parent, right } => {
                    pending.push(Frame::Arms {
                        parent,
                        left: output,
                    });
                    pending.push(Frame::Enter(right));
                }
                Frame::Arms { parent, left } => {
                    self.edge(parent, left.entry, EdgeKind::Arm);
                    self.edge(parent, output.entry, EdgeKind::Arm);
                    output = Span {
                        entry: parent,
                        exit: parent,
                    };
                }
                Frame::BindingValue { index, name, body } => {
                    let previous = self.bindings.insert(name, None);
                    pending.push(Frame::BindingBody {
                        index,
                        name,
                        previous,
                        value: output,
                    });
                    pending.push(Frame::Enter(body));
                }
                Frame::BindingBody {
                    index,
                    name,
                    previous,
                    value,
                } => {
                    if let Some(Some(slot)) = self.bindings.remove(name) {
                        self.nodes[index].kind = NodeKind::Let { slot };
                        self.free_bindings.push(slot);
                    }
                    if let Some(previous) = previous {
                        self.bindings.insert(name, previous);
                    }
                    let parent = self.nodes[index].id;
                    self.edge(parent, value.entry, EdgeKind::Arm);
                    self.edge(parent, output.entry, EdgeKind::Arm);
                    output = Span {
                        entry: parent,
                        exit: parent,
                    };
                }
            }
        }
        Ok(output)
    }
}

/// Compile a [`DoNode`] program into one [`ExecutionGraph`] with stable node
/// ids and a content hash.
///
/// Admission counts every source node before copying payloads: at most 2^20
/// nodes, each charged as one graph node. Lowering uses explicit traversal
/// frames, not the native call stack; nesting has no independent limit.
/// Transient frames and lexical slots are released when compilation returns.
pub fn compile_do(program: &DoNode) -> Result<ExecutionGraph, CompileError> {
    let nodes = preflight(program, 0)?;
    let mut c = Compiler::new(nodes);
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
/// Node and source-position bounds are preflighted before copying payloads.
/// The returned graph's `graph_hash` is left zeroed: native fragments are linked
/// only for this execution and cannot be encoded as portable program source.
pub fn compile_do_at(program: &DoNode, base: u32) -> Result<ExecutionGraph, CompileError> {
    let nodes = preflight(program, base)?;
    let mut c = Compiler::with_base(base, nodes);
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
    use xolotl_types::{OutputMode, Path, ResourceName, Value};

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

    #[test]
    fn frames_preserve_node_edge_order_and_shadowed_slots() -> anyhow::Result<()> {
        let program = DoNode::r#let(
            "x",
            DoNode::pure(1),
            DoNode::both(
                DoNode::r#let("x", DoNode::use_("x"), DoNode::use_("x")),
                DoNode::acting(Path::parse("identity://test/inner")?, DoNode::use_("x"))
                    .or_else(s("recover")),
            ),
        )
        .and_then(s("next"));
        let graph = compile_do(&program)?;
        let expected = [
            NodeKind::Let { slot: 0 },
            NodeKind::Pure(Value::integer(1)),
            NodeKind::Join(JoinKind::Both),
            NodeKind::Let { slot: 1 },
            NodeKind::Load { slot: 0 },
            NodeKind::Load { slot: 1 },
            NodeKind::Branch(BranchKind::OrElse {
                recover: s("recover"),
            }),
            NodeKind::Acting(Path::parse("identity://test/inner")?),
            NodeKind::Load { slot: 0 },
            NodeKind::Step(s("next")),
        ];
        for (index, (node, kind)) in graph.nodes.iter().zip(&expected).enumerate() {
            ensure!(node.id == NodeId::new(index as u32));
            ensure!(&node.kind == kind);
        }
        ensure!(graph.nodes.len() == expected.len());
        let expected_edges = [
            (3, 4, EdgeKind::Arm),
            (3, 5, EdgeKind::Arm),
            (7, 8, EdgeKind::Arm),
            (6, 7, EdgeKind::Arm),
            (2, 3, EdgeKind::Arm),
            (2, 6, EdgeKind::Arm),
            (0, 1, EdgeKind::Arm),
            (0, 2, EdgeKind::Arm),
            (0, 9, EdgeKind::Then),
        ];
        ensure!(graph.edges.len() == expected_edges.len());
        for (edge, (from, to, kind)) in graph.edges.iter().zip(expected_edges) {
            ensure!(edge.from == NodeId::new(from));
            ensure!(edge.to == NodeId::new(to));
            ensure!(edge.kind == kind);
        }
        let offset = compile_do_at(&program, 100)?;
        for (node, shifted) in graph.nodes.iter().zip(&offset.nodes) {
            ensure!(shifted.id.get() == node.id.get() + 100);
            ensure!(shifted.kind == node.kind);
        }
        ensure!(compile_do(&program)?.graph_hash == graph.graph_hash);
        Ok(())
    }

    #[test]
    fn deep_native_tree_compiles_and_clones_on_small_stack() -> anyhow::Result<()> {
        std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(|| {
                let mut program = DoNode::pure(Value::null());
                for _ in 0..10_000 {
                    program = program.and_then(s("next"));
                }
                let cloned = program.clone();
                let graph = compile_do(&cloned)?;
                ensure!(graph.nodes.len() == 10_001);
                ensure!(graph.edges.len() == 10_000);
                ensure!(graph.root == NodeId::new(0));
                ensure!(compile_do_at(&program, 17)?.nodes[10_000].id == NodeId::new(10_017));
                ensure!(graph.graph_hash == compile_do(&program)?.graph_hash);
                Ok::<_, anyhow::Error>(())
            })?
            .join()
            .map_err(|_panic| anyhow!("small-stack compiler panicked"))??;
        Ok(())
    }

    #[test]
    fn node_preflight_rejects_before_lexical_lowering() -> anyhow::Result<()> {
        let mut program = DoNode::use_("unbound");
        for _ in 1..MAX_NODES {
            program = program.and_then(s(""));
        }
        ensure!(preflight(&program, 0)? == MAX_NODES);
        program = program.and_then(s(""));
        ensure!(matches!(
            compile_do(&program),
            Err(CompileError::TooLarge { max: MAX_NODES })
        ));
        ensure!(matches!(
            compile_do_at(&program, 0),
            Err(CompileError::TooLarge { max: MAX_NODES })
        ));
        ensure!(matches!(
            compile_do_at(&program, u32::MAX),
            Err(CompileError::PositionExhausted)
        ));
        let actor = crate::ActorSpec {
            finalizers: alloc::vec![program],
            ..crate::ActorSpec::default()
        };
        ensure!(matches!(
            actor.bind_process_local_refs(xolotl_types::ProcessId::new(1)),
            Err(crate::ActorBindError::Compile(CompileError::TooLarge {
                max: MAX_NODES
            }))
        ));
        Ok(())
    }

    #[test]
    fn frames_preserve_lexical_visibility_and_first_failure() -> anyhow::Result<()> {
        for program in [
            DoNode::both(DoNode::use_("first"), DoNode::use_("second")),
            DoNode::race(DoNode::use_("first"), DoNode::use_("second")),
            DoNode::use_("first").finally(DoNode::use_("second")),
            DoNode::r#let("first", DoNode::use_("first"), DoNode::use_("second")),
        ] {
            ensure!(
                matches!(compile_do(&program), Err(CompileError::UnboundName(name)) if name == "first")
            );
        }
        let siblings = DoNode::both(
            DoNode::r#let("local", DoNode::pure(1), DoNode::use_("local")),
            DoNode::use_("local"),
        );
        ensure!(
            matches!(compile_do(&siblings), Err(CompileError::UnboundName(name)) if name == "local")
        );
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
    fn let_use_preserves_lexical_arms_and_slot() -> anyhow::Result<()> {
        let prog = DoNode::r#let("x", DoNode::pure(Value::integer(5)), DoNode::use_("x"));
        let g = compile_do(&prog)?;
        ensure!(matches!(
            g.node(g.root).context("binding root")?.kind,
            NodeKind::Let { slot: 0 }
        ));
        ensure!(g.out_edges_of(g.root, EdgeKind::Arm).count() == 2);
        ensure!(
            g.nodes
                .iter()
                .any(|node| matches!(node.kind, NodeKind::Load { slot: 0 }))
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

    #[test]
    fn finally_has_body_and_cleanup_arms() -> anyhow::Result<()> {
        let program = DoNode::pure(1).finally(DoNode::pure(2));
        let graph = compile_do(&program)?;
        let root = graph.node(graph.root).context("missing finally node")?;
        ensure!(matches!(&root.kind, NodeKind::Finally));
        ensure!(graph.out_edges_of(graph.root, EdgeKind::Arm).count() == 2);
        ensure!(graph.graph_hash != compile_do(&DoNode::pure(1))?.graph_hash);
        Ok(())
    }
}
