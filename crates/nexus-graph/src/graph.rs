//! The single execution IR (§13.2): `ExecutionGraph` / `Node` / `NodeKind`.
//!
//! `NodeId == CausalPosition` (§6.1): assigned at compile time, stable while
//! the Program is unchanged, never derived from wall clock or randomness. It
//! is the anchor for concurrency-safe recovery and idempotent dedup.

use nexus_types::{Failure, MethodId, NodeId, OutputMode, Path, ProcessId, ResourceName, Value};
use serde::{Deserialize, Serialize};

/// A reference to a named step function on the owning Process (§13.3). Steps
/// are **pure** `Value -> Do<A>` continuations; they are named, not closures,
/// so the graph is serializable and cannot smuggle cross-identity code.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StepRef {
    /// Process that owns the named step. The executor rejects a `StepRef` whose
    /// process differs from the currently running Process (§13.3).
    pub process: ProcessId,
    /// Step name on `process`'s step table. Cross-process work is only possible
    /// via Operations on Resources (§13.3).
    pub name: String,
    /// Optional inline argument supplied at compile time, passed alongside the
    /// piped-in value (used by `for_each`-style helpers).
    #[serde(default)]
    pub arg: Option<Value>,
}

impl StepRef {
    pub fn new(process: ProcessId, name: impl Into<String>) -> Self {
        Self {
            process,
            name: name.into(),
            arg: None,
        }
    }
    pub fn with_arg(mut self, v: Value) -> Self {
        self.arg = Some(v);
        self
    }
}

/// Template for the single side-effecting node kind (§13.2). At compile time we
/// know the target Resource (by name → resolved to a Handle at open) and the
/// method; the concrete input is bound from the upstream value when the
/// Executor reaches the node.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OperationTemplate {
    /// Resource the operation targets (control-plane name; the Executor maps
    /// it to an owned Handle).
    pub target: ResourceName,
    /// Method name within the target's interface.
    pub method: String,
    /// Numeric method id, filled when the graph is linked against a resolved
    /// interface; `None` until then.
    #[serde(default)]
    pub method_id: Option<MethodId>,
    /// Requested output mode (§4.3).
    #[serde(default)]
    pub output: OutputMode,
    /// A literal input fixed at compile time. When `None`, the node's input is
    /// the value flowing in along its incoming edge.
    #[serde(default)]
    pub literal_input: Option<Value>,
}

/// What a [`NodeKind::Branch`] does.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchKind {
    /// `OrElse` compensation: on failure of the guarded subgraph, route into
    /// the recovery step (carrying the failure as input).
    OrElse { recover: StepRef },
}

/// What a [`NodeKind::Join`] does (§13.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinKind {
    /// Both branches must complete; result is the pair (async I/O overlap,
    /// not CPU parallelism — §13.4).
    Both,
    /// First branch to complete wins; the other is cancelled.
    Race,
}

/// What a [`NodeKind::Wait`] waits for (§13.2).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitSpec {
    /// Wait until a signal is written to this path.
    Signal(Path),
    /// Wait until a wall-clock deadline (millis since epoch).
    Deadline(i64),
}

/// One node in the execution graph (§13.2). `Operation` is the only
/// side-effecting kind. `Fail` is the failure-dual of `Pure` (§13.3): an
/// immediate node that yields a failure outcome rather than a value — kept as
/// its own kind so the `Failure` is carried losslessly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    /// Produce a value immediately.
    Pure(Value),
    /// Produce a failure immediately (failure-dual of `Pure`; the Executor
    /// propagates it along the edges to the nearest enclosing `Branch`).
    Fail(Failure),
    /// Issue one Operation (the only side-effect node).
    Operation(OperationTemplate),
    /// A pure continuation: consume the upstream value, produce a subgraph
    /// (spliced in at run time — this is `AndThen` on the graph).
    Step(StepRef),
    /// Failure compensation / conditional.
    Branch(BranchKind),
    /// Both (all complete) / Race (take first).
    Join(JoinKind),
    /// Block-level identity switch (`act-as`, §13.2). Carries the identity
    /// `Path`; the kernel interns it to an `IdentityRef` when binding the
    /// node's child Operations (the hot `Operation` struct carries the ref).
    Acting(Path),
    /// Wait for a signal / deadline.
    Wait(WaitSpec),
}

impl NodeKind {
    /// Whether this node can produce an external side effect (only
    /// `Operation` does). Used by the recorder to decide Fact necessity.
    pub fn is_side_effecting(&self) -> bool {
        matches!(self, NodeKind::Operation(_))
    }
}

/// A graph node, identified by its stable [`NodeId`] (= `CausalPosition`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub kind: NodeKind,
}

/// The semantic role of an edge between two nodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Normal value flow: `from`'s output is `to`'s input.
    Value,
    /// `to` is the success continuation of `from`.
    Then,
    /// `to` is the failure path from a `Branch` node.
    Else,
    /// `to` is one parallel arm of a `Join` (`from` is the join node's source).
    Arm,
    /// A `Use(id)` data dependency back to a `Let`-bound node (DAG edge).
    Use,
}

/// A directed edge between two nodes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub kind: EdgeKind,
}

/// The single execution IR (§13.2). All Program formats compile to this; the
/// Executor only advances a cursor over it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    /// The entry node (where execution / recovery begins).
    pub root: NodeId,
    /// Content hash over the structure; the Process binds to this and recovery
    /// re-binds the same product (§10.4).
    pub graph_hash: [u8; 32],
}

impl ExecutionGraph {
    /// Look up a node by its id.
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        // Nodes are pushed in id order during compilation, so index directly
        // when possible, falling back to a scan.
        let idx = id.get() as usize;
        if idx < self.nodes.len() && self.nodes[idx].id == id {
            Some(&self.nodes[idx])
        } else {
            self.nodes.iter().find(|n| n.id == id)
        }
    }

    /// All edges leaving `from`.
    pub fn out_edges(&self, from: NodeId) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |e| e.from == from)
    }

    /// All edges of a given kind leaving `from`.
    pub fn out_edges_of(&self, from: NodeId, kind: EdgeKind) -> impl Iterator<Item = &Edge> {
        self.edges
            .iter()
            .filter(move |e| e.from == from && e.kind == kind)
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Whether node `id`'s output is consumed by any other node (§9.2): it has
    /// an outgoing `Then` (continuation), `Use` (data dependency), or feeds a
    /// `Join`/`Branch` arm result. An unconsumed pure-deterministic read need
    /// not record a Fact — recovery can safely recompute it. This is the
    /// compile-time data-flow signal the record-discipline uses, computed off
    /// the graph (never on the hot path).
    pub fn output_is_consumed(&self, id: NodeId) -> bool {
        self.edges
            .iter()
            .any(|e| e.from == id && matches!(e.kind, EdgeKind::Then | EdgeKind::Use))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(name: &str) -> StepRef {
        StepRef::new(ProcessId::new(1), name)
    }

    #[test]
    fn node_lookup_by_id() {
        let g = ExecutionGraph {
            nodes: vec![
                Node {
                    id: NodeId::new(0),
                    kind: NodeKind::Pure(Value::Int(1)),
                },
                Node {
                    id: NodeId::new(1),
                    kind: NodeKind::Step(s("s")),
                },
            ],
            edges: vec![Edge {
                from: NodeId::new(0),
                to: NodeId::new(1),
                kind: EdgeKind::Then,
            }],
            root: NodeId::new(0),
            graph_hash: [0u8; 32],
        };
        assert!(matches!(
            g.node(NodeId::new(0)).unwrap().kind,
            NodeKind::Pure(_)
        ));
        assert!(matches!(
            g.node(NodeId::new(1)).unwrap().kind,
            NodeKind::Step(_)
        ));
        assert!(g.node(NodeId::new(2)).is_none());
        assert_eq!(g.out_edges(NodeId::new(0)).count(), 1);
    }

    #[test]
    fn only_operation_is_side_effecting() {
        assert!(
            NodeKind::Operation(OperationTemplate {
                target: ResourceName::new(Path::parse("effect://x/post").unwrap()),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: None,
            })
            .is_side_effecting()
        );
        assert!(!NodeKind::Pure(Value::Null).is_side_effecting());
        assert!(!NodeKind::Step(s("s")).is_side_effecting());
    }
}
