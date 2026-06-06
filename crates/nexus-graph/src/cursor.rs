//! `GraphCursor` — where execution / recovery is positioned in an
//! [`ExecutionGraph`](crate::graph::ExecutionGraph) (§13.4 / §15.2).
//!
//! The Executor advances the cursor; `Step` nodes splice their produced
//! subgraph in at the cursor (the run-time face of `AndThen`). On recovery the
//! cursor is realigned by [`NodeId`] (§6.1 / §13.2) — never by wall clock — so
//! concurrent branches re-converge deterministically.

use nexus_types::{NodeId, Value};
use serde::{Deserialize, Serialize};

/// One entry on the cursor's continuation stack: a node still to be visited,
/// plus the value flowing into it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    pub node: NodeId,
    /// The value to feed this node (the upstream result). `Null` at the root.
    pub input: Value,
}

impl Frame {
    pub fn new(node: NodeId, input: Value) -> Self {
        Self { node, input }
    }
}

/// Position of execution within a graph. Serializable so it can be snapshotted
/// and restored on recovery (§15.2). The `pending` stack holds the not-yet-run
/// continuations; `done` records nodes whose outcome is already recorded (so
/// replay skips them, §15.1).
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GraphCursor {
    /// Continuation stack (LIFO): the next node to run is the top.
    pub pending: Vec<Frame>,
    /// Nodes whose outcome is durably recorded; replay advances past them.
    pub done: Vec<NodeId>,
}

impl GraphCursor {
    /// A fresh cursor positioned at `root` with a unit input.
    pub fn at_root(root: NodeId) -> Self {
        Self {
            pending: vec![Frame::new(root, Value::Null)],
            done: Vec::new(),
        }
    }

    /// Peek the next node to run, if any.
    pub fn peek(&self) -> Option<&Frame> {
        self.pending.last()
    }

    /// Pop the next frame to run.
    pub fn pop(&mut self) -> Option<Frame> {
        self.pending.pop()
    }

    /// Push a continuation frame.
    pub fn push(&mut self, frame: Frame) {
        self.pending.push(frame);
    }

    /// Mark a node's outcome durably recorded (replay will skip it, §15.1).
    pub fn mark_done(&mut self, node: NodeId) {
        if !self.done.contains(&node) {
            self.done.push(node);
        }
    }

    /// Whether `node`'s outcome is already recorded.
    pub fn is_done(&self, node: NodeId) -> bool {
        self.done.contains(&node)
    }

    /// Whether execution is complete (nothing left to run).
    pub fn is_finished(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_lifo_order() {
        let mut c = GraphCursor::at_root(NodeId::new(0));
        c.push(Frame::new(NodeId::new(1), Value::Int(1)));
        c.push(Frame::new(NodeId::new(2), Value::Int(2)));
        assert_eq!(c.pop().unwrap().node, NodeId::new(2));
        assert_eq!(c.pop().unwrap().node, NodeId::new(1));
        assert_eq!(c.pop().unwrap().node, NodeId::new(0));
        assert!(c.is_finished());
    }

    #[test]
    fn done_set_dedups_and_aligns_by_node_id() {
        let mut c = GraphCursor::at_root(NodeId::new(0));
        c.mark_done(NodeId::new(5));
        c.mark_done(NodeId::new(5));
        assert_eq!(c.done.len(), 1);
        assert!(c.is_done(NodeId::new(5)));
        assert!(!c.is_done(NodeId::new(6)));
    }

    #[test]
    fn cursor_serde_roundtrip_for_snapshot() {
        let mut c = GraphCursor::at_root(NodeId::new(0));
        c.mark_done(NodeId::new(0));
        c.push(Frame::new(NodeId::new(1), Value::Str("x".into())));
        let s = serde_json::to_string(&c).unwrap();
        let back: GraphCursor = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }
}
