//! `GraphCursor` — where execution / recovery is positioned in an
//! [`ExecutionGraph`](crate::graph::ExecutionGraph).
//!
//! The Executor advances the cursor; `Step` nodes splice their produced
//! subgraph in at the cursor (the run-time face of `AndThen`). Serialized
//! cursors and done sets are keyed by [`NodeId`], never by wall clock, so a
//! recovered run can align work to stable graph positions.

use andrias_types::{NodeId, Value};
use serde::{Deserialize, Serialize};

/// One entry on the cursor's continuation stack: a node still to be visited,
/// plus the value flowing into it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    /// Node to execute when this frame is popped.
    pub node: NodeId,
    /// The value to feed this node (the upstream result). `Null` at the root.
    pub input: Value,
}

impl Frame {
    /// Create a frame for `node` with its input value.
    pub fn new(node: NodeId, input: Value) -> Self {
        Self { node, input }
    }
}

/// Position of execution within a graph. Serializable so it can be snapshotted
/// and restored on recovery. The `pending` stack holds the not-yet-run
/// continuations; `done` records nodes whose outcome is already recorded (so
/// replay skips them).
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

    /// Mark a node's outcome durably recorded.
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
    use anyhow::{Context, ensure};

    #[test]
    fn cursor_lifo_order() -> anyhow::Result<()> {
        let mut c = GraphCursor::at_root(NodeId::new(0));
        c.push(Frame::new(NodeId::new(1), Value::Int(1)));
        c.push(Frame::new(NodeId::new(2), Value::Int(2)));
        ensure!(
            c.pop().context("missing first frame")?.node == NodeId::new(2),
            "unexpected first frame"
        );
        ensure!(
            c.pop().context("missing second frame")?.node == NodeId::new(1),
            "unexpected second frame"
        );
        ensure!(
            c.pop().context("missing root frame")?.node == NodeId::new(0),
            "unexpected root frame"
        );
        ensure!(c.is_finished(), "cursor should be finished");
        Ok(())
    }

    #[test]
    fn done_set_dedups_and_aligns_by_node_id() -> anyhow::Result<()> {
        let mut c = GraphCursor::at_root(NodeId::new(0));
        c.mark_done(NodeId::new(5));
        c.mark_done(NodeId::new(5));
        ensure!(
            c.done.len() == 1,
            "unexpected done length: {}",
            c.done.len()
        );
        ensure!(c.is_done(NodeId::new(5)), "node 5 should be done");
        ensure!(!c.is_done(NodeId::new(6)), "node 6 should not be done");
        Ok(())
    }

    #[test]
    fn cursor_serde_roundtrip_for_snapshot() -> anyhow::Result<()> {
        let mut c = GraphCursor::at_root(NodeId::new(0));
        c.mark_done(NodeId::new(0));
        c.push(Frame::new(NodeId::new(1), Value::Str("x".into())));
        let s = serde_json::to_string(&c)?;
        let back: GraphCursor = serde_json::from_str(&s)?;
        ensure!(c == back, "round trip changed cursor: {back:?}");
        Ok(())
    }
}
