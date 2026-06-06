//! The step table: named, pure `Value -> Do<A>` continuations (§13.3).
//!
//! Steps are **not** closures. A [`StepRef`](nexus_graph::StepRef) names a step
//! registered on a Process; the executor looks it up and calls it with the
//! piped-in value to produce a subgraph, which is spliced at the cursor (the
//! run-time face of `AndThen`, §13.4). Named-not-closure keeps the graph
//! serializable and blocks cross-identity code injection.

use nexus_graph::DoNode;
use nexus_types::{ProcessId, Value};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// A step function: pure, total, `(piped_value, optional_arg) -> Do<A>`. It
/// must not perform IO — time / randomness / effects go through Operation
/// nodes so the compiled `NodeId`s stay stable (§13.3).
pub type StepFn = Arc<dyn Fn(Value, Option<Value>) -> DoNode + Send + Sync>;

/// Per-process registry of named steps. Keyed by `(process, name)`.
#[derive(Clone, Default)]
pub struct StepTable {
    inner: Arc<RwLock<HashMap<(ProcessId, String), StepFn>>>,
}

impl StepTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a step on a process.
    pub fn install<F>(&self, process: ProcessId, name: impl Into<String>, f: F)
    where
        F: Fn(Value, Option<Value>) -> DoNode + Send + Sync + 'static,
    {
        self.inner
            .write()
            .insert((process, name.into()), Arc::new(f));
    }

    /// Look up a step on a process.
    pub fn get(&self, process: ProcessId, name: &str) -> Option<StepFn> {
        self.inner.read().get(&(process, name.to_string())).cloned()
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_and_invoke_step() {
        let t = StepTable::new();
        let pid = ProcessId::new(1);
        t.install(pid, "double", |v, _| match v {
            Value::Int(i) => DoNode::pure(Value::Int(i * 2)),
            _ => DoNode::pure(Value::Null),
        });
        let f = t.get(pid, "double").unwrap();
        assert_eq!(f(Value::Int(21), None), DoNode::pure(Value::Int(42)));
        // Step is process-scoped: another process doesn't see it.
        assert!(t.get(ProcessId::new(2), "double").is_none());
    }
}
