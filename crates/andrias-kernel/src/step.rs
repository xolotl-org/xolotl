//! The step table: named, pure `Value -> Do<A>` continuations.
//!
//! A [`StepRef`](andrias_graph::StepRef) names a step registered on a Process;
//! the executor looks it up and calls it with the piped-in value to produce a
//! subgraph, which is spliced at the cursor (the run-time face of `AndThen`).
//! Named steps keep the graph serializable and block cross-identity code
//! injection.

use andrias_graph::DoNode;
use andrias_types::{ProcessId, Value};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// A step function: pure, total, `(piped_value, optional_arg) -> Do<A>`. It
/// must not perform IO — time / randomness / effects go through Operation
/// nodes so the compiled `NodeId`s stay stable.
pub type StepFn = Arc<dyn Fn(Value, Option<Value>) -> DoNode + Send + Sync>;

/// Error returned when registering a process-local step.
#[derive(Debug, Error)]
pub enum StepInstallError {
    /// A step with the same process and name is already installed.
    #[error("step {name:?} is already installed on process {process}")]
    Duplicate {
        /// Process that owns the step namespace.
        process: ProcessId,
        /// Step name that already exists.
        name: String,
    },
}

/// Per-process registry of named steps. Keyed by `(process, name)`.
#[derive(Clone, Default)]
pub(crate) struct StepTable {
    inner: Arc<RwLock<HashMap<(ProcessId, String), StepFn>>>,
}

impl StepTable {
    /// Create an empty step table.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Register a step on a process.
    #[cfg(test)]
    pub(crate) fn install<F>(
        &self,
        process: ProcessId,
        name: impl Into<String>,
        f: F,
    ) -> Result<(), StepInstallError>
    where
        F: Fn(Value, Option<Value>) -> DoNode + Send + Sync + 'static,
    {
        self.install_step_fn(process, name, Arc::new(f))
    }

    /// Register an already shared step function on a process.
    pub(crate) fn install_step_fn(
        &self,
        process: ProcessId,
        name: impl Into<String>,
        f: StepFn,
    ) -> Result<(), StepInstallError> {
        let name = name.into();
        let key = (process, name.clone());
        let mut inner = self.inner.write();
        if inner.contains_key(&key) {
            return Err(StepInstallError::Duplicate { process, name });
        }
        inner.insert(key, f);
        Ok(())
    }

    /// Look up a step on a process.
    pub(crate) fn get(&self, process: ProcessId, name: &str) -> Option<StepFn> {
        self.inner.read().get(&(process, name.to_string())).cloned()
    }

    /// Remove every step registered on `process`.
    pub(crate) fn remove_process(&self, process: ProcessId) -> usize {
        let mut inner = self.inner.write();
        let before = inner.len();
        inner.retain(|(owner, _), _| *owner != process);
        before.saturating_sub(inner.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

    #[test]
    fn install_and_invoke_step() -> anyhow::Result<()> {
        let t = StepTable::new();
        let pid = ProcessId::new(1);
        t.install(pid, "double", |v, _| match v {
            Value::Int(i) => DoNode::pure(Value::Int(i * 2)),
            _ => DoNode::pure(Value::Null),
        })?;
        let f = t.get(pid, "double").context("missing installed step")?;
        ensure!(
            f(Value::Int(21), None) == DoNode::pure(Value::Int(42)),
            "step output mismatch"
        );
        // Step is process-scoped: another process doesn't see it.
        ensure!(
            t.get(ProcessId::new(2), "double").is_none(),
            "step leaked across process scope"
        );
        Ok(())
    }

    #[test]
    fn duplicate_step_registration_fails() -> anyhow::Result<()> {
        let t = StepTable::new();
        let pid = ProcessId::new(1);
        t.install(pid, "double", |v, _| DoNode::pure(v))?;
        let err = t
            .install(pid, "double", |v, _| DoNode::pure(v))
            .err()
            .context("duplicate step registration should fail")?;
        ensure!(
            matches!(err, StepInstallError::Duplicate { .. }),
            "unexpected duplicate error: {err:?}"
        );
        Ok(())
    }
}
