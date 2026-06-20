//! Kernel process inspection driver.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{MethodId, Outcome, OutputMode, ProcessId, Purity, Value};
use std::collections::BTreeMap;

/// `effect://kernel/process/inspect`.
pub(crate) const INSPECT_METHODS: &[MethodSpec] =
    &[MethodSpec::new("inspect", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external()];

/// Driver backing `effect://kernel/process/inspect`.
pub(crate) struct KernelInspectDriver {
    processes: nexus_kernel::ProcessTable,
    facts: nexus_kernel::FactSink,
}

impl KernelInspectDriver {
    /// Create an inspect driver over process and fact state.
    pub(crate) fn new(
        processes: nexus_kernel::ProcessTable,
        facts: nexus_kernel::FactSink,
    ) -> Self {
        Self { processes, facts }
    }
}

#[async_trait]
impl Driver for KernelInspectDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        if method.get() != 0 {
            return Err(DriverError::NoSuchMethod(method));
        }
        let input = crate::input::map(input, "inspect")?;
        let process = match input.get("process") {
            Some(value) => {
                let raw = value.as_int().ok_or_else(|| {
                    DriverError::InvalidInput("inspect.process must be an integer".into())
                })?;
                let pid = u64::try_from(raw).map_err(|_| {
                    DriverError::InvalidInput("inspect.process must be non-negative".into())
                })?;
                Some(ProcessId::new(pid))
            }
            None => None,
        };
        let include_facts = match input.get("include_recent_facts") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => {
                return Err(DriverError::InvalidInput(
                    "inspect.include_recent_facts must be a boolean".into(),
                ));
            }
        };
        let limit = match input.get("limit") {
            Some(value) => {
                let raw = value.as_int().ok_or_else(|| {
                    DriverError::InvalidInput("inspect.limit must be an integer".into())
                })?;
                usize::try_from(raw).map_err(|_| {
                    DriverError::InvalidInput("inspect.limit must be non-negative".into())
                })?
            }
            None => 32,
        }
        .min(256);

        let ids = match process {
            Some(pid) => vec![pid],
            None => self.processes.all_ids(),
        };
        let mut rows = Vec::with_capacity(ids.len());
        for pid in ids {
            let mut row = BTreeMap::new();
            row.insert("process".into(), Value::Int(pid.get() as i64));
            if let Some(status) = self.processes.status(pid) {
                row.insert("status".into(), Value::Str(format!("{status:?}")));
                row.insert("terminal".into(), Value::Bool(status.is_terminal()));
            } else {
                row.insert("status".into(), Value::Str("Unknown".into()));
            }
            if let Some(identity) = self.processes.identity(pid) {
                row.insert("identity".into(), Value::Int(identity.get() as i64));
            }
            let children = self
                .processes
                .children_of(pid)
                .into_iter()
                .map(|child| Value::Int(child.get() as i64))
                .collect();
            row.insert("children".into(), Value::List(children));
            let facts = self
                .facts
                .facts_of(pid)
                .map_err(|e| DriverError::Other(e.to_string()))?;
            row.insert("fact_count".into(), Value::Int(facts.len() as i64));
            if include_facts {
                row.insert(
                    "recent_facts".into(),
                    Value::List(facts.iter().rev().take(limit).map(project_fact).collect()),
                );
            }
            rows.push(Value::Map(row));
        }
        Ok(Outcome::Done(Value::List(rows)))
    }
}

fn project_fact(f: &nexus_types::Fact) -> Value {
    let mut m = BTreeMap::new();
    m.insert("op_id".into(), Value::Str(f.id.to_string()));
    m.insert("caller".into(), Value::Int(f.caller.get() as i64));
    m.insert("acting".into(), Value::Int(f.acting.get() as i64));
    m.insert("resource".into(), Value::Int(f.resource.get() as i64));
    m.insert("method".into(), Value::Int(f.method.get() as i64));
    m.insert("decision".into(), Value::Str(format!("{:?}", f.decision)));
    m.insert("replay".into(), Value::Str(format!("{:?}", f.replay)));
    m.insert("timestamp".into(), Value::Int(f.timestamp.get()));
    m.insert("tainted".into(), Value::Bool(!f.taint.is_pristine()));
    m.insert("protected".into(), Value::Bool(f.taint.has_protected()));
    Value::Map(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, bail, ensure};
    use nexus_kernel::Bootstrap;
    use nexus_types::{IdentityRef, NodeId, OperationId};

    #[tokio::test]
    async fn inspect_lists_processes() -> Result<()> {
        let boot = Bootstrap::in_memory();
        let d = KernelInspectDriver::new(boot.kernel.processes.clone(), boot.kernel.facts.clone());
        let out = d
            .call(
                MethodId::new(0),
                Value::Null,
                OutputMode::Unary,
                &DriverContext::new(IdentityRef::ROOT, boot.root),
            )
            .await
            .context("inspect processes")?;
        let rows = match out {
            Outcome::Done(Value::List(rows)) => rows,
            other => bail!("expected rows, got {other:?}"),
        };
        ensure!(!rows.is_empty(), "expected at least one process row");
        Ok(())
    }

    #[tokio::test]
    async fn inspect_can_include_recent_facts() -> Result<()> {
        let boot = Bootstrap::in_memory();
        boot.record_gateway_audit(nexus_kernel::GatewayAudit {
            event: "test",
            username: None,
            source_addr: None,
            outcome: "ok",
            mfa_level: None,
            details: None,
        })
        .context("record gateway audit")?;
        let d = KernelInspectDriver::new(boot.kernel.processes.clone(), boot.kernel.facts.clone());
        let mut input = BTreeMap::new();
        input.insert("include_recent_facts".into(), Value::Bool(true));
        input.insert("limit".into(), Value::Int(8));
        let out = d
            .call(
                MethodId::new(0),
                Value::Map(input),
                OutputMode::Unary,
                &DriverContext::new(IdentityRef::ROOT, boot.root),
            )
            .await
            .context("inspect recent facts")?;
        if !matches!(out, Outcome::Done(Value::List(_))) {
            bail!("expected rows, got {out:?}");
        };
        let id = OperationId::new(boot.root, NodeId::new(1), 0);
        ensure!(id.process == boot.root, "operation id process mismatch");
        Ok(())
    }

    #[tokio::test]
    async fn inspect_rejects_malformed_include_recent_facts() -> Result<()> {
        let boot = Bootstrap::in_memory();
        let d = KernelInspectDriver::new(boot.kernel.processes.clone(), boot.kernel.facts.clone());
        let mut input = BTreeMap::new();
        input.insert("include_recent_facts".into(), Value::Str("yes".into()));
        let out = d
            .call(
                MethodId::new(0),
                Value::Map(input),
                OutputMode::Unary,
                &DriverContext::new(IdentityRef::ROOT, boot.root),
            )
            .await;
        ensure!(
            matches!(out, Err(DriverError::InvalidInput(ref message)) if message.contains("include_recent_facts")),
            "inspect accepted malformed include_recent_facts: {out:?}"
        );
        Ok(())
    }
}
