//! Kernel process inspection driver (§18.4 / §24.3).
//!
//! The Console reaches runtime state through this ordinary effect, so inspect
//! reads are capability-gated Operations and recorded in the Fact stream.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_types::{MethodId, Outcome, OutputMode, ProcessId, Purity, Value};
use std::collections::BTreeMap;

/// `effect://kernel/process/inspect`.
pub const INSPECT_METHODS: &[MethodSpec] =
    &[MethodSpec::new("inspect", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external()];

pub struct KernelInspectDriver {
    processes: nexus_kernel::ProcessTable,
    facts: nexus_kernel::FactSink,
}

impl KernelInspectDriver {
    pub fn new(processes: nexus_kernel::ProcessTable, facts: nexus_kernel::FactSink) -> Self {
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
        let input = input.as_map().cloned().unwrap_or_default();
        let process = input
            .get("process")
            .and_then(Value::as_int)
            .and_then(|v| u64::try_from(v).ok())
            .map(ProcessId::new);
        let include_facts = input
            .get("include_recent_facts")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let limit = input
            .get("limit")
            .and_then(Value::as_int)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(32)
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
            let facts = self.facts.facts_of(pid);
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
    use nexus_kernel::Bootstrap;
    use nexus_types::{IdentityRef, NodeId, OperationId};

    #[tokio::test]
    async fn inspect_lists_processes() {
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
            .unwrap();
        let Outcome::Done(Value::List(rows)) = out else {
            panic!("expected rows");
        };
        assert!(!rows.is_empty());
    }

    #[tokio::test]
    async fn inspect_can_include_recent_facts() {
        let boot = Bootstrap::in_memory();
        boot.record_gateway_audit(nexus_kernel::GatewayAudit {
            event: "test",
            username: None,
            source_addr: None,
            outcome: "ok",
            mfa_level: None,
            details: None,
        })
        .unwrap();
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
            .unwrap();
        let Outcome::Done(Value::List(_)) = out else {
            panic!("expected rows");
        };
        let id = OperationId::new(boot.root, NodeId::new(1), 0);
        assert_eq!(id.process, boot.root);
    }
}
