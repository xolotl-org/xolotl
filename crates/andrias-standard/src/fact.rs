//! Fact read-side Driver: `state://fact` / `state://fact/<process>/*`.
//!
//! Facts are the kernel-written operation records. The read side is a
//! capability-gated, **read-only** projection: `state://fact`
//! lists the append stream for audit / billing / trace projectors, while
//! `state://fact/<process>` lists one process for why-not / replay tooling.
//! This Driver never mutates anything — it only reads the FactStore.

use andrias_kernel::{Driver, DriverContext, DriverError, MethodSpec, SharedFactStore};
use andrias_types::{Failure, MethodId, Outcome, OutputMode, ProcessId, Purity, Value};
use async_trait::async_trait;
use std::collections::BTreeMap;

/// Method names in registration order for `state://fact/*`. Read-only:
/// `read` is an Observation (it reflects external/durable state), not Pure, so
/// its outcome is recorded when it feeds control flow.
pub(crate) const FACT_METHODS: &[MethodSpec] =
    &[MethodSpec::new("read", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external()];

/// Drives `state://fact/*` over the kernel's [`SharedFactStore`].
pub(crate) struct FactDriver {
    facts: SharedFactStore,
}

impl FactDriver {
    /// Create a fact read-side projection driver backed by a shared fact store.
    pub(crate) fn new(facts: SharedFactStore) -> Self {
        Self { facts }
    }

    /// Project one Fact into a self-describing `Value` map (audit view). Only
    /// references and tags are exposed — never reconstructed business data.
    fn fact_to_value(f: &andrias_types::Fact) -> Value {
        let mut m = BTreeMap::new();
        m.insert("op_id".into(), Value::Str(f.id.to_string()));
        m.insert("caller".into(), Value::Int(f.caller.get() as i64));
        m.insert("acting".into(), Value::Int(f.acting.get() as i64));
        m.insert("resource".into(), Value::Int(f.resource.get() as i64));
        m.insert("method".into(), Value::Int(f.method.get() as i64));
        m.insert("decision".into(), Value::Str(format!("{:?}", f.decision)));
        m.insert("replay".into(), Value::Str(format!("{:?}", f.replay)));
        m.insert("timestamp".into(), Value::Int(f.timestamp.get()));
        // Surface the taint lineage for why-not tooling.
        let tainted = !f.taint.is_pristine();
        m.insert("tainted".into(), Value::Bool(tainted));
        m.insert("protected".into(), Value::Bool(f.taint.has_protected()));
        // Audit tags: the rule-independent structural projection
        // (sensitive_data / cross_identity) derived from this Fact alone.
        // Rule-driven tags (high_cost / compliance / alert) come from a projector
        // reading `state://kernel/audit/rules`; the always-on ones surface here.
        let tags = andrias_types::AuditRules::default().tags_for(f, 0);
        if !tags.is_empty() {
            let tag_strs: Vec<Value> = tags.iter().map(|t| Value::Str(format!("{t:?}"))).collect();
            m.insert("audit_tags".into(), Value::List(tag_strs));
        }
        Value::Map(m)
    }
}

#[async_trait]
impl Driver for FactDriver {
    async fn call(
        &self,
        method: MethodId,
        _input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        match method.get() {
            // read: list the global Fact stream at `state://fact`, or one
            // process when encoded as `state://fact/<id>`.
            0 => {
                let Some(path) = ctx.target_path.as_ref() else {
                    return Ok(Outcome::Fail(Failure::InvalidInput {
                        reason: "fact read has no bound path".into(),
                    }));
                };
                let facts = match fact_path_scope(path) {
                    Ok(FactScope::All) => self.facts.all_facts(),
                    Ok(FactScope::Process(process)) => self.facts.facts_of(process),
                    Err(failure) => return Ok(Outcome::Fail(failure)),
                }
                .map_err(|e| DriverError::Other(e.to_string()))?;
                let list: Vec<Value> = facts.iter().map(Self::fact_to_value).collect();
                Ok(Outcome::Done(Value::List(list)))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

enum FactScope {
    All,
    Process(ProcessId),
}

fn fact_path_scope(path: &andrias_types::Path) -> Result<FactScope, Failure> {
    let segs = path.segments();
    if path.scheme() != "state"
        || path.cluster().is_some()
        || segs.first().map(|s| s.as_str()) != Some("fact")
    {
        return Err(Failure::InvalidInput {
            reason: "fact read target must be state://fact or state://fact/<process>".into(),
        });
    }
    match (segs.get(1), segs.get(2)) {
        (None, None) => Ok(FactScope::All),
        (Some(raw), None) => raw
            .as_str()
            .parse::<u64>()
            .map(ProcessId::new)
            .map(FactScope::Process)
            .map_err(|_| Failure::InvalidInput {
                reason: "fact process scope must be a numeric process id".into(),
            }),
        _ => Err(Failure::InvalidInput {
            reason: "fact read target must be state://fact or state://fact/<process>".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use andrias_kernel::FactSink;
    use andrias_types::{
        DecisionTag, Fact, HandleId, IdentityRef, MethodId, NodeId, OperationId, OutcomeRef,
        ReplayClass, ResourceId, Timestamp, ValueRef,
    };
    use anyhow::{Context, Result, bail, ensure};

    fn fact(process: ProcessId, pos: u32) -> Fact {
        Fact {
            id: OperationId::new(process, NodeId::new(pos), 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller: process,
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(1),
            method: MethodId::new(0),
            input_ref: ValueRef::Inline(Value::Null),
            taint: andrias_types::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome_ref: OutcomeRef::Inline(Value::Null),
            batch: None,
            replay: ReplayClass::Observation,
            timestamp: Timestamp::millis(0),
        }
    }

    fn ctx_with_target(target: &str) -> Result<DriverContext> {
        let path = andrias_types::Path::parse(target).with_context(|| format!("parse {target}"))?;
        Ok(DriverContext::new(IdentityRef::ROOT, ProcessId::new(1)).with_target_path(path))
    }

    #[tokio::test]
    async fn read_returns_empty_for_unknown_process() -> Result<()> {
        let (_sink, store) = FactSink::in_memory();
        let d = FactDriver::new(store);
        let ctx = ctx_with_target("state://fact/99")?;
        let out = d
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await
            .context("read unknown process facts")?;
        ensure!(
            out == Outcome::Done(Value::List(vec![])),
            "unknown process facts: {out:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn root_fact_path_lists_global_stream() -> Result<()> {
        let (sink, store) = FactSink::in_memory();
        sink.complete(fact(ProcessId::new(1), 1))
            .context("write first fact")?;
        sink.complete(fact(ProcessId::new(2), 1))
            .context("write second fact")?;

        let d = FactDriver::new(store);
        let ctx = ctx_with_target("state://fact")?;
        let out = d
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await
            .context("read global facts")?;
        let rows = match out {
            Outcome::Done(Value::List(rows)) => rows,
            other => bail!("expected fact list, got {other:?}"),
        };
        ensure!(rows.len() == 2, "global fact count: {}", rows.len());
        Ok(())
    }

    #[tokio::test]
    async fn process_fact_path_filters_one_process() -> Result<()> {
        let (sink, store) = FactSink::in_memory();
        sink.complete(fact(ProcessId::new(1), 1))
            .context("write first fact")?;
        sink.complete(fact(ProcessId::new(2), 1))
            .context("write second fact")?;

        let d = FactDriver::new(store);
        let ctx = ctx_with_target("state://fact/2")?;
        let out = d
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await
            .context("read process facts")?;
        let rows = match out {
            Outcome::Done(Value::List(rows)) => rows,
            other => bail!("expected fact list, got {other:?}"),
        };
        ensure!(rows.len() == 1, "process fact count: {}", rows.len());
        Ok(())
    }

    #[tokio::test]
    async fn malformed_fact_scope_is_rejected_not_fallback() -> Result<()> {
        let (sink, store) = FactSink::in_memory();
        sink.complete(fact(ProcessId::new(1), 1))
            .context("write fact")?;
        let d = FactDriver::new(store);

        for target in [
            "state://fact/not-a-process",
            "state://fact/1/extra",
            "path://remote/state/fact/1",
        ] {
            let ctx = ctx_with_target(target)?;
            let out = d
                .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
                .await
                .with_context(|| format!("read malformed target {target}"))?;
            ensure!(
                matches!(out, Outcome::Fail(Failure::InvalidInput { .. })),
                "malformed fact target must fail: {target}"
            );
        }
        Ok(())
    }
}
