//! Fact read-side Driver (§9.4): `state://fact` / `state://fact/<process>/*`.
//!
//! Facts are the write-ahead source of truth (§9), written by the kernel. The
//! read side is a capability-gated, **read-only** projection: `state://fact`
//! lists the append stream for audit / billing / trace projectors, while
//! `state://fact/<process>` lists one process for why-not / replay tooling.
//! This Driver never mutates anything — it only reads the FactStore.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec, SharedFactStore};
use nexus_types::{MethodId, Outcome, OutputMode, ProcessId, Purity, Value};
use std::collections::BTreeMap;

/// Method names in registration order for `state://fact/*`. Read-only:
/// `read` is an Observation (it reflects external/durable state), not Pure, so
/// its outcome is recorded when it feeds control flow (§9.2/§9.3).
pub const FACT_METHODS: &[MethodSpec] =
    &[MethodSpec::new("read", Purity::Pure, MethodSpec::UNARY_ASYNC).observes_external()];

/// Drives `state://fact/*` over the kernel's [`SharedFactStore`].
pub struct FactDriver {
    facts: SharedFactStore,
}

impl FactDriver {
    pub fn new(facts: SharedFactStore) -> Self {
        Self { facts }
    }

    /// Project one Fact into a self-describing `Value` map (audit view). Only
    /// references and tags are exposed — never reconstructed business data.
    fn fact_to_value(f: &nexus_types::Fact) -> Value {
        let mut m = BTreeMap::new();
        m.insert("op_id".into(), Value::Str(f.id.to_string()));
        m.insert("caller".into(), Value::Int(f.caller.get() as i64));
        m.insert("acting".into(), Value::Int(f.acting.get() as i64));
        m.insert("resource".into(), Value::Int(f.resource.get() as i64));
        m.insert("method".into(), Value::Int(f.method.get() as i64));
        m.insert("decision".into(), Value::Str(format!("{:?}", f.decision)));
        m.insert("replay".into(), Value::Str(format!("{:?}", f.replay)));
        m.insert("timestamp".into(), Value::Int(f.timestamp.get()));
        // Surface the taint lineage for why-not tooling (§21.5).
        let tainted = !f.taint.is_pristine();
        m.insert("tainted".into(), Value::Bool(tainted));
        m.insert("protected".into(), Value::Bool(f.taint.has_protected()));
        // Audit tags (§21.3): the rule-independent structural projection
        // (sensitive_data / cross_identity) derived from this Fact alone.
        // Rule-driven tags (high_cost / compliance / alert) come from a projector
        // reading `state://kernel/audit/rules`; the always-on ones surface here.
        let tags = nexus_types::AuditRules::default().tags_for(f, 0);
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
                let facts = match ctx.target_path.as_ref().and_then(fact_path_scope) {
                    Some(FactScope::All) => self.facts.all_facts(),
                    Some(FactScope::Process(process)) => self.facts.facts_of(process),
                    None => self.facts.facts_of(ctx.caller),
                };
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

fn fact_path_scope(path: &nexus_types::Path) -> Option<FactScope> {
    let segs = path.segments();
    if path.scheme() != "state" || segs.first().map(|s| s.as_str()) != Some("fact") {
        return None;
    }
    match segs.get(1) {
        None => Some(FactScope::All),
        Some(raw) => raw
            .as_str()
            .parse::<u64>()
            .ok()
            .map(ProcessId::new)
            .map(FactScope::Process),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_kernel::FactSink;
    use nexus_types::{
        DecisionTag, Fact, HandleId, IdentityRef, MethodId, NodeId, OperationId, OutcomeRef,
        ReplayClass, ResourceId, Timestamp, ValueRef,
    };

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
            taint: nexus_types::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome_ref: OutcomeRef::Inline(Value::Null),
            batch: None,
            replay: ReplayClass::Observation,
            timestamp: Timestamp::millis(0),
        }
    }

    #[tokio::test]
    async fn read_returns_empty_for_unknown_process() {
        let (_sink, store) = FactSink::in_memory();
        let d = FactDriver::new(store);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_target_path(nexus_types::Path::parse("state://fact/99").unwrap());
        let out = d
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await
            .unwrap();
        assert_eq!(out, Outcome::Done(Value::List(vec![])));
    }

    #[tokio::test]
    async fn root_fact_path_lists_global_stream() {
        let (sink, store) = FactSink::in_memory();
        sink.complete(fact(ProcessId::new(1), 1)).unwrap();
        sink.complete(fact(ProcessId::new(2), 1)).unwrap();

        let d = FactDriver::new(store);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_target_path(nexus_types::Path::parse("state://fact").unwrap());
        let out = d
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await
            .unwrap();
        let Outcome::Done(Value::List(rows)) = out else {
            panic!("expected fact list");
        };
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn process_fact_path_filters_one_process() {
        let (sink, store) = FactSink::in_memory();
        sink.complete(fact(ProcessId::new(1), 1)).unwrap();
        sink.complete(fact(ProcessId::new(2), 1)).unwrap();

        let d = FactDriver::new(store);
        let ctx = DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
            .with_target_path(nexus_types::Path::parse("state://fact/2").unwrap());
        let out = d
            .call(MethodId::new(0), Value::Null, OutputMode::Unary, &ctx)
            .await
            .unwrap();
        let Outcome::Done(Value::List(rows)) = out else {
            panic!("expected fact list");
        };
        assert_eq!(rows.len(), 1);
    }
}
