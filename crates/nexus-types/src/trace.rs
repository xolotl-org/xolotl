//! Distributed-trace projection: spans are derived from Facts. A request carries
//! a `trace_id`; each Operation becomes a child span under its Process's span,
//! and `Spawn`/`Acting` inherit the parent span. This module is the wasm-safe
//! span model + the derivation that turns a Fact into a span. A projector can
//! render these to OpenTelemetry.

use crate::ids::ProcessId;
use crate::operation::{DecisionTag, Fact};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;

/// A trace id shared by every span of one logical request. Propagated
/// from the gateway inbound through Spawn/Acting; stable across the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TraceId(pub u64);

/// A span id, unique within a trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct SpanId(pub u64);

/// One span derived from a Fact. The Operation's stable `OperationId`
/// gives a deterministic span id, so the same op always maps to the same span
/// across replay (no wall-clock dependence on identity).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Span {
    /// Trace this span belongs to.
    pub trace_id: TraceId,
    /// Span id unique within the trace.
    pub span_id: SpanId,
    /// Parent span: the Process's span. An Operation is a child of its Process;
    /// a spawned child Process's span is a child of the spawner's span.
    pub parent: Option<SpanId>,
    /// Short operation name (`<resource>/<method>` once resolved; here the
    /// method id, since the Fact carries ids not names).
    pub name: SmolStr,
    /// Span start timestamp in millis since epoch.
    pub start_millis: i64,
    /// Whether the underlying operation succeeded (drives span status).
    pub ok: bool,
}

/// The propagating trace context threaded through execution. Carried in
/// the executor `Env` and inherited by Spawn/Acting; each Operation derives a
/// child span id from its `OperationId`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceContext {
    /// Trace id being propagated.
    pub trace_id: TraceId,
    /// The current parent span (the Process or Acting-block span).
    pub parent_span: SpanId,
}

impl TraceContext {
    /// Root a fresh trace for `process`. The root span
    /// id is derived from the process id so it is stable.
    pub fn root_for(process: ProcessId) -> Self {
        let trace_id = TraceId(splitmix(process.get() ^ 0x9E37_79B9_7F4A_7C15));
        Self {
            trace_id,
            parent_span: SpanId(splitmix(process.get())),
        }
    }

    /// Derive a child trace context under a new parent span (Spawn / Acting,
    /// ): same trace, new parent derived from `seed`.
    pub fn child(self, seed: u64) -> Self {
        Self {
            trace_id: self.trace_id,
            parent_span: SpanId(splitmix(self.parent_span.0 ^ seed)),
        }
    }

    /// Build the span for one Fact under this context. The span id is
    /// derived from the Fact's `OperationId` so it is deterministic and stable
    /// across replay.
    pub fn span_for(&self, fact: &Fact) -> Span {
        let op_seed = splitmix(
            fact.id.process.get()
                ^ (fact.id.position.get() as u64).rotate_left(17)
                ^ (fact.id.attempt as u64).rotate_left(31),
        );
        Span {
            trace_id: self.trace_id,
            span_id: SpanId(op_seed),
            parent: Some(self.parent_span),
            name: SmolStr::new(format!("m{}", fact.method.get())),
            start_millis: fact.timestamp.get(),
            ok: matches!(fact.decision, DecisionTag::Ok),
        }
    }
}

/// A fast, allocation-free integer hash (SplitMix64) for deriving stable ids.
fn splitmix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{HandleId, MethodId, NodeId, ResourceId, Timestamp};
    use crate::operation::{OperationId, OutcomeRef, ValueRef};
    use crate::replay::ReplayClass;
    use crate::{IdentityRef, Value};

    fn fact(process: ProcessId, node: u32, decision: DecisionTag) -> Fact {
        Fact {
            id: OperationId::new(process, NodeId::new(node), 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller: process,
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(1),
            method: MethodId::new(3),
            input_ref: ValueRef::Inline(Value::Null),
            taint: crate::taint::TaintSet::pristine(),
            decision,
            outcome_ref: OutcomeRef::None,
            batch: None,
            replay: ReplayClass::Deterministic,
            timestamp: Timestamp::millis(42),
        }
    }

    #[test]
    fn child_keeps_trace_id_changes_parent() {
        let root = TraceContext::root_for(ProcessId::new(1));
        let child = root.child(99);
        assert_eq!(
            root.trace_id, child.trace_id,
            "same trace across Spawn/Acting"
        );
        assert_ne!(root.parent_span, child.parent_span, "new parent span");
    }

    #[test]
    fn span_for_is_deterministic_and_under_parent() {
        let ctx = TraceContext::root_for(ProcessId::new(1));
        let f = fact(ProcessId::new(1), 5, DecisionTag::Ok);
        let a = ctx.span_for(&f);
        let b = ctx.span_for(&f);
        assert_eq!(a, b, "same op ⇒ same span (replay-stable)");
        assert_eq!(a.parent, Some(ctx.parent_span));
        assert_eq!(a.trace_id, ctx.trace_id);
        assert!(a.ok);
    }

    #[test]
    fn span_status_reflects_decision() {
        let ctx = TraceContext::root_for(ProcessId::new(1));
        let failed = ctx.span_for(&fact(ProcessId::new(1), 6, DecisionTag::DriverError));
        assert!(!failed.ok);
    }

    #[test]
    fn distinct_ops_get_distinct_spans() {
        let ctx = TraceContext::root_for(ProcessId::new(1));
        let s1 = ctx.span_for(&fact(ProcessId::new(1), 1, DecisionTag::Ok));
        let s2 = ctx.span_for(&fact(ProcessId::new(1), 2, DecisionTag::Ok));
        assert_ne!(s1.span_id, s2.span_id);
    }
}
