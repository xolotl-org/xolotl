//! `Operation`, `OperationId`, and `Fact` — the data-plane records (§6, §9).
//!
//! An [`Operation`] is the *only* way a side effect happens. Its identity,
//! [`OperationId`], is causally derived — `(ProcessId, CausalPosition,
//! attempt)` — with **no central counter** (§6.1). A [`Fact`] is the immutable,
//! write-ahead record of one operation attempt and is the system's single
//! source of truth (§9). Both are fixed-size hot records: they carry *refs*,
//! never inlined large payloads (§4.4 / §9).

use crate::ids::{
    CausalPosition, HandleId, IdentityRef, MethodId, ProcessId, ResourceId, Timestamp,
};
use crate::replay::ReplayClass;
use crate::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Causally-derived, globally-unique operation identity (§6.1). Equal id ⇒
/// same causal position + same attempt ⇒ exact dedup point in the Fact stream.
/// Never depends on wall clock; needs no central counter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct OperationId {
    /// Process that owns this causal position.
    pub process: ProcessId,
    /// Stable position in the compiled graph = `NodeId` (§13.2).
    pub position: CausalPosition,
    /// Incremented only on explicit retry; crash-replay reuses the same value.
    pub attempt: u32,
}

impl OperationId {
    /// Create an operation id from its causal coordinates.
    pub fn new(process: ProcessId, position: CausalPosition, attempt: u32) -> Self {
        Self {
            process,
            position,
            attempt,
        }
    }

    /// The same causal position at the next explicit retry.
    pub fn retry(self) -> Self {
        Self {
            attempt: self.attempt + 1,
            ..self
        }
    }
}

impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.process.get(),
            self.position.get(),
            self.attempt
        )
    }
}

/// Reference to an operation's input/output value. On the hot path large
/// payloads are passed by ref so the Fact stays fixed-size (§4.4 / §9). For
/// small inline values the ref *is* the value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueRef {
    /// A small value carried inline.
    Inline(Value),
    /// A large value addressed by content hash (blob/tensor/frame); the bytes
    /// live in the blob/tensor store, never in the Fact.
    External {
        /// Content hash for the external payload.
        hash: String,
        /// Byte size of the external payload.
        size: u64,
    },
}

impl ValueRef {
    /// Wrap a value, externalizing it if it carries a large out-of-line ref.
    pub fn of(v: Value) -> Self {
        match &v {
            Value::Blob(b) => ValueRef::External {
                hash: b.hash.clone(),
                size: b.size,
            },
            Value::Tensor(t) => ValueRef::External {
                hash: t.blob.hash.clone(),
                size: t.blob.size,
            },
            Value::Frame(fr) => ValueRef::External {
                hash: fr.blob.hash.clone(),
                size: fr.blob.size,
            },
            _ => ValueRef::Inline(v),
        }
    }

    /// Project a borrowed value into the fixed-size Fact representation.
    /// Inline values are cloned because Facts own their replay/audit snapshot;
    /// out-of-line values only copy the content-address metadata.
    pub fn of_ref(v: &Value) -> Self {
        match v {
            Value::Blob(b) => ValueRef::External {
                hash: b.hash.clone(),
                size: b.size,
            },
            Value::Tensor(t) => ValueRef::External {
                hash: t.blob.hash.clone(),
                size: t.blob.size,
            },
            Value::Frame(fr) => ValueRef::External {
                hash: fr.blob.hash.clone(),
                size: fr.blob.size,
            },
            _ => ValueRef::Inline(v.clone()),
        }
    }

    /// Borrow the inline value if this reference carries one.
    pub fn as_inline(&self) -> Option<&Value> {
        match self {
            ValueRef::Inline(v) => Some(v),
            ValueRef::External { .. } => None,
        }
    }
}

/// A single actual call — the one path through which side effects occur (§6).
/// Carries the input `Value` for dispatch; the data plane projects it to a
/// fixed-size [`ValueRef`] when recording the Fact (§4.4 / §9). Large modality
/// values (`Blob`/`Tensor`/`Frame`) are *already* out-of-line refs, so passing
/// them by value here is cheap — the bytes never travel inline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    /// Causally derived operation id.
    pub id: OperationId,
    /// The calling Process (`caller`, §2.5).
    pub process: ProcessId,
    /// The identity this call runs as (`acting`, §2.5).
    pub acting: IdentityRef,
    /// Handle authorizing this call.
    pub handle: HandleId,
    /// Interface method id selected by open/dispatch.
    pub method: MethodId,
    /// The input passed to the driver. Recorded in the Fact as `ValueRef::of`.
    pub input: Value,
    /// Provenance of the input value (§21.5). Propagates input→output: the
    /// outcome inherits this taint, and outbound/memory policies read it.
    #[serde(default)]
    pub taint: crate::taint::TaintSet,
    /// Output mode requested by the caller.
    pub output: crate::resource::OutputMode,
}

/// Why an operation ended the way it did — a fixed-size enum tag, not a full
/// snapshot (§9). The detailed outcome is materialized on the projection side.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionTag {
    /// Completed successfully.
    Ok,
    /// Denied by capability / owner / rights check.
    Denied,
    /// Rejected by a residual policy check.
    RejectedByPolicy,
    /// The driver returned an error.
    DriverError,
    /// Operation timed out.
    Timeout,
    /// Operation was cancelled.
    Cancelled,
    /// Held in quarantine (unsafe replay).
    Quarantined,
}

impl DecisionTag {
    /// Returns true when the decision represents success.
    pub fn is_ok(self) -> bool {
        matches!(self, DecisionTag::Ok)
    }
}

/// Reference to a materialized outcome summary (§9). The hot path writes only
/// this ref; audit/billing/trace projections materialize the detail lazily
/// from `input_ref` / `outcome_ref`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeRef {
    /// A small outcome carried inline.
    Inline(Value),
    /// A large outcome addressed by content hash.
    External {
        /// Content hash for the external payload.
        hash: String,
        /// Byte size of the external payload.
        size: u64,
    },
    /// No completed success body: pending facts and failures use this. A
    /// successful unit/null outcome is recorded as `Inline(Value::Null)` so
    /// recovery can distinguish completion from "begun, not completed".
    None,
}

impl OutcomeRef {
    /// Wrap a success value, externalizing large payload references.
    pub fn of(v: Value) -> Self {
        match &v {
            Value::Blob(b) => OutcomeRef::External {
                hash: b.hash.clone(),
                size: b.size,
            },
            Value::Tensor(t) => OutcomeRef::External {
                hash: t.blob.hash.clone(),
                size: t.blob.size,
            },
            Value::Frame(fr) => OutcomeRef::External {
                hash: fr.blob.hash.clone(),
                size: fr.blob.size,
            },
            _ => OutcomeRef::Inline(v),
        }
    }

    /// Project a borrowed success body into the Fact outcome representation.
    /// Like [`ValueRef::of_ref`], this avoids cloning tensor/blob/frame wrapper
    /// fields that are not stored in the hot record.
    pub fn of_ref(v: &Value) -> Self {
        match v {
            Value::Blob(b) => OutcomeRef::External {
                hash: b.hash.clone(),
                size: b.size,
            },
            Value::Tensor(t) => OutcomeRef::External {
                hash: t.blob.hash.clone(),
                size: t.blob.size,
            },
            Value::Frame(fr) => OutcomeRef::External {
                hash: fr.blob.hash.clone(),
                size: fr.blob.size,
            },
            _ => OutcomeRef::Inline(v.clone()),
        }
    }

    /// Borrow the inline success body if this reference carries one.
    pub fn as_inline(&self) -> Option<&Value> {
        match self {
            OutcomeRef::Inline(v) => Some(v),
            OutcomeRef::External { .. } | OutcomeRef::None => None,
        }
    }
}

/// Compact shape/cost metadata for one explicit batchable Operation (§17.5).
/// It is an audit summary, not the replay body: recovery still uses
/// `outcome_ref`, so summarizing a batch never discards the completed result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BatchSummary {
    /// Number of elements in the batch input list.
    pub elements: u64,
    /// Estimated input tokens for the whole batch.
    pub input_tokens: u64,
    /// Estimated output tokens for the whole batch.
    pub output_tokens: u64,
    /// Redacted structural summary of the input.
    pub input_summary: Value,
    /// Redacted structural summary of the output.
    pub output_summary: Value,
}

impl BatchSummary {
    /// Build a summary for list-shaped batch input and optional outcome.
    pub fn new(input: &Value, outcome: Option<&OutcomeRef>) -> Option<Self> {
        let Value::List(items) = input else {
            return None;
        };
        let output = outcome.and_then(OutcomeRef::as_inline);
        Some(Self {
            elements: items.len() as u64,
            input_tokens: input.approx_tokens(),
            output_tokens: output.map(Value::approx_tokens).unwrap_or(0),
            input_summary: summarize_value(input),
            output_summary: output.map(summarize_value).unwrap_or(Value::Null),
        })
    }

    /// Convert the summary to a value for audit and console projections.
    pub fn to_value(&self) -> Value {
        let mut m = BTreeMap::new();
        m.insert("elements".into(), Value::Int(self.elements as i64));
        m.insert("input_tokens".into(), Value::Int(self.input_tokens as i64));
        m.insert(
            "output_tokens".into(),
            Value::Int(self.output_tokens as i64),
        );
        m.insert("input_summary".into(), self.input_summary.clone());
        m.insert("output_summary".into(), self.output_summary.clone());
        Value::Map(m)
    }
}

fn summarize_value(v: &Value) -> Value {
    match v {
        Value::Null => kind("null"),
        Value::Bool(_) => kind("bool"),
        Value::Int(_) => kind("int"),
        Value::Float(_) => kind("float"),
        Value::Str(s) => {
            let mut m = kind_map("str");
            m.insert("chars".into(), Value::Int(s.chars().count() as i64));
            Value::Map(m)
        }
        Value::Bytes(b) => {
            let mut m = kind_map("bytes");
            m.insert("bytes".into(), Value::Int(b.len() as i64));
            Value::Map(m)
        }
        Value::List(items) => {
            let mut m = kind_map("list");
            m.insert("len".into(), Value::Int(items.len() as i64));
            if let Some(first) = items.first() {
                m.insert("elem".into(), summarize_value(first));
            }
            Value::Map(m)
        }
        Value::Map(fields) => {
            let mut m = kind_map("map");
            m.insert("fields".into(), Value::Int(fields.len() as i64));
            m.insert(
                "keys".into(),
                Value::List(fields.keys().take(8).cloned().map(Value::Str).collect()),
            );
            Value::Map(m)
        }
        Value::Blob(b) => {
            let mut m = kind_map("blob");
            m.insert("hash".into(), Value::Str(b.hash.clone()));
            m.insert("size".into(), Value::Int(b.size as i64));
            if let Some(mime) = &b.mime {
                m.insert("mime".into(), Value::Str(mime.clone()));
            }
            Value::Map(m)
        }
        Value::Tensor(t) => {
            let mut m = kind_map("tensor");
            m.insert("hash".into(), Value::Str(t.blob.hash.clone()));
            m.insert("size".into(), Value::Int(t.blob.size as i64));
            m.insert(
                "shape".into(),
                Value::List(t.shape.iter().map(|n| Value::Int(*n as i64)).collect()),
            );
            m.insert("dtype".into(), Value::Str(format!("{:?}", t.dtype)));
            Value::Map(m)
        }
        Value::Frame(fr) => {
            let mut m = kind_map("frame");
            m.insert("hash".into(), Value::Str(fr.blob.hash.clone()));
            m.insert("size".into(), Value::Int(fr.blob.size as i64));
            m.insert("ts_nanos".into(), Value::Int(fr.ts_nanos));
            m.insert("kind".into(), Value::Str(format!("{:?}", fr.kind)));
            Value::Map(m)
        }
        Value::StreamEnd(_) => kind("stream_end"),
    }
}

fn kind(name: &str) -> Value {
    Value::Map(kind_map(name))
}

fn kind_map(name: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([("kind".into(), Value::Str(name.into()))])
}

/// Immutable record of one operation attempt; the system's write-ahead source
/// of truth (§9). Fixed-size hot record: refs + lightweight tags only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Fact {
    /// `OperationId` — globally unique, no central counter (§9 / §6.1).
    pub id: OperationId,
    /// Fact schema version used for migration and replay compatibility.
    pub schema_version: u32,
    /// Process that issued the operation.
    pub caller: ProcessId,
    /// Identity the operation ran as.
    pub acting: IdentityRef,
    /// Handle used to authorize and dispatch the operation.
    pub handle: HandleId,
    /// Resource id resolved by the handle.
    pub resource: ResourceId,
    /// Method id invoked on the resource interface.
    pub method: MethodId,
    /// Reference only; large objects are blob/tensor refs (§4.4).
    pub input_ref: ValueRef,
    /// Provenance of the input (§21.5), recorded for audit / why-not. Defaults
    /// to pristine for Facts written before taint tracking existed.
    #[serde(default)]
    pub taint: crate::taint::TaintSet,
    /// Fixed-size decision tag, not a full snapshot.
    pub decision: DecisionTag,
    /// Reference; the summary is materialized on the projection side.
    pub outcome_ref: OutcomeRef,
    /// Optional §17.5 batch summary. It describes a `List` input to a batchable
    /// method while `input_ref`/`outcome_ref` remain the replay material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch: Option<BatchSummary>,
    /// Replay class derived from method purity and operation semantics.
    pub replay: ReplayClass,
    /// Timestamp assigned when the Fact was recorded.
    pub timestamp: Timestamp,
}

impl Fact {
    /// Current Fact schema version (§9.1 / §26). Bumping this requires a
    /// migration so historical Facts stay replayable.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Whether this Fact records a completed attempt (has an outcome). A
    /// pending Fact (begun, not completed) is handled per ReplayClass on
    /// recovery (§15.1).
    pub fn is_complete(&self) -> bool {
        !matches!(self.outcome_ref, OutcomeRef::None) || !self.decision.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::NodeId;
    use crate::value::{BlobRef, Value};

    #[test]
    fn operation_id_is_causal_not_counter() {
        let a = OperationId::new(ProcessId::new(1), NodeId::new(5), 0);
        let b = OperationId::new(ProcessId::new(1), NodeId::new(5), 0);
        assert_eq!(
            a, b,
            "same causal position + attempt ⇒ same id (dedup anchor)"
        );
        assert_ne!(a, a.retry(), "retry bumps attempt");
    }

    #[test]
    fn value_ref_externalizes_large_payloads() {
        let blob = Value::Blob(BlobRef {
            hash: "abc".into(),
            size: 1_000_000,
            mime: None,
        });
        match ValueRef::of(blob) {
            ValueRef::External { hash, size } => {
                assert_eq!(hash, "abc");
                assert_eq!(size, 1_000_000);
            }
            _ => panic!("large blob must be externalized, never inlined into a Fact"),
        }
        assert!(matches!(ValueRef::of(Value::Int(3)), ValueRef::Inline(_)));
    }

    #[test]
    fn borrowed_refs_externalize_large_payloads_without_owned_value() {
        let blob = Value::Blob(BlobRef {
            hash: "abc".into(),
            size: 1_000_000,
            mime: None,
        });

        assert_eq!(
            ValueRef::of_ref(&blob),
            ValueRef::External {
                hash: "abc".into(),
                size: 1_000_000
            }
        );
        assert_eq!(
            OutcomeRef::of_ref(&blob),
            OutcomeRef::External {
                hash: "abc".into(),
                size: 1_000_000
            }
        );
        assert_eq!(
            ValueRef::of_ref(&Value::Int(3)),
            ValueRef::Inline(Value::Int(3))
        );
    }

    #[test]
    fn null_success_is_a_completed_outcome() {
        let f = Fact {
            id: OperationId::new(ProcessId::new(2), NodeId::new(1), 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller: ProcessId::new(2),
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(7),
            method: MethodId::new(0),
            input_ref: ValueRef::Inline(Value::Null),
            taint: crate::taint::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome_ref: OutcomeRef::of(Value::Null),
            batch: None,
            replay: ReplayClass::Deterministic,
            timestamp: Timestamp::millis(123),
        };
        assert!(matches!(f.outcome_ref, OutcomeRef::Inline(Value::Null)));
        assert!(f.is_complete());
    }

    #[test]
    fn fact_serde_roundtrip() {
        let f = Fact {
            id: OperationId::new(ProcessId::new(2), NodeId::new(1), 0),
            schema_version: Fact::SCHEMA_VERSION,
            caller: ProcessId::new(2),
            acting: IdentityRef::ROOT,
            handle: HandleId::new(0, 1),
            resource: ResourceId::new(7),
            method: MethodId::new(0),
            input_ref: ValueRef::Inline(Value::Str("hi".into())),
            taint: crate::taint::TaintSet::pristine(),
            decision: DecisionTag::Ok,
            outcome_ref: OutcomeRef::Inline(Value::Int(1)),
            batch: None,
            replay: ReplayClass::Deterministic,
            timestamp: Timestamp::millis(123),
        };
        let s = serde_json::to_string(&f).unwrap();
        let back: Fact = serde_json::from_str(&s).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn batch_summary_summarizes_shape_without_replacing_outcome() {
        let input = Value::List(vec![Value::Str("alpha".into()), Value::Str("beta".into())]);
        let outcome = OutcomeRef::of(Value::List(vec![Value::Int(1), Value::Int(2)]));
        let summary = BatchSummary::new(&input, Some(&outcome)).unwrap();
        assert_eq!(summary.elements, 2);
        assert!(matches!(outcome, OutcomeRef::Inline(Value::List(_))));
        assert!(matches!(summary.to_value(), Value::Map(_)));
    }
}
