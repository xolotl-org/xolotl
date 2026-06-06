//! Generic data values, blob references, and failures.

use crate::path::Path;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// A self-describing value used for op input/output, state, and bindings.
///
/// Mirrors `serde_json::Value` plus a Blob variant. Equality and ordering are
/// well-defined so that hashes and idempotency keys are stable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(FloatBits),
    Str(String),
    List(Vec<Value>),
    Map(BTreeMap<String, Value>),
    Bytes(#[serde(with = "serde_bytes")] Vec<u8>),
    /// Reference to large opaque content (image / audio / video / file).
    /// Never inlined into a Fact (§4.4 iron rule).
    Blob(BlobRef),
    /// Numeric tensor reference: embeddings, audio waveforms, video frames,
    /// action vectors (§4.4). Bytes live behind the inner `BlobRef`.
    Tensor(TensorRef),
    /// A single timestamped frame: media sample or trajectory/sensor point
    /// (§4.4).
    Frame(FrameRef),
    StreamEnd(StreamMarker),
}

/// Signals the end of a streaming value sequence written via state append.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(tag = "__stream_marker")]
pub enum StreamMarker {
    Done,
    Error { message: String },
}

/// Wrapped f64 with bitwise equality so `Value` can be `Eq` and `Hash`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FloatBits(pub f64);

impl PartialEq for FloatBits {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_bits() == other.0.to_bits()
    }
}
impl Eq for FloatBits {}
impl std::hash::Hash for FloatBits {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        Ok(v)
    }
}

impl std::hash::Hash for Value {
    fn hash<H: std::hash::Hasher>(&self, h: &mut H) {
        std::mem::discriminant(self).hash(h);
        match self {
            Value::Null => {}
            Value::Bool(b) => b.hash(h),
            Value::Int(i) => i.hash(h),
            Value::Float(f) => f.hash(h),
            Value::Str(s) => s.hash(h),
            Value::Bytes(b) => b.hash(h),
            Value::List(xs) => {
                xs.len().hash(h);
                for x in xs {
                    x.hash(h);
                }
            }
            Value::Map(m) => {
                m.len().hash(h);
                for (k, v) in m {
                    k.hash(h);
                    v.hash(h);
                }
            }
            Value::Blob(b) => b.hash(h),
            Value::Tensor(t) => t.hash(h),
            Value::Frame(fr) => fr.hash(h),
            Value::StreamEnd(m) => m.hash(h),
        }
    }
}

impl Default for Value {
    /// The unit value (`Null`). Lets containers with a `Value` field derive
    /// `Default`.
    fn default() -> Self {
        Value::Null
    }
}

impl Value {
    pub fn unit() -> Self {
        Value::Null
    }

    pub fn as_map(&self) -> Option<&BTreeMap<String, Value>> {
        if let Value::Map(m) = self {
            Some(m)
        } else {
            None
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        if let Value::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        if let Value::Int(i) = self {
            Some(*i)
        } else {
            None
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        if let Value::Bool(b) = self {
            Some(*b)
        } else {
            None
        }
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Str(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Str(s)
    }
}
impl From<i64> for Value {
    fn from(i: i64) -> Self {
        Value::Int(i)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<()> for Value {
    fn from(_: ()) -> Self {
        Value::Null
    }
}

/// A pointer to large opaque content stored in `state://blob/<hash>` or
/// equivalent. Carries metadata for routing and quota.
///
/// `hash` is the hex-encoded sha256 of the content (the design's `sha256:
/// [u8;32]` rendered as a wasm/JSON-friendly hex string — equivalent content
/// address, fewer conversions). Large bytes never inline into a Fact (§4.4).
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct BlobRef {
    pub hash: String,
    pub size: u64,
    pub mime: Option<String>,
}

/// Numeric dtype of a [`TensorRef`] (§4.4). The kernel never computes on
/// tensors; this is metadata for routing (which model accepts which dtype)
/// and for the tensor store to interpret the backing bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DType {
    F16,
    Bf16,
    F32,
    F64,
    I8,
    I16,
    I32,
    I64,
    U8,
    Bool,
}

/// Reference to a numeric tensor: embedding, audio waveform, video frame,
/// action vector (§4.4). The bytes live behind `blob`; `dtype`/`shape`
/// describe how to interpret them. No codec/compute here — wasm-safe.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TensorRef {
    pub blob: BlobRef,
    pub dtype: DType,
    pub shape: Vec<u64>,
}

/// What a [`FrameRef`] samples (§4.4).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameKind {
    Audio,
    Video,
    /// A pose / action-trajectory sample point (robotics, UI automation).
    Pose,
    /// A sensor telemetry reading.
    Sensor,
}

/// A single timestamped frame: one media sample or trajectory/sensor point
/// (§4.4). Streams of these are appended to a Sequence Resource with
/// monotonically increasing `ts_nanos`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FrameRef {
    pub blob: BlobRef,
    pub ts_nanos: i64,
    pub kind: FrameKind,
}

impl Value {
    /// Construct a tensor value.
    pub fn tensor(blob: BlobRef, dtype: DType, shape: Vec<u64>) -> Self {
        Value::Tensor(TensorRef { blob, dtype, shape })
    }

    /// Construct a frame value.
    pub fn frame(blob: BlobRef, ts_nanos: i64, kind: FrameKind) -> Self {
        Value::Frame(FrameRef {
            blob,
            ts_nanos,
            kind,
        })
    }

    /// Whether this value carries a large out-of-line payload (blob / tensor
    /// / frame). The Fact recorder and trace projections use this to ensure
    /// only references — never bytes — are persisted (§4.4 iron rule).
    pub fn is_large_ref(&self) -> bool {
        matches!(self, Value::Blob(_) | Value::Tensor(_) | Value::Frame(_))
    }

    /// A cheap, conservative token-count estimate for budgeting (§21.2). Text is
    /// approximated at ~4 chars/token (the common GPT/BPE heuristic); structural
    /// values sum their parts. Out-of-line refs (blob/tensor/frame) contribute a
    /// flat nominal count since their true token cost is modality-specific and
    /// only known to the model backend. This is an estimate for *reservation* —
    /// settlement uses the backend's reported actual count.
    pub fn approx_tokens(&self) -> u64 {
        match self {
            Value::Null | Value::Bool(_) => 1,
            Value::Int(_) | Value::Float(_) => 1,
            Value::Str(s) => (s.chars().count() as u64 / 4).max(1),
            Value::Bytes(b) => (b.len() as u64 / 4).max(1),
            Value::List(items) => items.iter().map(Value::approx_tokens).sum::<u64>().max(1),
            Value::Map(m) => m
                .values()
                .map(Value::approx_tokens)
                .sum::<u64>()
                .saturating_add(m.len() as u64)
                .max(1),
            // A reference stands in for a large payload; charge a nominal amount.
            Value::Blob(_) | Value::Tensor(_) | Value::Frame(_) => 256,
            _ => 1,
        }
    }
}

/// Outcome failure. Failure values are carried in `Outcome::Fail` and may be
/// handled by `OrElse`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Failure {
    PermissionDenied {
        required: Vec<String>,
        actual: Vec<String>,
    },
    NoHandler {
        path: Path,
    },
    BudgetExhausted {
        dim: String,
    },
    RateLimited,
    /// The operation is suspended pending human approval (§8 / §17.4). Unlike a
    /// hard denial, this is *retryable*: once the approval is granted (the
    /// broker records `approved`), re-executing the operation passes. Carries
    /// the approval key to wait on and a human-readable reason.
    ApprovalPending {
        approval_key: String,
        reason: String,
    },
    Timeout,
    Cancelled,
    Quarantined {
        op_id: String,
        reason: String,
    },
    InvalidInput {
        reason: String,
    },
    HandlerError {
        kind: String,
        message: String,
    },
    KernelNamespaceProtected,
    /// A residual policy check (CompiledCheck) rejected an Operation because it
    /// violates a safety policy (injection guard, redaction, namespace
    /// protection).
    PolicyViolation {
        policy: String,
        detail: String,
    },
    /// The Operation target path is syntactically valid but semantically
    /// invalid (e.g. `state://` with zero segments, or `effect://` with only
    /// one segment).
    PathInvalid {
        path: Path,
        reason: String,
    },
    Custom {
        kind: String,
        message: String,
    },
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failure::PermissionDenied { required, .. } => {
                write!(f, "permission denied (required: {:?})", required)
            }
            Failure::NoHandler { path } => write!(f, "no handler for {}", path),
            Failure::BudgetExhausted { dim } => write!(f, "budget exhausted: {}", dim),
            Failure::RateLimited => write!(f, "rate limited"),
            Failure::ApprovalPending {
                approval_key,
                reason,
            } => write!(f, "approval pending ({approval_key}): {reason}"),
            Failure::Timeout => write!(f, "timeout"),
            Failure::Cancelled => write!(f, "cancelled"),
            Failure::Quarantined { reason, .. } => write!(f, "quarantined: {}", reason),
            Failure::InvalidInput { reason } => write!(f, "invalid input: {}", reason),
            Failure::HandlerError { message, .. } => write!(f, "handler: {}", message),
            Failure::KernelNamespaceProtected => write!(f, "kernel namespace protected"),
            Failure::PolicyViolation { policy, detail } => {
                write!(f, "policy violation ({policy}): {detail}")
            }
            Failure::PathInvalid { path, reason } => write!(f, "invalid path ({path}): {reason}"),
            Failure::Custom { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for Failure {}

impl Failure {
    pub fn policy(policy: impl Into<String>, detail: impl Into<String>) -> Self {
        Failure::PolicyViolation {
            policy: policy.into(),
            detail: detail.into(),
        }
    }

    pub fn path_invalid(path: Path, reason: impl Into<String>) -> Self {
        Failure::PathInvalid {
            path,
            reason: reason.into(),
        }
    }
}

/// How `Value`s are combined by a merge write (§12 `Value.write` Merge).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeRule {
    /// Map keys present in both: input wins. Lists are concatenated. Scalars:
    /// input wins.
    Shallow,
    /// Recursive shallow merge — nested maps recurse; lists concatenated.
    Deep,
}

#[derive(Debug, Error)]
pub enum ValueError {
    #[error("expected {expected}, got {got}")]
    TypeMismatch {
        expected: &'static str,
        got: &'static str,
    },
    #[error("missing key: {0}")]
    MissingKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_serde_roundtrip() {
        let mut m = BTreeMap::new();
        m.insert("a".into(), Value::Int(1));
        m.insert("b".into(), Value::Str("x".into()));
        let v = Value::Map(m);
        let s = serde_json::to_string(&v).unwrap();
        let back: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn float_bits_eq_for_nan() {
        let a = FloatBits(f64::NAN);
        let b = FloatBits(f64::NAN);
        // NaN is equal under bitwise comparison only if exactly the same bits.
        assert_eq!(a, b);
    }

    #[test]
    fn failure_display() {
        let f = Failure::NoHandler {
            path: crate::path::p("effect://x/post"),
        };
        assert!(f.to_string().contains("effect://x/post"));
    }

    #[test]
    fn value_hash_stability() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let v1 = Value::Str("hello".into());
        let v2 = Value::Str("hello".into());
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        v1.hash(&mut h1);
        v2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}
