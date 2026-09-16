//! Generic data values and complete media references.

use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod collection;
pub mod event;
mod payload;
mod resident;
mod semantics;
#[path = "value/serde.rs"]
mod serde_impl;
pub mod traversal;

pub use collection::{
    CollectionError, ListIter, MapIter, ValueList, ValueListBuilder, ValueMap, ValueMapBuilder,
};
pub use payload::{ValueBytes, ValueText};
pub use resident::{Value, ValueIdentity, ValueView};

/// Signals the end of a streaming value sequence written via state append.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(tag = "__stream_marker")]
pub enum StreamMarker {
    /// Stream completed normally.
    Done,
    /// Stream terminated with an error message.
    Error {
        /// Error detail carried with the terminal marker.
        message: String,
    },
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
impl core::hash::Hash for FloatBits {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.to_bits().hash(state);
    }
}

/// A pointer to large opaque content resolved by the host's object store.
/// Carries metadata for routing and quota.
///
/// The bundled filesystem adapter and Gateway use lowercase BLAKE3 content
/// hashes. Facts retain this reference instead of storing the object bytes.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct BlobRef {
    /// Content hash identifying the stored bytes.
    pub hash: String,
    /// Byte length of the stored payload.
    pub size: u64,
    /// Optional media type used by routing and display layers.
    pub mime: Option<String>,
}

/// Numeric dtype of a [`TensorRef`]. The kernel never computes on
/// tensors; this is metadata for routing (which model accepts which dtype)
/// and for the tensor store to interpret the backing bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DType {
    /// IEEE 754 half precision float.
    F16,
    /// Brain floating point 16-bit float.
    Bf16,
    /// IEEE 754 single precision float.
    F32,
    /// IEEE 754 double precision float.
    F64,
    /// Signed 8-bit integer.
    I8,
    /// Signed 16-bit integer.
    I16,
    /// Signed 32-bit integer.
    I32,
    /// Signed 64-bit integer.
    I64,
    /// Unsigned 8-bit integer.
    U8,
    /// Boolean element type.
    Bool,
}

/// Reference to a numeric tensor: embedding, audio waveform, video frame,
/// action vector. The bytes live behind `blob`; `dtype`/`shape`
/// describe how to interpret them. No codec/compute here — wasm-safe.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct TensorRef {
    /// Out-of-line bytes containing the tensor storage.
    pub blob: BlobRef,
    /// Element type of the tensor.
    pub dtype: DType,
    /// Tensor shape in row-major dimension order.
    pub shape: Vec<u64>,
}

/// What a [`FrameRef`] samples.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameKind {
    /// Audio media frame.
    Audio,
    /// Video media frame.
    Video,
    /// A pose / action-trajectory sample point (robotics, UI automation).
    Pose,
    /// A sensor telemetry reading.
    Sensor,
}

/// A single timestamped frame: one media sample or trajectory/sensor point.
/// Streams of these are appended to a Sequence Resource with
/// monotonically increasing `ts_nanos`.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct FrameRef {
    /// Out-of-line bytes for the frame payload.
    pub blob: BlobRef,
    /// Timestamp in nanoseconds.
    pub ts_nanos: i64,
    /// Media or sensor frame class.
    pub kind: FrameKind,
}

/// How `Value`s are combined by a merge write.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeRule {
    /// Map keys present in both: input wins. Lists are concatenated. Scalars:
    /// input wins.
    Shallow,
    /// Recursive shallow merge — nested maps recurse; lists concatenated.
    Deep,
}

/// Errors raised while extracting typed data from a [`Value`].
#[derive(Debug, Error)]
pub enum ValueError {
    /// A value had the wrong variant for the requested typed operation.
    #[error("expected {expected}, got {got}")]
    TypeMismatch {
        /// Expected variant or shape.
        expected: &'static str,
        /// Actual variant or shape.
        got: &'static str,
    },
    /// A required map key was absent.
    #[error("missing key: {0}")]
    MissingKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use anyhow::ensure;

    #[test]
    fn value_serde_roundtrip() -> anyhow::Result<()> {
        let mut m = BTreeMap::new();
        m.insert("a".into(), Value::integer(1));
        m.insert("b".into(), Value::string("x".into()));
        let v = Value::map(m);
        let s = serde_json::to_string(&v)?;
        let back: Value = serde_json::from_str(&s)?;
        ensure!(v == back, "serde roundtrip changed value");
        Ok(())
    }

    #[test]
    fn float_bits_eq_for_nan() {
        let a = FloatBits(f64::NAN);
        let b = FloatBits(f64::NAN);
        // NaN is equal under bitwise comparison only if exactly the same bits.
        assert_eq!(a, b);
    }

    #[test]
    fn value_hash_stability() {
        use core::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;
        let v1 = Value::string("hello".into());
        let v2 = Value::string("hello".into());
        let mut h1 = DefaultHasher::new();
        let mut h2 = DefaultHasher::new();
        v1.hash(&mut h1);
        v2.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }
}
