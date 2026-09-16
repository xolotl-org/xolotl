//! Versioned, lossless node/root tables for portable code and persistence.
//!
//! Use `#[serde(with = "xolotl_types::tagged_value")]` on a Value field. Node
//! records reference earlier records, so serde structure depth is independent
//! of Value depth. Floating-point bits and shared resident subvalues survive a
//! round trip. Decoding constructs the resident Value directly, one node at a
//! time; there is no recursive intermediate value tree.
//!
//! This format preserves sharing but does not canonicalize it. Hashes of its
//! encoded bytes are not semantic Value hashes. Use [`Value::semantic_digest`]
//! for sharing-independent identity. A [`ValueTableEncoder`] can intern roots
//! from every field of a checkpoint; serialize that table once and store the
//! returned [`ValueRoot`] IDs in the owning record. [`ValueTableDecoder`]
//! restores those roots with their shared resident descendants.

use crate::Value;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod decode;
mod encode;

pub use decode::ValueTableDecoder;
pub use encode::ValueTableEncoder;

/// A node reference inside its owning serialized value table.
///
/// This ID is neither a resident pointer nor a semantic digest. It is meaningful
/// only with the table that produced it; decoding callers must resolve every
/// field through that same [`ValueTableDecoder`] before publishing the record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValueRoot(u64);

/// A root could not be indexed into a lossless value table.
///
/// These are representation errors. Resident allocation uses ordinary `alloc`
/// failure behavior; this error type does not promise fallible allocation.
#[derive(Debug, thiserror::Error)]
pub enum ValueTableEncodeError {
    /// The table has more nodes than its u64 references can address.
    #[error("value table node identifier exceeds u64")]
    NodeIdOverflow,
    /// The resident graph traversal did not produce its requested root.
    #[error("value table is missing the requested root")]
    MissingRoot,
}

#[cfg(test)]
mod context_tests;
#[cfg(test)]
mod tests;

/// Version of the lossless node/root table format.
pub const VERSION: u32 = 1;

struct Borrowed<'a>(&'a Value);

impl Serialize for Borrowed<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        encode::serialize(self.0, serializer)
    }
}

struct Decoded(Value);

impl<'de> Deserialize<'de> for Decoded {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        decode::deserialize(deserializer).map(Self)
    }
}

/// Borrow a lossless node table without cloning resident values or leaf data.
/// Encoding allocates an index proportional to the visited resident graph.
pub fn serializable(value: &Value) -> impl Serialize + '_ {
    Borrowed(value)
}

/// Serialize one resident root and its reachable nodes with explicit types.
pub fn serialize<S: Serializer>(value: &Value, serializer: S) -> Result<S::Ok, S::Error> {
    encode::serialize(value, serializer)
}

/// Decode a versioned table, rejecting malformed types and forward references.
pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Value, D::Error> {
    decode::deserialize(deserializer)
}

/// The same encoding for an optional literal operation input.
pub mod optional {
    use super::*;

    /// Serialize None as null and Some as its explicit node/root table.
    pub fn serialize<S: Serializer>(
        value: &Option<Value>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        value.as_ref().map(Borrowed).serialize(serializer)
    }

    /// Deserialize an optional table, preserving Some(Value::null()).
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Value>, D::Error> {
        Option::<Decoded>::deserialize(deserializer).map(|value| value.map(|value| value.0))
    }
}
