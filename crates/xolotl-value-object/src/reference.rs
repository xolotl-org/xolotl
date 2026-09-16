//! Explicit encoding descriptors, separate from read authority and provenance.

use core::fmt;
use xolotl_types::{BlobRef, TaintSet, Value, ValueView};

/// The versioned representation carried by an immutable encoded object.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ValueEncoding {
    /// The version 1 Xolotl CBOR event envelope, streaming a logical value tree.
    /// Repeated resident DAG edges are encoded independently; physical sharing
    /// belongs to resident ownership and separately specified table formats.
    CborV1,
}

impl ValueEncoding {
    /// Stable protocol identifier, independent of descriptive media types.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CborV1 => "xolotl.value.cbor.v1",
        }
    }

    /// Select a known encoding by its exact, versioned protocol identifier.
    pub fn from_id(id: &str) -> Option<Self> {
        match id {
            "xolotl.value.cbor.v1" => Some(Self::CborV1),
            _ => None,
        }
    }

    /// A descriptive media type. Readers must use the explicit encoding and
    /// validate its envelope; a media type does not establish either validity
    /// or authority to read an object.
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::CborV1 => "application/vnd.xolotl.value+cbor",
        }
    }
}

/// A content reference paired with the encoding required to interpret it.
///
/// This descriptor carries no read authority, provenance attestation, retained
/// object lease, or promise that its bytes form a valid document. A reader must
/// resolve it through an admitted object port and validate through actual EOF.
/// Content hashes identify encoding bytes; legal chunk boundaries can produce
/// different hashes for the same logical value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedValueRef {
    /// Immutable content identity, encoded byte count, and descriptive media type.
    pub blob: BlobRef,
    /// Explicit interpretation of the referenced bytes, independent of MIME.
    pub encoding: ValueEncoding,
}

/// A value does not have the explicit encoded-object descriptor shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceError {
    /// The descriptor must be a map with exactly `encoding` and `blob` fields.
    Fields,
    /// The encoding must be a known, explicitly versioned protocol string.
    Encoding,
    /// The content reference must be a direct [`ValueView::Blob`].
    Blob,
}

impl fmt::Display for ReferenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Fields => "encoded value reference requires exactly encoding and blob fields",
            Self::Encoding => "encoded value reference has an unknown or missing encoding",
            Self::Blob => "encoded value reference requires a direct Blob value",
        })
    }
}

impl core::error::Error for ReferenceError {}

impl EncodedValueRef {
    /// Represent the descriptor as an ordinary, explicit protocol map.
    ///
    /// The result contains exactly `encoding` and a typed `blob`; it remains
    /// inert data until a caller explicitly selects an encoded-object reader.
    /// Encoding such a map as a value preserves the map itself. No Value or
    /// kernel operation recognizes descriptors implicitly or opens their bytes.
    pub fn into_value(self) -> Value {
        Value::map(
            [
                (
                    "encoding".into(),
                    Value::string(self.encoding.as_str().into()),
                ),
                ("blob".into(), Value::blob(self.blob)),
            ]
            .into_iter()
            .collect(),
        )
    }

    /// Parse only the exact protocol map, without resolving or reading content.
    ///
    /// Unknown fields, encodings, inferred MIME profiles and untyped hashes are
    /// rejected. Blob sizes retain their full width. This validates a descriptor
    /// shape only; canonical metadata, grammar, EOF and read authority still
    /// belong to the explicitly selected object port and document reader.
    pub fn try_from_value(value: &Value) -> Result<Self, ReferenceError> {
        let map = value.as_map().ok_or(ReferenceError::Fields)?;
        if map.len() != 2 || !map.contains_key("encoding") || !map.contains_key("blob") {
            return Err(ReferenceError::Fields);
        }
        let encoding = map
            .get("encoding")
            .and_then(Value::as_str)
            .and_then(ValueEncoding::from_id)
            .ok_or(ReferenceError::Encoding)?;
        let Some(ValueView::Blob(blob)) = map.get("blob").map(Value::view) else {
            return Err(ReferenceError::Blob);
        };
        Ok(Self {
            blob: blob.clone(),
            encoding,
        })
    }
}

/// A successfully committed encoded document and its publication provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedValue {
    /// Reference returned only after complete validation and acknowledged writes.
    pub reference: EncodedValueRef,
    /// Published metadata covering initial and final input provenance together
    /// with store and deduplication sources. Recorded claims do not supply it.
    pub taint: TaintSet,
}

#[cfg(test)]
mod tests;
