//! Incremental, lossless events for a value and its recorded provenance.
//!
//! A document contains a [`Kind::Taint`] record followed by exactly one value.
//! Records have explicit, matching begin and end events. String, byte and key
//! fields contain borrowed [`Event::Data`] chunks; their boundaries need not
//! coincide with UTF-8 boundaries and do not affect the represented value.
//!
//! These events describe data, not read authority or trusted provenance. A
//! consumer must validate the complete document and its enclosing transport
//! before publishing a value. Provenance supplied by an ingress boundary
//! remains distinct from labels claimed by a document.

use super::{DType, FrameKind};

mod builder;
pub use builder::{BuilderError, MaterializationDimension, MaterializationLimits, ValueBuilder};
mod cursor;
pub use cursor::{CursorError, ValueCursor};
mod validation;
pub use validation::{
    KeyCompletion, KeyEffect, KeyId, Validation, ValidationError, ValidationStep, Validator,
};

/// A variable-length field, collection or record in the event grammar.
///
/// Enum discriminants are not wire identifiers. A concrete codec defines its
/// versioned mapping independently.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Exactly one taint record followed by exactly one value.
    Document,
    /// Recorded sources in their original order, including repeated labels.
    Taint,
    /// UTF-8 text carried by zero or more data chunks.
    String,
    /// Arbitrary bytes carried by zero or more data chunks.
    Bytes,
    /// Zero or more values in source order.
    List,
    /// Alternating keys and values, with keys strictly increasing by UTF-8 bytes.
    Map,
    /// A UTF-8 map key carried by zero or more data chunks.
    Key,
    /// Hash string, unsigned byte size, then a null or media-type string.
    Blob,
    /// Blob record, dtype atom, then a shape record.
    Tensor,
    /// Zero or more unsigned tensor dimensions in source order.
    Shape,
    /// Blob record, signed timestamp, then a frame-kind atom.
    Frame,
    /// One string containing an end-of-stream error message.
    StreamError,
    /// Source string followed by channel string for recorded ingress provenance.
    Inbound,
    /// One host string for recorded fetched provenance.
    Fetched,
    /// One structured path for recorded protected provenance.
    Protected,
    /// Null or cluster string, scheme string, then a path-segments record.
    Path,
    /// Zero or more path-segment strings in source order.
    PathSegments,
}

/// A fixed-size value or field in the event grammar.
///
/// Unsigned integers and enum atoms are metadata fields, not additional
/// variants of [`super::Value`]. Their validity depends on the enclosing record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Atom {
    /// A null value or an absent optional metadata field.
    Null,
    /// A boolean value.
    Bool(bool),
    /// A signed value or timestamp.
    I64(i64),
    /// The exact IEEE-754 bits of a floating-point value.
    F64Bits(u64),
    /// An unsigned size or tensor dimension.
    U64(u64),
    /// A tensor element type.
    DType(DType),
    /// The kind of a timestamped frame.
    FrameKind(FrameKind),
    /// Recorded author-constant provenance.
    Author,
    /// Recorded model-output provenance.
    Model,
    /// A successful end-of-stream value.
    StreamDone,
}

/// One borrowed step in a lossless value document.
///
/// Data chunks can be empty and may split a UTF-8 code point. Text validity is
/// checked across chunks before the corresponding string or key ends. Neither
/// chunk boundaries nor empty chunks add semantic content.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event<'a> {
    /// Begin a field, collection or record.
    Begin(Kind),
    /// End the matching field, collection or record.
    End(Kind),
    /// Carry one fixed-size value or metadata field.
    Atom(Atom),
    /// Borrow bytes from a string, byte field or key without owning them.
    Data(&'a [u8]),
}
