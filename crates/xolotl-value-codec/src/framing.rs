//! Private, allocation-free framing for validated value events.

mod decode;
mod encode;
mod ids;

use core::fmt;

pub(crate) use decode::{DecodeStatus, DecodeStep, FrameDecoder};
pub(crate) use encode::{EventWriter, FrameEncoder};

const MAGIC: &[u8] = b"xolotl.value";
const VERSION: u64 = 1;
const MAX_DATA_RECORD_BYTES: u64 = u32::MAX as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// A structural wire error with a cumulative, non-wrapping byte offset.
pub struct Error {
    /// Number of wire bytes processed before the error was detected.
    pub offset: u64,
    /// The invalid wire shape or interrupted framing operation.
    pub kind: ErrorKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Structural framing failures, independent of value-grammar validation.
pub enum ErrorKind {
    /// A staged CBOR header is syntactically invalid or unrepresentable.
    InvalidCbor,
    /// The outer array, magic byte string, version type or event array is invalid.
    InvalidEnvelope,
    /// The envelope declares a version this codec does not understand.
    UnsupportedVersion(u64),
    /// An event record has the wrong arity or argument type.
    InvalidRecord,
    /// The event tag has no mapping in this format version.
    UnknownEvent(u64),
    /// A begin or end record names an unknown container kind.
    UnknownKind(u64),
    /// A tensor dtype record names an unknown element type.
    UnknownDType(u64),
    /// A frame-kind record names an unknown media or sensor class.
    UnknownFrameKind(u64),
    /// A signed integer argument lies outside the i64 range.
    InvalidInteger,
    /// One data record exceeds u32::MAX bytes; logical fields may span records.
    DataRecordTooLarge(u64),
    /// Actual EOF was reported before the entire envelope was received.
    Truncated,
    /// Bytes follow the enclosing event array's final break.
    TrailingData,
    /// The cumulative wire-byte position would exceed u64::MAX.
    OffsetOverflow,
    /// A previous event writer was abandoned without completing its record.
    IncompleteEvent,
    /// An incomplete event writer was dropped.
    Cancelled,
    /// A new event was offered after encoder shutdown began.
    Closed,
    /// The low-level encoder could not write a header to its fixed workspace.
    HeaderEncoding,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "value framing error at byte {}: ", self.offset)?;
        match self.kind {
            ErrorKind::InvalidCbor => formatter.write_str("invalid CBOR header"),
            ErrorKind::InvalidEnvelope => formatter.write_str("invalid value envelope"),
            ErrorKind::UnsupportedVersion(version) => {
                write!(formatter, "unsupported version {version}")
            }
            ErrorKind::InvalidRecord => formatter.write_str("invalid event record"),
            ErrorKind::UnknownEvent(id) => write!(formatter, "unknown event {id}"),
            ErrorKind::UnknownKind(id) => write!(formatter, "unknown container kind {id}"),
            ErrorKind::UnknownDType(id) => write!(formatter, "unknown tensor dtype {id}"),
            ErrorKind::UnknownFrameKind(id) => write!(formatter, "unknown frame kind {id}"),
            ErrorKind::InvalidInteger => formatter.write_str("invalid event integer"),
            ErrorKind::DataRecordTooLarge(bytes) => {
                write!(formatter, "data record contains {bytes} bytes")
            }
            ErrorKind::Truncated => formatter.write_str("truncated value stream"),
            ErrorKind::TrailingData => formatter.write_str("data follows the value envelope"),
            ErrorKind::OffsetOverflow => formatter.write_str("wire byte offset exceeds u64"),
            ErrorKind::IncompleteEvent => formatter.write_str("an event write is incomplete"),
            ErrorKind::Cancelled => formatter.write_str("an event write was cancelled"),
            ErrorKind::Closed => formatter.write_str("the encoder is closing or closed"),
            ErrorKind::HeaderEncoding => formatter.write_str("could not encode a CBOR header"),
        }
    }
}

impl core::error::Error for Error {}

fn advance_offset(offset: &mut u64, bytes: usize) -> Result<(), ErrorKind> {
    let bytes = u64::try_from(bytes).map_err(|_error| ErrorKind::OffsetOverflow)?;
    *offset = offset.checked_add(bytes).ok_or(ErrorKind::OffsetOverflow)?;
    Ok(())
}

#[cfg(test)]
mod tests;
