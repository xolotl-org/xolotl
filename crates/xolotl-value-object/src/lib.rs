#![no_std]
#![forbid(unsafe_code)]

//! Incrementally encode a value into an owned, unpublished object transaction.
//!
//! Select `cbor` for `ValueObjectWriter`. The writer composes the portable
//! value codec and object-write ports, without choosing an executor, filesystem,
//! gateway, or resident workspace. Reference descriptors carry an explicit
//! encoding; they confer no object read authority.
//!
//! This is an explicit encoding boundary. Wire lineage does not supply storage
//! authority. Initial and subsequently observed provenance are merged before
//! commit. Consumers likewise include object metadata and every read chunk's
//! provenance before publishing a decoded State or Fact.

extern crate alloc;
#[cfg(test)]
extern crate std;

mod reference;
pub use reference::{CommittedValue, EncodedValueRef, ReferenceError, ValueEncoding};

#[cfg(feature = "cbor")]
mod failure;
#[cfg(feature = "cbor")]
pub use failure::Failure;

#[cfg(feature = "cbor")]
mod writer;
#[cfg(feature = "cbor")]
pub use writer::{ValueObjectWriter, WriteError, WriteFailure};

#[cfg(feature = "cbor")]
mod reader;
#[cfg(feature = "cbor")]
pub use reader::{ReadError, ReadEvent, ReadFailure, ReadReceipt, ValueObjectReader, read_value};

#[cfg(feature = "cbor")]
mod copy;
#[cfg(feature = "cbor")]
pub use copy::{CopyError, CopyFailure, copy_value};

#[cfg(feature = "cbor")]
mod resident;
#[cfg(feature = "cbor")]
pub use resident::{encode_failure, encode_value};

#[cfg(all(test, feature = "cbor"))]
mod test_support;
