#![no_std]
#![forbid(unsafe_code)]

//! Incremental value validation and optional wire codecs, without an executor.
//!
//! The logical grammar lives in [`xolotl_types::value::event`]. This crate
//! drives its workspace effects through [`validation::KeyStore`]. Callers
//! choose resident key pages or an external workspace; neither field lengths
//! nor cumulative document size are tied to a resident I/O window.
//!
//! The `cbor` feature adds a versioned, lossless event encoding. Wire lineage
//! is data, not authority. A consumer must confirm real EOF and include the
//! actual ingress provenance before publishing an authoritative result.

extern crate alloc;
#[cfg(test)]
extern crate std;

pub mod validation;

#[cfg(feature = "cbor")]
pub mod cbor;
#[cfg(feature = "cbor")]
mod framing;

use core::fmt;
use xolotl_types::value::event::ValidationError;

/// A terminal validation, workspace or wire failure.
#[derive(Debug)]
pub enum Error<E> {
    /// A value event violates the shared logical grammar.
    Validation(ValidationError),
    /// The selected key workspace failed.
    Workspace(E),
    /// The versioned CBOR envelope is invalid or incomplete.
    #[cfg(feature = "cbor")]
    Wire(cbor::WireError),
    /// A failed, cancelled, or finished owner cannot accept more input.
    Closed,
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(error) => error.fmt(formatter),
            Self::Workspace(error) => write!(formatter, "value key workspace failed: {error}"),
            #[cfg(feature = "cbor")]
            Self::Wire(error) => error.fmt(formatter),
            Self::Closed => formatter.write_str("value codec owner is closed"),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for Error<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Validation(error) => Some(error),
            Self::Workspace(error) => Some(error),
            #[cfg(feature = "cbor")]
            Self::Wire(error) => Some(error),
            Self::Closed => None,
        }
    }
}
