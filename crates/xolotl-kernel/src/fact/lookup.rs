//! Indexed reads scoped to a record's current caller.

use super::FactError;
use std::num::NonZeroUsize;
use xolotl_types::{Fact, OperationId, ProcessId};

/// A point read with an optional caller filter and an encoded-byte budget.
///
/// The adapter locates the operation and checks its current caller in one locked
/// view or transaction, before copying or decoding the record. A nonmatching
/// caller does not spend the byte budget, even if the record is oversized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactLookup {
    /// Full operation identity to locate by index.
    pub id: OperationId,
    /// Match the current caller, which may differ from `id.process`.
    pub process: Option<ProcessId>,
    /// Maximum JSON encoding length, with the same accounting as [`super::FactQuery`].
    pub max_encoded_bytes: NonZeroUsize,
}

impl FactLookup {
    /// Look up any caller with an explicit encoded-byte budget.
    pub const fn new(id: OperationId, max_encoded_bytes: NonZeroUsize) -> Self {
        Self {
            id,
            process: None,
            max_encoded_bytes,
        }
    }
}

/// Distinguish a missing operation from an existing record outside the filter.
/// Live consumers can ignore filtered notifications while detecting lost records.
#[derive(Clone, Debug, Eq, PartialEq)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep point reads inline rather than adding a heap allocation for every returned Fact."
)]
pub enum FactLookupResult {
    /// The current record matches the query and fits its byte budget.
    Found(Fact),
    /// The operation identity is absent from the store.
    Missing,
    /// The operation exists, but its current caller does not match the filter.
    FilteredOut,
}

impl FactLookupResult {
    #[inline]
    pub(super) fn validate(&self, query: FactLookup) -> Result<(), FactError> {
        match self {
            Self::Found(fact)
                if fact.id != query.id
                    || query.process.is_some_and(|process| fact.caller != process) =>
            {
                Err(FactError(
                    "fact lookup returned a nonmatching record".into(),
                ))
            }
            Self::FilteredOut if query.process.is_none() => Err(FactError(
                "unfiltered fact lookup returned a filtered result".into(),
            )),
            _ => Ok(()),
        }
    }

    #[inline]
    pub(super) fn into_unfiltered(self) -> Result<Option<Fact>, FactError> {
        match self {
            Self::Found(fact) => Ok(Some(fact)),
            Self::Missing => Ok(None),
            Self::FilteredOut => Err(FactError(
                "unfiltered fact lookup returned a filtered result".into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests;
