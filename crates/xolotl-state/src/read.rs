use crate::{StateObservation, StateResult};
use core::{future::Future, num::NonZeroUsize};
use xolotl_types::{Path, Value};

/// Point reads independent of mutation, history, or subscription support.
pub trait StateRead {
    /// Backend-owned request state; immediate backends can return `Ready`.
    type Read<'a>: Future<Output = StateResult<StateObservation>>
    where
        Self: 'a;

    /// Read a value with its provenance from one consistent backend view.
    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a>;
}

/// Explicit value-only projection of a point read.
pub trait StateReadExt: StateRead {
    /// Discard provenance for trusted host metadata.
    fn read<'a>(&'a self, path: &'a Path) -> impl Future<Output = StateResult<Option<Value>>> + 'a {
        async move { Ok(self.read_tainted(path).await?.value) }
    }
}
impl<T: StateRead + ?Sized> StateReadExt for T {}

/// An exact path whose encoded current record exceeded a bounded read or
/// conditional mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatePointTooLarge {
    /// Requested path.
    pub path: Path,
    /// Backend encoded row bytes, including key and provenance.
    pub encoded_bytes: usize,
    /// Maximum encoded row bytes requested by the caller.
    pub limit_encoded_bytes: NonZeroUsize,
    /// Whether the backend observed provenance while measuring the row.
    /// A disk backend can reject using raw bytes without decoding provenance;
    /// in that case this is false and the failure has no current-record taint.
    /// Conditional mutations still retain their known input sources. Missing
    /// current-record sources mean unknown provenance, not a proven untainted record;
    /// callers must fail closed rather than use an untainted fallback.
    pub provenance_observed: bool,
}

/// Exact-path reads with a byte budget enforced before materializing an
/// over-budget result. A persisted backend can check raw bytes before decoding;
/// an in-memory backend checks its already-resident value before cloning it.
/// This capability is independent of unrestricted [`StateRead`]. Sizes use each
/// backend's lossless encoding, including key and provenance; the budget is not
/// a bound on resident heap usage or a later mutation.
pub trait StateBoundedRead {
    /// Backend-owned request state; immediate backends can return `Ready`.
    type BoundedRead<'a>: Future<Output = StateResult<StateObservation>>
    where
        Self: 'a;

    /// Return one exact path or a typed oversized error without copying or
    /// decoding an over-budget value for the result. `StateObservation::value` is None for an absent path.
    fn read_tainted_bounded<'a>(
        &'a self,
        path: &'a Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedRead<'a>;
}

/// Explicit value-only projection of a bounded point read.
pub trait StateBoundedReadExt: StateBoundedRead {
    /// Discard provenance for trusted host metadata.
    fn read_bounded<'a>(
        &'a self,
        path: &'a Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> impl Future<Output = StateResult<Option<Value>>> + 'a {
        async move {
            Ok(self
                .read_tainted_bounded(path, max_encoded_bytes)
                .await?
                .value)
        }
    }
}
impl<T: StateBoundedRead + ?Sized> StateBoundedReadExt for T {}
