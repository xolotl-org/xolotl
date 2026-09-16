//! Persistent resident collections and their shared reclamation machinery.

mod assembly;
mod list;
mod map;
mod node;

pub use assembly::{ValueListBuilder, ValueMapBuilder};
pub use list::{ListIter, ValueList};
pub use map::{MapIter, ValueMap};
pub(super) use node::CollectionRoot;

/// A collection change violates its member count or ordered construction contract.
///
/// These errors describe collection semantics. Allocations use the platform's
/// ordinary allocator and do not turn allocation failure into a recoverable
/// collection error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CollectionError {
    /// The resulting number of members exceeds [`usize::MAX`].
    #[error("collection member count exceeds usize::MAX")]
    LengthOverflow,
    /// A sequential map entry is not strictly greater than the previous UTF-8 key.
    #[error("sequential map keys must be unique and strictly increasing by UTF-8 bytes")]
    KeyOrder,
}

#[cfg(test)]
mod tests;
