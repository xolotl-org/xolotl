use xolotl_types::{Path, TaintSet, Value};

/// A committed state mutation with its original provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize))]
pub enum StateEvent {
    /// Replace a path with a value.
    Set {
        /// Path whose stored value was replaced.
        path: Path,
        /// Complete value after the mutation committed.
        #[cfg_attr(feature = "std", serde(with = "xolotl_types::tagged_value"))]
        value: Value,
        /// Provenance stored with the replacement value.
        taint: TaintSet,
    },
    /// Append an item to a sequence.
    Append {
        /// Path of the sequence receiving the item.
        path: Path,
        /// Appended item, rather than the resulting complete sequence.
        #[cfg_attr(feature = "std", serde(with = "xolotl_types::tagged_value"))]
        item: Value,
        /// Sources observed while appending, including the existing sequence.
        taint: TaintSet,
    },
    /// Delete a path.
    Delete {
        /// Path whose stored value was removed.
        path: Path,
        /// Sources observed while deciding and committing this deletion.
        taint: TaintSet,
    },
}

impl StateEvent {
    /// Provenance retained by this mutation, including deletion observations.
    pub fn taint(&self) -> &TaintSet {
        match self {
            Self::Set { taint, .. } | Self::Append { taint, .. } | Self::Delete { taint, .. } => {
                taint
            }
        }
    }

    /// Path changed by this event.
    pub fn path(&self) -> &Path {
        match self {
            Self::Set { path, .. } | Self::Append { path, .. } | Self::Delete { path, .. } => path,
        }
    }
}

/// One committed mutation at its backend-assigned timestamp.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize))]
pub struct StateHistoryEntry {
    /// Timestamp in milliseconds. Mutation ordering is independent of wall-clock regressions.
    pub at_millis: i64,
    /// Committed mutation and provenance.
    pub event: StateEvent,
}
