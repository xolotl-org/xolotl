use xolotl_types::{TaintSet, TaintedValue, Value};

/// Independent ceilings for retained current sourced absences, not history or RSS.
///
/// Each absence charges one record and its full backend encoding plus canonical
/// key bytes. Mutations check both dimensions in the same commit as State and
/// Source changes. Reopening retains usage even when limits are lowered: an
/// already over-limit dimension may stay unchanged or shrink, but may not grow.
/// Replacing an absence with a live value or pristine absence releases its charge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsenceLimits {
    /// Maximum retained records. `None` is unlimited; `Some(0)` forbids growth.
    pub records: Option<usize>,
    /// Maximum encoded record and key bytes. `None` is unlimited.
    pub encoded_bytes: Option<usize>,
}

impl Default for AbsenceLimits {
    fn default() -> Self {
        Self {
            records: Some(65_536),
            encoded_bytes: Some(64 * 1024 * 1024),
        }
    }
}

/// A consistent observation of a value or its absence, with one source set.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[cfg_attr(feature = "std", derive(serde::Serialize))]
pub struct StateObservation {
    /// An existing value, including a stored Null, or observed absence.
    #[cfg_attr(feature = "std", serde(with = "xolotl_types::tagged_value::optional"))]
    pub value: Option<Value>,
    /// Sources controlling the observed value or absence.
    pub taint: TaintSet,
}

impl From<TaintedValue> for StateObservation {
    fn from(value: TaintedValue) -> Self {
        Self {
            value: Some(value.value),
            taint: value.taint,
        }
    }
}
