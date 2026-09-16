use alloc::{boxed::Box, string::String};
use core::fmt;
use thiserror::Error;
use xolotl_types::{CollectionError, TaintSet, Value};

/// Failures at a state capability boundary.
#[derive(Error)]
pub enum StateError {
    /// A resident collection update exceeded its representable member count.
    #[error("state value update: {0}")]
    ValueUpdate(#[from] CollectionError),
    /// A requested state path or backend object does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// A compare-and-set observed a different value.
    #[error("state comparison did not match")]
    CasFailed {
        /// Canonical path of the comparison.
        path: String,
        /// Expected value, with absence distinct from null.
        expected: Option<Box<Value>>,
        /// Value observed inside the commit boundary.
        actual: Option<Box<Value>>,
    },
    /// Invalid or unsupported persisted encoding.
    #[error("state record encoding is invalid")]
    Serde(String),
    /// A backend reported an operation failure.
    #[error("backend: {0}")]
    Backend(String),
    /// The host did not install this capability.
    #[error("state capability is not installed: {0}")]
    MissingCapability(&'static str),
    /// The request cannot be executed by the selected capability.
    #[error("unsupported state request: {0}")]
    Unsupported(&'static str),
    /// A cursor or query does not belong to the requested scan.
    #[error("invalid state query: {0}")]
    InvalidQuery(String),
    /// The caller may retry this row with more space or explicitly continue after it.
    #[error("state row exceeds page byte budget")]
    RowTooLarge(Box<crate::StateRowTooLarge>),
}

impl fmt::Debug for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ValueUpdate(_) => "ValueUpdate",
            Self::NotFound(_) => "NotFound",
            Self::CasFailed { .. } => "CasFailed",
            Self::Serde(_) => "Serde",
            Self::Backend(_) => "Backend",
            Self::MissingCapability(_) => "MissingCapability",
            Self::Unsupported(_) => "Unsupported",
            Self::InvalidQuery(_) => "InvalidQuery",
            Self::RowTooLarge(_) => "RowTooLarge",
        })
    }
}

/// A failed storage operation and the sources observed before it failed.
///
/// Comparisons, partial scans, and failed decoding still observe data. Backends
/// attach those sources inside the same lock or transaction that observed it;
/// a later point read cannot recover an earlier observation's provenance.
/// Consumers must retain these sources even when handling an error and returning
/// a successful fallback. Display text is diagnostic, not a provenance channel.
#[derive(Error)]
#[error("{error}")]
pub struct StateFailure {
    /// Structured cause. Observed values are available only through explicit
    /// structured inspection, never through the comparison's display text.
    #[source]
    pub error: StateError,
    /// Sources participating in the failed operation's observation.
    pub taint: TaintSet,
}

impl fmt::Debug for StateFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StateFailure")
            .field("error", &self.error)
            .field("has_observed_sources", &!self.taint.is_pristine())
            .finish()
    }
}

impl StateFailure {
    /// Attach sources captured at the operation's observation boundary.
    pub fn new(error: StateError, taint: TaintSet) -> Self {
        Self { error, taint }
    }

    /// Preserve existing sources while adding another observed input or record.
    pub fn with_taint(mut self, taint: &TaintSet) -> Self {
        self.taint.union(taint);
        self
    }
}

impl From<StateError> for StateFailure {
    /// Construct a failure before any additional data has been observed.
    /// After an observation, use [`Self::new`] or [`Self::with_taint`].
    fn from(error: StateError) -> Self {
        Self::new(error, TaintSet::pristine())
    }
}

impl From<CollectionError> for StateFailure {
    fn from(error: CollectionError) -> Self {
        StateError::from(error).into()
    }
}

/// Result of a storage operation, including sources on failure.
pub type StateResult<T> = core::result::Result<T, StateFailure>;

#[cfg(feature = "std")]
impl From<serde_json::Error> for StateError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serde(alloc::string::ToString::to_string(&error))
    }
}

#[cfg(feature = "std")]
impl From<serde_json::Error> for StateFailure {
    fn from(error: serde_json::Error) -> Self {
        StateError::from(error).into()
    }
}
