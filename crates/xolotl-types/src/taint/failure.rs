//! Failures carry the same data and control provenance as successful values.

use alloc::string::ToString;
use core::fmt;
use serde::{Deserialize, Serialize};

use super::{TaintSet, TaintedValue};
use crate::{Failure, Value};

/// A failure whose diagnostic and success/failure decision have known provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaintedFailure {
    /// Domain failure carried through recovery and cleanup scopes.
    pub failure: Failure,
    /// Sources that influenced the failure, including its control dependencies.
    pub taint: TaintSet,
}

impl TaintedFailure {
    /// Preserve a failure and the provenance established with it.
    pub fn new(failure: Failure, taint: TaintSet) -> Self {
        Self { failure, taint }
    }

    /// Construct a static failure with no data-derived provenance.
    /// Runtime control dependencies must still be attached by the caller.
    pub fn pristine(failure: Failure) -> Self {
        Self::new(failure, TaintSet::pristine())
    }

    /// Supply a recovery program with a diagnostic retaining the failure's lineage.
    pub fn into_value(self) -> TaintedValue {
        TaintedValue::new(Value::string(self.failure.to_string()), self.taint)
    }
}

impl From<Failure> for TaintedFailure {
    /// Wrap a static or infrastructure failure before attaching runtime controls.
    fn from(failure: Failure) -> Self {
        Self::pristine(failure)
    }
}

impl fmt::Display for TaintedFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.failure.fmt(formatter)
    }
}

impl core::error::Error for TaintedFailure {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(&self.failure)
    }
}
