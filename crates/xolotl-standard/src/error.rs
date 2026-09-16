//! Failures retain all sources observed by a Standard capability invocation.
//!
//! Pure admission errors stay ordinary DriverErrors. Once an operation has
//! observed sources, failure is a tagged DriverOutput so lineage reaches the
//! same result boundary as successful values.

use xolotl_kernel::{DriverError, DriverOutput};
use xolotl_state::StateFailure;
use xolotl_types::{Failure, Outcome, TaintSet};

#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub(crate) struct ObservedFailure {
    pub(crate) error: DriverError,
    pub(crate) taint: TaintSet,
}

impl From<DriverError> for ObservedFailure {
    fn from(error: DriverError) -> Self {
        Self {
            error,
            taint: TaintSet::pristine(),
        }
    }
}

impl From<StateFailure> for ObservedFailure {
    fn from(failure: StateFailure) -> Self {
        Self {
            error: DriverError::Other(failure.error.to_string()),
            taint: failure.taint,
        }
    }
}

impl ObservedFailure {
    pub(crate) fn with_taint(mut self, taint: &TaintSet) -> Self {
        self.taint.union(taint);
        self
    }

    pub(crate) fn into_output(self, kind: &str) -> Result<DriverOutput, DriverError> {
        if self.taint.is_pristine() {
            return Err(self.error);
        }
        Ok(DriverOutput::new(Outcome::Fail(Failure::Custom {
            kind: kind.into(),
            message: self.error.to_string(),
        }))
        .with_taint(self.taint))
    }
}
