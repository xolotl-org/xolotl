//! Program results preserve provenance on both successful and failed paths.

use crate::{Outcome, TaintSet, TaintedFailure, TaintedValue};

/// The result and control-flow provenance of one program evaluation.
///
/// Invocation usage and cache origin belong to the individual call boundary.
/// Evaluating a program may combine new work with cached calls, so those call
/// properties are not metadata of the resulting value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionOutput {
    /// Successful value or failure produced by the evaluation.
    pub outcome: Outcome,
    /// Sources that influenced the result, including success/failure selection.
    pub taint: TaintSet,
}

impl ExecutionOutput {
    /// Preserve an outcome and the provenance established with it.
    pub fn new(outcome: Outcome, taint: TaintSet) -> Self {
        Self { outcome, taint }
    }

    /// Finish the shared control machine without discarding either path's lineage.
    pub fn from_result(result: Result<TaintedValue, TaintedFailure>) -> Self {
        match result {
            Ok(value) => Self::new(Outcome::Done(value.value), value.taint),
            Err(error) => Self::new(Outcome::Fail(error.failure), error.taint),
        }
    }

    /// Compose this result into another computation while retaining its lineage.
    /// Short-circuited success is a successful value at this program boundary.
    pub fn into_result(self) -> Result<TaintedValue, TaintedFailure> {
        match self.outcome {
            Outcome::Done(value) | Outcome::Short(value) => {
                Ok(TaintedValue::new(value, self.taint))
            }
            Outcome::Fail(failure) => Err(TaintedFailure::new(failure, self.taint)),
        }
    }
}
