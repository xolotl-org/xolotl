//! Program results preserve provenance on both successful and failed paths.

use crate::{Outcome, TaintSet, TaintedFailure, TaintedValue};
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// Maximum identities retained by one execution result.
pub const MAX_UNRESOLVED_OPERATION_IDS: usize = 1024;
/// Maximum UTF-8 bytes retained for one opaque reconciliation identity.
pub const MAX_UNRESOLVED_OPERATION_ID_BYTES: usize = 256;
/// Maximum aggregate UTF-8 bytes retained for reconciliation identities.
pub const MAX_UNRESOLVED_OPERATION_TOTAL_BYTES: usize = 16_384;

/// Host-observed effects whose outcome may still require external reconciliation.
///
/// This accompanies a successful result as well as a failure: `Race` can finish
/// successfully after aborting a losing effect, and Catch can handle an
/// `OutcomeUnknown` error without resolving its external effect. Only the host
/// may add identities observed at an Operation boundary. The public fields are
/// for wire adapters; hosts must validate records received from storage.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnresolvedOperations {
    /// Unique opaque identities, sorted for stable publication.
    pub operation_ids: Vec<String>,
    /// At least one identity could not fit within the retention bounds.
    pub identities_incomplete: bool,
}

impl UnresolvedOperations {
    /// Retain an identity once, or mark the set incomplete if it exceeds a bound.
    /// Returning `false` means the identity was not newly inserted.
    pub fn record(&mut self, operation_id: &str) -> bool {
        if operation_id.is_empty() || operation_id.len() > MAX_UNRESOLVED_OPERATION_ID_BYTES {
            self.identities_incomplete = true;
            return false;
        }
        match self
            .operation_ids
            .binary_search_by(|saved| saved.as_str().cmp(operation_id))
        {
            Ok(_) => false,
            Err(index) => {
                if self.operation_ids.len() >= MAX_UNRESOLVED_OPERATION_IDS {
                    self.identities_incomplete = true;
                    return false;
                }
                let bytes: usize = self.operation_ids.iter().map(String::len).sum();
                if bytes.saturating_add(operation_id.len()) > MAX_UNRESOLVED_OPERATION_TOTAL_BYTES {
                    self.identities_incomplete = true;
                    false
                } else {
                    self.operation_ids.insert(index, String::from(operation_id));
                    true
                }
            }
        }
    }

    /// Combine host-owned evidence without replacing a previously incomplete set.
    pub fn merge(&mut self, other: &Self) {
        for operation_id in &other.operation_ids {
            self.record(operation_id);
        }
        self.identities_incomplete |= other.identities_incomplete;
    }

    /// Check bounds and canonical order before trusting a decoded record.
    pub fn validate(&self) -> bool {
        self.operation_ids.len() <= MAX_UNRESOLVED_OPERATION_IDS
            && self
                .operation_ids
                .iter()
                .all(|id| !id.is_empty() && id.len() <= MAX_UNRESOLVED_OPERATION_ID_BYTES)
            && self.operation_ids.iter().map(String::len).sum::<usize>()
                <= MAX_UNRESOLVED_OPERATION_TOTAL_BYTES
            && self.operation_ids.windows(2).all(|pair| pair[0] < pair[1])
    }

    /// True only when there is no known or omitted identity.
    pub fn is_empty(&self) -> bool {
        self.operation_ids.is_empty() && !self.identities_incomplete
    }
}

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
    /// Host-observed effects whose identities must survive recovery and
    /// publication even if program control flow reports success.
    pub unresolved_operations: UnresolvedOperations,
}

impl ExecutionOutput {
    /// Preserve an outcome and the provenance established with it.
    pub fn new(outcome: Outcome, taint: TaintSet) -> Self {
        Self {
            outcome,
            taint,
            unresolved_operations: UnresolvedOperations::default(),
        }
    }

    /// Attach identities established by the trusted execution host.
    pub fn with_unresolved_operations(mut self, unresolved: UnresolvedOperations) -> Self {
        self.unresolved_operations = unresolved;
        self
    }

    /// Finish the shared control machine without discarding either path's lineage.
    pub fn from_result(result: Result<TaintedValue, TaintedFailure>) -> Self {
        match result {
            Ok(value) => Self::new(Outcome::Done(value.value), value.taint),
            Err(error) => Self::new(Outcome::Fail(error.failure), error.taint),
        }
    }

    /// Split the control result from host-observed effect settlement.
    /// Short-circuited success is a successful value at this program boundary.
    /// Callers composing this execution into another boundary must carry both parts.
    pub fn into_parts(self) -> (Result<TaintedValue, TaintedFailure>, UnresolvedOperations) {
        let result = match self.outcome {
            Outcome::Done(value) | Outcome::Short(value) => {
                Ok(TaintedValue::new(value, self.taint))
            }
            Outcome::Fail(failure) => Err(TaintedFailure::new(failure, self.taint)),
        };
        (result, self.unresolved_operations)
    }
}
