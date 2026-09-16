//! Retained operation attempts preserve complete values and their shared graphs.

use super::{BatchSummary, DecisionTag, OperationId};
use crate::{
    HandleId, IdentityRef, MethodId, ProcessId, ReplayClass, ResourceId, TaintSet, Timestamp, Value,
};

mod codec;

#[cfg(test)]
mod tests;

/// Record of one operation attempt. Stores assign an append slot at first begin
/// and update it on completion. Serializing a Fact writes a single shared value
/// table for its input, outcome and batch summaries; no media metadata is lost.
/// Resident payloads and history retention remain host resource choices.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fact {
    /// Attempt identity within the host's retained execution allocator namespace.
    pub id: OperationId,
    /// First-format Fact schema identifier, checked during admission and recovery.
    pub schema_version: u32,
    /// Process that issued the operation.
    pub caller: ProcessId,
    /// Identity the operation ran as.
    pub acting: IdentityRef,
    /// Handle used to authorize and dispatch the operation.
    pub handle: HandleId,
    /// Resource id resolved by the handle.
    pub resource: ResourceId,
    /// Method id invoked on the resource interface.
    pub method: MethodId,
    /// Complete input, sharing its resident storage with the invocation.
    pub input: Value,
    /// Input and output provenance retained for audit and policy decisions.
    /// Missing provenance is never interpreted as pristine data.
    pub taint: TaintSet,
    /// Decision tag for this attempt, including terminal failures and denials.
    pub decision: DecisionTag,
    /// Completed success body. `Some(Value::null())` is a successful unit result;
    /// pending and failed attempts have no success body.
    pub outcome: Option<Value>,
    /// Optional shape and cost summary, retaining the complete input and outcome.
    pub batch: Option<BatchSummary>,
    /// Replay class derived from method purity and operation semantics.
    pub replay: ReplayClass,
    /// Timestamp assigned when the Fact was recorded.
    pub timestamp: Timestamp,
}

impl Fact {
    /// First supported Fact format, preserving complete typed values and sharing.
    pub const SCHEMA_VERSION: u32 = 1;

    /// Whether this attempt completed successfully or has a terminal decision.
    /// Pending attempts have neither a success body nor a failure decision.
    pub fn is_complete(&self) -> bool {
        self.outcome.is_some() || !self.decision.is_ok()
    }
}
