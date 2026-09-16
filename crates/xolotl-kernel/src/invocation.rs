//! Platform-independent admission and records for one capability invocation.
//!
//! A completion preserves its reported source order, then appends input sources
//! not already reported. This applies to successful and failed outcomes on every
//! host. A Fact owns its audit sequence separately: input sources precede output
//! observations in the record.

use xolotl_types::{
    DecisionTag, DriverOutput, Fact, Failure, IdentityRef, MethodContract, Operation, ProcessId,
    ReplayClass, ResourceId, Rights, TaintSet, Timestamp,
};

mod accounting;
mod execute;
#[cfg(feature = "host")]
pub(crate) use accounting::Reservation;
pub use accounting::{
    Account, AccountPermit, AccountRequest, Billing, CallContext, Charge, Settlement,
};
pub use execute::{
    FactRecorder, InvocationCall, InvocationDriver, InvocationResult, NoFacts, invoke,
};

/// Host observations supplied for one invocation, independent of method rules.
#[derive(Clone, Copy, Debug)]
pub struct InvocationOptions {
    /// Wall clock used by policy and operation records.
    pub now_millis: i64,
    /// Retain a Fact even for a deterministic call whose output is unconsumed.
    pub record: bool,
}

/// Estimate inline token usage when a driver reports no measurement.
pub fn billable_input_tokens(value: &xolotl_types::Value) -> u64 {
    value.approx_tokens()
}

/// Apply the admitted cost model, including per-element flat batch charges.
pub fn estimate_cost(
    cost: &xolotl_types::CostModel,
    input: &xolotl_types::Value,
    in_tokens: u64,
    out_tokens: u64,
    batchable: bool,
) -> u64 {
    match (batchable, input.as_list()) {
        (true, Some(items)) => cost
            .flat_micro_usd
            .saturating_mul(items.len() as u64)
            .saturating_add(
                xolotl_types::CostModel {
                    flat_micro_usd: 0,
                    ..*cost
                }
                .estimate_micro_usd(in_tokens, out_tokens),
            ),
        _ => cost.estimate_micro_usd(in_tokens, out_tokens),
    }
}

/// An opened method after generation and delegation ancestry validation.
pub struct GrantedMethod {
    /// Process that owns the handle.
    pub owner: ProcessId,
    /// Identity whose policy was compiled at open time.
    pub acting: IdentityRef,
    /// Rights attenuated at open or delegation time.
    pub rights: Rights,
    /// Resource selected by the opened handle.
    pub resource: ResourceId,
    /// Frozen method rules from the selected dispatch entry.
    pub contract: MethodContract,
}

/// Admission and Fact semantics shared by portable and hosted dispatch.
pub struct Invocation<'a> {
    operation: &'a Operation,
    grant: GrantedMethod,
    options: InvocationOptions,
}

impl<'a> Invocation<'a> {
    /// Validate caller, acting identity, method rights and requested output.
    /// The host validates handle generation and active delegation ancestry first.
    pub fn admit(
        operation: &'a Operation,
        grant: GrantedMethod,
        options: InvocationOptions,
    ) -> Result<Self, Failure> {
        if operation.id.process != operation.process || operation.process != grant.owner {
            return Err(Failure::policy(
                "owner",
                "operation identity and handle owner disagree",
            ));
        }
        if operation.acting != grant.acting {
            return Err(Failure::policy(
                "acting",
                "handle was opened for another identity",
            ));
        }
        if !grant.rights.methods.allows(grant.contract.method_index) {
            return Err(Failure::PermissionDenied {
                required: alloc::vec![],
                actual: alloc::vec![],
            });
        }
        if !operation.output.is_supported_by(grant.contract.supports) {
            return Err(Failure::InvalidInput {
                reason: alloc::format!("unsupported output mode {:?}", operation.output),
            });
        }
        if grant.contract.requires_unprotected_input && operation.taint.has_protected() {
            return Err(Failure::policy(
                "taint",
                "method requires unprotected input",
            ));
        }
        Ok(Self {
            operation,
            grant,
            options,
        })
    }

    /// Execution metadata bound to the admitted method.
    pub fn contract(&self) -> MethodContract {
        self.grant.contract
    }

    /// Effects and process creation always require a write-ahead record.
    pub fn records_fact(&self) -> bool {
        self.options.record
            || matches!(
                self.grant.contract.replay,
                ReplayClass::IdempotentEffect | ReplayClass::NonIdempotentEffect
            )
            || matches!(
                self.operation.output,
                xolotl_types::OutputMode::AsyncProcess
            )
    }

    /// Intent record that must be committed before an external effect starts.
    pub fn pending_fact(&self) -> Fact {
        operation_fact(
            self.operation,
            self.grant.resource,
            self.grant.contract.replay,
            self.options.now_millis,
            DecisionTag::Ok,
        )
    }

    /// Record the returned value and sources, preserving the Fact's audit order:
    /// input sources precede newly reported output observations.
    pub fn completed_fact(&self, decision: DecisionTag, output: &DriverOutput) -> Fact {
        complete_fact(
            self.pending_fact(),
            decision,
            output,
            self.grant.contract.batchable,
        )
    }
}

pub(crate) fn complete_output(mut output: DriverOutput, input_taint: &TaintSet) -> DriverOutput {
    output.taint.union(input_taint);
    output
}

fn complete_fact(
    mut fact: Fact,
    decision: DecisionTag,
    output: &DriverOutput,
    batchable: bool,
) -> Fact {
    fact.decision = decision;
    fact.taint.union(&output.taint);
    fact.outcome = match &output.outcome {
        xolotl_types::Outcome::Done(value) | xolotl_types::Outcome::Short(value) => {
            Some(value.clone())
        }
        xolotl_types::Outcome::Fail(_) => None,
    };
    if batchable {
        fact.batch = xolotl_types::BatchSummary::new(&fact.input, fact.outcome.as_ref());
    }
    fact
}

/// Record a denied invocation, including denials before a method is resolved.
pub fn denied_fact(
    operation: &Operation,
    resource: Option<ResourceId>,
    replay: ReplayClass,
    now_millis: i64,
    decision: DecisionTag,
) -> Fact {
    operation_fact(
        operation,
        resource.unwrap_or_else(|| ResourceId::new(0)),
        replay,
        now_millis,
        decision,
    )
}

fn operation_fact(
    operation: &Operation,
    resource: ResourceId,
    replay: ReplayClass,
    now_millis: i64,
    decision: DecisionTag,
) -> Fact {
    Fact {
        id: operation.id,
        schema_version: Fact::SCHEMA_VERSION,
        caller: operation.process,
        acting: operation.acting,
        handle: operation.handle,
        resource,
        method: operation.method,
        input: if matches!(decision, DecisionTag::Denied) {
            xolotl_types::Value::null()
        } else {
            operation.input.clone()
        },
        taint: operation.taint.clone(),
        decision,
        outcome: None,
        batch: None,
        replay,
        timestamp: Timestamp::millis(now_millis),
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "typed setup failures propagate while assertions diagnose invocation contract failures"
)]
mod tests;
