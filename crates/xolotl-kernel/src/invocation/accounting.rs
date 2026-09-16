//! Shared charging decisions, independent of account storage and locking.

use super::billable_input_tokens;
use crate::Scope;
use xolotl_types::{
    CostModel, DriverOutput, Failure, MethodContract, Outcome, ProcessId, ProcessStatus,
    UsageDimension, Value,
};

/// Spending held at admission or measured after a call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Charge {
    /// Monetary charge in millionths of a US dollar.
    pub micro_usd: u64,
    /// Token charge counted by the scope budget.
    pub tokens: u64,
}

/// Compact pricing context retained without keeping an operation's input alive.
#[derive(Clone, Copy, Debug)]
pub struct Billing {
    cost: CostModel,
    input_tokens: u64,
    free: bool,
}

impl Billing {
    /// Freeze the admitted cost model and input estimate before dispatch.
    pub fn new(input: &Value, contract: MethodContract) -> Self {
        let mut cost = contract.cost;
        if contract.batchable
            && let Some(items) = input.as_list()
        {
            cost.flat_micro_usd = cost.flat_micro_usd.saturating_mul(items.len() as u64);
        }
        Self {
            cost,
            input_tokens: if contract.cost.is_free() {
                0
            } else {
                billable_input_tokens(input)
            },
            free: contract.cost.is_free(),
        }
    }

    /// Estimated output capacity, charged before any effect can begin.
    pub fn reservation(self) -> Charge {
        let tokens = if self.free { 0 } else { self.input_tokens };
        Charge {
            micro_usd: self.cost.estimate_micro_usd(tokens, tokens),
            tokens,
        }
    }

    /// Measured usage takes precedence over estimates, including explicit zero.
    pub fn actual(self, output: &DriverOutput) -> Charge {
        if self.free
            && output
                .usage
                .as_ref()
                .and_then(|usage| usage.get(&UsageDimension::OUTPUT_TOKENS))
                .is_none()
        {
            return Charge::default();
        }
        let input_tokens = output
            .usage
            .as_ref()
            .and_then(|usage| usage.get(&UsageDimension::INPUT_TOKENS))
            .copied()
            .unwrap_or(self.input_tokens);
        let output_tokens = output
            .usage
            .as_ref()
            .and_then(|usage| usage.get(&UsageDimension::OUTPUT_TOKENS))
            .copied()
            .unwrap_or_else(|| match &output.outcome {
                Outcome::Done(value) | Outcome::Short(value) => billable_input_tokens(value),
                Outcome::Fail(_) => 0,
            });
        Charge {
            micro_usd: self.cost.estimate_micro_usd(input_tokens, output_tokens),
            tokens: output_tokens,
        }
    }
}

/// Exactly one settlement releases one in-flight call from every reserved account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settlement {
    /// Amount to remove from the reservation already present in budget counters.
    pub reserved: Charge,
    /// Known usage to add after releasing the reservation.
    pub actual: Charge,
}

impl Settlement {
    /// Reconcile a completed call against its known usage.
    pub fn completed(reserved: Charge, actual: Charge) -> Self {
        Self { reserved, actual }
    }

    /// Refund before dispatch; after dispatch retain the uncertain spend while
    /// releasing concurrency. Later recovery may reconcile the retained estimate.
    pub fn cancelled(reserved: Charge, dispatched: bool) -> Self {
        Self {
            reserved: if dispatched {
                Charge::default()
            } else {
                reserved
            },
            actual: Charge::default(),
        }
    }

    /// Apply the shared decision to one owner or retained ancestor.
    pub fn apply(self, scope: &mut Scope) {
        scope.settle(
            self.reserved.micro_usd,
            self.actual.micro_usd,
            self.reserved.tokens,
            self.actual.tokens,
        );
    }
}

/// Execution context chosen by the trusted embedding, never by driver input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallContext {
    /// Ordinary execution requires a running, open scope.
    Body,
    /// A `Finally` request emitted by the control machine.
    Cleanup,
    /// A lifecycle finalizer owned by the embedding's finalization attempt.
    Finalizer,
}

/// Bound account admission. Only the invocation boundary constructs this token.
#[derive(Clone, Copy, Debug)]
pub struct AccountRequest {
    process: ProcessId,
    charge: Charge,
    context: CallContext,
    finalize_allowed: bool,
}

impl AccountRequest {
    pub(super) fn new(
        operation: &xolotl_types::Operation,
        charge: Charge,
        context: CallContext,
        contract: MethodContract,
    ) -> Self {
        Self {
            process: operation.process,
            charge,
            context,
            finalize_allowed: contract.permits_cleanup(operation.process),
        }
    }

    /// The operation's admitted owner.
    pub fn process(self) -> ProcessId {
        self.process
    }

    /// Amount reserved in the caller and all retained ancestor accounts.
    pub fn charge(self) -> Charge {
        self.charge
    }

    /// Check owner, lifecycle, finalizer permission, and budget under
    /// one short exclusive access. A successful body `Finally` uses ordinary
    /// admission; cancellation cleanup requires explicit method permission.
    pub fn reserve_scope(self, scope: &mut Scope) -> Result<(), Failure> {
        if scope.process() != self.process {
            return Err(Failure::policy(
                "account",
                "scope owner disagrees with operation",
            ));
        }
        let Charge { micro_usd, tokens } = self.charge;
        let result = match self.context {
            CallContext::Body => scope.reserve(micro_usd, tokens),
            CallContext::Cleanup
                if scope.status() == ProcessStatus::Running && scope.accepts_children() =>
            {
                scope.reserve(micro_usd, tokens)
            }
            CallContext::Cleanup if self.finalize_allowed => {
                scope.reserve_cleanup(micro_usd, tokens)
            }
            CallContext::Finalizer if self.finalize_allowed => {
                scope.reserve_finalizer(micro_usd, tokens)
            }
            _ => {
                return Err(Failure::policy(
                    "finalize",
                    "method is not allowed during finalization",
                ));
            }
        };
        result.map_err(|dim| Failure::BudgetExhausted { dim })
    }

    /// Charge a previously validated ancestor even after its own body completes.
    /// The embedding validates ancestry and rolls back this invocation's earlier
    /// reservations if any account in the same admission transaction rejects it.
    pub fn reserve_ancestor(self, scope: &mut Scope) -> Result<(), Failure> {
        scope
            .reserve_descendant(self.charge.micro_usd, self.charge.tokens)
            .map_err(|dim| Failure::BudgetExhausted { dim })
    }
}

/// Storage adapter for short, atomic account admission. No guard or exclusive
/// borrow may be retained in the returned permit across driver suspension.
pub trait Account {
    /// Captures the same account chain used during reservation.
    type Permit<'a>: AccountPermit + Unpin
    where
        Self: 'a;

    /// Reserve the caller and all ancestors atomically; failures must roll back
    /// only this attempt. The returned permit is settled exactly once.
    fn reserve(&self, request: AccountRequest) -> Result<Self::Permit<'_>, Failure>;
}

/// Trusted ownership of one successful reservation, including its ancestor chain.
pub trait AccountPermit {
    /// Apply a shared decision to the same accounts. This must be infallible,
    /// release concurrency exactly once, and never retain a lock across a poll.
    fn settle(&mut self, settlement: Settlement);
}

pub(crate) struct Reservation<P: AccountPermit> {
    permit: P,
    charge: Charge,
    dispatched: bool,
    settled: bool,
}

impl<P: AccountPermit> Reservation<P> {
    pub fn new(permit: P, charge: Charge) -> Self {
        Self {
            permit,
            charge,
            dispatched: false,
            settled: false,
        }
    }
    pub fn dispatch(&mut self) {
        self.dispatched = true;
    }
    pub fn complete(mut self, actual: Charge) {
        self.settled = true;
        self.permit
            .settle(Settlement::completed(self.charge, actual));
    }
}

impl<P: AccountPermit> Drop for Reservation<P> {
    fn drop(&mut self) {
        if !self.settled {
            self.settled = true;
            self.permit
                .settle(Settlement::cancelled(self.charge, self.dispatched));
        }
    }
}
