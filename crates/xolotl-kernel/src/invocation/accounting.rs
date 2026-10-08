//! Shared charging decisions, independent of account storage and locking.

use super::billable_input_tokens;
use crate::Scope;
use core::future::Future;
use xolotl_types::{
    CostModel, DriverOutput, Failure, MethodContract, OperationId, Outcome, ProcessId,
    ProcessStatus, UsageDimension, Value,
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
    /// releasing concurrency. The host may reconcile the retained estimate.
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

    /// Release concurrency after a failed settlement without refunding uncertain
    /// spending. Retain at least both the estimate and the reported usage in each
    /// dimension. This decision assumes the original reservation is still held.
    pub fn unconfirmed(reserved: Charge, actual: Charge) -> Self {
        Self {
            reserved: Charge::default(),
            actual: Charge {
                micro_usd: actual.micro_usd.saturating_sub(reserved.micro_usd),
                tokens: actual.tokens.saturating_sub(reserved.tokens),
            },
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
    operation: OperationId,
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
            operation: operation.id,
            charge,
            context,
            finalize_allowed: contract.permits_cleanup(operation.process),
        }
    }

    /// The operation's admitted owner.
    pub fn process(self) -> ProcessId {
        self.operation.process
    }

    /// Complete admitted identity, including execution, invocation, position and
    /// retry attempt. Persistent receipts must not be keyed by process alone.
    pub fn operation(self) -> OperationId {
        self.operation
    }

    /// Lifecycle context selected by the trusted request adapter.
    pub fn context(self) -> CallContext {
        self.context
    }

    /// Amount reserved in the caller and all retained ancestor accounts.
    pub fn charge(self) -> Charge {
        self.charge
    }

    /// Check owner, lifecycle, finalizer permission, and budget under
    /// one short exclusive access. A successful body `Finally` uses ordinary
    /// admission; cancellation cleanup requires explicit method permission.
    pub fn reserve_scope(self, scope: &mut Scope) -> Result<(), Failure> {
        if scope.process() != self.process() {
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
    /// only this attempt. The permit owns the reservation until successful
    /// settlement or abandonment. An unresolved storage commit must not permit
    /// later admission against stale account balances.
    fn reserve(&self, request: AccountRequest) -> Result<Self::Permit<'_>, Failure>;
}

/// Trusted ownership of one successful reservation, including its ancestor chain.
pub trait AccountPermit {
    /// Commit failures reported at the invocation boundary. Purely local
    /// accounts can use [`core::convert::Infallible`].
    type Error: Into<Failure>;

    /// A commit may finish immediately or suspend. It owns its commit state,
    /// borrowing neither the permit nor the temporary completion view. It may
    /// retain references already held by the permit. No allocation or `Send`
    /// bound is required; local accounts can use [`core::future::Ready`].
    type Commit: Future<Output = Result<(), Self::Error>> + Unpin;

    /// Commit the evidence required to start this operation. Called once, after
    /// any Fact intent barrier and before even constructing the driver future.
    /// The driver cannot start until the future succeeds. Failure or cancellation
    /// prevents dispatch and is followed by undispatched abandonment, after the
    /// commit future has been dropped.
    fn dispatch(&mut self) -> Self::Commit;

    /// Atomically retain the completion and settle the same accounts, releasing
    /// concurrency exactly once. Account adapters bind their result and account
    /// changes to the completion's admitted operation identity.
    /// Success ends permit ownership. Failure or cancellation is followed by
    /// abandonment using [`Settlement::unconfirmed`], and prevents completion of
    /// the pending Fact. The reservation remains owned while the commit waits.
    /// Keep enough receipt state to reconcile an ambiguous storage commit without
    /// applying the settlement twice or refunding unconfirmed spending.
    /// Encode or retain any completion data needed by the future before returning.
    fn settle(&mut self, completion: AccountCompletion<'_>) -> Self::Commit;

    /// End ownership when dispatch or settlement did not complete successfully,
    /// or the invocation was dropped. This bounded, nonpanicking cleanup releases
    /// concurrency; it cannot await an account commit. The decision is
    /// relative to the original reservation, so adapters must account for any
    /// settlement already applied before an ambiguous commit failure.
    ///
    /// Keep unresolved account receipts for reconciliation. If cleanup cannot
    /// commit, retain the uncertain spend and prevent admission from stale state;
    /// returning here must never assert that an unconfirmed refund succeeded.
    fn abandon(&mut self, settlement: Settlement);
}

/// A known invocation result and the settlement that belongs to it.
/// Constructed only by the invocation boundary after billing and output projection.
/// The adapter can persist the result and all affected accounts in one transaction
/// without retaining a borrow or making the driver produce a storage-specific type.
#[derive(Clone, Copy, Debug)]
pub struct AccountCompletion<'a> {
    operation: OperationId,
    settlement: Settlement,
    output: &'a DriverOutput,
}

impl<'a> AccountCompletion<'a> {
    /// The exact admitted operation, including execution and explicit retry.
    pub fn operation(self) -> OperationId {
        self.operation
    }

    /// Reservation and actual charge computed before output projection.
    pub fn settlement(self) -> Settlement {
        self.settlement
    }

    /// Final invocation result, including input provenance, reported usage and
    /// completion origin. Sink-only payloads have already been discarded; their
    /// actual charge is still retained in the settlement.
    pub fn output(self) -> &'a DriverOutput {
        self.output
    }
}

pub(crate) struct Reservation<P: AccountPermit> {
    permit: P,
    operation: OperationId,
    charge: Charge,
    abandonment: Settlement,
    settled: bool,
}

impl<P: AccountPermit> Reservation<P> {
    pub fn new(permit: P, operation: OperationId, charge: Charge) -> Self {
        Self {
            permit,
            operation,
            charge,
            abandonment: Settlement::cancelled(charge, false),
            settled: false,
        }
    }
    pub fn begin_dispatch(&mut self) -> P::Commit {
        self.permit.dispatch()
    }
    pub fn confirm_dispatch(&mut self) {
        self.abandonment = Settlement::cancelled(self.charge, true);
    }

    /// Retain known usage even if an owned settlement job is rejected before it
    /// can begin. This only changes the Drop fallback; it performs no commit.
    pub fn prepare_settlement(&mut self, actual: Charge) {
        self.abandonment = Settlement::unconfirmed(self.charge, actual);
    }
    pub fn begin_settlement(&mut self, actual: Charge, output: &DriverOutput) -> P::Commit {
        self.prepare_settlement(actual);
        self.permit.settle(AccountCompletion {
            operation: self.operation,
            settlement: Settlement::completed(self.charge, actual),
            output,
        })
    }
    pub fn confirm_settlement(mut self) {
        self.settled = true;
    }
}

impl<P: AccountPermit> Drop for Reservation<P> {
    fn drop(&mut self) {
        if !self.settled {
            self.settled = true;
            self.permit.abandon(self.abandonment);
        }
    }
}
