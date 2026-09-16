//! Owned, allocation-optional execution of one admitted invocation.

use core::{
    future::{Future, Ready, ready},
    pin::Pin,
    task::{Context, Poll},
};
use xolotl_types::{
    DecisionTag, DriverOutput, Fact, Failure, Operation, Outcome, OutputMode, ResourceId, TaintSet,
    Value,
};

use super::{
    Account, AccountRequest, Billing, CallContext, GrantedMethod, Invocation, InvocationOptions,
    accounting::Reservation, complete_fact, complete_output,
};

/// A resource implementation receives only the already admitted operation.
/// It cannot choose the invocation's authority, budget, or cleanup context.
pub trait InvocationDriver {
    /// A concrete, local, allocation-free future is supported; boxing is optional.
    type Call<'a>: Future<Output = DriverOutput> + Unpin
    where
        Self: 'a;

    /// Begin one operation after account admission and the required Fact barrier.
    /// The driver implements the output modes declared by its method contract.
    fn call(&self, resource: ResourceId, operation: Operation) -> Self::Call<'_>;
}

/// Write-ahead storage selected by the embedding. A successful `begin` must
/// satisfy the durability promised by that embedding before returning `Ready`.
pub trait FactRecorder {
    /// Both commits may complete synchronously or suspend without a `Send` bound.
    type Commit<'a>: Future<Output = Result<(), Failure>> + Unpin
    where
        Self: 'a;

    /// Record intent before dispatch. Rejection prevents the effect.
    fn begin(&self, fact: Fact) -> Self::Commit<'_>;
    /// Complete the same operation after execution.
    fn complete(&self, fact: Fact) -> Self::Commit<'_>;
}

/// Zero-residency recorder for unrecorded deterministic and observation calls.
/// Effects or explicit recording fail at the barrier before the driver starts.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFacts;

impl FactRecorder for NoFacts {
    type Commit<'a> = Ready<Result<(), Failure>>;
    fn begin(&self, _fact: Fact) -> Self::Commit<'_> {
        ready(Err(Failure::policy(
            "durability",
            "this embedding has no Fact recorder",
        )))
    }
    fn complete(&self, _fact: Fact) -> Self::Commit<'_> {
        ready(Err(Failure::policy(
            "durability",
            "this embedding has no Fact recorder",
        )))
    }
}

/// An actual result remains observable if its post-effect record cannot commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationResult {
    /// Real driver outcome, retaining its reported source order and then adding
    /// input sources that were not already reported.
    pub output: DriverOutput,
    /// The effect already ran; retain its pending record for reconciliation.
    pub completion_error: Option<Failure>,
}

#[derive(Clone, Copy)]
enum Stage {
    Reserve,
    Begin,
    Call,
    Complete,
    Done,
}

/// Named future that owns its input and statically selected adapter futures.
/// There is no mandatory future allocation, mutex, reference counting, or task.
/// Dropping it destroys the driver future before settling its account permit.
pub struct InvocationCall<'a, D: InvocationDriver + 'a, R: FactRecorder + 'a, A: Account + 'a> {
    driver_call: Option<D::Call<'a>>,
    commit: Option<R::Commit<'a>>,
    reservation: Option<Reservation<A::Permit<'a>>>,
    driver: &'a D,
    recorder: &'a R,
    account: &'a A,
    account_request: AccountRequest,
    operation: Option<Operation>,
    resource: ResourceId,
    input_taint: TaintSet,
    sink_only: bool,
    batchable: bool,
    billing: Billing,
    fact: Option<Fact>,
    output: Option<DriverOutput>,
    stage: Stage,
}

/// Admit a trusted invocation and return its owned execution future.
///
/// The embedding resolves handle generations first and chooses `context` from
/// machine/lifecycle state. Only that trusted adapter sees the account port;
/// the resource driver receives the admitted operation after the barrier.
/// Scope cancellation belongs to the embedding: close its scope's admission,
/// then cancel/drop the execution future before running its cleanup programs.
pub fn invoke<'a, D: InvocationDriver, R: FactRecorder, A: Account>(
    operation: Operation,
    grant: GrantedMethod,
    options: InvocationOptions,
    context: CallContext,
    driver: &'a D,
    recorder: &'a R,
    account: &'a A,
) -> Result<InvocationCall<'a, D, R, A>, Failure> {
    let (contract, resource, fact) = {
        let admitted = Invocation::admit(&operation, grant, options)?;
        (
            admitted.contract(),
            admitted.grant.resource,
            admitted.records_fact().then(|| admitted.pending_fact()),
        )
    };
    let billing = Billing::new(&operation.input, contract);
    let account_request = AccountRequest::new(&operation, billing.reservation(), context, contract);
    Ok(InvocationCall {
        driver_call: None,
        commit: None,
        reservation: None,
        driver,
        recorder,
        account,
        account_request,
        input_taint: operation.taint.clone(),
        sink_only: matches!(operation.output, OutputMode::SinkOnly),
        operation: Some(operation),
        resource,
        batchable: contract.batchable,
        billing,
        fact,
        output: None,
        stage: Stage::Reserve,
    })
}

impl<D: InvocationDriver, R: FactRecorder, A: Account> InvocationCall<'_, D, R, A> {
    fn fail(&mut self, failure: Failure) -> Poll<InvocationResult> {
        self.driver_call = None;
        self.commit = None;
        self.reservation = None;
        self.stage = Stage::Done;
        Poll::Ready(InvocationResult {
            output: DriverOutput::new(Outcome::Fail(failure)).with_taint(self.input_taint.clone()),
            completion_error: None,
        })
    }

    fn finish(&mut self, completion_error: Option<Failure>) -> Poll<InvocationResult> {
        self.stage = Stage::Done;
        match self.output.take() {
            Some(output) => Poll::Ready(InvocationResult {
                output,
                completion_error,
            }),
            None => self.fail(Failure::policy(
                "invocation",
                "completed invocation has no output",
            )),
        }
    }
}

impl<D: InvocationDriver, R: FactRecorder, A: Account> Future for InvocationCall<'_, D, R, A> {
    type Output = InvocationResult;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            match this.stage {
                Stage::Reserve => {
                    let permit = match this.account.reserve(this.account_request) {
                        Ok(permit) => permit,
                        Err(failure) => return this.fail(failure),
                    };
                    this.reservation = Some(Reservation::new(permit, this.billing.reservation()));
                    if let Some(fact) = &this.fact {
                        this.commit = Some(this.recorder.begin(fact.clone()));
                        this.stage = Stage::Begin;
                    } else {
                        this.stage = Stage::Call;
                    }
                }
                Stage::Begin => {
                    let result = match &mut this.commit {
                        Some(commit) => core::task::ready!(Pin::new(commit).poll(cx)),
                        None => {
                            return this
                                .fail(Failure::policy("invocation", "missing intent commit"));
                        }
                    };
                    this.commit = None;
                    if let Err(failure) = result {
                        return this.fail(failure);
                    }
                    this.stage = Stage::Call;
                }
                Stage::Call => {
                    if this.driver_call.is_none() {
                        let Some(operation) = this.operation.take() else {
                            return this.fail(Failure::policy("invocation", "missing operation"));
                        };
                        if let Some(reservation) = &mut this.reservation {
                            reservation.dispatch();
                        }
                        this.driver_call = Some(this.driver.call(this.resource, operation));
                    }
                    let output = match &mut this.driver_call {
                        Some(call) => core::task::ready!(Pin::new(call).poll(cx)),
                        None => {
                            return this.fail(Failure::policy("invocation", "missing driver call"));
                        }
                    };
                    this.driver_call = None;
                    let mut output = complete_output(output, &this.input_taint);
                    let actual = this.billing.actual(&output);
                    if this.sink_only {
                        match &mut output.outcome {
                            Outcome::Done(value) | Outcome::Short(value) => *value = Value::null(),
                            Outcome::Fail(_) => {}
                        }
                    }
                    if let Some(reservation) = this.reservation.take() {
                        reservation.complete(actual);
                    }
                    if let Some(fact) = this.fact.take() {
                        let decision = if output.outcome.is_success() {
                            DecisionTag::Ok
                        } else {
                            DecisionTag::DriverError
                        };
                        this.commit = Some(this.recorder.complete(complete_fact(
                            fact,
                            decision,
                            &output,
                            this.batchable,
                        )));
                        this.output = Some(output);
                        this.stage = Stage::Complete;
                    } else {
                        this.output = Some(output);
                        return this.finish(None);
                    }
                }
                Stage::Complete => {
                    let result = match &mut this.commit {
                        Some(commit) => core::task::ready!(Pin::new(commit).poll(cx)),
                        None => {
                            return this
                                .fail(Failure::policy("invocation", "missing outcome commit"));
                        }
                    };
                    this.commit = None;
                    return this.finish(result.err());
                }
                Stage::Done => {
                    return this.fail(Failure::policy(
                        "invocation",
                        "completed invocation was polled again",
                    ));
                }
            }
        }
    }
}

impl<D: InvocationDriver, R: FactRecorder, A: Account> Drop for InvocationCall<'_, D, R, A> {
    fn drop(&mut self) {
        self.driver_call = None;
        self.commit = None;
        self.reservation = None;
    }
}
