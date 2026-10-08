//! Owned, allocation-optional execution of one admitted invocation.

use core::{
    future::{Future, Ready, ready},
    pin::Pin,
    task::{Context, Poll},
};
use xolotl_types::{
    DecisionTag, DriverOutput, Fact, Failure, Operation, Outcome, OutputMode, ResourceId, TaintSet,
};

use super::{
    Account, AccountPermit, AccountRequest, Billing, CallContext, GrantedMethod, Invocation,
    InvocationOptions, accounting::Reservation, complete_fact, complete_output,
};

/// A resource implementation receives only the already admitted operation.
/// It cannot choose the invocation's authority, budget, or cleanup context.
pub trait InvocationDriver {
    /// A concrete, local, allocation-free future is supported; boxing is optional.
    type Call<'a>: Future<Output = DriverOutput> + Unpin
    where
        Self: 'a;

    /// Begin one operation after account admission, any selected Fact barrier,
    /// and the account's dispatch commit.
    /// The driver implements the output modes declared by its method contract.
    fn call(&self, resource: ResourceId, operation: Operation) -> Self::Call<'_>;
}

/// Optional invocation records selected by the embedding. A successful `begin`
/// satisfies the recording guarantees promised by that embedding.
pub trait FactRecorder {
    /// Both commits may complete synchronously or suspend without a `Send` bound.
    type Commit<'a>: Future<Output = Result<(), Failure>> + Unpin
    where
        Self: 'a;

    /// Record intent before dispatch. Rejection prevents the effect.
    fn begin(&self, fact: Fact) -> Self::Commit<'_>;
    /// Complete the same operation after account settlement, or record a
    /// pre-dispatch denial. An account settlement failure skips this commit.
    fn complete(&self, fact: Fact) -> Self::Commit<'_>;
}

/// Zero-residency recorder for any unrecorded invocation.
/// Explicit recording fails at the barrier before the driver starts.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFacts;

impl FactRecorder for NoFacts {
    type Commit<'a> = Ready<Result<(), Failure>>;
    fn begin(&self, _fact: Fact) -> Self::Commit<'_> {
        ready(Err(Failure::policy(
            "recording",
            "this embedding has no Fact recorder",
        )))
    }
    fn complete(&self, _fact: Fact) -> Self::Commit<'_> {
        ready(Err(Failure::policy(
            "recording",
            "this embedding has no Fact recorder",
        )))
    }
}

/// A failed invocation boundary. Dispatch failures have no new driver result;
/// settlement, optional Fact and output-delivery errors preserve any outcome
/// already produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CompletionError {
    /// Dispatch admission failed; no new driver call was made at this boundary.
    Dispatch(Failure),
    /// Account settlement failed; any pending Fact has not been completed.
    Settlement(Failure),
    /// Optional Fact completion failed after settlement or a pre-dispatch denial.
    /// This diagnostic does not invalidate the known invocation outcome.
    Fact(Failure),
    /// The stream's prefix or terminal delivery could not be confirmed after
    /// the invocation returned.
    Output(Failure),
}

impl CompletionError {
    /// Failure reported by the adapter at this commit boundary.
    pub fn failure(&self) -> &Failure {
        match self {
            Self::Dispatch(failure)
            | Self::Settlement(failure)
            | Self::Fact(failure)
            | Self::Output(failure) => failure,
        }
    }

    /// Whether a required account commit or output handoff remains unconfirmed.
    /// Optional Fact recording alone cannot interrupt a known outcome. Dispatch
    /// failure reports no new driver call; its original failure remains available.
    pub fn requires_interruption(&self) -> bool {
        matches!(self, Self::Settlement(_) | Self::Output(_))
    }

    /// Stop control flow for an unconfirmed required commit or output handoff.
    /// Call only when [`Self::requires_interruption`] or independent effect
    /// evidence establishes uncertainty, never merely for optional Fact failure.
    /// This does not authorize retry; retain the original [`InvocationResult`]
    /// and its known driver outcome for reconciliation.
    pub fn outcome_unknown(&self, operation: xolotl_types::OperationId) -> Failure {
        Failure::OutcomeUnknown {
            operation_ids: alloc::vec![alloc::format!("{operation}")],
            reason: alloc::format!("invocation completion is unconfirmed: {self}"),
        }
    }
}

impl core::fmt::Display for CompletionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let stage = match self {
            Self::Dispatch(_) => "dispatch admission",
            Self::Settlement(_) => "account settlement",
            Self::Fact(_) => "Fact completion",
            Self::Output(_) => "stream output commit",
        };
        write!(formatter, "{stage}: {}", self.failure())
    }
}

impl core::error::Error for CompletionError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        Some(self.failure())
    }
}

/// The actual outcome remains observable if accounting or Fact completion fails.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use = "inspect completion_error before acknowledging or retrying the invocation"]
pub struct InvocationResult {
    /// Real driver outcome, retaining its reported source order and then adding
    /// input sources that were not already reported.
    pub output: DriverOutput,
    /// Accounting, Fact, or stream output completion failed. The output still describes the
    /// actual driver result or pre-dispatch denial. Selected recording remains
    /// unconfirmed even if a failed commit left visible outcome bytes. This error
    /// alone never makes an effect safe to retry.
    /// Required settlement or uncertain dispatch errors take precedence over
    /// later delivery errors; delivery errors take precedence over optional
    /// Fact diagnostics, which may instead be reported through host tracing.
    pub completion_error: Option<CompletionError>,
    /// The host entered an effect boundary, or reused a result from one.
    /// A completion error for a pre-dispatch denial must not be presented as an
    /// unresolved external effect merely because its denial Fact also failed.
    pub effect_may_have_started: bool,
}

impl InvocationResult {
    /// An outcome with no reported completion error. This constructor performs
    /// no commits; the invocation adapter is responsible for confirming them.
    pub fn new(output: DriverOutput) -> Self {
        Self {
            output,
            completion_error: None,
            effect_may_have_started: false,
        }
    }
}

#[derive(Clone, Copy)]
enum Stage {
    Reserve,
    Begin,
    Dispatch,
    Call,
    Settle,
    Complete,
    Done,
}

/// Named future that owns its input and statically selected adapter futures.
/// There is no mandatory future allocation, mutex, reference counting, or task.
/// Dropping it destroys driver and commit futures before abandoning its account
/// permit, including cancellation during dispatch or settlement commits.
pub struct InvocationCall<'a, D: InvocationDriver + 'a, R: FactRecorder + 'a, A: Account + 'a> {
    driver_call: Option<D::Call<'a>>,
    commit: Option<R::Commit<'a>>,
    account_commit: Option<<A::Permit<'a> as AccountPermit>::Commit>,
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
    result: Option<InvocationResult>,
    stage: Stage,
    effect_may_have_started: bool,
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
        account_commit: None,
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
        result: None,
        stage: Stage::Reserve,
        effect_may_have_started: false,
    })
}

impl<D: InvocationDriver, R: FactRecorder, A: Account> InvocationCall<'_, D, R, A> {
    /// Admitted operation identity, retained through completion and interruption.
    pub fn operation(&self) -> xolotl_types::OperationId {
        self.account_request.operation()
    }

    /// Whether this invocation has crossed the driver dispatch boundary.
    /// This remains true after completion is consumed: cancellation or dropping
    /// the future after dispatch cannot prove that the effect did not happen.
    /// It is false for admission, reservation, and dispatch-barrier rejection.
    pub fn effect_may_have_started(&self) -> bool {
        self.effect_may_have_started
    }

    fn record_completion(&mut self, result: InvocationResult, decision: DecisionTag) {
        self.commit = self.fact.take().map(|fact| {
            self.recorder.complete(complete_fact(
                fact,
                decision,
                &result.output,
                self.batchable,
            ))
        });
        self.result = Some(result);
        self.stage = Stage::Complete;
    }

    fn fail(&mut self, failure: Failure) -> Poll<InvocationResult> {
        self.driver_call = None;
        self.commit = None;
        self.account_commit = None;
        self.reservation = None;
        self.stage = Stage::Done;
        Poll::Ready(InvocationResult {
            output: DriverOutput::new(Outcome::Fail(failure)).with_taint(self.input_taint.clone()),
            completion_error: None,
            effect_may_have_started: false,
        })
    }

    fn finish(&mut self, completion_error: Option<CompletionError>) -> Poll<InvocationResult> {
        self.stage = Stage::Done;
        match self.result.take() {
            Some(mut result) => {
                result.completion_error = completion_error;
                Poll::Ready(result)
            }
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
                    this.reservation = Some(Reservation::new(
                        permit,
                        this.account_request.operation(),
                        this.billing.reservation(),
                    ));
                    if let Some(fact) = &this.fact {
                        this.commit = Some(this.recorder.begin(fact.clone()));
                        this.stage = Stage::Begin;
                    } else {
                        this.stage = Stage::Dispatch;
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
                    this.stage = Stage::Dispatch;
                }
                Stage::Dispatch => {
                    let Some(reservation) = &mut this.reservation else {
                        return this.fail(Failure::policy("invocation", "missing reservation"));
                    };
                    let commit = this
                        .account_commit
                        .get_or_insert_with(|| reservation.begin_dispatch());
                    let result = core::task::ready!(Pin::new(commit).poll(cx));
                    this.account_commit = None;
                    if let Err(failure) = result {
                        this.reservation = None;
                        this.record_completion(
                            InvocationResult::new(
                                DriverOutput::new(Outcome::Fail(failure.into()))
                                    .with_taint(this.input_taint.clone()),
                            ),
                            DecisionTag::Denied,
                        );
                        continue;
                    }
                    reservation.confirm_dispatch();
                    let Some(operation) = this.operation.take() else {
                        return this.fail(Failure::policy("invocation", "missing operation"));
                    };
                    this.effect_may_have_started = true;
                    this.driver_call = Some(this.driver.call(this.resource, operation));
                    this.stage = Stage::Call;
                }
                Stage::Call => {
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
                        output.outcome = super::sink_outcome(output.outcome);
                    }
                    let Some(reservation) = &mut this.reservation else {
                        return this.fail(Failure::policy("invocation", "missing reservation"));
                    };
                    this.account_commit = Some(reservation.begin_settlement(actual, &output));
                    this.result = Some(InvocationResult {
                        output,
                        completion_error: None,
                        effect_may_have_started: true,
                    });
                    this.stage = Stage::Settle;
                }
                Stage::Settle => {
                    let result = match &mut this.account_commit {
                        Some(commit) => core::task::ready!(Pin::new(commit).poll(cx)),
                        None => {
                            return this
                                .fail(Failure::policy("invocation", "missing settlement commit"));
                        }
                    };
                    this.account_commit = None;
                    if let Err(failure) = result {
                        this.reservation = None;
                        return this.finish(Some(CompletionError::Settlement(failure.into())));
                    }
                    let Some(reservation) = this.reservation.take() else {
                        return this.fail(Failure::policy("invocation", "missing reservation"));
                    };
                    reservation.confirm_settlement();
                    let Some(result) = this.result.take() else {
                        return this.fail(Failure::policy("invocation", "missing output"));
                    };
                    let decision = if result.output.outcome.is_success() {
                        DecisionTag::Ok
                    } else {
                        DecisionTag::DriverError
                    };
                    this.record_completion(result, decision);
                }
                Stage::Complete => {
                    let result = match &mut this.commit {
                        Some(commit) => core::task::ready!(Pin::new(commit).poll(cx)),
                        None => Ok(()),
                    };
                    this.commit = None;
                    return this.finish(result.err().map(CompletionError::Fact));
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
        self.account_commit = None;
        self.reservation = None;
    }
}
