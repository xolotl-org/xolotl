use super::*;
use crate::Scope;
use alloc::{rc::Rc, vec, vec::Vec};
use core::{
    cell::{Cell, RefCell},
    future::{Future, Ready, ready},
    pin::Pin,
    task::{Context, Poll, Waker},
};
use xolotl_types::{
    BudgetSpec, BudgetState, CausalPosition, CompletionOrigin, CostModel, ExecutionId, HandleId,
    InvocationId, MethodBitmap, MethodId, OperationId, Outcome, OutputMode, OutputModeSet,
    ProcessStatus, RightFlags, TaintSet, TaintSource, UsageDimension, Value,
};

type Events = Rc<RefCell<Vec<&'static str>>>;

#[cfg(feature = "host")]
mod hosted;
mod runtime;

struct Accounts {
    scopes: RefCell<Vec<Scope>>,
    events: Events,
}

impl Accounts {
    fn new(events: &Events) -> Self {
        let mut scope = Scope::new(ProcessId::new(1), IdentityRef::ROOT);
        assert!(scope.start());
        Self {
            scopes: RefCell::new(vec![scope]),
            events: events.clone(),
        }
    }
    fn budget(&self) -> BudgetState {
        self.scopes.borrow()[0].budget().clone()
    }
}

struct Permit<'a> {
    accounts: &'a Accounts,
    count: usize,
}

impl AccountPermit for Permit<'_> {
    fn settle(&mut self, settlement: Settlement) {
        for scope in self
            .accounts
            .scopes
            .borrow_mut()
            .iter_mut()
            .take(self.count)
        {
            settlement.apply(scope);
        }
        self.accounts.events.borrow_mut().push("settled");
    }
}

impl Account for Accounts {
    type Permit<'a> = Permit<'a>;
    fn reserve(&self, request: AccountRequest) -> Result<Self::Permit<'_>, Failure> {
        let mut scopes = self.scopes.borrow_mut();
        request.reserve_scope(&mut scopes[0])?;
        for index in 1..scopes.len() {
            if let Err(error) = request.reserve_ancestor(&mut scopes[index]) {
                for scope in &mut scopes[..index] {
                    Settlement::cancelled(request.charge(), false).apply(scope);
                }
                return Err(error);
            }
        }
        self.events.borrow_mut().push("reserved");
        Ok(Permit {
            accounts: self,
            count: scopes.len(),
        })
    }
}

struct Driver {
    events: Events,
    ready: Cell<bool>,
    calls: Cell<usize>,
    output: DriverOutput,
}

impl Driver {
    fn new(events: &Events) -> Self {
        Self {
            events: events.clone(),
            ready: Cell::new(true),
            calls: Cell::new(0),
            output: DriverOutput::new(Outcome::Done(Value::string("abcdefgh".into()))),
        }
    }
}

struct DriverCall<'a>(&'a Driver);
impl Future for DriverCall<'_> {
    type Output = DriverOutput;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.0.ready.get() {
            Poll::Ready(self.0.output.clone())
        } else {
            Poll::Pending
        }
    }
}
impl Drop for DriverCall<'_> {
    fn drop(&mut self) {
        self.0.events.borrow_mut().push("driver dropped");
    }
}
impl InvocationDriver for Driver {
    type Call<'a> = DriverCall<'a>;
    fn call(&self, resource: ResourceId, _operation: Operation) -> Self::Call<'_> {
        assert_eq!(resource, ResourceId::new(9));
        self.calls.set(self.calls.get() + 1);
        self.events.borrow_mut().push("driver started");
        DriverCall(self)
    }
}

struct Recorder {
    events: Events,
    facts: RefCell<Vec<Fact>>,
    begin_ready: Cell<bool>,
    fail_begin: bool,
    fail_complete: bool,
}
impl Recorder {
    fn new(events: &Events) -> Self {
        Self {
            events: events.clone(),
            facts: RefCell::default(),
            begin_ready: Cell::new(true),
            fail_begin: false,
            fail_complete: false,
        }
    }
}
struct Commit<'a> {
    recorder: &'a Recorder,
    fact: Option<Fact>,
    begin: bool,
}
impl Future for Commit<'_> {
    type Output = Result<(), Failure>;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.begin && !this.recorder.begin_ready.get() {
            return Poll::Pending;
        }
        if (this.begin && this.recorder.fail_begin) || (!this.begin && this.recorder.fail_complete)
        {
            return Poll::Ready(Err(Failure::policy("test", "commit failed")));
        }
        if let Some(fact) = this.fact.take() {
            this.recorder.facts.borrow_mut().push(fact);
        }
        this.recorder.events.borrow_mut().push(if this.begin {
            "intent committed"
        } else {
            "outcome committed"
        });
        Poll::Ready(Ok(()))
    }
}
impl FactRecorder for Recorder {
    type Commit<'a> = Commit<'a>;
    fn begin(&self, fact: Fact) -> Self::Commit<'_> {
        Commit {
            recorder: self,
            fact: Some(fact),
            begin: true,
        }
    }
    fn complete(&self, fact: Fact) -> Self::Commit<'_> {
        Commit {
            recorder: self,
            fact: Some(fact),
            begin: false,
        }
    }
}

fn operation() -> Operation {
    Operation {
        id: OperationId::new(
            ProcessId::new(1),
            ExecutionId::FIRST,
            InvocationId::new(1),
            CausalPosition::new(0),
            0,
        ),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        method: MethodId::new(0),
        input: Value::integer(7),
        taint: TaintSet::pristine(),
        output: OutputMode::Unary,
    }
}
fn contract() -> MethodContract {
    MethodContract {
        cost: CostModel {
            flat_micro_usd: 11,
            per_1k_in_micro_usd: 1000,
            per_1k_out_micro_usd: 2000,
        },
        ..MethodContract::new(0, ReplayClass::NonIdempotentEffect, OutputModeSet::UNARY)
    }
}
fn grant(contract: MethodContract) -> GrantedMethod {
    GrantedMethod {
        owner: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(9),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        contract,
    }
}
fn options(record: bool) -> InvocationOptions {
    InvocationOptions {
        now_millis: 37,
        record,
    }
}
fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
}
fn finish<F: Future<Output = InvocationResult> + Unpin>(
    future: &mut F,
) -> Result<InvocationResult, Failure> {
    match poll(future) {
        Poll::Ready(result) => Ok(result),
        Poll::Pending => Err(Failure::policy("test", "unexpected suspension")),
    }
}

#[test]
fn invocation_orders_barriers_and_shares_fact_provenance() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let mut driver = Driver::new(&events);
    let mut op = operation();
    op.taint = TaintSet::author();
    driver.output.taint = TaintSet::of(TaintSource::ModelOutput);
    let expected = Invocation::admit(&op, grant(contract()), options(false))?;
    let mut expected_output = driver.output.clone();
    expected_output.taint.union(&op.taint);
    let expected_fact = expected.completed_fact(DecisionTag::Ok, &expected_output);
    let expected_charge = Billing::new(&op.input, contract()).actual(&expected_output);
    let result = finish(&mut invoke(
        op,
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert_eq!(result.output, expected_output);
    assert_eq!(result.completion_error, None);
    assert_eq!(recorder.facts.borrow()[1], expected_fact);
    assert_eq!(account.budget().spent_micro_usd, expected_charge.micro_usd);
    assert_eq!(account.budget().inflight_ops, 0);
    assert_eq!(
        &*events.borrow(),
        &[
            "reserved",
            "intent committed",
            "driver started",
            "driver dropped",
            "settled",
            "outcome committed"
        ]
    );
    Ok(())
}

#[test]
fn portable_invocation_preserves_cached_completion_origin() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let mut driver = Driver::new(&events);
    driver.output = driver.output.with_origin(CompletionOrigin::CachedOutcome);
    let result = finish(&mut invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert_eq!(result.output, driver.output);
    assert_eq!(result.output.origin, CompletionOrigin::CachedOutcome);
    assert_eq!(result.completion_error, None);
    Ok(())
}

#[test]
fn incomplete_barrier_cancellation_refunds_without_dispatch() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    recorder.begin_ready.set(false);
    let mut call = invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?;
    assert!(poll(&mut call).is_pending());
    assert!(poll(&mut call).is_pending());
    assert_eq!(account.budget().inflight_ops, 1);
    drop(call);
    assert_eq!(account.budget(), BudgetState::default());
    assert_eq!(driver.calls.get(), 0);
    Ok(())
}

#[test]
fn dispatched_cancellation_releases_future_then_concurrency_and_retains_spend()
-> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    driver.ready.set(false);
    let estimate = Billing::new(&operation().input, contract()).reservation();
    let mut call = invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?;
    assert!(poll(&mut call).is_pending());
    assert!(account.scopes.borrow_mut()[0].cancel());
    drop(call);
    assert_eq!(
        account.budget(),
        BudgetState {
            spent_micro_usd: estimate.micro_usd,
            inference_tokens: estimate.tokens,
            inflight_ops: 0
        }
    );
    assert_eq!(
        &events.borrow()[2..],
        &["driver started", "driver dropped", "settled"]
    );
    assert_eq!(recorder.facts.borrow().len(), 1);
    Ok(())
}

#[test]
fn missing_or_failed_recorder_denies_effect_and_refunds() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let driver = Driver::new(&events);
    let result = finish(&mut invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &NoFacts,
        &account,
    )?)?;
    assert!(matches!(result.output.outcome, Outcome::Fail(_)));
    assert_eq!(driver.calls.get(), 0);
    assert_eq!(account.budget(), BudgetState::default());
    let mut recorder = Recorder::new(&events);
    recorder.fail_begin = true;
    let result = finish(&mut invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert!(matches!(result.output.outcome, Outcome::Fail(_)));
    assert_eq!(driver.calls.get(), 0);
    assert_eq!(account.budget(), BudgetState::default());
    Ok(())
}

#[test]
fn completed_effect_retains_real_result_when_completion_commit_fails() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let mut recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    recorder.fail_complete = true;
    let result = finish(&mut invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert_eq!(result.output, driver.output);
    assert!(result.completion_error.is_some());
    assert_eq!(account.budget().inflight_ops, 0);
    assert_eq!(recorder.facts.borrow().len(), 1);
    Ok(())
}

#[test]
fn completed_ancestor_is_charged_and_failed_ancestor_admission_rolls_back() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    let mut parent = Scope::new(ProcessId::new(2), IdentityRef::ROOT);
    assert!(parent.start());
    assert!(parent.finish_body(ProcessStatus::Completed));
    assert_eq!(
        parent.mark_terminal_status(ProcessStatus::Completed),
        ProcessStatus::Completed
    );
    assert!(parent.complete_finalization());
    account.scopes.borrow_mut().push(parent);
    let result = finish(&mut invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert!(result.output.outcome.is_success());
    assert_eq!(
        account.scopes.borrow()[0].budget(),
        account.scopes.borrow()[1].budget()
    );
    let before = account.budget();
    account.scopes.borrow_mut()[1].set_budget_spec(BudgetSpec {
        max_inflight_ops: Some(0),
        ..BudgetSpec::default()
    });
    let result = finish(&mut invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert!(matches!(
        result.output.outcome,
        Outcome::Fail(Failure::BudgetExhausted { .. })
    ));
    assert_eq!(account.budget(), before);
    assert_eq!(driver.calls.get(), 1);
    Ok(())
}

#[test]
fn two_pending_calls_share_short_account_access_and_obey_capacity() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    driver.ready.set(false);
    account.scopes.borrow_mut()[0].set_budget_spec(BudgetSpec {
        max_inflight_ops: Some(2),
        ..BudgetSpec::default()
    });
    let mut first = invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?;
    let mut second = invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?;
    assert!(poll(&mut first).is_pending());
    assert!(poll(&mut second).is_pending());
    assert_eq!(account.budget().inflight_ops, 2);
    let third = finish(&mut invoke(
        operation(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert!(matches!(
        third.output.outcome,
        Outcome::Fail(Failure::BudgetExhausted { .. })
    ));
    assert_eq!(driver.calls.get(), 2);
    drop(first);
    assert_eq!(account.budget().inflight_ops, 1);
    drop(second);
    assert_eq!(account.budget().inflight_ops, 0);
    Ok(())
}

#[test]
fn authorized_acting_identity_is_independent_of_account_identity() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    let mut op = operation();
    op.acting = IdentityRef(11);
    let mut grant = grant(contract());
    grant.acting = op.acting;
    assert!(
        finish(&mut invoke(
            op,
            grant,
            options(false),
            CallContext::Body,
            &driver,
            &recorder,
            &account
        )?)?
        .output
        .outcome
        .is_success()
    );
    Ok(())
}

#[test]
fn protected_or_unowned_input_is_rejected_before_any_effect() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    let mut op = operation();
    op.process = ProcessId::new(9);
    assert!(
        invoke(
            op,
            grant(contract()),
            options(false),
            CallContext::Body,
            &driver,
            &recorder,
            &account
        )
        .is_err()
    );
    let mut op = operation();
    op.taint = TaintSet::of(TaintSource::Protected {
        path: xolotl_types::Path::parse("state://private/value")
            .map_err(|error| Failure::policy("test", alloc::format!("{error}")))?,
    });
    let mut contract = contract();
    contract.requires_unprotected_input = true;
    assert!(
        invoke(
            op,
            grant(contract),
            options(false),
            CallContext::Body,
            &driver,
            &recorder,
            &account
        )
        .is_err()
    );
    assert!(events.borrow().is_empty());
    assert_eq!(driver.calls.get(), 0);
    Ok(())
}

#[test]
fn cleanup_requires_permission_after_cancellation_and_body_stays_closed() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    assert!(
        finish(&mut invoke(
            operation(),
            grant(contract()),
            options(false),
            CallContext::Cleanup,
            &driver,
            &recorder,
            &account
        )?)?
        .output
        .outcome
        .is_success()
    );
    assert!(account.scopes.borrow_mut()[0].cancel());
    for context in [
        CallContext::Body,
        CallContext::Cleanup,
        CallContext::Finalizer,
    ] {
        assert!(matches!(
            finish(&mut invoke(
                operation(),
                grant(contract()),
                options(false),
                context,
                &driver,
                &recorder,
                &account
            )?)?
            .output
            .outcome,
            Outcome::Fail(_)
        ));
    }
    let mut contract = contract();
    contract.finalize_allowed = true;
    assert!(
        finish(&mut invoke(
            operation(),
            grant(contract),
            options(false),
            CallContext::Cleanup,
            &driver,
            &recorder,
            &account
        )?)?
        .output
        .outcome
        .is_success()
    );
    assert_eq!(driver.calls.get(), 2);
    assert_eq!(account.budget().inflight_ops, 0);
    Ok(())
}

#[test]
fn sink_only_preserves_usage_and_billing_before_discarding_payload() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    let mut op = operation();
    op.output = OutputMode::SinkOnly;
    let mut contract = contract();
    contract.supports |= OutputModeSet::SINK_ONLY;
    let actual = Billing::new(&op.input, contract).actual(&driver.output);
    let result = finish(&mut invoke(
        op,
        grant(contract),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert_eq!(result.output.outcome, Outcome::Done(Value::null()));
    assert_eq!(account.budget().inference_tokens, actual.tokens);
    assert_eq!(account.budget().spent_micro_usd, actual.micro_usd);
    Ok(())
}

#[test]
fn free_unrecorded_ready_call_needs_no_recorder_or_payload_token_walk() -> Result<(), Failure> {
    struct ReadyDriver;
    impl InvocationDriver for ReadyDriver {
        type Call<'a> = Ready<DriverOutput>;
        fn call(&self, _resource: ResourceId, operation: Operation) -> Self::Call<'_> {
            ready(DriverOutput::new(Outcome::Done(operation.input)))
        }
    }
    let events = Events::default();
    let account = Accounts::new(&events);
    let contract = MethodContract::new(0, ReplayClass::Deterministic, OutputModeSet::UNARY);
    let result = finish(&mut invoke(
        operation(),
        grant(contract),
        options(false),
        CallContext::Body,
        &ReadyDriver,
        &NoFacts,
        &account,
    )?)?;
    assert_eq!(result.output.outcome, Outcome::Done(Value::integer(7)));
    assert_eq!(account.budget(), BudgetState::default());
    let measured = DriverOutput::new(Outcome::Done(Value::null()))
        .with_usage([(UsageDimension::OUTPUT_TOKENS, 13)].into_iter().collect());
    assert_eq!(
        Billing::new(&Value::null(), contract).actual(&measured),
        Charge {
            micro_usd: 0,
            tokens: 13
        }
    );
    let byte_usage = DriverOutput::new(Outcome::Done(Value::string("an unbilled payload".into())))
        .with_usage([(UsageDimension::BYTES_READ, 1024)].into_iter().collect());
    assert_eq!(
        Billing::new(&Value::null(), contract).actual(&byte_usage),
        Charge::default()
    );
    let explicit_zero =
        DriverOutput::new(Outcome::Done(Value::string("an unbilled payload".into())))
            .with_usage([(UsageDimension::OUTPUT_TOKENS, 0)].into_iter().collect());
    assert_eq!(
        Billing::new(&Value::null(), contract).actual(&explicit_zero),
        Charge::default()
    );
    Ok(())
}

#[test]
fn cleanup_owner_exception_is_frozen_to_the_resource_owner() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    assert!(account.scopes.borrow_mut()[0].cancel());
    let mut contract = contract();
    contract.cleanup_owner = Some(ProcessId::new(2));
    let result = finish(&mut invoke(
        operation(),
        grant(contract),
        options(false),
        CallContext::Cleanup,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert!(matches!(result.output.outcome, Outcome::Fail(_)));
    contract.cleanup_owner = Some(ProcessId::new(1));
    assert!(
        finish(&mut invoke(
            operation(),
            grant(contract),
            options(false),
            CallContext::Cleanup,
            &driver,
            &recorder,
            &account
        )?)?
        .output
        .outcome
        .is_success()
    );
    assert_eq!(driver.calls.get(), 1);
    Ok(())
}
