use super::*;

#[test]
fn pending_dispatch_prevents_driver_construction_even_without_facts() -> Result<(), Failure> {
    for record in [false, true] {
        let events = Events::default();
        let account = Accounts::new(&events);
        account.dispatch_ready.set(false);
        let recorder = Recorder::new(&events);
        let driver = Driver::new(&events);
        let mut method = contract();
        method.replay = ReplayClass::Deterministic;
        let mut call = invoke(
            operation(),
            grant(method),
            options(record),
            CallContext::Body,
            &driver,
            &recorder,
            &account,
        )?;
        assert!(poll(&mut call).is_pending());
        assert!(poll(&mut call).is_pending());
        assert_eq!(driver.calls.get(), 0);
        assert_eq!(account.requests.borrow().len(), 1);
        assert!(account.receipts.borrow().is_empty());
        assert_eq!(account.budget().inflight_ops, 1);
        assert_eq!(recorder.facts.borrow().len(), usize::from(record));

        account.dispatch_ready.set(true);
        let result = finish(&mut call)?;
        assert_eq!(result.output, driver.output);
        assert_eq!(result.completion_error, None);
        assert_eq!(driver.calls.get(), 1);
        assert_eq!(account.completions.borrow().len(), 1);
        assert_eq!(account.budget().inflight_ops, 0);
        assert_eq!(recorder.facts.borrow().len(), 2 * usize::from(record));
        drop(call);
        assert_eq!(account.receipts.borrow().len(), 2);
    }
    Ok(())
}

#[test]
fn cancelled_dispatch_drops_commit_before_refunding_owner_and_ancestors() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let mut parent = Scope::new(ProcessId::new(2), IdentityRef::ROOT);
    assert!(parent.start());
    account.scopes.borrow_mut().push(parent);
    account.dispatch_ready.set(false);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    let mut call = invoke(
        operation(),
        grant(contract()),
        options(true),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?;
    assert!(poll(&mut call).is_pending());
    for scope in account.scopes.borrow().iter() {
        assert_eq!(scope.budget().inflight_ops, 1);
    }
    drop(call);
    assert_eq!(driver.calls.get(), 0);
    assert!(account.completions.borrow().is_empty());
    assert_eq!(recorder.facts.borrow().len(), 1);
    for scope in account.scopes.borrow().iter() {
        assert_eq!(scope.budget(), &BudgetState::default());
    }
    assert_eq!(
        &*events.borrow(),
        &[
            "reserved",
            "intent committed",
            "dispatch commit dropped",
            "abandoned",
        ]
    );
    Ok(())
}

#[test]
fn dispatch_rejection_after_wait_refunds_before_recording_denial() -> Result<(), Failure> {
    for fail_complete in [false, true] {
        let events = Events::default();
        let mut account = Accounts::new(&events);
        account.fail_dispatch = true;
        account.dispatch_ready.set(false);
        let mut recorder = Recorder::new(&events);
        recorder.fail_complete = fail_complete;
        recorder.complete_ready.set(false);
        let driver = Driver::new(&events);
        let mut call = invoke(
            operation(),
            grant(contract()),
            options(true),
            CallContext::Body,
            &driver,
            &recorder,
            &account,
        )?;
        assert!(poll(&mut call).is_pending());
        assert_eq!(account.budget().inflight_ops, 1);
        account.dispatch_ready.set(true);
        assert!(poll(&mut call).is_pending());
        assert_eq!(account.budget(), BudgetState::default());
        assert_eq!(driver.calls.get(), 0);
        assert!(account.completions.borrow().is_empty());
        recorder.complete_ready.set(true);
        let result = finish(&mut call)?;
        assert_eq!(
            result.output.outcome,
            Outcome::Fail(Failure::policy("account", "dispatch commit failed"))
        );
        assert!(!result.effect_may_have_started);
        assert_eq!(
            result.completion_error,
            fail_complete.then(|| CompletionError::Fact(Failure::policy("test", "commit failed")))
        );
        assert_eq!(
            recorder.facts.borrow().len(),
            if fail_complete { 1 } else { 2 }
        );
        let mut expected_events = vec![
            "reserved",
            "intent committed",
            "dispatch failed",
            "abandoned",
        ];
        if !fail_complete {
            expected_events.push("outcome committed");
        }
        assert_eq!(&*events.borrow(), &expected_events);
    }
    Ok(())
}

#[test]
fn pending_settlement_retains_reservation_and_cannot_complete_fact() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    account.settle_ready.set(false);
    let recorder = Recorder::new(&events);
    recorder.complete_ready.set(false);
    let driver = Driver::new(&events);
    let billing = Billing::new(&operation().input, contract());
    let reserved = billing.reservation();
    let mut call = invoke(
        operation(),
        grant(contract()),
        options(true),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?;
    assert!(poll(&mut call).is_pending());
    assert!(poll(&mut call).is_pending());
    assert_eq!(driver.calls.get(), 1);
    assert_eq!(
        account.budget(),
        BudgetState {
            spent_micro_usd: reserved.micro_usd,
            inference_tokens: reserved.tokens,
            inflight_ops: 1,
        }
    );
    assert!(account.completions.borrow().is_empty());
    assert_eq!(
        &*events.borrow(),
        &[
            "reserved",
            "intent committed",
            "dispatch committed",
            "driver started",
            "driver dropped",
        ]
    );

    account.settle_ready.set(true);
    assert!(poll(&mut call).is_pending());
    assert!(poll(&mut call).is_pending());
    let actual = billing.actual(&driver.output);
    assert_eq!(
        account.budget(),
        BudgetState {
            spent_micro_usd: actual.micro_usd,
            inference_tokens: actual.tokens,
            inflight_ops: 0,
        }
    );
    assert_eq!(account.completions.borrow().len(), 1);
    assert_eq!(recorder.facts.borrow().len(), 1);
    recorder.complete_ready.set(true);
    let result = finish(&mut call)?;
    assert_eq!(result.output, driver.output);
    assert_eq!(result.completion_error, None);
    assert!(result.effect_may_have_started);
    drop(call);
    assert_eq!(account.receipts.borrow().len(), 2);
    assert_eq!(recorder.facts.borrow().len(), 2);
    Ok(())
}

#[test]
fn cancelled_settlement_keeps_known_spend_and_drops_commit_before_abandonment()
-> Result<(), Failure> {
    for (input_tokens, output_tokens) in [(0, 0), (1000, 0), (0, 1000)] {
        let events = Events::default();
        let account = Accounts::new(&events);
        let mut parent = Scope::new(ProcessId::new(2), IdentityRef::ROOT);
        assert!(parent.start());
        account.scopes.borrow_mut().push(parent);
        account.settle_ready.set(false);
        let recorder = Recorder::new(&events);
        let mut driver = Driver::new(&events);
        driver.output = driver.output.with_usage(
            [
                (UsageDimension::INPUT_TOKENS, input_tokens),
                (UsageDimension::OUTPUT_TOKENS, output_tokens),
            ]
            .into(),
        );
        let billing = Billing::new(&operation().input, contract());
        let reserved = billing.reservation();
        let actual = billing.actual(&driver.output);
        let mut call = invoke(
            operation(),
            grant(contract()),
            options(true),
            CallContext::Body,
            &driver,
            &recorder,
            &account,
        )?;
        assert!(poll(&mut call).is_pending());
        drop(call);
        assert_eq!(driver.calls.get(), 1);
        assert_eq!(recorder.facts.borrow().len(), 1);
        assert!(account.completions.borrow().is_empty());
        for scope in account.scopes.borrow().iter() {
            assert_eq!(
                scope.budget(),
                &BudgetState {
                    spent_micro_usd: reserved.micro_usd.max(actual.micro_usd),
                    inference_tokens: reserved.tokens.max(actual.tokens),
                    inflight_ops: 0,
                }
            );
        }
        assert_eq!(
            &*events.borrow(),
            &[
                "reserved",
                "intent committed",
                "dispatch committed",
                "driver started",
                "driver dropped",
                "settlement commit dropped",
                "abandoned",
            ]
        );
    }
    Ok(())
}

#[test]
fn settlement_failure_after_wait_preserves_output_without_completing_fact() -> Result<(), Failure> {
    for record in [false, true] {
        let events = Events::default();
        let mut account = Accounts::new(&events);
        account.fail_settle = true;
        account.settle_ready.set(false);
        let recorder = Recorder::new(&events);
        let driver = Driver::new(&events);
        let mut method = contract();
        method.replay = ReplayClass::Deterministic;
        let mut call = invoke(
            operation(),
            grant(method),
            options(record),
            CallContext::Body,
            &driver,
            &recorder,
            &account,
        )?;
        assert!(poll(&mut call).is_pending());
        assert_eq!(account.budget().inflight_ops, 1);
        account.settle_ready.set(true);
        let result = finish(&mut call)?;
        assert_eq!(result.output, driver.output);
        assert_eq!(
            result.completion_error,
            Some(CompletionError::Settlement(Failure::policy(
                "account",
                "settlement commit failed"
            )))
        );
        drop(call);
        assert_eq!(account.budget().inflight_ops, 0);
        assert!(account.completions.borrow().is_empty());
        assert_eq!(recorder.facts.borrow().len(), usize::from(record));
        assert_eq!(
            account.receipts.borrow().last(),
            Some(&(operation().id, "abandoned"))
        );
    }
    Ok(())
}

#[test]
fn pending_settlement_does_not_make_its_concurrency_available_to_siblings() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    account.scopes.borrow_mut()[0].set_budget_spec(BudgetSpec {
        max_inflight_ops: Some(1),
        ..BudgetSpec::default()
    });
    account.settle_ready.set(false);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
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
    let mut sibling = operation();
    sibling.id.invocation = InvocationId::new(2);
    let blocked = finish(&mut invoke(
        sibling.clone(),
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert!(matches!(
        blocked.output.outcome,
        Outcome::Fail(Failure::BudgetExhausted { .. })
    ));
    assert_eq!(account.budget().inflight_ops, 1);
    assert_eq!(driver.calls.get(), 1);

    account.settle_ready.set(true);
    assert_eq!(finish(&mut call)?.completion_error, None);
    let admitted = finish(&mut invoke(
        sibling,
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert_eq!(admitted.output, driver.output);
    assert_eq!(admitted.completion_error, None);
    assert_eq!(driver.calls.get(), 2);
    assert_eq!(account.completions.borrow().len(), 2);
    assert_eq!(account.budget().inflight_ops, 0);
    Ok(())
}
