use super::*;

#[test]
fn account_receipts_keep_every_operation_coordinate() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    let base = operation().id;
    let ids = [
        base,
        OperationId {
            execution: ExecutionId::new(29)
                .ok_or_else(|| Failure::policy("test", "invalid execution identity"))?,
            ..base
        },
        OperationId {
            invocation: InvocationId::new(31),
            ..base
        },
        OperationId {
            position: CausalPosition::new(37),
            ..base
        },
        OperationId {
            attempt: 41,
            ..base
        },
    ];
    for id in ids {
        let mut op = operation();
        op.id = id;
        assert!(
            finish(&mut invoke(
                op,
                grant(contract()),
                options(true),
                CallContext::Cleanup,
                &driver,
                &recorder,
                &account,
            )?)?
            .output
            .outcome
            .is_success()
        );
    }
    let requests = account.requests.borrow();
    assert_eq!(requests.len(), ids.len());
    for (index, (request, id)) in requests.iter().zip(ids).enumerate() {
        assert_eq!(request.operation(), id);
        assert_eq!(request.process(), id.process);
        assert_eq!(request.context(), CallContext::Cleanup);
        assert_eq!(
            &account.receipts.borrow()[index * 2..index * 2 + 2],
            &[(id, "dispatch committed"), (id, "settled")],
        );
        assert_eq!(recorder.facts.borrow()[index * 2].id, id);
        assert_eq!(recorder.facts.borrow()[index * 2 + 1].id, id);
        assert_eq!(account.completions.borrow()[index].0, id);
    }
    Ok(())
}

#[test]
fn dispatch_commit_failure_refunds_ancestors_and_records_tainted_denial() -> Result<(), Failure> {
    let events = Events::default();
    let mut account = Accounts::new(&events);
    account.fail_dispatch = true;
    let mut parent = Scope::new(ProcessId::new(2), IdentityRef::ROOT);
    assert!(parent.start());
    account.scopes.borrow_mut().push(parent);
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    let mut op = operation();
    op.taint = TaintSet::author();
    let output = DriverOutput::new(Outcome::Fail(Failure::policy(
        "account",
        "dispatch commit failed",
    )))
    .with_taint(op.taint.clone());
    let expected = Invocation::admit(&op, grant(contract()), options(true))?
        .completed_fact(DecisionTag::Denied, &output);
    let result = finish(&mut invoke(
        op,
        grant(contract()),
        options(true),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert_eq!(result.output, output);
    assert_eq!(result.completion_error, None);
    assert_eq!(driver.calls.get(), 0);
    assert!(account.completions.borrow().is_empty());
    for scope in account.scopes.borrow().iter() {
        assert_eq!(scope.budget(), &BudgetState::default());
    }
    assert_eq!(recorder.facts.borrow().len(), 2);
    assert_eq!(recorder.facts.borrow()[1], expected);
    assert_eq!(
        &*events.borrow(),
        &[
            "reserved",
            "intent committed",
            "dispatch failed",
            "abandoned",
            "outcome committed",
        ]
    );
    Ok(())
}

#[test]
fn dispatch_denial_retains_record_error_without_claiming_driver_execution() -> Result<(), Failure> {
    let events = Events::default();
    let mut account = Accounts::new(&events);
    account.fail_dispatch = true;
    let mut recorder = Recorder::new(&events);
    recorder.fail_complete = true;
    let driver = Driver::new(&events);
    let result = finish(&mut invoke(
        operation(),
        grant(contract()),
        options(true),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert_eq!(
        result.output.outcome,
        Outcome::Fail(Failure::policy("account", "dispatch commit failed"))
    );
    assert_eq!(
        result.completion_error,
        Some(CompletionError::Fact(Failure::policy(
            "test",
            "commit failed"
        )))
    );
    assert_eq!(driver.calls.get(), 0);
    assert_eq!(account.budget(), BudgetState::default());
    assert_eq!(recorder.facts.borrow().len(), 1);
    assert_eq!(account.receipts.borrow().len(), 2);
    Ok(())
}

#[test]
fn cancelling_a_suspended_denial_commit_does_not_repeat_account_cleanup() -> Result<(), Failure> {
    let events = Events::default();
    let mut account = Accounts::new(&events);
    account.fail_dispatch = true;
    let recorder = Recorder::new(&events);
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
    assert_eq!(account.budget(), BudgetState::default());
    assert!(poll(&mut call).is_pending());
    drop(call);
    assert_eq!(account.budget(), BudgetState::default());
    assert_eq!(driver.calls.get(), 0);
    assert_eq!(recorder.facts.borrow().len(), 1);
    assert_eq!(
        &*account.receipts.borrow(),
        &[
            (operation().id, "dispatch failed"),
            (operation().id, "abandoned"),
        ]
    );
    Ok(())
}

#[test]
fn failed_settlement_preserves_result_and_greater_of_reserved_or_reported_spend()
-> Result<(), Failure> {
    for (input_tokens, output_tokens) in [(0, 0), (0, 9), (100, 0), (100, 9)] {
        for mode in [OutputMode::Unary, OutputMode::SinkOnly] {
            let events = Events::default();
            let mut account = Accounts::new(&events);
            account.fail_settle = true;
            let mut parent = Scope::new(ProcessId::new(2), IdentityRef::ROOT);
            assert!(parent.start());
            account.scopes.borrow_mut().push(parent);
            let recorder = Recorder::new(&events);
            let mut driver = Driver::new(&events);
            let mut op = operation();
            op.output = mode;
            op.taint = TaintSet::author();
            let mut method = contract();
            method.supports = OutputModeSet::UNARY.union(OutputModeSet::SINK_ONLY);
            driver.output.taint = TaintSet::of(TaintSource::ModelOutput);
            driver.output.origin = CompletionOrigin::CachedOutcome;
            driver.output.usage = Some(
                [
                    (UsageDimension::INPUT_TOKENS, input_tokens),
                    (UsageDimension::OUTPUT_TOKENS, output_tokens),
                ]
                .into_iter()
                .collect(),
            );
            let billing = Billing::new(&op.input, method);
            let reserved = billing.reservation();
            let actual = billing.actual(&driver.output);
            let mut expected = complete_output(driver.output.clone(), &op.taint);
            if mode == OutputMode::SinkOnly {
                expected.outcome = Outcome::Done(Value::null());
            }
            let result = finish(&mut invoke(
                op,
                grant(method),
                options(true),
                CallContext::Body,
                &driver,
                &recorder,
                &account,
            )?)?;
            assert_eq!(result.output, expected);
            assert!(result.effect_may_have_started);
            assert_eq!(
                result.completion_error,
                Some(CompletionError::Settlement(Failure::policy(
                    "account",
                    "settlement commit failed"
                )))
            );
            assert_eq!(driver.calls.get(), 1);
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
            assert_eq!(recorder.facts.borrow().len(), 1);
            assert!(account.completions.borrow().is_empty());
            assert_eq!(
                &*events.borrow(),
                &[
                    "reserved",
                    "intent committed",
                    "dispatch committed",
                    "driver started",
                    "driver dropped",
                    "settlement failed",
                    "abandoned",
                ]
            );
        }
    }
    Ok(())
}

#[test]
fn failed_settlement_preserves_driver_failure_and_provenance() -> Result<(), Failure> {
    let events = Events::default();
    let mut account = Accounts::new(&events);
    account.fail_settle = true;
    let recorder = Recorder::new(&events);
    let mut driver = Driver::new(&events);
    driver.output = DriverOutput::new(Outcome::Fail(Failure::Cancelled))
        .with_taint(TaintSet::of(TaintSource::ModelOutput));
    let mut op = operation();
    op.taint = TaintSet::author();
    let expected = complete_output(driver.output.clone(), &op.taint);
    let result = finish(&mut invoke(
        op,
        grant(contract()),
        options(true),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?)?;
    assert_eq!(result.output, expected);
    assert!(result.effect_may_have_started);
    assert!(result.completion_error.is_some());
    assert_eq!(recorder.facts.borrow().len(), 1);
    assert_eq!(account.budget().inflight_ops, 0);
    Ok(())
}

#[test]
fn unknown_driver_outcome_preserves_identity_usage_and_charge_without_facts() -> Result<(), Failure>
{
    let events = Events::default();
    let account = Accounts::new(&events);
    let mut driver = Driver::new(&events);
    let mut op = operation();
    op.taint = TaintSet::author();
    let failure = Failure::OutcomeUnknown {
        operation_ids: vec![alloc::format!("{}", op.id)],
        reason: "remote delivery was not confirmed".into(),
    };
    driver.output = DriverOutput::new(Outcome::Fail(failure))
        .with_taint(TaintSet::of(TaintSource::ModelOutput))
        .with_usage(
            [
                (UsageDimension::INPUT_TOKENS, 17),
                (UsageDimension::OUTPUT_TOKENS, 23),
            ]
            .into(),
        );
    let expected = complete_output(driver.output.clone(), &op.taint);
    let charge = Billing::new(&op.input, contract()).actual(&expected);
    let result = finish(&mut invoke(
        op,
        grant(contract()),
        options(false),
        CallContext::Body,
        &driver,
        &NoFacts,
        &account,
    )?)?;
    assert_eq!(result.output, expected);
    assert_eq!(result.completion_error, None);
    assert!(result.effect_may_have_started);
    assert_eq!(
        account.budget(),
        BudgetState {
            spent_micro_usd: charge.micro_usd,
            inference_tokens: charge.tokens,
            inflight_ops: 0,
        }
    );
    assert_eq!(account.completions.borrow()[0].2, expected);
    Ok(())
}

#[test]
fn unrecorded_calls_still_require_account_commits() -> Result<(), Failure> {
    for dispatch_failure in [false, true] {
        let events = Events::default();
        let mut account = Accounts::new(&events);
        account.fail_dispatch = dispatch_failure;
        account.fail_settle = !dispatch_failure;
        let driver = Driver::new(&events);
        let mut method = contract();
        method.replay = ReplayClass::Deterministic;
        let result = finish(&mut invoke(
            operation(),
            grant(method),
            options(false),
            CallContext::Body,
            &driver,
            &NoFacts,
            &account,
        )?)?;
        if dispatch_failure {
            assert_eq!(
                result.output.outcome,
                Outcome::Fail(Failure::policy("account", "dispatch commit failed"))
            );
            assert_eq!(result.completion_error, None);
            assert_eq!(driver.calls.get(), 0);
            assert_eq!(account.budget(), BudgetState::default());
        } else {
            assert_eq!(result.output, driver.output);
            assert_eq!(
                result.completion_error,
                Some(CompletionError::Settlement(Failure::policy(
                    "account",
                    "settlement commit failed"
                )))
            );
            assert_eq!(driver.calls.get(), 1);
            assert_eq!(account.budget().inflight_ops, 0);
        }
    }
    Ok(())
}

#[test]
fn cancellation_during_fact_completion_does_not_settle_or_abandon_twice() -> Result<(), Failure> {
    let events = Events::default();
    let account = Accounts::new(&events);
    let recorder = Recorder::new(&events);
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
    let settled = account.budget();
    assert_eq!(settled.inflight_ops, 0);
    assert!(poll(&mut call).is_pending());
    drop(call);
    assert_eq!(account.budget(), settled);
    assert_eq!(account.completions.borrow().len(), 1);
    assert_eq!(account.completions.borrow()[0].2, driver.output);
    assert_eq!(driver.calls.get(), 1);
    assert_eq!(recorder.facts.borrow().len(), 1);
    assert_eq!(
        &*account.receipts.borrow(),
        &[
            (operation().id, "dispatch committed"),
            (operation().id, "settled"),
        ]
    );
    Ok(())
}

#[test]
fn settlement_retains_the_exact_delivered_result_and_charge_before_projection()
-> Result<(), Failure> {
    for output_mode in [OutputMode::Unary, OutputMode::SinkOnly] {
        for outcome in [
            Outcome::Done(Value::bytes(vec![0, 1, 255])),
            Outcome::Short(Value::bytes(vec![0, 1, 255])),
            Outcome::Fail(Failure::InvalidInput {
                reason: "driver rejection".into(),
            }),
        ] {
            for record in [false, true] {
                let events = Events::default();
                let account = Accounts::new(&events);
                let mut parent = Scope::new(ProcessId::new(2), IdentityRef::ROOT);
                assert!(parent.start());
                account.scopes.borrow_mut().push(parent);
                let recorder = Recorder::new(&events);
                let mut driver = Driver::new(&events);
                driver.output = DriverOutput::new(outcome.clone())
                    .with_taint(TaintSet::of(TaintSource::ModelOutput))
                    .with_usage(
                        [
                            (UsageDimension::INPUT_TOKENS, 7),
                            (UsageDimension::OUTPUT_TOKENS, 13),
                            (UsageDimension::new("device_cycles"), 0),
                        ]
                        .into(),
                    )
                    .with_origin(CompletionOrigin::CachedOutcome);
                let mut op = operation();
                op.output = output_mode;
                op.taint = TaintSet::author();
                let mut method = contract();
                method.supports |= OutputModeSet::SINK_ONLY;
                method.replay = ReplayClass::Deterministic;
                let billing = Billing::new(&op.input, method);
                let charge = billing.actual(&driver.output);
                let expected = DriverOutput {
                    outcome: match (output_mode, outcome.clone()) {
                        (OutputMode::SinkOnly, Outcome::Done(_)) => Outcome::Done(Value::null()),
                        (OutputMode::SinkOnly, Outcome::Short(_)) => Outcome::Short(Value::null()),
                        (_, outcome) => outcome,
                    },
                    taint: TaintSet::from_recorded_sources(vec![
                        TaintSource::ModelOutput,
                        TaintSource::AuthorConstant,
                    ]),
                    usage: driver.output.usage.clone(),
                    origin: driver.output.origin,
                };
                let result = finish(&mut invoke(
                    op.clone(),
                    grant(method),
                    options(record),
                    CallContext::Body,
                    &driver,
                    &recorder,
                    &account,
                )?)?;
                assert_eq!(result.output, expected);
                assert_eq!(result.completion_error, None);
                assert_eq!(
                    &*account.completions.borrow(),
                    &[(
                        op.id,
                        Settlement::completed(billing.reservation(), charge),
                        expected
                    )]
                );
                for scope in account.scopes.borrow().iter() {
                    assert_eq!(scope.budget().spent_micro_usd, charge.micro_usd);
                    assert_eq!(scope.budget().inference_tokens, charge.tokens);
                    assert_eq!(scope.budget().inflight_ops, 0);
                }
                assert_eq!(recorder.facts.borrow().len(), if record { 2 } else { 0 });
            }
        }
    }
    Ok(())
}

#[test]
fn failed_settlement_releases_only_its_own_concurrency_and_retains_sibling_reservation()
-> Result<(), Failure> {
    let events = Events::default();
    let mut account = Accounts::new(&events);
    account.fail_settle = true;
    let recorder = Recorder::new(&events);
    let driver = Driver::new(&events);
    driver.ready.set(false);
    let mut second_op = operation();
    second_op.id.invocation = InvocationId::new(2);
    let mut first = invoke(
        operation(),
        grant(contract()),
        options(true),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?;
    let mut second = invoke(
        second_op,
        grant(contract()),
        options(true),
        CallContext::Body,
        &driver,
        &recorder,
        &account,
    )?;
    assert!(poll(&mut first).is_pending());
    assert!(poll(&mut second).is_pending());
    driver.ready.set(true);
    let result = finish(&mut first)?;
    assert!(result.completion_error.is_some());
    let billing = Billing::new(&operation().input, contract());
    let reserved = billing.reservation();
    let actual = billing.actual(&driver.output);
    let mut expected = BudgetState {
        spent_micro_usd: reserved.micro_usd + reserved.micro_usd.max(actual.micro_usd),
        inference_tokens: reserved.tokens + reserved.tokens.max(actual.tokens),
        inflight_ops: 1,
    };
    assert_eq!(account.budget(), expected);
    drop(first);
    assert_eq!(account.budget(), expected);
    drop(second);
    expected.inflight_ops = 0;
    assert_eq!(account.budget(), expected);
    assert_eq!(recorder.facts.borrow().len(), 2);
    assert_eq!(
        &*events.borrow(),
        &[
            "reserved",
            "intent committed",
            "dispatch committed",
            "driver started",
            "reserved",
            "intent committed",
            "dispatch committed",
            "driver started",
            "driver dropped",
            "settlement failed",
            "abandoned",
            "driver dropped",
            "abandoned",
        ]
    );
    Ok(())
}
