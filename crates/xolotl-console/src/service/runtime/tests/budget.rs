use super::*;
use xolotl_types::{BudgetSpec, CostModel, MethodAuthority, OutputModeSet};

fn budget_call(action: &str, budget: Value) -> anyhow::Result<ActionCall> {
    let operation = OperationTemplate {
        target: ResourceName::new(Path::parse("effect://calculator/billed")?),
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    };
    let mut call = call(
        Program::new(Expression::Invoke { operation }),
        Value::string("four".into()),
    )?;
    if action == ACTION_RUNTIME_OPERATION_INVOKE {
        call.action = action.into();
        call.input = map_value([
            ("target", Value::string("effect://calculator/billed".into())),
            ("method", Value::string("invoke".into())),
            ("input", Value::string("four".into())),
        ]);
    }
    let mut input = input_map(call.input)?;
    input.insert("budget".into(), budget)?;
    call.input = Value::from(input);
    Ok(call)
}

fn install_billed(state: &ConsoleState, calls: Arc<AtomicUsize>) -> anyhow::Result<()> {
    state.boot.register_effect_with_cost(
        "effect://calculator/billed",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            OutputModeSet::UNARY,
        )],
        Arc::new(FnDriver(move |_, input: Value| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        })),
        CostModel {
            flat_micro_usd: 7,
            ..CostModel::FREE
        },
    )?;
    Ok(())
}

#[tokio::test]
async fn every_budget_dimension_rejects_calls_before_driver_effects() -> anyhow::Result<()> {
    let (state, principal, calls) = fixture()?;
    install_billed(&state, calls.clone())?;
    for action in [ACTION_RUNTIME_OPERATION_INVOKE, ACTION_RUNTIME_PROGRAM_RUN] {
        for (dimension, limit) in [
            ("max_micro_usd", Value::string("6".into())),
            ("max_inflight_ops", Value::integer(0)),
            ("max_inference_tokens", Value::integer(0)),
        ] {
            let error = execute(
                &state,
                &principal,
                budget_call(action, map_value([(dimension, limit)]))?,
            )
            .await
            .err()
            .context("budget must reject")?;
            ensure!(error.code == ConsoleErrorCode::RateLimited);
            ensure!(error.execution.is_some());
            ensure!(
                calls.load(Ordering::SeqCst) == 0,
                "{action} ignored {dimension}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn caller_host_and_ancestor_budgets_intersect_without_resetting_spending()
-> anyhow::Result<()> {
    let (original, principal, calls) = fixture()?;
    install_billed(&original, calls.clone())?;
    let state = ConsoleState::with_config(
        original.boot.clone(),
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            runtime: ConsoleRuntimeConfig {
                budget: BudgetSpec {
                    max_micro_usd: Some(7),
                    max_inflight_ops: Some(1),
                    max_inference_tokens: None,
                },
                ..original.runtime.config.clone()
            },
            ..Default::default()
        },
    )?;
    ensure!(
        state
            .boot
            .kernel()
            .processes()
            .set_budget_spec(
                state.boot.root(),
                BudgetSpec {
                    max_micro_usd: Some(14),
                    ..Default::default()
                }
            )
            .is_ok()
    );
    let wider = map_value([
        ("max_micro_usd", Value::string(u64::MAX.to_string())),
        ("max_inflight_ops", Value::null()),
        ("max_inference_tokens", Value::string("10".into())),
    ]);
    let call = budget_call(ACTION_RUNTIME_PROGRAM_RUN, wider)?;
    for expected in 1..=2 {
        let output = execute(&state, &principal, call.clone())
            .await?
            .output
            .context("output")?;
        let admitted = output
            .as_map()
            .and_then(|map| map.get("budget"))
            .context("budget")?;
        ensure!(
            *admitted
                == crate::runtime::budget::value(&BudgetSpec {
                    max_micro_usd: Some(7),
                    max_inflight_ops: Some(1),
                    max_inference_tokens: Some(10),
                })?
        );
        ensure!(calls.load(Ordering::SeqCst) == expected);
    }
    let error = execute(&state, &principal, call)
        .await
        .err()
        .context("ancestor must reject")?;
    ensure!(error.code == ConsoleErrorCode::RateLimited);
    ensure!(calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn budget_shape_rejects_unknown_legacy_overflow_and_nonintegral_limits_before_allocation()
-> anyhow::Result<()> {
    let (state, principal, calls) = fixture()?;
    install_billed(&state, calls.clone())?;
    let before = state.boot.kernel().processes().len();
    for budget in [
        map_value([("daily_micro_usd", Value::integer(1))]),
        map_value([("monthly_micro_usd", Value::integer(1))]),
        map_value([(
            "max_micro_usd",
            Value::string("18446744073709551616".into()),
        )]),
        map_value([("max_micro_usd", Value::integer(-1))]),
        map_value([("max_micro_usd", Value::string("+1".into()))]),
        map_value([("max_micro_usd", Value::string("1.0".into()))]),
        map_value([("max_inflight_ops", Value::integer(i64::from(u32::MAX) + 1))]),
        Value::null(),
    ] {
        let error = execute(
            &state,
            &principal,
            budget_call(ACTION_RUNTIME_PROGRAM_RUN, budget)?,
        )
        .await
        .err()
        .context("invalid budget must reject")?;
        ensure!(error.code == ConsoleErrorCode::BadRequest);
        ensure!(error.execution.is_none());
        ensure!(state.boot.kernel().processes().len() == before);
    }
    ensure!(calls.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn config_and_wire_preserve_full_unsigned_limits_and_reject_obsolete_dimensions()
-> anyhow::Result<()> {
    let input = serde_json::json!({"budget": {
        "max_micro_usd": u64::MAX,
        "max_inflight_ops": u32::MAX,
        "max_inference_tokens": u64::MAX.to_string(),
    }});
    let config: ConsoleRuntimeConfig = serde_json::from_value(input)?;
    let encoded = serde_json::to_value(&config)?;
    ensure!(encoded["budget"]["max_micro_usd"] == u64::MAX.to_string());
    ensure!(encoded["budget"]["max_inference_tokens"] == u64::MAX.to_string());
    ensure!(serde_json::from_value::<ConsoleRuntimeConfig>(encoded)? == config);
    ensure!(
        crate::runtime::budget::parse(Some(crate::runtime::budget::value(&config.budget)?))?
            == config.budget
    );
    for name in ["daily_micro_usd", "monthly_micro_usd", "max_other"] {
        ensure!(
            serde_json::from_value::<ConsoleRuntimeConfig>(
                serde_json::json!({"budget": {name: 1}})
            )
            .is_err()
        );
        ensure!(serde_json::from_value::<BudgetSpec>(serde_json::json!({name: 1})).is_err());
    }
    Ok(())
}
