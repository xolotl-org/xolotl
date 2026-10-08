use super::*;

fn acting(identity: &str, body: Expression) -> anyhow::Result<Expression> {
    Ok(Expression::Acting {
        identity: Path::parse(identity)?,
        body: Box::new(body),
    })
}

#[tokio::test]
async fn acting_changes_fact_identity_and_restores_the_enclosing_scope() -> anyhow::Result<()> {
    let (state, principal, count) = fixture()?;
    let identity = "identity://calculator/worker";
    let operation = invoke("identity", OutputMode::Unary)?;
    let program = Program::new(acting(identity, operation.clone())?.then(operation));
    let value = Value::bytes(vec![0, 255]);
    let (output, execution) =
        execute_with_fact_recording(&state, &principal, call(program, value.clone())?).await?;
    let process = xolotl_types::ProcessId::new(execution.process_id.parse()?);
    ensure!(output.outcome == Outcome::Done(value) && count.load(Ordering::SeqCst) == 2);
    let facts = state.boot.kernel().facts().facts_of(process)?;
    let acting = state
        .boot
        .kernel()
        .identities()
        .lookup(&Path::parse(identity)?)?
        .context("acting identity")?;
    let original = state
        .boot
        .kernel()
        .identities()
        .lookup(&Path::parse(&principal.identity_path)?)?
        .context("principal identity")?;
    ensure!(facts.iter().any(|fact| fact.acting == acting));
    ensure!(facts.iter().any(|fact| fact.acting == original));
    ensure!(state.boot.kernel().handles().is_empty());
    ensure!(
        state
            .boot
            .kernel()
            .processes()
            .attached_grants(process)
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn every_identity_requires_exposure_and_user_authority_before_any_effect()
-> anyhow::Result<()> {
    let (state, mut principal, count) = fixture()?;
    let operation = invoke("identity", OutputMode::Unary)?;
    for (identity, grants) in [
        ("identity://outside/worker", vec!["*://**"]),
        (
            "identity://calculator/worker",
            vec!["perform://effect/calculator/**"],
        ),
        (
            "identity://calculator/worker",
            vec!["act-as://identity/calculator/**"],
        ),
        (
            "identity://calculator/worker",
            vec![
                "perform://effect/calculator/**",
                "act-as://identity/calculator/**@until=0",
            ],
        ),
    ] {
        principal.grants = CapSet::from_strs(grants)?;
        let program = Program::new(operation.clone().then(acting(identity, operation.clone())?));
        let error = execute(&state, &principal, call(program, Value::null())?)
            .await
            .err()
            .context("denied")?;
        ensure!(error.code == ConsoleErrorCode::Forbidden, "{error}");
        ensure!(count.load(Ordering::SeqCst) == 0);
    }
    Ok(())
}

#[tokio::test]
async fn identity_budget_counts_distinct_transitive_imports() -> anyhow::Result<()> {
    let (mut state, principal, count) = fixture()?;
    Arc::get_mut(&mut state)
        .context("exclusive state")?
        .runtime
        .config
        .max_identities = 1;
    let same = acting(
        "identity://calculator/one",
        invoke("identity", OutputMode::Unary)?,
    )?;
    let result = execute(
        &state,
        &principal,
        call(Program::new(same.clone().then(same.clone())), Value::null())?,
    )
    .await?;
    ensure!(result_value(result)?.is_null());
    ensure!(count.load(Ordering::SeqCst) == 2);
    let other = acting("identity://calculator/two", Expression::Input)?;
    let error = execute(
        &state,
        &principal,
        call(Program::new(same.then(other)), Value::null())?,
    )
    .await
    .err()
    .context("identity budget")?;
    ensure!(error.code == ConsoleErrorCode::BadRequest && count.load(Ordering::SeqCst) == 2);
    Ok(())
}
