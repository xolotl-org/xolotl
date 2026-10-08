use super::*;
use crate::RuntimeSubmissionIdentity;

fn identity(fixture: &Fixture, nonce: &str) -> RuntimeSubmissionIdentity {
    let (registry_instance, retry_epoch) = fixture.state.executions.submission_retry_scope();
    RuntimeSubmissionIdentity {
        registry_instance,
        retry_epoch,
        nonce: nonce.into(),
    }
}

fn identity_value(identity: &RuntimeSubmissionIdentity) -> Value {
    map_value([
        (
            "registry_instance",
            Value::string(identity.registry_instance.clone()),
        ),
        (
            "retry_epoch",
            Value::string(identity.retry_epoch.to_string()),
        ),
        ("nonce", Value::string(identity.nonce.clone())),
    ])
}

fn request(identity: RuntimeSubmissionIdentity, input: Value) -> anyhow::Result<RuntimeRequest> {
    let mut request = RuntimeRequest::new(
        RuntimeCode::Program(Program::new(echo()?)),
        input,
        "job",
        "guarded submission",
        10_000,
    );
    request.submission_identity = Some(identity);
    Ok(request)
}

async fn submit(
    fixture: &Fixture,
    request: RuntimeRequest,
) -> Result<ActionResult, ConsoleFailure> {
    fixture
        .service
        .submit_runtime(&fixture.token, Some("embedded"), request)
        .await
}

async fn lookup(fixture: &Fixture, identity: &RuntimeSubmissionIdentity) -> anyhow::Result<Value> {
    fixture
        .call(
            ACTION_RUNTIME_SUBMISSION_LOOKUP,
            map_value([("submission_identity", identity_value(identity))]),
        )
        .await?
        .output
        .context("submission evidence")
}

fn reference(result: &ActionResult) -> anyhow::Result<ExecutionReference> {
    Ok(result
        .execution
        .as_deref()
        .context("execution reference")?
        .clone())
}

#[tokio::test]
async fn guarded_retry_normalizes_protocol_and_native_source_without_repeating_effects()
-> anyhow::Result<()> {
    let fixture = Fixture::new(config()).await?;
    let identity = identity(&fixture, "native-wire");
    let unproven = lookup(&fixture, &identity).await?;
    ensure!(field(&unproven, "evidence")?.as_str() == Some("unproven"));
    ensure!(field(&unproven, "execution")?.is_null());
    let first = fixture
        .call(
            ACTION_RUNTIME_PROGRAM_SUBMIT,
            map_value([
                (
                    "source",
                    Value::string(serde_json::to_string_pretty(&Program::new(echo()?))?),
                ),
                ("input", Value::integer(73)),
                ("submission_identity", identity_value(&identity)),
            ]),
        )
        .await?;
    let original = reference(&first)?;
    let id = original.execution_id.as_deref().context("retained id")?;
    let finished = fixture.finished(id).await?;
    let deadline = field(&finished, "deadline")?.clone();
    let replay = submit(&fixture, request(identity.clone(), Value::integer(73))?).await?;
    ensure!(reference(&replay)? == original);
    ensure!(
        field(
            replay.output.as_ref().context("retry proof")?,
            "submission_evidence"
        )?
        .as_str()
            == Some("accepted")
    );
    let evidence = lookup(&fixture, &identity).await?;
    ensure!(field(&evidence, "evidence")?.as_str() == Some("accepted"));
    ensure!(evidence.as_map().is_some_and(|fields| fields.len() == 2));
    ensure!(field(&fixture.finished(id).await?, "deadline")? == &deadline);
    ensure!(fixture.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn guarded_retry_binds_raw_input_budget_and_optional_timeout() -> anyhow::Result<()> {
    let fixture = Fixture::new(config()).await?;
    let identity = identity(&fixture, "fingerprint");
    let first = submit(&fixture, request(identity.clone(), Value::integer(4))?).await?;
    fixture
        .finished(reference(&first)?.execution_id.as_deref().context("id")?)
        .await?;
    let changed_input = request(identity.clone(), Value::integer(5))?;
    let mut changed_budget = request(identity.clone(), Value::integer(4))?;
    changed_budget.budget.max_micro_usd = Some(u64::MAX);
    let mut changed_duration = request(identity.clone(), Value::integer(4))?;
    changed_duration.timeout_ms = Some(fixture.state.runtime.config.max_duration_ms);
    for changed in [changed_input, changed_budget, changed_duration] {
        let rejected = submit(&fixture, changed)
            .await
            .err()
            .context("fingerprint conflict")?;
        ensure!(rejected.code == ConsoleErrorCode::BadRequest);
    }
    let replay = submit(&fixture, request(identity, Value::integer(4))?).await?;
    ensure!(reference(&replay)? == reference(&first)?);
    ensure!(fixture.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn forgotten_submission_keeps_retry_proof_until_host_closes_epoch() -> anyhow::Result<()> {
    let fixture = Fixture::new(ConsoleExecutionConfig {
        max_records: 1,
        max_records_per_account: 1,
        max_concurrent: 1,
        max_concurrent_per_account: 1,
        ..config()
    })
    .await?;
    let identity = identity(&fixture, "retained");
    let first = submit(&fixture, request(identity.clone(), Value::integer(4))?).await?;
    let original = reference(&first)?;
    let id = original.execution_id.as_deref().context("id")?;
    fixture.finished(id).await?;
    fixture
        .call(ACTION_RUNTIME_EXECUTION_FORGET, id_input(id))
        .await?;
    ensure!(field(&lookup(&fixture, &identity).await?, "evidence")?.as_str() == Some("retired"));
    let replay = submit(&fixture, request(identity.clone(), Value::integer(4))?).await?;
    ensure!(reference(&replay)? == original);
    ensure!(
        field(
            replay.output.as_ref().context("retired proof")?,
            "submission_evidence"
        )?
        .as_str()
            == Some("retired")
    );
    let mut next = identity.clone();
    next.nonce = "new-work".into();
    ensure!(
        submit(&fixture, request(next.clone(), Value::integer(4))?)
            .await
            .err()
            .context("full")?
            .code
            == ConsoleErrorCode::RateLimited
    );
    let successor = fixture
        .service
        .close_submission_retry_epoch(identity.retry_epoch)?;
    ensure!(field(&lookup(&fixture, &identity).await?, "evidence")?.as_str() == Some("unproven"));
    ensure!(
        submit(&fixture, request(identity.clone(), Value::integer(4))?)
            .await
            .is_err()
    );
    next.retry_epoch = successor;
    let second = submit(&fixture, request(next, Value::integer(4))?).await?;
    fixture
        .finished(
            reference(&second)?
                .execution_id
                .as_deref()
                .context("new id")?,
        )
        .await?;
    ensure!(fixture.calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn failed_program_admission_releases_preparing_identity() -> anyhow::Result<()> {
    let fixture = Fixture::new(config()).await?;
    let identity = identity(&fixture, "invalid-method");
    let mut invalid = request(identity.clone(), Value::integer(4))?;
    let mut operation = match echo()? {
        Expression::Invoke { ref operation } => operation.clone(),
        _ => anyhow::bail!("echo operation"),
    };
    operation.method = "missing".into();
    invalid.code = RuntimeCode::Operation { operation };
    ensure!(submit(&fixture, invalid).await.is_err());
    ensure!(field(&lookup(&fixture, &identity).await?, "evidence")?.as_str() == Some("unproven"));
    let accepted = submit(&fixture, request(identity, Value::integer(4))?).await?;
    fixture
        .finished(
            reference(&accepted)?
                .execution_id
                .as_deref()
                .context("id")?,
        )
        .await?;
    ensure!(fixture.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn preparing_lookup_is_not_acceptance_and_attached_calls_reject_identity()
-> anyhow::Result<()> {
    let fixture = Fixture::new(config()).await?;
    let identity = identity(&fixture, "preparing");
    let typed =
        super::super::super::request::action(request(identity.clone(), Value::integer(4))?, true).1;
    let owner = fixture.owner().await?;
    let probe = fixture.state.executions.prepare_root_submission(
        &owner,
        &identity,
        typed.submission_fingerprint()?,
    )?;
    let crate::runtime::executions::RootSubmissionProbe::Reserved(reservation) = probe else {
        anyhow::bail!("new identity reservation");
    };
    let evidence = lookup(&fixture, &identity).await?;
    ensure!(field(&evidence, "evidence")?.as_str() == Some("preparing"));
    ensure!(field(&evidence, "execution")?.is_null());
    ensure!(
        submit(&fixture, request(identity.clone(), Value::integer(4))?)
            .await
            .err()
            .context("pending")?
            .code
            == ConsoleErrorCode::RateLimited
    );
    let rejected = fixture
        .service
        .run_runtime(
            &fixture.token,
            Some("embedded"),
            request(identity.clone(), Value::integer(4))?,
        )
        .await
        .err()
        .context("attached identity rejected")?;
    ensure!(rejected.code == ConsoleErrorCode::BadRequest);
    ensure!(fixture.calls.load(Ordering::SeqCst) == 0);
    drop(reservation);
    ensure!(field(&lookup(&fixture, &identity).await?, "evidence")?.as_str() == Some("unproven"));
    Ok(())
}

#[tokio::test]
async fn concurrent_guarded_submissions_produce_one_original_execution() -> anyhow::Result<()> {
    let fixture = Fixture::new(config()).await?;
    let identity = identity(&fixture, "concurrent");
    let (left, right) = tokio::join!(
        submit(&fixture, request(identity.clone(), Value::integer(4))?),
        submit(&fixture, request(identity.clone(), Value::integer(4))?),
    );
    let results = [left, right];
    let accepted = results
        .iter()
        .find_map(|result| result.as_ref().ok())
        .context("one acceptance")?;
    let original = reference(accepted)?;
    for result in &results {
        match result {
            Ok(result) => ensure!(reference(result)? == original),
            Err(error) => ensure!(error.code == ConsoleErrorCode::RateLimited),
        }
    }
    fixture
        .finished(original.execution_id.as_deref().context("id")?)
        .await?;
    ensure!(
        reference(&submit(&fixture, request(identity, Value::integer(4))?).await?)? == original
    );
    ensure!(fixture.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}
