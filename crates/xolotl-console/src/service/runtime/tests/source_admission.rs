use super::*;
use crate::{RuntimeCode, RuntimeRequest};

pub(super) fn limited_source_state(
    original: &ConsoleState,
    source_bytes: usize,
) -> anyhow::Result<Arc<ConsoleState>> {
    Ok(ConsoleState::with_config(
        original.boot.clone(),
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            max_concurrent_calls: 1,
            modules: original.modules.clone(),
            runtime: ConsoleRuntimeConfig {
                max_source_bytes: source_bytes,
                ..original.runtime.config.clone()
            },
            ..Default::default()
        },
    )?)
}

fn typed_request(program: Program) -> (ActionCall, TypedRuntimeInput) {
    request::action(
        RuntimeRequest::new(
            RuntimeCode::Program(program),
            Value::null(),
            "source admission",
            "operator requested a program",
            30_000,
        ),
        false,
    )
}

#[tokio::test]
async fn escaped_sources_share_exact_rust_and_json_admission_boundaries() -> anyhow::Result<()> {
    let (original, principal, calls) = fixture()?;
    let text = "\0\n\"\\".repeat(128);
    let program = Program::new(
        invoke("identity", OutputMode::Unary)?.then(Expression::literal(text.clone())),
    );
    let encoded = serde_json::to_vec(&program)?;
    let accepted = limited_source_state(&original, encoded.len())?;
    let source_call = call(program.clone(), Value::null())?;
    let source_plan = plan(&accepted, &principal, &source_call, false, None)?;
    let (typed_call, typed) = typed_request(program.clone());
    let typed_plan = plan(&accepted, &principal, &typed_call, false, Some(typed))?;
    ensure!(source_plan.prepared.id() == typed_plan.prepared.id());

    let source_result = execute(&accepted, &principal, source_call).await?;
    let (typed_call, typed) = typed_request(program.clone());
    let typed_result = run(
        &ActionContext {
            delivery: None,
            state: &accepted,
            source_addr: Some("embedded"),
            session_id: "test",
        },
        &principal,
        &typed_call,
        Some(typed),
    )
    .await?;
    ensure!(result_value(source_result)? == Value::string(text.clone()));
    ensure!(result_value(typed_result)? == Value::string(text));
    ensure!(calls.load(Ordering::SeqCst) == 2);

    let mut padded_call = call(program.clone(), Value::null())?;
    padded_call.input = map_value([(
        "source",
        Value::string(format!(" {}", serde_json::to_string(&program)?)),
    )]);
    let padded_failure = execute(&accepted, &principal, padded_call)
        .await
        .err()
        .context("protocol admission must count actual source bytes")?;
    ensure!(padded_failure.code == ConsoleErrorCode::BadRequest);

    let rejected = limited_source_state(&original, encoded.len() - 1)?;
    program.validate_structure_with_limits(rejected.runtime.compile_limits())?;
    let source_failure = execute(&rejected, &principal, call(program.clone(), Value::null())?)
        .await
        .err()
        .context("JSON source one byte over its limit")?;
    let (typed_call, typed) = typed_request(program);
    let typed_failure = run(
        &ActionContext {
            delivery: None,
            state: &rejected,
            source_addr: Some("embedded"),
            session_id: "test",
        },
        &principal,
        &typed_call,
        Some(typed),
    )
    .await
    .err()
    .context("Rust source one byte over its limit")?;
    ensure!(source_failure.code == ConsoleErrorCode::BadRequest);
    ensure!(ConsoleFailure::from(typed_failure).code == ConsoleErrorCode::BadRequest);
    ensure!(calls.load(Ordering::SeqCst) == 2);
    ensure!(original.boot.kernel().handles().is_empty());
    Ok(())
}

#[tokio::test]
async fn source_validation_preserves_input_rejections() -> anyhow::Result<()> {
    let (state, principal, calls) = fixture()?;
    for (source, expected) in [
        (None, "source is required"),
        (
            Some(Value::string(String::new())),
            "source must be a non-empty string",
        ),
        (Some(Value::null()), "source must be a non-empty string"),
        (Some(Value::integer(1)), "source must be a non-empty string"),
        (
            Some(Value::bytes(vec![1])),
            "source must be a non-empty string",
        ),
    ] {
        let mut source_call = call(Program::new(Expression::Input), Value::null())?;
        source_call.input = map_value(source.into_iter().map(|value| ("source", value)));
        match plan(&state, &principal, &source_call, false, None) {
            Err(ConsoleError::BadRequest(reason)) => ensure!(reason == expected),
            _ => anyhow::bail!("invalid source did not preserve its validation error"),
        }
    }
    for source in [" ", "{", "null"] {
        let mut source_call = call(Program::new(Expression::Input), Value::null())?;
        source_call.input = map_value([("source", Value::string(source.into()))]);
        let failure = execute(&state, &principal, source_call)
            .await
            .err()
            .context("malformed source must be rejected")?;
        ensure!(failure.code == ConsoleErrorCode::BadRequest);
    }
    let mut unsupported = Program::new(invoke("identity", OutputMode::Unary)?);
    unsupported.version += 1;
    let source_failure = execute(
        &state,
        &principal,
        call(unsupported.clone(), Value::null())?,
    )
    .await
    .err()
    .context("unsupported JSON program version")?;
    let (typed_call, typed) = typed_request(unsupported);
    let typed_failure = plan(&state, &principal, &typed_call, false, Some(typed))
        .err()
        .context("unsupported Rust program version")?;
    ensure!(source_failure.code == ConsoleErrorCode::BadRequest);
    ensure!(ConsoleFailure::from(typed_failure).code == ConsoleErrorCode::BadRequest);
    ensure!(calls.load(Ordering::SeqCst) == 0);
    ensure!(state.boot.kernel().handles().is_empty());
    Ok(())
}
