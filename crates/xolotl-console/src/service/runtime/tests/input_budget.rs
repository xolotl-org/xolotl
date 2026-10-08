use super::*;
use crate::{RuntimeCode, RuntimeRequest};
use xolotl_types::value::inspection::{ValueAdmissionLimits, admit};

fn shared_input() -> Value {
    let leaf = Value::list(vec![Value::integer(1), Value::string("hello".into())]);
    Value::list(vec![leaf.clone(), leaf])
}

fn limited_state(
    original: &ConsoleState,
    nodes: usize,
    depth: usize,
    bytes: usize,
) -> anyhow::Result<Arc<ConsoleState>> {
    Ok(ConsoleState::with_config(
        original.boot.clone(),
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            runtime: ConsoleRuntimeConfig {
                max_input_nodes: nodes,
                max_input_depth: depth,
                max_input_inline_bytes: bytes,
                ..original.runtime.config.clone()
            },
            ..Default::default()
        },
    )?)
}

fn typed_plan(
    state: &ConsoleState,
    principal: &ConsolePrincipal,
    program: Program,
    input: Value,
) -> Result<Plan, ConsoleError> {
    let request = RuntimeRequest::new(
        RuntimeCode::Program(program),
        input,
        "input budget",
        "operator requested an invocation",
        30_000,
    );
    let (call, typed) = request::action(request, false);
    plan(state, principal, &call, false, Some(typed))
}

#[tokio::test]
async fn source_and_typed_outer_inputs_share_logical_budget_before_dispatch() -> anyhow::Result<()>
{
    let (original, principal, calls) = fixture()?;
    let input = shared_input();
    let limits = ValueAdmissionLimits {
        max_nodes: 7,
        max_depth: 3,
        max_inline_bytes: 32,
    };
    let footprint = admit(&input, limits).context("exact logical footprint")?;
    ensure!((footprint.nodes, footprint.depth, footprint.inline_bytes) == (7, 3, 32));
    let program = Program::new(invoke("identity", OutputMode::Unary)?);
    let accepted = limited_state(&original, 7, 3, 32)?;
    let typed = typed_plan(&accepted, &principal, program.clone(), input.clone())?;
    ensure!(typed.input == input);
    let result = execute(&accepted, &principal, call(program.clone(), input.clone())?).await?;
    ensure!(result_value(result)? == input);
    ensure!(calls.load(Ordering::SeqCst) == 1);

    for (nodes, depth, bytes) in [(6, 3, 32), (7, 2, 32), (7, 3, 31)] {
        let state = limited_state(&original, nodes, depth, bytes)?;
        let source = execute(&state, &principal, call(program.clone(), input.clone())?)
            .await
            .err()
            .context("source input should be rejected")?;
        ensure!(source.code == ConsoleErrorCode::BadRequest);
        let typed = typed_plan(&state, &principal, program.clone(), input.clone())
            .err()
            .context("typed input should be rejected")?;
        let typed = ConsoleFailure::from(typed);
        ensure!(typed.code == ConsoleErrorCode::BadRequest);
        ensure!(calls.load(Ordering::SeqCst) == 1);
    }
    Ok(())
}

#[test]
fn outer_input_config_rejects_zero_and_oversized_limits() -> anyhow::Result<()> {
    for (nodes, depth, bytes) in [
        (0, 128, 4 * 1024 * 1024),
        (16_384, 0, 4 * 1024 * 1024),
        (16_384, 128, 0),
        (65_537, 128, 4 * 1024 * 1024),
        (16_384, 1_025, 4 * 1024 * 1024),
        (16_384, 128, 64 * 1024 * 1024 + 1),
    ] {
        let result = crate::runtime::RuntimeAdmission::new(ConsoleRuntimeConfig {
            max_input_nodes: nodes,
            max_input_depth: depth,
            max_input_inline_bytes: bytes,
            ..Default::default()
        });
        ensure!(result.is_err(), "invalid input limits were accepted");
    }
    Ok(())
}
