use super::*;
use anyhow::{Context, bail, ensure};

#[test]
fn runtime_preparation_moves_payloads_and_preserves_artifact_identity() -> anyhow::Result<()> {
    let compiled = Program::new(Expression::Constant {
        value: Value::bytes(vec![42; 1024 * 1024]),
    })
    .compile()?;
    let identity = compiled.id();
    let NodeKind::Literal(value) = &compiled.image().nodes[0].kind else {
        bail!("expected a byte constant");
    };
    let bytes = value.as_bytes().context("expected byte payload")?;
    let payload = bytes.as_ptr();
    let prepared = compiled.with_provenance();
    let NodeKind::Literal(value) = &prepared.image().nodes[0].kind else {
        bail!("expected the prepared constant");
    };
    let bytes = value
        .value
        .as_bytes()
        .context("expected original byte payload")?;
    ensure!(
        bytes.as_ptr() == payload,
        "preparation cloned the payload buffer"
    );
    ensure!(bytes.len() == 1024 * 1024);
    ensure!(value.taint == xolotl_types::TaintSet::author());
    ensure!(prepared.id() == identity);
    prepared.image().validate()?;
    Ok(())
}

#[test]
fn runtime_preparation_preserves_static_failures_in_the_tainted_error_type() -> anyhow::Result<()> {
    let compiled = Program::new(Expression::Fail {
        message: "authored failure".into(),
    })
    .compile()?;
    let identity = compiled.id();
    let prepared = compiled.with_provenance();
    let NodeKind::Fail(error) = &prepared.image().nodes[0].kind else {
        bail!("expected the prepared failure");
    };
    ensure!(error.failure == Failure::policy("program", "authored failure"));
    ensure!(error.taint.is_pristine());
    ensure!(prepared.id() == identity);
    prepared.image().validate()?;
    Ok(())
}

#[test]
fn large_module_uses_explicit_admission() -> anyhow::Result<()> {
    let program = Program::new(Expression::Sequence {
        steps: vec![Expression::Input; 65_537],
    });
    ensure!(matches!(program.compile(), Err(CompileError::Capacity)));
    let compiled = program.compile_with_limits(CompileLimits {
        instructions: 65_537,
        ..CompileLimits::default()
    })?;
    ensure!(compiled.image().nodes.len() == 65_537);
    Ok(())
}

#[test]
fn source_bytes_are_a_host_selected_module_budget() -> anyhow::Result<()> {
    let program = Program::new(Expression::literal("x".repeat(1024 * 1024)));
    let encoded = serde_json::to_vec(&program)?;
    ensure!(matches!(
        Program::from_json(&encoded),
        Err(CompileError::Capacity)
    ));
    let limits = CompileLimits {
        source_bytes: encoded.len(),
        ..CompileLimits::default()
    };
    let decoded = Program::from_json_with_limits(&encoded, limits)?;
    ensure!(decoded == program);
    ensure!(matches!(
        Program::from_json_with_limits(
            &encoded,
            CompileLimits {
                source_bytes: encoded.len() - 1,
                ..limits
            }
        ),
        Err(CompileError::Capacity)
    ));
    Ok(())
}

#[test]
fn admission_does_not_change_program_identity() -> anyhow::Result<()> {
    let program = Program::new(Expression::literal(7));
    let default = program.compile()?;
    let small = program.compile_with_limits(CompileLimits {
        instructions: 1,
        expression_depth: 0,
        ..CompileLimits::default()
    })?;
    ensure!(default.id() == small.id());
    ensure!(default.image().nodes == small.image().nodes);
    ensure!(matches!(
        program.compile_with_limits(CompileLimits {
            instructions: 0,
            ..CompileLimits::default()
        }),
        Err(CompileError::Capacity)
    ));
    Ok(())
}
