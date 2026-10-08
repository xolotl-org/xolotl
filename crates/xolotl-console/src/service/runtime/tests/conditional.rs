use super::*;
use crate::runtime::{ConsoleModule, ConsoleModules, ModuleManifest, ModuleOperation};
use xolotl_graph::StepRef;

fn input(tenant: &str) -> Value {
    map_value([("tenant", Value::string(tenant.into()))])
}

#[tokio::test]
async fn conditional_operation_grants_are_or_alternatives_at_actual_input() -> anyhow::Result<()> {
    let (state, mut principal, calls) = fixture()?;
    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/**@tenant=alice",
        "perform://effect/calculator/**@tenant=bob",
    ])?;
    let program = Program::new(invoke("identity", OutputMode::Unary)?);
    for tenant in ["alice", "bob"] {
        let value = input(tenant);
        let result = execute(&state, &principal, call(program.clone(), value.clone())?).await?;
        ensure!(result_value(result)? == value);
    }
    ensure!(calls.load(Ordering::SeqCst) == 2);
    let denied = execute(&state, &principal, call(program.clone(), input("mallory"))?)
        .await
        .err()
        .context("unmatched operation input must fail")?;
    ensure!(calls.load(Ordering::SeqCst) == 2, "{denied}");

    principal.grants = CapSet::from_strs(["perform://effect/calculator/**@until=0"])?;
    let expired = execute(&state, &principal, call(program, input("alice"))?)
        .await
        .err()
        .context("expired capability must fail")?;
    ensure!(calls.load(Ordering::SeqCst) == 2, "{expired}");
    Ok(())
}

#[tokio::test]
async fn conditional_acting_checks_scope_input_without_granting_method_authority()
-> anyhow::Result<()> {
    let (state, mut principal, calls) = fixture()?;
    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/**",
        "act-as://identity/calculator/worker@tenant=alice",
        "act-as://identity/calculator/worker@tenant=bob",
    ])?;
    let program = Program::new(Expression::Acting {
        identity: Path::parse("identity://calculator/worker")?,
        body: Box::new(invoke("identity", OutputMode::Unary)?),
    });
    for tenant in ["alice", "bob"] {
        let value = input(tenant);
        let result = execute(&state, &principal, call(program.clone(), value.clone())?).await?;
        ensure!(result_value(result)? == value);
    }
    ensure!(calls.load(Ordering::SeqCst) == 2);
    let denied = execute(&state, &principal, call(program, input("mallory"))?)
        .await
        .err()
        .context("unmatched acting scope must fail")?;
    ensure!(calls.load(Ordering::SeqCst) == 2, "{denied}");
    Ok(())
}

#[tokio::test]
async fn conditional_signal_wait_checks_the_value_entering_the_wait_node() -> anyhow::Result<()> {
    let (state, mut principal, calls) = fixture()?;
    xolotl_standard::install_standard(&state.boot, &xolotl_standard::StandardConfig::default())?;
    let signal = Path::parse("state://signals/ready")?;
    state.state.write_set(&signal, Value::integer(42)).await?;
    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/**",
        "subscribe://state/signals/ready@tenant=alice",
    ])?;
    let program = Program::new(
        invoke("identity", OutputMode::Unary)?.then(Expression::Wait {
            wait: WaitSpec::Signal(signal),
        }),
    );
    let allowed = execute(&state, &principal, call(program.clone(), input("alice"))?).await?;
    ensure!(result_value(allowed)? == Value::integer(42));
    let denied = execute(&state, &principal, call(program, input("bob"))?)
        .await
        .err()
        .context("signal input predicate must deny the value entering Wait")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden, "{denied}");
    ensure!(calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn module_import_keeps_conditional_method_alternatives() -> anyhow::Result<()> {
    let operation = OperationTemplate {
        target: ResourceName::new(Path::parse("effect://calculator/run")?),
        method: "identity".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    };
    let manifest = ModuleManifest {
        name: "tenant_identity".into(),
        revision: [9; 32],
        operations: vec![ModuleOperation {
            target: operation.target.clone(),
            method: operation.method.clone(),
            output: operation.output,
        }],
        identities: Vec::new(),
        signals: Vec::new(),
        modules: Vec::new(),
    };
    let modules = ConsoleModules::new([ConsoleModule::new(manifest, move |_, _| {
        Ok(Program::new(Expression::Invoke {
            operation: operation.clone(),
        }))
    })])?;
    let (state, mut principal, calls) = fixture_with_modules(modules)?;
    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/run@tenant=alice",
        "perform://effect/calculator/run@tenant=bob",
    ])?;
    let program = Program::new(Expression::Module {
        module: StepRef::new("tenant_identity"),
    });
    for tenant in ["alice", "bob"] {
        let value = input(tenant);
        let result = execute(&state, &principal, call(program.clone(), value.clone())?).await?;
        ensure!(result_value(result)? == value);
    }
    ensure!(calls.load(Ordering::SeqCst) == 2);
    let denied = execute(&state, &principal, call(program, input("mallory"))?)
        .await
        .err()
        .context("module operation must retain the user predicate")?;
    ensure!(calls.load(Ordering::SeqCst) == 2, "{denied}");
    Ok(())
}
