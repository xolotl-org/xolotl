use super::*;
use std::task::Poll;
use xolotl_types::{ProcessId, ReplayClass, TaintSource};

fn waiting(path: &str) -> anyhow::Result<Expression> {
    Ok(Expression::Wait {
        wait: WaitSpec::Signal(Path::parse(path)?),
    })
}

fn signal_fixture(
    modules: crate::runtime::ConsoleModules,
) -> anyhow::Result<(Arc<ConsoleState>, ConsolePrincipal, Arc<AtomicUsize>)> {
    let (state, principal, calls) = fixture_with_modules(modules)?;
    xolotl_standard::install_standard(&state.boot, &xolotl_standard::StandardConfig::default())?;
    Ok((state, principal, calls))
}

#[tokio::test]
async fn signal_binding_uses_real_operations_facts_and_provenance() -> anyhow::Result<()> {
    let (state, principal, _) = signal_fixture(Default::default())?;
    let path = Path::parse("state://signals/ready")?;
    let value = Value::bytes(vec![0, 128, 255]);
    let protected = TaintSet::of(TaintSource::Protected { path: path.clone() });
    state
        .state
        .write_set_tainted(&path, value.clone(), protected.clone())
        .await?;
    let source = Program::new(waiting(&path.to_string())?);
    let compiled = source.compile()?;
    let source_id = compiled.id();
    ensure!(xolotl_kernel::PreparedProgram::new(&compiled)?.id() == source_id);
    let (output, execution) =
        execute_with_fact_recording(&state, &principal, call(source, Value::integer(17))?).await?;
    let effective: String = source_id.iter().map(|byte| format!("{byte:02x}")).collect();
    ensure!(execution.program_id == effective);
    let process = ProcessId::new(execution.process_id.parse()?);
    let facts = state.boot.kernel().facts().facts_of(process)?;
    let fact = facts
        .iter()
        .find(|fact| fact.replay == ReplayClass::Observation)
        .context("signal observation fact")?;
    ensure!(fact.outcome.as_ref() == Some(&value));
    ensure!(fact.input == Value::integer(17));
    ensure!(fact.taint.has_protected());
    ensure!(output.outcome == Outcome::Done(value));
    ensure!(output.taint.has_protected());
    ensure!(state.boot.kernel().handles().is_empty());
    Ok(())
}

#[tokio::test]
async fn signal_authority_is_checked_before_earlier_effects() -> anyhow::Result<()> {
    let (state, mut principal, calls) = signal_fixture(Default::default())?;
    for (path, grants) in [
        (
            "state://signals/ready",
            vec!["perform://effect/calculator/**", "read://state/signals/**"],
        ),
        ("state://outside/ready", vec!["*://**"]),
    ] {
        principal.grants = CapSet::from_strs(grants)?;
        let source = Program::new(invoke("identity", OutputMode::Unary)?.then(waiting(path)?));
        let error = execute(&state, &principal, call(source, Value::null())?)
            .await
            .err()
            .context("denied observation")?;
        ensure!(error.code == ConsoleErrorCode::Forbidden && calls.load(Ordering::SeqCst) == 0);
    }
    Ok(())
}

#[tokio::test]
async fn explicit_subscribe_method_checks_conditional_grant_against_operation_input()
-> anyhow::Result<()> {
    let (state, mut principal, _) = signal_fixture(Default::default())?;
    let path = Path::parse("state://signals/ready")?;
    state.state.write_set(&path, Value::integer(42)).await?;
    principal.grants = CapSet::from_strs(["subscribe://state/signals/ready@tenant=alice"])?;
    let program = Program::new(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(path),
            method: "subscribe".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    });
    let allowed = call(
        program.clone(),
        map_value([("tenant", Value::string("alice".into()))]),
    )?;
    ensure!(result_value(execute(&state, &principal, allowed).await?)? == Value::integer(42));
    let denied = call(
        program,
        map_value([("tenant", Value::string("bob".into()))]),
    )?;
    let error = execute(&state, &principal, denied)
        .await
        .err()
        .context("non-matching operation input must fail")?;
    ensure!(error.code == ConsoleErrorCode::Forbidden);
    Ok(())
}

#[tokio::test]
async fn waiting_call_cancellation_releases_handles_and_execution_capacity() -> anyhow::Result<()> {
    let (state, principal, _) = signal_fixture(Default::default())?;
    let path = "state://signals/later";
    let source = Program::new(waiting(path)?);
    let mut pending = Box::pin(execute(
        &state,
        &principal,
        call(source.clone(), Value::null())?,
    ));
    ensure!(
        std::future::poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    ensure!(state.calls.available_permits() == 0);
    drop(pending);
    ensure!(state.calls.available_permits() == 1);
    ensure!(state.boot.kernel().handles().is_empty());
    ensure!(state.boot.drain_cleanup().await.failures.is_empty());
    // A present null is a completed signal, not the absence of a signal.
    state
        .state
        .write_set(&Path::parse(path)?, Value::null())
        .await?;
    ensure!(
        result_value(execute(&state, &principal, call(source, Value::null())?).await?)?.is_null()
    );
    Ok(())
}

#[tokio::test]
async fn module_signal_manifests_are_authorized_and_loaded_before_use() -> anyhow::Result<()> {
    use crate::runtime::{ConsoleModule, ConsoleModules, ModuleManifest};
    let path = Path::parse("state://signals/module")?;
    let body = waiting(&path.to_string())?;
    let modules = ConsoleModules::new([ConsoleModule::new(
        ModuleManifest {
            name: "signal".into(),
            revision: [5; 32],
            operations: vec![],
            modules: vec![],
            identities: vec![],
            signals: vec![path.clone()],
        },
        move |_, _| Ok(Program::new(body.clone())),
    )])?;
    let (state, mut principal, calls) = signal_fixture(modules)?;
    let source = Program::new(
        invoke("identity", OutputMode::Unary)?.then(Expression::Module {
            module: xolotl_graph::StepRef::new("signal"),
        }),
    );
    principal.grants = CapSet::from_strs(["perform://effect/calculator/**"])?;
    let (_, hidden) = super::modules::described_modules(&state, &principal).await?;
    ensure!(hidden.is_empty());
    let error = execute(&state, &principal, call(source.clone(), Value::null())?)
        .await
        .err()
        .context("manifest denial")?;
    ensure!(error.code == ConsoleErrorCode::Forbidden && calls.load(Ordering::SeqCst) == 0);
    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/**",
        "subscribe://state/signals/module@tenant=alice",
    ])?;
    let (_, visible) = super::modules::described_modules(&state, &principal).await?;
    ensure!(visible.len() == 1 && visible[0].name == "signal");
    let error = execute(&state, &principal, call(source.clone(), Value::null())?)
        .await
        .err()
        .context("conditional Signal grant must check the current module input")?;
    ensure!(error.code == ConsoleErrorCode::Forbidden && calls.load(Ordering::SeqCst) == 1);
    state.state.write_set(&path, Value::integer(42)).await?;
    ensure!(
        result_value(
            execute(
                &state,
                &principal,
                call(
                    source.clone(),
                    map_value([("tenant", Value::string("alice".into()))])
                )?
            )
            .await?
        )? == Value::integer(42)
    );
    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/**",
        "subscribe://state/signals/module",
    ])?;
    let (_, visible) = super::modules::described_modules(&state, &principal).await?;
    ensure!(visible.len() == 1 && visible[0].name == "signal");
    ensure!(
        result_value(execute(&state, &principal, call(source, Value::null())?).await?)?
            == Value::integer(42)
    );
    Ok(())
}

#[tokio::test]
async fn signal_paths_use_the_installed_method_authority_across_programs_and_modules()
-> anyhow::Result<()> {
    use crate::runtime::{ConsoleModule, ConsoleModules, ModuleManifest};

    let path = Path::parse("effect://calculator/signal")?;
    let body = waiting(&path.to_string())?;
    let modules = ConsoleModules::new([ConsoleModule::new(
        ModuleManifest {
            name: "effect_signal".into(),
            revision: [6; 32],
            operations: vec![],
            identities: vec![],
            signals: vec![path.clone()],
            modules: vec![],
        },
        move |_, _| Ok(Program::new(body.clone())),
    )])?;
    let (state, mut principal, _) = fixture_with_modules(modules)?;
    state.boot.register_subtree_resource_at(
        "effect://calculator/signal",
        "perform://effect/calculator/signal",
        InterfaceFamily::Callable,
        &[MethodSpec::new(
            "subscribe",
            xolotl_types::MethodAuthority::Perform,
            Purity::Pure,
            xolotl_types::OutputModeSet::UNARY,
        )
        .observes_external()],
        Arc::new(FnDriver(|_, input| Ok(input))),
    )?;

    let direct = Program::new(waiting(&path.to_string())?);
    let module = Program::new(Expression::Module {
        module: xolotl_graph::StepRef::new("effect_signal"),
    });
    principal.grants = CapSet::from_strs(["read://state/calculator/**"])?;
    let (_, hidden) = super::modules::described_modules(&state, &principal).await?;
    ensure!(hidden.is_empty());
    for source in [direct.clone(), module.clone()] {
        let error = execute(&state, &principal, call(source, Value::integer(7))?)
            .await
            .err()
            .context("method authority must deny a read-only grant")?;
        ensure!(error.code == ConsoleErrorCode::Forbidden);
    }

    principal.grants = CapSet::from_strs(["perform://effect/calculator/signal"])?;
    let (_, visible) = super::modules::described_modules(&state, &principal).await?;
    ensure!(visible.len() == 1 && visible[0].name == "effect_signal");
    for source in [direct, module] {
        ensure!(
            result_value(execute(&state, &principal, call(source, Value::integer(7))?).await?)?
                == Value::integer(7)
        );
    }
    Ok(())
}
