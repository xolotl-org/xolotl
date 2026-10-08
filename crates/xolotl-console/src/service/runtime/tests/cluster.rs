use super::*;
use crate::runtime::{ConsoleModule, ConsoleModules, ModuleManifest, ModuleOperation};
use xolotl_graph::StepRef;
use xolotl_types::{MethodAuthority, OutputModeSet};

const LOCAL: &str = "effect://cluster/echo";
const EDGE: &str = "path://edge/effect/cluster/echo";
const OTHER: &str = "path://other/effect/cluster/echo";
const SIGNAL: &str = "path://edge/state/signals/ready";

fn invoke_at(target: &str) -> anyhow::Result<Expression> {
    Ok(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse(target)?),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    })
}

fn fixture(
    modules: ConsoleModules,
    capabilities: Vec<&str>,
) -> anyhow::Result<(Arc<ConsoleState>, ConsolePrincipal, Arc<AtomicUsize>)> {
    let boot = Arc::new(Bootstrap::in_memory());
    let edge_calls = Arc::new(AtomicUsize::new(0));
    for (target, selector, result) in [
        (LOCAL, "perform://effect/cluster/echo", 11),
        (EDGE, "perform://path://edge/effect/cluster/echo", 22),
        (OTHER, "perform://path://other/effect/cluster/echo", 33),
    ] {
        let calls = edge_calls.clone();
        boot.register_subtree_resource_at(
            target,
            selector,
            InterfaceFamily::Callable,
            &[MethodSpec::new(
                "invoke",
                MethodAuthority::Perform,
                Purity::Pure,
                OutputModeSet::UNARY,
            )],
            Arc::new(FnDriver(move |_, _| {
                if result == 22 {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
                Ok(Value::integer(result))
            })),
        )?;
    }
    boot.register_subtree_resource_at(
        SIGNAL,
        "subscribe://path://edge/state/signals/ready",
        InterfaceFamily::Value,
        &[MethodSpec::new(
            "subscribe",
            MethodAuthority::Subscribe,
            Purity::Pure,
            OutputModeSet::UNARY,
        )],
        Arc::new(FnDriver(|_, _| Ok(Value::integer(77)))),
    )?;
    let state = ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            modules,
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                capabilities: capabilities.into_iter().map(str::to_owned).collect(),
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "cluster-user".into(),
        account_id: "cluster-user-account".into(),
        identity_path: "identity://console/accounts/cluster-user-account".into(),
        grants: CapSet::new(),
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    Ok((state, principal, edge_calls))
}

fn describe_target(target: &str) -> ActionCall {
    ActionCall {
        action: ACTION_RUNTIME_RESOURCE_DESCRIBE.into(),
        input: map_value([("target", Value::string(target.into()))]),
        ..Default::default()
    }
}

#[tokio::test]
async fn clustered_resource_and_module_require_matching_host_and_user_scope() -> anyhow::Result<()>
{
    let manifest = ModuleManifest {
        name: "edge_echo".into(),
        revision: [3; 32],
        operations: vec![ModuleOperation {
            target: ResourceName::new(Path::parse(EDGE)?),
            method: "invoke".into(),
            output: OutputMode::Unary,
        }],
        identities: Vec::new(),
        signals: Vec::new(),
        modules: Vec::new(),
    };
    let operation = invoke_at(EDGE)?;
    let modules = ConsoleModules::new([ConsoleModule::new(manifest, move |_, _| {
        Ok(Program::new(operation.clone()))
    })])?;
    let (state, mut principal, calls) =
        fixture(modules, vec!["perform://path://edge/effect/cluster/echo"])?;
    let process_count = state.boot.kernel().processes().len();
    principal.grants = CapSet::from_strs(["perform://effect/cluster/echo"])?;
    let denied = execute(&state, &principal, describe_target(EDGE))
        .await
        .err()
        .context("local grant must not describe clustered resource")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    let (_, hidden) = super::modules::described_modules(&state, &principal).await?;
    ensure!(hidden.is_empty());
    let denied = execute(
        &state,
        &principal,
        call(Program::new(invoke_at(EDGE)?), Value::null())?,
    )
    .await
    .err()
    .context("local grant must not invoke clustered resource")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    ensure!(state.boot.kernel().processes().len() == process_count);
    ensure!(calls.load(Ordering::SeqCst) == 0);

    principal.grants = CapSet::from_strs([
        "perform://path://edge/effect/cluster/echo",
        "perform://path://other/effect/cluster/echo",
    ])?;
    let described = execute(&state, &principal, describe_target(EDGE)).await?;
    ensure!(
        described
            .output
            .as_ref()
            .and_then(Value::as_map)
            .and_then(|map| map.get("target"))
            .and_then(Value::as_str)
            == Some(EDGE)
    );
    let (_, visible) = super::modules::described_modules(&state, &principal).await?;
    ensure!(visible.len() == 1 && visible[0].name == "edge_echo");
    for target in [LOCAL, OTHER] {
        let denied = execute(&state, &principal, describe_target(target))
            .await
            .err()
            .context("target outside host/user intersection")?;
        ensure!(denied.code == ConsoleErrorCode::Forbidden);
        let denied = execute(
            &state,
            &principal,
            call(Program::new(invoke_at(target)?), Value::null())?,
        )
        .await
        .err()
        .context("target outside host/user intersection")?;
        ensure!(denied.code == ConsoleErrorCode::Forbidden);
    }
    ensure!(calls.load(Ordering::SeqCst) == 0);
    let mut single = call(Program::new(Expression::Input), Value::null())?;
    single.action = ACTION_RUNTIME_OPERATION_INVOKE.into();
    single.input = map_value([
        ("target", Value::string(EDGE.into())),
        ("method", Value::string("invoke".into())),
    ]);
    ensure!(result_value(execute(&state, &principal, single).await?)? == Value::integer(22));
    ensure!(
        result_value(
            execute(
                &state,
                &principal,
                call(
                    Program::new(Expression::Module {
                        module: StepRef::new("edge_echo")
                    }),
                    Value::null()
                )?,
            )
            .await?
        )? == Value::integer(22)
    );
    ensure!(calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn clustered_signal_uses_installed_subscribe_method_and_its_own_authority()
-> anyhow::Result<()> {
    let signal = Path::parse(SIGNAL)?;
    let module = ConsoleModule::new(
        ModuleManifest {
            name: "edge_signal".into(),
            revision: [4; 32],
            operations: Vec::new(),
            identities: Vec::new(),
            signals: vec![signal.clone()],
            modules: Vec::new(),
        },
        move |_, _| {
            Ok(Program::new(Expression::Wait {
                wait: WaitSpec::Signal(signal.clone()),
            }))
        },
    );
    let (state, mut principal, calls) = fixture(
        ConsoleModules::new([module])?,
        vec![
            "perform://path://edge/effect/cluster/echo",
            "subscribe://path://edge/state/signals/ready",
        ],
    )?;
    principal.grants = CapSet::from_strs(["perform://path://edge/effect/cluster/echo"])?;
    let (_, hidden) = super::modules::described_modules(&state, &principal).await?;
    ensure!(hidden.is_empty());
    let program = Program::new(invoke_at(EDGE)?.then(Expression::Wait {
        wait: WaitSpec::Signal(Path::parse(SIGNAL)?),
    }));
    let denied = execute(&state, &principal, call(program.clone(), Value::null())?)
        .await
        .err()
        .context("missing subscribe authority")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    ensure!(calls.load(Ordering::SeqCst) == 0);
    principal.grants.push(xolotl_types::Capability::parse(
        "subscribe://path://edge/state/signals/ready",
    )?);
    let (_, visible) = super::modules::described_modules(&state, &principal).await?;
    ensure!(visible.len() == 1 && visible[0].name == "edge_signal");
    ensure!(
        result_value(execute(&state, &principal, call(program, Value::null())?).await?)?
            == Value::integer(77)
    );
    ensure!(calls.load(Ordering::SeqCst) == 1);
    ensure!(
        result_value(
            execute(
                &state,
                &principal,
                call(
                    Program::new(Expression::Module {
                        module: StepRef::new("edge_signal")
                    }),
                    Value::null()
                )?,
            )
            .await?
        )? == Value::integer(77)
    );
    Ok(())
}
