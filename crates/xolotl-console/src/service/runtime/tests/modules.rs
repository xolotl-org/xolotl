use super::*;
use crate::runtime::{ConsoleModule, ConsoleModules, ModuleManifest, ModuleOperation};
use xolotl_graph::StepRef;
use xolotl_types::OutputModeSet;

fn manifest(name: &str, methods: &[&str], dependencies: &[&str]) -> anyhow::Result<ModuleManifest> {
    Ok(ModuleManifest {
        identities: Vec::new(),
        signals: Vec::new(),
        name: name.into(),
        revision: [7; 32],
        operations: methods
            .iter()
            .map(|method| {
                Ok(ModuleOperation {
                    target: ResourceName::new(Path::parse("effect://calculator/run")?),
                    method: (*method).into(),
                    output: OutputMode::Unary,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
        modules: dependencies.iter().map(|name| (*name).into()).collect(),
    })
}

fn module(name: &str) -> Expression {
    Expression::Module {
        module: StepRef::new(name),
    }
}

pub(super) async fn described_modules(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
) -> anyhow::Result<(ActionResult, Vec<ModuleManifest>)> {
    let result = execute(
        state,
        principal,
        ActionCall {
            action: crate::protocol::ACTION_RUNTIME_DESCRIBE.into(),
            ..Default::default()
        },
    )
    .await?;
    let modules = result
        .output
        .as_ref()
        .and_then(Value::as_map)
        .and_then(|map| map.get("modules"))
        .context("visible modules")?;
    let modules = serde_json::from_value(serde_json::to_value(modules)?)?;
    Ok((result, modules))
}

#[tokio::test]
async fn module_discovery_projects_complete_authorized_dependencies() -> anyhow::Result<()> {
    let visible = manifest("visible", &["identity"], &[])?;
    let mut mixed = manifest("mixed", &["identity"], &[])?;
    mixed.operations.push(ModuleOperation {
        target: ResourceName::new(Path::parse("state://calculator/item")?),
        method: "write".into(),
        output: OutputMode::Unary,
    });
    let parent = manifest("parent", &[], &["mixed"])?;
    let composed = manifest("composed", &[], &["visible"])?;
    let mut outside = manifest("outside", &["identity"], &[])?;
    outside.operations[0].target = ResourceName::new(Path::parse("effect://outside/exposure")?);
    let mut missing_method = manifest("missing_method", &["absent"], &[])?;
    missing_method.operations[0].method = "absent".into();
    let modules = ConsoleModules::new(
        [visible, mixed, parent, composed, outside, missing_method]
            .into_iter()
            .map(|manifest| {
                ConsoleModule::new(manifest, |_, _| Ok(Program::new(Expression::Input)))
            }),
    )?;
    let (state, mut principal, calls) = fixture_with_modules(modules)?;
    principal.grants = CapSet::new();
    let (denied, empty) = described_modules(&state, &principal).await?;
    ensure!(empty.is_empty());
    principal.grants = CapSet::from_strs(["perform://effect/calculator/**"])?;
    let (partial, visible) = described_modules(&state, &principal).await?;
    ensure!(
        visible
            .iter()
            .map(|manifest| manifest.name.as_str())
            .collect::<Vec<_>>()
            == ["composed", "visible"]
    );
    ensure!(visible[0].modules == ["visible"]);
    let installed = state.modules.entries.get("visible").context("installed")?;
    ensure!(visible.get(1) == Some(installed.manifest.as_ref()));
    ensure!(denied.registry_rev == partial.registry_rev);
    let config = partial
        .output
        .as_ref()
        .and_then(Value::as_map)
        .and_then(|map| map.get("config"))
        .and_then(Value::as_map)
        .context("public runtime config")?;
    ensure!(config.get("capabilities").is_none());
    ensure!(calls.load(Ordering::SeqCst) == 0);

    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/**",
        "write://state/calculator/**",
    ])?;
    let (_, extended) = described_modules(&state, &principal).await?;
    ensure!(
        extended
            .iter()
            .map(|manifest| manifest.name.as_str())
            .collect::<Vec<_>>()
            == ["composed", "mixed", "parent", "visible"]
    );
    Ok(())
}

#[tokio::test]
async fn module_discovery_describes_installed_structure_across_lifecycle_switches()
-> anyhow::Result<()> {
    let pure = manifest("pure", &[], &[])?;
    let mut child = manifest("child", &[], &[])?;
    child.operations.push(ModuleOperation {
        target: ResourceName::new(Path::parse("effect://calculator/async")?),
        method: "spawn".into(),
        output: OutputMode::AsyncProcess,
    });
    let parent = manifest("parent", &[], &["child"])?;
    let modules =
        ConsoleModules::new([pure, child, parent].into_iter().map(|manifest| {
            ConsoleModule::new(manifest, |_, _| Ok(Program::new(Expression::Input)))
        }))?;
    let (base, principal, _) = fixture_with_modules(modules.clone())?;
    base.boot.register_subtree_resource_at(
        "effect://calculator/async",
        "perform://effect/calculator/**",
        InterfaceFamily::Callable,
        &[MethodSpec::new(
            "spawn",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            OutputModeSet::ASYNC_PROCESS,
        )],
        Arc::new(FnDriver(|_, input| Ok(input))),
    )?;
    for (runtime_enabled, submissions_enabled) in [(false, false), (true, false), (true, true)] {
        let mut runtime = base.runtime.config.clone();
        runtime.enabled = runtime_enabled;
        runtime.executions.enabled = submissions_enabled;
        runtime
            .capabilities
            .push("spawn-with://effect/calculator/**".into());
        let state = ConsoleState::with_config(
            base.boot.clone(),
            ConsoleConfig {
                session_store: Some(base.auth.session_store.clone()),
                modules: modules.clone(),
                runtime,
                ..Default::default()
            },
        )?;
        let (_, visible) = described_modules(&state, &principal).await?;
        ensure!(
            visible
                .iter()
                .map(|manifest| manifest.name.as_str())
                .collect::<Vec<_>>()
                == ["child", "parent", "pure"]
        );
    }
    Ok(())
}

#[tokio::test]
async fn unsupported_method_output_is_hidden_and_rejected_before_process_allocation()
-> anyhow::Result<()> {
    let supported = manifest("supported", &["identity"], &[])?;
    let mut unsupported = manifest("unsupported", &["identity"], &[])?;
    unsupported.operations[0].output = OutputMode::SinkOnly;
    let dependent = manifest("dependent", &[], &["unsupported"])?;
    let mut oversized_collect = manifest("oversized_collect", &["identity"], &[])?;
    oversized_collect.operations[0].output = OutputMode::Collect { limit: 257 };
    let modules = ConsoleModules::new(
        [supported, unsupported, dependent, oversized_collect]
            .into_iter()
            .map(|manifest| {
                ConsoleModule::new(manifest, |_, _| Ok(Program::new(Expression::Input)))
            }),
    )?;
    let (state, principal, calls) = fixture_with_modules(modules)?;
    let (_, visible) = described_modules(&state, &principal).await?;
    ensure!(
        visible
            .iter()
            .map(|manifest| manifest.name.as_str())
            .collect::<Vec<_>>()
            == ["supported"]
    );

    let process_count = state.boot.kernel().processes().len();
    for program in [
        Program::new(module("unsupported")),
        Program::new(invoke("identity", OutputMode::SinkOnly)?),
        Program::new(module("oversized_collect")),
    ] {
        let failure = execute(&state, &principal, call(program, Value::null())?)
            .await
            .err()
            .context("unsupported output must be rejected")?;
        ensure!(failure.code == ConsoleErrorCode::BadRequest);
        ensure!(failure.execution.is_none());
        ensure!(state.boot.kernel().processes().len() == process_count);
    }
    ensure!(calls.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn module_discovery_hides_identity_and_cyclic_dependencies_together() -> anyhow::Result<()> {
    let mut cycle_a = manifest("cycle_a", &[], &["cycle_b"])?;
    cycle_a
        .identities
        .push(Path::parse("identity://calculator/worker")?);
    let cycle_b = manifest("cycle_b", &[], &["cycle_a"])?;
    let parent = manifest("parent", &[], &["cycle_a"])?;
    let independent = manifest("independent", &["identity"], &[])?;
    let modules = ConsoleModules::new(
        [cycle_a, cycle_b, parent, independent]
            .into_iter()
            .map(|manifest| {
                ConsoleModule::new(manifest, |_, _| Ok(Program::new(Expression::Input)))
            }),
    )?;
    let (state, mut principal, _) = fixture_with_modules(modules)?;
    principal.grants = CapSet::from_strs(["perform://effect/calculator/**"])?;
    let (_, visible) = described_modules(&state, &principal).await?;
    ensure!(
        visible
            .iter()
            .map(|manifest| manifest.name.as_str())
            .collect::<Vec<_>>()
            == ["independent"]
    );
    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/**",
        "act-as://identity/calculator/worker",
    ])?;
    let (_, visible) = described_modules(&state, &principal).await?;
    ensure!(
        visible
            .iter()
            .map(|manifest| manifest.name.as_str())
            .collect::<Vec<_>>()
            == ["cycle_a", "cycle_b", "independent", "parent"]
    );
    Ok(())
}

#[tokio::test]
async fn module_scopes_are_declared_and_authorized_transitively() -> anyhow::Result<()> {
    let identity = Path::parse("identity://calculator/worker")?;
    let mut inner = manifest("inner", &["identity"], &[])?;
    inner.identities.push(identity.clone());
    let body = invoke("identity", OutputMode::Unary)?;
    let modules = ConsoleModules::new([
        ConsoleModule::new(inner, move |_, _| {
            Ok(Program::new(Expression::Acting {
                identity: identity.clone(),
                body: Box::new(body.clone()),
            }))
        }),
        ConsoleModule::new(manifest("outer", &[], &["inner"])?, |_, _| {
            Ok(Program::new(module("inner")))
        }),
    ])?;
    let (state, mut principal, count) = fixture_with_modules(modules)?;
    let program = Program::new(invoke("identity", OutputMode::Unary)?.then(module("outer")));
    principal.grants = CapSet::from_strs(["perform://effect/calculator/**"])?;
    let error = execute(&state, &principal, call(program.clone(), Value::null())?)
        .await
        .err()
        .context("transitive scope denial")?;
    ensure!(error.code == ConsoleErrorCode::Forbidden && count.load(Ordering::SeqCst) == 0);
    principal.grants = CapSet::from_strs([
        "perform://effect/calculator/**",
        "act-as://identity/calculator/worker",
    ])?;
    let value = Value::bytes(vec![255]);
    ensure!(
        result_value(execute(&state, &principal, call(program, value.clone())?).await?)? == value
    );
    ensure!(count.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn independent_modules_compose_with_arguments_and_manifest_revisions() -> anyhow::Result<()> {
    let inner = ConsoleModule::new(
        manifest("inner", &["identity"], &[])?,
        |_input, argument| {
            Ok(Program::new(
                Expression::Constant {
                    value: argument.cloned().unwrap_or(Value::null()),
                }
                .then(Expression::Invoke {
                    operation: OperationTemplate {
                        target: ResourceName::new(
                            Path::parse("effect://calculator/run")
                                .map_err(|_error| Failure::Cancelled)?,
                        ),
                        method: "identity".into(),
                        method_id: None,
                        output: OutputMode::Unary,
                        literal_input: None,
                    },
                }),
            ))
        },
    );
    let outer = ConsoleModule::new(manifest("outer", &[], &["inner"])?, |input, _| {
        Ok(Program::new(Expression::Module {
            module: StepRef::new("inner").with_arg(input.clone()),
        }))
    });
    let modules =
        ConsoleModules::compose([ConsoleModules::new([outer])?, ConsoleModules::new([inner])?])?;
    let (state, principal, count) = fixture_with_modules(modules.clone())?;
    let input = Value::bytes(vec![0, 128, 255]);
    ensure!(
        result_value(
            execute(
                &state,
                &principal,
                call(Program::new(module("outer")), input.clone())?
            )
            .await?
        )? == input
    );
    ensure!(count.load(Ordering::SeqCst) == 1 && state.boot.kernel().handles().is_empty());
    let mut changed = modules.entries.values().cloned().collect::<Vec<_>>();
    std::sync::Arc::make_mut(&mut changed[0].manifest).revision = [8; 32];
    let (changed, _, _) = fixture_with_modules(ConsoleModules::new(changed)?)?;
    ensure!(state.registry.current_rev() != changed.registry.current_rev());
    let reordered = ConsoleModules::new(modules.entries.values().rev().cloned())?;
    let (reordered, _, _) = fixture_with_modules(reordered)?;
    ensure!(state.registry.current_rev() == reordered.registry.current_rev());
    Ok(())
}

#[tokio::test]
async fn module_collect_allowance_bounds_dynamic_loader_output() -> anyhow::Result<()> {
    let mut declared = manifest("bounded_collect", &["identity"], &[])?;
    declared.operations[0].output = OutputMode::Collect { limit: 3 };
    let modules = ConsoleModules::new([ConsoleModule::new(declared, |input, _| {
        let requested = input.as_int().unwrap_or_default();
        let output = if requested < 0 {
            OutputMode::Unary
        } else {
            OutputMode::Collect {
                limit: usize::try_from(requested).unwrap_or_default(),
            }
        };
        Ok(Program::new(Expression::Invoke {
            operation: OperationTemplate {
                target: ResourceName::new(
                    Path::parse("effect://calculator/run").map_err(|_error| Failure::Cancelled)?,
                ),
                method: "identity".into(),
                method_id: None,
                output,
                literal_input: None,
            },
        }))
    })])?;
    let (state, principal, count) = fixture_with_modules(modules)?;
    for requested in [1, 3] {
        let value = result_value(
            execute(
                &state,
                &principal,
                call(
                    Program::new(module("bounded_collect")),
                    Value::integer(requested),
                )?,
            )
            .await?,
        )?;
        ensure!(value == Value::list(vec![Value::integer(requested)]));
    }
    ensure!(count.load(Ordering::SeqCst) == 2);
    for requested in [0, 4, -1] {
        let failure = execute(
            &state,
            &principal,
            call(
                Program::new(module("bounded_collect")),
                Value::integer(requested),
            )?,
        )
        .await
        .err()
        .context("undeclared loader output")?;
        ensure!(failure.code == ConsoleErrorCode::BadRequest);
    }
    ensure!(count.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn module_collect_allowance_cannot_exceed_host_limit() -> anyhow::Result<()> {
    let mut declared = manifest("oversized_collect", &["identity"], &[])?;
    declared.operations[0].output = OutputMode::Collect { limit: 257 };
    let modules = ConsoleModules::new([ConsoleModule::new(declared, |_, _| {
        Ok(Program::new(Expression::Input))
    })])?;
    let (state, principal, count) = fixture_with_modules(modules)?;
    let program =
        Program::new(invoke("identity", OutputMode::Unary)?.then(module("oversized_collect")));
    let failure = execute(&state, &principal, call(program, Value::integer(1))?)
        .await
        .err()
        .context("oversized declared allowance")?;
    ensure!(failure.code == ConsoleErrorCode::BadRequest);
    ensure!(count.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn every_transitive_manifest_is_admitted_before_top_level_effects() -> anyhow::Result<()> {
    let mut denied = manifest("denied", &["identity"], &[])?;
    denied.operations[0].target = ResourceName::new(Path::parse("effect://outside/exposure")?);
    let modules = ConsoleModules::new([
        ConsoleModule::new(manifest("outer", &[], &["denied"])?, |_input, _| {
            Ok(Program::new(Expression::Input))
        }),
        ConsoleModule::new(denied, |_input, _| Ok(Program::new(Expression::Input))),
    ])?;
    let (state, principal, count) = fixture_with_modules(modules)?;
    let program = Program::new(invoke("identity", OutputMode::Unary)?.then(module("outer")));
    let failure = execute(&state, &principal, call(program, Value::null())?)
        .await
        .err()
        .context("transitive rejection")?;
    ensure!(failure.code == ConsoleErrorCode::Forbidden && count.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn loaded_program_is_checked_before_any_of_its_operations_execute() -> anyhow::Result<()> {
    for forbidden in [
        invoke("double", OutputMode::Unary)?,
        module("other"),
        Expression::Wait {
            wait: WaitSpec::Signal(Path::parse("state://vault/secret")?),
        },
        Expression::Acting {
            identity: Path::parse("identity://root")?,
            body: Box::new(Expression::Input),
        },
    ] {
        let allowed = invoke("identity", OutputMode::Unary)?;
        let loader = ConsoleModule::new(manifest("bad", &["identity"], &[])?, move |_input, _| {
            Ok(Program::new(allowed.clone().then(forbidden.clone())))
        });
        let other = ConsoleModule::new(manifest("other", &[], &[])?, |_input, _| {
            Ok(Program::new(Expression::Input))
        });
        let (state, principal, count) =
            fixture_with_modules(ConsoleModules::new([loader, other])?)?;
        let failure = execute(
            &state,
            &principal,
            call(Program::new(module("bad")), Value::null())?,
        )
        .await
        .err()
        .context("loader rejected")?;
        ensure!(failure.code == ConsoleErrorCode::BadRequest && count.load(Ordering::SeqCst) == 0);
        ensure!(state.boot.kernel().handles().is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn loaded_escaped_source_accepts_its_exact_encoded_byte_limit() -> anyhow::Result<()> {
    let text = "\0\n\"\\".repeat(128);
    let returned = Program::new(
        invoke("identity", OutputMode::Unary)?.then(Expression::literal(text.clone())),
    );
    let source_bytes = serde_json::to_vec(&returned)?.len();
    let loader = ConsoleModule::new(manifest("bounded", &["identity"], &[])?, move |_, _| {
        Ok(returned.clone())
    });
    let (original, principal, calls) = fixture_with_modules(ConsoleModules::new([loader])?)?;
    let state = super::source_admission::limited_source_state(&original, source_bytes)?;
    let result = execute(
        &state,
        &principal,
        call(Program::new(module("bounded")), Value::null())?,
    )
    .await?;
    ensure!(result_value(result)? == Value::string(text));
    ensure!(calls.load(Ordering::SeqCst) == 1);
    ensure!(state.boot.kernel().handles().is_empty());
    Ok(())
}

#[tokio::test]
async fn oversized_loaded_source_preserves_outer_effects() -> anyhow::Result<()> {
    for outer_effect in [false, true] {
        let returned = Program::new(
            invoke("identity", OutputMode::Unary)?
                .then(Expression::literal("\0\n\"\\".repeat(128))),
        );
        let source_bytes = serde_json::to_vec(&returned)?.len() - 1;
        let loads = Arc::new(AtomicUsize::new(0));
        let recorded_loads = loads.clone();
        let loader = ConsoleModule::new(manifest("oversized", &["identity"], &[])?, move |_, _| {
            recorded_loads.fetch_add(1, Ordering::SeqCst);
            Ok(returned.clone())
        });
        let (original, principal, calls) = fixture_with_modules(ConsoleModules::new([loader])?)?;
        let state = super::source_admission::limited_source_state(&original, source_bytes)?;
        let shape = Program::new(
            invoke("identity", OutputMode::Unary)?
                .then(Expression::literal("\0\n\"\\".repeat(128))),
        );
        shape.validate_structure_with_limits(state.runtime.compile_limits())?;
        let committed = Arc::new(AtomicUsize::new(0));
        let recorded_commits = committed.clone();
        state.boot.register_subtree_resource_at(
            "effect://calculator/commit",
            "perform://effect/calculator/**",
            InterfaceFamily::Callable,
            &[MethodSpec::new(
                "commit",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                OutputModeSet::UNARY,
            )],
            Arc::new(FnDriver(move |_: MethodId, input: Value| {
                recorded_commits.fetch_add(1, Ordering::SeqCst);
                Ok(input)
            })),
        )?;
        let body = if outer_effect {
            Expression::Invoke {
                operation: OperationTemplate {
                    target: ResourceName::new(Path::parse("effect://calculator/commit")?),
                    method: "commit".into(),
                    method_id: None,
                    output: OutputMode::Unary,
                    literal_input: None,
                },
            }
            .then(module("oversized"))
        } else {
            module("oversized")
        };
        let program = Program::new(body);
        ensure!(serde_json::to_vec(&program)?.len() <= source_bytes);
        let failure = execute(&state, &principal, call(program, Value::null())?)
            .await
            .err()
            .context("loaded source one byte over its limit")?;
        ensure!(failure.code == ConsoleErrorCode::BadRequest);
        ensure!(loads.load(Ordering::SeqCst) == 1);
        ensure!(calls.load(Ordering::SeqCst) == 0);
        let expected_commits = if outer_effect { 1 } else { 0 };
        ensure!(committed.load(Ordering::SeqCst) == expected_commits);
        ensure!(state.boot.kernel().handles().is_empty());
        ensure!(state.calls.available_permits() == 1);
    }
    Ok(())
}

#[tokio::test]
async fn recursive_modules_remain_subject_to_kernel_code_and_step_budgets() -> anyhow::Result<()> {
    let loads = Arc::new(AtomicUsize::new(0));
    let recorded = loads.clone();
    let recursive = ConsoleModule::new(
        manifest("recursive", &[], &["recursive"])?,
        move |_input, _| {
            recorded.fetch_add(1, Ordering::SeqCst);
            Ok(Program::new(module("recursive")))
        },
    );
    let (state, principal, count) = fixture_with_modules(ConsoleModules::new([recursive])?)?;
    let failure = execute(
        &state,
        &principal,
        call(Program::new(module("recursive")), Value::null())?,
    )
    .await
    .err()
    .context("bounded recursion")?;
    // The kernel reports resident frame/instruction limits as policy violations.
    ensure!(failure.code == ConsoleErrorCode::Forbidden);
    ensure!((2..=state.runtime.config.max_instructions).contains(&loads.load(Ordering::SeqCst)));
    ensure!(count.load(Ordering::SeqCst) == 0 && state.calls.available_permits() == 1);
    Ok(())
}

#[test]
fn module_assembly_rejects_duplicate_missing_and_reserved_dependencies() -> anyhow::Result<()> {
    let one = ConsoleModule::new(manifest("one", &[], &[])?, |_input, _| {
        Ok(Program::new(Expression::Input))
    });
    ensure!(
        ConsoleModules::compose([
            ConsoleModules::new([one.clone()])?,
            ConsoleModules::new([one])?
        ])
        .is_err()
    );
    let missing = ConsoleModule::new(manifest("missing", &[], &["absent"])?, |_input, _| {
        Ok(Program::new(Expression::Input))
    });
    ensure!(fixture_with_modules(ConsoleModules::new([missing])?).is_err());
    let mut reserved = manifest("reserved", &["read"], &[])?;
    reserved.operations[0].target = ResourceName::new(Path::parse("state://vault/secret")?);
    ensure!(
        ConsoleModules::new([ConsoleModule::new(reserved, |_input, _| Ok(Program::new(
            Expression::Input
        )))])
        .is_err()
    );
    Ok(())
}
