use super::*;
use crate::protocol::{
    ACTION_RUNTIME_PROGRAM_RUN, ACTION_RUNTIME_RESOURCE_DESCRIBE, ConsoleErrorCode,
};
use crate::{ConsoleConfig, ConsoleExecutionConfig, ConsoleRuntimeConfig};
use anyhow::{Context, ensure};
use std::sync::atomic::{AtomicUsize, Ordering};
use xolotl_graph::portable::Transform;
use xolotl_kernel::{Bootstrap, Driver, DriverContext, DriverError, FnDriver, MethodSpec};
use xolotl_types::{CapSet, DriverOutput, InterfaceFamily, MethodId, ProcessStatus, Purity};

mod conditional;
mod input_budget;

fn fixture() -> anyhow::Result<(Arc<ConsoleState>, ConsolePrincipal, Arc<AtomicUsize>)> {
    fixture_with_modules(crate::runtime::ConsoleModules::default())
}

fn fixture_with_modules(
    modules: crate::runtime::ConsoleModules,
) -> anyhow::Result<(Arc<ConsoleState>, ConsolePrincipal, Arc<AtomicUsize>)> {
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
            .build(),
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let recorded = calls.clone();
    boot.register_subtree_resource_at(
        "effect://calculator/run",
        "perform://effect/calculator/**",
        InterfaceFamily::Callable,
        &[
            MethodSpec::new(
                "double",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                xolotl_types::OutputModeSet::UNARY,
            ),
            MethodSpec::new(
                "identity",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                xolotl_types::OutputModeSet::UNARY,
            ),
        ],
        Arc::new(FnDriver(
            move |method: xolotl_types::MethodId, input: Value| {
                recorded.fetch_add(1, Ordering::SeqCst);
                Ok(if method.get() == 0 {
                    Value::integer(input.as_int().unwrap_or(0) * 2)
                } else {
                    input
                })
            },
        )),
    )?;
    let recorded = calls.clone();
    boot.register_subtree_resource_at(
        "state://calculator",
        "*://state/calculator/**",
        InterfaceFamily::Value,
        &[
            MethodSpec::new(
                "read",
                xolotl_types::MethodAuthority::Read,
                Purity::Pure,
                xolotl_types::OutputModeSet::UNARY,
            ),
            MethodSpec::new(
                "write",
                xolotl_types::MethodAuthority::Write,
                Purity::Effectful,
                xolotl_types::OutputModeSet::UNARY,
            ),
        ],
        Arc::new(FnDriver(move |_: xolotl_types::MethodId, input: Value| {
            recorded.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        })),
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
                capabilities: vec![
                    "perform://effect/calculator/**".into(),
                    "*://state/calculator/**".into(),
                    "act-as://identity/calculator/**".into(),
                    "subscribe://state/signals/**".into(),
                ],
                ..Default::default()
            },
            max_concurrent_calls: 1,
            ..Default::default()
        },
    )?;
    let principal = ConsolePrincipal {
        authority_id: "local".into(),
        username: "composer".into(),
        account_id: "composer-account".into(),
        identity_path: "identity://console/accounts/composer-account".into(),
        grants: CapSet::from_strs(["*://**"])?,
        authority_ceiling: None,
        authentication: crate::AuthenticationEvidence {
            primary: crate::PrimaryAuthentication::Password { verified_at: 0 },
            secondary: Some(crate::SecondaryAuthentication::RecoveryCode { verified_at: 0 }),
        },
    };
    Ok((state, principal, calls))
}

fn invoke(method: &str, output: OutputMode) -> anyhow::Result<Expression> {
    Ok(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse(if matches!(method, "read" | "write") {
                "state://calculator/item"
            } else {
                "effect://calculator/run"
            })?),
            method: method.into(),
            method_id: None,
            output,
            literal_input: None,
        },
    })
}

fn call(program: Program, input: Value) -> anyhow::Result<ActionCall> {
    Ok(ActionCall {
        action: ACTION_RUNTIME_PROGRAM_RUN.into(),
        input: map_value([
            ("source", Value::string(serde_json::to_string(&program)?)),
            ("input", input),
        ]),
        scope: Some("application workflow".into()),
        justification: Some("runtime composition test".into()),
        ttl_ms: Some(30_000),
        ..Default::default()
    })
}

async fn execute(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    call: ActionCall,
) -> Result<ActionResult, ConsoleFailure> {
    super::super::execute(
        &ActionContext {
            delivery: None,
            state,
            source_addr: Some("embedded"),
            session_id: "test",
        },
        principal,
        call,
    )
    .await
    .map(|result| result.result)
    .map_err(ConsoleFailure::from)
}

fn result_value(result: ActionResult) -> anyhow::Result<Value> {
    result
        .output
        .context("output")?
        .as_map()
        .and_then(|map| map.get("value"))
        .cloned()
        .context("runtime value")
}

async fn execute_with_fact_recording(
    state: &Arc<ConsoleState>,
    principal: &ConsolePrincipal,
    call: ActionCall,
) -> anyhow::Result<(ExecutionOutput, ExecutionReference)> {
    let context = ActionContext {
        delivery: None,
        state,
        source_addr: Some("embedded"),
        session_id: "test",
    };
    let plan = plan(state, principal, &call, false, None)?;
    let request = begin(&context, principal, &call, &plan)?;
    let reference = ExecutionReference {
        execution_id: None,
        process_id: request.id().get().to_string(),
        program_id: plan.program_id,
    };
    let executor = request
        .executor()
        .with_fact_recording(true)
        .with_steps(plan.steps)
        .with_execution_config(
            state
                .runtime
                .execution_config(state.boot.kernel().execution_config()),
        )
        .with_deadline(plan.deadline)?;
    for operation in plan.operations {
        executor.prepare_operation(&operation.template)?;
    }
    let output = executor
        .eval_prepared(
            &plan.prepared,
            TaintedValue::new(plan.input, TaintSet::author()),
        )
        .await;
    request.finish(&output).await?;
    Ok((output, reference))
}

#[tokio::test]
async fn portable_composition_uses_installed_multimethod_resource_and_records_process()
-> anyhow::Result<()> {
    let (state, principal, count) = fixture()?;
    let mut program = Program::new(
        Expression::Call {
            function: "calculate".into(),
        }
        .both(Expression::Input),
    );
    program.functions.insert(
        "calculate".into(),
        invoke("double", OutputMode::Unary)?.then(Expression::Transform {
            operation: Transform::Add { value: 1 },
        }),
    );
    let result = execute(&state, &principal, call(program, Value::integer(20))?).await?;
    let output = result
        .output
        .as_ref()
        .context("output")?
        .as_map()
        .context("map")?;
    let process: u64 = output
        .get("process_id")
        .and_then(Value::as_str)
        .context("process")?
        .parse()?;
    let execution = result.execution.as_ref().context("execution reference")?;
    ensure!(execution.process_id == process.to_string());
    ensure!(
        Some(execution.program_id.as_str()) == output.get("program_id").and_then(Value::as_str)
    );
    ensure!(
        output
            .get("program_id")
            .and_then(Value::as_str)
            .context("program")?
            .len()
            == 64
    );
    ensure!(result_value(result)? == Value::list(vec![Value::integer(41), Value::integer(20)]));
    ensure!(count.load(Ordering::SeqCst) == 1);
    ensure!(
        state
            .boot
            .kernel()
            .processes()
            .status(xolotl_types::ProcessId::new(process))
            .is_some_and(|s| s.is_terminal())
    );
    ensure!(
        state
            .boot
            .kernel()
            .facts()
            .facts_of(xolotl_types::ProcessId::new(process))?
            .is_empty()
    );
    let audit = state
        .boot
        .kernel()
        .facts()
        .all_facts()?
        .into_iter()
        .filter_map(|fact| fact.outcome)
        .find(|record| {
            record
                .as_map()
                .and_then(|record| record.get("event"))
                .and_then(Value::as_str)
                == Some("console_runtime")
        })
        .context("runtime audit")?;
    let audit = audit.as_map().context("runtime audit fields")?;
    ensure!(audit.get("mfa_level").is_none());
    let details = audit
        .get("details")
        .and_then(Value::as_map)
        .context("runtime audit details")?;
    ensure!(
        details.get("process_id").and_then(Value::as_str) == Some(process.to_string().as_str())
    );
    ensure!(
        details.get("authentication")
            == Some(&crate::auth::audit::authentication_summary(
                &principal.authentication
            )),
        "request audit must preserve its verified session context"
    );
    Ok(())
}

#[tokio::test]
async fn all_imports_and_output_contracts_are_preflighted_before_first_effect() -> anyhow::Result<()>
{
    let (state, mut principal, count) = fixture()?;
    principal.grants = CapSet::from_strs(["perform://effect/calculator/**"])?;
    let program =
        Program::new(invoke("double", OutputMode::Unary)?.then(invoke("read", OutputMode::Unary)?));
    let error = execute(&state, &principal, call(program, Value::integer(1))?)
        .await
        .err()
        .context("denied")?;
    ensure!(error.code == ConsoleErrorCode::Forbidden);
    ensure!(count.load(Ordering::SeqCst) == 0);
    principal.grants = CapSet::from_strs(["*://**"])?;
    let program = Program::new(
        invoke("double", OutputMode::Unary)?.then(invoke("read", OutputMode::SinkOnly)?),
    );
    let error = execute(&state, &principal, call(program, Value::integer(1))?)
        .await
        .err()
        .context("invalid output")?;
    ensure!(error.code == ConsoleErrorCode::BadRequest);
    ensure!(count.load(Ordering::SeqCst) == 0);
    ensure!(state.boot.kernel().handles().is_empty());
    Ok(())
}

#[tokio::test]
async fn runtime_exposure_does_not_grant_authority_and_discovery_filters_methods()
-> anyhow::Result<()> {
    let (state, mut principal, count) = fixture()?;
    principal.grants = CapSet::from_strs(["read://state/calculator/**"])?;
    let resource = execute(
        &state,
        &principal,
        ActionCall {
            action: ACTION_RUNTIME_RESOURCE_DESCRIBE.into(),
            input: map_value([("target", Value::string("state://calculator/item".into()))]),
            ..Default::default()
        },
    )
    .await?
    .output
    .context("descriptor")?;
    let text = serde_json::to_string(&resource)?;
    ensure!(text.contains("read") && !text.contains("write"));
    let error = execute(
        &state,
        &principal,
        call(
            Program::new(invoke("double", OutputMode::Unary)?),
            Value::integer(1),
        )?,
    )
    .await
    .err()
    .context("denied")?;
    ensure!(error.code == ConsoleErrorCode::Forbidden);
    ensure!(count.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn host_owned_imports_and_reserved_targets_cannot_bypass_management() -> anyhow::Result<()> {
    let (state, mut principal, count) = fixture()?;
    principal.grants = CapSet::from_strs(["*://**"])?;
    let mut programs = vec![
        Program::new(Expression::Module {
            module: xolotl_graph::StepRef::new("native"),
        }),
        Program::new(Expression::Acting {
            identity: Path::parse("identity://root")?,
            body: Box::new(Expression::Input),
        }),
        Program::new(Expression::Wait {
            wait: WaitSpec::Signal(Path::parse("state://vault/console/password")?),
        }),
        Program::new(invoke("read", OutputMode::Stream)?),
        Program::new(invoke("read", OutputMode::AsyncProcess)?),
        Program::new(invoke("read", OutputMode::Collect { limit: 257 })?),
    ];
    for target in [
        "state://kernel/console/users/root",
        "state://vault/console/mfa/root",
        "effect://kernel/console/users",
        "state://fact",
        "state://**",
    ] {
        programs.push(Program::new(Expression::Invoke {
            operation: OperationTemplate {
                target: ResourceName::new(Path::parse(target)?),
                method: "write".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: None,
            },
        }));
    }
    for (index, program) in programs.into_iter().enumerate() {
        let error = execute(&state, &principal, call(program, Value::null())?)
            .await
            .err()
            .with_context(|| format!("unsupported program {index} unexpectedly succeeded"))?;
        let expected = if index == 1 {
            ConsoleErrorCode::Forbidden
        } else {
            ConsoleErrorCode::BadRequest
        };
        ensure!(error.code == expected, "program {index}: {error}");
    }
    ensure!(count.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn single_operation_and_tagged_program_values_are_lossless() -> anyhow::Result<()> {
    let (state, principal, _) = fixture()?;
    let value = Value::bytes(vec![0, 255, 17]);
    let mut invocation = call(Program::new(Expression::Input), Value::null())?;
    invocation.action = ACTION_RUNTIME_OPERATION_INVOKE.into();
    invocation.input = map_value([
        ("target", Value::string("state://calculator/item".into())),
        ("method", Value::string("read".into())),
        ("input", value.clone()),
        ("output", Value::string("collect".into())),
        ("collect_limit", Value::integer(1)),
    ]);
    let result = execute(&state, &principal, invocation).await?;
    ensure!(result_value(result)? == Value::list(vec![value.clone()]));
    let program = Program::new(
        Expression::Constant {
            value: value.clone(),
        }
        .then(invoke("read", OutputMode::Unary)?),
    );
    ensure!(
        result_value(execute(&state, &principal, call(program, Value::null())?).await?)? == value
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_program_and_deadline_release_process_authority_and_call_capacity()
-> anyhow::Result<()> {
    let (state, principal, _) = fixture()?;
    let program = Program::new(invoke("double", OutputMode::Unary)?.then(Expression::Wait {
        wait: WaitSpec::Deadline(xolotl_kernel::host::system_now_millis() + 60_000),
    }));
    let before = state.boot.kernel().processes().all_ids();
    let context = ActionContext {
        delivery: None,
        state: &state,
        source_addr: None,
        session_id: "test",
    };
    let mut pending = Box::pin(super::super::execute(
        &context,
        &principal,
        call(program.clone(), Value::integer(1))?,
    ));
    tokio::select! {
        biased;
        result = &mut pending => { result?; anyhow::bail!("program did not wait"); }
        () = tokio::task::yield_now() => {}
    }
    let request = state
        .boot
        .kernel()
        .processes()
        .all_ids()
        .into_iter()
        .find(|id| !before.contains(id))
        .context("request")?;
    ensure!(state.calls.try_acquire().is_err());
    drop(pending);
    ensure!(state.boot.kernel().processes().status(request) == Some(ProcessStatus::Cancelled));
    let Expression::Invoke { operation } = &invoke("double", OutputMode::Unary)? else {
        anyhow::bail!("operation fixture");
    };
    ensure!(
        state
            .boot
            .kernel()
            .executor_for(request)
            .prepare_operation(operation)
            == Err(Failure::Cancelled)
    );
    ensure!(state.boot.kernel().handles().is_empty());
    ensure!(state.calls.try_acquire().is_ok());
    ensure!(state.boot.drain_cleanup().await.failures.is_empty());
    let mut timed = call(program, Value::integer(1))?;
    timed.ttl_ms = Some(1);
    let error = tokio::time::timeout(Duration::from_secs(2), execute(&state, &principal, timed))
        .await?
        .err()
        .context("deadline")?;
    ensure!(error.message.contains("deadline"));
    let execution = error.execution.context("timed out execution")?;
    ensure!(execution.program_id.len() == 64);
    let process_id = xolotl_types::ProcessId::new(execution.process_id.parse()?);
    ensure!(
        state
            .boot
            .kernel()
            .processes()
            .status(process_id)
            .is_some_and(|s| s.is_terminal())
    );
    ensure!(state.boot.kernel().handles().is_empty());
    ensure!(state.calls.try_acquire().is_ok());
    Ok(())
}

struct PendingEffect(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Driver for PendingEffect {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        _context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
}

#[tokio::test]
async fn attached_deadline_preserves_kernel_uncertain_operation_ids() -> anyhow::Result<()> {
    let (state, principal, _) = fixture()?;
    let started = Arc::new(AtomicUsize::new(0));
    state.boot.register_effect(
        "effect://calculator/pending",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            xolotl_types::OutputModeSet::UNARY,
        )],
        Arc::new(PendingEffect(started.clone())),
    )?;
    let program = Program::new(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://calculator/pending")?),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    });
    let call = ActionCall {
        action: ACTION_RUNTIME_PROGRAM_RUN.into(),
        input: map_value([
            ("source", Value::string(serde_json::to_string(&program)?)),
            ("timeout_ms", Value::integer(250)),
        ]),
        scope: Some("deadline reconciliation".into()),
        justification: Some("retain uncertain effect identity".into()),
        ttl_ms: Some(1_000),
        ..Default::default()
    };
    let error = tokio::time::timeout(Duration::from_secs(2), execute(&state, &principal, call))
        .await?
        .err()
        .context("pending effect must fail at the Kernel deadline")?;
    ensure!(started.load(Ordering::SeqCst) == 1);
    let unknown = error
        .outcome_unknown
        .context("trusted uncertain-operation detail")?;
    ensure!(unknown.operation_ids.len() == 1);
    ensure!(!unknown.operation_ids[0].is_empty());
    Ok(())
}

#[test]
fn host_runtime_configuration_is_validated_and_changes_discovery_revision() -> anyhow::Result<()> {
    let default = crate::registry::DescriptorRegistry::new().current_rev();
    let runtime = ConsoleRuntimeConfig {
        enabled: true,
        capabilities: vec!["perform://effect/calculator/**".into()],
        ..Default::default()
    };
    let state = ConsoleState::with_config(
        Arc::new(Bootstrap::in_memory()),
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            runtime,
            ..Default::default()
        },
    )?;
    ensure!(state.registry.current_rev() != default);
    ensure!(
        ConsoleState::with_config(
            Arc::new(Bootstrap::in_memory()),
            ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default()
                    )
                )),
                runtime: ConsoleRuntimeConfig {
                    max_duration_ms: 900_000,
                    ..Default::default()
                },
                ..Default::default()
            }
        )
        .is_ok()
    );
    ensure!(
        ConsoleState::with_config(
            Arc::new(Bootstrap::in_memory()),
            ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default()
                    )
                )),
                runtime: ConsoleRuntimeConfig {
                    max_duration_ms: u64::MAX,
                    ..Default::default()
                },
                ..Default::default()
            }
        )
        .is_err()
    );
    ensure!(
        ConsoleState::with_config(
            Arc::new(Bootstrap::in_memory()),
            ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default()
                    )
                )),
                runtime: ConsoleRuntimeConfig {
                    max_steps: 0,
                    ..Default::default()
                },
                ..Default::default()
            }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn runtime_preflight_and_configuration_use_the_installed_kernel_clock() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicI64, Ordering};
    use xolotl_kernel::host::{AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner};

    struct Clock(AtomicI64);

    impl HostClock for Clock {
        fn monotonic_now(&self) -> std::time::Instant {
            std::time::Instant::now() + Duration::from_secs(3_600)
        }

        fn unix_millis(&self) -> i64 {
            self.0.load(Ordering::SeqCst)
        }

        fn sleep_until(
            &self,
            _deadline: std::time::Instant,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(std::future::pending())
        }
    }

    struct NoTasks;

    impl TaskSpawner for NoTasks {
        fn spawn(
            &self,
            _future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
        ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
            Err(TaskSpawnError::Unavailable)
        }
    }

    let clock = Arc::new(Clock(AtomicI64::new(1_000)));
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_host_runtime(HostRuntime::new(
                clock.clone(),
                Arc::new(NoTasks),
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            ))
            .build(),
    ));
    let config = ConsoleConfig {
        session_store: Some(std::sync::Arc::new(
            crate::session_store::MemoryConsoleSessionStore::new(
                crate::session_store::ConsoleSessionPolicy::default(),
            ),
        )),
        runtime: ConsoleRuntimeConfig {
            enabled: true,
            capabilities: vec!["perform://effect/calculator/**".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let state = ConsoleState::with_config(boot.clone(), config.clone())?;
    let (_, principal, _) = fixture()?;
    ensure!(super::super::protocol_greeting(&state)?.server_time_ms == 1_000);
    ensure!(
        super::super::registry_snapshot(&state)?
            .protocol
            .server_time_ms
            == 1_000
    );
    let planned = plan(
        &state,
        &principal,
        &call(Program::new(Expression::Input), Value::null())?,
        false,
        None,
    )?;
    let runtime = state.boot.kernel().host_runtime();
    runtime.validate_deadline(planned.deadline)?;
    let remaining = planned.deadline.saturating_duration_since(runtime.now())?;
    ensure!(remaining <= Duration::from_secs(30) && remaining > Duration::from_secs(29));
    let grants = CapSet::from_strs(["perform://effect/calculator/run@until=1500"])?;
    let path = Path::parse("effect://calculator/run")?;
    ensure!(allowed(&state, &grants, "perform", &path));
    let mut conditional = principal.clone();
    conditional.grants = grants.clone();
    let selector = crate::service::exact_resource_selector("perform", &path)?;
    ensure!(
        crate::auth::principal_request_selectors(
            &state.boot,
            &conditional,
            &path,
            "perform",
            selector.clone(),
        )?
        .len()
            == 1
    );
    clock.0.store(1_501, Ordering::SeqCst);
    ensure!(!allowed(&state, &grants, "perform", &path));
    ensure!(
        crate::auth::principal_request_selectors(
            &state.boot,
            &conditional,
            &path,
            "perform",
            selector,
        )
        .is_err()
    );

    clock.0.store(i64::MAX - 100, Ordering::SeqCst);
    let submission = ActionCall {
        action: crate::protocol::ACTION_RUNTIME_PROGRAM_SUBMIT.into(),
        input: map_value([
            (
                "source",
                Value::string(serde_json::to_string(&Program::new(Expression::Input))?),
            ),
            ("timeout_ms", Value::integer(500)),
        ]),
        scope: Some("clock test".into()),
        justification: Some("check deadline clock".into()),
        ttl_ms: Some(30_000),
        ..Default::default()
    };
    ensure!(plan(&state, &principal, &submission, false, None).is_err());

    clock.0.store(i64::MAX - 1, Ordering::SeqCst);
    ensure!(ConsoleState::with_config(boot, config).is_err());
    Ok(())
}

#[test]
fn detached_deadline_outlives_short_visibility_grant_but_attached_deadline_does_not()
-> anyhow::Result<()> {
    let (_, principal, _) = fixture()?;
    let state = ConsoleState::with_config(
        Arc::new(Bootstrap::in_memory()),
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                max_duration_ms: 900_000,
                executions: ConsoleExecutionConfig {
                    enabled: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    let mut attached = call(Program::new(Expression::Input), Value::null())?;
    attached.ttl_ms = Some(1_000);
    attached.input = map_value([
        (
            "source",
            Value::string(serde_json::to_string(&Program::new(Expression::Input))?),
        ),
        ("timeout_ms", Value::integer(900_000)),
    ]);
    let started = state.boot.kernel().host_runtime().now();
    let attached_plan = plan(&state, &principal, &attached, false, None)?;
    ensure!(attached_plan.deadline == attached_plan.admission_deadline);
    ensure!(
        attached_plan.deadline.elapsed_at(
            started
                .checked_add(Duration::from_secs(2))
                .context("deadline")?
        )?
    );

    attached.action = crate::protocol::ACTION_RUNTIME_PROGRAM_SUBMIT.into();
    let submitted_plan = plan(&state, &principal, &attached, false, None)?;
    ensure!(
        submitted_plan.admission_deadline.elapsed_at(
            started
                .checked_add(Duration::from_secs(2))
                .context("deadline")?
        )?
    );
    ensure!(
        !submitted_plan.deadline.elapsed_at(
            started
                .checked_add(Duration::from_secs(600))
                .context("deadline")?
        )?
    );
    attached.ttl_ms = Some(600_001);
    ensure!(plan(&state, &principal, &attached, false, None).is_err());
    Ok(())
}

#[tokio::test]
async fn console_cannot_raise_the_kernels_execution_budget() -> anyhow::Result<()> {
    let (_, principal, _) = fixture()?;
    let kernel = xolotl_kernel::KernelBuilder::in_memory()
        .with_execution_config(xolotl_kernel::ExecutionConfig {
            max_steps: Some(2),
            ..Default::default()
        })
        .build();
    let state = ConsoleState::with_config(
        Arc::new(Bootstrap::from_kernel(kernel)),
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    let program = Program::new(Expression::Sequence {
        steps: (0..10)
            .map(|_| Expression::Transform {
                operation: Transform::Add { value: 1 },
            })
            .collect(),
    });
    ensure!(
        execute(&state, &principal, call(program, Value::integer(0))?)
            .await
            .is_err()
    );
    ensure!(state.calls.try_acquire().is_ok());
    Ok(())
}

#[tokio::test]
async fn exposure_compilation_limits_and_mfa_fail_before_invocation() -> anyhow::Result<()> {
    let (state, principal, count) = fixture()?;
    let foreign = Program::new(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://outside/run")?),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    });
    let error = execute(&state, &principal, call(foreign, Value::null())?)
        .await
        .err()
        .context("host exposure")?;
    ensure!(error.code == ConsoleErrorCode::Forbidden);
    let program = Program::new(invoke("double", OutputMode::Unary)?);
    let mut weak = principal.clone();
    weak.authentication.secondary = None;
    let error = execute(&state, &weak, call(program.clone(), Value::null())?)
        .await
        .err()
        .context("MFA")?;
    ensure!(error.code == ConsoleErrorCode::StepUpRequired);
    let constrained = ConsoleState::with_config(
        state.boot.clone(),
        ConsoleConfig {
            session_store: Some(state.auth.session_store.clone()),
            runtime: ConsoleRuntimeConfig {
                max_source_bytes: 8,
                ..state.runtime.config.clone()
            },
            ..Default::default()
        },
    )?;
    let error = execute(&constrained, &principal, call(program, Value::null())?)
        .await
        .err()
        .context("source limit")?;
    ensure!(error.code == ConsoleErrorCode::BadRequest);
    let disabled = ConsoleState::shared(state.boot.clone(), state.auth.session_store.clone())?;
    ensure!(
        execute(
            &disabled,
            &principal,
            call(Program::new(Expression::Input), Value::null())?
        )
        .await
        .is_err()
    );
    ensure!(count.load(Ordering::SeqCst) == 0);
    Ok(())
}

mod acting;
mod authority;
mod budget;
mod cluster;
pub(super) mod discovery;
mod modules;
mod signals;
mod source_admission;
