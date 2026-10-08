use super::*;
use crate::protocol::*;
use crate::{
    BootstrapOutcome, ConsoleConfig, ConsoleExecutionConfig, ConsoleRuntimeConfig, ConsoleService,
    LoginRequest, RootProvisioning, RuntimeCode, RuntimeRequest, bootstrap_root_account,
};
use anyhow::{Context, ensure};
use std::sync::atomic::{AtomicUsize, Ordering};
use xolotl_kernel::{Bootstrap, Driver, DriverContext, DriverError, FnDriver, MethodSpec};
use xolotl_types::{DriverOutput, MethodAuthority, MethodId, OutputModeSet, Purity};

mod children;
mod cleanup;
mod cleanup_outcome;
mod delivery;
mod output;
mod submission;

struct Fixture {
    state: Arc<ConsoleState>,
    service: ConsoleService,
    token: String,
    calls: Arc<AtomicUsize>,
}

impl Fixture {
    async fn new(config: ConsoleExecutionConfig) -> anyhow::Result<Self> {
        Self::with_propagation(config, false, false).await
    }

    async fn with_propagation(
        config: ConsoleExecutionConfig,
        user: bool,
        host: bool,
    ) -> anyhow::Result<Self> {
        Self::with_boot(Arc::new(Bootstrap::in_memory()), config, user, host).await
    }

    async fn with_boot(
        boot: Arc<Bootstrap>,
        config: ConsoleExecutionConfig,
        user: bool,
        host: bool,
    ) -> anyhow::Result<Self> {
        let grants = std::iter::once("perform://effect/jobs/**".into())
            .chain(user.then(|| "spawn-with://effect/jobs/**".into()))
            .collect();
        Self::with_boot_grants(boot, config, grants, host).await
    }

    async fn with_boot_grants(
        boot: Arc<Bootstrap>,
        config: ConsoleExecutionConfig,
        grants: Vec<String>,
        host: bool,
    ) -> anyhow::Result<Self> {
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        boot.register_effect(
            "effect://jobs/echo",
            &[MethodSpec::new(
                "invoke",
                MethodAuthority::Perform,
                Purity::Effectful,
                OutputModeSet::UNARY,
            )
            .finalize_allowed()],
            Arc::new(FnDriver(move |_: xolotl_types::MethodId, input: Value| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(input)
            })),
        )?;
        let BootstrapOutcome::CreatedRandomPassword { password, .. } = bootstrap_root_account(
            &boot,
            &xolotl_kernel::host::TokioBlockingSpawner::default(),
            RootProvisioning {
                additional_grants: grants,
                ..Default::default()
            },
        )
        .await?
        else {
            anyhow::bail!("root");
        };
        let state = ConsoleState::with_config(
            boot,
            ConsoleConfig {
                session_store: Some(std::sync::Arc::new(
                    crate::session_store::MemoryConsoleSessionStore::new(
                        crate::session_store::ConsoleSessionPolicy::default(),
                    ),
                )),
                max_concurrent_calls: 1,
                runtime: ConsoleRuntimeConfig {
                    enabled: true,
                    capabilities: std::iter::once("perform://effect/jobs/**".into())
                        .chain(host.then(|| "spawn-with://effect/jobs/**".into()))
                        .collect(),
                    executions: config,
                    ..Default::default()
                },
                ..Default::default()
            },
        )?;
        let service = ConsoleService::new(state.clone());
        let login = service
            .login(
                LoginRequest {
                    username: "root".into(),
                    password: password.clone(),
                    second_factor: None,
                },
                "test".into(),
            )
            .await?
            .into_session()
            .ok()
            .context("authenticated session")?;
        let elevated = state
            .auth
            .enroll_test_totp(&state.boot, &login.token)
            .await?;
        ensure!(elevated.authentication.mfa_level() == 2);
        Ok(Self {
            state,
            service,
            token: elevated.token,
            calls,
        })
    }

    async fn call(&self, action: &str, input: Value) -> Result<ActionResult, ConsoleFailure> {
        self.service
            .call(&self.token, Some("embedded"), scoped(action, input))
            .await
    }

    async fn submit(&self, expression: Expression, value: Value) -> anyhow::Result<String> {
        let result = self
            .call(
                ACTION_RUNTIME_PROGRAM_SUBMIT,
                map_value([
                    (
                        "source",
                        Value::string(serde_json::to_string(&Program::new(expression))?),
                    ),
                    ("input", value),
                ]),
            )
            .await?;
        let id = result
            .execution
            .context("execution")?
            .execution_id
            .context("retained ID")?;
        ensure!(
            field(&result.output.context("record")?, "execution_id")?.as_str() == Some(id.as_str())
        );
        Ok(id)
    }

    async fn finished(&self, id: &str) -> anyhow::Result<Value> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let value = self
                    .call(ACTION_RUNTIME_EXECUTION_GET, id_input(id))
                    .await?
                    .output
                    .context("metadata")?;
                if field(&value, "status")?.as_str() == Some("finished") {
                    return Ok(value);
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await?
    }

    async fn owner(&self) -> anyhow::Result<ExecutionOwner> {
        let principal = self
            .state
            .auth
            .authenticate_token(&self.state.boot, &self.token)
            .await?;
        Ok(self
            .state
            .auth
            .execution_owner(
                &self.state.boot,
                self.token.split_once('.').context("SID")?.0,
                &principal,
            )
            .await?)
    }

    async fn wait_for_calls(&self, expected: usize) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.calls.load(Ordering::SeqCst) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }
}

fn config() -> ConsoleExecutionConfig {
    ConsoleExecutionConfig {
        enabled: true,
        authority_poll_ms: 10,
        cleanup_timeout_ms: 100,
        ..Default::default()
    }
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

struct AfterPendingEffect(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Driver for AfterPendingEffect {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        _context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        while self.0.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
        Ok(DriverOutput::new(xolotl_types::Outcome::Done(
            Value::bytes(vec![42; 1024]),
        )))
    }
}

fn pending_race() -> anyhow::Result<(Arc<Bootstrap>, Program)> {
    let boot = Arc::new(Bootstrap::in_memory());
    let started = Arc::new(AtomicUsize::new(0));
    let method = [MethodSpec::new(
        "invoke",
        MethodAuthority::Perform,
        Purity::Effectful,
        OutputModeSet::UNARY,
    )];
    boot.register_effect(
        "effect://jobs/pending",
        &method,
        Arc::new(PendingEffect(started.clone())),
    )?;
    boot.register_effect(
        "effect://jobs/winner",
        &method,
        Arc::new(AfterPendingEffect(started)),
    )?;
    let invoke = |target| -> anyhow::Result<Expression> {
        Ok(Expression::Invoke {
            operation: OperationTemplate {
                target: ResourceName::new(Path::parse(target)?),
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: None,
            },
        })
    };
    Ok((
        boot,
        Program::new(invoke("effect://jobs/pending")?.race(invoke("effect://jobs/winner")?)),
    ))
}

#[tokio::test]
async fn successful_race_exposes_uncertain_effects_even_when_result_is_omitted()
-> anyhow::Result<()> {
    let (boot, program) = pending_race()?;
    let fixture = Fixture::with_boot(
        boot,
        ConsoleExecutionConfig {
            max_result_bytes: 128,
            ..config()
        },
        false,
        false,
    )
    .await?;
    let request = RuntimeRequest::new(
        RuntimeCode::Program(program.clone()),
        Value::null(),
        "race",
        "inspect cancelled effect",
        10_000,
    );
    let called = fixture
        .service
        .run_runtime(&fixture.token, Some("embedded"), request)
        .await?;
    let attached = called
        .unresolved_operations
        .context("attached call must retain uncertain effect")?;
    ensure!(attached.operation_ids.len() == 1 && !attached.identities_incomplete);
    ensure!(
        field(&called.output.context("successful call")?, "value")?
            .as_bytes()
            .is_some_and(|bytes| bytes.len() == 1024)
    );

    let id = fixture.submit(program.body, Value::null()).await?;
    let metadata = fixture.finished(&id).await?;
    ensure!(field(&metadata, "outcome")?.as_str() == Some("done"));
    ensure!(field(&metadata, "result_status")?.as_str() == Some("omitted"));
    ensure!(field(&metadata, "unresolved_operation_count")?.as_int() == Some(1));
    ensure!(field(&metadata, "unresolved_identities_incomplete")?.as_bool() == Some(false));
    ensure!(
        metadata
            .as_map()
            .is_some_and(|map| !map.contains_key("unresolved_operations"))
    );
    let page = fixture
        .call(ACTION_RUNTIME_EXECUTION_LIST, Value::null())
        .await?
        .output
        .context("execution list")?;
    let entry = field(&page, "entries")?
        .as_list()
        .and_then(|entries| entries.first())
        .context("listed execution")?;
    ensure!(field(entry, "unresolved_operation_count")?.as_int() == Some(1));
    ensure!(
        entry
            .as_map()
            .is_some_and(|map| !map.contains_key("unresolved_operations"))
    );
    let retained = fixture
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("retained result")?;
    ensure!(field(&retained, "output")?.is_null());
    let unresolved = field(&retained, "unresolved_operations")?;
    ensure!(
        field(unresolved, "operation_ids")?
            .as_list()
            .is_some_and(|ids| ids.len() == 1)
    );
    ensure!(field(unresolved, "identities_incomplete")?.as_bool() == Some(false));
    Ok(())
}

#[tokio::test]
async fn independent_deadline_retains_kernel_uncertain_operation_ids() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let started = Arc::new(AtomicUsize::new(0));
    boot.register_effect(
        "effect://jobs/pending",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            OutputModeSet::UNARY,
        )],
        Arc::new(PendingEffect(started.clone())),
    )?;
    let fixture = Fixture::with_boot(
        boot,
        ConsoleExecutionConfig {
            cleanup_timeout_ms: 500,
            ..config()
        },
        false,
        false,
    )
    .await?;
    let accepted = fixture
        .call(
            ACTION_RUNTIME_OPERATION_SUBMIT,
            map_value([
                ("target", Value::string("effect://jobs/pending".into())),
                ("method", Value::string("invoke".into())),
                ("input", Value::null()),
                ("timeout_ms", Value::integer(250)),
            ]),
        )
        .await?;
    let id = accepted
        .execution
        .context("accepted execution")?
        .execution_id
        .context("execution ID")?;
    let metadata = fixture.finished(&id).await?;
    ensure!(field(&metadata, "outcome")?.as_str() == Some("failed"));
    ensure!(started.load(Ordering::SeqCst) == 1);
    let retained = fixture
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("retained result")?;
    let failure = field(field(&retained, "output")?, "failure")?;
    let ids = field(field(failure, "outcome_unknown")?, "operation_ids")?
        .as_list()
        .context("uncertain operation IDs")?;
    ensure!(
        ids.len() == 1
            && ids
                .get(0)
                .and_then(Value::as_str)
                .is_some_and(|id| !id.is_empty())
    );
    Ok(())
}

fn scoped(action: &str, input: Value) -> ActionCall {
    ActionCall {
        action: action.into(),
        input,
        scope: Some("job".into()),
        justification: Some("execution test".into()),
        ttl_ms: Some(10_000),
        ..Default::default()
    }
}

fn field<'a>(value: &'a Value, name: &str) -> anyhow::Result<&'a Value> {
    value
        .as_map()
        .and_then(|map| map.get(name))
        .with_context(|| format!("field {name}"))
}

fn id_input(id: &str) -> Value {
    map_value([("execution_id", Value::string(id.into()))])
}

fn echo() -> anyhow::Result<Expression> {
    Ok(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://jobs/echo")?),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    })
}

#[tokio::test]
async fn owned_rust_runtime_calls_and_submissions_share_service_admission() -> anyhow::Result<()> {
    let f = Fixture::new(config()).await?;
    let request = RuntimeRequest::new(
        RuntimeCode::Program(Program::new(echo()?)),
        Value::integer(7),
        "job",
        "owned Rust runtime call",
        10_000,
    );
    let called = f
        .service
        .run_runtime(&f.token, Some("embedded"), request)
        .await?;
    ensure!(field(&called.output.context("call output")?, "value")? == &Value::integer(7));
    ensure!(f.calls.load(Ordering::SeqCst) == 1);

    let Expression::Invoke { operation } = &echo()? else {
        anyhow::bail!("echo fixture must be an Invoke expression")
    };
    let request = RuntimeRequest::new(
        RuntimeCode::Operation {
            operation: operation.clone(),
        },
        Value::integer(11),
        "job",
        "owned Rust runtime submission",
        10_000,
    );
    let submitted = f
        .service
        .submit_runtime(&f.token, Some("embedded"), request)
        .await?;
    let id = submitted
        .execution
        .context("accepted execution")?
        .execution_id
        .context("retained execution ID")?;
    f.finished(&id).await?;
    ensure!(f.calls.load(Ordering::SeqCst) == 2);

    let too_large = RuntimeRequest::new(
        RuntimeCode::Program(Program::new(Expression::Literal {
            value: serde_json::Value::String("x".repeat(300_000)),
        })),
        Value::null(),
        "job",
        "bounded owned source",
        10_000,
    );
    let failure = f
        .service
        .run_runtime(&f.token, Some("embedded"), too_large)
        .await
        .err()
        .context("oversized owned program")?;
    ensure!(failure.code == ConsoleErrorCode::BadRequest);
    ensure!(f.calls.load(Ordering::SeqCst) == 2);

    for (scope, justification) in [
        ("x".repeat(1025), "bounded audit".into()),
        ("bounded audit".into(), "x".repeat(1025)),
    ] {
        let request = RuntimeRequest::new(
            RuntimeCode::Program(Program::new(echo()?)),
            Value::integer(13),
            scope,
            justification,
            10_000,
        );
        let failure = f
            .service
            .run_runtime(&f.token, Some("embedded"), request)
            .await
            .err()
            .context("oversized visibility metadata")?;
        ensure!(failure.code == ConsoleErrorCode::BadRequest);
    }
    ensure!(f.calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

fn wait() -> Expression {
    Expression::Wait {
        wait: WaitSpec::Deadline(xolotl_kernel::host::system_now_millis() + 60_000),
    }
}

#[tokio::test]
async fn submissions_release_call_capacity_and_preserve_lossless_results() -> anyhow::Result<()> {
    let f = Fixture::new(config()).await?;
    let value = Value::bytes(vec![0, 1, 255]);
    let submitted = f
        .call(
            ACTION_RUNTIME_OPERATION_SUBMIT,
            map_value([
                ("target", Value::string("effect://jobs/echo".into())),
                ("method", Value::string("invoke".into())),
                ("input", value.clone()),
            ]),
        )
        .await?;
    let id = submitted
        .execution
        .context("reference")?
        .execution_id
        .context("ID")?;
    let metadata = f.finished(&id).await?;
    ensure!(field(&metadata, "outcome")?.as_str() == Some("done"));
    ensure!(field(&metadata, "cleanup_status")?.as_str() == Some("complete"));
    let result = f
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("result")?;
    ensure!(field(field(&result, "output")?, "value")? == &value);
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    let denied = f
        .service
        .call(
            &f.token,
            None,
            ActionCall {
                action: ACTION_RUNTIME_EXECUTION_RESULT.into(),
                input: id_input(&id),
                ..Default::default()
            },
        )
        .await;
    ensure!(denied.is_err(), "result cannot bypass visibility admission");
    f.call(ACTION_RUNTIME_EXECUTION_FORGET, id_input(&id))
        .await?;
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_GET, id_input(&id))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_runs_lexical_cleanup_and_active_records_cannot_be_forgotten()
-> anyhow::Result<()> {
    let f = Fixture::new(ConsoleExecutionConfig {
        max_concurrent: 1,
        max_concurrent_per_account: 1,
        ..config()
    })
    .await?;
    let expression = Expression::Finally {
        body: Box::new(echo()?.then(wait()).then(echo()?)),
        cleanup: Box::new(echo()?),
    };
    let id = f.submit(expression, Value::null()).await?;
    f.wait_for_calls(1).await?;
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_FORGET, id_input(&id))
            .await
            .is_err()
    );
    let rejected = f.submit(echo()?, Value::null()).await;
    ensure!(rejected.is_err());
    ensure!(
        f.calls.load(Ordering::SeqCst) == 1,
        "capacity rejection must precede effects"
    );
    f.call(ACTION_RUNTIME_EXECUTION_CANCEL, id_input(&id))
        .await?;
    let finished = f.finished(&id).await?;
    ensure!(field(&finished, "outcome")?.as_str() == Some("cancelled"));
    ensure!(
        f.calls.load(Ordering::SeqCst) == 2,
        "only the lexical cleanup may execute after cancellation"
    );
    let again = f.submit(echo()?, Value::null()).await?;
    f.finished(&again).await?;
    f.call(ACTION_RUNTIME_EXECUTION_CANCEL, id_input(&id))
        .await?;
    Ok(())
}

#[tokio::test]
async fn result_overflow_preserves_success_and_reservation_precedes_effects() -> anyhow::Result<()>
{
    let f = Fixture::new(ConsoleExecutionConfig {
        max_records: 1,
        max_records_per_account: 1,
        max_concurrent: 1,
        max_concurrent_per_account: 1,
        max_result_bytes: 128,
        ..config()
    })
    .await?;
    let id = f.submit(echo()?, Value::bytes(vec![42; 1024])).await?;
    let completed = f.finished(&id).await?;
    ensure!(field(&completed, "outcome")?.as_str() == Some("done"));
    ensure!(field(&completed, "result_status")?.as_str() == Some("omitted"));
    let result = f
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("result")?;
    ensure!(field(&result, "output")?.is_null());
    ensure!(!field(&result, "retention_failure")?.is_null());
    ensure!(f.submit(echo()?, Value::null()).await.is_err());
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    f.call(ACTION_RUNTIME_EXECUTION_FORGET, id_input(&id))
        .await?;
    let id = f.submit(echo()?, Value::null()).await?;
    f.finished(&id).await?;
    ensure!(f.calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn timeout_is_an_execution_deadline_and_shutdown_closes_admission() -> anyhow::Result<()> {
    let f = Fixture::new(config()).await?;
    let call = scoped(
        ACTION_RUNTIME_PROGRAM_SUBMIT,
        map_value([
            (
                "source",
                Value::string(serde_json::to_string(&Program::new(wait().then(echo()?)))?),
            ),
            ("timeout_ms", Value::integer(40)),
        ]),
    );
    let result = f.service.call(&f.token, None, call).await?;
    let id = result
        .execution
        .context("reference")?
        .execution_id
        .context("id")?;
    let ended = f.finished(&id).await?;
    ensure!(field(&ended, "outcome")?.as_str() == Some("timed_out"));
    ensure!(f.calls.load(Ordering::SeqCst) == 0);
    let id = f
        .submit(echo()?.then(wait()).then(echo()?), Value::null())
        .await?;
    f.wait_for_calls(1).await?;
    tokio::time::timeout(Duration::from_secs(1), f.service.shutdown_executions()).await?;
    let ended = f.finished(&id).await?;
    ensure!(field(&ended, "outcome")?.as_str() == Some("cancelled"));
    ensure!(field(&ended, "stop_cause")?.as_str() == Some("shutdown"));
    ensure!(f.submit(echo()?, Value::null()).await.is_err());
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    f.service.shutdown_executions().await;
    let description = f
        .call(ACTION_RUNTIME_DESCRIBE, Value::null())
        .await?
        .output
        .context("description")?;
    let submission =
        crate::service::runtime::tests::discovery::mode(&description, "submission", "host")?;
    ensure!(submission.get("enabled").and_then(Value::as_bool) == Some(true));
    ensure!(submission.get("accepting").and_then(Value::as_bool) == Some(false));
    let call = crate::service::runtime::tests::discovery::mode(&description, "call", "host")?;
    ensure!(call.get("accepting").and_then(Value::as_bool) == Some(true));
    Ok(())
}

#[tokio::test]
async fn accepted_submission_can_finish_after_its_call_visibility_expires() -> anyhow::Result<()> {
    let f = Fixture::new(config()).await?;
    let wait = Expression::Wait {
        wait: WaitSpec::Deadline(xolotl_kernel::host::system_now_millis() + 1_500),
    };
    let mut call = scoped(
        ACTION_RUNTIME_PROGRAM_SUBMIT,
        map_value([
            (
                "source",
                Value::string(serde_json::to_string(&Program::new(wait.then(echo()?)))?),
            ),
            ("timeout_ms", Value::integer(4_000)),
        ]),
    );
    call.ttl_ms = Some(500);
    let result = f.service.call(&f.token, Some("embedded"), call).await?;
    let id = result
        .execution
        .context("execution")?
        .execution_id
        .context("retained ID")?;
    let accepted_at = std::time::Instant::now();
    let ended = f.finished(&id).await?;
    ensure!(accepted_at.elapsed() >= Duration::from_millis(500));
    ensure!(field(&ended, "outcome")?.as_str() == Some("done"));
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn logout_does_not_cancel_jobs_and_new_session_can_observe_them() -> anyhow::Result<()> {
    let mut f = Fixture::new(config()).await?;
    let owner = f.owner().await?;
    let id = f.submit(echo()?.then(wait()), Value::integer(1)).await?;
    f.wait_for_calls(1).await?;
    let replacement = f
        .service
        .step_up(
            &f.token,
            crate::StepUpRequest {
                proof: Some(f.state.auth.next_test_totp(&f.state.boot, "root").await?),
            },
            "embedded".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("stepped-up session")?;
    f.call(ACTION_ACCESS_SESSION_CURRENT_LOGOUT, Value::null())
        .await?;
    let grants = f.state.auth.execution_grants(&f.state.boot, &owner).await?;
    ensure!(grants.contains("perform", &Path::parse("effect://jobs/echo")?));
    tokio::time::sleep(Duration::from_millis(30)).await;
    let running = f.state.executions.get(&owner, &id)?;
    ensure!(field(&running, "status")?.as_str() == Some("running"));
    f.token = replacement.token;
    f.call(ACTION_RUNTIME_EXECUTION_CANCEL, id_input(&id))
        .await?;
    f.finished(&id).await?;
    Ok(())
}

#[tokio::test]
async fn role_revocation_stops_work_and_blocks_results_but_not_owner_cancellation()
-> anyhow::Result<()> {
    let f = Fixture::new(config()).await?;
    let user_path = Path::parse("state://kernel/console/users/root")?;
    let mut user = f
        .state
        .state
        .read(&user_path)
        .await?
        .context("user")?
        .as_map()
        .context("user map")?
        .clone();
    user.insert("grants".into(), Value::list(vec![]))?;
    user.insert(
        "roles".into(),
        Value::list(vec![Value::string("jobs".into())]),
    )?;
    f.state
        .state
        .write_set(&user_path, Value::from(user))
        .await?;
    let role_path = Path::parse("state://kernel/console/roles/jobs")?;
    f.state
        .state
        .write_set(
            &role_path,
            map_value([(
                "grants",
                Value::list(vec![Value::string("perform://effect/jobs/**".into())]),
            )]),
        )
        .await?;
    let done = f.submit(echo()?, Value::integer(7)).await?;
    f.finished(&done).await?;
    let id = f
        .submit(echo()?.then(wait()).then(echo()?), Value::null())
        .await?;
    f.wait_for_calls(2).await?;
    f.state
        .state
        .write_set(&role_path, map_value([("grants", Value::list(vec![]))]))
        .await?;
    let ended = f.finished(&id).await?;
    ensure!(field(&ended, "outcome")?.as_str() == Some("cancelled"));
    ensure!(field(&ended, "stop_cause")?.as_str() == Some("authority_revoked"));
    ensure!(f.calls.load(Ordering::SeqCst) == 2);
    let denied = f
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&done))
        .await
        .err()
        .context("revoked result")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);
    f.call(ACTION_RUNTIME_EXECUTION_CANCEL, id_input(&id))
        .await?;
    Ok(())
}

#[tokio::test]
async fn changed_account_predicate_revokes_volatile_execution_but_unconditional_covers_it()
-> anyhow::Result<()> {
    let f = Fixture::new(config()).await?;
    let user_path = Path::parse("state://kernel/console/users/root")?;
    let mut user = f
        .state
        .state
        .read(&user_path)
        .await?
        .context("user")?
        .as_map()
        .context("user map")?
        .clone();
    user.insert("grants".into(), Value::list(vec![]))?;
    user.insert(
        "roles".into(),
        Value::list(vec![Value::string("jobs".into())]),
    )?;
    f.state
        .state
        .write_set(&user_path, Value::from(user))
        .await?;
    let role_path = Path::parse("state://kernel/console/roles/jobs")?;
    let set_grant =
        |literal: &str| map_value([("grants", Value::list(vec![Value::string(literal.into())]))]);
    f.state
        .state
        .write_set(
            &role_path,
            set_grant("perform://effect/jobs/**@tenant=alice"),
        )
        .await?;
    let current = f
        .state
        .auth
        .execution_grants(&f.state.boot, &f.owner().await?)
        .await?;
    ensure!(
        current.matches_preflight(
            "perform",
            &Path::parse("effect://jobs/echo")?,
            xolotl_kernel::host::system_now_millis(),
        ),
        "conditional role grant was not available: {current:?}"
    );
    let id = f
        .submit(
            echo()?.then(wait()).then(echo()?),
            map_value([("tenant", Value::string("alice".into()))]),
        )
        .await
        .context("submit conditional volatile execution")?;
    f.wait_for_calls(1).await?;
    f.state
        .state
        .write_set(&role_path, set_grant("perform://effect/jobs/**"))
        .await?;
    tokio::time::sleep(Duration::from_millis(40)).await;
    let running = f.call(ACTION_RUNTIME_EXECUTION_GET, id_input(&id)).await?;
    ensure!(
        field(&running.output.context("running record")?, "status")?.as_str() == Some("running")
    );
    f.state
        .state
        .write_set(&role_path, set_grant("perform://effect/jobs/**@tenant=bob"))
        .await?;
    let ended = f.finished(&id).await?;
    ensure!(field(&ended, "outcome")?.as_str() == Some("cancelled"));
    ensure!(field(&ended, "stop_cause")?.as_str() == Some("authority_revoked"));
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn expired_current_until_cannot_cover_retained_candidate() -> anyhow::Result<()> {
    let f = Fixture::new(config()).await?;
    let owner = f.owner().await?;
    let user_path = Path::parse("state://kernel/console/users/root")?;
    let mut user = f
        .state
        .state
        .read(&user_path)
        .await?
        .context("user")?
        .as_map()
        .context("user map")?
        .clone();
    user.insert("grants".into(), Value::list(vec![]))?;
    user.insert(
        "roles".into(),
        Value::list(vec![Value::string("jobs".into())]),
    )?;
    f.state
        .state
        .write_set(&user_path, Value::from(user))
        .await?;
    let role_path = Path::parse("state://kernel/console/roles/jobs")?;
    let expired = "perform://effect/jobs/echo@until=0";
    f.state
        .state
        .write_set(
            &role_path,
            map_value([("grants", Value::list(vec![Value::string(expired.into())]))]),
        )
        .await?;
    let path = Path::parse("effect://jobs/echo")?;
    ensure!(
        check_authority(
            &f.state,
            &owner,
            &[("perform".into(), path)],
            &[xolotl_types::Capability::parse(expired)?],
        )
        .await
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn retained_until_candidate_uses_the_installed_host_clock() -> anyhow::Result<()> {
    use std::sync::atomic::AtomicI64;
    use xolotl_kernel::host::{AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner};

    struct Clock(AtomicI64);

    impl HostClock for Clock {
        fn monotonic_now(&self) -> std::time::Instant {
            std::time::Instant::now()
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
    let f = Fixture::with_boot(boot, config(), false, false).await?;
    let owner = f.owner().await?;
    let user_path = Path::parse("state://kernel/console/users/root")?;
    let mut user = f
        .state
        .state
        .read(&user_path)
        .await?
        .context("user")?
        .as_map()
        .context("user map")?
        .clone();
    user.insert("grants".into(), Value::list(vec![]))?;
    user.insert(
        "roles".into(),
        Value::list(vec![Value::string("jobs".into())]),
    )?;
    f.state
        .state
        .write_set(&user_path, Value::from(user))
        .await?;
    let role_path = Path::parse("state://kernel/console/roles/jobs")?;
    let retained = "perform://effect/jobs/echo@until=1500";
    f.state
        .state
        .write_set(
            &role_path,
            map_value([("grants", Value::list(vec![Value::string(retained.into())]))]),
        )
        .await?;
    let authority = [("perform".into(), Path::parse("effect://jobs/echo")?)];
    let candidates = [xolotl_types::Capability::parse(retained)?];
    ensure!(
        check_authority(&f.state, &owner, &authority, &candidates)
            .await
            .is_ok()
    );

    clock.0.store(1_500, Ordering::SeqCst);
    ensure!(
        check_authority(&f.state, &owner, &authority, &candidates)
            .await
            .is_ok()
    );

    clock.0.store(1_501, Ordering::SeqCst);
    ensure!(
        check_authority(&f.state, &owner, &authority, &candidates)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn records_and_cursors_are_bound_to_account_incarnation_and_host() -> anyhow::Result<()> {
    let f = Fixture::new(config()).await?;
    let owner = f.owner().await?;
    let one = f.submit(echo()?, Value::integer(1)).await?;
    f.finished(&one).await?;
    let two = f.submit(echo()?, Value::integer(2)).await?;
    f.finished(&two).await?;
    let page = f
        .call(
            ACTION_RUNTIME_EXECUTION_LIST,
            map_value([("limit", Value::integer(1))]),
        )
        .await?
        .output
        .context("page")?;
    let cursor = field(&page, "next_cursor")?.as_str().context("cursor")?;
    let page2 = f.state.executions.list(&owner, Some(cursor), 1, 4096)?;
    ensure!(
        field(&page2, "entries")?
            .as_list()
            .context("entries")?
            .len()
            == 1
    );
    let mut recreated = owner.clone();
    recreated.account_id = "new-account-instance".into();
    for id in [&one, &two] {
        ensure!(f.state.executions.get(&recreated, id).is_err());
        ensure!(f.state.executions.cancel(&recreated, id).await.is_err());
        ensure!(f.state.executions.forget(&recreated, id).await.is_err());
        ensure!(f.state.executions.result(&recreated, id, |_| true).is_err());
    }
    ensure!(
        f.state
            .executions
            .list(&recreated, Some(cursor), 1, 4096)
            .is_err()
    );
    let other = crate::runtime::executions::ExecutionRegistry::new(config())?;
    ensure!(other.list(&owner, Some(cursor), 1, 4096).is_err());
    // A stale authenticated principal cannot acquire the recreated account's owner.
    let principal = f
        .state
        .auth
        .authenticate_token(&f.state.boot, &f.token)
        .await?;
    let path = Path::parse("state://kernel/console/users/root")?;
    let mut user = f
        .state
        .state
        .read(&path)
        .await?
        .context("user")?
        .as_map()
        .context("map")?
        .clone();
    user.insert("account_id".into(), Value::string(recreated.account_id))?;
    f.state.state.write_set(&path, Value::from(user)).await?;
    ensure!(
        f.state
            .auth
            .execution_owner(
                &f.state.boot,
                f.token.split_once('.').context("SID")?.0,
                &principal
            )
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn expiration_reclaims_slots_and_worker_drop_preserves_known_body_outcome()
-> anyhow::Result<()> {
    let f = Fixture::new(ConsoleExecutionConfig {
        retention_ms: 20,
        max_records: 1,
        max_records_per_account: 1,
        max_concurrent: 1,
        max_concurrent_per_account: 1,
        ..config()
    })
    .await?;
    let owner = f.owner().await?;
    let id = f.submit(echo()?, Value::null()).await?;
    f.finished(&id).await?;
    tokio::time::sleep(Duration::from_millis(30)).await;
    ensure!(f.state.executions.get(&owner, &id).is_err());
    let (registration, _stop, reference) = f.state.executions.register(
        owner.clone(),
        vec![],
        ExecutionReference {
            execution_id: None,
            process_id: "123".into(),
            program_id: "ab".repeat(32),
        },
        xolotl_kernel::host::system_now_millis() + 1000,
        xolotl_types::BudgetSpec::default(),
    )?;
    registration.record_body(Completion {
        outcome: "done".into(),
        stop_cause: None,
        result: RetainedResult::encode(&Value::integer(5), 128),
        unresolved_operations: Default::default(),
        cleanup_complete: false,
        finalization: Default::default(),
    });
    drop(registration);
    let record = f
        .state
        .executions
        .get(&owner, reference.execution_id.as_deref().context("id")?)?;
    ensure!(field(&record, "outcome")?.as_str() == Some("done"));
    ensure!(field(&record, "cleanup_status")?.as_str() == Some("pending"));
    ensure!(field(&record, "result_status")?.as_str() == Some("available"));
    Ok(())
}

#[tokio::test]
async fn account_retention_and_authority_budgets_reject_before_effects() -> anyhow::Result<()> {
    let f = Fixture::new(ConsoleExecutionConfig {
        max_records: 2,
        max_records_per_account: 1,
        max_concurrent: 2,
        max_concurrent_per_account: 1,
        ..config()
    })
    .await?;
    let id = f.submit(echo()?, Value::integer(1)).await?;
    f.finished(&id).await?;
    ensure!(f.submit(echo()?, Value::integer(2)).await.is_err());
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    let mut other = f.owner().await?;
    other.account_id = "other".into();
    let (registration, _, _) = f.state.executions.register(
        other,
        vec![],
        ExecutionReference {
            execution_id: None,
            process_id: "999".into(),
            program_id: "bb".repeat(32),
        },
        xolotl_kernel::host::system_now_millis() + 1000,
        xolotl_types::BudgetSpec::default(),
    )?;
    drop(registration);
    let narrow = ConsoleState::with_config(
        f.state.boot.clone(),
        ConsoleConfig {
            session_store: Some(f.state.auth.session_store.clone()),
            runtime: ConsoleRuntimeConfig {
                executions: ConsoleExecutionConfig {
                    max_authority_bytes: 1,
                    ..config()
                },
                ..f.state.runtime.config.clone()
            },
            ..Default::default()
        },
    )?;
    let result = ConsoleService::new(narrow)
        .call(
            &f.token,
            None,
            scoped(
                ACTION_RUNTIME_OPERATION_SUBMIT,
                map_value([
                    ("target", Value::string("effect://jobs/echo".into())),
                    ("method", Value::string("invoke".into())),
                ]),
            ),
        )
        .await;
    ensure!(result.err().context("authority budget")?.code == ConsoleErrorCode::BadRequest);
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn account_generation_changes_stop_jobs_even_after_their_session_is_gone()
-> anyhow::Result<()> {
    let f = Fixture::new(config()).await?;
    let owner = f.owner().await?;
    let id = f
        .submit(echo()?.then(wait()).then(echo()?), Value::null())
        .await?;
    f.wait_for_calls(1).await?;
    f.call(ACTION_ACCESS_SESSION_CURRENT_LOGOUT, Value::null())
        .await?;
    let path = Path::parse("state://kernel/console/users/root")?;
    let mut user = f
        .state
        .state
        .read(&path)
        .await?
        .context("user")?
        .as_map()
        .context("map")?
        .clone();
    let version = user.get("version").and_then(Value::as_int).unwrap_or(0);
    user.insert("version".into(), Value::integer(version + 1))?;
    f.state.state.write_set(&path, Value::from(user)).await?;
    let record = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let record = f.state.executions.get(&owner, &id)?;
            if field(&record, "status")?.as_str() == Some("finished") {
                return Ok::<_, anyhow::Error>(record);
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await??;
    ensure!(field(&record, "outcome")?.as_str() == Some("cancelled"));
    ensure!(field(&record, "stop_cause")?.as_str() == Some("authority_revoked"));
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[test]
fn invalid_execution_budgets_fail_at_host_assembly_and_limits_change_revision() -> anyhow::Result<()>
{
    let boot = Arc::new(Bootstrap::in_memory());
    for executions in [
        ConsoleExecutionConfig {
            max_concurrent_per_account: 33,
            ..config()
        },
        ConsoleExecutionConfig {
            max_records_per_account: 257,
            ..config()
        },
        ConsoleExecutionConfig {
            max_result_bytes: 4 * 1024 * 1024,
            ..config()
        },
        ConsoleExecutionConfig {
            max_authority_bytes: 0,
            ..config()
        },
        ConsoleExecutionConfig {
            retention_ms: 0,
            ..config()
        },
    ] {
        ensure!(
            ConsoleState::with_config(
                boot.clone(),
                ConsoleConfig {
                    session_store: Some(std::sync::Arc::new(
                        crate::session_store::MemoryConsoleSessionStore::new(
                            crate::session_store::ConsoleSessionPolicy::default()
                        )
                    )),
                    runtime: ConsoleRuntimeConfig {
                        executions,
                        ..Default::default()
                    },
                    ..Default::default()
                }
            )
            .is_err()
        );
    }
    let one = ConsoleState::shared(
        boot.clone(),
        std::sync::Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
            crate::session_store::ConsoleSessionPolicy::default(),
        )),
    )?;
    let two = ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            runtime: ConsoleRuntimeConfig {
                executions: config(),
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    ensure!(one.registry.current_rev() != two.registry.current_rev());
    Ok(())
}
