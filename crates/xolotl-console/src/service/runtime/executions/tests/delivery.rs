use super::*;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::AtomicI64;
use std::time::Instant;
use tokio::sync::Semaphore;
use xolotl_kernel::host::{AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner};
use xolotl_state::{Backend, StateBoundedRead, StateObservation, StateResult};

struct Clock(AtomicI64);

impl HostClock for Clock {
    fn monotonic_now(&self) -> Instant {
        Instant::now()
    }

    fn unix_millis(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep_until(deadline.into()))
    }
}

struct Tasks(HostRuntime);

impl TaskSpawner for Tasks {
    fn spawn(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
        self.0.spawn(future)
    }
}

struct QueryGate {
    state: Backend,
    queries: AtomicUsize,
    remaining: AtomicUsize,
    entered: Semaphore,
    release: Semaphore,
}

impl StateBoundedRead for QueryGate {
    type BoundedRead<'a> = Pin<Box<dyn Future<Output = StateResult<StateObservation>> + Send + 'a>>;

    fn read_tainted_bounded<'a>(
        &'a self,
        path: &'a Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedRead<'a> {
        Box::pin(async move {
            let observed = self
                .state
                .read_tainted_bounded(path, max_encoded_bytes)
                .await?;
            if path
                .to_string()
                .starts_with(crate::paths::VAULT_CREDENTIALS_PREFIX)
            {
                self.queries.fetch_add(1, Ordering::SeqCst);
                if self
                    .remaining
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                        remaining.checked_sub(1)
                    })
                    == Ok(1)
                {
                    self.entered.add_permits(1);
                    self.release
                        .acquire()
                        .await
                        .map_err(|error| xolotl_state::StateError::Backend(error.to_string()))?
                        .forget();
                }
            }
            Ok(observed)
        })
    }
}

struct StreamEffect;

#[async_trait::async_trait]
impl Driver for StreamEffect {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        context.emit(input.clone()).await?;
        Ok(DriverOutput::new(xolotl_types::Outcome::Done(input)))
    }
}

async fn fixture() -> anyhow::Result<(Fixture, Arc<QueryGate>, Arc<Clock>, String)> {
    let state = xolotl_state::InMemoryBackend::new().into_backend();
    let gate = Arc::new(QueryGate {
        state: state.clone(),
        queries: AtomicUsize::new(0),
        remaining: AtomicUsize::new(0),
        entered: Semaphore::new(0),
        release: Semaphore::new(0),
    });
    let clock = Arc::new(Clock(AtomicI64::new(
        xolotl_kernel::host::system_now_millis(),
    )));
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(state.with_bounded_read(gate.clone()))
            .with_host_runtime(HostRuntime::new(
                clock.clone(),
                Arc::new(Tasks(HostRuntime::tokio())),
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            ))
            .build(),
    ));
    boot.register_effect(
        "effect://jobs/stream",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            OutputModeSet::STREAM,
        )],
        Arc::new(StreamEffect),
    )?;
    let fixture = Fixture::with_boot(boot, config(), false, false).await?;
    let expression = Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://jobs/stream")?),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Stream,
            literal_input: None,
        },
    };
    let id = fixture.submit(expression, Value::integer(73)).await?;
    fixture.finished(&id).await?;
    Ok((fixture, gate, clock, id))
}

async fn observe(
    state: &Arc<ConsoleState>,
    sid: &str,
    principal: &ConsolePrincipal,
    action: &str,
    id: &str,
) -> Result<Value, ConsoleError> {
    if action == "owner" {
        return state
            .auth
            .execution_owner(&state.boot, sid, principal)
            .await
            .map(|_| Value::null())
            .map_err(ConsoleError::from);
    }
    access_execution(
        &ActionContext {
            delivery: None,
            state,
            source_addr: Some("embedded"),
            session_id: sid,
        },
        principal,
        &scoped(action, id_input(id)),
    )
    .await
}

#[tokio::test]
async fn last_execution_query_rechecks_current_sid() -> anyhow::Result<()> {
    for action in [
        "owner",
        ACTION_RUNTIME_EXECUTION_RESULT,
        ACTION_RUNTIME_EXECUTION_OUTPUT_READ,
    ] {
        for change in ["logout", "expiry", "renewal"] {
            let (fixture, gate, clock, id) = fixture().await?;
            let principal = fixture
                .state
                .auth
                .authenticate_token(&fixture.state.boot, &fixture.token)
                .await?;
            let sid = fixture.token.split_once('.').context("SID")?.0.to_owned();
            let session = fixture
                .state
                .auth
                .session_store
                .get(&sid)
                .await?
                .context("session")?
                .record
                .to_value();
            let queries_before = gate.queries.load(Ordering::SeqCst);
            observe(&fixture.state, &sid, &principal, action, &id).await?;
            let last_query = gate.queries.load(Ordering::SeqCst) - queries_before;
            ensure!(last_query > 0, "{action} made no authority query");
            gate.remaining.store(last_query, Ordering::SeqCst);
            let state = fixture.state.clone();
            let requested_sid = sid.clone();
            let requested_id = id.clone();
            let reader = tokio::spawn(async move {
                observe(&state, &requested_sid, &principal, action, &requested_id).await
            });
            tokio::time::timeout(Duration::from_secs(3), gate.entered.acquire())
                .await
                .with_context(|| format!("{action}/{change} did not reach query {last_query}"))??
                .forget();
            ensure!(!reader.is_finished(), "{action}/{change} missed query wait");
            match change {
                "logout" => {
                    fixture
                        .state
                        .auth
                        .logout_sid_from_source(&fixture.state.boot, &sid, Some("embedded"))
                        .await?
                }
                "expiry" => clock.0.store(
                    field(&session, "idle_expires_at")?
                        .as_int()
                        .context("idle expiry")?,
                    Ordering::SeqCst,
                ),
                _ => {
                    clock.0.fetch_add(10, Ordering::SeqCst);
                    fixture
                        .state
                        .auth
                        .authenticate_token(&fixture.state.boot, &fixture.token)
                        .await?;
                }
            }
            gate.release.add_permits(1);
            let result = tokio::time::timeout(Duration::from_secs(3), reader).await??;
            if change == "renewal" {
                ensure!(result.is_ok(), "{action}/{change}: {result:?}");
                if action == ACTION_RUNTIME_EXECUTION_RESULT {
                    ensure!(field(field(&result?, "output")?, "value")?.as_int() == Some(73));
                } else if action == ACTION_RUNTIME_EXECUTION_OUTPUT_READ {
                    ensure!(
                        !field(&result?, "entries")?
                            .as_list()
                            .context("entries")?
                            .is_empty()
                    );
                }
            } else {
                ensure!(
                    matches!(result, Err(ConsoleError::Auth(AuthError::InvalidSession))),
                    "{action}/{change}: {result:?}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn new_sid_can_disclose_old_execution_result_and_output() -> anyhow::Result<()> {
    let (mut fixture, _gate, _clock, id) = fixture().await?;
    let replacement = fixture
        .service
        .step_up(
            &fixture.token,
            crate::StepUpRequest {
                proof: Some(
                    fixture
                        .state
                        .auth
                        .next_test_totp(&fixture.state.boot, "root")
                        .await?,
                ),
            },
            "embedded".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("replacement session")?;
    ensure!(fixture.token.split_once('.').context("old SID")?.0 != replacement.sid);
    fixture
        .call(ACTION_ACCESS_SESSION_CURRENT_LOGOUT, Value::null())
        .await?;
    fixture.token = replacement.token;
    let result = fixture
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("result")?;
    ensure!(field(field(&result, "output")?, "value")?.as_int() == Some(73));
    let page = fixture
        .call(ACTION_RUNTIME_EXECUTION_OUTPUT_READ, id_input(&id))
        .await?
        .output
        .context("page")?;
    ensure!(
        !field(&page, "entries")?
            .as_list()
            .context("entries")?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn closing_execution_admission_preserves_observation_and_calls() -> anyhow::Result<()> {
    let (fixture, _gate, _clock, id) = fixture().await?;
    let running_id = fixture
        .submit(echo()?.then(wait()), Value::integer(1))
        .await?;
    fixture.wait_for_calls(1).await?;
    fixture.service.close_execution_admission();
    fixture.service.close_execution_admission();
    ensure!(!fixture.state.executions.accepting());
    let running = fixture
        .call(ACTION_RUNTIME_EXECUTION_GET, id_input(&running_id))
        .await?
        .output
        .context("running metadata")?;
    ensure!(field(&running, "status")?.as_str() == Some("running"));
    fixture
        .call(ACTION_RUNTIME_EXECUTION_GET, id_input(&id))
        .await?;
    fixture
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?;
    ensure!(fixture.submit(echo()?, Value::integer(1)).await.is_err());
    fixture
        .call(
            ACTION_RUNTIME_OPERATION_INVOKE,
            map_value([
                ("target", Value::string("effect://jobs/echo".into())),
                ("method", Value::string("invoke".into())),
                ("input", Value::integer(9)),
            ]),
        )
        .await?;
    fixture.service.shutdown_executions().await;
    Ok(())
}
