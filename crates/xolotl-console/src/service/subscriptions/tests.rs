use super::*;
use crate::{
    ConsoleConfig, ConsoleRuntimeConfig, ConsoleStreamConfig, LoginRequest, RootProvisioning,
    RuntimeCode, RuntimeRequest, bootstrap_root_account,
};
use anyhow::{Context, ensure};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use xolotl_graph::{
    OperationTemplate,
    portable::{Expression, Program},
};
use xolotl_kernel::{Bootstrap, Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_standard::{StandardConfig, install_standard};
use xolotl_types::{
    InterfaceFamily, MethodId, Outcome, OutputMode, OutputModeSet, Purity, ResourceName, TaintSet,
    TaintSource, TaintedValue,
};

#[tokio::test]
async fn state_backend_diagnostic_is_not_a_subscription_error() -> anyhow::Result<()> {
    use std::task::{Context as TaskContext, Poll};
    use xolotl_state::{StateEvent, StateStream, StateSubscription, StateWatchError};

    struct BackendFault;
    impl StateSubscription for BackendFault {
        fn poll_next(
            &mut self,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<Result<Option<StateEvent>, StateWatchError>> {
            Poll::Ready(Err(StateWatchError::Backend(
                "state://vault/private-backend-path".into(),
            )))
        }
    }

    let mut events = Box::pin(StateStream::new(BackendFault).into_events());
    ensure!(matches!(
        events.next().await,
        Some(Err(SourceError::Failed))
    ));
    Ok(())
}

#[tokio::test]
async fn invalidated_state_subscription_requires_a_new_snapshot() -> anyhow::Result<()> {
    use std::task::{Context as TaskContext, Poll};
    use xolotl_state::{StateEvent, StateStream, StateSubscription, StateWatchError};

    struct Invalidated;
    impl StateSubscription for Invalidated {
        fn poll_next(
            &mut self,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<Result<Option<StateEvent>, StateWatchError>> {
            Poll::Ready(Err(StateWatchError::Invalidated))
        }
    }

    let mut events = Box::pin(StateStream::new(Invalidated).into_events());
    ensure!(matches!(
        events.next().await,
        Some(Err(SourceError::Invalidated))
    ));
    Ok(())
}

#[derive(Default)]
struct Probe {
    active: AtomicUsize,
    emitted: AtomicUsize,
    started: Notify,
}

struct Active(Arc<Probe>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct StreamingDriver {
    probe: Arc<Probe>,
    count: usize,
    hold: bool,
}

#[async_trait::async_trait]
impl Driver for StreamingDriver {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.probe.active.fetch_add(1, Ordering::SeqCst);
        let _active = Active(self.probe.clone());
        self.probe.started.notify_one();
        for _ in 0..self.count {
            ctx.emit_tainted(TaintedValue::new(
                input.clone(),
                TaintSet::of(TaintSource::ModelOutput),
            ))
            .await?;
            self.probe.emitted.fetch_add(1, Ordering::SeqCst);
        }
        if self.hold {
            std::future::pending::<()>().await;
        }
        Ok(DriverOutput::new(Outcome::Done(Value::integer(
            self.count as i64,
        ))))
    }
}

async fn fixture(
    count: usize,
    hold: bool,
) -> anyhow::Result<(Arc<ConsoleState>, ConsoleService, String, Arc<Probe>)> {
    fixture_with_modules(count, hold, crate::runtime::ConsoleModules::default()).await
}

async fn fixture_with_modules(
    count: usize,
    hold: bool,
    modules: crate::runtime::ConsoleModules,
) -> anyhow::Result<(Arc<ConsoleState>, ConsoleService, String, Arc<Probe>)> {
    let boot = Arc::new(Bootstrap::in_memory());
    install_standard(&boot, &StandardConfig::default())?;
    let probe = Arc::new(Probe::default());
    boot.register_subtree_resource_at(
        "effect://external/test/stream",
        "perform://effect/external/test/**",
        InterfaceFamily::Callable,
        &[MethodSpec::new(
            "read",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            OutputModeSet::STREAM,
        )],
        Arc::new(StreamingDriver {
            probe: probe.clone(),
            count,
            hold,
        }),
    )?;
    let outcome = bootstrap_root_account(
        &boot,
        &xolotl_kernel::host::TokioBlockingSpawner::default(),
        RootProvisioning {
            additional_grants: vec!["act-as://identity/stream/worker".into()],
            ..Default::default()
        },
    )
    .await?;
    let crate::BootstrapOutcome::CreatedRandomPassword { password, .. } = outcome else {
        anyhow::bail!("root password")
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
            modules,
            streams: ConsoleStreamConfig {
                max_subscriptions_global: 2,
                max_subscriptions_per_account: 2,
                max_event_bytes: 16 * 1024,
            },
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                capabilities: vec![
                    "perform://effect/external/test/**".into(),
                    "act-as://identity/stream/worker".into(),
                    "subscribe://state/stream/**".into(),
                ],
                max_output_streams: 4,
                stream_window_chunks: 2,
                stream_window_bytes: 4096,
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
                password,
                second_factor: None,
            },
            "test".into(),
        )
        .await?
        .into_session()
        .ok()
        .context("authenticated session")?;
    let login = state
        .auth
        .enroll_test_totp(&state.boot, &login.token)
        .await?;
    Ok((state, service, login.token, probe))
}

fn stream_call(id: &str, input: Value) -> StreamCall {
    StreamCall {
        stream: id.into(),
        input,
        scope: Some("test subscription".into()),
        justification: Some("exercise public subscription ownership".into()),
        ttl_ms: Some(60_000),
        ..Default::default()
    }
}

fn operation() -> StreamCall {
    stream_call(
        protocol::STREAM_RUNTIME_OPERATION,
        map_value([
            (
                "target",
                Value::string("effect://external/test/stream".into()),
            ),
            ("method", Value::string("read".into())),
            ("input", Value::bytes(vec![0, 128, 255])),
        ]),
    )
}

#[tokio::test]
async fn runtime_subscription_reserves_call_capacity_before_program_planning() -> anyhow::Result<()>
{
    let (state, service, token, _) = fixture(0, false).await?;
    let occupied = state.calls.clone().try_acquire_owned()?;
    let processes_before = state.boot.kernel().processes().len();
    let malformed = || {
        stream_call(
            protocol::STREAM_RUNTIME_PROGRAM,
            map_value([("source", Value::string("{not-json".into()))]),
        )
    };

    let failure = service
        .subscribe(&token, None, malformed())
        .await
        .err()
        .context("occupied call capacity must reject a runtime subscription")?;
    ensure!(failure.code == protocol::ConsoleErrorCode::RateLimited);
    ensure!(state.boot.kernel().processes().len() == processes_before);

    drop(occupied);
    let failure = service
        .subscribe(&token, None, malformed())
        .await
        .err()
        .context("the malformed program must be checked after capacity is available")?;
    ensure!(failure.code == protocol::ConsoleErrorCode::BadRequest);
    ensure!(state.boot.kernel().processes().len() == processes_before);
    Ok(())
}

#[tokio::test]
async fn runtime_delivery_rechecks_the_admitted_time_bound() -> anyhow::Result<()> {
    let (state, _service, token, _) = fixture(0, false).await?;
    let principal = state.auth.authenticate_token(&state.boot, &token).await?;
    let path = Path::parse("effect://external/test/stream")?;
    let now = xolotl_kernel::host::system_now_millis();
    let access = Access::Runtime {
        operations: vec![("perform".into(), path.clone(), Some("read".into()))],
        expires_at: Some(now.saturating_sub(1)),
    };
    ensure!(access.authorize(&state, &principal).await.is_err());
    let access = Access::Runtime {
        operations: vec![("perform".into(), path, Some("read".into()))],
        expires_at: Some(now.saturating_add(60_000)),
    };
    access.authorize(&state, &principal).await?;
    Ok(())
}

#[tokio::test]
async fn runtime_delivery_closes_at_the_earliest_grant_expiry_even_with_an_alternative()
-> anyhow::Result<()> {
    use std::sync::atomic::AtomicI64;
    use std::time::Instant;
    use xolotl_kernel::host::{AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner};

    struct FrozenClock {
        instant: Instant,
        millis: AtomicI64,
    }

    impl HostClock for FrozenClock {
        fn monotonic_now(&self) -> Instant {
            self.instant
        }

        fn unix_millis(&self) -> i64 {
            self.millis.load(Ordering::SeqCst)
        }

        fn sleep_until(
            &self,
            _deadline: Instant,
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

    let (login_state, _service, token, _) = fixture(0, false).await?;
    let mut principal = login_state
        .auth
        .authenticate_token(&login_state.boot, &token)
        .await?;
    let clock = Arc::new(FrozenClock {
        instant: Instant::now(),
        millis: AtomicI64::new(999),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::in_memory()
            .with_host_runtime(HostRuntime::new(
                clock.clone(),
                Arc::new(NoTasks),
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            ))
            .build(),
    ));
    let state = ConsoleState::with_config(
        boot,
        ConsoleConfig {
            session_store: Some(std::sync::Arc::new(
                crate::session_store::MemoryConsoleSessionStore::new(
                    crate::session_store::ConsoleSessionPolicy::default(),
                ),
            )),
            runtime: ConsoleRuntimeConfig {
                enabled: true,
                capabilities: vec!["perform://effect/external/test/stream#read".into()],
                ..Default::default()
            },
            ..Default::default()
        },
    )?;
    principal.grants = xolotl_types::CapSet::from_strs([
        "perform://effect/external/test/stream#read@until=1000",
        "perform://effect/external/test/stream#read@until=2000",
    ])?;
    let access = Access::Runtime {
        operations: vec![(
            "perform".into(),
            Path::parse("effect://external/test/stream")?,
            Some("read".into()),
        )],
        expires_at: Some(1_000),
    };
    access.authorize(&state, &principal).await?;
    clock.millis.store(1_000, Ordering::SeqCst);
    ensure!(
        access.authorize(&state, &principal).await.is_err(),
        "the later grant must not disclose output after an earlier admitted grant expires"
    );
    Ok(())
}

#[tokio::test]
async fn runtime_delivery_rechecks_the_admitted_method() -> anyhow::Result<()> {
    let (state, _service, token, _) = fixture(0, false).await?;
    let mut principal = state.auth.authenticate_token(&state.boot, &token).await?;
    let access = Access::Runtime {
        operations: vec![(
            "perform".into(),
            Path::parse("effect://external/test/stream")?,
            Some("read".into()),
        )],
        expires_at: None,
    };
    principal.grants =
        xolotl_types::CapSet::from_strs(["perform://effect/external/test/stream#read"])?;
    access.authorize(&state, &principal).await?;
    principal.grants =
        xolotl_types::CapSet::from_strs(["perform://effect/external/test/stream#other"])?;
    ensure!(access.authorize(&state, &principal).await.is_err());
    Ok(())
}

async fn receive(subscription: &mut ConsoleSubscription) -> anyhow::Result<ConsoleEvent> {
    tokio::time::timeout(Duration::from_secs(2), subscription.recv())
        .await??
        .context("event")
}

fn runtime(event: ConsoleEvent) -> anyhow::Result<Value> {
    let ConsoleEvent::Runtime { event } = event else {
        anyhow::bail!("runtime event")
    };
    Ok(event)
}

fn kind(event: &Value) -> anyhow::Result<&str> {
    event
        .as_map()
        .and_then(|map| map.get("kind"))
        .and_then(Value::as_str)
        .context("kind")
}

#[tokio::test]
async fn owned_rust_runtime_subscription_uses_the_public_delivery_lease() -> anyhow::Result<()> {
    let (_state, service, token, probe) = fixture(1, false).await?;
    let input = Value::bytes(vec![0, 128, 255]);
    let request = RuntimeRequest::new(
        RuntimeCode::Operation {
            operation: OperationTemplate {
                target: ResourceName::new(Path::parse("effect://external/test/stream")?),
                method: "read".into(),
                method_id: None,
                output: OutputMode::Stream,
                literal_input: None,
            },
        },
        input.clone(),
        "test subscription",
        "owned Rust runtime stream",
        60_000,
    );
    let mut subscription = service.subscribe_runtime(&token, None, request).await?;
    ensure!(subscription.execution().is_some());
    for expected in ["started", "output", "operation_finished", "finished"] {
        let event = runtime(receive(&mut subscription).await?)?;
        ensure!(kind(&event)? == expected);
        if expected == "output" {
            ensure!(event.as_map().and_then(|map| map.get("value")) == Some(&input));
        }
    }
    ensure!(subscription.recv().await?.is_none());
    ensure!(probe.emitted.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn successful_subscription_reports_cancelled_effect_identity() -> anyhow::Result<()> {
    struct Pending(Arc<AtomicUsize>);
    struct Winner(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl Driver for Pending {
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

    #[async_trait::async_trait]
    impl Driver for Winner {
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
            Ok(DriverOutput::new(Outcome::Done(Value::integer(42))))
        }
    }

    let (state, service, token, _) = fixture(0, false).await?;
    let started = Arc::new(AtomicUsize::new(0));
    let method = [MethodSpec::new(
        "invoke",
        xolotl_types::MethodAuthority::Perform,
        Purity::Effectful,
        OutputModeSet::UNARY,
    )];
    state.boot.register_effect(
        "effect://external/test/pending",
        &method,
        Arc::new(Pending(started.clone())),
    )?;
    state.boot.register_effect(
        "effect://external/test/winner",
        &method,
        Arc::new(Winner(started)),
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
    let program = Program::new(
        invoke("effect://external/test/pending")?.race(invoke("effect://external/test/winner")?),
    );
    let request = RuntimeRequest::new(
        RuntimeCode::Program(program),
        Value::null(),
        "race",
        "inspect cancelled effect",
        10_000,
    );
    let mut subscription = service.subscribe_runtime(&token, None, request).await?;
    loop {
        let event = runtime(receive(&mut subscription).await?)?;
        if kind(&event)? == "finished" {
            let fields = event.as_map().context("terminal event")?;
            ensure!(fields.get("outcome").and_then(Value::as_str) == Some("done"));
            let unresolved = fields
                .get("unresolved_operations")
                .and_then(Value::as_map)
                .context("terminal uncertain effects")?;
            ensure!(
                unresolved
                    .get("operation_ids")
                    .and_then(Value::as_list)
                    .is_some_and(|ids| ids.len() == 1)
            );
            ensure!(
                unresolved
                    .get("identities_incomplete")
                    .and_then(Value::as_bool)
                    == Some(false)
            );
            break;
        }
    }
    ensure!(subscription.recv().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn subscription_budget_denies_before_emission_and_reports_the_admitted_ceiling()
-> anyhow::Result<()> {
    let (_state, service, token, probe) = fixture(1, false).await?;
    let budget = xolotl_types::BudgetSpec {
        max_inflight_ops: Some(0),
        ..Default::default()
    };
    let mut call = operation();
    let mut input = input_map(call.input)?;
    input.insert("budget".into(), crate::runtime::budget::value(&budget)?)?;
    call.input = Value::from(input);
    let mut subscription = service.subscribe(&token, None, call).await?;
    for expected in ["started", "operation_finished", "finished"] {
        let event = runtime(receive(&mut subscription).await?)?;
        ensure!(kind(&event)? == expected);
        let map = event.as_map().context("event")?;
        if expected != "operation_finished" {
            ensure!(map.get("budget") == Some(&crate::runtime::budget::value(&budget)?));
        }
        if expected == "finished" {
            ensure!(map.get("outcome").and_then(Value::as_str) == Some("failed"));
            ensure!(
                map.get("failure")
                    .and_then(Value::as_map)
                    .and_then(|m| m.get("code"))
                    .and_then(Value::as_str)
                    == Some("rate_limited")
            );
        }
    }
    ensure!(subscription.recv().await?.is_none());
    ensure!(probe.emitted.load(Ordering::SeqCst) == 0);
    ensure!(probe.active.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn delegated_signal_subscription_uses_the_shared_operation_contract() -> anyhow::Result<()> {
    let (state, service, token, probe) = fixture(0, false).await?;
    let path = Path::parse("state://stream/ready")?;
    let value = Value::bytes(vec![17, 255]);
    state.state.write_set(&path, value.clone()).await?;
    let program = Program::new(Expression::Acting {
        identity: Path::parse("identity://stream/worker")?,
        body: Box::new(Expression::Wait {
            wait: xolotl_graph::WaitSpec::Signal(path),
        }),
    });
    let mut subscription = service
        .subscribe(
            &token,
            None,
            stream_call(
                protocol::STREAM_RUNTIME_PROGRAM,
                map_value([("source", Value::string(serde_json::to_string(&program)?))]),
            ),
        )
        .await?;
    let Access::Runtime {
        operations: authority,
        ..
    } = &subscription.access
    else {
        anyhow::bail!("runtime access")
    };
    ensure!(authority.iter().any(|(verb, _, _)| verb == "act-as"));
    ensure!(authority.iter().any(|(verb, _, _)| verb == "subscribe"));
    ensure!(kind(&runtime(receive(&mut subscription).await?)?)? == "started");
    let event = runtime(receive(&mut subscription).await?)?;
    ensure!(kind(&event)? == "finished");
    ensure!(event.as_map().and_then(|map| map.get("value")) == Some(&value));
    ensure!(subscription.recv().await?.is_none());
    ensure!(state.boot.kernel().handles().is_empty());
    ensure!(probe.emitted.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn delivery_authentication_does_not_generate_events_or_extend_idle_time() -> anyhow::Result<()>
{
    let (state, service, token, _) = fixture(1, false).await?;
    let mut subscription = service
        .subscribe(
            &token,
            None,
            stream_call(
                STREAM_STATE_WATCH,
                map_value([(
                    "pattern",
                    Value::string("state://console-test/delivery".into()),
                )]),
            ),
        )
        .await?;
    let sid = bearer_sid(Some(&token)).context("sid")?;
    let session_path = crate::paths::stored_session_path(sid)?;
    let session = state
        .auth
        .session_store
        .get(sid)
        .await?
        .context("session")?
        .encode()?;
    let mut private_events = state.state.subscribe(&session_path).await?;
    let path = Path::parse("state://console-test/delivery")?;
    state.state.write_set(&path, Value::integer(1)).await?;
    ensure!(
        matches!(receive(&mut subscription).await?, ConsoleEvent::StateSet { path: delivered, .. } if delivered == path)
    );
    ensure!(
        state
            .auth
            .session_store
            .get(sid)
            .await?
            .context("session")?
            .encode()?
            == session
    );
    ensure!(
        matches!(
            private_events.try_recv(),
            Err(xolotl_state::StateWatchError::Empty)
        ),
        "delivery wrote to the private session aggregate"
    );
    subscription.close().await;
    Ok(())
}

#[tokio::test]
async fn public_stream_preserves_parallel_operation_identity_values_taint_and_terminal_order()
-> anyhow::Result<()> {
    let (state, service, token, probe) = fixture(3, false).await?;
    let operation = Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://external/test/stream")?),
            method: "read".into(),
            method_id: None,
            output: OutputMode::Stream,
            literal_input: None,
        },
    };
    let program = Program::new(operation.clone().both(operation));
    let mut subscription = service
        .subscribe(
            &token,
            None,
            stream_call(
                protocol::STREAM_RUNTIME_PROGRAM,
                map_value([
                    ("source", Value::string(serde_json::to_string(&program)?)),
                    ("input", Value::bytes(vec![0, 128, 255])),
                ]),
            ),
        )
        .await?;
    let first = runtime(receive(&mut subscription).await?)?;
    ensure!(kind(&first)? == "started");
    let mut counts = BTreeMap::new();
    let mut ends = Vec::new();
    loop {
        let event = runtime(receive(&mut subscription).await?)?;
        let map = event.as_map().context("event map")?;
        match kind(&event)? {
            "output" => {
                let operation = map
                    .get("operation_id")
                    .and_then(Value::as_str)
                    .context("operation")?;
                ensure!(!ends.iter().any(|id| id == operation));
                ensure!(map.get("value") == Some(&Value::bytes(vec![0, 128, 255])));
                ensure!(
                    serde_json::to_string(map.get("taint").context("taint")?)?
                        .contains("model_output")
                );
                *counts.entry(operation.to_owned()).or_insert(0) += 1;
                let bytes = crate::wire::encode_server_frame(
                    &protocol::ServerFrame::Event {
                        stream: 1,
                        event: ConsoleEvent::Runtime {
                            event: event.clone(),
                        },
                    },
                    16 * 1024,
                )?;
                let frame = crate::wire::decode_server_frame(&bytes).map_err(anyhow::Error::msg)?;
                let Some(xolotl_console_protocol::pb::console_frame::Frame::Event(frame)) =
                    frame.frame
                else {
                    anyhow::bail!("event frame")
                };
                let Some(xolotl_console_protocol::pb::console_event::Kind::Runtime(wire)) =
                    frame.event.and_then(|event| event.kind)
                else {
                    anyhow::bail!("runtime wire")
                };
                ensure!(xolotl_proto::value_from_pb(&wire.event.context("payload")?)? == event);
            }
            "operation_finished" => {
                let operation = map
                    .get("operation_id")
                    .and_then(Value::as_str)
                    .context("operation")?;
                ensure!(counts.get(operation) == Some(&3));
                ensure!(map.get("failure").is_some_and(Value::is_null));
                ends.push(operation.to_owned());
            }
            "finished" => {
                ensure!(ends.len() == 2 && counts.len() == 2);
                break;
            }
            other => anyhow::bail!("unexpected {other}"),
        }
    }
    ensure!(subscription.recv().await?.is_none());
    ensure!(probe.emitted.load(Ordering::SeqCst) == 6);
    ensure!(state.calls.available_permits() == 1 && state.boot.kernel().handles().is_empty());
    Ok(())
}

#[tokio::test]
async fn host_modules_stream_through_the_same_owned_execution_and_revision_gate()
-> anyhow::Result<()> {
    use crate::runtime::{ConsoleModule, ConsoleModules, ModuleManifest, ModuleOperation};
    let operation = OperationTemplate {
        target: ResourceName::new(Path::parse("effect://external/test/stream")?),
        method: "read".into(),
        method_id: None,
        output: OutputMode::Stream,
        literal_input: None,
    };
    let identity = Path::parse("identity://stream/worker")?;
    let manifest = ModuleManifest {
        identities: vec![identity.clone()],
        signals: Vec::new(),
        name: "host.stream".into(),
        revision: [11; 32],
        modules: vec![],
        operations: vec![ModuleOperation {
            target: operation.target.clone(),
            method: operation.method.clone(),
            output: operation.output,
        }],
    };
    let modules = ConsoleModules::new([ConsoleModule::new(manifest, move |_input, argument| {
        Ok(Program::new(
            Expression::Constant {
                value: argument.cloned().unwrap_or(Value::null()),
            }
            .then(Expression::Acting {
                identity: identity.clone(),
                body: Box::new(Expression::Invoke {
                    operation: operation.clone(),
                }),
            }),
        ))
    })])?;
    let (state, service, token, probe) = fixture_with_modules(2, false, modules).await?;
    let program = Program::new(Expression::Module {
        module: xolotl_graph::StepRef::new("host.stream").with_arg(Value::bytes(vec![0, 255])),
    });
    let mut call = stream_call(
        protocol::STREAM_RUNTIME_PROGRAM,
        map_value([("source", Value::string(serde_json::to_string(&program)?))]),
    );
    call.registry_rev = Some(state.registry.current_rev() ^ 1);
    let failure = service
        .subscribe(&token, None, call.clone())
        .await
        .err()
        .context("stale module revision")?;
    ensure!(
        failure.code == protocol::ConsoleErrorCode::RegistryChanged
            && probe.emitted.load(Ordering::SeqCst) == 0
    );
    call.registry_rev = Some(state.registry.current_rev());
    let mut subscription = service.subscribe(&token, None, call).await?;
    for expected in [
        "started",
        "output",
        "output",
        "operation_finished",
        "finished",
    ] {
        let event = runtime(receive(&mut subscription).await?)?;
        ensure!(kind(&event)? == expected);
        if expected == "output" {
            ensure!(
                event.as_map().and_then(|map| map.get("value"))
                    == Some(&Value::bytes(vec![0, 255]))
            );
        }
    }
    ensure!(subscription.recv().await?.is_none());
    ensure!(probe.emitted.load(Ordering::SeqCst) == 2 && state.boot.kernel().handles().is_empty());
    Ok(())
}

#[tokio::test]
async fn slow_consumer_backpressures_and_close_joins_execution_and_reclaims_authority()
-> anyhow::Result<()> {
    let (state, service, token, probe) = fixture(1000, true).await?;
    let mut subscription = service.subscribe(&token, None, operation()).await?;
    tokio::time::timeout(Duration::from_secs(1), probe.started.notified()).await?;
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    ensure!(
        probe.emitted.load(Ordering::SeqCst) <= 4,
        "producer escaped its windows"
    );
    let error = service
        .subscribe(&token, None, operation())
        .await
        .err()
        .context("execution capacity")?;
    ensure!(error.code == protocol::ConsoleErrorCode::RateLimited);
    subscription.close().await;
    state.boot.drain_cleanup().await;
    ensure!(probe.active.load(Ordering::SeqCst) == 0);
    ensure!(state.calls.available_permits() == 1 && state.boot.kernel().handles().is_empty());
    ensure!(subscription.recv().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn worker_deadline_reclaims_execution_without_consumer_polling() -> anyhow::Result<()> {
    let (state, service, token, probe) = fixture(1000, true).await?;
    let mut call = operation();
    let mut input = call.input.as_map().context("input")?.clone();
    input.insert("timeout_ms".into(), Value::integer(20))?;
    call.input = Value::from(input);
    let mut subscription = service.subscribe(&token, None, call).await?;
    let execution = subscription
        .execution()
        .cloned()
        .context("allocated before polling")?;
    let reclaim_limit = Duration::from_millis(
        state
            .runtime
            .config
            .executions
            .cleanup_timeout_ms
            .saturating_add(1_000),
    );
    tokio::time::timeout(reclaim_limit, async {
        while state.calls.available_permits() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    ensure!(probe.active.load(Ordering::SeqCst) == 0 && state.boot.kernel().handles().is_empty());
    let mut failed = false;
    for _ in 0..4 {
        match subscription.recv().await {
            Err(error) => {
                ensure!(error.code == protocol::ConsoleErrorCode::OutcomeUnknown);
                ensure!(error.execution.as_deref() == Some(&execution));
                let detail = error
                    .outcome_unknown
                    .as_deref()
                    .context("settlement detail")?;
                ensure!(detail.reason == "settlement_timeout" && detail.operation_ids.is_empty());
                failed = true;
                break;
            }
            Ok(Some(_)) => {}
            Ok(None) => break,
        }
    }
    ensure!(failed);
    Ok(())
}

#[tokio::test]
async fn oversized_terminal_result_keeps_the_execution_identity() -> anyhow::Result<()> {
    let (state, service, token, _) = fixture(0, false).await?;
    let program = Program::new(Expression::Constant {
        value: Value::string("x".repeat(state.streams.max_event_bytes() + 1)),
    });
    let mut call = operation();
    call.stream = protocol::STREAM_RUNTIME_PROGRAM.into();
    call.input = map_value([("source", Value::string(serde_json::to_string(&program)?))]);
    let mut subscription = service.subscribe(&token, None, call).await?;
    let execution = subscription
        .execution()
        .cloned()
        .context("execution reference")?;
    ensure!(subscription.recv().await?.is_some());
    let failure = subscription
        .recv()
        .await
        .err()
        .context("oversized terminal result")?;
    ensure!(failure.code == protocol::ConsoleErrorCode::Internal);
    ensure!(failure.execution.as_deref() == Some(&execution));
    ensure!(subscription.recv().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn observation_admission_quota_expiry_and_revocation_are_shared_without_websocket()
-> anyhow::Result<()> {
    let (state, service, token, _) = fixture(1, false).await?;
    let call = stream_call(
        STREAM_STATE_WATCH,
        map_value([("pattern", Value::string("state://example/**".into()))]),
    );
    let mut a = service.subscribe(&token, None, call.clone()).await?;
    let mut b = service.subscribe(&token, None, call.clone()).await?;
    let error = service
        .subscribe(&token, None, call.clone())
        .await
        .err()
        .context("stream quota")?;
    ensure!(error.code == protocol::ConsoleErrorCode::RateLimited);
    b.close().await;
    let mut expiring = service
        .subscribe(
            &token,
            None,
            StreamCall {
                ttl_ms: Some(1),
                ..call
            },
        )
        .await?;
    let error = tokio::time::timeout(Duration::from_secs(1), expiring.recv())
        .await?
        .err()
        .context("expired")?;
    ensure!(error.code == protocol::ConsoleErrorCode::Forbidden);
    let path = Path::parse("state://example/item")?;
    state.state.write_set(&path, Value::integer(42)).await?;
    ensure!(
        matches!(receive(&mut a).await?, ConsoleEvent::StateSet { value, .. } if value == Value::integer(42))
    );
    state.state.write_set(&path, Value::integer(43)).await?;
    service
        .call(
            &token,
            None,
            ActionCall {
                action: protocol::ACTION_ACCESS_SESSION_CURRENT_LOGOUT.into(),
                ..Default::default()
            },
        )
        .await?;
    let error = a.recv().await.err().context("revoked queued event")?;
    ensure!(error.code == protocol::ConsoleErrorCode::NotAuthenticated);
    ensure!(a.recv().await?.is_none());
    Ok(())
}

#[tokio::test]
async fn state_watch_reports_source_categories_without_private_lineage_labels() -> anyhow::Result<()>
{
    let (state, service, token, _) = fixture(1, false).await?;
    let mut subscription = service
        .subscribe(
            &token,
            None,
            stream_call(
                STREAM_STATE_WATCH,
                map_value([("pattern", Value::string("state://example/**".into()))]),
            ),
        )
        .await?;
    let path = Path::parse("state://example/sourced-sequence")?;
    let protected_path = "state://vault/private-lineage-path";
    let mut initial = TaintSet::author();
    initial.add(TaintSource::Inbound {
        source: "gateway/private-installation".into(),
        channel: "private-channel".into(),
    });
    initial.add(TaintSource::Protected {
        path: Path::parse(protected_path)?,
    });
    state
        .state
        .write_set_tainted(&path, Value::list(vec![Value::integer(1)]), initial)
        .await?;
    let set = receive(&mut subscription).await?;
    let ConsoleEvent::StateSet {
        path: set_path,
        value,
        source: set_source,
    } = &set
    else {
        anyhow::bail!("expected StateSet")
    };
    ensure!(*set_path == path && *value == Value::list(vec![Value::integer(1)]));
    ensure!(
        *set_source
            == protocol::StateSourceSummary {
                tainted: true,
                author_constant: true,
                inbound: true,
                protected: true,
                ..Default::default()
            }
    );

    let mut appended = TaintSet::of(TaintSource::ModelOutput);
    appended.add(TaintSource::Fetched {
        host: "private-fetch-host".into(),
    });
    state
        .state
        .write_append_tainted(&path, Value::integer(2), appended)
        .await?;
    let append = receive(&mut subscription).await?;
    let ConsoleEvent::StateAppend {
        path: append_path,
        item,
        source: append_source,
    } = &append
    else {
        anyhow::bail!("expected StateAppend")
    };
    ensure!(*append_path == path && *item == Value::integer(2));
    let all_sources = protocol::StateSourceSummary {
        tainted: true,
        author_constant: true,
        model_output: true,
        inbound: true,
        fetched: true,
        protected: true,
    };
    ensure!(*append_source == all_sources);

    state.state.write_delete(&path).await?;
    let delete = receive(&mut subscription).await?;
    let ConsoleEvent::StateDelete {
        path: deleted_path,
        source: delete_source,
    } = &delete
    else {
        anyhow::bail!("expected StateDelete")
    };
    ensure!(*deleted_path == path && *delete_source == all_sources);

    for event in [set, append, delete] {
        let public = format!("{event:?}");
        for private in [
            protected_path,
            "private-installation",
            "private-channel",
            "private-fetch-host",
        ] {
            ensure!(!public.contains(private));
        }
    }
    Ok(())
}

#[tokio::test]
async fn ready_events_cannot_cross_expiry_or_identity_changes() -> anyhow::Result<()> {
    let (state, service, token, _) = fixture(1, false).await?;
    let call = stream_call(
        STREAM_STATE_WATCH,
        map_value([("pattern", Value::string("state://example/**".into()))]),
    );
    let mut expired = service.subscribe(&token, None, call.clone()).await?;
    let mut changed = service.subscribe(&token, None, call).await?;
    state
        .state
        .write_set(&Path::parse("state://example/item")?, Value::integer(42))
        .await?;
    expired.deadline = expired.state.boot.kernel().host_runtime().now();
    ensure!(
        expired
            .recv()
            .await
            .err()
            .context("expired ready event")?
            .code
            == protocol::ConsoleErrorCode::Forbidden
    );
    // Exercise a real host-side identity update while keeping the session valid.
    let user_path = Path::parse("state://kernel/console/users/root")?;
    let mut user = state
        .state
        .read(&user_path)
        .await?
        .context("user")?
        .into_map()
        .context("user map")?;
    user.insert(
        "identity_path".into(),
        Value::string("identity://console/accounts/reassigned-account".into()),
    )?;
    state.state.write_set(&user_path, Value::from(user)).await?;
    ensure!(
        changed.recv().await.err().context("changed identity")?.code
            == protocol::ConsoleErrorCode::Forbidden
    );
    Ok(())
}

#[tokio::test]
async fn transient_authentication_capacity_keeps_a_ready_event_for_retry() -> anyhow::Result<()> {
    let (state, service, token, _) = fixture(1, false).await?;
    let mut subscription = service
        .subscribe(
            &token,
            None,
            stream_call(
                STREAM_STATE_WATCH,
                map_value([("pattern", Value::string("state://example/**".into()))]),
            ),
        )
        .await?;
    state
        .state
        .write_set(&Path::parse("state://example/item")?, Value::integer(42))
        .await?;
    let capacity = state
        .authentications
        .try_acquire_many(u32::try_from(state.authentications.available_permits())?)?;
    let failure = tokio::time::timeout(Duration::from_secs(2), subscription.recv())
        .await?
        .err()
        .context("authentication capacity should refuse delivery")?;
    ensure!(failure.code == protocol::ConsoleErrorCode::RateLimited);
    drop(capacity);
    ensure!(matches!(
        receive(&mut subscription).await?,
        ConsoleEvent::StateSet { value, .. } if value == Value::integer(42)
    ));
    Ok(())
}

#[tokio::test]
async fn runtime_stream_preflights_every_import_before_effects_and_rejects_oversized_chunks()
-> anyhow::Result<()> {
    let (_state, service, token, probe) = fixture(1, false).await?;
    let valid = Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://external/test/stream")?),
            method: "read".into(),
            method_id: None,
            output: OutputMode::Stream,
            literal_input: None,
        },
    };
    let denied = Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://external/denied")?),
            method: "read".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    };
    let source = serde_json::to_string(&Program::new(valid.then(denied)))?;
    let failure = service
        .subscribe(
            &token,
            None,
            stream_call(
                protocol::STREAM_RUNTIME_PROGRAM,
                map_value([("source", Value::string(source))]),
            ),
        )
        .await
        .err()
        .context("preflight denied")?;
    ensure!(
        failure.code == protocol::ConsoleErrorCode::Forbidden
            && probe.emitted.load(Ordering::SeqCst) == 0
    );
    let mut call = operation();
    let mut input = call.input.as_map().context("input")?.clone();
    input.insert("input".into(), Value::bytes(vec![1; 8192]))?;
    call.input = Value::from(input);
    let mut subscription = service.subscribe(&token, None, call).await?;
    let mut finished = false;
    for _ in 0..4 {
        let event = runtime(receive(&mut subscription).await?)?;
        ensure!(kind(&event)? != "output");
        if kind(&event)? == "finished" {
            ensure!(
                event
                    .as_map()
                    .and_then(|map| map.get("outcome"))
                    .and_then(Value::as_str)
                    == Some("failed")
            );
            finished = true;
            break;
        }
    }
    ensure!(finished && probe.emitted.load(Ordering::SeqCst) == 0);
    Ok(())
}
