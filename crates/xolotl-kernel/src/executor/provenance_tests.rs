use super::*;
use crate::{Bootstrap, Driver, DriverContext, DriverError, MethodSpec};
use anyhow::{Context, ensure};
use std::{
    fmt::Debug,
    future::{Future, Ready, ready},
    num::NonZeroUsize,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use xolotl_graph::portable::{Expression as E, Program};
use xolotl_types::{Failure, MethodId, OutputMode, Path, Purity, TaintSource, TaintedValue};

// Fact and account work can yield before a driver or subscription is reached.
// Drive the evaluation to an observable milestone before advancing a paused
// clock or injecting an event; one initial poll no longer establishes either.
async fn drive_until<F: Future>(
    mut future: Pin<&mut F>,
    mut ready: impl FnMut() -> anyhow::Result<bool>,
) -> anyhow::Result<()>
where
    F::Output: Debug,
{
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if ready()? {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("evaluation did not reach expected event");
        }
        tokio::select! {
            result = future.as_mut() => anyhow::bail!("evaluation finished before expected event: {result:?}"),
            () = tokio::task::yield_now() => {},
        }
    }
}

struct ProtectedDriver {
    outcome: Outcome,
    taint: TaintSet,
    calls: AtomicUsize,
}

struct WaitingDriver {
    entered: AtomicBool,
    dropped: AtomicBool,
}

struct FailedSignalState {
    inner: xolotl_state::InMemoryBackend,
    taint: TaintSet,
    fail_subscription: bool,
}

impl xolotl_state::StateRead for FailedSignalState {
    type Read<'a> = core::future::Ready<xolotl_state::StateResult<xolotl_state::StateObservation>>;

    fn read_tainted<'a>(&'a self, _path: &'a Path) -> Self::Read<'a> {
        core::future::ready(Err(xolotl_state::StateFailure::new(
            xolotl_state::StateError::Backend("signal read rejected".into()),
            self.taint.clone(),
        )))
    }
}

impl xolotl_state::StateWatch for FailedSignalState {
    type Subscription = xolotl_state::StateStream;
    type Subscribe<'a> = core::future::Ready<xolotl_state::StateResult<Self::Subscription>>;

    fn subscribe<'a>(&'a self, path: &'a Path) -> Self::Subscribe<'a> {
        if self.fail_subscription {
            core::future::ready(Err(xolotl_state::StateFailure::new(
                xolotl_state::StateError::Backend("signal subscription rejected".into()),
                self.taint.clone(),
            )))
        } else {
            xolotl_state::StateWatch::subscribe(&self.inner, path)
        }
    }
}

#[tokio::test]
async fn signal_subscription_and_read_failures_preserve_observed_sources() -> anyhow::Result<()> {
    let taint = protected()?;
    for fail_subscription in [true, false] {
        let boot = Bootstrap::in_memory();
        let port = Arc::new(FailedSignalState {
            inner: xolotl_state::InMemoryBackend::new(),
            taint: taint.clone(),
            fail_subscription,
        });
        let state = xolotl_state::Backend::new()
            .with_read(port.clone())
            .with_watch(port.clone())
            .with_signal(port);
        super::signal_tests::install_signal_resource(&boot, state)?;
        let executor = boot.kernel().executor_for(boot.root());
        let wait = DoNode::wait_signal(Path::parse("state://signal/protected-failure")?);
        let output = executor.eval(&wait).await;
        ensure!(matches!(output.outcome, Outcome::Fail(_)));
        ensure!(output.taint == taint);
    }
    Ok(())
}

#[derive(Default)]
struct ScriptedSignalState {
    events: xolotl_state::host::WatchRegistry,
    current: parking_lot::Mutex<xolotl_state::StateObservation>,
}

impl xolotl_state::StateRead for ScriptedSignalState {
    type Read<'a> = Ready<xolotl_state::StateResult<xolotl_state::StateObservation>>;

    fn read_tainted<'a>(&'a self, _path: &'a Path) -> Self::Read<'a> {
        ready(Ok(self.current.lock().clone()))
    }
}

impl xolotl_state::StateWatch for ScriptedSignalState {
    type Subscription = xolotl_state::StateStream;
    type Subscribe<'a> = Ready<xolotl_state::StateResult<Self::Subscription>>;

    fn subscribe<'a>(&'a self, path: &'a Path) -> Self::Subscribe<'a> {
        ready(
            self.events
                .subscribe(path.clone(), NonZeroUsize::MIN.saturating_add(1)),
        )
    }
}

#[tokio::test]
async fn signal_delete_sources_survive_until_next_value() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let port = Arc::new(ScriptedSignalState::default());
    let state = xolotl_state::Backend::new().with_signal(port.clone());
    super::signal_tests::install_signal_resource(&boot, state)?;
    let executor = boot.kernel().executor_for(boot.root());
    let path = Path::parse("state://signal/protected-delete")?;
    let protected = TaintSet::of(TaintSource::Protected { path: path.clone() });
    let wait = DoNode::wait_signal(path.clone());
    let mut running = Box::pin(executor.eval(&wait));
    drive_until(running.as_mut(), || {
        Ok(!port.events.matching(&path).is_empty())
    })
    .await?;
    for event in [
        xolotl_state::StateEvent::Delete {
            path: path.clone(),
            taint: protected.clone(),
        },
        xolotl_state::StateEvent::Set {
            path: path.clone(),
            value: Value::integer(1),
            taint: TaintSet::pristine(),
        },
    ] {
        {
            let mut current = port.current.lock();
            xolotl_state::apply_history_event(&mut current, &event)?;
        }
        for sender in port.events.matching(&path) {
            drop(sender.send(event.clone()));
        }
    }
    let output = tokio::time::timeout(std::time::Duration::from_secs(1), running).await?;
    ensure!(output.outcome == Outcome::Done(Value::integer(1)));
    ensure!(output.taint == protected);
    Ok(())
}

struct DropFlag<'a>(&'a AtomicBool);

impl Drop for DropFlag<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

#[async_trait::async_trait]
impl Driver for WaitingDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if !ctx.taint.is_pristine() {
            return Err(DriverError::Other(
                "cleanup expected the pristine original input".into(),
            ));
        }
        let _guard = DropFlag(&self.dropped);
        self.entered.store(true, Ordering::Relaxed);
        std::future::pending().await
    }
}

#[async_trait::async_trait]
impl Driver for ProtectedDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(DriverOutput::new(self.outcome.clone()).with_taint(self.taint.clone()))
    }
}

fn protected() -> anyhow::Result<TaintSet> {
    Ok(TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/execution-result")?,
    }))
}

fn operation(target: ResourceName) -> OperationTemplate {
    OperationTemplate {
        target,
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    }
}

#[tokio::test]
async fn every_host_entry_preserves_success_and_failure_provenance() -> anyhow::Result<()> {
    for outcome in [
        Outcome::Done(Value::string("protected value".into())),
        Outcome::Fail(Failure::policy("source", "protected failure")),
    ] {
        let boot = Bootstrap::in_memory();
        let taint = protected()?;
        let target = boot.register_effect(
            "effect://result/source",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(ProtectedDriver {
                outcome: outcome.clone(),
                taint: taint.clone(),
                calls: AtomicUsize::new(0),
            }),
        )?;
        let operation = operation(target);
        let native = DoNode::op(operation.clone());
        let graph = compile_do(&native)?;
        let compiled = Program::new(E::Invoke { operation }).compile()?;
        let prepared = PreparedProgram::new(&compiled)?;
        let executor = boot.kernel().executor_for(boot.root());
        let mut buffers = ExecutionBuffers::default();
        for output in [
            executor.eval(&native).await,
            executor.eval_graph(&graph).await,
            executor.eval_graph_with_buffers(&graph, &mut buffers).await,
            executor
                .eval_program(&compiled, TaintedValue::pristine(Value::null()))
                .await,
            executor
                .eval_prepared(&prepared, TaintedValue::pristine(Value::null()))
                .await,
            executor
                .eval_prepared_with_buffers(
                    &prepared,
                    TaintedValue::pristine(Value::null()),
                    &mut buffers,
                )
                .await,
        ] {
            ensure!(output.outcome == outcome, "{output:?}");
            ensure!(output.taint == taint, "{output:?}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn protected_driver_failure_cannot_escape_through_native_or_portable_recovery()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let source = boot.register_effect(
        "effect://recovery/source",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(ProtectedDriver {
            outcome: Outcome::Fail(Failure::policy("source", "secret in error message")),
            taint: protected()?,
            calls: AtomicUsize::new(0),
        }),
    )?;
    let sink_driver = Arc::new(ProtectedDriver {
        outcome: Outcome::Done(Value::null()),
        taint: TaintSet::pristine(),
        calls: AtomicUsize::new(0),
    });
    let sink = boot.register_effect(
        "effect://recovery/outbound",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )
        .unprotected_input()],
        sink_driver.clone(),
    )?;
    let source = operation(source);
    let sink = operation(sink);
    let native_sink = sink.clone();
    let executor = boot
        .kernel()
        .executor_for(boot.root())
        .with_steps(StepModule::single("recover", move |error, _| {
            DoNode::op(OperationTemplate {
                literal_input: Some(error),
                ..native_sink.clone()
            })
        })?);
    let native = DoNode::op(source.clone()).or_else(StepRef::new("recover"));
    let portable = Program::new(E::Catch {
        body: Box::new(E::Invoke { operation: source }),
        recover: Box::new(E::Invoke { operation: sink }),
    })
    .compile()?;
    for output in [
        executor.eval(&native).await,
        executor
            .eval_program(&portable, TaintedValue::pristine(Value::null()))
            .await,
    ] {
        ensure!(
            matches!(
                output.outcome,
                Outcome::Fail(Failure::PolicyViolation { ref policy, .. }) if policy == "taint"
            ),
            "{output:?}"
        );
        ensure!(output.taint.has_protected());
    }
    ensure!(sink_driver.calls.load(Ordering::Relaxed) == 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn deadline_retains_live_success_and_recovery_control() -> anyhow::Result<()> {
    for fails in [false, true] {
        let boot = Bootstrap::in_memory();
        let taint = protected()?;
        let driver = Arc::new(ProtectedDriver {
            outcome: if fails {
                Outcome::Fail(Failure::policy("source", "protected failure"))
            } else {
                Outcome::Done(Value::integer(17))
            },
            taint: taint.clone(),
            calls: AtomicUsize::new(0),
        });
        let source = boot.register_effect(
            "effect://deadline/source",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            driver.clone(),
        )?;
        let body = E::Invoke {
            operation: operation(source),
        };
        let signal_path = Path::parse("state://signal/deadline")?;
        let signals = Arc::new(ScriptedSignalState::default());
        let waiting = E::Wait {
            wait: WaitSpec::Signal(signal_path.clone()),
        };
        super::signal_tests::install_signal_resource(
            &boot,
            xolotl_state::Backend::new().with_signal(signals.clone()),
        )?;
        let body = if fails {
            E::Catch {
                body: Box::new(body),
                recover: Box::new(waiting),
            }
        } else {
            body.then(waiting)
        };
        let program = Program::new(body).compile()?;
        let executor = boot.kernel().executor_for(boot.root()).with_deadline(
            boot.kernel()
                .host_runtime()
                .deadline_after(std::time::Duration::from_secs(1))
                .context("one-second deadline")?,
        )?;
        let mut run =
            Box::pin(executor.eval_program(&program, TaintedValue::pristine(Value::null())));
        drive_until(run.as_mut(), || {
            Ok(!signals.events.matching(&signal_path).is_empty())
        })
        .await?;
        ensure!(driver.calls.load(Ordering::Relaxed) == 1);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let output = run.await;
        ensure!(
            output.outcome == Outcome::Fail(Failure::Timeout),
            "{output:?}"
        );
        ensure!(output.unresolved_operations.operation_ids.is_empty());
        ensure!(output.taint == taint, "{output:?}");
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn deadline_before_first_poll_preserves_input_without_running_the_program()
-> anyhow::Result<()> {
    let boot = crate::fact::testing::observing_bootstrap();
    let taint = protected()?;
    let executor = boot
        .kernel()
        .executor_for(boot.root())
        .with_deadline(boot.kernel().host_runtime().now())?;
    let program = Program::new(E::Input).compile()?;
    let output = executor
        .eval_program(
            &program,
            TaintedValue::new(Value::integer(17), taint.clone()),
        )
        .await;
    ensure!(output.outcome == Outcome::Fail(Failure::Timeout));
    ensure!(output.taint == taint);
    ensure!(boot.kernel().facts().all_facts()?.is_empty());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn deadline_reports_pending_cleanup_and_preserves_held_taint() -> anyhow::Result<()> {
    for outcome in [
        Outcome::Done(Value::integer(17)),
        Outcome::Fail(Failure::policy("source", "protected failure")),
    ] {
        let boot = Bootstrap::in_memory();
        let taint = protected()?;
        let source = boot.register_effect(
            "effect://deadline/source",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(ProtectedDriver {
                outcome,
                taint: taint.clone(),
                calls: AtomicUsize::new(0),
            }),
        )?;
        let waiting = Arc::new(WaitingDriver {
            entered: AtomicBool::new(false),
            dropped: AtomicBool::new(false),
        });
        let target = boot.register_effect(
            "effect://deadline/cleanup",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )
            .finalize_allowed()],
            waiting.clone(),
        )?;
        let program = Program::new(
            E::Invoke {
                operation: operation(source),
            }
            .finally(E::Invoke {
                operation: operation(target),
            }),
        )
        .compile()?;
        let executor = boot.kernel().executor_for(boot.root()).with_deadline(
            boot.kernel()
                .host_runtime()
                .deadline_after(std::time::Duration::from_secs(1))
                .context("one-second deadline")?,
        )?;
        let mut run =
            Box::pin(executor.eval_program(&program, TaintedValue::pristine(Value::null())));
        drive_until(run.as_mut(), || Ok(waiting.entered.load(Ordering::Relaxed))).await?;
        ensure!(waiting.entered.load(Ordering::Relaxed));
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let output = run.await;
        ensure!(
            matches!(
                &output.outcome,
                Outcome::Fail(Failure::OutcomeUnknown {
                    operation_ids,
                    reason,
                }) if operation_ids.len() == 1 && reason == "deadline_exceeded"
            ),
            "{output:?}"
        );
        ensure!(output.taint == taint);
        ensure!(waiting.dropped.load(Ordering::Relaxed));
    }
    Ok(())
}

struct PendingIdsDriver {
    started: parking_lot::Mutex<Vec<OperationId>>,
    dropped: AtomicUsize,
}

struct CountDrop<'a>(&'a AtomicUsize);

impl Drop for CountDrop<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Driver for PendingIdsDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.started.lock().push(ctx.operation_id.ok_or_else(|| {
            DriverError::Other("Kernel operation is missing its causal ID".into())
        })?);
        let _dropped = CountDrop(&self.dropped);
        std::future::pending().await
    }
}

#[tokio::test(start_paused = true)]
async fn deadline_identifies_every_concurrent_pending_operation() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let driver = Arc::new(PendingIdsDriver {
        started: parking_lot::Mutex::new(Vec::new()),
        dropped: AtomicUsize::new(0),
    });
    let target = boot.register_effect(
        "effect://deadline/concurrent",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        driver.clone(),
    )?;
    let program = Program::new(
        E::Invoke {
            operation: operation(target.clone()),
        }
        .both(E::Invoke {
            operation: operation(target),
        }),
    )
    .compile()?;
    let executor = boot.kernel().executor_for(boot.root()).with_deadline(
        boot.kernel()
            .host_runtime()
            .deadline_after(std::time::Duration::from_secs(1))
            .context("one-second deadline")?,
    )?;
    let mut run = Box::pin(executor.eval_program(&program, TaintedValue::pristine(Value::null())));
    drive_until(run.as_mut(), || Ok(driver.started.lock().len() == 2)).await?;
    let mut expected: Vec<_> = driver
        .started
        .lock()
        .iter()
        .map(ToString::to_string)
        .collect();
    ensure!(expected.len() == 2, "both operations must reach the driver");
    expected.sort_unstable();
    expected.dedup();
    ensure!(expected.len() == 2, "parallel requests need distinct IDs");

    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    let output = run.await;
    ensure!(
        matches!(
            &output.outcome,
            Outcome::Fail(Failure::OutcomeUnknown {
                operation_ids,
                reason,
            }) if operation_ids == &expected && reason == "deadline_exceeded"
        ),
        "{output:?}"
    );
    ensure!(driver.dropped.load(Ordering::SeqCst) == 2);
    Ok(())
}

struct AfterPendingDriver {
    pending: Arc<PendingIdsDriver>,
}

#[async_trait::async_trait]
impl Driver for AfterPendingDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        while self.pending.started.lock().is_empty() {
            tokio::task::yield_now().await;
        }
        Ok(DriverOutput::new(Outcome::Done(Value::integer(42))))
    }
}

#[tokio::test]
async fn successful_race_only_retains_cancelled_effect_identity() -> anyhow::Result<()> {
    for observation in [false, true] {
        let boot = Bootstrap::in_memory();
        let pending = Arc::new(PendingIdsDriver {
            started: parking_lot::Mutex::new(Vec::new()),
            dropped: AtomicUsize::new(0),
        });
        let loser_method = MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            if observation {
                Purity::Pure
            } else {
                Purity::Effectful
            },
            MethodSpec::UNARY_ASYNC,
        );
        let loser_method = if observation {
            loser_method.observes_external()
        } else {
            loser_method
        };
        let winner_method = [MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )];
        let loser =
            boot.register_effect("effect://race/loser", &[loser_method], pending.clone())?;
        let winner = boot.register_effect(
            "effect://race/winner",
            &winner_method,
            Arc::new(AfterPendingDriver {
                pending: pending.clone(),
            }),
        )?;
        let program = Program::new(
            E::Invoke {
                operation: operation(loser),
            }
            .race(E::Invoke {
                operation: operation(winner),
            }),
        )
        .compile()?;
        let output = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            boot.kernel()
                .executor_for(boot.root())
                .eval_program(&program, TaintedValue::pristine(Value::null())),
        )
        .await?;
        let mut expected = pending
            .started
            .lock()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        ensure!(expected.len() == 1, "loser did not reach its driver");
        if observation {
            expected.clear();
        }
        ensure!(
            output.outcome == Outcome::Done(Value::integer(42)),
            "{output:?}"
        );
        ensure!(
            output.unresolved_operations.operation_ids == expected,
            "{output:?}"
        );
        ensure!(!output.unresolved_operations.identities_incomplete);
        ensure!(pending.dropped.load(Ordering::SeqCst) == 1);
    }
    Ok(())
}

#[tokio::test]
async fn successful_recovery_retains_driver_unknown_identity() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let target = boot.register_effect(
        "effect://recovery/unknown",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(ProtectedDriver {
            outcome: Outcome::Fail(Failure::OutcomeUnknown {
                operation_ids: vec!["provider-ticket-42".into()],
                reason: "transport reply lost".into(),
            }),
            taint: TaintSet::pristine(),
            calls: AtomicUsize::new(0),
        }),
    )?;
    let program = Program::new(E::Catch {
        body: Box::new(E::Invoke {
            operation: operation(target),
        }),
        recover: Box::new(E::literal(42)),
    })
    .compile()?;
    let output = boot
        .kernel()
        .executor_for(boot.root())
        .eval_program(&program, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(42)),
        "{output:?}"
    );
    ensure!(
        output.unresolved_operations.operation_ids == ["provider-ticket-42"],
        "{output:?}"
    );
    ensure!(!output.unresolved_operations.identities_incomplete);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn deadline_after_caught_unknown_effect_remains_outcome_unknown() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let driver = Arc::new(ProtectedDriver {
        outcome: Outcome::Fail(Failure::OutcomeUnknown {
            operation_ids: vec!["provider-ticket-42".into()],
            reason: "transport reply lost".into(),
        }),
        taint: TaintSet::pristine(),
        calls: AtomicUsize::new(0),
    });
    let target = boot.register_effect(
        "effect://deadline/unknown",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        driver.clone(),
    )?;
    let signal_path = Path::parse("state://signal/caught-unknown")?;
    let signals = Arc::new(ScriptedSignalState::default());
    super::signal_tests::install_signal_resource(
        &boot,
        xolotl_state::Backend::new().with_signal(signals.clone()),
    )?;
    let program = Program::new(E::Catch {
        body: Box::new(E::Invoke {
            operation: operation(target),
        }),
        recover: Box::new(E::Wait {
            wait: WaitSpec::Signal(signal_path.clone()),
        }),
    })
    .compile()?;
    let deadline = boot
        .kernel()
        .host_runtime()
        .deadline_after(std::time::Duration::from_secs(1))
        .context("one-second deadline")?;
    let executor = boot
        .kernel()
        .executor_for(boot.root())
        .with_deadline(deadline)?;
    let mut run = Box::pin(executor.eval_program(&program, TaintedValue::pristine(Value::null())));
    drive_until(run.as_mut(), || {
        Ok(!signals.events.matching(&signal_path).is_empty())
    })
    .await?;
    ensure!(driver.calls.load(Ordering::Relaxed) == 1);
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    let output = run.await;
    ensure!(
        matches!(
            &output.outcome,
            Outcome::Fail(Failure::OutcomeUnknown {
                operation_ids,
                reason,
            }) if operation_ids == &["provider-ticket-42"] && reason == "deadline_exceeded"
        ),
        "{output:?}"
    );
    ensure!(
        output.unresolved_operations.operation_ids == ["provider-ticket-42"],
        "{output:?}"
    );
    Ok(())
}
