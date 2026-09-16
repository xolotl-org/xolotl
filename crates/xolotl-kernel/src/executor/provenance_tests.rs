use super::*;
use crate::{Bootstrap, Driver, DriverContext, DriverError, MethodSpec};
use anyhow::ensure;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use xolotl_graph::portable::{Expression as E, Program};
use xolotl_types::{Failure, MethodId, OutputMode, Path, Purity, TaintSource, TaintedValue};

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
    type Read<'a> = core::future::Ready<xolotl_state::StateResult<Option<TaintedValue>>>;

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
    let boot = Bootstrap::in_memory();
    let taint = protected()?;
    for fail_subscription in [true, false] {
        let port = Arc::new(FailedSignalState {
            inner: xolotl_state::InMemoryBackend::new(),
            taint: taint.clone(),
            fail_subscription,
        });
        let state = xolotl_state::Backend::new()
            .with_read(port.clone())
            .with_watch(port);
        let executor = boot.kernel.executor_for(boot.root).with_state(state);
        let wait = DoNode::wait_signal(Path::parse("state://signal/protected-failure")?);
        let output = executor.eval(&wait).await;
        ensure!(matches!(output.outcome, Outcome::Fail(_)));
        ensure!(output.taint == taint);
    }
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
            &[MethodSpec::unary_async("invoke", Purity::Pure)],
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
        let executor = boot.kernel.executor_for(boot.root);
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
        &[MethodSpec::unary_async("invoke", Purity::Pure)],
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
        &[MethodSpec::unary_async("invoke", Purity::Effectful).unprotected_input()],
        sink_driver.clone(),
    )?;
    let source = operation(source);
    let sink = operation(sink);
    let native_sink = sink.clone();
    let executor = boot
        .kernel
        .executor_for(boot.root)
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
            &[MethodSpec::unary_async("invoke", Purity::Pure)],
            driver.clone(),
        )?;
        let body = E::Invoke {
            operation: operation(source),
        };
        let waiting = E::Wait {
            wait: WaitSpec::Signal(Path::parse("state://signal/deadline")?),
        };
        let body = if fails {
            E::Catch {
                body: Box::new(body),
                recover: Box::new(waiting),
            }
        } else {
            body.then(waiting)
        };
        let program = Program::new(body).compile()?;
        let executor = boot
            .kernel
            .executor_for(boot.root)
            .with_deadline(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
        let mut run =
            Box::pin(executor.eval_program(&program, TaintedValue::pristine(Value::null())));
        ensure!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(
                run.as_mut(),
                cx
            )))
            .await
            .is_pending()
        );
        ensure!(driver.calls.load(Ordering::Relaxed) == 1);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let output = run.await;
        ensure!(
            output.outcome == Outcome::Fail(Failure::Timeout),
            "{output:?}"
        );
        ensure!(output.taint == taint, "{output:?}");
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn deadline_before_first_poll_preserves_input_without_running_the_program()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let taint = protected()?;
    let executor = boot
        .kernel
        .executor_for(boot.root)
        .with_deadline(tokio::time::Instant::now());
    let program = Program::new(E::Input).compile()?;
    let output = executor
        .eval_program(
            &program,
            TaintedValue::new(Value::integer(17), taint.clone()),
        )
        .await;
    ensure!(output.outcome == Outcome::Fail(Failure::Timeout));
    ensure!(output.taint == taint);
    ensure!(boot.kernel.facts.all_facts()?.is_empty());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn deadline_preserves_held_finally_result_and_drops_pending_cleanup() -> anyhow::Result<()> {
    for outcome in [
        Outcome::Done(Value::integer(17)),
        Outcome::Fail(Failure::policy("source", "protected failure")),
    ] {
        let boot = Bootstrap::in_memory();
        let taint = protected()?;
        let source = boot.register_effect(
            "effect://deadline/source",
            &[MethodSpec::unary_async("invoke", Purity::Pure)],
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
            &[MethodSpec::unary_async("invoke", Purity::Pure).finalize_allowed()],
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
        let executor = boot
            .kernel
            .executor_for(boot.root)
            .with_deadline(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
        let mut run =
            Box::pin(executor.eval_program(&program, TaintedValue::pristine(Value::null())));
        ensure!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(
                run.as_mut(),
                cx
            )))
            .await
            .is_pending()
        );
        ensure!(waiting.entered.load(Ordering::Relaxed));
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        let output = run.await;
        ensure!(output.outcome == Outcome::Fail(Failure::Timeout));
        ensure!(output.taint == taint);
        ensure!(waiting.dropped.load(Ordering::Relaxed));
    }
    Ok(())
}
