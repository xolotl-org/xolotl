use super::*;
use crate::bootstrap::Bootstrap;
use crate::driver::{Driver, DriverContext, DriverError, DriverPlan};
use crate::handle::Handle;
use crate::host::{
    AbortTask, HostClock, HostRuntime, TaskSpawnError, TaskSpawner, TokioBlockingSpawner,
};
use anyhow::{Context, ensure};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use xolotl_state::{
    Backend, InMemoryBackend, StateMutation, StateResult, StateWrite, StateWriteExt,
};
use xolotl_types::{
    DriverId, HandleId, IdentityRef, MethodBitmap, MethodContract, MethodId, NodeId, ResourceId,
    RightFlags, Rights, TaintSource,
};

mod state;
pub(crate) use state::state_host;
use state::{
    PrepareGate, PublishedOutcomes, state_host_with_observer, state_host_with_prepare_gate,
};

#[derive(Default)]
struct ControlledDriver {
    entered: Notify,
    release: Notify,
    calls: AtomicUsize,
    dropped: AtomicUsize,
    outcome_unknown: AtomicBool,
    context: parking_lot::Mutex<Option<(IdentityRef, ProcessId)>>,
}

struct DriverRun<'a>(&'a AtomicUsize);

impl Drop for DriverRun<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Driver for ControlledDriver {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<crate::DriverOutput, DriverError> {
        *self.context.lock() = Some((ctx.acting, ctx.caller));
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _running = DriverRun(&self.dropped);
        self.entered.notify_one();
        self.release.notified().await;
        if self.outcome_unknown.load(Ordering::SeqCst) {
            return Err(DriverError::OutcomeUnknown {
                operation_id: "provider-ticket-42".into(),
                reason: "remote_ack_lost".into(),
            });
        }
        Ok(crate::DriverOutput::new(Outcome::Done(input))
            .with_taint(TaintSet::of(TaintSource::ModelOutput)))
    }
}

struct Fixture {
    boot: Bootstrap,
    driver: Arc<ControlledDriver>,
    op: Operation,
    published: PublishedOutcomes,
    record: bool,
}

struct Child {
    process: ProcessId,
    status_path: Path,
    outcome_path: Path,
}

struct GatedClock;

impl HostClock for GatedClock {
    fn monotonic_now(&self) -> std::time::Instant {
        tokio::time::Instant::now().into_std()
    }

    fn unix_millis(&self) -> i64 {
        0
    }

    fn sleep_until(
        &self,
        deadline: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep_until(tokio::time::Instant::from_std(
            deadline,
        )))
    }
}

struct GatedTasks(tokio::sync::watch::Receiver<bool>);

struct GatedAbort(tokio::task::AbortHandle);

impl AbortTask for GatedAbort {
    fn abort(&self) {
        self.0.abort();
    }
}

impl TaskSpawner for GatedTasks {
    fn spawn(
        &self,
        future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>,
    ) -> Result<Arc<dyn AbortTask>, TaskSpawnError> {
        let mut open = self.0.clone();
        let task = tokio::spawn(async move {
            while !*open.borrow_and_update() {
                if open.changed().await.is_err() {
                    return;
                }
            }
            future.await;
        });
        Ok(Arc::new(GatedAbort(task.abort_handle())))
    }
}

#[tokio::test]
async fn child_identity_is_its_own_scope_not_the_parent_caller() -> anyhow::Result<()> {
    let mut fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
    let acting = fixture
        .boot
        .kernel()
        .identities()
        .resolve_or_register(&Path::parse("identity://async-process/caller")?)?;
    let mut handle = fixture
        .boot
        .kernel()
        .handles()
        .get(fixture.op.handle)
        .context("missing handle")?;
    handle.acting = acting;
    fixture.op.handle = fixture.boot.kernel().handles().insert(handle)?;
    fixture.op.acting = acting;
    let child = fixture.start().await?;
    fixture.wait_entered().await?;
    fixture.driver.release.notify_one();
    wait_published(&fixture, &child, "completed").await?;
    ensure!(*fixture.driver.context.lock() == Some((acting, child.process)));
    ensure!(fixture.boot.kernel().processes().identity(child.process) == Some(acting));
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 1);
    ensure!(
        fixture.published_output(child.process)?.outcome == Outcome::Done(fixture.op.input.clone())
    );
    Ok(())
}

#[tokio::test]
async fn capacity_rejection_does_not_dispatch_or_retain_child_handles() -> anyhow::Result<()> {
    let fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
    fixture
        .boot
        .kernel()
        .processes()
        .set_capacity(std::num::NonZeroUsize::new(2))?;
    let handles = fixture.boot.kernel().handles().read().len();
    let outcome = fixture.execute().await.outcome;
    ensure!(
        matches!(outcome, Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "process_admission"),
        "capacity exhaustion did not surface as admission failure: {outcome:?}"
    );
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    ensure!(fixture.boot.kernel().handles().read().len() == handles);
    ensure!(fixture.boot.kernel().processes().len() == 2);
    ensure!(
        fixture
            .boot
            .kernel()
            .processes()
            .children_of(fixture.op.process)
            .is_empty()
    );
    Ok(())
}

impl Fixture {
    fn new(state: xolotl_state::Backend) -> anyhow::Result<Self> {
        Self::with_facts(state, FactSink::in_memory().0)
    }

    fn with_facts(state: xolotl_state::Backend, facts: FactSink) -> anyhow::Result<Self> {
        Self::with_contract(
            state,
            facts,
            MethodContract::new(
                0,
                xolotl_types::ReplayClass::Deterministic,
                OutputModeSet::ASYNC_PROCESS,
            ),
        )
    }

    fn effectful(state: xolotl_state::Backend) -> anyhow::Result<Self> {
        Self::with_effectful_facts(state, FactSink::in_memory().0)
    }

    fn with_effectful_facts(state: xolotl_state::Backend, facts: FactSink) -> anyhow::Result<Self> {
        Self::with_contract(
            state,
            facts,
            MethodContract::new(
                0,
                xolotl_types::ReplayClass::NonIdempotentEffect,
                OutputModeSet::ASYNC_PROCESS,
            ),
        )
    }

    fn with_contract(
        state: xolotl_state::Backend,
        facts: FactSink,
        contract: MethodContract,
    ) -> anyhow::Result<Self> {
        let published = PublishedOutcomes::default();
        let host = state_host_with_observer(state.clone(), published.clone());
        Self::with_host(state, facts, contract, host, published)
    }

    fn with_host(
        state: xolotl_state::Backend,
        facts: FactSink,
        contract: MethodContract,
        host: Arc<dyn crate::host::async_process::AsyncProcessHost>,
        published: PublishedOutcomes,
    ) -> anyhow::Result<Self> {
        Self::with_host_runtime(state, facts, contract, host, published, None)
    }

    fn with_host_runtime(
        state: xolotl_state::Backend,
        facts: FactSink,
        contract: MethodContract,
        host: Arc<dyn crate::host::async_process::AsyncProcessHost>,
        published: PublishedOutcomes,
        runtime: Option<HostRuntime>,
    ) -> anyhow::Result<Self> {
        Self::with_host_runtime_and_ids(state, facts, contract, host, published, runtime, None)
    }

    fn with_host_runtime_and_ids(
        state: xolotl_state::Backend,
        facts: FactSink,
        contract: MethodContract,
        host: Arc<dyn crate::host::async_process::AsyncProcessHost>,
        published: PublishedOutcomes,
        runtime: Option<HostRuntime>,
        ids: Option<crate::ExecutionIds>,
    ) -> anyhow::Result<Self> {
        let mut builder = crate::KernelBuilder::new(state)
            .with_fact_sink(facts)
            .with_async_process_host(host);
        if let Some(runtime) = runtime {
            builder = builder.with_host_runtime(runtime);
        }
        if let Some(ids) = ids {
            builder = builder.with_execution_ids(ids);
        }
        let boot = Bootstrap::from_kernel(builder.build());
        let process = boot
            .request_under(boot.root(), IdentityRef::ROOT, &[])?
            .detach();
        let driver = Arc::new(ControlledDriver::default());
        let method = MethodId::new(7);
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(method, contract, driver.clone());
        let handle = boot.kernel().handles().write().insert(Handle {
            open_verb: "perform".into(),
            id: HandleId::new(0, 0),
            process,
            acting: IdentityRef::ROOT,
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::SPAWN_WITH),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            bound_path: None,
        })?;
        let execution = boot.kernel().execution_ids().allocate()?;
        let op = Operation {
            id: xolotl_types::OperationId::new(
                process,
                execution,
                xolotl_types::InvocationId::new(0),
                NodeId::new(1),
                0,
            ),
            process,
            acting: IdentityRef::ROOT,
            handle,
            method,
            input: Value::string("result".into()),
            taint: TaintSet::author(),
            output: OutputMode::AsyncProcess,
        };
        Ok(Self {
            boot,
            driver,
            op,
            published,
            record: false,
        })
    }

    async fn execute(&self) -> DriverOutput {
        let result = self
            .boot
            .kernel()
            .data_plane()
            .execute(
                &self.op,
                crate::InvocationOptions {
                    caller_identity: None,
                    now_millis: 0,
                    record: self.record,
                },
            )
            .await;
        assert!(
            result.completion_error.is_none(),
            "{:?}",
            result.completion_error
        );
        result.output
    }

    async fn start(&self) -> anyhow::Result<Child> {
        let Outcome::Done(value) = self.execute().await.outcome else {
            anyhow::bail!("async process did not return its resource");
        };
        let value = value.as_map().context("resource is not a map")?;
        let process = u64::try_from(
            value
                .get("process")
                .and_then(Value::as_int)
                .context("missing child id")?,
        )?;
        Ok(Child {
            process: ProcessId::new(process),
            status_path: Path::parse(
                value
                    .get("status_path")
                    .and_then(Value::as_str)
                    .context("missing status path")?,
            )?,
            outcome_path: Path::parse(
                value
                    .get("outcome_path")
                    .and_then(Value::as_str)
                    .context("missing outcome path")?,
            )?,
        })
    }

    async fn wait_entered(&self) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(1), self.driver.entered.notified()).await?;
        Ok(())
    }

    fn published_output(&self, process: ProcessId) -> anyhow::Result<ExecutionOutput> {
        self.published
            .lock()
            .get(&process)
            .cloned()
            .context("missing published child outcome")
    }
}

async fn wait_until(mut ready: impl FnMut() -> bool) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(1), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

async fn wait_published(fixture: &Fixture, child: &Child, phase: &str) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let value = fixture
                .boot
                .kernel()
                .state()
                .read(&child.status_path)
                .await?;
            if value
                .as_ref()
                .and_then(Value::as_map)
                .and_then(|value| value.get("phase"))
                .and_then(Value::as_str)
                == Some(phase)
                && fixture
                    .boot
                    .kernel()
                    .processes()
                    .pending_cleanup()
                    .is_empty()
            {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn failed_child_observation_keeps_known_result_and_cleanup_does_not_repeat_the_driver()
-> anyhow::Result<()> {
    let faults = Arc::new(crate::fact::testing::CompletionFaults::default());
    let mut fixture = Fixture::with_facts(
        InMemoryBackend::new().into_backend(),
        FactSink::new(faults.clone()),
    )?;
    fixture.record = true;
    let child = fixture.start().await?;
    fixture.wait_entered().await?;
    faults.reject_write.store(true, Ordering::SeqCst);
    fixture.driver.release.notify_one();
    wait_until(|| {
        fixture
            .boot
            .kernel()
            .processes()
            .finalization_outcome(child.process)
            .is_some()
    })
    .await?;
    let retained = fixture
        .boot
        .kernel()
        .processes()
        .finalization_outcome(child.process)
        .context("missing retained failure")?;
    ensure!(retained.outcome == Outcome::Done(fixture.op.input.clone()));
    ensure!(retained.taint == TaintSet::of(TaintSource::ModelOutput).merged(&fixture.op.taint));
    ensure!(retained.unresolved_operations.is_empty());
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 1);
    ensure!(fixture.driver.dropped.load(Ordering::SeqCst) == 1);
    faults.reject_write.store(false, Ordering::SeqCst);
    let report = fixture.boot.drain_cleanup().await;
    ensure!(report.failures.is_empty());
    wait_published(&fixture, &child, "completed").await?;
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 1);
    let pending = fixture
        .boot
        .kernel()
        .facts()
        .facts_of(child.process)?
        .into_iter()
        .filter(|fact| !fact.is_complete())
        .count();
    ensure!(
        pending == 1,
        "selected observation remains pending after its completion write is rejected"
    );
    Ok(())
}

fn child_operation_id(fixture: &Fixture, process: ProcessId) -> String {
    xolotl_types::OperationId {
        process,
        ..fixture.op.id
    }
    .to_string()
}

#[tokio::test]
async fn cancellation_drops_the_running_driver_and_publishes_the_terminal_outcome()
-> anyhow::Result<()> {
    for force in [false, true] {
        let fixture = Fixture::effectful(InMemoryBackend::new().into_backend())?;
        let child = fixture.start().await?;
        fixture.wait_entered().await?;
        if force {
            fixture.boot.finalize_process(fixture.op.process).await?;
        } else {
            ensure!(fixture.boot.cancel_process(child.process)?);
        }
        wait_published(&fixture, &child, "cancelled").await?;
        ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 1);
        ensure!(fixture.driver.dropped.load(Ordering::SeqCst) == 1);
        ensure!(fixture.boot.kernel().handles().read().len() == usize::from(!force));
        let retained = fixture.published_output(child.process)?;
        let child_id = child_operation_id(&fixture, child.process);
        ensure!(retained.unresolved_operations.operation_ids == [child_id.as_str()]);
        let expected = if force {
            Outcome::Fail(Failure::OutcomeUnknown {
                operation_ids: vec![child_id],
                reason: "task_aborted_after_dispatch".into(),
            })
        } else {
            Outcome::Fail(Failure::Cancelled)
        };
        ensure!(retained.outcome == expected);
        ensure!(
            fixture
                .boot
                .kernel()
                .state()
                .read(&child.outcome_path)
                .await?
                == Some(outcome_to_value(&expected))
        );
        ensure!(
            fixture
                .boot
                .kernel()
                .processes()
                .pending_cleanup()
                .is_empty()
        );
    }
    Ok(())
}

#[tokio::test]
async fn aborting_a_dispatched_child_retains_unknown_effect_with_cancelled_status()
-> anyhow::Result<()> {
    let fixture = Fixture::effectful(InMemoryBackend::new().into_backend())?;
    let child = fixture.start().await?;
    fixture.wait_entered().await?;
    ensure!(fixture.boot.kernel().processes().abort_task(child.process));
    wait_until(|| {
        fixture
            .boot
            .kernel()
            .processes()
            .pending_cleanup()
            .contains(&child.process)
    })
    .await?;
    let report = fixture.boot.drain_cleanup().await;
    ensure!(report.failures.is_empty() && report.completed == 1);
    wait_published(&fixture, &child, "cancelled").await?;
    let retained = fixture.published_output(child.process)?;
    let child_id = child_operation_id(&fixture, child.process);
    ensure!(matches!(
        &retained.outcome,
        Outcome::Fail(Failure::OutcomeUnknown { operation_ids, reason })
            if operation_ids == &[child_id.as_str()] && reason == "task_aborted_after_dispatch"
    ));
    ensure!(retained.unresolved_operations.operation_ids == [child_id]);
    ensure!(fixture.driver.dropped.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn deterministic_child_cancellation_does_not_infer_an_external_effect() -> anyhow::Result<()>
{
    for force in [false, true] {
        let fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
        let child = fixture.start().await?;
        fixture.wait_entered().await?;
        if force {
            fixture.boot.finalize_process(fixture.op.process).await?;
        } else {
            ensure!(fixture.boot.cancel_process(child.process)?);
        }
        wait_published(&fixture, &child, "cancelled").await?;
        if force {
            ensure!(fixture.published.lock().get(&child.process).is_none());
            ensure!(
                fixture
                    .boot
                    .kernel()
                    .state()
                    .read(&child.outcome_path)
                    .await?
                    == Some(Value::null())
            );
        } else {
            let retained = fixture.published_output(child.process)?;
            ensure!(retained.outcome == Outcome::Fail(Failure::Cancelled));
            ensure!(retained.unresolved_operations.is_empty());
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_during_host_preparation_has_no_unresolved_child_operation()
-> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let gate = Arc::new(PrepareGate::default());
    let published = PublishedOutcomes::default();
    let fixture = Fixture::with_host(
        state.clone(),
        FactSink::in_memory().0,
        MethodContract::new(
            0,
            xolotl_types::ReplayClass::Deterministic,
            OutputModeSet::ASYNC_PROCESS,
        ),
        state_host_with_prepare_gate(state, gate.clone(), published.clone()),
        published,
    )?;
    let child = fixture.start().await?;
    tokio::time::timeout(Duration::from_secs(1), gate.entered.notified()).await?;
    ensure!(fixture.boot.cancel_process(child.process)?);
    wait_published(&fixture, &child, "cancelled").await?;
    let retained = fixture.published_output(child.process)?;
    ensure!(retained.unresolved_operations.is_empty());
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn child_outcome_unknown_retains_the_provider_identity() -> anyhow::Result<()> {
    let fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
    let child = fixture.start().await?;
    fixture.wait_entered().await?;
    fixture.driver.outcome_unknown.store(true, Ordering::SeqCst);
    fixture.driver.release.notify_one();
    wait_published(&fixture, &child, "failed").await?;
    let retained = fixture.published_output(child.process)?;
    ensure!(matches!(
        &retained.outcome,
        Outcome::Fail(Failure::OutcomeUnknown { operation_ids, .. })
            if operation_ids == &["provider-ticket-42"]
    ));
    ensure!(retained.unresolved_operations.operation_ids == ["provider-ticket-42"]);
    Ok(())
}

#[tokio::test]
async fn child_observation_failure_keeps_only_the_actual_provider_unknown_identity()
-> anyhow::Result<()> {
    let faults = Arc::new(crate::fact::testing::CompletionFaults::default());
    let mut fixture = Fixture::with_effectful_facts(
        InMemoryBackend::new().into_backend(),
        FactSink::new(faults.clone()),
    )?;
    fixture.record = true;
    let child = fixture.start().await?;
    fixture.wait_entered().await?;
    fixture.driver.outcome_unknown.store(true, Ordering::SeqCst);
    faults.reject_write.store(true, Ordering::SeqCst);
    fixture.driver.release.notify_one();
    wait_until(|| {
        fixture
            .boot
            .kernel()
            .processes()
            .finalization_outcome(child.process)
            .is_some()
    })
    .await?;
    let retained = fixture
        .boot
        .kernel()
        .processes()
        .finalization_outcome(child.process)
        .context("missing unconfirmed child outcome")?;
    ensure!(matches!(
        &retained.outcome,
        Outcome::Fail(Failure::OutcomeUnknown { operation_ids, .. })
            if operation_ids == &["provider-ticket-42"]
    ));
    ensure!(retained.unresolved_operations.operation_ids == ["provider-ticket-42"]);
    faults.reject_write.store(false, Ordering::SeqCst);
    ensure!(fixture.boot.drain_cleanup().await.failures.is_empty());
    wait_published(&fixture, &child, "failed").await?;
    Ok(())
}

#[tokio::test]
async fn abort_before_the_first_poll_retains_cleanup_without_dispatching() -> anyhow::Result<()> {
    let fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
    let child = fixture.start().await?;
    ensure!(fixture.boot.kernel().processes().abort_task(child.process));
    wait_until(|| {
        fixture
            .boot
            .kernel()
            .processes()
            .pending_cleanup()
            .contains(&child.process)
    })
    .await?;
    let report = fixture.boot.drain_cleanup().await;
    ensure!(report.failures.is_empty() && report.completed == 1);
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    ensure!(fixture.boot.kernel().handles().read().len() == 1);
    ensure!(
        fixture.boot.kernel().processes().status(child.process) == Some(ProcessStatus::Cancelled)
    );
    ensure!(
        fixture
            .boot
            .kernel()
            .state()
            .read(&child.outcome_path)
            .await?
            == Some(Value::null()),
        "an aborted body has no observed outcome"
    );
    ensure!(fixture.published.lock().get(&child.process).is_none());
    ensure!(
        fixture
            .boot
            .kernel()
            .facts()
            .facts_of(child.process)?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn finishing_the_parent_request_keeps_the_async_result_alive() -> anyhow::Result<()> {
    let fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
    let child = fixture.start().await?;
    fixture.wait_entered().await?;
    fixture
        .boot
        .finish_request_process(
            fixture.op.process,
            &xolotl_types::ExecutionOutput::new(
                Outcome::Done(Value::null()),
                xolotl_types::TaintSet::pristine(),
            ),
        )
        .await?;
    ensure!(
        fixture.boot.kernel().processes().status(child.process) == Some(ProcessStatus::Running)
    );
    ensure!(fixture.driver.dropped.load(Ordering::SeqCst) == 0);
    fixture.driver.release.notify_one();
    wait_published(&fixture, &child, "completed").await?;
    let output = fixture
        .boot
        .kernel()
        .state()
        .read_tainted(&child.outcome_path)
        .await?;
    let output_value = output.value.clone().context("missing async output")?;
    ensure!(output_value == outcome_to_value(&Outcome::Done(fixture.op.input.clone())));
    ensure!(output.taint == TaintSet::of(TaintSource::ModelOutput).merged(&fixture.op.taint));
    ensure!(fixture.boot.kernel().handles().read().is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn parent_completion_before_the_child_first_poll_preserves_delegated_authority_and_budget()
-> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let published = PublishedOutcomes::default();
    let host = state_host_with_observer(state.clone(), published.clone());
    let (release, gate) = tokio::sync::watch::channel(false);
    let runtime = HostRuntime::new(
        Arc::new(GatedClock),
        Arc::new(GatedTasks(gate)),
        Arc::new(TokioBlockingSpawner::default()),
    );
    let fixture = Fixture::with_host_runtime(
        state,
        FactSink::in_memory().0,
        MethodContract {
            cost: xolotl_types::CostModel {
                flat_micro_usd: 7,
                ..xolotl_types::CostModel::FREE
            },
            ..MethodContract::new(
                0,
                xolotl_types::ReplayClass::Deterministic,
                OutputModeSet::ASYNC_PROCESS,
            )
        },
        host,
        published,
        Some(runtime),
    )?;
    ensure!(
        fixture
            .boot
            .kernel()
            .processes()
            .set_budget_spec(
                fixture.op.process,
                xolotl_types::BudgetSpec {
                    max_micro_usd: Some(7),
                    max_inflight_ops: Some(1),
                    ..xolotl_types::BudgetSpec::default()
                }
            )
            .is_ok()
    );
    let child = fixture.start().await?;
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    let created_budget = fixture
        .boot
        .kernel()
        .processes()
        .budget_mut(fixture.op.process, |budget| budget.clone())
        .context("missing parent account")?;
    ensure!(created_budget.spent_micro_usd == 0 && created_budget.inflight_ops == 0);
    let outcome =
        xolotl_types::ExecutionOutput::new(Outcome::Done(Value::null()), TaintSet::pristine());
    fixture
        .boot
        .finish_request_process(fixture.op.process, &outcome)
        .await?;
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    ensure!(
        fixture
            .boot
            .kernel()
            .handles()
            .read()
            .get(fixture.op.handle)
            .is_none()
    );

    release.send(true)?;
    fixture.wait_entered().await?;
    fixture.driver.release.notify_one();
    wait_published(&fixture, &child, "completed").await?;
    for process in [fixture.boot.root(), fixture.op.process, child.process] {
        let budget = fixture
            .boot
            .kernel()
            .processes()
            .budget_mut(process, |budget| budget.clone())
            .context("missing retained account")?;
        ensure!(budget.spent_micro_usd == 7 && budget.inflight_ops == 0);
    }
    ensure!(
        fixture
            .boot
            .kernel()
            .state()
            .read(&child.outcome_path)
            .await?
            == Some(outcome_to_value(&Outcome::Done(fixture.op.input.clone())))
    );
    ensure!(fixture.boot.kernel().handles().read().is_empty());
    Ok(())
}

#[tokio::test]
async fn separate_boots_share_retained_state_without_reusing_async_paths() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let facts = FactSink::in_memory().0;
    let ids = crate::ExecutionIds::new(Arc::new(crate::InMemoryExecutionIdSource::new()));
    let fixture = |facts| {
        let published = PublishedOutcomes::default();
        let host = state_host_with_observer(state.clone(), published.clone());
        Fixture::with_host_runtime_and_ids(
            state.clone(),
            facts,
            MethodContract::new(
                0,
                xolotl_types::ReplayClass::Deterministic,
                OutputModeSet::ASYNC_PROCESS,
            ),
            host,
            published,
            None,
            Some(ids.clone()),
        )
    };
    let mut first = fixture(facts.clone())?;
    first.op.input = Value::integer(11);
    first.driver.release.notify_one();
    let original = first.start().await?;
    wait_published(&first, &original, "completed").await?;
    let original_result = state.read(&original.outcome_path).await?;

    let mut second = fixture(facts)?;
    second.op.input = Value::integer(22);
    second.driver.release.notify_one();
    let replacement = second.start().await?;
    wait_published(&second, &replacement, "completed").await?;
    ensure!(first.op.process == second.op.process && original.process == replacement.process);
    ensure!(first.op.id.execution != second.op.id.execution);
    ensure!(
        original.outcome_path != replacement.outcome_path
            && original.status_path != replacement.status_path
    );
    ensure!(state.read(&original.outcome_path).await? == original_result);
    ensure!(
        state.read(&replacement.outcome_path).await?
            == Some(outcome_to_value(&Outcome::Done(Value::integer(22))))
    );
    Ok(())
}

#[tokio::test]
async fn finalization_context_does_not_reject_the_same_process_id_in_another_kernel()
-> anyhow::Result<()> {
    let first = Fixture::new(InMemoryBackend::new().into_backend())?;
    let second = Fixture::new(InMemoryBackend::new().into_backend())?;
    ensure!(first.op.process == second.op.process);
    crate::process::scope_finalizer(
        first.boot.kernel().processes(),
        first.op.process,
        second
            .boot
            .finish_process_as(second.op.process, ProcessStatus::Completed),
    )
    .await?;
    ensure!(
        second.boot.kernel().processes().status(second.op.process)
            == Some(ProcessStatus::Completed)
    );
    ensure!(second.boot.kernel().handles().read().is_empty());
    ensure!(
        first.boot.kernel().processes().status(first.op.process) == Some(ProcessStatus::Running)
    );
    ensure!(first.boot.kernel().handles().read().len() == 1);
    let reentrant = crate::process::scope_finalizer(
        first.boot.kernel().processes(),
        first.op.process,
        first
            .boot
            .finish_process_as(first.op.process, ProcessStatus::Completed),
    )
    .await;
    ensure!(matches!(reentrant, Err(BootstrapError::ProcessBusy { .. })));
    let nested = crate::process::scope_finalizer(
        first.boot.kernel().processes(),
        first.op.process,
        crate::process::scope_finalizer(
            second.boot.kernel().processes(),
            second.op.process,
            first
                .boot
                .finish_process_as(first.op.process, ProcessStatus::Completed),
        ),
    )
    .await;
    ensure!(matches!(nested, Err(BootstrapError::ProcessBusy { .. })));
    Ok(())
}

#[tokio::test]
async fn foreign_finalizer_does_not_wait_for_another_finalization_owner() -> anyhow::Result<()> {
    let first = Fixture::new(InMemoryBackend::new().into_backend())?;
    let second = Fixture::new(InMemoryBackend::new().into_backend())?;
    let guard = acquire_finalization(
        second.boot.kernel().processes(),
        second.op.process,
        ProcessStatus::Completed,
    )
    .await?
    .context("missing finalization owner")?;
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        crate::process::scope_finalizer(
            first.boot.kernel().processes(),
            first.op.process,
            second
                .boot
                .finish_process_as(second.op.process, ProcessStatus::Completed),
        ),
    )
    .await?;
    ensure!(matches!(result, Err(BootstrapError::ProcessBusy { .. })));
    drop(guard);
    ensure!(second.boot.drain_cleanup().await.failures.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_closing_parent_rejects_async_admission_and_revokes_the_derived_handle()
-> anyhow::Result<()> {
    let fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
    ensure!(fixture.boot.cancel_process(fixture.op.process)?);
    ensure!(matches!(
        fixture.execute().await.outcome,
        Outcome::Fail(Failure::Cancelled)
    ));
    ensure!(
        fixture
            .boot
            .kernel()
            .processes()
            .children_of(fixture.op.process)
            .is_empty()
    );
    ensure!(fixture.boot.kernel().handles().read().len() == 1);
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn admission_without_a_runtime_has_no_child_side_effects() -> anyhow::Result<()> {
    let fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
    let result = fixture
        .execute()
        .now_or_never()
        .context("admission unexpectedly suspended")?;
    ensure!(matches!(result.outcome, Outcome::Fail(_)));
    ensure!(
        fixture
            .boot
            .kernel()
            .processes()
            .children_of(fixture.op.process)
            .is_empty()
    );
    ensure!(fixture.boot.kernel().handles().read().len() == 1);
    Ok(())
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum FailurePoint {
    InitialStatus = 1,
    Outcome = 2,
    TerminalStatus = 3,
    PanicInitialStatus = 5,
    StallTerminalStatus = 6,
    DelayedInitialStatus = 7,
    ObservedInitialStatus = 8,
}

struct InterruptedState {
    inner: Arc<InMemoryBackend>,
    failure: AtomicU8,
    hits: AtomicUsize,
    late_release: Arc<Notify>,
    late_conflicts: Arc<AtomicUsize>,
}

impl InterruptedState {
    fn backend(self: &Arc<Self>) -> Backend {
        Backend::new()
            .with_read(self.inner.clone())
            .with_write(self.clone())
            .with_query(self.inner.clone())
            .with_watch(self.inner.clone())
            .with_signal(self.inner.clone())
    }

    fn new(failure: FailurePoint) -> Self {
        Self {
            inner: Arc::new(InMemoryBackend::new()),
            failure: AtomicU8::new(failure as u8),
            hits: AtomicUsize::new(0),
            late_release: Arc::new(Notify::new()),
            late_conflicts: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn before_write(&self, path: &Path, value: &Value) -> StateResult<()> {
        let phase = value
            .as_map()
            .and_then(|value| value.get("phase"))
            .and_then(Value::as_str);
        let field = path.segments().last().map(|field| field.as_str());
        let failure = self.failure.load(Ordering::SeqCst);
        let matches = match failure {
            1 | 5 => field == Some("status") && phase == Some("running"),
            2 => field == Some("outcome"),
            3 | 6 => field == Some("status") && phase.is_some_and(|phase| phase != "running"),
            _ => false,
        };
        if matches
            && self
                .failure
                .compare_exchange(failure, 0, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            self.hits.fetch_add(1, Ordering::SeqCst);
            if failure == FailurePoint::PanicInitialStatus as u8 {
                std::panic::resume_unwind(Box::new(String::from("initial status backend panic")));
            }
            if failure == FailurePoint::StallTerminalStatus as u8 {
                std::future::pending::<()>().await;
            }
            return Err(
                xolotl_state::StateError::Backend("async publication unavailable".into()).into(),
            );
        }
        Ok(())
    }
}

impl StateWrite for InterruptedState {
    type Write<'a> = std::pin::Pin<
        Box<dyn std::future::Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>,
    >;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            if matches!(&mutation, StateMutation::CompareSet { expected: None, .. })
                && self
                    .failure
                    .compare_exchange(
                        FailurePoint::ObservedInitialStatus as u8,
                        0,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
            {
                self.inner
                    .write_set_tainted(
                        path,
                        Value::string("protected-status-value".into()),
                        TaintSet::of(TaintSource::Protected { path: path.clone() }),
                    )
                    .await?;
                let result = self.inner.mutate(path, mutation).await;
                // Only the atomic CAS failure retains this observation. A later
                // point read sees no row and cannot reconstruct its sources.
                self.inner.write_delete(path).await?;
                self.hits.fetch_add(1, Ordering::SeqCst);
                return result;
            }
            if matches!(&mutation, StateMutation::CompareSet { .. })
                && self
                    .failure
                    .compare_exchange(
                        FailurePoint::DelayedInitialStatus as u8,
                        0,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
            {
                let inner = self.inner.clone();
                let path = path.clone();
                let release = self.late_release.clone();
                let conflicts = self.late_conflicts.clone();
                // Model an already-sent backend request that can outlive its caller's future.
                let request = tokio::spawn(async move {
                    release.notified().await;
                    let result = inner.mutate(&path, mutation).await;
                    if result.is_err() {
                        conflicts.fetch_add(1, Ordering::SeqCst);
                    }
                    result
                });
                self.hits.fetch_add(1, Ordering::SeqCst);
                return request
                    .await
                    .map_err(|error| xolotl_state::StateError::Backend(error.to_string()))?;
            }
            if let StateMutation::Set(value) | StateMutation::CompareSet { value, .. } = &mutation {
                self.before_write(path, &value.value).await?;
            }
            self.inner.mutate(path, mutation).await
        })
    }
}

#[tokio::test]
async fn a_late_initial_status_write_cannot_replace_the_cancelled_publication() -> anyhow::Result<()>
{
    let state = Arc::new(InterruptedState::new(FailurePoint::DelayedInitialStatus));
    let fixture = Fixture::new(state.backend())?;
    let child = fixture.start().await?;
    wait_until(|| state.hits.load(Ordering::SeqCst) == 1).await?;
    fixture.boot.finalize_process(child.process).await?;
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    state.late_release.notify_one();
    wait_until(|| state.late_conflicts.load(Ordering::SeqCst) == 1).await?;
    wait_published(&fixture, &child, "cancelled").await?;
    ensure!(fixture.boot.kernel().handles().read().len() == 1);
    Ok(())
}

#[tokio::test]
async fn initial_status_failure_or_panic_prevents_driver_dispatch() -> anyhow::Result<()> {
    for failure in [
        FailurePoint::InitialStatus,
        FailurePoint::PanicInitialStatus,
    ] {
        let state = Arc::new(InterruptedState::new(failure));
        let fixture = Fixture::new(state.backend())?;
        let child = fixture.start().await?;
        wait_published(&fixture, &child, "failed").await?;
        ensure!(state.hits.load(Ordering::SeqCst) == 1);
        ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
        ensure!(fixture.boot.kernel().handles().read().len() == 1);
        ensure!(
            fixture
                .boot
                .kernel()
                .processes()
                .pending_cleanup()
                .is_empty()
        );
    }
    Ok(())
}

#[tokio::test]
async fn initial_status_conflict_preserves_atomic_sources_after_the_row_is_removed()
-> anyhow::Result<()> {
    let state = Arc::new(InterruptedState::new(FailurePoint::ObservedInitialStatus));
    let fixture = Fixture::new(state.backend())?;
    let child = fixture.start().await?;
    wait_published(&fixture, &child, "failed").await?;
    ensure!(state.hits.load(Ordering::SeqCst) == 1);
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    let expected = fixture
        .op
        .taint
        .clone()
        .merged(&TaintSet::of(TaintSource::Protected {
            path: child.status_path.clone(),
        }));
    let output = fixture
        .boot
        .kernel()
        .state()
        .read_tainted(&child.outcome_path)
        .await?;
    let output_value = output
        .value
        .clone()
        .context("missing failed child outcome")?;
    ensure!(output.taint == expected);
    let failure = output_value
        .as_map()
        .and_then(|value| value.get("failure"))
        .and_then(Value::as_str)
        .context("missing failed status diagnostic")?;
    ensure!(failure.contains("initial status write failed"));
    ensure!(!failure.contains("protected-status-value"));
    let status = fixture
        .boot
        .kernel()
        .state()
        .read_tainted(&child.status_path)
        .await?;
    status
        .value
        .as_ref()
        .context("missing terminal child status")?;
    ensure!(status.taint == expected);
    ensure!(fixture.published_output(child.process)?.taint == expected);
    Ok(())
}

#[tokio::test]
async fn publication_failures_retry_the_retained_outcome_without_reexecuting() -> anyhow::Result<()>
{
    for failure in [FailurePoint::Outcome, FailurePoint::TerminalStatus] {
        let state = Arc::new(InterruptedState::new(failure));
        let fixture = Fixture::new(state.backend())?;
        fixture.driver.release.notify_one();
        let child = fixture.start().await?;
        wait_until(|| state.hits.load(Ordering::SeqCst) == 1).await?;
        let before = fixture
            .boot
            .kernel()
            .processes()
            .finalization_outcome(child.process)
            .context("missing retained child outcome")?;
        ensure!(fixture.boot.kernel().processes().pending_cleanup() == [child.process]);
        ensure!(
            fixture
                .boot
                .kernel()
                .processes()
                .finalization_outcome(child.process)
                .is_some()
        );
        let report = fixture.boot.drain_cleanup().await;
        ensure!(report.completed == 1 && report.failures.is_empty());
        let after = fixture.published_output(child.process)?;
        ensure!(
            after.outcome == before.outcome
                && after.taint == before.taint
                && after.unresolved_operations == before.unresolved_operations
        );
        ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 1);
        ensure!(fixture.driver.dropped.load(Ordering::SeqCst) == 1);
        ensure!(
            fixture
                .boot
                .kernel()
                .processes()
                .pending_cleanup()
                .is_empty()
        );
        ensure!(
            fixture
                .boot
                .kernel()
                .processes()
                .finalization_outcome(child.process)
                .is_none()
        );
        ensure!(
            fixture
                .boot
                .kernel()
                .state()
                .read(&child.outcome_path)
                .await?
                == Some(outcome_to_value(&Outcome::Done(fixture.op.input.clone())))
        );
        wait_published(&fixture, &child, "completed").await?;
    }
    Ok(())
}

#[test]
fn runtime_shutdown_drops_the_body_and_allows_cleanup_on_another_runtime() -> anyhow::Result<()> {
    let fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let child = runtime.block_on(async {
        let child = fixture.start().await?;
        fixture.wait_entered().await?;
        Ok::<_, anyhow::Error>(child)
    })?;
    drop(runtime);
    ensure!(fixture.driver.dropped.load(Ordering::SeqCst) == 1);
    ensure!(fixture.boot.kernel().handles().read().len() == 1);
    ensure!(fixture.boot.kernel().processes().pending_cleanup() == [child.process]);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(fixture.boot.drain_cleanup());
    ensure!(report.completed == 1 && report.failures.is_empty());
    runtime.block_on(wait_published(&fixture, &child, "cancelled"))?;
    Ok(())
}

#[test]
fn runtime_shutdown_during_publication_preserves_the_completed_result() -> anyhow::Result<()> {
    let state = Arc::new(InterruptedState::new(FailurePoint::StallTerminalStatus));
    let fixture = Fixture::new(state.backend())?;
    fixture.driver.release.notify_one();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let child = runtime.block_on(async {
        let child = fixture.start().await?;
        wait_until(|| state.hits.load(Ordering::SeqCst) == 1).await?;
        Ok::<_, anyhow::Error>(child)
    })?;
    let before = fixture
        .boot
        .kernel()
        .processes()
        .finalization_outcome(child.process)
        .context("missing retained child outcome")?;
    drop(runtime);
    let retained = fixture
        .boot
        .kernel()
        .processes()
        .finalization_outcome(child.process)
        .context("completion was not retained")?;
    ensure!(retained.outcome == Outcome::Done(fixture.op.input.clone()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(fixture.boot.drain_cleanup());
    ensure!(report.completed == 1 && report.failures.is_empty());
    let after = fixture.published_output(child.process)?;
    ensure!(before.outcome == after.outcome && before.taint == after.taint);
    ensure!(before.unresolved_operations == after.unresolved_operations);
    ensure!(fixture.boot.kernel().handles().read().len() == 1);
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 1);
    runtime.block_on(wait_published(&fixture, &child, "completed"))?;
    Ok(())
}
