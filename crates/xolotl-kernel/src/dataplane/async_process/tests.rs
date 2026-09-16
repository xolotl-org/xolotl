use super::*;
use crate::bootstrap::Bootstrap;
use crate::driver::{Driver, DriverContext, DriverError, DriverPlan};
use crate::handle::{Handle, HandleState};
use anyhow::{Context, ensure};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use xolotl_state::{
    Backend, InMemoryBackend, StateMutation, StateResult, StateWrite, StateWriteExt,
};
use xolotl_types::{
    DriverId, Fact, IdentityRef, MethodBitmap, MethodContract, MethodId, NodeId, RightFlags,
    Rights, TaintSource,
};

#[derive(Default)]
struct ControlledDriver {
    entered: Notify,
    release: Notify,
    calls: AtomicUsize,
    dropped: AtomicUsize,
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
        _ctx: &DriverContext,
    ) -> Result<crate::DriverOutput, DriverError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _running = DriverRun(&self.dropped);
        self.entered.notify_one();
        self.release.notified().await;
        Ok(crate::DriverOutput::new(Outcome::Done(input))
            .with_taint(TaintSet::of(TaintSource::ModelOutput)))
    }
}

struct Fixture {
    boot: Bootstrap,
    driver: Arc<ControlledDriver>,
    op: Operation,
}

struct Child {
    process: ProcessId,
    status_path: Path,
    outcome_path: Path,
}

#[tokio::test]
async fn capacity_rejection_does_not_dispatch_or_retain_child_handles() -> anyhow::Result<()> {
    let fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
    fixture
        .boot
        .kernel
        .processes
        .set_capacity(std::num::NonZeroUsize::new(2))?;
    let handles = fixture.boot.kernel.handles.read().len();
    let outcome = fixture.execute().await.outcome;
    ensure!(
        matches!(outcome, Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "process_admission"),
        "capacity exhaustion did not surface as admission failure: {outcome:?}"
    );
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    ensure!(fixture.boot.kernel.handles.read().len() == handles);
    ensure!(fixture.boot.kernel.processes.len() == 2);
    ensure!(
        fixture
            .boot
            .kernel
            .processes
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

    fn with_contract(
        state: xolotl_state::Backend,
        facts: FactSink,
        contract: MethodContract,
    ) -> anyhow::Result<Self> {
        let boot = Bootstrap::from_kernel(crate::Kernel::with_backends(state, facts));
        let process = boot
            .request_under(boot.root, IdentityRef::ROOT, &[])?
            .detach();
        let driver = Arc::new(ControlledDriver::default());
        let method = MethodId::new(7);
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(method, contract, driver.clone());
        let handle = boot.kernel.handles.write().insert(Handle {
            id: HandleId::new(0, 0),
            process,
            acting: IdentityRef::ROOT,
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::SPAWN_WITH),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        })?;
        let execution = boot.kernel.execution_ids().allocate()?;
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
        Ok(Self { boot, driver, op })
    }

    async fn execute(&self) -> DriverOutput {
        self.boot
            .kernel
            .data_plane()
            .execute(
                &self.op,
                crate::InvocationOptions {
                    now_millis: 0,
                    record: false,
                },
            )
            .await
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
            let value = fixture.boot.kernel.state.read(&child.status_path).await?;
            if value
                .as_ref()
                .and_then(Value::as_map)
                .and_then(|value| value.get("phase"))
                .and_then(Value::as_str)
                == Some(phase)
                && fixture.boot.kernel.processes.pending_cleanup().is_empty()
            {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(())
}

fn lifecycle(fixture: &Fixture, process: ProcessId) -> anyhow::Result<Fact> {
    fixture
        .boot
        .kernel
        .facts
        .facts_of(process)?
        .into_iter()
        .find(|fact| fact.id.position == NodeId::new(u32::MAX))
        .context("missing lifecycle fact")
}

#[tokio::test]
async fn cancellation_drops_the_running_driver_and_publishes_the_terminal_outcome()
-> anyhow::Result<()> {
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
        ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 1);
        ensure!(fixture.driver.dropped.load(Ordering::SeqCst) == 1);
        ensure!(fixture.boot.kernel.handles.read().len() == usize::from(!force));
        ensure!(
            fixture.boot.kernel.state.read(&child.outcome_path).await?
                == Some(outcome_to_value(&Outcome::Fail(Failure::Cancelled)))
        );
        lifecycle(&fixture, child.process)?;
    }
    Ok(())
}

#[tokio::test]
async fn abort_before_the_first_poll_retains_cleanup_without_dispatching() -> anyhow::Result<()> {
    let fixture = Fixture::new(InMemoryBackend::new().into_backend())?;
    let child = fixture.start().await?;
    ensure!(fixture.boot.kernel.processes.abort_task(child.process));
    wait_until(|| {
        fixture
            .boot
            .kernel
            .processes
            .pending_cleanup()
            .contains(&child.process)
    })
    .await?;
    let report = fixture.boot.drain_cleanup().await;
    ensure!(report.failures.is_empty() && report.completed == 1);
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    ensure!(fixture.boot.kernel.handles.read().len() == 1);
    ensure!(fixture.boot.kernel.processes.status(child.process) == Some(ProcessStatus::Cancelled));
    ensure!(
        fixture.boot.kernel.state.read(&child.outcome_path).await?
            == Some(outcome_to_value(&Outcome::Fail(Failure::Cancelled)))
    );
    ensure!(fixture.boot.kernel.facts.facts_of(child.process)?.len() == 1);
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
    ensure!(fixture.boot.kernel.processes.status(child.process) == Some(ProcessStatus::Running));
    ensure!(fixture.driver.dropped.load(Ordering::SeqCst) == 0);
    fixture.driver.release.notify_one();
    wait_published(&fixture, &child, "completed").await?;
    let output = fixture
        .boot
        .kernel
        .state
        .read_tainted(&child.outcome_path)
        .await?
        .context("missing async output")?;
    ensure!(output.value == outcome_to_value(&Outcome::Done(fixture.op.input.clone())));
    ensure!(output.taint == TaintSet::of(TaintSource::ModelOutput).merged(&fixture.op.taint));
    ensure!(fixture.boot.kernel.handles.read().is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn parent_completion_before_the_child_first_poll_preserves_delegated_authority_and_budget()
-> anyhow::Result<()> {
    let fixture = Fixture::with_contract(
        InMemoryBackend::new().into_backend(),
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
    )?;
    ensure!(fixture.boot.kernel.processes.set_budget_spec(
        fixture.op.process,
        xolotl_types::BudgetSpec {
            daily_micro_usd: Some(7),
            max_inflight_ops: Some(1),
            ..xolotl_types::BudgetSpec::default()
        }
    ));
    let child = fixture.start().await?;
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    let created_budget = fixture
        .boot
        .kernel
        .processes
        .budget_mut(fixture.op.process, |budget| budget.clone())
        .context("missing parent account")?;
    ensure!(created_budget.spent_micro_usd == 0 && created_budget.inflight_ops == 0);
    let outcome =
        xolotl_types::ExecutionOutput::new(Outcome::Done(Value::null()), TaintSet::pristine());
    let completion = fixture
        .boot
        .finish_request_process(fixture.op.process, &outcome);
    tokio::pin!(completion);
    let completed = std::future::poll_fn(|context| {
        std::task::Poll::Ready(std::future::Future::poll(completion.as_mut(), context))
    })
    .await;
    let std::task::Poll::Ready(result) = completed else {
        anyhow::bail!("the in-memory parent completion unexpectedly yielded to the child");
    };
    result?;
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 0);
    ensure!(
        fixture
            .boot
            .kernel
            .handles
            .read()
            .get(fixture.op.handle)
            .is_none()
    );

    fixture.wait_entered().await?;
    fixture.driver.release.notify_one();
    wait_published(&fixture, &child, "completed").await?;
    for process in [fixture.boot.root, fixture.op.process, child.process] {
        let budget = fixture
            .boot
            .kernel
            .processes
            .budget_mut(process, |budget| budget.clone())
            .context("missing retained account")?;
        ensure!(budget.spent_micro_usd == 7 && budget.inflight_ops == 0);
    }
    ensure!(
        fixture.boot.kernel.state.read(&child.outcome_path).await?
            == Some(outcome_to_value(&Outcome::Done(fixture.op.input.clone())))
    );
    ensure!(fixture.boot.kernel.handles.read().is_empty());
    Ok(())
}

#[tokio::test]
async fn separate_boots_share_retained_state_without_reusing_async_paths() -> anyhow::Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let facts = FactSink::in_memory().0;
    let mut first = Fixture::with_facts(state.clone(), facts.clone())?;
    first.op.input = Value::integer(11);
    first.driver.release.notify_one();
    let original = first.start().await?;
    wait_published(&first, &original, "completed").await?;
    let original_result = state.read(&original.outcome_path).await?;

    let mut second = Fixture::with_facts(state.clone(), facts)?;
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
        &first.boot.kernel.processes,
        first.op.process,
        second
            .boot
            .finish_process_as(second.op.process, ProcessStatus::Completed),
    )
    .await?;
    ensure!(
        second.boot.kernel.processes.status(second.op.process) == Some(ProcessStatus::Completed)
    );
    ensure!(second.boot.kernel.handles.read().is_empty());
    ensure!(first.boot.kernel.processes.status(first.op.process) == Some(ProcessStatus::Running));
    ensure!(first.boot.kernel.handles.read().len() == 1);
    let reentrant = crate::process::scope_finalizer(
        &first.boot.kernel.processes,
        first.op.process,
        first
            .boot
            .finish_process_as(first.op.process, ProcessStatus::Completed),
    )
    .await;
    ensure!(matches!(reentrant, Err(BootstrapError::ProcessBusy { .. })));
    let nested = crate::process::scope_finalizer(
        &first.boot.kernel.processes,
        first.op.process,
        crate::process::scope_finalizer(
            &second.boot.kernel.processes,
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
        &second.boot.kernel.processes,
        second.op.process,
        ProcessStatus::Completed,
    )
    .await?
    .context("missing finalization owner")?;
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        crate::process::scope_finalizer(
            &first.boot.kernel.processes,
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
            .kernel
            .processes
            .children_of(fixture.op.process)
            .is_empty()
    );
    ensure!(fixture.boot.kernel.handles.read().len() == 1);
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
            .kernel
            .processes
            .children_of(fixture.op.process)
            .is_empty()
    );
    ensure!(fixture.boot.kernel.handles.read().len() == 1);
    Ok(())
}

#[derive(Clone, Copy)]
#[repr(u8)]
enum FailurePoint {
    InitialStatus = 1,
    Outcome = 2,
    TerminalStatus = 3,
    Marker = 4,
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
            4 => field == Some("finalized"),
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
    ensure!(fixture.boot.kernel.handles.read().len() == 1);
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
        ensure!(fixture.boot.kernel.handles.read().len() == 1);
        lifecycle(&fixture, child.process)?;
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
        .kernel
        .state
        .read_tainted(&child.outcome_path)
        .await?
        .context("missing failed child outcome")?;
    ensure!(output.taint == expected);
    let failure = output
        .value
        .as_map()
        .and_then(|value| value.get("failure"))
        .and_then(Value::as_str)
        .context("missing failed status diagnostic")?;
    ensure!(failure.contains("initial status write failed"));
    ensure!(!failure.contains("protected-status-value"));
    let status = fixture
        .boot
        .kernel
        .state
        .read_tainted(&child.status_path)
        .await?
        .context("missing terminal child status")?;
    ensure!(status.taint == expected);
    ensure!(lifecycle(&fixture, child.process)?.taint == expected);
    Ok(())
}

#[tokio::test]
async fn publication_failures_retry_the_retained_outcome_without_reexecuting() -> anyhow::Result<()>
{
    for failure in [
        FailurePoint::Outcome,
        FailurePoint::TerminalStatus,
        FailurePoint::Marker,
    ] {
        let state = Arc::new(InterruptedState::new(failure));
        let fixture = Fixture::new(state.backend())?;
        fixture.driver.release.notify_one();
        let child = fixture.start().await?;
        wait_until(|| state.hits.load(Ordering::SeqCst) == 1).await?;
        let before = lifecycle(&fixture, child.process)?;
        ensure!(fixture.boot.kernel.processes.pending_cleanup() == [child.process]);
        ensure!(
            fixture
                .boot
                .kernel
                .processes
                .finalization_outcome(child.process)
                .is_some()
        );
        let report = fixture.boot.drain_cleanup().await;
        ensure!(report.completed == 1 && report.failures.is_empty());
        let after = lifecycle(&fixture, child.process)?;
        ensure!(
            after.id == before.id
                && after.timestamp == before.timestamp
                && after.outcome == before.outcome
        );
        ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 1);
        ensure!(fixture.driver.dropped.load(Ordering::SeqCst) == 1);
        ensure!(fixture.boot.kernel.processes.pending_cleanup().is_empty());
        ensure!(
            fixture
                .boot
                .kernel
                .processes
                .finalization_outcome(child.process)
                .is_none()
        );
        ensure!(
            fixture.boot.kernel.state.read(&child.outcome_path).await?
                == Some(outcome_to_value(&Outcome::Done(fixture.op.input.clone())))
        );
        let record = after.outcome;
        let value = record
            .as_ref()
            .and_then(Value::as_map)
            .context("missing lifecycle result")?;
        ensure!(
            value.get("released_handles").and_then(Value::as_int) == Some(1)
                && value.get("revoked_handles").and_then(Value::as_int) == Some(0)
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
    ensure!(fixture.boot.kernel.handles.read().len() == 1);
    ensure!(fixture.boot.kernel.processes.pending_cleanup() == [child.process]);
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
    let before = lifecycle(&fixture, child.process)?;
    drop(runtime);
    let retained = fixture
        .boot
        .kernel
        .processes
        .finalization_outcome(child.process)
        .context("completion was not retained")?;
    ensure!(retained.outcome == Outcome::Done(fixture.op.input.clone()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(fixture.boot.drain_cleanup());
    ensure!(report.completed == 1 && report.failures.is_empty());
    let after = lifecycle(&fixture, child.process)?;
    ensure!(before.timestamp == after.timestamp && before.outcome == after.outcome);
    ensure!(fixture.driver.calls.load(Ordering::SeqCst) == 1);
    runtime.block_on(wait_published(&fixture, &child, "completed"))?;
    Ok(())
}
