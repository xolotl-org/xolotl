#![cfg(feature = "host")]

use anyhow::{Context, bail, ensure};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context as TaskContext, Wake, Waker},
    thread,
    time::{Duration, Instant},
};
use xolotl_graph::{
    ActorSpec, OperationTemplate,
    portable::{Expression, Program},
};
use xolotl_kernel::{
    Bootstrap, CompiledRequestGrantTemplate, DataPlane, Driver, DriverContext, DriverError,
    DriverPlan, EchoDriver, FactIoMode, FactSink, FactStore, FastPath, Handle, HandleTable,
    KernelBuilder, MethodSpec,
    host::{ClockDomainError, HostClock, HostRuntime},
};
use xolotl_types::{
    DriverId, DriverOutput, ExecutionId, Failure, HandleId, IdentityRef, InvocationId,
    MethodAuthority, MethodBitmap, MethodContract, MethodId, NodeId, Operation, OperationId,
    Outcome, OutputMode, OutputModeSet, ProcessId, ProcessStatus, Purity, ReplayClass, ResourceId,
    ResourceName, ResourceSelector, RightFlags, Rights, TaintedValue, Value,
};

#[path = "support/non_tokio_runtime.rs"]
mod non_tokio_runtime;
use non_tokio_runtime::{ManualClock, ThreadBlockingSpawner, ThreadTasks, block_on, wait_until};

fn host() -> (Bootstrap, ManualClock, ThreadTasks) {
    let clock = ManualClock::new();
    let tasks = ThreadTasks::default();
    let runtime = HostRuntime::new(
        Arc::new(clock.clone()),
        Arc::new(tasks.clone()),
        Arc::new(ThreadBlockingSpawner::default()),
    );
    let boot = Bootstrap::from_kernel(
        KernelBuilder::new(xolotl_state::InMemoryBackend::new().into_backend())
            .with_host_runtime(runtime)
            .build(),
    );
    (boot, clock, tasks)
}

#[test]
fn owned_blocking_work_runs_without_tokio_and_outlives_its_waiter() -> anyhow::Result<()> {
    ensure!(tokio::runtime::Handle::try_current().is_err());
    let (boot, _clock, _tasks) = host();
    let runtime = boot.kernel().host_runtime();
    ensure!(block_on(runtime.dispatch_blocking(|| 42_u8)?)?? == 42);

    let ran = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&ran);
    let waiter = runtime.dispatch_blocking(move || observed.store(true, Ordering::SeqCst))?;
    drop(waiter);
    wait_until(|| ran.load(Ordering::SeqCst))?;
    Ok(())
}

#[test]
fn hosted_fact_writes_run_without_tokio() -> anyhow::Result<()> {
    ensure!(tokio::runtime::Handle::try_current().is_err());
    let runtime = HostRuntime::new(
        Arc::new(ManualClock::new()),
        Arc::new(ThreadTasks::default()),
        Arc::new(ThreadBlockingSpawner::default()),
    );
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::NonIdempotentEffect, OutputModeSet::UNARY),
        Arc::new(EchoDriver),
    );
    let handles = HandleTable::new();
    let process = ProcessId::new(1);
    let handle = handles.insert(Handle {
        open_verb: "perform".into(),
        id: HandleId::new(0, 0),
        process,
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(1),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let plane = DataPlane::new_with_host_runtime(
        handles,
        facts,
        xolotl_state::InMemoryBackend::new().into_backend(),
        runtime,
    )
    .with_fact_io_mode(FactIoMode::Blocking);
    let operation = Operation {
        id: OperationId::new(
            process,
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(0),
            0,
        ),
        process,
        acting: IdentityRef::ROOT,
        handle,
        method: MethodId::new(7),
        input: Value::integer(42),
        taint: xolotl_types::TaintSet::pristine(),
        output: OutputMode::Unary,
    };
    let result = block_on(plane.execute(
        &operation,
        xolotl_kernel::InvocationOptions {
            caller_identity: None,
            now_millis: 1_000_000,
            record: true,
        },
    ))?;
    ensure!(result.output.outcome == Outcome::Done(Value::integer(42)));
    ensure!(result.completion_error.is_none());
    ensure!(
        store
            .get(operation.id)?
            .is_some_and(|fact| fact.is_complete())
    );
    Ok(())
}

#[derive(Default)]
struct WaitingDriver {
    entered: AtomicBool,
    dropped: AtomicBool,
}

struct DropFlag<'a>(&'a AtomicBool);

impl Drop for DropFlag<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Driver for WaitingDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        _context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let _guard = DropFlag(&self.dropped);
        self.entered.store(true, Ordering::SeqCst);
        Ok(std::future::pending::<DriverOutput>().await)
    }
}

fn effect(boot: &Bootstrap, driver: Arc<WaitingDriver>) -> anyhow::Result<ResourceName> {
    Ok(boot.register_effect(
        "effect://non-tokio-host",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        driver,
    )?)
}

fn program(target: ResourceName) -> anyhow::Result<xolotl_graph::portable::CompiledProgram> {
    Ok(Program::new(Expression::Invoke {
        operation: OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    })
    .compile()?)
}

struct PollWake(thread::Thread);

impl Wake for PollWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn poll_until_pending<F: Future>(
    mut future: Pin<&mut F>,
    ready: impl Fn() -> bool,
) -> anyhow::Result<()> {
    let wake = Waker::from(Arc::new(PollWake(thread::current())));
    let mut context = TaskContext::from_waker(&wake);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        ensure!(
            future.as_mut().poll(&mut context).is_pending(),
            "execution ended before entering its wait"
        );
        if ready() {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "execution did not enter its wait"
        );
        // The blocking ID refill wakes this thread; the short timeout also
        // observes drivers that publish readiness without waking the future.
        thread::park_timeout(Duration::from_millis(1));
    }
}

#[test]
fn foreign_clock_deadlines_are_rejected_before_execution() -> anyhow::Result<()> {
    let (boot, _clock, _tasks) = host();
    let foreign = HostRuntime::new(
        Arc::new(ManualClock::new()),
        Arc::new(ThreadTasks::default()),
        Arc::new(ThreadBlockingSpawner::default()),
    );
    let deadline = foreign
        .deadline_after(Duration::from_secs(30))
        .context("deadline")?;
    ensure!(matches!(
        boot.kernel()
            .executor_for(boot.root())
            .with_deadline(deadline),
        Err(ClockDomainError)
    ));
    ensure!(matches!(
        boot.kernel().data_plane().with_deadline(deadline),
        Err(ClockDomainError)
    ));
    let own = boot.kernel().host_runtime().now();
    let plane = boot.kernel().data_plane().with_deadline(own)?;
    ensure!(matches!(
        plane.with_host_runtime(foreign),
        Err(ClockDomainError)
    ));
    Ok(())
}

#[test]
fn deadline_interrupts_pending_driver_without_tokio_runtime() -> anyhow::Result<()> {
    ensure!(tokio::runtime::Handle::try_current().is_err());
    let (boot, clock, tasks) = host();
    let driver = Arc::new(WaitingDriver::default());
    let program = program(effect(&boot, driver.clone())?)?;
    let deadline = boot
        .kernel()
        .host_runtime()
        .deadline_after(Duration::from_secs(1))
        .context("deadline")?;
    let executor = boot
        .kernel()
        .executor_for(boot.root())
        .with_deadline(deadline)?;
    let mut running =
        Box::pin(executor.eval_program(&program, TaintedValue::pristine(Value::null())));
    poll_until_pending(running.as_mut(), || {
        driver.entered.load(Ordering::SeqCst) && clock.waiting() > 0
    })?;
    clock.advance(Duration::from_secs(1));
    let output = block_on(running)?;
    let Outcome::Fail(Failure::OutcomeUnknown {
        operation_ids,
        reason,
    }) = &output.outcome
    else {
        bail!("dispatched effect did not retain its unknown outcome: {output:?}");
    };
    ensure!(!operation_ids.is_empty() && reason == "deadline_exceeded");
    ensure!(output.unresolved_operations.operation_ids == *operation_ids);
    ensure!(driver.dropped.load(Ordering::SeqCst));
    ensure!(clock.waiting() == 0);
    ensure!(tasks.spawned.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[test]
fn actor_abort_drops_wait_and_finishes_without_tokio_runtime() -> anyhow::Result<()> {
    ensure!(tokio::runtime::Handle::try_current().is_err());
    let (boot, clock, tasks) = host();
    let spec = ActorSpec {
        name: "external-executor".into(),
        body: xolotl_graph::DoNode::wait_deadline(clock.unix_millis() + 60_000),
        ..ActorSpec::default()
    };
    let actor = block_on(boot.spawn_actor_under(boot.root(), IdentityRef::ROOT, "root", &spec))??;
    wait_until(|| clock.waiting() > 0)?;
    ensure!(boot.kernel().processes().has_task(actor.process));
    block_on(boot.finalize_process(actor.process))??;
    ensure!(boot.kernel().processes().status(actor.process) == Some(ProcessStatus::Cancelled));
    ensure!(!boot.kernel().processes().has_task(actor.process));
    ensure!(clock.waiting() == 0);
    ensure!(tasks.spawned.load(Ordering::SeqCst) >= 1);
    ensure!(tasks.aborted.load(Ordering::SeqCst) >= 1);
    Ok(())
}

#[test]
fn abandoned_request_uses_external_scheduler_and_rejected_spawn_can_be_drained()
-> anyhow::Result<()> {
    ensure!(tokio::runtime::Handle::try_current().is_err());
    let (boot, _clock, tasks) = host();
    let driver = Arc::new(WaitingDriver::default());
    let target = effect(&boot, driver.clone())?;
    let program = program(target.clone())?;
    let grants = [CompiledRequestGrantTemplate {
        selector: ResourceSelector::parse("perform://effect/non-tokio-host")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::name("invoke"),
            RightFlags::empty(),
        ),
    }];
    let request = boot.request_under(boot.root(), IdentityRef::ROOT, &grants)?;
    let process = request.id();
    let handle = boot.open_for(process, &target, "perform")?;
    let ticket = boot.cleanup_ticket(process)?;
    let executor = request.executor();
    let mut running =
        Box::pin(executor.eval_program(&program, TaintedValue::pristine(Value::null())));
    poll_until_pending(running.as_mut(), || driver.entered.load(Ordering::SeqCst))?;
    drop(running);
    ensure!(driver.dropped.load(Ordering::SeqCst));
    drop(request);
    ensure!(boot.kernel().handles().get(handle).is_none());
    wait_until(|| ticket.is_complete())?;
    ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Cancelled));
    ensure!(tasks.spawned.load(Ordering::SeqCst) == 1);

    tasks.reject.store(true, Ordering::SeqCst);
    let abandoned = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
    let abandoned_id = abandoned.id();
    let abandoned_ticket = boot.cleanup_ticket(abandoned_id)?;
    drop(abandoned);
    ensure!(!abandoned_ticket.is_complete());
    let report = block_on(boot.drain_cleanup())?;
    ensure!(report.completed == 1 && report.failures.is_empty());
    ensure!(abandoned_ticket.is_complete());
    ensure!(boot.kernel().processes().status(abandoned_id) == Some(ProcessStatus::Cancelled));
    ensure!(tasks.spawned.load(Ordering::SeqCst) == 1);
    Ok(())
}
