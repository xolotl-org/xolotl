use super::children::DisposalFailure;
use super::*;
use tokio::sync::Notify;
use xolotl_kernel::{Driver, DriverContext, DriverError};
use xolotl_types::{DriverOutput, IdentityRef, MethodId, ProcessId};

async fn fixture(
    config: ConsoleExecutionConfig,
    propagation: bool,
) -> anyhow::Result<(Fixture, Arc<DisposalFailure>)> {
    let state = xolotl_state::InMemoryBackend::new().into_backend();
    let fault = Arc::new(DisposalFailure::default());
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(state)
            .with_host_runtime(xolotl_kernel::host::HostRuntime::tokio_with_blocking(
                fault.clone(),
            ))
            .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
            .build(),
    ));
    let fixture = Fixture::with_boot(boot, config, propagation, propagation).await?;
    Ok((fixture, fault))
}

fn one_slot() -> ConsoleExecutionConfig {
    ConsoleExecutionConfig {
        max_concurrent: 1,
        max_concurrent_per_account: 1,
        cleanup_timeout_ms: 20,
        ..config()
    }
}

#[derive(Default)]
struct DisposalJobs {
    active: AtomicUsize,
    released: AtomicUsize,
    executed: AtomicUsize,
}

struct QueuedDisposal(Arc<DisposalJobs>);

impl Drop for QueuedDisposal {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.released.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct HeldDisposal {
    spawner: xolotl_kernel::host::TokioBlockingSpawner,
    hold: std::sync::atomic::AtomicBool,
    fail: std::sync::atomic::AtomicBool,
    held: std::sync::Mutex<Option<xolotl_kernel::host::BlockingJob>>,
    jobs: Arc<DisposalJobs>,
    rejected: AtomicUsize,
    cancelled: AtomicUsize,
    entered: Notify,
}

impl xolotl_kernel::host::BlockingSpawner for HeldDisposal {
    fn spawn(
        &self,
        job: xolotl_kernel::host::BlockingJob,
    ) -> Result<(), xolotl_kernel::host::BlockingSpawnError> {
        if self.fail.load(Ordering::SeqCst) {
            self.rejected.fetch_add(1, Ordering::SeqCst);
            return Err(xolotl_kernel::host::BlockingSpawnError::Unavailable);
        }
        if !self.hold.load(Ordering::SeqCst) {
            return self.spawner.spawn(job);
        }
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if held.is_some() {
            return Err(xolotl_kernel::host::BlockingSpawnError::AtCapacity);
        }
        self.jobs.active.fetch_add(1, Ordering::SeqCst);
        let capture = QueuedDisposal(self.jobs.clone());
        *held = Some(Box::new(move || {
            capture.0.executed.fetch_add(1, Ordering::SeqCst);
            job();
            drop(capture);
        }));
        self.entered.notify_one();
        Ok(())
    }
}

impl HeldDisposal {
    async fn release(&self, execute: bool) -> anyhow::Result<()> {
        self.hold.store(false, Ordering::SeqCst);
        let job = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .context("accepted disposal job")?;
        if execute {
            xolotl_kernel::host::BlockingSpawner::spawn(&self.spawner, job)?;
            self.spawner.wait_idle().await;
        } else {
            self.cancelled.fetch_add(1, Ordering::SeqCst);
            drop(job);
        }
        Ok(())
    }
}

async fn pending_disposal_fixture()
-> anyhow::Result<(Fixture, Arc<HeldDisposal>, String, ProcessId)> {
    let backend = xolotl_state::InMemoryBackend::new().into_backend();
    let disposal = Arc::new(HeldDisposal::default());
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(backend)
            .with_host_runtime(xolotl_kernel::host::HostRuntime::tokio_with_blocking(
                disposal.clone(),
            ))
            .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
            .build(),
    ));
    let f = Fixture::with_boot(boot, one_slot(), false, false).await?;
    let boot = &f.state.boot;
    let grants = [xolotl_kernel::CompiledRequestGrantTemplate {
        selector: xolotl_types::ResourceSelector::parse("perform://effect/jobs/echo")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::name("invoke"),
            xolotl_types::RightFlags::empty(),
        ),
    }];
    let process = boot
        .request_under(boot.root(), IdentityRef::ROOT, &grants)?
        .detach();
    let handle = boot.open_for(
        process,
        &xolotl_types::ResourceName::new(Path::parse("effect://jobs/echo")?),
        "perform",
    )?;
    ensure!(boot.kernel().handles().get(handle).is_some());
    let (registration, _, reference) = f.state.executions.register(
        f.owner().await?,
        Vec::new(),
        ExecutionReference {
            execution_id: None,
            process_id: process.get().to_string(),
            program_id: "00".repeat(32),
        },
        xolotl_kernel::host::system_now_millis() + 60_000,
        xolotl_types::BudgetSpec::default(),
    )?;
    registration.bind_cleanup(boot.cleanup_ticket(process)?)?;
    disposal.fail.store(true, Ordering::SeqCst);
    ensure!(matches!(
        boot.finish_process_as(process, ProcessStatus::Completed)
            .await,
        Err(xolotl_kernel::BootstrapError::TerminalRecordScheduling(
            xolotl_kernel::host::BlockingSpawnError::Unavailable
        ))
    ));
    ensure!(disposal.rejected.load(Ordering::SeqCst) == 1);
    ensure!(boot.kernel().handles().get(handle).is_some());
    registration.finish(false);
    disposal.fail.store(false, Ordering::SeqCst);
    disposal.hold.store(true, Ordering::SeqCst);
    Ok((
        f,
        disposal,
        reference.execution_id.context("execution ID")?,
        process,
    ))
}

async fn assert_disposed(f: &Fixture, process: ProcessId) -> anyhow::Result<()> {
    ensure!(f.state.boot.cleanup_ticket(process)?.is_complete());
    ensure!(f.state.boot.kernel().handles().is_empty());
    let scan = xolotl_state::StateScan::new(Path::parse(&format!(
        "state://kernel/process/{}",
        process.get()
    ))?);
    ensure!(
        f.state
            .boot
            .kernel()
            .state()
            .query(&scan)
            .await?
            .entries
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_shutdown_retains_accepted_disposal_until_host_release() -> anyhow::Result<()> {
    let (f, disposal, id, process) = pending_disposal_fixture().await?;
    let before = f.finished(&id).await?;
    super::super::cleanup::start(&f.state)?;
    tokio::time::timeout(Duration::from_secs(1), disposal.entered.notified()).await?;
    ensure!(disposal.jobs.active.load(Ordering::SeqCst) == 1);
    let (first, second) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(
            f.service.shutdown_executions(),
            f.service.shutdown_executions()
        )
    })
    .await?;
    ensure!(first.volatile_cleanup_pending == 1 && second.volatile_cleanup_pending == 1);
    ensure!(disposal.jobs.active.load(Ordering::SeqCst) == 1);
    ensure!(disposal.jobs.released.load(Ordering::SeqCst) == 0);
    ensure!(!f.state.executions.cleanup.running.load(Ordering::Acquire));
    super::super::cleanup::start(&f.state)?;
    ensure!(!f.state.executions.cleanup.running.load(Ordering::Acquire));
    disposal.release(true).await?;
    ensure!(disposal.jobs.active.load(Ordering::SeqCst) == 0);
    ensure!(disposal.jobs.executed.load(Ordering::SeqCst) == 1);
    ensure!(disposal.jobs.released.load(Ordering::SeqCst) == 1);
    ensure!(
        f.service
            .shutdown_executions()
            .await
            .volatile_cleanup_pending
            == 0
    );
    let after = f.finished(&id).await?;
    ensure!(field(&after, "cleanup_status")?.as_str() == Some("complete"));
    ensure!(field(&after, "expires_at")? == field(&before, "expires_at")?);
    ensure!(f.calls.load(Ordering::SeqCst) == 0);
    assert_disposed(&f, process).await
}

#[tokio::test]
async fn cleanup_timeout_retains_accepted_job_and_retries_after_host_cancellation()
-> anyhow::Result<()> {
    let (f, disposal, id, process) = pending_disposal_fixture().await?;
    let before = f.finished(&id).await?;
    super::super::cleanup::start(&f.state)?;
    tokio::time::timeout(Duration::from_secs(1), disposal.entered.notified()).await?;
    tokio::time::sleep(Duration::from_millis(60)).await;
    ensure!(disposal.jobs.active.load(Ordering::SeqCst) == 1);
    ensure!(disposal.jobs.released.load(Ordering::SeqCst) == 0);
    ensure!(f.state.executions.cleanup.running.load(Ordering::Acquire));
    ensure!(f.state.executions.pending_volatile_cleanup_count() == 1);
    disposal.release(false).await?;
    ensure!(disposal.cancelled.load(Ordering::SeqCst) == 1);
    ensure!(disposal.jobs.executed.load(Ordering::SeqCst) == 0);
    ensure!(disposal.jobs.released.load(Ordering::SeqCst) == 1);
    let after = cleaned(&f, &id).await?;
    ensure!(field(&after, "expires_at")? == field(&before, "expires_at")?);
    ensure!(field(&after, "outcome")? == field(&before, "outcome")?);
    ensure!(f.calls.load(Ordering::SeqCst) == 0);
    ensure!(
        f.service
            .shutdown_executions()
            .await
            .volatile_cleanup_pending
            == 0
    );
    assert_disposed(&f, process).await
}

#[tokio::test]
async fn accepted_disposal_cancellation_reports_unknown_and_preserves_retry_custody()
-> anyhow::Result<()> {
    use futures_util::FutureExt as _;
    let (f, disposal, id, process) = pending_disposal_fixture().await?;
    let before = f.finished(&id).await?;
    let ticket = f.state.boot.cleanup_ticket(process)?;
    let attempt = f.state.boot.resume_cleanup(&ticket);
    tokio::pin!(attempt);
    ensure!(attempt.as_mut().now_or_never().is_none());
    ensure!(disposal.jobs.active.load(Ordering::SeqCst) == 1);
    disposal.release(false).await?;
    ensure!(matches!(
        attempt.await,
        Err(xolotl_kernel::BootstrapError::TerminalRecordUnknown(
            xolotl_kernel::host::BlockingTaskError::Cancelled
        ))
    ));
    ensure!(!ticket.is_complete());
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Completed));
    ensure!(f.state.executions.pending_volatile_cleanup_count() == 1);
    ensure!(disposal.cancelled.load(Ordering::SeqCst) == 1);
    ensure!(disposal.jobs.released.load(Ordering::SeqCst) == 1);
    f.state.boot.resume_cleanup(&ticket).await?;
    super::super::cleanup::pass(&f.state).await;
    let after = f.finished(&id).await?;
    ensure!(field(&after, "expires_at")? == field(&before, "expires_at")?);
    ensure!(f.calls.load(Ordering::SeqCst) == 0);
    assert_disposed(&f, process).await
}

#[tokio::test]
async fn shutdown_waits_for_an_admitted_but_unpolled_cleanup_worker() -> anyhow::Result<()> {
    let f = Fixture::new(one_slot()).await?;
    super::super::cleanup::start(&f.state)?;
    // The current-thread runtime has not polled the spawned worker yet.
    let report = f.service.shutdown_executions().await;
    ensure!(report.volatile_cleanup_pending == 0);
    ensure!(!f.state.executions.cleanup.running.load(Ordering::Acquire));
    Ok(())
}

#[test]
fn a_dropped_runtime_retains_unknown_worker_custody_for_a_new_runtime() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (f, fault, id) = runtime.block_on(async {
        let (f, fault) = fixture(one_slot(), false).await?;
        fault.fail.store(true, Ordering::SeqCst);
        let id = f.submit(wait(), Value::null()).await?;
        tokio::task::yield_now().await;
        Ok::<_, anyhow::Error>((f, fault, id))
    })?;
    drop(runtime);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let pending = f.finished(&id).await?;
        ensure!(field(&pending, "outcome")?.as_str() == Some("interrupted"));
        ensure!(field(&pending, "result_status")?.as_str() == Some("omitted"));
        ensure!(
            f.service
                .shutdown_executions()
                .await
                .volatile_cleanup_pending
                == 1
        );
        ensure!(fault.rejected.load(Ordering::SeqCst) > 0);
        fault.fail.store(false, Ordering::SeqCst);
        ensure!(
            f.service
                .shutdown_executions()
                .await
                .volatile_cleanup_pending
                == 0
        );
        let completed = f.finished(&id).await?;
        ensure!(field(&completed, "outcome")?.as_str() == Some("interrupted"));
        ensure!(field(&completed, "expires_at")? == field(&pending, "expires_at")?);
        ensure!(f.calls.load(Ordering::SeqCst) == 0);
        Ok(())
    })
}

fn process(record: &Value) -> anyhow::Result<ProcessId> {
    Ok(ProcessId::new(
        field(record, "process_id")?
            .as_str()
            .context("process ID")?
            .parse()?,
    ))
}

async fn result(f: &Fixture, id: &str) -> anyhow::Result<Value> {
    f.call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(id))
        .await?
        .output
        .context("retained result")
}

async fn cleaned(f: &Fixture, id: &str) -> anyhow::Result<Value> {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let record = f
                .call(ACTION_RUNTIME_EXECUTION_GET, id_input(id))
                .await?
                .output
                .context("record")?;
            if field(&record, "cleanup_status")?.as_str() == Some("complete") {
                return Ok::<_, anyhow::Error>(record);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await?
}

async fn echo_submission(f: &Fixture) -> Result<ActionResult, ConsoleFailure> {
    f.call(
        ACTION_RUNTIME_OPERATION_SUBMIT,
        map_value([
            ("target", Value::string("effect://jobs/echo".into())),
            ("method", Value::string("invoke".into())),
        ]),
    )
    .await
}

#[tokio::test]
async fn completed_worker_keeps_custody_until_automatic_retry_without_replaying_body()
-> anyhow::Result<()> {
    let (f, fault) = fixture(one_slot(), false).await?;
    fault.fail.store(true, Ordering::SeqCst);
    let id = f.submit(echo()?, Value::bytes(vec![0, 255])).await?;
    let pending = f.finished(&id).await?;
    ensure!(field(&pending, "outcome")?.as_str() == Some("done"));
    ensure!(field(&pending, "cleanup_status")?.as_str() == Some("pending"));
    let ticket = f
        .state
        .boot
        .cleanup_ticket(process(field(&pending, "execution")?)?)?;
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Completed));
    ensure!(!ticket.is_complete());
    ensure!(fault.rejected.load(Ordering::SeqCst) > 0);
    let retained = result(&f, &id).await?;
    ensure!(field(field(&retained, "output")?, "value")? == &Value::bytes(vec![0, 255]));
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_FORGET, id_input(&id))
            .await
            .err()
            .context("pending cleanup must forbid forget")?
            .code
            == ConsoleErrorCode::BadRequest
    );
    ensure!(
        echo_submission(&f)
            .await
            .err()
            .context("cleanup quota")?
            .code
            == ConsoleErrorCode::RateLimited
    );
    super::super::cleanup::pass(&f.state).await;
    ensure!(field(&f.finished(&id).await?, "cleanup_status")?.as_str() == Some("pending"));
    fault.fail.store(false, Ordering::SeqCst);
    let complete = cleaned(&f, &id).await?;
    ensure!(field(&complete, "finished_at")? == field(&pending, "finished_at")?);
    ensure!(field(&complete, "expires_at")? == field(&pending, "expires_at")?);
    ensure!(field(&result(&f, &id).await?, "output")? == field(&retained, "output")?);
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    let next = f.submit(echo()?, Value::integer(9)).await?;
    cleaned(&f, &next).await?;
    ensure!(f.calls.load(Ordering::SeqCst) == 2);
    f.service.shutdown_executions().await;
    Ok(())
}

#[tokio::test]
async fn expired_results_remain_in_custody_until_automatic_cleanup_reclaims_capacity()
-> anyhow::Result<()> {
    let (f, fault) = fixture(
        ConsoleExecutionConfig {
            retention_ms: 100,
            max_records: 1,
            max_records_per_account: 1,
            ..one_slot()
        },
        false,
    )
    .await?;
    fault.fail.store(true, Ordering::SeqCst);
    let id = f.submit(echo()?, Value::integer(1)).await?;
    let pending = f.finished(&id).await?;
    ensure!(field(&pending, "cleanup_status")?.as_str() == Some("pending"));
    tokio::time::sleep(Duration::from_millis(150)).await;
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_GET, id_input(&id))
            .await
            .is_err()
    );
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
            .await
            .is_err()
    );
    ensure!(
        echo_submission(&f)
            .await
            .err()
            .context("expired custody quota")?
            .code
            == ConsoleErrorCode::RateLimited
    );
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    ensure!(fault.rejected.load(Ordering::SeqCst) > 0);
    fault.fail.store(false, Ordering::SeqCst);
    let accepted = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match echo_submission(&f).await {
                Ok(accepted) => return Ok::<_, anyhow::Error>(accepted),
                Err(error) if error.code == ConsoleErrorCode::RateLimited => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await??;
    let next = accepted
        .execution
        .context("next reference")?
        .execution_id
        .context("next execution")?;
    ensure!(next != id);
    f.wait_for_calls(2).await?;
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_GET, id_input(&id))
            .await
            .is_err()
    );
    f.service.shutdown_executions().await;
    ensure!(f.calls.load(Ordering::SeqCst) == 2);
    Ok(())
}

#[tokio::test]
async fn bounded_shutdown_and_cleanup_pass_leave_other_console_and_host_work_untouched()
-> anyhow::Result<()> {
    let (one, fault) = fixture(one_slot(), false).await?;
    let state = ConsoleState::with_config(
        one.state.boot.clone(),
        ConsoleConfig {
            session_store: Some(one.state.auth.session_store.clone()),
            runtime: one.state.runtime.config.clone(),
            ..Default::default()
        },
    )?;
    let two = Fixture {
        service: ConsoleService::new(state.clone()),
        state,
        token: one.token.clone(),
        calls: one.calls.clone(),
    };
    fault.fail.store(true, Ordering::SeqCst);
    let first = one.submit(echo()?, Value::integer(1)).await?;
    let second = two.submit(echo()?, Value::integer(2)).await?;
    let first_pending = one.finished(&first).await?;
    let second_pending = two.finished(&second).await?;
    let boot = &one.state.boot;
    let foreign = boot
        .request_under(boot.root(), IdentityRef::ROOT, &[])?
        .detach();
    let foreign_cleanup = boot.cleanup_ticket(foreign)?;
    ensure!(
        boot.finish_process_as(foreign, ProcessStatus::Completed)
            .await
            .is_err()
    );
    let generic_rows = xolotl_state::StateScan::new(Path::parse(&format!(
        "state://kernel/process/{}",
        foreign.get()
    ))?);
    let (one_shutdown, two_shutdown) = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(
            one.service.shutdown_executions(),
            two.service.shutdown_executions()
        )
    })
    .await?;
    ensure!(one_shutdown.volatile_cleanup_pending == 1);
    ensure!(two_shutdown.volatile_cleanup_pending == 1);
    ensure!(field(&one.finished(&first).await?, "cleanup_status")?.as_str() == Some("pending"));
    ensure!(field(&two.finished(&second).await?, "cleanup_status")?.as_str() == Some("pending"));
    ensure!(echo_submission(&one).await.is_err() && echo_submission(&two).await.is_err());
    fault.fail.store(false, Ordering::SeqCst);
    super::super::cleanup::pass(&one.state).await;
    let complete = one.finished(&first).await?;
    ensure!(field(&complete, "cleanup_status")?.as_str() == Some("complete"));
    ensure!(field(&complete, "expires_at")? == field(&first_pending, "expires_at")?);
    ensure!(field(&two.finished(&second).await?, "cleanup_status")?.as_str() == Some("pending"));
    ensure!(!foreign_cleanup.is_complete());
    ensure!(
        boot.kernel()
            .state()
            .query(&generic_rows)
            .await?
            .entries
            .is_empty()
    );
    super::super::cleanup::pass(&two.state).await;
    let complete = two.finished(&second).await?;
    ensure!(field(&complete, "cleanup_status")?.as_str() == Some("complete"));
    ensure!(field(&complete, "expires_at")? == field(&second_pending, "expires_at")?);
    let (one_shutdown, two_shutdown) = tokio::join!(
        one.service.shutdown_executions(),
        two.service.shutdown_executions()
    );
    ensure!(one_shutdown.volatile_cleanup_pending == 0);
    ensure!(two_shutdown.volatile_cleanup_pending == 0);
    ensure!(!foreign_cleanup.is_complete());
    ensure!(foreign_cleanup.terminal_status() == Some(ProcessStatus::Completed));
    ensure!(
        boot.kernel()
            .state()
            .query(&generic_rows)
            .await?
            .entries
            .is_empty()
    );
    ensure!(one.calls.load(Ordering::SeqCst) == 2);
    boot.finish_process_as(foreign, ProcessStatus::Completed)
        .await?;
    ensure!(foreign_cleanup.is_complete());
    ensure!(
        boot.resume_cleanup(&foreign_cleanup).await? == xolotl_kernel::CleanupProgress::Completed
    );
    ensure!(boot.kernel().handles().is_empty());
    ensure!(
        boot.kernel()
            .state()
            .query(&generic_rows)
            .await?
            .entries
            .is_empty()
    );
    Ok(())
}

#[derive(Default)]
struct HeldChild {
    calls: AtomicUsize,
    entered: Notify,
    release: Notify,
}

#[async_trait::async_trait]
impl Driver for HeldChild {
    async fn call(
        &self,
        _: MethodId,
        input: Value,
        _: OutputMode,
        _: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        self.release.notified().await;
        Ok(DriverOutput::new(Outcome::Done(input)))
    }
}

fn held_child(f: &Fixture) -> anyhow::Result<(Arc<HeldChild>, Expression)> {
    let body = Arc::new(HeldChild::default());
    let target = Path::parse("effect://jobs/held-child")?;
    f.state.boot.register_effect(
        "effect://jobs/held-child",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        body.clone(),
    )?;
    let invoke = Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(target),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::AsyncProcess,
            literal_input: None,
        },
    };
    Ok((body, invoke))
}

#[tokio::test]
async fn local_parent_cleanup_retry_does_not_cancel_an_independently_owned_child()
-> anyhow::Result<()> {
    let (f, fault) = fixture(config(), true).await?;
    let (body, invoke) = held_child(&f)?;
    fault.fail.store(true, Ordering::SeqCst);
    let parent = f.submit(invoke, Value::integer(41)).await?;
    let pending = f.finished(&parent).await?;
    ensure!(field(&pending, "cleanup_status")?.as_str() == Some("pending"));
    tokio::time::timeout(Duration::from_secs(1), body.entered.notified()).await?;
    let retained = result(&f, &parent).await?;
    let reference = field(field(&retained, "output")?, "value")?;
    let child = field(reference, "execution_id")?
        .as_str()
        .context("child execution")?;
    let child_process = process(reference)?;
    fault.fail.store(false, Ordering::SeqCst);
    cleaned(&f, &parent).await?;
    ensure!(
        f.state.boot.kernel().processes().status(child_process) == Some(ProcessStatus::Running)
    );
    let record = f
        .call(ACTION_RUNTIME_EXECUTION_GET, id_input(child))
        .await?
        .output
        .context("child record")?;
    ensure!(field(&record, "status")?.as_str() == Some("running"));
    ensure!(body.calls.load(Ordering::SeqCst) == 1);
    body.release.notify_one();
    let completed = cleaned(&f, child).await?;
    ensure!(field(&completed, "outcome")?.as_str() == Some("done"));
    ensure!(field(field(&result(&f, child).await?, "output")?, "value")? == &Value::integer(41));
    ensure!(body.calls.load(Ordering::SeqCst) == 1);
    f.service.shutdown_executions().await;
    Ok(())
}

#[tokio::test]
async fn expired_child_result_keeps_its_slot_until_automatic_cleanup_without_replaying_body()
-> anyhow::Result<()> {
    let (f, fault) = fixture(
        ConsoleExecutionConfig {
            retention_ms: 100,
            max_concurrent: 2,
            max_concurrent_per_account: 2,
            cleanup_timeout_ms: 20,
            ..config()
        },
        true,
    )
    .await?;
    let (body, invoke) = held_child(&f)?;
    let parent = f.submit(invoke, Value::integer(17)).await?;
    cleaned(&f, &parent).await?;
    let retained = result(&f, &parent).await?;
    let reference = field(field(&retained, "output")?, "value")?;
    let child = field(reference, "execution_id")?
        .as_str()
        .context("child execution")?;
    tokio::time::timeout(Duration::from_secs(1), body.entered.notified()).await?;
    // The parent has returned its slot. Keep that second slot occupied while
    // testing custody of the independently released child.
    let waiting = f.submit(wait(), Value::null()).await?;
    fault.fail.store(true, Ordering::SeqCst);
    body.release.notify_one();
    let pending = f.finished(child).await?;
    ensure!(field(&pending, "cleanup_status")?.as_str() == Some("pending"));
    ensure!(fault.rejected.load(Ordering::SeqCst) > 0);
    ensure!(field(field(&result(&f, child).await?, "output")?, "value")? == &Value::integer(17));
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_FORGET, id_input(child))
            .await
            .err()
            .context("child cleanup must forbid forget")?
            .code
            == ConsoleErrorCode::BadRequest
    );
    tokio::time::sleep(Duration::from_millis(150)).await;
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_GET, id_input(child))
            .await
            .is_err()
    );
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(child))
            .await
            .is_err()
    );
    ensure!(
        echo_submission(&f)
            .await
            .err()
            .context("expired child custody quota")?
            .code
            == ConsoleErrorCode::RateLimited
    );
    ensure!(body.calls.load(Ordering::SeqCst) == 1);
    ensure!(f.calls.load(Ordering::SeqCst) == 0);
    fault.fail.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match echo_submission(&f).await {
                Ok(_) => return Ok::<_, anyhow::Error>(()),
                Err(error) if error.code == ConsoleErrorCode::RateLimited => {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                Err(error) => return Err(error.into()),
            }
        }
    })
    .await??;
    f.wait_for_calls(1).await?;
    let still_waiting = f
        .call(ACTION_RUNTIME_EXECUTION_GET, id_input(&waiting))
        .await?
        .output
        .context("waiting sibling")?;
    ensure!(field(&still_waiting, "status")?.as_str() == Some("running"));
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_GET, id_input(child))
            .await
            .is_err()
    );
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(child))
            .await
            .is_err()
    );
    ensure!(body.calls.load(Ordering::SeqCst) == 1);
    f.service.shutdown_executions().await;
    ensure!(f.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn child_cleanup_panic_does_not_stop_supervision_and_shutdown_retains_retries()
-> anyhow::Result<()> {
    let (f, fault) = fixture(
        ConsoleExecutionConfig {
            max_concurrent: 2,
            max_concurrent_per_account: 2,
            cleanup_timeout_ms: 20,
            ..config()
        },
        true,
    )
    .await?;
    let (body, invoke) = held_child(&f)?;
    let parent = f.submit(invoke, Value::integer(73)).await?;
    cleaned(&f, &parent).await?;
    let retained = result(&f, &parent).await?;
    let reference = field(field(&retained, "output")?, "value")?;
    let child = field(reference, "execution_id")?
        .as_str()
        .context("child execution")?;
    tokio::time::timeout(Duration::from_secs(1), body.entered.notified()).await?;
    let waiting = f.submit(wait(), Value::null()).await?;
    fault.fail.store(true, Ordering::SeqCst);
    body.release.notify_one();
    let pending = f.finished(child).await?;
    ensure!(field(&pending, "cleanup_status")?.as_str() == Some("pending"));

    fault.panic_next.store(true, Ordering::SeqCst);
    fault.fail.store(false, Ordering::SeqCst);
    let complete = cleaned(&f, child).await?;
    ensure!(!fault.panic_next.load(Ordering::SeqCst));
    ensure!(fault.panics.load(Ordering::SeqCst) == 1);
    ensure!(field(&complete, "expires_at")? == field(&pending, "expires_at")?);
    ensure!(field(field(&result(&f, child).await?, "output")?, "value")? == &Value::integer(73));
    ensure!(body.calls.load(Ordering::SeqCst) == 1);
    let next = f.submit(echo()?, Value::null()).await?;
    cleaned(&f, &next).await?;
    ensure!(f.calls.load(Ordering::SeqCst) == 1);

    // Prepare a different pending cleanup before faulting shutdown itself.
    // Repeated shutdown must report the retained obligation, not unwind or
    // silently release its capacity when an extension panics again.
    fault.fail.store(true, Ordering::SeqCst);
    f.call(ACTION_RUNTIME_EXECUTION_CANCEL, id_input(&waiting))
        .await?;
    let pending = f.finished(&waiting).await?;
    ensure!(field(&pending, "cleanup_status")?.as_str() == Some("pending"));
    for _ in 0..2 {
        fault.panic_next.store(true, Ordering::SeqCst);
        let report =
            tokio::time::timeout(Duration::from_secs(1), f.service.shutdown_executions()).await?;
        ensure!(!fault.panic_next.load(Ordering::SeqCst));
        ensure!(report.volatile_cleanup_pending == 1);
    }
    fault.fail.store(false, Ordering::SeqCst);
    let report =
        tokio::time::timeout(Duration::from_secs(1), f.service.shutdown_executions()).await?;
    ensure!(report.volatile_cleanup_pending == 0);
    ensure!(fault.panics.load(Ordering::SeqCst) == 3);
    ensure!(field(&f.finished(&waiting).await?, "expires_at")? == field(&pending, "expires_at")?);
    ensure!(body.calls.load(Ordering::SeqCst) == 1 && f.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}
