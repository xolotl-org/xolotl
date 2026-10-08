//! Live cleanup preserves ownership, uncertain results and effect identities.

use super::*;
use anyhow::ensure;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use xolotl_types::IdentityRef;

use crate::host::{BlockingJob, BlockingSpawnError, BlockingSpawner, HostRuntime};
use anyhow::Context;
use std::sync::Mutex;
use tokio::sync::Notify;

struct LiveFinalizerAuthorizer {
    revoked: AtomicBool,
    pending: bool,
    entered: Notify,
}

#[async_trait::async_trait]
impl crate::RequestAuthorizer for LiveFinalizerAuthorizer {
    async fn authorize(&self) -> Result<(), xolotl_types::Failure> {
        self.entered.notify_one();
        if self.pending {
            return std::future::pending().await;
        }
        if self.revoked.load(Ordering::SeqCst) {
            Err(xolotl_types::Failure::policy(
                "request",
                "ownership revoked",
            ))
        } else {
            Ok(())
        }
    }
}

fn live_finalizer_fixture(
    boot: &Bootstrap,
    authorizer: Arc<LiveFinalizerAuthorizer>,
) -> anyhow::Result<(ProcessId, xolotl_types::HandleId, Arc<AtomicUsize>)> {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let target = boot.register_effect(
        "effect://cleanup/authorized",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )
        .finalize_allowed()],
        Arc::new(crate::driver::FnDriver(move |_, input| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(input)
        })),
    )?;
    let process = boot.kernel().processes().fresh_id()?;
    let planned = boot.plan_request_grants(
        boot.root(),
        &[ParsedRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/cleanup/authorized")?,
            rights: Some(GrantRights::new(
                GrantMethods::name("invoke"),
                RightFlags::empty(),
            )),
        }],
    )?;
    let mut entry = boot.request_process_entry(process, boot.root(), IdentityRef::ROOT, planned);
    entry.scope.start();
    entry
        .on_finalize
        .push(xolotl_graph::DoNode::op(xolotl_graph::OperationTemplate {
            target: target.clone(),
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(xolotl_types::Value::null()),
        }));
    boot.kernel().processes().admit_child(entry)?;
    let handle = boot.open_for(process, &target, "perform")?;
    drop(
        boot.kernel()
            .executor_for(process)
            .with_request_authorizer(authorizer),
    );
    Ok((process, handle, calls))
}

#[tokio::test]
async fn revoked_finalizer_authority_denies_effect_but_releases_local_resources()
-> anyhow::Result<()> {
    let boot = crate::fact::testing::observing_bootstrap();
    let authorizer = Arc::new(LiveFinalizerAuthorizer {
        revoked: AtomicBool::new(false),
        pending: false,
        entered: Notify::new(),
    });
    let (process, handle, calls) = live_finalizer_fixture(&boot, authorizer.clone())?;
    authorizer.revoked.store(true, Ordering::SeqCst);
    boot.finalize_process(process).await?;
    let report = boot
        .kernel()
        .processes()
        .finalization_report(process)
        .context("missing cleanup evidence")?;
    ensure!(calls.load(Ordering::SeqCst) == 0);
    ensure!(report.status == ProcessStatus::Cancelled);
    ensure!(report.finalizer_failures.len() == 1);
    ensure!(matches!(&report.finalizer_failures[0].1.failure,
            xolotl_types::Failure::PolicyViolation { policy, .. } if policy == "request"));
    ensure!(report.unresolved_operations.operation_ids.is_empty());
    ensure!(!report.unresolved_operations.identities_incomplete);
    ensure!(report.revoked_handles >= 1);
    ensure!(boot.kernel().handles().get(handle).is_none());
    ensure!(boot.kernel().handles().is_empty());
    ensure!(
        boot.kernel()
            .processes()
            .budget_mut(process, |budget| budget.inflight_ops)
            == Some(0)
    );
    ensure!(boot.cleanup_ticket(process)?.is_complete());
    ensure!(boot.kernel().facts().facts_of(process)?.is_empty());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn pending_finalizer_authorization_uses_cleanup_deadline_after_body_cancellation()
-> anyhow::Result<()> {
    let boot = Bootstrap::from_kernel(
        crate::KernelBuilder::in_memory()
            .with_execution_config(crate::ExecutionConfig {
                cleanup_timeout: std::time::Duration::from_secs(5),
                ..Default::default()
            })
            .build(),
    );
    let authorizer = Arc::new(LiveFinalizerAuthorizer {
        revoked: AtomicBool::new(false),
        pending: true,
        entered: Notify::new(),
    });
    let (process, handle, calls) = live_finalizer_fixture(&boot, authorizer.clone())?;
    ensure!(boot.cancel_process(process)?);
    let cleanup = boot.finalize_process(process);
    tokio::pin!(cleanup);
    tokio::select! {
        result = &mut cleanup => anyhow::bail!("cleanup stopped before authorization: {result:?}"),
        () = authorizer.entered.notified() => {}
    }
    tokio::time::advance(std::time::Duration::from_secs(5)).await;
    cleanup.await?;
    let report = boot
        .kernel()
        .processes()
        .finalization_report(process)
        .context("missing cleanup evidence")?;
    ensure!(calls.load(Ordering::SeqCst) == 0);
    ensure!(report.finalizer_failures.len() == 1);
    ensure!(matches!(
        report.finalizer_failures[0].1.failure,
        xolotl_types::Failure::Timeout
    ));
    ensure!(report.revoked_handles >= 1);
    ensure!(boot.kernel().handles().get(handle).is_none());
    ensure!(boot.kernel().handles().is_empty());
    ensure!(
        boot.kernel()
            .processes()
            .budget_mut(process, |budget| budget.inflight_ops)
            == Some(0)
    );
    ensure!(boot.cleanup_ticket(process)?.is_complete());
    Ok(())
}

#[derive(Clone, Copy)]
enum ControlledBehavior {
    Reject,
    Hold,
}

struct ControlledBlocking {
    selected: usize,
    behavior: ControlledBehavior,
    calls: AtomicUsize,
    job: Mutex<Option<BlockingJob>>,
    available: Notify,
}

impl ControlledBlocking {
    fn new(selected: usize, behavior: ControlledBehavior) -> Self {
        Self {
            selected,
            behavior,
            calls: AtomicUsize::new(0),
            job: Mutex::new(None),
            available: Notify::new(),
        }
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
    async fn next_job(&self) -> anyhow::Result<BlockingJob> {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let notified = self.available.notified();
                let job = self
                    .job
                    .lock()
                    .map_err(|error| anyhow::anyhow!("cleanup job lock poisoned: {error}"))?
                    .take();
                if let Some(job) = job {
                    return Ok::<_, anyhow::Error>(job);
                }
                notified.await;
            }
        })
        .await
        .context("cleanup job was not admitted")?
    }
}

impl BlockingSpawner for ControlledBlocking {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.selected {
            match self.behavior {
                ControlledBehavior::Reject => return Err(BlockingSpawnError::AtCapacity),
                ControlledBehavior::Hold => {
                    *self
                        .job
                        .lock()
                        .map_err(|_error| BlockingSpawnError::Unavailable)? = Some(job);
                    self.available.notify_one();
                }
            }
        } else {
            std::thread::spawn(job);
        }
        Ok(())
    }
}

fn runtime(spawner: Arc<ControlledBlocking>) -> HostRuntime {
    HostRuntime::tokio_with_blocking(spawner)
}
fn run_job(job: BlockingJob) -> anyhow::Result<()> {
    std::thread::spawn(job).join().map_err(|payload| {
        anyhow::Error::msg(crate::bootstrap::panic_payload_message(
            "cleanup job",
            payload,
        ))
    })
}
use crate::policy::{CheckCtx, CompiledCheck, PolicyDecision, PolicySnapshot};

struct UnwindingHandleCapture(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl CompiledCheck for UnwindingHandleCapture {
    async fn evaluate(&self, _: &CheckCtx) -> PolicyDecision {
        PolicyDecision::Allow
    }

    fn name(&self) -> &'static str {
        "terminal-handle-destructor"
    }
}

impl Drop for UnwindingHandleCapture {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::panic::resume_unwind(Box::new("injected terminal handle destructor panic"));
    }
}

#[test]
fn terminal_handle_destructor_panic_preserves_closed_count_for_retry() -> anyhow::Result<()> {
    let boot = crate::fact::testing::observing_bootstrap();
    let kernel = boot.kernel();
    let processes = kernel.processes();
    let process = processes.fresh_id()?;
    let execution = kernel.execution_ids().allocate()?;
    let mut entry =
        crate::process::ProcessEntry::new(process, Some(boot.root()), IdentityRef::ROOT);
    entry.scope.initialize_lifecycle(execution);
    entry.scope.start();
    processes.admit_child(entry)?;

    let drops = Arc::new(AtomicUsize::new(0));
    let mut plan = crate::DriverPlan::new(xolotl_types::DriverId::new(1), None, 0);
    plan.insert(
        xolotl_types::MethodId::new(0),
        xolotl_types::MethodContract::new(
            0,
            xolotl_types::ReplayClass::Deterministic,
            xolotl_types::OutputModeSet::UNARY,
        ),
        Arc::new(crate::EchoDriver),
    );
    let handle = kernel.handles().insert(crate::Handle {
        id: xolotl_types::HandleId::new(0, 0),
        process,
        acting: IdentityRef::ROOT,
        open_verb: "perform".into(),
        resource: xolotl_types::ResourceId::new(1),
        rights: xolotl_types::Rights::new(
            xolotl_types::MethodBitmap::method(0),
            xolotl_types::RightFlags::empty(),
        ),
        driver_plan: plan,
        fast_path: crate::FastPath::Conditional(PolicySnapshot::new(vec![Arc::new(
            UnwindingHandleCapture(drops.clone()),
        )])),
        bound_path: None,
    })?;
    ensure!(
        processes.begin_finalizing(process, ProcessStatus::Completed) == FinalizeStart::Started
    );

    let guard = processes.finalization_guard(process);
    let first = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = guard;
        commit_process_terminal_record(processes, kernel.handles(), process)
    }));
    ensure!(first.is_err());
    ensure!(drops.load(Ordering::SeqCst) == 1);
    ensure!(kernel.handles().get(handle).is_none());
    ensure!(kernel.handles().try_write().is_some());
    ensure!(kernel.facts().facts_of(process)?.is_empty());
    ensure!(processes.record_handle_cleanup(process, 0, 0) == Some((1, 0)));

    ensure!(
        processes.begin_finalizing(process, ProcessStatus::Completed) == FinalizeStart::Started
    );
    let guard = processes.finalization_guard(process);
    let record = commit_process_terminal_record(processes, kernel.handles(), process)?;
    ensure!(record == ProcessStatus::Completed);
    ensure!(processes.record_handle_cleanup(process, 0, 0) == Some((1, 0)));
    ensure!(kernel.facts().facts_of(process)?.is_empty());
    drop(guard);
    Ok(())
}

#[tokio::test]
async fn cleanup_keeps_body_and_finalizer_reconciliation_ids() -> anyhow::Result<()> {
    let boot = crate::fact::testing::observing_bootstrap();
    let kernel = boot.kernel();
    let table = kernel.processes();
    let process = table.fresh_id()?;
    let execution = kernel.execution_ids().allocate()?;
    let mut entry =
        crate::process::ProcessEntry::new(process, Some(boot.root()), IdentityRef::ROOT);
    entry.scope.initialize_lifecycle(execution);
    entry.scope.start();
    entry
        .on_finalize
        .push(xolotl_graph::DoNode::pure(xolotl_types::Value::null()));
    table.admit_child(entry)?;
    ensure!(table.begin_finalizing(process, ProcessStatus::Completed) == FinalizeStart::Started);
    let guard = table.finalization_guard(process);

    let mut body = xolotl_types::UnresolvedOperations::default();
    body.record("external-body-id");
    table
        .retain_finalization_control(process, &xolotl_types::TaintSet::pristine(), Some(&body))
        .ok_or_else(|| anyhow::anyhow!("missing finalization"))?;
    ensure!(table.next_finalizer(process).is_some());
    let mut finalizer = xolotl_types::UnresolvedOperations::default();
    finalizer.record("external-finalizer-id");
    finalizer.identities_incomplete = true;
    table
        .finish_finalizer(
            process,
            xolotl_types::ExecutionOutput::new(
                xolotl_types::Outcome::Done(xolotl_types::Value::null()),
                xolotl_types::TaintSet::pristine(),
            )
            .with_unresolved_operations(finalizer),
        )
        .ok_or_else(|| anyhow::anyhow!("missing active finalizer"))?;
    commit_process_terminal(table, kernel.handles(), kernel.state(), process, guard).await?;

    let unresolved = table
        .finalization_unresolved_operations(process)
        .context("missing reconciliation identities")?;
    ensure!(unresolved.operation_ids == ["external-body-id", "external-finalizer-id"]);
    ensure!(unresolved.identities_incomplete);
    ensure!(kernel.facts().facts_of(process)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn rejected_terminal_record_keeps_lifecycle_retryable() -> anyhow::Result<()> {
    let spawner = Arc::new(ControlledBlocking::new(1, ControlledBehavior::Reject));
    let boot = Bootstrap::from_kernel(
        crate::KernelBuilder::in_memory()
            .with_fact_sink(crate::FactSink::in_memory().0)
            .with_host_runtime(runtime(spawner.clone()))
            .build(),
    );
    let process =
        boot.spawn_request_process_under_with_request_grants(boot.root(), IdentityRef::ROOT, &[])?;

    let result = boot.finalize_process(process).await;
    ensure!(matches!(
        result,
        Err(BootstrapError::TerminalRecordScheduling(_))
    ));
    ensure!(spawner.calls() == 1);
    ensure!(boot.kernel().facts().facts_of(process)?.is_empty());
    boot.finalize_process(process).await?;
    ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Cancelled));
    Ok(())
}

#[tokio::test]
async fn discarded_terminal_record_reports_unknown_and_can_retry() -> anyhow::Result<()> {
    let spawner = Arc::new(ControlledBlocking::new(1, ControlledBehavior::Hold));
    let boot = Bootstrap::from_kernel(
        crate::KernelBuilder::in_memory()
            .with_fact_sink(crate::FactSink::in_memory().0)
            .with_host_runtime(runtime(spawner.clone()))
            .build(),
    );
    let process =
        boot.spawn_request_process_under_with_request_grants(boot.root(), IdentityRef::ROOT, &[])?;

    let first_boot = boot.clone();
    let first = tokio::spawn(async move { first_boot.finalize_process(process).await });
    drop(spawner.next_job().await?);
    ensure!(matches!(
        first.await?,
        Err(BootstrapError::TerminalRecordUnknown(_))
    ));
    ensure!(boot.kernel().facts().facts_of(process)?.is_empty());

    boot.finalize_process(process).await?;
    ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Cancelled));
    Ok(())
}

#[tokio::test]
async fn cancelled_waiter_does_not_release_active_terminal_record() -> anyhow::Result<()> {
    let spawner = Arc::new(ControlledBlocking::new(1, ControlledBehavior::Hold));
    let boot = Bootstrap::from_kernel(
        crate::KernelBuilder::in_memory()
            .with_fact_sink(crate::FactSink::in_memory().0)
            .with_host_runtime(runtime(spawner.clone()))
            .build(),
    );
    let process =
        boot.spawn_request_process_under_with_request_grants(boot.root(), IdentityRef::ROOT, &[])?;

    let first_boot = boot.clone();
    let first = tokio::spawn(async move { first_boot.finalize_process(process).await });
    let job = spawner.next_job().await?;
    first.abort();
    ensure!(first.await.is_err());
    ensure!(boot.kernel().facts().facts_of(process)?.is_empty());

    let retry_boot = boot.clone();
    let retry = tokio::spawn(async move { retry_boot.finalize_process(process).await });
    tokio::task::yield_now().await;
    ensure!(
        !retry.is_finished(),
        "retry overtook accepted handle disposal"
    );

    run_job(job)?;
    tokio::time::timeout(std::time::Duration::from_secs(2), retry).await???;
    ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Cancelled));
    ensure!(boot.cleanup_ticket(process)?.is_complete());
    ensure!(boot.kernel().facts().facts_of(process)?.is_empty());
    Ok(())
}
