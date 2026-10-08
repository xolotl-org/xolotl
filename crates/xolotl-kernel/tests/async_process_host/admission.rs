use super::*;
use std::{future::Future, pin::Pin};
use xolotl_kernel::InvocationOptions;

#[derive(Default)]
enum Reply {
    #[default]
    Accept,
    Reject,
    Panic,
}

struct PendingHost {
    inner: Arc<Host>,
    wait_before_reservation: bool,
    cancel_before_return: Option<Bootstrap>,
    reply: Reply,
    polled: AtomicUsize,
    dropped: AtomicUsize,
    resume: Notify,
}

impl PendingHost {
    fn new(inner: Arc<Host>) -> Self {
        Self {
            inner,
            wait_before_reservation: false,
            cancel_before_return: None,
            reply: Reply::Accept,
            polled: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
            resume: Notify::new(),
        }
    }
}

#[async_trait::async_trait]
impl AsyncProcessHost for PendingHost {
    async fn admit(&self, request: &AsyncProcessRequest) -> Result<AsyncProcessAdmission, Failure> {
        let _waiting = Running(&self.dropped);
        let reserved = if self.wait_before_reservation {
            None
        } else {
            Some(self.inner.admit(request).await?)
        };
        self.polled.fetch_add(1, Ordering::SeqCst);
        self.resume.notified().await;
        if let Some(boot) = &self.cancel_before_return {
            boot.cancel_process(request.source.process)
                .map_err(|_error| Failure::Cancelled)?;
        }
        match self.reply {
            Reply::Accept => match reserved {
                Some(admission) => Ok(admission),
                None => self.inner.admit(request).await,
            },
            Reply::Reject => Err(Failure::RateLimited),
            Reply::Panic => std::panic::resume_unwind(Box::new("host panicked after reserving")),
        }
    }
}

fn options() -> InvocationOptions {
    InvocationOptions {
        caller_identity: None,
        now_millis: 0,
        record: true,
    }
}

async fn paused(
    host: &PendingHost,
    execution: Pin<&mut impl Future<Output = xolotl_kernel::invocation::InvocationResult>>,
) -> anyhow::Result<()> {
    tokio::select! {
        output = execution => anyhow::bail!("admission did not wait: {:?}", output.output.outcome),
        ready = wait(|| host.polled.load(Ordering::SeqCst) == 1) => ready,
    }
}

fn no_child(f: &Fixture, parent: ProcessId, handles: usize, rejected: usize) -> anyhow::Result<()> {
    ensure!(f.body.calls.load(Ordering::SeqCst) == 0);
    ensure!(f.boot.kernel().processes().children_of(parent).is_empty());
    ensure!(f.boot.kernel().handles().len() == handles);
    ensure!(f.host.owner.rejected.load(Ordering::SeqCst) == rejected);
    ensure!(
        f.host
            .owner
            .published
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    );
    ensure!(
        f.host
            .owner
            .released
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty()
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn deadline_cancels_host_waits_and_releases_only_real_reservations() -> anyhow::Result<()> {
    for before in [false, true] {
        let f = Fixture::new()?;
        let request = f.request(RightFlags::SPAWN_WITH)?;
        let operation = f.invocation(&request)?;
        let host = Arc::new(PendingHost {
            wait_before_reservation: before,
            ..PendingHost::new(f.host.clone())
        });
        let dp = f
            .boot
            .kernel()
            .data_plane()
            .with_async_process_host(host.clone())
            .with_deadline(
                f.boot
                    .kernel()
                    .host_runtime()
                    .deadline_after(Duration::from_millis(80))
                    .context("admission deadline")?,
            )?;
        let handles = f.boot.kernel().handles().len();
        let mut run = Box::pin(dp.execute(&operation, options()));
        paused(&host, run.as_mut()).await?;
        no_child(&f, request.id(), handles, 0)?;
        let output = run.await;
        ensure!(output.output.outcome == Outcome::Fail(Failure::Timeout));
        ensure!(output.output.taint == operation.taint);
        ensure!(host.dropped.load(Ordering::SeqCst) == 1);
        no_child(&f, request.id(), handles, usize::from(!before))?;
        request
            .finish(&ExecutionOutput {
                outcome: output.output.outcome,
                taint: output.output.taint,
                unresolved_operations: Default::default(),
            })
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn parent_cancellation_interrupts_pending_admission_without_a_deadline() -> anyhow::Result<()>
{
    let f = Fixture::new()?;
    let request = f.request(RightFlags::SPAWN_WITH)?;
    let operation = f.invocation(&request)?;
    let host = Arc::new(PendingHost::new(f.host.clone()));
    let dp = f
        .boot
        .kernel()
        .data_plane()
        .with_async_process_host(host.clone());
    let handles = f.boot.kernel().handles().len();
    let mut run = Box::pin(dp.execute(&operation, options()));
    paused(&host, run.as_mut()).await?;
    ensure!(f.boot.cancel_process(request.id())?);
    let output = tokio::time::timeout(Duration::from_secs(2), run).await?;
    ensure!(output.output.outcome == Outcome::Fail(Failure::Cancelled));
    ensure!(host.dropped.load(Ordering::SeqCst) == 1);
    no_child(&f, request.id(), handles, 1)?;
    request
        .finish(&ExecutionOutput {
            outcome: output.output.outcome,
            taint: output.output.taint,
            unresolved_operations: Default::default(),
        })
        .await?;
    Ok(())
}

#[tokio::test]
async fn cancellation_in_the_hosts_final_poll_rejects_new_and_reconciled_acceptance()
-> anyhow::Result<()> {
    for reconcile in [false, true] {
        let f = Fixture::new()?;
        let request = f.request(RightFlags::SPAWN_WITH)?;
        let operation = f.invocation(&request)?;
        let dp = f
            .boot
            .kernel()
            .data_plane()
            .with_async_process_host(f.host.clone());
        if reconcile {
            ensure!(matches!(
                dp.execute(&operation, options()).await.output.outcome,
                Outcome::Done(_)
            ));
            wait(|| f.body.calls.load(Ordering::SeqCst) == 1).await?;
            f.host.reconcile.store(true, Ordering::SeqCst);
        }
        let host = Arc::new(PendingHost {
            cancel_before_return: Some(f.boot.clone()),
            ..PendingHost::new(f.host.clone())
        });
        let dp = dp.with_async_process_host(host.clone());
        let processes = f.boot.kernel().processes().len();
        let handles = f.boot.kernel().handles().len();
        let mut run = Box::pin(dp.execute(&operation, options()));
        paused(&host, run.as_mut()).await?;
        host.resume.notify_one();
        let output = run.await;
        ensure!(output.output.outcome == Outcome::Fail(Failure::Cancelled));
        ensure!(output.output.taint == operation.taint);
        ensure!(f.boot.kernel().processes().len() == processes);
        ensure!(f.boot.kernel().handles().len() == handles);
        ensure!(f.host.owner.rejected.load(Ordering::SeqCst) == usize::from(!reconcile));
        ensure!(f.body.calls.load(Ordering::SeqCst) == usize::from(reconcile));
        if reconcile {
            f.body.release.notify_one();
            ensure!(f.published().await?.is_some());
        } else {
            no_child(&f, request.id(), handles, 1)?;
        }
        request
            .finish(&ExecutionOutput {
                outcome: output.output.outcome,
                taint: output.output.taint,
                unresolved_operations: Default::default(),
            })
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn dropping_the_call_releases_a_reservation_held_across_await() -> anyhow::Result<()> {
    let f = Fixture::new()?;
    let request = f.request(RightFlags::SPAWN_WITH)?;
    let operation = f.invocation(&request)?;
    let host = Arc::new(PendingHost::new(f.host.clone()));
    let dp = f
        .boot
        .kernel()
        .data_plane()
        .with_async_process_host(host.clone());
    let handles = f.boot.kernel().handles().len();
    let mut run = Box::pin(dp.execute(&operation, options()));
    paused(&host, run.as_mut()).await?;
    drop(run);
    ensure!(host.dropped.load(Ordering::SeqCst) == 1);
    no_child(&f, request.id(), handles, 1)?;
    request
        .finish(&ExecutionOutput {
            outcome: Outcome::Fail(Failure::Cancelled),
            taint: operation.taint,
            unresolved_operations: Default::default(),
        })
        .await?;
    Ok(())
}

#[tokio::test]
async fn delayed_admission_transfers_the_guard_once_before_driver_dispatch() -> anyhow::Result<()> {
    let f = Fixture::new()?;
    let request = f.request(RightFlags::SPAWN_WITH)?;
    let operation = f.invocation(&request)?;
    let host = Arc::new(PendingHost::new(f.host.clone()));
    let dp = f
        .boot
        .kernel()
        .data_plane()
        .with_async_process_host(host.clone());
    let handles = f.boot.kernel().handles().len();
    let mut run = Box::pin(dp.execute(&operation, options()));
    paused(&host, run.as_mut()).await?;
    no_child(&f, request.id(), handles, 0)?;
    host.resume.notify_one();
    let output = run.await;
    ensure!(output.output.outcome == Outcome::Done(Value::string("my-host-reference".into())));
    wait(|| f.body.calls.load(Ordering::SeqCst) == 1).await?;
    ensure!(host.dropped.load(Ordering::SeqCst) == 1);
    ensure!(f.host.owner.rejected.load(Ordering::SeqCst) == 0);
    f.body.release.notify_one();
    ensure!(f.published().await?.context("body")?.outcome == Outcome::Done(operation.input));
    request
        .finish(&ExecutionOutput {
            outcome: output.output.outcome,
            taint: output.output.taint,
            unresolved_operations: Default::default(),
        })
        .await?;
    Ok(())
}

#[tokio::test]
async fn error_or_panic_after_await_releases_the_unaccepted_guard() -> anyhow::Result<()> {
    for reply in [Reply::Reject, Reply::Panic] {
        let f = Fixture::new()?;
        let request = f.request(RightFlags::SPAWN_WITH)?;
        let operation = f.invocation(&request)?;
        let host = Arc::new(PendingHost {
            reply,
            ..PendingHost::new(f.host.clone())
        });
        let dp = f
            .boot
            .kernel()
            .data_plane()
            .with_async_process_host(host.clone());
        let handles = f.boot.kernel().handles().len();
        let mut run = Box::pin(dp.execute(&operation, options()));
        paused(&host, run.as_mut()).await?;
        host.resume.notify_one();
        let output = run.await;
        ensure!(matches!(output.output.outcome, Outcome::Fail(_)));
        ensure!(host.dropped.load(Ordering::SeqCst) == 1);
        no_child(&f, request.id(), handles, 1)?;
        request
            .finish(&ExecutionOutput {
                outcome: output.output.outcome,
                taint: output.output.taint,
                unresolved_operations: Default::default(),
            })
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn delayed_acceptance_rechecks_authority_and_kernel_capacity() -> anyhow::Result<()> {
    for revoke in [false, true] {
        let f = Fixture::new()?;
        let request = f.request(RightFlags::SPAWN_WITH)?;
        let operation = f.invocation(&request)?;
        let host = Arc::new(PendingHost::new(f.host.clone()));
        let dp = f
            .boot
            .kernel()
            .data_plane()
            .with_async_process_host(host.clone());
        let handles = f.boot.kernel().handles().len();
        let mut run = Box::pin(dp.execute(&operation, options()));
        paused(&host, run.as_mut()).await?;
        if revoke {
            ensure!(f.boot.kernel().handles().revoke(operation.handle));
        } else {
            f.boot
                .kernel()
                .processes()
                .set_capacity(std::num::NonZeroUsize::new(2))?;
        }
        host.resume.notify_one();
        let output = run.await;
        ensure!(matches!(output.output.outcome, Outcome::Fail(_)));
        no_child(&f, request.id(), handles - usize::from(revoke), 1)?;
        request
            .finish(&ExecutionOutput {
                outcome: output.output.outcome,
                taint: output.output.taint,
                unresolved_operations: Default::default(),
            })
            .await?;
    }
    Ok(())
}

#[tokio::test]
async fn delayed_child_derivation_rechecks_both_grant_domains_at_current_time() -> anyhow::Result<()>
{
    let f = Fixture::new()?;
    let expires = f
        .boot
        .kernel()
        .host_runtime()
        .now_millis()
        .saturating_add(50);
    let request = f.boot.request_under(
        f.boot.root(),
        IdentityRef::ROOT,
        &[
            CompiledRequestGrantTemplate {
                selector: ResourceSelector::parse("perform://effect/host-test@tenant=alice")?,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::name("invoke"),
                    RightFlags::empty(),
                ),
            },
            CompiledRequestGrantTemplate {
                selector: ResourceSelector::parse(&format!(
                    "perform://effect/host-test@until={expires}"
                ))?,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::none(),
                    RightFlags::SPAWN_WITH,
                ),
            },
        ],
    )?;
    let mut operation = f.invocation(&request)?;
    operation.input = Value::map(std::collections::BTreeMap::from([(
        "tenant".into(),
        Value::string("alice".into()),
    )]));
    let host = Arc::new(PendingHost::new(f.host.clone()));
    let dp = f
        .boot
        .kernel()
        .data_plane()
        .with_async_process_host(host.clone());
    let handles = f.boot.kernel().handles().len();
    let mut run = Box::pin(dp.execute(&operation, options()));
    paused(&host, run.as_mut()).await?;
    wait(|| f.boot.kernel().host_runtime().now_millis() > expires).await?;
    host.resume.notify_one();
    let output = run.await;
    ensure!(matches!(output.output.outcome, Outcome::Fail(_)));
    no_child(&f, request.id(), handles, 1)?;
    request
        .finish(&ExecutionOutput {
            outcome: output.output.outcome,
            taint: output.output.taint,
            unresolved_operations: Default::default(),
        })
        .await?;
    Ok(())
}

#[tokio::test]
async fn delayed_receipt_cannot_bypass_revoked_propagation() -> anyhow::Result<()> {
    let f = Fixture::new()?;
    let request = f.request(RightFlags::SPAWN_WITH)?;
    let operation = f.invocation(&request)?;
    let dp = f
        .boot
        .kernel()
        .data_plane()
        .with_async_process_host(f.host.clone());
    let accepted = dp.execute(&operation, options()).await;
    ensure!(matches!(accepted.output.outcome, Outcome::Done(_)));
    wait(|| f.body.calls.load(Ordering::SeqCst) == 1).await?;
    f.host.reconcile.store(true, Ordering::SeqCst);
    let host = Arc::new(PendingHost::new(f.host.clone()));
    let dp = dp.with_async_process_host(host.clone());
    let processes = f.boot.kernel().processes().len();
    let handles = f.boot.kernel().handles().len();
    let mut run = Box::pin(dp.execute(&operation, options()));
    paused(&host, run.as_mut()).await?;
    ensure!(f.boot.kernel().handles().revoke(operation.handle));
    host.resume.notify_one();
    ensure!(matches!(
        run.await.output.outcome,
        Outcome::Fail(Failure::PermissionDenied { .. })
    ));
    ensure!(
        f.boot.kernel().processes().len() == processes
            && f.boot.kernel().handles().len() == handles - 1
    );
    ensure!(f.host.owner.rejected.load(Ordering::SeqCst) == 0);
    f.body.release.notify_one();
    ensure!(f.published().await?.is_some());
    ensure!(f.body.calls.load(Ordering::SeqCst) == 1);
    request
        .finish(&ExecutionOutput {
            outcome: accepted.output.outcome,
            taint: accepted.output.taint,
            unresolved_operations: Default::default(),
        })
        .await?;
    Ok(())
}

#[test]
fn abandoned_admission_releases_its_owner_even_if_the_hook_panics() -> anyhow::Result<()> {
    for panics in [false, true] {
        let owner = Arc::new(Owner::default());
        owner.rejection_panics.store(panics, Ordering::SeqCst);
        drop(AsyncProcessAdmission::new(Value::null(), owner.clone()));
        ensure!(owner.rejected.load(Ordering::SeqCst) == 1);
    }
    Ok(())
}
