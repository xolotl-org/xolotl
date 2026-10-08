use super::*;
use crate::{Bootstrap, BootstrapError, KernelBuilder};
use anyhow::{Context, ensure};
use futures_util::FutureExt;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use xolotl_state::{Backend, InMemoryBackend, StateMutation, StateRead, StateResult, StateWrite};
use xolotl_types::{ExecutionOutput, IdentityRef, Outcome, Path, TaintSet, Value};

fn request(boot: &Bootstrap, parent: ProcessId) -> anyhow::Result<ProcessId> {
    Ok(boot.request_under(parent, IdentityRef::ROOT, &[])?.detach())
}

fn output() -> ExecutionOutput {
    ExecutionOutput::new(Outcome::Done(Value::integer(42)), TaintSet::author())
}

#[derive(Default)]
struct FaultState {
    inner: InMemoryBackend,
    fail: AtomicBool,
}

impl StateRead for FaultState {
    type Read<'a> = <InMemoryBackend as StateRead>::Read<'a>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        self.inner.read_tainted(path)
    }
}

impl StateWrite for FaultState {
    type Write<'a> = std::pin::Pin<
        Box<dyn std::future::Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>,
    >;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            if matches!(mutation, StateMutation::Set(_)) && self.fail.swap(false, Ordering::SeqCst)
            {
                return Err(xolotl_state::StateError::Backend(
                    "business publication unavailable".into(),
                )
                .into());
            }
            self.inner.mutate(path, mutation).await
        })
    }
}

fn fault_fixture() -> (Bootstrap, Arc<FaultState>) {
    let state = Arc::new(FaultState::default());
    let boot = Bootstrap::from_kernel(
        KernelBuilder::new(
            Backend::new()
                .with_read(state.clone())
                .with_write(state.clone()),
        )
        .with_fact_sink(crate::FactSink::in_memory().0)
        .build(),
    );
    (boot, state)
}

struct FaultPublication;

#[async_trait::async_trait]
impl crate::process::ProcessPublication for FaultPublication {
    async fn publish(
        &self,
        state: &Backend,
        process: ProcessId,
        _: ProcessStatus,
        output: Option<&ExecutionOutput>,
    ) -> Result<(), BootstrapError> {
        let path = Path::parse(&format!("state://application/results/{}", process.get())).map_err(
            |source| BootstrapError::Path {
                literal: "application result".into(),
                source,
            },
        )?;
        state
            .write_set_tainted(
                &path,
                Value::integer(42),
                output.map_or_else(TaintSet::pristine, |output| output.taint.clone()),
            )
            .await
            .map_err(BootstrapError::from)?;
        Ok(())
    }
}

fn install_fault_publication(boot: &Bootstrap, process: ProcessId) -> anyhow::Result<()> {
    let mut table = boot.kernel().processes().inner.state.write();
    table
        .procs
        .get_mut(&process)
        .context("missing publication owner")?
        .publication = Some(Arc::new(FaultPublication));
    Ok(())
}

#[tokio::test]
async fn ticket_distinguishes_live_unknown_and_other_table_without_starting_cleanup()
-> anyhow::Result<()> {
    let boot = crate::fact::testing::observing_bootstrap();
    let process = request(&boot, boot.root())?;
    let ticket = boot.cleanup_ticket(process)?;
    ensure!(ticket.process() == process && !ticket.is_complete());
    ensure!(ticket.terminal_status().is_none());
    ensure!(boot.resume_cleanup(&ticket).await? == CleanupProgress::NotRequested);
    ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Running));
    ensure!(boot.cancel_process(process)?);
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Cancelled));
    ensure!(boot.resume_cleanup(&ticket).await? == CleanupProgress::NotRequested);
    ensure!(boot.kernel().facts().facts_of(process)?.is_empty());
    ensure!(matches!(
        boot.cleanup_ticket(ProcessId::new(u64::MAX)),
        Err(BootstrapError::NoSuchProcess { .. })
    ));
    let other = crate::fact::testing::observing_bootstrap();
    ensure!(request(&other, other.root())? == process);
    ensure!(matches!(
        other.resume_cleanup(&ticket).await,
        Err(BootstrapError::CleanupTicketMismatch { .. })
    ));
    ensure!(other.kernel().processes().status(process) == Some(ProcessStatus::Running));
    Ok(())
}

#[tokio::test]
async fn ticket_clones_pin_confirmation_until_host_acknowledges_and_allow_reap_after_drop()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let process = request(&boot, boot.root())?;
    let ticket = boot.cleanup_ticket(process)?;
    let cloned = ticket.clone();
    boot.finish_request_process(process, &output()).await?;
    ensure!(ticket.is_complete());
    ensure!(boot.resume_cleanup(&ticket).await? == CleanupProgress::Completed);
    ensure!(boot.kernel().processes().reap_finalized(usize::MAX) == 0);
    drop(ticket);
    ensure!(boot.kernel().processes().reap_finalized(usize::MAX) == 0);
    ensure!(cloned.is_complete());
    drop(cloned);
    ensure!(boot.kernel().processes().reap_finalized(usize::MAX) == 1);
    ensure!(matches!(
        boot.cleanup_ticket(process),
        Err(BootstrapError::NoSuchProcess { .. })
    ));
    Ok(())
}

#[tokio::test]
async fn retry_preserves_local_scope_and_leaves_unrelated_pending_cleanup_untouched()
-> anyhow::Result<()> {
    let (boot, state) = fault_fixture();
    let process = request(&boot, boot.root())?;
    install_fault_publication(&boot, process)?;
    let child = request(&boot, process)?;
    let other = request(&boot, boot.root())?;
    let ticket = boot.cleanup_ticket(process)?;
    boot.kernel().processes().request_cleanup_tree(other);
    state.fail.store(true, Ordering::SeqCst);
    ensure!(
        boot.finish_request_process(process, &output())
            .await
            .is_err()
    );
    ensure!(!ticket.is_complete());
    ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Completed));
    ensure!(boot.resume_cleanup(&ticket).await? == CleanupProgress::Completed);
    ensure!(ticket.is_complete());
    ensure!(boot.kernel().processes().status(child) == Some(ProcessStatus::Running));
    ensure!(boot.kernel().processes().pending_cleanup() == [other]);
    ensure!(boot.kernel().facts().facts_of(other)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn tree_retry_retains_descendant_obligation_after_ancestor_already_finalized()
-> anyhow::Result<()> {
    let (boot, state) = fault_fixture();
    let process = request(&boot, boot.root())?;
    let child = request(&boot, process)?;
    install_fault_publication(&boot, child)?;
    let other = request(&boot, boot.root())?;
    let ticket = boot.cleanup_ticket(process)?;
    boot.finish_request_process(process, &output()).await?;
    ensure!(ticket.is_complete());
    state.fail.store(true, Ordering::SeqCst);
    ensure!(boot.finalize_process(process).await.is_err());
    ensure!(!ticket.is_complete());
    ensure!(boot.kernel().processes().pending_cleanup() == [process]);
    ensure!(boot.resume_cleanup(&ticket).await? == CleanupProgress::Completed);
    ensure!(ticket.is_complete());
    ensure!(boot.kernel().processes().status(child) == Some(ProcessStatus::Cancelled));
    ensure!(boot.kernel().processes().status(other) == Some(ProcessStatus::Running));
    ensure!(boot.kernel().facts().facts_of(other)?.is_empty());
    ensure!(boot.kernel().processes().reap_finalized(usize::MAX) == 1);
    ensure!(ticket.is_complete());
    drop(ticket);
    ensure!(boot.kernel().processes().reap_finalized(usize::MAX) == 1);
    Ok(())
}

struct PublicationProbe {
    ticket: CleanupTicket,
    observed: AtomicBool,
}

#[async_trait::async_trait]
impl crate::process::ProcessPublication for PublicationProbe {
    async fn publish(
        &self,
        _: &Backend,
        _: ProcessId,
        _: ProcessStatus,
        _: Option<&ExecutionOutput>,
    ) -> Result<(), BootstrapError> {
        if self.ticket.is_complete() {
            return Err(BootstrapError::ProcessBusy {
                process: self.ticket.process(),
            });
        }
        self.observed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn publication_delivery_does_not_acknowledge_kernel_cleanup_or_finalizer_exit()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let process = request(&boot, boot.root())?;
    let ticket = boot.cleanup_ticket(process)?;
    let publication = Arc::new(PublicationProbe {
        ticket: ticket.clone(),
        observed: AtomicBool::new(false),
    });
    boot.kernel()
        .processes()
        .inner
        .state
        .write()
        .procs
        .get_mut(&process)
        .context("process")?
        .publication = Some(publication.clone());
    boot.finish_request_process(process, &output()).await?;
    ensure!(publication.observed.load(Ordering::SeqCst));
    ensure!(ticket.is_complete());

    let pending = request(&boot, boot.root())?;
    let pending_ticket = boot.cleanup_ticket(pending)?;
    let processes = boot.kernel().processes();
    ensure!(
        processes.begin_finalizing(pending, ProcessStatus::Completed)
            == crate::process::FinalizeStart::Started
    );
    let guard = processes.finalization_guard(pending);
    processes.mark_terminal_status(pending, ProcessStatus::Completed);
    processes
        .complete_finalization(pending)
        .context("finalization commit")?;
    ensure!(!pending_ticket.is_complete());
    drop(guard);
    ensure!(pending_ticket.is_complete());
    Ok(())
}

struct ReleaseProbe {
    table: Weak<ProcessTableShared>,
    process: ProcessId,
    ticket: Mutex<Option<CleanupTicket>>,
    complete_at_release: AtomicBool,
}

#[async_trait::async_trait]
impl crate::process::ProcessPublication for ReleaseProbe {
    fn released(&self, _: ProcessStatus, _: Option<&ExecutionOutput>) {
        let Some(inner) = self.table.upgrade() else {
            return;
        };
        let table = ProcessTable { inner };
        if let Ok(ticket) = table.cleanup_ticket(self.process) {
            self.complete_at_release
                .store(ticket.is_complete(), Ordering::SeqCst);
            *self.ticket.lock() = Some(ticket);
        }
    }

    async fn publish(
        &self,
        _: &Backend,
        _: ProcessId,
        _: ProcessStatus,
        _: Option<&ExecutionOutput>,
    ) -> Result<(), BootstrapError> {
        Ok(())
    }
}

#[tokio::test]
async fn unpolled_task_release_can_pin_cleanup_before_task_slot_is_released() -> anyhow::Result<()>
{
    let boot = Bootstrap::in_memory();
    let process = request(&boot, boot.root())?;
    ensure!(process == ProcessId::new(2));
    let processes = boot.kernel().processes();
    let publication = Arc::new(ReleaseProbe {
        table: Arc::downgrade(&processes.inner),
        process,
        ticket: Mutex::new(None),
        complete_at_release: AtomicBool::new(true),
    });
    processes
        .inner
        .state
        .write()
        .procs
        .get_mut(&process)
        .context("process")?
        .publication = Some(publication.clone());
    let polled = Arc::new(AtomicUsize::new(0));
    let observed = polled.clone();
    processes
        .spawn_task(
            process,
            boot.kernel().handles().clone(),
            move |_owner| async move {
                observed.fetch_add(1, Ordering::SeqCst);
                std::future::pending::<()>().await;
            },
        )
        .map_err(|error| anyhow::anyhow!("task attachment: {error:?}"))?;
    ensure!(processes.abort_task(process));
    tokio::time::timeout(
        Duration::from_secs(2),
        processes.wait_for_task_exit(process),
    )
    .await?;
    ensure!(polled.load(Ordering::SeqCst) == 0);
    ensure!(!publication.complete_at_release.load(Ordering::SeqCst));
    let ticket = publication
        .ticket
        .lock()
        .clone()
        .context("release ticket")?;
    ensure!(!ticket.is_complete());
    ensure!(boot.resume_cleanup(&ticket).await? == CleanupProgress::Completed);
    ensure!(ticket.is_complete());
    Ok(())
}

#[test]
fn publication_owned_ticket_does_not_keep_the_process_table_alive() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let process = request(&boot, boot.root())?;
    let ticket = boot.cleanup_ticket(process)?;
    let weak_table = Arc::downgrade(&boot.kernel().processes().inner);
    let publication = Arc::new(PublicationProbe {
        ticket: ticket.clone(),
        observed: AtomicBool::new(false),
    });
    let weak_publication = Arc::downgrade(&publication);
    boot.kernel()
        .processes()
        .inner
        .state
        .write()
        .procs
        .get_mut(&process)
        .context("process")?
        .publication = Some(publication);
    drop(boot);
    ensure!(weak_table.upgrade().is_none());
    ensure!(weak_publication.upgrade().is_none());
    ensure!(!ticket.is_complete());
    ensure!(ticket.terminal_status().is_none());
    drop(ticket);
    Ok(())
}

#[tokio::test]
async fn completed_scope_waits_for_direct_invocation_settlement_without_a_managed_task()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let process = request(&boot, boot.root())?;
    let ticket = boot.cleanup_ticket(process)?;
    let processes = boot.kernel().processes();
    processes
        .reserve(process, 0, 0)
        .map_err(anyhow::Error::msg)?;
    boot.finish_request_process(process, &output()).await?;
    ensure!(!ticket.is_complete());
    let mut retry = Box::pin(boot.resume_cleanup(&ticket));
    ensure!(retry.as_mut().now_or_never().is_none());
    processes.settle(process, 0, 0, 0, 0);
    ensure!(
        tokio::time::timeout(Duration::from_secs(2), retry).await?? == CleanupProgress::Completed
    );
    ensure!(ticket.is_complete());
    Ok(())
}

#[tokio::test]
async fn local_completion_does_not_wait_for_independent_child_account_occupancy()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let process = request(&boot, boot.root())?;
    let child = request(&boot, process)?;
    let ticket = boot.cleanup_ticket(process)?;
    let processes = boot.kernel().processes();
    processes.reserve(child, 0, 0).map_err(anyhow::Error::msg)?;
    boot.finish_request_process(process, &output()).await?;
    ensure!(ticket.is_complete());
    ensure!(boot.resume_cleanup(&ticket).await? == CleanupProgress::Completed);
    ensure!(processes.status(child) == Some(ProcessStatus::Running));
    processes.settle(child, 0, 0, 0, 0);
    Ok(())
}

#[tokio::test]
async fn cleanup_waiter_wakes_when_last_managed_task_releases_its_captures() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let process = request(&boot, boot.root())?;
    let ticket = boot.cleanup_ticket(process)?;
    let processes = boot.kernel().processes();
    let (started, running) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    processes
        .spawn_task(
            process,
            boot.kernel().handles().clone(),
            move |owner| async move {
                let _owner = owner;
                let _sent = started.send(());
                let _released = released.await;
            },
        )
        .map_err(|error| anyhow::anyhow!("task attachment: {error:?}"))?;
    tokio::time::timeout(Duration::from_secs(2), running).await??;
    ensure!(
        processes.begin_finalizing(process, ProcessStatus::Completed)
            == crate::process::FinalizeStart::Started
    );
    let guard = processes.finalization_guard(process);
    processes.mark_terminal_status(process, ProcessStatus::Completed);
    processes
        .complete_finalization(process)
        .context("finalization commit")?;
    drop(guard);
    ensure!(!ticket.is_complete());
    let mut retry = Box::pin(boot.resume_cleanup(&ticket));
    ensure!(retry.as_mut().now_or_never().is_none());
    release
        .send(())
        .map_err(|()| anyhow::anyhow!("task exited early"))?;
    ensure!(
        tokio::time::timeout(Duration::from_secs(2), retry).await?? == CleanupProgress::Completed
    );
    ensure!(ticket.is_complete());
    Ok(())
}

#[tokio::test]
async fn selected_tree_scope_survives_ancestor_completion() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let process = request(&boot, boot.root())?;
    let child = request(&boot, process)?;
    let ticket = boot.cleanup_ticket(process)?;
    let processes = boot.kernel().processes();
    {
        let mut inner = processes.inner.state.write();
        let entry = inner.procs.get_mut(&process).context("process")?;
        ensure!(entry.scope.cleanup_scope().is_none());
        ensure!(entry.scope.request_tree_cleanup());
    }
    ensure!(
        processes.begin_finalizing(process, ProcessStatus::Cancelled)
            == crate::process::FinalizeStart::Started
    );
    let guard = processes.finalization_guard(process);
    processes.mark_terminal_status(process, ProcessStatus::Cancelled);
    processes
        .complete_finalization(process)
        .context("finalization commit")?;
    drop(guard);
    ensure!(!ticket.is_complete());
    ensure!(processes.pending_cleanup() == [process]);
    ensure!(boot.resume_cleanup(&ticket).await? == CleanupProgress::Completed);
    ensure!(ticket.is_complete());
    ensure!(processes.status(child) == Some(ProcessStatus::Cancelled));
    Ok(())
}

#[tokio::test]
async fn terminal_observation_retains_first_decision_before_cleanup_is_committed()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let process = request(&boot, boot.root())?;
    let ticket = boot.cleanup_ticket(process)?;
    let processes = boot.kernel().processes();
    ensure!(
        processes.begin_finalizing(process, ProcessStatus::Cancelled)
            == crate::process::FinalizeStart::Started
    );
    let guard = processes.finalization_guard(process);
    ensure!(processes.status(process) == Some(ProcessStatus::Finalizing));
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Cancelled));
    ensure!(!ticket.is_complete());
    drop(guard);
    boot.finish_request_process(process, &output()).await?;
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Cancelled));
    ensure!(ticket.is_complete());
    Ok(())
}

#[tokio::test]
async fn normal_body_handoff_retains_captures_through_finalization_and_blocks_reap()
-> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let process = request(&boot, boot.root())?;
    let ticket = boot.cleanup_ticket(process)?;
    let processes = boot.kernel().processes();
    let task_processes = processes.clone();
    let (finished, observed) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    processes
        .spawn_task(
            process,
            boot.kernel().handles().clone(),
            move |owner| async move {
                let result = async {
                    let _outcome = owner.finish(output()).context("body outcome")?;
                    ensure!(
                        task_processes.begin_finalizing(process, ProcessStatus::Completed)
                            == crate::process::FinalizeStart::Started
                    );
                    let guard = task_processes.finalization_guard(process);
                    task_processes.mark_terminal_status(process, ProcessStatus::Completed);
                    task_processes
                        .complete_finalization(process)
                        .context("finalization commit")?;
                    drop(guard);
                    Ok::<(), anyhow::Error>(())
                }
                .await;
                drop(finished.send(result));
                let _released = released.await;
            },
        )
        .map_err(|error| anyhow::anyhow!("task attachment: {error:?}"))?;
    tokio::time::timeout(Duration::from_secs(2), observed).await???;
    ensure!(!processes.has_task(process));
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Completed));
    ensure!(!ticket.is_complete());
    drop(ticket);
    ensure!(processes.reap_finalized(usize::MAX) == 0);
    let ticket = boot.cleanup_ticket(process)?;
    let mut retry = Box::pin(boot.resume_cleanup(&ticket));
    ensure!(retry.as_mut().now_or_never().is_none());
    release
        .send(())
        .map_err(|()| anyhow::anyhow!("task exited early"))?;
    ensure!(
        tokio::time::timeout(Duration::from_secs(2), retry).await?? == CleanupProgress::Completed
    );
    ensure!(ticket.is_complete());
    drop(ticket);
    ensure!(processes.reap_finalized(usize::MAX) == 1);
    Ok(())
}
