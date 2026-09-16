//! Hosted task ownership, exit acknowledgement, and retained publications.

use super::{ProcessTable, TaskAttachment};
use crate::handle::HandleTable;
use parking_lot::RwLock;
use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use tokio::sync::{Notify, oneshot};
use tokio::task::AbortHandle;
use xolotl_types::{ExecutionOutput, Failure, Outcome, ProcessId, ProcessStatus};

tokio::task_local! {
    static BODY_PROCESS: (ProcessTable, Cell<Option<ProcessId>>);
    static FINALIZER_PROCESS: ProcessContext;
    static CLEANUP_PROCESS: ProcessContext;
}

#[derive(Clone)]
struct ProcessContext {
    table: ProcessTable,
    process: ProcessId,
    parent: Option<Arc<Self>>,
}

impl ProcessContext {
    fn process_for(&self, table: &ProcessTable) -> Option<ProcessId> {
        let mut current = Some(self);
        while let Some(context) = current {
            if Arc::ptr_eq(&context.table.inner, &table.inner) {
                return Some(context.process);
            }
            current = context.parent.as_deref();
        }
        None
    }
}

pub(crate) fn current_process(table: &ProcessTable) -> Option<ProcessId> {
    BODY_PROCESS
        .try_with(|(owner, process)| {
            Arc::ptr_eq(&owner.inner, &table.inner)
                .then(|| process.get())
                .flatten()
        })
        .ok()
        .flatten()
}

pub(crate) fn current_finalizer(table: &ProcessTable) -> Option<ProcessId> {
    FINALIZER_PROCESS
        .try_with(|context| context.process_for(table))
        .ok()
        .flatten()
}

pub(crate) fn current_cleanup(table: &ProcessTable) -> Option<ProcessId> {
    CLEANUP_PROCESS
        .try_with(|context| context.process_for(table))
        .ok()
        .flatten()
}

pub(crate) fn has_finalizer_context() -> bool {
    FINALIZER_PROCESS.try_with(|_| ()).is_ok()
}

pub(crate) async fn scope_finalizer<F: Future>(
    table: &ProcessTable,
    process: ProcessId,
    future: F,
) -> F::Output {
    let parent = FINALIZER_PROCESS
        .try_with(|context| Arc::new(context.clone()))
        .ok();
    FINALIZER_PROCESS
        .scope(
            ProcessContext {
                table: table.clone(),
                process,
                parent,
            },
            future,
        )
        .await
}

pub(crate) async fn scope_cleanup<F: Future>(
    table: &ProcessTable,
    process: ProcessId,
    future: F,
) -> F::Output {
    let parent = CLEANUP_PROCESS
        .try_with(|context| Arc::new(context.clone()))
        .ok();
    CLEANUP_PROCESS
        .scope(
            ProcessContext {
                table: table.clone(),
                process,
                parent,
            },
            future,
        )
        .await
}

pub(crate) fn outcome_status(outcome: &Outcome) -> ProcessStatus {
    match outcome {
        Outcome::Done(_) | Outcome::Short(_) => ProcessStatus::Completed,
        Outcome::Fail(Failure::Cancelled | Failure::Timeout) => ProcessStatus::Cancelled,
        Outcome::Fail(_) => ProcessStatus::Failed,
    }
}

#[async_trait::async_trait]
pub(crate) trait ProcessPublication: Send + Sync + 'static {
    async fn publish(
        &self,
        state: &xolotl_state::Backend,
        process: ProcessId,
        status: ProcessStatus,
        outcome: Option<&ExecutionOutput>,
    ) -> Result<(), crate::BootstrapError>;
}

pub(super) struct TaskRecord {
    abort: AbortHandle,
    state: Arc<TaskState>,
}

#[derive(Default)]
struct TaskState {
    accepted: AtomicBool,
    abandoned: AtomicBool,
    exited: AtomicBool,
    changed: Notify,
}

#[derive(Clone, Copy)]
enum DropPolicy {
    Finalize,
    #[cfg(feature = "durable")]
    RetainCheckpoint,
}

#[derive(Clone, Copy)]
enum AttachmentMode {
    Body,
    #[cfg(feature = "durable")]
    CheckpointCleanup,
}

/// Owns a task body. Drop requests cleanup; the enclosing task confirms exit.
pub(crate) struct TaskOwner {
    table: ProcessTable,
    handles: Arc<RwLock<HandleTable>>,
    process: ProcessId,
    state: Arc<TaskState>,
    policy: DropPolicy,
    owned: bool,
}

impl TaskOwner {
    /// The caller must drop its body future before transferring to finalization.
    pub(crate) fn finish(mut self, outcome: ExecutionOutput) -> Option<Arc<ExecutionOutput>> {
        let retained = self.table.retain_outcome(self.process, outcome);
        self.release();
        retained
    }

    fn release(&mut self) {
        self.owned = false;
        let _context = BODY_PROCESS.try_with(|(table, current)| {
            if Arc::ptr_eq(&table.inner, &self.table.inner) && current.get() == Some(self.process) {
                current.set(None);
            }
        });
        self.table.release_task(self.process, &self.state);
    }

    fn revoke(&self, process: ProcessId) {
        let revoked = self.handles.write().revoke_owned_by(process);
        self.table.record_revocation(process, revoked);
    }
}

impl Drop for TaskOwner {
    fn drop(&mut self) {
        if !self.owned {
            return;
        }
        let accepted = {
            // Serialize early runtime shutdown with attachment so a dead owner
            // can neither become accepted nor cancel a different accepted task.
            let _inner = self.table.inner.state.write();
            self.state.abandoned.store(true, Ordering::Release);
            self.state.accepted.load(Ordering::Acquire)
        };
        if !accepted {
            return;
        }
        match self.policy {
            DropPolicy::Finalize => {
                for process in self.table.request_cleanup_tree(self.process) {
                    if process != self.process {
                        self.table.abort_task(process);
                    }
                    self.revoke(process);
                }
            }
            #[cfg(feature = "durable")]
            DropPolicy::RetainCheckpoint => self.revoke(self.process),
        }
    }
}

struct TaskExit {
    table: ProcessTable,
    process: ProcessId,
    state: Arc<TaskState>,
}

impl Drop for TaskExit {
    fn drop(&mut self) {
        self.table.release_task(self.process, &self.state);
    }
}

struct ManagedTask<F> {
    future: Option<Pin<Box<F>>>,
    _exit: TaskExit,
}

impl<F: Future<Output = ()>> Future for ManagedTask<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        match self.get_mut().future.as_mut() {
            Some(future) => future.as_mut().poll(context),
            None => Poll::Ready(()),
        }
    }
}

impl<F> Drop for ManagedTask<F> {
    fn drop(&mut self) {
        // Dropping the owner alone does not drop sibling captures. Confirm exit
        // only after the entire callback future, including those captures, drops.
        drop(self.future.take());
    }
}

impl ProcessTable {
    pub(crate) fn spawn_task<F, Fut>(
        &self,
        process: ProcessId,
        handles: Arc<RwLock<HandleTable>>,
        run: F,
    ) -> Result<(), TaskAttachment>
    where
        F: FnOnce(TaskOwner) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.spawn_managed_task(
            process,
            handles,
            DropPolicy::Finalize,
            AttachmentMode::Body,
            run,
        )
    }

    #[cfg(feature = "durable")]
    pub(crate) fn spawn_recovery_task<F, Fut>(
        &self,
        process: ProcessId,
        handles: Arc<RwLock<HandleTable>>,
        run: F,
    ) -> Result<(), TaskAttachment>
    where
        F: FnOnce(TaskOwner) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.spawn_managed_task(
            process,
            handles,
            DropPolicy::RetainCheckpoint,
            AttachmentMode::Body,
            run,
        )
    }

    /// Attach terminal checkpoint cleanup without permitting another process body.
    #[cfg(feature = "durable")]
    pub(crate) fn spawn_checkpoint_cleanup_task<F, Fut>(
        &self,
        process: ProcessId,
        handles: Arc<RwLock<HandleTable>>,
        run: F,
    ) -> Result<(), TaskAttachment>
    where
        F: FnOnce(TaskOwner) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.spawn_managed_task(
            process,
            handles,
            DropPolicy::RetainCheckpoint,
            AttachmentMode::CheckpointCleanup,
            run,
        )
    }

    fn spawn_managed_task<F, Fut>(
        &self,
        process: ProcessId,
        handles: Arc<RwLock<HandleTable>>,
        policy: DropPolicy,
        mode: AttachmentMode,
        run: F,
    ) -> Result<(), TaskAttachment>
    where
        F: FnOnce(TaskOwner) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_missing| TaskAttachment::NoRuntime)?;
        let state = Arc::new(TaskState::default());
        let owner = TaskOwner {
            table: self.clone(),
            handles,
            process,
            state: state.clone(),
            policy,
            owned: true,
        };
        let (start, started) = oneshot::channel();
        let task = runtime.spawn(ManagedTask {
            future: Some(Box::pin(BODY_PROCESS.scope(
                (self.clone(), Cell::new(Some(process))),
                async move {
                    if started.await.is_ok() {
                        run(owner).await;
                    }
                },
            ))),
            _exit: TaskExit {
                table: self.clone(),
                process,
                state: state.clone(),
            },
        });
        let attachment = self.attach_managed_task(
            process,
            TaskRecord {
                abort: task.abort_handle(),
                state,
            },
            mode,
        );
        if attachment != TaskAttachment::Attached {
            task.abort();
            return Err(attachment);
        }
        let _started = start.send(());
        Ok(())
    }

    fn attach_managed_task(
        &self,
        process: ProcessId,
        task: TaskRecord,
        mode: AttachmentMode,
    ) -> TaskAttachment {
        let mut inner = self.inner.state.write();
        let Some(entry) = inner.procs.get(&process) else {
            return TaskAttachment::NoSuchProcess;
        };
        let accepts = match mode {
            AttachmentMode::Body => entry.accepts_children(),
            #[cfg(feature = "durable")]
            AttachmentMode::CheckpointCleanup => {
                entry.checkpoint != super::CheckpointState::None
                    && !entry.scope.finalized()
                    && !entry.scope.finalizer_active()
            }
        };
        if !accepts
            || task.state.abandoned.load(Ordering::Acquire)
            || task.state.exited.load(Ordering::Acquire)
        {
            return TaskAttachment::AlreadyTerminal;
        }
        if inner.tasks.contains_key(&process) {
            return TaskAttachment::AlreadyAttached;
        }
        task.state.accepted.store(true, Ordering::Release);
        inner.tasks.insert(process, task);
        TaskAttachment::Attached
    }

    pub(crate) fn has_task(&self, process: ProcessId) -> bool {
        self.inner.state.read().tasks.contains_key(&process)
    }

    /// Abort without releasing ownership before the body future has dropped.
    pub(crate) fn abort_task(&self, process: ProcessId) -> bool {
        let abort = self
            .inner
            .state
            .read()
            .tasks
            .get(&process)
            .map(|task| task.abort.clone());
        if let Some(abort) = abort {
            abort.abort();
            true
        } else {
            false
        }
    }

    pub(crate) async fn wait_for_task_exit(&self, process: ProcessId) {
        let state = self
            .inner
            .state
            .read()
            .tasks
            .get(&process)
            .map(|task| task.state.clone());
        let Some(state) = state else {
            return;
        };
        loop {
            let changed = state.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if state.exited.load(Ordering::Acquire) {
                return;
            }
            changed.await;
        }
    }

    fn release_task(&self, process: ProcessId, state: &Arc<TaskState>) {
        let removed = {
            let mut inner = self.inner.state.write();
            state.exited.store(true, Ordering::Release);
            let removed = if inner
                .tasks
                .get(&process)
                .is_some_and(|task| Arc::ptr_eq(&task.state, state))
            {
                inner.tasks.remove(&process)
            } else {
                None
            };
            inner.queue_reap_if_eligible(process);
            removed
        };
        drop(removed);
        state.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::DriverPlan;
    use crate::handle::{FastPath, Handle, HandleState};
    use crate::process::ProcessEntry;
    use anyhow::ensure;
    use std::time::Duration;
    use xolotl_types::{
        DriverId, HandleId, IdentityRef, MethodBitmap, ResourceId, RightFlags, Rights, TaintSet,
        Value,
    };

    fn fixture() -> anyhow::Result<(ProcessTable, Arc<RwLock<HandleTable>>, ProcessId, HandleId)> {
        let table = ProcessTable::new();
        let process = table.fresh_id()?;
        let mut entry = ProcessEntry::new(process, None, IdentityRef::ROOT);
        entry.scope.start();
        table.insert(entry);
        let handles = Arc::new(RwLock::new(HandleTable::new()));
        let handle = handles.write().insert(Handle {
            id: HandleId::new(0, 0),
            process,
            acting: IdentityRef::ROOT,
            resource: ResourceId::new(1),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: DriverPlan::new(DriverId::new(1), None, 0),
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        })?;
        Ok((table, handles, process, handle))
    }

    #[test]
    fn spawning_without_runtime_is_an_error_without_side_effects() -> anyhow::Result<()> {
        let (table, handles, process, handle) = fixture()?;
        let result = table.spawn_task(process, handles.clone(), |_owner| std::future::pending());
        ensure!(result == Err(TaskAttachment::NoRuntime));
        ensure!(table.status(process) == Some(ProcessStatus::Running));
        ensure!(table.pending_cleanup().is_empty());
        ensure!(!table.has_task(process));
        ensure!(handles.read().get(handle).is_some());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_before_first_poll_revokes_handles_and_queues_cleanup() -> anyhow::Result<()> {
        let (table, handles, process, handle) = fixture()?;
        let started = Arc::new(AtomicBool::new(false));
        let called = started.clone();
        ensure!(
            table
                .spawn_task(process, handles.clone(), move |owner| async move {
                    let _owner = owner;
                    called.store(true, Ordering::SeqCst);
                    std::future::pending::<()>().await;
                })
                .is_ok()
        );
        ensure!(table.abort_task(process));
        ensure!(table.has_task(process));
        tokio::time::timeout(Duration::from_secs(2), table.wait_for_task_exit(process)).await?;
        ensure!(!started.load(Ordering::SeqCst));
        ensure!(!table.has_task(process));
        ensure!(table.pending_cleanup() == vec![process]);
        ensure!(table.finalization_status(process) == Some(ProcessStatus::Cancelled));
        ensure!(handles.read().get(handle).is_none());
        Ok(())
    }

    #[test]
    fn runtime_shutdown_before_first_poll_retains_cleanup() -> anyhow::Result<()> {
        let (table, handles, process, handle) = fixture()?;
        let runtime = tokio::runtime::Builder::new_current_thread().build()?;
        let entered = runtime.enter();
        ensure!(
            table
                .spawn_task(process, handles.clone(), |owner| async move {
                    let _owner = owner;
                    std::future::pending::<()>().await;
                })
                .is_ok()
        );
        drop(entered);
        drop(runtime);
        ensure!(!table.has_task(process));
        ensure!(table.pending_cleanup() == vec![process]);
        ensure!(handles.read().get(handle).is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn duplicate_attachment_cannot_execute_or_cancel_existing_task() -> anyhow::Result<()> {
        let (table, handles, process, handle) = fixture()?;
        let (started, observed) = oneshot::channel();
        ensure!(
            table
                .spawn_task(process, handles.clone(), move |owner| async move {
                    let _owner = owner;
                    let _sent = started.send(());
                    std::future::pending::<()>().await;
                })
                .is_ok()
        );
        observed.await?;
        let called = Arc::new(AtomicBool::new(false));
        let called_by_rejected = called.clone();
        let (rejected_dropped, dropped) = oneshot::channel();
        struct RejectedDrop(Option<oneshot::Sender<()>>);
        impl Drop for RejectedDrop {
            fn drop(&mut self) {
                if let Some(sender) = self.0.take() {
                    let _sent = sender.send(());
                }
            }
        }
        let capture = RejectedDrop(Some(rejected_dropped));
        let result = table.spawn_task(process, handles.clone(), move |owner| async move {
            let (_owner, _capture) = (owner, capture);
            called_by_rejected.store(true, Ordering::SeqCst);
        });
        ensure!(result == Err(TaskAttachment::AlreadyAttached));
        dropped.await?;
        ensure!(!called.load(Ordering::SeqCst));
        ensure!(table.has_task(process));
        ensure!(table.status(process) == Some(ProcessStatus::Running));
        ensure!(table.pending_cleanup().is_empty());
        ensure!(handles.read().get(handle).is_some());
        table.abort_task(process);
        tokio::time::timeout(Duration::from_secs(2), table.wait_for_task_exit(process)).await?;
        Ok(())
    }

    struct BodyCapture {
        table: ProcessTable,
        process: ProcessId,
        state: Arc<TaskState>,
        dropped_before_exit: Arc<AtomicBool>,
    }

    impl Drop for BodyCapture {
        fn drop(&mut self) {
            self.dropped_before_exit.store(
                self.table.has_task(self.process) && !self.state.exited.load(Ordering::Acquire),
                Ordering::SeqCst,
            );
        }
    }

    struct PendingBody {
        // Drop the owner first to detect premature acknowledgement of body exit.
        _owner: TaskOwner,
        _capture: BodyCapture,
        started: Option<oneshot::Sender<()>>,
    }

    impl Future for PendingBody {
        type Output = ();

        fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<()> {
            if let Some(started) = self.get_mut().started.take() {
                let _sent = started.send(());
            }
            Poll::Pending
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn abort_waits_for_all_body_captures_to_drop() -> anyhow::Result<()> {
        let (table, handles, process, handle) = fixture()?;
        let capture_table = table.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_before_exit = dropped.clone();
        let (started, observed) = oneshot::channel();
        ensure!(
            table
                .spawn_task(process, handles.clone(), move |owner| {
                    let state = owner.state.clone();
                    PendingBody {
                        _owner: owner,
                        _capture: BodyCapture {
                            table: capture_table,
                            process,
                            state,
                            dropped_before_exit,
                        },
                        started: Some(started),
                    }
                })
                .is_ok()
        );
        observed.await?;
        ensure!(table.abort_task(process));
        ensure!(table.has_task(process));
        tokio::time::timeout(Duration::from_secs(2), table.wait_for_task_exit(process)).await?;
        ensure!(dropped.load(Ordering::SeqCst));
        ensure!(!table.has_task(process));
        ensure!(handles.read().get(handle).is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn normal_finish_retains_result_before_releasing_body_ownership() -> anyhow::Result<()> {
        let (table, handles, process, _handle) = fixture()?;
        let finished_table = table.clone();
        let (finished, observed) = oneshot::channel();
        ensure!(
            table
                .spawn_task(process, handles, move |owner| async move {
                    let owned = current_process(&finished_table) == Some(process);
                    let retained = owner.finish(ExecutionOutput {
                        outcome: Outcome::Done(Value::integer(42)),
                        taint: TaintSet::author(),
                    });
                    let released = current_process(&finished_table).is_none()
                        && !finished_table.has_task(process);
                    drop(finished.send((owned, released, retained)));
                })
                .is_ok()
        );
        let (owned, released, retained) = observed.await?;
        ensure!(owned && released);
        let retained = retained.ok_or_else(|| anyhow::anyhow!("outcome was lost"))?;
        ensure!(retained.outcome == Outcome::Done(Value::integer(42)));
        ensure!(retained.taint == TaintSet::author());
        ensure!(table.finalization_status(process) == Some(ProcessStatus::Completed));
        ensure!(table.status(process) == Some(ProcessStatus::Finalizing));
        ensure!(table.pending_cleanup() == vec![process]);
        let recorded = table
            .finalization_outcome(process)
            .ok_or_else(|| anyhow::anyhow!("outcome was not retained"))?;
        ensure!(Arc::ptr_eq(&retained, &recorded));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nested_finalizer_scopes_restore_previous_identity() -> anyhow::Result<()> {
        let table = ProcessTable::new();
        let outer = ProcessId::new(1);
        let inner = ProcessId::new(2);
        ensure!(current_finalizer(&table).is_none());
        scope_finalizer(&table, outer, async {
            ensure!(current_finalizer(&table) == Some(outer));
            scope_finalizer(&table, inner, async {
                ensure!(current_finalizer(&table) == Some(inner));
                ensure!(current_process(&table).is_none());
                Ok::<(), anyhow::Error>(())
            })
            .await?;
            ensure!(current_finalizer(&table) == Some(outer));
            Ok::<(), anyhow::Error>(())
        })
        .await?;
        ensure!(current_finalizer(&table).is_none());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn task_local_ownership_distinguishes_tables_with_identical_ids() -> anyhow::Result<()> {
        let (table, handles, process, _handle) = fixture()?;
        let (other, _other_handles, same_id, _other_handle) = fixture()?;
        ensure!(process == same_id);
        let scoped = table.clone();
        let (finished, observed) = oneshot::channel();
        ensure!(
            table
                .spawn_task(process, handles, move |owner| async move {
                    let body_matches = current_process(&scoped) == Some(process)
                        && current_process(&other).is_none();
                    let finalizer_matches = scope_finalizer(&scoped, process, async {
                        let outer_matches = current_finalizer(&scoped) == Some(process)
                            && current_finalizer(&other).is_none();
                        let inner_matches = scope_finalizer(&other, same_id, async {
                            current_finalizer(&other) == Some(same_id)
                                && current_finalizer(&scoped) == Some(process)
                                && current_process(&scoped) == Some(process)
                                && current_process(&other).is_none()
                        })
                        .await;
                        outer_matches
                            && inner_matches
                            && current_finalizer(&scoped) == Some(process)
                    })
                    .await;
                    drop(owner.finish(ExecutionOutput {
                        outcome: Outcome::Done(Value::null()),
                        taint: TaintSet::pristine(),
                    }));
                    let _sent = finished.send(
                        body_matches
                            && finalizer_matches
                            && current_process(&scoped).is_none()
                            && current_process(&other).is_none(),
                    );
                })
                .is_ok()
        );
        ensure!(observed.await?);
        Ok(())
    }

    #[cfg(feature = "durable")]
    #[tokio::test(flavor = "current_thread")]
    async fn checkpoint_cleanup_attaches_to_finalizing_and_remains_retryable_after_abort()
    -> anyhow::Result<()> {
        let (table, handles, process, handle) = fixture()?;
        let lifecycle = xolotl_types::ExecutionId::FIRST;
        ensure!(table.initialize_lifecycle(process, lifecycle) == Some(lifecycle));
        ensure!(
            table.begin_finalizing(process, ProcessStatus::Failed)
                == crate::process::FinalizeStart::Started
        );
        let guard = table.finalization_guard(process);
        drop(guard);
        ensure!(
            table.spawn_checkpoint_cleanup_task(process, handles.clone(), |_owner| {
                std::future::pending()
            }) == Err(TaskAttachment::AlreadyTerminal)
        );
        table.require_checkpoint(process, lifecycle)?;
        ensure!(
            table.spawn_recovery_task(process, handles.clone(), |_owner| std::future::pending())
                == Err(TaskAttachment::AlreadyTerminal)
        );
        let (started, observed) = oneshot::channel();
        ensure!(
            table
                .spawn_checkpoint_cleanup_task(process, handles.clone(), move |owner| async move {
                    let _owner = owner;
                    let _started = started.send(());
                    std::future::pending::<()>().await;
                })
                .is_ok()
        );
        observed.await?;
        ensure!(table.has_task(process));
        ensure!(
            table.spawn_checkpoint_cleanup_task(process, handles.clone(), |_owner| {
                std::future::pending()
            }) == Err(TaskAttachment::AlreadyAttached)
        );
        ensure!(table.abort_task(process));
        tokio::time::timeout(Duration::from_secs(2), table.wait_for_task_exit(process)).await?;
        ensure!(!table.has_task(process));
        ensure!(table.status(process) == Some(ProcessStatus::Finalizing));
        ensure!(table.finalization_status(process) == Some(ProcessStatus::Failed));
        ensure!(table.checkpoint_required(process) == Some(true));
        ensure!(table.checkpoint_retired(process) == Some(false));
        ensure!(handles.read().get(handle).is_none());
        let (retried, observed) = oneshot::channel();
        ensure!(
            table
                .spawn_checkpoint_cleanup_task(process, handles, move |owner| async move {
                    let _owner = owner;
                    let _retried = retried.send(());
                })
                .is_ok()
        );
        observed.await?;
        tokio::time::timeout(Duration::from_secs(2), table.wait_for_task_exit(process)).await?;
        ensure!(table.finalization_status(process) == Some(ProcessStatus::Failed));
        Ok(())
    }

    #[cfg(feature = "durable")]
    #[tokio::test(flavor = "current_thread")]
    async fn aborted_recovery_task_leaves_checkpoint_lifecycle_open() -> anyhow::Result<()> {
        let (table, handles, process, handle) = fixture()?;
        ensure!(
            table
                .spawn_recovery_task(process, handles.clone(), |owner| async move {
                    let _owner = owner;
                    std::future::pending::<()>().await;
                })
                .is_ok()
        );
        table.abort_task(process);
        tokio::time::timeout(Duration::from_secs(2), table.wait_for_task_exit(process)).await?;
        ensure!(table.status(process) == Some(ProcessStatus::Running));
        ensure!(table.pending_cleanup().is_empty());
        ensure!(table.finalization_status(process).is_none());
        ensure!(handles.read().get(handle).is_none());
        Ok(())
    }

    #[cfg(feature = "durable")]
    #[tokio::test(flavor = "current_thread")]
    async fn completed_recovery_callback_releases_task_without_choosing_terminal_intent()
    -> anyhow::Result<()> {
        let (table, handles, process, _handle) = fixture()?;
        let released_table = table.clone();
        let (released, observed) = oneshot::channel();
        ensure!(
            table
                .spawn_recovery_task(process, handles, move |owner| async move {
                    let _owner = owner;
                    let _sent = released.send(current_process(&released_table));
                })
                .is_ok()
        );
        ensure!(observed.await? == Some(process));
        tokio::time::timeout(Duration::from_secs(2), table.wait_for_task_exit(process)).await?;
        ensure!(!table.has_task(process));
        ensure!(table.status(process) == Some(ProcessStatus::Running));
        ensure!(table.finalization_status(process).is_none());
        ensure!(table.pending_cleanup().is_empty());
        Ok(())
    }
}
