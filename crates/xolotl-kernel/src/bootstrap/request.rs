//! Request ownership and host-driven completion of abandoned scopes.

use super::*;
use crate::Executor;
use std::sync::Arc;
use xolotl_types::ExecutionOutput;

enum RequestBootstrap<'a> {
    Borrowed(&'a Bootstrap),
    Shared(Arc<Bootstrap>),
}

/// Owns a request's lifecycle independently of its executor.
/// The host can be borrowed through [`Bootstrap::request_under`] or retained
/// through [`Bootstrap::request_under_owned`] when the request escapes its scope.
/// Dropping an unfinished scope cancels its tree and revokes handles immediately.
/// On a Tokio runtime, asynchronous lifecycle cleanup is scheduled once. Without
/// a runtime, or after cleanup failure, [`Bootstrap::drain_cleanup`] retries it.
/// Dropping an executor future cannot run its asynchronous `Finally` bodies.
#[must_use = "finish the request or explicitly transfer ownership with detach"]
pub struct RequestProcess<'a> {
    bootstrap: RequestBootstrap<'a>,
    process: ProcessId,
    owned: bool,
}

impl RequestProcess<'_> {
    fn bootstrap(&self) -> &Bootstrap {
        match &self.bootstrap {
            RequestBootstrap::Borrowed(bootstrap) => bootstrap,
            RequestBootstrap::Shared(bootstrap) => bootstrap,
        }
    }

    /// Identifier used for authority, cancellation and lifecycle records.
    pub fn id(&self) -> ProcessId {
        self.process
    }

    /// Create an executor bound to this request's authority.
    pub fn executor(&self) -> Executor {
        self.bootstrap().kernel.executor_for(self.process)
    }

    /// Finish after execution returns. Errors retain cleanup work for retry.
    pub async fn finish(mut self, output: &ExecutionOutput) -> Result<(), BootstrapError> {
        self.bootstrap()
            .finish_request_process(self.process, output)
            .await?;
        self.owned = false;
        Ok(())
    }

    /// Transfer lifecycle ownership to another host, such as checkpoint recovery.
    /// The recipient must eventually finish the returned process.
    pub fn detach(mut self) -> ProcessId {
        self.owned = false;
        self.process
    }
}

impl std::fmt::Debug for RequestProcess<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestProcess")
            .field("process", &self.process)
            .field("owned", &self.owned)
            .finish()
    }
}

impl Drop for RequestProcess<'_> {
    fn drop(&mut self) {
        if self.owned {
            self.bootstrap().abandon_request(self.process);
        }
    }
}

/// Failure retained for a later explicit cleanup attempt.
#[derive(Debug)]
pub struct ProcessCleanupFailure {
    /// Process whose lifecycle records or finalizers could not be completed.
    pub process: ProcessId,
    /// Cleanup error.
    pub error: BootstrapError,
}

/// Results from one pass over pending process cleanup, with no automatic retry loop.
#[derive(Debug, Default)]
pub struct ProcessCleanupReport {
    /// Cleanup requests completed, including work already won by another task.
    pub completed: usize,
    /// Process trees left pending for a subsequent attempt.
    pub failures: Vec<ProcessCleanupFailure>,
}

impl Bootstrap {
    /// Create an owned request with attenuated, precompiled authority.
    /// Scope creation and successful execution do not spawn a housekeeping task.
    pub fn request_under(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        grants: &[CompiledRequestGrantTemplate],
    ) -> Result<RequestProcess<'_>, BootstrapError> {
        let process = self
            .spawn_request_process_under_with_compiled_request_grants(anchor, identity, grants)?;
        Ok(self.own_process(process))
    }

    /// Create a request that retains its host beyond the caller's scope.
    /// This shares the supplied `Arc` without cloning the kernel and uses the
    /// same finish, detach, and cancellation lifecycle as [`Self::request_under`].
    pub fn request_under_owned(
        self: &Arc<Self>,
        anchor: ProcessId,
        identity: IdentityRef,
        grants: &[CompiledRequestGrantTemplate],
    ) -> Result<RequestProcess<'static>, BootstrapError> {
        let process = self
            .spawn_request_process_under_with_compiled_request_grants(anchor, identity, grants)?;
        Ok(RequestProcess {
            bootstrap: RequestBootstrap::Shared(Arc::clone(self)),
            process,
            owned: true,
        })
    }

    pub(super) fn own_process(&self, process: ProcessId) -> RequestProcess<'_> {
        RequestProcess {
            bootstrap: RequestBootstrap::Borrowed(self),
            process,
            owned: true,
        }
    }

    fn abandon_request(&self, process: ProcessId) {
        let descendants = self.kernel.processes.abandon_scope(process);
        let needs_cleanup = !descendants.is_empty();
        for descendant in descendants {
            self.kernel.processes.abort_task(descendant);
            super::finalize::close_process_handles(
                &self.kernel.processes,
                &self.kernel.handles,
                descendant,
            );
        }
        if needs_cleanup && let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let boot = self.clone();
            let cleanup = runtime.spawn(async move {
                if let Err(error) = boot.resume_cleanup(process).await {
                    tracing::warn!(process = process.get(), %error, "request cleanup remains pending");
                }
            });
            // The table retains progress even if the runtime shuts down this task.
            drop(cleanup);
        }
    }

    /// Finish abandoned scopes and interrupted finalizations, awaiting other owners as needed.
    /// This also works after the runtime that dropped a scope has shut down.
    /// Each pending tree is attempted once; failed work stays available for retry.
    pub async fn drain_cleanup(&self) -> ProcessCleanupReport {
        let mut report = ProcessCleanupReport::default();
        for process in self.kernel.processes.pending_cleanup() {
            match self.resume_cleanup(process).await {
                Ok(()) => report.completed += 1,
                Err(error) => report
                    .failures
                    .push(ProcessCleanupFailure { process, error }),
            }
        }
        report
    }

    async fn resume_cleanup(&self, process: ProcessId) -> Result<(), BootstrapError> {
        let Some((tree, status)) = self.kernel.processes.cleanup_scope(process) else {
            return Err(BootstrapError::NoSuchProcess { process });
        };
        if tree {
            self.finalize_process(process).await
        } else {
            self.finish_process_as(process, status).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use xolotl_graph::DoNode;
    use xolotl_state::{
        Backend, InMemoryBackend, StateMutation, StateRead, StateResult, StateWrite,
    };
    use xolotl_types::{Outcome, Value};

    fn marker(boot: &Bootstrap, process: ProcessId) -> anyhow::Result<Path> {
        let execution = boot
            .kernel
            .processes
            .lifecycle_execution(process)
            .context("missing lifecycle scope")?;
        Ok(finalized_marker_path(process, execution)?)
    }

    fn with_handle(boot: &Bootstrap) -> anyhow::Result<(RequestProcess<'_>, HandleId)> {
        let effect = boot.register_effect(
            "effect://owned-request",
            &[MethodSpec::new(
                "invoke",
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(crate::EchoDriver),
        )?;
        let request = boot.request_under(
            boot.root,
            IdentityRef::ROOT,
            &[CompiledRequestGrantTemplate {
                selector: ResourceSelector::parse("perform://effect/owned-request")?,
                methods: MethodBitmap::method(0),
            }],
        )?;
        let handle = boot.open_for(request.id(), &effect, "perform")?;
        Ok((request, handle))
    }

    #[test]
    fn drop_without_a_runtime_revokes_and_retains_cleanup_for_the_host() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let (request, handle) = with_handle(&boot)?;
        let process = request.id();
        let sibling = boot
            .request_under(boot.root, IdentityRef::ROOT, &[])?
            .detach();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let child = boot.kernel.processes.fresh_id()?;
        let mut entry = ProcessEntry::new(child, Some(process), IdentityRef::ROOT);
        entry.scope.start();
        entry.steps = StepModule::single("cleanup", move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            DoNode::pure(Value::null())
        })?;
        entry
            .on_finalize
            .push(DoNode::pure(Value::null()).and_then(xolotl_graph::StepRef::new("cleanup")));
        boot.kernel.processes.insert(entry);
        drop(request);
        ensure!(boot.kernel.handles.read().get(handle).is_none());
        ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Cancelled));
        ensure!(boot.kernel.processes.status(child) == Some(ProcessStatus::Cancelled));
        ensure!(boot.kernel.processes.status(sibling) == Some(ProcessStatus::Running));
        ensure!(boot.kernel.processes.pending_cleanup() == [process]);
        ensure!(matches!(
            boot.request_under(process, IdentityRef::ROOT, &[]),
            Err(BootstrapError::ProcessUnavailable { .. })
        ));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(boot.drain_cleanup());
        ensure!(report.failures.is_empty());
        ensure!(calls.load(Ordering::SeqCst) == 1);
        ensure!(boot.kernel.processes.pending_cleanup().is_empty());
        ensure!(boot.kernel.processes.attached_grants(process).is_empty());
        ensure!(
            runtime.block_on(boot.kernel.state.read(&marker(&boot, process)?))?
                == Some(Value::integer(1))
        );
        ensure!(
            runtime
                .block_on(boot.kernel.state.read(&marker(&boot, child)?))?
                .is_some()
        );
        runtime.block_on(boot.finalize_process(sibling))?;
        Ok(())
    }

    #[test]
    fn shared_request_outlives_its_creator_and_retains_the_same_cleanup() -> anyhow::Result<()> {
        let (request, host, handle) = {
            let boot = Arc::new(Bootstrap::in_memory());
            let effect = boot.register_effect(
                "effect://shared-request",
                &[MethodSpec::new(
                    "invoke",
                    Purity::Pure,
                    MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(crate::EchoDriver),
            )?;
            let request = boot.request_under_owned(
                boot.root,
                IdentityRef::ROOT,
                &[CompiledRequestGrantTemplate {
                    selector: ResourceSelector::parse("perform://effect/shared-request")?,
                    methods: MethodBitmap::method(0),
                }],
            )?;
            let handle = boot.open_for(request.id(), &effect, "perform")?;
            ensure!(Arc::strong_count(&boot) == 2);
            (request, Arc::downgrade(&boot), handle)
        };
        ensure!(host.strong_count() == 1);
        let boot = host.upgrade().context("request must retain its host")?;
        let process = request.id();
        ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Running));

        drop(request);
        ensure!(Arc::strong_count(&boot) == 1);
        ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Cancelled));
        ensure!(boot.kernel.handles.read().get(handle).is_none());
        ensure!(boot.kernel.processes.pending_cleanup() == [process]);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(boot.drain_cleanup());
        ensure!(report.completed == 1 && report.failures.is_empty());
        ensure!(boot.kernel.processes.pending_cleanup().is_empty());
        ensure!(boot.kernel.processes.attached_grants(process).is_empty());
        ensure!(
            runtime.block_on(boot.kernel.state.read(&marker(&boot, process)?))?
                == Some(Value::integer(1))
        );
        drop(boot);
        ensure!(host.upgrade().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn shared_finish_preserves_independently_owned_children() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        let parent = boot.request_under_owned(boot.root, IdentityRef::ROOT, &[])?;
        let parent_id = parent.id();
        let child = boot.request_under(parent_id, IdentityRef::ROOT, &[])?;
        ensure!(Arc::strong_count(&boot) == 2);

        parent
            .finish(&xolotl_types::ExecutionOutput::new(
                Outcome::Done(Value::null()),
                xolotl_types::TaintSet::pristine(),
            ))
            .await?;
        ensure!(Arc::strong_count(&boot) == 1);
        ensure!(boot.kernel.processes.status(parent_id) == Some(ProcessStatus::Completed));
        ensure!(boot.kernel.processes.status(child.id()) == Some(ProcessStatus::Running));
        ensure!(boot.kernel.processes.pending_cleanup().is_empty());
        let report = boot.drain_cleanup().await;
        ensure!(report.completed == 0 && report.failures.is_empty());

        child
            .finish(&xolotl_types::ExecutionOutput::new(
                Outcome::Done(Value::null()),
                xolotl_types::TaintSet::pristine(),
            ))
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn finish_preserves_body_control_in_the_lifecycle_fact() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let taint = xolotl_types::TaintSet::of(xolotl_types::TaintSource::Protected {
            path: Path::parse("state://vault/request-result")?,
        });
        for outcome in [
            Outcome::Done(Value::integer(17)),
            Outcome::Fail(xolotl_types::Failure::Timeout),
        ] {
            let request = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
            let process = request.id();
            request
                .finish(&ExecutionOutput::new(outcome, taint.clone()))
                .await?;
            let facts = boot.kernel.facts.facts_of(process)?;
            let finalized = facts
                .iter()
                .find(|fact| fact.id.position == super::super::FINALIZED_NODE)
                .context("lifecycle fact")?;
            ensure!(finalized.taint == taint);
            let marker = boot
                .kernel
                .state
                .read_tainted(&marker(&boot, process)?)
                .await?
                .context("finalization marker")?;
            ensure!(marker.taint == taint);
        }
        Ok(())
    }

    #[tokio::test]
    async fn nonterminal_finish_does_not_start_cleanup() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let (request, handle) = with_handle(&boot)?;
        let process = request.id();
        for status in [
            ProcessStatus::Created,
            ProcessStatus::Running,
            ProcessStatus::Waiting,
            ProcessStatus::Suspended,
            ProcessStatus::Finalizing,
        ] {
            ensure!(matches!(
                boot.finish_process_as(process, status).await,
                Err(BootstrapError::NonterminalStatus { .. })
            ));
        }
        ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Running));
        ensure!(boot.kernel.processes.pending_cleanup().is_empty());
        ensure!(boot.kernel.handles.read().get(handle).is_some());
        ensure!(boot.kernel.facts.facts_of(process)?.is_empty());
        ensure!(boot.kernel.processes.lifecycle_execution(process).is_none());
        request
            .finish(&xolotl_types::ExecutionOutput::new(
                Outcome::Done(Value::null()),
                xolotl_types::TaintSet::pristine(),
            ))
            .await?;
        ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Completed));
        Ok(())
    }

    #[tokio::test]
    async fn finalizing_a_tree_closes_all_descendants_before_waiting() -> anyhow::Result<()> {
        use std::task::Poll;
        let boot = Bootstrap::in_memory();
        let process = boot
            .request_under(boot.root, IdentityRef::ROOT, &[])?
            .detach();
        let waiting = boot.kernel.processes.fresh_id()?;
        let mut entry = ProcessEntry::new(waiting, Some(process), IdentityRef::ROOT);
        entry.scope.start();
        entry
            .on_finalize
            .push(DoNode::wait_signal(Path::parse("state://signal/cleanup")?));
        boot.kernel.processes.insert(entry);
        let sibling = boot
            .request_under(process, IdentityRef::ROOT, &[])?
            .detach();
        let descendant = boot
            .request_under(sibling, IdentityRef::ROOT, &[])?
            .detach();
        let mut cleanup = Box::pin(boot.finalize_process(process));
        ensure!(
            std::future::poll_fn(|cx| Poll::Ready(cleanup.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        ensure!(boot.kernel.processes.status(sibling) == Some(ProcessStatus::Cancelled));
        ensure!(boot.kernel.processes.status(descendant) == Some(ProcessStatus::Cancelled));
        ensure!(matches!(
            boot.request_under(descendant, IdentityRef::ROOT, &[]),
            Err(BootstrapError::ProcessUnavailable { .. })
        ));
        drop(cleanup);
        ensure!(boot.kernel.processes.pending_cleanup() == [process]);
        let report = boot.drain_cleanup().await;
        ensure!(report.completed == 1 && report.failures.is_empty());
        for id in [process, waiting, sibling, descendant] {
            ensure!(boot.kernel.state.read(&marker(&boot, id)?).await?.is_some());
        }
        Ok(())
    }

    struct InterruptedState {
        inner: InMemoryBackend,
        stall: AtomicBool,
        entered: AtomicBool,
        fail: AtomicBool,
    }

    impl StateRead for InterruptedState {
        type Read<'a> = <InMemoryBackend as StateRead>::Read<'a>;

        fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
            self.inner.read_tainted(path)
        }
    }

    impl StateWrite for InterruptedState {
        type Write<'a> = std::pin::Pin<
            Box<
                dyn std::future::Future<Output = StateResult<xolotl_state::StateCommit>>
                    + Send
                    + 'a,
            >,
        >;

        fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
            Box::pin(async move {
                if matches!(&mutation, StateMutation::Set(_)) {
                    if self.stall.swap(false, Ordering::SeqCst) {
                        self.entered.store(true, Ordering::SeqCst);
                        std::future::pending::<()>().await;
                    }
                    if self.fail.swap(false, Ordering::SeqCst) {
                        return Err(
                            xolotl_state::StateError::Backend("marker unavailable".into()).into(),
                        );
                    }
                }
                self.inner.mutate(path, mutation).await
            })
        }
    }

    #[test]
    fn runtime_shutdown_releases_cleanup_ownership_and_preserves_the_record() -> anyhow::Result<()>
    {
        let state = Arc::new(InterruptedState {
            inner: InMemoryBackend::new(),
            stall: AtomicBool::new(true),
            entered: AtomicBool::new(false),
            fail: AtomicBool::new(false),
        });
        let boot = Bootstrap::from_kernel(Kernel::with_backends(
            Backend::new()
                .with_read(state.clone())
                .with_write(state.clone()),
            crate::FactSink::in_memory().0,
        ));
        let (request, handle) = with_handle(&boot)?;
        let process = request.id();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            drop(request);
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                while !state.entered.load(Ordering::SeqCst) {
                    tokio::task::yield_now().await;
                }
            })
            .await
        })?;
        drop(runtime);
        ensure!(boot.kernel.handles.read().get(handle).is_none());
        ensure!(boot.kernel.processes.pending_cleanup() == [process]);
        let before = boot
            .kernel
            .facts
            .facts_of(process)?
            .pop()
            .context("missing committed record")?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(boot.drain_cleanup());
        ensure!(report.failures.is_empty() && report.completed == 1);
        let after = boot
            .kernel
            .facts
            .facts_of(process)?
            .pop()
            .context("missing retained record")?;
        ensure!(before.timestamp == after.timestamp && before.outcome == after.outcome);
        ensure!(
            runtime.block_on(boot.kernel.state.read(&marker(&boot, process)?))?
                == Some(Value::integer(1))
        );
        Ok(())
    }

    #[test]
    fn explicit_cleanup_reports_failure_and_can_retry() -> anyhow::Result<()> {
        let state = Arc::new(InterruptedState {
            inner: InMemoryBackend::new(),
            stall: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            fail: AtomicBool::new(true),
        });
        let boot = Bootstrap::from_kernel(Kernel::with_backends(
            Backend::new().with_read(state.clone()).with_write(state),
            crate::FactSink::in_memory().0,
        ));
        let request = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
        let process = request.id();
        let children = [
            boot.request_under(process, IdentityRef::ROOT, &[])?
                .detach(),
            boot.request_under(process, IdentityRef::ROOT, &[])?
                .detach(),
        ];
        drop(request);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(boot.drain_cleanup());
        ensure!(report.completed == 0 && report.failures.len() == 1);
        ensure!(report.failures[0].process == process);
        ensure!(boot.kernel.processes.pending_cleanup() == [process]);
        ensure!(
            runtime
                .block_on(boot.kernel.state.read(&marker(&boot, children[0])?))?
                .is_none()
        );
        ensure!(
            runtime
                .block_on(boot.kernel.state.read(&marker(&boot, children[1])?))?
                .is_some()
        );
        ensure!(boot.kernel.processes.lifecycle_execution(process).is_none());
        let report = runtime.block_on(boot.drain_cleanup());
        ensure!(report.failures.is_empty() && report.completed == 1);
        ensure!(boot.kernel.processes.pending_cleanup().is_empty());
        Ok(())
    }
}
