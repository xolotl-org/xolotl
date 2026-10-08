//! Request ownership and host-driven completion of abandoned scopes.

use super::*;
use crate::Executor;
use crate::process::{
    CleanupAction, CleanupProgress, CleanupTicket, CleanupTicketError, ProcessFinalizationReport,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::Notify;
use xolotl_types::ExecutionOutput;

#[derive(Default)]
pub(super) struct DetachedCleanupTasks {
    active: AtomicUsize,
    changed: Notify,
}

impl DetachedCleanupTasks {
    async fn wait_idle(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            changed.await;
        }
    }
}

/// Notify only after the task's Bootstrap clone has been destroyed, including
/// when the host cancels a scheduled cleanup task before it is first polled.
struct DetachedCleanupOwner {
    boot: Option<Bootstrap>,
    tasks: Arc<DetachedCleanupTasks>,
}

impl DetachedCleanupOwner {
    fn new(boot: Bootstrap) -> Self {
        let tasks = Arc::clone(&boot.cleanup_tasks);
        tasks.active.fetch_add(1, Ordering::AcqRel);
        Self {
            boot: Some(boot),
            tasks,
        }
    }
}

impl Drop for DetachedCleanupOwner {
    fn drop(&mut self) {
        drop(self.boot.take());
        self.tasks.active.fetch_sub(1, Ordering::AcqRel);
        self.tasks.changed.notify_waiters();
    }
}

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
    cleanup: CleanupTicket,
}

/// A failed completion retains the original cleanup identity for retries and observation.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct RequestFinishError {
    /// Original lifecycle failure, without flattening its typed cause.
    #[source]
    pub source: BootstrapError,
    /// Custody remains pinned even if detached cleanup completes before a retry.
    pub cleanup: CleanupTicket,
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

    /// Whether this request belongs to the same Kernel process domain as
    /// `bootstrap`. Process ids alone are local coordinates and may coincide
    /// across independent kernels.
    pub fn belongs_to(&self, bootstrap: &Bootstrap) -> bool {
        self.bootstrap()
            .kernel()
            .processes()
            .same_table(bootstrap.kernel().processes())
    }

    /// Create an executor bound to this request's authority.
    pub fn executor(&self) -> Executor {
        self.bootstrap().kernel().executor_for(self.process)
    }

    /// Retain cleanup custody before transferring request ownership to another task.
    pub fn cleanup_ticket(&self) -> CleanupTicket {
        self.cleanup.clone()
    }

    /// Select the body's terminal intent before waiting on output delivery.
    /// Retains provenance and bounded uncertainty, not the output payload.
    /// Earlier cancellation and cleanup selections remain authoritative.
    /// Finalizers still require `finish` or cleanup custody after owner release.
    /// A finalized process rejects new body evidence.
    pub fn complete_body(&self, output: &ExecutionOutput) -> Result<(), BootstrapError> {
        match self
            .bootstrap()
            .kernel()
            .processes()
            .retain_body_completion(self.process, output)
        {
            Some(true) => Ok(()),
            Some(false) => Err(BootstrapError::ProcessUnavailable {
                process: self.process,
            }),
            None => Err(BootstrapError::NoSuchProcess {
                process: self.process,
            }),
        }
    }

    /// Finish after execution returns. Errors retain cleanup work for retry.
    pub async fn finish(
        mut self,
        output: &ExecutionOutput,
    ) -> Result<Arc<ProcessFinalizationReport>, RequestFinishError> {
        let completed = self
            .bootstrap()
            .finish_request_process(self.process, output)
            .await
            .and_then(|()| {
                self.cleanup
                    .finalization_report()
                    .ok_or(BootstrapError::NoSuchProcess {
                        process: self.process,
                    })
            });
        let report = completed.map_err(|source| RequestFinishError {
            source,
            cleanup: self.cleanup.clone(),
        })?;
        self.owned = false;
        Ok(report)
    }

    /// Transfer lifecycle ownership to another live request owner.
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
        let cleanup = self.admit_owned_request(anchor, identity, grants)?;
        Ok(RequestProcess {
            process: cleanup.process(),
            cleanup,
            bootstrap: RequestBootstrap::Borrowed(self),
            owned: true,
        })
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
        let cleanup = self.admit_owned_request(anchor, identity, grants)?;
        Ok(RequestProcess {
            process: cleanup.process(),
            cleanup,
            bootstrap: RequestBootstrap::Shared(Arc::clone(self)),
            owned: true,
        })
    }

    fn admit_owned_request(
        &self,
        anchor: ProcessId,
        identity: IdentityRef,
        grants: &[CompiledRequestGrantTemplate],
    ) -> Result<CleanupTicket, BootstrapError> {
        let grants = grants
            .iter()
            .map(|grant| ParsedRequestGrantTemplate {
                selector: grant.selector.clone(),
                rights: Some(grant.rights.clone()),
            })
            .collect();
        let entry =
            self.prepare_request_process_entry(anchor, identity, grants, StepModule::default())?;
        Ok(self.kernel().processes().admit_request(entry)?)
    }

    pub(super) fn own_process(
        &self,
        process: ProcessId,
    ) -> Result<RequestProcess<'_>, BootstrapError> {
        Ok(RequestProcess {
            cleanup: self.cleanup_ticket(process)?,
            bootstrap: RequestBootstrap::Borrowed(self),
            process,
            owned: true,
        })
    }

    fn abandon_request(&self, process: ProcessId) {
        let descendants = self.kernel().processes().abandon_scope(process);
        let needs_cleanup = !descendants.is_empty();
        for descendant in descendants {
            self.kernel().processes().abort_task(descendant);
            super::finalize::close_process_handles(
                self.kernel().processes(),
                self.kernel().handles(),
                descendant,
            );
        }
        if needs_cleanup {
            let Ok(ticket) = self.cleanup_ticket(process) else {
                return;
            };
            let owner = DetachedCleanupOwner::new(self.clone());
            let cleanup = self.kernel().host_runtime().spawn(Box::pin(async move {
                if let Some(boot) = owner.boot.as_ref()
                    && let Err(error) = boot.resume_cleanup(&ticket).await
                {
                    tracing::warn!(process = process.get(), %error, "request cleanup remains pending");
                }
            }));
            // The table retains progress even if the runtime shuts down this task.
            drop(cleanup);
        }
    }

    /// Finish abandoned scopes and interrupted finalizations, awaiting other owners as needed.
    /// This also works after the runtime that dropped a scope has shut down.
    /// Each pending tree is attempted once; failed work stays available for retry.
    /// After callers stop admitting requests, this also waits for detached
    /// cleanup tasks to release their Kernel and storage captures.
    pub async fn drain_cleanup(&self) -> ProcessCleanupReport {
        let mut report = ProcessCleanupReport::default();
        for process in self.kernel().processes().pending_cleanup() {
            let result = match self.cleanup_ticket(process) {
                Ok(ticket) => self.resume_cleanup(&ticket).await,
                Err(error) => Err(error),
            };
            match result {
                Ok(CleanupProgress::Completed) => report.completed += 1,
                Ok(CleanupProgress::NotRequested) => {}
                Err(error) => report
                    .failures
                    .push(ProcessCleanupFailure { process, error }),
            }
        }
        // A concurrent drop may already have completed cleanup in the process
        // table while its detached task still owns a Kernel/storage clone.
        self.cleanup_tasks.wait_idle().await;
        report
    }

    /// Retain the admitted process's identity until cleanup custody is acknowledged.
    /// Acquire before task ownership is released; an unknown or already reaped
    /// identifier returns `NoSuchProcess`, never a fabricated completion receipt.
    /// Tickets share a weak table pin and do not keep a kernel alive.
    pub fn cleanup_ticket(&self, process: ProcessId) -> Result<CleanupTicket, BootstrapError> {
        self.kernel()
            .processes()
            .cleanup_ticket(process)
            .map_err(|error| match error {
                CleanupTicketError::Missing => BootstrapError::NoSuchProcess { process },
            })
    }

    /// Retry only this ticket's already selected Local or Tree cleanup scope.
    /// Live work without a cleanup request returns `NotRequested` unchanged.
    /// Completion requires lifecycle/publication success, release of all managed
    /// callback captures and body/finalizer owners, and direct invocation
    /// settlement in that scope.
    /// Errors preserve custody for retry.
    /// A ticket from another process table is rejected before any process changes.
    pub async fn resume_cleanup(
        &self,
        ticket: &CleanupTicket,
    ) -> Result<CleanupProgress, BootstrapError> {
        let processes = self.kernel().processes();
        let process = ticket.process();
        if !ticket.belongs_to(processes) {
            return Err(BootstrapError::CleanupTicketMismatch { process });
        }
        loop {
            let action = processes
                .cleanup_action(ticket)
                .ok_or(BootstrapError::NoSuchProcess { process })?;
            match action {
                CleanupAction::Completed => return Ok(CleanupProgress::Completed),
                CleanupAction::NotRequested => return Ok(CleanupProgress::NotRequested),
                CleanupAction::AwaitOwners => {
                    let selection =
                        processes
                            .cleanup_selection(ticket)
                            .map_err(|error| match error {
                                CleanupTicketError::Missing => {
                                    BootstrapError::NoSuchProcess { process }
                                }
                            })?;
                    super::finalize::reject_cleanup_self_wait(processes, process, &selection)?;
                    processes.wait_for_cleanup_owners(ticket).await;
                }
                CleanupAction::Resume => {
                    let selection =
                        processes
                            .cleanup_selection(ticket)
                            .map_err(|error| match error {
                                CleanupTicketError::Missing => {
                                    BootstrapError::NoSuchProcess { process }
                                }
                            })?;
                    super::finalize::finish_cleanup_selection(self.kernel(), process, &selection)
                        .await?;
                }
            }
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

    struct BusinessPublication(Path);

    #[async_trait::async_trait]
    impl crate::process::ProcessPublication for BusinessPublication {
        async fn publish(
            &self,
            state: &Backend,
            _process: ProcessId,
            status: ProcessStatus,
            outcome: Option<&ExecutionOutput>,
        ) -> Result<(), BootstrapError> {
            state
                .write_set_tainted(
                    &self.0,
                    Value::string(process_status_label(status).into()),
                    outcome
                        .map(|output| output.taint.clone())
                        .unwrap_or_default(),
                )
                .await?;
            Ok(())
        }
    }

    fn published_request<'a>(
        boot: &'a Bootstrap,
        anchor: ProcessId,
        path: Path,
        grants: &[CompiledRequestGrantTemplate],
    ) -> anyhow::Result<RequestProcess<'a>> {
        let process = boot.kernel().processes().fresh_id()?;
        let planned = boot.plan_request_grant_views(
            anchor,
            grants.iter().map(|grant| RequestGrantView {
                selector: &grant.selector,
                rights: Some(&grant.rights),
            }),
        )?;
        let mut entry = boot.request_process_entry(process, anchor, IdentityRef::ROOT, planned);
        entry.scope.start();
        entry.publication = Some(Arc::new(BusinessPublication(path)));
        boot.kernel().processes().admit_child(entry)?;
        Ok(boot.own_process(process)?)
    }

    fn with_handle(boot: &Bootstrap) -> anyhow::Result<(RequestProcess<'_>, HandleId)> {
        with_published_handle(boot, None)
    }

    fn with_published_handle(
        boot: &Bootstrap,
        publication: Option<Path>,
    ) -> anyhow::Result<(RequestProcess<'_>, HandleId)> {
        let effect = boot.register_effect(
            "effect://owned-request",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(crate::EchoDriver),
        )?;
        let grants = [CompiledRequestGrantTemplate {
            selector: ResourceSelector::parse("perform://effect/owned-request")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("invoke"),
                xolotl_types::RightFlags::empty(),
            ),
        }];
        let request = match publication {
            Some(path) => published_request(boot, boot.root(), path, &grants)?,
            None => boot.request_under(boot.root(), IdentityRef::ROOT, &grants)?,
        };
        let handle = boot.open_for(request.id(), &effect, "perform")?;
        Ok((request, handle))
    }

    #[tokio::test]
    async fn explicit_delegation_attenuates_flags_and_retains_scope_constraints()
    -> anyhow::Result<()> {
        use xolotl_graph::portable::{Expression, Program};
        use xolotl_types::{Failure, RightFlags, TaintedValue};
        let boot = Bootstrap::in_memory();
        let anchor = boot.request_under(
            boot.root(),
            IdentityRef::ROOT,
            &[CompiledRequestGrantTemplate {
                selector: ResourceSelector::parse("act-as://identity/worker/**@account=alice")?,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::none(),
                    RightFlags::DELEGATE,
                ),
            }],
        )?;
        let selector = ResourceSelector::parse("act-as://identity/worker/one")?;
        let before = boot.kernel().processes().count();
        for rights in [
            xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::none(),
                RightFlags::DELEGATE | RightFlags::CLONE,
            ),
            xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("invoke"),
                RightFlags::DELEGATE,
            ),
            xolotl_types::GrantRights::new(xolotl_types::GrantMethods::none(), RightFlags::empty()),
        ] {
            ensure!(matches!(
                boot.request_under(
                    anchor.id(),
                    IdentityRef::ROOT,
                    &[CompiledRequestGrantTemplate {
                        selector: selector.clone(),
                        rights
                    },]
                ),
                Err(BootstrapError::CapabilityCeiling { .. })
            ));
        }
        ensure!(boot.kernel().processes().count() == before);
        let child = boot.request_under(
            anchor.id(),
            IdentityRef::ROOT,
            &[CompiledRequestGrantTemplate {
                selector,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::none(),
                    RightFlags::DELEGATE,
                ),
            }],
        )?;
        let grants = boot.kernel().processes().attached_grants(child.id());
        ensure!(grants.len() == 1 && grants[0].rights.methods.is_empty());
        ensure!(grants[0].rights.flags == RightFlags::DELEGATE);
        ensure!(grants[0].constraints.predicates.len() == 1);
        let compiled = Program::new(Expression::Acting {
            identity: Path::parse("identity://worker/one")?,
            body: Box::new(Expression::Input),
        })
        .compile()?;
        for (account, allowed) in [("bob", false), ("alice", true)] {
            let value = Value::map(std::collections::BTreeMap::from([(
                "account".into(),
                Value::string(account.into()),
            )]));
            let output = child
                .executor()
                .eval_program(&compiled, TaintedValue::pristine(value.clone()))
                .await;
            if allowed {
                ensure!(output.outcome == Outcome::Done(value));
            } else {
                ensure!(
                    matches!(output.outcome, Outcome::Fail(Failure::PolicyViolation { ref policy, .. }) if policy == "act-as")
                );
            }
        }
        Ok(())
    }

    #[test]
    fn drop_without_a_runtime_revokes_and_retains_cleanup_for_the_host() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let (request, handle) = with_handle(&boot)?;
        let process = request.id();
        let sibling = boot
            .request_under(boot.root(), IdentityRef::ROOT, &[])?
            .detach();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let child = boot.kernel().processes().fresh_id()?;
        let mut entry = ProcessEntry::new(child, Some(process), IdentityRef::ROOT);
        entry.scope.start();
        entry.steps = StepModule::single("cleanup", move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            DoNode::pure(Value::null())
        })?;
        entry
            .on_finalize
            .push(DoNode::pure(Value::null()).and_then(xolotl_graph::StepRef::new("cleanup")));
        boot.kernel().processes().insert(entry);
        drop(request);
        ensure!(boot.kernel().handles().read().get(handle).is_none());
        ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Cancelled));
        ensure!(boot.kernel().processes().status(child) == Some(ProcessStatus::Cancelled));
        ensure!(boot.kernel().processes().status(sibling) == Some(ProcessStatus::Running));
        ensure!(boot.kernel().processes().pending_cleanup() == [process]);
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
        ensure!(boot.kernel().processes().pending_cleanup().is_empty());
        ensure!(
            boot.kernel()
                .processes()
                .attached_grants(process)
                .is_empty()
        );
        ensure!(boot.cleanup_ticket(process)?.is_complete());
        ensure!(
            boot.kernel()
                .processes()
                .finalization_report(process)
                .context("cleanup report")?
                .revoked_handles
                == 1
        );
        ensure!(boot.cleanup_ticket(child)?.is_complete());
        ensure!(
            boot.kernel()
                .processes()
                .finalization_report(child)
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
                    xolotl_types::MethodAuthority::Perform,
                    Purity::Pure,
                    MethodSpec::UNARY_ASYNC,
                )],
                Arc::new(crate::EchoDriver),
            )?;
            let request = boot.request_under_owned(
                boot.root(),
                IdentityRef::ROOT,
                &[CompiledRequestGrantTemplate {
                    selector: ResourceSelector::parse("perform://effect/shared-request")?,
                    rights: xolotl_types::GrantRights::new(
                        xolotl_types::GrantMethods::name("invoke"),
                        xolotl_types::RightFlags::empty(),
                    ),
                }],
            )?;
            let handle = boot.open_for(request.id(), &effect, "perform")?;
            ensure!(Arc::strong_count(&boot) == 2);
            (request, Arc::downgrade(&boot), handle)
        };
        ensure!(host.strong_count() == 1);
        let boot = host.upgrade().context("request must retain its host")?;
        let process = request.id();
        ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Running));

        drop(request);
        ensure!(Arc::strong_count(&boot) == 1);
        ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Cancelled));
        ensure!(boot.kernel().handles().read().get(handle).is_none());
        ensure!(boot.kernel().processes().pending_cleanup() == [process]);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(boot.drain_cleanup());
        ensure!(report.completed == 1 && report.failures.is_empty());
        ensure!(boot.kernel().processes().pending_cleanup().is_empty());
        ensure!(
            boot.kernel()
                .processes()
                .attached_grants(process)
                .is_empty()
        );
        ensure!(boot.cleanup_ticket(process)?.is_complete());
        ensure!(
            boot.kernel()
                .processes()
                .finalization_report(process)
                .context("cleanup report")?
                .revoked_handles
                == 1
        );
        drop(boot);
        ensure!(host.upgrade().is_none());
        Ok(())
    }

    #[tokio::test]
    async fn shared_finish_preserves_independently_owned_children() -> anyhow::Result<()> {
        let boot = Arc::new(Bootstrap::in_memory());
        let parent = boot.request_under_owned(boot.root(), IdentityRef::ROOT, &[])?;
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
        ensure!(boot.kernel().processes().status(parent_id) == Some(ProcessStatus::Completed));
        ensure!(boot.kernel().processes().status(child.id()) == Some(ProcessStatus::Running));
        ensure!(boot.kernel().processes().pending_cleanup().is_empty());
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
    async fn finish_preserves_body_control_in_cleanup() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let taint = xolotl_types::TaintSet::of(xolotl_types::TaintSource::Protected {
            path: Path::parse("state://vault/request-result")?,
        });
        for outcome in [
            Outcome::Done(Value::integer(17)),
            Outcome::Fail(xolotl_types::Failure::Timeout),
        ] {
            let request = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
            let process = request.id();
            request
                .finish(&ExecutionOutput::new(outcome, taint.clone()))
                .await?;
            let report = boot
                .kernel()
                .processes()
                .finalization_report(process)
                .context("cleanup report")?;
            ensure!(report.taint == taint);
            ensure!(boot.cleanup_ticket(process)?.is_complete());
        }
        Ok(())
    }

    #[tokio::test]
    async fn nonterminal_finish_does_not_start_cleanup() -> anyhow::Result<()> {
        let boot = crate::fact::testing::observing_bootstrap();
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
        ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Running));
        ensure!(boot.kernel().processes().pending_cleanup().is_empty());
        ensure!(boot.kernel().handles().read().get(handle).is_some());
        ensure!(boot.kernel().facts().facts_of(process)?.is_empty());
        ensure!(
            boot.kernel()
                .processes()
                .lifecycle_execution(process)
                .is_none()
        );
        request
            .finish(&xolotl_types::ExecutionOutput::new(
                Outcome::Done(Value::null()),
                xolotl_types::TaintSet::pristine(),
            ))
            .await?;
        ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Completed));
        Ok(())
    }

    #[tokio::test]
    async fn completed_body_survives_delivery_owner_drop_without_retaining_payload()
    -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let taint = xolotl_types::TaintSet::of(xolotl_types::TaintSource::Protected {
            path: Path::parse("state://vault/completed-body")?,
        });
        for outcome in [
            Outcome::Done(Value::integer(17)),
            Outcome::Fail(xolotl_types::Failure::HandlerError {
                kind: "body".into(),
                message: "failed".into(),
            }),
        ] {
            let request = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
            let process = request.id();
            let ticket = request.cleanup_ticket();
            let expected = crate::process::outcome_status(&outcome);
            let mut output = ExecutionOutput::new(outcome, taint.clone());
            output.unresolved_operations.record("known-pending-effect");
            output.unresolved_operations.identities_incomplete = true;
            request.complete_body(&output)?;
            request.complete_body(&output)?;
            ensure!(ticket.terminal_status() == Some(expected));
            ensure!(!ticket.is_complete());
            ensure!(
                boot.kernel()
                    .processes()
                    .finalization_outcome(process)
                    .is_none()
            );
            ensure!(matches!(
                boot.request_under(process, IdentityRef::ROOT, &[]),
                Err(BootstrapError::ProcessUnavailable { .. })
            ));
            drop(request);
            let cleanup = boot.drain_cleanup().await;
            ensure!(cleanup.failures.is_empty());
            let report = ticket
                .finalization_report()
                .context("body cleanup report")?;
            ensure!(ticket.is_complete() && report.status == expected);
            ensure!(report.taint == taint);
            ensure!(report.unresolved_operations == output.unresolved_operations);
        }
        Ok(())
    }

    #[tokio::test]
    async fn body_completion_does_not_replace_prior_cancellation() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let request = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
        let ticket = request.cleanup_ticket();
        ensure!(boot.cancel_process(request.id())?);
        let taint = xolotl_types::TaintSet::author();
        let output = ExecutionOutput::new(Outcome::Done(Value::null()), taint.clone());
        request.complete_body(&output)?;
        ensure!(ticket.terminal_status() == Some(ProcessStatus::Cancelled));
        request.finish(&output).await?;
        let report = ticket
            .finalization_report()
            .context("cancelled body report")?;
        ensure!(report.status == ProcessStatus::Cancelled && report.taint == taint);
        Ok(())
    }

    #[tokio::test]
    async fn body_completion_rejects_evidence_after_finalization() -> anyhow::Result<()> {
        let boot = Bootstrap::in_memory();
        let request = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
        let ticket = request.cleanup_ticket();
        let output = ExecutionOutput::new(
            Outcome::Done(Value::null()),
            xolotl_types::TaintSet::author(),
        );
        boot.finish_request_process(request.id(), &output).await?;
        let report = ticket.finalization_report().context("finalized report")?;
        ensure!(matches!(
            request.complete_body(&output),
            Err(BootstrapError::ProcessUnavailable { .. })
        ));
        ensure!(Arc::ptr_eq(
            &report,
            &ticket.finalization_report().context("unchanged report")?
        ));
        drop(request);
        ensure!(ticket.is_complete());
        Ok(())
    }

    #[tokio::test]
    async fn finalizing_a_tree_closes_all_descendants_before_waiting() -> anyhow::Result<()> {
        use std::task::Poll;
        let boot = Bootstrap::in_memory();
        crate::executor::signal_tests::install_signal_resource(
            &boot,
            boot.kernel().state().clone(),
        )?;
        let process = boot
            .request_under(boot.root(), IdentityRef::ROOT, &[])?
            .detach();
        let waiting = boot.kernel().processes().fresh_id()?;
        let mut entry = ProcessEntry::new(waiting, Some(process), IdentityRef::ROOT);
        entry.scope.start();
        entry.attached_grants.push(Grant {
            id: boot.kernel().processes().fresh_attached_grant_id(),
            holder: waiting,
            selector: ResourceSelector::parse("subscribe://state/signal/cleanup")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("subscribe"),
                RightFlags::empty(),
            ),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        entry
            .on_finalize
            .push(DoNode::wait_signal(Path::parse("state://signal/cleanup")?));
        boot.kernel().processes().insert(entry);
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
        ensure!(boot.kernel().processes().status(sibling) == Some(ProcessStatus::Cancelled));
        ensure!(boot.kernel().processes().status(descendant) == Some(ProcessStatus::Cancelled));
        ensure!(matches!(
            boot.request_under(descendant, IdentityRef::ROOT, &[]),
            Err(BootstrapError::ProcessUnavailable { .. })
        ));
        drop(cleanup);
        ensure!(boot.kernel().processes().pending_cleanup() == [process]);
        let report = boot.drain_cleanup().await;
        ensure!(report.completed == 1 && report.failures.is_empty());
        for id in [process, waiting, sibling, descendant] {
            ensure!(boot.cleanup_ticket(id)?.is_complete());
            ensure!(boot.kernel().processes().finalization_report(id).is_some());
        }
        Ok(())
    }

    struct InterruptedState {
        inner: InMemoryBackend,
        publication_path: Path,
        stall: AtomicBool,
        entered: AtomicBool,
        fail: AtomicBool,
        unknown: AtomicBool,
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
                if path == &self.publication_path && matches!(&mutation, StateMutation::Set(_)) {
                    if self.stall.swap(false, Ordering::SeqCst) {
                        self.entered.store(true, Ordering::SeqCst);
                        std::future::pending::<()>().await;
                    }
                    if self.fail.swap(false, Ordering::SeqCst) {
                        return Err(xolotl_state::StateError::Backend(
                            "business publication unavailable".into(),
                        )
                        .into());
                    }
                }
                let committed = self.inner.mutate(path, mutation).await?;
                if path == &self.publication_path && self.unknown.swap(false, Ordering::SeqCst) {
                    return Err(xolotl_state::StateError::CommitUncertain(
                        "business publication committed without acknowledgement".into(),
                    )
                    .into());
                }
                Ok(committed)
            })
        }
    }

    #[test]
    fn runtime_shutdown_releases_cleanup_ownership_and_preserves_disposal() -> anyhow::Result<()> {
        let state = Arc::new(InterruptedState {
            inner: InMemoryBackend::new(),
            publication_path: Path::parse("state://application/cleanup/shutdown")?,
            stall: AtomicBool::new(true),
            entered: AtomicBool::new(false),
            fail: AtomicBool::new(false),
            unknown: AtomicBool::new(false),
        });
        let boot = Bootstrap::from_kernel(
            crate::KernelBuilder::new(
                Backend::new()
                    .with_read(state.clone())
                    .with_write(state.clone()),
            )
            .with_fact_sink(crate::FactSink::in_memory().0)
            .build(),
        );
        let publication_path = state.publication_path.clone();
        let (request, handle) = with_published_handle(&boot, Some(publication_path.clone()))?;
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
        ensure!(boot.kernel().handles().read().get(handle).is_none());
        ensure!(boot.kernel().processes().pending_cleanup() == [process]);
        ensure!(boot.kernel().facts().facts_of(process)?.is_empty());
        ensure!(boot.kernel().processes().status(process) == Some(ProcessStatus::Cancelled));
        ensure!(
            boot.kernel()
                .processes()
                .record_handle_cleanup(process, 0, 0)
                == Some((0, 1))
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(boot.drain_cleanup());
        ensure!(report.failures.is_empty() && report.completed == 1);
        ensure!(boot.kernel().facts().facts_of(process)?.is_empty());
        ensure!(boot.cleanup_ticket(process)?.is_complete());
        ensure!(
            boot.kernel()
                .processes()
                .finalization_report(process)
                .context("cleanup report")?
                .revoked_handles
                == 1
        );
        ensure!(
            runtime.block_on(boot.kernel().state().read(&publication_path))?
                == Some(Value::string("cancelled".into()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn uncertain_business_publication_preserves_cleanup_custody() -> anyhow::Result<()> {
        let state = Arc::new(InterruptedState {
            inner: InMemoryBackend::new(),
            publication_path: Path::parse("state://application/cleanup/unknown")?,
            stall: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            fail: AtomicBool::new(false),
            unknown: AtomicBool::new(true),
        });
        let boot = Bootstrap::from_kernel(
            crate::KernelBuilder::new(
                Backend::new()
                    .with_read(state.clone())
                    .with_write(state.clone()),
            )
            .with_fact_sink(crate::FactSink::in_memory().0)
            .build(),
        );
        let (request, handle) = with_published_handle(&boot, Some(state.publication_path.clone()))?;
        let process = request.detach();
        let error = boot
            .finish_request_process(
                process,
                &ExecutionOutput::new(Outcome::Done(Value::integer(17)), Default::default()),
            )
            .await
            .err()
            .context("unknown publication was reported as complete")?;
        ensure!(matches!(error, BootstrapError::State(ref failure)
            if matches!(failure.error, xolotl_state::StateError::CommitUncertain(_))));
        ensure!(boot.kernel().handles().get(handle).is_none());
        ensure!(!boot.cleanup_ticket(process)?.is_complete());
        ensure!(boot.kernel().processes().pending_cleanup() == [process]);
        ensure!(
            boot.kernel().state().read(&state.publication_path).await?
                == Some(Value::string("completed".into()))
        );
        let report = boot.drain_cleanup().await;
        ensure!(report.completed == 1 && report.failures.is_empty());
        ensure!(boot.cleanup_ticket(process)?.is_complete());
        ensure!(
            boot.kernel()
                .processes()
                .finalization_report(process)
                .context("cleanup evidence")?
                .status
                == ProcessStatus::Completed
        );
        ensure!(boot.kernel().facts().facts_of(process)?.is_empty());
        Ok(())
    }

    #[test]
    fn explicit_cleanup_reports_failure_and_can_retry() -> anyhow::Result<()> {
        let state = Arc::new(InterruptedState {
            inner: InMemoryBackend::new(),
            publication_path: Path::parse("state://application/cleanup/first")?,
            stall: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            fail: AtomicBool::new(true),
            unknown: AtomicBool::new(false),
        });
        let boot = Bootstrap::from_kernel(
            crate::KernelBuilder::new(
                Backend::new()
                    .with_read(state.clone())
                    .with_write(state.clone()),
            )
            .with_fact_sink(crate::FactSink::in_memory().0)
            .build(),
        );
        let request = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
        let process = request.id();
        let children = [
            published_request(&boot, process, state.publication_path.clone(), &[])?.detach(),
            published_request(
                &boot,
                process,
                Path::parse("state://application/cleanup/second")?,
                &[],
            )?
            .detach(),
        ];
        drop(request);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let report = runtime.block_on(boot.drain_cleanup());
        ensure!(report.completed == 0 && report.failures.len() == 1);
        ensure!(report.failures[0].process == process);
        ensure!(boot.kernel().processes().pending_cleanup() == [process]);
        ensure!(!boot.cleanup_ticket(children[0])?.is_complete());
        ensure!(boot.cleanup_ticket(children[1])?.is_complete());
        ensure!(
            runtime
                .block_on(boot.kernel().state().read(&state.publication_path))?
                .is_none()
        );
        let second_path = Path::parse("state://application/cleanup/second")?;
        ensure!(
            runtime.block_on(boot.kernel().state().read(&second_path))?
                == Some(Value::string("cancelled".into()))
        );
        let report = runtime.block_on(boot.drain_cleanup());
        ensure!(report.failures.is_empty() && report.completed == 1);
        ensure!(boot.kernel().processes().pending_cleanup().is_empty());
        ensure!(children.iter().all(|child| {
            boot.cleanup_ticket(*child)
                .is_ok_and(|ticket| ticket.is_complete())
        }));
        ensure!(
            runtime.block_on(boot.kernel().state().read(&state.publication_path))?
                == Some(Value::string("cancelled".into()))
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_finish_keeps_typed_cause_and_custody_after_cleanup_retry() -> anyhow::Result<()>
    {
        let state = Arc::new(InterruptedState {
            inner: InMemoryBackend::new(),
            publication_path: Path::parse("state://application/cleanup/custody")?,
            stall: AtomicBool::new(false),
            entered: AtomicBool::new(false),
            fail: AtomicBool::new(true),
            unknown: AtomicBool::new(false),
        });
        let boot = Bootstrap::from_kernel(
            crate::KernelBuilder::new(
                Backend::new()
                    .with_read(state.clone())
                    .with_write(state.clone()),
            )
            .with_process_capacity(std::num::NonZeroUsize::MIN.saturating_add(1))
            .build(),
        );
        let (request, _) = with_published_handle(&boot, Some(state.publication_path.clone()))?;
        let process = request.id();
        let mut output = request
            .executor()
            .eval(&xolotl_graph::DoNode::pure(37))
            .await;
        output.unresolved_operations.record("body-operation");
        let error = request
            .finish(&output)
            .await
            .err()
            .context("publication must reject")?;
        ensure!(matches!(&error.source, BootstrapError::State(_)));
        ensure!(error.cleanup.process() == process);
        ensure!(boot.resume_cleanup(&error.cleanup).await? == CleanupProgress::Completed);
        ensure!(boot.drain_cleanup().await.failures.is_empty());
        let report = error
            .cleanup
            .finalization_report()
            .context("committed report")?;
        ensure!(report.unresolved_operations.operation_ids == ["body-operation"]);
        ensure!(matches!(
            boot.request_under(boot.root(), IdentityRef::ROOT, &[]),
            Err(BootstrapError::ProcessAdmission(
                crate::ProcessAdmissionError::Capacity { limit: 2 }
            ))
        ));
        drop(error);
        let next = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
        ensure!(boot.kernel().processes().status(process).is_none());
        ensure!(report.status == ProcessStatus::Completed);
        ensure!(output.outcome == Outcome::Done(Value::integer(37)));
        next.finish(&output).await?;
        Ok(())
    }
}
