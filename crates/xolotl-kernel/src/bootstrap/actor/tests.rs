use super::*;
use anyhow::{Context, bail, ensure};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use xolotl_state::{Backend, InMemoryBackend, StateMutation, StateResult, StateWrite};

#[derive(Default)]
struct AdmissionBackend {
    inner: Arc<InMemoryBackend>,
    entered: Notify,
    release: Arc<Notify>,
    finished: Arc<Notify>,
    block: AtomicBool,
    late: AtomicBool,
}

impl StateWrite for AdmissionBackend {
    type Write<'a> = std::pin::Pin<
        Box<dyn std::future::Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>,
    >;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            let initial_running = matches!(
                &mutation,
                StateMutation::CompareSet { expected: None, value }
                    if value.value.as_map().and_then(|map| map.get("status")).and_then(Value::as_str)
                        == Some("running")
            );
            if initial_running && self.late.load(Ordering::SeqCst) {
                let inner = self.inner.clone();
                let path = path.clone();
                let release = self.release.clone();
                let finished = self.finished.clone();
                let worker = tokio::spawn(async move {
                    release.notified().await;
                    let result = inner.mutate(&path, mutation).await;
                    finished.notify_one();
                    result
                });
                self.entered.notify_one();
                return worker
                    .await
                    .map_err(|error| xolotl_state::StateError::Backend(error.to_string()))?;
            }
            let commit = self.inner.mutate(path, mutation).await?;
            if initial_running
                && path.to_string().starts_with("state://agents/")
                && self.block.load(Ordering::SeqCst)
            {
                self.entered.notify_one();
                self.release.notified().await;
            }
            Ok(commit)
        })
    }
}

fn admission_fixture() -> (Bootstrap, Arc<AdmissionBackend>) {
    let backend = Arc::new(AdmissionBackend::default());
    backend.block.store(true, Ordering::SeqCst);
    let (facts, _) = crate::FactSink::in_memory();
    (
        Bootstrap::from_kernel(Kernel::with_backends(
            Backend::new()
                .with_read(backend.inner.clone())
                .with_write(backend.clone())
                .with_query(backend.inner.clone())
                .with_watch(backend.inner.clone()),
            facts,
        )),
        backend,
    )
}

fn counted_actor() -> anyhow::Result<(ActorSpec, StepModule, Arc<AtomicUsize>)> {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let module = StepModule::single("body", move |_, _| {
        observed.fetch_add(1, Ordering::SeqCst);
        DoNode::pure(Value::null())
    })?;
    let spec = ActorSpec {
        name: "admission".into(),
        body: DoNode::pure(Value::null()).and_then(xolotl_graph::StepRef::new("body")),
        ..ActorSpec::default()
    };
    Ok((spec, module, calls))
}

async fn wait_status(boot: &Bootstrap, directory: &Path, expected: &str) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if boot
                .kernel
                .state
                .read(directory)
                .await?
                .as_ref()
                .and_then(Value::as_map)
                .and_then(|map| map.get("status"))
                .and_then(Value::as_str)
                == Some(expected)
            {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await?
}

#[tokio::test]
async fn actor_terminal_status_preserves_result_provenance_for_waiters() -> anyhow::Result<()> {
    for failed in [false, true] {
        let boot = Bootstrap::in_memory();
        let signal = Path::parse("state://signal/actor-result")?;
        let taint = TaintSet::of(xolotl_types::TaintSource::Protected {
            path: Path::parse("state://vault/actor-result")?,
        });
        boot.kernel
            .state
            .write_set_tainted(&signal, Value::integer(17), taint.clone())
            .await?;
        let cleanup = Path::parse("state://signal/actor-cleanup")?;
        let cleanup_taint = TaintSet::of(xolotl_types::TaintSource::Fetched {
            host: "cleanup-service".into(),
        });
        boot.kernel
            .state
            .write_set_tainted(&cleanup, Value::null(), cleanup_taint.clone())
            .await?;
        let failed_cleanup = Path::parse("state://signal/actor-failed-cleanup")?;
        let failure_taint = TaintSet::of(xolotl_types::TaintSource::Protected {
            path: Path::parse("state://vault/failed-cleanup")?,
        });
        boot.kernel
            .state
            .write_set_tainted(&failed_cleanup, Value::null(), failure_taint.clone())
            .await?;
        let mut body = DoNode::wait_signal(signal);
        if failed {
            body = body.and_then(xolotl_graph::StepRef::new("fail"));
        }
        let spec = ActorSpec {
            name: "provenance".into(),
            body,
            finalizers: vec![
                DoNode::wait_signal(cleanup),
                DoNode::wait_signal(failed_cleanup).and_then(xolotl_graph::StepRef::new("fail")),
            ],
            ..ActorSpec::default()
        };
        let actor = boot
            .spawn_actor_under_with_steps(
                boot.root,
                IdentityRef::ROOT,
                "root",
                &spec,
                StepModule::single("fail", |_, _| {
                    DoNode::fail(Failure::policy("actor", "protected result failed"))
                })?,
            )
            .await?;
        let directory = actor_directory_path("root", &spec.name)?;
        wait_status(
            &boot,
            &directory,
            if failed { "failed" } else { "completed" },
        )
        .await?;
        ensure!(
            boot.kernel
                .processes
                .status(actor.process)
                .is_some_and(|status| status.is_terminal())
        );
        let output = boot
            .kernel
            .executor_for(boot.root)
            .eval(&DoNode::wait_signal(directory))
            .await;
        ensure!(matches!(output.outcome, Outcome::Done(_)));
        ensure!(output.taint == taint, "{output:?}");
        let facts = boot.kernel.facts.facts_of(actor.process)?;
        let finalized = facts
            .iter()
            .find(|fact| fact.id.position == FINALIZED_NODE)
            .context("lifecycle fact")?;
        ensure!(
            finalized.taint == taint.merged(&cleanup_taint).merged(&failure_taint),
            "{finalized:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_admission_reconciles_a_committed_directory() -> anyhow::Result<()> {
    let (boot, backend) = admission_fixture();
    let (spec, module, calls) = counted_actor()?;
    let directory = actor_directory_path("root", &spec.name)?;
    let mut admission = Box::pin(boot.spawn_actor_under_with_steps(
        boot.root,
        IdentityRef::ROOT,
        "root",
        &spec,
        module,
    ));
    tokio::select! {
        result = &mut admission => bail!("admission unexpectedly completed: {}", result.is_ok()),
        () = backend.entered.notified() => {}
    }
    drop(admission);
    let report = tokio::time::timeout(Duration::from_secs(2), boot.drain_cleanup()).await?;
    ensure!(
        report.failures.is_empty(),
        "cleanup failed: {:?}",
        report.failures
    );
    wait_status(&boot, &directory, "cancelled").await?;
    ensure!(calls.load(Ordering::SeqCst) == 0);
    ensure!(boot.kernel.processes.pending_cleanup().is_empty());
    Ok(())
}

#[tokio::test]
async fn late_backend_commit_cannot_reanimate_cancelled_admission() -> anyhow::Result<()> {
    let (boot, backend) = admission_fixture();
    backend.late.store(true, Ordering::SeqCst);
    let (spec, module, calls) = counted_actor()?;
    let directory = actor_directory_path("root", &spec.name)?;
    let mut admission = Box::pin(boot.spawn_actor_under_with_steps(
        boot.root,
        IdentityRef::ROOT,
        "root",
        &spec,
        module,
    ));
    tokio::select! {
        result = &mut admission => bail!("admission unexpectedly completed: {}", result.is_ok()),
        () = backend.entered.notified() => {}
    }
    drop(admission);
    let report = tokio::time::timeout(Duration::from_secs(2), boot.drain_cleanup()).await?;
    ensure!(report.failures.is_empty());
    wait_status(&boot, &directory, "cancelled").await?;
    backend.release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), backend.finished.notified()).await?;
    wait_status(&boot, &directory, "cancelled").await?;
    ensure!(calls.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn parent_closure_stops_directory_admission_before_body_start() -> anyhow::Result<()> {
    let (boot, backend) = admission_fixture();
    let parent = boot
        .request_under(boot.root, IdentityRef::ROOT, &[])?
        .detach();
    let (spec, module, calls) = counted_actor()?;
    let directory = actor_directory_path("root", &spec.name)?;
    let mut admission = Box::pin(boot.spawn_actor_under_with_steps(
        parent,
        IdentityRef::ROOT,
        "root",
        &spec,
        module,
    ));
    tokio::select! {
        result = &mut admission => bail!("admission unexpectedly completed: {}", result.is_ok()),
        () = backend.entered.notified() => {}
    }
    tokio::time::timeout(Duration::from_secs(2), boot.finalize_process(parent)).await??;
    ensure!(admission.await.is_err());
    wait_status(&boot, &directory, "cancelled").await?;
    ensure!(calls.load(Ordering::SeqCst) == 0);
    ensure!(boot.kernel.processes.status(parent) == Some(ProcessStatus::Cancelled));
    Ok(())
}

#[tokio::test]
async fn failed_admission_cannot_change_another_actors_directory() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let spec = ActorSpec {
        name: "owner".into(),
        body: DoNode::wait_signal(Path::parse("state://signal/never")?),
        ..ActorSpec::default()
    };
    let first = boot
        .spawn_actor_under(boot.root, IdentityRef::ROOT, "root", &spec)
        .await?;
    let expected = boot.kernel.state.read(&first.directory).await?;
    ensure!(
        boot.spawn_actor_under(boot.root, IdentityRef::ROOT, "root", &spec)
            .await
            .is_err()
    );
    let report = boot.drain_cleanup().await;
    ensure!(report.failures.is_empty());
    ensure!(boot.kernel.state.read(&first.directory).await? == expected);
    ensure!(boot.kernel.processes.status(first.process) == Some(ProcessStatus::Running));
    boot.finalize_process(first.process).await?;
    Ok(())
}

#[tokio::test]
async fn finished_ancestor_can_close_an_independently_running_actor() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let parent = boot.request_under(boot.root, IdentityRef::ROOT, &[])?;
    let parent_id = parent.id();
    let spec = ActorSpec {
        name: "independent".into(),
        body: DoNode::wait_signal(Path::parse("state://signal/never")?),
        ..ActorSpec::default()
    };
    let actor = boot
        .spawn_actor_under(parent_id, IdentityRef::ROOT, "root", &spec)
        .await?;
    parent
        .finish(&xolotl_types::ExecutionOutput::new(
            Outcome::Done(Value::null()),
            xolotl_types::TaintSet::pristine(),
        ))
        .await?;
    ensure!(boot.kernel.processes.status(actor.process) == Some(ProcessStatus::Running));
    tokio::time::timeout(Duration::from_secs(2), boot.finalize_process(parent_id)).await??;
    wait_status(&boot, &actor.directory, "cancelled").await?;
    ensure!(boot.kernel.processes.status(parent_id) == Some(ProcessStatus::Completed));
    ensure!(!boot.kernel.processes.has_task(actor.process));
    Ok(())
}

struct ReentrantDriver {
    bootstrap: std::sync::Weak<Bootstrap>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::Driver for ReentrantDriver {
    async fn call(
        &self,
        _method: xolotl_types::MethodId,
        _input: Value,
        _output: xolotl_types::OutputMode,
        context: &crate::DriverContext,
    ) -> Result<crate::DriverOutput, crate::DriverError> {
        let boot = self
            .bootstrap
            .upgrade()
            .ok_or_else(|| crate::DriverError::Other("host missing".into()))?;
        let process = context
            .operation_id
            .ok_or_else(|| crate::DriverError::Other("identity missing".into()))?
            .process;
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let target = if call == 0 { process } else { boot.root };
        match boot.finalize_process(target).await {
            Err(BootstrapError::ProcessBusy { process: blocked }) if target == blocked => {
                Ok(crate::DriverOutput::new(Outcome::Done(Value::null())))
            }
            other => Err(crate::DriverError::Other(format!(
                "unexpected reentrant result: {other:?}"
            ))),
        }
    }
}

#[tokio::test]
async fn body_and_finalizer_cannot_join_their_own_process_tree() -> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::in_memory());
    let calls = Arc::new(AtomicUsize::new(0));
    let resource = boot.register_effect(
        "effect://lifecycle/reentrant",
        &[
            MethodSpec::new("invoke", Purity::Effectful, MethodSpec::UNARY_ASYNC)
                .finalize_allowed(),
        ],
        Arc::new(ReentrantDriver {
            bootstrap: Arc::downgrade(&boot),
            calls: calls.clone(),
        }),
    )?;
    let operation = DoNode::op(xolotl_graph::OperationTemplate {
        target: resource,
        method: "invoke".into(),
        method_id: None,
        output: xolotl_types::OutputMode::Unary,
        literal_input: Some(Value::null()),
    });
    let spec = ActorSpec {
        name: "reentrant".into(),
        body: operation.clone(),
        finalizers: vec![operation],
        declared_capabilities: vec!["perform://effect/lifecycle/reentrant".into()],
        ..ActorSpec::default()
    };
    let actor = boot
        .spawn_actor_under(boot.root, IdentityRef::ROOT, "root", &spec)
        .await?;
    wait_status(&boot, &actor.directory, "completed").await?;
    ensure!(calls.load(Ordering::SeqCst) == 2);
    let facts = boot.kernel.facts.facts_of(actor.process)?;
    let terminal = facts
        .iter()
        .find(|fact| fact.id.position == FINALIZED_NODE)
        .context("missing lifecycle fact")?;
    let record = terminal
        .outcome
        .as_ref()
        .and_then(Value::as_map)
        .context("missing lifecycle result")?;
    ensure!(record.get("finalizer_failure_count") == Some(&Value::integer(0)));
    ensure!(boot.kernel.processes.status(boot.root) == Some(ProcessStatus::Running));
    Ok(())
}
