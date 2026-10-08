use super::*;
use crate::{
    Bootstrap, EchoDriver, ExecutionIdError, ExecutionIdRange, ExecutionIdSource, FactSink,
    InMemoryExecutionIdSource, InMemoryFactStore, MethodSpec,
};
use anyhow::{Context, ensure};
use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicUsize, Ordering};
use xolotl_graph::{
    ActorSpec,
    portable::{Expression as E, Program},
};
use xolotl_state::InMemoryBackend;
use xolotl_types::{Failure, OutputMode, Path, Purity};

fn effect(boot: &Bootstrap) -> anyhow::Result<OperationTemplate> {
    let target = boot.register_effect(
        "effect://identity/echo",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )
        .finalize_allowed()],
        Arc::new(EchoDriver),
    )?;
    Ok(OperationTemplate {
        target,
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::integer(1)),
    })
}

#[test]
fn explicit_identity_cannot_detach_kernel_runtime_tables() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
    let kernel = boot.kernel();
    let identity = kernel
        .identities()
        .resolve_or_register(&Path::parse("identity://standalone/caller")?)?;
    ensure!(matches!(
        Executor::new(
            boot.root(),
            identity,
            kernel.data_plane(),
            kernel.registry().clone(),
        ),
        Err(RuntimeAssemblyError::PartiallyBound)
    ));
    Ok(())
}

#[tokio::test]
async fn independent_hosts_and_executors_share_the_fact_namespace() -> anyhow::Result<()> {
    let store = Arc::new(InMemoryFactStore::new());
    let ids = ExecutionIds::new(Arc::new(InMemoryExecutionIdSource::new()));
    for _ in 0..2 {
        let boot = Bootstrap::from_kernel(
            crate::KernelBuilder::new(InMemoryBackend::new().into_backend())
                .with_fact_sink(FactSink::new(store.clone()))
                .with_execution_ids(ids.clone())
                .build(),
        );
        let operation = effect(&boot)?;
        for _ in 0..2 {
            let executor = Executor::from_process_table(
                boot.root(),
                boot.kernel().processes().clone(),
                boot.kernel().data_plane(),
                boot.kernel().registry().clone(),
            )?
            .with_fact_recording(true);
            for _ in 0..2 {
                ensure!(
                    executor.eval(&DoNode::op(operation.clone())).await.outcome
                        == Outcome::Done(Value::integer(1))
                );
            }
        }
    }
    let facts = crate::FactStore::all_facts(&*store)?;
    ensure!(facts.len() == 8);
    ensure!(
        facts
            .iter()
            .map(|fact| fact.id.execution)
            .collect::<BTreeSet<_>>()
            .len()
            == 8
    );
    ensure!(
        facts
            .iter()
            .all(|fact| fact.id.position == NodeId::ROOT && fact.id.invocation.get() == 1)
    );
    Ok(())
}

#[tokio::test]
async fn selected_observation_completion_failure_preserves_known_execution_result()
-> anyhow::Result<()> {
    for commit_unknown in [false, true] {
        let faults = Arc::new(crate::fact::testing::CompletionFaults::default());
        faults.reject_write.store(!commit_unknown, Ordering::SeqCst);
        faults
            .commit_unknown_after_complete
            .store(commit_unknown, Ordering::SeqCst);
        let boot = Bootstrap::from_kernel(
            crate::KernelBuilder::new(InMemoryBackend::new().into_backend())
                .with_fact_sink(FactSink::new(faults.clone()))
                .build(),
        );
        let operation = effect(&boot)?;
        let output = boot
            .kernel()
            .executor_for(boot.root())
            .with_fact_recording(true)
            .eval(&DoNode::op(operation))
            .await;
        ensure!(output.outcome == Outcome::Done(Value::integer(1)));
        ensure!(output.unresolved_operations.operation_ids.is_empty());
        let facts = crate::FactStore::all_facts(&*faults)?;
        ensure!(facts.len() == 1);
        ensure!(facts[0].is_complete() == commit_unknown);
        ensure!(
            boot.kernel()
                .processes()
                .budget_mut(boot.root(), |budget| budget.inflight_ops)
                == Some(0)
        );
    }
    Ok(())
}

#[tokio::test]
async fn loop_and_parallel_calls_preserve_the_same_static_source_position() -> anyhow::Result<()> {
    let boot = crate::fact::testing::observing_bootstrap();
    let operation = effect(&boot)?;
    let call = E::Call {
        function: "effect".into(),
    };
    let mut source = Program::new(E::While {
        condition: Box::new(E::literal(true)),
        body: Box::new(E::Parallel {
            left: Box::new(call.clone()),
            right: Box::new(call),
        }),
        max_iterations: 3,
    });
    source
        .functions
        .insert("effect".into(), E::Invoke { operation });
    let compiled = source.compile()?;
    let position = compiled
        .image()
        .nodes
        .iter()
        .find_map(|node| {
            matches!(node.kind, xolotl_core::NodeKind::Request(_)).then_some(node.position)
        })
        .context("missing operation instruction")?;
    let outcome = boot
        .kernel()
        .executor_for(boot.root())
        .with_fact_recording(true)
        .eval_program(&compiled, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        matches!(outcome.outcome, Outcome::Fail(_)),
        "unbounded condition must hit its iteration ceiling"
    );
    let facts = boot.kernel().facts().facts_of(boot.root())?;
    ensure!(facts.len() == 6);
    ensure!(
        facts
            .iter()
            .all(|fact| u64::from(fact.id.position.get()) == position && fact.id.attempt == 0)
    );
    ensure!(
        facts
            .iter()
            .map(|fact| fact.id.execution)
            .collect::<BTreeSet<_>>()
            .len()
            == 1
    );
    ensure!(
        facts
            .iter()
            .map(|fact| fact.id.invocation)
            .collect::<BTreeSet<_>>()
            .len()
            == 6
    );
    Ok(())
}

#[tokio::test]
async fn actor_body_and_finalizers_have_distinct_identities() -> anyhow::Result<()> {
    let boot = crate::fact::testing::observing_bootstrap();
    let calls = Arc::new(parking_lot::Mutex::new(Vec::new()));
    let target = boot.register_effect(
        "effect://identity/echo",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )
        .finalize_allowed()],
        Arc::new(IdentityDriver(Arc::clone(&calls))),
    )?;
    let operation = OperationTemplate {
        target,
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: None,
    };
    let caller_identity = boot
        .kernel()
        .identities()
        .resolve_or_register(&Path::parse("identity://actor/caller")?)?;
    let invoke = |input| {
        DoNode::op(OperationTemplate {
            literal_input: Some(Value::integer(input)),
            ..operation.clone()
        })
    };
    let actor = boot
        .spawn_actor_under(
            boot.root(),
            caller_identity,
            "root",
            &ActorSpec {
                name: "operation_identity".into(),
                body: invoke(1),
                declared_capabilities: vec!["perform://effect/identity/echo".into()],
                finalizers: vec![invoke(2), invoke(3)],
                ..ActorSpec::default()
            },
        )
        .await?;
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let directory = boot.kernel().state().read(&actor.directory).await?;
            if directory
                .as_ref()
                .and_then(Value::as_map)
                .and_then(|map| map.get("status"))
                .and_then(Value::as_str)
                == Some("completed")
            {
                return Ok::<_, xolotl_state::StateFailure>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    let calls = calls.lock().clone();
    ensure!(calls.len() == 3);
    for ((id, acting, caller, input), value) in calls.iter().zip([1, 3, 2]) {
        ensure!(*input == Value::integer(value));
        ensure!(*acting == caller_identity && *caller == actor.process);
        ensure!(id.position == NodeId::ROOT && id.invocation.get() == 1);
    }
    ensure!(
        calls
            .iter()
            .map(|(id, ..)| id.execution)
            .collect::<BTreeSet<_>>()
            .len()
            == 3
    );
    let lifecycle = boot
        .kernel()
        .processes()
        .lifecycle_execution(actor.process)
        .context("missing lifecycle identity")?;
    ensure!(calls.iter().all(|(id, ..)| id.execution != lifecycle));
    ensure!(boot.kernel().facts().facts_of(actor.process)?.is_empty());
    let directory = boot
        .kernel()
        .state()
        .read(&actor.directory)
        .await?
        .context("missing directory")?;
    ensure!(
        directory.as_map().and_then(|map| map.get("execution"))
            == Some(&Value::string(lifecycle.get().to_string()))
    );
    Ok(())
}

#[tokio::test]
async fn reserved_lifecycle_is_consumed_once_by_the_first_evaluation() -> anyhow::Result<()> {
    let boot = crate::fact::testing::observing_bootstrap();
    let operation = effect(&boot)?;
    let request = boot.request_under(
        boot.root(),
        IdentityRef::ROOT,
        &[crate::CompiledRequestGrantTemplate {
            selector: xolotl_types::ResourceSelector::parse("perform://effect/identity/echo")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("invoke"),
                xolotl_types::RightFlags::empty(),
            ),
        }],
    )?;
    let mut executor = request.executor().with_fact_recording(true);
    let reserved = executor.reserve_lifecycle().await?;
    ensure!(executor.reserve_lifecycle().await? == reserved);
    ensure!(boot.kernel().processes().lifecycle_execution(request.id()) == Some(reserved));
    ensure!(boot.kernel().facts().facts_of(request.id())?.is_empty());
    let program = DoNode::op(operation);
    let first = executor.eval(&program).await;
    let second = executor.eval(&program).await;
    ensure!(first.outcome == Outcome::Done(Value::integer(1)));
    ensure!(second.outcome == first.outcome);
    let facts = boot.kernel().facts().facts_of(request.id())?;
    ensure!(facts.len() == 2);
    ensure!(facts[0].id.execution == reserved);
    ensure!(facts[1].id.execution != reserved);
    ensure!(boot.kernel().processes().lifecycle_execution(request.id()) == Some(reserved));
    ensure!(executor.reserve_lifecycle().await.is_err());
    request.finish(&second).await?;
    Ok(())
}

type IdentityCalls = Arc<parking_lot::Mutex<Vec<(OperationId, IdentityRef, ProcessId, Value)>>>;

struct DispatchProbe {
    entered: tokio::sync::Notify,
    operation: parking_lot::Mutex<Option<OperationId>>,
}

#[async_trait::async_trait]
impl crate::Driver for DispatchProbe {
    async fn call(
        &self,
        _: xolotl_types::MethodId,
        _: Value,
        _: OutputMode,
        context: &crate::DriverContext,
    ) -> Result<DriverOutput, crate::DriverError> {
        *self.operation.lock() = context.operation_id;
        self.entered.notify_one();
        std::future::pending().await
    }
}

struct AuthorizationProbe {
    entered: tokio::sync::Notify,
    allow: bool,
}

#[async_trait::async_trait]
impl crate::RequestAuthorizer for AuthorizationProbe {
    async fn authorize(&self) -> Result<(), Failure> {
        self.entered.notify_one();
        if self.allow {
            Ok(())
        } else {
            std::future::pending().await
        }
    }
}

#[tokio::test]
async fn cancellation_distinguishes_authorization_wait_from_effect_dispatch() -> anyhow::Result<()>
{
    for dispatched in [false, true] {
        let boot = crate::fact::testing::observing_bootstrap();
        let driver = Arc::new(DispatchProbe {
            entered: tokio::sync::Notify::new(),
            operation: parking_lot::Mutex::new(None),
        });
        let target = boot.register_effect(
            "effect://identity/pending",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )],
            driver.clone(),
        )?;
        let authorizer = Arc::new(AuthorizationProbe {
            entered: tokio::sync::Notify::new(),
            allow: dispatched,
        });
        let executor = boot
            .kernel()
            .executor_for(boot.root())
            .with_request_authorizer(authorizer.clone());
        let program = DoNode::op(OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(Value::null()),
        });
        let call = executor.eval(&program);
        tokio::pin!(call);
        tokio::select! {
            output = &mut call => anyhow::bail!("call unexpectedly completed: {output:?}"),
            () = tokio::time::sleep(std::time::Duration::from_secs(1)) => anyhow::bail!("call did not reach the expected admission boundary"),
            () = async {
                if dispatched {
                    driver.entered.notified().await;
                } else {
                    authorizer.entered.notified().await;
                }
            } => {}
        }
        ensure!(
            boot.kernel()
                .processes()
                .cancel_if_non_terminal(boot.root())
                == Some(true)
        );
        let output = tokio::time::timeout(std::time::Duration::from_secs(1), call).await?;
        if dispatched {
            let id = driver
                .operation
                .lock()
                .context("missing dispatched identity")?
                .to_string();
            ensure!(output.outcome == Outcome::Fail(Failure::Cancelled));
            ensure!(output.unresolved_operations.operation_ids == vec![id]);
        } else {
            ensure!(output.outcome == Outcome::Fail(Failure::Cancelled));
            ensure!(output.unresolved_operations.operation_ids.is_empty());
            ensure!(driver.operation.lock().is_none());
        }
        ensure!(boot.kernel().facts().facts_of(boot.root())?.is_empty());
    }
    Ok(())
}

struct IdentityDriver(IdentityCalls);

#[async_trait::async_trait]
impl crate::Driver for IdentityDriver {
    async fn call(
        &self,
        _: xolotl_types::MethodId,
        input: Value,
        _: OutputMode,
        context: &crate::DriverContext,
    ) -> Result<DriverOutput, crate::DriverError> {
        let id = context
            .operation_id
            .ok_or_else(|| crate::DriverError::Other("missing operation identity".into()))?;
        self.0
            .lock()
            .push((id, context.acting, context.caller, input.clone()));
        Ok(DriverOutput::new(Outcome::Done(input)))
    }
}

struct Unavailable;
impl ExecutionIdSource for Unavailable {
    fn reserve(&self, _: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        Err(ExecutionIdError::Backend("identity source offline".into()))
    }
}

#[tokio::test]
async fn identity_failure_or_exhaustion_prevents_dispatch() -> anyhow::Result<()> {
    let sources: [Arc<dyn ExecutionIdSource>; 2] = [
        Arc::new(Unavailable),
        Arc::new(InMemoryExecutionIdSource::from_high_water(u64::MAX)),
    ];
    for source in sources {
        let boot = Bootstrap::from_kernel(
            crate::KernelBuilder::in_memory()
                .with_fact_sink(crate::FactSink::in_memory().0)
                .with_execution_ids(ExecutionIds::new(source))
                .build(),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let target = boot.register_effect(
            "effect://identity/fail",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(crate::FnDriver(move |_, _: Value| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(Value::null())
            })),
        )?;
        let outcome = boot
            .kernel()
            .executor_for(boot.root())
            .eval(&DoNode::op(OperationTemplate {
                target,
                method: "invoke".into(),
                method_id: None,
                output: OutputMode::Unary,
                literal_input: None,
            }))
            .await;
        ensure!(matches!(
            outcome.outcome,
            Outcome::Fail(Failure::PolicyViolation { .. })
        ));
        ensure!(calls.load(Ordering::SeqCst) == 0);
        ensure!(boot.kernel().facts().all_facts()?.is_empty());
        ensure!(
            boot.kernel()
                .processes()
                .lifecycle_execution(boot.root())
                .is_none()
        );
    }
    Ok(())
}

struct FailsBeforeFinalizer {
    calls: AtomicUsize,
    source: InMemoryExecutionIdSource,
}
impl ExecutionIdSource for FailsBeforeFinalizer {
    fn reserve(&self, _: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 1 {
            return Err(ExecutionIdError::Backend("retry reservation".into()));
        }
        self.source.reserve(NonZeroU64::MIN)
    }
}

#[tokio::test]
async fn allocation_failure_retains_an_unstarted_finalizer() -> anyhow::Result<()> {
    let boot = Bootstrap::from_kernel(
        crate::KernelBuilder::in_memory()
            .with_execution_ids(ExecutionIds::new(Arc::new(FailsBeforeFinalizer {
                calls: AtomicUsize::new(0),
                source: InMemoryExecutionIdSource::new(),
            })))
            .build(),
    );
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let process = boot.kernel().processes().fresh_id()?;
    let mut entry =
        crate::process::ProcessEntry::new(process, Some(boot.root()), IdentityRef::ROOT);
    entry.scope.start();
    entry.steps = StepModule::single("finalize", move |_, _| {
        observed.fetch_add(1, Ordering::SeqCst);
        DoNode::pure(Value::null())
    })?;
    entry
        .on_finalize
        .push(DoNode::pure(Value::null()).and_then(StepRef::new("finalize")));
    boot.kernel().processes().insert(entry);
    ensure!(matches!(
        boot.finalize_process(process).await,
        Err(crate::BootstrapError::ExecutionId(_))
    ));
    ensure!(calls.load(Ordering::SeqCst) == 0 && boot.kernel().processes().has_finalizers(process));
    let lifecycle = boot.kernel().processes().lifecycle_execution(process);
    boot.finalize_process(process).await?;
    ensure!(
        calls.load(Ordering::SeqCst) == 1 && !boot.kernel().processes().has_finalizers(process)
    );
    ensure!(boot.kernel().processes().lifecycle_execution(process) == lifecycle);
    Ok(())
}
