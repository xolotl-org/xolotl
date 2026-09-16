use super::*;
use crate::{
    Bootstrap, EchoDriver, ExecutionIdError, ExecutionIdRange, ExecutionIdSource, FactSink,
    InMemoryExecutionIdSource, InMemoryFactStore, Kernel, MethodSpec,
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
use xolotl_types::{Failure, OutputMode, Purity};

fn effect(boot: &Bootstrap) -> anyhow::Result<OperationTemplate> {
    let target = boot.register_effect(
        "effect://identity/echo",
        &[
            MethodSpec::new("invoke", Purity::Effectful, MethodSpec::UNARY_ASYNC)
                .finalize_allowed(),
        ],
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

#[tokio::test]
async fn independent_hosts_and_executors_share_the_fact_namespace() -> anyhow::Result<()> {
    let store = Arc::new(InMemoryFactStore::new());
    for _ in 0..2 {
        let boot = Bootstrap::from_kernel(Kernel::with_backends(
            InMemoryBackend::new().into_backend(),
            FactSink::new(store.clone()),
        ));
        let operation = effect(&boot)?;
        for _ in 0..2 {
            let executor = Executor::new(
                boot.root,
                boot.kernel.data_plane(),
                boot.kernel.registry.clone(),
            )
            .with_processes(boot.kernel.processes.clone());
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
async fn loop_and_parallel_calls_preserve_the_same_static_source_position() -> anyhow::Result<()> {
    let boot = Bootstrap::in_memory();
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
        .kernel
        .executor_for(boot.root)
        .eval_program(&compiled, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        matches!(outcome.outcome, Outcome::Fail(_)),
        "unbounded condition must hit its iteration ceiling"
    );
    let facts = boot.kernel.facts.facts_of(boot.root)?;
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
    let boot = Bootstrap::in_memory();
    let operation = effect(&boot)?;
    let invoke = |input| {
        DoNode::op(OperationTemplate {
            literal_input: Some(Value::integer(input)),
            ..operation.clone()
        })
    };
    let actor = boot
        .spawn_actor_under(
            boot.root,
            IdentityRef::ROOT,
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
            let directory = boot.kernel.state.read(&actor.directory).await?;
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
    let facts = boot.kernel.facts.facts_of(actor.process)?;
    ensure!(facts.len() == 4);
    let effects: Vec<_> = facts
        .iter()
        .filter(|fact| fact.id.invocation.get() != 0)
        .collect();
    ensure!(effects.len() == 3);
    for (fact, value) in effects.iter().zip([1, 3, 2]) {
        ensure!(fact.input == Value::integer(value));
        ensure!(fact.id.position == NodeId::ROOT && fact.id.invocation.get() == 1);
    }
    ensure!(
        effects
            .iter()
            .map(|fact| fact.id.execution)
            .collect::<BTreeSet<_>>()
            .len()
            == 3
    );
    ensure!(
        facts
            .iter()
            .map(|fact| fact.id)
            .collect::<BTreeSet<_>>()
            .len()
            == 4
    );
    let lifecycle = facts
        .iter()
        .find(|fact| fact.id.invocation.get() == 0)
        .context("missing lifecycle fact")?;
    ensure!(
        effects
            .iter()
            .all(|fact| fact.id.execution != lifecycle.id.execution)
    );
    let directory = boot
        .kernel
        .state
        .read(&actor.directory)
        .await?
        .context("missing directory")?;
    ensure!(
        directory.as_map().and_then(|map| map.get("execution"))
            == Some(&Value::string(lifecycle.id.execution.get().to_string()))
    );
    Ok(())
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
            Kernel::in_memory().with_execution_ids(ExecutionIds::new(source)),
        );
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let target = boot.register_effect(
            "effect://identity/fail",
            &[MethodSpec::new(
                "invoke",
                Purity::Effectful,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(crate::FnDriver(move |_, _: Value| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(Value::null())
            })),
        )?;
        let outcome = boot
            .kernel
            .executor_for(boot.root)
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
        ensure!(boot.kernel.facts.all_facts()?.is_empty());
        ensure!(
            boot.kernel
                .processes
                .lifecycle_execution(boot.root)
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
    let boot = Bootstrap::from_kernel(Kernel::in_memory().with_execution_ids(ExecutionIds::new(
        Arc::new(FailsBeforeFinalizer {
            calls: AtomicUsize::new(0),
            source: InMemoryExecutionIdSource::new(),
        }),
    )));
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let process = boot.kernel.processes.fresh_id()?;
    let mut entry = crate::process::ProcessEntry::new(process, Some(boot.root), IdentityRef::ROOT);
    entry.scope.start();
    entry.steps = StepModule::single("finalize", move |_, _| {
        observed.fetch_add(1, Ordering::SeqCst);
        DoNode::pure(Value::null())
    })?;
    entry
        .on_finalize
        .push(DoNode::pure(Value::null()).and_then(StepRef::new("finalize")));
    boot.kernel.processes.insert(entry);
    ensure!(matches!(
        boot.finalize_process(process).await,
        Err(crate::BootstrapError::ExecutionId(_))
    ));
    ensure!(calls.load(Ordering::SeqCst) == 0 && boot.kernel.processes.has_finalizers(process));
    let lifecycle = boot.kernel.processes.lifecycle_execution(process);
    boot.finalize_process(process).await?;
    ensure!(calls.load(Ordering::SeqCst) == 1 && !boot.kernel.processes.has_finalizers(process));
    ensure!(boot.kernel.processes.lifecycle_execution(process) == lifecycle);
    Ok(())
}
