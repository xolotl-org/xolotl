#![cfg(feature = "durable")]

use anyhow::{Context, ensure};
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use xolotl_graph::{
    OperationTemplate, WaitSpec,
    portable::{Expression as E, Program},
};
use xolotl_kernel::executor::durable::{
    CheckpointInfo, CheckpointJournal, CheckpointQuery, CheckpointStore, ExecutionCheckpoint,
    ExecutionSnapshot,
};
use xolotl_kernel::{
    Bootstrap, DurableRecoveryConfig, ExecutionIdError, ExecutionIdRange, ExecutionIdSource,
    FactSink, FnDriver, Kernel, MethodSpec, RequestGrantTemplate,
};
use xolotl_state::TaintedValue;
use xolotl_storage_redb::RedbStore;
use xolotl_types::{
    Failure, IdentityRef, Outcome, Path, ProcessId, ProcessStatus, Purity, ReplayClass, Value,
};

fn boot(store: &RedbStore, checkpoints: Arc<dyn CheckpointStore>) -> anyhow::Result<Bootstrap> {
    Ok(Bootstrap::from_kernel(
        Kernel::with_backends(
            store.state_backend().into_backend(),
            FactSink::new(Arc::new(store.fact_store()?)),
        )
        .with_checkpoint_store(checkpoints),
    ))
}

fn register_counter(
    boot: &Bootstrap,
    calls: Arc<AtomicUsize>,
) -> anyhow::Result<OperationTemplate> {
    let name = boot.register_effect_with_cost(
        "effect://counter/tick",
        &[MethodSpec::new(
            "invoke",
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(FnDriver(move |_method, _input| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Value::bytes(vec![0, 255]))
        })),
        xolotl_types::CostModel {
            flat_micro_usd: 100,
            ..Default::default()
        },
    )?;
    Ok(OperationTemplate {
        target: name,
        method: "invoke".into(),
        method_id: None,
        output: Default::default(),
        literal_input: None,
    })
}

fn request(boot: &Bootstrap) -> anyhow::Result<ProcessId> {
    Ok(boot.spawn_request_process_under_with_request_grants(
        boot.root,
        IdentityRef::ROOT,
        &[RequestGrantTemplate {
            literal: "perform://effect/counter/tick",
            methods: xolotl_types::MethodBitmap::method(0),
        }],
    )?)
}

#[tokio::test]
async fn checkpoint_restores_failure_provenance_held_during_cleanup() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("failure-provenance.redb"))?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let boot = boot(&store, checkpoints.clone())?;
    let process = boot.spawn_request_process_under_with_compiled_request_grants(
        boot.root,
        IdentityRef::ROOT,
        &[],
    )?;
    let signal = Path::parse("state://signal/failure-cleanup")?;
    let mut source = Program::new(
        E::Fail {
            message: "protected failure".into(),
        }
        .finally(E::Wait {
            wait: WaitSpec::Signal(signal.clone()),
        }),
    );
    source.durable = true;
    let prepared = xolotl_kernel::PreparedProgram::new(&source.compile()?)?;
    let executor = boot.kernel.executor_for(process);
    let taint = xolotl_types::TaintSet::of(xolotl_types::TaintSource::Protected {
        path: Path::parse("state://vault/checkpoint-failure")?,
    });
    let mut run = Box::pin(
        executor.eval_prepared(&prepared, TaintedValue::new(Value::null(), taint.clone())),
    );
    ensure!(
        std::future::poll_fn(|cx| std::task::Poll::Ready(std::future::Future::poll(
            run.as_mut(),
            cx
        )))
        .await
        .is_pending()
    );
    drop(run);
    let mut journal = checkpoints.acquire(process)?;
    let saved = journal.load(usize::MAX)?.context("cleanup checkpoint")?;
    ensure!(!saved.finished && saved.pending.len() == 1);
    drop(journal);
    boot.kernel.state.write_set(&signal, Value::null()).await?;
    let output = executor
        .eval_prepared(&saved.program, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(matches!(output.outcome, Outcome::Fail(_)), "{output:?}");
    ensure!(output.taint == taint, "{output:?}");
    let mut journal = checkpoints.acquire(process)?;
    let finished = journal.load(usize::MAX)?.context("finished checkpoint")?;
    let checkpoint = finished.machine.checkpoint();
    let Err(error) = checkpoint.result().context("terminal result")? else {
        anyhow::bail!("checkpoint must retain the failed result");
    };
    ensure!(error.taint == taint);
    drop(journal);
    ensure!(boot.finish_checkpointed_request(process, &output).await?);
    Ok(())
}

#[tokio::test]
async fn recovery_reuses_the_saved_layout_within_current_host_ceilings() -> anyhow::Result<()> {
    use xolotl_kernel::{ExecutionConfig, PreparedProgram};
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("layout.redb"))?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let boot = boot(&store, checkpoints.clone())?;
    let process = boot.spawn_request_process_under_with_compiled_request_grants(
        boot.root,
        IdentityRef::ROOT,
        &[],
    )?;
    let signal = Path::parse("state://signal/layout")?;
    let call = E::Call {
        function: "wait".into(),
    };
    let mut source = Program::new(call.clone());
    source.functions.insert(
        "wait".into(),
        E::If {
            condition: Box::new(E::literal(false)),
            yes: Box::new(call),
            no: Box::new(E::Wait {
                wait: WaitSpec::Signal(signal.clone()),
            }),
        },
    );
    source.durable = true;
    let prepared = PreparedProgram::new(&source.compile()?)?;
    let original = boot
        .kernel
        .executor_for(process)
        .with_execution_config(ExecutionConfig {
            frames_per_task: 8,
            ..ExecutionConfig::default()
        });
    ensure!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            original.eval_prepared(&prepared, TaintedValue::pristine(Value::null())),
        )
        .await
        .is_err()
    );
    let saved = checkpoints
        .snapshots()?
        .pop()
        .context("missing checkpoint")?;
    ensure!(saved.machine.meta.limits.frames_per_task == 8);

    let restricted = boot
        .kernel
        .executor_for(process)
        .with_execution_config(ExecutionConfig {
            frames_per_task: 4,
            ..ExecutionConfig::default()
        });
    let output = restricted
        .eval_prepared(&saved.program, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        matches!(output.outcome, Outcome::Fail(Failure::PolicyViolation { ref detail, .. })
        if detail.contains("checkpoint exceeds"))
    );

    boot.kernel
        .state
        .write_set(&signal, Value::boolean(true))
        .await?;
    let resumed = boot
        .kernel
        .executor_for(process)
        .with_execution_config(ExecutionConfig {
            frames_per_task: 16,
            ..ExecutionConfig::default()
        });
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        resumed.eval_prepared(&saved.program, TaintedValue::pristine(Value::null())),
    )
    .await?;
    ensure!(
        output.outcome == Outcome::Done(Value::boolean(true)),
        "resume failed: {output:?}"
    );
    let finished = checkpoints
        .snapshots()?
        .pop()
        .context("missing completed checkpoint")?;
    ensure!(finished.finished);
    ensure!(finished.machine.meta.limits.frames_per_task == 8);
    ensure!(boot.finish_checkpointed_request(process, &output).await?);
    Ok(())
}

#[tokio::test]
async fn reopening_database_resumes_bindings_without_repeating_completed_effects()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("kernel.redb");
    let signal = Path::parse("state://signal/continue")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let process = {
        let store = RedbStore::open(&path)?;
        let checkpoints = Arc::new(store.checkpoint_store());
        let boot = boot(&store, checkpoints.clone())?;
        let op = register_counter(&boot, calls.clone())?;
        let mut program = Program::new(E::Let {
            name: "result".into(),
            value: Box::new(E::Invoke { operation: op }),
            body: Box::new(
                E::Wait {
                    wait: WaitSpec::Signal(signal.clone()),
                }
                .then(E::Use {
                    name: "result".into(),
                }),
            ),
        });
        program.durable = true;
        let compiled = program.compile()?;
        let process = request(&boot)?;
        let executor = boot.kernel.executor_for(process);
        ensure!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                executor.eval_program(&compiled, TaintedValue::pristine(Value::null()))
            )
            .await
            .is_err()
        );
        ensure!(calls.load(Ordering::SeqCst) == 1);
        let saved = checkpoints
            .snapshots()?
            .pop()
            .context("missing checkpoint")?;
        ensure!(!saved.finished && saved.pending.len() == 1);
        ensure!(
            saved
                .machine
                .bindings
                .iter()
                .flatten()
                .any(|value| value.value == Value::bytes(vec![0, 255]))
        );
        process
    };
    let store = RedbStore::open(&path)?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let boot = boot(&store, checkpoints.clone())?;
    register_counter(&boot, calls.clone())?;
    boot.reserve_checkpoint_process_ids()?;
    let saved = checkpoints
        .snapshots()?
        .pop()
        .context("missing persisted checkpoint")?;
    boot.restore_checkpoint_process(&saved)?;
    boot.kernel
        .state
        .write_set(&signal, Value::boolean(true))
        .await?;
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        boot.kernel
            .executor_for(process)
            .eval_prepared(&saved.program, TaintedValue::pristine(Value::null())),
    )
    .await?;
    ensure!(
        output.outcome == Outcome::Done(Value::bytes(vec![0, 255])),
        "restored value changed: {output:?}"
    );
    ensure!(
        calls.load(Ordering::SeqCst) == 1,
        "completed effect repeated"
    );
    ensure!(boot.finish_checkpointed_request(process, &output).await?);
    ensure!(checkpoints.snapshots()?.is_empty());
    let next = request(&boot)?;
    ensure!(next.get() > process.get());
    Ok(())
}

struct FaultyStore {
    inner: Arc<dyn CheckpointStore>,
    fail_on: usize,
    writes: Arc<AtomicUsize>,
    ticket_floor: u64,
    commit_limit: usize,
    retire_before_commit: bool,
    corruption: Option<CheckpointCorruption>,
}
struct FaultyJournal {
    inner: Box<dyn CheckpointJournal>,
    fail_on: usize,
    writes: Arc<AtomicUsize>,
    ticket_floor: u64,
    commit_limit: usize,
    retire_before_commit: bool,
    corruption: Option<CheckpointCorruption>,
}

#[derive(Clone, Copy)]
enum CheckpointCorruption {
    MissingTask,
    UnsupportedVersion,
    UnexpectedPending,
}
impl CheckpointStore for FaultyStore {
    fn try_acquire(
        &self,
        process: ProcessId,
    ) -> Result<Option<Box<dyn CheckpointJournal>>, Failure> {
        let Some(inner) = self.inner.try_acquire(process)? else {
            return Ok(None);
        };
        Ok(Some(Box::new(FaultyJournal {
            inner,
            fail_on: self.fail_on,
            writes: self.writes.clone(),
            ticket_floor: self.ticket_floor,
            commit_limit: self.commit_limit,
            retire_before_commit: self.retire_before_commit,
            corruption: self.corruption,
        })))
    }
    fn high_water(&self) -> Result<Option<ProcessId>, Failure> {
        self.inner.high_water()
    }
    fn scan(&self, query: CheckpointQuery) -> Result<Vec<CheckpointInfo>, Failure> {
        self.inner.scan(query)
    }
    fn snapshots(&self) -> Result<Vec<ExecutionSnapshot>, Failure> {
        self.inner.snapshots()
    }
}
impl ExecutionIdSource for FaultyStore {
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        self.inner.reserve(count)
    }
}
impl CheckpointJournal for FaultyJournal {
    fn load(&mut self, max_bytes: usize) -> Result<Option<ExecutionSnapshot>, Failure> {
        Ok(self.inner.load(max_bytes)?.map(|mut snapshot| {
            snapshot.machine.meta.ticket = snapshot.machine.meta.ticket.max(self.ticket_floor);
            match self.corruption {
                Some(CheckpointCorruption::MissingTask) => {
                    snapshot.machine.tasks.pop();
                }
                Some(CheckpointCorruption::UnsupportedVersion) => {
                    snapshot.machine.meta.version += 1;
                }
                Some(CheckpointCorruption::UnexpectedPending) => {
                    snapshot.pending.insert(u64::MAX, ReplayClass::Observation);
                }
                None => {}
            }
            snapshot
        }))
    }
    fn commit(
        &mut self,
        checkpoint: &ExecutionCheckpoint<'_>,
        max_bytes: usize,
    ) -> Result<(), Failure> {
        if self.writes.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_on {
            return Err(Failure::Custom {
                kind: "checkpoint_store".into(),
                message: "injected disk failure".into(),
            });
        }
        if self.retire_before_commit {
            self.inner.retire()?;
        }
        self.inner
            .commit(checkpoint, max_bytes.min(self.commit_limit))
    }
    fn retire(&mut self) -> Result<(), Failure> {
        self.inner.retire()
    }
}

#[tokio::test]
async fn checkpoint_byte_limits_preserve_prior_records_and_high_water() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("checkpoint-limits.redb"))?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let limited = Arc::new(FaultyStore {
        inner: checkpoints.clone(),
        fail_on: usize::MAX,
        writes: Arc::new(AtomicUsize::new(0)),
        ticket_floor: 0,
        commit_limit: 0,
        retire_before_commit: false,
        corruption: None,
    });
    let boot = boot(&store, checkpoints.clone())?;
    let process = boot.spawn_request_process_under_with_compiled_request_grants(
        boot.root,
        IdentityRef::ROOT,
        &[],
    )?;
    let signal = Path::parse("state://signal/checkpoint-limits")?;
    let mut source = Program::new(E::Wait {
        wait: WaitSpec::Signal(signal.clone()),
    });
    source.durable = true;
    let program = source.compile()?;
    let output = boot
        .kernel
        .executor_for(process)
        .with_checkpoint_store(limited.clone())
        .eval_program(&program, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(matches!(output.outcome, Outcome::Fail(_)));
    ensure!(checkpoints.snapshots()?.is_empty());
    ensure!(checkpoints.high_water()?.is_none());

    ensure!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            boot.kernel
                .executor_for(process)
                .eval_program(&program, TaintedValue::pristine(Value::null())),
        )
        .await
        .is_err()
    );
    let saved = checkpoints
        .snapshots()?
        .pop()
        .context("waiting checkpoint")?;
    let previous = serde_json::to_vec(&saved)?;
    let page = checkpoints.scan(CheckpointQuery {
        after: None,
        through: process,
        limit: NonZeroUsize::MIN,
    })?;
    ensure!(
        page == [CheckpointInfo {
            process,
            encoded_bytes: previous.len()
        }]
    );
    let high_water = checkpoints.high_water()?;
    ensure!(high_water == Some(process));
    {
        let mut lease = checkpoints.acquire(process)?;
        ensure!(lease.load(previous.len() - 1).is_err());
        let loaded = lease
            .load(previous.len())?
            .context("exact-limit checkpoint")?;
        ensure!(serde_json::to_vec(&loaded)? == previous);
    }
    boot.kernel
        .state
        .write_set(&signal, Value::boolean(true))
        .await?;
    let output = boot
        .kernel
        .executor_for(process)
        .with_checkpoint_store(limited)
        .eval_prepared(&saved.program, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(matches!(output.outcome, Outcome::Fail(_)));
    ensure!(checkpoints.high_water()? == high_water);
    let retained = checkpoints
        .snapshots()?
        .pop()
        .context("retained checkpoint after failure")?;
    ensure!(serde_json::to_vec(&retained)? == previous);
    Ok(())
}

#[tokio::test]
async fn retired_leases_cannot_recreate_checkpoint_records() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("retired-lease.redb"))?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let retiring = Arc::new(FaultyStore {
        inner: checkpoints.clone(),
        fail_on: usize::MAX,
        writes: Arc::new(AtomicUsize::new(0)),
        ticket_floor: 0,
        commit_limit: usize::MAX,
        retire_before_commit: true,
        corruption: None,
    });
    let boot = boot(&store, retiring)?;
    let process = boot.spawn_request_process_under_with_compiled_request_grants(
        boot.root,
        IdentityRef::ROOT,
        &[],
    )?;
    let mut source = Program::new(E::literal(7_i64));
    source.durable = true;
    let output = boot
        .kernel
        .executor_for(process)
        .eval_program(&source.compile()?, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(matches!(output.outcome, Outcome::Fail(ref failure)
        if failure.to_string().contains("retired journal lease")));
    ensure!(checkpoints.snapshots()?.is_empty());
    ensure!(checkpoints.high_water()? == Some(process));
    Ok(())
}

#[tokio::test]
async fn commit_failures_prevent_dispatch_or_quarantine_uncertain_effects() -> anyhow::Result<()> {
    for fail_on in [2, 3] {
        let directory = tempfile::tempdir()?;
        let store = RedbStore::open(directory.path().join("kernel.redb"))?;
        let checkpoints = Arc::new(store.checkpoint_store());
        let faulty = Arc::new(FaultyStore {
            inner: checkpoints.clone(),
            fail_on,
            writes: Arc::new(AtomicUsize::new(0)),
            ticket_floor: 0,
            commit_limit: usize::MAX,
            retire_before_commit: false,
            corruption: None,
        });
        let boot = boot(&store, faulty)?;
        let calls = Arc::new(AtomicUsize::new(0));
        let op = register_counter(&boot, calls.clone())?;
        let mut source = Program::new(E::Invoke { operation: op });
        source.durable = true;
        let program = source.compile()?;
        let process = request(&boot)?;
        let output = boot
            .kernel
            .executor_for(process)
            .eval_program(&program, TaintedValue::pristine(Value::null()))
            .await;
        ensure!(
            matches!(output.outcome, Outcome::Fail(_)),
            "injected failure was lost"
        );
        ensure!(calls.load(Ordering::SeqCst) == usize::from(fail_on == 3));
        ensure!(
            !boot.finish_checkpointed_request(process, &output).await?,
            "unfinished execution was finalized"
        );
        if fail_on == 3 {
            let saved = checkpoints
                .snapshots()?
                .pop()
                .context("missing pending effect")?;
            ensure!(
                saved.process.budget.spent_micro_usd >= 100,
                "uncertain spending was absent from the dispatch checkpoint"
            );
            let output = boot
                .kernel
                .executor_for(process)
                .with_checkpoint_store(checkpoints.clone())
                .eval_program(&program, TaintedValue::pristine(Value::null()))
                .await;
            ensure!(
                matches!(output.outcome, Outcome::Fail(Failure::Quarantined { .. })),
                "uncertain effect was not held: {output:?}"
            );
            ensure!(calls.load(Ordering::SeqCst) == 1);
        }
        let lease = checkpoints.acquire(process)?;
        ensure!(
            checkpoints.acquire(process).is_err(),
            "concurrent executor acquired journal"
        );
        drop(lease);
        drop(checkpoints.acquire(process)?);
    }
    Ok(())
}

#[tokio::test]
async fn resumed_invocations_keep_u64_tickets_and_static_source_positions() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("large-ticket.redb"))?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let boot = boot(&store, checkpoints.clone())?;
    let calls = Arc::new(AtomicUsize::new(0));
    let operation = register_counter(&boot, calls.clone())?;
    let signal = Path::parse("state://signal/large-ticket")?;
    let mut source = Program::new(
        E::Wait {
            wait: WaitSpec::Signal(signal.clone()),
        }
        .then(E::Invoke { operation }),
    );
    source.durable = true;
    let compiled = source.compile()?;
    let process = request(&boot)?;
    ensure!(
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            boot.kernel
                .executor_for(process)
                .eval_program(&compiled, TaintedValue::pristine(Value::null())),
        )
        .await
        .is_err()
    );
    let saved = checkpoints
        .snapshots()?
        .pop()
        .context("missing waiting checkpoint")?;
    let ticket_floor = u64::from(u32::MAX) + 100;
    let offset = Arc::new(FaultyStore {
        inner: checkpoints.clone(),
        fail_on: usize::MAX,
        writes: Arc::new(AtomicUsize::new(0)),
        ticket_floor,
        commit_limit: usize::MAX,
        retire_before_commit: false,
        corruption: None,
    });
    boot.kernel
        .state
        .write_set(&signal, Value::boolean(true))
        .await?;
    let output = boot
        .kernel
        .executor_for(process)
        .with_checkpoint_store(offset)
        .eval_prepared(&saved.program, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::bytes(vec![0, 255])),
        "resume failed: {output:?}"
    );
    let facts = boot.kernel.facts.facts_of(process)?;
    let fact = facts.first().context("missing resumed operation fact")?;
    ensure!(fact.id.execution == saved.execution);
    ensure!(fact.id.invocation.get() == ticket_floor + 1);
    ensure!((fact.id.position.get() as usize) < compiled.image().nodes.len());
    ensure!(calls.load(Ordering::SeqCst) == 1);
    let finished = checkpoints
        .snapshots()?
        .pop()
        .context("missing final checkpoint")?;
    ensure!(finished.finished && finished.execution == saved.execution);
    ensure!(finished.machine.meta.ticket == ticket_floor + 1);
    Ok(())
}

#[derive(Default)]
struct InterruptedDriver {
    ids: parking_lot::Mutex<Vec<xolotl_types::OperationId>>,
}

#[async_trait::async_trait]
impl xolotl_kernel::Driver for InterruptedDriver {
    async fn call(
        &self,
        _method: xolotl_types::MethodId,
        _input: Value,
        _output: xolotl_types::OutputMode,
        ctx: &xolotl_kernel::DriverContext,
    ) -> Result<xolotl_kernel::DriverOutput, xolotl_kernel::DriverError> {
        let id = ctx
            .operation_id
            .ok_or_else(|| xolotl_kernel::DriverError::Other("missing operation id".into()))?;
        let first = {
            let mut ids = self.ids.lock();
            ids.push(id);
            ids.len() == 1
        };
        if first {
            std::future::pending::<()>().await;
        }
        Ok(xolotl_kernel::DriverOutput::new(Outcome::Done(
            Value::integer(7),
        )))
    }
}

fn register_interrupted_driver(
    boot: &Bootstrap,
    driver: Arc<InterruptedDriver>,
) -> anyhow::Result<OperationTemplate> {
    let target = boot.register_effect(
        "effect://counter/tick",
        &[MethodSpec::new(
            "invoke",
            Purity::Idempotent,
            MethodSpec::UNARY_ASYNC,
        )],
        driver,
    )?;
    Ok(OperationTemplate {
        target,
        method: "invoke".into(),
        method_id: None,
        output: Default::default(),
        literal_input: None,
    })
}

#[tokio::test]
async fn pending_invocation_identity_survives_reopen_with_ephemeral_facts() -> anyhow::Result<()> {
    pending_invocation_after_reopen(false).await
}

#[tokio::test]
async fn pending_invocation_reuses_its_retained_fact_slot_after_reopen() -> anyhow::Result<()> {
    pending_invocation_after_reopen(true).await
}

async fn pending_invocation_after_reopen(retain_facts: bool) -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("identity.redb");
    let driver = Arc::new(InterruptedDriver::default());
    let process = {
        let store = RedbStore::open(&path)?;
        let checkpoints = Arc::new(store.checkpoint_store());
        let boot = if retain_facts {
            boot(&store, checkpoints.clone())?
        } else {
            Bootstrap::from_kernel(Kernel::in_memory().with_checkpoint_store(checkpoints.clone()))
        };
        let operation = register_interrupted_driver(&boot, driver.clone())?;
        let mut source = Program::new(E::Invoke { operation });
        source.durable = true;
        let compiled = source.compile()?;
        let process = request(&boot)?;
        ensure!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                boot.kernel
                    .executor_for(process)
                    .eval_program(&compiled, TaintedValue::pristine(Value::null())),
            )
            .await
            .is_err()
        );
        let saved = checkpoints
            .snapshots()?
            .pop()
            .context("missing interrupted checkpoint")?;
        ensure!(!saved.finished && saved.pending.len() == 1);
        let facts = boot.kernel.facts.facts_of(process)?;
        ensure!(facts.len() == 1 && !facts[0].is_complete());
        process
    };
    let store = RedbStore::open(&path)?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let boot = if retain_facts {
        boot(&store, checkpoints.clone())?
    } else {
        Bootstrap::from_kernel(Kernel::in_memory().with_checkpoint_store(checkpoints.clone()))
    };
    let operation = register_interrupted_driver(&boot, driver.clone())?;
    boot.reserve_checkpoint_process_ids()?;
    let fresh_process = request(&boot)?;
    let fresh = Program::new(E::Invoke { operation }).compile()?;
    ensure!(
        boot.kernel
            .executor_for(fresh_process)
            .eval_program(&fresh, TaintedValue::pristine(Value::null()))
            .await
            .outcome
            == Outcome::Done(Value::integer(7))
    );
    let saved = checkpoints
        .snapshots()?
        .into_iter()
        .find(|saved| saved.process.id == process)
        .context("missing saved execution")?;
    boot.restore_checkpoint_process(&saved)?;
    let output = boot
        .kernel
        .executor_for(process)
        .eval_prepared(&saved.program, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(7)),
        "restore failed: {output:?}"
    );
    let ids = driver.ids.lock();
    ensure!(ids.len() == 3);
    ensure!(ids[0] == ids[2], "restored operation identity changed");
    ensure!(
        ids[0].execution != ids[1].execution,
        "fresh work reused the saved execution scope"
    );
    let finished = checkpoints
        .snapshots()?
        .into_iter()
        .find(|saved| saved.process.id == process)
        .context("missing completed checkpoint")?;
    ensure!(finished.finished && finished.execution == saved.execution);
    ensure!(finished.process.lifecycle_execution == saved.process.lifecycle_execution);
    let facts = boot.kernel.facts.facts_of(process)?;
    ensure!(
        facts.len() == 1 && facts[0].is_complete(),
        "resumed operation left a stale pending fact: {facts:?}"
    );
    ensure!(facts[0].id == ids[0]);
    ensure!(
        boot.kernel.facts.cursor() == 2,
        "retry advanced the fact cursor"
    );
    Ok(())
}

#[tokio::test]
async fn startup_holds_missing_providers_then_resumes_once() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("startup.redb");
    let signal = Path::parse("state://signal/startup")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let process = {
        let store = RedbStore::open(&path)?;
        let checkpoints = Arc::new(store.checkpoint_store());
        let boot = boot(&store, checkpoints.clone())?;
        let operation = register_counter(&boot, calls.clone())?;
        let mut source = Program::new(
            E::Wait {
                wait: WaitSpec::Signal(signal.clone()),
            }
            .then(E::Invoke { operation }),
        );
        source.durable = true;
        let program = source.compile()?;
        let process = request(&boot)?;
        ensure!(
            tokio::time::timeout(
                std::time::Duration::from_millis(50),
                boot.kernel
                    .executor_for(process)
                    .eval_program(&program, TaintedValue::pristine(Value::null()))
            )
            .await
            .is_err()
        );
        process
    };
    let store = RedbStore::open(&path)?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let boot = Arc::new(boot(&store, checkpoints.clone())?);
    boot.reserve_checkpoint_process_ids()?;
    let held = boot.resume_checkpointed_processes().await?;
    ensure!(held.resumed == 0 && held.quarantined == 1);
    let saved = checkpoints
        .snapshots()?
        .pop()
        .context("missing held checkpoint")?;
    ensure!(!saved.finished);
    let marker = Path::parse(&format!(
        "state://kernel/process/{}/{}/finalized",
        process.get(),
        saved.process.lifecycle_execution.get()
    ))?;
    register_counter(&boot, calls.clone())?;
    boot.kernel
        .state
        .write_set(&signal, Value::boolean(true))
        .await?;
    let (a, b) = tokio::join!(
        boot.resume_checkpointed_processes(),
        boot.resume_checkpointed_processes()
    );
    ensure!(
        a?.resumed + b?.resumed == 1,
        "concurrent recovery scheduled duplicate executions"
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if boot.kernel.state.read(&marker).await?.is_some()
                && checkpoints.snapshots()?.is_empty()
            {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    ensure!(calls.load(Ordering::SeqCst) == 1);
    ensure!(boot.resume_checkpointed_processes().await?.resumed == 0);
    ensure!(checkpoints.snapshots()?.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_new_recovery_sweep_retries_low_ids_after_higher_ids_are_reaped() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("recovery-sweeps.redb");
    let signal = Path::parse("state://signal/low-checkpoint")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let (low, high, saved) = {
        let store = RedbStore::open(&path)?;
        let checkpoints = Arc::new(store.checkpoint_store());
        let boot = boot(&store, checkpoints.clone())?;
        let operation = register_counter(&boot, calls.clone())?;
        let mut source = Program::new(
            E::Wait {
                wait: WaitSpec::Signal(signal.clone()),
            }
            .then(E::Invoke { operation }),
        );
        source.durable = true;
        let program = source.compile()?;
        let low = request(&boot)?;
        let executor = boot.kernel.executor_for(low);
        let mut run =
            Box::pin(executor.eval_program(&program, TaintedValue::pristine(Value::null())));
        ensure!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(run.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(run);
        let saved = checkpoints
            .snapshots()?
            .pop()
            .context("waiting low checkpoint")?;
        let high = boot.spawn_request_process_under_with_compiled_request_grants(
            boot.root,
            IdentityRef::ROOT,
            &[],
        )?;
        let mut source = Program::new(E::literal(17));
        source.durable = true;
        let output = boot
            .kernel
            .executor_for(high)
            .eval_program(&source.compile()?, TaintedValue::pristine(Value::null()))
            .await;
        ensure!(output.outcome == Outcome::Done(Value::integer(17)));
        ensure!(low < high && calls.load(Ordering::SeqCst) == 0);
        (low, high, saved)
    };
    let store = RedbStore::open(&path)?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let mut recovered = boot(&store, checkpoints.clone())?;
    recovered
        .kernel
        .processes
        .set_capacity(NonZeroUsize::new(2))?;
    recovered.kernel = recovered
        .kernel
        .with_checkpoint_recovery_config(DurableRecoveryConfig {
            page_size: NonZeroUsize::new(2).context("two checkpoint directory entries")?,
            max_in_flight: NonZeroUsize::MIN,
            reap_batch: 1,
        });
    let recovered = Arc::new(recovered);
    let mut first = recovered.checkpoint_recovery()?;
    let report = first.advance().await?;
    ensure!(report.quarantined == 1 && report.resumed == 1 && !report.complete);
    ensure!(recovered.kernel.processes.status(low).is_none());
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if recovered.kernel.processes.status(high) == Some(ProcessStatus::Completed)
                && checkpoints
                    .scan(CheckpointQuery {
                        after: Some(low),
                        through: high,
                        limit: NonZeroUsize::MIN,
                    })?
                    .is_empty()
            {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    ensure!(first.advance().await?.complete);
    ensure!(recovered.kernel.processes.len() == 1);
    ensure!(recovered.kernel.processes.status(high).is_none());
    ensure!(checkpoints.high_water()? == Some(high));

    register_counter(&recovered, calls.clone())?;
    let error = recovered
        .restore_checkpoint_process(&saved)
        .err()
        .context("arbitrary snapshot import reopened after reap")?;
    ensure!(error.to_string().contains("checkpoint admission is closed"));
    recovered
        .kernel
        .state
        .write_set(&signal, Value::boolean(true))
        .await?;
    let report = recovered.checkpoint_recovery()?.advance().await?;
    ensure!(report.resumed == 1 && report.quarantined == 0 && report.complete);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if recovered.kernel.processes.status(low) == Some(ProcessStatus::Completed)
                && checkpoints.snapshots()?.is_empty()
            {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    ensure!(calls.load(Ordering::SeqCst) == 1);
    ensure!(recovered.kernel.processes.len() <= 2);
    ensure!(checkpoints.high_water()? == Some(high));
    Ok(())
}

#[tokio::test]
async fn automatic_recovery_validates_finished_machine_state_before_admission() -> anyhow::Result<()>
{
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("invalid-finished.redb"))?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let process = {
        let boot = boot(&store, checkpoints.clone())?;
        let process = boot.spawn_request_process_under_with_compiled_request_grants(
            boot.root,
            IdentityRef::ROOT,
            &[],
        )?;
        let mut source = Program::new(E::literal(23));
        source.durable = true;
        let output = boot
            .kernel
            .executor_for(process)
            .eval_program(&source.compile()?, TaintedValue::pristine(Value::null()))
            .await;
        ensure!(output.outcome == Outcome::Done(Value::integer(23)));
        process
    };
    let saved = checkpoints
        .snapshots()?
        .pop()
        .context("finished checkpoint")?;
    ensure!(saved.finished && saved.pending.is_empty());
    for corruption in [
        CheckpointCorruption::MissingTask,
        CheckpointCorruption::UnsupportedVersion,
        CheckpointCorruption::UnexpectedPending,
    ] {
        let writes = Arc::new(AtomicUsize::new(0));
        let corrupted = Arc::new(FaultyStore {
            inner: checkpoints.clone(),
            fail_on: usize::MAX,
            writes: writes.clone(),
            ticket_floor: 0,
            commit_limit: usize::MAX,
            retire_before_commit: false,
            corruption: Some(corruption),
        });
        let boot = Arc::new(boot(&store, corrupted)?);
        boot.kernel.processes.set_capacity(NonZeroUsize::new(2))?;
        let report = boot.checkpoint_recovery()?.advance().await?;
        ensure!(report.resumed == 0 && report.quarantined == 1 && report.complete);
        ensure!(boot.kernel.processes.status(process).is_none());
        ensure!(boot.kernel.processes.len() == 1);
        ensure!(boot.kernel.facts.facts_of(process)?.is_empty());
        ensure!(writes.load(Ordering::SeqCst) == 0);
        ensure!(checkpoints.acquire(process)?.load(usize::MAX)?.is_some());
    }
    let boot = Arc::new(boot(&store, checkpoints.clone())?);
    let report = boot.checkpoint_recovery()?.advance().await?;
    ensure!(report.resumed == 1 && report.quarantined == 0);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if checkpoints.snapshots()?.is_empty() {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn changed_pending_replay_contract_is_held_before_process_admission() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("changed-replay-contract.redb");
    let driver = Arc::new(InterruptedDriver::default());
    let saved = {
        let store = RedbStore::open(&path)?;
        let checkpoints = Arc::new(store.checkpoint_store());
        let boot = boot(&store, checkpoints.clone())?;
        let operation = register_interrupted_driver(&boot, driver.clone())?;
        let mut source = Program::new(E::Invoke { operation });
        source.durable = true;
        let program = source.compile()?;
        let process = request(&boot)?;
        let executor = boot.kernel.executor_for(process);
        let mut run =
            Box::pin(executor.eval_program(&program, TaintedValue::pristine(Value::null())));
        ensure!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(run.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(run);
        let saved = checkpoints
            .snapshots()?
            .pop()
            .context("interrupted idempotent checkpoint")?;
        ensure!(!saved.finished && saved.pending.len() == 1);
        ensure!(
            saved
                .pending
                .values()
                .all(|class| *class == ReplayClass::IdempotentEffect)
        );
        ensure!(driver.ids.lock().len() == 1);
        saved
    };
    let store = RedbStore::open(&path)?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let boot = Arc::new(boot(&store, checkpoints.clone())?);
    boot.kernel.processes.set_capacity(NonZeroUsize::new(2))?;
    let calls = Arc::new(AtomicUsize::new(0));
    register_counter(&boot, calls.clone())?;
    let before = boot.kernel.facts.facts_of(saved.process.id)?;
    ensure!(before.len() == 1 && !before[0].is_complete());

    let report = boot.checkpoint_recovery()?.advance().await?;
    ensure!(report.resumed == 0 && report.quarantined == 1 && report.complete);
    ensure!(boot.kernel.processes.status(saved.process.id).is_none());
    ensure!(boot.kernel.processes.len() == 1);
    ensure!(calls.load(Ordering::SeqCst) == 0);
    ensure!(boot.kernel.facts.facts_of(saved.process.id)? == before);
    let retained = checkpoints
        .acquire(saved.process.id)?
        .load(usize::MAX)?
        .context("retained replay-contract checkpoint")?;
    ensure!(serde_json::to_vec(&retained)? == serde_json::to_vec(&saved)?);
    let other = request(&boot)?;
    ensure!(other > saved.process.id && boot.kernel.processes.len() == 2);
    Ok(())
}

#[tokio::test]
async fn durability_rejects_processes_and_outputs_that_cannot_be_restored() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = RedbStore::open(directory.path().join("admission.redb"))?;
    let checkpoints = Arc::new(store.checkpoint_store());
    let boot = boot(&store, checkpoints.clone())?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut operation = register_counter(&boot, calls.clone())?;
    let mut source = Program::new(E::Invoke {
        operation: operation.clone(),
    });
    source.durable = true;
    let program = source.compile()?;
    let parent = request(&boot)?;
    let child =
        boot.spawn_request_process_under_with_request_grants(parent, IdentityRef::ROOT, &[])?;
    for process in [boot.root, child] {
        let output = boot
            .kernel
            .executor_for(process)
            .eval_program(&program, TaintedValue::pristine(Value::null()))
            .await;
        ensure!(matches!(output.outcome, Outcome::Fail(_)));
    }
    operation.output = xolotl_types::OutputMode::AsyncProcess;
    source.body = E::Invoke { operation };
    let program = source.compile()?;
    ensure!(matches!(
        boot.kernel
            .executor_for(parent)
            .eval_program(&program, TaintedValue::pristine(Value::null()))
            .await
            .outcome,
        Outcome::Fail(_)
    ));
    ensure!(calls.load(Ordering::SeqCst) == 0);
    ensure!(checkpoints.snapshots()?.is_empty());
    Ok(())
}
