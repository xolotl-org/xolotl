#![cfg(feature = "durable")]

#[path = "durable/workflow.rs"]
mod workflow;

use anyhow::{Context, ensure};
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::ops::Bound;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::task::Poll;
use std::time::Duration;
use xolotl_graph::WaitSpec;
use xolotl_sdk::{
    Bootstrap, CheckpointInfo, CheckpointJournal, CheckpointQuery, CheckpointStore,
    DurableRecoveryConfig, ExecutionCheckpoint, ExecutionConfig, ExecutionIdError,
    ExecutionIdRange, ExecutionIdSource, ExecutionIds, ExecutionSnapshot, Expression, FactSink,
    Failure, IdentityRef, InMemoryBackend, InMemoryExecutionIdSource, Outcome, Path,
    PreparedProgram, ProcessId, Program, StateResult, Value, XolotlBuilder,
};
use xolotl_state::{
    Backend, StateMutation, StateRead, StateReadExt, StateStream, StateWatch, StateWrite,
    TaintedValue,
};
use xolotl_types::{ExecutionOutput, ProcessStatus, TaintSet};

#[derive(Default)]
struct CheckpointEntry {
    leased: bool,
    saved: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Default)]
struct CheckpointStats {
    acquired: usize,
    loads: usize,
    active: usize,
    peak_active: usize,
    max_loads_per_lease: usize,
}

#[derive(Default)]
struct CheckpointMemory {
    entries: BTreeMap<ProcessId, CheckpointEntry>,
    high_water: Option<ProcessId>,
    stats: CheckpointStats,
    retire_failures: usize,
}

#[derive(Clone, Default)]
struct MemoryCheckpoints(Arc<Mutex<CheckpointMemory>>, Arc<InMemoryExecutionIdSource>);

impl ExecutionIdSource for MemoryCheckpoints {
    fn reserve(&self, count: std::num::NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        self.1.reserve(count)
    }
}

struct MemoryJournal {
    store: MemoryCheckpoints,
    process: ProcessId,
    retired: bool,
    loads: usize,
}

fn checkpoint_error(error: impl std::fmt::Display) -> Failure {
    Failure::Custom {
        kind: "test_checkpoint".into(),
        message: error.to_string(),
    }
}

impl CheckpointStore for MemoryCheckpoints {
    fn try_acquire(
        &self,
        process: ProcessId,
    ) -> Result<Option<Box<dyn CheckpointJournal>>, Failure> {
        let mut memory = self.0.lock().map_err(checkpoint_error)?;
        let entry = memory.entries.entry(process).or_default();
        if entry.leased {
            return Ok(None);
        }
        entry.leased = true;
        memory.stats.acquired += 1;
        memory.stats.active += 1;
        memory.stats.peak_active = memory.stats.peak_active.max(memory.stats.active);
        Ok(Some(Box::new(MemoryJournal {
            store: self.clone(),
            process,
            retired: false,
            loads: 0,
        })))
    }

    fn high_water(&self) -> Result<Option<ProcessId>, Failure> {
        Ok(self.0.lock().map_err(checkpoint_error)?.high_water)
    }

    fn scan(&self, query: CheckpointQuery) -> Result<Vec<CheckpointInfo>, Failure> {
        if query.after.is_some_and(|after| after > query.through) {
            return Err(checkpoint_error("scan starts after its upper bound"));
        }
        if query.after == Some(query.through) {
            return Ok(Vec::new());
        }
        let memory = self.0.lock().map_err(checkpoint_error)?;
        let lower = query.after.map_or(Bound::Unbounded, Bound::Excluded);
        let mut page = Vec::new();
        for (&process, entry) in memory
            .entries
            .range((lower, Bound::Included(query.through)))
        {
            let Some(bytes) = &entry.saved else {
                continue;
            };
            page.try_reserve(1).map_err(checkpoint_error)?;
            page.push(CheckpointInfo {
                process,
                encoded_bytes: bytes.len(),
            });
            if page.len() == query.limit.get() {
                break;
            }
        }
        Ok(page)
    }

    fn snapshots(&self) -> Result<Vec<ExecutionSnapshot>, Failure> {
        self.0
            .lock()
            .map_err(checkpoint_error)?
            .entries
            .iter()
            .filter_map(|(&process, entry)| entry.saved.as_ref().map(|bytes| (process, bytes)))
            .map(|(process, bytes)| decode_snapshot(process, bytes, usize::MAX))
            .collect()
    }
}

impl CheckpointJournal for MemoryJournal {
    fn load(&mut self, max_bytes: usize) -> Result<Option<ExecutionSnapshot>, Failure> {
        let mut memory = self.store.0.lock().map_err(checkpoint_error)?;
        self.loads += 1;
        memory.stats.loads += 1;
        memory.stats.max_loads_per_lease = memory.stats.max_loads_per_lease.max(self.loads);
        memory
            .entries
            .get(&self.process)
            .and_then(|entry| entry.saved.as_ref())
            .map(|bytes| decode_snapshot(self.process, bytes, max_bytes))
            .transpose()
    }

    fn commit(
        &mut self,
        checkpoint: &ExecutionCheckpoint<'_>,
        max_bytes: usize,
    ) -> Result<(), Failure> {
        if self.retired {
            return Err(checkpoint_error("retired journal cannot commit"));
        }
        if checkpoint.process() != self.process {
            return Err(checkpoint_error("journal owner mismatch"));
        }
        let mut writer = CheckpointWriter {
            bytes: Vec::new(),
            limit: max_bytes,
        };
        serde_json::to_writer(&mut writer, checkpoint).map_err(checkpoint_error)?;
        let mut memory = self.store.0.lock().map_err(checkpoint_error)?;
        memory
            .entries
            .get_mut(&self.process)
            .ok_or_else(|| checkpoint_error("missing leased journal"))?
            .saved = Some(writer.bytes);
        memory.high_water = memory.high_water.max(Some(self.process));
        Ok(())
    }

    fn retire(&mut self) -> Result<(), Failure> {
        if self.retired {
            return Ok(());
        }
        let mut memory = self.store.0.lock().map_err(checkpoint_error)?;
        if memory.retire_failures != 0 {
            memory.retire_failures -= 1;
            return Err(checkpoint_error("retirement unavailable"));
        }
        memory
            .entries
            .get_mut(&self.process)
            .ok_or_else(|| checkpoint_error("missing leased journal"))?
            .saved = None;
        memory.high_water = memory.high_water.max(Some(self.process));
        self.retired = true;
        Ok(())
    }
}

impl Drop for MemoryJournal {
    fn drop(&mut self) {
        let mut memory = self
            .store
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remove = if let Some(entry) = memory.entries.get_mut(&self.process) {
            entry.leased = false;
            entry.saved.is_none()
        } else {
            false
        };
        if remove {
            memory.entries.remove(&self.process);
        }
        memory.stats.active -= 1;
    }
}

fn decode_snapshot(
    process: ProcessId,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<ExecutionSnapshot, Failure> {
    if bytes.len() > max_bytes {
        return Err(checkpoint_error("checkpoint exceeds encoded byte limit"));
    }
    let saved: ExecutionSnapshot = serde_json::from_slice(bytes).map_err(checkpoint_error)?;
    if saved.process.id != process {
        return Err(checkpoint_error("checkpoint owner mismatch"));
    }
    Ok(saved)
}

struct CheckpointWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for CheckpointWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::Error::other("checkpoint exceeds encoded byte limit"));
        }
        self.bytes
            .try_reserve(bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MemoryCheckpoints {
    fn stats(&self) -> Result<CheckpointStats, Failure> {
        Ok(self.0.lock().map_err(checkpoint_error)?.stats)
    }

    fn reset_stats(&self) -> anyhow::Result<()> {
        let mut memory = self.0.lock().map_err(checkpoint_error)?;
        ensure!(memory.stats.active == 0);
        memory.stats = CheckpointStats::default();
        Ok(())
    }

    fn fail_next_retirement(&self) -> Result<(), Failure> {
        self.0.lock().map_err(checkpoint_error)?.retire_failures += 1;
        Ok(())
    }
}

fn recovery_config(
    page_size: usize,
    max_in_flight: usize,
    reap_batch: usize,
) -> anyhow::Result<DurableRecoveryConfig> {
    Ok(DurableRecoveryConfig {
        page_size: NonZeroUsize::new(page_size).context("nonzero page size")?,
        max_in_flight: NonZeroUsize::new(max_in_flight).context("nonzero recovery concurrency")?,
        reap_batch,
    })
}

async fn wait_for_recovery_exit(store: &MemoryCheckpoints) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if store.stats()?.active == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("recovery did not release its journals")?
}

fn request(boot: &Bootstrap) -> anyhow::Result<ProcessId> {
    Ok(
        boot.spawn_request_process_under_with_compiled_request_grants(
            boot.root,
            IdentityRef::ROOT,
            &[],
        )?,
    )
}

async fn finished_backlog(
    store: &Arc<MemoryCheckpoints>,
    count: usize,
) -> anyhow::Result<Vec<ProcessId>> {
    let boot = XolotlBuilder::new()
        .with_checkpoint_store(store.clone())
        .build_bootstrap();
    let mut program = Program::new(Expression::literal(19));
    program.durable = true;
    let prepared = PreparedProgram::new(&program.compile()?)?;
    let mut processes = Vec::new();
    for _ in 0..count {
        let process = request(&boot)?;
        let output = boot
            .kernel
            .executor_for(process)
            .eval_prepared(&prepared, TaintedValue::pristine(Value::null()))
            .await;
        ensure!(output.outcome == Outcome::Done(Value::integer(19)));
        processes.push(process);
    }
    store.reset_stats()?;
    Ok(processes)
}

async fn waiting_backlog(
    store: &Arc<MemoryCheckpoints>,
    count: usize,
) -> anyhow::Result<Vec<(ProcessId, Path)>> {
    let boot = XolotlBuilder::new()
        .with_checkpoint_store(store.clone())
        .build_bootstrap();
    let mut processes = Vec::new();
    for index in 0..count {
        let signal = Path::parse(&format!("state://signal/backlog/{index}"))?;
        let mut program = Program::new(Expression::Wait {
            wait: WaitSpec::Signal(signal.clone()),
        });
        program.durable = true;
        let prepared = PreparedProgram::new(&program.compile()?)?;
        let process = request(&boot)?;
        let executor = boot.kernel.executor_for(process);
        let mut run =
            Box::pin(executor.eval_prepared(&prepared, TaintedValue::pristine(Value::null())));
        ensure!(
            std::future::poll_fn(|cx| Poll::Ready(run.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(run);
        processes.push((process, signal));
    }
    ensure!(store.snapshots()?.len() == count);
    store.reset_stats()?;
    Ok(processes)
}

#[tokio::test]
async fn dropping_durable_request_preserves_checkpoint_for_recovery() -> anyhow::Result<()> {
    let store = Arc::new(MemoryCheckpoints::default());
    let runtime = XolotlBuilder::new()
        .with_checkpoint_store(store.clone())
        .build();
    let signal = Path::parse("state://signal/drop-durable")?;
    let mut program = Program::new(Expression::Wait {
        wait: WaitSpec::Signal(signal.clone()),
    });
    program.durable = true;
    let prepared = PreparedProgram::new(&program.compile()?)?;
    let mut run = Box::pin(runtime.run_prepared(
        IdentityRef::ROOT,
        &[],
        &prepared,
        TaintedValue::pristine(Value::null()),
    ));
    ensure!(
        std::future::poll_fn(|cx| Poll::Ready(run.as_mut().poll(cx)))
            .await
            .is_pending()
    );
    let before = store
        .snapshots()?
        .pop()
        .context("missing initial checkpoint")?;
    let process = before.process.id;
    ensure!(!before.finished && !before.pending.is_empty());
    ensure!(store.acquire(process).is_err());
    drop(run);
    let report = runtime.drain_cleanup().await;
    ensure!(report.completed == 0 && report.failures.is_empty());
    ensure!(
        runtime.bootstrap().kernel.processes.status(process)
            == Some(xolotl_types::ProcessStatus::Running)
    );
    let marker = Path::parse(&format!(
        "state://kernel/process/{}/{}/finalized",
        process.get(),
        before.process.lifecycle_execution.get()
    ))?;
    ensure!(
        runtime
            .bootstrap()
            .kernel
            .state
            .read(&marker)
            .await?
            .is_none()
    );
    let saved = store
        .acquire(process)?
        .load(usize::MAX)?
        .context("missing retained checkpoint")?;
    ensure!(!saved.finished && saved.pending == before.pending);
    drop(runtime);

    let restored = XolotlBuilder::new()
        .with_checkpoint_store(store.clone())
        .build();
    let boot = restored.bootstrap();
    boot.restore_checkpoint_process(&saved)?;
    boot.kernel
        .state
        .write_set(&signal, Value::integer(73))
        .await?;
    let result = boot
        .kernel
        .executor_for(process)
        .eval_prepared(
            &saved.program,
            xolotl_state::TaintedValue::pristine(Value::null()),
        )
        .await;
    ensure!(
        result.outcome == Outcome::Done(Value::integer(73)),
        "resumed execution failed: {result:?}"
    );
    ensure!(boot.finish_checkpointed_request(process, &result).await?);
    ensure!(boot.kernel.state.read(&marker).await?.is_some());
    ensure!(store.snapshots()?.is_empty());
    Ok(())
}

#[derive(Default)]
struct MarkerFailureState {
    inner: InMemoryBackend,
    fail: AtomicBool,
}

impl MarkerFailureState {
    fn backend(self: &Arc<Self>) -> Backend {
        Backend::new()
            .with_read(self.clone())
            .with_write(self.clone())
            .with_watch(self.clone())
    }
}

impl StateRead for MarkerFailureState {
    type Read<'a> = std::future::Ready<StateResult<Option<TaintedValue>>>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        self.inner.read_tainted(path)
    }
}

impl StateWrite for MarkerFailureState {
    type Write<'a> = std::future::Ready<StateResult<xolotl_state::StateCommit>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        if matches!(mutation, StateMutation::Set(_)) && self.fail.swap(false, Ordering::SeqCst) {
            return std::future::ready(Err(xolotl_sdk::StateError::Backend(
                "marker unavailable".into(),
            )
            .into()));
        }
        self.inner.mutate(path, mutation)
    }
}

impl StateWatch for MarkerFailureState {
    type Subscription = StateStream;
    type Subscribe<'a> = std::future::Ready<StateResult<StateStream>>;

    fn subscribe<'a>(&'a self, pattern: &'a Path) -> Self::Subscribe<'a> {
        self.inner.subscribe(pattern)
    }
}

fn cleanup_resource(boot: &xolotl_sdk::Bootstrap) -> anyhow::Result<xolotl_sdk::ResourceName> {
    Ok(boot.register_effect(
        "effect://test/lifecycle",
        &[xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_sdk::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(xolotl_kernel::EchoDriver),
    )?)
}

#[tokio::test]
async fn restarting_after_marker_failure_reuses_the_committed_lifecycle_record()
-> anyhow::Result<()> {
    let state = Arc::new(MarkerFailureState::default());
    let facts = FactSink::in_memory().0;
    let store = Arc::new(MemoryCheckpoints::default());
    let runtime = XolotlBuilder::new()
        .with_backends(state.backend(), facts.clone())
        .with_checkpoint_store(store.clone())
        .build();
    let boot = runtime.bootstrap();
    let resource = cleanup_resource(boot)?;
    let process = boot.spawn_request_process_under_with_request_grants(
        boot.root,
        IdentityRef::ROOT,
        &[xolotl_kernel::RequestGrantTemplate {
            literal: "perform://effect/test/lifecycle",
            methods: xolotl_types::MethodBitmap::method(0),
        }],
    )?;
    let handle = boot.open_for(process, &resource, "perform")?;
    ensure!(boot.kernel.handles.read().get(handle).is_some());
    let mut program = Program::new(Expression::literal(53));
    program.durable = true;
    let prepared = PreparedProgram::new(&program.compile()?)?;
    let result = boot
        .kernel
        .executor_for(process)
        .eval_prepared(&prepared, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(result.outcome == Outcome::Done(Value::integer(53)));
    state.fail.store(true, Ordering::SeqCst);
    ensure!(
        boot.finish_process_as(process, ProcessStatus::Failed)
            .await
            .is_err()
    );
    ensure!(boot.kernel.handles.read().get(handle).is_none());
    let saved = store
        .acquire(process)?
        .load(usize::MAX)?
        .context("missing terminal checkpoint")?;
    ensure!(saved.finished);
    let marker = Path::parse(&format!(
        "state://kernel/process/{}/{}/finalized",
        process.get(),
        saved.process.lifecycle_execution.get(),
    ))?;
    ensure!(state.read(&marker).await?.is_none());
    let before = facts
        .facts_of(process)?
        .pop()
        .context("missing lifecycle fact")?;
    let Some(record) = before.outcome.as_ref().and_then(Value::as_map) else {
        anyhow::bail!("missing lifecycle payload");
    };
    ensure!(record.get("released_handles") == Some(&Value::integer(1)));
    ensure!(record.get("revoked_handles") == Some(&Value::integer(0)));
    ensure!(record.get("status").and_then(Value::as_str) == Some("failed"));
    drop(runtime);

    let restored = XolotlBuilder::new()
        .with_backends(state.backend(), facts.clone())
        .with_checkpoint_store(store.clone())
        .build();
    let boot = Arc::new(restored.bootstrap().clone());
    cleanup_resource(&boot)?;
    for (field, invalid) in [
        ("event", Value::string("OtherEvent".into())),
        ("status", Value::string("running".into())),
        ("released_handles", Value::integer(-1)),
        ("released_handles", Value::null()),
        ("revoked_handles", Value::integer(-1)),
    ] {
        let mut corrupted = before.clone();
        let Some(mut record) = corrupted.outcome.as_ref().and_then(Value::as_map).cloned() else {
            anyhow::bail!("missing lifecycle payload");
        };
        drop(record.insert(field.into(), invalid)?);
        corrupted.outcome = Some(Value::from(record));
        facts.store().complete(corrupted)?;
        ensure!(
            boot.restore_checkpoint_process(&saved).is_err(),
            "accepted invalid {field}"
        );
        ensure!(
            boot.kernel.processes.status(process).is_none(),
            "inserted process after validation failure"
        );
    }
    let mut wrong_schema = before.clone();
    wrong_schema.schema_version += 1;
    facts.store().complete(wrong_schema)?;
    ensure!(boot.restore_checkpoint_process(&saved).is_err());
    ensure!(boot.kernel.processes.status(process).is_none());
    facts.store().complete(before.clone())?;
    let report = boot.checkpoint_recovery()?.advance().await?;
    ensure!(report.resumed == 1 && report.quarantined == 0);
    ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Finalizing));
    wait_for_recovery_exit(&store).await?;
    ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Failed));
    ensure!(state.read(&marker).await? == Some(Value::integer(1)));
    let retained = facts.facts_of(process)?;
    ensure!(
        retained == [before],
        "lifecycle record changed during restart"
    );
    ensure!(store.snapshots()?.is_empty());
    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    let error = boot
        .restore_checkpoint_process(&saved)
        .err()
        .context("reintroduced a reaped checkpoint process")?;
    ensure!(error.to_string().contains("checkpoint admission is closed"));
    ensure!(boot.kernel.processes.status(process).is_none());
    ensure!(state.read(&marker).await? == Some(Value::integer(1)));
    ensure!(store.acquire(process)?.load(usize::MAX)?.is_none());
    Ok(())
}

#[tokio::test]
async fn explicit_identity_source_composes_independent_stores_in_either_builder_order()
-> anyhow::Result<()> {
    let facts = FactSink::in_memory().0;
    let state = InMemoryBackend::new().into_backend();
    let ids = ExecutionIds::new(Arc::new(InMemoryExecutionIdSource::from_high_water(1000)));
    let first_store = Arc::new(MemoryCheckpoints::default());
    let second_store = Arc::new(MemoryCheckpoints::default());
    let first = XolotlBuilder::new()
        .with_execution_ids(ids.clone())
        .with_checkpoint_store(first_store.clone())
        .with_backends(state.clone(), facts.clone())
        .build();
    let second = XolotlBuilder::new()
        .with_checkpoint_store(second_store.clone())
        .with_backends(state, facts.clone())
        .with_execution_ids(ids)
        .build();
    let mut program = Program::new(Expression::literal(7));
    program.durable = true;
    let prepared = PreparedProgram::new(&program.compile()?)?;
    for runtime in [&first, &second] {
        let boot = runtime.bootstrap();
        let process = boot.spawn_request_process_under_with_compiled_request_grants(
            boot.root,
            IdentityRef::ROOT,
            &[],
        )?;
        ensure!(
            boot.kernel
                .executor_for(process)
                .eval_prepared(&prepared, TaintedValue::pristine(Value::null()))
                .await
                .outcome
                == Outcome::Done(Value::integer(7))
        );
    }
    let first_saved = first_store
        .snapshots()?
        .pop()
        .context("missing first checkpoint")?;
    let second_saved = second_store
        .snapshots()?
        .pop()
        .context("missing second checkpoint")?;
    ensure!(first_saved.execution.get() > 1000 && second_saved.execution.get() > 1000);
    ensure!(first_saved.process.id == second_saved.process.id);
    ensure!(first_saved.execution != second_saved.execution);
    for (runtime, saved) in [(&first, &first_saved), (&second, &second_saved)] {
        ensure!(
            runtime
                .bootstrap()
                .finish_checkpointed_request(
                    saved.process.id,
                    &ExecutionOutput::new(Outcome::Done(Value::integer(7)), TaintSet::pristine()),
                )
                .await?
        );
    }
    ensure!(first_store.snapshots()?.is_empty() && second_store.snapshots()?.is_empty());
    let recorded = facts.facts_of(first_saved.process.id)?;
    ensure!(recorded.len() == 2 && recorded[0].id != recorded[1].id);
    Ok(())
}

#[tokio::test]
async fn bounded_recovery_reaps_a_backlog_larger_than_the_process_table() -> anyhow::Result<()> {
    let store = Arc::new(MemoryCheckpoints::default());
    let processes = finished_backlog(&store, 9).await?;
    let high_water = store.high_water()?;
    let boot = Arc::new(
        XolotlBuilder::new()
            .with_checkpoint_store(store.clone())
            .with_process_capacity(NonZeroUsize::new(2).context("root and one request")?)
            .with_checkpoint_recovery_config(recovery_config(2, 3, 1)?)
            .build_bootstrap(),
    );
    let mut recovery = boot.checkpoint_recovery()?;
    ensure!(store.stats()?.loads == 0);
    let mut resumed = 0;
    let mut deferred = 0;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let report = recovery.advance().await?;
            resumed += report.resumed;
            deferred += report.deferred;
            ensure!(report.quarantined == 0);
            ensure!(boot.kernel.processes.len() <= 2);
            if report.complete && store.snapshots()?.is_empty() && store.stats()?.active == 0 {
                return Ok::<(), anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .context("bounded backlog stopped making progress")??;
    ensure!(resumed == processes.len() && deferred != 0);
    ensure!(store.high_water()? == high_water);
    let stats = store.stats()?;
    ensure!(stats.acquired == processes.len() && stats.loads == processes.len());
    ensure!(stats.peak_active == 1 && stats.max_loads_per_lease == 1);
    boot.kernel.processes.reap_finalized(1);
    ensure!(boot.kernel.processes.len() == 1);
    for process in processes {
        ensure!(boot.kernel.facts.facts_of(process)?.len() == 1);
    }
    Ok(())
}

#[tokio::test]
async fn recovery_sessions_share_capacity_without_waiting_for_running_programs()
-> anyhow::Result<()> {
    let store = Arc::new(MemoryCheckpoints::default());
    let processes = waiting_backlog(&store, 3).await?;
    let boot = Arc::new(
        XolotlBuilder::new()
            .with_checkpoint_store(store.clone())
            .with_checkpoint_recovery_config(recovery_config(3, 1, 0)?)
            .build_bootstrap(),
    );
    let mut first = boot.checkpoint_recovery()?;
    let mut second = boot.checkpoint_recovery()?;
    let report = tokio::time::timeout(Duration::from_millis(250), first.advance()).await??;
    ensure!(report.resumed == 1 && report.deferred == 1 && !report.complete);
    let report = tokio::time::timeout(Duration::from_millis(250), second.advance()).await??;
    ensure!(report.resumed == 0 && report.skipped == 1 && report.deferred == 1);
    ensure!(store.snapshots()?.len() == 3);
    ensure!(store.stats()?.active == 1 && store.stats()?.loads == 1);
    let mut resumed = 1;
    for (index, (process, signal)) in processes.iter().enumerate() {
        boot.kernel
            .state
            .write_set(signal, Value::integer(index as i64))
            .await?;
        wait_for_recovery_exit(&store).await?;
        ensure!(boot.kernel.processes.status(*process) == Some(ProcessStatus::Completed));
        ensure!(store.snapshots()?.len() == processes.len() - index - 1);
        if index + 1 < processes.len() {
            let (a, b) = tokio::time::timeout(Duration::from_millis(250), async {
                tokio::join!(first.advance(), second.advance())
            })
            .await?;
            let (a, b) = (a?, b?);
            ensure!(a.resumed + b.resumed == 1);
            ensure!(a.quarantined + b.quarantined == 0);
            resumed += a.resumed + b.resumed;
            ensure!(store.stats()?.active == 1);
        }
    }
    ensure!(resumed == processes.len());
    let stats = store.stats()?;
    ensure!(stats.acquired == processes.len() && stats.loads == processes.len());
    ensure!(stats.peak_active == 1 && stats.max_loads_per_lease == 1);
    ensure!(first.advance().await?.complete);
    ensure!(second.advance().await?.complete);
    Ok(())
}

#[tokio::test]
async fn retirement_failure_keeps_cleanup_retryable_and_blocks_reaping() -> anyhow::Result<()> {
    let store = Arc::new(MemoryCheckpoints::default());
    let process = finished_backlog(&store, 1).await?[0];
    let boot = Arc::new(
        XolotlBuilder::new()
            .with_checkpoint_store(store.clone())
            .with_checkpoint_recovery_config(recovery_config(2, 1, 0)?)
            .build_bootstrap(),
    );
    store.fail_next_retirement()?;
    let report = boot.checkpoint_recovery()?.advance().await?;
    ensure!(report.resumed == 1 && report.complete);
    wait_for_recovery_exit(&store).await?;
    ensure!(store.snapshots()?.len() == 1);
    ensure!(boot.kernel.processes.reap_finalized(1) == 0);
    let before = boot.kernel.facts.facts_of(process)?;
    ensure!(before.len() == 1);

    let report = boot.checkpoint_recovery()?.advance().await?;
    ensure!(report.resumed == 1 && report.quarantined == 0);
    wait_for_recovery_exit(&store).await?;
    ensure!(store.snapshots()?.is_empty());
    ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Completed));
    ensure!(boot.kernel.facts.facts_of(process)? == before);
    ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    let stats = store.stats()?;
    ensure!(stats.acquired == 2 && stats.loads == 2 && stats.peak_active == 1);
    Ok(())
}

#[tokio::test]
async fn an_unfinished_checkpoint_with_a_cancellation_fact_resumes_cleanup() -> anyhow::Result<()> {
    let state = Arc::new(MarkerFailureState::default());
    let facts = FactSink::in_memory().0;
    let store = Arc::new(MemoryCheckpoints::default());
    let saved = {
        let boot = XolotlBuilder::new()
            .with_backends(state.backend(), facts.clone())
            .with_checkpoint_store(store.clone())
            .build_bootstrap();
        let process = request(&boot)?;
        let signal = Path::parse("state://signal/permanent-cancellation")?;
        let mut program = Program::new(Expression::Wait {
            wait: WaitSpec::Signal(signal),
        });
        program.durable = true;
        let prepared = PreparedProgram::new(&program.compile()?)?;
        let executor = boot.kernel.executor_for(process);
        let mut run =
            Box::pin(executor.eval_prepared(&prepared, TaintedValue::pristine(Value::null())));
        ensure!(
            std::future::poll_fn(|cx| Poll::Ready(run.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        drop(run);
        state.fail.store(true, Ordering::SeqCst);
        ensure!(
            boot.finish_process_as(process, ProcessStatus::Cancelled)
                .await
                .is_err()
        );
        let saved = store
            .snapshots()?
            .pop()
            .context("unfinished cancelled checkpoint")?;
        ensure!(!saved.finished && !saved.pending.is_empty());
        saved
    };
    let process = saved.process.id;
    let before = facts.facts_of(process)?;
    ensure!(before.len() == 1);
    let marker = Path::parse(&format!(
        "state://kernel/process/{}/{}/finalized",
        process.get(),
        saved.process.lifecycle_execution.get(),
    ))?;
    ensure!(state.read(&marker).await?.is_none());
    store.reset_stats()?;
    let boot = Arc::new(
        XolotlBuilder::new()
            .with_backends(state.backend(), facts.clone())
            .with_checkpoint_store(store.clone())
            .build_bootstrap(),
    );
    boot.restore_checkpoint_process(&saved)?;
    ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Finalizing));
    let report = boot.checkpoint_recovery()?.advance().await?;
    ensure!(report.resumed == 1 && report.quarantined == 0);
    wait_for_recovery_exit(&store).await?;
    ensure!(store.snapshots()?.is_empty());
    ensure!(boot.kernel.processes.status(process) == Some(ProcessStatus::Cancelled));
    ensure!(state.read(&marker).await? == Some(Value::integer(0)));
    ensure!(facts.facts_of(process)? == before);
    ensure!(store.stats()?.loads == 1 && store.stats()?.acquired == 1);
    Ok(())
}

#[tokio::test]
async fn recovery_quarantines_oversized_records_before_process_admission() -> anyhow::Result<()> {
    let store = Arc::new(MemoryCheckpoints::default());
    let process = finished_backlog(&store, 1).await?[0];
    let boot = Arc::new(
        XolotlBuilder::new()
            .with_checkpoint_store(store.clone())
            .with_execution_config(ExecutionConfig {
                max_checkpoint_bytes: 1,
                ..ExecutionConfig::default()
            })
            .build_bootstrap(),
    );
    let report = boot.checkpoint_recovery()?.advance().await?;
    ensure!(report.resumed == 0 && report.quarantined == 1 && report.complete);
    ensure!(boot.kernel.processes.status(process).is_none());
    ensure!(boot.kernel.processes.len() == 1);
    ensure!(store.snapshots()?.len() == 1);
    ensure!(store.stats()?.loads == 1 && store.stats()?.active == 0);
    Ok(())
}

#[tokio::test]
async fn persisted_terminal_intent_cleans_up_uncertain_requests_without_replay()
-> anyhow::Result<()> {
    for (status, intent, terminal) in [
        (ProcessStatus::Cancelled, None, ProcessStatus::Cancelled),
        (
            ProcessStatus::Finalizing,
            Some(ProcessStatus::Failed),
            ProcessStatus::Failed,
        ),
    ] {
        let store = Arc::new(MemoryCheckpoints::default());
        let process = waiting_backlog(&store, 1).await?[0].0;
        let mut saved = store.snapshots()?.pop().context("pending checkpoint")?;
        saved.process.status = status;
        saved.process.terminal_intent = intent;
        for class in saved.pending.values_mut() {
            *class = xolotl_types::ReplayClass::NonIdempotentEffect;
        }
        {
            let mut memory = store.0.lock().map_err(checkpoint_error)?;
            memory
                .entries
                .get_mut(&process)
                .context("retained record")?
                .saved = Some(serde_json::to_vec(&saved)?);
        }
        let boot = Arc::new(
            XolotlBuilder::new()
                .with_checkpoint_store(store.clone())
                .build_bootstrap(),
        );
        ensure!(boot.kernel.facts.facts_of(process)?.is_empty());
        let report = boot.checkpoint_recovery()?.advance().await?;
        ensure!(report.resumed == 1 && report.quarantined == 0);
        wait_for_recovery_exit(&store).await?;
        ensure!(store.snapshots()?.is_empty());
        ensure!(boot.kernel.processes.status(process) == Some(terminal));
        ensure!(boot.kernel.facts.facts_of(process)?.len() == 1);
        ensure!(boot.kernel.processes.reap_finalized(1) == 1);
    }
    Ok(())
}

#[tokio::test]
async fn finalizing_checkpoint_without_terminal_intent_stays_held() -> anyhow::Result<()> {
    let store = Arc::new(MemoryCheckpoints::default());
    let process = waiting_backlog(&store, 1).await?[0].0;
    let mut saved = store.snapshots()?.pop().context("pending checkpoint")?;
    saved.process.status = ProcessStatus::Finalizing;
    ensure!(saved.process.terminal_intent.is_none());
    {
        let mut memory = store.0.lock().map_err(checkpoint_error)?;
        memory
            .entries
            .get_mut(&process)
            .context("retained record")?
            .saved = Some(serde_json::to_vec(&saved)?);
    }
    let boot = Arc::new(
        XolotlBuilder::new()
            .with_checkpoint_store(store.clone())
            .build_bootstrap(),
    );
    let report = boot.checkpoint_recovery()?.advance().await?;
    ensure!(report.quarantined == 1 && report.resumed == 0 && report.complete);
    ensure!(boot.kernel.processes.len() == 1);
    ensure!(boot.kernel.facts.facts_of(process)?.is_empty());
    ensure!(store.snapshots()?.len() == 1);
    Ok(())
}

#[tokio::test]
async fn a_retired_snapshot_cannot_create_a_new_execution_in_a_fresh_kernel() -> anyhow::Result<()>
{
    let store = Arc::new(MemoryCheckpoints::default());
    let process = finished_backlog(&store, 1).await?[0];
    let saved = store
        .snapshots()?
        .pop()
        .context("saved checkpoint before retirement")?;
    {
        let boot = Arc::new(
            XolotlBuilder::new()
                .with_checkpoint_store(store.clone())
                .build_bootstrap(),
        );
        ensure!(boot.checkpoint_recovery()?.advance().await?.resumed == 1);
        wait_for_recovery_exit(&store).await?;
        ensure!(store.snapshots()?.is_empty());
    }
    let boot = XolotlBuilder::new()
        .with_checkpoint_store(store.clone())
        .build_bootstrap();
    ensure!(boot.kernel.facts.facts_of(process)?.is_empty());
    boot.restore_checkpoint_process(&saved)?;
    let outcome = boot
        .kernel
        .executor_for(process)
        .eval_prepared(&saved.program, TaintedValue::pristine(Value::null()))
        .await;
    ensure!(
        matches!(outcome.outcome, Outcome::Fail(_)),
        "retired checkpoint restarted: {outcome:?}"
    );
    ensure!(store.snapshots()?.is_empty());
    ensure!(store.high_water()? == Some(process));
    Ok(())
}
