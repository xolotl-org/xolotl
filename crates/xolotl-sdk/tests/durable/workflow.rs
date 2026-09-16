//! A batch of durable coordinators delegates short worker scopes and consumes
//! State notifications incrementally. Checkpoints use the parent fixture's real
//! current-format JSON codec in retained test memory; this is not a disk test.

use super::{MemoryCheckpoints, recovery_config, wait_for_recovery_exit};
use anyhow::{Context, bail, ensure};
use async_trait::async_trait;
use std::collections::BTreeSet;
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicUsize, Ordering},
};
use std::task::Poll;
use std::time::Duration;
use xolotl_graph::WaitSpec;
use xolotl_kernel::{CompiledRequestGrantTemplate, DriverOutput, MethodSpec};
use xolotl_sdk::{
    Bootstrap, CheckpointStore, Driver, DriverContext, DriverError, Expression, FactSink,
    IdentityRef, InMemoryBackend, OperationTemplate, Outcome, Path, PreparedProgram, ProcessId,
    Program, Purity, ResourceName, TaintSet, TaintedValue, Value, XolotlBuilder,
};
use xolotl_state::{
    Backend, InMemoryOptions, MemoryHistory, StateEvent, StateScan, StateStream, StateWatchError,
};
use xolotl_types::{
    MethodBitmap, MethodId, OutputMode, ProcessStatus, ReplayClass, ResourceSelector, TaintSource,
};

const ITEMS: usize = 7;
const WINDOW: usize = 2;
const WORK: &str = "effect://scenario/workflow/work";
const PUBLISH: &str = "effect://scenario/workflow/publish";

#[derive(Default)]
struct Activity {
    active: AtomicUsize,
    peak: AtomicUsize,
    children: AtomicUsize,
    published: [AtomicUsize; 2],
}

struct WorkLease<'a>(&'a Activity);

impl Drop for WorkLease<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
    }
}

struct Worker {
    boot: Weak<Bootstrap>,
    child_program: PreparedProgram,
    activity: Arc<Activity>,
}

impl Worker {
    async fn run(&self, input: Value, ctx: &DriverContext) -> anyhow::Result<DriverOutput> {
        ensure!(ctx.operation_id.is_some());
        let active = self.activity.active.fetch_add(1, Ordering::SeqCst) + 1;
        let _lease = WorkLease(&self.activity);
        self.activity.peak.fetch_max(active, Ordering::SeqCst);
        let boot = self.boot.upgrade().context("workflow host was released")?;
        let child = boot.request_under(ctx.caller, ctx.acting, &[grant(PUBLISH)?])?;
        self.activity.children.fetch_add(1, Ordering::SeqCst);
        ensure!(
            boot.kernel
                .processes
                .children_of(ctx.caller)
                .contains(&child.id())
        );
        let output = child
            .executor()
            .eval_prepared(
                &self.child_program,
                TaintedValue::new(input, ctx.taint.clone()),
            )
            .await;
        child.finish(&output).await?;
        boot.kernel.processes.reap_finalized(1);
        Ok(DriverOutput::new(output.outcome).with_taint(output.taint))
    }
}

#[async_trait]
impl Driver for Worker {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.run(input, ctx)
            .await
            .map_err(|error| DriverError::Other(error.to_string()))
    }
}

struct Publisher {
    state: Backend,
    activity: Arc<Activity>,
}

impl Publisher {
    async fn run(&self, input: Value, ctx: &DriverContext) -> anyhow::Result<DriverOutput> {
        ensure!(ctx.operation_id.is_some());
        let pair = input.as_list().context("worker input")?;
        ensure!(pair.len() == 2);
        let item = usize::try_from(pair.get(0).and_then(Value::as_int).context("item")?)?;
        let phase = usize::try_from(pair.get(1).and_then(Value::as_int).context("phase")?)?;
        ensure!(item < ITEMS && phase < 2);
        // Let other admitted workers run while this child still owns its scope.
        tokio::task::yield_now().await;
        let value = result(item, phase);
        let receipt = self
            .state
            .write_cas_tainted(
                &output_path(item, phase)?,
                None,
                value.clone(),
                ctx.taint.clone(),
            )
            .await?;
        self.activity.published[phase].fetch_add(1, Ordering::SeqCst);
        Ok(DriverOutput::new(Outcome::Done(value)).with_taint(receipt.taint.merged(&ctx.taint)))
    }
}

#[async_trait]
impl Driver for Publisher {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.run(input, ctx)
            .await
            .map_err(|error| DriverError::Other(error.to_string()))
    }
}

fn grant(target: &str) -> anyhow::Result<CompiledRequestGrantTemplate> {
    let action = target.strip_prefix("effect://").context("effect target")?;
    Ok(CompiledRequestGrantTemplate {
        selector: ResourceSelector::parse(&format!("perform://effect/{action}"))?,
        methods: MethodBitmap::method(0),
    })
}

fn invoke(target: &str) -> anyhow::Result<Expression> {
    Ok(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse(target)?),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        },
    })
}

fn install(boot: &Arc<Bootstrap>, activity: &Arc<Activity>) -> anyhow::Result<()> {
    boot.register_effect(
        PUBLISH,
        &[MethodSpec::unary_async("invoke", Purity::Effectful)],
        Arc::new(Publisher {
            state: boot.kernel.state.clone(),
            activity: activity.clone(),
        }),
    )?;
    boot.register_effect(
        WORK,
        &[MethodSpec::unary_async("invoke", Purity::Effectful)],
        Arc::new(Worker {
            boot: Arc::downgrade(boot),
            child_program: PreparedProgram::new(&Program::new(invoke(PUBLISH)?).compile()?)?,
            activity: activity.clone(),
        }),
    )?;
    Ok(())
}

fn signal(item: usize, phase: &str) -> anyhow::Result<Path> {
    Ok(Path::parse(&format!(
        "state://workflow/signals/{item}/{phase}"
    ))?)
}

fn output_path(item: usize, phase: usize) -> anyhow::Result<Path> {
    Ok(Path::parse(&format!(
        "state://workflow/results/{item}/{phase}"
    ))?)
}

fn input(item: usize, phase: usize) -> Value {
    Value::list(vec![
        Value::integer(item as i64),
        Value::integer(phase as i64),
    ])
}

fn result(item: usize, phase: usize) -> Value {
    Value::list(vec![
        Value::integer(item as i64),
        Value::integer(phase as i64),
        Value::integer((item * 10 + phase) as i64),
    ])
}

fn source(item: usize) -> anyhow::Result<TaintSet> {
    Ok(TaintSet::of(TaintSource::Protected {
        path: Path::parse(&format!("state://workflow/input/{item}"))?,
    }))
}

fn coordinator(item: usize) -> anyhow::Result<PreparedProgram> {
    let mut program = Program::new(
        Expression::Constant {
            value: input(item, 0),
        }
        .then(invoke(WORK)?)
        .then(Expression::Wait {
            wait: WaitSpec::Signal(signal(item, "resume")?),
        })
        .then(Expression::Constant {
            value: input(item, 1),
        })
        .then(invoke(WORK)?)
        .then(Expression::Wait {
            wait: WaitSpec::Signal(signal(item, "ack")?),
        }),
    );
    program.durable = true;
    Ok(PreparedProgram::new(&program.compile()?)?)
}

async fn consume(
    events: &mut StateStream,
    state: &Backend,
    phase: usize,
    dispatcher: &TaintSet,
    seen: &mut BTreeSet<(usize, usize)>,
) -> anyhow::Result<usize> {
    let (path, value, taint) = loop {
        match events.recv().await? {
            StateEvent::Set { path, value, taint } => break (path, value, taint),
            StateEvent::Delete { .. } => {}
            StateEvent::Append { .. } => bail!("worker replaced a result with retained history"),
        }
    };
    let item = value
        .as_list()
        .and_then(|row| row.get(0))
        .and_then(Value::as_int)
        .context("result item")?;
    let item = usize::try_from(item)?;
    ensure!(item < ITEMS && value == result(item, phase) && path == output_path(item, phase)?);
    // The coordinator's two Constant nodes contribute authored instructions
    // in addition to the protected input that influences their execution.
    let mut expected = source(item)?.merged(&TaintSet::author());
    if phase == 1 {
        expected.union(dispatcher);
    }
    ensure!(taint.contains_all(&expected) && taint.sources().len() == expected.sources().len());
    ensure!(
        seen.insert((item, phase)),
        "completed stage was published again after recovery"
    );
    ensure!(state.read_tainted(&path).await? == Some(TaintedValue::new(value, taint)));
    state.write_delete(&path).await?;
    ensure!(state.read(&path).await?.is_none());
    Ok(item)
}

fn drain_deletes(events: &mut StateStream) -> anyhow::Result<()> {
    loop {
        match events.try_recv() {
            Ok(StateEvent::Delete { .. }) => {}
            Err(StateWatchError::Empty) => return Ok(()),
            other => bail!("unexpected queued output or lost notification: {other:?}"),
        }
    }
}

#[tokio::test]
async fn delegated_batch_resumes_with_bounded_workers_and_incremental_results() -> anyhow::Result<()>
{
    let progress = std::cell::Cell::new(("setup", 0usize));
    tokio::time::timeout(Duration::from_secs(20), async {
        let checkpoints = Arc::new(MemoryCheckpoints::default());
        let state = InMemoryBackend::with_options(InMemoryOptions {
            history: MemoryHistory::Disabled,
            notification_capacity: NonZeroUsize::new(WINDOW).context("window")?,
            ..Default::default()
        })?
        .into_backend();
        let (facts, _) = FactSink::in_memory();
        let activity = Arc::new(Activity::default());
        let mut events = state
            .subscribe(&Path::parse("state://workflow/results/**")?)
            .await?;
        let dispatcher = TaintSet::of(TaintSource::Inbound {
            source: "dispatcher".into(),
            channel: "resume".into(),
        });
        let consumer = TaintSet::of(TaintSource::Inbound {
            source: "consumer".into(),
            channel: "ack".into(),
        });
        let mut seen = BTreeSet::new();
        let mut jobs: Vec<(usize, ProcessId)> = Vec::new();
        let boot = Arc::new(
            XolotlBuilder::new()
                .with_backends(state.clone(), facts.clone())
                .with_checkpoint_store(checkpoints.clone())
                .with_process_capacity(
                    NonZeroUsize::new(ITEMS + 2).context("initial process capacity")?,
                )
                .build_bootstrap(),
        );
        install(&boot, &activity)?;
        for item in 0..ITEMS {
            progress.set(("initial publication", item));
            let request = boot.request_under(
                boot.root,
                IdentityRef::ROOT,
                &[grant(WORK)?, grant(PUBLISH)?],
            )?;
            // The test host now owns the durable request; dropping its future
            // suspends execution without cancelling the delegated workflow.
            let process = request.detach();
            let prepared = coordinator(item)?;
            let executor = boot.kernel.executor_for(process);
            let mut run = Box::pin(
                executor.eval_prepared(&prepared, TaintedValue::new(Value::null(), source(item)?)),
            );
            let consumed = tokio::select! {
                output = &mut run => bail!("coordinator completed before its signal: {output:?}"),
                result = consume(&mut events, &state, 0, &dispatcher, &mut seen) => result?,
            };
            ensure!(consumed == item);
            progress.set(("post-effect checkpoint", item));
            // Commit the post-effect continuation and establish its State wait.
            // This program's only pending deterministic imports are Wait nodes;
            // effect calls above are NonIdempotentEffect. A Wait is replayed by
            // re-establishing its subscription, not as a recorded Observation.
            while checkpoints
                .snapshots()?
                .iter()
                .find(|saved| saved.process.id == process)
                .is_none_or(|saved| {
                    saved.pending.len() != 1
                        || saved
                            .pending
                            .values()
                            .any(|class| *class != ReplayClass::Deterministic)
                })
            {
                ensure!(
                    poll_fn(|cx| Poll::Ready(run.as_mut().poll(cx)))
                        .await
                        .is_pending()
                );
                tokio::task::yield_now().await;
            }
            drop(run);
            ensure!(activity.active.load(Ordering::SeqCst) == 0);
            ensure!(boot.kernel.processes.children_of(process).is_empty());
            jobs.push((item, process));
        }
        drain_deletes(&mut events)?;
        ensure!(checkpoints.snapshots()?.len() == ITEMS && checkpoints.stats()?.peak_active == 1);
        ensure!(activity.published[0].load(Ordering::SeqCst) == ITEMS);
        let old_host = Arc::downgrade(&boot);
        drop(boot);
        ensure!(
            old_host.upgrade().is_none(),
            "worker registration retained its host"
        );
        checkpoints.reset_stats()?;

        let capacity = 1 + WINDOW * 2; // Root, live coordinators and their worker children.
        let restored = Arc::new(
            XolotlBuilder::new()
                .with_backends(state.clone(), facts)
                .with_checkpoint_store(checkpoints.clone())
                .with_process_capacity(
                    NonZeroUsize::new(capacity).context("recovery process capacity")?,
                )
                .with_checkpoint_recovery_config(recovery_config(1, WINDOW, WINDOW)?)
                .build_bootstrap(),
        );
        install(&restored, &activity)?;
        let mut recovery = restored.checkpoint_recovery()?;
        let mut resumed = 0;
        let mut deferred = 0;
        for wave in jobs.chunks(WINDOW) {
            progress.set(("recovery admission", wave[0].0));
            while checkpoints.stats()?.active < wave.len() {
                let report = recovery.advance().await?;
                ensure!(report.quarantined == 0 && report.resumed <= 1);
                resumed += report.resumed;
                deferred += report.deferred;
                ensure!(restored.kernel.processes.len() <= capacity);
            }
            let report = recovery.advance().await?;
            ensure!(report.quarantined == 0 && report.resumed == 0);
            deferred += report.deferred;
            ensure!(checkpoints.stats()?.loads == resumed);
            // All admitted coordinators remain suspended until dispatch grants
            // this wave work; no result collection grows with the backlog.
            drain_deletes(&mut events)?;
            for (item, _) in wave {
                state
                    .write_set_tainted(
                        &signal(*item, "resume")?,
                        Value::integer(*item as i64),
                        dispatcher.clone(),
                    )
                    .await?;
            }
            for _ in wave {
                progress.set(("recovered publication", wave[0].0));
                let item = consume(&mut events, &state, 1, &dispatcher, &mut seen).await?;
                ensure!(wave.iter().any(|(expected, _)| *expected == item));
                state
                    .write_set_tainted(
                        &signal(item, "ack")?,
                        Value::integer(item as i64),
                        consumer.clone(),
                    )
                    .await?;
            }
            progress.set(("recovered lifecycle completion", wave[0].0));
            wait_for_recovery_exit(&checkpoints).await?;
            ensure!(activity.active.load(Ordering::SeqCst) == 0);
            for (item, process) in wave {
                ensure!(
                    restored.kernel.processes.status(*process) == Some(ProcessStatus::Completed)
                );
                let expected = source(*item)?
                    .merged(&TaintSet::author())
                    .merged(&dispatcher)
                    .merged(&consumer);
                let lifecycle = restored
                    .kernel
                    .facts
                    .facts_of(*process)?
                    .into_iter()
                    .find(|fact| {
                        fact.outcome
                            .as_ref()
                            .and_then(Value::as_map)
                            .and_then(|record| record.get("event"))
                            .and_then(Value::as_str)
                            == Some("ProcessFinalized")
                    })
                    .context("missing completed coordinator lifecycle")?;
                ensure!(lifecycle.taint.contains_all(&expected));
                ensure!(restored.kernel.processes.children_of(*process).is_empty());
                state.write_delete(&signal(*item, "resume")?).await?;
                state.write_delete(&signal(*item, "ack")?).await?;
            }
        }
        progress.set(("final release", ITEMS));
        drain_deletes(&mut events)?;
        ensure!(recovery.advance().await?.complete);
        restored.kernel.processes.reap_finalized(WINDOW);
        let stats = checkpoints.stats()?;
        ensure!(resumed == ITEMS && deferred > 0 && stats.peak_active == WINDOW);
        ensure!(stats.loads == ITEMS && stats.max_loads_per_lease == 1 && stats.active == 0);
        ensure!(seen.len() == ITEMS * 2 && activity.children.load(Ordering::SeqCst) == ITEMS * 2);
        ensure!(
            activity
                .published
                .iter()
                .all(|count| count.load(Ordering::SeqCst) == ITEMS)
        );
        ensure!(activity.peak.load(Ordering::SeqCst) <= WINDOW);
        ensure!(checkpoints.snapshots()?.is_empty() && restored.kernel.processes.len() == 1);
        ensure!(
            state
                .query(&StateScan::new(Path::parse("state://workflow/results")?))
                .await?
                .entries
                .is_empty()
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    .with_context(|| {
        let (stage, item) = progress.get();
        format!("batch workflow stopped during {stage}, item {item}")
    })?
}
