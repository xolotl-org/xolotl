use super::*;
use crate::host::{BlockingJob, BlockingSpawnError, BlockingSpawner};
use anyhow::{Context, ensure};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

struct ControlledBlocking {
    selected: usize,
    reject: bool,
    calls: AtomicUsize,
    jobs: Mutex<VecDeque<BlockingJob>>,
    available: Notify,
}

impl ControlledBlocking {
    fn hold(selected: usize) -> Arc<Self> {
        Arc::new(Self {
            selected,
            reject: false,
            calls: AtomicUsize::new(0),
            jobs: Mutex::new(VecDeque::new()),
            available: Notify::new(),
        })
    }

    fn reject(selected: usize) -> Arc<Self> {
        Arc::new(Self {
            selected,
            reject: true,
            calls: AtomicUsize::new(0),
            jobs: Mutex::new(VecDeque::new()),
            available: Notify::new(),
        })
    }

    async fn next_job(&self) -> anyhow::Result<BlockingJob> {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let notified = self.available.notified();
                if let Some(job) = self
                    .jobs
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .pop_front()
                {
                    return job;
                }
                notified.await;
            }
        })
        .await
        .context("Fact blocking job was not admitted")
    }
}

impl BlockingSpawner for ControlledBlocking {
    fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.selected {
            if self.reject {
                return Err(BlockingSpawnError::AtCapacity);
            }
            self.jobs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push_back(job);
            self.available.notify_one();
        } else {
            std::thread::spawn(job);
        }
        Ok(())
    }
}

fn fixture(
    blocking: Arc<ControlledBlocking>,
) -> anyhow::Result<(
    DataPlane,
    Operation,
    Arc<crate::fact::InMemoryFactStore>,
    Arc<AtomicUsize>,
)> {
    fixture_with_replay(blocking, ReplayClass::NonIdempotentEffect)
}

fn fixture_with_replay(
    blocking: Arc<ControlledBlocking>,
    replay: ReplayClass,
) -> anyhow::Result<(
    DataPlane,
    Operation,
    Arc<crate::fact::InMemoryFactStore>,
    Arc<AtomicUsize>,
)> {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, replay, SUPPORTS_UNARY),
        Arc::new(FnDriver(move |_method, _input| {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(Value::integer(77))
        })),
    );
    let handles = HandleTable::new();
    let handle = handles.insert(Handle {
        open_verb: "perform".into(),
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let runtime = HostRuntime::tokio_with_blocking(blocking);
    let plane = DataPlane::new_with_host_runtime(handles, facts, test_state(), runtime)
        .with_fact_io_mode(FactIoMode::Blocking);
    Ok((plane, op(handle, 7, Value::integer(5)), store, calls))
}

struct CachedState;

impl StateRead for CachedState {
    type Read<'a> = core::future::Ready<StateResult<xolotl_state::StateObservation>>;

    fn read_tainted<'a>(&'a self, _path: &'a Path) -> Self::Read<'a> {
        core::future::ready(Ok(xolotl_state::StateObservation::from(TaintedValue::new(
            super::super::outcome_to_value(&Outcome::Done(Value::integer(91))),
            xolotl_types::TaintSet::pristine(),
        ))))
    }
}

fn options() -> InvocationOptions {
    InvocationOptions {
        caller_identity: None,
        now_millis: 0,
        record: true,
    }
}

#[tokio::test]
async fn rejected_begin_has_no_fact_or_driver_call() -> anyhow::Result<()> {
    let blocking = ControlledBlocking::reject(1);
    let (plane, operation, store, calls) = fixture(Arc::clone(&blocking))?;
    let result = plane.execute(&operation, options()).await;
    ensure!(matches!(
        result.output.outcome,
        Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "fact_write_not_admitted"
    ));
    ensure!(result.completion_error.is_none());
    ensure!(!result.effect_may_have_started);
    ensure!(store.get(operation.id)?.is_none());
    ensure!(calls.load(Ordering::SeqCst) == 0);
    ensure!(blocking.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn denied_call_uses_owned_completion_job() -> anyhow::Result<()> {
    let blocking = ControlledBlocking::hold(1);
    let (plane, mut operation, store, calls) = fixture(Arc::clone(&blocking))?;
    operation.handle = HandleId::new(99, 99);
    let id = operation.id;
    let task = tokio::spawn(async move { plane.execute(&operation, options()).await });
    let job = blocking.next_job().await?;
    ensure!(calls.load(Ordering::SeqCst) == 0);
    job();
    let result = task.await?;
    ensure!(matches!(
        result.output.outcome,
        Outcome::Fail(Failure::PolicyViolation { .. })
    ));
    ensure!(result.completion_error.is_none());
    ensure!(!result.effect_may_have_started);
    ensure!(store.get(id)?.context("missing denial Fact")?.is_complete());
    Ok(())
}

#[tokio::test]
async fn cached_outcome_uses_owned_completion_without_driver() -> anyhow::Result<()> {
    let blocking = ControlledBlocking::hold(1);
    let (mut plane, operation, store, calls) =
        fixture_with_replay(Arc::clone(&blocking), ReplayClass::IdempotentEffect)?;
    plane.state = Backend::new().with_read(Arc::new(CachedState));
    let id = operation.id;
    let task = tokio::spawn(async move { plane.execute(&operation, options()).await });
    let job = blocking.next_job().await?;
    ensure!(calls.load(Ordering::SeqCst) == 0);
    job();
    let result = task.await?;
    ensure!(result.output.outcome == Outcome::Done(Value::integer(91)));
    ensure!(result.output.origin == CompletionOrigin::CachedOutcome);
    ensure!(result.completion_error.is_none());
    ensure!(calls.load(Ordering::SeqCst) == 0);
    ensure!(store.get(id)?.context("missing cached Fact")?.is_complete());
    Ok(())
}

#[tokio::test]
async fn cancelled_begin_waiter_leaves_only_pending_fact() -> anyhow::Result<()> {
    let blocking = ControlledBlocking::hold(1);
    let (plane, operation, store, calls) = fixture(Arc::clone(&blocking))?;
    let id = operation.id;
    let task = tokio::spawn(async move { plane.execute(&operation, options()).await });
    let job = blocking.next_job().await?;
    ensure!(calls.load(Ordering::SeqCst) == 0);
    task.abort();
    drop(task.await);
    job();
    let fact = store
        .get(id)?
        .context("accepted begin did not write its Fact")?;
    ensure!(!fact.is_complete());
    ensure!(calls.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn cancelled_completion_waiter_does_not_revoke_accepted_write() -> anyhow::Result<()> {
    let blocking = ControlledBlocking::hold(2);
    let (plane, operation, store, calls) = fixture(Arc::clone(&blocking))?;
    let id = operation.id;
    let task = tokio::spawn(async move { plane.execute(&operation, options()).await });
    let job = blocking.next_job().await?;
    ensure!(calls.load(Ordering::SeqCst) == 1);
    ensure!(!store.get(id)?.context("missing begin Fact")?.is_complete());
    task.abort();
    drop(task.await);
    job();
    let fact = store
        .get(id)?
        .context("accepted completion did not write its Fact")?;
    ensure!(fact.is_complete());
    ensure!(fact.outcome == Some(Value::integer(77)));
    ensure!(calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn lost_completion_worker_keeps_real_output_and_operation_identity() -> anyhow::Result<()> {
    let blocking = ControlledBlocking::hold(2);
    let (plane, operation, store, calls) = fixture(Arc::clone(&blocking))?;
    let id = operation.id;
    let next_plane = plane.clone();
    let mut next_operation = operation.clone();
    next_operation.id.position = NodeId::new(1);
    let task = tokio::spawn(async move { plane.execute(&operation, options()).await });
    let job = blocking.next_job().await?;
    drop(job);
    let result = task.await?;
    ensure!(result.output.outcome == Outcome::Done(Value::integer(77)));
    ensure!(matches!(
        result.completion_error,
        Some(CompletionError::Fact(Failure::Custom { ref kind, ref message }))
            if kind == "fact_write_result_unknown" && message.contains(&id.to_string())
    ));
    ensure!(result.effect_may_have_started);
    ensure!(
        !store
            .get(id)?
            .context("missing pending Fact")?
            .is_complete()
    );
    ensure!(calls.load(Ordering::SeqCst) == 1);
    ensure!(matches!(
        next_plane.facts.observed_cursor(),
        Err(error) if error.kind() == crate::fact::FactErrorKind::ReopenRequired
    ));
    let next = next_plane.execute(&next_operation, options()).await;
    ensure!(matches!(
        next.output.outcome,
        Outcome::Fail(Failure::Custom { ref kind, .. }) if kind == "fact_store_reopen_required"
    ));
    ensure!(!next.effect_may_have_started);
    ensure!(calls.load(Ordering::SeqCst) == 1);
    ensure!(store.get(next_operation.id)?.is_none());
    Ok(())
}

#[tokio::test]
async fn committed_but_unconfirmed_fact_keeps_driver_output() -> anyhow::Result<()> {
    use crate::fact::testing::CompletionFaults;

    let blocking = ControlledBlocking::hold(usize::MAX);
    let (mut plane, operation, _store, calls) = fixture(blocking)?;
    let facts = Arc::new(CompletionFaults::default());
    facts
        .commit_unknown_after_complete
        .store(true, Ordering::SeqCst);
    plane.facts = FactSink::new(Arc::clone(&facts));
    let result = plane.execute(&operation, options()).await;
    ensure!(result.output.outcome == Outcome::Done(Value::integer(77)));
    ensure!(matches!(
        result.completion_error,
        Some(CompletionError::Fact(Failure::Custom { ref kind, ref message }))
            if kind == "fact_commit_outcome_unknown" && message.contains(&operation.id.to_string())
    ));
    ensure!(result.effect_may_have_started);
    ensure!(calls.load(Ordering::SeqCst) == 1);
    let fresh_view = FactSink::new(facts);
    let record = fresh_view
        .get(operation.id)?
        .context("unconfirmed commit was not visible in a new sink view")?;
    ensure!(record.outcome == Some(Value::integer(77)));
    Ok(())
}
