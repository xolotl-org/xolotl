use super::*;
use futures_util::FutureExt;
use std::sync::atomic::{AtomicBool, AtomicU64};
use xolotl_kernel::{
    Driver, DriverContext, DriverError, ExecutionIdError, ExecutionIdRange, ExecutionIdSource,
    FactError, FactLookup, FactLookupResult, FactPage, FactQuery, FactSink, FactStore,
    InMemoryFactStore, KernelBuilder,
};
use xolotl_types::{DriverOutput, Fact, MethodId, ProcessId};

struct StateWrites {
    backend: xolotl_state::Backend,
    writes: AtomicUsize,
    generic_writes: AtomicUsize,
}

impl xolotl_state::StateWrite for StateWrites {
    type Write<'a> = std::pin::Pin<
        Box<
            dyn std::future::Future<Output = xolotl_state::StateResult<xolotl_state::StateCommit>>
                + Send
                + 'a,
        >,
    >;

    fn mutate<'a>(
        &'a self,
        path: &'a Path,
        mutation: xolotl_state::StateMutation,
    ) -> Self::Write<'a> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if path.to_string().starts_with("state://kernel/process/") {
            self.generic_writes.fetch_add(1, Ordering::SeqCst);
        }
        Box::pin(self.backend.mutate(path, mutation))
    }
}

#[derive(Default)]
struct FactWrites {
    store: InMemoryFactStore,
    tracked_process: AtomicU64,
    request_writes: AtomicUsize,
    lifecycle_writes: AtomicUsize,
}

impl FactWrites {
    fn record_write(&self, fact: &Fact) {
        if fact.id.process.get() == self.tracked_process.load(Ordering::SeqCst) {
            self.request_writes.fetch_add(1, Ordering::SeqCst);
        }
        if fact.outcome.as_ref().is_some_and(|outcome| {
            field(outcome, "event").is_ok_and(|event| {
                matches!(
                    event.as_str(),
                    Some("console_execution" | "ProcessFinalized")
                )
            })
        }) {
            self.lifecycle_writes.fetch_add(1, Ordering::SeqCst);
        }
    }
}

impl ExecutionIdSource for FactWrites {
    fn reserve(&self, count: std::num::NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        self.store.reserve(count)
    }
}

impl FactStore for FactWrites {
    fn append(&self, fact: Fact) -> Result<u64, FactError> {
        self.record_write(&fact);
        self.store.append(fact)
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        self.record_write(&fact);
        self.store.complete(fact)
    }

    fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        self.store.scan(query)
    }

    fn lookup(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        self.store.lookup(query)
    }

    fn facts_of(&self, process: ProcessId) -> Result<Vec<Fact>, FactError> {
        self.store.facts_of(process)
    }

    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        self.store.all_facts()
    }

    fn cursor(&self) -> u64 {
        self.store.cursor()
    }
}

async fn prepare_worker(fixture: &Fixture, target: &str) -> anyhow::Result<(Worker, Plan)> {
    let owner = fixture.owner().await?;
    let principal = fixture
        .state
        .auth
        .authenticate_token(&fixture.state.boot, &fixture.token)
        .await?;
    let call = scoped(
        ACTION_RUNTIME_OPERATION_SUBMIT,
        map_value([
            ("target", Value::string(target.into())),
            ("method", Value::string("invoke".into())),
            ("input", Value::integer(37)),
        ]),
    );
    let plan = plan(&fixture.state, &principal, &call, false, None)?;
    let context = ActionContext {
        delivery: None,
        state: &fixture.state,
        session_id: fixture.token.split_once('.').context("SID")?.0,
        source_addr: Some("test"),
    };
    let request = begin(&context, &principal, &call, &plan)?;
    let process = request.id();
    let cleanup_ticket = fixture.state.boot.cleanup_ticket(process)?;
    let authority = vec![("perform".into(), Path::parse(target)?)];
    let (registration, stop, reference) = fixture.state.executions.register(
        owner.clone(),
        authority.clone(),
        ExecutionReference {
            execution_id: None,
            process_id: process.get().to_string(),
            program_id: plan.program_id.clone(),
        },
        xolotl_kernel::host::system_now_millis() + 10_000,
        plan.budget.clone(),
    )?;
    registration.bind_cleanup(cleanup_ticket.clone())?;
    Ok((
        Worker {
            state: fixture.state.clone(),
            owner,
            authority,
            authority_candidates: admitted_authority_candidates(
                &plan,
                &principal.grants,
                &[("perform".into(), Path::parse(target)?)],
            )?,
            request,
            cleanup_ticket,
            registration,
            stop,
            reference,
        },
        plan,
    ))
}

#[tokio::test]
async fn completed_body_resists_late_cancellation_without_call_fact_writes() -> anyhow::Result<()> {
    let facts = Arc::new(FactWrites::default());
    let backend = xolotl_state::InMemoryBackend::new().into_backend();
    let state_writes = Arc::new(StateWrites {
        backend: backend.clone(),
        writes: AtomicUsize::new(0),
        generic_writes: AtomicUsize::new(0),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(backend.with_write(state_writes.clone()))
            .with_fact_sink(FactSink::new(facts.clone()))
            .build(),
    ));
    let fixture = Fixture::with_boot(boot, config(), false, false).await?;
    let (mut worker, plan) = prepare_worker(&fixture, "effect://jobs/echo").await?;
    let owner = worker.owner.clone();
    let id = worker
        .reference
        .execution_id
        .clone()
        .context("execution ID")?;
    let process = worker.request.id();
    let ticket = worker.cleanup_ticket.clone();
    facts.tracked_process.store(process.get(), Ordering::SeqCst);
    ensure!(facts.lifecycle_writes.load(Ordering::SeqCst) == 0);
    let state_writes_before = state_writes.writes.load(Ordering::SeqCst);
    let (output, stop_outcome) = worker.evaluate(plan).await;
    ensure!(matches!(&output.outcome, Outcome::Done(value) if value == &Value::integer(37)));
    ensure!(stop_outcome.is_none());
    ensure!(facts.request_writes.load(Ordering::SeqCst) == 0);
    ensure!(!fixture.state.boot.cancel_process(process)?);
    worker.finish(output, stop_outcome).await;
    ensure!(state_writes.writes.load(Ordering::SeqCst) == state_writes_before);
    let pending = fixture.finished(&id).await?;
    ensure!(facts.request_writes.load(Ordering::SeqCst) == 0);
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Completed));
    ensure!(ticket.is_complete());
    ensure!(state_writes.generic_writes.load(Ordering::SeqCst) == 0);
    ensure!(fixture.state.boot.kernel().handles().is_empty());
    ensure!(
        fixture
            .state
            .boot
            .kernel()
            .processes()
            .attached_grants(process)
            .is_empty()
    );
    ensure!(
        fixture.state.boot.kernel().processes().status(process) == Some(ProcessStatus::Completed)
    );
    ensure!(field(&pending, "outcome")?.as_str() == Some("done"));
    ensure!(field(&pending, "cleanup_status")?.as_str() == Some("complete"));
    let before = fixture.state.executions.result(&owner, &id, |_| true)?;
    ensure!(
        field(field(field(&before, "finalization")?, "report")?, "status")?.as_str()
            == Some("completed")
    );
    ensure!(field(field(&before, "output")?, "value")? == &Value::integer(37));
    ensure!(field(field(&before, "output")?, "failure")?.is_null());

    let after = fixture.state.executions.result(&owner, &id, |_| true)?;
    let complete = field(&after, "record")?;
    ensure!(field(complete, "cleanup_status")?.as_str() == Some("complete"));
    ensure!(
        fixture.state.boot.kernel().processes().status(process) == Some(ProcessStatus::Completed)
    );
    for name in ["outcome", "finished_at", "expires_at"] {
        ensure!(field(complete, name)? == field(&pending, name)?);
    }
    ensure!(field(&after, "output")? == field(&before, "output")?);
    ensure!(fixture.calls.load(Ordering::SeqCst) == 1);
    ensure!(
        fixture
            .service
            .shutdown_executions()
            .await
            .volatile_cleanup_pending
            == 0
    );
    ensure!(facts.request_writes.load(Ordering::SeqCst) == 0);
    ensure!(state_writes.generic_writes.load(Ordering::SeqCst) == 0);
    ensure!(
        facts.lifecycle_writes.load(Ordering::SeqCst) == 0,
        "ordinary body/cleanup wrote a retired lifecycle Fact"
    );
    Ok(())
}

#[tokio::test]
async fn output_stop_preserves_completed_worker_body_and_separate_lifecycle() -> anyhow::Result<()>
{
    let fixture = Fixture::new(config()).await?;
    let (mut worker, plan) = prepare_worker(&fixture, "effect://jobs/echo").await?;
    let owner = worker.owner.clone();
    let id = worker
        .reference
        .execution_id
        .clone()
        .context("execution ID")?;
    let process = worker.request.id();
    let (output, reason) = worker.evaluate(plan).await;
    ensure!(reason.is_none());
    ensure!(output.outcome == Outcome::Done(Value::integer(37)));
    let expected = result_value(&output)?;
    ensure!(!fixture.state.boot.cancel_process(process)?);
    worker.finish(output, Some("output_limit")).await;
    let retained = fixture.state.executions.result(&owner, &id, |_| true)?;
    ensure!(field(field(&retained, "record")?, "outcome")?.as_str() == Some("done"));
    ensure!(field(field(&retained, "record")?, "stop_cause")?.as_str() == Some("output_limit"));
    ensure!(field(&retained, "output")? == &expected);
    ensure!(
        field(
            field(field(&retained, "finalization")?, "report")?,
            "status"
        )?
        .as_str()
            == Some("completed")
    );
    ensure!(field(field(&retained, "record")?, "cleanup_status")?.as_str() == Some("complete"));
    Ok(())
}

#[derive(Default)]
struct HoldInvocation {
    held: AtomicBool,
    released: AtomicUsize,
}

struct InvocationCapture<'a>(&'a AtomicUsize);

impl Drop for InvocationCapture<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Driver for HoldInvocation {
    async fn call(
        &self,
        _: MethodId,
        input: Value,
        _: OutputMode,
        _: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if input == Value::integer(37) {
            return Ok(DriverOutput::new(Outcome::Done(input)));
        }
        let _capture = InvocationCapture(&self.released);
        self.held.store(true, Ordering::SeqCst);
        std::future::pending().await
    }
}

#[tokio::test]
async fn successful_lifecycle_keeps_console_custody_until_direct_invocation_settles()
-> anyhow::Result<()> {
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_fact_sink(FactSink::in_memory().0)
            .build(),
    ));
    let fixture = Fixture::with_boot(
        boot,
        ConsoleExecutionConfig {
            max_concurrent: 1,
            max_concurrent_per_account: 1,
            ..config()
        },
        false,
        false,
    )
    .await?;
    let driver = Arc::new(HoldInvocation::default());
    let target = "effect://jobs/held-invocation";
    fixture.state.boot.register_effect(
        target,
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            OutputModeSet::UNARY,
        )],
        driver.clone(),
    )?;
    let (mut worker, plan) = prepare_worker(&fixture, target).await?;
    let process = worker.request.id();
    let ticket = worker.cleanup_ticket.clone();
    let owner = worker.owner.clone();
    let id = worker
        .reference
        .execution_id
        .clone()
        .context("execution ID")?;
    // An embedding can retain a directly invoked future without attaching a
    // managed process task. Keep its real accounting reservation across finish.
    let executor = worker.request.executor();
    let program = xolotl_graph::DoNode::Op(OperationTemplate {
        target: ResourceName::new(Path::parse(target)?),
        method: "invoke".into(),
        method_id: None,
        output: OutputMode::Unary,
        literal_input: Some(Value::integer(99)),
    });
    let mut invocation = Box::pin(executor.eval(&program));
    ensure!(invocation.as_mut().now_or_never().is_none());
    ensure!(driver.held.load(Ordering::SeqCst));
    ensure!(!fixture.state.boot.kernel().processes().has_task(process));
    let (output, reason) = worker.evaluate(plan).await;
    ensure!(matches!(&output.outcome, Outcome::Done(value) if value == &Value::integer(37)));
    worker.finish(output, reason).await;
    ensure!(
        fixture.state.boot.kernel().processes().status(process) == Some(ProcessStatus::Completed)
    );
    ensure!(!ticket.is_complete());
    let before = fixture.state.executions.result(&owner, &id, |_| true)?;
    let pending = field(&before, "record")?;
    ensure!(field(pending, "outcome")?.as_str() == Some("done"));
    ensure!(field(pending, "cleanup_status")?.as_str() == Some("pending"));
    ensure!(field(field(&before, "output")?, "value")? == &Value::integer(37));
    ensure!(fixture.state.executions.forget(&owner, &id).await.is_err());
    ensure!(
        fixture
            .call(
                ACTION_RUNTIME_OPERATION_SUBMIT,
                map_value([
                    ("target", Value::string("effect://jobs/echo".into())),
                    ("method", Value::string("invoke".into())),
                ])
            )
            .await
            .err()
            .context("pending custody must reserve capacity")?
            .code
            == ConsoleErrorCode::RateLimited
    );
    ensure!(fixture.calls.load(Ordering::SeqCst) == 0);

    // Dropping the invocation settles its admitted account and destroys the
    // driver's native capture. The directory may now acknowledge the ticket.
    drop(invocation);
    drop(executor);
    ensure!(driver.released.load(Ordering::SeqCst) == 1);
    ensure!(ticket.is_complete());
    let after = fixture.state.executions.result(&owner, &id, |_| true)?;
    let complete = field(&after, "record")?;
    ensure!(field(complete, "cleanup_status")?.as_str() == Some("complete"));
    for name in ["outcome", "finished_at", "expires_at"] {
        ensure!(field(complete, name)? == field(pending, name)?);
    }
    ensure!(field(&after, "output")? == field(&before, "output")?);
    let next = fixture.submit(echo()?, Value::integer(11)).await?;
    fixture.finished(&next).await?;
    ensure!(fixture.calls.load(Ordering::SeqCst) == 1);
    ensure!(
        fixture
            .service
            .shutdown_executions()
            .await
            .volatile_cleanup_pending
            == 0
    );
    Ok(())
}
