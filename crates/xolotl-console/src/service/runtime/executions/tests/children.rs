use super::*;
use tokio::sync::Notify;
use xolotl_kernel::{Driver, DriverContext, DriverError};
use xolotl_types::{DriverOutput, MethodId, ProcessId, TaintSource};

mod publication;
mod receipts;

#[derive(Default)]
pub(super) struct DisposalFailure {
    spawner: xolotl_kernel::host::TokioBlockingSpawner,
    pub(super) fail: std::sync::atomic::AtomicBool,
    pub(super) panic_next: std::sync::atomic::AtomicBool,
    pub(super) rejected: AtomicUsize,
    pub(super) panics: AtomicUsize,
}

struct PanickingCleanupPayload;

impl Drop for PanickingCleanupPayload {
    #[expect(
        clippy::panic,
        reason = "inject a destructor failure into cleanup supervision"
    )]
    fn drop(&mut self) {
        panic!("cleanup panic payload destructor");
    }
}

impl xolotl_kernel::host::BlockingSpawner for DisposalFailure {
    #[expect(
        clippy::panic,
        reason = "inject a blocking-port panic with a panicking payload"
    )]
    fn spawn(
        &self,
        job: xolotl_kernel::host::BlockingJob,
    ) -> Result<(), xolotl_kernel::host::BlockingSpawnError> {
        if self.panic_next.swap(false, Ordering::SeqCst) {
            self.panics.fetch_add(1, Ordering::SeqCst);
            std::panic::panic_any(PanickingCleanupPayload);
        }
        if self.fail.load(Ordering::SeqCst) {
            self.rejected.fetch_add(1, Ordering::SeqCst);
            return Err(xolotl_kernel::host::BlockingSpawnError::Unavailable);
        }
        self.spawner.spawn(job)
    }
}

#[derive(Default)]
struct Body {
    calls: AtomicUsize,
    drops: AtomicUsize,
    release: Notify,
}
struct Running<'a>(&'a AtomicUsize);
impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Driver for Body {
    async fn call(
        &self,
        _: MethodId,
        input: Value,
        _: OutputMode,
        _: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let _running = Running(&self.drops);
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.release.notified().await;
        Ok(DriverOutput::new(Outcome::Done(input))
            .with_taint(TaintSet::of(TaintSource::ModelOutput)))
    }
}

fn install(f: &Fixture) -> anyhow::Result<Arc<Body>> {
    let body = Arc::new(Body::default());
    f.state.boot.register_effect(
        "effect://jobs/child",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            MethodSpec::UNARY_ASYNC,
        )],
        body.clone(),
    )?;
    Ok(body)
}
fn invoke() -> anyhow::Result<Expression> {
    Ok(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://jobs/child")?),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::AsyncProcess,
            literal_input: None,
        },
    })
}
async fn entered(body: &Body) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(2), async {
        while body.calls.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}
async fn child(f: &Fixture, parent: &str) -> anyhow::Result<(String, ProcessId)> {
    f.finished(parent).await?;
    let result = f
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(parent))
        .await?
        .output
        .context("result")?;
    let reference = field(field(&result, "output")?, "value")?;
    Ok((
        field(reference, "execution_id")?
            .as_str()
            .context("child ID")?
            .into(),
        ProcessId::new(
            field(reference, "process_id")?
                .as_str()
                .context("process")?
                .parse()?,
        ),
    ))
}

#[tokio::test]
async fn sibling_submissions_share_the_parent_budget_after_its_body_finishes() -> anyhow::Result<()>
{
    let f = Fixture::with_propagation(config(), true, true).await?;
    let body = install(&f)?;
    let budget = crate::runtime::budget::value(&xolotl_types::BudgetSpec {
        max_inflight_ops: Some(1),
        ..Default::default()
    })?;
    let accepted = f
        .call(
            ACTION_RUNTIME_PROGRAM_SUBMIT,
            map_value([
                (
                    "source",
                    Value::string(serde_json::to_string(&Program::new(
                        invoke()?.both(invoke()?),
                    ))?),
                ),
                ("budget", budget.clone()),
            ]),
        )
        .await?;
    let parent = accepted
        .execution
        .context("reference")?
        .execution_id
        .context("parent ID")?;
    let finished = f.finished(&parent).await?;
    ensure!(field(&finished, "outcome")?.as_str() == Some("done"));
    ensure!(field(&finished, "budget")? == &budget);
    entered(&body).await?;
    let result = f
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&parent))
        .await?
        .output
        .context("result")?;
    let references = field(field(&result, "output")?, "value")?
        .as_list()
        .context("children")?;
    ensure!(references.len() == 2);
    // Keep the accepted driver suspended until the sibling has exhausted the shared slot.
    let failed = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            for reference in references {
                let id = field(reference, "execution_id")?
                    .as_str()
                    .context("child ID")?;
                let metadata = f
                    .call(ACTION_RUNTIME_EXECUTION_GET, id_input(id))
                    .await?
                    .output
                    .context("metadata")?;
                ensure!(field(&metadata, "budget")? == &budget);
                if field(&metadata, "outcome")?.as_str() == Some("failed") {
                    return Ok::<_, anyhow::Error>(id.to_owned());
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    ensure!(body.calls.load(Ordering::SeqCst) == 1);
    body.release.notify_one();
    for reference in references {
        let id = field(reference, "execution_id")?
            .as_str()
            .context("child ID")?;
        let finished = f.finished(id).await?;
        ensure!(
            field(&finished, "outcome")?.as_str()
                == Some(if id == failed { "failed" } else { "done" })
        );
    }
    ensure!(body.calls.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn submitted_child_survives_parent_and_uses_shared_cancel_result_and_forget()
-> anyhow::Result<()> {
    let f = Fixture::with_propagation(config(), true, true).await?;
    let body = install(&f)?;
    let parent = f.submit(invoke()?, Value::bytes(vec![255, 0])).await?;
    let (id, _) = child(&f, &parent).await?;
    entered(&body).await?;
    let row = f
        .call(ACTION_RUNTIME_EXECUTION_GET, id_input(&id))
        .await?
        .output
        .context("child")?;
    ensure!(field(&row, "status")?.as_str() == Some("running"));
    ensure!(field(&row, "lifetime")?.as_str() == Some("host"));
    let list = f
        .call(ACTION_RUNTIME_EXECUTION_LIST, Value::null())
        .await?
        .output
        .context("list")?;
    ensure!(field(&list, "entries")?.as_list().context("entries")?.len() == 2);
    f.call(ACTION_RUNTIME_EXECUTION_CANCEL, id_input(&id))
        .await?;
    let finished = f.finished(&id).await?;
    ensure!(field(&finished, "outcome")?.as_str() == Some("cancelled"));
    ensure!(field(&finished, "cleanup_status")?.as_str() == Some("complete"));
    ensure!(body.drops.load(Ordering::SeqCst) == 1);
    let result = f
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("result")?;
    ensure!(!field(field(&result, "output")?, "failure")?.is_null());
    f.call(ACTION_RUNTIME_EXECUTION_FORGET, id_input(&id))
        .await?;
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_GET, id_input(&id))
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn host_exposure_and_user_propagation_are_both_required() -> anyhow::Result<()> {
    for (user, host) in [(true, false), (false, true)] {
        let f = Fixture::with_propagation(config(), user, host).await?;
        let body = install(&f)?;
        let result = f
            .call(
                ACTION_RUNTIME_PROGRAM_SUBMIT,
                map_value([(
                    "source",
                    Value::string(serde_json::to_string(&Program::new(invoke()?))?),
                )]),
            )
            .await;
        ensure!(result.err().context("propagation denied")?.code == ConsoleErrorCode::Forbidden);
        ensure!(body.calls.load(Ordering::SeqCst) == 0);
    }
    Ok(())
}

#[tokio::test]
async fn conditional_method_and_propagation_grants_use_the_literal_operation_input()
-> anyhow::Result<()> {
    let f = Fixture::with_boot_grants(
        Arc::new(Bootstrap::in_memory()),
        config(),
        [
            "perform://effect/jobs/**@tenant=alice",
            "perform://effect/jobs/**@tenant=bob",
            "spawn-with://effect/jobs/**@lane=east",
            "spawn-with://effect/jobs/**@lane=west",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        true,
    )
    .await?;
    let body = install(&f)?;
    for (tenant, lane, allowed) in [
        ("alice", "east", true),
        ("bob", "west", true),
        ("mallory", "west", false),
        ("alice", "north", false),
    ] {
        let literal = map_value([
            ("tenant", Value::string(tenant.into())),
            ("lane", Value::string(lane.into())),
        ]);
        let mut expression = invoke()?;
        let Expression::Invoke { operation } = &mut expression else {
            anyhow::bail!("expected invocation");
        };
        operation.literal_input = Some(literal.clone());
        let prior = body.calls.load(Ordering::SeqCst);
        let parent = f
            .submit(
                expression,
                map_value([
                    ("tenant", Value::string("mallory".into())),
                    ("lane", Value::string("north".into())),
                ]),
            )
            .await?;
        if allowed {
            let (child_id, _) = child(&f, &parent).await?;
            tokio::time::timeout(Duration::from_secs(2), async {
                while body.calls.load(Ordering::SeqCst) == prior {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            body.release.notify_one();
            ensure!(field(&f.finished(&child_id).await?, "outcome")?.as_str() == Some("done"));
        } else {
            ensure!(field(&f.finished(&parent).await?, "outcome")?.as_str() == Some("failed"));
            ensure!(body.calls.load(Ordering::SeqCst) == prior);
        }
    }
    Ok(())
}

#[tokio::test]
async fn conditional_propagation_survives_monitoring_until_account_revocation() -> anyhow::Result<()>
{
    let method = "perform://effect/jobs/**@tenant=alice";
    let propagation = "spawn-with://effect/jobs/**@lane=east";
    let f = Fixture::with_boot_grants(
        Arc::new(Bootstrap::in_memory()),
        config(),
        vec![method.into(), propagation.into()],
        true,
    )
    .await?;
    let body = install(&f)?;
    let mut expression = invoke()?;
    let Expression::Invoke { operation } = &mut expression else {
        anyhow::bail!("expected invocation");
    };
    operation.literal_input = Some(map_value([
        ("tenant", Value::string("alice".into())),
        ("lane", Value::string("east".into())),
    ]));
    let parent = f
        .submit(
            expression,
            map_value([
                ("tenant", Value::string("other".into())),
                ("lane", Value::string("west".into())),
            ]),
        )
        .await?;
    let (child_id, _) = child(&f, &parent).await?;
    entered(&body).await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    ensure!(
        body.drops.load(Ordering::SeqCst) == 0,
        "periodic account revalidation rejected the retained conditional grant"
    );

    let path = Path::parse("state://kernel/console/users/root")?;
    let mut user = f
        .state
        .state
        .read(&path)
        .await?
        .context("user")?
        .as_map()
        .context("map")?
        .clone();
    user.insert(
        "grants".into(),
        Value::list(vec![Value::string(method.into())]),
    )?;
    f.state.state.write_set(&path, Value::from(user)).await?;
    let record = f.finished(&child_id).await?;
    ensure!(field(&record, "outcome")?.as_str() == Some("cancelled"));
    ensure!(field(&record, "stop_cause")?.as_str() == Some("authority_revoked"));
    ensure!(body.drops.load(Ordering::SeqCst) == 1);
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&child_id))
            .await
            .err()
            .context("revoked result")?
            .code
            == ConsoleErrorCode::Forbidden
    );
    Ok(())
}

#[tokio::test]
async fn attached_request_cannot_detach_children() -> anyhow::Result<()> {
    let f = Fixture::with_propagation(config(), true, true).await?;
    let body = install(&f)?;
    let program = Program::new(invoke()?);
    let result = f
        .call(
            ACTION_RUNTIME_PROGRAM_RUN,
            map_value([("source", Value::string(serde_json::to_string(&program)?))]),
        )
        .await;
    ensure!(result.err().context("lifecycle denied")?.code == ConsoleErrorCode::BadRequest);
    ensure!(body.calls.load(Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn child_capacity_is_reserved_before_any_driver_effect() -> anyhow::Result<()> {
    let f = Fixture::with_propagation(
        ConsoleExecutionConfig {
            max_concurrent: 1,
            max_concurrent_per_account: 1,
            ..config()
        },
        true,
        true,
    )
    .await?;
    let body = install(&f)?;
    let id = f.submit(invoke()?, Value::null()).await?;
    ensure!(field(&f.finished(&id).await?, "outcome")?.as_str() == Some("failed"));
    ensure!(body.calls.load(Ordering::SeqCst) == 0);
    let list = f
        .call(ACTION_RUNTIME_EXECUTION_LIST, Value::null())
        .await?
        .output
        .context("list")?;
    ensure!(field(&list, "entries")?.as_list().context("entries")?.len() == 1);
    Ok(())
}

#[tokio::test]
async fn shutdown_waits_for_child_driver_release_after_parent_finished() -> anyhow::Result<()> {
    let f = Fixture::with_propagation(config(), true, true).await?;
    let body = install(&f)?;
    let parent = f.submit(invoke()?, Value::null()).await?;
    let (id, _) = child(&f, &parent).await?;
    entered(&body).await?;
    tokio::time::timeout(Duration::from_secs(2), f.service.shutdown_executions()).await?;
    ensure!(body.drops.load(Ordering::SeqCst) == 1);
    let record = f.finished(&id).await?;
    ensure!(field(&record, "outcome")?.as_str() == Some("cancelled"));
    ensure!(field(&record, "stop_cause")?.as_str() == Some("shutdown"));
    Ok(())
}

#[tokio::test]
async fn child_retains_original_submission_deadline_after_parent_completion() -> anyhow::Result<()>
{
    let f = Fixture::with_propagation(config(), true, true).await?;
    let body = install(&f)?;
    let call = scoped(
        ACTION_RUNTIME_OPERATION_SUBMIT,
        map_value([
            ("target", Value::string("effect://jobs/child".into())),
            ("method", Value::string("invoke".into())),
            ("output", Value::string("async_process".into())),
            ("timeout_ms", Value::integer(150)),
        ]),
    );
    let submitted = f.service.call(&f.token, None, call).await?;
    let parent = submitted
        .execution
        .context("reference")?
        .execution_id
        .context("ID")?;
    let (id, _) = child(&f, &parent).await?;
    ensure!(field(&f.finished(&id).await?, "outcome")?.as_str() == Some("timed_out"));
    ensure!(body.calls.load(Ordering::SeqCst) == 1 && body.drops.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn propagation_revocation_stops_children_and_blocks_retained_results() -> anyhow::Result<()> {
    let f = Fixture::with_propagation(config(), true, true).await?;
    let body = install(&f)?;
    let parent = f.submit(invoke()?, Value::null()).await?;
    let (id, _) = child(&f, &parent).await?;
    entered(&body).await?;
    let path = Path::parse("state://kernel/console/users/root")?;
    let mut user = f
        .state
        .state
        .read(&path)
        .await?
        .context("user")?
        .as_map()
        .context("map")?
        .clone();
    // Preserve method permission and account generation; revoke only propagation.
    user.insert(
        "grants".into(),
        Value::list(vec![Value::string("perform://effect/jobs/**".into())]),
    )?;
    f.state.state.write_set(&path, Value::from(user)).await?;
    let record = f.finished(&id).await?;
    ensure!(field(&record, "outcome")?.as_str() == Some("cancelled"));
    ensure!(field(&record, "stop_cause")?.as_str() == Some("authority_revoked"));
    ensure!(body.drops.load(Ordering::SeqCst) == 1);
    ensure!(
        f.call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
            .await
            .err()
            .context("denied result")?
            .code
            == ConsoleErrorCode::Forbidden
    );
    Ok(())
}

#[tokio::test]
async fn forced_abort_keeps_unknown_result_and_later_cleanup_acknowledgement() -> anyhow::Result<()>
{
    let f = Fixture::with_propagation(config(), true, true).await?;
    let body = install(&f)?;
    let parent = f.submit(invoke()?, Value::null()).await?;
    let (id, process) = child(&f, &parent).await?;
    entered(&body).await?;
    f.state.boot.finalize_process(process).await?;
    let ended = f.finished(&id).await?;
    ensure!(field(&ended, "outcome")?.as_str() == Some("failed"));
    ensure!(field(&ended, "result_status")?.as_str() == Some("available"));
    ensure!(field(&ended, "unresolved_operation_count")?.as_int() == Some(1));
    let result = f
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("retained child result")?;
    let operation_ids = field(field(&result, "unresolved_operations")?, "operation_ids")?
        .as_list()
        .context("unresolved child operation IDs")?;
    ensure!(operation_ids.len() == 1);
    ensure!(
        field(field(field(&result, "output")?, "failure")?, "code")?.as_str()
            == Some("outcome_unknown")
    );
    ensure!(
        field(field(field(&result, "finalization")?, "report")?, "status")?.as_str()
            == Some("cancelled")
    );
    ensure!(!field(field(&result, "output")?, "failure")?.is_null());
    ensure!(field(&ended, "cleanup_status")?.as_str() == Some("complete"));
    ensure!(body.drops.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn child_results_preserve_provenance_and_enforce_retention_budget() -> anyhow::Result<()> {
    for bytes in [vec![0, 255], vec![42; 8192]] {
        let f = Fixture::with_propagation(
            ConsoleExecutionConfig {
                max_result_bytes: 1024,
                ..config()
            },
            true,
            true,
        )
        .await?;
        let body = install(&f)?;
        body.release.notify_one();
        let parent = f.submit(invoke()?, Value::bytes(bytes.clone())).await?;
        let (id, _) = child(&f, &parent).await?;
        let ended = f.finished(&id).await?;
        ensure!(field(&ended, "outcome")?.as_str() == Some("done"));
        let result = f
            .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
            .await?
            .output
            .context("result")?;
        if bytes.len() < 1024 {
            ensure!(field(field(&result, "output")?, "value")? == &Value::bytes(bytes));
            let taint: TaintSet = serde_json::from_value(serde_json::to_value(field(
                field(&result, "output")?,
                "taint",
            )?)?)?;
            ensure!(
                taint.contains_all(&TaintSet::author())
                    && taint.contains_all(&TaintSet::of(TaintSource::ModelOutput))
            );
        } else {
            ensure!(field(&ended, "result_status")?.as_str() == Some("omitted"));
            ensure!(field(&result, "output")?.is_null());
        }
    }
    Ok(())
}

#[tokio::test]
async fn rejected_disposal_retains_result_and_retry_does_not_renew_retention() -> anyhow::Result<()>
{
    let state = xolotl_state::InMemoryBackend::new().into_backend();
    let fault = Arc::new(DisposalFailure::default());
    let boot = Arc::new(Bootstrap::from_kernel(
        xolotl_kernel::KernelBuilder::new(state)
            .with_host_runtime(xolotl_kernel::host::HostRuntime::tokio_with_blocking(
                fault.clone(),
            ))
            .with_fact_sink(xolotl_kernel::FactSink::in_memory().0)
            .build(),
    ));
    let f = Fixture::with_boot(boot, config(), true, true).await?;
    let body = install(&f)?;
    let parent = f.submit(invoke()?, Value::bytes(vec![0, 255])).await?;
    let (id, _) = child(&f, &parent).await?;
    entered(&body).await?;
    fault.fail.store(true, Ordering::SeqCst);
    body.release.notify_one();
    let pending = f.finished(&id).await?;
    ensure!(field(&pending, "outcome")?.as_str() == Some("done"));
    ensure!(field(&pending, "cleanup_status")?.as_str() == Some("pending"));
    ensure!(fault.rejected.load(Ordering::SeqCst) > 0);
    ensure!(body.drops.load(Ordering::SeqCst) == 1);
    let output = f
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("retained")?;
    ensure!(field(field(&output, "output")?, "value")? == &Value::bytes(vec![0, 255]));
    tokio::time::timeout(Duration::from_secs(1), f.service.shutdown_executions()).await?;
    fault.fail.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(5)).await;
    ensure!(f.state.boot.drain_cleanup().await.failures.is_empty());
    let completed = f.finished(&id).await?;
    ensure!(field(&completed, "cleanup_status")?.as_str() == Some("complete"));
    ensure!(field(&completed, "finished_at")? == field(&pending, "finished_at")?);
    ensure!(field(&completed, "expires_at")? == field(&pending, "expires_at")?);
    ensure!(body.calls.load(Ordering::SeqCst) == 1);
    let retried = f
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("retried")?;
    ensure!(field(&retried, "output")? == field(&output, "output")?);
    Ok(())
}
