use super::*;
use futures_util::FutureExt;
use xolotl_kernel::stream::{StreamRouter as _, send};
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput};
use xolotl_types::{
    CausalPosition, ExecutionId, InvocationId, MethodId, OperationId, Outcome, ProcessId, TaintSet,
    TaintSource, TaintedValue,
};

#[derive(Default)]
struct Probe {
    emitted: AtomicUsize,
    operation: std::sync::Mutex<Option<OperationId>>,
}

struct StreamDriver {
    probe: Arc<Probe>,
    count: usize,
    hold: bool,
}

#[async_trait::async_trait]
impl Driver for StreamDriver {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        *self
            .probe
            .operation
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = context.operation_id;
        for _ in 0..self.count {
            context
                .emit_tainted(TaintedValue::new(
                    input.clone(),
                    TaintSet::of(TaintSource::ModelOutput),
                ))
                .await?;
            self.probe.emitted.fetch_add(1, Ordering::SeqCst);
        }
        if self.hold {
            std::future::pending::<()>().await;
        }
        Ok(DriverOutput::new(Outcome::Done(Value::integer(
            self.count as i64,
        ))))
    }
}

async fn fixture(
    config: ConsoleExecutionConfig,
    count: usize,
    hold: bool,
) -> anyhow::Result<(Fixture, Arc<Probe>)> {
    let boot = Arc::new(Bootstrap::in_memory());
    let probe = Arc::new(Probe::default());
    boot.register_effect(
        "effect://jobs/stream",
        &[MethodSpec::new(
            "invoke",
            MethodAuthority::Perform,
            Purity::Effectful,
            OutputModeSet::STREAM,
        )
        .finalize_allowed()],
        Arc::new(StreamDriver {
            probe: probe.clone(),
            count,
            hold,
        }),
    )?;
    Ok((Fixture::with_boot(boot, config, false, false).await?, probe))
}

fn expression() -> anyhow::Result<Expression> {
    Ok(Expression::Invoke {
        operation: OperationTemplate {
            target: ResourceName::new(Path::parse("effect://jobs/stream")?),
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Stream,
            literal_input: None,
        },
    })
}

fn output_input(id: &str, cursor: i64, limit: i64, wait_ms: i64) -> Value {
    map_value([
        ("execution_id", Value::string(id.into())),
        ("cursor", Value::integer(cursor)),
        ("limit", Value::integer(limit)),
        ("wait_ms", Value::integer(wait_ms)),
    ])
}

async fn read(fixture: &Fixture, id: &str, cursor: i64, limit: i64) -> anyhow::Result<Value> {
    fixture
        .call(
            ACTION_RUNTIME_EXECUTION_OUTPUT_READ,
            output_input(id, cursor, limit, 0),
        )
        .await?
        .output
        .context("output page")
}

fn events(page: &Value) -> anyhow::Result<&xolotl_types::ValueList> {
    field(page, "entries")?.as_list().context("output entries")
}

fn event(page: &Value, index: usize) -> anyhow::Result<&Value> {
    events(page)?.get(index).context("output event")
}

#[tokio::test]
async fn stream_worker_finishes_without_observer_and_pages_replay_independently()
-> anyhow::Result<()> {
    let (fixture, probe) = fixture(config(), 3, false).await?;
    let id = fixture
        .submit(expression()?, Value::bytes(vec![0, 1, 255]))
        .await?;
    let record = fixture.finished(&id).await?;
    ensure!(field(&record, "outcome")?.as_str() == Some("done"));
    ensure!(probe.emitted.load(Ordering::SeqCst) == 3);
    ensure!(field(&record, "output_observation")?.as_bool() == Some(true));
    ensure!(field(&record, "output_sequence")?.as_int() == Some(5));

    let first = read(&fixture, &id, 0, 2).await?;
    let second_observer = read(&fixture, &id, 0, 2).await?;
    ensure!(first == second_observer);
    ensure!(field(&first, "complete")?.as_bool() == Some(true));
    ensure!(field(&first, "has_more")?.as_bool() == Some(true));
    ensure!(events(&first)?.len() == 2);
    ensure!(field(event(&first, 0)?, "sequence")?.as_int() == Some(1));
    ensure!(field(event(&first, 0)?, "kind")?.as_str() == Some("output"));
    ensure!(field(event(&first, 0)?, "value")?.as_bytes() == Some(&[0, 1, 255][..]));
    ensure!(!field(event(&first, 0)?, "taint")?.is_null());
    let middle = read(&fixture, &id, 2, 2).await?;
    ensure!(field(event(&middle, 0)?, "sequence")?.as_int() == Some(3));
    ensure!(field(event(&middle, 1)?, "kind")?.as_str() == Some("operation_finished"));
    let last = read(&fixture, &id, 4, 2).await?;
    ensure!(events(&last)?.len() == 1);
    ensure!(field(event(&last, 0)?, "kind")?.as_str() == Some("terminal"));
    ensure!(field(event(&last, 0)?, "outcome")?.as_str() == Some("done"));
    ensure!(field(&last, "has_more")?.as_bool() == Some(false));
    ensure!(events(&read(&fixture, &id, 5, 2).await?)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn output_quota_failure_keeps_committed_prefix_and_terminal() -> anyhow::Result<()> {
    let config = ConsoleExecutionConfig {
        max_output_events: 3,
        ..config()
    };
    let (fixture, _) = fixture(config, 4, false).await?;
    let id = fixture.submit(expression()?, Value::integer(7)).await?;
    let record = fixture.finished(&id).await?;
    ensure!(field(&record, "stop_cause")?.as_str() == Some("output_limit"));
    let page = read(&fixture, &id, 0, 8).await?;
    ensure!(events(&page)?.len() == 3);
    ensure!(field(event(&page, 0)?, "sequence")?.as_int() == Some(1));
    ensure!(field(event(&page, 1)?, "sequence")?.as_int() == Some(2));
    ensure!(field(event(&page, 2)?, "kind")?.as_str() == Some("terminal"));
    ensure!(field(event(&page, 2)?, "outcome")? == field(&record, "outcome")?);
    ensure!(field(event(&page, 2)?, "stop_cause")?.as_str() == Some("output_limit"));
    Ok(())
}

#[tokio::test]
async fn output_quota_failure_preserves_completed_evaluation_evidence() -> anyhow::Result<()> {
    let config = ConsoleExecutionConfig {
        max_output_events: 3,
        ..config()
    };
    let (fixture, _) = fixture(config.clone(), 0, false).await?;
    let owner = fixture.owner().await?;
    let (registration, _stop, _) =
        fixture
            .state
            .executions
            .register_authorized(crate::runtime::executions::Admission {
                owner,
                authority: vec![("perform".into(), Path::parse("effect://jobs/stream")?)],
                authority_candidates: vec![xolotl_types::Capability::parse(
                    "perform://effect/jobs/stream#invoke",
                )?]
                .into(),
                reference: ExecutionReference {
                    execution_id: None,
                    process_id: "7".into(),
                    program_id: "00".repeat(32),
                },
                budget: xolotl_types::BudgetSpec::default(),
                deadline: xolotl_kernel::host::system_now_millis() + 60_000,
                origin: None,
                stream_output: true,
            })?;
    let (router, ports) = streaming::ports(&fixture.state.runtime.config);
    let operation = OperationId::new(
        ProcessId::new(7),
        ExecutionId::FIRST,
        InvocationId::new(1),
        CausalPosition::new(1),
        0,
    );
    let sink = router.open(operation)?;
    for _ in 0..3 {
        send(
            sink.as_ref(),
            TaintedValue::new(Value::integer(7), TaintSet::of(TaintSource::ModelOutput)),
        )
        .await?;
    }
    drop(sink);
    drop(router);
    let mut completed = ExecutionOutput::new(Outcome::Done(Value::integer(9)), TaintSet::author());
    completed.unresolved_operations.record("host-operation-1");
    let mut observed = None;
    let failure = streaming::pump_log(
        std::future::ready(completed.clone()),
        ports,
        &registration,
        config.max_output_event_bytes,
        || {},
        &mut observed,
    )
    .await;
    ensure!(matches!(failure, Some(Failure::BudgetExhausted { .. })));
    ensure!(observed == Some(completed));
    Ok(())
}

async fn log_handoff_fixture() -> anyhow::Result<(
    Fixture,
    xolotl_kernel::RequestProcess<'static>,
    Registration,
    ExecutionOwner,
    String,
)> {
    let (fixture, _) = fixture(config(), 0, false).await?;
    let request = fixture.state.boot.request_under_owned(
        fixture.state.boot.root(),
        xolotl_types::IdentityRef::ROOT,
        &[],
    )?;
    let owner = fixture.owner().await?;
    let (registration, _stop, reference) =
        fixture
            .state
            .executions
            .register_authorized(crate::runtime::executions::Admission {
                owner: owner.clone(),
                authority: vec![("perform".into(), Path::parse("effect://jobs/stream")?)],
                authority_candidates: vec![xolotl_types::Capability::parse(
                    "perform://effect/jobs/stream#invoke",
                )?]
                .into(),
                reference: ExecutionReference {
                    execution_id: None,
                    process_id: request.id().get().to_string(),
                    program_id: "00".repeat(32),
                },
                budget: xolotl_types::BudgetSpec::default(),
                deadline: xolotl_kernel::host::system_now_millis() + 60_000,
                origin: None,
                stream_output: true,
            })?;
    registration.bind_cleanup(request.cleanup_ticket())?;
    let id = reference.execution_id.context("execution ID")?;
    Ok((fixture, request, registration, owner, id))
}

fn acquired_log_body(outcome: Outcome) -> ExecutionOutput {
    let mut output = ExecutionOutput::new(outcome, TaintSet::of(TaintSource::ModelOutput));
    output.unresolved_operations.record("acquired-log-effect");
    output
}

#[tokio::test]
async fn pending_log_drop_retains_acquired_body_in_registration_and_kernel() -> anyhow::Result<()> {
    for (outcome, status, label) in [
        (
            Outcome::Done(Value::integer(37)),
            xolotl_types::ProcessStatus::Completed,
            "done",
        ),
        (
            Outcome::Fail(Failure::BudgetExhausted {
                dim: "known.body".into(),
            }),
            xolotl_types::ProcessStatus::Failed,
            "failed",
        ),
    ] {
        let (fixture, request, registration, owner, id) = log_handoff_fixture().await?;
        let ticket = request.cleanup_ticket();
        let expected = acquired_log_body(outcome);
        let (router, ports) = streaming::ports(&fixture.state.runtime.config);
        let _sink = router.open(OperationId::new(
            request.id(),
            ExecutionId::FIRST,
            InvocationId::new(1),
            CausalPosition::new(0),
            0,
        ))?;
        let mut output = None;
        let evaluation = async {
            record_acquired_body(&fixture.state, &request, &registration, &expected);
            expected.clone()
        };
        ensure!(
            streaming::pump_log(
                evaluation,
                ports,
                &registration,
                config().max_output_event_bytes,
                || {},
                &mut output,
            )
            .now_or_never()
            .is_none()
        );
        ensure!(output == Some(expected.clone()));
        ensure!(ticket.terminal_status() == Some(status));
        ensure!(!ticket.is_complete());
        drop(request);
        drop(registration);
        let record = fixture.state.executions.get(&owner, &id)?;
        ensure!(field(&record, "outcome")?.as_str() == Some(label));
        let retained = fixture.state.executions.result(&owner, &id, |_| true)?;
        ensure!(field(&retained, "output")? == &result_value(&expected)?);
        ensure!(
            field(&retained, "unresolved_operations")?
                == &serde_value(&expected.unresolved_operations)?
        );
        fixture.state.boot.drain_cleanup().await;
        let report = ticket
            .finalization_report()
            .context("body cleanup report")?;
        ensure!(report.status == status);
        ensure!(report.taint == expected.taint);
        ensure!(report.unresolved_operations == expected.unresolved_operations);
    }
    Ok(())
}

#[tokio::test]
async fn expired_log_settlement_preserves_body_and_later_stop_cause() -> anyhow::Result<()> {
    let (fixture, request, registration, owner, id) = log_handoff_fixture().await?;
    let expected = acquired_log_body(Outcome::Done(Value::integer(37)));
    let (router, ports) = streaming::ports(&fixture.state.runtime.config);
    let _sink = router.open(OperationId::new(
        request.id(),
        ExecutionId::FIRST,
        InvocationId::new(1),
        CausalPosition::new(0),
        0,
    ))?;
    let mut output = None;
    let evaluation = async {
        record_acquired_body(&fixture.state, &request, &registration, &expected);
        expected.clone()
    };
    let mut pump = Box::pin(streaming::pump_log(
        evaluation,
        ports,
        &registration,
        config().max_output_event_bytes,
        || {},
        &mut output,
    ));
    ensure!(pump.as_mut().now_or_never().is_none());
    registration.record_stop_cause("timed_out");
    let runtime = fixture.state.boot.kernel().host_runtime();
    ensure!(
        crate::host_time::timeout_at(runtime, runtime.now(), pump.as_mut())
            .await
            .is_err()
    );
    drop(pump);
    let observed = output.context("acquired body after settlement expiry")?;
    ensure!(observed == expected);
    request.finish(&observed).await?;
    record_body(
        &fixture.state,
        &registration,
        &observed,
        Some("output_limit"),
    );
    registration.finish(true);
    let record = fixture.state.executions.get(&owner, &id)?;
    ensure!(field(&record, "outcome")?.as_str() == Some("done"));
    ensure!(field(&record, "stop_cause")?.as_str() == Some("timed_out"));
    let retained = fixture.state.executions.result(&owner, &id, |_| true)?;
    ensure!(field(&retained, "output")? == &result_value(&expected)?);
    let page = read(&fixture, &id, 0, 8).await?;
    ensure!(field(event(&page, 0)?, "outcome")?.as_str() == Some("done"));
    ensure!(field(event(&page, 0)?, "stop_cause")?.as_str() == Some("timed_out"));
    Ok(())
}

#[tokio::test]
async fn later_stop_cause_does_not_replace_first_body_or_finalization() -> anyhow::Result<()> {
    let (fixture, request, registration, owner, id) = log_handoff_fixture().await?;
    let expected = acquired_log_body(Outcome::Done(Value::integer(37)));
    request.complete_body(&expected)?;
    let first_finalization =
        crate::runtime::executions::finalization::FinalizationProjection::Omitted;
    registration.record_body(Completion {
        outcome: "done".into(),
        stop_cause: None,
        result: RetainedResult::encode(&result_value(&expected)?, config().max_result_bytes),
        unresolved_operations: expected.unresolved_operations.clone(),
        cleanup_complete: false,
        finalization: first_finalization.clone(),
    });
    for stop_cause in ["output_limit", "timed_out"] {
        registration.record_body(Completion {
            outcome: "interrupted".into(),
            stop_cause: Some(stop_cause),
            result: RetainedResult::Omitted("replacement must not be retained".into()),
            unresolved_operations: Default::default(),
            cleanup_complete: true,
            finalization: Default::default(),
        });
    }
    drop(registration);
    let record = fixture.state.executions.get(&owner, &id)?;
    ensure!(field(&record, "outcome")?.as_str() == Some("done"));
    ensure!(field(&record, "stop_cause")?.as_str() == Some("output_limit"));
    let retained = fixture.state.executions.result(&owner, &id, |_| true)?;
    ensure!(field(&retained, "output")? == &result_value(&expected)?);
    ensure!(field(&retained, "finalization")? == &first_finalization.value()?);
    ensure!(
        field(&retained, "unresolved_operations")?
            == &serde_value(&expected.unresolved_operations)?
    );
    request.finish(&expected).await?;
    Ok(())
}

#[tokio::test]
async fn output_quota_failure_preserves_in_flight_effect_identity() -> anyhow::Result<()> {
    let config = ConsoleExecutionConfig {
        max_output_events: 3,
        ..config()
    };
    let (fixture, probe) = fixture(config, 4, true).await?;
    let id = fixture.submit(expression()?, Value::integer(7)).await?;
    let record = fixture.finished(&id).await?;
    ensure!(probe.emitted.load(Ordering::SeqCst) >= 3);
    ensure!(field(&record, "outcome")?.as_str() == Some("cancelled"));
    ensure!(field(&record, "stop_cause")?.as_str() == Some("output_limit"));
    ensure!(field(&record, "unresolved_operation_count")?.as_int() == Some(1));
    let retained = fixture
        .call(ACTION_RUNTIME_EXECUTION_RESULT, id_input(&id))
        .await?
        .output
        .context("retained result")?;
    let identities = field(field(&retained, "unresolved_operations")?, "operation_ids")?
        .as_list()
        .context("reconciliation identities")?;
    ensure!(identities.len() == 1);
    let failure = field(field(&retained, "output")?, "failure")?;
    ensure!(field(failure, "code")?.as_str() == Some("internal"));
    ensure!(
        field(failure, "message")?.as_str()
            == Some("runtime execution was cancelled; effects may have occurred")
    );
    let operation = probe
        .operation
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .context("dispatched operation")?;
    ensure!(identities.first().and_then(Value::as_str) == Some(operation.to_string().as_str()));
    Ok(())
}

#[tokio::test]
async fn output_event_limit_accepts_exactly_full_log() -> anyhow::Result<()> {
    let config = ConsoleExecutionConfig {
        max_output_events: 3,
        ..config()
    };
    let (fixture, _) = fixture(config, 1, false).await?;
    let id = fixture.submit(expression()?, Value::integer(7)).await?;
    let record = fixture.finished(&id).await?;
    ensure!(field(&record, "outcome")?.as_str() == Some("done"));
    let page = read(&fixture, &id, 0, 8).await?;
    ensure!(events(&page)?.len() == 3);
    ensure!(field(event(&page, 2)?, "kind")?.as_str() == Some("terminal"));
    ensure!(field(&page, "has_more")?.as_bool() == Some(false));
    Ok(())
}

#[tokio::test]
async fn waiting_reader_revalidates_revoked_session() -> anyhow::Result<()> {
    let (fixture, _) = fixture(config(), 0, true).await?;
    let owner = fixture.owner().await?;
    let id = fixture.submit(expression()?, Value::integer(7)).await?;
    let service = fixture.service.clone();
    let token = fixture.token.clone();
    let requested_id = id.clone();
    let reader = tokio::spawn(async move {
        service
            .call(
                &token,
                Some("embedded"),
                scoped(
                    ACTION_RUNTIME_EXECUTION_OUTPUT_READ,
                    output_input(&requested_id, 0, 4, 200),
                ),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while fixture.state.calls.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    ensure!(
        !reader.is_finished(),
        "reader should still be waiting for output"
    );
    fixture
        .state
        .auth
        .logout_sid_from_source(
            &fixture.state.boot,
            fixture.token.split_once('.').context("SID")?.0,
            Some("embedded"),
        )
        .await?;
    let result = tokio::time::timeout(Duration::from_secs(1), reader).await??;
    let denied = result
        .err()
        .context("revoked reader must not receive an output page")?;
    ensure!(denied.code == ConsoleErrorCode::NotAuthenticated);
    fixture.state.executions.cancel(&owner, &id).await?;
    Ok(())
}

#[tokio::test]
async fn output_delivery_uses_current_resource_grants() -> anyhow::Result<()> {
    let (fixture, _) = fixture(config(), 1, false).await?;
    let id = fixture.submit(expression()?, Value::integer(7)).await?;
    fixture.finished(&id).await?;
    ensure!(!events(&read(&fixture, &id, 0, 4).await?)?.is_empty());

    let user_path = Path::parse("state://kernel/console/users/root")?;
    let mut user = fixture
        .state
        .state
        .read(&user_path)
        .await?
        .context("user")?
        .as_map()
        .context("user map")?
        .clone();
    user.insert("grants".into(), Value::list(vec![]))?;
    user.insert(
        "roles".into(),
        Value::list(vec![Value::string("jobs".into())]),
    )?;
    fixture
        .state
        .state
        .write_set(&user_path, Value::from(user))
        .await?;
    let role_path = Path::parse("state://kernel/console/roles/jobs")?;
    fixture
        .state
        .state
        .write_set(&role_path, map_value([("grants", Value::list(vec![]))]))
        .await?;
    let denied = fixture
        .call(
            ACTION_RUNTIME_EXECUTION_OUTPUT_READ,
            output_input(&id, 0, 4, 0),
        )
        .await
        .err()
        .context("revoked output read")?;
    ensure!(denied.code == ConsoleErrorCode::Forbidden);

    fixture
        .state
        .state
        .write_set(
            &role_path,
            map_value([(
                "grants",
                Value::list(vec![Value::string("perform://effect/jobs/**".into())]),
            )]),
        )
        .await?;
    ensure!(!events(&read(&fixture, &id, 0, 4).await?)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn forget_and_expiry_release_reserved_log_capacity() -> anyhow::Result<()> {
    let config = ConsoleExecutionConfig {
        max_output_event_bytes: 1024,
        max_output_bytes_per_execution: 4096,
        max_output_bytes_total: 4096,
        retention_ms: 500,
        ..config()
    };
    let (fixture, _) = fixture(config, 1, false).await?;
    let first = fixture.submit(expression()?, Value::integer(1)).await?;
    fixture.finished(&first).await?;
    ensure!(
        fixture
            .submit(expression()?, Value::integer(2))
            .await
            .is_err()
    );
    fixture
        .call(ACTION_RUNTIME_EXECUTION_FORGET, id_input(&first))
        .await?;
    ensure!(
        fixture
            .call(
                ACTION_RUNTIME_EXECUTION_OUTPUT_READ,
                output_input(&first, 1, 2, 0)
            )
            .await
            .is_err()
    );
    let second = fixture.submit(expression()?, Value::integer(2)).await?;
    fixture.finished(&second).await?;
    tokio::time::sleep(Duration::from_millis(550)).await;
    let expired = fixture
        .call(
            ACTION_RUNTIME_EXECUTION_OUTPUT_READ,
            output_input(&second, 1, 2, 0),
        )
        .await
        .err()
        .context("expired output cursor")?;
    ensure!(expired.code == ConsoleErrorCode::BadRequest);
    ensure!(expired.message.contains("expired"));
    let third = fixture.submit(expression()?, Value::integer(3)).await?;
    fixture.finished(&third).await?;
    Ok(())
}
