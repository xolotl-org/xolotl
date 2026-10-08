use super::*;
use anyhow::{Context, ensure};
use futures_util::FutureExt;
use std::{future, time::Duration};
use xolotl_kernel::{Bootstrap, RequestProcess, stream::StreamSink};
use xolotl_types::{
    CausalPosition, CompletionOrigin, ExecutionId, IdentityRef, InvocationId, ProcessStatus,
};

fn fixture() -> anyhow::Result<(Arc<ConsoleState>, RequestProcess<'static>)> {
    let boot = Arc::new(Bootstrap::in_memory());
    let request = boot.request_under_owned(boot.root(), IdentityRef::ROOT, &[])?;
    Ok((
        ConsoleState::shared(
            boot,
            std::sync::Arc::new(crate::session_store::MemoryConsoleSessionStore::new(
                crate::session_store::ConsoleSessionPolicy::default(),
            )),
        )?,
        request,
    ))
}

fn body(outcome: Outcome) -> ExecutionOutput {
    let mut output = ExecutionOutput::new(outcome, TaintSet::author());
    output.unresolved_operations.record("known-stream-effect");
    output
}

fn terminal_port(
    request: &RequestProcess<'_>,
    output: &ExecutionOutput,
) -> anyhow::Result<mpsc::Receiver<Port>> {
    let (router, ports) = ports(&crate::ConsoleRuntimeConfig::default());
    let sink = router.open(OperationId::new(
        request.id(),
        ExecutionId::FIRST,
        InvocationId::new(1),
        CausalPosition::new(0),
        0,
    ))?;
    sink.close(xolotl_kernel::stream::StreamEnd {
        outcome: match &output.outcome {
            Outcome::Done(_) | Outcome::Short(_) => Ok(()),
            Outcome::Fail(failure) => Err(failure.clone()),
        },
        taint: output.taint.clone(),
        origin: CompletionOrigin::CurrentAttempt,
    });
    Ok(ports)
}

fn field<'a>(value: &'a Value, name: &str) -> anyhow::Result<&'a Value> {
    value
        .as_map()
        .and_then(|fields| fields.get(name))
        .with_context(|| format!("missing {name}"))
}

#[tokio::test]
async fn rejected_terminal_delivery_retains_body_and_finishes_request() -> anyhow::Result<()> {
    for outcome in [
        Outcome::Done(Value::integer(37)),
        Outcome::Fail(Failure::Custom {
            kind: "body_failure".into(),
            message: "known body failure".into(),
        }),
    ] {
        let (state, request) = fixture()?;
        let ticket = request.cleanup_ticket();
        let expected = body(outcome);
        let ports = terminal_port(&request, &expected)?;
        let (events, receiver) = mpsc::channel(1);
        drop(receiver);
        let mut output = None;
        let delivery = pump(
            future::ready(expected.clone()),
            ports,
            &events,
            16 * 1024,
            &request,
            &mut output,
        )
        .await;
        ensure!(matches!(
            delivery.as_ref().err().map(ConsoleError::kind),
            Some(ConsoleError::Runtime(Failure::Cancelled))
        ));
        let output = output.context("acquired body")?;
        ensure!(output.outcome == expected.outcome);
        ensure!(output.taint == expected.taint);
        ensure!(output.unresolved_operations == expected.unresolved_operations);
        ensure!(!ticket.is_complete());
        let deadline = state
            .boot
            .kernel()
            .host_runtime()
            .deadline_after(Duration::from_secs(30))
            .context("cleanup deadline")?;
        let error = finish_delivery(&state, request, output, delivery, deadline)
            .await
            .err()
            .context("delivery error")?;
        ensure!(matches!(
            error.kind(),
            ConsoleError::Runtime(Failure::Cancelled)
        ));
        let failure = ConsoleFailure::from(error);
        let retained = failure.runtime_completion.context("retained completion")?;
        ensure!(field(&retained, "body")? == &executions::result_value(&expected)?);
        ensure!(field(&retained, "cleanup_failure")?.is_null());
        ensure!(failure.unresolved_operations.as_deref() == Some(&expected.unresolved_operations));
        ensure!(ticket.is_complete());
        let report = ticket.finalization_report().context("cleanup report")?;
        ensure!(report.taint == expected.taint);
        ensure!(report.unresolved_operations == expected.unresolved_operations);
        ensure!(
            report.status
                == if expected.outcome.is_success() {
                    ProcessStatus::Completed
                } else {
                    ProcessStatus::Failed
                }
        );
    }
    Ok(())
}

#[tokio::test]
async fn oversized_terminal_delivery_retains_body_and_original_error() -> anyhow::Result<()> {
    let (state, request) = fixture()?;
    let ticket = request.cleanup_ticket();
    let expected = body(Outcome::Done(Value::integer(37)));
    let ports = terminal_port(&request, &expected)?;
    let (events, _receiver) = mpsc::channel(1);
    let mut output = None;
    let delivery = pump(
        future::ready(expected.clone()),
        ports,
        &events,
        0,
        &request,
        &mut output,
    )
    .await;
    let original = delivery
        .as_ref()
        .err()
        .context("size rejection")?
        .to_string();
    ensure!(matches!(
        delivery.as_ref().err().map(ConsoleError::kind),
        Some(ConsoleError::Operation(_))
    ));
    let deadline = state
        .boot
        .kernel()
        .host_runtime()
        .deadline_after(Duration::from_secs(30))
        .context("cleanup deadline")?;
    let error = finish_delivery(
        &state,
        request,
        output.context("acquired body")?,
        delivery,
        deadline,
    )
    .await
    .err()
    .context("delivery error")?;
    ensure!(error.kind().to_string() == original);
    let failure = ConsoleFailure::from(error);
    let retained = failure.runtime_completion.context("retained completion")?;
    ensure!(field(&retained, "body")? == &executions::result_value(&expected)?);
    ensure!(ticket.is_complete());
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Completed));
    Ok(())
}

#[tokio::test]
async fn pending_delivery_drop_preserves_body_cleanup_metadata() -> anyhow::Result<()> {
    for (outcome, status) in [
        (Outcome::Done(Value::integer(37)), ProcessStatus::Completed),
        (
            Outcome::Fail(Failure::BudgetExhausted {
                dim: "test.body".into(),
            }),
            ProcessStatus::Failed,
        ),
    ] {
        let (state, request) = fixture()?;
        let ticket = request.cleanup_ticket();
        let expected = body(outcome);
        let ports = terminal_port(&request, &expected)?;
        let (events, _receiver) = mpsc::channel(1);
        events.try_send(ConsoleEvent::Runtime {
            event: Value::null(),
        })?;
        let mut output = None;
        ensure!(
            pump(
                future::ready(expected.clone()),
                ports,
                &events,
                16 * 1024,
                &request,
                &mut output,
            )
            .now_or_never()
            .is_none()
        );
        ensure!(output.as_ref().context("acquired body")?.outcome == expected.outcome);
        ensure!(ticket.terminal_status() == Some(status));
        ensure!(!ticket.is_complete());
        ensure!(ticket.finalization_report().is_none());
        drop(request);
        state.boot.drain_cleanup().await;
        ensure!(ticket.is_complete());
        let report = ticket.finalization_report().context("cleanup report")?;
        ensure!(report.status == status);
        ensure!(report.taint == expected.taint);
        ensure!(report.unresolved_operations == expected.unresolved_operations);
    }
    Ok(())
}

#[tokio::test]
async fn delivery_timeout_keeps_body_and_independent_pending_cleanup() -> anyhow::Result<()> {
    let (state, request) = fixture()?;
    let ticket = request.cleanup_ticket();
    let expected = body(Outcome::Done(Value::integer(37)));
    let ports = terminal_port(&request, &expected)?;
    let (events, _receiver) = mpsc::channel(1);
    events.try_send(ConsoleEvent::Runtime {
        event: Value::null(),
    })?;
    let mut output = None;
    ensure!(
        pump(
            future::ready(expected.clone()),
            ports,
            &events,
            16 * 1024,
            &request,
            &mut output,
        )
        .now_or_never()
        .is_none()
    );
    let deadline = state.boot.kernel().host_runtime().now();
    let original = Failure::Timeout;
    ensure!(matches!(
        delivery_timeout(output.as_ref()).kind(),
        ConsoleError::Runtime(Failure::Timeout)
    ));
    let error = finish_delivery(
        &state,
        request,
        output.context("acquired body")?,
        Err(ConsoleError::Runtime(original.clone())),
        deadline,
    )
    .await
    .err()
    .context("delivery timeout")?;
    ensure!(matches!(error.kind(), ConsoleError::Runtime(failure) if failure == &original));
    let failure = ConsoleFailure::from(error);
    let retained = failure.runtime_completion.context("retained completion")?;
    ensure!(field(&retained, "body")? == &executions::result_value(&expected)?);
    ensure!(!field(&retained, "cleanup_failure")?.is_null());
    ensure!(failure.finalization_error.is_some());
    ensure!(failure.unresolved_operations.as_deref() == Some(&expected.unresolved_operations));
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Completed));
    ensure!(!ticket.is_complete());
    state.boot.drain_cleanup().await;
    ensure!(ticket.is_complete());
    ensure!(
        ticket
            .finalization_report()
            .context("cleanup report")?
            .status
            == ProcessStatus::Completed
    );
    Ok(())
}

#[tokio::test]
async fn delivery_drop_before_body_acquisition_still_cancels_request() -> anyhow::Result<()> {
    ensure!(
        matches!(delivery_timeout(None).kind(), ConsoleError::Runtime(Failure::OutcomeUnknown { reason, .. }) if reason == "settlement_timeout")
    );
    let (state, request) = fixture()?;
    let ticket = request.cleanup_ticket();
    let (events, _receiver) = mpsc::channel(1);
    let (port_sender, ports) = mpsc::channel(1);
    let mut output = None;
    ensure!(
        pump(
            future::pending(),
            ports,
            &events,
            16 * 1024,
            &request,
            &mut output,
        )
        .now_or_never()
        .is_none()
    );
    ensure!(output.is_none());
    drop(port_sender);
    drop(request);
    state.boot.drain_cleanup().await;
    ensure!(ticket.is_complete());
    ensure!(ticket.terminal_status() == Some(ProcessStatus::Cancelled));
    Ok(())
}
