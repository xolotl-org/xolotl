use super::ports::{Gate, ProbeStore};
use super::*;
use crate::{
    GatewayBudgetCharge, GatewayCancelRequest, GatewayInputStreamStart, GatewayRequestState,
    GatewayStreamDirection, GatewayStreamOpenRequest, SubmitOptions,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use xolotl_kernel::{
    Driver, DriverContext, DriverError, DriverOutput, FactSink, Kernel, MethodSpec,
};
use xolotl_state::{Backend, InMemoryBackend, StateMutation, StateRead, StateResult, StateWrite};
use xolotl_types::{MethodId, OutputMode, Path, ProcessId, ProcessStatus, Purity};

struct ReceiptCasState {
    inner: InMemoryBackend,
    gate: Arc<Gate>,
    armed: AtomicBool,
    pause_after_commit: bool,
}

impl StateRead for ReceiptCasState {
    type Read<'a> = <InMemoryBackend as StateRead>::Read<'a>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        self.inner.read_tainted(path)
    }
}

impl StateWrite for ReceiptCasState {
    type Write<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        Box::pin(async move {
            let consumes_receipt = matches!(
                &mutation,
                StateMutation::CompareSet { value, .. }
                    if value.value.as_map().and_then(|map| map.get("used")) == Some(&Value::boolean(true))
            );
            if consumes_receipt && self.armed.swap(false, Ordering::AcqRel) {
                if self.pause_after_commit {
                    let commit = self.inner.mutate(path, mutation).await?;
                    self.gate
                        .enter()
                        .await
                        .map_err(|failure| failure.with_taint(&commit.taint))?;
                    Ok(commit)
                } else {
                    self.gate.enter().await?;
                    self.inner.mutate(path, mutation).await
                }
            } else {
                self.inner.mutate(path, mutation).await
            }
        })
    }
}

struct CountingEcho(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl Driver for CountingEcho {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        _output: OutputMode,
        _context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Ok(DriverOutput::new(Outcome::Done(input)))
    }
}

async fn fixture(
    pause_after_commit: bool,
) -> anyhow::Result<(Fixture, Arc<Gate>, Arc<AtomicUsize>)> {
    let gate = Gate::new();
    let state = Arc::new(ReceiptCasState {
        inner: InMemoryBackend::new(),
        gate: gate.clone(),
        armed: AtomicBool::new(true),
        pause_after_commit,
    });
    let boot = Arc::new(Bootstrap::from_kernel(Kernel::with_backends(
        Backend::new().with_read(state.clone()).with_write(state),
        FactSink::in_memory().0,
    )));
    let calls = Arc::new(AtomicUsize::new(0));
    let fixture = Fixture::with_boot(
        boot,
        MethodSpec::unary_async("invoke", Purity::Pure),
        Arc::new(CountingEcho(calls.clone())),
    )
    .await?;
    Ok((fixture, gate, calls))
}

fn stream_submission() -> GatewaySubmission {
    GatewaySubmission::input_stream(
        "echo",
        GatewayStreamOpenRequest {
            stream_id: "cancelled-object-input".into(),
            direction: GatewayStreamDirection::ClientToKernel,
            modality: GatewayModality::Bytes,
            item_schema_id: String::new(),
            max_inline_item_bytes: 16,
            max_items: Some(4),
            max_bytes: Some(64),
        },
    )
}

fn running_request(fixture: &Fixture, initial_handles: usize) -> anyhow::Result<ProcessId> {
    let requests = fixture.gateway.requests.inner.lock();
    ensure!(requests.global_running == 1);
    ensure!(requests.budget_running.inflight_ops == 1);
    let entry = requests
        .entries
        .values()
        .find(|entry| entry.state == GatewayRequestState::Running)
        .context("missing running request")?;
    let process = entry.request_process;
    ensure!(fixture.boot.kernel.processes.status(process) == Some(ProcessStatus::Running));
    ensure!(fixture.boot.kernel.handles.read().len() > initial_handles);
    ensure!(
        !fixture
            .boot
            .kernel
            .processes
            .attached_grants(process)
            .is_empty()
    );
    Ok(process)
}

async fn assert_finalized(
    fixture: &Fixture,
    process: ProcessId,
    initial_handles: usize,
    status: ProcessStatus,
) -> anyhow::Result<()> {
    ensure!(fixture.boot.kernel.processes.status(process) == Some(status));
    ensure!(fixture.boot.kernel.handles.read().len() == initial_handles);
    {
        let requests = fixture.gateway.requests.inner.lock();
        ensure!(requests.global_running == 0);
        ensure!(requests.principal_running.is_empty());
        ensure!(requests.surface_running.is_empty());
        ensure!(requests.risk_running.is_empty());
        ensure!(requests.budget_reservations.is_empty());
        ensure!(requests.budget_running == GatewayBudgetCharge::default());
        ensure!(
            requests
                .entries
                .values()
                .all(|entry| entry.state != GatewayRequestState::Running)
        );
    }
    let cleanup = fixture.boot.drain_cleanup().await;
    ensure!(cleanup.failures.is_empty(), "{cleanup:?}");
    ensure!(
        fixture
            .boot
            .kernel
            .processes
            .attached_grants(process)
            .is_empty()
    );
    ensure!(fixture.boot.kernel.handles.read().len() == initial_handles);
    let execution = fixture
        .boot
        .kernel
        .processes
        .lifecycle_execution(process)
        .context("missing request lifecycle identity")?;
    let marker = Path::parse(&format!(
        "state://kernel/process/{}/{}/finalized",
        process.get(),
        execution.get(),
    ))?;
    ensure!(
        fixture.boot.kernel.state.read(&marker).await?.is_some(),
        "missing lifecycle completion marker: {marker}"
    );
    Ok(())
}

#[tokio::test]
async fn cancelling_ticket_cas_releases_request_resources_before_and_after_storage_commit()
-> anyhow::Result<()> {
    for streamed in [false, true] {
        for pause_after_commit in [false, true] {
            let (fixture, gate, calls) = fixture(pause_after_commit).await?;
            let (ticket, response) = fixture.upload(b"cancel at receipt CAS", None, true).await?;
            let initial_handles = fixture.boot.kernel.handles.read().len();
            let mut submission = Box::pin(async {
                if streamed {
                    let start = fixture
                        .gateway
                        .accept_input_stream_submission(&fixture.session, stream_submission())
                        .await?;
                    let GatewayInputStreamStart::Accepted(stream) = start else {
                        bail!("unexpected stream replay");
                    };
                    Ok::<_, anyhow::Error>(
                        fixture
                            .gateway
                            .complete_input_stream_submission(
                                *stream,
                                response.item.clone(),
                                Some(response.provenance.clone()),
                            )
                            .await?,
                    )
                } else {
                    Ok(fixture
                        .gateway
                        .submit(
                            &fixture.session,
                            direct_input_with_provenance(
                                "echo",
                                response.item.clone(),
                                response.provenance.clone(),
                            ),
                        )
                        .await?)
                }
            });
            tokio::select! {
                result = &mut submission => bail!("submission did not wait for receipt CAS: {result:?}"),
                ready = gate.wait() => ready?,
            }
            let process = running_request(&fixture, initial_handles)?;
            ensure!(calls.load(Ordering::Acquire) == 0);
            ensure!(fixture.record(ticket.ticket_id()).await?.used == pause_after_commit);
            drop(submission);
            assert_finalized(&fixture, process, initial_handles, ProcessStatus::Cancelled).await?;
            ensure!(calls.load(Ordering::Acquire) == 0);
            ensure!(
                fixture.record(ticket.ticket_id()).await?.used == pause_after_commit,
                "cancellation changed receipt consumption"
            );
            let retry = fixture
                .gateway
                .submit(
                    &fixture.session,
                    direct_input_with_provenance(
                        "echo",
                        response.item.clone(),
                        response.provenance.clone(),
                    ),
                )
                .await;
            if pause_after_commit {
                ensure!(retry.is_err());
                ensure!(calls.load(Ordering::Acquire) == 0);
            } else {
                ensure!(retry?.output.outcome == Outcome::Done(response.item));
                ensure!(calls.load(Ordering::Acquire) == 1);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn dropping_an_accepted_input_stream_releases_its_request_owner() -> anyhow::Result<()> {
    let (fixture, _gate, calls) = fixture(false).await?;
    let initial_handles = fixture.boot.kernel.handles.read().len();
    let start = fixture
        .gateway
        .accept_input_stream_submission(&fixture.session, stream_submission())
        .await?;
    let GatewayInputStreamStart::Accepted(stream) = start else {
        bail!("unexpected stream replay");
    };
    let process = running_request(&fixture, initial_handles)?;
    drop(stream);
    assert_finalized(&fixture, process, initial_handles, ProcessStatus::Cancelled).await?;
    ensure!(calls.load(Ordering::Acquire) == 0);
    Ok(())
}

#[tokio::test]
async fn terminated_input_stream_does_not_start_receipt_consumption() -> anyhow::Result<()> {
    for expired in [false, true] {
        let (fixture, gate, calls) = fixture(false).await?;
        let (ticket, response) = fixture.upload(b"known stopped stream", None, true).await?;
        let initial_handles = fixture.boot.kernel.handles.read().len();
        let start = fixture
            .gateway
            .accept_input_stream_submission(&fixture.session, stream_submission())
            .await?;
        let GatewayInputStreamStart::Accepted(mut stream) = start else {
            bail!("unexpected stream replay");
        };
        let process = running_request(&fixture, initial_handles)?;
        let status = if expired {
            stream.deadline = Some(tokio::time::Instant::now());
            ProcessStatus::Failed
        } else {
            ensure!(fixture.gateway.cancel(
                &fixture.session,
                GatewayCancelRequest {
                    submission_id: stream.accepted.submission_id.clone(),
                    trace_root: stream.accepted.trace_root.clone(),
                    reason: None,
                }
            )?);
            ProcessStatus::Cancelled
        };
        let result = tokio::select! {
            result = fixture.gateway.complete_input_stream_submission(
                *stream, response.item.clone(), Some(response.provenance.clone()),
            ) => result,
            ready = gate.wait() => {
                ready?;
                bail!("known stopped input stream attempted receipt CAS");
            }
        };
        ensure!(result.is_err());
        ensure!(!fixture.record(ticket.ticket_id()).await?.used);
        ensure!(calls.load(Ordering::Acquire) == 0);
        assert_finalized(&fixture, process, initial_handles, status).await?;
        gate.release();
        ensure!(
            fixture
                .gateway
                .submit(
                    &fixture.session,
                    direct_input_with_provenance(
                        "echo",
                        response.item.clone(),
                        response.provenance,
                    )
                )
                .await?
                .output
                .outcome
                == Outcome::Done(response.item)
        );
        ensure!(calls.load(Ordering::Acquire) == 1);
    }
    Ok(())
}

#[tokio::test]
async fn direct_input_expiring_during_metadata_does_not_start_receipt_consumption()
-> anyhow::Result<()> {
    let (mut fixture, receipt_gate, calls) = fixture(false).await?;
    let (ticket, response) = fixture
        .upload(b"deadline before admission", None, true)
        .await?;
    let metadata_gate = Gate::new();
    let mut probe = ProbeStore::new(fixture.files.clone());
    probe.metadata_gate = Some(metadata_gate.clone());
    fixture.install_probe(Arc::new(probe));
    let initial_handles = fixture.boot.kernel.handles.read().len();
    let deadline = now_millis().saturating_add(200);
    let submission = direct_input_with_provenance("echo", response.item, response.provenance)
        .with_options(SubmitOptions {
            deadline_ms: Some(u64::try_from(deadline)?),
            ..SubmitOptions::default()
        });
    let expire = async {
        metadata_gate.wait().await?;
        let remaining = deadline.saturating_sub(now_millis()).max(0) as u64;
        tokio::time::sleep(std::time::Duration::from_millis(remaining + 2)).await;
        metadata_gate.release();
        Ok::<_, anyhow::Error>(())
    };
    let submitted = async {
        tokio::select! {
            result = fixture.gateway.submit(&fixture.session, submission) => Ok::<_, anyhow::Error>(result),
            ready = receipt_gate.wait() => {
                ready?;
                bail!("expired direct input attempted receipt CAS");
            }
        }
    };
    let (result, expired) = tokio::join!(submitted, expire);
    expired?;
    ensure!(result?.is_err());
    ensure!(!fixture.record(ticket.ticket_id()).await?.used);
    ensure!(calls.load(Ordering::Acquire) == 0);
    let process = fixture
        .gateway
        .requests
        .inner
        .lock()
        .entries
        .values()
        .next()
        .context("missing rejected request")?
        .request_process;
    assert_finalized(&fixture, process, initial_handles, ProcessStatus::Failed).await?;
    Ok(())
}

#[tokio::test]
async fn another_gateway_cannot_complete_or_fail_a_foreign_input_stream() -> anyhow::Result<()> {
    for complete in [false, true] {
        let (origin, _origin_gate, origin_calls) = fixture(false).await?;
        let (other, _other_gate, other_calls) = fixture(false).await?;
        let origin_handles = origin.boot.kernel.handles.read().len();
        let other_handles = other.boot.kernel.handles.read().len();
        let GatewayInputStreamStart::Accepted(origin_stream) = origin
            .gateway
            .accept_input_stream_submission(&origin.session, stream_submission())
            .await?
        else {
            bail!("unexpected origin stream replay");
        };
        let GatewayInputStreamStart::Accepted(other_stream) = other
            .gateway
            .accept_input_stream_submission(&other.session, stream_submission())
            .await?
        else {
            bail!("unexpected other stream replay");
        };
        let origin_process = running_request(&origin, origin_handles)?;
        let other_process = running_request(&other, other_handles)?;
        ensure!(
            origin_process == other_process,
            "fixture must use colliding process ids"
        );
        let rejected = if complete {
            other
                .gateway
                .complete_input_stream_submission(*origin_stream, Value::null(), None)
                .await
                .is_err()
        } else {
            other
                .gateway
                .fail_input_stream_submission(*origin_stream, "foreign stream")
                .await
                .is_err()
        };
        ensure!(rejected);
        assert_finalized(
            &origin,
            origin_process,
            origin_handles,
            ProcessStatus::Cancelled,
        )
        .await?;
        ensure!(running_request(&other, other_handles)? == other_process);
        ensure!(origin_calls.load(Ordering::Acquire) == 0);
        ensure!(other_calls.load(Ordering::Acquire) == 0);
        let completed = other
            .gateway
            .complete_input_stream_submission(*other_stream, Value::null(), None)
            .await?;
        ensure!(completed.output.outcome == Outcome::Done(Value::null()));
        ensure!(other_calls.load(Ordering::Acquire) == 1);
    }
    Ok(())
}
