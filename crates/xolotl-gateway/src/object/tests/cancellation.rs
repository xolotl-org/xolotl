use super::ports::{Gate, ProbeStore};
use super::*;
use crate::{
    GatewayBudgetCharge, GatewayCancelRequest, GatewayRequestState, GatewayStreamDirection,
    GatewayStreamOpenRequest, SubmitOptions,
};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use xolotl_kernel::{
    Driver, DriverContext, DriverError, DriverOutput, FactSink, KernelBuilder, MethodSpec,
};
use xolotl_state::{
    Backend, InMemoryBackend, StateBoundedRead, StateBoundedWrite, StateMutation, StateRead,
    StateResult, StateWrite,
};
use xolotl_types::{MethodId, OutputMode, Path, ProcessId, ProcessStatus, Purity, TaintedValue};

struct ReceiptCasState {
    inner: InMemoryBackend,
    gate: Arc<Gate>,
    armed: AtomicBool,
    pause_after_commit: bool,
    fail_consume_after_commit: AtomicBool,
    fail_append_after_commit: AtomicBool,
    fail_append_before_commit: AtomicBool,
    preparation_port_calls: AtomicUsize,
}

impl StateRead for ReceiptCasState {
    type Read<'a> = <InMemoryBackend as StateRead>::Read<'a>;

    fn read_tainted<'a>(&'a self, path: &'a Path) -> Self::Read<'a> {
        self.preparation_port_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.read_tainted(path)
    }
}

impl xolotl_state::StateQuery for ReceiptCasState {
    type Query<'a> = <InMemoryBackend as xolotl_state::StateQuery>::Query<'a>;

    fn query<'a>(&'a self, query: &'a xolotl_state::StateScan) -> Self::Query<'a> {
        xolotl_state::StateQuery::query(&self.inner, query)
    }
}

impl StateBoundedRead for ReceiptCasState {
    type BoundedRead<'a> = <InMemoryBackend as StateBoundedRead>::BoundedRead<'a>;

    fn read_tainted_bounded<'a>(
        &'a self,
        path: &'a Path,
        max_encoded_bytes: NonZeroUsize,
    ) -> Self::BoundedRead<'a> {
        self.preparation_port_calls.fetch_add(1, Ordering::Relaxed);
        self.inner.read_tainted_bounded(path, max_encoded_bytes)
    }
}

impl StateWrite for ReceiptCasState {
    type Write<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>>;

    fn mutate<'a>(&'a self, path: &'a Path, mutation: StateMutation) -> Self::Write<'a> {
        self.preparation_port_calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(self.inner.mutate(path, mutation))
    }
}

impl StateBoundedWrite for ReceiptCasState {
    type BoundedWrite<'a> =
        Pin<Box<dyn Future<Output = StateResult<xolotl_state::StateCommit>> + Send + 'a>>;

    fn compare_set_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        value: TaintedValue,
        limit: NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(async move {
            let consumes_receipt = value
                .value
                .as_map()
                .and_then(|map| map.get("used_by"))
                .and_then(Value::as_str)
                .is_some();
            let appends_object = value.value.as_map()
                .and_then(|map| map.get("committed_items"))
                .is_some_and(|items| matches!(items.view(), xolotl_types::ValueView::List(items) if !items.is_empty()))
                && !consumes_receipt;
            if consumes_receipt && self.fail_consume_after_commit.swap(false, Ordering::AcqRel) {
                self.inner
                    .compare_set_bounded(path, expected, value, limit)
                    .await?;
                return Err(xolotl_state::StateError::Backend(
                    "lost consumption CAS response".into(),
                )
                .into());
            }
            if appends_object && self.fail_append_after_commit.swap(false, Ordering::AcqRel) {
                self.inner
                    .compare_set_bounded(path, expected, value, limit)
                    .await?;
                return Err(
                    xolotl_state::StateError::Backend("lost append CAS response".into()).into(),
                );
            }
            if appends_object && self.fail_append_before_commit.swap(false, Ordering::AcqRel) {
                return Err(xolotl_state::StateError::Backend(
                    "append CAS verdict unavailable".into(),
                )
                .into());
            }
            if consumes_receipt && self.armed.swap(false, Ordering::AcqRel) {
                if self.pause_after_commit {
                    let commit = self
                        .inner
                        .compare_set_bounded(path, expected, value, limit)
                        .await?;
                    self.gate
                        .enter()
                        .await
                        .map_err(|failure| failure.with_taint(&commit.taint))?;
                    Ok(commit)
                } else {
                    self.gate.enter().await?;
                    self.inner
                        .compare_set_bounded(path, expected, value, limit)
                        .await
                }
            } else {
                self.inner
                    .compare_set_bounded(path, expected, value, limit)
                    .await
            }
        })
    }

    fn compare_delete_bounded<'a>(
        &'a self,
        path: &'a Path,
        expected: Option<Value>,
        taint: TaintSet,
        limit: NonZeroUsize,
    ) -> Self::BoundedWrite<'a> {
        Box::pin(
            self.inner
                .compare_delete_bounded(path, expected, taint, limit),
        )
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
    fixture_with_faults(pause_after_commit, false, false, false).await
}

async fn fixture_with_faults(
    pause_after_commit: bool,
    fail_consume_after_commit: bool,
    fail_append_after_commit: bool,
    fail_append_before_commit: bool,
) -> anyhow::Result<(Fixture, Arc<Gate>, Arc<AtomicUsize>)> {
    let (fixture, gate, calls, _) = fixture_with_ports(
        pause_after_commit,
        fail_consume_after_commit,
        fail_append_after_commit,
        fail_append_before_commit,
    )
    .await?;
    Ok((fixture, gate, calls))
}

async fn fixture_with_ports(
    pause_after_commit: bool,
    fail_consume_after_commit: bool,
    fail_append_after_commit: bool,
    fail_append_before_commit: bool,
) -> anyhow::Result<(Fixture, Arc<Gate>, Arc<AtomicUsize>, Arc<ReceiptCasState>)> {
    let gate = Gate::new();
    let state = Arc::new(ReceiptCasState {
        inner: InMemoryBackend::new(),
        gate: gate.clone(),
        armed: AtomicBool::new(true),
        pause_after_commit,
        fail_consume_after_commit: AtomicBool::new(fail_consume_after_commit),
        fail_append_after_commit: AtomicBool::new(fail_append_after_commit),
        fail_append_before_commit: AtomicBool::new(fail_append_before_commit),
        preparation_port_calls: AtomicUsize::new(0),
    });
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(
            Backend::new()
                .with_read(state.clone())
                .with_query(state.clone())
                .with_bounded_read(state.clone())
                .with_write(state.clone())
                .with_bounded_write(state.clone()),
        )
        .with_fact_sink(FactSink::in_memory().0)
        .build(),
    ));
    let calls = Arc::new(AtomicUsize::new(0));
    let fixture = Fixture::with_boot(
        boot,
        MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        ),
        Arc::new(CountingEcho(calls.clone())),
    )
    .await?;
    Ok((fixture, gate, calls, state))
}

fn fill_preparation_capacity(fixture: &Fixture) -> anyhow::Result<Vec<crate::GatewayPreparation>> {
    let mut owners = Vec::new();
    for _ in 0..=fixture
        .gateway
        .profile_snapshot()
        .limits
        .max_in_flight_requests
    {
        match fixture.gateway.prepare_submission(
            &fixture.session,
            crate::GatewaySubmissionHead::direct_input("echo"),
            None,
        ) {
            Ok(owner) => owners.push(owner),
            Err(GatewayError::LimitExceeded(_)) => return Ok(owners),
            Err(error) => return Err(error.into()),
        }
    }
    bail!("preparation did not enforce its configured capacity")
}

#[tokio::test]
async fn rejected_preparation_does_not_touch_idempotency_or_object_ports() -> anyhow::Result<()> {
    let (mut fixture, _receipt_gate, calls, state) =
        fixture_with_ports(false, false, false, false).await?;
    let (_ticket, response) = fixture
        .upload(b"reject before preparation ports", None, false)
        .await?;
    let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
    fixture.install_probe(probe.clone());
    let owners = fill_preparation_capacity(&fixture)?;
    let initial_port_calls = state.preparation_port_calls.load(Ordering::Relaxed);
    let mut submission =
        fixture.direct_input_with_provenance("echo", response.item, response.provenance)?;
    submission.options.idempotency_key = Some("rejected-before-reservation".into());
    ensure!(matches!(
        fixture.gateway.submit(&fixture.session, submission).await,
        Err(GatewayError::LimitExceeded(_))
    ));
    ensure!(state.preparation_port_calls.load(Ordering::Relaxed) == initial_port_calls);
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
    ensure!(calls.load(Ordering::Acquire) == 0);
    ensure!(fixture.gateway.requests.inner.lock().entries.is_empty());
    drop(owners);
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn blocked_metadata_holds_admission_and_drop_preserves_pending_reservation()
-> anyhow::Result<()> {
    let (mut fixture, _receipt_gate, calls, state) =
        fixture_with_ports(false, false, false, false).await?;
    let (_ticket, response) = fixture
        .upload(b"preparation is in flight", None, false)
        .await?;
    let metadata_gate = Gate::new();
    let mut probe = ProbeStore::new(fixture.files.clone());
    probe.metadata_gate = Some(metadata_gate.clone());
    let probe = Arc::new(probe);
    fixture.install_probe(probe.clone());
    let mut owners = fill_preparation_capacity(&fixture)?;
    drop(owners.pop().context("missing preparation capacity")?);
    let mut submission =
        fixture.direct_input_with_provenance("echo", response.item, response.provenance)?;
    submission.options.idempotency_key = Some("dropped-during-preparation".into());
    let mut pending = Box::pin(fixture.gateway.submit(&fixture.session, submission.clone()));
    tokio::select! {
        ready = metadata_gate.wait() => ready?,
        result = &mut pending => bail!("submission did not pause in metadata: {result:?}"),
    }
    let initial_port_calls = state.preparation_port_calls.load(Ordering::Relaxed);
    let rejected = submission.clone().with_options(SubmitOptions {
        idempotency_key: Some("independent-rejected-preparation".into()),
        expected_request_scope: submission.options.expected_request_scope.clone(),
        ..SubmitOptions::default()
    });
    ensure!(matches!(
        fixture.gateway.submit(&fixture.session, rejected).await,
        Err(GatewayError::LimitExceeded(_))
    ));
    ensure!(state.preparation_port_calls.load(Ordering::Relaxed) == initial_port_calls);
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 1);
    drop(pending);
    ensure!(fixture.gateway.requests.inner.lock().global_running == owners.len());
    ensure!(fixture.gateway.requests.inner.lock().entries.is_empty());
    ensure!(
        matches!(fixture.gateway.submit(&fixture.session, submission).await,
        Err(GatewayError::LimitExceeded(message)) if message.contains("idempotent result is unsettled"))
    );
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 1);
    ensure!(calls.load(Ordering::Acquire) == 0);
    drop(owners);
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn foreign_preparation_is_rejected_before_state_and_object_ports() -> anyhow::Result<()> {
    let (origin, _origin_gate, _origin_calls) = fixture(false).await?;
    let (mut other, _other_gate, calls, state) =
        fixture_with_ports(false, false, false, false).await?;
    let (_ticket, response) = other.upload(b"foreign preparation", None, false).await?;
    let probe = Arc::new(ProbeStore::new(other.files.clone()));
    other.install_probe(probe.clone());
    let mut head = crate::GatewaySubmissionHead::direct_input("echo");
    head.options.idempotency_key = Some("foreign-preparation".into());
    head.options.expected_request_scope = Some(crate::tests::test_request_scope(
        &origin.gateway,
        &origin.session,
        "echo",
    )?);
    let owner = origin
        .gateway
        .prepare_submission(&origin.session, head, None)?;
    let initial_port_calls = state.preparation_port_calls.load(Ordering::Relaxed);
    ensure!(
        matches!(other.gateway.submit_prepared(owner, response.item, Some(response.provenance)).await,
        Err(GatewayError::Rejected(message)) if message.contains("another gateway runtime"))
    );
    ensure!(state.preparation_port_calls.load(Ordering::Relaxed) == initial_port_calls);
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
    ensure!(calls.load(Ordering::Acquire) == 0);
    ensure!(origin.gateway.requests.inner.lock().global_running == 0);
    ensure!(other.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn expired_preparation_releases_capacity_before_touching_ports() -> anyhow::Result<()> {
    let (mut fixture, _receipt_gate, calls, state) =
        fixture_with_ports(false, false, false, false).await?;
    let (_ticket, response) = fixture.upload(b"expired preparation", None, false).await?;
    let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
    fixture.install_probe(probe.clone());
    let mut head = crate::GatewaySubmissionHead::direct_input("echo");
    head.options.idempotency_key = Some("expired-preparation".into());
    head.options.expected_request_scope = Some(crate::tests::test_request_scope(
        &fixture.gateway,
        &fixture.session,
        "echo",
    )?);
    head.server_deadline = Some(
        fixture
            .gateway
            .deadline_after(std::time::Duration::from_millis(100))?,
    );
    let owner = fixture
        .gateway
        .prepare_submission(&fixture.session, head, None)?;
    let initial_port_calls = state.preparation_port_calls.load(Ordering::Relaxed);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    ensure!(
        matches!(fixture.gateway.submit_prepared(owner, response.item, Some(response.provenance)).await,
        Err(GatewayError::Rejected(message)) if message.contains("deadline"))
    );
    ensure!(state.preparation_port_calls.load(Ordering::Relaxed) == initial_port_calls);
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
    ensure!(calls.load(Ordering::Acquire) == 0);
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    Ok(())
}

#[tokio::test]
async fn unknown_append_result_is_confirmed_only_by_its_persisted_operation_id()
-> anyhow::Result<()> {
    let (fixture, _gate, _calls) = fixture_with_faults(false, false, true, false).await?;
    let ticket = fixture.issue(true).await?;
    let mut upload = fixture.begin(&ticket, None).await?;
    upload.write(b"known operation").await?;
    let response = upload.commit(GatewayObjectKind::Blob).await?;
    let record = fixture.record(ticket.ticket_id()).await?;
    ensure!(record.committed_items.len() == 1);
    ensure!(record.committed_items[0].item == response.item);
    ensure!(record.committed_items[0].append_ids.len() == 1);
    Ok(())
}

#[tokio::test]
async fn missing_append_operation_id_preserves_unknown_result_even_when_content_was_published()
-> anyhow::Result<()> {
    let (fixture, _gate, _calls) = fixture_with_faults(false, false, false, true).await?;
    let ticket = fixture.issue(true).await?;
    let mut upload = fixture.begin(&ticket, None).await?;
    upload.write(b"unresolved append").await?;
    ensure!(matches!(
        upload.commit(GatewayObjectKind::Blob).await,
        Err(GatewayError::Indeterminate(_))
    ));
    ensure!(!fixture.record(ticket.ticket_id()).await?.is_committed());
    let blob = xolotl_types::BlobRef {
        hash: content_digest(b"unresolved append"),
        size: b"unresolved append".len() as u64,
        mime: None,
    };
    ensure!(fixture.gateway.objects.metadata(&blob).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn unknown_consumption_result_never_dispatches_driver_or_releases_pending_identity()
-> anyhow::Result<()> {
    let (fixture, _gate, calls) = fixture_with_faults(false, true, false, false).await?;
    let (ticket, response) = fixture.upload(b"unknown consume", None, true).await?;
    let submission =
        fixture.direct_input_with_provenance("echo", response.item.clone(), response.provenance)?;
    ensure!(matches!(
        fixture
            .gateway
            .submit(&fixture.session, submission.clone())
            .await,
        Err(GatewayError::Indeterminate(_))
    ));
    ensure!(calls.load(Ordering::Acquire) == 0);
    ensure!(fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission)
            .await
            .is_err()
    );
    ensure!(calls.load(Ordering::Acquire) == 0);
    Ok(())
}

fn stream_submission(fixture: &Fixture) -> anyhow::Result<GatewaySubmission> {
    Ok(GatewaySubmission::input_stream(
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
    .with_options(SubmitOptions {
        idempotency_key: Some("cancelled-object-stream".into()),
        expected_request_scope: Some(crate::tests::test_request_scope(
            &fixture.gateway,
            &fixture.session,
            "echo",
        )?),
        ..SubmitOptions::default()
    }))
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
    ensure!(fixture.boot.kernel().processes().status(process) == Some(ProcessStatus::Running));
    ensure!(fixture.boot.kernel().handles().len() > initial_handles);
    ensure!(
        !fixture
            .boot
            .kernel()
            .processes()
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
    let ticket = fixture.boot.cleanup_ticket(process)?;
    ensure!(fixture.boot.kernel().processes().status(process) == Some(status));
    ensure!(fixture.boot.kernel().handles().len() == initial_handles);
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
            .kernel()
            .processes()
            .attached_grants(process)
            .is_empty()
    );
    ensure!(fixture.boot.kernel().handles().len() == initial_handles);
    ensure!(ticket.terminal_status() == Some(status));
    ensure!(ticket.is_complete(), "request cleanup remains incomplete");
    ensure!(
        fixture.boot.resume_cleanup(&ticket).await? == xolotl_kernel::CleanupProgress::Completed
    );
    let rows = fixture
        .boot
        .kernel()
        .state()
        .query(&xolotl_state::StateScan::new(Path::parse(&format!(
            "state://kernel/process/{}",
            process.get(),
        ))?))
        .await?;
    ensure!(
        rows.entries.is_empty(),
        "ordinary request cleanup persisted generic lifecycle rows"
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
            let initial_handles = fixture.boot.kernel().handles().len();
            let mut submission = Box::pin(async {
                if streamed {
                    let start = fixture
                        .gateway
                        .accept_input_stream_submission(
                            &fixture.session,
                            stream_submission(&fixture)?,
                        )
                        .await?;
                    let stream = start;
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
                            fixture.direct_input_with_provenance(
                                "echo",
                                response.item.clone(),
                                response.provenance.clone(),
                            )?,
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
            ensure!(
                fixture.record(ticket.ticket_id()).await?.used_by.is_some() == pause_after_commit
            );
            drop(submission);
            assert_finalized(&fixture, process, initial_handles, ProcessStatus::Cancelled).await?;
            ensure!(calls.load(Ordering::Acquire) == 0);
            ensure!(
                fixture.record(ticket.ticket_id()).await?.used_by.is_some() == pause_after_commit,
                "cancellation changed receipt consumption"
            );
            let fresh_submission_result = fixture
                .gateway
                .submit(
                    &fixture.session,
                    fixture.direct_input_with_provenance(
                        "echo",
                        response.item.clone(),
                        response.provenance.clone(),
                    )?,
                )
                .await;
            if pause_after_commit {
                ensure!(fresh_submission_result.is_err());
                ensure!(calls.load(Ordering::Acquire) == 0);
            } else {
                ensure!(fresh_submission_result?.output.outcome == Outcome::Done(response.item));
                ensure!(calls.load(Ordering::Acquire) == 1);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn dropping_an_accepted_input_stream_releases_its_request_owner() -> anyhow::Result<()> {
    let (fixture, _gate, calls) = fixture(false).await?;
    let initial_handles = fixture.boot.kernel().handles().len();
    let start = fixture
        .gateway
        .accept_input_stream_submission(&fixture.session, stream_submission(&fixture)?)
        .await?;
    let stream = start;
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
        let initial_handles = fixture.boot.kernel().handles().len();
        let start = fixture
            .gateway
            .accept_input_stream_submission(&fixture.session, stream_submission(&fixture)?)
            .await?;
        let mut stream = start;
        let process = running_request(&fixture, initial_handles)?;
        if expired {
            stream.deadline = Some(fixture.boot.kernel().host_runtime().now());
        } else {
            ensure!(fixture.gateway.cancel(
                &fixture.session,
                GatewayCancelRequest {
                    submission_id: stream.accepted.submission_id.clone(),
                    trace_root: stream.accepted.trace_root.clone(),
                    reason: None,
                }
            )?);
        }
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
        ensure!(!fixture.record(ticket.ticket_id()).await?.used_by.is_some());
        ensure!(calls.load(Ordering::Acquire) == 0);
        assert_finalized(&fixture, process, initial_handles, ProcessStatus::Cancelled).await?;
        gate.release();
        ensure!(
            fixture
                .gateway
                .submit(
                    &fixture.session,
                    fixture.direct_input_with_provenance(
                        "echo",
                        response.item.clone(),
                        response.provenance,
                    )?
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
    let initial_handles = fixture.boot.kernel().handles().len();
    let deadline = now_millis().saturating_add(200);
    let mut submission =
        fixture.direct_input_with_provenance("echo", response.item, response.provenance)?;
    submission.options.deadline_ms = Some(u64::try_from(deadline)?);
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
    ensure!(!fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    ensure!(calls.load(Ordering::Acquire) == 0);
    {
        let requests = fixture.gateway.requests.inner.lock();
        ensure!(requests.entries.is_empty());
        ensure!(requests.global_running == 0);
        ensure!(requests.budget_running == GatewayBudgetCharge::default());
    }
    ensure!(fixture.boot.kernel().handles().len() == initial_handles);
    ensure!(fixture.boot.drain_cleanup().await.failures.is_empty());
    Ok(())
}

#[tokio::test]
async fn another_gateway_cannot_complete_or_fail_a_foreign_input_stream() -> anyhow::Result<()> {
    for complete in [false, true] {
        let (origin, _origin_gate, origin_calls) = fixture(false).await?;
        let (other, _other_gate, other_calls) = fixture(false).await?;
        let origin_handles = origin.boot.kernel().handles().len();
        let other_handles = other.boot.kernel().handles().len();
        let origin_stream = origin
            .gateway
            .accept_input_stream_submission(&origin.session, stream_submission(&origin)?)
            .await?;
        let other_stream = other
            .gateway
            .accept_input_stream_submission(&other.session, stream_submission(&other)?)
            .await?;
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
