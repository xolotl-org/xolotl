use super::ports::{Gate, ProbeStore, WriteReply};
use super::*;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::Barrier;
use xolotl_kernel::{FactSink, KernelBuilder};
use xolotl_state::{Backend, InMemoryBackend};
use xolotl_types::{Path, ResourceName, TaintedValue};

impl Fixture {
    pub(super) fn direct_input_with_provenance(
        &self,
        surface_id: &str,
        payload: Value,
        provenance: GatewayPayloadProvenance,
    ) -> anyhow::Result<GatewaySubmission> {
        let mut submission =
            crate::tests::direct_input_with_provenance(surface_id, payload, provenance);
        submission.options.expected_request_scope = Some(crate::tests::test_request_scope(
            &self.gateway,
            &self.session,
            surface_id,
        )?);
        Ok(submission)
    }
}

#[tokio::test]
async fn upload_ticket_lookup_rejects_oversized_record_before_ticket_decode() -> anyhow::Result<()>
{
    let fixture = Fixture::new().await?;
    let ticket = fixture.issue(true).await?;
    let state = fixture.boot.kernel().state();
    let path = upload_ticket_path(ticket.ticket_id())?;
    state
        .write_set(
            &path,
            Value::string("x".repeat(ticket::MAX_TICKET_ENCODED_BYTES)),
        )
        .await?;
    let error = match ticket::StoredTicket::load(state, ticket.ticket_id()).await {
        Ok(_) => anyhow::bail!("oversized ticket was accepted"),
        Err(error) => error,
    };
    ensure!(
        matches!(error, GatewayError::Rejected(message) if message.contains("current state record exceeds encoded byte budget")),
        "ticket lookup must use bounded State reads"
    );
    Ok(())
}

#[tokio::test]
async fn upload_ticket_update_rejects_oversized_concurrent_replacement() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let ticket = fixture.issue(true).await?;
    let state = fixture.boot.kernel().state();
    let path = upload_ticket_path(ticket.ticket_id())?;
    let mut stored = ticket::StoredTicket::load(state, ticket.ticket_id()).await?;
    stored.ticket.expires_at_ms += 1;
    let replacement = Value::string("x".repeat(ticket::MAX_TICKET_ENCODED_BYTES));
    state.write_set(&path, replacement.clone()).await?;

    let error = match state
        .write_cas_bounded(
            &path,
            Some(ticket.to_value()?),
            stored.ticket.to_value()?,
            ticket::ticket_state_budget(),
        )
        .await
    {
        Ok(_) => anyhow::bail!("oversized concurrent ticket was decoded by CAS"),
        Err(error) => error,
    };
    ensure!(
        error
            .to_string()
            .contains("current state record exceeds encoded byte budget")
    );
    ensure!(state.read(&path).await? == Some(replacement));
    Ok(())
}

#[tokio::test]
async fn upload_ticket_issue_requires_bounded_point_read() -> anyhow::Result<()> {
    let state = Arc::new(InMemoryBackend::new());
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(
            Backend::new()
                .with_read(state.clone())
                .with_write(state.clone())
                .with_query(state),
        )
        .with_fact_sink(FactSink::in_memory().0)
        .build(),
    ));
    let fixture = Fixture::with_boot(
        boot,
        xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        ),
        Arc::new(xolotl_kernel::EchoDriver),
    )
    .await?;
    let request = IssueObjectUploadTicketRequest {
        surface_id: "echo".into(),
        submission_token: None,
        modality: GatewayModality::Bytes,
        expected_size: None,
        expected_digest: None,
        allowed_media_types: Vec::new(),
        expires_in_ms: Some(60_000),
        single_use: true,

        max_objects: None,
        max_total_bytes: None,
        max_record_bytes: None,
    };
    let mut stale_session = fixture.session.clone();
    stale_session.profile_name.push_str("-other");
    let unauthorized = match fixture
        .gateway
        .issue_object_upload_ticket(&stale_session, request.clone())
        .await
    {
        Ok(_) => anyhow::bail!("invalid session must be checked first"),
        Err(error) => error,
    };
    ensure!(matches!(
        unauthorized,
        GatewayError::Rejected(message) if message.contains("different profile snapshot")
    ));
    let error = match fixture
        .gateway
        .issue_object_upload_ticket(&fixture.session, request)
        .await
    {
        Ok(_) => anyhow::bail!("a ticket without bounded lookup must not be issued"),
        Err(error) => error,
    };
    ensure!(matches!(
        error,
        GatewayError::Rejected(message) if message.contains("require bounded state reads")
    ));
    Ok(())
}

#[tokio::test]
async fn upload_ticket_issue_requires_bounded_conditional_write() -> anyhow::Result<()> {
    let state = Arc::new(InMemoryBackend::new());
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(
            Backend::new()
                .with_read(state.clone())
                .with_bounded_read(state.clone())
                .with_write(state.clone())
                .with_query(state),
        )
        .with_fact_sink(FactSink::in_memory().0)
        .build(),
    ));
    let fixture = Fixture::with_boot(
        boot,
        xolotl_kernel::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Pure,
            xolotl_kernel::MethodSpec::UNARY_ASYNC,
        ),
        Arc::new(xolotl_kernel::EchoDriver),
    )
    .await?;
    let error = match fixture.issue(true).await {
        Ok(_) => anyhow::bail!("a ticket without bounded mutation must not be issued"),
        Err(error) => error,
    };
    ensure!(
        error
            .to_string()
            .contains("require bounded state reads and writes")
    );
    Ok(())
}

#[tokio::test]
async fn upload_ticket_maintenance_removes_expired_and_consumed_records_only() -> anyhow::Result<()>
{
    let fixture = Fixture::new().await?;
    let state = fixture.boot.kernel().state();
    let expired = fixture.issue(true).await?;
    let expired_path = upload_ticket_path(expired.ticket_id())?;
    let mut expired_record = fixture.record(expired.ticket_id()).await?;
    expired_record.expires_at_ms = now_millis() - 1;
    state
        .write_set(&expired_path, expired_record.to_value()?)
        .await?;

    let (consumed, response) = fixture.upload(b"consumed content", None, true).await?;
    fixture
        .gateway
        .submit(
            &fixture.session,
            fixture.direct_input_with_provenance(
                "echo",
                response.item.clone(),
                response.provenance,
            )?,
        )
        .await?;
    ensure!(
        fixture
            .record(consumed.ticket_id())
            .await?
            .used_by
            .is_some()
    );
    let live = fixture.issue(true).await?;

    let mut cursor = None;
    let mut removed = 0;
    loop {
        let batch = ticket::maintain_upload_tickets_batch(state, cursor, now_millis()).await?;
        removed += batch.removed;
        cursor = batch.next;
        if cursor.is_none() {
            break;
        }
    }
    ensure!(removed == 2);
    ensure!(state.read(&expired_path).await?.is_none());
    ensure!(
        state
            .read(&upload_ticket_path(consumed.ticket_id())?)
            .await?
            .is_none()
    );
    ensure!(
        state
            .read(&upload_ticket_path(live.ticket_id())?)
            .await?
            .is_some()
    );
    ensure!(
        fixture
            .gateway
            .objects
            .metadata(response.item.backing_blob().context("missing blob")?)
            .await?
            .is_some(),
        "ticket cleanup must not delete shared object content"
    );
    Ok(())
}

#[tokio::test]
async fn upload_ticket_maintenance_stale_snapshot_cannot_delete_live_replacement()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let state = fixture.boot.kernel().state();
    let ticket = fixture.issue(true).await?;
    let path = upload_ticket_path(ticket.ticket_id())?;
    let mut expired = fixture.record(ticket.ticket_id()).await?;
    expired.expires_at_ms = now_millis() - 1;
    let stale = expired.to_value()?;
    state.write_set(&path, stale.clone()).await?;
    let replacement = ticket.to_value()?;
    state.write_set(&path, replacement.clone()).await?;

    ensure!(
        !ticket::prune_upload_ticket_entry(
            state,
            &path,
            TaintedValue::pristine(stale),
            now_millis(),
        )
        .await?,
        "compare-delete must lose against a replacement"
    );
    ensure!(state.read(&path).await? == Some(replacement));
    Ok(())
}

#[tokio::test]
async fn upload_ticket_maintenance_rejects_oversized_concurrent_replacement() -> anyhow::Result<()>
{
    let fixture = Fixture::new().await?;
    let state = fixture.boot.kernel().state();
    let ticket = fixture.issue(true).await?;
    let path = upload_ticket_path(ticket.ticket_id())?;
    let mut expired = fixture.record(ticket.ticket_id()).await?;
    expired.expires_at_ms = now_millis() - 1;
    let stale = expired.to_value()?;
    state.write_set(&path, stale.clone()).await?;
    let replacement = Value::string("x".repeat(ticket::MAX_TICKET_ENCODED_BYTES));
    state.write_set(&path, replacement.clone()).await?;

    let error = match ticket::prune_upload_ticket_entry(
        state,
        &path,
        TaintedValue::pristine(stale),
        now_millis(),
    )
    .await
    {
        Ok(_) => anyhow::bail!("oversized concurrent row was decoded by compare-delete"),
        Err(error) => error,
    };
    ensure!(
        matches!(error, GatewayError::Rejected(message) if message.contains("current state record exceeds encoded byte budget"))
    );
    ensure!(state.read(&path).await? == Some(replacement));
    Ok(())
}

#[tokio::test]
async fn upload_ticket_maintenance_skips_oversized_row_and_resumes_bounded_pages()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let state = fixture.boot.kernel().state();
    let oversized_path = upload_ticket_path("aaa")?;
    state
        .write_set(
            &oversized_path,
            Value::string("x".repeat(ticket::TICKET_MAINTENANCE_PAGE_BYTES + 1)),
        )
        .await?;
    let mut paths = Vec::new();
    for _ in 0..ticket::TICKET_MAINTENANCE_BATCH + 1 {
        let issued = fixture.issue(true).await?;
        let path = upload_ticket_path(issued.ticket_id())?;
        let mut record = fixture.record(issued.ticket_id()).await?;
        record.expires_at_ms = now_millis() - 1;
        state.write_set(&path, record.to_value()?).await?;
        paths.push(path);
    }

    let skipped = ticket::maintain_upload_tickets_batch(state, None, now_millis()).await?;
    ensure!(skipped.examined == 1 && skipped.skipped_oversized == 1);
    ensure!(skipped.removed == 0);
    let first = ticket::maintain_upload_tickets_batch(state, skipped.next, now_millis()).await?;
    ensure!(first.examined <= ticket::TICKET_MAINTENANCE_BATCH);
    ensure!(first.removed == ticket::TICKET_MAINTENANCE_BATCH);
    let last = ticket::maintain_upload_tickets_batch(state, first.next, now_millis()).await?;
    ensure!(last.removed == 1 && last.next.is_none());
    ensure!(state.read(&oversized_path).await?.is_some());
    for path in paths {
        ensure!(state.read(&path).await?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn upload_ticket_maintenance_runs_while_gateway_is_idle() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let ticket = fixture.issue(true).await?;
    let path = upload_ticket_path(ticket.ticket_id())?;
    let state = fixture.boot.kernel().state();
    let mut record = fixture.record(ticket.ticket_id()).await?;
    record.expires_at_ms = now_millis() - 1;
    state.write_set(&path, record.to_value()?).await?;

    tokio::time::timeout(Duration::from_secs(7), async {
        loop {
            if state.read(&path).await?.is_none() {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    Ok(())
}

#[tokio::test]
async fn upload_ticket_maintenance_restarts_scan_after_bad_cursor() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let state = fixture.boot.kernel().state();
    let ticket = fixture.issue(true).await?;
    let path = upload_ticket_path(ticket.ticket_id())?;
    let mut record = fixture.record(ticket.ticket_id()).await?;
    record.expires_at_ms = now_millis() - 1;
    state.write_set(&path, record.to_value()?).await?;

    let mut cursor = Some(xolotl_state::StateCursor(vec![0xff]));
    ensure!(
        ticket::maintain_upload_tickets_step(state, &mut cursor, now_millis())
            .await
            .is_err()
    );
    ensure!(cursor.is_none(), "failed scan retained an invalid cursor");
    let retry = ticket::maintain_upload_tickets_step(state, &mut cursor, now_millis()).await?;
    ensure!(retry.removed == 1);
    ensure!(state.read(&path).await?.is_none());
    Ok(())
}

async fn write_and_commit(
    fixture: &Fixture,
    ticket: &GatewayObjectUploadTicket,
    bytes: &[u8],
) -> Result<CommitObjectUploadResponse, GatewayError> {
    let mut upload = fixture.begin(ticket, None).await?;
    upload.write(bytes).await?;
    upload.commit(GatewayObjectKind::Blob).await
}

#[tokio::test]
async fn empty_and_read_only_stores_reject_uploads_explicitly() -> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    for store in [
        ObjectStore::new(),
        ObjectStore::new().with_read(Arc::new(fixture.files.clone())),
    ] {
        fixture.gateway.objects = store;
        let ticket = fixture.issue(true).await?;
        ensure!(matches!(fixture.begin(&ticket, None).await,
                Err(GatewayError::Rejected(message)) if message.contains("object.write")));
        ensure!(!fixture.record(ticket.ticket_id()).await?.is_committed());
        ensure!(fixture.files.pending_uploads() == 0);
    }
    Ok(())
}

#[tokio::test]
async fn partial_writes_remain_bounded_and_commit_complete_content() -> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let mut probe = ProbeStore::new(fixture.files.clone());
    probe.write_reply = WriteReply::Partial(997);
    let probe = Arc::new(probe);
    fixture.install_probe(probe.clone());
    let bytes = vec![61; 40_001];
    let (_, response) = fixture.upload(&bytes, None, false).await?;
    ensure!(probe.writes.load(Ordering::Relaxed) > 40);
    ensure!(probe.max_write_bytes.load(Ordering::Relaxed) <= UPLOAD_CHUNK_BYTES.get());
    ensure!(probe.aborts.load(Ordering::Relaxed) == 0);
    ensure!(fixture.files.pending_uploads() == 0);
    let mut received = vec![0; bytes.len()];
    let read = fixture
        .gateway
        .objects
        .read_chunk(
            response.item.backing_blob().context("missing blob")?,
            0,
            &mut received,
        )
        .await?;
    ensure!(read.end && read.bytes_read == bytes.len() && received == bytes);
    Ok(())
}

#[tokio::test]
async fn invalid_write_acknowledgments_and_storage_failures_release_staging() -> anyhow::Result<()>
{
    let mut fixture = Fixture::new().await?;
    for (reply, commit_error) in [
        (WriteReply::Zero, false),
        (WriteReply::Excessive, false),
        (WriteReply::WrongOffset, false),
        (WriteReply::Error, false),
        (WriteReply::Full, true),
    ] {
        let mut probe = ProbeStore::new(fixture.files.clone());
        probe.write_reply = reply;
        probe.commit_error = commit_error;
        let probe = Arc::new(probe);
        fixture.install_probe(probe.clone());
        let ticket = fixture.issue(true).await?;
        ensure!(
            write_and_commit(&fixture, &ticket, b"failed upload")
                .await
                .is_err()
        );
        ensure!(probe.aborts.load(Ordering::Relaxed) == 0);
        ensure!(fixture.files.pending_uploads() == 0);
        ensure!(!fixture.record(ticket.ticket_id()).await?.is_committed());
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_upload_drops_staging_owner_without_publishing_receipt() -> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let gate = Gate::new();
    let mut probe = ProbeStore::new(fixture.files.clone());
    probe.write_gate = Some(gate.clone());
    let probe = Arc::new(probe);
    fixture.install_probe(probe.clone());
    let ticket = fixture.issue(true).await?;
    let mut upload = Box::pin(write_and_commit(&fixture, &ticket, b"cancel upload"));
    tokio::select! {
        result = &mut upload => bail!("upload did not wait: {result:?}"),
        ready = gate.wait() => ready?,
    }
    ensure!(fixture.files.pending_uploads() == 1);
    drop(upload);
    ensure!(fixture.files.pending_uploads() == 0);
    ensure!(
        probe.aborts.load(Ordering::Relaxed) == 0,
        "cancellation spawned async abort"
    );
    ensure!(!fixture.record(ticket.ticket_id()).await?.is_committed());
    Ok(())
}

#[tokio::test]
async fn concurrent_commits_publish_one_receipt_and_preserve_shared_content() -> anyhow::Result<()>
{
    let mut fixture = Fixture::new().await?;
    let mut probe = ProbeStore::new(fixture.files.clone());
    probe.commit_barrier = Some(Arc::new(Barrier::new(2)));
    fixture.install_probe(Arc::new(probe));
    let ticket = fixture.issue(true).await?;
    let (left, right) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            write_and_commit(&fixture, &ticket, b"shared commit"),
            write_and_commit(&fixture, &ticket, b"shared commit"),
        )
    })
    .await?;
    let left = left?;
    let right = right?;
    ensure!(left.item == right.item);
    let response = left;
    ensure!(
        fixture
            .record(ticket.ticket_id())
            .await?
            .committed_items
            .len()
            == 1
    );
    ensure!(fixture.record(ticket.ticket_id()).await?.is_committed());
    ensure!(fixture.files.pending_uploads() == 0);
    let mut bytes = vec![0; response.size as usize];
    fixture
        .gateway
        .objects
        .read_chunk(
            response.item.backing_blob().context("missing blob")?,
            0,
            &mut bytes,
        )
        .await?;
    ensure!(bytes == b"shared commit");
    Ok(())
}

#[tokio::test]
async fn concurrent_single_use_submissions_have_one_admission_winner() -> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let (ticket, response) = fixture.upload(b"one submission", None, true).await?;
    let gate = Gate::new();
    let mut probe = ProbeStore::new(fixture.files.clone());
    probe.metadata_gate = Some(gate.clone());
    fixture.install_probe(Arc::new(probe));
    let submission =
        fixture.direct_input_with_provenance("echo", response.item.clone(), response.provenance)?;
    let other_submission = submission.clone().with_options(crate::SubmitOptions {
        idempotency_key: Some("other-concurrent-object-submit".into()),
        expected_request_scope: submission.options.expected_request_scope.clone(),
        ..crate::SubmitOptions::default()
    });
    let release = async {
        gate.wait().await?;
        gate.wait().await?;
        gate.release();
        gate.release();
        Ok::<_, anyhow::Error>(())
    };
    let (left, right, released) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            fixture.gateway.submit(&fixture.session, submission.clone()),
            fixture.gateway.submit(&fixture.session, other_submission),
            release,
        )
    })
    .await?;
    released?;
    ensure!(
        left.is_ok() != right.is_ok(),
        "expected one admission winner: {left:?}, {right:?}"
    );
    ensure!(fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    Ok(())
}

async fn expire_after_gate(
    fixture: &Fixture,
    ticket: &GatewayObjectUploadTicket,
    gate: &Gate,
) -> anyhow::Result<()> {
    gate.wait().await?;
    let expiry = fixture.record(ticket.ticket_id()).await?.expires_at_ms;
    let remaining = expiry.saturating_sub(now_millis()).max(0) as u64;
    tokio::time::sleep(Duration::from_millis(remaining + 2)).await;
    gate.release();
    Ok(())
}

fn reload_profile(fixture: &Fixture) -> anyhow::Result<()> {
    let mut profile = echo_profile(ResourceName::new(Path::parse("effect://echo/say")?))?;
    profile.revision = fixture.gateway.profile_rev().saturating_add(1);
    fixture.gateway.replace_profile(profile)?;
    Ok(())
}

#[tokio::test]
async fn delayed_upload_rechecks_expiry_and_active_profile_before_receipt_publish()
-> anyhow::Result<()> {
    for expire in [false, true] {
        let mut fixture = Fixture::new().await?;
        let gate = Gate::new();
        let mut probe = ProbeStore::new(fixture.files.clone());
        probe.write_gate = Some(gate.clone());
        fixture.install_probe(Arc::new(probe));
        let ticket = fixture.issue(true).await?;
        if expire {
            let mut record = fixture.record(ticket.ticket_id()).await?;
            record.expires_at_ms = now_millis() + 200;
            fixture
                .boot
                .kernel()
                .state()
                .write_set(&upload_ticket_path(ticket.ticket_id())?, record.to_value()?)
                .await?;
        }
        let intervene = async {
            if expire {
                expire_after_gate(&fixture, &ticket, &gate).await?;
            } else {
                gate.wait().await?;
                reload_profile(&fixture)?;
                gate.release();
            }
            Ok::<_, anyhow::Error>(())
        };
        let (result, intervention) =
            tokio::join!(write_and_commit(&fixture, &ticket, b"delayed"), intervene,);
        intervention?;
        ensure!(
            result.is_err(),
            "delayed upload published a receipt, expire={expire}"
        );
        ensure!(!fixture.record(ticket.ticket_id()).await?.is_committed());
        ensure!(fixture.files.pending_uploads() == 0);
    }
    Ok(())
}

#[tokio::test]
async fn delayed_metadata_rechecks_expiry_and_profile_without_consuming_receipt()
-> anyhow::Result<()> {
    for expire in [false, true] {
        let mut fixture = Fixture::new().await?;
        let (ticket, response) = fixture.upload(b"delayed metadata", None, true).await?;
        if expire {
            let mut record = fixture.record(ticket.ticket_id()).await?;
            record.expires_at_ms = now_millis() + 200;
            fixture
                .boot
                .kernel()
                .state()
                .write_set(&upload_ticket_path(ticket.ticket_id())?, record.to_value()?)
                .await?;
        }
        let gate = Gate::new();
        let mut probe = ProbeStore::new(fixture.files.clone());
        probe.metadata_gate = Some(gate.clone());
        fixture.install_probe(Arc::new(probe));
        let intervene = async {
            if expire {
                expire_after_gate(&fixture, &ticket, &gate).await?;
            } else {
                gate.wait().await?;
                reload_profile(&fixture)?;
                gate.release();
            }
            Ok::<_, anyhow::Error>(())
        };
        let (result, intervention) = tokio::join!(
            fixture.gateway.submit(
                &fixture.session,
                fixture.direct_input_with_provenance("echo", response.item, response.provenance)?
            ),
            intervene,
        );
        intervention?;
        ensure!(result.is_err());
        ensure!(!fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    }
    Ok(())
}
