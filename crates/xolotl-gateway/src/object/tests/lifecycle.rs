use super::ports::{Gate, ProbeStore, WriteReply};
use super::*;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::Barrier;
use xolotl_types::{Path, ResourceName};

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
        ensure!(!fixture.record(ticket.ticket_id()).await?.committed);
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
        ensure!(!fixture.record(ticket.ticket_id()).await?.committed);
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
    ensure!(!fixture.record(ticket.ticket_id()).await?.committed);
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
    let response = match (left, right) {
        (Ok(response), Err(_)) | (Err(_), Ok(response)) => response,
        other => bail!("expected one receipt CAS winner: {other:?}"),
    };
    ensure!(fixture.record(ticket.ticket_id()).await?.committed);
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
        direct_input_with_provenance("echo", response.item.clone(), response.provenance);
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
            fixture.gateway.submit(&fixture.session, submission),
            release,
        )
    })
    .await?;
    released?;
    ensure!(
        left.is_ok() != right.is_ok(),
        "expected one admission winner: {left:?}, {right:?}"
    );
    ensure!(fixture.record(ticket.ticket_id()).await?.used);
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
                .kernel
                .state
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
        ensure!(!fixture.record(ticket.ticket_id()).await?.committed);
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
                .kernel
                .state
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
                direct_input_with_provenance("echo", response.item, response.provenance)
            ),
            intervene,
        );
        intervention?;
        ensure!(result.is_err());
        ensure!(!fixture.record(ticket.ticket_id()).await?.used);
    }
    Ok(())
}
