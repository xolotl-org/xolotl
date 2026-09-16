use super::ports::{Gate, ProbeStore, WriteReply};
use super::*;
use std::sync::atomic::Ordering;
use std::time::Duration;
use xolotl_types::{DType, FrameKind, Path, ResourceName};

fn ticket_request(modality: GatewayModality) -> IssueObjectUploadTicketRequest {
    IssueObjectUploadTicketRequest {
        surface_id: "echo".into(),
        submission_token: None,
        modality,
        expected_size: None,
        expected_digest: None,
        allowed_media_types: Vec::new(),
        expires_in_ms: Some(60_000),
        single_use: true,
    }
}

fn ensure_staging_empty(fixture: &Fixture) -> anyhow::Result<()> {
    ensure!(fixture.files.pending_uploads() == 0);
    ensure!(
        std::fs::read_dir(fixture._directory.path().join("staging"))?
            .next()
            .is_none(),
        "upload left staging files"
    );
    Ok(())
}

async fn ensure_unpublished(
    fixture: &Fixture,
    ticket: &GatewayObjectUploadTicket,
    bytes: &[u8],
) -> anyhow::Result<()> {
    ensure_staging_empty(fixture)?;
    ensure!(!fixture.record(ticket.ticket_id()).await?.committed);
    let blob = BlobRef {
        hash: blake3::hash(bytes).to_hex().to_string(),
        size: bytes.len() as u64,
        mime: None,
    };
    ensure!(fixture.gateway.objects.metadata(&blob).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn dyn_gateway_uploads_and_reads_multimegabyte_content_with_a_reused_buffer()
-> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let mut probe = ProbeStore::new(fixture.files.clone());
    probe.write_reply = WriteReply::Partial(4093);
    let probe = Arc::new(probe);
    fixture.install_probe(probe.clone());
    let gateway: &dyn Gateway = &fixture.gateway;
    let ticket = gateway
        .issue_object_upload_ticket(&fixture.session, ticket_request(GatewayModality::Bytes))
        .await?;
    let mut upload = gateway
        .begin_object_upload(
            &fixture.session,
            BeginObjectUploadRequest {
                ticket_id: ticket.ticket_id().into(),
                media_type: Some("application/octet-stream".into()),
                submission_token: None,
            },
        )
        .await?;
    let mut buffer = [0_u8; 32 * 1024 + 13];
    let mut expected = blake3::Hasher::new();
    let mut size = 0_u64;
    for round in 0..97 {
        for (index, byte) in buffer.iter_mut().enumerate() {
            *byte = ((index * 31 + round * 17) & 0xff) as u8;
        }
        expected.update(&buffer);
        size += buffer.len() as u64;
        ensure!(upload.write(&buffer).await? == size);
    }
    let response = upload.commit(GatewayObjectKind::Blob).await?;
    let digest = expected.finalize().to_hex().to_string();
    ensure!(size > 3 * 1024 * 1024);
    ensure!(response.size == size && response.digest == digest);
    let blob = response.item.backing_blob().context("missing blob")?;
    ensure!(blob.size == size && blob.hash == digest);
    ensure!(blob.mime.as_deref() == Some("application/octet-stream"));
    ensure!(probe.max_write_bytes.load(Ordering::Relaxed) == UPLOAD_CHUNK_BYTES.get());
    ensure!(probe.writes.load(Ordering::Relaxed) > 97);
    let record = fixture.record(ticket.ticket_id()).await?;
    ensure!(record.committed && !record.used);
    ensure!(record.expected_size == Some(size));
    ensure!(record.expected_digest.as_deref() == Some(digest.as_str()));
    ensure_staging_empty(&fixture)?;

    let mut received = blake3::Hasher::new();
    let mut offset = 0_u64;
    loop {
        let read = fixture
            .gateway
            .objects
            .read_chunk(blob, offset, &mut buffer)
            .await?;
        ensure!(read.bytes_read <= buffer.len());
        ensure!(read.bytes_read > 0 || read.end, "read made no progress");
        received.update(&buffer[..read.bytes_read]);
        offset += read.bytes_read as u64;
        ensure!(offset <= size);
        ensure!(read.end == (offset == size));
        if read.end {
            break;
        }
    }
    ensure!(offset == size && received.finalize().to_hex().as_str() == digest);
    Ok(())
}

#[tokio::test]
async fn empty_upload_commits_and_explicit_abort_removes_staging() -> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
    fixture.install_probe(probe.clone());
    let ticket = fixture.issue(true).await?;
    let upload = fixture.begin(&ticket, None).await?;
    let response = upload.commit(GatewayObjectKind::Blob).await?;
    ensure!(response.size == 0);
    ensure!(response.digest == blake3::hash(b"").to_hex().as_str());
    ensure!(probe.writes.load(Ordering::Relaxed) == 0);
    ensure!(fixture.record(ticket.ticket_id()).await?.committed);
    let mut buffer = [0_u8; 17];
    let read = fixture
        .gateway
        .objects
        .read_chunk(
            response.item.backing_blob().context("missing blob")?,
            0,
            &mut buffer,
        )
        .await?;
    ensure!(read.bytes_read == 0 && read.end);
    ensure_staging_empty(&fixture)?;

    let ticket = fixture.issue(true).await?;
    let mut upload = fixture.begin(&ticket, None).await?;
    let bytes = b"explicitly abandoned bytes";
    ensure!(upload.write(bytes).await? == bytes.len() as u64);
    ensure!(fixture.files.pending_uploads() == 1);
    upload.abort().await?;
    ensure!(probe.aborts.load(Ordering::Relaxed) == 1);
    ensure_unpublished(&fixture, &ticket, bytes).await?;
    Ok(())
}

#[tokio::test]
async fn unknown_length_tensors_and_frames_receive_canonical_references_at_eof()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    for modality in [GatewayModality::Tensor, GatewayModality::SensorFrame] {
        let ticket = fixture
            .gateway
            .issue_object_upload_ticket(&fixture.session, ticket_request(modality))
            .await?;
        ensure!(ticket.expected_size.is_none() && ticket.expected_digest.is_none());
        let mut upload = fixture
            .begin(&ticket, Some("application/octet-stream"))
            .await?;
        let mut expected = blake3::Hasher::new();
        let mut size = 0_u64;
        for bytes in [b"sensor".as_slice(), b"-sample", b" bytes"] {
            expected.update(bytes);
            size += bytes.len() as u64;
            ensure!(upload.write(bytes).await? == size);
        }
        let kind = match modality {
            GatewayModality::Tensor => GatewayObjectKind::Tensor {
                dtype: DType::U8,
                shape: vec![size],
            },
            _ => GatewayObjectKind::Frame {
                ts_nanos: 23,
                kind: FrameKind::Sensor,
            },
        };
        let response = upload.commit(kind).await?;
        match (response.item.view(), modality) {
            (xolotl_types::ValueView::Tensor(tensor), GatewayModality::Tensor) => {
                ensure!(tensor.dtype == DType::U8 && tensor.shape == [size]);
            }
            (xolotl_types::ValueView::Frame(frame), GatewayModality::SensorFrame) => {
                ensure!(frame.ts_nanos == 23 && frame.kind == FrameKind::Sensor);
            }
            other => bail!("unexpected committed kind: {other:?}"),
        }
        let blob = response
            .item
            .backing_blob()
            .context("missing typed backing blob")?;
        ensure!(blob.hash == expected.finalize().to_hex().as_str() && blob.size == size);
        ensure!(blob.mime.as_deref() == Some("application/octet-stream"));
        ensure!(response.digest == blob.hash && response.size == blob.size);
        let metadata = fixture
            .gateway
            .objects
            .metadata(blob)
            .await?
            .context("typed object was not published")?;
        ensure!(metadata.blob == *blob);
        ensure!(fixture.record(ticket.ticket_id()).await?.committed);
        ensure_staging_empty(&fixture)?;
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_a_polled_write_closes_the_sink_after_partial_progress() -> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let gate = Gate::new();
    let mut probe = ProbeStore::new(fixture.files.clone());
    probe.write_reply = WriteReply::Partial(3);
    probe.write_gate = Some(gate.clone());
    let probe = Arc::new(probe);
    fixture.install_probe(probe.clone());
    let ticket = fixture.issue(true).await?;
    let mut upload = fixture.begin(&ticket, None).await?;
    let bytes = b"cancel after a stored prefix";
    drop(upload.write(bytes));
    ensure!(probe.writes.load(Ordering::Relaxed) == 0);
    ensure!(fixture.files.pending_uploads() == 1);

    gate.release();
    let mut write = Box::pin(upload.write(bytes));
    tokio::select! {
        result = &mut write => bail!("write did not wait: {result:?}"),
        ready = async {
            gate.wait().await?;
            gate.wait().await
        } => ready?,
    }
    ensure!(probe.writes.load(Ordering::Relaxed) == 2);
    ensure!(fixture.files.pending_uploads() == 1);
    drop(write);
    ensure_unpublished(&fixture, &ticket, bytes).await?;
    ensure!(probe.aborts.load(Ordering::Relaxed) == 0);
    ensure!(
        tokio::time::timeout(Duration::from_secs(1), upload.write(b"resume"))
            .await?
            .is_err(),
        "cancelled write left the sink resumable"
    );
    ensure!(upload.commit(GatewayObjectKind::Blob).await.is_err());
    ensure!(probe.writes.load(Ordering::Relaxed) == 2);
    ensure_unpublished(&fixture, &ticket, bytes).await?;
    Ok(())
}

#[tokio::test]
async fn declared_size_and_digest_mismatches_never_publish_content() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let bytes = b"three";
    for (expected_size, expected_digest, overflow) in [
        (Some(bytes.len() as u64 - 1), None, true),
        (Some(bytes.len() as u64 + 1), None, false),
        (None, Some("a".repeat(64)), false),
    ] {
        let mut request = ticket_request(GatewayModality::Bytes);
        request.expected_size = expected_size;
        request.expected_digest = expected_digest;
        let ticket = fixture
            .gateway
            .issue_object_upload_ticket(&fixture.session, request)
            .await?;
        let mut upload = fixture.begin(&ticket, None).await?;
        ensure!(upload.write(&bytes[..2]).await? == 2);
        if overflow {
            ensure!(upload.write(&bytes[2..]).await.is_err());
        } else {
            ensure!(upload.write(&bytes[2..]).await? == bytes.len() as u64);
        }
        ensure!(upload.commit(GatewayObjectKind::Blob).await.is_err());
        ensure_unpublished(&fixture, &ticket, bytes).await?;
        ensure!(
            std::fs::read_dir(fixture._directory.path().join("objects"))?
                .next()
                .is_none(),
            "invalid upload published an object"
        );
    }
    Ok(())
}

#[tokio::test]
async fn pending_writes_close_when_the_profile_changes_or_the_ticket_expires() -> anyhow::Result<()>
{
    for expire in [false, true] {
        let mut fixture = Fixture::new().await?;
        let gate = Gate::new();
        let mut probe = ProbeStore::new(fixture.files.clone());
        probe.write_gate = Some(gate.clone());
        let probe = Arc::new(probe);
        fixture.install_probe(probe.clone());
        let mut request = ticket_request(GatewayModality::Bytes);
        if expire {
            request.expires_in_ms = Some(1_000);
        }
        let ticket = fixture
            .gateway
            .issue_object_upload_ticket(&fixture.session, request)
            .await?;
        let mut upload = fixture.begin(&ticket, None).await?;
        let bytes = b"authority changed during storage";
        let intervene = async {
            gate.wait().await?;
            if expire {
                let remaining = ticket.expires_at_ms().saturating_sub(now_millis()).max(0);
                tokio::time::sleep(Duration::from_millis(remaining as u64 + 2)).await;
            } else {
                let mut profile =
                    echo_profile(ResourceName::new(Path::parse("effect://echo/say")?))?;
                profile.revision = fixture.gateway.profile_rev().saturating_add(1);
                fixture.gateway.replace_profile(profile)?;
            }
            gate.release();
            Ok::<_, anyhow::Error>(())
        };
        let (result, intervention) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(upload.write(bytes), intervene)
        })
        .await?;
        intervention?;
        ensure!(
            result.is_err(),
            "write retained stale authority, expire={expire}"
        );
        ensure_unpublished(&fixture, &ticket, bytes).await?;
        ensure!(
            tokio::time::timeout(Duration::from_secs(1), upload.write(b"resume"))
                .await?
                .is_err()
        );
        ensure!(upload.commit(GatewayObjectKind::Blob).await.is_err());
        ensure!(probe.writes.load(Ordering::Relaxed) == 1);
        ensure_unpublished(&fixture, &ticket, bytes).await?;
    }
    Ok(())
}
