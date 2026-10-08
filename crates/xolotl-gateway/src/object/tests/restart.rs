use super::*;
use crate::OpenObjectReadRequest;
use redb::TableDefinition;
use std::path::Path as FsPath;
use xolotl_kernel::{EchoDriver, FactSink, KernelBuilder, MethodSpec};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{Path, Purity, TaintedValue};

async fn reopen(
    directory: &FsPath,
) -> anyhow::Result<(GatewayRuntime, GatewaySession, ObjectStore)> {
    let state = RedbStore::open(directory.join("gateway.redb"))?;
    let boot = Arc::new(Bootstrap::from_kernel(
        KernelBuilder::new(state.state_backend().into_backend())
            .with_fact_sink(FactSink::new(Arc::new(state.fact_store()?)))
            .build(),
    ));
    let objects = FileObjectStore::open(directory.join("content"))?.into_object_store();
    let target = boot.register_effect(
        "effect://echo/say",
        &[MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(EchoDriver),
    )?;
    let gateway = GatewayRuntime::new(
        boot,
        echo_profile(target)?,
        Arc::new(crate::MemoryGatewayIdempotencyStore::default()),
    )?
    .with_object_store(objects.clone());
    let session = gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    Ok((gateway, session, objects))
}

fn open(grant: &GatewayObjectReadGrant) -> OpenObjectReadRequest {
    OpenObjectReadRequest {
        grant_id: grant.grant_id().into(),
        offset: grant.offset(),
        length: Some(grant.length()),
    }
}

#[tokio::test]
async fn multi_object_ticket_members_survive_redb_restart_and_consume_together()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let (ticket_id, first, second, provenance) = {
        let (gateway, session, _) = reopen(directory.path()).await?;
        let ticket = gateway
            .issue_object_upload_ticket(
                &session,
                IssueObjectUploadTicketRequest {
                    surface_id: "echo".into(),
                    submission_token: None,
                    modality: GatewayModality::Value,
                    expected_size: None,
                    expected_digest: None,
                    allowed_media_types: Vec::new(),
                    expires_in_ms: Some(60_000),
                    single_use: true,
                    max_objects: Some(2),
                    max_total_bytes: Some(1024),
                    max_record_bytes: None,
                },
            )
            .await?;
        let mut upload = gateway
            .begin_object_upload(
                &session,
                BeginObjectUploadRequest {
                    ticket_id: ticket.ticket_id().into(),
                    media_type: None,
                    submission_token: None,
                    expected_size: Some(3),
                    expected_digest: None,
                },
            )
            .await?;
        upload.write(b"one").await?;
        let first = upload.commit(GatewayObjectKind::Blob).await?;
        let mut upload = gateway
            .begin_object_upload(
                &session,
                BeginObjectUploadRequest {
                    ticket_id: ticket.ticket_id().into(),
                    media_type: None,
                    submission_token: None,
                    expected_size: Some(3),
                    expected_digest: None,
                },
            )
            .await?;
        upload.write(b"two").await?;
        let second = upload.commit(GatewayObjectKind::Blob).await?;
        (
            ticket.ticket_id().to_owned(),
            first.item,
            second.item,
            first.provenance,
        )
    };
    let (gateway, session, _) = reopen(directory.path()).await?;
    let value = gateway
        .boot
        .kernel()
        .state()
        .read(&upload_ticket_path(&ticket_id)?)
        .await?
        .context("ticket after restart")?;
    let record = GatewayObjectUploadTicket::from_value(&value)?;
    ensure!(record.committed_items.len() == 2);
    let payload = Value::list(vec![first, second]);
    let mut submission = direct_input_with_provenance("echo", payload.clone(), provenance);
    submission.options.expected_request_scope = Some(crate::tests::test_request_scope(
        &gateway, &session, "echo",
    )?);
    let result = gateway.submit(&session, submission).await?;
    ensure!(result.output.outcome == Outcome::Done(payload));
    Ok(())
}

#[tokio::test]
async fn expired_upload_ticket_is_reclaimed_after_redb_restart() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let ticket_id = {
        let (gateway, session, _objects) = reopen(directory.path()).await?;
        let ticket = gateway
            .issue_object_upload_ticket(
                &session,
                IssueObjectUploadTicketRequest {
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
                },
            )
            .await?;
        let path = upload_ticket_path(ticket.ticket_id())?;
        let mut record = ticket.clone();
        record.expires_at_ms = now_millis() - 1;
        gateway
            .boot
            .kernel()
            .state()
            .write_set(&path, record.to_value()?)
            .await?;
        ticket.ticket_id().to_owned()
    };
    let (gateway, _session, _objects) = reopen(directory.path()).await?;
    let state = gateway.boot.kernel().state();
    let batch = ticket::maintain_upload_tickets_batch(state, None, now_millis()).await?;
    ensure!(batch.removed == 1);
    ensure!(
        state
            .read(&upload_ticket_path(&ticket_id)?)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn oversized_provenance_header_does_not_hide_preceding_ticket_cleanup() -> anyhow::Result<()>
{
    let directory = tempfile::tempdir()?;
    let database = directory.path().join("gateway.redb");
    let (first, second) = {
        let (gateway, session, _) = reopen(directory.path()).await?;
        let ticket = gateway
            .issue_object_upload_ticket(
                &session,
                IssueObjectUploadTicketRequest {
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
                },
            )
            .await?;
        let state = gateway.boot.kernel().state();
        let original = upload_ticket_path(ticket.ticket_id())?;
        let mut expired = ticket;
        expired.expires_at_ms = now_millis() - 1;
        let first = upload_ticket_path("aaa")?;
        expired.ticket_id = "aaa".into();
        state.write_set(&first, expired.to_value()?).await?;
        let second = upload_ticket_path("bbb")?;
        expired.ticket_id = "bbb".into();
        state.write_set(&second, expired.to_value()?).await?;
        state.write_delete(&original).await?;
        (first, second)
    };
    {
        const VALUES: TableDefinition<&str, &[u8]> = TableDefinition::new("state_values");
        let db = redb::Database::create(&database)?;
        let txn = db.begin_write()?;
        let oversized = upload_ticket_path("ccc")?.to_string();
        let mut row = b"XSV1".to_vec();
        row.extend_from_slice(&(ticket::TICKET_MAINTENANCE_PAGE_BYTES as u64).to_le_bytes());
        row.resize(row.len() + ticket::TICKET_MAINTENANCE_PAGE_BYTES, b' ');
        row.extend_from_slice(b"null");
        txn.open_table(VALUES)?
            .insert(oversized.as_str(), row.as_slice())?;
        txn.commit()?;
    }

    let (gateway, _, _) = reopen(directory.path()).await?;
    let state = gateway.boot.kernel().state();
    let preceding = ticket::maintain_upload_tickets_batch(state, None, now_millis()).await?;
    ensure!(preceding.removed == 2 && preceding.examined == 3);
    ensure!(state.read(&first).await?.is_none());
    ensure!(state.read(&second).await?.is_none());
    let skipped =
        ticket::maintain_upload_tickets_batch(state, preceding.next, now_millis()).await?;
    ensure!(skipped.skipped_oversized == 1 && skipped.examined == 1);
    Ok(())
}

#[test]
fn read_grant_and_revocation_survive_full_storage_restarts() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let bytes: Vec<u8> = (0_u8..=255).cycle().take(48 * 1024 + 37).collect();
    let object_taint = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://private/persistent-artifact")?,
    });
    let selection_taint = TaintSet::of(TaintSource::ModelOutput);
    let expected_taint = object_taint.clone().merged(&selection_taint);

    // Every phase drops its runtime and all store handles before reopening.
    // Only ordinary grant data, expected content and paths cross each restart.
    let grant = {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (gateway, session, objects) = reopen(directory.path()).await?;
            let upload = objects
                .begin_upload(UploadOptions {
                    expected_size: Some(bytes.len() as u64),
                    mime: Some("application/octet-stream".into()),
                    taint: object_taint.clone(),
                })
                .await?;
            objects
                .write_all(&upload, 0, &bytes, UPLOAD_CHUNK_BYTES)
                .await?;
            let metadata = objects
                .commit_upload(&upload, &TaintSet::pristine())
                .await?;
            ensure!(metadata.taint == object_taint);
            let grant = gateway
                .issue_object_read_grant(
                    &session,
                    IssueObjectReadGrantRequest {
                        surface_id: "echo".into(),
                        object: TaintedValue::new(
                            Value::blob(metadata.blob.clone()),
                            selection_taint.clone(),
                        ),
                        offset: 0,
                        length: None,
                        expires_in_ms: Some(300_000),
                    },
                )
                .await?;
            ensure!(grant.metadata().blob == metadata.blob);
            ensure!(grant.metadata().taint == expected_taint);
            ensure!(grant.offset() == 0 && grant.length() == bytes.len() as u64);
            Ok::<_, anyhow::Error>(grant)
        })?
    };

    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (gateway, session, _objects) = reopen(directory.path()).await?;
            let mut download = gateway.open_object_read(&session, open(&grant)).await?;
            ensure!(download.metadata() == grant.metadata());
            ensure!(download.expires_at_ms() == grant.expires_at_ms());
            ensure!(download.start_offset() == 0);
            ensure!(download.end_offset() == bytes.len() as u64);

            let mut buffer = [0_u8; 4093];
            let mut received = 0;
            while !download.is_complete() {
                let chunk = download.read(&mut buffer).await?;
                ensure!(chunk.bytes_read > 0 && chunk.bytes_read <= buffer.len());
                ensure!(chunk.taint == expected_taint);
                let end = received + chunk.bytes_read;
                ensure!(buffer[..chunk.bytes_read] == bytes[received..end]);
                received = end;
                ensure!(download.next_offset() == received as u64);
                ensure!(chunk.end == (received == bytes.len()));
            }
            ensure!(received == bytes.len());
            download.finish().await?;
            ensure!(
                gateway
                    .revoke_object_read_grant(&session, grant.grant_id())
                    .await?
            );
            Ok::<_, anyhow::Error>(())
        })?;
    }

    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let (gateway, session, objects) = reopen(directory.path()).await?;
            let result = gateway.open_object_read(&session, open(&grant)).await;
            ensure!(
                matches!(&result, Err(GatewayError::Rejected(message)) if message == "object read grant not found"),
                "revocation did not persist: {result:?}"
            );
            ensure!(
                !gateway
                    .revoke_object_read_grant(&session, grant.grant_id())
                    .await?
            );
            let metadata = objects
                .metadata(&grant.metadata().blob)
                .await?
                .context("revocation removed committed content")?;
            ensure!(metadata.blob == grant.metadata().blob);
            ensure!(metadata.taint == object_taint);
            let mut buffer = [0_u8; 64];
            let chunk = objects.read_chunk(&metadata.blob, 0, &mut buffer).await?;
            ensure!(chunk.bytes_read == buffer.len());
            ensure!(buffer == bytes[..buffer.len()]);
            ensure!(chunk.taint == object_taint && !chunk.end);
            Ok::<_, anyhow::Error>(())
        })?;
    }
    Ok(())
}
