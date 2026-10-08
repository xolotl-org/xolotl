use super::ports::ProbeStore;
use super::*;
use anyhow::{Context, ensure};
use std::sync::atomic::Ordering;
use tokio::sync::Barrier;
use xolotl_types::{DType, Outcome};

async fn issue_multi(
    fixture: &Fixture,
    max_objects: usize,
    max_total_bytes: u64,
) -> anyhow::Result<GatewayObjectUploadTicket> {
    Ok(fixture
        .gateway
        .issue_object_upload_ticket(
            &fixture.session,
            IssueObjectUploadTicketRequest {
                surface_id: "echo".into(),
                submission_token: None,
                modality: GatewayModality::Value,
                expected_size: None,
                expected_digest: None,
                allowed_media_types: Vec::new(),
                expires_in_ms: Some(60_000),
                single_use: true,
                max_objects: Some(max_objects),
                max_total_bytes: Some(max_total_bytes),
                max_record_bytes: None,
            },
        )
        .await?)
}

async fn upload(
    fixture: &Fixture,
    ticket: &GatewayObjectUploadTicket,
    bytes: &[u8],
    kind: GatewayObjectKind,
) -> Result<CommitObjectUploadResponse, GatewayError> {
    let mut upload = fixture.begin(ticket, None).await?;
    upload.write(bytes).await?;
    upload.commit(kind).await
}

#[tokio::test]
async fn one_ticket_admits_distinct_typed_members_and_deduplicates_backing_reads()
-> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let ticket = issue_multi(&fixture, 2, 1024).await?;
    let blob = upload(&fixture, &ticket, b"first", GatewayObjectKind::Blob).await?;
    let tensor = upload(
        &fixture,
        &ticket,
        b"second",
        GatewayObjectKind::Tensor {
            dtype: DType::U8,
            shape: vec![6],
        },
    )
    .await?;
    let record = fixture.record(ticket.ticket_id()).await?;
    ensure!(record.committed_items.len() == 2);
    ensure!(
        record
            .committed_items
            .iter()
            .all(|binding| binding.append_ids.len() == 1)
    );
    let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
    fixture.install_probe(probe.clone());
    let payload = Value::list(vec![
        blob.item.clone(),
        tensor.item.clone(),
        blob.item.clone(),
    ]);
    let result = fixture
        .gateway
        .submit(
            &fixture.session,
            fixture.direct_input_with_provenance(
                "echo",
                payload.clone(),
                blob.provenance.clone(),
            )?,
        )
        .await?;
    ensure!(result.output.outcome == Outcome::Done(payload));
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 2);
    ensure!(fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    Ok(())
}

#[tokio::test]
async fn all_typed_members_are_checked_before_any_shared_metadata_lookup() -> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let ticket = issue_multi(&fixture, 2, 1024).await?;
    let blob = upload(&fixture, &ticket, b"member", GatewayObjectKind::Blob).await?;
    let other = fixture.upload(b"foreign", None, false).await?.1;
    let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
    fixture.install_probe(probe.clone());
    let bad = Value::list(vec![blob.item.clone(), other.item]);
    ensure!(
        fixture
            .gateway
            .submit(
                &fixture.session,
                fixture.direct_input_with_provenance("echo", bad, blob.provenance.clone())?
            )
            .await
            .is_err()
    );
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
    let wrong_type = Value::tensor(
        blob.item.backing_blob().context("blob")?.clone(),
        DType::U8,
        vec![6],
    );
    ensure!(
        fixture
            .gateway
            .submit(
                &fixture.session,
                fixture.direct_input_with_provenance("echo", wrong_type, blob.provenance)?
            )
            .await
            .is_err()
    );
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
    ensure!(fixture.record(ticket.ticket_id()).await?.used_by.is_none());
    Ok(())
}

#[tokio::test]
async fn concurrent_distinct_uploads_append_without_losing_either_member() -> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let mut probe = ProbeStore::new(fixture.files.clone());
    probe.commit_barrier = Some(Arc::new(Barrier::new(2)));
    fixture.install_probe(Arc::new(probe));
    let ticket = issue_multi(&fixture, 2, 1024).await?;
    let (left, right) = tokio::join!(
        upload(&fixture, &ticket, b"left", GatewayObjectKind::Blob),
        upload(&fixture, &ticket, b"right", GatewayObjectKind::Blob),
    );
    let (left, right) = (left?, right?);
    let record = fixture.record(ticket.ticket_id()).await?;
    ensure!(record.committed_items.len() == 2);
    ensure!(
        record
            .committed_items
            .iter()
            .any(|binding| binding.item == left.item)
    );
    ensure!(
        record
            .committed_items
            .iter()
            .any(|binding| binding.item == right.item)
    );
    Ok(())
}

#[tokio::test]
async fn ticket_count_and_canonical_byte_budgets_reject_later_appends() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    for (max_objects, max_total_bytes) in [(1, 1024), (2, 5)] {
        let ticket = issue_multi(&fixture, max_objects, max_total_bytes).await?;
        upload(&fixture, &ticket, b"one", GatewayObjectKind::Blob).await?;
        ensure!(
            upload(&fixture, &ticket, b"four", GatewayObjectKind::Blob)
                .await
                .is_err()
        );
        ensure!(
            fixture
                .record(ticket.ticket_id())
                .await?
                .committed_items
                .len()
                == 1
        );
    }
    Ok(())
}
