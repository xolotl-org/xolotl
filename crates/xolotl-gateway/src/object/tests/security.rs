use super::ports::{MetadataReply, ProbeStore};
use super::*;
use crate::{GatewayPrincipalSurfaceBinding, GatewayProfile, GatewaySurface};
use std::sync::atomic::Ordering;
use xolotl_types::{DType, FrameKind, Path, ResourceName};

#[tokio::test]
async fn shared_state_profiles_cannot_use_each_others_upload_authority() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let other_token = "other-profile-bearer-token-32-bytes";
    let name = ResourceName::new(Path::parse("effect://echo/say")?);
    let profile = GatewayProfile::new("other-profile")
        .with_bearer_identity(
            "other-credential",
            "alice",
            other_token,
            "identity://other-alice",
        )?
        .with_surface(GatewaySurface::effect_invoke("echo", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/echo/say"],
        ));
    let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
    let other = GatewayRuntime::new(
        fixture.boot.clone(),
        profile,
        fixture.gateway.idempotency.clone(),
    )?
    .with_object_store(
        ObjectStore::new()
            .with_read(probe.clone())
            .with_write(probe.clone()),
    );
    let other_session = other
        .authenticate(PresentedCredential::bearer(other_token))
        .await?;
    let uncommitted = fixture.issue(true).await?;
    ensure!(
        other
            .begin_object_upload(
                &other_session,
                BeginObjectUploadRequest {
                    ticket_id: uncommitted.ticket_id().into(),
                    media_type: None,
                    submission_token: None,

                    expected_size: None,
                    expected_digest: None,
                }
            )
            .await
            .is_err()
    );
    ensure!(probe.writes.load(Ordering::Relaxed) == 0);
    ensure!(
        !fixture
            .record(uncommitted.ticket_id())
            .await?
            .is_committed()
    );
    let (ticket, response) = fixture
        .upload(b"profile private receipt", None, true)
        .await?;
    let submission =
        fixture.direct_input_with_provenance("echo", response.item.clone(), response.provenance)?;
    ensure!(
        other
            .submit(&other_session, submission.clone())
            .await
            .is_err()
    );
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
    ensure!(!fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission)
            .await?
            .output
            .outcome
            == Outcome::Done(response.item)
    );
    Ok(())
}

#[tokio::test]
async fn unauthorized_proofs_never_read_shared_metadata_or_consume_receipts() -> anyhow::Result<()>
{
    let mut fixture = Fixture::new().await?;
    let (committed_ticket, response) = fixture
        .upload(b"authorized bytes", Some("image/png"), true)
        .await?;
    let uncommitted = fixture.issue(true).await?;
    let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
    fixture.install_probe(probe.clone());
    let mut bad_store = response.provenance.clone();
    bad_store
        .store_proof
        .as_mut()
        .context("missing proof")?
        .store_id = "foreign".into();
    let mut fake = response.provenance.clone();
    fake.store_proof.as_mut().context("missing proof")?.proof = "nonexistent".into();
    let mut conflict = response.provenance.clone();
    conflict.upload_ticket = Some(uncommitted.ticket_id().into());
    for provenance in [
        GatewayPayloadProvenance {
            upload_ticket: Some(uncommitted.ticket_id().into()),
            store_proof: None,
        },
        committed_object_provenance(uncommitted.ticket_id()),
        bad_store,
        fake,
        conflict,
    ] {
        ensure!(
            fixture
                .gateway
                .submit(
                    &fixture.session,
                    fixture.direct_input_with_provenance(
                        "echo",
                        response.item.clone(),
                        provenance
                    )?,
                )
                .await
                .is_err()
        );
        ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
        ensure!(
            !fixture
                .record(committed_ticket.ticket_id())
                .await?
                .used_by
                .is_some()
        );
        ensure!(
            !fixture
                .record(uncommitted.ticket_id())
                .await?
                .used_by
                .is_some()
        );
    }
    let saved = fixture.record(committed_ticket.ticket_id()).await?;
    for field in [
        "principal",
        "surface",
        "token",
        "digest",
        "size",
        "mime",
        "expiry",
    ] {
        let mut invalid = saved.clone();
        match field {
            "principal" => invalid.principal_id = "other".into(),
            "surface" => invalid.surface_id = "other".into(),
            "token" => invalid.submission_token = Some("different".into()),
            "digest" => invalid.expected_digest = Some("a".repeat(96)),
            "size" => invalid.expected_size = Some(response.size + 1),
            "mime" => invalid.allowed_media_types = vec!["text/*".into()],
            _ => invalid.expires_at_ms = now_millis().saturating_sub(1),
        }
        let invalid_value = if field == "digest" || field == "size" || field == "mime" {
            let mut map = saved.to_value()?.into_map().context("ticket map")?;
            if field == "digest" {
                map.insert("expected_digest".into(), Value::string("a".repeat(96)))?;
            } else if field == "size" {
                map.insert(
                    "expected_size".into(),
                    Value::integer((response.size + 1) as i64),
                )?;
            } else {
                map.insert(
                    "allowed_media_types".into(),
                    Value::list(vec![Value::string("text/*".into())]),
                )?;
            }
            Value::from(map)
        } else {
            invalid.to_value()?
        };
        fixture
            .boot
            .kernel()
            .state()
            .write_set(
                &upload_ticket_path(committed_ticket.ticket_id())?,
                invalid_value.clone(),
            )
            .await?;
        ensure!(
            fixture
                .gateway
                .submit(
                    &fixture.session,
                    fixture.direct_input_with_provenance(
                        "echo",
                        response.item.clone(),
                        response.provenance.clone()
                    )?,
                )
                .await
                .is_err(),
            "accepted wrong {field}"
        );
        ensure!(
            probe.metadata_reads.load(Ordering::Relaxed) == 0,
            "looked up metadata with wrong {field}"
        );
        ensure!(
            fixture
                .boot
                .kernel()
                .state()
                .read(&upload_ticket_path(committed_ticket.ticket_id())?)
                .await?
                == Some(invalid_value),
            "invalid ticket was modified during rejected admission"
        );
    }
    Ok(())
}

#[tokio::test]
async fn failed_metadata_inspection_does_not_consume_single_use_receipt() -> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let (ticket, response) = fixture
        .upload(b"inspect me", Some("image/png"), true)
        .await?;
    for reply in [
        MetadataReply::Missing,
        MetadataReply::Error,
        MetadataReply::WrongHash,
        MetadataReply::WrongSize,
        MetadataReply::WrongMime,
    ] {
        let mut probe = ProbeStore::new(fixture.files.clone());
        probe.metadata_reply = reply;
        let probe = Arc::new(probe);
        fixture.install_probe(probe.clone());
        ensure!(
            fixture
                .gateway
                .submit(
                    &fixture.session,
                    fixture.direct_input_with_provenance(
                        "echo",
                        response.item.clone(),
                        response.provenance.clone()
                    )?,
                )
                .await
                .is_err()
        );
        ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 1);
        ensure!(!fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    }
    Ok(())
}

#[tokio::test]
async fn repeated_references_share_one_metadata_lookup_and_check_every_descriptor()
-> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    let (ticket, response) = fixture
        .upload(b"repeated reference", Some("image/png"), true)
        .await?;
    let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
    fixture.install_probe(probe.clone());
    let blob = response
        .item
        .backing_blob()
        .context("missing blob")?
        .clone();
    let mut conflicting = blob.clone();
    conflicting.mime = Some("text/plain".into());
    let invalid = Value::list(vec![Value::blob(blob.clone()), Value::blob(conflicting)]);
    ensure!(
        fixture
            .gateway
            .submit(
                &fixture.session,
                fixture.direct_input_with_provenance(
                    "echo",
                    invalid,
                    response.provenance.clone()
                )?,
            )
            .await
            .is_err()
    );
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
    ensure!(!fixture.record(ticket.ticket_id()).await?.used_by.is_some());

    let repeated = Value::list((0..64).map(|_| Value::blob(blob.clone())).collect());
    ensure!(
        fixture
            .gateway
            .submit(
                &fixture.session,
                fixture.direct_input_with_provenance(
                    "echo",
                    repeated.clone(),
                    response.provenance
                )?,
            )
            .await?
            .output
            .outcome
            == Outcome::Done(repeated)
    );
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 1);
    ensure!(fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    Ok(())
}

#[tokio::test]
async fn committed_ticket_binds_complete_tensor_and_frame_descriptors() -> anyhow::Result<()> {
    let mut fixture = Fixture::new().await?;
    for (modality, kind) in [
        (
            GatewayModality::Tensor,
            GatewayObjectKind::Tensor {
                dtype: DType::U8,
                shape: vec![4],
            },
        ),
        (
            GatewayModality::SensorFrame,
            GatewayObjectKind::Frame {
                ts_nanos: 7,
                kind: FrameKind::Sensor,
            },
        ),
    ] {
        let ticket = fixture
            .gateway
            .issue_object_upload_ticket(
                &fixture.session,
                IssueObjectUploadTicketRequest {
                    surface_id: "echo".into(),
                    submission_token: None,
                    modality,
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
        let mut upload = fixture
            .begin(&ticket, Some("application/octet-stream"))
            .await?;
        upload.write(b"data").await?;
        let response = upload.commit(kind).await?;
        ensure!(
            fixture
                .record(ticket.ticket_id())
                .await?
                .committed_items
                .iter()
                .any(|binding| binding.item == response.item)
        );
        let blob = response
            .item
            .backing_blob()
            .context("typed backing blob")?
            .clone();
        let forged = match modality {
            GatewayModality::Tensor => Value::tensor(blob, DType::U8, vec![2, 2]),
            _ => Value::frame(blob, 8, FrameKind::Sensor),
        };
        let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
        fixture.install_probe(probe.clone());
        ensure!(
            fixture
                .gateway
                .submit(
                    &fixture.session,
                    fixture.direct_input_with_provenance(
                        "echo",
                        forged,
                        response.provenance.clone(),
                    )?,
                )
                .await
                .is_err()
        );
        ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
        ensure!(!fixture.record(ticket.ticket_id()).await?.used_by.is_some());
        ensure!(
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
                .await?
                .output
                .outcome
                == Outcome::Done(response.item)
        );
        ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 1);
        ensure!(fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    }
    Ok(())
}

#[tokio::test]
async fn matching_ticket_and_proof_aliases_consume_one_receipt() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let (ticket, response) = fixture.upload(b"matching aliases", None, true).await?;
    let mut provenance = response.provenance;
    provenance.upload_ticket = Some(ticket.ticket_id().into());
    ensure!(
        fixture
            .gateway
            .submit(
                &fixture.session,
                fixture.direct_input_with_provenance("echo", response.item.clone(), provenance)?,
            )
            .await?
            .output
            .outcome
            == Outcome::Done(response.item)
    );
    ensure!(fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    Ok(())
}

#[tokio::test]
async fn inspection_rejection_preserves_single_use_receipt_for_corrected_submission()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let (ticket, response) = fixture.upload(b"retry admission", None, true).await?;
    let mut submission = fixture.direct_input_with_provenance(
        "echo",
        response.item.clone(),
        response.provenance.clone(),
    )?;
    submission.requested_output = xolotl_types::OutputMode::Collect { limit: usize::MAX };
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission)
            .await
            .is_err()
    );
    ensure!(!fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    ensure!(
        fixture
            .gateway
            .submit(
                &fixture.session,
                fixture.direct_input_with_provenance(
                    "echo",
                    response.item.clone(),
                    response.provenance
                )?,
            )
            .await?
            .output
            .outcome
            == Outcome::Done(response.item)
    );
    ensure!(fixture.record(ticket.ticket_id()).await?.used_by.is_some());
    Ok(())
}
