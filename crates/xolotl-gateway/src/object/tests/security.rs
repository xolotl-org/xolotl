use super::ports::{MetadataReply, ProbeStore};
use super::*;
use crate::{GatewayPrincipalSurfaceBinding, GatewayProfile, GatewaySurface};
use std::sync::atomic::Ordering;
use xolotl_types::{Path, ResourceName};

#[tokio::test]
async fn shared_state_profiles_cannot_use_each_others_upload_authority() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let other_token = "other-profile-bearer-token";
    let name = ResourceName::new(Path::parse("effect://echo/say")?);
    let profile = GatewayProfile::new("other-profile")
        .with_bearer_identity(
            "other-credential",
            "alice",
            other_token,
            "process://other-alice",
        )?
        .with_surface(GatewaySurface::effect_invoke("echo", name))
        .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
            "alice",
            ["echo"],
            ["perform://effect/echo/say"],
        ));
    let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
    let other = GatewayRuntime::new(fixture.boot.clone(), profile)?.with_object_store(
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
                }
            )
            .await
            .is_err()
    );
    ensure!(probe.writes.load(Ordering::Relaxed) == 0);
    ensure!(!fixture.record(uncommitted.ticket_id()).await?.committed);
    let (ticket, response) = fixture
        .upload(b"profile private receipt", None, true)
        .await?;
    let submission =
        direct_input_with_provenance("echo", response.item.clone(), response.provenance);
    ensure!(
        other
            .submit(&other_session, submission.clone())
            .await
            .is_err()
    );
    ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
    ensure!(!fixture.record(ticket.ticket_id()).await?.used);
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
                    direct_input_with_provenance("echo", response.item.clone(), provenance),
                )
                .await
                .is_err()
        );
        ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 0);
        ensure!(!fixture.record(committed_ticket.ticket_id()).await?.used);
        ensure!(!fixture.record(uncommitted.ticket_id()).await?.used);
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
            "digest" => invalid.expected_digest = Some("a".repeat(64)),
            "size" => invalid.expected_size = Some(response.size + 1),
            "mime" => invalid.allowed_media_types = vec!["text/*".into()],
            _ => invalid.expires_at_ms = now_millis().saturating_sub(1),
        }
        fixture
            .boot
            .kernel
            .state
            .write_set(
                &upload_ticket_path(committed_ticket.ticket_id())?,
                invalid.to_value()?,
            )
            .await?;
        ensure!(
            fixture
                .gateway
                .submit(
                    &fixture.session,
                    direct_input_with_provenance(
                        "echo",
                        response.item.clone(),
                        response.provenance.clone()
                    ),
                )
                .await
                .is_err(),
            "accepted wrong {field}"
        );
        ensure!(
            probe.metadata_reads.load(Ordering::Relaxed) == 0,
            "looked up metadata with wrong {field}"
        );
        ensure!(!fixture.record(committed_ticket.ticket_id()).await?.used);
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
                    direct_input_with_provenance(
                        "echo",
                        response.item.clone(),
                        response.provenance.clone()
                    ),
                )
                .await
                .is_err()
        );
        ensure!(probe.metadata_reads.load(Ordering::Relaxed) == 1);
        ensure!(!fixture.record(ticket.ticket_id()).await?.used);
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
                direct_input_with_provenance("echo", response.item.clone(), provenance),
            )
            .await?
            .output
            .outcome
            == Outcome::Done(response.item)
    );
    ensure!(fixture.record(ticket.ticket_id()).await?.used);
    Ok(())
}

#[tokio::test]
async fn inspection_rejection_preserves_single_use_receipt_for_corrected_submission()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let (ticket, response) = fixture.upload(b"retry admission", None, true).await?;
    let mut submission =
        direct_input_with_provenance("echo", response.item.clone(), response.provenance.clone());
    submission.requested_output = xolotl_types::OutputMode::Collect { limit: usize::MAX };
    ensure!(
        fixture
            .gateway
            .submit(&fixture.session, submission)
            .await
            .is_err()
    );
    ensure!(!fixture.record(ticket.ticket_id()).await?.used);
    ensure!(
        fixture
            .gateway
            .submit(
                &fixture.session,
                direct_input_with_provenance("echo", response.item.clone(), response.provenance),
            )
            .await?
            .output
            .outcome
            == Outcome::Done(response.item)
    );
    ensure!(fixture.record(ticket.ticket_id()).await?.used);
    Ok(())
}
