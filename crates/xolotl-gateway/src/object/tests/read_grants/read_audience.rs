use super::*;
use crate::GatewayObjectDownload;
use std::sync::atomic::Ordering;

fn audience_profile(visible: bool) -> anyhow::Result<GatewayProfile> {
    let mut profile = GatewayProfile::new("gateway-test")
        .with_bearer_identity("cred-alice", "alice", TEST_TOKEN, "process://alice")?
        .with_surface(GatewaySurface::effect_invoke(
            "echo",
            ResourceName::new(Path::parse("effect://echo/say")?),
        ));
    if visible {
        profile = profile.with_principal_surface_binding(GatewayPrincipalSurfaceBinding::new(
            "alice",
            ["echo"],
            Vec::<String>::new(),
            Vec::<String>::new(),
        ));
    }
    Ok(profile)
}

async fn read_and_finish(
    mut download: GatewayObjectDownload,
    expected: &[u8],
) -> anyhow::Result<()> {
    let mut received = 0;
    let mut buffer = [0_u8; 3];
    while !download.is_complete() {
        let chunk = download.read(&mut buffer).await?;
        ensure!(chunk.bytes_read > 0);
        let end = received + chunk.bytes_read;
        ensure!(expected.get(received..end) == Some(&buffer[..chunk.bytes_read]));
        received = end;
    }
    ensure!(received == expected.len());
    download.finish().await?;
    Ok(())
}

#[tokio::test]
async fn explicit_read_grants_support_audiences_without_submission_or_discovery()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let bytes = b"training artifact";
    let metadata = fixture
        .seed(bytes, "application/octet-stream", TaintSet::pristine())
        .await?;
    let process_count = fixture.boot.kernel.processes.all_ids().len();
    for visible in [true, false] {
        let gateway = GatewayRuntime::new(fixture.boot.clone(), audience_profile(visible)?)?
            .with_object_store(fixture.files.clone().into_object_store());
        let session = gateway
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await?;
        let descriptor = gateway.describe(&session)?;
        ensure!(descriptor.surfaces.len() == usize::from(visible));
        if visible {
            ensure!(descriptor.surfaces[0].surface_id == "echo");
        }
        let grant = gateway
            .issue_object_read_grant(
                &session,
                request(TaintedValue::pristine(Value::blob(metadata.blob.clone()))),
            )
            .await?;
        ensure!(
            matches!(
                gateway
                    .submit(
                        &session,
                        GatewaySubmission::direct_input("echo", Value::string("denied".into())),
                    )
                    .await,
                Err(GatewayError::Rejected(_))
            ),
            "object read delegation must not authorize submission"
        );
        ensure!(fixture.boot.kernel.processes.all_ids().len() == process_count);
        let download = gateway.open_object_read(&session, open(&grant)).await?;
        read_and_finish(download, bytes).await?;
        ensure!(
            gateway
                .revoke_object_read_grant(&session, grant.grant_id())
                .await?
        );
        ensure!(
            !gateway
                .revoke_object_read_grant(&session, grant.grant_id())
                .await?
        );
        ensure!(
            gateway
                .open_object_read(&session, open(&grant))
                .await
                .is_err()
        );
        ensure!(fixture.boot.kernel.processes.all_ids().len() == process_count);
    }
    Ok(())
}

#[tokio::test]
async fn replicas_can_consume_read_grants_with_different_discovery_and_submission_bindings()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let bytes = b"replicated artifact";
    let metadata = fixture
        .seed(bytes, "text/plain", TaintSet::pristine())
        .await?;
    let grant = fixture
        .gateway
        .issue_object_read_grant(
            &fixture.session,
            request(TaintedValue::pristine(Value::blob(metadata.blob))),
        )
        .await?;
    let process_count = fixture.boot.kernel.processes.all_ids().len();
    for visible in [true, false] {
        let replica = GatewayRuntime::new(fixture.boot.clone(), audience_profile(visible)?)?
            .with_object_store(fixture.files.clone().into_object_store());
        let session = replica
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await?;
        ensure!(replica.describe(&session)?.surfaces.len() == usize::from(visible));
        let download = replica.open_object_read(&session, open(&grant)).await?;
        read_and_finish(download, bytes).await?;
    }
    ensure!(fixture.boot.kernel.processes.all_ids().len() == process_count);
    Ok(())
}

#[tokio::test]
async fn known_object_hashes_and_upload_receipts_do_not_delegate_reads() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let (ticket, committed) = fixture
        .upload(b"uploaded artifact", Some("text/plain"), true)
        .await?;
    let receipt = committed
        .provenance
        .store_proof
        .as_ref()
        .context("committed upload receipt")?;
    ensure!(receipt.proof == ticket.ticket_id());
    ensure!(fixture.record(ticket.ticket_id()).await?.committed);
    let blob = committed.item.backing_blob().context("committed blob")?;
    for visible in [true, false] {
        let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
        let gateway = GatewayRuntime::new(fixture.boot.clone(), audience_profile(visible)?)?
            .with_object_store(ObjectStore::new().with_read(probe.clone()));
        let session = gateway
            .authenticate(PresentedCredential::bearer(TEST_TOKEN))
            .await?;
        for candidate in [
            blob.hash.clone(),
            receipt.proof.clone(),
            format!("org_{}", &blob.hash[..32]),
        ] {
            ensure!(
                gateway
                    .open_object_read(
                        &session,
                        OpenObjectReadRequest {
                            grant_id: candidate,
                            offset: 0,
                            length: None,
                        },
                    )
                    .await
                    .is_err()
            );
        }
        ensure!(probe.metadata_reads.load(Ordering::Acquire) == 0);
    }
    ensure!(!fixture.record(ticket.ticket_id()).await?.used);
    Ok(())
}

#[tokio::test]
async fn unknown_export_surfaces_are_rejected_before_object_metadata_io() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let metadata = fixture
        .seed(b"artifact", "text/plain", TaintSet::pristine())
        .await?;
    let probe = Arc::new(ProbeStore::new(fixture.files.clone()));
    let gateway = GatewayRuntime::new(fixture.boot.clone(), audience_profile(false)?)?
        .with_object_store(ObjectStore::new().with_read(probe.clone()));
    let session = gateway
        .authenticate(PresentedCredential::bearer(TEST_TOKEN))
        .await?;
    let mut issue = request(TaintedValue::pristine(Value::blob(metadata.blob)));
    issue.surface_id = "unknown".into();
    ensure!(matches!(
        gateway.issue_object_read_grant(&session, issue).await,
        Err(GatewayError::Rejected(message)) if message.contains("unknown object export surface")
    ));
    ensure!(probe.metadata_reads.load(Ordering::Acquire) == 0);
    Ok(())
}
