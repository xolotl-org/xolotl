use super::*;
use xolotl_gateway::{
    BeginObjectUploadRequest, GatewayModality, GatewayObjectKind, GatewaySubmission,
    IssueObjectUploadTicketRequest, PresentedCredential, SubmitOptions,
};
use xolotl_standard::{StandardConfig, StandardModule, StandardModules, install_standard};
use xolotl_types::{DType, Outcome};

#[tokio::test]
async fn selected_state_profile_uploads_tensor_consumed_by_shared_standard_blob() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let objects = xolotl_storage_fs::FileObjectStore::open(directory.path())?.into_object_store();
    let boot = Arc::new(Bootstrap::in_memory());
    install_standard(
        &boot,
        &StandardConfig::default()
            .with_modules(StandardModules::none().with(StandardModule::Blob))
            .with_object_store(objects.clone()),
    )?;
    let path = profile::profile_path("app")?;
    let token = "daemon-application-test-token-32-bytes";
    boot.kernel().state().write_set(&path, serde_json::from_value(json!({
        "profile_name": "app", "version": 1,
        "credentials": [{
            "credential_id": "test-key", "principal_id": "client",
            "verifier": {"kind": "bearer", "token_hash": blake3::hash(token.as_bytes()).to_hex().to_string()}
        }],
        "identity_mappings": [{"principal_id": "client", "identity_path": "identity://client"}],
        "surfaces": [{"surface_id": "read", "target": "effect://blob/read"}],
        "principal_surface_bindings": [{
            "principal_id": "client", "visible_surfaces": ["read"], "submit_surfaces": ["read"],
            "capability_ceiling": ["perform://effect/blob/read"]
        }]
    }))?).await?;
    let gateway = GatewayRuntime::new(
        boot.clone(),
        profile::load_profile(boot.kernel().state(), &path, "app").await?,
        Arc::new(xolotl_gateway::MemoryGatewayIdempotencyStore::default()),
    )?
    .with_object_store(objects);
    let session = gateway
        .authenticate(PresentedCredential::bearer(token))
        .await?;
    let ticket = gateway
        .issue_object_upload_ticket(
            &session,
            IssueObjectUploadTicketRequest {
                surface_id: "read".into(),
                submission_token: None,
                modality: GatewayModality::Tensor,
                expected_size: Some(8),
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
    let mut upload = gateway
        .begin_object_upload(
            &session,
            BeginObjectUploadRequest {
                ticket_id: ticket.ticket_id().into(),
                media_type: None,
                submission_token: None,

                expected_size: None,
                expected_digest: None,
            },
        )
        .await?;
    let bytes = [0, 0, 128, 63, 0, 0, 0, 64];
    upload.write(&bytes[..4]).await?;
    upload.write(&bytes[4..]).await?;
    let committed = upload
        .commit(GatewayObjectKind::Tensor {
            dtype: DType::F32,
            shape: vec![2],
        })
        .await?;
    ensure!(matches!(
        committed.item.view(),
        xolotl_types::ValueView::Tensor(_)
    ));
    ensure!(
        boot.kernel()
            .state()
            .read(&Path::parse(&format!("state://blob/{}", committed.digest))?)
            .await?
            .is_none()
    );
    let submission = GatewaySubmission::direct_input("read", committed.item)
        .with_provenance(committed.provenance)
        .with_options(SubmitOptions {
            expected_request_scope: Some(
                gateway
                    .describe(&session)?
                    .surfaces
                    .into_iter()
                    .find(|surface| surface.surface_id == "read")
                    .context("read request scope")?
                    .request_scope,
            ),
            idempotency_key: Some("selected-state-profile-tensor".into()),
            ..SubmitOptions::default()
        });
    let result = gateway.submit(&session, submission.clone()).await?;
    ensure!(result.output.outcome == Outcome::Done(Value::bytes(bytes.to_vec())));
    let repeated = gateway.submit(&session, submission).await?;
    ensure!(repeated.output.outcome == result.output.outcome);
    Ok(())
}
