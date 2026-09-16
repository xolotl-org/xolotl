use super::*;
use crate::{
    GatewayInputStreamStart, GatewayStreamDirection, GatewayStreamOpenRequest, GatewaySubmitResult,
};
use xolotl_graph::{DoNode, OperationTemplate};
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_standard::{StandardConfig, StandardModule, StandardModules, install_standard};
use xolotl_types::{
    CompletionOrigin, DType, Failure, FrameKind, MethodId, OutputMode, Path, Purity, ResourceName,
};

#[tokio::test]
async fn gateway_upload_is_readable_by_standard_blob_without_state_content() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    install_standard(
        &fixture.boot,
        &StandardConfig::default()
            .with_modules(StandardModules::none().with(StandardModule::Blob))
            .with_object_store(fixture.files.clone().into_object_store()),
    )?;
    let name = ResourceName::new(Path::parse("effect://blob/read")?);
    let handle = fixture
        .boot
        .open_for(fixture.boot.root, &name, "perform")
        .map_err(|error| anyhow::anyhow!("{error:?}"))?;
    let executor = fixture.boot.kernel.executor_for(fixture.boot.root);
    executor.bind_handle(name.clone(), handle);
    for bytes in [
        Vec::new(),
        b"small shared object".to_vec(),
        vec![29; 40_001],
        vec![37; 1024 * 1024 + 1],
    ] {
        let (_, response) = fixture
            .upload(&bytes, Some("application/octet-stream"), false)
            .await?;
        ensure!(
            fixture
                .boot
                .kernel
                .state
                .read(&Path::parse(&format!("state://blob/{}", response.digest))?)
                .await?
                .is_none(),
            "upload materialized object content in State"
        );
        let operation = |output| {
            DoNode::op(OperationTemplate {
                target: name.clone(),
                method: "invoke".into(),
                method_id: None,
                output,
                literal_input: Some(response.item.clone()),
            })
        };
        let unary = executor.eval(&operation(OutputMode::Unary)).await;
        if bytes.len() <= 1024 * 1024 {
            ensure!(
                unary.outcome == Outcome::Done(Value::bytes(bytes.clone())),
                "{unary:?}"
            );
        } else {
            ensure!(
                unary.outcome == Outcome::Done(response.item.clone()),
                "{unary:?}"
            );
        }
        let streamed = executor
            .eval(&operation(OutputMode::Collect { limit: 128 }))
            .await;
        let Some(chunks) = streamed.outcome.value().and_then(Value::as_list) else {
            bail!("expected collected object chunks, got {streamed:?}");
        };
        if bytes.is_empty() {
            ensure!(chunks.len() == 1 && chunks.get(0).is_some_and(Value::is_null));
            continue;
        }
        let mut received = Vec::new();
        for chunk in chunks {
            let Some(chunk) = chunk.as_bytes() else {
                bail!("unexpected collected object item: {chunk:?}");
            };
            ensure!(chunk.len() <= 16 * 1024);
            received.extend_from_slice(chunk);
        }
        ensure!(received == bytes);
    }
    Ok(())
}

struct ObserveTaint;

#[async_trait::async_trait]
impl Driver for ObserveTaint {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        Ok(DriverOutput::new(Outcome::Done(Value::boolean(
            context.taint.has_protected()
                && context.taint.sources().contains(&TaintSource::ModelOutput)
                && context.taint.sources().iter().any(|source| {
                    matches!(source, TaintSource::Inbound { channel, .. } if channel == "object-upload")
                }),
        ))))
    }
}

async fn submit_object(
    fixture: &Fixture,
    response: &CommitObjectUploadResponse,
    streamed: bool,
) -> anyhow::Result<GatewaySubmitResult> {
    if !streamed {
        return Ok(fixture
            .gateway
            .submit(
                &fixture.session,
                direct_input_with_provenance(
                    "echo",
                    response.item.clone(),
                    response.provenance.clone(),
                ),
            )
            .await?);
    }
    let start = fixture
        .gateway
        .accept_input_stream_submission(
            &fixture.session,
            GatewaySubmission::input_stream(
                "echo",
                GatewayStreamOpenRequest {
                    stream_id: "object-input".into(),
                    direction: GatewayStreamDirection::ClientToKernel,
                    modality: GatewayModality::Bytes,
                    item_schema_id: String::new(),
                    max_inline_item_bytes: 16,
                    max_items: Some(4),
                    max_bytes: Some(64),
                },
            ),
        )
        .await?;
    let GatewayInputStreamStart::Accepted(stream) = start else {
        bail!("unexpected input stream replay");
    };
    Ok(fixture
        .gateway
        .complete_input_stream_submission(
            *stream,
            response.item.clone(),
            Some(response.provenance.clone()),
        )
        .await?)
}

#[tokio::test]
async fn shared_object_provenance_reaches_both_submission_entries_and_taint_policy()
-> anyhow::Result<()> {
    for require_unprotected in [false, true] {
        let mut method = MethodSpec::unary_async("invoke", Purity::Pure);
        if require_unprotected {
            method = method.unprotected_input();
        }
        let fixture = Fixture::with_driver(method, Arc::new(ObserveTaint)).await?;
        let mut taint = TaintSet::of(TaintSource::Protected {
            path: Path::parse("state://vault/private")?,
        });
        taint.add(TaintSource::ModelOutput);
        let original = fixture
            .seed(b"shared lineage", "application/octet-stream", taint)
            .await?;
        let (_, response) = fixture
            .upload(b"shared lineage", Some("image/png"), false)
            .await?;
        ensure!(response.item.backing_blob() == Some(&original.blob));
        for streamed in [false, true] {
            let result = submit_object(&fixture, &response, streamed).await?;
            ensure!(result.origin == CompletionOrigin::CurrentAttempt);
            ensure!(result.output.taint.has_protected());
            ensure!(
                result
                    .output
                    .taint
                    .sources()
                    .contains(&TaintSource::ModelOutput)
            );
            ensure!(result.output.taint.sources().iter().any(|source| {
                matches!(source, TaintSource::Inbound { channel, .. } if channel == "object-upload")
            }));
            if require_unprotected {
                ensure!(
                    matches!(result.output.outcome, Outcome::Fail(Failure::PolicyViolation { policy, .. }) if policy == "taint"),
                    "protected object bypassed policy at streamed={streamed}"
                );
            } else {
                ensure!(
                    result.output.outcome == Outcome::Done(Value::boolean(true)),
                    "lost provenance at streamed={streamed}: {result:?}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn all_typed_uploads_return_canonical_backing_metadata() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let canonical = fixture
        .seed(b"typed", "application/octet-stream", TaintSet::pristine())
        .await?;
    for modality in [
        GatewayModality::Bytes,
        GatewayModality::Tensor,
        GatewayModality::VideoFrame,
    ] {
        let kind = || match modality {
            GatewayModality::Bytes => GatewayObjectKind::Blob,
            GatewayModality::Tensor => GatewayObjectKind::Tensor {
                dtype: DType::U8,
                shape: vec![5],
            },
            _ => GatewayObjectKind::Frame {
                ts_nanos: 1_000,
                kind: FrameKind::Video,
            },
        };
        let mut request = IssueObjectUploadTicketRequest {
            surface_id: "echo".into(),
            submission_token: None,
            modality,
            expected_size: None,
            expected_digest: None,
            allowed_media_types: Vec::new(),
            expires_in_ms: Some(60_000),
            single_use: false,
        };
        let ticket = fixture
            .gateway
            .issue_object_upload_ticket(&fixture.session, request.clone())
            .await?;
        let mut upload = fixture.begin(&ticket, Some("image/png")).await?;
        upload.write(b"typed").await?;
        let response = upload.commit(kind()).await?;
        ensure!(response.item.backing_blob() == Some(&canonical.blob));
        request.allowed_media_types = vec!["image/*".into()];
        let constrained = fixture
            .gateway
            .issue_object_upload_ticket(&fixture.session, request)
            .await?;
        let mut upload = fixture.begin(&constrained, Some("image/png")).await?;
        upload.write(b"typed").await?;
        ensure!(upload.commit(kind()).await.is_err());
        ensure!(!fixture.record(constrained.ticket_id()).await?.committed);
        ensure!(
            fixture
                .files
                .clone()
                .into_object_store()
                .metadata(&canonical.blob)
                .await?
                .is_some()
        );
    }
    Ok(())
}
