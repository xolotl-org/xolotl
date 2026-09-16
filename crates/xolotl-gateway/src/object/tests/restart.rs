use super::*;
use crate::OpenObjectReadRequest;
use std::path::Path as FsPath;
use xolotl_kernel::{EchoDriver, FactSink, Kernel, MethodSpec};
use xolotl_storage_redb::RedbStore;
use xolotl_types::{Path, Purity, TaintedValue};

async fn reopen(
    directory: &FsPath,
) -> anyhow::Result<(GatewayRuntime, GatewaySession, ObjectStore)> {
    let state = RedbStore::open(directory.join("gateway.redb"))?;
    let boot = Arc::new(Bootstrap::from_kernel(Kernel::with_backends(
        state.state_backend().into_backend(),
        FactSink::new(Arc::new(state.fact_store()?)),
    )));
    let objects = FileObjectStore::open(directory.join("content"))?.into_object_store();
    let target = boot.register_effect(
        "effect://echo/say",
        &[MethodSpec::unary_async("invoke", Purity::Pure)],
        Arc::new(EchoDriver),
    )?;
    let gateway =
        GatewayRuntime::new(boot, echo_profile(target)?)?.with_object_store(objects.clone());
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
