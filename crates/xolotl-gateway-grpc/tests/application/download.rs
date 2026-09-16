use super::harness::{
    DOWNLOAD_PATH, EffectOptions, Fixture, TEST_WAIT, TOKEN, encode_frames, request,
};
use super::ports::{Gate, Pause, ProbeOptions, ResponseProbe};
use anyhow::{Context as _, ensure};
use prost::Message as _;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::{Code, Streaming};
use xolotl_gateway::{
    Gateway, GatewayObjectReadGrant, GatewaySession, IssueObjectReadGrantRequest,
    PresentedCredential,
};
use xolotl_gateway_grpc::ApplicationGrpcConfig;
use xolotl_kernel::EchoDriver;
use xolotl_proto::xolotl::v1::application as pb;
use xolotl_state::object::{ObjectMetadata, ObjectWrite, UploadOptions};
use xolotl_types::{BlobRef, Path, Purity, TaintSet, TaintSource, TaintedValue, Value};

use pb::download_object_response::Event;

async fn session(fixture: &Fixture) -> anyhow::Result<GatewaySession> {
    Ok(fixture
        .gateway
        .authenticate(PresentedCredential::bearer(TOKEN))
        .await?)
}

async fn object(fixture: &Fixture, size: usize) -> anyhow::Result<ObjectMetadata> {
    let upload = fixture
        .files
        .begin_upload(UploadOptions {
            expected_size: Some(size as u64),
            taint: TaintSet::of(TaintSource::Protected {
                path: Path::parse("state://vault/download")?,
            }),
            ..Default::default()
        })
        .await?;
    let mut buffer = [0_u8; 16 * 1024];
    let mut offset = 0;
    while offset < size {
        let count = (size - offset).min(buffer.len());
        for (index, byte) in buffer[..count].iter_mut().enumerate() {
            *byte = ((offset + index) % 251) as u8;
        }
        let written = fixture
            .files
            .write_chunk(&upload, offset as u64, &buffer[..count])
            .await?;
        ensure!(written.bytes_written > 0);
        offset += written.bytes_written;
    }
    Ok(fixture
        .files
        .commit_upload(&upload, &TaintSet::pristine())
        .await?)
}

async fn grant(
    fixture: &Fixture,
    metadata: &ObjectMetadata,
    offset: u64,
    length: Option<u64>,
    ttl: u64,
) -> anyhow::Result<GatewayObjectReadGrant> {
    Ok(fixture
        .gateway
        .issue_object_read_grant(
            &session(fixture).await?,
            IssueObjectReadGrantRequest {
                surface_id: "echo".into(),
                object: TaintedValue::new(
                    Value::blob(metadata.blob.clone()),
                    TaintSet::of(TaintSource::ModelOutput),
                ),
                offset,
                length,
                expires_in_ms: Some(ttl),
            },
        )
        .await?)
}

fn read_request(
    grant: &GatewayObjectReadGrant,
    offset: u64,
    length: Option<u64>,
) -> pb::DownloadObjectRequest {
    pb::DownloadObjectRequest {
        read_grant_id: grant.grant_id().into(),
        offset,
        length,
    }
}

async fn next(stream: &mut Streaming<pb::DownloadObjectResponse>) -> anyhow::Result<Option<Event>> {
    tokio::time::timeout(TEST_WAIT, stream.message())
        .await??
        .map(|message| message.event.context("download event missing"))
        .transpose()
}

async fn consume(
    fixture: &Fixture,
    grant: &GatewayObjectReadGrant,
    offset: u64,
    length: Option<u64>,
    max_frame_bytes: usize,
) -> anyhow::Result<()> {
    let mut client = fixture.client().await?;
    let mut stream = client
        .download_object(request(read_request(grant, offset, length))?)
        .await?
        .into_inner();
    let expected_end = length.map_or(grant.offset() + grant.length(), |length| offset + length);
    let Some(Event::Header(header)) = next(&mut stream).await? else {
        anyhow::bail!("download header missing");
    };
    let blob = header.blob.context("canonical content reference missing")?;
    ensure!(blob.hash == grant.metadata().blob.hash && blob.size == grant.metadata().blob.size);
    ensure!(header.offset == offset && header.length == expected_end - offset);
    ensure!(header.expires_at_ms == grant.expires_at_ms());
    ensure!(
        header
            .taint
            .context("header provenance missing")?
            .sources
            .len()
            == 2
    );
    let mut next_offset = offset;
    loop {
        let message = tokio::time::timeout(TEST_WAIT, stream.message())
            .await??
            .context("download ended without completion")?;
        ensure!(message.encoded_len() <= max_frame_bytes);
        match message.event.context("download event missing")? {
            Event::Chunk(chunk) => {
                ensure!(chunk.offset == next_offset && !chunk.data.is_empty());
                ensure!(
                    chunk
                        .taint
                        .context("chunk provenance missing")?
                        .sources
                        .len()
                        == 2
                );
                for (index, &byte) in chunk.data.iter().enumerate() {
                    ensure!(byte == ((next_offset % 251 + index as u64 % 251) % 251) as u8);
                }
                next_offset += chunk.data.len() as u64;
                ensure!(next_offset <= expected_end);
            }
            Event::Completed(done) => {
                ensure!(next_offset == expected_end);
                ensure!(done.next_offset == next_offset && done.bytes_read == next_offset - offset);
                break;
            }
            Event::Header(_) => anyhow::bail!("duplicate download header"),
        }
    }
    ensure!(next(&mut stream).await?.is_none());
    Ok(())
}

#[tokio::test]
async fn cumulative_download_and_resumed_ranges_preserve_bytes_and_provenance() -> anyhow::Result<()>
{
    let fixture = Fixture::new(ApplicationGrpcConfig::default()).await?;
    let size = 3 * 1024 * 1024 + 71;
    let metadata = object(&fixture, size).await?;
    let grant = grant(&fixture, &metadata, 7, Some(size as u64 - 19), 60_000).await?;
    consume(&fixture, &grant, 7, None, 64 * 1024).await?;
    consume(&fixture, &grant, 7, Some(23), 64 * 1024).await?;
    consume(&fixture, &grant, 30, Some(4097), 64 * 1024).await?;
    let reads = fixture.probe.reads();
    consume(&fixture, &grant, 17, Some(0), 64 * 1024).await?;
    consume(
        &fixture,
        &grant,
        grant.offset() + grant.length(),
        None,
        64 * 1024,
    )
    .await?;
    ensure!(fixture.probe.reads() == reads);
    ensure!(fixture.probe.max_read_bytes() <= 16 * 1024);
    fixture.close().await
}

#[tokio::test]
async fn high_u64_ranges_and_small_frames_keep_exact_offsets() -> anyhow::Result<()> {
    let metadata = ObjectMetadata {
        blob: BlobRef {
            hash: "a".repeat(64),
            size: u64::MAX,
            mime: None,
        },
        taint: TaintSet::of(TaintSource::Protected {
            path: Path::parse("state://vault/virtual-download")?,
        }),
    };
    let fixture = Fixture::with_options(
        ApplicationGrpcConfig {
            max_frame_bytes: 256,
            ..Default::default()
        },
        ProbeOptions {
            virtual_object: Some(metadata.clone()),
            ..Default::default()
        },
        None,
    )
    .await?;
    let start = u64::MAX - 32 * 1024;
    let grant = grant(&fixture, &metadata, start, None, 60_000).await?;
    consume(&fixture, &grant, start, Some(4097), 256).await?;
    consume(&fixture, &grant, u64::MAX - 511, None, 256).await?;
    consume(&fixture, &grant, u64::MAX, Some(0), 256).await?;
    ensure!(fixture.probe.max_read_bytes() <= 256);
    let reads = fixture.probe.reads();
    let error = fixture
        .client()
        .await?
        .download_object(request(read_request(&grant, u64::MAX, Some(1)))?)
        .await
        .err()
        .context("overflowing read range accepted")?;
    ensure!(error.code() == Code::InvalidArgument && fixture.probe.reads() == reads);
    fixture.close().await
}

#[tokio::test]
async fn authentication_range_and_revoked_grants_reject_before_storage_reads() -> anyhow::Result<()>
{
    let fixture = Fixture::new(ApplicationGrpcConfig::default()).await?;
    let metadata = object(&fixture, 4096).await?;
    let grant = grant(&fixture, &metadata, 13, Some(1024), 60_000).await?;
    let mut client = fixture.client().await?;
    let error = client
        .download_object(read_request(&grant, 13, None))
        .await
        .err()
        .context("unauthenticated download accepted")?;
    ensure!(error.code() == Code::Unauthenticated);
    for (offset, length) in [(0, None), (13, Some(1025)), (1038, Some(0))] {
        ensure!(
            client
                .download_object(request(read_request(&grant, offset, length))?)
                .await
                .is_err()
        );
    }
    ensure!(
        fixture
            .gateway
            .revoke_object_read_grant(&session(&fixture).await?, grant.grant_id())
            .await?
    );
    ensure!(
        client
            .download_object(request(read_request(&grant, 13, None))?)
            .await
            .is_err()
    );
    ensure!(fixture.probe.reads() == 0);
    fixture.close().await
}

#[tokio::test]
async fn oversized_header_provenance_rejects_without_reading_content() -> anyhow::Result<()> {
    let fixture = Fixture::new(ApplicationGrpcConfig {
        max_frame_bytes: 256,
        ..Default::default()
    })
    .await?;
    let metadata = object(&fixture, 4096).await?;
    let grant = fixture
        .gateway
        .issue_object_read_grant(
            &session(&fixture).await?,
            IssueObjectReadGrantRequest {
                surface_id: "echo".into(),
                object: TaintedValue::new(
                    Value::blob(metadata.blob),
                    TaintSet::of(TaintSource::Fetched {
                        host: "x".repeat(4096).into(),
                    }),
                ),
                offset: 0,
                length: None,
                expires_in_ms: Some(60_000),
            },
        )
        .await?;
    let error = fixture
        .client()
        .await?
        .download_object(request(read_request(&grant, 0, None))?)
        .await
        .err()
        .context("oversized download header accepted")?;
    ensure!(error.code() == Code::ResourceExhausted && fixture.probe.reads() == 0);
    fixture.close().await
}

#[tokio::test]
async fn grant_changes_during_pending_reads_never_publish_the_buffer() -> anyhow::Result<()> {
    for expires in [false, true] {
        let gate = Gate::new();
        let fixture = Fixture::with_options(
            ApplicationGrpcConfig::default(),
            ProbeOptions {
                read: Some(Pause {
                    gate: gate.clone(),
                    after: true,
                }),
                ..Default::default()
            },
            None,
        )
        .await?;
        let metadata = object(&fixture, 4096).await?;
        let grant = grant(
            &fixture,
            &metadata,
            0,
            None,
            if expires { 1000 } else { 60_000 },
        )
        .await?;
        let mut stream = fixture
            .client()
            .await?
            .download_object(request(read_request(&grant, 0, None))?)
            .await?
            .into_inner();
        gate.wait().await?;
        if expires {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64;
            tokio::time::sleep(Duration::from_millis(
                (grant.expires_at_ms() - now).max(0) as u64 + 10,
            ))
            .await;
        } else {
            ensure!(
                fixture
                    .gateway
                    .revoke_object_read_grant(&session(&fixture).await?, grant.grant_id())
                    .await?
            );
        }
        gate.open();
        loop {
            match tokio::time::timeout(TEST_WAIT, stream.message()).await? {
                Ok(Some(message)) => ensure!(matches!(message.event, Some(Event::Header(_)))),
                Err(error) => {
                    ensure!(error.code() == Code::InvalidArgument);
                    break;
                }
                Ok(None) => anyhow::bail!("revoked or expired download ended successfully"),
            }
        }
        ensure!(fixture.probe.reads() == 1);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn resetting_a_pending_download_drops_the_read_and_releases_capacity() -> anyhow::Result<()> {
    let gate = Gate::new();
    let fixture = Fixture::with_options(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        },
        ProbeOptions {
            read: Some(Pause {
                gate: gate.clone(),
                after: false,
            }),
            ..Default::default()
        },
        None,
    )
    .await?;
    let metadata = object(&fixture, 4096).await?;
    let grant = grant(&fixture, &metadata, 0, None, 60_000).await?;
    let raw = fixture.raw().await?;
    let pending = raw
        .request(
            DOWNLOAD_PATH,
            encode_frames(&[read_request(&grant, 0, None)])?,
            true,
        )
        .await?;
    let (mut send, response) = pending.streaming_response().await?;
    gate.wait().await?;
    full(&fixture, &grant).await?;
    send.send_reset(h2::Reason::CANCEL);
    gate.wait_exited().await?;
    drop(response);
    drop(send);
    consume(&fixture, &grant, 0, None, 64 * 1024).await?;
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn rpc_deadline_cancels_a_pending_object_read() -> anyhow::Result<()> {
    let gate = Gate::new();
    let fixture = Fixture::with_options(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        },
        ProbeOptions {
            read: Some(Pause {
                gate: gate.clone(),
                after: false,
            }),
            ..Default::default()
        },
        None,
    )
    .await?;
    let metadata = object(&fixture, 4096).await?;
    let grant = grant(&fixture, &metadata, 0, None, 60_000).await?;
    let raw = fixture.raw().await?;
    let pending = raw
        .request_with_headers(
            DOWNLOAD_PATH,
            encode_frames(&[read_request(&grant, 0, None)])?,
            true,
            &[("grpc-timeout", "100m")],
        )
        .await?;
    gate.wait().await?;
    let response = pending.response().await?;
    ensure!(response.code == Code::DeadlineExceeded);
    gate.wait_exited().await?;
    ensure!(
        response
            .frames::<pb::DownloadObjectResponse>()?
            .iter()
            .all(|message| matches!(message.event, Some(Event::Header(_))))
    );
    consume(&fixture, &grant, 0, None, 64 * 1024).await?;
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn shutdown_cancels_a_pending_object_read_and_rejects_new_downloads() -> anyhow::Result<()> {
    let gate = Gate::new();
    let fixture = Fixture::with_options(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        },
        ProbeOptions {
            read: Some(Pause {
                gate: gate.clone(),
                after: false,
            }),
            ..Default::default()
        },
        None,
    )
    .await?;
    let metadata = object(&fixture, 4096).await?;
    let grant = grant(&fixture, &metadata, 0, None, 60_000).await?;
    let raw = fixture.raw().await?;
    let pending = raw
        .request(
            DOWNLOAD_PATH,
            encode_frames(&[read_request(&grant, 0, None)])?,
            true,
        )
        .await?;
    gate.wait().await?;
    fixture.service.clone().shutdown();
    let response = pending.response().await?;
    ensure!(response.code == Code::Unavailable);
    gate.wait_exited().await?;
    ensure!(
        response
            .frames::<pb::DownloadObjectResponse>()?
            .iter()
            .all(|message| matches!(message.event, Some(Event::Header(_))))
    );
    let error = fixture
        .client()
        .await?
        .download_object(request(read_request(&grant, 0, None))?)
        .await
        .err()
        .context("closed service accepted a download")?;
    ensure!(error.code() == Code::Unavailable && fixture.probe.reads() == 1);
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn storage_timeout_drops_a_pending_read_and_releases_the_response_permit()
-> anyhow::Result<()> {
    let gate = Gate::new();
    let fixture = Fixture::with_options(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            storage_timeout: Duration::from_millis(500),
            ..Default::default()
        },
        ProbeOptions {
            read: Some(Pause {
                gate: gate.clone(),
                after: false,
            }),
            ..Default::default()
        },
        None,
    )
    .await?;
    let metadata = object(&fixture, 4096).await?;
    let grant = grant(&fixture, &metadata, 0, None, 60_000).await?;
    let raw = fixture.raw().await?;
    let pending = raw
        .request(
            DOWNLOAD_PATH,
            encode_frames(&[read_request(&grant, 0, None)])?,
            true,
        )
        .await?;
    gate.wait().await?;
    full(&fixture, &grant).await?;
    let response = pending.response().await?;
    ensure!(response.code == Code::DeadlineExceeded);
    gate.wait_exited().await?;
    ensure!(
        response
            .frames::<pb::DownloadObjectResponse>()?
            .iter()
            .all(|message| matches!(message.event, Some(Event::Header(_))))
    );
    ensure!(fixture.probe.reads() == 1);
    consume(&fixture, &grant, 0, None, 64 * 1024).await?;
    ensure!(fixture.probe.reads() == 2);
    drop(raw);
    fixture.close().await
}

async fn full(fixture: &Fixture, grant: &GatewayObjectReadGrant) -> anyhow::Result<()> {
    let error = fixture
        .client()
        .await?
        .download_object(request(read_request(grant, grant.offset(), Some(0)))?)
        .await
        .err()
        .context("occupied response window accepted a download")?;
    ensure!(error.code() == Code::ResourceExhausted);
    Ok(())
}

async fn plateau(fixture: &Fixture) -> anyhow::Result<usize> {
    tokio::time::timeout(TEST_WAIT, async {
        let mut previous = 0;
        let mut unchanged = 0;
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let reads = fixture.probe.reads();
            if reads > 0 && reads == previous {
                unchanged += 1;
                if unchanged == 5 {
                    return reads;
                }
            } else {
                unchanged = 0;
            }
            previous = reads;
        }
    })
    .await
    .map_err(Into::into)
}

#[tokio::test]
async fn http2_backpressure_bounds_reads_until_transport_credit_returns() -> anyhow::Result<()> {
    for initial_window in [0, 1024] {
        let fixture = Fixture::new(ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        })
        .await?;
        let size = 3 * 1024 * 1024 + 71;
        let metadata = object(&fixture, size).await?;
        let grant = grant(&fixture, &metadata, 0, None, 60_000).await?;
        let raw = fixture.raw_with_window(initial_window).await?;
        let pending = raw
            .request(
                DOWNLOAD_PATH,
                encode_frames(&[read_request(&grant, 0, None)])?,
                true,
            )
            .await?;
        let (send, response) = pending.streaming_response().await?;
        let paused_reads = plateau(&fixture).await?;
        ensure!(
            paused_reads <= 64,
            "window {initial_window}: {paused_reads} reads buffered"
        );
        full(&fixture, &grant).await?;
        raw.set_receive_window(64 * 1024).await?;
        let mut body = response.into_body();
        let mut received = 0;
        tokio::time::timeout(TEST_WAIT, async {
            while let Some(data) = body.data().await {
                let data = data?;
                received += data.len();
                body.flow_control().release_capacity(data.len())?;
            }
            let trailers = body
                .trailers()
                .await?
                .context("download trailers missing")?;
            ensure!(
                trailers
                    .get("grpc-status")
                    .context("download status missing")?
                    == "0"
            );
            anyhow::Ok(())
        })
        .await??;
        ensure!(received > size && fixture.probe.reads() > paused_reads);
        ensure!(fixture.probe.max_read_bytes() <= 16 * 1024);
        drop(body);
        drop(send);
        drop(raw);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn empty_download_keeps_response_capacity_while_http2_retains_data() -> anyhow::Result<()> {
    let response_probe = ResponseProbe::new();
    let mut effect = EffectOptions::stream(Arc::new(EchoDriver), Purity::Pure);
    effect.response_probe = Some(response_probe.clone());
    let fixture = Fixture::with_effect(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        },
        effect,
        None,
    )
    .await?;
    let metadata = object(&fixture, 0).await?;
    let grant = grant(&fixture, &metadata, 0, None, 60_000).await?;
    let raw = fixture.raw_with_window(0).await?;
    let pending = raw
        .request(
            DOWNLOAD_PATH,
            encode_frames(&[read_request(&grant, 0, None)])?,
            true,
        )
        .await?;
    let (mut send, response) = pending.streaming_response().await?;
    response_probe.completed.wait().await?;
    full(&fixture, &grant).await?;
    ensure!(fixture.probe.reads() == 0);
    send.send_reset(h2::Reason::CANCEL);
    drop(response);
    drop(send);
    response_probe.dropped.wait().await?;
    response_probe.wait_data_released().await?;
    consume(&fixture, &grant, 0, None, 64 * 1024).await?;
    drop(raw);
    fixture.close().await
}
