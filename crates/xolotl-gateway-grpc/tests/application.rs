use anyhow::{Context, bail, ensure};
use std::time::Duration;
use tonic::Code;
use tonic::codegen::tokio_stream;
use xolotl_gateway_grpc::ApplicationGrpcConfig;
use xolotl_proto::value_from_pb_checked;
use xolotl_proto::xolotl::v1::application as pb;
use xolotl_state::object::ObjectRead;
use xolotl_types::Outcome;

#[path = "application/cancellation.rs"]
mod cancellation;
#[path = "application/download.rs"]
mod download;
#[path = "application/harness.rs"]
mod harness;
#[path = "application/output.rs"]
mod output;
#[path = "application/ports.rs"]
mod ports;
#[cfg(feature = "structured-output")]
#[path = "application/structured.rs"]
mod structured;

use harness::{Fixture, TEST_WAIT, begin, finish, output_outcome as outcome_to_pb, request};

#[tokio::test]
async fn cumulative_object_upload_is_bounded_per_frame_and_enters_submit() -> anyhow::Result<()> {
    let fixture = Fixture::new(ApplicationGrpcConfig::default()).await?;
    let mut client = fixture.client().await?;
    let ticket = fixture.issue(&mut client).await?;
    const CHUNKS: usize = 193;
    const CHUNK_BYTES: usize = 16 * 1024 + 7;
    let frames = std::iter::once(begin(&ticket.ticket_id))
        .chain((0..CHUNKS).map(|chunk| {
            pb::UploadObjectRequest {
                frame: Some(pb::upload_object_request::Frame::Chunk(
                    (0..CHUNK_BYTES)
                        .map(|index| ((chunk * CHUNK_BYTES + index) % 251) as u8)
                        .collect(),
                )),
            }
        }))
        .chain(std::iter::once(finish()));
    let uploaded = tokio::time::timeout(
        TEST_WAIT,
        client.upload_object(request(tokio_stream::iter(frames))?),
    )
    .await??
    .into_inner();
    let total = CHUNKS * CHUNK_BYTES;
    ensure!(total > 3 * 1024 * 1024 && uploaded.size == total as u64);
    let item = value_from_pb_checked(uploaded.item.as_ref().context("upload item missing")?)?;
    let blob = item.backing_blob().context("upload has no backing blob")?;
    ensure!(blob.hash == uploaded.digest && blob.size == uploaded.size);
    ensure!(fixture.probe.max_write_bytes() <= 16 * 1024);
    ensure!(fixture.files.pending_uploads() == 0);
    let mut buffer = [0_u8; 8191];
    let mut offset = 0_u64;
    loop {
        let read = fixture.files.read_chunk(blob, offset, &mut buffer).await?;
        ensure!(read.bytes_read > 0 || read.end);
        for (index, &byte) in buffer[..read.bytes_read].iter().enumerate() {
            ensure!(byte == ((offset as usize + index) % 251) as u8);
        }
        offset += read.bytes_read as u64;
        if read.end {
            break;
        }
    }
    ensure!(offset == uploaded.size);
    let submission = pb::SubmitRequest {
        surface_id: "echo".into(),
        payload: uploaded.item,
        provenance: uploaded.provenance,
        output: None,
        options: None,
    };
    let submitted = client
        .submit(request(submission.clone())?)
        .await?
        .into_inner();
    let completed = submitted
        .completion
        .context("submission completion missing")?;
    ensure!(completed.outcome == Some(outcome_to_pb(&Outcome::Done(item))));
    ensure!(
        completed
            .taint
            .context("submission lineage missing")?
            .sources
            .iter()
            .any(|source| {
                matches!(
                    source.kind,
                    Some(xolotl_proto::xolotl::v1::taint_source::Kind::Inbound(_))
                )
            })
    );
    ensure!(fixture.receipt_flag(&ticket.ticket_id, "used").await?);
    ensure!(client.submit(request(submission)?).await.is_err());
    fixture.close().await
}

#[tokio::test]
async fn finish_waits_for_clean_data_eof_or_trailers_before_commit() -> anyhow::Result<()> {
    let fixture = Fixture::new(ApplicationGrpcConfig::default()).await?;
    let mut client = fixture.client().await?;
    let raw = fixture.raw().await?;
    for trailers in [false, true] {
        let ticket = fixture.issue(&mut client).await?;
        let commits_before = fixture.probe.commits();
        let mut upload = raw
            .upload(
                &ticket.ticket_id,
                &[begin(&ticket.ticket_id), finish()],
                false,
            )
            .await?;
        fixture.body_waits.wait().await?;
        ensure!(fixture.files.pending_uploads() == 1);
        ensure!(fixture.probe.commits() == commits_before);
        ensure!(!fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
        if trailers {
            upload
                .stream
                .send_trailers(tonic::codegen::http::HeaderMap::new())?;
        } else {
            upload
                .stream
                .send_data(tonic::codegen::Bytes::new(), true)?;
        }
        let response = upload.response().await?;
        ensure!(response.code == Code::Ok);
        let uploaded = response.upload()?;
        ensure!(uploaded.size == 0);
        ensure!(fixture.probe.commits() == commits_before + 1);
        ensure!(fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
        ensure!(fixture.files.pending_uploads() == 0);
    }
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn malformed_sequences_never_publish_or_retain_staging() -> anyhow::Result<()> {
    let fixture = Fixture::new(ApplicationGrpcConfig::default()).await?;
    let mut client = fixture.client().await?;
    let raw = fixture.raw().await?;
    for case in [
        "empty",
        "chunk_first",
        "duplicate_begin",
        "no_finish",
        "tail",
        "missing_frame",
        "missing_kind",
    ] {
        let ticket = fixture.issue(&mut client).await?;
        let start = begin(&ticket.ticket_id);
        let chunk = pb::UploadObjectRequest {
            frame: Some(pb::upload_object_request::Frame::Chunk(
                b"unpublished".to_vec(),
            )),
        };
        let frames = match case {
            "empty" => vec![],
            "chunk_first" => vec![chunk],
            "duplicate_begin" => vec![start.clone(), start, finish()],
            "no_finish" => vec![start, chunk],
            "tail" => vec![start, finish(), chunk],
            "missing_frame" => vec![start, pb::UploadObjectRequest { frame: None }],
            "missing_kind" => vec![
                start,
                pb::UploadObjectRequest {
                    frame: Some(pb::upload_object_request::Frame::Finish(
                        pb::FinishObjectUpload { kind: None },
                    )),
                },
            ],
            _ => bail!("unknown test case"),
        };
        let response = raw
            .upload(&ticket.ticket_id, &frames, true)
            .await?
            .response()
            .await?;
        ensure!(
            response.code == Code::InvalidArgument,
            "{case}: {:?}",
            response.code
        );
        ensure!(
            fixture.files.pending_uploads() == 0,
            "{case} retained staging"
        );
        ensure!(fixture.probe.commits() == 0, "{case} reached commit");
        ensure!(!fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
    }
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn oversized_frame_is_rejected_before_its_payload_is_written() -> anyhow::Result<()> {
    let config = ApplicationGrpcConfig {
        max_frame_bytes: 1024,
        ..Default::default()
    };
    let fixture = Fixture::new(config).await?;
    let mut client = fixture.client().await?;
    let ticket = fixture.issue(&mut client).await?;
    let frames = vec![
        begin(&ticket.ticket_id),
        pb::UploadObjectRequest {
            frame: Some(pb::upload_object_request::Frame::Chunk(vec![0_u8; 2048])),
        },
        finish(),
    ];
    let error = client
        .upload_object(request(tokio_stream::iter(frames))?)
        .await
        .err()
        .context("oversized frame was accepted")?;
    ensure!(error.code() != Code::Ok);
    ensure!(fixture.probe.writes() == 0);
    ensure!(fixture.files.pending_uploads() == 0);
    ensure!(!fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
    fixture.close().await
}

#[tokio::test]
async fn first_frame_and_post_finish_idle_timeouts_release_the_upload_window() -> anyhow::Result<()>
{
    let config = ApplicationGrpcConfig {
        max_concurrent_uploads: 1,
        first_frame_timeout: Duration::from_millis(100),
        idle_timeout: Duration::from_millis(100),
        ..Default::default()
    };
    let fixture = Fixture::new(config).await?;
    let mut client = fixture.client().await?;
    let raw = fixture.raw().await?;
    let ticket = fixture.issue(&mut client).await?;
    let response = raw
        .upload(&ticket.ticket_id, &[], false)
        .await?
        .response()
        .await?;
    ensure!(response.code == Code::DeadlineExceeded);
    ensure!(fixture.files.pending_uploads() == 0);
    let upload = raw
        .upload(
            &ticket.ticket_id,
            &[begin(&ticket.ticket_id), finish()],
            false,
        )
        .await?;
    fixture.body_waits.wait().await?;
    let response = upload.response().await?;
    ensure!(response.code == Code::DeadlineExceeded);
    ensure!(fixture.files.pending_uploads() == 0 && fixture.probe.commits() == 0);
    let response = raw
        .upload(
            &ticket.ticket_id,
            &[begin(&ticket.ticket_id), finish()],
            true,
        )
        .await?
        .response()
        .await?;
    ensure!(response.code == Code::Ok);
    drop(raw);
    fixture.close().await
}
