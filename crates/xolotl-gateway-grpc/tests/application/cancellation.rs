use super::harness::{DESCRIBE_PATH, Fixture, begin, chunk, finish, request};
use super::ports::{Gate, Pause, ProbeOptions, one_published};
use anyhow::{Context, ensure};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Barrier;
use tonic::Code;
use tonic::codegen::Bytes;
use xolotl_gateway_grpc::ApplicationGrpcConfig;
use xolotl_proto::xolotl::v1::application as pb;
use xolotl_state::object::ObjectRead;

#[tokio::test]
async fn http2_reset_after_finish_never_commits_and_releases_the_shared_permit()
-> anyhow::Result<()> {
    let config = ApplicationGrpcConfig {
        max_concurrent_uploads: 1,
        ..Default::default()
    };
    let fixture = Fixture::new(config).await?;
    let mut client = fixture.client().await?;
    let ticket = fixture.issue(&mut client).await?;
    let next = fixture.issue(&mut client).await?;
    let raw = fixture.raw().await?;
    let mut upload = raw
        .upload(
            &ticket.ticket_id,
            &[
                begin(&ticket.ticket_id),
                chunk(b"must remain unpublished"),
                finish(),
            ],
            false,
        )
        .await?;
    fixture.body_waits.wait().await?;
    ensure!(fixture.files.pending_uploads() == 1 && fixture.probe.commits() == 0);
    let rejected = raw
        .upload(&next.ticket_id, &[begin(&next.ticket_id), finish()], true)
        .await?
        .response()
        .await?;
    ensure!(rejected.code == Code::ResourceExhausted);
    upload.stream.send_reset(h2::Reason::CANCEL);
    fixture.probe.dropped.wait().await?;
    ensure!(fixture.files.pending_uploads() == 0 && fixture.probe.commits() == 0);
    ensure!(!fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
    drop(upload);
    let accepted = raw
        .upload(&next.ticket_id, &[begin(&next.ticket_id), finish()], true)
        .await?
        .response()
        .await?;
    ensure!(accepted.code == Code::Ok);
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn reset_during_a_write_releases_staging_before_and_after_storage_progress()
-> anyhow::Result<()> {
    for after in [false, true] {
        let gate = Gate::new();
        let options = ProbeOptions {
            write: Some(Pause {
                gate: gate.clone(),
                after,
            }),
            ..Default::default()
        };
        let fixture =
            Fixture::with_options(ApplicationGrpcConfig::default(), options, None).await?;
        let mut client = fixture.client().await?;
        let ticket = fixture.issue(&mut client).await?;
        let raw = fixture.raw().await?;
        let mut upload = raw
            .upload(
                &ticket.ticket_id,
                &[
                    begin(&ticket.ticket_id),
                    chunk(b"accepted prefix"),
                    finish(),
                ],
                true,
            )
            .await?;
        gate.wait().await?;
        ensure!(fixture.files.pending_uploads() == 1);
        upload.stream.send_reset(h2::Reason::CANCEL);
        gate.wait_exited().await?;
        fixture.probe.dropped.wait().await?;
        ensure!(fixture.files.pending_uploads() == 0 && fixture.probe.commits() == 0);
        ensure!(!fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
        drop(upload);
        drop(raw);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn reset_during_content_commit_preserves_already_published_objects() -> anyhow::Result<()> {
    for after in [false, true] {
        let gate = Gate::new();
        let options = ProbeOptions {
            commit: Some(Pause {
                gate: gate.clone(),
                after,
            }),
            ..Default::default()
        };
        let fixture =
            Fixture::with_options(ApplicationGrpcConfig::default(), options, None).await?;
        let mut client = fixture.client().await?;
        let ticket = fixture.issue(&mut client).await?;
        let raw = fixture.raw().await?;
        let mut upload = raw
            .upload(
                &ticket.ticket_id,
                &[
                    begin(&ticket.ticket_id),
                    chunk(b"shared committed bytes"),
                    finish(),
                ],
                true,
            )
            .await?;
        gate.wait().await?;
        upload.stream.send_reset(h2::Reason::CANCEL);
        gate.wait_exited().await?;
        fixture.probe.dropped.wait().await?;
        ensure!(fixture.files.pending_uploads() == 0);
        ensure!(!fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
        if after {
            let published = one_published(&fixture.probe)?;
            let metadata = fixture
                .files
                .metadata(&published.blob)
                .await?
                .context("published object was rolled back")?;
            ensure!(metadata.blob == published.blob);
        } else {
            ensure!(fixture.probe.published()?.is_empty());
        }
        drop(upload);
        drop(raw);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn reset_during_receipt_cas_preserves_the_actual_storage_outcome() -> anyhow::Result<()> {
    for after in [false, true] {
        let gate = Gate::new();
        let fixture = Fixture::with_options(
            ApplicationGrpcConfig {
                max_concurrent_uploads: 1,
                ..Default::default()
            },
            ProbeOptions::default(),
            Some(Pause {
                gate: gate.clone(),
                after,
            }),
        )
        .await?;
        let mut client = fixture.client().await?;
        let ticket = fixture.issue(&mut client).await?;
        let raw = fixture.raw().await?;
        let mut upload = raw
            .upload(
                &ticket.ticket_id,
                &[
                    begin(&ticket.ticket_id),
                    chunk(b"receipt commit is uncertain"),
                    finish(),
                ],
                true,
            )
            .await?;
        gate.wait().await?;
        upload.stream.send_reset(h2::Reason::CANCEL);
        gate.wait_exited().await?;
        fixture.probe.dropped.wait().await?;
        ensure!(fixture.files.pending_uploads() == 0);
        ensure!(fixture.receipt_flag(&ticket.ticket_id, "committed").await? == after);
        ensure!(!fixture.receipt_flag(&ticket.ticket_id, "used").await?);
        let published = one_published(&fixture.probe)?;
        ensure!(fixture.files.metadata(&published.blob).await?.is_some());
        drop(upload);
        let next = fixture.issue(&mut client).await?;
        ensure!(
            raw.upload(&next.ticket_id, &[begin(&next.ticket_id), finish()], true)
                .await?
                .response()
                .await?
                .code
                == Code::Ok
        );
        drop(raw);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn shutdown_cancels_owned_storage_work_and_rejects_new_rpcs() -> anyhow::Result<()> {
    let gate = Gate::new();
    let fixture = Fixture::with_options(
        ApplicationGrpcConfig::default(),
        ProbeOptions {
            write: Some(Pause {
                gate: gate.clone(),
                after: false,
            }),
            ..Default::default()
        },
        None,
    )
    .await?;
    let mut client = fixture.client().await?;
    let ticket = fixture.issue(&mut client).await?;
    let raw = fixture.raw().await?;
    let upload = raw
        .upload(
            &ticket.ticket_id,
            &[begin(&ticket.ticket_id), chunk(b"shutdown"), finish()],
            true,
        )
        .await?;
    gate.wait().await?;
    fixture.service.clone().shutdown();
    gate.wait_exited().await?;
    fixture.probe.dropped.wait().await?;
    ensure!(upload.response().await?.code == Code::Unavailable);
    ensure!(fixture.files.pending_uploads() == 0 && fixture.probe.commits() == 0);
    ensure!(!fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
    let error = client
        .describe(request(pb::DescribeRequest {})?)
        .await
        .err()
        .context("closed service accepted Describe")?;
    ensure!(error.code() == Code::Unavailable);
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn shutdown_cancels_unary_message_and_trailers_waits_before_handler_entry()
-> anyhow::Result<()> {
    for bytes in [
        Bytes::from_static(&[0, 0, 0, 0, 1]),
        Bytes::from_static(&[0, 0, 0, 0, 0]),
    ] {
        let fixture = Fixture::new(ApplicationGrpcConfig::default()).await?;
        let raw = fixture.raw().await?;
        let pending = raw.request(DESCRIBE_PATH, bytes, false).await?;
        fixture.body_waits.wait().await?;
        fixture.service.shutdown();
        let response = tokio::time::timeout(Duration::from_secs(2), pending.response()).await??;
        ensure!(response.code == Code::Unavailable);
        fixture.close().await?;
        drop(raw);
    }
    Ok(())
}

#[tokio::test]
async fn storage_timeout_drops_a_partially_completed_write_and_releases_capacity()
-> anyhow::Result<()> {
    let gate = Gate::new();
    let fixture = Fixture::with_options(
        ApplicationGrpcConfig {
            max_concurrent_uploads: 1,
            storage_timeout: Duration::from_millis(500),
            ..Default::default()
        },
        ProbeOptions {
            write: Some(Pause {
                gate: gate.clone(),
                after: true,
            }),
            ..Default::default()
        },
        None,
    )
    .await?;
    let mut client = fixture.client().await?;
    let ticket = fixture.issue(&mut client).await?;
    let raw = fixture.raw().await?;
    let upload = raw
        .upload(
            &ticket.ticket_id,
            &[
                begin(&ticket.ticket_id),
                chunk(b"timed-out prefix"),
                finish(),
            ],
            true,
        )
        .await?;
    gate.wait().await?;
    ensure!(upload.response().await?.code == Code::DeadlineExceeded);
    gate.wait_exited().await?;
    fixture.probe.dropped.wait().await?;
    ensure!(fixture.files.pending_uploads() == 0 && fixture.probe.commits() == 0);
    ensure!(!fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
    ensure!(
        raw.upload(
            &ticket.ticket_id,
            &[begin(&ticket.ticket_id), finish()],
            true
        )
        .await?
        .response()
        .await?
        .code
            == Code::Ok
    );
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn concurrent_uploads_have_one_receipt_cas_winner_and_keep_shared_content()
-> anyhow::Result<()> {
    let fixture = Fixture::with_options(
        ApplicationGrpcConfig::default(),
        ProbeOptions {
            commit_barrier: Some(Arc::new(Barrier::new(2))),
            ..Default::default()
        },
        None,
    )
    .await?;
    let mut client = fixture.client().await?;
    let ticket = fixture.issue(&mut client).await?;
    let raw = fixture.raw().await?;
    let frames = [
        begin(&ticket.ticket_id),
        chunk(b"one shared object"),
        finish(),
    ];
    let left = raw.upload(&ticket.ticket_id, &frames, true).await?;
    let right = raw.upload(&ticket.ticket_id, &frames, true).await?;
    let (left, right) = tokio::join!(left.response(), right.response());
    let (left, right) = (left?, right?);
    ensure!((left.code == Code::Ok) != (right.code == Code::Ok));
    ensure!([left.code, right.code].contains(&Code::InvalidArgument));
    ensure!(fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
    ensure!(fixture.files.pending_uploads() == 0);
    let published = fixture.probe.published()?;
    ensure!(published.len() == 2 && published[0].blob == published[1].blob);
    ensure!(fixture.files.metadata(&published[0].blob).await?.is_some());
    drop(raw);
    fixture.close().await
}
