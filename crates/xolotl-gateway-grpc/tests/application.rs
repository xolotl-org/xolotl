use anyhow::{Context, bail, ensure};
use std::time::Duration;
use tonic::Code;
use tonic::codegen::tokio_stream;
use xolotl_gateway_grpc::ApplicationGrpcConfig;
use xolotl_proto::xolotl::v1::application as pb;
use xolotl_proto::{value_from_pb, value_to_pb};
use xolotl_state::object::ObjectRead;
use xolotl_types::{Outcome, Value};

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

use harness::{
    Fixture, SUBMIT_PATH, TEST_WAIT, begin, encode_frames, finish, output_outcome as outcome_to_pb,
    request,
};

#[tokio::test]
async fn request_lookup_round_trip_preserves_results_without_execution_or_epoch_changes()
-> anyhow::Result<()> {
    use pb::lookup_request_request::Identity;
    use pb::lookup_request_response::Evidence;
    use std::sync::Arc;
    use xolotl_gateway::GatewayIdempotencyStore;

    for token in [false, true] {
        let fixture = Fixture::with_effect(
            ApplicationGrpcConfig::default(),
            harness::EffectOptions::unary(
                Arc::new(xolotl_kernel::EchoDriver),
                xolotl_types::Purity::Effectful,
            ),
            None,
        )
        .await?;
        let mut client = fixture.client().await?;
        ensure!(
            client
                .describe(request(pb::DescribeRequest {})?)
                .await?
                .into_inner()
                .max_frame_bytes
                == ApplicationGrpcConfig::default().max_frame_bytes as u64
        );
        let scope = fixture.request_scope(&mut client).await?;
        let lookup = pb::LookupRequestRequest {
            surface_id: "echo".into(),
            expected_request_scope: scope.clone(),
            retry_epoch: 0,
            identity: Some(if token {
                Identity::SubmissionToken("original-token".into())
            } else {
                Identity::IdempotencyKey("original-key".into())
            }),
        };
        let empty_usage = fixture.idempotency.usage().await?;
        ensure!(matches!(
            client
                .lookup_request(request(lookup.clone())?)
                .await?
                .into_inner()
                .evidence,
            Some(Evidence::Unproven(_))
        ));
        let unavailable = client
            .deliver_request_result(request(lookup.clone())?)
            .await
            .err()
            .context("unproven result unexpectedly delivered")?;
        ensure!(unavailable.code() == Code::FailedPrecondition);
        ensure!(unavailable.message() == "retained result unavailable: unproven");
        ensure!(fixture.idempotency.usage().await? == empty_usage);
        let mut expected = client
            .submit(request(pb::SubmitRequest {
                surface_id: "echo".into(),
                payload: Some(value_to_pb(&Value::string("once".into()))),
                options: Some(pb::SubmitOptions {
                    expected_request_scope: Some(scope),
                    idempotency_key: (!token).then(|| "original-key".into()),
                    submission_token: token.then(|| "original-token".into()),
                    ..Default::default()
                }),
                ..Default::default()
            })?)
            .await?
            .into_inner();
        let Some(pb::submit_response::Terminal::Completion(completion)) =
            expected.terminal.as_mut()
        else {
            bail!("original submission lost completion");
        };
        completion.origin = pb::CompletionOrigin::CachedOutcome as i32;
        let settled_usage = fixture.idempotency.usage().await?;
        let Some(Evidence::Settled(observed)) = client
            .lookup_request(request(lookup.clone())?)
            .await?
            .into_inner()
            .evidence
        else {
            bail!("settled result lost its evidence");
        };
        ensure!(observed.accepted == expected.accepted);
        ensure!(observed.result_class == pb::RequestResultClass::Done as i32);
        ensure!(
            client
                .deliver_request_result(request(lookup.clone())?)
                .await?
                .into_inner()
                == expected
        );
        ensure!(fixture.idempotency.usage().await? == settled_usage);
        ensure!(fixture.idempotency.retry_epoch().await? == 0);
        ensure!(fixture.idempotency.close_retry_epoch(0).await? == 1);
        let closed_usage = fixture.idempotency.usage().await?;
        ensure!(matches!(
            client
                .lookup_request(request(lookup)?)
                .await?
                .into_inner()
                .evidence,
            Some(Evidence::Unproven(_))
        ));
        ensure!(fixture.idempotency.usage().await? == closed_usage);
        ensure!(fixture.idempotency.retry_epoch().await? == 1);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn unary_response_revocation_after_service_completion_withholds_first_and_cached_results()
-> anyhow::Result<()> {
    use http_body::Body;
    use std::future::poll_fn;
    use std::pin::Pin;
    use tonic::codegen::{Bytes, Service, http};
    use xolotl_gateway::{
        Gateway, GatewayIdempotencyStore, GatewayPrincipalSurfaceBinding, GatewayProfile,
        GatewaySurface, PresentedCredential,
    };

    struct EncodedRequest(Option<Bytes>);

    impl Body for EncodedRequest {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: Pin<&mut Self>,
            _context: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            std::task::Poll::Ready(
                self.get_mut()
                    .0
                    .take()
                    .map(|bytes| Ok(http_body::Frame::data(bytes))),
            )
        }

        fn is_end_stream(&self) -> bool {
            self.0.is_none()
        }
    }

    for response_kind in ["current", "cached", "lookup", "deliver"] {
        let fixture = Fixture::new(ApplicationGrpcConfig::default()).await?;
        let mut client = fixture.client().await?;
        let submitted = pb::SubmitRequest {
            surface_id: "echo".into(),
            payload: Some(value_to_pb(&Value::string("protected result".into()))),
            provenance: None,
            output: None,
            options: Some(pb::SubmitOptions {
                expected_request_scope: Some(fixture.request_scope(&mut client).await?),
                idempotency_key: Some("retained-result".into()),
                ..Default::default()
            }),
        };
        if response_kind != "current" {
            client.submit(request(submitted.clone())?).await?;
        }
        let (path, bytes) = if matches!(response_kind, "lookup" | "deliver") {
            (
                if response_kind == "lookup" {
                    "/xolotl.v1.application.ApplicationGateway/LookupRequest"
                } else {
                    "/xolotl.v1.application.ApplicationGateway/DeliverRequestResult"
                },
                encode_frames(&[pb::LookupRequestRequest {
                    surface_id: "echo".into(),
                    expected_request_scope: submitted
                        .options
                        .as_ref()
                        .and_then(|options| options.expected_request_scope.clone())
                        .context("original scope missing")?,
                    retry_epoch: 0,
                    identity: Some(pb::lookup_request_request::Identity::IdempotencyKey(
                        "retained-result".into(),
                    )),
                }])?,
            )
        } else {
            (SUBMIT_PATH, encode_frames(&[submitted])?)
        };
        let mut ingress = fixture.service.clone().into_server();
        let mut encoded = http::Request::builder()
            .method("POST")
            .uri(format!("http://{}{path}", fixture.authority()))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .header("authorization", format!("Bearer {}", harness::TOKEN))
            .body(tonic::body::Body::new(EncodedRequest(Some(bytes))))?;
        encoded
            .extensions_mut()
            .insert(tonic::transport::server::TcpConnectInfo {
                local_addr: Some(fixture.authority().parse()?),
                remote_addr: Some("127.0.0.1:4000".parse()?),
            });
        let response = ingress.call(encoded).await?;
        ensure!(
            !response.headers().contains_key("grpc-status"),
            "service rejected request: {:?}",
            response.headers()
        );
        let original_usage = fixture.idempotency.usage().await?;
        ensure!(original_usage.records == 1);
        let session = fixture
            .gateway
            .authenticate(PresentedCredential::bearer(harness::TOKEN))
            .await?;
        let descriptor = fixture.gateway.describe(&session)?;
        let target = descriptor
            .surfaces
            .first()
            .context("surface missing")?
            .target
            .clone();
        fixture.gateway.replace_profile(
            GatewayProfile::new("application-test")
                .with_revision(descriptor.profile_rev + 1)
                .with_bearer_identity(
                    "alice-credential",
                    "alice",
                    harness::TOKEN,
                    "identity://alice",
                )?
                .with_registered_host(&fixture.authority())?
                .with_surface(GatewaySurface::effect_invoke("echo", target))
                .with_principal_surface_binding(GatewayPrincipalSurfaceBinding::allow(
                    "alice",
                    ["echo"],
                    ["perform://effect/echo/say"],
                )),
        )?;
        let mut body = response.into_body();
        let frame = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .context("missing withheld-delivery status")??;
        let trailers = frame
            .trailers_ref()
            .context("protected result was disclosed")?;
        ensure!(trailers.get("grpc-status") == Some(&http::HeaderValue::from_static("9")));
        ensure!(
            trailers.get("x-xolotl-error-code")
                == Some(&http::HeaderValue::from_static("outcome_unknown"))
        );
        ensure!(
            poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                .await
                .is_none()
        );
        ensure!(fixture.idempotency.usage().await? == original_usage);
        drop(body);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn describe_and_submit_respect_explicit_retry_epoch_closure() -> anyhow::Result<()> {
    use xolotl_gateway::GatewayIdempotencyStore;

    let fixture = Fixture::new(ApplicationGrpcConfig::default()).await?;
    let mut client = fixture.client().await?;
    ensure!(
        client
            .describe(request(pb::DescribeRequest {})?)
            .await?
            .into_inner()
            .retry_epoch
            == 0
    );
    let mut submission = pb::SubmitRequest {
        surface_id: "echo".into(),
        payload: Some(value_to_pb(&Value::string("once".into()))),
        provenance: None,
        output: None,
        options: Some(pb::SubmitOptions {
            expected_request_scope: Some(fixture.request_scope(&mut client).await?),
            idempotency_key: Some("plain-key".into()),
            ..Default::default()
        }),
    };
    client.submit(request(submission.clone())?).await?;
    ensure!(fixture.idempotency.usage().await?.records == 1);
    ensure!(fixture.idempotency.close_retry_epoch(0).await? == 1);
    ensure!(fixture.idempotency.usage().await?.records == 0);
    ensure!(
        client
            .describe(request(pb::DescribeRequest {})?)
            .await?
            .into_inner()
            .retry_epoch
            == 1
    );
    let old = client
        .submit(request(submission.clone())?)
        .await
        .err()
        .context("closed identity executed")?;
    ensure!(old.code() == Code::InvalidArgument);
    submission.options.as_mut().context("options")?.retry_epoch = 1;
    let first = client
        .submit(request(submission.clone())?)
        .await?
        .into_inner();
    let replay = client.submit(request(submission)?).await?.into_inner();
    ensure!(first.accepted == replay.accepted);
    ensure!(
        replay
            .into_completion()
            .context("scoped replay completion")?
            .origin
            == pb::CompletionOrigin::CachedOutcome as i32
    );
    fixture.close().await
}

#[tokio::test]
async fn unary_submit_applies_grpc_timeout_to_gateway_admission() -> anyhow::Result<()> {
    let fixture = Fixture::new(ApplicationGrpcConfig::default()).await?;
    let raw = fixture.raw().await?;
    let submission = pb::SubmitRequest {
        surface_id: "echo".into(),
        payload: Some(value_to_pb(&Value::string("deadline".into()))),
        provenance: None,
        output: None,
        options: None,
    };
    let response = raw
        .request_with_headers(
            SUBMIT_PATH,
            encode_frames(std::slice::from_ref(&submission))?,
            true,
            &[("grpc-timeout", "301S")],
        )
        .await?
        .response()
        .await?;
    ensure!(response.code == Code::InvalidArgument);
    ensure!(response.frames::<pb::SubmitResponse>()?.is_empty());
    drop(raw);
    let mut client = fixture.client().await?;
    let completed = client
        .submit(request(submission)?)
        .await?
        .into_inner()
        .into_completion()
        .context("submission without timeout did not complete")?;
    ensure!(
        completed.outcome
            == Some(outcome_to_pb(&Outcome::Done(Value::string(
                "deadline".into()
            ))))
    );
    fixture.close().await
}

#[tokio::test]
async fn one_grpc_ticket_submits_two_distinct_uploaded_objects() -> anyhow::Result<()> {
    let fixture = Fixture::new(ApplicationGrpcConfig::default()).await?;
    let mut client = fixture.client().await?;
    let ticket = fixture.issue(&mut client).await?;
    ensure!(ticket.max_objects >= 2);
    let first = client
        .upload_object(request(tokio_stream::iter([
            begin(&ticket.ticket_id),
            harness::chunk(b"first object"),
            finish(),
        ]))?)
        .await?
        .into_inner();
    let second = client
        .upload_object(request(tokio_stream::iter([
            begin(&ticket.ticket_id),
            harness::chunk(b"second object"),
            finish(),
        ]))?)
        .await?
        .into_inner();
    ensure!(first.digest != second.digest);
    let payload = Value::list(vec![
        value_from_pb(first.item.as_ref().context("first item missing")?)?,
        value_from_pb(second.item.as_ref().context("second item missing")?)?,
    ]);
    let request_scope = fixture.request_scope(&mut client).await?;
    let submitted = client
        .submit(request(pb::SubmitRequest {
            surface_id: "echo".into(),
            payload: Some(value_to_pb(&payload)),
            provenance: first.provenance,
            output: None,
            options: Some(pb::SubmitOptions {
                expected_request_scope: Some(request_scope),
                idempotency_key: Some("two-object-submit".into()),
                ..Default::default()
            }),
        })?)
        .await?
        .into_inner();
    ensure!(
        submitted
            .into_completion()
            .context("completion missing")?
            .outcome
            == Some(outcome_to_pb(&Outcome::Done(payload)))
    );
    ensure!(fixture.receipt_flag(&ticket.ticket_id, "used").await?);
    fixture.close().await
}

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
    let item = value_from_pb(uploaded.item.as_ref().context("upload item missing")?)?;
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
        options: Some(pb::SubmitOptions {
            expected_request_scope: Some(fixture.request_scope(&mut client).await?),
            idempotency_key: Some("large-upload-submit".into()),
            ..Default::default()
        }),
    };
    let submitted = client
        .submit(request(submission.clone())?)
        .await?
        .into_inner();
    let completed = submitted
        .into_completion()
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
    let mut new_attempt = submission;
    new_attempt
        .options
        .as_mut()
        .context("submit options missing")?
        .idempotency_key = Some("large-upload-second-attempt".into());
    ensure!(client.submit(request(new_attempt)?).await.is_err());
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
