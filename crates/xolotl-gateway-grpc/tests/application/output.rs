use super::harness::{
    EffectOptions, Fixture, OUTPUT_PATH, TEST_WAIT, begin, decode_frames, encode_frames, finish,
    inline_value, output_outcome as outcome_to_pb, output_value, request,
};
use super::ports::{Gate, Pause, ResponseProbe, Signal};
use anyhow::{Context, bail, ensure};
use pb::application_gateway_client::ApplicationGatewayClient;
use pb::submit_output_response::Event;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use tonic::codegen::tokio_stream;
use tonic::transport::Channel;
use tonic::{Code, Streaming};
use xolotl_gateway_grpc::ApplicationGrpcConfig;
use xolotl_kernel::{Driver, DriverContext, DriverError};
use xolotl_proto::xolotl::v1::{self as common, application as pb};
use xolotl_proto::{output_mode_to_pb, path_to_pb, value_from_pb_checked, value_to_pb};
use xolotl_types::{
    DriverOutput, MethodId, Outcome, OutputMode, Path, Purity, TaintSet, TaintSource, TaintedValue,
    Value,
};

const CHUNKS: usize = 193;
const CHUNK_BYTES: usize = 16 * 1024 + 7;

#[derive(Clone, Copy, Debug)]
enum Plan {
    Bytes { count: usize, size: usize },
    Wait,
    InvalidSchema,
    OversizedValue,
    OversizedChunkTaint,
    OversizedCompletionTaint,
}

struct OutputProbe {
    calls: AtomicUsize,
    live: AtomicUsize,
    rejected: AtomicUsize,
    emitted: watch::Sender<usize>,
    entered: Arc<Signal>,
    exited: Arc<Signal>,
}

impl OutputProbe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            live: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
            emitted: watch::channel(0).0,
            entered: Signal::new(),
            exited: Signal::new(),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }

    fn emitted(&self) -> usize {
        *self.emitted.borrow()
    }

    fn sent(&self) {
        self.emitted.send_modify(|count| *count += 1);
    }

    async fn plateau(&self) -> anyhow::Result<usize> {
        let mut progress = self.emitted.subscribe();
        tokio::time::timeout(TEST_WAIT, async {
            loop {
                let count = *progress.borrow_and_update();
                match tokio::time::timeout(Duration::from_millis(100), progress.changed()).await {
                    Ok(result) => result?,
                    Err(_) => {
                        ensure!(count > 0 && self.live.load(Ordering::Acquire) == 1);
                        return Ok(count);
                    }
                }
            }
        })
        .await?
    }
}

struct RunningDriver(Arc<OutputProbe>);

impl Drop for RunningDriver {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::AcqRel);
        self.0.exited.notify();
    }
}

struct OutputDriver {
    plan: Plan,
    probe: Arc<OutputProbe>,
    taint: TaintSet,
}

impl OutputDriver {
    fn new(plan: Plan) -> anyhow::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            plan,
            probe: OutputProbe::new(),
            taint: TaintSet::of(TaintSource::Protected {
                path: Path::parse("state://private/output-test")?,
            }),
        }))
    }
}

#[tonic::async_trait]
impl Driver for OutputDriver {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        if output != OutputMode::Stream {
            return Err(DriverError::UnsupportedOutput(output));
        }
        self.probe.calls.fetch_add(1, Ordering::AcqRel);
        self.probe.live.fetch_add(1, Ordering::AcqRel);
        let _running = RunningDriver(self.probe.clone());
        self.probe.entered.notify();
        if input.as_str() == Some("healthy") {
            ctx.emit(Value::integer(7)).await?;
            self.probe.sent();
            return Ok(DriverOutput::new(Outcome::Done(Value::integer(1))));
        }
        let count = match self.plan {
            Plan::Bytes { count, size } => {
                for index in 0..count {
                    ctx.emit_tainted(TaintedValue::new(
                        Value::bytes(vec![(index % 251) as u8; size]),
                        self.taint.clone(),
                    ))
                    .await?;
                    self.probe.sent();
                }
                count
            }
            Plan::Wait => {
                ctx.emit(Value::integer(7)).await?;
                self.probe.sent();
                return std::future::pending().await;
            }
            Plan::InvalidSchema => {
                ctx.emit(Value::integer(7)).await?;
                self.probe.sent();
                if ctx
                    .emit(Value::string("invalid-output".into()))
                    .await
                    .is_err()
                {
                    self.probe.rejected.fetch_add(1, Ordering::AcqRel);
                }
                1
            }
            Plan::OversizedValue => {
                ctx.emit(Value::bytes(vec![0; 2048])).await?;
                self.probe.sent();
                return std::future::pending().await;
            }
            Plan::OversizedChunkTaint => {
                ctx.emit_tainted(TaintedValue::new(Value::integer(7), oversized_taint()))
                    .await?;
                self.probe.sent();
                return std::future::pending().await;
            }
            Plan::OversizedCompletionTaint => {
                return Ok(DriverOutput::new(Outcome::Done(Value::integer(1)))
                    .with_taint(oversized_taint()));
            }
        };
        Ok(
            DriverOutput::new(Outcome::Done(Value::integer(count as i64)))
                .with_taint(TaintSet::of(TaintSource::ModelOutput)),
        )
    }
}

fn oversized_taint() -> TaintSet {
    TaintSet::of(TaintSource::Fetched {
        host: "x".repeat(2048).into(),
    })
}

fn submission(payload: Value) -> pb::SubmitRequest {
    pb::SubmitRequest {
        surface_id: "echo".into(),
        payload: Some(value_to_pb(&payload)),
        provenance: None,
        output: Some(output_mode_to_pb(OutputMode::Stream)),
        options: None,
    }
}

async fn start(
    client: &mut ApplicationGatewayClient<Channel>,
    submission: pb::SubmitRequest,
) -> anyhow::Result<Streaming<pb::SubmitOutputResponse>> {
    Ok(
        tokio::time::timeout(TEST_WAIT, client.submit_output(request(submission)?))
            .await??
            .into_inner(),
    )
}

async fn next(stream: &mut Streaming<pb::SubmitOutputResponse>) -> anyhow::Result<Option<Event>> {
    tokio::time::timeout(TEST_WAIT, stream.message())
        .await??
        .map(|message| message.event.context("output event missing"))
        .transpose()
}

fn accepted(event: Option<Event>) -> anyhow::Result<pb::GatewayAccepted> {
    let Some(Event::Accepted(accepted)) = event else {
        bail!("Accepted must be the first output event");
    };
    ensure!(accepted.surface_id == "echo");
    ensure!(!accepted.submission_id.is_empty() && !accepted.trace_root.is_empty());
    ensure!(accepted.submission_id != accepted.trace_root);
    Ok(accepted)
}

async fn healthy(fixture: &Fixture) -> anyhow::Result<()> {
    let mut client = fixture.client().await?;
    let mut output = start(&mut client, submission(Value::string("healthy".into()))).await?;
    accepted(next(&mut output).await?)?;
    let Some(Event::Chunk(chunk)) = next(&mut output).await? else {
        bail!("replacement request did not enter its driver");
    };
    ensure!(chunk.item == Some(output_value(&Value::integer(7))));
    let Some(Event::Completed(completed)) = next(&mut output).await? else {
        bail!("replacement request did not complete");
    };
    ensure!(completed.outcome == Some(outcome_to_pb(&Outcome::Done(Value::integer(1)))));
    ensure!(completed.origin == pb::CompletionOrigin::CurrentAttempt as i32);
    ensure!(next(&mut output).await?.is_none());
    Ok(())
}

async fn full(fixture: &Fixture) -> anyhow::Result<()> {
    let error = tokio::time::timeout(
        TEST_WAIT,
        fixture
            .client()
            .await?
            .submit_output(request(submission(Value::null()))?),
    )
    .await?
    .err()
    .context("occupied response window accepted another request")?;
    ensure!(error.code() == Code::ResourceExhausted);
    Ok(())
}

fn has_inbound(taint: &common::TaintSet) -> bool {
    taint.sources.iter().any(|source| {
        matches!(&source.kind, Some(common::taint_source::Kind::Inbound(inbound))
            if !inbound.source.is_empty() && !inbound.channel.is_empty())
    })
}

#[tokio::test]
async fn cumulative_output_preserves_order_taint_and_distinct_final_schema() -> anyhow::Result<()> {
    let driver = OutputDriver::new(Plan::Bytes {
        count: CHUNKS,
        size: CHUNK_BYTES,
    })?;
    let mut effect = EffectOptions::stream(driver.clone(), Purity::Pure);
    effect.output_schema = Some(schema("integer"));
    effect.stream_schema = Some(schema("bytes"));
    let fixture = Fixture::with_effect(ApplicationGrpcConfig::default(), effect, None).await?;
    let mut client = fixture.client().await?;
    let mut output = start(&mut client, submission(Value::null())).await?;
    accepted(next(&mut output).await?)?;
    let protected = path_to_pb(&Path::parse("state://private/output-test")?);
    for index in 0..CHUNKS {
        let Some(Event::Chunk(chunk)) = next(&mut output).await? else {
            bail!("missing chunk {index}");
        };
        let value = value_from_pb_checked(inline_value(
            chunk.item.as_ref().context("chunk item missing")?,
        )?)?;
        let Some(bytes) = value.as_bytes() else {
            bail!("chunk is not bytes")
        };
        ensure!(
            bytes.len() == CHUNK_BYTES && bytes.iter().all(|&byte| byte == (index % 251) as u8)
        );
        let taint = chunk.taint.as_ref().context("chunk taint missing")?;
        ensure!(has_inbound(taint));
        ensure!(taint.sources.iter().any(|source| {
            matches!(&source.kind, Some(common::taint_source::Kind::ProtectedPath(path)) if path == &protected)
        }));
    }
    let Some(Event::Completed(completed)) = next(&mut output).await? else {
        bail!("Completed must follow the last chunk");
    };
    ensure!(
        completed.outcome == Some(outcome_to_pb(&Outcome::Done(Value::integer(CHUNKS as i64))))
    );
    ensure!(completed.origin == pb::CompletionOrigin::CurrentAttempt as i32);
    let taint = completed.taint.context("final taint missing")?;
    ensure!(has_inbound(&taint));
    ensure!(taint.sources.iter().any(|source| matches!(
        source.kind,
        Some(common::taint_source::Kind::ModelOutput(_))
    )));
    ensure!(next(&mut output).await?.is_none());
    ensure!(CHUNKS * CHUNK_BYTES > 3 * 1024 * 1024);
    ensure!(driver.probe.emitted() == CHUNKS && driver.probe.calls() == 1);
    fixture.close().await
}

#[tokio::test]
async fn zero_and_small_http2_windows_bound_emit_progress_until_credit_returns()
-> anyhow::Result<()> {
    for initial_window in [0, 1024] {
        let driver = OutputDriver::new(Plan::Bytes {
            count: CHUNKS,
            size: CHUNK_BYTES,
        })?;
        let fixture = Fixture::with_effect(
            ApplicationGrpcConfig {
                output_window_chunks: 2,
                output_window_bytes: 8 * CHUNK_BYTES + 4096,
                ..Default::default()
            },
            EffectOptions::stream(driver.clone(), Purity::Pure),
            None,
        )
        .await?;
        let raw = fixture.raw_with_window(initial_window).await?;
        let pending = raw
            .request(
                OUTPUT_PATH,
                encode_frames(&[submission(Value::null())])?,
                true,
            )
            .await?;
        let (send, response) = pending.streaming_response().await?;
        ensure!(response.headers().get("grpc-status").is_none());
        driver.probe.entered.wait().await?;
        let plateau = driver.probe.plateau().await?;
        // Hyper's 400 KiB send buffer and tonic's 32 KiB batching are additional
        // bounded owners; transport credit is not a per-chunk client ACK.
        ensure!(
            plateau <= 64,
            "window {initial_window}: {plateau} chunks buffered"
        );
        raw.set_receive_window(64 * 1024).await?;
        let mut body = response.into_body();
        let mut received = 0;
        tokio::time::timeout(TEST_WAIT, async {
            while let Some(data) = body.data().await {
                let data = data?;
                received += data.len();
                body.flow_control().release_capacity(data.len())?;
            }
            let trailers = body.trailers().await?.context("output trailers missing")?;
            ensure!(trailers.get("grpc-status").context("status missing")? == "0");
            anyhow::Ok(())
        })
        .await??;
        ensure!(received > CHUNKS * CHUNK_BYTES);
        ensure!(driver.probe.emitted() == CHUNKS && driver.probe.emitted() > plateau);
        drop(body);
        drop(send);
        drop(raw);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn reset_of_a_flow_control_blocked_response_releases_driver_and_output_permit()
-> anyhow::Result<()> {
    let driver = OutputDriver::new(Plan::Bytes {
        count: CHUNKS,
        size: CHUNK_BYTES,
    })?;
    let fixture = Fixture::with_effect(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            output_window_chunks: 2,
            ..Default::default()
        },
        EffectOptions::stream(driver.clone(), Purity::Pure),
        None,
    )
    .await?;
    let raw = fixture.raw_with_window(0).await?;
    let pending = raw
        .request(
            OUTPUT_PATH,
            encode_frames(&[submission(Value::null())])?,
            true,
        )
        .await?;
    let (mut send, response) = pending.streaming_response().await?;
    driver.probe.entered.wait().await?;
    ensure!(driver.probe.plateau().await? < CHUNKS);
    full(&fixture).await?;
    ensure!(driver.probe.calls() == 1);
    send.send_reset(h2::Reason::CANCEL);
    driver.probe.exited.wait().await?;
    ensure!(driver.probe.live.load(Ordering::Acquire) == 0);
    drop(response);
    drop(send);
    healthy(&fixture).await?;
    ensure!(driver.probe.calls() == 2);
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn completed_short_output_keeps_its_quota_until_the_encoded_body_drops() -> anyhow::Result<()>
{
    for count in [0, 1] {
        let driver = OutputDriver::new(Plan::Bytes { count, size: 13 })?;
        let response_probe = ResponseProbe::new();
        let mut effect = EffectOptions::stream(driver.clone(), Purity::Pure);
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
        let raw = fixture.raw_with_window(0).await?;
        let pending = raw
            .request(
                OUTPUT_PATH,
                encode_frames(&[submission(Value::null())])?,
                true,
            )
            .await?;
        let (mut send, response) = pending.streaming_response().await?;
        ensure!(response.headers().get("grpc-status").is_none());
        driver.probe.exited.wait().await?;
        response_probe.completed.wait().await?;
        ensure!(driver.probe.live.load(Ordering::Acquire) == 0);
        ensure!(driver.probe.calls() == 1 && driver.probe.emitted() == count);
        // Both complete streams fit below tonic's 32 KiB batching threshold:
        // source EOF is consumed while Hyper still holds the encoded DATA.
        full(&fixture).await?;
        send.send_reset(h2::Reason::CANCEL);
        drop(response);
        drop(send);
        response_probe.dropped.wait().await?;
        response_probe.wait_data_released().await?;
        healthy(&fixture).await?;
        ensure!(driver.probe.calls() == 2);
        drop(raw);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn completed_short_output_keeps_its_quota_while_h2_retains_data_after_body_drop()
-> anyhow::Result<()> {
    let driver = OutputDriver::new(Plan::Bytes { count: 1, size: 13 })?;
    let response_probe = ResponseProbe::new();
    let mut effect = EffectOptions::stream(driver.clone(), Purity::Pure);
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
    let raw = fixture.raw_with_window(1).await?;
    let pending = raw
        .request(
            OUTPUT_PATH,
            encode_frames(&[submission(Value::null())])?,
            true,
        )
        .await?;
    let (mut send, response) = pending.streaming_response().await?;
    ensure!(response.headers().get("grpc-status").is_none());
    driver.probe.exited.wait().await?;
    response_probe.completed.wait().await?;
    response_probe.dropped.wait().await?;
    ensure!(driver.probe.live.load(Ordering::Acquire) == 0);
    ensure!(response_probe.retained_data() > 0);
    let mut body = response.into_body();
    let prefix = tokio::time::timeout(TEST_WAIT, body.data())
        .await?
        .context("one-byte response prefix missing")??;
    ensure!(prefix.len() == 1);
    full(&fixture).await?;
    ensure!(driver.probe.calls() == 1 && response_probe.retained_data() > 0);
    send.send_reset(h2::Reason::CANCEL);
    drop(prefix);
    drop(body);
    drop(send);
    response_probe.wait_data_released().await?;
    healthy(&fixture).await?;
    ensure!(driver.probe.calls() == 2);
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn grpc_timeout_remains_active_after_output_response_headers() -> anyhow::Result<()> {
    let driver = OutputDriver::new(Plan::Wait)?;
    let fixture = Fixture::with_effect(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        },
        EffectOptions::stream(driver.clone(), Purity::Pure),
        None,
    )
    .await?;
    let raw = fixture.raw().await?;
    let pending = raw
        .request_with_headers(
            OUTPUT_PATH,
            encode_frames(&[submission(Value::null())])?,
            true,
            &[("grpc-timeout", "1S")],
        )
        .await?;
    let (send, response) = pending.streaming_response().await?;
    ensure!(response.status().is_success());
    ensure!(response.headers().get("grpc-status").is_none());
    driver.probe.entered.wait().await?;
    ensure!(driver.probe.live.load(Ordering::Acquire) == 1);
    let mut body = response.into_body();
    let mut accepted_seen = false;
    let mut chunks = 0;
    tokio::time::timeout(TEST_WAIT, async {
        while let Some(data) = body.data().await {
            let data = data?;
            body.flow_control().release_capacity(data.len())?;
            for message in decode_frames::<pb::SubmitOutputResponse>(&data)? {
                match message.event.context("output event missing")? {
                    Event::Accepted(value) => {
                        ensure!(!accepted_seen && chunks == 0);
                        accepted(Some(Event::Accepted(value)))?;
                        accepted_seen = true;
                    }
                    Event::Chunk(chunk) => {
                        ensure!(accepted_seen && chunks == 0);
                        ensure!(chunk.item == Some(output_value(&Value::integer(7))));
                        chunks += 1;
                    }
                    Event::Completed(_) => bail!("pending driver completed before grpc-timeout"),
                }
            }
        }
        let trailers = body
            .trailers()
            .await?
            .context("deadline trailers missing")?;
        let status = trailers
            .get("grpc-status")
            .context("deadline status missing")?
            .to_str()?
            .parse::<i32>()?;
        ensure!(Code::from_i32(status) == Code::DeadlineExceeded);
        anyhow::Ok(())
    })
    .await??;
    ensure!(accepted_seen && chunks == 1);
    driver.probe.exited.wait().await?;
    ensure!(driver.probe.live.load(Ordering::Acquire) == 0);
    drop(body);
    drop(send);
    healthy(&fixture).await?;
    ensure!(driver.probe.calls() == 2);
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn an_earlier_submission_deadline_is_not_extended_by_grpc_timeout() -> anyhow::Result<()> {
    let driver = OutputDriver::new(Plan::Wait)?;
    let fixture = Fixture::with_effect(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        },
        EffectOptions::stream(driver.clone(), Purity::Pure),
        None,
    )
    .await?;
    let raw = fixture.raw().await?;
    let mut submitted = submission(Value::null());
    submitted.options = Some(pb::SubmitOptions {
        deadline_ms: Some(u64::try_from(
            (SystemTime::now() + Duration::from_millis(300))
                .duration_since(UNIX_EPOCH)?
                .as_millis(),
        )?),
        ..Default::default()
    });
    let response = raw
        .request_with_headers(
            OUTPUT_PATH,
            encode_frames(&[submitted])?,
            true,
            &[("grpc-timeout", "5S")],
        )
        .await?
        .response()
        .await?;
    ensure!(response.code == Code::Ok);
    let mut events = response.frames::<pb::SubmitOutputResponse>()?.into_iter();
    accepted(events.next().and_then(|message| message.event))?;
    let Some(Event::Chunk(chunk)) = events.next().and_then(|message| message.event) else {
        bail!("driver did not emit before the submission deadline");
    };
    ensure!(chunk.item == Some(output_value(&Value::integer(7))));
    let Some(Event::Completed(completed)) = events.next().and_then(|message| message.event) else {
        bail!("submission deadline did not produce its final outcome");
    };
    ensure!(
        completed.outcome
            == Some(outcome_to_pb(&Outcome::Fail(
                xolotl_types::Failure::Timeout
            )))
    );
    ensure!(completed.origin == pb::CompletionOrigin::CurrentAttempt as i32);
    ensure!(events.next().is_none());
    driver.probe.exited.wait().await?;
    ensure!(driver.probe.live.load(Ordering::Acquire) == 0);
    healthy(&fixture).await?;
    ensure!(driver.probe.calls() == 2);
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn grpc_timeout_beyond_the_profile_deadline_limit_is_rejected_before_dispatch()
-> anyhow::Result<()> {
    let driver = OutputDriver::new(Plan::Wait)?;
    let fixture = Fixture::with_effect(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        },
        EffectOptions::stream(driver.clone(), Purity::Pure),
        None,
    )
    .await?;
    let raw = fixture.raw().await?;
    let response = raw
        .request_with_headers(
            OUTPUT_PATH,
            encode_frames(&[submission(Value::null())])?,
            true,
            &[("grpc-timeout", "99999999H")],
        )
        .await?
        .response()
        .await?;
    ensure!(response.code == Code::InvalidArgument);
    ensure!(response.frames::<pb::SubmitOutputResponse>()?.is_empty());
    ensure!(driver.probe.calls() == 0);
    healthy(&fixture).await?;
    ensure!(driver.probe.calls() == 1);
    drop(raw);
    fixture.close().await
}

#[tokio::test]
async fn dropping_tonic_output_cancels_its_driver_and_allows_another_request() -> anyhow::Result<()>
{
    let driver = OutputDriver::new(Plan::Wait)?;
    let fixture = Fixture::with_effect(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        },
        EffectOptions::stream(driver.clone(), Purity::Pure),
        None,
    )
    .await?;
    let mut client = fixture.client().await?;
    let mut output = start(&mut client, submission(Value::null())).await?;
    accepted(next(&mut output).await?)?;
    driver.probe.entered.wait().await?;
    full(&fixture).await?;
    drop(output);
    driver.probe.exited.wait().await?;
    ensure!(driver.probe.live.load(Ordering::Acquire) == 0);
    healthy(&fixture).await?;
    ensure!(driver.probe.calls() == 2);
    fixture.close().await
}

#[tokio::test]
async fn shutdown_cancels_output_driver_and_rejects_new_output_requests() -> anyhow::Result<()> {
    let driver = OutputDriver::new(Plan::Wait)?;
    let fixture = Fixture::with_effect(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        },
        EffectOptions::stream(driver.clone(), Purity::Pure),
        None,
    )
    .await?;
    let mut client = fixture.client().await?;
    let mut output = start(&mut client, submission(Value::null())).await?;
    accepted(next(&mut output).await?)?;
    driver.probe.entered.wait().await?;
    fixture.service.shutdown();
    driver.probe.exited.wait().await?;
    loop {
        match tokio::time::timeout(TEST_WAIT, output.message()).await? {
            Ok(Some(message)) => ensure!(matches!(message.event, Some(Event::Chunk(_)))),
            Ok(None) => bail!("shutdown produced successful output EOF"),
            Err(status) => {
                ensure!(status.code() == Code::Unavailable);
                break;
            }
        }
    }
    let error = start(&mut client, submission(Value::null()))
        .await
        .err()
        .context("shutdown accepted output")?;
    ensure!(
        error
            .downcast_ref::<tonic::Status>()
            .is_some_and(|status| status.code() == Code::Unavailable)
    );
    ensure!(driver.probe.live.load(Ordering::Acquire) == 0 && driver.probe.calls() == 1);
    drop(output);
    fixture.close().await
}

#[tokio::test]
async fn gateway_and_kernel_idempotency_replay_only_cached_final_outcomes() -> anyhow::Result<()> {
    for gateway_key in [true, false] {
        let driver = OutputDriver::new(Plan::Bytes { count: 1, size: 13 })?;
        let fixture = Fixture::with_effect(
            ApplicationGrpcConfig {
                max_concurrent_output_responses: 1,
                ..Default::default()
            },
            EffectOptions::stream(driver.clone(), Purity::Idempotent),
            None,
        )
        .await?;
        let mut submitted = if gateway_key {
            submission(Value::null())
        } else {
            submission(Value::map(BTreeMap::from([(
                "_idem_key".into(),
                Value::string("kernel-stream-key".into()),
            )])))
        };
        if gateway_key {
            submitted.options = Some(pb::SubmitOptions {
                idempotency_key: Some("gateway-stream-key".into()),
                ..Default::default()
            });
        }
        let mut client = fixture.client().await?;
        let mut first = start(&mut client, submitted.clone()).await?;
        let original = accepted(next(&mut first).await?)?;
        ensure!(matches!(next(&mut first).await?, Some(Event::Chunk(_))));
        let Some(Event::Completed(current)) = next(&mut first).await? else {
            bail!("first completion missing")
        };
        ensure!(current.origin == pb::CompletionOrigin::CurrentAttempt as i32);
        ensure!(current.outcome == Some(outcome_to_pb(&Outcome::Done(Value::integer(1)))));
        ensure!(next(&mut first).await?.is_none());
        drop(first);
        let mut replay = start(&mut client, submitted).await?;
        let replayed = accepted(next(&mut replay).await?)?;
        let Some(Event::Completed(cached)) = next(&mut replay).await? else {
            bail!("cache replayed historical chunks")
        };
        if gateway_key {
            ensure!(cached.origin == pb::CompletionOrigin::CachedOutcome as i32);
            ensure!(cached.outcome == current.outcome && replayed == original);
            ensure!(cached.taint == current.taint && cached.taint.is_some());
        } else {
            // A cached invocation does not make this fresh program a request replay.
            ensure!(cached.origin == pb::CompletionOrigin::CurrentAttempt as i32);
            ensure!(
                cached.outcome == Some(outcome_to_pb(&Outcome::Done(Value::integer(1)))),
                "kernel cache request outcome: {:?}",
                cached.outcome
            );
            ensure!(replayed.submission_id != original.submission_id);
            ensure!(cached.taint == current.taint && cached.taint.is_some());
        }
        ensure!(next(&mut replay).await?.is_none());
        ensure!(driver.probe.calls() == 1);
        fixture.close().await?;
    }
    Ok(())
}

fn schema(kind: &str) -> Value {
    Value::map(BTreeMap::from([(
        "type".into(),
        Value::string(kind.into()),
    )]))
}

#[tokio::test]
async fn swallowed_schema_rejection_cannot_leak_invalid_output_or_report_success()
-> anyhow::Result<()> {
    let driver = OutputDriver::new(Plan::InvalidSchema)?;
    let mut effect = EffectOptions::stream(driver.clone(), Purity::Pure);
    effect.stream_schema = Some(schema("integer"));
    let fixture = Fixture::with_effect(
        ApplicationGrpcConfig {
            max_concurrent_output_responses: 1,
            ..Default::default()
        },
        effect,
        None,
    )
    .await?;
    let mut client = fixture.client().await?;
    let mut output = start(&mut client, submission(Value::null())).await?;
    let mut failed = false;
    let mut accepted_seen = false;
    let mut chunks = 0;
    loop {
        match tokio::time::timeout(TEST_WAIT, output.message()).await? {
            Ok(Some(message)) => match message.event.context("event missing")? {
                Event::Accepted(_) => {
                    ensure!(!accepted_seen);
                    accepted_seen = true;
                }
                Event::Chunk(chunk) => {
                    ensure!(accepted_seen && !failed);
                    ensure!(chunk.item == Some(output_value(&Value::integer(7))));
                    chunks += 1;
                    ensure!(chunks <= 1);
                }
                Event::Completed(completed) => {
                    ensure!(accepted_seen && !failed);
                    ensure!(matches!(
                        completed.outcome.and_then(|outcome| outcome.kind),
                        Some(pb::output_outcome::Kind::Fail(_))
                    ));
                    failed = true;
                }
            },
            Ok(None) => break,
            Err(status) => {
                ensure!(status.code() == Code::InvalidArgument);
                failed = true;
                break;
            }
        }
    }
    ensure!(failed && driver.probe.rejected.load(Ordering::Acquire) == 1);
    driver.probe.exited.wait().await?;
    drop(output);
    healthy(&fixture).await?;
    fixture.close().await
}

#[tokio::test]
async fn oversized_output_value_or_taint_fails_conversion_and_releases_response_owner()
-> anyhow::Result<()> {
    for plan in [
        Plan::OversizedValue,
        Plan::OversizedChunkTaint,
        Plan::OversizedCompletionTaint,
    ] {
        let driver = OutputDriver::new(plan)?;
        let fixture = Fixture::with_effect(
            ApplicationGrpcConfig {
                max_frame_bytes: 1024,
                max_concurrent_output_responses: 1,
                output_window_bytes: 16 * 1024,
                ..Default::default()
            },
            EffectOptions::stream(driver.clone(), Purity::Pure),
            None,
        )
        .await?;
        let mut client = fixture.client().await?;
        let mut output = start(&mut client, submission(Value::null())).await?;
        loop {
            match tokio::time::timeout(TEST_WAIT, output.message()).await? {
                Ok(Some(message)) => ensure!(
                    matches!(message.event, Some(Event::Accepted(_))),
                    "{plan:?} escaped its encoding bound"
                ),
                Ok(None) => bail!("{plan:?} completed without an encoding error"),
                Err(status) => {
                    ensure!(
                        status.code() == Code::ResourceExhausted,
                        "{plan:?}: {status}"
                    );
                    break;
                }
            }
        }
        driver.probe.exited.wait().await?;
        ensure!(driver.probe.live.load(Ordering::Acquire) == 0);
        drop(output);
        healthy(&fixture).await?;
        ensure!(driver.probe.calls() == 2);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn reset_during_receipt_consumption_cannot_start_output_driver() -> anyhow::Result<()> {
    for after in [false, true] {
        let gate = Gate::new();
        let driver = OutputDriver::new(Plan::Wait)?;
        let fixture = Fixture::with_effect(
            ApplicationGrpcConfig {
                max_concurrent_output_responses: 1,
                ..Default::default()
            },
            EffectOptions::stream(driver.clone(), Purity::Pure),
            Some(Pause {
                gate: gate.clone(),
                after,
            }),
        )
        .await?;
        let mut client = fixture.client().await?;
        let ticket = fixture.issue(&mut client).await?;
        let uploaded = client
            .upload_object(request(tokio_stream::iter([
                begin(&ticket.ticket_id),
                finish(),
            ]))?)
            .await?
            .into_inner();
        let submitted = pb::SubmitRequest {
            payload: uploaded.item,
            provenance: uploaded.provenance,
            ..submission(Value::null())
        };
        let raw = fixture.raw().await?;
        let mut pending = raw
            .request(OUTPUT_PATH, encode_frames(&[submitted])?, true)
            .await?;
        gate.wait().await?;
        ensure!(driver.probe.calls() == 0);
        ensure!(fixture.receipt_flag(&ticket.ticket_id, "used").await? == after);
        full(&fixture).await?;
        pending.stream.send_reset(h2::Reason::CANCEL);
        gate.wait_exited().await?;
        ensure!(driver.probe.calls() == 0);
        ensure!(fixture.receipt_flag(&ticket.ticket_id, "committed").await?);
        ensure!(fixture.receipt_flag(&ticket.ticket_id, "used").await? == after);
        drop(pending);
        healthy(&fixture).await?;
        ensure!(driver.probe.calls() == 1);
        drop(raw);
        fixture.close().await?;
    }
    Ok(())
}
