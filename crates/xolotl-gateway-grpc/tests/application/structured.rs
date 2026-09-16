//! Real gRPC object output, download, and cancellation across host boundaries.

use super::harness::{
    EffectOptions, Fixture, OUTPUT_PATH, TEST_WAIT, TOKEN, encode_frames, output_keys,
    output_outcome, request,
};
use super::ports::{Gate, Pause, ProbeOptions};
use anyhow::{Context, bail, ensure};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Code, Streaming};
use xolotl_gateway::{
    Gateway, GatewayCancelRequest, GatewayError, GatewayOutputDisclosurePolicy,
    GatewayOutputDisclosureRequest, GatewayOutputKind, PresentedCredential,
};
use xolotl_gateway_grpc::ApplicationGrpcConfig;
use xolotl_kernel::{Driver, DriverContext, DriverError};
use xolotl_proto::xolotl::v1::application as pb;
use xolotl_proto::{output_mode_to_pb, value_to_pb};
use xolotl_types::{
    BlobRef, DType, DriverOutput, Failure, FloatBits, MethodId, Outcome, OutputMode, Purity,
    TaintSet, TaintSource, TaintedValue, Value,
    value::event::{MaterializationLimits, ValueBuilder},
};
use xolotl_value_codec::cbor::{DecodeStatus, Decoder};

#[derive(Default)]
struct Disclosure {
    deny: AtomicBool,
    gate: Option<Arc<Gate>>,
    kinds: Mutex<Vec<GatewayOutputKind>>,
}

#[tonic::async_trait]
impl GatewayOutputDisclosurePolicy for Disclosure {
    async fn authorize(
        &self,
        request: GatewayOutputDisclosureRequest<'_>,
    ) -> Result<(), GatewayError> {
        self.kinds
            .lock()
            .map_err(|error| GatewayError::Rejected(format!("test lock: {error}")))?
            .push(request.kind());
        if let Some(gate) = &self.gate {
            gate.block()
                .await
                .map_err(|error| GatewayError::Rejected(error.to_string()))?;
        }
        if self.deny.load(Ordering::Acquire) {
            return Err(GatewayError::Unauthorized("test disclosure denied".into()));
        }
        Ok(())
    }
}

struct Output {
    outcome: Outcome,
    chunk: Option<Value>,
    count: usize,
    wait: bool,
    calls: AtomicUsize,
}

impl Output {
    fn unary(outcome: Outcome) -> Arc<Self> {
        Arc::new(Self {
            outcome,
            chunk: None,
            count: 0,
            wait: false,
            calls: AtomicUsize::new(0),
        })
    }
    fn stream(value: Value, count: usize, wait: bool) -> Arc<Self> {
        Arc::new(Self {
            outcome: Outcome::Done(Value::null()),
            chunk: Some(value),
            count,
            wait,
            calls: AtomicUsize::new(0),
        })
    }
}

#[tonic::async_trait]
impl Driver for Output {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        if let Some(value) = &self.chunk {
            for _ in 0..self.count {
                ctx.emit_tainted(TaintedValue::new(
                    value.clone(),
                    TaintSet::of(TaintSource::ModelOutput),
                ))
                .await?;
            }
        }
        if self.wait {
            return std::future::pending().await;
        }
        Ok(DriverOutput::new(self.outcome.clone())
            .with_taint(TaintSet::of(TaintSource::ModelOutput)))
    }
}

fn config() -> ApplicationGrpcConfig {
    ApplicationGrpcConfig {
        max_frame_bytes: 1024,
        output_window_chunks: 1,
        output_window_bytes: 256 * 1024,
        ..ApplicationGrpcConfig::default()
    }
}

fn submission(stream: bool) -> pb::SubmitRequest {
    pb::SubmitRequest {
        surface_id: "echo".into(),
        payload: Some(value_to_pb(&Value::null())),
        output: Some(output_mode_to_pb(if stream {
            OutputMode::Stream
        } else {
            OutputMode::Unary
        })),
        provenance: None,
        options: Some(pb::SubmitOptions {
            idempotency_key: Some("structured-result".into()),
            ..Default::default()
        }),
    }
}

fn typed_value() -> Value {
    let mut value = Value::list(vec![
        Value::integer(i64::MIN),
        Value::integer(i64::MAX),
        Value::float(FloatBits(f64::from_bits(0x7ff8_0000_0000_1234))),
        Value::bytes((0..=255).cycle().take(65_537).collect()),
        Value::tensor(
            BlobRef {
                hash: "nested-inert-object".into(),
                size: u64::MAX,
                mime: None,
            },
            DType::F64,
            vec![u64::MAX, 0],
        ),
    ]);
    for _ in 0..96 {
        value = Value::list(vec![value]);
    }
    value
}

async fn event(
    output: &mut Streaming<pb::SubmitOutputResponse>,
) -> anyhow::Result<pb::submit_output_response::Event> {
    tokio::time::timeout(TEST_WAIT, output.message())
        .await??
        .context("output EOF")?
        .event
        .context("event missing")
}

fn object(
    outcome: &pb::OutputOutcome,
) -> anyhow::Result<(&pb::EncodedOutputObject, GatewayOutputKind)> {
    use pb::output_outcome::Kind;
    match outcome.kind.as_ref().context("outcome kind missing")? {
        Kind::Done(value) | Kind::Short(value) => {
            let kind = if matches!(&outcome.kind, Some(Kind::Done(_))) {
                GatewayOutputKind::Done
            } else {
                GatewayOutputKind::Short
            };
            let Some(pb::output_value::Content::Object(object)) = &value.content else {
                bail!("value was not externalized")
            };
            Ok((object, kind))
        }
        Kind::Fail(failure) => {
            let Some(pb::output_failure::Content::Object(object)) = &failure.content else {
                bail!("failure was not externalized")
            };
            Ok((object, GatewayOutputKind::Fail))
        }
    }
}

async fn download(
    fixture: &Fixture,
    object: &pb::EncodedOutputObject,
) -> anyhow::Result<TaintedValue> {
    ensure!(object.encoding == "xolotl.value.cbor.v1");
    let blob = object.blob.as_ref().context("object identity missing")?;
    let mut client = fixture.client().await?;
    let mut download = client
        .download_object(request(pb::DownloadObjectRequest {
            read_grant_id: object.read_grant_id.clone(),
            offset: 0,
            length: None,
        })?)
        .await?
        .into_inner();
    let mut decoder = Decoder::new(output_keys(), None);
    let mut builder = ValueBuilder::new(MaterializationLimits::default());
    let mut offset = 0;
    let mut header = false;
    let mut completed = false;
    while let Some(frame) = tokio::time::timeout(TEST_WAIT, download.message()).await?? {
        use pb::download_object_response::Event;
        match frame.event.context("download event missing")? {
            Event::Header(value) => {
                ensure!(!header && value.blob.as_ref() == Some(blob));
                ensure!(value.offset == 0 && value.length == blob.size);
                header = true;
            }
            Event::Chunk(chunk) => {
                ensure!(header && !completed && chunk.offset == offset);
                ensure!(!chunk.data.is_empty() && chunk.data.len() < config().max_frame_bytes);
                offset += chunk.data.len() as u64;
                let mut bytes = chunk.data.as_ref();
                while !bytes.is_empty() {
                    let step = decoder.decode(bytes).await?;
                    ensure!(step.consumed > 0);
                    bytes = &bytes[step.consumed..];
                    if let DecodeStatus::Event(event) = step.status {
                        builder.push(event)?;
                    }
                }
            }
            Event::Completed(value) => {
                ensure!(header && !completed && offset == blob.size);
                ensure!(value.bytes_read == offset && value.next_offset == offset);
                completed = true;
            }
        }
    }
    ensure!(completed && !decoder.is_complete());
    decoder.finish()?;
    Ok(builder.finish()?)
}

#[tokio::test]
async fn unary_objects_preserve_program_results_typed_failures_and_cached_origin()
-> anyhow::Result<()> {
    let value = typed_value();
    let failure = Failure::PolicyViolation {
        policy: "policy-name".into(),
        detail: "诊断🧠".repeat(16_384),
    };
    for outcome in [
        Outcome::Done(value.clone()),
        Outcome::Short(value.clone()),
        Outcome::Fail(failure.clone()),
    ] {
        let driver = Output::unary(outcome.clone());
        let policy = Arc::new(Disclosure::default());
        let fixture = Fixture::with_effect(
            config(),
            EffectOptions::unary(driver.clone(), Purity::Pure).with_disclosure(policy.clone()),
            None,
        )
        .await?;
        let mut client = fixture.client().await?;
        let current = client
            .submit(request(submission(false))?)
            .await?
            .into_inner()
            .completion
            .context("completion missing")?;
        ensure!(current.origin == pb::CompletionOrigin::CurrentAttempt as i32);
        let (reference, kind) = object(current.outcome.as_ref().context("outcome missing")?)?;
        let decoded = download(&fixture, reference).await?;
        ensure!(decoded.taint.sources().contains(&TaintSource::ModelOutput));
        match &outcome {
            Outcome::Done(expected) => {
                ensure!(kind == GatewayOutputKind::Done && decoded.value == *expected)
            }
            Outcome::Short(expected) => {
                // Short is scoped to the invoked operation; the program's
                // successful result is Done before reaching Gateway delivery.
                ensure!(kind == GatewayOutputKind::Done && decoded.value == *expected)
            }
            Outcome::Fail(_) => {
                ensure!(kind == GatewayOutputKind::Fail);
                let fields = decoded
                    .value
                    .as_map()
                    .and_then(|map| map.get("PolicyViolation"))
                    .and_then(Value::as_map)
                    .context("typed failure fields missing")?;
                ensure!(fields.get("policy").and_then(Value::as_str) == Some("policy-name"));
                let Failure::PolicyViolation { detail, .. } = &failure else {
                    bail!("wrong fixture")
                };
                ensure!(fields.get("detail").and_then(Value::as_str) == Some(detail.as_str()));
            }
        }
        let cached = client
            .submit(request(submission(false))?)
            .await?
            .into_inner()
            .completion
            .context("cached completion missing")?;
        ensure!(cached.origin == pb::CompletionOrigin::CachedOutcome as i32);
        let (cached_reference, cached_kind) =
            object(cached.outcome.as_ref().context("cached outcome missing")?)?;
        ensure!(cached_kind == kind && cached_reference.blob == reference.blob);
        ensure!(cached_reference.read_grant_id != reference.read_grant_id);
        ensure!(driver.calls.load(Ordering::Acquire) == 1);
        ensure!(fixture.probe.max_write_bytes() <= 257 && fixture.files.pending_uploads() == 0);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_stream_externalizes_each_large_item_and_keeps_its_real_final_outcome()
-> anyhow::Result<()> {
    let value = typed_value();
    let driver = Output::stream(value.clone(), 17, false);
    let fixture = Fixture::with_effect(
        config(),
        EffectOptions::stream(driver, Purity::Pure)
            .with_disclosure(Arc::new(Disclosure::default())),
        None,
    )
    .await?;
    let mut client = fixture.client().await?;
    let mut output = client
        .submit_output(request(submission(true))?)
        .await?
        .into_inner();
    ensure!(matches!(
        event(&mut output).await?,
        pb::submit_output_response::Event::Accepted(_)
    ));
    for _ in 0..17 {
        let pb::submit_output_response::Event::Chunk(chunk) = event(&mut output).await? else {
            bail!("chunk missing")
        };
        let Some(pb::output_value::Content::Object(reference)) =
            chunk.item.and_then(|value| value.content)
        else {
            bail!("chunk was not externalized")
        };
        ensure!(download(&fixture, &reference).await?.value == value);
    }
    let pb::submit_output_response::Event::Completed(final_result) = event(&mut output).await?
    else {
        bail!("final outcome missing")
    };
    ensure!(final_result.outcome == Some(output_outcome(&Outcome::Done(Value::null()))));
    ensure!(output.message().await?.is_none());
    ensure!(fixture.probe.commits() == 17 && fixture.files.pending_uploads() == 0);
    fixture.close().await
}

#[tokio::test]
async fn externalization_requires_host_installation_and_explicit_disclosure() -> anyhow::Result<()>
{
    let driver = Output::unary(Outcome::Done(Value::bytes(vec![7; 4096])));
    let fixture = Fixture::with_effect(
        config(),
        EffectOptions::unary(driver.clone(), Purity::Pure),
        None,
    )
    .await?;
    let mut client = fixture.client().await?;
    let error = client
        .submit(request(submission(false))?)
        .await
        .err()
        .context("unconfigured object output succeeded")?;
    ensure!(error.code() == Code::ResourceExhausted && fixture.probe.commits() == 0);
    fixture.close().await?;

    let policy = Arc::new(Disclosure {
        deny: AtomicBool::new(true),
        ..Default::default()
    });
    let fixture = Fixture::with_effect(
        config(),
        EffectOptions::unary(driver, Purity::Pure).with_disclosure(policy.clone()),
        None,
    )
    .await?;
    let mut client = fixture.client().await?;
    let error = client
        .submit(request(submission(false))?)
        .await
        .err()
        .context("denied object output succeeded")?;
    ensure!(error.code() == Code::PermissionDenied && fixture.probe.commits() == 1);
    ensure!(fixture.files.pending_uploads() == 0);
    policy.deny.store(false, Ordering::Release);
    let completion = client
        .submit(request(submission(false))?)
        .await?
        .into_inner()
        .completion
        .context("cached completion missing")?;
    ensure!(completion.origin == pb::CompletionOrigin::CachedOutcome as i32);
    let (reference, kind) = object(completion.outcome.as_ref().context("outcome missing")?)?;
    ensure!(
        kind == GatewayOutputKind::Done
            && download(&fixture, reference).await?.value == Value::bytes(vec![7; 4096])
    );
    fixture.close().await
}

#[tokio::test]
async fn request_cancellation_and_deadline_advance_while_disclosure_is_pending()
-> anyhow::Result<()> {
    for deadline in [false, true] {
        let gate = Gate::new();
        let policy = Arc::new(Disclosure {
            gate: Some(gate.clone()),
            ..Default::default()
        });
        let driver = Output::stream(Value::bytes(vec![3; 4096]), 1, true);
        let fixture = Fixture::with_effect(
            config(),
            EffectOptions::stream(driver, Purity::Pure).with_disclosure(policy),
            None,
        )
        .await?;
        let mut client = fixture.client().await?;
        let mut input = submission(true);
        if deadline {
            input
                .options
                .as_mut()
                .context("options missing")?
                .deadline_ms = Some(
                u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())? + 1000,
            );
        }
        let mut output = client.submit_output(request(input)?).await?.into_inner();
        let pb::submit_output_response::Event::Accepted(accepted) = event(&mut output).await?
        else {
            bail!("acceptance missing")
        };
        gate.wait().await?;
        if !deadline {
            let session = fixture
                .gateway
                .authenticate(PresentedCredential::bearer(TOKEN))
                .await?;
            ensure!(fixture.gateway.cancel(
                &session,
                GatewayCancelRequest {
                    submission_id: accepted.submission_id,
                    trace_root: accepted.trace_root,
                    reason: None,
                }
            )?);
        }
        let pb::submit_output_response::Event::Completed(completion) = event(&mut output).await?
        else {
            bail!("interrupted request emitted an object chunk")
        };
        ensure!(
            completion.outcome
                == Some(output_outcome(&Outcome::Fail(if deadline {
                    Failure::Timeout
                } else {
                    Failure::Cancelled
                })))
        );
        ensure!(output.message().await?.is_none());
        gate.wait_exited().await?;
        ensure!(fixture.files.pending_uploads() == 0);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn reset_during_object_encoding_reclaims_staging_and_transport_capacity() -> anyhow::Result<()>
{
    let gate = Gate::new();
    let driver = Output::stream(Value::bytes(vec![5; 4096]), 1, true);
    let fixture = Fixture::with_effect_and_options(
        config(),
        EffectOptions::stream(driver, Purity::Pure)
            .with_disclosure(Arc::new(Disclosure::default())),
        ProbeOptions {
            write: Some(Pause {
                gate: gate.clone(),
                after: true,
            }),
            ..Default::default()
        },
    )
    .await?;
    let raw = fixture.raw().await?;
    let mut rpc = raw
        .request(OUTPUT_PATH, encode_frames(&[submission(true)])?, true)
        .await?;
    gate.wait().await?;
    ensure!(fixture.files.pending_uploads() == 1);
    rpc.stream.send_reset(h2::Reason::CANCEL);
    gate.wait_exited().await?;
    fixture.probe.dropped.wait().await?;
    ensure!(fixture.files.pending_uploads() == 0 && fixture.probe.commits() == 0);
    drop(rpc);
    drop(raw);
    fixture.close().await
}
