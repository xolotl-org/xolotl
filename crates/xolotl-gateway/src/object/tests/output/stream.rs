use super::*;
use crate::{GatewayCancelRequest, GatewayOutputStream, StreamWindow};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll, Waker};
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_types::{MethodId, OutputMode, Purity};

struct EmittingDriver {
    emitted: AtomicUsize,
    count: usize,
}

fn chunk_source(index: usize) -> TaintSource {
    TaintSource::Fetched {
        host: format!("chunk-{index}").into(),
    }
}

#[async_trait::async_trait]
impl Driver for EmittingDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        context: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        for index in 0..self.count {
            context
                .emit_tainted(TaintedValue::new(
                    Value::integer(index as i64),
                    TaintSet::of(chunk_source(index)),
                ))
                .await?;
            self.emitted.fetch_add(1, Ordering::AcqRel);
        }
        Ok(DriverOutput::new(Outcome::Done(Value::null())))
    }
}

async fn fixture() -> anyhow::Result<(Fixture, Arc<EmittingDriver>)> {
    let driver = Arc::new(EmittingDriver {
        emitted: AtomicUsize::new(0),
        count: 3,
    });
    let fixture = Fixture::with_driver(
        MethodSpec::new("invoke", Purity::Effectful, MethodSpec::STREAM_ASYNC),
        driver.clone(),
    )
    .await?;
    Ok((fixture, driver))
}

async fn open(fixture: &Fixture) -> anyhow::Result<GatewayOutputStream> {
    Ok(fixture
        .gateway
        .submit_output_stream(
            &fixture.session,
            GatewaySubmission::direct_input("echo", Value::null())
                .with_requested_output(OutputMode::Stream)
                .with_options(crate::SubmitOptions {
                    idempotency_key: Some("structured-output-stream".into()),
                    ..crate::SubmitOptions::default()
                }),
            StreamWindow {
                max_chunks: NonZeroUsize::MIN,
                max_inline_bytes: NonZeroUsize::MIN.saturating_add(4095),
            },
        )
        .await?)
}

async fn next(stream: &mut GatewayOutputStream) -> anyhow::Result<GatewayOutputEvent> {
    Ok(
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await?
            .context("stream omitted completion")??,
    )
}

fn pending(stream: &mut GatewayOutputStream) -> bool {
    matches!(
        stream.poll_next(&mut TaskContext::from_waker(Waker::noop())),
        Poll::Pending
    )
}

#[tokio::test]
async fn output_owner_retains_one_chunk_credit_through_commit_policy_and_delivery()
-> anyhow::Result<()> {
    let (fixture, driver) = fixture().await?;
    let mut stream = open(&fixture).await?;
    let accepted = stream.accepted().clone();
    let policy = RecordingPolicy::default();
    for index in 0..3 {
        let event = next(&mut stream).await?;
        ensure!(matches!(event, GatewayOutputEvent::Chunk(_)));
        let gate = ports::Gate::new();
        let waiting_policy = RecordingPolicy {
            gate: Some(gate.clone()),
            ..RecordingPolicy::default()
        };
        let mut scratch = [0; 97];
        let mut encoding = Box::pin(fixture.gateway.externalize_output_event(
            &fixture.session,
            &accepted,
            event,
            &mut scratch,
            keys(),
            options(),
            &waiting_policy,
        ));
        tokio::select! {
            result = &mut encoding => bail!("output completed before policy: {:?}", result.map(|_| ())),
            entered = gate.wait() => entered?,
        }
        ensure!(pending(&mut stream));
        ensure!(driver.emitted.load(Ordering::Acquire) == index + 1);
        gate.release();
        let output = encoding.await?;
        ensure!(output.kind() == GatewayOutputKind::Chunk && output.origin().is_none());
        ensure!(output.taint().sources().contains(&chunk_source(index)));
        for previous in 0..index {
            ensure!(
                !output.taint().sources().contains(&chunk_source(previous)),
                "ordinary output retained historical chunk sources"
            );
        }
        output.validate()?;
        ensure!(decode(&fixture, &output).await?.value == Value::integer(index as i64));
        ensure!(pending(&mut stream));
        ensure!(
            driver.emitted.load(Ordering::Acquire) == index + 1,
            "encoding released credit before delivery"
        );
        drop(output);
    }
    let event = next(&mut stream).await?;
    ensure!(matches!(event, GatewayOutputEvent::Complete(_)));
    let mut scratch = [0; 97];
    let output = fixture
        .gateway
        .externalize_output_event(
            &fixture.session,
            &accepted,
            event,
            &mut scratch,
            keys(),
            options(),
            &policy,
        )
        .await?;
    ensure!(output.kind() == GatewayOutputKind::Done);
    for previous in 0..3 {
        ensure!(!output.taint().sources().contains(&chunk_source(previous)));
    }
    drop(output);
    ensure!(stream.next().await.is_none());
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    ensure!(grant_count(&fixture).await? == 4);
    Ok(())
}

#[tokio::test]
async fn cancelled_encoding_or_policy_releases_owned_staging_and_chunk_capacity()
-> anyhow::Result<()> {
    for during_policy in [false, true] {
        let (mut fixture, driver) = fixture().await?;
        let gate = ports::Gate::new();
        if !during_policy {
            let mut probe = ports::ProbeStore::new(fixture.files.clone());
            probe.write_gate = Some(gate.clone());
            fixture.install_probe(Arc::new(probe));
        }
        let policy = RecordingPolicy {
            gate: during_policy.then(|| gate.clone()),
            ..RecordingPolicy::default()
        };
        let mut stream = open(&fixture).await?;
        let accepted = stream.accepted().clone();
        let event = next(&mut stream).await?;
        let mut scratch = [0; 13];
        {
            let mut encoding = Box::pin(fixture.gateway.externalize_output_event(
                &fixture.session,
                &accepted,
                event,
                &mut scratch,
                keys(),
                options(),
                &policy,
            ));
            tokio::select! {
                result = &mut encoding => bail!("operation completed before cancellation: {:?}", result.map(|_| ())),
                entered = gate.wait() => entered?,
            }
            ensure!(pending(&mut stream));
            ensure!(driver.emitted.load(Ordering::Acquire) == 1);
            ensure!(fixture.files.pending_uploads() == usize::from(!during_policy));
            drop(stream);
            ensure!(
                fixture.gateway.requests.inner.lock().global_running == 1,
                "pending output released its request lease"
            );
        }
        ensure!(fixture.files.pending_uploads() == 0);
        ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
        ensure!(grant_count(&fixture).await? == 0);
        if during_policy {
            let blob = policy.observed.lock()[0].1.blob.clone();
            ensure!(
                fixture.files.metadata(&blob).await?.is_some(),
                "cancelled delivery removed published content"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_during_disclosure_cannot_issue_a_chunk_grant() -> anyhow::Result<()> {
    let (fixture, _) = fixture().await?;
    let mut stream = open(&fixture).await?;
    let accepted = stream.accepted().clone();
    let event = next(&mut stream).await?;
    let gate = ports::Gate::new();
    let policy = RecordingPolicy {
        gate: Some(gate.clone()),
        ..RecordingPolicy::default()
    };
    let mut scratch = [0; 97];
    let mut encoding = Box::pin(fixture.gateway.externalize_output_event(
        &fixture.session,
        &accepted,
        event,
        &mut scratch,
        keys(),
        options(),
        &policy,
    ));
    tokio::select! {
        result = &mut encoding => bail!("operation completed before cancellation: {:?}", result.map(|_| ())),
        entered = gate.wait() => entered?,
    }
    ensure!(fixture.gateway.cancel(
        &fixture.session,
        GatewayCancelRequest {
            submission_id: accepted.submission_id.clone(),
            trace_root: accepted.trace_root.clone(),
            reason: None,
        }
    )?);
    gate.release();
    let failure = match encoding.await {
        Ok(_) => bail!("cancelled output was granted"),
        Err(failure) => failure,
    };
    ensure!(failure.taint.sources().contains(&chunk_source(0)));
    ensure!(grant_count(&fixture).await? == 0);
    let GatewayOutputEvent::Complete(result) = next(&mut stream).await? else {
        bail!("cancelled stream delivered another chunk")
    };
    ensure!(result.output.outcome == Outcome::Fail(Failure::Cancelled));
    ensure!(stream.next().await.is_none());
    Ok(())
}

#[tokio::test]
async fn committed_owner_keeps_capacity_after_response_drop_and_rejects_delivery()
-> anyhow::Result<()> {
    let (fixture, _) = fixture().await?;
    let mut stream = open(&fixture).await?;
    let accepted = stream.accepted().clone();
    let event = next(&mut stream).await?;
    let policy = RecordingPolicy::default();
    let mut scratch = [0; 97];
    let output = fixture
        .gateway
        .externalize_output_event(
            &fixture.session,
            &accepted,
            event,
            &mut scratch,
            keys(),
            options(),
            &policy,
        )
        .await?;
    output.validate()?;
    drop(stream);
    ensure!(fixture.gateway.requests.inner.lock().global_running == 1);
    ensure!(output.validate().is_err());
    let blob = output.reference().blob.clone();
    drop(output);
    ensure!(fixture.gateway.requests.inner.lock().global_running == 0);
    ensure!(fixture.files.metadata(&blob).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn cancelled_async_workspace_factory_releases_the_owned_chunk_without_storage_work()
-> anyhow::Result<()> {
    let (fixture, driver) = fixture().await?;
    let mut stream = open(&fixture).await?;
    let accepted = stream.accepted().clone();
    let event = next(&mut stream).await?;
    let Fixture {
        _directory,
        files,
        boot: _boot,
        gateway,
        session,
    } = fixture;
    let gateway = Arc::new(gateway);
    let gate = ports::Gate::new();
    let factory_gate = gate.clone();
    let policy = Arc::new(RecordingPolicy::default());
    let externalizer = gateway.clone().output_externalizer(
        NonZeroUsize::MIN.saturating_add(96),
        options(),
        move || {
            let gate = factory_gate.clone();
            async move {
                gate.enter().await?;
                Ok::<_, xolotl_state::StateFailure>(keys())
            }
        },
        policy.clone(),
    );
    let mut opening: Pin<
        Box<
            dyn Future<
                    Output = Result<
                        GatewayExternalizedOutput,
                        crate::GatewayOutputExternalizationError,
                    >,
                > + Send
                + 'static,
        >,
    > = externalizer.externalize(session, accepted, event);
    tokio::select! {
        result = &mut opening => bail!("workspace opened before release: {:?}", result.map(|_| ())),
        entered = gate.wait() => entered?,
    }
    ensure!(pending(&mut stream));
    ensure!(driver.emitted.load(Ordering::Acquire) == 1);
    ensure!(files.pending_uploads() == 0 && policy.observed.lock().is_empty());
    drop(stream);
    ensure!(gateway.requests.inner.lock().global_running == 1);
    drop(opening);
    ensure!(gateway.requests.inner.lock().global_running == 0);
    ensure!(files.pending_uploads() == 0 && policy.observed.lock().is_empty());
    Ok(())
}
