use super::*;
use crate::session::{ExternalOutbound, drive_external_session};
use anyhow::{Context, bail, ensure};
use prost::Message;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, watch};
use tonic::Code;
use tonic::codegen::tokio_stream::StreamExt;
use tonic::codegen::tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::server::TcpConnectInfo;
use tonic::transport::{Endpoint, Server};
use xolotl_gateway::GatewayTransportSecurityMode;
use xolotl_gateway::external::{
    EndpointSession, EnvelopeAad, ExternalCredential, ExternalSessionHandler,
    ExternalSessionOutbound, SecureEnvelope, SecureEnvelopeEpochGate, SecureEnvelopeReplayWindow,
    external_session_transcript_hash, secure_external_envelope_from_pb,
    secure_external_envelope_to_pb,
};
use xolotl_proto::xolotl::v1 as pb;
use xolotl_proto::xolotl::v1::external::external_service_client::ExternalServiceClient;
use xolotl_proto::{
    command_result_to_pb, control_frame_from_pb, control_frame_to_pb, inbound_event_to_pb,
    invoke_result_to_pb, outbound_command_from_pb, role_ready_to_pb,
    role_session_client_hello_to_pb,
};
use xolotl_types::Value;
use xolotl_types::external::{
    AckStatus, CommandResult, ControlFrame, EventAck, InboundEvent, InvokeResult,
    ObservedGenerations, OutboundCommand, Role, RoleReady, RoleSessionClientHello, SessionContext,
};

struct TestExternalHandler {
    context: SessionContext,
    events: Mutex<Vec<InboundEvent>>,
    controls: Mutex<Vec<ControlFrame>>,
    envelopes: Mutex<Vec<SecureEnvelope>>,
    closed: Mutex<Vec<SessionContext>>,
    outbound: watch::Sender<Option<Arc<dyn ExternalSessionOutbound<Error = Status>>>>,
    command_result: watch::Sender<Option<CommandResult>>,
}

impl TestExternalHandler {
    fn new(role: Role) -> Self {
        Self {
            context: test_session_context(role),
            events: std::sync::Mutex::new(Vec::new()),
            controls: std::sync::Mutex::new(Vec::new()),
            envelopes: std::sync::Mutex::new(Vec::new()),
            closed: std::sync::Mutex::new(Vec::new()),
            outbound: watch::channel(None).0,
            command_result: watch::channel(None).0,
        }
    }
}

fn lock_status<'a, T>(mutex: &'a Mutex<T>, name: &str) -> Result<MutexGuard<'a, T>, Status> {
    mutex
        .lock()
        .map_err(|_error| Status::internal(format!("{name} mutex poisoned")))
}

fn lock_test<'a, T>(mutex: &'a Mutex<T>, name: &str) -> anyhow::Result<MutexGuard<'a, T>> {
    mutex
        .lock()
        .map_err(|_error| anyhow::anyhow!("{name} mutex poisoned"))
}

#[tonic::async_trait]
impl ExternalSessionHandler for TestExternalHandler {
    type Error = Status;
    type OutboundError = Status;

    async fn adjudicate_session(
        &self,
        _hello: &RoleSessionClientHello,
    ) -> Result<SessionContext, Status> {
        Ok(self.context.clone())
    }

    async fn on_ready(
        &self,
        _session: &EndpointSession,
        _context: SessionContext,
        outbound: Arc<dyn ExternalSessionOutbound<Error = Status>>,
    ) -> Result<(), Status> {
        self.outbound.send_replace(Some(outbound));
        Ok(())
    }

    async fn on_inbound_event(
        &self,
        event: InboundEvent,
        _session: &EndpointSession,
        _context: &SessionContext,
    ) -> Result<EventAck, Status> {
        lock_status(&self.events, "events")?.push(event.clone());
        Ok(EventAck {
            id: event.id,
            status: AckStatus::Accepted,
            reject_reason: None,
            stream_epoch: event.stream_epoch,
        })
    }

    async fn on_source_stream_request(
        &self,
        request: xolotl_types::external::SourceStreamRequest,
        _session: &EndpointSession,
        _context: &SessionContext,
    ) -> Result<xolotl_types::external::SourceStreamResult, Status> {
        Ok(xolotl_types::external::SourceStreamResult {
            request_id: request.request_id,
            stream_id: request.stream_id,
            outcome: xolotl_types::external::SourceStreamOutcome::Inspected(
                xolotl_types::external::SourceStreamSnapshot {
                    revision: 0,
                    active: None,
                },
            ),
        })
    }

    async fn on_control(
        &self,
        frame: ControlFrame,
        _session: &EndpointSession,
        _context: &SessionContext,
    ) -> Result<(), Status> {
        lock_status(&self.controls, "controls")?.push(frame);
        Ok(())
    }

    async fn on_command_result(
        &self,
        result: CommandResult,
        _session: &EndpointSession,
        _context: &SessionContext,
    ) -> Result<(), Status> {
        self.command_result.send_replace(Some(result));
        Ok(())
    }

    async fn on_invoke_result(
        &self,
        _result: InvokeResult,
        _session: &EndpointSession,
        _context: &SessionContext,
    ) -> Result<(), Status> {
        Ok(())
    }

    fn on_closed(&self, _session: &EndpointSession, context: SessionContext) -> Result<(), Status> {
        lock_status(&self.closed, "closed")?.push(context);
        self.outbound.send_replace(None);
        Ok(())
    }

    async fn open_secure_envelope(
        &self,
        envelope: &SecureEnvelope,
        _session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<Vec<u8>, Status> {
        lock_status(&self.envelopes, "envelopes")?.push(envelope.clone());
        let epoch_gate = SecureEnvelopeEpochGate::new(context.key_epoch);
        test_credential(context)
            .open_with_replay_window_and_epoch_gate(
                envelope,
                0,
                &mut SecureEnvelopeReplayWindow::default(),
                &epoch_gate,
            )
            .map_err(|_error| Status::permission_denied("secure envelope rejected"))
    }

    async fn seal_secure_envelope(
        &self,
        plaintext: Vec<u8>,
        aad: EnvelopeAad,
        context: &SessionContext,
    ) -> Result<SecureEnvelope, Status> {
        test_credential(context)
            .seal_with_aad(&plaintext, aad)
            .map_err(|_error| Status::internal("secure envelope seal failed"))
    }
}

fn test_credential(context: &SessionContext) -> ExternalCredential {
    ExternalCredential::new(
        &context.installation_id,
        context.credential_generation,
        [0x7a; 32],
    )
}

fn test_session_context(role: Role) -> SessionContext {
    SessionContext {
        installation_id: "install-1".into(),
        projection_id: "projection-1".into(),
        role,
        registry_hash: "registry-hash".into(),
        credential_generation: 1,
        binding_generation: 2,
        installation_config_version: 3,
        projection_version: 4,
        presentation_config_generation: 5,
        alias_catalog_generation: 6,
        session_id: "session-1".into(),
        scope_epoch: u64::from(role == Role::Source),
        installation_epoch: 1,
        key_epoch: 0,
    }
}

fn test_hello(role: Role) -> RoleSessionClientHello {
    RoleSessionClientHello {
        role,
        installation_id: "install-1".into(),
        projection_id: "projection-1".into(),
        registry_hash: "registry-hash".into(),
        observed: ObservedGenerations {
            presentation_config_generation: 5,
            alias_catalog_generation: 6,
        },
        config_schema: None,
    }
}

fn external_hello(role: Role) -> ext::ExternalFrame {
    ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::RoleSessionClientHello(
            role_session_client_hello_to_pb(&test_hello(role)),
        )),
    }
}

fn external_ready(context: &SessionContext) -> anyhow::Result<ext::ExternalFrame> {
    external_secure_frame(
        context,
        "role_ready",
        0,
        ext::external_frame::Frame::RoleReady(role_ready_to_pb(&RoleReady {
            accepted_context: context.clone(),
        })),
    )
}

fn external_event(id: &str) -> ext::ExternalFrame {
    ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::InboundEvent(
            inbound_event_to_pb(&InboundEvent {
                id: id.into(),
                payload: Value::string("hello".into()),
                observed: ObservedGenerations::default(),
                timestamp_ms: 1234,
                stream_id: None,
                seq: None,
                stream_epoch: None,
            }),
        )),
    }
}

fn external_source_stream_inspect() -> ext::ExternalFrame {
    ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::SourceStreamRequest(
            xolotl_proto::source_stream_request_to_pb(
                &xolotl_types::external::SourceStreamRequest {
                    request_id: "inspect-1".into(),
                    stream_id: "records".into(),
                    operation: xolotl_types::external::SourceStreamOperation::Inspect,
                },
            ),
        )),
    }
}

fn external_invoke_result() -> ext::ExternalFrame {
    ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::InvokeResult(
            invoke_result_to_pb(&InvokeResult {
                invocation_id: "invoke-1".into(),
                outcome: Ok(Value::string("ok".into())),
            }),
        )),
    }
}

fn external_secure_envelope(context: &SessionContext) -> anyhow::Result<ext::ExternalFrame> {
    external_secure_envelope_with_type(
        context,
        "control.heartbeat",
        ext::external_frame::Frame::Control(control_frame_to_pb(&ControlFrame::Heartbeat {
            timestamp_ms: 1234,
        })),
    )
}

fn external_secure_envelope_with_type(
    context: &SessionContext,
    frame_type: &str,
    inner: ext::external_frame::Frame,
) -> anyhow::Result<ext::ExternalFrame> {
    external_secure_frame(context, frame_type, 1, inner)
}

fn external_secure_frame(
    context: &SessionContext,
    frame_type: &str,
    seq: u64,
    inner: ext::external_frame::Frame,
) -> anyhow::Result<ext::ExternalFrame> {
    let aad = EnvelopeAad {
        version: 1,
        projection_id: context.projection_id.clone(),
        role: context.role.as_str().into(),
        session_id: context.session_id.clone(),
        seq,
        frame_type: frame_type.into(),
        binding_generation: context.binding_generation,
        credential_generation: context.credential_generation,
        transcript_hash: external_session_transcript_hash(&test_hello(context.role), context)
            .to_vec(),
        key_epoch: 0,
        direction: "client_to_daemon".into(),
    };
    let sealed = test_credential(context).seal_with_aad(
        &ext::ExternalFrame { frame: Some(inner) }.encode_to_vec(),
        aad,
    )?;
    Ok(ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::SecureEnvelope(
            secure_external_envelope_to_pb(sealed),
        )),
    })
}

fn secure_inbound_frame(
    context: &SessionContext,
    frame_type: &str,
    seq: u64,
    frame: ext::ExternalFrame,
) -> anyhow::Result<ext::ExternalFrame> {
    external_secure_frame(
        context,
        frame_type,
        seq,
        frame.frame.context("missing test frame")?,
    )
}

fn opened_output(
    context: &SessionContext,
    frame: &ext::external_frame::Frame,
) -> anyhow::Result<(EnvelopeAad, ext::external_frame::Frame)> {
    let ext::external_frame::Frame::SecureEnvelope(envelope) = frame else {
        bail!("outbound business frame was not sealed");
    };
    let envelope = secure_external_envelope_from_pb(envelope.clone())?;
    ensure!(envelope.aad().direction == "daemon_to_client");
    ensure!(
        envelope.aad().transcript_hash
            == external_session_transcript_hash(&test_hello(context.role), context)
    );
    let plaintext = test_credential(context).open_with_replay_window_and_epoch_gate(
        &envelope,
        0,
        &mut SecureEnvelopeReplayWindow::default(),
        &SecureEnvelopeEpochGate::new(context.key_epoch),
    )?;
    let inner = ext::ExternalFrame::decode(plaintext.as_slice())?;
    Ok((
        envelope.aad().clone(),
        inner.frame.context("missing sealed inner frame")?,
    ))
}

async fn run_external_frames(
    handler: Arc<TestExternalHandler>,
    frames: Vec<ext::ExternalFrame>,
) -> Vec<Result<ext::ExternalFrame, Status>> {
    let (tx, mut rx) = mpsc::channel(8);
    let input = tonic::codegen::tokio_stream::iter(frames.into_iter().map(Ok));
    drive_external_session(input, tx, handler).await;
    let mut out = Vec::new();
    while let Some(frame) = rx.recv().await {
        out.push(frame);
    }
    out
}

fn ok_frame(
    out: &[Result<ext::ExternalFrame, Status>],
    index: usize,
) -> anyhow::Result<&ext::external_frame::Frame> {
    let frame = out
        .get(index)
        .with_context(|| format!("missing output frame {index}"))?
        .as_ref()
        .map_err(|status| anyhow::anyhow!("output frame {index} failed: {status}"))?;
    frame
        .frame
        .as_ref()
        .with_context(|| format!("output frame {index} has no payload"))
}

fn err_status(out: &[Result<ext::ExternalFrame, Status>], index: usize) -> anyhow::Result<&Status> {
    match out
        .get(index)
        .with_context(|| format!("missing output frame {index}"))?
    {
        Ok(_) => bail!("output frame {index} unexpectedly succeeded"),
        Err(status) => Ok(status),
    }
}

#[tokio::test]
async fn external_outbound_reports_backpressure_when_queue_is_full() -> anyhow::Result<()> {
    let (tx, mut rx) = mpsc::channel(1);
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let outbound = ExternalOutbound::from_sender(
        tx,
        handler,
        context.clone(),
        external_session_transcript_hash(&test_hello(Role::Source), &context),
    );

    outbound
        .send_control(ControlFrame::Heartbeat { timestamp_ms: 1 })
        .await?;
    let err = match outbound
        .send_control(ControlFrame::Heartbeat { timestamp_ms: 2 })
        .await
    {
        Ok(()) => bail!("second outbound control frame unexpectedly fit in full queue"),
        Err(err) => err,
    };

    ensure!(
        err.code() == Code::ResourceExhausted,
        "backpressure used wrong status"
    );
    let sent = rx.recv().await.context("missing queued outbound frame")??;
    let (_, ext::external_frame::Frame::Control(control)) = opened_output(
        &context,
        sent.frame.as_ref().context("missing queued frame")?,
    )?
    else {
        bail!("expected control frame");
    };
    ensure!(
        control_frame_from_pb(&control)? == ControlFrame::Heartbeat { timestamp_ms: 1 },
        "queued control frame mismatch"
    );
    outbound
        .send_control(ControlFrame::Heartbeat { timestamp_ms: 3 })
        .await?;
    let sent = rx.recv().await.context("missing next queued frame")??;
    let (aad, _) = opened_output(&context, sent.frame.as_ref().context("missing next frame")?)?;
    ensure!(aad.seq == 2, "failed enqueue reused a sequence");
    outbound.close();
    ensure!(
        outbound
            .send_control(ControlFrame::Heartbeat { timestamp_ms: 4 })
            .await
            .err()
            .is_some_and(|error| error.code() == Code::Cancelled),
        "closed outbound accepted a frame"
    );
    Ok(())
}

#[tokio::test]
async fn external_outbound_concurrency_preserves_wire_sequence() -> anyhow::Result<()> {
    let (tx, mut rx) = mpsc::channel(128);
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let outbound = Arc::new(ExternalOutbound::from_sender(
        tx,
        handler,
        context.clone(),
        external_session_transcript_hash(&test_hello(Role::Provider), &context),
    ));
    let mut jobs = Vec::new();
    for timestamp_ms in 0..96 {
        let outbound = Arc::clone(&outbound);
        jobs.push(tokio::spawn(async move {
            outbound
                .send_control(ControlFrame::Heartbeat { timestamp_ms })
                .await
        }));
    }
    for job in jobs {
        job.await??;
    }
    for expected_seq in 0..96 {
        let frame = rx.recv().await.context("missing concurrent frame")??;
        let (aad, _) = opened_output(&context, frame.frame.as_ref().context("empty frame")?)?;
        ensure!(aad.seq == expected_seq);
    }
    Ok(())
}

#[tokio::test]
async fn cancellation_deadline_includes_wait_for_sender_order() -> anyhow::Result<()> {
    let scope = xolotl_gateway::external::ExternalSessionScope::default();
    let (tx, mut rx) = mpsc::channel(32);
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let outbound = Arc::new(ExternalOutbound::from_sender(
        tx,
        handler,
        context.clone(),
        external_session_transcript_hash(&test_hello(Role::Provider), &context),
    ));
    outbound.start_cancellation(&scope);
    let permit = outbound.send_order.acquire().await?;
    for timestamp_ms in 0..32 {
        outbound.enqueue_cancel(ControlFrame::Heartbeat { timestamp_ms })?;
    }
    ensure!(
        outbound
            .enqueue_cancel(ControlFrame::Heartbeat { timestamp_ms: 32 })
            .is_err()
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    drop(permit);
    tokio::task::yield_now().await;
    ensure!(
        rx.try_recv().is_err(),
        "expired cancellation was delivered after sender wait"
    );
    outbound.enqueue_cancel(ControlFrame::Heartbeat { timestamp_ms: 33 })?;
    tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await?
        .context("fresh cancellation missing")??;
    outbound.close();
    scope.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn oversized_outbound_and_cancellation_frames_never_enter_the_queue() -> anyhow::Result<()> {
    let scope = xolotl_gateway::external::ExternalSessionScope::default();
    let (tx, mut rx) = mpsc::channel(32);
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let outbound = Arc::new(ExternalOutbound::from_sender(
        tx,
        handler,
        context.clone(),
        external_session_transcript_hash(&test_hello(Role::Provider), &context),
    ));
    outbound.start_cancellation(&scope);
    let oversized = ControlFrame::ProviderCancel {
        invocation_id: "invocation".into(),
        reason: "x".repeat(1024 * 1024),
    };
    ensure!(
        outbound
            .send_control(oversized.clone())
            .await
            .err()
            .context("oversized outbound admitted")?
            .code()
            == Code::ResourceExhausted
    );
    ensure!(
        outbound
            .enqueue_cancel(oversized)
            .err()
            .context("oversized notification admitted")?
            .code()
            == Code::ResourceExhausted
    );
    ensure!(rx.try_recv().is_err());
    scope.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn dropping_response_interrupts_pending_inbound_and_closes_partial_handshake()
-> anyhow::Result<()> {
    let scope = Arc::new(xolotl_gateway::external::ExternalSessionScope::new(1));
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let (input_tx, input_rx) = mpsc::channel(4);
    let (tx, rx) = mpsc::channel(4);
    let (done_tx, done) = oneshot::channel();
    let permit = scope.try_admit().context("admission missing")?;
    let weak = Arc::downgrade(&scope);
    let task_handler = handler.clone();
    let abort = scope
        .spawn(async move {
            let _permit = permit;
            crate::session::drive_external_session_scoped(
                ReceiverStream::new(input_rx),
                tx,
                task_handler,
                weak,
            )
            .await;
            done_tx.send(()).unwrap_or(());
        })
        .context("scope closed")?;
    input_tx.send(Ok(external_hello(Role::Source))).await?;
    let mut response = SessionResponseStream::new(rx, done, abort);
    response
        .next()
        .await
        .context("missing selected context")??;
    drop(response);
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if !lock_test(&handler.closed, "closed")?.is_empty() {
                break Ok::<_, anyhow::Error>(());
            }
            tokio::task::yield_now().await;
        }
    })
    .await??;
    ensure!(
        lock_test(&handler.closed, "closed")?.as_slice() == std::slice::from_ref(&handler.context)
    );
    ensure!(
        scope.try_admit().is_some(),
        "aborted reader retained admission"
    );
    drop(input_tx);
    scope.shutdown().await;
    ensure!(lock_test(&handler.closed, "closed")?.len() == 1);
    Ok(())
}

#[tokio::test]
async fn session_response_stream_surfaces_task_failure() -> anyhow::Result<()> {
    let (tx, rx) = mpsc::channel(1);
    drop(tx);
    let scope = xolotl_gateway::external::ExternalSessionScope::default();
    let (done_tx, done) = tokio::sync::oneshot::channel();
    let abort = scope
        .spawn(async move {
            let _done_tx = done_tx;
            std::panic::resume_unwind(Box::new("external grpc test task failure"));
        })
        .context("scope closed")?;
    let mut stream = SessionResponseStream::new(rx, done, abort);
    let err = match stream
        .next()
        .await
        .context("session response stream ended without surfacing task failure")?
    {
        Ok(frame) => bail!("unexpected frame from failed session task: {frame:?}"),
        Err(error) => error,
    };
    ensure!(
        err.code() == Code::Internal,
        "task failure used wrong status: {err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_handshake_and_source_event_ack() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Source),
            external_ready(&context)?,
            secure_inbound_frame(&context, "inbound_event", 1, external_event("event-1"))?,
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    match ok_frame(&out, 0)? {
        ext::external_frame::Frame::SessionContext(ctx) => {
            ensure!(
                ctx.installation_id == "install-1",
                "installation id mismatch"
            );
            ensure!(
                ctx.role == ext::ExternalRole::Source as i32,
                "external role mismatch"
            );
        }
        other => bail!("expected SessionContext, got {other:?}"),
    }
    let (aad, response) = opened_output(&context, ok_frame(&out, 1)?)?;
    ensure!(aad.seq == 0 && aad.frame_type == "event_ack");
    match response {
        ext::external_frame::Frame::EventAck(ack) => {
            ensure!(ack.id == "event-1", "ack id mismatch");
            ensure!(
                ack.status == ext::AckStatus::Accepted as i32,
                "ack status mismatch"
            );
        }
        other => bail!("expected EventAck, got {other:?}"),
    }
    ensure!(
        lock_test(&handler.events, "events")?.len() == 1,
        "handler did not receive exactly one event"
    );
    Ok(())
}

#[tokio::test]
async fn external_grpc_source_command_round_trip_uses_secure_wire_frames() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let mut ready = handler.outbound.subscribe();
    let mut received_result = handler.command_result.subscribe();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = oneshot::channel();
    let server = tokio::spawn(
        Server::builder()
            .add_service(ExternalGrpcService::from_arc(handler.clone()).into_server())
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                drop(stop_rx.await);
            }),
    );

    let channel = Endpoint::from_shared(format!("http://{addr}"))?
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await?;
    let mut client = ExternalServiceClient::new(channel);
    let (input_tx, input_rx) = mpsc::channel(8);
    input_tx.send(external_hello(Role::Source)).await?;
    let mut response = client
        .session(ReceiverStream::new(input_rx))
        .await?
        .into_inner();
    let selected = tokio::time::timeout(Duration::from_secs(10), response.message())
        .await??
        .context("missing session context")?;
    ensure!(matches!(
        selected.frame,
        Some(ext::external_frame::Frame::SessionContext(_))
    ));

    input_tx.send(external_ready(&context)?).await?;
    tokio::time::timeout(Duration::from_secs(10), ready.changed()).await??;
    let outbound = ready
        .borrow_and_update()
        .as_ref()
        .cloned()
        .context("Source sender missing after RoleReady")?;
    let command = OutboundCommand {
        id: "command-1".into(),
        action: Value::string("perform".into()),
        observed: ObservedGenerations {
            presentation_config_generation: context.presentation_config_generation,
            alias_catalog_generation: context.alias_catalog_generation,
        },
    };
    outbound.send_outbound_command(command.clone()).await?;
    let sent = tokio::time::timeout(Duration::from_secs(10), response.message())
        .await??
        .context("missing outbound command")?;
    let (aad, inner) = opened_output(
        &context,
        sent.frame.as_ref().context("empty command frame")?,
    )?;
    ensure!(aad.seq == 0 && aad.frame_type == "outbound_command");
    let ext::external_frame::Frame::OutboundCommand(wire_command) = inner else {
        bail!("Source did not receive an outbound command");
    };
    ensure!(outbound_command_from_pb(&wire_command)? == command);

    let result = CommandResult {
        id: command.id,
        outcome: Ok(Value::boolean(true)),
    };
    input_tx
        .send(secure_inbound_frame(
            &context,
            "command_result",
            1,
            ext::ExternalFrame {
                frame: Some(ext::external_frame::Frame::CommandResult(
                    command_result_to_pb(&result),
                )),
            },
        )?)
        .await?;
    tokio::time::timeout(Duration::from_secs(10), received_result.changed()).await??;
    ensure!(received_result.borrow_and_update().as_ref() == Some(&result));

    drop(outbound);
    drop(input_tx);
    ensure!(
        tokio::time::timeout(Duration::from_secs(10), response.message())
            .await??
            .is_none(),
        "Source stream did not close after input EOF"
    );
    drop(response);
    drop(client);
    stop_tx
        .send(())
        .map_err(|()| anyhow::anyhow!("gRPC server stopped before shutdown"))?;
    tokio::time::timeout(Duration::from_secs(10), server).await???;
    ensure!(lock_test(&handler.closed, "closed")?.as_slice() == [context]);
    Ok(())
}

#[tokio::test]
async fn external_grpc_admission_cancellation_and_scope_shutdown_over_http2() -> anyhow::Result<()>
{
    let scope = Arc::new(xolotl_gateway::external::ExternalSessionScope::new(1));
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = oneshot::channel();
    let service = ExternalGrpcService::from_arc(handler.clone()).with_session_scope(scope.clone());
    let server = tokio::spawn(
        Server::builder()
            .add_service(service.into_server())
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                drop(stop_rx.await);
            }),
    );
    let channel = Endpoint::from_shared(format!("http://{addr}"))?
        .connect()
        .await?;
    let mut client = ExternalServiceClient::new(channel);
    for (index, authenticate_ready) in [false, true].into_iter().enumerate() {
        let (input_tx, input_rx) = mpsc::channel(4);
        input_tx.send(external_hello(Role::Provider)).await?;
        let mut response = client
            .session(ReceiverStream::new(input_rx))
            .await?
            .into_inner();
        tokio::time::timeout(Duration::from_secs(1), response.message())
            .await??
            .context("missing selected context")?;
        let mut ready = handler.outbound.subscribe();
        if authenticate_ready {
            input_tx.send(external_ready(&handler.context)?).await?;
            tokio::time::timeout(Duration::from_secs(1), ready.changed()).await??;
        }
        let (second_tx, second_rx) = mpsc::channel(1);
        let rejected = client
            .session(ReceiverStream::new(second_rx))
            .await
            .err()
            .context("aggregate capacity accepted another session")?;
        ensure!(rejected.code() == Code::ResourceExhausted);
        drop(second_tx);
        drop(response);
        drop(input_tx);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if lock_test(&handler.closed, "closed")?.len() == index + 1
                    && let Some(permit) = scope.try_admit()
                {
                    drop(permit);
                    break Ok::<_, anyhow::Error>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .context("server did not release cancelled session")??;
    }
    let (input_tx, input_rx) = mpsc::channel(4);
    input_tx.send(external_hello(Role::Provider)).await?;
    let mut response = client
        .session(ReceiverStream::new(input_rx))
        .await?
        .into_inner();
    tokio::time::timeout(Duration::from_secs(1), response.message())
        .await??
        .context("missing selected context before shutdown")?;
    let mut ready = handler.outbound.subscribe();
    input_tx.send(external_ready(&handler.context)?).await?;
    tokio::time::timeout(Duration::from_secs(1), ready.changed()).await??;
    scope.shutdown().await;
    ensure!(lock_test(&handler.closed, "closed")?.len() == 3);
    ensure!(scope.try_admit().is_none());
    drop(response);
    drop(input_tx);
    stop_tx
        .send(())
        .map_err(|_send_error| anyhow::anyhow!("server already stopped"))?;
    tokio::time::timeout(Duration::from_secs(1), server).await???;
    Ok(())
}

#[tokio::test]
async fn external_source_stream_request_returns_correlated_result() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let out = run_external_frames(
        handler,
        vec![
            external_hello(Role::Source),
            external_ready(&context)?,
            secure_inbound_frame(
                &context,
                "source_stream_request",
                1,
                external_source_stream_inspect(),
            )?,
        ],
    )
    .await;
    ensure!(out.len() == 2);
    let (aad, ext::external_frame::Frame::SourceStreamResult(result)) =
        opened_output(&context, ok_frame(&out, 1)?)?
    else {
        bail!("missing stream result");
    };
    ensure!(aad.frame_type == "source_stream_result");
    ensure!(result.request_id == "inspect-1" && result.stream_id == "records");
    ensure!(matches!(
        result.outcome,
        Some(ext::source_stream_result::Outcome::Inspected(_))
    ));
    Ok(())
}

#[tokio::test]
async fn external_secure_source_stream_request_binds_its_frame_type() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let inner = external_source_stream_inspect()
        .frame
        .context("missing inspect frame")?;
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Source),
            external_ready(&context)?,
            external_secure_envelope_with_type(&context, "source_stream_request", inner.clone())?,
        ],
    )
    .await;
    ensure!(out.len() == 2);
    ensure!(matches!(
        opened_output(&context, ok_frame(&out, 1)?)?.1,
        ext::external_frame::Frame::SourceStreamResult(_)
    ));
    let bad = run_external_frames(
        handler,
        vec![
            external_hello(Role::Source),
            external_ready(&context)?,
            external_secure_envelope_with_type(&context, "inbound_event", inner)?,
        ],
    )
    .await;
    ensure!(bad.len() == 2);
    let Err(status) = &bad[1] else {
        bail!("mismatched secure Source stream type was accepted");
    };
    ensure!(status.code() == Code::PermissionDenied);
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_malformed_value_before_handler() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let malformed = pb::Value {
        kind: Some(pb::value::Kind::TensorVal(pb::TensorRef {
            blob: Some(pb::BlobRef {
                hash: "tensor-hash".into(),
                size: 8,
                mime: None,
            }),
            dtype: "complex64".into(),
            shape: vec![1],
        })),
    };
    let event = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::InboundEvent(
            ext::InboundEvent {
                id: "event-1".into(),
                payload: Some(malformed),
                timestamp_ms: 1234,
                observed: Some(ext::ObservedGenerations::default()),
                stream_id: None,
                seq: None,
                stream_epoch: None,
            },
        )),
    };
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Source),
            external_ready(&context)?,
            secure_inbound_frame(&context, "inbound_event", 1, event)?,
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        matches!(
            ok_frame(&out, 0)?,
            ext::external_frame::Frame::SessionContext(_)
        ),
        "handshake did not produce session context"
    );
    let status = err_status(&out, 1)?;
    ensure!(
        status.code() == Code::InvalidArgument,
        "malformed value used wrong status"
    );
    ensure!(
        status.message() == "invalid wire value",
        "malformed value used wrong message"
    );
    ensure!(
        lock_test(&handler.events, "events")?.is_empty(),
        "malformed event reached handler"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_close_hook_runs_after_ready_eof() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let out = run_external_frames(
        handler.clone(),
        vec![external_hello(Role::Provider), external_ready(&context)?],
    )
    .await;

    ensure!(out.len() == 1, "unexpected output frame count");
    let closed = lock_test(&handler.closed, "closed")?.clone();
    ensure!(closed == vec![context], "close hook context mismatch");
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_business_before_ready() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let out = run_external_frames(
        handler,
        vec![external_hello(Role::Source), external_event("event-1")],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        matches!(
            ok_frame(&out, 0)?,
            ext::external_frame::Frame::SessionContext(_)
        ),
        "handshake did not produce session context"
    );
    ensure!(
        err_status(&out, 1)?.code() == tonic::Code::Unauthenticated,
        "business-before-ready used wrong status"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_plaintext_ready_and_business() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let plaintext_ready = ext::ExternalFrame {
        frame: Some(ext::external_frame::Frame::RoleReady(role_ready_to_pb(
            &RoleReady {
                accepted_context: context.clone(),
            },
        ))),
    };
    let out = run_external_frames(
        handler.clone(),
        vec![external_hello(Role::Source), plaintext_ready],
    )
    .await;
    ensure!(out.len() == 2 && err_status(&out, 1)?.code() == Code::Unauthenticated);

    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Source),
            external_ready(&context)?,
            external_event("plaintext"),
        ],
    )
    .await;
    ensure!(out.len() == 2 && err_status(&out, 1)?.code() == Code::Unauthenticated);
    ensure!(lock_test(&handler.events, "events")?.is_empty());
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_wrong_role_business_frame() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Source));
    let context = handler.context.clone();
    let out = run_external_frames(
        handler,
        vec![
            external_hello(Role::Source),
            external_ready(&context)?,
            secure_inbound_frame(&context, "invoke_result", 1, external_invoke_result())?,
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        matches!(
            ok_frame(&out, 0)?,
            ext::external_frame::Frame::SessionContext(_)
        ),
        "handshake did not produce session context"
    );
    ensure!(
        err_status(&out, 1)?.code() == tonic::Code::PermissionDenied,
        "wrong-role business frame used wrong status"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_admits_secure_envelope_with_matching_context() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Provider),
            external_ready(&context)?,
            external_secure_envelope(&context)?,
        ],
    )
    .await;

    ensure!(out.len() == 1, "unexpected output frame count");
    ensure!(
        matches!(
            ok_frame(&out, 0)?,
            ext::external_frame::Frame::SessionContext(_)
        ),
        "handshake did not produce session context"
    );
    ensure!(
        lock_test(&handler.envelopes, "envelopes")?.len() == 2,
        "secure envelope was not opened"
    );
    ensure!(
        lock_test(&handler.controls, "controls")?.len() == 1,
        "secure control frame did not reach handler"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_accepts_secure_control_frame_type() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let inner =
        ext::external_frame::Frame::Control(control_frame_to_pb(&ControlFrame::ConfigAck {
            axis: xolotl_types::external::ConfigAxis::InstallationConfig,
            version: context.installation_config_version,
            status: xolotl_types::external::ApplyStatus::Applied,
        }));
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Provider),
            external_ready(&context)?,
            external_secure_envelope_with_type(&context, "control.config_ack", inner)?,
        ],
    )
    .await;

    ensure!(out.len() == 1, "unexpected output frame count");
    ensure!(
        matches!(
            ok_frame(&out, 0)?,
            ext::external_frame::Frame::SessionContext(_)
        ),
        "handshake did not produce session context"
    );
    ensure!(
        lock_test(&handler.controls, "controls")?.len() == 1,
        "secure config ack did not reach handler"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_generic_secure_control_frame_type() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let inner =
        ext::external_frame::Frame::Control(control_frame_to_pb(&ControlFrame::ConfigAck {
            axis: xolotl_types::external::ConfigAxis::InstallationConfig,
            version: context.installation_config_version,
            status: xolotl_types::external::ApplyStatus::Applied,
        }));
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Provider),
            external_ready(&context)?,
            external_secure_envelope_with_type(&context, "control", inner)?,
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        err_status(&out, 1)?.code() == tonic::Code::PermissionDenied,
        "generic secure control type used wrong status"
    );
    ensure!(
        lock_test(&handler.controls, "controls")?.is_empty(),
        "generic secure control frame reached handler"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_secure_envelope_frame_type_mismatch() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let inner = ext::external_frame::Frame::InvokeResult(invoke_result_to_pb(&InvokeResult {
        invocation_id: "invoke-1".into(),
        outcome: Ok(Value::string("ok".into())),
    }));
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Provider),
            external_ready(&context)?,
            external_secure_envelope_with_type(&context, "control", inner)?,
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        err_status(&out, 1)?.code() == tonic::Code::PermissionDenied,
        "secure envelope frame type mismatch used wrong status"
    );
    ensure!(
        lock_test(&handler.controls, "controls")?.is_empty(),
        "mismatched secure envelope frame reached control handler"
    );
    Ok(())
}

#[tokio::test]
async fn external_session_rejects_secure_envelope_context_mismatch() -> anyhow::Result<()> {
    let handler = Arc::new(TestExternalHandler::new(Role::Provider));
    let context = handler.context.clone();
    let mut envelope = external_secure_envelope(&context)?;
    if let Some(ext::external_frame::Frame::SecureEnvelope(envelope)) = envelope.frame.as_mut() {
        envelope.generation = envelope.generation.saturating_add(1);
    }
    let out = run_external_frames(
        handler.clone(),
        vec![
            external_hello(Role::Provider),
            external_ready(&context)?,
            envelope,
        ],
    )
    .await;

    ensure!(out.len() == 2, "unexpected output frame count");
    ensure!(
        err_status(&out, 1)?.code() == tonic::Code::PermissionDenied,
        "secure envelope context mismatch used wrong status"
    );
    ensure!(
        lock_test(&handler.envelopes, "envelopes")?.len() == 1,
        "context-mismatched secure envelope reached handler"
    );
    Ok(())
}

fn request_with_peer(peer: &str) -> anyhow::Result<Request<()>> {
    let mut request = Request::new(());
    request.extensions_mut().insert(TcpConnectInfo {
        local_addr: None,
        remote_addr: Some(peer.parse()?),
    });
    Ok(request)
}

#[test]
fn external_grpc_default_transport_rejects_non_loopback_peer() -> anyhow::Result<()> {
    let svc = ExternalGrpcService::new(TestExternalHandler::new(Role::Source));

    let missing_peer = Request::new(());
    ensure!(
        matches!(svc.source_addr_for_request(&missing_peer), Err(status) if status.code() == Code::PermissionDenied),
        "missing peer was accepted in local-trusted mode"
    );

    let request = request_with_peer("10.0.0.8:7443")?;
    let err = match svc.source_addr_for_request(&request) {
        Ok(_) => bail!("non-loopback peer was accepted in default transport mode"),
        Err(err) => err,
    };
    ensure!(
        err.code() == Code::PermissionDenied,
        "non-loopback peer used wrong status"
    );
    ensure!(
        svc.source_addr_for_request(&request_with_peer("127.0.0.1:7443")?)?
            == Some("127.0.0.1".into()),
        "loopback source address mismatch"
    );
    Ok(())
}

#[test]
fn external_grpc_tls_modes_reject_plain_connections() -> anyhow::Result<()> {
    for mode in [
        GatewayTransportSecurityMode::ProductionTls,
        GatewayTransportSecurityMode::MutualTls,
    ] {
        let svc = ExternalGrpcService::with_config(
            TestExternalHandler::new(Role::Source),
            ExternalGrpcConfig {
                transport_security: GatewayTransportSecurityConfig {
                    mode,
                    ..Default::default()
                },
            },
        );
        let request = request_with_peer("127.0.0.1:7443")?;
        let Err(err) = svc.source_addr_for_request(&request) else {
            bail!("plain connection accepted under TLS policy");
        };
        ensure!(err.code() == Code::PermissionDenied);
    }
    Ok(())
}

#[test]
fn external_grpc_trusted_proxy_uses_forwarded_source_only_from_trusted_peer() -> anyhow::Result<()>
{
    let transport = GatewayTransportSecurityConfig {
        mode: GatewayTransportSecurityMode::TrustedReverseProxy,
        trusted_proxy: xolotl_gateway::GatewayTrustedProxyConfig {
            peers: vec!["127.0.0.1".parse()?],
            ..Default::default()
        },
        unsafe_relaxations: Vec::new(),
    };
    let svc = ExternalGrpcService::with_config(
        TestExternalHandler::new(Role::Source),
        ExternalGrpcConfig {
            transport_security: transport,
        },
    );

    let missing_peer = Request::new(());
    ensure!(
        matches!(svc.source_addr_for_request(&missing_peer), Err(status) if status.code() == Code::PermissionDenied),
        "missing peer was accepted in trusted-proxy mode"
    );

    let mut trusted = request_with_peer("127.0.0.1:7443")?;
    trusted
        .metadata_mut()
        .insert("x-forwarded-for", "203.0.113.9".parse()?);
    trusted
        .metadata_mut()
        .insert("x-forwarded-proto", "https".parse()?);
    ensure!(
        svc.source_addr_for_request(&trusted)? == Some("203.0.113.9".into()),
        "trusted proxy forwarded source mismatch"
    );

    for value in ["203.0.113.9, 10.0.0.4", "not-an-ip, 203.0.113.9"] {
        trusted
            .metadata_mut()
            .insert("x-forwarded-for", value.parse()?);
        ensure!(
            matches!(svc.source_addr_for_request(&trusted), Err(status) if status.code() == Code::PermissionDenied),
            "ambiguous forwarded source {value} was accepted"
        );
    }

    let mut untrusted = request_with_peer("127.0.0.2:7443")?;
    untrusted
        .metadata_mut()
        .insert("x-forwarded-for", "203.0.113.10".parse()?);
    let err = match svc.source_addr_for_request(&untrusted) {
        Ok(_) => bail!("untrusted proxy peer was accepted"),
        Err(err) => err,
    };
    ensure!(
        err.code() == Code::PermissionDenied,
        "untrusted proxy used wrong status"
    );
    Ok(())
}

#[test]
fn external_grpc_rejects_ambiguous_forwarded_protocol() -> anyhow::Result<()> {
    let svc = ExternalGrpcService::with_config(
        TestExternalHandler::new(Role::Source),
        ExternalGrpcConfig {
            transport_security: GatewayTransportSecurityConfig {
                mode: GatewayTransportSecurityMode::TrustedReverseProxy,
                trusted_proxy: xolotl_gateway::GatewayTrustedProxyConfig {
                    peers: vec!["127.0.0.1".parse()?],
                    ..Default::default()
                },
                ..Default::default()
            },
        },
    );
    for (header, value) in [
        ("x-forwarded-proto", "https, http"),
        ("forwarded", "proto=https, proto=http"),
        ("forwarded", "proto=https;proto=http"),
    ] {
        let mut request = request_with_peer("127.0.0.1:7443")?;
        request.metadata_mut().insert(header, value.parse()?);
        ensure!(
            matches!(svc.source_addr_for_request(&request), Err(status) if status.code() == Code::PermissionDenied),
            "ambiguous {header}: {value} was accepted"
        );
    }
    Ok(())
}
