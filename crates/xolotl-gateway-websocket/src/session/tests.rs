use super::*;
use crate::ExternalWebSocketService;
use anyhow::{Context, ensure};
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, StatusCode};
use futures_util::FutureExt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Mutex, MutexGuard};
use tower::ServiceExt;
use xolotl_gateway::external::{
    EnvelopeAad, ExternalCredential, SecureEnvelope, SecureEnvelopeEpochGate,
    SecureEnvelopeReplayWindow, external_session_transcript_hash, secure_external_envelope_from_pb,
    secure_external_envelope_to_pb,
};
use xolotl_types::external::{
    AckStatus, CommandResult, EventAck, InboundEvent, InvokeResult, ObservedGenerations, RoleReady,
    RoleSessionClientHello, SessionContext,
};
use xolotl_types::{MethodId, Path, Value};

// Neither error implements std::error::Error or depends on a transport.
#[derive(Debug, Eq, PartialEq)]
enum HandlerError {
    Denied,
    Unexpected,
    Poisoned,
}

#[derive(Debug, Eq, PartialEq)]
enum SendError {
    Backpressured,
    Disconnected,
    InvalidFrame,
    SequenceExhausted,
}

#[derive(Default)]
struct Observed {
    outbound: Option<Arc<dyn ExternalSessionOutbound<Error = SendError>>>,
    events: Vec<InboundEvent>,
    results: Vec<InvokeResult>,
    commands: Vec<CommandResult>,
    closed: usize,
}

// Intentionally not Clone: sharing a service must not clone the handler.
struct Handler {
    context: SessionContext,
    reject_hello: bool,
    observed: Mutex<Observed>,
    inbound_seq: Mutex<u64>,
}

#[tokio::test]
async fn dropping_selected_and_ready_sessions_releases_once() -> anyhow::Result<()> {
    for authenticate_ready in [false, true] {
        let service = service(Role::Source);
        let (tx, mut rx) = mpsc::channel(4);
        let session = if authenticate_ready {
            ready(&service, &tx, &mut rx).await?
        } else {
            let mut session = WebSocketSession::new();
            receive(
                &service,
                &mut session,
                &tx,
                ext::external_frame::Frame::RoleSessionClientHello(
                    xolotl_proto::role_session_client_hello_to_pb(&test_hello(
                        &service.handler.context,
                    )),
                ),
            )
            .await?
            .map_err(|error| anyhow::anyhow!("{error:?}"))?;
            session
        };
        drop(session);
        ensure!(observed(&service.handler)?.closed == 1);
    }
    Ok(())
}

#[tokio::test]
async fn oversized_outbound_and_cancellation_frames_are_rejected() -> anyhow::Result<()> {
    let service = service(Role::Provider);
    let (tx, mut rx) = mpsc::channel(4);
    let session = ready(&service, &tx, &mut rx).await?;
    let sender = session.outbound.as_ref().context("ready sender missing")?;
    sender.start_cancellation(&service.scope);
    let oversized = ControlFrame::ProviderCancel {
        invocation_id: "invocation".into(),
        reason: "x".repeat(crate::DEFAULT_MAX_FRAME_BYTES),
    };
    ensure!(sender.send_control(oversized.clone()).await == Err(SendError::InvalidFrame));
    ensure!(sender.enqueue_cancel(oversized) == Err(SendError::InvalidFrame));
    ensure!(rx.try_recv().is_err());
    drop(session);
    service.scope.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn upgrade_enforces_frame_and_fragmented_message_limits_before_decoding() -> anyhow::Result<()>
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let scope = Arc::new(ExternalSessionScope::new(1));
    let mut service = service(Role::Source).with_session_scope(scope.clone());
    service.config.max_frame_bytes = 1024;
    let service = Arc::new(service);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = Router::new().route("/ws", crate::session_route(service.clone()));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            drop(stop_rx.await);
        })
        .await
    });
    for fragmented in [false, true] {
        let mut socket = tokio::net::TcpStream::connect(addr).await?;
        socket.write_all(format!("GET /ws HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await?;
        let mut response = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !response.ends_with(b"\r\n\r\n") {
                ensure!(response.len() < 4096, "upgrade header overflow");
                response.push(socket.read_u8().await?);
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
        ensure!(
            response.starts_with(b"HTTP/1.1 101"),
            "upgrade rejected: {response:?}"
        );
        if fragmented {
            for opcode in [0x02, 0x00] {
                let mut frame = vec![opcode, 0xfe, 0x02, 0x58, 0, 0, 0, 0];
                frame.resize(608, 0);
                socket.write_all(&frame).await?;
            }
        } else {
            socket
                .write_all(&[0x82, 0xfe, 0x04, 0xb0, 0, 0, 0, 0])
                .await?;
        }
        let mut tail = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            socket.read_to_end(&mut tail),
        )
        .await??;
        ensure!(
            observed(&service.handler)?.closed == 0,
            "oversized pre-hello frame selected a context"
        );
        ensure!(
            scope.try_admit().is_some(),
            "oversized session retained admission"
        );
    }
    scope.shutdown().await;
    stop_tx.send(()).unwrap_or(());
    tokio::time::timeout(std::time::Duration::from_secs(1), server).await???;
    Ok(())
}

impl Handler {
    fn new(role: Role) -> Self {
        Self {
            context: SessionContext {
                installation_id: "installation".into(),
                projection_id: "projection".into(),
                role,
                registry_hash: "registry".into(),
                credential_generation: 2,
                binding_generation: 3,
                installation_config_version: 4,
                projection_version: 5,
                presentation_config_generation: 6,
                alias_catalog_generation: 7,
                session_id: "session".into(),
                scope_epoch: u64::from(role == Role::Source),
                installation_epoch: 1,
                key_epoch: 0,
            },
            reject_hello: false,
            observed: Mutex::new(Observed::default()),
            inbound_seq: Mutex::new(0),
        }
    }

    fn observed(&self) -> Result<MutexGuard<'_, Observed>, HandlerError> {
        self.observed
            .lock()
            .map_err(|_error| HandlerError::Poisoned)
    }
}

#[async_trait::async_trait]
impl ExternalSessionHandler for Handler {
    type Error = HandlerError;
    type OutboundError = SendError;

    async fn adjudicate_session(
        &self,
        _hello: &RoleSessionClientHello,
    ) -> Result<SessionContext, Self::Error> {
        if self.reject_hello {
            return Err(HandlerError::Denied);
        }
        Ok(self.context.clone())
    }

    async fn on_ready(
        &self,
        session: &EndpointSession,
        context: SessionContext,
        outbound: Arc<dyn ExternalSessionOutbound<Error = Self::OutboundError>>,
    ) -> Result<(), Self::Error> {
        if session.phase() != SessionPhase::Ready || context != self.context {
            return Err(HandlerError::Unexpected);
        }
        self.observed()?.outbound = Some(outbound);
        Ok(())
    }

    fn on_closed(
        &self,
        session: &EndpointSession,
        context: SessionContext,
    ) -> Result<(), Self::Error> {
        if session.phase() != SessionPhase::Closed || context != self.context {
            return Err(HandlerError::Unexpected);
        }
        self.observed()?.closed += 1;
        Ok(())
    }

    async fn on_inbound_event(
        &self,
        event: InboundEvent,
        _session: &EndpointSession,
        _context: &SessionContext,
    ) -> Result<EventAck, Self::Error> {
        if event.id == "denied" {
            return Err(HandlerError::Denied);
        }
        let ack = EventAck {
            id: event.id.clone(),
            status: AckStatus::Accepted,
            reject_reason: None,
            stream_epoch: event.stream_epoch,
        };
        self.observed()?.events.push(event);
        Ok(ack)
    }

    async fn on_source_stream_request(
        &self,
        request: xolotl_types::external::SourceStreamRequest,
        _session: &EndpointSession,
        _context: &SessionContext,
    ) -> Result<xolotl_types::external::SourceStreamResult, Self::Error> {
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

    async fn on_command_result(
        &self,
        result: CommandResult,
        _session: &EndpointSession,
        _context: &SessionContext,
    ) -> Result<(), Self::Error> {
        self.observed()?.commands.push(result);
        Ok(())
    }

    async fn on_invoke_result(
        &self,
        result: InvokeResult,
        _session: &EndpointSession,
        _context: &SessionContext,
    ) -> Result<(), Self::Error> {
        self.observed()?.results.push(result);
        Ok(())
    }

    async fn on_control(
        &self,
        _frame: ControlFrame,
        _session: &EndpointSession,
        _context: &SessionContext,
    ) -> Result<(), Self::Error> {
        Err(HandlerError::Unexpected)
    }

    async fn open_secure_envelope(
        &self,
        envelope: &SecureEnvelope,
        _session: &EndpointSession,
        context: &SessionContext,
    ) -> Result<Vec<u8>, Self::Error> {
        test_credential(context)
            .open_with_replay_window_and_epoch_gate(
                envelope,
                0,
                &mut SecureEnvelopeReplayWindow::default(),
                &SecureEnvelopeEpochGate::new(context.key_epoch),
            )
            .map_err(|_error| HandlerError::Denied)
    }

    async fn seal_secure_envelope(
        &self,
        plaintext: Vec<u8>,
        aad: EnvelopeAad,
        context: &SessionContext,
    ) -> Result<SecureEnvelope, Self::OutboundError> {
        test_credential(context)
            .seal_with_aad(&plaintext, aad)
            .map_err(|_error| SendError::InvalidFrame)
    }
}

fn test_credential(context: &SessionContext) -> ExternalCredential {
    ExternalCredential::new(
        &context.installation_id,
        context.credential_generation,
        [0x6a; 32],
    )
}

fn service(role: Role) -> ExternalWebSocketService<Handler> {
    ExternalWebSocketService::new(Handler::new(role), |error| match error {
        OutboundQueueError::Full => SendError::Backpressured,
        OutboundQueueError::Closed => SendError::Disconnected,
        OutboundQueueError::InvalidFrame => SendError::InvalidFrame,
        OutboundQueueError::SequenceExhausted => SendError::SequenceExhausted,
    })
}

fn wire(frame: ext::external_frame::Frame) -> anyhow::Result<ext::ExternalFrame> {
    let bytes = ext::ExternalFrame { frame: Some(frame) }.encode_to_vec();
    decode_message(Ok(Message::Binary(bytes.into())), 4096)?.context("binary frame missing")
}

fn test_hello(context: &SessionContext) -> RoleSessionClientHello {
    RoleSessionClientHello {
        role: context.role,
        installation_id: context.installation_id.clone(),
        projection_id: context.projection_id.clone(),
        registry_hash: context.registry_hash.clone(),
        observed: ObservedGenerations {
            presentation_config_generation: context.presentation_config_generation,
            alias_catalog_generation: context.alias_catalog_generation,
        },
        config_schema: None,
    }
}

fn test_frame_type(frame: &ext::external_frame::Frame) -> anyhow::Result<&'static str> {
    Ok(match frame {
        ext::external_frame::Frame::RoleReady(_) => "role_ready",
        ext::external_frame::Frame::InboundEvent(_) => "inbound_event",
        ext::external_frame::Frame::SourceStreamRequest(_) => "source_stream_request",
        ext::external_frame::Frame::CommandResult(_) => "command_result",
        ext::external_frame::Frame::InvokeResult(_) => "invoke_result",
        ext::external_frame::Frame::Control(control) => match control.kind.as_ref() {
            Some(ext::control_frame::Kind::Heartbeat(_)) => "control.heartbeat",
            Some(ext::control_frame::Kind::ConfigAck(_)) => "control.config_ack",
            _ => anyhow::bail!("unsupported test control kind"),
        },
        _ => anyhow::bail!("unsupported test inbound frame"),
    })
}

fn sealed_input(
    service: &ExternalWebSocketService<Handler>,
    frame: ext::external_frame::Frame,
) -> anyhow::Result<ext::external_frame::Frame> {
    let context = &service.handler.context;
    let seq = {
        let mut next = service
            .handler
            .inbound_seq
            .lock()
            .map_err(|_error| anyhow::anyhow!("inbound seq mutex poisoned"))?;
        let seq = *next;
        *next = next.checked_add(1).context("test inbound seq exhausted")?;
        seq
    };
    let aad = EnvelopeAad {
        version: 1,
        projection_id: context.projection_id.clone(),
        role: context.role.as_str().into(),
        session_id: context.session_id.clone(),
        seq,
        frame_type: test_frame_type(&frame)?.into(),
        binding_generation: context.binding_generation,
        credential_generation: context.credential_generation,
        transcript_hash: external_session_transcript_hash(&test_hello(context), context).to_vec(),
        key_epoch: 0,
        direction: "client_to_daemon".into(),
    };
    let envelope = test_credential(context).seal_with_aad(
        &ext::ExternalFrame { frame: Some(frame) }.encode_to_vec(),
        aad,
    )?;
    Ok(ext::external_frame::Frame::SecureEnvelope(
        secure_external_envelope_to_pb(envelope),
    ))
}

fn opened_output(
    context: &SessionContext,
    frame: ext::ExternalFrame,
) -> anyhow::Result<(EnvelopeAad, ext::external_frame::Frame)> {
    let Some(ext::external_frame::Frame::SecureEnvelope(envelope)) = frame.frame else {
        anyhow::bail!("outbound business frame was not sealed");
    };
    let envelope = secure_external_envelope_from_pb(envelope)?;
    ensure!(envelope.aad().direction == "daemon_to_client");
    ensure!(
        envelope.aad().transcript_hash
            == external_session_transcript_hash(&test_hello(context), context)
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

async fn receive(
    service: &ExternalWebSocketService<Handler>,
    session: &mut WebSocketSession<Handler>,
    tx: &mpsc::Sender<ext::ExternalFrame>,
    frame: ext::external_frame::Frame,
) -> anyhow::Result<Result<(), SessionError<HandlerError>>> {
    let frame = match (&frame, session.endpoint.phase()) {
        (ext::external_frame::Frame::RoleSessionClientHello(_), _)
        | (_, SessionPhase::AwaitingHello) => frame,
        (ext::external_frame::Frame::SecureEnvelope(_), _) => frame,
        _ => sealed_input(service, frame)?,
    };
    Ok(handle_frame(
        session,
        tx,
        &service.handler,
        wire(frame)?,
        service.send_error,
    )
    .await)
}

async fn ready(
    service: &ExternalWebSocketService<Handler>,
    tx: &mpsc::Sender<ext::ExternalFrame>,
    rx: &mut mpsc::Receiver<ext::ExternalFrame>,
) -> anyhow::Result<WebSocketSession<Handler>> {
    let context = &service.handler.context;
    let hello = test_hello(context);
    let mut session = WebSocketSession::new();
    receive(
        service,
        &mut session,
        tx,
        ext::external_frame::Frame::RoleSessionClientHello(
            xolotl_proto::role_session_client_hello_to_pb(&hello),
        ),
    )
    .await??;
    ensure!(session.endpoint.phase() == SessionPhase::AwaitingReady);
    let selected = rx.try_recv()?.frame.context("session context missing")?;
    ensure!(selected == ext::external_frame::Frame::SessionContext(session_context_to_pb(context)));
    receive(
        service,
        &mut session,
        tx,
        ext::external_frame::Frame::RoleReady(xolotl_proto::role_ready_to_pb(&RoleReady {
            accepted_context: context.clone(),
        })),
    )
    .await??;
    ensure!(session.endpoint.phase() == SessionPhase::Ready);
    Ok(session)
}

fn event(id: &str) -> InboundEvent {
    InboundEvent {
        id: id.into(),
        payload: Value::integer(42),
        observed: ObservedGenerations::default(),
        timestamp_ms: 123,
        stream_id: None,
        seq: None,
        stream_epoch: None,
    }
}

fn observed(handler: &Handler) -> anyhow::Result<MutexGuard<'_, Observed>> {
    handler
        .observed()
        .map_err(|error| anyhow::anyhow!("test handler state: {error:?}"))
}

#[tokio::test]
async fn outbound_queue_rejects_full_and_closed_without_waiting() -> anyhow::Result<()> {
    let service = service(Role::Source);
    let (tx, mut rx) = mpsc::channel(1);
    let _session = ready(&service, &tx, &mut rx).await?;
    let outbound = observed(&service.handler)?
        .outbound
        .clone()
        .context("ready sender missing")?;
    let first = ControlFrame::Heartbeat { timestamp_ms: 1 };
    let second = ControlFrame::Heartbeat { timestamp_ms: 2 };
    ensure!(outbound.send_control(first.clone()).await.is_ok());

    let result = outbound
        .send_control(second.clone())
        .now_or_never()
        .context("full outbound queue must not suspend the caller")?;
    ensure!(result == Err(SendError::Backpressured));
    let (first_aad, first_frame) = opened_output(&service.handler.context, rx.try_recv()?)?;
    ensure!(first_aad.seq == 0 && first_aad.frame_type == "control.heartbeat");
    ensure!(first_frame == ext::external_frame::Frame::Control(control_frame_to_pb(&first)));
    ensure!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));

    // Capacity becoming available keeps this sender usable.
    ensure!(outbound.send_control(second.clone()).await.is_ok());
    let (second_aad, second_frame) = opened_output(&service.handler.context, rx.try_recv()?)?;
    ensure!(second_aad.seq == 2);
    ensure!(second_frame == ext::external_frame::Frame::Control(control_frame_to_pb(&second)));
    drop(rx);
    let result = outbound
        .send_control(second)
        .now_or_never()
        .context("closed outbound queue must not suspend the caller")?;
    ensure!(result == Err(SendError::Disconnected));
    Ok(())
}

#[tokio::test]
async fn source_ack_backpressure_returns_to_session_cleanup() -> anyhow::Result<()> {
    let service = service(Role::Source);
    let (tx, mut rx) = mpsc::channel(1);
    let mut session = ready(&service, &tx, &mut rx).await?;
    let queued =
        ext::external_frame::Frame::Control(control_frame_to_pb(&ControlFrame::Heartbeat {
            timestamp_ms: 1,
        }));
    send_frame(&tx, queued.clone())?;
    let input = event("accepted-before-ack");
    let result = receive(
        &service,
        &mut session,
        &tx,
        ext::external_frame::Frame::InboundEvent(xolotl_proto::inbound_event_to_pb(&input)),
    )
    .now_or_never()
    .context("ACK backpressure must not block session cleanup")??;
    ensure!(matches!(
        result,
        Err(SessionError::Outbound(OutboundQueueError::Full))
    ));
    ensure!(observed(&service.handler)?.events == [input]);
    ensure!(rx.try_recv()?.frame == Some(queued));
    close_session(&mut session, service.handler.as_ref());
    ensure!(observed(&service.handler)?.closed == 1);
    ensure!(session.endpoint.admit_business() == Err(SessionReject::Closed));
    Ok(())
}

#[tokio::test]
async fn session_route_can_be_mounted_at_a_host_selected_path() -> anyhow::Result<()> {
    let service = Arc::new(service(Role::Source));
    let app = Router::new().route("/connections/external", crate::session_route(service));
    let peer = SocketAddr::from((Ipv4Addr::LOCALHOST, 12345));
    let request = Request::builder()
        .uri("/connections/external")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
        .extension(ConnectInfo(peer))
        .body(Body::empty())?;
    // A direct Router call has no Hyper upgrade state. Reaching this rejection
    // proves the selected path dispatches to the WebSocket upgrade extractor.
    let response = app.clone().oneshot(request).await?;
    ensure!(response.status() == StatusCode::UPGRADE_REQUIRED);

    let response = app
        .clone()
        .oneshot(Request::builder().uri("/ws").body(Body::empty())?)
        .await?;
    ensure!(response.status() == StatusCode::NOT_FOUND);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/connections/external")
                .body(Body::empty())?,
        )
        .await?;
    ensure!(response.status() == StatusCode::METHOD_NOT_ALLOWED);
    Ok(())
}

#[tokio::test]
async fn custom_handler_runs_source_handshake_frames_and_close() -> anyhow::Result<()> {
    let service = service(Role::Source).clone();
    let (tx, mut rx) = mpsc::channel(4);
    let mut session = ready(&service, &tx, &mut rx).await?;
    let input = event("event");
    receive(
        &service,
        &mut session,
        &tx,
        ext::external_frame::Frame::InboundEvent(xolotl_proto::inbound_event_to_pb(&input)),
    )
    .await??;
    ensure!(observed(&service.handler)?.events == [input]);
    let (aad, ack) = opened_output(&service.handler.context, rx.try_recv()?)?;
    ensure!(aad.seq == 0 && aad.frame_type == "event_ack");
    ensure!(matches!(ack, ext::external_frame::Frame::EventAck(ack) if ack.id == "event"));

    let outbound = observed(&service.handler)?
        .outbound
        .clone()
        .context("ready sender missing")?;
    let command = OutboundCommand {
        id: "command".into(),
        action: Value::string("perform".into()),
        observed: ObservedGenerations::default(),
    };
    ensure!(
        outbound
            .send_outbound_command(command.clone())
            .await
            .is_ok()
    );
    let (aad, sent) = opened_output(&service.handler.context, rx.try_recv()?)?;
    ensure!(aad.seq == 1 && aad.frame_type == "outbound_command");
    ensure!(sent == ext::external_frame::Frame::OutboundCommand(outbound_command_to_pb(&command)));
    let result = CommandResult {
        id: command.id,
        outcome: Ok(Value::boolean(true)),
    };
    receive(
        &service,
        &mut session,
        &tx,
        ext::external_frame::Frame::CommandResult(xolotl_proto::command_result_to_pb(&result)),
    )
    .await??;
    ensure!(observed(&service.handler)?.commands == [result]);
    let heartbeat = ControlFrame::Heartbeat { timestamp_ms: 456 };
    ensure!(outbound.send_control(heartbeat.clone()).await.is_ok());
    let (aad, sent) = opened_output(&service.handler.context, rx.try_recv()?)?;
    ensure!(aad.seq == 2 && aad.frame_type == "control.heartbeat");
    ensure!(sent == ext::external_frame::Frame::Control(control_frame_to_pb(&heartbeat)));

    drop(rx);
    ensure!(
        outbound.send_control(heartbeat).await == Err(SendError::Disconnected),
        "closed sender must return the host's own error"
    );
    close_session(&mut session, service.handler.as_ref());
    ensure!(session.endpoint.admit_business() == Err(SessionReject::Closed));
    ensure!(observed(&service.handler)?.closed == 1);
    Ok(())
}

#[tokio::test]
async fn websocket_routes_source_stream_lifecycle_and_rejects_provider_role() -> anyhow::Result<()>
{
    let request = xolotl_types::external::SourceStreamRequest {
        request_id: "inspect-1".into(),
        stream_id: "records".into(),
        operation: xolotl_types::external::SourceStreamOperation::Inspect,
    };
    let frame = ext::external_frame::Frame::SourceStreamRequest(
        xolotl_proto::source_stream_request_to_pb(&request),
    );
    let source = service(Role::Source);
    let (tx, mut rx) = mpsc::channel(4);
    let mut session = ready(&source, &tx, &mut rx).await?;
    receive(&source, &mut session, &tx, frame.clone()).await??;
    let (aad, ext::external_frame::Frame::SourceStreamResult(result)) =
        opened_output(&source.handler.context, rx.try_recv()?)?
    else {
        anyhow::bail!("missing Source stream result");
    };
    ensure!(aad.frame_type == "source_stream_result");
    ensure!(result.request_id == request.request_id);
    ensure!(matches!(
        result.outcome,
        Some(ext::source_stream_result::Outcome::Inspected(_))
    ));

    let provider = service(Role::Provider);
    let (tx, mut rx) = mpsc::channel(4);
    let mut session = ready(&provider, &tx, &mut rx).await?;
    ensure!(matches!(
        receive(&provider, &mut session, &tx, frame).await?,
        Err(SessionError::Frame(
            ExternalFrameError::ExternalRoleFrameRejected
        ))
    ));
    Ok(())
}

#[tokio::test]
async fn custom_handler_runs_provider_invocation_roundtrip() -> anyhow::Result<()> {
    let service = service(Role::Provider);
    let (tx, mut rx) = mpsc::channel(4);
    let mut session = ready(&service, &tx, &mut rx).await?;
    let outbound = observed(&service.handler)?
        .outbound
        .clone()
        .context("ready sender missing")?;
    let invoke = Invoke {
        invocation_id: "invocation".into(),
        effect_path: Path::parse("effect://custom/invoke")?,
        method_id: MethodId::new(17),
        input: Value::integer(21),
        deadline_ms: Some(5000),
        output_stream_to: None,
    };
    ensure!(outbound.send_invoke(invoke.clone()).await.is_ok());
    let (aad, sent) = opened_output(&service.handler.context, rx.try_recv()?)?;
    ensure!(aad.seq == 0 && aad.frame_type == "invoke");
    ensure!(sent == ext::external_frame::Frame::Invoke(invoke_to_pb(&invoke)));
    let result = InvokeResult {
        invocation_id: invoke.invocation_id,
        outcome: Ok(Value::integer(42)),
    };
    receive(
        &service,
        &mut session,
        &tx,
        ext::external_frame::Frame::InvokeResult(xolotl_proto::invoke_result_to_pb(&result)),
    )
    .await??;
    ensure!(observed(&service.handler)?.results == [result]);
    close_session(&mut session, service.handler.as_ref());
    ensure!(observed(&service.handler)?.closed == 1);
    ensure!(
        outbound
            .send_control(ControlFrame::Heartbeat { timestamp_ms: 8 })
            .await
            == Err(SendError::Disconnected)
    );
    Ok(())
}

#[tokio::test]
async fn websocket_rejects_plaintext_ready_and_business_frames() -> anyhow::Result<()> {
    let service = service(Role::Source);
    let (tx, mut rx) = mpsc::channel(4);
    let mut session = WebSocketSession::new();
    receive(
        &service,
        &mut session,
        &tx,
        ext::external_frame::Frame::RoleSessionClientHello(
            xolotl_proto::role_session_client_hello_to_pb(&test_hello(&service.handler.context)),
        ),
    )
    .await??;
    let _context = rx.try_recv()?;
    let plaintext_ready =
        ext::external_frame::Frame::RoleReady(xolotl_proto::role_ready_to_pb(&RoleReady {
            accepted_context: service.handler.context.clone(),
        }));
    ensure!(matches!(
        handle_frame(
            &mut session,
            &tx,
            &service.handler,
            wire(plaintext_ready)?,
            service.send_error
        )
        .await,
        Err(SessionError::Protocol(
            "RoleReady requires a secure envelope"
        ))
    ));

    let mut session = ready(&service, &tx, &mut rx).await?;
    ensure!(matches!(
        handle_frame(
            &mut session,
            &tx,
            &service.handler,
            wire(ext::external_frame::Frame::InboundEvent(
                xolotl_proto::inbound_event_to_pb(&event("plaintext"))
            ))?,
            service.send_error,
        )
        .await,
        Err(SessionError::Frame(
            ExternalFrameError::PlaintextBusinessRejected
        ))
    ));
    ensure!(observed(&service.handler)?.events.is_empty());
    Ok(())
}

#[tokio::test]
async fn websocket_rejects_reflected_daemon_envelope() -> anyhow::Result<()> {
    let service = service(Role::Source);
    let (tx, mut rx) = mpsc::channel(4);
    let mut session = ready(&service, &tx, &mut rx).await?;
    let sender = session
        .outbound
        .as_ref()
        .context("ready outbound missing")?;
    ensure!(
        sender
            .send_control(ControlFrame::Heartbeat { timestamp_ms: 9 })
            .await
            .is_ok()
    );
    let reflected = rx.try_recv()?;
    ensure!(matches!(
        handle_frame(
            &mut session,
            &tx,
            &service.handler,
            reflected,
            service.send_error
        )
        .await,
        Err(SessionError::Frame(
            ExternalFrameError::SecureEnvelopeContextRejected
        ))
    ));
    Ok(())
}

#[tokio::test]
async fn websocket_outbound_sequence_exhaustion_fails_closed() -> anyhow::Result<()> {
    let service = service(Role::Provider);
    let (tx, mut rx) = mpsc::channel(4);
    let session = ready(&service, &tx, &mut rx).await?;
    let sender = session
        .outbound
        .as_ref()
        .context("ready outbound missing")?;
    sender.next_seq.store(u64::MAX, Ordering::Relaxed);
    let result = sender
        .send_control(ControlFrame::Heartbeat { timestamp_ms: 1 })
        .await;
    ensure!(result == Err(SendError::SequenceExhausted));
    ensure!(sender.next_seq.load(Ordering::Relaxed) == u64::MAX);
    ensure!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    sender.close();
    ensure!(
        sender
            .send_control(ControlFrame::Heartbeat { timestamp_ms: 2 })
            .await
            == Err(SendError::Disconnected)
    );
    Ok(())
}

#[tokio::test]
async fn session_guards_and_typed_handler_rejection_precede_delivery() -> anyhow::Result<()> {
    let service = service(Role::Source);
    let (tx, mut rx) = mpsc::channel(4);
    let mut session = WebSocketSession::new();
    let input = event("event");
    let frame = ext::external_frame::Frame::InboundEvent(xolotl_proto::inbound_event_to_pb(&input));
    ensure!(matches!(
        receive(&service, &mut session, &tx, frame).await?,
        Err(SessionError::Frame(
            ExternalFrameError::PlaintextBusinessRejected
        ))
    ));
    ensure!(observed(&service.handler)?.events.is_empty());
    session = ready(&service, &tx, &mut rx).await?;
    let mut stale = event("stale");
    stale.observed.presentation_config_generation = 100;
    ensure!(matches!(
        receive(
            &service,
            &mut session,
            &tx,
            ext::external_frame::Frame::InboundEvent(xolotl_proto::inbound_event_to_pb(&stale)),
        )
        .await?,
        Err(SessionError::Session(SessionReject::StaleGeneration))
    ));
    let wrong_role = InvokeResult {
        invocation_id: "forged".into(),
        outcome: Ok(Value::null()),
    };
    ensure!(matches!(
        receive(
            &service,
            &mut session,
            &tx,
            ext::external_frame::Frame::InvokeResult(xolotl_proto::invoke_result_to_pb(
                &wrong_role
            )),
        )
        .await?,
        Err(SessionError::Frame(
            ExternalFrameError::ExternalRoleFrameRejected
        ))
    ));
    ensure!(observed(&service.handler)?.results.is_empty());
    ensure!(matches!(
        receive(
            &service,
            &mut session,
            &tx,
            ext::external_frame::Frame::InboundEvent(xolotl_proto::inbound_event_to_pb(&event(
                "denied"
            ))),
        )
        .await?,
        Err(SessionError::Handler(HandlerError::Denied))
    ));
    ensure!(observed(&service.handler)?.events.is_empty());
    ensure!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    close_session(&mut session, service.handler.as_ref());
    ensure!(observed(&service.handler)?.closed == 1);
    Ok(())
}

#[test]
fn websocket_decoder_keeps_frame_and_size_requirements() -> anyhow::Result<()> {
    ensure!(decode_message(Ok(Message::Ping(Vec::new().into())), 4)?.is_none());
    ensure!(matches!(
        decode_message(Ok(Message::Text("not protobuf".into())), 4096),
        Err(SessionError::Protocol(_))
    ));
    ensure!(matches!(
        decode_message(Ok(Message::Binary(vec![0xff].into())), 4096),
        Err(SessionError::Decode(_))
    ));
    ensure!(matches!(
        decode_message(Ok(Message::Binary(vec![0; 5].into())), 4),
        Err(SessionError::Protocol(_))
    ));
    ensure!(matches!(
        decode_message(Ok(Message::Close(None)), 4096),
        Err(SessionError::Closed)
    ));
    Ok(())
}
