use crate::ExternalWebSocketService;
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, mpsc};
use tonic::Status;
use xolotl_gateway::external::{
    EndpointSession, ExternalFrameError, ExternalFrameOrigin, ExternalInboundFrame,
    ExternalSessionHandler, ExternalSessionOutbound, SessionPhase, SessionReject,
    external_inbound_frame_from_pb, ready_external_session_context, require_external_role,
    secure_external_envelope_from_pb, validate_secure_external_envelope_context,
    validate_secure_external_inner_frame_type,
};
use xolotl_proto::xolotl::v1::external as ext;
use xolotl_proto::{
    control_frame_to_pb, event_ack_to_pb, invoke_to_pb, outbound_command_to_pb, role_ready_from_pb,
    role_session_client_hello_from_pb, session_context_to_pb,
};
use xolotl_types::external::{ControlFrame, Invoke, OutboundCommand, Role};

/// Daemon-to-external frame sender for one ready Provider or Source session.
#[derive(Clone)]
struct ExternalWebSocketOutbound {
    tx: mpsc::Sender<ext::ExternalFrame>,
}

impl ExternalWebSocketOutbound {
    /// Create an outbound sender from the WebSocket writer channel.
    fn from_sender(tx: mpsc::Sender<ext::ExternalFrame>) -> Self {
        Self { tx }
    }

    /// Send one Provider invoke to the connected endpoint.
    async fn send_invoke(&self, invoke: Invoke) -> Result<(), Status> {
        self.send(ext::external_frame::Frame::Invoke(invoke_to_pb(&invoke)))
            .await
    }

    /// Send one Source outbound command to the connected endpoint.
    async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), Status> {
        self.send(ext::external_frame::Frame::OutboundCommand(
            outbound_command_to_pb(&command),
        ))
        .await
    }

    /// Send one control frame to the connected endpoint.
    async fn send_control(&self, frame: ControlFrame) -> Result<(), Status> {
        self.send(ext::external_frame::Frame::Control(control_frame_to_pb(
            &frame,
        )))
        .await
    }

    async fn send(&self, frame: ext::external_frame::Frame) -> Result<(), Status> {
        self.tx
            .send(ext::ExternalFrame { frame: Some(frame) })
            .await
            .map_err(|_error| Status::unavailable("external WebSocket session closed"))
    }
}

#[tonic::async_trait]
impl ExternalSessionOutbound for ExternalWebSocketOutbound {
    type Error = Status;

    async fn send_invoke(&self, invoke: Invoke) -> Result<(), Self::Error> {
        ExternalWebSocketOutbound::send_invoke(self, invoke).await
    }

    async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), Self::Error> {
        ExternalWebSocketOutbound::send_outbound_command(self, command).await
    }

    async fn send_control(&self, frame: ControlFrame) -> Result<(), Self::Error> {
        ExternalWebSocketOutbound::send_control(self, frame).await
    }
}

pub(crate) async fn drive_socket<H>(
    socket: WebSocket,
    service: Arc<ExternalWebSocketService<H>>,
    _permit: OwnedSemaphorePermit,
) where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    let (mut writer, mut reader) = socket.split();
    let (tx, mut rx) = mpsc::channel::<ext::ExternalFrame>(32);
    let mut write_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let mut bytes = Vec::with_capacity(frame.encoded_len());
            if let Err(error) = frame.encode(&mut bytes) {
                tracing::warn!(?error, "external WebSocket frame encode failed");
                break;
            }
            if let Err(error) = writer.send(Message::Binary(bytes.into())).await {
                tracing::warn!(?error, "external WebSocket send failed");
                break;
            }
        }
    });

    let mut session = EndpointSession::new();
    loop {
        let timeout_ms = if session.phase() == SessionPhase::AwaitingHello {
            service.config.first_frame_timeout_ms
        } else {
            service.config.idle_timeout_ms
        };
        let next =
            tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), reader.next()).await;
        let Some(message) = (match next {
            Ok(message) => message,
            Err(error) => {
                tracing::warn!(?error, "external WebSocket session timed out");
                break;
            }
        }) else {
            break;
        };
        let frame = match decode_message(message, service.config.max_frame_bytes) {
            Ok(Some(frame)) => frame,
            Ok(None) => continue,
            Err(status) => {
                tracing::warn!(?status, "external WebSocket frame rejected");
                break;
            }
        };
        if let Err(status) = handle_frame(&mut session, &tx, service.handler.as_ref(), frame).await
        {
            tracing::warn!(?status, "external WebSocket frame handler rejected frame");
            break;
        }
    }

    close_session(&mut session, service.handler.as_ref()).await;
    drop(tx);
    match tokio::time::timeout(std::time::Duration::from_millis(250), &mut write_task).await {
        Ok(result) => record_write_task_join(result),
        Err(_elapsed) => {
            write_task.abort();
            match write_task.await {
                Ok(()) => {}
                Err(error) if error.is_cancelled() => {
                    tracing::debug!("external WebSocket writer task aborted during shutdown");
                }
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        "external WebSocket writer task failed during shutdown"
                    );
                }
            }
        }
    }
}

fn record_write_task_join(result: Result<(), tokio::task::JoinError>) {
    match result {
        Ok(()) => {}
        Err(error) if error.is_cancelled() => {
            tracing::debug!("external WebSocket writer task cancelled during shutdown");
        }
        Err(error) => {
            tracing::warn!(
                ?error,
                "external WebSocket writer task failed during shutdown"
            );
        }
    }
}

fn decode_message(
    message: Result<Message, axum::Error>,
    max_frame_bytes: usize,
) -> Result<Option<ext::ExternalFrame>, Status> {
    let message = message
        .map_err(|error| Status::aborted(format!("external WebSocket receive failed: {error}")))?;
    match message {
        Message::Binary(bytes) => {
            if bytes.len() > max_frame_bytes {
                return Err(Status::resource_exhausted(
                    "external WebSocket frame too large",
                ));
            }
            ext::ExternalFrame::decode(bytes.as_ref())
                .map(Some)
                .map_err(|error| {
                    Status::invalid_argument(format!("bad external WebSocket frame: {error}"))
                })
        }
        Message::Ping(_) | Message::Pong(_) => Ok(None),
        Message::Close(_) => Err(Status::cancelled("external WebSocket closed")),
        Message::Text(_) => Err(Status::invalid_argument(
            "external WebSocket requires binary protobuf frames",
        )),
    }
}

async fn close_session<H>(session: &mut EndpointSession, handler: &H)
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    let context = session.context().cloned();
    session.close();
    if let Some(context) = context
        && let Err(error) = handler.on_closed(session, context).await
    {
        tracing::warn!(?error, "external WebSocket close handler failed");
    }
}

async fn handle_frame<H>(
    session: &mut EndpointSession,
    tx: &mpsc::Sender<ext::ExternalFrame>,
    handler: &H,
    frame: ext::ExternalFrame,
) -> Result<(), Status>
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    let frame = frame
        .frame
        .ok_or_else(|| Status::invalid_argument("empty external frame"))?;
    match frame {
        ext::external_frame::Frame::RoleSessionClientHello(hello) => {
            if session.phase() != SessionPhase::AwaitingHello {
                return Err(session_reject_status(SessionReject::OutOfOrder));
            }
            let hello = role_session_client_hello_from_pb(&hello).map_err(convert_status)?;
            let selected = handler.adjudicate_session(&hello).await?;
            let context = session
                .on_hello(&hello, |_| selected)
                .map_err(session_reject_status)?;
            send_frame(
                tx,
                ext::external_frame::Frame::SessionContext(session_context_to_pb(&context)),
            )
            .await
        }
        ext::external_frame::Frame::RoleReady(ready) => {
            let ready = role_ready_from_pb(&ready).map_err(convert_status)?;
            session.on_ready(&ready).map_err(session_reject_status)?;
            handler
                .on_ready(
                    session,
                    ready.accepted_context,
                    Arc::new(ExternalWebSocketOutbound::from_sender(tx.clone())),
                )
                .await
        }
        ext::external_frame::Frame::SecureEnvelope(envelope) => {
            session.admit_business().map_err(session_reject_status)?;
            let context = ready_external_session_context(session).map_err(session_reject_status)?;
            let envelope =
                secure_external_envelope_from_pb(envelope).map_err(external_frame_status)?;
            validate_secure_external_envelope_context(&envelope, &context)
                .map_err(external_frame_status)?;
            let frame_type = envelope.aad().frame_type.as_str();
            let plaintext = handler
                .open_secure_envelope(&envelope, session, context)
                .await?;
            let inner = ext::ExternalFrame::decode(plaintext.as_slice())
                .map_err(|_error| Status::invalid_argument("bad secure envelope payload"))?;
            validate_secure_external_inner_frame_type(&inner, frame_type)
                .map_err(external_frame_status)?;
            let inner = inner
                .frame
                .ok_or_else(|| external_frame_status(ExternalFrameError::EmptyFrame))?;
            handle_business_frame(
                session,
                tx,
                handler,
                inner,
                ExternalFrameOrigin::SecureEnvelope,
            )
            .await
        }
        frame => {
            handle_business_frame(session, tx, handler, frame, ExternalFrameOrigin::Plain).await
        }
    }
}

async fn handle_business_frame<H>(
    session: &mut EndpointSession,
    tx: &mpsc::Sender<ext::ExternalFrame>,
    handler: &H,
    frame: ext::external_frame::Frame,
    origin: ExternalFrameOrigin,
) -> Result<(), Status>
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    match external_inbound_frame_from_pb(frame, origin).map_err(external_frame_status)? {
        ExternalInboundFrame::InboundEvent(event) => {
            session
                .admit_source_event(&event.observed)
                .map_err(session_reject_status)?;
            let context = ready_external_session_context(session).map_err(session_reject_status)?;
            require_external_role(&context, Role::Source).map_err(external_frame_status)?;
            let ack = handler.on_inbound_event(event, session, context).await?;
            send_frame(
                tx,
                ext::external_frame::Frame::EventAck(event_ack_to_pb(&ack)),
            )
            .await
        }
        ExternalInboundFrame::CommandResult(result) => {
            session.admit_business().map_err(session_reject_status)?;
            let context = ready_external_session_context(session).map_err(session_reject_status)?;
            require_external_role(&context, Role::Source).map_err(external_frame_status)?;
            handler.on_command_result(result, session, context).await
        }
        ExternalInboundFrame::InvokeResult(result) => {
            session.admit_business().map_err(session_reject_status)?;
            let context = ready_external_session_context(session).map_err(session_reject_status)?;
            require_external_role(&context, Role::Provider).map_err(external_frame_status)?;
            handler.on_invoke_result(result, session, context).await
        }
        ExternalInboundFrame::Control(frame) => {
            session.admit_business().map_err(session_reject_status)?;
            let context = ready_external_session_context(session).map_err(session_reject_status)?;
            handler.on_control(frame, session, context).await
        }
    }
}

async fn send_frame(
    tx: &mpsc::Sender<ext::ExternalFrame>,
    frame: ext::external_frame::Frame,
) -> Result<(), Status> {
    tx.send(ext::ExternalFrame { frame: Some(frame) })
        .await
        .map_err(|_error| Status::unavailable("external WebSocket session closed"))
}

fn session_reject_status(reject: SessionReject) -> Status {
    match reject {
        SessionReject::NotReady | SessionReject::OutOfOrder | SessionReject::ContextMismatch => {
            Status::failed_precondition("external session frame rejected")
        }
        SessionReject::StaleGeneration | SessionReject::RevokedCredential => {
            Status::permission_denied("external session generation rejected")
        }
        SessionReject::Closed => Status::cancelled("external session closed"),
    }
}

fn convert_status(error: xolotl_proto::ConvertError) -> Status {
    Status::invalid_argument(error.to_string())
}

fn external_frame_status(error: ExternalFrameError) -> Status {
    match error {
        ExternalFrameError::EmptyFrame => Status::invalid_argument("empty external frame"),
        ExternalFrameError::BadControlFrame => Status::invalid_argument("bad control frame"),
        ExternalFrameError::BadSecureEnvelope => Status::invalid_argument("bad secure envelope"),
        ExternalFrameError::BadFramePayload => Status::invalid_argument("invalid wire value"),
        ExternalFrameError::ExternalFrameDirectionRejected => {
            Status::invalid_argument("external frame direction rejected")
        }
        ExternalFrameError::ExternalRoleFrameRejected => {
            Status::permission_denied("external role frame rejected")
        }
        ExternalFrameError::SecureEnvelopePayloadRejected => {
            Status::invalid_argument("secure external frame direction rejected")
        }
        ExternalFrameError::SecureEnvelopeContextRejected => {
            Status::permission_denied("secure envelope context rejected")
        }
        ExternalFrameError::SecureEnvelopeFrameTypeMismatch => {
            Status::permission_denied("secure external frame type mismatch")
        }
    }
}
