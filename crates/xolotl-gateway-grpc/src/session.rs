use prost::Message;
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::Status;
use tonic::codegen::tokio_stream::{Stream, StreamExt};
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

/// Daemon-to-External frame sender for one ready Provider or Source session.
#[derive(Clone)]
pub(crate) struct ExternalOutbound {
    tx: mpsc::Sender<Result<ext::ExternalFrame, Status>>,
}

impl ExternalOutbound {
    /// Create an outbound sender from the gRPC response stream channel.
    pub(crate) fn from_sender(tx: mpsc::Sender<Result<ext::ExternalFrame, Status>>) -> Self {
        Self { tx }
    }

    /// Send one Provider invoke to the connected endpoint.
    async fn send_invoke(&self, invoke: Invoke) -> Result<(), Status> {
        send_external_frame(
            &self.tx,
            ext::external_frame::Frame::Invoke(invoke_to_pb(&invoke)),
        )
        .await
    }

    /// Send one Source outbound command to the connected endpoint.
    async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), Status> {
        send_external_frame(
            &self.tx,
            ext::external_frame::Frame::OutboundCommand(outbound_command_to_pb(&command)),
        )
        .await
    }

    /// Send one control frame to the connected endpoint.
    async fn send_control(&self, frame: ControlFrame) -> Result<(), Status> {
        send_external_frame(
            &self.tx,
            ext::external_frame::Frame::Control(control_frame_to_pb(&frame)),
        )
        .await
    }
}

#[tonic::async_trait]
impl ExternalSessionOutbound for ExternalOutbound {
    type Error = Status;

    async fn send_invoke(&self, invoke: Invoke) -> Result<(), Self::Error> {
        ExternalOutbound::send_invoke(self, invoke).await
    }

    async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), Self::Error> {
        ExternalOutbound::send_outbound_command(self, command).await
    }

    async fn send_control(&self, frame: ControlFrame) -> Result<(), Self::Error> {
        ExternalOutbound::send_control(self, frame).await
    }
}

pub(crate) async fn drive_external_session<S, H>(
    mut inbound: S,
    tx: mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    handler: Arc<H>,
) where
    S: Stream<Item = Result<ext::ExternalFrame, Status>> + Unpin,
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    let mut session = EndpointSession::new();
    while let Some(frame) = inbound.next().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(status) => {
                close_external_session(&mut session, handler.as_ref()).await;
                if let Err(error) = tx.try_send(Err(status)) {
                    tracing::warn!(?error, "external gRPC stream error was not delivered");
                }
                return;
            }
        };
        if let Err(status) = handle_external_frame(&mut session, &tx, handler.as_ref(), frame).await
        {
            close_external_session(&mut session, handler.as_ref()).await;
            if let Err(error) = tx.try_send(Err(status)) {
                tracing::warn!(?error, "external gRPC frame error was not delivered");
            }
            return;
        }
    }
    close_external_session(&mut session, handler.as_ref()).await;
}

async fn close_external_session<H>(session: &mut EndpointSession, handler: &H)
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    let context = session.context().cloned();
    session.close();
    if let Some(context) = context
        && let Err(error) = handler.on_closed(session, context).await
    {
        tracing::warn!(?error, "external gRPC close handler failed");
    }
}

async fn handle_external_frame<H>(
    session: &mut EndpointSession,
    tx: &mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    handler: &H,
    frame: ext::ExternalFrame,
) -> Result<(), Status>
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    let frame = frame
        .frame
        .ok_or_else(|| Status::invalid_argument("empty External frame"))?;
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
            send_external_frame(
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
                    Arc::new(ExternalOutbound::from_sender(tx.clone())),
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
    tx: &mpsc::Sender<Result<ext::ExternalFrame, Status>>,
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
            send_external_frame(
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

async fn send_external_frame(
    tx: &mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    frame: ext::external_frame::Frame,
) -> Result<(), Status> {
    tx.try_send(Ok(ext::ExternalFrame { frame: Some(frame) }))
        .map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => {
                Status::resource_exhausted("External outbound queue full")
            }
            mpsc::error::TrySendError::Closed(_) => Status::cancelled("External session closed"),
        })
}

fn external_frame_status(error: ExternalFrameError) -> Status {
    match error {
        ExternalFrameError::EmptyFrame => Status::invalid_argument("empty External frame"),
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

fn convert_status(_error: xolotl_proto::ConvertError) -> Status {
    Status::invalid_argument("invalid wire value")
}

fn session_reject_status(reject: SessionReject) -> Status {
    match reject {
        SessionReject::NotReady | SessionReject::OutOfOrder | SessionReject::ContextMismatch => {
            Status::failed_precondition("External session is not ready")
        }
        SessionReject::StaleGeneration | SessionReject::RevokedCredential => {
            Status::permission_denied("External session generation rejected")
        }
        SessionReject::Closed => Status::cancelled("External session closed"),
    }
}
