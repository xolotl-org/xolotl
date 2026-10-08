use prost::Message;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use tokio::sync::{Semaphore, mpsc};
use tonic::Status;
use tonic::codegen::tokio_stream::{Stream, StreamExt};
use xolotl_gateway::external::{
    EndpointSession, ExternalCancellationSender, ExternalFrameError, ExternalInboundFrame,
    ExternalSessionHandler, ExternalSessionOutbound, ExternalSessionScope, SessionPhase,
    SessionReject, authenticated_external_inbound_frame_from_pb, require_external_role,
    secure_external_envelope_from_pb, secure_external_envelope_to_pb, secure_external_outbound_aad,
    secure_external_outbound_frame_type, selected_external_session_context,
    validate_secure_external_envelope_session, validate_secure_external_inner_frame_type,
};
use xolotl_proto::xolotl::v1::external as ext;
use xolotl_proto::{
    control_frame_to_pb, event_ack_to_pb, invoke_to_pb, outbound_command_to_pb, role_ready_from_pb,
    role_session_client_hello_from_pb, session_context_to_pb, source_stream_result_to_pb,
};
use xolotl_types::external::{ControlFrame, Invoke, OutboundCommand, Role, SessionContext};

/// Daemon-to-External frame sender for one ready Provider or Source session.
pub(crate) struct ExternalOutbound<H> {
    tx: mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    handler: Arc<H>,
    context: SessionContext,
    transcript_hash: [u8; 32],
    next_seq: AtomicU64,
    pub(crate) send_order: Semaphore,
    closed: AtomicBool,
    cancellation: OnceLock<ExternalCancellationSender>,
}

impl<H> ExternalOutbound<H>
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    /// Create an outbound sender from the gRPC response stream channel.
    pub(crate) fn from_sender(
        tx: mpsc::Sender<Result<ext::ExternalFrame, Status>>,
        handler: Arc<H>,
        context: SessionContext,
        transcript_hash: [u8; 32],
    ) -> Self {
        Self {
            tx,
            handler,
            context,
            transcript_hash,
            next_seq: AtomicU64::new(0),
            send_order: Semaphore::new(1),
            closed: AtomicBool::new(false),
            cancellation: OnceLock::new(),
        }
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.send_order.close();
        if let Some(sender) = self.cancellation.get() {
            sender.close();
        }
    }

    pub(crate) fn start_cancellation(self: &Arc<Self>, scope: &ExternalSessionScope) {
        let weak = Arc::downgrade(self);
        drop(self.cancellation.set(ExternalCancellationSender::new(
            scope,
            move |deadline, frame| {
                let weak = weak.clone();
                async move {
                    if let Some(sender) = weak.upgrade() {
                        drop(
                            tokio::time::timeout_at(
                                tokio::time::Instant::from_std(deadline),
                                sender.send_until(
                                    ext::external_frame::Frame::Control(control_frame_to_pb(
                                        &frame,
                                    )),
                                    Some(deadline),
                                ),
                            )
                            .await,
                        );
                    }
                }
            },
        )));
    }

    async fn send(&self, frame: ext::external_frame::Frame) -> Result<(), Status> {
        self.send_until(frame, None).await
    }

    async fn send_until(
        &self,
        frame: ext::external_frame::Frame,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), Status> {
        // Serializing seal and enqueue keeps wire order within the peer's
        // bounded replay window even under concurrent outbound calls.
        let _permit = self
            .send_order
            .acquire()
            .await
            .map_err(|_closed| Status::cancelled("External session closed"))?;
        if self.closed.load(Ordering::Acquire) {
            return Err(Status::cancelled("External session closed"));
        }
        if deadline.is_some_and(|deadline| deadline <= std::time::Instant::now()) {
            return Err(Status::deadline_exceeded("External notification expired"));
        }
        let frame_type =
            secure_external_outbound_frame_type(&frame).map_err(external_frame_status)?;
        let plaintext = ext::ExternalFrame { frame: Some(frame) };
        if plaintext.encoded_len() > 1024 * 1024 {
            return Err(Status::resource_exhausted(
                "External outbound frame too large",
            ));
        }
        let plaintext = plaintext.encode_to_vec();
        // Never wrap or reuse a sequence, including after a failed seal or enqueue.
        let seq = self
            .next_seq
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_max| Status::resource_exhausted("External outbound sequence exhausted"))?;
        let aad =
            secure_external_outbound_aad(&self.context, &self.transcript_hash, seq, frame_type);
        let envelope = self
            .handler
            .seal_secure_envelope(plaintext, aad, &self.context)
            .await?;
        if self.closed.load(Ordering::Acquire) {
            return Err(Status::cancelled("External session closed"));
        }
        if deadline.is_some_and(|deadline| deadline <= std::time::Instant::now()) {
            return Err(Status::deadline_exceeded("External notification expired"));
        }
        send_external_frame(
            &self.tx,
            ext::external_frame::Frame::SecureEnvelope(secure_external_envelope_to_pb(envelope)),
        )
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
}

#[tonic::async_trait]
impl<H> ExternalSessionOutbound for ExternalOutbound<H>
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    type Error = Status;

    fn enqueue_cancel(&self, frame: ControlFrame) -> Result<(), Self::Error> {
        let wire = ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::Control(control_frame_to_pb(
                &frame,
            ))),
        };
        if wire.encoded_len() > 1024 * 1024 {
            return Err(Status::resource_exhausted(
                "External cancellation frame too large",
            ));
        }
        if self.closed.load(Ordering::Acquire)
            || !self
                .cancellation
                .get()
                .is_some_and(|sender| sender.enqueue(frame))
        {
            return Err(Status::unavailable(
                "External cancellation queue unavailable",
            ));
        }
        Ok(())
    }

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

#[cfg(test)]
pub(crate) async fn drive_external_session<S, H>(
    inbound: S,
    tx: mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    handler: Arc<H>,
) where
    S: Stream<Item = Result<ext::ExternalFrame, Status>> + Unpin,
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    let scope = Arc::new(ExternalSessionScope::default());
    drive_external_session_scoped(inbound, tx, handler, Arc::downgrade(&scope)).await;
    scope.shutdown().await;
}

struct SessionGuard<H: ExternalSessionHandler<Error = Status, OutboundError = Status>> {
    session: EndpointSession,
    outbound: Option<Arc<ExternalOutbound<H>>>,
    handler: Arc<H>,
}

impl<H: ExternalSessionHandler<Error = Status, OutboundError = Status>> Drop for SessionGuard<H> {
    fn drop(&mut self) {
        if let Some(outbound) = &self.outbound {
            outbound.close();
        }
        let context = self.session.context().cloned();
        self.session.close();
        if let Some(context) = context
            && let Err(error) = self.handler.on_closed(&self.session, context)
        {
            tracing::warn!(?error, "external gRPC close handler failed");
        }
    }
}

pub(crate) async fn drive_external_session_scoped<S, H>(
    mut inbound: S,
    tx: mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    handler: Arc<H>,
    scope: Weak<ExternalSessionScope>,
) where
    S: Stream<Item = Result<ext::ExternalFrame, Status>> + Unpin,
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    let mut guard = SessionGuard {
        session: EndpointSession::new(),
        outbound: None,
        handler: handler.clone(),
    };
    loop {
        let duration = if guard.session.phase() == SessionPhase::AwaitingHello {
            10
        } else {
            300
        };
        let frame = tokio::select! {
            _ = tx.closed() => break,
            frame = tokio::time::timeout(std::time::Duration::from_secs(duration), inbound.next()) => frame,
        };
        let result = match frame {
            Ok(Some(Ok(frame))) if frame.encoded_len() <= 1024 * 1024 => {
                let SessionGuard {
                    session, outbound, ..
                } = &mut guard;
                tokio::select! {
                    _ = tx.closed() => break,
                    result = tokio::time::timeout(std::time::Duration::from_secs(300), handle_external_frame(session, outbound, &tx, &handler, &scope, frame)) => {
                        result.unwrap_or_else(|_| Err(Status::deadline_exceeded("External handler timed out")))
                    }
                }
            }
            Ok(Some(Ok(_))) => Err(Status::resource_exhausted("External frame too large")),
            Ok(Some(Err(status))) => Err(status),
            Ok(None) => break,
            Err(_) => Err(Status::deadline_exceeded("External session timed out")),
        };
        if let Err(status) = result {
            drop(tx.try_send(Err(status)));
            break;
        }
    }
}

async fn handle_external_frame<H>(
    session: &mut EndpointSession,
    outbound: &mut Option<Arc<ExternalOutbound<H>>>,
    tx: &mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    handler: &Arc<H>,
    scope: &Weak<ExternalSessionScope>,
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
        }
        ext::external_frame::Frame::RoleReady(_) => Err(Status::unauthenticated(
            "RoleReady requires a secure envelope",
        )),
        ext::external_frame::Frame::SecureEnvelope(envelope) => {
            if !matches!(
                session.phase(),
                SessionPhase::AwaitingReady | SessionPhase::Ready
            ) {
                return Err(session_reject_status(SessionReject::OutOfOrder));
            }
            let context =
                selected_external_session_context(session).map_err(session_reject_status)?;
            let envelope =
                secure_external_envelope_from_pb(envelope).map_err(external_frame_status)?;
            validate_secure_external_envelope_session(&envelope, session)
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
            if session.phase() == SessionPhase::AwaitingReady {
                let ext::external_frame::Frame::RoleReady(ready) = inner else {
                    return Err(session_reject_status(SessionReject::OutOfOrder));
                };
                let ready = role_ready_from_pb(&ready).map_err(convert_status)?;
                session
                    .on_authenticated_ready(&ready)
                    .map_err(session_reject_status)?;
                let transcript_hash = *session
                    .transcript_hash()
                    .ok_or_else(|| session_reject_status(SessionReject::ContextMismatch))?;
                let sender = Arc::new(ExternalOutbound::from_sender(
                    tx.clone(),
                    Arc::clone(handler),
                    ready.accepted_context.clone(),
                    transcript_hash,
                ));
                let scope = scope
                    .upgrade()
                    .ok_or_else(|| Status::unavailable("External scope closed"))?;
                sender.start_cancellation(&scope);
                *outbound = Some(Arc::clone(&sender));
                return handler
                    .on_ready(session, ready.accepted_context, sender)
                    .await;
            }
            handle_business_frame(session, outbound.as_deref(), handler, inner).await
        }
        _frame => Err(external_frame_status(
            ExternalFrameError::PlaintextBusinessRejected,
        )),
    }
}

async fn handle_business_frame<H>(
    session: &EndpointSession,
    outbound: Option<&ExternalOutbound<H>>,
    handler: &H,
    frame: ext::external_frame::Frame,
) -> Result<(), Status>
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
{
    match authenticated_external_inbound_frame_from_pb(frame).map_err(external_frame_status)? {
        ExternalInboundFrame::InboundEvent(event) => {
            session
                .admit_source_event(&event.observed)
                .map_err(session_reject_status)?;
            let context =
                selected_external_session_context(session).map_err(session_reject_status)?;
            require_external_role(context, Role::Source).map_err(external_frame_status)?;
            let ack = handler.on_inbound_event(event, session, context).await?;
            outbound
                .ok_or_else(|| session_reject_status(SessionReject::NotReady))?
                .send(ext::external_frame::Frame::EventAck(event_ack_to_pb(&ack)))
                .await
        }
        ExternalInboundFrame::SourceStreamRequest(request) => {
            session.admit_business().map_err(session_reject_status)?;
            let context =
                selected_external_session_context(session).map_err(session_reject_status)?;
            require_external_role(context, Role::Source).map_err(external_frame_status)?;
            let result = handler
                .on_source_stream_request(request, session, context)
                .await?;
            outbound
                .ok_or_else(|| session_reject_status(SessionReject::NotReady))?
                .send(ext::external_frame::Frame::SourceStreamResult(
                    source_stream_result_to_pb(&result),
                ))
                .await
        }
        ExternalInboundFrame::CommandResult(result) => {
            session.admit_business().map_err(session_reject_status)?;
            let context =
                selected_external_session_context(session).map_err(session_reject_status)?;
            require_external_role(context, Role::Source).map_err(external_frame_status)?;
            handler.on_command_result(result, session, context).await
        }
        ExternalInboundFrame::InvokeResult(result) => {
            session.admit_business().map_err(session_reject_status)?;
            let context =
                selected_external_session_context(session).map_err(session_reject_status)?;
            require_external_role(context, Role::Provider).map_err(external_frame_status)?;
            handler.on_invoke_result(result, session, context).await
        }
        ExternalInboundFrame::Control(frame) => {
            session.admit_business().map_err(session_reject_status)?;
            let context =
                selected_external_session_context(session).map_err(session_reject_status)?;
            handler.on_control(frame, session, context).await
        }
    }
}

fn send_external_frame(
    tx: &mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    frame: ext::external_frame::Frame,
) -> Result<(), Status> {
    let frame = ext::ExternalFrame { frame: Some(frame) };
    if frame.encoded_len() > 1024 * 1024 {
        return Err(Status::resource_exhausted(
            "External outbound frame too large",
        ));
    }
    tx.try_send(Ok(frame)).map_err(|error| match error {
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
        ExternalFrameError::PlaintextBusinessRejected => {
            Status::unauthenticated("external business frame requires a secure envelope")
        }
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
