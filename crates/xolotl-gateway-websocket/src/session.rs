use crate::OutboundQueueError;
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use prost::Message as ProstMessage;
use std::convert::Infallible;
use std::fmt::Debug;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
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

/// Daemon-to-external frame sender for one ready Provider or Source session.
struct ExternalWebSocketOutbound<H: ExternalSessionHandler> {
    tx: mpsc::Sender<ext::ExternalFrame>,
    handler: Arc<H>,
    context: SessionContext,
    transcript_hash: [u8; 32],
    next_seq: AtomicU64,
    send_order: Semaphore,
    closed: AtomicBool,
    cancellation: OnceLock<ExternalCancellationSender>,
    max_frame_bytes: usize,
    send_error: fn(OutboundQueueError) -> H::OutboundError,
}

enum OutboundSendError<E> {
    Queue(OutboundQueueError),
    Seal(E),
}

impl<H: ExternalSessionHandler> ExternalWebSocketOutbound<H> {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.send_order.close();
        if let Some(sender) = self.cancellation.get() {
            sender.close();
        }
    }

    fn start_cancellation(self: &Arc<Self>, scope: &ExternalSessionScope) {
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
                                sender.send_raw_until(
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

    async fn send_raw(
        &self,
        frame: ext::external_frame::Frame,
    ) -> Result<(), OutboundSendError<H::OutboundError>> {
        self.send_raw_until(frame, None).await
    }

    async fn send_raw_until(
        &self,
        frame: ext::external_frame::Frame,
        deadline: Option<std::time::Instant>,
    ) -> Result<(), OutboundSendError<H::OutboundError>> {
        // Keep sealing and enqueueing ordered for the peer's replay window.
        let _permit = self
            .send_order
            .acquire()
            .await
            .map_err(|_closed| OutboundSendError::Queue(OutboundQueueError::Closed))?;
        if self.closed.load(Ordering::Acquire)
            || deadline.is_some_and(|deadline| deadline <= std::time::Instant::now())
        {
            return Err(OutboundSendError::Queue(OutboundQueueError::Closed));
        }
        let frame_type = secure_external_outbound_frame_type(&frame)
            .map_err(|_error| OutboundSendError::Queue(OutboundQueueError::InvalidFrame))?;
        let plaintext = ext::ExternalFrame { frame: Some(frame) };
        if plaintext.encoded_len() > self.max_frame_bytes {
            return Err(OutboundSendError::Queue(OutboundQueueError::InvalidFrame));
        }
        let plaintext = plaintext.encode_to_vec();
        // Failed sealing or enqueueing burns the sequence; it is never reused.
        let seq = self
            .next_seq
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_max| OutboundSendError::Queue(OutboundQueueError::SequenceExhausted))?;
        let aad =
            secure_external_outbound_aad(&self.context, &self.transcript_hash, seq, frame_type);
        let envelope = self
            .handler
            .seal_secure_envelope(plaintext, aad, &self.context)
            .await
            .map_err(OutboundSendError::Seal)?;
        if self.closed.load(Ordering::Acquire)
            || deadline.is_some_and(|deadline| deadline <= std::time::Instant::now())
        {
            return Err(OutboundSendError::Queue(OutboundQueueError::Closed));
        }
        let frame = ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::SecureEnvelope(
                secure_external_envelope_to_pb(envelope),
            )),
        };
        if frame.encoded_len() > self.max_frame_bytes {
            return Err(OutboundSendError::Queue(OutboundQueueError::InvalidFrame));
        }
        self.tx.try_send(frame).map_err(|error| {
            OutboundSendError::Queue(match error {
                mpsc::error::TrySendError::Full(_) => OutboundQueueError::Full,
                mpsc::error::TrySendError::Closed(_) => OutboundQueueError::Closed,
            })
        })
    }

    async fn send(&self, frame: ext::external_frame::Frame) -> Result<(), H::OutboundError> {
        self.send_raw(frame).await.map_err(|error| match error {
            OutboundSendError::Queue(error) => (self.send_error)(error),
            OutboundSendError::Seal(error) => error,
        })
    }
}

#[async_trait::async_trait]
impl<H: ExternalSessionHandler> ExternalSessionOutbound for ExternalWebSocketOutbound<H> {
    type Error = H::OutboundError;

    fn enqueue_cancel(&self, frame: ControlFrame) -> Result<(), Self::Error> {
        let wire = ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::Control(control_frame_to_pb(
                &frame,
            ))),
        };
        if wire.encoded_len() > self.max_frame_bytes {
            return Err((self.send_error)(OutboundQueueError::InvalidFrame));
        }
        if self.closed.load(Ordering::Acquire)
            || !self
                .cancellation
                .get()
                .is_some_and(|sender| sender.enqueue(frame))
        {
            return Err((self.send_error)(OutboundQueueError::Closed));
        }
        Ok(())
    }

    async fn send_invoke(&self, invoke: Invoke) -> Result<(), Self::Error> {
        self.send(ext::external_frame::Frame::Invoke(invoke_to_pb(&invoke)))
            .await
    }

    async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), Self::Error> {
        self.send(ext::external_frame::Frame::OutboundCommand(
            outbound_command_to_pb(&command),
        ))
        .await
    }

    async fn send_control(&self, frame: ControlFrame) -> Result<(), Self::Error> {
        self.send(ext::external_frame::Frame::Control(control_frame_to_pb(
            &frame,
        )))
        .await
    }
}

/// Transport-owned per-connection state beyond the protocol handshake gate.
struct WebSocketSession<H: ExternalSessionHandler> {
    endpoint: EndpointSession,
    outbound: Option<Arc<ExternalWebSocketOutbound<H>>>,
    handler: Option<Arc<H>>,
    scope: Weak<ExternalSessionScope>,
    max_frame_bytes: usize,
}

impl<H: ExternalSessionHandler> WebSocketSession<H> {
    fn new() -> Self {
        Self {
            endpoint: EndpointSession::new(),
            outbound: None,
            handler: None,
            scope: Weak::new(),
            max_frame_bytes: crate::DEFAULT_MAX_FRAME_BYTES,
        }
    }
}

impl<H: ExternalSessionHandler> Drop for WebSocketSession<H> {
    fn drop(&mut self) {
        if let Some(outbound) = self.outbound.take() {
            outbound.close();
        }
        if self.endpoint.phase() == SessionPhase::Closed {
            return;
        }
        let context = self.endpoint.context().cloned();
        self.endpoint.close();
        if let (Some(handler), Some(context)) = (&self.handler, context)
            && handler.on_closed(&self.endpoint, context).is_err()
        {
            tracing::warn!("external WebSocket close handler failed");
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum SessionError<E: Debug> {
    #[error("WebSocket receive failed: {0}")]
    Receive(axum::Error),
    #[error("invalid protobuf frame: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("invalid wire value: {0}")]
    Convert(#[from] xolotl_proto::ConvertError),
    #[error("session rejected frame: {0}")]
    Session(#[from] SessionReject),
    #[error("frame rejected: {0}")]
    Frame(#[from] ExternalFrameError),
    #[error("{0}")]
    Protocol(&'static str),
    #[error("handler rejected frame: {0:?}")]
    Handler(E),
    #[error("external WebSocket session closed")]
    Closed,
    #[error(transparent)]
    Outbound(#[from] OutboundQueueError),
}

fn session_outbound_error<E: Debug, O>(error: OutboundSendError<O>) -> SessionError<E> {
    match error {
        OutboundSendError::Queue(error) => SessionError::Outbound(error),
        OutboundSendError::Seal(_error) => {
            SessionError::Protocol("secure external response seal failed")
        }
    }
}

pub(crate) async fn drive_socket<H>(
    socket: WebSocket,
    handler: Arc<H>,
    config: crate::ExternalWebSocketConfig,
    send_error: fn(OutboundQueueError) -> H::OutboundError,
    scope: Weak<ExternalSessionScope>,
    _permit: OwnedSemaphorePermit,
) where
    H: ExternalSessionHandler,
    H::Error: Debug,
{
    let (mut writer, mut reader) = socket.split();
    let (tx, mut rx) = mpsc::channel::<ext::ExternalFrame>(32);
    let (done_tx, mut done) = tokio::sync::oneshot::channel();
    let Some(owner) = scope.upgrade() else {
        return;
    };
    let Some(writer_abort) = owner.spawn(async move {
        while let Some(frame) = rx.recv().await {
            let bytes = frame.encode_to_vec();
            if !matches!(
                tokio::time::timeout(
                    std::time::Duration::from_secs(1),
                    writer.send(Message::Binary(bytes.into()))
                )
                .await,
                Ok(Ok(()))
            ) {
                break;
            }
        }
        done_tx.send(()).unwrap_or(());
    }) else {
        return;
    };
    drop(owner);
    struct WriterGuard(tokio::task::AbortHandle);
    impl Drop for WriterGuard {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _writer_guard = WriterGuard(writer_abort);
    let mut session = WebSocketSession::<H>::new();
    session.handler = Some(handler.clone());
    session.scope = scope;
    session.max_frame_bytes = config.max_frame_bytes;
    let first_deadline = tokio::time::Instant::now()
        + std::time::Duration::from_millis(config.first_frame_timeout_ms);
    loop {
        let deadline = if session.endpoint.phase() == SessionPhase::AwaitingHello {
            first_deadline
        } else {
            tokio::time::Instant::now() + std::time::Duration::from_millis(config.idle_timeout_ms)
        };
        let next = tokio::select! {
            _ = &mut done => break,
            next = tokio::time::timeout_at(deadline, reader.next()) => next,
        };
        let Ok(Some(message)) = next else {
            break;
        };
        let frame = match decode_message(message, config.max_frame_bytes) {
            Ok(Some(frame)) => frame,
            Ok(None) => continue,
            Err(_) => break,
        };
        let result = tokio::select! {
            _ = &mut done => break,
            result = tokio::time::timeout(std::time::Duration::from_millis(config.idle_timeout_ms), handle_frame(&mut session, &tx, &handler, frame, send_error)) => result,
        };
        if !matches!(result, Ok(Ok(()))) {
            break;
        }
    }
    close_session(&mut session, handler.as_ref());
}

fn decode_message(
    message: Result<Message, axum::Error>,
    max_frame_bytes: usize,
) -> Result<Option<ext::ExternalFrame>, SessionError<Infallible>> {
    let message = message.map_err(SessionError::Receive)?;
    match message {
        Message::Binary(bytes) => {
            if bytes.len() > max_frame_bytes {
                return Err(SessionError::Protocol("external WebSocket frame too large"));
            }
            ext::ExternalFrame::decode(bytes.as_ref())
                .map(Some)
                .map_err(Into::into)
        }
        Message::Ping(_) | Message::Pong(_) => Ok(None),
        Message::Close(_) => Err(SessionError::Closed),
        Message::Text(_) => Err(SessionError::Protocol(
            "external WebSocket requires binary protobuf frames",
        )),
    }
}

fn close_session<H>(session: &mut WebSocketSession<H>, handler: &H)
where
    H: ExternalSessionHandler,
    H::Error: Debug,
{
    if let Some(outbound) = session.outbound.take() {
        outbound.close();
    }
    if session.endpoint.phase() == SessionPhase::Closed {
        return;
    }
    let context = session.endpoint.context().cloned();
    session.endpoint.close();
    if let Some(context) = context
        && let Err(error) = handler.on_closed(&session.endpoint, context)
    {
        tracing::warn!(?error, "external WebSocket close handler failed");
    }
}

async fn handle_frame<H>(
    session: &mut WebSocketSession<H>,
    tx: &mpsc::Sender<ext::ExternalFrame>,
    handler: &Arc<H>,
    frame: ext::ExternalFrame,
    send_error: fn(OutboundQueueError) -> H::OutboundError,
) -> Result<(), SessionError<H::Error>>
where
    H: ExternalSessionHandler,
    H::Error: Debug,
{
    session.handler = Some(handler.clone());
    let frame = frame.frame.ok_or(ExternalFrameError::EmptyFrame)?;
    match frame {
        ext::external_frame::Frame::RoleSessionClientHello(hello) => {
            if session.endpoint.phase() != SessionPhase::AwaitingHello {
                return Err(SessionReject::OutOfOrder.into());
            }
            let hello = role_session_client_hello_from_pb(&hello)?;
            let selected = handler
                .adjudicate_session(&hello)
                .await
                .map_err(SessionError::Handler)?;
            let context = session.endpoint.on_hello(&hello, |_| selected)?;
            send_frame(
                tx,
                ext::external_frame::Frame::SessionContext(session_context_to_pb(&context)),
            )
            .map_err(Into::into)
        }
        ext::external_frame::Frame::RoleReady(_) => Err(SessionError::Protocol(
            "RoleReady requires a secure envelope",
        )),
        ext::external_frame::Frame::SecureEnvelope(envelope) => {
            if !matches!(
                session.endpoint.phase(),
                SessionPhase::AwaitingReady | SessionPhase::Ready
            ) {
                return Err(SessionReject::OutOfOrder.into());
            }
            let context = selected_external_session_context(&session.endpoint)?;
            let envelope = secure_external_envelope_from_pb(envelope)?;
            validate_secure_external_envelope_session(&envelope, &session.endpoint)?;
            let frame_type = envelope.aad().frame_type.as_str();
            let plaintext = handler
                .open_secure_envelope(&envelope, &session.endpoint, context)
                .await
                .map_err(SessionError::Handler)?;
            let inner = ext::ExternalFrame::decode(plaintext.as_slice())?;
            validate_secure_external_inner_frame_type(&inner, frame_type)?;
            let inner = inner.frame.ok_or(ExternalFrameError::EmptyFrame)?;
            if session.endpoint.phase() == SessionPhase::AwaitingReady {
                let ext::external_frame::Frame::RoleReady(ready) = inner else {
                    return Err(SessionReject::OutOfOrder.into());
                };
                let ready = role_ready_from_pb(&ready)?;
                session.endpoint.on_authenticated_ready(&ready)?;
                let transcript_hash = *session
                    .endpoint
                    .transcript_hash()
                    .ok_or(SessionReject::ContextMismatch)?;
                let sender = Arc::new(ExternalWebSocketOutbound {
                    tx: tx.clone(),
                    handler: Arc::clone(handler),
                    context: ready.accepted_context.clone(),
                    transcript_hash,
                    next_seq: AtomicU64::new(0),
                    send_order: Semaphore::new(1),
                    closed: AtomicBool::new(false),
                    cancellation: OnceLock::new(),
                    max_frame_bytes: session.max_frame_bytes,
                    send_error,
                });
                if let Some(scope) = session.scope.upgrade() {
                    sender.start_cancellation(&scope);
                }
                session.outbound = Some(Arc::clone(&sender));
                return handler
                    .on_ready(&session.endpoint, ready.accepted_context, sender)
                    .await
                    .map_err(SessionError::Handler);
            }
            handle_business_frame(
                &session.endpoint,
                session.outbound.as_deref(),
                handler,
                inner,
            )
            .await
        }
        _frame => Err(ExternalFrameError::PlaintextBusinessRejected.into()),
    }
}

async fn handle_business_frame<H>(
    session: &EndpointSession,
    outbound: Option<&ExternalWebSocketOutbound<H>>,
    handler: &H,
    frame: ext::external_frame::Frame,
) -> Result<(), SessionError<H::Error>>
where
    H: ExternalSessionHandler,
    H::Error: Debug,
{
    match authenticated_external_inbound_frame_from_pb(frame)? {
        ExternalInboundFrame::InboundEvent(event) => {
            session.admit_source_event(&event.observed)?;
            let context = selected_external_session_context(session)?;
            require_external_role(context, Role::Source)?;
            let ack = handler
                .on_inbound_event(event, session, context)
                .await
                .map_err(SessionError::Handler)?;
            outbound
                .ok_or(SessionReject::NotReady)?
                .send_raw(ext::external_frame::Frame::EventAck(event_ack_to_pb(&ack)))
                .await
                .map_err(session_outbound_error)
        }
        ExternalInboundFrame::SourceStreamRequest(request) => {
            session.admit_business()?;
            let context = selected_external_session_context(session)?;
            require_external_role(context, Role::Source)?;
            let result = handler
                .on_source_stream_request(request, session, context)
                .await
                .map_err(SessionError::Handler)?;
            outbound
                .ok_or(SessionReject::NotReady)?
                .send_raw(ext::external_frame::Frame::SourceStreamResult(
                    source_stream_result_to_pb(&result),
                ))
                .await
                .map_err(session_outbound_error)
        }
        ExternalInboundFrame::CommandResult(result) => {
            session.admit_business()?;
            let context = selected_external_session_context(session)?;
            require_external_role(context, Role::Source)?;
            handler
                .on_command_result(result, session, context)
                .await
                .map_err(SessionError::Handler)
        }
        ExternalInboundFrame::InvokeResult(result) => {
            session.admit_business()?;
            let context = selected_external_session_context(session)?;
            require_external_role(context, Role::Provider)?;
            handler
                .on_invoke_result(result, session, context)
                .await
                .map_err(SessionError::Handler)
        }
        ExternalInboundFrame::Control(frame) => {
            session.admit_business()?;
            let context = selected_external_session_context(session)?;
            handler
                .on_control(frame, session, context)
                .await
                .map_err(SessionError::Handler)
        }
    }
}

fn send_frame(
    tx: &mpsc::Sender<ext::ExternalFrame>,
    frame: ext::external_frame::Frame,
) -> Result<(), OutboundQueueError> {
    tx.try_send(ext::ExternalFrame { frame: Some(frame) })
        .map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => OutboundQueueError::Full,
            mpsc::error::TrySendError::Closed(_) => OutboundQueueError::Closed,
        })
}

#[cfg(test)]
mod tests;
