#![forbid(unsafe_code)]

//! WebSocket transport adapter for external Provider and Source sessions.
//!
//! The adapter carries the same logical session frames as the external gRPC
//! transport. WebSocket is a transport choice; Provider and Source remain the
//! only external program roles.

use axum::Router;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use futures::{SinkExt, StreamExt};
use nexus_actors::endpoint::{EndpointSession, SessionPhase, SessionReject};
use nexus_actors::pairing::SecureEnvelope;
use nexus_gateway::{
    ExternalFrameError, ExternalFrameOrigin, ExternalInboundFrame, GatewayTransportSecurityConfig,
    GatewayTransportSecurityMode, GatewayUnsafeTransportRelaxation, external_inbound_frame_from_pb,
    local_trusted_browser_origin, ready_external_session_context, require_external_role,
    secure_external_envelope_from_pb, validate_secure_external_envelope_context,
    validate_secure_external_inner_frame_type,
};
use nexus_proto::nexus::v1::external as ext;
use nexus_proto::{
    control_frame_to_pb, event_ack_to_pb, invoke_to_pb, outbound_command_to_pb, role_ready_from_pb,
    role_session_client_hello_from_pb, session_context_to_pb,
};
use nexus_types::external::{
    AckStatus, CommandResult, ControlFrame, EventAck, InboundEvent, Invoke, InvokeResult,
    OutboundCommand, ProviderReady, Role, RoleSessionClientHello, SessionContext,
};
use prost::Message as ProstMessage;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tonic::Status;

/// External WebSocket protocol version served by this adapter.
pub const EXTERNAL_WS_PROTOCOL_VERSION: u32 = 1;
/// Default maximum inbound binary frame size.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Hard cap for inbound binary frame size.
pub const HARD_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
/// Default time allowed for the first session frame.
pub const DEFAULT_FIRST_FRAME_TIMEOUT_MS: u64 = 10_000;
/// Hard cap for first-frame timeout.
pub const HARD_FIRST_FRAME_TIMEOUT_MS: u64 = 300_000;
/// Default idle timeout after the first frame.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 300_000;
/// Hard cap for idle timeout.
pub const HARD_IDLE_TIMEOUT_MS: u64 = 86_400_000;
/// Default maximum concurrent WebSocket sessions.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;
/// Hard cap for concurrent WebSocket sessions.
pub const HARD_MAX_CONNECTIONS: usize = 4096;

/// WebSocket transport config for external Provider/Source sessions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalWebSocketConfig {
    /// Maximum inbound protobuf frame bytes.
    pub max_frame_bytes: usize,
    /// First-frame timeout in milliseconds.
    pub first_frame_timeout_ms: u64,
    /// Idle timeout in milliseconds.
    pub idle_timeout_ms: u64,
    /// Maximum concurrent WebSocket sessions.
    pub max_connections: usize,
    /// Transport security and trusted-proxy policy.
    pub transport_security: GatewayTransportSecurityConfig,
}

impl Default for ExternalWebSocketConfig {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            first_frame_timeout_ms: DEFAULT_FIRST_FRAME_TIMEOUT_MS,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            transport_security: GatewayTransportSecurityConfig::default(),
        }
        .bounded()
    }
}

impl ExternalWebSocketConfig {
    /// Clamp deployment-provided values to hard bounds and non-zero defaults.
    pub fn bounded(mut self) -> Self {
        self.max_frame_bytes = clamp_or_default(
            self.max_frame_bytes,
            DEFAULT_MAX_FRAME_BYTES,
            HARD_MAX_FRAME_BYTES,
        );
        self.first_frame_timeout_ms = clamp_or_default_u64(
            self.first_frame_timeout_ms,
            DEFAULT_FIRST_FRAME_TIMEOUT_MS,
            HARD_FIRST_FRAME_TIMEOUT_MS,
        );
        self.idle_timeout_ms = clamp_or_default_u64(
            self.idle_timeout_ms,
            DEFAULT_IDLE_TIMEOUT_MS,
            HARD_IDLE_TIMEOUT_MS,
        );
        self.max_connections = clamp_or_default(
            self.max_connections,
            DEFAULT_MAX_CONNECTIONS,
            HARD_MAX_CONNECTIONS,
        );
        self.transport_security = self.transport_security.bounded();
        self
    }
}

/// Daemon-to-external frame sender for one ready Provider or Source session.
#[derive(Clone)]
pub struct ExternalWebSocketOutbound {
    tx: mpsc::Sender<ext::ExternalFrame>,
}

impl ExternalWebSocketOutbound {
    /// Create an outbound sender from the WebSocket writer channel.
    pub fn from_sender(tx: mpsc::Sender<ext::ExternalFrame>) -> Self {
        Self { tx }
    }

    /// Send one Provider invoke to the connected endpoint.
    pub async fn send_invoke(&self, invoke: Invoke) -> Result<(), Status> {
        self.send(ext::external_frame::Frame::Invoke(invoke_to_pb(&invoke)))
            .await
    }

    /// Send one Source outbound command to the connected endpoint.
    pub async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), Status> {
        self.send(ext::external_frame::Frame::OutboundCommand(
            outbound_command_to_pb(&command),
        ))
        .await
    }

    /// Send one control frame to the connected endpoint.
    pub async fn send_control(&self, frame: ControlFrame) -> Result<(), Status> {
        self.send(ext::external_frame::Frame::Control(control_frame_to_pb(
            &frame,
        )))
        .await
    }

    async fn send(&self, frame: ext::external_frame::Frame) -> Result<(), Status> {
        self.tx
            .send(ext::ExternalFrame { frame: Some(frame) })
            .await
            .map_err(|_| Status::unavailable("external WebSocket session closed"))
    }
}

/// Runtime hooks for one Provider or Source WebSocket session.
#[tonic::async_trait]
pub trait ExternalWebSocketSessionHandler: Send + Sync + 'static {
    /// Select the authoritative session context for a client hello.
    async fn adjudicate_session(
        &self,
        hello: &RoleSessionClientHello,
    ) -> Result<SessionContext, Status>;

    /// Called after the endpoint confirms the daemon-selected context.
    async fn on_ready(
        &self,
        _session: &EndpointSession,
        _context: SessionContext,
        _outbound: ExternalWebSocketOutbound,
    ) -> Result<(), Status> {
        Ok(())
    }

    /// Called when a ready session stream terminates.
    async fn on_closed(
        &self,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<(), Status> {
        Ok(())
    }

    /// Admit and handle one Source event.
    async fn on_inbound_event(
        &self,
        event: InboundEvent,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<EventAck, Status> {
        Ok(EventAck {
            id: event.id,
            status: AckStatus::Rejected,
            reject_reason: Some("source event handler unavailable".into()),
        })
    }

    /// Handle a Source command result.
    async fn on_command_result(
        &self,
        _result: CommandResult,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<(), Status> {
        Ok(())
    }

    /// Handle a Provider invocation result.
    async fn on_invoke_result(
        &self,
        _result: InvokeResult,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<(), Status> {
        Ok(())
    }

    /// Handle a Provider readiness report.
    async fn on_provider_ready(
        &self,
        _ready: ProviderReady,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<(), Status> {
        Ok(())
    }

    /// Handle a control frame.
    async fn on_control(
        &self,
        _frame: ControlFrame,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<(), Status> {
        Ok(())
    }

    /// Open one encrypted envelope.
    async fn open_secure_envelope(
        &self,
        _envelope: &SecureEnvelope,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<Vec<u8>, Status> {
        Err(Status::permission_denied("secure envelope rejected"))
    }
}

/// WebSocket adapter for external Provider/Source sessions.
#[derive(Clone)]
pub struct ExternalWebSocketService<H> {
    handler: Arc<H>,
    config: ExternalWebSocketConfig,
    connection_limiter: Arc<Semaphore>,
}

impl<H> ExternalWebSocketService<H>
where
    H: ExternalWebSocketSessionHandler,
{
    /// Build an external WebSocket service from a handler.
    pub fn new(handler: H) -> Self {
        Self::with_config(handler, ExternalWebSocketConfig::default())
    }

    /// Build an external WebSocket service from a handler and config.
    pub fn with_config(handler: H, config: ExternalWebSocketConfig) -> Self {
        Self::from_arc_with_config(Arc::new(handler), config)
    }

    /// Build an external WebSocket service from a shared handler.
    pub fn from_arc(handler: Arc<H>) -> Self {
        Self::from_arc_with_config(handler, ExternalWebSocketConfig::default())
    }

    /// Build an external WebSocket service from a shared handler and config.
    pub fn from_arc_with_config(handler: Arc<H>, config: ExternalWebSocketConfig) -> Self {
        let config = config.bounded();
        Self {
            handler,
            connection_limiter: Arc::new(Semaphore::new(config.max_connections)),
            config,
        }
    }
}

/// Serve external WebSocket sessions on `/ws`.
pub async fn serve<H>(
    service: Arc<ExternalWebSocketService<H>>,
    listener: TcpListener,
) -> std::io::Result<()>
where
    H: ExternalWebSocketSessionHandler,
{
    let app = Router::new()
        .route("/ws", get(ws_handler::<H>))
        .with_state(service);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

async fn ws_handler<H>(
    State(service): State<Arc<ExternalWebSocketService<H>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response
where
    H: ExternalWebSocketSessionHandler,
{
    if validate_ws_transport(&headers, peer.ip(), &service.config.transport_security).is_err() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(permit) = service.connection_limiter.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    upgrade
        .protocols(["nexus-external-v1"])
        .on_upgrade(move |socket| drive_socket(socket, service, permit))
}

async fn drive_socket<H>(
    socket: WebSocket,
    service: Arc<ExternalWebSocketService<H>>,
    _permit: OwnedSemaphorePermit,
) where
    H: ExternalWebSocketSessionHandler,
{
    let (mut writer, mut reader) = socket.split();
    let (tx, mut rx) = mpsc::channel::<ext::ExternalFrame>(32);
    let write_task = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            let mut bytes = Vec::with_capacity(frame.encoded_len());
            if frame.encode(&mut bytes).is_err() {
                break;
            }
            if writer.send(Message::Binary(bytes.into())).await.is_err() {
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
            Err(_) => {
                break;
            }
        }) else {
            break;
        };
        let frame = match decode_message(message, service.config.max_frame_bytes) {
            Ok(Some(frame)) => frame,
            Ok(None) => continue,
            Err(_) => break,
        };
        if handle_frame(&mut session, &tx, service.handler.as_ref(), frame)
            .await
            .is_err()
        {
            break;
        }
    }

    close_session(&mut session, service.handler.as_ref()).await;
    drop(tx);
    write_task.abort();
}

fn decode_message(
    message: Result<Message, axum::Error>,
    max_frame_bytes: usize,
) -> Result<Option<ext::ExternalFrame>, Status> {
    let message = message.map_err(|_| Status::aborted("external WebSocket receive failed"))?;
    match message {
        Message::Binary(bytes) => {
            if bytes.len() > max_frame_bytes {
                return Err(Status::resource_exhausted(
                    "external WebSocket frame too large",
                ));
            }
            ext::ExternalFrame::decode(bytes.as_ref())
                .map(Some)
                .map_err(|_| Status::invalid_argument("bad external WebSocket frame"))
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
    H: ExternalWebSocketSessionHandler,
{
    let context = session.context().cloned();
    session.close();
    if let Some(context) = context {
        let _ = handler.on_closed(session, context).await;
    }
}

async fn handle_frame<H>(
    session: &mut EndpointSession,
    tx: &mpsc::Sender<ext::ExternalFrame>,
    handler: &H,
    frame: ext::ExternalFrame,
) -> Result<(), Status>
where
    H: ExternalWebSocketSessionHandler,
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
                    ExternalWebSocketOutbound::from_sender(tx.clone()),
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
            let frame_type = envelope.aad.frame_type.as_str();
            let plaintext = handler
                .open_secure_envelope(&envelope, session, context)
                .await?;
            let inner = ext::ExternalFrame::decode(plaintext.as_slice())
                .map_err(|_| Status::invalid_argument("bad secure envelope payload"))?;
            validate_secure_external_inner_frame_type(&inner, &frame_type)
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
    H: ExternalWebSocketSessionHandler,
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
        ExternalInboundFrame::ProviderReady(ready) => {
            session.admit_business().map_err(session_reject_status)?;
            let context = ready_external_session_context(session).map_err(session_reject_status)?;
            require_external_role(&context, Role::Provider).map_err(external_frame_status)?;
            handler.on_provider_ready(ready, session, context).await
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
        .map_err(|_| Status::unavailable("external WebSocket session closed"))
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

fn convert_status(error: nexus_proto::ConvertError) -> Status {
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

fn validate_ws_transport(
    headers: &HeaderMap,
    peer: IpAddr,
    config: &GatewayTransportSecurityConfig,
) -> Result<(), ()> {
    match config.mode {
        GatewayTransportSecurityMode::LocalTrusted => {
            if !peer.is_loopback() {
                return Err(());
            }
            if let Some(origin) = headers.get(header::ORIGIN) {
                let origin = origin.to_str().map_err(|_| ())?;
                if !local_trusted_browser_origin(origin) {
                    return Err(());
                }
            }
        }
        GatewayTransportSecurityMode::TrustedReverseProxy => {
            if !config.trusted_proxy.peers.contains(&peer) {
                return Err(());
            }
            if config.trusted_proxy.honor_x_forwarded_proto {
                let proto = headers
                    .get("x-forwarded-proto")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default();
                if !matches!(proto, "https" | "wss") {
                    return Err(());
                }
            }
        }
        GatewayTransportSecurityMode::UnsafePlaintext
        | GatewayTransportSecurityMode::DisabledForTest => {}
        GatewayTransportSecurityMode::ProductionTls | GatewayTransportSecurityMode::MutualTls => {
            if !config
                .unsafe_relaxations
                .contains(&GatewayUnsafeTransportRelaxation::AllowPlaintext)
            {
                return Err(());
            }
        }
    }
    Ok(())
}

fn clamp_or_default(value: usize, default: usize, hard: usize) -> usize {
    if value == 0 { default } else { value.min(hard) }
}

fn clamp_or_default_u64(value: u64, default: u64, hard: u64) -> u64 {
    if value == 0 { default } else { value.min(hard) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_websocket_config_is_bounded() {
        let config = ExternalWebSocketConfig {
            max_frame_bytes: usize::MAX,
            first_frame_timeout_ms: u64::MAX,
            idle_timeout_ms: u64::MAX,
            max_connections: usize::MAX,
            ..ExternalWebSocketConfig::default()
        }
        .bounded();
        assert_eq!(config.max_frame_bytes, HARD_MAX_FRAME_BYTES);
        assert_eq!(config.first_frame_timeout_ms, HARD_FIRST_FRAME_TIMEOUT_MS);
        assert_eq!(config.idle_timeout_ms, HARD_IDLE_TIMEOUT_MS);
        assert_eq!(config.max_connections, HARD_MAX_CONNECTIONS);
    }

    #[test]
    fn secure_envelope_context_must_match_session() {
        let context = SessionContext {
            installation_id: "install".into(),
            projection_id: "source".into(),
            role: Role::Source,
            registry_hash: "hash".into(),
            credential_generation: 2,
            binding_generation: 3,
            installation_config_version: 4,
            projection_version: 5,
            presentation_config_generation: 6,
            alias_catalog_generation: 7,
            session_id: "session".into(),
        };
        let envelope = SecureEnvelope {
            installation_id: "install".into(),
            generation: 2,
            aad: nexus_actors::pairing::EnvelopeAad {
                projection_id: "source".into(),
                role: "source".into(),
                session_id: "session".into(),
                frame_type: "inbound_event".into(),
                binding_generation: 3,
                credential_generation: 2,
                transcript_hash: vec![0; 32],
                ..nexus_actors::pairing::EnvelopeAad::default()
            },
            nonce_prefix: [0; 12],
            ciphertext: Vec::new(),
        };
        validate_secure_external_envelope_context(&envelope, &context).unwrap();
    }
}
