#![forbid(unsafe_code)]

//! `nexus-gateway-grpc` - gRPC protocol adapter.
//!
//! Tonic adapter for external Provider and Source sessions.
//!
//! [`ExternalGrpcService`] serves `nexus.v1.external.ExternalService.Session`.
//! Values are marshalled with the structural `nexus-proto` conversions.
//!
//! Builds anywhere prost/tonic resolve - `nexus-proto`'s bindings are vendored,
//! so no `protoc` is required.

use nexus_actors::endpoint::{EndpointSession, SessionPhase, SessionReject};
use nexus_actors::pairing::SecureEnvelope;
use nexus_gateway::{
    ExternalFrameError, ExternalFrameOrigin, ExternalInboundFrame, GatewayTransportSecurityConfig,
    GatewayTransportSecurityMode, external_inbound_frame_from_pb, ready_external_session_context,
    require_external_role, secure_external_envelope_from_pb,
    validate_secure_external_envelope_context, validate_secure_external_inner_frame_type,
};
use nexus_proto::nexus::v1::external as ext;
use nexus_proto::nexus::v1::external::external_service_server::{
    ExternalService as ExternalGrpc, ExternalServiceServer,
};
use nexus_proto::{
    control_frame_to_pb, event_ack_to_pb, invoke_to_pb, outbound_command_to_pb, role_ready_from_pb,
    role_session_client_hello_from_pb, session_context_to_pb,
};
use nexus_types::external::{
    AckStatus, CommandResult, ControlFrame, EventAck, InboundEvent, Invoke, InvokeResult,
    OutboundCommand, ProviderReady, Role, RoleSessionClientHello, SessionContext,
};
use prost::Message;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::{Stream, StreamExt};
use tonic::metadata::MetadataMap;
use tonic::{Request, Response, Status};

/// Daemon-to-External frame sender for one ready Provider or Source session.
#[derive(Clone)]
pub struct ExternalOutbound {
    tx: mpsc::Sender<Result<ext::ExternalFrame, Status>>,
}

impl ExternalOutbound {
    /// Create an outbound sender from the gRPC response stream channel.
    pub fn from_sender(tx: mpsc::Sender<Result<ext::ExternalFrame, Status>>) -> Self {
        Self { tx }
    }

    /// Send one Provider invoke to the connected endpoint.
    pub async fn send_invoke(&self, invoke: Invoke) -> Result<(), Status> {
        send_external_frame(
            &self.tx,
            ext::external_frame::Frame::Invoke(invoke_to_pb(&invoke)),
        )
        .await
    }

    /// Send one Source outbound command to the connected endpoint.
    pub async fn send_outbound_command(&self, command: OutboundCommand) -> Result<(), Status> {
        send_external_frame(
            &self.tx,
            ext::external_frame::Frame::OutboundCommand(outbound_command_to_pb(&command)),
        )
        .await
    }

    /// Send one control frame to the connected endpoint.
    pub async fn send_control(&self, frame: ControlFrame) -> Result<(), Status> {
        send_external_frame(
            &self.tx,
            ext::external_frame::Frame::Control(control_frame_to_pb(&frame)),
        )
        .await
    }
}

/// Runtime hooks for one Provider or Source role session.
#[tonic::async_trait]
pub trait ExternalSessionHandler: Send + Sync + 'static {
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
        _outbound: ExternalOutbound,
    ) -> Result<(), Status> {
        Ok(())
    }

    /// Called when a ready role session stream terminates.
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

    /// Open one encrypted External envelope.
    async fn open_secure_envelope(
        &self,
        _envelope: &SecureEnvelope,
        _session: &EndpointSession,
        _context: SessionContext,
    ) -> Result<Vec<u8>, Status> {
        Err(Status::permission_denied("secure envelope rejected"))
    }
}

/// gRPC adapter for `nexus.v1.external.ExternalService.Session`.
#[derive(Clone)]
pub struct ExternalGrpcService<H> {
    handler: Arc<H>,
    transport_security: GatewayTransportSecurityConfig,
}

impl<H> ExternalGrpcService<H>
where
    H: ExternalSessionHandler,
{
    /// Build an External gRPC service from a handler.
    pub fn new(handler: H) -> Self {
        Self::with_config(handler, ExternalGrpcConfig::default())
    }

    /// Build an External gRPC service from a handler and transport config.
    pub fn with_config(handler: H, config: ExternalGrpcConfig) -> Self {
        Self::from_arc_with_config(Arc::new(handler), config)
    }

    /// Build an External gRPC service from a shared handler.
    pub fn from_arc(handler: Arc<H>) -> Self {
        Self::from_arc_with_config(handler, ExternalGrpcConfig::default())
    }

    /// Build an External gRPC service from a shared handler and transport config.
    pub fn from_arc_with_config(handler: Arc<H>, config: ExternalGrpcConfig) -> Self {
        let config = config.bounded();
        Self {
            handler,
            transport_security: config.transport_security,
        }
    }

    /// Wrap into a tonic server service.
    pub fn into_server(self) -> ExternalServiceServer<Self> {
        ExternalServiceServer::new(self)
    }

    fn source_addr_for_request<T>(&self, request: &Request<T>) -> Result<Option<String>, Status> {
        let peer = request.remote_addr().map(|addr| addr.ip());
        let source_addr =
            verified_grpc_source_addr(request.metadata(), peer, &self.transport_security);
        if validate_grpc_transport(request.metadata(), peer, &self.transport_security).is_some() {
            return Err(Status::permission_denied("request rejected"));
        }
        Ok(source_addr)
    }
}

/// External gRPC transport hardening config.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalGrpcConfig {
    /// Transport security and trusted-proxy policy.
    pub transport_security: GatewayTransportSecurityConfig,
}

impl Default for ExternalGrpcConfig {
    fn default() -> Self {
        Self {
            transport_security: GatewayTransportSecurityConfig::default(),
        }
        .bounded()
    }
}

impl ExternalGrpcConfig {
    /// Clamp deployment-provided values to supported bounds.
    pub fn bounded(mut self) -> Self {
        self.transport_security = self.transport_security.bounded();
        self
    }
}

#[tonic::async_trait]
impl<H> ExternalGrpc for ExternalGrpcService<H>
where
    H: ExternalSessionHandler,
{
    type SessionStream =
        Pin<Box<dyn Stream<Item = Result<ext::ExternalFrame, Status>> + Send + 'static>>;

    async fn session(
        &self,
        request: Request<tonic::Streaming<ext::ExternalFrame>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let _source_addr = self.source_addr_for_request(&request)?;
        let (tx, rx) = mpsc::channel(32);
        let handler = self.handler.clone();
        tokio::spawn(async move {
            drive_external_session(request.into_inner(), tx, handler).await;
        });
        Ok(Response::new(Box::pin(
            tonic::codegen::tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

async fn drive_external_session<S, H>(
    mut inbound: S,
    tx: mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    handler: Arc<H>,
) where
    S: Stream<Item = Result<ext::ExternalFrame, Status>> + Unpin,
    H: ExternalSessionHandler,
{
    let mut session = EndpointSession::new();
    while let Some(frame) = inbound.next().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(status) => {
                close_external_session(&mut session, handler.as_ref()).await;
                let _ = tx.try_send(Err(status));
                return;
            }
        };
        if let Err(status) = handle_external_frame(&mut session, &tx, handler.as_ref(), frame).await
        {
            close_external_session(&mut session, handler.as_ref()).await;
            let _ = tx.try_send(Err(status));
            return;
        }
    }
    close_external_session(&mut session, handler.as_ref()).await;
}

async fn close_external_session<H>(session: &mut EndpointSession, handler: &H)
where
    H: ExternalSessionHandler,
{
    let context = session.context().cloned();
    session.close();
    if let Some(context) = context {
        let _ = handler.on_closed(session, context).await;
    }
}

async fn handle_external_frame<H>(
    session: &mut EndpointSession,
    tx: &mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    handler: &H,
    frame: ext::ExternalFrame,
) -> Result<(), Status>
where
    H: ExternalSessionHandler,
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
                    ExternalOutbound::from_sender(tx.clone()),
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
    tx: &mpsc::Sender<Result<ext::ExternalFrame, Status>>,
    handler: &H,
    frame: ext::external_frame::Frame,
    origin: ExternalFrameOrigin,
) -> Result<(), Status>
where
    H: ExternalSessionHandler,
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

fn convert_status(_error: nexus_proto::ConvertError) -> Status {
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

fn verified_grpc_source_addr(
    metadata: &MetadataMap,
    peer: Option<IpAddr>,
    transport: &GatewayTransportSecurityConfig,
) -> Option<String> {
    if transport.trusts_peer(peer)
        && transport.trusted_proxy.honor_x_forwarded_for
        && let Some(forwarded) = forwarded_client_addr(metadata)
    {
        return Some(forwarded);
    }
    peer.map(|ip| ip.to_string())
}

fn validate_grpc_transport(
    metadata: &MetadataMap,
    peer: Option<IpAddr>,
    transport: &GatewayTransportSecurityConfig,
) -> Option<&'static str> {
    if let Some(outcome) = transport_denial_outcome(peer, transport) {
        return Some(outcome);
    }
    if matches!(
        transport.mode,
        GatewayTransportSecurityMode::TrustedReverseProxy
    ) && transport.trusted_proxy.honor_x_forwarded_proto
    {
        let Some(proto) = forwarded_grpc_proto(metadata, peer, transport) else {
            return Some("proto_required");
        };
        if !secure_forwarded_proto(&proto) {
            return Some("proto_denied");
        }
    }
    None
}

fn forwarded_grpc_proto(
    metadata: &MetadataMap,
    peer: Option<IpAddr>,
    transport: &GatewayTransportSecurityConfig,
) -> Option<String> {
    if !transport.trusts_peer(peer) {
        return None;
    }
    metadata
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(first_forwarded_value)
        .or_else(|| {
            metadata
                .get("forwarded")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| forwarded_header_param(value, "proto"))
        })
}

fn secure_forwarded_proto(proto: &str) -> bool {
    matches!(
        proto.trim().to_ascii_lowercase().as_str(),
        "https" | "wss" | "grpcs"
    )
}

fn forwarded_client_addr(metadata: &MetadataMap) -> Option<String> {
    metadata
        .get("x-forwarded-for")
        .or_else(|| metadata.get("x-real-ip"))
        .and_then(|value| value.to_str().ok())
        .and_then(first_forwarded_value)
        .or_else(|| {
            metadata
                .get("forwarded")
                .and_then(|value| value.to_str().ok())
                .and_then(forwarded_header_for)
        })
}

fn forwarded_header_for(value: &str) -> Option<String> {
    forwarded_header_param(value, "for").and_then(|value| {
        if value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
            None
        } else {
            Some(value)
        }
    })
}

fn forwarded_header_param(value: &str, expected_name: &str) -> Option<String> {
    let first = value.split(',').next()?.trim();
    for part in first.split(';') {
        let Some((name, raw_value)) = part.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case(expected_name) {
            continue;
        }
        let value = raw_value.trim().trim_matches('"').trim();
        if value.is_empty() {
            return None;
        }
        return Some(value.to_string());
    }
    None
}

fn first_forwarded_value(value: &str) -> Option<String> {
    value
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn transport_denial_outcome(
    peer: Option<IpAddr>,
    transport: &GatewayTransportSecurityConfig,
) -> Option<&'static str> {
    match transport.mode {
        GatewayTransportSecurityMode::ProductionTls | GatewayTransportSecurityMode::MutualTls => {
            None
        }
        GatewayTransportSecurityMode::TrustedReverseProxy => {
            (peer.is_some() && !transport.trusts_peer(peer)).then_some("transport_untrusted_proxy")
        }
        GatewayTransportSecurityMode::LocalTrusted => peer
            .is_some_and(|ip| !ip.is_loopback())
            .then_some("transport_not_local"),
        GatewayTransportSecurityMode::UnsafePlaintext
        | GatewayTransportSecurityMode::DisabledForTest => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_proto::nexus::v1 as pb;
    use nexus_proto::{
        control_frame_from_pb, inbound_event_to_pb, provider_ready_to_pb, role_ready_to_pb,
        role_session_client_hello_to_pb,
    };
    use nexus_types::Value;
    use nexus_types::external::{
        EffectHandlerSpec, ObservedGenerations, RoleReady, RoleSessionClientHello,
    };
    use tonic::Code;
    use tonic::transport::server::TcpConnectInfo;

    struct TestExternalHandler {
        context: SessionContext,
        events: std::sync::Mutex<Vec<InboundEvent>>,
        provider_ready: std::sync::Mutex<Vec<ProviderReady>>,
        controls: std::sync::Mutex<Vec<ControlFrame>>,
        envelopes: std::sync::Mutex<Vec<SecureEnvelope>>,
        envelope_plaintext: std::sync::Mutex<Option<Vec<u8>>>,
        closed: std::sync::Mutex<Vec<SessionContext>>,
    }

    impl TestExternalHandler {
        fn new(role: Role) -> Self {
            Self {
                context: test_session_context(role),
                events: std::sync::Mutex::new(Vec::new()),
                provider_ready: std::sync::Mutex::new(Vec::new()),
                controls: std::sync::Mutex::new(Vec::new()),
                envelopes: std::sync::Mutex::new(Vec::new()),
                envelope_plaintext: std::sync::Mutex::new(None),
                closed: std::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[tonic::async_trait]
    impl ExternalSessionHandler for TestExternalHandler {
        async fn adjudicate_session(
            &self,
            _hello: &RoleSessionClientHello,
        ) -> Result<SessionContext, Status> {
            Ok(self.context.clone())
        }

        async fn on_inbound_event(
            &self,
            event: InboundEvent,
            _session: &EndpointSession,
            _context: SessionContext,
        ) -> Result<EventAck, Status> {
            self.events.lock().unwrap().push(event.clone());
            Ok(EventAck {
                id: event.id,
                status: AckStatus::Accepted,
                reject_reason: None,
            })
        }

        async fn on_provider_ready(
            &self,
            ready: ProviderReady,
            _session: &EndpointSession,
            _context: SessionContext,
        ) -> Result<(), Status> {
            self.provider_ready.lock().unwrap().push(ready);
            Ok(())
        }

        async fn on_control(
            &self,
            frame: ControlFrame,
            _session: &EndpointSession,
            _context: SessionContext,
        ) -> Result<(), Status> {
            self.controls.lock().unwrap().push(frame);
            Ok(())
        }

        async fn on_closed(
            &self,
            _session: &EndpointSession,
            context: SessionContext,
        ) -> Result<(), Status> {
            self.closed.lock().unwrap().push(context);
            Ok(())
        }

        async fn open_secure_envelope(
            &self,
            envelope: &SecureEnvelope,
            _session: &EndpointSession,
            _context: SessionContext,
        ) -> Result<Vec<u8>, Status> {
            self.envelopes.lock().unwrap().push(envelope.clone());
            self.envelope_plaintext
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(|| Status::permission_denied("secure envelope rejected"))
        }
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
        }
    }

    fn external_hello(role: Role) -> ext::ExternalFrame {
        ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::RoleSessionClientHello(
                role_session_client_hello_to_pb(&RoleSessionClientHello {
                    role,
                    installation_id: "install-1".into(),
                    projection_id: "projection-1".into(),
                    registry_hash: "registry-hash".into(),
                    observed: ObservedGenerations {
                        presentation_config_generation: 5,
                        alias_catalog_generation: 6,
                    },
                    config_schema: None,
                }),
            )),
        }
    }

    fn external_ready(context: &SessionContext) -> ext::ExternalFrame {
        ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::RoleReady(role_ready_to_pb(
                &RoleReady {
                    accepted_context: context.clone(),
                },
            ))),
        }
    }

    fn external_event(id: &str) -> ext::ExternalFrame {
        ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::InboundEvent(
                inbound_event_to_pb(&InboundEvent {
                    id: id.into(),
                    payload: Value::Str("hello".into()),
                    observed: ObservedGenerations::default(),
                    timestamp_ms: 1234,
                    stream_id: None,
                    seq: None,
                }),
            )),
        }
    }

    fn external_provider_ready() -> ext::ExternalFrame {
        ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::ProviderReady(
                provider_ready_to_pb(&ProviderReady {
                    provides: vec![EffectHandlerSpec {
                        path: "effect://external-provider/install-1/search".into(),
                        purity: nexus_types::Purity::Idempotent,
                        description: Some("search".into()),
                    }],
                }),
            )),
        }
    }

    fn external_secure_envelope(context: &SessionContext) -> ext::ExternalFrame {
        external_secure_envelope_with_type(context, "provider_ready")
    }

    fn external_secure_envelope_with_type(
        context: &SessionContext,
        frame_type: &str,
    ) -> ext::ExternalFrame {
        ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::SecureEnvelope(
                ext::SecureEnvelope {
                    installation_id: context.installation_id.clone(),
                    generation: context.credential_generation,
                    aad: Some(ext::EnvelopeAad {
                        version: 1,
                        projection_id: context.projection_id.clone(),
                        role: nexus_gateway::external_role_slug(context.role).into(),
                        session_id: "session-1".into(),
                        seq: 0,
                        frame_type: frame_type.into(),
                        binding_generation: context.binding_generation,
                        credential_generation: context.credential_generation,
                        transcript_hash: vec![0x42; 32],
                        key_epoch: 0,
                    }),
                    nonce_prefix: vec![0; 12],
                    ciphertext: vec![1, 2, 3],
                },
            )),
        }
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

    #[tokio::test]
    async fn external_outbound_reports_backpressure_when_queue_is_full() {
        let (tx, mut rx) = mpsc::channel(1);
        let outbound = ExternalOutbound::from_sender(tx);

        outbound
            .send_control(ControlFrame::Heartbeat { timestamp_ms: 1 })
            .await
            .unwrap();
        let err = outbound
            .send_control(ControlFrame::Heartbeat { timestamp_ms: 2 })
            .await
            .unwrap_err();

        assert_eq!(err.code(), Code::ResourceExhausted);
        let sent = rx.recv().await.unwrap().unwrap();
        let Some(ext::external_frame::Frame::Control(control)) = sent.frame else {
            panic!("expected control frame");
        };
        assert_eq!(
            control_frame_from_pb(&control).unwrap(),
            ControlFrame::Heartbeat { timestamp_ms: 1 }
        );
    }

    #[tokio::test]
    async fn external_session_handshake_and_source_event_ack() {
        let handler = Arc::new(TestExternalHandler::new(Role::Source));
        let context = handler.context.clone();
        let out = run_external_frames(
            handler.clone(),
            vec![
                external_hello(Role::Source),
                external_ready(&context),
                external_event("event-1"),
            ],
        )
        .await;

        assert_eq!(out.len(), 2);
        match out[0].as_ref().unwrap().frame.as_ref().unwrap() {
            ext::external_frame::Frame::SessionContext(ctx) => {
                assert_eq!(ctx.installation_id, "install-1");
                assert_eq!(ctx.role, ext::ExternalRole::Source as i32);
            }
            other => panic!("expected SessionContext, got {other:?}"),
        }
        match out[1].as_ref().unwrap().frame.as_ref().unwrap() {
            ext::external_frame::Frame::EventAck(ack) => {
                assert_eq!(ack.id, "event-1");
                assert_eq!(ack.status, ext::AckStatus::Accepted as i32);
            }
            other => panic!("expected EventAck, got {other:?}"),
        }
        assert_eq!(handler.events.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn external_session_rejects_malformed_value_before_handler() {
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
                },
            )),
        };
        let out = run_external_frames(
            handler.clone(),
            vec![
                external_hello(Role::Source),
                external_ready(&context),
                event,
            ],
        )
        .await;

        assert_eq!(out.len(), 2);
        assert!(matches!(
            out[0].as_ref().unwrap().frame.as_ref().unwrap(),
            ext::external_frame::Frame::SessionContext(_)
        ));
        assert_eq!(out[1].as_ref().unwrap_err().code(), Code::InvalidArgument);
        assert_eq!(out[1].as_ref().unwrap_err().message(), "invalid wire value");
        assert!(handler.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn external_session_close_hook_runs_after_ready_eof() {
        let handler = Arc::new(TestExternalHandler::new(Role::Provider));
        let context = handler.context.clone();
        let out = run_external_frames(
            handler.clone(),
            vec![external_hello(Role::Provider), external_ready(&context)],
        )
        .await;

        assert_eq!(out.len(), 1);
        let closed = handler.closed.lock().unwrap().clone();
        assert_eq!(closed, vec![context]);
    }

    #[tokio::test]
    async fn external_session_rejects_business_before_ready() {
        let handler = Arc::new(TestExternalHandler::new(Role::Source));
        let out = run_external_frames(
            handler,
            vec![external_hello(Role::Source), external_event("event-1")],
        )
        .await;

        assert_eq!(out.len(), 2);
        assert!(matches!(
            out[0].as_ref().unwrap().frame.as_ref().unwrap(),
            ext::external_frame::Frame::SessionContext(_)
        ));
        assert_eq!(
            out[1].as_ref().unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
    }

    #[tokio::test]
    async fn external_session_rejects_wrong_role_business_frame() {
        let handler = Arc::new(TestExternalHandler::new(Role::Source));
        let context = handler.context.clone();
        let out = run_external_frames(
            handler,
            vec![
                external_hello(Role::Source),
                external_ready(&context),
                external_provider_ready(),
            ],
        )
        .await;

        assert_eq!(out.len(), 2);
        assert!(matches!(
            out[0].as_ref().unwrap().frame.as_ref().unwrap(),
            ext::external_frame::Frame::SessionContext(_)
        ));
        assert_eq!(
            out[1].as_ref().unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
    }

    #[tokio::test]
    async fn external_session_admits_secure_envelope_with_matching_context() {
        let handler = Arc::new(TestExternalHandler::new(Role::Provider));
        let context = handler.context.clone();
        let inner = ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::ProviderReady(
                provider_ready_to_pb(&ProviderReady {
                    provides: vec![EffectHandlerSpec {
                        path: "effect://external-provider/install-1/search".into(),
                        purity: nexus_types::Purity::Idempotent,
                        description: None,
                    }],
                }),
            )),
        };
        *handler.envelope_plaintext.lock().unwrap() = Some(inner.encode_to_vec());
        let out = run_external_frames(
            handler.clone(),
            vec![
                external_hello(Role::Provider),
                external_ready(&context),
                external_secure_envelope(&context),
            ],
        )
        .await;

        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0].as_ref().unwrap().frame.as_ref().unwrap(),
            ext::external_frame::Frame::SessionContext(_)
        ));
        assert_eq!(handler.envelopes.lock().unwrap().len(), 1);
        assert_eq!(handler.provider_ready.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn external_session_accepts_secure_control_frame_type() {
        let handler = Arc::new(TestExternalHandler::new(Role::Provider));
        let context = handler.context.clone();
        let inner = ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::Control(control_frame_to_pb(
                &ControlFrame::ConfigAck {
                    axis: nexus_types::external::ConfigAxis::InstallationConfig,
                    version: context.installation_config_version,
                    status: nexus_types::external::ApplyStatus::Applied,
                },
            ))),
        };
        *handler.envelope_plaintext.lock().unwrap() = Some(inner.encode_to_vec());
        let out = run_external_frames(
            handler.clone(),
            vec![
                external_hello(Role::Provider),
                external_ready(&context),
                external_secure_envelope_with_type(&context, "control.config_ack"),
            ],
        )
        .await;

        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0].as_ref().unwrap().frame.as_ref().unwrap(),
            ext::external_frame::Frame::SessionContext(_)
        ));
        assert_eq!(handler.controls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn external_session_rejects_generic_secure_control_frame_type() {
        let handler = Arc::new(TestExternalHandler::new(Role::Provider));
        let context = handler.context.clone();
        let inner = ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::Control(control_frame_to_pb(
                &ControlFrame::ConfigAck {
                    axis: nexus_types::external::ConfigAxis::InstallationConfig,
                    version: context.installation_config_version,
                    status: nexus_types::external::ApplyStatus::Applied,
                },
            ))),
        };
        *handler.envelope_plaintext.lock().unwrap() = Some(inner.encode_to_vec());
        let out = run_external_frames(
            handler.clone(),
            vec![
                external_hello(Role::Provider),
                external_ready(&context),
                external_secure_envelope_with_type(&context, "control"),
            ],
        )
        .await;

        assert_eq!(out.len(), 2);
        assert_eq!(
            out[1].as_ref().unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        assert!(handler.controls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn external_session_rejects_secure_envelope_frame_type_mismatch() {
        let handler = Arc::new(TestExternalHandler::new(Role::Provider));
        let context = handler.context.clone();
        let inner = ext::ExternalFrame {
            frame: Some(ext::external_frame::Frame::ProviderReady(
                provider_ready_to_pb(&ProviderReady {
                    provides: vec![EffectHandlerSpec {
                        path: "effect://external-provider/install-1/search".into(),
                        purity: nexus_types::Purity::Idempotent,
                        description: None,
                    }],
                }),
            )),
        };
        *handler.envelope_plaintext.lock().unwrap() = Some(inner.encode_to_vec());
        let out = run_external_frames(
            handler.clone(),
            vec![
                external_hello(Role::Provider),
                external_ready(&context),
                external_secure_envelope_with_type(&context, "control"),
            ],
        )
        .await;

        assert_eq!(out.len(), 2);
        assert_eq!(
            out[1].as_ref().unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(handler.provider_ready.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn external_session_rejects_secure_envelope_context_mismatch() {
        let handler = Arc::new(TestExternalHandler::new(Role::Provider));
        let context = handler.context.clone();
        let mut envelope = external_secure_envelope(&context);
        if let Some(ext::external_frame::Frame::SecureEnvelope(envelope)) = envelope.frame.as_mut()
        {
            envelope.generation = envelope.generation.saturating_add(1);
        }
        let out = run_external_frames(
            handler.clone(),
            vec![
                external_hello(Role::Provider),
                external_ready(&context),
                envelope,
            ],
        )
        .await;

        assert_eq!(out.len(), 2);
        assert_eq!(
            out[1].as_ref().unwrap_err().code(),
            tonic::Code::PermissionDenied
        );
        assert!(handler.envelopes.lock().unwrap().is_empty());
    }

    fn request_with_peer(peer: &str) -> Request<()> {
        let mut request = Request::new(());
        request.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer.parse().unwrap()),
        });
        request
    }

    #[test]
    fn external_grpc_default_transport_rejects_non_loopback_peer() {
        let svc = ExternalGrpcService::new(TestExternalHandler::new(Role::Source));

        let err = svc
            .source_addr_for_request(&request_with_peer("10.0.0.8:7443"))
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        assert_eq!(
            svc.source_addr_for_request(&request_with_peer("127.0.0.1:7443"))
                .unwrap(),
            Some("127.0.0.1".into())
        );
    }

    #[test]
    fn external_grpc_trusted_proxy_uses_forwarded_source_only_from_trusted_peer() {
        let transport = GatewayTransportSecurityConfig {
            mode: GatewayTransportSecurityMode::TrustedReverseProxy,
            trusted_proxy: nexus_gateway::GatewayTrustedProxyConfig {
                peers: vec!["127.0.0.1".parse().unwrap()],
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

        let mut trusted = request_with_peer("127.0.0.1:7443");
        trusted
            .metadata_mut()
            .insert("x-forwarded-for", "203.0.113.9, 10.0.0.4".parse().unwrap());
        trusted
            .metadata_mut()
            .insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(
            svc.source_addr_for_request(&trusted).unwrap(),
            Some("203.0.113.9".into())
        );

        let mut untrusted = request_with_peer("127.0.0.2:7443");
        untrusted
            .metadata_mut()
            .insert("x-forwarded-for", "203.0.113.10".parse().unwrap());
        let err = svc.source_addr_for_request(&untrusted).unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
    }
}
