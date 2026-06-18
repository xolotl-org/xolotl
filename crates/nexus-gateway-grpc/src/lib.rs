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

use nexus_gateway::GatewayTransportSecurityConfig;
use nexus_gateway::external::ExternalSessionHandler;
use nexus_proto::nexus::v1::external as ext;
use nexus_proto::nexus::v1::external::external_service_server::{
    ExternalService as ExternalGrpc, ExternalServiceServer,
};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::codegen::tokio_stream::Stream;
use tonic::{Request, Response, Status};

mod session;
mod transport;
use session::drive_external_session;
use transport::{validate_grpc_transport, verified_grpc_source_addr};

/// gRPC adapter for `nexus.v1.external.ExternalService.Session`.
#[derive(Clone)]
pub struct ExternalGrpcService<H> {
    handler: Arc<H>,
    transport_security: GatewayTransportSecurityConfig,
}

impl<H> ExternalGrpcService<H>
where
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
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
        if validate_grpc_transport(request.metadata(), peer, &self.transport_security).is_some() {
            return Err(Status::permission_denied("request rejected"));
        }
        verified_grpc_source_addr(request.metadata(), peer, &self.transport_security)
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
    H: ExternalSessionHandler<Error = Status, OutboundError = Status>,
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

#[cfg(test)]
mod tests;
