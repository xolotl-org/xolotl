#![forbid(unsafe_code)]

//! `xolotl-gateway-grpc` - gRPC protocol adapter.
//!
//! Independent application and external Provider/Source admission boundaries.
//!
//! [`ApplicationGrpcService`] exposes profile discovery, object uploads and typed
//! submission through [`xolotl_gateway::Gateway`].
//! [`ExternalGrpcService`] serves `xolotl.v1.external.ExternalService.Session`.
//! Values are marshalled with the structural `xolotl-proto` conversions.
//!
//! Builds anywhere prost/tonic resolve - `xolotl-proto`'s bindings are vendored,
//! so no `protoc` is required.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tonic::codegen::tokio_stream::Stream;
use tonic::codegen::tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use xolotl_gateway::GatewayTransportSecurityConfig;
use xolotl_gateway::external::ExternalSessionHandler;
use xolotl_proto::xolotl::v1::external as ext;
use xolotl_proto::xolotl::v1::external::external_service_server::{
    ExternalService as ExternalGrpc, ExternalServiceServer,
};

mod application;
mod session;
mod transport;
pub use application::{
    ApplicationGrpcConfig, ApplicationGrpcService, ApplicationIngress,
    ApplicationObjectDownloadStream, ApplicationOutputStream,
};
use session::drive_external_session;
use transport::{validate_grpc_transport, verified_grpc_source_addr};

/// gRPC adapter for `xolotl.v1.external.ExternalService.Session`.
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
        let task = tokio::spawn(async move {
            drive_external_session(request.into_inner(), tx, handler).await;
        });
        Ok(Response::new(Box::pin(SessionResponseStream::new(
            rx, task,
        ))))
    }
}

struct SessionResponseStream {
    rx: ReceiverStream<Result<ext::ExternalFrame, Status>>,
    task: JoinHandle<()>,
    task_joined: bool,
}

impl SessionResponseStream {
    fn new(rx: mpsc::Receiver<Result<ext::ExternalFrame, Status>>, task: JoinHandle<()>) -> Self {
        Self {
            rx: ReceiverStream::new(rx),
            task,
            task_joined: false,
        }
    }
}

impl Stream for SessionResponseStream {
    type Item = Result<ext::ExternalFrame, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.rx).poll_next(cx) {
            Poll::Ready(Some(item)) => return Poll::Ready(Some(item)),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => {}
        }
        if self.task_joined {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.task).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                self.task_joined = true;
                Poll::Ready(None)
            }
            Poll::Ready(Err(error)) if error.is_cancelled() => {
                self.task_joined = true;
                tracing::debug!("external gRPC session task cancelled");
                Poll::Ready(None)
            }
            Poll::Ready(Err(error)) => {
                self.task_joined = true;
                tracing::warn!(?error, "external gRPC session task failed");
                Poll::Ready(Some(Err(Status::internal(
                    "external gRPC session task failed",
                ))))
            }
        }
    }
}

#[cfg(test)]
mod tests;
