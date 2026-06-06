//! `nexus-gateway-grpc` — gRPC protocol adapter (Gateway, §18.1).
//!
//! A thin tonic service over the shared [`Gateway`](nexus_gateway::Gateway):
//! `Submit` authenticates the bearer token, decodes the structured program, runs it,
//! and returns the outcome. The five §18.1 steps live in `nexus-gateway`; this
//! crate only speaks gRPC. Values are marshalled with the **structural**
//! `nexus-proto` conversions.
//!
//! Builds anywhere prost/tonic resolve — `nexus-proto`'s bindings are vendored,
//! so no `protoc` is required.

use nexus_gateway::{AuthToken, Gateway, InProcessGateway};
use nexus_kernel::Bootstrap;
use nexus_proto::nexus::v1 as pb;
use nexus_proto::nexus::v1::gateway_service_server::{GatewayService, GatewayServiceServer};
use nexus_proto::{outcome_to_pb, program_from_pb};
use std::sync::Arc;
use tonic::{Request, Response, Status};

/// gRPC gateway: wraps an [`InProcessGateway`] and serves [`GatewayService`].
pub struct GrpcGateway {
    gateway: Arc<InProcessGateway>,
}

impl GrpcGateway {
    pub fn new(boot: Arc<Bootstrap>) -> Self {
        Self {
            gateway: Arc::new(InProcessGateway::new(boot)),
        }
    }

    pub fn from_gateway(gateway: Arc<InProcessGateway>) -> Self {
        Self { gateway }
    }

    /// Wrap into a tonic server service.
    pub fn into_server(self) -> GatewayServiceServer<Self> {
        GatewayServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl GatewayService for GrpcGateway {
    async fn submit(
        &self,
        request: Request<pb::SubmitRequest>,
    ) -> Result<Response<pb::SubmitResponse>, Status> {
        let req = request.into_inner();
        let identity = self
            .gateway
            .authenticate(&AuthToken(req.auth_token))
            .await
            .map_err(|e| Status::unauthenticated(e.to_string()))?;
        let program = program_from_pb(
            req.program
                .as_ref()
                .ok_or_else(|| Status::invalid_argument("missing program"))?,
        )
        .map_err(|e| Status::invalid_argument(format!("bad program: {e}")))?;
        let outcome = self
            .gateway
            .submit(&identity, program)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(pb::SubmitResponse {
            outcome: Some(outcome_to_pb(&outcome)),
        }))
    }

    async fn health(
        &self,
        _request: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        Ok(Response::new(pb::HealthResponse {
            ready: true,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_graph::DoNode;
    use nexus_proto::{program_to_pb, value_from_pb};
    use nexus_types::Value;
    use tonic::Code;

    #[test]
    fn outcome_carries_structural_value() {
        // A Done outcome with a structured map must survive as a structural
        // pb::Value (not a JSON string blob).
        let mut m = std::collections::BTreeMap::new();
        m.insert("answer".to_string(), Value::Int(42));
        let outcome = nexus_types::Outcome::Done(Value::Map(m.clone()));
        let pb = outcome_to_pb(&outcome);
        match pb.result {
            Some(pb::outcome::Result::Done(v)) => {
                assert_eq!(value_from_pb(&v), Value::Map(m));
            }
            _ => panic!("expected Done"),
        }
    }

    #[tokio::test]
    async fn submit_runs_structured_program() {
        let boot = Arc::new(Bootstrap::in_memory());
        let svc = GrpcGateway::new(boot);
        let response = svc
            .submit(Request::new(pb::SubmitRequest {
                auth_token: "process://alice".into(),
                program: Some(program_to_pb(&DoNode::Pure(Value::Int(9)))),
            }))
            .await
            .unwrap()
            .into_inner();
        match response.outcome.and_then(|o| o.result) {
            Some(pb::outcome::Result::Done(v)) => assert_eq!(value_from_pb(&v), Value::Int(9)),
            other => panic!("expected Done(9), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn submit_rejects_missing_program() {
        let boot = Arc::new(Bootstrap::in_memory());
        let svc = GrpcGateway::new(boot);
        let err = svc
            .submit(Request::new(pb::SubmitRequest {
                auth_token: "process://alice".into(),
                program: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn health_reports_ready_and_version() {
        let boot = Arc::new(Bootstrap::in_memory());
        let svc = GrpcGateway::new(boot);
        let response = svc
            .health(Request::new(pb::HealthRequest {}))
            .await
            .unwrap()
            .into_inner();
        assert!(response.ready);
        assert_eq!(response.version, env!("CARGO_PKG_VERSION"));
    }
}
