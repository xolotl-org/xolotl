#![forbid(unsafe_code)]

//! `nexus-gateway-grpc` — gRPC protocol adapter (Gateway, §18.1).
//!
//! A thin tonic service over the shared [`Gateway`]:
//! `Submit` authenticates the bearer token, decodes the structured program, runs it,
//! and returns the outcome. The five §18.1 steps live in `nexus-gateway`; this
//! crate only speaks gRPC. Values are marshalled with the **structural**
//! `nexus-proto` conversions.
//!
//! Builds anywhere prost/tonic resolve — `nexus-proto`'s bindings are vendored,
//! so no `protoc` is required.

use nexus_gateway::{AuthToken, Gateway, GatewayError, InProcessGateway, RequestIdentity};
use nexus_kernel::{Bootstrap, GatewayAudit};
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
    /// Build a gRPC adapter around an in-process gateway for `boot`.
    pub fn new(boot: Arc<Bootstrap>) -> Self {
        Self {
            gateway: Arc::new(InProcessGateway::new(boot)),
        }
    }

    /// Build a gRPC adapter from an already-constructed in-process gateway.
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
        let source_addr = request.remote_addr().map(|addr| addr.ip().to_string());
        let req = request.into_inner();
        let identity = match self.gateway.authenticate(&AuthToken(req.auth_token)).await {
            Ok(identity) => identity,
            Err(e) => {
                record_grpc_audit(
                    &self.gateway,
                    None,
                    source_addr.as_deref(),
                    e.audit_outcome(),
                );
                return Err(Status::unauthenticated(e.public_message()));
            }
        };
        let Some(program) = req.program.as_ref() else {
            record_grpc_audit(
                &self.gateway,
                Some(&identity),
                source_addr.as_deref(),
                "bad_request",
            );
            return Err(Status::invalid_argument("missing program"));
        };
        let program = match program_from_pb(program) {
            Ok(program) => program,
            Err(_) => {
                record_grpc_audit(
                    &self.gateway,
                    Some(&identity),
                    source_addr.as_deref(),
                    "bad_request",
                );
                return Err(Status::invalid_argument("bad program"));
            }
        };
        let outcome = match self.gateway.submit(&identity, program).await {
            Ok(outcome) => outcome,
            Err(e) => {
                record_grpc_audit(
                    &self.gateway,
                    Some(&identity),
                    source_addr.as_deref(),
                    e.audit_outcome(),
                );
                return Err(gateway_status(e));
            }
        };
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

fn gateway_status(e: GatewayError) -> Status {
    let message = e.public_message();
    match e {
        GatewayError::Unauthenticated => Status::unauthenticated(message),
        GatewayError::Unauthorized(_) => Status::permission_denied(message),
        GatewayError::Rejected(_) => Status::failed_precondition(message),
    }
}

fn record_grpc_audit(
    gateway: &InProcessGateway,
    identity: Option<&RequestIdentity>,
    source_addr: Option<&str>,
    outcome: &'static str,
) {
    let _ = gateway.record_gateway_audit(GatewayAudit {
        event: "gateway_grpc",
        username: identity.map(|i| i.identity.as_str()),
        source_addr,
        outcome,
        mfa_level: None,
        details: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use nexus_graph::DoNode;
    use nexus_proto::{program_to_pb, value_from_pb};
    use nexus_types::{OutcomeRef, Value};
    use tonic::Code;

    fn audit_outcomes(boot: &Bootstrap, event: &str) -> Vec<String> {
        boot.kernel
            .facts
            .all_facts()
            .unwrap()
            .into_iter()
            .filter_map(|fact| match fact.outcome_ref {
                OutcomeRef::Inline(Value::Map(m))
                    if m.get("event").and_then(Value::as_str) == Some(event) =>
                {
                    m.get("outcome").and_then(Value::as_str).map(str::to_string)
                }
                _ => None,
            })
            .collect()
    }

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
        let svc = GrpcGateway::new(boot.clone());
        let err = svc
            .submit(Request::new(pb::SubmitRequest {
                auth_token: "process://alice".into(),
                program: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
        assert!(audit_outcomes(&boot, "gateway_grpc").contains(&"bad_request".into()));
    }

    #[tokio::test]
    async fn submit_auth_failure_is_redacted_and_audited() {
        let boot = Arc::new(Bootstrap::in_memory());
        let svc = GrpcGateway::new(boot.clone());
        let err = svc
            .submit(Request::new(pb::SubmitRequest {
                auth_token: String::new(),
                program: Some(program_to_pb(&DoNode::Pure(Value::Int(1)))),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
        assert_eq!(err.message(), "authentication failed");
        assert!(audit_outcomes(&boot, "gateway_grpc").contains(&"auth_failed".into()));
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
