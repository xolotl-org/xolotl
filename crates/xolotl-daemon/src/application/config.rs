use crate::transport::GatewayTransportSecurityTuning;
use serde::Deserialize;
use std::time::Duration;
use xolotl_gateway::GatewayTransportSecurityConfig;
use xolotl_gateway_grpc::ApplicationGrpcConfig;

/// Bootstrap selection only. The selected profile remains authoritative in State.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApplicationGatewayConfig {
    pub profile: Option<String>,
    pub grpc: ApplicationGatewayGrpcConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApplicationGatewayGrpcConfig {
    pub transport_security: GatewayTransportSecurityTuning,
    pub max_frame_bytes: usize,
    pub max_concurrent_uploads: usize,
    pub max_concurrent_output_responses: usize,
    pub output_window_chunks: usize,
    pub output_window_bytes: usize,
    pub first_frame_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub storage_timeout_ms: u64,
}

impl Default for ApplicationGatewayGrpcConfig {
    fn default() -> Self {
        let config = ApplicationGrpcConfig::default();
        Self {
            transport_security: GatewayTransportSecurityTuning::default(),
            max_frame_bytes: config.max_frame_bytes,
            max_concurrent_uploads: config.max_concurrent_uploads,
            max_concurrent_output_responses: config.max_concurrent_output_responses,
            output_window_chunks: config.output_window_chunks,
            output_window_bytes: config.output_window_bytes,
            first_frame_timeout_ms: 15_000,
            idle_timeout_ms: 30_000,
            storage_timeout_ms: 120_000,
        }
    }
}

impl ApplicationGatewayGrpcConfig {
    pub fn service_config(
        &self,
        transport_security: GatewayTransportSecurityConfig,
    ) -> ApplicationGrpcConfig {
        ApplicationGrpcConfig {
            transport_security,
            max_frame_bytes: self.max_frame_bytes,
            max_concurrent_uploads: self.max_concurrent_uploads,
            max_concurrent_output_responses: self.max_concurrent_output_responses,
            output_window_chunks: self.output_window_chunks,
            output_window_bytes: self.output_window_bytes,
            first_frame_timeout: Duration::from_millis(self.first_frame_timeout_ms),
            idle_timeout: Duration::from_millis(self.idle_timeout_ms),
            storage_timeout: Duration::from_millis(self.storage_timeout_ms),
        }
    }
}
