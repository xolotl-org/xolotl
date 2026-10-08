use crate::transport::GatewayTransportSecurityTuning;
use serde::Deserialize;
use std::num::NonZeroUsize;
use std::time::Duration;
use xolotl_gateway::{GatewayIdempotencyLimits, GatewayTransportSecurityConfig};
use xolotl_gateway_grpc::ApplicationGrpcConfig;

/// Host selection and request capacity. The selected profile remains authoritative in State.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApplicationGatewayConfig {
    pub profile: Option<String>,
    pub request_storage: ApplicationRequestStorageConfig,
    pub grpc: ApplicationGatewayGrpcConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApplicationRequestStorageConfig {
    pub max_records: NonZeroUsize,
    pub max_bytes: NonZeroUsize,
    pub max_record_bytes: NonZeroUsize,
    /// Host monotonic interval for store-wide retry-range closure, independent
    /// of profile revisions and result retention. Defaults to 15 minutes;
    /// accepts 1..=86,400,000 ms. Closure reclaims eligible settled evidence,
    /// preserves pending and unknown work, and rejects missing old identities.
    /// Capacity can fill before closure; size limits and cadence together.
    #[serde(deserialize_with = "deserialize_retry_epoch_ms")]
    pub retry_epoch_ms: u64,
}

impl Default for ApplicationRequestStorageConfig {
    fn default() -> Self {
        let limits = GatewayIdempotencyLimits::default();
        Self {
            max_records: limits.max_records,
            max_bytes: limits.max_bytes,
            max_record_bytes: limits.max_record_bytes,
            retry_epoch_ms: 15 * 60 * 1000,
        }
    }
}

impl ApplicationRequestStorageConfig {
    pub fn retry_epoch_period(&self) -> anyhow::Result<Duration> {
        anyhow::ensure!(
            (1..=24 * 60 * 60 * 1000).contains(&self.retry_epoch_ms),
            "application_gateway.request_storage.retry_epoch_ms must be 1..=86400000"
        );
        Ok(Duration::from_millis(self.retry_epoch_ms))
    }

    pub fn limits(&self) -> Result<GatewayIdempotencyLimits, xolotl_gateway::GatewayError> {
        let limits = GatewayIdempotencyLimits {
            max_records: self.max_records,
            max_bytes: self.max_bytes,
            max_record_bytes: self.max_record_bytes,
        };
        limits.validate()?;
        Ok(limits)
    }
}

fn deserialize_retry_epoch_ms<'de, Decoder>(decoder: Decoder) -> Result<u64, Decoder::Error>
where
    Decoder: serde::Deserializer<'de>,
{
    let millis = u64::deserialize(decoder)?;
    let config = ApplicationRequestStorageConfig {
        retry_epoch_ms: millis,
        ..ApplicationRequestStorageConfig::default()
    };
    config
        .retry_epoch_period()
        .map_err(serde::de::Error::custom)?;
    Ok(millis)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_storage_defaults_use_domain_limits() -> anyhow::Result<()> {
        anyhow::ensure!(
            ApplicationGatewayConfig::default()
                .request_storage
                .limits()?
                == GatewayIdempotencyLimits::default()
        );
        Ok(())
    }

    #[test]
    fn request_storage_rejects_zero_and_insufficient_reservation_capacity() {
        for field in ["max_records", "max_bytes", "max_record_bytes"] {
            let value = serde_json::json!({(field): 0});
            assert!(serde_json::from_value::<ApplicationRequestStorageConfig>(value).is_err());
        }
        let config = ApplicationRequestStorageConfig {
            max_bytes: NonZeroUsize::MIN,
            ..ApplicationRequestStorageConfig::default()
        };
        assert!(config.limits().is_err());
    }

    #[test]
    fn retry_epoch_period_is_independent_and_validated_for_native_and_decoded_config()
    -> anyhow::Result<()> {
        let default: ApplicationRequestStorageConfig =
            serde_json::from_value(serde_json::json!({}))?;
        anyhow::ensure!(default.retry_epoch_period()? == Duration::from_secs(900));
        for millis in [1, 86_400_000] {
            let decoded: ApplicationRequestStorageConfig =
                serde_json::from_value(serde_json::json!({"retry_epoch_ms": millis}))?;
            anyhow::ensure!(decoded.retry_epoch_period()? == Duration::from_millis(millis));
            anyhow::ensure!(decoded.limits()? == default.limits()?);
        }
        for millis in [0, 86_400_001, u64::MAX] {
            anyhow::ensure!(
                serde_json::from_value::<ApplicationRequestStorageConfig>(
                    serde_json::json!({"retry_epoch_ms": millis})
                )
                .is_err()
            );
            let native = ApplicationRequestStorageConfig {
                retry_epoch_ms: millis,
                ..default.clone()
            };
            anyhow::ensure!(native.retry_epoch_period().is_err());
        }
        Ok(())
    }
}
