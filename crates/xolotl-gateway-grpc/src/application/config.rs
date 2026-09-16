use std::time::Duration;
use tokio::sync::Semaphore;
use tonic::Status;
use xolotl_gateway::GatewayTransportSecurityConfig;

/// Application gRPC transport windows, separate from object length and task policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationGrpcConfig {
    /// Listener security and explicitly trusted reverse proxies.
    pub transport_security: GatewayTransportSecurityConfig,
    /// Maximum encoded protobuf message, including metadata and envelope overhead.
    /// Applies to incoming and outgoing frames, not cumulative object or stream bytes.
    pub max_frame_bytes: usize,
    /// Upload RPCs allowed to hold a staging owner at once. Excess calls fail
    /// immediately instead of waiting in an adapter-owned queue.
    pub max_concurrent_uploads: usize,
    /// Unary, stream and object download responses retained at once, including
    /// object encoding and encoded HTTP/2 buffers. All share this response window.
    pub max_concurrent_output_responses: usize,
    /// Kernel output credits, including chunks borrowed for protobuf conversion.
    pub output_window_chunks: usize,
    /// Charged inline bytes retained by the kernel output window.
    /// Neither output window restricts cumulative stream traffic.
    pub output_window_bytes: usize,
    /// Wait for a complete Begin frame after authentication.
    pub first_frame_timeout: Duration,
    /// Wait for each subsequent complete frame, including EOF after Finish.
    /// This is a per-frame wait, not a total upload deadline.
    pub idle_timeout: Duration,
    /// Wait for each authentication or object/receipt storage operation.
    /// Task execution deadlines belong to Gateway admission and the client RPC.
    pub storage_timeout: Duration,
}

impl Default for ApplicationGrpcConfig {
    fn default() -> Self {
        Self {
            transport_security: GatewayTransportSecurityConfig::default(),
            max_frame_bytes: 64 * 1024,
            max_concurrent_uploads: 8,
            max_concurrent_output_responses: 8,
            output_window_chunks: 16,
            output_window_bytes: 256 * 1024,
            first_frame_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(30),
            storage_timeout: Duration::from_secs(120),
        }
    }
}

impl ApplicationGrpcConfig {
    pub(super) fn validate(&mut self) -> Result<(), Status> {
        if self.max_frame_bytes == 0 || self.max_frame_bytes > u32::MAX as usize {
            return Err(Status::invalid_argument(
                "max_frame_bytes must fit the nonzero gRPC message length",
            ));
        }
        if self.max_concurrent_uploads == 0 || self.max_concurrent_uploads > Semaphore::MAX_PERMITS
        {
            return Err(Status::invalid_argument(
                "max_concurrent_uploads is outside the semaphore range",
            ));
        }
        if self.max_concurrent_output_responses == 0
            || self.max_concurrent_output_responses > Semaphore::MAX_PERMITS
            || self.output_window_chunks == 0
            || self.output_window_chunks > Semaphore::MAX_PERMITS
            || self.output_window_bytes == 0
        {
            return Err(Status::invalid_argument(
                "application output windows must be nonzero and representable",
            ));
        }
        for duration in [
            self.first_frame_timeout,
            self.idle_timeout,
            self.storage_timeout,
        ] {
            if duration.is_zero() || tokio::time::Instant::now().checked_add(duration).is_none() {
                return Err(Status::invalid_argument(
                    "application wait windows must be nonzero and representable",
                ));
            }
        }
        self.transport_security = self.transport_security.clone().bounded();
        Ok(())
    }
}
