use std::time::Duration;

use prost::Message;
use tonic::Status;
use xolotl_federation::{FederationNodeId, FederationOnlineKeyAuthorization, FederationRoot};
use xolotl_proto::xolotl::v1::federation as pb;

/// Hard upper bound for any serialized Session frame, independent of config.
pub const MAX_FEDERATION_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Hard upper bound for a Hello carrying complete post-quantum identity material.
pub const MAX_FEDERATION_HELLO_BYTES: usize = 16 * 1024;

/// Transport limits. Core and storage retain their own independent limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationGrpcConfig {
    /// Largest encoded Session frame accepted or emitted by this transport.
    pub max_frame_bytes: usize,
    /// Aggregate inbound and outbound Sessions, including TLS/application
    /// handshakes, shared across one runtime's clones. Rejection is immediate;
    /// failed handshakes and terminated session actors release admission.
    pub max_sessions: usize,
    /// Concurrent signature and identity verifications on blocking workers.
    pub max_blocking_verifications: usize,
    /// Unanswered requests permitted on one Session.
    pub max_in_flight: usize,
    /// Maximum records requested in one bounded read batch.
    pub max_batch_records: usize,
    /// Maximum record payload bytes requested in one bounded read batch.
    pub max_batch_bytes: usize,
    /// Control frames buffered before backpressure reaches the producer.
    pub control_queue_frames: usize,
    /// Data frames buffered before backpressure reaches the producer.
    pub data_queue_frames: usize,
    /// Encoded data bytes buffered for one Session.
    pub data_queue_bytes: usize,
    /// Time allowed to exchange and verify the application-level handshake.
    pub hello_timeout: Duration,
    /// Time allowed for the underlying TLS handshake.
    pub tls_handshake_timeout: Duration,
    /// Time allowed for a correlated business response.
    pub response_timeout: Duration,
}

impl Default for FederationGrpcConfig {
    fn default() -> Self {
        Self {
            // A retained call result may contain 1 MiB of output plus
            // metadata and unresolved effect identifiers.
            max_frame_bytes: 2 * 1024 * 1024,
            max_sessions: 64,
            max_blocking_verifications: 8,
            max_in_flight: 16,
            max_batch_records: 128,
            max_batch_bytes: 512 * 1024,
            control_queue_frames: 16,
            data_queue_frames: 4,
            data_queue_bytes: 2 * 1024 * 1024,
            hello_timeout: Duration::from_secs(10),
            tls_handshake_timeout: Duration::from_secs(5),
            response_timeout: Duration::from_secs(30),
        }
    }
}

impl FederationGrpcConfig {
    /// Validate transport bounds, including enough frame space for complete
    /// post-quantum Hello and Authenticate messages.
    pub fn validate(self) -> Result<Self, Status> {
        let counts = [
            self.max_frame_bytes,
            self.max_sessions,
            self.max_blocking_verifications,
            self.max_in_flight,
            self.max_batch_records,
            self.max_batch_bytes,
            self.control_queue_frames,
            self.data_queue_frames,
            self.data_queue_bytes,
        ];
        if counts.contains(&0)
            || self.max_frame_bytes > MAX_FEDERATION_FRAME_BYTES
            || self.max_sessions > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_blocking_verifications > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_in_flight > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_in_flight > u32::MAX as usize
            || self.data_queue_bytes > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_batch_records > u32::MAX as usize
            || self.max_batch_bytes > u32::MAX as usize
            || self.max_batch_bytes >= self.max_frame_bytes
            || self.hello_timeout.is_zero()
            || self.tls_handshake_timeout.is_zero()
            || self.response_timeout.is_zero()
        {
            return Err(Status::invalid_argument("invalid federation gRPC limits"));
        }
        // Reserve enough space for the complete PQ identity material before
        // accepting a frame limit for a future Session transport.
        let minimum = pb::SyncFrame {
            body: Some(pb::sync_frame::Body::Hello(pb::Hello {
                protocol_version: crate::FEDERATION_PROTOCOL_VERSION,
                node_id: vec![0; FederationNodeId::LEN],
                max_frame_bytes: self.max_frame_bytes as u64,
                max_in_flight: self.max_in_flight as u32,
                max_batch_records: self.max_batch_records as u32,
                max_batch_bytes: self.max_batch_bytes as u64,
                root_descriptor: vec![0; FederationRoot::ENCODED_LEN],
                online_authorization: vec![0; FederationOnlineKeyAuthorization::ENCODED_LEN],
                root_signature: vec![0; FederationRoot::SIGNATURE_LEN],
                nonce: vec![0; 32],
                required_features: Vec::new(),
                served_capabilities: 15,
            })),
        }
        .encoded_len();
        let authentication = pb::SyncFrame {
            body: Some(pb::sync_frame::Body::Authenticate(pb::Authenticate {
                online_signature: vec![0; FederationRoot::SIGNATURE_LEN],
            })),
        }
        .encoded_len();
        if minimum > self.max_frame_bytes
            || minimum > MAX_FEDERATION_HELLO_BYTES
            || authentication > self.max_frame_bytes
        {
            return Err(Status::invalid_argument(
                "federation frame limit cannot hold Hello",
            ));
        }
        Ok(self)
    }
}

/// One outbound TLS route carrying an expected node ID. TLS certificates
/// establish only the channel: the adapter must also verify the ML-DSA root,
/// online-key authorization and current exporter-bound session proof before it
/// passes the peer identity into federation service requests.
#[derive(Clone)]
pub struct PeerDialConfig {
    /// gRPC endpoint reached over TLS.
    pub uri: String,
    /// Node identity required by the application-level peer proof.
    pub expected_peer: FederationNodeId,
    /// DNS name checked against the server certificate.
    pub server_name: String,
    /// PEM trust anchor used to validate the server's TLS certificate.
    pub peer_trust_root_pem: Vec<u8>,
    /// PEM certificate presented by this client for mutual TLS.
    pub client_certificate_pem: Vec<u8>,
    /// Private PEM key corresponding to `client_certificate_pem`.
    pub client_key_pem: Vec<u8>,
}
