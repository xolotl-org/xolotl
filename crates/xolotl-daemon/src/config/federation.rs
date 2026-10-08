//! Opt-in publisher bootstrap. Peer admission is kept in the same redb file
//! and is never inferred from the TLS certificate or these local credentials.

use crate::transport::GatewayTransportSecurityTuning;
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::num::{NonZeroU64, NonZeroUsize};
use std::time::Duration;
use xolotl_federation_grpc::config::FederationGrpcConfig;

use super::{FederationOutboundCallConfig, FederationOutboundHostedSubjectConfig};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FederationPublisherConfig {
    /// Canonical, binary v1 root descriptor. The offline root signing key is
    /// not needed by the daemon once it has signed the online authorization.
    pub root_descriptor_path: Option<String>,
    /// Binary PKCS#8 ML-DSA-65 online private key (0600).
    pub online_key_path: Option<String>,
    /// Canonical, binary v1 authorization for the online public key.
    pub online_authorization_path: Option<String>,
    /// Raw ML-DSA-65 signature over that authorization, signed by the root.
    pub online_authorization_signature_path: Option<String>,
    /// Explicit persisted peer policy reconciled before the listener binds.
    #[serde(default)]
    pub peers: Vec<FederationPeerConfig>,
    /// Stable local streams advertised by this publisher.
    #[serde(default)]
    pub streams: Vec<FederationStreamConfig>,
    /// Exact streams exposed to any authenticated federation node, without a
    /// private peer or subscription. First enablement requires an empty stream.
    #[serde(default)]
    pub public_streams: Vec<FederationPublicStreamConfig>,
    /// Exact remote public streams followed into a bounded, durable local
    /// inbox. These routes create no private peer or subscription authority.
    #[serde(default)]
    pub public_follows: Vec<FederationPublicFollowConfig>,
    /// Exact invited remote streams received under host-held Hosted Sync
    /// credentials into separate durable local inboxes.
    #[serde(default)]
    pub guest_follows: Vec<FederationGuestFollowConfig>,
    /// Explicit application-sealed snapshots for exact private node-self
    /// subscriptions. Each declaration pins bytes before publishing an offer.
    #[serde(default)]
    pub snapshot_offers: Vec<FederationSnapshotOfferConfig>,
    /// Application/operator reader-quiescence decisions for exact active
    /// private snapshot anchors. A declaration never invents a projection.
    #[serde(default)]
    pub snapshot_reader_releases: Vec<FederationSnapshotReaderReleaseConfig>,
    /// Exact publisher-side replica commitments. Omission never retires an
    /// existing commitment; retirement requires a disabled row and its CAS.
    #[serde(default)]
    pub replica_members: Vec<FederationReplicaMemberConfig>,
    /// Explicit opt-in to bounded, replica-safe publisher-log retirement.
    pub replica_history_maintenance: Option<FederationReplicaHistoryMaintenanceConfig>,
    /// Explicit public State history prefixes replayed into named streams.
    #[serde(default)]
    pub state_history_publications: Vec<FederationStateHistoryPublicationConfig>,
    /// Explicit trusted-host retirement of removed State sources. Omission
    /// retains their pins. Each declaration settles only an existing window
    /// through its exact terminal cursor, then conditionally releases the pin;
    /// it neither scans new history nor removes the published stream.
    #[serde(default)]
    pub state_history_publication_retirements:
        Vec<FederationStateHistoryPublicationRetirementConfig>,
    /// Exact implementations of exported methods in the current host lifecycle.
    #[serde(default)]
    pub methods: Vec<FederationMethodConfig>,
    /// Explicit peer/subject grants. Declaring a method never grants access.
    #[serde(default)]
    pub call_authorities: Vec<FederationCallAuthorityConfig>,
    #[serde(default)]
    pub outbound_calls: Vec<FederationOutboundCallConfig>,
    /// Explicit host-held holder credentials for stock Hosted outbound calls.
    /// Issuance and the durable local identity mapping remain application or
    /// operator decisions; this manifest never mints a Hosted assertion.
    #[serde(default)]
    pub outbound_hosted_subjects: Vec<FederationOutboundHostedSubjectConfig>,
    /// Exact remote objects to fetch into the local object store. Successful
    /// transfer records Verified; application reference binding is separate.
    #[serde(default)]
    pub object_receives: Vec<FederationObjectReceiveConfig>,
    /// When present, this manifest owns the complete set of exact object
    /// disclosure grants. Omitted rows are revoked before serving.
    pub object_grants: Option<Vec<FederationObjectGrantConfig>>,
    /// Which issuers may assert hosted subjects for a peer and purpose.
    #[serde(default)]
    pub subject_issuers: Vec<FederationSubjectIssuerConfig>,
    /// When present, this manifest owns the complete set of hosted stream
    /// grants; omitted entries are disabled at startup. Absence leaves grants
    /// to an embedding host or application access service.
    pub subject_grants: Option<Vec<FederationSubjectGrantConfig>>,
    /// Optional complete manifest of stock-owned issuer rights to share one
    /// exact stream by invitation. Omission leaves embedding-host rows alone.
    pub invitation_issuer_authorities: Option<Vec<FederationInvitationIssuerAuthorityConfig>>,
    /// Optional complete manifest of stock-owned invitations. Bearer entries
    /// contain only a precomputed digest, never the redemption secret.
    pub invitations: Option<Vec<FederationInvitationConfig>>,
    pub grpc: FederationPublisherGrpcConfig,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationInvitationIssuerAuthorityConfig {
    pub issuer: String,
    pub namespace: String,
    pub subject: String,
    pub stream_id: String,
    pub enabled: bool,
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationInvitationConfig {
    pub id: String,
    pub issuer: String,
    pub namespace: String,
    pub subject: String,
    pub stream_id: String,
    pub audience: FederationInvitationAudienceConfig,
    pub not_before_ms: u64,
    pub expires_ms: u64,
    pub grant_expires_ms: u64,
    pub max_redemptions: u32,
    pub history: FederationSubjectGrantHistoryConfig,
    /// Exact current row revision when reconciling an existing invitation.
    /// Omit only on initial creation; an unchanged row stays revision-stable.
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FederationInvitationAudienceConfig {
    Named {
        presenter: String,
        issuer: String,
        namespace: String,
        subject: String,
    },
    Bearer {
        secret_digest: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationSubjectGrantConfig {
    pub issuer: String,
    pub namespace: String,
    pub subject: String,
    pub presenter: String,
    pub stream_id: String,
    pub not_before_ms: u64,
    pub expires_ms: u64,
    pub history: FederationSubjectGrantHistoryConfig,
    pub enabled: bool,
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationSubjectGrantHistoryConfig {
    All,
    FromGrant,
}

/// A method's contract digest binds its implementation and local authority
/// template. The program ID is the portable compiler image identity, not a
/// hash of file spelling or JSON whitespace.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationMethodConfig {
    pub export: String,
    pub path: String,
    pub method: String,
    pub contract_digest: String,
    pub program_path: String,
    pub program_id: String,
    /// Stable concrete `identity://` path, registered in this host's directory.
    pub identity_path: String,
    pub codec: FederationMethodCodecConfig,
    #[serde(default)]
    pub grants: Vec<FederationMethodGrantConfig>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationMethodCodecConfig {
    BytesV1,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationMethodGrantConfig {
    pub selector: String,
    /// Named methods; empty means no method authority unless all_methods is set.
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub all_methods: bool,
    #[serde(default)]
    pub flags: Vec<FederationGrantFlagConfig>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FederationGrantFlagConfig {
    Clone,
    Transfer,
    SpawnWith,
    Delegate,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationCallAuthorityConfig {
    /// Exact authenticated transport node allowed to present the subject.
    pub presenter: String,
    pub subject: FederationCallSubjectConfig,
    pub export: String,
    pub path: String,
    pub method: String,
    pub contract_digest: String,
    pub enabled: bool,
    pub expires_ms: u64,
    pub max_input_bytes: u64,
    pub max_prepare_window_ms: u64,
    pub max_result_retention_ms: u64,
    /// Exact previous revision for a changed persisted rule; absent on create.
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FederationCallSubjectConfig {
    /// The subject is the authenticated presenter itself.
    Node,
    Hosted {
        issuer: String,
        namespace: String,
        subject: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationSubjectIssuerConfig {
    pub issuer: String,
    pub namespace: String,
    pub presenter: String,
    pub purposes: Vec<FederationSubjectPurposeConfig>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FederationSubjectPurposeConfig {
    Discover,
    Sync,
    Invoke,
    ObjectRead,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPeerConfig {
    /// Hex SHA-384 fingerprint of the peer's canonical root descriptor.
    pub node_id: String,
    pub enabled: bool,
    /// CAS revision when changing an existing peer row; absent for creation.
    pub expected_revision: Option<u64>,
    /// CAS revision when changing an existing online-admission row.
    pub admission_expected_revision: Option<u64>,
    pub minimum_online_generation: u64,
    /// Exact SHA-384 digests of root-signed online authorization bytes.
    pub allowed_authorization_digests: Vec<String>,
    #[serde(default)]
    pub exports: Vec<FederationExportConfig>,
    /// Optional outbound route. A node can dial without opening a listener.
    pub dial: Option<FederationPeerDialConfig>,
    /// Remote streams to receive over the outbound Session.
    #[serde(default)]
    pub subscriptions: Vec<FederationPeerSubscriptionConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPeerDialConfig {
    /// h2 authority, for example `http://peer.example:7443`. TLS is mandatory
    /// inside the federation connector despite this internal URI scheme.
    pub uri: String,
    pub server_name: String,
    /// PEM root pin for this peer's TLS certificate, separate from its signed
    /// federation node identity and online-key admission rule.
    pub trust_root_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPeerSubscriptionConfig {
    /// Stable 16-byte stream ID declared by the remote publisher.
    pub stream_id: String,
    /// Bump to establish a fresh delivery contract after changing authority.
    #[serde(default)]
    pub generation: u64,
    /// Explicit snapshot schemas this stock receiver is willing to archive
    /// and use as a delivery baseline. Empty means history gaps fail closed.
    #[serde(default)]
    pub snapshot_schema_revisions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum FederationSnapshotOfferConfig {
    /// Serve application-sealed content through a listener or reverse Session
    /// dial. Publication still requires an enabled serving peer and exact proof.
    Publish {
        subscriber_node: String,
        stream_id: String,
        subscription_generation: u64,
        snapshot_id: String,
        position_sequence: u64,
        position_digest: String,
        schema_revision: String,
        content_path: String,
        content_digest: String,
        content_bytes: u64,
        /// Digest of the application's durable decision that these bytes
        /// represent the exact committed stream position and scope.
        publication_digest: String,
    },
    /// Local maintenance requiring neither a listener nor a dial. The daemon
    /// reads and retires the exact current offer; concurrent replacement fails
    /// its compare-and-set without retiring the replacement.
    Retire {
        subscriber_node: String,
        stream_id: String,
        subscription_generation: u64,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationSnapshotReaderReleaseConfig {
    pub publisher_node: String,
    pub stream_id: String,
    pub subscription_generation: u64,
    pub install_id: String,
    pub federation_generation: u64,
    pub application_generation: u64,
    pub completion_digest: String,
    /// Nonzero digest of the application's durable decision that all readers
    /// through the preceding generation have stopped.
    pub release_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationReplicaMemberConfig {
    /// Exact publisher-owned stream and replica root identity.
    pub stream_id: String,
    pub member_node: String,
    /// Name an embedding host's exact subscription, or derive the stock
    /// subscriber ID from its configured generation. Set exactly one when
    /// enabled; disabled rows only need the stream and member.
    pub subscription_id: Option<String>,
    pub stock_generation: Option<u64>,
    pub enabled: bool,
    /// None promises retention until explicit CAS retirement. A lease is an
    /// absolute deadline; the daemon never silently renews it.
    pub lease_until_ms: Option<u64>,
    /// Exact current revision for an extension, re-enrollment or retirement.
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationReplicaHistoryMaintenanceConfig {
    /// Only these exact local streams may be automatically trimmed.
    pub stream_ids: Vec<String>,
    #[serde(default = "default_replica_maintenance_interval_ms")]
    pub interval_ms: NonZeroU64,
    #[serde(default = "default_replica_maintenance_batches_per_tick")]
    pub max_batches_per_tick: NonZeroUsize,
    #[serde(default = "default_replica_maintenance_records_per_batch")]
    pub records_per_batch: NonZeroUsize,
}

fn default_replica_maintenance_interval_ms() -> NonZeroU64 {
    NonZeroU64::MIN.saturating_add(9_999)
}

fn default_replica_maintenance_batches_per_tick() -> NonZeroUsize {
    NonZeroUsize::MIN.saturating_add(7)
}

fn default_replica_maintenance_records_per_batch() -> NonZeroUsize {
    NonZeroUsize::MIN.saturating_add(255)
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationExportConfig {
    pub name: String,
    pub serve: bool,
    pub receive: bool,
    /// CAS revision when changing an existing export row.
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationStreamConfig {
    /// Hex 16-byte stable stream ID.
    pub id: String,
    pub export: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPublicStreamConfig {
    /// Hex 16-byte ID of a locally declared stream.
    pub stream_id: String,
    pub enabled: bool,
    pub max_read_records: usize,
    pub max_read_bytes: usize,
    /// Exact previous revision when changing a persisted public policy.
    pub expected_revision: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationPublicFollowConfig {
    /// Pinned ML-DSA root node ID of the remote publisher.
    pub publisher_node: String,
    pub stream_id: String,
    pub dial: FederationPeerDialConfig,
    pub minimum_online_generation: u64,
    /// Exact accepted online authorization digests for this public route.
    pub allowed_authorization_digests: Vec<String>,
    /// Local rolling inbox bounds; old local payloads are pruned atomically.
    pub max_inbox_records: usize,
    pub max_inbox_bytes: usize,
}

/// One invitation-only follower. The host never derives a Guest grant from a
/// private peer row; every identity, invitation and TLS authority is pinned.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationGuestFollowConfig {
    pub publisher_node: String,
    pub stream_id: String,
    pub dial: FederationPeerDialConfig,
    pub minimum_online_generation: u64,
    pub allowed_authorization_digests: Vec<String>,
    /// Explicit stable generation for replacement of this local relationship.
    pub generation: u64,
    pub invitation_id: String,
    pub invitation_revision: u64,
    /// Optional raw 32-byte bearer secret in a private regular file.
    pub invitation_secret_path: Option<String>,
    pub issuer: String,
    pub namespace: String,
    pub subject: String,
    pub issuer_descriptor_path: String,
    pub assertion_path: String,
    pub issuer_signature_path: String,
    pub holder_key_path: String,
    pub max_inbox_records: usize,
    pub max_inbox_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationObjectGrantConfig {
    pub presenter: String,
    pub subject: FederationCallSubjectConfig,
    /// Lowercase 96-character SHA-384 content digest.
    pub hash: String,
    pub size: u64,
    pub mime: Option<String>,
    pub range_start: u64,
    pub range_end: u64,
    pub expires_at_ms: u64,
    pub max_total_bytes: u64,
    pub max_chunk_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationObjectReceiveConfig {
    /// Node ID of an enabled private peer with a pinned outbound TLS route.
    pub provider_node: String,
    pub grant_id: u64,
    pub grant_revision: u64,
    /// Exact BlobRef expected from that grant.
    pub hash: String,
    pub size: u64,
    pub mime: Option<String>,
    /// SHA-384 digest of the local application context selecting this object.
    pub owner_digest: String,
    /// Explicit per-request and local allocation bound, at most 512 KiB.
    pub max_chunk_bytes: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationStateHistoryPublicationConfig {
    /// Must be below `state://federation/public/<namespace>`.
    pub prefix: String,
    /// Hex 16-byte ID of a stream declared in this config.
    pub stream_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationStateHistoryPublicationRetirementConfig {
    pub prefix: String,
    pub stream_id: String,
    /// Exact completed cursor, or the fixed high watermark of an existing
    /// pending window. A mismatch rejects without extending publication.
    pub expected_cursor: i64,
}

impl FederationPublisherConfig {
    pub fn required_path<'a>(value: &'a Option<String>, label: &str) -> Result<&'a str> {
        let path = value
            .as_deref()
            .map(str::trim)
            .filter(|path| !path.is_empty());
        let path = path.ok_or_else(|| anyhow::anyhow!("federation.{label} is required"))?;
        ensure!(
            std::path::Path::new(path).is_absolute(),
            "federation.{label} must be an absolute path"
        );
        Ok(path)
    }

    pub fn validate_credentials(&self) -> Result<()> {
        ensure!(
            !self.peers.is_empty()
                || !self.streams.is_empty()
                || !self.state_history_publications.is_empty()
                || !self.public_streams.is_empty()
                || !self.public_follows.is_empty()
                || !self.guest_follows.is_empty()
                || !self.replica_members.is_empty()
                || self.replica_history_maintenance.is_some()
                || !self.snapshot_reader_releases.is_empty()
                || self
                    .object_grants
                    .as_ref()
                    .is_some_and(|grants| !grants.is_empty())
                || !self.subject_issuers.is_empty()
                || self
                    .invitations
                    .as_ref()
                    .is_some_and(|items| !items.is_empty()),
            "federation requires an explicit peer, stream, follow, snapshot release, object grant or subject issuer policy"
        );
        Self::required_path(&self.root_descriptor_path, "root_descriptor_path")?;
        Self::required_path(&self.online_key_path, "online_key_path")?;
        Self::required_path(&self.online_authorization_path, "online_authorization_path")?;
        Self::required_path(
            &self.online_authorization_signature_path,
            "online_authorization_signature_path",
        )?;
        self.grpc.service_config()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FederationPublisherGrpcConfig {
    pub transport_security: GatewayTransportSecurityTuning,
    pub max_frame_bytes: usize,
    pub max_sessions: usize,
    pub max_blocking_verifications: usize,
    pub max_in_flight: usize,
    pub max_batch_records: usize,
    pub max_batch_bytes: usize,
    pub control_queue_frames: usize,
    pub data_queue_frames: usize,
    pub data_queue_bytes: usize,
    pub hello_timeout_ms: u64,
    pub tls_handshake_timeout_ms: u64,
    pub response_timeout_ms: u64,
}

impl Default for FederationPublisherGrpcConfig {
    fn default() -> Self {
        let config = FederationGrpcConfig::default();
        Self {
            transport_security: GatewayTransportSecurityTuning::default(),
            max_frame_bytes: config.max_frame_bytes,
            max_sessions: config.max_sessions,
            max_blocking_verifications: config.max_blocking_verifications,
            max_in_flight: config.max_in_flight,
            max_batch_records: config.max_batch_records,
            max_batch_bytes: config.max_batch_bytes,
            control_queue_frames: config.control_queue_frames,
            data_queue_frames: config.data_queue_frames,
            data_queue_bytes: config.data_queue_bytes,
            hello_timeout_ms: config.hello_timeout.as_millis() as u64,
            tls_handshake_timeout_ms: config.tls_handshake_timeout.as_millis() as u64,
            response_timeout_ms: config.response_timeout.as_millis() as u64,
        }
    }
}

impl FederationPublisherGrpcConfig {
    pub fn service_config(&self) -> Result<FederationGrpcConfig> {
        FederationGrpcConfig {
            max_frame_bytes: self.max_frame_bytes,
            max_sessions: self.max_sessions,
            max_blocking_verifications: self.max_blocking_verifications,
            max_in_flight: self.max_in_flight,
            max_batch_records: self.max_batch_records,
            max_batch_bytes: self.max_batch_bytes,
            control_queue_frames: self.control_queue_frames,
            data_queue_frames: self.data_queue_frames,
            data_queue_bytes: self.data_queue_bytes,
            hello_timeout: Duration::from_millis(self.hello_timeout_ms),
            tls_handshake_timeout: Duration::from_millis(self.tls_handshake_timeout_ms),
            response_timeout: Duration::from_millis(self.response_timeout_ms),
        }
        .validate()
        .map_err(|error| anyhow::anyhow!("invalid federation gRPC configuration: {error}"))
    }
}
