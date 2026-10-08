//! Stock publisher listener. An address explicitly opts in; all signing,
//! transport and peer-admission state must be present before the bind succeeds.

mod guest_follows;
mod invitations;
mod object_receives;
mod private_follows;
mod public_follows;
mod publication_retirement;
mod replica_retention;
mod snapshot_publisher;
mod snapshot_receiver;
#[cfg(test)]
mod snapshot_stock_tests;
mod storage_workers;
mod subject_grants;

use anyhow::{Context, Result, ensure};
use futures_util::stream;
use private_follows::run_subscriptions;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tonic::Status;
use xolotl_federation::{
    AuthorityOwner, CallCancelled, CallInvoked, CancelCallRequest, EventType, ExportAccess,
    ExportName, FederationError, FederationInvitationStore as _, FederationLimits,
    FederationManagement as _, FederationNodeId, FederationObjectReadService,
    FederationObjectReadStore as _, FederationOnlineKey, FederationOnlineKeyAuthorization,
    FederationPublicReadStore as _, FederationPublicService, FederationRoot, FederationService,
    FederationStore as _, InvokeCallRequest, ObjectGrantSpec, ObjectReadAuthority,
    ObjectReadRequest, PeerAdmission, PrepareCallRequest, PublicReadLimits, PublicStreamPolicy,
    PublishRequest, RequestId, SchemaRevision, StreamId, StreamRef, StreamSpec, SubjectIssuerId,
    SubjectPurpose, SubscriptionId, SubscriptionRef, VerifiedFederationPeerProof,
};
use xolotl_federation_grpc::{
    FederationCallInvoker, FederationGrpcPublisherServer, FederationGrpcRuntime,
    FederationGrpcSubscriberClient, FederationLocalCredentials, FederationObjectReader,
    FederationPeerPolicy, FederationSubscriberServices, config::PeerDialConfig,
    federation_tls_incoming,
};
use xolotl_federation_kernel::FederationKernelCallBridge;
use xolotl_gateway::GatewayTransportSecurityMode;
#[cfg(all(test, unix))]
use xolotl_sdk::Backend;
use xolotl_sdk::Bootstrap;
use xolotl_state::StateHistoryEntry;
use xolotl_state::host::object::ObjectStore;
use xolotl_storage_redb::{
    RedbFederationStateProjection, RedbFederationStore, RedbGuestFollowerStore,
    RedbPublicFollowerStore,
};

use crate::{
    config::{
        FederationCallAuthorityConfig, FederationCallSubjectConfig, FederationMethodConfig,
        FederationObjectGrantConfig, FederationOutboundCallConfig, FederationPublisherConfig,
        StorageHistoryMode, StorageKind, XolotlConfig,
    },
    federation_catalog::{
        StockFederationCatalog, SubjectIssuerRule, parse_authorities, parse_issuer_rules,
        reconcile_authorities,
    },
    transport,
};

const STOCK_RECORD_BYTES: usize = 512 * 1024;
const RECORD_FRAME_OVERHEAD: usize = 4096;
const OUTBOUND_RETIRE_PAGE: usize = 256;
const OUTBOUND_RETIRE_PAGES_PER_PASS: usize = 8;
const INVITATION_RETIRE_PAGE: usize = 256;
const INVITATION_RETIRE_PAGES_PER_PASS: usize = 8;

/// Scan a bounded number of source-ledger pages at host startup or on
/// a maintenance tick. The cursor survives across ticks so an old active row
/// cannot starve retirement of later terminal rows.
pub(crate) async fn retire_completed_outbound_pages(
    runtime: &xolotl_kernel::host::HostRuntime,
    store: RedbFederationStore,
    after: Option<RequestId>,
) -> Result<Option<RequestId>> {
    runtime
        .dispatch_blocking(move || {
            let mut cursor = after;
            for _ in 0..OUTBOUND_RETIRE_PAGES_PER_PASS {
                let (_retired, next) =
                    store.retire_completed_outbound(cursor, OUTBOUND_RETIRE_PAGE)?;
                cursor = next;
                if cursor.is_none() {
                    break;
                }
            }
            Ok::<_, FederationError>(cursor)
        })?
        .await
        .context("outbound retirement worker failed")?
        .map_err(Into::into)
}

pub(crate) fn start_outbound_retirement(
    runtime: xolotl_kernel::host::HostRuntime,
    store: RedbFederationStore,
    mut cursor: Option<RequestId>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            match retire_completed_outbound_pages(&runtime, store.clone(), cursor).await {
                Ok(next) => cursor = next,
                Err(error) => tracing::warn!(%error, "federation outbound retirement failed"),
            }
        }
    })
}

pub(crate) fn start_invitation_retirement(
    runtime: xolotl_kernel::host::HostRuntime,
    store: RedbFederationStore,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok());
            if let Some(now_ms) = now_ms {
                let store = store.clone();
                let result = async {
                    runtime
                        .dispatch_blocking(move || {
                            for _ in 0..INVITATION_RETIRE_PAGES_PER_PASS {
                                let retired = store
                                    .retire_expired_invitations(now_ms, INVITATION_RETIRE_PAGE)?;
                                if retired < INVITATION_RETIRE_PAGE {
                                    break;
                                }
                            }
                            Ok::<_, FederationError>(())
                        })?
                        .await
                        .context("federation invitation retirement worker failed")?
                        .map_err(anyhow::Error::from)
                }
                .await;
                match result {
                    Ok(()) => {}
                    Err(error) => {
                        tracing::warn!(%error, "federation invitation retirement failed");
                    }
                }
            } else {
                tracing::warn!("federation invitation retirement clock is unavailable");
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    })
}

pub(crate) struct PreparedPublisher {
    address: Option<SocketAddr>,
    snapshot_storage_path: String,
    local: Arc<FederationLocalCredentials>,
    online_not_before_ms: u64,
    online_expires_ms: u64,
    tls: Arc<rustls::ServerConfig>,
    grpc: xolotl_federation_grpc::config::FederationGrpcConfig,
    transport_runtime: std::sync::OnceLock<FederationGrpcRuntime>,
    policy: PublisherPolicyPlan,
    methods: Vec<FederationMethodConfig>,
    call_authorities: Vec<FederationCallAuthorityConfig>,
    outbound_calls: Vec<FederationOutboundCallConfig>,
    outbound_hosted: Vec<crate::federation_outbound::PreparedHostedSubject>,
    object_grants: Option<Vec<ObjectGrantSpec>>,
    invitation_manifest: invitations::ManifestPlan,
    object_receives: Vec<object_receives::PreparedObjectReceive>,
    snapshot_offers: Vec<snapshot_publisher::PreparedSnapshotOffer>,
    snapshot_reader_releases: Vec<snapshot_receiver::PreparedReaderRelease>,
    public_follows: Vec<public_follows::PreparedPublicFollow>,
    guest_follows: Vec<guest_follows::PreparedGuestFollow>,
    replica_retention: replica_retention::Plan,
}

struct PublisherPolicyPlan {
    peers: Vec<PeerPlan>,
    streams: Vec<StreamSpec>,
    public_streams: Vec<PublicStreamPlan>,
    publications: Vec<StateHistoryPublication>,
    publication_retirements: Vec<publication_retirement::Retirement>,
    dials: Vec<PeerDialPlan>,
    inbound_subscriptions: Vec<InboundPeerPlan>,
    issuer_rules: Vec<SubjectIssuerRule>,
    subject_grants: Option<Vec<subject_grants::PreparedSubjectGrant>>,
}

struct PublicStreamPlan {
    policy: PublicStreamPolicy,
    expected_revision: Option<u64>,
}

#[derive(Clone)]
struct PeerDialPlan {
    route: PeerDialConfig,
    subscriptions: Vec<RemoteSubscriptionPlan>,
}

#[derive(Clone)]
struct InboundPeerPlan {
    peer: FederationNodeId,
    subscriptions: Vec<RemoteSubscriptionPlan>,
}

#[derive(Clone)]
struct RemoteSubscriptionPlan {
    stream: StreamRef,
    subscription: SubscriptionRef,
    request_id: RequestId,
    snapshot_schemas: Arc<[SchemaRevision]>,
}

struct PeerPlan {
    node: FederationNodeId,
    enabled: bool,
    expected_revision: Option<u64>,
    admission_expected_revision: Option<u64>,
    admission: PeerAdmission,
    exports: Vec<ExportPlan>,
}

struct ExportPlan {
    name: ExportName,
    access: ExportAccess,
    expected_revision: Option<u64>,
}

#[derive(Clone)]
struct StateHistoryPublication {
    prefix: xolotl_types::Path,
    stream: StreamRef,
}

fn state_publication_prefix(value: &str) -> Result<xolotl_types::Path> {
    let prefix =
        xolotl_types::Path::parse(value).context("invalid federation State publication prefix")?;
    RedbFederationStateProjection::validate_publication_prefix(&prefix)?;
    ensure!(
        prefix.cluster().is_none()
            && prefix.scheme() == "state"
            && prefix.segments().len() >= 3
            && prefix.segments()[0].as_str() == "federation"
            && prefix.segments()[1].as_str() == "public",
        "federation publication prefix must be below state://federation/public/<namespace>"
    );
    Ok(prefix)
}

impl PreparedPublisher {
    pub(crate) fn transport_runtime(
        &self,
        host: &xolotl_kernel::host::HostRuntime,
    ) -> Result<FederationGrpcRuntime> {
        let blocking = host.blocking_spawner();
        if let Some(runtime) = self.transport_runtime.get() {
            ensure!(
                Arc::ptr_eq(&runtime.blocking_spawner(), &blocking),
                "federation transport already belongs to another host"
            );
            return Ok(runtime.clone());
        }
        let runtime = FederationGrpcRuntime::new(self.grpc, blocking.clone())?;
        let selected = self.transport_runtime.get_or_init(|| runtime);
        ensure!(
            Arc::ptr_eq(&selected.blocking_spawner(), &blocking),
            "federation transport already belongs to another host"
        );
        Ok(selected.clone())
    }

    pub(crate) fn node_id(&self) -> xolotl_federation::FederationNodeId {
        self.local.node_id()
    }

    pub(crate) fn needs_projection(&self) -> bool {
        !self.policy.publications.is_empty() || !self.policy.publication_retirements.is_empty()
    }

    pub(crate) fn needs_public_follow_store(&self) -> bool {
        !self.public_follows.is_empty()
    }

    pub(crate) fn start_public_follows(
        &self,
        runtime: &xolotl_kernel::host::HostRuntime,
        federation_store: RedbFederationStore,
        follow_store: RedbPublicFollowerStore,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>> {
        public_follows::start(
            self.public_follows.clone(),
            federation_store,
            follow_store,
            Arc::clone(&self.local),
            self.transport_runtime(runtime)?,
        )
    }

    pub(crate) fn needs_guest_follow_store(&self) -> bool {
        !self.guest_follows.is_empty()
    }

    pub(crate) fn start_guest_follows(
        &self,
        runtime: &xolotl_kernel::host::HostRuntime,
        federation_store: RedbFederationStore,
        guest_store: RedbGuestFollowerStore,
    ) -> Result<Vec<tokio::task::JoinHandle<()>>> {
        guest_follows::start(
            self.guest_follows.clone(),
            federation_store,
            guest_store,
            Arc::clone(&self.local),
            self.transport_runtime(runtime)?,
        )
    }

    pub(crate) fn start_remote_cancellation_retries(
        &self,
        runtime: xolotl_kernel::host::HostRuntime,
        store: RedbFederationStore,
    ) -> Result<tokio::task::JoinHandle<()>> {
        let sessions = self.outbound_sessions(&runtime, store.clone())?;
        Ok(crate::federation_cancellation::start_remote_retries(
            runtime, store, sessions,
        ))
    }

    pub(crate) fn outbound_sessions(
        &self,
        runtime: &xolotl_kernel::host::HostRuntime,
        store: RedbFederationStore,
    ) -> Result<Arc<dyn xolotl_federation_grpc::FederationCallSessionProvider>> {
        // Cancellation maintenance can start before the listener's own policy
        // reconciliation, including when no outbound Resource remains active.
        reconcile_policy(&store, &self.policy)?;
        let policy: Arc<dyn FederationPeerPolicy> = Arc::new(PersistedPeerPolicy {
            store,
            local: self.local.node_id(),
            issuer_rules: self.policy.issuer_rules.clone(),
        });
        crate::federation_outbound::stock_sessions(
            Arc::clone(&self.local),
            policy,
            self.transport_runtime(runtime)?,
            self.policy.dials.iter().map(|dial| dial.route.clone()),
            &self.outbound_hosted,
        )
    }

    /// Install stable outbound Resources before live Kernel execution.
    pub(crate) fn install_outbound(
        &self,
        boot: &Bootstrap,
        store: &RedbFederationStore,
    ) -> Result<()> {
        if self.outbound_calls.is_empty() {
            return Ok(());
        }
        reconcile_policy(store, &self.policy)?;
        let policy: Arc<dyn FederationPeerPolicy> = Arc::new(PersistedPeerPolicy {
            store: store.clone(),
            local: self.local.node_id(),
            issuer_rules: self.policy.issuer_rules.clone(),
        });
        crate::federation_outbound::install(
            boot,
            store.clone(),
            &self.outbound_calls,
            &self.outbound_hosted,
            crate::federation_outbound::StockConnectionConfig {
                routes: self
                    .policy
                    .dials
                    .iter()
                    .map(|dial| dial.route.clone())
                    .collect(),
                local: Arc::clone(&self.local),
                policy,
                grpc: self.transport_runtime(boot.kernel().host_runtime())?,
            },
        )
    }
}

pub(crate) fn prepare(config: &XolotlConfig) -> Result<Option<PreparedPublisher>> {
    let address = config.server.federation_grpc_addr.as_deref();
    if address.is_none()
        && config.federation.streams.is_empty()
        && config.federation.state_history_publications.is_empty()
        && config
            .federation
            .state_history_publication_retirements
            .is_empty()
        && config.federation.public_streams.is_empty()
        && config.federation.public_follows.is_empty()
        && config.federation.guest_follows.is_empty()
        && config.federation.object_receives.is_empty()
        && config.federation.snapshot_offers.is_empty()
        && config.federation.snapshot_reader_releases.is_empty()
        && config.federation.outbound_calls.is_empty()
        && config.federation.outbound_hosted_subjects.is_empty()
        && config.federation.replica_members.is_empty()
        && config.federation.replica_history_maintenance.is_none()
        && config
            .federation
            .peers
            .iter()
            .all(|peer| peer.dial.is_none() && peer.subscriptions.is_empty())
    {
        return Ok(None);
    }
    ensure!(
        address.is_some() || config.federation.public_streams.is_empty(),
        "public federation streams require a publisher listener"
    );
    ensure!(
        config.storage.kind == StorageKind::Redb,
        "federation publisher requires persistent redb storage"
    );
    if !config.federation.state_history_publications.is_empty()
        || !config
            .federation
            .state_history_publication_retirements
            .is_empty()
    {
        ensure!(
            config.storage.state_history == StorageHistoryMode::Full,
            "federation State publication requires State history capability"
        );
    }
    let credentials = &config.federation;
    credentials.validate_credentials()?;
    let security = credentials
        .grpc
        .transport_security
        .validate_grpc_listener("federation transport", address.unwrap_or("127.0.0.1:0"))?;
    ensure!(
        matches!(
            security.config.mode,
            GatewayTransportSecurityMode::ProductionTls | GatewayTransportSecurityMode::MutualTls
        ),
        "federation publisher requires production_tls or mtls"
    );
    ensure!(
        security.config.trusted_proxy.peers.is_empty()
            && security.config.unsafe_relaxations.is_empty(),
        "federation publisher cannot use proxy trust or unsafe transport relaxations"
    );
    let tls = transport::grpc_tls_server_config(&security)?
        .context("federation publisher TLS material is required")?;
    let (local, online_not_before_ms, online_expires_ms) = load_local_credentials(credentials)?;
    let material = security
        .tls
        .as_ref()
        .context("federation TLS material is required")?;
    let policy = parse_policy(credentials, local.node_id(), address.is_some(), material)?;
    let outbound_hosted = crate::federation_outbound::parse_hosted(
        &credentials.outbound_hosted_subjects,
        local.node_id(),
        policy.dials.iter().map(|dial| dial.route.expected_peer),
    )?;
    let public_follows = public_follows::parse(
        &credentials.public_follows,
        local.node_id(),
        material,
        &credentials.peers,
        &credentials.grpc,
    )?;
    let guest_follows = guest_follows::parse(
        &credentials.guest_follows,
        local.node_id(),
        material,
        &credentials.peers,
        &credentials.grpc,
    )?;
    let invitation_manifest = invitations::parse(
        credentials.invitation_issuer_authorities.as_deref(),
        credentials.invitations.as_deref(),
        local.node_id(),
        &policy.streams,
        &policy.issuer_rules,
    )?;
    let object_grants = parse_object_grants(credentials.object_grants.as_deref(), local.node_id())?;
    let grpc = credentials.grpc.service_config()?;
    let object_receives = object_receives::parse(
        &credentials.object_receives,
        local.node_id(),
        &policy.dials,
        grpc,
    )?;
    let replica_retention =
        replica_retention::parse(credentials, local.node_id(), &policy.streams)?;
    let snapshot_offers = snapshot_publisher::parse(
        &credentials.snapshot_offers,
        local.node_id(),
        &policy.streams,
        &credentials.peers,
    )?;
    let snapshot_reader_releases =
        snapshot_receiver::parse_releases(&credentials.snapshot_reader_releases, local.node_id())?;
    ensure!(
        address.is_some()
            || !snapshot_offers.iter().any(|offer| matches!(
                offer.action,
                snapshot_publisher::SnapshotOfferAction::Publish(_)
            ))
            || !policy.dials.is_empty(),
        "stock snapshot offers require a listener or reverse Session dial"
    );
    ensure!(
        grpc.max_batch_bytes >= STOCK_RECORD_BYTES
            && grpc.max_frame_bytes >= STOCK_RECORD_BYTES + RECORD_FRAME_OVERHEAD,
        "stock federation requires a 512 KiB batch and frame space for one complete record"
    );
    Ok(Some(PreparedPublisher {
        address: address.map(|_| security.listen_addr),
        snapshot_storage_path: config.storage.path.clone(),
        local,
        online_not_before_ms,
        online_expires_ms,
        tls,
        grpc,
        transport_runtime: std::sync::OnceLock::new(),
        policy,
        methods: credentials.methods.clone(),
        call_authorities: credentials.call_authorities.clone(),
        outbound_calls: credentials.outbound_calls.clone(),
        outbound_hosted,
        object_grants,
        invitation_manifest,
        object_receives,
        snapshot_offers,
        snapshot_reader_releases,
        public_follows,
        guest_follows,
        replica_retention,
    }))
}

fn load_local_credentials(
    config: &FederationPublisherConfig,
) -> Result<(Arc<FederationLocalCredentials>, u64, u64)> {
    let root = crate::config::read_private_bounded_file(
        FederationPublisherConfig::required_path(
            &config.root_descriptor_path,
            "root_descriptor_path",
        )?,
        "federation root descriptor",
        FederationRoot::ENCODED_LEN as u64,
    )?;
    let root = FederationRoot::decode(&root).context("decode federation root descriptor")?;
    let online_key = crate::config::read_private_bounded_file(
        FederationPublisherConfig::required_path(&config.online_key_path, "online_key_path")?,
        "federation online key",
        64 * 1024,
    )?;
    let online_key = FederationOnlineKey::from_pkcs8(&online_key)
        .context("decode federation online ML-DSA-65 PKCS#8 key")?;
    let authorization = crate::config::read_private_bounded_file(
        FederationPublisherConfig::required_path(
            &config.online_authorization_path,
            "online_authorization_path",
        )?,
        "federation online authorization",
        FederationOnlineKeyAuthorization::ENCODED_LEN as u64,
    )?;
    let authorization = FederationOnlineKeyAuthorization::decode(&authorization)
        .context("decode federation online authorization")?;
    let not_before_ms = authorization.not_before_ms();
    let expires_ms = authorization.expires_ms();
    let signature = crate::config::read_private_bounded_file(
        FederationPublisherConfig::required_path(
            &config.online_authorization_signature_path,
            "online_authorization_signature_path",
        )?,
        "federation online authorization signature",
        FederationRoot::SIGNATURE_LEN as u64,
    )?;
    ensure!(
        signature.len() == FederationRoot::SIGNATURE_LEN,
        "federation online authorization signature has the wrong length"
    );
    let local =
        FederationLocalCredentials::new(root, authorization, signature.to_vec(), online_key)
            .context("validate local federation signer and root authorization")?;
    Ok((Arc::new(local), not_before_ms, expires_ms))
}

fn parse_policy(
    config: &FederationPublisherConfig,
    local: FederationNodeId,
    listening: bool,
    tls: &transport::GatewayListenerTlsMaterial,
) -> Result<PublisherPolicyPlan> {
    let mut peer_ids = HashSet::new();
    let mut peers = Vec::with_capacity(config.peers.len());
    let mut dials = Vec::new();
    let mut inbound_subscriptions = Vec::new();
    for peer in &config.peers {
        let node = FederationNodeId::from_bytes(decode_hex::<48>(&peer.node_id, "peer node_id")?);
        ensure!(node != local, "federation peer cannot be the local node");
        ensure!(peer_ids.insert(node), "duplicate federation peer node_id");
        validate_revision(peer.expected_revision, "peer expected_revision")?;
        validate_revision(
            peer.admission_expected_revision,
            "peer admission_expected_revision",
        )?;
        let admission = PeerAdmission {
            minimum_online_generation: peer.minimum_online_generation,
            allowed_authorization_digests: peer
                .allowed_authorization_digests
                .iter()
                .map(|digest| decode_hex::<48>(digest, "online authorization digest"))
                .collect::<Result<Vec<_>>>()?,
        };
        admission.validate()?;
        let mut export_names = HashSet::new();
        let mut exports = Vec::with_capacity(peer.exports.len());
        for export in &peer.exports {
            let name = ExportName::new(export.name.clone())?;
            ensure!(
                export_names.insert(name.clone()),
                "duplicate federation peer export"
            );
            validate_revision(export.expected_revision, "export expected_revision")?;
            exports.push(ExportPlan {
                name,
                access: ExportAccess {
                    serve: export.serve,
                    receive: export.receive,
                },
                expected_revision: export.expected_revision,
            });
        }
        peers.push(PeerPlan {
            node,
            enabled: peer.enabled,
            expected_revision: peer.expected_revision,
            admission_expected_revision: peer.admission_expected_revision,
            admission,
            exports,
        });
        ensure!(
            peer.dial.is_some() || listening || peer.subscriptions.is_empty(),
            "federation subscriptions require an outbound route or local listener"
        );
        ensure!(
            peer.subscriptions.is_empty() || peer.enabled,
            "federation subscription peer must be enabled"
        );
        ensure!(
            peer.subscriptions.is_empty() || peer.exports.iter().any(|export| export.receive),
            "federation subscriptions require an explicit receive export grant"
        );
        let mut seen = HashSet::new();
        let mut subscriptions = Vec::new();
        for subscription in &peer.subscriptions {
            let id = StreamId::from_bytes(decode_hex::<16>(
                &subscription.stream_id,
                "subscription stream_id",
            )?);
            ensure!(
                seen.insert(id),
                "duplicate federation subscription stream_id"
            );
            let stream = StreamRef {
                publisher: node,
                id,
            };
            ensure!(
                subscription.snapshot_schema_revisions.len() <= 16,
                "too many snapshot schemas for one federation subscription"
            );
            let mut snapshot_schemas =
                Vec::with_capacity(subscription.snapshot_schema_revisions.len());
            for schema in &subscription.snapshot_schema_revisions {
                let revision = SchemaRevision::from_bytes(decode_hex::<32>(
                    schema,
                    "snapshot schema revision",
                )?);
                ensure!(
                    !snapshot_schemas.contains(&revision),
                    "duplicate snapshot schema revision"
                );
                snapshot_schemas.push(revision);
            }
            let mut plan = remote_subscription(local, stream, subscription.generation);
            plan.snapshot_schemas = snapshot_schemas.into();
            subscriptions.push(plan);
        }
        if let Some(dial) = &peer.dial {
            ensure!(peer.enabled, "federation outbound peer must be enabled");
            let uri = tonic::transport::Endpoint::from_shared(dial.uri.clone())?;
            let uri = uri.uri();
            ensure!(
                uri.scheme_str() == Some("http")
                    && uri.host().is_some()
                    && uri.port_u16().is_some()
                    && uri.path() == "/"
                    && uri.query().is_none(),
                "federation dial URI must be an http authority with an explicit port"
            );
            rustls::pki_types::ServerName::try_from(dial.server_name.as_str())
                .context("invalid federation peer TLS server_name")?;
            let trust_root = std::path::Path::new(&dial.trust_root_path);
            ensure!(
                trust_root.is_absolute() && trust_root.is_file(),
                "federation peer trust_root_path must be an absolute regular file"
            );
            let peer_trust_root_pem = std::fs::read(trust_root).with_context(|| {
                format!("read federation peer trust root '{}'", dial.trust_root_path)
            })?;
            ensure!(
                !peer_trust_root_pem.is_empty() && peer_trust_root_pem.len() <= 1024 * 1024,
                "federation peer trust root must be 1 MiB or less"
            );
            dials.push(PeerDialPlan {
                route: PeerDialConfig {
                    uri: dial.uri.clone(),
                    expected_peer: node,
                    server_name: dial.server_name.clone(),
                    peer_trust_root_pem,
                    client_certificate_pem: tls.certificate_chain_pem.clone(),
                    client_key_pem: tls.private_key_pem.to_vec(),
                },
                subscriptions,
            });
        } else if !subscriptions.is_empty() {
            inbound_subscriptions.push(InboundPeerPlan {
                peer: node,
                subscriptions,
            });
        }
    }
    let mut stream_ids = HashSet::new();
    let mut streams = Vec::with_capacity(config.streams.len());
    for stream in &config.streams {
        let id = StreamId::from_bytes(decode_hex::<16>(&stream.id, "stream id")?);
        ensure!(stream_ids.insert(id), "duplicate federation stream id");
        streams.push(StreamSpec {
            stream: StreamRef {
                publisher: local,
                id,
            },
            export: ExportName::new(stream.export.clone())?,
        });
    }
    let mut publications: Vec<StateHistoryPublication> = Vec::new();
    let mut published_ids = HashSet::new();
    for publication in &config.state_history_publications {
        let prefix = state_publication_prefix(&publication.prefix)?;
        ensure!(
            publications.iter().all(|other| {
                !prefix.is_prefix_of(&other.prefix) && !other.prefix.is_prefix_of(&prefix)
            }),
            "federation State publication prefixes must not overlap"
        );
        let id = StreamId::from_bytes(decode_hex::<16>(
            &publication.stream_id,
            "publication stream_id",
        )?);
        ensure!(
            published_ids.insert(id),
            "federation stream has multiple State sources"
        );
        let stream = streams
            .iter()
            .find(|stream| stream.stream.id == id)
            .ok_or_else(|| {
                anyhow::anyhow!("federation publication references undeclared stream")
            })?;
        publications.push(StateHistoryPublication {
            prefix,
            stream: stream.stream,
        });
    }
    let publication_retirements = publication_retirement::parse(config, local, &published_ids)?;
    ensure!(
        stream_ids.iter().all(|id| {
            published_ids.contains(id)
                || publication_retirements
                    .iter()
                    .any(|retirement| retirement.stream_id() == *id)
        }),
        "every federation stream must have one State publication source or exact retirement"
    );
    let mut public_ids = HashSet::new();
    let mut public_streams = Vec::with_capacity(config.public_streams.len());
    for public in &config.public_streams {
        let id = StreamId::from_bytes(decode_hex::<16>(&public.stream_id, "public stream_id")?);
        ensure!(
            public_ids.insert(id),
            "duplicate federation public stream_id"
        );
        let stream = streams
            .iter()
            .find(|stream| stream.stream.id == id)
            .ok_or_else(|| anyhow::anyhow!("public policy references undeclared stream"))?;
        validate_revision(public.expected_revision, "public expected_revision")?;
        let policy = PublicStreamPolicy {
            stream: stream.stream,
            enabled: public.enabled,
            max_read_records: public.max_read_records,
            max_read_bytes: public.max_read_bytes,
        };
        policy.validate(local)?;
        ensure!(
            public.max_read_records <= config.grpc.max_batch_records
                && public.max_read_bytes <= config.grpc.max_batch_bytes,
            "public policy exceeds stock federation batch limits"
        );
        public_streams.push(PublicStreamPlan {
            policy,
            expected_revision: public.expected_revision,
        });
    }
    let known_peers: Vec<_> = peers.iter().map(|peer| peer.node).collect();
    let issuer_rules = parse_issuer_rules(&config.subject_issuers, local, &known_peers)?;
    let enabled_peers: Vec<_> = peers
        .iter()
        .filter(|peer| peer.enabled)
        .map(|peer| peer.node)
        .collect();
    let subject_grants = subject_grants::parse(
        config.subject_grants.as_deref(),
        local,
        &enabled_peers,
        &streams,
        &issuer_rules,
    )?;
    Ok(PublisherPolicyPlan {
        peers,
        streams,
        public_streams,
        publications,
        publication_retirements,
        dials,
        inbound_subscriptions,
        issuer_rules,
        subject_grants,
    })
}

fn remote_subscription(
    local: FederationNodeId,
    stream: StreamRef,
    generation: u64,
) -> RemoteSubscriptionPlan {
    fn id(domain: &str, local: FederationNodeId, stream: StreamRef, generation: u64) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new_derive_key(domain);
        hasher.update(local.as_bytes());
        hasher.update(stream.publisher.as_bytes());
        hasher.update(stream.id.as_bytes());
        hasher.update(&generation.to_be_bytes());
        let mut output = [0; 16];
        output.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        output
    }
    RemoteSubscriptionPlan {
        stream,
        subscription: SubscriptionRef {
            subscriber: local,
            id: SubscriptionId::from_bytes(id(
                "xolotl.federation.stock-subscription-id.v1",
                local,
                stream,
                generation,
            )),
        },
        request_id: RequestId::from_bytes(id(
            "xolotl.federation.stock-open-request-id.v1",
            local,
            stream,
            generation,
        )),
        snapshot_schemas: Arc::from([]),
    }
}

fn validate_revision(revision: Option<u64>, label: &str) -> Result<()> {
    ensure!(revision != Some(0), "federation {label} must be positive");
    Ok(())
}

fn parse_object_grants(
    config: Option<&[FederationObjectGrantConfig]>,
    local: FederationNodeId,
) -> Result<Option<Vec<ObjectGrantSpec>>> {
    let Some(config) = config else {
        return Ok(None);
    };
    ensure!(
        config.len() <= xolotl_federation::MAX_OBJECT_GRANTS,
        "too many object grants"
    );
    let mut grants = Vec::with_capacity(config.len());
    for entry in config {
        let presenter =
            FederationNodeId::from_bytes(decode_hex::<48>(&entry.presenter, "object presenter")?);
        let subject = match &entry.subject {
            FederationCallSubjectConfig::Node => {
                xolotl_federation::FederationSubject::Node(presenter)
            }
            FederationCallSubjectConfig::Hosted {
                issuer,
                namespace,
                subject,
            } => xolotl_federation::FederationSubject::Hosted(xolotl_federation::HostedSubject {
                issuer: SubjectIssuerId::from_bytes(decode_hex::<48>(
                    issuer,
                    "object subject issuer",
                )?),
                namespace: namespace.clone(),
                subject: subject.clone(),
            }),
        };
        let spec = ObjectGrantSpec {
            presenter,
            subject,
            blob: xolotl_types::BlobRef {
                hash: entry.hash.clone(),
                size: entry.size,
                mime: entry.mime.clone(),
            },
            range_start: entry.range_start,
            range_end: entry.range_end,
            expires_at_ms: entry.expires_at_ms,
            max_total_bytes: entry.max_total_bytes,
            max_chunk_bytes: entry.max_chunk_bytes,
        };
        spec.validate(local)?;
        ensure!(!grants.contains(&spec), "duplicate object grant");
        grants.push(spec);
    }
    Ok(Some(grants))
}

struct PersistedObjectClock(RedbFederationStore);

impl xolotl_federation::FederationObjectClock for PersistedObjectClock {
    fn now_ms(&self) -> std::result::Result<u64, FederationError> {
        self.0.sample_time_ms(|| {
            xolotl_federation::FederationObjectClock::now_ms(&xolotl_federation::SystemObjectClock)
        })
    }
}

struct StockObjectReader {
    local: FederationNodeId,
    service: FederationObjectReadService,
    objects: ObjectStore,
}

impl FederationObjectReader for StockObjectReader {
    fn authorize_delivery(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        context: Option<&xolotl_federation::ObjectDeliveryContext>,
    ) -> std::result::Result<(), FederationError> {
        self.service.authorize_delivery(
            request,
            authority,
            context.ok_or(FederationError::Unauthorized)?,
        )
    }

    fn read_object(
        &self,
        request: ObjectReadRequest,
        authority: ObjectReadAuthority,
    ) -> xolotl_federation_grpc::ObjectReadFuture<'_> {
        Box::pin(async move {
            let delivery = self
                .service
                .read_for_delivery(&self.objects, request, authority)
                .await?;
            Ok((delivery.page, Some(delivery.context)))
        })
    }

    fn bind_reader_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> std::result::Result<Arc<dyn FederationObjectReader>, FederationError> {
        Ok(Arc::new(Self {
            local: self.local,
            objects: self.objects.clone(),
            service: self.service.with_decision(decision)?,
        }))
    }

    fn local_node(&self) -> FederationNodeId {
        self.local
    }
}

fn object_service(
    store: &RedbFederationStore,
    grpc: xolotl_federation_grpc::config::FederationGrpcConfig,
) -> Result<FederationObjectReadService> {
    let max_chunk = grpc
        .max_batch_bytes
        .min(grpc.max_frame_bytes.saturating_sub(RECORD_FRAME_OVERHEAD))
        .min(xolotl_federation::MAX_OBJECT_CHUNK_BYTES);
    // A declaration of an exact object grant is the trusted host's disclosure
    // decision for that content identity, including any recorded provenance.
    let disclosure = Arc::new(
        |_subject: &xolotl_federation::FederationSubject,
         _metadata: &xolotl_state::object::ObjectMetadata| true,
    );
    Ok(FederationObjectReadService::new(
        Arc::new(store.clone()),
        Arc::new(PersistedObjectClock(store.clone())),
        disclosure,
        max_chunk,
    )?)
}

async fn reconcile_object_grants(
    store: &RedbFederationStore,
    service: &FederationObjectReadService,
    objects: &ObjectStore,
    desired: &[ObjectGrantSpec],
) -> Result<()> {
    let existing = store.list_object_grants()?;
    for spec in desired {
        let same: Vec<_> = existing.iter().filter(|view| view.spec == *spec).collect();
        ensure!(
            same.iter().all(|view| view.enabled),
            "a revoked object grant cannot be reissued from an old manifest"
        );
        ensure!(same.len() <= 1, "duplicate persisted object grants");
        if same.is_empty() {
            let issued = service.issue(objects, spec.clone()).await?;
            tracing::info!(
                grant_id = issued.id.get(),
                revision = issued.revision,
                "issued exact federation object grant"
            );
        }
    }
    for view in existing {
        if view.enabled && !desired.contains(&view.spec) {
            store.revoke_object_grant(view.id, view.revision)?;
        }
    }
    Ok(())
}

fn reconcile_public_streams(store: &RedbFederationStore, plan: &[PublicStreamPlan]) -> Result<()> {
    let existing = store.list_public_stream_policies()?;
    let mut changes = Vec::new();
    for desired in plan {
        let current = existing
            .iter()
            .find(|(policy, _)| policy.stream == desired.policy.stream);
        match current {
            Some((policy, revision)) if *policy == desired.policy => {}
            Some((policy, revision)) => {
                ensure!(
                    desired.expected_revision == Some(*revision),
                    "changed public stream policy requires its current revision"
                );
                ensure!(
                    policy.enabled || !desired.policy.enabled,
                    "disabled public stream cannot be re-enabled"
                );
                changes.push((Some(*revision), desired.policy));
            }
            None if !desired.policy.enabled => {}
            None => {
                ensure!(
                    desired.expected_revision.is_none(),
                    "new public stream policy cannot specify an old revision"
                );
                changes.push((None, desired.policy));
            }
        }
    }
    let configured: HashSet<_> = plan.iter().map(|item| item.policy.stream).collect();
    for (policy, revision) in existing {
        if policy.enabled && !configured.contains(&policy.stream) {
            changes.push((
                Some(revision),
                PublicStreamPolicy {
                    enabled: false,
                    ..policy
                },
            ));
        }
    }
    for (revision, policy) in changes {
        store.set_public_stream_policy(revision, policy)?;
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    ensure!(
        value.len() == 2 * N,
        "federation {label} must be {N} bytes of hex"
    );
    let mut decoded = [0; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        let chunk = &value.as_bytes()[2 * index..2 * index + 2];
        let high = hex_nibble(chunk[0])
            .ok_or_else(|| anyhow::anyhow!("invalid federation {label} hex"))?;
        let low = hex_nibble(chunk[1])
            .ok_or_else(|| anyhow::anyhow!("invalid federation {label} hex"))?;
        *byte = high << 4 | low;
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Compare the complete desired bootstrap policy before making any change.
/// A changed row needs the operator's exact previous revision, so an old
/// config snapshot cannot revive a later revocation on restart.
fn reconcile_policy(store: &RedbFederationStore, plan: &PublisherPolicyPlan) -> Result<()> {
    let configured: HashSet<_> = plan.peers.iter().map(|peer| peer.node).collect();
    for peer in &plan.peers {
        ensure!(
            store
                .peer(peer.node)?
                .is_none_or(|entry| entry.owner == AuthorityOwner::Manifest),
            "federation peer is application-owned"
        );
        let current = store.peer_authority(peer.node)?;
        if current.is_none_or(|(_, enabled)| enabled != peer.enabled) {
            ensure!(
                current.map(|(revision, _)| revision) == peer.expected_revision,
                "federation peer policy revision conflict"
            );
        }
        let admission = store.peer_admission(peer.node)?;
        ensure!(
            store
                .online_admission(peer.node)?
                .is_none_or(|entry| entry.owner == AuthorityOwner::Manifest),
            "federation peer admission is application-owned"
        );
        if admission
            .as_ref()
            .is_none_or(|(_, current)| current != &peer.admission)
        {
            ensure!(
                admission.map(|(revision, _)| revision) == peer.admission_expected_revision,
                "federation online admission revision conflict"
            );
        }
        for export in &peer.exports {
            ensure!(
                store
                    .export(peer.node, &export.name)?
                    .is_none_or(|entry| entry.owner == AuthorityOwner::Manifest),
                "federation export is application-owned"
            );
            let current = store.export_authority(peer.node, &export.name)?;
            if current.is_none_or(|(_, access)| access != export.access) {
                ensure!(
                    current.map(|(revision, _)| revision) == export.expected_revision,
                    "federation export policy revision conflict"
                );
            }
        }
    }
    // Do the revocations first, create new peers disabled, then install their
    // exact online and export rules before enabling connections.
    for (node, revision, enabled) in store.list_manifest_peer_authorities()? {
        if enabled && !configured.contains(&node) {
            store.set_manifest_peer_authority(node, Some(revision), false)?;
        }
    }
    for peer in &plan.peers {
        let configured: HashSet<_> = peer.exports.iter().map(|export| &export.name).collect();
        for (name, revision, access) in store.list_manifest_export_authorities(peer.node)? {
            if !configured.contains(&name) && (access.serve || access.receive) {
                store.set_manifest_export_authority(
                    peer.node,
                    name,
                    Some(revision),
                    ExportAccess {
                        serve: false,
                        receive: false,
                    },
                )?;
            }
        }
    }
    for peer in &plan.peers {
        match store.peer_authority(peer.node)? {
            None => {
                store.set_manifest_peer_authority(peer.node, None, false)?;
            }
            Some((revision, true)) if !peer.enabled => {
                store.set_manifest_peer_authority(peer.node, Some(revision), false)?;
            }
            _ => {}
        }
    }
    for peer in &plan.peers {
        let current = store.peer_admission(peer.node)?;
        if current
            .as_ref()
            .is_none_or(|(_, admission)| admission != &peer.admission)
        {
            store.set_manifest_peer_admission(
                peer.node,
                current.map(|(revision, _)| revision),
                peer.admission.clone(),
            )?;
        }
        for export in &peer.exports {
            let current = store.export_authority(peer.node, &export.name)?;
            if current.is_none_or(|(_, access)| access != export.access) {
                store.set_manifest_export_authority(
                    peer.node,
                    export.name.clone(),
                    current.map(|(revision, _)| revision),
                    export.access,
                )?;
            }
        }
    }
    for peer in &plan.peers {
        if peer.enabled {
            let (revision, enabled) = store
                .peer_authority(peer.node)?
                .context("federation peer row disappeared during bootstrap")?;
            if !enabled {
                store.set_manifest_peer_authority(peer.node, Some(revision), true)?;
            }
        }
    }
    for stream in &plan.streams {
        store.declare_stream(stream.clone())?;
    }
    Ok(())
}

#[cfg(test)]
async fn scan_state_history(
    workers: &storage_workers::StorageWorkers,
    service: &FederationService,
    projection: &RedbFederationStateProjection,
    publication: &StateHistoryPublication,
    through: Option<i64>,
) -> Result<usize> {
    RedbFederationStateProjection::validate_publication_prefix(&publication.prefix)?;
    let source = projection.clone();
    let declaration = publication.clone();
    let (expected, high) = workers
        .run(move || -> Result<_> {
            let committed = source.high_watermark()?;
            let high = through.unwrap_or(committed);
            ensure!(
                (0..=committed).contains(&high),
                "federation State projection cutoff exceeds committed history"
            );
            let expected = source.cursor(declaration.stream, &declaration.prefix)?;
            ensure!(
                expected.is_none_or(|cursor| cursor <= high),
                "federation State projection cursor exceeds history high watermark"
            );
            Ok((expected, high))
        })
        .await
        .context("load federation State publication window")?;
    if expected == Some(high) {
        return Ok(0);
    }
    let mut scan = StatePublicationScan::new(1);
    scan.high = Some(high);
    scan.pending[0].1 = StatePublicationProgress::Reading {
        expected,
        high,
        after: None,
        published: 0,
    };
    while !scan
        .tick(
            workers,
            service,
            projection,
            std::slice::from_ref(publication),
        )
        .await?
    {
        tokio::task::yield_now().await;
    }
    Ok(scan.published)
}

struct PublishedStateHistoryPage {
    published: usize,
    next: Option<Vec<u8>>,
    complete: bool,
}

fn publish_state_history_page(
    service: &FederationService,
    projection: &RedbFederationStateProjection,
    publication: &StateHistoryPublication,
    high: i64,
) -> Result<PublishedStateHistoryPage> {
    let Some(page) = projection.publication_page(publication.stream, &publication.prefix, high)?
    else {
        return Ok(PublishedStateHistoryPage {
            published: 0,
            next: None,
            complete: true,
        });
    };
    let mut requests = Vec::with_capacity(page.entries().len());
    for entry in page.entries() {
        ensure!(
            publication.prefix.is_prefix_of(entry.event.path())
                && entry.event.taint().is_pristine(),
            "federation State publication encountered a private or mismatched event"
        );
        let payload =
            serde_json::to_vec(&entry).context("encode federation State history event")?;
        ensure!(
            payload.len() <= service.limits().max_record_bytes,
            "federation State history event exceeds record limit"
        );
        requests.push(PublishRequest {
            retry_epoch: page.retry_epoch(),
            stream: publication.stream,
            publish_id: state_history_publish_id(publication.stream, entry),
            event_type: EventType::new("xolotl.state.mutation.v1")?,
            schema_revision: SchemaRevision::from_bytes(
                *blake3::hash(b"xolotl.federation.state-history-schema.v1\0").as_bytes(),
            ),
            event_ref: None,
            payload: Arc::from(payload),
        });
    }
    let mut receipts = Vec::with_capacity(requests.len());
    for request in requests {
        let record = match service.append_published(request.clone()) {
            Ok(record) => record,
            Err(FederationError::Capacity) if !receipts.is_empty() => break,
            Err(error) => return Err(error.into()),
        };
        receipts.push(request.receipt(&record)?);
    }
    let published = receipts.len();
    let next = projection.commit_publication_prefix(&page, &receipts)?;
    let complete = next.is_none() && page.high() == high;
    Ok(PublishedStateHistoryPage {
        published,
        next,
        complete,
    })
}

fn state_history_publish_id(stream: StreamRef, entry: &StateHistoryEntry) -> RequestId {
    RedbFederationStateProjection::publish_id(stream, entry)
}

async fn scan_all_publications(
    workers: &storage_workers::StorageWorkers,
    service: &FederationService,
    projection: &RedbFederationStateProjection,
    publications: &[StateHistoryPublication],
) -> Result<()> {
    let mut scan = StatePublicationScan::new(publications.len());
    while !scan
        .tick(workers, service, projection, publications)
        .await?
    {
        tokio::task::yield_now().await;
    }
    Ok(())
}

struct StatePublicationWindow {
    publication: StateHistoryPublication,
    expected: Option<i64>,
    high: i64,
}

async fn settle_state_publication_windows(
    workers: &storage_workers::StorageWorkers,
    service: &FederationService,
    projection: &RedbFederationStateProjection,
    windows: &[StatePublicationWindow],
) -> Result<()> {
    let publications = windows
        .iter()
        .map(|window| window.publication.clone())
        .collect::<Vec<_>>();
    let mut scan = StatePublicationScan {
        high: windows.iter().map(|window| window.high).max(),
        pending: windows
            .iter()
            .enumerate()
            .map(|(index, window)| {
                (
                    index,
                    StatePublicationProgress::Reading {
                        expected: window.expected,
                        high: window.high,
                        after: None,
                        published: 0,
                    },
                )
            })
            .collect(),
        published: 0,
        capacity_stalls: 0,
    };
    while !scan
        .tick(workers, service, projection, &publications)
        .await?
    {
        tokio::task::yield_now().await;
    }
    Ok(())
}

const STATE_PUBLICATION_STEPS: usize = 8;

enum StatePublicationProgress {
    Unloaded,
    Reading {
        expected: Option<i64>,
        high: i64,
        after: Option<Arc<Vec<u8>>>,
        published: usize,
    },
}

struct StatePublicationScan {
    high: Option<i64>,
    pending: VecDeque<(usize, StatePublicationProgress)>,
    published: usize,
    capacity_stalls: usize,
}

impl StatePublicationScan {
    fn new(count: usize) -> Self {
        Self {
            high: None,
            pending: (0..count)
                .map(|index| (index, StatePublicationProgress::Unloaded))
                .collect(),
            published: 0,
            capacity_stalls: 0,
        }
    }

    async fn tick(
        &mut self,
        workers: &storage_workers::StorageWorkers,
        service: &FederationService,
        projection: &RedbFederationStateProjection,
        publications: &[StateHistoryPublication],
    ) -> Result<bool> {
        let mut steps = 0;
        if self.pending.is_empty() {
            return Ok(true);
        }
        if self.high.is_none() {
            let source = projection.clone();
            self.high = Some(
                workers
                    .run(move || source.high_watermark())
                    .await
                    .context("load federation State publication high watermark")?,
            );
            steps += 1;
        }
        let high = self
            .high
            .context("missing State publication high watermark")?;
        while steps < STATE_PUBLICATION_STEPS && !self.pending.is_empty() {
            self.pending.rotate_left(1);
            let (index, previous) = self
                .pending
                .back()
                .context("missing State publication work")?;
            steps += 1;
            let publication = &publications[*index];
            RedbFederationStateProjection::validate_publication_prefix(&publication.prefix)?;
            let source = projection.clone();
            let declaration = publication.clone();
            let progress = match previous {
                StatePublicationProgress::Unloaded => {
                    let expected = workers
                        .run(move || source.cursor(declaration.stream, &declaration.prefix))
                        .await
                        .context("load federation State publication window")?;
                    ensure!(
                        expected.is_none_or(|cursor| cursor <= high),
                        "federation State projection cursor exceeds history high watermark"
                    );
                    if expected == Some(high) {
                        self.pending.pop_back();
                        continue;
                    }
                    StatePublicationProgress::Reading {
                        expected,
                        high,
                        after: None,
                        published: 0,
                    }
                }
                StatePublicationProgress::Reading {
                    expected,
                    high,
                    after,
                    published,
                } => {
                    let expected = *expected;
                    let high = *high;
                    let publisher = service.clone();
                    let page = workers
                        .run(move || {
                            publish_state_history_page(&publisher, &source, &declaration, high)
                        })
                        .await
                        .context("publish federation State history page");
                    let page = match page {
                        Ok(page) => page,
                        Err(error)
                            if matches!(
                                error.downcast_ref::<FederationError>(),
                                Some(FederationError::Capacity)
                            ) =>
                        {
                            self.capacity_stalls += 1;
                            if self.capacity_stalls >= self.pending.len() {
                                return Err(error);
                            }
                            continue;
                        }
                        Err(error) => {
                            self.capacity_stalls = 0;
                            return Err(error);
                        }
                    };
                    self.capacity_stalls = 0;
                    let published = published.saturating_add(page.published);
                    if page.complete {
                        if published != 0 {
                            tracing::info!(stream = ?publication.stream.id, events = published, cursor = high,
                                "federation State history projected");
                        }
                        self.published = self.published.saturating_add(published);
                        self.pending.pop_back();
                        continue;
                    }
                    match page.next {
                        Some(next) => {
                            ensure!(
                                after.as_ref().map(|key| key.as_slice()) != Some(next.as_slice()),
                                "federation State history cursor did not advance"
                            );
                            StatePublicationProgress::Reading {
                                expected,
                                high,
                                after: Some(Arc::new(next)),
                                published,
                            }
                        }
                        None => StatePublicationProgress::Reading {
                            expected,
                            high,
                            after: None,
                            published,
                        },
                    }
                }
            };
            self.pending
                .back_mut()
                .context("missing State publication work")?
                .1 = progress;
        }
        Ok(self.pending.is_empty())
    }
}

fn complete_publication_tick(role: &'static str, outcome: Result<()>) -> Result<()> {
    match outcome {
        Err(error)
            if error.downcast_ref::<xolotl_kernel::host::BlockingSpawnError>()
                == Some(&xolotl_kernel::host::BlockingSpawnError::AtCapacity) =>
        {
            tracing::warn!(role, error = %format!("{error:#}"), "publication deferred until next tick");
            Ok(())
        }
        outcome => outcome,
    }
}

pub(crate) struct PublisherListener {
    #[cfg(test)]
    pub(crate) address: Option<SocketAddr>,
    pub(crate) task: tokio::task::JoinHandle<Result<()>>,
    pub(crate) runtime: FederationGrpcRuntime,
    pub(crate) calls: Option<Arc<FederationKernelCallBridge>>,
}

#[cfg(test)]
pub(crate) async fn start(
    prepared: PreparedPublisher,
    store: RedbFederationStore,
    projection: Option<RedbFederationStateProjection>,
    boot: Arc<Bootstrap>,
) -> Result<PublisherListener> {
    start_with_objects(prepared, store, projection, boot, ObjectStore::new()).await
}

pub(crate) async fn start_with_objects(
    prepared: PreparedPublisher,
    store: RedbFederationStore,
    projection: Option<RedbFederationStateProjection>,
    boot: Arc<Bootstrap>,
    objects: ObjectStore,
) -> Result<PublisherListener> {
    let receive_blocking = boot.kernel().host_runtime().blocking_spawner();
    let runtime = prepared.transport_runtime(boot.kernel().host_runtime())?;
    let publication_workers = storage_workers::StorageWorkers::new(
        prepared.grpc.max_blocking_verifications,
        Arc::clone(&receive_blocking),
    )?;
    let catalog = Arc::new(StockFederationCatalog::load(&prepared.methods, &boot)?);
    let known_peers: Vec<_> = prepared.policy.peers.iter().map(|peer| peer.node).collect();
    let authorities = parse_authorities(
        &prepared.call_authorities,
        &catalog,
        prepared.local.node_id(),
        &known_peers,
        &prepared.policy.issuer_rules,
    )?;
    let policy = Arc::new(PersistedPeerPolicy {
        store: store.clone(),
        local: prepared.local.node_id(),
        issuer_rules: prepared.policy.issuer_rules.clone(),
    });
    let now_ms = policy
        .current_time_ms()
        .context("check federation trusted time")?;
    ensure!(
        (prepared.online_not_before_ms..prepared.online_expires_ms).contains(&now_ms),
        "local federation online key is outside its validity period"
    );
    let limits = FederationLimits {
        max_record_bytes: STOCK_RECORD_BYTES,
        ..FederationLimits::default()
    };
    let service = FederationService::new(Arc::new(store.clone()), limits)?;
    if !prepared.policy.publication_retirements.is_empty() {
        publication_retirement::retire(
            &publication_workers,
            &service,
            projection
                .as_ref()
                .context("federation State projection was not initialized")?,
            &prepared.policy.publication_retirements,
            &prepared.policy.publications,
        )
        .await?;
    }
    reconcile_policy(&store, &prepared.policy)?;
    let replica_pending =
        replica_retention::reconcile_members(&store, &prepared.replica_retention.members, now_ms)?;
    if replica_pending.pending != 0 {
        tracing::warn!(
            pending = replica_pending.pending,
            "federation replica commitments await exact publisher subscriptions"
        );
    }
    if let Some(grants) = &prepared.policy.subject_grants {
        subject_grants::reconcile(&store, grants)?;
    }
    reconcile_authorities(&store, &authorities)?;
    // The first public grant must be committed while the stream is empty,
    // before replaying State history into the publication store.
    reconcile_public_streams(&store, &prepared.policy.public_streams)?;
    let call_store = Arc::new(store.clone());
    let dial_call_store = Arc::clone(&call_store);
    let bridge = if catalog.len() == 0 {
        None
    } else {
        let directory: Arc<dyn xolotl_federation::FederationCallStore> = call_store.clone();
        Some(FederationKernelCallBridge::new(boot, directory, catalog)?)
    };
    let call_invoker: Option<Arc<dyn FederationCallInvoker>> = bridge
        .as_ref()
        .map(|bridge| Arc::new(StockCallInvoker(Arc::clone(bridge))) as Arc<_>);
    let dial_call_invoker = call_invoker.clone();
    // Every stock peer accepts this same payload floor, so a record published
    // before a peer connects remains deliverable even when its configured
    // batch limit differs from ours.
    let grpc = prepared.grpc;
    let object_service = object_service(&store, grpc)?;
    if let Some(grants) = &prepared.object_grants {
        reconcile_object_grants(&store, &object_service, &objects, grants).await?;
    }
    let receive_objects = objects.clone();
    let object_reader: Arc<dyn FederationObjectReader> = Arc::new(StockObjectReader {
        local: prepared.local.node_id(),
        service: object_service,
        objects,
    });
    let dial_object_reader = Arc::clone(&object_reader);
    let receive_store = store.clone();
    let retention_store = store.clone();
    let release_store = store.clone();
    let public = FederationPublicService::new(
        call_store.clone(),
        PublicReadLimits {
            max_records: grpc
                .max_batch_records
                .min(xolotl_federation::MAX_PUBLIC_READ_RECORDS),
            max_bytes: grpc
                .max_batch_bytes
                .min(xolotl_federation::MAX_PUBLIC_READ_BYTES),
        },
    )?;
    if !prepared.policy.publications.is_empty() {
        let projection = projection
            .as_ref()
            .context("federation State projection was not initialized")?;
        scan_all_publications(
            &publication_workers,
            &service,
            projection,
            &prepared.policy.publications,
        )
        .await?;
    }
    // An invitation using FromGrant captures the stream's committed head, so
    // stock State publication must finish its first scan before creation.
    invitations::reconcile(
        call_store.as_ref(),
        &prepared.invitation_manifest,
        policy.current_time_ms()?,
    )?;
    let snapshot_offers = prepared.snapshot_offers;
    let snapshot_reader_releases = prepared.snapshot_reader_releases;
    let snapshot_publisher = if snapshot_offers.is_empty() {
        None
    } else {
        Some(
            snapshot_publisher::prepare(
                &publication_workers,
                &prepared.snapshot_storage_path,
                Arc::clone(&dial_call_store),
                &snapshot_offers,
            )
            .await?,
        )
    };
    let publications = prepared.policy.publications;
    let object_receives = prepared.object_receives;
    let dials = prepared.policy.dials;
    let inbound_subscriptions = prepared.policy.inbound_subscriptions;
    let replica_retention = prepared.replica_retention;
    let snapshot_archive = snapshot_receiver::StockSnapshotArchive::open(
        &prepared.snapshot_storage_path,
        storage_workers::StorageWorkers::new(
            grpc.max_blocking_verifications,
            Arc::clone(&receive_blocking),
        )?,
    )?;
    let release_archive = snapshot_archive.clone();
    let node = prepared.local.node_id();
    let local = Arc::clone(&prepared.local);
    let dial_policy: Arc<dyn FederationPeerPolicy> = policy.clone();
    let receive_policy: Arc<dyn FederationPeerPolicy> = policy.clone();
    let mut publisher = FederationGrpcPublisherServer::new(
        service.clone(),
        prepared.local,
        policy,
        runtime.clone(),
    )?
    .with_call_store(call_store)?
    .with_public_service(public)?
    .with_invitation_store(dial_call_store.clone())?
    .with_guest_store(dial_call_store.clone())
    .with_object_reader(object_reader)?;
    if let Some(invoker) = call_invoker {
        publisher = publisher.with_call_invoker(invoker);
    }
    if let Some(source) = &snapshot_publisher {
        publisher = publisher.with_snapshot_publisher(dial_call_store.clone(), source.clone())?;
    }
    let publisher_observer = publisher.clone();
    let listener = match prepared.address {
        Some(address) => Some(
            TcpListener::bind(address)
                .await
                .with_context(|| format!("bind federation publisher '{address}'"))?,
        ),
        None => None,
    };
    let address = listener.as_ref().map(TcpListener::local_addr).transpose()?;
    let lifecycle = runtime.clone();
    let listener_runtime = runtime.clone();
    let task = tokio::spawn(async move {
        let serving = async move {
            let Some(listener) = listener else {
                return std::future::pending::<Result<()>>().await;
            };
            let incoming = stream::unfold(listener, |listener| async move {
                let accepted = listener.accept().await.map(|(stream, _)| stream);
                Some((accepted, listener))
            });
            let incoming = federation_tls_incoming(incoming, prepared.tls, listener_runtime)?;
            tonic::transport::Server::builder()
                .add_service(publisher.tonic_service())
                .serve_with_incoming(incoming)
                .await?;
            Ok::<(), anyhow::Error>(())
        };
        let projecting = async {
            if publications.is_empty() {
                return std::future::pending::<Result<()>>().await;
            }
            let Some(projection) = projection else {
                return std::future::pending::<Result<()>>().await;
            };
            let mut scan = StatePublicationScan::new(publications.len());
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let outcome = scan
                    .tick(&publication_workers, &service, &projection, &publications)
                    .await;
                if matches!(outcome, Ok(true)) {
                    scan = StatePublicationScan::new(publications.len());
                }
                complete_publication_tick("State history", outcome.map(|_| ()))?;
            }
        };
        let dialing = async {
            if dials.is_empty() && inbound_subscriptions.is_empty() {
                return std::future::pending::<()>().await;
            }
            let outbound = futures_util::future::join_all(dials.into_iter().map(|dial| {
                supervise_peer(
                    dial,
                    Arc::clone(&local),
                    Arc::clone(&dial_policy),
                    runtime.clone(),
                    PeerSessionServices {
                        service: service.clone(),
                        call_store: Arc::clone(&dial_call_store),
                        call_invoker: dial_call_invoker.clone(),
                        object_reader: Arc::clone(&dial_object_reader),
                        snapshot_archive: snapshot_archive.clone(),
                        snapshot_publisher: snapshot_publisher.clone(),
                    },
                )
            }));
            let inbound =
                futures_util::future::join_all(inbound_subscriptions.into_iter().map(|plan| {
                    supervise_inbound_peer(
                        plan,
                        publisher_observer.clone(),
                        grpc,
                        service.clone(),
                        Arc::clone(&dial_call_store),
                        snapshot_archive.clone(),
                    )
                }));
            tokio::join!(outbound, inbound);
        };
        let offering = async {
            if snapshot_offers.is_empty() {
                return std::future::pending::<Result<()>>().await;
            }
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                let store = Arc::clone(&dial_call_store);
                let plans = snapshot_offers.clone();
                let outcome = publication_workers
                    .run(move || snapshot_publisher::reconcile(&store, &plans))
                    .await
                    .context("reconcile stock snapshot offers");
                complete_publication_tick("snapshot offers", outcome.map(|_| ()))?;
            }
        };
        let receiving = object_receives::supervise_all(
            object_receives,
            receive_store,
            receive_objects,
            Arc::clone(&local),
            receive_policy,
            runtime.clone(),
        );
        let retaining = replica_retention::supervise(
            retention_store,
            replica_retention,
            runtime.blocking_spawner(),
        );
        let releasing = async {
            if snapshot_reader_releases.is_empty() {
                return std::future::pending::<()>().await;
            }
            let mut next = 0;
            loop {
                for _ in 0..snapshot_reader_releases.len().min(8) {
                    let release = snapshot_reader_releases[next].release;
                    next = (next + 1) % snapshot_reader_releases.len();
                    match release_archive
                        .retire_released(release_store.clone(), release)
                        .await
                    {
                        Ok(progress)
                            if progress.inbox.removed != 0 || progress.removed_files != 0 =>
                        {
                            tracing::debug!(
                                removed_records = progress.inbox.removed,
                                removed_files = progress.removed_files,
                                "stock snapshot reader release cleaned old generations"
                            );
                        }
                        Ok(_) => {}
                        Err(error) => {
                            tracing::warn!(%error, "stock snapshot reader release rejected");
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        };
        tokio::select! {
            result = serving => result.context("federation publisher listener exited"),
            result = projecting => result.context("federation State publication stopped"),
            () = dialing => anyhow::bail!("federation dial supervisors stopped"),
            result = offering => result.context("stock snapshot offer reconciliation stopped"),
            () = receiving => anyhow::bail!("federation object receivers stopped"),
            () = retaining => anyhow::bail!("federation replica retention supervisor stopped"),
            () = releasing => anyhow::bail!("federation snapshot release supervisor stopped"),
        }
    });
    if let Some(address) = address {
        tracing::info!(addr = %address, node = ?node, "federation publisher listening");
    } else {
        tracing::info!(node = ?node, "federation outbound-only node started");
    }
    Ok(PublisherListener {
        #[cfg(test)]
        address,
        task,
        runtime: lifecycle,
        calls: bridge,
    })
}

struct StockCallInvoker(Arc<FederationKernelCallBridge>);

impl FederationCallInvoker for StockCallInvoker {
    fn bind_invoker_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> std::result::Result<Arc<dyn FederationCallInvoker>, FederationError> {
        Ok(Arc::new(StockAdmittedCallInvoker {
            bridge: Arc::clone(&self.0),
            decision,
        }))
    }

    fn validate_prepare(&self, request: &PrepareCallRequest) -> Result<(), FederationError> {
        self.0.validate_prepare(request)
    }

    fn invoke_call(
        &self,
        request: InvokeCallRequest,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<CallInvoked, FederationError>> + Send + '_>> {
        Box::pin(self.0.invoke(request, now_ms))
    }

    fn cancel_call(
        &self,
        request: CancelCallRequest,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<CallCancelled, FederationError>> + Send + '_>> {
        Box::pin(self.0.cancel(request, now_ms))
    }
}

struct StockAdmittedCallInvoker {
    bridge: Arc<FederationKernelCallBridge>,
    decision: xolotl_federation::FederationDecision,
}

impl FederationCallInvoker for StockAdmittedCallInvoker {
    fn validate_prepare(
        &self,
        request: &PrepareCallRequest,
    ) -> std::result::Result<(), FederationError> {
        self.decision.check_peer(request.authenticated_origin)?;
        self.bridge.validate_prepare(request)
    }

    fn invoke_call(
        &self,
        request: InvokeCallRequest,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<CallInvoked, FederationError>> + Send + '_>>
    {
        Box::pin(
            self.bridge
                .invoke_with_decision(request, now_ms, self.decision.clone()),
        )
    }

    fn cancel_call(
        &self,
        request: CancelCallRequest,
        now_ms: u64,
    ) -> Pin<
        Box<dyn Future<Output = std::result::Result<CallCancelled, FederationError>> + Send + '_>,
    > {
        Box::pin(
            self.bridge
                .cancel_with_decision(request, now_ms, self.decision.clone()),
        )
    }
}

#[derive(Clone)]
struct PeerSessionServices {
    service: FederationService,
    call_store: Arc<RedbFederationStore>,
    call_invoker: Option<Arc<dyn FederationCallInvoker>>,
    object_reader: Arc<dyn FederationObjectReader>,
    snapshot_archive: snapshot_receiver::StockSnapshotArchive,
    snapshot_publisher: Option<Arc<snapshot_publisher::StockSnapshotPublisher>>,
}

async fn supervise_peer(
    dial: PeerDialPlan,
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    runtime: FederationGrpcRuntime,
    services: PeerSessionServices,
) {
    let peer = dial.route.expected_peer;
    let mut backoff = std::time::Duration::from_millis(250);
    loop {
        let started = std::time::Instant::now();
        match run_peer_session(
            &dial,
            Arc::clone(&local),
            Arc::clone(&policy),
            runtime.clone(),
            &services,
        )
        .await
        {
            Ok(()) => tracing::warn!(?peer, "federation outbound Session ended"),
            Err(error) => {
                tracing::warn!(?peer, error = %format!("{error:#}"), "federation outbound Session failed")
            }
        }
        if started.elapsed() >= std::time::Duration::from_secs(5) {
            backoff = std::time::Duration::from_millis(250);
        }
        tokio::time::sleep(backoff).await;
        backoff = backoff
            .saturating_mul(2)
            .min(std::time::Duration::from_secs(30));
    }
}

async fn supervise_inbound_peer(
    plan: InboundPeerPlan,
    publisher: FederationGrpcPublisherServer,
    config: xolotl_federation_grpc::config::FederationGrpcConfig,
    service: FederationService,
    snapshot_store: Arc<RedbFederationStore>,
    snapshot_archive: snapshot_receiver::StockSnapshotArchive,
) {
    loop {
        if let Some(client) = publisher.connected_peer(
            plan.peer,
            xolotl_federation_grpc::ServedCapability::Publication,
        ) && let Err(error) = run_subscriptions(
            client,
            &plan.subscriptions,
            config,
            &service,
            &snapshot_store,
            &snapshot_archive,
        )
        .await
        {
            tracing::warn!(peer = ?plan.peer, error = %format!("{error:#}"), "federation inbound Session subscription failed");
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn run_peer_session(
    dial: &PeerDialPlan,
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    runtime: FederationGrpcRuntime,
    services: &PeerSessionServices,
) -> Result<()> {
    let config = runtime.config();
    let reverse = FederationSubscriberServices {
        service: services.service.clone(),
        call_store: Some(services.call_store.clone()),
        call_invoker: services.call_invoker.clone(),
        object_reader: Some(Arc::clone(&services.object_reader)),
    };
    let client = if let Some(source) = &services.snapshot_publisher {
        FederationGrpcSubscriberClient::connect_with_snapshot_services(
            dial.route.clone(),
            local,
            policy,
            runtime,
            reverse,
            services.call_store.clone(),
            source.clone(),
        )
        .await
    } else {
        FederationGrpcSubscriberClient::connect_with_services(
            dial.route.clone(),
            local,
            policy,
            runtime,
            reverse,
        )
        .await
    }
    .context("connect federation peer")?;
    run_subscriptions(
        client,
        &dial.subscriptions,
        config,
        &services.service,
        &services.call_store,
        &services.snapshot_archive,
    )
    .await
}

struct PersistedPeerPolicy {
    store: RedbFederationStore,
    local: FederationNodeId,
    issuer_rules: Vec<SubjectIssuerRule>,
}

impl FederationPeerPolicy for PersistedPeerPolicy {
    fn decision_clock(
        &self,
    ) -> std::result::Result<Arc<dyn xolotl_federation::FederationObjectClock>, Status> {
        Ok(Arc::new(xolotl_federation::SystemObjectClock))
    }

    fn current_time_ms(&self) -> Result<u64, Status> {
        self.store
            .sample_time_ms(|| {
                xolotl_federation::FederationObjectClock::now_ms(
                    &xolotl_federation::SystemObjectClock,
                )
            })
            .map_err(|_error| Status::failed_precondition("federation trusted clock rejected"))
    }

    fn check_current_peer(
        &self,
        proof: VerifiedFederationPeerProof,
        now_ms: u64,
    ) -> Result<(), Status> {
        self.store
            .with_decision(xolotl_federation::FederationDecision::new(
                proof,
                xolotl_federation::FederationAdmission::Private,
                self.decision_clock()?,
            ))
            .and_then(|store| store.check_peer_admission(proof, now_ms))
            .map_err(|_error| Status::permission_denied("federation peer admission rejected"))
    }

    fn check_public_peer(
        &self,
        proof: VerifiedFederationPeerProof,
        _now_ms: u64,
    ) -> Result<(), Status> {
        match self.store.peer_authority(proof.node_id()) {
            Ok(None) => Ok(()),
            _ => Err(Status::permission_denied(
                "configured or disabled peer cannot enter public-only federation session",
            )),
        }
    }

    fn accepts_subject_issuer(
        &self,
        issuer: SubjectIssuerId,
        namespace: &str,
        purpose: SubjectPurpose,
        presenter: FederationNodeId,
        audience: FederationNodeId,
    ) -> bool {
        audience == self.local
            && self.issuer_rules.iter().any(|rule| {
                rule.issuer == issuer
                    && rule.namespace == namespace
                    && rule.purpose == purpose
                    && rule.presenter == presenter
            })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject as _};
    #[cfg(unix)]
    use sha2::{Digest as _, Sha384};
    use std::path::Path;
    use xolotl_federation::{
        CallAuthorityKey, CallAuthorityRule, CallMethod, CallPath, CallStatus, CallTarget, Digest,
        FederationCallStore as _, FederationOutboundCallStore, FederationRootKey,
        FederationSubject, HistoryStart, InspectSubscriptionRequest, OpenRequest,
        OutboundCallIntent, PrepareCallRequest, ReadRequest, RootSignaturePurpose, SubscriptionId,
        SubscriptionRef,
    };
    use xolotl_federation_grpc::FederationCallIdentity as _;
    use xolotl_types::{Path as StatePath, Value};

    pub(crate) const SERVER_CERT: &[u8] = include_bytes!("../tests/fixtures/ml-dsa-65-cert.pem");
    pub(crate) const SERVER_KEY: &[u8] = include_bytes!("../tests/fixtures/ml-dsa-65-key.pem");
    pub(crate) const CA_CERT: &[u8] = include_bytes!("../tests/fixtures/ml-dsa-65-ca-cert.pem");

    #[cfg(unix)]
    pub(crate) fn test_boot(state: Backend) -> Arc<Bootstrap> {
        Arc::new(Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::new(state).build(),
        ))
    }

    #[cfg(unix)]
    pub(crate) fn test_boot_with_blocking(
        state: Backend,
        blocking: Arc<xolotl_kernel::host::TokioBlockingSpawner>,
    ) -> Arc<Bootstrap> {
        Arc::new(Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::new(state)
                .with_host_runtime(xolotl_kernel::host::HostRuntime::tokio_with_blocking(
                    blocking,
                ))
                .build(),
        ))
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepared_transport_rejects_a_second_host_blocking_owner() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let prepared = prepare(&config)?.context("federation disabled")?;
        let blocking = Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default());
        let host = xolotl_kernel::host::HostRuntime::tokio_with_blocking(blocking.clone());
        let transport = prepared.transport_runtime(&host)?;
        let selected = prepared.transport_runtime(&host.clone())?;
        ensure!(Arc::ptr_eq(
            &transport.blocking_spawner(),
            &selected.blocking_spawner()
        ));
        let other = xolotl_kernel::host::HostRuntime::tokio();
        ensure!(prepared.transport_runtime(&other).is_err());
        transport.shutdown().await;
        blocking.close();
        blocking.wait_idle().await;
        Ok(())
    }

    #[cfg(unix)]
    pub(crate) fn live_test_boot(db: &xolotl_storage_redb::RedbStore) -> Result<Arc<Bootstrap>> {
        live_test_boot_with_host(db, xolotl_kernel::host::HostRuntime::tokio())
    }

    #[cfg(unix)]
    pub(crate) fn live_test_boot_with_host(
        db: &xolotl_storage_redb::RedbStore,
        runtime: xolotl_kernel::host::HostRuntime,
    ) -> Result<Arc<Bootstrap>> {
        let boot = Arc::new(Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::new(db.state_backend().into_backend())
                .with_host_runtime(runtime)
                .with_identity_directory(Arc::new(db.identity_directory()))
                .with_fact_sink(xolotl_kernel::FactSink::new(Arc::new(db.fact_store()?)))
                .build(),
        ));
        Ok(boot)
    }

    #[cfg(unix)]
    pub(crate) fn wall_ms() -> Result<u64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?)
    }

    #[cfg(unix)]
    pub(crate) fn private_file(path: &Path, bytes: &[u8]) -> Result<String> {
        use std::os::unix::fs::PermissionsExt;

        std::fs::write(path, bytes)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(path.to_string_lossy().into_owned())
    }

    #[cfg(unix)]
    pub(crate) fn configured_publisher(directory: &Path) -> Result<XolotlConfig> {
        use crate::config::{
            FederationExportConfig, FederationPeerConfig, FederationStateHistoryPublicationConfig,
            FederationStreamConfig,
        };

        let root_key = FederationRootKey::generate()?;
        let online_key = FederationOnlineKey::generate()?;
        let root = root_key.root()?;
        let now_ms: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis()
            .try_into()?;
        let authorization = FederationOnlineKeyAuthorization::new(
            online_key.public_key(),
            1,
            now_ms.saturating_sub(1_000),
            now_ms + 60_000,
        )?;
        let signature = root_key.sign(
            RootSignaturePurpose::OnlineKeyAuthorization,
            &authorization.encode(),
        )?;
        let mut config = XolotlConfig::default();
        config.server.federation_grpc_addr = Some("127.0.0.1:0".into());
        config.storage.kind = StorageKind::Redb;
        config.storage.path = directory.join("state.redb").to_string_lossy().into_owned();
        config.storage.state_history = StorageHistoryMode::Full;
        config.federation.peers.push(FederationPeerConfig {
            node_id: "22".repeat(48),
            enabled: true,
            expected_revision: None,
            admission_expected_revision: None,
            minimum_online_generation: 1,
            allowed_authorization_digests: vec!["33".repeat(48)],
            exports: vec![FederationExportConfig {
                name: "notes".into(),
                serve: true,
                receive: false,
                expected_revision: None,
            }],
            dial: None,
            subscriptions: Vec::new(),
        });
        config.federation.streams.push(FederationStreamConfig {
            id: "44".repeat(16),
            export: "notes".into(),
        });
        config.federation.state_history_publications.push(
            FederationStateHistoryPublicationConfig {
                prefix: "state://federation/public/notes".into(),
                stream_id: "44".repeat(16),
            },
        );
        config.federation.root_descriptor_path =
            Some(private_file(&directory.join("root.bin"), &root.encode())?);
        config.federation.online_key_path = Some(private_file(
            &directory.join("online.pk8"),
            online_key.to_pkcs8()?.as_ref(),
        )?);
        config.federation.online_authorization_path = Some(private_file(
            &directory.join("authorization.bin"),
            &authorization.encode(),
        )?);
        config.federation.online_authorization_signature_path = Some(private_file(
            &directory.join("authorization.sig"),
            &signature,
        )?);
        let security = &mut config.federation.grpc.transport_security;
        security.mode = "production_tls".into();
        security.certificate_chain_path =
            Some(private_file(&directory.join("server.crt"), SERVER_CERT)?);
        security.private_key_path = Some(private_file(&directory.join("server.key"), SERVER_KEY)?);
        Ok(config)
    }

    #[cfg(unix)]
    pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[cfg(unix)]
    pub(crate) fn online_digest_hex(config: &XolotlConfig) -> Result<String> {
        let path = config
            .federation
            .online_authorization_path
            .as_deref()
            .context("online authorization path missing")?;
        Ok(hex_bytes(&Sha384::digest(std::fs::read(path)?)))
    }

    #[cfg(unix)]
    async fn wait_for_acknowledgement(
        service: &FederationService,
        subscription: SubscriptionRef,
        sequence: u64,
    ) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            loop {
                let inspected = service.inspect_subscription(InspectSubscriptionRequest {
                    authenticated_subscriber: subscription.subscriber,
                    subscription,
                });
                if inspected
                    .as_ref()
                    .ok()
                    .and_then(|inspection| inspection.acknowledged)
                    .is_some_and(|position| position.sequence() >= sequence)
                {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .context("federation acknowledgement did not arrive")?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn publisher_starts_only_with_valid_persistent_identity_and_hybrid_tls() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut config = configured_publisher(directory.path())?;
        ensure!(prepare(&XolotlConfig::default())?.is_none());
        config.storage.kind = StorageKind::Memory;
        ensure!(prepare(&config).is_err());
        config.storage.kind = StorageKind::Redb;
        config.federation.grpc.transport_security.mode = "local_trusted".into();
        ensure!(prepare(&config).is_err());
        config.federation.grpc.transport_security.mode = "production_tls".into();
        let prepared = prepare(&config)?.context("publisher was unexpectedly disabled")?;
        let database = xolotl_storage_redb::RedbStore::open_with_history(
            directory.path().join("state.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store = database.federation_store(prepared.node_id())?;
        let projection = database.federation_state_projection(prepared.node_id())?;
        let listener = start(
            prepared,
            store,
            Some(projection),
            test_boot(database.state_backend().into_backend()),
        )
        .await?;

        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_slice(CA_CERT)?)?;
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
            crate::pqc_tls_crypto_provider()?,
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let socket = tokio::net::TcpStream::connect(
            listener
                .address
                .context("federation listener was disabled")?,
        )
        .await?;
        let tls = connector
            .connect(ServerName::try_from("localhost")?, socket)
            .await?;
        let session = tls.get_ref().1;
        ensure!(session.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3));
        ensure!(session.handshake_kind() == Some(rustls::HandshakeKind::Full));
        ensure!(session.alpn_protocol() == Some(b"h2".as_slice()));
        ensure!(
            session
                .negotiated_key_exchange_group()
                .is_some_and(|group| { group.name() == rustls::NamedGroup::X25519MLKEM768 })
        );
        drop(tls);
        listener.task.abort();
        drop(listener.task.await);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn two_daemons_resume_both_directions_after_outbound_restart() -> Result<()> {
        use crate::config::{FederationPeerDialConfig, FederationPeerSubscriptionConfig};

        let directory = tempfile::tempdir()?;
        let a_dir = directory.path().join("a");
        let b_dir = directory.path().join("b");
        std::fs::create_dir(&a_dir)?;
        std::fs::create_dir(&b_dir)?;
        let mut a = configured_publisher(&a_dir)?;
        let mut b = configured_publisher(&b_dir)?;
        let a_node = prepare(&a)?.context("a disabled")?.node_id();
        let b_node = prepare(&b)?.context("b disabled")?.node_id();
        a.federation.peers[0].node_id = hex_bytes(b_node.as_bytes());
        a.federation.peers[0].allowed_authorization_digests = vec![online_digest_hex(&b)?];
        a.federation.peers[0].exports[0].receive = true;
        a.federation.peers[0]
            .subscriptions
            .push(FederationPeerSubscriptionConfig {
                stream_id: "55".repeat(16),
                generation: 0,
                snapshot_schema_revisions: Vec::new(),
            });
        b.federation.peers[0].node_id = hex_bytes(a_node.as_bytes());
        b.federation.peers[0].allowed_authorization_digests = vec![online_digest_hex(&a)?];
        b.federation.peers[0].exports[0].receive = true;
        b.federation.peers[0]
            .subscriptions
            .push(FederationPeerSubscriptionConfig {
                stream_id: "44".repeat(16),
                generation: 0,
                snapshot_schema_revisions: Vec::new(),
            });
        b.federation.streams[0].id = "55".repeat(16);
        b.federation.state_history_publications[0].prefix =
            "state://federation/public/mobile".into();
        b.federation.state_history_publications[0].stream_id = "55".repeat(16);
        // A subscribes over B's outbound Session while B advertises smaller
        // Read limits; the client must use the authenticated Hello limits.
        a.federation.grpc.max_batch_bytes = 768 * 1024;
        b.federation.grpc.max_batch_records = 8;
        b.server.federation_grpc_addr = None;

        let prepared_a = prepare(&a)?.context("a disabled")?;
        let db_a = xolotl_storage_redb::RedbStore::open_with_history(
            a_dir.join("federation.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store_a = db_a.federation_store(a_node)?;
        let projection_a = db_a.federation_state_projection(a_node)?;
        let state_a = db_a.state_backend().into_backend();
        let service_a =
            FederationService::new(Arc::new(store_a.clone()), FederationLimits::default())?;
        let runtime_a = start(
            prepared_a,
            store_a,
            Some(projection_a),
            test_boot(state_a.clone()),
        )
        .await?;
        let address = runtime_a.address.context("a did not listen")?;

        b.federation.peers[0].dial = Some(FederationPeerDialConfig {
            uri: format!("http://{address}"),
            server_name: "localhost".into(),
            trust_root_path: private_file(&b_dir.join("peer-ca.pem"), CA_CERT)?,
        });
        let prepared_b = prepare(&b)?.context("outbound-only b disabled")?;
        let db_b = xolotl_storage_redb::RedbStore::open_with_history(
            b_dir.join("federation.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store_b = db_b.federation_store(b_node)?;
        let projection_b = db_b.federation_state_projection(b_node)?;
        let state_b = db_b.state_backend().into_backend();
        let service_b =
            FederationService::new(Arc::new(store_b.clone()), FederationLimits::default())?;
        let blocking_b = Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default());
        let runtime_b = start(
            prepared_b,
            store_b.clone(),
            Some(projection_b.clone()),
            test_boot_with_blocking(state_b.clone(), blocking_b.clone()),
        )
        .await?;
        ensure!(runtime_b.address.is_none());

        let a_path = StatePath::parse("state://federation/public/notes/entry")?;
        let b_path = StatePath::parse("state://federation/public/mobile/entry")?;
        state_a.write_set(&a_path, Value::integer(1)).await?;
        state_b.write_set(&b_path, Value::integer(1)).await?;
        let a_stream = StreamRef {
            publisher: a_node,
            id: StreamId::from_bytes([0x44; 16]),
        };
        let b_stream = StreamRef {
            publisher: b_node,
            id: StreamId::from_bytes([0x55; 16]),
        };
        let b_receives_a = remote_subscription(b_node, a_stream, 0).subscription;
        let a_receives_b = remote_subscription(a_node, b_stream, 0).subscription;
        wait_for_acknowledgement(&service_a, b_receives_a, 1)
            .await
            .context("b did not acknowledge a")?;
        wait_for_acknowledgement(&service_b, a_receives_b, 1)
            .await
            .context("a did not acknowledge b")?;

        runtime_b.task.abort();
        drop(runtime_b.task.await);
        runtime_b.runtime.shutdown().await;
        blocking_b.close();
        blocking_b.wait_idle().await;
        db_b.wait_idle().await;
        drop(service_b);
        drop(store_b);
        drop(projection_b);
        drop(state_b);
        drop(db_b);
        state_a.write_set(&a_path, Value::integer(2)).await?;
        let db_b = xolotl_storage_redb::RedbStore::open_with_history(
            b_dir.join("federation.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store_b = db_b.federation_store(b_node)?;
        let projection_b = db_b.federation_state_projection(b_node)?;
        let state_b = db_b.state_backend().into_backend();
        let service_b =
            FederationService::new(Arc::new(store_b.clone()), FederationLimits::default())?;
        state_b.write_set(&b_path, Value::integer(2)).await?;
        let restarted_b = start(
            prepare(&b)?.context("restarted b disabled")?,
            store_b,
            Some(projection_b),
            test_boot(state_b),
        )
        .await?;
        wait_for_acknowledgement(&service_a, b_receives_a, 2)
            .await
            .context("b did not resume a")?;
        wait_for_acknowledgement(&service_b, a_receives_b, 2)
            .await
            .context("a did not resume b")?;
        restarted_b.task.abort();
        drop(restarted_b.task.await);
        runtime_a.task.abort();
        drop(runtime_a.task.await);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn stock_peer_precheck_uses_decision_time_instead_of_an_older_frame_time() -> Result<()> {
        use xolotl_federation::{
            FederationSessionTranscript, PeerAdmission, verify_federation_peer_proof,
        };

        let directory = tempfile::tempdir()?;
        let db = xolotl_storage_redb::RedbStore::open(directory.path().join("precheck.redb"))?;
        let local = FederationNodeId::from_bytes([71; 48]);
        let root_key = FederationRootKey::generate()?;
        let root = root_key.root()?;
        let peer = root.node_id();
        let online_key = FederationOnlineKey::generate()?;
        let now = wall_ms()?;
        let authorization = FederationOnlineKeyAuthorization::new(
            online_key.public_key(),
            1,
            now.saturating_sub(1_000),
            now + 60_000,
        )?;
        let root_signature = root_key.sign(
            RootSignaturePurpose::OnlineKeyAuthorization,
            &authorization.encode(),
        )?;
        let transcript =
            FederationSessionTranscript::new(local, peer, [1; 32], [2; 32], [3; 48], [4; 48])?;
        let online_signature = online_key.sign_session(peer, &authorization, &transcript)?;
        let proof = verify_federation_peer_proof(
            &root,
            peer,
            &authorization,
            &root_signature,
            &transcript,
            &online_signature,
            now,
        )?;
        let store = db.federation_store(local)?;
        store.set_peer_authority(peer, None, true)?;
        store.set_peer_admission(
            peer,
            None,
            PeerAdmission {
                minimum_online_generation: 1,
                allowed_authorization_digests: vec![proof.authorization_digest()],
            },
        )?;
        let policy = PersistedPeerPolicy {
            store: store.clone(),
            local,
            issuer_rules: Vec::new(),
        };
        policy.current_time_ms()?;
        policy.check_current_peer(proof, now.saturating_sub(100))?;
        store.set_peer_authority(peer, Some(1), false)?;
        ensure!(policy.check_current_peer(proof, now).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stock_call_reconciles_original_ref_after_source_restart_and_revocation() -> Result<()>
    {
        use crate::config::{
            FederationCallAuthorityConfig, FederationCallSubjectConfig,
            FederationMethodCodecConfig, FederationMethodConfig, FederationPeerDialConfig,
        };
        use sha2::Digest as _;
        use tonic::Code;
        use xolotl_sdk::{Expression, Program};

        let directory = tempfile::tempdir()?;
        let a_dir = directory.path().join("target");
        let b_dir = directory.path().join("source");
        std::fs::create_dir(&a_dir)?;
        std::fs::create_dir(&b_dir)?;
        let mut a = configured_publisher(&a_dir)?;
        let mut b = configured_publisher(&b_dir)?;
        let a_node = prepare(&a)?.context("target disabled")?.node_id();
        let b_node = prepare(&b)?.context("source disabled")?.node_id();
        for config in [&mut a, &mut b] {
            config.federation.streams.clear();
            config.federation.state_history_publications.clear();
            config.federation.peers[0].exports[0].name = "tools".into();
        }
        a.federation.peers[0].node_id = hex_bytes(b_node.as_bytes());
        a.federation.peers[0].allowed_authorization_digests = vec![online_digest_hex(&b)?];
        b.federation.peers[0].node_id = hex_bytes(a_node.as_bytes());
        b.federation.peers[0].allowed_authorization_digests = vec![online_digest_hex(&a)?];
        b.federation.peers[0].exports[0].receive = true;
        b.server.federation_grpc_addr = None;

        let program = Program::new(Expression::Input);
        let program_path = private_file(
            &a_dir.join("echo-program.json"),
            &serde_json::to_vec(&program)?,
        )?;
        let mut method = FederationMethodConfig {
            export: "tools".into(),
            path: "/echo".into(),
            method: "echo".into(),
            contract_digest: String::new(),
            program_path,
            program_id: String::new(),
            identity_path: "identity://federation/echo".into(),
            codec: FederationMethodCodecConfig::BytesV1,
            grants: Vec::new(),
        };
        crate::federation_catalog::commit_test_method(&mut method)?;
        let target = CallTarget {
            export: ExportName::new(method.export.clone())?,
            path: CallPath::new(method.path.clone())?,
            method: CallMethod::new(method.method.clone())?,
            contract_digest: decode_hex::<32>(&method.contract_digest, "test contract")?,
        };
        let authority = FederationCallAuthorityConfig {
            presenter: hex_bytes(b_node.as_bytes()),
            subject: FederationCallSubjectConfig::Node,
            export: method.export.clone(),
            path: method.path.clone(),
            method: method.method.clone(),
            contract_digest: method.contract_digest.clone(),
            enabled: true,
            expires_ms: wall_ms()? + 120_000,
            max_input_bytes: 1024,
            max_prepare_window_ms: 30_000,
            max_result_retention_ms: 30_000,
            expected_revision: None,
        };
        a.federation.methods.push(method);
        a.federation.call_authorities.push(authority.clone());

        let db_a = xolotl_storage_redb::RedbStore::open_with_history(
            a_dir.join("calls.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store_a = db_a.federation_store(a_node)?;
        let runtime_a = start(
            prepare(&a)?.context("target disabled")?,
            store_a.clone(),
            None,
            live_test_boot(&db_a)?,
        )
        .await?;
        let address = runtime_a.address.context("target did not listen")?;
        b.federation.peers[0].dial = Some(FederationPeerDialConfig {
            uri: format!("http://{address}"),
            server_name: "localhost".into(),
            trust_root_path: private_file(&b_dir.join("peer-ca.pem"), CA_CERT)?,
        });
        let prepared_b = prepare(&b)?.context("source disabled")?;
        let route = prepared_b.policy.dials[0].route.clone();
        let local_b = Arc::clone(&prepared_b.local);
        let grpc_b = prepared_b.grpc;
        let db_b = xolotl_storage_redb::RedbStore::open_with_history(
            b_dir.join("calls.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store_b = db_b.federation_store(b_node)?;
        let runtime_b = start(
            prepared_b,
            store_b.clone(),
            None,
            test_boot(db_b.state_backend().into_backend()),
        )
        .await?;
        ensure!(runtime_b.address.is_none());
        let policy_b: Arc<dyn FederationPeerPolicy> = Arc::new(PersistedPeerPolicy {
            store: store_b.clone(),
            local: b_node,
            issuer_rules: Vec::new(),
        });
        let client = FederationGrpcSubscriberClient::connect(
            route.clone(),
            Arc::clone(&local_b),
            Arc::clone(&policy_b),
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                grpc_b,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await?;
        let input: Arc<[u8]> = Arc::from(b"hello federation".as_slice());
        let request_id = RequestId::from_bytes([0xa1; 16]);
        let intent = OutboundCallIntent {
            target_node: a_node,
            request: PrepareCallRequest {
                authenticated_origin: b_node,
                subject: FederationSubject::Node(b_node),
                origin_request_id: request_id,
                target: target.clone(),
                input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
                input_bytes: input.len() as u64,
                prepare_deadline_ms: wall_ms()? + 15_000,
                execution_deadline_ms: wall_ms()? + 30_000,
                result_retention_ms: 30_000,
            },
            input: Arc::clone(&input),
        };
        let source: Arc<dyn FederationOutboundCallStore> = Arc::new(store_b.clone());
        let prepared = client
            .prepare_call_persisted(0, intent, Arc::clone(&source), wall_ms()?)
            .await
            .context("prepare original call before source restart")?;
        ensure!(prepared.status == CallStatus::Reserved && prepared.call.target == a_node);
        ensure!(source.outbound_call(request_id)?.prepared == Some(prepared.clone()));
        let invoked = client
            .invoke_call_persisted(0, request_id, Arc::clone(&source), wall_ms()?)
            .await
            .context("invoke original call before source restart")?;
        ensure!(invoked.call == prepared.call && invoked.status == CallStatus::Accepted);
        ensure!(source.outbound_call(request_id)?.invoke_possible);

        // A second Prepare reached the target, but its response was lost
        // before the source could bind the CallRef. The source cancellation
        // and original request survive restart.
        let cancelled_operation: xolotl_types::OperationId = "31/32/33/34/35".parse()?;
        let cancelled_id =
            xolotl_federation_grpc::DurableOperationIdHash::new(store_b.kernel_call_namespace()?)?
                .request_id(b_node, cancelled_operation)?;
        store_b.bind_outbound_origin(
            cancelled_id,
            cancelled_operation,
            Digest::from_bytes([0xb3; 48]),
        )?;
        let now = wall_ms()?;
        let cancelled_request = PrepareCallRequest {
            authenticated_origin: b_node,
            subject: FederationSubject::Node(b_node),
            origin_request_id: cancelled_id,
            target: target.clone(),
            input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
            input_bytes: input.len() as u64,
            prepare_deadline_ms: now + 1_000,
            execution_deadline_ms: now + 30_000,
            result_retention_ms: 30_000,
        };
        store_b.stage_outbound(
            OutboundCallIntent {
                target_node: a_node,
                request: cancelled_request.clone(),
                input: Arc::clone(&input),
            },
            now,
        )?;
        let target_prepared = client
            .prepare_call_as(0, cancelled_request.clone())
            .await
            .context("target accepted second Prepare before source restart")?;
        ensure!(target_prepared.status == CallStatus::Reserved);
        ensure!(
            store_a.prepared_call_for_request(&cancelled_request)? == Some(target_prepared.clone())
        );
        ensure!(store_b.stage_outbound_cancellation(cancelled_operation)? == Some(cancelled_id));
        ensure!(store_b.outbound_call(cancelled_id)?.prepared.is_none());

        // The source lost its Session and reopened the same durable ledger;
        // Inspect must settle the original CallRef rather than prepare again.
        drop(client);
        runtime_b.task.abort();
        drop(runtime_b.task.await);
        drop(policy_b);
        drop(source);
        drop(store_b);
        drop(db_b);
        let reopened_b = xolotl_storage_redb::RedbStore::open_with_history(
            b_dir.join("calls.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store_b = reopened_b.federation_store(b_node)?;
        let persisted: Arc<dyn FederationOutboundCallStore> = Arc::new(store_b.clone());
        let record = persisted.outbound_call(request_id)?;
        ensure!(record.prepared == Some(prepared.clone()) && record.invoke_possible);
        ensure!(
            persisted
                .pending_outbound_cancellations(None, 32)?
                .iter()
                .any(|row| row.intent.request_id() == cancelled_id)
        );
        let restarted_b = start(
            prepare(&b)?.context("restarted source disabled")?,
            store_b.clone(),
            None,
            test_boot(reopened_b.state_backend().into_backend()),
        )
        .await?;
        let policy_b: Arc<dyn FederationPeerPolicy> = Arc::new(PersistedPeerPolicy {
            store: store_b.clone(),
            local: b_node,
            issuer_rules: Vec::new(),
        });
        let reconnect = FederationGrpcSubscriberClient::connect(
            route.clone(),
            Arc::clone(&local_b),
            Arc::clone(&policy_b),
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                grpc_b,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await?;
        let settled = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                let inspection = reconnect
                    .inspect_call_persisted(0, request_id, Arc::clone(&persisted))
                    .await
                    .context("inspect original call after source restart")?;
                if inspection.status == CallStatus::Finished {
                    break Ok::<_, anyhow::Error>(inspection);
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await??;
        ensure!(settled.call == prepared.call);
        let result = settled
            .result
            .as_ref()
            .context("missing retained Call result")?;
        ensure!(result.succeeded && result.output.as_ref() == input.as_ref());
        ensure!(persisted.outbound_call(request_id)?.terminal == Some(settled));

        let rule = CallAuthorityRule {
            subject: FederationSubject::Node(b_node),
            presenter: b_node,
            target: target.clone(),
            enabled: true,
            expires_ms: authority.expires_ms,
            max_input_bytes: authority.max_input_bytes,
            max_prepare_window_ms: authority.max_prepare_window_ms,
            max_result_retention_ms: authority.max_result_retention_ms,
        };
        let key = CallAuthorityKey::from_rule(&rule);
        let current = store_a
            .call_authority(&key)?
            .context("missing call authority")?;
        let mut disabled = current.rule;
        disabled.enabled = false;
        store_a.set_call_authority(Some(current.revision), disabled)?;
        ensure!(
            store_a.prepared_call_for_request(&cancelled_request)? == Some(target_prepared.clone())
        );
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        ensure!(wall_ms()? > now + 1_000);
        let cancelled_row = persisted
            .pending_outbound_cancellations(None, 32)?
            .into_iter()
            .find(|row| row.intent.request_id() == cancelled_id)
            .context("cancelled source call lost after restart")?;
        let sessions = crate::federation_outbound::stock_sessions(
            Arc::clone(&local_b),
            Arc::clone(&policy_b),
            FederationGrpcRuntime::new(
                grpc_b,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
            [route],
            &[],
        )?;
        crate::federation_cancellation::retry_cancellation(
            &xolotl_kernel::host::HostRuntime::default(),
            &store_b,
            sessions.as_ref(),
            cancelled_row.into(),
        )
        .await
        .context("reconcile cancelled source call after target grant revocation")?;
        let cancelled = persisted.outbound_call(cancelled_id)?;
        ensure!(
            cancelled
                .prepared
                .as_ref()
                .is_some_and(|prepared| prepared.call == target_prepared.call)
                && !cancelled.invoke_possible
                && cancelled.cancel_acknowledged.is_some()
        );
        ensure!(
            persisted
                .pending_outbound_cancellations(None, 32)?
                .is_empty()
        );
        let cancellation_terminal = reconnect
            .inspect_call_persisted(0, cancelled_id, Arc::clone(&persisted))
            .await
            .context("inspect cancelled call after target grant revocation")?;
        ensure!(cancellation_terminal.status == CallStatus::Closed);
        let denied_id = RequestId::from_bytes([0xa2; 16]);
        let denied = reconnect
            .prepare_call_persisted(
                0,
                OutboundCallIntent {
                    target_node: a_node,
                    request: PrepareCallRequest {
                        authenticated_origin: b_node,
                        subject: FederationSubject::Node(b_node),
                        origin_request_id: denied_id,
                        target,
                        input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
                        input_bytes: input.len() as u64,
                        prepare_deadline_ms: wall_ms()? + 15_000,
                        execution_deadline_ms: wall_ms()? + 30_000,
                        result_retention_ms: 30_000,
                    },
                    input,
                },
                Arc::clone(&persisted),
                wall_ms()?,
            )
            .await
            .err()
            .context("revoked method granted a new CallRef")?;
        ensure!(denied.code() == Code::PermissionDenied);
        ensure!(persisted.outbound_call(denied_id)?.prepared.is_none());
        restarted_b.task.abort();
        drop(restarted_b.task.await);
        runtime_a.task.abort();
        drop(runtime_a.task.await);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unknown_node_reads_only_public_stream_over_proven_tls_session() -> Result<()> {
        use crate::config::FederationPublicStreamConfig;
        use sha2::Digest as _;
        use tonic::Code;

        struct PinnedPublisher(FederationNodeId);
        impl FederationPeerPolicy for PinnedPublisher {
            fn decision_clock(
                &self,
            ) -> Result<Arc<dyn xolotl_federation::FederationObjectClock>, Status> {
                Ok(Arc::new(xolotl_federation::SystemObjectClock))
            }

            fn current_time_ms(&self) -> Result<u64, Status> {
                wall_ms().map_err(|error| Status::failed_precondition(error.to_string()))
            }

            fn check_current_peer(
                &self,
                proof: VerifiedFederationPeerProof,
                _now_ms: u64,
            ) -> Result<(), Status> {
                if proof.node_id() == self.0 {
                    Ok(())
                } else {
                    Err(Status::permission_denied("unexpected publisher"))
                }
            }
        }

        let directory = tempfile::tempdir()?;
        let a_dir = directory.path().join("public-publisher");
        let b_dir = directory.path().join("unknown-reader");
        std::fs::create_dir(&a_dir)?;
        std::fs::create_dir(&b_dir)?;
        let mut a = configured_publisher(&a_dir)?;
        let b = configured_publisher(&b_dir)?;
        let a_node = prepare(&a)?.context("publisher disabled")?.node_id();
        let prepared_b = prepare(&b)?.context("reader credentials disabled")?;
        let b_node = prepared_b.node_id();
        a.federation.peers.clear();
        a.federation
            .public_streams
            .push(FederationPublicStreamConfig {
                stream_id: "44".repeat(16),
                enabled: true,
                max_read_records: 8,
                max_read_bytes: STOCK_RECORD_BYTES,
                expected_revision: None,
            });
        let db_a = xolotl_storage_redb::RedbStore::open_with_history(
            a_dir.join("public.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store_a = db_a.federation_store(a_node)?;
        let projection_a = db_a.federation_state_projection(a_node)?;
        let state_a = db_a.state_backend().into_backend();
        let runtime_a = start(
            prepare(&a)?.context("public-only publisher disabled")?,
            store_a.clone(),
            Some(projection_a),
            test_boot(state_a.clone()),
        )
        .await?;
        let stream = StreamRef {
            publisher: a_node,
            id: StreamId::from_bytes([0x44; 16]),
        };
        ensure!(store_a.peer_authority(b_node)?.is_none());
        state_a
            .write_set(
                &StatePath::parse("state://federation/public/notes/entry")?,
                Value::integer(7),
            )
            .await?;
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                if store_a
                    .inspect_public_stream(b_node, stream)
                    .ok()
                    .and_then(|view| view.head)
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await?;
        let route = PeerDialConfig {
            uri: format!(
                "http://{}",
                runtime_a.address.context("publisher did not listen")?
            ),
            expected_peer: a_node,
            server_name: "localhost".into(),
            peer_trust_root_pem: CA_CERT.to_vec(),
            client_certificate_pem: SERVER_CERT.to_vec(),
            client_key_pem: SERVER_KEY.to_vec(),
        };
        let policy_b: Arc<dyn FederationPeerPolicy> = Arc::new(PinnedPublisher(a_node));
        let local_b = prepared_b.local;
        let grpc_b = prepared_b.grpc;
        let client = FederationGrpcSubscriberClient::connect(
            route.clone(),
            Arc::clone(&local_b),
            Arc::clone(&policy_b),
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                grpc_b,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await?;
        let view = client.inspect_public(stream).await?;
        ensure!(view.stream == stream && view.policy_revision == 1 && view.head.is_some());
        let page = client
            .read_public(xolotl_federation::PublicReadRequest {
                authenticated_reader: b_node,
                stream,
                expected_policy_revision: view.policy_revision,
                after: None,
                max_records: 8,
                max_bytes: STOCK_RECORD_BYTES,
            })
            .await?;
        ensure!(page.records.len() == 1 && page.records[0].stream() == stream);
        ensure!(store_a.peer_authority(b_node)?.is_none());
        let follower_path = b_dir.join("public-follow.redb");
        {
            let receiver_db = xolotl_storage_redb::RedbStore::open(&follower_path)?;
            let follower = receiver_db.public_follower_store(b_node)?;
            follower.observe(&view)?;
            let accepted = follower.accept_page(stream, &page, 2, STOCK_RECORD_BYTES)?;
            ensure!(accepted.cursor == Some(page.records[0].position()));
        }
        state_a
            .write_set(
                &StatePath::parse("state://federation/public/notes/entry")?,
                Value::integer(8),
            )
            .await?;
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                if store_a
                    .inspect_public_stream(b_node, stream)
                    .ok()
                    .and_then(|view| view.head)
                    .is_some_and(|head| head.sequence() >= 2)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await?;
        {
            let receiver_db = xolotl_storage_redb::RedbStore::open(&follower_path)?;
            let follower = receiver_db.public_follower_store(b_node)?;
            let cursor = follower
                .inspect(stream)?
                .context("missing durable public follower cursor")?
                .cursor
                .context("public follower cursor was not persisted")?;
            let fresh_view = client.inspect_public(stream).await?;
            follower.observe(&fresh_view)?;
            let next = client
                .read_public(xolotl_federation::PublicReadRequest {
                    authenticated_reader: b_node,
                    stream,
                    expected_policy_revision: fresh_view.policy_revision,
                    after: Some(cursor),
                    max_records: 8,
                    max_bytes: STOCK_RECORD_BYTES,
                })
                .await?;
            ensure!(next.records.len() == 1 && next.records[0].sequence() == 2);
            ensure!(
                follower
                    .accept_page(stream, &next, 2, STOCK_RECORD_BYTES)?
                    .cursor
                    == Some(next.records[0].position())
            );
            ensure!(
                follower
                    .read_inbox(stream, None, 8, STOCK_RECORD_BYTES)?
                    .records
                    .len()
                    == 2
            );
        }
        let mut follow_config = b.clone();
        follow_config.federation.peers.clear();
        let trust_root_path = private_file(&b_dir.join("publisher-ca.crt"), CA_CERT)?;
        let authorization_path = a
            .federation
            .online_authorization_path
            .as_ref()
            .context("publisher authorization path missing")?;
        let authorization_digest = Sha384::digest(std::fs::read(authorization_path)?);
        follow_config
            .federation
            .public_follows
            .push(crate::config::FederationPublicFollowConfig {
                publisher_node: hex_bytes(a_node.as_bytes()),
                stream_id: hex_bytes(stream.id.as_bytes()),
                dial: crate::config::FederationPeerDialConfig {
                    uri: route.uri.clone(),
                    server_name: route.server_name.clone(),
                    trust_root_path,
                },
                minimum_online_generation: 1,
                allowed_authorization_digests: vec![hex_bytes(&authorization_digest)],
                max_inbox_records: 2,
                max_inbox_bytes: STOCK_RECORD_BYTES,
            });
        let prepared_follow = prepare(&follow_config)?.context("public follower disabled")?;
        ensure!(prepared_follow.needs_public_follow_store());
        let receiver_db = xolotl_storage_redb::RedbStore::open(&follower_path)?;
        let follower = receiver_db.public_follower_store(b_node)?;
        let tasks = prepared_follow.start_public_follows(
            &xolotl_kernel::host::HostRuntime::default(),
            receiver_db.federation_store(b_node)?,
            follower.clone(),
        )?;
        state_a
            .write_set(
                &StatePath::parse("state://federation/public/notes/entry")?,
                Value::integer(9),
            )
            .await?;
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                if follower
                    .inspect(stream)
                    .ok()
                    .flatten()
                    .and_then(|view| view.cursor)
                    .is_some_and(|cursor| cursor.sequence() >= 3)
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await?;
        ensure!(follower.inspect(stream)?.is_some_and(|view| view.retained_records == 2
            && view.local_minimum_available == 2));
        for task in tasks {
            task.abort();
            drop(task.await);
        }
        drop(follower);
        drop(receiver_db);
        ensure!(store_a.peer_authority(b_node)?.is_none());

        let private = client
            .open(OpenRequest {
                authenticated_subscriber: b_node,
                request_id: RequestId::from_bytes([0x91; 16]),
                subscription: SubscriptionRef {
                    subscriber: b_node,
                    id: SubscriptionId::from_bytes([0x92; 16]),
                },
                stream,
                expected_control_revision: None,
                history: HistoryStart::All,
            })
            .await
            .err()
            .context("public-only Session accepted private Open")?;
        ensure!(private.code() == Code::PermissionDenied);
        ensure!(store_a.peer_authority(b_node)?.is_none());

        let call_client = FederationGrpcSubscriberClient::connect(
            route.clone(),
            Arc::clone(&local_b),
            Arc::clone(&policy_b),
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                grpc_b,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await?;
        let call = call_client
            .prepare_call_as(
                0,
                PrepareCallRequest {
                    authenticated_origin: b_node,
                    subject: FederationSubject::Node(b_node),
                    origin_request_id: RequestId::from_bytes([0x93; 16]),
                    target: CallTarget {
                        export: ExportName::new("tools")?,
                        path: CallPath::new("/echo")?,
                        method: CallMethod::new("echo")?,
                        contract_digest: [1; 32],
                    },
                    input_digest: Digest::from_bytes(Sha384::digest([]).into()),
                    input_bytes: 0,
                    prepare_deadline_ms: wall_ms()? + 10_000,
                    execution_deadline_ms: wall_ms()? + 20_000,
                    result_retention_ms: 10_000,
                },
            )
            .await
            .err()
            .context("public-only Session accepted private Call")?;
        ensure!(call.code() == Code::PermissionDenied);

        let active = FederationGrpcSubscriberClient::connect(
            route.clone(),
            Arc::clone(&local_b),
            Arc::clone(&policy_b),
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                grpc_b,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await?;
        ensure!(active.inspect_public(stream).await?.policy_revision == view.policy_revision);
        let old_prepared = prepare(&a)?.context("old public plan missing")?;
        let old_plan = &old_prepared.policy.public_streams;
        store_a.set_public_stream_policy(
            Some(view.policy_revision),
            PublicStreamPolicy {
                stream,
                enabled: false,
                max_read_records: 8,
                max_read_bytes: STOCK_RECORD_BYTES,
            },
        )?;
        let revoked = active
            .inspect_public(stream)
            .await
            .err()
            .context("revoked public policy remained readable")?;
        ensure!(revoked.code() == Code::PermissionDenied);
        ensure!(reconcile_public_streams(&store_a, old_plan).is_err());

        store_a.set_peer_authority(b_node, None, false)?;
        let disabled = FederationGrpcSubscriberClient::connect(
            route,
            local_b,
            policy_b,
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                grpc_b,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await;
        if let Ok(client) = disabled {
            ensure!(client.inspect_public(stream).await.is_err());
        }
        runtime_a.task.abort();
        drop(runtime_a.task.await);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unknown_node_reads_exact_object_grant_over_proven_tls_session() -> Result<()> {
        use crate::config::FederationObjectGrantConfig;
        use sha2::Digest as _;
        use tonic::Code;
        use xolotl_state::object::{ObjectWrite as _, UploadOptions};
        use xolotl_types::TaintSet;

        struct PinnedPublisher(FederationNodeId);
        impl FederationPeerPolicy for PinnedPublisher {
            fn decision_clock(
                &self,
            ) -> Result<Arc<dyn xolotl_federation::FederationObjectClock>, Status> {
                Ok(Arc::new(xolotl_federation::SystemObjectClock))
            }

            fn current_time_ms(&self) -> Result<u64, Status> {
                wall_ms().map_err(|error| Status::failed_precondition(error.to_string()))
            }
            fn check_current_peer(
                &self,
                proof: VerifiedFederationPeerProof,
                _now_ms: u64,
            ) -> Result<(), Status> {
                if proof.node_id() == self.0 {
                    Ok(())
                } else {
                    Err(Status::permission_denied("unexpected publisher"))
                }
            }
        }

        let directory = tempfile::tempdir()?;
        let a_dir = directory.path().join("object-publisher");
        let b_dir = directory.path().join("object-reader");
        std::fs::create_dir(&a_dir)?;
        std::fs::create_dir(&b_dir)?;
        let mut a = configured_publisher(&a_dir)?;
        let b = configured_publisher(&b_dir)?;
        let a_node = prepare(&a)?.context("publisher disabled")?.node_id();
        let prepared_b = prepare(&b)?.context("reader disabled")?;
        let b_node = prepared_b.node_id();
        let bytes = b"federated object bytes";
        let files = xolotl_storage_fs::FileObjectStore::open(a_dir.join("objects"))?;
        let upload = files
            .begin_upload(UploadOptions {
                expected_size: Some(bytes.len() as u64),
                mime: Some("application/octet-stream".into()),
                ..UploadOptions::default()
            })
            .await?;
        let written = files.write_chunk(&upload, 0, bytes).await?;
        ensure!(written.bytes_written == bytes.len());
        let blob = files
            .commit_upload(&upload, &TaintSet::pristine())
            .await?
            .blob;
        a.federation.peers.clear();
        a.federation.streams.clear();
        a.federation.state_history_publications.clear();
        a.federation.object_grants = Some(vec![FederationObjectGrantConfig {
            presenter: hex_bytes(b_node.as_bytes()),
            subject: FederationCallSubjectConfig::Node,
            hash: blob.hash.clone(),
            size: blob.size,
            mime: blob.mime.clone(),
            range_start: 0,
            range_end: blob.size,
            expires_at_ms: wall_ms()? + 120_000,
            max_total_bytes: 4 * blob.size,
            max_chunk_bytes: 8,
        }]);
        let db_a = xolotl_storage_redb::RedbStore::open_with_history(
            a_dir.join("object.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store_a = db_a.federation_store(a_node)?;
        let runtime_a = start_with_objects(
            prepare(&a)?.context("object-only publisher disabled")?,
            store_a.clone(),
            None,
            test_boot(db_a.state_backend().into_backend()),
            files.into_object_store(),
        )
        .await?;
        ensure!(store_a.peer_authority(b_node)?.is_none());
        let grants = store_a.list_object_grants()?;
        ensure!(grants.len() == 1 && grants[0].enabled);
        let grant = grants[0].id;
        let revision = grants[0].revision;
        let route = PeerDialConfig {
            uri: format!(
                "http://{}",
                runtime_a.address.context("publisher did not listen")?
            ),
            expected_peer: a_node,
            server_name: "localhost".into(),
            peer_trust_root_pem: CA_CERT.to_vec(),
            client_certificate_pem: SERVER_CERT.to_vec(),
            client_key_pem: SERVER_KEY.to_vec(),
        };
        let client = FederationGrpcSubscriberClient::connect(
            route,
            prepared_b.local,
            Arc::new(PinnedPublisher(a_node)),
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                prepared_b.grpc,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await?;
        let transfer = xolotl_federation::ObjectTransferId::from_bytes([0x85; 16]);
        let mut received = Vec::new();
        let mut offset = 0;
        loop {
            let page = client
                .read_object(ObjectReadRequest {
                    authenticated_presenter: b_node,
                    subject: FederationSubject::Node(b_node),
                    transfer,
                    grant,
                    expected_revision: revision,
                    blob: blob.clone(),
                    offset,
                    max_bytes: (blob.size - offset).min(8) as usize,
                })
                .await?;
            ensure!(page.transfer == transfer && page.offset == offset);
            offset += page.bytes.len() as u64;
            received.extend_from_slice(&page.bytes);
            if page.end_of_range {
                ensure!(page.end_of_object);
                break;
            }
        }
        ensure!(received == bytes);
        ensure!(xolotl_types::BlobRef::sha384_hex(&Sha384::digest(&received).into()) == blob.hash);
        ensure!(store_a.peer_authority(b_node)?.is_none());
        store_a.revoke_object_grant(grant, revision)?;
        let denied = client
            .read_object(ObjectReadRequest {
                authenticated_presenter: b_node,
                subject: FederationSubject::Node(b_node),
                transfer,
                grant,
                expected_revision: revision,
                blob,
                offset: 0,
                max_bytes: 8,
            })
            .await
            .err()
            .context("revoked object grant remained readable")?;
        ensure!(denied.code() == Code::PermissionDenied);
        runtime_a.task.abort();
        drop(runtime_a.task.await);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn guest_redeems_named_invitation_over_proven_tls_without_peer_trust() -> Result<()> {
        use crate::config::{FederationSubjectIssuerConfig, FederationSubjectPurposeConfig};
        use tonic::Code;
        use xolotl_federation::{
            FederationInvitationStore as _, GrantHistory, HostedSubject, InvitationAudience,
            InvitationId, InvitationSpec, SubjectAssertion, SubjectGrant, SubjectHolderKey,
            SubjectIssuerKey,
        };
        use xolotl_federation_grpc::FederationHostedSubjectCredentials;

        struct PinnedPublisher(FederationNodeId);
        impl FederationPeerPolicy for PinnedPublisher {
            fn decision_clock(
                &self,
            ) -> Result<Arc<dyn xolotl_federation::FederationObjectClock>, Status> {
                Ok(Arc::new(xolotl_federation::SystemObjectClock))
            }

            fn current_time_ms(&self) -> Result<u64, Status> {
                wall_ms().map_err(|error| Status::failed_precondition(error.to_string()))
            }
            fn check_current_peer(
                &self,
                proof: VerifiedFederationPeerProof,
                _now_ms: u64,
            ) -> Result<(), Status> {
                if proof.node_id() == self.0 {
                    Ok(())
                } else {
                    Err(Status::permission_denied("unexpected publisher"))
                }
            }
        }

        let directory = tempfile::tempdir()?;
        let a_dir = directory.path().join("guest-publisher");
        let b_dir = directory.path().join("guest-presenter");
        std::fs::create_dir(&a_dir)?;
        std::fs::create_dir(&b_dir)?;
        let mut a = configured_publisher(&a_dir)?;
        let b = configured_publisher(&b_dir)?;
        let a_node = prepare(&a)?.context("publisher disabled")?.node_id();
        let prepared_b = prepare(&b)?.context("guest credentials disabled")?;
        let b_node = prepared_b.node_id();
        let issuer_key = SubjectIssuerKey::generate()?;
        let issuer = issuer_key.issuer()?;
        let holder = Arc::new(SubjectHolderKey::generate()?);
        let guest = HostedSubject {
            issuer: issuer.id(),
            namespace: "people".into(),
            subject: "guest".into(),
        };
        let owner = HostedSubject {
            issuer: issuer.id(),
            namespace: "people".into(),
            subject: "owner".into(),
        };
        a.federation.peers.clear();
        a.federation
            .subject_issuers
            .push(FederationSubjectIssuerConfig {
                issuer: hex_bytes(&issuer.id().as_bytes()),
                namespace: "people".into(),
                presenter: hex_bytes(b_node.as_bytes()),
                purposes: vec![FederationSubjectPurposeConfig::Sync],
            });
        let db_a = xolotl_storage_redb::RedbStore::open_with_history(
            a_dir.join("guest.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store_a = db_a.federation_store(a_node)?;
        let projection_a = db_a.federation_state_projection(a_node)?;
        let state_a = db_a.state_backend().into_backend();
        let runtime_a = start(
            prepare(&a)?.context("guest publisher disabled")?,
            store_a.clone(),
            Some(projection_a),
            test_boot(state_a.clone()),
        )
        .await?;
        let stream = StreamRef {
            publisher: a_node,
            id: StreamId::from_bytes([0x44; 16]),
        };
        store_a.append_published(PublishRequest {
            retry_epoch: store_a.publication_epoch(stream)?,
            stream,
            publish_id: RequestId::from_bytes([0x20; 16]),
            event_type: EventType::new("guest-test")?,
            schema_revision: SchemaRevision::from_bytes([0x20; 32]),
            event_ref: None,
            payload: Arc::from(b"guest-entry".as_slice()),
        })?;
        ensure!(store_a.peer_authority(b_node)?.is_none());
        store_a.set_invitation_issuer_authority(&owner, stream, None, true)?;
        let now = wall_ms()?;
        let invitation = InvitationId::from_bytes([0x21; 16]);
        let spec = InvitationSpec {
            issuer: owner,
            stream,
            audience: InvitationAudience::Named {
                presenter: b_node,
                subject: guest.clone(),
            },
            not_before_ms: now - 1_000,
            expires_ms: now + 50_000,
            grant_expires_ms: now + 40_000,
            max_redemptions: 1,
            history: GrantHistory::All,
        };
        let created = store_a.create_invitation(invitation, spec, now)?;
        let assertion = SubjectAssertion::new(
            issuer.id(),
            "people",
            "guest",
            a_node,
            b_node,
            SubjectPurpose::Sync,
            now - 1_000,
            now + 40_000,
            holder.public_key(),
        )?;
        let credentials = Arc::new(FederationHostedSubjectCredentials::new(
            &issuer,
            assertion.clone(),
            issuer_key.sign_assertion(&assertion)?,
            holder,
        )?);
        let route = PeerDialConfig {
            uri: format!(
                "http://{}",
                runtime_a.address.context("publisher did not listen")?
            ),
            expected_peer: a_node,
            server_name: "localhost".into(),
            peer_trust_root_pem: CA_CERT.to_vec(),
            client_certificate_pem: SERVER_CERT.to_vec(),
            client_key_pem: SERVER_KEY.to_vec(),
        };
        let client = FederationGrpcSubscriberClient::connect(
            route.clone(),
            Arc::clone(&prepared_b.local),
            Arc::new(PinnedPublisher(a_node)),
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                prepared_b.grpc,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await?;
        client.register_subject(7, Arc::clone(&credentials)).await?;
        let request_id = RequestId::from_bytes([0x22; 16]);
        let receipt = client
            .redeem_invitation_as(7, invitation, request_id, created.revision, None)
            .await?;
        ensure!(receipt.currently_authorized && receipt.stream == stream);
        ensure!(store_a.peer_authority(b_node)?.is_none());
        let subscription = SubscriptionRef {
            subscriber: b_node,
            id: SubscriptionId::from_bytes([0x23; 16]),
        };
        let opened = client
            .open_as(
                7,
                OpenRequest {
                    authenticated_subscriber: b_node,
                    request_id: RequestId::from_bytes([0x24; 16]),
                    subscription,
                    stream,
                    expected_control_revision: None,
                    history: HistoryStart::All,
                },
            )
            .await?;
        ensure!(opened.subscription == subscription);
        let read = ReadRequest {
            authenticated_subscriber: b_node,
            subscription,
            after: None,
            max_records: 8,
            max_bytes: STOCK_RECORD_BYTES,
        };
        let page = client.read_as(7, read.clone(), stream).await?;
        ensure!(page.records.len() == 1);
        let revoked_invitation = store_a.revoke_invitation(invitation, created.revision)?;
        ensure!(!revoked_invitation.enabled);
        let reconnect = FederationGrpcSubscriberClient::connect(
            route.clone(),
            Arc::clone(&prepared_b.local),
            Arc::new(PinnedPublisher(a_node)),
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                prepared_b.grpc,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await?;
        reconnect
            .register_subject(7, Arc::clone(&credentials))
            .await?;
        let replay = reconnect
            .redeem_invitation_as(7, invitation, request_id, created.revision, None)
            .await?;
        ensure!(replay == receipt);
        ensure!(client.read_as(7, read.clone(), stream).await?.records.len() == 1);
        let denied = client
            .redeem_invitation_as(
                7,
                invitation,
                RequestId::from_bytes([0x25; 16]),
                created.revision,
                None,
            )
            .await
            .err()
            .context("revoked invitation allowed new redemption")?;
        ensure!(denied.code() == Code::PermissionDenied);
        let expired_id = InvitationId::from_bytes([0x26; 16]);
        let expiry_now = wall_ms()?;
        let expired = store_a.create_invitation(
            expired_id,
            InvitationSpec {
                issuer: HostedSubject {
                    issuer: issuer.id(),
                    namespace: "people".into(),
                    subject: "owner".into(),
                },
                stream,
                audience: InvitationAudience::Named {
                    presenter: b_node,
                    subject: guest.clone(),
                },
                not_before_ms: expiry_now - 1,
                expires_ms: expiry_now + 50,
                grant_expires_ms: expiry_now + 50,
                max_redemptions: 1,
                history: GrantHistory::All,
            },
            expiry_now,
        )?;
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        let denied = client
            .redeem_invitation_as(
                7,
                expired_id,
                RequestId::from_bytes([0x27; 16]),
                expired.revision,
                None,
            )
            .await
            .err()
            .context("expired invitation allowed redemption")?;
        ensure!(denied.code() == Code::PermissionDenied);
        let untrusted_key = SubjectIssuerKey::generate()?;
        let untrusted = untrusted_key.issuer()?;
        let untrusted_holder = Arc::new(SubjectHolderKey::generate()?);
        let untrusted_assertion = SubjectAssertion::new(
            untrusted.id(),
            "people",
            "guest",
            a_node,
            b_node,
            SubjectPurpose::Sync,
            now - 1_000,
            now + 40_000,
            untrusted_holder.public_key(),
        )?;
        let untrusted_credentials = Arc::new(FederationHostedSubjectCredentials::new(
            &untrusted,
            untrusted_assertion.clone(),
            untrusted_key.sign_assertion(&untrusted_assertion)?,
            untrusted_holder,
        )?);
        let untrusted_client = FederationGrpcSubscriberClient::connect(
            route.clone(),
            Arc::clone(&prepared_b.local),
            Arc::new(PinnedPublisher(a_node)),
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                prepared_b.grpc,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await?;
        let denied = untrusted_client
            .register_subject(8, untrusted_credentials)
            .await
            .err()
            .context("untrusted issuer registered in Guest Session")?;
        ensure!(denied.code() == Code::PermissionDenied);
        let mut grant: SubjectGrant = store_a
            .subject_grant(&guest, b_node, stream)?
            .context("redeemed guest grant missing")?
            .grant;
        grant.enabled = false;
        store_a.set_subject_grant(Some(1), grant)?;
        let denied = client
            .read_as(7, read, stream)
            .await
            .err()
            .context("revoked guest grant remained readable")?;
        ensure!(denied.code() == Code::PermissionDenied);
        ensure!(store_a.peer_authority(b_node)?.is_none());
        store_a.set_peer_authority(b_node, None, false)?;
        let disabled = FederationGrpcSubscriberClient::connect(
            route,
            prepared_b.local,
            Arc::new(PinnedPublisher(a_node)),
            xolotl_federation_grpc::FederationGrpcRuntime::new(
                prepared_b.grpc,
                Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
            )?,
        )
        .await;
        if let Ok(disabled) = disabled {
            ensure!(disabled.register_subject(9, credentials).await.is_err());
        }
        runtime_a.task.abort();
        drop(runtime_a.task.await);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stock_guest_follow_persists_inbox_and_replays_ack_after_restart() -> Result<()> {
        use crate::config::{
            FederationGuestFollowConfig, FederationPeerDialConfig, FederationSubjectIssuerConfig,
            FederationSubjectPurposeConfig,
        };
        use xolotl_federation::{
            FederationGuestStore as _, FederationInvitationStore as _, GrantHistory, HostedSubject,
            InvitationAudience, InvitationId, InvitationSpec, SubjectAssertion, SubjectGrant,
            SubjectHolderKey, SubjectIssuerKey,
        };

        let directory = tempfile::tempdir()?;
        let a_dir = directory.path().join("publisher");
        let b_dir = directory.path().join("guest");
        std::fs::create_dir(&a_dir)?;
        std::fs::create_dir(&b_dir)?;
        let mut a = configured_publisher(&a_dir)?;
        let mut b = configured_publisher(&b_dir)?;
        let a_node = prepare(&a)?.context("publisher disabled")?.node_id();
        let b_node = prepare(&b)?.context("guest disabled")?.node_id();
        let issuer_key = SubjectIssuerKey::generate()?;
        let issuer = issuer_key.issuer()?;
        let holder = SubjectHolderKey::generate()?;
        let guest = HostedSubject {
            issuer: issuer.id(),
            namespace: "people".into(),
            subject: "guest".into(),
        };
        let owner = HostedSubject {
            issuer: issuer.id(),
            namespace: "people".into(),
            subject: "owner".into(),
        };
        a.federation.peers.clear();
        a.federation
            .subject_issuers
            .push(FederationSubjectIssuerConfig {
                issuer: hex_bytes(&issuer.id().as_bytes()),
                namespace: "people".into(),
                presenter: hex_bytes(b_node.as_bytes()),
                purposes: vec![FederationSubjectPurposeConfig::Sync],
            });
        let db_a = xolotl_storage_redb::RedbStore::open_with_history(
            a_dir.join("publisher.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store_a = db_a.federation_store(a_node)?;
        let runtime_a = start(
            prepare(&a)?.context("Guest publisher disabled")?,
            store_a.clone(),
            Some(db_a.federation_state_projection(a_node)?),
            test_boot(db_a.state_backend().into_backend()),
        )
        .await?;
        let stream = StreamRef {
            publisher: a_node,
            id: StreamId::from_bytes([0x44; 16]),
        };
        let publish = |id: u8| {
            store_a.append_published(PublishRequest {
                retry_epoch: store_a.publication_epoch(stream)?,
                stream,
                publish_id: RequestId::from_bytes([id; 16]),
                event_type: EventType::new("guest-test")?,
                schema_revision: SchemaRevision::from_bytes([0x20; 32]),
                event_ref: None,
                payload: Arc::from(vec![id; 8]),
            })
        };
        publish(0x31)?;
        store_a.set_invitation_issuer_authority(&owner, stream, None, true)?;
        let now = wall_ms()?;
        let invitation = InvitationId::from_bytes([0x21; 16]);
        let created = store_a.create_invitation(
            invitation,
            InvitationSpec {
                issuer: owner,
                stream,
                audience: InvitationAudience::Named {
                    presenter: b_node,
                    subject: guest.clone(),
                },
                not_before_ms: now - 1_000,
                expires_ms: now + 50_000,
                grant_expires_ms: now + 40_000,
                max_redemptions: 1,
                history: GrantHistory::All,
            },
            now,
        )?;
        let assertion = SubjectAssertion::new(
            issuer.id(),
            "people",
            "guest",
            a_node,
            b_node,
            SubjectPurpose::Sync,
            now - 1_000,
            now + 40_000,
            holder.public_key(),
        )?;
        b.federation.peers.clear();
        let authorization_digest = online_digest_hex(&a)?;
        b.federation
            .guest_follows
            .push(FederationGuestFollowConfig {
                publisher_node: hex_bytes(a_node.as_bytes()),
                stream_id: hex_bytes(stream.id.as_bytes()),
                dial: FederationPeerDialConfig {
                    uri: format!(
                        "http://{}",
                        runtime_a
                            .address
                            .context("Guest publisher did not listen")?
                    ),
                    server_name: "localhost".into(),
                    trust_root_path: private_file(&b_dir.join("publisher-ca.crt"), CA_CERT)?,
                },
                minimum_online_generation: 1,
                allowed_authorization_digests: vec![authorization_digest],
                generation: 1,
                invitation_id: hex_bytes(&invitation.as_bytes()),
                invitation_revision: created.revision,
                invitation_secret_path: None,
                issuer: hex_bytes(&issuer.id().as_bytes()),
                namespace: guest.namespace.clone(),
                subject: guest.subject.clone(),
                issuer_descriptor_path: private_file(&b_dir.join("issuer.bin"), &issuer.encode())?,
                assertion_path: private_file(&b_dir.join("assertion.bin"), &assertion.encode())?,
                issuer_signature_path: private_file(
                    &b_dir.join("assertion.sig"),
                    &issuer_key.sign_assertion(&assertion)?,
                )?,
                holder_key_path: private_file(
                    &b_dir.join("holder.pk8"),
                    holder.to_pkcs8()?.as_ref(),
                )?,
                max_inbox_records: 8,
                max_inbox_bytes: STOCK_RECORD_BYTES,
            });
        let prepared_b = prepare(&b)?.context("stock Guest follower disabled")?;
        ensure!(prepared_b.needs_guest_follow_store());
        let follow_spec = prepared_b.guest_follows[0].spec.clone();
        let receiver_path = b_dir.join("receiver.redb");
        {
            let db_b = xolotl_storage_redb::RedbStore::open(&receiver_path)?;
            let follower = db_b.guest_follower_store(b_node)?;
            struct RejectingHost {
                attempted: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            }
            impl xolotl_kernel::host::BlockingSpawner for RejectingHost {
                fn spawn(
                    &self,
                    job: xolotl_kernel::host::BlockingJob,
                ) -> Result<(), xolotl_kernel::host::BlockingSpawnError> {
                    drop(job);
                    if let Some(attempted) = self
                        .attempted
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                    {
                        let _attempted = attempted.send(());
                    }
                    Err(xolotl_kernel::host::BlockingSpawnError::Unavailable)
                }
            }
            let (attempted, observed) = tokio::sync::oneshot::channel();
            let rejecting =
                xolotl_kernel::host::HostRuntime::tokio_with_blocking(Arc::new(RejectingHost {
                    attempted: std::sync::Mutex::new(Some(attempted)),
                }));
            let rejected_prepared = prepare(&b)?.context("rejecting Guest follower disabled")?;
            let rejected_tasks = rejected_prepared.start_guest_follows(
                &rejecting,
                db_b.federation_store(b_node)?,
                follower.clone(),
            )?;
            tokio::time::timeout(std::time::Duration::from_secs(5), observed).await??;
            for task in rejected_tasks {
                task.abort();
                drop(task.await);
            }
            rejected_prepared
                .transport_runtime(&rejecting)?
                .shutdown()
                .await;
            let rejected = follower
                .inspect(&follow_spec)
                .err()
                .context("rejected Guest storage stage created a durable row")?;
            ensure!(matches!(rejected, FederationError::NotFound));
            let blocking = Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default());
            let host = xolotl_kernel::host::HostRuntime::tokio_with_blocking(blocking.clone());
            let tasks = prepared_b.start_guest_follows(
                &host,
                db_b.federation_store(b_node)?,
                follower.clone(),
            )?;
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if follower
                        .inspect(&follow_spec)
                        .ok()
                        .and_then(|view| view.cursor)
                        .is_some_and(|position| position.sequence() == 1)
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            })
            .await?;
            ensure!(
                follower
                    .read_inbox(&follow_spec, None, 8, STOCK_RECORD_BYTES)?
                    .records
                    .len()
                    == 1
            );
            ensure!(
                db_b.federation_store(b_node)?
                    .peer_authority(a_node)?
                    .is_none()
            );
            for task in tasks {
                task.abort();
                drop(task.await);
            }
            prepared_b.transport_runtime(&host)?.shutdown().await;
            blocking.close();
            blocking.wait_idle().await;
            db_b.wait_idle().await;
            // Model a crash after Accept commits but before its ACK leaves the
            // host: only the receiver inbox advances to sequence two.
            publish(0x32)?;
            let after = follower.inspect(&follow_spec)?.cursor;
            let second = store_a.read_guest(
                guest.clone(),
                wall_ms()?,
                ReadRequest {
                    authenticated_subscriber: b_node,
                    subscription: follow_spec.subscription,
                    after,
                    max_records: 8,
                    max_bytes: STOCK_RECORD_BYTES,
                },
            )?;
            ensure!(second.records.len() == 1 && second.records[0].sequence() == 2);
            follower.accept_page(&follow_spec, &second)?;
            ensure!(
                store_a
                    .inspect_guest_subscription(
                        guest.clone(),
                        wall_ms()?,
                        InspectSubscriptionRequest {
                            authenticated_subscriber: b_node,
                            subscription: follow_spec.subscription,
                        },
                    )?
                    .acknowledged
                    .is_none_or(|position| position.sequence() < 2)
            );
        }
        {
            let db_b = xolotl_storage_redb::RedbStore::open(&receiver_path)?;
            let follower = db_b.guest_follower_store(b_node)?;
            ensure!(
                follower
                    .inspect(&follow_spec)?
                    .cursor
                    .is_some_and(|cursor| cursor.sequence() == 2)
            );
            let prepared_b = prepare(&b)?.context("restarted Guest follower disabled")?;
            let blocking = Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default());
            let host = xolotl_kernel::host::HostRuntime::tokio_with_blocking(blocking.clone());
            let tasks = prepared_b.start_guest_follows(
                &host,
                db_b.federation_store(b_node)?,
                follower.clone(),
            )?;
            tokio::time::timeout(std::time::Duration::from_secs(20), async {
                loop {
                    if store_a
                        .inspect_guest_subscription(
                            guest.clone(),
                            wall_ms()?,
                            InspectSubscriptionRequest {
                                authenticated_subscriber: b_node,
                                subscription: follow_spec.subscription,
                            },
                        )
                        .ok()
                        .and_then(|view| view.acknowledged)
                        .is_some_and(|position| position.sequence() == 2)
                    {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Ok::<(), anyhow::Error>(())
            })
            .await??;
            let remote = store_a.inspect_guest_subscription(
                guest.clone(),
                wall_ms()?,
                InspectSubscriptionRequest {
                    authenticated_subscriber: b_node,
                    subscription: follow_spec.subscription,
                },
            )?;
            ensure!(
                remote
                    .acknowledged
                    .is_some_and(|position| position.sequence() == 2)
            );
            ensure!(
                follower
                    .read_inbox(&follow_spec, None, 8, STOCK_RECORD_BYTES)?
                    .records
                    .len()
                    == 2
            );
            let mut grant: SubjectGrant = store_a
                .subject_grant(&guest, b_node, stream)?
                .context("Guest grant missing after redemption")?
                .grant;
            grant.enabled = false;
            store_a.set_subject_grant(Some(1), grant)?;
            publish(0x33)?;
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            ensure!(
                follower
                    .inspect(&follow_spec)?
                    .cursor
                    .is_some_and(|position| position.sequence() == 2)
            );
            ensure!(store_a.peer_authority(b_node)?.is_none());
            for task in tasks {
                task.abort();
                drop(task.await);
            }
            prepared_b.transport_runtime(&host)?.shutdown().await;
            blocking.close();
            blocking.wait_idle().await;
            db_b.wait_idle().await;
        }
        runtime_a.task.abort();
        drop(runtime_a.task.await);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_publication_retries_host_capacity_without_losing_its_cursor() -> Result<()> {
        use std::time::Duration;
        use xolotl_kernel::host::{
            BlockingJob, BlockingSpawnError, BlockingSpawner, BlockingTaskError, HostRuntime,
            TokioBlockingSpawner, blocking::dispatch,
        };

        struct PublicationHost {
            inner: Arc<TokioBlockingSpawner>,
            rejected: tokio::sync::Notify,
        }
        impl BlockingSpawner for PublicationHost {
            fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
                let outcome = self.inner.spawn(job);
                if outcome == Err(BlockingSpawnError::AtCapacity) {
                    self.rejected.notify_one();
                }
                outcome
            }
        }

        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let mut prepared = prepare(&config)?.context("publisher was unexpectedly disabled")?;
        prepared.address = None;
        let publication = prepared.policy.publications[0].clone();
        let database = xolotl_storage_redb::RedbStore::open_with_history(
            directory.path().join("periodic.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store = database.federation_store(prepared.node_id())?;
        let projection = database.federation_state_projection(prepared.node_id())?;
        let state = database.state_backend().into_backend();
        let blocking = Arc::new(TokioBlockingSpawner::new(4)?);
        let host = Arc::new(PublicationHost {
            inner: Arc::clone(&blocking),
            rejected: tokio::sync::Notify::new(),
        });
        let boot = Arc::new(Bootstrap::from_kernel(
            xolotl_kernel::KernelBuilder::new(state.clone())
                .with_host_runtime(HostRuntime::tokio_with_blocking(host.clone()))
                .build(),
        ));
        let listener = start(prepared, store.clone(), Some(projection.clone()), boot).await?;
        blocking.wait_idle().await;
        let original = projection.cursor(publication.stream, &publication.prefix)?;
        state
            .write_set(
                &StatePath::parse("state://federation/public/notes/later")?,
                Value::integer(17),
            )
            .await?;
        let high = projection.high_watermark()?;
        let mut releases = Vec::new();
        let mut jobs = Vec::new();
        for _index in 0..4 {
            let (entered, ready) = tokio::sync::oneshot::channel();
            let (release, gate) = std::sync::mpsc::channel();
            jobs.push(dispatch(blocking.as_ref(), move || -> Result<()> {
                let _entered = entered.send(());
                gate.recv_timeout(Duration::from_secs(15))?;
                Ok(())
            })?);
            releases.push(release);
            tokio::time::timeout(Duration::from_secs(5), ready).await??;
        }
        tokio::task::yield_now().await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(5)).await;
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(5), host.rejected.notified()).await?;
        tokio::task::yield_now().await;
        ensure!(
            !listener.task.is_finished(),
            "host capacity terminated State publication"
        );
        ensure!(projection.cursor(publication.stream, &publication.prefix)? == original);
        for release in releases {
            release.send(())?;
        }
        for job in jobs {
            job.await??;
        }
        blocking.wait_idle().await;
        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                if projection.cursor(publication.stream, &publication.prefix)? == Some(high) {
                    return Ok::<(), anyhow::Error>(());
                }
                ensure!(
                    !listener.task.is_finished(),
                    "State publication stopped before recovery"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await??;
        listener.task.abort();
        ensure!(
            listener
                .task
                .await
                .err()
                .is_some_and(|error| error.is_cancelled())
        );
        blocking.close();
        blocking.wait_idle().await;
        let rejected = complete_publication_tick(
            "snapshot offers",
            Err(anyhow::Error::new(BlockingSpawnError::Unavailable).context("offer")),
        )
        .err()
        .context("closed host was ignored")?;
        ensure!(
            rejected.downcast_ref::<BlockingSpawnError>() == Some(&BlockingSpawnError::Unavailable)
        );
        let unknown =
            complete_publication_tick("State history", Err(BlockingTaskError::Cancelled.into()))
                .err()
                .context("indeterminate job was ignored")?;
        ensure!(unknown.downcast_ref::<BlockingTaskError>() == Some(&BlockingTaskError::Cancelled));
        let capacity =
            complete_publication_tick("snapshot offers", Err(FederationError::Capacity.into()))
                .err()
                .context("business capacity was ignored")?;
        ensure!(matches!(
            capacity.downcast_ref::<FederationError>(),
            Some(FederationError::Capacity)
        ));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_state_publication_configuration_enables_publication_without_listener()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut config = configured_publisher(directory.path())?;
        config.server.federation_grpc_addr = None;
        config.federation.peers.clear();
        let prepared = prepare(&config)?.context("local publication was silently disabled")?;
        ensure!(prepared.address.is_none());
        let publication = prepared.policy.publications[0].clone();
        let db = xolotl_storage_redb::RedbStore::open_with_history(
            directory.path().join("local-publication.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store = db.federation_store(prepared.node_id())?;
        let projection = db.federation_state_projection(prepared.node_id())?;
        let state = db.state_backend().into_backend();
        state
            .write_set(
                &StatePath::parse("state://federation/public/notes/entry")?,
                Value::integer(1),
            )
            .await?;
        let high = projection.high_watermark()?;
        let publisher = start(prepared, store, Some(projection.clone()), test_boot(state)).await?;
        publisher.task.abort();
        ensure!(
            publisher
                .task
                .await
                .is_err_and(|error| error.is_cancelled())
        );
        ensure!(projection.cursor(publication.stream, &publication.prefix)? == Some(high));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn local_state_publication_configuration_rejects_missing_prerequisites() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut config = configured_publisher(directory.path())?;
        config.server.federation_grpc_addr = None;
        config.federation.peers.clear();
        config.storage.kind = StorageKind::Memory;
        let error = prepare(&config)
            .err()
            .context("memory publication was ignored")?;
        ensure!(error.to_string() == "federation publisher requires persistent redb storage");
        config.storage.kind = StorageKind::Redb;
        config.storage.state_history = StorageHistoryMode::CurrentOnly;
        let error = prepare(&config)
            .err()
            .context("current-only publication was ignored")?;
        ensure!(
            error.to_string() == "federation State publication requires State history capability"
        );
        config.storage.state_history = StorageHistoryMode::Full;
        let publications = std::mem::take(&mut config.federation.state_history_publications);
        let error = prepare(&config)
            .err()
            .context("stream without source was ignored")?;
        ensure!(
            error.to_string()
                == "every federation stream must have one State publication source or exact retirement"
        );
        config.federation.state_history_publications = publications;
        config.federation.streams.clear();
        let error = prepare(&config)
            .err()
            .context("source without stream was ignored")?;
        ensure!(error.to_string() == "federation publication references undeclared stream");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn oversized_publication_prefix_is_rejected_before_append_and_cursor_effects()
    -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut config = configured_publisher(directory.path())?;
        let prepared = prepare(&config)?.context("publisher was unexpectedly disabled")?;
        let mut publication = prepared.policy.publications[0].clone();
        publication.prefix =
            StatePath::parse(&format!("state://federation/public/{}", "x".repeat(4096)))?;
        config.federation.state_history_publications[0].prefix = publication.prefix.to_string();
        let error = prepare(&config)
            .err()
            .context("oversized prefix passed preparation")?;
        ensure!(matches!(
            error.downcast_ref::<FederationError>(),
            Some(FederationError::Invalid("invalid State publication prefix"))
        ));
        let db = xolotl_storage_redb::RedbStore::open_with_history(
            directory.path().join("prefix-rejection.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store = db.federation_store(prepared.node_id())?;
        let projection = db.federation_state_projection(prepared.node_id())?;
        reconcile_policy(&store, &prepared.policy)?;
        let service = FederationService::new(Arc::new(store.clone()), FederationLimits::default())?;
        let state = db.state_backend().into_backend();
        state
            .write_set(&publication.prefix, Value::integer(1))
            .await?;
        let workers = storage_workers::StorageWorkers::new(
            1,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::new(2)?),
        )?;
        let error = scan_state_history(&workers, &service, &projection, &publication, None)
            .await
            .err()
            .context("oversized prefix was scanned")?;
        ensure!(matches!(
            error.downcast_ref::<FederationError>(),
            Some(FederationError::Invalid("invalid State publication prefix"))
        ));
        ensure!(
            projection
                .cursor(publication.stream, &publication.prefix)?
                .is_none()
        );
        let peer = prepared.policy.peers[0].node;
        let subscription = SubscriptionRef {
            subscriber: peer,
            id: SubscriptionId::from_bytes([0x71; 16]),
        };
        store.open(OpenRequest {
            authenticated_subscriber: peer,
            request_id: RequestId::from_bytes([0x72; 16]),
            subscription,
            stream: publication.stream,
            expected_control_revision: None,
            history: HistoryStart::All,
        })?;
        let page = store.read(ReadRequest {
            authenticated_subscriber: peer,
            subscription,
            after: None,
            max_records: 10,
            max_bytes: STOCK_RECORD_BYTES,
        })?;
        ensure!(page.records.is_empty() && page.head.is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn oversized_state_history_event_is_rejected_before_publication() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let prepared = prepare(&config)?.context("publisher was unexpectedly disabled")?;
        let db = xolotl_storage_redb::RedbStore::open_with_history(
            directory.path().join("oversized.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store = db.federation_store(prepared.node_id())?;
        let projection = db.federation_state_projection(prepared.node_id())?;
        let state = db.state_backend().into_backend();
        state
            .write_set(
                &StatePath::parse("state://federation/public/notes/valid")?,
                Value::integer(1),
            )
            .await?;
        let path = StatePath::parse("state://federation/public/notes/oversized")?;
        state
            .write_set(&path, Value::string("x".repeat(STOCK_RECORD_BYTES + 1)))
            .await?;
        let stream = prepared.policy.publications[0].stream;
        let peer = prepared.policy.peers[0].node;
        let error = start(
            prepared,
            store.clone(),
            Some(projection.clone()),
            test_boot(state),
        )
        .await
        .err()
        .context("oversized State event was published")?;
        ensure!(
            error.root_cause().to_string() == "federation State history event exceeds record limit"
        );
        ensure!(
            projection.cursor(
                stream,
                &StatePath::parse("state://federation/public/notes")?
            )? == None
        );
        let subscription = SubscriptionRef {
            subscriber: peer,
            id: SubscriptionId::from_bytes([0x71; 16]),
        };
        store.open(OpenRequest {
            authenticated_subscriber: peer,
            request_id: RequestId::from_bytes([0x72; 16]),
            subscription,
            stream,
            expected_control_revision: None,
            history: HistoryStart::All,
        })?;
        let page = store.read(ReadRequest {
            authenticated_subscriber: peer,
            subscription,
            after: None,
            max_records: 10,
            max_bytes: STOCK_RECORD_BYTES,
        })?;
        ensure!(page.records.is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_history_replay_is_idempotent_and_catches_later_commits() -> Result<()> {
        use std::{
            sync::atomic::{AtomicUsize, Ordering},
            task::Poll,
        };
        use xolotl_kernel::host::{
            BlockingJob, BlockingSpawnError, BlockingSpawner, TokioBlockingSpawner,
        };

        struct PublicationHost {
            inner: Arc<TokioBlockingSpawner>,
            jobs: AtomicUsize,
            gate: std::sync::Mutex<
                Option<(
                    tokio::sync::oneshot::Sender<()>,
                    std::sync::mpsc::Receiver<()>,
                )>,
            >,
        }
        impl BlockingSpawner for PublicationHost {
            fn spawn(&self, job: BlockingJob) -> Result<(), BlockingSpawnError> {
                let gate = if self.jobs.fetch_add(1, Ordering::SeqCst) == 1 {
                    self.gate
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take()
                } else {
                    None
                };
                self.inner.spawn(Box::new(move || {
                    if let Some((entered, release)) = gate {
                        let _entered = entered.send(());
                        let _released = release.recv_timeout(std::time::Duration::from_secs(5));
                    }
                    job();
                }))
            }
        }
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let prepared = prepare(&config)?.context("publisher was unexpectedly disabled")?;
        let database_path = directory.path().join("history.redb");
        let db = xolotl_storage_redb::RedbStore::open_with_history(
            &database_path,
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store = db.federation_store(prepared.node_id())?;
        let projection = db.federation_state_projection(prepared.node_id())?;
        reconcile_policy(&store, &prepared.policy)?;
        let service = FederationService::new(Arc::new(store.clone()), FederationLimits::default())?;
        let state = db.state_backend().into_backend();
        let path = StatePath::parse("state://federation/public/notes/entry-1")?;
        state.write_set(&path, Value::integer(1)).await?;
        let publication = &prepared.policy.publications[0];
        let blocking = Arc::new(TokioBlockingSpawner::new(2)?);
        let (entered, ready) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let host = Arc::new(PublicationHost {
            inner: Arc::clone(&blocking),
            jobs: AtomicUsize::new(0),
            gate: std::sync::Mutex::new(Some((entered, gate))),
        });
        let gated_workers = storage_workers::StorageWorkers::new(1, host.clone())?;
        let mut scan = Box::pin(scan_state_history(
            &gated_workers,
            &service,
            &projection,
            publication,
            None,
        ));
        tokio::select! {
            outcome = &mut scan => anyhow::bail!("State scan completed before the accepted page gate: {outcome:?}"),
            entered = tokio::time::timeout(std::time::Duration::from_secs(5), ready) => entered??,
        }
        ensure!(host.jobs.load(Ordering::SeqCst) == 2);
        drop(scan);
        drop(service);
        drop(store);
        drop(state);
        drop(projection);
        drop(db);
        blocking.close();
        let mut idle = std::pin::pin!(blocking.wait_idle());
        ensure!(
            std::future::poll_fn(|context| Poll::Ready(idle.as_mut().poll(context)))
                .await
                .is_pending()
        );
        let busy = xolotl_storage_redb::RedbStore::open_with_history(
            &database_path,
            xolotl_storage_redb::RedbHistory::Full,
        )
        .err()
        .context("accepted State page released its database before completion")?;
        ensure!(busy.to_string() == "Database already open. Cannot acquire lock.");
        release.send(())?;
        tokio::time::timeout(std::time::Duration::from_secs(5), idle).await?;
        let db = xolotl_storage_redb::RedbStore::open_with_history(
            &database_path,
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store = db.federation_store(prepared.node_id())?;
        let projection = db.federation_state_projection(prepared.node_id())?;
        let state = db.state_backend().into_backend();
        let service = FederationService::new(Arc::new(store.clone()), FederationLimits::default())?;
        ensure!(
            projection.cursor(publication.stream, &publication.prefix)?
                == Some(projection.high_watermark()?)
        );
        let rejected = scan_state_history(&gated_workers, &service, &projection, publication, None)
            .await
            .err()
            .context("closed State host accepted a scan")?;
        ensure!(
            rejected.downcast_ref::<BlockingSpawnError>() == Some(&BlockingSpawnError::Unavailable)
        );
        let workers =
            storage_workers::StorageWorkers::new(1, Arc::new(TokioBlockingSpawner::new(8)?))?;
        ensure!(scan_state_history(&workers, &service, &projection, publication, None).await? == 0);
        // The cursor skips unchanged history without repeatedly re-reading it.
        ensure!(scan_state_history(&workers, &service, &projection, publication, None).await? == 0);
        let snapshot = projection.high_watermark()?;
        state.write_set(&path, Value::integer(2)).await?;
        let uncommitted = projection
            .high_watermark()?
            .checked_add(1)
            .context("history timestamp exhausted")?;
        let cutoff_error = scan_state_history(
            &workers,
            &service,
            &projection,
            publication,
            Some(uncommitted),
        )
        .await
        .err()
        .context("uncommitted State cutoff was accepted")?;
        ensure!(
            cutoff_error.root_cause().to_string()
                == "federation State projection cutoff exceeds committed history"
        );
        ensure!(projection.cursor(publication.stream, &publication.prefix)? == Some(snapshot));
        ensure!(
            scan_state_history(&workers, &service, &projection, publication, Some(snapshot))
                .await?
                == 0
        );
        ensure!(scan_state_history(&workers, &service, &projection, publication, None).await? == 1);
        reconcile_policy(&store, &prepared.policy)?;

        let peer = prepared.policy.peers[0].node;
        let subscription = SubscriptionRef {
            subscriber: peer,
            id: SubscriptionId::from_bytes([8; 16]),
        };
        service.open(OpenRequest {
            authenticated_subscriber: peer,
            request_id: RequestId::from_bytes([9; 16]),
            subscription,
            stream: publication.stream,
            expected_control_revision: Some(0),
            history: HistoryStart::All,
        })?;
        let page = service.read(ReadRequest {
            authenticated_subscriber: peer,
            subscription,
            after: None,
            max_records: 10,
            max_bytes: 1024 * 1024,
        })?;
        ensure!(page.records.len() == 2);
        ensure!(page.records[0].sequence() == 1 && page.records[1].sequence() == 2);
        drop(page);
        drop(service);
        drop(store);
        drop(state);
        drop(projection);
        drop(db);

        let reopened = xolotl_storage_redb::RedbStore::open_with_history(
            &database_path,
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store = reopened.federation_store(prepared.node_id())?;
        let projection = reopened.federation_state_projection(prepared.node_id())?;
        let service = FederationService::new(Arc::new(store), FederationLimits::default())?;
        ensure!(scan_state_history(&workers, &service, &projection, publication, None).await? == 0);
        let mismatch = projection
            .cursor(
                publication.stream,
                &StatePath::parse("state://federation/public/different")?,
            )
            .err()
            .context("State cursor accepted another prefix")?;
        ensure!(matches!(mismatch, FederationError::Conflict));
        let page = service.read(ReadRequest {
            authenticated_subscriber: peer,
            subscription,
            after: None,
            max_records: 10,
            max_bytes: 1024 * 1024,
        })?;
        ensure!(page.records.len() == 2);
        Ok(())
    }

    #[cfg(unix)]
    struct CountingPublicationHost {
        inner: xolotl_kernel::host::TokioBlockingSpawner,
        jobs: std::sync::atomic::AtomicUsize,
        reject_at: usize,
    }

    impl xolotl_kernel::host::BlockingSpawner for CountingPublicationHost {
        fn spawn(
            &self,
            job: xolotl_kernel::host::BlockingJob,
        ) -> Result<(), xolotl_kernel::host::BlockingSpawnError> {
            let attempt = self.jobs.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if attempt == self.reject_at {
                return Err(xolotl_kernel::host::BlockingSpawnError::AtCapacity);
            }
            self.inner.spawn(job)
        }
    }

    #[cfg(unix)]
    fn configured_rotating_publisher(directory: &Path) -> Result<XolotlConfig> {
        let mut config = configured_publisher(directory)?;
        config
            .federation
            .streams
            .push(crate::config::FederationStreamConfig {
                id: "45".repeat(16),
                export: "notes".into(),
            });
        config.federation.state_history_publications.push(
            crate::config::FederationStateHistoryPublicationConfig {
                prefix: "state://federation/public/other".into(),
                stream_id: "45".repeat(16),
            },
        );
        Ok(config)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stock_publication_recovers_pending_owner_before_rejecting_new_capacity() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let prepared = prepare(&configured_rotating_publisher(directory.path())?)?
            .context("publisher disabled")?;
        let database = directory.path().join("blocked-publications.redb");
        let options = xolotl_storage_redb::RedbOptions {
            history: xolotl_storage_redb::RedbHistory::Full,
            federation_publish_id_limit: std::num::NonZeroUsize::MIN,
            ..xolotl_storage_redb::RedbOptions::default()
        };
        let first = &prepared.policy.publications[0];
        let second = &prepared.policy.publications[1];
        let first_path = StatePath::parse(&format!("{}/item", first.prefix))?;
        let second_path = StatePath::parse(&format!("{}/item", second.prefix))?;
        let workers = storage_workers::StorageWorkers::new(
            1,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::new(1)?),
        )?;
        let (pending_request, pending_digest) = {
            let db = xolotl_storage_redb::RedbStore::open_with_options(&database, options)?;
            let store = db.federation_store(prepared.node_id())?;
            reconcile_policy(&store, &prepared.policy)?;
            let projection = db.federation_state_projection(prepared.node_id())?;
            let state = db.state_backend().into_backend();
            let service = FederationService::new(Arc::new(store), FederationLimits::default())?;
            state.write_set(&first_path, Value::integer(0)).await?;
            ensure!(scan_state_history(&workers, &service, &projection, first, None).await? == 1);
            state.write_set(&second_path, Value::integer(0)).await?;
            let page = projection
                .publication_page(second.stream, &second.prefix, projection.high_watermark()?)?
                .context("pending publication page")?;
            ensure!(page.entries().len() == 1);
            let entry = &page.entries()[0];
            let request = PublishRequest {
                stream: second.stream,
                retry_epoch: page.retry_epoch(),
                publish_id: state_history_publish_id(second.stream, entry),
                event_type: EventType::new("xolotl.state.mutation.v1")?,
                schema_revision: SchemaRevision::from_bytes(
                    *blake3::hash(b"xolotl.federation.state-history-schema.v1\0").as_bytes(),
                ),
                event_ref: None,
                payload: Arc::from(serde_json::to_vec(entry)?),
            };
            let record = service.append_published(request.clone())?;
            state.write_set(&first_path, Value::integer(1)).await?;
            (request, record.digest())
        };
        let db = xolotl_storage_redb::RedbStore::open_with_options(&database, options)?;
        let store = db.federation_store(prepared.node_id())?;
        let projection = db.federation_state_projection(prepared.node_id())?;
        let high = projection.high_watermark()?;
        let service = FederationService::new(Arc::new(store.clone()), FederationLimits::default())?;
        let blocked =
            scan_all_publications(&workers, &service, &projection, std::slice::from_ref(first))
                .await;
        ensure!(matches!(
            blocked
                .as_ref()
                .err()
                .and_then(|error| error.downcast_ref::<FederationError>()),
            Some(FederationError::Capacity)
        ));
        let interrupted_host = Arc::new(CountingPublicationHost {
            inner: xolotl_kernel::host::TokioBlockingSpawner::new(1)?,
            jobs: std::sync::atomic::AtomicUsize::new(0),
            reject_at: 5,
        });
        let interrupted_workers = storage_workers::StorageWorkers::new(1, interrupted_host)?;
        let mut scan = StatePublicationScan::new(prepared.policy.publications.len());
        let interrupted = scan
            .tick(
                &interrupted_workers,
                &service,
                &projection,
                &prepared.policy.publications,
            )
            .await
            .err()
            .context("publication worker interruption was not exercised")?;
        ensure!(matches!(
            interrupted.downcast_ref::<xolotl_kernel::host::BlockingSpawnError>(),
            Some(xolotl_kernel::host::BlockingSpawnError::AtCapacity)
        ));
        while !scan
            .tick(
                &interrupted_workers,
                &service,
                &projection,
                &prepared.policy.publications,
            )
            .await?
        {
            tokio::task::yield_now().await;
        }
        ensure!(matches!(
            service.append_published(pending_request),
            Err(FederationError::Conflict)
        ));
        for (index, publication) in prepared.policy.publications.iter().enumerate() {
            ensure!(projection.cursor(publication.stream, &publication.prefix)? == Some(high));
            let peer = prepared.policy.peers[0].node;
            let identity_byte = u8::try_from(index + 1)?;
            let subscription = SubscriptionRef {
                subscriber: peer,
                id: SubscriptionId::from_bytes([identity_byte; 16]),
            };
            service.open(OpenRequest {
                authenticated_subscriber: peer,
                request_id: RequestId::from_bytes([identity_byte; 16]),
                subscription,
                stream: publication.stream,
                expected_control_revision: None,
                history: HistoryStart::All,
            })?;
            let page = service.read(ReadRequest {
                authenticated_subscriber: peer,
                subscription,
                after: None,
                max_records: 10,
                max_bytes: 1024 * 1024,
            })?;
            ensure!(page.records.len() == if index == 0 { 2 } else { 1 });
            if index == 1 {
                ensure!(page.records[0].digest() == pending_digest);
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stock_publication_settles_competing_prefixes_on_identity_capacity() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let prepared = prepare(&configured_rotating_publisher(directory.path())?)?
            .context("publisher disabled")?;
        let db = xolotl_storage_redb::RedbStore::open_with_options(
            directory.path().join("competing-publications.redb"),
            xolotl_storage_redb::RedbOptions {
                history: xolotl_storage_redb::RedbHistory::Full,
                federation_publish_id_limit: std::num::NonZeroUsize::new(2).context("limit")?,
                ..xolotl_storage_redb::RedbOptions::default()
            },
        )?;
        let store = db.federation_store(prepared.node_id())?;
        reconcile_policy(&store, &prepared.policy)?;
        let projection = db.federation_state_projection(prepared.node_id())?;
        let state = db.state_backend().into_backend();
        for publication in &prepared.policy.publications {
            let target = StatePath::parse(&format!("{}/item", publication.prefix))?;
            for value in 0..2 {
                state.write_set(&target, Value::integer(value)).await?;
            }
        }
        let high = projection.high_watermark()?;
        let pages = prepared
            .policy
            .publications
            .iter()
            .map(|publication| {
                projection
                    .publication_page(publication.stream, &publication.prefix, high)?
                    .context("publication page")
            })
            .collect::<Result<Vec<_>>>()?;
        let service = FederationService::new(Arc::new(store.clone()), FederationLimits::default())?;
        let mut first_requests = Vec::new();
        for (publication, page) in prepared.policy.publications.iter().zip(&pages) {
            ensure!(page.entries().len() == 2);
            let entry = &page.entries()[0];
            let request = PublishRequest {
                stream: publication.stream,
                retry_epoch: page.retry_epoch(),
                publish_id: state_history_publish_id(publication.stream, entry),
                event_type: EventType::new("xolotl.state.mutation.v1")?,
                schema_revision: SchemaRevision::from_bytes(
                    *blake3::hash(b"xolotl.federation.state-history-schema.v1\0").as_bytes(),
                ),
                event_ref: None,
                payload: Arc::from(serde_json::to_vec(entry)?),
            };
            service.append_published(request.clone())?;
            first_requests.push(request);
        }
        let first = &prepared.policy.publications[0];
        let settled = publish_state_history_page(&service, &projection, first, high)?;
        ensure!(settled.published == 1 && settled.next.is_some() && !settled.complete);
        ensure!(projection.cursor(first.stream, &first.prefix)?.is_none());
        ensure!(store.publication_epoch(first.stream)? == 2);
        ensure!(matches!(
            service.append_published(first_requests[0].clone()),
            Err(FederationError::Conflict)
        ));
        let workers = storage_workers::StorageWorkers::new(
            1,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::new(2)?),
        )?;
        scan_all_publications(
            &workers,
            &service,
            &projection,
            &prepared.policy.publications,
        )
        .await?;
        for (publication, request) in prepared.policy.publications.iter().zip(first_requests) {
            ensure!(projection.cursor(publication.stream, &publication.prefix)? == Some(high));
            ensure!(
                store
                    .inspect_publication(publication.stream, 1, request.publish_id)?
                    .is_none()
            );
            ensure!(matches!(
                service.append_published(request),
                Err(FederationError::Conflict)
            ));
        }
        state
            .trim_history_before(high + 1, xolotl_state::StateHistoryTrimLimits::default())
            .await?;
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_publication_rotates_with_bounded_steps_and_a_global_watermark() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let directory = tempfile::tempdir()?;
        let prepared = prepare(&configured_rotating_publisher(directory.path())?)?
            .context("publisher disabled")?;
        let db = xolotl_storage_redb::RedbStore::open_with_history(
            directory.path().join("rotating.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let projection = db.federation_state_projection(prepared.node_id())?;
        let state = db.state_backend().into_backend();
        let busy_path = StatePath::parse("state://federation/public/notes/entry")?;
        let short_path = StatePath::parse("state://federation/public/other/entry")?;
        for value in 0..641 {
            state.write_set(&busy_path, Value::integer(value)).await?;
        }
        state.write_set(&short_path, Value::integer(1)).await?;
        let high = projection.high_watermark()?;
        let store = db.federation_store(prepared.node_id())?;
        reconcile_policy(&store, &prepared.policy)?;
        let service = FederationService::new(Arc::new(store), FederationLimits::default())?;
        let host = Arc::new(CountingPublicationHost {
            inner: xolotl_kernel::host::TokioBlockingSpawner::new(1)?,
            jobs: AtomicUsize::new(0),
            reject_at: 0,
        });
        let workers = storage_workers::StorageWorkers::new(1, host.clone())?;
        let publications = &prepared.policy.publications;
        let mut scan = StatePublicationScan::new(publications.len());
        ensure!(
            !scan
                .tick(&workers, &service, &projection, publications)
                .await?
        );
        ensure!(host.jobs.load(Ordering::SeqCst) == STATE_PUBLICATION_STEPS);
        ensure!(
            projection
                .cursor(publications[0].stream, &publications[0].prefix)?
                .is_none()
        );
        ensure!(projection.cursor(publications[1].stream, &publications[1].prefix)? == Some(high));
        state.write_set(&short_path, Value::integer(2)).await?;
        for _tick in 0..4 {
            let before = host.jobs.load(Ordering::SeqCst);
            let done = scan
                .tick(&workers, &service, &projection, publications)
                .await?;
            ensure!(host.jobs.load(Ordering::SeqCst) - before <= STATE_PUBLICATION_STEPS);
            if done {
                break;
            }
        }
        ensure!(scan.pending.is_empty() && scan.high == Some(high));
        ensure!(projection.cursor(publications[0].stream, &publications[0].prefix)? == Some(high));
        let peer = prepared.policy.peers[0].node;
        let subscription = SubscriptionRef {
            subscriber: peer,
            id: SubscriptionId::from_bytes([0x75; 16]),
        };
        service.open(OpenRequest {
            authenticated_subscriber: peer,
            request_id: RequestId::from_bytes([0x76; 16]),
            subscription,
            stream: publications[1].stream,
            expected_control_revision: None,
            history: HistoryStart::All,
        })?;
        let read = || {
            service.read(ReadRequest {
                authenticated_subscriber: peer,
                subscription,
                after: None,
                max_records: 256,
                max_bytes: 4 * 1024 * 1024,
            })
        };
        ensure!(read()?.records.len() == 1);
        scan_all_publications(&workers, &service, &projection, publications).await?;
        let records = read()?.records;
        ensure!(records.len() == 2 && records[1].sequence() == 2);
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_publication_retires_completed_prefixes_without_spending_tick_steps() -> Result<()>
    {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let directory = tempfile::tempdir()?;
        let mut config = configured_rotating_publisher(directory.path())?;
        for index in 2..=STATE_PUBLICATION_STEPS {
            let stream_id = format!("{:02x}", 0x44 + index).repeat(16);
            config
                .federation
                .streams
                .push(crate::config::FederationStreamConfig {
                    id: stream_id.clone(),
                    export: "notes".into(),
                });
            config.federation.state_history_publications.push(
                crate::config::FederationStateHistoryPublicationConfig {
                    prefix: format!("state://federation/public/other{index}"),
                    stream_id,
                },
            );
        }
        let prepared = prepare(&config)?.context("publisher disabled")?;
        let db = xolotl_storage_redb::RedbStore::open_with_history(
            directory.path().join("completed-slots.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let projection = db.federation_state_projection(prepared.node_id())?;
        let state = db.state_backend().into_backend();
        let path = StatePath::parse("state://federation/public/notes/entry")?;
        for value in 0..2000 {
            state.write_set(&path, Value::integer(value)).await?;
        }
        let high = projection.high_watermark()?;
        let store = db.federation_store(prepared.node_id())?;
        reconcile_policy(&store, &prepared.policy)?;
        let service = FederationService::new(Arc::new(store), FederationLimits::default())?;
        let host = Arc::new(CountingPublicationHost {
            inner: xolotl_kernel::host::TokioBlockingSpawner::new(1)?,
            jobs: AtomicUsize::new(0),
            reject_at: 0,
        });
        let workers = storage_workers::StorageWorkers::new(1, host.clone())?;
        let publications = &prepared.policy.publications;
        let mut scan = StatePublicationScan::new(publications.len());
        for _tick in 0..16 {
            let before = host.jobs.load(Ordering::SeqCst);
            ensure!(
                !scan
                    .tick(&workers, &service, &projection, publications)
                    .await?
            );
            ensure!(host.jobs.load(Ordering::SeqCst) - before <= STATE_PUBLICATION_STEPS);
            if scan.pending.len() == 1 {
                break;
            }
        }
        ensure!(scan.pending.len() == 1 && scan.pending[0].0 == 0);
        for publication in publications.iter().skip(1) {
            ensure!(projection.cursor(publication.stream, &publication.prefix)? == Some(high));
        }
        let StatePublicationProgress::Reading {
            published: before_events,
            ..
        } = &scan.pending[0].1
        else {
            anyhow::bail!("busy prefix stopped reading before other prefixes completed")
        };
        let before_events = *before_events;
        let before_jobs = host.jobs.load(Ordering::SeqCst);
        ensure!(
            !scan
                .tick(&workers, &service, &projection, publications)
                .await?
        );
        ensure!(host.jobs.load(Ordering::SeqCst) - before_jobs == STATE_PUBLICATION_STEPS);
        ensure!(
            matches!(scan.pending[0].1, StatePublicationProgress::Reading { published, .. }
            if published == before_events + STATE_PUBLICATION_STEPS * 128)
        );
        ensure!(
            projection
                .cursor(publications[0].stream, &publications[0].prefix)?
                .is_none()
        );
        for _tick in 0..4 {
            let before = host.jobs.load(Ordering::SeqCst);
            let done = scan
                .tick(&workers, &service, &projection, publications)
                .await?;
            ensure!(host.jobs.load(Ordering::SeqCst) - before <= STATE_PUBLICATION_STEPS);
            if done {
                break;
            }
        }
        ensure!(scan.pending.is_empty() && scan.published == 2000);
        ensure!(projection.cursor(publications[0].stream, &publications[0].prefix)? == Some(high));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn state_publication_capacity_preserves_pages_and_pending_cas() -> Result<()> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use xolotl_kernel::host::BlockingSpawnError;
        for reject_at in [6, 7] {
            let directory = tempfile::tempdir()?;
            let prepared = prepare(&configured_rotating_publisher(directory.path())?)?
                .context("publisher disabled")?;
            let db = xolotl_storage_redb::RedbStore::open_with_history(
                directory.path().join("capacity.redb"),
                xolotl_storage_redb::RedbHistory::Full,
            )?;
            let projection = db.federation_state_projection(prepared.node_id())?;
            let state = db.state_backend().into_backend();
            let busy_path = StatePath::parse("state://federation/public/notes/entry")?;
            for value in 0..385 {
                state.write_set(&busy_path, Value::integer(value)).await?;
            }
            state
                .write_set(
                    &StatePath::parse("state://federation/public/other/entry")?,
                    Value::integer(1),
                )
                .await?;
            let high = projection.high_watermark()?;
            let store = db.federation_store(prepared.node_id())?;
            reconcile_policy(&store, &prepared.policy)?;
            let service = FederationService::new(Arc::new(store), FederationLimits::default())?;
            let host = Arc::new(CountingPublicationHost {
                inner: xolotl_kernel::host::TokioBlockingSpawner::new(1)?,
                jobs: AtomicUsize::new(0),
                reject_at,
            });
            let workers = storage_workers::StorageWorkers::new(1, host.clone())?;
            let publications = &prepared.policy.publications;
            let mut scan = StatePublicationScan::new(publications.len());
            let rejected = scan
                .tick(&workers, &service, &projection, publications)
                .await
                .err()
                .context("capacity rejection was hidden")?;
            ensure!(
                rejected.downcast_ref::<BlockingSpawnError>()
                    == Some(&BlockingSpawnError::AtCapacity)
            );
            ensure!(scan.high == Some(high) && scan.pending.front().map(|work| work.0) == Some(0));
            let busy = &scan
                .pending
                .iter()
                .find(|work| work.0 == 0)
                .context("busy prefix lost after capacity rejection")?
                .1;
            ensure!(matches!(busy, StatePublicationProgress::Reading {
                after: Some(_), published, ..
            } if *published == if reject_at == 6 { 128 } else { 256 }));
            ensure!(scan.pending.iter().all(|work| work.0 != 1));
            ensure!(
                projection.cursor(publications[1].stream, &publications[1].prefix)? == Some(high)
            );
            state.write_set(&busy_path, Value::integer(999)).await?;
            let before = host.jobs.load(Ordering::SeqCst);
            ensure!(
                scan.tick(&workers, &service, &projection, publications)
                    .await?
            );
            ensure!(host.jobs.load(Ordering::SeqCst) - before <= STATE_PUBLICATION_STEPS);
            for publication in publications {
                ensure!(projection.cursor(publication.stream, &publication.prefix)? == Some(high));
            }
            ensure!(
                scan_state_history(&workers, &service, &projection, &publications[0], None).await?
                    == 1
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn state_history_time_index_pages_without_skipping() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let prepared = prepare(&config)?.context("publisher was unexpectedly disabled")?;
        let db = xolotl_storage_redb::RedbStore::open_with_history(
            directory.path().join("time-index.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let projection = db.federation_state_projection(prepared.node_id())?;
        let state = db.state_backend().into_backend();
        let publication = &prepared.policy.publications[0];
        let path = StatePath::parse("state://federation/public/notes/entry")?;
        for value in 0..130 {
            state.write_set(&path, Value::integer(value)).await?;
        }
        state
            .write_set(
                &StatePath::parse("state://federation/public/other/entry")?,
                Value::integer(999),
            )
            .await?;
        let high = projection.high_watermark()?;
        let first = projection.history_page(&publication.prefix, i64::MIN, high, None)?;
        ensure!(first.entries.len() == 128);
        let cursor = first
            .next
            .context("first time-index page has no continuation")?;
        let second = projection.history_page(&publication.prefix, i64::MIN, high, Some(&cursor))?;
        ensure!(second.entries.len() == 2 && second.next.is_none());
        ensure!(
            first.entries.last().context("empty first page")?.at_millis
                < second
                    .entries
                    .first()
                    .context("empty second page")?
                    .at_millis
        );
        let store = db.federation_store(prepared.node_id())?;
        reconcile_policy(&store, &prepared.policy)?;
        let service = FederationService::new(Arc::new(store), FederationLimits::default())?;
        let workers = storage_workers::StorageWorkers::new(
            1,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::new(8)?),
        )?;
        ensure!(
            scan_state_history(&workers, &service, &projection, publication, None).await? == 130
        );
        ensure!(projection.cursor(publication.stream, &publication.prefix)? == Some(high));
        let peer = prepared.policy.peers[0].node;
        let subscription = SubscriptionRef {
            subscriber: peer,
            id: SubscriptionId::from_bytes([0x73; 16]),
        };
        service.open(OpenRequest {
            authenticated_subscriber: peer,
            request_id: RequestId::from_bytes([0x74; 16]),
            subscription,
            stream: publication.stream,
            expected_control_revision: None,
            history: HistoryStart::All,
        })?;
        let published = service.read(ReadRequest {
            authenticated_subscriber: peer,
            subscription,
            after: None,
            max_records: 256,
            max_bytes: 4 * 1024 * 1024,
        })?;
        ensure!(published.records.len() == 130);
        let expected = first.entries.into_iter().chain(second.entries);
        for (index, (record, entry)) in published.records.iter().zip(expected).enumerate() {
            ensure!(record.sequence() == index as u64 + 1);
            ensure!(record.payload() == serde_json::to_vec(&entry)?);
            let xolotl_state::StateEvent::Set {
                path: observed,
                value,
                ..
            } = entry.event
            else {
                anyhow::bail!("published mutation is not Set")
            };
            ensure!(observed == path && value == Value::integer(index as i64));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn startup_policy_revokes_removed_peer_and_rejects_stale_reenable() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let original = prepare(&config)?.context("publisher was unexpectedly disabled")?;
        let db = xolotl_storage_redb::RedbStore::open_with_history(
            directory.path().join("policy.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store = db.federation_store(original.node_id())?;
        reconcile_policy(&store, &original.policy)?;
        let old_peer = original.policy.peers[0].node;
        ensure!(
            store
                .peer_authority(old_peer)?
                .is_some_and(|(_, enabled)| enabled)
        );
        let live_peer = FederationNodeId::from_bytes([0x56; 48]);
        store.set_peer_authority(live_peer, None, true)?;
        ensure!(store.set_peer_authority(old_peer, Some(1), false).is_err());

        let mut changed = config;
        changed.federation.peers[0].node_id = "55".repeat(48);
        let replacement = prepare(&changed)?.context("replacement publisher disabled")?;
        reconcile_policy(&store, &replacement.policy)?;
        ensure!(
            store
                .peer_authority(old_peer)?
                .is_some_and(|(_, enabled)| !enabled)
        );
        ensure!(
            store
                .peer_authority(replacement.policy.peers[0].node)?
                .is_some_and(|(_, enabled)| enabled)
        );
        ensure!(store.peer_authority(live_peer)? == Some((1, true)));
        ensure!(reconcile_policy(&store, &original.policy).is_err());
        ensure!(
            store
                .peer_authority(old_peer)?
                .is_some_and(|(_, enabled)| !enabled)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn startup_policy_revokes_removed_export_and_rejects_stale_reenable() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config = configured_publisher(directory.path())?;
        let original = prepare(&config)?.context("publisher was unexpectedly disabled")?;
        let db = xolotl_storage_redb::RedbStore::open_with_history(
            directory.path().join("export-policy.redb"),
            xolotl_storage_redb::RedbHistory::Full,
        )?;
        let store = db.federation_store(original.node_id())?;
        reconcile_policy(&store, &original.policy)?;
        let peer = original.policy.peers[0].node;
        let export = &original.policy.peers[0].exports[0].name;
        ensure!(
            store
                .export_authority(peer, export)?
                .is_some_and(|(_, access)| access.serve || access.receive)
        );

        let mut changed = config;
        changed.federation.peers[0].exports.clear();
        let replacement = prepare(&changed)?.context("replacement publisher disabled")?;
        reconcile_policy(&store, &replacement.policy)?;
        ensure!(
            store
                .export_authority(peer, export)?
                .is_some_and(|(_, access)| !access.serve && !access.receive)
        );
        ensure!(reconcile_policy(&store, &original.policy).is_err());
        ensure!(
            store
                .export_authority(peer, export)?
                .is_some_and(|(_, access)| !access.serve && !access.receive)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn publisher_rejects_tampered_authorization_and_unsafe_key_file() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let mut config = configured_publisher(directory.path())?;
        let signature_path = config
            .federation
            .online_authorization_signature_path
            .as_ref()
            .context("signature path")?;
        let mut signature = std::fs::read(signature_path)?;
        signature[0] ^= 1;
        std::fs::write(signature_path, signature)?;
        ensure!(prepare(&config).is_err());

        config = configured_publisher(directory.path())?;
        let key_path = config
            .federation
            .online_key_path
            .as_ref()
            .context("key path")?;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o644))?;
        ensure!(prepare(&config).is_err());

        config = configured_publisher(directory.path())?;
        config.federation.state_history_publications[0].prefix = "state://vault".into();
        ensure!(prepare(&config).is_err());
        config.federation.state_history_publications[0].prefix =
            "state://federation/public/notes".into();
        config.storage.state_history = StorageHistoryMode::CurrentOnly;
        ensure!(prepare(&config).is_err());
        Ok(())
    }
}
