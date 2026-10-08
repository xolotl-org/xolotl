use std::{
    io::{self, Cursor, Write as _},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _};
use sha2::{Digest as _, Sha384};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Code, Request, transport::Endpoint};
use xolotl_federation::{
    CallAuthorityRule, CallMethod, CallPath, CallTarget, CloseSubscriptionRequest, Digest,
    EventType, ExportAccess, ExportName, FederationCallStore, FederationError, FederationLimits,
    FederationNodeId, FederationOnlineKey, FederationOnlineKeyAuthorization, FederationRootKey,
    FederationService, FederationSnapshotPublisherStore, FederationStore, FederationSubject,
    HistoryStart, InspectSubscriptionRequest, MemoryFederationCallStore, MemoryFederationStore,
    OpenRequest, PrepareCallRequest, PublishRequest, ReadRequest, RequestId, RootSignaturePurpose,
    SchemaRevision, SnapshotContentSource, SnapshotId, SnapshotOffer, SnapshotOfferRequest,
    SnapshotPublicationProof, StreamId, StreamRef, StreamSpec, SubscriptionId, SubscriptionRef,
    VerifiedFederationPeerProof,
};
use xolotl_federation_grpc::{
    FederationGrpcPublisherServer, FederationGrpcPublisherSession, FederationGrpcSubscriberClient,
    FederationLocalCredentials, FederationPeerPolicy, FederationSubscriberServices,
    FederationTlsChannel,
    config::{FederationGrpcConfig, PeerDialConfig},
    federation_tls_incoming,
};
use xolotl_proto::xolotl::v1::federation as pb;
use xolotl_storage_redb::{RedbFederationStore, RedbStore};

#[path = "publisher/snapshot_handoff.rs"]
mod snapshot_handoff;

const CERT: &[u8] = include_bytes!("../../xolotl-daemon/tests/fixtures/ml-dsa-65-cert.pem");
const KEY: &[u8] = include_bytes!("../../xolotl-daemon/tests/fixtures/ml-dsa-65-key.pem");
const CA: &[u8] = include_bytes!("../../xolotl-daemon/tests/fixtures/ml-dsa-65-ca-cert.pem");

struct Policy;

impl FederationPeerPolicy for Policy {
    fn decision_clock(
        &self,
    ) -> Result<Arc<dyn xolotl_federation::FederationObjectClock>, tonic::Status> {
        Ok(Arc::new(|| Ok(150)))
    }

    fn current_time_ms(&self) -> Result<u64, tonic::Status> {
        Ok(150)
    }

    fn check_current_peer(
        &self,
        _proof: VerifiedFederationPeerProof,
        _now_ms: u64,
    ) -> Result<(), tonic::Status> {
        Ok(())
    }
}

fn identity() -> Result<Arc<FederationLocalCredentials>> {
    let root_key = FederationRootKey::generate()?;
    let root = root_key.root()?;
    let online_key = FederationOnlineKey::generate()?;
    let authorization =
        FederationOnlineKeyAuthorization::new(online_key.public_key(), 1, 100, 200)?;
    let signature = root_key.sign(
        RootSignaturePurpose::OnlineKeyAuthorization,
        &authorization.encode(),
    )?;
    Ok(Arc::new(FederationLocalCredentials::new(
        root,
        authorization,
        signature,
        online_key,
    )?))
}

fn tls_configs() -> Result<(Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>)> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        )
    });
    let provider = Arc::new(provider);
    let certificates =
        CertificateDer::pem_reader_iter(&mut Cursor::new(CERT)).collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_reader(&mut Cursor::new(KEY))?;
    let mut server = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certificates, key)?;
    server.alpn_protocols = vec![b"h2".to_vec()];
    server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    server.send_tls13_tickets = 0;
    server.max_tls13_tickets = 0;
    server.max_early_data_size = 0;
    server.send_half_rtt_data = false;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from_pem_reader(&mut Cursor::new(CA))?)?;
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    client.enable_early_data = false;
    Ok((Arc::new(server), Arc::new(client)))
}

fn local_service(node: FederationNodeId) -> Result<FederationService> {
    Ok(FederationService::new(
        Arc::new(MemoryFederationStore::new(node)),
        FederationLimits {
            max_record_bytes: FederationGrpcConfig::default().max_batch_bytes,
            ..FederationLimits::default()
        },
    )?)
}

fn open(subscriber: FederationNodeId, publisher: FederationNodeId) -> pb::SyncFrame {
    pb::SyncFrame {
        body: Some(pb::sync_frame::Body::Open(pb::Open {
            request: 1,
            request_id: vec![7; 16],
            subscription: Some(pb::SubscriptionRef {
                subscriber: subscriber.as_bytes().to_vec(),
                id: vec![4; 16],
            }),
            stream: Some(pb::StreamRef {
                publisher: publisher.as_bytes().to_vec(),
                id: vec![3; 16],
            }),
            expected_control_revision: None,
            history_mode: pb::HistoryMode::All as i32,
            history_after: None,
            context_id: 0,
            holder_request_signature: Vec::new(),
        })),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_hybrid_tls_grpc_stream_proves_peer_and_serves_open() -> Result<()> {
    let config = FederationGrpcConfig {
        max_sessions: 1,
        max_blocking_verifications: 1,
        hello_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        ..FederationGrpcConfig::default()
    };
    let server_identity = identity()?;
    let client_identity = identity()?;
    let server_node = server_identity.node_id();
    let client_node = client_identity.node_id();
    let server_service = local_service(server_node)?;
    server_service.set_peer_authority(client_node, None, true)?;
    server_service.set_peer_admission(
        client_node,
        None,
        xolotl_federation::PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![client_identity.authorization_digest()],
        },
    )?;
    server_service.set_export_authority(
        client_node,
        ExportName::new("friends")?,
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    server_service.declare_stream(StreamSpec {
        stream: StreamRef {
            publisher: server_node,
            id: StreamId::from_bytes([3; 16]),
        },
        export: ExportName::new("friends")?,
    })?;
    let listener_runtime = xolotl_federation_grpc::FederationGrpcRuntime::new(
        config,
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?;
    let server = FederationGrpcPublisherServer::new(
        server_service,
        server_identity,
        Arc::new(Policy),
        listener_runtime.clone(),
    )?;
    let (server_tls, client_tls) = tls_configs()?;
    let mut unsafe_tls = (*server_tls).clone();
    unsafe_tls.max_early_data_size = 1;
    ensure!(
        federation_tls_incoming(
            futures_util::stream::empty::<io::Result<tokio::io::DuplexStream>>(),
            Arc::new(unsafe_tls),
            listener_runtime.clone(),
        )
        .is_err()
    );
    let second_connector = tokio_rustls::TlsConnector::from(Arc::clone(&client_tls));
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let incoming = federation_tls_incoming(
        TcpListenerStream::new(listener),
        server_tls,
        listener_runtime.clone(),
    )?;
    let (stop_tx, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(server.tonic_service())
            .serve_with_incoming_shutdown(incoming, async {
                drop(stop_rx.await);
            })
            .await
    });

    let (facts_tx, mut facts_rx) = mpsc::channel(1);
    let connector = tokio_rustls::TlsConnector::from(client_tls);
    let client_channel = Endpoint::from_shared(format!("http://localhost:{}", addr.port()))?
        .connect_with_connector(tower::service_fn(move |_uri| {
            let connector = connector.clone();
            let facts_tx = facts_tx.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(addr).await?;
                let tls = connector
                    .connect(
                        ServerName::try_from("localhost").map_err(io::Error::other)?,
                        tcp,
                    )
                    .await?;
                let facts = FederationTlsChannel::from_client_tls(tls.get_ref().1, server_node)
                    .map_err(io::Error::other)?;
                facts_tx.send(facts).await.map_err(io::Error::other)?;
                Ok::<_, io::Error>(TokioIo::new(tls))
            }
        }))
        .await?;
    let facts = facts_rx
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("missing TLS facts"))?;
    let mut client = pb::federation_service_client::FederationServiceClient::new(client_channel);
    let (send, receive) = mpsc::channel(4);
    let response = client.session(ReceiverStream::new(receive)).await?;
    let mut inbound = response.into_inner();
    let mut client_admission = FederationGrpcPublisherSession::new(
        facts,
        Arc::clone(&client_identity),
        Arc::new(Policy),
        local_service(client_node)?,
        config,
    )?;
    send.send(client_admission.initial_frame()?).await?;
    let server_hello = inbound
        .message()
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing Hello"))?;
    let client_auth = client_admission
        .receive(server_hello)?
        .ok_or_else(|| anyhow::anyhow!("missing Authenticate"))?;
    send.send(client_auth).await?;
    let server_auth = inbound
        .message()
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing Authenticate"))?;
    ensure!(client_admission.receive(server_auth)?.is_none());

    send.send(open(client_node, server_node)).await?;
    let opened = inbound
        .message()
        .await?
        .ok_or_else(|| anyhow::anyhow!("missing Opened"))?;
    ensure!(matches!(opened.body, Some(pb::sync_frame::Body::Opened(_))));

    let second_tcp = tokio::net::TcpStream::connect(addr).await?;
    let second_handshake = tokio::time::timeout(
        Duration::from_secs(2),
        second_connector.connect(ServerName::try_from("localhost")?, second_tcp),
    )
    .await?;
    ensure!(second_handshake.is_err(), "connection cap was not enforced");

    send.send(pb::SyncFrame {
        body: Some(pb::sync_frame::Body::Failure(pb::SyncFailure {
            request: 9,
            code: pb::FailureCode::Invalid as i32,
            message: "x".repeat(config.max_frame_bytes),
            commit_verdict: pb::CommitVerdict::Unspecified as i32,
        })),
    })
    .await?;
    let too_large = inbound
        .message()
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("oversize frame accepted"))?;
    ensure!(too_large.code() == Code::OutOfRange);

    drop(send);
    drop(client);
    drop(inbound);
    stop_tx
        .send(())
        .map_err(|_sent| anyhow::anyhow!("server stopped early"))?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    Ok(())
}

struct SnapshotFileSource {
    path: PathBuf,
    publisher: RedbFederationStore,
    subscriber: FederationNodeId,
    revoke_on_read: Arc<AtomicBool>,
}

impl SnapshotContentSource for SnapshotFileSource {
    fn read_snapshot_chunk(
        &self,
        offer: &SnapshotOffer,
        offset: u64,
        bytes: usize,
    ) -> Result<Arc<[u8]>, FederationError> {
        let content = std::fs::read(&self.path)
            .map_err(|error| FederationError::Storage(error.to_string()))?;
        if content.len() as u64 != offer.manifest.content_bytes
            || Digest::from_bytes(Sha384::digest(&content).into()) != offer.manifest.content_digest
        {
            return Err(FederationError::Conflict);
        }
        let start = usize::try_from(offset).map_err(|_error| FederationError::Capacity)?;
        let end = start.checked_add(bytes).ok_or(FederationError::Capacity)?;
        let chunk = Arc::from(content.get(start..end).ok_or(FederationError::Conflict)?);
        if self.revoke_on_read.swap(false, Ordering::SeqCst) {
            self.publisher.set_export_authority(
                self.subscriber,
                ExportName::new("snapshot")?,
                Some(1),
                ExportAccess::default(),
            )?;
        }
        Ok(chunk)
    }
}

async fn start_snapshot_peer(
    publisher: RedbFederationStore,
    source: Arc<SnapshotFileSource>,
    server_identity: Arc<FederationLocalCredentials>,
    client_identity: Arc<FederationLocalCredentials>,
    config: FederationGrpcConfig,
) -> Result<(
    FederationGrpcSubscriberClient,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<Result<()>>,
    [xolotl_federation_grpc::FederationGrpcRuntime; 2],
    Arc<xolotl_kernel::host::TokioBlockingSpawner>,
)> {
    let blocking = Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default());
    let server_node = server_identity.node_id();
    let service = FederationService::new(
        Arc::new(publisher.clone()),
        FederationLimits {
            max_record_bytes: config.max_batch_bytes,
            ..FederationLimits::default()
        },
    )?;
    let listener_runtime =
        xolotl_federation_grpc::FederationGrpcRuntime::new(config, blocking.clone())?;
    let server = FederationGrpcPublisherServer::new(
        service,
        server_identity,
        Arc::new(Policy),
        listener_runtime.clone(),
    )?
    .with_snapshot_publisher(Arc::new(publisher), source)?;
    let (server_tls, _) = tls_configs()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let incoming = federation_tls_incoming(
        TcpListenerStream::new(listener),
        server_tls,
        listener_runtime.clone(),
    )?;
    let (stop_tx, stop_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(server.tonic_service())
            .serve_with_incoming_shutdown(incoming, async {
                drop(stop_rx.await);
            })
            .await?;
        Ok(())
    });
    let client_runtime =
        xolotl_federation_grpc::FederationGrpcRuntime::new(config, blocking.clone())?;
    let client = FederationGrpcSubscriberClient::connect(
        PeerDialConfig {
            uri: format!("http://localhost:{}", address.port()),
            expected_peer: server_node,
            server_name: "localhost".to_owned(),
            peer_trust_root_pem: CA.to_vec(),
            client_certificate_pem: CERT.to_vec(),
            client_key_pem: KEY.to_vec(),
        },
        Arc::clone(&client_identity),
        Arc::new(Policy),
        client_runtime.clone(),
    )
    .await?;
    Ok((
        client,
        stop_tx,
        task,
        [listener_runtime, client_runtime],
        blocking,
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_offer_and_chunks_survive_tls_session_and_store_restart_and_recheck_revocation()
-> Result<()> {
    let config = FederationGrpcConfig {
        max_sessions: 1,
        max_blocking_verifications: 1,
        hello_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        ..FederationGrpcConfig::default()
    };
    let server_identity = identity()?;
    let client_identity = identity()?;
    let server_node = server_identity.node_id();
    let client_node = client_identity.node_id();
    let stream = StreamRef {
        publisher: server_node,
        id: StreamId::from_bytes([90; 16]),
    };
    let subscription = SubscriptionRef {
        subscriber: client_node,
        id: SubscriptionId::from_bytes([91; 16]),
    };
    let directory = tempfile::tempdir()?;
    let publisher_path = directory.path().join("publisher.redb");
    let content_path = directory.path().join("application.snapshot");
    let bytes = b"durable application snapshot across a restarted TLS Session";
    let mut content = std::fs::File::create(&content_path)?;
    content.write_all(bytes)?;
    content.sync_all()?;
    drop(content);

    let db = RedbStore::open(&publisher_path)?;
    let publisher = db.federation_store(server_node)?;
    publisher.set_peer_authority(client_node, None, true)?;
    publisher.set_peer_admission(
        client_node,
        None,
        xolotl_federation::PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![client_identity.authorization_digest()],
        },
    )?;
    publisher.set_export_authority(
        client_node,
        ExportName::new("snapshot")?,
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    publisher.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("snapshot")?,
    })?;
    publisher.open(OpenRequest {
        authenticated_subscriber: client_node,
        request_id: RequestId::from_bytes([92; 16]),
        subscription,
        stream,
        expected_control_revision: Some(0),
        history: HistoryStart::All,
    })?;
    let record = publisher.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([93; 16]),
        event_type: EventType::new("snapshot-fixture")?,
        schema_revision: SchemaRevision::from_bytes([94; 32]),
        event_ref: None,
        payload: Arc::from(b"before snapshot".as_slice()),
    })?;
    let offer = publisher.publish_snapshot_offer(SnapshotOfferRequest {
        authenticated_subscriber: client_node,
        subscription,
        proof: SnapshotPublicationProof {
            snapshot_id: SnapshotId::from_bytes([95; 16]),
            stream,
            position: record.position(),
            schema_revision: SchemaRevision::from_bytes([96; 32]),
            content_digest: Digest::from_bytes(Sha384::digest(bytes).into()),
            content_bytes: bytes.len() as u64,
            publication_digest: Digest::from_bytes(
                Sha384::digest(b"test publication proof").into(),
            ),
        },
    })?;
    let revoke_on_read = Arc::new(AtomicBool::new(false));
    let source = Arc::new(SnapshotFileSource {
        path: content_path.clone(),
        publisher: publisher.clone(),
        subscriber: client_node,
        revoke_on_read: Arc::clone(&revoke_on_read),
    });
    let source_lifetime = Arc::downgrade(&source);
    let (client, stop, task, runtimes, blocking) = start_snapshot_peer(
        publisher.clone(),
        source.clone(),
        Arc::clone(&server_identity),
        Arc::clone(&client_identity),
        config,
    )
    .await?;
    ensure!(client.inspect_snapshot(subscription).await? == offer);
    let first = client.read_snapshot(offer.clone(), 0, 7).await?;
    ensure!(first.offset == 0 && first.bytes.as_ref() == &bytes[..7] && !first.complete);
    for runtime in &runtimes {
        runtime.close();
    }
    drop(client);
    stop.send(())
        .map_err(|_sent| anyhow::anyhow!("server stopped early"))?;
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    for runtime in &runtimes {
        runtime.shutdown().await;
    }
    blocking.close();
    blocking.wait_idle().await;
    drop(source);
    drop(publisher);
    drop(db);
    ensure!(
        source_lifetime.upgrade().is_none(),
        "snapshot Session retained the publisher after shutdown"
    );

    let db = RedbStore::open(&publisher_path)?;
    let publisher = db.federation_store(server_node)?;
    ensure!(publisher.snapshot_offer(client_node, subscription)? == Some(offer.clone()));
    let source = Arc::new(SnapshotFileSource {
        path: content_path,
        publisher: publisher.clone(),
        subscriber: client_node,
        revoke_on_read: Arc::clone(&revoke_on_read),
    });
    let (client, stop, task, runtimes, blocking) = start_snapshot_peer(
        publisher.clone(),
        source,
        server_identity,
        client_identity,
        config,
    )
    .await?;
    ensure!(client.inspect_snapshot(subscription).await? == offer);
    let mut wrong_offer = offer.clone();
    wrong_offer.manifest.content_digest = Digest::from_bytes([97; 48]);
    let rejected = client
        .read_snapshot(wrong_offer, 0, 7)
        .await
        .err()
        .context("changed snapshot offer was accepted")?;
    ensure!(rejected.code() == Code::FailedPrecondition);
    let mut received = first.bytes.as_ref().to_vec();
    while received.len() < bytes.len() {
        let chunk = client
            .read_snapshot(offer.clone(), received.len() as u64, 7)
            .await?;
        received.extend_from_slice(&chunk.bytes);
        ensure!(chunk.complete == (received.len() == bytes.len()));
    }
    ensure!(received == bytes);
    revoke_on_read.store(true, Ordering::SeqCst);
    let denied = client
        .read_snapshot(offer.clone(), 0, 7)
        .await
        .err()
        .context("snapshot read succeeded after revocation")?;
    ensure!(denied.code() == Code::PermissionDenied);
    let denied = client
        .inspect_snapshot(subscription)
        .await
        .err()
        .context("snapshot inspection succeeded after revocation")?;
    ensure!(denied.code() == Code::PermissionDenied);
    for runtime in &runtimes {
        runtime.close();
    }
    drop(client);
    stop.send(())
        .map_err(|_sent| anyhow::anyhow!("server stopped early"))?;
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    for runtime in &runtimes {
        runtime.shutdown().await;
    }
    blocking.close();
    blocking.wait_idle().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_dialer_can_publish_snapshot_on_reverse_session() -> Result<()> {
    let config = FederationGrpcConfig {
        max_sessions: 1,
        max_blocking_verifications: 1,
        hello_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        ..FederationGrpcConfig::default()
    };
    let server_identity = identity()?;
    let dialer_identity = identity()?;
    let server_node = server_identity.node_id();
    let dialer_node = dialer_identity.node_id();
    let stream = StreamRef {
        publisher: dialer_node,
        id: StreamId::from_bytes([101; 16]),
    };
    let subscription = SubscriptionRef {
        subscriber: server_node,
        id: SubscriptionId::from_bytes([102; 16]),
    };
    let directory = tempfile::tempdir()?;
    let content_path = directory.path().join("reverse.snapshot");
    let bytes = b"dialer-published snapshot";
    let mut content = std::fs::File::create(&content_path)?;
    content.write_all(bytes)?;
    content.sync_all()?;
    drop(content);
    let db = RedbStore::open(directory.path().join("dialer.redb"))?;
    let publisher = db.federation_store(dialer_node)?;
    publisher.set_peer_authority(server_node, None, true)?;
    publisher.set_peer_admission(
        server_node,
        None,
        xolotl_federation::PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![server_identity.authorization_digest()],
        },
    )?;
    publisher.set_export_authority(
        server_node,
        ExportName::new("snapshot")?,
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    publisher.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("snapshot")?,
    })?;
    publisher.open(OpenRequest {
        authenticated_subscriber: server_node,
        request_id: RequestId::from_bytes([103; 16]),
        subscription,
        stream,
        expected_control_revision: Some(0),
        history: HistoryStart::All,
    })?;
    let record = publisher.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([104; 16]),
        event_type: EventType::new("reverse-snapshot")?,
        schema_revision: SchemaRevision::from_bytes([105; 32]),
        event_ref: None,
        payload: Arc::from(b"before snapshot".as_slice()),
    })?;
    let offer = publisher.publish_snapshot_offer(SnapshotOfferRequest {
        authenticated_subscriber: server_node,
        subscription,
        proof: SnapshotPublicationProof {
            snapshot_id: SnapshotId::from_bytes([106; 16]),
            stream,
            position: record.position(),
            schema_revision: SchemaRevision::from_bytes([107; 32]),
            content_digest: Digest::from_bytes(Sha384::digest(bytes).into()),
            content_bytes: bytes.len() as u64,
            publication_digest: Digest::from_bytes(Sha384::digest(b"reverse publication").into()),
        },
    })?;

    let subscriber = local_service(server_node)?;
    subscriber.set_peer_authority(dialer_node, None, true)?;
    subscriber.set_peer_admission(
        dialer_node,
        None,
        xolotl_federation::PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![dialer_identity.authorization_digest()],
        },
    )?;
    let listener_runtime = xolotl_federation_grpc::FederationGrpcRuntime::new(
        config,
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?;
    let server = FederationGrpcPublisherServer::new(
        subscriber,
        server_identity,
        Arc::new(Policy),
        listener_runtime.clone(),
    )?;
    let server_access = server.clone();
    let (server_tls, _) = tls_configs()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let incoming = federation_tls_incoming(
        TcpListenerStream::new(listener),
        server_tls,
        listener_runtime.clone(),
    )?;
    let (stop, stop_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(server.tonic_service())
            .serve_with_incoming_shutdown(incoming, async {
                drop(stop_rx.await);
            })
            .await
    });
    let source = Arc::new(SnapshotFileSource {
        path: content_path,
        publisher: publisher.clone(),
        subscriber: server_node,
        revoke_on_read: Arc::new(AtomicBool::new(false)),
    });
    let dialer = FederationGrpcSubscriberClient::connect_with_snapshot_services(
        PeerDialConfig {
            uri: format!("http://localhost:{}", address.port()),
            expected_peer: server_node,
            server_name: "localhost".to_owned(),
            peer_trust_root_pem: CA.to_vec(),
            client_certificate_pem: CERT.to_vec(),
            client_key_pem: KEY.to_vec(),
        },
        dialer_identity,
        Arc::new(Policy),
        xolotl_federation_grpc::FederationGrpcRuntime::new(
            config,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
        )?,
        FederationSubscriberServices {
            service: FederationService::new(
                Arc::new(publisher.clone()),
                FederationLimits::default(),
            )?,
            call_store: None,
            call_invoker: None,
            object_reader: None,
        },
        Arc::new(publisher),
        source,
    )
    .await?;
    let reverse = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(handle) = server_access.connected_peer(
                dialer_node,
                xolotl_federation_grpc::ServedCapability::Snapshot,
            ) {
                break handle;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    ensure!(reverse.inspect_snapshot(subscription).await? == offer);
    let chunk = reverse.read_snapshot(offer, 0, bytes.len()).await?;
    ensure!(chunk.complete && chunk.bytes.as_ref() == bytes);
    drop(reverse);
    drop(dialer);
    stop.send(())
        .map_err(|_sent| anyhow::anyhow!("server stopped early"))?;
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plaintext_and_claimed_exporter_metadata_cannot_create_connection_evidence() -> Result<()> {
    let identity = identity()?;
    let listener_runtime = xolotl_federation_grpc::FederationGrpcRuntime::new(
        FederationGrpcConfig::default(),
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?;
    let server = FederationGrpcPublisherServer::new(
        local_service(identity.node_id())?,
        identity,
        Arc::new(Policy),
        listener_runtime.clone(),
    )?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (stop_tx, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(server.tonic_service())
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                drop(stop_rx.await);
            })
            .await
    });
    let mut client =
        pb::federation_service_client::FederationServiceClient::connect(format!("http://{addr}"))
            .await?;
    let (_send, receive) = mpsc::channel(1);
    let mut request = Request::new(ReceiverStream::new(receive));
    request
        .metadata_mut()
        .insert("x-federation-exporter", "claimed-channel-binding".parse()?);
    let status = client
        .session(request)
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("plaintext federation RPC was admitted"))?;
    ensure!(status.code() == Code::Unauthenticated);
    drop(client);
    stop_tx
        .send(())
        .map_err(|_sent| anyhow::anyhow!("server stopped early"))?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscriber_dials_real_hybrid_tls_and_accepts_before_ack() -> Result<()> {
    let config = FederationGrpcConfig {
        hello_timeout: Duration::from_secs(10),
        response_timeout: Duration::from_secs(10),
        ..FederationGrpcConfig::default()
    };
    let server_identity = identity()?;
    let client_identity = identity()?;
    let server_node = server_identity.node_id();
    let client_node = client_identity.node_id();
    let publisher = local_service(server_node)?;
    let subscriber = local_service(client_node)?;
    let export = ExportName::new("friends")?;
    let stream = StreamRef {
        publisher: server_node,
        id: StreamId::from_bytes([3; 16]),
    };
    let subscription = SubscriptionRef {
        subscriber: client_node,
        id: SubscriptionId::from_bytes([4; 16]),
    };
    let reverse_stream = StreamRef {
        publisher: client_node,
        id: StreamId::from_bytes([13; 16]),
    };
    let reverse_subscription = SubscriptionRef {
        subscriber: server_node,
        id: SubscriptionId::from_bytes([14; 16]),
    };
    publisher.set_peer_authority(client_node, None, true)?;
    publisher.set_peer_admission(
        client_node,
        None,
        xolotl_federation::PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![client_identity.authorization_digest()],
        },
    )?;
    publisher.set_export_authority(
        client_node,
        export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    publisher.declare_stream(StreamSpec {
        stream,
        export: export.clone(),
    })?;
    publisher.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([5; 16]),
        event_type: EventType::new("created")?,
        schema_revision: SchemaRevision::from_bytes([6; 32]),
        event_ref: None,
        payload: Arc::from(b"one".as_slice()),
    })?;
    publisher.set_export_authority(
        client_node,
        ExportName::new("reverse")?,
        None,
        ExportAccess {
            serve: false,
            receive: true,
        },
    )?;
    subscriber.set_peer_authority(server_node, None, true)?;
    subscriber.set_peer_admission(
        server_node,
        None,
        xolotl_federation::PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![server_identity.authorization_digest()],
        },
    )?;
    subscriber.set_export_authority(
        server_node,
        export,
        None,
        ExportAccess {
            serve: false,
            receive: true,
        },
    )?;
    subscriber.set_export_authority(
        server_node,
        ExportName::new("reverse")?,
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    subscriber.declare_stream(StreamSpec {
        stream: reverse_stream,
        export: ExportName::new("reverse")?,
    })?;
    subscriber.append_published(PublishRequest {
        retry_epoch: 1,
        stream: reverse_stream,
        publish_id: RequestId::from_bytes([15; 16]),
        event_type: EventType::new("created")?,
        schema_revision: SchemaRevision::from_bytes([6; 32]),
        event_ref: None,
        payload: Arc::from(b"reverse".as_slice()),
    })?;

    let call_store = Arc::new(MemoryFederationCallStore::new(server_node));
    let call_target = CallTarget {
        export: ExportName::new("actions")?,
        path: CallPath::new("/timer")?,
        method: CallMethod::new("start")?,
        contract_digest: [31; 32],
    };
    call_store.set_call_authority(
        None,
        CallAuthorityRule {
            subject: FederationSubject::Node(client_node),
            presenter: client_node,
            target: call_target.clone(),
            enabled: true,
            expires_ms: 190,
            max_input_bytes: 1024,
            max_prepare_window_ms: 20,
            max_result_retention_ms: 100,
        },
    )?;
    let listener_runtime = xolotl_federation_grpc::FederationGrpcRuntime::new(
        config,
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?;
    let server = FederationGrpcPublisherServer::new(
        publisher.clone(),
        server_identity,
        Arc::new(Policy),
        listener_runtime.clone(),
    )?
    .with_call_store(call_store)?;
    let server_access = server.clone();
    let (server_tls, _) = tls_configs()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let incoming = federation_tls_incoming(
        TcpListenerStream::new(listener),
        server_tls,
        listener_runtime.clone(),
    )?;
    let (stop_tx, stop_rx) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(server.tonic_service())
            .serve_with_incoming_shutdown(incoming, async {
                drop(stop_rx.await);
            })
            .await
    });
    let client = FederationGrpcSubscriberClient::connect_bidirectional(
        PeerDialConfig {
            uri: format!("http://localhost:{}", address.port()),
            expected_peer: server_node,
            server_name: "localhost".to_owned(),
            peer_trust_root_pem: CA.to_vec(),
            client_certificate_pem: CERT.to_vec(),
            client_key_pem: KEY.to_vec(),
        },
        Arc::clone(&client_identity),
        Arc::new(Policy),
        xolotl_federation_grpc::FederationGrpcRuntime::new(
            config,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
        )?,
        subscriber.clone(),
        None,
    )
    .await?;
    ensure!(client.peer_node() == server_node);
    let input = Arc::<[u8]>::from(b"timer".as_slice());
    let origin_request_id = RequestId::from_bytes([21; 16]);
    let unavailable = client
        .prepare_call_as(
            0,
            PrepareCallRequest {
                authenticated_origin: client_node,
                subject: FederationSubject::Node(client_node),
                origin_request_id,
                target: call_target,
                input_digest: Digest::from_bytes(Sha384::digest(&input).into()),
                input_bytes: input.len() as u64,
                prepare_deadline_ms: 170,
                execution_deadline_ms: 180,
                result_retention_ms: 50,
            },
        )
        .await
        .err()
        .ok_or_else(|| anyhow::anyhow!("Prepare reserved work without Kernel bridge"))?;
    ensure!(unavailable.code() == Code::Unavailable);
    let ordinary_runtime = xolotl_federation_grpc::FederationGrpcRuntime::new(
        config,
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?;
    let ordinary = FederationGrpcSubscriberClient::connect(
        PeerDialConfig {
            uri: format!("http://localhost:{}", address.port()),
            expected_peer: server_node,
            server_name: "localhost".to_owned(),
            peer_trust_root_pem: CA.to_vec(),
            client_certificate_pem: CERT.to_vec(),
            client_key_pem: KEY.to_vec(),
        },
        Arc::clone(&client_identity),
        Arc::new(Policy),
        ordinary_runtime.clone(),
    )
    .await?;
    ensure!(ordinary.serves(xolotl_federation_grpc::ServedCapability::Publication));
    ensure!(!ordinary.serves(xolotl_federation_grpc::ServedCapability::Object));
    let missing = ordinary
        .inspect_subscription(InspectSubscriptionRequest {
            authenticated_subscriber: client_node,
            subscription,
        })
        .await
        .err()
        .context("ordinary session found unopened subscription")?;
    ensure!(missing.code() == Code::PermissionDenied);
    ensure!(!ordinary.is_closed());
    ensure!(
        server_access
            .connected_peer(
                client_node,
                xolotl_federation_grpc::ServedCapability::Snapshot
            )
            .is_none()
    );
    let reverse_client = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(handle) = server_access.connected_peer(
                client_node,
                xolotl_federation_grpc::ServedCapability::Publication,
            ) {
                break handle;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let unavailable_snapshot = reverse_client
        .inspect_snapshot(reverse_subscription)
        .await
        .err()
        .context("uninstalled snapshot service accepted a request")?;
    ensure!(unavailable_snapshot.code() == Code::Unavailable);
    let failure = xolotl_federation_grpc::RemoteSyncFailure::from_status(&unavailable_snapshot)
        .context("unsupported snapshot lost its commit verdict")?;
    ensure!(failure.verdict() == pb::CommitVerdict::NotCommitted);
    ensure!(!reverse_client.is_closed());
    let reverse_opened = reverse_client
        .open_and_install(
            OpenRequest {
                authenticated_subscriber: server_node,
                request_id: RequestId::from_bytes([17; 16]),
                subscription: reverse_subscription,
                stream: reverse_stream,
                expected_control_revision: None,
                history: HistoryStart::All,
            },
            &publisher,
        )
        .await?;
    let reverse_page = reverse_client
        .read_accept_ack(
            ReadRequest {
                authenticated_subscriber: server_node,
                subscription: reverse_subscription,
                after: reverse_opened.start,
                max_records: 8,
                max_bytes: 1024,
            },
            reverse_stream,
            &publisher,
        )
        .await?;
    ensure!(reverse_page.records.len() == 1);
    let opened = client
        .open_and_install(
            OpenRequest {
                authenticated_subscriber: client_node,
                request_id: RequestId::from_bytes([7; 16]),
                subscription,
                stream,
                expected_control_revision: None,
                history: HistoryStart::All,
            },
            &subscriber,
        )
        .await?;
    ensure!(opened.subscription == subscription);
    let page = client
        .read_accept_ack(
            ReadRequest {
                authenticated_subscriber: client_node,
                subscription,
                after: opened.start,
                max_records: 8,
                max_bytes: 1024,
            },
            stream,
            &subscriber,
        )
        .await?;
    ensure!(page.records.len() == 1);
    let accepted_again = subscriber.accept(xolotl_federation::AcceptRequest {
        authenticated_publisher: server_node,
        subscription,
        record: page.records[0].clone(),
    })?;
    ensure!(!accepted_again.newly_accepted);
    ensure!(accepted_again.position == page.records[0].position());
    let inspection = client
        .inspect_subscription(InspectSubscriptionRequest {
            authenticated_subscriber: client_node,
            subscription,
        })
        .await?;
    ensure!(inspection.acknowledged == Some(page.records[0].position()));
    ensure!(!inspection.closed);
    let empty = client
        .read(
            ReadRequest {
                authenticated_subscriber: client_node,
                subscription,
                after: Some(page.records[0].position()),
                max_records: 8,
                max_bytes: 1024,
            },
            stream,
        )
        .await?;
    ensure!(empty.records.is_empty());
    let closed = client
        .close_subscription(CloseSubscriptionRequest {
            authenticated_subscriber: client_node,
            request_id: RequestId::from_bytes([8; 16]),
            subscription,
            expected_subscription_revision: Some(inspection.subscription_revision),
        })
        .await?;
    let inspected_closed = client
        .inspect_subscription(InspectSubscriptionRequest {
            authenticated_subscriber: client_node,
            subscription,
        })
        .await?;
    ensure!(inspected_closed.closed);
    ensure!(inspected_closed.subscription_revision == closed.subscription_revision);
    drop(reverse_client);
    drop(ordinary);
    ordinary_runtime.shutdown().await;
    drop(client);
    stop_tx
        .send(())
        .map_err(|_sent| anyhow::anyhow!("server stopped early"))?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    Ok(())
}
