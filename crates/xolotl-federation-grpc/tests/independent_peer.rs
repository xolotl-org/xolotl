//! Protocol acceptance against a peer that does not call Xolotl's wire or
//! Session implementations. The peer encodes the v1 identity and transcript
//! directly from the published byte layout and uses only protobuf types for
//! the gRPC envelope. This is one independent peer implementation in Rust,
//! not a claim of cross-language interoperability.

use std::{io::Cursor, sync::Arc, time::Duration};

use anyhow::{Context as _, Result, anyhow, ensure};
use aws_lc_rs::{
    rand::{SecureRandom as _, SystemRandom},
    signature::{KeyPair as _, ML_DSA_65, ML_DSA_65_SIGNING, ParsedPublicKey, PqdsaKeyPair},
};
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _};
use sha2::{Digest as _, Sha384};
use tokio::{
    net::TcpListener,
    sync::{mpsc, oneshot},
};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{
    Code,
    transport::{Channel, Endpoint},
};
use xolotl_federation::{
    AcceptRequest, AuthorityRevision, Digest, EventType, ExportAccess, ExportName, FederationError,
    FederationLimits, FederationNodeId, FederationOnlineKey, FederationOnlineKeyAuthorization,
    FederationRootKey, FederationService, FederationStore, InboxReadRequest,
    InspectSubscriptionRequest, InstallSubscriptionRequest, OpenResult, Position, PublishRequest,
    Record, RecordParts, RequestId, RootSignaturePurpose, SchemaRevision, StreamId, StreamRef,
    StreamSpec, SubscriptionId, SubscriptionRef, VerifiedFederationPeerProof,
};
use xolotl_federation_grpc::{
    FederationGrpcPublisherServer, FederationLocalCredentials, FederationPeerPolicy,
    config::FederationGrpcConfig, federation_tls_incoming,
};
use xolotl_proto::xolotl::v1::federation as pb;
use xolotl_storage_redb::RedbStore;

const CERT: &[u8] = include_bytes!("../../xolotl-daemon/tests/fixtures/ml-dsa-65-cert.pem");
const KEY: &[u8] = include_bytes!("../../xolotl-daemon/tests/fixtures/ml-dsa-65-key.pem");
const CA: &[u8] = include_bytes!("../../xolotl-daemon/tests/fixtures/ml-dsa-65-ca-cert.pem");
const ROOT_PREFIX: &[u8] = b"xolotl.federation.root.v1\0";
const NODE_PREFIX: &[u8] = b"xolotl.federation.node-id.v1\0";
const ONLINE_PREFIX: &[u8] = b"xolotl.federation.online-key.v1\0";
const ROOT_SIGNATURE_PREFIX: &[u8] = b"xolotl.federation.signature.v1\0";
const CAPABILITIES_PREFIX: &[u8] = b"xolotl.federation.hello-capabilities.v1\0";
const SESSION_PREFIX: &[u8] = b"xolotl.federation.online-session.v1\0";
const EXPORTER_LABEL: &[u8] = b"EXPORTER-xolotl-federation-v1";
const PUBLIC_KEY_BYTES: usize = 1952;
const SIGNATURE_BYTES: usize = 3309;
const RECORD_PREFIX: &[u8] = b"xolotl.federation.record.v1\0";

struct AllowPeer;

impl FederationPeerPolicy for AllowPeer {
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

fn keypair() -> Result<PqdsaKeyPair> {
    PqdsaKeyPair::generate(&ML_DSA_65_SIGNING).map_err(|_error| anyhow!("ML-DSA key generation"))
}

fn signature(key: &PqdsaKeyPair, input: &[u8]) -> Result<Vec<u8>> {
    let mut output = vec![0; SIGNATURE_BYTES];
    let written = key
        .sign(input, &mut output)
        .map_err(|_error| anyhow!("ML-DSA signing"))?;
    ensure!(written == SIGNATURE_BYTES);
    Ok(output)
}

fn verify(public: &[u8], input: &[u8], signature: &[u8]) -> Result<()> {
    ensure!(public.len() == PUBLIC_KEY_BYTES && signature.len() == SIGNATURE_BYTES);
    ParsedPublicKey::new(&ML_DSA_65, public)
        .map_err(|_error| anyhow!("invalid ML-DSA public key"))?
        .verify_sig(input, signature)
        .map_err(|_error| anyhow!("invalid ML-DSA signature"))
}

fn hash(parts: &[&[u8]]) -> [u8; 48] {
    let mut digest = Sha384::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().into()
}

fn root_signature_input(authorization: &[u8]) -> Result<Vec<u8>> {
    let mut input = ROOT_SIGNATURE_PREFIX.to_vec();
    input.push(2); // OnlineKeyAuthorization
    input.extend_from_slice(&u32::try_from(authorization.len())?.to_be_bytes());
    input.extend_from_slice(authorization);
    Ok(input)
}

fn root_public_key(descriptor: &[u8]) -> Result<&[u8]> {
    let header = [ROOT_PREFIX, &[0, 1, 0, 1, 0x07, 0xa0]].concat();
    ensure!(descriptor.len() == header.len() + PUBLIC_KEY_BYTES);
    ensure!(
        descriptor.starts_with(&header),
        "noncanonical root descriptor"
    );
    Ok(&descriptor[header.len()..])
}

fn online_public_key(authorization: &[u8]) -> Result<&[u8]> {
    let header = [ONLINE_PREFIX, &[0, 1, 0, 1, 0x07, 0xa0]].concat();
    ensure!(authorization.len() == header.len() + 24 + PUBLIC_KEY_BYTES);
    ensure!(
        authorization.starts_with(&header),
        "noncanonical online authorization"
    );
    let fields = &authorization[header.len()..header.len() + 24];
    ensure!(u64::from_be_bytes(fields[..8].try_into()?) > 0);
    ensure!(u64::from_be_bytes(fields[8..16].try_into()?) <= 150);
    ensure!(u64::from_be_bytes(fields[16..24].try_into()?) > 150);
    Ok(&authorization[header.len() + 24..])
}

struct IndependentPeer {
    node: FederationNodeId,
    online: PqdsaKeyPair,
    hello: pb::Hello,
}

impl IndependentPeer {
    fn new() -> Result<Self> {
        let root = keypair()?;
        let online = keypair()?;
        let mut descriptor = ROOT_PREFIX.to_vec();
        descriptor.extend_from_slice(&[0, 1, 0, 1, 0x07, 0xa0]);
        descriptor.extend_from_slice(root.public_key().as_ref());
        let node = hash(&[NODE_PREFIX, &descriptor]);

        let mut authorization = ONLINE_PREFIX.to_vec();
        authorization.extend_from_slice(&[0, 1, 0, 1, 0x07, 0xa0]);
        authorization.extend_from_slice(&1u64.to_be_bytes());
        authorization.extend_from_slice(&100u64.to_be_bytes());
        authorization.extend_from_slice(&200u64.to_be_bytes());
        authorization.extend_from_slice(online.public_key().as_ref());
        let root_signature = signature(&root, &root_signature_input(&authorization)?)?;

        let limits = FederationGrpcConfig::default();
        let mut peer = Self {
            node: FederationNodeId::from_bytes(node),
            online,
            hello: pb::Hello {
                protocol_version: 1,
                node_id: node.to_vec(),
                max_frame_bytes: limits.max_frame_bytes as u64,
                max_in_flight: limits.max_in_flight as u32,
                max_batch_records: limits.max_batch_records as u32,
                max_batch_bytes: limits.max_batch_bytes as u64,
                root_descriptor: descriptor,
                online_authorization: authorization,
                root_signature,
                nonce: Vec::new(),
                required_features: Vec::new(),
                served_capabilities: 0,
            },
        };
        peer.renew_nonce()?;
        Ok(peer)
    }

    fn renew_nonce(&mut self) -> Result<()> {
        let mut nonce = [0; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_error| anyhow!("nonce generation"))?;
        self.hello.nonce = nonce.to_vec();
        Ok(())
    }

    fn node_id(&self) -> FederationNodeId {
        self.node
    }

    fn authenticate(&self, server: &pb::Hello, exporter: &[u8; 48]) -> Result<pb::SyncFrame> {
        let input = session_input(&self.hello, server, &self.hello, exporter)?;
        Ok(frame(pb::sync_frame::Body::Authenticate(
            pb::Authenticate {
                online_signature: signature(&self.online, &input)?,
            },
        )))
    }
}

fn capabilities(initiator: &pb::Hello, responder: &pb::Hello) -> [u8; 48] {
    let mut digest = Sha384::new();
    digest.update(CAPABILITIES_PREFIX);
    for hello in [initiator, responder] {
        digest.update(hello.protocol_version.to_be_bytes());
        digest.update(hello.served_capabilities.to_be_bytes());
        digest.update(&hello.node_id);
        digest.update(hello.max_frame_bytes.to_be_bytes());
        digest.update(hello.max_in_flight.to_be_bytes());
        digest.update(hello.max_batch_records.to_be_bytes());
        digest.update(hello.max_batch_bytes.to_be_bytes());
    }
    digest.finalize().into()
}

fn session_input(
    initiator: &pb::Hello,
    responder: &pb::Hello,
    signer: &pb::Hello,
    exporter: &[u8; 48],
) -> Result<Vec<u8>> {
    ensure!(initiator.nonce.len() == 32 && responder.nonce.len() == 32);
    let mut input = SESSION_PREFIX.to_vec();
    input.extend_from_slice(&signer.node_id);
    input.extend_from_slice(&initiator.node_id);
    input.extend_from_slice(&responder.node_id);
    input.extend_from_slice(&initiator.nonce);
    input.extend_from_slice(&responder.nonce);
    input.extend_from_slice(exporter);
    input.extend_from_slice(&capabilities(initiator, responder));
    input.extend_from_slice(&hash(&[&signer.online_authorization]));
    Ok(input)
}

fn verify_hello(hello: &pb::Hello, expected_node: FederationNodeId) -> Result<()> {
    ensure!(hello.protocol_version == 1 && hello.required_features.is_empty());
    ensure!(hello.served_capabilities & !15 == 0);
    ensure!(hello.node_id == expected_node.as_bytes());
    ensure!(hello.nonce.len() == 32 && hello.nonce.iter().any(|byte| *byte != 0));
    ensure!(hash(&[NODE_PREFIX, &hello.root_descriptor]) == expected_node.as_bytes().as_slice());
    verify(
        root_public_key(&hello.root_descriptor)?,
        &root_signature_input(&hello.online_authorization)?,
        &hello.root_signature,
    )?;
    online_public_key(&hello.online_authorization)?;
    Ok(())
}

fn frame(body: pb::sync_frame::Body) -> pb::SyncFrame {
    pb::SyncFrame { body: Some(body) }
}

fn server_identity() -> Result<Arc<FederationLocalCredentials>> {
    let root_key = FederationRootKey::generate()?;
    let root = root_key.root()?;
    let online = FederationOnlineKey::generate()?;
    let authorization = FederationOnlineKeyAuthorization::new(online.public_key(), 1, 100, 200)?;
    let signature = root_key.sign(
        RootSignaturePurpose::OnlineKeyAuthorization,
        &authorization.encode(),
    )?;
    Ok(Arc::new(FederationLocalCredentials::new(
        root,
        authorization,
        signature,
        online,
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

async fn connect(
    address: std::net::SocketAddr,
    tls: Arc<rustls::ClientConfig>,
) -> Result<(
    pb::federation_service_client::FederationServiceClient<Channel>,
    [u8; 48],
)> {
    let (exporter_tx, mut exporter_rx) = mpsc::channel(1);
    let connector = tokio_rustls::TlsConnector::from(tls);
    let channel = Endpoint::from_shared(format!("http://localhost:{}", address.port()))?
        .connect_with_connector(tower::service_fn(move |_uri| {
            let connector = connector.clone();
            let exporter_tx = exporter_tx.clone();
            async move {
                let tcp = tokio::net::TcpStream::connect(address).await?;
                let tls = connector
                    .connect(
                        ServerName::try_from("localhost").map_err(std::io::Error::other)?,
                        tcp,
                    )
                    .await?;
                let exporter = tls
                    .get_ref()
                    .1
                    .export_keying_material([0; 48], EXPORTER_LABEL, None)
                    .map_err(std::io::Error::other)?;
                exporter_tx
                    .send(exporter)
                    .await
                    .map_err(std::io::Error::other)?;
                Ok::<_, std::io::Error>(TokioIo::new(tls))
            }
        }))
        .await?;
    let exporter = exporter_rx.recv().await.context("missing TLS exporter")?;
    Ok((
        pb::federation_service_client::FederationServiceClient::new(channel),
        exporter,
    ))
}

fn open(peer: FederationNodeId, server: FederationNodeId) -> pb::SyncFrame {
    frame(pb::sync_frame::Body::Open(pb::Open {
        request: 1,
        request_id: vec![7; 16],
        subscription: Some(wire_subscription(peer)),
        stream: Some(wire_stream(server)),
        expected_control_revision: None,
        history_mode: pb::HistoryMode::All as i32,
        history_after: None,
        context_id: 0,
        holder_request_signature: Vec::new(),
    }))
}

fn wire_stream(publisher: FederationNodeId) -> pb::StreamRef {
    pb::StreamRef {
        publisher: publisher.as_bytes().to_vec(),
        id: vec![3; 16],
    }
}

fn wire_subscription(subscriber: FederationNodeId) -> pb::SubscriptionRef {
    pb::SubscriptionRef {
        subscriber: subscriber.as_bytes().to_vec(),
        id: vec![4; 16],
    }
}

fn read(subscriber: FederationNodeId) -> pb::SyncFrame {
    frame(pb::sync_frame::Body::Read(pb::Read {
        request: 2,
        subscription: Some(wire_subscription(subscriber)),
        after: None,
        max_records: 8,
        max_bytes: 1024,
        context_id: 0,
        holder_request_signature: Vec::new(),
    }))
}

fn acknowledge(subscriber: FederationNodeId, position: pb::Position) -> pb::SyncFrame {
    frame(pb::sync_frame::Body::Acknowledge(pb::Acknowledge {
        request: 3,
        subscription: Some(wire_subscription(subscriber)),
        position: Some(position),
        context_id: 0,
        holder_request_signature: Vec::new(),
    }))
}

fn inspect(subscriber: FederationNodeId) -> pb::SyncFrame {
    frame(pb::sync_frame::Body::Inspect(pb::Inspect {
        request: 4,
        subscription: Some(wire_subscription(subscriber)),
        context_id: 0,
        holder_request_signature: Vec::new(),
    }))
}

fn record_digest(record: &pb::Record) -> Result<[u8; 48]> {
    let stream = record.stream.as_ref().context("record stream missing")?;
    ensure!(stream.publisher.len() == 48 && stream.id.len() == 16);
    ensure!(record.sequence > 0);
    ensure!(record.publish_id.len() == 16 && record.schema_revision.len() == 32);
    ensure!(!record.event_type.is_empty() && record.event_type.len() <= 256);
    let mut hasher = Sha384::new();
    hasher.update(RECORD_PREFIX);
    hasher.update(&stream.publisher);
    hasher.update(&stream.id);
    hasher.update(record.sequence.to_be_bytes());
    hasher.update(&record.publish_id);
    hasher.update(u64::try_from(record.event_type.len())?.to_be_bytes());
    hasher.update(record.event_type.as_bytes());
    hasher.update(&record.schema_revision);
    match &record.event_ref {
        Some(reference) => {
            ensure!(reference.origin.len() == 48);
            hasher.update([1]);
            hasher.update(&reference.origin);
            for literal in [&reference.namespace, &reference.id] {
                hasher.update(u64::try_from(literal.len())?.to_be_bytes());
                hasher.update(literal.as_bytes());
            }
        }
        None => hasher.update([0]),
    }
    hasher.update(u64::try_from(record.payload.len())?.to_be_bytes());
    hasher.update(hash(&[&record.payload]));
    Ok(hasher.finalize().into())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_peer_delivers_durably_and_invalid_proofs_fail_closed() -> Result<()> {
    let config = FederationGrpcConfig {
        hello_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        ..FederationGrpcConfig::default()
    };
    let identity = server_identity()?;
    let server_node = identity.node_id();
    let mut peer = IndependentPeer::new()?;
    let directory = tempfile::tempdir()?;
    let publisher_path = directory.path().join("publisher.redb");
    let receiver_path = directory.path().join("receiver.redb");
    let publisher_db = RedbStore::open(&publisher_path)?;
    let receiver_db = RedbStore::open(&receiver_path)?;
    let publisher_store = publisher_db.federation_store(server_node)?;
    let receiver_store = receiver_db.federation_store(peer.node_id())?;
    let service = FederationService::new(
        Arc::new(publisher_store.clone()),
        FederationLimits {
            max_record_bytes: config.max_batch_bytes,
            ..FederationLimits::default()
        },
    )?;
    let receiver = FederationService::new(
        Arc::new(receiver_store.clone()),
        FederationLimits::default(),
    )?;
    service.set_peer_authority(peer.node_id(), None, true)?;
    service.set_peer_admission(
        peer.node_id(),
        None,
        xolotl_federation::PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![
                Sha384::digest(&peer.hello.online_authorization).into(),
            ],
        },
    )?;
    service.set_export_authority(
        peer.node_id(),
        ExportName::new("friends")?,
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    service.declare_stream(StreamSpec {
        stream: StreamRef {
            publisher: server_node,
            id: StreamId::from_bytes([3; 16]),
        },
        export: ExportName::new("friends")?,
    })?;
    let published = service.append_published(PublishRequest {
        retry_epoch: 1,
        stream: StreamRef {
            publisher: server_node,
            id: StreamId::from_bytes([3; 16]),
        },
        publish_id: RequestId::from_bytes([9; 16]),
        event_type: EventType::new("note.created")?,
        schema_revision: SchemaRevision::from_bytes([6; 32]),
        event_ref: None,
        payload: Arc::from(b"durable independent delivery".as_slice()),
    })?;
    let listener_runtime = xolotl_federation_grpc::FederationGrpcRuntime::new(
        config,
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?;
    let server = FederationGrpcPublisherServer::new(
        service,
        identity,
        Arc::new(AllowPeer),
        listener_runtime.clone(),
    )?;
    let (server_tls, client_tls) = tls_configs()?;
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

    let (mut client, exporter) = connect(address, Arc::clone(&client_tls)).await?;
    let (send, receive) = mpsc::channel(4);
    let mut inbound = client
        .session(ReceiverStream::new(receive))
        .await?
        .into_inner();
    send.send(frame(pb::sync_frame::Body::Hello(peer.hello.clone())))
        .await?;
    let server_hello = match inbound
        .message()
        .await?
        .context("missing server Hello")?
        .body
    {
        Some(pb::sync_frame::Body::Hello(hello)) => hello,
        _ => return Err(anyhow!("server did not begin with Hello")),
    };
    verify_hello(&server_hello, server_node)?;
    send.send(peer.authenticate(&server_hello, &exporter)?)
        .await?;
    let server_signature = match inbound
        .message()
        .await?
        .context("missing server proof")?
        .body
    {
        Some(pb::sync_frame::Body::Authenticate(auth)) => auth.online_signature,
        _ => return Err(anyhow!("server did not return Authenticate")),
    };
    verify(
        online_public_key(&server_hello.online_authorization)?,
        &session_input(&peer.hello, &server_hello, &server_hello, &exporter)?,
        &server_signature,
    )?;
    send.send(open(peer.node_id(), server_node)).await?;
    let response = inbound.message().await?.context("missing Opened")?;
    let opened = match response.body {
        Some(pb::sync_frame::Body::Opened(opened)) => opened,
        other => return Err(anyhow!("expected Opened, received {other:?}")),
    };
    ensure!(opened.request == 1 && opened.request_id == [7; 16]);
    ensure!(opened.export_name == "friends");
    ensure!(
        opened
            .subscription
            .as_ref()
            .is_some_and(
                |subscription| subscription.subscriber == peer.node_id().as_bytes()
                    && subscription.id == [4; 16]
            )
    );
    ensure!(
        opened.stream.as_ref().is_some_and(
            |stream| stream.publisher == server_node.as_bytes() && stream.id == [3; 16]
        )
    );
    ensure!(opened.start.is_none() && opened.subscription_revision > 0);
    let subscription = SubscriptionRef {
        subscriber: peer.node_id(),
        id: SubscriptionId::from_bytes([4; 16]),
    };
    let stream = StreamRef {
        publisher: server_node,
        id: StreamId::from_bytes([3; 16]),
    };
    let opened_local = OpenResult {
        request_id: RequestId::from_bytes([7; 16]),
        subscription,
        stream,
        export: ExportName::new(opened.export_name)?,
        publisher_authority: AuthorityRevision {
            peer: opened.publisher_peer_revision,
            export: opened.publisher_export_revision,
        },
        subscription_revision: opened.subscription_revision,
        start: None,
    };
    let install = InstallSubscriptionRequest {
        authenticated_publisher: server_node,
        opened: opened_local.clone(),
    };
    ensure!(matches!(
        receiver.install_subscription(install.clone()),
        Err(FederationError::Unauthorized)
    ));
    receiver.set_peer_authority(server_node, None, true)?;
    ensure!(matches!(
        receiver.install_subscription(install.clone()),
        Err(FederationError::Unauthorized)
    ));
    receiver.set_export_authority(
        server_node,
        ExportName::new("friends")?,
        None,
        ExportAccess {
            serve: false,
            receive: true,
        },
    )?;
    ensure!(receiver.install_subscription(install)? == opened_local);

    send.send(read(peer.node_id())).await?;
    let response = inbound.message().await?.context("missing Batch")?;
    let mut batch = match response.body {
        Some(pb::sync_frame::Body::Batch(batch)) => batch,
        other => return Err(anyhow!("expected Batch, received {other:?}")),
    };
    ensure!(batch.request == 2 && batch.subscription == Some(wire_subscription(peer.node_id())));
    ensure!(batch.minimum_available == 1 && batch.records.len() == 1);
    let wire_record = batch.records.remove(0);
    let digest = record_digest(&wire_record)?;
    ensure!(wire_record.digest == digest);
    ensure!(wire_record.stream == Some(wire_stream(server_node)));
    ensure!(wire_record.sequence == 1 && wire_record.publish_id == [9; 16]);
    ensure!(wire_record.event_type == "note.created" && wire_record.schema_revision == [6; 32]);
    ensure!(wire_record.event_ref.is_none());
    ensure!(wire_record.payload == b"durable independent delivery");
    let position = pb::Position {
        sequence: wire_record.sequence,
        digest: digest.to_vec(),
    };
    ensure!(batch.head == Some(position.clone()));
    let imported = Record::from_parts(
        RecordParts {
            stream,
            sequence: wire_record.sequence,
            publish_id: RequestId::from_bytes([9; 16]),
            event_type: EventType::new(wire_record.event_type)?,
            schema_revision: SchemaRevision::from_bytes([6; 32]),
            event_ref: None,
            payload: Arc::from(wire_record.payload),
        },
        Digest::from_bytes(digest),
    )?;
    ensure!(imported == published);
    let accepted = receiver.accept(AcceptRequest {
        authenticated_publisher: server_node,
        subscription,
        record: imported,
    })?;
    let accepted_position = Position::new(position.sequence, Digest::from_bytes(digest))?;
    ensure!(accepted.newly_accepted && accepted.position == accepted_position);
    let inbox = receiver.read_inbox(InboxReadRequest {
        subscription,
        expected_stream: stream,
        after: None,
        max_records: 8,
        max_bytes: 1024,
    })?;
    ensure!(inbox.received == Some(accepted_position) && inbox.records == vec![published.clone()]);

    send.send(acknowledge(peer.node_id(), position.clone()))
        .await?;
    let response = inbound.message().await?.context("missing Acknowledged")?;
    let acknowledged = match response.body {
        Some(pb::sync_frame::Body::Acknowledged(acknowledged)) => acknowledged,
        other => return Err(anyhow!("expected Acknowledged, received {other:?}")),
    };
    ensure!(acknowledged.request == 3 && acknowledged.position == Some(position.clone()));
    send.send(inspect(peer.node_id())).await?;
    let response = inbound.message().await?.context("missing Inspected")?;
    let inspected = match response.body {
        Some(pb::sync_frame::Body::Inspected(inspected)) => inspected,
        other => return Err(anyhow!("expected Inspected, received {other:?}")),
    };
    ensure!(inspected.request == 4 && inspected.acknowledged == Some(position));
    ensure!(inspected.head == inspected.acknowledged);
    drop(send);
    drop(inbound);
    drop(client);

    // A valid online key cannot authenticate a proof for another TLS channel.
    peer.renew_nonce()?;
    let (mut client, mut exporter) = connect(address, Arc::clone(&client_tls)).await?;
    let (send, receive) = mpsc::channel(4);
    let mut inbound = client
        .session(ReceiverStream::new(receive))
        .await?
        .into_inner();
    send.send(frame(pb::sync_frame::Body::Hello(peer.hello.clone())))
        .await?;
    let server_hello = match inbound
        .message()
        .await?
        .context("missing server Hello")?
        .body
    {
        Some(pb::sync_frame::Body::Hello(hello)) => hello,
        _ => return Err(anyhow!("server did not begin with Hello")),
    };
    exporter[0] ^= 1;
    send.send(peer.authenticate(&server_hello, &exporter)?)
        .await?;
    ensure!(matches!(
        inbound
            .message()
            .await?
            .context("missing server proof")?
            .body,
        Some(pb::sync_frame::Body::Authenticate(_))
    ));
    let rejected = inbound
        .message()
        .await
        .err()
        .context("wrong TLS channel proof admitted")?;
    ensure!(rejected.code() == Code::Unauthenticated);
    drop(send);
    drop(inbound);
    drop(client);

    // A fresh connection with a valid root but corrupted authorization proof
    // must never dispatch the queued business frame.
    peer.renew_nonce()?;
    let (mut client, exporter) = connect(address, Arc::clone(&client_tls)).await?;
    let (send, receive) = mpsc::channel(4);
    let mut inbound = client
        .session(ReceiverStream::new(receive))
        .await?
        .into_inner();
    let mut corrupt = peer.hello.clone();
    corrupt.root_signature[0] ^= 1;
    send.send(frame(pb::sync_frame::Body::Hello(corrupt)))
        .await?;
    let server_hello = match inbound
        .message()
        .await?
        .context("missing server Hello")?
        .body
    {
        Some(pb::sync_frame::Body::Hello(hello)) => hello,
        _ => return Err(anyhow!("server did not begin with Hello")),
    };
    send.send(peer.authenticate(&server_hello, &exporter)?)
        .await?;
    send.send(open(peer.node_id(), server_node)).await?;
    ensure!(matches!(
        inbound
            .message()
            .await?
            .context("missing server proof")?
            .body,
        Some(pb::sync_frame::Body::Authenticate(_))
    ));
    let rejected = inbound
        .message()
        .await
        .err()
        .context("corrupt root proof admitted")?;
    ensure!(rejected.code() == Code::Unauthenticated);
    drop(send);
    drop(inbound);
    drop(client);

    // An Open in the Hello slot is rejected even when it names a configured peer.
    let (mut client, _exporter) = connect(address, client_tls).await?;
    let (send, receive) = mpsc::channel(2);
    let mut inbound = client
        .session(ReceiverStream::new(receive))
        .await?
        .into_inner();
    send.send(open(peer.node_id(), server_node)).await?;
    ensure!(matches!(
        inbound
            .message()
            .await?
            .context("missing server Hello")?
            .body,
        Some(pb::sync_frame::Body::Hello(_))
    ));
    let rejected = inbound
        .message()
        .await
        .err()
        .context("pre-auth Open admitted")?;
    ensure!(rejected.code() == Code::Unauthenticated);
    drop(send);
    drop(inbound);
    drop(client);

    stop_tx
        .send(())
        .map_err(|_sent| anyhow!("server stopped early"))?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    drop(receiver);
    drop(receiver_store);
    drop(receiver_db);
    drop(publisher_store);
    drop(publisher_db);

    let publisher_db = RedbStore::open(&publisher_path)?;
    let publisher = publisher_db.federation_store(server_node)?;
    let persisted = publisher.inspect_subscription(InspectSubscriptionRequest {
        authenticated_subscriber: peer.node_id(),
        subscription,
    })?;
    ensure!(persisted.acknowledged == Some(accepted_position));
    ensure!(persisted.head == Some(accepted_position));
    let receiver_db = RedbStore::open(&receiver_path)?;
    let receiver = receiver_db.federation_store(peer.node_id())?;
    let persisted = receiver.read_inbox(InboxReadRequest {
        subscription,
        expected_stream: stream,
        after: None,
        max_records: 8,
        max_bytes: 1024,
    })?;
    ensure!(persisted.received == Some(accepted_position));
    ensure!(persisted.records == vec![published]);
    Ok(())
}

/// Run explicitly on hosts with OpenSSL 3.6+, PyOpenSSL and h2 installed. The
/// Python process implements protobuf and gRPC framing itself and obtains the
/// TLS exporter from OpenSSL, so this crosses both language and TLS stacks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires OpenSSL 3.6+, PyOpenSSL and h2"]
async fn python_openssl_h2_peer_opens_and_reads() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let python =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/python_session_peer.py");
    let peer_directory = directory.path().join("python-peer");
    let prepare = tokio::task::spawn_blocking({
        let python = python.clone();
        let peer_directory = peer_directory.clone();
        move || {
            std::process::Command::new("python3")
                .arg(python)
                .arg("prepare")
                .arg(peer_directory)
                .output()
        }
    })
    .await??;
    ensure!(
        prepare.status.success(),
        "Python peer preparation failed: {}",
        String::from_utf8_lossy(&prepare.stderr)
    );
    let node_hex = String::from_utf8(prepare.stdout)?;
    let node_hex = node_hex.trim();
    ensure!(node_hex.len() == 96);
    let mut node_bytes = [0_u8; 48];
    for (byte, digits) in node_bytes
        .iter_mut()
        .zip(node_hex.as_bytes().as_chunks::<2>().0)
    {
        *byte = u8::from_str_radix(std::str::from_utf8(digits)?, 16)?;
    }
    let peer = FederationNodeId::from_bytes(node_bytes);

    let config = FederationGrpcConfig {
        hello_timeout: Duration::from_secs(8),
        response_timeout: Duration::from_secs(8),
        ..FederationGrpcConfig::default()
    };
    let identity = server_identity()?;
    let server_node = identity.node_id();
    let db = RedbStore::open(directory.path().join("publisher.redb"))?;
    let store = db.federation_store(server_node)?;
    let service = FederationService::new(
        Arc::new(store.clone()),
        FederationLimits {
            max_record_bytes: config.max_batch_bytes,
            ..FederationLimits::default()
        },
    )?;
    service.set_peer_authority(peer, None, true)?;
    service.set_peer_admission(
        peer,
        None,
        xolotl_federation::PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![
                Sha384::digest(std::fs::read(peer_directory.join("authorization.bin"))?).into(),
            ],
        },
    )?;
    service.set_export_authority(
        peer,
        ExportName::new("friends")?,
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    let stream = StreamRef {
        publisher: server_node,
        id: StreamId::from_bytes([3; 16]),
    };
    service.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("friends")?,
    })?;
    let published = service.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([9; 16]),
        event_type: EventType::new("note.created")?,
        schema_revision: SchemaRevision::from_bytes([6; 32]),
        event_ref: None,
        payload: Arc::from(b"durable Python delivery".as_slice()),
    })?;
    let listener_runtime = xolotl_federation_grpc::FederationGrpcRuntime::new(
        config,
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?;
    let server = FederationGrpcPublisherServer::new(
        service,
        identity,
        Arc::new(AllowPeer),
        listener_runtime.clone(),
    )?;
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

    let ca = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../xolotl-daemon/tests/fixtures/ml-dsa-65-ca-cert.pem");
    let server_hex = server_node
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("python3")
            .arg(python)
            .arg("client")
            .arg(peer_directory)
            .arg(address.to_string())
            .arg(server_hex)
            .arg(ca)
            .output()
    })
    .await??;
    ensure!(
        output.status.success(),
        "Python Session failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout)?;
    for marker in [
        "python_tls_session_open_read=ok",
        "python_tls_session_reject_exporter=ok",
        "python_tls_session_reject_root_signature=ok",
    ] {
        ensure!(output.contains(marker), "Python Session omitted {marker}");
    }
    let inspected = store.inspect_subscription(InspectSubscriptionRequest {
        authenticated_subscriber: peer,
        subscription: SubscriptionRef {
            subscriber: peer,
            id: SubscriptionId::from_bytes([4; 16]),
        },
    })?;
    ensure!(inspected.head == Some(published.position()) && !inspected.closed);
    ensure!(matches!(
        store.inspect_subscription(InspectSubscriptionRequest {
            authenticated_subscriber: peer,
            subscription: SubscriptionRef {
                subscriber: peer,
                id: SubscriptionId::from_bytes([5; 16]),
            },
        }),
        Err(FederationError::NotFound)
    ));
    stop_tx
        .send(())
        .map_err(|_sent| anyhow!("server stopped early"))?;
    tokio::time::timeout(Duration::from_secs(3), server_task).await???;
    Ok(())
}
