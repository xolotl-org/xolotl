//! One-shot outbound TLS connector and bounded subscriber Session driver.
//! Reconnecting requires a fresh TLS exporter and a fresh Session proof.

use std::{
    io::{self, Cursor},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _};
use tokio::{
    net::TcpStream,
    sync::{OwnedSemaphorePermit, mpsc, oneshot, watch},
};
use tonic::{
    Status,
    transport::{Channel, Endpoint},
};
use xolotl_federation::{
    AcceptRequest, AcknowledgeRequest, CallCancelled, CallInspection, CallInvoked, CallPrepared,
    CancelCallRequest, CloseSubscriptionRequest, CloseSubscriptionResult, FederationCallStore,
    FederationNodeId, FederationOutboundCallStore, FederationService,
    FederationSnapshotPublisherStore, InspectCallRequest, InspectSubscriptionRequest,
    InstallSubscriptionRequest, InvitationId, InvitationSecret, InvokeCallRequest, ObjectReadPage,
    ObjectReadRequest, OpenRequest, OpenResult, OutboundCallIntent, Position, PrepareCallRequest,
    PublicReadPage, PublicReadRequest, PublicStreamView, ReadPage, ReadRequest, RequestId,
    SnapshotContentSource, SnapshotOffer, SnapshotReadChunk, SnapshotReceived,
    SnapshotReceivedRequest, StreamRef, SubscriptionInspection, SubscriptionRef,
};
use xolotl_proto::xolotl::v1::federation as pb;

use crate::{
    config::{FederationGrpcConfig, PeerDialConfig},
    delivery::{DeliveryFrame, DeliveryRequestStream},
    runtime::{FederationGrpcRuntime, SessionTasks, SessionTermination, WorkerPool},
    session::{
        FederationCallInvoker, FederationGrpcPublisherSession, FederationLocalCredentials,
        FederationObjectReader, FederationPeerPolicy,
    },
    subscriber::{
        FederationGrpcSubscriberSession, FederationHostedSubjectCredentials,
        FederationInvitationReceipt, FederationSubscriberEvent, FederationSubscriberResult,
    },
    tls::FederationTlsChannel,
    wire,
};

struct InboundServices {
    service: Option<FederationService>,
    call_store: Option<Arc<dyn FederationCallStore>>,
    call_invoker: Option<Arc<dyn FederationCallInvoker>>,
    object_reader: Option<Arc<dyn FederationObjectReader>>,
    snapshot_publisher: Option<(
        Arc<dyn FederationSnapshotPublisherStore>,
        Arc<dyn SnapshotContentSource>,
    )>,
}

/// Optional services exposed in the reverse direction of an outbound
/// authenticated Session.
pub struct FederationSubscriberServices {
    /// Local publication service reachable in the reverse direction.
    pub service: FederationService,
    /// Optional durable target call directory for reverse requests.
    pub call_store: Option<Arc<dyn FederationCallStore>>,
    /// Optional checked Kernel bridge for reverse Invoke and Cancel.
    pub call_invoker: Option<Arc<dyn FederationCallInvoker>>,
    /// Optional exact-object reader for reverse requests.
    pub object_reader: Option<Arc<dyn FederationObjectReader>>,
}

pub(crate) enum Command {
    RedeemInvitation(
        u32,
        InvitationId,
        RequestId,
        u64,
        Option<InvitationSecret>,
        oneshot::Sender<Result<FederationInvitationReceipt, Status>>,
    ),
    ReadObject(
        u32,
        ObjectReadRequest,
        oneshot::Sender<Result<ObjectReadPage, Status>>,
    ),
    InspectSnapshot(
        SubscriptionRef,
        oneshot::Sender<Result<SnapshotOffer, Status>>,
    ),
    ReadSnapshot(
        SnapshotOffer,
        u64,
        usize,
        oneshot::Sender<Result<SnapshotReadChunk, Status>>,
    ),
    ReceiveSnapshot(
        SnapshotReceivedRequest,
        oneshot::Sender<Result<SnapshotReceived, Status>>,
    ),
    InspectPublic(StreamRef, oneshot::Sender<Result<PublicStreamView, Status>>),
    ReadPublic(
        PublicReadRequest,
        oneshot::Sender<Result<PublicReadPage, Status>>,
    ),
    Open(
        u32,
        OpenRequest,
        oneshot::Sender<Result<OpenResult, Status>>,
    ),
    Read(
        u32,
        ReadRequest,
        StreamRef,
        oneshot::Sender<Result<ReadPage, Status>>,
    ),
    Acknowledge(
        u32,
        AcknowledgeRequest,
        oneshot::Sender<Result<Position, Status>>,
    ),
    Inspect(
        u32,
        InspectSubscriptionRequest,
        oneshot::Sender<Result<SubscriptionInspection, Status>>,
    ),
    Close(
        u32,
        CloseSubscriptionRequest,
        oneshot::Sender<Result<CloseSubscriptionResult, Status>>,
    ),
    RegisterSubject(
        u32,
        Arc<FederationHostedSubjectCredentials>,
        oneshot::Sender<Result<u32, Status>>,
    ),
    PrepareCall(
        u32,
        PrepareCallRequest,
        oneshot::Sender<Result<CallPrepared, Status>>,
    ),
    InvokeCall(
        u32,
        InvokeCallRequest,
        oneshot::Sender<Result<CallInvoked, Status>>,
    ),
    InspectCall(
        u32,
        InspectCallRequest,
        oneshot::Sender<Result<CallInspection, Status>>,
    ),
    CancelCall(
        u32,
        CancelCallRequest,
        oneshot::Sender<Result<CallCancelled, Status>>,
    ),
}

enum Waiter {
    RedeemInvitation(oneshot::Sender<Result<FederationInvitationReceipt, Status>>),
    ReadObject(oneshot::Sender<Result<ObjectReadPage, Status>>),
    InspectSnapshot(oneshot::Sender<Result<SnapshotOffer, Status>>),
    ReadSnapshot(oneshot::Sender<Result<SnapshotReadChunk, Status>>),
    ReceiveSnapshot(oneshot::Sender<Result<SnapshotReceived, Status>>),
    InspectPublic(oneshot::Sender<Result<PublicStreamView, Status>>),
    ReadPublic(oneshot::Sender<Result<PublicReadPage, Status>>),
    Open(oneshot::Sender<Result<OpenResult, Status>>),
    Read(oneshot::Sender<Result<ReadPage, Status>>),
    Acknowledge(oneshot::Sender<Result<Position, Status>>),
    Inspect(oneshot::Sender<Result<SubscriptionInspection, Status>>),
    Close(oneshot::Sender<Result<CloseSubscriptionResult, Status>>),
    RegisterSubject(oneshot::Sender<Result<u32, Status>>),
    PrepareCall(oneshot::Sender<Result<CallPrepared, Status>>),
    InvokeCall(oneshot::Sender<Result<CallInvoked, Status>>),
    InspectCall(oneshot::Sender<Result<CallInspection, Status>>),
    CancelCall(oneshot::Sender<Result<CallCancelled, Status>>),
}

impl Waiter {
    fn finish(self, result: Result<FederationSubscriberResult, Status>) -> Result<(), Status> {
        match (self, result) {
            (
                Self::RedeemInvitation(tx),
                Ok(FederationSubscriberResult::InvitationRedeemed(value)),
            ) => {
                drop(tx.send(Ok(value)));
            }
            (Self::ReadObject(tx), Ok(FederationSubscriberResult::ObjectChunk(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::InspectSnapshot(tx), Ok(FederationSubscriberResult::SnapshotOffered(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::ReadSnapshot(tx), Ok(FederationSubscriberResult::SnapshotChunk(value))) => {
                drop(tx.send(Ok(value)));
            }
            (
                Self::ReceiveSnapshot(tx),
                Ok(FederationSubscriberResult::SnapshotReceived(value)),
            ) => {
                drop(tx.send(Ok(value)));
            }
            (Self::InspectPublic(tx), Ok(FederationSubscriberResult::PublicInspected(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::ReadPublic(tx), Ok(FederationSubscriberResult::PublicBatch(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::Open(tx), Ok(FederationSubscriberResult::Opened(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::Read(tx), Ok(FederationSubscriberResult::Batch(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::Acknowledge(tx), Ok(FederationSubscriberResult::Acknowledged(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::Inspect(tx), Ok(FederationSubscriberResult::Inspected(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::Close(tx), Ok(FederationSubscriberResult::Closed(value))) => {
                drop(tx.send(Ok(value)));
            }
            (
                Self::RegisterSubject(tx),
                Ok(FederationSubscriberResult::SubjectRegistered(value)),
            ) => {
                drop(tx.send(Ok(value)));
            }
            (Self::PrepareCall(tx), Ok(FederationSubscriberResult::CallPrepared(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::InvokeCall(tx), Ok(FederationSubscriberResult::CallInvoked(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::InspectCall(tx), Ok(FederationSubscriberResult::CallInspected(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::CancelCall(tx), Ok(FederationSubscriberResult::CallCancelled(value))) => {
                drop(tx.send(Ok(value)));
            }
            (Self::Open(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::InspectPublic(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::ReadPublic(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::ReadObject(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::InspectSnapshot(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::ReadSnapshot(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::ReceiveSnapshot(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::RedeemInvitation(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::Read(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::Acknowledge(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::Inspect(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::Close(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::RegisterSubject(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::PrepareCall(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::InvokeCall(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::InspectCall(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            (Self::CancelCall(tx), Err(status)) => {
                drop(tx.send(Err(status)));
            }
            _ => return Err(Status::internal("federation response waiter mismatched")),
        }
        Ok(())
    }

    fn fail(self, status: Status) {
        drop(self.finish(Err(status)));
    }
}

/// Authenticated subscriber on one TLS connection. Cloneable handles share one
/// bounded request queue and one runtime-owned Session. Runtime closure interrupts
/// the actor even while handles remain live. Dropping the last handle shuts down
/// its actor; a transport failure fails all outstanding requests.
/// Remote SyncFailure errors preserve code, request and commit verdict in
/// Status details; recover them with [`crate::RemoteSyncFailure::from_status`].
/// A missing verdict or transport failure is never evidence of non-commit.
#[derive(Clone)]
pub struct FederationGrpcSubscriberClient {
    _runtime: Option<FederationGrpcRuntime>,
    commands: mpsc::Sender<Command>,
    termination: watch::Receiver<Option<Status>>,
    local_node: FederationNodeId,
    peer_node: FederationNodeId,
    blocking: WorkerPool,
    config: FederationGrpcConfig,
    peer_max_batch_records: usize,
    peer_max_batch_bytes: usize,
    peer_served_capabilities: u32,
    decision: Option<xolotl_federation::FederationDecision>,
}

impl FederationGrpcSubscriberClient {
    /// Dial a pinned peer using real rustls TLS 1.3 with only the v1 hybrid
    /// group. `route.uri` is an `http://host:port` h2 authority for tonic; the
    /// connector itself establishes TLS and verifies the pinned certificate
    /// trust root and server name. Every new connection needs a new `connect`.
    pub async fn connect(
        route: PeerDialConfig,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        runtime: FederationGrpcRuntime,
    ) -> Result<Self, Status> {
        Self::connect_inner(
            route,
            local,
            policy,
            runtime,
            InboundServices {
                service: None,
                call_store: None,
                call_invoker: None,
                object_reader: None,
                snapshot_publisher: None,
            },
        )
        .await
    }

    /// Dial a peer and also publish the local store over this same authenticated
    /// Session, including when the remote node initiates Open after we dial.
    pub async fn connect_bidirectional(
        route: PeerDialConfig,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        runtime: FederationGrpcRuntime,
        service: FederationService,
        call_store: Option<Arc<dyn FederationCallStore>>,
    ) -> Result<Self, Status> {
        Self::connect_inner(
            route,
            local,
            policy,
            runtime,
            InboundServices {
                service: Some(service),
                call_store,
                call_invoker: None,
                object_reader: None,
                snapshot_publisher: None,
            },
        )
        .await
    }

    /// As above, with an asynchronous checked Kernel call bridge.
    pub async fn connect_with_invoker(
        route: PeerDialConfig,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        runtime: FederationGrpcRuntime,
        service: FederationService,
        call_store: Option<Arc<dyn FederationCallStore>>,
        call_invoker: Arc<dyn FederationCallInvoker>,
    ) -> Result<Self, Status> {
        Self::connect_inner(
            route,
            local,
            policy,
            runtime,
            InboundServices {
                service: Some(service),
                call_store,
                call_invoker: Some(call_invoker),
                object_reader: None,
                snapshot_publisher: None,
            },
        )
        .await
    }

    /// Dial and serve the local publisher, call bridge and object reader over
    /// the reverse direction of the same proven Session.
    pub async fn connect_with_services(
        route: PeerDialConfig,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        runtime: FederationGrpcRuntime,
        services: FederationSubscriberServices,
    ) -> Result<Self, Status> {
        Self::connect_inner(
            route,
            local,
            policy,
            runtime,
            InboundServices {
                service: Some(services.service),
                call_store: services.call_store,
                call_invoker: services.call_invoker,
                object_reader: services.object_reader,
                snapshot_publisher: None,
            },
        )
        .await
    }

    /// Dial and expose the local publisher's pinned application snapshots in
    /// the reverse direction of this authenticated Session.
    pub async fn connect_with_snapshot_services(
        route: PeerDialConfig,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        runtime: FederationGrpcRuntime,
        services: FederationSubscriberServices,
        store: Arc<dyn FederationSnapshotPublisherStore>,
        source: Arc<dyn SnapshotContentSource>,
    ) -> Result<Self, Status> {
        Self::connect_inner(
            route,
            local,
            policy,
            runtime,
            InboundServices {
                service: Some(services.service),
                call_store: services.call_store,
                call_invoker: services.call_invoker,
                object_reader: services.object_reader,
                snapshot_publisher: Some((store, source)),
            },
        )
        .await
    }

    async fn connect_inner(
        route: PeerDialConfig,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        runtime: FederationGrpcRuntime,
        inbound: InboundServices,
    ) -> Result<Self, Status> {
        let permit = runtime.admit()?;
        let config = runtime.config();
        if route.expected_peer == local.node_id() {
            return Err(Status::invalid_argument(
                "federation peer is the local node",
            ));
        }
        let endpoint = Endpoint::from_shared(route.uri)
            .map_err(|_error| Status::invalid_argument("invalid federation peer URI"))?;
        let uri = endpoint.uri();
        if uri.scheme_str() != Some("http") || uri.path() != "/" || uri.query().is_some() {
            return Err(Status::invalid_argument(
                "federation peer URI must be an http authority",
            ));
        }
        let host = uri
            .host()
            .ok_or_else(|| Status::invalid_argument("missing federation peer host"))?
            .to_owned();
        let port = uri
            .port_u16()
            .ok_or_else(|| Status::invalid_argument("missing federation peer port"))?;
        let server_name = ServerName::try_from(route.server_name)
            .map_err(|_error| Status::invalid_argument("invalid federation TLS server name"))?;
        let tls = tls_config(
            &route.peer_trust_root_pem,
            &route.client_certificate_pem,
            &route.client_key_pem,
        )?;
        let expected_peer = route.expected_peer;
        let attempted = Arc::new(AtomicBool::new(false));
        let (proof_tx, proof_rx) = oneshot::channel();
        let proof_tx = Arc::new(Mutex::new(Some(proof_tx)));
        let connector = tower::service_fn(move |_uri| {
            let host = host.clone();
            let server_name = server_name.clone();
            let tls = Arc::clone(&tls);
            let attempted = Arc::clone(&attempted);
            let proof_tx = Arc::clone(&proof_tx);
            async move {
                // A tonic Channel can reconnect internally. Reusing its old
                // exporter would authenticate a different socket, so refuse
                // reconnect and require a fresh client/Session instead.
                if attempted.swap(true, Ordering::SeqCst) {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "federation TLS reconnect requires a new Session",
                    ));
                }
                let tcp = tokio::time::timeout(
                    config.tls_handshake_timeout,
                    TcpStream::connect((host.as_str(), port)),
                )
                .await
                .map_err(|_error| {
                    io::Error::new(io::ErrorKind::TimedOut, "federation TCP connect timed out")
                })??;
                let stream = tokio::time::timeout(
                    config.tls_handshake_timeout,
                    tokio_rustls::TlsConnector::from(tls).connect(server_name, tcp),
                )
                .await
                .map_err(|_error| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "federation TLS handshake timed out",
                    )
                })??;
                let proof =
                    FederationTlsChannel::from_client_tls(stream.get_ref().1, expected_peer)
                        .map_err(io::Error::other)?;
                proof_tx
                    .lock()
                    .map_err(|_error| io::Error::other("federation TLS state poisoned"))?
                    .take()
                    .ok_or_else(|| io::Error::other("federation TLS proof already consumed"))?
                    .send(proof)
                    .map_err(|_error| io::Error::other("federation TLS proof receiver closed"))?;
                Ok::<_, io::Error>(TokioIo::new(stream))
            }
        });
        let connect_timeout = config
            .tls_handshake_timeout
            .checked_mul(2)
            .ok_or_else(|| Status::invalid_argument("federation TLS timeout overflows"))?;
        let channel =
            tokio::time::timeout(connect_timeout, endpoint.connect_with_connector(connector))
                .await
                .map_err(|_error| {
                    Status::deadline_exceeded("federation channel connect timed out")
                })?
                .map_err(|_error| Status::unavailable("federation channel connection failed"))?;
        let proof = tokio::time::timeout(config.tls_handshake_timeout, proof_rx)
            .await
            .map_err(|_error| Status::deadline_exceeded("federation TLS proof timed out"))?
            .map_err(|_error| Status::unauthenticated("federation TLS proof unavailable"))?;
        Self::start(channel, proof, local, policy, runtime, inbound, permit).await
    }

    async fn start(
        channel: Channel,
        proof: FederationTlsChannel,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        runtime: FederationGrpcRuntime,
        inbound: InboundServices,
        permit: OwnedSemaphorePermit,
    ) -> Result<Self, Status> {
        let config = runtime.config();
        let local_node = local.node_id();
        let peer_node = proof
            .expected_peer
            .ok_or_else(|| Status::unauthenticated("missing pinned federation peer"))?;
        let blocking = runtime.worker_pool();
        let deadline = deadline(config.hello_timeout)?;
        let served_capabilities = if inbound.service.is_some() { 1 } else { 0 }
            | if inbound.call_store.is_some() && inbound.call_invoker.is_some() {
                2
            } else {
                0
            }
            | if inbound.object_reader.is_some() {
                4
            } else {
                0
            }
            | if inbound.snapshot_publisher.is_some() {
                8
            } else {
                0
            };
        let inbound_local = Arc::clone(&local);
        let inbound_policy = Arc::clone(&policy);
        let (mut state, initial) = on_blocking(blocking.clone(), deadline, move || {
            let mut state = FederationGrpcSubscriberSession::new(proof, local, policy, config)?;
            state.advertise_services(served_capabilities);
            let initial = state.initial_frame()?;
            Ok((state, initial))
        })
        .await?;
        let (outbound, receive) = mpsc::channel(config.control_queue_frames);
        send_until(&outbound, initial, deadline).await?;
        let mut client = pb::federation_service_client::FederationServiceClient::new(channel)
            .max_decoding_message_size(config.max_frame_bytes)
            .max_encoding_message_size(config.max_frame_bytes);
        let mut incoming = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            client.session(DeliveryRequestStream::new(receive, blocking.clone())),
        )
        .await
        .map_err(|_error| Status::deadline_exceeded("federation Session start timed out"))??
        .into_inner();
        for expected in 0..2 {
            let inbound = receive_until(&mut incoming, deadline).await?;
            let (next, event) = on_blocking(blocking.clone(), deadline, move || {
                let event = state.receive(inbound);
                Ok((state, event))
            })
            .await?;
            state = next;
            match (expected, event?) {
                (0, FederationSubscriberEvent::Send(authentication)) => {
                    send_until(&outbound, authentication, deadline).await?;
                }
                (1, FederationSubscriberEvent::Ready) => {}
                _ => {
                    return Err(Status::unauthenticated(
                        "invalid federation handshake sequence",
                    ));
                }
            }
        }
        let verified = state.verified_state()?;
        let decision = inbound_policy.receiver_decision(verified.proof)?;
        let peer_served_capabilities = verified.served_capabilities;
        let peer_max_batch_records = verified.max_batch_records;
        let peer_max_batch_bytes = verified.max_batch_bytes;
        let publisher = if let Some(service) = inbound.service {
            let mut gate = FederationGrpcPublisherSession::from_verified(
                verified,
                inbound_local,
                inbound_policy,
                service,
                config,
            )?;
            if let Some(store) = inbound.call_store {
                gate = gate.with_call_store(store)?;
            }
            if let Some(invoker) = inbound.call_invoker {
                gate = gate.with_call_invoker(invoker);
            }
            if let Some(reader) = inbound.object_reader {
                gate = gate.with_object_reader(reader)?;
            }
            if let Some((store, source)) = inbound.snapshot_publisher {
                gate = gate.with_snapshot_publisher(store, source)?;
            }
            Some(gate)
        } else {
            None
        };
        let (commands, receiver) = mpsc::channel(config.control_queue_frames);
        let (mut client, termination_sender) = Self::from_live(
            commands,
            local_node,
            peer_node,
            blocking.clone(),
            config,
            peer_max_batch_records,
            peer_max_batch_bytes,
        );
        client.decision = Some(decision);
        let actor_blocking = blocking.clone();
        let owner = runtime.task_owner();
        client.peer_served_capabilities = peer_served_capabilities;
        client._runtime = Some(runtime);
        let termination = SessionTermination::new(termination_sender);
        drop(SessionTasks::spawn(&owner, async move {
            let _permit = permit;
            let mut termination = termination;
            let result = run(
                state,
                publisher,
                incoming,
                outbound,
                receiver,
                actor_blocking,
                config,
            )
            .await;
            termination.finish(
                result
                    .err()
                    .unwrap_or_else(|| Status::cancelled("federation Session closed")),
            );
        })?);
        Ok(client)
    }

    /// Whether the authenticated peer installed this service group at Hello.
    /// This is routing evidence only; each request still requires authorization.
    pub fn serves(&self, capability: crate::ServedCapability) -> bool {
        self.peer_served_capabilities & capability as u32 != 0
    }

    pub(crate) fn bind_served_capabilities(&mut self, capabilities: u32) {
        self.peer_served_capabilities = capabilities;
    }

    /// Authenticated node at the other end of this live Session.
    pub fn peer_node(&self) -> FederationNodeId {
        self.peer_node
    }

    /// Non-wire remote authority for receiver-side business decisions.
    pub fn decision(&self) -> Result<xolotl_federation::FederationDecision, Status> {
        self.decision.clone().ok_or_else(|| {
            Status::failed_precondition("receiver atomic federation admission unavailable")
        })
    }

    pub(crate) fn bind_live_decision(&mut self, decision: xolotl_federation::FederationDecision) {
        self.decision = Some(decision);
    }

    /// Local node identity used to prove this Session.
    pub fn local_node(&self) -> FederationNodeId {
        self.local_node
    }

    /// Effective record and payload limits for one Read request on this
    /// authenticated Session. Callers doing their own durable acceptance must
    /// obey both local configuration and the peer's Hello limits.
    pub fn negotiated_batch_limits(&self) -> (usize, usize) {
        (
            self.config
                .max_batch_records
                .min(self.peer_max_batch_records),
            self.config.max_batch_bytes.min(self.peer_max_batch_bytes),
        )
    }

    /// Whether the request actor has closed or its transport has failed.
    pub fn is_closed(&self) -> bool {
        self.commands.is_closed()
    }

    /// Wait until this connection can no longer accept requests.
    pub async fn closed(&self) {
        self.commands.closed().await;
    }

    pub(crate) fn from_live(
        commands: mpsc::Sender<Command>,
        local_node: FederationNodeId,
        peer_node: FederationNodeId,
        blocking: WorkerPool,
        config: FederationGrpcConfig,
        peer_max_batch_records: usize,
        peer_max_batch_bytes: usize,
    ) -> (Self, watch::Sender<Option<Status>>) {
        let (termination_sender, termination) = watch::channel(None);
        (
            Self {
                _runtime: None,
                commands,
                termination,
                local_node,
                peer_node,
                blocking,
                config,
                peer_max_batch_records,
                peer_max_batch_bytes,
                decision: None,
                peer_served_capabilities: 0,
            },
            termination_sender,
        )
    }

    /// Open an exact subscription as this node's own principal.
    pub async fn open(&self, request: OpenRequest) -> Result<OpenResult, Status> {
        self.open_as(0, request).await
    }

    /// Inspect a public stream without creating a peer or subscription row.
    pub async fn inspect_public(&self, stream: StreamRef) -> Result<PublicStreamView, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::InspectPublic(stream, tx), rx)
            .await
    }

    /// Read a fenced page from a public stream without a subscription.
    pub async fn read_public(&self, request: PublicReadRequest) -> Result<PublicReadPage, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::ReadPublic(request, tx), rx)
            .await
    }

    /// Read an authorized object range as the node principal.
    pub async fn read_object(&self, request: ObjectReadRequest) -> Result<ObjectReadPage, Status> {
        self.read_object_as(0, request).await
    }

    /// Inspect the durable snapshot offer for a private Node-self subscription.
    pub async fn inspect_snapshot(
        &self,
        subscription: SubscriptionRef,
    ) -> Result<SnapshotOffer, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::InspectSnapshot(subscription, tx), rx)
            .await
    }

    /// Read one bounded slice from an offer returned by this publisher.
    pub async fn read_snapshot(
        &self,
        offer: SnapshotOffer,
        offset: u64,
        max_bytes: usize,
    ) -> Result<SnapshotReadChunk, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::ReadSnapshot(offer, offset, max_bytes, tx), rx)
            .await
    }

    /// Report an exact durable archive or its contiguous accepted suffix in
    /// the same receiver generation. Neither is an ordinary prefix event ACK.
    pub async fn receive_snapshot(
        &self,
        request: SnapshotReceivedRequest,
    ) -> Result<SnapshotReceived, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::ReceiveSnapshot(request, tx), rx)
            .await
    }

    /// Read an authorized object range under a registered ObjectRead subject.
    pub async fn read_object_as(
        &self,
        context_id: u32,
        request: ObjectReadRequest,
    ) -> Result<ObjectReadPage, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::ReadObject(context_id, request, tx), rx)
            .await
    }

    /// Open a subscription under a registered hosted Sync subject context.
    pub async fn open_as(
        &self,
        context_id: u32,
        request: OpenRequest,
    ) -> Result<OpenResult, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::Open(context_id, request, tx), rx)
            .await
    }

    /// `stream` is the expected publisher stream for this subscription and is
    /// checked against every record in the returned Batch.
    pub async fn read(&self, request: ReadRequest, stream: StreamRef) -> Result<ReadPage, Status> {
        self.read_as(0, request, stream).await
    }

    /// Read an exact subscription under a selected subject context.
    pub async fn read_as(
        &self,
        context_id: u32,
        request: ReadRequest,
        stream: StreamRef,
    ) -> Result<ReadPage, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::Read(context_id, request, stream, tx), rx)
            .await
    }

    /// Report one locally durable receiver position as the node principal.
    pub async fn acknowledge(&self, request: AcknowledgeRequest) -> Result<Position, Status> {
        self.acknowledge_as(0, request).await
    }

    /// Report a durable receiver position under a registered subject context.
    pub async fn acknowledge_as(
        &self,
        context_id: u32,
        request: AcknowledgeRequest,
    ) -> Result<Position, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::Acknowledge(context_id, request, tx), rx)
            .await
    }

    /// Inspect a node-self subscription's publisher-side state.
    pub async fn inspect_subscription(
        &self,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, Status> {
        self.inspect_subscription_as(0, request).await
    }

    /// Inspect a subscription under a registered hosted subject context.
    pub async fn inspect_subscription_as(
        &self,
        context_id: u32,
        request: InspectSubscriptionRequest,
    ) -> Result<SubscriptionInspection, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::Inspect(context_id, request, tx), rx)
            .await
    }

    /// Close a node-self subscription using its stable control request ID.
    pub async fn close_subscription(
        &self,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, Status> {
        self.close_subscription_as(0, request).await
    }

    /// Close a subscription under a registered subject context.
    pub async fn close_subscription_as(
        &self,
        context_id: u32,
        request: CloseSubscriptionRequest,
    ) -> Result<CloseSubscriptionResult, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::Close(context_id, request, tx), rx)
            .await
    }

    /// Register holder-proven hosted credentials on this Session and return
    /// the accepted context ID for later requests.
    pub async fn register_subject(
        &self,
        context_id: u32,
        credentials: Arc<FederationHostedSubjectCredentials>,
    ) -> Result<u32, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::RegisterSubject(context_id, credentials, tx), rx)
            .await
    }

    /// Redeem a publisher invitation for a registered Sync subject.
    pub async fn redeem_invitation_as(
        &self,
        context_id: u32,
        invitation: InvitationId,
        request_id: RequestId,
        expected_revision: u64,
        secret: Option<InvitationSecret>,
    ) -> Result<FederationInvitationReceipt, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(
            Command::RedeemInvitation(
                context_id,
                invitation,
                request_id,
                expected_revision,
                secret,
                tx,
            ),
            rx,
        )
        .await
    }

    /// Prepare a remote call under node self or a registered Invoke subject.
    pub async fn prepare_call_as(
        &self,
        context_id: u32,
        request: PrepareCallRequest,
    ) -> Result<CallPrepared, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::PrepareCall(context_id, request, tx), rx)
            .await
    }

    /// Ask the target to hand a prepared call to its durable Kernel bridge.
    pub async fn invoke_call_as(
        &self,
        context_id: u32,
        request: InvokeCallRequest,
    ) -> Result<CallInvoked, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::InvokeCall(context_id, request, tx), rx)
            .await
    }

    /// Reconcile a CallRef after a lost response or poll for its terminal.
    pub async fn inspect_call_as(
        &self,
        context_id: u32,
        request: InspectCallRequest,
    ) -> Result<CallInspection, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::InspectCall(context_id, request, tx), rx)
            .await
    }

    /// Select cancellation of an exact CallRef with a stable control request ID.
    pub async fn cancel_call_as(
        &self,
        context_id: u32,
        request: CancelCallRequest,
    ) -> Result<CallCancelled, Status> {
        let (tx, rx) = oneshot::channel();
        self.send_command(Command::CancelCall(context_id, request, tx), rx)
            .await
    }

    /// Commit the complete source intent before Prepare leaves this process.
    /// A retry with the same source ID reuses an already bound CallRef.
    pub async fn prepare_call_persisted(
        &self,
        context_id: u32,
        intent: OutboundCallIntent,
        source: Arc<dyn FederationOutboundCallStore>,
        now_ms: u64,
    ) -> Result<CallPrepared, Status> {
        self.check_source(&source, intent.target_node)?;
        let request_id = intent.request_id();
        let request = intent.request.clone();
        let staged = self
            .source_operation(Arc::clone(&source), move |store| {
                store.stage_outbound(intent, now_ms)
            })
            .await?;
        if let Some(prepared) = staged.prepared {
            return Ok(prepared);
        }
        let prepared = self.prepare_call_as(context_id, request).await?;
        let accepted = prepared.clone();
        self.source_operation(source, move |store| {
            store.bind_outbound_prepared(request_id, accepted)
        })
        .await?;
        Ok(prepared)
    }

    /// Commit that the target may have seen Invoke before sending it. A lost
    /// response must be reconciled through Inspect using the same CallRef.
    pub async fn invoke_call_persisted(
        &self,
        context_id: u32,
        request_id: RequestId,
        source: Arc<dyn FederationOutboundCallStore>,
        now_ms: u64,
    ) -> Result<CallInvoked, Status> {
        self.check_source(&source, self.peer_node)?;
        let existing = self
            .source_operation(Arc::clone(&source), move |store| {
                store.outbound_call(request_id)
            })
            .await?;
        if existing.intent.target_node != self.peer_node {
            return Err(Status::permission_denied(
                "outbound call targets another peer",
            ));
        }
        let record = self
            .source_operation(source, move |store| {
                store.mark_outbound_invoke_possible(request_id, now_ms)
            })
            .await?;
        if record.intent.target_node != self.peer_node {
            return Err(Status::permission_denied(
                "outbound call targets another peer",
            ));
        }
        let prepared = record
            .prepared
            .ok_or_else(|| Status::failed_precondition("outbound call has no CallRef"))?;
        self.invoke_call_as(
            context_id,
            InvokeCallRequest {
                authenticated_origin: self.local_node,
                subject: record.intent.request.subject,
                origin_request_id: request_id,
                call: prepared.call,
                input: record.intent.input,
            },
        )
        .await
    }

    /// Inspect a bound call and settle only a retained, proven terminal
    /// receipt. Unproven leaves the source ledger unsettled.
    pub async fn inspect_call_persisted(
        &self,
        context_id: u32,
        request_id: RequestId,
        source: Arc<dyn FederationOutboundCallStore>,
    ) -> Result<CallInspection, Status> {
        self.check_source(&source, self.peer_node)?;
        let (target_node, terminal, prepared, subject) = self
            .source_operation(Arc::clone(&source), move |store| {
                let record = store.outbound_call(request_id)?;
                Ok((
                    record.intent.target_node,
                    record.terminal,
                    record.prepared,
                    record.intent.request.subject,
                ))
            })
            .await?;
        if target_node != self.peer_node {
            return Err(Status::permission_denied(
                "outbound call targets another peer",
            ));
        }
        if let Some(terminal) = terminal {
            return Ok(terminal);
        }
        let prepared =
            prepared.ok_or_else(|| Status::failed_precondition("outbound call has no CallRef"))?;
        let inspected = self
            .inspect_call_as(
                context_id,
                InspectCallRequest {
                    authenticated_origin: self.local_node,
                    subject,
                    call: prepared.call,
                },
            )
            .await?;
        if inspected.status == xolotl_federation::CallStatus::Closed
            || (inspected.status == xolotl_federation::CallStatus::Finished
                && inspected.result.is_some())
        {
            let receipt = inspected.clone();
            self.source_operation(source, move |store| {
                store.settle_outbound(request_id, receipt).map(|_record| ())
            })
            .await?;
        }
        Ok(inspected)
    }

    fn check_source(
        &self,
        source: &Arc<dyn FederationOutboundCallStore>,
        target: FederationNodeId,
    ) -> Result<(), Status> {
        if source.local_node() != self.local_node || target != self.peer_node {
            return Err(Status::invalid_argument(
                "outbound call store or target differs from Session",
            ));
        }
        Ok(())
    }

    async fn source_operation<T: Send + 'static>(
        &self,
        source: Arc<dyn FederationOutboundCallStore>,
        operation: impl FnOnce(
            &dyn FederationOutboundCallStore,
        ) -> Result<T, xolotl_federation::FederationError>
        + Send
        + 'static,
    ) -> Result<T, Status> {
        let source = source
            .bind_outbound_decision(self.decision()?)
            .map_err(|error| wire::failure_status(wire::failure(1, &error)))?;
        on_blocking(
            self.blocking.clone(),
            deadline(self.config.response_timeout)?,
            move || {
                operation(source.as_ref())
                    .map_err(|error| wire::failure_status(wire::failure(1, &error)))
            },
        )
        .await
    }

    /// Install the authenticated Open result using the host's durable store.
    /// The stable `request_id` makes a retry safe after an indeterminate result.
    pub async fn open_and_install(
        &self,
        request: OpenRequest,
        service: &FederationService,
    ) -> Result<OpenResult, Status> {
        self.check_service(service)?;
        let opened = self.open(request).await?;
        let peer = self.peer_node;
        let installed = self
            .store_operation(service.clone(), move |service| {
                service.install_subscription(InstallSubscriptionRequest {
                    authenticated_publisher: peer,
                    opened,
                })
            })
            .await?;
        Ok(installed)
    }

    /// Accept each verified record into the durable inbox, then acknowledge
    /// the last accepted position. Partial acceptance can be retried through
    /// the store's idempotent Accept contract; no ACK is sent on accept error.
    pub async fn read_accept_ack(
        &self,
        mut request: ReadRequest,
        stream: StreamRef,
        service: &FederationService,
    ) -> Result<ReadPage, Status> {
        self.check_service(service)?;
        request.max_records = request
            .max_records
            .min(self.config.max_batch_records)
            .min(self.peer_max_batch_records);
        request.max_bytes = request
            .max_bytes
            .min(self.config.max_batch_bytes)
            .min(self.peer_max_batch_bytes);
        let subscription = request.subscription;
        let page = self.read(request, stream).await?;
        let records = page.records.clone();
        let peer = self.peer_node;
        let accepted = self
            .store_operation(service.clone(), move |service| {
                let mut last = None;
                for record in records {
                    last = Some(
                        service
                            .accept(AcceptRequest {
                                authenticated_publisher: peer,
                                subscription,
                                record,
                            })?
                            .position,
                    );
                }
                Ok(last)
            })
            .await?;
        if let Some(position) = accepted {
            self.acknowledge(AcknowledgeRequest {
                authenticated_subscriber: self.local_node,
                subscription,
                position,
            })
            .await?;
        }
        Ok(page)
    }

    fn check_service(&self, service: &FederationService) -> Result<(), Status> {
        if service.local_node() != self.local_node {
            return Err(Status::invalid_argument(
                "federation subscriber store belongs to another node",
            ));
        }
        Ok(())
    }

    async fn store_operation<T: Send + 'static>(
        &self,
        service: FederationService,
        operation: impl FnOnce(FederationService) -> Result<T, xolotl_federation::FederationError>
        + Send
        + 'static,
    ) -> Result<T, Status> {
        let service = service
            .with_decision(self.decision()?)
            .map_err(|error| wire::failure_status(wire::failure(1, &error)))?;
        on_blocking(
            self.blocking.clone(),
            deadline(self.config.response_timeout)?,
            move || {
                operation(service).map_err(|error| Status::failed_precondition(error.to_string()))
            },
        )
        .await
    }

    async fn send_command<T>(
        &self,
        command: Command,
        receiver: oneshot::Receiver<Result<T, Status>>,
    ) -> Result<T, Status> {
        let sent = tokio::time::timeout(self.config.response_timeout, self.commands.send(command))
            .await
            .map_err(|_error| Status::deadline_exceeded("federation command queue timed out"))?;
        if sent.is_err() {
            return Err(self.termination_status().await);
        }
        match tokio::time::timeout(self.config.response_timeout, receiver)
            .await
            .map_err(|_error| {
                Status::unavailable("federation operation outcome indeterminate; retry identity")
            })? {
            Ok(result) => result,
            Err(_error) => Err(self.termination_status().await),
        }
    }

    async fn termination_status(&self) -> Status {
        let mut termination = self.termination.clone();
        termination
            .wait_for(Option::is_some)
            .await
            .ok()
            .and_then(|status| status.as_ref().cloned())
            .unwrap_or_else(|| {
                Status::unavailable("federation Session actor stopped without a status")
            })
    }
}

fn tls_config(
    ca_pem: &[u8],
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<Arc<rustls::ClientConfig>, Status> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        )
    });
    let mut roots = rustls::RootCertStore::empty();
    let ca = CertificateDer::pem_reader_iter(&mut Cursor::new(ca_pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_error| Status::invalid_argument("invalid federation trust root PEM"))?;
    if ca.is_empty() {
        return Err(Status::invalid_argument("missing federation trust root"));
    }
    for certificate in ca {
        roots
            .add(certificate)
            .map_err(|_error| Status::invalid_argument("invalid federation trust root"))?;
    }
    let certificates = CertificateDer::pem_reader_iter(&mut Cursor::new(cert_pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_error| Status::invalid_argument("invalid federation client certificate PEM"))?;
    if certificates.is_empty() {
        return Err(Status::invalid_argument(
            "missing federation client certificate",
        ));
    }
    let key = PrivateKeyDer::from_pem_reader(&mut Cursor::new(key_pem))
        .map_err(|_error| Status::invalid_argument("invalid federation client key PEM"))?;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_error| Status::invalid_argument("invalid federation TLS profile"))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certificates, key)
        .map_err(|_error| Status::invalid_argument("invalid federation client certificate/key"))?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    tls.enable_early_data = false;
    tls.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(tls))
}

pub(crate) async fn run(
    mut state: FederationGrpcSubscriberSession,
    mut publisher: Option<FederationGrpcPublisherSession>,
    mut incoming: tonic::Streaming<pb::SyncFrame>,
    outbound: mpsc::Sender<DeliveryFrame>,
    mut commands: mpsc::Receiver<Command>,
    blocking: WorkerPool,
    config: FederationGrpcConfig,
) -> Result<(), Status> {
    let mut waiters = std::collections::HashMap::<u64, Waiter>::new();
    let result = loop {
        let wake = state.next_deadline().unwrap_or_else(|| {
            deadline(config.response_timeout).unwrap_or_else(|_| Instant::now())
        });
        tokio::select! {
            frame = incoming.message() => {
                let frame = match frame {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break Err(Status::unavailable("federation Session ended")),
                    Err(status) => break Err(status),
                };
                if is_request_frame(&frame) {
                    let Some(mut gate) = publisher.take() else {
                        let work_deadline = deadline(config.response_timeout).unwrap_or(wake);
                        let checked = on_blocking(blocking.clone(), work_deadline, move || {
                            let response = state.reject_unserved_request(frame)?;
                            Ok((state, response))
                        }).await;
                        let response;
                        (state, response) = match checked { Ok(value) => value, Err(status) => break Err(status) };
                        if let Err(status) = send_until(&outbound, response, work_deadline).await {
                            break Err(status);
                        }
                        continue;
                    };
                    let work_deadline = deadline(config.response_timeout).unwrap_or(wake);
                    let work = on_blocking(blocking.clone(), work_deadline, move || {
                        let response = gate.receive(frame)?;
                        let pending_invoke = gate.take_pending_invoke();
                        let pending_cancel = gate.take_pending_cancel();
                        let pending_object = gate.take_pending_object();
                        Ok((gate, response, pending_invoke, pending_cancel, pending_object))
                    }).await;
                    let (gate, response, pending_invoke, pending_cancel, pending_object) = match work {
                        Ok(value) => value,
                        Err(status) => break Err(status),
                    };
                    let response = if let Some(pending) = pending_invoke {
                        let outcome = tokio::time::timeout_at(
                            tokio::time::Instant::from_std(work_deadline),
                            pending.invoker.invoke_call(pending.call, pending.now_ms),
                        ).await.map_err(|_error| Status::unavailable("federation Invoke outcome indeterminate; inspect CallRef"));
                        match outcome {
                            Ok(value) => gate.finish_invoke(pending.request, value),
                            Err(status) => Err(status),
                        }
                    } else if let Some(pending) = pending_cancel {
                        let outcome = tokio::time::timeout_at(
                            tokio::time::Instant::from_std(work_deadline),
                            pending.invoker.cancel_call(pending.call, pending.now_ms),
                        ).await.map_err(|_error| Status::unavailable("federation Cancel outcome indeterminate; inspect CallRef"));
                        match outcome {
                            Ok(value) => gate.finish_cancel(pending.request, value),
                            Err(status) => Err(status),
                        }
                    } else if let Some(pending) = pending_object {
                        let expected = pending.read.clone();
                        let outcome = tokio::time::timeout_at(
                            tokio::time::Instant::from_std(work_deadline),
                            pending.read_page(),
                        ).await.map_err(|_error| Status::unavailable("object read outcome indeterminate; retry transfer ID"));
                        match outcome {
                            Ok(value) => gate.finish_object(pending.request, &expected, value),
                            Err(status) => Err(status),
                        }
                    } else {
                        response.ok_or_else(|| Status::internal("federation request has no response"))
                    };
                    let response = match response { Ok(value) => value, Err(status) => break Err(status) };
                    let response = match gate.response_protector().and_then(|protect| protect(response)) {
                        Ok(value) => value,
                        Err(status) => break Err(status),
                    };
                    publisher = Some(gate);
                    if let Err(status) = send_until(&outbound, response, work_deadline).await { break Err(status); }
                    continue;
                }
                let work_deadline = deadline(config.response_timeout).unwrap_or(wake);
                let work = on_blocking(blocking.clone(), work_deadline, move || {
                    let event = state.receive(frame);
                    Ok((state, event))
                }).await;
                let (next, event) = match work { Ok(value) => value, Err(status) => break Err(status) };
                state = next;
                match event {
                    Ok(FederationSubscriberEvent::Completed { request, result }) => {
                        let Some(waiter) = waiters.remove(&request) else {
                            break Err(Status::internal("federation response waiter missing"));
                        };
                        if let Err(status) = waiter.finish(result) { break Err(status); }
                    }
                    Ok(_) => break Err(Status::invalid_argument("unexpected federation handshake frame")),
                    Err(status) => break Err(status),
                }
            }
            command = commands.recv() => {
                let Some(command) = command else { break Ok(()); };
                let work_deadline = deadline(config.response_timeout).unwrap_or(wake);
                let work = on_blocking(blocking.clone(), work_deadline, move || {
                    let queued = queue_command(&mut state, command);
                    Ok((state, queued))
                }).await;
                let (next, queued) = match work { Ok(value) => value, Err(status) => break Err(status) };
                state = next;
                if let Some((request, frame, waiter)) = queued {
                    waiters.insert(request, waiter);
                    let frame = match state.protect_request(frame) {
                        Ok(value) => value,
                        Err(status) => break Err(status),
                    };
                    if let Err(status) = send_until(&outbound, frame, work_deadline).await { break Err(status); }
                }
            }
            () = tokio::time::sleep_until(tokio::time::Instant::from_std(wake)) => {
                if let Err(status) = state.check_response_deadline() { break Err(status); }
            }
        }
    };
    let status = result
        .as_ref()
        .err()
        .cloned()
        .unwrap_or_else(|| Status::cancelled("federation Session closed"));
    for (_, waiter) in waiters {
        waiter.fail(status.clone());
    }
    result
}

fn is_request_frame(frame: &pb::SyncFrame) -> bool {
    use pb::sync_frame::Body;
    matches!(
        frame.body.as_ref(),
        Some(
            Body::Open(_)
                | Body::Read(_)
                | Body::Acknowledge(_)
                | Body::Inspect(_)
                | Body::Close(_)
                | Body::RegisterSubject(_)
                | Body::PrepareCall(_)
                | Body::InvokeCall(_)
                | Body::InspectCall(_)
                | Body::CancelCall(_)
                | Body::InspectPublic(_)
                | Body::ReadPublic(_)
                | Body::ReadObject(_)
                | Body::InspectSnapshot(_)
                | Body::ReadSnapshot(_)
                | Body::ReceiveSnapshot(_)
                | Body::RedeemInvitation(_)
        )
    )
}

fn queue_command(
    state: &mut FederationGrpcSubscriberSession,
    command: Command,
) -> Option<(u64, pb::SyncFrame, Waiter)> {
    match command {
        Command::RedeemInvitation(context_id, invitation, request_id, revision, secret, tx) => {
            match state.redeem_invitation_as(context_id, invitation, request_id, revision, secret) {
                Ok((request, frame)) => Some((request, frame, Waiter::RedeemInvitation(tx))),
                Err(status) => {
                    drop(tx.send(Err(status)));
                    None
                }
            }
        }
        Command::ReadObject(context_id, value, tx) => match state.read_object_as(context_id, value)
        {
            Ok((request, frame)) => Some((request, frame, Waiter::ReadObject(tx))),
            Err(status) => {
                drop(tx.send(Err(status)));
                None
            }
        },
        Command::InspectSnapshot(subscription, tx) => match state.inspect_snapshot(subscription) {
            Ok((request, frame)) => Some((request, frame, Waiter::InspectSnapshot(tx))),
            Err(status) => {
                drop(tx.send(Err(status)));
                None
            }
        },
        Command::ReadSnapshot(offer, offset, max_bytes, tx) => {
            match state.read_snapshot(offer, offset, max_bytes) {
                Ok((request, frame)) => Some((request, frame, Waiter::ReadSnapshot(tx))),
                Err(status) => {
                    drop(tx.send(Err(status)));
                    None
                }
            }
        }
        Command::ReceiveSnapshot(value, tx) => match state.receive_snapshot(value) {
            Ok((request, frame)) => Some((request, frame, Waiter::ReceiveSnapshot(tx))),
            Err(status) => {
                drop(tx.send(Err(status)));
                None
            }
        },
        Command::InspectPublic(stream, tx) => match state.inspect_public(stream) {
            Ok((request, frame)) => Some((request, frame, Waiter::InspectPublic(tx))),
            Err(status) => {
                drop(tx.send(Err(status)));
                None
            }
        },
        Command::ReadPublic(value, tx) => match state.read_public(value) {
            Ok((request, frame)) => Some((request, frame, Waiter::ReadPublic(tx))),
            Err(status) => {
                drop(tx.send(Err(status)));
                None
            }
        },
        Command::Open(context_id, value, tx) => match state.open_as(context_id, value) {
            Ok((request, frame)) => Some((request, frame, Waiter::Open(tx))),
            Err(status) => {
                drop(tx.send(Err(status)));
                None
            }
        },
        Command::Read(context_id, value, stream, tx) => {
            match state.read_as(context_id, value, stream) {
                Ok((request, frame)) => Some((request, frame, Waiter::Read(tx))),
                Err(status) => {
                    drop(tx.send(Err(status)));
                    None
                }
            }
        }
        Command::Acknowledge(context_id, value, tx) => {
            match state.acknowledge_as(context_id, value) {
                Ok((request, frame)) => Some((request, frame, Waiter::Acknowledge(tx))),
                Err(status) => {
                    drop(tx.send(Err(status)));
                    None
                }
            }
        }
        Command::Inspect(context_id, value, tx) => match state.inspect_as(context_id, value) {
            Ok((request, frame)) => Some((request, frame, Waiter::Inspect(tx))),
            Err(status) => {
                drop(tx.send(Err(status)));
                None
            }
        },
        Command::Close(context_id, value, tx) => {
            match state.close_subscription_as(context_id, value) {
                Ok((request, frame)) => Some((request, frame, Waiter::Close(tx))),
                Err(status) => {
                    drop(tx.send(Err(status)));
                    None
                }
            }
        }
        Command::RegisterSubject(context_id, credentials, tx) => {
            match state.register_subject(context_id, credentials) {
                Ok((request, frame)) => Some((request, frame, Waiter::RegisterSubject(tx))),
                Err(status) => {
                    drop(tx.send(Err(status)));
                    None
                }
            }
        }
        Command::PrepareCall(context_id, value, tx) => {
            match state.prepare_call_as(context_id, value) {
                Ok((request, frame)) => Some((request, frame, Waiter::PrepareCall(tx))),
                Err(status) => {
                    drop(tx.send(Err(status)));
                    None
                }
            }
        }
        Command::InvokeCall(context_id, value, tx) => match state.invoke_call_as(context_id, value)
        {
            Ok((request, frame)) => Some((request, frame, Waiter::InvokeCall(tx))),
            Err(status) => {
                drop(tx.send(Err(status)));
                None
            }
        },
        Command::InspectCall(context_id, value, tx) => {
            match state.inspect_call_as(context_id, value) {
                Ok((request, frame)) => Some((request, frame, Waiter::InspectCall(tx))),
                Err(status) => {
                    drop(tx.send(Err(status)));
                    None
                }
            }
        }
        Command::CancelCall(context_id, value, tx) => match state.cancel_call_as(context_id, value)
        {
            Ok((request, frame)) => Some((request, frame, Waiter::CancelCall(tx))),
            Err(status) => {
                drop(tx.send(Err(status)));
                None
            }
        },
    }
}

fn deadline(timeout: Duration) -> Result<Instant, Status> {
    Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Status::invalid_argument("federation timeout overflows"))
}

async fn on_blocking<T, F>(blocking: WorkerPool, deadline: Instant, task: F) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, Status> + Send + 'static,
{
    blocking.run(deadline, task).await
}

async fn receive_until(
    incoming: &mut tonic::Streaming<pb::SyncFrame>,
    deadline: Instant,
) -> Result<pb::SyncFrame, Status> {
    match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), incoming.message())
        .await
    {
        Ok(Ok(Some(frame))) => Ok(frame),
        Ok(Ok(None)) => Err(Status::unauthenticated("federation handshake ended early")),
        Ok(Err(status)) => Err(status),
        Err(_error) => Err(Status::deadline_exceeded("federation handshake timed out")),
    }
}

async fn send_until(
    outbound: &mpsc::Sender<DeliveryFrame>,
    frame: impl Into<DeliveryFrame>,
    deadline: Instant,
) -> Result<(), Status> {
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        outbound.send(frame.into().with_deadline(deadline)),
    )
    .await
    .map_err(|_error| Status::deadline_exceeded("federation send timed out"))?
    .map_err(|_error| Status::cancelled("federation peer closed"))
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn client_waiter_preserves_remote_commit_claim_without_local_evidence()
    -> anyhow::Result<()> {
        use super::*;
        use crate::RemoteSyncFailure;
        for verdict in [
            pb::CommitVerdict::NotCommitted,
            pb::CommitVerdict::Committed,
            pb::CommitVerdict::Indeterminate,
            pb::CommitVerdict::Unspecified,
        ] {
            let (sender, receiver) = oneshot::channel();
            let status = wire::failure_status(pb::SyncFailure {
                request: 18,
                code: pb::FailureCode::Unavailable as i32,
                message: "private remote storage detail".into(),
                commit_verdict: verdict as i32,
            });
            Waiter::InvokeCall(sender).finish(Err(status))?;
            let Err(failure) = receiver.await? else {
                anyhow::bail!("remote failure returned success");
            };
            let remote = RemoteSyncFailure::from_status(&failure)
                .context("typed remote failure survived waiter")?;
            ensure!(remote.request == 18);
            ensure!(remote.verdict() == verdict);
            ensure!(!failure.message().contains("private"));
        }
        Ok(())
    }

    use std::{future::Future as _, task::Poll};

    use anyhow::{Context as _, ensure};

    use super::*;

    fn test_command() -> (Command, oneshot::Receiver<Result<PublicStreamView, Status>>) {
        let (sender, receiver) = oneshot::channel();
        (
            Command::InspectPublic(
                StreamRef {
                    publisher: FederationNodeId::from_bytes([2; 48]),
                    id: xolotl_federation::StreamId::from_bytes([3; 16]),
                },
                sender,
            ),
            receiver,
        )
    }

    #[tokio::test]
    async fn closed_commands_preserve_actor_status_across_handoff_and_client_clones()
    -> anyhow::Result<()> {
        for (reported, dequeued) in [(true, true), (true, false), (false, true), (false, false)] {
            let (commands, mut incoming) = mpsc::channel(1);
            let (client, termination) = FederationGrpcSubscriberClient::from_live(
                commands,
                FederationNodeId::from_bytes([1; 48]),
                FederationNodeId::from_bytes([2; 48]),
                FederationGrpcRuntime::new(
                    FederationGrpcConfig::default(),
                    Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
                )?
                .worker_pool(),
                FederationGrpcConfig::default(),
                1,
                1024,
            );
            let retained = client.clone();
            let (command, response) = test_command();
            let mut pending = std::pin::pin!(client.send_command(command, response));
            ensure!(
                std::future::poll_fn(|context| Poll::Ready(pending.as_mut().poll(context)))
                    .await
                    .is_pending()
            );
            if dequeued {
                drop(incoming.recv().await.context("queued command")?);
            }
            drop(incoming);
            ensure!(
                std::future::poll_fn(|context| Poll::Ready(pending.as_mut().poll(context)))
                    .await
                    .is_pending()
            );
            let expected = if reported {
                Status::with_details(
                    tonic::Code::DataLoss,
                    "actor protocol failure",
                    b"terminal evidence".as_slice().into(),
                )
            } else {
                Status::unavailable("federation Session actor stopped without a status")
            };
            if reported {
                termination.send_replace(Some(expected.clone()));
            }
            drop(termination);
            let failure = pending.await.err().context("failed in-flight request")?;
            ensure!(failure.code() == expected.code());
            ensure!(failure.message() == expected.message());
            ensure!(failure.details() == expected.details());
            let (command, response) = test_command();
            let failure = retained
                .send_command(command, response)
                .await
                .err()
                .context("new request on closed clone")?;
            ensure!(failure.code() == expected.code());
            ensure!(failure.message() == expected.message());
            ensure!(failure.details() == expected.details());
        }
        Ok(())
    }
}
