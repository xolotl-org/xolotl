//! Publisher-side tonic RPC driver. It admits one RPC from one proven TLS
//! connection, then processes frames serially on a bounded blocking executor.

use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Instant,
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};
use xolotl_federation::{
    FederationCallStore, FederationGuestStore, FederationInvitationStore, FederationPublicService,
    FederationService, FederationSnapshotPublisherStore, SnapshotContentSource,
};
use xolotl_proto::xolotl::v1::federation as pb;

use crate::{
    config::FederationGrpcConfig,
    delivery::{DeliveryFrame, DeliveryFuture},
    incoming::FederationTlsConnectInfo,
    runtime::{
        AbortOnDrop, FederationGrpcRuntime, SessionChildren, SessionTasks, SessionTermination,
        WorkerPool,
    },
    session::{
        FederationCallInvoker, FederationGrpcPublisherSession, FederationLocalCredentials,
        FederationObjectReader, FederationPeerPolicy,
    },
    subscriber::FederationGrpcSubscriberSession,
    subscriber_driver::{self, FederationGrpcSubscriberClient},
    tls::FederationTlsChannel,
};

type ConnectedPeers =
    HashMap<xolotl_federation::FederationNodeId, Vec<(u64, FederationGrpcSubscriberClient)>>;

/// Add `tonic_service()` to a tonic router and serve it only through
/// `federation_tls_incoming`. A plain listener or forwarded header cannot
/// produce the required private TLS connection extension and is denied.
#[derive(Clone)]
pub struct FederationGrpcPublisherServer {
    driver: PublisherDriver,
    runtime: FederationGrpcRuntime,
}

#[derive(Clone)]
struct PublisherDriver {
    service: FederationService,
    call_store: Option<Arc<dyn FederationCallStore>>,
    call_invoker: Option<Arc<dyn FederationCallInvoker>>,
    public_service: Option<FederationPublicService>,
    invitation_store: Option<Arc<dyn FederationInvitationStore>>,
    guest_store: Option<Arc<dyn FederationGuestStore>>,
    object_reader: Option<Arc<dyn FederationObjectReader>>,
    snapshot_publisher: Option<(
        Arc<dyn FederationSnapshotPublisherStore>,
        Arc<dyn SnapshotContentSource>,
    )>,
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    config: FederationGrpcConfig,
    blocking: WorkerPool,
    guest_blocking: WorkerPool,
    connected: Arc<Mutex<ConnectedPeers>>,
    next_connection: Arc<AtomicU64>,
}

impl FederationGrpcPublisherServer {
    /// Bind a local publication service to the matching signer, live peer
    /// policy, and bounded transport configuration.
    pub fn new(
        service: FederationService,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        runtime: FederationGrpcRuntime,
    ) -> Result<Self, Status> {
        let config = runtime.config();
        if service.local_node() != local.node_id() {
            return Err(Status::invalid_argument(
                "federation signer does not belong to the local store",
            ));
        }
        Ok(Self {
            driver: PublisherDriver {
                service,
                call_store: None,
                call_invoker: None,
                public_service: None,
                invitation_store: None,
                guest_store: None,
                object_reader: None,
                snapshot_publisher: None,
                local,
                policy,
                config,
                blocking: runtime.worker_pool(),
                guest_blocking: runtime.worker_pool(),
                connected: Arc::new(Mutex::new(HashMap::new())),
                next_connection: Arc::new(AtomicU64::new(1)),
            },
            runtime,
        })
    }

    /// Install an atomic, durable call directory for this local node.
    pub fn with_call_store(mut self, store: Arc<dyn FederationCallStore>) -> Result<Self, Status> {
        if store.local_node() != self.driver.service.local_node() {
            return Err(Status::invalid_argument(
                "federation call store belongs to another node",
            ));
        }
        self.driver.call_store = Some(store);
        Ok(self)
    }

    /// Enable Invoke only after the host installs a checked Kernel bridge.
    pub fn with_call_invoker(mut self, invoker: Arc<dyn FederationCallInvoker>) -> Self {
        self.driver.call_invoker = Some(invoker);
        self
    }

    /// Expose only streams with an explicit public policy to authenticated
    /// nodes lacking a configured peer relationship.
    pub fn with_public_service(mut self, service: FederationPublicService) -> Result<Self, Status> {
        if service.store().local_node() != self.driver.service.local_node() {
            return Err(Status::invalid_argument(
                "public service belongs to another node",
            ));
        }
        self.driver.public_service = Some(service);
        Ok(self)
    }

    /// Enable holder-proven invitation redemption on this listener.
    pub fn with_invitation_store(
        mut self,
        store: Arc<dyn FederationInvitationStore>,
    ) -> Result<Self, Status> {
        if store.local_node() != self.driver.service.local_node() {
            return Err(Status::invalid_argument(
                "invitation store belongs to another node",
            ));
        }
        self.driver.invitation_store = Some(store);
        Ok(self)
    }

    /// Serve exact, time-bounded guest subscription grants after redemption.
    pub fn with_guest_store(mut self, store: Arc<dyn FederationGuestStore>) -> Self {
        self.driver.guest_store = Some(store);
        self
    }

    /// Serve exact authorized object ranges through this node's object port.
    pub fn with_object_reader(
        mut self,
        reader: Arc<dyn FederationObjectReader>,
    ) -> Result<Self, Status> {
        if reader.local_node() != self.driver.service.local_node() {
            return Err(Status::invalid_argument(
                "object reader belongs to another node",
            ));
        }
        self.driver.object_reader = Some(reader);
        Ok(self)
    }

    /// Serve a pinned application snapshot through the authenticated private
    /// Session. The content source runs on the server's bounded blocking pool.
    pub fn with_snapshot_publisher(
        mut self,
        store: Arc<dyn FederationSnapshotPublisherStore>,
        source: Arc<dyn SnapshotContentSource>,
    ) -> Result<Self, Status> {
        if store.local_node() != self.driver.service.local_node() {
            return Err(Status::invalid_argument(
                "snapshot publisher belongs to another node",
            ));
        }
        self.driver.snapshot_publisher = Some((store, source));
        Ok(self)
    }

    /// Select the most recent live authenticated Session serving the required
    /// group. Ordinary outbound-only sessions cannot shadow reverse services.
    /// Reuses the runtime-bounded registry; disconnect releases its entry.
    /// Service advertisement is not a grant and requests retain authorization.
    pub fn connected_peer(
        &self,
        peer: xolotl_federation::FederationNodeId,
        capability: crate::ServedCapability,
    ) -> Option<FederationGrpcSubscriberClient> {
        self.driver
            .connected
            .lock()
            .ok()?
            .get(&peer)
            .and_then(|sessions| {
                sessions
                    .iter()
                    .rev()
                    .find(|(_, client)| !client.is_closed() && client.serves(capability))
            })
            .map(|(_, client)| client.clone())
    }

    /// Apply the limit in tonic before protobuf decoding or compression can
    /// allocate an unbounded message. The session checks decoded frames again.
    pub fn tonic_service(self) -> pb::federation_service_server::FederationServiceServer<Self> {
        let max_frame_bytes = self.driver.config.max_frame_bytes;
        pb::federation_service_server::FederationServiceServer::new(self)
            .max_decoding_message_size(max_frame_bytes)
            .max_encoding_message_size(max_frame_bytes)
    }
}

/// Publisher response stream whose Drop interrupts its owned session actor.
/// Accepted blocking operations remain in the host drain; dropping a response
/// is not evidence of cancellation or rollback of an accepted effect.
/// Protected replies carry their locally admitted authority through both
/// queues. Final-poll authorization uses one pending bounded host blocking
/// job per stream, within the original response deadline. Completion hands
/// off immediately, without repeating payload reads, quotas or effects.
pub struct FederationGrpcPublisherStream {
    receiver: Option<ReceiverStream<Result<DeliveryFrame, Status>>>,
    _actor: AbortOnDrop,
    closed: bool,
    blocking: WorkerPool,
    pending: Option<DeliveryFuture>,
}

impl FederationGrpcPublisherStream {
    pub(crate) fn new(
        receiver: mpsc::Receiver<Result<DeliveryFrame, Status>>,
        abort: tokio::task::AbortHandle,
        blocking: WorkerPool,
    ) -> Self {
        Self {
            receiver: Some(ReceiverStream::new(receiver)),
            _actor: AbortOnDrop(abort),
            closed: false,
            blocking,
            pending: None,
        }
    }
}

impl Stream for FederationGrpcPublisherStream {
    type Item = Result<pb::SyncFrame, Status>;
    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.closed {
            return Poll::Ready(None);
        }
        if self.pending.is_none() {
            let Some(receiver) = self.receiver.as_mut() else {
                return Poll::Ready(None);
            };
            match Pin::new(receiver).poll_next(context) {
                Poll::Ready(Some(Ok(frame))) => {
                    self.pending = Some(frame.start(self.blocking.clone()))
                }
                Poll::Ready(Some(Err(status))) => {
                    self.closed = true;
                    self.receiver.take();
                    self._actor.0.abort();
                    return Poll::Ready(Some(Err(status)));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
        let Some(pending) = self.pending.as_mut() else {
            return Poll::Ready(None);
        };
        match pending.as_mut().poll(context) {
            Poll::Ready(result) => {
                self.pending.take();
                if result.is_err() {
                    self.closed = true;
                    self.receiver.take();
                    self._actor.0.abort();
                }
                Poll::Ready(Some(result))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

struct ConnectedSession {
    connected: Arc<Mutex<ConnectedPeers>>,
    peer: xolotl_federation::FederationNodeId,
    connection_id: u64,
    termination: SessionTermination,
}

impl Drop for ConnectedSession {
    fn drop(&mut self) {
        let mut connected = self
            .connected
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(sessions) = connected.get_mut(&self.peer) {
            sessions.retain(|(id, _)| *id != self.connection_id);
            if sessions.is_empty() {
                connected.remove(&self.peer);
            }
        }
    }
}

#[tonic::async_trait]
impl pb::federation_service_server::FederationService for FederationGrpcPublisherServer {
    type SessionStream = FederationGrpcPublisherStream;

    async fn session(
        &self,
        request: Request<tonic::Streaming<pb::SyncFrame>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let (channel, permit) = request
            .extensions()
            .get::<FederationTlsConnectInfo>()
            .ok_or_else(|| Status::unauthenticated("verified federation TLS connection required"))?
            .take_channel()?;
        if !self.runtime.owns_permit(&permit) {
            return Err(Status::failed_precondition(
                "federation incoming and publisher runtime differ",
            ));
        }
        let incoming = request.into_inner();
        let (outbound, receiver) = mpsc::channel(1);
        let server = self.driver.clone();
        let owner = self.runtime.task_owner();
        let actor_owner = owner.clone();
        let abort = SessionTasks::spawn(&owner, async move {
            if let Err(status) = server
                .drive(channel, incoming, &outbound, permit, actor_owner)
                .await
            {
                drop(
                    tokio::time::timeout(
                        server.config.response_timeout,
                        outbound.send(Err(status)),
                    )
                    .await,
                );
            }
        })?;
        Ok(Response::new(FederationGrpcPublisherStream::new(
            receiver,
            abort,
            self.driver.blocking.clone(),
        )))
    }
}

impl PublisherDriver {
    async fn drive(
        &self,
        channel: FederationTlsChannel,
        mut incoming: tonic::Streaming<pb::SyncFrame>,
        outbound: &mpsc::Sender<Result<DeliveryFrame, Status>>,
        session_permit: OwnedSemaphorePermit,
        owner: std::sync::Weak<SessionTasks>,
    ) -> Result<(), Status> {
        let session_permit = Arc::new(session_permit);
        let deadline = Instant::now()
            .checked_add(self.config.hello_timeout)
            .ok_or_else(|| Status::invalid_argument("federation Hello timeout overflows"))?;
        let local = Arc::clone(&self.local);
        let policy = Arc::clone(&self.policy);
        let service = self.service.clone();
        let call_store = self.call_store.clone();
        let call_invoker = self.call_invoker.clone();
        let public_service = self.public_service.clone();
        let invitation_store = self.invitation_store.clone();
        let guest_store = self.guest_store.clone();
        let object_reader = self.object_reader.clone();
        let snapshot_publisher = self.snapshot_publisher.clone();
        let config = self.config;
        let (mut session, initial) = self
            .on_blocking(deadline, move || {
                let mut session =
                    FederationGrpcPublisherSession::new(channel, local, policy, service, config)?;
                if let Some(store) = call_store {
                    session = session.with_call_store(store)?;
                }
                if let Some(invoker) = call_invoker {
                    session = session.with_call_invoker(invoker);
                }
                if let Some(public) = public_service {
                    session = session.with_public_service(public)?;
                }
                if let Some(store) = invitation_store {
                    session = session.with_invitation_store(store)?;
                }
                if let Some(store) = guest_store {
                    session = session.with_guest_store(store);
                }
                if let Some(reader) = object_reader {
                    session = session.with_object_reader(reader)?;
                }
                if let Some((store, source)) = snapshot_publisher {
                    session = session.with_snapshot_publisher(store, source)?;
                }
                let initial = session.initial_frame()?;
                Ok((session, initial))
            })
            .await?;
        send_until(outbound, initial, deadline).await?;

        let hello = receive_until(&mut incoming, deadline).await?;
        let (next, authentication) = self
            .on_blocking(deadline, move || {
                let authentication = session.receive(hello)?;
                Ok((session, authentication))
            })
            .await?;
        session = next;
        let authentication = authentication
            .ok_or_else(|| Status::internal("federation Hello did not produce proof"))?;
        send_until(outbound, authentication, deadline).await?;

        let proof = receive_until(&mut incoming, deadline).await?;
        session = self
            .on_blocking(deadline, move || {
                if session.receive(proof)?.is_some() {
                    return Err(Status::internal("unexpected federation proof response"));
                }
                Ok(session)
            })
            .await?;

        if session.is_limited_reader() {
            return self
                .drive_public(session, incoming, outbound, owner, session_permit)
                .await;
        }

        let verified = session.verified_state()?;
        let decision = xolotl_federation::FederationDecision::new(
            verified.proof,
            xolotl_federation::FederationAdmission::Private,
            self.policy.decision_clock()?,
        );
        let peer = verified.proof.node_id();
        let peer_served_capabilities = verified.served_capabilities;
        let peer_max_batch_records = verified.max_batch_records;
        let peer_max_batch_bytes = verified.max_batch_bytes;
        let subscriber = FederationGrpcSubscriberSession::from_verified(
            verified,
            Arc::clone(&self.local),
            Arc::clone(&self.policy),
            self.config,
        )?;
        let (commands, receiver) = mpsc::channel(self.config.control_queue_frames);
        let (mut handle, termination) = FederationGrpcSubscriberClient::from_live(
            commands,
            self.local.node_id(),
            peer,
            self.blocking.clone(),
            self.config,
            peer_max_batch_records,
            peer_max_batch_bytes,
        );
        handle.bind_served_capabilities(peer_served_capabilities);
        handle.bind_live_decision(decision);
        let connection_id = self.next_connection.fetch_add(1, Ordering::Relaxed);
        let mut connection = ConnectedSession {
            connected: Arc::clone(&self.connected),
            peer,
            connection_id,
            termination: SessionTermination::new(termination),
        };
        self.connected
            .lock()
            .map_err(|_error| Status::internal("federation connection registry poisoned"))?
            .entry(peer)
            .or_default()
            .push((connection_id, handle));
        let (raw_outbound, mut raw_receiver) = mpsc::channel(self.config.control_queue_frames);
        let forwarding = outbound.clone();
        let forward_permit = Arc::clone(&session_permit);
        let (forwarded_tx, forwarded) = tokio::sync::oneshot::channel();
        let forward = AbortOnDrop(SessionTasks::spawn(&owner, async move {
            let _permit = forward_permit;
            let result = async {
                while let Some(frame) = raw_receiver.recv().await {
                    let deadline = Instant::now()
                        .checked_add(config.response_timeout)
                        .ok_or_else(|| {
                            Status::invalid_argument("federation response timeout overflows")
                        })?;
                    send_until(&forwarding, frame, deadline).await?;
                }
                Ok::<(), Status>(())
            }
            .await;
            drop(forwarded_tx.send(result));
        })?);
        let result = subscriber_driver::run(
            subscriber,
            Some(session),
            incoming,
            raw_outbound,
            receiver,
            self.blocking.clone(),
            self.config,
        )
        .await;
        connection.termination.finish(
            result
                .as_ref()
                .err()
                .cloned()
                .unwrap_or_else(|| Status::cancelled("federation Session closed")),
        );
        drop(connection);
        let forwarded = forwarded
            .await
            .map_err(|_error| Status::unavailable("federation forwarding task interrupted"))?;
        drop(forward);
        result.and(forwarded)
    }

    async fn drive_public(
        &self,
        mut session: FederationGrpcPublisherSession,
        mut incoming: tonic::Streaming<pb::SyncFrame>,
        outbound: &mpsc::Sender<Result<DeliveryFrame, Status>>,
        owner: std::sync::Weak<SessionTasks>,
        session_permit: Arc<OwnedSemaphorePermit>,
    ) -> Result<(), Status> {
        let mut children = SessionChildren::new(owner);
        let guest_slots = Arc::new(Semaphore::new(self.config.max_in_flight));
        loop {
            let deadline = Instant::now()
                .checked_add(self.config.response_timeout)
                .ok_or_else(|| Status::invalid_argument("federation response timeout overflows"))?;
            let frame = match tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                incoming.message(),
            )
            .await
            {
                Ok(Ok(Some(frame))) => frame,
                Ok(Ok(None)) => return Ok(()),
                Ok(Err(status)) => return Err(status),
                Err(_) => {
                    return Err(Status::deadline_exceeded(
                        "public federation read timed out",
                    ));
                }
            };
            let (next, response, pending_object, pending_guest) = self
                .on_blocking(deadline, move || {
                    let response = session.receive(frame)?;
                    let pending_object = session.take_pending_object();
                    let pending_guest = session.take_pending_guest();
                    Ok((session, response, pending_object, pending_guest))
                })
                .await?;
            session = next;
            let protect = session.response_protector()?;
            if let Some(pending) = pending_guest {
                let slot = Arc::clone(&guest_slots)
                    .try_acquire_owned()
                    .map_err(|_error| {
                        Status::resource_exhausted("guest operation in-flight limit reached")
                    })?;
                let server = self.clone();
                let outbound = outbound.clone();
                let permit = Arc::clone(&session_permit);
                children.spawn(async move {
                    let _permit = permit;
                    let _slot = slot;
                    let outcome = server
                        .on_guest_blocking(deadline, move || pending.execute())
                        .await;
                    match outcome {
                        Ok(response) => match protect(response) {
                            Ok(response) => {
                                drop(send_until(&outbound, response, deadline).await);
                            }
                            Err(status) => {
                                drop(outbound.send(Err(status)).await);
                            }
                        },
                        Err(status) => {
                            drop(outbound.send(Err(status)).await);
                        }
                    }
                })?;
                continue;
            }
            if let Some(pending) = pending_object {
                let slot = Arc::clone(&guest_slots)
                    .try_acquire_owned()
                    .map_err(|_error| {
                        Status::resource_exhausted("limited federation in-flight limit reached")
                    })?;
                let outbound = outbound.clone();
                let permit = Arc::clone(&session_permit);
                children.spawn(async move {
                    let _permit = permit;
                    let _slot = slot;
                    match pending.execute(deadline).await {
                        Ok(response) => match protect(response) {
                            Ok(response) => {
                                drop(send_until(&outbound, response, deadline).await);
                            }
                            Err(status) => {
                                drop(outbound.send(Err(status)).await);
                            }
                        },
                        Err(status) => {
                            drop(outbound.send(Err(status)).await);
                        }
                    }
                })?;
                continue;
            }
            let response =
                response.ok_or_else(|| Status::internal("public request has no response"))?;
            send_until(outbound, protect(response)?, deadline).await?;
        }
    }

    async fn on_blocking<T, F>(&self, deadline: Instant, task: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, Status> + Send + 'static,
    {
        self.blocking.run(deadline, task).await
    }

    async fn on_guest_blocking<T, F>(&self, deadline: Instant, task: F) -> Result<T, Status>
    where
        T: Send + 'static,
        F: FnOnce() -> Result<T, Status> + Send + 'static,
    {
        self.guest_blocking.run(deadline, task).await
    }
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
        Err(_elapsed) => Err(Status::deadline_exceeded("federation handshake timed out")),
    }
}

async fn send_until(
    outbound: &mpsc::Sender<Result<DeliveryFrame, Status>>,
    frame: impl Into<DeliveryFrame>,
    deadline: Instant,
) -> Result<(), Status> {
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        outbound.send(Ok(frame.into().with_deadline(deadline))),
    )
    .await
    .map_err(|_elapsed| Status::deadline_exceeded("federation send timed out"))?
    .map_err(|_closed| Status::cancelled("federation peer closed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Result, ensure};
    use xolotl_federation::FederationNodeId;
    use xolotl_kernel::host::TokioBlockingSpawner;

    #[tokio::test]
    async fn response_drop_cleans_registry_and_shutdown_joins_blocked_forwarding() -> Result<()> {
        let runtime = FederationGrpcRuntime::new(
            FederationGrpcConfig {
                max_sessions: 1,
                ..FederationGrpcConfig::default()
            },
            Arc::new(TokioBlockingSpawner::default()),
        )?;
        let owner = runtime.task_owner();
        let peer = FederationNodeId::from_bytes([2; 48]);
        let (commands, receiver) = mpsc::channel(1);
        let (client, termination) = FederationGrpcSubscriberClient::from_live(
            commands,
            FederationNodeId::from_bytes([1; 48]),
            peer,
            runtime.worker_pool(),
            runtime.config(),
            1,
            1,
        );
        let connected = Arc::new(Mutex::new(HashMap::from([(
            peer,
            vec![(7, client.clone())],
        )])));
        let connection = ConnectedSession {
            connected: connected.clone(),
            peer,
            connection_id: 7,
            termination: SessionTermination::new(termination),
        };
        let permit = runtime.admit()?;
        let (outbound, output) = mpsc::channel(1);
        outbound
            .send(Ok(pb::SyncFrame { body: None }.into()))
            .await?;
        let (started, ready) = tokio::sync::oneshot::channel();
        let (resource, released) = tokio::sync::oneshot::channel::<()>();
        let actor_owner = owner.clone();
        let abort = SessionTasks::spawn(&owner, async move {
            let _connection = connection;
            let _permit = permit;
            let _commands = receiver;
            let mut children = SessionChildren::new(actor_owner);
            let spawned = children.spawn(async move {
                let _resource = resource;
                started.send(()).unwrap_or(());
                drop(outbound.send(Ok(pb::SyncFrame { body: None }.into())).await);
            });
            if spawned.is_err() {
                return;
            }
            std::future::pending::<()>().await;
        })?;
        let response = FederationGrpcPublisherStream::new(output, abort, runtime.worker_pool());
        ready.await?;
        drop(response);
        runtime.shutdown().await;
        ensure!(released.await.is_err());
        ensure!(
            connected
                .lock()
                .map_err(|error| anyhow::anyhow!("{error}"))?
                .is_empty()
        );
        ensure!(client.is_closed());
        client.closed().await;
        Ok(())
    }
}
