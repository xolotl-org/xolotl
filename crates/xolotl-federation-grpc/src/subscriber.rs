//! Subscriber-side state for one exporter-bound Session. The transport owns
//! framing and I/O; this state machine owns admission and request correlation.

use std::{collections::HashMap, sync::Arc, time::Instant};

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use prost::Message as _;
use tonic::Status;
use xolotl_federation::{
    AcknowledgeRequest, CallCancelled, CallInspection, CallInvoked, CallPrepared, CallRef,
    CancelCallRequest, CloseSubscriptionRequest, CloseSubscriptionResult, ExportName,
    FederationNodeId, FederationSessionTranscript, FederationSubject, HostedSubject,
    InspectCallRequest, InspectSubscriptionRequest, InvitationId, InvitationSecret,
    InvokeCallRequest, MAX_SNAPSHOT_CHUNK_BYTES, ObjectReadPage, ObjectReadRequest, OpenRequest,
    OpenResult, Position, PrepareCallRequest, PublicReadPage, PublicReadRequest, PublicStreamView,
    ReadPage, ReadRequest, RequestId, SnapshotOffer, SnapshotReadChunk, SnapshotReadRequest,
    SnapshotReceived, SnapshotReceivedRequest, StreamRef, SubjectAssertion, SubjectHolderKey,
    SubjectIssuer, SubjectPurpose, SubscriptionInspection, SubscriptionRef,
    VerifiedFederationPeerProof, verify_federation_peer_proof,
};
use xolotl_proto::xolotl::v1::federation as pb;

use crate::{
    config::FederationGrpcConfig,
    session::{FederationLocalCredentials, FederationPeerPolicy, VerifiedSession},
    tls::{FederationTlsChannel, LocalRole},
    wire::{self, PeerHello},
};

#[derive(Clone, Copy)]
struct Limits {
    served_capabilities: u32,
    frame_bytes: usize,
    in_flight: usize,
    batch_records: usize,
    batch_bytes: usize,
}

enum Phase {
    New,
    AwaitHello,
    AwaitAuthenticate {
        peer: Box<PeerHello>,
        transcript: FederationSessionTranscript,
    },
    Ready {
        proof: VerifiedFederationPeerProof,
        limits: Limits,
        transcript: Arc<FederationSessionTranscript>,
    },
    Closed,
}

enum PendingKind {
    RedeemInvitation {
        invitation: InvitationId,
        request_id: RequestId,
        subject: HostedSubject,
    },
    ReadObject {
        transfer: xolotl_federation::ObjectTransferId,
        grant: xolotl_federation::ObjectGrantId,
        revision: u64,
        offset: u64,
        max_bytes: usize,
        object_size: u64,
    },
    InspectSnapshot {
        subscription: SubscriptionRef,
    },
    ReadSnapshot {
        offer: SnapshotOffer,
        offset: u64,
        max_bytes: usize,
    },
    ReceiveSnapshot {
        expected: SnapshotReceivedRequest,
    },
    InspectPublic {
        stream: StreamRef,
    },
    ReadPublic {
        stream: StreamRef,
        revision: u64,
        after: Option<Position>,
        max_records: usize,
        max_bytes: usize,
    },
    Open {
        request_id: RequestId,
        subscription: SubscriptionRef,
        stream: StreamRef,
    },
    Read {
        subscription: SubscriptionRef,
        stream: StreamRef,
        after: Option<Position>,
        max_records: usize,
        max_bytes: usize,
    },
    Acknowledge {
        position: Position,
    },
    Inspect {
        subscription: SubscriptionRef,
    },
    Close {
        request_id: RequestId,
        subscription: SubscriptionRef,
    },
    RegisterSubject {
        context_id: u32,
        credentials: Arc<FederationHostedSubjectCredentials>,
    },
    PrepareCall {
        origin_request_id: RequestId,
        prepare_deadline_ms: u64,
        execution_deadline_ms: u64,
        result_retention_ms: u64,
    },
    InvokeCall {
        call: CallRef,
    },
    InspectCall {
        call: CallRef,
    },
    CancelCall {
        call: CallRef,
        control_request_id: RequestId,
    },
}

struct Pending {
    kind: PendingKind,
    deadline: Instant,
}

/// A successful response retains its request number so the host can route it
/// to the exact waiter. A business `Failure` is returned as `Err(Status)` in
/// `Completed`; malformed and unmatched frames fail the entire session.
#[derive(Debug)]
pub enum FederationSubscriberEvent {
    /// Send the enclosed frame on the same authenticated Session stream.
    Send(pb::SyncFrame),
    /// Both peer proofs and negotiated transport bounds were accepted.
    Ready,
    /// One numbered request completed with either a typed result or business failure.
    Completed {
        /// Local request number returned when the request frame was created.
        request: u64,
        /// Correlated response; a business rejection does not close the Session.
        result: Result<FederationSubscriberResult, Status>,
    },
}

/// Typed business response to a subscriber request.
#[derive(Debug)]
pub enum FederationSubscriberResult {
    /// Invitation exchange and resulting exact subject grant.
    InvitationRedeemed(FederationInvitationReceipt),
    /// One bounded, independently verified object range.
    ObjectChunk(ObjectReadPage),
    /// Publisher's durable offer for one private Node-self subscription.
    SnapshotOffered(SnapshotOffer),
    /// One authenticated bounded slice of a pinned application snapshot.
    SnapshotChunk(SnapshotReadChunk),
    /// Publisher's durable receipt for an exact archived transport baseline.
    SnapshotReceived(SnapshotReceived),
    /// Current public stream policy and head.
    PublicInspected(PublicStreamView),
    /// Bounded page from a public stream.
    PublicBatch(PublicReadPage),
    /// Publisher's persisted subscription opening.
    Opened(OpenResult),
    /// Bounded page for an installed subscription.
    Batch(ReadPage),
    /// Publisher accepted the named durable receipt position.
    Acknowledged(Position),
    /// Current remote subscription view.
    Inspected(SubscriptionInspection),
    /// Publisher's persisted close result.
    Closed(CloseSubscriptionResult),
    /// Hosted-subject context accepted for this Session.
    SubjectRegistered(u32),
    /// Durable remote call preparation receipt.
    CallPrepared(CallPrepared),
    /// Durable remote Kernel handoff status.
    CallInvoked(CallInvoked),
    /// Current remote call receipt or terminal.
    CallInspected(CallInspection),
    /// Remote cancellation request receipt.
    CallCancelled(CallCancelled),
}

/// The stable receipt for an invitation exchange. `currently_authorized` is
/// re-evaluated by the host on retry; the holder must still use the grant's
/// exact stream, subject and presenter on every later operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationInvitationReceipt {
    /// Invitation presented to the publisher.
    pub invitation: InvitationId,
    /// Idempotency key of this redemption.
    pub request_id: RequestId,
    /// Hosted subject to which the grant was issued.
    pub subject: HostedSubject,
    /// Exact authorized stream.
    pub stream: StreamRef,
    /// Persisted subject-grant revision.
    pub grant_revision: u64,
    /// Expiration of the resulting grant in trusted milliseconds.
    pub grant_expires_ms: u64,
    /// Earliest history sequence included in the grant.
    pub history_floor: u64,
    /// Whether current authority still permits this grant at response time.
    pub currently_authorized: bool,
}

/// Holder-owned assertion material for one hosted subject. The private holder
/// key remains with this client and signs registration and every hosted frame.
pub struct FederationHostedSubjectCredentials {
    issuer_descriptor: Vec<u8>,
    assertion: SubjectAssertion,
    issuer_signature: Vec<u8>,
    holder: Arc<SubjectHolderKey>,
}

impl FederationHostedSubjectCredentials {
    /// Assemble credentials only when the assertion, issuer and holder key
    /// identify the same subject. The holder key remains local.
    pub fn new(
        issuer: &SubjectIssuer,
        assertion: SubjectAssertion,
        issuer_signature: Vec<u8>,
        holder: Arc<SubjectHolderKey>,
    ) -> Result<Self, Status> {
        if assertion.subject().issuer != issuer.id()
            || issuer_signature.len() != xolotl_federation::FederationRoot::SIGNATURE_LEN
            || holder.public_key() != assertion.holder_public_key()
        {
            return Err(Status::invalid_argument(
                "invalid hosted subject credentials",
            ));
        }
        Ok(Self {
            issuer_descriptor: issuer.encode(),
            assertion,
            issuer_signature,
            holder,
        })
    }
}

/// A single TLS connection's subscriber protocol state. `channel` must be
/// extracted from the completed rustls connection carrying this very RPC.
/// The built-in client constructs it internally; custom hosts must preserve
/// the same socket-to-Session pairing.
pub struct FederationGrpcSubscriberSession {
    channel: FederationTlsChannel,
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    config: FederationGrpcConfig,
    local_hello: pb::Hello,
    handshake_deadline: Instant,
    last_time_ms: u64,
    phase: Phase,
    next_request: u64,
    last_unserved_request: u64,
    pending: HashMap<u64, Pending>,
    registered: HashMap<u32, Arc<FederationHostedSubjectCredentials>>,
}

impl FederationGrpcSubscriberSession {
    pub(crate) fn protect_request(
        &self,
        frame: pb::SyncFrame,
    ) -> Result<crate::delivery::DeliveryFrame, Status> {
        use pb::sync_frame::Body;
        let Phase::Ready { proof, .. } = &self.phase else {
            return Err(Status::failed_precondition("delivery Session is not ready"));
        };
        let context = match frame.body.as_ref() {
            Some(Body::Open(value)) => value.context_id,
            Some(Body::Read(value)) => value.context_id,
            Some(Body::Acknowledge(value)) => value.context_id,
            Some(Body::Inspect(value)) => value.context_id,
            Some(Body::Close(value)) => value.context_id,
            Some(Body::PrepareCall(value)) => value.context_id,
            Some(Body::InvokeCall(value)) => value.context_id,
            Some(Body::InspectCall(value)) => value.context_id,
            Some(Body::CancelCall(value)) => value.context_id,
            Some(Body::ReadObject(value)) => value.context_id,
            Some(Body::RedeemInvitation(value)) => value.context_id,
            _ => 0,
        };
        let deadline = if let Some(Body::RegisterSubject(value)) = frame.body.as_ref() {
            self.pending
                .get(&value.request)
                .and_then(|pending| {
                    if let PendingKind::RegisterSubject { credentials, .. } = &pending.kind {
                        Some(credentials.assertion.expires_ms())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| Status::permission_denied("subject registration was not admitted"))?
        } else if context != 0 {
            self.registered
                .get(&context)
                .ok_or_else(|| Status::permission_denied("delivery subject unavailable"))?
                .assertion
                .expires_ms()
        } else {
            u64::MAX
        };
        let proof = *proof;
        let floor = self.last_time_ms;
        let local = Arc::clone(&self.local);
        let policy = Arc::clone(&self.policy);
        Ok(crate::delivery::DeliveryFrame::protected(
            frame,
            Arc::new(move || {
                let now = policy.current_time_ms()?;
                if now < floor || now >= proof.expires_ms() || now >= deadline {
                    return Err(Status::permission_denied(
                        "federation request delivery authority expired",
                    ));
                }
                local.check_validity(now)?;
                policy.check_current_peer(proof, now)
            }),
        ))
    }

    pub(crate) fn from_verified(
        verified: VerifiedSession,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        config: FederationGrpcConfig,
    ) -> Result<Self, Status> {
        let config = config.validate()?;
        if verified.proof.node_id() == local.node_id() {
            return Err(Status::invalid_argument(
                "federation peer is the local node",
            ));
        }
        let now_ms = policy.current_time_ms()?;
        local.check_validity(now_ms)?;
        policy.check_current_peer(verified.proof, now_ms)?;
        Ok(Self {
            channel: verified.channel,
            local,
            policy,
            config,
            local_hello: pb::Hello::default(),
            handshake_deadline: Instant::now(),
            last_time_ms: now_ms,
            phase: Phase::Ready {
                proof: verified.proof,
                limits: Limits {
                    served_capabilities: verified.served_capabilities,
                    frame_bytes: verified.max_frame_bytes,
                    in_flight: verified.max_in_flight.min(config.max_in_flight),
                    batch_records: verified.max_batch_records,
                    batch_bytes: verified.max_batch_bytes,
                },
                transcript: verified.transcript,
            },
            next_request: 1,
            last_unserved_request: 0,
            pending: HashMap::new(),
            registered: HashMap::new(),
        })
    }

    pub(crate) fn reject_unserved_request(
        &mut self,
        frame: pb::SyncFrame,
    ) -> Result<pb::SyncFrame, Status> {
        self.peer()?;
        if frame.encoded_len() > self.config.max_frame_bytes {
            return Err(Status::resource_exhausted(
                "federation frame exceeds local limit",
            ));
        }
        let Some((request, _)) = frame.body.as_ref().and_then(wire::request_service) else {
            return Err(Status::invalid_argument("unsupported federation request"));
        };
        if request <= self.last_unserved_request {
            return Err(Status::invalid_argument(
                "replayed federation request correlation",
            ));
        }
        self.last_unserved_request = request;
        Ok(wire::service_unavailable(request))
    }

    pub(crate) fn advertise_services(&mut self, served_capabilities: u32) {
        self.local_hello.served_capabilities = served_capabilities;
    }

    pub(crate) fn verified_state(&self) -> Result<VerifiedSession, Status> {
        let Phase::Ready {
            proof,
            limits,
            transcript,
        } = &self.phase
        else {
            return Err(Status::failed_precondition(
                "federation peer is not authenticated",
            ));
        };
        Ok(VerifiedSession {
            channel: self.channel.paired_after_verification(proof.node_id()),
            proof: *proof,
            transcript: Arc::clone(transcript),
            max_frame_bytes: limits.frame_bytes,
            max_in_flight: limits.in_flight,
            max_batch_records: limits.batch_records,
            max_batch_bytes: limits.batch_bytes,
            served_capabilities: limits.served_capabilities,
        })
    }

    /// Start one outbound state machine for a pinned peer and a completed TLS
    /// channel. Call [`Self::initial_frame`] before processing peer frames.
    pub fn new(
        channel: FederationTlsChannel,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        config: FederationGrpcConfig,
    ) -> Result<Self, Status> {
        let config = config.validate()?;
        if channel.role != LocalRole::Initiator || channel.expected_peer.is_none() {
            return Err(Status::unauthenticated(
                "outbound federation session requires a pinned peer",
            ));
        }
        if channel.expected_peer == Some(local.node_id()) {
            return Err(Status::invalid_argument(
                "federation peer is the local node",
            ));
        }
        let now_ms = policy.current_time_ms()?;
        local.check_validity(now_ms)?;
        let mut nonce = [0; 32];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_error| Status::internal("federation random source failed"))?;
        if nonce == [0; 32] {
            return Err(Status::internal("federation random source failed"));
        }
        let handshake_deadline = Instant::now()
            .checked_add(config.hello_timeout)
            .ok_or_else(|| Status::invalid_argument("federation Hello timeout overflows"))?;
        Ok(Self {
            channel,
            local_hello: local.hello(nonce, config, config.max_in_flight as u32),
            local,
            policy,
            config,
            handshake_deadline,
            last_time_ms: now_ms,
            phase: Phase::New,
            next_request: 1,
            last_unserved_request: 0,
            pending: HashMap::new(),
            registered: HashMap::new(),
        })
    }

    /// Produce this connection's single Hello and start the handshake deadline.
    pub fn initial_frame(&mut self) -> Result<pb::SyncFrame, Status> {
        if !matches!(self.phase, Phase::New) {
            self.close();
            return Err(Status::failed_precondition(
                "federation session already started",
            ));
        }
        if let Err(status) = self
            .check_handshake_deadline()
            .and_then(|()| self.current_time_ms())
        {
            self.close();
            return Err(status);
        }
        self.phase = Phase::AwaitHello;
        Ok(frame(pb::sync_frame::Body::Hello(self.local_hello.clone())))
    }

    /// Consume a peer frame. Any protocol, identity or policy error closes the
    /// session and invalidates all pending requests.
    pub fn receive(
        &mut self,
        incoming: pb::SyncFrame,
    ) -> Result<FederationSubscriberEvent, Status> {
        let result = self.receive_inner(incoming);
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Queue a node-self subscription Open. The caller sends the returned frame
    /// and correlates its response with the returned request number.
    pub fn open(&mut self, value: OpenRequest) -> Result<(u64, pb::SyncFrame), Status> {
        self.open_as(0, value)
    }

    /// Queue an Open under a registered hosted-subject context, or zero for
    /// node self. The peer still checks current stream and subject authority.
    pub fn open_as(
        &mut self,
        context_id: u32,
        value: OpenRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        let peer = self.peer()?;
        if value.authenticated_subscriber != self.local.node_id()
            || value.subscription.subscriber != self.local.node_id()
            || value.stream.publisher != peer
        {
            return Err(Status::permission_denied("invalid outbound Open identity"));
        }
        let kind = PendingKind::Open {
            request_id: value.request_id,
            subscription: value.subscription,
            stream: value.stream,
        };
        self.queue(kind, context_id, |request| {
            Ok(frame(pb::sync_frame::Body::Open(wire::open_to_pb(
                request, &value,
            ))))
        })
    }

    /// Queue a bounded node-self read for a previously opened subscription.
    pub fn read(
        &mut self,
        value: ReadRequest,
        stream: StreamRef,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.read_as(0, value, stream)
    }

    /// Inspect an explicitly public stream without installing a subscription.
    pub fn inspect_public(&mut self, stream: StreamRef) -> Result<(u64, pb::SyncFrame), Status> {
        if stream.publisher != self.peer()? {
            return Err(Status::permission_denied(
                "public stream publisher is not the peer",
            ));
        }
        self.queue(PendingKind::InspectPublic { stream }, 0, |request| {
            Ok(frame(pb::sync_frame::Body::InspectPublic(
                pb::InspectPublic {
                    request,
                    stream: Some(wire::stream_to_pb(stream)),
                },
            )))
        })
    }

    /// Queue a bounded public read pinned to an inspected policy revision.
    pub fn read_public(
        &mut self,
        value: PublicReadRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        let peer = self.peer()?;
        let limits = self.limits()?;
        if value.authenticated_reader != self.local.node_id() || value.stream.publisher != peer {
            return Err(Status::permission_denied(
                "invalid outbound public Read identity",
            ));
        }
        if value.expected_policy_revision == 0
            || value.max_records == 0
            || value.max_bytes == 0
            || value.max_records > limits.batch_records.min(self.config.max_batch_records)
            || value.max_bytes > limits.batch_bytes.min(self.config.max_batch_bytes)
        {
            return Err(Status::resource_exhausted(
                "public Read exceeds negotiated batch limit",
            ));
        }
        let kind = PendingKind::ReadPublic {
            stream: value.stream,
            revision: value.expected_policy_revision,
            after: value.after,
            max_records: value.max_records,
            max_bytes: value.max_bytes,
        };
        self.queue(kind, 0, |request| {
            Ok(frame(pb::sync_frame::Body::ReadPublic(pb::ReadPublic {
                request,
                stream: Some(wire::stream_to_pb(value.stream)),
                expected_policy_revision: value.expected_policy_revision,
                after: value.after.map(wire::position_to_pb),
                max_records: value.max_records.try_into().map_err(|_error| {
                    Status::resource_exhausted("public record limit overflows")
                })?,
                max_bytes: value
                    .max_bytes
                    .try_into()
                    .map_err(|_error| Status::resource_exhausted("public byte limit overflows"))?,
            })))
        })
    }

    /// Read one exact object range under a node or registered ObjectRead
    /// subject; a BlobRef alone does not authorize this request.
    pub fn read_object_as(
        &mut self,
        context_id: u32,
        value: ObjectReadRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        let peer = self.peer()?;
        let limits = self.limits()?;
        self.check_object_origin(context_id, value.authenticated_presenter, &value.subject)?;
        value
            .validate(peer)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        if value.max_bytes > limits.batch_bytes.min(self.config.max_batch_bytes)
            || value.max_bytes.saturating_add(4096)
                > limits.frame_bytes.min(self.config.max_frame_bytes)
        {
            return Err(Status::resource_exhausted(
                "object chunk exceeds negotiated limit",
            ));
        }
        let kind = PendingKind::ReadObject {
            transfer: value.transfer,
            grant: value.grant,
            revision: value.expected_revision,
            offset: value.offset,
            max_bytes: value.max_bytes,
            object_size: value.blob.size,
        };
        self.queue(kind, context_id, |request| {
            Ok(frame(pb::sync_frame::Body::ReadObject(
                wire::read_object_to_pb(request, &value)?,
            )))
        })
    }

    /// Read one exact object range as the local node principal.
    pub fn read_object(
        &mut self,
        value: ObjectReadRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.read_object_as(0, value)
    }

    /// Inspect a publisher-pinned snapshot for this node's private subscription.
    pub fn inspect_snapshot(
        &mut self,
        subscription: SubscriptionRef,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        if subscription.subscriber != self.local.node_id() {
            return Err(Status::permission_denied(
                "snapshot subscription is not local",
            ));
        }
        self.queue(
            PendingKind::InspectSnapshot { subscription },
            0,
            |request| {
                Ok(frame(pb::sync_frame::Body::InspectSnapshot(
                    wire::inspect_snapshot_to_pb(request, subscription),
                )))
            },
        )
    }

    /// Read one bounded slice from the exact offer previously inspected.
    pub fn read_snapshot(
        &mut self,
        offer: SnapshotOffer,
        offset: u64,
        max_bytes: usize,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        let limits = self.limits()?;
        if offer.manifest.subscription.subscriber != self.local.node_id()
            || offer.manifest.stream.publisher != self.peer()?
        {
            return Err(Status::permission_denied("snapshot offer has wrong nodes"));
        }
        if max_bytes == 0
            || max_bytes > MAX_SNAPSHOT_CHUNK_BYTES
            || max_bytes > limits.batch_bytes.min(self.config.max_batch_bytes)
            || max_bytes.saturating_add(4096) > limits.frame_bytes.min(self.config.max_frame_bytes)
            || offset > offer.manifest.content_bytes
        {
            return Err(Status::resource_exhausted(
                "snapshot chunk exceeds negotiated limit",
            ));
        }
        let read = SnapshotReadRequest {
            authenticated_subscriber: self.local.node_id(),
            subscription: offer.manifest.subscription,
            manifest_digest: offer.manifest.binding_digest(),
            offset,
            max_bytes,
        };
        let kind = PendingKind::ReadSnapshot {
            offer,
            offset,
            max_bytes,
        };
        self.queue(kind, 0, |request| {
            Ok(frame(pb::sync_frame::Body::ReadSnapshot(
                wire::read_snapshot_to_pb(request, read)?,
            )))
        })
    }

    /// Report a durable archive of the exact offered snapshot. This never
    /// substitutes for an event Acknowledge or application projection commit.
    pub fn receive_snapshot(
        &mut self,
        value: SnapshotReceivedRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.peer()?;
        if value.authenticated_subscriber != self.local.node_id()
            || value.subscription.subscriber != self.local.node_id()
        {
            return Err(Status::permission_denied(
                "invalid outbound snapshot receipt identity",
            ));
        }
        if value.manifest_digest.as_bytes() == &[0; 48]
            || value.publication_digest.as_bytes() == &[0; 48]
            || value.federation_generation == 0
            || value.archive_digest.as_bytes() == &[0; 48]
            || value.install_id.as_bytes() == &[0; 16]
        {
            return Err(Status::invalid_argument("empty snapshot receipt binding"));
        }
        let outbound = value;
        self.queue(
            PendingKind::ReceiveSnapshot { expected: value },
            0,
            |request| {
                Ok(frame(pb::sync_frame::Body::ReceiveSnapshot(
                    wire::receive_snapshot_to_pb(request, outbound),
                )))
            },
        )
    }

    /// Redeem an invitation for a registered Sync subject. Reuse `request_id`
    /// when retrying an indeterminate exchange.
    pub fn redeem_invitation_as(
        &mut self,
        context_id: u32,
        invitation: InvitationId,
        request_id: RequestId,
        expected_revision: u64,
        secret: Option<InvitationSecret>,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.peer()?;
        if context_id == 0
            || invitation.as_bytes() == [0; 16]
            || request_id.as_bytes() == &[0; 16]
            || expected_revision == 0
        {
            return Err(Status::invalid_argument("invalid invitation redemption"));
        }
        let credentials = self.registered.get(&context_id).ok_or_else(|| {
            Status::failed_precondition("hosted subject context is not registered")
        })?;
        if credentials.assertion.purpose() != SubjectPurpose::Sync {
            return Err(Status::permission_denied(
                "invitation requires Sync subject",
            ));
        }
        let subject = credentials.assertion.subject().clone();
        self.queue(
            PendingKind::RedeemInvitation {
                invitation,
                request_id,
                subject,
            },
            context_id,
            |request| {
                Ok(frame(pb::sync_frame::Body::RedeemInvitation(
                    pb::RedeemInvitation {
                        request,
                        invitation_id: invitation.as_bytes().to_vec(),
                        request_id: request_id.as_bytes().to_vec(),
                        expected_revision,
                        secret: secret.map_or_else(Vec::new, |secret| secret.as_bytes().to_vec()),
                        context_id,
                        holder_request_signature: Vec::new(),
                    },
                )))
            },
        )
    }

    /// Queue a bounded subscription read under the selected subject context.
    pub fn read_as(
        &mut self,
        context_id: u32,
        value: ReadRequest,
        stream: StreamRef,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        let peer = self.peer()?;
        let limits = self.limits()?;
        if value.authenticated_subscriber != self.local.node_id()
            || value.subscription.subscriber != self.local.node_id()
            || stream.publisher != peer
        {
            return Err(Status::permission_denied("invalid outbound Read identity"));
        }
        if value.max_records == 0
            || value.max_bytes == 0
            || value.max_records > limits.batch_records.min(self.config.max_batch_records)
            || value.max_bytes > limits.batch_bytes.min(self.config.max_batch_bytes)
        {
            return Err(Status::resource_exhausted(
                "read exceeds negotiated batch limit",
            ));
        }
        let kind = PendingKind::Read {
            subscription: value.subscription,
            stream,
            after: value.after,
            max_records: value.max_records,
            max_bytes: value.max_bytes,
        };
        self.queue(kind, context_id, |request| {
            Ok(frame(pb::sync_frame::Body::Read(wire::read_to_pb(
                request, &value,
            )?)))
        })
    }

    /// Acknowledge one receiver-persisted position as the local node.
    pub fn acknowledge(
        &mut self,
        value: AcknowledgeRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.acknowledge_as(0, value)
    }

    /// Acknowledge one receiver-persisted position under a subject context.
    /// This method does not itself persist a local inbox receipt.
    pub fn acknowledge_as(
        &mut self,
        context_id: u32,
        value: AcknowledgeRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.peer()?;
        if value.authenticated_subscriber != self.local.node_id()
            || value.subscription.subscriber != self.local.node_id()
        {
            return Err(Status::permission_denied(
                "invalid outbound Acknowledge identity",
            ));
        }
        let kind = PendingKind::Acknowledge {
            position: value.position,
        };
        self.queue(kind, context_id, |request| {
            Ok(frame(pb::sync_frame::Body::Acknowledge(pb::Acknowledge {
                request,
                subscription: Some(wire::subscription_to_pb(value.subscription)),
                position: Some(wire::position_to_pb(value.position)),
                context_id: 0,
                holder_request_signature: Vec::new(),
            })))
        })
    }

    /// Inspect a node-self subscription's current publisher-side state.
    pub fn inspect(
        &mut self,
        value: InspectSubscriptionRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.inspect_as(0, value)
    }

    /// Inspect a subscription under the selected subject context.
    pub fn inspect_as(
        &mut self,
        context_id: u32,
        value: InspectSubscriptionRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.peer()?;
        if value.authenticated_subscriber != self.local.node_id()
            || value.subscription.subscriber != self.local.node_id()
        {
            return Err(Status::permission_denied(
                "invalid outbound Inspect identity",
            ));
        }
        let kind = PendingKind::Inspect {
            subscription: value.subscription,
        };
        self.queue(kind, context_id, |request| {
            Ok(frame(pb::sync_frame::Body::Inspect(wire::inspect_to_pb(
                request, value,
            ))))
        })
    }

    /// Queue an idempotent node-self subscription close.
    pub fn close_subscription(
        &mut self,
        value: CloseSubscriptionRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.close_subscription_as(0, value)
    }

    /// Queue an idempotent close under the selected subject context.
    pub fn close_subscription_as(
        &mut self,
        context_id: u32,
        value: CloseSubscriptionRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.peer()?;
        if value.authenticated_subscriber != self.local.node_id()
            || value.subscription.subscriber != self.local.node_id()
        {
            return Err(Status::permission_denied("invalid outbound Close identity"));
        }
        let kind = PendingKind::Close {
            request_id: value.request_id,
            subscription: value.subscription,
        };
        self.queue(kind, context_id, |request| {
            Ok(frame(pb::sync_frame::Body::Close(wire::close_to_pb(
                request, value,
            ))))
        })
    }

    /// Register a hosted subject against this session's TLS-bound transcript.
    /// The peer still applies its issuer policy and current grant decisions.
    pub fn register_subject(
        &mut self,
        context_id: u32,
        credentials: Arc<FederationHostedSubjectCredentials>,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        let peer = self.peer()?;
        if context_id == 0
            || self.registered.len() >= 32
            || self.registered.contains_key(&context_id)
            || self.pending.values().any(|pending| matches!(&pending.kind, PendingKind::RegisterSubject { context_id: pending_id, .. } if *pending_id == context_id))
            || credentials.assertion.audience() != peer
            || credentials.assertion.presenter() != self.local.node_id()
        {
            return Err(Status::invalid_argument("invalid hosted subject context"));
        }
        let transcript = self.transcript()?;
        let presentation = credentials
            .holder
            .sign_presentation(&credentials.assertion, transcript)
            .map_err(|_error| Status::unauthenticated("invalid holder presentation"))?;
        let purpose = match credentials.assertion.purpose() {
            SubjectPurpose::Discover => pb::SubjectPurpose::Discover,
            SubjectPurpose::Sync => pb::SubjectPurpose::Sync,
            SubjectPurpose::Invoke => pb::SubjectPurpose::Invoke,
            SubjectPurpose::ObjectRead => pb::SubjectPurpose::ObjectRead,
        };
        let kind = PendingKind::RegisterSubject {
            context_id,
            credentials: Arc::clone(&credentials),
        };
        self.queue(kind, 0, |request| {
            Ok(frame(pb::sync_frame::Body::RegisterSubject(
                pb::RegisterSubject {
                    request,
                    context_id,
                    purpose: purpose as i32,
                    issuer_descriptor: credentials.issuer_descriptor.clone(),
                    assertion: credentials.assertion.encode(),
                    issuer_signature: credentials.issuer_signature.clone(),
                    holder_presentation: presentation,
                },
            )))
        })
    }

    /// Reserve a remote CallRef under node self or a registered Invoke subject.
    /// Retain the request ID to reconcile a lost response.
    pub fn prepare_call_as(
        &mut self,
        context_id: u32,
        value: PrepareCallRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.check_call_origin(context_id, value.authenticated_origin, &value.subject)?;
        let kind = PendingKind::PrepareCall {
            origin_request_id: value.origin_request_id,
            prepare_deadline_ms: value.prepare_deadline_ms,
            execution_deadline_ms: value.execution_deadline_ms,
            result_retention_ms: value.result_retention_ms,
        };
        self.queue(kind, context_id, |request| {
            Ok(frame(pb::sync_frame::Body::PrepareCall(
                wire::prepare_call_to_pb(request, &value),
            )))
        })
    }

    /// Ask the target to durably hand a prepared call to its Kernel.
    pub fn invoke_call_as(
        &mut self,
        context_id: u32,
        value: InvokeCallRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.check_call_origin(context_id, value.authenticated_origin, &value.subject)?;
        if value.call.target != self.peer()? {
            return Err(Status::permission_denied("call target is not the peer"));
        }
        let kind = PendingKind::InvokeCall { call: value.call };
        self.queue(kind, context_id, |request| {
            Ok(frame(pb::sync_frame::Body::InvokeCall(
                wire::invoke_call_to_pb(request, &value),
            )))
        })
    }

    /// Inspect one exact CallRef without assuming that a lost response means
    /// the prior invocation did not execute.
    pub fn inspect_call_as(
        &mut self,
        context_id: u32,
        value: InspectCallRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.check_call_origin(context_id, value.authenticated_origin, &value.subject)?;
        if value.call.target != self.peer()? {
            return Err(Status::permission_denied("call target is not the peer"));
        }
        let kind = PendingKind::InspectCall { call: value.call };
        self.queue(kind, context_id, |request| {
            Ok(frame(pb::sync_frame::Body::InspectCall(
                wire::inspect_call_to_pb(request, &value),
            )))
        })
    }

    /// Request cancellation of one CallRef using a stable control request ID.
    pub fn cancel_call_as(
        &mut self,
        context_id: u32,
        value: CancelCallRequest,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        self.check_call_origin(context_id, value.authenticated_origin, &value.subject)?;
        if value.call.target != self.peer()? {
            return Err(Status::permission_denied("call target is not the peer"));
        }
        let kind = PendingKind::CancelCall {
            call: value.call,
            control_request_id: value.control_request_id,
        };
        self.queue(kind, context_id, |request| {
            Ok(frame(pb::sync_frame::Body::CancelCall(
                wire::cancel_call_to_pb(request, &value),
            )))
        })
    }

    fn check_call_origin(
        &mut self,
        context_id: u32,
        origin: FederationNodeId,
        subject: &FederationSubject,
    ) -> Result<(), Status> {
        if origin != self.local.node_id() {
            return Err(Status::permission_denied(
                "call origin is not the local node",
            ));
        }
        self.peer()?;
        match (context_id, subject) {
            (0, FederationSubject::Node(node)) if *node == origin => Ok(()),
            (0, _) => Err(Status::permission_denied(
                "node-self call subject differs from origin",
            )),
            (_, FederationSubject::Hosted(hosted)) => {
                let credentials = self.registered.get(&context_id).ok_or_else(|| {
                    Status::failed_precondition("hosted subject context is not registered")
                })?;
                if credentials.assertion.purpose() != SubjectPurpose::Invoke
                    || credentials.assertion.subject() != hosted
                {
                    return Err(Status::permission_denied(
                        "call subject differs from registered context",
                    ));
                }
                Ok(())
            }
            (_, _) => Err(Status::permission_denied("invalid hosted call subject")),
        }
    }

    fn check_object_origin(
        &self,
        context_id: u32,
        origin: FederationNodeId,
        subject: &FederationSubject,
    ) -> Result<(), Status> {
        if origin != self.local.node_id() {
            return Err(Status::permission_denied(
                "object presenter is not the local node",
            ));
        }
        match (context_id, subject) {
            (0, FederationSubject::Node(node)) if *node == origin => Ok(()),
            (_, FederationSubject::Hosted(hosted)) if context_id != 0 => {
                let credentials = self.registered.get(&context_id).ok_or_else(|| {
                    Status::failed_precondition("hosted object context is not registered")
                })?;
                if credentials.assertion.purpose() == SubjectPurpose::ObjectRead
                    && credentials.assertion.subject() == hosted
                {
                    Ok(())
                } else {
                    Err(Status::permission_denied(
                        "object subject differs from registered context",
                    ))
                }
            }
            _ => Err(Status::permission_denied("invalid object subject")),
        }
    }

    /// Earliest outstanding business-response deadline, if any.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.values().map(|pending| pending.deadline).min()
    }

    /// Deadline for completing this Session's peer proof.
    pub fn handshake_deadline(&self) -> Instant {
        self.handshake_deadline
    }

    /// Close the Session when any outstanding response has timed out.
    pub fn check_response_deadline(&mut self) -> Result<(), Status> {
        if self
            .next_deadline()
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.close();
            return Err(Status::deadline_exceeded("federation response timed out"));
        }
        Ok(())
    }

    /// Invalidate all outstanding request correlations and hosted contexts.
    pub fn close(&mut self) {
        self.phase = Phase::Closed;
        self.pending.clear();
        self.registered.clear();
    }

    fn receive_inner(
        &mut self,
        incoming: pb::SyncFrame,
    ) -> Result<FederationSubscriberEvent, Status> {
        if incoming.encoded_len() > self.config.max_frame_bytes {
            return Err(Status::resource_exhausted(
                "federation frame exceeds local limit",
            ));
        }
        let phase = std::mem::replace(&mut self.phase, Phase::Closed);
        match (phase, incoming.body) {
            (Phase::AwaitHello, Some(pb::sync_frame::Body::Hello(hello))) => {
                self.check_handshake_deadline()?;
                self.current_time_ms()?;
                let peer = wire::hello(hello)?;
                if Some(peer.node) != self.channel.expected_peer {
                    return Err(Status::unauthenticated("unexpected federation peer"));
                }
                let local = wire::hello(self.local_hello.clone())?;
                let digest = wire::hello_capabilities_digest(&local, &peer);
                let transcript = FederationSessionTranscript::new(
                    local.node,
                    peer.node,
                    local.nonce,
                    peer.nonce,
                    self.channel.exporter,
                    digest,
                )
                .map_err(|_error| Status::unauthenticated("invalid federation transcript"))?;
                let signature = self
                    .local
                    .online_key
                    .sign_session(self.local.node_id(), &self.local.authorization, &transcript)
                    .map_err(|_error| Status::internal("federation signing failed"))?;
                self.phase = Phase::AwaitAuthenticate {
                    peer: Box::new(peer),
                    transcript,
                };
                Ok(FederationSubscriberEvent::Send(frame(
                    pb::sync_frame::Body::Authenticate(pb::Authenticate {
                        online_signature: signature,
                    }),
                )))
            }
            (
                Phase::AwaitAuthenticate { peer, transcript },
                Some(pb::sync_frame::Body::Authenticate(auth)),
            ) => {
                self.check_handshake_deadline()?;
                let signature = wire::authenticate(auth)?;
                let now_ms = self.current_time_ms()?;
                let proof = verify_federation_peer_proof(
                    &peer.root,
                    peer.node,
                    &peer.authorization,
                    &peer.root_signature,
                    &transcript,
                    &signature,
                    now_ms,
                )
                .map_err(|_error| Status::unauthenticated("invalid federation peer proof"))?;
                self.policy.check_current_peer(proof, now_ms)?;
                let limits = Limits {
                    served_capabilities: peer.served_capabilities,
                    frame_bytes: peer.max_frame_bytes as usize,
                    in_flight: (peer.max_in_flight as usize).min(self.config.max_in_flight),
                    batch_records: peer.max_batch_records as usize,
                    batch_bytes: peer.max_batch_bytes as usize,
                };
                self.phase = Phase::Ready {
                    proof,
                    limits,
                    transcript: Arc::new(transcript),
                };
                Ok(FederationSubscriberEvent::Ready)
            }
            (
                Phase::Ready {
                    proof,
                    limits,
                    transcript,
                },
                body,
            ) => {
                self.check_current_peer(proof)?;
                self.check_response_deadline()?;
                let event = self.complete(body)?;
                self.phase = Phase::Ready {
                    proof,
                    limits,
                    transcript,
                };
                Ok(event)
            }
            (Phase::New | Phase::Closed, _) => Err(Status::failed_precondition(
                "federation session is not active",
            )),
            _ => Err(Status::unauthenticated(
                "federation handshake frames are out of order",
            )),
        }
    }

    fn complete(
        &mut self,
        body: Option<pb::sync_frame::Body>,
    ) -> Result<FederationSubscriberEvent, Status> {
        use pb::sync_frame::Body;
        let request = match &body {
            Some(Body::Opened(value)) => value.request,
            Some(Body::Batch(value)) => value.request,
            Some(Body::PublicInspected(value)) => value.request,
            Some(Body::PublicBatch(value)) => value.request,
            Some(Body::ObjectChunk(value)) => value.request,
            Some(Body::SnapshotOffered(value)) => value.request,
            Some(Body::SnapshotChunk(value)) => value.request,
            Some(Body::SnapshotReceived(value)) => value.request,
            Some(Body::InvitationRedeemed(value)) => value.request,
            Some(Body::Acknowledged(value)) => value.request,
            Some(Body::Inspected(value)) => value.request,
            Some(Body::Closed(value)) => value.request,
            Some(Body::SubjectRegistered(value)) => value.request,
            Some(Body::CallPrepared(value)) => value.request,
            Some(Body::CallInvoked(value)) => value.request,
            Some(Body::CallInspected(value)) => value.request,
            Some(Body::CallCancelled(value)) => value.request,
            Some(Body::Failure(value)) => value.request,
            _ => {
                return Err(Status::invalid_argument(
                    "unsupported federation response frame",
                ));
            }
        };
        if request == 0 {
            return Err(Status::invalid_argument("zero federation response request"));
        }
        let pending = self
            .pending
            .remove(&request)
            .ok_or_else(|| Status::invalid_argument("unknown or replayed federation response"))?;
        if Instant::now() >= pending.deadline {
            return Err(Status::deadline_exceeded("federation response timed out"));
        }
        let result = match (pending.kind, body) {
            (
                PendingKind::RedeemInvitation {
                    invitation,
                    request_id,
                    subject,
                },
                Some(Body::InvitationRedeemed(value)),
            ) => {
                let actual_invitation =
                    InvitationId::from_bytes(value.invitation_id.try_into().map_err(|_error| {
                        Status::invalid_argument("invalid redeemed invitation ID")
                    })?);
                let actual_request =
                    RequestId::from_bytes(value.request_id.try_into().map_err(|_error| {
                        Status::invalid_argument("invalid redeemed request ID")
                    })?);
                let stream = wire::stream(
                    value
                        .stream
                        .ok_or_else(|| Status::invalid_argument("missing redeemed stream"))?,
                )?;
                if actual_invitation != invitation
                    || actual_request != request_id
                    || Some(stream.publisher) != self.channel.expected_peer
                    || value.grant_revision == 0
                    || value.grant_expires_ms == 0
                {
                    return Err(Status::invalid_argument(
                        "InvitationRedeemed does not match request",
                    ));
                }
                Ok(FederationSubscriberResult::InvitationRedeemed(
                    FederationInvitationReceipt {
                        invitation,
                        request_id,
                        subject,
                        stream,
                        grant_revision: value.grant_revision,
                        grant_expires_ms: value.grant_expires_ms,
                        history_floor: value.history_floor,
                        currently_authorized: value.currently_authorized,
                    },
                ))
            }
            (PendingKind::InspectSnapshot { subscription }, Some(Body::SnapshotOffered(value))) => {
                let offer = wire::snapshot_offer(
                    value
                        .offer
                        .ok_or_else(|| Status::invalid_argument("missing snapshot offer"))?,
                )?;
                if offer.manifest.subscription != subscription
                    || Some(offer.manifest.stream.publisher) != self.channel.expected_peer
                {
                    return Err(Status::invalid_argument(
                        "SnapshotOffered does not match InspectSnapshot",
                    ));
                }
                Ok(FederationSubscriberResult::SnapshotOffered(offer))
            }
            (
                PendingKind::ReadSnapshot {
                    offer,
                    offset,
                    max_bytes,
                },
                Some(Body::SnapshotChunk(value)),
            ) => Ok(FederationSubscriberResult::SnapshotChunk(
                wire::snapshot_chunk(value, &offer, offset, max_bytes)?,
            )),
            (PendingKind::ReceiveSnapshot { expected }, Some(Body::SnapshotReceived(value))) => {
                Ok(FederationSubscriberResult::SnapshotReceived(
                    wire::snapshot_received(value, &expected)?,
                ))
            }
            (
                PendingKind::ReadObject {
                    transfer,
                    grant,
                    revision,
                    offset,
                    max_bytes,
                    object_size,
                },
                Some(Body::ObjectChunk(value)),
            ) => {
                if value.data.len() > max_bytes {
                    return Err(Status::resource_exhausted(
                        "object chunk exceeds requested bytes",
                    ));
                }
                let page = wire::object_chunk(value)?;
                let end = offset
                    .checked_add(page.bytes.len() as u64)
                    .ok_or_else(|| Status::invalid_argument("object offset overflows"))?;
                if page.transfer != transfer
                    || page.grant != grant
                    || page.revision != revision
                    || page.offset != offset
                    || end > object_size
                    || page.end_of_object != (end == object_size)
                    || (page.bytes.is_empty() && !page.end_of_object && !page.end_of_range)
                {
                    return Err(Status::invalid_argument(
                        "ObjectChunk does not match ReadObject",
                    ));
                }
                Ok(FederationSubscriberResult::ObjectChunk(page))
            }
            (PendingKind::InspectPublic { stream }, Some(Body::PublicInspected(value))) => {
                let actual = wire::stream(
                    value
                        .stream
                        .ok_or_else(|| Status::invalid_argument("missing public stream"))?,
                )?;
                if actual != stream
                    || value.policy_revision == 0
                    || value.minimum_available == 0
                    || value.max_read_records == 0
                    || value.max_read_bytes == 0
                {
                    return Err(Status::invalid_argument(
                        "PublicInspected does not match request",
                    ));
                }
                let head = value.head.map(wire::position).transpose()?;
                if head.is_some_and(|head| head.sequence() < value.minimum_available) {
                    return Err(Status::invalid_argument(
                        "public head precedes retained history",
                    ));
                }
                Ok(FederationSubscriberResult::PublicInspected(
                    PublicStreamView {
                        stream,
                        export: ExportName::new(value.export_name)
                            .map_err(|error| Status::invalid_argument(error.to_string()))?,
                        policy_revision: value.policy_revision,
                        head,
                        minimum_available: value.minimum_available,
                        max_read_records: value.max_read_records as usize,
                        max_read_bytes: usize::try_from(value.max_read_bytes).map_err(
                            |_error| Status::resource_exhausted("public byte limit overflows"),
                        )?,
                    },
                ))
            }
            (
                PendingKind::ReadPublic {
                    stream,
                    revision,
                    after,
                    max_records,
                    max_bytes,
                },
                Some(Body::PublicBatch(value)),
            ) => {
                let actual = wire::stream(
                    value
                        .stream
                        .ok_or_else(|| Status::invalid_argument("missing public stream"))?,
                )?;
                if actual != stream
                    || value.policy_revision != revision
                    || value.minimum_available == 0
                    || value.records.len() > max_records
                {
                    return Err(Status::invalid_argument(
                        "PublicBatch does not match ReadPublic",
                    ));
                }
                let wire_bytes = value
                    .records
                    .iter()
                    .try_fold(0usize, |total, record| {
                        total.checked_add(record.payload.len())
                    })
                    .ok_or_else(|| {
                        Status::resource_exhausted("PublicBatch byte count overflows")
                    })?;
                if wire_bytes > max_bytes {
                    return Err(Status::resource_exhausted(
                        "PublicBatch exceeds requested bytes",
                    ));
                }
                let head = value.head.map(wire::position).transpose()?;
                if head.is_some_and(|head| {
                    after.is_some_and(|after| after.sequence() > head.sequence())
                }) {
                    return Err(Status::invalid_argument("PublicBatch cursor exceeds head"));
                }
                let mut expected = after.map_or(Some(value.minimum_available), |after| {
                    after.sequence().checked_add(1)
                });
                let mut records = Vec::with_capacity(value.records.len());
                for wire_record in value.records {
                    let record = wire::record(wire_record)?;
                    if record.stream() != stream
                        || Some(record.sequence()) != expected
                        || head.is_some_and(|head| record.sequence() > head.sequence())
                    {
                        return Err(Status::invalid_argument(
                            "PublicBatch records are not contiguous",
                        ));
                    }
                    expected = record.sequence().checked_add(1);
                    records.push(record);
                }
                Ok(FederationSubscriberResult::PublicBatch(PublicReadPage {
                    policy_revision: revision,
                    records,
                    head,
                    minimum_available: value.minimum_available,
                }))
            }
            (
                PendingKind::Open {
                    request_id,
                    subscription,
                    stream,
                },
                Some(Body::Opened(value)),
            ) => {
                let opened = wire::opened(value)?;
                if opened.subscription_revision == 0
                    || opened.request_id != request_id
                    || opened.subscription != subscription
                    || opened.stream != stream
                {
                    return Err(Status::invalid_argument(
                        "Opened identity does not match Open",
                    ));
                }
                Ok(FederationSubscriberResult::Opened(opened))
            }
            (
                PendingKind::Read {
                    subscription,
                    stream,
                    after,
                    max_records,
                    max_bytes,
                },
                Some(Body::Batch(value)),
            ) => {
                if value.records.len() > max_records {
                    return Err(Status::resource_exhausted(
                        "Batch exceeds requested record count",
                    ));
                }
                let wire_bytes = value
                    .records
                    .iter()
                    .try_fold(0usize, |total, record| {
                        total.checked_add(record.payload.len())
                    })
                    .ok_or_else(|| Status::resource_exhausted("Batch byte count overflows"))?;
                if wire_bytes > max_bytes {
                    return Err(Status::resource_exhausted(
                        "Batch exceeds requested byte count",
                    ));
                }
                let (actual_subscription, page) = wire::batch(value)?;
                if actual_subscription != subscription
                    || page.records.iter().any(|record| record.stream() != stream)
                {
                    return Err(Status::invalid_argument(
                        "Batch identity does not match Read",
                    ));
                }
                if page.minimum_available == 0
                    || page.head.is_some_and(|head| {
                        after.is_some_and(|position| position.sequence() > head.sequence())
                            || page
                                .records
                                .last()
                                .is_some_and(|record| record.sequence() > head.sequence())
                    })
                {
                    return Err(Status::invalid_argument("Batch range is inconsistent"));
                }
                let mut previous = after.map(Position::sequence);
                for record in &page.records {
                    if let Some(sequence) = previous {
                        if record.sequence()
                            != sequence.checked_add(1).ok_or_else(|| {
                                Status::invalid_argument("Batch sequence overflows")
                            })?
                        {
                            return Err(Status::invalid_argument(
                                "Batch records are not contiguous",
                            ));
                        }
                    } else if record.sequence() < page.minimum_available.max(1) {
                        return Err(Status::invalid_argument(
                            "Batch starts before retained history",
                        ));
                    }
                    previous = Some(record.sequence());
                }
                Ok(FederationSubscriberResult::Batch(page))
            }
            (PendingKind::Acknowledge { position }, Some(Body::Acknowledged(value))) => {
                let actual =
                    wire::position(value.position.ok_or_else(|| {
                        Status::invalid_argument("missing acknowledged position")
                    })?)?;
                if actual != position {
                    return Err(Status::invalid_argument(
                        "Acknowledged position does not match Acknowledge",
                    ));
                }
                Ok(FederationSubscriberResult::Acknowledged(actual))
            }
            (PendingKind::Inspect { subscription }, Some(Body::Inspected(value))) => {
                let inspected = wire::inspected(value)?;
                if inspected.subscription != subscription
                    || Some(inspected.stream.publisher) != self.channel.expected_peer
                {
                    return Err(Status::invalid_argument(
                        "Inspected identity does not match Inspect",
                    ));
                }
                Ok(FederationSubscriberResult::Inspected(inspected))
            }
            (
                PendingKind::Close {
                    request_id,
                    subscription,
                },
                Some(Body::Closed(value)),
            ) => {
                let closed = wire::closed(value)?;
                if closed.request_id != request_id || closed.subscription != subscription {
                    return Err(Status::invalid_argument(
                        "Closed identity does not match Close",
                    ));
                }
                Ok(FederationSubscriberResult::Closed(closed))
            }
            (
                PendingKind::RegisterSubject {
                    context_id,
                    credentials,
                },
                Some(Body::SubjectRegistered(value)),
            ) => {
                if value.context_id != context_id || self.registered.contains_key(&context_id) {
                    return Err(Status::invalid_argument(
                        "SubjectRegistered context does not match request",
                    ));
                }
                self.registered.insert(context_id, credentials);
                Ok(FederationSubscriberResult::SubjectRegistered(context_id))
            }
            (
                PendingKind::PrepareCall {
                    origin_request_id,
                    prepare_deadline_ms,
                    execution_deadline_ms,
                    result_retention_ms,
                },
                Some(Body::CallPrepared(value)),
            ) => {
                let prepared = wire::call_prepared(value)?;
                if prepared.origin_request_id != origin_request_id
                    || Some(prepared.call.target) != self.channel.expected_peer
                    || prepared.reserved_until_ms > prepare_deadline_ms
                    || prepared.execution_deadline_ms > execution_deadline_ms
                    || prepared.result_retention_ms > result_retention_ms
                    || matches!(prepared.status, xolotl_federation::CallStatus::Unproven)
                {
                    return Err(Status::invalid_argument(
                        "CallPrepared does not match PrepareCall",
                    ));
                }
                Ok(FederationSubscriberResult::CallPrepared(prepared))
            }
            (PendingKind::InvokeCall { call }, Some(Body::CallInvoked(value))) => {
                let invoked = wire::call_invoked(value)?;
                if invoked.call != call {
                    return Err(Status::invalid_argument(
                        "CallInvoked does not match InvokeCall",
                    ));
                }
                Ok(FederationSubscriberResult::CallInvoked(invoked))
            }
            (PendingKind::InspectCall { call }, Some(Body::CallInspected(value))) => {
                let inspected = wire::call_inspected(value)?;
                if inspected.call != call {
                    return Err(Status::invalid_argument(
                        "CallInspected does not match InspectCall",
                    ));
                }
                Ok(FederationSubscriberResult::CallInspected(inspected))
            }
            (
                PendingKind::CancelCall {
                    call,
                    control_request_id,
                },
                Some(Body::CallCancelled(value)),
            ) => {
                let cancelled = wire::call_cancelled(value)?;
                if cancelled.call != call || cancelled.control_request_id != control_request_id {
                    return Err(Status::invalid_argument(
                        "CallCancelled does not match CancelCall",
                    ));
                }
                Ok(FederationSubscriberResult::CallCancelled(cancelled))
            }
            (_, Some(Body::Failure(value))) => {
                let code = pb::FailureCode::try_from(value.code).map_err(|_error| {
                    Status::invalid_argument("unknown federation failure code")
                })?;
                if code == pb::FailureCode::Unspecified {
                    return Err(Status::invalid_argument(
                        "unspecified federation failure code",
                    ));
                }
                Err(wire::failure_status(value))
            }
            _ => {
                return Err(Status::invalid_argument(
                    "federation response variant does not match request",
                ));
            }
        };
        Ok(FederationSubscriberEvent::Completed { request, result })
    }

    fn queue(
        &mut self,
        kind: PendingKind,
        context_id: u32,
        encode: impl FnOnce(u64) -> Result<pb::SyncFrame, Status>,
    ) -> Result<(u64, pb::SyncFrame), Status> {
        let limits = self.limits()?;
        if self.pending.len() >= limits.in_flight {
            return Err(Status::resource_exhausted(
                "federation in-flight limit reached",
            ));
        }
        let request = self.next_request;
        let next = request
            .checked_add(1)
            .ok_or_else(|| Status::resource_exhausted("federation request numbers exhausted"))?;
        let mut outbound = encode(request)?;
        if context_id != 0 {
            let body = outbound
                .body
                .as_mut()
                .ok_or_else(|| Status::invalid_argument("empty federation request"))?;
            self.sign_business_frame(context_id, request, body)?;
        }
        if outbound.encoded_len() > limits.frame_bytes
            || outbound.encoded_len() > self.config.max_frame_bytes
        {
            return Err(Status::resource_exhausted(
                "federation request exceeds negotiated frame limit",
            ));
        }
        let deadline = Instant::now()
            .checked_add(self.config.response_timeout)
            .ok_or_else(|| Status::invalid_argument("federation response timeout overflows"))?;
        self.next_request = next;
        self.pending.insert(request, Pending { kind, deadline });
        Ok((request, outbound))
    }

    fn peer(&mut self) -> Result<FederationNodeId, Status> {
        let proof = match self.phase {
            Phase::Ready { proof, .. } => proof,
            _ => {
                return Err(Status::failed_precondition(
                    "federation peer is not authenticated",
                ));
            }
        };
        if let Err(status) = self
            .check_response_deadline()
            .and_then(|()| self.check_current_peer(proof))
        {
            self.close();
            return Err(status);
        }
        Ok(proof.node_id())
    }

    fn limits(&self) -> Result<Limits, Status> {
        match self.phase {
            Phase::Ready { limits, .. } => Ok(limits),
            _ => Err(Status::failed_precondition(
                "federation peer is not authenticated",
            )),
        }
    }

    fn transcript(&self) -> Result<&FederationSessionTranscript, Status> {
        match &self.phase {
            Phase::Ready { transcript, .. } => Ok(transcript),
            _ => Err(Status::failed_precondition(
                "federation peer is not authenticated",
            )),
        }
    }

    fn sign_business_frame(
        &self,
        context_id: u32,
        request: u64,
        body: &mut pb::sync_frame::Body,
    ) -> Result<(), Status> {
        let credentials = self.registered.get(&context_id).ok_or_else(|| {
            Status::failed_precondition("hosted subject context is not registered")
        })?;
        let purpose = match body {
            pb::sync_frame::Body::PrepareCall(_)
            | pb::sync_frame::Body::InvokeCall(_)
            | pb::sync_frame::Body::InspectCall(_)
            | pb::sync_frame::Body::CancelCall(_) => SubjectPurpose::Invoke,
            pb::sync_frame::Body::ReadObject(_) => SubjectPurpose::ObjectRead,
            _ => SubjectPurpose::Sync,
        };
        if credentials.assertion.purpose() != purpose {
            return Err(Status::permission_denied(
                "hosted subject purpose does not allow this operation",
            ));
        }
        let (wire_context, signature) = hosted_fields_mut(body)?;
        *wire_context = context_id;
        signature.clear();
        let digest = wire::subject_request_digest(body)?;
        let proof = credentials
            .holder
            .sign_request(
                &credentials.assertion,
                self.transcript()?,
                context_id,
                request,
                digest,
            )
            .map_err(|_error| Status::internal("hosted request signing failed"))?;
        let (_, signature) = hosted_fields_mut(body)?;
        *signature = proof;
        Ok(())
    }

    fn current_time_ms(&mut self) -> Result<u64, Status> {
        let now_ms = self.policy.current_time_ms()?;
        if now_ms < self.last_time_ms {
            return Err(Status::failed_precondition(
                "federation policy clock moved backwards",
            ));
        }
        self.local.check_validity(now_ms)?;
        self.last_time_ms = now_ms;
        Ok(now_ms)
    }

    fn check_current_peer(&mut self, proof: VerifiedFederationPeerProof) -> Result<(), Status> {
        let now_ms = self.current_time_ms()?;
        if now_ms >= proof.expires_ms() {
            return Err(Status::unauthenticated("federation online key expired"));
        }
        self.policy.check_current_peer(proof, now_ms)
    }

    fn check_handshake_deadline(&self) -> Result<(), Status> {
        if Instant::now() >= self.handshake_deadline {
            return Err(Status::deadline_exceeded("federation handshake timed out"));
        }
        Ok(())
    }
}

fn frame(body: pb::sync_frame::Body) -> pb::SyncFrame {
    pb::SyncFrame { body: Some(body) }
}

fn hosted_fields_mut(body: &mut pb::sync_frame::Body) -> Result<(&mut u32, &mut Vec<u8>), Status> {
    use pb::sync_frame::Body;
    match body {
        Body::Open(value) => Ok((&mut value.context_id, &mut value.holder_request_signature)),
        Body::Read(value) => Ok((&mut value.context_id, &mut value.holder_request_signature)),
        Body::Acknowledge(value) => {
            Ok((&mut value.context_id, &mut value.holder_request_signature))
        }
        Body::Inspect(value) => Ok((&mut value.context_id, &mut value.holder_request_signature)),
        Body::Close(value) => Ok((&mut value.context_id, &mut value.holder_request_signature)),
        Body::PrepareCall(value) => {
            Ok((&mut value.context_id, &mut value.holder_request_signature))
        }
        Body::InvokeCall(value) => Ok((&mut value.context_id, &mut value.holder_request_signature)),
        Body::InspectCall(value) => {
            Ok((&mut value.context_id, &mut value.holder_request_signature))
        }
        Body::CancelCall(value) => Ok((&mut value.context_id, &mut value.holder_request_signature)),
        Body::ReadObject(value) => Ok((&mut value.context_id, &mut value.holder_request_signature)),
        Body::InspectSnapshot(value) => {
            Ok((&mut value.context_id, &mut value.holder_request_signature))
        }
        Body::ReadSnapshot(value) => {
            Ok((&mut value.context_id, &mut value.holder_request_signature))
        }
        Body::ReceiveSnapshot(value) => {
            Ok((&mut value.context_id, &mut value.holder_request_signature))
        }
        Body::RedeemInvitation(value) => {
            Ok((&mut value.context_id, &mut value.holder_request_signature))
        }
        _ => Err(Status::invalid_argument(
            "hosted context is not a sync request",
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use anyhow::{Result, ensure};
    use tonic::Code;
    use xolotl_federation::{
        AuthorityRevision, CallMethod, CallPath, CallTarget, Digest, ExportName, FederationLimits,
        FederationOnlineKey, FederationOnlineKeyAuthorization, FederationRootKey,
        FederationService, HistoryStart, MemoryFederationStore, OpenRequest, OpenResult, RequestId,
        RootSignaturePurpose, StreamId, SubjectIssuerKey, SubscriptionId,
    };

    use super::*;
    use crate::session::FederationGrpcPublisherSession;

    struct Policy;

    impl FederationPeerPolicy for Policy {
        fn decision_clock(
            &self,
        ) -> Result<Arc<dyn xolotl_federation::FederationObjectClock>, Status> {
            Ok(Arc::new(|| Ok(150)))
        }

        fn current_time_ms(&self) -> Result<u64, Status> {
            Ok(150)
        }
        fn check_current_peer(
            &self,
            _proof: VerifiedFederationPeerProof,
            _now_ms: u64,
        ) -> Result<(), Status> {
            Ok(())
        }
    }

    fn identity() -> Result<Arc<FederationLocalCredentials>> {
        let root_key = FederationRootKey::generate()?;
        let root = root_key.root()?;
        let online = FederationOnlineKey::generate()?;
        let authorization =
            FederationOnlineKeyAuthorization::new(online.public_key(), 1, 100, 200)?;
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

    fn ready() -> Result<(
        FederationGrpcSubscriberSession,
        FederationNodeId,
        FederationNodeId,
    )> {
        let local = identity()?;
        let remote = identity()?;
        let local_node = local.node_id();
        let remote_node = remote.node_id();
        let config = FederationGrpcConfig {
            response_timeout: Duration::from_secs(1),
            max_in_flight: 1,
            ..FederationGrpcConfig::default()
        };
        let mut subscriber = FederationGrpcSubscriberSession::new(
            FederationTlsChannel {
                role: LocalRole::Initiator,
                expected_peer: Some(remote_node),
                exporter: [9; 48],
            },
            local,
            Arc::new(Policy),
            config,
        )?;
        let mut publisher = FederationGrpcPublisherSession::new(
            FederationTlsChannel {
                role: LocalRole::Responder,
                expected_peer: None,
                exporter: [9; 48],
            },
            remote,
            Arc::new(Policy),
            FederationService::new(
                Arc::new(MemoryFederationStore::new(remote_node)),
                FederationLimits::default(),
            )?,
            config,
        )?;
        let subscriber_hello = subscriber.initial_frame()?;
        let publisher_hello = publisher.initial_frame()?;
        let subscriber_auth = match subscriber.receive(publisher_hello)? {
            FederationSubscriberEvent::Send(frame) => frame,
            _ => anyhow::bail!("subscriber did not sign Hello"),
        };
        let publisher_auth = publisher
            .receive(subscriber_hello)?
            .ok_or_else(|| anyhow::anyhow!("publisher did not sign Hello"))?;
        ensure!(publisher.receive(subscriber_auth)?.is_none());
        ensure!(matches!(
            subscriber.receive(publisher_auth)?,
            FederationSubscriberEvent::Ready
        ));
        Ok((subscriber, local_node, remote_node))
    }

    fn open(local: FederationNodeId, remote: FederationNodeId) -> OpenRequest {
        OpenRequest {
            authenticated_subscriber: local,
            request_id: RequestId::from_bytes([7; 16]),
            subscription: SubscriptionRef {
                subscriber: local,
                id: SubscriptionId::from_bytes([4; 16]),
            },
            stream: StreamRef {
                publisher: remote,
                id: StreamId::from_bytes([3; 16]),
            },
            expected_control_revision: None,
            history: HistoryStart::All,
        }
    }

    fn opened(request: u64, open: &OpenRequest) -> Result<pb::SyncFrame> {
        Ok(frame(pb::sync_frame::Body::Opened(wire::opened_to_pb(
            request,
            &OpenResult {
                request_id: open.request_id,
                subscription: open.subscription,
                stream: open.stream,
                export: ExportName::new("friends")?,
                publisher_authority: AuthorityRevision { peer: 1, export: 1 },
                subscription_revision: 1,
                start: None,
            },
        ))))
    }

    fn rejected(
        session: &mut FederationGrpcSubscriberSession,
        frame: pb::SyncFrame,
        code: Code,
    ) -> Result<()> {
        match session.receive(frame) {
            Err(status) if status.code() == code => Ok(()),
            Err(status) => anyhow::bail!("expected {code:?}, got {status}"),
            Ok(_) => anyhow::bail!("federation frame was accepted"),
        }
    }

    #[test]
    fn outbound_only_rejects_reverse_open_without_poisoning_forward_requests() -> Result<()> {
        let (mut session, local, remote) = ready()?;
        let reverse = open(remote, local);
        let response = session.reject_unserved_request(frame(pb::sync_frame::Body::Open(
            wire::open_to_pb(1, &reverse),
        )))?;
        ensure!(
            matches!(response.body, Some(pb::sync_frame::Body::Failure(value))
            if value.request == 1 && value.code == pb::FailureCode::Unavailable as i32
                && value.commit_verdict == pb::CommitVerdict::NotCommitted as i32)
        );
        let forward = open(local, remote);
        let (request, _) = session.open(forward.clone())?;
        ensure!(matches!(
            session.receive(opened(request, &forward)?)?,
            FederationSubscriberEvent::Completed { .. }
        ));
        let replay = session
            .reject_unserved_request(frame(pb::sync_frame::Body::Open(wire::open_to_pb(
                1, &reverse,
            ))))
            .err()
            .ok_or_else(|| anyhow::anyhow!("replayed reverse request was accepted"))?;
        ensure!(replay.code() == Code::InvalidArgument);
        Ok(())
    }

    #[test]
    fn snapshot_receipt_uses_its_own_request_and_response_kind() -> Result<()> {
        let (mut session, local, _) = ready()?;
        let expected = SnapshotReceivedRequest {
            authenticated_subscriber: local,
            subscription: SubscriptionRef {
                subscriber: local,
                id: SubscriptionId::from_bytes([4; 16]),
            },
            manifest_digest: Digest::from_bytes([1; 48]),
            publication_digest: Digest::from_bytes([2; 48]),
            position: Position::new(3, Digest::from_bytes([3; 48]))?,
            install_id: xolotl_federation::SnapshotId::from_bytes([4; 16]),
            archive_digest: Digest::from_bytes([5; 48]),
            federation_generation: 1,
            suffix: None,
        };
        let (request, outbound) = session.receive_snapshot(expected)?;
        ensure!(matches!(
            outbound.body,
            Some(pb::sync_frame::Body::ReceiveSnapshot(_))
        ));
        rejected(
            &mut session,
            frame(pb::sync_frame::Body::Acknowledged(pb::Acknowledged {
                request,
                position: Some(wire::position_to_pb(expected.position)),
            })),
            Code::InvalidArgument,
        )?;

        let (mut session, local, _) = ready()?;
        let expected = SnapshotReceivedRequest {
            authenticated_subscriber: local,
            subscription: SubscriptionRef {
                subscriber: local,
                id: SubscriptionId::from_bytes([4; 16]),
            },
            ..expected
        };
        let (request, _) = session.receive_snapshot(expected)?;
        let response = wire::snapshot_received_to_pb(request, expected.into());
        ensure!(matches!(
            session.receive(frame(pb::sync_frame::Body::SnapshotReceived(response)))?,
            FederationSubscriberEvent::Completed {
                result: Ok(FederationSubscriberResult::SnapshotReceived(received)),
                ..
            } if received == expected.into()
        ));
        Ok(())
    }

    #[test]
    fn request_correlation_rejects_unknown_replay_variant_and_identity() -> Result<()> {
        let (mut session, local, remote) = ready()?;
        let request = open(local, remote);
        let (number, _) = session.open(request.clone())?;
        ensure!(number == 1);
        ensure!(
            session
                .open(request.clone())
                .err()
                .is_some_and(|status| status.code() == Code::ResourceExhausted)
        );
        rejected(
            &mut session,
            opened(number + 1, &request)?,
            Code::InvalidArgument,
        )?;

        let (mut session, local, remote) = ready()?;
        let request = open(local, remote);
        let (number, _) = session.open(request)?;
        rejected(
            &mut session,
            frame(pb::sync_frame::Body::Acknowledged(pb::Acknowledged {
                request: number,
                position: Some(pb::Position {
                    sequence: 1,
                    digest: vec![1; 48],
                }),
            })),
            Code::InvalidArgument,
        )?;

        let (mut session, local, remote) = ready()?;
        let request = open(local, remote);
        let (number, _) = session.open(request.clone())?;
        let mut wrong = opened(number, &request)?;
        if let Some(pb::sync_frame::Body::Opened(value)) = &mut wrong.body {
            value.request_id = vec![8; 16];
        }
        rejected(&mut session, wrong, Code::InvalidArgument)?;

        let (mut session, local, remote) = ready()?;
        let request = open(local, remote);
        let (number, _) = session.open(request.clone())?;
        ensure!(matches!(
            session.receive(opened(number, &request)?)?,
            FederationSubscriberEvent::Completed {
                request: 1,
                result: Ok(FederationSubscriberResult::Opened(_))
            }
        ));
        rejected(
            &mut session,
            opened(number, &request)?,
            Code::InvalidArgument,
        )?;

        let (mut session, local, remote) = ready()?;
        let subscription = open(local, remote).subscription;
        let (number, _) = session.inspect(InspectSubscriptionRequest {
            authenticated_subscriber: local,
            subscription,
        })?;
        let wrong_inspection = wire::inspected_to_pb(
            number,
            &SubscriptionInspection {
                subscription,
                stream: StreamRef {
                    publisher: local,
                    id: StreamId::from_bytes([3; 16]),
                },
                export: ExportName::new("friends")?,
                subscription_revision: 1,
                start: None,
                acknowledged: None,
                head: None,
                minimum_available: 1,
                closed: false,
            },
        );
        rejected(
            &mut session,
            frame(pb::sync_frame::Body::Inspected(wrong_inspection)),
            Code::InvalidArgument,
        )?;

        let (mut session, local, remote) = ready()?;
        let subscription = open(local, remote).subscription;
        let (number, _) = session.close_subscription(CloseSubscriptionRequest {
            authenticated_subscriber: local,
            request_id: RequestId::from_bytes([9; 16]),
            subscription,
            expected_subscription_revision: None,
        })?;
        rejected(
            &mut session,
            frame(pb::sync_frame::Body::Closed(pb::Closed {
                request: number,
                request_id: vec![8; 16],
                subscription: Some(wire::subscription_to_pb(subscription)),
                subscription_revision: 2,
            })),
            Code::InvalidArgument,
        )?;

        let (mut session, local, remote) = ready()?;
        let request = open(local, remote);
        let (number, _) = session.open(request)?;
        session
            .pending
            .get_mut(&number)
            .ok_or_else(|| anyhow::anyhow!("missing queued request"))?
            .deadline = Instant::now() - Duration::from_millis(1);
        ensure!(
            session
                .check_response_deadline()
                .err()
                .is_some_and(|status| status.code() == Code::DeadlineExceeded)
        );
        Ok(())
    }

    #[test]
    fn registered_subject_signs_each_outbound_sync_frame() -> Result<()> {
        let (mut session, local, remote) = ready()?;
        let issuer_key = SubjectIssuerKey::generate()?;
        let issuer = issuer_key.issuer()?;
        let holder = Arc::new(SubjectHolderKey::generate()?);
        let assertion = SubjectAssertion::new(
            issuer.id(),
            "people",
            "alice",
            remote,
            local,
            SubjectPurpose::Sync,
            100,
            200,
            holder.public_key(),
        )?;
        let credentials = Arc::new(FederationHostedSubjectCredentials::new(
            &issuer,
            assertion.clone(),
            issuer_key.sign_assertion(&assertion)?,
            holder,
        )?);
        let (number, registration) = session.register_subject(7, credentials)?;
        ensure!(matches!(
            registration.body,
            Some(pb::sync_frame::Body::RegisterSubject(_))
        ));
        ensure!(matches!(
            session.receive(frame(pb::sync_frame::Body::SubjectRegistered(
                pb::SubjectRegistered {
                    request: number,
                    context_id: 7,
                }
            )))?,
            FederationSubscriberEvent::Completed {
                result: Ok(FederationSubscriberResult::SubjectRegistered(7)),
                ..
            }
        ));
        let (_, outbound) = session.open_as(7, open(local, remote))?;
        let Some(pb::sync_frame::Body::Open(opened)) = outbound.body else {
            anyhow::bail!("missing hosted Open frame");
        };
        ensure!(opened.context_id == 7);
        ensure!(
            opened.holder_request_signature.len()
                == xolotl_federation::FederationRoot::SIGNATURE_LEN
        );
        ensure!(wire::subject_request_digest(&pb::sync_frame::Body::Open(opened))? != [0; 48]);
        Ok(())
    }

    #[test]
    fn invoke_subject_signs_call_and_cannot_open_stream() -> Result<()> {
        let (mut session, local, remote) = ready()?;
        let issuer_key = SubjectIssuerKey::generate()?;
        let issuer = issuer_key.issuer()?;
        let holder = Arc::new(SubjectHolderKey::generate()?);
        let assertion = SubjectAssertion::new(
            issuer.id(),
            "people",
            "alice",
            remote,
            local,
            SubjectPurpose::Invoke,
            100,
            200,
            holder.public_key(),
        )?;
        let subject = FederationSubject::Hosted(assertion.subject().clone());
        let credentials = Arc::new(FederationHostedSubjectCredentials::new(
            &issuer,
            assertion.clone(),
            issuer_key.sign_assertion(&assertion)?,
            holder,
        )?);
        let (registration, _) = session.register_subject(8, credentials)?;
        session.receive(frame(pb::sync_frame::Body::SubjectRegistered(
            pb::SubjectRegistered {
                request: registration,
                context_id: 8,
            },
        )))?;
        ensure!(session.open_as(8, open(local, remote)).is_err());
        let (_, outgoing) = session.prepare_call_as(
            8,
            PrepareCallRequest {
                authenticated_origin: local,
                subject,
                origin_request_id: RequestId::from_bytes([21; 16]),
                target: CallTarget {
                    export: ExportName::new("actions")?,
                    path: CallPath::new("/timer")?,
                    method: CallMethod::new("start")?,
                    contract_digest: [22; 32],
                },
                input_digest: Digest::from_bytes([23; 48]),
                input_bytes: 1,
                prepare_deadline_ms: 170,
                execution_deadline_ms: 180,
                result_retention_ms: 10,
            },
        )?;
        let Some(pb::sync_frame::Body::PrepareCall(value)) = outgoing.body else {
            anyhow::bail!("missing hosted PrepareCall frame");
        };
        ensure!(value.context_id == 8);
        ensure!(
            value.holder_request_signature.len()
                == xolotl_federation::FederationRoot::SIGNATURE_LEN
        );
        ensure!(
            wire::subject_request_digest(&pb::sync_frame::Body::PrepareCall(value))? != [0; 48]
        );
        Ok(())
    }
}
