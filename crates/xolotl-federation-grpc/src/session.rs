//! A single-connection federation admission and request dispatcher. A host
//! supplies the live rustls connection, drives the stream, and owns the
//! current peer policy. This module never promotes wire claims to authority.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Instant,
};

use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};
use prost::Message as _;
use tonic::Status;
use xolotl_federation::{
    CallCancelled, CallInvoked, CancelCallRequest, FederationCallStore, FederationError,
    FederationGuestStore, FederationInvitationStore, FederationNodeId, FederationOnlineKey,
    FederationOnlineKeyAuthorization, FederationPublicService, FederationRoot, FederationService,
    FederationSessionTranscript, FederationSnapshotPublisherStore, FederationSubject,
    HostedSubject, InvitationId, InvitationSecret, InvokeCallRequest, ObjectDeliveryContext,
    ObjectReadAdmission, ObjectReadAuthority, ObjectReadPage, ObjectReadRequest,
    PrepareCallRequest, PublicReadRequest, RedeemInvitationRequest, RequestId,
    RootSignaturePurpose, SessionSubjects, SnapshotContentSource, SubjectIssuer, SubjectIssuerId,
    SubjectIssuerPolicy, SubjectProofError, SubjectPurpose, VerifiedFederationPeerProof,
    verify_federation_peer_proof,
};
use xolotl_proto::xolotl::v1::federation as pb;

use crate::{
    config::FederationGrpcConfig,
    delivery::{DeliveryCheck, DeliveryFrame},
    tls::{FederationTlsChannel, LocalRole},
    wire::{self, PeerHello},
};

/// The host's authoritative, current admission decision. Implementations must
/// use a trusted, rollback-aware clock and check peer enablement, online-key
/// generation, exact authorization digest/revocation and local security policy.
/// A cached handshake result
/// is insufficient: `check_current_peer` runs before every business request.
pub trait FederationPeerPolicy: Send + Sync {
    /// Receiver-side admission path. Unconfigured followers override this
    /// with their explicit immutable local pin and the unconfigured boundary.
    fn receiver_decision(
        &self,
        proof: VerifiedFederationPeerProof,
    ) -> Result<xolotl_federation::FederationDecision, Status> {
        Ok(xolotl_federation::FederationDecision::new(
            proof,
            xolotl_federation::FederationAdmission::Private,
            self.decision_clock()?,
        ))
    }

    /// Supply a trusted decision clock that does not acquire backend locks.
    /// A frame precheck clock that writes the same database is not suitable.
    fn decision_clock(&self) -> Result<Arc<dyn xolotl_federation::FederationObjectClock>, Status> {
        Err(Status::failed_precondition(
            "atomic federation admission unavailable",
        ))
    }

    /// Return trusted wall time for authorization validity and replay bounds.
    fn current_time_ms(&self) -> Result<u64, Status>;

    /// Recheck the exact proven online authorization before each private
    /// business frame; revocation cannot rely on the initial handshake alone.
    fn check_current_peer(
        &self,
        proof: VerifiedFederationPeerProof,
        now_ms: u64,
    ) -> Result<(), Status>;

    /// Admit an authenticated, unconfigured node to public reads only. Hosts
    /// must reject every configured peer row here, including disabled peers.
    fn check_public_peer(
        &self,
        _proof: VerifiedFederationPeerProof,
        _now_ms: u64,
    ) -> Result<(), Status> {
        Err(Status::permission_denied(
            "public federation reader rejected",
        ))
    }

    /// A separate, local grant to trust one issuer for a namespace and use.
    /// Existing node admission never implies authority to assert hosted users.
    fn accepts_subject_issuer(
        &self,
        _issuer: SubjectIssuerId,
        _namespace: &str,
        _purpose: SubjectPurpose,
        _presenter: FederationNodeId,
        _audience: FederationNodeId,
    ) -> bool {
        false
    }
}

/// Host bridge which persists the original work identity and coordinates the
/// checked Kernel acceptance receipt. A call directory by itself is not this
/// bridge; without one, Invoke returns Unavailable before changing call state.
pub trait FederationCallInvoker: Send + Sync {
    /// Carry authority to actual Kernel admission, not merely queue insertion.
    fn bind_invoker_decision(
        &self,
        _decision: xolotl_federation::FederationDecision,
    ) -> Result<Arc<dyn FederationCallInvoker>, FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Reject an exact target that this host cannot execute durably before a
    /// target-side CallRef is reserved. The call store still owns the atomic
    /// authorization and reservation decision.
    fn validate_prepare(&self, request: &PrepareCallRequest) -> Result<(), FederationError>;

    /// Hand the original CallRef to a checked durable Kernel bridge.
    fn invoke_call(
        &self,
        request: InvokeCallRequest,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<CallInvoked, FederationError>> + Send + '_>>;
    /// Persist cancellation selection and ask the original Kernel journal to
    /// stop; the returned receipt does not itself prove a terminal.
    fn cancel_call(
        &self,
        request: CancelCallRequest,
        now_ms: u64,
    ) -> Pin<Box<dyn Future<Output = Result<CallCancelled, FederationError>> + Send + '_>>;
}

/// A bounded object read returning bytes and their native disclosure context.
/// Readers with equivalent retained policy state may omit the context; final
/// delivery still requires their explicit authorization hook.
pub type ObjectReadFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<(ObjectReadPage, Option<ObjectDeliveryContext>), FederationError>,
            > + Send
            + 'a,
    >,
>;

type ObjectDeliveryScope = (
    ObjectReadRequest,
    ObjectReadAuthority,
    Arc<dyn FederationObjectReader>,
    Arc<OnceLock<ObjectDeliveryContext>>,
);

/// Host-owned asynchronous object backend. The Session verifies the presenter
/// and hosted subject before handing a request to this bridge.
pub trait FederationObjectReader: Send + Sync {
    /// Recheck current authority and mutable disclosure policy in the final
    /// handoff's bounded blocking job, without rereading payload/metadata,
    /// charging quota or repeating business effects. Host clock/policy work may
    /// block. Delegate to the bound service with its native read context.
    /// Custom readers must explicitly implement this contract; the default
    /// denies disclosure. A missing
    /// context is not evidence: only readers with their own equivalent retained
    /// disclosure state may accept it.
    fn authorize_delivery(
        &self,
        _request: &ObjectReadRequest,
        _authority: ObjectReadAuthority,
        _context: Option<&ObjectDeliveryContext>,
    ) -> Result<(), FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Bind the authority to both the reservation and final disclosure store.
    fn bind_reader_decision(
        &self,
        _decision: xolotl_federation::FederationDecision,
    ) -> Result<Arc<dyn FederationObjectReader>, FederationError> {
        Err(FederationError::Unauthorized)
    }

    /// Node whose object authority this reader enforces.
    fn local_node(&self) -> FederationNodeId;
    /// Read one authorized, bounded range while retaining a stable transfer
    /// identity. `authority` comes from this Session, never the remote frame;
    /// the reader rechecks its proof and mode with the grant in storage.
    /// Return locally produced native disclosure context, never reconstructed
    /// wire evidence. Custom readers may return None only when their delivery
    /// hook retains equivalent state for the exact read and policy decision.
    fn read_object(
        &self,
        request: ObjectReadRequest,
        authority: ObjectReadAuthority,
    ) -> crate::ObjectReadFuture<'_>;
}

pub(crate) struct PendingObject {
    pub request: u64,
    pub read: ObjectReadRequest,
    pub authority: ObjectReadAuthority,
    pub reader: Arc<dyn FederationObjectReader>,
    pub max_frame_bytes: usize,
    context: Arc<OnceLock<ObjectDeliveryContext>>,
}

impl PendingObject {
    pub(crate) async fn read_page(&self) -> Result<ObjectReadPage, FederationError> {
        let (page, context) = self
            .reader
            .read_object(self.read.clone(), self.authority)
            .await?;
        if let Some(context) = context {
            self.context
                .set(context)
                .map_err(|_error| FederationError::Unauthorized)?;
        }
        Ok(page)
    }

    pub(crate) async fn execute(self, deadline: Instant) -> Result<pb::SyncFrame, Status> {
        let expected = self.read.clone();
        let result =
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), self.read_page())
                .await
                .map_err(|_error| {
                    Status::unavailable("object read outcome indeterminate; retry transfer ID")
                })?;
        object_response(self.request, &expected, result, self.max_frame_bytes)
    }
}

pub(crate) struct PendingGuest {
    request: u64,
    max_frame_bytes: usize,
    operation: GuestOperation,
}

enum GuestOperation {
    Redeem(Arc<dyn FederationInvitationStore>, RedeemInvitationRequest),
    Open(
        Arc<dyn FederationGuestStore>,
        HostedSubject,
        u64,
        xolotl_federation::OpenRequest,
    ),
    Inspect(
        Arc<dyn FederationGuestStore>,
        HostedSubject,
        u64,
        xolotl_federation::InspectSubscriptionRequest,
    ),
    Close(
        Arc<dyn FederationGuestStore>,
        HostedSubject,
        u64,
        xolotl_federation::CloseSubscriptionRequest,
    ),
    Read(
        Arc<dyn FederationGuestStore>,
        HostedSubject,
        u64,
        xolotl_federation::ReadRequest,
    ),
    Acknowledge(
        Arc<dyn FederationGuestStore>,
        HostedSubject,
        u64,
        xolotl_federation::AcknowledgeRequest,
    ),
}

impl PendingGuest {
    pub(crate) fn execute(self) -> Result<pb::SyncFrame, Status> {
        use pb::sync_frame::Body;
        let request = self.request;
        let response = match self.operation {
            GuestOperation::Redeem(store, redemption) => {
                match store.redeem_invitation(redemption) {
                    Ok(result) => frame(Body::InvitationRedeemed(pb::InvitationRedeemed {
                        request,
                        invitation_id: result.invitation.as_bytes().to_vec(),
                        request_id: result.request_id.as_bytes().to_vec(),
                        stream: Some(wire::stream_to_pb(result.grant.grant.stream)),
                        grant_revision: result.grant.revision,
                        grant_expires_ms: result.grant.grant.expires_ms,
                        history_floor: result.grant.history_floor,
                        currently_authorized: result.currently_authorized,
                    })),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }
            }
            GuestOperation::Open(store, subject, now, open) => {
                match store.open_guest(subject, now, open) {
                    Ok(result) => frame(Body::Opened(wire::opened_to_pb(request, &result))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }
            }
            GuestOperation::Inspect(store, subject, now, inspect) => {
                match store.inspect_guest_subscription(subject, now, inspect) {
                    Ok(result) => frame(Body::Inspected(wire::inspected_to_pb(request, &result))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }
            }
            GuestOperation::Close(store, subject, now, close) => {
                match store.close_guest_subscription(subject, now, close) {
                    Ok(result) => frame(Body::Closed(wire::closed_to_pb(request, result))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }
            }
            GuestOperation::Read(store, subject, now, read) => {
                let subscription = read.subscription;
                match store.read_guest(subject, now, read) {
                    Ok(result) => frame(Body::Batch(wire::batch_to_pb(
                        request,
                        subscription,
                        &result,
                    ))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }
            }
            GuestOperation::Acknowledge(store, subject, now, ack) => {
                match store.acknowledge_guest(subject, now, ack) {
                    Ok(position) => frame(Body::Acknowledged(pb::Acknowledged {
                        request,
                        position: Some(wire::position_to_pb(position)),
                    })),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }
            }
        };
        if response.encoded_len() > self.max_frame_bytes {
            return Err(Status::resource_exhausted(
                "guest response exceeds negotiated frame limit",
            ));
        }
        Ok(response)
    }
}

pub(crate) struct PendingInvoke {
    pub request: u64,
    pub call: InvokeCallRequest,
    pub now_ms: u64,
    pub invoker: Arc<dyn FederationCallInvoker>,
}

pub(crate) struct PendingCancel {
    pub request: u64,
    pub call: CancelCallRequest,
    pub now_ms: u64,
    pub invoker: Arc<dyn FederationCallInvoker>,
}

struct IssuerPolicy<'a>(&'a dyn FederationPeerPolicy);

impl SubjectIssuerPolicy for IssuerPolicy<'_> {
    fn accepts(
        &self,
        issuer: SubjectIssuerId,
        namespace: &str,
        purpose: SubjectPurpose,
        presenter: FederationNodeId,
        audience: FederationNodeId,
    ) -> bool {
        self.0
            .accepts_subject_issuer(issuer, namespace, purpose, presenter, audience)
    }
}

/// Reusable local signer. Its root authorization is verified at construction;
/// the online key is checked against the authorization before any session is
/// created and its validity is rechecked during handshake and business frames.
/// The host remains responsible for key wrapping and rotation.
pub struct FederationLocalCredentials {
    pub(crate) root: FederationRoot,
    pub(crate) authorization: FederationOnlineKeyAuthorization,
    pub(crate) root_signature: Vec<u8>,
    pub(crate) online_key: FederationOnlineKey,
}

impl FederationLocalCredentials {
    /// Verify the root's authorization for the supplied online key before the
    /// credentials can be used in any Session.
    pub fn new(
        root: FederationRoot,
        authorization: FederationOnlineKeyAuthorization,
        root_signature: Vec<u8>,
        online_key: FederationOnlineKey,
    ) -> Result<Self, Status> {
        if online_key.public_key() != authorization.public_key() {
            return Err(Status::invalid_argument(
                "local federation online key does not match authorization",
            ));
        }
        root.verify(
            RootSignaturePurpose::OnlineKeyAuthorization,
            &authorization.encode(),
            &root_signature,
        )
        .map_err(|_error| Status::invalid_argument("invalid local federation authorization"))?;
        Ok(Self {
            root,
            authorization,
            root_signature,
            online_key,
        })
    }

    /// Stable root-derived node identity; online-key rotation preserves it.
    pub fn node_id(&self) -> FederationNodeId {
        self.root.node_id()
    }

    /// Exact root-signed online authorization fingerprint for local admission.
    pub fn authorization_digest(&self) -> [u8; 48] {
        use sha2::{Digest as _, Sha384};
        Sha384::digest(self.authorization.encode()).into()
    }

    pub(crate) fn check_validity(&self, now_ms: u64) -> Result<(), Status> {
        if now_ms < self.authorization.not_before_ms() || now_ms >= self.authorization.expires_ms()
        {
            return Err(Status::failed_precondition(
                "local federation online key is outside its validity period",
            ));
        }
        Ok(())
    }

    pub(crate) fn hello(
        &self,
        nonce: [u8; 32],
        config: FederationGrpcConfig,
        max_in_flight: u32,
    ) -> pb::Hello {
        pb::Hello {
            protocol_version: crate::FEDERATION_PROTOCOL_VERSION,
            node_id: self.node_id().as_bytes().to_vec(),
            max_frame_bytes: config.max_frame_bytes as u64,
            max_in_flight,
            max_batch_records: config.max_batch_records as u32,
            max_batch_bytes: config.max_batch_bytes as u64,
            root_descriptor: self.root.encode(),
            online_authorization: self.authorization.encode(),
            root_signature: self.root_signature.clone(),
            nonce: nonce.to_vec(),
            required_features: Vec::new(),
            served_capabilities: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct PeerLimits {
    served_capabilities: u32,
    max_frame_bytes: usize,
    max_in_flight: usize,
    max_batch_records: usize,
    max_batch_bytes: usize,
}

pub(crate) struct VerifiedSession {
    pub served_capabilities: u32,
    pub channel: FederationTlsChannel,
    pub proof: VerifiedFederationPeerProof,
    pub transcript: Arc<FederationSessionTranscript>,
    pub max_frame_bytes: usize,
    pub max_in_flight: usize,
    pub max_batch_records: usize,
    pub max_batch_bytes: usize,
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
        limits: PeerLimits,
        mode: AdmissionMode,
        subjects: Option<SessionSubjects>,
        transcript: Arc<FederationSessionTranscript>,
    },
    Closed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AdmissionMode {
    Private,
    PublicOnly,
    Guest,
}

/// Inbound request gate for one full-handshake, hybrid TLS connection. Either
/// peer may dial. After proof verification, a paired subscriber state can
/// originate requests on this same Session while this gate verifies and
/// dispatches incoming business frames.
///
/// The initial Hello and returned Authenticate must be sent on that same
/// connection before the caller polls another inbound frame. A production
/// stream driver must bound concurrent handshakes, apply a read timeout and
/// configure tonic's `max_decoding_message_size` to `config.max_frame_bytes`
/// before protobuf decoding; the post-decode limit below is only a second gate.
/// `receive` performs ML-DSA verification synchronously, so a Tokio driver
/// must run handshake admission on a bounded blocking executor and cap
/// concurrent verification work instead of blocking its I/O tasks.
pub struct FederationGrpcPublisherSession {
    channel: FederationTlsChannel,
    local: Arc<FederationLocalCredentials>,
    policy: Arc<dyn FederationPeerPolicy>,
    service: FederationService,
    public_service: Option<FederationPublicService>,
    invitation_store: Option<Arc<dyn FederationInvitationStore>>,
    guest_store: Option<Arc<dyn FederationGuestStore>>,
    call_store: Option<Arc<dyn FederationCallStore>>,
    call_invoker: Option<Arc<dyn FederationCallInvoker>>,
    object_reader: Option<Arc<dyn FederationObjectReader>>,
    snapshot_publisher: Option<(
        Arc<dyn FederationSnapshotPublisherStore>,
        Arc<dyn SnapshotContentSource>,
    )>,
    config: FederationGrpcConfig,
    local_hello: pb::Hello,
    handshake_deadline: Instant,
    last_time_ms: u64,
    phase: Phase,
    pending_invoke: Option<PendingInvoke>,
    pending_cancel: Option<PendingCancel>,
    pending_object: Option<PendingObject>,
    pending_guest: Option<PendingGuest>,
    last_request_id: u64,
    delivery_subject: Option<(FederationSubject, SubjectPurpose, u64)>,
    delivery_object: Option<ObjectDeliveryScope>,
}

impl FederationGrpcPublisherSession {
    pub(crate) fn response_protector(
        &self,
    ) -> Result<
        impl Fn(pb::SyncFrame) -> Result<DeliveryFrame, Status> + Send + 'static + use<>,
        Status,
    > {
        let Phase::Ready { proof, mode, .. } = &self.phase else {
            return Err(Status::failed_precondition("delivery Session is not ready"));
        };
        let proof = *proof;
        let mode = *mode;
        let peer = proof.node_id();
        let decision = self.decision(proof, mode)?;
        let (subject, purpose, deadline) = self
            .delivery_subject
            .clone()
            .ok_or_else(|| Status::failed_precondition("delivery request was not admitted"))?;
        let policy = Arc::clone(&self.policy);
        let local = Arc::clone(&self.local);
        let floor = self.last_time_ms;
        let delivery_subject = subject.clone();
        let base: DeliveryCheck = Arc::new(move || {
            let now = policy.current_time_ms()?;
            if now < floor || now >= proof.expires_ms() || now >= deadline {
                return Err(Status::permission_denied(
                    "federation delivery authority expired",
                ));
            }
            local.check_validity(now)?;
            match mode {
                AdmissionMode::Private => policy.check_current_peer(proof, now)?,
                AdmissionMode::PublicOnly | AdmissionMode::Guest => {
                    policy.check_public_peer(proof, now)?
                }
            }
            if let FederationSubject::Hosted(subject) = &delivery_subject
                && !policy.accepts_subject_issuer(
                    subject.issuer,
                    &subject.namespace,
                    purpose,
                    peer,
                    local.node_id(),
                )
            {
                return Err(Status::permission_denied(
                    "federation delivery subject revoked",
                ));
            }
            Ok(())
        });
        let service = self.service.clone();
        let guest = self.guest_store.clone();
        let public = self.public_service.clone();
        let snapshots = self
            .snapshot_publisher
            .as_ref()
            .map(|(store, _)| Arc::clone(store));
        let calls = self.call_store.clone();
        let object = self.delivery_object.clone();
        Ok(move |response: pb::SyncFrame| {
            use pb::sync_frame::Body;
            let mut scope: Option<DeliveryCheck> = None;
            let subscription = match response.body.as_ref() {
                Some(Body::Batch(value)) => value.subscription.clone(),
                Some(Body::Opened(value)) => value.subscription.clone(),
                Some(Body::Inspected(value)) => value.subscription.clone(),
                _ => None,
            };
            if let Some(subscription) = subscription {
                let subscription = wire::subscription(subscription)?;
                let request = xolotl_federation::InspectSubscriptionRequest {
                    authenticated_subscriber: peer,
                    subscription,
                };
                let subject = subject.clone();
                let clock = decision.clone();
                let payload = matches!(response.body.as_ref(), Some(Body::Batch(_)));
                if mode == AdmissionMode::Guest {
                    let store = guest
                        .as_ref()
                        .ok_or_else(|| Status::permission_denied("guest delivery unavailable"))?
                        .bind_guest_decision(decision.clone())
                        .map_err(decision_status)?;
                    let subject = guest_subject(subject)?;
                    scope = Some(Arc::new(move || {
                        store
                            .authorize_guest_delivery(
                                &subject,
                                request,
                                payload,
                                clock.now_ms().map_err(decision_status)?,
                            )
                            .map_err(decision_status)
                    }));
                } else {
                    let service = service
                        .with_decision(decision.clone())
                        .map_err(decision_status)?;
                    scope = Some(Arc::new(move || {
                        service
                            .store()
                            .authorize_subscription_delivery(
                                &subject,
                                request,
                                payload,
                                clock.now_ms().map_err(decision_status)?,
                            )
                            .map_err(decision_status)
                    }));
                }
            }
            match response.body.as_ref() {
                Some(Body::Hello(_) | Body::Authenticate(_) | Body::Failure(_)) => {
                    return Ok(response.into());
                }
                Some(Body::PublicBatch(value)) => {
                    let stream = wire::stream(
                        value
                            .stream
                            .clone()
                            .ok_or_else(|| Status::internal("missing delivery stream"))?,
                    )?;
                    let revision = value.policy_revision;
                    let store = public
                        .as_ref()
                        .ok_or_else(|| Status::permission_denied("public delivery unavailable"))?
                        .store()
                        .bind_public_decision(decision.clone())
                        .map_err(decision_status)?;
                    scope = Some(Arc::new(move || {
                        store
                            .authorize_public_delivery(peer, stream, revision)
                            .map_err(decision_status)
                    }));
                }
                Some(Body::SnapshotOffered(value)) => {
                    let expected = wire::snapshot_offer(
                        value
                            .offer
                            .clone()
                            .ok_or_else(|| Status::internal("missing delivery offer"))?,
                    )?;
                    let store = snapshots
                        .as_ref()
                        .ok_or_else(|| Status::permission_denied("snapshot delivery unavailable"))?
                        .bind_snapshot_publisher_decision(decision.clone())
                        .map_err(decision_status)?;
                    scope = Some(Arc::new(move || {
                        store
                            .authorize_snapshot_delivery(
                                peer,
                                expected.manifest.subscription,
                                expected.manifest.binding_digest(),
                                Some(expected.publication_digest),
                            )
                            .map_err(decision_status)
                    }));
                }
                Some(Body::SnapshotChunk(value)) => {
                    let subscription = wire::subscription(
                        value
                            .subscription
                            .clone()
                            .ok_or_else(|| Status::internal("missing delivery subscription"))?,
                    )?;
                    let digest: [u8; 48] = value
                        .manifest_digest
                        .as_slice()
                        .try_into()
                        .map_err(|_error| Status::internal("invalid delivery manifest digest"))?;
                    let store = snapshots
                        .as_ref()
                        .ok_or_else(|| Status::permission_denied("snapshot delivery unavailable"))?
                        .bind_snapshot_publisher_decision(decision.clone())
                        .map_err(decision_status)?;
                    scope = Some(Arc::new(move || {
                        store
                            .authorize_snapshot_delivery(
                                peer,
                                subscription,
                                xolotl_federation::Digest::from_bytes(digest),
                                None,
                            )
                            .map_err(decision_status)
                    }));
                }
                Some(Body::SnapshotReceived(value)) => {
                    let received = wire::receive_snapshot(
                        peer,
                        pb::ReceiveSnapshot {
                            request: value.request,
                            subscription: value.subscription.clone(),
                            manifest_digest: value.manifest_digest.clone(),
                            publication_digest: value.publication_digest.clone(),
                            position: value.position.clone(),
                            context_id: 0,
                            holder_request_signature: Vec::new(),
                            install_id: value.install_id.clone(),
                            archive_digest: value.archive_digest.clone(),
                            federation_generation: value.federation_generation,
                            suffix: value.suffix.clone(),
                        },
                    )?;
                    let store = snapshots
                        .as_ref()
                        .ok_or_else(|| Status::permission_denied("snapshot delivery unavailable"))?
                        .bind_snapshot_publisher_decision(decision.clone())
                        .map_err(decision_status)?;
                    scope = Some(Arc::new(move || {
                        store
                            .authorize_snapshot_receipt_delivery(peer, received.into())
                            .map_err(decision_status)
                    }));
                }
                Some(Body::CallInspected(value))
                    if value.result.is_some() || !value.unresolved_effect_ids.is_empty() =>
                {
                    let call = wire::call_ref(
                        value
                            .call
                            .clone()
                            .ok_or_else(|| Status::internal("missing delivery CallRef"))?,
                    )?;
                    let request = xolotl_federation::InspectCallRequest {
                        authenticated_origin: peer,
                        subject: subject.clone(),
                        call,
                    };
                    let store = calls
                        .as_ref()
                        .ok_or_else(|| Status::permission_denied("call delivery unavailable"))?
                        .bind_call_decision(decision.clone())
                        .map_err(decision_status)?;
                    let clock = decision.clone();
                    let retained_until = value
                        .result
                        .as_ref()
                        .map(|_| value.result_retained_until_ms);
                    scope = Some(Arc::new(move || {
                        store
                            .authorize_call_delivery(
                                &request,
                                retained_until,
                                clock.now_ms().map_err(decision_status)?,
                            )
                            .map_err(decision_status)
                    }));
                }
                Some(Body::ObjectChunk(_)) => {
                    let (request, authority, reader, context) =
                        object.clone().ok_or_else(|| {
                            Status::permission_denied("object delivery authority unavailable")
                        })?;
                    scope = Some(Arc::new(move || {
                        reader
                            .authorize_delivery(&request, authority, context.get())
                            .map_err(decision_status)
                    }));
                }
                _ => {}
            }
            let base = Arc::clone(&base);
            Ok(DeliveryFrame::protected(
                response,
                Arc::new(move || {
                    base()?;
                    if let Some(scope) = &scope {
                        scope()?;
                    }
                    Ok(())
                }),
            ))
        })
    }

    fn decision(
        &self,
        proof: VerifiedFederationPeerProof,
        mode: AdmissionMode,
    ) -> Result<xolotl_federation::FederationDecision, Status> {
        Ok(xolotl_federation::FederationDecision::new(
            proof,
            match mode {
                AdmissionMode::Private => xolotl_federation::FederationAdmission::Private,
                AdmissionMode::PublicOnly | AdmissionMode::Guest => {
                    xolotl_federation::FederationAdmission::Unconfigured
                }
            },
            self.policy.decision_clock()?,
        ))
    }

    /// `channel` must come from this RPC's own completed TLS connection. The
    /// host configures certificate trust, disables 0-RTT and resumption, then
    /// extracts the channel binding before handing any stream frame here.
    pub fn new(
        channel: FederationTlsChannel,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        service: FederationService,
        config: FederationGrpcConfig,
    ) -> Result<Self, Status> {
        let config = config.validate()?;
        if local.node_id() != service.local_node() {
            return Err(Status::invalid_argument(
                "federation signer does not belong to the local store",
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
        let local_hello = local.hello(nonce, config, config.max_in_flight as u32);
        let handshake_deadline = Instant::now()
            .checked_add(config.hello_timeout)
            .ok_or_else(|| Status::invalid_argument("federation Hello timeout overflows"))?;
        Ok(Self {
            channel,
            local,
            policy,
            service,
            public_service: None,
            invitation_store: None,
            guest_store: None,
            call_store: None,
            call_invoker: None,
            object_reader: None,
            snapshot_publisher: None,
            config,
            local_hello,
            handshake_deadline,
            last_time_ms: now_ms,
            phase: Phase::New,
            pending_invoke: None,
            pending_cancel: None,
            pending_object: None,
            pending_guest: None,
            last_request_id: 0,
            delivery_subject: None,
            delivery_object: None,
        })
    }

    /// Enable durable federated calls on this authenticated Session. The call
    /// directory belongs to the same node as the publication store.
    pub fn with_call_store(mut self, store: Arc<dyn FederationCallStore>) -> Result<Self, Status> {
        if store.local_node() != self.local.node_id() {
            return Err(Status::invalid_argument(
                "federation call store belongs to another node",
            ));
        }
        self.call_store = Some(store);
        Ok(self)
    }

    /// Enable checked target Kernel handoff for prepared calls.
    pub fn with_call_invoker(mut self, invoker: Arc<dyn FederationCallInvoker>) -> Self {
        self.call_invoker = Some(invoker);
        self
    }

    /// Enable explicitly public stream reads for authenticated unknown nodes.
    pub fn with_public_service(mut self, service: FederationPublicService) -> Result<Self, Status> {
        if service.store().local_node() != self.local.node_id() {
            return Err(Status::invalid_argument(
                "public service belongs to another node",
            ));
        }
        self.public_service = Some(service);
        Ok(self)
    }

    /// Admit unconfigured, authenticated guests for holder-proven invitation
    /// redemption and exact invitation-origin stream grants.
    pub fn with_invitation_store(
        mut self,
        store: Arc<dyn FederationInvitationStore>,
    ) -> Result<Self, Status> {
        if store.local_node() != self.local.node_id() {
            return Err(Status::invalid_argument(
                "invitation store belongs to another node",
            ));
        }
        self.invitation_store = Some(store);
        Ok(self)
    }

    /// Enable guest operations restricted to exact redeemed subject grants.
    pub fn with_guest_store(mut self, store: Arc<dyn FederationGuestStore>) -> Self {
        self.guest_store = Some(store);
        self
    }

    /// Enable exact object reads backed by this node's checked object reader.
    pub fn with_object_reader(
        mut self,
        reader: Arc<dyn FederationObjectReader>,
    ) -> Result<Self, Status> {
        if reader.local_node() != self.local.node_id() {
            return Err(Status::invalid_argument(
                "object reader belongs to another node",
            ));
        }
        self.object_reader = Some(reader);
        Ok(self)
    }

    /// Enable private Node-self snapshot offer inspection and bounded reads.
    /// The host owns immutable content and durable publication proof storage.
    pub fn with_snapshot_publisher(
        mut self,
        store: Arc<dyn FederationSnapshotPublisherStore>,
        source: Arc<dyn SnapshotContentSource>,
    ) -> Result<Self, Status> {
        if store.local_node() != self.local.node_id() {
            return Err(Status::invalid_argument(
                "snapshot publisher belongs to another node",
            ));
        }
        self.snapshot_publisher = Some((store, source));
        Ok(self)
    }

    pub(crate) fn take_pending_object(&mut self) -> Option<PendingObject> {
        self.pending_object.take()
    }

    pub(crate) fn take_pending_guest(&mut self) -> Option<PendingGuest> {
        self.pending_guest.take()
    }

    pub(crate) fn is_limited_reader(&self) -> bool {
        matches!(
            self.phase,
            Phase::Ready {
                mode: AdmissionMode::PublicOnly | AdmissionMode::Guest,
                ..
            }
        )
    }

    pub(crate) fn take_pending_invoke(&mut self) -> Option<PendingInvoke> {
        self.pending_invoke.take()
    }

    pub(crate) fn verified_state(&self) -> Result<VerifiedSession, Status> {
        let Phase::Ready {
            proof,
            limits,
            transcript,
            mode: AdmissionMode::Private,
            ..
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
            max_frame_bytes: limits.max_frame_bytes,
            max_in_flight: limits.max_in_flight,
            max_batch_records: limits.max_batch_records,
            max_batch_bytes: limits.max_batch_bytes,
            served_capabilities: limits.served_capabilities,
        })
    }

    pub(crate) fn from_verified(
        verified: VerifiedSession,
        local: Arc<FederationLocalCredentials>,
        policy: Arc<dyn FederationPeerPolicy>,
        service: FederationService,
        config: FederationGrpcConfig,
    ) -> Result<Self, Status> {
        let config = config.validate()?;
        if service.local_node() != local.node_id() || verified.proof.node_id() == local.node_id() {
            return Err(Status::invalid_argument("invalid verified federation peer"));
        }
        let now_ms = policy.current_time_ms()?;
        local.check_validity(now_ms)?;
        policy.check_current_peer(verified.proof, now_ms)?;
        let subjects = SessionSubjects::new(verified.proof, &verified.transcript, local.node_id())
            .map_err(subject_status)?;
        let limits = PeerLimits {
            served_capabilities: verified.served_capabilities,
            max_frame_bytes: verified.max_frame_bytes,
            max_in_flight: verified.max_in_flight,
            max_batch_records: verified.max_batch_records,
            max_batch_bytes: verified.max_batch_bytes,
        };
        Ok(Self {
            channel: verified.channel,
            local,
            policy,
            service,
            public_service: None,
            invitation_store: None,
            guest_store: None,
            call_store: None,
            call_invoker: None,
            object_reader: None,
            snapshot_publisher: None,
            config,
            local_hello: pb::Hello::default(),
            handshake_deadline: Instant::now(),
            last_time_ms: now_ms,
            phase: Phase::Ready {
                proof: verified.proof,
                limits,
                mode: AdmissionMode::Private,
                subjects: Some(subjects),
                transcript: verified.transcript,
            },
            pending_invoke: None,
            pending_cancel: None,
            pending_object: None,
            pending_guest: None,
            last_request_id: 0,
            delivery_subject: None,
            delivery_object: None,
        })
    }

    pub(crate) fn take_pending_cancel(&mut self) -> Option<PendingCancel> {
        self.pending_cancel.take()
    }

    pub(crate) fn finish_invoke(
        &self,
        request: u64,
        result: Result<CallInvoked, FederationError>,
    ) -> Result<pb::SyncFrame, Status> {
        let response = match result {
            Ok(result)
                if matches!(
                    result.status,
                    xolotl_federation::CallStatus::Preparing
                        | xolotl_federation::CallStatus::Accepted
                        | xolotl_federation::CallStatus::Finished
                ) =>
            {
                frame(pb::sync_frame::Body::CallInvoked(wire::call_invoked_to_pb(
                    request, result,
                )))
            }
            Ok(_) => {
                return Err(Status::internal(
                    "call invoker returned invalid success state",
                ));
            }
            Err(error) => frame(pb::sync_frame::Body::Failure(wire::failure(
                request, &error,
            ))),
        };
        let Phase::Ready { limits, .. } = &self.phase else {
            return Err(Status::failed_precondition(
                "federation Session is not authenticated",
            ));
        };
        if response.encoded_len() > self.config.max_frame_bytes
            || response.encoded_len() > limits.max_frame_bytes
        {
            return Err(Status::resource_exhausted(
                "call response exceeds frame limit",
            ));
        }
        Ok(response)
    }

    pub(crate) fn finish_cancel(
        &self,
        request: u64,
        result: Result<CallCancelled, FederationError>,
    ) -> Result<pb::SyncFrame, Status> {
        let response = match result {
            Ok(result) => frame(pb::sync_frame::Body::CallCancelled(
                wire::call_cancelled_to_pb(request, result),
            )),
            Err(error) => frame(pb::sync_frame::Body::Failure(wire::failure(
                request, &error,
            ))),
        };
        let Phase::Ready { limits, .. } = &self.phase else {
            return Err(Status::failed_precondition(
                "federation Session is not authenticated",
            ));
        };
        if response.encoded_len() > self.config.max_frame_bytes
            || response.encoded_len() > limits.max_frame_bytes
        {
            return Err(Status::resource_exhausted(
                "call response exceeds frame limit",
            ));
        }
        Ok(response)
    }

    pub(crate) fn finish_object(
        &self,
        request: u64,
        expected: &ObjectReadRequest,
        result: Result<ObjectReadPage, FederationError>,
    ) -> Result<pb::SyncFrame, Status> {
        let Phase::Ready { limits, .. } = &self.phase else {
            return Err(Status::failed_precondition(
                "federation Session is not authenticated",
            ));
        };
        object_response(
            request,
            expected,
            result,
            self.config.max_frame_bytes.min(limits.max_frame_bytes),
        )
    }

    fn served_capabilities(&self) -> u32 {
        1 | if self.call_store.is_some() && self.call_invoker.is_some() {
            2
        } else {
            0
        } | if self.object_reader.is_some() { 4 } else { 0 }
            | if self.snapshot_publisher.is_some() {
                8
            } else {
                0
            }
    }

    /// Queue this frame on the connection before reading its first peer frame.
    pub fn initial_frame(&mut self) -> Result<pb::SyncFrame, Status> {
        if !matches!(self.phase, Phase::New) || Instant::now() >= self.handshake_deadline {
            self.phase = Phase::Closed;
            return Err(Status::failed_precondition(
                "federation session cannot start Hello",
            ));
        }
        if let Err(status) = self.current_time_ms() {
            self.phase = Phase::Closed;
            return Err(status);
        }
        self.local_hello.served_capabilities = self.served_capabilities();
        self.phase = Phase::AwaitHello;
        Ok(frame(pb::sync_frame::Body::Hello(self.local_hello.clone())))
    }

    /// Valid correlated requests for an uninstalled service return Unavailable
    /// with NotCommitted and leave the authenticated session usable. Protocol
    /// and current-policy failures still close it.
    /// Consume one inbound frame. A protocol or policy failure poisons this
    /// session, so the stream driver must close it rather than retrying later.
    pub fn receive(&mut self, incoming: pb::SyncFrame) -> Result<Option<pb::SyncFrame>, Status> {
        let result = self.receive_inner(incoming);
        if result.is_err() {
            self.phase = Phase::Closed;
        }
        result
    }

    fn receive_inner(&mut self, incoming: pb::SyncFrame) -> Result<Option<pb::SyncFrame>, Status> {
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
                if self
                    .channel
                    .expected_peer
                    .is_some_and(|expected| expected != peer.node)
                    || peer.node == self.local.node_id()
                {
                    return Err(Status::unauthenticated("unexpected federation peer"));
                }
                let local = wire::hello(self.local_hello.clone())?;
                let (initiator, responder) = match self.channel.role {
                    LocalRole::Initiator => (&local, &peer),
                    LocalRole::Responder => (&peer, &local),
                };
                let digest = wire::hello_capabilities_digest(initiator, responder);
                let transcript = FederationSessionTranscript::new(
                    initiator.node,
                    responder.node,
                    initiator.nonce,
                    responder.nonce,
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
                Ok(Some(frame(pb::sync_frame::Body::Authenticate(
                    pb::Authenticate {
                        online_signature: signature,
                    },
                ))))
            }
            (
                Phase::AwaitAuthenticate { peer, transcript },
                Some(pb::sync_frame::Body::Authenticate(authenticate)),
            ) => {
                self.check_handshake_deadline()?;
                let signature = wire::authenticate(authenticate)?;
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
                let mode = match self.policy.check_current_peer(proof, now_ms) {
                    Ok(()) => AdmissionMode::Private,
                    Err(private_error) => {
                        if self.public_service.is_none()
                            && self.object_reader.is_none()
                            && self.invitation_store.is_none()
                        {
                            return Err(private_error);
                        }
                        self.policy.check_public_peer(proof, now_ms)?;
                        if self.invitation_store.is_some() && self.guest_store.is_some() {
                            AdmissionMode::Guest
                        } else {
                            AdmissionMode::PublicOnly
                        }
                    }
                };
                let limits = PeerLimits {
                    served_capabilities: peer.served_capabilities,
                    max_frame_bytes: peer.max_frame_bytes as usize,
                    max_in_flight: peer.max_in_flight as usize,
                    max_batch_records: peer.max_batch_records as usize,
                    max_batch_bytes: peer.max_batch_bytes as usize,
                };
                let subjects = if mode != AdmissionMode::PublicOnly {
                    Some(
                        SessionSubjects::new(proof, &transcript, self.local.node_id())
                            .map_err(subject_status)?,
                    )
                } else {
                    None
                };
                self.phase = Phase::Ready {
                    proof,
                    limits,
                    mode,
                    subjects,
                    transcript: Arc::new(transcript),
                };
                Ok(None)
            }
            (
                Phase::Ready {
                    proof,
                    limits,
                    mode,
                    mut subjects,
                    transcript,
                },
                body,
            ) => {
                let now_ms = self.check_current_peer(proof, mode)?;
                if mode == AdmissionMode::PublicOnly
                    && !matches!(
                        body,
                        Some(pb::sync_frame::Body::InspectPublic(_))
                            | Some(pb::sync_frame::Body::ReadPublic(_))
                            | Some(pb::sync_frame::Body::ReadObject(_))
                    )
                {
                    return Err(Status::permission_denied(
                        "public reader cannot use private federation operations",
                    ));
                }
                if mode == AdmissionMode::Guest
                    && !matches!(
                        body,
                        Some(pb::sync_frame::Body::InspectPublic(_))
                            | Some(pb::sync_frame::Body::ReadPublic(_))
                            | Some(pb::sync_frame::Body::ReadObject(_))
                            | Some(pb::sync_frame::Body::RegisterSubject(_))
                            | Some(pb::sync_frame::Body::RedeemInvitation(_))
                            | Some(pb::sync_frame::Body::Open(_))
                            | Some(pb::sync_frame::Body::Inspect(_))
                            | Some(pb::sync_frame::Body::Read(_))
                            | Some(pb::sync_frame::Body::Close(_))
                            | Some(pb::sync_frame::Body::Acknowledge(_))
                    )
                {
                    return Err(Status::permission_denied(
                        "guest cannot use privileged federation operations",
                    ));
                }
                let issuer_policy = IssuerPolicy(self.policy.as_ref());
                let request_id = match body.as_ref() {
                    Some(pb::sync_frame::Body::RegisterSubject(value)) => value.request,
                    Some(pb::sync_frame::Body::InspectPublic(value)) => value.request,
                    Some(pb::sync_frame::Body::ReadPublic(value)) => value.request,
                    Some(pb::sync_frame::Body::ReadObject(value)) => value.request,
                    Some(pb::sync_frame::Body::RedeemInvitation(value)) => value.request,
                    Some(body) => subject_request_fields(body)?.2,
                    None => return Err(Status::invalid_argument("empty federation frame")),
                };
                if request_id <= self.last_request_id {
                    return Err(Status::invalid_argument(
                        "replayed federation request correlation",
                    ));
                }
                self.last_request_id = request_id;
                self.delivery_subject = Some((
                    FederationSubject::Node(proof.node_id()),
                    SubjectPurpose::Sync,
                    u64::MAX,
                ));
                self.delivery_object = None;
                let response = match body {
                    Some(pb::sync_frame::Body::InspectPublic(value)) => self.dispatch_public(
                        proof,
                        mode,
                        &limits,
                        pb::sync_frame::Body::InspectPublic(value),
                    )?,
                    Some(pb::sync_frame::Body::ReadPublic(value)) => self.dispatch_public(
                        proof,
                        mode,
                        &limits,
                        pb::sync_frame::Body::ReadPublic(value),
                    )?,
                    Some(pb::sync_frame::Body::ReadObject(value))
                        if mode != AdmissionMode::Private && value.context_id == 0 =>
                    {
                        if value.context_id != 0 || !value.holder_request_signature.is_empty() {
                            return Err(Status::permission_denied(
                                "public-only object read requires node-self",
                            ));
                        }
                        self.queue_object(
                            proof,
                            FederationSubject::Node(proof.node_id()),
                            &limits,
                            mode,
                            value,
                        )?
                    }
                    Some(pb::sync_frame::Body::RegisterSubject(value)) => {
                        if value.request == 0 || value.context_id == 0 {
                            return Err(Status::invalid_argument("invalid subject registration"));
                        }
                        let issuer = SubjectIssuer::decode(&value.issuer_descriptor)
                            .map_err(subject_status)?;
                        let purpose = wire::subject_purpose(value.purpose)?;
                        if mode == AdmissionMode::Guest
                            && !matches!(purpose, SubjectPurpose::Sync | SubjectPurpose::ObjectRead)
                        {
                            return Err(Status::permission_denied(
                                "guest subject purpose is unavailable",
                            ));
                        }
                        subjects
                            .as_mut()
                            .ok_or_else(|| {
                                Status::permission_denied("public reader cannot register a subject")
                            })?
                            .install(
                                value.context_id,
                                &issuer,
                                &value.assertion,
                                &value.issuer_signature,
                                &value.holder_presentation,
                                purpose,
                                now_ms,
                                &issuer_policy,
                            )
                            .map_err(subject_status)?;
                        Some(frame(pb::sync_frame::Body::SubjectRegistered(
                            pb::SubjectRegistered {
                                request: value.request,
                                context_id: value.context_id,
                            },
                        )))
                    }
                    Some(body) => {
                        let (context_id, purpose, request_id, holder_signature) =
                            subject_request_fields(&body)?;
                        if mode == AdmissionMode::Guest && context_id == 0 {
                            return Err(Status::permission_denied(
                                "guest private operation requires hosted subject",
                            ));
                        }
                        if context_id == 0 && !holder_signature.is_empty() {
                            return Err(Status::invalid_argument(
                                "node-self request has unexpected holder signature",
                            ));
                        }
                        let digest = wire::subject_request_digest(&body)?;
                        let subject = subjects
                            .as_mut()
                            .ok_or_else(|| {
                                Status::permission_denied(
                                    "public reader cannot use private federation operations",
                                )
                            })?
                            .authorize_request(
                                context_id,
                                purpose,
                                request_id,
                                digest,
                                (!holder_signature.is_empty()).then_some(holder_signature),
                                now_ms,
                                &issuer_policy,
                            )
                            .map_err(subject_status)?;
                        let deadline = subjects
                            .as_ref()
                            .ok_or_else(|| {
                                Status::permission_denied("subject delivery unavailable")
                            })?
                            .delivery_deadline(context_id)
                            .map_err(subject_status)?;
                        self.delivery_subject = Some((subject.clone(), purpose, deadline));
                        match body {
                            pb::sync_frame::Body::RedeemInvitation(value) => self
                                .dispatch_redemption(
                                    proof, mode, subject, now_ms, &limits, value,
                                )?,
                            body => self.dispatch_request(
                                proof,
                                subject,
                                now_ms,
                                &limits,
                                mode,
                                Some(body),
                            )?,
                        }
                    }
                    None => return Err(Status::invalid_argument("empty federation frame")),
                };
                if let Some(response) = response.as_ref()
                    && (response.encoded_len() > limits.max_frame_bytes
                        || response.encoded_len() > self.config.max_frame_bytes)
                {
                    return Err(Status::resource_exhausted(
                        "federation response exceeds negotiated frame limit",
                    ));
                }
                self.phase = Phase::Ready {
                    proof,
                    limits,
                    mode,
                    subjects,
                    transcript,
                };
                Ok(response)
            }
            (Phase::New | Phase::Closed, _) => Err(Status::failed_precondition(
                "federation session has not started or is closed",
            )),
            _ => Err(Status::unauthenticated(
                "federation handshake frames are out of order",
            )),
        }
    }

    fn check_handshake_deadline(&self) -> Result<(), Status> {
        if Instant::now() >= self.handshake_deadline {
            return Err(Status::deadline_exceeded("federation handshake timed out"));
        }
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

    fn check_current_peer(
        &mut self,
        proof: VerifiedFederationPeerProof,
        mode: AdmissionMode,
    ) -> Result<u64, Status> {
        let now_ms = self.current_time_ms()?;
        if now_ms >= proof.expires_ms() {
            return Err(Status::unauthenticated("federation online key expired"));
        }
        match mode {
            AdmissionMode::Private => self.policy.check_current_peer(proof, now_ms)?,
            AdmissionMode::PublicOnly | AdmissionMode::Guest => {
                self.policy.check_public_peer(proof, now_ms)?
            }
        }
        Ok(now_ms)
    }

    fn dispatch_redemption(
        &mut self,
        proof: VerifiedFederationPeerProof,
        mode: AdmissionMode,
        subject: FederationSubject,
        now_ms: u64,
        limits: &PeerLimits,
        value: pb::RedeemInvitation,
    ) -> Result<Option<pb::SyncFrame>, Status> {
        let presenter = proof.node_id();
        let FederationSubject::Hosted(subject) = subject else {
            return Err(Status::permission_denied(
                "invitation requires hosted subject",
            ));
        };
        if value.context_id == 0 || value.expected_revision == 0 {
            return Err(Status::invalid_argument("invalid invitation redemption"));
        }
        let invitation = InvitationId::from_bytes(
            value
                .invitation_id
                .try_into()
                .map_err(|_error| Status::invalid_argument("invalid invitation ID length"))?,
        );
        let request_id =
            RequestId::from_bytes(value.request_id.try_into().map_err(|_error| {
                Status::invalid_argument("invalid invitation request ID length")
            })?);
        let secret = if value.secret.is_empty() {
            None
        } else {
            Some(InvitationSecret::from_bytes(
                value.secret.try_into().map_err(|_error| {
                    Status::invalid_argument("invalid invitation secret length")
                })?,
            ))
        };
        let request = value.request;
        let redemption = RedeemInvitationRequest {
            invitation,
            request_id,
            authenticated_presenter: presenter,
            subject,
            expected_invitation_revision: value.expected_revision,
            secret,
            now_ms,
        };
        let Some(store) = self.invitation_store.clone() else {
            return Ok(Some(wire::service_unavailable(request)));
        };
        let store = store
            .bind_invitation_decision(self.decision(proof, mode)?)
            .map_err(decision_status)?;
        self.queue_guest(request, limits, GuestOperation::Redeem(store, redemption))
    }

    fn queue_guest(
        &mut self,
        request: u64,
        limits: &PeerLimits,
        operation: GuestOperation,
    ) -> Result<Option<pb::SyncFrame>, Status> {
        if self.pending_guest.is_some() {
            return Err(Status::failed_precondition(
                "guest operation is already pending",
            ));
        }
        self.pending_guest = Some(PendingGuest {
            request,
            max_frame_bytes: limits.max_frame_bytes.min(self.config.max_frame_bytes),
            operation,
        });
        Ok(None)
    }

    fn dispatch_public(
        &self,
        proof: VerifiedFederationPeerProof,
        mode: AdmissionMode,
        limits: &PeerLimits,
        body: pb::sync_frame::Body,
    ) -> Result<Option<pb::SyncFrame>, Status> {
        use pb::sync_frame::Body;
        let peer = proof.node_id();
        let decision = self.decision(proof, mode)?;
        let service = self
            .public_service
            .as_ref()
            .map(|service| service.with_decision(decision))
            .transpose()
            .map_err(decision_status)?;
        let response = match body {
            Body::InspectPublic(value) => {
                let request = value.request;
                let stream = wire::stream(
                    value
                        .stream
                        .ok_or_else(|| Status::invalid_argument("missing public stream"))?,
                )?;
                let Some(service) = &service else {
                    return Ok(Some(wire::service_unavailable(request)));
                };
                match service.inspect(peer, stream) {
                    Ok(view) => frame(Body::PublicInspected(pb::PublicInspected {
                        request,
                        stream: Some(wire::stream_to_pb(view.stream)),
                        export_name: view.export.as_str().to_owned(),
                        policy_revision: view.policy_revision,
                        head: view.head.map(wire::position_to_pb),
                        minimum_available: view.minimum_available,
                        max_read_records: view
                            .max_read_records
                            .try_into()
                            .map_err(|_error| Status::internal("invalid public read limit"))?,
                        max_read_bytes: view
                            .max_read_bytes
                            .try_into()
                            .map_err(|_error| Status::internal("invalid public byte limit"))?,
                    })),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }
            }
            Body::ReadPublic(value) => {
                let request = value.request;
                if value.max_records == 0
                    || value.max_bytes == 0
                    || value.max_records as usize
                        > limits.max_batch_records.min(self.config.max_batch_records)
                    || value.max_bytes
                        > limits.max_batch_bytes.min(self.config.max_batch_bytes) as u64
                {
                    return Err(Status::resource_exhausted(
                        "public read exceeds negotiated batch limit",
                    ));
                }
                let stream = wire::stream(
                    value
                        .stream
                        .ok_or_else(|| Status::invalid_argument("missing public stream"))?,
                )?;
                let read = PublicReadRequest {
                    authenticated_reader: peer,
                    stream,
                    expected_policy_revision: value.expected_policy_revision,
                    after: value.after.map(wire::position).transpose()?,
                    max_records: value.max_records as usize,
                    max_bytes: usize::try_from(value.max_bytes).map_err(|_error| {
                        Status::resource_exhausted("public read byte limit overflows")
                    })?,
                };
                let Some(service) = &service else {
                    return Ok(Some(wire::service_unavailable(request)));
                };
                match service.read(read) {
                    Ok(page) => frame(Body::PublicBatch(pb::PublicBatch {
                        request,
                        stream: Some(wire::stream_to_pb(stream)),
                        policy_revision: page.policy_revision,
                        records: page.records.iter().map(wire::record_to_pb).collect(),
                        head: page.head.map(wire::position_to_pb),
                        minimum_available: page.minimum_available,
                    })),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }
            }
            _ => {
                return Err(Status::invalid_argument(
                    "invalid public federation request",
                ));
            }
        };
        Ok(Some(response))
    }

    fn queue_object(
        &mut self,
        proof: VerifiedFederationPeerProof,
        subject: FederationSubject,
        limits: &PeerLimits,
        mode: AdmissionMode,
        value: pb::ReadObject,
    ) -> Result<Option<pb::SyncFrame>, Status> {
        if value.max_bytes == 0
            || value.max_bytes as usize > xolotl_federation::MAX_OBJECT_CHUNK_BYTES
            || value.max_bytes as usize > limits.max_batch_bytes.min(self.config.max_batch_bytes)
            || value.max_bytes as usize + 4096
                > limits.max_frame_bytes.min(self.config.max_frame_bytes)
        {
            return Err(Status::resource_exhausted(
                "object chunk exceeds negotiated limit",
            ));
        }
        let request = value.request;
        let read = wire::read_object(proof.node_id(), subject, value)?;
        let Some(reader) = self.object_reader.as_ref() else {
            return Ok(Some(wire::service_unavailable(request)));
        };
        let reader = reader
            .bind_reader_decision(self.decision(proof, mode)?)
            .map_err(decision_status)?;
        if self.pending_object.is_some() {
            return Err(Status::failed_precondition(
                "object read is already pending",
            ));
        }
        self.pending_object = Some(PendingObject {
            request,
            read,
            authority: ObjectReadAuthority::new(
                proof,
                match mode {
                    AdmissionMode::Private => ObjectReadAdmission::Private,
                    AdmissionMode::PublicOnly | AdmissionMode::Guest => {
                        ObjectReadAdmission::Unconfigured
                    }
                },
            ),
            reader,
            max_frame_bytes: limits.max_frame_bytes.min(self.config.max_frame_bytes),
            context: Arc::new(OnceLock::new()),
        });
        if let Some(pending) = &self.pending_object {
            self.delivery_object = Some((
                pending.read.clone(),
                pending.authority,
                Arc::clone(&pending.reader),
                Arc::clone(&pending.context),
            ));
        }
        Ok(None)
    }

    fn dispatch_request(
        &mut self,
        proof: VerifiedFederationPeerProof,
        subject: FederationSubject,
        now_ms: u64,
        limits: &PeerLimits,
        mode: AdmissionMode,
        body: Option<pb::sync_frame::Body>,
    ) -> Result<Option<pb::SyncFrame>, Status> {
        use pb::sync_frame::Body;
        let peer = proof.node_id();
        let decision = self.decision(proof, mode)?;
        let service = self
            .service
            .with_decision(decision.clone())
            .map_err(decision_status)?;
        match body {
            Some(Body::Open(value)) if value.request != 0 => {
                let request = value.request;
                let record_bytes = service.limits().max_record_bytes;
                if record_bytes > self.config.max_batch_bytes.min(limits.max_batch_bytes)
                    || record_bytes.saturating_add(4096)
                        > self.config.max_frame_bytes.min(limits.max_frame_bytes)
                {
                    return Ok(Some(frame(Body::Failure(wire::failure(
                        request,
                        &FederationError::Capacity,
                    )))));
                }
                let opened = wire::open(peer, value)?;
                if mode == AdmissionMode::Guest {
                    let store = self
                        .guest_store
                        .clone()
                        .ok_or_else(|| Status::permission_denied("guest delivery unavailable"))?
                        .bind_guest_decision(decision)
                        .map_err(decision_status)?;
                    return self.queue_guest(
                        request,
                        limits,
                        GuestOperation::Open(store, guest_subject(subject)?, now_ms, opened),
                    );
                }
                let result = service.open_as(subject, now_ms, opened);
                Ok(Some(match result {
                    Ok(result) => frame(Body::Opened(wire::opened_to_pb(request, &result))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            Some(Body::Inspect(value)) if value.request != 0 => {
                let request = value.request;
                let inspect = wire::inspect(peer, value)?;
                if mode == AdmissionMode::Guest {
                    let store = self
                        .guest_store
                        .clone()
                        .ok_or_else(|| Status::permission_denied("guest delivery unavailable"))?
                        .bind_guest_decision(decision)
                        .map_err(decision_status)?;
                    return self.queue_guest(
                        request,
                        limits,
                        GuestOperation::Inspect(store, guest_subject(subject)?, now_ms, inspect),
                    );
                }
                let result = service.inspect_subscription_as(subject, now_ms, inspect);
                Ok(Some(match result {
                    Ok(result) => frame(Body::Inspected(wire::inspected_to_pb(request, &result))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            Some(Body::Close(value)) if value.request != 0 => {
                let request = value.request;
                let close = wire::close(peer, value)?;
                if mode == AdmissionMode::Guest {
                    let store = self
                        .guest_store
                        .clone()
                        .ok_or_else(|| Status::permission_denied("guest delivery unavailable"))?
                        .bind_guest_decision(decision)
                        .map_err(decision_status)?;
                    return self.queue_guest(
                        request,
                        limits,
                        GuestOperation::Close(store, guest_subject(subject)?, now_ms, close),
                    );
                }
                let result = service.close_subscription_as(subject, now_ms, close);
                Ok(Some(match result {
                    Ok(result) => frame(Body::Closed(wire::closed_to_pb(request, result))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            Some(Body::Read(value)) if value.request != 0 => {
                let request = value.request;
                if value.max_records as usize > limits.max_batch_records
                    || value.max_bytes > limits.max_batch_bytes as u64
                    || value.max_records as usize > self.config.max_batch_records
                    || value.max_bytes > self.config.max_batch_bytes as u64
                {
                    return Err(Status::resource_exhausted(
                        "federation read exceeds negotiated batch limit",
                    ));
                }
                let read = wire::read(peer, value)?;
                let subscription = read.subscription;
                if mode == AdmissionMode::Guest {
                    let store = self
                        .guest_store
                        .clone()
                        .ok_or_else(|| Status::permission_denied("guest delivery unavailable"))?
                        .bind_guest_decision(decision)
                        .map_err(decision_status)?;
                    return self.queue_guest(
                        request,
                        limits,
                        GuestOperation::Read(store, guest_subject(subject)?, now_ms, read),
                    );
                }
                let result = service.read_as(subject, now_ms, read);
                Ok(Some(match result {
                    Ok(result) => frame(Body::Batch(wire::batch_to_pb(
                        request,
                        subscription,
                        &result,
                    ))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            Some(Body::Acknowledge(value)) if value.request != 0 => {
                let request = value.request;
                let ack = wire::acknowledge(peer, value)?;
                if mode == AdmissionMode::Guest {
                    let store = self
                        .guest_store
                        .clone()
                        .ok_or_else(|| Status::permission_denied("guest delivery unavailable"))?
                        .bind_guest_decision(decision)
                        .map_err(decision_status)?;
                    return self.queue_guest(
                        request,
                        limits,
                        GuestOperation::Acknowledge(store, guest_subject(subject)?, now_ms, ack),
                    );
                }
                let result = service.acknowledge_as(subject, now_ms, ack);
                Ok(Some(match result {
                    Ok(position) => frame(Body::Acknowledged(pb::Acknowledged {
                        request,
                        position: Some(wire::position_to_pb(position)),
                    })),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            Some(Body::PrepareCall(value)) if value.request != 0 => {
                let request = value.request;
                let call = wire::prepare_call(peer, subject, value)?;
                let Some(invoker) = self.call_invoker.as_ref() else {
                    return Ok(Some(call_unavailable(request)));
                };
                let Some(store) = self
                    .call_store
                    .as_ref()
                    .map(|store| store.bind_call_decision(decision.clone()))
                    .transpose()
                    .map_err(decision_status)?
                else {
                    return Ok(Some(call_unavailable(request)));
                };
                // A known exact RequestId can be reconciled after its method
                // was removed or its deadline elapsed. The stored reservation
                // is inert; only a new Prepare needs current Kernel admission.
                let result = match store.prepared_call_for_request(&call) {
                    Ok(Some(prepared)) => Ok(prepared),
                    Ok(None) => invoker
                        .validate_prepare(&call)
                        .and_then(|()| store.prepare_call(call, now_ms)),
                    Err(error) => Err(error),
                };
                Ok(Some(match result {
                    Ok(result) => frame(Body::CallPrepared(wire::call_prepared_to_pb(
                        request, &result,
                    ))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            Some(Body::InvokeCall(value)) if value.request != 0 => {
                let request = value.request;
                let call = wire::invoke_call(peer, subject, value)?;
                if call.call.target != self.local.node_id() {
                    return Err(Status::permission_denied(
                        "call target is not the local node",
                    ));
                }
                let Some(invoker) = self.call_invoker.as_ref() else {
                    return Ok(Some(call_unavailable(request)));
                };
                if self.pending_invoke.is_some() {
                    return Err(Status::failed_precondition(
                        "federation Invoke is already pending",
                    ));
                }
                self.pending_invoke = Some(PendingInvoke {
                    request,
                    call,
                    now_ms,
                    invoker: invoker
                        .bind_invoker_decision(decision)
                        .map_err(decision_status)?,
                });
                Ok(None)
            }
            Some(Body::InspectCall(value)) if value.request != 0 => {
                let request = value.request;
                let call = wire::inspect_call(peer, subject, value)?;
                if call.call.target != self.local.node_id() {
                    return Err(Status::permission_denied(
                        "call target is not the local node",
                    ));
                }
                let Some(store) = self
                    .call_store
                    .as_ref()
                    .map(|store| store.bind_call_decision(decision.clone()))
                    .transpose()
                    .map_err(decision_status)?
                else {
                    return Ok(Some(call_unavailable(request)));
                };
                let result = store.inspect_call(call, now_ms);
                Ok(Some(match result {
                    Ok(result) => frame(Body::CallInspected(wire::call_inspected_to_pb(
                        request, &result,
                    ))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            Some(Body::CancelCall(value)) if value.request != 0 => {
                let request = value.request;
                let call = wire::cancel_call(peer, subject, value)?;
                if call.call.target != self.local.node_id() {
                    return Err(Status::permission_denied(
                        "call target is not the local node",
                    ));
                }
                if let Some(invoker) = self.call_invoker.as_ref() {
                    if self.pending_cancel.is_some() {
                        return Err(Status::failed_precondition(
                            "federation Cancel is already pending",
                        ));
                    }
                    self.pending_cancel = Some(PendingCancel {
                        request,
                        call,
                        now_ms,
                        invoker: invoker
                            .bind_invoker_decision(decision)
                            .map_err(decision_status)?,
                    });
                    return Ok(None);
                }
                let Some(store) = self
                    .call_store
                    .as_ref()
                    .map(|store| store.bind_call_decision(decision.clone()))
                    .transpose()
                    .map_err(decision_status)?
                else {
                    return Ok(Some(call_unavailable(request)));
                };
                let result = store.cancel_call(call, now_ms);
                Ok(Some(match result {
                    Ok(result) => frame(Body::CallCancelled(wire::call_cancelled_to_pb(
                        request, result,
                    ))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            Some(Body::ReadObject(value)) if value.request != 0 => {
                self.queue_object(proof, subject, limits, mode, value)
            }
            Some(Body::InspectSnapshot(value)) if value.request != 0 => {
                if mode != AdmissionMode::Private || subject != FederationSubject::Node(peer) {
                    return Err(Status::permission_denied(
                        "snapshot requires private Node-self authority",
                    ));
                }
                let request = value.request;
                let subscription = wire::inspect_snapshot(peer, value)?;
                let Some((store, _)) = self.snapshot_publisher.as_ref() else {
                    return Ok(Some(wire::service_unavailable(request)));
                };
                let store = store
                    .bind_snapshot_publisher_decision(decision)
                    .map_err(decision_status)?;
                let result = store
                    .snapshot_offer(peer, subscription)
                    .and_then(|offer| offer.ok_or(FederationError::NotFound));
                Ok(Some(match result {
                    Ok(offer) => frame(Body::SnapshotOffered(wire::snapshot_offer_to_pb(
                        request, &offer,
                    ))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            Some(Body::ReadSnapshot(value)) if value.request != 0 => {
                if mode != AdmissionMode::Private || subject != FederationSubject::Node(peer) {
                    return Err(Status::permission_denied(
                        "snapshot requires private Node-self authority",
                    ));
                }
                let request = value.request;
                let max_bytes = value.max_bytes as usize;
                if max_bytes == 0
                    || max_bytes > xolotl_federation::MAX_SNAPSHOT_CHUNK_BYTES
                    || max_bytes > limits.max_batch_bytes.min(self.config.max_batch_bytes)
                    || max_bytes.saturating_add(4096)
                        > limits.max_frame_bytes.min(self.config.max_frame_bytes)
                {
                    return Err(Status::resource_exhausted(
                        "snapshot chunk exceeds negotiated limit",
                    ));
                }
                let read = wire::read_snapshot(peer, value)?;
                let Some((store, source)) = self.snapshot_publisher.as_ref() else {
                    return Ok(Some(wire::service_unavailable(request)));
                };
                let store = store
                    .bind_snapshot_publisher_decision(decision)
                    .map_err(decision_status)?;
                let result = store.read_snapshot_chunk(read, source.as_ref());
                Ok(Some(match result {
                    Ok(chunk) => frame(Body::SnapshotChunk(wire::snapshot_chunk_to_pb(
                        request, chunk,
                    ))),
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            Some(Body::ReceiveSnapshot(value)) if value.request != 0 => {
                if mode != AdmissionMode::Private || subject != FederationSubject::Node(peer) {
                    return Err(Status::permission_denied(
                        "snapshot receipt requires private Node-self authority",
                    ));
                }
                let request = value.request;
                let received = wire::receive_snapshot(peer, value)?;
                let Some((store, _)) = self.snapshot_publisher.as_ref() else {
                    return Ok(Some(wire::service_unavailable(request)));
                };
                let store = store
                    .bind_snapshot_publisher_decision(decision)
                    .map_err(decision_status)?;
                let result = store.receive_snapshot(received);
                Ok(Some(match result {
                    Ok(receipt) if receipt == received.into() => frame(Body::SnapshotReceived(
                        wire::snapshot_received_to_pb(request, receipt),
                    )),
                    Ok(_) => {
                        return Err(Status::internal(
                            "snapshot publisher returned a mismatched receipt",
                        ));
                    }
                    Err(error) => frame(Body::Failure(wire::failure(request, &error))),
                }))
            }
            _ => Err(Status::invalid_argument(
                "unsupported or invalid federation request frame",
            )),
        }
    }
}

fn frame(body: pb::sync_frame::Body) -> pb::SyncFrame {
    pb::SyncFrame { body: Some(body) }
}

fn decision_status(error: FederationError) -> Status {
    wire::failure_status(wire::failure(1, &error))
}

fn object_response(
    request: u64,
    expected: &ObjectReadRequest,
    result: Result<ObjectReadPage, FederationError>,
    max_frame_bytes: usize,
) -> Result<pb::SyncFrame, Status> {
    let response = match result {
        Ok(page) => {
            if page.transfer != expected.transfer
                || page.grant != expected.grant
                || page.revision != expected.expected_revision
                || page.offset != expected.offset
                || page.bytes.len() > expected.max_bytes
                || (page.bytes.is_empty() && !page.end_of_range && !page.end_of_object)
            {
                return Err(Status::internal(
                    "object backend returned a mismatched page",
                ));
            }
            frame(pb::sync_frame::Body::ObjectChunk(wire::object_chunk_to_pb(
                request, page,
            )))
        }
        Err(error) => frame(pb::sync_frame::Body::Failure(wire::failure(
            request, &error,
        ))),
    };
    if response.encoded_len() > max_frame_bytes {
        return Err(Status::resource_exhausted(
            "object response exceeds frame limit",
        ));
    }
    Ok(response)
}

fn guest_subject(subject: FederationSubject) -> Result<HostedSubject, Status> {
    match subject {
        FederationSubject::Hosted(subject) => Ok(subject),
        FederationSubject::Node(_) => Err(Status::permission_denied(
            "guest private operation requires hosted subject",
        )),
    }
}

fn call_unavailable(request: u64) -> pb::SyncFrame {
    frame(pb::sync_frame::Body::Failure(pb::SyncFailure {
        request,
        code: pb::FailureCode::Unavailable as i32,
        message: "federated call operation is unavailable".into(),
        commit_verdict: pb::CommitVerdict::NotCommitted as i32,
    }))
}

fn subject_request_fields(
    body: &pb::sync_frame::Body,
) -> Result<(u32, SubjectPurpose, u64, &[u8]), Status> {
    use pb::sync_frame::Body;
    let (context, request, signature) = match body {
        Body::Open(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::Inspect(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::Close(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::Read(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::Acknowledge(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::PrepareCall(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::InvokeCall(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::InspectCall(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::CancelCall(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::ReadObject(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::RedeemInvitation(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::InspectSnapshot(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::ReadSnapshot(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        Body::ReceiveSnapshot(value) => (
            value.context_id,
            value.request,
            value.holder_request_signature.as_slice(),
        ),
        _ => {
            return Err(Status::invalid_argument(
                "unsupported federation business frame",
            ));
        }
    };
    if request == 0 {
        return Err(Status::invalid_argument(
            "missing federation request correlation",
        ));
    }
    let purpose = match body {
        Body::ReadObject(_) => SubjectPurpose::ObjectRead,
        Body::PrepareCall(_) | Body::InvokeCall(_) | Body::InspectCall(_) | Body::CancelCall(_) => {
            SubjectPurpose::Invoke
        }
        _ => SubjectPurpose::Sync,
    };
    Ok((context, purpose, request, signature))
}

fn subject_status(error: SubjectProofError) -> Status {
    match error {
        SubjectProofError::IssuerUnauthorized => Status::permission_denied(error.to_string()),
        SubjectProofError::ContextConflict | SubjectProofError::Capacity => {
            Status::invalid_argument(error.to_string())
        }
        SubjectProofError::CryptoFailure => Status::internal(error.to_string()),
        _ => Status::unauthenticated(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    mod delivery;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use anyhow::{Result, ensure};
    use tonic::Code;
    use xolotl_federation::{
        ExportAccess, ExportName, FederationLimits, FederationRootKey, MemoryFederationStore,
        StreamId, StreamRef, StreamSpec, SubjectAssertion, SubjectHolderKey, SubjectIssuerKey,
    };

    use super::*;

    async fn poll_once<Pending: Future + ?Sized>(
        mut future: Pin<&mut Pending>,
    ) -> std::task::Poll<Pending::Output> {
        std::future::poll_fn(|context| std::task::Poll::Ready(future.as_mut().poll(context))).await
    }

    struct Policy {
        now_ms: Arc<AtomicU64>,
        enabled: AtomicBool,
        minimum_generation: AtomicU64,
        revoked_authorization: Mutex<Option<[u8; 48]>>,
        subject_issuer: Mutex<Option<SubjectIssuerId>>,
    }

    impl Policy {
        fn new() -> Self {
            Self {
                now_ms: Arc::new(AtomicU64::new(150)),
                enabled: AtomicBool::new(true),
                minimum_generation: AtomicU64::new(1),
                revoked_authorization: Mutex::new(None),
                subject_issuer: Mutex::new(None),
            }
        }
    }

    impl FederationPeerPolicy for Policy {
        fn decision_clock(
            &self,
        ) -> Result<Arc<dyn xolotl_federation::FederationObjectClock>, Status> {
            let time = Arc::clone(&self.now_ms);
            Ok(Arc::new(move || Ok(time.load(Ordering::SeqCst))))
        }

        fn current_time_ms(&self) -> Result<u64, Status> {
            Ok(self.now_ms.load(Ordering::SeqCst))
        }

        fn check_current_peer(
            &self,
            proof: VerifiedFederationPeerProof,
            _now_ms: u64,
        ) -> Result<(), Status> {
            if !self.enabled.load(Ordering::SeqCst)
                || proof.online_generation() < self.minimum_generation.load(Ordering::SeqCst)
                || *self
                    .revoked_authorization
                    .lock()
                    .map_err(|_error| Status::internal("peer policy lock poisoned"))?
                    == Some(proof.authorization_digest())
            {
                return Err(Status::permission_denied("federation peer revoked"));
            }
            Ok(())
        }

        fn accepts_subject_issuer(
            &self,
            issuer: SubjectIssuerId,
            namespace: &str,
            purpose: SubjectPurpose,
            _presenter: FederationNodeId,
            _audience: FederationNodeId,
        ) -> bool {
            namespace == "accounts.example"
                && purpose == SubjectPurpose::Sync
                && self.subject_issuer.lock().ok().and_then(|value| *value) == Some(issuer)
        }
    }

    fn identity(expires_ms: u64) -> Result<Arc<FederationLocalCredentials>> {
        let root_key = FederationRootKey::generate()?;
        let root = root_key.root()?;
        let online_key = FederationOnlineKey::generate()?;
        let authorization =
            FederationOnlineKeyAuthorization::new(online_key.public_key(), 1, 100, expires_ms)?;
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

    fn setup() -> Result<(
        FederationGrpcPublisherSession,
        FederationGrpcPublisherSession,
        Arc<Policy>,
        FederationNodeId,
        FederationNodeId,
    )> {
        let a = identity(200)?;
        let b = identity(300)?;
        let a_node = a.node_id();
        let b_node = b.node_id();
        let a_policy = Arc::new(Policy::new());
        let b_policy = Arc::new(Policy::new());
        let a_store = Arc::new(MemoryFederationStore::new(a_node));
        let b_store = Arc::new(MemoryFederationStore::new(b_node));
        let limits = FederationLimits {
            max_record_bytes: FederationGrpcConfig::default().max_batch_bytes,
            ..FederationLimits::default()
        };
        let a_service = FederationService::new(a_store, limits)?;
        let b_service = FederationService::new(b_store, limits)?;
        b_service.set_peer_authority(a_node, None, true)?;
        b_service.set_peer_admission(
            a_node,
            None,
            xolotl_federation::PeerAdmission {
                minimum_online_generation: 1,
                allowed_authorization_digests: vec![a.authorization_digest()],
            },
        )?;
        b_service.set_export_authority(
            a_node,
            ExportName::new("friends")?,
            None,
            ExportAccess {
                serve: true,
                receive: false,
            },
        )?;
        b_service.declare_stream(StreamSpec {
            stream: StreamRef {
                publisher: b_node,
                id: StreamId::from_bytes([3; 16]),
            },
            export: ExportName::new("friends")?,
        })?;
        let a_session = FederationGrpcPublisherSession::new(
            FederationTlsChannel {
                role: LocalRole::Initiator,
                expected_peer: Some(b_node),
                exporter: [9; 48],
            },
            a,
            a_policy,
            a_service,
            FederationGrpcConfig::default(),
        )?;
        let b_session = FederationGrpcPublisherSession::new(
            FederationTlsChannel {
                role: LocalRole::Responder,
                expected_peer: None,
                exporter: [9; 48],
            },
            b,
            b_policy.clone(),
            b_service,
            FederationGrpcConfig::default(),
        )?;
        Ok((a_session, b_session, b_policy, a_node, b_node))
    }

    fn authenticate(
        initiator: &mut FederationGrpcPublisherSession,
        responder: &mut FederationGrpcPublisherSession,
    ) -> Result<()> {
        let a_hello = initiator.initial_frame()?;
        let b_hello = responder.initial_frame()?;
        let a_auth = initiator
            .receive(b_hello)?
            .ok_or_else(|| anyhow::anyhow!("initiator did not sign"))?;
        let b_auth = responder
            .receive(a_hello)?
            .ok_or_else(|| anyhow::anyhow!("responder did not sign"))?;
        ensure!(initiator.receive(b_auth)?.is_none());
        ensure!(responder.receive(a_auth)?.is_none());
        Ok(())
    }

    fn open(a_node: FederationNodeId, b_node: FederationNodeId) -> pb::SyncFrame {
        frame(pb::sync_frame::Body::Open(pb::Open {
            request: 1,
            request_id: vec![7; 16],
            subscription: Some(pb::SubscriptionRef {
                subscriber: a_node.as_bytes().to_vec(),
                id: vec![4; 16],
            }),
            stream: Some(pb::StreamRef {
                publisher: b_node.as_bytes().to_vec(),
                id: vec![3; 16],
            }),
            expected_control_revision: None,
            history_mode: pb::HistoryMode::All as i32,
            history_after: None,
            context_id: 0,
            holder_request_signature: Vec::new(),
        }))
    }

    fn rejected(
        session: &mut FederationGrpcPublisherSession,
        frame: pb::SyncFrame,
        expected: Code,
    ) -> Result<()> {
        match session.receive(frame) {
            Err(status) if status.code() == expected => Ok(()),
            Err(status) => anyhow::bail!("expected {expected:?}, got {status}"),
            Ok(_) => anyhow::bail!("expected {expected:?} rejection"),
        }
    }

    fn transcript(
        initiator: &FederationGrpcPublisherSession,
        responder: &FederationGrpcPublisherSession,
    ) -> Result<FederationSessionTranscript> {
        let first = wire::hello(initiator.local_hello.clone())?;
        let second = wire::hello(responder.local_hello.clone())?;
        Ok(FederationSessionTranscript::new(
            first.node,
            second.node,
            first.nonce,
            second.nonce,
            responder.channel.exporter,
            wire::hello_capabilities_digest(&first, &second),
        )?)
    }

    fn subject_registration(
        assertion: &SubjectAssertion,
        issuer_key: &SubjectIssuerKey,
        holder: &SubjectHolderKey,
        transcript: &FederationSessionTranscript,
    ) -> Result<pb::SyncFrame> {
        Ok(frame(pb::sync_frame::Body::RegisterSubject(
            pb::RegisterSubject {
                request: 40,
                context_id: 7,
                purpose: pb::SubjectPurpose::Sync as i32,
                issuer_descriptor: issuer_key.issuer()?.encode(),
                assertion: assertion.encode(),
                issuer_signature: issuer_key.sign_assertion(assertion)?,
                holder_presentation: holder.sign_presentation(assertion, transcript)?,
            },
        )))
    }

    #[test]
    fn open_rejects_peer_unable_to_read_one_published_record() -> Result<()> {
        let (mut initiator, mut responder, _policy, a_node, b_node) = setup()?;
        initiator.config.max_batch_bytes = 128 * 1024;
        initiator.local_hello.max_batch_bytes = 128 * 1024;
        authenticate(&mut initiator, &mut responder)?;
        let response = responder
            .receive(open(a_node, b_node))?
            .ok_or_else(|| anyhow::anyhow!("missing Open response"))?;
        ensure!(matches!(
            response.body,
            Some(pb::sync_frame::Body::Failure(pb::SyncFailure { code, .. }))
                if code == pb::FailureCode::Capacity as i32
        ));
        Ok(())
    }

    #[test]
    fn hosted_subject_is_verified_per_frame_and_denied_by_node_only_store() -> Result<()> {
        let issuer_key = SubjectIssuerKey::generate()?;
        let issuer = issuer_key.issuer()?;
        let holder = SubjectHolderKey::generate()?;

        let (mut a, mut b, _policy, a_node, b_node) = setup()?;
        authenticate(&mut a, &mut b)?;
        let channel = transcript(&a, &b)?;
        let assertion = SubjectAssertion::new(
            issuer.id(),
            "accounts.example",
            "alice",
            b_node,
            a_node,
            SubjectPurpose::Sync,
            100,
            190,
            holder.public_key(),
        )?;
        rejected(
            &mut b,
            subject_registration(&assertion, &issuer_key, &holder, &channel)?,
            Code::PermissionDenied,
        )?;

        let (mut a, mut b, policy, a_node, b_node) = setup()?;
        *policy
            .subject_issuer
            .lock()
            .map_err(|_error| anyhow::anyhow!("issuer policy lock poisoned"))? = Some(issuer.id());
        authenticate(&mut a, &mut b)?;
        let channel = transcript(&a, &b)?;
        let assertion = SubjectAssertion::new(
            issuer.id(),
            "accounts.example",
            "alice",
            b_node,
            a_node,
            SubjectPurpose::Sync,
            100,
            190,
            holder.public_key(),
        )?;
        let registered = b.receive(subject_registration(
            &assertion,
            &issuer_key,
            &holder,
            &channel,
        )?)?;
        ensure!(matches!(
            registered.and_then(|frame| frame.body),
            Some(pb::sync_frame::Body::SubjectRegistered(
                pb::SubjectRegistered { context_id: 7, .. }
            ))
        ));
        let mut hosted = open(a_node, b_node);
        if let Some(pb::sync_frame::Body::Open(value)) = hosted.body.as_mut() {
            value.request = 41;
            value.context_id = 7;
        }
        rejected(&mut b, hosted, Code::Unauthenticated)?;

        let (mut a, mut b, policy, a_node, b_node) = setup()?;
        *policy
            .subject_issuer
            .lock()
            .map_err(|_error| anyhow::anyhow!("issuer policy lock poisoned"))? = Some(issuer.id());
        authenticate(&mut a, &mut b)?;
        let channel = transcript(&a, &b)?;
        let assertion = SubjectAssertion::new(
            issuer.id(),
            "accounts.example",
            "alice",
            b_node,
            a_node,
            SubjectPurpose::Sync,
            100,
            190,
            holder.public_key(),
        )?;
        b.receive(subject_registration(
            &assertion,
            &issuer_key,
            &holder,
            &channel,
        )?)?;
        let mut hosted = open(a_node, b_node);
        if let Some(pb::sync_frame::Body::Open(value)) = hosted.body.as_mut() {
            value.request = 41;
            value.context_id = 7;
        }
        let digest = wire::subject_request_digest(
            hosted
                .body
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("missing Open body"))?,
        )?;
        if let Some(pb::sync_frame::Body::Open(value)) = hosted.body.as_mut() {
            value.holder_request_signature = holder.sign_request(
                &assertion,
                &channel,
                value.context_id,
                value.request,
                digest,
            )?;
        }
        let denied = b.receive(hosted)?;
        ensure!(
            matches!(denied.and_then(|frame| frame.body), Some(pb::sync_frame::Body::Failure(pb::SyncFailure { code, .. })) if code == pb::FailureCode::Forbidden as i32)
        );
        Ok(())
    }

    #[test]
    fn invitation_frame_requires_the_registered_holders_request_signature() -> Result<()> {
        let issuer_key = SubjectIssuerKey::generate()?;
        let issuer = issuer_key.issuer()?;
        let holder = SubjectHolderKey::generate()?;
        let (mut a, mut b, policy, a_node, b_node) = setup()?;
        *policy
            .subject_issuer
            .lock()
            .map_err(|_error| anyhow::anyhow!("issuer policy lock poisoned"))? = Some(issuer.id());
        authenticate(&mut a, &mut b)?;
        let channel = transcript(&a, &b)?;
        let assertion = SubjectAssertion::new(
            issuer.id(),
            "accounts.example",
            "alice",
            b_node,
            a_node,
            SubjectPurpose::Sync,
            100,
            190,
            holder.public_key(),
        )?;
        b.receive(subject_registration(
            &assertion,
            &issuer_key,
            &holder,
            &channel,
        )?)?;
        let mut body = pb::sync_frame::Body::RedeemInvitation(pb::RedeemInvitation {
            request: 41,
            invitation_id: vec![1; 16],
            request_id: vec![2; 16],
            expected_revision: 1,
            secret: Vec::new(),
            context_id: 7,
            holder_request_signature: Vec::new(),
        });
        let digest = wire::subject_request_digest(&body)?;
        if let pb::sync_frame::Body::RedeemInvitation(value) = &mut body {
            value.holder_request_signature = holder.sign_request(
                &assertion,
                &channel,
                value.context_id,
                value.request,
                digest,
            )?;
            value.holder_request_signature[0] ^= 0x80;
        }
        rejected(&mut b, frame(body), Code::Unauthenticated)?;
        Ok(())
    }

    #[test]
    fn admission_orders_proofs_then_checks_current_policy_on_each_business_frame() -> Result<()> {
        let (_a, mut b, _policy, a_node, b_node) = setup()?;
        rejected(&mut b, open(a_node, b_node), Code::FailedPrecondition)?;
        ensure!(b.initial_frame().is_err());

        let (mut a, mut b, policy, a_node, b_node) = setup()?;
        authenticate(&mut a, &mut b)?;
        let response = b.receive(open(a_node, b_node))?;
        ensure!(matches!(
            response.and_then(|frame| frame.body),
            Some(pb::sync_frame::Body::Opened(_))
        ));
        policy.enabled.store(false, Ordering::SeqCst);
        rejected(&mut b, open(a_node, b_node), Code::PermissionDenied)?;
        ensure!(b.receive(open(a_node, b_node)).is_err());
        Ok(())
    }

    #[test]
    fn session_proof_rejects_other_tls_exporter_and_wrong_expected_peer() -> Result<()> {
        let (mut a, mut b, _policy, a_node, b_node) = setup()?;
        b.channel.exporter = [8; 48];
        let a_hello = a.initial_frame()?;
        let b_hello = b.initial_frame()?;
        let a_auth = a
            .receive(b_hello)?
            .ok_or_else(|| anyhow::anyhow!("missing auth"))?;
        let b_auth = b
            .receive(a_hello)?
            .ok_or_else(|| anyhow::anyhow!("missing auth"))?;
        rejected(&mut a, b_auth, Code::Unauthenticated)?;
        rejected(&mut b, a_auth, Code::Unauthenticated)?;

        let (mut a, mut b, _policy, _, _) = setup()?;
        a.channel.expected_peer = Some(a_node);
        a.initial_frame()?;
        let b_hello = b.initial_frame()?;
        rejected(&mut a, b_hello, Code::Unauthenticated)?;
        ensure!(a.channel.expected_peer != Some(b_node));
        Ok(())
    }

    #[test]
    fn expired_or_advanced_generation_closes_ready_session() -> Result<()> {
        let (mut a, mut b, policy, a_node, b_node) = setup()?;
        authenticate(&mut a, &mut b)?;
        policy.minimum_generation.store(2, Ordering::SeqCst);
        rejected(&mut b, open(a_node, b_node), Code::PermissionDenied)?;

        let (mut a, mut b, policy, a_node, b_node) = setup()?;
        authenticate(&mut a, &mut b)?;
        policy.now_ms.store(200, Ordering::SeqCst);
        rejected(&mut b, open(a_node, b_node), Code::Unauthenticated)?;
        Ok(())
    }

    #[test]
    fn expired_local_authorization_closes_handshake_and_ready_session() -> Result<()> {
        let (_a, mut b, policy, _a_node, _b_node) = setup()?;
        policy.now_ms.store(300, Ordering::SeqCst);
        ensure!(matches!(
            b.initial_frame(),
            Err(status) if status.code() == Code::FailedPrecondition
        ));
        ensure!(matches!(b.phase, Phase::Closed));

        let (mut a, mut b, policy, _a_node, _b_node) = setup()?;
        let a_hello = a.initial_frame()?;
        b.initial_frame()?;
        policy.now_ms.store(300, Ordering::SeqCst);
        rejected(&mut b, a_hello, Code::FailedPrecondition)?;

        let (mut a, mut b, policy, _a_node, _b_node) = setup()?;
        let a_hello = a.initial_frame()?;
        let b_hello = b.initial_frame()?;
        let a_auth = a
            .receive(b_hello)?
            .ok_or_else(|| anyhow::anyhow!("missing initiator authentication"))?;
        b.receive(a_hello)?;
        policy.now_ms.store(300, Ordering::SeqCst);
        rejected(&mut b, a_auth, Code::FailedPrecondition)?;

        let (mut a, mut b, policy, a_node, b_node) = setup()?;
        authenticate(&mut a, &mut b)?;
        policy.now_ms.store(300, Ordering::SeqCst);
        rejected(&mut b, open(a_node, b_node), Code::FailedPrecondition)?;
        Ok(())
    }

    #[test]
    fn clock_rollback_closes_handshake_and_ready_session() -> Result<()> {
        let (mut a, mut b, policy, _a_node, _b_node) = setup()?;
        let a_hello = a.initial_frame()?;
        let b_hello = b.initial_frame()?;
        let a_auth = a
            .receive(b_hello)?
            .ok_or_else(|| anyhow::anyhow!("missing initiator authentication"))?;
        b.receive(a_hello)?;
        policy.now_ms.store(149, Ordering::SeqCst);
        rejected(&mut b, a_auth, Code::FailedPrecondition)?;

        let (mut a, mut b, policy, a_node, b_node) = setup()?;
        authenticate(&mut a, &mut b)?;
        policy.now_ms.store(149, Ordering::SeqCst);
        rejected(&mut b, open(a_node, b_node), Code::FailedPrecondition)?;
        Ok(())
    }

    #[test]
    fn exact_authorization_revocation_and_oversize_frame_fail_closed() -> Result<()> {
        let (_a, mut b, _policy, _a_node, _b_node) = setup()?;
        b.initial_frame()?;
        let oversized = frame(pb::sync_frame::Body::Failure(pb::SyncFailure {
            request: 1,
            code: pb::FailureCode::Invalid as i32,
            message: "x".repeat(b.config.max_frame_bytes),
            commit_verdict: pb::CommitVerdict::Unspecified as i32,
        }));
        rejected(&mut b, oversized, Code::ResourceExhausted)?;
        ensure!(
            b.receive(frame(pb::sync_frame::Body::Authenticate(
                pb::Authenticate {
                    online_signature: vec![0; FederationRoot::SIGNATURE_LEN],
                }
            )))
            .is_err()
        );

        let (mut a, mut b, policy, a_node, b_node) = setup()?;
        authenticate(&mut a, &mut b)?;
        let digest = match &b.phase {
            Phase::Ready { proof, .. } => proof.authorization_digest(),
            _ => anyhow::bail!("peer was not admitted"),
        };
        *policy
            .revoked_authorization
            .lock()
            .map_err(|_error| anyhow::anyhow!("peer policy lock poisoned"))? = Some(digest);
        rejected(&mut b, open(a_node, b_node), Code::PermissionDenied)?;
        Ok(())
    }

    #[tokio::test]
    async fn batch_blocked_in_outbound_queue_is_rejected_at_tonic_poll_after_export_revocation()
    -> Result<()> {
        use tokio_stream::StreamExt as _;
        let (mut a, mut b, _policy, a_node, b_node) = setup()?;
        authenticate(&mut a, &mut b)?;
        b.receive(open(a_node, b_node))?;
        let published = b
            .service
            .append_published(xolotl_federation::PublishRequest {
                retry_epoch: 1,
                stream: StreamRef {
                    publisher: b_node,
                    id: StreamId::from_bytes([3; 16]),
                },
                publish_id: RequestId::from_bytes([31; 16]),
                event_type: xolotl_federation::EventType::new("private")?,
                schema_revision: xolotl_federation::SchemaRevision::from_bytes([32; 32]),
                event_ref: None,
                payload: Arc::from(b"private record".as_slice()),
            })?;
        let response = b
            .receive(frame(pb::sync_frame::Body::Read(pb::Read {
                request: 2,
                subscription: Some(pb::SubscriptionRef {
                    subscriber: a_node.as_bytes().to_vec(),
                    id: vec![4; 16],
                }),
                after: None,
                max_records: 1,
                max_bytes: 1024,
                context_id: 0,
                holder_request_signature: Vec::new(),
            })))?
            .ok_or_else(|| anyhow::anyhow!("missing batch"))?;
        ensure!(
            matches!(&response.body, Some(pb::sync_frame::Body::Batch(batch)) if batch.records.len() == 1)
        );
        let deadline = Instant::now() + std::time::Duration::from_secs(30);
        let queued = b.response_protector()?(response)?.with_deadline(deadline);
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let control = frame(pb::sync_frame::Body::Failure(wire::failure(
            90,
            &FederationError::Unauthorized,
        )));
        sender
            .send(Ok(b.response_protector()?(control)?.with_deadline(deadline)))
            .await
            .map_err(|_error| anyhow::anyhow!("queue closed"))?;
        let actor = tokio::spawn(std::future::pending::<()>());
        let mut stream = crate::FederationGrpcPublisherStream::new(
            receiver,
            actor.abort_handle(),
            delivery::worker_pool()?,
        );
        let mut blocked = Box::pin(sender.send(Ok(queued)));
        ensure!(poll_once(blocked.as_mut()).await.is_pending());
        b.service.set_export_authority(
            a_node,
            ExportName::new("friends")?,
            Some(1),
            ExportAccess {
                serve: false,
                receive: false,
            },
        )?;
        ensure!(matches!(
            stream
                .next()
                .await
                .transpose()?
                .and_then(|value| value.body),
            Some(pb::sync_frame::Body::Failure(_))
        ));
        blocked
            .await
            .map_err(|_error| anyhow::anyhow!("queue closed"))?;
        ensure!(matches!(stream.next().await, Some(Err(_))));
        ensure!(stream.next().await.is_none());
        ensure!(sender.is_closed());
        ensure!(
            actor.await.is_err_and(|error| error.is_cancelled()),
            "delivery rejection aborts actor"
        );
        ensure!(
            b.service
                .store()
                .read(xolotl_federation::ReadRequest {
                    authenticated_subscriber: a_node,
                    subscription: xolotl_federation::SubscriptionRef {
                        subscriber: a_node,
                        id: xolotl_federation::SubscriptionId::from_bytes([4; 16])
                    },
                    after: None,
                    max_records: 1,
                    max_bytes: 1024,
                })
                .is_err()
        );
        ensure!(published.payload() == b"private record");
        Ok(())
    }

    #[tokio::test]
    async fn locally_admitted_peer_proof_is_retained_but_rechecked_at_request_stream_poll()
    -> Result<()> {
        use tokio_stream::StreamExt as _;
        let (mut a, mut b, policy, a_node, b_node) = setup()?;
        authenticate(&mut a, &mut b)?;
        b.receive(open(a_node, b_node))?;
        let response = b.response_protector()?(frame(pb::sync_frame::Body::Acknowledged(
            pb::Acknowledged {
                request: 2,
                position: None,
            },
        )))?;
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(response.with_deadline(Instant::now() + std::time::Duration::from_secs(30)))
            .await
            .map_err(|_error| anyhow::anyhow!("queue closed"))?;
        policy.minimum_generation.store(2, Ordering::SeqCst);
        let mut stream =
            crate::delivery::DeliveryRequestStream::new(receiver, delivery::worker_pool()?);
        ensure!(stream.next().await.is_none());
        ensure!(sender.is_closed());
        Ok(())
    }
}
