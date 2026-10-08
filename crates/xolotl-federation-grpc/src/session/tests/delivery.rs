use super::*;

use sha2::{Digest as _, Sha384};
use tokio_stream::StreamExt as _;
use xolotl_federation::{
    CallAuthorityRule, CallKernelBinding, CallMethod, CallPath, CallTarget, Digest, EventType,
    FederationObjectReadStore, FederationStore, InspectCallRequest, ObjectGrantSpec,
    ObjectTransferId, PeerAdmission, PersistedCallResult, PublishRequest, SchemaRevision,
    SnapshotId, SnapshotOfferRequest, SnapshotPublicationProof, SnapshotReadRequest,
    SnapshotReceivedRequest, SnapshotSuffixCoverage, SubscriptionId, SubscriptionRef,
};
use xolotl_storage_redb::{RedbFederationStore, RedbStore};

pub(super) fn worker_pool() -> Result<crate::runtime::WorkerPool> {
    Ok(crate::FederationGrpcRuntime::new(
        FederationGrpcConfig::default(),
        Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default()),
    )?
    .worker_pool())
}

struct Fixture {
    session: FederationGrpcPublisherSession,
    policy: Arc<Policy>,
    peer: FederationNodeId,
    node: FederationNodeId,
    store: RedbFederationStore,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Result<Self> {
        let (mut initiator, mut session, policy, peer, node) = setup()?;
        let directory = tempfile::tempdir()?;
        let db = RedbStore::open(directory.path().join("publisher.redb"))?;
        let store = db.federation_store(node)?;
        store.set_peer_authority(peer, None, true)?;
        store.set_peer_admission(
            peer,
            None,
            PeerAdmission {
                minimum_online_generation: 1,
                allowed_authorization_digests: vec![initiator.local.authorization_digest()],
            },
        )?;
        store.set_export_authority(
            peer,
            ExportName::new("friends")?,
            None,
            ExportAccess {
                serve: true,
                receive: false,
            },
        )?;
        store.declare_stream(StreamSpec {
            stream: StreamRef {
                publisher: node,
                id: StreamId::from_bytes([3; 16]),
            },
            export: ExportName::new("friends")?,
        })?;
        session.service =
            FederationService::new(Arc::new(store.clone()), session.service.limits())?;
        authenticate(&mut initiator, &mut session)?;
        session.receive(open(peer, node))?;
        Ok(Self {
            session,
            policy,
            peer,
            node,
            store,
            _directory: directory,
        })
    }

    fn subscription(&self) -> SubscriptionRef {
        SubscriptionRef {
            subscriber: self.peer,
            id: SubscriptionId::from_bytes([4; 16]),
        }
    }
}

async fn rejects_blocked_reply(
    reply: DeliveryFrame,
    revoke: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    sender
        .send(Ok(DeliveryFrame::from(frame(
            pb::sync_frame::Body::Failure(wire::failure(99, &FederationError::Unauthorized)),
        ))
        .with_deadline(deadline)))
        .await
        .map_err(|_error| anyhow::anyhow!("queue closed"))?;
    let actor = tokio::spawn(std::future::pending::<()>());
    let mut stream =
        crate::FederationGrpcPublisherStream::new(receiver, actor.abort_handle(), worker_pool()?);
    let mut blocked = Box::pin(sender.send(Ok(reply.with_deadline(deadline))));
    ensure!(poll_once(blocked.as_mut()).await.is_pending());
    revoke()?;
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
        "denied delivery aborts Session actor"
    );
    Ok(())
}

struct SnapshotSource(Arc<AtomicU64>);

impl SnapshotContentSource for SnapshotSource {
    fn read_snapshot_chunk(
        &self,
        _offer: &xolotl_federation::SnapshotOffer,
        _offset: u64,
        bytes: usize,
    ) -> Result<Arc<[u8]>, FederationError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(Arc::from(vec![1; bytes]))
    }
}

#[tokio::test]
async fn snapshot_offer_and_bytes_blocked_in_queue_keep_the_original_authority() -> Result<()> {
    for send_chunk in [false, true] {
        let mut fixture = Fixture::new()?;
        let reads = Arc::new(AtomicU64::new(0));
        fixture.session = fixture.session.with_snapshot_publisher(
            Arc::new(fixture.store.clone()),
            Arc::new(SnapshotSource(Arc::clone(&reads))),
        )?;
        let record = fixture.store.append_published(PublishRequest {
            retry_epoch: 1,
            stream: StreamRef {
                publisher: fixture.node,
                id: StreamId::from_bytes([3; 16]),
            },
            publish_id: RequestId::from_bytes([40; 16]),
            event_type: EventType::new("state")?,
            schema_revision: SchemaRevision::from_bytes([41; 32]),
            event_ref: None,
            payload: Arc::from(b"state".as_slice()),
        })?;
        let offer = fixture.store.publish_snapshot_offer(SnapshotOfferRequest {
            authenticated_subscriber: fixture.peer,
            subscription: fixture.subscription(),
            proof: SnapshotPublicationProof {
                snapshot_id: SnapshotId::from_bytes([42; 16]),
                stream: record.stream(),
                position: record.position(),
                schema_revision: record.schema_revision(),
                content_digest: Digest::from_bytes(Sha384::digest([1; 4]).into()),
                content_bytes: 4,
                publication_digest: Digest::from_bytes([43; 48]),
            },
        })?;
        let request = if send_chunk {
            frame(pb::sync_frame::Body::ReadSnapshot(
                wire::read_snapshot_to_pb(
                    2,
                    SnapshotReadRequest {
                        authenticated_subscriber: fixture.peer,
                        subscription: fixture.subscription(),
                        manifest_digest: offer.manifest.binding_digest(),
                        offset: 0,
                        max_bytes: 4,
                    },
                )?,
            ))
        } else {
            frame(pb::sync_frame::Body::InspectSnapshot(
                wire::inspect_snapshot_to_pb(2, fixture.subscription()),
            ))
        };
        let reply = fixture
            .session
            .receive(request)?
            .ok_or_else(|| anyhow::anyhow!("missing snapshot reply"))?;
        ensure!(matches!(&reply.body, Some(pb::sync_frame::Body::SnapshotChunk(_))) == send_chunk);
        let protected = fixture.session.response_protector()?(reply)?;
        rejects_blocked_reply(protected, || {
            fixture.store.set_peer_admission(
                fixture.peer,
                Some(1),
                PeerAdmission {
                    minimum_online_generation: 2,
                    allowed_authorization_digests: vec![match &fixture.session.phase {
                        Phase::Ready { proof, .. } => proof.authorization_digest(),
                        _ => anyhow::bail!("Session was not admitted"),
                    }],
                },
            )?;
            Ok(())
        })
        .await?;
        ensure!(reads.load(Ordering::SeqCst) == u64::from(send_chunk));
        ensure!(fixture.store.local_snapshot_offer(fixture.subscription())? == Some(offer));
    }
    Ok(())
}

#[tokio::test]
async fn archive_and_suffix_receipts_recheck_scope_after_offer_retirement() -> Result<()> {
    for suffix in [false, true] {
        let mut fixture = Fixture::new()?;
        fixture.session = fixture.session.with_snapshot_publisher(
            Arc::new(fixture.store.clone()),
            Arc::new(SnapshotSource(Arc::new(AtomicU64::new(0)))),
        )?;
        let request = PublishRequest {
            retry_epoch: 1,
            stream: StreamRef {
                publisher: fixture.node,
                id: StreamId::from_bytes([3; 16]),
            },
            publish_id: RequestId::from_bytes([40; 16]),
            event_type: EventType::new("state")?,
            schema_revision: SchemaRevision::from_bytes([41; 32]),
            event_ref: None,
            payload: Arc::from(b"state".as_slice()),
        };
        let first = fixture.store.append_published(request.clone())?;
        let second = fixture.store.append_published(PublishRequest {
            retry_epoch: 1,
            publish_id: RequestId::from_bytes([44; 16]),
            ..request
        })?;
        let offer = fixture.store.publish_snapshot_offer(SnapshotOfferRequest {
            authenticated_subscriber: fixture.peer,
            subscription: fixture.subscription(),
            proof: SnapshotPublicationProof {
                snapshot_id: SnapshotId::from_bytes([42; 16]),
                stream: first.stream(),
                position: first.position(),
                schema_revision: first.schema_revision(),
                content_digest: Digest::from_bytes(Sha384::digest([1; 4]).into()),
                content_bytes: 4,
                publication_digest: Digest::from_bytes([43; 48]),
            },
        })?;
        let mut receipt = SnapshotReceivedRequest {
            authenticated_subscriber: fixture.peer,
            subscription: fixture.subscription(),
            manifest_digest: offer.manifest.binding_digest(),
            publication_digest: offer.publication_digest,
            position: first.position(),
            install_id: SnapshotId::from_bytes([45; 16]),
            archive_digest: Digest::from_bytes([46; 48]),
            federation_generation: 1,
            suffix: None,
        };
        fixture.store.receive_snapshot(receipt)?;
        fixture.store.retire_snapshot_offer(&offer)?;
        if suffix {
            receipt.suffix = Some(SnapshotSuffixCoverage {
                after: first.position(),
                through: second.position(),
            });
        }
        let reply = fixture
            .session
            .receive(frame(pb::sync_frame::Body::ReceiveSnapshot(
                wire::receive_snapshot_to_pb(2, receipt),
            )))?
            .ok_or_else(|| anyhow::anyhow!("missing snapshot receipt"))?;
        ensure!(matches!(
            &reply.body,
            Some(pb::sync_frame::Body::SnapshotReceived(_))
        ));
        fixture.session.response_protector()?(reply.clone())?.handoff()?;
        let protected = fixture.session.response_protector()?(reply)?;
        rejects_blocked_reply(protected, || {
            fixture
                .store
                .set_peer_authority(fixture.peer, Some(1), false)?;
            Ok(())
        })
        .await?;
    }
    Ok(())
}

#[derive(Clone)]
struct ObjectReader {
    store: Arc<dyn FederationObjectReadStore>,
    reads: Arc<AtomicU64>,
}

impl ObjectReader {
    fn bound(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<Self, FederationError> {
        Ok(Self {
            store: self.store.bind_object_decision(decision)?,
            reads: Arc::clone(&self.reads),
        })
    }
}

impl FederationObjectReader for ObjectReader {
    fn bind_reader_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<Arc<dyn FederationObjectReader>, FederationError> {
        Ok(Arc::new(self.bound(decision)?))
    }

    fn local_node(&self) -> FederationNodeId {
        self.store.local_node()
    }

    fn authorize_delivery(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        _context: Option<&ObjectDeliveryContext>,
    ) -> Result<(), FederationError> {
        self.store
            .authorize_object_delivery(request, authority, 150)
    }

    fn read_object(
        &self,
        request: ObjectReadRequest,
        authority: ObjectReadAuthority,
    ) -> crate::ObjectReadFuture<'_> {
        Box::pin(async move {
            self.store.reserve_object_read(&request, authority, 150)?;
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.store.confirm_object_read(&request, authority, 150)?;
            Ok((
                ObjectReadPage {
                    transfer: request.transfer,
                    grant: request.grant,
                    revision: request.expected_revision,
                    offset: request.offset,
                    bytes: vec![1; request.max_bytes],
                    end_of_object: true,
                    end_of_range: true,
                },
                None,
            ))
        })
    }
}

struct UnsupportedObjectReader(ObjectReader);

struct PolicyObjectSource {
    reads: AtomicU64,
    metadata_reads: AtomicU64,
}

impl xolotl_state::object::ObjectRead for PolicyObjectSource {
    type Metadata<'a> =
        std::future::Ready<xolotl_state::StateResult<Option<xolotl_state::object::ObjectMetadata>>>;
    type ReadChunk<'a> =
        std::future::Ready<xolotl_state::StateResult<xolotl_state::object::ObjectReadChunk>>;

    fn metadata<'a>(&'a self, blob: &'a xolotl_types::BlobRef) -> Self::Metadata<'a> {
        let taint = if self.metadata_reads.fetch_add(1, Ordering::SeqCst) == 0 {
            xolotl_types::TaintSet::author()
        } else {
            xolotl_types::TaintSet::pristine()
        };
        std::future::ready(Ok(Some(xolotl_state::object::ObjectMetadata {
            blob: blob.clone(),
            taint,
        })))
    }

    fn read_chunk<'a>(
        &'a self,
        _blob: &'a xolotl_types::BlobRef,
        _offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        buffer.fill(1);
        std::future::ready(Ok(xolotl_state::object::ObjectReadChunk {
            bytes_read: buffer.len(),
            end: true,
            taint: xolotl_types::TaintSet::of(xolotl_types::TaintSource::ModelOutput),
        }))
    }
}

struct PolicyObjectReader {
    local: FederationNodeId,
    service: xolotl_federation::FederationObjectReadService,
    objects: Arc<PolicyObjectSource>,
}

impl FederationObjectReader for PolicyObjectReader {
    fn bind_reader_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<Arc<dyn FederationObjectReader>, FederationError> {
        Ok(Arc::new(Self {
            local: self.local,
            service: self.service.with_decision(decision)?,
            objects: Arc::clone(&self.objects),
        }))
    }

    fn local_node(&self) -> FederationNodeId {
        self.local
    }

    fn authorize_delivery(
        &self,
        request: &ObjectReadRequest,
        authority: ObjectReadAuthority,
        context: Option<&ObjectDeliveryContext>,
    ) -> Result<(), FederationError> {
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
    ) -> crate::ObjectReadFuture<'_> {
        Box::pin(async move {
            let delivery = self
                .service
                .read_for_delivery(&*self.objects, request, authority)
                .await?;
            Ok((delivery.page, Some(delivery.context)))
        })
    }
}

#[tokio::test]
async fn queued_object_rechecks_mutable_policy_on_each_original_metadata_view() -> Result<()> {
    for denied_view in 1..=3 {
        let mut fixture = Fixture::new()?;
        let grant = fixture.store.issue_object_grant(
            ObjectGrantSpec {
                subject: FederationSubject::Node(fixture.peer),
                presenter: fixture.peer,
                blob: xolotl_types::BlobRef {
                    hash: "a".repeat(96),
                    size: 4,
                    mime: None,
                },
                range_start: 0,
                range_end: 4,
                expires_at_ms: 190,
                max_total_bytes: 4,
                max_chunk_bytes: 4,
            },
            150,
        )?;
        let deny = Arc::new(AtomicU64::new(0));
        let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
        let policy_deny = Arc::clone(&deny);
        let policy_observations = Arc::clone(&observations);
        let expected_blob = grant.spec.blob.clone();
        let expected_subject = grant.spec.subject.clone();
        let disclosure = Arc::new(
            move |subject: &FederationSubject, metadata: &xolotl_state::object::ObjectMetadata| {
                let Ok(mut observations) = policy_observations.lock() else {
                    return false;
                };
                observations.push((subject.clone(), metadata.clone()));
                drop(observations);
                let view = if metadata.taint == xolotl_types::TaintSet::author() {
                    1
                } else if metadata.taint
                    == xolotl_types::TaintSet::of(xolotl_types::TaintSource::ModelOutput)
                {
                    2
                } else if metadata.taint.is_pristine() {
                    3
                } else {
                    return false;
                };
                subject == &expected_subject
                    && metadata.blob == expected_blob
                    && policy_deny.load(Ordering::SeqCst) != view
            },
        );
        let objects = Arc::new(PolicyObjectSource {
            reads: AtomicU64::new(0),
            metadata_reads: AtomicU64::new(0),
        });
        let service = xolotl_federation::FederationObjectReadService::new(
            Arc::new(fixture.store.clone()),
            Arc::new(|| Ok(150)),
            disclosure,
            4,
        )?;
        fixture.session = fixture
            .session
            .with_object_reader(Arc::new(PolicyObjectReader {
                local: fixture.node,
                service,
                objects: Arc::clone(&objects),
            }))?;
        let request = ObjectReadRequest {
            authenticated_presenter: fixture.peer,
            subject: grant.spec.subject.clone(),
            transfer: ObjectTransferId::from_bytes([60; 16]),
            grant: grant.id,
            expected_revision: grant.revision,
            blob: grant.spec.blob.clone(),
            offset: 0,
            max_bytes: 4,
        };
        fixture
            .session
            .receive(frame(pb::sync_frame::Body::ReadObject(
                wire::read_object_to_pb(2, &request)?,
            )))?;
        let pending = fixture
            .session
            .take_pending_object()
            .ok_or_else(|| anyhow::anyhow!("missing object read"))?;
        let reader = Arc::clone(&pending.reader);
        let context = Arc::clone(&pending.context);
        let authority = pending.authority;
        let response = if denied_view == 2 {
            let page = pending.read_page().await;
            fixture
                .session
                .finish_object(pending.request, &request, page)?
        } else {
            pending
                .execute(Instant::now() + std::time::Duration::from_secs(5))
                .await?
        };
        ensure!(
            matches!(&response.body, Some(pb::sync_frame::Body::ObjectChunk(chunk)) if chunk.data == vec![1; 4])
        );
        ensure!(
            reader
                .authorize_delivery(&request, authority, None)
                .is_err()
        );
        let mut other_request = request.clone();
        other_request.transfer = ObjectTransferId::from_bytes([61; 16]);
        ensure!(
            reader
                .authorize_delivery(&other_request, authority, context.get())
                .is_err()
        );
        reader.authorize_delivery(&request, authority, context.get())?;
        let original = {
            let observed = observations
                .lock()
                .map_err(|error| anyhow::anyhow!("policy observations poisoned: {error}"))?;
            ensure!(observed.len() == 6);
            let original = observed[..3].to_vec();
            ensure!(observed[3..6] == original);
            original
        };
        let protected = fixture.session.response_protector()?(response)?;
        rejects_blocked_reply(protected, || {
            deny.store(denied_view, Ordering::SeqCst);
            Ok(())
        })
        .await?;
        let observed = observations
            .lock()
            .map_err(|error| anyhow::anyhow!("policy observations poisoned: {error}"))?;
        ensure!(observed.len() == 6 + denied_view as usize);
        ensure!(observed[6..] == original[..denied_view as usize]);
        ensure!(objects.reads.load(Ordering::SeqCst) == 1);
        ensure!(objects.metadata_reads.load(Ordering::SeqCst) == 2);
        let retained = fixture
            .store
            .object_grant(grant.id)?
            .ok_or_else(|| anyhow::anyhow!("grant lost"))?;
        ensure!(retained.revision == grant.revision && retained.charged_bytes == 4);
    }
    Ok(())
}

struct InvalidResultReader(ObjectReader);

impl FederationObjectReader for InvalidResultReader {
    fn bind_reader_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<Arc<dyn FederationObjectReader>, FederationError> {
        Ok(Arc::new(Self(self.0.bound(decision)?)))
    }

    fn local_node(&self) -> FederationNodeId {
        self.0.local_node()
    }

    fn read_object(
        &self,
        request: ObjectReadRequest,
        authority: ObjectReadAuthority,
    ) -> crate::ObjectReadFuture<'_> {
        Box::pin(async move {
            self.0.read_object(request, authority).await?;
            Err(FederationError::Invalid(
                "driver rejected result after accepted read",
            ))
        })
    }
}

#[tokio::test]
async fn invalid_result_after_committed_object_quota_preserves_unspecified_verdict() -> Result<()> {
    let mut fixture = Fixture::new()?;
    let reads = Arc::new(AtomicU64::new(0));
    fixture.session = fixture
        .session
        .with_object_reader(Arc::new(InvalidResultReader(ObjectReader {
            store: Arc::new(fixture.store.clone()),
            reads: Arc::clone(&reads),
        })))?;
    let grant = fixture.store.issue_object_grant(
        ObjectGrantSpec {
            subject: FederationSubject::Node(fixture.peer),
            presenter: fixture.peer,
            blob: xolotl_types::BlobRef {
                hash: "a".repeat(96),
                size: 4,
                mime: None,
            },
            range_start: 0,
            range_end: 4,
            expires_at_ms: 190,
            max_total_bytes: 4,
            max_chunk_bytes: 4,
        },
        150,
    )?;
    let request = ObjectReadRequest {
        authenticated_presenter: fixture.peer,
        subject: grant.spec.subject.clone(),
        transfer: ObjectTransferId::from_bytes([59; 16]),
        grant: grant.id,
        expected_revision: grant.revision,
        blob: grant.spec.blob.clone(),
        offset: 0,
        max_bytes: 4,
    };
    fixture
        .session
        .receive(frame(pb::sync_frame::Body::ReadObject(
            wire::read_object_to_pb(2, &request)?,
        )))?;
    let pending = fixture
        .session
        .take_pending_object()
        .ok_or_else(|| anyhow::anyhow!("missing object operation"))?;
    let reply = pending
        .execute(Instant::now() + std::time::Duration::from_secs(5))
        .await?;
    let reply = fixture.session.response_protector()?(reply)?;
    fixture.policy.enabled.store(false, Ordering::SeqCst);
    let delivered = reply
        .with_deadline(Instant::now() + std::time::Duration::from_secs(5))
        .start(worker_pool()?)
        .await?;
    let Some(pb::sync_frame::Body::Failure(failure)) = delivered.body else {
        anyhow::bail!("missing sanitized control failure");
    };
    ensure!(failure.request == 2 && failure.code == pb::FailureCode::Invalid as i32);
    ensure!(failure.commit_verdict == pb::CommitVerdict::Unspecified as i32);
    ensure!(!failure.message.contains("driver"));
    let preserved = crate::RemoteSyncFailure::from_status(&wire::failure_status(failure))
        .ok_or_else(|| anyhow::anyhow!("remote failure lost"))?;
    ensure!(preserved.request == 2 && preserved.verdict() == pb::CommitVerdict::Unspecified);
    ensure!(reads.load(Ordering::SeqCst) == 1);
    ensure!(
        fixture
            .store
            .object_grant(grant.id)?
            .ok_or_else(|| anyhow::anyhow!("grant lost"))?
            .charged_bytes
            == 4
    );
    Ok(())
}

impl FederationObjectReader for UnsupportedObjectReader {
    fn bind_reader_decision(
        &self,
        decision: xolotl_federation::FederationDecision,
    ) -> Result<Arc<dyn FederationObjectReader>, FederationError> {
        Ok(Arc::new(Self(self.0.bound(decision)?)))
    }

    fn local_node(&self) -> FederationNodeId {
        self.0.local_node()
    }

    fn read_object(
        &self,
        request: ObjectReadRequest,
        authority: ObjectReadAuthority,
    ) -> crate::ObjectReadFuture<'_> {
        self.0.read_object(request, authority)
    }
}

#[tokio::test]
async fn object_grant_revocation_and_unsupported_handoff_never_redo_or_refund_a_read() -> Result<()>
{
    for unsupported in [false, true] {
        let mut fixture = Fixture::new()?;
        let reads = Arc::new(AtomicU64::new(0));
        let reader = ObjectReader {
            store: Arc::new(fixture.store.clone()),
            reads: Arc::clone(&reads),
        };
        let reader: Arc<dyn FederationObjectReader> = if unsupported {
            Arc::new(UnsupportedObjectReader(reader))
        } else {
            Arc::new(reader)
        };
        fixture.session = fixture.session.with_object_reader(reader)?;
        let grant = fixture.store.issue_object_grant(
            ObjectGrantSpec {
                subject: FederationSubject::Node(fixture.peer),
                presenter: fixture.peer,
                blob: xolotl_types::BlobRef {
                    hash: "a".repeat(96),
                    size: 4,
                    mime: None,
                },
                range_start: 0,
                range_end: 4,
                expires_at_ms: 190,
                max_total_bytes: 4,
                max_chunk_bytes: 4,
            },
            150,
        )?;
        let read = ObjectReadRequest {
            authenticated_presenter: fixture.peer,
            subject: grant.spec.subject.clone(),
            transfer: ObjectTransferId::from_bytes([44; 16]),
            grant: grant.id,
            expected_revision: grant.revision,
            blob: grant.spec.blob.clone(),
            offset: 0,
            max_bytes: 4,
        };
        fixture
            .session
            .receive(frame(pb::sync_frame::Body::ReadObject(
                wire::read_object_to_pb(2, &read)?,
            )))?;
        let pending = fixture
            .session
            .take_pending_object()
            .ok_or_else(|| anyhow::anyhow!("missing object operation"))?;
        let response = pending
            .execute(Instant::now() + std::time::Duration::from_secs(1))
            .await?;
        ensure!(
            matches!(&response.body, Some(pb::sync_frame::Body::ObjectChunk(chunk)) if chunk.data.len() == 4)
        );
        let protected = fixture.session.response_protector()?(response)?;
        rejects_blocked_reply(protected, || {
            if !unsupported {
                fixture
                    .store
                    .revoke_object_grant(grant.id, grant.revision)?;
            }
            Ok(())
        })
        .await?;
        ensure!(reads.load(Ordering::SeqCst) == 1);
        ensure!(
            fixture
                .store
                .object_grant(grant.id)?
                .ok_or_else(|| anyhow::anyhow!("grant lost"))?
                .charged_bytes
                == 4
        );
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_call_control_stays_inspectable_but_queued_output_obeys_method_revocation_and_ttl()
-> Result<()> {
    for expire in [false, true] {
        let mut fixture = Fixture::new()?;
        fixture.session = fixture
            .session
            .with_call_store(Arc::new(fixture.store.clone()))?;
        let target = CallTarget {
            export: ExportName::new("friends")?,
            path: CallPath::new("/")?,
            method: CallMethod::new("echo")?,
            contract_digest: [45; 32],
        };
        let mut rule = CallAuthorityRule {
            subject: FederationSubject::Node(fixture.peer),
            presenter: fixture.peer,
            target: target.clone(),
            enabled: true,
            expires_ms: 1000,
            max_input_bytes: 4,
            max_prepare_window_ms: 100,
            max_result_retention_ms: 10,
        };
        fixture.store.set_call_authority(None, rule.clone())?;
        let prepare = PrepareCallRequest {
            authenticated_origin: fixture.peer,
            subject: rule.subject.clone(),
            origin_request_id: RequestId::from_bytes([46; 16]),
            target,
            input_digest: Digest::from_bytes(Sha384::digest(b"body").into()),
            input_bytes: 4,
            prepare_deadline_ms: 180,
            execution_deadline_ms: 190,
            result_retention_ms: 2,
        };
        let call = fixture.store.prepare_call(prepare.clone(), 150)?.call;
        fixture.store.invoke_call(
            InvokeCallRequest {
                authenticated_origin: fixture.peer,
                subject: rule.subject.clone(),
                origin_request_id: prepare.origin_request_id,
                call,
                input: Arc::from(b"body".as_slice()),
            },
            150,
        )?;
        fixture.store.bind_kernel_identity(
            call,
            CallKernelBinding {
                process: 47,
                lifecycle: 48,
            },
            150,
        )?;
        fixture
            .store
            .record_kernel_acceptance(call, Digest::from_bytes([49; 48]))?;
        let cancel = CancelCallRequest {
            authenticated_origin: fixture.peer,
            subject: rule.subject.clone(),
            control_request_id: RequestId::from_bytes([51; 16]),
            call,
            expected_control_revision: None,
        };
        let cancelled = fixture.store.cancel_call(cancel.clone(), 150)?;
        ensure!(cancelled.call == call && cancelled.cancellation_requested);
        ensure!(cancelled.status == xolotl_federation::CallStatus::Accepted);
        ensure!(!cancelled.kernel_cancel_accepted && !cancelled.execution_stopped);
        let result = PersistedCallResult::new(true, Arc::from(b"private result".as_slice()), None)?;
        fixture
            .store
            .record_call_result(call, result.clone(), vec![[50; 32]], 150)?;
        ensure!(fixture.store.cancel_call(cancel, 150)? == cancelled);
        let inspect = InspectCallRequest {
            authenticated_origin: fixture.peer,
            subject: rule.subject.clone(),
            call,
        };
        let response = fixture
            .session
            .receive(frame(pb::sync_frame::Body::InspectCall(
                wire::inspect_call_to_pb(2, &inspect),
            )))?
            .ok_or_else(|| anyhow::anyhow!("missing call inspection"))?;
        ensure!(
            matches!(&response.body, Some(pb::sync_frame::Body::CallInspected(value)) if value.result.is_some())
        );
        let protected = fixture.session.response_protector()?(response)?;
        rejects_blocked_reply(protected, || {
            if expire {
                fixture.policy.now_ms.store(152, Ordering::SeqCst);
            } else {
                rule.enabled = false;
                fixture.store.set_call_authority(Some(1), rule.clone())?;
            }
            Ok(())
        })
        .await?;
        let control = fixture
            .store
            .inspect_call(inspect, if expire { 152 } else { 150 })?;
        ensure!(control.call == call && control.cancellation_requested);
        ensure!(control.status == xolotl_federation::CallStatus::Finished);
        ensure!(control.unresolved_effect_ids == vec![[50; 32]]);
        ensure!(control.result == if expire { None } else { Some(result) });
        if expire {
            fixture.store.authorize_call_delivery(
                &InspectCallRequest {
                    authenticated_origin: fixture.peer,
                    subject: rule.subject,
                    call,
                },
                None,
                152,
            )?;
        }
    }
    Ok(())
}
