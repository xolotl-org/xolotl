use std::sync::Arc;

use anyhow::{Result, ensure};
use xolotl_federation::{
    AcceptRequest, AcknowledgeRequest, CloseSubscriptionRequest, Digest, EventRef, EventType,
    ExportAccess, ExportName, FederationError, FederationIdentityError, FederationLimits,
    FederationNodeId, FederationOnlineKey, FederationOnlineKeyAuthorization, FederationRoot,
    FederationRootKey, FederationService, FederationSessionTranscript, HistoryStart,
    InspectSubscriptionRequest, InstallSubscriptionRequest, MemoryFederationStore, OpenRequest,
    Position, ProjectionProgress, PublishRequest, ReadRequest, Record, RequestId,
    RootSignaturePurpose, SchemaRevision, StreamId, StreamRef, StreamSpec, SubscriptionId,
    SubscriptionRef, verify_federation_peer_proof,
};

macro_rules! check_eq {
    ($actual:expr, $expected:expr) => {{
        let actual = &$actual;
        let expected = &$expected;
        ensure!(actual == expected, "mismatch: {actual:?} != {expected:?}");
    }};
}

struct Pair {
    publisher: FederationService,
    receiver: FederationService,
    publisher_id: FederationNodeId,
    receiver_id: FederationNodeId,
    stream: StreamRef,
    subscription: SubscriptionRef,
    export: ExportName,
}

impl Pair {
    fn new() -> Result<Self> {
        let publisher_id = FederationNodeId::from_bytes([1; 48]);
        let receiver_id = FederationNodeId::from_bytes([2; 48]);
        let publisher = FederationService::new(
            Arc::new(MemoryFederationStore::new(publisher_id)),
            FederationLimits::default(),
        )?;
        let receiver = FederationService::new(
            Arc::new(MemoryFederationStore::new(receiver_id)),
            FederationLimits::default(),
        )?;
        let export = ExportName::new("notes")?;
        publisher.set_peer_authority(receiver_id, None, true)?;
        publisher.set_export_authority(
            receiver_id,
            export.clone(),
            None,
            ExportAccess {
                serve: true,
                receive: false,
            },
        )?;
        receiver.set_peer_authority(publisher_id, None, true)?;
        receiver.set_export_authority(
            publisher_id,
            export.clone(),
            None,
            ExportAccess {
                serve: false,
                receive: true,
            },
        )?;
        let stream = StreamRef {
            publisher: publisher_id,
            id: StreamId::from_bytes([3; 16]),
        };
        publisher.declare_stream(StreamSpec {
            stream,
            export: export.clone(),
        })?;
        let subscription = SubscriptionRef {
            subscriber: receiver_id,
            id: SubscriptionId::from_bytes([4; 16]),
        };
        Ok(Self {
            publisher,
            receiver,
            publisher_id,
            receiver_id,
            stream,
            subscription,
            export,
        })
    }

    fn open(&self) -> Result<xolotl_federation::OpenResult> {
        let opened = self.publisher.open(OpenRequest {
            authenticated_subscriber: self.receiver_id,
            request_id: RequestId::from_bytes([5; 16]),
            subscription: self.subscription,
            stream: self.stream,
            expected_control_revision: Some(0),
            history: HistoryStart::All,
        })?;
        self.receiver
            .install_subscription(InstallSubscriptionRequest {
                authenticated_publisher: self.publisher_id,
                opened: opened.clone(),
            })?;
        Ok(opened)
    }

    fn publish(&self, id: u8, payload: &[u8]) -> std::result::Result<Record, FederationError> {
        self.publisher.append_published(PublishRequest {
            retry_epoch: 1,
            stream: self.stream,
            publish_id: RequestId::from_bytes([id; 16]),
            event_type: EventType::new("note.created")?,
            schema_revision: SchemaRevision::from_bytes([9; 32]),
            event_ref: None,
            payload: Arc::from(payload),
        })
    }
}

#[test]
fn two_nodes_replay_without_reapplying_and_projection_has_own_position() -> Result<()> {
    let pair = Pair::new()?;
    let opened = pair.open()?;
    let repeat = pair.publisher.open(OpenRequest {
        authenticated_subscriber: pair.receiver_id,
        request_id: opened.request_id,
        subscription: pair.subscription,
        stream: pair.stream,
        expected_control_revision: Some(0),
        history: HistoryStart::All,
    })?;
    check_eq!(opened, repeat);

    let first = pair.publish(11, b"first")?;
    let second = pair.publish(12, b"second")?;
    let same = pair.publish(11, b"first")?;
    check_eq!(first, same);
    check_eq!(second.sequence(), 2);
    check_eq!(pair.publish(11, b"changed"), Err(FederationError::Conflict));
    let page = pair.publisher.read(ReadRequest {
        authenticated_subscriber: pair.receiver_id,
        subscription: pair.subscription,
        after: None,
        max_records: 1,
        max_bytes: 10,
    })?;
    check_eq!(page.records, vec![first.clone()]);
    check_eq!(page.head, Some(second.position()));
    let accepted = pair.receiver.accept(AcceptRequest {
        authenticated_publisher: pair.publisher_id,
        subscription: pair.subscription,
        record: first.clone(),
    })?;
    ensure!(accepted.newly_accepted);
    check_eq!(accepted.position, first.position());
    let duplicate = pair.receiver.accept(AcceptRequest {
        authenticated_publisher: pair.publisher_id,
        subscription: pair.subscription,
        record: first.clone(),
    })?;
    ensure!(!duplicate.newly_accepted);
    let ack = pair.publisher.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: pair.receiver_id,
        subscription: pair.subscription,
        position: accepted.position,
    })?;
    check_eq!(ack, first.position());
    let next_page = pair.publisher.read(ReadRequest {
        authenticated_subscriber: pair.receiver_id,
        subscription: pair.subscription,
        after: Some(first.position()),
        max_records: 3,
        max_bytes: 10,
    })?;
    check_eq!(next_page.records, vec![second.clone()]);
    let second_accepted = pair.receiver.accept(AcceptRequest {
        authenticated_publisher: pair.publisher_id,
        subscription: pair.subscription,
        record: second.clone(),
    })?;
    check_eq!(second_accepted.position, second.position());
    check_eq!(
        pair.receiver
            .record_projection_progress(ProjectionProgress {
                subscription: pair.subscription,
                position: second.position(),
            }),
        Err(FederationError::Gap {
            expected: 1,
            received: 2
        })
    );
    check_eq!(
        pair.receiver
            .record_projection_progress(ProjectionProgress {
                subscription: pair.subscription,
                position: first.position(),
            })?,
        first.position()
    );
    check_eq!(
        pair.receiver
            .record_projection_progress(ProjectionProgress {
                subscription: pair.subscription,
                position: second.position(),
            })?,
        second.position()
    );
    Ok(())
}

#[test]
fn detached_record_views_cannot_mutate_verified_records() -> Result<()> {
    let pair = Pair::new()?;
    let record = pair.publish(11, b"payload")?;
    let original = record.clone();
    let mut payload = record.payload_arc();
    ensure!(Arc::get_mut(&mut payload).is_none());
    Arc::make_mut(&mut payload)[0] = b'X';
    let mut parts = record.parts();
    parts.sequence += 1;
    parts.event_type = EventType::new("changed")?;
    Arc::make_mut(&mut parts.payload)[0] = b'Y';
    check_eq!(record, original);
    check_eq!(record.payload(), b"payload");
    check_eq!(Record::from_parts(record.parts(), record.digest())?, record);
    ensure!(matches!(
        Record::from_parts(parts, record.digest()),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn record_restore_rejects_each_changed_semantic_field() -> Result<()> {
    let pair = Pair::new()?;
    let mut parts = pair.publish(11, b"payload")?.parts();
    parts.event_ref = Some(EventRef::new(pair.publisher_id, "events", "one")?);
    let record = Record::new(parts)?;
    let mut changed = Vec::new();
    let mut parts = record.parts();
    parts.stream.publisher = pair.receiver_id;
    changed.push(parts);
    let mut parts = record.parts();
    parts.stream.id = StreamId::from_bytes([99; 16]);
    changed.push(parts);
    let mut parts = record.parts();
    parts.sequence += 1;
    changed.push(parts);
    let mut parts = record.parts();
    parts.publish_id = RequestId::from_bytes([99; 16]);
    changed.push(parts);
    let mut parts = record.parts();
    parts.event_type = EventType::new("changed")?;
    changed.push(parts);
    let mut parts = record.parts();
    parts.schema_revision = SchemaRevision::from_bytes([99; 32]);
    changed.push(parts);
    let mut parts = record.parts();
    parts.event_ref = None;
    changed.push(parts);
    let mut parts = record.parts();
    parts.event_ref = Some(EventRef::new(pair.receiver_id, "events", "one")?);
    changed.push(parts);
    let mut parts = record.parts();
    parts.event_ref = Some(EventRef::new(pair.publisher_id, "changed", "one")?);
    changed.push(parts);
    let mut parts = record.parts();
    parts.event_ref = Some(EventRef::new(pair.publisher_id, "events", "changed")?);
    changed.push(parts);
    let mut parts = record.parts();
    Arc::make_mut(&mut parts.payload)[0] = b'X';
    changed.push(parts);
    let mut parts = record.parts();
    parts.payload = Arc::from(&b"payload!"[..]);
    changed.push(parts);
    for parts in changed {
        check_eq!(
            Record::from_parts(parts, record.digest()),
            Err(FederationError::Conflict)
        );
    }
    let mut parts = record.parts();
    parts.sequence = 0;
    ensure!(matches!(
        Record::from_parts(parts, record.digest()),
        Err(FederationError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn gaps_conflicts_and_revocation_do_not_advance() -> Result<()> {
    let pair = Pair::new()?;
    pair.open()?;
    let first = pair.publish(11, b"a")?;
    let second = pair.publish(12, b"b")?;
    check_eq!(
        pair.receiver.accept(AcceptRequest {
            authenticated_publisher: pair.publisher_id,
            subscription: pair.subscription,
            record: second.clone(),
        }),
        Err(FederationError::Gap {
            expected: 1,
            received: 2
        })
    );
    let bad_position = Position::new(first.sequence(), Digest::from_bytes([7; 48]))?;
    check_eq!(
        pair.publisher.acknowledge(AcknowledgeRequest {
            authenticated_subscriber: pair.receiver_id,
            subscription: pair.subscription,
            position: bad_position,
        }),
        Err(FederationError::Conflict)
    );
    check_eq!(
        Record::from_parts(first.parts(), Digest::from_bytes([6; 48])),
        Err(FederationError::Conflict)
    );
    pair.receiver.accept(AcceptRequest {
        authenticated_publisher: pair.publisher_id,
        subscription: pair.subscription,
        record: first,
    })?;
    pair.receiver
        .set_peer_authority(pair.publisher_id, Some(1), false)?;
    check_eq!(
        pair.receiver.accept(AcceptRequest {
            authenticated_publisher: pair.publisher_id,
            subscription: pair.subscription,
            record: second,
        }),
        Err(FederationError::Unauthorized)
    );
    Ok(())
}

#[test]
fn limits_and_open_request_identity_are_enforced() -> Result<()> {
    let pair = Pair::new()?;
    let opened = pair.open()?;
    check_eq!(opened.export, pair.export);
    check_eq!(
        pair.publisher.open(OpenRequest {
            authenticated_subscriber: pair.receiver_id,
            request_id: opened.request_id,
            subscription: SubscriptionRef {
                subscriber: pair.receiver_id,
                id: SubscriptionId::from_bytes([8; 16]),
            },
            stream: pair.stream,
            expected_control_revision: Some(0),
            history: HistoryStart::All,
        }),
        Err(FederationError::Conflict)
    );
    pair.publish(11, b"record")?;
    check_eq!(
        pair.publisher.read(ReadRequest {
            authenticated_subscriber: pair.receiver_id,
            subscription: pair.subscription,
            after: None,
            max_records: 257,
            max_bytes: 1,
        }),
        Err(FederationError::Capacity)
    );
    check_eq!(
        pair.publisher.read(ReadRequest {
            authenticated_subscriber: pair.receiver_id,
            subscription: pair.subscription,
            after: None,
            max_records: 1,
            max_bytes: 2,
        }),
        Err(FederationError::Capacity)
    );
    Ok(())
}

#[test]
fn from_now_keeps_history_out_of_read_and_receiver_cursors_then_close_survives_replay() -> Result<()>
{
    let pair = Pair::new()?;
    let old = pair.publish(31, b"old")?;
    let baseline = pair.publish(32, b"baseline")?;
    let opened = pair.publisher.open(OpenRequest {
        authenticated_subscriber: pair.receiver_id,
        request_id: RequestId::from_bytes([33; 16]),
        subscription: pair.subscription,
        stream: pair.stream,
        expected_control_revision: Some(0),
        history: HistoryStart::FromNow,
    })?;
    check_eq!(opened.start, Some(baseline.position()));
    pair.receiver
        .install_subscription(InstallSubscriptionRequest {
            authenticated_publisher: pair.publisher_id,
            opened: opened.clone(),
        })?;
    let read = |after| {
        pair.publisher.read(ReadRequest {
            authenticated_subscriber: pair.receiver_id,
            subscription: pair.subscription,
            after,
            max_records: 8,
            max_bytes: 128,
        })
    };
    check_eq!(read(None)?.records, vec![]);
    check_eq!(
        read(Some(old.position())),
        Err(FederationError::Unauthorized)
    );
    check_eq!(
        pair.receiver.accept(AcceptRequest {
            authenticated_publisher: pair.publisher_id,
            subscription: pair.subscription,
            record: baseline.clone(),
        }),
        Err(FederationError::Conflict)
    );
    let next = pair.publish(34, b"new")?;
    check_eq!(read(None)?.records, vec![next.clone()]);
    pair.receiver.accept(AcceptRequest {
        authenticated_publisher: pair.publisher_id,
        subscription: pair.subscription,
        record: next.clone(),
    })?;
    check_eq!(
        pair.receiver
            .record_projection_progress(ProjectionProgress {
                subscription: pair.subscription,
                position: next.position(),
            })?,
        next.position()
    );
    pair.publisher.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: pair.receiver_id,
        subscription: pair.subscription,
        position: next.position(),
    })?;
    let inspect = || {
        pair.publisher
            .inspect_subscription(InspectSubscriptionRequest {
                authenticated_subscriber: pair.receiver_id,
                subscription: pair.subscription,
            })
    };
    let before = inspect()?;
    check_eq!(before.start, Some(baseline.position()));
    check_eq!(before.acknowledged, Some(next.position()));
    ensure!(!before.closed);
    let close = CloseSubscriptionRequest {
        authenticated_subscriber: pair.receiver_id,
        request_id: RequestId::from_bytes([35; 16]),
        subscription: pair.subscription,
        expected_subscription_revision: Some(opened.subscription_revision),
    };
    let closed = pair.publisher.close_subscription(close)?;
    check_eq!(pair.publisher.close_subscription(close)?, closed);
    ensure!(inspect()?.closed);
    check_eq!(read(None), Err(FederationError::Conflict));
    Ok(())
}

#[test]
fn ml_dsa_root_fingerprint_and_signature_are_purpose_bound() -> Result<()> {
    let key = FederationRootKey::generate()?;
    let root = key.root()?;
    let encoded = root.encode();
    let restored = FederationRoot::decode(&encoded)?;
    let node = root.node_id();
    check_eq!(restored.node_id(), node);
    ensure!(node.matches_root(&restored));
    check_eq!(FederationNodeId::from_bytes(*node.as_bytes()), node);

    let signature = key.sign(RootSignaturePurpose::NodeDescription, b"description")?;
    root.verify(
        RootSignaturePurpose::NodeDescription,
        b"description",
        &signature,
    )?;
    check_eq!(
        root.verify(
            RootSignaturePurpose::OnlineKeyAuthorization,
            b"description",
            &signature
        ),
        Err(FederationIdentityError::InvalidSignature)
    );
    check_eq!(
        root.verify(RootSignaturePurpose::NodeDescription, b"other", &signature),
        Err(FederationIdentityError::InvalidSignature)
    );
    let other = FederationRootKey::generate()?.root()?;
    check_eq!(
        other.verify(
            RootSignaturePurpose::NodeDescription,
            b"description",
            &signature
        ),
        Err(FederationIdentityError::InvalidSignature)
    );

    let saved = key.to_pkcs8()?;
    let reopened = FederationRootKey::from_pkcs8(saved.as_ref())?;
    check_eq!(reopened.root()?.node_id(), node);
    Ok(())
}

#[test]
fn root_descriptor_rejects_classical_and_noncanonical_profiles() -> Result<()> {
    let root = FederationRootKey::generate()?.root()?;
    let encoded = root.encode();
    check_eq!(
        FederationRoot::decode(&encoded[..encoded.len() - 1]).err(),
        Some(FederationIdentityError::InvalidRootDescriptor)
    );
    let prefix_len = b"xolotl.federation.root.v1\0".len();
    let mut classic = encoded.clone();
    classic[prefix_len + 1] = 2;
    check_eq!(
        FederationRoot::decode(&classic).err(),
        Some(FederationIdentityError::UnsupportedSignatureAlgorithm)
    );
    let mut different_mode = encoded.clone();
    different_mode[prefix_len + 3] = 2;
    check_eq!(
        FederationRoot::decode(&different_mode).err(),
        Some(FederationIdentityError::UnsupportedSignatureAlgorithm)
    );
    let mut wrong_len = encoded;
    wrong_len[prefix_len + 5] = 0;
    check_eq!(
        FederationRoot::decode(&wrong_len).err(),
        Some(FederationIdentityError::InvalidRootDescriptor)
    );
    Ok(())
}

#[test]
fn root_authorizes_online_key_for_one_fresh_channel() -> Result<()> {
    let root_key = FederationRootKey::generate()?;
    let root = root_key.root()?;
    let peer = root.node_id();
    let local = FederationNodeId::from_bytes([7; 48]);
    let online_key = FederationOnlineKey::generate()?;
    let authorization =
        FederationOnlineKeyAuthorization::new(online_key.public_key(), 3, 100, 200)?;
    let saved = authorization.encode();
    let authorization = FederationOnlineKeyAuthorization::decode(&saved)?;
    let root_signature = root_key.sign(RootSignaturePurpose::OnlineKeyAuthorization, &saved)?;
    let transcript =
        FederationSessionTranscript::new(local, peer, [1; 32], [2; 32], [3; 48], [4; 48])?;
    let online_signature = online_key.sign_session(peer, &authorization, &transcript)?;
    let verified = verify_federation_peer_proof(
        &root,
        peer,
        &authorization,
        &root_signature,
        &transcript,
        &online_signature,
        150,
    )?;
    check_eq!(verified.node_id(), peer);
    check_eq!(verified.online_generation(), 3);

    let changed_exporter =
        FederationSessionTranscript::new(local, peer, [1; 32], [2; 32], [9; 48], [4; 48])?;
    check_eq!(
        verify_federation_peer_proof(
            &root,
            peer,
            &authorization,
            &root_signature,
            &changed_exporter,
            &online_signature,
            150,
        ),
        Err(FederationIdentityError::InvalidSignature)
    );
    check_eq!(
        verify_federation_peer_proof(
            &root,
            peer,
            &authorization,
            &root_signature,
            &transcript,
            &online_signature,
            200,
        ),
        Err(FederationIdentityError::OnlineKeyOutsideValidity)
    );
    check_eq!(
        verify_federation_peer_proof(
            &root,
            local,
            &authorization,
            &root_signature,
            &transcript,
            &online_signature,
            150,
        ),
        Err(FederationIdentityError::PeerMismatch)
    );
    let wrong_root_signature = root_key.sign(RootSignaturePurpose::NodeDescription, &saved)?;
    check_eq!(
        verify_federation_peer_proof(
            &root,
            peer,
            &authorization,
            &wrong_root_signature,
            &transcript,
            &online_signature,
            150,
        ),
        Err(FederationIdentityError::InvalidSignature)
    );
    Ok(())
}
