#![cfg(feature = "federation")]

use std::sync::Arc;

use anyhow::{Result, ensure};
use xolotl_federation::{
    AcceptRequest, AcknowledgeRequest, CloseSubscriptionRequest, Digest, EventType, ExportAccess,
    ExportName, FederationError, FederationNodeId, FederationOnlineKey,
    FederationOnlineKeyAuthorization, FederationRootKey, FederationSessionTranscript,
    FederationStore, HistoryStart, InboxReadRequest, InspectSubscriptionRequest,
    InstallSubscriptionRequest, OpenRequest, PeerAdmission, Position, ProjectionProgress,
    PublishRequest, ReadRequest, RequestId, RootSignaturePurpose, SchemaRevision, StreamId,
    StreamRef, StreamSpec, SubscriptionId, SubscriptionRef, VerifiedFederationPeerProof,
    verify_federation_peer_proof,
};
use xolotl_storage_redb::RedbStore;

fn publish(
    store: &impl FederationStore,
    stream: StreamRef,
    id: u8,
    bytes: &'static [u8],
) -> std::result::Result<xolotl_federation::Record, FederationError> {
    store.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([id; 16]),
        event_type: EventType::new("note.created")?,
        schema_revision: SchemaRevision::from_bytes([9; 32]),
        event_ref: None,
        payload: Arc::from(bytes),
    })
}

#[test]
fn history_baseline_and_closed_receipt_survive_publisher_and_receiver_restart() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let publisher_path = directory.path().join("publisher-history.redb");
    let receiver_path = directory.path().join("receiver-history.redb");
    let publisher_id = FederationNodeId::from_bytes([81; 48]);
    let receiver_id = FederationNodeId::from_bytes([82; 48]);
    let export = ExportName::new("private-history")?;
    let stream = StreamRef {
        publisher: publisher_id,
        id: StreamId::from_bytes([83; 16]),
    };
    let subscription = SubscriptionRef {
        subscriber: receiver_id,
        id: SubscriptionId::from_bytes([84; 16]),
    };
    let publisher_db = RedbStore::open(&publisher_path)?;
    let receiver_db = RedbStore::open(&receiver_path)?;
    let publisher = publisher_db.federation_store(publisher_id)?;
    let receiver = receiver_db.federation_store(receiver_id)?;
    publisher.set_peer_authority(receiver_id, None, true)?;
    receiver.set_peer_authority(publisher_id, None, true)?;
    publisher.set_export_authority(
        receiver_id,
        export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    receiver.set_export_authority(
        publisher_id,
        export.clone(),
        None,
        ExportAccess {
            serve: false,
            receive: true,
        },
    )?;
    publisher.declare_stream(StreamSpec { stream, export })?;
    let old = publish(&publisher, stream, 85, b"private old")?;
    let request = OpenRequest {
        authenticated_subscriber: receiver_id,
        request_id: RequestId::from_bytes([86; 16]),
        subscription,
        stream,
        expected_control_revision: Some(0),
        history: HistoryStart::FromNow,
    };
    let opened = publisher.open(request.clone())?;
    ensure!(opened.start == Some(old.position()));
    receiver.install_subscription(InstallSubscriptionRequest {
        authenticated_publisher: publisher_id,
        opened: opened.clone(),
    })?;
    let next = publish(&publisher, stream, 87, b"new")?;
    drop(publisher);
    drop(receiver);
    drop(publisher_db);
    drop(receiver_db);

    let publisher_db = RedbStore::open(&publisher_path)?;
    let receiver_db = RedbStore::open(&receiver_path)?;
    let publisher = publisher_db.federation_store(publisher_id)?;
    let receiver = receiver_db.federation_store(receiver_id)?;
    ensure!(publisher.open(request)? == opened);
    let page = publisher.read(ReadRequest {
        authenticated_subscriber: receiver_id,
        subscription,
        after: None,
        max_records: 8,
        max_bytes: 1024,
    })?;
    ensure!(page.records == vec![next.clone()] && page.minimum_available == 2);
    ensure!(
        publisher
            .read(ReadRequest {
                authenticated_subscriber: receiver_id,
                subscription,
                after: Some(Position::new(1, old.digest())?),
                max_records: 1,
                max_bytes: 1024,
            })
            .is_ok()
    );
    ensure!(matches!(
        receiver.accept(AcceptRequest {
            authenticated_publisher: publisher_id,
            subscription,
            record: old,
        }),
        Err(FederationError::Conflict)
    ));
    let accepted = receiver.accept(AcceptRequest {
        authenticated_publisher: publisher_id,
        subscription,
        record: next.clone(),
    })?;
    ensure!(accepted.position == next.position());
    publisher.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: receiver_id,
        subscription,
        position: next.position(),
    })?;
    let close = CloseSubscriptionRequest {
        authenticated_subscriber: receiver_id,
        request_id: RequestId::from_bytes([88; 16]),
        subscription,
        expected_subscription_revision: Some(opened.subscription_revision),
    };
    let closed = publisher.close_subscription(close)?;
    drop(publisher);
    drop(receiver);
    drop(publisher_db);
    drop(receiver_db);

    let publisher_db = RedbStore::open(&publisher_path)?;
    let publisher = publisher_db.federation_store(publisher_id)?;
    ensure!(publisher.close_subscription(close)? == closed);
    let inspected = publisher.inspect_subscription(InspectSubscriptionRequest {
        authenticated_subscriber: receiver_id,
        subscription,
    })?;
    ensure!(inspected.closed && inspected.start == opened.start);
    ensure!(inspected.acknowledged == Some(next.position()));
    ensure!(matches!(
        publisher.read(ReadRequest {
            authenticated_subscriber: receiver_id,
            subscription,
            after: None,
            max_records: 1,
            max_bytes: 1024,
        }),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn records_cursors_and_replay_survive_both_node_restarts() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let publisher_path = directory.path().join("publisher.redb");
    let receiver_path = directory.path().join("receiver.redb");
    let publisher_id = FederationNodeId::from_bytes([1; 48]);
    let receiver_id = FederationNodeId::from_bytes([2; 48]);
    let export = ExportName::new("notes")?;
    let stream = StreamRef {
        publisher: publisher_id,
        id: StreamId::from_bytes([3; 16]),
    };
    let subscription = SubscriptionRef {
        subscriber: receiver_id,
        id: SubscriptionId::from_bytes([4; 16]),
    };
    let open_request = OpenRequest {
        authenticated_subscriber: receiver_id,
        request_id: RequestId::from_bytes([5; 16]),
        subscription,
        stream,
        expected_control_revision: Some(0),
        history: HistoryStart::All,
    };

    let publisher_db = RedbStore::open(&publisher_path)?;
    let receiver_db = RedbStore::open(&receiver_path)?;
    let publisher = publisher_db.federation_store(publisher_id)?;
    let receiver = receiver_db.federation_store(receiver_id)?;
    ensure!(publisher.local_node() == publisher_id);
    ensure!(receiver.local_node() == receiver_id);
    ensure!(publisher.set_peer_authority(receiver_id, None, true)? == 1);
    ensure!(
        publisher.set_export_authority(
            receiver_id,
            export.clone(),
            None,
            ExportAccess {
                serve: true,
                receive: false,
            }
        )? == 1
    );
    ensure!(receiver.set_peer_authority(publisher_id, None, true)? == 1);
    ensure!(
        receiver.set_export_authority(
            publisher_id,
            export.clone(),
            None,
            ExportAccess {
                serve: false,
                receive: true,
            }
        )? == 1
    );
    publisher.declare_stream(StreamSpec { stream, export })?;
    let opened = publisher.open(open_request.clone())?;
    ensure!(
        receiver.install_subscription(InstallSubscriptionRequest {
            authenticated_publisher: publisher_id,
            opened: opened.clone(),
        })? == opened
    );
    let first = publish(&publisher, stream, 11, b"first")?;
    let second = publish(&publisher, stream, 12, b"second")?;
    ensure!(first.sequence() == 1 && second.sequence() == 2);
    let accepted = receiver.accept(AcceptRequest {
        authenticated_publisher: publisher_id,
        subscription,
        record: first.clone(),
    })?;
    ensure!(accepted.newly_accepted && accepted.position == first.position());
    let inbox_request = InboxReadRequest {
        subscription,
        expected_stream: stream,
        after: None,
        max_records: 1,
        max_bytes: 64,
    };
    let inbox = receiver.read_inbox(inbox_request)?;
    ensure!(inbox.opened == opened && inbox.records == vec![first.clone()]);
    ensure!(inbox.received == Some(first.position()) && inbox.projected.is_none());
    ensure!(matches!(
        receiver.read_inbox(InboxReadRequest {
            max_bytes: 1,
            ..inbox_request
        }),
        Err(FederationError::Capacity)
    ));
    ensure!(matches!(
        receiver.read_inbox(InboxReadRequest {
            after: Some(Position::new(1, Digest::from_bytes([99; 48]))?),
            ..inbox_request
        }),
        Err(FederationError::Conflict)
    ));
    ensure!(
        publisher.acknowledge(AcknowledgeRequest {
            authenticated_subscriber: receiver_id,
            subscription,
            position: first.position(),
        })? == first.position()
    );
    ensure!(
        receiver.record_projection_progress(ProjectionProgress {
            subscription,
            position: first.position(),
        })? == first.position()
    );
    drop(publisher);
    drop(receiver);
    drop(publisher_db);
    drop(receiver_db);

    let publisher_db = RedbStore::open(&publisher_path)?;
    let receiver_db = RedbStore::open(&receiver_path)?;
    ensure!(matches!(
        publisher_db.federation_store(receiver_id),
        Err(FederationError::Conflict)
    ));
    let publisher = publisher_db.federation_store(publisher_id)?;
    let receiver = receiver_db.federation_store(receiver_id)?;
    let restored_inbox = receiver.read_inbox(inbox_request)?;
    ensure!(restored_inbox.records == vec![first.clone()]);
    ensure!(restored_inbox.projected == Some(first.position()));
    ensure!(publisher.open(open_request)? == opened);
    ensure!(
        receiver.install_subscription(InstallSubscriptionRequest {
            authenticated_publisher: publisher_id,
            opened: opened.clone(),
        })? == opened
    );
    ensure!(publish(&publisher, stream, 11, b"first")? == first);
    ensure!(matches!(
        publish(&publisher, stream, 11, b"changed"),
        Err(FederationError::Conflict)
    ));
    let page = publisher.read(ReadRequest {
        authenticated_subscriber: receiver_id,
        subscription,
        after: Some(first.position()),
        max_records: 1,
        max_bytes: 64,
    })?;
    ensure!(page.records == vec![second.clone()]);
    ensure!(page.head == Some(second.position()) && page.minimum_available == 1);
    let repeated = receiver.accept(AcceptRequest {
        authenticated_publisher: publisher_id,
        subscription,
        record: first.clone(),
    })?;
    ensure!(!repeated.newly_accepted && repeated.position == first.position());
    ensure!(
        publisher.acknowledge(AcknowledgeRequest {
            authenticated_subscriber: receiver_id,
            subscription,
            position: first.position(),
        })? == first.position()
    );
    let next = receiver.accept(AcceptRequest {
        authenticated_publisher: publisher_id,
        subscription,
        record: second.clone(),
    })?;
    ensure!(next.newly_accepted && next.position == second.position());
    let pending_projection = receiver.read_inbox(InboxReadRequest {
        after: Some(first.position()),
        ..inbox_request
    })?;
    ensure!(pending_projection.records == vec![second.clone()]);
    ensure!(pending_projection.projected == Some(first.position()));
    ensure!(
        receiver.record_projection_progress(ProjectionProgress {
            subscription,
            position: second.position(),
        })? == second.position()
    );
    ensure!(publish(&publisher, stream, 13, b"third")?.sequence() == 3);
    Ok(())
}

#[test]
fn conflicts_gaps_and_authority_changes_do_not_advance_cursors() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let publisher_id = FederationNodeId::from_bytes([21; 48]);
    let receiver_id = FederationNodeId::from_bytes([22; 48]);
    let publisher_db = RedbStore::open(directory.path().join("publisher.redb"))?;
    let receiver_db = RedbStore::open(directory.path().join("receiver.redb"))?;
    let publisher = publisher_db.federation_store(publisher_id)?;
    let receiver = receiver_db.federation_store(receiver_id)?;
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
        id: StreamId::from_bytes([23; 16]),
    };
    let subscription = SubscriptionRef {
        subscriber: receiver_id,
        id: SubscriptionId::from_bytes([24; 16]),
    };
    publisher.declare_stream(StreamSpec {
        stream,
        export: export.clone(),
    })?;
    let request = OpenRequest {
        authenticated_subscriber: receiver_id,
        request_id: RequestId::from_bytes([25; 16]),
        subscription,
        stream,
        expected_control_revision: Some(0),
        history: HistoryStart::All,
    };
    let opened = publisher.open(request.clone())?;
    receiver.install_subscription(InstallSubscriptionRequest {
        authenticated_publisher: publisher_id,
        opened,
    })?;
    ensure!(matches!(
        publisher.open(OpenRequest {
            stream: StreamRef {
                publisher: publisher_id,
                id: StreamId::from_bytes([26; 16]),
            },
            ..request
        }),
        Err(FederationError::NotFound | FederationError::Conflict)
    ));
    let first = publish(&publisher, stream, 31, b"first")?;
    let second = publish(&publisher, stream, 32, b"second")?;
    let invalid_position = Position::new(1, Digest::from_bytes([7; 48]))?;
    ensure!(matches!(
        publisher.read(ReadRequest {
            authenticated_subscriber: receiver_id,
            subscription,
            after: Some(invalid_position),
            max_records: 1,
            max_bytes: 64,
        }),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.accept(AcceptRequest {
            authenticated_publisher: publisher_id,
            subscription,
            record: second.clone(),
        }),
        Err(FederationError::Gap {
            expected: 1,
            received: 2
        })
    ));
    ensure!(matches!(
        publisher.acknowledge(AcknowledgeRequest {
            authenticated_subscriber: receiver_id,
            subscription,
            position: invalid_position,
        }),
        Err(FederationError::Conflict)
    ));
    let first_accept = receiver.accept(AcceptRequest {
        authenticated_publisher: publisher_id,
        subscription,
        record: first.clone(),
    })?;
    ensure!(first_accept.newly_accepted && first_accept.position == first.position());
    let mut conflicting = first.parts();
    conflicting.payload = Arc::from(b"changed".as_slice());
    let conflicting = xolotl_federation::Record::new(conflicting)?;
    ensure!(matches!(
        receiver.accept(AcceptRequest {
            authenticated_publisher: publisher_id,
            subscription,
            record: conflicting,
        }),
        Err(FederationError::Conflict)
    ));
    ensure!(
        receiver
            .accept(AcceptRequest {
                authenticated_publisher: publisher_id,
                subscription,
                record: first.clone(),
            })?
            .position
            == first.position()
    );
    ensure!(
        receiver
            .accept(AcceptRequest {
                authenticated_publisher: publisher_id,
                subscription,
                record: second.clone(),
            })?
            .position
            == second.position()
    );
    ensure!(matches!(
        receiver.record_projection_progress(ProjectionProgress {
            subscription,
            position: second.position(),
        }),
        Err(FederationError::Gap {
            expected: 1,
            received: 2
        })
    ));
    publisher.set_export_authority(
        receiver_id,
        export,
        Some(1),
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    ensure!(matches!(
        publisher.read(ReadRequest {
            authenticated_subscriber: receiver_id,
            subscription,
            after: None,
            max_records: 1,
            max_bytes: 64,
        }),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        publisher.acknowledge(AcknowledgeRequest {
            authenticated_subscriber: receiver_id,
            subscription,
            position: first.position(),
        }),
        Err(FederationError::Conflict)
    ));
    receiver.set_peer_authority(publisher_id, Some(1), false)?;
    ensure!(matches!(
        receiver.accept(AcceptRequest {
            authenticated_publisher: publisher_id,
            subscription,
            record: second,
        }),
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}

#[test]
fn concurrent_authority_compare_and_set_has_one_winner() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open(directory.path().join("federation.redb"))?;
    let local = FederationNodeId::from_bytes([41; 48]);
    let peer = FederationNodeId::from_bytes([42; 48]);
    let store = db.federation_store(local)?;
    ensure!(store.set_peer_authority(peer, None, true)? == 1);
    let mut joins = Vec::new();
    for _ in 0..8 {
        let store = store.clone();
        joins.push(std::thread::spawn(move || {
            store.set_peer_authority(peer, Some(1), false)
        }));
    }
    let mut winners = 0;
    for join in joins {
        match join
            .join()
            .map_err(|_panic| anyhow::anyhow!("authority worker panicked"))?
        {
            Ok(2) => winners += 1,
            Err(FederationError::Conflict) => {}
            outcome => anyhow::bail!("unexpected compare-and-set result: {outcome:?}"),
        }
    }
    ensure!(winners == 1);
    ensure!(store.set_peer_authority(peer, Some(2), true)? == 3);
    Ok(())
}

fn verified_peer(
    root_key: &FederationRootKey,
    local: FederationNodeId,
    generation: u64,
    expires_ms: u64,
) -> Result<VerifiedFederationPeerProof> {
    let root = root_key.root()?;
    let peer = root.node_id();
    let online_key = FederationOnlineKey::generate()?;
    let authorization = FederationOnlineKeyAuthorization::new(
        online_key.public_key(),
        generation,
        100,
        expires_ms,
    )?;
    let authorization_bytes = authorization.encode();
    let root_signature = root_key.sign(
        RootSignaturePurpose::OnlineKeyAuthorization,
        &authorization_bytes,
    )?;
    let transcript =
        FederationSessionTranscript::new(local, peer, [1; 32], [2; 32], [3; 48], [4; 48])?;
    let online_signature = online_key.sign_session(peer, &authorization, &transcript)?;
    Ok(verify_federation_peer_proof(
        &root,
        peer,
        &authorization,
        &root_signature,
        &transcript,
        &online_signature,
        150,
    )?)
}

#[test]
fn peer_admission_is_persistent_exact_and_revocable_without_changing_export_authority() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("federation.redb");
    let local = FederationNodeId::from_bytes([71; 48]);
    let root_key = FederationRootKey::generate()?;
    let peer = root_key.root()?.node_id();
    let first = verified_peer(&root_key, local, 1, 300)?;
    let second = verified_peer(&root_key, local, 2, 300)?;
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(local)?;

    ensure!(store.checked_time_ms(150)? == 150);
    ensure!(matches!(
        store.check_peer_admission(first, 150),
        Err(FederationError::Unauthorized)
    ));
    ensure!(store.set_peer_authority(peer, None, true)? == 1);
    ensure!(matches!(
        store.check_peer_admission(first, 150),
        Err(FederationError::Unauthorized)
    ));
    let original = PeerAdmission {
        minimum_online_generation: 1,
        allowed_authorization_digests: vec![first.authorization_digest()],
    };
    ensure!(store.set_peer_admission(peer, None, original.clone())? == 1);
    ensure!(store.peer_admission(peer)? == Some((1, original.clone())));
    store.check_peer_admission(first, 150)?;
    let export = ExportName::new("notes")?;
    ensure!(
        store.set_export_authority(
            peer,
            export.clone(),
            None,
            ExportAccess {
                serve: true,
                receive: false,
            }
        )? == 1
    );
    let stream = StreamRef {
        publisher: local,
        id: StreamId::from_bytes([72; 16]),
    };
    let subscription = SubscriptionRef {
        subscriber: peer,
        id: SubscriptionId::from_bytes([73; 16]),
    };
    store.declare_stream(StreamSpec { stream, export })?;
    let opened = store.open(OpenRequest {
        authenticated_subscriber: peer,
        request_id: RequestId::from_bytes([74; 16]),
        subscription,
        stream,
        expected_control_revision: Some(0),
        history: HistoryStart::All,
    })?;
    let record = publish(&store, stream, 75, b"still available after key rotation")?;
    ensure!(opened.publisher_authority.peer == 1);
    ensure!(matches!(
        store.check_peer_admission(second, 150),
        Err(FederationError::Unauthorized)
    ));
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(local)?;
    store.check_peer_admission(first, 150)?;
    let overlap = PeerAdmission {
        minimum_online_generation: 1,
        allowed_authorization_digests: vec![
            first.authorization_digest(),
            second.authorization_digest(),
        ],
    };
    ensure!(store.set_peer_admission(peer, Some(1), overlap)? == 2);
    store.check_peer_admission(first, 150)?;
    store.check_peer_admission(second, 150)?;
    ensure!(matches!(
        store.set_peer_admission(peer, Some(1), original.clone()),
        Err(FederationError::Conflict)
    ));
    let rotated = PeerAdmission {
        minimum_online_generation: 2,
        allowed_authorization_digests: vec![second.authorization_digest()],
    };
    ensure!(store.set_peer_admission(peer, Some(2), rotated.clone())? == 3);
    ensure!(store.peer_admission(peer)? == Some((3, rotated)));
    ensure!(
        store
            .read(ReadRequest {
                authenticated_subscriber: peer,
                subscription,
                after: None,
                max_records: 1,
                max_bytes: 128,
            })?
            .records
            == vec![record]
    );
    ensure!(matches!(
        store.check_peer_admission(first, 150),
        Err(FederationError::Unauthorized)
    ));
    store.check_peer_admission(second, 150)?;
    ensure!(matches!(
        store.set_peer_admission(peer, Some(3), original),
        Err(FederationError::Conflict)
    ));

    ensure!(store.set_peer_authority(peer, Some(1), false)? == 2);
    ensure!(matches!(
        store.check_peer_admission(second, 150),
        Err(FederationError::Unauthorized)
    ));
    ensure!(store.set_peer_authority(peer, Some(2), true)? == 3);
    store.check_peer_admission(second, 150)?;
    ensure!(store.checked_time_ms(151)? == 151);
    ensure!(matches!(
        store.checked_time_ms(150),
        Err(FederationError::ClockRollback)
    ));
    ensure!(matches!(
        store.check_peer_admission(second, 150),
        Err(FederationError::ClockRollback)
    ));
    drop(store);
    drop(db);

    let db = RedbStore::open(&path)?;
    let store = db.federation_store(local)?;
    ensure!(matches!(
        store.checked_time_ms(150),
        Err(FederationError::ClockRollback)
    ));
    store.check_peer_admission(second, store.checked_time_ms(151)?)?;
    ensure!(store.checked_time_ms(300)? == 300);
    ensure!(matches!(
        store.check_peer_admission(second, 300),
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}
