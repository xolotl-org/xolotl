#![cfg(feature = "federation")]

use std::sync::Arc;

use anyhow::{Result, ensure};
use xolotl_federation::{
    AcceptRequest, Digest, EventType, ExportAccess, ExportName, FederationError, FederationNodeId,
    FederationPublicReadStore, FederationStore, HistoryStart, InboxReadRequest,
    InstallSubscriptionRequest, MAX_RETIRE_BYTES, MemoryFederationStore, OpenRequest,
    ProjectionProgress, PublicReadRequest, PublicStreamPolicy, PublishRequest, ReadRequest,
    RequestId, SchemaRevision, StreamId, StreamRef, StreamSpec, SubscriptionId, SubscriptionRef,
};
use xolotl_storage_redb::RedbStore;

const PUBLISHER: FederationNodeId = FederationNodeId::from_bytes([91; 48]);
const RECEIVER: FederationNodeId = FederationNodeId::from_bytes([92; 48]);
const PUBLIC_READER: FederationNodeId = FederationNodeId::from_bytes([96; 48]);
const STREAM: StreamRef = StreamRef {
    publisher: PUBLISHER,
    id: StreamId::from_bytes([93; 16]),
};
const SUBSCRIPTION: SubscriptionRef = SubscriptionRef {
    subscriber: RECEIVER,
    id: SubscriptionId::from_bytes([94; 16]),
};

fn publish(store: &impl FederationStore, id: u8) -> Result<xolotl_federation::Record> {
    Ok(store.append_published(PublishRequest {
        retry_epoch: 1,
        stream: STREAM,
        publish_id: RequestId::from_bytes([id; 16]),
        event_type: EventType::new("note")?,
        schema_revision: SchemaRevision::from_bytes([95; 32]),
        event_ref: None,
        payload: Arc::from([id].as_slice()),
    })?)
}

fn publisher_read(after: Option<xolotl_federation::Position>) -> ReadRequest {
    ReadRequest {
        authenticated_subscriber: RECEIVER,
        subscription: SUBSCRIPTION,
        after,
        max_records: 8,
        max_bytes: 1024,
    }
}

fn inbox_read(after: Option<xolotl_federation::Position>) -> InboxReadRequest {
    InboxReadRequest {
        subscription: SUBSCRIPTION,
        expected_stream: STREAM,
        after,
        max_records: 8,
        max_bytes: 1024,
    }
}

fn exercise(
    publisher: &(impl FederationStore + FederationPublicReadStore),
    receiver: &impl FederationStore,
) -> Result<(xolotl_federation::Record, xolotl_federation::Record)> {
    let export = ExportName::new("notes")?;
    publisher.set_peer_authority(RECEIVER, None, true)?;
    receiver.set_peer_authority(PUBLISHER, None, true)?;
    publisher.set_export_authority(
        RECEIVER,
        export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    receiver.set_export_authority(
        PUBLISHER,
        export.clone(),
        None,
        ExportAccess {
            serve: false,
            receive: true,
        },
    )?;
    publisher.declare_stream(StreamSpec {
        stream: STREAM,
        export,
    })?;
    let public = publisher.set_public_stream_policy(
        None,
        PublicStreamPolicy {
            stream: STREAM,
            enabled: true,
            max_read_records: 8,
            max_read_bytes: 1024,
        },
    )?;
    let first = publish(publisher, 1)?;
    let second = publish(publisher, 2)?;
    let third = publish(publisher, 3)?;
    let opened = publisher.open(OpenRequest {
        authenticated_subscriber: RECEIVER,
        request_id: RequestId::from_bytes([4; 16]),
        subscription: SUBSCRIPTION,
        stream: STREAM,
        expected_control_revision: Some(0),
        history: HistoryStart::All,
    })?;
    receiver.install_subscription(InstallSubscriptionRequest {
        authenticated_publisher: PUBLISHER,
        opened,
    })?;
    for record in [&first, &second, &third] {
        receiver.accept(AcceptRequest {
            authenticated_publisher: PUBLISHER,
            subscription: SUBSCRIPTION,
            record: record.clone(),
        })?;
    }
    receiver.record_projection_progress(ProjectionProgress {
        subscription: SUBSCRIPTION,
        position: first.position(),
    })?;
    let trimmed = receiver.retire_projected_inbox(SUBSCRIPTION, 1)?;
    ensure!(trimmed.removed == 1 && trimmed.retired_through == Some(first.position()));
    ensure!(receiver.read_inbox(inbox_read(None))?.records == vec![second.clone(), third.clone()]);
    ensure!(
        receiver
            .read_inbox(inbox_read(Some(first.position())))?
            .records
            == vec![second.clone(), third.clone()]
    );
    receiver.record_projection_progress(ProjectionProgress {
        subscription: SUBSCRIPTION,
        position: second.position(),
    })?;
    ensure!(
        receiver
            .retire_projected_inbox(SUBSCRIPTION, 1)?
            .retired_through
            == Some(second.position())
    );
    ensure!(receiver.read_inbox(inbox_read(None))?.records == vec![third.clone()]);
    ensure!(matches!(
        receiver.read_inbox(inbox_read(Some(first.position()))),
        Err(FederationError::ResyncRequired {
            minimum_available: 3
        })
    ));
    ensure!(
        receiver
            .read_inbox(inbox_read(Some(second.position())))?
            .records
            == vec![third.clone()]
    );
    ensure!(matches!(
        receiver.accept(AcceptRequest {
            authenticated_publisher: PUBLISHER,
            subscription: SUBSCRIPTION,
            record: first.clone(),
        }),
        Err(FederationError::Indeterminate)
    ));
    ensure!(receiver.retire_projected_inbox(SUBSCRIPTION, 1)?.removed == 0);

    ensure!(matches!(
        publisher.retire_published_history(STREAM, second.position(), 1),
        Err(FederationError::Capacity)
    ));
    let wrong = xolotl_federation::Position::new(second.sequence(), Digest::from_bytes([0; 48]))?;
    ensure!(matches!(
        publisher.retire_published_history(STREAM, wrong, 2),
        Err(FederationError::Conflict)
    ));
    let retired = publisher.retire_published_history(STREAM, second.position(), 2)?;
    ensure!(
        retired.removed == 2
            && retired.minimum_available == 3
            && retired.head == Some(third.position())
    );
    ensure!(
        publisher
            .retire_published_history(STREAM, second.position(), 2)?
            .removed
            == 0
    );
    ensure!(matches!(
        publisher.read(publisher_read(None)),
        Err(FederationError::ResyncRequired {
            minimum_available: 3
        })
    ));
    ensure!(matches!(
        publisher.read(publisher_read(Some(first.position()))),
        Err(FederationError::ResyncRequired {
            minimum_available: 3
        })
    ));
    ensure!(
        publisher
            .read(publisher_read(Some(second.position())))?
            .records
            == vec![third.clone()]
    );
    let replay = publisher.append_published(PublishRequest {
        retry_epoch: 1,
        stream: STREAM,
        publish_id: RequestId::from_bytes([1; 16]),
        event_type: EventType::new("note")?,
        schema_revision: SchemaRevision::from_bytes([95; 32]),
        event_ref: None,
        payload: Arc::from([1u8].as_slice()),
    });
    ensure!(matches!(replay, Err(FederationError::Indeterminate)));
    let public_page = publisher.read_public_stream(PublicReadRequest {
        authenticated_reader: PUBLIC_READER,
        stream: STREAM,
        expected_policy_revision: public.policy_revision,
        after: Some(second.position()),
        max_records: 8,
        max_bytes: 1024,
    })?;
    ensure!(public_page.records == vec![third.clone()] && public_page.minimum_available == 3);
    ensure!(matches!(
        publisher.read_public_stream(PublicReadRequest {
            after: Some(first.position()),
            ..PublicReadRequest {
                authenticated_reader: PUBLIC_READER,
                stream: STREAM,
                expected_policy_revision: public.policy_revision,
                after: None,
                max_records: 8,
                max_bytes: 1024,
            }
        }),
        Err(FederationError::ResyncRequired {
            minimum_available: 3
        })
    ));
    Ok((second, third))
}

#[test]
fn memory_retirement_preserves_unprojected_records_and_exact_cursor_anchor() -> Result<()> {
    let publisher = MemoryFederationStore::new(PUBLISHER);
    let receiver = MemoryFederationStore::new(RECEIVER);
    exercise(&publisher, &receiver)?;
    Ok(())
}

#[test]
fn redb_retirement_persists_both_anchors_across_reopen() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let publisher_path = directory.path().join("publisher.redb");
    let receiver_path = directory.path().join("receiver.redb");
    let publisher_db = RedbStore::open(&publisher_path)?;
    let receiver_db = RedbStore::open(&receiver_path)?;
    let publisher = publisher_db.federation_store(PUBLISHER)?;
    let receiver = receiver_db.federation_store(RECEIVER)?;
    let (anchor, unprojected) = exercise(&publisher, &receiver)?;
    drop(publisher);
    drop(receiver);
    drop(publisher_db);
    drop(receiver_db);
    let publisher = RedbStore::open(&publisher_path)?.federation_store(PUBLISHER)?;
    let receiver = RedbStore::open(&receiver_path)?.federation_store(RECEIVER)?;
    ensure!(
        publisher
            .read(publisher_read(Some(anchor.position())))?
            .records
            == vec![unprojected.clone()]
    );
    ensure!(receiver.read_inbox(inbox_read(None))?.records == vec![unprojected.clone()]);
    receiver.record_projection_progress(ProjectionProgress {
        subscription: SUBSCRIPTION,
        position: unprojected.position(),
    })?;
    ensure!(
        receiver
            .retire_projected_inbox(SUBSCRIPTION, 1)?
            .retired_through
            == Some(unprojected.position())
    );
    ensure!(receiver.read_inbox(inbox_read(None))?.records.is_empty());
    Ok(())
}

fn prepare(
    publisher: &impl FederationStore,
    receiver: &impl FederationStore,
    history: HistoryStart,
) -> Result<xolotl_federation::OpenResult> {
    let export = ExportName::new("notes")?;
    publisher.set_peer_authority(RECEIVER, None, true)?;
    receiver.set_peer_authority(PUBLISHER, None, true)?;
    publisher.set_export_authority(
        RECEIVER,
        export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    receiver.set_export_authority(
        PUBLISHER,
        export.clone(),
        None,
        ExportAccess {
            serve: false,
            receive: true,
        },
    )?;
    publisher.declare_stream(StreamSpec {
        stream: STREAM,
        export,
    })?;
    Ok(publisher.open(OpenRequest {
        authenticated_subscriber: RECEIVER,
        request_id: RequestId::from_bytes([101; 16]),
        subscription: SUBSCRIPTION,
        stream: STREAM,
        expected_control_revision: Some(0),
        history,
    })?)
}

fn exact_open_baseline(
    publisher: &impl FederationStore,
    receiver: &impl FederationStore,
) -> Result<()> {
    let export = ExportName::new("notes")?;
    publisher.set_peer_authority(RECEIVER, None, true)?;
    receiver.set_peer_authority(PUBLISHER, None, true)?;
    publisher.set_export_authority(
        RECEIVER,
        export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    receiver.set_export_authority(
        PUBLISHER,
        export.clone(),
        None,
        ExportAccess {
            serve: false,
            receive: true,
        },
    )?;
    publisher.declare_stream(StreamSpec {
        stream: STREAM,
        export,
    })?;
    let first = publish(publisher, 1)?;
    let opened = publisher.open(OpenRequest {
        authenticated_subscriber: RECEIVER,
        request_id: RequestId::from_bytes([101; 16]),
        subscription: SUBSCRIPTION,
        stream: STREAM,
        expected_control_revision: Some(0),
        history: HistoryStart::FromNow,
    })?;
    ensure!(opened.start == Some(first.position()));
    receiver.install_subscription(InstallSubscriptionRequest {
        authenticated_publisher: PUBLISHER,
        opened,
    })?;
    let wrong = xolotl_federation::Position::new(first.sequence(), Digest::from_bytes([0; 48]))?;
    ensure!(matches!(
        receiver.read_inbox(inbox_read(Some(wrong))),
        Err(FederationError::Conflict)
    ));
    ensure!(
        receiver
            .read_inbox(inbox_read(Some(first.position())))?
            .records
            .is_empty()
    );
    Ok(())
}

#[test]
fn open_baseline_requires_exact_digest_on_both_backends() -> Result<()> {
    exact_open_baseline(
        &MemoryFederationStore::new(PUBLISHER),
        &MemoryFederationStore::new(RECEIVER),
    )?;
    let directory = tempfile::tempdir()?;
    let publisher =
        RedbStore::open(directory.path().join("publisher.redb"))?.federation_store(PUBLISHER)?;
    let receiver =
        RedbStore::open(directory.path().join("receiver.redb"))?.federation_store(RECEIVER)?;
    exact_open_baseline(&publisher, &receiver)
}

fn byte_bound(publisher: &impl FederationStore, receiver: &impl FederationStore) -> Result<()> {
    let opened = prepare(publisher, receiver, HistoryStart::All)?;
    receiver.install_subscription(InstallSubscriptionRequest {
        authenticated_publisher: PUBLISHER,
        opened,
    })?;
    let large: Arc<[u8]> = Arc::from(vec![7; MAX_RETIRE_BYTES / 4]);
    let mut records = Vec::new();
    for id in 1..=5 {
        let payload = if id == 5 {
            Arc::from([8u8].as_slice())
        } else {
            large.clone()
        };
        let record = publisher.append_published(PublishRequest {
            retry_epoch: 1,
            stream: STREAM,
            publish_id: RequestId::from_bytes([id; 16]),
            event_type: EventType::new("note")?,
            schema_revision: SchemaRevision::from_bytes([95; 32]),
            event_ref: None,
            payload,
        })?;
        receiver.accept(AcceptRequest {
            authenticated_publisher: PUBLISHER,
            subscription: SUBSCRIPTION,
            record: record.clone(),
        })?;
        receiver.record_projection_progress(ProjectionProgress {
            subscription: SUBSCRIPTION,
            position: record.position(),
        })?;
        records.push(record);
    }
    ensure!(matches!(
        publisher.retire_published_history(STREAM, records[4].position(), 5),
        Err(FederationError::Capacity)
    ));
    let trimmed = receiver.retire_projected_inbox(SUBSCRIPTION, 5)?;
    ensure!(trimmed.removed == 4 && trimmed.retired_through == Some(records[3].position()));
    ensure!(
        receiver
            .read_inbox(inbox_read(Some(records[3].position())))?
            .records
            == vec![records[4].clone()]
    );
    ensure!(
        publisher
            .retire_published_history(STREAM, records[3].position(), 4)?
            .removed
            == 4
    );
    ensure!(
        publisher
            .read(publisher_read(Some(records[3].position())))?
            .records
            == vec![records[4].clone()]
    );
    ensure!(
        receiver
            .retire_projected_inbox(SUBSCRIPTION, 1)?
            .retired_through
            == Some(records[4].position())
    );
    ensure!(
        publisher
            .retire_published_history(STREAM, records[4].position(), 1)?
            .removed
            == 1
    );
    Ok(())
}

#[test]
fn retirement_byte_bound_stops_at_exact_anchor() -> Result<()> {
    byte_bound(
        &MemoryFederationStore::new(PUBLISHER),
        &MemoryFederationStore::new(RECEIVER),
    )?;
    let directory = tempfile::tempdir()?;
    let publisher =
        RedbStore::open(directory.path().join("publisher.redb"))?.federation_store(PUBLISHER)?;
    let receiver =
        RedbStore::open(directory.path().join("receiver.redb"))?.federation_store(RECEIVER)?;
    byte_bound(&publisher, &receiver)
}

#[test]
fn missing_history_does_not_rebase_a_receiver_or_discard_its_inbox() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let publisher_path = directory.path().join("publisher.redb");
    let receiver_path = directory.path().join("receiver.redb");
    let publisher = RedbStore::open(&publisher_path)?.federation_store(PUBLISHER)?;
    let receiver = RedbStore::open(&receiver_path)?.federation_store(RECEIVER)?;
    let opened = prepare(&publisher, &receiver, HistoryStart::All)?;
    receiver.install_subscription(InstallSubscriptionRequest {
        authenticated_publisher: PUBLISHER,
        opened,
    })?;
    let first = publish(&publisher, 1)?;
    let second = publish(&publisher, 2)?;
    let third = publish(&publisher, 3)?;
    receiver.accept(AcceptRequest {
        authenticated_publisher: PUBLISHER,
        subscription: SUBSCRIPTION,
        record: first.clone(),
    })?;
    publisher.retire_published_history(STREAM, second.position(), 2)?;
    ensure!(matches!(
        publisher.read(publisher_read(Some(first.position()))),
        Err(FederationError::ResyncRequired {
            minimum_available: 3
        })
    ));
    ensure!(matches!(
        receiver.accept(AcceptRequest {
            authenticated_publisher: PUBLISHER,
            subscription: SUBSCRIPTION,
            record: third.clone(),
        }),
        Err(FederationError::Gap {
            expected: 2,
            received: 3
        })
    ));
    ensure!(receiver.read_inbox(inbox_read(None))?.records == vec![first.clone()]);
    drop(publisher);
    drop(receiver);

    let publisher = RedbStore::open(&publisher_path)?.federation_store(PUBLISHER)?;
    let receiver = RedbStore::open(&receiver_path)?.federation_store(RECEIVER)?;
    ensure!(matches!(
        publisher.read(publisher_read(Some(first.position()))),
        Err(FederationError::ResyncRequired {
            minimum_available: 3
        })
    ));
    let inbox = receiver.read_inbox(inbox_read(None))?;
    ensure!(inbox.received == Some(first.position()));
    ensure!(inbox.projected.is_none() && inbox.records == vec![first]);
    ensure!(
        publisher
            .read(publisher_read(Some(second.position())))?
            .records
            == vec![third]
    );
    Ok(())
}
