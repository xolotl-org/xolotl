#![cfg(feature = "federation")]

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result, ensure};
use xolotl_federation::{
    AcknowledgeRequest, CloseSubscriptionRequest, Digest, EventType, ExportAccess, ExportName,
    FederationError, FederationNodeId, FederationReplicaRetentionStore,
    FederationSnapshotPublisherStore, FederationStore, HistoryStart, MemoryFederationStore,
    OpenRequest, Position, PublishRequest, ReadRequest, ReplicaMemberSpec, ReplicaRetentionTerm,
    RequestId, SchemaRevision, SnapshotId, SnapshotOfferRequest, SnapshotPublicationProof,
    SnapshotReceivedRequest, SnapshotSuffixCoverage, StreamId, StreamRef, StreamSpec,
    SubscriptionId, SubscriptionRef,
};
use xolotl_storage_redb::{RedbFederationStore, RedbStore};

const PUBLISHER: FederationNodeId = FederationNodeId::from_bytes([101; 48]);
const REPLICA: FederationNodeId = FederationNodeId::from_bytes([102; 48]);
const STREAM: StreamRef = StreamRef {
    publisher: PUBLISHER,
    id: StreamId::from_bytes([103; 16]),
};
const SUBSCRIPTION: SubscriptionRef = SubscriptionRef {
    subscriber: REPLICA,
    id: SubscriptionId::from_bytes([104; 16]),
};

fn setup(path: &Path) -> Result<(RedbStore, RedbFederationStore)> {
    let db = RedbStore::open(path)?;
    let store = db.federation_store(PUBLISHER)?;
    store.set_peer_authority(REPLICA, None, true)?;
    store.set_export_authority(
        REPLICA,
        ExportName::new("notes")?,
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    store.declare_stream(StreamSpec {
        stream: STREAM,
        export: ExportName::new("notes")?,
    })?;
    Ok((db, store))
}

fn open(store: &impl FederationStore, subscription: SubscriptionRef, request: u8) -> Result<()> {
    store.open(OpenRequest {
        authenticated_subscriber: REPLICA,
        request_id: RequestId::from_bytes([request; 16]),
        subscription,
        stream: STREAM,
        expected_control_revision: None,
        history: HistoryStart::All,
    })?;
    Ok(())
}

fn publish(store: &impl FederationStore, id: u8) -> Result<Position> {
    Ok(store
        .append_published(PublishRequest {
            retry_epoch: 1,
            stream: STREAM,
            publish_id: RequestId::from_bytes([id; 16]),
            event_type: EventType::new("note")?,
            schema_revision: SchemaRevision::from_bytes([105; 32]),
            event_ref: None,
            payload: Arc::from([id].as_slice()),
        })?
        .position())
}

fn member(subscription: SubscriptionRef, term: ReplicaRetentionTerm) -> ReplicaMemberSpec {
    ReplicaMemberSpec {
        stream: STREAM,
        member: REPLICA,
        subscription,
        term,
    }
}

fn two_replica_frontiers_contract(
    store: &(impl FederationStore + FederationReplicaRetentionStore),
) -> Result<()> {
    let fast_replica = FederationNodeId::from_bytes([107; 48]);
    let fast_subscription = SubscriptionRef {
        subscriber: fast_replica,
        id: SubscriptionId::from_bytes([108; 16]),
    };
    for replica in [REPLICA, fast_replica] {
        store.set_peer_authority(replica, None, true)?;
        store.set_export_authority(
            replica,
            ExportName::new("notes")?,
            None,
            ExportAccess {
                serve: true,
                receive: false,
            },
        )?;
    }
    store.declare_stream(StreamSpec {
        stream: STREAM,
        export: ExportName::new("notes")?,
    })?;
    let first = publish(store, 1)?;
    let second = publish(store, 2)?;
    let third = publish(store, 3)?;
    let fourth = publish(store, 4)?;
    open(store, SUBSCRIPTION, 5)?;
    store.open(OpenRequest {
        authenticated_subscriber: fast_replica,
        request_id: RequestId::from_bytes([6; 16]),
        subscription: fast_subscription,
        stream: STREAM,
        expected_control_revision: None,
        history: HistoryStart::All,
    })?;
    let slow = store.join_replica(
        member(SUBSCRIPTION, ReplicaRetentionTerm::Permanent),
        None,
        10,
    )?;
    store.join_replica(
        ReplicaMemberSpec {
            stream: STREAM,
            member: fast_replica,
            subscription: fast_subscription,
            term: ReplicaRetentionTerm::Permanent,
        },
        None,
        10,
    )?;
    let retained = |after| -> Result<Vec<Position>> {
        Ok(store
            .read(ReadRequest {
                authenticated_subscriber: REPLICA,
                subscription: SUBSCRIPTION,
                after,
                max_records: 8,
                max_bytes: 1024,
            })?
            .records
            .iter()
            .map(|record| record.position())
            .collect())
    };
    store.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: fast_replica,
        subscription: fast_subscription,
        position: fourth,
    })?;
    ensure!(store.replica_member(STREAM, REPLICA)? == Some(slow));
    let blocked = store.retire_replica_safe_history(STREAM, 11, 4)?;
    ensure!(blocked.removed == 0 && blocked.minimum_available == 1);
    ensure!(blocked.head == Some(fourth) && blocked.retired_through.is_none());
    ensure!(matches!(
        store.retire_published_history(STREAM, first, 1),
        Err(FederationError::Conflict)
    ));
    ensure!(retained(None)? == vec![first, second, third, fourth]);
    store.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        position: first,
    })?;
    let limited = store.retire_replica_safe_history(STREAM, 12, 4)?;
    ensure!(limited.removed == 1 && limited.retired_through == Some(first));
    ensure!(limited.minimum_available == 2 && limited.head == Some(fourth));
    ensure!(store.retire_replica_safe_history(STREAM, 12, 4)?.removed == 0);
    ensure!(matches!(
        store.retire_published_history(STREAM, second, 1),
        Err(FederationError::Conflict)
    ));
    ensure!(retained(Some(first))? == vec![second, third, fourth]);
    store.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        position: third,
    })?;
    for position in [second, third] {
        let advanced = store.retire_replica_safe_history(STREAM, 13, 1)?;
        ensure!(advanced.removed == 1 && advanced.retired_through == Some(position));
        ensure!(advanced.minimum_available == position.sequence() + 1);
        ensure!(advanced.head == Some(fourth));
    }
    ensure!(store.retire_replica_safe_history(STREAM, 13, 1)?.removed == 0);
    ensure!(retained(Some(third))? == vec![fourth]);
    let slow_front = store
        .replica_member(STREAM, REPLICA)?
        .context("slow member missing")?;
    let fast_front = store
        .replica_member(STREAM, fast_replica)?
        .context("fast member missing")?;
    ensure!(slow_front.acknowledged == Some(third) && !slow_front.retired);
    ensure!(fast_front.acknowledged == Some(fourth) && !fast_front.retired);
    ensure!(
        store
            .retire_replica(STREAM, REPLICA, slow.revision, 14)?
            .retired
    );
    let released = store.retire_replica_safe_history(STREAM, 14, 1)?;
    ensure!(released.removed == 1 && released.retired_through == Some(fourth));
    ensure!(released.minimum_available == 5 && released.head == Some(fourth));
    ensure!(retained(Some(fourth))?.is_empty());
    ensure!(store.replica_member(STREAM, fast_replica)? == Some(fast_front));
    ensure!(store.retire_replica_safe_history(STREAM, 14, 1)?.removed == 0);
    Ok(())
}

#[test]
fn two_replica_frontiers_limit_memory_trim_until_slow_member_advances_or_retires() -> Result<()> {
    two_replica_frontiers_contract(&MemoryFederationStore::new(PUBLISHER))
}

#[test]
fn two_replica_frontiers_limit_redb_trim_until_slow_member_advances_or_retires() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("two-replica-frontiers.redb"))?;
    two_replica_frontiers_contract(&db.federation_store(PUBLISHER)?)
}

#[test]
fn ordinary_subscription_ack_does_not_create_replica_commitment() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (_db, store) = setup(&dir.path().join("store.redb"))?;
    let first = publish(&store, 1)?;
    let second = publish(&store, 2)?;
    open(&store, SUBSCRIPTION, 3)?;
    store.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        position: first,
    })?;
    ensure!(store.replica_member(STREAM, REPLICA)?.is_none());
    ensure!(store.scan_replica_members(STREAM, None, 1)?.is_empty());
    ensure!(store.retire_published_history(STREAM, second, 2)?.removed == 2);
    Ok(())
}

#[test]
fn sealed_snapshot_receipt_advances_replica_frontier_without_becoming_event_ack() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("store.redb");
    let (db, store) = setup(&path)?;
    let first = publish(&store, 1)?;
    let _second = publish(&store, 2)?;
    let snapshot_position = publish(&store, 3)?;
    let fourth = publish(&store, 4)?;
    open(&store, SUBSCRIPTION, 5)?;
    store.join_replica(
        member(SUBSCRIPTION, ReplicaRetentionTerm::Permanent),
        None,
        10,
    )?;
    store.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        position: first,
    })?;
    let offer = store.publish_snapshot_offer(SnapshotOfferRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        proof: SnapshotPublicationProof {
            snapshot_id: SnapshotId::from_bytes([10; 16]),
            stream: STREAM,
            position: snapshot_position,
            schema_revision: SchemaRevision::from_bytes([11; 32]),
            content_digest: Digest::from_bytes([12; 48]),
            content_bytes: 8,
            publication_digest: Digest::from_bytes([13; 48]),
        },
    })?;
    ensure!(matches!(
        store.acknowledge(AcknowledgeRequest {
            authenticated_subscriber: REPLICA,
            subscription: SUBSCRIPTION,
            position: fourth,
        }),
        Err(FederationError::Conflict)
    ));
    let receipt = SnapshotReceivedRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        manifest_digest: offer.manifest.binding_digest(),
        publication_digest: offer.publication_digest,
        position: snapshot_position,
        install_id: SnapshotId::from_bytes([14; 16]),
        archive_digest: Digest::from_bytes([15; 48]),
        federation_generation: 1,
        suffix: None,
    };
    for bad in [
        SnapshotReceivedRequest {
            manifest_digest: Digest::from_bytes([16; 48]),
            ..receipt
        },
        SnapshotReceivedRequest {
            publication_digest: Digest::from_bytes([17; 48]),
            ..receipt
        },
        SnapshotReceivedRequest {
            position: fourth,
            ..receipt
        },
    ] {
        ensure!(matches!(
            store.receive_snapshot(bad),
            Err(FederationError::Conflict)
        ));
    }
    ensure!(matches!(
        store.receive_snapshot(SnapshotReceivedRequest {
            authenticated_subscriber: PUBLISHER,
            ..receipt
        }),
        Err(FederationError::Unauthorized)
    ));
    let confirmed = store.receive_snapshot(receipt)?;
    ensure!(confirmed == receipt.into());
    let view = store
        .replica_member(STREAM, REPLICA)?
        .context("replica missing")?;
    ensure!(view.acknowledged == Some(first));
    ensure!(view.snapshot_covered == Some(snapshot_position));
    ensure!(
        store
            .retire_replica_safe_history(STREAM, 10, 3)?
            .retired_through
            == Some(snapshot_position)
    );
    drop(store);
    drop(db);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(PUBLISHER)?;
    ensure!(store.receive_snapshot(receipt)? == confirmed);
    store.retire_snapshot_offer(&offer)?;
    ensure!(store.receive_snapshot(receipt)? == confirmed);
    ensure!(matches!(
        store.receive_snapshot(SnapshotReceivedRequest {
            suffix: Some(SnapshotSuffixCoverage {
                after: snapshot_position,
                through: Position::new(
                    snapshot_position.sequence() + 257,
                    Digest::from_bytes([30; 48])
                )?,
            }),
            ..receipt
        }),
        Err(FederationError::Capacity)
    ));
    ensure!(
        store
            .replica_member(STREAM, REPLICA)?
            .context("replica missing")?
            .snapshot_covered
            == Some(snapshot_position)
    );
    let suffix = SnapshotReceivedRequest {
        suffix: Some(SnapshotSuffixCoverage {
            after: snapshot_position,
            through: fourth,
        }),
        ..receipt
    };
    for bad in [
        SnapshotReceivedRequest {
            federation_generation: 2,
            ..suffix
        },
        SnapshotReceivedRequest {
            install_id: SnapshotId::from_bytes([19; 16]),
            ..suffix
        },
        SnapshotReceivedRequest {
            suffix: Some(SnapshotSuffixCoverage {
                after: first,
                through: fourth,
            }),
            ..receipt
        },
        SnapshotReceivedRequest {
            suffix: Some(SnapshotSuffixCoverage {
                after: snapshot_position,
                through: Position::new(fourth.sequence(), Digest::from_bytes([20; 48]))?,
            }),
            ..receipt
        },
    ] {
        ensure!(matches!(
            store.receive_snapshot(bad),
            Err(FederationError::Conflict)
        ));
    }
    ensure!(store.receive_snapshot(suffix)? == suffix.into());
    ensure!(store.receive_snapshot(suffix)? == suffix.into());
    ensure!(store.receive_snapshot(receipt)? == confirmed);
    ensure!(store.retire_replica_safe_history(STREAM, 10, 1)?.removed == 1);
    ensure!(store.receive_snapshot(suffix)? == suffix.into());
    let view = store
        .replica_member(STREAM, REPLICA)?
        .context("replica missing")?;
    ensure!(view.acknowledged == Some(first));
    ensure!(view.snapshot_covered == Some(fourth));
    drop(store);
    drop(db);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(PUBLISHER)?;
    ensure!(store.receive_snapshot(suffix)? == suffix.into());
    ensure!(
        store
            .replica_member(STREAM, REPLICA)?
            .context("replica missing")?
            .snapshot_covered
            == Some(fourth)
    );
    let fifth = publish(&store, 5)?;
    let next_offer = store.publish_snapshot_offer(SnapshotOfferRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        proof: SnapshotPublicationProof {
            snapshot_id: SnapshotId::from_bytes([21; 16]),
            stream: STREAM,
            position: fifth,
            schema_revision: SchemaRevision::from_bytes([11; 32]),
            content_digest: Digest::from_bytes([22; 48]),
            content_bytes: 8,
            publication_digest: Digest::from_bytes([23; 48]),
        },
    })?;
    let next_receipt = SnapshotReceivedRequest {
        manifest_digest: next_offer.manifest.binding_digest(),
        publication_digest: next_offer.publication_digest,
        position: fifth,
        install_id: SnapshotId::from_bytes([24; 16]),
        archive_digest: Digest::from_bytes([25; 48]),
        federation_generation: 2,
        ..receipt
    };
    store.receive_snapshot(next_receipt)?;
    ensure!(matches!(
        store.receive_snapshot(receipt),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.receive_snapshot(suffix),
        Err(FederationError::Conflict)
    ));
    ensure!(
        store
            .authorize_snapshot_receipt_delivery(REPLICA, confirmed)
            .is_err()
    );
    ensure!(
        store
            .authorize_snapshot_receipt_delivery(REPLICA, next_receipt.into())
            .is_ok()
    );
    drop(store);
    drop(db);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(PUBLISHER)?;
    ensure!(matches!(
        store.receive_snapshot(suffix),
        Err(FederationError::Conflict)
    ));
    store.set_peer_authority(REPLICA, Some(1), false)?;
    ensure!(matches!(
        store.receive_snapshot(receipt),
        Err(FederationError::Unauthorized | FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn archive_suffix_cannot_bridge_a_retired_unconfirmed_gap() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("gap.redb");
    let (db, store) = setup(&path)?;
    let baseline = publish(&store, 1)?;
    let missing = publish(&store, 2)?;
    let through = publish(&store, 3)?;
    open(&store, SUBSCRIPTION, 4)?;
    let offer = store.publish_snapshot_offer(SnapshotOfferRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        proof: SnapshotPublicationProof {
            snapshot_id: SnapshotId::from_bytes([31; 16]),
            stream: STREAM,
            position: baseline,
            schema_revision: SchemaRevision::from_bytes([32; 32]),
            content_digest: Digest::from_bytes([33; 48]),
            content_bytes: 8,
            publication_digest: Digest::from_bytes([34; 48]),
        },
    })?;
    let receipt = SnapshotReceivedRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        manifest_digest: offer.manifest.binding_digest(),
        publication_digest: offer.publication_digest,
        position: baseline,
        install_id: SnapshotId::from_bytes([35; 16]),
        archive_digest: Digest::from_bytes([36; 48]),
        federation_generation: 1,
        suffix: None,
    };
    let suffix = SnapshotReceivedRequest {
        suffix: Some(SnapshotSuffixCoverage {
            after: baseline,
            through,
        }),
        ..receipt
    };
    ensure!(matches!(
        store.receive_snapshot(suffix),
        Err(FederationError::Conflict)
    ));
    store.receive_snapshot(receipt)?;
    let joined = store.join_replica(
        member(SUBSCRIPTION, ReplicaRetentionTerm::Permanent),
        None,
        10,
    )?;
    store.retire_replica(STREAM, REPLICA, joined.revision, 10)?;
    store.retire_snapshot_offer(&offer)?;
    store.retire_published_history(STREAM, missing, 2)?;
    ensure!(matches!(
        store.receive_snapshot(suffix),
        Err(FederationError::Conflict)
    ));
    let member = store
        .replica_member(STREAM, REPLICA)?
        .context("replica missing")?;
    ensure!(member.acknowledged.is_none() && member.snapshot_covered == Some(baseline));
    drop(store);
    drop(db);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(PUBLISHER)?;
    ensure!(matches!(
        store.receive_snapshot(suffix),
        Err(FederationError::Conflict)
    ));
    ensure!(
        store
            .replica_member(STREAM, REPLICA)?
            .context("replica missing")?
            .snapshot_covered
            == Some(baseline)
    );
    Ok(())
}

#[test]
fn permanent_commitment_survives_close_revocation_and_restart_until_cas_retirement() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("store.redb");
    let (db, store) = setup(&path)?;
    let first = publish(&store, 1)?;
    let second = publish(&store, 2)?;
    open(&store, SUBSCRIPTION, 3)?;
    let joined = store.join_replica(
        member(SUBSCRIPTION, ReplicaRetentionTerm::Permanent),
        None,
        10,
    )?;
    ensure!(joined.revision == 1 && joined.baseline.is_none() && joined.acknowledged.is_none());
    ensure!(matches!(
        store.retire_published_history(STREAM, first, 1),
        Err(FederationError::Conflict)
    ));
    store.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        position: first,
    })?;
    ensure!(store.retire_published_history(STREAM, first, 1)?.removed == 1);
    ensure!(matches!(
        store.retire_published_history(STREAM, second, 1),
        Err(FederationError::Conflict)
    ));
    store.close_subscription(CloseSubscriptionRequest {
        authenticated_subscriber: REPLICA,
        request_id: RequestId::from_bytes([4; 16]),
        subscription: SUBSCRIPTION,
        expected_subscription_revision: Some(1),
    })?;
    store.set_peer_authority(REPLICA, Some(1), false)?;
    ensure!(matches!(
        store.retire_published_history(STREAM, second, 1),
        Err(FederationError::Conflict)
    ));
    drop(store);
    drop(db);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(PUBLISHER)?;
    let saved = store
        .replica_member(STREAM, REPLICA)?
        .context("durable member missing")?;
    ensure!(saved.revision == 1 && saved.acknowledged == Some(first) && !saved.retired);
    ensure!(matches!(
        store.retire_published_history(STREAM, second, 1),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.retire_replica(STREAM, REPLICA, 0, 11),
        Err(FederationError::Conflict)
    ));
    let retired = store.retire_replica(STREAM, REPLICA, 1, 11)?;
    ensure!(retired.retired && retired.revision == 2);
    ensure!(store.retire_published_history(STREAM, second, 1)?.removed == 1);
    Ok(())
}

#[test]
fn lease_expiry_needs_a_committed_clock_decision_and_safe_retirement_is_bounded() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (_db, store) = setup(&dir.path().join("store.redb"))?;
    let first = publish(&store, 1)?;
    let second = publish(&store, 2)?;
    let third = publish(&store, 3)?;
    open(&store, SUBSCRIPTION, 4)?;
    store.join_replica(
        member(SUBSCRIPTION, ReplicaRetentionTerm::LeaseUntilMs(100)),
        None,
        10,
    )?;
    ensure!(matches!(
        store.retire_published_history(STREAM, first, 1),
        Err(FederationError::Conflict)
    ));
    ensure!(store.retire_replica_safe_history(STREAM, 99, 1)?.removed == 0);
    ensure!(
        !store
            .replica_member(STREAM, REPLICA)?
            .context("member missing")?
            .retired
    );
    ensure!(matches!(
        store.retire_replica_safe_history(STREAM, 98, 1),
        Err(FederationError::ClockRollback)
    ));
    ensure!(matches!(
        store.retire_published_history(STREAM, first, 1),
        Err(FederationError::Conflict)
    ));
    let trimmed = store.retire_replica_safe_history(STREAM, 100, 1)?;
    ensure!(trimmed.removed == 1 && trimmed.retired_through == Some(first));
    ensure!(
        store
            .replica_member(STREAM, REPLICA)?
            .context("member missing")?
            .retired
    );
    ensure!(
        store
            .retire_replica_safe_history(STREAM, 100, 1)?
            .retired_through
            == Some(second)
    );
    ensure!(
        store
            .retire_replica_safe_history(STREAM, 100, 1)?
            .retired_through
            == Some(third)
    );
    ensure!(store.retire_replica_safe_history(STREAM, 100, 1)?.removed == 0);
    Ok(())
}

#[test]
fn failed_retirement_preserves_payloads_and_member_watermark() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (_db, store) = setup(&dir.path().join("store.redb"))?;
    let first = publish(&store, 1)?;
    let second = publish(&store, 2)?;
    open(&store, SUBSCRIPTION, 3)?;
    store.join_replica(
        member(SUBSCRIPTION, ReplicaRetentionTerm::Permanent),
        None,
        10,
    )?;
    store.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        position: first,
    })?;
    ensure!(matches!(
        store.retire_published_history(STREAM, second, 2),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.retire_published_history(STREAM, Position::new(1, Digest::from_bytes([1; 48]))?, 1),
        Err(FederationError::Conflict)
    ));
    ensure!(
        store
            .replica_member(STREAM, REPLICA)?
            .context("member missing")?
            .acknowledged
            == Some(first)
    );
    ensure!(
        store
            .retire_published_history(STREAM, first, 1)?
            .minimum_available
            == 2
    );
    Ok(())
}

#[test]
fn renewal_upgrade_and_reenrollment_require_exact_revisions() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let (_db, store) = setup(&dir.path().join("store.redb"))?;
    publish(&store, 1)?;
    open(&store, SUBSCRIPTION, 2)?;
    let joined = store.join_replica(
        member(SUBSCRIPTION, ReplicaRetentionTerm::LeaseUntilMs(100)),
        None,
        10,
    )?;
    ensure!(matches!(
        store.extend_replica(
            STREAM,
            REPLICA,
            0,
            ReplicaRetentionTerm::LeaseUntilMs(200),
            20
        ),
        Err(FederationError::Conflict)
    ));
    let renewed = store.extend_replica(
        STREAM,
        REPLICA,
        joined.revision,
        ReplicaRetentionTerm::LeaseUntilMs(200),
        20,
    )?;
    ensure!(renewed.revision == 2);
    let permanent = store.extend_replica(
        STREAM,
        REPLICA,
        renewed.revision,
        ReplicaRetentionTerm::Permanent,
        30,
    )?;
    ensure!(matches!(
        store.extend_replica(
            STREAM,
            REPLICA,
            permanent.revision,
            ReplicaRetentionTerm::LeaseUntilMs(300),
            40
        ),
        Err(FederationError::Conflict)
    ));
    let retired = store.retire_replica(STREAM, REPLICA, permanent.revision, 40)?;
    ensure!(retired.revision == 4 && retired.retired);
    ensure!(matches!(
        store.join_replica(
            member(SUBSCRIPTION, ReplicaRetentionTerm::Permanent),
            Some(4),
            50
        ),
        Err(FederationError::Conflict)
    ));
    let new_subscription = SubscriptionRef {
        subscriber: REPLICA,
        id: SubscriptionId::from_bytes([106; 16]),
    };
    open(&store, new_subscription, 3)?;
    let rejoined = store.join_replica(
        member(new_subscription, ReplicaRetentionTerm::Permanent),
        Some(4),
        50,
    )?;
    ensure!(rejoined.revision == 5 && !rejoined.retired);
    ensure!(store.scan_replica_members(STREAM, None, 1)? == vec![rejoined]);
    Ok(())
}
