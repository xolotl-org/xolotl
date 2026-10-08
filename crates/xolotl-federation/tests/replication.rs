use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use xolotl_federation::{
    AcknowledgeRequest, CloseSubscriptionRequest, EventType, ExportAccess, ExportName,
    FederationError, FederationNodeId, FederationReplicaRetentionStore, FederationStore,
    HistoryStart, MemoryFederationStore, OpenRequest, Position, PublishRequest, ReplicaMemberSpec,
    ReplicaRetentionTerm, RequestId, SchemaRevision, StreamId, StreamRef, StreamSpec,
    SubscriptionId, SubscriptionRef,
};

const PUBLISHER: FederationNodeId = FederationNodeId::from_bytes([111; 48]);
const REPLICA: FederationNodeId = FederationNodeId::from_bytes([112; 48]);
const STREAM: StreamRef = StreamRef {
    publisher: PUBLISHER,
    id: StreamId::from_bytes([113; 16]),
};
const SUBSCRIPTION: SubscriptionRef = SubscriptionRef {
    subscriber: REPLICA,
    id: SubscriptionId::from_bytes([114; 16]),
};

fn setup() -> Result<MemoryFederationStore> {
    let store = MemoryFederationStore::new(PUBLISHER);
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
    Ok(store)
}

fn open(store: &MemoryFederationStore, subscription: SubscriptionRef, request: u8) -> Result<()> {
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

fn publish(store: &MemoryFederationStore, id: u8) -> Result<Position> {
    Ok(store
        .append_published(PublishRequest {
            retry_epoch: 1,
            stream: STREAM,
            publish_id: RequestId::from_bytes([id; 16]),
            event_type: EventType::new("note")?,
            schema_revision: SchemaRevision::from_bytes([115; 32]),
            event_ref: None,
            payload: Arc::from([id].as_slice()),
        })?
        .position())
}

fn member(term: ReplicaRetentionTerm) -> ReplicaMemberSpec {
    ReplicaMemberSpec {
        stream: STREAM,
        member: REPLICA,
        subscription: SUBSCRIPTION,
        term,
    }
}

#[test]
fn ordinary_ack_is_not_a_replica_promise() -> Result<()> {
    let store = setup()?;
    let first = publish(&store, 1)?;
    let second = publish(&store, 2)?;
    open(&store, SUBSCRIPTION, 3)?;
    store.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: REPLICA,
        subscription: SUBSCRIPTION,
        position: first,
    })?;
    ensure!(store.replica_member(STREAM, REPLICA)?.is_none());
    ensure!(store.retire_published_history(STREAM, second, 2)?.removed == 2);
    Ok(())
}

#[test]
fn permanent_member_survives_close_and_revocation_until_explicit_retirement() -> Result<()> {
    let store = setup()?;
    let first = publish(&store, 1)?;
    let second = publish(&store, 2)?;
    open(&store, SUBSCRIPTION, 3)?;
    let joined = store.join_replica(member(ReplicaRetentionTerm::Permanent), None, 10)?;
    ensure!(joined.revision == 1 && joined.acknowledged.is_none());
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
    let saved = store
        .replica_member(STREAM, REPLICA)?
        .context("member missing")?;
    ensure!(saved.acknowledged == Some(first) && !saved.retired);
    ensure!(matches!(
        store.retire_replica(STREAM, REPLICA, 0, 11),
        Err(FederationError::Conflict)
    ));
    ensure!(store.retire_replica(STREAM, REPLICA, 1, 11)?.retired);
    ensure!(store.retire_published_history(STREAM, second, 1)?.removed == 1);
    Ok(())
}

#[test]
fn lease_expiry_and_renewal_obey_trusted_clock_and_bounded_pruning() -> Result<()> {
    let store = setup()?;
    let first = publish(&store, 1)?;
    let second = publish(&store, 2)?;
    let third = publish(&store, 3)?;
    open(&store, SUBSCRIPTION, 4)?;
    let joined = store.join_replica(member(ReplicaRetentionTerm::LeaseUntilMs(100)), None, 10)?;
    let renewed = store.extend_replica(
        STREAM,
        REPLICA,
        joined.revision,
        ReplicaRetentionTerm::LeaseUntilMs(200),
        20,
    )?;
    ensure!(renewed.revision == 2);
    ensure!(store.retire_replica_safe_history(STREAM, 100, 1)?.removed == 0);
    ensure!(matches!(
        store.retire_published_history(STREAM, first, 1),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.retire_replica_safe_history(STREAM, 99, 1),
        Err(FederationError::ClockRollback)
    ));
    ensure!(
        store
            .retire_replica_safe_history(STREAM, 200, 1)?
            .retired_through
            == Some(first)
    );
    ensure!(
        store
            .replica_member(STREAM, REPLICA)?
            .context("member missing")?
            .retired
    );
    ensure!(
        store
            .retire_replica_safe_history(STREAM, 200, 1)?
            .retired_through
            == Some(second)
    );
    ensure!(
        store
            .retire_replica_safe_history(STREAM, 200, 1)?
            .retired_through
            == Some(third)
    );
    ensure!(store.retire_replica_safe_history(STREAM, 200, 1)?.removed == 0);
    Ok(())
}

#[test]
fn reenrollment_requires_fresh_subscription_and_cas() -> Result<()> {
    let store = setup()?;
    publish(&store, 1)?;
    open(&store, SUBSCRIPTION, 2)?;
    let joined = store.join_replica(member(ReplicaRetentionTerm::Permanent), None, 10)?;
    ensure!(matches!(
        store.extend_replica(
            STREAM,
            REPLICA,
            1,
            ReplicaRetentionTerm::LeaseUntilMs(100),
            20
        ),
        Err(FederationError::Conflict)
    ));
    let retired = store.retire_replica(STREAM, REPLICA, joined.revision, 20)?;
    ensure!(matches!(
        store.join_replica(
            member(ReplicaRetentionTerm::Permanent),
            Some(retired.revision),
            30
        ),
        Err(FederationError::Conflict)
    ));
    let next_subscription = SubscriptionRef {
        subscriber: REPLICA,
        id: SubscriptionId::from_bytes([116; 16]),
    };
    open(&store, next_subscription, 3)?;
    let next = store.join_replica(
        ReplicaMemberSpec {
            subscription: next_subscription,
            ..member(ReplicaRetentionTerm::Permanent)
        },
        Some(retired.revision),
        30,
    )?;
    ensure!(next.revision == 3 && !next.retired);
    ensure!(store.scan_replica_members(STREAM, None, 1)? == vec![next]);
    Ok(())
}
