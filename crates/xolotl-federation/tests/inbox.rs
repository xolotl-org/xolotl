use std::sync::Arc;

use anyhow::{Result, ensure};
use xolotl_federation::{
    AcceptRequest, Digest, EventType, ExportAccess, ExportName, FederationError, FederationNodeId,
    FederationStore, HistoryStart, InboxReadRequest, InstallSubscriptionRequest,
    MemoryFederationStore, OpenRequest, Position, ProjectionProgress, PublishRequest, RequestId,
    SchemaRevision, StreamId, StreamRef, StreamSpec, SubscriptionId, SubscriptionRef,
};

#[test]
fn local_inbox_exposes_only_accepted_tail_and_fences_revocation() -> Result<()> {
    let publisher_id = FederationNodeId::from_bytes([1; 48]);
    let receiver_id = FederationNodeId::from_bytes([2; 48]);
    let publisher = MemoryFederationStore::new(publisher_id);
    let receiver = MemoryFederationStore::new(receiver_id);
    let export = ExportName::new("notes")?;
    let stream = StreamRef {
        publisher: publisher_id,
        id: StreamId::from_bytes([3; 16]),
    };
    let subscription = SubscriptionRef {
        subscriber: receiver_id,
        id: SubscriptionId::from_bytes([4; 16]),
    };
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
    publisher.declare_stream(StreamSpec { stream, export })?;
    let old = publisher.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([5; 16]),
        event_type: EventType::new("note")?,
        schema_revision: SchemaRevision::from_bytes([6; 32]),
        event_ref: None,
        payload: Arc::from(b"old".as_slice()),
    })?;
    let opened = publisher.open(OpenRequest {
        authenticated_subscriber: receiver_id,
        request_id: RequestId::from_bytes([7; 16]),
        subscription,
        stream,
        expected_control_revision: Some(0),
        history: HistoryStart::FromNow,
    })?;
    ensure!(opened.start == Some(old.position()));
    receiver.install_subscription(InstallSubscriptionRequest {
        authenticated_publisher: publisher_id,
        opened,
    })?;
    let fresh = publisher.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([8; 16]),
        event_type: EventType::new("note")?,
        schema_revision: SchemaRevision::from_bytes([6; 32]),
        event_ref: None,
        payload: Arc::from(b"fresh".as_slice()),
    })?;
    let request = InboxReadRequest {
        subscription,
        expected_stream: stream,
        after: None,
        max_records: 1,
        max_bytes: 16,
    };
    ensure!(receiver.read_inbox(request)?.records.is_empty());
    receiver.accept(AcceptRequest {
        authenticated_publisher: publisher_id,
        subscription,
        record: fresh.clone(),
    })?;
    let page = receiver.read_inbox(request)?;
    ensure!(page.records == vec![fresh.clone()]);
    ensure!(page.received == Some(fresh.position()) && page.projected.is_none());
    ensure!(matches!(
        receiver.read_inbox(InboxReadRequest {
            after: Some(Position::new(2, Digest::from_bytes([9; 48]))?),
            ..request
        }),
        Err(FederationError::Conflict)
    ));
    receiver.record_projection_progress(ProjectionProgress {
        subscription,
        position: fresh.position(),
    })?;
    ensure!(receiver.read_inbox(request)?.projected == Some(fresh.position()));
    receiver.set_export_authority(
        publisher_id,
        ExportName::new("notes")?,
        Some(1),
        ExportAccess {
            serve: false,
            receive: false,
        },
    )?;
    ensure!(matches!(
        receiver.read_inbox(request),
        Err(FederationError::Unauthorized | FederationError::Conflict)
    ));
    Ok(())
}
