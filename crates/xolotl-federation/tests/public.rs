use std::sync::Arc;

use anyhow::{Result, ensure};
use xolotl_federation::{
    EventType, ExportName, FederationError, FederationNodeId, FederationPublicReadStore,
    FederationPublicService, FederationStore, MAX_PUBLIC_POLICIES, MemoryFederationStore,
    PublicReadLimits, PublicReadRequest, PublicStreamPolicy, PublishRequest, RequestId,
    SchemaRevision, StreamId, StreamRef, StreamSpec,
};

#[test]
fn public_service_never_creates_private_subscription_authority() -> Result<()> {
    let node = FederationNodeId::from_bytes([41; 48]);
    let reader = FederationNodeId::from_bytes([42; 48]);
    let stream = StreamRef {
        publisher: node,
        id: StreamId::from_bytes([43; 16]),
    };
    let store = Arc::new(MemoryFederationStore::new(node));
    store.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("posts")?,
    })?;
    let policy = PublicStreamPolicy {
        stream,
        enabled: true,
        max_read_records: 2,
        max_read_bytes: 32,
    };
    let view = store.set_public_stream_policy(None, policy)?;
    ensure!(store.public_stream_policy(stream)? == Some((policy, 1)));
    ensure!(store.list_public_stream_policies()? == vec![(policy, 1)]);
    let service = FederationPublicService::new(store.clone(), PublicReadLimits::default())?;
    ensure!(service.inspect(reader, stream)? == view);
    let record = store.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([44; 16]),
        event_type: EventType::new("post")?,
        schema_revision: SchemaRevision::from_bytes([45; 32]),
        event_ref: None,
        payload: Arc::from(b"hello".as_slice()),
    })?;
    let request = PublicReadRequest {
        authenticated_reader: reader,
        stream,
        expected_policy_revision: 1,
        after: None,
        max_records: 2,
        max_bytes: 32,
    };
    ensure!(service.read(request)?.records == vec![record]);
    ensure!(
        store
            .open(xolotl_federation::OpenRequest {
                authenticated_subscriber: reader,
                request_id: RequestId::from_bytes([46; 16]),
                subscription: xolotl_federation::SubscriptionRef {
                    subscriber: reader,
                    id: xolotl_federation::SubscriptionId::from_bytes([47; 16]),
                },
                stream,
                expected_control_revision: None,
                history: xolotl_federation::HistoryStart::All,
            })
            .is_err()
    );
    let disabled = PublicStreamPolicy {
        enabled: false,
        ..policy
    };
    store.set_public_stream_policy(Some(1), disabled)?;
    ensure!(store.public_stream_policy(stream)? == Some((disabled, 2)));
    ensure!(store.list_public_stream_policies()? == vec![(disabled, 2)]);
    ensure!(matches!(
        service.read(request),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        store.set_public_stream_policy(Some(2), policy),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn public_policy_count_has_a_global_ceiling() -> Result<()> {
    let node = FederationNodeId::from_bytes([51; 48]);
    let store = MemoryFederationStore::new(node);
    for index in 0..=MAX_PUBLIC_POLICIES {
        let stream = StreamRef {
            publisher: node,
            id: StreamId::from_bytes((index as u128).to_be_bytes()),
        };
        store.declare_stream(StreamSpec {
            stream,
            export: ExportName::new("public")?,
        })?;
        let result = store.set_public_stream_policy(
            None,
            PublicStreamPolicy {
                stream,
                enabled: true,
                max_read_records: 1,
                max_read_bytes: 1,
            },
        );
        if index == MAX_PUBLIC_POLICIES {
            ensure!(matches!(result, Err(FederationError::Capacity)));
        } else {
            ensure!(result?.policy_revision == 1);
        }
    }
    Ok(())
}
