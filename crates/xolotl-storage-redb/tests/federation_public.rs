#![cfg(feature = "federation")]

use std::sync::Arc;

use anyhow::{Result, ensure};
use xolotl_federation::{
    EventType, ExportName, FederationError, FederationNodeId, FederationPublicReadStore,
    FederationStore, InspectSubscriptionRequest, MemoryFederationStore, PublicReadRequest,
    PublicStreamPolicy, PublishRequest, RequestId, SchemaRevision, StreamId, StreamRef, StreamSpec,
    SubscriptionId, SubscriptionRef,
};
use xolotl_storage_redb::RedbStore;

fn publish(
    store: &impl FederationStore,
    stream: StreamRef,
    id: u8,
    bytes: &'static [u8],
) -> Result<xolotl_federation::Record> {
    Ok(store.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([id; 16]),
        event_type: EventType::new("public.note")?,
        schema_revision: SchemaRevision::from_bytes([9; 32]),
        event_ref: None,
        payload: Arc::from(bytes),
    })?)
}

fn policy(stream: StreamRef, enabled: bool, max_records: usize) -> PublicStreamPolicy {
    PublicStreamPolicy {
        stream,
        enabled,
        max_read_records: max_records,
        max_read_bytes: 8,
    }
}

fn read(
    reader: FederationNodeId,
    stream: StreamRef,
    revision: u64,
    after: Option<xolotl_federation::Position>,
    max_records: usize,
) -> PublicReadRequest {
    PublicReadRequest {
        authenticated_reader: reader,
        stream,
        expected_policy_revision: revision,
        after,
        max_records,
        max_bytes: 8,
    }
}

#[test]
fn unknown_verified_node_reads_only_explicit_public_stream_across_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("federation.redb");
    let node = FederationNodeId::from_bytes([31; 48]);
    let stranger = FederationNodeId::from_bytes([32; 48]);
    let public = StreamRef {
        publisher: node,
        id: StreamId::from_bytes([34; 16]),
    };
    let private = StreamRef {
        publisher: node,
        id: StreamId::from_bytes([35; 16]),
    };
    let second;
    {
        let db = RedbStore::open(&path)?;
        let store = db.federation_store(node)?;
        store.declare_stream(StreamSpec {
            stream: private,
            export: ExportName::new("private")?,
        })?;
        publish(&store, private, 1, b"secret")?;
        ensure!(matches!(
            store.set_public_stream_policy(None, policy(private, true, 2)),
            Err(FederationError::Invalid(_))
        ));
        ensure!(matches!(
            store.inspect_public_stream(stranger, private),
            Err(FederationError::Unauthorized)
        ));
        store.declare_stream(StreamSpec {
            stream: public,
            export: ExportName::new("public")?,
        })?;
        let view = store.set_public_stream_policy(None, policy(public, true, 2))?;
        ensure!(view.policy_revision == 1 && view.head.is_none());
        ensure!(store.peer_authority(stranger)?.is_none());
        let first = publish(&store, public, 2, b"one")?;
        second = publish(&store, public, 3, b"two")?;
        let third = publish(&store, public, 4, b"three")?;
        let page = store.read_public_stream(read(stranger, public, 1, None, 2))?;
        ensure!(page.records == vec![first, second.clone()]);
        ensure!(page.head == Some(third.position()) && page.minimum_available == 1);
        ensure!(
            store
                .read_public_stream(read(stranger, public, 1, Some(second.position()), 2))?
                .records
                == vec![third]
        );
        let forged = xolotl_federation::Position::new(1, second.digest())?;
        ensure!(matches!(
            store.read_public_stream(read(stranger, public, 1, Some(forged), 2)),
            Err(FederationError::Conflict)
        ));
        ensure!(matches!(
            store.inspect_subscription(InspectSubscriptionRequest {
                authenticated_subscriber: stranger,
                subscription: SubscriptionRef {
                    subscriber: stranger,
                    id: SubscriptionId::from_bytes([36; 16]),
                },
            }),
            Err(FederationError::NotFound)
        ));
        ensure!(store.peer_authority(stranger)?.is_none());
    }
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    ensure!(store.peer_authority(stranger)?.is_none());
    ensure!(store.public_stream_policy(public)? == Some((policy(public, true, 2), 1)));
    ensure!(store.list_public_stream_policies()? == vec![(policy(public, true, 2), 1)]);
    ensure!(
        store
            .inspect_public_stream(stranger, public)?
            .policy_revision
            == 1
    );
    ensure!(
        store
            .read_public_stream(read(stranger, public, 1, Some(second.position()), 2))?
            .records
            .len()
            == 1
    );
    let updated = store.set_public_stream_policy(Some(1), policy(public, true, 1))?;
    ensure!(updated.policy_revision == 2 && updated.head.is_some());
    ensure!(matches!(
        store.read_public_stream(read(stranger, public, 1, None, 1)),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.read_public_stream(read(stranger, public, 2, None, 2)),
        Err(FederationError::Capacity)
    ));
    ensure!(
        store
            .read_public_stream(read(stranger, public, 2, None, 1))?
            .records
            .len()
            == 1
    );
    let revoked = store.set_public_stream_policy(Some(2), policy(public, false, 1))?;
    ensure!(revoked.policy_revision == 3);
    ensure!(store.public_stream_policy(public)? == Some((policy(public, false, 1), 3)));
    ensure!(store.list_public_stream_policies()? == vec![(policy(public, false, 1), 3)]);
    ensure!(matches!(
        store.inspect_public_stream(stranger, public),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        store.set_public_stream_policy(Some(3), policy(public, true, 1)),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

fn public_reader_admission_contract(
    store: &(impl FederationStore + FederationPublicReadStore),
) -> Result<PublicReadRequest> {
    let reader = FederationNodeId::from_bytes([82; 48]);
    let stranger = FederationNodeId::from_bytes([83; 48]);
    let stream = StreamRef {
        publisher: FederationStore::local_node(store),
        id: StreamId::from_bytes([84; 16]),
    };
    store.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("public-admission")?,
    })?;
    let view = store.set_public_stream_policy(None, policy(stream, true, 1))?;
    let record = publish(store, stream, 1, b"public")?;
    let request = read(reader, stream, view.policy_revision, None, 1);
    ensure!(store.inspect_public_stream(reader, stream)?.head == Some(record.position()));
    ensure!(store.read_public_stream(request)?.records == vec![record.clone()]);
    for (expected_revision, enabled) in [(None, true), (Some(1), false), (Some(2), true)] {
        store.set_peer_authority(reader, expected_revision, enabled)?;
        ensure!(
            matches!(
                store.inspect_public_stream(reader, stream),
                Err(FederationError::Unauthorized)
            ),
            "configured reader reached public discovery with enabled={enabled}"
        );
        ensure!(
            matches!(
                store.read_public_stream(request),
                Err(FederationError::Unauthorized)
            ),
            "configured reader reached public read with enabled={enabled}"
        );
        ensure!(store.inspect_public_stream(stranger, stream)?.head == Some(record.position()));
        ensure!(
            store
                .read_public_stream(PublicReadRequest {
                    authenticated_reader: stranger,
                    ..request
                })?
                .records
                == vec![record.clone()]
        );
    }
    Ok(request)
}

#[test]
fn memory_public_reader_admission_uses_current_managed_peer_state() -> Result<()> {
    let store = MemoryFederationStore::new(FederationNodeId::from_bytes([81; 48]));
    public_reader_admission_contract(&store)?;
    Ok(())
}

#[test]
fn redb_public_reader_admission_uses_current_managed_peer_state_after_reopen() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("public-admission.redb");
    let node = FederationNodeId::from_bytes([81; 48]);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    let request = public_reader_admission_contract(&store)?;
    drop(store);
    drop(db);
    let reopened = RedbStore::open(&path)?.federation_store(node)?;
    ensure!(matches!(
        reopened.inspect_public_stream(request.authenticated_reader, request.stream),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        reopened.read_public_stream(request),
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}
