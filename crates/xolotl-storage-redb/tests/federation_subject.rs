#![cfg(feature = "federation")]

use std::sync::Arc;

use anyhow::{Result, ensure};
use xolotl_federation::{
    AcknowledgeRequest, CloseSubscriptionRequest, EventType, ExportAccess, ExportName,
    FederationError, FederationNodeId, FederationStore, FederationSubject, GrantHistory,
    HistoryStart, HostedSubject, InspectSubscriptionRequest, MemoryFederationStore, OpenRequest,
    PublishRequest, ReadRequest, RequestId, SchemaRevision, StreamId, StreamRef, StreamSpec,
    SubjectGrant, SubjectGrantKey, SubjectIssuerId, SubscriptionId, SubscriptionRef,
};
use xolotl_storage_redb::RedbStore;

const PUBLISHER: FederationNodeId = FederationNodeId::from_bytes([31; 48]);
const PRESENTER: FederationNodeId = FederationNodeId::from_bytes([32; 48]);
const OTHER_DEVICE: FederationNodeId = FederationNodeId::from_bytes([33; 48]);
const STREAM: StreamRef = StreamRef {
    publisher: PUBLISHER,
    id: StreamId::from_bytes([34; 16]),
};

fn subject(name: &str) -> HostedSubject {
    HostedSubject {
        issuer: SubjectIssuerId::from_bytes([35; 48]),
        namespace: "people".into(),
        subject: name.into(),
    }
}

fn grant(
    name: &str,
    presenter: FederationNodeId,
    history: GrantHistory,
    enabled: bool,
) -> SubjectGrant {
    SubjectGrant {
        subject: subject(name),
        presenter,
        stream: STREAM,
        not_before_ms: 100,
        expires_ms: 1_000,
        history,
        enabled,
    }
}

fn open(presenter: FederationNodeId, request: u8, subscription: u8) -> OpenRequest {
    OpenRequest {
        authenticated_subscriber: presenter,
        request_id: RequestId::from_bytes([request; 16]),
        subscription: SubscriptionRef {
            subscriber: presenter,
            id: SubscriptionId::from_bytes([subscription; 16]),
        },
        stream: STREAM,
        expected_control_revision: None,
        history: HistoryStart::All,
    }
}

fn read(request: &OpenRequest) -> ReadRequest {
    ReadRequest {
        authenticated_subscriber: request.authenticated_subscriber,
        subscription: request.subscription,
        after: None,
        max_records: 8,
        max_bytes: 1024,
    }
}

fn publish(store: &impl FederationStore, request: u8) -> Result<xolotl_federation::Record> {
    Ok(store.append_published(PublishRequest {
        retry_epoch: 1,
        stream: STREAM,
        publish_id: RequestId::from_bytes([request; 16]),
        event_type: EventType::new("note.created")?,
        schema_revision: SchemaRevision::from_bytes([37; 32]),
        event_ref: None,
        payload: Arc::from(b"private note".as_slice()),
    })?)
}

fn exercise(store: &impl FederationStore) -> Result<(OpenRequest, OpenRequest)> {
    let export = ExportName::new("notes")?;
    store.set_peer_authority(PRESENTER, None, true)?;
    store.set_peer_authority(OTHER_DEVICE, None, true)?;
    store.set_export_authority(
        PRESENTER,
        export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    store.declare_stream(StreamSpec {
        stream: STREAM,
        export,
    })?;
    let old = publish(store, 38)?;
    let alice = FederationSubject::Hosted(subject("alice"));
    let bob = FederationSubject::Hosted(subject("bob"));
    let alice_open = open(PRESENTER, 39, 40);
    let bob_open = open(PRESENTER, 41, 42);
    ensure!(matches!(
        store.open_as(alice.clone(), 200, alice_open.clone()),
        Err(FederationError::Unauthorized)
    ));
    ensure!(
        store.set_subject_grant(
            None,
            grant("alice", PRESENTER, GrantHistory::FromGrant, true)
        )? == 1
    );
    ensure!(store.set_subject_grant(None, grant("bob", PRESENTER, GrantHistory::All, true))? == 1);
    let alice_grant = store
        .subject_grant(&subject("alice"), PRESENTER, STREAM)?
        .ok_or_else(|| anyhow::anyhow!("missing Alice grant"))?;
    ensure!(alice_grant.grant == grant("alice", PRESENTER, GrantHistory::FromGrant, true));
    ensure!(alice_grant.revision == 1 && alice_grant.history_floor == old.sequence());
    ensure!(
        store
            .subject_grant(&subject("charlie"), PRESENTER, STREAM)?
            .is_none()
    );
    let first = store.scan_subject_grants(None, 1)?;
    ensure!(first.len() == 1);
    let second =
        store.scan_subject_grants(Some(&SubjectGrantKey::from_grant(&first[0].grant)), 1)?;
    ensure!(second.len() == 1 && second[0].grant.subject != first[0].grant.subject);
    ensure!(
        [
            first[0].grant.subject.clone(),
            second[0].grant.subject.clone()
        ]
        .contains(&subject("alice"))
            && [
                first[0].grant.subject.clone(),
                second[0].grant.subject.clone()
            ]
            .contains(&subject("bob"))
    );
    ensure!(
        store
            .scan_subject_grants(Some(&SubjectGrantKey::from_grant(&second[0].grant)), 1)?
            .is_empty()
    );
    ensure!(store.scan_subject_grants(None, 0).is_err());
    let opened_alice = store.open_as(alice.clone(), 200, alice_open.clone())?;
    let opened_bob = store.open_as(bob.clone(), 200, bob_open.clone())?;
    ensure!(opened_alice.start == Some(old.position()) && opened_bob.start.is_none());
    ensure!(matches!(
        store.open_as(bob.clone(), 200, alice_open.clone()),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.open_as(alice.clone(), 200, open(OTHER_DEVICE, 43, 44)),
        Err(FederationError::Unauthorized)
    ));
    let fresh = publish(store, 45)?;
    ensure!(
        store
            .read_as(alice.clone(), 200, read(&alice_open))?
            .records
            == vec![fresh.clone()]
    );
    ensure!(store.read_as(bob.clone(), 200, read(&bob_open))?.records == vec![old, fresh.clone()]);
    ensure!(matches!(
        store.read_as(bob.clone(), 200, read(&alice_open)),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        store.read_as(FederationSubject::Node(PRESENTER), 200, read(&alice_open)),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        store.inspect_subscription_as(
            bob.clone(),
            200,
            InspectSubscriptionRequest {
                authenticated_subscriber: PRESENTER,
                subscription: alice_open.subscription
            }
        ),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        store.acknowledge_as(
            bob.clone(),
            200,
            AcknowledgeRequest {
                authenticated_subscriber: PRESENTER,
                subscription: alice_open.subscription,
                position: fresh.position()
            }
        ),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        store.close_subscription_as(
            bob.clone(),
            200,
            CloseSubscriptionRequest {
                authenticated_subscriber: PRESENTER,
                request_id: RequestId::from_bytes([46; 16]),
                subscription: alice_open.subscription,
                expected_subscription_revision: None
            }
        ),
        Err(FederationError::Unauthorized)
    ));
    ensure!(
        store.acknowledge_as(
            alice.clone(),
            200,
            AcknowledgeRequest {
                authenticated_subscriber: PRESENTER,
                subscription: alice_open.subscription,
                position: fresh.position()
            }
        )? == fresh.position()
    );
    ensure!(
        store.set_subject_grant(
            Some(1),
            grant("alice", PRESENTER, GrantHistory::FromGrant, false)
        )? == 2
    );
    ensure!(matches!(
        store.read_as(alice.clone(), 200, read(&alice_open)),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        store.open_as(alice.clone(), 200, alice_open.clone()),
        Err(FederationError::Unauthorized)
    ));
    ensure!(store.read_as(bob, 200, read(&bob_open))?.records.len() == 2);
    ensure!(
        store.set_subject_grant(
            Some(2),
            grant("alice", PRESENTER, GrantHistory::FromGrant, true)
        )? == 3
    );
    ensure!(
        store
            .subject_grant(&subject("alice"), PRESENTER, STREAM)?
            .ok_or_else(|| anyhow::anyhow!("missing renewed Alice grant"))?
            .history_floor
            == fresh.sequence()
    );
    ensure!(matches!(
        store.read_as(alice.clone(), 200, read(&alice_open)),
        Err(FederationError::Conflict)
    ));
    let renewed = open(PRESENTER, 47, 48);
    ensure!(store.open_as(alice.clone(), 200, renewed.clone())?.start == Some(fresh.position()));
    ensure!(
        store
            .read_as(alice.clone(), 200, read(&renewed))?
            .records
            .is_empty()
    );
    ensure!(matches!(
        store.read_as(alice, 1_000, read(&renewed)),
        Err(FederationError::Unauthorized)
    ));
    Ok((renewed, bob_open))
}

#[test]
fn memory_subject_grants_isolate_presenters_and_revoke_subscriptions() -> Result<()> {
    exercise(&MemoryFederationStore::new(PUBLISHER))?;
    Ok(())
}

#[test]
fn redb_subject_grants_survive_restart_and_fence_old_replays() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("subjects.redb");
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(PUBLISHER)?;
    let (renewed, bob_open) = exercise(&store)?;
    drop(store);
    drop(db);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(PUBLISHER)?;
    let alice = FederationSubject::Hosted(subject("alice"));
    let bob = FederationSubject::Hosted(subject("bob"));
    let restored = store
        .subject_grant(&subject("alice"), PRESENTER, STREAM)?
        .ok_or_else(|| anyhow::anyhow!("missing restored Alice grant"))?;
    ensure!(restored.revision == 3 && restored.grant.enabled);
    ensure!(store.scan_subject_grants(None, 256)?.len() == 2);
    ensure!(
        store
            .open_as(alice.clone(), 200, renewed.clone())?
            .start
            .is_some()
    );
    ensure!(
        store
            .read_as(alice, 200, read(&renewed))?
            .records
            .is_empty()
    );
    ensure!(
        store
            .read_as(bob.clone(), 200, read(&bob_open))?
            .records
            .len()
            == 2
    );
    ensure!(matches!(
        store.open_as(bob, 200, renewed),
        Err(FederationError::Conflict)
    ));
    Ok(())
}
