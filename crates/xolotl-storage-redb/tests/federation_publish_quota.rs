#![cfg(feature = "federation")]

use std::num::NonZeroUsize;
use std::sync::{Arc, Barrier};

use anyhow::{Result, ensure};
use xolotl_federation::{
    Digest, EventType, ExportName, FederationAdmission, FederationDecision, FederationError,
    FederationNodeId, FederationOnlineKey, FederationOnlineKeyAuthorization,
    FederationPublicReadStore, FederationRootKey, FederationSessionTranscript, FederationStore,
    MemoryFederationStore, PeerAdmission, Position, PublicReadRequest, PublicStreamPolicy,
    PublicationReceipt, PublishRequest, Record, RequestId, RootSignaturePurpose, SchemaRevision,
    StreamId, StreamRef, StreamSpec, verify_federation_peer_proof,
};
use xolotl_storage_redb::{RedbOptions, RedbStore};

fn node() -> FederationNodeId {
    FederationNodeId::from_bytes([1; 48])
}

fn stream(id: u8) -> StreamRef {
    StreamRef {
        publisher: node(),
        id: StreamId::from_bytes([id; 16]),
    }
}

fn publish(
    store: &impl FederationStore,
    stream: StreamRef,
    id: u8,
    payload: &'static [u8],
) -> Result<Record, FederationError> {
    store.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([id; 16]),
        event_type: EventType::new("quota.event")?,
        schema_revision: SchemaRevision::from_bytes([2; 32]),
        event_ref: None,
        payload: Arc::from(payload),
    })
}

fn declare(store: &(impl FederationStore + FederationPublicReadStore), id: u8) -> Result<()> {
    store.declare_stream(StreamSpec {
        stream: stream(id),
        export: ExportName::new("quota")?,
    })?;
    store.set_public_stream_policy(
        None,
        PublicStreamPolicy {
            stream: stream(id),
            enabled: true,
            max_read_records: 8,
            max_read_bytes: 1024,
        },
    )?;
    Ok(())
}

fn quota_contract(store: &(impl FederationStore + FederationPublicReadStore)) -> Result<()> {
    declare(store, 1)?;
    declare(store, 2)?;
    let first = publish(store, stream(1), 1, b"first")?;
    store.retire_published_history(stream(1), first.position(), 1)?;
    let second = publish(store, stream(1), 2, b"second")?;
    ensure!(publish(store, stream(1), 2, b"second")? == second);
    ensure!(matches!(
        publish(store, stream(1), 2, b"changed"),
        Err(FederationError::Conflict)
    ));
    for target in [stream(1), stream(2)] {
        ensure!(matches!(
            publish(store, target, 3, b"rejected"),
            Err(FederationError::Capacity)
        ));
    }
    let reader = FederationNodeId::from_bytes([3; 48]);
    let page = store.read_public_stream(PublicReadRequest {
        authenticated_reader: reader,
        stream: stream(1),
        expected_policy_revision: 1,
        after: None,
        max_records: 8,
        max_bytes: 1024,
    })?;
    ensure!(page.head == Some(second.position()) && page.records == vec![second.clone()]);
    ensure!(
        store
            .inspect_public_stream(reader, stream(2))?
            .head
            .is_none()
    );
    store.retire_published_history(stream(1), second.position(), 1)?;
    for id in [1, 2] {
        ensure!(matches!(
            publish(store, stream(1), id, b"retry"),
            Err(FederationError::Indeterminate)
        ));
    }
    ensure!(matches!(
        publish(store, stream(2), 3, b"rejected"),
        Err(FederationError::Capacity)
    ));
    let view = store.inspect_public_stream(reader, stream(1))?;
    ensure!(view.head == Some(second.position()) && view.minimum_available == 3);
    Ok(())
}

fn options(limit: usize) -> Result<RedbOptions> {
    Ok(RedbOptions {
        federation_publish_id_limit: NonZeroUsize::new(limit)
            .ok_or_else(|| anyhow::anyhow!("zero limit"))?,
        ..RedbOptions::default()
    })
}

#[test]
fn memory_retains_publish_id_quota_across_streams_and_pruning() -> Result<()> {
    quota_contract(&MemoryFederationStore::with_publish_id_limit(
        node(),
        options(2)?.federation_publish_id_limit,
    ))
}

#[test]
fn redb_retains_publish_id_quota_across_streams_and_pruning() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open_with_options(directory.path().join("quota.redb"), options(2)?)?;
    quota_contract(&db.federation_store(node())?)
}

#[test]
fn redb_reopen_lower_preserves_evidence_and_raise_retries_rejected_identity() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("reopen.redb");
    let first;
    let second;
    {
        let db = RedbStore::open_with_options(&path, options(2)?)?;
        let store = db.federation_store(node())?;
        declare(&store, 1)?;
        declare(&store, 2)?;
        first = publish(&store, stream(1), 1, b"first")?;
        second = publish(&store, stream(1), 2, b"second")?;
        ensure!(matches!(
            publish(&store, stream(1), 3, b"third"),
            Err(FederationError::Capacity)
        ));
        ensure!(matches!(
            publish(&store, stream(2), 3, b"third"),
            Err(FederationError::Capacity)
        ));
    }
    {
        let db = RedbStore::open_with_options(&path, options(1)?)?;
        let store = db.federation_store(node())?;
        ensure!(publish(&store, stream(1), 1, b"first")? == first);
        ensure!(publish(&store, stream(1), 2, b"second")? == second);
        ensure!(matches!(
            publish(&store, stream(1), 2, b"changed"),
            Err(FederationError::Conflict)
        ));
        store.retire_published_history(stream(1), second.position(), 2)?;
        ensure!(matches!(
            publish(&store, stream(1), 1, b"first"),
            Err(FederationError::Indeterminate)
        ));
        ensure!(matches!(
            publish(&store, stream(1), 3, b"third"),
            Err(FederationError::Capacity)
        ));
    }
    {
        let db = RedbStore::open_with_options(&path, options(4)?)?;
        let store = db.federation_store(node())?;
        ensure!(matches!(
            publish(&store, stream(1), 2, b"second"),
            Err(FederationError::Indeterminate)
        ));
        let third = publish(&store, stream(1), 3, b"third")?;
        ensure!(third.sequence() == 3);
        ensure!(publish(&store, stream(1), 3, b"third")? == third);
        ensure!(publish(&store, stream(2), 3, b"third")?.sequence() == 1);
    }
    Ok(())
}

fn concurrent_contract<S: FederationStore + Clone + 'static>(store: S) -> Result<()> {
    for id in [1, 2] {
        store.declare_stream(StreamSpec {
            stream: stream(id),
            export: ExportName::new("quota")?,
        })?;
    }
    let barrier = Arc::new(Barrier::new(2));
    let workers = [1, 2].map(|id| {
        let store = store.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            publish(&store, stream(id), id, b"race")
        })
    });
    let mut winners = 0;
    let mut rejected = 0;
    for worker in workers {
        match worker
            .join()
            .map_err(|_panic| anyhow::anyhow!("worker panicked"))?
        {
            Ok(_) => winners += 1,
            Err(FederationError::Capacity) => rejected += 1,
            Err(error) => return Err(error.into()),
        }
    }
    ensure!(winners == 1 && rejected == 1);
    Ok(())
}

fn bound_contract(store: &(impl FederationStore + FederationPublicReadStore)) -> Result<()> {
    let root = FederationRootKey::generate()?;
    let descriptor = root.root()?;
    let peer = descriptor.node_id();
    let online = FederationOnlineKey::generate()?;
    let authorization = FederationOnlineKeyAuthorization::new(online.public_key(), 1, 100, 1000)?;
    let transcript =
        FederationSessionTranscript::new(peer, node(), [1; 32], [2; 32], [3; 48], [4; 48])?;
    let root_signature = root.sign(
        RootSignaturePurpose::OnlineKeyAuthorization,
        &authorization.encode(),
    )?;
    let online_signature = online.sign_session(peer, &authorization, &transcript)?;
    let proof = verify_federation_peer_proof(
        &descriptor,
        peer,
        &authorization,
        &root_signature,
        &transcript,
        &online_signature,
        500,
    )?;
    store.set_peer_authority(peer, None, true)?;
    store.set_peer_admission(
        peer,
        None,
        PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![proof.authorization_digest()],
        },
    )?;
    let bound = store.bind_decision(FederationDecision::new(
        proof,
        FederationAdmission::Private,
        Arc::new(|| Ok(500)),
    ))?;
    declare(store, 1)?;
    declare(store, 2)?;
    let first = publish(store, stream(1), 1, b"first")?;
    ensure!(publish(&bound, stream(1), 1, b"first")? == first);
    ensure!(matches!(
        publish(&bound, stream(2), 2, b"rejected"),
        Err(FederationError::Capacity)
    ));
    store.retire_published_history(stream(1), first.position(), 1)?;
    ensure!(matches!(
        publish(&bound, stream(1), 1, b"first"),
        Err(FederationError::Indeterminate)
    ));
    ensure!(matches!(
        publish(&bound, stream(2), 2, b"rejected"),
        Err(FederationError::Capacity)
    ));
    Ok(())
}

#[test]
fn memory_bound_view_shares_publish_identity_quota() -> Result<()> {
    bound_contract(&MemoryFederationStore::with_publish_id_limit(
        node(),
        NonZeroUsize::MIN,
    ))
}

#[test]
fn redb_bound_view_shares_publish_identity_quota() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open_with_options(directory.path().join("bound.redb"), options(1)?)?;
    bound_contract(&db.federation_store(node())?)
}

#[test]
fn memory_clones_share_one_concurrent_publish_slot() -> Result<()> {
    concurrent_contract(MemoryFederationStore::with_publish_id_limit(
        node(),
        NonZeroUsize::MIN,
    ))
}

#[test]
fn redb_views_share_one_concurrent_publish_slot() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open_with_options(directory.path().join("race.redb"), options(1)?)?;
    concurrent_contract(db.federation_store(node())?)
}

fn epoch_request(retry_epoch: u64, id: u64) -> Result<PublishRequest> {
    let mut identity = [0; 16];
    identity[8..].copy_from_slice(&id.to_be_bytes());
    Ok(PublishRequest {
        stream: stream(1),
        retry_epoch,
        publish_id: RequestId::from_bytes(identity),
        event_type: EventType::new("epoch.event")?,
        schema_revision: SchemaRevision::from_bytes([2; 32]),
        event_ref: None,
        payload: Arc::from(b"epoch".as_slice()),
    })
}

fn epoch_contract(
    store: &(impl FederationStore + FederationPublicReadStore),
) -> Result<(RequestId, Position)> {
    declare(store, 1)?;
    let known = epoch_request(1, 1)?;
    let unknown = epoch_request(1, 2)?;
    let known_record = store.append_published(known.clone())?;
    let unknown_record = store.append_published(unknown.clone())?;
    let confirmed = known.receipt(&known_record)?;
    ensure!(matches!(
        store.retire_publication_identities(&[confirmed]),
        Err(FederationError::Conflict)
    ));
    ensure!(store.close_publication_epoch(stream(1), 1)? == 2);
    ensure!(matches!(
        store.append_published(unknown.clone()),
        Err(FederationError::Conflict)
    ));
    let wrong = PublicationReceipt {
        position: Position::new(confirmed.position.sequence(), Digest::from_bytes([9; 48]))?,
        ..confirmed
    };
    ensure!(matches!(
        store.retire_publication_identities(&[confirmed, wrong]),
        Err(FederationError::Conflict)
    ));
    ensure!(
        store.inspect_publication(stream(1), 1, known.publish_id)? == Some(known_record.position())
    );
    ensure!(store.retire_publication_identities(&[confirmed])? == 1);
    ensure!(store.retire_publication_identities(&[confirmed])? == 0);
    ensure!(matches!(
        store.append_published(known),
        Err(FederationError::Conflict)
    ));
    ensure!(
        store.inspect_publication(stream(1), 1, unknown.publish_id)?
            == Some(unknown_record.position())
    );
    let new = epoch_request(2, 3)?;
    let record = store.append_published(new.clone())?;
    ensure!(record.sequence() == 3);
    ensure!(store.close_publication_epoch(stream(1), 2)? == 3);
    store.retire_publication_identities(&[new.receipt(&record)?])?;
    store.retire_published_history(stream(1), record.position(), 3)?;
    ensure!(
        store.inspect_publication(stream(1), 1, unknown.publish_id)?
            == Some(unknown_record.position())
    );
    Ok((unknown.publish_id, unknown_record.position()))
}

#[test]
fn memory_closed_epochs_reject_stale_append_and_preserve_unknown_evidence() -> Result<()> {
    epoch_contract(&MemoryFederationStore::with_publish_id_limit(
        node(),
        NonZeroUsize::new(2).ok_or_else(|| anyhow::anyhow!("limit"))?,
    ))?;
    Ok(())
}

#[test]
fn redb_closed_epochs_and_unknown_evidence_survive_reopen_and_payload_trim() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("epochs.redb");
    let (identity, position) = {
        let db = RedbStore::open_with_options(&path, options(2)?)?;
        epoch_contract(&db.federation_store(node())?)?
    };
    let db = RedbStore::open_with_options(&path, options(2)?)?;
    let store = db.federation_store(node())?;
    ensure!(store.publication_epoch(stream(1))? == 3);
    ensure!(store.inspect_publication(stream(1), 1, identity)? == Some(position));
    ensure!(matches!(
        store.append_published(epoch_request(1, 1)?),
        Err(FederationError::Conflict)
    ));
    ensure!(store.append_published(epoch_request(3, 4)?)?.sequence() == 4);
    Ok(())
}

#[test]
fn released_identity_slots_support_more_than_65536_publications() -> Result<()> {
    let store = MemoryFederationStore::with_publish_id_limit(node(), NonZeroUsize::MIN);
    declare(&store, 1)?;
    for identity in 1..=65_537 {
        let request = epoch_request(identity, identity)?;
        let record = store.append_published(request.clone())?;
        store.close_publication_epoch(stream(1), identity)?;
        store.retire_publication_identities(&[request.receipt(&record)?])?;
        store.retire_published_history(stream(1), record.position(), 1)?;
    }
    ensure!(store.publication_epoch(stream(1))? == 65_538);
    ensure!(matches!(
        store.append_published(epoch_request(1, 1)?),
        Err(FederationError::Conflict)
    ));
    Ok(())
}
