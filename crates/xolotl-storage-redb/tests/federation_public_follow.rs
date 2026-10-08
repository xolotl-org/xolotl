#![cfg(feature = "federation")]

use std::sync::Arc;

use anyhow::{Result, ensure};
use xolotl_federation::{
    EventType, ExportName, FederationError, FederationNodeId, PublicReadPage, PublicStreamView,
    Record, RecordParts, RequestId, SchemaRevision, StreamId, StreamRef,
};
use xolotl_storage_redb::RedbStore;

#[path = "../../xolotl-federation/tests/support/decision_contract.rs"]
pub mod decision_contract;

#[test]
fn public_follow_checks_publisher_pin_and_peer_boundary_at_accept_and_reopen() -> Result<()> {
    use xolotl_federation::{FederationAdmission, FederationStore as _};
    let peers = decision_contract::Peers::new()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("online-public-follow.redb");
    let stream = peers.stream();
    let first = record(stream, 1)?;
    let second = record(stream, 2)?;
    {
        let db = RedbStore::open(&path)?;
        let follows = db.public_follower_store(peers.receiver)?;
        let authority = db.federation_store(peers.receiver)?;
        let decision = peers
            .decision(peers.publisher_proof, FederationAdmission::Unconfigured)
            .with_unconfigured_policy(decision_contract::admission(peers.publisher_proof))?;
        let remote = follows.with_decision(decision)?;
        remote.observe(&view(stream, 1, 1)?)?;
        let page = PublicReadPage {
            policy_revision: 1,
            records: vec![first.clone()],
            head: Some(first.position()),
            minimum_available: 1,
        };
        ensure!(remote.accept_page(stream, &page, 4, 512 * 1024)?.cursor == Some(first.position()));
        authority.set_peer_authority(peers.publisher, None, false)?;
        let page = PublicReadPage {
            policy_revision: 1,
            records: vec![second.clone()],
            head: Some(second.position()),
            minimum_available: 1,
        };
        ensure!(matches!(
            remote.accept_page(stream, &page, 4, 512 * 1024),
            Err(FederationError::Unauthorized)
        ));
        ensure!(
            follows
                .inspect(stream)?
                .is_some_and(|state| state.cursor == Some(first.position()))
        );
    }
    let db = RedbStore::open(&path)?;
    let follows = db.public_follower_store(peers.receiver)?;
    ensure!(
        follows
            .inspect(stream)?
            .is_some_and(|state| state.cursor == Some(first.position()))
    );
    let remote = follows
        .with_decision(peers.decision(peers.publisher_proof, FederationAdmission::Unconfigured))?;
    ensure!(matches!(
        remote.observe(&view(stream, 1, 1)?),
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}

fn record(stream: StreamRef, sequence: u64) -> Result<Record> {
    Ok(Record::new(RecordParts {
        stream,
        sequence,
        publish_id: RequestId::from_bytes([sequence as u8; 16]),
        event_type: EventType::new("public.event")?,
        schema_revision: SchemaRevision::from_bytes([3; 32]),
        event_ref: None,
        payload: Arc::from(vec![sequence as u8; 256]),
    })?)
}

fn view(stream: StreamRef, revision: u64, minimum_available: u64) -> Result<PublicStreamView> {
    Ok(PublicStreamView {
        stream,
        export: ExportName::new("public")?,
        policy_revision: revision,
        head: None,
        minimum_available,
        max_read_records: 128,
        max_read_bytes: 512 * 1024,
    })
}

#[test]
fn public_follower_cursor_survives_restart_and_inbox_has_explicit_bounds_and_gaps() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("follow.redb");
    let local = FederationNodeId::from_bytes([81; 48]);
    let publisher = FederationNodeId::from_bytes([82; 48]);
    let stream = StreamRef {
        publisher,
        id: StreamId::from_bytes([83; 16]),
    };
    let first = record(stream, 1)?;
    let second = record(stream, 2)?;
    let third = record(stream, 3)?;
    {
        let db = RedbStore::open(&path)?;
        let follow = db.public_follower_store(local)?;
        ensure!(follow.inspect(stream)?.is_none());
        ensure!(follow.observe(&view(stream, 1, 1)?)?.cursor.is_none());
        let page = PublicReadPage {
            policy_revision: 1,
            records: vec![first.clone(), second.clone()],
            head: Some(second.position()),
            minimum_available: 1,
        };
        let accepted = follow.accept_page(stream, &page, 2, 512 * 1024)?;
        ensure!(accepted.cursor == Some(second.position()) && accepted.retained_records == 2);
        ensure!(follow.read_inbox(stream, None, 2, 512 * 1024)?.records == page.records);
        ensure!(matches!(
            follow.accept_page(stream, &page, 2, 512 * 1024),
            Err(FederationError::Conflict)
        ));
    }
    {
        let db = RedbStore::open(&path)?;
        let follow = db.public_follower_store(local)?;
        ensure!(follow.inspect(stream)?.and_then(|state| state.cursor) == Some(second.position()));
        let page = PublicReadPage {
            policy_revision: 1,
            records: vec![third.clone()],
            head: Some(third.position()),
            minimum_available: 2,
        };
        let accepted = follow.accept_page(stream, &page, 2, 512 * 1024)?;
        ensure!(accepted.cursor == Some(third.position()));
        ensure!(accepted.local_minimum_available == 2 && accepted.retained_records == 2);
        ensure!(
            follow.read_inbox(stream, None, 2, 512 * 1024)?.records == vec![second, third.clone()]
        );
        ensure!(matches!(
            follow.read_inbox(stream, Some(first.position()), 2, 512 * 1024),
            Err(FederationError::ResyncRequired {
                minimum_available: 2
            })
        ));
        let mut updated = view(stream, 2, 3)?;
        updated.head = Some(third.position());
        ensure!(follow.observe(&updated)?.policy_revision == 2);
        ensure!(matches!(
            follow.observe(&view(stream, 3, 5)?),
            Err(FederationError::ResyncRequired {
                minimum_available: 5
            })
        ));
        ensure!(
            follow
                .inspect(stream)?
                .is_some_and(|state| state.policy_revision == 2)
        );
    }
    Ok(())
}
