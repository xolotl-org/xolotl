#![cfg(feature = "federation")]

use std::sync::Arc;

use anyhow::{Result, ensure};
use xolotl_federation::{
    AuthorityRevision, EventType, ExportName, FederationError, FederationNodeId, HostedSubject,
    InvitationId, OpenResult, ReadPage, Record, RecordParts, RequestId, SchemaRevision, StreamId,
    StreamRef, SubjectIssuerId, SubscriptionId, SubscriptionRef,
};
use xolotl_storage_redb::{GuestFollowSpec, RedbStore};

#[path = "../../xolotl-federation/tests/support/decision_contract.rs"]
pub mod decision_contract;

#[test]
fn guest_follow_checks_expiry_at_open_install_and_accept_without_losing_staged_ids() -> Result<()> {
    use std::sync::atomic::Ordering;
    use xolotl_federation::FederationAdmission;
    let peers = decision_contract::Peers::new()?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("online-guest-follow.redb");
    let spec = spec(peers.receiver, peers.publisher);
    let opened = OpenResult {
        request_id: spec.open_request,
        subscription: spec.subscription,
        stream: spec.stream,
        export: ExportName::new("invited")?,
        publisher_authority: AuthorityRevision { peer: 0, export: 1 },
        subscription_revision: 1,
        start: None,
    };
    {
        let db = RedbStore::open(&path)?;
        let follows = db.guest_follower_store(peers.receiver)?;
        let remote = follows.with_decision(
            peers
                .decision(peers.publisher_proof, FederationAdmission::Unconfigured)
                .with_unconfigured_policy(decision_contract::admission(peers.publisher_proof))?,
        )?;
        remote.prepare(&spec)?;
        remote.mark_redeemed(&spec)?;
        peers.time.store(1000, Ordering::SeqCst);
        ensure!(matches!(
            remote.install_open(&spec, &opened),
            Err(FederationError::Unauthorized)
        ));
        ensure!(follows.inspect(&spec)?.opened.is_none());
    }
    let db = RedbStore::open(&path)?;
    let follows = db.guest_follower_store(peers.receiver)?;
    let staged = follows.inspect(&spec)?;
    ensure!(staged.redeemed && staged.opened.is_none());
    peers.time.store(150, Ordering::SeqCst);
    let remote = follows
        .with_decision(peers.decision(peers.publisher_proof, FederationAdmission::Unconfigured))?;
    ensure!(matches!(
        remote.install_open(&spec, &opened),
        Err(FederationError::ClockRollback)
    ));
    Ok(())
}

#[test]
fn guest_follow_accepts_online_records_but_rejects_a_new_configured_peer_row() -> Result<()> {
    use xolotl_federation::{FederationAdmission, FederationStore as _};
    let peers = decision_contract::Peers::new()?;
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("guest-boundary.redb"))?;
    let follows = db.guest_follower_store(peers.receiver)?;
    let authority = db.federation_store(peers.receiver)?;
    let spec = spec(peers.receiver, peers.publisher);
    let remote = follows
        .with_decision(peers.decision(peers.publisher_proof, FederationAdmission::Unconfigured))?;
    remote.prepare(&spec)?;
    remote.mark_redeemed(&spec)?;
    remote.install_open(
        &spec,
        &OpenResult {
            request_id: spec.open_request,
            subscription: spec.subscription,
            stream: spec.stream,
            export: ExportName::new("invited")?,
            publisher_authority: AuthorityRevision { peer: 0, export: 1 },
            subscription_revision: 1,
            start: None,
        },
    )?;
    let first = record(spec.stream, 1)?;
    let page = ReadPage {
        records: vec![first.clone()],
        head: Some(first.position()),
        minimum_available: 1,
    };
    ensure!(remote.accept_page(&spec, &page)?.cursor == Some(first.position()));
    authority.set_peer_authority(peers.publisher, None, true)?;
    ensure!(matches!(
        remote.accept_page(&spec, &page),
        Err(FederationError::Unauthorized)
    ));
    ensure!(follows.inspect(&spec)?.cursor == Some(first.position()));
    Ok(())
}

fn record(stream: StreamRef, sequence: u64) -> Result<Record> {
    Ok(Record::new(RecordParts {
        stream,
        sequence,
        publish_id: RequestId::from_bytes([sequence as u8; 16]),
        event_type: EventType::new("guest.event")?,
        schema_revision: SchemaRevision::from_bytes([3; 32]),
        event_ref: None,
        payload: Arc::from(vec![sequence as u8; 256]),
    })?)
}

fn spec(local: FederationNodeId, publisher: FederationNodeId) -> GuestFollowSpec {
    GuestFollowSpec {
        stream: StreamRef {
            publisher,
            id: StreamId::from_bytes([3; 16]),
        },
        subscription: SubscriptionRef {
            subscriber: local,
            id: SubscriptionId::from_bytes([4; 16]),
        },
        invitation: InvitationId::from_bytes([5; 16]),
        invitation_revision: 1,
        redeem_request: RequestId::from_bytes([6; 16]),
        open_request: RequestId::from_bytes([7; 16]),
        subject: HostedSubject {
            issuer: SubjectIssuerId::from_bytes([8; 48]),
            namespace: "people".into(),
            subject: "guest".into(),
        },
        max_inbox_records: 2,
        max_inbox_bytes: 512 * 1024,
    }
}

#[test]
fn invited_follow_stages_ids_and_recovers_exact_inbox_without_peer_authority() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("guest.redb");
    let local = FederationNodeId::from_bytes([1; 48]);
    let publisher = FederationNodeId::from_bytes([2; 48]);
    let spec = spec(local, publisher);
    let first = record(spec.stream, 1)?;
    let second = record(spec.stream, 2)?;
    let third = record(spec.stream, 3)?;
    let opened = OpenResult {
        request_id: spec.open_request,
        subscription: spec.subscription,
        stream: spec.stream,
        export: ExportName::new("invited")?,
        publisher_authority: AuthorityRevision { peer: 0, export: 1 },
        subscription_revision: 1,
        start: None,
    };
    {
        let db = RedbStore::open(&path)?;
        let follows = db.guest_follower_store(local)?;
        ensure!(
            db.federation_store(local)?
                .peer_authority(publisher)?
                .is_none()
        );
        let staged = follows.prepare(&spec)?;
        ensure!(!staged.redeemed && staged.opened.is_none());
        ensure!(follows.prepare(&spec)? == staged);
        follows.mark_redeemed(&spec)?;
        follows.install_open(&spec, &opened)?;
        let page = ReadPage {
            records: vec![first.clone(), second.clone()],
            head: Some(second.position()),
            minimum_available: 1,
        };
        let accepted = follows.accept_page(&spec, &page)?;
        ensure!(accepted.cursor == Some(second.position()) && accepted.retained_records == 2);
        ensure!(follows.accept_page(&spec, &page)?.cursor == accepted.cursor);
        ensure!(follows.read_inbox(&spec, None, 8, 512 * 1024)?.records == page.records);
        let mut changed = spec.clone();
        changed.subject.subject.push_str("-changed");
        ensure!(matches!(
            follows.prepare(&changed),
            Err(FederationError::Conflict)
        ));
    }
    {
        let db = RedbStore::open(&path)?;
        let follows = db.guest_follower_store(local)?;
        ensure!(follows.inspect(&spec)?.opened == Some(opened));
        let accepted = follows.accept_page(
            &spec,
            &ReadPage {
                records: vec![third.clone()],
                head: Some(third.position()),
                minimum_available: 2,
            },
        )?;
        ensure!(accepted.cursor == Some(third.position()));
        ensure!(accepted.local_minimum_available == 2 && accepted.retained_records == 2);
        ensure!(
            follows.read_inbox(&spec, None, 8, 512 * 1024)?.records == vec![second, third.clone()]
        );
        ensure!(matches!(
            follows.read_inbox(&spec, Some(first.position()), 8, 512 * 1024),
            Err(FederationError::ResyncRequired {
                minimum_available: 2
            })
        ));
        ensure!(matches!(
            follows.accept_page(
                &spec,
                &ReadPage {
                    records: vec![],
                    head: Some(third.position()),
                    minimum_available: 5,
                }
            ),
            Err(FederationError::ResyncRequired {
                minimum_available: 5
            })
        ));
        ensure!(
            db.federation_store(local)?
                .peer_authority(publisher)?
                .is_none()
        );
    }
    Ok(())
}
