#![cfg(feature = "federation")]

use std::sync::{Arc, Barrier};

use anyhow::{Context, Result, ensure};
use xolotl_federation::{
    EventType, ExportName, FederationError, FederationInvitationStore, FederationNodeId,
    FederationStore, GrantHistory, HostedSubject, INVITATION_RECEIPT_RETENTION_MS,
    InvitationAudience, InvitationId, InvitationSecret, InvitationSpec, PublishRequest,
    RedeemInvitationRequest, RequestId, SchemaRevision, StreamId, StreamRef, StreamSpec,
    SubjectGrantKey, SubjectIssuerId,
};
use xolotl_storage_redb::RedbStore;

fn subject(id: u8) -> HostedSubject {
    HostedSubject {
        issuer: SubjectIssuerId::from_bytes([81; 48]),
        namespace: "people".into(),
        subject: format!("user-{id}"),
    }
}

fn spec(
    issuer: HostedSubject,
    stream: StreamRef,
    audience: InvitationAudience,
    max_redemptions: u32,
) -> InvitationSpec {
    InvitationSpec {
        issuer,
        stream,
        audience,
        not_before_ms: 10,
        expires_ms: 100,
        grant_expires_ms: 100,
        max_redemptions,
        history: GrantHistory::FromGrant,
    }
}

#[test]
fn named_invitation_redeems_atomically_and_replay_never_revives_access() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("federation.redb");
    let node = FederationNodeId::from_bytes([1; 48]);
    let peer = FederationNodeId::from_bytes([2; 48]);
    let stream = StreamRef {
        publisher: node,
        id: StreamId::from_bytes([3; 16]),
    };
    let issuer = subject(1);
    let invited = subject(2);
    let id = InvitationId::from_bytes([4; 16]);
    let request_id = RequestId::from_bytes([5; 16]);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    store.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("album")?,
    })?;
    store.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([6; 16]),
        event_type: EventType::new("photo")?,
        schema_revision: SchemaRevision::from_bytes([7; 32]),
        event_ref: None,
        payload: Arc::from(b"older".as_slice()),
    })?;
    store.set_invitation_issuer_authority(&issuer, stream, None, true)?;
    let invitation = spec(
        issuer,
        stream,
        InvitationAudience::Named {
            presenter: peer,
            subject: invited.clone(),
        },
        1,
    );
    let created = store.create_invitation(id, invitation.clone(), 10)?;
    ensure!(created.revision == 1 && created.redemptions == 0);
    ensure!(store.create_invitation(id, invitation.clone(), 11)? == created);
    let request = RedeemInvitationRequest {
        invitation: id,
        request_id,
        authenticated_presenter: peer,
        subject: invited.clone(),
        expected_invitation_revision: 1,
        secret: None,
        now_ms: 20,
    };
    let accepted = store.redeem_invitation(request.clone())?;
    ensure!(accepted.currently_authorized && accepted.grant.history_floor == 1);
    ensure!(
        store
            .invitation(id)?
            .context("invitation missing")?
            .redemptions
            == 1
    );
    let entry = store
        .subject_grant(&invited, peer, stream)?
        .context("grant missing")?;
    ensure!(entry == accepted.grant);
    let key = SubjectGrantKey {
        subject: invited,
        presenter: peer,
        stream,
    };
    ensure!(key.encoded()?.len() > 0);
    let revoked = store.revoke_invitation(id, 1)?;
    ensure!(!revoked.enabled && revoked.revision == 2);
    let replay = store.redeem_invitation(RedeemInvitationRequest {
        now_ms: 21,
        ..request.clone()
    })?;
    ensure!(replay == accepted);
    ensure!(matches!(
        store.redeem_invitation(RedeemInvitationRequest {
            request_id: RequestId::from_bytes([8; 16]),
            now_ms: 22,
            ..request.clone()
        }),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        store.redeem_invitation(RedeemInvitationRequest {
            subject: subject(3),
            now_ms: 23,
            ..request.clone()
        }),
        Err(FederationError::Conflict)
    ));
    let mut denied = accepted.grant.grant.clone();
    denied.enabled = false;
    store.set_subject_grant(Some(1), denied)?;
    let replay = store.redeem_invitation(RedeemInvitationRequest {
        now_ms: 24,
        ..request.clone()
    })?;
    ensure!(!replay.currently_authorized && replay.grant == accepted.grant);
    drop(store);
    drop(db);
    let reopened = RedbStore::open(&path)?.federation_store(node)?;
    let after_expiry = reopened.redeem_invitation(RedeemInvitationRequest {
        now_ms: 100,
        ..request
    })?;
    ensure!(!after_expiry.currently_authorized && after_expiry.grant == accepted.grant);
    let cutoff = 100 + INVITATION_RECEIPT_RETENTION_MS;
    ensure!(reopened.retire_expired_invitations(cutoff - 1, 1)? == 0);
    ensure!(reopened.retire_expired_invitations(cutoff, 1)? == 1);
    ensure!(reopened.invitation(id)?.is_none());
    ensure!(reopened.invitation_high_water()? == id);
    ensure!(matches!(
        reopened.redeem_invitation(RedeemInvitationRequest {
            invitation: id,
            request_id,
            authenticated_presenter: peer,
            subject: subject(2),
            expected_invitation_revision: 1,
            secret: None,
            now_ms: cutoff + 1,
        }),
        Err(FederationError::Indeterminate)
    ));
    ensure!(matches!(
        reopened.create_invitation(id, invitation.clone(), cutoff + 1),
        Err(FederationError::Indeterminate)
    ));
    let later = InvitationSpec {
        not_before_ms: cutoff + 1,
        expires_ms: cutoff + 101,
        grant_expires_ms: cutoff + 101,
        ..invitation
    };
    let next_id = InvitationId::from_bytes([5; 16]);
    ensure!(reopened.create_invitation(next_id, later, cutoff + 1)?.id == next_id);
    Ok(())
}

#[test]
fn configured_peer_cannot_redeem_or_query_a_guest_receipt() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let node = FederationNodeId::from_bytes([41; 48]);
    let peer = FederationNodeId::from_bytes([42; 48]);
    let stream = StreamRef {
        publisher: node,
        id: StreamId::from_bytes([43; 16]),
    };
    let issuer = subject(41);
    let accepted_subject = subject(42);
    let pending_subject = subject(43);
    let accepted_id = InvitationId::from_sequence(1);
    let pending_id = InvitationId::from_sequence(2);
    let store = RedbStore::open(dir.path().join("federation.redb"))?.federation_store(node)?;
    store.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("album")?,
    })?;
    store.set_invitation_issuer_authority(&issuer, stream, None, true)?;
    for (id, invited) in [
        (accepted_id, accepted_subject.clone()),
        (pending_id, pending_subject.clone()),
    ] {
        store.create_invitation(
            id,
            spec(
                issuer.clone(),
                stream,
                InvitationAudience::Named {
                    presenter: peer,
                    subject: invited,
                },
                1,
            ),
            10,
        )?;
    }
    let accepted_request = RedeemInvitationRequest {
        invitation: accepted_id,
        request_id: RequestId::from_bytes([44; 16]),
        authenticated_presenter: peer,
        subject: accepted_subject.clone(),
        expected_invitation_revision: 1,
        secret: None,
        now_ms: 20,
    };
    let accepted = store.redeem_invitation(accepted_request.clone())?;
    ensure!(accepted.currently_authorized);
    ensure!(
        store
            .redeem_invitation(RedeemInvitationRequest {
                now_ms: 21,
                ..accepted_request.clone()
            })?
            .currently_authorized
    );
    let pending_request = RedeemInvitationRequest {
        invitation: pending_id,
        request_id: RequestId::from_bytes([45; 16]),
        authenticated_presenter: peer,
        subject: pending_subject.clone(),
        expected_invitation_revision: 1,
        secret: None,
        now_ms: 22,
    };

    // Model a peer row committed after Guest Session admission. Both a new
    // redemption and an old receipt query must recheck this mode in the write
    // transaction, whether the configured peer is enabled or disabled.
    for (expected_revision, enabled, now_ms) in [(None, true, 22), (Some(1), false, 23)] {
        store.set_peer_authority(peer, expected_revision, enabled)?;
        ensure!(matches!(
            store.redeem_invitation(RedeemInvitationRequest {
                now_ms,
                ..accepted_request.clone()
            }),
            Err(FederationError::Unauthorized)
        ));
        ensure!(matches!(
            store.redeem_invitation(RedeemInvitationRequest {
                now_ms,
                ..pending_request.clone()
            }),
            Err(FederationError::Unauthorized)
        ));
        ensure!(
            store
                .subject_grant(&pending_subject, peer, stream)?
                .is_none()
        );
        ensure!(
            store
                .invitation(pending_id)?
                .context("invitation missing")?
                .redemptions
                == 0
        );
    }
    ensure!(store.subject_grant(&accepted_subject, peer, stream)? == Some(accepted.grant));
    Ok(())
}

#[test]
fn bearer_invitation_has_constant_secret_check_and_single_winner() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let node = FederationNodeId::from_bytes([11; 48]);
    let peers = [
        FederationNodeId::from_bytes([12; 48]),
        FederationNodeId::from_bytes([13; 48]),
    ];
    let stream = StreamRef {
        publisher: node,
        id: StreamId::from_bytes([14; 16]),
    };
    let issuer = subject(11);
    let id = InvitationId::from_bytes([15; 16]);
    let secret = InvitationSecret::from_bytes([16; 32]);
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let store = Arc::new(db.federation_store(node)?);
    store.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("one-file")?,
    })?;
    store.set_invitation_issuer_authority(&issuer, stream, None, true)?;
    store.create_invitation(
        id,
        spec(
            issuer,
            stream,
            InvitationAudience::Bearer {
                secret_digest: secret.digest(id),
            },
            1,
        ),
        10,
    )?;
    ensure!(matches!(
        store.redeem_invitation(RedeemInvitationRequest {
            invitation: id,
            request_id: RequestId::from_bytes([17; 16]),
            authenticated_presenter: peers[0],
            subject: subject(12),
            expected_invitation_revision: 1,
            secret: Some(InvitationSecret::from_bytes([0; 32])),
            now_ms: 19,
        }),
        Err(FederationError::Unauthorized)
    ));
    ensure!(
        store
            .invitation(id)?
            .context("invitation missing")?
            .redemptions
            == 0
    );
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for (index, peer) in peers.into_iter().enumerate() {
        let store = store.clone();
        let barrier = barrier.clone();
        let secret = secret.clone();
        handles.push(std::thread::spawn(move || {
            let request = RedeemInvitationRequest {
                invitation: id,
                request_id: RequestId::from_bytes([index as u8 + 20; 16]),
                authenticated_presenter: peer,
                subject: subject(index as u8 + 20),
                expected_invitation_revision: 1,
                secret: Some(secret),
                now_ms: 20,
            };
            barrier.wait();
            store.redeem_invitation(request)
        }));
    }
    barrier.wait();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| {
            handle
                .join()
                .map_err(|_error| anyhow::anyhow!("thread panicked"))
        })
        .collect::<Result<_>>()?;
    ensure!(outcomes.iter().filter(|result| result.is_ok()).count() == 1);
    ensure!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(FederationError::Unauthorized)))
            .count()
            == 1
    );
    ensure!(
        store
            .invitation(id)?
            .context("invitation missing")?
            .redemptions
            == 1
    );
    Ok(())
}

#[test]
fn manifest_ownership_is_atomic_and_cannot_claim_embedding_rows() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("federation.redb");
    let node = FederationNodeId::from_bytes([31; 48]);
    let guest = FederationNodeId::from_bytes([32; 48]);
    let stream = StreamRef {
        publisher: node,
        id: StreamId::from_bytes([33; 16]),
    };
    let embedded_issuer = subject(31);
    let manifest_issuer = subject(32);
    let embedded_id = InvitationId::from_sequence(1);
    let manifest_id = InvitationId::from_sequence(2);
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(node)?;
    store.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("shared")?,
    })?;
    ensure!(store.set_invitation_issuer_authority(&embedded_issuer, stream, None, true)? == 1);
    ensure!(
        store.set_manifest_invitation_issuer_authority(&manifest_issuer, stream, None, true)? == 1
    );
    ensure!(store.invitation_issuer_authority(&manifest_issuer, stream)? == Some((1, true)));
    ensure!(matches!(
        store.set_manifest_invitation_issuer_authority(&embedded_issuer, stream, Some(1), false),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.set_invitation_issuer_authority(&manifest_issuer, stream, Some(1), false),
        Err(FederationError::Conflict)
    ));
    let embedded_spec = spec(
        embedded_issuer,
        stream,
        InvitationAudience::Named {
            presenter: guest,
            subject: subject(33),
        },
        1,
    );
    let manifest_spec = spec(
        manifest_issuer.clone(),
        stream,
        InvitationAudience::Named {
            presenter: guest,
            subject: subject(34),
        },
        1,
    );
    store.create_invitation(embedded_id, embedded_spec.clone(), 10)?;
    let created = store.create_manifest_invitation(manifest_id, manifest_spec.clone(), 10)?;
    ensure!(matches!(
        store.create_manifest_invitation(embedded_id, embedded_spec, 11),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        store.create_invitation(manifest_id, manifest_spec.clone(), 11),
        Err(FederationError::Conflict)
    ));
    ensure!(store.create_manifest_invitation(manifest_id, manifest_spec, 11)? == created);
    let issuers = store.list_manifest_issuer_authorities(None, 1)?;
    ensure!(
        issuers.len() == 1 && issuers[0].key.issuer == manifest_issuer && issuers[0].revision == 1
    );
    ensure!(
        store
            .list_manifest_issuer_authorities(Some(&issuers[0].key), 1)?
            .is_empty()
    );
    ensure!(store.list_manifest_invitations(None, 1)? == vec![created.clone()]);
    ensure!(
        store
            .list_manifest_invitations(Some(manifest_id), 1)?
            .is_empty()
    );
    drop(store);
    drop(db);
    let store = RedbStore::open(&path)?.federation_store(node)?;
    ensure!(store.list_manifest_invitations(None, 1)? == vec![created]);
    ensure!(store.list_manifest_issuer_authorities(None, 1)?.len() == 1);
    store.revoke_invitation(manifest_id, 1)?;
    ensure!(!store.list_manifest_invitations(None, 1)?[0].enabled);
    let cutoff = 100 + INVITATION_RECEIPT_RETENTION_MS;
    ensure!(store.retire_expired_invitations(cutoff, 2)? == 2);
    ensure!(store.list_manifest_invitations(None, 1)?.is_empty());
    ensure!(store.invitation_high_water()? == manifest_id);
    Ok(())
}
