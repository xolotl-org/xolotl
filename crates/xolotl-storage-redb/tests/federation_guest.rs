#![cfg(feature = "federation")]

use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use xolotl_federation::{
    AcknowledgeRequest, CloseSubscriptionRequest, EventType, ExportName, FederationError,
    FederationGuestStore, FederationInvitationStore, FederationNodeId, FederationStore,
    FederationSubject, GrantHistory, HistoryStart, HostedSubject, InspectSubscriptionRequest,
    InvitationAudience, InvitationId, InvitationSpec, OpenRequest, PublishRequest, ReadRequest,
    RedeemInvitationRequest, RequestId, SchemaRevision, StreamId, StreamRef, StreamSpec,
    SubjectGrant, SubjectIssuerId, SubscriptionId, SubscriptionRef,
};
use xolotl_storage_redb::RedbStore;

const NODE: FederationNodeId = FederationNodeId::from_bytes([51; 48]);
const GUEST: FederationNodeId = FederationNodeId::from_bytes([52; 48]);
const STREAM: StreamRef = StreamRef {
    publisher: NODE,
    id: StreamId::from_bytes([53; 16]),
};

fn person(name: &str) -> HostedSubject {
    HostedSubject {
        issuer: SubjectIssuerId::from_bytes([54; 48]),
        namespace: "people".into(),
        subject: name.into(),
    }
}

fn invitation(subject: HostedSubject, presenter: FederationNodeId) -> InvitationSpec {
    InvitationSpec {
        issuer: person("issuer"),
        stream: STREAM,
        audience: InvitationAudience::Named { presenter, subject },
        not_before_ms: 10,
        expires_ms: 200,
        grant_expires_ms: 200,
        max_redemptions: 1,
        history: GrantHistory::All,
    }
}

fn open(presenter: FederationNodeId, request_id: u8, subscription_id: u8) -> OpenRequest {
    OpenRequest {
        authenticated_subscriber: presenter,
        request_id: RequestId::from_bytes([request_id; 16]),
        subscription: SubscriptionRef {
            subscriber: presenter,
            id: SubscriptionId::from_bytes([subscription_id; 16]),
        },
        stream: STREAM,
        expected_control_revision: None,
        history: HistoryStart::All,
    }
}

fn read(open: &OpenRequest) -> ReadRequest {
    ReadRequest {
        authenticated_subscriber: open.authenticated_subscriber,
        subscription: open.subscription,
        after: None,
        max_records: 8,
        max_bytes: 1024,
    }
}

#[test]
fn unknown_node_guest_uses_only_redeemed_invitation_and_survives_restart() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("federation.redb");
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(NODE)?;
    let subject = person("guest");
    let invite_id = InvitationId::from_sequence(1);
    store.declare_stream(StreamSpec {
        stream: STREAM,
        export: ExportName::new("pictures")?,
    })?;
    let record = store.append_published(PublishRequest {
        retry_epoch: 1,
        stream: STREAM,
        publish_id: RequestId::from_bytes([55; 16]),
        event_type: EventType::new("picture")?,
        schema_revision: SchemaRevision::from_bytes([56; 32]),
        event_ref: None,
        payload: Arc::from(b"picture".as_slice()),
    })?;
    store.set_invitation_issuer_authority(&person("issuer"), STREAM, None, true)?;
    store.create_invitation(invite_id, invitation(subject.clone(), GUEST), 10)?;
    let request = open(GUEST, 57, 58);
    ensure!(matches!(
        store.open_guest(subject.clone(), 20, request.clone()),
        Err(FederationError::Unauthorized)
    ));
    let redemption = store.redeem_invitation(RedeemInvitationRequest {
        invitation: invite_id,
        request_id: RequestId::from_bytes([59; 16]),
        authenticated_presenter: GUEST,
        subject: subject.clone(),
        expected_invitation_revision: 1,
        secret: None,
        now_ms: 20,
    })?;
    ensure!(redemption.currently_authorized);
    ensure!(matches!(
        store.open_as(
            FederationSubject::Hosted(subject.clone()),
            21,
            request.clone()
        ),
        Err(FederationError::Unauthorized)
    ));
    let opened = store.open_guest(subject.clone(), 21, request.clone())?;
    ensure!(opened.subscription_revision == 1);
    ensure!(
        store
            .read_guest(subject.clone(), 22, read(&request))?
            .records
            == vec![record.clone()]
    );
    ensure!(matches!(
        store.read_as(
            FederationSubject::Hosted(subject.clone()),
            22,
            read(&request)
        ),
        Err(FederationError::Unauthorized)
    ));
    drop(store);
    drop(db);

    let store = RedbStore::open(&path)?.federation_store(NODE)?;
    store.revoke_invitation(invite_id, 1)?;
    let inspection = store.inspect_guest_subscription(
        subject.clone(),
        23,
        InspectSubscriptionRequest {
            authenticated_subscriber: GUEST,
            subscription: request.subscription,
        },
    )?;
    ensure!(!inspection.closed && inspection.head == Some(record.position()));
    ensure!(
        store
            .read_guest(subject.clone(), 23, read(&request))?
            .records
            == vec![record.clone()]
    );
    ensure!(
        store.acknowledge_guest(
            subject.clone(),
            24,
            AcknowledgeRequest {
                authenticated_subscriber: GUEST,
                subscription: request.subscription,
                position: record.position(),
            }
        )? == record.position()
    );
    let closed = store.close_guest_subscription(
        subject.clone(),
        25,
        CloseSubscriptionRequest {
            authenticated_subscriber: GUEST,
            request_id: RequestId::from_bytes([60; 16]),
            subscription: request.subscription,
            expected_subscription_revision: Some(1),
        },
    )?;
    ensure!(closed.subscription_revision == 2);
    ensure!(matches!(
        store.read_guest(subject.clone(), 26, read(&request)),
        Err(FederationError::Conflict)
    ));

    let next = open(GUEST, 61, 62);
    store.open_guest(subject.clone(), 27, next.clone())?;
    let mut revoked = redemption.grant.grant;
    revoked.enabled = false;
    ensure!(store.set_subject_grant(Some(1), revoked)? == 2);
    ensure!(matches!(
        store.read_guest(subject, 28, read(&next)),
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}

#[test]
fn configured_peer_cannot_continue_an_existing_guest_subscription() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let store = db.federation_store(NODE)?;
    let subject = person("guest");
    store.declare_stream(StreamSpec {
        stream: STREAM,
        export: ExportName::new("pictures")?,
    })?;
    let record = store.append_published(PublishRequest {
        retry_epoch: 1,
        stream: STREAM,
        publish_id: RequestId::from_bytes([70; 16]),
        event_type: EventType::new("picture")?,
        schema_revision: SchemaRevision::from_bytes([71; 32]),
        event_ref: None,
        payload: Arc::from(b"picture".as_slice()),
    })?;
    store.set_invitation_issuer_authority(&person("issuer"), STREAM, None, true)?;
    let invite = InvitationId::from_sequence(1);
    store.create_invitation(invite, invitation(subject.clone(), GUEST), 10)?;
    store.redeem_invitation(RedeemInvitationRequest {
        invitation: invite,
        request_id: RequestId::from_bytes([72; 16]),
        authenticated_presenter: GUEST,
        subject: subject.clone(),
        expected_invitation_revision: 1,
        secret: None,
        now_ms: 20,
    })?;
    let active = open(GUEST, 73, 74);
    store.open_guest(subject.clone(), 21, active.clone())?;
    ensure!(
        store
            .read_guest(subject.clone(), 22, read(&active))?
            .records
            == vec![record.clone()]
    );

    // Model a peer row committed after Session admission but before a guest
    // operation reaches its own redb transaction.
    for (expected_revision, enabled) in [(None, true), (Some(1), false)] {
        store.set_peer_authority(GUEST, expected_revision, enabled)?;
        ensure!(matches!(
            store.open_guest(subject.clone(), 23, open(GUEST, 75, 76)),
            Err(FederationError::Unauthorized)
        ));
        ensure!(matches!(
            store.inspect_guest_subscription(
                subject.clone(),
                23,
                InspectSubscriptionRequest {
                    authenticated_subscriber: GUEST,
                    subscription: active.subscription,
                },
            ),
            Err(FederationError::Unauthorized)
        ));
        ensure!(matches!(
            store.read_guest(subject.clone(), 23, read(&active)),
            Err(FederationError::Unauthorized)
        ));
        ensure!(matches!(
            store.acknowledge_guest(
                subject.clone(),
                23,
                AcknowledgeRequest {
                    authenticated_subscriber: GUEST,
                    subscription: active.subscription,
                    position: record.position(),
                },
            ),
            Err(FederationError::Unauthorized)
        ));
        ensure!(matches!(
            store.close_guest_subscription(
                subject.clone(),
                23,
                CloseSubscriptionRequest {
                    authenticated_subscriber: GUEST,
                    request_id: RequestId::from_bytes([77; 16]),
                    subscription: active.subscription,
                    expected_subscription_revision: Some(1),
                },
            ),
            Err(FederationError::Unauthorized)
        ));
    }
    ensure!(
        store
            .subject_grant(&subject, GUEST, STREAM)?
            .is_some_and(|row| row.grant.enabled)
    );
    Ok(())
}

#[test]
fn guest_cannot_use_managed_grant_and_disabled_peer_blocks_redemption() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = RedbStore::open(dir.path().join("federation.redb"))?;
    let store = db.federation_store(NODE)?;
    store.declare_stream(StreamSpec {
        stream: STREAM,
        export: ExportName::new("pictures")?,
    })?;
    store.set_peer_authority(GUEST, None, true)?;
    let subject = person("managed");
    store.set_subject_grant(
        None,
        SubjectGrant {
            subject: subject.clone(),
            presenter: GUEST,
            stream: STREAM,
            not_before_ms: 10,
            expires_ms: 200,
            history: GrantHistory::All,
            enabled: true,
        },
    )?;
    ensure!(matches!(
        store.open_guest(subject.clone(), 20, open(GUEST, 63, 64)),
        Err(FederationError::Unauthorized)
    ));
    // Guest-only admission must not change an enabled managed peer's grant.
    ensure!(
        store
            .open_as(FederationSubject::Hosted(subject), 20, open(GUEST, 66, 67))
            .is_ok()
    );
    store.set_peer_authority(GUEST, Some(1), false)?;
    store.set_invitation_issuer_authority(&person("issuer"), STREAM, None, true)?;
    let id = InvitationId::from_sequence(1);
    let invited = person("invited");
    store.create_invitation(id, invitation(invited.clone(), GUEST), 10)?;
    ensure!(matches!(
        store.redeem_invitation(RedeemInvitationRequest {
            invitation: id,
            request_id: RequestId::from_bytes([65; 16]),
            authenticated_presenter: GUEST,
            subject: invited.clone(),
            expected_invitation_revision: 1,
            secret: None,
            now_ms: 21,
        }),
        Err(FederationError::Unauthorized)
    ));
    ensure!(store.subject_grant(&invited, GUEST, STREAM)?.is_none());
    ensure!(
        store
            .invitation(id)?
            .context("invitation missing")?
            .redemptions
            == 0
    );
    Ok(())
}
