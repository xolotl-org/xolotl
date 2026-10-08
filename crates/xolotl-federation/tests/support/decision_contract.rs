use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use anyhow::{Result, ensure};
use xolotl_federation::*;

pub struct Peers {
    pub publisher: FederationNodeId,
    pub receiver: FederationNodeId,
    pub publisher_proof: VerifiedFederationPeerProof,
    pub receiver_proof: VerifiedFederationPeerProof,
    pub receiver_replacement: VerifiedFederationPeerProof,
    pub time: Arc<AtomicU64>,
}

pub fn proof(
    root: &FederationRootKey,
    audience: FederationNodeId,
    generation: u64,
) -> Result<VerifiedFederationPeerProof> {
    let descriptor = root.root()?;
    let online = FederationOnlineKey::generate()?;
    let authorization =
        FederationOnlineKeyAuthorization::new(online.public_key(), generation, 100, 1000)?;
    let transcript = FederationSessionTranscript::new(
        descriptor.node_id(),
        audience,
        [3; 32],
        [4; 32],
        [5; 48],
        [6; 48],
    )?;
    let root_signature = root.sign(
        RootSignaturePurpose::OnlineKeyAuthorization,
        &authorization.encode(),
    )?;
    let online_signature =
        online.sign_session(descriptor.node_id(), &authorization, &transcript)?;
    Ok(verify_federation_peer_proof(
        &descriptor,
        descriptor.node_id(),
        &authorization,
        &root_signature,
        &transcript,
        &online_signature,
        150,
    )?)
}

impl Peers {
    pub fn new() -> Result<Self> {
        let publisher_key = FederationRootKey::generate()?;
        let receiver_key = FederationRootKey::generate()?;
        let publisher = publisher_key.root()?.node_id();
        let receiver = receiver_key.root()?.node_id();
        Ok(Self {
            publisher,
            receiver,
            publisher_proof: proof(&publisher_key, receiver, 1)?,
            receiver_proof: proof(&receiver_key, publisher, 1)?,
            receiver_replacement: proof(&receiver_key, publisher, 2)?,
            time: Arc::new(AtomicU64::new(150)),
        })
    }

    pub fn decision(
        &self,
        proof: VerifiedFederationPeerProof,
        admission: FederationAdmission,
    ) -> FederationDecision {
        let time = Arc::clone(&self.time);
        FederationDecision::new(
            proof,
            admission,
            Arc::new(move || Ok(time.load(Ordering::SeqCst))),
        )
    }

    pub fn stream(&self) -> StreamRef {
        StreamRef {
            publisher: self.publisher,
            id: StreamId::from_bytes([7; 16]),
        }
    }

    pub fn subscription(&self) -> SubscriptionRef {
        SubscriptionRef {
            subscriber: self.receiver,
            id: SubscriptionId::from_bytes([8; 16]),
        }
    }

    pub fn open(&self) -> OpenRequest {
        OpenRequest {
            authenticated_subscriber: self.receiver,
            request_id: RequestId::from_bytes([9; 16]),
            subscription: self.subscription(),
            stream: self.stream(),
            expected_control_revision: Some(0),
            history: HistoryStart::All,
        }
    }
}

pub fn admission(proof: VerifiedFederationPeerProof) -> PeerAdmission {
    PeerAdmission {
        minimum_online_generation: proof.online_generation(),
        allowed_authorization_digests: vec![proof.authorization_digest()],
    }
}

pub fn publisher_setup(peers: &Peers, store: &dyn FederationStore) -> Result<Record> {
    store.set_peer_authority(peers.receiver, None, true)?;
    store.set_peer_admission(peers.receiver, None, admission(peers.receiver_proof))?;
    store.set_export_authority(
        peers.receiver,
        ExportName::new("notes")?,
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    store.declare_stream(StreamSpec {
        stream: peers.stream(),
        export: ExportName::new("notes")?,
    })?;
    Ok(store.append_published(PublishRequest {
        retry_epoch: 1,
        stream: peers.stream(),
        publish_id: RequestId::from_bytes([10; 16]),
        event_type: EventType::new("note")?,
        schema_revision: SchemaRevision::from_bytes([11; 32]),
        event_ref: None,
        payload: Arc::from(b"record".as_slice()),
    })?)
}

pub fn publisher_contract(peers: &Peers, store: &dyn FederationStore) -> Result<()> {
    publisher_setup(peers, store)?;
    let remote =
        store.bind_decision(peers.decision(peers.receiver_proof, FederationAdmission::Private))?;
    store.set_peer_admission(
        peers.receiver,
        Some(1),
        admission(peers.receiver_replacement),
    )?;
    ensure!(matches!(
        remote.open(peers.open()),
        Err(FederationError::Unauthorized)
    ));
    let replacement = store
        .bind_decision(peers.decision(peers.receiver_replacement, FederationAdmission::Private))?;
    let opened = replacement.open(peers.open())?;
    ensure!(opened.subscription_revision == 1);
    let read = ReadRequest {
        authenticated_subscriber: peers.receiver,
        subscription: peers.subscription(),
        after: None,
        max_records: 4,
        max_bytes: 1024,
    };
    ensure!(replacement.read(read.clone())?.records.len() == 1);
    ensure!(matches!(
        remote.read(read.clone()),
        Err(FederationError::Unauthorized)
    ));
    peers.time.store(1000, Ordering::SeqCst);
    ensure!(matches!(
        replacement.read(read.clone()),
        Err(FederationError::Unauthorized)
    ));
    peers.time.store(150, Ordering::SeqCst);
    ensure!(matches!(
        replacement.read(read),
        Err(FederationError::ClockRollback)
    ));
    peers.time.store(1001, Ordering::SeqCst);
    Ok(())
}

pub fn rejected_write_retains_time_contract(
    peers: &Peers,
    store: &dyn FederationStore,
) -> Result<()> {
    publisher_setup(peers, store)?;
    let remote =
        store.bind_decision(peers.decision(peers.receiver_proof, FederationAdmission::Private))?;
    peers.time.store(500, Ordering::SeqCst);
    ensure!(matches!(
        remote.set_peer_authority(peers.receiver, Some(999), false),
        Err(FederationError::Conflict)
    ));
    peers.time.store(400, Ordering::SeqCst);
    ensure!(matches!(
        remote.set_peer_authority(peers.receiver, Some(1), false),
        Err(FederationError::ClockRollback)
    ));
    peers.time.store(500, Ordering::SeqCst);
    ensure!(remote.open(peers.open())?.subscription_revision == 1);
    Ok(())
}

pub fn receiver_contract(
    peers: &Peers,
    publisher: &dyn FederationStore,
    receiver: &dyn FederationStore,
) -> Result<()> {
    let record = publisher_setup(peers, publisher)?;
    let opened = publisher.open(peers.open())?;
    receiver.set_peer_authority(peers.publisher, None, true)?;
    receiver.set_peer_admission(peers.publisher, None, admission(peers.publisher_proof))?;
    receiver.set_export_authority(
        peers.publisher,
        opened.export.clone(),
        None,
        ExportAccess {
            serve: false,
            receive: true,
        },
    )?;
    let remote = receiver
        .bind_decision(peers.decision(peers.publisher_proof, FederationAdmission::Private))?;
    let install = InstallSubscriptionRequest {
        authenticated_publisher: peers.publisher,
        opened,
    };
    receiver.set_peer_authority(peers.publisher, Some(1), false)?;
    ensure!(matches!(
        remote.install_subscription(install.clone()),
        Err(FederationError::Unauthorized)
    ));
    receiver.set_peer_authority(peers.publisher, Some(2), true)?;
    remote.install_subscription(install)?;
    let accept = AcceptRequest {
        authenticated_publisher: peers.publisher,
        subscription: peers.subscription(),
        record,
    };
    receiver.set_peer_admission(
        peers.publisher,
        Some(1),
        PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![[12; 48]],
        },
    )?;
    ensure!(matches!(
        remote.accept(accept.clone()),
        Err(FederationError::Unauthorized)
    ));
    receiver.set_peer_admission(peers.publisher, Some(2), admission(peers.publisher_proof))?;
    ensure!(remote.accept(accept.clone())?.newly_accepted);
    ensure!(!remote.accept(accept)?.newly_accepted);
    Ok(())
}

pub fn public_contract<S: FederationStore + FederationPublicReadStore>(
    peers: &Peers,
    store: &S,
) -> Result<()> {
    store.declare_stream(StreamSpec {
        stream: peers.stream(),
        export: ExportName::new("public")?,
    })?;
    store.set_public_stream_policy(
        None,
        PublicStreamPolicy {
            stream: peers.stream(),
            enabled: true,
            max_read_records: 4,
            max_read_bytes: 1024,
        },
    )?;
    let remote = store.bind_public_decision(
        peers.decision(peers.receiver_proof, FederationAdmission::Unconfigured),
    )?;
    remote.inspect_public_stream(peers.receiver, peers.stream())?;
    store.set_peer_authority(peers.receiver, None, true)?;
    ensure!(matches!(
        remote.inspect_public_stream(peers.receiver, peers.stream()),
        Err(FederationError::Unauthorized)
    ));
    store.set_peer_authority(peers.receiver, Some(1), false)?;
    ensure!(matches!(
        remote.inspect_public_stream(peers.receiver, peers.stream()),
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}

pub fn object_contract<S: FederationStore + FederationObjectReadStore>(
    peers: &Peers,
    store: &S,
) -> Result<()> {
    store.set_peer_authority(peers.receiver, None, true)?;
    store.set_peer_admission(peers.receiver, None, admission(peers.receiver_proof))?;
    let grant = store.issue_object_grant(
        ObjectGrantSpec {
            presenter: peers.receiver,
            subject: FederationSubject::Node(peers.receiver),
            blob: xolotl_types::BlobRef {
                hash: "ab".repeat(48),
                size: 4,
                mime: None,
            },
            range_start: 0,
            range_end: 4,
            expires_at_ms: 900,
            max_total_bytes: 8,
            max_chunk_bytes: 4,
        },
        150,
    )?;
    let remote = store
        .bind_object_decision(peers.decision(peers.receiver_proof, FederationAdmission::Private))?;
    let authority = ObjectReadAuthority::new(peers.receiver_proof, ObjectReadAdmission::Private);
    let request = ObjectReadRequest {
        authenticated_presenter: peers.receiver,
        subject: grant.spec.subject.clone(),
        transfer: ObjectTransferId::from_bytes([13; 16]),
        grant: grant.id,
        expected_revision: grant.revision,
        blob: grant.spec.blob.clone(),
        offset: 0,
        max_bytes: 4,
    };
    remote.reserve_object_read(&request, authority, 150)?;
    store.set_peer_admission(
        peers.receiver,
        Some(1),
        admission(peers.receiver_replacement),
    )?;
    ensure!(matches!(
        remote.confirm_object_read(&request, authority, 150),
        Err(FederationError::Unauthorized)
    ));
    ensure!(
        store
            .object_grant(grant.id)?
            .is_some_and(|view| view.charged_bytes == 4)
    );
    let replacement = store.bind_object_decision(
        peers.decision(peers.receiver_replacement, FederationAdmission::Private),
    )?;
    let authority =
        ObjectReadAuthority::new(peers.receiver_replacement, ObjectReadAdmission::Private);
    replacement.reserve_object_read(&request, authority, 150)?;
    peers.time.store(900, Ordering::SeqCst);
    ensure!(matches!(
        replacement.confirm_object_read(&request, authority, 150),
        Err(FederationError::Unauthorized)
    ));
    ensure!(
        store
            .object_grant(grant.id)?
            .is_some_and(|view| view.charged_bytes == 8)
    );
    Ok(())
}

pub fn hosted_contract(peers: &Peers, store: &dyn FederationStore) -> Result<()> {
    publisher_setup(peers, store)?;
    let hosted = HostedSubject {
        issuer: SubjectIssuerId::from_bytes([14; 48]),
        namespace: "accounts".into(),
        subject: "reader".into(),
    };
    store.set_subject_grant(
        None,
        SubjectGrant {
            subject: hosted.clone(),
            presenter: peers.receiver,
            stream: peers.stream(),
            not_before_ms: 100,
            expires_ms: 200,
            history: GrantHistory::All,
            enabled: true,
        },
    )?;
    let remote =
        store.bind_decision(peers.decision(peers.receiver_proof, FederationAdmission::Private))?;
    remote.open_as(FederationSubject::Hosted(hosted.clone()), 150, peers.open())?;
    peers.time.store(200, Ordering::SeqCst);
    ensure!(matches!(
        remote.read_as(
            FederationSubject::Hosted(hosted),
            150,
            ReadRequest {
                authenticated_subscriber: peers.receiver,
                subscription: peers.subscription(),
                after: None,
                max_records: 4,
                max_bytes: 1024,
            }
        ),
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}

pub fn object_receiver_contract<S: FederationStore + FederationObjectReceiveStore>(
    peers: &Peers,
    store: &S,
) -> Result<()> {
    store.set_peer_authority(peers.publisher, None, true)?;
    store.set_peer_admission(peers.publisher, None, admission(peers.publisher_proof))?;
    let remote = store.bind_receive_decision(
        peers.decision(peers.publisher_proof, FederationAdmission::Private),
    )?;
    let spec = ObjectReceiveSpec {
        provider: peers.publisher,
        subject: FederationSubject::Node(peers.receiver),
        grant: ObjectGrantId::new(1)?,
        grant_revision: 1,
        blob: xolotl_types::BlobRef {
            hash: "ac".repeat(48),
            size: 4,
            mime: None,
        },
        owner: Digest::from_bytes([15; 48]),
    };
    let pending = remote.begin_receive(spec.clone())?;
    store.set_peer_admission(
        peers.publisher,
        Some(1),
        PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![[16; 48]],
        },
    )?;
    ensure!(matches!(
        remote.mark_object_verified(pending.transfer, pending.revision, &spec.blob),
        Err(FederationError::Unauthorized)
    ));
    ensure!(
        store
            .object_receive(pending.transfer)?
            .is_some_and(|view| view.phase == ObjectReceivePhase::Pending)
    );
    store.set_peer_admission(peers.publisher, Some(2), admission(peers.publisher_proof))?;
    ensure!(
        remote
            .mark_object_verified(pending.transfer, pending.revision, &spec.blob)?
            .phase
            == ObjectReceivePhase::Verified
    );
    Ok(())
}
