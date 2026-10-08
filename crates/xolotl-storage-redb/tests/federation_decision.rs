#![cfg(feature = "federation")]

#[path = "../../xolotl-federation/tests/support/decision_contract.rs"]
pub mod contract;

#[test]
fn snapshot_bytes_returned_by_the_source_are_checked_again_before_disclosure() -> anyhow::Result<()>
{
    use xolotl_federation::*;
    struct RevokingSource {
        store: xolotl_storage_redb::RedbFederationStore,
        peer: FederationNodeId,
        replacement: PeerAdmission,
    }
    impl SnapshotContentSource for RevokingSource {
        fn read_snapshot_chunk(
            &self,
            _offer: &SnapshotOffer,
            _offset: u64,
            bytes: usize,
        ) -> Result<Arc<[u8]>, FederationError> {
            self.store
                .set_peer_admission(self.peer, Some(1), self.replacement.clone())?;
            Ok(Arc::from(vec![1; bytes]))
        }
    }
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open(directory.path().join("snapshot-publisher.redb"))?;
    let store = db.federation_store(peers.publisher)?;
    let record = contract::publisher_setup(&peers, &store)?;
    store.open(peers.open())?;
    let offer = store.publish_snapshot_offer(SnapshotOfferRequest {
        authenticated_subscriber: peers.receiver,
        subscription: peers.subscription(),
        proof: SnapshotPublicationProof {
            snapshot_id: SnapshotId::from_bytes([21; 16]),
            stream: peers.stream(),
            position: record.position(),
            schema_revision: SchemaRevision::from_bytes([22; 32]),
            content_digest: Digest::from_bytes([23; 48]),
            content_bytes: 4,
            publication_digest: Digest::from_bytes([24; 48]),
        },
    })?;
    let remote = store.bind_snapshot_publisher_decision(
        peers.decision(peers.receiver_proof, FederationAdmission::Private),
    )?;
    let source = RevokingSource {
        store: store.clone(),
        peer: peers.receiver,
        replacement: contract::admission(peers.receiver_replacement),
    };
    ensure!(matches!(
        remote.read_snapshot_chunk(
            SnapshotReadRequest {
                authenticated_subscriber: peers.receiver,
                subscription: peers.subscription(),
                manifest_digest: offer.manifest.binding_digest(),
                offset: 0,
                max_bytes: 4,
            },
            &source
        ),
        Err(FederationError::Unauthorized)
    ));
    ensure!(store.local_snapshot_offer(peers.subscription())? == Some(offer));
    Ok(())
}

#[test]
fn sealed_snapshot_archive_does_not_bypass_receiver_admission_or_lose_its_intent()
-> anyhow::Result<()> {
    use xolotl_federation::*;
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let publisher_db = RedbStore::open(directory.path().join("archive-publisher.redb"))?;
    let receiver_path = directory.path().join("archive-receiver.redb");
    let publisher = publisher_db.federation_store(peers.publisher)?;
    let record = contract::publisher_setup(&peers, &publisher)?;
    let opened = publisher.open(peers.open())?;
    let manifest = SnapshotManifest {
        id: SnapshotId::from_bytes([25; 16]),
        subscription: peers.subscription(),
        stream: peers.stream(),
        subscription_revision: opened.subscription_revision,
        publisher_authority: opened.publisher_authority,
        position: record.position(),
        schema_revision: SchemaRevision::from_bytes([26; 32]),
        content_digest: Digest::from_bytes([27; 48]),
        content_bytes: 4,
    };
    let intent = SnapshotInstallRequest {
        install_id: SnapshotId::from_bytes([28; 16]),
        subject: FederationSubject::Node(peers.receiver),
        manifest: manifest.clone(),
        publication_digest: Digest::from_bytes([29; 48]),
        expected_generation: 0,
    };
    let completion = SnapshotArchiveCompletion {
        install_id: intent.install_id,
        snapshot_id: manifest.id,
        content_digest: manifest.content_digest,
        manifest_digest: manifest.binding_digest(),
        archive_digest: Digest::from_bytes([30; 48]),
    };
    {
        let db = RedbStore::open(&receiver_path)?;
        let receiver = db.federation_store(peers.receiver)?;
        receiver.set_peer_authority(peers.publisher, None, true)?;
        receiver.set_peer_admission(
            peers.publisher,
            None,
            contract::admission(peers.publisher_proof),
        )?;
        receiver.set_export_authority(
            peers.publisher,
            opened.export.clone(),
            None,
            ExportAccess {
                serve: false,
                receive: true,
            },
        )?;
        receiver.install_subscription(InstallSubscriptionRequest {
            authenticated_publisher: peers.publisher,
            opened,
        })?;
        let remote = receiver.bind_snapshot_decision(
            peers.decision(peers.publisher_proof, FederationAdmission::Private),
        )?;
        remote.begin_snapshot_install(intent.clone())?;
        peers.time.store(1000, Ordering::SeqCst);
        ensure!(matches!(
            remote.commit_snapshot_archive(peers.subscription(), completion),
            Err(FederationError::Unauthorized)
        ));
        ensure!(
            receiver
                .snapshot_install(peers.subscription())?
                .is_some_and(
                    |view| view.pending == Some(intent.clone()) && view.archived.is_none()
                )
        );
    }
    let db = RedbStore::open(&receiver_path)?;
    let receiver = db.federation_store(peers.receiver)?;
    ensure!(
        receiver
            .snapshot_install(peers.subscription())?
            .is_some_and(|view| view.pending == Some(intent))
    );
    Ok(())
}

#[test]
fn claimed_call_keeps_its_identity_when_online_authority_expires_before_kernel_admission()
-> anyhow::Result<()> {
    use sha2::{Digest as _, Sha384};
    use xolotl_federation::*;
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open(directory.path().join("call.redb"))?;
    let store = db.federation_store(peers.publisher)?;
    store.set_peer_authority(peers.receiver, None, true)?;
    store.set_peer_admission(
        peers.receiver,
        None,
        contract::admission(peers.receiver_proof),
    )?;
    let target = CallTarget {
        export: ExportName::new("calls")?,
        path: CallPath::new("/echo")?,
        method: CallMethod::new("echo")?,
        contract_digest: [31; 32],
    };
    store.set_export_authority(
        peers.receiver,
        target.export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    store.set_call_authority(
        None,
        CallAuthorityRule {
            subject: FederationSubject::Node(peers.receiver),
            presenter: peers.receiver,
            target: target.clone(),
            enabled: true,
            expires_ms: 2000,
            max_input_bytes: 1024,
            max_prepare_window_ms: 100,
            max_result_retention_ms: 100,
        },
    )?;
    let remote = store
        .bind_call_decision(peers.decision(peers.receiver_proof, FederationAdmission::Private))?;
    let request = PrepareCallRequest {
        authenticated_origin: peers.receiver,
        subject: FederationSubject::Node(peers.receiver),
        origin_request_id: RequestId::from_bytes([32; 16]),
        target,
        input_digest: Digest::from_bytes(Sha384::digest(b"input").into()),
        input_bytes: 5,
        prepare_deadline_ms: 200,
        execution_deadline_ms: 1500,
        result_retention_ms: 100,
    };
    let prepared = remote.prepare_call(request.clone(), 150)?;
    remote.invoke_call(
        InvokeCallRequest {
            authenticated_origin: peers.receiver,
            subject: request.subject,
            origin_request_id: request.origin_request_id,
            call: prepared.call,
            input: Arc::from(b"input".as_slice()),
        },
        150,
    )?;
    let binding = CallKernelBinding {
        process: 33,
        lifecycle: 34,
    };
    remote.bind_kernel_identity(prepared.call, binding, 150)?;
    peers.time.store(1000, Ordering::SeqCst);
    ensure!(matches!(
        remote.authorize_kernel_execution(prepared.call, 150),
        Err(FederationError::Unauthorized)
    ));
    let retained = store.kernel_call(prepared.call, 1000)?;
    ensure!(retained.binding == Some(binding) && retained.accepted_digest.is_none());
    ensure!(matches!(
        remote.record_kernel_acceptance(prepared.call, Digest::from_bytes([35; 48])),
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}

use anyhow::{Result, ensure};
use std::sync::{Arc, atomic::Ordering};
use xolotl_federation::{FederationAdmission, FederationError, FederationStore, ReadRequest};
use xolotl_storage_redb::RedbStore;

#[test]
fn rejected_write_retains_time_without_committing_business_changes_after_reopen() -> Result<()> {
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("rejected-write.redb");
    {
        let db = RedbStore::open(&path)?;
        contract::rejected_write_retains_time_contract(
            &peers,
            &db.federation_store(peers.publisher)?,
        )?;
    }
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(peers.publisher)?;
    ensure!(store.peer_authority(peers.receiver)? == Some((1, true)));
    ensure!(matches!(
        store.checked_time_ms(400),
        Err(FederationError::ClockRollback)
    ));
    Ok(())
}

#[test]
fn expired_read_retains_its_time_observation_after_reopen() -> Result<()> {
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("expired-read.redb");
    {
        let db = RedbStore::open(&path)?;
        let store = db.federation_store(peers.publisher)?;
        contract::publisher_setup(&peers, &store)?;
        let remote = store
            .with_decision(peers.decision(peers.receiver_proof, FederationAdmission::Private))?;
        peers.time.store(1200, Ordering::SeqCst);
        ensure!(matches!(
            remote.peer_authority(peers.receiver),
            Err(FederationError::Unauthorized)
        ));
        peers.time.store(900, Ordering::SeqCst);
        ensure!(matches!(
            remote.peer_authority(peers.receiver),
            Err(FederationError::ClockRollback)
        ));
    }
    let db = RedbStore::open(&path)?;
    ensure!(matches!(
        db.federation_store(peers.publisher)?.checked_time_ms(900),
        Err(FederationError::ClockRollback)
    ));
    Ok(())
}

#[test]
fn read_snapshot_is_the_authorization_cutoff_for_one_bounded_batch() -> Result<()> {
    use std::sync::{Mutex, atomic::AtomicBool};
    use xolotl_federation::FederationDecision;

    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open(directory.path().join("queued-snapshot.redb"))?;
    let store = db.federation_store(peers.publisher)?;
    contract::publisher_setup(&peers, &store)?;
    store.open(peers.open())?;
    let (queued, seen) = std::sync::mpsc::channel();
    let (release, proceed) = std::sync::mpsc::channel();
    let proceed = Mutex::new(proceed);
    let first = AtomicBool::new(true);
    let decision = FederationDecision::new(
        peers.receiver_proof,
        FederationAdmission::Private,
        Arc::new(move || {
            if first.swap(false, Ordering::SeqCst) {
                queued.send(()).map_err(|_error| FederationError::Corrupt)?;
                proceed
                    .lock()
                    .map_err(|_error| FederationError::Corrupt)?
                    .recv()
                    .map_err(|_error| FederationError::Corrupt)?;
            }
            Ok(150)
        }),
    );
    let remote = store.bind_decision(decision)?;
    let request = ReadRequest {
        authenticated_subscriber: peers.receiver,
        subscription: peers.subscription(),
        after: None,
        max_records: 4,
        max_bytes: 1024,
    };
    let worker = std::thread::spawn(move || remote.read(request));
    seen.recv()?;
    let revoker_store = store.clone();
    let peer = peers.receiver;
    let replacement = contract::admission(peers.receiver_replacement);
    let revoker =
        std::thread::spawn(move || revoker_store.set_peer_admission(peer, Some(1), replacement));
    release.send(())?;
    let result = worker
        .join()
        .map_err(|_error| anyhow::anyhow!("reader panicked"))?;
    ensure!(result?.records.len() == 1);
    revoker
        .join()
        .map_err(|_error| anyhow::anyhow!("revoker panicked"))??;
    let remote =
        store.bind_decision(peers.decision(peers.receiver_proof, FederationAdmission::Private))?;
    ensure!(matches!(
        remote.read(ReadRequest {
            authenticated_subscriber: peers.receiver,
            subscription: peers.subscription(),
            after: None,
            max_records: 4,
            max_bytes: 1024,
        }),
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}

#[test]
fn publisher_online_authority_is_checked_at_the_redb_decision() -> Result<()> {
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("publisher.redb");
    {
        let db = RedbStore::open(&path)?;
        let store = db.federation_store(peers.publisher)?;
        contract::publisher_contract(&peers, &store)?;
    }
    let db = RedbStore::open(&path)?;
    let store = db.federation_store(peers.publisher)?;
    let remote = store
        .bind_decision(peers.decision(peers.receiver_replacement, FederationAdmission::Private))?;
    peers.time.store(150, Ordering::SeqCst);
    ensure!(matches!(
        remote.read(ReadRequest {
            authenticated_subscriber: peers.receiver,
            subscription: peers.subscription(),
            after: None,
            max_records: 4,
            max_bytes: 1024,
        }),
        Err(FederationError::ClockRollback)
    ));
    Ok(())
}

#[test]
fn receiver_install_and_accept_share_current_online_authority() -> Result<()> {
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let publisher_db = RedbStore::open(directory.path().join("publisher.redb"))?;
    let receiver_db = RedbStore::open(directory.path().join("receiver.redb"))?;
    contract::receiver_contract(
        &peers,
        &publisher_db.federation_store(peers.publisher)?,
        &receiver_db.federation_store(peers.receiver)?,
    )
}

#[test]
fn public_admission_rejects_configured_peers_in_the_disclosure_transaction() -> Result<()> {
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open(directory.path().join("publisher.redb"))?;
    contract::public_contract(&peers, &db.federation_store(peers.publisher)?)
}

#[test]
fn staged_object_disclosure_checks_revocation_and_fresh_time() -> Result<()> {
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open(directory.path().join("publisher.redb"))?;
    contract::object_contract(&peers, &db.federation_store(peers.publisher)?)
}

#[test]
fn queued_hosted_request_uses_decision_time_for_the_subject_grant() -> Result<()> {
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open(directory.path().join("publisher.redb"))?;
    contract::hosted_contract(&peers, &db.federation_store(peers.publisher)?)
}

#[test]
fn object_receiver_verification_is_a_new_online_admission_decision() -> Result<()> {
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open(directory.path().join("receiver.redb"))?;
    contract::object_receiver_contract(&peers, &db.federation_store(peers.receiver)?)
}

#[test]
fn revocation_committed_before_a_queued_read_is_not_a_handshake_check() -> Result<()> {
    let peers = contract::Peers::new()?;
    let directory = tempfile::tempdir()?;
    let db = RedbStore::open(directory.path().join("publisher.redb"))?;
    let store = Arc::new(db.federation_store(peers.publisher)?);
    contract::publisher_setup(&peers, store.as_ref())?;
    let remote =
        store.bind_decision(peers.decision(peers.receiver_proof, FederationAdmission::Private))?;
    remote.open(peers.open())?;
    let (queued, seen) = std::sync::mpsc::channel();
    let (release, proceed) = std::sync::mpsc::channel();
    let read = ReadRequest {
        authenticated_subscriber: peers.receiver,
        subscription: peers.subscription(),
        after: None,
        max_records: 4,
        max_bytes: 1024,
    };
    let worker = std::thread::spawn(move || -> Result<_> {
        queued.send(())?;
        proceed.recv()?;
        Ok(remote.read(read))
    });
    seen.recv()?;
    store.set_peer_admission(
        peers.receiver,
        Some(1),
        contract::admission(peers.receiver_replacement),
    )?;
    release.send(())?;
    ensure!(matches!(
        worker
            .join()
            .map_err(|_error| anyhow::anyhow!("reader panicked"))??,
        Err(FederationError::Unauthorized)
    ));
    Ok(())
}
