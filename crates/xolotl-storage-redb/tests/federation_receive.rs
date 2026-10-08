#![cfg(feature = "federation")]

use core::future::Future;
use std::{
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
};

use anyhow::{Context, Result, ensure};
use redb::{ReadableDatabase as _, ReadableTable as _, TableDefinition};
use serde::{Deserialize, Serialize};
use xolotl_federation::{
    Digest, FederationError, FederationNodeId, FederationObjectChunkSource,
    FederationObjectReadService, FederationObjectReceiveStore, FederationObjectReceiver,
    FederationObjectReferenceGuard, FederationObjectReferenceStore, FederationOnlineKey,
    FederationOnlineKeyAuthorization, FederationRootKey, FederationSessionTranscript,
    FederationSubject, ObjectGrantId, ObjectGrantSpec, ObjectReadAdmission, ObjectReadAuthority,
    ObjectReadPage, ObjectReadRequest, ObjectReceivePhase, ObjectReceiveSpec, ObjectReceiveView,
    RootSignaturePurpose, VerifiedFederationPeerProof, bind_verified_object,
    verify_federation_peer_proof,
};
use xolotl_state::object::{ObjectDelete, ObjectRead, ObjectWrite, UploadOptions};
use xolotl_storage_fs::FileObjectStore;
use xolotl_storage_redb::RedbStore;
use xolotl_types::TaintSet;

const APPLICATION_REFS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("test_application_object_references");

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
enum ApplicationSubject {
    Node(Vec<u8>),
    Hosted {
        issuer: Vec<u8>,
        namespace: String,
        subject: String,
    },
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ApplicationRef {
    transfer: [u8; 16],
    provider: Vec<u8>,
    subject: ApplicationSubject,
    owner: Vec<u8>,
    grant: u64,
    grant_revision: u64,
    blob: xolotl_types::BlobRef,
}

impl ApplicationRef {
    fn for_receive(view: &ObjectReceiveView) -> Self {
        Self {
            transfer: view.transfer.as_bytes(),
            provider: view.spec.provider.as_bytes().to_vec(),
            subject: match &view.spec.subject {
                FederationSubject::Node(node) => ApplicationSubject::Node(node.as_bytes().to_vec()),
                FederationSubject::Hosted(hosted) => ApplicationSubject::Hosted {
                    issuer: hosted.issuer.as_bytes().to_vec(),
                    namespace: hosted.namespace.clone(),
                    subject: hosted.subject.clone(),
                },
            },
            owner: view.spec.owner.as_bytes().to_vec(),
            grant: view.spec.grant.get(),
            grant_revision: view.spec.grant_revision,
            blob: view.spec.blob.clone(),
        }
    }
}

struct ApplicationReferences {
    db: redb::Database,
    lock: Mutex<()>,
}

impl ApplicationReferences {
    fn open(path: &std::path::Path) -> Result<Self> {
        Ok(Self {
            db: redb::Database::create(path)?,
            lock: Mutex::new(()),
        })
    }

    fn reference(&self, transfer: [u8; 16]) -> Result<Option<ApplicationRef>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(APPLICATION_REFS)?;
        Ok(table
            .get(transfer.as_slice())?
            .map(|entry| serde_json::from_slice(entry.value()))
            .transpose()?)
    }

    fn remove(&self, transfer: [u8; 16]) -> Result<()> {
        let _guard = self
            .lock
            .lock()
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(APPLICATION_REFS)?;
            table.remove(transfer.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    fn publish<'a>(
        &'a self,
        view: &ObjectReceiveView,
    ) -> Result<ApplicationReferenceGuard<'a>, FederationError> {
        let lock = self
            .lock
            .lock()
            .map_err(|error| FederationError::Storage(error.to_string()))?;
        let expected = ApplicationRef::for_receive(view);
        let bytes = serde_json::to_vec(&expected)
            .map_err(|error| FederationError::Storage(error.to_string()))?;
        let txn = self
            .db
            .begin_write()
            .map_err(|error| FederationError::Storage(error.to_string()))?;
        {
            let mut table = txn
                .open_table(APPLICATION_REFS)
                .map_err(|error| FederationError::Storage(error.to_string()))?;
            if let Some(saved) = table
                .get(view.transfer.as_bytes().as_slice())
                .map_err(|error| FederationError::Storage(error.to_string()))?
            {
                if saved.value() != bytes.as_slice() {
                    return Err(FederationError::Conflict);
                }
            } else {
                table
                    .insert(view.transfer.as_bytes().as_slice(), bytes.as_slice())
                    .map_err(|error| FederationError::Storage(error.to_string()))?;
            }
        }
        txn.commit()
            .map_err(|_error| FederationError::Indeterminate)?;
        let saved = self
            .reference(view.transfer.as_bytes())
            .map_err(|error| FederationError::Storage(error.to_string()))?
            .ok_or(FederationError::Corrupt)?;
        if saved != expected {
            return Err(FederationError::Conflict);
        }
        Ok(ApplicationReferenceGuard {
            _lock: lock,
            blob: saved.blob,
        })
    }
}

struct ApplicationReferenceGuard<'a> {
    _lock: MutexGuard<'a, ()>,
    blob: xolotl_types::BlobRef,
}

impl FederationObjectReferenceGuard for ApplicationReferenceGuard<'_> {
    fn committed_blob(&self) -> &xolotl_types::BlobRef {
        &self.blob
    }
}

impl FederationObjectReferenceStore for ApplicationReferences {
    type Guard<'a> = ApplicationReferenceGuard<'a>;
    type Publish<'a> = std::future::Ready<Result<Self::Guard<'a>, FederationError>>;

    fn publish_and_hold<'a>(&'a self, view: &'a ObjectReceiveView) -> Self::Publish<'a> {
        std::future::ready(self.publish(view))
    }
}

struct Remote {
    service: FederationObjectReadService,
    objects: FileObjectStore,
    authority: ObjectReadAuthority,
}

impl FederationObjectChunkSource for Remote {
    type Read<'a> = Pin<Box<dyn Future<Output = Result<ObjectReadPage, FederationError>> + 'a>>;

    fn read(&self, request: ObjectReadRequest) -> Self::Read<'_> {
        Box::pin(self.service.read(&self.objects, request, self.authority))
    }
}

struct NeverRead;

fn verified_peer(
    root_key: &FederationRootKey,
    local: FederationNodeId,
) -> Result<VerifiedFederationPeerProof> {
    let root = root_key.root()?;
    let peer = root.node_id();
    let online_key = FederationOnlineKey::generate()?;
    let authorization =
        FederationOnlineKeyAuthorization::new(online_key.public_key(), 1, 100, 1000)?;
    let signature = root_key.sign(
        RootSignaturePurpose::OnlineKeyAuthorization,
        &authorization.encode(),
    )?;
    let transcript =
        FederationSessionTranscript::new(local, peer, [1; 32], [2; 32], [3; 48], [4; 48])?;
    let online_signature = online_key.sign_session(peer, &authorization, &transcript)?;
    Ok(verify_federation_peer_proof(
        &root,
        peer,
        &authorization,
        &signature,
        &transcript,
        &online_signature,
        100,
    )?)
}

impl FederationObjectChunkSource for NeverRead {
    type Read<'a> = std::future::Ready<Result<ObjectReadPage, FederationError>>;

    fn read(&self, _request: ObjectReadRequest) -> Self::Read<'_> {
        std::future::ready(Err(FederationError::Storage(
            "unexpected remote read".into(),
        )))
    }
}

#[tokio::test]
async fn receiver_restarts_from_zero_and_recovers_committed_content() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let provider = FederationNodeId::from_bytes([110; 48]);
    let receiver_root = FederationRootKey::generate()?;
    let proof = verified_peer(&receiver_root, provider)?;
    let receiver = proof.node_id();
    let provider_objects = FileObjectStore::open(dir.path().join("provider-objects"))?;
    let upload = provider_objects
        .begin_upload(UploadOptions::default())
        .await?;
    let content = b"durable federation object";
    provider_objects.write_chunk(&upload, 0, content).await?;
    let blob = provider_objects
        .commit_upload(&upload, &TaintSet::pristine())
        .await?
        .blob;
    let provider_db = RedbStore::open(dir.path().join("provider.redb"))?;
    let provider_store = provider_db.federation_store(provider)?;
    let service = FederationObjectReadService::new(
        Arc::new(provider_store),
        Arc::new(|| Ok(100)),
        Arc::new(
            |_: &FederationSubject, metadata: &xolotl_state::object::ObjectMetadata| {
                metadata.taint.is_pristine()
            },
        ),
        4,
    )?;
    let grant = service
        .issue(
            &provider_objects,
            ObjectGrantSpec {
                presenter: receiver,
                subject: FederationSubject::Node(receiver),
                blob: blob.clone(),
                range_start: 0,
                range_end: blob.size,
                expires_at_ms: 1000,
                max_total_bytes: blob.size * 4,
                max_chunk_bytes: 4,
            },
        )
        .await?;
    let remote = Remote {
        service,
        objects: provider_objects,
        authority: ObjectReadAuthority::new(proof, ObjectReadAdmission::Unconfigured),
    };
    let spec = ObjectReceiveSpec {
        provider,
        subject: FederationSubject::Node(receiver),
        grant: grant.id,
        grant_revision: grant.revision,
        blob: blob.clone(),
        owner: Digest::from_bytes([112; 48]),
    };

    let receiver_db_path = dir.path().join("receiver.redb");
    let receiver_object_root = dir.path().join("receiver-objects");
    let receiver_db = RedbStore::open(&receiver_db_path)?;
    let receiver_store = receiver_db.federation_store(receiver)?;
    let pending = receiver_store.begin_receive(spec.clone())?;
    ensure!(pending.phase == ObjectReceivePhase::Pending && pending.revision == 1);
    let receiver_objects = FileObjectStore::open(&receiver_object_root)?;
    let abandoned = receiver_objects
        .begin_upload(UploadOptions {
            expected_size: Some(blob.size),
            ..UploadOptions::default()
        })
        .await?;
    receiver_objects.write_chunk(&abandoned, 0, b"dura").await?;
    drop(abandoned);
    drop(receiver_objects);
    drop(receiver_store);
    drop(receiver_db);

    let receiver_db = RedbStore::open(&receiver_db_path)?;
    let receiver_store = receiver_db.federation_store(receiver)?;
    let receiver_objects = FileObjectStore::open(&receiver_object_root)?;
    let resumed = receiver_store.begin_receive(spec.clone())?;
    ensure!(resumed.transfer == pending.transfer && resumed.phase == ObjectReceivePhase::Pending);
    let coordinator = FederationObjectReceiver::new(Arc::new(receiver_store.clone()), 4)?;
    let verified = coordinator
        .fetch(&remote, &receiver_objects, spec.clone())
        .await?;
    ensure!(
        verified.transfer == pending.transfer && verified.phase == ObjectReceivePhase::Verified
    );
    ensure!(verified.revision == 2);
    let saved = receiver_objects
        .metadata(&blob)
        .await?
        .context("received object missing")?;
    ensure!(saved.blob == blob && !saved.taint.is_pristine());
    drop(coordinator);
    drop(receiver_store);
    drop(receiver_db);
    drop(receiver_objects);

    let receiver_db = RedbStore::open(&receiver_db_path)?;
    let receiver_store = receiver_db.federation_store(receiver)?;
    let receiver_objects = FileObjectStore::open(&receiver_object_root)?;
    let coordinator = FederationObjectReceiver::new(Arc::new(receiver_store.clone()), 4)?;
    let stable = coordinator
        .fetch(&NeverRead, &receiver_objects, spec.clone())
        .await?;
    ensure!(stable == verified);
    let second_owner = ObjectReceiveSpec {
        owner: Digest::from_bytes([113; 48]),
        ..spec
    };
    let second = receiver_store.begin_receive(second_owner.clone())?;
    ensure!(second.transfer != stable.transfer && second.phase == ObjectReceivePhase::Pending);
    let recovered = coordinator
        .fetch(&NeverRead, &receiver_objects, second_owner)
        .await?;
    ensure!(recovered.phase == ObjectReceivePhase::Verified);
    let application_db_path = dir.path().join("application.redb");
    let references = ApplicationReferences::open(&application_db_path)?;
    let bound = bind_verified_object(&receiver_store, &references, stable.transfer).await?;
    ensure!(bound.phase == ObjectReceivePhase::Bound && bound.revision == 3);
    ensure!(
        references.reference(stable.transfer.as_bytes())?
            == Some(ApplicationRef::for_receive(&bound))
    );
    ensure!(bind_verified_object(&receiver_store, &references, stable.transfer).await? == bound);
    references.remove(stable.transfer.as_bytes())?;
    receiver_store.retire_bound_object(stable.transfer, 3)?;
    ensure!(receiver_store.object_receive(stable.transfer)?.is_none());
    Ok(())
}

#[tokio::test]
async fn application_handoff_and_gc_gate_survive_reopen_with_real_object_deletion() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let object_root = directory.path().join("objects");
    let db_path = directory.path().join("federation.redb");
    let application_ref = directory.path().join("application.redb");
    let local = FederationNodeId::from_bytes([71; 48]);
    let provider = FederationNodeId::from_bytes([72; 48]);
    let objects = FileObjectStore::open(&object_root)?;
    let bytes = b"application-owned federated content";
    let upload = objects
        .begin_upload(UploadOptions {
            expected_size: Some(bytes.len() as u64),
            ..UploadOptions::default()
        })
        .await?;
    objects.write_chunk(&upload, 0, bytes).await?;
    let blob = objects
        .commit_upload(&upload, &TaintSet::pristine())
        .await?
        .blob;
    let spec = ObjectReceiveSpec {
        provider,
        subject: FederationSubject::Node(local),
        grant: ObjectGrantId::new(7)?,
        grant_revision: 1,
        blob: blob.clone(),
        owner: Digest::from_bytes([73; 48]),
    };

    let database = RedbStore::open(&db_path)?;
    let store = database.federation_store(local)?;
    let receiver = FederationObjectReceiver::new(Arc::new(store.clone()), 8)?;
    let verified = receiver.fetch(&NeverRead, &objects, spec.clone()).await?;
    ensure!(verified.phase == ObjectReceivePhase::Verified);
    ensure!(
        store.reserve_receive_gc(&blob) == Err(FederationError::Conflict),
        "verified but unbound bytes must remain protected"
    );

    // A crash between application publication and the federation CAS leaves a
    // durable reference plus a Verified receipt. Reopening can finish the CAS.
    let references = ApplicationReferences::open(&application_ref)?;
    drop(references.publish(&verified)?);
    ensure!(store.object_receive(verified.transfer)? == Some(verified.clone()));
    drop(receiver);
    drop(store);
    drop(database);
    drop(references);

    let database = RedbStore::open(&db_path)?;
    let store = database.federation_store(local)?;
    let references = ApplicationReferences::open(&application_ref)?;
    let bound = bind_verified_object(&store, &references, verified.transfer).await?;
    ensure!(bound.phase == ObjectReceivePhase::Bound);
    drop(store);
    drop(database);
    drop(references);

    let database = RedbStore::open(&db_path)?;
    let store = database.federation_store(local)?;
    let references = ApplicationReferences::open(&application_ref)?;
    ensure!(
        references.reference(verified.transfer.as_bytes())?
            == Some(ApplicationRef::for_receive(&bound)),
        "the application's own reference remains visible after reopen"
    );
    ensure!(store.object_receive(bound.transfer)? == Some(bound.clone()));
    ensure!(store.reserve_receive_gc(&blob) == Err(FederationError::Conflict));

    // A separate, unfinished owner of the same content also blocks deletion.
    let other = ObjectReceiveSpec {
        owner: Digest::from_bytes([74; 48]),
        ..spec.clone()
    };
    let pending = store.begin_receive(other)?;
    references.remove(bound.transfer.as_bytes())?;
    store.retire_bound_object(bound.transfer, bound.revision)?;
    ensure!(store.reserve_receive_gc(&blob) == Err(FederationError::Conflict));
    ensure!(
        store.retire_unbound_object(pending.transfer, pending.revision + 1)
            == Err(FederationError::Conflict)
    );
    store.retire_unbound_object(pending.transfer, pending.revision)?;

    let fence = store.reserve_receive_gc(&blob)?;
    ensure!(
        store.begin_receive(spec.clone()) == Err(FederationError::Conflict),
        "new transfers cannot race with object deletion"
    );
    drop(store);
    drop(database);

    let database = RedbStore::open(&db_path)?;
    let store = database.federation_store(local)?;
    ensure!(store.receive_gc_fence(&blob.hash)? == Some(fence.clone()));
    ensure!(store.active_receive_gc_fences()? == vec![fence.clone()]);
    ensure!(store.begin_receive(spec.clone()) == Err(FederationError::Conflict));
    ensure!(objects.metadata(&blob).await?.is_some());
    objects.delete(&blob).await?;
    ensure!(objects.metadata(&blob).await?.is_none());
    store.release_receive_gc(&fence)?;
    let newer = store.reserve_receive_gc(&blob)?;
    ensure!(newer.generation > fence.generation);
    ensure!(store.release_receive_gc(&fence) == Err(FederationError::Conflict));
    store.release_receive_gc(&newer)?;
    ensure!(store.active_receive_gc_fences()?.is_empty());
    let again = store.begin_receive(spec)?;
    ensure!(again.transfer != verified.transfer);
    Ok(())
}
