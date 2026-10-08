#![cfg(feature = "federation")]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, ensure};
use sha2::Digest as _;
use xolotl_federation::{
    FederationError, FederationNodeId, FederationObjectReadService, FederationObjectReadStore,
    FederationOnlineKey, FederationOnlineKeyAuthorization, FederationRootKey,
    FederationSessionTranscript, FederationStore, FederationSubject, ObjectDigestVerifier,
    ObjectGrantId, ObjectGrantSpec, ObjectReadAdmission, ObjectReadAuthority, ObjectReadRequest,
    ObjectTransferId, PeerAdmission, RootSignaturePurpose, VerifiedFederationPeerProof,
    verify_federation_peer_proof,
};
use xolotl_state::object::{ObjectMetadata, ObjectWrite, UploadOptions};
use xolotl_storage_fs::FileObjectStore;
use xolotl_storage_redb::RedbStore;
use xolotl_types::{BlobRef, TaintSet};

fn request(
    view: &xolotl_federation::ObjectGrantView,
    offset: u64,
    max_bytes: usize,
) -> ObjectReadRequest {
    ObjectReadRequest {
        authenticated_presenter: view.spec.presenter,
        subject: view.spec.subject.clone(),
        transfer: ObjectTransferId::from_bytes([93; 16]),
        grant: view.id,
        expected_revision: view.revision,
        blob: view.spec.blob.clone(),
        offset,
        max_bytes,
    }
}

fn verified_peer(
    root_key: &FederationRootKey,
    local: FederationNodeId,
    expires_ms: u64,
) -> Result<VerifiedFederationPeerProof> {
    let root = root_key.root()?;
    let peer = root.node_id();
    let online_key = FederationOnlineKey::generate()?;
    let authorization =
        FederationOnlineKeyAuthorization::new(online_key.public_key(), 1, 100, expires_ms)?;
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

#[tokio::test]
async fn exact_object_grant_is_durable_bounded_and_revocable() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let object_root = dir.path().join("objects");
    let db_path = dir.path().join("federation.redb");
    let node = FederationNodeId::from_bytes([81; 48]);
    let peer_root = FederationRootKey::generate()?;
    let proof = verified_peer(&peer_root, node, 150)?;
    let peer = proof.node_id();
    let unconfigured = ObjectReadAuthority::new(proof, ObjectReadAdmission::Unconfigured);
    let private = ObjectReadAuthority::new(proof, ObjectReadAdmission::Private);
    let bytes = b"hello federation";
    let clock = Arc::new(AtomicU64::new(100));
    let now = {
        let clock = clock.clone();
        Arc::new(move || Ok(clock.load(Ordering::SeqCst)))
    };
    let disclosure =
        Arc::new(|_: &FederationSubject, metadata: &ObjectMetadata| metadata.taint.is_pristine());
    let objects = FileObjectStore::open(&object_root)?;
    let upload = objects.begin_upload(UploadOptions::default()).await?;
    objects.write_chunk(&upload, 0, bytes).await?;
    let metadata = objects
        .commit_upload(&upload, &TaintSet::pristine())
        .await?;
    let blob = metadata.blob.clone();

    let db = RedbStore::open(&db_path)?;
    let grants = db.federation_store(node)?;
    let service = FederationObjectReadService::new(
        Arc::new(grants.clone()),
        now.clone(),
        disclosure.clone(),
        4,
    )?;
    let spec = ObjectGrantSpec {
        presenter: peer,
        subject: FederationSubject::Node(peer),
        blob: blob.clone(),
        range_start: 0,
        range_end: blob.size,
        expires_at_ms: 101,
        max_total_bytes: blob.size * 2,
        max_chunk_bytes: 4,
    };
    let mut wrong_size = spec.clone();
    wrong_size.blob.size += 1;
    ensure!(matches!(
        service.issue(&objects, wrong_size).await,
        Err(FederationError::Unauthorized)
    ));
    let grant = service.issue(&objects, spec).await?;
    ensure!(grant.id.get() == 1 && grant.revision == 1);
    ensure!(grants.list_object_grants()? == vec![grant.clone()]);
    ensure!(matches!(
        service
            .read(
                &objects,
                ObjectReadRequest {
                    subject: FederationSubject::Node(node),
                    ..request(&grant, 0, 4)
                },
                unconfigured,
            )
            .await,
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        service
            .read(&objects, request(&grant, blob.size - 1, 4), unconfigured,)
            .await,
        Err(FederationError::Unauthorized)
    ));
    let mut verifier = ObjectDigestVerifier::new(blob.clone())?;
    let mut offset = 0;
    while offset < blob.size {
        let size = (blob.size - offset).min(4) as usize;
        let page = service
            .read(&objects, request(&grant, offset, size), unconfigured)
            .await?;
        ensure!(page.bytes.len() == size);
        verifier.push(offset, &page.bytes)?;
        offset += page.bytes.len() as u64;
        ensure!(page.end_of_range == (offset == blob.size));
    }
    ensure!(verifier.finish()? == blob);
    let charged = grants
        .object_grant(grant.id)?
        .context("issued grant missing")?;
    ensure!(charged.charged_bytes == blob.size);
    drop(service);
    drop(grants);
    drop(db);
    drop(objects);

    let reopened_objects = FileObjectStore::open(&object_root)?;
    let reopened_db = RedbStore::open(&db_path)?;
    let reopened = reopened_db.federation_store(node)?;
    ensure!(
        reopened
            .object_grant(grant.id)?
            .context("grant missing after restart")?
            .charged_bytes
            == blob.size
    );
    let service = FederationObjectReadService::new(Arc::new(reopened.clone()), now, disclosure, 4)?;
    let page = service
        .read(&reopened_objects, request(&grant, 0, 4), unconfigured)
        .await?;
    ensure!(page.bytes == bytes[..4]);
    ensure!(
        reopened
            .object_grant(grant.id)?
            .context("grant missing after read")?
            .charged_bytes
            == blob.size + 4
    );
    reopened.reserve_object_read(&request(&grant, 4, 4), unconfigured, 100)?;
    let revoked = reopened.revoke_object_grant(grant.id, 1)?;
    ensure!(!revoked.enabled && revoked.revision == 2);
    ensure!(reopened.list_object_grants()? == vec![revoked.clone()]);
    ensure!(matches!(
        reopened.revoke_object_grant(grant.id, 1),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        service
            .read(&reopened_objects, request(&grant, 4, 4), unconfigured,)
            .await,
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        reopened.confirm_object_read(&request(&grant, 4, 4), unconfigured, 100,),
        Err(FederationError::Unauthorized)
    ));
    ensure!(reopened.retire_object_grants(101, 1)? == 1);
    ensure!(reopened.object_grant(grant.id)?.is_none());
    let next = reopened.issue_object_grant(
        ObjectGrantSpec {
            presenter: peer,
            subject: FederationSubject::Node(peer),
            blob,
            range_start: 0,
            range_end: 4,
            expires_at_ms: 200,
            max_total_bytes: 8,
            max_chunk_bytes: 4,
        },
        101,
    )?;
    ensure!(next.id.get() == 2);
    let pending = request(&next, 0, 4);
    ensure!(matches!(
        reopened.reserve_object_read(&pending, private, 101),
        Err(FederationError::Unauthorized)
    ));
    let foreign_root = FederationRootKey::generate()?;
    let foreign = ObjectReadAuthority::new(
        verified_peer(&foreign_root, node, 150)?,
        ObjectReadAdmission::Unconfigured,
    );
    ensure!(matches!(
        reopened.reserve_object_read(&pending, foreign, 101),
        Err(FederationError::Unauthorized)
    ));
    reopened.reserve_object_read(&pending, unconfigured, 101)?;
    reopened.set_peer_authority(peer, None, true)?;
    ensure!(matches!(
        reopened.confirm_object_read(&pending, unconfigured, 101),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        reopened.reserve_object_read(&pending, unconfigured, 101),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        reopened.reserve_object_read(&pending, private, 101),
        Err(FederationError::Unauthorized)
    ));
    let allowed = PeerAdmission {
        minimum_online_generation: 1,
        allowed_authorization_digests: vec![proof.authorization_digest()],
    };
    reopened.set_peer_admission(peer, None, allowed.clone())?;
    reopened.reserve_object_read(&pending, private, 101)?;
    reopened.confirm_object_read(&pending, private, 101)?;
    reopened.set_peer_admission(
        peer,
        Some(1),
        PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![],
        },
    )?;
    ensure!(matches!(
        reopened.confirm_object_read(&pending, private, 101),
        Err(FederationError::Unauthorized)
    ));
    reopened.set_peer_admission(peer, Some(2), allowed)?;
    reopened.set_peer_authority(peer, Some(1), false)?;
    ensure!(matches!(
        reopened.confirm_object_read(&pending, private, 101),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        reopened.reserve_object_read(&pending, private, 101),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        reopened.reserve_object_read(&pending, unconfigured, 101),
        Err(FederationError::Unauthorized)
    ));
    reopened.set_peer_authority(peer, Some(2), true)?;
    ensure!(matches!(
        reopened.confirm_object_read(&pending, private, 150),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        reopened.reserve_object_read(&pending, private, 200),
        Err(FederationError::Unauthorized)
    ));
    ensure!(matches!(
        reopened.reserve_object_read(&pending, private, 99),
        Err(FederationError::ClockRollback)
    ));
    Ok(())
}

#[test]
fn digest_verifier_requires_complete_canonical_bytes() -> Result<()> {
    let data = b"correct bytes";
    let digest = sha2::Sha384::digest(data);
    let blob = BlobRef {
        hash: BlobRef::sha384_hex(&digest.into()),
        size: data.len() as u64,
        mime: Some("text/plain".into()),
    };
    let mut incomplete = ObjectDigestVerifier::new(blob.clone())?;
    incomplete.push(0, &data[..3])?;
    ensure!(matches!(
        incomplete.finish(),
        Err(FederationError::Conflict)
    ));
    let mut corrupt = ObjectDigestVerifier::new(blob.clone())?;
    corrupt.push(0, b"wrongly bytes")?;
    ensure!(matches!(corrupt.finish(), Err(FederationError::Corrupt)));
    let mut ordered = ObjectDigestVerifier::new(blob)?;
    ensure!(matches!(
        ordered.push(1, data),
        Err(FederationError::Conflict)
    ));
    ordered.push(0, data)?;
    ordered.finish()?;
    ensure!(ObjectGrantId::new(0).is_err());
    Ok(())
}
