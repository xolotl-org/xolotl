//! Real TLS download with a separate durable application projection handoff.

use super::*;

use redb::{Database, ReadableDatabase as _, ReadableTable as _, TableDefinition};
use xolotl_federation::{
    AcceptRequest, FederationSnapshotStore, InboxReadRequest, SnapshotInstallRequest,
    SnapshotManifest, SnapshotProjectionCompletion,
};

const STAGING: TableDefinition<&[u8], &[u8]> = TableDefinition::new("app_snapshot_staging");
const SEALED: TableDefinition<&[u8], &[u8]> = TableDefinition::new("app_snapshot_sealed");
const COMPLETIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("app_snapshot_completions");

fn initialize_application(path: &std::path::Path) -> Result<Database> {
    let db = Database::create(path)?;
    let txn = db.begin_write()?;
    txn.open_table(STAGING)?;
    txn.open_table(SEALED)?;
    txn.open_table(COMPLETIONS)?;
    txn.commit()?;
    Ok(db)
}

fn chunk_key(id: SnapshotId, offset: u64) -> [u8; 24] {
    let mut key = [0; 24];
    key[..16].copy_from_slice(id.as_bytes());
    key[16..].copy_from_slice(&offset.to_be_bytes());
    key
}

fn stage_chunk(db: &Database, id: SnapshotId, offset: u64, bytes: &[u8]) -> Result<()> {
    ensure!(!bytes.is_empty());
    let txn = db.begin_write()?;
    txn.open_table(STAGING)?
        .insert(chunk_key(id, offset).as_slice(), bytes)?;
    txn.commit()?;
    Ok(())
}

/// Seal exact contiguous staged bytes and completion evidence in one
/// application transaction. This test host never supplies an unsealed proof
/// to the federation store.
fn seal_application(
    db: &Database,
    install_id: SnapshotId,
    manifest: &SnapshotManifest,
) -> Result<()> {
    let txn = db.begin_write()?;
    let mut content = Vec::with_capacity(usize::try_from(manifest.content_bytes)?);
    {
        let staging = txn.open_table(STAGING)?;
        while content.len() < manifest.content_bytes as usize {
            let offset = content.len() as u64;
            let key = chunk_key(install_id, offset);
            let part = staging
                .get(key.as_slice())?
                .context("application snapshot chunk missing")?;
            ensure!(!part.value().is_empty());
            content.extend_from_slice(part.value());
            ensure!(content.len() as u64 <= manifest.content_bytes);
        }
    }
    ensure!(content.len() as u64 == manifest.content_bytes);
    ensure!(Digest::from_bytes(Sha384::digest(&content).into()) == manifest.content_digest);

    let manifest_digest = manifest.binding_digest();
    let mut completion_hash = Sha384::new();
    completion_hash.update(b"application/snapshot-completion\0");
    completion_hash.update(install_id.as_bytes());
    completion_hash.update(manifest_digest.as_bytes());
    completion_hash.update(&content);
    let completion_digest: [u8; 48] = completion_hash.finalize().into();
    let mut proof = Vec::with_capacity(104);
    proof.extend_from_slice(manifest_digest.as_bytes());
    proof.extend_from_slice(&1_u64.to_be_bytes());
    proof.extend_from_slice(&completion_digest);
    txn.open_table(SEALED)?
        .insert(install_id.as_bytes().as_slice(), content.as_slice())?;
    txn.open_table(COMPLETIONS)?
        .insert(install_id.as_bytes().as_slice(), proof.as_slice())?;
    txn.commit()?;
    Ok(())
}

/// Recover only evidence found in the independent durable application DB,
/// checking the sealed content and completion hash again after reopen.
fn application_completion(
    db: &Database,
    install_id: SnapshotId,
    manifest: &SnapshotManifest,
) -> Result<Option<SnapshotProjectionCompletion>> {
    let txn = db.begin_read()?;
    let proofs = txn.open_table(COMPLETIONS)?;
    let Some(proof) = proofs.get(install_id.as_bytes().as_slice())? else {
        return Ok(None);
    };
    let proof = proof.value();
    ensure!(proof.len() == 104);
    let manifest_digest = Digest::from_bytes(proof[..48].try_into()?);
    ensure!(manifest_digest == manifest.binding_digest());
    let application_generation = u64::from_be_bytes(proof[48..56].try_into()?);
    ensure!(application_generation == 1);
    let completion_digest = Digest::from_bytes(proof[56..104].try_into()?);
    let sealed = txn.open_table(SEALED)?;
    let bytes = sealed
        .get(install_id.as_bytes().as_slice())?
        .context("sealed application snapshot missing")?;
    let bytes = bytes.value();
    ensure!(bytes.len() as u64 == manifest.content_bytes);
    ensure!(Digest::from_bytes(Sha384::digest(bytes).into()) == manifest.content_digest);
    let mut hash = Sha384::new();
    hash.update(b"application/snapshot-completion\0");
    hash.update(install_id.as_bytes());
    hash.update(manifest_digest.as_bytes());
    hash.update(bytes);
    ensure!(Digest::from_bytes(hash.finalize().into()) == completion_digest);
    Ok(Some(SnapshotProjectionCompletion {
        install_id,
        snapshot_id: manifest.id,
        content_digest: manifest.content_digest,
        manifest_digest,
        application_generation,
        completion_digest,
    }))
}

fn publish_record(
    publisher: &RedbFederationStore,
    stream: StreamRef,
    id: u8,
) -> Result<xolotl_federation::Record> {
    Ok(publisher.append_published(PublishRequest {
        retry_epoch: 1,
        stream,
        publish_id: RequestId::from_bytes([id; 16]),
        event_type: EventType::new("snapshot-handoff")?,
        schema_revision: SchemaRevision::from_bytes([121; 32]),
        event_ref: None,
        payload: Arc::from([id].as_slice()),
    })?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn downloaded_snapshot_seals_independent_application_before_anchor_and_resumes_after_reopen()
-> Result<()> {
    let config = FederationGrpcConfig {
        max_sessions: 1,
        max_blocking_verifications: 1,
        hello_timeout: Duration::from_secs(5),
        response_timeout: Duration::from_secs(5),
        ..FederationGrpcConfig::default()
    };
    let publisher_identity = identity()?;
    let receiver_identity = identity()?;
    let publisher_node = publisher_identity.node_id();
    let receiver_node = receiver_identity.node_id();
    let stream = StreamRef {
        publisher: publisher_node,
        id: StreamId::from_bytes([122; 16]),
    };
    let subscription = SubscriptionRef {
        subscriber: receiver_node,
        id: SubscriptionId::from_bytes([123; 16]),
    };
    let install_id = SnapshotId::from_bytes([124; 16]);
    let directory = tempfile::tempdir()?;
    let publisher_path = directory.path().join("publisher.redb");
    let receiver_path = directory.path().join("receiver.redb");
    let application_path = directory.path().join("application.redb");
    let content_path = directory.path().join("published.snapshot");
    let snapshot_bytes = b"application state through the second committed record";
    let mut published = std::fs::File::create(&content_path)?;
    published.write_all(snapshot_bytes)?;
    published.sync_all()?;
    drop(published);

    let publisher_db = RedbStore::open(&publisher_path)?;
    let publisher = publisher_db.federation_store(publisher_node)?;
    publisher.set_peer_authority(receiver_node, None, true)?;
    publisher.set_peer_admission(
        receiver_node,
        None,
        xolotl_federation::PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![receiver_identity.authorization_digest()],
        },
    )?;
    publisher.set_export_authority(
        receiver_node,
        ExportName::new("snapshot")?,
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    publisher.declare_stream(StreamSpec {
        stream,
        export: ExportName::new("snapshot")?,
    })?;
    let receiver_db = RedbStore::open(&receiver_path)?;
    let receiver = receiver_db.federation_store(receiver_node)?;
    let receiver_service =
        FederationService::new(Arc::new(receiver.clone()), FederationLimits::default())?;
    receiver.set_peer_authority(publisher_node, None, true)?;
    receiver.set_peer_admission(
        publisher_node,
        None,
        xolotl_federation::PeerAdmission {
            minimum_online_generation: 1,
            allowed_authorization_digests: vec![publisher_identity.authorization_digest()],
        },
    )?;
    receiver.set_export_authority(
        publisher_node,
        ExportName::new("snapshot")?,
        None,
        ExportAccess {
            serve: false,
            receive: true,
        },
    )?;
    let source = Arc::new(SnapshotFileSource {
        path: content_path,
        publisher: publisher.clone(),
        subscriber: receiver_node,
        revoke_on_read: Arc::new(AtomicBool::new(false)),
    });
    let (client, stop, task, runtimes, blocking) = start_snapshot_peer(
        publisher.clone(),
        source,
        publisher_identity,
        receiver_identity,
        config,
    )
    .await?;
    let opened = client
        .open_and_install(
            OpenRequest {
                authenticated_subscriber: receiver_node,
                request_id: RequestId::from_bytes([125; 16]),
                subscription,
                stream,
                expected_control_revision: Some(0),
                history: HistoryStart::All,
            },
            &receiver_service,
        )
        .await?;
    ensure!(opened.start.is_none());
    drop(receiver_service);
    let _first = publish_record(&publisher, stream, 126)?;
    let second = publish_record(&publisher, stream, 127)?;
    let offer = publisher.publish_snapshot_offer(SnapshotOfferRequest {
        authenticated_subscriber: receiver_node,
        subscription,
        proof: SnapshotPublicationProof {
            snapshot_id: SnapshotId::from_bytes([128; 16]),
            stream,
            position: second.position(),
            schema_revision: SchemaRevision::from_bytes([129; 32]),
            content_digest: Digest::from_bytes(Sha384::digest(snapshot_bytes).into()),
            content_bytes: snapshot_bytes.len() as u64,
            publication_digest: Digest::from_bytes(
                Sha384::digest(b"durable test publication").into(),
            ),
        },
    })?;
    let third = publish_record(&publisher, stream, 130)?;
    ensure!(client.inspect_snapshot(subscription).await? == offer);
    let request = SnapshotInstallRequest {
        install_id,
        subject: FederationSubject::Node(receiver_node),
        manifest: offer.manifest.clone(),
        publication_digest: offer.publication_digest,
        expected_generation: 0,
    };
    ensure!(receiver.begin_snapshot_install(request.clone())?.pending == Some(request.clone()));

    let application = initialize_application(&application_path)?;
    let mut offset = 0_u64;
    let mut last_offset = 0_u64;
    let mut last_bytes = Vec::new();
    while offset < offer.manifest.content_bytes {
        let chunk = client.read_snapshot(offer.clone(), offset, 7).await?;
        ensure!(chunk.offset == offset && !chunk.bytes.is_empty());
        stage_chunk(&application, install_id, offset, &chunk.bytes)?;
        last_offset = offset;
        last_bytes = chunk.bytes.as_ref().to_vec();
        offset += chunk.bytes.len() as u64;
        ensure!(chunk.complete == (offset == offer.manifest.content_bytes));
    }
    ensure!(application_completion(&application, install_id, &offer.manifest)?.is_none());
    drop(application);
    drop(receiver);
    drop(receiver_db);

    // Simulate a crash after all chunks were durable but before the
    // application's atomic seal. Neither database may infer a completion.
    let application = Database::open(&application_path)?;
    let receiver_db = RedbStore::open(&receiver_path)?;
    let receiver = receiver_db.federation_store(receiver_node)?;
    let recovered = receiver
        .snapshot_install(subscription)?
        .context("install intent missing")?;
    ensure!(recovered.pending == Some(request) && recovered.active.is_none());
    ensure!(application_completion(&application, install_id, &offer.manifest)?.is_none());

    // A corrupt durable chunk cannot produce application completion evidence.
    last_bytes[0] ^= 1;
    stage_chunk(&application, install_id, last_offset, &last_bytes)?;
    ensure!(seal_application(&application, install_id, &offer.manifest).is_err());
    ensure!(application_completion(&application, install_id, &offer.manifest)?.is_none());
    ensure!(
        receiver
            .snapshot_install(subscription)?
            .context("intent missing")?
            .active
            .is_none()
    );
    let repaired = client.read_snapshot(offer.clone(), last_offset, 7).await?;
    stage_chunk(&application, install_id, last_offset, &repaired.bytes)?;
    seal_application(&application, install_id, &offer.manifest)?;
    drop(application);

    let application = Database::open(&application_path)?;
    let completion = application_completion(&application, install_id, &offer.manifest)?
        .context("application seal not durable")?;
    let anchor = receiver.commit_snapshot_anchor(subscription, completion)?;
    ensure!(anchor.manifest.position == second.position() && anchor.federation_generation == 1);
    drop(receiver);
    drop(receiver_db);
    drop(application);

    let receiver_db = RedbStore::open(&receiver_path)?;
    let receiver = receiver_db.federation_store(receiver_node)?;
    let view = receiver
        .snapshot_install(subscription)?
        .context("anchor missing")?;
    ensure!(view.active == Some(anchor) && view.pending.is_none() && view.generation == 1);
    let page = client
        .read(
            ReadRequest {
                authenticated_subscriber: receiver_node,
                subscription,
                after: Some(second.position()),
                max_records: 8,
                max_bytes: 1024,
            },
            stream,
        )
        .await?;
    ensure!(page.records.len() == 1 && page.records[0] == third);
    ensure!(
        receiver
            .accept_in_generation(
                1,
                AcceptRequest {
                    authenticated_publisher: publisher_node,
                    subscription,
                    record: page.records[0].clone(),
                }
            )?
            .position
            == third.position()
    );
    let inbox = receiver.read_inbox_in_generation(
        1,
        InboxReadRequest {
            subscription,
            expected_stream: stream,
            after: Some(second.position()),
            max_records: 8,
            max_bytes: 1024,
        },
    )?;
    ensure!(inbox.records == vec![third]);

    drop(client);
    stop.send(())
        .map_err(|_sent| anyhow::anyhow!("server stopped early"))?;
    tokio::time::timeout(Duration::from_secs(3), task).await???;
    for runtime in runtimes {
        runtime.shutdown().await;
    }
    blocking.close();
    blocking.wait_idle().await;
    Ok(())
}
