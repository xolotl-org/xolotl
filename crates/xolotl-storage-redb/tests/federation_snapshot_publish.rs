#![cfg(feature = "federation")]

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use redb::{Database, ReadableDatabase, TableDefinition};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    AcknowledgeRequest, Digest, EventType, ExportAccess, ExportName, FederationError,
    FederationNodeId, FederationSnapshotPublisherStore, FederationStore, HistoryStart,
    MAX_SNAPSHOT_CHUNK_BYTES, OpenRequest, Position, PublishRequest, RequestId, SchemaRevision,
    SnapshotContentSource, SnapshotId, SnapshotOffer, SnapshotOfferRequest,
    SnapshotPublicationProof, SnapshotReadRequest, StreamId, StreamRef, StreamSpec, SubscriptionId,
    SubscriptionRef,
};
use xolotl_storage_redb::{RedbFederationStore, RedbStore};

const PUBLISHER: FederationNodeId = FederationNodeId::from_bytes([61; 48]);
const RECEIVER: FederationNodeId = FederationNodeId::from_bytes([62; 48]);
const STREAM: StreamRef = StreamRef {
    publisher: PUBLISHER,
    id: StreamId::from_bytes([63; 16]),
};
const SUBSCRIPTION: SubscriptionRef = SubscriptionRef {
    subscriber: RECEIVER,
    id: SubscriptionId::from_bytes([64; 16]),
};
const APP_BYTES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("snapshot_bytes");
const APP_PUBLICATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("snapshot_publications");

fn setup(path: &Path) -> Result<(RedbStore, RedbFederationStore)> {
    let db = RedbStore::open(path)?;
    let publisher = db.federation_store(PUBLISHER)?;
    publisher.set_peer_authority(RECEIVER, None, true)?;
    publisher.set_export_authority(
        RECEIVER,
        ExportName::new("notes")?,
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    publisher.declare_stream(StreamSpec {
        stream: STREAM,
        export: ExportName::new("notes")?,
    })?;
    publisher.open(OpenRequest {
        authenticated_subscriber: RECEIVER,
        request_id: RequestId::from_bytes([65; 16]),
        subscription: SUBSCRIPTION,
        stream: STREAM,
        expected_control_revision: Some(0),
        history: HistoryStart::All,
    })?;
    Ok((db, publisher))
}

fn publish(publisher: &impl FederationStore, id: u8) -> Result<xolotl_federation::Record> {
    Ok(publisher.append_published(PublishRequest {
        retry_epoch: 1,
        stream: STREAM,
        publish_id: RequestId::from_bytes([id; 16]),
        event_type: EventType::new("note")?,
        schema_revision: SchemaRevision::from_bytes([66; 32]),
        event_ref: None,
        payload: Arc::from([id].as_slice()),
    })?)
}

fn seal_application_publication(
    path: &Path,
    id: SnapshotId,
    position: Position,
    bytes: &[u8],
) -> Result<SnapshotPublicationProof> {
    let content_digest = Digest::from_bytes(Sha384::digest(bytes).into());
    let mut hash = Sha384::new();
    hash.update(b"application/pinned-federation-snapshot\0");
    hash.update(id.as_bytes());
    hash.update(STREAM.publisher.as_bytes());
    hash.update(STREAM.id.as_bytes());
    hash.update(position.sequence().to_be_bytes());
    hash.update(position.digest().as_bytes());
    hash.update(content_digest.as_bytes());
    hash.update((bytes.len() as u64).to_be_bytes());
    let publication_digest: [u8; 48] = hash.finalize().into();
    let db = Database::create(path)?;
    let txn = db.begin_write()?;
    txn.open_table(APP_BYTES)?
        .insert(id.as_bytes().as_slice(), bytes)?;
    txn.open_table(APP_PUBLICATIONS)?
        .insert(id.as_bytes().as_slice(), publication_digest.as_slice())?;
    txn.commit()?;
    drop(db);

    let db = Database::open(path)?;
    let txn = db.begin_read()?;
    let publications = txn.open_table(APP_PUBLICATIONS)?;
    let saved = publications
        .get(id.as_bytes().as_slice())?
        .context("publication proof missing")?;
    let publication_digest = Digest::from_bytes(saved.value().try_into()?);
    Ok(SnapshotPublicationProof {
        snapshot_id: id,
        stream: STREAM,
        position,
        schema_revision: SchemaRevision::from_bytes([67; 32]),
        content_digest,
        content_bytes: bytes.len() as u64,
        publication_digest,
    })
}

type BeforeReturn = Box<dyn Fn() -> Result<(), FederationError> + Send + Sync>;

struct DurableSource {
    path: PathBuf,
    before_return: Option<BeforeReturn>,
}

impl DurableSource {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            before_return: None,
        }
    }
}

impl SnapshotContentSource for DurableSource {
    fn read_snapshot_chunk(
        &self,
        offer: &SnapshotOffer,
        offset: u64,
        bytes: usize,
    ) -> Result<Arc<[u8]>, FederationError> {
        let content = {
            let db = Database::open(&self.path)
                .map_err(|error| FederationError::Storage(error.to_string()))?;
            let txn = db
                .begin_read()
                .map_err(|error| FederationError::Storage(error.to_string()))?;
            let proofs = txn
                .open_table(APP_PUBLICATIONS)
                .map_err(|error| FederationError::Storage(error.to_string()))?;
            let proof = proofs
                .get(offer.manifest.id.as_bytes().as_slice())
                .map_err(|error| FederationError::Storage(error.to_string()))?
                .ok_or(FederationError::NotFound)?;
            if proof.value() != offer.publication_digest.as_bytes() {
                return Err(FederationError::Conflict);
            }
            let table = txn
                .open_table(APP_BYTES)
                .map_err(|error| FederationError::Storage(error.to_string()))?;
            let saved = table
                .get(offer.manifest.id.as_bytes().as_slice())
                .map_err(|error| FederationError::Storage(error.to_string()))?
                .ok_or(FederationError::NotFound)?;
            let content = saved.value();
            if content.len() as u64 != offer.manifest.content_bytes
                || Digest::from_bytes(Sha384::digest(content).into())
                    != offer.manifest.content_digest
            {
                return Err(FederationError::Conflict);
            }
            let start = usize::try_from(offset).map_err(|_error| FederationError::Capacity)?;
            let end = start.checked_add(bytes).ok_or(FederationError::Capacity)?;
            Arc::from(content.get(start..end).ok_or(FederationError::Conflict)?)
        };
        if let Some(callback) = &self.before_return {
            callback()?;
        }
        Ok(content)
    }
}

fn offer_request(proof: SnapshotPublicationProof) -> SnapshotOfferRequest {
    SnapshotOfferRequest {
        authenticated_subscriber: RECEIVER,
        subscription: SUBSCRIPTION,
        proof,
    }
}

fn read_request(offer: &SnapshotOffer, offset: u64, max_bytes: usize) -> SnapshotReadRequest {
    SnapshotReadRequest {
        authenticated_subscriber: RECEIVER,
        subscription: SUBSCRIPTION,
        manifest_digest: offer.manifest.binding_digest(),
        offset,
        max_bytes,
    }
}

#[test]
fn offer_is_durable_exact_and_chunk_reads_recheck_revocation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let publisher_path = directory.path().join("publisher.redb");
    let application_path = directory.path().join("application.redb");
    let (publisher_db, publisher) = setup(&publisher_path)?;
    let first = publish(&publisher, 1)?;
    let second = publish(&publisher, 2)?;
    publisher.acknowledge(AcknowledgeRequest {
        authenticated_subscriber: RECEIVER,
        subscription: SUBSCRIPTION,
        position: second.position(),
    })?;
    let bytes = b"bounded immutable snapshot bytes";
    let proof = seal_application_publication(
        &application_path,
        SnapshotId::from_bytes([68; 16]),
        second.position(),
        bytes,
    )?;
    ensure!(matches!(
        publisher.publish_snapshot_offer(offer_request(SnapshotPublicationProof {
            position: first.position(),
            ..proof
        })),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        publisher.publish_snapshot_offer(offer_request(SnapshotPublicationProof {
            position: Position::new(second.sequence(), Digest::from_bytes([69; 48]))?,
            ..proof
        })),
        Err(FederationError::Conflict)
    ));
    let offer = publisher.publish_snapshot_offer(offer_request(proof))?;
    ensure!(publisher.publish_snapshot_offer(offer_request(proof))? == offer);
    let third = publish(&publisher, 3)?;
    ensure!(matches!(
        publisher.retire_published_history(STREAM, third.position(), 3),
        Err(FederationError::Conflict)
    ));
    ensure!(
        publisher
            .retire_published_history(STREAM, second.position(), 2)?
            .removed
            == 2
    );
    ensure!(matches!(
        publisher.publish_snapshot_offer(offer_request(SnapshotPublicationProof {
            publication_digest: Digest::from_bytes([70; 48]),
            ..proof
        })),
        Err(FederationError::Conflict)
    ));
    drop(publisher);
    drop(publisher_db);

    let publisher_db = RedbStore::open(&publisher_path)?;
    let publisher = publisher_db.federation_store(PUBLISHER)?;
    ensure!(publisher.snapshot_offer(RECEIVER, SUBSCRIPTION)? == Some(offer.clone()));
    let source = DurableSource::new(&application_path);
    let mut collected = Vec::new();
    let mut offset = 0_u64;
    while offset < bytes.len() as u64 {
        let chunk = publisher.read_snapshot_chunk(read_request(&offer, offset, 7), &source)?;
        ensure!(chunk.bytes.len() <= 7 && chunk.offset == offset && chunk.offer == offer);
        collected.extend_from_slice(&chunk.bytes);
        offset += chunk.bytes.len() as u64;
        ensure!(chunk.complete == (offset == bytes.len() as u64));
    }
    ensure!(collected == bytes);
    ensure!(
        publisher
            .read_snapshot_chunk(read_request(&offer, offset, 7), &source)?
            .complete
    );
    ensure!(matches!(
        publisher.read_snapshot_chunk(
            read_request(&offer, 0, MAX_SNAPSHOT_CHUNK_BYTES + 1),
            &source
        ),
        Err(FederationError::Capacity)
    ));
    ensure!(matches!(
        publisher.read_snapshot_chunk(read_request(&offer, bytes.len() as u64 + 1, 7), &source),
        Err(FederationError::Conflict)
    ));
    let mut wrong_binding = read_request(&offer, 0, 7);
    wrong_binding.manifest_digest = Digest::from_bytes([71; 48]);
    ensure!(matches!(
        publisher.read_snapshot_chunk(wrong_binding, &source),
        Err(FederationError::Conflict)
    ));

    let revoking = publisher.clone();
    let source = DurableSource {
        path: application_path,
        before_return: Some(Box::new(move || {
            revoking.set_export_authority(
                RECEIVER,
                ExportName::new("notes")?,
                Some(1),
                ExportAccess::default(),
            )?;
            Ok(())
        })),
    };
    ensure!(matches!(
        publisher.read_snapshot_chunk(read_request(&offer, 0, 7), &source),
        Err(FederationError::Unauthorized | FederationError::Conflict)
    ));
    ensure!(publisher.snapshot_offer(RECEIVER, SUBSCRIPTION).is_err());
    Ok(())
}

#[test]
fn offer_accepts_only_the_exact_retired_cursor_and_full_history_scope() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (_publisher_db, publisher) = setup(&directory.path().join("publisher.redb"))?;
    let first = publish(&publisher, 1)?;
    let second = publish(&publisher, 2)?;
    let third = publish(&publisher, 3)?;
    publisher.retire_published_history(STREAM, second.position(), 2)?;
    let proof = seal_application_publication(
        &directory.path().join("application.redb"),
        SnapshotId::from_bytes([72; 16]),
        second.position(),
        b"state through retired cursor",
    )?;
    ensure!(matches!(
        publisher.publish_snapshot_offer(offer_request(SnapshotPublicationProof {
            position: first.position(),
            ..proof
        })),
        Err(FederationError::ResyncRequired { .. })
    ));
    ensure!(
        publisher
            .publish_snapshot_offer(offer_request(proof))?
            .manifest
            .position
            == second.position()
    );
    ensure!(matches!(
        publisher.retire_published_history(STREAM, third.position(), 1),
        Err(FederationError::Conflict)
    ));

    let limited = SubscriptionRef {
        subscriber: RECEIVER,
        id: SubscriptionId::from_bytes([73; 16]),
    };
    let opened = publisher.open(OpenRequest {
        authenticated_subscriber: RECEIVER,
        request_id: RequestId::from_bytes([74; 16]),
        subscription: limited,
        stream: STREAM,
        expected_control_revision: Some(1),
        history: HistoryStart::FromNow,
    })?;
    ensure!(opened.start == Some(third.position()));
    ensure!(matches!(
        publisher.publish_snapshot_offer(SnapshotOfferRequest {
            authenticated_subscriber: RECEIVER,
            subscription: limited,
            proof: SnapshotPublicationProof {
                position: third.position(),
                ..proof
            },
        }),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn retired_offer_releases_its_pin_and_fences_in_flight_reads() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let application_path = directory.path().join("application.redb");
    let publisher_path = directory.path().join("publisher.redb");
    let (publisher_db, publisher) = setup(&publisher_path)?;
    let first = publish(&publisher, 1)?;
    let second = publish(&publisher, 2)?;
    let first_proof = seal_application_publication(
        &application_path,
        SnapshotId::from_bytes([75; 16]),
        first.position(),
        b"first application state",
    )?;
    let first_offer = publisher.publish_snapshot_offer(offer_request(first_proof))?;
    ensure!(matches!(
        publisher.retire_published_history(STREAM, second.position(), 2),
        Err(FederationError::Conflict)
    ));

    let retiring = publisher.clone();
    let expected = first_offer.clone();
    let retiring_source = DurableSource {
        path: application_path.clone(),
        before_return: Some(Box::new(move || {
            retiring.retire_snapshot_offer(&expected)?;
            Ok(())
        })),
    };
    ensure!(matches!(
        publisher.read_snapshot_chunk(read_request(&first_offer, 0, 5), &retiring_source),
        Err(FederationError::NotFound | FederationError::Conflict)
    ));
    drop(retiring_source);
    ensure!(publisher.local_snapshot_offer(SUBSCRIPTION)?.is_none());
    publisher.retire_snapshot_offer(&first_offer)?;
    ensure!(
        publisher
            .retire_published_history(STREAM, second.position(), 2)?
            .removed
            == 2
    );

    let second_proof = seal_application_publication(
        &application_path,
        SnapshotId::from_bytes([76; 16]),
        second.position(),
        b"second application state",
    )?;
    let second_offer = publisher.publish_snapshot_offer(offer_request(second_proof))?;
    ensure!(matches!(
        publisher.retire_snapshot_offer(&first_offer),
        Err(FederationError::Conflict)
    ));
    ensure!(publisher.local_snapshot_offer(SUBSCRIPTION)? == Some(second_offer.clone()));
    let source = DurableSource::new(&application_path);
    ensure!(
        publisher
            .read_snapshot_chunk(read_request(&second_offer, 0, 6), &source)?
            .bytes
            .as_ref()
            == b"second"
    );

    publisher.set_export_authority(
        RECEIVER,
        ExportName::new("notes")?,
        Some(1),
        ExportAccess::default(),
    )?;
    ensure!(publisher.snapshot_offer(RECEIVER, SUBSCRIPTION).is_err());
    ensure!(publisher.local_snapshot_offer(SUBSCRIPTION)? == Some(second_offer.clone()));
    publisher.retire_snapshot_offer(&second_offer)?;
    ensure!(publisher.local_snapshot_offer(SUBSCRIPTION)?.is_none());
    drop(publisher);
    drop(publisher_db);
    let reopened = RedbStore::open(&publisher_path)?;
    let publisher = reopened.federation_store(PUBLISHER)?;
    ensure!(publisher.local_snapshot_offer(SUBSCRIPTION)?.is_none());
    publisher.retire_snapshot_offer(&second_offer)?;
    Ok(())
}
