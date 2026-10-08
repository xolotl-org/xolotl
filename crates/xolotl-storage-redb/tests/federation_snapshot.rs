#![cfg(feature = "federation")]

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result, ensure};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    AcceptRequest, AuthorityRevision, Digest, EventType, ExportAccess, ExportName, FederationError,
    FederationNodeId, FederationSnapshotStore, FederationStore, FederationSubject, HistoryStart,
    InboxReadRequest, InstallSubscriptionRequest, OpenRequest, Position, ProjectionProgress,
    PublishRequest, ReadRequest, RequestId, SchemaRevision, SnapshotAnchor,
    SnapshotArchiveCompletion, SnapshotId, SnapshotInstallRequest, SnapshotManifest,
    SnapshotProjectionCompletion, SnapshotReaderRelease, StreamId, StreamRef, StreamSpec,
    SubscriptionId, SubscriptionRef,
};
use xolotl_storage_redb::{RedbFederationStore, RedbStore};

const PUBLISHER: FederationNodeId = FederationNodeId::from_bytes([41; 48]);
const RECEIVER: FederationNodeId = FederationNodeId::from_bytes([42; 48]);
const STREAM: StreamRef = StreamRef {
    publisher: PUBLISHER,
    id: StreamId::from_bytes([43; 16]),
};
const SUBSCRIPTION: SubscriptionRef = SubscriptionRef {
    subscriber: RECEIVER,
    id: SubscriptionId::from_bytes([44; 16]),
};
const APPLICATION_PROOFS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("application_snapshot_proofs");
const APPLICATION_BYTES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("application_snapshot_bytes");
const APPLICATION_READER_RELEASES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("application_reader_releases");
const INBOX_ROWS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("federation_inbox_v1");

fn setup(
    publisher_path: &Path,
    receiver_path: &Path,
    history: HistoryStart,
) -> Result<(
    RedbStore,
    RedbStore,
    RedbFederationStore,
    RedbFederationStore,
)> {
    let publisher_db = RedbStore::open(publisher_path)?;
    let receiver_db = RedbStore::open(receiver_path)?;
    let publisher = publisher_db.federation_store(PUBLISHER)?;
    let receiver = receiver_db.federation_store(RECEIVER)?;
    let export = ExportName::new("notes")?;
    publisher.set_peer_authority(RECEIVER, None, true)?;
    receiver.set_peer_authority(PUBLISHER, None, true)?;
    publisher.set_export_authority(
        RECEIVER,
        export.clone(),
        None,
        ExportAccess {
            serve: true,
            receive: false,
        },
    )?;
    receiver.set_export_authority(
        PUBLISHER,
        export.clone(),
        None,
        ExportAccess {
            serve: false,
            receive: true,
        },
    )?;
    publisher.declare_stream(StreamSpec {
        stream: STREAM,
        export,
    })?;
    let opened = publisher.open(OpenRequest {
        authenticated_subscriber: RECEIVER,
        request_id: RequestId::from_bytes([45; 16]),
        subscription: SUBSCRIPTION,
        stream: STREAM,
        expected_control_revision: Some(0),
        history,
    })?;
    receiver.install_subscription(InstallSubscriptionRequest {
        authenticated_publisher: PUBLISHER,
        opened,
    })?;
    Ok((publisher_db, receiver_db, publisher, receiver))
}

fn publish(store: &impl FederationStore, id: u8) -> Result<xolotl_federation::Record> {
    Ok(store.append_published(PublishRequest {
        retry_epoch: 1,
        stream: STREAM,
        publish_id: RequestId::from_bytes([id; 16]),
        event_type: EventType::new("note")?,
        schema_revision: SchemaRevision::from_bytes([46; 32]),
        event_ref: None,
        payload: Arc::from([id].as_slice()),
    })?)
}

fn accept(store: &impl FederationStore, record: &xolotl_federation::Record) -> Result<Position> {
    Ok(store
        .accept(AcceptRequest {
            authenticated_publisher: PUBLISHER,
            subscription: SUBSCRIPTION,
            record: record.clone(),
        })?
        .position)
}

fn accept_request(record: &xolotl_federation::Record) -> AcceptRequest {
    AcceptRequest {
        authenticated_publisher: PUBLISHER,
        subscription: SUBSCRIPTION,
        record: record.clone(),
    }
}

fn inbox(after: Option<Position>) -> InboxReadRequest {
    InboxReadRequest {
        subscription: SUBSCRIPTION,
        expected_stream: STREAM,
        after,
        max_records: 8,
        max_bytes: 1024,
    }
}

/// A separate application database seals the bytes and completion together.
/// The federation store cannot invent or atomically commit this proof for it.
fn seal_application(
    path: &Path,
    install_id: SnapshotId,
    manifest: &SnapshotManifest,
    bytes: &[u8],
) -> Result<()> {
    ensure!(bytes.len() as u64 == manifest.content_bytes);
    ensure!(Digest::from_bytes(Sha384::digest(bytes).into()) == manifest.content_digest);
    let mut proof = Vec::with_capacity(48 + 8 + 48);
    proof.extend_from_slice(manifest.binding_digest().as_bytes());
    proof.extend_from_slice(&1_u64.to_be_bytes());
    let mut hash = Sha384::new();
    hash.update(b"application/snapshot-completion\0");
    hash.update(install_id.as_bytes());
    hash.update(manifest.binding_digest().as_bytes());
    hash.update(bytes);
    proof.extend_from_slice(&hash.finalize());
    let db = Database::create(path)?;
    let txn = db.begin_write()?;
    txn.open_table(APPLICATION_BYTES)?
        .insert(install_id.as_bytes().as_slice(), bytes)?;
    txn.open_table(APPLICATION_PROOFS)?
        .insert(install_id.as_bytes().as_slice(), proof.as_slice())?;
    txn.commit()?;
    Ok(())
}

fn reopened_application_completion(
    path: &Path,
    install_id: SnapshotId,
    manifest: &SnapshotManifest,
) -> Result<SnapshotProjectionCompletion> {
    let db = Database::open(path)?;
    let txn = db.begin_read()?;
    let proofs = txn.open_table(APPLICATION_PROOFS)?;
    let saved = proofs
        .get(install_id.as_bytes().as_slice())?
        .context("application completion missing")?;
    let proof = saved.value();
    ensure!(proof.len() == 104);
    let manifest_digest = Digest::from_bytes(proof[..48].try_into()?);
    ensure!(manifest_digest == manifest.binding_digest());
    let application_generation = u64::from_be_bytes(proof[48..56].try_into()?);
    let completion_digest = Digest::from_bytes(proof[56..104].try_into()?);
    let bytes_table = txn.open_table(APPLICATION_BYTES)?;
    let bytes = bytes_table
        .get(install_id.as_bytes().as_slice())?
        .context("application snapshot missing")?;
    ensure!(Digest::from_bytes(Sha384::digest(bytes.value()).into()) == manifest.content_digest);
    Ok(SnapshotProjectionCompletion {
        install_id,
        snapshot_id: manifest.id,
        content_digest: manifest.content_digest,
        manifest_digest,
        application_generation,
        completion_digest,
    })
}

fn seal_reader_release(path: &Path, anchor: &SnapshotAnchor) -> Result<()> {
    let db = Database::open(path)?;
    let txn = db.begin_write()?;
    let completion = {
        let proofs = txn.open_table(APPLICATION_PROOFS)?;
        let saved = proofs
            .get(anchor.install_id.as_bytes().as_slice())?
            .context("application completion missing")?;
        saved.value()[56..104].to_vec()
    };
    ensure!(completion.as_slice() == anchor.completion_digest.as_bytes());
    let mut hash = Sha384::new();
    hash.update(b"application/readers-released\0");
    hash.update(anchor.install_id.as_bytes());
    hash.update(anchor.federation_generation.to_be_bytes());
    hash.update(anchor.completion_digest.as_bytes());
    let release_digest: [u8; 48] = hash.finalize().into();
    txn.open_table(APPLICATION_READER_RELEASES)?.insert(
        anchor.install_id.as_bytes().as_slice(),
        release_digest.as_slice(),
    )?;
    txn.commit()?;
    Ok(())
}

fn reopened_reader_release(path: &Path, anchor: &SnapshotAnchor) -> Result<SnapshotReaderRelease> {
    let db = Database::open(path)?;
    let txn = db.begin_read()?;
    let releases = txn.open_table(APPLICATION_READER_RELEASES)?;
    let saved = releases
        .get(anchor.install_id.as_bytes().as_slice())?
        .context("reader release missing")?;
    Ok(SnapshotReaderRelease {
        subscription: anchor.manifest.subscription,
        install_id: anchor.install_id,
        federation_generation: anchor.federation_generation,
        application_generation: anchor.application_generation,
        completion_digest: anchor.completion_digest,
        released_through_generation: anchor.federation_generation - 1,
        release_digest: Digest::from_bytes(saved.value().try_into()?),
    })
}

#[test]
fn snapshot_install_survives_reopen_and_fences_old_delivery_generation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let publisher_path = directory.path().join("publisher.redb");
    let receiver_path = directory.path().join("receiver.redb");
    let application_path = directory.path().join("application.redb");
    let (_publisher_db, receiver_db, publisher, receiver) =
        setup(&publisher_path, &receiver_path, HistoryStart::All)?;
    let first = publish(&publisher, 1)?;
    let second = publish(&publisher, 2)?;
    let third = publish(&publisher, 3)?;
    let opened = publisher.inspect_subscription(xolotl_federation::InspectSubscriptionRequest {
        authenticated_subscriber: RECEIVER,
        subscription: SUBSCRIPTION,
    })?;
    ensure!(accept(&receiver, &first)? == first.position());
    ensure!(accept(&receiver, &second)? == second.position());
    ensure!(
        receiver.record_projection_progress(ProjectionProgress {
            subscription: SUBSCRIPTION,
            position: first.position(),
        })? == first.position()
    );
    publisher.retire_published_history(STREAM, second.position(), 2)?;
    ensure!(matches!(
        publisher.read(ReadRequest {
            authenticated_subscriber: RECEIVER,
            subscription: SUBSCRIPTION,
            after: None,
            max_records: 8,
            max_bytes: 1024,
        }),
        Err(FederationError::ResyncRequired { .. })
    ));
    let snapshot_bytes = b"pure remote state through record three";
    let snapshot = SnapshotManifest {
        id: SnapshotId::from_bytes([48; 16]),
        subscription: SUBSCRIPTION,
        stream: STREAM,
        subscription_revision: opened.subscription_revision,
        publisher_authority: AuthorityRevision { peer: 1, export: 1 },
        position: third.position(),
        schema_revision: SchemaRevision::from_bytes([47; 32]),
        content_digest: Digest::from_bytes(Sha384::digest(snapshot_bytes).into()),
        content_bytes: snapshot_bytes.len() as u64,
    };
    let install_id = SnapshotId::from_bytes([49; 16]);
    let request = SnapshotInstallRequest {
        install_id,
        subject: FederationSubject::Node(RECEIVER),
        manifest: snapshot.clone(),
        publication_digest: Digest::from_bytes([85; 48]),
        expected_generation: 0,
    };
    let pending = receiver.begin_snapshot_install(request.clone())?;
    ensure!(pending.pending == Some(request.clone()));
    receiver.abort_snapshot_install(SUBSCRIPTION, install_id)?;
    ensure!(receiver.read_inbox(inbox(None))?.records == vec![first.clone(), second.clone()]);
    ensure!(receiver.begin_snapshot_install(request)?.pending.is_some());
    ensure!(matches!(
        receiver.accept(accept_request(&second)),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.accept_in_generation(0, accept_request(&second)),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.read_inbox(inbox(None)),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.read_inbox_in_generation(0, inbox(None)),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.record_projection_progress(ProjectionProgress {
            subscription: SUBSCRIPTION,
            position: second.position(),
        }),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.record_projection_progress_in_generation(
            0,
            ProjectionProgress {
                subscription: SUBSCRIPTION,
                position: second.position(),
            }
        ),
        Err(FederationError::Conflict)
    ));
    seal_application(&application_path, install_id, &snapshot, snapshot_bytes)?;
    drop(receiver);
    drop(receiver_db);

    let receiver_db = RedbStore::open(&receiver_path)?;
    let receiver = receiver_db.federation_store(RECEIVER)?;
    ensure!(
        receiver
            .snapshot_install(SUBSCRIPTION)?
            .context("intent missing")?
            .pending
            .is_some()
    );
    let completion = reopened_application_completion(&application_path, install_id, &snapshot)?;
    let anchor = receiver.commit_snapshot_anchor(SUBSCRIPTION, completion)?;
    ensure!(anchor.federation_generation == 1 && anchor.manifest.position == third.position());
    ensure!(receiver.receiver_cursor_in_generation(1, SUBSCRIPTION)? == Some(third.position()));
    ensure!(matches!(
        receiver.receiver_cursor_in_generation(0, SUBSCRIPTION),
        Err(FederationError::Conflict)
    ));
    ensure!(receiver.commit_snapshot_anchor(SUBSCRIPTION, completion)? == anchor);
    ensure!(matches!(
        receiver.commit_snapshot_anchor(
            SUBSCRIPTION,
            SnapshotProjectionCompletion {
                manifest_digest: Digest::from_bytes([99; 48]),
                ..completion
            }
        ),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.accept(accept_request(&second)),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.record_projection_progress_in_generation(
            1,
            ProjectionProgress {
                subscription: SUBSCRIPTION,
                position: second.position(),
            }
        ),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.accept_in_generation(0, accept_request(&second)),
        Err(FederationError::Conflict)
    ));
    let fourth = publish(&publisher, 4)?;
    ensure!(
        receiver
            .accept_in_generation(1, accept_request(&fourth))?
            .position
            == fourth.position()
    );
    ensure!(receiver.read_inbox_in_generation(1, inbox(None))?.records == vec![fourth.clone()]);
    ensure!(
        receiver
            .read_inbox_in_generation(1, inbox(Some(third.position())))?
            .records
            == vec![fourth.clone()]
    );
    ensure!(matches!(
        receiver.read_inbox_in_generation(1, inbox(Some(first.position()))),
        Err(FederationError::Unauthorized)
    ));
    ensure!(
        receiver.record_projection_progress_in_generation(
            1,
            ProjectionProgress {
                subscription: SUBSCRIPTION,
                position: fourth.position(),
            }
        )? == fourth.position()
    );
    ensure!(matches!(
        receiver.retire_projected_inbox_in_generation(0, SUBSCRIPTION, 1),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.retire_projected_inbox(SUBSCRIPTION, 1),
        Err(FederationError::Conflict)
    ));
    let retired = receiver.retire_projected_inbox_in_generation(1, SUBSCRIPTION, 1)?;
    ensure!(retired.removed == 1 && retired.retired_through == Some(fourth.position()));
    ensure!(receiver.receiver_cursor_in_generation(1, SUBSCRIPTION)? == Some(fourth.position()));
    ensure!(
        receiver
            .read_inbox_in_generation(1, inbox(None))?
            .records
            .is_empty()
    );
    ensure!(matches!(
        receiver.read_inbox(inbox(None)),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn snapshot_install_rejects_uncovered_receipts_revocation_and_close() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (_publisher_db, _receiver_db, publisher, receiver) = setup(
        &directory.path().join("publisher.redb"),
        &directory.path().join("receiver.redb"),
        HistoryStart::All,
    )?;
    let first = publish(&publisher, 1)?;
    let second = publish(&publisher, 2)?;
    accept(&receiver, &first)?;
    accept(&receiver, &second)?;
    let opened = publisher.inspect_subscription(xolotl_federation::InspectSubscriptionRequest {
        authenticated_subscriber: RECEIVER,
        subscription: SUBSCRIPTION,
    })?;
    let bytes = b"snapshot";
    let early = SnapshotManifest {
        id: SnapshotId::from_bytes([50; 16]),
        subscription: SUBSCRIPTION,
        stream: STREAM,
        subscription_revision: opened.subscription_revision,
        publisher_authority: AuthorityRevision { peer: 1, export: 1 },
        position: first.position(),
        schema_revision: SchemaRevision::from_bytes([47; 32]),
        content_digest: Digest::from_bytes(Sha384::digest(bytes).into()),
        content_bytes: bytes.len() as u64,
    };
    ensure!(matches!(
        receiver.begin_snapshot_install(SnapshotInstallRequest {
            install_id: SnapshotId::from_bytes([51; 16]),
            subject: FederationSubject::Node(RECEIVER),
            manifest: early.clone(),
            publication_digest: Digest::from_bytes([85; 48]),
            expected_generation: 0,
        }),
        Err(FederationError::Conflict)
    ));
    let later = SnapshotManifest {
        id: SnapshotId::from_bytes([52; 16]),
        position: second.position(),
        ..early
    };
    let install_id = SnapshotId::from_bytes([53; 16]);
    receiver.begin_snapshot_install(SnapshotInstallRequest {
        install_id,
        subject: FederationSubject::Node(RECEIVER),
        manifest: later.clone(),
        publication_digest: Digest::from_bytes([85; 48]),
        expected_generation: 0,
    })?;
    let application_path = directory.path().join("application.redb");
    seal_application(&application_path, install_id, &later, bytes)?;
    let completion = reopened_application_completion(&application_path, install_id, &later)?;
    receiver.set_export_authority(
        PUBLISHER,
        ExportName::new("notes")?,
        Some(1),
        ExportAccess::default(),
    )?;
    ensure!(
        receiver
            .commit_snapshot_anchor(SUBSCRIPTION, completion)
            .is_err()
    );
    ensure!(
        receiver
            .snapshot_install(SUBSCRIPTION)?
            .context("intent missing")?
            .active
            .is_none()
    );
    receiver.close_snapshot_receiver(SUBSCRIPTION)?;
    ensure!(matches!(
        receiver.commit_snapshot_anchor(SUBSCRIPTION, completion),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.accept(accept_request(&second)),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn snapshot_install_rejects_a_history_exclusion_without_view_proof() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let (_publisher_db, _receiver_db, publisher, receiver) = setup(
        &directory.path().join("publisher.redb"),
        &directory.path().join("receiver.redb"),
        HistoryStart::All,
    )?;
    let first = publish(&publisher, 1)?;
    let limited = SubscriptionRef {
        subscriber: RECEIVER,
        id: SubscriptionId::from_bytes([54; 16]),
    };
    let opened = publisher.open(OpenRequest {
        authenticated_subscriber: RECEIVER,
        request_id: RequestId::from_bytes([55; 16]),
        subscription: limited,
        stream: STREAM,
        expected_control_revision: Some(1),
        history: HistoryStart::FromNow,
    })?;
    ensure!(opened.start == Some(first.position()));
    receiver.install_subscription(InstallSubscriptionRequest {
        authenticated_publisher: PUBLISHER,
        opened: opened.clone(),
    })?;
    let second = publish(&publisher, 2)?;
    let bytes = b"current state includes pre-grant history";
    let manifest = SnapshotManifest {
        id: SnapshotId::from_bytes([56; 16]),
        subscription: limited,
        stream: STREAM,
        subscription_revision: opened.subscription_revision,
        publisher_authority: AuthorityRevision { peer: 1, export: 1 },
        position: second.position(),
        schema_revision: SchemaRevision::from_bytes([47; 32]),
        content_digest: Digest::from_bytes(Sha384::digest(bytes).into()),
        content_bytes: bytes.len() as u64,
    };
    ensure!(matches!(
        receiver.begin_snapshot_install(SnapshotInstallRequest {
            install_id: SnapshotId::from_bytes([57; 16]),
            subject: FederationSubject::Node(RECEIVER),
            manifest,
            publication_digest: Digest::from_bytes([85; 48]),
            expected_generation: 0,
        }),
        Err(FederationError::Conflict)
    ));
    Ok(())
}

#[test]
fn archived_snapshot_receives_tail_but_cannot_claim_application_progress() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let receiver_path = directory.path().join("receiver.redb");
    let application_path = directory.path().join("application.redb");
    let (_publisher_db, receiver_db, publisher, receiver) = setup(
        &directory.path().join("publisher.redb"),
        &receiver_path,
        HistoryStart::All,
    )?;
    let records = (1..=5)
        .map(|id| publish(&publisher, id))
        .collect::<Result<Vec<_>>>()?;
    accept(&receiver, &records[0])?;
    accept(&receiver, &records[1])?;
    let opened = publisher.inspect_subscription(xolotl_federation::InspectSubscriptionRequest {
        authenticated_subscriber: RECEIVER,
        subscription: SUBSCRIPTION,
    })?;
    let bytes = b"application state through third record";
    let manifest = SnapshotManifest {
        id: SnapshotId::from_bytes([70; 16]),
        subscription: SUBSCRIPTION,
        stream: STREAM,
        subscription_revision: opened.subscription_revision,
        publisher_authority: AuthorityRevision { peer: 1, export: 1 },
        position: records[2].position(),
        schema_revision: SchemaRevision::from_bytes([47; 32]),
        content_digest: Digest::from_bytes(Sha384::digest(bytes).into()),
        content_bytes: bytes.len() as u64,
    };
    let install_id = SnapshotId::from_bytes([71; 16]);
    receiver.begin_snapshot_install(SnapshotInstallRequest {
        install_id,
        subject: FederationSubject::Node(RECEIVER),
        manifest: manifest.clone(),
        publication_digest: Digest::from_bytes([85; 48]),
        expected_generation: 0,
    })?;
    let archive = SnapshotArchiveCompletion {
        install_id,
        snapshot_id: manifest.id,
        content_digest: manifest.content_digest,
        manifest_digest: manifest.binding_digest(),
        archive_digest: Digest::from_bytes(Sha384::digest(b"sealed archive receipt").into()),
    };
    let archived = receiver.commit_snapshot_archive(SUBSCRIPTION, archive)?;
    ensure!(receiver.commit_snapshot_archive(SUBSCRIPTION, archive)? == archived);
    ensure!(
        receiver
            .snapshot_install(SUBSCRIPTION)?
            .is_some_and(|view| {
                view.archived == Some(archived.clone())
                    && view.active.is_none()
                    && view.generation == 1
            })
    );
    ensure!(matches!(
        receiver.begin_snapshot_install(SnapshotInstallRequest {
            install_id: SnapshotId::from_bytes([74; 16]),
            subject: FederationSubject::Node(RECEIVER),
            manifest: SnapshotManifest {
                id: SnapshotId::from_bytes([75; 16]),
                position: records[3].position(),
                ..manifest
            },
            publication_digest: Digest::from_bytes([85; 48]),
            expected_generation: 1,
        }),
        Err(FederationError::Conflict)
    ));
    ensure!(
        receiver.receiver_cursor_in_generation(1, SUBSCRIPTION)? == Some(records[2].position())
    );
    ensure!(matches!(
        receiver.accept_in_generation(1, accept_request(&records[4])),
        Err(FederationError::Gap {
            expected: 4,
            received: 5
        })
    ));
    receiver.accept_in_generation(1, accept_request(&records[3]))?;
    ensure!(receiver.read_inbox_in_generation(1, inbox(None))?.records == vec![records[3].clone()]);
    ensure!(matches!(
        receiver.record_projection_progress_in_generation(
            1,
            ProjectionProgress {
                subscription: SUBSCRIPTION,
                position: records[3].position(),
            }
        ),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.retire_projected_inbox_in_generation(1, SUBSCRIPTION, 1),
        Err(FederationError::Conflict)
    ));
    let fake_release = SnapshotReaderRelease {
        subscription: SUBSCRIPTION,
        install_id,
        federation_generation: 1,
        application_generation: 1,
        completion_digest: Digest::from_bytes([72; 48]),
        released_through_generation: 0,
        release_digest: Digest::from_bytes([73; 48]),
    };
    ensure!(matches!(
        receiver.retire_snapshotted_inbox(fake_release, 1),
        Err(FederationError::Conflict)
    ));
    drop(receiver);
    drop(receiver_db);

    let receiver_db = RedbStore::open(&receiver_path)?;
    let receiver = receiver_db.federation_store(RECEIVER)?;
    ensure!(
        receiver
            .snapshot_install(SUBSCRIPTION)?
            .is_some_and(|view| {
                view.archived == Some(archived.clone()) && view.active.is_none()
            })
    );
    receiver.accept_in_generation(1, accept_request(&records[4]))?;
    ensure!(receiver.read_inbox_in_generation(1, inbox(None))?.records == records[3..].to_vec());
    seal_application(&application_path, install_id, &manifest, bytes)?;
    let projection = reopened_application_completion(&application_path, install_id, &manifest)?;
    let active = receiver.bind_archived_snapshot_projection(SUBSCRIPTION, projection)?;
    ensure!(active.federation_generation == archived.federation_generation);
    ensure!(receiver.bind_archived_snapshot_projection(SUBSCRIPTION, projection)? == active);
    ensure!(
        receiver
            .snapshot_install(SUBSCRIPTION)?
            .is_some_and(|view| { view.archived == Some(archived) && view.active == Some(active) })
    );
    Ok(())
}

#[test]
fn snapshot_cleanup_requires_a_current_reader_release_and_deletes_in_bounded_batches() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let receiver_path = directory.path().join("receiver.redb");
    let application_path = directory.path().join("application.redb");
    let (_publisher_db, receiver_db, publisher, receiver) = setup(
        &directory.path().join("publisher.redb"),
        &receiver_path,
        HistoryStart::All,
    )?;
    let records = (1..=5)
        .map(|id| publish(&publisher, id))
        .collect::<Result<Vec<_>>>()?;
    for record in &records[..4] {
        accept(&receiver, record)?;
    }
    let opened = publisher.inspect_subscription(xolotl_federation::InspectSubscriptionRequest {
        authenticated_subscriber: RECEIVER,
        subscription: SUBSCRIPTION,
    })?;
    let snapshot_bytes = b"remote state through record four";
    let manifest = SnapshotManifest {
        id: SnapshotId::from_bytes([58; 16]),
        subscription: SUBSCRIPTION,
        stream: STREAM,
        subscription_revision: opened.subscription_revision,
        publisher_authority: AuthorityRevision { peer: 1, export: 1 },
        position: records[3].position(),
        schema_revision: SchemaRevision::from_bytes([47; 32]),
        content_digest: Digest::from_bytes(Sha384::digest(snapshot_bytes).into()),
        content_bytes: snapshot_bytes.len() as u64,
    };
    let install_id = SnapshotId::from_bytes([59; 16]);
    receiver.begin_snapshot_install(SnapshotInstallRequest {
        install_id,
        subject: FederationSubject::Node(RECEIVER),
        manifest: manifest.clone(),
        publication_digest: Digest::from_bytes([85; 48]),
        expected_generation: 0,
    })?;
    seal_application(&application_path, install_id, &manifest, snapshot_bytes)?;
    let completion = reopened_application_completion(&application_path, install_id, &manifest)?;
    let anchor = receiver.commit_snapshot_anchor(SUBSCRIPTION, completion)?;
    receiver.accept_in_generation(anchor.federation_generation, accept_request(&records[4]))?;

    // A completion alone never grants physical deletion. A release must name
    // the exact active anchor and certify that all prior readers have exited.
    seal_reader_release(&application_path, &anchor)?;
    let release = reopened_reader_release(&application_path, &anchor)?;
    ensure!(matches!(
        receiver.retire_snapshotted_inbox(
            SnapshotReaderRelease {
                released_through_generation: anchor.federation_generation,
                ..release
            },
            1
        ),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.retire_snapshotted_inbox(
            SnapshotReaderRelease {
                completion_digest: Digest::from_bytes([60; 48]),
                ..release
            },
            1
        ),
        Err(FederationError::Conflict)
    ));
    ensure!(matches!(
        receiver.retire_snapshotted_inbox(release, 0),
        Err(FederationError::Capacity)
    ));
    for index in 0..4 {
        let retired = receiver.retire_snapshotted_inbox(release, 1)?;
        ensure!(retired.removed == 1);
        ensure!(retired.drained == (index == 3));
        ensure!(retired.covered_through == records[3].position());
    }
    ensure!(receiver.retire_snapshotted_inbox(release, 1)?.removed == 0);
    ensure!(receiver.read_inbox_in_generation(1, inbox(None))?.records == vec![records[4].clone()]);
    drop(receiver);
    drop(receiver_db);
    let db = Database::open(&receiver_path)?;
    let txn = db.begin_read()?;
    ensure!(txn.open_table(INBOX_ROWS)?.len()? == 1);
    Ok(())
}
