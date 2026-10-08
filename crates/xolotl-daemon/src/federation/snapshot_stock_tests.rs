use super::*;
use anyhow::Context as _;
use sha2::{Digest as _, Sha384};
use std::time::Duration;
use xolotl_federation::{
    FederationReplicaRetentionStore as _, FederationSnapshotPublisherStore as _,
    FederationSnapshotStore as _, InboxReadRequest, InspectSubscriptionRequest, ProjectionProgress,
    PublishRequest, SnapshotArchiveAnchor, SnapshotId, SnapshotReaderRelease,
};

use crate::config::{
    FederationPeerDialConfig, FederationPeerSubscriptionConfig, FederationSnapshotOfferConfig,
    FederationSnapshotReaderReleaseConfig,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn published(
    service: &FederationService,
    stream: StreamRef,
    id: u8,
) -> Result<xolotl_federation::Record> {
    Ok(service.append_published(PublishRequest {
        retry_epoch: service.store().publication_epoch(stream)?,
        stream,
        publish_id: RequestId::from_bytes([id; 16]),
        event_type: EventType::new("stock-snapshot-test")?,
        schema_revision: SchemaRevision::from_bytes([10; 32]),
        event_ref: None,
        payload: Arc::from([id].as_slice()),
    })?)
}

async fn wait_for_archive(
    store: &RedbFederationStore,
    subscription: SubscriptionRef,
) -> Result<SnapshotArchiveAnchor> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(view) = store.snapshot_install(subscription)?
                && view.active.is_none()
                && let Some(anchor) = view.archived
            {
                return Ok::<_, anyhow::Error>(anchor);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("stock receiver did not archive offered snapshot")?
}

#[cfg(unix)]
#[tokio::test]
async fn stock_private_follower_resyncs_from_pinned_snapshot_and_accepts_later_records()
-> Result<()> {
    let directory = tempfile::tempdir()?;
    let a_dir = directory.path().join("publisher");
    let b_dir = directory.path().join("receiver");
    std::fs::create_dir(&a_dir)?;
    std::fs::create_dir(&b_dir)?;
    let mut a = tests::configured_publisher(&a_dir)?;
    let mut b = tests::configured_publisher(&b_dir)?;
    let a_node = prepare(&a)?.context("publisher disabled")?.node_id();
    let b_node = prepare(&b)?.context("receiver disabled")?.node_id();
    a.federation.peers[0].node_id = hex(b_node.as_bytes());
    a.federation.peers[0].allowed_authorization_digests = vec![tests::online_digest_hex(&b)?];
    b.federation.peers[0].node_id = hex(a_node.as_bytes());
    b.federation.peers[0].allowed_authorization_digests = vec![tests::online_digest_hex(&a)?];
    b.federation.peers[0].exports[0].receive = true;
    b.federation.peers[0]
        .subscriptions
        .push(FederationPeerSubscriptionConfig {
            stream_id: "44".repeat(16),
            generation: 0,
            snapshot_schema_revisions: vec!["77".repeat(32)],
        });
    b.server.federation_grpc_addr = None;

    let publisher_db = xolotl_storage_redb::RedbStore::open_with_history(
        a_dir.join("publisher.redb"),
        xolotl_storage_redb::RedbHistory::Full,
    )?;
    let publisher_store = publisher_db.federation_store(a_node)?;
    let publisher_projection = publisher_db.federation_state_projection(a_node)?;
    let publisher_service = FederationService::new(
        Arc::new(publisher_store.clone()),
        FederationLimits::default(),
    )?;
    let first_runtime = start(
        prepare(&a)?.context("publisher disabled")?,
        publisher_store.clone(),
        Some(publisher_projection.clone()),
        tests::test_boot(publisher_db.state_backend().into_backend()),
    )
    .await?;
    let stream = StreamRef {
        publisher: a_node,
        id: StreamId::from_bytes([0x44; 16]),
    };
    let first_address = first_runtime.address.context("publisher did not listen")?;
    b.federation.peers[0].dial = Some(FederationPeerDialConfig {
        uri: format!("http://{first_address}"),
        server_name: "localhost".into(),
        trust_root_path: tests::private_file(&b_dir.join("peer-ca.pem"), tests::CA_CERT)?,
    });
    let receiver_db = xolotl_storage_redb::RedbStore::open_with_history(
        b_dir.join("receiver.redb"),
        xolotl_storage_redb::RedbHistory::Full,
    )?;
    let receiver_store = receiver_db.federation_store(b_node)?;
    let receiver_projection = receiver_db.federation_state_projection(b_node)?;
    let receiver_blocking = Arc::new(xolotl_kernel::host::TokioBlockingSpawner::default());
    let first_receiver = start(
        prepare(&b)?.context("receiver disabled")?,
        receiver_store.clone(),
        Some(receiver_projection.clone()),
        tests::test_boot_with_blocking(
            receiver_db.state_backend().into_backend(),
            receiver_blocking.clone(),
        ),
    )
    .await?;
    let subscription = remote_subscription(b_node, stream, 0).subscription;
    let first = published(&publisher_service, stream, 1)?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if publisher_service
                .inspect_subscription(InspectSubscriptionRequest {
                    authenticated_subscriber: b_node,
                    subscription,
                })
                .ok()
                .and_then(|inspection| inspection.acknowledged)
                == Some(first.position())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("first stock record was not acknowledged")?;
    first_receiver.task.abort();
    drop(first_receiver.task.await);
    first_receiver.runtime.shutdown().await;
    receiver_blocking.wait_idle().await;

    let second = published(&publisher_service, stream, 2)?;
    let third = published(&publisher_service, stream, 3)?;
    publisher_store.retire_published_history(stream, second.position(), 2)?;
    first_runtime.task.abort();
    drop(first_runtime.task.await);
    first_runtime.runtime.shutdown().await;

    // The application independently seals bytes and provides a stable proof
    // binding them to the exact committed stream position.
    let bytes = b"application projection through the third stock record";
    let content_path = tests::private_file(&a_dir.join("snapshot.bin"), bytes)?;
    a.federation
        .snapshot_offers
        .push(FederationSnapshotOfferConfig::Publish {
            subscriber_node: hex(b_node.as_bytes()),
            stream_id: "44".repeat(16),
            subscription_generation: 0,
            snapshot_id: "66".repeat(16),
            position_sequence: third.position().sequence(),
            position_digest: hex(third.position().digest().as_bytes()),
            schema_revision: "77".repeat(32),
            content_path,
            content_digest: hex(&Sha384::digest(bytes)),
            content_bytes: bytes.len() as u64,
            publication_digest: hex(&Sha384::digest(b"application durable publication proof")),
        });
    let prepared_a = prepare(&a)?.context("snapshot publisher disabled")?;
    let closed = Arc::new(xolotl_kernel::host::TokioBlockingSpawner::new(1)?);
    closed.close();
    let denied_workers = storage_workers::StorageWorkers::new(1, closed)?;
    let pins =
        std::path::PathBuf::from(format!("{}.federation-published-snapshots", a.storage.path));
    ensure!(!pins.exists());
    let rejected = snapshot_publisher::prepare(
        &denied_workers,
        &a.storage.path,
        Arc::new(publisher_store.clone()),
        &prepared_a.snapshot_offers,
    )
    .await
    .err()
    .context("closed snapshot publisher host accepted preparation")?;
    ensure!(!pins.exists());
    ensure!(
        publisher_store
            .local_snapshot_offer(subscription)?
            .is_none()
    );
    ensure!(
        rejected.downcast_ref::<xolotl_kernel::host::BlockingSpawnError>()
            == Some(&xolotl_kernel::host::BlockingSpawnError::Unavailable)
    );
    ensure!(rejected.to_string() == "prepare stock snapshot pins");
    let restarted_a = start(
        prepared_a,
        publisher_store.clone(),
        Some(publisher_projection),
        tests::test_boot(publisher_db.state_backend().into_backend()),
    )
    .await?;
    let address = restarted_a.address.context("publisher did not listen")?;
    b.federation.peers[0]
        .dial
        .as_mut()
        .context("receiver dial missing")?
        .uri = format!("http://{address}");
    let runtime_b = start(
        prepare(&b)?.context("receiver disabled")?,
        receiver_store.clone(),
        Some(receiver_projection),
        tests::test_boot_with_blocking(
            receiver_db.state_backend().into_backend(),
            receiver_blocking.clone(),
        ),
    )
    .await?;
    let anchor = wait_for_archive(&receiver_store, subscription).await?;
    ensure!(
        anchor.manifest.id == SnapshotId::from_bytes([0x66; 16])
            && anchor.manifest.position == third.position()
            && anchor.federation_generation == 1
    );
    let archive = snapshot_receiver::StockSnapshotArchive::open(
        &b.storage.path,
        storage_workers::StorageWorkers::new(
            1,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::new(1)?),
        )?,
    )?;
    ensure!(
        archive
            .completion(anchor.install_id, &anchor.manifest, 1)
            .await?
            .is_some()
    );

    let fourth = published(&publisher_service, stream, 4)?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = receiver_store.read_inbox_in_generation(
                1,
                InboxReadRequest {
                    subscription,
                    expected_stream: stream,
                    after: Some(third.position()),
                    max_records: 1,
                    max_bytes: STOCK_RECORD_BYTES,
                },
            )?;
            if page.records.first() == Some(&fourth) {
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("post-snapshot record was not accepted")??;
    let joined = publisher_store.join_replica(
        xolotl_federation::ReplicaMemberSpec {
            stream,
            member: b_node,
            subscription,
            term: xolotl_federation::ReplicaRetentionTerm::Permanent,
        },
        None,
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis(),
        )?,
    )?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let member = publisher_store
                .replica_member(stream, b_node)?
                .context("replica missing")?;
            if member.snapshot_covered == Some(fourth.position()) {
                ensure!(member.acknowledged == Some(first.position()));
                return Ok::<_, anyhow::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .context("archived suffix did not advance native replica coverage")??;
    ensure!(joined.revision == 1);
    runtime_b.task.abort();
    drop(runtime_b.task.await);
    runtime_b.runtime.shutdown().await;
    receiver_blocking.wait_idle().await;
    ensure!(
        publisher_service
            .inspect_subscription(InspectSubscriptionRequest {
                authenticated_subscriber: b_node,
                subscription,
            })?
            .acknowledged
            == Some(first.position()),
        "archived baseline and later records must not become ordinary ACKs"
    );
    ensure!(
        receiver_store
            .record_projection_progress_in_generation(
                1,
                ProjectionProgress {
                    subscription,
                    position: fourth.position(),
                },
            )
            .is_err()
    );
    ensure!(
        receiver_store
            .retire_projected_inbox_in_generation(1, subscription, 1)
            .is_err()
    );

    // An operator-supplied release cannot turn a byte archive into an
    // application completion or remove the old inbox generation.
    let release = SnapshotReaderRelease {
        subscription,
        install_id: anchor.install_id,
        federation_generation: anchor.federation_generation,
        application_generation: anchor.federation_generation,
        completion_digest: xolotl_federation::Digest::from_bytes([0x90; 48]),
        released_through_generation: 0,
        release_digest: xolotl_federation::Digest::from_bytes([0x91; 48]),
    };
    let old_part = archive.path(subscription, 0, SnapshotId::from_bytes([0xb1; 16]), "part");
    std::fs::write(&old_part, b"interrupted older generation")?;
    ensure!(
        archive
            .retire_released(receiver_store.clone(), release)
            .await
            .is_err()
            && old_part.exists()
    );
    b.federation
        .snapshot_reader_releases
        .push(FederationSnapshotReaderReleaseConfig {
            publisher_node: hex(a_node.as_bytes()),
            stream_id: "44".repeat(16),
            subscription_generation: 0,
            install_id: hex(anchor.install_id.as_bytes()),
            federation_generation: anchor.federation_generation,
            application_generation: release.application_generation,
            completion_digest: hex(release.completion_digest.as_bytes()),
            release_digest: hex(release.release_digest.as_bytes()),
        });

    let restarted_b = start(
        prepare(&b)?.context("receiver restart disabled")?,
        receiver_store.clone(),
        Some(receiver_db.federation_state_projection(b_node)?),
        tests::test_boot_with_blocking(
            receiver_db.state_backend().into_backend(),
            receiver_blocking.clone(),
        ),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    ensure!(
        old_part.exists(),
        "stock release must reject archive-only state"
    );
    ensure!(
        publisher_service
            .inspect_subscription(InspectSubscriptionRequest {
                authenticated_subscriber: b_node,
                subscription,
            })?
            .acknowledged
            == Some(first.position()),
        "restart must not replay the archived baseline as an inbox ACK"
    );
    restarted_b.task.abort();
    drop(restarted_b.task.await);
    restarted_b.runtime.shutdown().await;
    receiver_blocking.close();
    receiver_blocking.wait_idle().await;
    receiver_db.wait_idle().await;
    restarted_a.task.abort();
    drop(restarted_a.task.await);
    restarted_a.runtime.shutdown().await;
    drop(receiver_store);
    drop(receiver_db);
    let reopened_db = xolotl_storage_redb::RedbStore::open_with_history(
        b_dir.join("receiver.redb"),
        xolotl_storage_redb::RedbHistory::Full,
    )?;
    let reopened_store = reopened_db.federation_store(b_node)?;
    let reopened_archive = snapshot_receiver::StockSnapshotArchive::open(
        &b.storage.path,
        storage_workers::StorageWorkers::new(
            1,
            Arc::new(xolotl_kernel::host::TokioBlockingSpawner::new(1)?),
        )?,
    )?;
    ensure!(
        reopened_store
            .snapshot_install(subscription)?
            .is_some_and(|view| view.active.is_none() && view.archived == Some(anchor.clone()))
    );
    ensure!(
        reopened_archive
            .completion(anchor.install_id, &anchor.manifest, 1)
            .await?
            .is_some_and(|proof| proof.archive_digest == anchor.archive_digest)
    );
    ensure!(
        reopened_archive
            .retire_released(reopened_store.clone(), release)
            .await
            .is_err()
            && old_part.exists()
    );
    ensure!(
        reopened_store
            .read_inbox_in_generation(
                1,
                InboxReadRequest {
                    subscription,
                    expected_stream: stream,
                    after: Some(third.position()),
                    max_records: 1,
                    max_bytes: STOCK_RECORD_BYTES,
                },
            )?
            .records
            == vec![fourth]
    );
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn local_snapshot_retirement_needs_no_transport_and_preserves_exact_offer_cas() -> Result<()>
{
    let directory = tempfile::tempdir()?;
    let mut config = tests::configured_publisher(directory.path())?;
    let local = prepare(&config)?.context("publisher disabled")?.node_id();
    let subscriber = FederationNodeId::from_bytes([0x22; 48]);
    config.federation.peers[0].node_id = hex(subscriber.as_bytes());
    let db = xolotl_storage_redb::RedbStore::open_with_history(
        directory.path().join("local-retirement.redb"),
        xolotl_storage_redb::RedbHistory::Full,
    )?;
    let store = db.federation_store(local)?;
    let projection = db.federation_state_projection(local)?;
    let boot = tests::test_boot(db.state_backend().into_backend());
    let initialized = start(
        prepare(&config)?.context("publisher disabled")?,
        store.clone(),
        Some(projection.clone()),
        boot.clone(),
    )
    .await?;
    initialized.task.abort();
    drop(initialized.task.await);
    initialized.runtime.shutdown().await;
    let service = FederationService::new(Arc::new(store.clone()), FederationLimits::default())?;
    let stream = StreamRef {
        publisher: local,
        id: StreamId::from_bytes([0x44; 16]),
    };
    let subscription = remote_subscription(subscriber, stream, 0).subscription;
    service.open(xolotl_federation::OpenRequest {
        authenticated_subscriber: subscriber,
        request_id: RequestId::from_bytes([0x21; 16]),
        subscription,
        stream,
        expected_control_revision: None,
        history: xolotl_federation::HistoryStart::All,
    })?;
    let record = published(&service, stream, 0x32)?;
    let bytes = b"sealed local snapshot";
    let proof = xolotl_federation::SnapshotPublicationProof {
        snapshot_id: SnapshotId::from_bytes([0x66; 16]),
        stream,
        position: record.position(),
        schema_revision: SchemaRevision::from_bytes([0x77; 32]),
        content_digest: xolotl_federation::Digest::from_bytes(Sha384::digest(bytes).into()),
        content_bytes: bytes.len() as u64,
        publication_digest: xolotl_federation::Digest::from_bytes([0x88; 48]),
    };
    let first = store.publish_snapshot_offer(xolotl_federation::SnapshotOfferRequest {
        authenticated_subscriber: subscriber,
        subscription,
        proof,
    })?;
    store.retire_snapshot_offer(&first)?;
    let replacement = store.publish_snapshot_offer(xolotl_federation::SnapshotOfferRequest {
        authenticated_subscriber: subscriber,
        subscription,
        proof: xolotl_federation::SnapshotPublicationProof {
            snapshot_id: SnapshotId::from_bytes([0x67; 16]),
            ..proof
        },
    })?;
    ensure!(matches!(
        store.retire_snapshot_offer(&first),
        Err(FederationError::Conflict)
    ));
    ensure!(store.local_snapshot_offer(subscription)? == Some(replacement));
    config.server.federation_grpc_addr = None;
    config.federation.snapshot_offers = vec![FederationSnapshotOfferConfig::Publish {
        subscriber_node: hex(subscriber.as_bytes()),
        stream_id: "44".repeat(16),
        subscription_generation: 0,
        snapshot_id: hex(proof.snapshot_id.as_bytes()),
        position_sequence: proof.position.sequence(),
        position_digest: hex(proof.position.digest().as_bytes()),
        schema_revision: hex(proof.schema_revision.as_bytes()),
        content_path: tests::private_file(&directory.path().join("snapshot.bin"), bytes)?,
        content_digest: hex(proof.content_digest.as_bytes()),
        content_bytes: proof.content_bytes,
        publication_digest: hex(proof.publication_digest.as_bytes()),
    }];
    let rejected = prepare(&config)
        .err()
        .context("snapshot Publish had no serving transport")?;
    ensure!(
        rejected.to_string() == "stock snapshot offers require a listener or reverse Session dial"
    );
    config.federation.peers.clear();
    config.federation.snapshot_offers = vec![FederationSnapshotOfferConfig::Retire {
        subscriber_node: hex(subscriber.as_bytes()),
        stream_id: "44".repeat(16),
        subscription_generation: 0,
    }];
    let prepared = prepare(&config)?.context("local retirement silently disabled")?;
    ensure!(prepared.address.is_none() && prepared.policy.dials.is_empty());
    let retiring = start(prepared, store.clone(), Some(projection), boot).await?;
    ensure!(retiring.address.is_none());
    ensure!(store.local_snapshot_offer(subscription)?.is_none());
    ensure!(
        snapshot_publisher::reconcile(
            &store,
            &prepare(&config)?
                .context("retirement disabled")?
                .snapshot_offers
        )? == 0
    );
    retiring.task.abort();
    drop(retiring.task.await);
    retiring.runtime.shutdown().await;
    Ok(())
}
