//! Explicit application-sealed bytes exposed through stock private snapshots.
//! The daemon validates the file digest and the exact publisher log position;
//! the application or operator remains responsible for the semantic proof.
//! Retire-only plans are local maintenance and need no listener or dial. Each
//! retirement reads the current offer and retires that exact value by CAS;
//! concurrent replacement is a conflict, not permission to retire a newer offer.

use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    Digest, FederationError, FederationNodeId, FederationSnapshotPublisherStore,
    MAX_SNAPSHOT_BYTES, Position, SchemaRevision, SnapshotContentSource, SnapshotId, SnapshotOffer,
    SnapshotOfferRequest, SnapshotPublicationProof, StreamId, StreamRef, StreamSpec,
    SubscriptionRef,
};
use xolotl_storage_redb::RedbFederationStore;

use crate::config::{FederationPeerConfig, FederationSnapshotOfferConfig};

use super::{decode_hex, remote_subscription, storage_workers::StorageWorkers};

const COPY_BYTES: usize = 1024 * 1024;
const MAX_OFFERS: usize = 64;
const MAX_PINNED_FILES: usize = 64;

#[derive(Clone)]
pub(super) struct PreparedSnapshotOffer {
    pub(super) subscription: SubscriptionRef,
    pub(super) action: SnapshotOfferAction,
}

#[derive(Clone)]
pub(super) enum SnapshotOfferAction {
    Publish(Box<PreparedPublication>),
    Retire,
}

#[derive(Clone)]
pub(super) struct PreparedPublication {
    proof: SnapshotPublicationProof,
    content_path: PathBuf,
}

pub(super) fn parse(
    config: &[FederationSnapshotOfferConfig],
    local: FederationNodeId,
    streams: &[StreamSpec],
    peers: &[FederationPeerConfig],
) -> Result<Vec<PreparedSnapshotOffer>> {
    ensure!(config.len() <= MAX_OFFERS, "too many stock snapshot offers");
    let mut seen = HashSet::new();
    let mut plans = Vec::with_capacity(config.len());
    for item in config {
        let (subscriber_node, stream_id, generation) = match item {
            FederationSnapshotOfferConfig::Publish {
                subscriber_node,
                stream_id,
                subscription_generation,
                ..
            }
            | FederationSnapshotOfferConfig::Retire {
                subscriber_node,
                stream_id,
                subscription_generation,
            } => (subscriber_node, stream_id, *subscription_generation),
        };
        let subscriber = FederationNodeId::from_bytes(decode_hex::<48>(
            subscriber_node,
            "snapshot subscriber_node",
        )?);
        ensure!(
            subscriber != local,
            "snapshot subscriber cannot be the local node"
        );
        let stream = StreamRef {
            publisher: local,
            id: StreamId::from_bytes(decode_hex::<16>(stream_id, "snapshot stream_id")?),
        };
        let declared = streams
            .iter()
            .find(|declared| declared.stream == stream)
            .context("snapshot offer references an undeclared local stream")?;
        let subscription = remote_subscription(subscriber, stream, generation).subscription;
        ensure!(
            seen.insert(subscription),
            "duplicate stock snapshot subscription"
        );
        let action = match item {
            FederationSnapshotOfferConfig::Retire { .. } => SnapshotOfferAction::Retire,
            FederationSnapshotOfferConfig::Publish {
                snapshot_id,
                position_sequence,
                position_digest,
                schema_revision,
                content_path,
                content_digest,
                content_bytes,
                publication_digest,
                ..
            } => {
                ensure!(
                    peers.iter().any(|peer| peer.enabled
                        && peer.node_id.eq_ignore_ascii_case(subscriber_node)
                        && peer
                            .exports
                            .iter()
                            .any(|export| export.serve && export.name == declared.export.as_str())),
                    "snapshot offer needs an enabled serving peer"
                );
                let content_path = PathBuf::from(content_path);
                ensure!(
                    content_path.is_absolute(),
                    "snapshot content path must be absolute"
                );
                let metadata = fs::symlink_metadata(&content_path)?;
                ensure!(
                    metadata.is_file(),
                    "snapshot content must be a regular file"
                );
                ensure!(
                    metadata.len() == *content_bytes && *content_bytes <= MAX_SNAPSHOT_BYTES,
                    "snapshot content size disagrees with the declared bounded proof"
                );
                let proof = SnapshotPublicationProof {
                    snapshot_id: SnapshotId::from_bytes(decode_hex::<16>(
                        snapshot_id,
                        "snapshot_id",
                    )?),
                    stream,
                    position: Position::new(
                        *position_sequence,
                        Digest::from_bytes(decode_hex::<48>(
                            position_digest,
                            "snapshot position_digest",
                        )?),
                    )?,
                    schema_revision: SchemaRevision::from_bytes(decode_hex::<32>(
                        schema_revision,
                        "snapshot schema_revision",
                    )?),
                    content_digest: Digest::from_bytes(decode_hex::<48>(
                        content_digest,
                        "snapshot content_digest",
                    )?),
                    content_bytes: *content_bytes,
                    publication_digest: Digest::from_bytes(decode_hex::<48>(
                        publication_digest,
                        "snapshot publication_digest",
                    )?),
                };
                proof.validate()?;
                SnapshotOfferAction::Publish(Box::new(PreparedPublication {
                    proof,
                    content_path,
                }))
            }
        };
        plans.push(PreparedSnapshotOffer {
            subscription,
            action,
        });
    }
    Ok(plans)
}

pub(super) struct StockSnapshotPublisher {
    directory: PathBuf,
}

pub(super) async fn prepare(
    workers: &StorageWorkers,
    storage_path: &str,
    store: Arc<RedbFederationStore>,
    plans: &[PreparedSnapshotOffer],
) -> Result<Arc<StockSnapshotPublisher>> {
    let storage_path = storage_path.to_owned();
    let plans_for_pin = plans.to_vec();
    let source = workers
        .run(move || -> Result<_> {
            let source = StockSnapshotPublisher::open(&storage_path)?;
            source.pin_all(&plans_for_pin)?;
            Ok(Arc::new(source))
        })
        .await
        .context("prepare stock snapshot pins")?;
    let plans_for_offer = plans.to_vec();
    let waiting = workers
        .run(move || reconcile(&store, &plans_for_offer))
        .await
        .context("reconcile stock snapshot offers at startup")?;
    if waiting != 0 {
        tracing::info!(
            waiting,
            "stock snapshots await publisher Open subscriptions"
        );
    }
    Ok(source)
}

impl StockSnapshotPublisher {
    pub(super) fn open(storage_path: &str) -> Result<Self> {
        let mut name = OsString::from(storage_path);
        name.push(".federation-published-snapshots");
        let directory = PathBuf::from(name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder.create(&directory)?;
            let metadata = fs::symlink_metadata(&directory)?;
            ensure!(
                metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
                "published snapshot pin directory must be private"
            );
        }
        #[cfg(not(unix))]
        fs::create_dir_all(&directory)?;
        Ok(Self { directory })
    }

    pub(super) fn pin_all(&self, plans: &[PreparedSnapshotOffer]) -> Result<()> {
        for plan in plans {
            if let SnapshotOfferAction::Publish(publication) = &plan.action {
                self.pin(publication.proof, &publication.content_path)?;
            }
        }
        Ok(())
    }

    fn pin(&self, proof: SnapshotPublicationProof, source: &Path) -> Result<()> {
        let destination = self.path(proof.snapshot_id, proof.content_digest);
        if destination.exists() {
            ensure!(
                digest_file(&destination, proof.content_bytes)? == proof.content_digest,
                "pinned published snapshot was changed or corrupted"
            );
            return Ok(());
        }
        let existing = fs::read_dir(&self.directory)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sealed"))
            .count();
        ensure!(
            existing < MAX_PINNED_FILES,
            "published snapshot pin archive is full"
        );
        let partial = destination.with_extension("part");
        let mut input = File::open(source)?;
        ensure!(
            input.metadata()?.len() == proof.content_bytes,
            "application snapshot content changed before pinning"
        );
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut output = options.open(&partial)?;
        let mut hasher = Sha384::new();
        let mut total = 0_u64;
        let mut buffer = [0; COPY_BYTES];
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .context("snapshot content size overflow")?;
            ensure!(
                total <= proof.content_bytes,
                "application snapshot grew while pinning"
            );
            hasher.update(&buffer[..count]);
            output.write_all(&buffer[..count])?;
        }
        ensure!(
            total == proof.content_bytes
                && Digest::from_bytes(hasher.finalize().into()) == proof.content_digest,
            "application snapshot content differs from durable publication proof"
        );
        output.sync_all()?;
        drop(output);
        fs::rename(&partial, &destination)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    fn path(&self, id: SnapshotId, digest: Digest) -> PathBuf {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut name = String::with_capacity(16 * 2 + 1 + 48 * 2 + 7);
        for byte in id.as_bytes() {
            name.push(HEX[(byte >> 4) as usize] as char);
            name.push(HEX[(byte & 15) as usize] as char);
        }
        name.push('-');
        for byte in digest.as_bytes() {
            name.push(HEX[(byte >> 4) as usize] as char);
            name.push(HEX[(byte & 15) as usize] as char);
        }
        name.push_str(".sealed");
        self.directory.join(name)
    }
}

impl SnapshotContentSource for StockSnapshotPublisher {
    fn read_snapshot_chunk(
        &self,
        offer: &SnapshotOffer,
        offset: u64,
        bytes: usize,
    ) -> Result<Arc<[u8]>, FederationError> {
        let manifest = &offer.manifest;
        if offset
            .checked_add(bytes as u64)
            .is_none_or(|end| end > manifest.content_bytes)
        {
            return Err(FederationError::Capacity);
        }
        let path = self.path(manifest.id, manifest.content_digest);
        let mut file = File::open(path).map_err(|_error| FederationError::NotFound)?;
        if file
            .metadata()
            .map_err(|error| FederationError::Storage(error.to_string()))?
            .len()
            != manifest.content_bytes
        {
            return Err(FederationError::Corrupt);
        }
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| FederationError::Storage(error.to_string()))?;
        let mut chunk = vec![0; bytes];
        file.read_exact(&mut chunk)
            .map_err(|_error| FederationError::Corrupt)?;
        Ok(chunk.into())
    }
}

fn digest_file(path: &Path, expected_len: u64) -> Result<Digest> {
    let mut file = File::open(path)?;
    ensure!(
        file.metadata()?.len() == expected_len,
        "pinned snapshot length changed"
    );
    let mut hash = Sha384::new();
    let mut buffer = [0; COPY_BYTES];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(Digest::from_bytes(hash.finalize().into()))
}

pub(super) fn reconcile(
    store: &RedbFederationStore,
    plans: &[PreparedSnapshotOffer],
) -> Result<usize> {
    let mut waiting = 0;
    for plan in plans {
        let current = store.local_snapshot_offer(plan.subscription)?;
        match &plan.action {
            SnapshotOfferAction::Retire => {
                if let Some(current) = current {
                    store.retire_snapshot_offer(&current)?;
                }
            }
            SnapshotOfferAction::Publish(publication) => {
                let proof = publication.proof;
                if let Some(current) = &current {
                    let matches_proof = current.manifest.id == proof.snapshot_id
                        && current.manifest.stream == proof.stream
                        && current.manifest.position == proof.position
                        && current.manifest.schema_revision == proof.schema_revision
                        && current.manifest.content_digest == proof.content_digest
                        && current.manifest.content_bytes == proof.content_bytes
                        && current.publication_digest == proof.publication_digest;
                    if matches_proof
                        && matches!(store.snapshot_offer(plan.subscription.subscriber, plan.subscription),
                            Ok(Some(offer)) if offer == *current)
                    {
                        continue;
                    }
                    store.retire_snapshot_offer(current)?;
                }
                match store.publish_snapshot_offer(SnapshotOfferRequest {
                    authenticated_subscriber: plan.subscription.subscriber,
                    subscription: plan.subscription,
                    proof,
                }) {
                    Ok(_) => {}
                    Err(FederationError::NotFound) => waiting += 1,
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    Ok(waiting)
}
