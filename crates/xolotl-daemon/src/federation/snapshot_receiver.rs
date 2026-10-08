//! Stock's opaque application snapshot archive. The federation inbox owns
//! delivery; this independent durable directory owns the bytes that justify
//! advancing its baseline. A consumer must interpret the advertised schema.

use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha384};
use xolotl_federation::{
    Digest, FederationNodeId, FederationSnapshotStore as _, MAX_RETIRE_RECORDS, MAX_SNAPSHOT_BYTES,
    SnapshotArchiveCompletion, SnapshotId, SnapshotInboxRetirement, SnapshotManifest,
    SnapshotReaderRelease, StreamId, StreamRef, SubscriptionRef,
};
use xolotl_federation_grpc::FederationGrpcSubscriberClient;
use xolotl_storage_redb::RedbFederationStore;

use crate::config::FederationSnapshotReaderReleaseConfig;

use super::{decode_hex, remote_subscription, storage_workers::StorageWorkers};

const CHUNK_BYTES: usize = 1024 * 1024;
const MAX_ARCHIVED_FILES: usize = 64;
const MAX_READER_RELEASES: usize = 64;
const FILES_PER_CLEANUP: usize = 4;

#[derive(Clone, Copy)]
pub(super) struct PreparedReaderRelease {
    pub(super) release: SnapshotReaderRelease,
}

pub(super) fn parse_releases(
    config: &[FederationSnapshotReaderReleaseConfig],
    local: FederationNodeId,
) -> Result<Vec<PreparedReaderRelease>> {
    ensure!(
        config.len() <= MAX_READER_RELEASES,
        "too many stock snapshot reader releases"
    );
    let mut seen = HashSet::new();
    let mut plans = Vec::with_capacity(config.len());
    for item in config {
        let publisher = FederationNodeId::from_bytes(decode_hex::<48>(
            &item.publisher_node,
            "snapshot release publisher_node",
        )?);
        ensure!(
            publisher != local,
            "snapshot release cannot target the local node"
        );
        let stream = StreamRef {
            publisher,
            id: StreamId::from_bytes(decode_hex::<16>(
                &item.stream_id,
                "snapshot release stream_id",
            )?),
        };
        let subscription =
            remote_subscription(local, stream, item.subscription_generation).subscription;
        ensure!(
            seen.insert(subscription),
            "duplicate snapshot reader release subscription"
        );
        ensure!(
            item.federation_generation > 0
                && item.application_generation == item.federation_generation,
            "stock snapshot release generations must match and be nonzero"
        );
        let install_id = SnapshotId::from_bytes(decode_hex::<16>(
            &item.install_id,
            "snapshot release install_id",
        )?);
        let completion_digest = Digest::from_bytes(decode_hex::<48>(
            &item.completion_digest,
            "snapshot release completion_digest",
        )?);
        let release_digest = Digest::from_bytes(decode_hex::<48>(
            &item.release_digest,
            "snapshot release release_digest",
        )?);
        ensure!(
            install_id.as_bytes() != &[0; 16]
                && completion_digest.as_bytes() != &[0; 48]
                && release_digest.as_bytes() != &[0; 48],
            "snapshot reader release identities and evidence must be nonzero"
        );
        plans.push(PreparedReaderRelease {
            release: SnapshotReaderRelease {
                subscription,
                install_id,
                federation_generation: item.federation_generation,
                application_generation: item.application_generation,
                completion_digest,
                released_through_generation: item.federation_generation - 1,
                release_digest,
            },
        });
    }
    Ok(plans)
}

pub(super) struct CleanupProgress {
    pub(super) inbox: SnapshotInboxRetirement,
    pub(super) removed_files: usize,
}

#[derive(Clone)]
pub(super) struct StockSnapshotArchive {
    directory: PathBuf,
    workers: StorageWorkers,
    reservation: Arc<Mutex<()>>,
}

impl StockSnapshotArchive {
    pub(super) fn open(storage_path: &str, workers: StorageWorkers) -> Result<Self> {
        let mut name = OsString::from(storage_path);
        name.push(".federation-snapshots");
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
                "federation snapshot archive must be a private directory"
            );
        }
        #[cfg(not(unix))]
        fs::create_dir_all(&directory)?;
        Ok(Self {
            directory,
            workers,
            reservation: Arc::new(Mutex::new(())),
        })
    }

    pub(super) async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.workers.run(work).await
    }

    pub(super) async fn completion(
        &self,
        install_id: SnapshotId,
        manifest: &SnapshotManifest,
        application_generation: u64,
    ) -> Result<Option<SnapshotArchiveCompletion>> {
        let path = self.path(
            manifest.subscription,
            application_generation,
            install_id,
            "sealed",
        );
        let manifest = manifest.clone();
        self.blocking(move || verify_sealed(&path, install_id, &manifest, application_generation))
            .await
    }

    pub(super) async fn download_and_seal(
        &self,
        client: &FederationGrpcSubscriberClient,
        manifest: &SnapshotManifest,
        install_id: SnapshotId,
        application_generation: u64,
        max_chunk_bytes: usize,
    ) -> Result<SnapshotArchiveCompletion> {
        manifest.validate()?;
        ensure!(max_chunk_bytes > 0);
        let part = self.path(
            manifest.subscription,
            application_generation,
            install_id,
            "part",
        );
        let sealed = self.path(
            manifest.subscription,
            application_generation,
            install_id,
            "sealed",
        );
        if let Some(completion) = self
            .completion(install_id, manifest, application_generation)
            .await?
        {
            return Ok(completion);
        }
        let offer = client.inspect_snapshot(manifest.subscription).await?;
        ensure!(
            offer.manifest == *manifest,
            "publisher changed the pending snapshot offer"
        );

        // A crash may leave a partial final write. Recheck the complete digest
        // before sealing; if it fails, restart once from byte zero.
        for attempt in 0..2 {
            let part_for_len = part.clone();
            let reservation = Arc::clone(&self.reservation);
            let length = manifest.content_bytes;
            let offset = self
                .blocking(move || stage_length(&part_for_len, length, attempt != 0, &reservation))
                .await?;
            let mut offset = offset;
            while offset < manifest.content_bytes {
                let requested = (manifest.content_bytes - offset)
                    .min(max_chunk_bytes.min(CHUNK_BYTES) as u64)
                    as usize;
                let chunk = client
                    .read_snapshot(offer.clone(), offset, requested)
                    .await?;
                ensure!(
                    chunk.offer == offer
                        && chunk.offset == offset
                        && chunk.bytes.len() == requested,
                    "snapshot chunk differs from the authorized offer"
                );
                let bytes = chunk.bytes;
                let part_for_write = part.clone();
                self.blocking(move || write_staged(&part_for_write, offset, &bytes))
                    .await?;
                offset += requested as u64;
                ensure!(
                    chunk.complete == (offset == manifest.content_bytes),
                    "snapshot completion flag disagrees with content length"
                );
            }
            let part_for_seal = part.clone();
            let sealed_for_seal = sealed.clone();
            let manifest_for_seal = manifest.clone();
            let completion = self
                .blocking(move || {
                    seal(
                        &part_for_seal,
                        &sealed_for_seal,
                        install_id,
                        &manifest_for_seal,
                        application_generation,
                    )
                })
                .await?;
            if let Some(completion) = completion {
                return Ok(completion);
            }
        }
        anyhow::bail!("snapshot content failed full digest verification twice")
    }

    pub(super) async fn retire_released(
        &self,
        store: RedbFederationStore,
        release: SnapshotReaderRelease,
    ) -> Result<CleanupProgress> {
        ensure!(
            release.application_generation == release.federation_generation,
            "stock snapshot release generations differ"
        );
        let inbox = self
            .blocking(move || Ok(store.retire_snapshotted_inbox(release, MAX_RETIRE_RECORDS)?))
            .await?;
        let removed_files = if inbox.drained {
            let directory = self.directory.clone();
            self.blocking(move || {
                remove_released_files(
                    &directory,
                    release.subscription,
                    release.released_through_generation,
                    FILES_PER_CLEANUP,
                )
            })
            .await?
        } else {
            0
        };
        Ok(CleanupProgress {
            inbox,
            removed_files,
        })
    }

    pub(super) fn path(
        &self,
        subscription: SubscriptionRef,
        application_generation: u64,
        install_id: SnapshotId,
        suffix: &str,
    ) -> PathBuf {
        let mut name = String::with_capacity(48 * 2 + 16 * 2 + 16 + 16 * 2 + suffix.len() + 4);
        append_hex(&mut name, subscription.subscriber.as_bytes());
        name.push('-');
        append_hex(&mut name, subscription.id.as_bytes());
        name.push('-');
        append_hex(&mut name, &application_generation.to_be_bytes());
        name.push('-');
        append_hex(&mut name, install_id.as_bytes());
        name.push('.');
        name.push_str(suffix);
        self.directory.join(name)
    }
}

fn remove_released_files(
    directory: &Path,
    subscription: SubscriptionRef,
    released_through_generation: u64,
    limit: usize,
) -> Result<usize> {
    ensure!(limit > 0 && limit <= FILES_PER_CLEANUP);
    let mut prefix = String::with_capacity(48 * 2 + 16 * 2 + 2);
    append_hex(&mut prefix, subscription.subscriber.as_bytes());
    prefix.push('-');
    append_hex(&mut prefix, subscription.id.as_bytes());
    prefix.push('-');
    let mut removed = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str().and_then(|name| name.strip_prefix(&prefix)) else {
            continue;
        };
        let Some((generation, remainder)) = name.split_once('-') else {
            continue;
        };
        if generation.len() != 16 || !generation.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(generation) = u64::from_str_radix(generation, 16) else {
            continue;
        };
        let Some((id, suffix)) = remainder.split_once('.') else {
            continue;
        };
        if generation > released_through_generation
            || id.len() != 32
            || !id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || !matches!(suffix, "sealed" | "part")
        {
            continue;
        }
        fs::remove_file(entry.path())?;
        removed += 1;
        if removed == limit {
            break;
        }
    }
    if removed != 0 {
        File::open(directory)?.sync_all()?;
    }
    Ok(removed)
}

pub(super) fn install_id(manifest: &SnapshotManifest) -> SnapshotId {
    let mut hash = blake3::Hasher::new_derive_key("xolotl.federation.stock-snapshot-install.v1");
    hash.update(manifest.binding_digest().as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&hash.finalize().as_bytes()[..16]);
    if bytes == [0; 16] {
        bytes[0] = 1;
    }
    SnapshotId::from_bytes(bytes)
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 15) as usize] as char);
    }
}

fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}

fn stage_length(
    path: &Path,
    content_bytes: u64,
    reset: bool,
    reservation: &Mutex<()>,
) -> Result<u64> {
    ensure!(content_bytes <= MAX_SNAPSHOT_BYTES);
    let _reservation = reservation
        .lock()
        .map_err(|_error| anyhow::anyhow!("snapshot archive reservation lock poisoned"))?;
    if !path.exists() {
        let directory = path.parent().context("snapshot stage has no directory")?;
        let mut count = 0;
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "part" || extension == "sealed")
            {
                count += 1;
            }
        }
        ensure!(count < MAX_ARCHIVED_FILES, "stock snapshot archive is full");
    }
    let file = private_file(path)?;
    if reset || file.metadata()?.len() > content_bytes {
        file.set_len(0)?;
        file.sync_all()?;
        return Ok(0);
    }
    Ok(file.metadata()?.len())
}

fn write_staged(path: &Path, offset: u64, bytes: &[u8]) -> Result<()> {
    let mut file = private_file(path)?;
    ensure!(
        file.metadata()?.len() == offset,
        "snapshot staging offset changed"
    );
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(bytes)?;
    file.sync_data()?;
    Ok(())
}

fn verified_digest(path: &Path, expected_bytes: u64) -> Result<Option<Digest>> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() != expected_bytes {
        return Ok(None);
    }
    let mut hash = Sha384::new();
    let mut buffer = [0; CHUNK_BYTES];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(Some(Digest::from_bytes(hash.finalize().into())))
}

fn completion(
    install_id: SnapshotId,
    manifest: &SnapshotManifest,
    application_generation: u64,
) -> Result<SnapshotArchiveCompletion> {
    ensure!(application_generation > 0);
    let manifest_digest = manifest.binding_digest();
    let mut hash = Sha384::new();
    hash.update(b"xolotl/stock-snapshot-archive/v1\0");
    hash.update(install_id.as_bytes());
    hash.update(manifest_digest.as_bytes());
    hash.update(manifest.content_digest.as_bytes());
    hash.update(application_generation.to_be_bytes());
    Ok(SnapshotArchiveCompletion {
        install_id,
        snapshot_id: manifest.id,
        content_digest: manifest.content_digest,
        manifest_digest,
        archive_digest: Digest::from_bytes(hash.finalize().into()),
    })
}

fn verify_sealed(
    path: &Path,
    install_id: SnapshotId,
    manifest: &SnapshotManifest,
    application_generation: u64,
) -> Result<Option<SnapshotArchiveCompletion>> {
    if !path.exists() {
        return Ok(None);
    }
    ensure!(
        verified_digest(path, manifest.content_bytes)? == Some(manifest.content_digest),
        "sealed stock snapshot content was changed or corrupted"
    );
    completion(install_id, manifest, application_generation).map(Some)
}

fn seal(
    part: &Path,
    sealed: &Path,
    install_id: SnapshotId,
    manifest: &SnapshotManifest,
    application_generation: u64,
) -> Result<Option<SnapshotArchiveCompletion>> {
    if verified_digest(part, manifest.content_bytes)? != Some(manifest.content_digest) {
        return Ok(None);
    }
    let file = File::open(part)?;
    file.sync_all()?;
    if sealed.exists() {
        return verify_sealed(sealed, install_id, manifest, application_generation);
    }
    let existing = fs::read_dir(part.parent().context("snapshot part has no directory")?)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sealed"))
        .count();
    ensure!(
        existing < MAX_ARCHIVED_FILES,
        "stock snapshot archive is full"
    );
    fs::rename(part, sealed)?;
    File::open(sealed.parent().context("snapshot seal has no directory")?)?.sync_all()?;
    completion(install_id, manifest, application_generation).map(Some)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use xolotl_federation::{
        AuthorityRevision, FederationNodeId, Position, SchemaRevision, StreamId, StreamRef,
        SubscriptionId,
    };
    use xolotl_kernel::host::{BlockingSpawnError, TokioBlockingSpawner};

    fn test_workers() -> Result<StorageWorkers> {
        StorageWorkers::new(1, Arc::new(TokioBlockingSpawner::new(1)?))
    }

    fn manifest(content: &[u8]) -> Result<SnapshotManifest> {
        Ok(SnapshotManifest {
            id: SnapshotId::from_bytes([6; 16]),
            subscription: SubscriptionRef {
                subscriber: FederationNodeId::from_bytes([2; 48]),
                id: SubscriptionId::from_bytes([3; 16]),
            },
            stream: StreamRef {
                publisher: FederationNodeId::from_bytes([1; 48]),
                id: StreamId::from_bytes([4; 16]),
            },
            subscription_revision: 1,
            publisher_authority: AuthorityRevision { peer: 1, export: 1 },
            position: Position::new(2, Digest::from_bytes([5; 48]))?,
            schema_revision: SchemaRevision::from_bytes([7; 32]),
            content_digest: Digest::from_bytes(Sha384::digest(content).into()),
            content_bytes: content.len() as u64,
        })
    }

    #[tokio::test]
    async fn sealed_bytes_prove_completion_after_reopen_and_corruption_fails_closed() -> Result<()>
    {
        let directory = tempfile::tempdir()?;
        let storage_path = directory.path().join("host.redb");
        let archive = StockSnapshotArchive::open(
            storage_path.to_str().context("UTF-8 path")?,
            test_workers()?,
        )?;
        let bytes = b"application-owned state through committed stream position";
        let manifest = manifest(bytes)?;
        let id = install_id(&manifest);
        let part = archive.path(manifest.subscription, 1, id, "part");
        let sealed = archive.path(manifest.subscription, 1, id, "sealed");
        ensure!(archive.completion(id, &manifest, 1).await?.is_none());
        write_staged(&part, 0, &bytes[..9])?;
        ensure!(stage_length(&part, bytes.len() as u64, false, &archive.reservation)? == 9);
        write_staged(&part, 9, &bytes[9..])?;
        let proof = seal(&part, &sealed, id, &manifest, 1)?.context("valid seal rejected")?;
        drop(archive);

        let blocking = Arc::new(TokioBlockingSpawner::new(1)?);
        let reopened = StockSnapshotArchive::open(
            storage_path.to_str().context("UTF-8 path")?,
            StorageWorkers::new(1, blocking.clone())?,
        )?;
        ensure!(reopened.completion(id, &manifest, 1).await? == Some(proof));
        fs::write(&sealed, b"corrupt")?;
        let corruption = reopened
            .completion(id, &manifest, 1)
            .await
            .err()
            .context("corrupt sealed snapshot was accepted")?;
        ensure!(corruption.to_string() == "sealed stock snapshot content was changed or corrupted");
        blocking.close();
        let failure = reopened
            .completion(id, &manifest, 1)
            .await
            .err()
            .context("closed archive host accepted verification")?;
        ensure!(
            failure.downcast_ref::<BlockingSpawnError>() == Some(&BlockingSpawnError::Unavailable)
        );
        Ok(())
    }

    #[test]
    fn partial_or_corrupt_content_cannot_seal() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage_path = directory.path().join("host.redb");
        let archive = StockSnapshotArchive::open(
            storage_path.to_str().context("UTF-8 path")?,
            test_workers()?,
        )?;
        let bytes = b"valid application snapshot";
        let manifest = manifest(bytes)?;
        let id = install_id(&manifest);
        let part = archive.path(manifest.subscription, 1, id, "part");
        let sealed = archive.path(manifest.subscription, 1, id, "sealed");
        write_staged(&part, 0, b"invalid application data!")?;
        ensure!(seal(&part, &sealed, id, &manifest, 1)?.is_none());
        ensure!(!sealed.exists());
        ensure!(stage_length(&part, manifest.content_bytes, true, &archive.reservation)? == 0);
        write_staged(&part, 0, bytes)?;
        ensure!(seal(&part, &sealed, id, &manifest, 1)?.is_some());
        Ok(())
    }

    #[test]
    fn cleanup_names_only_released_generations_and_is_bounded() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage_path = directory.path().join("host.redb");
        let archive = StockSnapshotArchive::open(
            storage_path.to_str().context("UTF-8 path")?,
            test_workers()?,
        )?;
        let subscription = manifest(b"snapshot")?.subscription;
        let old_one = archive.path(subscription, 1, SnapshotId::from_bytes([1; 16]), "sealed");
        let old_part = archive.path(subscription, 1, SnapshotId::from_bytes([2; 16]), "part");
        let old_two = archive.path(subscription, 2, SnapshotId::from_bytes([3; 16]), "sealed");
        let active = archive.path(subscription, 3, SnapshotId::from_bytes([4; 16]), "sealed");
        let another = archive.path(
            SubscriptionRef {
                id: SubscriptionId::from_bytes([9; 16]),
                ..subscription
            },
            1,
            SnapshotId::from_bytes([5; 16]),
            "sealed",
        );
        for path in [&old_one, &old_part, &old_two, &active, &another] {
            fs::write(path, b"bytes")?;
        }
        ensure!(remove_released_files(&archive.directory, subscription, 2, 1)? == 1);
        ensure!(active.exists() && another.exists());
        ensure!(remove_released_files(&archive.directory, subscription, 2, 4)? == 2);
        ensure!(remove_released_files(&archive.directory, subscription, 2, 4)? == 0);
        ensure!(!old_one.exists() && !old_part.exists() && !old_two.exists());
        ensure!(active.exists() && another.exists());
        Ok(())
    }

    #[test]
    fn interrupted_part_files_count_against_archive_capacity() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let storage_path = directory.path().join("host.redb");
        let archive = StockSnapshotArchive::open(
            storage_path.to_str().context("UTF-8 path")?,
            test_workers()?,
        )?;
        let subscription = manifest(b"snapshot")?.subscription;
        for index in 0..MAX_ARCHIVED_FILES {
            let mut id = [0; 16];
            id[0] = index as u8;
            fs::write(
                archive.path(subscription, 1, SnapshotId::from_bytes(id), "part"),
                [],
            )?;
        }
        let next = archive.path(subscription, 2, SnapshotId::from_bytes([0xee; 16]), "part");
        ensure!(stage_length(&next, 1, false, &archive.reservation).is_err());
        ensure!(!next.exists());
        ensure!(remove_released_files(&archive.directory, subscription, 1, 4)? == 4);
        ensure!(stage_length(&next, 1, false, &archive.reservation)? == 0);
        Ok(())
    }

    #[test]
    fn release_declaration_binds_an_exact_subscription_and_generation() -> Result<()> {
        let manifest = manifest(b"snapshot")?;
        let mut publisher = String::new();
        let mut stream = String::new();
        let mut install = String::new();
        let mut completion = String::new();
        let mut evidence = String::new();
        append_hex(&mut publisher, manifest.stream.publisher.as_bytes());
        append_hex(&mut stream, manifest.stream.id.as_bytes());
        append_hex(&mut install, &[8; 16]);
        append_hex(&mut completion, &[9; 48]);
        append_hex(&mut evidence, &[10; 48]);
        let config = FederationSnapshotReaderReleaseConfig {
            publisher_node: publisher,
            stream_id: stream,
            subscription_generation: 0,
            install_id: install,
            federation_generation: 3,
            application_generation: 3,
            completion_digest: completion,
            release_digest: evidence,
        };
        let local = manifest.subscription.subscriber;
        let expected = remote_subscription(local, manifest.stream, 0).subscription;
        let release = parse_releases(std::slice::from_ref(&config), local)?[0].release;
        ensure!(release.subscription == expected && release.released_through_generation == 2);
        let mut mismatched = config.clone();
        mismatched.application_generation = 4;
        ensure!(parse_releases(&[mismatched], local).is_err());
        ensure!(parse_releases(&[config.clone(), config], local).is_err());
        Ok(())
    }
}
