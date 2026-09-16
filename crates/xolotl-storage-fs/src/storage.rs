use crate::Shared;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use xolotl_state::object::{ObjectMetadata, ObjectReadChunk};
use xolotl_state::{StateError, StateFailure, StateResult};
use xolotl_types::TaintSet;

mod metadata;

pub(crate) fn io_error(error: std::io::Error) -> StateFailure {
    StateError::Backend(error.to_string()).into()
}

pub(crate) fn validate_hash(hash: &str) -> StateResult<&str> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StateError::Backend("invalid object hash".into()).into());
    }
    Ok(hash)
}

pub(crate) fn metadata(shared: &Shared, hash: &str) -> StateResult<Option<ObjectMetadata>> {
    let directory = shared.root.join("objects").join(validate_hash(hash)?);
    let file = match File::open(directory.join(metadata::FILE_NAME)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !directory.exists() => {
            return Ok(None);
        }
        Err(error) => return Err(io_error(error)),
    };
    let stored = metadata::read(file, shared.options.max_metadata_bytes.get())?;
    let validation = (|| -> StateResult<()> {
        if stored.blob.hash != hash {
            return Err(StateError::Backend("invalid object metadata identity".into()).into());
        }
        let actual = std::fs::metadata(directory.join("data"))
            .map_err(io_error)?
            .len();
        if actual != stored.blob.size {
            return Err(
                StateError::Backend("object length disagrees with its metadata".into()).into(),
            );
        }
        Ok(())
    })();
    validation.map_err(|failure| failure.with_taint(&stored.taint))?;
    Ok(Some(stored))
}

pub(crate) fn read_chunk(
    shared: &Shared,
    hash: &str,
    offset: u64,
    count: usize,
) -> StateResult<(ObjectReadChunk, Vec<u8>)> {
    let metadata = metadata(shared, hash)?.ok_or_else(|| StateError::NotFound(hash.to_owned()))?;
    let bytes = (|| -> StateResult<Vec<u8>> {
        let remaining = metadata
            .blob
            .size
            .checked_sub(offset)
            .ok_or_else(|| StateError::Backend("object offset exceeds its length".into()))?;
        let count = count.min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let mut bytes = vec![0; count];
        if count > 0 {
            let mut file = File::open(shared.root.join("objects").join(hash).join("data"))
                .map_err(io_error)?;
            file.seek(SeekFrom::Start(offset)).map_err(io_error)?;
            file.read_exact(&mut bytes).map_err(io_error)?;
        }
        Ok(bytes)
    })()
    .map_err(|failure| failure.with_taint(&metadata.taint))?;
    let count = bytes.len();
    Ok((
        ObjectReadChunk {
            bytes_read: count,
            end: offset + count as u64 == metadata.blob.size,
            taint: metadata.taint,
        },
        bytes,
    ))
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> StateResult<()> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(io_error)
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> StateResult<()> {
    Ok(())
}

pub(crate) fn publish(
    shared: &Shared,
    staging: &Path,
    result: ObjectMetadata,
    cancelled: &AtomicBool,
) -> StateResult<ObjectMetadata> {
    let mut observed = result.taint.clone();
    publish_inner(shared, staging, result, cancelled, &mut observed)
        .map_err(|failure| failure.with_taint(&observed))
}

fn publish_inner(
    shared: &Shared,
    staging: &Path,
    mut result: ObjectMetadata,
    cancelled: &AtomicBool,
    observed: &mut TaintSet,
) -> StateResult<ObjectMetadata> {
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(shared.root.join("commit.lock"))
        .map_err(io_error)?;
    lock.lock().map_err(io_error)?;
    if cancelled.load(Ordering::Acquire) {
        return Err(StateError::Backend("upload was cancelled".into()).into());
    }
    let objects = shared.root.join("objects");
    let destination = objects.join(&result.blob.hash);
    match metadata(shared, &result.blob.hash)? {
        Some(mut existing) => {
            observed.union(&existing.taint);
            if existing.blob.size != result.blob.size {
                return Err(StateError::Backend("conflicting object length".into()).into());
            }
            existing.taint.union(&result.taint);
            metadata::write(
                &destination,
                &existing,
                shared.options.max_metadata_bytes.get(),
            )?;
            result = existing;
        }
        None => {
            metadata::write(staging, &result, shared.options.max_metadata_bytes.get())?;
            if cancelled.load(Ordering::Acquire) {
                return Err(StateError::Backend("upload was cancelled".into()).into());
            }
            std::fs::rename(staging, &destination).map_err(io_error)?;
            sync_directory(&objects)?;
        }
    }
    // Read the published metadata while still holding the publication lock.
    // The receipt reflects durable sources, including the deduplicated object's
    // previous floor; locally decorating a receipt cannot establish that fact.
    let published = metadata(shared, &result.blob.hash)?
        .ok_or_else(|| StateError::Backend("published object metadata is missing".into()))?;
    observed.union(&published.taint);
    if published.blob != result.blob || !published.taint.contains_all(&result.taint) {
        return Err(StateError::Backend(
            "published object metadata does not cover the sealed commit".into(),
        )
        .into());
    }
    Ok(published)
}

pub(crate) fn delete(shared: &Shared, hash: &str) -> StateResult<()> {
    let retired = tempfile::Builder::new()
        .prefix("retired-")
        .tempdir_in(shared.root.join("staging"))
        .map_err(io_error)?;
    {
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(shared.root.join("commit.lock"))
            .map_err(io_error)?;
        lock.lock().map_err(io_error)?;
        let objects = shared.root.join("objects");
        match std::fs::rename(
            objects.join(validate_hash(hash)?),
            retired.path().join("object"),
        ) {
            Ok(()) => sync_directory(&objects)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
    }
    retired.close().map_err(io_error)
}
