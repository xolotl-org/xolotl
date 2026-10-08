use crate::{Shared, cleanup, storage};
use sha2::{Digest as _, Sha384};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use xolotl_state::object::{ObjectMetadata, ObjectWriteChunk, UploadOptions};
use xolotl_state::{StateError, StateResult};
use xolotl_types::{BlobRef, TaintSet};

struct Commit {
    // The first publication attempt freezes the content identity and its source
    // floor together. A deduplicated receipt can carry additional stored sources;
    // those never change which commit requests are valid retries.
    request: ObjectMetadata,
    receipt: Option<ObjectMetadata>,
}

enum Phase {
    Open,
    Sealed(Commit),
    Aborted,
}

pub(crate) struct Upload {
    id: String,
    directory: Option<tempfile::TempDir>,
    file: Option<File>,
    options: UploadOptions,
    hasher: Sha384,
    size: u64,
    phase: Phase,
    cleanup: cleanup::Sender,
    slot: Option<tokio::sync::OwnedSemaphorePermit>,
    #[cfg(test)]
    probe: std::sync::Arc<crate::tests::IoProbe>,
}

impl Drop for Upload {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.take() {
            self.cleanup.enqueue(cleanup::Task {
                file: self.file.take(),
                directory,
                slot: self.slot.take(),
                #[cfg(test)]
                probe: self.probe.clone(),
            });
        }
    }
}

impl Upload {
    pub(crate) fn new(
        shared: &Shared,
        options: UploadOptions,
        slot: tokio::sync::OwnedSemaphorePermit,
    ) -> StateResult<Self> {
        #[cfg(test)]
        shared
            .probe
            .upload_creations
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let taint = options.taint.clone();
        let cleanup = shared
            .cleanup_sender()
            .map_err(|failure| failure.with_taint(&taint))?;
        Self::create(
            &shared.root,
            options,
            cleanup,
            slot,
            #[cfg(test)]
            shared.probe.clone(),
        )
        .map_err(|failure| failure.with_taint(&taint))
    }

    fn create(
        root: &Path,
        options: UploadOptions,
        cleanup: cleanup::Sender,
        slot: tokio::sync::OwnedSemaphorePermit,
        #[cfg(test)] probe: std::sync::Arc<crate::tests::IoProbe>,
    ) -> StateResult<Self> {
        let directory = tempfile::Builder::new()
            .prefix("upload-")
            .tempdir_in(root.join("staging"))
            .map_err(storage::io_error)?;
        let id = directory
            .path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| StateError::Backend("invalid staging name".into()))?
            .to_owned();
        let mut upload = Self {
            id,
            directory: Some(directory),
            file: None,
            options,
            hasher: Sha384::new(),
            size: 0,
            phase: Phase::Open,
            cleanup,
            slot: Some(slot),
            #[cfg(test)]
            probe,
        };
        #[cfg(test)]
        if upload
            .probe
            .upload_open_failures
            .fetch_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |remaining| remaining.checked_sub(1),
            )
            .is_ok()
        {
            return Err(storage::io_error(std::io::Error::other(
                "injected staging data open failure",
            )));
        }
        upload.file = Some(
            OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(
                    upload
                        .directory
                        .as_ref()
                        .ok_or_else(|| {
                            StateError::Backend("upload has no staging directory".into())
                        })?
                        .path()
                        .join("data"),
                )
                .map_err(storage::io_error)?,
        );
        Ok(upload)
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    pub(crate) fn sources(&self) -> TaintSet {
        let mut sources = self.options.taint.clone();
        if let Phase::Sealed(commit) = &self.phase {
            sources.union(&commit.request.taint);
            if let Some(receipt) = &commit.receipt {
                sources.union(&receipt.taint);
            }
        }
        sources
    }

    pub(crate) fn write(&mut self, offset: u64, bytes: &[u8]) -> StateResult<ObjectWriteChunk> {
        self.write_inner(offset, bytes)
            .map_err(|failure| failure.with_taint(&self.sources()))
    }

    fn write_inner(&mut self, offset: u64, bytes: &[u8]) -> StateResult<ObjectWriteChunk> {
        if !matches!(self.phase, Phase::Open) {
            return Err(StateError::Backend("upload is closed".into()).into());
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| StateError::Backend("object offset overflow".into()))?;
        if offset > self.size || self.options.expected_size.is_some_and(|size| end > size) {
            return Err(
                StateError::Backend("noncontiguous or oversized upload chunk".into()).into(),
            );
        }
        let file = self
            .file
            .as_mut()
            .ok_or_else(|| StateError::Backend("upload has no staging file".into()))?;
        let overlap = usize::try_from(self.size - offset)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        if overlap > 0 {
            let mut existing = vec![0; overlap];
            file.seek(SeekFrom::Start(offset))
                .map_err(storage::io_error)?;
            file.read_exact(&mut existing).map_err(storage::io_error)?;
            if existing != bytes[..overlap] {
                return Err(StateError::Backend("conflicting upload retry".into()).into());
            }
        }
        if end > self.size {
            file.seek(SeekFrom::Start(self.size))
                .map_err(storage::io_error)?;
            if let Err(error) = file.write_all(&bytes[overlap..]) {
                if let Err(rollback) = file.set_len(self.size) {
                    self.phase = Phase::Aborted;
                    return Err(StateError::Backend(format!(
                        "upload write failed: {error}; rollback failed: {rollback}"
                    ))
                    .into());
                }
                return Err(storage::io_error(error));
            }
            self.hasher.update(&bytes[overlap..]);
            self.size = end;
        }
        Ok(ObjectWriteChunk {
            bytes_written: bytes.len(),
            next_offset: end,
        })
    }

    pub(crate) fn commit(
        &mut self,
        shared: &Shared,
        cancelled: &AtomicBool,
        final_taint: &TaintSet,
    ) -> StateResult<ObjectMetadata> {
        self.commit_inner(shared, cancelled, final_taint)
            .map_err(|failure| failure.with_taint(&self.sources()).with_taint(final_taint))
    }

    fn commit_inner(
        &mut self,
        shared: &Shared,
        cancelled: &AtomicBool,
        final_taint: &TaintSet,
    ) -> StateResult<ObjectMetadata> {
        let required = self.options.taint.clone().merged(final_taint);
        match &self.phase {
            Phase::Sealed(commit) => {
                if !commit.request.taint.contains_all(&required)
                    || !required.contains_all(&commit.request.taint)
                {
                    return Err(StateError::Backend(
                        "upload commit sources differ from the sealed request".into(),
                    )
                    .into());
                }
                if let Some(metadata) = &commit.receipt {
                    let metadata = metadata.clone();
                    self.cleanup()?;
                    return Ok(metadata);
                }
            }
            Phase::Aborted => return Err(StateError::Backend("upload was aborted".into()).into()),
            Phase::Open => {
                self.validate_commit()?;
                // A failed preflight leaves the upload writable. Every fallible
                // filesystem operation after this transition sees sealed bytes
                // and provenance, even when a caller loses the acknowledgement.
                self.phase = Phase::Sealed(Commit {
                    request: ObjectMetadata {
                        blob: BlobRef {
                            hash: BlobRef::sha384_hex(&self.hasher.clone().finalize().into()),
                            size: self.size,
                            mime: self.options.mime.clone(),
                        },
                        taint: required,
                    },
                    receipt: None,
                });
            }
        }
        let Phase::Sealed(commit) = &mut self.phase else {
            return Err(StateError::Backend("upload has no sealed commit".into()).into());
        };
        self.file
            .as_ref()
            .ok_or_else(|| StateError::Backend("upload has no staging file".into()))?
            .sync_all()
            .map_err(storage::io_error)?;
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| StateError::Backend("upload has no staging directory".into()))?;
        let metadata =
            storage::publish(shared, directory.path(), commit.request.clone(), cancelled)?;
        commit.receipt = Some(metadata.clone());
        self.cleanup()?;
        Ok(metadata)
    }

    fn validate_commit(&self) -> StateResult<()> {
        if self
            .options
            .expected_size
            .is_some_and(|size| size != self.size)
        {
            return Err(
                StateError::Backend("upload length does not match its declaration".into()).into(),
            );
        }
        if self.file.is_none() || self.directory.is_none() {
            return Err(StateError::Backend("upload has no staging state".into()).into());
        }
        Ok(())
    }

    pub(crate) fn abort(&mut self) -> StateResult<()> {
        let sources = self.sources();
        self.phase = Phase::Aborted;
        self.cleanup()
            .map_err(|failure| failure.with_taint(&sources))
    }

    fn cleanup(&mut self) -> StateResult<()> {
        drop(self.file.take());
        if let Some(directory) = self.directory.as_ref() {
            match std::fs::remove_dir_all(directory.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(storage::io_error(error)),
            }
        }
        drop(self.directory.take());
        Ok(())
    }
}
