//! First-format metadata: XOF1, a little-endian u64 source length, JSON sources,
//! then a JSON BlobRef. One atomic file owns the sources and descriptor together.
//!
//! Decode the complete source header before admitting the total record size or
//! descriptor. A damaged or over-budget source header cannot establish a known
//! source floor and is rejected; it never produces an object receipt.

use super::{io_error, sync_directory};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use xolotl_state::{StateError, StateFailure, StateResult, object::ObjectMetadata};
use xolotl_types::{BlobRef, TaintSet};

pub(super) const FILE_NAME: &str = "metadata";
const FORMAT: &[u8; 4] = b"XOF1";
const PREFIX_BYTES: usize = 12;

pub(super) fn read(file: File, limit: usize) -> StateResult<ObjectMetadata> {
    let mut reader = BufReader::new(file);
    let mut prefix = [0; PREFIX_BYTES];
    reader.read_exact(&mut prefix).map_err(io_error)?;
    if &prefix[..4] != FORMAT {
        return Err(StateError::Backend("unsupported object metadata format".into()).into());
    }
    let mut length = [0; 8];
    length.copy_from_slice(&prefix[4..]);
    let source_bytes = u64::from_le_bytes(length);
    if source_bytes > limit.saturating_sub(PREFIX_BYTES) as u64 {
        return Err(
            StateError::Backend("object source header exceeds configured limit".into()).into(),
        );
    }
    let mut sources = reader.by_ref().take(source_bytes);
    let taint: TaintSet = serde_json::from_reader(&mut sources)?;
    let source_remaining = sources.limit();
    let blob = (|| -> StateResult<BlobRef> {
        if source_remaining != 0 {
            return Err(StateError::Backend("object source header is truncated".into()).into());
        }
        if reader.get_ref().metadata().map_err(io_error)?.len() > limit as u64 {
            return Err(metadata_limit());
        }
        // A concurrent file change cannot make descriptor decoding unbounded or
        // turn the policy window's artificial EOF into accepted physical EOF.
        let descriptor_bytes = limit as u64 - PREFIX_BYTES as u64 - source_bytes;
        let blob = serde_json::from_reader(reader.by_ref().take(descriptor_bytes))?;
        if reader.read(&mut [0; 1]).map_err(io_error)? != 0 {
            return Err(metadata_limit());
        }
        Ok(blob)
    })()
    .map_err(|failure| failure.with_taint(&taint))?;
    Ok(ObjectMetadata { blob, taint })
}

struct BoundedWriter<'a> {
    file: &'a mut File,
    remaining: usize,
}

impl Write for BoundedWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other(
                "object metadata exceeds configured limit",
            ));
        }
        let written = self.file.write(bytes)?;
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

pub(super) fn write(directory: &Path, metadata: &ObjectMetadata, limit: usize) -> StateResult<()> {
    write_inner(directory, metadata, limit).map_err(|failure| failure.with_taint(&metadata.taint))
}

fn write_inner(directory: &Path, metadata: &ObjectMetadata, limit: usize) -> StateResult<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(directory).map_err(io_error)?;
    let source_bytes = {
        let mut writer = BoundedWriter {
            file: temporary.as_file_mut(),
            remaining: limit,
        };
        writer.write_all(FORMAT).map_err(io_error)?;
        writer.write_all(&[0; 8]).map_err(io_error)?;
        serde_json::to_writer(&mut writer, &metadata.taint)?;
        let source_bytes = u64::try_from(limit - writer.remaining - PREFIX_BYTES)
            .map_err(|_error| metadata_limit())?;
        serde_json::to_writer(&mut writer, &metadata.blob)?;
        source_bytes
    };
    // Fill the already reserved prefix after streaming the borrowed sources.
    // No complete metadata buffer or second source serialization is required.
    let file = temporary.as_file_mut();
    file.seek(SeekFrom::Start(4)).map_err(io_error)?;
    file.write_all(&source_bytes.to_le_bytes())
        .map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    temporary
        .persist(directory.join(FILE_NAME))
        .map_err(|error| io_error(error.error))?;
    sync_directory(directory)
}

fn metadata_limit() -> StateFailure {
    StateError::Backend("object metadata exceeds configured limit".into()).into()
}
