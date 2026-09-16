use super::super::{ObjectMetadata, ObjectRead, ObjectReadChunk};
use crate::StateResult;
use alloc::{boxed::Box, rc::Rc};
use anyhow::ensure;
use core::{
    future::{Future, Ready, ready},
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use xolotl_types::{BlobRef, TaintSet};

#[test]
fn progress_accepts_partial_reads_empty_windows_and_exact_eof() -> anyhow::Result<()> {
    for (offset, offered, size, bytes_read, end, next) in [
        (1, 4, 8, 2, false, 3),
        (6, 4, 8, 2, true, 8),
        (8, 4, 8, 0, true, 8),
        (2, 0, 8, 0, false, 2),
        (0, 0, 0, 0, true, 0),
        (u64::MAX - 2, 2, u64::MAX, 2, true, u64::MAX),
    ] {
        let chunk = ObjectReadChunk {
            bytes_read,
            end,
            taint: TaintSet::pristine(),
        };
        ensure!(chunk.checked_next_offset(offset, offered, size)? == next);
    }
    Ok(())
}

#[test]
fn progress_rejects_invalid_acknowledgements_without_slicing_payload() -> anyhow::Result<()> {
    for (offset, offered, size, bytes_read, end) in [
        (0, 2, 8, 3, false),
        (0, 2, 8, 0, false),
        (0, 2, 8, 1, true),
        (7, 2, 8, 1, false),
        (7, 2, 8, 2, true),
        (0, 0, 8, 0, true),
        (9, 0, 8, 0, false),
        (u64::MAX, 1, u64::MAX, 1, true),
    ] {
        let chunk = ObjectReadChunk {
            bytes_read,
            end,
            taint: TaintSet::pristine(),
        };
        ensure!(chunk.checked_next_offset(offset, offered, size).is_err());
    }
    Ok(())
}

struct LocalReader {
    bytes: Rc<[u8]>,
}

impl ObjectRead for LocalReader {
    type Metadata<'a> = Ready<StateResult<Option<ObjectMetadata>>>;
    type ReadChunk<'a> = Pin<Box<dyn Future<Output = StateResult<ObjectReadChunk>> + 'a>>;

    fn metadata<'a>(&'a self, blob: &'a BlobRef) -> Self::Metadata<'a> {
        ready(Ok(Some(ObjectMetadata {
            blob: blob.clone(),
            taint: TaintSet::pristine(),
        })))
    }

    fn read_chunk<'a>(
        &'a self,
        _blob: &'a BlobRef,
        offset: u64,
        buffer: &'a mut [u8],
    ) -> Self::ReadChunk<'a> {
        Box::pin(async move {
            let start = usize::try_from(offset)
                .ok()
                .filter(|offset| *offset <= self.bytes.len())
                .ok_or(crate::StateError::Unsupported("test reader offset"))?;
            let length = buffer.len().min(self.bytes.len() - start);
            buffer[..length].copy_from_slice(&self.bytes[start..start + length]);
            Ok(ObjectReadChunk {
                bytes_read: length,
                end: start + length == self.bytes.len(),
                taint: TaintSet::pristine(),
            })
        })
    }
}

#[test]
fn local_reader_composes_with_borrowed_windows_without_send_or_a_runtime() -> anyhow::Result<()> {
    let reader = LocalReader {
        bytes: Rc::from(&b"abc"[..]),
    };
    let blob = BlobRef {
        hash: "local".into(),
        size: 3,
        mime: None,
    };
    let mut buffer = [0; 2];
    let chunk = {
        let mut read = pin!(reader.read_chunk(&blob, 1, &mut buffer));
        let Poll::Ready(result) = read.as_mut().poll(&mut Context::from_waker(Waker::noop()))
        else {
            anyhow::bail!("local read must complete immediately");
        };
        result?
    };
    ensure!(chunk.checked_next_offset(1, buffer.len(), blob.size)? == 3);
    ensure!(&buffer == b"bc");
    Ok(())
}
