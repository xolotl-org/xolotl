//! Borrowed encoding of a completed resident value into an immutable object.

use core::num::NonZeroUsize;
use xolotl_state::object::ObjectWrite;
use xolotl_types::{TaintSet, TaintedValue, value::event::ValueCursor};
use xolotl_value_codec::validation::KeyStore;

use crate::{CommittedValue, Failure, ValueObjectWriter, WriteError, WriteFailure};

/// Encode a completed resident value without cloning or owning its payload.
///
/// The cursor borrows both the value and its recorded provenance, splitting
/// variable fields according to `scratch.len()`. Final storage provenance comes
/// from the same supplied tainted value, so callers need not assemble a second
/// source-label path. The upload is committed only after the cursor reaches EOF
/// and the writer validates and drains its closing envelope.
///
/// Cancellation and failure release cursor frames and owned upload staging.
/// The caller retains the source value's independent shared ownership.
pub async fn encode_value<W: ObjectWrite + ?Sized, K: KeyStore>(
    store: &W,
    scratch: &mut [u8],
    keys: K,
    max_frames: Option<usize>,
    value: &TaintedValue,
) -> Result<CommittedValue, WriteFailure<K::Error>> {
    let failure = |error| Failure::new(error, value.taint.clone());
    let chunk_bytes =
        NonZeroUsize::new(scratch.len()).ok_or_else(|| failure(WriteError::EmptyBuffer))?;
    let cursor = ValueCursor::new(&value.value, &value.taint, chunk_bytes, max_frames)
        .map_err(|error| failure(WriteError::Cursor(error)))?;
    encode_cursor(store, scratch, keys, max_frames, cursor, &value.taint).await
}

/// Encode a failure as its complete, ordinary Serde Value shape without JSON.
///
/// The shared cursor borrows the variant's fields, long strings, permission
/// lists, and canonical path fragments. The supplied provenance accompanies
/// both the document and object publication. Failure diagnostics never pass
/// through Display or a temporary resident Value before encoding.
pub async fn encode_failure<W: ObjectWrite + ?Sized, K: KeyStore>(
    store: &W,
    scratch: &mut [u8],
    keys: K,
    max_frames: Option<usize>,
    failure: &xolotl_types::Failure,
    taint: &TaintSet,
) -> Result<CommittedValue, WriteFailure<K::Error>> {
    let attach = |error| Failure::new(error, taint.clone());
    let chunk_bytes =
        NonZeroUsize::new(scratch.len()).ok_or_else(|| attach(WriteError::EmptyBuffer))?;
    let cursor = ValueCursor::from_failure(failure, taint, chunk_bytes, max_frames)
        .map_err(|error| attach(WriteError::Cursor(error)))?;
    encode_cursor(store, scratch, keys, max_frames, cursor, taint).await
}

async fn encode_cursor<W: ObjectWrite + ?Sized, K: KeyStore>(
    store: &W,
    scratch: &mut [u8],
    keys: K,
    max_frames: Option<usize>,
    mut cursor: ValueCursor<'_>,
    taint: &TaintSet,
) -> Result<CommittedValue, WriteFailure<K::Error>> {
    let mut writer =
        ValueObjectWriter::begin(store, scratch, keys, max_frames, taint.clone()).await?;
    while let Some(event) = cursor
        .next_event()
        .map_err(|error| Failure::new(WriteError::Cursor(error), taint.clone()))?
    {
        writer.write(event, taint).await?;
    }
    writer.finish(taint).await
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "resident/failure_tests.rs"]
mod failure_tests;
