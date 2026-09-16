//! One cancellation-owned path from value events to an immutable object.

use core::fmt;
use xolotl_state::{
    StateError, StateFailure,
    object::{ObjectWrite, UploadId, UploadOptions},
};
use xolotl_types::{
    TaintSet,
    value::event::{CursorError, Event},
};
use xolotl_value_codec::{Error as CodecError, cbor::Encoder, validation::KeyStore};

use crate::Failure;
use crate::reference::{CommittedValue, EncodedValueRef, ValueEncoding};

/// Encoding or publication failure with the sources observed by this writer.
pub type WriteFailure<E> = Failure<WriteError<E>>;

/// A terminal failure to encode, stage, or commit one document.
#[derive(Debug)]
pub enum WriteError<E> {
    /// The provided I/O workspace cannot make progress.
    EmptyBuffer,
    /// The writer was finished, failed, or cancelled after its first poll.
    Closed,
    /// Shared value validation or encoding failed.
    Codec(CodecError<E>),
    /// The borrowed resident value cursor could not retain its working frames.
    Cursor(CursorError),
    /// The object port failed while beginning, writing, or committing.
    Storage(StateError),
    /// The codec did not produce bytes into a nonempty output window.
    CodecProgress,
    /// The store published metadata without required input provenance.
    /// The potentially published immutable content is not deleted.
    Provenance,
    /// Committed metadata does not match the acknowledged encoding length.
    Size {
        /// Fully acknowledged encoded length.
        expected: u64,
        /// Length reported by the committing object port.
        actual: u64,
    },
}

impl<E: fmt::Display> fmt::Display for WriteError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBuffer => formatter.write_str("encoded object output buffer is empty"),
            Self::Closed => formatter.write_str("encoded object writer is closed"),
            Self::Codec(error) => error.fmt(formatter),
            Self::Cursor(error) => error.fmt(formatter),
            Self::Storage(error) => error.fmt(formatter),
            Self::CodecProgress => formatter.write_str("value encoder made no output progress"),
            Self::Provenance => {
                formatter.write_str("committed object metadata omits required provenance")
            }
            Self::Size { expected, actual } => write!(
                formatter,
                "committed object contains {actual} bytes; acknowledged {expected}"
            ),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for WriteError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Codec(error) => Some(error),
            Self::Cursor(error) => Some(error),
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

struct Session<K> {
    upload: UploadId,
    encoder: Encoder<K>,
    acknowledged: u64,
    buffered: usize,
}

/// An exclusive upload owner with caller-provided I/O and map-key workspaces.
///
/// The object port receives known source provenance when staging begins and
/// merges sources supplied at [`Self::finish`] before publication. Claims in
/// recorded taint events never substitute for that storage provenance.
///
/// Polled cancellation or failure drops the private upload lease and closes
/// this writer. It never clones or exposes that lease, and never needs another
/// caller poll to abort staging. Cleanup follows [`ObjectWrite`]'s contract.
/// There is no executor, background task, or `Send` requirement.
pub struct ValueObjectWriter<'store, 'buffer, W: ?Sized, K> {
    store: &'store W,
    scratch: &'buffer mut [u8],
    taint: TaintSet,
    session: Option<Session<K>>,
}

impl<'store, 'buffer, W: ObjectWrite + ?Sized, K: KeyStore>
    ValueObjectWriter<'store, 'buffer, W, K>
{
    /// Begin a fresh CBOR document without reserving its final encoded size.
    ///
    /// `scratch` bounds each offered output window and must be nonempty.
    /// `max_frames` is an optional semantic nesting policy, independent of
    /// cumulative field length. The key store owns any additional retention.
    pub async fn begin(
        store: &'store W,
        scratch: &'buffer mut [u8],
        keys: K,
        max_frames: Option<usize>,
        mut initial_taint: TaintSet,
    ) -> Result<Self, WriteFailure<K::Error>> {
        if scratch.is_empty() {
            return Err(Failure::new(WriteError::EmptyBuffer, initial_taint));
        }
        let upload = store
            .begin_upload(UploadOptions {
                expected_size: None,
                mime: Some(ValueEncoding::CborV1.media_type().into()),
                taint: initial_taint.clone(),
            })
            .await
            .map_err(|failure| {
                let error = storage_error(failure, &mut initial_taint);
                Failure::new(error, initial_taint.clone())
            })?;
        Ok(Self {
            store,
            scratch,
            taint: initial_taint,
            session: Some(Session {
                upload,
                encoder: Encoder::new(keys, max_frames),
                acknowledged: 0,
                buffered: 0,
            }),
        })
    }

    /// Whether another event or final EOF can be offered.
    pub fn is_open(&self) -> bool {
        self.session.is_some()
    }

    /// Sources retained by this operation, including after failure or cancellation.
    /// Recorded wire claims do not supply these publication sources.
    pub fn observed_taint(&self) -> &TaintSet {
        &self.taint
    }

    /// Validate one event and retain its encoding in the owned upload or buffer.
    ///
    /// Consecutive events share `scratch`; full windows are written with
    /// backpressure, and a partial window remains owned here. Use [`Self::flush`]
    /// to await acknowledgement of every accepted byte before source EOF.
    ///
    /// Dropping this future before polling leaves the writer unchanged. Once
    /// polled, the future owns the entire session until required writes succeed.
    /// A cancelled final sink write closes the owner even if the event's codec
    /// guard had already generated every byte.
    /// `sources` records the actual provenance observed while obtaining this
    /// event. It is retained before validation or I/O and cannot be removed by
    /// a later call. Recorded taint events do not replace this argument.
    pub async fn write(
        &mut self,
        event: Event<'_>,
        sources: &TaintSet,
    ) -> Result<(), WriteFailure<K::Error>> {
        self.write_inner(event, sources)
            .await
            .map_err(|error| Failure::new(error, self.taint.clone()))
    }

    async fn write_inner(
        &mut self,
        event: Event<'_>,
        sources: &TaintSet,
    ) -> Result<(), WriteError<K::Error>> {
        let mut session = self.session.take().ok_or(WriteError::Closed)?;
        self.taint.union(sources);
        {
            let mut pending = session
                .encoder
                .encode(event)
                .await
                .map_err(WriteError::Codec)?;
            while !pending.is_complete() {
                let count = pending
                    .write(&mut self.scratch[session.buffered..])
                    .map_err(WriteError::Codec)?;
                if count == 0 {
                    return Err(WriteError::CodecProgress);
                }
                session.buffered += count;
                if session.buffered == self.scratch.len() {
                    flush_buffer::<W, K::Error>(
                        self.store,
                        &session.upload,
                        &mut session.acknowledged,
                        &mut session.buffered,
                        self.scratch,
                        &mut self.taint,
                    )
                    .await?;
                }
            }
        }
        self.session = Some(session);
        Ok(())
    }

    /// Await acknowledgement of every accepted byte without closing the document.
    ///
    /// The buffer is reusable only after every partial write is acknowledged.
    /// Polled cancellation or failure closes the complete upload, including
    /// bytes that were accepted before this flush began.
    pub async fn flush(&mut self) -> Result<(), WriteFailure<K::Error>> {
        self.flush_inner()
            .await
            .map_err(|error| Failure::new(error, self.taint.clone()))
    }

    async fn flush_inner(&mut self) -> Result<(), WriteError<K::Error>> {
        let mut session = self.session.take().ok_or(WriteError::Closed)?;
        flush_buffer::<W, K::Error>(
            self.store,
            &session.upload,
            &mut session.acknowledged,
            &mut session.buffered,
            self.scratch,
            &mut self.taint,
        )
        .await?;
        self.session = Some(session);
        Ok(())
    }

    /// Confirm actual event-source EOF, drain every final byte, and commit.
    ///
    /// `final_taint` includes sources discovered while consuming the complete
    /// input. It is merged with the initial sources before object publication;
    /// passing a smaller set cannot remove initial sources. Only a complete
    /// validated document can reach the commit request. Returned metadata must
    /// cover this required provenance and the acknowledged encoded length.
    /// A broken metadata response after commit is reported without deleting
    /// potentially shared immutable content. As with writes, polled cancellation
    /// consumes the session; no asynchronous abort is required.
    pub async fn finish(
        &mut self,
        final_taint: &TaintSet,
    ) -> Result<CommittedValue, WriteFailure<K::Error>> {
        self.finish_inner(final_taint)
            .await
            .map_err(|error| Failure::new(error, self.taint.clone()))
    }

    async fn finish_inner(
        &mut self,
        final_taint: &TaintSet,
    ) -> Result<CommittedValue, WriteError<K::Error>> {
        let mut session = self.session.take().ok_or(WriteError::Closed)?;
        self.taint.union(final_taint);
        while !session.encoder.is_complete() {
            let count = session
                .encoder
                .finish(&mut self.scratch[session.buffered..])
                .map_err(WriteError::Codec)?;
            if count == 0 {
                return Err(WriteError::CodecProgress);
            }
            session.buffered += count;
            if session.buffered == self.scratch.len() {
                flush_buffer::<W, K::Error>(
                    self.store,
                    &session.upload,
                    &mut session.acknowledged,
                    &mut session.buffered,
                    self.scratch,
                    &mut self.taint,
                )
                .await?;
            }
        }
        flush_buffer::<W, K::Error>(
            self.store,
            &session.upload,
            &mut session.acknowledged,
            &mut session.buffered,
            self.scratch,
            &mut self.taint,
        )
        .await?;
        let metadata = self
            .store
            .commit_upload(&session.upload, &self.taint)
            .await
            .map_err(|failure| storage_error(failure, &mut self.taint))?;
        self.taint.union(&metadata.taint);
        if metadata.blob.size != session.acknowledged {
            return Err(WriteError::Size {
                expected: session.acknowledged,
                actual: metadata.blob.size,
            });
        }
        if !metadata.taint.contains_all(&self.taint) {
            return Err(WriteError::Provenance);
        }
        Ok(CommittedValue {
            reference: EncodedValueRef {
                blob: metadata.blob,
                encoding: ValueEncoding::CborV1,
            },
            taint: metadata.taint,
        })
    }
}

async fn flush_buffer<W: ObjectWrite + ?Sized, E>(
    store: &W,
    upload: &UploadId,
    acknowledged: &mut u64,
    buffered: &mut usize,
    scratch: &[u8],
    taint: &mut TaintSet,
) -> Result<(), WriteError<E>> {
    let mut bytes = &scratch[..*buffered];
    while !bytes.is_empty() {
        let result = store
            .write_chunk(upload, *acknowledged, bytes)
            .await
            .map_err(|failure| storage_error(failure, taint))?;
        *acknowledged = result
            .checked_next_offset(*acknowledged, bytes.len())
            .map_err(|failure| storage_error(failure, taint))?;
        bytes = &bytes[result.bytes_written..];
    }
    *buffered = 0;
    Ok(())
}

fn storage_error<E>(failure: StateFailure, taint: &mut TaintSet) -> WriteError<E> {
    taint.union(&failure.taint);
    WriteError::Storage(failure.error)
}

#[cfg(test)]
mod tests;
