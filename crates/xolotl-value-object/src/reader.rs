//! One complete encoded document read through an explicitly supplied object port.

use core::{fmt, ops::Range};
use xolotl_state::{
    StateError, StateFailure,
    object::{ObjectMetadata, ObjectRead},
};
use xolotl_types::{
    TaintSet,
    value::event::{Atom, BuilderError, Event, Kind},
};
use xolotl_value_codec::{
    Error as CodecError,
    cbor::{DecodeStatus, Decoder},
    validation::KeyStore,
};

use crate::{EncodedValueRef, Failure, ValueEncoding};

mod resident;
pub use resident::read_value;

/// Why one complete-document read or explicit materialization failed.
#[derive(Debug)]
pub enum ReadError<E> {
    /// A nonempty caller-owned workspace is required for read progress.
    EmptyBuffer,
    /// The owner already failed, was cancelled, or delivered its receipt.
    Closed,
    /// The supplied reference does not resolve to committed content.
    Missing,
    /// Hash, size, or descriptive MIME disagrees with canonical metadata.
    MetadataMismatch,
    /// The object port failed or returned invalid progress.
    Storage(StateError),
    /// The shared document decoder rejected framing, grammar, or key work.
    Codec(CodecError<E>),
    /// The decoder did not consume the offered bytes consistently.
    CodecProgress,
    /// Completion was requested before actual EOF and document validation.
    Incomplete,
    /// Explicit resident materialization rejected the document or its budget.
    Materialization(BuilderError),
}

impl<E: fmt::Display> fmt::Display for ReadError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBuffer => formatter.write_str("encoded object input buffer is empty"),
            Self::Closed => formatter.write_str("encoded object reader is closed"),
            Self::Missing => formatter.write_str("encoded object is missing"),
            Self::MetadataMismatch => {
                formatter.write_str("encoded object reference differs from canonical metadata")
            }
            Self::Storage(error) => error.fmt(formatter),
            Self::Codec(error) => error.fmt(formatter),
            Self::CodecProgress => formatter.write_str("value decoder returned invalid progress"),
            Self::Incomplete => formatter.write_str("encoded object has not completed validation"),
            Self::Materialization(error) => error.fmt(formatter),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for ReadError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::Codec(error) => Some(error),
            Self::Materialization(error) => Some(error),
            _ => None,
        }
    }
}

/// A failed read together with the sources already observed by its owner.
///
/// This includes opening metadata and every acknowledged chunk, even when its
/// progress or bytes are subsequently rejected. Explicit materialization also
/// conservatively retains completely parsed wire claims. None of these labels
/// authorizes an object read, disclosure, or external effect.
pub type ReadFailure<E> = Failure<ReadError<E>>;

/// One tentative event borrowing the reader's scratch and source observation.
///
/// The complete document has not necessarily been validated. Keep a streaming
/// consumer's result private until a [`ReadReceipt`] is returned. These sources
/// support policy checks; they do not establish authority to send the event or
/// any object bytes to another audience.
#[derive(Clone, Copy, Debug)]
pub struct ReadEvent<'a> {
    /// The accepted event, with data borrowed directly from the input window.
    pub event: Event<'a>,
    /// Initial sources, metadata, and all chunks read through this event.
    pub taint: &'a TaintSet,
}

/// Evidence that one canonical object reached real EOF as a valid document.
///
/// The private fields can only be produced by a completed reader. This is
/// validation evidence, not a read grant, retention lease, or disclosure grant.
#[derive(Clone, Debug)]
pub struct ReadReceipt {
    reference: EncodedValueRef,
    taint: TaintSet,
}

impl ReadReceipt {
    /// Canonical object descriptor whose complete bytes were validated.
    pub fn reference(&self) -> &EncodedValueRef {
        &self.reference
    }

    /// Initial sources plus every observed metadata and read-chunk source.
    /// Claims recorded inside the document are interpreted by its consumer.
    pub fn taint(&self) -> &TaintSet {
        &self.taint
    }
}

struct Session<K> {
    decoder: Decoder<K>,
    next_offset: u64,
    cursor: usize,
    buffered: usize,
    object_end: bool,
}

enum Phase<K> {
    Open(Session<K>),
    Complete,
    Closed,
}

// Retain only coordinates while the read loop may refill scratch. Reborrow the
// selected data after leaving that loop, without copying its payload or keeping
// a buffer borrow alive across the next mutable storage read.
enum BufferedEvent {
    Begin(Kind),
    End(Kind),
    Atom(Atom),
    Data(Range<usize>),
}

impl BufferedEvent {
    fn capture(event: Event<'_>, consumed: &[u8], cursor: usize) -> Option<Self> {
        Some(match event {
            Event::Begin(kind) => Self::Begin(kind),
            Event::End(kind) => Self::End(kind),
            Event::Atom(atom) => Self::Atom(atom),
            Event::Data(bytes) => {
                // Decoder data must borrow the acknowledged input prefix. The
                // checked range also covers empty data records at its end.
                let start = bytes
                    .as_ptr()
                    .addr()
                    .checked_sub(consumed.as_ptr().addr())?;
                let end = start.checked_add(bytes.len())?;
                if end > consumed.len() {
                    return None;
                }
                Self::Data(cursor.checked_add(start)?..cursor.checked_add(end)?)
            }
        })
    }

    fn borrow(self, scratch: &[u8]) -> Option<Event<'_>> {
        Some(match self {
            Self::Begin(kind) => Event::Begin(kind),
            Self::End(kind) => Event::End(kind),
            Self::Atom(atom) => Event::Atom(atom),
            Self::Data(range) => Event::Data(scratch.get(range)?),
        })
    }
}

/// A streaming document owner using one borrowed I/O window and key workspace.
///
/// The caller supplies an already admitted [`ObjectRead`] port. Opening a
/// descriptor does not create authority and never dereferences nested Blob,
/// Tensor, or Frame descriptors. The explicit encoding selects the decoder;
/// MIME is compared as part of canonical metadata, not used to infer a codec.
///
/// This owner reads exactly one complete object. Its source set grows with
/// sources contributing to that document, while payload retention stays within
/// `scratch` plus the selected validator workspace. There is no cumulative byte
/// or event limit, executor, background task, or global `Send` requirement.
/// Independent stream messages need independent source ownership.
///
/// A polled read takes the session until it can return an accepted result.
/// Failure or cancellation closes it and releases key work; dropping an
/// unpolled future leaves it usable. Previously observed sources remain
/// available through [`Self::observed_taint`] after cancellation.
#[must_use = "consume the document through EOF and finish it, or drop the reader"]
pub struct ValueObjectReader<'store, 'buffer, R: ?Sized, K> {
    store: &'store R,
    scratch: &'buffer mut [u8],
    metadata: ObjectMetadata,
    observed: TaintSet,
    phase: Phase<K>,
}

impl<'store, 'buffer, R: ObjectRead + ?Sized, K: KeyStore>
    ValueObjectReader<'store, 'buffer, R, K>
{
    /// Resolve exact canonical metadata before reading any document bytes.
    ///
    /// `initial_sources` describes the caller's reference and other inputs.
    /// `max_frames` is an optional simultaneous nesting policy; scratch size
    /// bounds individual I/O windows independently of document length.
    pub async fn open(
        store: &'store R,
        reference: &EncodedValueRef,
        scratch: &'buffer mut [u8],
        keys: K,
        max_frames: Option<usize>,
        mut initial_sources: TaintSet,
    ) -> Result<Self, ReadFailure<K::Error>> {
        if scratch.is_empty() {
            return Err(ReadFailure {
                error: ReadError::EmptyBuffer,
                taint: initial_sources,
            });
        }
        let metadata = store
            .metadata(&reference.blob)
            .await
            .map_err(|failure| {
                initial_sources.union(&failure.taint);
                ReadFailure {
                    error: ReadError::Storage(failure.error),
                    taint: initial_sources.clone(),
                }
            })?
            .ok_or_else(|| ReadFailure {
                error: ReadError::Missing,
                taint: initial_sources.clone(),
            })?;
        initial_sources.union(&metadata.taint);
        if metadata.blob != reference.blob {
            return Err(ReadFailure {
                error: ReadError::MetadataMismatch,
                taint: initial_sources,
            });
        }
        let decoder = match reference.encoding {
            ValueEncoding::CborV1 => Decoder::new(keys, max_frames),
        };
        Ok(Self {
            store,
            scratch,
            metadata,
            observed: initial_sources,
            phase: Phase::Open(Session {
                decoder,
                next_offset: 0,
                cursor: 0,
                buffered: 0,
                // Even an empty object must return its own acknowledged EOF.
                object_end: false,
            }),
        })
    }

    /// Canonical metadata captured when this document was opened.
    pub fn metadata(&self) -> &ObjectMetadata {
        &self.metadata
    }

    /// All initial and acknowledged object sources observed so far.
    pub fn observed_taint(&self) -> &TaintSet {
        &self.observed
    }

    /// Whether another event can be read from the current session.
    pub fn is_open(&self) -> bool {
        matches!(self.phase, Phase::Open(_))
    }

    /// Whether validated EOF is ready to be consumed by [`Self::finish`].
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, Phase::Complete)
    }

    /// Read through one accepted event, borrowing its bytes until the next call.
    ///
    /// `None` means the object port acknowledged actual EOF, every supplied
    /// byte was consumed, and the decoder validated the complete document.
    /// An envelope end alone is insufficient. Errors retain all sources seen
    /// before the failure, including a chunk whose progress was invalid.
    pub async fn next_event(&mut self) -> Result<Option<ReadEvent<'_>>, ReadFailure<K::Error>> {
        let mut session = match core::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::Open(session) => session,
            Phase::Complete => {
                self.phase = Phase::Complete;
                return Ok(None);
            }
            Phase::Closed => return Err(self.failure(ReadError::Closed)),
        };
        let event = loop {
            if session.cursor == session.buffered {
                if session.object_end {
                    session
                        .decoder
                        .finish()
                        .map_err(|error| self.failure(ReadError::Codec(error)))?;
                    if session.decoder.bytes_read() != self.metadata.blob.size {
                        return Err(self.failure(ReadError::CodecProgress));
                    }
                    self.phase = Phase::Complete;
                    return Ok(None);
                }
                let remaining = self.metadata.blob.size - session.next_offset;
                let offered = self
                    .scratch
                    .len()
                    .min(usize::try_from(remaining).unwrap_or(usize::MAX));
                let chunk = self
                    .store
                    .read_chunk(
                        &self.metadata.blob,
                        session.next_offset,
                        &mut self.scratch[..offered],
                    )
                    .await
                    .map_err(|failure| self.storage_failure(failure))?;
                self.observed.union(&chunk.taint);
                session.next_offset = chunk
                    .checked_next_offset(session.next_offset, offered, self.metadata.blob.size)
                    .map_err(|failure| self.storage_failure(failure))?;
                session.cursor = 0;
                session.buffered = chunk.bytes_read;
                session.object_end = chunk.end;
                if session.buffered == 0 {
                    // checked_next_offset permits this only at canonical EOF.
                    continue;
                }
            }
            let available = session.buffered - session.cursor;
            let step = session
                .decoder
                .decode(&self.scratch[session.cursor..session.buffered])
                .await
                .map_err(|error| self.failure(ReadError::Codec(error)))?;
            if step.consumed == 0 || step.consumed > available {
                return Err(self.failure(ReadError::CodecProgress));
            }
            let start = session.cursor;
            session.cursor += step.consumed;
            match step.status {
                DecodeStatus::Event(event) => {
                    break BufferedEvent::capture(
                        event,
                        &self.scratch[start..session.cursor],
                        start,
                    )
                    .ok_or_else(|| self.failure(ReadError::CodecProgress))?;
                }
                DecodeStatus::NeedInput | DecodeStatus::End => {
                    if session.cursor != session.buffered {
                        return Err(self.failure(ReadError::CodecProgress));
                    }
                }
            }
        };
        let event = event
            .borrow(self.scratch)
            .ok_or_else(|| self.failure(ReadError::CodecProgress))?;
        self.phase = Phase::Open(session);
        Ok(Some(ReadEvent {
            event,
            taint: &self.observed,
        }))
    }

    /// Close a validated document and return its sole completion receipt.
    ///
    /// This does not drain unread input or publish a consumer's tentative state.
    /// A premature finish closes the reader and returns its observed sources.
    pub fn finish(&mut self) -> Result<ReadReceipt, ReadFailure<K::Error>> {
        match core::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::Complete => Ok(ReadReceipt {
                reference: EncodedValueRef {
                    blob: self.metadata.blob.clone(),
                    encoding: ValueEncoding::CborV1,
                },
                taint: self.observed.clone(),
            }),
            Phase::Open(_session) => Err(self.failure(ReadError::Incomplete)),
            Phase::Closed => Err(self.failure(ReadError::Closed)),
        }
    }

    fn failure(&self, error: ReadError<K::Error>) -> ReadFailure<K::Error> {
        ReadFailure {
            error,
            taint: self.observed.clone(),
        }
    }

    fn storage_failure(&mut self, failure: StateFailure) -> ReadFailure<K::Error> {
        self.observed.union(&failure.taint);
        self.failure(ReadError::Storage(failure.error))
    }
}

#[cfg(test)]
mod tests;
