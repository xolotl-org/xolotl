use super::{Atom, Event, Kind};
use alloc::{collections::TryReserveError, vec::Vec};
use core::{cmp::Ordering, fmt};
use thiserror::Error;

mod frame;
mod utf8;
use frame::{Frame, Key, KeyFrame};

/// A workspace key identity scoped to one validator and its storage owner.
/// Identities are never reused within a document. They carry no storage lease,
/// and must not be passed to another validator's workspace.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyId(u64);

impl KeyId {
    /// The opaque identity's numeric value within its owning workspace.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One operation on the caller-owned, rereadable map-key workspace.
///
/// Effects never perform I/O themselves. A driver may use resident memory or
/// await an external store; the pending validation keeps the offered bytes
/// borrowed throughout. Storage must avoid materializing an entire key merely
/// to compare a prefix or append a fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyEffect<'a> {
    /// Create an empty key under a fresh identity.
    Create {
        /// Identity allocated by this validator.
        key: KeyId,
    },
    /// Compare the stored range with `bytes`, returning stored-versus-input order.
    /// The stored range has exactly `bytes.len()` bytes. An unreadable or short
    /// range is a storage error; a suffix after that range must not affect order.
    ComparePrefix {
        /// Previously completed key to read.
        key: KeyId,
        /// Absolute starting byte offset within that key.
        offset: u64,
        /// Current key bytes to compare against the equally long stored range.
        bytes: &'a [u8],
    },
    /// Append all offered bytes at the current key's acknowledged length.
    /// A driver may divide the fragment into smaller I/O windows. It completes
    /// this effect only when every offered byte has been accepted.
    Append {
        /// Current key being built.
        key: KeyId,
        /// Expected key length before this append.
        offset: u64,
        /// Borrowed fragment, independent of the cumulative key size.
        bytes: &'a [u8],
    },
    /// Release a key that no longer participates in validation.
    Release {
        /// Identity to release before accepting the triggering event.
        key: KeyId,
    },
}

/// Successful completion of the one currently pending workspace operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyCompletion {
    /// Creation, complete append, or release succeeded.
    Done,
    /// The stored range's lexicographic order relative to the offered bytes.
    Compared(Ordering),
}

/// Progress while accepting one borrowed event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationStep<'a> {
    /// Execute this effect and return its completion on the next advance.
    Effect(KeyEffect<'a>),
    /// The event and all of its workspace effects have been accepted.
    Accepted,
}

/// A terminal semantic or validation-protocol failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ValidationError {
    /// An event is not a valid field or value in the current record.
    #[error("unexpected value event in {context:?}")]
    UnexpectedEvent {
        /// The enclosing record, or `None` outside the document.
        context: Option<Kind>,
    },
    /// An end event does not match its open record.
    #[error("expected end of {expected:?}, received end of {actual:?}")]
    MismatchedEnd {
        /// Currently open record.
        expected: Kind,
        /// Received end marker.
        actual: Kind,
    },
    /// A required field or map value is missing at the end of a record.
    #[error("incomplete {kind:?} record")]
    IncompleteRecord {
        /// Record missing one or more required fields.
        kind: Kind,
    },
    /// EOF arrived without exactly one complete document.
    #[error("value document is incomplete")]
    IncompleteDocument,
    /// A text field contains invalid or unfinished UTF-8.
    #[error("value text is not valid UTF-8")]
    Utf8,
    /// A structured path component violates the shared path identifier rules.
    #[error("invalid structured path identifier")]
    Path,
    /// Map keys are not strictly increasing in UTF-8 byte order.
    #[error("map keys must be unique and strictly increasing by UTF-8 bytes")]
    MapKeyOrder,
    /// A logical field's byte length cannot be represented by `u64`.
    #[error("value field length exceeds u64")]
    LengthOverflow,
    /// No fresh workspace identity remains in the document's `u64` namespace.
    #[error("map-key workspace identities are exhausted")]
    KeyExhausted,
    /// Opening another record exceeds an explicitly configured frame budget.
    #[error("value validator exceeds its frame budget of {limit}")]
    FrameBudget {
        /// Maximum simultaneously open records, including the document.
        limit: usize,
    },
    /// The frame stack could not grow.
    #[error("cannot allocate value validator frames: {0}")]
    Allocation(#[from] TryReserveError),
    /// A completion was missing, unexpected, replayed, or of the wrong kind.
    #[error("completion does not match the pending value validation effect")]
    WrongCompletion,
    /// An event transaction was dropped before reaching `Accepted`.
    #[error("value validation was abandoned before accepting its event")]
    Abandoned,
}

#[derive(Debug)]
enum DocumentState {
    Awaiting,
    Open,
    Complete,
}

/// Pure, incremental validation of exactly one value document.
///
/// The validator owns only nonrecursive semantic frames and scoped key
/// identities. Every variable-size field is validated across borrowed chunks;
/// UTF-8 retains at most three incomplete bytes. Exact map-key comparison uses
/// explicit workspace effects, so this type has no I/O, async or scheduler.
///
/// The workspace driver owns all key resources. On any failure or abandoned
/// transaction it must close that workspace, including unfinished operations;
/// no release effects are emitted after a terminal failure. Successful record
/// endings release keys before acknowledging their events.
pub struct Validator {
    frames: Vec<Frame>,
    max_frames: Option<usize>,
    next_key: Option<u64>,
    document: DocumentState,
    failure: Option<ValidationError>,
}

impl fmt::Debug for Validator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Validator")
            .field("open_frames", &self.frames.len())
            .field("max_frames", &self.max_frames)
            .field("document", &self.document)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl Validator {
    /// Construct an empty validator without preallocating frames or keys.
    ///
    /// `max_frames` limits simultaneously open records, not document bytes,
    /// field lengths, or item counts. `None` allows checked stack growth without
    /// a fixed depth limit; zero rejects the opening document event.
    pub const fn new(max_frames: Option<usize>) -> Self {
        Self {
            frames: Vec::new(),
            max_frames,
            next_key: Some(0),
            document: DocumentState::Awaiting,
            failure: None,
        }
    }

    /// Borrow the validator exclusively for one event and its workspace effects.
    /// Semantic checking starts on the transaction's first `advance(None)`.
    /// Dropping the transaction before `Accepted` permanently closes validation.
    pub fn begin<'v, 'e>(
        &'v mut self,
        event: Event<'e>,
    ) -> Result<Validation<'v, 'e>, ValidationError> {
        self.check()?;
        if matches!(self.document, DocumentState::Complete) {
            return Err(self.fail(ValidationError::UnexpectedEvent { context: None }));
        }
        Ok(Validation {
            validator: self,
            event,
            progress: Progress::Fresh,
        })
    }

    /// Confirm real EOF after exactly one completely accepted document.
    /// This checks semantic completion only, not transport completion or authority.
    /// An incomplete EOF is terminal and cannot be resumed with more events.
    pub fn finish(&mut self) -> Result<(), ValidationError> {
        self.check()?;
        if !matches!(self.document, DocumentState::Complete) {
            return Err(self.fail(ValidationError::IncompleteDocument));
        }
        self.frames = Vec::new();
        Ok(())
    }

    fn check(&self) -> Result<(), ValidationError> {
        match &self.failure {
            Some(error) => Err(error.clone()),
            None => Ok(()),
        }
    }

    fn fail(&mut self, error: ValidationError) -> ValidationError {
        if let Some(error) = &self.failure {
            return error.clone();
        }
        self.frames = Vec::new();
        self.failure = Some(error.clone());
        error
    }

    fn push(&mut self, frame: Frame) -> Result<(), ValidationError> {
        if let Some(limit) = self.max_frames
            && self.frames.len() >= limit
        {
            return Err(ValidationError::FrameBudget { limit });
        }
        if self.frames.len() == self.frames.capacity() {
            let target = self.frames.capacity().saturating_mul(2).max(4);
            let target = self.max_frames.map_or(target, |limit| target.min(limit));
            self.frames.try_reserve_exact(target - self.frames.len())?;
        }
        self.frames.push(frame);
        Ok(())
    }

    fn key_id(&mut self) -> Result<KeyId, ValidationError> {
        let id = self.next_key.ok_or(ValidationError::KeyExhausted)?;
        self.next_key = id.checked_add(1);
        Ok(KeyId(id))
    }
}

#[derive(Clone, Copy, Debug)]
enum Pending {
    Create,
    Compare { next_length: u64 },
    Append { next_length: u64 },
    Release,
}

#[derive(Debug)]
enum Progress {
    Fresh,
    Pending(Pending),
    Accepted,
    Failed,
}

/// Exclusive transaction accepting one event without copying its fragments.
///
/// Call `advance(None)` once. For each returned effect, execute it and call
/// `advance(Some(completion))` exactly once. Do not advance after `Accepted`.
/// Storage errors are handled by dropping this transaction and its workspace
/// owner; the pure validator does not reinterpret or retry storage failures.
#[must_use = "drive the event to Accepted or drop it to close validation"]
pub struct Validation<'v, 'e> {
    validator: &'v mut Validator,
    event: Event<'e>,
    progress: Progress,
}

impl fmt::Debug for Validation<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Validation")
            .field("progress", &self.progress)
            .finish_non_exhaustive()
    }
}

impl<'e> Validation<'_, 'e> {
    /// Advance after exactly the completion requested by the preceding step.
    /// Missing or mismatched completions, extra completions, and replay after
    /// acceptance are terminal protocol errors. Input remains borrowed until
    /// acceptance, so an asynchronous driver can apply normal backpressure.
    pub fn advance(
        &mut self,
        completion: Option<KeyCompletion>,
    ) -> Result<ValidationStep<'e>, ValidationError> {
        self.validator.check()?;
        let progress = core::mem::replace(&mut self.progress, Progress::Failed);
        let result = match (progress, completion) {
            (Progress::Fresh, None) => self.start(),
            (Progress::Pending(pending), Some(completion)) => self.complete(pending, completion),
            _ => Err(ValidationError::WrongCompletion),
        };
        match result {
            Ok(step) => Ok(step),
            Err(error) => Err(self.validator.fail(error)),
        }
    }

    fn accepted(&mut self) -> ValidationStep<'e> {
        self.progress = Progress::Accepted;
        ValidationStep::Accepted
    }

    fn effect(&mut self, effect: KeyEffect<'e>, pending: Pending) -> ValidationStep<'e> {
        self.progress = Progress::Pending(pending);
        ValidationStep::Effect(effect)
    }

    fn start(&mut self) -> Result<ValidationStep<'e>, ValidationError> {
        match self.event {
            Event::Begin(kind) => self.begin_record(kind),
            Event::End(kind) => self.end_record(kind),
            Event::Data(bytes) => self.data(bytes),
            Event::Atom(atom) => {
                self.validator
                    .frames
                    .last_mut()
                    .ok_or(ValidationError::UnexpectedEvent { context: None })?
                    .atom(atom)?;
                Ok(self.accepted())
            }
        }
    }

    fn begin_record(&mut self, kind: Kind) -> Result<ValidationStep<'e>, ValidationError> {
        if matches!(self.validator.document, DocumentState::Awaiting) {
            if kind != Kind::Document {
                return Err(ValidationError::UnexpectedEvent { context: None });
            }
            self.validator.push(Frame::new(kind, None))?;
            self.validator.document = DocumentState::Open;
            return Ok(self.accepted());
        }
        let parent = self
            .validator
            .frames
            .last_mut()
            .ok_or(ValidationError::UnexpectedEvent { context: None })?;
        let identifier = parent.begin(kind)?;
        if kind == Kind::Key {
            let previous = match parent {
                Frame::Map { previous, .. } => *previous,
                _ => return Err(ValidationError::UnexpectedEvent { context: None }),
            };
            let id = self.validator.key_id()?;
            self.validator.push(Frame::Key(KeyFrame {
                current: Key { id, length: 0 },
                previous,
                order: Ordering::Equal,
                utf8: utf8::Utf8::default(),
            }))?;
            return Ok(self.effect(KeyEffect::Create { key: id }, Pending::Create));
        }
        self.validator.push(Frame::new(kind, identifier))?;
        Ok(self.accepted())
    }

    fn end_record(&mut self, kind: Kind) -> Result<ValidationStep<'e>, ValidationError> {
        let frame = self
            .validator
            .frames
            .last()
            .ok_or(ValidationError::UnexpectedEvent { context: None })?;
        if frame.kind() != kind {
            return Err(ValidationError::MismatchedEnd {
                expected: frame.kind(),
                actual: kind,
            });
        }
        frame.finish()?;
        let frame = self
            .validator
            .frames
            .pop()
            .ok_or(ValidationError::UnexpectedEvent { context: None })?;
        let release = match frame {
            Frame::Key(key) => {
                let Some(Frame::Map { previous, .. }) = self.validator.frames.last_mut() else {
                    return Err(ValidationError::UnexpectedEvent { context: None });
                };
                previous.replace(key.current)
            }
            Frame::Map { previous, .. } => previous,
            _ => None,
        };
        if kind == Kind::Document {
            self.validator.document = DocumentState::Complete;
        }
        match release {
            Some(key) => Ok(self.effect(KeyEffect::Release { key: key.id }, Pending::Release)),
            None => Ok(self.accepted()),
        }
    }

    fn data(&mut self, bytes: &'e [u8]) -> Result<ValidationStep<'e>, ValidationError> {
        let frame = self
            .validator
            .frames
            .last_mut()
            .ok_or(ValidationError::UnexpectedEvent { context: None })?;
        match frame {
            Frame::Field {
                length,
                utf8,
                identifier,
                ..
            } => {
                let next = next_length(*length, bytes.len())?;
                if let Some(utf8) = utf8 {
                    utf8.push(bytes)?;
                }
                if let Some(identifier) = identifier {
                    identifier
                        .push(bytes)
                        .map_err(|_error| ValidationError::Path)?;
                }
                *length = next;
                Ok(self.accepted())
            }
            Frame::Key(key) => {
                let next = next_length(key.current.length, bytes.len())?;
                key.utf8.push(bytes)?;
                if bytes.is_empty() {
                    return Ok(self.accepted());
                }
                if key.order == Ordering::Equal
                    && let Some(previous) = key.previous
                {
                    let remaining = previous.length.saturating_sub(key.current.length);
                    let common = usize::try_from(remaining)
                        .unwrap_or(usize::MAX)
                        .min(bytes.len());
                    if common > 0 {
                        let effect = KeyEffect::ComparePrefix {
                            key: previous.id,
                            offset: key.current.length,
                            bytes: &bytes[..common],
                        };
                        return Ok(self.effect(effect, Pending::Compare { next_length: next }));
                    }
                    key.order = Ordering::Less;
                }
                self.append(next)
            }
            frame => Err(ValidationError::UnexpectedEvent {
                context: Some(frame.kind()),
            }),
        }
    }

    fn append(&mut self, next_length: u64) -> Result<ValidationStep<'e>, ValidationError> {
        let Some(Frame::Key(key)) = self.validator.frames.last() else {
            return Err(ValidationError::WrongCompletion);
        };
        let Event::Data(bytes) = self.event else {
            return Err(ValidationError::WrongCompletion);
        };
        let effect = KeyEffect::Append {
            key: key.current.id,
            offset: key.current.length,
            bytes,
        };
        Ok(self.effect(effect, Pending::Append { next_length }))
    }

    fn complete(
        &mut self,
        pending: Pending,
        completion: KeyCompletion,
    ) -> Result<ValidationStep<'e>, ValidationError> {
        match (pending, completion) {
            (Pending::Create | Pending::Release, KeyCompletion::Done) => Ok(self.accepted()),
            (Pending::Append { next_length }, KeyCompletion::Done) => {
                let Some(Frame::Key(key)) = self.validator.frames.last_mut() else {
                    return Err(ValidationError::WrongCompletion);
                };
                key.current.length = next_length;
                Ok(self.accepted())
            }
            (Pending::Compare { next_length }, KeyCompletion::Compared(order)) => {
                if order == Ordering::Greater {
                    return Err(ValidationError::MapKeyOrder);
                }
                let Some(Frame::Key(key)) = self.validator.frames.last_mut() else {
                    return Err(ValidationError::WrongCompletion);
                };
                key.order = if order == Ordering::Equal
                    && key
                        .previous
                        .is_some_and(|previous| previous.length < next_length)
                {
                    Ordering::Less
                } else {
                    order
                };
                self.append(next_length)
            }
            _ => Err(ValidationError::WrongCompletion),
        }
    }
}

impl Drop for Validation<'_, '_> {
    fn drop(&mut self) {
        if !matches!(self.progress, Progress::Accepted) {
            self.validator.fail(ValidationError::Abandoned);
        }
    }
}

fn next_length(length: u64, offered: usize) -> Result<u64, ValidationError> {
    let offered = u64::try_from(offered).map_err(|_error| ValidationError::LengthOverflow)?;
    length
        .checked_add(offered)
        .ok_or(ValidationError::LengthOverflow)
}

#[cfg(test)]
mod tests;
