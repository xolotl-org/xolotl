//! Explicit resident materialization of one validated event document.

use super::{Event, ValidationError, ValidationStep, Validator};
use crate::{CollectionError, TaintSet, TaintedValue, Value};
use alloc::{collections::TryReserveError, vec::Vec};
use core::fmt;
use thiserror::Error;

mod admission;
mod frame;
mod keys;
use admission::Admission;
pub use admission::{MaterializationDimension, MaterializationLimits};
use frame::{Field, Frame};
use keys::Keys;

/// A terminal failure while explicitly building a resident value.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BuilderError {
    /// The event document violated the shared lossless grammar.
    #[error(transparent)]
    Validation(#[from] ValidationError),
    /// A caller-selected materialization admission budget was exhausted.
    #[error("resident materialization exceeds its {dimension} budget of {limit}")]
    Admission {
        /// The logical dimension whose admission failed.
        dimension: MaterializationDimension,
        /// Maximum admitted units in that dimension.
        limit: u64,
    },
    /// A resident collection rejected member ordering or its resulting count.
    #[error(transparent)]
    Collection(#[from] CollectionError),
    /// A growable construction buffer could not be allocated.
    #[error("cannot allocate resident value construction storage: {0}")]
    Allocation(#[from] TryReserveError),
    /// The builder and its validator disagreed about an accepted event.
    #[error("resident value builder lost validated {0} state")]
    Invariant(&'static str),
}

/// Materialize exactly one complete lossless event document in resident memory.
///
/// This is an explicit alternative to a streaming consumer. It retains the
/// complete value, recorded provenance and unfinished fields. It therefore
/// needs storage proportional to that resident representation. Referenced blob
/// content is not loaded. Construction and release use explicit frames rather
/// than recursion, including for deeply nested unfinished collections.
/// Collections use the shared sequential assembler: full member leaves join
/// incrementally, without copying a published update path for each input item.
///
/// [`Self::push`] borrows each event only for the duration of that call and
/// checks it with the shared [`Validator`]. The builder owns that validator's
/// resident map-key workspace. [`Self::finish`] is the only publication point:
/// call it only after the enclosing input has confirmed actual EOF. Receiving
/// `End(Document)` alone does not publish a value or authorize its provenance.
/// Any failure immediately drops partial value payloads, frames and keys;
/// later calls cannot resume or retrieve a partial value. Already completed
/// source claims remain available through [`Self::observed_taint`] as failure
/// evidence, without establishing their authority.
///
/// Defaults impose no cumulative size or depth limit. Explicit
/// [`MaterializationLimits`] are admission policy for this resident operation,
/// not limits on a codec's I/O windows or on tasks using streaming consumers.
/// Fallible buffer growth reports [`BuilderError::Allocation`]; resident Value
/// and collection allocations otherwise use the platform's ordinary allocator.
pub struct ValueBuilder {
    session: Option<Session>,
    observed_taint: TaintSet,
    failure: Option<BuilderError>,
}

impl Default for ValueBuilder {
    fn default() -> Self {
        Self::new(MaterializationLimits::default())
    }
}

impl fmt::Debug for ValueBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValueBuilder")
            .field(
                "open_frames",
                &self.session.as_ref().map(|s| s.frames.len()),
            )
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl ValueBuilder {
    /// Start without allocating payloads, frames, or a map-key workspace.
    pub fn new(limits: MaterializationLimits) -> Self {
        Self {
            session: Some(Session {
                validator: Validator::new(limits.max_frames),
                admission: Admission::new(limits),
                frames: Vec::new(),
                keys: Keys::default(),
                completed: None,
            }),
            observed_taint: TaintSet::pristine(),
            failure: None,
        }
    }

    /// Borrow source claims that have been completely parsed so far.
    ///
    /// Claims retain their recorded order and repetitions. Incomplete source
    /// records are excluded; after failure only previously completed claims
    /// remain. This is the same source storage moved into a successful result,
    /// not a second parser or a copy of the document. Claimed provenance does
    /// not establish trust or grant access to any referenced content.
    pub fn observed_taint(&self) -> &TaintSet {
        &self.observed_taint
    }

    /// Admit, validate and retain one event, without publishing any value.
    ///
    /// Chunk boundaries, including empty chunks and split UTF-8 scalars, do
    /// not affect the represented data or logical admission accounting.
    pub fn push(&mut self, event: Event<'_>) -> Result<(), BuilderError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        let mut session = self
            .session
            .take()
            .ok_or(BuilderError::Invariant("open session"))?;
        match session.push(event, &mut self.observed_taint) {
            Ok(()) => {
                self.session = Some(session);
                Ok(())
            }
            Err(error) => {
                self.failure = Some(error.clone());
                Err(error)
            }
        }
    }

    /// Confirm actual EOF and consume the builder to publish the complete value.
    ///
    /// The caller must first finish transport/framing validation. A claimed
    /// document-end event is insufficient evidence of EOF. Recorded provenance
    /// remains untrusted unless the ingress boundary establishes its authority.
    /// Incomplete EOF consumes and releases all construction state.
    pub fn finish(mut self) -> Result<TaintedValue, BuilderError> {
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        let mut session = self
            .session
            .take()
            .ok_or(BuilderError::Invariant("open session"))?;
        session.validator.finish()?;
        if !session.frames.is_empty() || !session.keys.is_empty() {
            return Err(BuilderError::Invariant("finished document"));
        }
        let value = session
            .completed
            .take()
            .ok_or(BuilderError::Invariant("completed value"))?;
        Ok(TaintedValue::new(value, self.observed_taint))
    }
}

struct Session {
    validator: Validator,
    admission: Admission,
    frames: Vec<Frame>,
    keys: Keys,
    completed: Option<Value>,
}

impl Session {
    fn push(
        &mut self,
        event: Event<'_>,
        observed_taint: &mut TaintSet,
    ) -> Result<(), BuilderError> {
        self.admission.admit(event)?;
        let mut validation = self.validator.begin(event)?;
        let mut completion = None;
        loop {
            match validation.advance(completion)? {
                ValidationStep::Accepted => break,
                ValidationStep::Effect(effect) => {
                    completion = Some(self.keys.complete(effect)?);
                }
            }
        }
        drop(validation);

        match event {
            Event::Begin(kind) => {
                let frame = Frame::new(kind, &mut self.keys)?;
                self.frames.try_reserve(1)?;
                self.frames.push(frame);
                Ok(())
            }
            Event::Data(bytes) => self
                .frames
                .last_mut()
                .ok_or(BuilderError::Invariant("data frame"))?
                .data(bytes),
            Event::Atom(atom) => self.accept(Field::Atom(atom), observed_taint),
            Event::End(_kind) => {
                let frame = self
                    .frames
                    .pop()
                    .ok_or(BuilderError::Invariant("ending frame"))?;
                let field = frame.finish(&self.keys)?;
                self.accept(field, observed_taint)
            }
        }
    }

    fn accept(&mut self, field: Field, observed_taint: &mut TaintSet) -> Result<(), BuilderError> {
        match (self.frames.last_mut(), field) {
            (Some(frame), field) => frame.accept(field, observed_taint),
            (None, Field::Document(document)) if self.completed.is_none() => {
                self.completed = Some(document);
                // A completed document retains only its unpublished result.
                self.frames = Vec::new();
                Ok(())
            }
            _ => Err(BuilderError::Invariant("parent record")),
        }
    }
}

#[cfg(test)]
mod tests;
