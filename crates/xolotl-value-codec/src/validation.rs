//! Async workspace effects for the pure value grammar.

use core::{cmp::Ordering, future::Future};
use xolotl_types::value::event::{
    Event, KeyCompletion, KeyEffect, KeyId, ValidationStep, Validator,
};

use crate::Error;

mod memory;
pub use memory::{MemoryKeyError, MemoryKeyOptions, MemoryKeyStore};

/// Rereadable storage for only the keys currently needed by one validator.
///
/// Keys are scoped to one document. The driver owns the workspace exclusively
/// and drops it after a failure or polled cancellation. Every operation must
/// retain ownership of unfinished work when its future is dropped. Dropping
/// the workspace must reclaim its resources or transfer cleanup to an adapter
/// mechanism that runs without another poll from the abandoned caller.
///
/// Implementations must bound staging independently of total key length and
/// complete release before acknowledging it (or bound any retained cleanup).
/// There is no global `Send`, `Sync`, allocation, or executor requirement.
pub trait KeyStore {
    /// Workspace-specific failure.
    type Error;
    /// Create one empty key.
    type Create<'a>: Future<Output = Result<(), Self::Error>>
    where
        Self: 'a;
    /// Compare a stored prefix with borrowed input.
    type ComparePrefix<'a>: Future<Output = Result<Ordering, Self::Error>>
    where
        Self: 'a;
    /// Append the complete input fragment.
    type Append<'a>: Future<Output = Result<(), Self::Error>>
    where
        Self: 'a;
    /// Reclaim a key no longer used by validation.
    type Release<'a>: Future<Output = Result<(), Self::Error>>
    where
        Self: 'a;

    /// Create an empty key under a fresh identity.
    fn create(&mut self, key: KeyId) -> Self::Create<'_>;

    /// Compare stored bytes at `offset` against at most `bytes.len()` input
    /// bytes, in stored-versus-input order. A stored suffix beyond this range
    /// must not affect the result. A logical key ending within this range sorts
    /// before a longer otherwise equal input; a physical short read inside the
    /// known stored length is an error. The validator requests equally long
    /// common ranges and handles key lengths separately.
    fn compare_prefix<'a>(
        &'a mut self,
        key: KeyId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::ComparePrefix<'a>;

    /// Append every byte at the expected current length. Only acknowledge after
    /// the complete borrowed fragment is stored; split it into windows as needed.
    fn append<'a>(&'a mut self, key: KeyId, offset: u64, bytes: &'a [u8]) -> Self::Append<'a>;

    /// Reclaim this key before accepting more work.
    fn release(&mut self, key: KeyId) -> Self::Release<'_>;
}

struct Session<K> {
    grammar: Validator,
    keys: K,
}

/// Exclusive validation owner for one document and its key workspace.
///
/// Each accepted event includes all awaited workspace effects. A failed or
/// cancelled polled `accept` closes the owner and immediately drops its
/// workspace. Dropping an unpolled future leaves it usable. No async abort is
/// required for cleanup; that responsibility belongs to the selected store.
pub struct EventValidator<K> {
    session: Option<Session<K>>,
}

impl<K: KeyStore> EventValidator<K> {
    /// Start a document with an explicit optional open-record budget.
    pub fn new(keys: K, max_frames: Option<usize>) -> Self {
        Self {
            session: Some(Session {
                grammar: Validator::new(max_frames),
                keys,
            }),
        }
    }

    /// Whether this owner can accept another event or finish its document.
    pub fn is_open(&self) -> bool {
        self.session.is_some()
    }

    /// Validate a borrowed event, applying backpressure through every effect.
    pub async fn accept(&mut self, event: Event<'_>) -> Result<(), Error<K::Error>> {
        // This take runs on the first poll, so cancellation cannot restore a
        // grammar cursor after an operation whose outcome is unknown.
        let mut session = self.session.take().ok_or(Error::Closed)?;
        {
            let mut transaction = session.grammar.begin(event).map_err(Error::Validation)?;
            let mut completion = None;
            loop {
                let effect = match transaction.advance(completion).map_err(Error::Validation)? {
                    ValidationStep::Accepted => break,
                    ValidationStep::Effect(effect) => effect,
                };
                completion = Some(match effect {
                    KeyEffect::Create { key } => {
                        session.keys.create(key).await.map_err(Error::Workspace)?;
                        KeyCompletion::Done
                    }
                    KeyEffect::ComparePrefix { key, offset, bytes } => KeyCompletion::Compared(
                        session
                            .keys
                            .compare_prefix(key, offset, bytes)
                            .await
                            .map_err(Error::Workspace)?,
                    ),
                    KeyEffect::Append { key, offset, bytes } => {
                        session
                            .keys
                            .append(key, offset, bytes)
                            .await
                            .map_err(Error::Workspace)?;
                        KeyCompletion::Done
                    }
                    KeyEffect::Release { key } => {
                        session.keys.release(key).await.map_err(Error::Workspace)?;
                        KeyCompletion::Done
                    }
                });
            }
        }
        self.session = Some(session);
        Ok(())
    }

    /// Confirm actual source EOF and release the workspace.
    ///
    /// A document-end event alone does not establish EOF. An incomplete finish
    /// is terminal, just like a failed or cancelled event.
    pub fn finish(&mut self) -> Result<(), Error<K::Error>> {
        let mut session = self.session.take().ok_or(Error::Closed)?;
        session.grammar.finish().map_err(Error::Validation)
    }
}

#[cfg(test)]
mod tests;
