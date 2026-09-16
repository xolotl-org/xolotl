use super::BuilderError;
use crate::value::event::{KeyCompletion, KeyEffect, KeyId};
use alloc::{collections::BTreeMap, string::String, vec::Vec};

/// The builder explicitly owns resident keys. It never assumes codec windows
/// are large enough to hold a whole key or compare a complete key at once.
#[derive(Default)]
pub(super) struct Keys {
    entries: BTreeMap<KeyId, Vec<u8>>,
    created: Option<KeyId>,
}

impl Keys {
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.created.is_none()
    }

    pub(super) fn take_created(&mut self) -> Result<KeyId, BuilderError> {
        self.created
            .take()
            .ok_or(BuilderError::Invariant("new map key"))
    }

    pub(super) fn text(&self, key: KeyId) -> Result<String, BuilderError> {
        let bytes = self
            .entries
            .get(&key)
            .ok_or(BuilderError::Invariant("completed map key"))?;
        let mut owned = Vec::new();
        owned.try_reserve_exact(bytes.len())?;
        owned.extend_from_slice(bytes);
        String::from_utf8(owned).map_err(|_error| BuilderError::Invariant("map key UTF-8"))
    }

    pub(super) fn complete(
        &mut self,
        effect: KeyEffect<'_>,
    ) -> Result<KeyCompletion, BuilderError> {
        match effect {
            KeyEffect::Create { key } => {
                if self.created.replace(key).is_some()
                    || self.entries.insert(key, Vec::new()).is_some()
                {
                    return Err(BuilderError::Invariant("fresh map key"));
                }
            }
            KeyEffect::ComparePrefix { key, offset, bytes } => {
                let stored = self
                    .entries
                    .get(&key)
                    .ok_or(BuilderError::Invariant("previous map key"))?;
                let start = usize::try_from(offset)
                    .map_err(|_error| BuilderError::Invariant("map key offset"))?;
                let end = start
                    .checked_add(bytes.len())
                    .ok_or(BuilderError::Invariant("map key range"))?;
                let prefix = stored
                    .get(start..end)
                    .ok_or(BuilderError::Invariant("stored map key range"))?;
                return Ok(KeyCompletion::Compared(prefix.cmp(bytes)));
            }
            KeyEffect::Append { key, offset, bytes } => {
                let stored = self
                    .entries
                    .get_mut(&key)
                    .ok_or(BuilderError::Invariant("current map key"))?;
                if u64::try_from(stored.len()).ok() != Some(offset) {
                    return Err(BuilderError::Invariant("map key append offset"));
                }
                stored.try_reserve(bytes.len())?;
                stored.extend_from_slice(bytes);
            }
            KeyEffect::Release { key } => {
                if self.entries.remove(&key).is_none() {
                    return Err(BuilderError::Invariant("released map key"));
                }
            }
        }
        Ok(KeyCompletion::Done)
    }
}
