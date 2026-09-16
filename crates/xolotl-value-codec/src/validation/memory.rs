use alloc::{collections::BTreeMap, collections::TryReserveError, vec::Vec};
use core::{cmp::Ordering, future::Ready, future::ready, num::NonZeroUsize};
use thiserror::Error;
use xolotl_types::value::event::KeyId;

use super::KeyStore;

/// Resident workspace policy, independent of cumulative document size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryKeyOptions {
    /// Each key-data page reserves this many bytes. Existing key bytes are never
    /// copied to grow a page; only the page directory may grow.
    pub page_bytes: NonZeroUsize,
    /// Optional number of simultaneously active key identities.
    pub max_keys: Option<usize>,
    /// Optional total reserved key-data bytes, including unused page tails.
    /// Directory/map metadata is additional O(active keys + pages), and follows
    /// the platform allocator. This is not a whole-process memory bound.
    pub max_bytes: Option<usize>,
}

/// A resident workspace cannot satisfy an operation.
#[derive(Debug, Error)]
pub enum MemoryKeyError {
    /// A key does not exist or creation tried to reuse an active identity.
    #[error("unknown or reused map-key identity {0}")]
    Identity(u64),
    /// An append or comparison used an invalid offset.
    #[error("invalid map-key offset {0}")]
    Offset(u64),
    /// A resident length or page calculation cannot be represented.
    #[error("map-key resident length overflow")]
    LengthOverflow,
    /// The caller's active-key budget is exhausted.
    #[error("map-key count exceeds budget {0}")]
    KeyBudget(usize),
    /// The caller's resident key-data budget is exhausted.
    #[error("map-key pages exceed resident byte budget {0}")]
    ByteBudget(usize),
    /// Key data or its page directory could not be allocated.
    #[error("cannot allocate map-key pages: {0}")]
    Allocation(#[from] TryReserveError),
}

#[derive(Default)]
struct Key {
    pages: Vec<Vec<u8>>,
    length: usize,
}

/// Synchronous paged key storage usable with any executor, including no executor.
///
/// Lookups retain only active identities. Prefix comparisons index the page
/// directory directly, so fragmented keys do not repeatedly scan all preceding
/// chunks. Releasing a key immediately frees its pages. Keys larger than the
/// selected resident budget require an external [`KeyStore`] instead.
pub struct MemoryKeyStore {
    options: MemoryKeyOptions,
    keys: BTreeMap<KeyId, Key>,
    reserved_bytes: usize,
}

impl MemoryKeyStore {
    /// Start an empty workspace without allocating key data.
    pub const fn new(options: MemoryKeyOptions) -> Self {
        Self {
            options,
            keys: BTreeMap::new(),
            reserved_bytes: 0,
        }
    }

    /// Number of currently retained identities, including unfinished keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Reserved key-data bytes, including each page's unused tail.
    pub const fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    fn create_inner(&mut self, key: KeyId) -> Result<(), MemoryKeyError> {
        if self.keys.contains_key(&key) {
            return Err(MemoryKeyError::Identity(key.get()));
        }
        if let Some(limit) = self.options.max_keys
            && self.keys.len() >= limit
        {
            return Err(MemoryKeyError::KeyBudget(limit));
        }
        self.keys.insert(key, Key::default());
        Ok(())
    }

    fn compare_inner(
        &self,
        key: KeyId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<Ordering, MemoryKeyError> {
        let key = self
            .keys
            .get(&key)
            .ok_or(MemoryKeyError::Identity(key.get()))?;
        let start = usize::try_from(offset).map_err(|_error| MemoryKeyError::Offset(offset))?;
        if start > key.length {
            return Err(MemoryKeyError::Offset(offset));
        }
        let count = bytes.len().min(key.length - start);
        let page_bytes = self.options.page_bytes.get();
        let mut compared = 0;
        while compared < count {
            let position = start + compared;
            let in_page = position % page_bytes;
            let window = (page_bytes - in_page).min(count - compared);
            let stored = &key.pages[position / page_bytes][in_page..in_page + window];
            let order = stored.cmp(&bytes[compared..compared + window]);
            if order != Ordering::Equal {
                return Ok(order);
            }
            compared += window;
        }
        Ok(count.cmp(&bytes.len()))
    }

    fn append_inner(
        &mut self,
        identity: KeyId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryKeyError> {
        let key = self
            .keys
            .get_mut(&identity)
            .ok_or(MemoryKeyError::Identity(identity.get()))?;
        if u64::try_from(key.length).map_err(|_error| MemoryKeyError::LengthOverflow)? != offset {
            return Err(MemoryKeyError::Offset(offset));
        }
        let end = key
            .length
            .checked_add(bytes.len())
            .ok_or(MemoryKeyError::LengthOverflow)?;
        let page_bytes = self.options.page_bytes.get();
        let total_pages = end.div_ceil(page_bytes);
        // An earlier failed allocation can leave reserved pages beyond the
        // acknowledged length. Reuse them if a direct caller retries with a
        // smaller fragment; the EventValidator itself closes on any error.
        let new_pages = total_pages.saturating_sub(key.pages.len());
        let projected = new_pages
            .checked_mul(page_bytes)
            .and_then(|bytes| self.reserved_bytes.checked_add(bytes))
            .ok_or(MemoryKeyError::LengthOverflow)?;
        if let Some(limit) = self.options.max_bytes
            && projected > limit
        {
            return Err(MemoryKeyError::ByteBudget(limit));
        }
        key.pages.try_reserve(new_pages)?;
        for _ in 0..new_pages {
            let mut page = Vec::new();
            page.try_reserve_exact(page_bytes)?;
            let reserved = self
                .reserved_bytes
                .checked_add(page.capacity())
                .ok_or(MemoryKeyError::LengthOverflow)?;
            if let Some(limit) = self.options.max_bytes
                && reserved > limit
            {
                return Err(MemoryKeyError::ByteBudget(limit));
            }
            page.resize(page_bytes, 0);
            key.pages.push(page);
            self.reserved_bytes = reserved;
        }
        let mut copied = 0;
        while copied < bytes.len() {
            let position = key.length + copied;
            let in_page = position % page_bytes;
            let window = (page_bytes - in_page).min(bytes.len() - copied);
            key.pages[position / page_bytes][in_page..in_page + window]
                .copy_from_slice(&bytes[copied..copied + window]);
            copied += window;
        }
        key.length = end;
        Ok(())
    }

    fn release_inner(&mut self, key: KeyId) -> Result<(), MemoryKeyError> {
        let key = self
            .keys
            .remove(&key)
            .ok_or(MemoryKeyError::Identity(key.get()))?;
        for page in &key.pages {
            self.reserved_bytes -= page.capacity();
        }
        Ok(())
    }
}

impl KeyStore for MemoryKeyStore {
    type Error = MemoryKeyError;
    type Create<'a> = Ready<Result<(), Self::Error>>;
    type ComparePrefix<'a> = Ready<Result<Ordering, Self::Error>>;
    type Append<'a> = Ready<Result<(), Self::Error>>;
    type Release<'a> = Ready<Result<(), Self::Error>>;

    fn create(&mut self, key: KeyId) -> Self::Create<'_> {
        ready(self.create_inner(key))
    }

    fn compare_prefix<'a>(
        &'a mut self,
        key: KeyId,
        offset: u64,
        bytes: &'a [u8],
    ) -> Self::ComparePrefix<'a> {
        ready(self.compare_inner(key, offset, bytes))
    }

    fn append<'a>(&'a mut self, key: KeyId, offset: u64, bytes: &'a [u8]) -> Self::Append<'a> {
        ready(self.append_inner(key, offset, bytes))
    }

    fn release(&mut self, key: KeyId) -> Self::Release<'_> {
        ready(self.release_inner(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};

    #[test]
    fn shorter_append_reuses_pages_reserved_before_a_failed_growth() -> anyhow::Result<()> {
        let id = super::super::tests::key_ids(1)?[0];
        let mut store = MemoryKeyStore::new(MemoryKeyOptions {
            page_bytes: NonZeroUsize::new(4).context("test page size")?,
            max_keys: Some(1),
            max_bytes: Some(12),
        });
        store.create_inner(id)?;
        store.append_inner(id, 0, b"a")?;
        // Reproduce the state after one additional page was allocated but a
        // later page allocation failed, before any new bytes were acknowledged.
        // This avoids forcing a process-wide allocator failure in a unit test.
        let extra_page = alloc::vec![0; 4];
        store.reserved_bytes += extra_page.capacity();
        store
            .keys
            .get_mut(&id)
            .context("created key")?
            .pages
            .push(extra_page);
        let reserved = store.reserved_bytes();
        store.append_inner(id, 1, b"b")?;
        ensure!(store.reserved_bytes() == reserved);
        ensure!(store.compare_inner(id, 0, b"ab")? == Ordering::Equal);
        ensure!(store.compare_inner(id, 0, b"abx")? == Ordering::Less);
        store.append_inner(id, 2, b"cdefgh")?;
        ensure!(store.reserved_bytes() == reserved);
        ensure!(store.compare_inner(id, 0, b"abcdefgh")? == Ordering::Equal);
        store.release_inner(id)?;
        ensure!(store.reserved_bytes() == 0 && store.key_count() == 0);
        Ok(())
    }
}
