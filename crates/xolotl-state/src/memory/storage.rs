//! Lock topology and bounded snapshots of current values.
//! Mutation, history, and delivery policy live in `memory`.
//! Every operation needing both locks takes the journal before a value shard.

use super::{Journal, MemoryState};
use crate::{
    StateCursor, StateError, StateFailure, StatePage, StateResult, StateRowTooLarge, StateScan,
    TaintedValue,
};
use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::collections::{BTreeMap, hash_map::RandomState};
use std::hash::BuildHasher;
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use xolotl_types::Path;

type Values = BTreeMap<Path, TaintedValue>;

// Separate hot lock words, including adjacent-line prefetch on common hosts.
#[repr(align(128))]
struct Shard(RwLock<Values>);

pub(super) struct Sharded {
    journal: RwLock<Journal>,
    shards: Box<[Shard]>,
    hasher: RandomState,
}

impl Sharded {
    fn shard(&self, path: &Path) -> &RwLock<Values> {
        &self.shards[self.hasher.hash_one(path) as usize % self.shards.len()].0
    }
}

pub(super) enum Storage {
    Compact(RwLock<MemoryState>),
    Sharded(Sharded),
}

impl Default for Storage {
    fn default() -> Self {
        Self::Compact(RwLock::new(MemoryState::default()))
    }
}

impl Storage {
    pub(super) fn new(count: NonZeroUsize) -> StateResult<Self> {
        if count == NonZeroUsize::MIN {
            return Ok(Self::default());
        }
        let mut shards = Vec::new();
        shards.try_reserve_exact(count.get()).map_err(|error| {
            StateError::Backend(format!(
                "cannot allocate {} state read shards: {error}",
                count
            ))
        })?;
        shards.resize_with(count.get(), || Shard(RwLock::new(BTreeMap::new())));
        Ok(Self::Sharded(Sharded {
            journal: RwLock::new(Journal::default()),
            shards: shards.into_boxed_slice(),
            hasher: RandomState::new(),
        }))
    }

    pub(super) fn get(&self, path: &Path) -> Option<TaintedValue> {
        match self {
            Self::Compact(state) => state.read().values.get(path).cloned(),
            Self::Sharded(state) => state.shard(path).read().get(path).cloned(),
        }
    }

    pub(super) fn query(&self, query: &StateScan) -> StateResult<StatePage> {
        use std::ops::Bound;
        let after = query
            .cursor
            .as_ref()
            .map(|cursor| {
                std::str::from_utf8(&cursor.0)
                    .map_err(|error| crate::query::invalid_cursor(error.to_string()))
                    .and_then(|key| {
                        Path::parse(key)
                            .map_err(|error| crate::query::invalid_cursor(error.to_string()))
                    })
            })
            .transpose()?;
        if after
            .as_ref()
            .is_some_and(|path| path != &query.prefix && !query.prefix.is_prefix_of(path))
        {
            return Err(crate::query::invalid_cursor("cursor is outside the prefix"));
        }
        let from = after
            .as_ref()
            .map_or(Bound::Included(&query.prefix), Bound::Excluded);
        match self {
            Self::Compact(state) => {
                collect_page(state.read().values.range((from, Bound::Unbounded)), query)
            }
            Self::Sharded(state) => {
                let _journal = state.journal.read();
                let guards = state
                    .shards
                    .iter()
                    .map(|shard| shard.0.read())
                    .collect::<Vec<_>>();
                let mut ranges = guards
                    .iter()
                    .map(|values| values.range((from, Bound::Unbounded)).peekable())
                    .collect::<Vec<_>>();
                let rows = std::iter::from_fn(|| {
                    let index = ranges
                        .iter_mut()
                        .enumerate()
                        .filter_map(|(index, range)| {
                            range.peek().map(|(path, _value)| (index, *path))
                        })
                        .min_by(|(_, a), (_, b)| a.cmp(b))
                        .map(|(index, _path)| index)?;
                    ranges[index].next()
                });
                collect_page(rows, query)
            }
        }
    }

    pub(super) fn read(&self) -> JournalRead<'_> {
        match self {
            Self::Compact(state) => JournalRead::Compact(state.read()),
            Self::Sharded(state) => JournalRead::Sharded(state.journal.read()),
        }
    }

    pub(super) fn write(&self) -> JournalWrite<'_> {
        match self {
            Self::Compact(state) => JournalWrite::Compact(state.write()),
            Self::Sharded(state) => JournalWrite::Sharded(state.journal.write()),
        }
    }

    pub(super) fn write_path(&self, path: &Path) -> CommitGuard<'_> {
        match self {
            Self::Compact(state) => CommitGuard::Compact(state.write()),
            Self::Sharded(state) => {
                let shard = state.shard(path);
                let journal = state.journal.write();
                let values = shard.write();
                CommitGuard::Sharded { values, journal }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn is_unlocked(&self) -> bool {
        match self {
            Self::Compact(state) => state.try_write().is_some(),
            Self::Sharded(state) => {
                let Some(_journal) = state.journal.try_write() else {
                    return false;
                };
                state
                    .shards
                    .iter()
                    .all(|shard| shard.0.try_write().is_some())
            }
        }
    }
}

fn collect_page<'a>(
    mut rows: impl Iterator<Item = (&'a Path, &'a TaintedValue)>,
    query: &StateScan,
) -> StateResult<StatePage> {
    let mut page = StatePage::empty();
    let mut previous = query.cursor.clone();
    loop {
        if page.entries.len() == query.limits.entries.get()
            || page.examined == query.limits.examined.get()
        {
            page.next = previous;
            return Ok(page);
        }
        let Some((path, value)) = rows.next() else {
            break;
        };
        if path != &query.prefix && !query.prefix.is_prefix_of(path) {
            break;
        }
        page.examined += 1;
        page.taint.union(&value.taint);
        let key = path.to_string();
        let bytes = crate::host::encoded_size(value)
            .map_err(|failure| failure.with_taint(&page.taint))?
            .checked_add(key.len())
            .ok_or_else(|| {
                StateFailure::new(
                    StateError::Backend("state record size overflow".into()),
                    page.taint.clone(),
                )
            })?;
        let cursor = StateCursor(key.into_bytes());
        if bytes > query.limits.encoded_bytes.get() - page.encoded_bytes {
            if page.entries.is_empty() {
                return Err(StateFailure::new(
                    StateError::RowTooLarge(Box::new(StateRowTooLarge {
                        path: path.clone(),
                        encoded_bytes: bytes,
                        retry: previous,
                        resume: cursor,
                    })),
                    page.taint,
                ));
            }
            page.next = previous;
            return Ok(page);
        }
        page.entries.push((path.clone(), value.clone()));
        page.encoded_bytes += bytes;
        previous = Some(cursor);
    }
    Ok(page)
}

pub(super) enum JournalRead<'a> {
    Compact(RwLockReadGuard<'a, MemoryState>),
    Sharded(RwLockReadGuard<'a, Journal>),
}

impl Deref for JournalRead<'_> {
    type Target = Journal;

    fn deref(&self) -> &Journal {
        match self {
            Self::Compact(state) => &state.journal,
            Self::Sharded(journal) => journal,
        }
    }
}

pub(super) enum JournalWrite<'a> {
    Compact(RwLockWriteGuard<'a, MemoryState>),
    Sharded(RwLockWriteGuard<'a, Journal>),
}

impl Deref for JournalWrite<'_> {
    type Target = Journal;

    fn deref(&self) -> &Journal {
        match self {
            Self::Compact(state) => &state.journal,
            Self::Sharded(journal) => journal,
        }
    }
}

impl DerefMut for JournalWrite<'_> {
    fn deref_mut(&mut self) -> &mut Journal {
        match self {
            Self::Compact(state) => &mut state.journal,
            Self::Sharded(journal) => journal,
        }
    }
}

pub(super) enum CommitGuard<'a> {
    Compact(RwLockWriteGuard<'a, MemoryState>),
    Sharded {
        // Declaration order releases values before the journal on every exit path.
        values: RwLockWriteGuard<'a, Values>,
        journal: RwLockWriteGuard<'a, Journal>,
    },
}

impl CommitGuard<'_> {
    pub(super) fn parts_mut(&mut self) -> (&mut Values, &mut Journal) {
        match self {
            Self::Compact(state) => {
                let MemoryState { values, journal } = &mut **state;
                (values, journal)
            }
            Self::Sharded { values, journal } => (values, journal),
        }
    }
}

impl Deref for CommitGuard<'_> {
    type Target = Journal;

    fn deref(&self) -> &Journal {
        match self {
            Self::Compact(state) => &state.journal,
            Self::Sharded { journal, .. } => journal,
        }
    }
}

#[cfg(test)]
mod tests;
