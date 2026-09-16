//! Sequential assembly shares the published AVL index and its iterative release.
//!
//! A full leaf enters a binary-carry forest. Only equal-height trees merge
//! during ingestion, so every completed leaf and branch is allocated once.
//! The right-to-left final fold joins the remaining O(log n) trees without
//! copying their members. No vector of all leaves or pending members is kept.

use super::{
    CollectionError, ValueList, ValueMap,
    node::{self, Index, LEAF_CAPACITY, Leaf, ListLeaf, MapLeaf},
};
use crate::Value;
use alloc::{string::String, sync::Arc, vec::Vec};
use core::{fmt, mem};

struct Forest<L: Leaf> {
    // Earlier trees are taller; each height occurs at most once.
    trees: Vec<Arc<Index<L>>>,
}

impl<L: Leaf> Forest<L> {
    const fn new() -> Self {
        Self { trees: Vec::new() }
    }

    fn push(&mut self, mut tree: Arc<Index<L>>) {
        while let Some(left) = self.trees.pop() {
            if left.height != tree.height {
                self.trees.push(left);
                break;
            }
            tree = node::join(left, tree);
        }
        self.trees.push(tree);
    }

    fn finish(mut self) -> Option<Arc<Index<L>>> {
        let mut root = self.trees.pop()?;
        while let Some(left) = self.trees.pop() {
            root = node::join(left, root);
        }
        Some(root)
    }
}

struct Assembly<L: Leaf> {
    pending: Vec<L::Member>,
    forest: Forest<L>,
    len: usize,
}

impl<L: Leaf> Assembly<L> {
    const fn new() -> Self {
        Self {
            pending: Vec::new(),
            forest: Forest::new(),
            len: 0,
        }
    }

    fn push(&mut self, member: impl FnOnce() -> L::Member) -> Result<(), CollectionError> {
        let len = self
            .len
            .checked_add(1)
            .ok_or(CollectionError::LengthOverflow)?;
        // Grow only for actual members, never at Begin(List/Map). A deeply
        // nested empty prefix therefore retains no leaf buffers.
        self.pending.push(member());
        self.len = len;
        if self.pending.len() == LEAF_CAPACITY {
            self.flush();
        }
        Ok(())
    }

    fn flush(&mut self) {
        if !self.pending.is_empty() {
            let members = mem::take(&mut self.pending).into_boxed_slice();
            self.forest.push(Index::leaf(L::from_members(members)));
        }
    }

    fn finish(mut self) -> Option<Arc<Index<L>>> {
        self.flush();
        self.forest.finish()
    }
}

/// Assemble one list in O(n) time without copying previously accepted members.
///
/// Construction retains at most 32 pending members and O(log n) index roots
/// beyond the final collection. Creating an empty builder allocates nothing.
/// [`Self::finish`] moves completed leaves into the ordinary [`ValueList`]; it
/// does not copy all members into another resident representation. Nested Values
/// and partial builds use the same iterative release as published collections.
#[derive(Default)]
pub struct ValueListBuilder {
    assembly: Assembly<ListLeaf>,
}

impl ValueListBuilder {
    /// Start without allocating pending members or index storage.
    pub const fn new() -> Self {
        Self {
            assembly: Assembly::new(),
        }
    }

    /// Number of accepted members, including the unfinished leaf.
    pub fn len(&self) -> usize {
        self.assembly.len
    }

    /// Whether no members have been accepted.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Append one member. Length overflow leaves accepted members unchanged.
    /// Allocation uses the platform's ordinary allocator behavior.
    pub fn push(&mut self, value: Value) -> Result<(), CollectionError> {
        self.assembly.push(|| value)
    }

    /// Publish the accepted members without cloning their values or leaf slots.
    pub fn finish(self) -> ValueList {
        ValueList {
            root: self.assembly.finish(),
        }
    }
}

/// Assemble a strictly ordered map without copying earlier member slots.
///
/// Keys must be unique and increasing by UTF-8 bytes. Ordinary unordered map
/// updates remain available through [`ValueMap::insert`]. Temporary storage is
/// one leaf of at most 32 entries plus O(log n) index roots; key bytes already
/// accepted into a leaf are shared with its routing metadata.
#[derive(Default)]
pub struct ValueMapBuilder {
    assembly: Assembly<MapLeaf>,
}

impl ValueMapBuilder {
    /// Start without allocating pending members or index storage.
    pub const fn new() -> Self {
        Self {
            assembly: Assembly::new(),
        }
    }

    /// Number of accepted unique keys, including the unfinished leaf.
    pub fn len(&self) -> usize {
        self.assembly.len
    }

    /// Whether no entries have been accepted.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Borrow the last accepted key without retaining another key allocation.
    pub fn last_key(&self) -> Option<&str> {
        self.assembly
            .pending
            .last()
            .map(|(key, _)| key.as_ref())
            .or_else(|| {
                self.assembly
                    .forest
                    .trees
                    .last()
                    .map(|tree| tree.summary.as_ref())
            })
    }

    /// Append a strictly greater key. Ordering or length errors leave accepted
    /// entries unchanged and release the rejected key and value.
    pub fn append(&mut self, key: String, value: Value) -> Result<(), CollectionError> {
        if self.last_key().is_some_and(|last| last >= key.as_str()) {
            return Err(CollectionError::KeyOrder);
        }
        self.assembly.push(|| (key.into(), value))
    }

    /// Publish the accepted entries without copying their leaf slots or values.
    pub fn finish(self) -> ValueMap {
        ValueMap {
            root: self.assembly.finish(),
        }
    }
}

impl<L: Leaf> Default for Assembly<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ValueListBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValueListBuilder")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ValueMapBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValueMapBuilder")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// Infallible collection conversions consume already-owned members in leaf-sized
/// groups. Like Vec/BTreeMap collection, allocation failure follows the platform;
/// a member index cannot outgrow usize while its nonzero-sized slots are resident.
pub(super) fn collect<L: Leaf>(
    values: impl IntoIterator<Item = L::Member>,
) -> Option<Arc<Index<L>>> {
    let mut values = values.into_iter();
    let mut forest = Forest::new();
    loop {
        let members: Vec<_> = values.by_ref().take(LEAF_CAPACITY).collect();
        if members.is_empty() {
            return forest.finish();
        }
        forest.push(Index::leaf(L::from_members(members.into_boxed_slice())));
    }
}

#[cfg(test)]
mod tests;
