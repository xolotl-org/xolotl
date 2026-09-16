use super::{
    CollectionError,
    node::{self, CollectionRoot, Data, Index, LEAF_CAPACITY, Leaves, ListLeaf},
};
use crate::value::Value;
use alloc::{sync::Arc, vec::Vec};
use core::{fmt, iter::FusedIterator, mem, slice};

/// An immutable-payload sequence with persistent, path-local updates.
///
/// Cloning is O(1). Lookup and updates visit O(log n) index nodes; updates copy
/// at most one 32-member leaf and share all unaffected subtrees. No operation
/// obtains a mutable reference to a nested Value.
#[derive(Clone, Default)]
pub struct ValueList {
    pub(super) root: Option<Arc<Index<ListLeaf>>>,
}

impl ValueList {
    /// Construct an empty sequence without allocating.
    pub const fn new() -> Self {
        Self { root: None }
    }

    /// Return the number of members.
    pub fn len(&self) -> usize {
        self.root.as_ref().map_or(0, |root| root.len)
    }

    /// Whether the sequence has no members.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Borrow a member in O(log n), without cloning its payload.
    pub fn get(&self, mut index: usize) -> Option<&Value> {
        let mut node = self.root.as_deref()?;
        if index >= node.len {
            return None;
        }
        loop {
            match node.data() {
                Data::Leaf(leaf) => return leaf.0.get(index),
                Data::Branch { left, right } => {
                    if index < left.len {
                        node = left;
                    } else {
                        index -= left.len;
                        node = right;
                    }
                }
            }
        }
    }

    /// Borrow the first member, if present.
    pub fn first(&self) -> Option<&Value> {
        self.get(0)
    }

    /// Borrow the last member, if present.
    pub fn last(&self) -> Option<&Value> {
        self.get(self.len().checked_sub(1)?)
    }

    /// Iterate over borrowed members in order.
    ///
    /// Traversal uses O(log n) pointer scratch, with no allocation for an empty
    /// sequence or one leaf. The exact number of remaining items is available.
    pub fn iter(&self) -> ListIter<'_> {
        ListIter {
            leaves: Leaves::new(self.root.as_deref()),
            current: [].iter(),
            remaining: self.len(),
        }
    }

    /// Append one member, preserving every existing snapshot.
    ///
    /// A length overflow leaves this sequence unchanged.
    pub fn push(&mut self, value: Value) -> Result<(), CollectionError> {
        self.len()
            .checked_add(1)
            .ok_or(CollectionError::LengthOverflow)?;
        self.root = Some(match &self.root {
            Some(root) => append(root, value),
            None => Index::leaf(ListLeaf(vec![value].into_boxed_slice())),
        });
        Ok(())
    }

    /// Replace one member and return its previous independently owned value.
    ///
    /// An out-of-bounds index returns `Ok(None)` and leaves the list unchanged.
    /// No references to mutable nested children are exposed.
    pub fn set(&mut self, index: usize, value: Value) -> Result<Option<Value>, CollectionError> {
        let Some(root) = &self.root else {
            return Ok(None);
        };
        if index >= root.len {
            return Ok(None);
        }
        let (root, previous) = replace(root, index, value);
        self.root = Some(root);
        Ok(Some(previous))
    }

    /// Append another sequence's members to a new snapshot.
    ///
    /// This copies the right-hand member slots, sharing each nested Value's
    /// payload. It takes O(m + log(n + m)) time for m appended members, with
    /// O(log m) temporary stack space. Even when concatenating a list with
    /// itself, the resulting member index remains a tree: a compact index
    /// cannot represent exponentially many members.
    pub fn concat(&self, other: &Self) -> Result<Self, CollectionError> {
        self.len()
            .checked_add(other.len())
            .ok_or(CollectionError::LengthOverflow)?;
        let root = match (&self.root, &other.root) {
            (Some(left), Some(right)) => Some(node::join(left.clone(), copy_members(right))),
            (Some(root), None) | (None, Some(root)) => Some(root.clone()),
            (None, None) => None,
        };
        Ok(Self { root })
    }

    pub(in crate::value) fn root_identity(&self) -> Option<usize> {
        self.root.as_ref().map(|root| Arc::as_ptr(root).addr())
    }

    pub(in crate::value) fn into_root(self) -> Option<CollectionRoot> {
        self.root.map(CollectionRoot::List)
    }
}

impl fmt::Debug for ValueList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValueList")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl From<Vec<Value>> for ValueList {
    fn from(values: Vec<Value>) -> Self {
        Self {
            root: super::assembly::collect::<ListLeaf>(values),
        }
    }
}

impl FromIterator<Value> for ValueList {
    fn from_iter<T: IntoIterator<Item = Value>>(values: T) -> Self {
        Self {
            root: super::assembly::collect::<ListLeaf>(values),
        }
    }
}

impl<'a> IntoIterator for &'a ValueList {
    type Item = &'a Value;
    type IntoIter = ListIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Borrowed ordered members of a [`ValueList`].
pub struct ListIter<'a> {
    leaves: Leaves<'a, ListLeaf>,
    current: slice::Iter<'a, Value>,
    remaining: usize,
}

impl<'a> Iterator for ListIter<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(value) = self.current.next() {
                self.remaining -= 1;
                return Some(value);
            }
            self.current = self.leaves.next()?.0.iter();
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for ListIter<'_> {}
impl FusedIterator for ListIter<'_> {}

fn append(node: &Arc<Index<ListLeaf>>, value: Value) -> Arc<Index<ListLeaf>> {
    match node.data() {
        Data::Leaf(leaf) if leaf.0.len() < LEAF_CAPACITY => {
            let mut members = Vec::with_capacity(leaf.0.len() + 1);
            members.extend(leaf.0.iter().cloned());
            members.push(value);
            Index::leaf(ListLeaf(members.into_boxed_slice()))
        }
        Data::Leaf(_) => node::join(
            node.clone(),
            Index::leaf(ListLeaf(vec![value].into_boxed_slice())),
        ),
        Data::Branch { left, right } => node::balance(left.clone(), append(right, value)),
    }
}

fn copy_members(node: &Index<ListLeaf>) -> Arc<Index<ListLeaf>> {
    match node.data() {
        Data::Leaf(leaf) => Index::leaf(ListLeaf(leaf.0.to_vec().into_boxed_slice())),
        Data::Branch { left, right } => node::join(copy_members(left), copy_members(right)),
    }
}

fn replace(
    node: &Arc<Index<ListLeaf>>,
    index: usize,
    value: Value,
) -> (Arc<Index<ListLeaf>>, Value) {
    match node.data() {
        Data::Leaf(leaf) => {
            let mut members = leaf.0.to_vec();
            let previous = mem::replace(&mut members[index], value);
            (Index::leaf(ListLeaf(members.into_boxed_slice())), previous)
        }
        Data::Branch { left, right } => {
            if index < left.len {
                let (left, previous) = replace(left, index, value);
                (node::balance(left, right.clone()), previous)
            } else {
                let (right, previous) = replace(right, index - left.len, value);
                (node::balance(left.clone(), right), previous)
            }
        }
    }
}
