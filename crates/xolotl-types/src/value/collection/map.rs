use super::{
    CollectionError,
    node::{self, CollectionRoot, Data, Index, LEAF_CAPACITY, Leaves, MapLeaf},
};
use crate::value::Value;
use alloc::{collections::BTreeMap, string::String, sync::Arc};
use core::{fmt, iter::FusedIterator, mem, slice};

/// A persistent map with strict UTF-8 key order and immutable nested payloads.
///
/// Cloning is O(1). Lookup and updates visit O(log n) index nodes. Updates copy
/// at most one 32-member leaf and share unrelated subtrees and key allocations.
/// There is no access to mutable nested values.
#[derive(Clone, Default)]
pub struct ValueMap {
    pub(super) root: Option<Arc<Index<MapLeaf>>>,
}

impl ValueMap {
    /// Construct an empty map without allocating.
    pub const fn new() -> Self {
        Self { root: None }
    }

    /// Return the number of unique keys.
    pub fn len(&self) -> usize {
        self.root.as_ref().map_or(0, |root| root.len)
    }

    /// Whether this map has no keys.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Borrow a value by key, without cloning a key or payload.
    pub fn get(&self, key: &str) -> Option<&Value> {
        let mut node = self.root.as_deref()?;
        loop {
            match node.data() {
                Data::Leaf(leaf) => {
                    let index = leaf
                        .0
                        .binary_search_by(|(entry, _)| entry.as_ref().cmp(key))
                        .ok()?;
                    return Some(&leaf.0[index].1);
                }
                Data::Branch { left, right } => {
                    node = if key <= left.summary.as_ref() {
                        left
                    } else {
                        right
                    };
                }
            }
        }
    }

    /// Borrow an entry by its position in strict UTF-8 key order.
    ///
    /// Lookup takes O(log n) time and allocates nothing. An owner can retain a
    /// shared map and an index across suspension without borrowing an iterator
    /// from itself or copying the key.
    pub fn get_index(&self, mut index: usize) -> Option<(&str, &Value)> {
        let mut node = self.root.as_deref()?;
        if index >= node.len {
            return None;
        }
        loop {
            match node.data() {
                Data::Leaf(leaf) => {
                    return leaf.0.get(index).map(|(key, value)| (key.as_ref(), value));
                }
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

    /// Whether a key is present, without cloning a key or value.
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Iterate over borrowed keys and values in strict UTF-8 key order.
    pub fn iter(&self) -> MapIter<'_> {
        MapIter {
            leaves: Leaves::new(self.root.as_deref()),
            current: [].iter(),
            remaining: self.len(),
        }
    }

    /// Iterate over keys in strict UTF-8 order.
    pub fn keys(&self) -> impl ExactSizeIterator<Item = &str> + FusedIterator {
        self.iter().map(|(key, _)| key)
    }

    /// Iterate over values in key order.
    pub fn values(&self) -> impl ExactSizeIterator<Item = &Value> + FusedIterator {
        self.iter().map(|(_, value)| value)
    }

    /// Insert a value and return the previous independently owned member.
    ///
    /// Replacing a value retains its existing key allocation. Length overflow
    /// is checked before copying an update path and leaves the map unchanged.
    pub fn insert(&mut self, key: String, value: Value) -> Result<Option<Value>, CollectionError> {
        if self.get(&key).is_none() {
            self.len()
                .checked_add(1)
                .ok_or(CollectionError::LengthOverflow)?;
        }
        let (root, previous) = match &self.root {
            Some(root) => insert(root, key, value),
            None => (
                Index::leaf(MapLeaf(vec![(key.into(), value)].into_boxed_slice())),
                None,
            ),
        };
        self.root = Some(root);
        Ok(previous)
    }

    /// Remove a key and return its former value while preserving old snapshots.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        let root = self.root.as_ref()?;
        let (root, previous) = remove(root, key);
        self.root = root;
        previous
    }

    pub(in crate::value) fn root_identity(&self) -> Option<usize> {
        self.root.as_ref().map(|root| Arc::as_ptr(root).addr())
    }

    pub(in crate::value) fn into_root(self) -> Option<CollectionRoot> {
        self.root.map(CollectionRoot::Map)
    }
}

impl fmt::Debug for ValueMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValueMap")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl From<BTreeMap<String, Value>> for ValueMap {
    fn from(values: BTreeMap<String, Value>) -> Self {
        Self {
            root: super::assembly::collect::<MapLeaf>(
                values.into_iter().map(|(key, value)| (key.into(), value)),
            ),
        }
    }
}

impl FromIterator<(String, Value)> for ValueMap {
    fn from_iter<T: IntoIterator<Item = (String, Value)>>(values: T) -> Self {
        Self::from(values.into_iter().collect::<BTreeMap<_, _>>())
    }
}

impl<'a> IntoIterator for &'a ValueMap {
    type Item = (&'a str, &'a Value);
    type IntoIter = MapIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Borrowed key/value pairs of a [`ValueMap`] in strict UTF-8 key order.
pub struct MapIter<'a> {
    leaves: Leaves<'a, MapLeaf>,
    current: slice::Iter<'a, (Arc<str>, Value)>,
    remaining: usize,
}

impl<'a> Iterator for MapIter<'a> {
    type Item = (&'a str, &'a Value);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((key, value)) = self.current.next() {
                self.remaining -= 1;
                return Some((key, value));
            }
            self.current = self.leaves.next()?.0.iter();
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for MapIter<'_> {}
impl FusedIterator for MapIter<'_> {}

fn insert(
    node: &Arc<Index<MapLeaf>>,
    key: String,
    value: Value,
) -> (Arc<Index<MapLeaf>>, Option<Value>) {
    match node.data() {
        Data::Leaf(leaf) => {
            let mut members = leaf.0.to_vec();
            match members.binary_search_by(|(entry, _)| entry.as_ref().cmp(&key)) {
                Ok(index) => {
                    let previous = mem::replace(&mut members[index].1, value);
                    (
                        Index::leaf(MapLeaf(members.into_boxed_slice())),
                        Some(previous),
                    )
                }
                Err(index) => {
                    members.insert(index, (key.into(), value));
                    if members.len() <= LEAF_CAPACITY {
                        (Index::leaf(MapLeaf(members.into_boxed_slice())), None)
                    } else {
                        let right = members.split_off(members.len() / 2);
                        (
                            node::join(
                                Index::leaf(MapLeaf(members.into_boxed_slice())),
                                Index::leaf(MapLeaf(right.into_boxed_slice())),
                            ),
                            None,
                        )
                    }
                }
            }
        }
        Data::Branch { left, right } => {
            if key.as_str() <= left.summary.as_ref() {
                let (left, previous) = insert(left, key, value);
                (node::balance(left, right.clone()), previous)
            } else {
                let (right, previous) = insert(right, key, value);
                (node::balance(left.clone(), right), previous)
            }
        }
    }
}

fn remove(node: &Arc<Index<MapLeaf>>, key: &str) -> (Option<Arc<Index<MapLeaf>>>, Option<Value>) {
    match node.data() {
        Data::Leaf(leaf) => {
            let Ok(index) = leaf
                .0
                .binary_search_by(|(entry, _)| entry.as_ref().cmp(key))
            else {
                return (Some(node.clone()), None);
            };
            let mut members = leaf.0.to_vec();
            let (_, previous) = members.remove(index);
            let root = if members.is_empty() {
                None
            } else {
                Some(Index::leaf(MapLeaf(members.into_boxed_slice())))
            };
            (root, Some(previous))
        }
        Data::Branch { left, right } => {
            if key <= left.summary.as_ref() {
                let (replacement, previous) = remove(left, key);
                if previous.is_none() {
                    return (Some(node.clone()), None);
                }
                (
                    Some(match replacement {
                        Some(left) => node::balance(left, right.clone()),
                        None => right.clone(),
                    }),
                    previous,
                )
            } else {
                let (replacement, previous) = remove(right, key);
                if previous.is_none() {
                    return (Some(node.clone()), None);
                }
                (
                    Some(match replacement {
                        Some(right) => node::balance(left.clone(), right),
                        None => left.clone(),
                    }),
                    previous,
                )
            }
        }
    }
}
