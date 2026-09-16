//! A typed AVL index and one allocation-free reclaimer for both leaf types.

use super::super::Value;
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::{cmp, mem};

pub(super) const LEAF_CAPACITY: usize = 32;

/// A root detached from a Value, ready for the shared release queue.
pub(in crate::value) enum CollectionRoot {
    List(Arc<Index<ListLeaf>>),
    Map(Arc<Index<MapLeaf>>),
}

pub(in crate::value) struct ListLeaf(pub(super) Box<[Value]>);
pub(in crate::value) struct MapLeaf(pub(super) Box<[(Arc<str>, Value)]>);

/// Each specialization fixes both its payload and cached routing metadata.
pub(in crate::value) trait Leaf: Sized {
    type Member;
    type Summary: Clone;

    fn from_members(members: Box<[Self::Member]>) -> Self;
    fn len(&self) -> usize;
    fn summary(&self) -> Self::Summary;
    fn empty() -> Self;
    fn release(self, pending: &mut Option<Pending>);
    fn pending(body: Box<Body<Self>>) -> Pending;
}

/// The body is always present while a node can be observed. Body, rather than
/// Index, implements Drop so an exclusively owned Index can transfer its body
/// straight into the release queue without allocating a replacement.
pub(in crate::value) struct Index<L: Leaf> {
    pub(super) len: usize,
    pub(super) height: u8,
    pub(super) summary: L::Summary,
    body: Box<Body<L>>,
}

pub(in crate::value) struct Body<L: Leaf> {
    data: Data<L>,
    // Always None in published nodes. Reclamation owns the body exclusively.
    next: Option<Pending>,
}

pub(super) enum Data<L: Leaf> {
    Leaf(L),
    Branch {
        left: Arc<Index<L>>,
        right: Arc<Index<L>>,
    },
}

pub(in crate::value) enum Pending {
    List(Box<Body<ListLeaf>>),
    Map(Box<Body<MapLeaf>>),
}

impl Leaf for ListLeaf {
    type Member = Value;
    type Summary = ();

    fn from_members(members: Box<[Value]>) -> Self {
        Self(members)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn summary(&self) {}

    fn empty() -> Self {
        Self(Box::default())
    }

    fn release(self, pending: &mut Option<Pending>) {
        for value in self.0.into_vec() {
            enqueue_value(value, pending);
        }
    }

    fn pending(body: Box<Body<Self>>) -> Pending {
        Pending::List(body)
    }
}

impl Leaf for MapLeaf {
    type Member = (Arc<str>, Value);
    type Summary = Arc<str>;

    fn from_members(members: Box<[(Arc<str>, Value)]>) -> Self {
        Self(members)
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn summary(&self) -> Self::Summary {
        // Empty leaves exist only as already-drained destructor placeholders.
        self.0
            .last()
            .map(|(key, _)| key.clone())
            .unwrap_or_default()
    }

    fn empty() -> Self {
        Self(Box::default())
    }

    fn release(self, pending: &mut Option<Pending>) {
        for (_, value) in self.0.into_vec() {
            enqueue_value(value, pending);
        }
    }

    fn pending(body: Box<Body<Self>>) -> Pending {
        Pending::Map(body)
    }
}

impl<L: Leaf> Index<L> {
    pub(super) fn leaf(leaf: L) -> Arc<Self> {
        debug_assert!(leaf.len() > 0 && leaf.len() <= LEAF_CAPACITY);
        Arc::new(Self {
            len: leaf.len(),
            height: 0,
            summary: leaf.summary(),
            body: Box::new(Body {
                data: Data::Leaf(leaf),
                next: None,
            }),
        })
    }

    fn branch(left: Arc<Self>, right: Arc<Self>) -> Arc<Self> {
        // Public growth checks its final length before constructing any path.
        // All rotation children are disjoint subsets of that checked length.
        Arc::new(Self {
            len: left.len + right.len,
            height: cmp::max(left.height, right.height) + 1,
            summary: right.summary.clone(),
            body: Box::new(Body {
                data: Data::Branch { left, right },
                next: None,
            }),
        })
    }

    pub(super) fn data(&self) -> &Data<L> {
        &self.body.data
    }
}

/// Join disjoint ordered members. Never attach overlapping indexing subtrees:
/// a snapshot may share with another snapshot, but a single index is a tree.
pub(super) fn join<L: Leaf>(left: Arc<Index<L>>, right: Arc<Index<L>>) -> Arc<Index<L>> {
    if left.height > right.height + 1
        && let Data::Branch {
            left: outer,
            right: inner,
        } = left.data()
    {
        return balance(outer.clone(), join(inner.clone(), right));
    }
    if right.height > left.height + 1
        && let Data::Branch {
            left: inner,
            right: outer,
        } = right.data()
    {
        return balance(join(left, inner.clone()), outer.clone());
    }
    Index::branch(left, right)
}

/// Rebalance children whose heights differ by at most two. Recursion is only
/// along a balanced member index, never along the depth of nested Values.
pub(super) fn balance<L: Leaf>(left: Arc<Index<L>>, right: Arc<Index<L>>) -> Arc<Index<L>> {
    if left.height > right.height + 1
        && let Data::Branch {
            left: outer,
            right: inner,
        } = left.data()
    {
        if outer.height >= inner.height {
            return Index::branch(outer.clone(), Index::branch(inner.clone(), right));
        }
        if let Data::Branch {
            left: middle_left,
            right: middle_right,
        } = inner.data()
        {
            return Index::branch(
                Index::branch(outer.clone(), middle_left.clone()),
                Index::branch(middle_right.clone(), right),
            );
        }
    }
    if right.height > left.height + 1
        && let Data::Branch {
            left: inner,
            right: outer,
        } = right.data()
    {
        if outer.height >= inner.height {
            return Index::branch(Index::branch(left, inner.clone()), outer.clone());
        }
        if let Data::Branch {
            left: middle_left,
            right: middle_right,
        } = inner.data()
        {
            return Index::branch(
                Index::branch(left, middle_left.clone()),
                Index::branch(middle_right.clone(), outer.clone()),
            );
        }
    }
    Index::branch(left, right)
}

/// Borrowed depth-first traversal with O(log n) pointer scratch. An empty or
/// single-leaf collection never allocates traversal scratch.
pub(super) struct Leaves<'a, L: Leaf> {
    next: Option<&'a Index<L>>,
    pending: Vec<&'a Index<L>>,
}

impl<'a, L: Leaf> Leaves<'a, L> {
    pub(super) fn new(root: Option<&'a Index<L>>) -> Self {
        Self {
            next: root,
            pending: Vec::new(),
        }
    }
}

impl<'a, L: Leaf> Iterator for Leaves<'a, L> {
    type Item = &'a L;

    fn next(&mut self) -> Option<Self::Item> {
        let mut node = self.next.take().or_else(|| self.pending.pop())?;
        loop {
            match node.data() {
                Data::Leaf(leaf) => return Some(leaf),
                Data::Branch { left, right } => {
                    self.pending.push(right);
                    node = left;
                }
            }
        }
    }
}

fn enqueue_value(value: Value, pending: &mut Option<Pending>) {
    match value.into_collection_root() {
        Some(CollectionRoot::List(node)) => enqueue(node, pending),
        Some(CollectionRoot::Map(node)) => enqueue(node, pending),
        None => {}
    }
}

fn enqueue<L: Leaf>(node: Arc<Index<L>>, pending: &mut Option<Pending>) {
    // into_inner guarantees one winner when final owners release concurrently.
    // A direct final Arc drop also enters Body::drop, so mixed paths are safe.
    if let Some(node) = Arc::into_inner(node) {
        let mut body = node.body;
        body.next = pending.take();
        *pending = Some(L::pending(body));
    }
}

fn release_data<L: Leaf>(data: Data<L>, pending: &mut Option<Pending>) {
    match data {
        Data::Leaf(leaf) => leaf.release(pending),
        Data::Branch { left, right } => {
            enqueue(left, pending);
            enqueue(right, pending);
        }
    }
}

fn release_body<L: Leaf>(body: &mut Body<L>, pending: &mut Option<Pending>) {
    *pending = body.next.take();
    release_data(
        mem::replace(&mut body.data, Data::Leaf(L::empty())),
        pending,
    );
    // Body's ordinary destructor now sees only an empty, allocation-free leaf.
}

impl<L: Leaf> Drop for Body<L> {
    fn drop(&mut self) {
        let mut pending = self.next.take();
        release_data(
            mem::replace(&mut self.data, Data::Leaf(L::empty())),
            &mut pending,
        );
        while let Some(body) = pending.take() {
            match body {
                Pending::List(mut body) => release_body(&mut body, &mut pending),
                Pending::Map(mut body) => release_body(&mut body, &mut pending),
            }
        }
    }
}
