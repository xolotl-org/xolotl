//! Iterative resident graph traversal for caller-owned analysis and codec work.
//!
//! Traversal reads immutable Values only. It does not load objects, expand
//! streams, prescribe admission budgets, or turn storage identities into value
//! equality. Caller-owned memo tables determine each operation's summaries.

use super::{ListIter, MapIter, Value, ValueIdentity, ValueView};
use alloc::vec::Vec;
use core::marker::PhantomData;

/// An opaque memo key valid only for the lifetime of its borrowed Value.
///
/// Clones sharing one allocation have one key. Inline scalar positions have
/// distinct keys even when they have equal contents. This is not semantic
/// equality, a content digest, or a durable identifier. Neither a key nor a
/// traversal retains an allocation independently of the borrowed root.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ValueNodeKey<'a> {
    identity: Identity,
    borrow: PhantomData<&'a Value>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Identity {
    Shared(ValueIdentity),
    Inline(usize),
}

impl<'a> ValueNodeKey<'a> {
    /// Identify a live resident node without allocating or inspecting children.
    pub fn of(value: &'a Value) -> Self {
        Self {
            identity: value.identity().map_or_else(
                || Identity::Inline(core::ptr::from_ref(value).addr()),
                Identity::Shared,
            ),
            borrow: PhantomData,
        }
    }
}

enum Children<'a> {
    List(ListIter<'a>),
    Map(MapIter<'a>),
}

impl<'a> Children<'a> {
    fn next(&mut self) -> Option<&'a Value> {
        match self {
            Self::List(items) => items.next(),
            Self::Map(entries) => entries.next().map(|(_, value)| value),
        }
    }
}

struct Frame<'a> {
    value: &'a Value,
    children: Children<'a>,
}

/// An iterative postorder walk with caller-owned memoization.
///
/// After each [`Self::next`] result, record that node's [`ValueNodeKey`] before
/// requesting another node. The `completed` lookup must report those recorded
/// keys throughout the walk. Every child of a returned collection is then
/// already complete, and shared subgraphs are visited once. Ordered collection
/// iteration, not traversal order, defines child ordering in a summary.
///
/// Construction and walking one leaf do not allocate. Composite traversal uses
/// explicit pending-node storage and collection iterator scratch; neither the
/// call stack nor an implicit recursion limit depends on Value nesting. The
/// frame storage follows nesting depth. Each live collection iterator also
/// retains its logarithmic index path, so a wide collection does not require a
/// second array of child pointers. Scratch uses ordinary `alloc` allocation
/// failure behavior. There is no hidden resident depth/size limit.
///
/// ```
/// use std::collections::BTreeMap;
/// use xolotl_types::Value;
/// use xolotl_types::value::traversal::{ValueNodeKey, ValuePostorder};
///
/// let child = Value::list(vec![Value::integer(1)]);
/// let root = Value::list(vec![child.clone(), child]);
/// let mut completed = BTreeMap::new();
/// let mut walk = ValuePostorder::new(&root);
/// while let Some(value) = walk.next(|key| completed.contains_key(&key)) {
///     completed.insert(ValueNodeKey::of(value), ());
/// }
/// assert_eq!(completed.len(), 3);
/// ```
pub struct ValuePostorder<'a> {
    first: Option<&'a Value>,
    pending: Vec<Frame<'a>>,
}

impl<'a> ValuePostorder<'a> {
    /// Start at a borrowed root without allocating or cloning its payload.
    pub fn new(root: &'a Value) -> Self {
        Self {
            first: Some(root),
            pending: Vec::new(),
        }
    }

    /// Return the next unfinished node after all its children are complete.
    ///
    /// `completed` may already contain results from other roots that remain
    /// borrowed. This permits analyses spanning independently composed Values
    /// without converting or importing their resident subgraphs.
    pub fn next(&mut self, completed: impl Fn(ValueNodeKey<'a>) -> bool) -> Option<&'a Value> {
        match self.try_next(completed, |_, _| Ok::<(), core::convert::Infallible>(())) {
            Ok(value) => value,
            Err(error) => match error {},
        }
    }

    /// Check newly reached nodes before descending and return the next completed node.
    ///
    /// `enter` receives the borrowed node and its current depth, counting the
    /// root as one. It runs before allocating that collection's iterator or
    /// pending frame. Callers can enforce their own admission policy without
    /// first visiting a graph's entire depth. No default limit is imposed.
    ///
    /// Already completed nodes are skipped without calling `enter`; summaries
    /// must still account for shared subtrees at each logical use. If `enter`
    /// returns an error, discard the walk; the failed candidate is consumed.
    pub fn try_next<E>(
        &mut self,
        completed: impl Fn(ValueNodeKey<'a>) -> bool,
        mut enter: impl FnMut(&'a Value, usize) -> Result<(), E>,
    ) -> Result<Option<&'a Value>, E> {
        let mut candidate = self.first.take();
        loop {
            if let Some(value) = candidate.take()
                && !completed(ValueNodeKey::of(value))
            {
                enter(value, self.pending.len() + 1)?;
                let children = match value.view() {
                    ValueView::List(items) => Children::List(items.iter()),
                    ValueView::Map(entries) => Children::Map(entries.iter()),
                    _ => return Ok(Some(value)),
                };
                self.pending.push(Frame { value, children });
            }
            let Some(frame) = self.pending.last_mut() else {
                return Ok(None);
            };
            match frame.children.next() {
                Some(child) => candidate = Some(child),
                None => {
                    let value = frame.value;
                    self.pending.pop();
                    return Ok(Some(value));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeSet, vec};
    use anyhow::ensure;

    #[test]
    fn wide_shared_graph_visits_children_once_with_bounded_active_frames() {
        let leaf = Value::list(vec![Value::from("shared")]);
        let root = Value::list((0..32_768).map(|_| leaf.clone()).collect());
        let mut completed = BTreeSet::new();
        let mut walk = ValuePostorder::new(&root);
        let mut count = 0;
        while let Some(value) = walk.next(|key| completed.contains(&key)) {
            // Breadth belongs to the resident collection, not a temporary
            // expanded queue. A flat pending-children implementation would
            // retain tens of thousands of entries for this input.
            assert!(walk.pending.len() <= 2);
            if let Some(items) = value.as_list() {
                for child in items {
                    assert!(completed.contains(&ValueNodeKey::of(child)));
                }
            }
            completed.insert(ValueNodeKey::of(value));
            count += 1;
        }
        assert_eq!(count, 3);
        assert!(completed.contains(&ValueNodeKey::of(&root)));
        assert!(
            ValuePostorder::new(&root)
                .next(|key| completed.contains(&key))
                .is_none()
        );
    }

    #[test]
    fn memo_keys_distinguish_inline_positions_and_share_owned_leaves() {
        let first = Value::integer(1);
        let second = first.clone();
        assert_ne!(ValueNodeKey::of(&first), ValueNodeKey::of(&second));
        let bytes = Value::bytes(vec![1, 2, 3]);
        let shared = bytes.clone();
        assert_eq!(ValueNodeKey::of(&bytes), ValueNodeKey::of(&shared));
        let copied = Value::bytes(vec![1, 2, 3]);
        assert_ne!(ValueNodeKey::of(&bytes), ValueNodeKey::of(&copied));
        let mut walk = ValuePostorder::new(&first);
        assert!(
            walk.next(|_| false)
                .is_some_and(|value| core::ptr::eq(value, &first))
        );
        assert_eq!(walk.pending.capacity(), 0);
        assert!(walk.next(|_| false).is_none());
    }

    #[test]
    fn caller_admission_stops_before_allocating_deep_pending_frames() -> anyhow::Result<()> {
        std::thread::Builder::new()
            .stack_size(128 * 1024)
            .spawn(|| -> anyhow::Result<()> {
                let mut root = Value::null();
                for _ in 0..20_000 {
                    root = Value::list(vec![root]);
                }
                let mut entered = 0;
                let mut walk = ValuePostorder::new(&root);
                let result = walk.try_next(
                    |_| false,
                    |_, depth| {
                        entered += 1;
                        if depth <= 32 { Ok(()) } else { Err(depth) }
                    },
                );
                ensure!(result == Err(33));
                ensure!(entered == 33);
                ensure!(walk.pending.len() == 32);
                // Vec growth follows accepted frames, not the 20,000-node
                // resident chain that was already owned by the caller.
                ensure!(walk.pending.capacity() <= 64);
                Ok(())
            })?
            .join()
            .map_err(|_error| anyhow::anyhow!("admission traversal worker panicked"))??;
        Ok(())
    }
}
