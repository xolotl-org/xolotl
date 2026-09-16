//! Borrowed traversal for idempotent structural input checks.

use std::collections::HashSet;
use xolotl_types::{
    Value, ValueIdentity, ValueView,
    value::{ListIter, MapIter},
};

enum Children<'a> {
    List(ListIter<'a>),
    Map(MapIter<'a>),
}

impl<'a> Children<'a> {
    fn next(&mut self) -> Option<&'a Value> {
        match self {
            Self::List(values) => values.next(),
            Self::Map(values) => values.next().map(|(_, value)| value),
        }
    }
}

struct Inspection<'a> {
    next: Option<&'a Value>,
    parents: Vec<Children<'a>>,
    containers: HashSet<ValueIdentity>,
}

/// Inspect a resident graph without recursively walking the call stack or
/// materializing the children of wide containers. Shared containers are visited
/// once. This is for structural checks, not rendering or occurrence counting.
pub(crate) fn inspection_values(value: &Value) -> impl Iterator<Item = &Value> {
    Inspection {
        next: Some(value),
        parents: Vec::new(),
        containers: HashSet::new(),
    }
}

impl<'a> Iterator for Inspection<'a> {
    type Item = &'a Value;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let current = if let Some(value) = self.next.take() {
                value
            } else {
                loop {
                    let parent = self.parents.last_mut()?;
                    if let Some(value) = parent.next() {
                        break value;
                    }
                    self.parents.pop();
                }
            };
            let children = match current.view() {
                ValueView::List(values) => Some(Children::List(values.iter())),
                ValueView::Map(values) => Some(Children::Map(values.iter())),
                _ => None,
            };
            if let Some(children) = children {
                if current
                    .identity()
                    .is_some_and(|identity| !self.containers.insert(identity))
                {
                    continue;
                }
                self.parents.push(children);
            }
            return Some(current);
        }
    }
}
