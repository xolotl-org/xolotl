//! Exact structural classes shared by both compared DAGs. A digest collision
//! never establishes equality, and allocation/sharing shape never rejects it.

use super::{Value, ValueNodeKey, ValuePostorder, ValueView, is_leaf, local::Local};
use alloc::{collections::BTreeMap, vec::Vec};

#[derive(Eq, Ord, PartialEq, PartialOrd)]
enum Child<'a> {
    Item(usize),
    Entry(&'a str, usize),
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct Signature<'a> {
    local: Local<'a>,
    children: Vec<Child<'a>>,
}

pub(super) fn equal(left: &Value, right: &Value) -> bool {
    if Local::of(left) != Local::of(right) {
        return false;
    }
    if is_leaf(left) {
        return true;
    }

    let mut classes = BTreeMap::new();
    let mut structures = BTreeMap::new();
    for root in [left, right] {
        let mut walk = ValuePostorder::new(root);
        while let Some(value) = walk.next(|key| classes.contains_key(&key)) {
            // Postorder has completed every child. Signatures retain only borrowed
            // leaf fields and class numbers; they cannot recursively own Values.
            let children = match value.view() {
                ValueView::List(items) => items
                    .iter()
                    .map(|child| Child::Item(classes[&ValueNodeKey::of(child)]))
                    .collect(),
                ValueView::Map(entries) => entries
                    .iter()
                    .map(|(key, child)| Child::Entry(key, classes[&ValueNodeKey::of(child)]))
                    .collect(),
                _ => Vec::new(),
            };
            let signature = Signature {
                local: Local::of(value),
                children,
            };
            let next_class = structures.len();
            let class = *structures.entry(signature).or_insert(next_class);
            classes.insert(ValueNodeKey::of(value), class);
        }
    }
    classes[&ValueNodeKey::of(left)] == classes[&ValueNodeKey::of(right)]
}
