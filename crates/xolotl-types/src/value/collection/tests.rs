use super::{
    CollectionError, ValueList, ValueMap,
    node::{Data, Index, LEAF_CAPACITY, Leaf},
};
use crate::value::Value;
use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    sync::Arc,
    vec::Vec,
};
use anyhow::{Context, ensure};
use core::fmt::Debug;
use std::{panic, sync::Barrier, thread};

pub(super) fn inspect<L: Leaf>(root: Option<&Arc<Index<L>>>) -> anyhow::Result<BTreeSet<usize>>
where
    L::Summary: Debug + PartialEq,
{
    let mut seen = BTreeSet::new();
    let mut pending: Vec<_> = root.into_iter().collect();
    while let Some(node) = pending.pop() {
        ensure!(
            seen.insert(Arc::as_ptr(node).addr()),
            "an index must be a tree"
        );
        match node.data() {
            Data::Leaf(leaf) => {
                ensure!(leaf.len() > 0 && leaf.len() <= LEAF_CAPACITY);
                ensure!(node.len == leaf.len() && node.height == 0);
                ensure!(node.summary == leaf.summary());
            }
            Data::Branch { left, right } => {
                ensure!(node.len == left.len.checked_add(right.len).context("index length")?);
                ensure!(
                    left.height.abs_diff(right.height) <= 1,
                    "AVL height invariant"
                );
                ensure!(node.height == left.height.max(right.height) + 1);
                ensure!(node.summary == right.summary);
                pending.extend([left, right]);
            }
        }
    }
    Ok(seen)
}

fn check_map(map: &ValueMap, reference: &BTreeMap<String, i64>) -> anyhow::Result<()> {
    ensure!(map.len() == reference.len());
    ensure!(map.is_empty() == reference.is_empty());
    let mut actual = map.iter();
    for (key, value) in reference {
        let (actual_key, actual_value) = actual.next().context("map item")?;
        ensure!(actual_key == key && actual_value.as_int() == Some(*value));
        ensure!(map.get(key).and_then(Value::as_int) == Some(*value));
    }
    ensure!(actual.next().is_none() && actual.len() == 0);
    ensure!(map.get("not-present").is_none());
    drop(inspect(map.root.as_ref())?);
    Ok(())
}

#[test]
fn list_updates_preserve_snapshots_and_share_unaffected_paths() -> anyhow::Result<()> {
    let original: ValueList = (0..16_384).map(Value::integer).collect();
    let old_nodes = inspect(original.root.as_ref())?;
    let mut changed = original.clone();
    ensure!(changed.root_identity() == original.root_identity());
    ensure!(
        changed
            .set(8_111, Value::integer(-1))?
            .and_then(|v| v.as_int())
            == Some(8_111)
    );
    changed.push(Value::integer(16_384))?;
    ensure!(changed.len() == 16_385 && original.len() == 16_384);
    ensure!(original.get(8_111).and_then(Value::as_int) == Some(8_111));
    for (index, value) in changed.iter().enumerate() {
        let expected = if index == 8_111 {
            -1
        } else {
            i64::try_from(index)?
        };
        ensure!(value.as_int() == Some(expected));
    }
    let new_nodes = inspect(changed.root.as_ref())?;
    let height = usize::from(changed.root.as_ref().context("changed root")?.height);
    let new_count = new_nodes.difference(&old_nodes).count();
    ensure!(new_count <= 4 * (height + 1));
    ensure!(new_nodes.intersection(&old_nodes).count() > old_nodes.len() / 2);
    let identity = changed.root_identity();
    ensure!(changed.set(changed.len(), Value::null())?.is_none());
    ensure!(changed.root_identity() == identity);
    ensure!(changed.get(usize::MAX).is_none());
    Ok(())
}

#[test]
fn list_append_balances_across_leaf_and_tree_boundaries() -> anyhow::Result<()> {
    let mut list = ValueList::new();
    for index in 0..8_193 {
        list.push(Value::integer(index))?;
        if index % 97 == 0 {
            drop(inspect(list.root.as_ref())?);
        }
    }
    drop(inspect(list.root.as_ref())?);
    ensure!(list.iter().map(Value::as_int).eq((0..8_193).map(Some)));
    Ok(())
}

#[test]
fn concatenation_copies_member_slots_even_for_identical_snapshots() -> anyhow::Result<()> {
    let mut list: ValueList = (0..67).map(Value::integer).collect();
    for _ in 0..6 {
        let next = list.concat(&list)?;
        ensure!(next.len() == list.len() * 2);
        ensure!(
            next.iter()
                .map(Value::as_int)
                .eq(list.iter().chain(list.iter()).map(Value::as_int))
        );
        drop(inspect(next.root.as_ref())?);
        list = next;
    }
    let nested = Value::from(list);
    let repeated = ValueList::from(vec![nested.clone(), nested]);
    ensure!(
        repeated.get(0).context("first nested")?.identity()
            == repeated.get(1).context("second nested")?.identity()
    );
    drop(inspect(repeated.root.as_ref())?);
    Ok(())
}

#[test]
fn concatenation_balances_unequal_index_heights() -> anyhow::Result<()> {
    for (left_len, right_len) in [
        (1, 1_024),
        (1_024, 1),
        (37, 8_192),
        (8_192, 37),
        (0, 33),
        (33, 0),
    ] {
        let left: ValueList = (0..left_len).map(Value::integer).collect();
        let right: ValueList = (left_len..left_len + right_len)
            .map(Value::integer)
            .collect();
        let joined = left.concat(&right)?;
        ensure!(
            joined
                .iter()
                .map(Value::as_int)
                .eq((0..left_len + right_len).map(Some))
        );
        drop(inspect(joined.root.as_ref())?);
        ensure!(joined.first().and_then(Value::as_int) == Some(0));
        ensure!(joined.last().and_then(Value::as_int) == Some(left_len + right_len - 1));
    }
    Ok(())
}

fn permutation(count: usize) -> Vec<usize> {
    let mut values: Vec<_> = (0..count).collect();
    let mut state = 0x4b1d_7a65_u64;
    for index in (1..count).rev() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        values.swap(index, (state as usize) % (index + 1));
    }
    values
}

#[test]
fn map_updates_and_maximum_removal_match_ordered_reference() -> anyhow::Result<()> {
    let count = 2_049;
    for order in [
        (0..count).collect::<Vec<_>>(),
        (0..count).rev().collect(),
        permutation(count),
    ] {
        let mut map = ValueMap::new();
        let mut reference = BTreeMap::new();
        for (step, index) in order.into_iter().enumerate() {
            let key = format!("{index:08}");
            let value = i64::try_from(index)?;
            ensure!(map.insert(key.clone(), Value::integer(value))?.is_none());
            ensure!(reference.insert(key, value).is_none());
            if step % 71 == 0 {
                check_map(&map, &reference)?;
            }
        }
        check_map(&map, &reference)?;
        let snapshot = map.clone();
        let snapshot_nodes = inspect(snapshot.root.as_ref())?;
        let key = String::from("00001024");
        ensure!(
            map.insert(key.clone(), Value::integer(-1))?
                .and_then(|v| v.as_int())
                == Some(1_024)
        );
        ensure!(reference.insert(key, -1) == Some(1_024));
        let changed_nodes = inspect(map.root.as_ref())?;
        let height = usize::from(map.root.as_ref().context("map root")?.height);
        ensure!(changed_nodes.difference(&snapshot_nodes).count() <= 2 * (height + 1));
        ensure!(snapshot.get("00001024").and_then(Value::as_int) == Some(1_024));
        let identity = map.root_identity();
        ensure!(map.remove("not-present").is_none());
        ensure!(map.root_identity() == identity);
        // Descending removal repeatedly changes subtree maxima and collapses
        // empty leaves, exercising both routing metadata and AVL deletion.
        for (step, index) in (0..count).rev().enumerate() {
            let key = format!("{index:08}");
            ensure!(map.remove(&key).and_then(|v| v.as_int()) == reference.remove(&key));
            if step % 71 == 0 {
                check_map(&map, &reference)?;
            }
        }
        check_map(&map, &reference)?;
        ensure!(snapshot.len() == count);
    }
    Ok(())
}

#[test]
fn map_permuted_removal_and_reinsertion_preserve_search_order() -> anyhow::Result<()> {
    let mut map = ValueMap::new();
    let mut reference = BTreeMap::new();
    for index in 0..3_001 {
        let key = format!("{index:08}");
        ensure!(map.insert(key.clone(), Value::integer(index))?.is_none());
        ensure!(reference.insert(key, index).is_none());
    }
    for (step, index) in permutation(3_001).into_iter().enumerate() {
        let key = format!("{index:08}");
        ensure!(map.remove(&key).and_then(|v| v.as_int()) == reference.remove(&key));
        if step % 79 == 0 {
            check_map(&map, &reference)?;
        }
        if index % 3 == 0 {
            ensure!(map.insert(key.clone(), Value::integer(-1))?.is_none());
            ensure!(reference.insert(key, -1).is_none());
        }
    }
    check_map(&map, &reference)
}

#[test]
fn utf8_keys_and_borrowed_iterators_retain_exact_remaining_length() -> anyhow::Result<()> {
    let long_key = "界".repeat(16_384);
    let mut map: ValueMap = ["", "z", "é", "中", "🙂", long_key.as_str()]
        .into_iter()
        .enumerate()
        .map(|(index, key)| (String::from(key), Value::integer(index as i64)))
        .collect();
    let borrowed_key = map
        .iter()
        .find(|(key, _)| *key == long_key)
        .context("large key")?
        .0;
    let original_ptr = borrowed_key.as_ptr();
    let snapshot = map.clone();
    ensure!(map.insert(long_key.clone(), Value::integer(-1))?.is_some());
    let replacement_key = map
        .iter()
        .find(|(key, _)| *key == long_key)
        .context("updated key")?
        .0;
    ensure!(original_ptr == replacement_key.as_ptr());
    ensure!(snapshot.get(&long_key).and_then(Value::as_int) == Some(5));
    let mut iter = map.iter();
    let first = iter.next().context("first map item")?;
    ensure!(first.0.is_empty() && iter.len() == map.len() - 1);
    drop(iter);
    ensure!(first.1.as_int() == Some(0));
    let mut keys = map.keys();
    let mut values = map.values();
    for remaining in (0..map.len()).rev() {
        ensure!(keys.next().is_some() && values.next().is_some());
        ensure!(keys.len() == remaining && values.len() == remaining);
    }
    ensure!(keys.next().is_none() && keys.next().is_none());
    ensure!(values.next().is_none() && values.next().is_none());
    let list: ValueList = (0..101).map(Value::integer).collect();
    let mut items = list.iter();
    let retained = items.next().context("list member")?;
    for remaining in (0..100).rev() {
        ensure!(items.next().is_some() && items.len() == remaining);
    }
    ensure!(items.next().is_none() && items.next().is_none());
    drop(items);
    ensure!(retained.as_int() == Some(0));
    Ok(())
}

#[test]
fn extracted_child_does_not_retain_unrelated_payloads_or_snapshots() -> anyhow::Result<()> {
    let bytes: Arc<[u8]> = vec![7; 1 << 20].into();
    let weak = Arc::downgrade(&bytes);
    let mut map = ValueMap::new();
    ensure!(
        map.insert(String::from("large"), Value::shared_bytes(bytes))?
            .is_none()
    );
    ensure!(
        map.insert(
            String::from("small"),
            Value::from(ValueList::from(vec![Value::integer(9)]))
        )?
        .is_none()
    );
    let snapshot = map.clone();
    let selected = map.get("small").context("selected child")?.clone();
    drop(map.remove("large").context("removed payload")?);
    ensure!(weak.upgrade().is_some());
    drop(snapshot);
    ensure!(weak.upgrade().is_none());
    drop(map);
    ensure!(
        selected
            .as_list()
            .and_then(|list| list.get(0))
            .and_then(Value::as_int)
            == Some(9)
    );
    Ok(())
}

fn nested(depth: usize, bytes: Arc<[u8]>) -> Value {
    let mut value = Value::shared_bytes(bytes);
    for index in 0..depth {
        value = if index % 2 == 0 {
            Value::from(ValueList::from(vec![value]))
        } else {
            Value::from(ValueMap::from_iter([(String::from("child"), value)]))
        };
    }
    value
}

fn small_stack(test: impl FnOnce() -> anyhow::Result<()> + Send + 'static) -> anyhow::Result<()> {
    thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(test)?
        .join()
        .map_err(|_panic| anyhow::anyhow!("small-stack thread unwound"))?
}

#[test]
fn mixed_deep_collections_drop_on_a_small_stack() -> anyhow::Result<()> {
    small_stack(|| {
        let bytes: Arc<[u8]> = vec![1; 256].into();
        let weak = Arc::downgrade(&bytes);
        let value = nested(24_000, bytes);
        let snapshot = value.clone();
        drop(value);
        ensure!(weak.upgrade().is_some());
        drop(snapshot);
        ensure!(weak.upgrade().is_none());
        Ok(())
    })
}

#[test]
fn partial_updates_release_deep_replaced_children_on_a_small_stack() -> anyhow::Result<()> {
    small_stack(|| {
        let bytes: Arc<[u8]> = vec![2; 256].into();
        let weak = Arc::downgrade(&bytes);
        let mut list = ValueList::from(vec![nested(24_000, bytes), Value::integer(5)]);
        let selected = list.get(1).context("selected sibling")?.clone();
        drop(list.set(0, Value::null())?.context("replaced deep child")?);
        ensure!(weak.upgrade().is_none());
        drop(list);
        ensure!(selected.as_int() == Some(5));
        Ok(())
    })
}

#[test]
fn caller_unwind_uses_the_same_iterative_reclaimer() -> anyhow::Result<()> {
    small_stack(|| {
        let bytes: Arc<[u8]> = vec![3; 256].into();
        let weak = Arc::downgrade(&bytes);
        let value = nested(24_000, bytes);
        let result = panic::catch_unwind(move || {
            let _owner = value;
            panic::resume_unwind(Box::new("collection unwind fixture"));
        });
        ensure!(result.is_err());
        ensure!(weak.upgrade().is_none());
        Ok(())
    })
}

#[test]
fn concurrent_final_owners_release_shared_deep_roots() -> anyhow::Result<()> {
    small_stack(|| {
        for trial in 0..24 {
            let bytes: Arc<[u8]> = vec![4; 256].into();
            let weak = Arc::downgrade(&bytes);
            let child = nested(2_048, bytes);
            let left = Value::from(ValueList::from(vec![child.clone()]));
            let right = if trial % 2 == 0 {
                child
            } else {
                Value::from(ValueMap::from_iter([(String::from("alias"), child)]))
            };
            let barrier = Arc::new(Barrier::new(2));
            let other_barrier = barrier.clone();
            let other = thread::Builder::new()
                .stack_size(64 * 1024)
                .spawn(move || {
                    other_barrier.wait();
                    drop(right);
                })?;
            barrier.wait();
            drop(left);
            other
                .join()
                .map_err(|_panic| anyhow::anyhow!("competing final release unwound"))?;
            ensure!(
                weak.upgrade().is_none(),
                "final root retained on trial {trial}"
            );
        }
        Ok(())
    })
}

#[test]
fn empty_collections_and_length_overflow_are_explicit() -> anyhow::Result<()> {
    let mut empty = ValueList::new();
    ensure!(empty.is_empty() && empty.iter().len() == 0);
    ensure!(empty.set(0, Value::null())?.is_none());
    let mut empty_map = ValueMap::new();
    ensure!(empty_map.is_empty() && empty_map.iter().len() == 0);
    ensure!(empty_map.remove("").is_none());
    let mut list = ValueList::from(vec![Value::integer(1)]);
    // The private length fixture never reaches indexing or traversal. Release
    // depends only on ownership, so its intentionally enlarged cache is safe.
    Arc::get_mut(list.root.as_mut().context("list root")?)
        .context("unique list root")?
        .len = usize::MAX;
    let identity = list.root_identity();
    ensure!(list.push(Value::integer(2)) == Err(CollectionError::LengthOverflow));
    ensure!(
        list.concat(&ValueList::from(vec![Value::null()])).err()
            == Some(CollectionError::LengthOverflow)
    );
    ensure!(list.root_identity() == identity && list.len() == usize::MAX);
    let mut map = ValueMap::from_iter([(String::from("a"), Value::integer(1))]);
    Arc::get_mut(map.root.as_mut().context("map root")?)
        .context("unique map root")?
        .len = usize::MAX;
    let identity = map.root_identity();
    ensure!(
        map.insert(String::from("b"), Value::integer(2)).err()
            == Some(CollectionError::LengthOverflow)
    );
    ensure!(map.root_identity() == identity && map.len() == usize::MAX);
    ensure!(map.get("a").and_then(Value::as_int) == Some(1));
    Ok(())
}
#[test]
fn indexed_map_entries_follow_sorted_order_and_share_payloads() -> anyhow::Result<()> {
    let mut map = super::ValueMap::new();
    for index in (0..257).rev() {
        map.insert(
            alloc::format!("key-{index:04}"),
            crate::Value::string(alloc::format!("value-{index}")),
        )?;
    }
    let snapshot = map.clone();
    for (index, (key, value)) in snapshot.iter().enumerate() {
        let (indexed_key, indexed_value) = map.get_index(index).context("entry is in bounds")?;
        ensure!(indexed_key == key);
        ensure!(core::ptr::eq(indexed_value, value));
    }
    ensure!(map.get_index(map.len()).is_none());
    ensure!(map.get_index(usize::MAX).is_none());
    ensure!(super::ValueMap::new().get_index(0).is_none());
    Ok(())
}
