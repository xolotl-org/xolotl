use super::*;
use crate::value::collection::{node::Data, tests::inspect};
use alloc::{collections::BTreeSet, format, string::ToString};
use anyhow::{Context, ensure};

fn leaves<L: Leaf>(roots: impl IntoIterator<Item = Arc<Index<L>>>) -> BTreeSet<usize> {
    let mut pending: Vec<_> = roots.into_iter().collect();
    let mut found = BTreeSet::new();
    while let Some(node) = pending.pop() {
        match node.data() {
            Data::Leaf(_) => {
                found.insert(Arc::as_ptr(&node).addr());
            }
            Data::Branch { left, right } => pending.extend([left.clone(), right.clone()]),
        }
    }
    found
}

#[test]
fn sequential_lists_keep_a_logarithmic_forest_and_reuse_completed_leaves() -> anyhow::Result<()> {
    for length in [
        0, 1, 31, 32, 33, 63, 64, 65, 1023, 1024, 1025, 4095, 4096, 4097, 65_535,
    ] {
        let mut builder = ValueListBuilder::new();
        ensure!(
            builder.assembly.pending.capacity() == 0
                && builder.assembly.forest.trees.capacity() == 0
        );
        for index in 0..length {
            builder.push(Value::integer(index as i64))?;
            ensure!(builder.len() == index + 1);
            ensure!(builder.assembly.pending.len() < LEAF_CAPACITY);
            ensure!(builder.assembly.pending.capacity() <= LEAF_CAPACITY);
            let trees = &builder.assembly.forest.trees;
            ensure!(trees.len() <= usize::BITS as usize);
            ensure!(trees.windows(2).all(|pair| pair[0].height > pair[1].height));
            ensure!(
                trees.iter().map(|tree| tree.len).sum::<usize>() + builder.assembly.pending.len()
                    == builder.len()
            );
        }
        let completed = leaves(builder.assembly.forest.trees.iter().cloned());
        let list = builder.finish();
        ensure!(list.len() == length && list.is_empty() == (length == 0));
        let published = leaves(list.root.iter().cloned());
        ensure!(
            completed.is_subset(&published),
            "finish copied a completed leaf"
        );
        ensure!(published.len() == length.div_ceil(LEAF_CAPACITY));
        drop(inspect(list.root.as_ref())?);
        for (index, value) in list.iter().enumerate() {
            ensure!(value.as_int() == Some(index as i64));
            ensure!(list.get(index) == Some(value));
        }
    }
    Ok(())
}

#[test]
fn sequential_maps_keep_order_across_carries_and_share_key_and_value_storage() -> anyhow::Result<()>
{
    let child = Value::list(vec![Value::bytes(vec![0, 255])]);
    let mut builder = ValueMapBuilder::new();
    ensure!(builder.is_empty() && builder.last_key().is_none());
    for index in 0..4097 {
        let key = format!("entry-{index:08}");
        builder.append(key.clone(), child.clone())?;
        ensure!(builder.last_key() == Some(key.as_str()));
        ensure!(builder.assembly.pending.capacity() <= LEAF_CAPACITY);
        ensure!(builder.assembly.forest.trees.len() <= usize::BITS as usize);
    }
    let tail_key = builder.last_key().context("last key")?.as_ptr();
    let completed = leaves(builder.assembly.forest.trees.iter().cloned());
    let map = builder.finish();
    ensure!(map.len() == 4097);
    ensure!(map.keys().last().context("published key")?.as_ptr() == tail_key);
    let published = leaves(map.root.iter().cloned());
    ensure!(completed.is_subset(&published));
    ensure!(published.len() == 4097_usize.div_ceil(LEAF_CAPACITY));
    drop(inspect(map.root.as_ref())?);
    for (index, (key, value)) in map.iter().enumerate() {
        ensure!(key == format!("entry-{index:08}"));
        ensure!(value.identity() == child.identity());
        ensure!(map.get(key).and_then(Value::identity) == child.identity());
    }
    Ok(())
}

#[test]
fn rejected_keys_and_lengths_leave_accepted_entries_unchanged() -> anyhow::Result<()> {
    let mut map = ValueMapBuilder::new();
    for index in 0..32 {
        map.append(format!("key-{index:02}"), Value::integer(index))?;
    }
    let previous = map
        .last_key()
        .context("complete leaf last key")?
        .to_string();
    ensure!(map.assembly.pending.is_empty());
    ensure!(map.append(previous.clone(), Value::null()) == Err(CollectionError::KeyOrder));
    ensure!(map.append("".into(), Value::null()) == Err(CollectionError::KeyOrder));
    ensure!(map.len() == 32 && map.last_key() == Some(previous.as_str()));
    map.append("key-32".into(), Value::integer(32))?;
    map.assembly.len = usize::MAX;
    ensure!(map.append("key-33".into(), Value::null()) == Err(CollectionError::LengthOverflow));
    ensure!(map.assembly.pending.len() == 1 && map.last_key() == Some("key-32"));
    map.assembly.len = 33;
    ensure!(map.finish().len() == 33);

    let mut list = ValueListBuilder::new();
    list.push(Value::integer(7))?;
    list.assembly.len = usize::MAX;
    ensure!(list.push(Value::null()) == Err(CollectionError::LengthOverflow));
    ensure!(list.assembly.pending.len() == 1);
    list.assembly.len = 1;
    ensure!(list.finish().first().and_then(Value::as_int) == Some(7));
    Ok(())
}

#[test]
fn utf8_order_and_empty_keys_use_the_same_map_contract() -> anyhow::Result<()> {
    let mut builder = ValueMapBuilder::new();
    for (index, key) in ["", "a", "a\u{00e9}", "\u{00e9}", "\u{1f642}"]
        .into_iter()
        .enumerate()
    {
        builder.append(key.into(), Value::integer(index as i64))?;
    }
    let map = builder.finish();
    ensure!(map.keys().collect::<Vec<_>>() == ["", "a", "a\u{00e9}", "\u{00e9}", "\u{1f642}"]);
    drop(inspect(map.root.as_ref())?);
    Ok(())
}

#[test]
fn partial_builds_and_rejected_deep_values_release_on_a_small_stack() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(|| -> anyhow::Result<()> {
            for members in [1, 32, 65] {
                let root = ValueList::from(vec![Value::bytes(vec![1, 2, 3])]);
                let weak = Arc::downgrade(root.root.as_ref().context("observed root")?);
                let mut value = Value::from(root);
                for _ in 0..12_000 {
                    let mut list = ValueListBuilder::new();
                    list.push(value)?;
                    value = Value::from(list.finish());
                }
                let mut builder = ValueListBuilder::new();
                builder.push(value)?;
                for _ in 1..members {
                    builder.push(Value::null())?;
                }
                ensure!(weak.upgrade().is_some());
                drop(builder);
                ensure!(weak.upgrade().is_none());
            }
            let root = ValueList::from(vec![Value::integer(7)]);
            let weak = Arc::downgrade(root.root.as_ref().context("rejected root")?);
            let mut value = Value::from(root);
            for _ in 0..12_000 {
                value = Value::list(vec![value]);
            }
            let mut builder = ValueMapBuilder::new();
            builder.append("z".into(), Value::null())?;
            ensure!(builder.append("a".into(), value) == Err(CollectionError::KeyOrder));
            ensure!(weak.upgrade().is_none());
            Ok(())
        })?
        .join()
        .map_err(|_panic| anyhow::anyhow!("assembly worker failed"))??;
    Ok(())
}
