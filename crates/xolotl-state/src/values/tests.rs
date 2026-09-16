use super::*;
use alloc::vec;
use anyhow::{Context, ensure};
use xolotl_types::{TaintSource, value::ValueView};

fn map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::from(ValueMap::from_iter(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value)),
    ))
}

#[test]
fn shallow_merge_preserves_unrelated_members_and_replaces_collisions() -> anyhow::Result<()> {
    let left = map([("x", Value::integer(1)), ("y", Value::integer(2))]);
    let right = map([("y", Value::integer(20)), ("z", Value::integer(3))]);
    let snapshot = left.clone();
    let merged = merge_values(Some(left), right, MergeRule::Shallow)?;
    ensure!(
        merged
            == map([
                ("x", Value::integer(1)),
                ("y", Value::integer(20)),
                ("z", Value::integer(3))
            ])
    );
    ensure!(
        snapshot
            .as_map()
            .and_then(|map| map.get("y"))
            .and_then(Value::as_int)
            == Some(2)
    );
    Ok(())
}

#[test]
fn deep_merge_combines_nested_maps_and_lists() -> anyhow::Result<()> {
    let left = map([
        ("nested", map([("a", Value::integer(1))])),
        ("items", Value::list(vec![Value::integer(1)])),
    ]);
    let right = map([
        ("nested", map([("b", Value::integer(2))])),
        ("items", Value::list(vec![Value::integer(2)])),
    ]);
    let merged = merge_values(Some(left), right, MergeRule::Deep)?;
    ensure!(
        merged
            == map([
                (
                    "nested",
                    map([("a", Value::integer(1)), ("b", Value::integer(2))])
                ),
                (
                    "items",
                    Value::list(vec![Value::integer(1), Value::integer(2)])
                ),
            ])
    );
    Ok(())
}

#[test]
fn deep_self_merge_concatenates_lists_and_shares_repeated_results() -> anyhow::Result<()> {
    let sequence = Value::list(vec![Value::integer(1), Value::integer(2)]);
    let value = map([("a", sequence.clone()), ("b", sequence)]);
    let merged = merge_values(Some(value.clone()), value, MergeRule::Deep)?;
    let entries = merged.as_map().context("merged map")?;
    let left = entries.get("a").context("first list")?;
    let right = entries.get("b").context("second list")?;
    ensure!(left.identity() == right.identity());
    ensure!(
        left == &Value::list(vec![
            Value::integer(1),
            Value::integer(2),
            Value::integer(1),
            Value::integer(2)
        ])
    );
    Ok(())
}

#[test]
fn root_lists_concatenate_and_missing_values_use_the_incoming_root() -> anyhow::Result<()> {
    for rule in [MergeRule::Shallow, MergeRule::Deep] {
        let left = Value::list(vec![Value::integer(1), Value::integer(2)]);
        let right = Value::list(vec![Value::integer(3)]);
        let merged = merge_values(Some(left), right, rule)?;
        ensure!(
            merged
                == Value::list(vec![
                    Value::integer(1),
                    Value::integer(2),
                    Value::integer(3)
                ])
        );
        let incoming = map([("x", Value::integer(7))]);
        let identity = incoming.identity();
        ensure!(merge_values(None, incoming, rule)?.identity() == identity);
    }
    Ok(())
}

#[test]
fn deep_merge_memoizes_repeated_map_pairs() -> anyhow::Result<()> {
    let mut left = map([("a", Value::integer(1))]);
    let mut right = map([("b", Value::integer(2))]);
    for _ in 0..96 {
        left = map([("x", left.clone()), ("y", left)]);
        right = map([("x", right.clone()), ("y", right)]);
    }
    let merged = merge_values(Some(left), right, MergeRule::Deep)?;
    let mut current = &merged;
    for _ in 0..96 {
        let members = current.as_map().context("merged branch")?;
        let first = members.get("x").context("first alias")?;
        let second = members.get("y").context("second alias")?;
        ensure!(first.identity().is_some() && first.identity() == second.identity());
        current = first;
    }
    ensure!(current == &map([("a", Value::integer(1)), ("b", Value::integer(2))]));
    Ok(())
}

#[cfg(feature = "std")]
#[test]
fn deep_merge_and_result_release_use_a_small_thread_stack() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .stack_size(64 * 1024)
        .spawn(|| -> anyhow::Result<()> {
            let mut left = map([("a", Value::integer(1))]);
            let mut right = map([("b", Value::integer(2))]);
            for _ in 0..12_000 {
                left = map([("child", left)]);
                right = map([("child", right)]);
            }
            let merged = merge_values(Some(left), right, MergeRule::Deep)?;
            let mut current = &merged;
            for _ in 0..12_000 {
                current = current
                    .as_map()
                    .and_then(|map| map.get("child"))
                    .context("merged depth")?;
            }
            ensure!(current.as_map().context("merged leaf")?.len() == 2);
            drop(merged);
            Ok(())
        })?
        .join()
        .map_err(|_panic| anyhow::anyhow!("deep merge thread unwound"))?
}

#[test]
fn append_and_history_share_type_validation_and_provenance() -> anyhow::Result<()> {
    let path = Path::parse("state://sequence")?;
    let first_taint = TaintSet::of(TaintSource::ModelOutput);
    let current = append_value(&path, None, Value::integer(1), first_taint.clone())?;
    let snapshot = current.clone();
    let second_taint = TaintSet::author();
    let appended = append_value(
        &path,
        Some(&current),
        Value::integer(2),
        second_taint.clone(),
    )?;
    let mut combined = first_taint;
    combined.union(&second_taint);
    ensure!(appended.taint == combined);
    ensure!(appended.value == Value::list(vec![Value::integer(1), Value::integer(2)]));
    ensure!(current == snapshot);
    let event = crate::StateEvent::Append {
        path,
        item: Value::integer(2),
        taint: second_taint,
    };
    let mut replay = Some(current);
    crate::apply_history_event(&mut replay, &event)?;
    ensure!(replay == Some(appended));
    let mut invalid = Some(TaintedValue::pristine(Value::integer(9)));
    let before = invalid.clone();
    ensure!(crate::apply_history_event(&mut invalid, &event).is_err());
    ensure!(invalid == before);
    ensure!(matches!(
        invalid
            .as_ref()
            .context("retained invalid value")?
            .value
            .view(),
        ValueView::Int(9)
    ));
    Ok(())
}
