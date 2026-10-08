use super::*;
use alloc::{collections::BTreeMap, string::String, vec};
use anyhow::{Context, ensure};

#[test]
fn bounded_index_charges_shared_nodes_edges_keys_and_leaf_bytes() -> anyhow::Result<()> {
    let leaf = Value::bytes(vec![7; 4]);
    let shared = Value::list(vec![leaf.clone(), leaf]);
    let mut table = ValueTableEncoder::new();
    let root = table.intern_bounded(&shared, 8)?;
    ensure!(table.node_count() == 2);
    ensure!(
        serde_json::to_vec(&table.serializable_root(root))?
            == serde_json::to_vec(&serializable(&shared))?
    );
    ensure!(matches!(
        ValueTableEncoder::new().intern_bounded(&shared, 7),
        Err(ValueTableEncodeError::BudgetExceeded)
    ));
    let independent = Value::list(vec![Value::bytes(vec![7; 4]), Value::bytes(vec![7; 4])]);
    ensure!(matches!(
        ValueTableEncoder::new().intern_bounded(&independent, 8),
        Err(ValueTableEncodeError::BudgetExceeded)
    ));
    let map = Value::map(BTreeMap::from([(String::from("abcd"), Value::null())]));
    let mut table = ValueTableEncoder::new();
    ensure!(matches!(
        table.intern_bounded(&map, 5),
        Err(ValueTableEncodeError::BudgetExceeded)
    ));
    ensure!(table.node_count() == 0);
    ensure!(ValueTableEncoder::new().intern_bounded(&map, 7).is_ok());
    for leaf in [Value::from("abcd"), Value::bytes(vec![1; 4])] {
        ensure!(matches!(
            ValueTableEncoder::new().intern_bounded(&leaf, 4),
            Err(ValueTableEncodeError::BudgetExceeded)
        ));
        ensure!(ValueTableEncoder::new().intern_bounded(&leaf, 5).is_ok());
    }
    Ok(())
}

#[test]
fn bounded_index_rejects_depth_and_width_before_indexing_descendants() {
    let mut deep = Value::null();
    for _depth in 0..4096 {
        deep = Value::list(vec![deep]);
    }
    let wide = Value::list(vec![Value::null(); 4096]);
    let wide_map = Value::map(
        (0..4096)
            .map(|index| (alloc::format!("key-{index}"), Value::null()))
            .collect(),
    );
    let shared = Value::list(vec![Value::bytes(vec![1; 4096]); 4096]);
    for root in [&deep, &wide, &wide_map, &shared] {
        let mut table = ValueTableEncoder::new();
        assert!(matches!(
            table.intern_bounded(root, 16),
            Err(ValueTableEncodeError::BudgetExceeded)
        ));
        assert_eq!(table.node_count(), 0);
    }
}

#[derive(Serialize)]
struct Record<'table, 'value> {
    values: &'table ValueTableEncoder<'value>,
    input: ValueRoot,
    result: ValueRoot,
}

#[derive(Deserialize)]
struct RestoredRecord {
    values: ValueTableDecoder,
    input: ValueRoot,
    result: ValueRoot,
}

#[test]
fn one_table_preserves_sharing_between_independent_record_fields() -> anyhow::Result<()> {
    let shared = Value::bytes(vec![7; 128 * 1024]);
    let input = Value::map(BTreeMap::from([(String::from("payload"), shared.clone())]));
    let result = Value::list(vec![shared, Value::from("done")]);
    let mut values = ValueTableEncoder::new();
    let input_root = values.intern(&input)?;
    let result_root = values.intern(&result)?;
    ensure!(values.intern(&input)? == input_root);
    ensure!(values.node_count() == 4);
    let bytes = serde_json::to_vec(&Record {
        values: &values,
        input: input_root,
        result: result_root,
    })?;
    let decoded: RestoredRecord = serde_json::from_slice(&bytes)?;
    ensure!(decoded.values.node_count() == 4);
    let restored_input = decoded
        .values
        .resolve(decoded.input)
        .context("input root")?;
    let restored_result = decoded
        .values
        .resolve(decoded.result)
        .context("result root")?;
    let bad: ValueRoot = serde_json::from_str("18446744073709551615")?;
    ensure!(decoded.values.resolve(bad).is_none());
    drop(decoded);
    ensure!(restored_input == input && restored_result == result);
    let left = restored_input
        .as_map()
        .and_then(|map| map.get("payload"))
        .context("input payload")?;
    let right = restored_result
        .as_list()
        .and_then(|items| items.get(0))
        .context("result payload")?;
    ensure!(left.identity().is_some() && left.identity() == right.identity());
    Ok(())
}

#[test]
fn empty_and_malformed_shared_tables_have_one_strict_first_format() -> anyhow::Result<()> {
    let table = ValueTableEncoder::new();
    let bytes = serde_json::to_vec(&table)?;
    ensure!(bytes == br#"{"version":1,"nodes":[]}"#);
    let table: ValueTableDecoder = serde_json::from_slice(&bytes)?;
    ensure!(table.node_count() == 0);
    let root: ValueRoot = serde_json::from_str("0")?;
    ensure!(table.resolve(root).is_none());
    for invalid in [
        r#"{"version":99,"nodes":[]}"#,
        r#"{"version":1,"nodes":[],"root":0}"#,
        r#"{"version":1,"nodes":[{"list":[0]}]}"#,
        r#"{"version":1,"nodes":[],"nodes":[]}"#,
        r#"{"version":1}"#,
    ] {
        ensure!(serde_json::from_str::<ValueTableDecoder>(invalid).is_err());
    }
    Ok(())
}

#[test]
fn deep_shared_record_roots_decode_and_release_on_a_small_stack() -> anyhow::Result<()> {
    std::thread::Builder::new()
        .stack_size(128 * 1024)
        .spawn(|| -> anyhow::Result<()> {
            let mut input = Value::null();
            for _ in 0..20_000 {
                input = Value::list(vec![input]);
            }
            let result = Value::list(vec![input.clone(), input.clone()]);
            let mut values = ValueTableEncoder::new();
            let first = values.intern(&input)?;
            let second = values.intern(&result)?;
            ensure!(values.node_count() == 20_002);
            let bytes = serde_json::to_vec(&Record {
                values: &values,
                input: first,
                result: second,
            })?;
            let record: RestoredRecord = serde_json::from_slice(&bytes)?;
            let first = record.values.resolve(record.input).context("first root")?;
            let second = record
                .values
                .resolve(record.result)
                .context("second root")?;
            drop(record);
            ensure!(first == input && second == result);
            ensure!(
                second
                    .as_list()
                    .and_then(|items| items.get(0))
                    .and_then(Value::identity)
                    == first.identity()
            );
            Ok(())
        })?
        .join()
        .map_err(|_error| anyhow::anyhow!("shared record worker panicked"))??;
    Ok(())
}
