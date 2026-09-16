use super::*;
use alloc::{collections::BTreeMap, string::String, vec};
use anyhow::{Context, ensure};

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
