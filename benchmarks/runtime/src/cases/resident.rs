use super::{Config, Work};
use anyhow::{Context, ensure};
use std::hint::black_box;
use xolotl_types::{Value, ValueListBuilder};

pub(super) fn shared(width: usize) -> anyhow::Result<Value> {
    let payload = Value::bytes(vec![0x5a; 1024]);
    let mut list = ValueListBuilder::new();
    for _ in 0..width {
        list.push(payload.clone())?;
    }
    Ok(Value::from(list.finish()))
}

pub fn run(config: &Config) -> anyhow::Result<Work> {
    let original = shared(config.width.get())?;
    let mut changed = original.as_list().context("list")?.clone();
    let middle = config.width.get() / 2;
    drop(changed.set(middle, Value::integer(42))?);
    ensure!(
        original
            .as_list()
            .and_then(|list| list.get(middle))
            .and_then(Value::as_bytes)
            .is_some()
    );
    ensure!(changed.get(middle).and_then(Value::as_int) == Some(42));
    if config.width.get() > 1 {
        let untouched = if middle == 0 { 1 } else { 0 };
        ensure!(
            changed.get(untouched).and_then(Value::identity)
                == original
                    .as_list()
                    .and_then(|list| list.get(untouched))
                    .and_then(Value::identity)
        );
    }
    let mut deep = original.clone();
    for _ in 0..config.depth.get() {
        deep = Value::list(vec![deep]);
    }
    let cloned = deep.clone();
    ensure!(deep.identity() == cloned.identity());
    let mut dag = original;
    // Exponential logical size with only 25 distinct branch objects.
    for _ in 0..24 {
        dag = Value::list(vec![dag.clone(), dag]);
    }
    let encoded = serde_json::to_vec(&xolotl_types::tagged_value::serializable(&dag))?;
    let mut decoder = serde_json::Deserializer::from_slice(&encoded);
    let restored = xolotl_types::tagged_value::deserialize(&mut decoder)?;
    decoder.end()?;
    ensure!(black_box(&dag) == black_box(&restored));
    let children = restored.as_list().context("restored DAG")?;
    ensure!(children.get(0).and_then(Value::identity) == children.get(1).and_then(Value::identity));
    drop((changed, deep, cloned, dag, restored, encoded));
    Ok(Work {
        units: 1,
        unit: "wide copy/update, deep clone/drop, shared DAG encode/restore",
    })
}
