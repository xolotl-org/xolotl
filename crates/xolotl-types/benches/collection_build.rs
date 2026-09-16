//! Compare actual production construction APIs on identical resident inputs.
//! Timing includes construction and release; source fixtures are prepared once.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use xolotl_types::{
    CollectionError, Value, ValueList, ValueListBuilder, ValueMap, ValueMapBuilder,
};

#[expect(
    clippy::panic,
    reason = "a failed construction must abort the benchmark rather than count as a fast sample"
)]
fn successful<T>(result: Result<T, CollectionError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("collection benchmark construction failed: {error}"),
    }
}

fn list_updates(input: &[Value]) -> Result<ValueList, CollectionError> {
    let mut values = ValueList::new();
    for value in input {
        values.push(value.clone())?;
    }
    Ok(values)
}

fn list_assembly(input: &[Value]) -> Result<ValueList, CollectionError> {
    let mut values = ValueListBuilder::new();
    for value in input {
        values.push(value.clone())?;
    }
    Ok(values.finish())
}

fn map_updates(input: &[(String, Value)]) -> Result<ValueMap, CollectionError> {
    let mut values = ValueMap::new();
    for (key, value) in input {
        drop(values.insert(key.clone(), value.clone())?);
    }
    Ok(values)
}

fn map_assembly(input: &[(String, Value)]) -> Result<ValueMap, CollectionError> {
    let mut values = ValueMapBuilder::new();
    for (key, value) in input {
        values.append(key.clone(), value.clone())?;
    }
    Ok(values.finish())
}

fn construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("collection_build");
    group.sample_size(20);
    let text = Value::string("one shared model response payload".repeat(128));
    let bytes = Value::bytes(vec![128; 4096]);
    for width in [32, 1024, 32_768] {
        let list: Vec<_> = (0..width)
            .map(|index| match index % 3 {
                0 => Value::integer(index as i64),
                1 => text.clone(),
                _ => bytes.clone(),
            })
            .collect();
        let map: Vec<_> = list
            .iter()
            .enumerate()
            .map(|(index, value)| (format!("entry-{index:08}"), value.clone()))
            .collect();
        for values in [
            successful(list_updates(&list)),
            successful(list_assembly(&list)),
        ] {
            assert_eq!(values.len(), width);
            assert!(values.iter().eq(list.iter()));
        }
        for values in [
            successful(map_updates(&map)),
            successful(map_assembly(&map)),
        ] {
            assert_eq!(values.len(), width);
            assert!(
                values
                    .iter()
                    .eq(map.iter().map(|(key, value)| (key.as_str(), value)))
            );
        }
        group.throughput(Throughput::Elements(width as u64));
        group.bench_with_input(
            BenchmarkId::new("list_updates", width),
            &list,
            |b, values| {
                b.iter(|| black_box(successful(list_updates(black_box(values)))));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("list_assembly", width),
            &list,
            |b, values| {
                b.iter(|| black_box(successful(list_assembly(black_box(values)))));
            },
        );
        group.bench_with_input(BenchmarkId::new("map_updates", width), &map, |b, values| {
            b.iter(|| black_box(successful(map_updates(black_box(values)))));
        });
        group.bench_with_input(
            BenchmarkId::new("map_assembly", width),
            &map,
            |b, values| {
                b.iter(|| black_box(successful(map_assembly(black_box(values)))));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, construction);
criterion_main!(benches);
