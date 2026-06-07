use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nexus_actors::fetch::{INLINE_BODY_LIMIT, body_to_value};
use nexus_actors::{IndexDriver, InferenceDriver, MemoryDriver, validate_url};
use nexus_kernel::{Driver, DriverContext};
use nexus_state::{Backend, InMemoryBackend};
use nexus_types::{FloatBits, IdentityRef, MethodId, Outcome, OutputMode, ProcessId, Value};
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

const EXACT_INDEX_ITEMS: usize = 1_024;
const ANN_INDEX_ITEMS: usize = 5_000;
const VECTOR_DIMS: usize = 32;
const MEMORY_RECALL_ITEMS: usize = 256;

fn runtime() -> Runtime {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime must build")
}

fn ctx() -> DriverContext {
    DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
}

fn patterned_vector(seed: usize, dims: usize) -> Value {
    Value::List(
        (0..dims)
            .map(|dim| {
                let n = ((seed.wrapping_mul(31)) ^ (dim.wrapping_mul(17))) % 257;
                let x = (n as f64 / 128.0) - 1.0;
                Value::Float(FloatBits(x))
            })
            .collect(),
    )
}

fn index_item(space: &str, id: usize, dims: usize) -> Value {
    let mut m = BTreeMap::new();
    m.insert("space_id".into(), Value::Str(space.into()));
    m.insert("id".into(), Value::Str(format!("v{id}")));
    m.insert("vector".into(), patterned_vector(id, dims));
    Value::Map(m)
}

fn index_batch(space: &str, count: usize, dims: usize) -> Value {
    Value::List((0..count).map(|id| index_item(space, id, dims)).collect())
}

fn search_query(space: &str, seed: usize, dims: usize, k: i64) -> Value {
    let mut m = BTreeMap::new();
    m.insert("space_id".into(), Value::Str(space.into()));
    m.insert("query_vec".into(), patterned_vector(seed, dims));
    m.insert("k".into(), Value::Int(k));
    Value::Map(m)
}

fn delete_input(space: &str, id: usize) -> Value {
    let mut m = BTreeMap::new();
    m.insert("space_id".into(), Value::Str(space.into()));
    m.insert("id".into(), Value::Str(format!("v{id}")));
    Value::Map(m)
}

fn prepopulated_index(rt: &Runtime, space: &str, count: usize, dims: usize) -> IndexDriver {
    let driver = IndexDriver::new();
    let input = index_batch(space, count, dims);
    rt.block_on(async {
        let out = driver
            .call(MethodId::new(0), input, OutputMode::Unary, &ctx())
            .await
            .expect("index batch upsert must succeed");
        match out {
            Outcome::Done(Value::List(results)) => {
                assert_eq!(results.len(), count);
            }
            other => panic!("expected batch upsert result, got {other:?}"),
        }
    });
    driver
}

fn text_batch(count: usize) -> Value {
    Value::List(
        (0..count)
            .map(|i| {
                Value::Str(format!(
                    "benchmark document {i}: deterministic baseline text"
                ))
            })
            .collect(),
    )
}

fn rerank_request(query: &str, candidates: usize) -> Value {
    let mut m = BTreeMap::new();
    m.insert("query".into(), Value::Str(query.into()));
    m.insert(
        "candidates".into(),
        Value::List(
            (0..candidates)
                .map(|i| Value::Str(format!("candidate passage {i} for {query}")))
                .collect(),
        ),
    );
    Value::Map(m)
}

fn rerank_batch(requests: usize, candidates: usize) -> Value {
    Value::List(
        (0..requests)
            .map(|i| rerank_request(&format!("query {i}"), candidates))
            .collect(),
    )
}

fn memory_state() -> Backend {
    Arc::new(InMemoryBackend::new())
}

fn memory_store_input(owner: &str, id: usize) -> Value {
    let mut m = BTreeMap::new();
    m.insert("owner".into(), Value::Str(owner.into()));
    m.insert(
        "entry".into(),
        Value::Str(format!(
            "memory benchmark entry {id}: retrieval text about topic {}",
            id % 16
        )),
    );
    Value::Map(m)
}

fn memory_recall_input(owner: &str, query: &str, k: i64) -> Value {
    let mut m = BTreeMap::new();
    m.insert("owner".into(), Value::Str(owner.into()));
    m.insert("query".into(), Value::Str(query.into()));
    m.insert("k".into(), Value::Int(k));
    Value::Map(m)
}

fn prepopulated_memory(rt: &Runtime, owner: &str, entries: usize) -> MemoryDriver {
    let driver = MemoryDriver::new(memory_state());
    rt.block_on(async {
        for i in 0..entries {
            driver
                .call(
                    MethodId::new(0),
                    memory_store_input(owner, i),
                    OutputMode::Unary,
                    &ctx(),
                )
                .await
                .expect("memory store must succeed");
        }
    });
    driver
}

fn bench_index(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("actors/index");
    group.sample_size(10);

    group.bench_function("upsert_batch_128x32d", |b| {
        b.iter_batched(
            || (IndexDriver::new(), index_batch("upsert", 128, VECTOR_DIMS)),
            |(driver, input)| {
                let out = rt
                    .block_on(async {
                        driver
                            .call(
                                MethodId::new(0),
                                black_box(input),
                                OutputMode::Unary,
                                &ctx(),
                            )
                            .await
                    })
                    .expect("index upsert must succeed");
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("search_exact_1024x32d", |b| {
        b.iter_batched(
            || {
                let driver = prepopulated_index(&rt, "exact", EXACT_INDEX_ITEMS, VECTOR_DIMS);
                let query = search_query("exact", 17, VECTOR_DIMS, 10);
                (driver, query)
            },
            |(driver, query)| {
                let out = rt
                    .block_on(async {
                        driver
                            .call(
                                MethodId::new(1),
                                black_box(query),
                                OutputMode::Unary,
                                &ctx(),
                            )
                            .await
                    })
                    .expect("index exact search must succeed");
                black_box(out);
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("search_ann_5000x32d", |b| {
        b.iter_batched(
            || {
                let driver = prepopulated_index(&rt, "ann", ANN_INDEX_ITEMS, VECTOR_DIMS);
                let query = search_query("ann", 17, VECTOR_DIMS, 10);
                (driver, query)
            },
            |(driver, query)| {
                let out = rt
                    .block_on(async {
                        driver
                            .call(
                                MethodId::new(1),
                                black_box(query),
                                OutputMode::Unary,
                                &ctx(),
                            )
                            .await
                    })
                    .expect("index ANN search must succeed");
                black_box(out);
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("delete_existing_1024x32d", |b| {
        b.iter_batched(
            || {
                let driver = prepopulated_index(&rt, "delete", EXACT_INDEX_ITEMS, VECTOR_DIMS);
                let input = delete_input("delete", 17);
                (driver, input)
            },
            |(driver, input)| {
                let out = rt
                    .block_on(async {
                        driver
                            .call(
                                MethodId::new(2),
                                black_box(input),
                                OutputMode::Unary,
                                &ctx(),
                            )
                            .await
                    })
                    .expect("index delete must succeed");
                black_box(out);
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_inference(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("actors/inference");
    group.sample_size(10);

    group.bench_function("infer_unary_baseline", |b| {
        let driver = InferenceDriver::baseline();
        let input = Value::Str("Summarize the benchmark fixture in one sentence.".into());
        b.iter(|| {
            let out = rt
                .block_on(async {
                    driver
                        .call(
                            MethodId::new(0),
                            black_box(input.clone()),
                            OutputMode::Unary,
                            &ctx(),
                        )
                        .await
                })
                .expect("baseline infer must succeed");
            black_box(out);
        });
    });

    group.bench_function("embed_batch_128_baseline", |b| {
        b.iter_batched(
            || (InferenceDriver::baseline(), text_batch(128)),
            |(driver, input)| {
                let out = rt
                    .block_on(async {
                        driver
                            .call(
                                MethodId::new(1),
                                black_box(input),
                                OutputMode::Unary,
                                &ctx(),
                            )
                            .await
                    })
                    .expect("baseline embed must succeed");
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("rerank_batch_64x16_baseline", |b| {
        b.iter_batched(
            || (InferenceDriver::baseline(), rerank_batch(64, 16)),
            |(driver, input)| {
                let out = rt
                    .block_on(async {
                        driver
                            .call(
                                MethodId::new(2),
                                black_box(input),
                                OutputMode::Unary,
                                &ctx(),
                            )
                            .await
                    })
                    .expect("baseline rerank must succeed");
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_fetch(c: &mut Criterion) {
    let mut group = c.benchmark_group("actors/fetch");
    group.sample_size(10);

    group.bench_function("validate_public_https_url", |b| {
        b.iter(|| {
            let url = validate_url(black_box("https://example.com/path?q=1"))
                .expect("public https URL must validate");
            black_box(url);
        });
    });

    group.bench_function("validate_rejected_private_ipv4_url", |b| {
        b.iter(|| {
            let result = validate_url(black_box("http://127.0.0.1/admin"));
            assert!(result.is_err());
            let _ = black_box(result);
        });
    });

    group.bench_function("body_to_value_inline_text_4kb", |b| {
        b.iter_batched(
            || vec![b'a'; 4 * 1024],
            |bytes| {
                let value = body_to_value(black_box(bytes), Some("text/plain".into()));
                black_box(value);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("body_to_value_blob_threshold_1mb", |b| {
        b.iter_batched(
            || vec![b'a'; INLINE_BODY_LIMIT],
            |bytes| {
                let value =
                    body_to_value(black_box(bytes), Some("application/octet-stream".into()));
                black_box(value);
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_memory(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("actors/memory");
    group.sample_size(10);

    group.bench_function("store_one_baseline_pipeline", |b| {
        b.iter_batched(
            || {
                (
                    MemoryDriver::new(memory_state()),
                    memory_store_input("bench", 0),
                )
            },
            |(driver, input)| {
                let out = rt
                    .block_on(async {
                        driver
                            .call(
                                MethodId::new(0),
                                black_box(input),
                                OutputMode::Unary,
                                &ctx(),
                            )
                            .await
                    })
                    .expect("memory store must succeed");
                black_box(out);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("recall_256_entries_baseline_pipeline", |b| {
        b.iter_batched(
            || {
                let driver = prepopulated_memory(&rt, "bench", MEMORY_RECALL_ITEMS);
                let input = memory_recall_input("bench", "topic 7 retrieval text", 8);
                (driver, input)
            },
            |(driver, input)| {
                let out = rt
                    .block_on(async {
                        driver
                            .call(
                                MethodId::new(1),
                                black_box(input),
                                OutputMode::Unary,
                                &ctx(),
                            )
                            .await
                    })
                    .expect("memory recall must succeed");
                black_box(out);
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_index,
    bench_inference,
    bench_fetch,
    bench_memory
);
criterion_main!(benches);
