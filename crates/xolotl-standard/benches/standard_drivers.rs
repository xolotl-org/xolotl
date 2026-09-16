use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::collections::BTreeMap;
use std::hint::black_box;
use tokio::runtime::{Builder, Runtime};
use xolotl_graph::{DoNode, OperationTemplate};
use xolotl_kernel::Bootstrap;
use xolotl_standard::{StandardConfig, install_standard};
use xolotl_types::{Failure, FloatBits, Outcome, OutputMode, Path, ResourceName, Value};

const EXACT_INDEX_ITEMS: usize = 1_024;
const ANN_INDEX_ITEMS: usize = 5_000;
const IDENTICAL_INDEX_ITEMS: usize = 8_192;
const VECTOR_DIMS: usize = 32;
const MEMORY_RECALL_ITEMS: usize = 256;

fn setup_failure(message: impl Into<String>) -> Outcome {
    Outcome::Fail(Failure::HandlerError {
        kind: "benchmark_setup".into(),
        message: message.into(),
    })
}

fn runtime() -> Result<Runtime, Outcome> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| setup_failure(format!("tokio runtime build failed: {error}")))
}

fn bench_setup_failure(c: &mut Criterion, name: &'static str, outcome: Outcome) {
    c.bench_function(name, |b| b.iter(|| black_box(outcome.clone())));
}

fn boot() -> Result<Bootstrap, Outcome> {
    let boot = Bootstrap::in_memory();
    install_standard(&boot, &StandardConfig::default())
        .map_err(|error| setup_failure(format!("standard package install failed: {error}")))?;
    Ok(boot)
}

fn run_effect(rt: &Runtime, boot: &Bootstrap, path: &str, input: Value) -> Outcome {
    let target = match Path::parse(path) {
        Ok(path) => ResourceName::new(path),
        Err(error) => {
            return setup_failure(format!("benchmark effect path parse failed: {error}"));
        }
    };
    let handle = match boot.open_for(boot.root, &target, "perform") {
        Ok(handle) => handle,
        Err(error) => {
            return setup_failure(format!("benchmark effect open failed: {error}"));
        }
    };
    let ex = boot.kernel.executor_for(boot.root);
    ex.bind_handle(target.clone(), handle);
    rt.block_on(async {
        ex.eval(&DoNode::Op(OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: Some(input),
        }))
        .await
        .outcome
    })
}

fn patterned_vector(seed: usize, dims: usize) -> Value {
    xolotl_standard::EmbeddingRepresentation::Dense(
        (0..dims)
            .map(|dim| {
                let n = ((seed.wrapping_mul(31)) ^ (dim.wrapping_mul(17))) % 257;
                let x = (n as f64 / 128.0) - 1.0;
                Value::float(FloatBits(x))
            })
            .collect(),
    )
    .into_value()
}

fn index_item(space: &str, id: usize, dims: usize) -> Value {
    let mut m = BTreeMap::new();
    m.insert("space_id".into(), Value::string(space.into()));
    m.insert("id".into(), Value::string(format!("v{id}")));
    m.insert("representation".into(), patterned_vector(id, dims));
    Value::map(m)
}

fn index_batch(space: &str, count: usize, dims: usize) -> Value {
    Value::list((0..count).map(|id| index_item(space, id, dims)).collect())
}

fn search_query(space: &str, seed: usize, dims: usize, k: i64) -> Value {
    let mut m = BTreeMap::new();
    m.insert("space_id".into(), Value::string(space.into()));
    m.insert("representation".into(), patterned_vector(seed, dims));
    m.insert("k".into(), Value::integer(k));
    Value::map(m)
}

fn delete_input(space: &str, id: usize) -> Value {
    let mut m = BTreeMap::new();
    m.insert("space_id".into(), Value::string(space.into()));
    m.insert("id".into(), Value::string(format!("v{id}")));
    Value::map(m)
}

fn prepopulated_index(
    rt: &Runtime,
    space: &str,
    count: usize,
    dims: usize,
) -> Result<Bootstrap, Outcome> {
    populate_index(rt, index_batch(space, count, dims), count)
}

fn populate_index(rt: &Runtime, input: Value, count: usize) -> Result<Bootstrap, Outcome> {
    let boot = boot()?;
    let out = run_effect(rt, &boot, "effect://index/upsert", input);
    match out {
        Outcome::Done(value) => {
            let results = value
                .as_list()
                .ok_or_else(|| setup_failure("expected batch upsert list"))?;
            if results.len() != count
                || results.iter().any(|result| result != &Value::boolean(true))
            {
                return Err(setup_failure(format!(
                    "expected {count} index upsert results, got {}",
                    results.len()
                )));
            }
        }
        other => {
            return Err(setup_failure(format!(
                "expected batch upsert result, got {other:?}"
            )));
        }
    }
    Ok(boot)
}

fn text_batch(count: usize) -> Value {
    Value::list(
        (0..count)
            .map(|i| {
                Value::string(format!(
                    "benchmark document {i}: deterministic baseline text"
                ))
            })
            .collect(),
    )
}

fn rerank_request(query: &str, candidates: usize) -> Value {
    let mut m = BTreeMap::new();
    m.insert("query".into(), Value::string(query.into()));
    m.insert(
        "candidates".into(),
        Value::list(
            (0..candidates)
                .map(|i| Value::string(format!("candidate passage {i} for {query}")))
                .collect(),
        ),
    );
    Value::map(m)
}

fn rerank_batch(requests: usize, candidates: usize) -> Value {
    Value::list(
        (0..requests)
            .map(|i| rerank_request(&format!("query {i}"), candidates))
            .collect(),
    )
}

fn memory_store_input(owner: &str, id: usize) -> Value {
    let mut m = BTreeMap::new();
    m.insert("owner".into(), Value::string(owner.into()));
    m.insert(
        "entry".into(),
        Value::string(format!(
            "memory benchmark entry {id}: retrieval text about topic {}",
            id % 16
        )),
    );
    Value::map(m)
}

fn memory_recall_input(owner: &str, query: &str, k: i64) -> Value {
    let mut m = BTreeMap::new();
    m.insert("owner".into(), Value::string(owner.into()));
    m.insert("query".into(), Value::string(query.into()));
    m.insert("k".into(), Value::integer(k));
    Value::map(m)
}

fn prepopulated_memory(rt: &Runtime, owner: &str, entries: usize) -> Result<Bootstrap, Outcome> {
    let boot = boot()?;
    for i in 0..entries {
        let out = run_effect(
            rt,
            &boot,
            "effect://memory/store",
            memory_store_input(owner, i),
        );
        if !matches!(out, Outcome::Done(_)) {
            return Err(setup_failure(format!(
                "memory prepopulate entry {i} failed: {out:?}"
            )));
        }
    }
    Ok(boot)
}

fn bench_index(c: &mut Criterion) {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(outcome) => {
            bench_setup_failure(c, "standard/index/runtime_setup_failed", outcome);
            return;
        }
    };
    let mut group = c.benchmark_group("standard/index");
    group.sample_size(10);

    group.bench_function("upsert_batch_128x32d", |b| {
        b.iter_batched(
            || boot().map(|boot| (boot, index_batch("upsert", 128, VECTOR_DIMS))),
            |setup| match setup {
                Ok((boot, input)) => {
                    let out = run_effect(&rt, &boot, "effect://index/upsert", black_box(input));
                    black_box(out);
                }
                Err(outcome) => {
                    black_box(outcome);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("search_exact_1024x32d", |b| {
        b.iter_batched_ref(
            || {
                let setup = prepopulated_index(&rt, "exact", EXACT_INDEX_ITEMS, VECTOR_DIMS)
                    .map(|boot| (boot, search_query("exact", 17, VECTOR_DIMS, 10)));
                assert!(
                    setup.is_ok(),
                    "index setup failed: {:?}",
                    setup.as_ref().err()
                );
                setup
            },
            |setup: &mut Result<(Bootstrap, Value), Outcome>| match setup {
                Ok((boot, query)) => {
                    let out = run_effect(
                        &rt,
                        boot,
                        "effect://index/search",
                        black_box(std::mem::take(query)),
                    );
                    assert_search_result(&out);
                    black_box(out)
                }
                Err(outcome) => black_box(outcome.clone()),
            },
            BatchSize::PerIteration,
        );
    });

    group.bench_function("search_ann_5000x32d", |b| {
        b.iter_batched_ref(
            || {
                let setup = prepopulated_index(&rt, "ann", ANN_INDEX_ITEMS, VECTOR_DIMS)
                    .map(|boot| (boot, search_query("ann", 17, VECTOR_DIMS, 10)));
                assert!(
                    setup.is_ok(),
                    "index setup failed: {:?}",
                    setup.as_ref().err()
                );
                setup
            },
            |setup: &mut Result<(Bootstrap, Value), Outcome>| match setup {
                Ok((boot, query)) => {
                    let out = run_effect(
                        &rt,
                        boot,
                        "effect://index/search",
                        black_box(std::mem::take(query)),
                    );
                    assert_search_result(&out);
                    black_box(out)
                }
                Err(outcome) => black_box(outcome.clone()),
            },
            BatchSize::PerIteration,
        );
    });

    group.bench_function("delete_existing_1024x32d", |b| {
        b.iter_batched(
            || {
                let boot = prepopulated_index(&rt, "delete", EXACT_INDEX_ITEMS, VECTOR_DIMS)?;
                let input = delete_input("delete", 17);
                Ok((boot, input))
            },
            |setup: Result<(Bootstrap, Value), Outcome>| match setup {
                Ok((boot, input)) => {
                    let out = run_effect(&rt, &boot, "effect://index/delete", black_box(input));
                    black_box(out);
                }
                Err(outcome) => {
                    black_box(outcome);
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("delete_identical_8192x1d", |b| {
        b.iter_batched_ref(
            || {
                let space = "delete-identical";
                let items = Value::list(
                    (0..IDENTICAL_INDEX_ITEMS)
                        .map(|id| {
                            Value::map(BTreeMap::from([
                                ("space_id".into(), Value::string(space.into())),
                                ("id".into(), Value::string(format!("v{id}"))),
                                (
                                    "representation".into(),
                                    xolotl_standard::EmbeddingRepresentation::Dense(
                                        vec![Value::integer(1)].into(),
                                    )
                                    .into_value(),
                                ),
                            ]))
                        })
                        .collect(),
                );
                let setup = populate_index(&rt, items, IDENTICAL_INDEX_ITEMS).map(|boot| {
                    let inputs = (0..IDENTICAL_INDEX_ITEMS)
                        .map(|id| delete_input(space, id))
                        .collect();
                    (boot, inputs)
                });
                assert!(
                    setup.is_ok(),
                    "index setup failed: {:?}",
                    setup.as_ref().err()
                );
                setup
            },
            |setup: &mut Result<(Bootstrap, Vec<Value>), Outcome>| match setup {
                Ok((boot, inputs)) => {
                    let mut completed = 0;
                    for input in std::mem::take(inputs) {
                        let out = run_effect(&rt, boot, "effect://index/delete", black_box(input));
                        assert_eq!(out, Outcome::Done(Value::boolean(true)));
                        black_box(out);
                        completed += 1;
                    }
                    black_box(completed)
                }
                Err(_) => black_box(0),
            },
            BatchSize::PerIteration,
        );
    });

    group.finish();
}

fn assert_search_result(outcome: &Outcome) {
    let valid = match outcome {
        Outcome::Done(value) => value.as_list().is_some_and(|hits| {
            hits.len() == 10
                && hits.iter().all(|hit| {
                    matches!(hit.as_map().and_then(|fields| fields.get("sim")).map(Value::view),
                    Some(xolotl_types::ValueView::Float(FloatBits(score)))
                        if score.is_finite() && (-1.000001..=1.000001).contains(&score))
                })
        }),
        _ => false,
    };
    assert!(
        valid,
        "index search did not return ten finite similarities: {outcome:?}"
    );
}

fn bench_inference(c: &mut Criterion) {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(outcome) => {
            bench_setup_failure(c, "standard/inference/runtime_setup_failed", outcome);
            return;
        }
    };
    let mut group = c.benchmark_group("standard/inference");
    group.sample_size(10);

    group.bench_function("infer_unary_baseline", |b| {
        let boot = boot();
        let input = Value::string("Summarize the benchmark fixture in one sentence.".into());
        b.iter(|| match &boot {
            Ok(boot) => {
                let out = run_effect(
                    &rt,
                    boot,
                    "effect://inference/infer",
                    black_box(input.clone()),
                );
                black_box(out);
            }
            Err(outcome) => {
                black_box(outcome.clone());
            }
        });
    });

    group.bench_function("embed_batch_128_baseline", |b| {
        b.iter_batched(
            || boot().map(|boot| (boot, text_batch(128))),
            |setup| match setup {
                Ok((boot, input)) => {
                    let out = run_effect(&rt, &boot, "effect://inference/embed", black_box(input));
                    black_box(out);
                }
                Err(outcome) => {
                    black_box(outcome);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("rerank_batch_64x16_baseline", |b| {
        b.iter_batched(
            || boot().map(|boot| (boot, rerank_batch(64, 16))),
            |setup| match setup {
                Ok((boot, input)) => {
                    let out = run_effect(&rt, &boot, "effect://inference/rerank", black_box(input));
                    black_box(out);
                }
                Err(outcome) => {
                    black_box(outcome);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_memory(c: &mut Criterion) {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(outcome) => {
            bench_setup_failure(c, "standard/memory/runtime_setup_failed", outcome);
            return;
        }
    };
    let mut group = c.benchmark_group("standard/memory");
    group.sample_size(10);

    group.bench_function("store_one_baseline_pipeline", |b| {
        b.iter_batched(
            || boot().map(|boot| (boot, memory_store_input("bench", 0))),
            |setup| match setup {
                Ok((boot, input)) => {
                    let out = run_effect(&rt, &boot, "effect://memory/store", black_box(input));
                    black_box(out);
                }
                Err(outcome) => {
                    black_box(outcome);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("recall_256_entries_baseline_pipeline", |b| {
        b.iter_batched(
            || {
                let boot = prepopulated_memory(&rt, "bench", MEMORY_RECALL_ITEMS)?;
                let input = memory_recall_input("bench", "topic 7 retrieval text", 8);
                Ok((boot, input))
            },
            |setup: Result<(Bootstrap, Value), Outcome>| match setup {
                Ok((boot, input)) => {
                    let out = run_effect(&rt, &boot, "effect://memory/recall", black_box(input));
                    black_box(out);
                }
                Err(outcome) => {
                    black_box(outcome);
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_index, bench_inference, bench_memory);
criterion_main!(benches);
