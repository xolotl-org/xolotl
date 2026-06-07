use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nexus_state::{InMemoryBackend, StateBackend};
use nexus_types::{Path, Value};
use std::hint::black_box;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

const ITEMS: u32 = 1_024;

fn runtime() -> Runtime {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime must build")
}

fn path(s: &str) -> Path {
    Path::parse(s).expect("benchmark path must parse")
}

fn prepopulate_prefix(rt: &Runtime, backend: &InMemoryBackend, keys: u32) {
    rt.block_on(async {
        for i in 0..keys {
            backend
                .write_set(
                    &path(&format!("state://bench/prefix/k{i}")),
                    Value::Int(i as i64),
                )
                .await
                .expect("state set must succeed");
        }
    });
}

fn prepopulate_sequence(rt: &Runtime, backend: &InMemoryBackend, path: &Path, items: u32) {
    rt.block_on(async {
        for i in 0..items {
            backend
                .write_append(path, Value::Int(i as i64))
                .await
                .expect("state append must succeed");
        }
    });
}

fn bench_current_values(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("state/in_memory/current");

    group.bench_function("write_set", |b| {
        b.iter_batched(
            || (InMemoryBackend::new(), path("state://bench/value")),
            |(backend, path)| {
                rt.block_on(async {
                    backend
                        .write_set(black_box(&path), black_box(Value::Int(1)))
                        .await
                        .expect("state set must succeed");
                });
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("read_current_value", |b| {
        let backend = InMemoryBackend::new();
        let p = path("state://bench/value");
        rt.block_on(async {
            backend
                .write_set(&p, Value::Int(1))
                .await
                .expect("state set must succeed");
        });
        b.iter(|| {
            let value = rt.block_on(async {
                backend
                    .read(black_box(&p))
                    .await
                    .expect("read must succeed")
            });
            black_box(value);
        });
    });

    group.bench_function("write_cas_success", |b| {
        b.iter_batched(
            || {
                let backend = InMemoryBackend::new();
                let p = path("state://bench/cas");
                rt.block_on(async {
                    backend
                        .write_set(&p, Value::Int(1))
                        .await
                        .expect("state set must succeed");
                });
                (backend, p)
            },
            |(backend, p)| {
                rt.block_on(async {
                    backend
                        .write_cas(
                            black_box(&p),
                            black_box(Some(Value::Int(1))),
                            black_box(Value::Int(2)),
                        )
                        .await
                        .expect("state CAS must succeed");
                });
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_sequences_and_history(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("state/in_memory/history");
    group.sample_size(10);

    group.bench_function("append_after_1024_items", |b| {
        b.iter_batched(
            || {
                let backend = InMemoryBackend::new();
                let p = path("state://bench/log");
                prepopulate_sequence(&rt, &backend, &p, ITEMS);
                (backend, p)
            },
            |(backend, p)| {
                rt.block_on(async {
                    backend
                        .write_append(black_box(&p), black_box(Value::Int(ITEMS as i64)))
                        .await
                        .expect("state append must succeed");
                });
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("read_prefix_1024_keys", |b| {
        b.iter_batched(
            || {
                let backend = InMemoryBackend::new();
                prepopulate_prefix(&rt, &backend, ITEMS);
                (backend, path("state://bench/prefix"))
            },
            |(backend, prefix)| {
                let rows = rt.block_on(async {
                    backend
                        .read_prefix(black_box(&prefix))
                        .await
                        .expect("prefix read must succeed")
                });
                black_box(rows);
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("read_range_1024_history_entries", |b| {
        b.iter_batched(
            || {
                let backend = InMemoryBackend::new();
                let p = path("state://bench/history");
                prepopulate_sequence(&rt, &backend, &p, ITEMS);
                (backend, p)
            },
            |(backend, p)| {
                let rows = rt.block_on(async {
                    backend
                        .read_range(black_box(&p), 0, i64::MAX)
                        .await
                        .expect("range read must succeed")
                });
                black_box(rows);
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_concurrency(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("state/in_memory/concurrency");

    group.bench_function("concurrent_write_set_64", |b| {
        b.iter(|| {
            let backend = Arc::new(InMemoryBackend::new());
            rt.block_on(async {
                let mut tasks = Vec::new();
                for i in 0..64u32 {
                    let backend = backend.clone();
                    tasks.push(tokio::spawn(async move {
                        backend
                            .write_set(
                                &Path::parse(&format!("state://bench/concurrent/k{i}"))
                                    .expect("path must parse"),
                                Value::Int(i as i64),
                            )
                            .await
                            .expect("state set must succeed");
                    }));
                }
                for task in tasks {
                    task.await.expect("state writer task must join");
                }
            });
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_current_values,
    bench_sequences_and_history,
    bench_concurrency
);
criterion_main!(benches);
