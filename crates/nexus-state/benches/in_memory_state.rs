use anyhow::{Result, anyhow};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nexus_state::{InMemoryBackend, StateBackend};
use nexus_types::{Path, Value};
use std::hint::black_box;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

const ITEMS: u32 = 1_024;

fn runtime() -> Result<Runtime> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow!("tokio runtime build failed: {error}"))
}

fn path(s: &str) -> Result<Path> {
    Path::parse(s).map_err(|error| anyhow!("benchmark path parse failed for {s}: {error}"))
}

fn bench_setup_failure(c: &mut Criterion, name: &'static str, error: anyhow::Error) {
    let message = error.to_string();
    c.bench_function(name, |b| b.iter(|| black_box(message.as_str())));
}

fn observe<T>(result: Result<T>) {
    match result {
        Ok(value) => drop(black_box(value)),
        Err(error) => observe_error(error),
    }
}

fn observe_error(error: anyhow::Error) {
    let message = error.to_string();
    drop(black_box(message));
}

fn prepopulate_prefix(rt: &Runtime, backend: &InMemoryBackend, keys: u32) -> Result<()> {
    rt.block_on(async {
        for i in 0..keys {
            let path = path(&format!("state://bench/prefix/k{i}"))?;
            backend
                .write_set(&path, Value::Int(i as i64))
                .await
                .map_err(|error| anyhow!("state set failed during prefix prepopulate: {error}"))?;
        }
        Ok::<(), anyhow::Error>(())
    })
}

fn prepopulate_sequence(
    rt: &Runtime,
    backend: &InMemoryBackend,
    path: &Path,
    items: u32,
) -> Result<()> {
    rt.block_on(async {
        for i in 0..items {
            backend
                .write_append(path, Value::Int(i as i64))
                .await
                .map_err(|error| {
                    anyhow!("state append failed during sequence prepopulate: {error}")
                })?;
        }
        Ok::<(), anyhow::Error>(())
    })
}

fn bench_current_values(c: &mut Criterion) {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(error) => {
            bench_setup_failure(c, "state/in_memory/runtime_setup_failed", error);
            return;
        }
    };
    let mut group = c.benchmark_group("state/in_memory/current");

    group.bench_function("write_set", |b| {
        b.iter_batched(
            || path("state://bench/value").map(|path| (InMemoryBackend::new(), path)),
            |setup| match setup {
                Ok((backend, path)) => {
                    let result: Result<()> = rt.block_on(async {
                        backend
                            .write_set(black_box(&path), black_box(Value::Int(1)))
                            .await
                            .map_err(|error| anyhow!("state set failed: {error}"))
                    });
                    observe(result);
                }
                Err(error) => {
                    observe_error(error);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("read_current_value", |b| {
        let setup = path("state://bench/value").and_then(|p| {
            let backend = InMemoryBackend::new();
            rt.block_on(async {
                backend
                    .write_set(&p, Value::Int(1))
                    .await
                    .map_err(|error| anyhow!("state set failed: {error}"))?;
                Ok::<(InMemoryBackend, Path), anyhow::Error>((backend, p))
            })
        });
        match setup {
            Ok((backend, p)) => {
                b.iter(|| {
                    let value: Result<Option<Value>> = rt.block_on(async {
                        backend
                            .read(black_box(&p))
                            .await
                            .map_err(|error| anyhow!("state read failed: {error}"))
                    });
                    observe(value);
                });
            }
            Err(error) => {
                b.iter(|| observe_error(anyhow!("{error}")));
            }
        }
    });

    group.bench_function("write_cas_success", |b| {
        b.iter_batched(
            || {
                let backend = InMemoryBackend::new();
                let p = path("state://bench/cas")?;
                rt.block_on(async {
                    backend
                        .write_set(&p, Value::Int(1))
                        .await
                        .map_err(|error| anyhow!("state set failed before CAS: {error}"))?;
                    Ok::<(InMemoryBackend, Path), anyhow::Error>((backend, p))
                })
            },
            |setup| match setup {
                Ok((backend, p)) => {
                    let result: Result<()> = rt.block_on(async {
                        backend
                            .write_cas(
                                black_box(&p),
                                black_box(Some(Value::Int(1))),
                                black_box(Value::Int(2)),
                            )
                            .await
                            .map_err(|error| anyhow!("state CAS failed: {error}"))
                    });
                    observe(result);
                }
                Err(error) => {
                    observe_error(error);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_sequences_and_history(c: &mut Criterion) {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(error) => {
            bench_setup_failure(c, "state/in_memory/history_runtime_setup_failed", error);
            return;
        }
    };
    let mut group = c.benchmark_group("state/in_memory/history");
    group.sample_size(10);

    group.bench_function("append_after_1024_items", |b| {
        b.iter_batched(
            || {
                let backend = InMemoryBackend::new();
                let p = path("state://bench/log")?;
                prepopulate_sequence(&rt, &backend, &p, ITEMS)?;
                Ok::<(InMemoryBackend, Path), anyhow::Error>((backend, p))
            },
            |setup| match setup {
                Ok((backend, p)) => {
                    let result: Result<()> = rt.block_on(async {
                        backend
                            .write_append(black_box(&p), black_box(Value::Int(ITEMS as i64)))
                            .await
                            .map_err(|error| anyhow!("state append failed: {error}"))
                    });
                    observe(result);
                }
                Err(error) => {
                    observe_error(error);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("read_prefix_1024_keys", |b| {
        b.iter_batched(
            || {
                let backend = InMemoryBackend::new();
                prepopulate_prefix(&rt, &backend, ITEMS)?;
                let prefix = path("state://bench/prefix")?;
                Ok::<(InMemoryBackend, Path), anyhow::Error>((backend, prefix))
            },
            |setup| match setup {
                Ok((backend, prefix)) => {
                    let rows: Result<Vec<(Path, Value)>> = rt.block_on(async {
                        backend
                            .read_prefix(black_box(&prefix))
                            .await
                            .map_err(|error| anyhow!("prefix read failed: {error}"))
                    });
                    observe(rows);
                }
                Err(error) => {
                    observe_error(error);
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("read_range_1024_history_entries", |b| {
        b.iter_batched(
            || {
                let backend = InMemoryBackend::new();
                let p = path("state://bench/history")?;
                prepopulate_sequence(&rt, &backend, &p, ITEMS)?;
                Ok::<(InMemoryBackend, Path), anyhow::Error>((backend, p))
            },
            |setup| match setup {
                Ok((backend, p)) => {
                    let rows = rt.block_on(async {
                        backend
                            .read_range(black_box(&p), 0, i64::MAX)
                            .await
                            .map_err(|error| anyhow!("range read failed: {error}"))
                    });
                    observe(rows);
                }
                Err(error) => {
                    observe_error(error);
                }
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn bench_concurrency(c: &mut Criterion) {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(error) => {
            bench_setup_failure(c, "state/in_memory/concurrency_runtime_setup_failed", error);
            return;
        }
    };
    let mut group = c.benchmark_group("state/in_memory/concurrency");

    group.bench_function("concurrent_write_set_64", |b| {
        b.iter(|| {
            let backend = Arc::new(InMemoryBackend::new());
            let result: Result<()> = rt.block_on(async {
                let mut tasks = Vec::new();
                for i in 0..64u32 {
                    let backend = backend.clone();
                    tasks.push(tokio::spawn(async move {
                        let path = path(&format!("state://bench/concurrent/k{i}"))?;
                        backend
                            .write_set(&path, Value::Int(i as i64))
                            .await
                            .map_err(|error| anyhow!("state set failed in writer task: {error}"))
                    }));
                }
                for task in tasks {
                    let result = task
                        .await
                        .map_err(|error| anyhow!("state writer task join failed: {error}"))?;
                    result?;
                }
                Ok::<(), anyhow::Error>(())
            });
            observe(result);
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
