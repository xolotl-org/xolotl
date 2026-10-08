use anyhow::{Context, Result, anyhow, ensure};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::io::Write;
use std::num::NonZeroUsize;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use tokio::runtime::{Builder, Runtime};
use xolotl_state::{
    InMemoryBackend, InMemoryOptions, MemoryHistory, StateHistoryQuery, StateHistoryTrimLimits,
    StateScan, prelude::*,
};
use xolotl_types::{Path, TaintSet, TaintSource, Value};

const ITEMS: u32 = 1_024;
const THREADS: usize = 8;
const OPERATIONS_PER_THREAD: u32 = 1_024;

fn configurations() -> [(&'static str, InMemoryOptions); 5] {
    let compact = InMemoryOptions {
        history: MemoryHistory::Full,
        ..InMemoryOptions::default()
    };
    let sharded = InMemoryOptions {
        read_shards: NonZeroUsize::MIN.saturating_add(31),
        ..compact
    };
    [
        ("compact", compact),
        ("sharded_32", sharded),
        (
            "sharded_128",
            InMemoryOptions {
                read_shards: NonZeroUsize::MIN.saturating_add(127),
                ..compact
            },
        ),
        (
            "compact_current_only",
            InMemoryOptions {
                history: MemoryHistory::Disabled,
                ..compact
            },
        ),
        (
            "sharded_32_current_only",
            InMemoryOptions {
                history: MemoryHistory::Disabled,
                ..sharded
            },
        ),
    ]
}

fn runtime() -> Result<Runtime> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .context("benchmark runtime build failed")
}

fn path(s: &str) -> Result<Path> {
    Path::parse(s).map_err(|error| anyhow!("benchmark path parse failed for {s}: {error}"))
}

fn required<T, E: std::fmt::Display>(result: std::result::Result<T, E>) -> T {
    result.unwrap_or_else(|error| {
        let message = format!("state benchmark failed: {error}");
        let _reported = writeln!(std::io::stderr().lock(), "{message}");
        std::panic::resume_unwind(Box::new(message));
    })
}

fn prepopulate_prefix(rt: &Runtime, backend: &InMemoryBackend, keys: u32) -> Result<()> {
    rt.block_on(async {
        for i in 0..keys {
            let path = path(&format!("state://bench/prefix/k{i}"))?;
            backend
                .write_set(&path, Value::integer(i64::from(i)))
                .await?;
        }
        Ok(())
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
                .write_append(path, Value::integer(i64::from(i)))
                .await?;
        }
        Ok(())
    })
}

fn bench_current_values(c: &mut Criterion) {
    for (name, options) in configurations() {
        bench_current_values_for(c, name, options);
    }
}

fn bench_source_fingerprint(c: &mut Criterion) {
    let mut deep = Value::null();
    for _depth in 0..65_536 {
        deep = Value::list(vec![deep]);
    }
    let wide = Value::list(vec![Value::null(); 65_536]);
    let shared = Value::list(vec![Value::bytes(vec![255; 16 * 1024]); 64]);
    let mut group = c.benchmark_group("state/source_fingerprint");
    for (name, value, budget) in [
        ("deep_reject", &deep, 1024),
        ("wide_reject", &wide, 1024),
        ("shared_accept", &shared, 1024 * 1024),
    ] {
        group.bench_function(name, |bench| {
            bench.iter(|| {
                black_box(required(
                    xolotl_state::host::source_payload_fingerprint_bounded(
                        black_box(value),
                        budget,
                    ),
                ))
            })
        });
    }
    group.finish();
}

fn bench_current_values_for(c: &mut Criterion, name: &str, options: InMemoryOptions) {
    let rt = required(runtime());
    let create = || required(InMemoryBackend::with_options(options));
    let value_path = required(path("state://bench/value"));
    let cas_path = required(path("state://bench/cas"));
    let mut group = c.benchmark_group(format!("state/in_memory/{name}/current"));

    group.bench_function("write_set", |b| {
        b.iter_batched_ref(
            create,
            |backend| {
                required(rt.block_on(
                    backend.write_set(black_box(&value_path), black_box(Value::integer(1))),
                ));
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("read_current_value", |b| {
        let backend = create();
        required(rt.block_on(backend.write_set(&value_path, Value::integer(1))));
        b.iter(|| {
            drop(black_box(required(
                rt.block_on(backend.read(black_box(&value_path))),
            )));
        });
    });

    group.bench_function("write_cas_success", |b| {
        b.iter_batched_ref(
            || {
                let backend = create();
                required(rt.block_on(backend.write_set(&cas_path, Value::integer(1))));
                backend
            },
            |backend| {
                required(rt.block_on(backend.write_cas(
                    black_box(&cas_path),
                    black_box(Some(Value::integer(1))),
                    black_box(Value::integer(2)),
                )));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_absence_replacement(c: &mut Criterion) {
    let rt = required(runtime());
    let target = required(path("state://absence-bench/target"));
    let taint = TaintSet::of(TaintSource::ModelOutput);
    let mut group = c.benchmark_group("state/in_memory/absence_replacement");
    for read_shards in [NonZeroUsize::MIN, NonZeroUsize::MIN.saturating_add(31)] {
        for records in [1_024_u32, 16_384] {
            let backend = required(InMemoryBackend::with_options(InMemoryOptions {
                read_shards,
                history: MemoryHistory::Disabled,
                ..InMemoryOptions::default()
            }));
            required(rt.block_on(async {
                for index in 0..records {
                    let key = path(&format!("state://absence-bench/retained/{index:05}"))?;
                    backend
                        .write_set_tainted(&key, Value::integer(1), taint.clone())
                        .await?;
                    backend.write_delete(&key).await?;
                }
                Ok::<(), anyhow::Error>(())
            }));
            group.bench_function(format!("shards_{read_shards}/records_{records}"), |bench| {
                bench.iter(|| {
                    required(rt.block_on(async {
                        backend
                            .write_set_tainted(black_box(&target), Value::integer(1), taint.clone())
                            .await?;
                        backend.write_delete(black_box(&target)).await?;
                        Ok::<(), anyhow::Error>(())
                    }));
                });
            });
            let observed = required(rt.block_on(backend.read_at(&target, 0)));
            required((|| -> Result<()> {
                ensure!(observed.value.is_none() && observed.taint == taint);
                Ok(())
            })());
        }
    }
    group.finish();
}

fn bench_sequences_and_history(c: &mut Criterion) {
    for (name, options) in configurations() {
        if options.history == MemoryHistory::Full {
            bench_sequences_and_history_for(c, name, options);
        }
    }
}

fn bench_sequences_and_history_for(c: &mut Criterion, name: &str, options: InMemoryOptions) {
    let rt = required(runtime());
    let create = || required(InMemoryBackend::with_options(options));
    let sequence_path = required(path("state://bench/log"));
    let prefix = required(path("state://bench/prefix"));
    let history_path = required(path("state://bench/history"));
    let mut group = c.benchmark_group(format!("state/in_memory/{name}/history"));
    group.sample_size(10);

    group.bench_function("append_after_1024_items", |b| {
        b.iter_batched_ref(
            || {
                let backend = create();
                required(prepopulate_sequence(&rt, &backend, &sequence_path, ITEMS));
                backend
            },
            |backend| {
                required(rt.block_on(backend.write_append(
                    black_box(&sequence_path),
                    black_box(Value::integer(i64::from(ITEMS))),
                )));
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("query_pages_1024_keys", |b| {
        let backend = create();
        required(prepopulate_prefix(&rt, &backend, ITEMS));
        b.iter(|| {
            let rows = required(rt.block_on(async {
                let mut pages = backend.pages(StateScan::new(black_box(&prefix).clone()));
                let mut count = 0;
                while let Some(page) = pages.next().await? {
                    count += page.entries.len();
                    black_box(page);
                }
                Ok::<_, xolotl_state::StateFailure>(count)
            }));
            required((|| {
                ensure!(rows == ITEMS as usize, "incomplete prefix read");
                Ok::<(), anyhow::Error>(())
            })());
            black_box(rows);
        });
    });

    group.bench_function("history_pages_1024_entries", |b| {
        let backend = create();
        required(prepopulate_sequence(&rt, &backend, &history_path, ITEMS));
        b.iter(|| {
            let rows = required(rt.block_on(async {
                let mut pages = backend.history_pages(StateHistoryQuery::new(
                    black_box(&history_path).clone(),
                    0,
                    i64::MAX,
                ));
                let mut count = 0;
                while let Some(page) = pages.next().await? {
                    count += page.entries.len();
                    black_box(page);
                }
                Ok::<_, xolotl_state::StateFailure>(count)
            }));
            required((|| {
                ensure!(rows == ITEMS as usize, "incomplete history read");
                Ok::<(), anyhow::Error>(())
            })());
            black_box(rows);
        });
    });

    group.finish();
}

fn bench_rolling_history_trim(c: &mut Criterion) {
    let rt = required(runtime());
    let path = required(path("state://bench/rolling_history"));
    let mut group = c.benchmark_group("state/in_memory/history_retention");
    group.sample_size(10);
    for retained in [256, 4_096] {
        group.bench_function(format!("trim_64_of_{retained}"), |b| {
            b.iter_custom(|iterations| {
                let backend = required(InMemoryBackend::with_options(InMemoryOptions {
                    history: MemoryHistory::Full,
                    ..InMemoryOptions::default()
                }));
                for _ in 0..retained {
                    required(rt.block_on(backend.write_set(&path, Value::integer(1))));
                }
                let mut query = StateHistoryQuery::new(path.clone(), 0, i64::MAX);
                query.limits.entries = NonZeroUsize::MIN.saturating_add(64);
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    let page = required(rt.block_on(backend.history(&query)));
                    let floor = required(
                        page.entries
                            .get(64)
                            .map(|entry| entry.at_millis)
                            .ok_or_else(|| anyhow!("rolling history lost its trim boundary")),
                    );
                    let start = Instant::now();
                    let trimmed = required(
                        rt.block_on(backend.trim_before(floor, StateHistoryTrimLimits::default())),
                    );
                    elapsed += start.elapsed();
                    assert_eq!(trimmed.removed_events, 64);
                    query.from_millis = floor;
                    for _ in 0..64 {
                        required(rt.block_on(backend.write_set(&path, Value::integer(1))));
                    }
                }
                elapsed
            });
        });
    }
    group.finish();
}

#[derive(Clone, Copy)]
enum Workload {
    Read,
    Write,
}

async fn run_workload(backend: &InMemoryBackend, path: &Path, workload: Workload) -> Result<()> {
    match workload {
        Workload::Read => {
            for _ in 0..OPERATIONS_PER_THREAD {
                let value = backend.read(black_box(path)).await?;
                ensure!(
                    value == Some(Value::integer(0)),
                    "unexpected concurrent read"
                );
                drop(black_box(value));
            }
        }
        Workload::Write => {
            for i in 0..OPERATIONS_PER_THREAD {
                backend
                    .write_set(black_box(path), black_box(Value::integer(i64::from(i))))
                    .await?;
            }
        }
    }
    Ok(())
}

fn threaded_batch(
    backend: &InMemoryBackend,
    runtimes: &[Runtime],
    paths: &[Path],
    workload: Workload,
) -> Result<Duration> {
    ensure!(runtimes.len() == THREADS && paths.len() == THREADS);
    std::thread::scope(|scope| {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (finished_tx, finished_rx) = mpsc::channel();
        let mut starters = Vec::with_capacity(THREADS);
        let mut workers = Vec::with_capacity(THREADS);
        for (index, (rt, path)) in runtimes.iter().zip(paths).enumerate() {
            let ready_tx = ready_tx.clone();
            let finished_tx = finished_tx.clone();
            let (start_tx, start_rx) = mpsc::channel();
            let worker = std::thread::Builder::new()
                .name(format!("state-bench-{index}"))
                .spawn_scoped(scope, move || -> Result<()> {
                    ready_tx.send(()).context("worker readiness send failed")?;
                    start_rx.recv().context("worker start receive failed")?;
                    let result = rt.block_on(run_workload(backend, path, workload));
                    finished_tx
                        .send(())
                        .context("worker completion send failed")?;
                    result
                })
                .context("benchmark worker creation failed")?;
            starters.push(start_tx);
            workers.push(worker);
        }
        drop(ready_tx);
        drop(finished_tx);
        for _ in 0..THREADS {
            ready_rx.recv().context("worker readiness receive failed")?;
        }

        // Only kickoff/completion messages and the operation batch are timed.
        // Disconnectable start channels also release workers if setup fails.
        let start = Instant::now();
        for starter in starters {
            starter.send(()).context("worker start send failed")?;
        }
        for _ in 0..THREADS {
            finished_rx
                .recv()
                .context("worker completion receive failed")?;
        }
        let elapsed = start.elapsed();
        for worker in workers {
            match worker.join() {
                Ok(result) => result?,
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
        Ok(elapsed)
    })
}

fn bench_concurrency(c: &mut Criterion) {
    for (name, options) in configurations() {
        bench_concurrency_for(c, name, options);
    }
}

fn bench_concurrency_for(c: &mut Criterion, name: &str, options: InMemoryOptions) {
    let runtimes = required((0..THREADS).map(|_| runtime()).collect::<Result<Vec<_>>>());
    let rt = required(runtimes.first().context("missing setup runtime"));
    let mut group = c.benchmark_group(format!("state/in_memory/{name}/concurrency"));
    group.sample_size(20);
    group.throughput(Throughput::Elements(
        THREADS as u64 * u64::from(OPERATIONS_PER_THREAD),
    ));

    for (name, workload, same_key) in [
        ("read_same_key_8_threads", Workload::Read, true),
        ("read_distinct_keys_8_threads", Workload::Read, false),
        ("write_same_key_8_threads", Workload::Write, true),
        ("write_distinct_keys_8_threads", Workload::Write, false),
    ] {
        let paths = required(
            (0..THREADS)
                .map(|index| {
                    let key = if same_key { 0 } else { index };
                    path(&format!("state://bench/concurrent/k{key}"))
                })
                .collect::<Result<Vec<_>>>(),
        );
        group.bench_function(name, |b| {
            b.iter_custom(|iterations| {
                required((|| {
                    let mut elapsed = Duration::ZERO;
                    for _ in 0..iterations {
                        let backend = InMemoryBackend::with_options(options)?;
                        for path in &paths {
                            rt.block_on(backend.write_set(path, Value::integer(0)))?;
                        }
                        elapsed += threaded_batch(&backend, &runtimes, &paths, workload)?;
                        let expected = match workload {
                            Workload::Read => 0,
                            Workload::Write => i64::from(OPERATIONS_PER_THREAD - 1),
                        };
                        for path in &paths {
                            ensure!(
                                rt.block_on(backend.read(path))? == Some(Value::integer(expected)),
                                "unexpected value after worker batch"
                            );
                        }
                    }
                    Ok::<Duration, anyhow::Error>(elapsed)
                })())
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_current_values,
    bench_source_fingerprint,
    bench_absence_replacement,
    bench_sequences_and_history,
    bench_rolling_history_trim,
    bench_concurrency
);
criterion_main!(benches);
