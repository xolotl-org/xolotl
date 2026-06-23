use anyhow::{Context, Result, anyhow};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use redb::TableDefinition;
use std::hint::black_box;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::runtime::{Builder, Runtime};
use xolotl_kernel::{FactSink, FactStore};
use xolotl_state::StateBackend;
use xolotl_storage_redb::RedbStore;
use xolotl_types::{
    DecisionTag, Fact, HandleId, IdentityRef, MethodId, NodeId, OperationId, OutcomeRef, Path,
    ProcessId, ReplayClass, ResourceId, TaintSet, Timestamp, Value, ValueRef,
};

const FACTS_IN_SCAN_BENCH: u32 = 4_096;
const STATE_ITEMS_IN_SEQUENCE: u32 = 1_024;
const STATE_KEYS_IN_PREFIX_SCAN: u32 = 1_024;
const STATE_WRITES_IN_RANGE_SCAN: u32 = 1_024;
const BENCH_FACTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("facts");
const BENCH_FACT_INDEX_TABLE: TableDefinition<&str, u64> = TableDefinition::new("fact_index");
const BENCH_FACT_PROCESS_INDEX_TABLE: TableDefinition<&str, u64> =
    TableDefinition::new("fact_process_index");
const BENCH_FACT_META_TABLE: TableDefinition<&str, u64> = TableDefinition::new("fact_meta");
const BENCH_NEXT_CURSOR_KEY: &str = "next_cursor";

fn runtime() -> Result<Runtime> {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| anyhow!("tokio runtime build failed: {error}"))
}

fn redb_store() -> Result<(TempDir, RedbStore)> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("bench.redb"))?;
    Ok((dir, store))
}

fn bench_path(name: &str) -> Result<Path> {
    Path::parse(name).map_err(|error| anyhow!("benchmark path parse failed for {name}: {error}"))
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

fn fact(process: ProcessId, node: u32, complete: bool) -> Fact {
    Fact {
        id: OperationId::new(process, NodeId::new(node), 0),
        schema_version: Fact::SCHEMA_VERSION,
        caller: process,
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(1),
        method: MethodId::new(0),
        input_ref: ValueRef::Inline(Value::Int(node as i64)),
        taint: TaintSet::pristine(),
        decision: DecisionTag::Ok,
        outcome_ref: if complete {
            OutcomeRef::Inline(Value::Int(node as i64))
        } else {
            OutcomeRef::None
        },
        batch: None,
        replay: ReplayClass::NonIdempotentEffect,
        timestamp: Timestamp::millis(1_700_000_000_000 + node as i64),
    }
}

fn prepopulate_state_sequence(
    rt: &Runtime,
    backend: &xolotl_storage_redb::RedbStateBackend,
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

fn prepopulate_state_prefix(
    rt: &Runtime,
    backend: &xolotl_storage_redb::RedbStateBackend,
    keys: u32,
) -> Result<()> {
    rt.block_on(async {
        for i in 0..keys {
            let path = bench_path(&format!("state://bench/prefix/k{i}"))?;
            backend
                .write_set(&path, Value::Int(i as i64))
                .await
                .map_err(|error| anyhow!("state set failed during prefix prepopulate: {error}"))?;
        }
        Ok::<(), anyhow::Error>(())
    })
}

fn prepopulate_state_history(
    rt: &Runtime,
    backend: &xolotl_storage_redb::RedbStateBackend,
    path: &Path,
    writes: u32,
) -> Result<()> {
    rt.block_on(async {
        for i in 0..writes {
            backend
                .write_set(path, Value::Int(i as i64))
                .await
                .map_err(|error| anyhow!("state set failed during history prepopulate: {error}"))?;
        }
        Ok::<(), anyhow::Error>(())
    })
}

fn bench_state(c: &mut Criterion) {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(error) => {
            bench_setup_failure(c, "redb/state/runtime_setup_failed", error);
            return;
        }
    };
    let mut group = c.benchmark_group("redb/state");
    group.sample_size(10);

    group.bench_function("append_empty_sequence", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store()?;
                let backend = store.state_backend();
                let path = bench_path("state://bench/log")?;
                Ok((dir, backend, path))
            },
            |setup: Result<_>| match setup {
                Ok((_dir, backend, path)) => {
                    let result = rt.block_on(async {
                        backend
                            .write_append(black_box(&path), black_box(Value::Int(1)))
                            .await
                            .map_err(|error| anyhow!("state append failed: {error}"))
                    });
                    observe(result);
                }
                Err(error) => observe_error(error),
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("set_current_value", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store()?;
                let backend = store.state_backend();
                let path = bench_path("state://bench/value")?;
                Ok((dir, backend, path))
            },
            |setup: Result<_>| match setup {
                Ok((_dir, backend, path)) => {
                    let result = rt.block_on(async {
                        backend
                            .write_set(black_box(&path), black_box(Value::Int(7)))
                            .await
                            .map_err(|error| anyhow!("state set failed: {error}"))
                    });
                    observe(result);
                }
                Err(error) => observe_error(error),
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("cas_success_current_value", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store()?;
                let backend = store.state_backend();
                let path = bench_path("state://bench/cas")?;
                rt.block_on(async {
                    backend
                        .write_set(&path, Value::Int(1))
                        .await
                        .map_err(|error| anyhow!("state set failed before CAS: {error}"))?;
                    Ok::<(), anyhow::Error>(())
                })?;
                Ok((dir, backend, path))
            },
            |setup: Result<_>| match setup {
                Ok((_dir, backend, path)) => {
                    let result = rt.block_on(async {
                        backend
                            .write_cas(
                                black_box(&path),
                                black_box(Some(Value::Int(1))),
                                black_box(Value::Int(2)),
                            )
                            .await
                            .map_err(|error| anyhow!("state CAS failed: {error}"))
                    });
                    observe(result);
                }
                Err(error) => observe_error(error),
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("append_after_1024_items_same_path", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store()?;
                let backend = store.state_backend();
                let path = bench_path("state://bench/log")?;
                prepopulate_state_sequence(&rt, &backend, &path, STATE_ITEMS_IN_SEQUENCE)?;
                Ok((dir, backend, path))
            },
            |setup: Result<_>| match setup {
                Ok((_dir, backend, path)) => {
                    let result = rt.block_on(async {
                        backend
                            .write_append(
                                black_box(&path),
                                black_box(Value::Int(STATE_ITEMS_IN_SEQUENCE as i64)),
                            )
                            .await
                            .map_err(|error| anyhow!("state append failed: {error}"))
                    });
                    observe(result);
                }
                Err(error) => observe_error(error),
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("read_materialized_sequence_1024_items", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store()?;
                let backend = store.state_backend();
                let path = bench_path("state://bench/log")?;
                prepopulate_state_sequence(&rt, &backend, &path, STATE_ITEMS_IN_SEQUENCE)?;
                Ok((dir, backend, path))
            },
            |setup: Result<_>| match setup {
                Ok((_dir, backend, path)) => {
                    let result = rt.block_on(async {
                        backend
                            .read(black_box(&path))
                            .await
                            .map_err(|error| anyhow!("state read failed: {error}"))?
                            .context("sequence must exist")
                    });
                    observe(result);
                }
                Err(error) => observe_error(error),
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("read_prefix_1024_keys", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store()?;
                let backend = store.state_backend();
                prepopulate_state_prefix(&rt, &backend, STATE_KEYS_IN_PREFIX_SCAN)?;
                Ok((dir, backend, bench_path("state://bench/prefix")?))
            },
            |setup: Result<_>| match setup {
                Ok((_dir, backend, prefix)) => {
                    let result = rt.block_on(async {
                        backend
                            .read_prefix(black_box(&prefix))
                            .await
                            .map_err(|error| anyhow!("state prefix read failed: {error}"))
                    });
                    observe(result);
                }
                Err(error) => observe_error(error),
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("read_range_1024_writes_same_path", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store()?;
                let backend = store.state_backend();
                let path = bench_path("state://bench/history")?;
                prepopulate_state_history(&rt, &backend, &path, STATE_WRITES_IN_RANGE_SCAN)?;
                Ok((dir, backend, path))
            },
            |setup: Result<_>| match setup {
                Ok((_dir, backend, path)) => {
                    let result = rt.block_on(async {
                        backend
                            .read_range(black_box(&path), 0, i64::MAX)
                            .await
                            .map_err(|error| anyhow!("state range read failed: {error}"))
                    });
                    observe(result);
                }
                Err(error) => observe_error(error),
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn fact_sink() -> Result<(TempDir, FactSink)> {
    let (dir, store) = redb_store()?;
    let fact_store = store.fact_store()?;
    Ok((dir, FactSink::new(Arc::new(fact_store))))
}

fn op_key(id: &OperationId) -> String {
    format!("{}/{}/{}", id.process.get(), id.position.get(), id.attempt)
}

fn process_key(process: ProcessId, slot: u64) -> String {
    format!("{:020}/{slot:020}", process.get())
}

fn prepopulated_fact_sink(count: u32) -> Result<(TempDir, FactSink)> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("bench.redb");
    let rows: Vec<_> = (0..count)
        .map(|i| {
            let process = if i % 2 == 0 {
                ProcessId::new(1)
            } else {
                ProcessId::new(2)
            };
            let slot = i as u64;
            let fact = fact(process, i, true);
            let bytes = serde_json::to_vec(&fact)?;
            let op_key = op_key(&fact.id);
            let process_key = process_key(fact.caller, slot);
            Ok((slot, bytes, op_key, process_key))
        })
        .collect::<Result<Vec<_>>>()?;

    {
        let db = redb::Database::create(&path)?;
        let txn = db.begin_write()?;
        {
            let mut table = txn.open_table(BENCH_FACTS_TABLE)?;
            for (slot, bytes, _, _) in &rows {
                table.insert(*slot, bytes.as_slice())?;
            }
        }
        {
            let mut table = txn.open_table(BENCH_FACT_INDEX_TABLE)?;
            for (slot, _, key, _) in &rows {
                table.insert(key.as_str(), *slot)?;
            }
        }
        {
            let mut table = txn.open_table(BENCH_FACT_PROCESS_INDEX_TABLE)?;
            for (slot, _, _, key) in &rows {
                table.insert(key.as_str(), *slot)?;
            }
        }
        {
            let mut table = txn.open_table(BENCH_FACT_META_TABLE)?;
            table.insert(BENCH_NEXT_CURSOR_KEY, count as u64)?;
        }
        txn.commit()?;
    }

    let store = RedbStore::open(&path)?;
    let fact_store = store.fact_store()?;
    Ok((dir, FactSink::new(Arc::new(fact_store))))
}

fn bench_facts(c: &mut Criterion) {
    let mut group = c.benchmark_group("redb/facts");
    group.sample_size(10);

    group.bench_function("append_complete_non_idempotent", |b| {
        b.iter_batched(
            fact_sink,
            |setup| match setup {
                Ok((_dir, sink)) => {
                    let process = ProcessId::new(1);
                    let result = (|| {
                        sink.begin(black_box(fact(process, 0, false)))?;
                        sink.complete(black_box(fact(process, 0, true)))?;
                        Ok(())
                    })();
                    observe(result);
                }
                Err(error) => observe_error(error),
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function(
        "facts_of_scan_4096_facts",
        |b| match prepopulated_fact_sink(FACTS_IN_SCAN_BENCH) {
            Ok((_dir, sink)) => {
                b.iter(|| {
                    observe(
                        sink.facts_of(black_box(ProcessId::new(1)))
                            .map_err(|error| anyhow!("facts_of failed: {error}")),
                    );
                });
            }
            Err(error) => {
                let message = error.to_string();
                b.iter(|| black_box(message.as_str()));
            }
        },
    );

    group.bench_function(
        "all_facts_scan_4096_facts",
        |b| match prepopulated_fact_sink(FACTS_IN_SCAN_BENCH) {
            Ok((_dir, sink)) => {
                b.iter(|| {
                    observe(
                        sink.all_facts()
                            .map_err(|error| anyhow!("all_facts failed: {error}")),
                    );
                });
            }
            Err(error) => {
                let message = error.to_string();
                b.iter(|| black_box(message.as_str()));
            }
        },
    );

    group.bench_function("fact_store_cursor", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store()?;
                let fact_store = store.fact_store()?;
                fact_store.append(fact(ProcessId::new(1), 0, true))?;
                Ok((dir, fact_store))
            },
            |setup: Result<_>| match setup {
                Ok((_dir, fact_store)) => {
                    black_box(fact_store.cursor());
                }
                Err(error) => observe_error(error),
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_state, bench_facts);
criterion_main!(benches);
