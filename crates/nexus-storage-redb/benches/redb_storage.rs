use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nexus_kernel::{FactSink, FactStore};
use nexus_state::StateBackend;
use nexus_storage_redb::RedbStore;
use nexus_types::{
    DecisionTag, Fact, HandleId, IdentityRef, MethodId, NodeId, OperationId, OutcomeRef, Path,
    ProcessId, ReplayClass, ResourceId, TaintSet, Timestamp, Value, ValueRef,
};
use redb::TableDefinition;
use std::hint::black_box;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::runtime::{Builder, Runtime};

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

fn runtime() -> Runtime {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime must build")
}

fn redb_store() -> (TempDir, RedbStore) {
    let dir = tempfile::tempdir().expect("tempdir must be created");
    let store = RedbStore::open(dir.path().join("bench.redb")).expect("redb store must open");
    (dir, store)
}

fn bench_path(name: &str) -> Path {
    Path::parse(name).expect("benchmark path must parse")
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
    backend: &nexus_storage_redb::RedbStateBackend,
    path: &Path,
    items: u32,
) {
    rt.block_on(async {
        for i in 0..items {
            backend
                .write_append(path, Value::Int(i as i64))
                .await
                .expect("state append must succeed");
        }
    });
}

fn prepopulate_state_prefix(
    rt: &Runtime,
    backend: &nexus_storage_redb::RedbStateBackend,
    keys: u32,
) {
    rt.block_on(async {
        for i in 0..keys {
            let path = bench_path(&format!("state://bench/prefix/k{i}"));
            backend
                .write_set(&path, Value::Int(i as i64))
                .await
                .expect("state set must succeed");
        }
    });
}

fn prepopulate_state_history(
    rt: &Runtime,
    backend: &nexus_storage_redb::RedbStateBackend,
    path: &Path,
    writes: u32,
) {
    rt.block_on(async {
        for i in 0..writes {
            backend
                .write_set(path, Value::Int(i as i64))
                .await
                .expect("state set must succeed");
        }
    });
}

fn bench_state(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("redb/state");
    group.sample_size(10);

    group.bench_function("append_empty_sequence", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store();
                let backend = store.state_backend();
                let path = bench_path("state://bench/log");
                (dir, backend, path)
            },
            |(_dir, backend, path)| {
                rt.block_on(async {
                    backend
                        .write_append(black_box(&path), black_box(Value::Int(1)))
                        .await
                        .expect("state append must succeed");
                });
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("set_current_value", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store();
                let backend = store.state_backend();
                let path = bench_path("state://bench/value");
                (dir, backend, path)
            },
            |(_dir, backend, path)| {
                rt.block_on(async {
                    backend
                        .write_set(black_box(&path), black_box(Value::Int(7)))
                        .await
                        .expect("state set must succeed");
                });
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("cas_success_current_value", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store();
                let backend = store.state_backend();
                let path = bench_path("state://bench/cas");
                rt.block_on(async {
                    backend
                        .write_set(&path, Value::Int(1))
                        .await
                        .expect("state set must succeed");
                });
                (dir, backend, path)
            },
            |(_dir, backend, path)| {
                rt.block_on(async {
                    backend
                        .write_cas(
                            black_box(&path),
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

    group.bench_function("append_after_1024_items_same_path", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store();
                let backend = store.state_backend();
                let path = bench_path("state://bench/log");
                prepopulate_state_sequence(&rt, &backend, &path, STATE_ITEMS_IN_SEQUENCE);
                (dir, backend, path)
            },
            |(_dir, backend, path)| {
                rt.block_on(async {
                    backend
                        .write_append(
                            black_box(&path),
                            black_box(Value::Int(STATE_ITEMS_IN_SEQUENCE as i64)),
                        )
                        .await
                        .expect("state append must succeed");
                });
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("read_materialized_sequence_1024_items", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store();
                let backend = store.state_backend();
                let path = bench_path("state://bench/log");
                prepopulate_state_sequence(&rt, &backend, &path, STATE_ITEMS_IN_SEQUENCE);
                (dir, backend, path)
            },
            |(_dir, backend, path)| {
                let value = rt
                    .block_on(async {
                        backend
                            .read(black_box(&path))
                            .await
                            .expect("state read must succeed")
                    })
                    .expect("sequence must exist");
                black_box(value);
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("read_prefix_1024_keys", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store();
                let backend = store.state_backend();
                prepopulate_state_prefix(&rt, &backend, STATE_KEYS_IN_PREFIX_SCAN);
                (dir, backend, bench_path("state://bench/prefix"))
            },
            |(_dir, backend, prefix)| {
                let rows = rt.block_on(async {
                    backend
                        .read_prefix(black_box(&prefix))
                        .await
                        .expect("state prefix read must succeed")
                });
                black_box(rows);
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("read_range_1024_writes_same_path", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store();
                let backend = store.state_backend();
                let path = bench_path("state://bench/history");
                prepopulate_state_history(&rt, &backend, &path, STATE_WRITES_IN_RANGE_SCAN);
                (dir, backend, path)
            },
            |(_dir, backend, path)| {
                let rows = rt.block_on(async {
                    backend
                        .read_range(black_box(&path), 0, i64::MAX)
                        .await
                        .expect("state range read must succeed")
                });
                black_box(rows);
            },
            BatchSize::LargeInput,
        );
    });

    group.finish();
}

fn fact_sink() -> (TempDir, FactSink) {
    let (dir, store) = redb_store();
    let fact_store = store.fact_store().expect("fact store must open");
    (dir, FactSink::new(Arc::new(fact_store)))
}

fn op_key(id: &OperationId) -> String {
    format!("{}/{}/{}", id.process.get(), id.position.get(), id.attempt)
}

fn process_key(process: ProcessId, slot: u64) -> String {
    format!("{:020}/{slot:020}", process.get())
}

fn prepopulated_fact_sink(count: u32) -> (TempDir, FactSink) {
    let dir = tempfile::tempdir().expect("tempdir must be created");
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
            let bytes = serde_json::to_vec(&fact).expect("fact must serialize");
            let op_key = op_key(&fact.id);
            let process_key = process_key(fact.caller, slot);
            (slot, bytes, op_key, process_key)
        })
        .collect();

    {
        let db = redb::Database::create(&path).expect("redb database must be created");
        let txn = db.begin_write().expect("redb write txn must start");
        {
            let mut table = txn.open_table(BENCH_FACTS_TABLE).unwrap();
            for (slot, bytes, _, _) in &rows {
                table.insert(*slot, bytes.as_slice()).unwrap();
            }
        }
        {
            let mut table = txn.open_table(BENCH_FACT_INDEX_TABLE).unwrap();
            for (slot, _, key, _) in &rows {
                table.insert(key.as_str(), *slot).unwrap();
            }
        }
        {
            let mut table = txn.open_table(BENCH_FACT_PROCESS_INDEX_TABLE).unwrap();
            for (slot, _, _, key) in &rows {
                table.insert(key.as_str(), *slot).unwrap();
            }
        }
        {
            let mut table = txn.open_table(BENCH_FACT_META_TABLE).unwrap();
            table
                .insert(BENCH_NEXT_CURSOR_KEY, count as u64)
                .expect("cursor metadata must insert");
        }
        txn.commit().expect("redb write txn must commit");
    }

    let store = RedbStore::open(&path).expect("redb store must open");
    let fact_store = store.fact_store().expect("fact store must open");
    (dir, FactSink::new(Arc::new(fact_store)))
}

fn bench_facts(c: &mut Criterion) {
    let mut group = c.benchmark_group("redb/facts");
    group.sample_size(10);

    group.bench_function("append_complete_non_idempotent", |b| {
        b.iter_batched(
            fact_sink,
            |(_dir, sink)| {
                let process = ProcessId::new(1);
                sink.begin(black_box(fact(process, 0, false)))
                    .expect("fact begin must succeed");
                sink.complete(black_box(fact(process, 0, true)))
                    .expect("fact complete must succeed");
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("facts_of_scan_4096_facts", |b| {
        let (_dir, sink) = prepopulated_fact_sink(FACTS_IN_SCAN_BENCH);
        b.iter(|| {
            let facts = sink
                .facts_of(black_box(ProcessId::new(1)))
                .expect("facts_of must succeed");
            black_box(facts);
        });
    });

    group.bench_function("all_facts_scan_4096_facts", |b| {
        let (_dir, sink) = prepopulated_fact_sink(FACTS_IN_SCAN_BENCH);
        b.iter(|| {
            let facts = sink.all_facts().expect("all_facts must succeed");
            black_box(facts);
        });
    });

    group.bench_function("fact_store_cursor", |b| {
        b.iter_batched(
            || {
                let (dir, store) = redb_store();
                let fact_store = store.fact_store().expect("fact store must open");
                fact_store
                    .append(fact(ProcessId::new(1), 0, true))
                    .expect("fact append must succeed");
                (dir, fact_store)
            },
            |(_dir, fact_store)| {
                black_box(fact_store.cursor());
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_state, bench_facts);
criterion_main!(benches);
