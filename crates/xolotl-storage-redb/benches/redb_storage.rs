use anyhow::{Context, Result, anyhow};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use redb::TableDefinition;
use std::hint::black_box;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::runtime::{Builder, Runtime};
use xolotl_kernel::{FactSink, FactStore};
use xolotl_source::{
    ExternalInstallationAuthority, ExternalInstallationMutation, SourceClaim, SourceClaimId,
    SourceCommit, SourceCommitOutcome, SourceEventCommit,
};
use xolotl_state::{StateHistoryQuery, StateScan, prelude::*};
use xolotl_storage_redb::{RedbHistory, RedbStore};
use xolotl_types::{
    DecisionTag, ExecutionId, Fact, HandleId, IdentityRef, InvocationId, MethodId, NodeId,
    OperationId, Path, ProcessId, Purity, ReplayClass, ResourceId, TaintSet, Timestamp, Transport,
    TrustLevel, Value,
    external::{
        EventSource, ExternalInstallationDef, ExternalProjectionDef, OverflowPolicy, Role,
        StreamCapacity,
    },
};

const FACTS_IN_SCAN_BENCH: u32 = 4_096;
const STATE_ITEMS_IN_SEQUENCE: u32 = 1_024;
const STATE_KEYS_IN_PREFIX_SCAN: u32 = 1_024;
const STATE_WRITES_IN_RANGE_SCAN: u32 = 1_024;
const SOURCE_SINK_CAPACITY: usize = 512;
const SOURCE_PAYLOAD_BYTES: usize = 256;
const BENCH_FACTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("facts");
const BENCH_FACT_INDEX_TABLE: TableDefinition<&[u8], u64> = TableDefinition::new("fact_index_v1");
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

#[expect(
    clippy::panic,
    reason = "a failed benchmark must stop instead of timing an error path"
)]
fn observe<T>(result: Result<T>) {
    match result {
        Ok(value) => drop(black_box(value)),
        Err(error) => panic!("benchmark operation failed: {error:#}"),
    }
}

#[expect(clippy::panic, reason = "an invalid fixture must stop the benchmark")]
fn observe_error(error: anyhow::Error) -> ! {
    panic!("benchmark setup failed: {error:#}");
}

fn fact(process: ProcessId, node: u32, complete: bool) -> Fact {
    Fact {
        id: OperationId::new(
            process,
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(node),
            0,
        ),
        schema_version: Fact::SCHEMA_VERSION,
        caller: process,
        caller_identity: Some(IdentityRef::ROOT),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(1),
        method: MethodId::new(0),
        input: Value::integer(node as i64),
        taint: TaintSet::pristine(),
        decision: DecisionTag::Ok,
        outcome: if complete {
            Some(Value::integer(node as i64))
        } else {
            None
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
                .write_append(path, Value::integer(i as i64))
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
                .write_set(&path, Value::integer(i as i64))
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
                .write_set(path, Value::integer(i as i64))
                .await
                .map_err(|error| anyhow!("state set failed during history prepopulate: {error}"))?;
        }
        Ok::<(), anyhow::Error>(())
    })
}

fn source_sink_fixture(
    rt: &Runtime,
    items: usize,
) -> Result<(TempDir, xolotl_storage_redb::RedbStateBackend, Path)> {
    let (dir, store) = redb_store()?;
    let backend = store.state_backend();
    let path = bench_path("state://bench/source-sink")?;
    let definition = ExternalInstallationDef {
        id: "bench".into(),
        platform: "bench".into(),
        transport: Transport::Grpc { endpoint: None },
        trust: TrustLevel::Full,
        config_schema: Value::map(Default::default()),
        config: Value::null(),
        projections: vec![ExternalProjectionDef {
            id: "sink".into(),
            role: Role::Source,
            namespace: None,
            provides: vec![],
            emits: Some(EventSource {
                sink: path.clone(),
                purity: Purity::Effectful,
                event_schema: None,
                max_inline_payload_bytes: 1024,
                capacity: StreamCapacity {
                    max_events: SOURCE_SINK_CAPACITY as u32,
                    on_overflow: OverflowPolicy::DropOldest,
                },
                rate_limit: None,
                commands: false,
                command_schema: None,
                command_result_schema: None,
            }),
            version: 1,
        }],
        version: 0,
    };
    let installed = rt.block_on(backend.compare_install(definition, None))?;
    anyhow::ensure!(
        matches!(installed, ExternalInstallationMutation::Applied(Some(ref record)) if record.scope_epoch("sink") == Some(2))
    );
    if items > 0 {
        let payload = Value::string("x".repeat(SOURCE_PAYLOAD_BYTES));
        rt.block_on(async {
            backend
                .write_set(&path, Value::list(vec![payload; items]))
                .await
                .map_err(|error| anyhow!("Source sink setup failed: {error}"))
        })?;
    }
    let actual = rt.block_on(async {
        backend
            .read(&path)
            .await
            .map_err(|error| anyhow!("Source sink setup read failed: {error}"))
    })?;
    let actual_items = actual
        .as_ref()
        .and_then(Value::as_list)
        .map_or(0, |values| values.len());
    anyhow::ensure!(
        actual_items == items,
        "Source sink setup has {actual_items} items, expected {items}"
    );
    Ok((dir, backend, path))
}

fn commit_source_sink(
    rt: &Runtime,
    backend: &xolotl_storage_redb::RedbStateBackend,
    path: &Path,
    capacity: &StreamCapacity,
    payload: &Value,
    taint: &TaintSet,
) -> Result<()> {
    let outcome = rt.block_on(backend.commit(SourceCommit {
        claim: SourceClaim {
            installation_id: "bench",
            projection_id: "sink",
            scope_epoch: 2,
            stream_epoch: None,
            event_id: "bench-event",
            claim_id: SourceClaimId::from_bytes([1; 16]),
        },
        received_at_ms: 1_700_000_000_000,
        decision_clock: std::sync::Arc::new(|| 1_700_000_000_000),
        dedupe_window_ms: 60_000,
        sink: path,
        capacity,
        max_inline_payload_bytes: 1_024,
        payload,
        taint,
        stream: None,
        rate_limit: None,
    }))?;
    anyhow::ensure!(
        outcome == SourceCommitOutcome::Accepted,
        "Source sink benchmark did not commit: {outcome:?}"
    );
    Ok(())
}

fn bench_source_sink(c: &mut Criterion) {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(error) => observe_error(error),
    };
    let capacity = StreamCapacity {
        max_events: SOURCE_SINK_CAPACITY as u32,
        on_overflow: OverflowPolicy::DropOldest,
    };
    let payload = Value::string("y".repeat(SOURCE_PAYLOAD_BYTES));
    let taint = TaintSet::pristine();
    let mut group = c.benchmark_group("redb/source_sink");
    group.sample_size(10);
    for (name, items) in [
        ("append_empty", 0),
        ("append_near_capacity", SOURCE_SINK_CAPACITY - 1),
        ("drop_oldest_full", SOURCE_SINK_CAPACITY),
    ] {
        group.bench_function(name, |b| {
            b.iter_batched_ref(
                || source_sink_fixture(&rt, items),
                |setup| match setup {
                    Ok((_dir, backend, path)) => {
                        observe(commit_source_sink(
                            &rt,
                            backend,
                            black_box(path),
                            &capacity,
                            &payload,
                            &taint,
                        ));
                    }
                    Err(error) => observe_error(anyhow!("{error:#}")),
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_state(c: &mut Criterion) {
    let rt = match runtime() {
        Ok(rt) => rt,
        Err(error) => observe_error(error),
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
                            .write_append(black_box(&path), black_box(Value::integer(1)))
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
                            .write_set(black_box(&path), black_box(Value::integer(7)))
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
                        .write_set(&path, Value::integer(1))
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
                                black_box(Some(Value::integer(1))),
                                black_box(Value::integer(2)),
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
                                black_box(Value::integer(STATE_ITEMS_IN_SEQUENCE as i64)),
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

    group.bench_function("query_pages_1024_keys", |b| {
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
                        let mut pages = backend.pages(StateScan::new(black_box(&prefix).clone()));
                        let mut count = 0;
                        while let Some(page) = pages.next().await? {
                            count += page.entries.len();
                            black_box(page);
                        }
                        Ok::<_, anyhow::Error>(count)
                    });
                    observe(result);
                }
                Err(error) => observe_error(error),
            },
            BatchSize::LargeInput,
        );
    });

    group.bench_function("history_pages_1024_writes_same_path", |b| {
        b.iter_batched(
            || {
                let dir = tempfile::tempdir()?;
                let store =
                    RedbStore::open_with_history(dir.path().join("bench.redb"), RedbHistory::Full)?;
                let backend = store.state_backend();
                let path = bench_path("state://bench/history")?;
                prepopulate_state_history(&rt, &backend, &path, STATE_WRITES_IN_RANGE_SCAN)?;
                Ok((dir, backend, path))
            },
            |setup: Result<_>| match setup {
                Ok((_dir, backend, path)) => {
                    let result = rt.block_on(async {
                        let mut pages = backend.history_pages(StateHistoryQuery::new(
                            black_box(&path).clone(),
                            0,
                            i64::MAX,
                        ));
                        let mut count = 0;
                        while let Some(page) = pages.next().await? {
                            count += page.entries.len();
                            black_box(page);
                        }
                        Ok::<_, anyhow::Error>(count)
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

fn process_key(process: ProcessId, slot: u64) -> String {
    format!("{:020}/{slot:020}", process.get())
}

fn prepopulated_fact_sink(count: u32) -> Result<(TempDir, FactSink)> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("bench.redb");
    // The raw insert below bypasses adapter writes, but must use a complete
    // first-format database. Reopening a partial schema is deliberately rejected.
    drop(RedbStore::open(&path)?);
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
            let op_key = fact.id.to_bytes();
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
                table.insert(key.as_slice(), *slot)?;
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
    let sink = FactSink::new(Arc::new(fact_store));
    let actual = sink.all_facts()?.len();
    anyhow::ensure!(
        actual == count as usize,
        "fact fixture has {actual} rows, expected {count}"
    );
    let indexed = sink.facts_of(ProcessId::new(1))?.len();
    let expected = count.div_ceil(2) as usize;
    anyhow::ensure!(
        indexed == expected,
        "fact fixture has {indexed} indexed rows, expected {expected}"
    );
    Ok((dir, sink))
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
            Err(error) => observe_error(error),
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
            Err(error) => observe_error(error),
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

criterion_group!(benches, bench_state, bench_facts, bench_source_sink);
criterion_main!(benches);
