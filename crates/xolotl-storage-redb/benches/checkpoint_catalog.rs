use anyhow::{Context, ensure};
use criterion::{BenchmarkId, Criterion};
use redb::{Database, TableDefinition};
use std::{hint::black_box, num::NonZeroUsize, sync::Arc, time::Duration};
use xolotl_graph::portable::{Expression, Program};
use xolotl_kernel::{
    Bootstrap, Kernel,
    executor::durable::{CheckpointQuery, CheckpointStore},
};
use xolotl_storage_redb::{RedbCheckpointStore, RedbStore};
use xolotl_types::{Failure, IdentityRef, Outcome, ProcessId, TaintedValue, Value};

fn checked<T: Default>(result: Result<T, Failure>, validate: impl FnOnce(&T) -> bool) -> T {
    assert!(
        result.as_ref().is_ok_and(validate),
        "benchmark storage operation failed or returned invalid data: {:?}",
        result.as_ref().err()
    );
    result.unwrap_or_default()
}

fn fixture(
    count: usize,
    payload_bytes: usize,
) -> anyhow::Result<(tempfile::TempDir, RedbCheckpointStore)> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("catalog.redb");
    let mut saved = {
        let store = RedbStore::open(&path)?;
        let checkpoints = Arc::new(store.checkpoint_store());
        let boot =
            Bootstrap::from_kernel(Kernel::in_memory().with_checkpoint_store(checkpoints.clone()));
        let process = boot.spawn_request_process_under_with_compiled_request_grants(
            boot.root,
            IdentityRef::ROOT,
            &[],
        )?;
        let mut source = Program::new(Expression::literal("x".repeat(payload_bytes)));
        source.durable = true;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let outcome = runtime.block_on(
            boot.kernel
                .executor_for(process)
                .eval_program(&source.compile()?, TaintedValue::pristine(Value::null())),
        );
        ensure!(
            matches!(outcome.outcome, Outcome::Done(_)),
            "fixture did not commit: {outcome:?}"
        );
        checkpoints
            .acquire(process)?
            .load(usize::MAX)?
            .context("missing fixture checkpoint")?
    };
    // Prepare retained rows in one transaction; setup and persistence are untimed.
    {
        let db = Database::create(&path)?;
        let transaction = db.begin_write()?;
        {
            let mut table = transaction.open_table(TableDefinition::<u64, &[u8]>::new(
                "execution_checkpoints_v1",
            ))?;
            for index in 0..count {
                saved.process.id = ProcessId::new(index as u64 + 2);
                let bytes = serde_json::to_vec(&saved)?;
                table.insert(saved.process.id.get(), bytes.as_slice())?;
            }
        }
        transaction.commit()?;
    }
    let store = RedbStore::open(&path)?;
    Ok((directory, store.checkpoint_store()))
}

fn benchmark(c: &mut Criterion) -> anyhow::Result<()> {
    let mut group = c.benchmark_group("checkpoint_catalog");
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(300));
    group.measurement_time(Duration::from_secs(1));
    for count in [64, 1024] {
        for payload in [256, 16_384] {
            let (_directory, store) = fixture(count, payload)?;
            let query = CheckpointQuery {
                after: None,
                through: store.high_water()?.context("missing process high water")?,
                limit: NonZeroUsize::MIN.saturating_add(63),
            };
            let label = format!("rows_{count}/payload_{payload}");
            group.bench_with_input(BenchmarkId::new("page_64", &label), &query, |b, query| {
                b.iter(|| {
                    let entries =
                        checked(store.scan(black_box(*query)), |entries| entries.len() == 64);
                    drop(black_box(entries));
                });
            });
            group.bench_with_input(
                BenchmarkId::new("decode_all", &label),
                &count,
                |b, count| {
                    b.iter(|| {
                        let snapshots =
                            checked(store.snapshots(), |snapshots| snapshots.len() == *count);
                        drop(black_box(snapshots));
                    });
                },
            );
            group.bench_with_input(
                BenchmarkId::new("high_water", &label),
                &query.through,
                |b, through| {
                    b.iter(|| {
                        let high_water = checked(store.high_water(), |high_water| {
                            *high_water == Some(*through)
                        });
                        black_box(high_water);
                    });
                },
            );
        }
    }
    group.finish();
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let mut criterion = Criterion::default().configure_from_args();
    benchmark(&mut criterion)?;
    criterion.final_summary();
    Ok(())
}
