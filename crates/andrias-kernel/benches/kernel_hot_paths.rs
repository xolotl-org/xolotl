use andrias_kernel::{
    Bootstrap, DataPlane, Driver, DriverContext, DriverError, DriverPlan, EchoDriver, FastPath,
    Handle, HandleState, HandleTable, MethodSpec, OpenRequest, RequestGrantTemplate,
};
use andrias_types::{
    ConstraintSet, DecisionTag, DriverId, Expiry, Fact, Grant, HandleId, IdentityRef, MethodBitmap,
    MethodId, NodeId, Operation, OperationId, Outcome, OutcomeRef, OutputMode, OutputModeSet, Path,
    ProcessId, Purity, ReplayClass, ResourceId, ResourceName, ResourceSelector, RightFlags, Rights,
    TaintSet, Timestamp, Value, ValueRef,
};
use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
use criterion::{BatchSize, Criterion};
use std::hint::black_box;
use std::sync::{Arc, Mutex};
use tokio::runtime::{Builder, Runtime};

const FIXED_OPEN_MILLIS: i64 = 1_700_000_000_000;

#[derive(Default)]
struct BenchFailure {
    errors: Mutex<Vec<String>>,
}

impl BenchFailure {
    fn record(&self, err: anyhow::Error) {
        let mut errors = match self.errors.lock() {
            Ok(errors) => errors,
            Err(poisoned) => poisoned.into_inner(),
        };
        errors.push(format!("{err:?}"));
    }

    fn finish(&self) -> anyhow::Result<()> {
        let mut errors = match self.errors.lock() {
            Ok(errors) => errors,
            Err(poisoned) => poisoned.into_inner(),
        };
        let errors = std::mem::take(&mut *errors);
        if errors.is_empty() {
            return Ok(());
        }
        bail!(
            "benchmark reported {} error(s):\n{}",
            errors.len(),
            errors.join("\n")
        )
    }
}

fn capture_result<T>(failure: &BenchFailure, result: anyhow::Result<T>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(err) => {
            failure.record(err);
            None
        }
    }
}

fn capture_condition(failure: &BenchFailure, condition: bool, message: &'static str) {
    if !condition {
        failure.record(anyhow!(message));
    }
}

struct OpenFixture {
    boot: Bootstrap,
    process: ProcessId,
    resource: ResourceId,
    path: Path,
}

impl OpenFixture {
    fn new(effect_path: &str) -> anyhow::Result<Self> {
        let boot = Bootstrap::in_memory();
        let name = register_echo_effect(&boot, effect_path, Purity::Pure)?;
        let resource = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .context("registered effect did not resolve")?;
        let process = boot.root;
        Ok(Self {
            boot,
            process,
            resource,
            path: name.path().clone(),
        })
    }

    fn with_many_grants(effect_path: &str, grants: usize) -> anyhow::Result<Self> {
        let boot = Bootstrap::in_memory();
        let name = register_echo_effect(&boot, effect_path, Purity::Pure)?;
        let resource = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .context("registered effect did not resolve")?;
        let process = ProcessId::new(99_001);
        for i in 0..grants {
            let selector = ResourceSelector::parse(&format!("perform://effect/irrelevant/g{i}"))
                .with_context(|| format!("irrelevant grant selector {i} did not parse"))?;
            boot.kernel.registry.register_grant(Grant {
                id: boot.kernel.registry.next_grant_id(),
                holder: process,
                selector,
                rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        boot.kernel.registry.register_grant(Grant {
            id: boot.kernel.registry.next_grant_id(),
            holder: process,
            selector: ResourceSelector::parse("perform://effect/bench/open-many-grants")
                .context("matching grant selector did not parse")?,
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        Ok(Self {
            boot,
            process,
            resource,
            path: name.path().clone(),
        })
    }

    fn open_at(&self, handles: &mut HandleTable, now_millis: i64) -> anyhow::Result<HandleId> {
        let handle = andrias_kernel::open_resource(
            &self.boot.kernel.registry,
            handles,
            OpenRequest {
                process: self.process,
                resource: self.resource,
                verb: "perform".into(),
                rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                acting: IdentityRef::ROOT,
                requested_path: Some(self.path.clone()),
                now_millis,
            },
        )
        .context("open resource failed")?;
        Ok(handle)
    }
}

struct ChunkDriver {
    chunks: usize,
}

#[async_trait]
impl Driver for ChunkDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        for i in 0..self.chunks {
            ctx.emit(Value::Int(i as i64));
        }
        Ok(Outcome::Done(Value::Null))
    }
}

fn register_echo_effect(
    boot: &Bootstrap,
    path: &str,
    purity: Purity,
) -> anyhow::Result<ResourceName> {
    let name = boot
        .register_effect(
            path,
            &[MethodSpec::new(
                "invoke",
                purity,
                OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
            )],
            Arc::new(EchoDriver),
        )
        .context("effect registration failed")?;
    Ok(name)
}

fn unconstrained_dataplane_fixture(effect_path: &str) -> anyhow::Result<(DataPlane, Operation)> {
    let boot = Bootstrap::in_memory();
    let name = register_echo_effect(&boot, effect_path, Purity::Pure)?;
    let handle = boot
        .open_for(boot.root, &name, "perform")
        .context("root open failed")?;
    let op = operation(boot.root, handle, 0, Value::Int(42));
    Ok((boot.kernel.data_plane(), op))
}

fn conditional_dataplane_fixture() -> anyhow::Result<(DataPlane, Operation)> {
    conditional_dataplane_fixture_with_input(
        "effect://bench/conditional",
        Value::Str("acme".into()),
    )
}

fn conditional_denied_dataplane_fixture() -> anyhow::Result<(DataPlane, Operation)> {
    conditional_dataplane_fixture_with_input(
        "effect://bench/conditional-denied",
        Value::Str("other".into()),
    )
}

fn conditional_dataplane_fixture_with_input(
    effect_path: &str,
    tenant: Value,
) -> anyhow::Result<(DataPlane, Operation)> {
    let boot = Bootstrap::in_memory();
    let name = register_echo_effect(&boot, effect_path, Purity::Pure)?;
    let resource = boot
        .kernel
        .registry
        .resolve_resource(&name)
        .context("registered effect did not resolve")?;
    let child = boot
        .spawn_request_process_under_with_request_grants(boot.root, IdentityRef::ROOT, &[])
        .context("child process did not spawn")?;
    let grant = Grant {
        id: boot.kernel.registry.next_grant_id(),
        holder: child,
        selector: ResourceSelector::parse(&format!(
            "perform://{}",
            effect_path.replacen("://", "/", 1)
        ))
        .context("conditional grant selector did not parse")?,
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        constraints: ConstraintSet {
            predicates: vec![
                andrias_types::Predicate::parse("tenant=acme")
                    .context("conditional grant predicate did not parse")?,
            ],
        },
        expires: Expiry::Never,
    };
    boot.kernel.registry.register_grant(grant);

    let mut handles = boot.kernel.handles.write();
    let handle = andrias_kernel::open_resource(
        &boot.kernel.registry,
        &mut handles,
        OpenRequest {
            process: child,
            resource,
            verb: "perform".into(),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            acting: IdentityRef::ROOT,
            requested_path: Some(name.path().clone()),
            now_millis: FIXED_OPEN_MILLIS,
        },
    )
    .context("constrained open failed")?;
    drop(handles);

    let input = Value::Map([("tenant".into(), tenant)].into());
    let op = operation(child, handle, 0, input);
    Ok((boot.kernel.data_plane(), op))
}

fn idempotent_dataplane_fixture() -> anyhow::Result<(DataPlane, Operation)> {
    let boot = Bootstrap::in_memory();
    let name = register_echo_effect(&boot, "effect://bench/idempotent", Purity::Idempotent)?;
    let handle = boot
        .open_for(boot.root, &name, "perform")
        .context("root open failed")?;
    let op = operation(
        boot.root,
        handle,
        0,
        Value::Str("dedupe-keyed-input".into()),
    );
    Ok((boot.kernel.data_plane(), op))
}

fn collect_dataplane_fixture(chunks: usize) -> anyhow::Result<(DataPlane, Operation)> {
    let boot = Bootstrap::in_memory();
    let name = boot
        .register_effect(
            "effect://bench/collect",
            &[MethodSpec::new(
                "invoke",
                Purity::Pure,
                MethodSpec::STREAM_ASYNC,
            )],
            Arc::new(ChunkDriver { chunks }),
        )
        .context("streaming effect registration failed")?;
    let handle = boot
        .open_for(boot.root, &name, "perform")
        .context("root open failed")?;
    let mut op = operation(boot.root, handle, 0, Value::Null);
    op.output = OutputMode::Collect { limit: chunks };
    Ok((boot.kernel.data_plane(), op))
}

fn bench_handle(process: ProcessId, resource: ResourceId) -> Handle {
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(MethodId::new(0), Arc::new(EchoDriver));
    Handle {
        id: HandleId::new(0, 0),
        process,
        resource,
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    }
}

fn populated_handle_table(count: usize) -> (HandleTable, Vec<HandleId>) {
    let mut table = HandleTable::new();
    let ids = (0..count)
        .map(|i| {
            table.insert(bench_handle(
                ProcessId::new(1),
                ResourceId::new(i as u64 + 1),
            ))
        })
        .collect();
    (table, ids)
}

fn operation(process: ProcessId, handle: HandleId, node: u32, input: Value) -> Operation {
    Operation {
        id: OperationId::new(process, NodeId::new(node), 0),
        process,
        acting: IdentityRef::ROOT,
        handle,
        method: MethodId::new(0),
        input,
        taint: TaintSet::pristine(),
        output: OutputMode::Unary,
    }
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
        timestamp: Timestamp::millis(FIXED_OPEN_MILLIS),
    }
}

fn runtime() -> anyhow::Result<Runtime> {
    let runtime = Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .context("tokio runtime did not build")?;
    Ok(runtime)
}

fn bench_open(c: &mut Criterion) -> anyhow::Result<()> {
    let mut group = c.benchmark_group("kernel/open");
    let failure = BenchFailure::default();

    group.bench_function("open_resource_cold_compile", |b| {
        b.iter_batched_ref(
            || {
                capture_result(&failure, OpenFixture::new("effect://bench/open-cold"))
                    .map(|fixture| (fixture, HandleTable::new()))
            },
            |batch| {
                if let Some(handle) = batch.as_mut().and_then(|(fixture, handles)| {
                    capture_result(&failure, fixture.open_at(handles, FIXED_OPEN_MILLIS))
                }) {
                    black_box(handle);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("open_resource_cache_hit_fixed_time", |b| {
        b.iter_batched_ref(
            || {
                let fixture =
                    capture_result(&failure, OpenFixture::new("effect://bench/open-hit"))?;
                let mut warm_handles = HandleTable::new();
                let handle = capture_result(
                    &failure,
                    fixture.open_at(&mut warm_handles, FIXED_OPEN_MILLIS),
                )?;
                black_box(handle);
                Some((fixture, HandleTable::new()))
            },
            |batch| {
                if let Some(handle) = batch.as_mut().and_then(|(fixture, handles)| {
                    capture_result(&failure, fixture.open_at(handles, FIXED_OPEN_MILLIS))
                }) {
                    black_box(handle);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("open_resource_cache_miss_fresh_time", |b| {
        b.iter_batched_ref(
            || {
                let fixture =
                    capture_result(&failure, OpenFixture::new("effect://bench/open-fresh-time"))?;
                let mut warm_handles = HandleTable::new();
                let handle = capture_result(
                    &failure,
                    fixture.open_at(&mut warm_handles, FIXED_OPEN_MILLIS),
                )?;
                black_box(handle);
                Some((fixture, HandleTable::new()))
            },
            |batch| {
                if let Some(handle) = batch.as_mut().and_then(|(fixture, handles)| {
                    capture_result(&failure, fixture.open_at(handles, FIXED_OPEN_MILLIS + 1))
                }) {
                    black_box(handle);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("open_resource_cold_many_grants_4096", |b| {
        b.iter_batched_ref(
            || {
                capture_result(
                    &failure,
                    OpenFixture::with_many_grants("effect://bench/open-many-grants", 4_096),
                )
                .map(|fixture| (fixture, HandleTable::new()))
            },
            |batch| {
                if let Some(handle) = batch.as_mut().and_then(|(fixture, handles)| {
                    capture_result(&failure, fixture.open_at(handles, FIXED_OPEN_MILLIS))
                }) {
                    black_box(handle);
                }
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
    failure.finish()
}

fn bench_handle_table(c: &mut Criterion) -> anyhow::Result<()> {
    let mut group = c.benchmark_group("kernel/handle_table");
    let failure = BenchFailure::default();

    group.bench_function("get_16384_live_handles", |b| {
        let (table, ids) = populated_handle_table(16_384);
        let mut index = 0usize;
        b.iter(|| {
            index = (index + 1021) % ids.len();
            match table.get(black_box(ids[index])) {
                Some(handle) => {
                    black_box(handle.resource);
                }
                None => failure.record(anyhow!("handle must exist")),
            }
        });
    });

    group.bench_function("revoke_then_reuse_slot", |b| {
        b.iter_batched(
            || populated_handle_table(1),
            |(mut table, ids)| {
                let old = ids[0];
                capture_condition(&failure, table.revoke(old), "handle revoke failed");
                let new = table.insert(bench_handle(ProcessId::new(2), ResourceId::new(2)));
                black_box(new);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
    failure.finish()
}

fn bench_dataplane(c: &mut Criterion) -> anyhow::Result<()> {
    let rt = runtime()?;
    let mut group = c.benchmark_group("kernel/dataplane");
    let failure = BenchFailure::default();

    group.bench_function("execute_unconditional_echo_no_fact", |b| {
        let (plane, op) = match unconstrained_dataplane_fixture("effect://bench/dataplane-hot") {
            Ok(fixture) => fixture,
            Err(err) => {
                failure.record(err);
                return;
            }
        };
        b.iter(|| {
            let out = rt.block_on(plane.execute(
                black_box(&op),
                0,
                ReplayClass::Deterministic,
                OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
                FIXED_OPEN_MILLIS,
                false,
            ));
            black_box(out.outcome);
        });
    });

    group.bench_function("execute_conditional_constraint_no_fact", |b| {
        let (plane, op) = match conditional_dataplane_fixture() {
            Ok(fixture) => fixture,
            Err(err) => {
                failure.record(err);
                return;
            }
        };
        b.iter(|| {
            let out = rt.block_on(plane.execute(
                black_box(&op),
                0,
                ReplayClass::Deterministic,
                OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
                FIXED_OPEN_MILLIS,
                false,
            ));
            black_box(out.outcome);
        });
    });

    group.bench_function("execute_conditional_constraint_denied", |b| {
        let (plane, op) = match conditional_denied_dataplane_fixture() {
            Ok(fixture) => fixture,
            Err(err) => {
                failure.record(err);
                return;
            }
        };
        b.iter(|| {
            let out = rt.block_on(plane.execute(
                black_box(&op),
                0,
                ReplayClass::Deterministic,
                OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
                FIXED_OPEN_MILLIS,
                false,
            ));
            black_box(out.outcome);
        });
    });

    group.bench_function("execute_unconditional_echo_with_fact", |b| {
        let (plane, base_op) =
            match unconstrained_dataplane_fixture("effect://bench/dataplane-fact") {
                Ok(fixture) => fixture,
                Err(err) => {
                    failure.record(err);
                    return;
                }
            };
        let mut node = 0u32;
        b.iter(|| {
            node = node.wrapping_add(1);
            let mut op = base_op.clone();
            op.id = OperationId::new(op.process, NodeId::new(node), 0);
            let out = rt.block_on(plane.execute(
                black_box(&op),
                0,
                ReplayClass::Observation,
                OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
                FIXED_OPEN_MILLIS,
                true,
            ));
            black_box(out.outcome);
        });
    });

    group.bench_function("execute_idempotent_effect_dedup_hit", |b| {
        let (plane, op) = match idempotent_dataplane_fixture() {
            Ok(fixture) => fixture,
            Err(err) => {
                failure.record(err);
                return;
            }
        };
        let first = rt.block_on(plane.execute(
            &op,
            0,
            ReplayClass::IdempotentEffect,
            OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
            FIXED_OPEN_MILLIS,
            false,
        ));
        if !first.outcome.is_success() {
            failure.record(anyhow!("first idempotent run failed: {:?}", first.outcome));
            return;
        }
        b.iter(|| {
            let out = rt.block_on(plane.execute(
                black_box(&op),
                0,
                ReplayClass::IdempotentEffect,
                OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
                FIXED_OPEN_MILLIS,
                false,
            ));
            black_box(out.outcome);
        });
    });

    group.bench_function("execute_collect_stream_32_chunks", |b| {
        let (plane, base_op) = match collect_dataplane_fixture(32) {
            Ok(fixture) => fixture,
            Err(err) => {
                failure.record(err);
                return;
            }
        };
        let mut node = 0u32;
        b.iter(|| {
            node = node.wrapping_add(1);
            let mut op = base_op.clone();
            op.id = OperationId::new(op.process, NodeId::new(node), 0);
            let out = rt.block_on(plane.execute(
                black_box(&op),
                0,
                ReplayClass::Deterministic,
                MethodSpec::STREAM_ASYNC,
                FIXED_OPEN_MILLIS,
                false,
            ));
            black_box(out.outcome);
        });
    });

    group.bench_function("execute_unconditional_echo_concurrent_64", |b| {
        let (plane, op) =
            match unconstrained_dataplane_fixture("effect://bench/dataplane-concurrent") {
                Ok(fixture) => fixture,
                Err(err) => {
                    failure.record(err);
                    return;
                }
            };
        b.iter(|| {
            if let Err(err) = rt.block_on(run_concurrent_echo(
                black_box(plane.clone()),
                black_box(op.clone()),
                64,
            )) {
                failure.record(err);
            }
        });
    });

    group.finish();
    failure.finish()
}

async fn run_concurrent_echo(
    plane: DataPlane,
    op: Operation,
    workers: usize,
) -> anyhow::Result<()> {
    let mut tasks = Vec::with_capacity(workers);
    for i in 0..workers {
        let plane = plane.clone();
        let mut op = op.clone();
        op.id = OperationId::new(op.process, NodeId::new(i as u32), 0);
        tasks.push(tokio::spawn(async move {
            plane
                .execute(
                    &op,
                    0,
                    ReplayClass::Deterministic,
                    OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
                    FIXED_OPEN_MILLIS,
                    false,
                )
                .await
        }));
    }
    for task in tasks {
        let out = task
            .await
            .context("concurrent dataplane task did not join")?;
        match out.outcome {
            Outcome::Done(value) => {
                black_box(value);
            }
            other => bail!("expected successful echo outcome, got {other:?}"),
        }
    }
    Ok(())
}

fn bench_fact_sink(c: &mut Criterion) -> anyhow::Result<()> {
    let mut group = c.benchmark_group("kernel/fact_sink");
    let failure = BenchFailure::default();

    group.bench_function("in_memory_non_idempotent_begin_complete", |b| {
        let (sink, _) = andrias_kernel::FactSink::in_memory();
        let process = ProcessId::new(1);
        let mut node = 0u32;
        b.iter(|| {
            node = node.wrapping_add(1);
            if let Err(err) = sink
                .begin(fact(process, node, false))
                .context("begin fact failed")
            {
                failure.record(err);
            }
            if let Err(err) = sink
                .complete(fact(process, node, true))
                .context("complete fact failed")
            {
                failure.record(err);
            }
        });
    });

    group.finish();
    failure.finish()
}

// Cost of spawning a request Process under the root anchor. Request grants are
// attached to the Process, so the global grant registry is not written on this
// path. Measure 1, 4, and 16 request grant templates.
fn bench_request_spawn(c: &mut Criterion) -> anyhow::Result<()> {
    const CAPS: &[&str] = &[
        "perform://effect/inference/infer",
        "read://state/memory/alice/recent",
        "write://state/chat/telegram/out",
        "perform://effect/memory/recall",
        "perform://effect/blob/read",
        "perform://effect/time/now",
        "subscribe://state/events/extensions/x/y",
        "perform://effect/fetch/get",
        "read://state/memory/alice/persona",
        "perform://effect/embed/run",
        "write://state/memory/alice/learned",
        "perform://effect/rank/score",
        "perform://effect/approval/ask",
        "read://state/kernel/routing/inference",
        "perform://effect/compress/summarize",
        "perform://effect/deliberation/run",
    ];

    let mut group = c.benchmark_group("request_spawn");
    let failure = BenchFailure::default();
    for &k in &[1usize, 4, 16] {
        let grants: Vec<RequestGrantTemplate<'_>> = CAPS[..k]
            .iter()
            .map(|literal| RequestGrantTemplate {
                literal,
                methods: MethodBitmap::method(0),
            })
            .collect();
        group.bench_function(format!("request_grants_{k}"), |b| {
            b.iter_batched(
                Bootstrap::in_memory,
                |boot| {
                    if let Some(child) = capture_result(
                        &failure,
                        boot.spawn_request_process_under_with_request_grants(
                            boot.root,
                            IdentityRef::ROOT,
                            black_box(&grants),
                        )
                        .context("request process spawn failed"),
                    ) {
                        black_box(child);
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
    failure.finish()
}

fn main() -> anyhow::Result<()> {
    let mut criterion = Criterion::default().configure_from_args();
    bench_open(&mut criterion).context("kernel/open benchmarks failed")?;
    bench_handle_table(&mut criterion).context("kernel/handle_table benchmarks failed")?;
    bench_dataplane(&mut criterion).context("kernel/dataplane benchmarks failed")?;
    bench_fact_sink(&mut criterion).context("kernel/fact_sink benchmarks failed")?;
    bench_request_spawn(&mut criterion).context("request_spawn benchmarks failed")?;
    criterion.final_summary();
    Ok(())
}
