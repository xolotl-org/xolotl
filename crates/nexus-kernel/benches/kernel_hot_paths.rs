use async_trait::async_trait;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use nexus_kernel::{
    Bootstrap, DataPlane, Driver, DriverContext, DriverError, DriverPlan, EchoDriver, FastPath,
    Handle, HandleState, HandleTable, MethodSpec, OpenRequest, RequestGrantTemplate,
};
use nexus_types::{
    ConstraintSet, DecisionTag, DriverId, Expiry, Fact, Grant, HandleId, IdentityRef, MethodBitmap,
    MethodId, NodeId, Operation, OperationId, Outcome, OutcomeRef, OutputMode, OutputModeSet, Path,
    ProcessId, Purity, ReplayClass, ResourceId, ResourceName, ResourceSelector, RightFlags, Rights,
    TaintSet, Timestamp, Value, ValueRef,
};
use std::hint::black_box;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

const FIXED_OPEN_MILLIS: i64 = 1_700_000_000_000;

struct OpenFixture {
    boot: Bootstrap,
    process: ProcessId,
    resource: ResourceId,
    path: Path,
}

impl OpenFixture {
    fn new(effect_path: &str) -> Self {
        let boot = Bootstrap::in_memory();
        let name = register_echo_effect(&boot, effect_path, Purity::Pure);
        let resource = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .expect("registered effect must resolve");
        let process = boot.root;
        Self {
            boot,
            process,
            resource,
            path: name.path().clone(),
        }
    }

    fn with_many_grants(effect_path: &str, grants: usize) -> Self {
        let boot = Bootstrap::in_memory();
        let name = register_echo_effect(&boot, effect_path, Purity::Pure);
        let resource = boot
            .kernel
            .registry
            .resolve_resource(&name)
            .expect("registered effect must resolve");
        let process = ProcessId::new(99_001);
        for i in 0..grants {
            boot.kernel.registry.register_grant(Grant {
                id: boot.kernel.registry.next_grant_id(),
                holder: process,
                selector: ResourceSelector::parse(&format!("perform://effect/irrelevant/g{i}"))
                    .expect("irrelevant selector must parse"),
                rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        boot.kernel.registry.register_grant(Grant {
            id: boot.kernel.registry.next_grant_id(),
            holder: process,
            selector: ResourceSelector::parse("perform://effect/bench/open-many-grants")
                .expect("matching selector must parse"),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            constraints: ConstraintSet::empty(),
            expires: Expiry::Never,
        });
        Self {
            boot,
            process,
            resource,
            path: name.path().clone(),
        }
    }

    fn open_at(&self, handles: &mut HandleTable, now_millis: i64) -> HandleId {
        nexus_kernel::open_resource(
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
        .expect("open must succeed")
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

fn register_echo_effect(boot: &Bootstrap, path: &str, purity: Purity) -> ResourceName {
    boot.register_effect(
        path,
        &[MethodSpec::new(
            "invoke",
            purity,
            OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
        )],
        Arc::new(EchoDriver),
    )
    .expect("effect registration must succeed")
}

fn unconstrained_dataplane_fixture(effect_path: &str) -> (DataPlane, Operation) {
    let boot = Bootstrap::in_memory();
    let name = register_echo_effect(&boot, effect_path, Purity::Pure);
    let handle = boot
        .open_for(boot.root, &name, "perform")
        .expect("root open must succeed");
    let op = operation(boot.root, handle, 0, Value::Int(42));
    (boot.kernel.data_plane(), op)
}

fn conditional_dataplane_fixture() -> (DataPlane, Operation) {
    conditional_dataplane_fixture_with_input(
        "effect://bench/conditional",
        Value::Str("acme".into()),
    )
}

fn conditional_denied_dataplane_fixture() -> (DataPlane, Operation) {
    conditional_dataplane_fixture_with_input(
        "effect://bench/conditional-denied",
        Value::Str("other".into()),
    )
}

fn conditional_dataplane_fixture_with_input(
    effect_path: &str,
    tenant: Value,
) -> (DataPlane, Operation) {
    let boot = Bootstrap::in_memory();
    let name = register_echo_effect(&boot, effect_path, Purity::Pure);
    let resource = boot
        .kernel
        .registry
        .resolve_resource(&name)
        .expect("registered effect must resolve");
    let child = boot
        .spawn_request_process_under_with_request_grants(boot.root, IdentityRef::ROOT, &[])
        .expect("child process must spawn");
    let grant = Grant {
        id: boot.kernel.registry.next_grant_id(),
        holder: child,
        selector: ResourceSelector::parse(&format!(
            "perform://{}",
            effect_path.replacen("://", "/", 1)
        ))
        .expect("selector must parse"),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        constraints: ConstraintSet {
            predicates: vec![
                nexus_types::Predicate::parse("tenant=acme").expect("predicate must parse"),
            ],
        },
        expires: Expiry::Never,
    };
    boot.kernel.registry.register_grant(grant);

    let mut handles = boot.kernel.handles.write();
    let handle = nexus_kernel::open_resource(
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
    .expect("constrained open must succeed");
    drop(handles);

    let input = Value::Map([("tenant".into(), tenant)].into());
    let op = operation(child, handle, 0, input);
    (boot.kernel.data_plane(), op)
}

fn idempotent_dataplane_fixture() -> (DataPlane, Operation) {
    let boot = Bootstrap::in_memory();
    let name = register_echo_effect(&boot, "effect://bench/idempotent", Purity::Idempotent);
    let handle = boot
        .open_for(boot.root, &name, "perform")
        .expect("root open must succeed");
    let op = operation(
        boot.root,
        handle,
        0,
        Value::Str("dedupe-keyed-input".into()),
    );
    (boot.kernel.data_plane(), op)
}

fn collect_dataplane_fixture(chunks: usize) -> (DataPlane, Operation) {
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
        .expect("streaming effect registration must succeed");
    let handle = boot
        .open_for(boot.root, &name, "perform")
        .expect("root open must succeed");
    let mut op = operation(boot.root, handle, 0, Value::Null);
    op.output = OutputMode::Collect { limit: chunks };
    (boot.kernel.data_plane(), op)
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

fn runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("tokio runtime must build")
}

fn bench_open(c: &mut Criterion) {
    let mut group = c.benchmark_group("kernel/open");

    group.bench_function("open_resource_cold_compile", |b| {
        b.iter_batched_ref(
            || {
                (
                    OpenFixture::new("effect://bench/open-cold"),
                    HandleTable::new(),
                )
            },
            |(fixture, handles)| {
                black_box(fixture.open_at(handles, FIXED_OPEN_MILLIS));
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("open_resource_cache_hit_fixed_time", |b| {
        b.iter_batched_ref(
            || {
                let fixture = OpenFixture::new("effect://bench/open-hit");
                let mut warm_handles = HandleTable::new();
                fixture.open_at(&mut warm_handles, FIXED_OPEN_MILLIS);
                (fixture, HandleTable::new())
            },
            |(fixture, handles)| {
                black_box(fixture.open_at(handles, FIXED_OPEN_MILLIS));
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("open_resource_cache_miss_fresh_time", |b| {
        b.iter_batched_ref(
            || {
                let fixture = OpenFixture::new("effect://bench/open-fresh-time");
                let mut warm_handles = HandleTable::new();
                fixture.open_at(&mut warm_handles, FIXED_OPEN_MILLIS);
                (fixture, HandleTable::new())
            },
            |(fixture, handles)| {
                black_box(fixture.open_at(handles, FIXED_OPEN_MILLIS + 1));
            },
            BatchSize::SmallInput,
        );
    });

    group.bench_function("open_resource_cold_many_grants_4096", |b| {
        b.iter_batched_ref(
            || {
                (
                    OpenFixture::with_many_grants("effect://bench/open-many-grants", 4_096),
                    HandleTable::new(),
                )
            },
            |(fixture, handles)| {
                black_box(fixture.open_at(handles, FIXED_OPEN_MILLIS));
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_handle_table(c: &mut Criterion) {
    let mut group = c.benchmark_group("kernel/handle_table");

    group.bench_function("get_16384_live_handles", |b| {
        let (table, ids) = populated_handle_table(16_384);
        let mut index = 0usize;
        b.iter(|| {
            index = (index + 1021) % ids.len();
            let handle = table.get(black_box(ids[index])).expect("handle must exist");
            black_box(handle.resource);
        });
    });

    group.bench_function("revoke_then_reuse_slot", |b| {
        b.iter_batched(
            || populated_handle_table(1),
            |(mut table, ids)| {
                let old = ids[0];
                assert!(table.revoke(old));
                let new = table.insert(bench_handle(ProcessId::new(2), ResourceId::new(2)));
                black_box(new);
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_dataplane(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("kernel/dataplane");

    group.bench_function("execute_unconditional_echo_no_fact", |b| {
        let (plane, op) = unconstrained_dataplane_fixture("effect://bench/dataplane-hot");
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
        let (plane, op) = conditional_dataplane_fixture();
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
        let (plane, op) = conditional_denied_dataplane_fixture();
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
        let (plane, base_op) = unconstrained_dataplane_fixture("effect://bench/dataplane-fact");
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
        let (plane, op) = idempotent_dataplane_fixture();
        let first = rt.block_on(plane.execute(
            &op,
            0,
            ReplayClass::IdempotentEffect,
            OutputModeSet::UNARY | OutputModeSet::ASYNC_PROCESS,
            FIXED_OPEN_MILLIS,
            false,
        ));
        assert!(first.outcome.is_success());
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
        let (plane, base_op) = collect_dataplane_fixture(32);
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
        let (plane, op) = unconstrained_dataplane_fixture("effect://bench/dataplane-concurrent");
        b.iter(|| {
            rt.block_on(run_concurrent_echo(
                black_box(plane.clone()),
                black_box(op.clone()),
                64,
            ));
        });
    });

    group.finish();
}

async fn run_concurrent_echo(plane: DataPlane, op: Operation, workers: usize) {
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
        let out = task.await.expect("concurrent dataplane task must join");
        match out.outcome {
            Outcome::Done(value) => {
                black_box(value);
            }
            other => panic!("expected successful echo outcome, got {other:?}"),
        }
    }
}

fn bench_fact_sink(c: &mut Criterion) {
    let mut group = c.benchmark_group("kernel/fact_sink");

    group.bench_function("in_memory_non_idempotent_begin_complete", |b| {
        let (sink, _) = nexus_kernel::FactSink::in_memory();
        let process = ProcessId::new(1);
        let mut node = 0u32;
        b.iter(|| {
            node = node.wrapping_add(1);
            sink.begin(fact(process, node, false))
                .expect("begin fact must succeed");
            sink.complete(fact(process, node, true))
                .expect("complete fact must succeed");
        });
    });

    group.finish();
}

// Cost of spawning a request Process under the root anchor. Request grants are
// attached to the Process, so the global grant registry is not written on this
// path. Measure 1, 4, and 16 request grant templates.
fn bench_request_spawn(c: &mut Criterion) {
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
                    let child = boot
                        .spawn_request_process_under_with_request_grants(
                            boot.root,
                            IdentityRef::ROOT,
                            black_box(&grants),
                        )
                        .expect("root anchor covers request grant templates");
                    black_box(child);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_open,
    bench_handle_table,
    bench_dataplane,
    bench_fact_sink,
    bench_request_spawn
);
criterion_main!(benches);
