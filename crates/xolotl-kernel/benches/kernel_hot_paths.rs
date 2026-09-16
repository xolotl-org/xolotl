use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
use criterion::{BatchSize, BenchmarkId, Criterion};
use std::hint::black_box;
use std::sync::{Arc, Mutex};
use tokio::runtime::{Builder, Runtime};
use xolotl_kernel::{
    Bootstrap, DataPlane, Driver, DriverContext, DriverError, DriverPlan, EchoDriver, FastPath,
    Handle, HandleState, HandleTable, InvocationOptions, MethodSpec, OpenRequest,
    RequestGrantTemplate,
};
use xolotl_types::{
    ConstraintSet, DecisionTag, DriverId, ExecutionId, Expiry, Fact, Grant, HandleId, IdentityRef,
    InvocationId, MethodBitmap, MethodContract, MethodId, NodeId, Operation, OperationId, Outcome,
    OutputMode, OutputModeSet, Path, ProcessId, Purity, ReplayClass, ResourceId, ResourceName,
    ResourceSelector, RightFlags, Rights, TaintSet, Timestamp, Value,
};

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
        let handle = xolotl_kernel::open_resource(
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
    ) -> Result<xolotl_kernel::DriverOutput, DriverError> {
        for i in 0..self.chunks {
            ctx.emit(Value::integer(i as i64)).await?;
        }
        Ok(xolotl_kernel::DriverOutput::new(Outcome::Done(
            Value::null(),
        )))
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

fn unconstrained_dataplane_fixture(
    effect_path: &str,
    observes_external: bool,
) -> anyhow::Result<(DataPlane, Operation)> {
    let boot = Bootstrap::in_memory();
    let method = MethodSpec {
        observes_external,
        ..MethodSpec::unary_async("invoke", Purity::Pure)
    };
    let name = boot.register_effect(effect_path, &[method], Arc::new(EchoDriver))?;
    let handle = boot
        .open_for(boot.root, &name, "perform")
        .context("root open failed")?;
    let op = operation(boot.root, handle, 0, Value::integer(42));
    Ok((boot.kernel.data_plane(), op))
}

fn conditional_dataplane_fixture() -> anyhow::Result<(DataPlane, Operation)> {
    conditional_dataplane_fixture_with_input(
        "effect://bench/conditional",
        Value::string("acme".into()),
    )
}

fn conditional_denied_dataplane_fixture() -> anyhow::Result<(DataPlane, Operation)> {
    conditional_dataplane_fixture_with_input(
        "effect://bench/conditional-denied",
        Value::string("other".into()),
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
                xolotl_types::Predicate::parse("tenant=acme")
                    .context("conditional grant predicate did not parse")?,
            ],
        },
        expires: Expiry::Never,
    };
    boot.kernel.registry.register_grant(grant);

    let mut handles = boot.kernel.handles.write();
    let handle = xolotl_kernel::open_resource(
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

    let input = Value::map([("tenant".into(), tenant)].into());
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
        Value::string("dedupe-keyed-input".into()),
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
    let mut op = operation(boot.root, handle, 0, Value::null());
    op.output = OutputMode::Collect { limit: chunks };
    Ok((boot.kernel.data_plane(), op))
}

fn bench_handle(process: ProcessId, resource: ResourceId) -> Handle {
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(0),
        MethodContract::new(0, ReplayClass::Deterministic, OutputModeSet::UNARY),
        Arc::new(EchoDriver),
    );
    Handle {
        id: HandleId::new(0, 0),
        process,
        acting: IdentityRef::ROOT,
        resource,
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    }
}

fn populated_handle_table(count: usize) -> anyhow::Result<(HandleTable, Vec<HandleId>)> {
    let mut table = HandleTable::new();
    let ids = (0..count)
        .map(|i| {
            table.insert(bench_handle(
                ProcessId::new(1),
                ResourceId::new(i as u64 + 1),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((table, ids))
}

fn operation_id(process: ProcessId, node: u32) -> OperationId {
    OperationId::new(
        process,
        ExecutionId::FIRST,
        InvocationId::new(u64::from(node) + 1),
        NodeId::new(node),
        0,
    )
}

fn operation(process: ProcessId, handle: HandleId, node: u32, input: Value) -> Operation {
    Operation {
        id: operation_id(process, node),
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
        id: operation_id(process, node),
        schema_version: Fact::SCHEMA_VERSION,
        caller: process,
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

    let (table, ids) = populated_handle_table(16_384)?;
    group.bench_function("get_16384_live_handles", |b| {
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
            |fixture| {
                let Some((mut table, ids)) = capture_result(&failure, fixture) else {
                    return;
                };
                let old = ids[0];
                capture_condition(&failure, table.revoke(old), "handle revoke failed");
                if let Some(new) = capture_result(
                    &failure,
                    table
                        .insert(bench_handle(ProcessId::new(2), ResourceId::new(2)))
                        .context("replacement handle admission failed"),
                ) {
                    black_box(new);
                }
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
        let (plane, op) =
            match unconstrained_dataplane_fixture("effect://bench/dataplane-hot", false) {
                Ok(fixture) => fixture,
                Err(err) => {
                    failure.record(err);
                    return;
                }
            };
        b.iter(|| {
            let out = rt.block_on(plane.execute(
                black_box(&op),
                InvocationOptions {
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                },
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
                InvocationOptions {
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                },
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
                InvocationOptions {
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                },
            ));
            black_box(out.outcome);
        });
    });

    group.bench_function("execute_unconditional_echo_with_fact", |b| {
        let (plane, base_op) =
            match unconstrained_dataplane_fixture("effect://bench/dataplane-fact", true) {
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
            op.id = operation_id(op.process, node);
            let out = rt.block_on(plane.execute(
                black_box(&op),
                InvocationOptions {
                    now_millis: FIXED_OPEN_MILLIS,
                    record: true,
                },
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
            InvocationOptions {
                now_millis: FIXED_OPEN_MILLIS,
                record: false,
            },
        ));
        if !first.outcome.is_success() {
            failure.record(anyhow!("first idempotent run failed: {:?}", first.outcome));
            return;
        }
        b.iter(|| {
            let out = rt.block_on(plane.execute(
                black_box(&op),
                InvocationOptions {
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                },
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
            op.id = operation_id(op.process, node);
            let out = rt.block_on(plane.execute(
                black_box(&op),
                InvocationOptions {
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                },
            ));
            black_box(out.outcome);
        });
    });

    group.bench_function("execute_unconditional_echo_concurrent_64", |b| {
        let (plane, op) =
            match unconstrained_dataplane_fixture("effect://bench/dataplane-concurrent", false) {
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
        op.id = operation_id(op.process, i as u32);
        tasks.push(tokio::spawn(async move {
            plane
                .execute(
                    &op,
                    InvocationOptions {
                        now_millis: FIXED_OPEN_MILLIS,
                        record: false,
                    },
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
        let (sink, _) = xolotl_kernel::FactSink::in_memory();
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

fn bench_fact_reads(c: &mut Criterion) -> anyhow::Result<()> {
    use std::num::NonZeroUsize;
    use xolotl_kernel::{FactLookup, FactLookupResult, FactOrder, FactQuery};

    let query = FactQuery::new(
        NonZeroUsize::new(64).context("nonzero page limit")?,
        NonZeroUsize::new(1024 * 1024).context("nonzero byte limit")?,
    );
    let mut group = c.benchmark_group("kernel/fact_reads");
    let failure = BenchFailure::default();
    for count in [64u32, 4096, 65536] {
        let (sink, _) = xolotl_kernel::FactSink::in_memory();
        for node in 0..count {
            sink.begin(fact(ProcessId::new(1), node, true))?;
        }
        let target = fact(ProcessId::new(1), count - 1, true).id;
        for (name, query) in [
            ("scan_page_64", query),
            (
                "reverse_page_64",
                FactQuery {
                    order: FactOrder::Reverse,
                    ..query
                },
            ),
            (
                "reverse_sparse_64",
                FactQuery {
                    order: FactOrder::Reverse,
                    process: Some(ProcessId::new(99)),
                    ..query
                },
            ),
        ] {
            group.bench_function(BenchmarkId::new(name, count), |b| {
                b.iter(|| {
                    let page =
                        capture_result(&failure, sink.scan(black_box(query)).map_err(Into::into));
                    if let Some(page) = page {
                        let expected = if query.process.is_some() { 0 } else { 64 };
                        capture_condition(
                            &failure,
                            page.facts.len() == expected,
                            "fact page size mismatch",
                        );
                        capture_condition(
                            &failure,
                            page.examined == 64,
                            "fact candidate budget mismatch",
                        );
                        black_box(page);
                    }
                });
            });
        }
        group.bench_function(BenchmarkId::new("bounded_get", count), |b| {
            b.iter(|| {
                let record = capture_result(
                    &failure,
                    sink.get_bounded(black_box(target), query.max_encoded_bytes)
                        .map_err(Into::into),
                );
                if let Some(record) = record {
                    capture_condition(&failure, record.is_some(), "bounded fact lookup missed");
                    black_box(record);
                }
            });
        });
        for (name, process) in [("scoped_get", 1), ("filtered_lookup", 99)] {
            let lookup = FactLookup {
                id: target,
                process: Some(ProcessId::new(process)),
                max_encoded_bytes: if process == 1 {
                    query.max_encoded_bytes
                } else {
                    NonZeroUsize::MIN
                },
            };
            group.bench_function(BenchmarkId::new(name, count), |b| {
                b.iter(|| {
                    let result = capture_result(
                        &failure,
                        sink.lookup(black_box(lookup)).map_err(Into::into),
                    );
                    if let Some(result) = result {
                        capture_condition(
                            &failure,
                            if process == 1 {
                                matches!(&result, FactLookupResult::Found(fact) if fact.id == target)
                            } else {
                                matches!(&result, FactLookupResult::FilteredOut)
                            },
                            "scoped fact lookup result mismatch",
                        );
                        black_box(result);
                    }
                });
            });
        }
        group.bench_function(BenchmarkId::new("get", count), |b| {
            b.iter(|| {
                let record =
                    capture_result(&failure, sink.get(black_box(target)).map_err(Into::into));
                if let Some(record) = record {
                    capture_condition(&failure, record.is_some(), "fact lookup missed");
                    black_box(record);
                }
            });
        });
        group.bench_function(BenchmarkId::new("all_facts", count), |b| {
            b.iter(|| {
                let records = capture_result(&failure, sink.all_facts().map_err(Into::into));
                black_box(records);
            });
        });
    }
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

fn bench_process_reaping(c: &mut Criterion) -> anyhow::Result<()> {
    const BATCH: usize = 64;
    let runtime = Builder::new_current_thread().enable_all().build()?;
    let failure = BenchFailure::default();
    let mut group = c.benchmark_group("process_reaping");
    group.throughput(criterion::Throughput::Elements(BATCH as u64));
    for live in [64usize, 4096, 65_536] {
        let mut boot = Bootstrap::in_memory();
        for _ in 0..live {
            boot.request_under(boot.root, IdentityRef::ROOT, &[])?
                .detach();
        }
        group.bench_function(BenchmarkId::new("batch_64", live), |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = std::time::Duration::ZERO;
                for _ in 0..iterations {
                    // Bound benchmark history between batches, while retaining the
                    // same process table and identity source. Only reaping is timed.
                    boot.kernel.facts = xolotl_kernel::FactSink::in_memory().0;
                    boot.kernel.state = xolotl_state::InMemoryBackend::new().into_backend();
                    let prepared: anyhow::Result<()> = runtime.block_on(async {
                        for _ in 0..BATCH {
                            boot.request_under(boot.root, IdentityRef::ROOT, &[])?
                                .finish(&xolotl_types::ExecutionOutput::new(
                                    Outcome::Done(Value::null()),
                                    xolotl_types::TaintSet::pristine(),
                                ))
                                .await?;
                        }
                        Ok(())
                    });
                    if capture_result(&failure, prepared).is_none() {
                        break;
                    }
                    let start = std::time::Instant::now();
                    let reaped = black_box(boot.kernel.processes.reap_finalized(BATCH));
                    elapsed += start.elapsed();
                    capture_condition(&failure, reaped == BATCH, "reaping missed completed leaves");
                }
                elapsed
            });
        });
    }
    group.finish();
    failure.finish()
}

fn bench_prepared_program(c: &mut Criterion) -> anyhow::Result<()> {
    use xolotl_graph::portable::{Expression as E, Program, Transform};
    use xolotl_kernel::{ExecutionBuffers, ExecutionConfig, PreparedProgram};
    use xolotl_state::TaintedValue;

    let runtime = Builder::new_current_thread().enable_all().build()?;
    let boot = Bootstrap::in_memory();
    let executor = boot.kernel.executor_for(boot.root);
    let failure = BenchFailure::default();
    let mut group = c.benchmark_group("kernel/prepared");
    for (name, body, expected) in [
        ("input", E::Input, Value::integer(0)),
        (
            "transforms_64",
            E::Sequence {
                steps: vec![
                    E::Transform {
                        operation: Transform::Add { value: 1 }
                    };
                    64
                ],
            },
            Value::integer(64),
        ),
        (
            "sequential_forks_64",
            E::Sequence {
                steps: vec![E::literal(1).both(E::literal(2)); 64],
            },
            Value::list(vec![Value::integer(1), Value::integer(2)]),
        ),
        (
            "asymmetric_stacks",
            (0..32)
                .fold(E::Input, |body, _| body.finally(E::Input))
                .both(E::Input),
            Value::list(vec![Value::integer(0), Value::integer(0)]),
        ),
    ] {
        let program = PreparedProgram::new(&Program::new(body).compile()?)?;
        let expected = Outcome::Done(expected);
        group.bench_function(name, |b| {
            b.iter(|| {
                let output = runtime.block_on(executor.eval_prepared(
                    black_box(&program),
                    TaintedValue::pristine(Value::integer(0)),
                ));
                capture_condition(
                    &failure,
                    output.outcome == expected,
                    "prepared program output mismatch",
                );
                black_box(output);
            });
        });
        let mut buffers = ExecutionBuffers::default();
        buffers.reserve_for(&program, &ExecutionConfig::default())?;
        group.bench_function(format!("{name}_reused"), |b| {
            b.iter(|| {
                let output = runtime.block_on(executor.eval_prepared_with_buffers(
                    black_box(&program),
                    TaintedValue::pristine(Value::integer(0)),
                    &mut buffers,
                ));
                capture_condition(
                    &failure,
                    output.outcome == expected,
                    "reused program output mismatch",
                );
                black_box(output);
            });
        });
    }
    group.finish();
    failure.finish()
}

fn bench_payload_program(c: &mut Criterion) -> anyhow::Result<()> {
    use xolotl_graph::portable::{Expression as E, Program};
    use xolotl_kernel::{ExecutionBuffers, ExecutionConfig, PreparedProgram};
    use xolotl_state::TaintedValue;

    let runtime = Builder::new_current_thread().enable_all().build()?;
    let boot = Bootstrap::in_memory();
    let executor = boot.kernel.executor_for(boot.root);
    let failure = BenchFailure::default();
    let mut group = c.benchmark_group("kernel/payload");
    for size in [64 * 1024, 1024 * 1024] {
        let input = Value::bytes(vec![0x5a; size]);
        for (name, body, expected) in [
            ("input", E::Input, input.clone()),
            (
                "inputs_64",
                E::Sequence {
                    steps: vec![E::Input; 64],
                },
                input.clone(),
            ),
            (
                "fork",
                E::Input.both(E::Input),
                Value::list(vec![input.clone(), input.clone()]),
            ),
            ("race", E::Input.race(E::Input), input.clone()),
        ] {
            let program = PreparedProgram::new(&Program::new(body).compile()?)?;
            let mut buffers = ExecutionBuffers::default();
            buffers.reserve_for(&program, &ExecutionConfig::default())?;
            capture_condition(
                &failure,
                runtime
                    .block_on(executor.eval_prepared_with_buffers(
                        &program,
                        TaintedValue::pristine(input.clone()),
                        &mut buffers,
                    ))
                    .outcome
                    == Outcome::Done(expected),
                "payload program output mismatch",
            );
            group.bench_with_input(BenchmarkId::new(name, size), &input, |b, input| {
                // Isolate execution from input creation and final output destruction.
                b.iter_batched(
                    || TaintedValue::pristine(input.clone()),
                    |input| {
                        black_box(runtime.block_on(executor.eval_prepared_with_buffers(
                            black_box(&program),
                            input,
                            &mut buffers,
                        )))
                    },
                    BatchSize::PerIteration,
                );
            });
        }
    }
    group.finish();
    failure.finish()
}

fn bench_native_admission(c: &mut Criterion) -> anyhow::Result<()> {
    use std::{io::Write, mem::size_of};
    use xolotl_graph::{DoNode, StepRef, compile_do};
    use xolotl_kernel::{ExecutionBuffers, ExecutionConfig};
    use xolotl_state::TaintedValue;

    let runtime = Builder::new_current_thread().enable_all().build()?;
    let boot = Bootstrap::in_memory();
    let executor = boot.kernel.executor_for(boot.root);
    let failure = BenchFailure::default();
    let mut group = c.benchmark_group("kernel/native");
    for depth in [1, 64] {
        let body = (0..depth).fold(DoNode::pure(Value::integer(42)), |body, _| {
            body.or_else(StepRef::new("unused"))
        });
        let graph = compile_do(&body)?;
        group.bench_function(BenchmarkId::new("dormant_recovery", depth), |b| {
            b.iter(|| {
                let output = runtime.block_on(executor.eval_graph(black_box(&graph)));
                capture_condition(
                    &failure,
                    output.outcome == Outcome::Done(Value::integer(42)),
                    "dormant native recovery output mismatch",
                );
                black_box(output);
            });
        });
        let mut buffers = ExecutionBuffers::default();
        group.bench_function(BenchmarkId::new("dormant_recovery_reused", depth), |b| {
            b.iter(|| {
                let output = runtime
                    .block_on(executor.eval_graph_with_buffers(black_box(&graph), &mut buffers));
                capture_condition(
                    &failure,
                    output.outcome == Outcome::Done(Value::integer(42)),
                    "reused dormant native recovery output mismatch",
                );
                black_box(output);
            });
        });
        if buffers.retained_bytes() != 0 {
            let config = ExecutionConfig::default();
            let eager = config.max_tasks
                * size_of::<xolotl_core::Task<TaintedValue, xolotl_types::TaintedFailure>>()
                + config.max_frames
                    * size_of::<
                        Option<xolotl_core::Frame<TaintedValue, xolotl_types::TaintedFailure>>,
                    >()
                + config.max_tasks * config.bindings_per_task * size_of::<Option<TaintedValue>>();
            writeln!(
                std::io::stdout().lock(),
                "native recovery depth {depth}: {} B retained; previous eager layout: {eager} B",
                buffers.retained_bytes(),
            )?;
        }
    }
    group.finish();
    failure.finish()
}

fn bench_native_steps(c: &mut Criterion) -> anyhow::Result<()> {
    use xolotl_graph::{ActorSpec, DoNode, StepRef, compile_do};
    use xolotl_kernel::{ExecutionBuffers, StepModule};

    let runtime = Builder::new_current_thread().enable_all().build()?;
    let boot = Bootstrap::in_memory();
    let actor = runtime.block_on(boot.spawn_actor_under_with_steps(
        boot.root,
        IdentityRef::ROOT,
        "root",
        &ActorSpec {
            name: "native_steps".into(),
            body: DoNode::wait_signal(Path::parse("state://bench/native/hold")?),
            ..ActorSpec::default()
        },
        StepModule::single("increment", |input, _| match input.as_int() {
            Some(value) => DoNode::pure(value + 1),
            _ => DoNode::fail(xolotl_types::Failure::InvalidInput {
                reason: "expected integer".into(),
            }),
        })?,
    ))?;
    let executor = boot.kernel.executor_for(actor.process);
    let failure = BenchFailure::default();
    let mut group = c.benchmark_group("kernel/native_steps");
    for depth in [1, 64] {
        let body = (0..depth).fold(DoNode::pure(0), |body, _| {
            body.and_then(StepRef::new("increment"))
        });
        let graph = compile_do(&body)?;
        let mut buffers = ExecutionBuffers::default();
        group.bench_function(BenchmarkId::new("sequential_reused", depth), |b| {
            b.iter(|| {
                let output = runtime
                    .block_on(executor.eval_graph_with_buffers(black_box(&graph), &mut buffers));
                capture_condition(
                    &failure,
                    output.outcome == Outcome::Done(Value::integer(depth)),
                    "native step output mismatch",
                );
                black_box(output);
            });
        });
    }
    group.finish();
    runtime.block_on(boot.finalize_process(actor.process))?;
    failure.finish()
}

fn bench_execution_ids(c: &mut Criterion) -> anyhow::Result<()> {
    let ids =
        xolotl_kernel::ExecutionIds::new(Arc::new(xolotl_kernel::InMemoryExecutionIdSource::new()));
    let execution = ids.allocate()?;
    let id = OperationId::new(
        ProcessId::new(1),
        execution,
        InvocationId::new(1),
        NodeId::ROOT,
        0,
    );
    let mut group = c.benchmark_group("kernel/execution_identity");
    group.bench_function("allocate_amortized", |b| {
        b.iter(|| black_box(ids.allocate()))
    });
    group.bench_function("canonical_bytes", |b| {
        b.iter(|| black_box(black_box(id).to_bytes()))
    });
    group.finish();
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let mut criterion = Criterion::default().configure_from_args();
    bench_open(&mut criterion).context("kernel/open benchmarks failed")?;
    bench_handle_table(&mut criterion).context("kernel/handle_table benchmarks failed")?;
    bench_dataplane(&mut criterion).context("kernel/dataplane benchmarks failed")?;
    bench_fact_sink(&mut criterion).context("kernel/fact_sink benchmarks failed")?;
    bench_fact_reads(&mut criterion).context("kernel/fact_reads benchmarks failed")?;
    bench_request_spawn(&mut criterion).context("request_spawn benchmarks failed")?;
    bench_process_reaping(&mut criterion).context("process reaping benchmarks failed")?;
    bench_prepared_program(&mut criterion).context("prepared program benchmarks failed")?;
    bench_payload_program(&mut criterion).context("payload program benchmarks failed")?;
    bench_native_admission(&mut criterion).context("native admission benchmarks failed")?;
    bench_native_steps(&mut criterion).context("native step benchmarks failed")?;
    bench_execution_ids(&mut criterion).context("execution identity benchmarks failed")?;
    criterion.final_summary();
    Ok(())
}
