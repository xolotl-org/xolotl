use anyhow::{Context, anyhow, bail, ensure};
use async_trait::async_trait;
use criterion::{BatchSize, BenchmarkId, Criterion};
use std::hint::black_box;
use std::sync::{Arc, Mutex};
use tokio::runtime::{Builder, Runtime};
use xolotl_graph::OperationTemplate;
use xolotl_kernel::{
    Bootstrap, DataPlane, Driver, DriverContext, DriverError, DriverPlan, EchoDriver, FactStore,
    FastPath, Handle, HandleTable, InvocationOptions, KernelBuilder, MethodSpec, OpenRequest,
    RequestGrantTemplate,
};
use xolotl_types::{
    ConstraintSet, DecisionTag, DriverId, ExecutionId, Expiry, Fact, Grant, HandleId, IdentityRef,
    InterfaceFamily, InvocationId, MethodBitmap, MethodContract, MethodId, NodeId, Operation,
    OperationId, Outcome, OutputMode, OutputModeSet, Path, ProcessId, Purity, ReplayClass,
    ResourceId, ResourceName, ResourceSelector, RightFlags, Rights, TaintSet, Timestamp, Value,
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
            .kernel()
            .registry()
            .resolve_resource(&name)
            .context("registered effect did not resolve")?;
        let process = boot.root();
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
            .kernel()
            .registry()
            .resolve_resource(&name)
            .context("registered effect did not resolve")?;
        let process = ProcessId::new(99_001);
        for i in 0..grants {
            let selector = ResourceSelector::parse(&format!("perform://effect/irrelevant/g{i}"))
                .with_context(|| format!("irrelevant grant selector {i} did not parse"))?;
            boot.kernel().registry().register_grant(Grant {
                id: boot.kernel().registry().next_grant_id(),
                holder: process,
                selector,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::name("invoke"),
                    RightFlags::empty(),
                ),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        boot.kernel().registry().register_grant(Grant {
            id: boot.kernel().registry().next_grant_id(),
            holder: process,
            selector: ResourceSelector::parse("perform://effect/bench/open-many-grants")
                .context("matching grant selector did not parse")?,
            rights: xolotl_types::GrantRights::new(
                xolotl_types::GrantMethods::name("invoke"),
                RightFlags::empty(),
            ),
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

    fn with_many_wildcard_grants(effect_path: &str, grants: usize) -> anyhow::Result<Self> {
        // A cold-open benchmark needs an explicit cache-disabled registry now
        // that simple plans can be reused across different wall-clock millis.
        let boot = Bootstrap::from_kernel(
            KernelBuilder::in_memory()
                .with_open_cache_capacity(0)
                .build(),
        );
        let name = register_echo_effect(&boot, effect_path, Purity::Pure)?;
        let resource = boot.kernel().registry().resolve_resource(&name)?;
        let process = ProcessId::new(99_002);
        for index in 0..grants {
            boot.kernel().registry().register_grant(Grant {
                id: boot.kernel().registry().next_grant_id(),
                holder: process,
                selector: ResourceSelector::parse("perform://effect/bench/**")?,
                rights: xolotl_types::GrantRights::new(
                    if index + 1 == grants {
                        xolotl_types::GrantMethods::name("invoke")
                    } else {
                        xolotl_types::GrantMethods::none()
                    },
                    RightFlags::empty(),
                ),
                constraints: ConstraintSet::empty(),
                expires: Expiry::Never,
            });
        }
        Ok(Self {
            boot,
            process,
            resource,
            path: name.path().clone(),
        })
    }

    fn open_at(&self, handles: &HandleTable, now_millis: i64) -> anyhow::Result<HandleId> {
        let handle = xolotl_kernel::open_resource(
            self.boot.kernel().registry(),
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
                xolotl_types::MethodAuthority::Perform,
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
        ..MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            Purity::Pure,
            MethodSpec::UNARY_ASYNC,
        )
    };
    let name = boot.register_effect(effect_path, &[method], Arc::new(EchoDriver))?;
    let handle = boot
        .open_for(boot.root(), &name, "perform")
        .context("root open failed")?;
    let op = operation(boot.root(), handle, 0, Value::integer(42));
    Ok((boot.kernel().data_plane(), op))
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
        .kernel()
        .registry()
        .resolve_resource(&name)
        .context("registered effect did not resolve")?;
    let child = boot
        .spawn_request_process_under_with_request_grants(boot.root(), IdentityRef::ROOT, &[])
        .context("child process did not spawn")?;
    let grant = Grant {
        id: boot.kernel().registry().next_grant_id(),
        holder: child,
        selector: ResourceSelector::parse(&format!(
            "perform://{}",
            effect_path.replacen("://", "/", 1)
        ))
        .context("conditional grant selector did not parse")?,
        rights: xolotl_types::GrantRights::new(
            xolotl_types::GrantMethods::name("invoke"),
            RightFlags::empty(),
        ),
        constraints: ConstraintSet {
            predicates: vec![
                xolotl_types::Predicate::parse("tenant=acme")
                    .context("conditional grant predicate did not parse")?,
            ],
        },
        expires: Expiry::Never,
    };
    boot.kernel().registry().register_grant(grant);

    let handle = xolotl_kernel::open_resource(
        boot.kernel().registry(),
        boot.kernel().handles(),
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

    let input = Value::map([("tenant".into(), tenant)].into());
    let op = operation(child, handle, 0, input);
    Ok((boot.kernel().data_plane(), op))
}

fn idempotent_dataplane_fixture() -> anyhow::Result<(DataPlane, Operation)> {
    let boot = Bootstrap::in_memory();
    let name = register_echo_effect(&boot, "effect://bench/idempotent", Purity::Idempotent)?;
    let handle = boot
        .open_for(boot.root(), &name, "perform")
        .context("root open failed")?;
    let op = operation(
        boot.root(),
        handle,
        0,
        Value::string("dedupe-keyed-input".into()),
    );
    Ok((boot.kernel().data_plane(), op))
}

fn collect_dataplane_fixture(chunks: usize) -> anyhow::Result<(DataPlane, Operation)> {
    let boot = Bootstrap::in_memory();
    let name = boot
        .register_effect(
            "effect://bench/collect",
            &[MethodSpec::new(
                "invoke",
                xolotl_types::MethodAuthority::Perform,
                Purity::Pure,
                MethodSpec::STREAM_ASYNC,
            )],
            Arc::new(ChunkDriver { chunks }),
        )
        .context("streaming effect registration failed")?;
    let handle = boot
        .open_for(boot.root(), &name, "perform")
        .context("root open failed")?;
    let mut op = operation(boot.root(), handle, 0, Value::null());
    op.output = OutputMode::Collect { limit: chunks };
    Ok((boot.kernel().data_plane(), op))
}

fn bench_handle(process: ProcessId, resource: ResourceId) -> Handle {
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(0),
        MethodContract::new(0, ReplayClass::Deterministic, OutputModeSet::UNARY),
        Arc::new(EchoDriver),
    );
    Handle {
        open_verb: "perform".into(),
        id: HandleId::new(0, 0),
        process,
        acting: IdentityRef::ROOT,
        resource,
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        bound_path: None,
    }
}

fn populated_handle_table(count: usize) -> anyhow::Result<(HandleTable, Vec<HandleId>)> {
    let table = HandleTable::new();
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
                let warm_handles = HandleTable::new();
                let handle =
                    capture_result(&failure, fixture.open_at(&warm_handles, FIXED_OPEN_MILLIS))?;
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

    group.bench_function("open_resource_cache_hit_fresh_time", |b| {
        b.iter_batched_ref(
            || {
                let fixture =
                    capture_result(&failure, OpenFixture::new("effect://bench/open-fresh-time"))?;
                let warm_handles = HandleTable::new();
                let handle =
                    capture_result(&failure, fixture.open_at(&warm_handles, FIXED_OPEN_MILLIS))?;
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

    let wildcard_fixture =
        OpenFixture::with_many_wildcard_grants("effect://bench/open-many-wildcards", 4_096)?;
    group.bench_function("candidate_snapshot_many_wildcards_4096", |b| {
        b.iter(|| {
            black_box(wildcard_fixture.boot.kernel().registry().candidate_grants(
                wildcard_fixture.process,
                "perform",
                &wildcard_fixture.path,
            ));
        });
    });
    group.bench_function("open_resource_cold_many_wildcards_4096", |b| {
        b.iter(|| {
            let handles = HandleTable::new();
            if let Some(handle) = capture_result(
                &failure,
                wildcard_fixture.open_at(&handles, FIXED_OPEN_MILLIS),
            ) {
                black_box(handle);
            }
        });
    });

    group.finish();
    failure.finish()
}

struct PrefixResolutionFixture {
    boot: Bootstrap,
    root: ResourceName,
    concrete: ResourceName,
}

impl PrefixResolutionFixture {
    fn new(unrelated: usize) -> anyhow::Result<Self> {
        let boot = Bootstrap::in_memory();
        let root = boot.register_subtree_resource_at(
            "state://bench/target",
            "read://state/bench/**",
            InterfaceFamily::Value,
            &[MethodSpec::new(
                "read",
                xolotl_types::MethodAuthority::Read,
                Purity::Pure,
                MethodSpec::UNARY_ASYNC,
            )],
            Arc::new(EchoDriver),
        )?;
        let registry = boot.kernel().registry();
        let expected = registry.resolve_resource(&root)?;
        let template = registry
            .resource(expected)
            .context("subtree root missing")?;
        for index in 0..unrelated {
            let mut sibling = template.clone();
            sibling.id = registry.next_resource_id();
            sibling.descriptor.name =
                ResourceName::new(Path::parse(&format!("state://bench/unrelated-{index}"))?);
            registry.admit_resource(sibling, false)?;
        }
        let concrete = ResourceName::new(Path::parse("state://bench/target/tenant/item")?);
        ensure!(registry.counts().names == unrelated + 1);
        ensure!(registry.resolve_resource(&concrete)? == expected);
        Ok(Self {
            boot,
            root,
            concrete,
        })
    }
}

fn bench_resource_resolution(c: &mut Criterion) -> anyhow::Result<()> {
    let mut group = c.benchmark_group("kernel/resource_resolution");
    for unrelated in [64, 4_096] {
        // Build once. The timed interval includes only a read-lock lookup; it
        // excludes registration, path parsing and any per-Executor cache.
        let fixture = PrefixResolutionFixture::new(unrelated)?;
        let registry = fixture.boot.kernel().registry();
        group.bench_function(BenchmarkId::new("dynamic_prefix", unrelated), |b| {
            b.iter(|| black_box(registry.resolve_resource(black_box(&fixture.concrete))));
        });
        group.bench_function(BenchmarkId::new("exact_control", unrelated), |b| {
            b.iter(|| black_box(registry.resolve_resource(black_box(&fixture.root))));
        });
    }
    group.finish();
    Ok(())
}

struct PrepareFixture {
    _boot: Bootstrap,
    executor: xolotl_kernel::Executor,
    template: OperationTemplate,
}

impl PrepareFixture {
    fn new() -> anyhow::Result<Self> {
        let boot = Bootstrap::in_memory();
        let target = register_echo_effect(&boot, "effect://bench/executor-prepare", Purity::Pure)?;
        let executor = boot.kernel().executor_for(boot.root());
        let template = OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: OutputMode::Unary,
            literal_input: None,
        };
        Ok(Self {
            _boot: boot,
            executor,
            template,
        })
    }

    fn prepare(&self) -> anyhow::Result<()> {
        self.executor
            .prepare_operation(black_box(&self.template))
            .map_err(anyhow::Error::from)
    }
}

fn bench_executor_prepare(c: &mut Criterion) -> anyhow::Result<()> {
    let failure = BenchFailure::default();
    let mut group = c.benchmark_group("kernel/executor_prepare");

    group.bench_function("cold_method_and_handle", |b| {
        b.iter_batched_ref(
            || capture_result(&failure, PrepareFixture::new()),
            |fixture| {
                if let Some(fixture) = fixture.as_ref() {
                    capture_result(&failure, fixture.prepare());
                }
            },
            BatchSize::SmallInput,
        );
    });

    let warm = PrepareFixture::new()?;
    warm.prepare().context("warm prepare did not succeed")?;
    group.bench_function("warm_method_and_handle", |b| {
        b.iter(|| {
            capture_result(&failure, warm.prepare());
        });
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
                let Some((table, ids)) = capture_result(&failure, fixture) else {
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

    // Process finalization calls these owner operations even when that process
    // has no handles. A long-lived table keeps its high-water slot array.
    for slots in [64usize, 4_096, 65_536] {
        let (table, _background) = populated_handle_table(slots)?;
        let absent = ProcessId::new(2);
        // This packed owner array is a favorable lower bound for the old
        // whole-Slot scan: real Slots have a much larger stride and the old
        // cleanup also held the table's write lock throughout the scan.
        let packed_owners = vec![ProcessId::new(1); slots];
        group.bench_function(BenchmarkId::new("linear_owner_scan_floor", slots), |b| {
            b.iter(|| {
                let owner = black_box(absent);
                black_box(
                    packed_owners
                        .iter()
                        .filter(|&&candidate| candidate == owner)
                        .count(),
                );
            });
        });
        group.bench_function(BenchmarkId::new("revoke_absent_owner", slots), |b| {
            b.iter_custom(|iterations| {
                let start = std::time::Instant::now();
                for _ in 0..iterations {
                    black_box(table.revoke_owned_by(black_box(absent)));
                }
                start.elapsed()
            });
        });

        let target = bench_handle(absent, ResourceId::new(slots as u64 + 1));
        group.bench_function(BenchmarkId::new("revoke_one_owner", slots), |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = std::time::Duration::ZERO;
                for _ in 0..iterations {
                    if capture_result(
                        &failure,
                        table
                            .insert(target.clone())
                            .context("owner handle insertion failed"),
                    )
                    .is_none()
                    {
                        break;
                    }
                    let start = std::time::Instant::now();
                    let revoked = black_box(table.revoke_owned_by(black_box(absent)));
                    elapsed += start.elapsed();
                    capture_condition(
                        &failure,
                        revoked == 1,
                        "single owner cleanup missed its handle",
                    );
                }
                elapsed
            });
        });
    }

    // A multi-handle owner exercises the release cursor and owner-index
    // removal. Reinstallation is outside the measured interval; the table
    // keeps the same high-water slot count across iterations.
    for owned in [8usize, 128] {
        let table = HandleTable::new();
        let owner = ProcessId::new(2);
        let target = bench_handle(owner, ResourceId::new(1));
        for _ in 0..owned {
            table.insert(target.clone())?;
        }
        group.bench_function(BenchmarkId::new("release_many_owner", owned), |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = std::time::Duration::ZERO;
                'iterations: for _ in 0..iterations {
                    let start = std::time::Instant::now();
                    let released = black_box(table.release_owned_by(black_box(owner)));
                    elapsed += start.elapsed();
                    if released != owned {
                        failure.record(anyhow!(
                            "multi-handle owner cleanup released {released} of {owned} handles"
                        ));
                        break;
                    }
                    for _ in 0..owned {
                        if let Err(error) = table.insert(target.clone()) {
                            failure.record(anyhow!(error));
                            break 'iterations;
                        }
                    }
                }
                elapsed
            });
        });
    }

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
                    caller_identity: None,
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                },
            ));
            if let Some(error) = out.completion_error {
                failure.record(anyhow!("data plane completion failed: {error}"));
                return;
            }
            black_box(out.output.outcome);
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
                    caller_identity: None,
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                },
            ));
            if let Some(error) = out.completion_error {
                failure.record(anyhow!("data plane completion failed: {error}"));
                return;
            }
            black_box(out.output.outcome);
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
                    caller_identity: None,
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                },
            ));
            if let Some(error) = out.completion_error {
                failure.record(anyhow!("data plane completion failed: {error}"));
                return;
            }
            black_box(out.output.outcome);
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
                    caller_identity: None,
                    now_millis: FIXED_OPEN_MILLIS,
                    record: true,
                },
            ));
            if let Some(error) = out.completion_error {
                failure.record(anyhow!("data plane completion failed: {error}"));
                return;
            }
            black_box(out.output.outcome);
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
                caller_identity: None,
                now_millis: FIXED_OPEN_MILLIS,
                record: false,
            },
        ));
        if first.completion_error.is_some() || !first.output.outcome.is_success() {
            failure.record(anyhow!("first idempotent run failed: {first:?}"));
            return;
        }
        b.iter(|| {
            let out = rt.block_on(plane.execute(
                black_box(&op),
                InvocationOptions {
                    caller_identity: None,
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                },
            ));
            if let Some(error) = out.completion_error {
                failure.record(anyhow!("data plane completion failed: {error}"));
                return;
            }
            black_box(out.output.outcome);
        });
    });

    for source_count in [1, 64] {
        group.bench_function(
            BenchmarkId::new("execute_idempotent_effect_sourced_hit", source_count),
            |bencher| {
                let Some((plane, mut operation)) =
                    capture_result(&failure, idempotent_dataplane_fixture())
                else {
                    return;
                };
                let sources = TaintSet::from_recorded_sources(
                    (0..source_count)
                        .map(|index| xolotl_types::TaintSource::Fetched {
                            host: format!("cache-source-{index}").into(),
                        })
                        .collect(),
                );
                operation.taint = sources.clone();
                let options = InvocationOptions {
                    caller_identity: None,
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                };
                let first = rt.block_on(plane.execute(&operation, options));
                if first.completion_error.is_some() || !first.output.outcome.is_success() {
                    failure.record(anyhow!("cache seeding failed: {first:?}"));
                    return;
                }
                operation.taint = TaintSet::pristine();
                bencher.iter(|| {
                    let result = rt.block_on(plane.execute(black_box(&operation), options));
                    capture_condition(
                        &failure,
                        result.completion_error.is_none()
                            && result.output.outcome.is_success()
                            && result.output.origin
                                == xolotl_types::CompletionOrigin::CachedOutcome
                            && result.output.taint == sources,
                        "cached hit lost observed sources",
                    );
                    drop(black_box(result));
                });
            },
        );
    }

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
                    caller_identity: None,
                    now_millis: FIXED_OPEN_MILLIS,
                    record: false,
                },
            ));
            if let Some(error) = out.completion_error {
                failure.record(anyhow!("data plane completion failed: {error}"));
                return;
            }
            black_box(out.output.outcome);
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
                        caller_identity: None,
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
        ensure!(
            out.completion_error.is_none(),
            "data plane completion failed: {:?}",
            out.completion_error
        );
        match out.output.outcome {
            Outcome::Done(value) => {
                black_box(value);
            }
            other => bail!("expected successful echo outcome, got {other:?}"),
        }
    }
    Ok(())
}

fn bench_fact_sink(c: &mut Criterion) -> anyhow::Result<()> {
    const FACTS_PER_BATCH: usize = 64;
    let mut group = c.benchmark_group("kernel/fact_sink");
    group.throughput(criterion::Throughput::Elements(FACTS_PER_BATCH as u64));
    let failure = BenchFailure::default();

    for subscribed in [false, true] {
        let name = if subscribed {
            "in_memory_begin_complete_subscribed_64"
        } else {
            "in_memory_begin_complete_unsubscribed_64"
        };
        group.bench_function(name, |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = std::time::Duration::ZERO;
                for _ in 0..iterations {
                    let (sink, store) = xolotl_kernel::FactSink::in_memory();
                    let _subscription = subscribed.then(|| store.subscribe_facts());
                    let process = ProcessId::new(1);
                    let facts: Vec<_> = (0..FACTS_PER_BATCH)
                        .map(|node| {
                            let completed = fact(process, node as u32, true);
                            let mut pending = completed.clone();
                            pending.outcome = None;
                            (pending, completed)
                        })
                        .collect();
                    let start = std::time::Instant::now();
                    let mut result = Ok(());
                    for (pending, completed) in facts {
                        result = sink.begin(pending).and_then(|()| sink.complete(completed));
                        if result.is_err() {
                            break;
                        }
                    }
                    elapsed += start.elapsed();
                    if let Err(error) = result.context("Fact begin/complete failed") {
                        failure.record(error);
                        break;
                    }
                    capture_condition(
                        &failure,
                        store.len() == FACTS_PER_BATCH,
                        "fact batch did not retain 64 records",
                    );
                }
                elapsed
            });
        });
    }

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

    let runtime = runtime()?;
    let mut group = c.benchmark_group("request_spawn");
    let failure = BenchFailure::default();
    for &k in &[1usize, 4, 16] {
        let grants: Vec<RequestGrantTemplate<'_>> = CAPS[..k]
            .iter()
            .map(|literal| RequestGrantTemplate {
                literal,
                rights: xolotl_types::GrantRights::new(
                    xolotl_types::GrantMethods::name(if literal.starts_with("perform://") {
                        "invoke"
                    } else if literal.starts_with("subscribe://") {
                        "subscribe"
                    } else if literal.starts_with("write://") {
                        "write"
                    } else {
                        "read"
                    }),
                    xolotl_types::RightFlags::empty(),
                ),
            })
            .collect();
        group.bench_function(format!("request_grants_{k}"), |b| {
            b.iter_batched(
                Bootstrap::in_memory,
                |boot| {
                    if let Some(child) = capture_result(
                        &failure,
                        boot.spawn_request_process_under_with_request_grants(
                            boot.root(),
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
    group.bench_function("sequential_retirement_capacity_2", |bencher| {
        let boot = Bootstrap::from_kernel(
            KernelBuilder::new(xolotl_state::InMemoryBackend::new().into_backend())
                .with_process_capacity(std::num::NonZeroUsize::MIN.saturating_add(1))
                .build(),
        );
        let completed = xolotl_types::ExecutionOutput::new(
            Outcome::Done(Value::integer(37)),
            TaintSet::pristine(),
        );
        let mut previous = None;
        bencher.iter(|| {
            let result = runtime.block_on(async {
                let request = boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
                if let Some(previous) = previous {
                    ensure!(boot.kernel().processes().status(previous).is_none());
                }
                previous = Some(request.id());
                let report = request.finish(black_box(&completed)).await?;
                ensure!(report.status == xolotl_types::ProcessStatus::Completed);
                ensure!(boot.kernel().processes().len() == 2);
                Ok(report)
            });
            if let Some(report) = capture_result(&failure, result) {
                drop(black_box(report));
            }
        });
    });
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
        let state = xolotl_state::InMemoryBackend::with_options(xolotl_state::InMemoryOptions {
            history: xolotl_state::MemoryHistory::Disabled,
            ..Default::default()
        })?
        .into_backend();
        let boot = Bootstrap::from_kernel(KernelBuilder::new(state).build());
        for _ in 0..live {
            boot.request_under(boot.root(), IdentityRef::ROOT, &[])?
                .detach();
        }
        group.bench_function(BenchmarkId::new("batch_64", live), |b| {
            b.iter_custom(|iterations| {
                let mut elapsed = std::time::Duration::ZERO;
                for _ in 0..iterations {
                    // The installed ports and namespace are fixed for all samples.
                    // Preparation and explicit retention cleanup are not timed.
                    let prepared: anyhow::Result<()> = runtime.block_on(async {
                        for _ in 0..BATCH {
                            let request =
                                boot.request_under(boot.root(), IdentityRef::ROOT, &[])?;
                            request
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
                    let reaped = black_box(boot.kernel().processes().reap_finalized(BATCH));
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
    let executor = boot.kernel().executor_for(boot.root());
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
    let executor = boot.kernel().executor_for(boot.root());
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
    let executor = boot.kernel().executor_for(boot.root());
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
    let lexical_boot = Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_execution_config(ExecutionConfig {
                bindings_per_task: 1,
                ..Default::default()
            })
            .build(),
    );
    let lexical_executor = lexical_boot.kernel().executor_for(lexical_boot.root());
    for count in [1, 64] {
        let local = |value| {
            DoNode::r#let(
                "local",
                DoNode::pure(Value::integer(value)),
                DoNode::use_("local"),
            )
        };
        let body = (1..count).fold(local(0), |body, value| body.finally(local(value)));
        let graph = compile_do(&body)?;
        let mut buffers = ExecutionBuffers::default();
        group.bench_function(
            BenchmarkId::new("lexical_finally_reused", count),
            |bencher| {
                bencher.iter(|| {
                    let output = runtime.block_on(
                        lexical_executor.eval_graph_with_buffers(black_box(&graph), &mut buffers),
                    );
                    capture_condition(
                        &failure,
                        output.outcome == Outcome::Done(Value::integer(0)),
                        "lexical binding output mismatch",
                    );
                    black_box(output);
                });
            },
        );
        if buffers.retained_bytes() != 0 {
            writeln!(
                std::io::stdout().lock(),
                "native lexical scopes {count}: 1 binding slot; {} B retained execution containers (excluding code and payloads)",
                buffers.retained_bytes()
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
        boot.root(),
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
    let executor = boot.kernel().executor_for(actor.process);
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
    bench_resource_resolution(&mut criterion).context("resource resolution benchmarks failed")?;
    bench_executor_prepare(&mut criterion).context("executor prepare benchmarks failed")?;
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
