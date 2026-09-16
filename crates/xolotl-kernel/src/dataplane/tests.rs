use super::*;
use crate::driver::{Driver, DriverContext, DriverPlan, EchoDriver, FnDriver};
use crate::fact::FactStore;
use crate::handle::{Handle, HandleState};
use anyhow::{Context, bail, ensure};
use xolotl_state::{
    Backend, InMemoryBackend, StateError, StateMutation, StateRead, StateResult, StateScan,
    StateWrite, TaintedValue,
};
use xolotl_types::{
    DriverId, Fact, HandleId, IdentityRef, MethodBitmap, MethodContract, MethodId, NodeId,
    OperationId, OutputMode, OutputModeSet, ProcessId, ReplayClass, ResourceId, RightFlags, Rights,
    Value,
};

const SUPPORTS_UNARY: OutputModeSet = OutputModeSet::UNARY;
const SUPPORTS_STREAM: OutputModeSet = OutputModeSet::STREAM;
const SUPPORTS_ASYNC: OutputModeSet = OutputModeSet::ASYNC_PROCESS;

mod completion;

fn test_state() -> Backend {
    InMemoryBackend::new().into_backend()
}

struct FailingWriteState;

impl StateRead for FailingWriteState {
    type Read<'a> = core::future::Ready<StateResult<Option<TaintedValue>>>;

    fn read_tainted<'a>(&'a self, _path: &'a Path) -> Self::Read<'a> {
        core::future::ready(Ok(None))
    }
}

impl StateWrite for FailingWriteState {
    type Write<'a> = core::future::Ready<StateResult<xolotl_state::StateCommit>>;

    fn mutate<'a>(&'a self, _path: &'a Path, _mutation: StateMutation) -> Self::Write<'a> {
        core::future::ready(Err(StateError::Backend(
            "simulated state write failure".into(),
        )
        .into()))
    }
}

struct PendingWriteState;

impl StateWrite for PendingWriteState {
    type Write<'a> = core::future::Pending<StateResult<xolotl_state::StateCommit>>;

    fn mutate<'a>(&'a self, _path: &'a Path, _mutation: StateMutation) -> Self::Write<'a> {
        core::future::pending()
    }
}

fn dataplane_with_handle(
    rights: Rights,
    fast_path: FastPath,
    contract: MethodContract,
) -> anyhow::Result<(DataPlane, HandleId)> {
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(MethodId::new(7), contract, Arc::new(EchoDriver));
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights,
        driver_plan: plan,
        fast_path,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, _) = FactSink::in_memory();
    Ok((
        DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state()),
        id,
    ))
}

struct TaintReportingStateDriver {
    state: Backend,
}

#[async_trait::async_trait]
impl Driver for TaintReportingStateDriver {
    async fn call(
        &self,
        method: MethodId,
        _input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<crate::DriverOutput, DriverError> {
        let path = ctx
            .target_path
            .clone()
            .ok_or_else(|| DriverError::Other("state test driver has no bound path".into()))?;
        match method.get() {
            0 => {
                let tv = self
                    .state
                    .read_tainted(&path)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                match tv {
                    Some(tv) => {
                        Ok(crate::DriverOutput::new(Outcome::Done(tv.value)).with_taint(tv.taint))
                    }
                    None => Ok(crate::DriverOutput::new(Outcome::Done(Value::null()))),
                }
            }
            4 => {
                let rows = self
                    .state
                    .query(&StateScan::new(path))
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                let mut taint = xolotl_types::TaintSet::pristine();
                let values = rows
                    .entries
                    .into_iter()
                    .map(|(p, tv)| {
                        taint.union(&tv.taint);
                        let mut m = BTreeMap::new();
                        m.insert("path".into(), Value::string(p.to_string()));
                        m.insert("value".into(), tv.value);
                        Value::map(m)
                    })
                    .collect();
                Ok(crate::DriverOutput::new(Outcome::Done(Value::list(values))).with_taint(taint))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn dataplane_with_state_handle(
    state: Backend,
    method: MethodId,
    bound_path: Path,
    replay: ReplayClass,
) -> anyhow::Result<(DataPlane, HandleId, Arc<crate::fact::InMemoryFactStore>)> {
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        method,
        MethodContract::new(u32::try_from(method.get())?, replay, SUPPORTS_UNARY),
        Arc::new(TaintReportingStateDriver {
            state: state.clone(),
        }),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::ALL, RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: Some(bound_path),
    })?;
    let (facts, store) = FactSink::in_memory();
    Ok((
        DataPlane::new(Arc::new(RwLock::new(table)), facts, state),
        id,
        store,
    ))
}

fn op(handle: HandleId, method: u64, input: Value) -> Operation {
    Operation {
        id: OperationId::new(
            ProcessId::new(1),
            xolotl_types::ExecutionId::FIRST,
            xolotl_types::InvocationId::new(1),
            NodeId::new(0),
            0,
        ),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        handle,
        method: MethodId::new(method),
        input,
        taint: xolotl_types::TaintSet::pristine(),
        output: OutputMode::Unary,
    }
}

#[tokio::test]
async fn unconditional_executes_and_records_ok() -> anyhow::Result<()> {
    let (dp, id) = dataplane_with_handle(
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        FastPath::Unconditional,
        MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY),
    )?;
    let out = dp
        .execute(
            &op(id, 7, Value::integer(9)),
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;
    ensure!(
        out.outcome == Outcome::Done(Value::integer(9)),
        "unexpected outcome: {:?}",
        out.outcome
    );
    Ok(())
}

#[tokio::test]
async fn state_read_output_taint_uses_persisted_taint() -> anyhow::Result<()> {
    let state = test_state();
    let path = Path::parse("state://chat/private")?;
    let protected =
        xolotl_types::TaintSet::of(xolotl_types::TaintSource::Protected { path: path.clone() });
    state
        .write_set_tainted(&path, Value::string("secret".into()), protected)
        .await
        .context("writing protected state failed")?;
    let (dp, id, store) =
        dataplane_with_state_handle(state, MethodId::new(0), path, ReplayClass::Observation)?;

    let out = dp
        .execute(
            &op(id, 0, Value::null()),
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;

    ensure!(
        out.taint.has_protected(),
        "output taint should be protected"
    );
    let facts = store.all_facts().context("reading facts failed")?;
    let fact = facts.first().context("missing recorded fact")?;
    ensure!(fact.taint.has_protected(), "fact taint should be protected");
    Ok(())
}

struct GuardedEcho(Arc<std::sync::atomic::AtomicUsize>);

#[async_trait::async_trait]
impl Driver for GuardedEcho {
    fn input_admission(&self, _method: MethodId) -> Option<crate::driver::InputAdmission> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(|input| {
            if input.as_str().is_some() {
                Err(Box::new(crate::driver::InputRejection {
                    failure: Failure::InvalidInput {
                        reason: "strings require a separate input edge".into(),
                    },
                    recorded_input: Value::string("redacted".into()),
                }))
            } else {
                Ok(())
            }
        })
    }

    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        EchoDriver.call(method, input, output, ctx).await
    }
}

#[tokio::test]
async fn provider_input_admission_is_frozen_and_records_only_its_safe_projection()
-> anyhow::Result<()> {
    let contract = MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY);
    let (dp, id) = dataplane_with_handle(
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        FastPath::Unconditional,
        contract,
    )?;
    let compilations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    dp.handles
        .write()
        .get_mut(id)
        .context("handle")?
        .driver_plan
        .insert(
            MethodId::new(7),
            contract,
            Arc::new(GuardedEcho(compilations.clone())),
        );
    let options = InvocationOptions {
        now_millis: 0,
        record: true,
    };
    let rejected = dp
        .execute(&op(id, 7, Value::string("private".into())), options)
        .await;
    ensure!(matches!(
        rejected.outcome,
        Outcome::Fail(Failure::InvalidInput { .. })
    ));
    let facts = dp.facts.all_facts()?;
    ensure!(facts.len() == 1);
    ensure!(facts[0].input == Value::string("redacted".into()));
    let accepted = dp.execute(&op(id, 7, Value::integer(23)), options).await;
    ensure!(accepted.outcome == Outcome::Done(Value::integer(23)));
    ensure!(compilations.load(std::sync::atomic::Ordering::SeqCst) == 1);
    Ok(())
}

#[tokio::test]
async fn state_list_output_taint_unions_persisted_taint() -> anyhow::Result<()> {
    let state = test_state();
    let prefix = Path::parse("state://chat")?;
    let public = Path::parse("state://chat/public")?;
    let private = Path::parse("state://chat/private")?;
    state
        .write_set(&public, Value::string("ok".into()))
        .await
        .context("writing public state failed")?;
    let protected = xolotl_types::TaintSet::of(xolotl_types::TaintSource::Protected {
        path: private.clone(),
    });
    state
        .write_set_tainted(&private, Value::string("secret".into()), protected)
        .await
        .context("writing protected state failed")?;
    let (dp, id, store) =
        dataplane_with_state_handle(state, MethodId::new(4), prefix, ReplayClass::Observation)?;

    let out = dp
        .execute(
            &op(id, 4, Value::null()),
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;

    ensure!(
        out.taint.has_protected(),
        "listed output taint should be protected"
    );
    let facts = store.all_facts().context("reading facts failed")?;
    let fact = facts.first().context("missing recorded fact")?;
    ensure!(fact.taint.has_protected(), "fact taint should be protected");
    Ok(())
}

#[tokio::test]
async fn media_descriptors_retain_types_and_metadata_in_driver_and_facts() -> anyhow::Result<()> {
    use xolotl_types::{BlobRef, DType, FrameKind};
    let blob = BlobRef {
        hash: "deadbeef".into(),
        size: 4096,
        mime: Some("application/x-checkpoint".into()),
    };
    for value in [
        Value::blob(blob.clone()),
        Value::tensor(blob.clone(), DType::Bf16, vec![2, u64::MAX]),
        Value::frame(blob, i64::MIN, FrameKind::Pose),
    ] {
        let (dp, id) = dataplane_with_handle(
            Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            FastPath::Unconditional,
            MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY),
        )?;
        let out = dp
            .execute(
                &op(id, 7, value.clone()),
                InvocationOptions {
                    now_millis: 0,
                    record: true,
                },
            )
            .await;
        ensure!(out.outcome == Outcome::Done(value.clone()));
        let facts = dp.facts.all_facts()?;
        let [fact] = facts.as_slice() else {
            anyhow::bail!("media invocation must record exactly one Fact");
        };
        ensure!(fact.input == value && fact.outcome.as_ref() == Some(&value));
        ensure!(fact.input.identity() == value.identity());
        ensure!(fact.outcome.as_ref().and_then(Value::identity) == value.identity());
    }
    Ok(())
}

#[tokio::test]
async fn batchable_list_records_single_fact_with_batch_summary() -> anyhow::Result<()> {
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    let mut contract = MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY);
    contract.batchable = true;
    plan.insert(MethodId::new(7), contract, Arc::new(EchoDriver));
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
    let input = Value::list(vec![Value::string("a".into()), Value::string("b".into())]);
    let out = dp
        .execute(
            &op(id, 7, input),
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;
    ensure!(
        matches!(&out.outcome, Outcome::Done(value) if value.as_list().is_some()),
        "batchable call should return a list, got {:?}",
        out.outcome
    );
    let facts = store
        .facts_of(ProcessId::new(1))
        .context("reading facts failed")?;
    ensure!(facts.len() == 1, "batchable call should record one Fact");
    let fact = facts.first().context("missing batchable fact")?;
    let batch = fact.batch.as_ref().context("missing batch summary")?;
    ensure!(batch.elements == 2, "batch element count mismatch");
    ensure!(
        fact.outcome.as_ref().and_then(Value::as_list).is_some(),
        "batch fact outcome should be inline list"
    );
    Ok(())
}

#[tokio::test]
async fn missing_right_is_denied() -> anyhow::Result<()> {
    let (dp, id) = dataplane_with_handle(
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        FastPath::Unconditional,
        MethodContract::new(3, ReplayClass::Deterministic, SUPPORTS_UNARY),
    )?;
    // method_index 3 is not in the bitmap.
    let out = dp
        .execute(
            &op(id, 7, Value::null()),
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;
    ensure!(
        matches!(out.outcome, Outcome::Fail(Failure::PermissionDenied { .. })),
        "missing right should deny, got {:?}",
        out.outcome
    );
    Ok(())
}

#[tokio::test]
async fn wrong_owner_is_denied() -> anyhow::Result<()> {
    let (dp, id) = dataplane_with_handle(
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        FastPath::Unconditional,
        MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY),
    )?;
    let mut o = op(id, 7, Value::string("private unadmitted input".into()));
    o.process = ProcessId::new(999);
    let out = dp
        .execute(
            &o,
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;
    ensure!(
        matches!(out.outcome, Outcome::Fail(_)),
        "wrong owner should fail"
    );
    let facts = dp.facts.all_facts()?;
    ensure!(facts.len() == 1);
    ensure!(facts[0].input.is_null());
    Ok(())
}

fn counted_dataplane(
    contract: MethodContract,
    methods: MethodBitmap,
) -> anyhow::Result<(DataPlane, HandleId, Arc<std::sync::atomic::AtomicUsize>)> {
    let (dp, handle) = dataplane_with_handle(
        Rights::new(methods, RightFlags::empty()),
        FastPath::Unconditional,
        contract,
    )?;
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    dp.handles
        .write()
        .get_mut(handle)
        .context("missing fixture handle")?
        .driver_plan
        .insert(
            MethodId::new(7),
            contract,
            Arc::new(FnDriver(move |_method, input| {
                observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(input)
            })),
        );
    Ok((dp, handle, calls))
}

#[tokio::test]
async fn identity_and_operation_namespace_are_bound_to_the_opened_handle() -> anyhow::Result<()> {
    for field in ["acting", "operation_id", "owner"] {
        let (dp, handle, calls) = counted_dataplane(
            MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY),
            MethodBitmap::method(0),
        )?;
        let mut operation = op(handle, 7, Value::null());
        match field {
            "acting" => operation.acting = IdentityRef::new(99),
            "operation_id" => operation.id.process = ProcessId::new(99),
            _ => {
                operation.process = ProcessId::new(99);
                operation.id.process = operation.process;
            }
        }
        let output = dp
            .execute(
                &operation,
                InvocationOptions {
                    now_millis: 0,
                    record: false,
                },
            )
            .await;
        ensure!(matches!(
            output.outcome,
            Outcome::Fail(Failure::PolicyViolation { .. })
        ));
        ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 0);
    }
    Ok(())
}

#[tokio::test]
async fn frozen_contract_controls_output_and_method_rights() -> anyhow::Result<()> {
    let contract = MethodContract::new(3, ReplayClass::Deterministic, SUPPORTS_UNARY);
    let (dp, handle, calls) = counted_dataplane(contract, MethodBitmap::method(3))?;
    let mut operation = op(handle, 7, Value::null());
    operation.output = OutputMode::Stream;
    let output = dp
        .execute(
            &operation,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(matches!(
        output.outcome,
        Outcome::Fail(Failure::InvalidInput { .. })
    ));
    ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 0);
    operation.output = OutputMode::Unary;
    operation.id.attempt = 1;
    let output = dp
        .execute(
            &operation,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(output.outcome == Outcome::Done(Value::null()));
    ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 1);

    let (dp, handle, calls) = counted_dataplane(contract, MethodBitmap::method(7))?;
    let output = dp
        .execute(
            &op(handle, 7, Value::null()),
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(matches!(
        output.outcome,
        Outcome::Fail(Failure::PermissionDenied { .. })
    ));
    ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 0);
    Ok(())
}

#[tokio::test]
async fn hosted_calls_require_a_live_running_process() -> anyhow::Result<()> {
    use crate::process::{ProcessEntry, ProcessTable};
    use xolotl_types::ProcessStatus;

    for status in [
        None,
        Some(ProcessStatus::Created),
        Some(ProcessStatus::Finalizing),
        Some(ProcessStatus::Completed),
        Some(ProcessStatus::Cancelled),
    ] {
        let (dp, handle, calls) = counted_dataplane(
            MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY),
            MethodBitmap::method(0),
        )?;
        let processes = ProcessTable::new();
        if let Some(status) = status {
            let mut entry = ProcessEntry::new(ProcessId::new(1), None, IdentityRef::ROOT);
            entry.scope.restore_lifecycle(
                status,
                (status == ProcessStatus::Finalizing).then_some(ProcessStatus::Completed),
            )?;
            processes.insert(entry);
        }
        let output = dp
            .with_processes(processes)
            .execute(
                &op(handle, 7, Value::null()),
                InvocationOptions {
                    now_millis: 0,
                    record: false,
                },
            )
            .await;
        ensure!(matches!(output.outcome, Outcome::Fail(Failure::Cancelled)));
        ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 0);
    }
    Ok(())
}

#[tokio::test]
async fn direct_calls_charge_the_frozen_batch_contract() -> anyhow::Result<()> {
    use crate::process::{ProcessEntry, ProcessTable};
    use xolotl_types::{BudgetSpec, CostModel};

    let contract = MethodContract {
        cost: CostModel {
            flat_micro_usd: 3,
            ..CostModel::FREE
        },
        batchable: true,
        ..MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY)
    };
    let (dp, handle, calls) = counted_dataplane(contract, MethodBitmap::method(0))?;
    let processes = ProcessTable::new();
    let process = ProcessId::new(1);
    let mut entry = ProcessEntry::new(process, None, IdentityRef::ROOT);
    ensure!(entry.scope.start());
    processes.insert(entry);
    let dp = dp.with_processes(processes.clone());
    ensure!(processes.set_budget_spec(
        process,
        BudgetSpec {
            daily_micro_usd: Some(5),
            ..BudgetSpec::default()
        }
    ));
    let mut operation = op(
        handle,
        7,
        Value::list(vec![Value::integer(1), Value::integer(2)]),
    );
    let output = dp
        .execute(
            &operation,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(
        matches!(output.outcome, Outcome::Fail(Failure::BudgetExhausted { ref dim }) if dim == "daily_micro_usd")
    );
    ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 0);
    ensure!(processes.set_budget_spec(
        process,
        BudgetSpec {
            daily_micro_usd: Some(6),
            ..BudgetSpec::default()
        }
    ));
    operation.id.attempt = 1;
    let output = dp
        .execute(
            &operation,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(output.outcome == Outcome::Done(operation.input));
    ensure!(calls.load(std::sync::atomic::Ordering::SeqCst) == 1);
    let budget = processes
        .budget_mut(process, |budget| budget.clone())
        .context("missing budget")?;
    ensure!(budget.spent_micro_usd == 6 && budget.inflight_ops == 0);
    Ok(())
}

#[tokio::test]
async fn driver_failure_records_driver_error() -> anyhow::Result<()> {
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::NonIdempotentEffect, SUPPORTS_UNARY),
        Arc::new(FnDriver(|_, _| Err(DriverError::Other("boom".into())))),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
    // record=false, but a NonIdempotentEffect is always recorded so
    // the write-ahead barrier still fires.
    let out = dp
        .execute(
            &op(id, 7, Value::null()),
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(
        matches!(out.outcome, Outcome::Fail(Failure::HandlerError { .. })),
        "driver failure should surface handler error, got {:?}",
        out.outcome
    );
    // NonIdempotentEffect ⇒ write-ahead barrier fired at begin.
    ensure!(store.sync_count() >= 1, "write-ahead barrier should sync");
    Ok(())
}

#[tokio::test]
async fn unconsumed_deterministic_read_skips_fact() -> anyhow::Result<()> {
    // With record=false and a Deterministic class, no Fact is written
    // because recovery can recompute the read. The store stays empty.
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY),
        Arc::new(EchoDriver),
    );
    let id2 = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let dp2 = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
    let out = dp2
        .execute(
            &op(id2, 7, Value::integer(1)),
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(
        out.outcome == Outcome::Done(Value::integer(1)),
        "deterministic read outcome mismatch: {:?}",
        out.outcome
    );
    ensure!(
        store.is_empty(),
        "unconsumed deterministic read should write no Fact"
    );
    Ok(())
}

#[tokio::test]
async fn unconsumed_idempotent_effect_still_records_fact() -> anyhow::Result<()> {
    // Effectful / IdempotentEffect operations are external side effects, so
    // recovery must know they happened even if later graph nodes do not
    // consume the result.
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::IdempotentEffect, SUPPORTS_UNARY),
        Arc::new(EchoDriver),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
    let out = dp
        .execute(
            &op(id, 7, Value::integer(1)),
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(
        out.outcome == Outcome::Done(Value::integer(1)),
        "idempotent effect outcome mismatch: {:?}",
        out.outcome
    );
    ensure!(store.len() == 1, "idempotent effect should write one Fact");
    Ok(())
}

#[tokio::test]
async fn idempotent_effect_dedupes_by_business_key() -> anyhow::Result<()> {
    // Two IdempotentEffect ops carrying the same `_idem_key` run the driver
    // only once; the second short-circuits to the cached outcome.
    use std::sync::atomic::{AtomicU32, Ordering};
    static CALLS: AtomicU32 = AtomicU32::new(0);
    CALLS.store(0, Ordering::SeqCst);

    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::IdempotentEffect, SUPPORTS_UNARY),
        Arc::new(FnDriver(|_m: MethodId, _in: Value| {
            CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(Value::integer(100))
        })),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let state = test_state();
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, state.clone());

    let mut m = std::collections::BTreeMap::new();
    m.insert("_idem_key".to_string(), Value::string("order-1".into()));
    let input = Value::map(m);
    let o = op(id, 7, input);
    let mut retry = o.clone();
    retry.id = retry.id.retry().context("retry exhausted")?;

    let first = dp
        .execute(
            &o,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    let second = dp
        .execute(
            &retry,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;

    ensure!(
        first.outcome == Outcome::Done(Value::integer(100)),
        "first idempotent outcome mismatch: {:?}",
        first.outcome
    );
    ensure!(
        second.outcome == Outcome::Done(Value::integer(100)),
        "second idempotent outcome mismatch: {:?}",
        second.outcome
    );
    ensure!(CALLS.load(Ordering::SeqCst) == 1, "driver should run once");
    let facts = store
        .facts_of(ProcessId::new(1))
        .context("reading facts failed")?;
    ensure!(facts.len() == 2, "retry attempts should remain auditable");
    let first_fact = facts.first().context("missing first retry fact")?;
    let second_fact = facts.get(1).context("missing second retry fact")?;
    ensure!(first_fact.id.attempt == 0, "first attempt mismatch");
    ensure!(second_fact.id.attempt == 1, "second attempt mismatch");
    ensure!(
        facts.iter().all(|f| f.decision == DecisionTag::Ok),
        "all retry facts should be ok decisions"
    );
    Ok(())
}

#[tokio::test]
async fn idempotent_replay_preserves_original_input_and_output_provenance() -> anyhow::Result<()> {
    let state = test_state();
    let path = Path::parse("state://private/replay")?;
    let protected = TaintSet::of(xolotl_types::TaintSource::Protected { path: path.clone() });
    state
        .write_set_tainted(&path, Value::string("original".into()), protected.clone())
        .await?;
    let (dp, handle, store) = dataplane_with_state_handle(
        state.clone(),
        MethodId::new(0),
        path.clone(),
        ReplayClass::IdempotentEffect,
    )?;
    let mut original = op(
        handle,
        0,
        Value::map(BTreeMap::from([(
            "_idem_key".into(),
            Value::string("tainted-replay".into()),
        )])),
    );
    original.taint = TaintSet::of(xolotl_types::TaintSource::ModelOutput);
    let first = dp
        .execute(
            &original,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(first.outcome == Outcome::Done(Value::string("original".into())));
    let mut expected_taint = protected.merged(&original.taint);
    ensure!(first.taint == expected_taint);
    state
        .write_set(&path, Value::string("changed".into()))
        .await?;

    let mut retry = original.clone();
    retry.id = retry.id.retry().context("retry identity exhausted")?;
    retry.taint = TaintSet::of(xolotl_types::TaintSource::Inbound {
        source: "retry-client".into(),
        channel: "test".into(),
    });
    let replay = dp
        .execute(
            &retry,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(replay.outcome == Outcome::Done(Value::string("original".into())));
    expected_taint.union(&retry.taint);
    ensure!(replay.taint == expected_taint);
    let facts = store.facts_of(retry.process)?;
    let fact = facts
        .iter()
        .find(|fact| fact.id == retry.id)
        .context("missing replay fact")?;
    ensure!(fact.taint.sources().len() == expected_taint.sources().len());
    ensure!(
        expected_taint
            .sources()
            .iter()
            .all(|source| fact.taint.sources().contains(source))
    );
    Ok(())
}

#[tokio::test]
async fn idempotent_effect_preserves_known_result_when_cache_write_fails() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static CALLS: AtomicU32 = AtomicU32::new(0);
    CALLS.store(0, Ordering::SeqCst);

    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::IdempotentEffect, SUPPORTS_UNARY),
        Arc::new(FnDriver(|_m: MethodId, _in: Value| {
            CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(Value::integer(100))
        })),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let dp = DataPlane::new(
        Arc::new(RwLock::new(table)),
        facts,
        Backend::new()
            .with_read(Arc::new(FailingWriteState))
            .with_write(Arc::new(FailingWriteState)),
    );

    let mut m = std::collections::BTreeMap::new();
    m.insert("_idem_key".to_string(), Value::string("order-1".into()));
    let out = dp
        .execute(
            &op(id, 7, Value::map(m)),
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;

    ensure!(CALLS.load(Ordering::SeqCst) == 1, "driver should run once");
    ensure!(out.outcome == Outcome::Done(Value::integer(100)));
    ensure!(
        out.taint == TaintSet::pristine(),
        "cache failure must not change effect provenance"
    );

    let facts = store
        .facts_of(ProcessId::new(1))
        .context("reading facts failed")?;
    let fact = facts.first().context("missing idempotency failure fact")?;
    ensure!(facts.len() == 1, "unexpected fact count: {}", facts.len());
    ensure!(
        fact.decision == DecisionTag::Ok,
        "unexpected fact decision: {:?}",
        fact.decision
    );
    ensure!(
        fact.outcome == Some(Value::integer(100)),
        "cache failure must not replace a known effect result"
    );
    Ok(())
}

#[tokio::test]
async fn completed_effect_settles_and_records_before_a_pending_cache_write() -> anyhow::Result<()> {
    use core::{future::Future, task::Poll};
    let contract = MethodContract {
        cost: xolotl_types::CostModel {
            per_1k_out_micro_usd: 1000,
            ..xolotl_types::CostModel::FREE
        },
        ..MethodContract::new(0, ReplayClass::IdempotentEffect, SUPPORTS_UNARY)
    };
    let (mut dp, handle) = dataplane_with_handle(
        Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        FastPath::Unconditional,
        contract,
    )?;
    dp.state = Backend::new()
        .with_read(Arc::new(FailingWriteState))
        .with_write(Arc::new(PendingWriteState));
    let processes = crate::process::ProcessTable::new();
    let mut entry = crate::process::ProcessEntry::new(ProcessId::new(1), None, IdentityRef::ROOT);
    ensure!(entry.scope.start());
    processes.insert(entry);
    let dp = dp.with_processes(processes.clone());
    let operation = op(handle, 7, Value::string("response-body".into()));
    {
        let mut run = core::pin::pin!(dp.execute(
            &operation,
            InvocationOptions {
                now_millis: 0,
                record: true
            }
        ));
        ensure!(
            core::future::poll_fn(|cx| Poll::Ready(run.as_mut().poll(cx)))
                .await
                .is_pending()
        );
        let budget = processes
            .budget_mut(operation.process, |budget| budget.clone())
            .context("budget")?;
        ensure!(
            budget.inflight_ops == 0 && budget.inference_tokens == 3 && budget.spent_micro_usd == 3
        );
        let facts = dp.facts.all_facts()?;
        ensure!(facts.len() == 1 && facts[0].outcome == Some(operation.input.clone()));
    }
    let budget = processes
        .budget_mut(operation.process, |budget| budget.clone())
        .context("budget")?;
    ensure!(
        budget.inflight_ops == 0 && budget.inference_tokens == 3 && budget.spent_micro_usd == 3
    );
    Ok(())
}

#[tokio::test]
async fn idempotent_effect_dedupes_across_data_plane_instances() -> anyhow::Result<()> {
    // Idempotency records live in state://idemp/*, so a restarted DataPlane
    // sharing the backend still dedupes the same effective key.
    use std::sync::atomic::{AtomicU32, Ordering};
    static CALLS: AtomicU32 = AtomicU32::new(0);
    CALLS.store(0, Ordering::SeqCst);

    let mk_table = || -> anyhow::Result<_> {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(
            MethodId::new(7),
            MethodContract::new(0, ReplayClass::IdempotentEffect, SUPPORTS_UNARY),
            Arc::new(FnDriver(|_m: MethodId, _in: Value| {
                CALLS.fetch_add(1, Ordering::SeqCst);
                Ok(Value::integer(100))
            })),
        );
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            acting: IdentityRef::ROOT,
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        })?;
        Ok((table, id))
    };

    let state = test_state();
    let (table1, id1) = mk_table()?;
    let (facts1, _) = FactSink::in_memory();
    let dp1 = DataPlane::new(Arc::new(RwLock::new(table1)), facts1, state.clone());
    let (table2, id2) = mk_table()?;
    let (facts2, _) = FactSink::in_memory();
    let dp2 = DataPlane::new(Arc::new(RwLock::new(table2)), facts2, state.clone());

    let mut m = std::collections::BTreeMap::new();
    m.insert("_idem_key".to_string(), Value::string("order-1".into()));
    let first = dp1
        .execute(
            &op(id1, 7, Value::map(m.clone())),
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;
    let second = dp2
        .execute(
            &op(id2, 7, Value::map(m)),
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;

    ensure!(
        first.outcome == Outcome::Done(Value::integer(100)),
        "first dataplane outcome mismatch: {:?}",
        first.outcome
    );
    ensure!(
        second.outcome == Outcome::Done(Value::integer(100)),
        "second dataplane outcome mismatch: {:?}",
        second.outcome
    );
    ensure!(CALLS.load(Ordering::SeqCst) == 1, "driver should run once");
    let prefix = Path::parse("state://idemp")?;
    let entries = state
        .query(&StateScan::new(prefix))
        .await
        .context("reading idempotency prefix failed")?;
    ensure!(
        !entries.entries.is_empty(),
        "idempotency state should be populated"
    );
    Ok(())
}

/// A FactStore whose writes always fail, exercising the fail-closed
/// write-ahead path without needing a real disk fault.
#[derive(Default)]
struct FailingFactStore(crate::InMemoryExecutionIdSource);

impl crate::ExecutionIdSource for FailingFactStore {
    fn reserve(
        &self,
        count: std::num::NonZeroU64,
    ) -> Result<crate::ExecutionIdRange, crate::ExecutionIdError> {
        self.0.reserve(count)
    }
}
impl crate::fact::FactStore for FailingFactStore {
    fn scan(&self, query: crate::FactQuery) -> Result<crate::FactPage, crate::FactError> {
        crate::InMemoryFactStore::new().scan(query)
    }
    fn lookup(
        &self,
        _query: crate::FactLookup,
    ) -> Result<crate::FactLookupResult, crate::FactError> {
        Ok(crate::FactLookupResult::Missing)
    }
    fn append(&self, _fact: Fact) -> Result<u64, crate::fact::FactError> {
        Err(crate::fact::FactError("simulated disk failure".into()))
    }
    fn complete(&self, _fact: Fact) -> Result<(), crate::fact::FactError> {
        Err(crate::fact::FactError("simulated disk failure".into()))
    }
    fn sync(&self) -> Result<(), crate::fact::FactError> {
        Err(crate::fact::FactError("simulated disk failure".into()))
    }
    fn facts_of(&self, _process: ProcessId) -> Result<Vec<Fact>, crate::fact::FactError> {
        Ok(Vec::new())
    }
    fn all_facts(&self) -> Result<Vec<Fact>, crate::fact::FactError> {
        Ok(Vec::new())
    }
    fn cursor(&self) -> u64 {
        0
    }
}

#[tokio::test]
async fn idempotent_dedup_denies_when_retry_fact_record_fails() -> anyhow::Result<()> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static CALLS: AtomicU32 = AtomicU32::new(0);
    CALLS.store(0, Ordering::SeqCst);

    let mk_table = || -> anyhow::Result<_> {
        let mut table = HandleTable::new();
        let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
        plan.insert(
            MethodId::new(7),
            MethodContract::new(0, ReplayClass::IdempotentEffect, SUPPORTS_UNARY),
            Arc::new(FnDriver(|_m: MethodId, _in: Value| {
                CALLS.fetch_add(1, Ordering::SeqCst);
                Ok(Value::integer(100))
            })),
        );
        let id = table.insert(Handle {
            id: HandleId::new(0, 0),
            process: ProcessId::new(1),
            acting: IdentityRef::ROOT,
            resource: ResourceId::new(5),
            rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
            driver_plan: plan,
            fast_path: FastPath::Unconditional,
            state: HandleState::Active,
            bound_path: None,
        })?;
        Ok((table, id))
    };

    let state = test_state();
    let (table, id) = mk_table()?;
    let (facts, _) = FactSink::in_memory();
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, state.clone());

    let mut m = std::collections::BTreeMap::new();
    m.insert("_idem_key".to_string(), Value::string("order-1".into()));
    let input = Value::map(m);
    let first = dp
        .execute(
            &op(id, 7, input.clone()),
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    ensure!(
        first.outcome == Outcome::Done(Value::integer(100)),
        "first idempotent outcome mismatch: {:?}",
        first.outcome
    );

    let (table, id) = mk_table()?;
    let failing_facts = FactSink::new(Arc::new(FailingFactStore::default()));
    let failing_dp = DataPlane::new(Arc::new(RwLock::new(table)), failing_facts, state);
    let mut retry = op(id, 7, input);
    retry.id = retry.id.retry().context("retry exhausted")?;
    let second = failing_dp
        .execute(
            &retry,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;

    ensure!(
        CALLS.load(Ordering::SeqCst) == 1,
        "cached retry should not call driver again"
    );
    ensure!(
        matches!(
            &second.outcome,
            Outcome::Fail(Failure::PolicyViolation { policy, detail })
                if policy == "durability" && detail.contains("dedup fact record failed")
        ),
        "dedup fact failure should deny the retry, got {:?}",
        second.outcome
    );
    Ok(())
}

#[tokio::test]
async fn write_ahead_failure_denies_effect_fail_closed() -> anyhow::Result<()> {
    // A NonIdempotentEffect must write ahead before the effect is issued.
    // If that durable append fails, the op is denied and the driver is
    // never called; no effect can happen without a record.
    use std::sync::atomic::{AtomicBool, Ordering};
    static CALLED: AtomicBool = AtomicBool::new(false);
    CALLED.store(false, Ordering::SeqCst);

    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::NonIdempotentEffect, SUPPORTS_UNARY),
        Arc::new(FnDriver(|_m: MethodId, _in: Value| {
            CALLED.store(true, Ordering::SeqCst);
            Ok(Value::integer(1))
        })),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let facts = FactSink::new(Arc::new(FailingFactStore::default()));
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());

    let out = dp
        .execute(
            &op(id, 7, Value::integer(9)),
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;

    ensure!(matches!(out.outcome, Outcome::Fail(_)), "op must be denied");
    ensure!(
        !CALLED.load(Ordering::SeqCst),
        "driver must not run when the write-ahead barrier fails"
    );
    Ok(())
}

struct StreamingDriver;

#[async_trait::async_trait]
impl Driver for StreamingDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<crate::DriverOutput, DriverError> {
        if output != OutputMode::Stream {
            return Err(DriverError::Other("expected stream output".into()));
        }
        ctx.emit(Value::string("chunk-1".into())).await?;
        ctx.emit(Value::string("chunk-2".into())).await?;
        Ok(crate::DriverOutput::new(Outcome::Done(Value::integer(2))))
    }
}

struct OneChunkStreamingDriver;

#[async_trait::async_trait]
impl Driver for OneChunkStreamingDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<crate::DriverOutput, DriverError> {
        if output != OutputMode::Stream {
            return Err(DriverError::Other("expected stream output".into()));
        }
        ctx.emit(Value::string("chunk".into())).await?;
        Ok(crate::DriverOutput::new(Outcome::Done(Value::integer(1))))
    }
}

#[tokio::test]
async fn stream_chunks_reach_explicit_sink_with_one_fact_and_no_state_retention()
-> anyhow::Result<()> {
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_STREAM),
        Arc::new(StreamingDriver),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let state = test_state();
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, state.clone());

    let mut o = op(id, 7, Value::null());
    o.output = OutputMode::Stream;
    let (sink, mut receiver) = crate::host::stream::channel(crate::stream::StreamWindow::default());
    let out = dp
        .execute_with_stream(
            &o,
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
            sink,
        )
        .await;
    ensure!(
        out.outcome == Outcome::Done(Value::integer(2)),
        "streaming outcome mismatch: {:?}",
        out.outcome
    );

    for expected in ["chunk-1", "chunk-2"] {
        let Some(crate::host::stream::StreamItem::Chunk(chunk)) = receiver.recv().await else {
            bail!("missing stream chunk");
        };
        ensure!(chunk.value == Value::string(expected.into()));
    }
    ensure!(matches!(
        receiver.recv().await,
        Some(crate::host::stream::StreamItem::End(
            crate::stream::StreamEnd {
                outcome: Ok(()),
                ..
            }
        ))
    ));
    ensure!(state.read(&stream_path(&o)?).await?.is_none());
    ensure!(
        store.len() == 1,
        "one completed invocation should record one Fact"
    );
    Ok(())
}

#[tokio::test]
async fn closed_stream_receiver_returns_driver_error() -> anyhow::Result<()> {
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_STREAM),
        Arc::new(OneChunkStreamingDriver),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, _) = FactSink::in_memory();
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());

    let mut o = op(id, 7, Value::null());
    o.output = OutputMode::Stream;
    let (sink, receiver) = crate::host::stream::channel(crate::stream::StreamWindow::default());
    drop(receiver);
    let out = dp
        .execute_with_stream(
            &o,
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
            sink,
        )
        .await;

    match out.outcome {
        Outcome::Fail(xolotl_types::Failure::HandlerError { message, .. }) => {
            ensure!(
                message.contains("closed"),
                "unexpected handler error message: {message}"
            );
        }
        other => bail!("expected stream sink failure, got {other:?}"),
    }
    Ok(())
}

struct CollectDriver;

#[async_trait::async_trait]
impl Driver for CollectDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<crate::DriverOutput, DriverError> {
        if output != OutputMode::Stream {
            return Err(DriverError::Other("expected stream output".into()));
        }
        ctx.emit(Value::string("a".into())).await?;
        ctx.emit(Value::string("b".into())).await?;
        Ok(crate::DriverOutput::new(Outcome::Done(Value::integer(2))))
    }
}

#[tokio::test]
async fn collect_aggregates_stream_chunks_up_to_limit() -> anyhow::Result<()> {
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_STREAM),
        Arc::new(CollectDriver),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
    let mut o = op(id, 7, Value::null());
    o.output = OutputMode::Collect { limit: 1 };

    let out = dp
        .execute(
            &o,
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;
    ensure!(
        out.outcome == Outcome::Short(Value::list(vec![Value::string("a".into())])),
        "collect outcome mismatch: {:?}",
        out.outcome
    );
    ensure!(store.len() == 1, "collect should record one Fact");
    Ok(())
}

#[tokio::test]
async fn collect_wraps_unary_result_when_no_chunks_are_emitted() -> anyhow::Result<()> {
    struct UnaryOnlyCollectDriver;

    #[async_trait::async_trait]
    impl Driver for UnaryOnlyCollectDriver {
        async fn call(
            &self,
            _method: MethodId,
            input: Value,
            output: OutputMode,
            ctx: &DriverContext,
        ) -> Result<crate::DriverOutput, DriverError> {
            if output != OutputMode::Unary {
                return Err(DriverError::Other("expected unary output".into()));
            }
            if ctx.stream_to.is_some() {
                return Err(DriverError::Other("unexpected stream sink".into()));
            }
            Ok(crate::DriverOutput::new(Outcome::Done(input)))
        }
    }

    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY),
        Arc::new(UnaryOnlyCollectDriver),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, _) = FactSink::in_memory();
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state());
    let mut o = op(id, 7, Value::integer(9));
    o.output = OutputMode::Collect { limit: 8 };
    let out = dp
        .execute(
            &o,
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;
    ensure!(
        out.outcome == Outcome::Done(Value::list(vec![Value::integer(9)])),
        "collect unary wrap outcome mismatch: {:?}",
        out.outcome
    );
    Ok(())
}

#[tokio::test]
async fn sink_only_suppresses_response_body_without_erasing_usage() -> anyhow::Result<()> {
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract {
            cost: xolotl_types::CostModel {
                per_1k_out_micro_usd: 1000,
                ..xolotl_types::CostModel::FREE
            },
            ..MethodContract::new(
                0,
                ReplayClass::NonIdempotentEffect,
                OutputModeSet::SINK_ONLY,
            )
        },
        Arc::new(EchoDriver),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let processes = crate::process::ProcessTable::new();
    let mut process = crate::process::ProcessEntry::new(ProcessId::new(1), None, IdentityRef::ROOT);
    ensure!(process.scope.start());
    processes.insert(process);
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, test_state())
        .with_processes(processes.clone());
    let mut o = op(id, 7, Value::string("response-body".into()));
    o.output = OutputMode::SinkOnly;
    let out = dp
        .execute(
            &o,
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;
    ensure!(
        out.outcome == Outcome::Done(Value::null()),
        "sink-only outcome mismatch: {:?}",
        out.outcome
    );
    let facts = store
        .facts_of(ProcessId::new(1))
        .context("reading facts failed")?;
    ensure!(facts.len() == 1, "sink-only should record one Fact");
    let fact = facts.first().context("missing sink-only fact")?;
    ensure!(
        fact.outcome.as_ref().is_some_and(Value::is_null),
        "sink-only fact should record Null"
    );
    let budget = processes
        .budget_mut(ProcessId::new(1), |budget| budget.clone())
        .context("budget")?;
    ensure!(
        budget.spent_micro_usd == 3 && budget.inference_tokens == 3 && budget.inflight_ops == 0
    );
    Ok(())
}

struct AsyncDriver;

#[async_trait::async_trait]
impl Driver for AsyncDriver {
    async fn call(
        &self,
        _method: MethodId,
        input: Value,
        output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<crate::DriverOutput, DriverError> {
        if output != OutputMode::AsyncProcess {
            return Err(DriverError::Other("expected async process output".into()));
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        Ok(crate::DriverOutput::new(Outcome::Done(input)))
    }
}

type AsyncFixture = (
    DataPlane,
    HandleId,
    xolotl_state::Backend,
    Arc<crate::fact::InMemoryFactStore>,
    crate::process::ProcessTable,
);

fn async_dataplane(rights: Rights) -> anyhow::Result<AsyncFixture> {
    let mut table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_ASYNC),
        Arc::new(AsyncDriver),
    );
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        resource: ResourceId::new(5),
        rights,
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        state: HandleState::Active,
        bound_path: None,
    })?;
    let (facts, store) = FactSink::in_memory();
    let state = xolotl_state::InMemoryBackend::new().into_backend();
    let processes = crate::process::ProcessTable::new();
    let parent = processes.initialize_root(|_| {});
    ensure!(
        parent == ProcessId::new(1),
        "unexpected parent process id: {parent:?}"
    );
    let dp = DataPlane::new(Arc::new(RwLock::new(table)), facts, state.clone())
        .with_processes(processes.clone());
    Ok((dp, id, state, store, processes))
}

#[tokio::test]
async fn async_process_requires_spawn_with_right() -> anyhow::Result<()> {
    let (dp, id, _state, _store, _processes) =
        async_dataplane(Rights::new(MethodBitmap::method(0), RightFlags::empty()))?;
    let mut o = op(id, 7, Value::string("work".into()));
    o.output = OutputMode::AsyncProcess;

    let out = dp
        .execute(
            &o,
            InvocationOptions {
                now_millis: 0,
                record: true,
            },
        )
        .await;
    ensure!(
        matches!(out.outcome, Outcome::Fail(Failure::PermissionDenied { .. })),
        "async process without spawn right should deny, got {:?}",
        out.outcome
    );
    Ok(())
}

#[tokio::test]
async fn async_process_returns_pollable_resource_and_records_child_fact() -> anyhow::Result<()> {
    let (dp, id, state, store, processes) =
        async_dataplane(Rights::new(MethodBitmap::method(0), RightFlags::SPAWN_WITH))?;
    let mut o = op(id, 7, Value::string("work".into()));
    o.output = OutputMode::AsyncProcess;

    let out = dp
        .execute(
            &o,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    let (child, status_path, outcome_path) = match out.outcome {
        Outcome::Done(value) => {
            let m = value.as_map().context("expected async resource map")?;
            ensure!(
                m.get("kind") == Some(&Value::string("executor_resource".into())),
                "async resource kind mismatch: {m:?}"
            );
            ensure!(
                m.get("path") == Some(&Value::string("proc://async/2/1".into())),
                "async resource path mismatch: {m:?}"
            );
            let child = ProcessId::new(u64::try_from(
                m.get("process")
                    .and_then(Value::as_int)
                    .context("expected child process id")?,
            )?);
            let status_path = Path::parse(
                m.get("status_path")
                    .and_then(Value::as_str)
                    .context("expected status path")?,
            )?;
            let outcome_path = Path::parse(
                m.get("outcome_path")
                    .and_then(Value::as_str)
                    .context("expected outcome path")?,
            )?;
            (child, status_path, outcome_path)
        }
        other => bail!("expected async resource map, got {other:?}"),
    };
    ensure!(child == ProcessId::new(2), "child process id mismatch");
    ensure!(processes.exists(child), "child process should exist");

    let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Some(v) = state.read(&outcome_path).await? {
                break Ok::<Value, anyhow::Error>(v);
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .context("async child did not write outcome before timeout")??;
    let mut expected = BTreeMap::new();
    expected.insert("status".into(), Value::string("done".into()));
    expected.insert("value".into(), Value::string("work".into()));
    ensure!(
        outcome == Value::map(expected),
        "async child outcome mismatch: {outcome:?}"
    );
    ensure!(
        processes.status(child) == Some(xolotl_types::ProcessStatus::Completed),
        "async child should be completed"
    );
    let status = state
        .read(&status_path)
        .await
        .context("reading child status failed")?
        .context("missing child status")?;
    let m = status.as_map().context("expected status map")?;
    ensure!(
        m.get("phase") == Some(&Value::string("completed".into())),
        "child status phase mismatch: {m:?}"
    );
    ensure!(
        store.len() == 3,
        "parent spawn, child execution and child finalization should each record one Fact"
    );
    Ok(())
}

#[tokio::test]
async fn async_process_completion_does_not_overwrite_cancellation() -> anyhow::Result<()> {
    let (dp, id, state, _store, processes) =
        async_dataplane(Rights::new(MethodBitmap::method(0), RightFlags::SPAWN_WITH))?;
    let mut o = op(id, 7, Value::string("work".into()));
    o.output = OutputMode::AsyncProcess;

    let out = dp
        .execute(
            &o,
            InvocationOptions {
                now_millis: 0,
                record: false,
            },
        )
        .await;
    let (child, status_path) = match out.outcome {
        Outcome::Done(value) => {
            let m = value.as_map().context("expected async resource map")?;
            let child = ProcessId::new(u64::try_from(
                m.get("process")
                    .and_then(Value::as_int)
                    .context("expected child process id")?,
            )?);
            let status_path = Path::parse(
                m.get("status_path")
                    .and_then(Value::as_str)
                    .context("expected status path")?,
            )?;
            (child, status_path)
        }
        other => bail!("expected async resource map, got {other:?}"),
    };
    ensure!(
        processes.cancel_if_non_terminal(child) == Some(true),
        "child process should accept cancellation"
    );

    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Some(xolotl_types::ProcessStatus::Completed) = processes.status(child) {
                bail!("async child completion overwrote cancellation");
            }
            if let Some(value) = state.read(&status_path).await?
                && value
                    .as_map()
                    .and_then(|map| map.get("phase"))
                    .and_then(Value::as_str)
                    == Some("cancelled")
            {
                break Ok::<(), anyhow::Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .context("async child did not publish cancelled status before timeout")??;
    ensure!(
        processes.status(child) == Some(xolotl_types::ProcessStatus::Cancelled),
        "child process status was not cancelled"
    );
    Ok(())
}
