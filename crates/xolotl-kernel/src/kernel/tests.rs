use super::*;
use crate::{
    Bootstrap, BootstrapError, ExecutionIdSource, FactError, FactLookup, FactLookupResult,
    FactPage, FactQuery, FactStore, IdentityError, InMemoryExecutionIdSource, InMemoryFactStore,
};
use anyhow::ensure;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::atomic::{AtomicUsize, Ordering};
use xolotl_types::{ExecutionId, Fact, IdentityRef, Path};

struct BusinessStateDriver {
    state: Backend,
    path: Path,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl crate::Driver for BusinessStateDriver {
    async fn call(
        &self,
        _method: xolotl_types::MethodId,
        input: xolotl_types::Value,
        _output: xolotl_types::OutputMode,
        _context: &crate::DriverContext,
    ) -> Result<crate::DriverOutput, crate::DriverError> {
        self.state
            .write_set(&self.path, input.clone())
            .await
            .map_err(|error| crate::DriverError::Other(error.to_string()))?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(crate::DriverOutput::new(xolotl_types::Outcome::Done(input)))
    }
}

fn business_operation(
    boot: &Bootstrap,
) -> anyhow::Result<(xolotl_graph::OperationTemplate, Path, Arc<AtomicUsize>)> {
    let path = Path::parse("state://business/observation-test")?;
    let calls = Arc::new(AtomicUsize::new(0));
    let target = boot.register_effect(
        "effect://business/write",
        &[crate::MethodSpec::new(
            "invoke",
            xolotl_types::MethodAuthority::Perform,
            xolotl_types::Purity::Effectful,
            crate::MethodSpec::UNARY_ASYNC,
        )],
        Arc::new(BusinessStateDriver {
            state: boot.kernel().state().clone(),
            path: path.clone(),
            calls: calls.clone(),
        }),
    )?;
    Ok((
        xolotl_graph::OperationTemplate {
            target,
            method: "invoke".into(),
            method_id: None,
            output: xolotl_types::OutputMode::Unary,
            literal_input: Some(xolotl_types::Value::integer(42)),
        },
        path,
        calls,
    ))
}

#[tokio::test]
async fn default_disabled_observation_does_not_prevent_real_business_calls() -> anyhow::Result<()> {
    use xolotl_types::{Outcome, Value};
    let boot = Bootstrap::from_kernel(KernelBuilder::in_memory().build());
    ensure!(!boot.kernel().facts().is_enabled());
    let (operation, path, calls) = business_operation(&boot)?;
    let output = boot
        .kernel()
        .executor_for(boot.root())
        .eval(&xolotl_graph::DoNode::op(operation.clone()))
        .await;
    ensure!(
        output.outcome == Outcome::Done(Value::integer(42)),
        "{output:?}"
    );
    ensure!(calls.load(Ordering::SeqCst) == 1);
    ensure!(boot.kernel().state().read(&path).await? == Some(Value::integer(42)));
    ensure!(boot.kernel().facts().all_facts().is_err());
    let handle = boot.open_for(boot.root(), &operation.target, "perform")?;
    let direct = xolotl_types::Operation {
        id: xolotl_types::OperationId::new(
            boot.root(),
            boot.kernel().execution_ids().allocate()?,
            xolotl_types::InvocationId::new(1),
            xolotl_types::NodeId::ROOT,
            0,
        ),
        process: boot.root(),
        acting: IdentityRef::ROOT,
        handle,
        method: xolotl_types::MethodId::new(0),
        input: Value::integer(73),
        taint: xolotl_types::TaintSet::pristine(),
        output: xolotl_types::OutputMode::Unary,
    };
    let result = boot
        .kernel()
        .data_plane()
        .execute(
            &direct,
            crate::InvocationOptions {
                now_millis: 100,
                caller_identity: Some(IdentityRef::ROOT),
                record: false,
            },
        )
        .await;
    ensure!(
        result.output.outcome == Outcome::Done(Value::integer(73)),
        "{result:?}"
    );
    ensure!(result.completion_error.is_none());
    ensure!(calls.load(Ordering::SeqCst) == 2);
    ensure!(boot.kernel().state().read(&path).await? == Some(Value::integer(73)));
    ensure!(
        boot.kernel()
            .processes()
            .budget_mut(boot.root(), |budget| budget.inflight_ops)
            == Some(0)
    );
    Ok(())
}

#[tokio::test]
async fn optional_gateway_audit_without_storage_neither_reserves_ids_nor_changes_business_state()
-> anyhow::Result<()> {
    use xolotl_types::Value;
    let source = Arc::new(CountedIds::new(1000));
    let ids = ExecutionIds::new(source.clone());
    let boot = Bootstrap::from_kernel(
        KernelBuilder::in_memory()
            .with_execution_ids(ids.clone())
            .build(),
    );
    let path = Path::parse("state://business/audit-test")?;
    boot.kernel()
        .state()
        .write_set(&path, Value::integer(17))
        .await?;
    let status = boot.kernel().processes().status(boot.root());
    let audit = || crate::GatewayAudit {
        event: "gateway.request",
        username: Some("operator"),
        source_addr: Some("trusted-local"),
        outcome: "accepted",
        details: None,
    };
    ensure!(source.reservations.load(Ordering::SeqCst) == 0);
    boot.record_optional_gateway_audit(audit())?;
    ensure!(source.reservations.load(Ordering::SeqCst) == 0);
    ensure!(ids.allocate()?.get() == 1001);
    boot.record_optional_gateway_audit(audit())?;
    ensure!(ids.allocate()?.get() == 1002);
    ensure!(source.reservations.load(Ordering::SeqCst) == 1);
    ensure!(boot.record_gateway_audit(audit()).is_err());
    ensure!(ids.allocate()?.get() == 1003);
    ensure!(boot.kernel().state().read(&path).await? == Some(Value::integer(17)));
    ensure!(boot.kernel().processes().status(boot.root()) == status);
    ensure!(boot.kernel().handles().is_empty());
    ensure!(boot.kernel().facts().all_facts().is_err());
    Ok(())
}

#[tokio::test]
async fn required_observation_without_storage_or_with_full_quota_never_dispatches()
-> anyhow::Result<()> {
    use xolotl_types::{Outcome, Value};
    for quota in [false, true] {
        let ids = ExecutionIds::new(Arc::new(InMemoryExecutionIdSource::from_high_water(1000)));
        let mut builder = KernelBuilder::in_memory().with_execution_ids(ids.clone());
        let store = Arc::new(InMemoryFactStore::with_limits(
            crate::FactRetentionLimits {
                max_records: NonZeroUsize::MIN,
                ..Default::default()
            },
        )?);
        if quota {
            builder = builder.with_fact_sink(FactSink::from_parts(store.clone(), ids));
        }
        let boot = Bootstrap::from_kernel(builder.build());
        if quota {
            boot.kernel()
                .facts()
                .begin(crate::fact::testing::sample_fact(boot.root().get(), 7))?;
        }
        let before = store.all_facts()?;
        let usage = store.usage();
        let cursor = store.cursor();
        let mut notifications = store.subscribe_facts();
        let (operation, path, calls) = business_operation(&boot)?;
        boot.kernel()
            .state()
            .write_set(&path, Value::integer(17))
            .await?;
        let output = boot
            .kernel()
            .executor_for(boot.root())
            .with_fact_recording(true)
            .eval(&xolotl_graph::DoNode::op(operation.clone()))
            .await;
        ensure!(
            matches!(output.outcome, Outcome::Fail(xolotl_types::Failure::PolicyViolation { ref policy, .. }) if policy == "fact_recording"),
            "{output:?}"
        );
        ensure!(calls.load(Ordering::SeqCst) == 0);
        ensure!(boot.kernel().state().read(&path).await? == Some(Value::integer(17)));
        ensure!(store.all_facts()? == before && store.usage() == usage && store.cursor() == cursor);
        ensure!(matches!(
            notifications.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        ensure!(
            boot.kernel()
                .processes()
                .budget_mut(boot.root(), |budget| budget.inflight_ops)
                == Some(0)
        );
        let retry = boot
            .kernel()
            .executor_for(boot.root())
            .eval(&xolotl_graph::DoNode::op(operation))
            .await;
        ensure!(
            retry.outcome == Outcome::Done(Value::integer(42)),
            "{retry:?}"
        );
        ensure!(calls.load(Ordering::SeqCst) == 1);
        ensure!(boot.kernel().state().read(&path).await? == Some(Value::integer(42)));
    }
    Ok(())
}

#[test]
fn builder_uses_the_supplied_state_without_installing_other_ports() {
    let kernel = KernelBuilder::new(Backend::new()).build();
    assert!(!kernel.state().has_read());
    assert!(!kernel.state().has_write());
}

#[test]
fn request_admission_rejects_unregistered_identity_without_allocating_process() -> anyhow::Result<()>
{
    let boot = Bootstrap::in_memory();
    let identity = IdentityRef::new(1);
    let before = boot.kernel().processes().len();
    ensure!(matches!(
        boot.request_under(boot.root(), identity, &[]),
        Err(BootstrapError::Identity(IdentityError::Missing(missing))) if missing == identity
    ));
    ensure!(boot.kernel().processes().len() == before);
    let path = Path::parse("identity://users/alice")?;
    ensure!(boot.kernel().identities().lookup(&path)?.is_none());
    ensure!(boot.kernel().identities().resolve_or_register(&path)? == identity);
    let request = boot.request_under(boot.root(), identity, &[])?;
    ensure!(request.id() != boot.root());
    Ok(())
}

struct CountedIds {
    source: InMemoryExecutionIdSource,
    reservations: AtomicUsize,
}

impl CountedIds {
    fn new(high_water: u64) -> Self {
        Self {
            source: InMemoryExecutionIdSource::from_high_water(high_water),
            reservations: AtomicUsize::new(0),
        }
    }
}

impl ExecutionIdSource for CountedIds {
    fn reserve(
        &self,
        count: NonZeroU64,
    ) -> Result<crate::ExecutionIdRange, crate::ExecutionIdError> {
        self.reservations.fetch_add(1, Ordering::SeqCst);
        self.source.reserve(count)
    }
}

struct FactsOnly(InMemoryFactStore);

impl FactStore for FactsOnly {
    fn append(&self, fact: Fact) -> Result<u64, FactError> {
        self.0.append(fact)
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        self.0.complete(fact)
    }

    fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        self.0.scan(query)
    }

    fn lookup(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        self.0.lookup(query)
    }

    fn facts_of(&self, process: ProcessId) -> Result<Vec<Fact>, FactError> {
        self.0.facts_of(process)
    }

    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        self.0.all_facts()
    }

    fn cursor(&self) -> u64 {
        self.0.cursor()
    }
}

#[test]
fn fact_storage_and_execution_ids_can_be_independent_ports() -> anyhow::Result<()> {
    let store = Arc::new(FactsOnly(InMemoryFactStore::new()));
    let source = Arc::new(CountedIds::new(1000));
    let ids = ExecutionIds::new(source.clone());
    let facts = FactSink::from_parts(store, ids.clone());
    let kernel = KernelBuilder::in_memory()
        .with_fact_sink(facts)
        .with_execution_ids(ids)
        .build();
    ensure!(source.reservations.load(Ordering::SeqCst) == 0);
    ensure!(kernel.execution_ids().allocate()?.get() == 1001);
    ensure!(kernel.facts().execution_ids().allocate()?.get() == 1002);
    ensure!(source.reservations.load(Ordering::SeqCst) == 1);
    Ok(())
}

#[test]
fn shared_backends_do_not_share_runtime_tables() -> anyhow::Result<()> {
    let (facts, store) = FactSink::in_memory();
    let ids = ExecutionIds::new(Arc::new(InMemoryExecutionIdSource::new()));
    let first = KernelBuilder::in_memory()
        .with_fact_sink(facts.clone())
        .with_execution_ids(ids.clone())
        .with_process_capacity(NonZeroUsize::MIN)
        .build();
    let second = KernelBuilder::in_memory()
        .with_fact_sink(facts)
        .with_execution_ids(ids.clone())
        .build();
    ensure!(first.processes().is_empty() && second.processes().is_empty());
    // Construction has not reserved an identity, even for the root.
    ensure!(store.reserve(NonZeroU64::MIN)?.first() == ExecutionId::FIRST);
    ensure!(ids.allocate()? == ExecutionId::FIRST);
    let clone = first.clone();
    ensure!(first.execution_ids().allocate()?.get() == 2);
    ensure!(clone.execution_ids().allocate()?.get() == 3);
    ensure!(second.execution_ids().allocate()?.get() == 4);

    let first = Bootstrap::from_kernel(first);
    let clone = Bootstrap::from_kernel(clone);
    ensure!(first.root() == clone.root());
    ensure!(second.processes().is_empty());
    ensure!(first.kernel().registry().counts().grants == 1);
    ensure!(second.registry().counts().grants == 0);
    first
        .kernel()
        .processes()
        .set_capacity(Some(NonZeroUsize::MIN.saturating_add(1)))?;
    ensure!(clone.kernel().processes().capacity() == first.kernel().processes().capacity());
    ensure!(second.processes().capacity().is_none());
    Ok(())
}

#[test]
fn handle_slot_limit_is_fixed_per_shared_kernel_table() -> anyhow::Result<()> {
    let limited = KernelBuilder::in_memory().with_handle_slot_limit(0).build();
    let clone = limited.clone();
    let separate = KernelBuilder::in_memory().build();
    ensure!(limited.handles().slot_limit() == Some(0));
    ensure!(clone.handles().slot_limit() == Some(0));
    ensure!(separate.handles().slot_limit().is_none());
    ensure!(limited.handles().allocated_slots() == 0);
    Ok(())
}

#[test]
fn explicit_identity_source_overrides_facts_in_either_setter_order() -> anyhow::Result<()> {
    for explicit_first in [false, true] {
        let source = Arc::new(CountedIds::new(1000));
        let ids = ExecutionIds::new(source.clone());
        let (facts, store) = FactSink::in_memory();
        let builder = KernelBuilder::in_memory();
        let kernel = if explicit_first {
            builder.with_execution_ids(ids).with_fact_sink(facts)
        } else {
            builder.with_fact_sink(facts).with_execution_ids(ids)
        }
        .build();
        ensure!(source.reservations.load(Ordering::SeqCst) == 0);
        ensure!(kernel.execution_ids().allocate()?.get() == 1001);
        ensure!(kernel.clone().execution_ids().allocate()?.get() == 1002);
        ensure!(kernel.facts().execution_ids().allocate()?.get() == 1003);
        ensure!(source.reservations.load(Ordering::SeqCst) == 1);
        ensure!(store.reserve(NonZeroU64::MIN)?.first() == ExecutionId::FIRST);
    }
    Ok(())
}
