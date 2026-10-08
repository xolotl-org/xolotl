use super::*;
use crate::fact::{
    FactError, FactLookup, FactLookupResult, FactPage, FactQuery, InMemoryFactStore,
};
use crate::{ExecutionIdError, ExecutionIdRange, ExecutionIdSource, WeakHandleTable};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicUsize, Ordering};

struct ReentrantFacts {
    handles: WeakHandleTable,
    store: InMemoryFactStore,
    completed: AtomicUsize,
}

impl ReentrantFacts {
    fn unlocked_handles(&self) -> Result<HandleTable, FactError> {
        let handles = self
            .handles
            .upgrade()
            .ok_or_else(|| FactError::new("table lost".into()))?;
        // Avoid hanging the test if a denial reintroduces a caller-held lock.
        let guard = handles
            .try_write()
            .ok_or_else(|| FactError::new("Fact callback holds handle lock".into()))?;
        drop(guard);
        Ok(handles)
    }
}

impl ExecutionIdSource for ReentrantFacts {
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        self.store.reserve(count)
    }
}

impl FactStore for ReentrantFacts {
    fn append(&self, _: Fact) -> Result<u64, FactError> {
        Err(FactError::new(
            "denied invocation must never begin dispatch".into(),
        ))
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        let handles = self.unlocked_handles()?;
        // A host audit adapter can synchronously revoke other local authority.
        if handles.revoke_owned_by(ProcessId::new(42)) != 1 {
            return Err(FactError::new(
                "audit adapter did not reclaim its handle".into(),
            ));
        }
        self.store.complete(fact)?;
        self.completed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        self.store.scan(query)
    }
    fn lookup(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        self.store.lookup(query)
    }
    fn facts_of(&self, process: ProcessId) -> Result<Vec<Fact>, FactError> {
        self.store.facts_of(process)
    }
    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        self.store.all_facts()
    }
    fn cursor(&self) -> u64 {
        self.store.cursor()
    }
}

#[tokio::test]
async fn admission_denials_record_facts_without_holding_handle_locks() -> anyhow::Result<()> {
    for reason in [
        "stale",
        "method",
        "owner",
        "identity",
        "rights",
        "output",
        "propagation",
        "host",
    ] {
        let rights = Rights::new(
            MethodBitmap::method(u32::from(reason == "rights")),
            if reason == "host" {
                RightFlags::SPAWN_WITH
            } else {
                RightFlags::empty()
            },
        );
        let supports = if reason == "output" {
            SUPPORTS_UNARY
        } else {
            SUPPORTS_UNARY | SUPPORTS_ASYNC
        };
        let (mut plane, id) = dataplane_with_handle(
            rights,
            FastPath::Unconditional,
            MethodContract::new(0, ReplayClass::NonIdempotentEffect, supports),
        )?;
        let mut observer_handle = plane.handles.get(id).context("original handle")?;
        observer_handle.process = ProcessId::new(42);
        let observer_handle = plane.handles.insert(observer_handle)?;
        let facts = Arc::new(ReentrantFacts {
            handles: plane.handles.downgrade(),
            store: InMemoryFactStore::new(),
            completed: AtomicUsize::new(0),
        });
        plane.facts = FactSink::new(facts.clone());
        let mut operation = op(id, 7, Value::null());
        match reason {
            "stale" => ensure!(plane.handles.revoke(id)),
            "method" => operation.method = MethodId::new(99),
            "owner" => {
                operation.process = ProcessId::new(2);
                operation.id.process = operation.process;
            }
            "identity" => operation.acting = IdentityRef::new(99),
            "output" | "propagation" | "host" => operation.output = OutputMode::AsyncProcess,
            "rights" => {}
            _ => anyhow::bail!("unknown denial"),
        }
        operation.taint = TaintSet::author();
        let result = plane
            .execute(
                &operation,
                InvocationOptions {
                    caller_identity: None,
                    now_millis: 0,
                    record: true,
                },
            )
            .await;
        ensure!(
            matches!(result.output.outcome, Outcome::Fail(_)),
            "{reason}"
        );
        ensure!(
            result.completion_error.is_none(),
            "{reason}: {:?}",
            result.completion_error
        );
        ensure!(result.output.taint == operation.taint);
        ensure!(facts.completed.load(Ordering::SeqCst) == 1, "{reason}");
        ensure!(plane.handles.get(observer_handle).is_none());
        let recorded = facts.store.facts_of(operation.process)?;
        ensure!(recorded.len() == 1 && recorded[0].taint == operation.taint);
    }
    Ok(())
}

struct TargetReentryDriver {
    handles: WeakHandleTable,
}

#[async_trait::async_trait]
impl Driver for TargetReentryDriver {
    async fn call(
        &self,
        _method: MethodId,
        _input: Value,
        _output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<crate::DriverOutput, DriverError> {
        let handles = self
            .handles
            .upgrade()
            .ok_or_else(|| DriverError::Other("table lost".into()))?;
        let mut table = handles
            .try_write()
            .ok_or_else(|| DriverError::Other("driver holds handle read lock".into()))?;
        if table.revoke_owned_by(ctx.caller) != 1 {
            return Err(DriverError::Other("expected one live handle".into()));
        }
        drop(table);
        let target = ctx
            .target_path
            .as_ref()
            .ok_or_else(|| DriverError::Other("dispatch lost its bound target".into()))?;
        Ok(crate::DriverOutput::new(Outcome::Done(Value::string(
            target.to_string(),
        ))))
    }
}

#[tokio::test]
async fn dispatch_retains_its_target_while_the_driver_revokes_its_handle() -> anyhow::Result<()> {
    let table = HandleTable::new();
    let mut plan = DriverPlan::new(DriverId::new(1), None, 0);
    plan.insert(
        MethodId::new(7),
        MethodContract::new(0, ReplayClass::Deterministic, SUPPORTS_UNARY),
        Arc::new(TargetReentryDriver {
            handles: table.downgrade(),
        }),
    );
    let target = Path::parse("state://private/concrete/target")?;
    let id = table.insert(Handle {
        id: HandleId::new(0, 0),
        process: ProcessId::new(1),
        acting: IdentityRef::ROOT,
        open_verb: "read".into(),
        resource: ResourceId::new(1),
        rights: Rights::new(MethodBitmap::method(0), RightFlags::empty()),
        driver_plan: plan,
        fast_path: FastPath::Unconditional,
        bound_path: Some(target.clone()),
    })?;
    let plane = DataPlane::new(table, FactSink::in_memory().0, test_state());
    let operation = op(id, 7, Value::null());
    let options = InvocationOptions {
        caller_identity: None,
        now_millis: 0,
        record: false,
    };
    let result = plane.execute(&operation, options).await;
    ensure!(result.completion_error.is_none());
    ensure!(result.output.outcome == Outcome::Done(Value::string(target.to_string())));
    ensure!(plane.handles.get(id).is_none());
    ensure!(matches!(
        plane.execute(&operation, options).await.output.outcome,
        Outcome::Fail(_)
    ));
    Ok(())
}
