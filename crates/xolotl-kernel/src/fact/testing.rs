//! Fault injection at the selected observation write and its commit result.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

pub(crate) fn observing_bootstrap() -> crate::Bootstrap {
    crate::Bootstrap::from_kernel(
        crate::KernelBuilder::in_memory()
            .with_fact_sink(FactSink::in_memory().0)
            .build(),
    )
}

pub(crate) fn sample_fact(process: u64, position: u32) -> Fact {
    use xolotl_types::{
        DecisionTag, ExecutionId, HandleId, IdentityRef, InvocationId, MethodId, NodeId, ProcessId,
        ReplayClass, ResourceId, TaintSet, Timestamp, Value,
    };
    Fact {
        id: OperationId::new(
            ProcessId::new(process),
            ExecutionId::FIRST,
            InvocationId::new(1),
            NodeId::new(position),
            0,
        ),
        schema_version: Fact::SCHEMA_VERSION,
        caller: ProcessId::new(process),
        caller_identity: Some(IdentityRef::ROOT),
        acting: IdentityRef::ROOT,
        handle: HandleId::new(0, 1),
        resource: ResourceId::new(1),
        method: MethodId::new(0),
        input: Value::null(),
        taint: TaintSet::pristine(),
        decision: DecisionTag::Ok,
        outcome: Some(Value::integer(1)),
        batch: None,
        replay: ReplayClass::NonIdempotentEffect,
        timestamp: Timestamp::millis(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, ensure};
    use tokio::sync::broadcast::error::TryRecvError;

    #[test]
    fn retention_rejection_preserves_rows_indexes_cursor_usage_and_notifications()
    -> anyhow::Result<()> {
        let first = sample_fact(1, 1);
        let second = sample_fact(1, 2);
        let budget = serde_json::to_vec(&first)?.len() + serde_json::to_vec(&second)?.len();
        let store = InMemoryFactStore::with_limits(FactRetentionLimits {
            max_records: NonZeroUsize::MIN.saturating_add(1),
            max_encoded_bytes: NonZeroUsize::new(budget).context("byte budget")?,
            max_record_bytes: NonZeroUsize::new(budget).context("record budget")?,
        })?;
        ensure!(store.append(first.clone())? == 0);
        ensure!(store.append(second.clone())? == 1);
        let before = store.all_facts()?;
        let usage = store.usage();
        let cursor = store.cursor();
        let mut notifications = store.subscribe_facts();
        ensure!(store.append(sample_fact(1, 3)).is_err());
        let mut duplicate = first.clone();
        duplicate.input = xolotl_types::Value::string("ignored".repeat(100));
        ensure!(store.append(duplicate)? == 0);
        let mut completion = first.clone();
        completion.outcome = Some(xolotl_types::Value::string("expanded".repeat(16)));
        ensure!(
            serde_json::to_vec(&completion)?.len() <= budget,
            "completion must fit the individual row budget but not total retained bytes"
        );
        ensure!(store.complete(completion).is_err());
        ensure!(store.all_facts()? == before && store.usage() == usage && store.cursor() == cursor);
        ensure!(store.get(first.id)? == Some(first));
        ensure!(store.get(second.id)? == Some(second));
        ensure!(store.get(sample_fact(1, 3).id)?.is_none());
        ensure!(matches!(notifications.try_recv(), Err(TryRecvError::Empty)));
        Ok(())
    }
}

#[derive(Default)]
pub(crate) struct CompletionFaults {
    pub store: InMemoryFactStore,
    pub reject_write: AtomicBool,
    pub commit_unknown_after_complete: AtomicBool,
}

impl ExecutionIdSource for CompletionFaults {
    fn reserve(&self, count: NonZeroU64) -> Result<ExecutionIdRange, ExecutionIdError> {
        self.store.reserve(count)
    }
}

impl FactStore for CompletionFaults {
    fn append(&self, fact: Fact) -> Result<u64, FactError> {
        self.store.append(fact)
    }

    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        if self.reject_write.load(Ordering::SeqCst) {
            return Err(FactError::new("injected completion write failure".into()));
        }
        self.store.complete(fact)?;
        if self.commit_unknown_after_complete.load(Ordering::SeqCst) {
            return Err(FactError::commit_outcome_unknown(
                "injected unconfirmed completion commit".into(),
            ));
        }
        Ok(())
    }

    fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        self.store.scan(query)
    }

    fn lookup(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        self.store.lookup(query)
    }

    fn facts_of(&self, process: xolotl_types::ProcessId) -> Result<Vec<Fact>, FactError> {
        self.store.facts_of(process)
    }

    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        self.store.all_facts()
    }

    fn cursor(&self) -> u64 {
        self.store.cursor()
    }
}
