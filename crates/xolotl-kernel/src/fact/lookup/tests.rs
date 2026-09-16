use super::*;
use crate::fact::tests::fact;
use crate::{FactPage, FactQuery, FactSink, FactStore, InMemoryFactStore};
use anyhow::{Context, ensure};
use xolotl_types::{ReplayClass, Value};

#[test]
fn bounded_lookup_distinguishes_missing_from_oversized_records() -> anyhow::Result<()> {
    let (sink, store) = FactSink::in_memory();
    let mut saved = fact(1, 0, ReplayClass::Observation);
    saved.input = Value::string("quoted\"\n".repeat(1024));
    let size = serde_json::to_vec(&saved)?.len();
    store.append(saved.clone())?;
    ensure!(
        sink.get_bounded(
            saved.id,
            NonZeroUsize::new(size - 1).context("short budget")?
        )
        .is_err()
    );
    ensure!(
        sink.get_bounded(saved.id, NonZeroUsize::new(size).context("exact budget")?)?
            == Some(saved)
    );
    ensure!(
        sink.get_bounded(fact(1, 9, ReplayClass::Observation).id, NonZeroUsize::MIN)?
            .is_none()
    );
    Ok(())
}

#[test]
fn lookup_filters_current_caller_before_spending_the_byte_budget() -> anyhow::Result<()> {
    let (sink, store) = FactSink::in_memory();
    let mut saved = fact(1, 0, ReplayClass::Observation);
    saved.caller = ProcessId::new(2);
    saved.input = Value::string("quoted\"\n".repeat(1024));
    store.append(saved.clone())?;
    let mut query = FactLookup {
        process: Some(ProcessId::new(1)),
        ..FactLookup::new(saved.id, NonZeroUsize::MIN)
    };
    ensure!(sink.lookup(query)? == FactLookupResult::FilteredOut);
    ensure!(
        sink.lookup(FactLookup {
            id: fact(1, 9, ReplayClass::Observation).id,
            ..query
        })? == FactLookupResult::Missing
    );

    saved.caller = ProcessId::new(1);
    store.complete(saved.clone())?;
    ensure!(sink.lookup(query).is_err());
    query.max_encoded_bytes =
        NonZeroUsize::new(serde_json::to_vec(&saved)?.len()).context("exact byte budget")?;
    ensure!(sink.lookup(query)? == FactLookupResult::Found(saved.clone()));

    saved.caller = ProcessId::new(2);
    store.complete(saved.clone())?;
    ensure!(sink.lookup(query)? == FactLookupResult::FilteredOut);
    query.process = None;
    ensure!(sink.lookup(query)? == FactLookupResult::Found(saved));
    Ok(())
}

struct InvalidLookupStore {
    inner: InMemoryFactStore,
    result: FactLookupResult,
}

impl crate::ExecutionIdSource for InvalidLookupStore {
    fn reserve(
        &self,
        count: std::num::NonZeroU64,
    ) -> Result<crate::ExecutionIdRange, crate::ExecutionIdError> {
        self.inner.reserve(count)
    }
}

impl FactStore for InvalidLookupStore {
    fn append(&self, fact: Fact) -> Result<u64, FactError> {
        self.inner.append(fact)
    }
    fn complete(&self, fact: Fact) -> Result<(), FactError> {
        self.inner.complete(fact)
    }
    fn sync(&self) -> Result<(), FactError> {
        self.inner.sync()
    }
    fn scan(&self, query: FactQuery) -> Result<FactPage, FactError> {
        self.inner.scan(query)
    }
    fn lookup(&self, _query: FactLookup) -> Result<FactLookupResult, FactError> {
        Ok(self.result.clone())
    }
    fn facts_of(&self, process: ProcessId) -> Result<Vec<Fact>, FactError> {
        self.inner.facts_of(process)
    }
    fn all_facts(&self) -> Result<Vec<Fact>, FactError> {
        self.inner.all_facts()
    }
    fn cursor(&self) -> u64 {
        self.inner.cursor()
    }
}

#[test]
fn sink_rejects_invalid_lookup_results_from_custom_adapters() -> anyhow::Result<()> {
    let expected = fact(1, 0, ReplayClass::Observation);
    let query = FactLookup::new(expected.id, NonZeroUsize::MAX);
    for result in [
        FactLookupResult::Found(fact(1, 1, ReplayClass::Observation)),
        FactLookupResult::FilteredOut,
    ] {
        let sink = FactSink::new(std::sync::Arc::new(InvalidLookupStore {
            inner: InMemoryFactStore::new(),
            result,
        }));
        ensure!(sink.lookup(query).is_err());
        ensure!(sink.get(query.id).is_err());
        ensure!(sink.get_bounded(query.id, query.max_encoded_bytes).is_err());
    }
    let sink = FactSink::new(std::sync::Arc::new(InvalidLookupStore {
        inner: InMemoryFactStore::new(),
        result: FactLookupResult::Found(expected),
    }));
    ensure!(
        sink.lookup(FactLookup {
            process: Some(ProcessId::new(2)),
            ..query
        })
        .is_err()
    );
    Ok(())
}
