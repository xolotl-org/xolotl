use super::*;
use crate::fact::tests::fact;
use crate::{FactStore, InMemoryFactStore};
use anyhow::{Context, ensure};
use xolotl_types::{ReplayClass, Value};

fn query(limit: usize, bytes: usize) -> anyhow::Result<FactQuery> {
    Ok(FactQuery::new(
        NonZeroUsize::new(limit).context("nonzero record limit")?,
        NonZeroUsize::new(bytes).context("nonzero byte limit")?,
    ))
}

#[test]
fn filtered_pages_use_slots_and_observe_updates_inside_fixed_interval() -> anyhow::Result<()> {
    let store = InMemoryFactStore::new();
    let first = fact(1, 0, ReplayClass::Observation);
    let other = fact(2, 1, ReplayClass::Observation);
    let mut last = fact(1, 2, ReplayClass::Observation);
    store.append(first.clone())?;
    store.append(other.clone())?;
    store.append(last.clone())?;
    let mut q = query(1, 65536)?;
    q.max_examined = NonZeroUsize::new(8).context("candidate budget")?;
    q.process = Some(ProcessId::new(1));
    let page = store.scan(q)?;
    ensure!(page.facts == [first]);
    ensure!(page.next == Some(1) && page.end == 3 && !page.is_complete());

    last.outcome = Some(Value::integer(99));
    store.complete(last.clone())?;
    store.append(fact(1, 3, ReplayClass::Observation))?;
    q = q.next_page(&page).context("missing next page")?;
    let page = store.scan(q)?;
    ensure!(page.facts == [last.clone()]);
    ensure!(page.next.is_none() && page.end == 3 && page.is_complete());
    ensure!(store.get(last.id)? == Some(last));
    ensure!(store.get(other.id)? == Some(other));
    ensure!(
        store
            .get(fact(1, 99, ReplayClass::Observation).id)?
            .is_none()
    );
    Ok(())
}

#[test]
fn byte_budget_preserves_unread_slot_and_oversized_record_errors() -> anyhow::Result<()> {
    let store = InMemoryFactStore::new();
    let first = fact(1, 0, ReplayClass::Observation);
    let mut large = fact(1, 1, ReplayClass::Observation);
    large.input = Value::string("quoted\"\n".repeat(1024));
    let first_size = serde_json::to_vec(&first)?.len();
    let large_size = serde_json::to_vec(&large)?.len();
    store.append(first.clone())?;
    store.append(large.clone())?;

    let mut q = query(usize::MAX, first_size)?;
    let page = store.scan(q)?;
    ensure!(page.facts == [first]);
    ensure!(page.encoded_bytes == first_size && page.next == Some(1) && page.end == 2);
    q = q.next_page(&page).context("missing next page")?;
    let error = store.scan(q).err().context("oversized fact must fail")?;
    ensure!(error.0.contains("slot 1") && error.0.contains("byte limit"));
    q.max_encoded_bytes = NonZeroUsize::new(large_size).context("encoded size")?;
    let page = store.scan(q)?;
    ensure!(page.facts == [large] && page.encoded_bytes == large_size);
    ensure!(page.is_complete());
    Ok(())
}

#[test]
fn process_filter_precedes_byte_accounting_and_can_exhaust_empty_interval() -> anyhow::Result<()> {
    let store = InMemoryFactStore::new();
    let mut large = fact(2, 0, ReplayClass::Observation);
    large.input = Value::string("payload".repeat(2048));
    let target = fact(1, 1, ReplayClass::Observation);
    let size = serde_json::to_vec(&target)?.len();
    store.append(large)?;
    store.append(target.clone())?;
    let mut q = query(8, size)?;
    q.process = Some(ProcessId::new(1));
    let page = store.scan(q)?;
    ensure!(page.facts == [target] && page.encoded_bytes == size);
    ensure!(page.is_complete());
    q.process = Some(ProcessId::new(3));
    let page = store.scan(q)?;
    ensure!(page.facts.is_empty() && page.next.is_none() && page.is_complete());
    ensure!(page.encoded_bytes == 0);
    Ok(())
}

#[test]
fn interval_validation_clamping_and_empty_pages() -> anyhow::Result<()> {
    let store = InMemoryFactStore::new();
    let mut q = query(usize::MAX, usize::MAX)?;
    ensure!(store.scan(q)?.is_complete());
    store.append(fact(1, 0, ReplayClass::Observation))?;
    q.before = Some(u64::MAX);
    let page = store.scan(q)?;
    ensure!(page.end == 1 && page.is_complete());
    q.from = 1;
    let page = store.scan(q)?;
    ensure!(page.facts.is_empty() && page.is_complete());
    q.before = Some(0);
    ensure!(store.scan(q).is_err());
    q.before = None;
    q.from = u64::MAX;
    ensure!(store.scan(q).is_err());
    Ok(())
}

#[test]
fn reverse_pages_keep_the_remaining_interval_and_observe_current_records() -> anyhow::Result<()> {
    let (sink, store) = crate::FactSink::in_memory();
    let mut expected = Vec::new();
    for slot in 0..5 {
        let item = fact(
            if slot % 2 == 0 { 1 } else { 2 },
            slot,
            ReplayClass::Observation,
        );
        if slot % 2 == 0 {
            expected.push(item.clone());
        }
        store.append(item)?;
    }
    expected.reverse();
    let mut q = query(2, 65536)?;
    q.order = FactOrder::Reverse;
    q.process = Some(ProcessId::new(1));
    let mut actual = Vec::new();
    for end in [5, 3, 1] {
        let page = sink.scan(q)?;
        ensure!(page.end == end);
        ensure!(page.examined <= 2 && page.facts.len() == 1);
        let next = q.next_page(&page);
        actual.extend(page.facts);
        store.append(fact(1, end as u32 + 10, ReplayClass::Observation))?;
        match next {
            Some(next) => {
                ensure!(next.from == 0 && next.before == Some(end - 2));
                q = next;
            }
            None => ensure!(end == 1),
        }
    }
    ensure!(actual == expected);
    Ok(())
}

#[test]
fn sparse_filters_yield_empty_pages_with_bounded_candidate_work() -> anyhow::Result<()> {
    let (sink, store) = crate::FactSink::in_memory();
    for slot in 0..10 {
        store.append(fact(2, slot, ReplayClass::Observation))?;
    }
    for order in [FactOrder::Forward, FactOrder::Reverse] {
        let mut q = query(3, 1)?;
        q.order = order;
        q.process = Some(ProcessId::new(99));
        let mut examined = 0;
        let mut pages = 0;
        loop {
            let page = sink.scan(q)?;
            ensure!(page.facts.is_empty() && page.encoded_bytes == 0);
            ensure!(page.examined <= 3);
            examined += page.examined;
            pages += 1;
            let Some(next) = q.next_page(&page) else {
                break;
            };
            q = next;
        }
        ensure!(examined == 10 && pages == 4);
    }
    Ok(())
}

#[test]
fn reverse_byte_limit_preserves_the_unread_record() -> anyhow::Result<()> {
    let (sink, store) = crate::FactSink::in_memory();
    let mut large = fact(1, 0, ReplayClass::Observation);
    large.input = Value::string("quoted\"\n".repeat(1024));
    let small = fact(1, 1, ReplayClass::Observation);
    let small_size = serde_json::to_vec(&small)?.len();
    let large_size = serde_json::to_vec(&large)?.len();
    store.append(large.clone())?;
    store.append(small.clone())?;
    let mut q = query(3, small_size)?;
    q.order = FactOrder::Reverse;
    let page = sink.scan(q)?;
    ensure!(page.facts == [small] && page.examined == 2 && page.next == Some(1));
    q = q.next_page(&page).context("unread record continuation")?;
    ensure!(sink.scan(q).is_err());
    q.max_encoded_bytes = NonZeroUsize::new(large_size).context("large encoding")?;
    let page = sink.scan(q)?;
    ensure!(page.facts == [large] && page.is_complete());
    Ok(())
}

#[test]
fn reverse_page_validation_rejects_nonprogress_and_false_accounting() -> anyhow::Result<()> {
    let mut q = query(3, 65536)?;
    q.from = 1;
    q.order = FactOrder::Reverse;
    q.process = Some(ProcessId::new(1));
    let item = fact(1, 0, ReplayClass::Observation);
    let valid = FactPage {
        encoded_bytes: serde_json::to_vec(&item)?.len(),
        facts: vec![item],
        next: Some(2),
        end: 4,
        examined: 2,
    };
    valid.validate(q)?;
    for cursor in [0, 1, 4, 5] {
        let mut invalid = valid.clone();
        invalid.next = Some(cursor);
        ensure!(invalid.validate(q).is_err());
    }
    let mut invalid = valid;
    invalid.examined = 0;
    ensure!(invalid.validate(q).is_err());
    invalid.examined = 4;
    ensure!(invalid.validate(q).is_err());
    Ok(())
}

#[test]
fn unfiltered_pages_cannot_skip_slots_or_claim_premature_exhaustion() -> anyhow::Result<()> {
    for order in [FactOrder::Forward, FactOrder::Reverse] {
        let mut q = query(2, 65536)?;
        q.order = order;
        let item = fact(1, 0, ReplayClass::Observation);
        let mut page = FactPage {
            encoded_bytes: serde_json::to_vec(&item)?.len(),
            facts: vec![item],
            next: None,
            end: 100,
            examined: 1,
        };
        ensure!(page.validate(q).is_err());
        page.next = Some(match order {
            FactOrder::Forward => 2,
            FactOrder::Reverse => 98,
        });
        ensure!(page.validate(q).is_err());
        page.next = Some(match order {
            FactOrder::Forward => 1,
            FactOrder::Reverse => 99,
        });
        page.validate(q)?;
        page.examined = 2;
        page.validate(q)?;
    }
    Ok(())
}
