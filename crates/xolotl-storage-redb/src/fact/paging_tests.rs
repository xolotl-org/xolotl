use super::{tests::fact, *};
use crate::RedbStore;
use anyhow::{Context, anyhow, ensure};
use std::num::NonZeroUsize;
use xolotl_kernel::FactOrder;
use xolotl_types::Value;

fn query(limit: usize, max_encoded_bytes: usize) -> anyhow::Result<FactQuery> {
    Ok(FactQuery::new(
        NonZeroUsize::new(limit).ok_or_else(|| anyhow!("zero record budget"))?,
        NonZeroUsize::new(max_encoded_bytes).ok_or_else(|| anyhow!("zero byte budget"))?,
    ))
}

fn replace_bytes(store: &RedbFactStore, slot: u64, bytes: &[u8]) -> anyhow::Result<()> {
    let txn = store.db.begin_write()?;
    txn.open_table(FACTS_TABLE)?.insert(slot, bytes)?;
    txn.commit()?;
    Ok(())
}

#[test]
fn global_pages_preserve_append_order_and_record_budget() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let expected = [
        fact(1, 0, false),
        fact(2, 0, true),
        fact(1, 1, true),
        fact(3, 0, false),
        fact(1, 2, true),
    ];
    for record in &expected {
        fs.append(record.clone())?;
    }

    let mut request = query(2, usize::MAX)?;
    let mut observed = Vec::new();
    for expected_next in [Some(2), Some(4), None] {
        let page = fs.scan(request)?;
        ensure!(page.next == expected_next && page.end == 5);
        ensure!(page.facts.len() <= 2);
        ensure!(page.examined == page.facts.len());
        let encoded_bytes = page.facts.iter().try_fold(0, |sum, record| {
            serde_json::to_vec(record).map(|bytes| sum + bytes.len())
        })?;
        ensure!(page.encoded_bytes == encoded_bytes);
        if let Some(next) = request.next_page(&page) {
            request = next;
        } else {
            request.from = page.end;
            request.before = Some(page.end);
        }
        observed.extend(page.facts);
    }
    ensure!(observed == expected);
    let exhausted = fs.scan(request)?;
    ensure!(exhausted.facts.is_empty() && exhausted.is_complete());
    ensure!(exhausted.encoded_bytes == 0 && exhausted.examined == 0);
    Ok(())
}

#[test]
fn filtered_pages_skip_unrelated_records_and_keep_absolute_cursors() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let first = fact(1, 0, true);
    let second = fact(1, 1, true);
    let mut unrelated = fact(2, 0, true);
    unrelated.input = Value::string("x".repeat(4096));
    fs.append(unrelated.clone())?;
    fs.append(first.clone())?;
    unrelated.id.position = xolotl_types::NodeId::new(1);
    fs.append(unrelated)?;
    fs.append(second.clone())?;
    fs.append(fact(2, 2, true))?;
    // A filtered page must not decode another process's malformed record.
    replace_bytes(&fs, 2, b"invalid JSON")?;

    let mut request = query(1, serde_json::to_vec(&first)?.len())?;
    request.process = Some(ProcessId::new(1));
    let page = fs.scan(request)?;
    ensure!(page.facts == [first] && page.next == Some(2) && page.end == 5);
    ensure!(page.examined == 1);
    request = request.next_page(&page).context("first continuation")?;
    let page = fs.scan(request)?;
    ensure!(page.facts == [second] && page.next == Some(4) && !page.is_complete());
    ensure!(page.examined == 1);
    request = request.next_page(&page).context("second continuation")?;
    let page = fs.scan(request)?;
    ensure!(page.facts.is_empty() && page.is_complete());
    ensure!(page.encoded_bytes == 0 && page.examined == 0);
    Ok(())
}

#[test]
fn reverse_pages_keep_the_lower_bound_and_exclude_later_appends() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("reverse.redb"))?;
    let fs = store.fact_store()?;
    let expected = [
        fact(1, 0, true),
        fact(2, 0, true),
        fact(1, 1, false),
        fact(3, 0, true),
        fact(1, 2, true),
    ];
    for record in &expected {
        fs.append(record.clone())?;
    }
    let mut request = query(2, usize::MAX)?;
    request.order = FactOrder::Reverse;
    request.from = 1;
    let page = fs.scan(request)?;
    ensure!(page.facts == [expected[4].clone(), expected[3].clone()]);
    ensure!(page.next == Some(3) && page.end == 5 && page.examined == 2);
    store.fact_store()?.append(fact(1, 3, true))?;
    let completed = fact(1, 1, true);
    fs.complete(completed.clone())?;

    request = request.next_page(&page).context("reverse continuation")?;
    ensure!(request.from == 1 && request.before == Some(3));
    let page = fs.scan(request)?;
    ensure!(page.facts == [completed, expected[1].clone()]);
    ensure!(page.end == 3 && page.examined == 2 && page.is_complete());
    ensure!(request.next_page(&page).is_none());
    Ok(())
}

#[test]
fn reverse_process_pages_charge_only_indexed_candidates() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("sparse-reverse.redb"))?;
    let fs = store.fact_store()?;
    let first = fact(1, 0, true);
    let second = fact(1, 1, true);
    for record in [
        fact(2, 0, true),
        first.clone(),
        fact(2, 1, true),
        second.clone(),
        fact(2, 2, true),
    ] {
        fs.append(record)?;
    }
    for slot in [0, 2, 4] {
        replace_bytes(&fs, slot, b"invalid unrelated JSON")?;
    }
    let mut request = query(8, usize::MAX)?;
    request.order = FactOrder::Reverse;
    request.process = Some(ProcessId::new(1));
    request.max_examined = NonZeroUsize::MIN;
    let page = fs.scan(request)?;
    ensure!(page.facts == [second] && page.examined == 1 && page.next == Some(3));
    request = request
        .next_page(&page)
        .context("newest caller continuation")?;
    let page = fs.scan(request)?;
    ensure!(page.facts == [first] && page.examined == 1 && page.next == Some(1));
    request = request
        .next_page(&page)
        .context("oldest caller continuation")?;
    let page = fs.scan(request)?;
    ensure!(page.facts.is_empty() && page.examined == 0 && page.is_complete());
    Ok(())
}

#[test]
fn directional_candidate_budget_stops_before_decoding_the_next_record() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("examined.redb"))?;
    let fs = store.fact_store()?;
    for position in 0..3 {
        fs.append(fact(1, position, true))?;
    }
    replace_bytes(&fs, 1, b"invalid JSON")?;
    for order in [FactOrder::Forward, FactOrder::Reverse] {
        for process in [None, Some(ProcessId::new(1))] {
            let mut request = query(8, usize::MAX)?;
            request.order = order;
            request.process = process;
            request.max_examined = NonZeroUsize::MIN;
            let page = fs.scan(request)?;
            let position = match order {
                FactOrder::Forward => 0,
                FactOrder::Reverse => 2,
            };
            ensure!(page.facts == [fact(1, position, true)] && page.examined == 1);
            request = request
                .next_page(&page)
                .context("candidate budget continuation")?;
            ensure!(fs.scan(request).is_err());
        }
    }
    Ok(())
}

#[test]
fn exact_byte_budget_stops_before_the_next_record() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let first = fact(1, 0, true);
    let second = fact(1, 1, true);
    let third = fact(1, 2, true);
    let bytes = serde_json::to_vec(&first)?.len() + serde_json::to_vec(&second)?.len();
    fs.append(first.clone())?;
    fs.append(second.clone())?;
    fs.append(third.clone())?;

    let mut request = query(usize::MAX, bytes)?;
    let page = fs.scan(request)?;
    ensure!(page.facts == [first, second]);
    ensure!(page.encoded_bytes == bytes && page.next == Some(2) && page.end == 3);
    ensure!(page.examined == 3);
    request = request
        .next_page(&page)
        .context("byte budget continuation")?;
    let page = fs.scan(request)?;
    ensure!(page.facts == [third] && page.is_complete());
    Ok(())
}

#[test]
fn oversized_record_can_be_retried_without_skipping_its_slot() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let first = fact(1, 0, true);
    let mut large = fact(1, 1, true);
    large.input = Value::string("x".repeat(4096));
    let first_size = serde_json::to_vec(&first)?.len();
    let large_size = serde_json::to_vec(&large)?.len();
    fs.append(first.clone())?;
    fs.append(large.clone())?;

    for process in [None, Some(ProcessId::new(1))] {
        let mut request = query(8, first_size)?;
        request.process = process;
        let page = fs.scan(request)?;
        ensure!(page.facts.as_slice() == std::slice::from_ref(&first));
        ensure!(page.next == Some(1) && page.encoded_bytes == first_size);
        ensure!(page.examined == 2);
        request = request.next_page(&page).context("oversized continuation")?;
        let Err(error) = fs.scan(request) else {
            return Err(anyhow!("oversized first record was accepted"));
        };
        ensure!(error.0.contains("slot 1") && error.0.contains("encoded byte limit"));
        request.max_encoded_bytes = query(8, large_size)?.max_encoded_bytes;
        let page = fs.scan(request)?;
        ensure!(page.facts.as_slice() == std::slice::from_ref(&large));
        ensure!(page.encoded_bytes == large_size && page.is_complete());
    }
    Ok(())
}

#[test]
fn reverse_byte_budget_retries_an_oversized_candidate_at_slot_zero() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("reverse-bytes.redb"))?;
    let fs = store.fact_store()?;
    let mut large = fact(1, 0, true);
    large.input = Value::string("x".repeat(4096));
    let last = fact(1, 1, true);
    let last_size = serde_json::to_vec(&last)?.len();
    let large_size = serde_json::to_vec(&large)?.len();
    fs.append(large.clone())?;
    fs.append(last.clone())?;
    for process in [None, Some(ProcessId::new(1))] {
        let mut request = query(8, last_size)?;
        request.order = FactOrder::Reverse;
        request.process = process;
        let page = fs.scan(request)?;
        ensure!(page.facts.as_slice() == std::slice::from_ref(&last));
        ensure!(page.examined == 2 && page.next == Some(1) && page.end == 2);
        request = request
            .next_page(&page)
            .context("reverse byte continuation")?;
        let error = fs.scan(request).err().context("oversized oldest record")?;
        ensure!(error.0.contains("slot 0") && error.0.contains("encoded byte limit"));
        request.max_encoded_bytes = NonZeroUsize::new(large_size).context("encoded size")?;
        let page = fs.scan(request)?;
        ensure!(page.facts.as_slice() == std::slice::from_ref(&large));
        ensure!(page.encoded_bytes == large_size && page.examined == 1 && page.is_complete());
    }
    Ok(())
}

#[test]
fn byte_budget_uses_stored_encoding_and_is_checked_before_decoding() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let record = fact(1, 0, true);
    fs.append(record.clone())?;
    let compact_size = serde_json::to_vec(&record)?.len();
    let pretty = serde_json::to_vec_pretty(&record)?;
    ensure!(pretty.len() > compact_size);
    replace_bytes(&fs, 0, &pretty)?;
    ensure!(fs.scan(query(1, compact_size)?).is_err());
    let page = fs.scan(query(1, pretty.len())?)?;
    ensure!(page.facts == [record] && page.encoded_bytes == pretty.len());

    replace_bytes(&fs, 0, b"not JSON")?;
    let Err(error) = fs.scan(query(1, 1)?) else {
        return Err(anyhow!("oversized malformed record was accepted"));
    };
    ensure!(error.0.contains("encoded byte limit"));
    let Err(error) = fs.scan(query(1, 64)?) else {
        return Err(anyhow!("malformed record was accepted"));
    };
    ensure!(!error.0.contains("encoded byte limit"));
    Ok(())
}

#[test]
fn captured_append_bound_excludes_later_appends() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let other = store.fact_store()?;
    fs.append(fact(1, 0, true))?;
    let second = fact(1, 1, true);
    fs.append(second.clone())?;
    let mut request = query(1, usize::MAX)?;
    let page = fs.scan(request)?;
    ensure!(page.next == Some(1) && page.end == 2);
    let third = fact(1, 2, true);
    other.append(third.clone())?;

    request = request.next_page(&page).context("frozen continuation")?;
    let page = fs.scan(request)?;
    ensure!(page.facts == [second] && page.end == 2 && page.is_complete());
    ensure!(request.next_page(&page).is_none());
    request.from = page.end;
    ensure!(fs.scan(request)?.facts.is_empty());
    request.before = None;
    let page = fs.scan(request)?;
    ensure!(page.facts == [third] && page.end == 3 && page.is_complete());
    Ok(())
}

#[test]
fn completion_changes_an_existing_slot_without_changing_the_append_bound() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let first = fact(1, 0, false);
    let second = fact(1, 1, false);
    fs.append(first.clone())?;
    fs.append(second)?;
    let mut request = query(1, usize::MAX)?;
    let page = fs.scan(request)?;
    ensure!(page.facts == [first] && page.end == 2);
    fs.complete(fact(1, 0, true))?;
    let completed = fact(1, 1, true);
    fs.complete(completed.clone())?;
    ensure!(fs.cursor() == 2);

    request = request.next_page(&page).context("updated continuation")?;
    let page = fs.scan(request)?;
    ensure!(page.facts == [completed] && page.end == 2 && page.is_complete());
    request.from = 0;
    let page = fs.scan(request)?;
    ensure!(page.facts == [fact(1, 0, true)] && page.end == 2);
    Ok(())
}

#[test]
fn scan_bound_comes_from_persisted_metadata_even_when_cached_cursor_is_stale() -> anyhow::Result<()>
{
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    fs.append(fact(1, 0, true))?;
    fs.append(fact(1, 1, true))?;
    for stale in [0, u64::MAX] {
        fs.cursor.store(stale, Ordering::Relaxed);
        let page = fs.scan(query(8, usize::MAX)?)?;
        ensure!(page.end == 2 && page.is_complete() && page.facts.len() == 2);
    }
    Ok(())
}

#[test]
fn empty_exhausted_filtered_and_reversed_intervals() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let mut request = query(usize::MAX, usize::MAX)?;
    let page = fs.scan(request)?;
    ensure!(page.facts.is_empty() && page.end == 0 && page.is_complete());
    fs.append(fact(1, 0, true))?;
    fs.append(fact(1, 1, true))?;
    request.before = Some(u64::MAX);
    request.process = Some(ProcessId::new(u64::MAX));
    let page = fs.scan(request)?;
    ensure!(page.facts.is_empty() && page.end == 2 && page.is_complete());
    ensure!(page.examined == 0);
    request.process = None;
    request.from = 2;
    let page = fs.scan(request)?;
    ensure!(page.facts.is_empty() && page.is_complete());
    request.from = 3;
    ensure!(fs.scan(request).is_err());
    request.from = 2;
    request.before = Some(1);
    ensure!(fs.scan(request).is_err());
    request.from = 1;
    let page = fs.scan(request)?;
    ensure!(page.facts.is_empty() && page.is_complete() && page.end == 1);
    request.from = 0;
    request.before = Some(0);
    let page = fs.scan(request)?;
    ensure!(page.facts.is_empty() && page.end == 0 && page.is_complete());
    Ok(())
}

#[test]
fn point_lookup_observes_pending_and_completed_records() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let pending = fact(1, 0, false);
    ensure!(fs.get(pending.id)?.is_none());
    fs.append(pending.clone())?;
    ensure!(fs.get(pending.id)?.as_ref() == Some(&pending));
    let completed = fact(1, 0, true);
    fs.complete(completed.clone())?;
    ensure!(fs.get(completed.id)?.as_ref() == Some(&completed));
    let other = fact(2, 0, false);
    ensure!(fs.get(other.id)?.is_none());
    Ok(())
}

#[test]
fn bounded_lookup_checks_stored_size_before_decoding_and_observes_growth() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("lookup-bytes.redb"))?;
    let fs = store.fact_store()?;
    let pending = fact(1, 0, false);
    ensure!(fs.get_bounded(pending.id, NonZeroUsize::MIN)?.is_none());
    fs.append(pending.clone())?;
    let compact_size = serde_json::to_vec(&pending)?.len();
    let pretty = serde_json::to_vec_pretty(&pending)?;
    replace_bytes(&fs, 0, &pretty)?;
    let compact_limit = NonZeroUsize::new(compact_size).context("compact size")?;
    ensure!(fs.get_bounded(pending.id, compact_limit).is_err());
    let pretty_limit = NonZeroUsize::new(pretty.len()).context("pretty size")?;
    ensure!(fs.get_bounded(pending.id, pretty_limit)?.as_ref() == Some(&pending));

    let mut completed = fact(1, 0, true);
    completed.input = Value::string("x".repeat(4096));
    fs.complete(completed.clone())?;
    ensure!(fs.get_bounded(pending.id, pretty_limit).is_err());
    let completed_limit =
        NonZeroUsize::new(serde_json::to_vec(&completed)?.len()).context("completed size")?;
    ensure!(fs.get_bounded(pending.id, completed_limit)?.as_ref() == Some(&completed));

    replace_bytes(&fs, 0, b"invalid JSON")?;
    let error = fs
        .get_bounded(pending.id, NonZeroUsize::MIN)
        .err()
        .context("oversized lookup")?;
    ensure!(error.0.contains("encoded byte limit"));
    let error = fs
        .get_bounded(pending.id, NonZeroUsize::MAX)
        .err()
        .context("malformed lookup")?;
    ensure!(!error.0.contains("encoded byte limit"));
    Ok(())
}

#[test]
fn scoped_lookup_filters_before_checking_size_or_decoding() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("scoped-lookup.redb"))?;
    let fs = store.fact_store()?;
    let mut record = fact(1, 0, true);
    record.caller = ProcessId::new(2);
    record.input = Value::string("x".repeat(4096));
    fs.append(record.clone())?;

    ensure!(matches!(
        fs.lookup(FactLookup {
            id: fact(1, 1, true).id,
            process: Some(record.caller),
            max_encoded_bytes: NonZeroUsize::MIN,
        })?,
        FactLookupResult::Missing
    ));
    for process in [None, Some(record.caller)] {
        let error = fs
            .lookup(FactLookup {
                id: record.id,
                process,
                max_encoded_bytes: NonZeroUsize::MIN,
            })
            .err()
            .context("oversized matching record")?;
        ensure!(error.0.contains("encoded byte limit"));
        ensure!(matches!(
            fs.lookup(FactLookup {
                id: record.id,
                process,
                max_encoded_bytes: NonZeroUsize::MAX,
            })?,
            FactLookupResult::Found(found) if found == record
        ));
    }
    for bytes in [serde_json::to_vec(&record)?, b"invalid JSON".to_vec()] {
        replace_bytes(&fs, 0, &bytes)?;
        for max_encoded_bytes in [NonZeroUsize::MIN, NonZeroUsize::MAX] {
            ensure!(matches!(
                fs.lookup(FactLookup {
                    id: record.id,
                    process: Some(record.id.process),
                    max_encoded_bytes,
                })?,
                FactLookupResult::FilteredOut
            ));
        }
    }
    let error = fs
        .lookup(FactLookup {
            id: record.id,
            process: Some(record.caller),
            max_encoded_bytes: NonZeroUsize::MAX,
        })
        .err()
        .context("malformed matching record")?;
    ensure!(!error.0.contains("encoded byte limit"));
    Ok(())
}

#[test]
fn scoped_lookup_preserves_the_full_process_id_range() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("scoped-process-ids.redb"))?;
    let fs = store.fact_store()?;
    let processes = [0, 1, 1_u64 << 63, u64::MAX].map(ProcessId::new);
    for (position, caller) in [0, 1, 2, 3].into_iter().zip(processes) {
        let mut record = fact(10, position, true);
        record.caller = caller;
        fs.append(record.clone())?;
        for process in processes {
            match fs.lookup(FactLookup {
                id: record.id,
                process: Some(process),
                max_encoded_bytes: NonZeroUsize::MAX,
            })? {
                FactLookupResult::Found(found) => ensure!(process == caller && found == record),
                FactLookupResult::FilteredOut => ensure!(process != caller),
                FactLookupResult::Missing => return Err(anyhow!("indexed fact was missing")),
            }
        }
    }
    Ok(())
}

#[test]
fn dangling_indexes_are_errors_instead_of_missing_records() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let record = fact(1, 0, false);
    let id = record.id;
    fs.append(record)?;
    let txn = fs.db.begin_write()?;
    txn.open_table(FACTS_TABLE)?.remove(0)?;
    txn.commit()?;

    ensure!(fs.get(id).is_err());
    for process in [None, Some(ProcessId::new(1)), Some(ProcessId::new(2))] {
        let error = fs
            .lookup(FactLookup {
                id,
                process,
                max_encoded_bytes: NonZeroUsize::MIN,
            })
            .err()
            .context("dangling operation index")?;
        ensure!(error.0.contains("operation index points to missing slot 0"));
    }
    let mut request = query(8, usize::MAX)?;
    ensure!(fs.scan(request).is_err());
    request.process = Some(ProcessId::new(1));
    ensure!(fs.scan(request).is_err());
    ensure!(fs.facts_of(ProcessId::new(1)).is_err());
    ensure!(fs.append(fact(1, 0, false)).is_err());
    ensure!(fs.complete(fact(1, 0, true)).is_err());
    ensure!(fs.cursor() == 1);
    let txn = fs.db.begin_read()?;
    ensure!(txn.open_table(FACTS_TABLE)?.get(0)?.is_none());
    Ok(())
}

#[test]
fn global_scans_reject_missing_first_middle_and_last_slots() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    for missing in [0, 1, 2] {
        let store = RedbStore::open(dir.path().join(format!("missing-{missing}.redb")))?;
        let fs = store.fact_store()?;
        for position in 0..3 {
            fs.append(fact(1, position, true))?;
        }
        let txn = fs.db.begin_write()?;
        txn.open_table(FACTS_TABLE)?.remove(missing)?;
        txn.commit()?;

        for order in [FactOrder::Forward, FactOrder::Reverse] {
            let mut request = query(8, usize::MAX)?;
            request.order = order;
            let Err(error) = fs.scan(request) else {
                return Err(anyhow!("global scan ignored missing slot {missing}"));
            };
            ensure!(error.0.contains(&format!("missing slot {missing}")));
        }
    }
    Ok(())
}

#[test]
fn global_scan_rejects_a_head_beyond_the_primary_table_tail() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    for retained in [0, 2] {
        let store = RedbStore::open(dir.path().join(format!("tail-{retained}.redb")))?;
        let fs = store.fact_store()?;
        for position in 0..retained {
            fs.append(fact(1, position, true))?;
        }
        let txn = fs.db.begin_write()?;
        txn.open_table(FACT_META_TABLE)?
            .insert(NEXT_CURSOR_KEY, 3)?;
        txn.commit()?;

        for order in [FactOrder::Forward, FactOrder::Reverse] {
            let mut request = query(8, usize::MAX)?;
            request.order = order;
            let Err(error) = fs.scan(request) else {
                return Err(anyhow!("global scan ignored a truncated append interval"));
            };
            let missing = match order {
                FactOrder::Forward => retained,
                FactOrder::Reverse => 2,
            };
            ensure!(error.0.contains(&format!("missing slot {missing}")));
        }
    }
    Ok(())
}

#[test]
fn continuation_reports_a_gap_after_a_valid_bounded_page() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    for position in 0..3 {
        fs.append(fact(1, position, true))?;
    }
    let txn = fs.db.begin_write()?;
    txn.open_table(FACTS_TABLE)?.remove(1)?;
    txn.commit()?;

    for order in [FactOrder::Forward, FactOrder::Reverse] {
        let mut request = query(1, usize::MAX)?;
        request.order = order;
        let first = fs.scan(request)?;
        let (position, next) = match order {
            FactOrder::Forward => (0, 1),
            FactOrder::Reverse => (2, 2),
        };
        ensure!(first.facts == [fact(1, position, true)] && first.next == Some(next));
        ensure!(first.end == 3);
        request = request.next_page(&first).context("gap continuation")?;
        let Err(error) = fs.scan(request) else {
            return Err(anyhow!("continuation skipped missing slot 1"));
        };
        ensure!(error.0.contains("missing slot 1"));

        request.from = 0;
        request.before = Some(1);
        let bounded = fs.scan(request)?;
        ensure!(bounded.facts == [fact(1, 0, true)] && bounded.is_complete());
    }
    Ok(())
}

#[test]
fn mismatched_operation_index_is_an_error() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let first = fact(1, 0, false);
    let first_id = first.id;
    let second = fact(1, 1, true);
    let first_bytes = serde_json::to_vec(&first)?;
    let second_bytes = serde_json::to_vec(&second)?;
    fs.append(first)?;
    fs.append(second.clone())?;
    let txn = fs.db.begin_write()?;
    txn.open_table(FACT_INDEX_TABLE)?
        .insert(first_id.to_bytes().as_slice(), 1)?;
    txn.commit()?;

    ensure!(fs.get(first_id).is_err());
    ensure!(fs.get_bounded(first_id, NonZeroUsize::MAX).is_err());
    let error = fs
        .lookup(FactLookup {
            id: first_id,
            process: Some(second.caller),
            max_encoded_bytes: NonZeroUsize::MAX,
        })
        .err()
        .context("mismatched operation index")?;
    ensure!(
        error
            .0
            .contains("operation index does not match record at slot 1")
    );
    ensure!(fs.append(fact(1, 0, false)).is_err());
    ensure!(fs.complete(fact(1, 0, true)).is_err());
    ensure!(fs.cursor() == 2);
    ensure!(fs.get(second.id)?.as_ref() == Some(&second));
    let txn = fs.db.begin_read()?;
    let table = txn.open_table(FACTS_TABLE)?;
    ensure!(table.get(0)?.context("first record missing")?.value() == first_bytes);
    ensure!(table.get(1)?.context("second record missing")?.value() == second_bytes);
    Ok(())
}

#[test]
fn mismatched_process_index_slot_is_an_error() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    fs.append(fact(1, 0, true))?;
    fs.append(fact(1, 1, true))?;
    let txn = fs.db.begin_write()?;
    let key = RedbFactStore::process_key(ProcessId::new(1), 0);
    txn.open_table(FACT_PROCESS_INDEX_TABLE)?
        .insert(key.as_str(), 1)?;
    txn.commit()?;

    let error = fs
        .lookup(FactLookup {
            id: fact(1, 0, true).id,
            process: Some(ProcessId::new(1)),
            max_encoded_bytes: NonZeroUsize::MIN,
        })
        .err()
        .context("mismatched process index slot")?;
    ensure!(error.0.contains("process index key") && error.0.contains("does not match slot 1"));
    ensure!(fs.get(fact(1, 0, true).id)?.is_some());
    let mut request = query(8, usize::MAX)?;
    request.process = Some(ProcessId::new(1));
    for order in [FactOrder::Forward, FactOrder::Reverse] {
        request.order = order;
        ensure!(fs.scan(request).is_err());
    }
    ensure!(fs.facts_of(ProcessId::new(1)).is_err());
    Ok(())
}

#[test]
fn mismatched_process_index_caller_is_an_error() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let mut record = fact(1, 0, true);
    fs.append(record.clone())?;
    record.caller = ProcessId::new(2);
    replace_bytes(&fs, 0, &serde_json::to_vec(&record)?)?;

    let error = fs
        .lookup(FactLookup {
            id: record.id,
            process: Some(ProcessId::new(1)),
            max_encoded_bytes: NonZeroUsize::MAX,
        })
        .err()
        .context("mismatched process index caller")?;
    ensure!(
        error
            .0
            .contains("process index does not match record at slot 0")
    );
    let mut request = query(8, usize::MAX)?;
    request.process = Some(ProcessId::new(1));
    for order in [FactOrder::Forward, FactOrder::Reverse] {
        request.order = order;
        ensure!(fs.scan(request).is_err());
    }
    ensure!(fs.facts_of(ProcessId::new(1)).is_err());
    Ok(())
}

#[test]
fn completion_updates_process_index_membership() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let pending = fact(1, 0, false);
    fs.append(pending.clone())?;
    ensure!(matches!(
        fs.lookup(FactLookup {
            id: pending.id,
            process: Some(pending.caller),
            max_encoded_bytes: NonZeroUsize::MAX,
        })?,
        FactLookupResult::Found(found) if found == pending
    ));
    ensure!(matches!(
        fs.lookup(FactLookup {
            id: pending.id,
            process: Some(ProcessId::new(u64::MAX)),
            max_encoded_bytes: NonZeroUsize::MIN,
        })?,
        FactLookupResult::FilteredOut
    ));
    let mut completed = fact(1, 0, true);
    completed.caller = ProcessId::new(u64::MAX);
    fs.complete(completed.clone())?;

    ensure!(matches!(
        fs.lookup(FactLookup {
            id: pending.id,
            process: Some(pending.caller),
            max_encoded_bytes: NonZeroUsize::MIN,
        })?,
        FactLookupResult::FilteredOut
    ));
    ensure!(matches!(
        fs.lookup(FactLookup {
            id: completed.id,
            process: Some(completed.caller),
            max_encoded_bytes: NonZeroUsize::MAX,
        })?,
        FactLookupResult::Found(found) if found == completed
    ));
    let mut request = query(8, usize::MAX)?;
    request.process = Some(ProcessId::new(1));
    ensure!(fs.scan(request)?.facts.is_empty());
    ensure!(fs.facts_of(ProcessId::new(1))?.is_empty());
    request.process = Some(completed.caller);
    let page = fs.scan(request)?;
    ensure!(page.facts.as_slice() == std::slice::from_ref(&completed));
    ensure!(page.end == 1 && page.is_complete());
    ensure!(fs.facts_of(completed.caller)? == [completed]);
    Ok(())
}

#[test]
fn unsupported_schema_versions_are_rejected_without_rewriting_records() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let mut record = fact(1, 0, false);
    fs.append(record.clone())?;
    for version in [0, Fact::SCHEMA_VERSION - 1, Fact::SCHEMA_VERSION + 1] {
        record.schema_version = version;
        let bytes = serde_json::to_vec(&record)?;
        replace_bytes(&fs, 0, &bytes)?;
        let error = fs
            .get(record.id)
            .err()
            .context("unsupported schema accepted")?;
        ensure!(
            error
                .to_string()
                .contains("unsupported Fact schema_version")
        );
        for process in [None, Some(record.caller)] {
            let mut request = query(8, usize::MAX)?;
            request.process = process;
            ensure!(fs.scan(request).is_err());
        }
        ensure!(fs.facts_of(record.caller).is_err());
        ensure!(fs.all_facts().is_err());
        ensure!(fs.append(fact(1, 0, false)).is_err());
        ensure!(fs.complete(fact(1, 0, true)).is_err());
        let txn = fs.db.begin_read()?;
        let table = txn.open_table(FACTS_TABLE)?;
        ensure!(table.get(0)?.context("stored record was deleted")?.value() == bytes);
    }
    Ok(())
}

#[test]
fn persisted_facts_cannot_omit_provenance() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let record = fact(1, 0, true);
    fs.append(record.clone())?;
    let mut malformed = serde_json::to_value(&record)?;
    malformed
        .as_object_mut()
        .context("fact is not an object")?
        .remove("taint");
    let bytes = serde_json::to_vec(&malformed)?;
    replace_bytes(&fs, 0, &bytes)?;
    ensure!(fs.get(record.id).is_err());
    ensure!(fs.scan(query(1, usize::MAX)?).is_err());
    ensure!(fs.all_facts().is_err());
    ensure!(fs.append(record).is_err());
    ensure!(fs.complete(fact(1, 0, true)).is_err());
    let txn = fs.db.begin_read()?;
    let table = txn.open_table(FACTS_TABLE)?;
    ensure!(table.get(0)?.context("stored record was deleted")?.value() == bytes);
    Ok(())
}

#[test]
fn cursor_exhaustion_never_wraps_and_preserves_existing_records() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let store = RedbStore::open(dir.path().join("facts.redb"))?;
    let fs = store.fact_store()?;
    let last_slot = u64::MAX - 1;
    let txn = fs.db.begin_write()?;
    txn.open_table(FACT_META_TABLE)?
        .insert(NEXT_CURSOR_KEY, last_slot)?;
    txn.commit()?;
    let pending = fact(1, 0, false);
    ensure!(fs.append(pending.clone())? == last_slot);
    ensure!(fs.cursor() == u64::MAX);
    ensure!(matches!(
        fs.lookup(FactLookup {
            id: pending.id,
            process: Some(pending.caller),
            max_encoded_bytes: NonZeroUsize::MAX,
        })?,
        FactLookupResult::Found(found) if found == pending
    ));

    for order in [FactOrder::Forward, FactOrder::Reverse] {
        for process in [None, Some(pending.caller)] {
            let mut request = query(1, usize::MAX)?;
            request.order = order;
            request.from = last_slot;
            request.process = process;
            let page = fs.scan(request)?;
            ensure!(page.facts.as_slice() == std::slice::from_ref(&pending));
            ensure!(page.end == u64::MAX && page.is_complete());
            ensure!(request.next_page(&page).is_none());
            request.from = page.end;
            ensure!(fs.scan(request)?.facts.is_empty());
        }
    }
    ensure!(fs.append(fact(1, 1, false)).is_err());
    ensure!(fs.complete(fact(1, 1, true)).is_err());
    ensure!(fs.get(fact(1, 1, true).id)?.is_none());
    ensure!(fs.append(pending)? == last_slot);
    let completed = fact(1, 0, true);
    fs.complete(completed.clone())?;
    ensure!(fs.get(completed.id)?.as_ref() == Some(&completed));
    ensure!(fs.cursor() == u64::MAX);
    ensure!(fs.all_facts()? == [completed]);
    Ok(())
}
