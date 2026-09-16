//! Indexed fact reads with record, byte and examined-candidate budgets.

use super::{NEXT_CURSOR_KEY, RedbFactStore, ensure_fact_schema, fact_err};
use crate::{FACT_INDEX_TABLE, FACT_META_TABLE, FACT_PROCESS_INDEX_TABLE, FACTS_TABLE};
use redb::ReadableDatabase;
use std::num::NonZeroUsize;
use xolotl_kernel::{FactError, FactLookup, FactLookupResult, FactOrder, FactPage, FactQuery};
use xolotl_types::{Fact, OperationId, ProcessId};

impl RedbFactStore {
    pub(super) fn scan_page(&self, query: FactQuery) -> Result<FactPage, FactError> {
        let txn = self.db.begin_read().map_err(fact_err)?;
        // The append bound and records must come from the same committed view.
        let meta = txn.open_table(FACT_META_TABLE).map_err(fact_err)?;
        let head = meta
            .get(NEXT_CURSOR_KEY)
            .map_err(fact_err)?
            .map(|value| value.value())
            .ok_or_else(|| FactError("fact cursor metadata missing".into()))?;
        let end = query.before.unwrap_or(head).min(head);
        if query.from > end {
            return Err(FactError("fact scan starts after its end".into()));
        }
        let mut page = FactPage {
            facts: Vec::new(),
            next: (query.from != end).then_some(match query.order {
                FactOrder::Forward => query.from,
                FactOrder::Reverse => end,
            }),
            end,
            encoded_bytes: 0,
            examined: 0,
        };
        if page.next.is_none() {
            return Ok(page);
        }

        let facts = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        if let Some(process) = query.process {
            let index = txn.open_table(FACT_PROCESS_INDEX_TABLE).map_err(fact_err)?;
            let from_key = Self::process_key(process, query.from);
            let end_key = Self::process_key(process, end);
            let mut rows = index
                .range(from_key.as_str()..end_key.as_str())
                .map_err(fact_err)?;
            while let Some(item) = next_row(&mut rows, query.order) {
                let (key, slot) = item.map_err(fact_err)?;
                let slot = slot.value();
                Self::validate_process_index(key.value(), process, slot)?;
                let bytes = facts.get(slot).map_err(fact_err)?.ok_or_else(|| {
                    FactError(format!("fact process index points to missing slot {slot}"))
                })?;
                if consume_page_fact(&query, &mut page, slot, bytes.value())? {
                    return Ok(page);
                }
            }
        } else {
            let mut rows = facts.range(query.from..end).map_err(fact_err)?;
            while let Some(item) = next_row(&mut rows, query.order) {
                let (slot, bytes) = item.map_err(fact_err)?;
                let slot = slot.value();
                let expected = next_slot(&query, &page);
                if expected != Some(slot) {
                    return Err(missing_slot(expected.unwrap_or(slot)));
                }
                if consume_page_fact(&query, &mut page, slot, bytes.value())? {
                    return Ok(page);
                }
            }
            if let Some(slot) = next_slot(&query, &page) {
                return Err(missing_slot(slot));
            }
        }
        page.next = None;
        Ok(page)
    }

    pub(super) fn lookup_record(&self, query: FactLookup) -> Result<FactLookupResult, FactError> {
        let txn = self.db.begin_read().map_err(fact_err)?;
        let index = txn.open_table(FACT_INDEX_TABLE).map_err(fact_err)?;
        let Some(slot) = index
            .get(query.id.to_bytes().as_slice())
            .map_err(fact_err)?
        else {
            return Ok(FactLookupResult::Missing);
        };
        let slot = slot.value();
        let facts = txn.open_table(FACTS_TABLE).map_err(fact_err)?;
        let bytes = facts.get(slot).map_err(fact_err)?.ok_or_else(|| {
            FactError(format!(
                "fact operation index points to missing slot {slot}"
            ))
        })?;
        // Check current caller membership before charging or decoding the record.
        if let Some(process) = query.process {
            let process_index = txn.open_table(FACT_PROCESS_INDEX_TABLE).map_err(fact_err)?;
            let key = Self::process_key(process, slot);
            let Some(indexed_slot) = process_index.get(key.as_str()).map_err(fact_err)? else {
                return Ok(FactLookupResult::FilteredOut);
            };
            Self::validate_process_index(&key, process, indexed_slot.value())?;
        }
        if bytes.value().len() > query.max_encoded_bytes.get() {
            return Err(byte_limit_error(slot, query.max_encoded_bytes));
        }
        let fact = decode_indexed_fact(bytes.value(), slot, query.id, query.process)?;
        Ok(FactLookupResult::Found(fact))
    }
}

fn next_row<I: DoubleEndedIterator>(rows: &mut I, order: FactOrder) -> Option<I::Item> {
    match order {
        FactOrder::Forward => rows.next(),
        FactOrder::Reverse => rows.next_back(),
    }
}

fn next_slot(query: &FactQuery, page: &FactPage) -> Option<u64> {
    match query.order {
        FactOrder::Forward => page.next,
        FactOrder::Reverse => page.next.and_then(|before| before.checked_sub(1)),
    }
}

fn missing_slot(slot: u64) -> FactError {
    FactError(format!("fact append interval is missing slot {slot}"))
}

fn byte_limit_error(slot: u64, max_encoded_bytes: NonZeroUsize) -> FactError {
    FactError(format!(
        "fact at slot {slot} exceeds encoded byte limit {max_encoded_bytes}"
    ))
}

pub(super) fn decode_fact(
    bytes: &[u8],
    slot: u64,
    process: Option<ProcessId>,
) -> Result<Fact, FactError> {
    let fact: Fact = serde_json::from_slice(bytes).map_err(fact_err)?;
    ensure_fact_schema(&fact)?;
    if process.is_some_and(|process| process != fact.caller) {
        return Err(FactError(format!(
            "fact process index does not match record at slot {slot}"
        )));
    }
    Ok(fact)
}

pub(super) fn decode_indexed_fact(
    bytes: &[u8],
    slot: u64,
    id: OperationId,
    process: Option<ProcessId>,
) -> Result<Fact, FactError> {
    let fact = decode_fact(bytes, slot, process)?;
    if fact.id != id {
        return Err(FactError(format!(
            "fact operation index does not match record at slot {slot}"
        )));
    }
    Ok(fact)
}

fn consume_page_fact(
    query: &FactQuery,
    page: &mut FactPage,
    slot: u64,
    bytes: &[u8],
) -> Result<bool, FactError> {
    page.examined += 1;
    // Charge the stored encoding before allocating a decoded record. An oversized
    // candidate was examined but remains inside the continuation's interval.
    if bytes.len() > query.max_encoded_bytes.get() - page.encoded_bytes {
        if page.facts.is_empty() {
            return Err(byte_limit_error(slot, query.max_encoded_bytes));
        }
        page.next = Some(match query.order {
            FactOrder::Forward => slot,
            FactOrder::Reverse => slot + 1,
        });
        return Ok(true);
    }
    let fact = decode_fact(bytes, slot, query.process)?;
    page.encoded_bytes += bytes.len();
    page.facts.push(fact);
    page.next = match query.order {
        FactOrder::Forward => (slot + 1 < page.end).then_some(slot + 1),
        FactOrder::Reverse => (slot > query.from).then_some(slot),
    };
    Ok(page.next.is_none()
        || page.facts.len() == query.limit.get()
        || page.examined == query.max_examined.get())
}
