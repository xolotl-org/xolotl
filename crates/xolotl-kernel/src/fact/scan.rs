//! Directional, bounded reads of a Fact append interval.

use super::FactError;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use xolotl_types::{Fact, ProcessId};

/// Traversal order within an append interval, independent of event timestamps.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactOrder {
    /// Oldest append slot first.
    Forward,
    /// Newest append slot first.
    Reverse,
}

/// A bounded read of the append interval `[from, before)`.
///
/// Each page captures `end = min(before.unwrap_or(head), head)` from the same
/// locked view or transaction as its records. Use [`Self::next_page`] to continue;
/// it excludes later appends in either direction. An empty page can still have a
/// continuation when its examination budget was spent on nonmatching candidates.
///
/// Append intervals do not freeze values or caller membership: completion can
/// replace an existing record between pages. Quiesce writers for a stable
/// classification. These cursors do not track incremental outcome updates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactQuery {
    /// First append slot in the interval, inclusive.
    pub from: u64,
    /// Exclusive upper bound, or `None` to capture the current store head.
    pub before: Option<u64>,
    /// Match only this caller, or all callers when absent. Filter before copying
    /// or decoding records and before charging either result limit.
    pub process: Option<ProcessId>,
    /// Read oldest or newest append slots first.
    pub order: FactOrder,
    /// Maximum number of matching records returned.
    pub limit: NonZeroUsize,
    /// Maximum storage candidates examined, including nonmatching memory slots
    /// and a matching record that does not fit the remaining byte budget.
    /// Indexed adapters need not visit unrelated callers. This limits candidate
    /// work, not wall time or the cost of examining an individual value.
    pub max_examined: NonZeroUsize,
    /// Maximum sum of record JSON encoding lengths, excluding page metadata and
    /// array framing. Encoded stores charge stored bytes; memory stores charge
    /// current serialization. This is not a Rust heap or RSS limit.
    /// An oversized first match errors; otherwise the unread match is retained
    /// in the continuation so it can be retried with a larger budget.
    pub max_encoded_bytes: NonZeroUsize,
}

impl FactQuery {
    /// Read forwards with explicit record and byte budgets. By default the
    /// examination budget equals the result limit; sparse filters can return
    /// empty pages that must still be continued.
    pub const fn new(limit: NonZeroUsize, max_encoded_bytes: NonZeroUsize) -> Self {
        Self {
            from: 0,
            before: None,
            process: None,
            order: FactOrder::Forward,
            limit,
            max_examined: limit,
            max_encoded_bytes,
        }
    }

    /// Continue a validated page with the same filters, direction and budgets.
    /// Reverse pages shrink their upper bound; `page.end` describes the current
    /// page's interval, not an immutable first-page head.
    pub fn next_page(self, page: &FactPage) -> Option<Self> {
        let next = page.next?;
        Some(match self.order {
            FactOrder::Forward => Self {
                from: next,
                before: Some(page.end),
                ..self
            },
            FactOrder::Reverse => Self {
                before: Some(next),
                ..self
            },
        })
    }
}

/// One bounded view of retained operation records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactPage {
    /// Matching records in the requested append order.
    pub facts: Vec<Fact>,
    /// Forward: next inclusive lower bound. Reverse: next exclusive upper bound.
    /// `None` means the interval was exhausted, even if no records matched.
    pub next: Option<u64>,
    /// Exclusive upper bound captured for this page's storage view.
    pub end: u64,
    /// Storage candidates examined, including filtered and byte-rejected candidates.
    pub examined: usize,
    /// Sum of record encoding lengths, measured as [`FactQuery::max_encoded_bytes`].
    pub encoded_bytes: usize,
}

impl FactPage {
    /// Whether this page exhausted its append interval.
    pub const fn is_complete(&self) -> bool {
        self.next.is_none()
    }

    pub(super) fn validate(&self, query: FactQuery) -> Result<(), FactError> {
        let count = u64::try_from(self.facts.len())
            .map_err(|error| FactError(format!("fact page count overflow: {error}")))?;
        let examined = u64::try_from(self.examined)
            .map_err(|error| FactError(format!("fact examination count overflow: {error}")))?;
        let consumed = match query.order {
            FactOrder::Forward => self.next.unwrap_or(self.end).checked_sub(query.from),
            FactOrder::Reverse => self.end.checked_sub(self.next.unwrap_or(query.from)),
        };
        if query.from > self.end
            || query.before.is_some_and(|end| self.end > end)
            || self
                .next
                .is_some_and(|next| next <= query.from || next >= self.end)
            || consumed.is_none_or(|slots| {
                slots < count
                    || (query.process.is_none() && slots != count)
                    || examined > slots.saturating_add(u64::from(self.next.is_some()))
            })
            || (self.next.is_some() && self.examined == 0)
            || self.facts.len() > self.examined
            || self.facts.len() > query.limit.get()
            || self.examined > query.max_examined.get()
            || self.encoded_bytes > query.max_encoded_bytes.get()
            || (self.encoded_bytes == 0) != self.facts.is_empty()
            || query
                .process
                .is_some_and(|process| self.facts.iter().any(|f| f.caller != process))
        {
            return Err(FactError("invalid fact scan page".into()));
        }
        Ok(())
    }
}

pub(super) fn scan_memory(
    facts: &[Fact],
    head: u64,
    query: FactQuery,
) -> Result<FactPage, FactError> {
    let end = query.before.unwrap_or(head).min(head);
    if query.from > end {
        return Err(FactError("fact scan starts after its end".into()));
    }
    let mut page = FactPage {
        facts: Vec::new(),
        next: None,
        end,
        examined: 0,
        encoded_bytes: 0,
    };
    let from = usize::try_from(query.from)
        .map_err(|error| FactError(format!("fact scan start overflow: {error}")))?;
    let before = usize::try_from(end)
        .map_err(|error| FactError(format!("fact scan end overflow: {error}")))?;
    if facts.get(from..before).is_none() {
        return Err(FactError("fact append interval is missing records".into()));
    }
    let mut slots = from..before;
    while page.examined < query.max_examined.get() && page.facts.len() < query.limit.get() {
        let slot = match query.order {
            FactOrder::Forward => slots.next(),
            FactOrder::Reverse => slots.next_back(),
        };
        let Some(slot) = slot else { break };
        page.examined += 1;
        let fact = &facts[slot];
        if query.process.is_some_and(|process| process != fact.caller) {
            continue;
        }
        let remaining = query.max_encoded_bytes.get() - page.encoded_bytes;
        let Some(size) = encoded_size(fact, remaining)? else {
            if page.facts.is_empty() {
                return Err(FactError(format!(
                    "fact at slot {slot} exceeds encoded byte limit {}",
                    query.max_encoded_bytes
                )));
            }
            page.next = Some(match query.order {
                FactOrder::Forward => slot as u64,
                FactOrder::Reverse => slot as u64 + 1,
            });
            return Ok(page);
        };
        page.encoded_bytes += size;
        page.facts.push(fact.clone());
    }
    if !slots.is_empty() {
        page.next = Some(match query.order {
            FactOrder::Forward => slots.start as u64,
            FactOrder::Reverse => slots.end as u64,
        });
    }
    Ok(page)
}

struct SizeWriter {
    size: usize,
    limit: usize,
    exceeded: bool,
}

impl Write for SizeWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.size {
            self.exceeded = true;
            return Err(io::Error::other("fact encoding exceeds byte limit"));
        }
        self.size += bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn encoded_size(fact: &Fact, limit: usize) -> Result<Option<usize>, FactError> {
    let mut writer = SizeWriter {
        size: 0,
        limit,
        exceeded: false,
    };
    match serde_json::to_writer(&mut writer, fact) {
        Ok(()) => Ok(Some(writer.size)),
        Err(_error) if writer.exceeded => Ok(None),
        Err(error) => Err(FactError(format!("fact encoding failed: {error}"))),
    }
}

#[cfg(test)]
mod tests;
