use crate::{StateCursor, StateHistoryEntry, StateObservation, StatePageLimits, StateResult};
use alloc::vec::Vec;
use core::future::Future;
use core::num::NonZeroUsize;
use xolotl_types::{Path, TaintSet};

/// Whether a State path participates in mutation history. The reserved
/// `state://vault/**` namespace only retains current values: credential
/// rotation must not leave older verifier material in the queryable journal.
/// Built-in backends apply this rule regardless of their history mode; custom
/// backends that expose history must preserve the same vault boundary.
pub fn history_retains_path(path: &Path) -> bool {
    path.scheme() != "state"
        || !path
            .segments()
            .first()
            .is_some_and(|segment| segment.as_str() == "vault")
}

/// A bounded history query in stable backend key order.
/// Each page is consistent; subsequent pages observe live state. Time bounds
/// are half-open (`from_millis..to_millis`); a reversed interval is invalid.
#[derive(Clone, Debug)]
pub struct StateHistoryQuery {
    /// Include mutations at this exact Path and its descendants, not textual
    /// prefix matches. Check keys before observing record content or provenance.
    pub path: Path,
    /// Inclusive lower timestamp bound, in milliseconds.
    pub from_millis: i64,
    /// Exclusive upper timestamp bound, in milliseconds.
    pub to_millis: i64,
    /// Backend continuation bound to this path, time interval, and retained
    /// history floor, or `None` to start its scan.
    pub cursor: Option<StateCursor>,
    /// Independent output and candidate-work budgets for this page.
    pub limits: StatePageLimits,
}

impl StateHistoryQuery {
    /// Start a history scan with default page limits and no continuation.
    /// Interval validation occurs when the backend executes the query.
    pub fn new(path: Path, from_millis: i64, to_millis: i64) -> Self {
        Self {
            path,
            from_millis,
            to_millis,
            cursor: None,
            limits: StatePageLimits::default(),
        }
    }
}

/// One history page, retaining the mutation's original taint.
#[derive(Clone, Debug)]
pub struct StateHistoryPage {
    /// Matching mutations in backend key order, with their original provenance.
    pub entries: Vec<StateHistoryEntry>,
    /// Sources of consumed in-scope records, including time-filtered rows, plus
    /// at most one admitted but unconsumed boundary row, observed only while byte
    /// budget remains. Out-of-scope candidates contribute no content or provenance.
    /// Before union, each row's key and
    /// lossless provenance metadata must fit the full page byte limit. An
    /// oversized row follows delivery of any consumed candidates as a partial
    /// page. Without consumption progress, rejection yields
    /// `RowTooLarge(provenance_observed = false)` without observing that header.
    /// Consumed provenance input is bounded by the page limit, plus at most one
    /// boundary's metadata bounded by that same limit, not an RSS bound.
    pub taint: TaintSet,
    /// Continue from this position; `None` ends the scan. An empty page may
    /// still have a continuation when its candidate-work or consumed-byte budget
    /// is exhausted. An admitted byte-boundary row contributes taint but remains
    /// unconsumed; this position precedes that row.
    /// Exact budget exhaustion stops before examining another row and includes
    /// no next-row sources. A continuation may precede a terminal empty page.
    pub next: Option<StateCursor>,
    /// Candidate records charged against this page's examined-record budget,
    /// including candidates excluded by path or timestamp filters.
    pub examined: usize,
    /// Backend-encoded bytes actually consumed: complete events and applicable
    /// key metadata for time-matching rows, or canonical keys and losslessly
    /// encoded provenance metadata for in-scope time-filtered rows, without
    /// traversing their payloads. Out-of-scope candidates and an observed but
    /// unconsumed boundary row contribute no bytes. Not a heap-residency measure.
    pub encoded_bytes: usize,
}

/// Historical reads independent of current state reads and writes. Protected
/// vault paths never enter the journal, even in the full retention mode.
pub trait StateHistory {
    /// Backend-owned state for one bounded history page; no `Send` or boxing
    /// requirement is imposed by this capability.
    type History<'a>: Future<Output = StateResult<StateHistoryPage>>
    where
        Self: 'a;
    /// Backend-owned state for a historical point read, which may replay history.
    type At<'a>: Future<Output = StateResult<StateObservation>>
    where
        Self: 'a;
    /// Read one consistent page for [`StateHistoryQuery`] under [`StatePageLimits`],
    /// with accounting, provenance, and continuation defined by [`StateHistoryPage`].
    /// Admission failure returns [`crate::StateError::RowTooLarge`] with
    /// stage-specific accounting and retry/skip positions in [`crate::StateRowTooLarge`].
    /// An invalid interval or continuation returns [`crate::StateError::InvalidQuery`].
    /// A lower bound preceding the backend's retention floor returns
    /// [`crate::StateError::HistoryTrimmed`]. A vault prefix returns
    /// [`crate::StateError::HistoryExcluded`].
    fn history<'a>(&'a self, query: &'a StateHistoryQuery) -> Self::History<'a>;
    /// Reconstruct a value and its provenance at the specified timestamp.
    /// If the first replayed event is Set, its replacement does not observe
    /// the prior baseline. Append and Delete require baseline provenance.
    /// Zero selects the current value. Replay work is backend-defined and may
    /// depend on the complete history of this path; use pages for bounded work.
    /// Nonzero reads of vault paths return [`crate::StateError::HistoryExcluded`].
    fn read_at<'a>(&'a self, path: &'a Path, at_millis: i64) -> Self::At<'a>;
}

/// Result of atomically folding old mutations into historical path baselines.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateHistoryTrim {
    /// Earliest timestamp for which historical operations remain valid.
    pub retained_from_millis: i64,
    /// Number of mutation records removed by this operation.
    pub removed_events: u64,
}

/// Caller-selected ceiling for one atomic trim, including backend-encoded input
/// records and index keys plus newly constructed path baselines. Exceeding either ceiling
/// leaves the floor and stored history unchanged. Small successive floor
/// advances can be used instead of one large transaction.
/// The first folded Set for a path replaces its baseline without reading,
/// decoding, or charging the prior baseline. Append and Delete depend on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateHistoryTrimLimits {
    /// Maximum removed mutation records.
    pub events: NonZeroUsize,
    /// Maximum combined encoded mutation and new baseline bytes.
    pub encoded_bytes: NonZeroUsize,
}

impl Default for StateHistoryTrimLimits {
    fn default() -> Self {
        Self {
            events: NonZeroUsize::MIN.saturating_add(4095),
            encoded_bytes: NonZeroUsize::MIN.saturating_add(16 * 1024 * 1024 - 1),
        }
    }
}

/// Optional maintenance capability for an explicitly retained history.
///
/// `trim_before(floor)` folds mutations at timestamps strictly less than
/// `floor` into exact-path value and provenance baselines in the same commit
/// that removes those mutations. The floor only advances. Historical reads and
/// history queries beginning before it return `HistoryTrimmed`, while current
/// reads are unchanged. A trim invalidates previously issued history cursors;
/// it does not affect current-state query cursors or live subscriptions.
pub trait StateHistoryRetention {
    /// Backend-owned future for reading the current global floor.
    type Floor<'a>: Future<Output = StateResult<i64>>
    where
        Self: 'a;
    /// Backend-owned future for a trim operation.
    type Trim<'a>: Future<Output = StateResult<StateHistoryTrim>>
    where
        Self: 'a;

    /// Return `i64::MIN` if this history has never been trimmed.
    fn retained_from(&self) -> Self::Floor<'_>;

    /// Retain mutation records at or after `floor` and make earlier reads fail.
    /// `floor` must be positive and less than `i64::MAX`, leaving room for a
    /// later mutation timestamp. The history clock advances atomically to at
    /// least `floor - 1`; future writes therefore cannot fall behind the new
    /// floor, even after a long idle interval. Repeating the current floor
    /// succeeds without work; moving it backwards is invalid. Implementations
    /// serialize this operation with writes and readers.
    fn trim_before(&self, floor: i64, limits: StateHistoryTrimLimits) -> Self::Trim<'_>;
}

/// Caller-owned history cursor that fetches and returns one bounded page at a
/// time. It does not accumulate prior pages or establish a cross-page snapshot.
pub struct StateHistoryPager<'a, T: ?Sized> {
    port: &'a T,
    query: StateHistoryQuery,
    finished: bool,
}

impl<'a, T: StateHistory + ?Sized> StateHistoryPager<'a, T> {
    /// Retain the supplied query and backend without issuing a request yet.
    pub fn new(port: &'a T, query: StateHistoryQuery) -> Self {
        Self {
            port,
            query,
            finished: false,
        }
    }
    /// Fetch the next page, or `None` after a page ends the scan. Empty pages
    /// with continuations remain visible. A repeated continuation is rejected
    /// as [`crate::StateError::InvalidQuery`]; errors do not advance this pager.
    pub async fn next(&mut self) -> StateResult<Option<StateHistoryPage>> {
        if self.finished {
            return Ok(None);
        }
        let page = self.port.history(&self.query).await?;
        if let Some(next) = &page.next {
            if Some(next) == self.query.cursor.as_ref() {
                return Err(crate::StateFailure::new(
                    crate::StateError::InvalidQuery(
                        "history page did not advance its cursor".into(),
                    ),
                    page.taint,
                ));
            }
            self.query.cursor = Some(next.clone());
        } else {
            self.finished = true;
        }
        Ok(Some(page))
    }
}

/// Cursor-management helpers for any statically composed history capability.
pub trait StateHistoryExt: StateHistory {
    /// Create a pager retaining this query's limits and continuation.
    fn history_pages(&self, query: StateHistoryQuery) -> StateHistoryPager<'_, Self> {
        StateHistoryPager::new(self, query)
    }
}
impl<T: StateHistory + ?Sized> StateHistoryExt for T {}

/// Replay a mutation without losing the provenance of an appended sequence.
/// Invalid append history is rejected and leaves the current value unchanged.
pub fn apply_event(current: &mut StateObservation, event: &crate::StateEvent) -> StateResult<()> {
    use crate::StateEvent;
    let replacement = match event {
        StateEvent::Set { value, taint, .. } => StateObservation {
            value: Some(value.clone()),
            taint: taint.clone(),
        },
        StateEvent::Append { path, item, taint } => crate::values::append_observed_value(
            path,
            current.value.as_ref(),
            item.clone(),
            current.taint.clone().merged(taint),
        )?
        .into(),
        StateEvent::DropPrefixAppend {
            path,
            removed,
            item,
            taint,
        } => crate::values::drop_prefix_append_observed_value(
            path,
            current.value.as_ref(),
            *removed,
            item.clone(),
            current.taint.clone().merged(taint),
        )?
        .into(),
        StateEvent::Delete { taint, .. } => StateObservation {
            value: None,
            taint: current.taint.clone().merged(taint),
        },
    };
    *current = replacement;
    Ok(())
}

#[cfg(test)]
mod tests;
