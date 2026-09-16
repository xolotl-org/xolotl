use crate::{StateCursor, StateHistoryEntry, StatePageLimits, StateResult, TaintedValue};
use alloc::vec::Vec;
use core::future::Future;
use xolotl_types::{Path, TaintSet};

/// A bounded history query in stable backend key order.
/// Each page is consistent; subsequent pages observe live state. Time bounds
/// are half-open (`from_millis..to_millis`); a reversed interval is invalid.
#[derive(Clone, Debug)]
pub struct StateHistoryQuery {
    /// Include mutations at this path and its descendant paths.
    pub path: Path,
    /// Inclusive lower timestamp bound, in milliseconds.
    pub from_millis: i64,
    /// Exclusive upper timestamp bound, in milliseconds.
    pub to_millis: i64,
    /// Backend continuation for this query, or `None` to start its scan.
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
    /// Sources of all records examined, including filtered or deferred entries
    /// whose metadata affected this page's accounting or continuation.
    pub taint: TaintSet,
    /// Continue from this position; `None` ends the scan. An empty page may
    /// still have a continuation when its candidate-work budget is exhausted.
    pub next: Option<StateCursor>,
    /// Candidate records charged against this page's examined-record budget,
    /// including candidates excluded by path or timestamp filters.
    pub examined: usize,
    /// Backend-encoded bytes of returned records, including provenance and
    /// applicable key metadata. This is not a heap-residency measurement.
    pub encoded_bytes: usize,
}

/// Historical reads independent of current state reads and writes.
pub trait StateHistory {
    /// Backend-owned state for one bounded history page; no `Send` or boxing
    /// requirement is imposed by this capability.
    type History<'a>: Future<Output = StateResult<StateHistoryPage>>
    where
        Self: 'a;
    /// Backend-owned state for a historical point read, which may replay history.
    type At<'a>: Future<Output = StateResult<Option<TaintedValue>>>
    where
        Self: 'a;
    /// Read one bounded page for the requested path prefix and half-open interval.
    /// An invalid interval or continuation returns [`crate::StateError::InvalidQuery`].
    fn history<'a>(&'a self, query: &'a StateHistoryQuery) -> Self::History<'a>;
    /// Reconstruct a value and its provenance at the specified timestamp.
    /// Zero selects the current value. Replay work is backend-defined and may
    /// depend on the complete history of this path; use pages for bounded work.
    fn read_at<'a>(&'a self, path: &'a Path, at_millis: i64) -> Self::At<'a>;
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
pub fn apply_event(
    current: &mut Option<TaintedValue>,
    event: &crate::StateEvent,
) -> StateResult<()> {
    use crate::StateEvent;
    let replacement = match event {
        StateEvent::Set { value, taint, .. } => {
            Some(TaintedValue::new(value.clone(), taint.clone()))
        }
        StateEvent::Append { path, item, taint } => Some(crate::append_value(
            path,
            current.as_ref(),
            item.clone(),
            taint.clone(),
        )?),
        StateEvent::Delete { .. } => None,
    };
    *current = replacement;
    Ok(())
}
