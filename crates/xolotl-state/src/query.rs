use crate::{StateResult, TaintedValue};
#[cfg(feature = "memory")]
use alloc::string::String;
use alloc::vec::Vec;
use core::{future::Future, num::NonZeroUsize};
use xolotl_types::{Path, TaintSet};

/// Opaque backend keyset position. It is not portable between backends or queries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateCursor(
    /// Backend-issued bytes to retain and return unchanged when continuing.
    pub Vec<u8>,
);

/// Independent per-page work and output budgets, never limits on total task work.
/// Defaults permit 256 returned entries, 4096 examined candidates, and 1 MiB of
/// consumed encoded records per page. Before observing an in-scope row's
/// provenance, its key and lossless provenance metadata must individually fit
/// the full encoded-byte limit. Consumed provenance input is bounded by that
/// limit, plus at most one admitted but unconsumed boundary row bounded by the
/// same limit. This bounds encoded input, not heap residency or collected pages.
/// Exhausting any budget ends the page before examining another candidate;
/// boundary provenance is observed only while encoded-byte budget remains.
#[derive(Clone, Copy, Debug)]
pub struct StatePageLimits {
    /// Maximum number of matching records returned in one page.
    pub entries: NonZeroUsize,
    /// Maximum physical candidates charged to one page, including filtered rows
    /// and out-of-scope keys that the backend's layout requires examining.
    pub examined: NonZeroUsize,
    /// Maximum consumed lossless backend record bytes, including provenance and
    /// applicable key metadata. Also the individual key-and-provenance admission
    /// limit before taint union; no separate provenance budget is required.
    pub encoded_bytes: NonZeroUsize,
}

impl Default for StatePageLimits {
    fn default() -> Self {
        Self {
            entries: NonZeroUsize::MIN.saturating_add(255),
            examined: NonZeroUsize::MIN.saturating_add(4095),
            encoded_bytes: NonZeroUsize::MIN.saturating_add(1024 * 1024 - 1),
        }
    }
}

/// One prefix page. Each page is consistent; later pages observe live state.
#[derive(Clone, Debug)]
pub struct StateScan {
    /// Include this exact Path and its descendants, not textual prefix matches.
    /// Scope is checked from keys before observing record content or provenance.
    pub prefix: Path,
    /// Backend continuation for this scan, or `None` to start at the prefix.
    pub cursor: Option<StateCursor>,
    /// Independent output and candidate-work budgets for this page.
    pub limits: StatePageLimits,
}

impl StateScan {
    /// Start a prefix scan with default page limits and no continuation.
    pub fn new(prefix: Path) -> Self {
        Self {
            prefix,
            cursor: None,
            limits: StatePageLimits::default(),
        }
    }
}

/// A record whose metadata or payload cannot be admitted by one page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRowTooLarge {
    /// Path of the record that cannot fit in an otherwise empty page.
    pub path: Path,
    /// Required size under the backend's accounting: key and lossless provenance
    /// metadata for a metadata-admission rejection or a time-filtered history
    /// row, otherwise the complete encoded record including applicable key data.
    pub encoded_bytes: usize,
    /// Whether this backend observed the row's provenance before rejecting it.
    /// Metadata exceeding the full page limit is rejected before taint union
    /// with this set to `false`. The failure retains previously observed taint;
    /// pristine failure taint does not prove that the rejected row is untainted.
    pub provenance_observed: bool,
    /// The request's starting position, immediately before the rejected row,
    /// for retry with a larger page budget. Consumed candidates are delivered
    /// in a partial page before an oversized row can fail a subsequent request.
    pub retry: Option<StateCursor>,
    /// Position immediately after the row, for an explicit caller-selected skip.
    pub resume: StateCursor,
}

/// A bounded prefix result in the backend's stable key order.
#[derive(Clone, Debug)]
pub struct StatePage {
    /// Matching paths and current values, retaining each value's provenance.
    pub entries: Vec<(Path, TaintedValue)>,
    /// Sources of consumed in-scope records, including sourced absence, plus at
    /// most one admitted but unconsumed boundary row, observed only while byte
    /// budget remains. Out-of-scope candidates contribute no content or provenance.
    /// Each row's key and lossless provenance
    /// metadata must fit the full page byte limit before union; otherwise the
    /// a page with consumed candidates returns before that row. Without
    /// consumption progress, `RowTooLarge(provenance_observed = false)` rejects
    /// the row without observing its provenance.
    pub taint: TaintSet,
    /// Continue from this position; `None` ends the scan. An empty page may
    /// still carry a continuation after exhausting its candidate-work budget.
    /// A byte-budget boundary remains unconsumed: continuation precedes that row,
    /// even though its admitted provenance is included in this page's taint.
    /// Exact exhaustion stops before examining another row; that row's sources
    /// are not included, and a continuation may precede a terminal empty page.
    pub next: Option<StateCursor>,
    /// Candidate records charged against the page's examined-record budget.
    /// This may exceed the number of returned entries.
    pub examined: usize,
    /// Backend-encoded bytes of consumed records, including sourced absence,
    /// provenance and applicable key metadata. An observed but unconsumed
    /// boundary row is excluded. This is not a heap-residency measurement.
    pub encoded_bytes: usize,
}

impl StatePage {
    /// Construct an empty terminal page with zero reported work and bytes.
    pub fn empty() -> Self {
        Self {
            entries: Vec::new(),
            taint: TaintSet::pristine(),
            next: None,
            examined: 0,
            encoded_bytes: 0,
        }
    }
}

/// Optional keyset queries. Physical indexes belong to the backend.
pub trait StateQuery {
    /// Backend-owned request for one bounded page, without a `Send` or boxing
    /// requirement on statically composed implementations.
    type Query<'a>: Future<Output = StateResult<StatePage>>
    where
        Self: 'a;
    /// Read one consistent page under [`StatePageLimits`], using the Path scope
    /// in [`StateScan`] and provenance/continuation semantics in [`StatePage`].
    /// Admission failure returns [`crate::StateError::RowTooLarge`] with
    /// stage-specific accounting and retry/skip positions in [`StateRowTooLarge`].
    fn query<'a>(&'a self, query: &'a StateScan) -> Self::Query<'a>;
}

#[cfg(feature = "memory")]
pub(crate) fn invalid_cursor(message: impl Into<String>) -> crate::StateFailure {
    crate::StateError::InvalidQuery(message.into()).into()
}

/// A caller-owned cursor and at most one bounded response page.
pub struct StatePager<'a, T: ?Sized> {
    port: &'a T,
    query: StateScan,
    finished: bool,
}

impl<'a, T: StateQuery + ?Sized> StatePager<'a, T> {
    /// Retain the supplied query and backend without issuing a request yet.
    pub fn new(port: &'a T, query: StateScan) -> Self {
        Self {
            port,
            query,
            finished: false,
        }
    }

    /// Fetch the next page, or `None` after a page ends the scan. Empty pages
    /// with continuations remain visible. A repeated continuation is rejected
    /// as [`crate::StateError::InvalidQuery`]; errors do not advance this pager.
    pub async fn next(&mut self) -> StateResult<Option<StatePage>> {
        if self.finished {
            return Ok(None);
        }
        let page = self.port.query(&self.query).await?;
        if let Some(next) = &page.next {
            if Some(next) == self.query.cursor.as_ref() {
                return Err(crate::StateFailure::new(
                    crate::StateError::InvalidQuery("state page did not advance its cursor".into()),
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

/// Cursor-management helpers for any statically composed query capability.
pub trait StateQueryExt: StateQuery {
    /// Create a pager retaining this scan's limits and continuation.
    fn pages(&self, query: StateScan) -> StatePager<'_, Self> {
        StatePager::new(self, query)
    }
}
impl<T: StateQuery + ?Sized> StateQueryExt for T {}
