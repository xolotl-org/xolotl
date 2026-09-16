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
/// encoded records per page.
#[derive(Clone, Copy, Debug)]
pub struct StatePageLimits {
    /// Maximum number of matching records returned in one page.
    pub entries: NonZeroUsize,
    /// Maximum candidate records charged to one page, including filtered rows.
    pub examined: NonZeroUsize,
    /// Lossless backend record bytes including provenance, not heap residency.
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
    /// Include this path and its descendant paths.
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

/// A path that cannot be inlined within this page's byte budget.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateRowTooLarge {
    /// Path of the record that cannot fit in an otherwise empty page.
    pub path: Path,
    /// Complete encoded record size required by this backend's page accounting.
    pub encoded_bytes: usize,
    /// Position before the row, for retry with a larger page budget.
    pub retry: Option<StateCursor>,
    /// Position after the row, for an explicit caller-selected continuation.
    pub resume: StateCursor,
}

/// A bounded prefix result in the backend's stable key order.
#[derive(Clone, Debug)]
pub struct StatePage {
    /// Matching paths and current values, retaining each value's provenance.
    pub entries: Vec<(Path, TaintedValue)>,
    /// Sources of all records examined by this page, including a record that
    /// affected continuation or byte accounting without being returned.
    pub taint: TaintSet,
    /// Continue from this position; `None` ends the scan. An empty page may
    /// still carry a continuation after exhausting its candidate-work budget.
    pub next: Option<StateCursor>,
    /// Candidate records charged against the page's examined-record budget.
    /// This may exceed the number of returned entries.
    pub examined: usize,
    /// Backend-encoded bytes of returned records, including provenance and
    /// applicable key metadata. This is not a heap-residency measurement.
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
    /// Read one consistent page, honoring its independent budgets. An individual
    /// record exceeding an empty page's byte budget produces
    /// [`crate::StateError::RowTooLarge`] so the caller can retry or explicitly skip it.
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
