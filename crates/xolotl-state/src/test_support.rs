//! Explicit whole-result collectors for backend conformance fixtures.
//! Production code consumes `StatePager` or `StateHistoryPager` one page at a time.

use crate::*;
use alloc::vec::Vec;
use core::future::Future;
use core::num::NonZeroUsize;
use xolotl_types::{Path, Value};

/// Whole-prefix collectors for bounded test fixtures. Each request still uses
/// entry and candidate limits, but total allocation and work are unbounded and
/// the encoded-byte limit is raised to the platform maximum.
pub trait CollectState: StateQuery {
    /// Collect every matching page in backend order, preserving provenance.
    /// Pages observe live state rather than one snapshot of the entire prefix.
    fn read_prefix_tainted<'a>(
        &'a self,
        prefix: &'a Path,
    ) -> impl Future<Output = StateResult<Vec<(Path, TaintedValue)>>> + 'a {
        async move {
            let mut query = StateScan::new(prefix.clone());
            query.limits.encoded_bytes = NonZeroUsize::MAX;
            let mut pages = StatePager::new(self, query);
            let mut values = Vec::new();
            while let Some(page) = pages.next().await? {
                values.extend(page.entries);
            }
            Ok(values)
        }
    }
    /// Collect a complete prefix while discarding provenance for fixture assertions.
    fn read_prefix<'a>(
        &'a self,
        prefix: &'a Path,
    ) -> impl Future<Output = StateResult<Vec<(Path, Value)>>> + 'a {
        async move {
            Ok(self
                .read_prefix_tainted(prefix)
                .await?
                .into_iter()
                .map(|(path, value)| (path, value.value))
                .collect())
        }
    }
}
impl<T: StateQuery + ?Sized> CollectState for T {}

/// Whole-history collection for test fixtures, with unbounded total work and
/// allocation. Production callers should consume [`StateHistoryPager`] pages.
pub trait CollectHistory: StateHistory {
    /// Collect the path and descendant history in `from_millis..to_millis`, then
    /// stably sort by timestamp. The encoded-byte limit is raised to the platform
    /// maximum; entry and candidate limits still apply to each underlying request.
    fn read_range<'a>(
        &'a self,
        path: &'a Path,
        from_millis: i64,
        to_millis: i64,
    ) -> impl Future<Output = StateResult<Vec<StateHistoryEntry>>> + 'a {
        async move {
            let mut query = StateHistoryQuery::new(path.clone(), from_millis, to_millis);
            query.limits.encoded_bytes = NonZeroUsize::MAX;
            let mut pages = StateHistoryPager::new(self, query);
            let mut entries = Vec::new();
            while let Some(page) = pages.next().await? {
                entries.extend(page.entries);
            }
            entries.sort_by_key(|entry| entry.at_millis);
            Ok(entries)
        }
    }
}
impl<T: StateHistory + ?Sized> CollectHistory for T {}
