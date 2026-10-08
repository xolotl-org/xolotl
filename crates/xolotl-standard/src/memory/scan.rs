//! Namespace paging with one-record fallback for oversized resident values.
//!
//! The State page window bounds one response, not the size of a memory record.
//! An oversized row is read explicitly and then its backend continuation resumes
//! the scan. This retains only one page or one oversized record at a time.
//! Consolidation instead narrows each page to remaining admission and uses
//! bounded point reads for oversized rows. Backend envelope bytes are distinct
//! from consolidation's exact record encoding: fallback reads are capped by
//! the whole-call encoded admission, then the caller charges exact records.
//! Exhausted admission permits only a one-byte terminal probe, never a point
//! read, so a terminal continuation does not reject an exactly full namespace.

use super::{Backend, Path, StateError, StateFailure, TaintedValue};
use std::num::NonZeroUsize;
use xolotl_state::{StateResult, StateScan};
use xolotl_types::TaintSet;

pub(super) struct NamespacePage {
    pub(super) entries: Vec<(Path, TaintedValue)>,
    pub(super) taint: TaintSet,
}

pub(super) struct NamespaceScan<'a> {
    state: &'a Backend,
    query: StateScan,
    finished: bool,
}

impl<'a> NamespaceScan<'a> {
    pub(super) fn new(state: &'a Backend, prefix: Path) -> Self {
        Self {
            state,
            query: StateScan::new(prefix),
            finished: false,
        }
    }

    pub(super) async fn next(&mut self) -> StateResult<Option<NamespacePage>> {
        self.next_with_read_limit(None, true).await
    }

    pub(super) async fn next_bounded(
        &mut self,
        remaining_records: usize,
        remaining_bytes: usize,
        fallback_bytes: NonZeroUsize,
    ) -> StateResult<Option<NamespacePage>> {
        self.query.limits.entries = self
            .query
            .limits
            .entries
            .min(NonZeroUsize::new(remaining_records).unwrap_or(NonZeroUsize::MIN));
        self.query.limits.encoded_bytes = self
            .query
            .limits
            .encoded_bytes
            .min(NonZeroUsize::new(remaining_bytes).unwrap_or(NonZeroUsize::MIN));
        if remaining_records == 0 || remaining_bytes == 0 {
            self.query.limits.encoded_bytes = NonZeroUsize::MIN;
        }
        self.next_with_read_limit(
            Some(fallback_bytes),
            remaining_records != 0 && remaining_bytes != 0,
        )
        .await
    }

    async fn next_with_read_limit(
        &mut self,
        read_limit: Option<NonZeroUsize>,
        allow_fallback: bool,
    ) -> StateResult<Option<NamespacePage>> {
        if self.finished {
            return Ok(None);
        }
        let (entries, next, observed) = match self.state.query(&self.query).await {
            Ok(page) => (page.entries, page.next, page.taint),
            Err(StateFailure {
                error: StateError::RowTooLarge(row),
                taint,
            }) => {
                if !allow_fallback {
                    return Err(StateFailure::new(StateError::RowTooLarge(row), taint));
                }
                let mut observed = taint;
                let entry = if let Some(limit) = read_limit {
                    self.state.read_tainted_bounded(&row.path, limit).await
                } else {
                    self.state.read_tainted(&row.path).await
                }
                .map_err(|error| error.with_taint(&observed))?;
                observed.union(&entry.taint);
                (
                    entry
                        .value
                        .into_iter()
                        .map(|value| {
                            (
                                row.path.clone(),
                                TaintedValue::new(value, entry.taint.clone()),
                            )
                        })
                        .collect(),
                    Some(row.resume),
                    observed,
                )
            }
            Err(error) => return Err(error),
        };
        if let Some(next) = &next {
            if self.query.cursor.as_ref() == Some(next) {
                return Err(StateFailure::new(
                    StateError::InvalidQuery("memory namespace scan did not advance".into()),
                    observed,
                ));
            }
        } else {
            self.finished = true;
        }
        self.query.cursor = next;
        Ok(Some(NamespacePage {
            entries,
            taint: observed,
        }))
    }
}
