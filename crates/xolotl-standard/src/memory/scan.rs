//! Namespace paging with one-record fallback for oversized resident values.
//!
//! The State page window bounds one response, not the size of a memory record.
//! An oversized row is read explicitly and then its backend continuation resumes
//! the scan. This retains only one page or one oversized record at a time.

use super::{Backend, Path, StateError, StateFailure, TaintedValue};
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
        if self.finished {
            return Ok(None);
        }
        let mut observed = TaintSet::pristine();
        let (entries, next) = match self.state.query(&self.query).await {
            Ok(page) => {
                observed.union(&page.taint);
                (page.entries, page.next)
            }
            Err(StateFailure {
                error: StateError::RowTooLarge(row),
                taint,
            }) => {
                observed.union(&taint);
                let entry = self
                    .state
                    .read_tainted(&row.path)
                    .await
                    .map_err(|error| error.with_taint(&observed))?;
                (
                    entry
                        .into_iter()
                        .map(|entry| (row.path.clone(), entry))
                        .collect(),
                    Some(row.resume),
                )
            }
            Err(error) => return Err(error),
        };
        for (_, entry) in &entries {
            observed.union(&entry.taint);
        }
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
