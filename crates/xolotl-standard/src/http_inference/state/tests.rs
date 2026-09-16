use super::*;
use anyhow::{Result, bail, ensure};
use core::future::{Ready, ready};
use xolotl_state::{
    StateCursor, StateError, StateFailure, StatePage, StateQuery, StateResult, StateScan,
};
use xolotl_types::{TaintSet, TaintSource};

struct LateFailure {
    first: TaintSet,
    last: TaintSet,
}

impl StateQuery for LateFailure {
    type Query<'a> = Ready<StateResult<StatePage>>;

    fn query<'a>(&'a self, query: &'a StateScan) -> Self::Query<'a> {
        ready(if query.cursor.is_none() {
            // Continuation and examined-row work can depend on sources even
            // when no values fit in this page.
            Ok(StatePage {
                next: Some(StateCursor(vec![1])),
                examined: 1,
                taint: self.first.clone(),
                ..StatePage::empty()
            })
        } else {
            Err(StateFailure::new(
                StateError::Backend("fixture second page failed".into()),
                self.last.clone(),
            ))
        })
    }
}

#[tokio::test]
async fn late_configuration_scan_failure_preserves_page_and_failure_observations() -> Result<()> {
    let first = TaintSet::of(TaintSource::Protected {
        path: Path::parse("state://vault/configuration-cursor")?,
    });
    let last = TaintSet::of(TaintSource::Fetched {
        host: "failed-query.fixture".into(),
    });
    let state = Backend::new().with_query(Arc::new(LateFailure {
        first: first.clone(),
        last: last.clone(),
    }));
    let Err(HttpInferenceError::State(failure)) =
        read_prefix_values(&state, "state://kernel/inference/backends").await
    else {
        bail!("configuration scan lost its structured State failure");
    };
    ensure!(matches!(failure.error, StateError::Backend(_)));
    ensure!(failure.taint.contains_all(&first));
    ensure!(failure.taint.contains_all(&last));
    Ok(())
}
