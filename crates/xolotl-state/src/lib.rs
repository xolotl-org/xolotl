#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Independent storage capabilities for the Xolotl state plane (`state://`).
//!
//! Read, mutation, query, history, watch, and flush contracts support static
//! composition with `no_std + alloc`, without requiring a scheduler or `Send`.
//! The optional `std` host erases only installed capabilities into `Backend`.
//! The `memory` feature supplies compact or sharded in-process storage.

extern crate alloc;

mod error;
mod event;
mod history;
#[cfg(feature = "std")]
pub mod host;
#[cfg(feature = "memory")]
pub mod memory;
pub mod object;
mod query;
mod read;
#[cfg(any(all(test, feature = "std"), feature = "test-support"))]
pub mod test_support;
mod values;
mod watch;
mod write;

pub use error::{StateError, StateFailure, StateResult};
pub use event::{StateEvent, StateHistoryEntry};
pub use history::{
    StateHistory, StateHistoryExt, StateHistoryPage, StateHistoryPager, StateHistoryQuery,
    apply_event as apply_history_event,
};
#[cfg(feature = "std")]
pub use host::Backend;
#[cfg(feature = "memory")]
pub use memory::{InMemoryBackend, InMemoryOptions, MemoryHistory};
pub use query::{
    StateCursor, StatePage, StatePageLimits, StatePager, StateQuery, StateQueryExt,
    StateRowTooLarge, StateScan,
};
pub use read::{StateRead, StateReadExt};
pub use values::{append_value, merge_values};
pub use watch::{StateStream, StateSubscription, StateWatch, StateWatchError};
pub use write::{StateCommit, StateFlush, StateMutation, StateWrite, StateWriteExt};
pub use xolotl_types::TaintedValue;

/// Methods for statically composed state capabilities.
pub mod prelude {
    pub use crate::{
        StateFlush, StateHistory, StateHistoryExt, StateQuery, StateQueryExt, StateRead,
        StateReadExt, StateWatch, StateWrite, StateWriteExt,
    };
}

#[cfg(all(test, feature = "memory"))]
mod integration_tests {
    use super::*;
    use anyhow::{anyhow, bail, ensure};
    use xolotl_types::{Path, Value};

    fn p(s: &str) -> anyhow::Result<Path> {
        Path::parse(s).map_err(|error| anyhow!("path parse failed for {s}: {error}"))
    }

    #[tokio::test]
    async fn dyn_backend_works_through_trait() -> anyhow::Result<()> {
        let b = InMemoryBackend::new().into_backend();
        b.write_set(&p("state://greet")?, Value::string("hi".into()))
            .await?;
        let v = b.read(&p("state://greet")?).await?;
        ensure!(
            v == Some(Value::string("hi".into())),
            "unexpected value: {v:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ordered_events_under_load() -> anyhow::Result<()> {
        let b = InMemoryBackend::new().into_backend();
        let mut rx = b.subscribe(&p("state://q")?).await?;
        for i in 0..50 {
            b.write_set(&p("state://q")?, Value::integer(i)).await?;
        }
        let mut last = -1;
        for _ in 0..50 {
            let ev = rx
                .recv()
                .await
                .map_err(|error| anyhow!("event receive failed: {error}"))?;
            if let StateEvent::Set { value, .. } = &ev
                && let Some(i) = value.as_int()
            {
                ensure!(i > last, "event order regressed: {i} after {last}");
                last = i;
            } else {
                bail!("unexpected event: {ev:?}");
            }
        }
        Ok(())
    }
}
