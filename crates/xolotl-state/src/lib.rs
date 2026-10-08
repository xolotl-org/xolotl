#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

//! Independent storage capabilities for the Xolotl state plane (`state://`).
//!
//! Read, bounded exact-path read, mutation, bounded conditional mutation,
//! query, history, watch, and flush
//! contracts support static composition with `no_std + alloc`, without
//! requiring a scheduler or `Send`.
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
mod observation;
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
    StateHistoryRetention, StateHistoryTrim, StateHistoryTrimLimits,
    apply_event as apply_history_event, history_retains_path,
};
#[cfg(feature = "std")]
pub use host::Backend;
#[cfg(feature = "memory")]
pub use memory::{InMemoryBackend, InMemoryOptions, MemoryHistory};
pub use observation::{AbsenceLimits, StateObservation};
pub use query::{
    StateCursor, StatePage, StatePageLimits, StatePager, StateQuery, StateQueryExt,
    StateRowTooLarge, StateScan,
};
pub use read::{
    StateBoundedRead, StateBoundedReadExt, StatePointTooLarge, StateRead, StateReadExt,
};
pub use values::{append_value, drop_prefix_append_value, merge_values};
pub use watch::{StateStream, StateSubscription, StateWatch, StateWatchError};
pub use write::{
    StateBoundedWrite, StateBoundedWriteExt, StateCommit, StateFlush, StateMutation, StateWrite,
    StateWriteExt,
};
pub use xolotl_types::TaintedValue;

/// Methods for statically composed state capabilities.
pub mod prelude {
    pub use crate::{
        StateBoundedRead, StateBoundedReadExt, StateBoundedWrite, StateBoundedWriteExt, StateFlush,
        StateHistory, StateHistoryExt, StateHistoryRetention, StateQuery, StateQueryExt, StateRead,
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
    async fn bounded_read_requires_its_own_port() -> anyhow::Result<()> {
        use std::{num::NonZeroUsize, sync::Arc};
        let path = p("state://bounded/only-child")?;
        let port = Arc::new(InMemoryBackend::new());
        let read_only = Backend::new().with_read(port.clone());
        let missing = read_only
            .read_bounded(&path, NonZeroUsize::MIN)
            .await
            .err()
            .ok_or_else(|| anyhow!("bounded read used an unrestricted port"))?;
        ensure!(matches!(
            missing.error,
            StateError::MissingCapability("bounded_read")
        ));
        let bounded = Backend::new().with_bounded_read(port);
        ensure!(!bounded.has_read() && bounded.has_bounded_read());
        ensure!(
            bounded
                .read_bounded(&path, NonZeroUsize::MIN)
                .await?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn bounded_write_requires_its_own_port() -> anyhow::Result<()> {
        use std::{num::NonZeroUsize, sync::Arc};
        let path = p("state://bounded/write")?;
        let port = Arc::new(InMemoryBackend::new());
        let ordinary = Backend::new().with_write(port.clone());
        let missing = ordinary
            .write_cas_bounded(&path, None, Value::integer(1), NonZeroUsize::MIN)
            .await
            .err()
            .ok_or_else(|| anyhow!("bounded write used an unrestricted port"))?;
        ensure!(matches!(
            missing.error,
            StateError::MissingCapability("bounded_write")
        ));
        let incoming = xolotl_types::TaintSet::author();
        let missing = ordinary
            .write_compare_delete_tainted_bounded(&path, None, incoming.clone(), NonZeroUsize::MIN)
            .await
            .err()
            .ok_or_else(|| anyhow!("bounded delete used an unrestricted port"))?;
        ensure!(
            matches!(
                missing.error,
                StateError::MissingCapability("bounded_write")
            ) && missing.taint == incoming
        );
        let bounded = Backend::new().with_bounded_write(port);
        ensure!(!bounded.has_write() && bounded.has_bounded_write());
        let missing = bounded
            .write_delete_tainted(&path, incoming.clone())
            .await
            .err()
            .ok_or_else(|| anyhow!("ordinary delete used a bounded port"))?;
        ensure!(
            matches!(missing.error, StateError::MissingCapability("write"))
                && missing.taint == incoming
        );
        bounded
            .write_cas_bounded(&path, None, Value::integer(1), NonZeroUsize::MIN)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn signal_observation_requires_one_coherent_port() -> anyhow::Result<()> {
        use std::sync::Arc;
        let path = p("state://signal/coherent")?;
        let primary = Arc::new(InMemoryBackend::new());
        let other = Arc::new(InMemoryBackend::new());
        primary.write_set(&path, Value::integer(7)).await?;

        let unpaired = Backend::new()
            .with_read(primary.clone())
            .with_watch(other.clone());
        let missing = unpaired
            .observe_signal(&path)
            .await
            .err()
            .ok_or_else(|| anyhow!("unpaired read and watch ports enabled signal wait"))?;
        ensure!(matches!(
            missing.error,
            StateError::MissingCapability("signal")
        ));

        let paired = unpaired
            .with_read(other.clone())
            .with_signal(primary.clone());
        let (current, _events) = paired.observe_signal(&path).await?;
        ensure!(current.value == Some(Value::integer(7)));
        primary.write_set(&path, Value::integer(8)).await?;
        ensure!(paired.read(&path).await?.is_none());
        ensure!(paired.observe_signal_current(&path).await?.value == primary.read(&path).await?);
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
