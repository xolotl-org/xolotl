#![forbid(unsafe_code)]

//! `xolotl-state` — backend trait and in-process implementation for the
//! Xolotl state plane (`state://`).
//!
//! The data plane reaches storage through state-plane Operations served by a
//! `StateBackend`. The standard state driver exposes read, write, append,
//! delete, and list methods; event subscriptions and `Wait(Signal)` use the
//! backend subscription API. This crate ships one always-available
//! implementation, the in-memory backend.

pub mod backend;
pub mod memory;

pub use backend::{
    DynBackend, StateBackend, StateError, StateEvent, StateHistoryEntry, StateResult, StateStream,
    TaintedValue, merge_values,
};
pub use memory::InMemoryBackend;

/// Convenience alias used across the workspace.
pub type Backend = std::sync::Arc<dyn StateBackend>;

#[cfg(test)]
mod integration_tests {
    use super::*;
    use anyhow::{anyhow, bail, ensure};
    use std::sync::Arc;
    use xolotl_types::{Path, Value};

    fn p(s: &str) -> anyhow::Result<Path> {
        Path::parse(s).map_err(|error| anyhow!("path parse failed for {s}: {error}"))
    }

    #[tokio::test]
    async fn dyn_backend_works_through_trait() -> anyhow::Result<()> {
        let b: Backend = Arc::new(InMemoryBackend::new());
        b.write_set(&p("state://greet")?, Value::Str("hi".into()))
            .await?;
        let v = b.read(&p("state://greet")?).await?;
        ensure!(
            v == Some(Value::Str("hi".into())),
            "unexpected value: {v:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn ordered_events_under_load() -> anyhow::Result<()> {
        let b: Backend = Arc::new(InMemoryBackend::new());
        let mut rx = b.subscribe(&p("state://q")?).await?;
        for i in 0..50 {
            b.write_set(&p("state://q")?, Value::Int(i)).await?;
        }
        let mut last = -1;
        for _ in 0..50 {
            let ev = rx
                .recv()
                .await
                .map_err(|error| anyhow!("event receive failed: {error}"))?;
            if let StateEvent::Set {
                value: Value::Int(i),
                ..
            } = ev
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
