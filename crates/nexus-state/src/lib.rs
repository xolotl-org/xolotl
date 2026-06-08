#![forbid(unsafe_code)]

//! `nexus-state` — backend trait and in-process implementation for the
//! Nexus state plane (`state://`).
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
    use nexus_types::{Path, Value};
    use std::sync::Arc;

    fn p(s: &str) -> Path {
        Path::parse(s).unwrap()
    }

    /// End-to-end check: backend behind a trait object behaves as expected.
    #[tokio::test]
    async fn dyn_backend_works_through_trait() {
        let b: Backend = Arc::new(InMemoryBackend::new());
        b.write_set(&p("state://greet"), Value::Str("hi".into()))
            .await
            .unwrap();
        let v = b.read(&p("state://greet")).await.unwrap();
        assert_eq!(v, Some(Value::Str("hi".into())));
    }

    /// Subscribe across multiple writers and assert ordering for a single key.
    #[tokio::test]
    async fn ordered_events_under_load() {
        let b: Backend = Arc::new(InMemoryBackend::new());
        let mut rx = b.subscribe(&p("state://q")).await.unwrap();
        for i in 0..50 {
            b.write_set(&p("state://q"), Value::Int(i)).await.unwrap();
        }
        let mut last = -1;
        for _ in 0..50 {
            let ev = rx.recv().await.unwrap();
            if let StateEvent::Set {
                value: Value::Int(i),
                ..
            } = ev
            {
                assert!(i > last);
                last = i;
            } else {
                panic!("unexpected event");
            }
        }
    }
}
