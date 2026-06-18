//! Event Bus: `effect://events/publish`,
//! `effect://events/subscribe`.
//!
//! Thin façade over the state plane's Sequence semantics: publish = append to a
//! topic's Sequence Resource; subscribe = register interest (the kernel's state
//! backend delivers via its broadcast channel). Cross-Process communication is
//! "one appends, another subscribes the same Resource".
//!
//! `subscribe` is mode-aware. In `OutputMode::Stream` it taps the backend's
//! subscription channel (`state.subscribe`, the same channel the executor's
//! `Wait(Signal)` consumes) and forwards each appended event to the operation's
//! stream sink via [`DriverContext::emit`], bounded so a quiet topic can't wedge
//! the run. In `OutputMode::Unary` it confirms the topic is addressable.

use async_trait::async_trait;
use nexus_kernel::{Driver, DriverContext, DriverError, MethodSpec};
use nexus_state::{Backend, StateEvent};
use nexus_types::{MethodId, Outcome, OutputMode, Path, Purity, Value};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://events/<method>` Resource with public method
/// `invoke`.
pub(crate) const EVENTS_METHODS: &[MethodSpec] = &[
    MethodSpec::new("publish", Purity::Effectful, MethodSpec::UNARY_ASYNC),
    MethodSpec::new("subscribe", Purity::Pure, MethodSpec::STREAM_ASYNC).observes_external(),
];

/// Upper bound on events forwarded to one streaming subscriber before the
/// driver returns, so a subscribe Operation always terminates. A caller
/// may lower it via `max_events`; long-lived ingest uses a Source.
const DEFAULT_STREAM_LIMIT: usize = 1024;

/// Drives the event bus actions.
pub(crate) struct EventBusDriver {
    state: Backend,
}

impl EventBusDriver {
    /// Create an event bus driver backed by the state plane.
    pub(crate) fn new(state: Backend) -> Self {
        Self { state }
    }

    fn topic_path(topic: &str) -> Result<Path, DriverError> {
        // Topics live under state://events/<topic> as Sequence Resources.
        Path::parse(&format!("state://events/{topic}"))
            .map_err(|e| DriverError::Other(e.to_string()))
    }

    /// Stream appended events on `topic` to the operation's sink. Returns the
    /// count delivered once the channel closes or the bound is hit.
    async fn stream_topic(
        &self,
        path: &Path,
        limit: usize,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let mut rx = self
            .state
            .subscribe(path)
            .await
            .map_err(|e| DriverError::Other(format!("subscribe failed: {e}")))?;
        let mut delivered = 0usize;
        while delivered < limit {
            match rx.recv().await {
                // Topics are Sequence Resources, so a publish is an Append.
                Ok(StateEvent::Append { path: p, item, .. }) if &p == path => {
                    if !ctx.emit(item) {
                        break; // receiver dropped (caller cancelled / disconnected)
                    }
                    delivered += 1;
                }
                // A whole-topic Set (e.g. reset) is forwarded as a single chunk.
                Ok(StateEvent::Set { path: p, value, .. }) if &p == path => {
                    if !ctx.emit(value) {
                        break;
                    }
                    delivered += 1;
                }
                Ok(_) => continue, // unrelated path on a shared channel
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    return Err(DriverError::Other(format!(
                        "event stream lagged and dropped {skipped} events"
                    )));
                }
            }
        }
        Ok(Outcome::Done(Value::Int(delivered as i64)))
    }
}

#[async_trait]
impl Driver for EventBusDriver {
    async fn call(
        &self,
        method: MethodId,
        input: Value,
        output: OutputMode,
        ctx: &DriverContext,
    ) -> Result<Outcome, DriverError> {
        let m = crate::input::map(input, "events")?;
        let topic = m
            .get("topic")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .to_string();
        let path = Self::topic_path(&topic)?;
        match method.get() {
            // publish: append the event payload to the topic Sequence.
            0 => {
                let event = m.get("event").cloned().unwrap_or(Value::Null);
                self.state
                    .write_append(&path, event)
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(Outcome::Done(Value::Bool(true)))
            }
            // subscribe: in Stream mode, forward appended events to the sink via
            // the backend subscription channel; otherwise confirm the topic is
            // addressable (the Unary acknowledgement, unchanged).
            1 => {
                if output == OutputMode::Stream {
                    let limit = m
                        .get("max_events")
                        .and_then(|v| v.as_int())
                        .map(|n| n.max(0) as usize)
                        .unwrap_or(DEFAULT_STREAM_LIMIT);
                    self.stream_topic(&path, limit, ctx).await
                } else {
                    Ok(Outcome::Done(Value::Str(path.to_string())))
                }
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use nexus_state::InMemoryBackend;
    use nexus_types::{IdentityRef, ProcessId};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn publish_input(topic: &str, event: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("topic".into(), Value::Str(topic.into()));
        m.insert("event".into(), Value::Str(event.into()));
        Value::Map(m)
    }

    #[tokio::test]
    async fn publish_appends_to_topic() -> Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = EventBusDriver::new(state.clone());
        d.call(
            MethodId::new(0),
            publish_input("alerts", "fire"),
            OutputMode::Unary,
            &ctx(),
        )
        .await
        .context("publish event")?;
        let topic_path = EventBusDriver::topic_path("alerts").context("build topic path")?;
        let stored = state.read(&topic_path).await.context("read topic events")?;
        let expected = Some(Value::List(vec![Value::Str("fire".into())]));
        ensure!(stored == expected, "stored events: {stored:?}");
        Ok(())
    }

    #[tokio::test]
    async fn subscribe_unary_returns_topic_path() -> Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = EventBusDriver::new(state.clone());
        let mut m = BTreeMap::new();
        m.insert("topic".into(), Value::Str("alerts".into()));
        let out = d
            .call(MethodId::new(1), Value::Map(m), OutputMode::Unary, &ctx())
            .await
            .context("subscribe unary")?;
        let expected = Outcome::Done(Value::Str("state://events/alerts".into()));
        ensure!(out == expected, "subscribe output: {out:?}");
        Ok(())
    }

    #[tokio::test]
    async fn published_event_reaches_streaming_subscriber() -> Result<()> {
        let state: Backend = Arc::new(InMemoryBackend::new());
        let d = Arc::new(EventBusDriver::new(state.clone()));

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sink_path = Path::parse("state://stream/sub").context("parse stream sink path")?;
        let sctx =
            DriverContext::new(IdentityRef::ROOT, ProcessId::new(2)).with_stream(sink_path, tx);

        let mut sm = BTreeMap::new();
        sm.insert("topic".into(), Value::Str("chat".into()));
        sm.insert("max_events".into(), Value::Int(2));
        let sub = d.clone();
        let handle = tokio::spawn(async move {
            sub.call(MethodId::new(1), Value::Map(sm), OutputMode::Stream, &sctx)
                .await
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        d.call(
            MethodId::new(0),
            publish_input("chat", "hello"),
            OutputMode::Unary,
            &ctx(),
        )
        .await
        .context("publish first event")?;
        d.call(
            MethodId::new(0),
            publish_input("chat", "world"),
            OutputMode::Unary,
            &ctx(),
        )
        .await
        .context("publish second event")?;

        let out = handle
            .await
            .context("join subscriber task")?
            .context("run subscriber")?;
        ensure!(
            out == Outcome::Done(Value::Int(2)),
            "stream subscriber output: {out:?}"
        );
        let first = rx.recv().await;
        ensure!(
            first == Some(Value::Str("hello".into())),
            "first stream chunk: {first:?}"
        );
        let second = rx.recv().await;
        ensure!(
            second == Some(Value::Str("world".into())),
            "second stream chunk: {second:?}"
        );
        Ok(())
    }
}
