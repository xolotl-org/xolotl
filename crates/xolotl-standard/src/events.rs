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
//! stream sink via [`DriverContext::emit_tainted`]. A matching topic deletion ends
//! that subscription without emitting a data chunk. The terminal delivery count
//! and later failures retain all sources observed on the topic, including
//! deletion; each data chunk keeps its own event's sources. In `OutputMode::Unary`
//! it confirms the topic is addressable.
//!
//! Streaming subscriptions have no implicit cumulative event limit. An optional
//! nonnegative `max_events` sets an explicit stopping condition; zero returns
//! immediately without opening a subscription. The successful terminal value is
//! the complete decimal string of delivered data chunks, including `"0"`.

use crate::error::ObservedFailure;
use async_trait::async_trait;
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
use xolotl_state::{Backend, StateEvent, TaintedValue};
use xolotl_types::{MethodId, Outcome, OutputMode, Path, Purity, Value};
use xolotl_types::{ValueMap, ValueView};

mod count;
use count::DeliveryCount;

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate `effect://events/<method>` Resource with public method
/// `invoke`.
pub(crate) const EVENTS_METHODS: &[MethodSpec] = &[
    MethodSpec::new("publish", Purity::Effectful, MethodSpec::UNARY_ASYNC).finalize_allowed(),
    MethodSpec::new("subscribe", Purity::Pure, MethodSpec::STREAM_ASYNC).observes_external(),
];

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
        Path::try_new("state")
            .and_then(|path| path.try_push("events"))
            .and_then(|path| path.try_push_literal(topic))
            .map_err(|e| DriverError::Other(format!("invalid event topic {topic:?}: {e}")))
    }

    /// Stream appended items and whole-topic replacements to the operation's sink.
    /// A matching deletion ends the subscription without emitting a data chunk.
    /// Return the decimal count of chunks delivered on deletion, closure, or an
    /// explicitly requested limit. No limit means continued subscription. Zero
    /// returns immediately without observing State. Idle subscriptions wait for
    /// the next event or closure and remain cancellable by their operation owner,
    /// retaining every matched event's sources in that count or any later failure.
    async fn stream_topic(
        &self,
        path: &Path,
        limit: Option<u64>,
        ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        let mut delivered = DeliveryCount::new();
        let mut observed = ctx.taint.clone();
        if delivered.reached(limit) {
            return Ok(
                DriverOutput::new(Outcome::Done(Value::string(delivered.into_decimal())))
                    .with_taint(observed),
            );
        }
        let mut rx = match self.state.subscribe(path).await {
            Ok(subscription) => subscription,
            Err(error) => {
                return ObservedFailure::from(error)
                    .with_taint(&ctx.taint)
                    .into_output("events");
            }
        };
        while !delivered.reached(limit) {
            let event = match rx.recv().await {
                Ok(event) => event,
                Err(xolotl_state::StateWatchError::Closed) => break,
                Err(xolotl_state::StateWatchError::Lagged(skipped)) => {
                    return ObservedFailure::from(DriverError::Other(format!(
                        "event stream lagged and dropped {skipped} events"
                    )))
                    .with_taint(&observed)
                    .into_output("events");
                }
                Err(error) => {
                    return ObservedFailure::from(DriverError::Other(format!(
                        "event stream failed: {error}"
                    )))
                    .with_taint(&observed)
                    .into_output("events");
                }
            };
            if event.path() != path {
                continue;
            }
            let (value, taint) = match event {
                StateEvent::Append { item, taint, .. }
                | StateEvent::Set {
                    value: item, taint, ..
                } => (item, taint),
                StateEvent::Delete { taint, .. } => {
                    observed.union(&taint);
                    break;
                }
            };
            observed.union(&taint);
            if let Err(error) = ctx.emit_tainted(TaintedValue::new(value, taint)).await {
                return ObservedFailure::from(DriverError::from(error))
                    .with_taint(&observed)
                    .into_output("events");
            }
            delivered.increment();
        }
        Ok(
            DriverOutput::new(Outcome::Done(Value::string(delivered.into_decimal())))
                .with_taint(observed),
        )
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
    ) -> Result<DriverOutput, DriverError> {
        let m = crate::input::map(input, "events")?;
        let topic = optional_topic(&m)?;
        let path = Self::topic_path(&topic)?;
        match method.get() {
            // publish: append the event payload to the topic Sequence.
            0 => {
                let event = m.get("event").cloned().ok_or_else(|| {
                    DriverError::InvalidInput("events.publish requires event".into())
                })?;
                match self
                    .state
                    .write_append_tainted(&path, event, ctx.taint.clone())
                    .await
                {
                    Ok(commit) => Ok(DriverOutput::new(Outcome::Done(Value::boolean(true)))
                        .with_taint(commit.taint)),
                    Err(error) => ObservedFailure::from(error)
                        .with_taint(&ctx.taint)
                        .into_output("events"),
                }
            }
            // subscribe: in Stream mode, forward appended events to the sink via
            // the backend subscription channel; otherwise confirm the topic is
            // addressable (the Unary acknowledgement, unchanged).
            1 => {
                if output == OutputMode::Stream {
                    let limit = optional_stream_limit(&m)?;
                    self.stream_topic(&path, limit, ctx).await
                } else {
                    Ok(DriverOutput::new(Outcome::Done(Value::string(
                        path.to_string(),
                    ))))
                }
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

fn optional_topic(m: &ValueMap) -> Result<String, DriverError> {
    match m.get("topic").map(Value::view) {
        None => Ok("default".into()),
        Some(ValueView::Str(topic)) if !topic.is_empty() => Ok(topic.to_owned()),
        Some(ValueView::Str(_)) => Err(DriverError::InvalidInput(
            "events topic must not be empty".into(),
        )),
        Some(_) => Err(DriverError::InvalidInput(
            "events topic must be a string".into(),
        )),
    }
}

fn optional_stream_limit(m: &ValueMap) -> Result<Option<u64>, DriverError> {
    match m.get("max_events").map(Value::view) {
        None => Ok(None),
        Some(ValueView::Int(limit)) if limit >= 0 => Ok(Some(limit as u64)),
        Some(ValueView::Int(_)) => Err(DriverError::InvalidInput(
            "events max_events must be non-negative".into(),
        )),
        Some(_) => Err(DriverError::InvalidInput(
            "events max_events must be an integer".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::{Context, Result, ensure};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use xolotl_state::InMemoryBackend;
    use xolotl_types::{IdentityRef, ProcessId};

    mod provenance;
    mod streaming;

    fn ctx() -> DriverContext {
        DriverContext::new(IdentityRef::ROOT, ProcessId::new(1))
    }

    fn publish_input(topic: &str, event: &str) -> Value {
        let mut m = BTreeMap::new();
        m.insert("topic".into(), Value::string(topic.into()));
        m.insert("event".into(), Value::string(event.into()));
        Value::map(m)
    }

    #[tokio::test]
    async fn publish_appends_to_topic() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
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
        let expected = Some(Value::list(vec![Value::string("fire".into())]));
        ensure!(stored == expected, "stored events: {stored:?}");
        Ok(())
    }

    #[tokio::test]
    async fn publish_requires_explicit_event() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = EventBusDriver::new(state);
        let mut m = BTreeMap::new();
        m.insert("topic".into(), Value::string("alerts".into()));
        let out = d
            .call(MethodId::new(0), Value::map(m), OutputMode::Unary, &ctx())
            .await;
        ensure!(out.is_err(), "publish accepted a missing event");
        Ok(())
    }

    #[tokio::test]
    async fn topic_rejects_path_delimiters() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = EventBusDriver::new(state);
        let out = d
            .call(
                MethodId::new(0),
                publish_input("alerts/ops", "fire"),
                OutputMode::Unary,
                &ctx(),
            )
            .await;
        ensure!(out.is_err(), "topic with path delimiter was accepted");
        Ok(())
    }

    #[tokio::test]
    async fn subscribe_rejects_invalid_max_events() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = EventBusDriver::new(state);
        let mut m = BTreeMap::new();
        m.insert("topic".into(), Value::string("alerts".into()));
        m.insert("max_events".into(), Value::integer(-1));
        let out = d
            .call(MethodId::new(1), Value::map(m), OutputMode::Stream, &ctx())
            .await;
        ensure!(out.is_err(), "negative max_events was accepted");
        Ok(())
    }

    #[tokio::test]
    async fn subscribe_unary_returns_topic_path() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = EventBusDriver::new(state.clone());
        let mut m = BTreeMap::new();
        m.insert("topic".into(), Value::string("alerts".into()));
        let out = d
            .call(MethodId::new(1), Value::map(m), OutputMode::Unary, &ctx())
            .await
            .context("subscribe unary")?;
        let expected = Outcome::Done(Value::string("state://events/alerts".into()));
        ensure!(out.outcome == expected, "subscribe output: {out:?}");
        Ok(())
    }

    #[tokio::test]
    async fn published_event_reaches_streaming_subscriber() -> Result<()> {
        let state: Backend = InMemoryBackend::new().into_backend();
        let d = Arc::new(EventBusDriver::new(state.clone()));

        let (tx, mut rx) =
            xolotl_kernel::host::stream::channel(xolotl_kernel::stream::StreamWindow::default());
        let sink_path = Path::parse("state://stream/sub").context("parse stream sink path")?;
        let sctx =
            DriverContext::new(IdentityRef::ROOT, ProcessId::new(2)).with_stream(sink_path, tx);

        let mut sm = BTreeMap::new();
        sm.insert("topic".into(), Value::string("chat".into()));
        sm.insert("max_events".into(), Value::integer(2));
        let sub = d.clone();
        let handle = tokio::spawn(async move {
            sub.call(MethodId::new(1), Value::map(sm), OutputMode::Stream, &sctx)
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
        let topic = EventBusDriver::topic_path("chat")?;
        let protected = xolotl_types::TaintSet::of(xolotl_types::TaintSource::Protected {
            path: topic.clone(),
        });
        state
            .write_append_tainted(&topic, Value::string("world".into()), protected.clone())
            .await?;

        let out = handle
            .await
            .context("join subscriber task")?
            .context("run subscriber")?;
        ensure!(
            out.outcome == Outcome::Done(Value::string("2".into())),
            "stream subscriber output: {out:?}"
        );
        ensure!(
            out.taint.has_protected(),
            "terminal count lost observed sources"
        );
        let Some(xolotl_kernel::host::stream::StreamItem::Chunk(first)) = rx.recv().await else {
            anyhow::bail!("missing first stream chunk");
        };
        let first = first.into_value();
        ensure!(
            first == TaintedValue::pristine(Value::string("hello".into())),
            "first stream chunk: {first:?}"
        );
        let Some(xolotl_kernel::host::stream::StreamItem::Chunk(second)) = rx.recv().await else {
            anyhow::bail!("missing second stream chunk");
        };
        let second = second.into_value();
        ensure!(
            second == TaintedValue::new(Value::string("world".into()), protected),
            "second stream chunk: {second:?}"
        );
        Ok(())
    }
}
