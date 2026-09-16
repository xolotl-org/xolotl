use super::*;
use std::{
    future::{Future, Ready, poll_fn, ready},
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use xolotl_state::{StateResult, StateSubscription, StateWatch, StateWatchError};
use xolotl_types::{TaintSet, TaintSource};

struct ScriptedWatch(Vec<Result<StateEvent, StateWatchError>>);

struct ScriptedSubscription(std::vec::IntoIter<Result<StateEvent, StateWatchError>>);

impl StateSubscription for ScriptedSubscription {
    fn poll_next(
        &mut self,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<StateEvent>, StateWatchError>> {
        Poll::Ready(self.0.next().transpose())
    }
}

impl StateWatch for ScriptedWatch {
    type Subscription = ScriptedSubscription;
    type Subscribe<'a> = Ready<StateResult<Self::Subscription>>;

    fn subscribe<'a>(&'a self, _pattern: &'a Path) -> Self::Subscribe<'a> {
        ready(Ok(ScriptedSubscription(self.0.clone().into_iter())))
    }
}

fn scripted(events: Vec<Result<StateEvent, StateWatchError>>) -> EventBusDriver {
    EventBusDriver::new(
        InMemoryBackend::new()
            .into_backend()
            .with_watch(Arc::new(ScriptedWatch(events))),
    )
}

fn subscription_input(topic: &str, max_events: i64) -> Value {
    Value::map(BTreeMap::from([
        ("topic".into(), Value::string(topic.into())),
        ("max_events".into(), Value::integer(max_events)),
    ]))
}

async fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

#[tokio::test]
async fn deletion_without_a_prior_delivery_ends_the_subscription_with_observed_sources()
-> Result<()> {
    let state = InMemoryBackend::new().into_backend();
    let topic = EventBusDriver::topic_path("private")?;
    let protected = TaintSet::of(TaintSource::Protected {
        path: topic.clone(),
    });
    state
        .write_set_tainted(&topic, Value::string("existing".into()), protected.clone())
        .await?;
    let driver = EventBusDriver::new(state.clone());
    let (sink, mut receiver) =
        xolotl_kernel::host::stream::channel(xolotl_kernel::stream::StreamWindow::default());
    let input_sources = TaintSet::of(TaintSource::ModelOutput);
    let context = ctx()
        .with_taint(input_sources.clone())
        .with_stream(Path::parse("state://stream/deletion")?, sink);
    let subscription = driver.call(
        MethodId::new(1),
        subscription_input("private", 1),
        OutputMode::Stream,
        &context,
    );
    tokio::pin!(subscription);
    ensure!(poll_once(subscription.as_mut()).await.is_pending());
    state.write_delete(&topic).await?;
    let Poll::Ready(output) = poll_once(subscription.as_mut()).await else {
        anyhow::bail!("topic deletion did not end the subscription");
    };
    let output = output?;
    let mut expected = input_sources;
    expected.union(&protected);
    ensure!(output.outcome == Outcome::Done(Value::string("0".into())) && output.taint == expected);
    let next = receiver.recv();
    tokio::pin!(next);
    ensure!(
        poll_once(next.as_mut()).await.is_pending(),
        "deletion emitted a data chunk"
    );
    Ok(())
}

#[tokio::test]
async fn terminal_sources_include_matching_deletion_without_changing_individual_chunk_sources()
-> Result<()> {
    let topic = EventBusDriver::topic_path("chat")?;
    let unrelated = EventBusDriver::topic_path("other")?;
    let model = TaintSet::of(TaintSource::ModelOutput);
    let protected = TaintSet::of(TaintSource::Protected {
        path: topic.clone(),
    });
    let driver = scripted(vec![
        Ok(StateEvent::Delete {
            path: unrelated.clone(),
            taint: TaintSet::of(TaintSource::Protected { path: unrelated }),
        }),
        Ok(StateEvent::Append {
            path: topic.clone(),
            item: Value::integer(1),
            taint: model.clone(),
        }),
        Ok(StateEvent::Set {
            path: topic.clone(),
            value: Value::integer(2),
            taint: TaintSet::pristine(),
        }),
        Ok(StateEvent::Delete {
            path: topic.clone(),
            taint: protected.clone(),
        }),
        Ok(StateEvent::Append {
            path: topic,
            item: Value::integer(3),
            taint: TaintSet::pristine(),
        }),
    ]);
    let (sink, mut receiver) =
        xolotl_kernel::host::stream::channel(xolotl_kernel::stream::StreamWindow::default());
    let context = ctx().with_stream(Path::parse("state://stream/events")?, sink);
    let output = driver
        .call(
            MethodId::new(1),
            subscription_input("chat", 3),
            OutputMode::Stream,
            &context,
        )
        .await?;
    let mut expected = model.clone();
    expected.union(&protected);
    ensure!(output.outcome == Outcome::Done(Value::string("2".into())) && output.taint == expected);
    for expected in [
        TaintedValue::new(Value::integer(1), model),
        TaintedValue::pristine(Value::integer(2)),
    ] {
        let Some(xolotl_kernel::host::stream::StreamItem::Chunk(chunk)) = receiver.recv().await
        else {
            anyhow::bail!("missing delivered data chunk");
        };
        ensure!(chunk.into_value() == expected);
    }
    let next = receiver.recv();
    tokio::pin!(next);
    ensure!(
        poll_once(next.as_mut()).await.is_pending(),
        "subscription continued after deletion"
    );
    Ok(())
}

#[tokio::test]
async fn late_watch_errors_keep_sources_from_previously_delivered_events() -> Result<()> {
    for error in [
        StateWatchError::Lagged(1),
        StateWatchError::Backend("late failure".into()),
    ] {
        let topic = EventBusDriver::topic_path("chat")?;
        let protected = TaintSet::of(TaintSource::Protected {
            path: topic.clone(),
        });
        let driver = scripted(vec![
            Ok(StateEvent::Append {
                path: topic,
                item: Value::integer(1),
                taint: protected.clone(),
            }),
            Err(error),
        ]);
        let (sink, _receiver) =
            xolotl_kernel::host::stream::channel(xolotl_kernel::stream::StreamWindow::default());
        let context = ctx().with_stream(Path::parse("state://stream/failure")?, sink);
        let output = driver
            .call(
                MethodId::new(1),
                subscription_input("chat", 2),
                OutputMode::Stream,
                &context,
            )
            .await?;
        ensure!(matches!(output.outcome, Outcome::Fail(_)) && output.taint == protected);
    }
    Ok(())
}

#[tokio::test]
async fn failed_delivery_keeps_sources_from_earlier_matching_events() -> Result<()> {
    let topic = EventBusDriver::topic_path("chat")?;
    let protected = TaintSet::of(TaintSource::Protected {
        path: topic.clone(),
    });
    let driver = scripted(vec![
        Ok(StateEvent::Append {
            path: topic.clone(),
            item: Value::integer(1),
            taint: protected.clone(),
        }),
        Ok(StateEvent::Set {
            path: topic,
            value: Value::integer(2),
            taint: TaintSet::pristine(),
        }),
    ]);
    let (sink, receiver) =
        xolotl_kernel::host::stream::channel(xolotl_kernel::stream::StreamWindow {
            max_chunks: std::num::NonZeroUsize::MIN,
            ..Default::default()
        });
    let context = ctx().with_stream(Path::parse("state://stream/disconnect")?, sink);
    let subscription = driver.call(
        MethodId::new(1),
        subscription_input("chat", 2),
        OutputMode::Stream,
        &context,
    );
    tokio::pin!(subscription);
    ensure!(poll_once(subscription.as_mut()).await.is_pending());
    drop(receiver);
    let Poll::Ready(output) = poll_once(subscription.as_mut()).await else {
        anyhow::bail!("disconnection did not release the pending delivery");
    };
    let output = output?;
    ensure!(matches!(output.outcome, Outcome::Fail(_)) && output.taint == protected);
    Ok(())
}
