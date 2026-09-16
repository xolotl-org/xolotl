use super::*;
use std::{
    future::{Ready, ready},
    task::{Context as TaskContext, Poll},
};
use xolotl_state::{StateResult, StateSubscription, StateWatch, StateWatchError};
use xolotl_types::{TaintSet, TaintSource};

struct GeneratedWatch(u64);

struct GeneratedSubscription {
    topic: Path,
    delivered: u64,
    total: u64,
    deleted: bool,
}

impl StateSubscription for GeneratedSubscription {
    fn poll_next(
        &mut self,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<Option<StateEvent>, StateWatchError>> {
        let event = if self.delivered < self.total {
            let event = StateEvent::Append {
                path: self.topic.clone(),
                item: Value::integer(self.delivered as i64),
                taint: TaintSet::pristine(),
            };
            self.delivered += 1;
            Some(event)
        } else if !self.deleted {
            self.deleted = true;
            Some(StateEvent::Delete {
                path: self.topic.clone(),
                taint: TaintSet::of(TaintSource::ModelOutput),
            })
        } else {
            None
        };
        Poll::Ready(Ok(event))
    }
}

impl StateWatch for GeneratedWatch {
    type Subscription = GeneratedSubscription;
    type Subscribe<'a> = Ready<StateResult<Self::Subscription>>;

    fn subscribe<'a>(&'a self, topic: &'a Path) -> Self::Subscribe<'a> {
        ready(Ok(GeneratedSubscription {
            topic: topic.clone(),
            delivered: 0,
            total: self.0,
            deleted: false,
        }))
    }
}

#[tokio::test]
async fn default_subscription_passes_the_former_limit_through_one_leased_credit() -> Result<()> {
    const TOTAL: u64 = 2053;
    let state = Backend::default().with_watch(Arc::new(GeneratedWatch(TOTAL)));
    let driver = EventBusDriver::new(state);
    let (sink, mut receiver) =
        xolotl_kernel::host::stream::channel(xolotl_kernel::stream::StreamWindow {
            max_chunks: std::num::NonZeroUsize::MIN,
            max_inline_bytes: std::num::NonZeroUsize::new(256).context("nonzero window")?,
        });
    let context = ctx().with_stream(Path::parse("state://stream/continued")?, sink);
    let producer = async move {
        let result = driver
            .call(
                MethodId::new(1),
                Value::map(BTreeMap::from([(
                    "topic".into(),
                    Value::string("continued".into()),
                )])),
                OutputMode::Stream,
                &context,
            )
            .await;
        drop(context);
        result
    };
    let consumer = async {
        for sequence in 0..TOTAL {
            let Some(xolotl_kernel::host::stream::StreamItem::Chunk(chunk)) = receiver.recv().await
            else {
                anyhow::bail!("subscription ended before event {sequence}");
            };
            ensure!(chunk.into_value() == TaintedValue::pristine(Value::integer(sequence as i64)));
        }
        Ok::<_, anyhow::Error>(())
    };
    let (output, consumed) = tokio::join!(producer, consumer);
    consumed?;
    let output = output?;
    ensure!(output.outcome == Outcome::Done(Value::string(TOTAL.to_string())));
    ensure!(output.taint == TaintSet::of(TaintSource::ModelOutput));
    Ok(())
}

#[tokio::test]
async fn explicit_zero_returns_without_installing_or_observing_state_watch() -> Result<()> {
    let driver = EventBusDriver::new(Backend::default());
    let input_sources = TaintSet::of(TaintSource::ModelOutput);
    let output = driver
        .call(
            MethodId::new(1),
            Value::map(BTreeMap::from([
                ("topic".into(), Value::string("unused".into())),
                ("max_events".into(), Value::integer(0)),
            ])),
            OutputMode::Stream,
            &ctx().with_taint(input_sources.clone()),
        )
        .await?;
    ensure!(output.outcome == Outcome::Done(Value::string("0".into())));
    ensure!(output.taint == input_sources);
    Ok(())
}
