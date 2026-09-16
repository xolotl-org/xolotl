use super::{Config, Work};
use anyhow::ensure;
use futures_util::FutureExt;
use std::{num::NonZeroUsize, sync::Arc};
use xolotl_kernel::{
    host::stream::{StreamItem, channel},
    stream::{StreamEnd, StreamSink, StreamWindow, send, try_send},
};
use xolotl_types::{CompletionOrigin, TaintSet, TaintedValue, Value};

pub async fn run(config: &Config, cancel: bool) -> anyhow::Result<Work> {
    let (sink, mut receiver) = channel(StreamWindow {
        max_chunks: NonZeroUsize::MIN,
        max_inline_bytes: config.window,
    });
    let weak = Arc::downgrade(&sink);
    let count = config.work.get();
    let producer = async {
        for index in 0..count {
            send(
                &sink,
                TaintedValue::pristine(Value::integer(i64::try_from(index)?)),
            )
            .await
            .map_err(|error| anyhow::anyhow!("stream send: {error:?}"))?;
        }
        Ok::<_, anyhow::Error>(())
    };
    let consumer = async {
        for index in 0..count {
            let Some(StreamItem::Chunk(chunk)) = receiver.recv().await else {
                anyhow::bail!("missing chunk")
            };
            ensure!(chunk.value.as_int() == Some(index as i64));
            if index % config.slow_every.get() == 0 {
                // Retain the actual receive lease while the producer waits for credit.
                if config.delay_micros == 0 {
                    tokio::task::yield_now().await;
                } else {
                    tokio::time::sleep(std::time::Duration::from_micros(config.delay_micros)).await;
                }
            }
            drop(chunk);
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::try_join!(producer, consumer)?;
    if cancel {
        send(&sink, TaintedValue::pristine(Value::integer(7)))
            .await
            .map_err(|error| anyhow::anyhow!("cancellation setup: {error:?}"))?;
        let mut blocked = Box::pin(send(&sink, TaintedValue::pristine(Value::integer(8))));
        ensure!(blocked.as_mut().now_or_never().is_none());
        drop(receiver);
        ensure!(blocked.await.is_err());
    } else {
        sink.close(StreamEnd {
            outcome: Ok(()),
            taint: TaintSet::pristine(),
            origin: CompletionOrigin::CurrentAttempt,
        });
        let Some(StreamItem::End(end)) = receiver.recv().await else {
            anyhow::bail!("missing terminal")
        };
        ensure!(end.outcome.is_ok());
        ensure!(receiver.recv().await.is_none());
        drop(receiver);
    }
    ensure!(try_send(&sink, TaintedValue::pristine(Value::null())).is_err());
    drop(sink);
    ensure!(
        weak.upgrade().is_none(),
        "channel owner retained after teardown"
    );
    // The weak allocation itself is also released inside this measured operation.
    drop(weak);
    Ok(Work {
        units: u64::try_from(count)?,
        unit: "chunks through one leased credit, including slow-consumer polls",
    })
}
