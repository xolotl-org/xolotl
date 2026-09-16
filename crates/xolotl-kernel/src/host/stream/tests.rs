use super::*;
use crate::stream::{send, try_send};
use anyhow::{Context as _, ensure};
use std::future::{Future, poll_fn};
use std::num::NonZeroUsize;
use std::pin::Pin;
use xolotl_types::{BlobRef, Value};

fn window(chunks: usize, bytes: usize) -> anyhow::Result<StreamWindow> {
    Ok(StreamWindow {
        max_chunks: NonZeroUsize::new(chunks).context("zero chunk limit")?,
        max_inline_bytes: NonZeroUsize::new(bytes).context("zero byte limit")?,
    })
}

async fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

async fn chunk(receiver: &mut StreamReceiver) -> anyhow::Result<StreamChunk> {
    match receiver.recv().await {
        Some(StreamItem::Chunk(chunk)) => Ok(chunk),
        _ => anyhow::bail!("expected a data chunk"),
    }
}

#[tokio::test]
async fn borrowed_chunks_retain_chunk_and_byte_credits() -> anyhow::Result<()> {
    let value = TaintedValue::pristine(Value::integer(1));
    let bytes = encoded_charge(&value, usize::MAX)?;
    let (sink, mut receiver) = channel(window(2, bytes * 2 - 1)?);
    send(sink.as_ref(), value.clone()).await?;
    let leased = chunk(&mut receiver).await?;
    ensure!(try_send(sink.as_ref(), value.clone()) == Err(StreamSendError::Full(value.clone())));
    let pending = send(sink.as_ref(), value.clone());
    tokio::pin!(pending);
    ensure!(poll_once(pending.as_mut()).await.is_pending());
    ensure!(sink.shared.lock().bytes == bytes);
    drop(leased);
    pending.await?;
    ensure!(chunk(&mut receiver).await?.into_value() == value);
    ensure!(sink.shared.lock().chunks == 0);
    ensure!(sink.shared.lock().bytes == 0);
    Ok(())
}

#[tokio::test]
async fn million_chunks_reuse_a_fixed_resident_window() -> anyhow::Result<()> {
    const COUNT: i64 = 1_000_000;
    let (sink, mut receiver) = channel(window(1, 256)?);
    let producer = async {
        for index in 0..COUNT {
            send(sink.as_ref(), TaintedValue::pristine(Value::integer(index))).await?;
            let state = sink.shared.lock();
            ensure!(state.chunks == 1 && state.bytes <= 256);
        }
        sink.close(StreamEnd {
            outcome: Ok(()),
            taint: TaintSet::pristine(),
            origin: CompletionOrigin::CurrentAttempt,
        });
        Ok::<_, anyhow::Error>(())
    };
    let consumer = async {
        for index in 0..COUNT {
            let chunk = chunk(&mut receiver).await?;
            ensure!(chunk.value.value == Value::integer(index));
        }
        ensure!(matches!(
            receiver.recv().await,
            Some(StreamItem::End(StreamEnd {
                outcome: Ok(()),
                ..
            }))
        ));
        Ok::<_, anyhow::Error>(())
    };
    let (produced, consumed) = tokio::join!(producer, consumer);
    produced?;
    consumed?;
    let state = sink.shared.lock();
    ensure!(state.chunks == 0 && state.bytes == 0 && state.send_waiters.is_empty());
    Ok(())
}

#[tokio::test]
async fn oversized_inline_chunks_are_distinct_from_large_object_references() -> anyhow::Result<()> {
    let (sink, mut receiver) = channel(window(2, 1024)?);
    let large = TaintedValue::pristine(Value::bytes(vec![0; 2048]));
    ensure!(matches!(
        send(sink.as_ref(), large.clone()).await,
        Err(StreamSendError::Rejected {
            value,
            reason,
        }) if value == large && *reason == StreamRejection::InlineBytesExceeded { limit: 1024 }
    ));
    let reference = TaintedValue::pristine(Value::blob(BlobRef {
        hash: "a".repeat(64),
        size: u64::MAX,
        mime: None,
    }));
    send(sink.as_ref(), reference.clone()).await?;
    ensure!(chunk(&mut receiver).await?.into_value() == reference);
    Ok(())
}

#[tokio::test]
async fn terminal_is_accepted_while_full_and_waits_for_borrowed_chunks() -> anyhow::Result<()> {
    let (sink, mut receiver) = channel(window(1, 1024)?);
    let value = TaintedValue::pristine(Value::integer(1));
    send(sink.as_ref(), value.clone()).await?;
    let expected = StreamEnd {
        outcome: Ok(()),
        taint: TaintSet::author(),
        origin: CompletionOrigin::CurrentAttempt,
    };
    let mut terminal = Some(expected.clone());
    poll_fn(|cx| sink.poll_finish(cx, &mut terminal)).await?;
    ensure!(terminal.is_none());
    sink.close(StreamEnd {
        outcome: Err(Failure::Cancelled),
        taint: TaintSet::pristine(),
        origin: CompletionOrigin::CurrentAttempt,
    });
    ensure!(try_send(sink.as_ref(), value.clone()) == Err(StreamSendError::Closed(value)));
    let leased = chunk(&mut receiver).await?;
    let next = receiver.recv();
    tokio::pin!(next);
    ensure!(poll_once(next.as_mut()).await.is_pending());
    drop(leased);
    ensure!(matches!(next.await, Some(StreamItem::End(end)) if end == expected));
    Ok(())
}

#[tokio::test]
async fn cancelling_waiters_removes_registration_without_waiting_for_capacity() -> anyhow::Result<()>
{
    let (sink, mut receiver) = channel(window(1, 1024)?);
    let value = TaintedValue::pristine(Value::integer(1));
    send(sink.as_ref(), value.clone()).await?;
    for _ in 0..256 {
        let mut pending = Box::pin(send(sink.as_ref(), value.clone()));
        ensure!(poll_once(pending.as_mut()).await.is_pending());
        ensure!(sink.shared.lock().send_waiters.len() == 1);
        drop(pending);
        ensure!(sink.shared.lock().send_waiters.is_empty());
    }
    let mut first = Box::pin(send(sink.as_ref(), value.clone()));
    let mut second = Box::pin(send(sink.as_ref(), value.clone()));
    ensure!(poll_once(first.as_mut()).await.is_pending());
    ensure!(poll_once(second.as_mut()).await.is_pending());
    ensure!(sink.shared.lock().send_waiters.len() == 2);
    drop(first);
    ensure!(sink.shared.lock().send_waiters.len() == 1);
    drop(chunk(&mut receiver).await?);
    second.await?;
    ensure!(chunk(&mut receiver).await?.into_value() == value);
    Ok(())
}

#[tokio::test]
async fn receiver_close_wakes_pending_send_and_retains_its_value() -> anyhow::Result<()> {
    let (sink, receiver) = channel(window(1, 1024)?);
    let value = TaintedValue::pristine(Value::integer(1));
    send(sink.as_ref(), value.clone()).await?;
    let pending = send(sink.as_ref(), value.clone());
    tokio::pin!(pending);
    ensure!(poll_once(pending.as_mut()).await.is_pending());
    drop(receiver);
    ensure!(pending.await == Err(StreamSendError::Closed(value)));
    poll_fn(|cx| sink.poll_closed(cx)).await;
    ensure!(sink.shared.lock().send_waiters.is_empty());
    Ok(())
}
