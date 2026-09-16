//! Bounded host channels implementing the portable output contracts.

use crate::stream::{
    StreamEnd, StreamError, StreamRejection, StreamRouter, StreamSendError, StreamSendRequest,
    StreamSink, StreamWindow,
};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::ops::Deref;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use tokio::sync::mpsc;
use xolotl_types::{CompletionOrigin, Failure, TaintSet, TaintedValue};

/// A host output edge that can cross executor threads.
pub type DynStreamSink = Arc<dyn StreamSink + Send + Sync>;

/// A host router creates a separate sink for every operation.
pub type DynStreamRouter = Arc<dyn StreamRouter<Sink = DynStreamSink> + Send + Sync>;

impl<S: StreamSink + ?Sized> StreamSink for Arc<S> {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        request: &mut StreamSendRequest,
    ) -> Poll<Result<(), StreamSendError<TaintedValue>>> {
        (**self).poll_send(cx, request)
    }

    fn cancel_send(&self, request: &mut StreamSendRequest) {
        (**self).cancel_send(request);
    }

    fn poll_finish(
        &self,
        cx: &mut Context<'_>,
        end: &mut Option<StreamEnd>,
    ) -> Poll<Result<(), StreamError>> {
        (**self).poll_finish(cx, end)
    }

    fn close(&self, end: StreamEnd) {
        (**self).close(end);
    }

    fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        (**self).poll_closed(cx)
    }
}

/// Build a stream with independent data credits and a terminal slot.
/// Inline charging uses the lossless tagged JSON encoding of the entire
/// `TaintedValue`, including provenance. It is not an allocator/RSS estimate.
/// Blob, tensor, and frame references charge only their inline metadata.
pub fn channel(window: StreamWindow) -> (Arc<ChannelSink>, StreamReceiver) {
    let (tx, rx) = mpsc::channel(window.max_chunks.get());
    let shared = Arc::new(Mutex::new(Shared {
        window,
        chunks: 0,
        bytes: 0,
        accepting: true,
        receiver_open: true,
        terminal: None,
        next_waiter: 0,
        send_waiters: BTreeMap::new(),
        reader: None,
        closed: None,
    }));
    (
        Arc::new(ChannelSink {
            tx,
            shared: shared.clone(),
        }),
        StreamReceiver {
            rx,
            shared,
            ended: false,
        },
    )
}

struct Shared {
    window: StreamWindow,
    chunks: usize,
    bytes: usize,
    accepting: bool,
    receiver_open: bool,
    terminal: Option<StreamEnd>,
    next_waiter: u64,
    send_waiters: BTreeMap<u64, Waker>,
    reader: Option<Waker>,
    closed: Option<Waker>,
}

impl Shared {
    fn register(&mut self, request: &mut StreamSendRequest, waker: &Waker) {
        let id = match request.registration() {
            Some(id) => id,
            None => {
                while self.send_waiters.contains_key(&self.next_waiter) {
                    self.next_waiter = self.next_waiter.wrapping_add(1);
                }
                let id = self.next_waiter;
                self.next_waiter = self.next_waiter.wrapping_add(1);
                request.set_registration(id);
                id
            }
        };
        self.send_waiters.insert(id, waker.clone());
    }

    fn unregister(&mut self, request: &mut StreamSendRequest) {
        if let Some(id) = request.take_registration() {
            self.send_waiters.remove(&id);
        }
    }
}

/// Sender for one stream lifecycle. Sends never grow the resident data window.
pub struct ChannelSink {
    tx: mpsc::Sender<StreamChunk>,
    shared: Arc<Mutex<Shared>>,
}

impl ChannelSink {
    fn accept_terminal(&self, end: &mut Option<StreamEnd>) -> Result<(), StreamError> {
        let (reader, senders, closed) = {
            let mut state = self.shared.lock();
            if !state.receiver_open || !state.accepting {
                return Err(StreamError::Closed);
            }
            let Some(end) = end.take() else {
                return Ok(());
            };
            state.accepting = false;
            state.terminal = Some(end);
            (
                state.reader.take(),
                std::mem::take(&mut state.send_waiters),
                state.closed.take(),
            )
        };
        wake_all(reader, senders, closed);
        Ok(())
    }
}

impl StreamSink for ChannelSink {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        request: &mut StreamSendRequest,
    ) -> Poll<Result<(), StreamSendError<TaintedValue>>> {
        let Some(chunk) = request.chunk() else {
            return Poll::Ready(Ok(()));
        };
        let limit = self.shared.lock().window.max_inline_bytes.get();
        let charge = encoded_charge(chunk, limit);
        let mut state = self.shared.lock();
        if !state.receiver_open || !state.accepting {
            state.unregister(request);
            return Poll::Ready(match request.take_chunk() {
                Some(chunk) => Err(StreamSendError::Closed(chunk)),
                None => Ok(()),
            });
        }
        let bytes = match charge {
            Ok(bytes) => bytes,
            Err(reason) => {
                state.unregister(request);
                return Poll::Ready(match request.take_chunk() {
                    Some(value) => Err(StreamSendError::Rejected {
                        value,
                        reason: Box::new(reason),
                    }),
                    None => Ok(()),
                });
            }
        };
        if state.chunks == state.window.max_chunks.get()
            || bytes > state.window.max_inline_bytes.get() - state.bytes
        {
            state.register(request, cx.waker());
            return Poll::Pending;
        }
        state.unregister(request);
        let Some(value) = request.take_chunk() else {
            return Poll::Ready(Ok(()));
        };
        state.chunks += 1;
        state.bytes += bytes;
        drop(state);
        let chunk = StreamChunk {
            value,
            credit: Credit {
                shared: self.shared.clone(),
                bytes,
            },
        };
        // Data credits include reservations and borrowed chunks, so the
        // underlying queue always has a slot for an accepted reservation.
        Poll::Ready(self.tx.try_send(chunk).map_err(|error| match error {
            mpsc::error::TrySendError::Full(chunk) => StreamSendError::Full(chunk.into_value()),
            mpsc::error::TrySendError::Closed(chunk) => StreamSendError::Closed(chunk.into_value()),
        }))
    }

    fn cancel_send(&self, request: &mut StreamSendRequest) {
        if request.registration().is_some() {
            self.shared.lock().unregister(request);
        }
    }

    fn poll_finish(
        &self,
        _cx: &mut Context<'_>,
        end: &mut Option<StreamEnd>,
    ) -> Poll<Result<(), StreamError>> {
        Poll::Ready(self.accept_terminal(end))
    }

    fn close(&self, end: StreamEnd) {
        drop(self.accept_terminal(&mut Some(end)));
    }

    fn poll_closed(&self, cx: &mut Context<'_>) -> Poll<()> {
        let mut state = self.shared.lock();
        if !state.receiver_open || !state.accepting {
            Poll::Ready(())
        } else {
            state.closed = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Drop for ChannelSink {
    fn drop(&mut self) {
        self.close(StreamEnd {
            outcome: Err(Failure::Cancelled),
            taint: TaintSet::pristine(),
            origin: CompletionOrigin::CurrentAttempt,
        });
    }
}

struct Credit {
    shared: Arc<Mutex<Shared>>,
    bytes: usize,
}

impl Drop for Credit {
    fn drop(&mut self) {
        let (reader, senders) = {
            let mut state = self.shared.lock();
            state.chunks -= 1;
            state.bytes -= self.bytes;
            (state.reader.take(), std::mem::take(&mut state.send_waiters))
        };
        wake_all(reader, senders, None);
    }
}

/// A received chunk holds its data credits until released by the consumer.
pub struct StreamChunk {
    value: TaintedValue,
    credit: Credit,
}

impl Deref for StreamChunk {
    type Target = TaintedValue;
    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl StreamChunk {
    /// Transfer the envelope out of the window and acknowledge this chunk.
    /// Any retention after this call is explicitly owned by the caller.
    pub fn into_value(self) -> TaintedValue {
        let Self { value, credit } = self;
        drop(credit);
        value
    }
}

/// Ordered stream data or its separate terminal record.
pub enum StreamItem {
    /// A leased chunk with its own provenance.
    Chunk(StreamChunk),
    /// The terminal, delivered after all earlier chunks have been released.
    End(StreamEnd),
}

/// Single receiving edge for an operation's output stream.
pub struct StreamReceiver {
    rx: mpsc::Receiver<StreamChunk>,
    shared: Arc<Mutex<Shared>>,
    ended: bool,
}

impl StreamReceiver {
    /// Receive the next chunk or terminal, waiting only for available output.
    pub async fn recv(&mut self) -> Option<StreamItem> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }

    /// Poll without allocating a receive future.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<StreamItem>> {
        if self.ended {
            return Poll::Ready(None);
        }
        if let Poll::Ready(Some(chunk)) = self.rx.poll_recv(cx) {
            return Poll::Ready(Some(StreamItem::Chunk(chunk)));
        }
        let mut state = self.shared.lock();
        if state.chunks == 0
            && let Some(end) = state.terminal.take()
        {
            self.ended = true;
            return Poll::Ready(Some(StreamItem::End(end)));
        }
        state.reader = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl Drop for StreamReceiver {
    fn drop(&mut self) {
        let (senders, closed) = {
            let mut state = self.shared.lock();
            state.receiver_open = false;
            state.terminal = None;
            state.reader = None;
            (std::mem::take(&mut state.send_waiters), state.closed.take())
        };
        wake_all(None, senders, closed);
    }
}

fn wake_all(reader: Option<Waker>, senders: BTreeMap<u64, Waker>, closed: Option<Waker>) {
    if let Some(waker) = reader {
        waker.wake();
    }
    for (_, waker) in senders {
        waker.wake();
    }
    if let Some(waker) = closed {
        waker.wake();
    }
}

fn encoded_charge(value: &TaintedValue, limit: usize) -> Result<usize, StreamRejection> {
    struct Count {
        bytes: usize,
        limit: usize,
        exceeded: bool,
    }
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit - self.bytes {
                self.exceeded = true;
                return Err(io::Error::other("inline byte limit exceeded"));
            }
            self.bytes += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count {
        bytes: 0,
        limit,
        exceeded: false,
    };
    match serde_json::to_writer(&mut count, value) {
        Ok(()) => Ok(count.bytes),
        Err(_) if count.exceeded => Err(StreamRejection::InlineBytesExceeded { limit }),
        Err(error) => Err(StreamRejection::Encoding {
            message: error.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests;
