//! Pull-driven object reads with one bounded window and owned pending storage.

use prost::bytes::{Bytes, BytesMut};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tonic::Status;
use tonic::codegen::tokio_stream::Stream;
use xolotl_gateway::GatewayObjectDownload;
use xolotl_proto::xolotl::v1::application as pb;
use xolotl_types::TaintSet;

use super::gateway_status;
use super::wire::download as wire;

type ReadFuture = Pin<Box<dyn Future<Output = Result<Box<Window>, Status>> + Send>>;
type FinishFuture =
    Pin<Box<dyn Future<Output = Result<pb::DownloadObjectResponse, Status>> + Send>>;

struct Window {
    download: GatewayObjectDownload,
    buffer: Bytes,
    filled: usize,
    sent: usize,
    offset: u64,
    taint: TaintSet,
}

enum State {
    Ready(Box<Window>),
    Reading(ReadFuture),
    Finishing(FinishFuture),
    Done,
}

/// One authenticated download, advanced only while tonic polls its response.
/// Dropping the stream drops any pending read and its owner. The ingress Body
/// retains the response permit through encoded DATA and HTTP/2 backpressure.
pub struct ApplicationObjectDownloadStream {
    header: Option<pb::DownloadObjectResponse>,
    state: State,
    max_frame_bytes: usize,
    read_window_bytes: usize,
    storage_timeout: Duration,
}

impl ApplicationObjectDownloadStream {
    pub(super) fn new(
        download: GatewayObjectDownload,
        max_frame_bytes: usize,
        storage_timeout: Duration,
    ) -> Result<Self, Status> {
        let header = wire::header_to_pb(&download, max_frame_bytes)?;
        Ok(Self {
            header: Some(header),
            state: State::Ready(Box::new(Window {
                download,
                buffer: Bytes::new(),
                filled: 0,
                sent: 0,
                offset: 0,
                taint: TaintSet::pristine(),
            })),
            max_frame_bytes,
            read_window_bytes: max_frame_bytes.min(16 * 1024),
            storage_timeout,
        })
    }
}

impl Stream for ApplicationObjectDownloadStream {
    type Item = Result<pb::DownloadObjectResponse, Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            match std::mem::replace(&mut this.state, State::Done) {
                State::Done => return Poll::Ready(None),
                State::Ready(mut window) => {
                    if let Err(error) = window.download.validate() {
                        return Poll::Ready(Some(Err(gateway_status(error))));
                    }
                    if let Some(header) = this.header.take() {
                        this.state = State::Ready(window);
                        return Poll::Ready(Some(Ok(header)));
                    }
                    if window.sent < window.filled {
                        let offset = window.offset + window.sent as u64;
                        let frame = wire::chunk_to_pb(
                            offset,
                            window.buffer.slice(window.sent..window.filled),
                            &window.taint,
                            this.max_frame_bytes,
                        );
                        return match frame {
                            Ok((frame, count)) => {
                                window.sent += count;
                                this.state = State::Ready(window);
                                Poll::Ready(Some(Ok(frame)))
                            }
                            Err(error) => Poll::Ready(Some(Err(error))),
                        };
                    }
                    let timeout = this.storage_timeout;
                    if window.download.is_complete() {
                        let next_offset = window.download.next_offset();
                        let bytes_read = next_offset - window.download.start_offset();
                        let max_frame_bytes = this.max_frame_bytes;
                        this.state = State::Finishing(Box::pin(async move {
                            tokio::time::timeout(timeout, window.download.finish())
                                .await
                                .map_err(|_error| storage_timeout())?
                                .map_err(gateway_status)?;
                            wire::completed_to_pb(next_offset, bytes_read, max_frame_bytes)
                        }));
                    } else {
                        let read_window_bytes = this.read_window_bytes;
                        this.state = State::Reading(Box::pin(async move {
                            let mut buffer = window
                                .buffer
                                .try_into_mut()
                                .unwrap_or_else(|_shared| BytesMut::zeroed(read_window_bytes));
                            buffer.resize(read_window_bytes, 0);
                            window.offset = window.download.next_offset();
                            let read =
                                tokio::time::timeout(timeout, window.download.read(&mut buffer))
                                    .await
                                    .map_err(|_error| storage_timeout())?
                                    .map_err(gateway_status)?;
                            window.buffer = buffer.freeze();
                            window.filled = read.bytes_read;
                            window.sent = 0;
                            window.taint = read.taint;
                            Ok(window)
                        }));
                    }
                }
                State::Reading(mut future) => match future.as_mut().poll(cx) {
                    Poll::Pending => {
                        this.state = State::Reading(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(window)) => this.state = State::Ready(window),
                    Poll::Ready(Err(error)) => return Poll::Ready(Some(Err(error))),
                },
                State::Finishing(mut future) => match future.as_mut().poll(cx) {
                    Poll::Pending => {
                        this.state = State::Finishing(future);
                        return Poll::Pending;
                    }
                    Poll::Ready(result) => return Poll::Ready(Some(result)),
                },
            }
        }
    }
}

fn storage_timeout() -> Status {
    Status::deadline_exceeded("object storage wait expired")
}
