//! Cancellation reaches socket I/O before TLS and HTTP/2 protocol admission.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tonic::transport::server::Connected;

pub(super) struct ApplicationConnection {
    stream: TcpStream,
    shutdown: Pin<Box<dyn Future<Output = ()> + Send>>,
    closed: bool,
}

impl ApplicationConnection {
    pub(super) fn new(stream: TcpStream, mut shutdown: watch::Receiver<bool>) -> Self {
        let closed = *shutdown.borrow();
        Self {
            stream,
            shutdown: Box::pin(async move {
                super::wait_for_shutdown(&mut shutdown).await;
            }),
            closed,
        }
    }

    fn open_stream(&mut self, cx: &mut Context<'_>) -> io::Result<&mut TcpStream> {
        if !self.closed && self.shutdown.as_mut().poll(cx).is_ready() {
            self.closed = true;
        }
        if self.closed {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "application Gateway connection closed",
            ));
        }
        Ok(&mut self.stream)
    }
}

impl Connected for ApplicationConnection {
    type ConnectInfo = <TcpStream as Connected>::ConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}

impl AsyncRead for ApplicationConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().open_stream(cx)?).poll_read(cx, buffer)
    }
}

impl AsyncWrite for ApplicationConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().open_stream(cx)?).poll_write(cx, bytes)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().open_stream(cx)?).poll_write_vectored(cx, buffers)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().open_stream(cx)?).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().open_stream(cx)?).poll_shutdown(cx)
    }
}
