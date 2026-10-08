//! Host-composable TLS incoming adapter for tonic. The channel binding stays
//! attached to the exact accepted socket through tonic's `Connected` extension.

use std::{
    future::Future as _,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use futures_util::{Stream, StreamExt as _};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::OwnedSemaphorePermit,
    time::{Instant, Sleep},
};
use tokio_rustls::server::TlsStream;
use tonic::{Status, transport::server::Connected};

use crate::{runtime::FederationGrpcRuntime, tls::FederationTlsChannel};

/// Tonic clones connection metadata for RPC requests. The channel is consumed
/// once: another RPC on the same TLS connection cannot reuse its proof.
#[derive(Clone)]
pub struct FederationTlsConnectInfo {
    channel: Arc<Mutex<Option<(FederationTlsChannel, OwnedSemaphorePermit)>>>,
}

impl FederationTlsConnectInfo {
    pub(crate) fn take_channel(
        &self,
    ) -> Result<(FederationTlsChannel, OwnedSemaphorePermit), Status> {
        self.channel
            .lock()
            .map_err(|_error| Status::unauthenticated("federation connection state failed"))?
            .take()
            .ok_or_else(|| Status::unauthenticated("federation channel already used"))
    }
}

/// An accepted TLS socket. Until its Session starts, dropping it releases
/// shared runtime admission. The Session then owns that charge until it ends.
pub struct FederationTlsStream<IO> {
    stream: TlsStream<IO>,
    info: FederationTlsConnectInfo,
    read_idle: Pin<Box<Sleep>>,
    write_stall: Option<Pin<Box<Sleep>>>,
    io_timeout: Duration,
}

impl<IO> FederationTlsStream<IO> {
    fn poll_write_stall(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let timer = self
            .write_stall
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(self.io_timeout)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "federation TLS write stalled",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<IO> Connected for FederationTlsStream<IO> {
    type ConnectInfo = FederationTlsConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for FederationTlsStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        match Pin::new(&mut this.stream).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                if buffer.filled().len() > before {
                    this.read_idle
                        .as_mut()
                        .reset(Instant::now() + this.io_timeout);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match this.read_idle.as_mut().poll(cx) {
                Poll::Ready(()) => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "federation TLS read idle timeout",
                ))),
                Poll::Pending => Poll::Pending,
            },
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for FederationTlsStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.stream).poll_write(cx, bytes) {
            Poll::Ready(Ok(written)) => {
                this.write_stall = None;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match this.poll_write_stall(cx) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                _ => Poll::Pending,
            },
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.stream).poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                this.write_stall = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => this.poll_write_stall(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.stream).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => {
                this.write_stall = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => this.poll_write_stall(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.stream).poll_write_vectored(cx, buffers) {
            Poll::Ready(Ok(written)) => {
                this.write_stall = None;
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => match this.poll_write_stall(cx) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                _ => Poll::Pending,
            },
        }
    }
}

/// Stream of fully checked TLS connections passed to the tonic server. The
/// connection extension retains the same rustls exporter as its Session.
pub type FederationIncoming<IO> =
    Pin<Box<dyn Stream<Item = io::Result<FederationTlsStream<IO>>> + Send>>;

/// Accept only full TLS 1.3 hybrid sessions before tonic sees any bytes.
/// The host supplies the bind/listener and its reviewed ML-DSA certificate
/// configuration. A failed or slow handshake is dropped, not passed as a
/// plaintext or partially authenticated gRPC connection.
/// The runtime shares admission with outbound dials and publisher actors.
/// An accepted connection transfers its charged permit with the one-use TLS
/// proof; it is not charged again when its Session RPC starts.
pub fn federation_tls_incoming<S, IO>(
    incoming: S,
    tls: Arc<rustls::ServerConfig>,
    runtime: FederationGrpcRuntime,
) -> Result<FederationIncoming<IO>, Status>
where
    S: Stream<Item = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = runtime.config();
    if tls.alpn_protocols.as_slice() != [b"h2".to_vec()]
        || tls.max_early_data_size != 0
        || tls.send_half_rtt_data
        || tls.send_tls13_tickets != 0
        || tls.max_tls13_tickets != 0
        || tls.ticketer.enabled()
    {
        return Err(Status::failed_precondition(
            "federation TLS server must disable early data and resumption and require h2",
        ));
    }
    let stream = incoming
        .map(move |incoming| {
            let tls = Arc::clone(&tls);
            let runtime = runtime.clone();
            async move {
                let io = incoming?;
                let permit = runtime.admit().map_err(|_error| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "federation connection limit reached",
                    )
                })?;
                let stream = tokio::time::timeout(
                    config.tls_handshake_timeout,
                    tokio_rustls::TlsAcceptor::from(tls).accept(io),
                )
                .await
                .map_err(|_error| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "federation TLS handshake timed out",
                    )
                })??;
                let channel = FederationTlsChannel::from_server_tls(stream.get_ref().1).map_err(
                    |_error| {
                        io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "federation TLS profile rejected",
                        )
                    },
                )?;
                Ok::<_, io::Error>(FederationTlsStream {
                    stream,
                    info: FederationTlsConnectInfo {
                        channel: Arc::new(Mutex::new(Some((channel, permit)))),
                    },
                    read_idle: Box::pin(tokio::time::sleep(config.response_timeout)),
                    write_stall: None,
                    io_timeout: config.response_timeout,
                })
            }
        })
        .buffer_unordered(config.max_sessions)
        .filter_map(|accepted| async move {
            match accepted {
                Ok(stream) => Some(Ok(stream)),
                Err(error) => {
                    tracing::warn!(%error, "federation connection admission rejected");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    None
                }
            }
        });
    Ok(Box::pin(stream))
}
