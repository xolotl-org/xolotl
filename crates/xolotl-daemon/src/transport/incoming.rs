use futures_util::{Stream, StreamExt};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::server::TlsStream;
use tonic::transport::server::{Connected, TcpConnectInfo};
use xolotl_gateway_grpc::{GrpcConnectionInfo, GrpcTlsConnectionInfo};

const GRPC_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const GRPC_CONCURRENT_HANDSHAKES: usize = 64;

pub(crate) enum GrpcConnection<IO> {
    Plain(IO),
    Tls {
        stream: Box<TlsStream<IO>>,
        info: GrpcConnectionInfo,
    },
}

impl<IO> Connected for GrpcConnection<IO>
where
    IO: Connected<ConnectInfo = TcpConnectInfo>,
{
    type ConnectInfo = GrpcConnectionInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        match self {
            Self::Plain(io) => GrpcConnectionInfo {
                tcp: io.connect_info(),
                tls: None,
            },
            Self::Tls { info, .. } => info.clone(),
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for GrpcConnection<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(io) => Pin::new(io).poll_read(cx, buffer),
            Self::Tls { stream, .. } => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for GrpcConnection<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(io) => Pin::new(io).poll_write(cx, bytes),
            Self::Tls { stream, .. } => Pin::new(stream).poll_write(cx, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(io) => Pin::new(io).poll_flush(cx),
            Self::Tls { stream, .. } => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(io) => Pin::new(io).poll_shutdown(cx),
            Self::Tls { stream, .. } => Pin::new(stream).poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(io) => io.is_write_vectored(),
            Self::Tls { stream, .. } => stream.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(io) => Pin::new(io).poll_write_vectored(cx, buffers),
            Self::Tls { stream, .. } => Pin::new(stream).poll_write_vectored(cx, buffers),
        }
    }
}

/// Complete each TLS handshake before handing the socket to tonic. A bounded
/// number of handshakes may run concurrently so slow peers do not serialize
/// listener admission. Failed handshakes never reach a Gateway service.
pub(crate) fn grpc_incoming<IO, S>(
    incoming: S,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> impl Stream<Item = io::Result<GrpcConnection<IO>>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Connected<ConnectInfo = TcpConnectInfo> + Send + 'static,
    S: Stream<Item = io::Result<IO>>,
{
    incoming
        .map(move |incoming| {
            let tls = tls.clone();
            async move {
                let io = incoming?;
                let Some(config) = tls else {
                    return Ok::<_, io::Error>(GrpcConnection::Plain(io));
                };
                let tcp = io.connect_info();
                let stream = tokio::time::timeout(
                    GRPC_TLS_HANDSHAKE_TIMEOUT,
                    tokio_rustls::TlsAcceptor::from(config).accept(io),
                )
                .await
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("gRPC TLS handshake timed out: {error}"),
                    )
                })??;
                let info = verified_tls_connection_info(tcp, &stream)?;
                Ok(GrpcConnection::Tls {
                    stream: Box::new(stream),
                    info,
                })
            }
        })
        .buffer_unordered(GRPC_CONCURRENT_HANDSHAKES)
        .filter_map(|result| async move {
            match result {
                Ok(connection) => Some(Ok(connection)),
                Err(error) => {
                    tracing::warn!(%error, "gRPC connection admission rejected");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    None
                }
            }
        })
}

fn verified_tls_connection_info<IO>(
    tcp: TcpConnectInfo,
    stream: &TlsStream<IO>,
) -> io::Result<GrpcConnectionInfo> {
    let (_, session) = stream.get_ref();
    let accepted = session.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
        && session.handshake_kind() == Some(rustls::HandshakeKind::Full)
        && session.alpn_protocol() == Some(b"h2".as_slice())
        && session
            .negotiated_key_exchange_group()
            .is_some_and(|group| group.name() == rustls::NamedGroup::X25519MLKEM768)
        && session.negotiated_cipher_suite().is_some_and(|suite| {
            matches!(
                suite.suite(),
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                    | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            )
        });
    if !accepted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "gRPC TLS handshake did not satisfy the post-quantum profile",
        ));
    }
    let certificates = session.peer_certificates().unwrap_or_default();
    let total_bytes: usize = certificates.iter().map(|cert| cert.as_ref().len()).sum();
    if certificates.len() > 8 || total_bytes > 128 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "gRPC client certificate chain exceeds admission limit",
        ));
    }
    let peer_certificates = certificates
        .iter()
        .map(|certificate| certificate.as_ref().to_vec())
        .collect();
    Ok(GrpcConnectionInfo {
        tcp,
        tls: Some(GrpcTlsConnectionInfo::new(peer_certificates)),
    })
}
