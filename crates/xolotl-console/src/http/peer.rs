//! Verified connection provenance for HTTP and WebSocket adapters.

use super::HttpFailure;
use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{StatusCode, request::Parts},
};
use std::{net::SocketAddr, sync::Arc};

/// A source verified by an embedding host outside TCP, such as a Unix socket.
///
/// Attach this as an Axum `Extension` only after the host has established the
/// connection's identity. Its source participates in audit and rate limits; it
/// does not make client-supplied forwarded headers trustworthy. When all clients
/// on a local socket share one trust boundary, one extension may cover that
/// route set. Otherwise, attach a different value per verified connection.
#[derive(Clone, Debug)]
pub struct HttpPeer {
    source: Arc<str>,
}

impl HttpPeer {
    /// Name a host-verified, non-TCP source. The host owns the verification.
    /// Names are bounded and prefixed to keep them separate from IP sources.
    pub fn verified_source(source: impl AsRef<str>) -> Result<Self, HttpPeerError> {
        let source = source.as_ref();
        if source.is_empty()
            || source.len() > 128
            || source
                .chars()
                .any(|ch| ch.is_control() || ch.is_whitespace())
        {
            return Err(HttpPeerError::InvalidSource);
        }
        Ok(Self {
            source: Arc::from(format!("embedded:{source}")),
        })
    }
}

/// Identity for one accepted TCP connection. Use
/// `into_make_service_with_connect_info::<HttpTcpConnection>()` to issue it once
/// per connection; `ConnectInfo<HttpTcpConnection>` then appears on its requests.
/// The address alone may be reused and cannot identify an automation verdict.
#[derive(Clone, Debug)]
pub struct HttpTcpConnection {
    peer: SocketAddr,
    identity: Arc<()>,
}

impl HttpTcpConnection {
    /// Record the actual socket peer of one newly accepted connection.
    pub fn new(peer: SocketAddr) -> Self {
        Self {
            peer,
            identity: Arc::new(()),
        }
    }
}

impl
    axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, tokio::net::TcpListener>>
    for HttpTcpConnection
{
    fn connect_info(stream: axum::serve::IncomingStream<'_, tokio::net::TcpListener>) -> Self {
        Self::new(*stream.remote_addr())
    }
}

/// Host-verified automation client allowed to omit `Origin` on HTTP routes
/// when the adapter explicitly enables that policy. This is a connection
/// verdict, never a request header or an account authorization grant.
///
/// Attach it as an Axum `Extension` only at a trusted connection boundary,
/// after verifying that the client is an automation client. The constructor's
/// peer must match the connection provenance used by Console on each request.
#[derive(Clone, Debug)]
pub struct VerifiedAutomationClient {
    peer: AutomationPeer,
}

#[derive(Clone, Debug)]
enum AutomationPeer {
    Tcp(HttpTcpConnection),
    Host(Arc<str>),
}

impl VerifiedAutomationClient {
    /// Bind a host verification decision to this TCP connection instance.
    pub fn for_tcp_connection(connection: &HttpTcpConnection) -> Self {
        Self {
            peer: AutomationPeer::Tcp(connection.clone()),
        }
    }

    /// Bind a host verification decision to this `HttpPeer` instance (or its
    /// clones). Recreating the same source name does not reproduce the verdict.
    pub fn for_host_peer(peer: &HttpPeer) -> Self {
        Self {
            peer: AutomationPeer::Host(peer.source.clone()),
        }
    }

    fn matches(&self, peer: &VerifiedPeer, connection: Option<&HttpTcpConnection>) -> bool {
        match (&self.peer, peer) {
            (AutomationPeer::Tcp(expected), VerifiedPeer::Tcp(actual)) => {
                connection.is_some_and(|connection| {
                    expected.peer == *actual
                        && Arc::ptr_eq(&expected.identity, &connection.identity)
                })
            }
            (AutomationPeer::Host(expected), VerifiedPeer::Host(actual)) => {
                Arc::ptr_eq(expected, &actual.source)
            }
            _ => false,
        }
    }
}

/// An invalid host-provided peer name.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HttpPeerError {
    /// Source names must be nonempty, at most 128 bytes, and contain no whitespace or controls.
    #[error("invalid verified HTTP peer source")]
    InvalidSource,
}

/// The only provenance accepted by Console routes. Both forms at once are
/// ambiguous, and absence is rejected before any authentication or dispatch.
pub(crate) enum VerifiedPeer {
    Tcp(SocketAddr),
    Host(HttpPeer),
    AutomationTcp(SocketAddr),
    AutomationHost(HttpPeer),
}

impl VerifiedPeer {
    pub(crate) fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Tcp(addr) | Self::AutomationTcp(addr) => Some(*addr),
            Self::Host(_) | Self::AutomationHost(_) => None,
        }
    }

    pub(crate) fn is_verified_automation(&self) -> bool {
        matches!(self, Self::AutomationTcp(_) | Self::AutomationHost(_))
    }

    pub(crate) fn source(
        &self,
        headers: &axum::http::HeaderMap,
        transport: &crate::ConsoleTransportSecurityConfig,
    ) -> String {
        match self {
            Self::Tcp(addr) | Self::AutomationTcp(addr) => {
                super::transport::verified_source_addr(headers, Some(*addr), transport)
            }
            Self::Host(peer) | Self::AutomationHost(peer) => peer.source.to_string(),
        }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for VerifiedPeer {
    type Rejection = HttpFailure;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let host = parts.extensions.get::<HttpPeer>();
        let tcp = parts.extensions.get::<ConnectInfo<SocketAddr>>();
        let connection = parts
            .extensions
            .get::<ConnectInfo<HttpTcpConnection>>()
            .map(|info| &info.0);
        let peer = match (host, tcp, connection) {
            (Some(host), None, None) => Self::Host(host.clone()),
            (None, Some(tcp), None) => Self::Tcp(tcp.0),
            (None, None, Some(connection)) => Self::Tcp(connection.peer),
            (None, None, None) => {
                return Err((
                    StatusCode::FORBIDDEN,
                    String::from("console connection provenance is required"),
                )
                    .into());
            }
            _ => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    String::from("ambiguous console connection provenance"),
                )
                    .into());
            }
        };
        if let Some(automation) = parts.extensions.get::<VerifiedAutomationClient>() {
            if !automation.matches(&peer, connection) {
                return Err((
                    StatusCode::FORBIDDEN,
                    String::from(
                        "automation client verification does not match connection provenance",
                    ),
                )
                    .into());
            }
            return Ok(match peer {
                Self::Tcp(addr) | Self::AutomationTcp(addr) => Self::AutomationTcp(addr),
                Self::Host(peer) | Self::AutomationHost(peer) => Self::AutomationHost(peer),
            });
        }
        Ok(peer)
    }
}
