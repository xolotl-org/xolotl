use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tonic::metadata::MetadataMap;
use tonic::transport::server::TcpConnectInfo;
use tonic::{Request, Status};
use xolotl_gateway::{GatewayTransportSecurityConfig, GatewayTransportSecurityMode};

/// Facts supplied by the host after a TLS handshake has completed and passed
/// its protocol, key-exchange, cipher-suite and certificate checks.
#[derive(Clone, Debug)]
pub struct GrpcTlsConnectionInfo {
    peer_certificates: Arc<Vec<Vec<u8>>>,
}

impl GrpcTlsConnectionInfo {
    /// Retain the certificate chain already validated by the host TLS adapter.
    /// Constructing this value alone does not perform certificate validation.
    pub fn new(peer_certificates: Vec<Vec<u8>>) -> Self {
        Self {
            peer_certificates: Arc::new(peer_certificates),
        }
    }

    /// Borrow the validated peer chain without copying certificate bytes.
    pub fn peer_certificates(&self) -> &[Vec<u8>] {
        &self.peer_certificates
    }
}

/// Connection metadata inserted by a host-owned transport adapter.
#[derive(Clone, Debug)]
pub struct GrpcConnectionInfo {
    /// Socket metadata supplied by tonic for this connection.
    pub tcp: TcpConnectInfo,
    /// Completed TLS facts, if this connection passed the host TLS boundary.
    pub tls: Option<GrpcTlsConnectionInfo>,
}

impl GrpcConnectionInfo {
    /// Remote socket address reported by the connected TCP transport.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.tcp.remote_addr()
    }
}

pub(crate) fn grpc_remote_addr<T>(request: &Request<T>) -> Option<SocketAddr> {
    match request.extensions().get::<GrpcConnectionInfo>() {
        Some(info) => info.remote_addr(),
        None => request.remote_addr(),
    }
}

pub(crate) fn grpc_peer_certificates<T>(request: &Request<T>) -> Option<&[Vec<u8>]> {
    request
        .extensions()
        .get::<GrpcConnectionInfo>()
        .and_then(|info| info.tls.as_ref())
        .map(GrpcTlsConnectionInfo::peer_certificates)
}

pub(crate) fn verified_grpc_tls_boundary<T>(
    request: &Request<T>,
    mode: GatewayTransportSecurityMode,
) -> bool {
    match mode {
        GatewayTransportSecurityMode::ProductionTls => request
            .extensions()
            .get::<GrpcConnectionInfo>()
            .is_some_and(|info| info.tls.is_some()),
        GatewayTransportSecurityMode::MutualTls => {
            grpc_peer_certificates(request).is_some_and(|certificates| !certificates.is_empty())
        }
        _ => true,
    }
}

pub(crate) fn verified_grpc_source_addr(
    metadata: &MetadataMap,
    peer: Option<IpAddr>,
    transport: &GatewayTransportSecurityConfig,
) -> Result<Option<String>, Status> {
    if transport.trusts_peer(peer) && transport.trusted_proxy.honor_x_forwarded_for {
        match forwarded_client_addr(metadata) {
            Ok(Some(forwarded)) => return Ok(Some(forwarded)),
            Ok(None) => {}
            Err(ForwardedHeaderError::InvalidHeaderValue) => {
                return Err(Status::permission_denied("request rejected"));
            }
        }
    }
    Ok(peer.map(|ip| ip.to_string()))
}

pub(crate) fn validate_grpc_transport(
    metadata: &MetadataMap,
    peer: Option<IpAddr>,
    transport: &GatewayTransportSecurityConfig,
) -> Option<&'static str> {
    if let Some(outcome) = transport_denial_outcome(peer, transport) {
        return Some(outcome);
    }
    if matches!(
        transport.mode,
        GatewayTransportSecurityMode::TrustedReverseProxy
    ) && transport.trusted_proxy.honor_x_forwarded_proto
    {
        let proto = match forwarded_grpc_proto(metadata, peer, transport) {
            Ok(Some(proto)) => proto,
            Ok(None) => return Some("proto_required"),
            Err(ForwardedHeaderError::InvalidHeaderValue) => return Some("proto_invalid"),
        };
        if !secure_forwarded_proto(&proto) {
            return Some("proto_denied");
        }
    }
    None
}

fn forwarded_grpc_proto(
    metadata: &MetadataMap,
    peer: Option<IpAddr>,
    transport: &GatewayTransportSecurityConfig,
) -> Result<Option<String>, ForwardedHeaderError> {
    if !transport.trusts_peer(peer) {
        return Ok(None);
    }
    if let Some(value) = single_metadata_value(metadata, "x-forwarded-proto")? {
        return single_forwarded_value(value);
    }
    match single_metadata_value(metadata, "forwarded")? {
        Some(value) => forwarded_header_param(value, "proto"),
        None => Ok(None),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ForwardedHeaderError {
    InvalidHeaderValue,
}

fn single_metadata_value<'a>(
    metadata: &'a MetadataMap,
    name: &'static str,
) -> Result<Option<&'a str>, ForwardedHeaderError> {
    let mut values = metadata.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ForwardedHeaderError::InvalidHeaderValue);
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_error| ForwardedHeaderError::InvalidHeaderValue)
}

fn secure_forwarded_proto(proto: &str) -> bool {
    matches!(
        proto.trim().to_ascii_lowercase().as_str(),
        "https" | "wss" | "grpcs"
    )
}

fn forwarded_client_addr(metadata: &MetadataMap) -> Result<Option<String>, ForwardedHeaderError> {
    if let Some(value) = single_metadata_value(metadata, "x-forwarded-for")?
        .or(single_metadata_value(metadata, "x-real-ip")?)
    {
        return single_forwarded_value(value);
    }
    match single_metadata_value(metadata, "forwarded")? {
        Some(value) => forwarded_header_for(value),
        None => Ok(None),
    }
}

fn forwarded_header_for(value: &str) -> Result<Option<String>, ForwardedHeaderError> {
    Ok(forwarded_header_param(value, "for")?
        .filter(|value| !(value.eq_ignore_ascii_case("unknown") || value.starts_with('_'))))
}

pub(crate) fn forwarded_header_param(
    value: &str,
    expected_name: &str,
) -> Result<Option<String>, ForwardedHeaderError> {
    // We cannot know which element a proxy appended. Accepting the first
    // element would let client-supplied values hide the direct proxy's facts.
    if value.contains(',') {
        return Err(ForwardedHeaderError::InvalidHeaderValue);
    }
    let mut found = None;
    for part in value.split(';') {
        let (name, raw_value) = part
            .split_once('=')
            .ok_or(ForwardedHeaderError::InvalidHeaderValue)?;
        if !name.trim().eq_ignore_ascii_case(expected_name) {
            continue;
        }
        if found.is_some() {
            return Err(ForwardedHeaderError::InvalidHeaderValue);
        }
        let raw_value = raw_value.trim();
        let value = if let Some(quoted) = raw_value.strip_prefix('"') {
            quoted
                .strip_suffix('"')
                .ok_or(ForwardedHeaderError::InvalidHeaderValue)?
        } else {
            raw_value
        };
        if value.is_empty() || value.contains('"') || value.contains('\\') {
            return Err(ForwardedHeaderError::InvalidHeaderValue);
        }
        found = Some(value.to_string());
    }
    Ok(found)
}

pub(crate) fn single_forwarded_value(value: &str) -> Result<Option<String>, ForwardedHeaderError> {
    if value.contains(',') {
        return Err(ForwardedHeaderError::InvalidHeaderValue);
    }
    Ok(Some(value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string))
}

fn transport_denial_outcome(
    peer: Option<IpAddr>,
    transport: &GatewayTransportSecurityConfig,
) -> Option<&'static str> {
    match transport.mode {
        GatewayTransportSecurityMode::ProductionTls | GatewayTransportSecurityMode::MutualTls => {
            None
        }
        GatewayTransportSecurityMode::TrustedReverseProxy => {
            (!transport.trusts_peer(peer)).then_some("transport_untrusted_proxy")
        }
        GatewayTransportSecurityMode::LocalTrusted => {
            (!peer.is_some_and(|ip| ip.is_loopback())).then_some("transport_not_local")
        }
        GatewayTransportSecurityMode::UnsafePlaintext
        | GatewayTransportSecurityMode::DisabledForTest => None,
    }
}
