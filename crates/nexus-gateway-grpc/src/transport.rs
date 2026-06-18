use nexus_gateway::{GatewayTransportSecurityConfig, GatewayTransportSecurityMode};
use std::net::IpAddr;
use tonic::Status;
use tonic::metadata::MetadataMap;

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
    if let Some(value) = metadata.get("x-forwarded-proto") {
        return value
            .to_str()
            .map_err(|_| ForwardedHeaderError::InvalidHeaderValue)
            .map(first_forwarded_value);
    }
    match metadata.get("forwarded") {
        Some(value) => value
            .to_str()
            .map_err(|_| ForwardedHeaderError::InvalidHeaderValue)
            .map(|value| forwarded_header_param(value, "proto")),
        None => Ok(None),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ForwardedHeaderError {
    InvalidHeaderValue,
}

fn secure_forwarded_proto(proto: &str) -> bool {
    matches!(
        proto.trim().to_ascii_lowercase().as_str(),
        "https" | "wss" | "grpcs"
    )
}

fn forwarded_client_addr(metadata: &MetadataMap) -> Result<Option<String>, ForwardedHeaderError> {
    if let Some(value) = metadata
        .get("x-forwarded-for")
        .or_else(|| metadata.get("x-real-ip"))
    {
        return value
            .to_str()
            .map_err(|_| ForwardedHeaderError::InvalidHeaderValue)
            .map(first_forwarded_value);
    }
    match metadata.get("forwarded") {
        Some(value) => value
            .to_str()
            .map_err(|_| ForwardedHeaderError::InvalidHeaderValue)
            .map(forwarded_header_for),
        None => Ok(None),
    }
}

fn forwarded_header_for(value: &str) -> Option<String> {
    forwarded_header_param(value, "for").and_then(|value| {
        if value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
            None
        } else {
            Some(value)
        }
    })
}

fn forwarded_header_param(value: &str, expected_name: &str) -> Option<String> {
    let first = value.split(',').next()?.trim();
    for part in first.split(';') {
        let Some((name, raw_value)) = part.split_once('=') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case(expected_name) {
            continue;
        }
        let value = raw_value.trim().trim_matches('"').trim();
        if value.is_empty() {
            return None;
        }
        return Some(value.to_string());
    }
    None
}

fn first_forwarded_value(value: &str) -> Option<String> {
    value
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
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
            (peer.is_some() && !transport.trusts_peer(peer)).then_some("transport_untrusted_proxy")
        }
        GatewayTransportSecurityMode::LocalTrusted => peer
            .is_some_and(|ip| !ip.is_loopback())
            .then_some("transport_not_local"),
        GatewayTransportSecurityMode::UnsafePlaintext
        | GatewayTransportSecurityMode::DisabledForTest => None,
    }
}
