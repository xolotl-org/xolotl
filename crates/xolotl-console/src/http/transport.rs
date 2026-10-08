//! HTTP origin, host and trusted proxy admission.

use axum::http::{HeaderMap, HeaderName, header};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

pub(crate) fn validate_upgrade_headers(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<(), String> {
    validate_origin_headers("console websocket", headers, peer, transport).map(|_| ())
}

pub(crate) fn validate_http_auth_headers(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<String, String> {
    validate_origin_headers("console http auth", headers, peer, transport)
}

/// Admit a host-verified, explicitly configured automation client only when
/// `Origin` is wholly absent. A supplied origin always receives normal checks.
pub(crate) fn validate_http_request_headers(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    transport: &crate::ConsoleTransportSecurityConfig,
    allow_originless: bool,
) -> Result<(), String> {
    if allow_originless && !headers.contains_key(header::ORIGIN) {
        let label = "console http auth";
        let trusted_proxy = transport.trusts_peer(peer.map(|p| p.ip()));
        let host = external_host(label, headers, trusted_proxy, transport)?;
        OriginParts::parse_host(host, label)?;
        external_forwarded_proto(label, headers, trusted_proxy, transport)?;
        return Ok(());
    }
    validate_http_auth_headers(headers, peer, transport).map(|_| ())
}

fn validate_origin_headers(
    label: &str,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<String, String> {
    let origin = required_single_header(label, "origin", &header::ORIGIN, headers)?;
    let parsed_origin = OriginParts::parse(origin, label)?;
    let trusted_proxy = transport.trusts_peer(peer.map(|p| p.ip()));
    let external_host = external_host(label, headers, trusted_proxy, transport)?;
    let external = OriginParts::parse_host(external_host, label)?;
    let external_proto = external_forwarded_proto(label, headers, trusted_proxy, transport)?;

    if transport.relaxed_origin() {
        return Ok(origin.into());
    }
    if !same_host(parsed_origin.host, external.host) {
        return Err(format!("{label} origin is not allowed"));
    }
    if !transport.ignore_origin_port()
        && effective_port(parsed_origin.scheme, parsed_origin.port)
            != effective_port(parsed_origin.scheme, external.port)
    {
        return Err(format!("{label} origin port is not allowed"));
    }
    if let Some(proto) = external_proto
        && parsed_origin.scheme != proto
    {
        return Err(format!("{label} origin scheme is not allowed"));
    }
    Ok(origin.into())
}

fn required_single_header<'a>(
    label: &str,
    field: &str,
    name: &HeaderName,
    headers: &'a HeaderMap,
) -> Result<&'a str, String> {
    let mut values = headers.get_all(name).iter();
    let value = values
        .next()
        .ok_or_else(|| format!("{label} {field} header is required"))?;
    if values.next().is_some() {
        return Err(format!("{label} {field} header is malformed"));
    }
    let value = value
        .to_str()
        .map_err(|_error| format!("{label} {field} header is malformed"))?;
    if value.is_empty() || value.contains(',') {
        return Err(format!("{label} {field} header is malformed"));
    }
    Ok(value)
}

fn effective_port(scheme: &str, port: Option<u16>) -> u16 {
    port.unwrap_or(if scheme == "https" { 443 } else { 80 })
}

fn same_host(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
        || left
            .parse::<Ipv6Addr>()
            .ok()
            .zip(right.parse::<Ipv6Addr>().ok())
            .is_some_and(|(left, right)| left == right)
}

#[derive(Debug, Eq, PartialEq)]
struct OriginParts<'a> {
    scheme: &'a str,
    host: &'a str,
    port: Option<u16>,
}

impl<'a> OriginParts<'a> {
    fn parse(origin: &'a str, label: &str) -> Result<Self, String> {
        let (scheme, rest) = origin
            .split_once("://")
            .ok_or_else(|| format!("{label} origin is malformed"))?;
        if !matches!(scheme, "http" | "https") {
            return Err(format!("{label} origin scheme is unsupported"));
        }
        if rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err(format!("{label} origin is malformed"));
        }
        let mut parsed = Self::parse_host(rest, label)?;
        parsed.scheme = scheme;
        Ok(parsed)
    }

    fn parse_host(authority: &'a str, label: &str) -> Result<Self, String> {
        if authority.is_empty() {
            return Err(format!("{label} host header is required"));
        }
        if authority.bytes().any(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'/' | b'?' | b'#' | b'@' | b'\\')
        }) {
            return Err(format!("{label} host header is malformed"));
        }
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            let (host, rest) = stripped
                .split_once(']')
                .ok_or_else(|| format!("{label} host header is malformed"))?;
            host.parse::<Ipv6Addr>()
                .map_err(|_error| format!("{label} host header is malformed"))?;
            let port = match rest.strip_prefix(':') {
                Some(port) => Some(parse_origin_port(port, label)?),
                None if rest.is_empty() => None,
                None => return Err(format!("{label} host header is malformed")),
            };
            (host, port)
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if host.contains(':') || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                return Err(format!("{label} host header is malformed"));
            }
            (host, Some(parse_origin_port(port, label)?))
        } else {
            (authority, None)
        };
        if host.is_empty() || host.contains('[') || host.contains(']') {
            return Err(format!("{label} host header is malformed"));
        }
        Ok(Self {
            scheme: "",
            host,
            port,
        })
    }
}

fn parse_origin_port(raw: &str, label: &str) -> Result<u16, String> {
    if raw.is_empty() {
        return Err(format!("{label} host header is malformed"));
    }
    raw.parse::<u16>()
        .map_err(|_error| format!("{label} host header is malformed"))
}

fn external_host<'a>(
    label: &str,
    headers: &'a HeaderMap,
    trusted_proxy: bool,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<&'a str, String> {
    // Even when a trusted proxy supplies the external authority, the HTTP
    // request itself must carry one unambiguous Host header.
    let host = required_single_header(label, "host", &header::HOST, headers)?;
    OriginParts::parse_host(host, label)?;
    if trusted_proxy
        && transport.trusted_proxy.honor_x_forwarded_host
        && let Some(host) = single_forwarded_header(label, "x-forwarded-host", headers)?
    {
        return Ok(host);
    }
    Ok(host)
}

fn external_forwarded_proto<'a>(
    label: &str,
    headers: &'a HeaderMap,
    trusted_proxy: bool,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Result<Option<&'a str>, String> {
    if !(trusted_proxy && transport.trusted_proxy.honor_x_forwarded_proto) {
        return Ok(None);
    }
    let Some(proto) = single_forwarded_header(label, "x-forwarded-proto", headers)? else {
        return Ok(None);
    };
    if !matches!(proto, "http" | "https") {
        return Err(format!("{label} x-forwarded-proto header is unsupported"));
    }
    Ok(Some(proto))
}

// Authority headers are overwritten by the trusted proxy, never interpreted as
// chains. Selecting either end would silently trust a client-supplied value.
fn single_forwarded_header<'a>(
    label: &str,
    name: &str,
    headers: &'a HeaderMap,
) -> Result<Option<&'a str>, String> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(format!("{label} {name} header is malformed"));
    }
    let value = value
        .to_str()
        .map_err(|_error| format!("{label} {name} header is malformed"))?
        .trim();
    if value.is_empty() || value.contains(',') {
        return Err(format!("{label} {name} header is malformed"));
    }
    Ok(Some(value))
}

pub(crate) fn verified_source_addr(
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> String {
    let peer_ip = peer.map(|peer| peer.ip());
    if transport.trusts_peer(peer_ip)
        && transport.trusted_proxy.honor_x_forwarded_for
        && let Some(forwarded) = forwarded_client_addr(headers, transport)
    {
        return forwarded.to_string();
    }
    peer_ip
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn forwarded_client_addr(
    headers: &HeaderMap,
    transport: &crate::ConsoleTransportSecurityConfig,
) -> Option<IpAddr> {
    if !headers.contains_key("x-forwarded-for") {
        return single_forwarded_header("console", "x-real-ip", headers)
            .ok()??
            .parse()
            .ok();
    }
    // Only the trusted suffix has provenance. HeaderMap preserves value order;
    // traverse both repeated fields and their comma-separated addresses in reverse.
    // Stop before inspecting any prefix supplied by the first untrusted hop.
    let mut source = None;
    for value in headers.get_all("x-forwarded-for").iter().rev() {
        for address in value.as_bytes().rsplit(|byte| *byte == b',') {
            let address = std::str::from_utf8(address).ok()?.trim().parse().ok()?;
            source = Some(address);
            if !transport.trusts_peer(source) {
                return source;
            }
        }
    }
    // A malformed trusted suffix returns None immediately above. In particular,
    // never fall back to X-Real-IP after any X-Forwarded-For was supplied.
    source
}

#[cfg(test)]
pub(crate) fn source_addr(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    verified_source_addr(headers, peer, &crate::http::console_transport_default())
}

#[cfg(test)]
mod tests;
