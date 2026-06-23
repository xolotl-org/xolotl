use crate::GatewayError;
use std::net::{IpAddr, Ipv6Addr};

/// Browser origin registered for a gateway listener.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GatewayAllowedOrigin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl GatewayAllowedOrigin {
    /// Parse an HTTP(S) origin without path, query, or fragment.
    pub fn parse(origin: &str) -> Result<Self, GatewayError> {
        let origin = origin.trim();
        let (scheme, rest) = origin
            .split_once("://")
            .ok_or_else(|| GatewayError::InvalidProfile("origin must include scheme".into()))?;
        if rest.is_empty() || rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err(GatewayError::InvalidProfile(
                "origin must not include path, query, or fragment".into(),
            ));
        }
        let scheme = scheme.to_ascii_lowercase();
        if !matches!(scheme.as_str(), "http" | "https") {
            return Err(GatewayError::InvalidProfile(
                "origin scheme must be http or https".into(),
            ));
        }
        let (host, port) = parse_origin_authority(rest)?;
        let host = host.to_ascii_lowercase();
        if host.trim().is_empty() {
            return Err(GatewayError::InvalidProfile(
                "origin host must not be empty".into(),
            ));
        }
        let port = normalize_origin_port(&scheme, port);
        Ok(Self { scheme, host, port })
    }

    /// Return true when `origin` matches this registered origin.
    pub fn matches(&self, origin: &str, ignore_port: bool) -> bool {
        let Ok(candidate) = Self::parse(origin) else {
            return false;
        };
        self.scheme == candidate.scheme
            && self.host == candidate.host
            && (ignore_port || self.port == candidate.port)
    }

    /// Return true when this origin is a loopback/localhost HTTP(S) origin.
    pub fn is_local_trusted(&self) -> bool {
        matches!(self.scheme.as_str(), "http" | "https")
            && (self.host == "localhost"
                || self
                    .host
                    .parse::<IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false))
    }

    /// Return the canonical string form used in diagnostics.
    pub fn as_str(&self) -> String {
        match self.port {
            Some(port) => format!("{}://{}:{port}", self.scheme, self.host),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// Return true when an Origin header matches the registered origin set.
pub fn browser_origin_allowed(
    origin: &str,
    registered_origins: &[GatewayAllowedOrigin],
    ignore_port: bool,
) -> bool {
    registered_origins
        .iter()
        .any(|registered| registered.matches(origin, ignore_port))
}

/// Return true when an Origin header is acceptable for a local trust boundary.
pub fn local_trusted_browser_origin(origin: &str) -> bool {
    GatewayAllowedOrigin::parse(origin).is_ok_and(|origin| origin.is_local_trusted())
}

/// Gateway Host/SNI authority registered for a listener profile.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct GatewayAllowedHost {
    host: String,
    port: Option<u16>,
}

impl GatewayAllowedHost {
    /// Parse a host authority without scheme, path, query, or fragment.
    pub fn parse(authority: &str) -> Result<Self, GatewayError> {
        let authority = authority.trim();
        if authority.is_empty()
            || authority.contains("://")
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
        {
            return Err(GatewayError::InvalidProfile(
                "gateway host must be host[:port] without scheme, path, or userinfo".into(),
            ));
        }
        let (host, port) = parse_origin_authority(authority)?;
        let host = host.to_ascii_lowercase();
        if host.trim().is_empty()
            || host.chars().any(|ch| ch.is_ascii_whitespace())
            || host.contains('*')
            || (host.contains(':') && host.parse::<Ipv6Addr>().is_err())
        {
            return Err(GatewayError::InvalidProfile(
                "gateway host authority is invalid".into(),
            ));
        }
        Ok(Self { host, port })
    }

    /// Return true when `authority` matches this registered Host/SNI authority.
    pub fn matches(&self, authority: &str) -> bool {
        let Ok(candidate) = Self::parse(authority) else {
            return false;
        };
        self.host == candidate.host && self.port == candidate.port
    }

    /// Return the canonical string form used in diagnostics.
    pub fn as_str(&self) -> String {
        let host = if self.host.parse::<Ipv6Addr>().is_ok() {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.port {
            Some(port) => format!("{host}:{port}"),
            None => host,
        }
    }
}

/// Return true when a Host/SNI authority matches the registered host set.
pub fn gateway_host_allowed(authority: &str, registered_hosts: &[GatewayAllowedHost]) -> bool {
    registered_hosts
        .iter()
        .any(|registered| registered.matches(authority))
}

fn parse_origin_authority(authority: &str) -> Result<(&str, Option<u16>), GatewayError> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err(GatewayError::InvalidProfile(
            "origin authority must not be empty".into(),
        ));
    }
    if let Some(stripped) = authority.strip_prefix('[') {
        let (host, rest) = stripped.split_once(']').ok_or_else(|| {
            GatewayError::InvalidProfile("origin IPv6 host is missing closing bracket".into())
        })?;
        let port = match rest.strip_prefix(':') {
            Some(port) if !port.is_empty() => Some(parse_origin_port(port)?),
            Some(_) => {
                return Err(GatewayError::InvalidProfile(
                    "origin port must not be empty".into(),
                ));
            }
            None if rest.is_empty() => None,
            None => {
                return Err(GatewayError::InvalidProfile(
                    "origin authority has invalid IPv6 suffix".into(),
                ));
            }
        };
        return Ok((host, port));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, Some(parse_origin_port(port)?)),
        _ => (authority, None),
    };
    Ok((host, port))
}

fn parse_origin_port(port: &str) -> Result<u16, GatewayError> {
    port.parse::<u16>()
        .map_err(|_error| GatewayError::InvalidProfile("origin port is invalid".into()))
}

fn normalize_origin_port(scheme: &str, port: Option<u16>) -> Option<u16> {
    match (scheme, port) {
        ("http", Some(80)) | ("https", Some(443)) => None,
        (_, port) => port,
    }
}

/// Transport boundary declared for a gateway listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayTransportSecurityMode {
    /// The listener terminates TLS itself.
    ProductionTls,
    /// The listener terminates TLS and verifies client certificates.
    MutualTls,
    /// TLS terminates at a configured reverse proxy.
    TrustedReverseProxy,
    /// Plain transport is accepted only across a local trust boundary.
    LocalTrusted,
    /// Plain transport is explicitly accepted for this listener.
    UnsafePlaintext,
    /// Transport checks are disabled for tests.
    DisabledForTest,
}

impl GatewayTransportSecurityMode {
    /// Return the stable configuration name for this mode.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProductionTls => "production_tls",
            Self::MutualTls => "mtls",
            Self::TrustedReverseProxy => "trusted_reverse_proxy",
            Self::LocalTrusted => "local_trusted",
            Self::UnsafePlaintext => "unsafe_plaintext",
            Self::DisabledForTest => "disabled_for_test",
        }
    }
}

/// Explicit transport-security relaxations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayUnsafeTransportRelaxation {
    /// Accept a plain HTTP/WS or HTTP/2 backend hop.
    AllowPlaintext,
    /// Ignore the port component when checking browser origins.
    IgnoreOriginPort,
    /// Disable browser Origin matching.
    RelaxedOrigin,
}

impl GatewayUnsafeTransportRelaxation {
    /// Return the stable configuration name for this relaxation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllowPlaintext => "allow_plaintext",
            Self::IgnoreOriginPort => "ignore_origin_port",
            Self::RelaxedOrigin => "relaxed_origin",
        }
    }
}

/// Trusted reverse-proxy handling for gateway transports.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayTrustedProxyConfig {
    /// Direct peer IP addresses allowed to supply forwarded headers.
    pub peers: Vec<IpAddr>,
    /// Whether `X-Forwarded-Proto` is accepted from trusted peers.
    pub honor_x_forwarded_proto: bool,
    /// Whether `X-Forwarded-Host` is accepted from trusted peers.
    pub honor_x_forwarded_host: bool,
    /// Whether `X-Forwarded-For` and `X-Real-IP` are accepted from trusted peers.
    pub honor_x_forwarded_for: bool,
}

impl Default for GatewayTrustedProxyConfig {
    fn default() -> Self {
        Self {
            peers: Vec::new(),
            honor_x_forwarded_proto: true,
            honor_x_forwarded_host: true,
            honor_x_forwarded_for: true,
        }
    }
}

/// Transport security and proxy policy for gateway listeners.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayTransportSecurityConfig {
    /// Declared transport boundary mode.
    pub mode: GatewayTransportSecurityMode,
    /// Trusted proxy peers and forwarded-header policy.
    pub trusted_proxy: GatewayTrustedProxyConfig,
    /// Explicit unsafe transport relaxations.
    pub unsafe_relaxations: Vec<GatewayUnsafeTransportRelaxation>,
}

impl Default for GatewayTransportSecurityConfig {
    fn default() -> Self {
        Self {
            mode: GatewayTransportSecurityMode::LocalTrusted,
            trusted_proxy: GatewayTrustedProxyConfig::default(),
            unsafe_relaxations: Vec::new(),
        }
    }
}

impl GatewayTransportSecurityConfig {
    /// Normalize set-like fields.
    pub fn bounded(mut self) -> Self {
        self.unsafe_relaxations.sort_by_key(|r| r.as_str());
        self.unsafe_relaxations.dedup();
        self.trusted_proxy.peers.sort();
        self.trusted_proxy.peers.dedup();
        self
    }

    /// Return true when this config explicitly accepts unsafe transport state.
    pub fn is_unsafe(&self) -> bool {
        matches!(self.mode, GatewayTransportSecurityMode::UnsafePlaintext)
            || !self.unsafe_relaxations.is_empty()
    }

    /// Return true when `peer` is allowed to supply forwarded headers.
    pub fn trusts_peer(&self, peer: Option<IpAddr>) -> bool {
        matches!(self.mode, GatewayTransportSecurityMode::TrustedReverseProxy)
            && peer.is_some_and(|ip| self.trusted_proxy.peers.contains(&ip))
    }

    /// Return true when browser Origin checks may ignore port mismatches.
    pub fn ignore_origin_port(&self) -> bool {
        self.unsafe_relaxations
            .contains(&GatewayUnsafeTransportRelaxation::IgnoreOriginPort)
    }

    /// Return true when browser Origin checks are disabled.
    pub fn relaxed_origin(&self) -> bool {
        self.unsafe_relaxations
            .contains(&GatewayUnsafeTransportRelaxation::RelaxedOrigin)
    }

    /// Return stable names for configured unsafe relaxations.
    pub fn unsafe_relaxation_names(&self) -> Vec<String> {
        self.unsafe_relaxations
            .iter()
            .map(|r| r.as_str().to_string())
            .collect()
    }
}
