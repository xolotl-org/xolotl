//! Host listener security and TLS construction shared by Gateway transports.

use anyhow::{Context, Result};
use serde::Deserialize;
#[cfg(any(feature = "external-grpc", feature = "application-grpc"))]
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use xolotl_gateway::{
    GatewayTransportSecurityConfig, GatewayTransportSecurityMode, GatewayTrustedProxyConfig,
    GatewayUnsafeTransportRelaxation,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayTransportSecurityTuning {
    #[serde(default = "default_gateway_transport_security_mode")]
    pub mode: String,
    #[serde(default)]
    pub trusted_proxy_peers: Vec<String>,
    #[serde(default = "default_true")]
    pub honor_x_forwarded_proto: bool,
    #[serde(default = "default_true")]
    pub honor_x_forwarded_host: bool,
    #[serde(default = "default_true")]
    pub honor_x_forwarded_for: bool,
    #[serde(default)]
    pub unsafe_relaxations: Vec<String>,
    pub certificate_chain_path: Option<String>,
    pub private_key_path: Option<String>,
    #[serde(default)]
    pub client_trust_roots: Vec<String>,
}

impl Default for GatewayTransportSecurityTuning {
    fn default() -> Self {
        Self {
            mode: default_gateway_transport_security_mode(),
            trusted_proxy_peers: Vec::new(),
            honor_x_forwarded_proto: true,
            honor_x_forwarded_host: true,
            honor_x_forwarded_for: true,
            unsafe_relaxations: Vec::new(),
            certificate_chain_path: None,
            private_key_path: None,
            client_trust_roots: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GatewayListenerSecurity {
    pub listen_addr: SocketAddr,
    pub config: GatewayTransportSecurityConfig,
    #[cfg(any(feature = "external-grpc", feature = "application-grpc"))]
    pub tls: Option<GatewayListenerTlsMaterial>,
}

#[cfg(any(feature = "external-grpc", feature = "application-grpc"))]
#[derive(Debug, Clone)]
pub struct GatewayListenerTlsMaterial {
    pub certificate_chain_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    pub client_trust_roots_pem: Vec<u8>,
}

impl GatewayTransportSecurityTuning {
    #[cfg(feature = "external-websocket")]
    pub fn validate_plain_listener(
        &self,
        label: &str,
        listen_addr: &str,
    ) -> Result<GatewayListenerSecurity> {
        self.validate_plain_listener_inner(label, listen_addr, cfg!(test))
    }

    #[cfg(any(feature = "external-grpc", feature = "application-grpc"))]
    pub fn validate_grpc_listener(
        &self,
        label: &str,
        listen_addr: &str,
    ) -> Result<GatewayListenerSecurity> {
        self.validate_grpc_listener_inner(label, listen_addr, cfg!(test))
    }

    #[cfg(feature = "external-websocket")]
    pub(crate) fn validate_plain_listener_inner(
        &self,
        label: &str,
        listen_addr: &str,
        allow_disabled_for_test: bool,
    ) -> Result<GatewayListenerSecurity> {
        let listen_addr = listen_addr.parse::<SocketAddr>().with_context(|| {
            format!("{label} listen address '{listen_addr}' must be an IP socket address")
        })?;
        let config = self.to_gateway_transport_security_config(label)?;
        match config.mode {
            GatewayTransportSecurityMode::ProductionTls => {
                self.validate_tls_material(label, false)?;
                anyhow::bail!(
                    "{label} production_tls requires a TLS listener; configure trusted_reverse_proxy, local_trusted, or unsafe_plaintext for the current plain listener"
                );
            }
            GatewayTransportSecurityMode::MutualTls => {
                self.validate_tls_material(label, true)?;
                anyhow::bail!(
                    "{label} mtls requires a TLS listener; configure trusted_reverse_proxy, local_trusted, or unsafe_plaintext for the current plain listener"
                );
            }
            GatewayTransportSecurityMode::TrustedReverseProxy => {
                if config.trusted_proxy.peers.is_empty() {
                    anyhow::bail!(
                        "{label} trusted_reverse_proxy requires at least one trusted_proxy_peers entry"
                    );
                }
            }
            GatewayTransportSecurityMode::LocalTrusted => {
                if !listen_addr.ip().is_loopback() {
                    anyhow::bail!("{label} local_trusted requires a loopback listen address");
                }
            }
            GatewayTransportSecurityMode::UnsafePlaintext => {}
            GatewayTransportSecurityMode::DisabledForTest => {
                if !allow_disabled_for_test {
                    anyhow::bail!(
                        "{label} transport security mode disabled_for_test is only valid in tests"
                    );
                }
            }
        }
        Ok(GatewayListenerSecurity {
            listen_addr,
            config,
            #[cfg(any(feature = "external-grpc", feature = "application-grpc"))]
            tls: None,
        })
    }

    #[cfg(any(feature = "external-grpc", feature = "application-grpc"))]
    pub(crate) fn validate_grpc_listener_inner(
        &self,
        label: &str,
        listen_addr: &str,
        allow_disabled_for_test: bool,
    ) -> Result<GatewayListenerSecurity> {
        let listen_addr = listen_addr.parse::<SocketAddr>().with_context(|| {
            format!("{label} listen address '{listen_addr}' must be an IP socket address")
        })?;
        let config = self.to_gateway_transport_security_config(label)?;
        let tls = match config.mode {
            GatewayTransportSecurityMode::ProductionTls => {
                Some(self.load_tls_material(label, false)?)
            }
            GatewayTransportSecurityMode::MutualTls => Some(self.load_tls_material(label, true)?),
            GatewayTransportSecurityMode::TrustedReverseProxy => {
                if config.trusted_proxy.peers.is_empty() {
                    anyhow::bail!(
                        "{label} trusted_reverse_proxy requires at least one trusted_proxy_peers entry"
                    );
                }
                None
            }
            GatewayTransportSecurityMode::LocalTrusted => {
                if !listen_addr.ip().is_loopback() {
                    anyhow::bail!("{label} local_trusted requires a loopback listen address");
                }
                None
            }
            GatewayTransportSecurityMode::UnsafePlaintext => None,
            GatewayTransportSecurityMode::DisabledForTest => {
                if !allow_disabled_for_test {
                    anyhow::bail!(
                        "{label} transport security mode disabled_for_test is only valid in tests"
                    );
                }
                None
            }
        };
        Ok(GatewayListenerSecurity {
            listen_addr,
            config,
            tls,
        })
    }

    fn to_gateway_transport_security_config(
        &self,
        label: &str,
    ) -> Result<GatewayTransportSecurityConfig> {
        let mode = match self.mode.as_str() {
            "production_tls" => GatewayTransportSecurityMode::ProductionTls,
            "mtls" => GatewayTransportSecurityMode::MutualTls,
            "trusted_reverse_proxy" => GatewayTransportSecurityMode::TrustedReverseProxy,
            "local_trusted" => GatewayTransportSecurityMode::LocalTrusted,
            "unsafe_plaintext" => GatewayTransportSecurityMode::UnsafePlaintext,
            "disabled_for_test" => GatewayTransportSecurityMode::DisabledForTest,
            other => anyhow::bail!("unknown transport security mode '{other}' for {label}"),
        };
        let peers = self
            .trusted_proxy_peers
            .iter()
            .map(|peer| {
                peer.parse::<IpAddr>()
                    .with_context(|| format!("invalid trusted proxy peer '{peer}' for {label}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let unsafe_relaxations = self
            .unsafe_relaxations
            .iter()
            .map(|relaxation| match relaxation.as_str() {
                "allow_plaintext" => Ok(GatewayUnsafeTransportRelaxation::AllowPlaintext),
                "ignore_origin_port" => Ok(GatewayUnsafeTransportRelaxation::IgnoreOriginPort),
                "relaxed_origin" => Ok(GatewayUnsafeTransportRelaxation::RelaxedOrigin),
                other => {
                    anyhow::bail!("unknown unsafe transport relaxation '{other}' for {label}")
                }
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(GatewayTransportSecurityConfig {
            mode,
            trusted_proxy: GatewayTrustedProxyConfig {
                peers,
                honor_x_forwarded_proto: self.honor_x_forwarded_proto,
                honor_x_forwarded_host: self.honor_x_forwarded_host,
                honor_x_forwarded_for: self.honor_x_forwarded_for,
            },
            unsafe_relaxations,
        }
        .bounded())
    }

    fn validate_tls_material(&self, label: &str, require_client_roots: bool) -> Result<()> {
        let cert = non_empty_path(self.certificate_chain_path.as_deref())
            .ok_or_else(|| anyhow::anyhow!("{label} TLS mode requires certificate_chain_path"))?;
        let key = non_empty_path(self.private_key_path.as_deref())
            .ok_or_else(|| anyhow::anyhow!("{label} TLS mode requires private_key_path"))?;
        ensure_file(cert, &format!("{label} certificate_chain_path"))?;
        ensure_file(key, &format!("{label} private_key_path"))?;
        if require_client_roots && self.client_trust_roots.is_empty() {
            anyhow::bail!("{label} mtls requires at least one client_trust_roots entry");
        }
        for root in &self.client_trust_roots {
            let root = non_empty_path(Some(root.as_str()))
                .ok_or_else(|| anyhow::anyhow!("{label} client_trust_roots must not be empty"))?;
            ensure_file(root, &format!("{label} client_trust_roots"))?;
        }
        Ok(())
    }

    #[cfg(any(feature = "external-grpc", feature = "application-grpc"))]
    fn load_tls_material(
        &self,
        label: &str,
        require_client_roots: bool,
    ) -> Result<GatewayListenerTlsMaterial> {
        self.validate_tls_material(label, require_client_roots)?;
        let cert = non_empty_path(self.certificate_chain_path.as_deref())
            .ok_or_else(|| anyhow::anyhow!("{label} TLS mode requires certificate_chain_path"))?;
        let key = non_empty_path(self.private_key_path.as_deref())
            .ok_or_else(|| anyhow::anyhow!("{label} TLS mode requires private_key_path"))?;
        let certificate_chain_pem = fs::read(cert)
            .with_context(|| format!("read {label} certificate_chain_path '{cert}'"))?;
        let private_key_pem =
            fs::read(key).with_context(|| format!("read {label} private_key_path '{key}'"))?;
        let mut client_trust_roots_pem = Vec::new();
        for root in &self.client_trust_roots {
            let root = non_empty_path(Some(root.as_str()))
                .ok_or_else(|| anyhow::anyhow!("{label} client_trust_roots must not be empty"))?;
            let pem = fs::read(root)
                .with_context(|| format!("read {label} client_trust_roots '{root}'"))?;
            client_trust_roots_pem.extend_from_slice(&pem);
            if !client_trust_roots_pem.ends_with(b"\n") {
                client_trust_roots_pem.push(b'\n');
            }
        }
        Ok(GatewayListenerTlsMaterial {
            certificate_chain_pem,
            private_key_pem,
            client_trust_roots_pem,
        })
    }
}

fn default_gateway_transport_security_mode() -> String {
    "local_trusted".into()
}

fn non_empty_path(path: Option<&str>) -> Option<&str> {
    path.map(str::trim).filter(|path| !path.is_empty())
}

fn ensure_file(path: &str, label: &str) -> Result<()> {
    if !Path::new(path).is_file() {
        anyhow::bail!("{label} '{path}' must be an existing file");
    }
    Ok(())
}

#[cfg(any(feature = "external-grpc", feature = "application-grpc"))]
pub(crate) fn grpc_server_builder(
    security: &GatewayListenerSecurity,
) -> Result<tonic::transport::Server> {
    let server = tonic::transport::Server::builder();
    if let Some(tls) = security.tls.as_ref() {
        return server
            .tls_config(tonic_server_tls_config(tls)?)
            .map_err(|error| anyhow::anyhow!("configure gRPC TLS listener: {error}"));
    }
    Ok(server)
}

#[cfg(any(feature = "external-grpc", feature = "application-grpc"))]
fn tonic_server_tls_config(
    tls: &GatewayListenerTlsMaterial,
) -> Result<tonic::transport::ServerTlsConfig> {
    let identity = tonic::transport::Identity::from_pem(
        tls.certificate_chain_pem.clone(),
        tls.private_key_pem.clone(),
    );
    let mut config = tonic::transport::ServerTlsConfig::new().identity(identity);
    if !tls.client_trust_roots_pem.is_empty() {
        config = config.client_ca_root(tonic::transport::Certificate::from_pem(
            tls.client_trust_roots_pem.clone(),
        ));
    }
    Ok(config)
}

pub(crate) fn log_transport_security(
    label: &'static str,
    addr: &str,
    config: &GatewayTransportSecurityConfig,
) {
    if config.is_unsafe() {
        tracing::warn!(
            %label,
            %addr,
            mode = config.mode.as_str(),
            unsafe_relaxations = ?config.unsafe_relaxation_names(),
            "gateway unsafe transport enabled"
        );
    } else {
        tracing::info!(%label, %addr, mode = config.mode.as_str(), "gateway transport");
    }
}

fn default_true() -> bool {
    true
}
