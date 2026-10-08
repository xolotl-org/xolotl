//! Host listener security and TLS construction shared by Gateway transports.

use anyhow::{Context, Result};
#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};
use serde::Deserialize;
#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
use std::fs;
#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
use std::sync::Arc;
use xolotl_gateway::{
    GatewayTransportSecurityConfig, GatewayTransportSecurityMode, GatewayTrustedProxyConfig,
    GatewayUnsafeTransportRelaxation,
};
#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
use zeroize::Zeroizing;

#[cfg(any(feature = "external-grpc", feature = "application-grpc"))]
pub(crate) mod incoming;

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
    #[cfg(any(
        feature = "external-grpc",
        feature = "application-grpc",
        feature = "federation-grpc"
    ))]
    pub tls: Option<GatewayListenerTlsMaterial>,
}

#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
#[derive(Clone)]
pub struct GatewayListenerTlsMaterial {
    pub certificate_chain_pem: Vec<u8>,
    pub private_key_pem: Zeroizing<Vec<u8>>,
    pub client_trust_roots_pem: Vec<u8>,
}

#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
impl std::fmt::Debug for GatewayListenerTlsMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayListenerTlsMaterial")
            .field("certificate_chain_bytes", &self.certificate_chain_pem.len())
            .field("private_key_pem", &"<redacted>")
            .field(
                "client_trust_roots_bytes",
                &self.client_trust_roots_pem.len(),
            )
            .finish()
    }
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

    #[cfg(any(
        feature = "external-grpc",
        feature = "application-grpc",
        feature = "federation-grpc"
    ))]
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
            #[cfg(any(
                feature = "external-grpc",
                feature = "application-grpc",
                feature = "federation-grpc"
            ))]
            tls: None,
        })
    }

    #[cfg(any(
        feature = "external-grpc",
        feature = "application-grpc",
        feature = "federation-grpc"
    ))]
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

    #[cfg(any(
        feature = "external-grpc",
        feature = "application-grpc",
        feature = "federation-grpc"
    ))]
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
            crate::config::read_private_pem_file(key, &format!("{label} private_key_path"))?;
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

#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
pub(crate) fn grpc_tls_server_config(
    security: &GatewayListenerSecurity,
) -> Result<Option<Arc<rustls::ServerConfig>>> {
    let Some(tls) = security.tls.as_ref() else {
        return Ok(None);
    };
    anyhow::ensure!(
        matches!(
            security.config.mode,
            GatewayTransportSecurityMode::ProductionTls | GatewayTransportSecurityMode::MutualTls
        ),
        "gRPC TLS material requires a TLS security mode"
    );
    let certificates =
        parse_ml_dsa_certificates(&tls.certificate_chain_pem, "gRPC server certificate chain")?;
    let private_key = PrivateKeyDer::from_pem_reader(&mut Cursor::new(&tls.private_key_pem))
        .context("parse gRPC server private key")?;
    validate_server_identity(&certificates, &private_key)?;

    let provider = Arc::new(crate::pqc_tls_crypto_provider()?);
    let builder = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("configure TLS 1.3 only")?;
    let builder = if security.config.mode == GatewayTransportSecurityMode::MutualTls {
        anyhow::ensure!(
            !tls.client_trust_roots_pem.is_empty(),
            "gRPC mutual TLS requires client trust roots"
        );
        let roots =
            parse_ml_dsa_certificates(&tls.client_trust_roots_pem, "gRPC client trust roots")?;
        let mut store = rustls::RootCertStore::empty();
        for root in roots {
            store
                .add(root)
                .context("load ML-DSA-65 client trust root")?;
        }
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(store), provider)
                .build()
                .context("configure ML-DSA-65 client certificate verification")?;
        builder.with_client_cert_verifier(verifier)
    } else {
        anyhow::ensure!(
            tls.client_trust_roots_pem.is_empty(),
            "gRPC client trust roots require mutual TLS mode"
        );
        builder.with_no_client_auth()
    };
    let mut config = builder
        .with_single_cert(certificates, private_key)
        .context("configure ML-DSA-65 gRPC server identity")?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    anyhow::ensure!(
        !config.ticketer.enabled(),
        "gRPC TLS ticket producer must be disabled"
    );
    Ok(Some(Arc::new(config)))
}

#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
fn validate_server_identity(
    certificates: &[CertificateDer<'static>],
    private_key: &PrivateKeyDer<'static>,
) -> Result<()> {
    let certified = rustls::sign::CertifiedKey::from_der(
        certificates.to_vec(),
        private_key.clone_key(),
        &crate::pqc_tls_crypto_provider()?,
    )
    .context("validate gRPC server certificate and private key")?;
    certified
        .keys_match()
        .context("gRPC server certificate must match its private key")?;
    anyhow::ensure!(
        certified
            .key
            .choose_scheme(&[rustls::SignatureScheme::ML_DSA_65])
            .is_some(),
        "gRPC server private key must sign with ML-DSA-65"
    );
    Ok(())
}

#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
fn parse_ml_dsa_certificates(pem: &[u8], label: &str) -> Result<Vec<CertificateDer<'static>>> {
    const ML_DSA_65_OID: &str = "2.16.840.1.101.3.4.3.18";
    let certificates = CertificateDer::pem_reader_iter(&mut Cursor::new(pem))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("parse {label}"))?;
    anyhow::ensure!(
        !certificates.is_empty(),
        "{label} must contain a certificate"
    );
    for (index, certificate) in certificates.iter().enumerate() {
        let (remaining, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
            .map_err(|error| anyhow::anyhow!("parse {label} certificate {index}: {error}"))?;
        anyhow::ensure!(
            remaining.is_empty(),
            "{label} certificate {index} has trailing data"
        );
        anyhow::ensure!(
            parsed.public_key().algorithm.algorithm.to_id_string() == ML_DSA_65_OID
                && parsed.signature_algorithm.algorithm.to_id_string() == ML_DSA_65_OID
                && parsed.tbs_certificate.signature.algorithm.to_id_string() == ML_DSA_65_OID,
            "{label} certificate {index} must use ML-DSA-65 for its public key and signature"
        );
    }
    Ok(certificates)
}

#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "external-websocket"
))]
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
