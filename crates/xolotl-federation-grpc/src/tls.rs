//! A channel binding taken directly from the completed rustls connection.
//! No wire field, metadata header or caller-supplied byte slice can create one.

use tonic::Status;
use xolotl_federation::FederationNodeId;

const EXPORTER_LABEL: &[u8] = b"EXPORTER-xolotl-federation-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LocalRole {
    Initiator,
    Responder,
}

/// Evidence extracted from one live TLS connection. It is deliberately
/// neither `Clone` nor constructible from serialized facts. The stream driver
/// must keep it paired with the exact connection from which it was extracted.
pub struct FederationTlsChannel {
    pub(crate) role: LocalRole,
    pub(crate) expected_peer: Option<FederationNodeId>,
    pub(crate) exporter: [u8; 48],
}

impl FederationTlsChannel {
    /// Internal paired state for the opposite direction of the same already
    /// authenticated RPC. This never creates evidence for another socket.
    pub(crate) fn paired_after_verification(&self, peer: FederationNodeId) -> Self {
        Self {
            role: self.role,
            expected_peer: Some(peer),
            exporter: self.exporter,
        }
    }

    /// The client must pin its intended federation node independently of DNS
    /// and the TLS server name. The online proof later binds that node to this
    /// exact TLS channel.
    pub fn from_client_tls(
        connection: &rustls::ClientConnection,
        expected_peer: FederationNodeId,
    ) -> Result<Self, Status> {
        Self::extract(connection, LocalRole::Initiator, Some(expected_peer))
    }

    /// Inbound peers may be unknown before Hello, but local policy must approve
    /// the proven node before the first business frame is dispatched.
    pub fn from_server_tls(connection: &rustls::ServerConnection) -> Result<Self, Status> {
        Self::extract(connection, LocalRole::Responder, None)
    }

    fn extract<T: CompletedTls>(
        connection: &T,
        role: LocalRole,
        expected_peer: Option<FederationNodeId>,
    ) -> Result<Self, Status> {
        if connection.tls_is_handshaking()
            || connection.tls_protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3)
            || connection.tls_handshake_kind() != Some(rustls::HandshakeKind::Full)
            || connection.tls_alpn_protocol() != Some(b"h2".as_slice())
            || connection.tls_key_exchange_group() != Some(rustls::NamedGroup::X25519MLKEM768)
            || !matches!(
                connection.tls_cipher_suite(),
                Some(
                    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                        | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
                )
            )
        {
            return Err(Status::unauthenticated(
                "federation TLS session does not satisfy the v1 hybrid profile",
            ));
        }
        let exporter = connection.tls_exporter()?;
        if exporter == [0; 48] {
            return Err(Status::unauthenticated("invalid federation TLS exporter"));
        }
        Ok(Self {
            role,
            expected_peer,
            exporter,
        })
    }
}

trait CompletedTls {
    fn tls_is_handshaking(&self) -> bool;
    fn tls_protocol_version(&self) -> Option<rustls::ProtocolVersion>;
    fn tls_handshake_kind(&self) -> Option<rustls::HandshakeKind>;
    fn tls_alpn_protocol(&self) -> Option<&[u8]>;
    fn tls_key_exchange_group(&self) -> Option<rustls::NamedGroup>;
    fn tls_cipher_suite(&self) -> Option<rustls::CipherSuite>;
    fn tls_exporter(&self) -> Result<[u8; 48], Status>;
}

macro_rules! completed_tls {
    ($connection:ty) => {
        impl CompletedTls for $connection {
            fn tls_is_handshaking(&self) -> bool {
                self.is_handshaking()
            }

            fn tls_protocol_version(&self) -> Option<rustls::ProtocolVersion> {
                self.protocol_version()
            }

            fn tls_handshake_kind(&self) -> Option<rustls::HandshakeKind> {
                self.handshake_kind()
            }

            fn tls_alpn_protocol(&self) -> Option<&[u8]> {
                self.alpn_protocol()
            }

            fn tls_key_exchange_group(&self) -> Option<rustls::NamedGroup> {
                self.negotiated_key_exchange_group()
                    .map(|group| group.name())
            }

            fn tls_cipher_suite(&self) -> Option<rustls::CipherSuite> {
                self.negotiated_cipher_suite().map(|suite| suite.suite())
            }

            fn tls_exporter(&self) -> Result<[u8; 48], Status> {
                self.export_keying_material([0; 48], EXPORTER_LABEL, None)
                    .map_err(|_error| Status::unauthenticated("federation TLS exporter failed"))
            }
        }
    };
}

completed_tls!(rustls::ClientConnection);
completed_tls!(rustls::ServerConnection);

#[cfg(test)]
mod tests {
    use std::{io::Cursor, sync::Arc};

    use anyhow::{Result, ensure};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject as _};
    use xolotl_federation::FederationNodeId;

    use super::FederationTlsChannel;

    const CERT: &[u8] = include_bytes!("../../xolotl-daemon/tests/fixtures/ml-dsa-65-cert.pem");
    const KEY: &[u8] = include_bytes!("../../xolotl-daemon/tests/fixtures/ml-dsa-65-key.pem");
    const CA: &[u8] = include_bytes!("../../xolotl-daemon/tests/fixtures/ml-dsa-65-ca-cert.pem");

    #[test]
    fn channel_binding_requires_completed_hybrid_tls_and_matches_both_ends() -> Result<()> {
        let mut provider = rustls::crypto::aws_lc_rs::default_provider();
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
        let provider = Arc::new(provider);
        let certificates = CertificateDer::pem_reader_iter(&mut Cursor::new(CERT))
            .collect::<Result<Vec<_>, _>>()?;
        let key = PrivateKeyDer::from_pem_reader(&mut Cursor::new(KEY))?;
        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(certificates, key)?;
        server_config.alpn_protocols = vec![b"h2".to_vec()];
        server_config.send_tls13_tickets = 0;
        server_config.max_tls13_tickets = 0;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from_pem_reader(&mut Cursor::new(CA))?)?;
        let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec()];
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            ServerName::try_from("localhost")?,
        )?;
        let mut server = rustls::ServerConnection::new(Arc::new(server_config))?;
        let node = FederationNodeId::from_bytes([1; 48]);
        ensure!(FederationTlsChannel::from_client_tls(&client, node).is_err());
        ensure!(FederationTlsChannel::from_server_tls(&server).is_err());

        for _ in 0..8 {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes)?;
            if !bytes.is_empty() {
                let mut source = Cursor::new(bytes);
                while source.position() < source.get_ref().len() as u64 {
                    server.read_tls(&mut source)?;
                    server.process_new_packets()?;
                }
            }
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes)?;
            if !bytes.is_empty() {
                let mut source = Cursor::new(bytes);
                while source.position() < source.get_ref().len() as u64 {
                    client.read_tls(&mut source)?;
                    client.process_new_packets()?;
                }
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        ensure!(!client.is_handshaking() && !server.is_handshaking());
        let from_client = FederationTlsChannel::from_client_tls(&client, node)?;
        let from_server = FederationTlsChannel::from_server_tls(&server)?;
        ensure!(from_client.exporter == from_server.exporter);
        ensure!(from_client.exporter != [0; 48]);
        Ok(())
    }
}
