use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, ensure};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _};

const CERT: &[u8] = include_bytes!("../../tests/fixtures/ml-dsa-65-cert.pem");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/ml-dsa-65-key.pem");
const ROOT: &[u8] = include_bytes!("../../tests/fixtures/ml-dsa-65-ca-cert.pem");
const CLASSICAL_CERT: &[u8] = include_bytes!("../../tests/fixtures/ecdsa-cert.pem");
const CLASSICAL_KEY: &[u8] = include_bytes!("../../tests/fixtures/ecdsa-key.pem");

#[test]
fn client_construction_does_not_select_global_provider() -> Result<()> {
    let previous = rustls::crypto::CryptoProvider::get_default().cloned();
    super::client_builder()?.build()?;
    let current = rustls::crypto::CryptoProvider::get_default();
    ensure!(match (previous.as_ref(), current) {
        (None, None) => true,
        (Some(previous), Some(current)) => Arc::ptr_eq(previous, current),
        _ => false,
    });
    let config = super::client_config()?;
    ensure!(!config.enable_early_data);
    ensure!(config.crypto_provider().kx_groups.len() == 1);
    ensure!(
        config
            .crypto_provider()
            .signature_verification_algorithms
            .mapping
            .len()
            == 1
    );
    Ok(())
}

#[test]
fn installed_classical_provider_does_not_change_client_policy() -> Result<()> {
    const CHILD_ENV: &str = "XOLOTL_TLS_PROVIDER_TEST_CHILD";
    if std::env::var_os(CHILD_ENV).is_none() {
        let status = std::process::Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "http_tls::tests::installed_classical_provider_does_not_change_client_policy",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .status()?;
        ensure!(status.success());
        return Ok(());
    }
    let mut classical = rustls::crypto::aws_lc_rs::default_provider();
    classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    classical
        .install_default()
        .map_err(|_provider| anyhow::anyhow!("test provider already installed"))?;
    client_construction_does_not_select_global_provider()?;
    https_negotiation_preserves_strict_policy()
}

#[tokio::test]
async fn https_negotiation_preserves_strict_policy() -> Result<()> {
    let (response, negotiated) = request(super::crypto_provider()?, CERT, KEY, ROOT).await?;
    ensure!(response? == "ok");
    ensure!(negotiated? == Some(rustls::NamedGroup::X25519MLKEM768));

    let mut chacha = super::crypto_provider()?;
    chacha.cipher_suites =
        vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256];
    let (response, negotiated) = request(chacha, CERT, KEY, ROOT).await?;
    ensure!(response? == "ok");
    ensure!(negotiated? == Some(rustls::NamedGroup::X25519MLKEM768));

    let (response, negotiated) =
        request(super::crypto_provider()?, CERT, KEY, CLASSICAL_CERT).await?;
    ensure!(
        response.is_err() && negotiated.is_err(),
        "untrusted identity unexpectedly accepted"
    );

    let mut classical = super::crypto_provider()?;
    classical.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
    let (response, negotiated) = request(classical, CERT, KEY, ROOT).await?;
    ensure!(response.is_err() && negotiated.is_err());

    let mut aes128 = super::crypto_provider()?;
    aes128.cipher_suites = vec![rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256];
    let (response, negotiated) = request(aes128, CERT, KEY, ROOT).await?;
    ensure!(response.is_err() && negotiated.is_err());

    let (response, _) = request(
        rustls::crypto::aws_lc_rs::default_provider(),
        CLASSICAL_CERT,
        CLASSICAL_KEY,
        CLASSICAL_CERT,
    )
    .await?;
    ensure!(
        response.is_err(),
        "classical certificate authentication unexpectedly succeeded"
    );
    Ok(())
}

async fn request(
    provider: rustls::crypto::CryptoProvider,
    certificate: &[u8],
    key: &[u8],
    root: &[u8],
) -> Result<(
    Result<String, reqwest::Error>,
    Result<Option<rustls::NamedGroup>>,
)> {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from_pem_slice(certificate)?],
            PrivateKeyDer::from_pem_slice(key)?,
        )?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let server = std::thread::spawn(move || -> Result<Option<rustls::NamedGroup>> {
        let (socket, _) = listener.accept()?;
        socket.set_read_timeout(Some(Duration::from_secs(5)))?;
        socket.set_write_timeout(Some(Duration::from_secs(5)))?;
        let connection = rustls::ServerConnection::new(Arc::new(config))?;
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut request = [0_u8; 4096];
        ensure!(stream.read(&mut request)? != 0);
        ensure!(stream.conn.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3));
        ensure!(stream.conn.handshake_kind() == Some(rustls::HandshakeKind::Full));
        stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")?;
        stream.flush()?;
        Ok(stream
            .conn
            .negotiated_key_exchange_group()
            .map(|group| group.name()))
    });
    let mut config = super::client_config()?;
    let verifier = rustls_platform_verifier::Verifier::new_with_extra_roots(
        [CertificateDer::from_pem_slice(root)?],
        Arc::clone(config.crypto_provider()),
    )?;
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(verifier));
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .no_proxy()
        .resolve("localhost", address)
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = match client
        .get(format!("https://localhost:{}/", address.port()))
        .send()
        .await
    {
        Ok(response) => response.text().await,
        Err(error) => Err(error),
    };
    let negotiated = server
        .join()
        .map_err(|_panic| anyhow::anyhow!("TLS server panicked"))?;
    Ok((response, negotiated))
}
