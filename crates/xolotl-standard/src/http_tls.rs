use std::sync::Arc;

use rustls_platform_verifier::BuilderVerifierExt as _;

pub(crate) fn client_builder() -> Result<reqwest::ClientBuilder, rustls::Error> {
    Ok(reqwest::Client::builder().use_preconfigured_tls(client_config()?))
}

fn crypto_provider() -> Result<rustls::crypto::CryptoProvider, rustls::Error> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.cipher_suites.retain(|suite| {
        matches!(
            suite.suite(),
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        )
    });
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    let algorithms = provider.signature_verification_algorithms.mapping;
    let position = algorithms
        .iter()
        .position(|(scheme, _)| *scheme == rustls::SignatureScheme::ML_DSA_65)
        .ok_or_else(|| rustls::Error::General("AWS-LC must support ML-DSA-65".into()))?;
    provider.signature_verification_algorithms.mapping = &algorithms[position..position + 1];
    provider.signature_verification_algorithms.all = algorithms[position].1;
    Ok(provider)
}

fn client_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider()?))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_platform_verifier()?
        .with_no_client_auth();
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

#[cfg(all(
    test,
    any(all(unix, not(target_os = "android")), target_os = "windows")
))]
mod tests;
