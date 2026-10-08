//! Explicit stock mappings from local Kernel effects to remote v1 CallTargets.

use serde::Deserialize;

/// One exact local effect method; the target cannot be inferred from a caller's
/// input. Kernel grants still decide who may open and invoke this Resource.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationOutboundCallConfig {
    pub local_path: String,
    pub local_method: String,
    /// Stable host revision; bump when replacing the local binding contract.
    pub binding_generation: u64,
    /// Hex SHA-384 node ID of an enabled peer with an outbound TLS route.
    pub peer_node: String,
    pub export: String,
    pub path: String,
    pub method: String,
    pub contract_digest: String,
    /// Only these host-resolved acting identities may use this mapping.
    /// Entries are `root` or concrete `identity://...` paths.
    #[serde(default)]
    pub allowed_acting: Vec<String>,
    /// Names of explicit host-held Hosted credentials admitted for this method.
    /// Each name maps one stable local acting identity to an issuer-signed
    /// assertion and holder key for this exact target node.
    #[serde(default)]
    pub allowed_hosted: Vec<String>,
    #[serde(default)]
    pub codec: FederationOutboundCodecConfig,
    #[serde(default)]
    pub timing: FederationOutboundTimingConfig,
}

/// A deliberate trust delegation from a stable local Kernel identity to a
/// Hosted subject. The daemon holds the holder key and signs each request;
/// installations where the user retains that key use the embedding ports.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FederationOutboundHostedSubjectConfig {
    pub name: String,
    /// `root` or a concrete `identity://...` path. Numeric IdentityRef values
    /// are never accepted as durable identity mappings.
    pub acting: String,
    /// Hex SHA-384 target node ID. Must have an enabled pinned TLS route.
    pub peer_node: String,
    /// Exact remote Hosted principal. Assertion replacement may renew its
    /// validity or holder key, but cannot silently change this mapping.
    pub issuer: String,
    pub namespace: String,
    pub subject: String,
    /// Canonical issuer descriptor and issuer-signed Invoke assertion.
    pub issuer_descriptor_path: String,
    pub assertion_path: String,
    pub issuer_signature_path: String,
    /// Binary PKCS#8 ML-DSA-65 holder private key (0600).
    pub holder_key_path: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationOutboundCodecConfig {
    #[default]
    BytesV1,
    ValueJsonV1,
}

#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FederationOutboundTimingConfig {
    pub prepare_ms: Option<u64>,
    pub execution_ms: Option<u64>,
    pub result_retention_ms: Option<u64>,
    pub poll_ms: Option<u64>,
}
