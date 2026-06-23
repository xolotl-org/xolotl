use crate::{GatewayError, GatewayGeneration, GatewayProfileRev, MIN_BEARER_TOKEN_BYTES};
use sha2::Digest;

/// Credentials presented by an inbound protocol adapter. They are untrusted
/// until [`Gateway::authenticate`] verifies them against the compiled profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PresentedCredential {
    /// A bearer secret presented through a transport credential channel.
    Bearer(BearerToken),
    /// A TLS client certificate verified by the listener and matched by DER
    /// SHA-256 fingerprint.
    ClientCertificate(ClientCertificateCredential),
}

impl PresentedCredential {
    /// Build a presented bearer credential.
    pub fn bearer(token: impl Into<String>) -> Self {
        Self::Bearer(BearerToken::new(token))
    }

    /// Build a presented client certificate credential from the leaf DER.
    pub fn client_certificate_der(der: impl AsRef<[u8]>) -> Self {
        Self::ClientCertificate(ClientCertificateCredential::from_der(der))
    }
}

/// Raw bearer token material. `Debug` is deliberately redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct BearerToken(String);

impl BearerToken {
    /// Wrap raw bearer token material.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(<redacted>)")
    }
}

/// Hashed bearer token material stored in a gateway profile.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct BearerTokenHash(pub(crate) String);

impl BearerTokenHash {
    /// Hash a high-entropy bearer token for storage in a profile.
    pub fn from_token(token: &str) -> Result<Self, GatewayError> {
        if token.len() < MIN_BEARER_TOKEN_BYTES {
            return Err(GatewayError::InvalidProfile(format!(
                "bearer tokens must be at least {MIN_BEARER_TOKEN_BYTES} bytes"
            )));
        }
        Ok(Self(hash_bearer_token(token)))
    }

    /// Use a precomputed lowercase hex BLAKE3 hash from deployment config.
    pub fn from_hex(hash: impl Into<String>) -> Result<Self, GatewayError> {
        let hash = hash.into();
        let ok = hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(GatewayError::InvalidProfile(
                "bearer token hash must be a 64-character lowercase hex string".into(),
            ));
        }
        Ok(Self(hash))
    }
}

pub(crate) fn hash_bearer_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

impl std::fmt::Debug for BearerTokenHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerTokenHash(<redacted>)")
    }
}

/// TLS client certificate credential material presented by a transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientCertificateCredential {
    pub(crate) der_sha256: ClientCertificateDerSha256,
}

impl ClientCertificateCredential {
    /// Hash a leaf certificate DER to its profile matcher.
    pub fn from_der(der: impl AsRef<[u8]>) -> Self {
        Self {
            der_sha256: ClientCertificateDerSha256::from_der(der),
        }
    }
}

/// SHA-256 fingerprint of a client certificate DER.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClientCertificateDerSha256(pub(crate) String);

impl ClientCertificateDerSha256 {
    /// Hash certificate DER bytes for use in a gateway profile.
    pub fn from_der(der: impl AsRef<[u8]>) -> Self {
        let digest = sha2::Sha256::digest(der.as_ref());
        Self(hex_lower(&digest))
    }

    /// Use a precomputed lowercase hex SHA-256 fingerprint from deployment config.
    pub fn from_hex(hash: impl Into<String>) -> Result<Self, GatewayError> {
        let hash = hash.into();
        let ok = hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !ok {
            return Err(GatewayError::InvalidProfile(
                "client certificate DER SHA-256 must be a 64-character lowercase hex string".into(),
            ));
        }
        Ok(Self(hash))
    }
}

impl std::fmt::Debug for ClientCertificateDerSha256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ClientCertificateDerSha256(<redacted>)")
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// A credential accepted by a gateway profile.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayCredential {
    /// Stable redacted credential identifier used for admin display and audit
    /// correlation. It is not the raw secret.
    pub(crate) credential_id: String,
    /// Principal produced when this credential verifies.
    pub(crate) principal_id: String,
    /// Whether this credential is active in the profile snapshot.
    pub(crate) enabled: bool,
    /// Monotonic credential generation used to invalidate existing sessions.
    pub(crate) generation: GatewayGeneration,
    /// Credential verifier material.
    pub(crate) kind: GatewayCredentialKind,
}

impl GatewayCredential {
    /// Accept a bearer token by hashing it immediately.
    pub fn bearer_token(
        credential_id: impl Into<String>,
        principal_id: impl Into<String>,
        token: &str,
    ) -> Result<Self, GatewayError> {
        Ok(Self::bearer_hash(
            credential_id,
            principal_id,
            BearerTokenHash::from_token(token)?,
        ))
    }

    /// Accept a precomputed bearer token hash.
    pub fn bearer_hash(
        credential_id: impl Into<String>,
        principal_id: impl Into<String>,
        token_hash: BearerTokenHash,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            principal_id: principal_id.into(),
            enabled: true,
            generation: 1,
            kind: GatewayCredentialKind::Bearer { token_hash },
        }
    }

    /// Accept a TLS client certificate by DER SHA-256 fingerprint.
    pub fn client_certificate_der_sha256(
        credential_id: impl Into<String>,
        principal_id: impl Into<String>,
        der_sha256: ClientCertificateDerSha256,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            principal_id: principal_id.into(),
            enabled: true,
            generation: 1,
            kind: GatewayCredentialKind::ClientCertificate { der_sha256 },
        }
    }

    /// Mark whether this credential is active.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set the credential generation.
    pub fn with_generation(mut self, generation: GatewayGeneration) -> Self {
        self.generation = generation;
        self
    }
}

/// Credential verifier material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GatewayCredentialKind {
    /// Bearer token checked by hash.
    Bearer {
        /// BLAKE3 hash of the high-entropy bearer token.
        token_hash: BearerTokenHash,
    },
    /// TLS client certificate checked by DER SHA-256 fingerprint.
    ClientCertificate {
        /// SHA-256 fingerprint of the leaf certificate DER.
        der_sha256: ClientCertificateDerSha256,
    },
}

/// Maps a verified external principal to the Andrias identity path a request
/// Process runs as.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayIdentityMapping {
    /// Verified external principal id.
    pub(crate) principal_id: String,
    /// Andrias identity path, usually `process://<account-or-agent>`.
    pub(crate) identity_path: String,
    /// Whether this principal mapping is active in the profile snapshot.
    pub(crate) enabled: bool,
    /// Monotonic principal generation used to invalidate existing sessions.
    pub(crate) generation: GatewayGeneration,
}

impl GatewayIdentityMapping {
    /// Create a principal-to-identity mapping.
    pub fn new(principal_id: impl Into<String>, identity_path: impl Into<String>) -> Self {
        Self {
            principal_id: principal_id.into(),
            identity_path: identity_path.into(),
            enabled: true,
            generation: 1,
        }
    }

    /// Mark whether this principal mapping is active.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set the principal generation.
    pub fn with_generation(mut self, generation: GatewayGeneration) -> Self {
        self.generation = generation;
        self
    }
}

/// Authentication method that verified a principal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayAuthMethod {
    /// Bearer token auth.
    Bearer,
    /// TLS client certificate auth.
    ClientCertificate,
}

/// Principal verified from a presented credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPrincipal {
    /// External principal id after credential verification.
    pub(crate) principal_id: String,
    /// Redacted credential id used to correlate audit without storing secrets.
    pub(crate) credential_id: String,
    /// Credential generation that was current at authentication.
    pub(crate) credential_generation: GatewayGeneration,
    /// Principal generation that was current at authentication.
    pub(crate) principal_generation: GatewayGeneration,
    /// Auth method used for the credential.
    pub(crate) auth_method: GatewayAuthMethod,
}

impl VerifiedPrincipal {
    /// External principal id after credential verification.
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Redacted credential id used to correlate audit.
    pub fn credential_id(&self) -> &str {
        &self.credential_id
    }

    /// Credential generation that was current at authentication.
    pub fn credential_generation(&self) -> GatewayGeneration {
        self.credential_generation
    }

    /// Principal generation that was current at authentication.
    pub fn principal_generation(&self) -> GatewayGeneration {
        self.principal_generation
    }

    /// Auth method used for the credential.
    pub fn auth_method(&self) -> GatewayAuthMethod {
        self.auth_method
    }
}

/// Authenticated gateway session. Protocol adapters may cache this for a
/// connection, but every submission still carries the profile snapshot id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewaySession {
    /// Verified principal.
    pub(crate) principal: VerifiedPrincipal,
    /// Andrias identity path the request Process will run as.
    pub(crate) identity_path: String,
    /// Gateway profile name used for this session.
    pub(crate) profile_name: String,
    /// Gateway profile revision used for this session.
    pub(crate) profile_rev: GatewayProfileRev,
}

impl GatewaySession {
    /// Verified principal for this session.
    pub fn principal(&self) -> &VerifiedPrincipal {
        &self.principal
    }

    /// Andrias identity path the request Process will run as.
    pub fn identity_path(&self) -> &str {
        &self.identity_path
    }

    /// Gateway profile name used for this session.
    pub fn profile_name(&self) -> &str {
        &self.profile_name
    }

    /// Gateway profile revision used for this session.
    pub fn profile_rev(&self) -> GatewayProfileRev {
        self.profile_rev
    }
}
