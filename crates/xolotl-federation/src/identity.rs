use std::fmt;

use aws_lc_rs::signature::{
    KeyPair as _, ML_DSA_65, ML_DSA_65_SIGNING, ParsedPublicKey, PqdsaKeyPair,
};
use sha2::{Digest as _, Sha384};
use thiserror::Error;

const ROOT_PREFIX: &[u8] = b"xolotl.federation.root.v1\0";
const NODE_ID_PREFIX: &[u8] = b"xolotl.federation.node-id.v1\0";
const SIGNATURE_PREFIX: &[u8] = b"xolotl.federation.signature.v1\0";
const ROOT_ALGORITHM: [u8; 2] = 1u16.to_be_bytes(); // ML-DSA-65, FIPS 204
const ROOT_SIGNATURE_MODE: [u8; 2] = 1u16.to_be_bytes(); // pure ML-DSA, empty context
const ROOT_PUBLIC_KEY_LEN: usize = 1952;
const ROOT_HEADER_LEN: usize = ROOT_PREFIX.len() + 6;
const MAX_SIGNED_MESSAGE_BYTES: usize = 64 * 1024;

/// A SHA-384 fingerprint of the complete canonical v1 root descriptor.
/// Parsing its bytes does not authenticate the root or an online peer.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FederationNodeId([u8; 48]);

impl FederationNodeId {
    /// Byte length of the SHA-384 root-descriptor fingerprint.
    pub const LEN: usize = 48;

    /// Restore an ID from canonical fingerprint bytes; this alone does not
    /// authenticate a root or a current Session.
    pub const fn from_bytes(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    /// Canonical fingerprint bytes used in wire and storage keys.
    pub const fn as_bytes(&self) -> &[u8; 48] {
        &self.0
    }

    /// Check that this ID names the supplied canonical root descriptor.
    pub fn matches_root(self, root: &FederationRoot) -> bool {
        self == root.node_id()
    }
}

/// Failure while parsing, signing, or verifying v1 ML-DSA node identity.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationIdentityError {
    /// Root descriptor has a noncanonical format or length.
    #[error("invalid federation root descriptor")]
    InvalidRootDescriptor,
    /// Root algorithm or signature mode is outside the v1 profile.
    #[error("unsupported federation root algorithm or signature mode")]
    UnsupportedSignatureAlgorithm,
    /// ML-DSA-65 public key is malformed.
    #[error("invalid ML-DSA-65 public key")]
    InvalidPublicKey,
    /// ML-DSA-65 private key is malformed.
    #[error("invalid ML-DSA-65 private key")]
    InvalidPrivateKey,
    /// Signature does not verify for this root, purpose and message.
    #[error("invalid ML-DSA-65 signature")]
    InvalidSignature,
    /// Root-authorized online-key grant is malformed or invalid.
    #[error("invalid federation online-key authorization")]
    InvalidOnlineAuthorization,
    /// Online key was used outside its bounded validity interval.
    #[error("federation online key is not valid at this time")]
    OnlineKeyOutsideValidity,
    /// Peer or signer identity differs from the Session binding.
    #[error("federation peer or signer does not match the session")]
    PeerMismatch,
    /// Channel-bound Session transcript is malformed.
    #[error("invalid federation session transcript")]
    InvalidSessionTranscript,
    /// Signing input exceeds the fixed cryptographic message bound.
    #[error("federation signed message exceeds the limit")]
    MessageTooLarge,
    /// The cryptographic provider could not complete an operation.
    #[error("federation signing operation failed")]
    CryptoFailure,
}

/// The only root signing profile accepted by the unreleased federation v1.
/// The descriptor encodes format, algorithm, parameters, verification mode and
/// the complete raw public key. Other profiles require a new reviewed format.
pub struct FederationRoot {
    public_key: ParsedPublicKey,
}

impl fmt::Debug for FederationRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FederationRoot")
            .field("algorithm", &"ML-DSA-65")
            .field("node_id", &self.node_id())
            .finish()
    }
}

impl FederationRoot {
    /// Canonical descriptor length for the fixed v1 ML-DSA-65 profile.
    pub const ENCODED_LEN: usize = ROOT_HEADER_LEN + ROOT_PUBLIC_KEY_LEN;
    /// Raw ML-DSA-65 signature length accepted on the wire.
    pub const SIGNATURE_LEN: usize = 3309;

    /// Parse an ML-DSA-65 public key before wrapping it in a v1 descriptor.
    pub fn from_ml_dsa_65_public_key(bytes: &[u8]) -> Result<Self, FederationIdentityError> {
        if bytes.len() != ROOT_PUBLIC_KEY_LEN {
            return Err(FederationIdentityError::InvalidPublicKey);
        }
        let public_key = ParsedPublicKey::new(&ML_DSA_65, bytes)
            .map_err(|_error| FederationIdentityError::InvalidPublicKey)?;
        Ok(Self { public_key })
    }

    /// Parse exactly one canonical v1 descriptor. Classic and unknown algorithms
    /// are never treated as an acceptable fallback.
    pub fn decode(encoded: &[u8]) -> Result<Self, FederationIdentityError> {
        if encoded.len() != Self::ENCODED_LEN || !encoded.starts_with(ROOT_PREFIX) {
            return Err(FederationIdentityError::InvalidRootDescriptor);
        }
        let header = &encoded[ROOT_PREFIX.len()..ROOT_HEADER_LEN];
        if header[..2] != ROOT_ALGORITHM || header[2..4] != ROOT_SIGNATURE_MODE {
            return Err(FederationIdentityError::UnsupportedSignatureAlgorithm);
        }
        if header[4..6] != (ROOT_PUBLIC_KEY_LEN as u16).to_be_bytes() {
            return Err(FederationIdentityError::InvalidRootDescriptor);
        }
        Self::from_ml_dsa_65_public_key(&encoded[ROOT_HEADER_LEN..])
    }

    /// Encode the complete canonical v1 descriptor, including algorithm mode.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(Self::ENCODED_LEN);
        encoded.extend_from_slice(ROOT_PREFIX);
        encoded.extend_from_slice(&ROOT_ALGORITHM);
        encoded.extend_from_slice(&ROOT_SIGNATURE_MODE);
        encoded.extend_from_slice(&(ROOT_PUBLIC_KEY_LEN as u16).to_be_bytes());
        encoded.extend_from_slice(self.public_key.as_ref());
        encoded
    }

    /// Borrow the validated raw ML-DSA-65 verification key.
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }

    /// Hash the complete canonical descriptor into its stable node identity.
    pub fn node_id(&self) -> FederationNodeId {
        let mut hasher = Sha384::new();
        hasher.update(NODE_ID_PREFIX);
        hasher.update(ROOT_PREFIX);
        hasher.update(ROOT_ALGORITHM);
        hasher.update(ROOT_SIGNATURE_MODE);
        hasher.update((ROOT_PUBLIC_KEY_LEN as u16).to_be_bytes());
        hasher.update(self.public_key.as_ref());
        FederationNodeId(hasher.finalize().into())
    }

    /// Verify a bounded, purpose-separated signature over an already canonical
    /// message. This checks key possession only; callers must still validate
    /// audience, subject, authority, freshness and any TLS channel binding.
    pub fn verify(
        &self,
        purpose: RootSignaturePurpose,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), FederationIdentityError> {
        if signature.len() != ML_DSA_65_SIGNING.signature_len() {
            return Err(FederationIdentityError::InvalidSignature);
        }
        let signed = signature_input(purpose, message)?;
        self.public_key
            .verify_sig(&signed, signature)
            .map_err(|_error| FederationIdentityError::InvalidSignature)
    }
}

/// Fixed signature domains. The message in each domain must have its own
/// canonical, complete semantics before it is passed to sign or verify.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RootSignaturePurpose {
    /// Signature over a canonical node description.
    NodeDescription = 1,
    /// Root grant of one bounded online signing key.
    OnlineKeyAuthorization = 2,
}

fn signature_input(
    purpose: RootSignaturePurpose,
    message: &[u8],
) -> Result<Vec<u8>, FederationIdentityError> {
    if message.len() > MAX_SIGNED_MESSAGE_BYTES {
        return Err(FederationIdentityError::MessageTooLarge);
    }
    let mut input = Vec::with_capacity(SIGNATURE_PREFIX.len() + 1 + 4 + message.len());
    input.extend_from_slice(SIGNATURE_PREFIX);
    input.push(purpose as u8);
    input.extend_from_slice(&(message.len() as u32).to_be_bytes());
    input.extend_from_slice(message);
    Ok(input)
}

/// ML-DSA-65 root signer. Storage, wrapping and rotation of its secret belong
/// to the embedding host; a PKCS#8 document zeroizes its bytes on drop.
pub struct FederationRootKey(PqdsaKeyPair);

impl FederationRootKey {
    /// Generate a new offline ML-DSA-65 identity root using the crypto provider.
    pub fn generate() -> Result<Self, FederationIdentityError> {
        PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
            .map(Self)
            .map_err(|_error| FederationIdentityError::CryptoFailure)
    }

    /// Parse an existing PKCS#8 root secret supplied by secure host storage.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, FederationIdentityError> {
        PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, bytes)
            .map(Self)
            .map_err(|_error| FederationIdentityError::InvalidPrivateKey)
    }

    /// Export the root secret as a zeroizing PKCS#8 document for offline storage.
    pub fn to_pkcs8(&self) -> Result<aws_lc_rs::pkcs8::Document, FederationIdentityError> {
        self.0
            .to_pkcs8v1()
            .map_err(|_error| FederationIdentityError::CryptoFailure)
    }

    /// Derive the public root descriptor corresponding to this signer.
    pub fn root(&self) -> Result<FederationRoot, FederationIdentityError> {
        FederationRoot::from_ml_dsa_65_public_key(self.0.public_key().as_ref())
    }

    /// Sign a bounded canonical message under an explicit purpose domain.
    pub fn sign(
        &self,
        purpose: RootSignaturePurpose,
        message: &[u8],
    ) -> Result<Vec<u8>, FederationIdentityError> {
        let signed = signature_input(purpose, message)?;
        let mut signature = vec![0; ML_DSA_65_SIGNING.signature_len()];
        let written = self
            .0
            .sign(&signed, &mut signature)
            .map_err(|_error| FederationIdentityError::CryptoFailure)?;
        if written != signature.len() {
            return Err(FederationIdentityError::CryptoFailure);
        }
        Ok(signature)
    }
}
