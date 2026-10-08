use aws_lc_rs::signature::{
    KeyPair as _, ML_DSA_65, ML_DSA_65_SIGNING, ParsedPublicKey, PqdsaKeyPair,
};
use sha2::{Digest as _, Sha384};

use crate::{FederationIdentityError, FederationNodeId, FederationRoot, RootSignaturePurpose};

const AUTH_PREFIX: &[u8] = b"xolotl.federation.online-key.v1\0";
const SESSION_PREFIX: &[u8] = b"xolotl.federation.online-session.v1\0";
const SUBJECT_CHANNEL_PREFIX: &[u8] = b"xolotl.federation.subject-channel.v1\0";
const ML_DSA_65_CODE: [u8; 2] = 1u16.to_be_bytes();
const PURE_EMPTY_CONTEXT_CODE: [u8; 2] = 1u16.to_be_bytes();
const ONLINE_PUBLIC_KEY_LEN: usize = 1952;
const AUTH_HEADER_LEN: usize = AUTH_PREFIX.len() + 6 + 24;

/// A root-authorized ML-DSA-65 key for proving one node's participation in
/// sessions. The root signs the exact encoding under OnlineKeyAuthorization.
/// Local policy still owns revocation and maximum validity duration.
pub struct FederationOnlineKeyAuthorization {
    public_key: ParsedPublicKey,
    generation: u64,
    not_before_ms: u64,
    expires_ms: u64,
}

impl FederationOnlineKeyAuthorization {
    /// Canonical byte length of the versioned online-key authorization.
    pub const ENCODED_LEN: usize = AUTH_HEADER_LEN + ONLINE_PUBLIC_KEY_LEN;

    /// Validate an online public key, generation and validity interval.
    pub fn new(
        public_key: &[u8],
        generation: u64,
        not_before_ms: u64,
        expires_ms: u64,
    ) -> Result<Self, FederationIdentityError> {
        if public_key.len() != ONLINE_PUBLIC_KEY_LEN
            || generation == 0
            || not_before_ms >= expires_ms
        {
            return Err(FederationIdentityError::InvalidOnlineAuthorization);
        }
        let public_key = ParsedPublicKey::new(&ML_DSA_65, public_key)
            .map_err(|_error| FederationIdentityError::InvalidOnlineAuthorization)?;
        Ok(Self {
            public_key,
            generation,
            not_before_ms,
            expires_ms,
        })
    }

    /// Decode canonical authorization fields without verifying the root signature.
    pub fn decode(encoded: &[u8]) -> Result<Self, FederationIdentityError> {
        if encoded.len() != Self::ENCODED_LEN || !encoded.starts_with(AUTH_PREFIX) {
            return Err(FederationIdentityError::InvalidOnlineAuthorization);
        }
        let fields = &encoded[AUTH_PREFIX.len()..AUTH_HEADER_LEN];
        if fields[..2] != ML_DSA_65_CODE || fields[2..4] != PURE_EMPTY_CONTEXT_CODE {
            return Err(FederationIdentityError::UnsupportedSignatureAlgorithm);
        }
        if fields[4..6] != (ONLINE_PUBLIC_KEY_LEN as u16).to_be_bytes() {
            return Err(FederationIdentityError::InvalidOnlineAuthorization);
        }
        let generation = u64::from_be_bytes(
            fields[6..14]
                .try_into()
                .map_err(|_error| FederationIdentityError::InvalidOnlineAuthorization)?,
        );
        let not_before_ms = u64::from_be_bytes(
            fields[14..22]
                .try_into()
                .map_err(|_error| FederationIdentityError::InvalidOnlineAuthorization)?,
        );
        let expires_ms = u64::from_be_bytes(
            fields[22..30]
                .try_into()
                .map_err(|_error| FederationIdentityError::InvalidOnlineAuthorization)?,
        );
        Self::new(
            &encoded[AUTH_HEADER_LEN..],
            generation,
            not_before_ms,
            expires_ms,
        )
    }

    /// Encode the exact authorization bytes covered by the root signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(Self::ENCODED_LEN);
        encoded.extend_from_slice(AUTH_PREFIX);
        encoded.extend_from_slice(&ML_DSA_65_CODE);
        encoded.extend_from_slice(&PURE_EMPTY_CONTEXT_CODE);
        encoded.extend_from_slice(&(ONLINE_PUBLIC_KEY_LEN as u16).to_be_bytes());
        encoded.extend_from_slice(&self.generation.to_be_bytes());
        encoded.extend_from_slice(&self.not_before_ms.to_be_bytes());
        encoded.extend_from_slice(&self.expires_ms.to_be_bytes());
        encoded.extend_from_slice(self.public_key.as_ref());
        encoded
    }

    /// Return the root-authorized online-key generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the first valid Unix millisecond.
    pub const fn not_before_ms(&self) -> u64 {
        self.not_before_ms
    }

    /// Return the exclusive expiry in Unix milliseconds.
    pub const fn expires_ms(&self) -> u64 {
        self.expires_ms
    }

    /// Borrow the authorized ML-DSA-65 online public key.
    pub fn public_key(&self) -> &[u8] {
        self.public_key.as_ref()
    }
}

/// Facts that the transport must derive from its actual, completed session.
/// In particular, `tls_exporter` must be produced by TLS 1.3 after checking
/// the negotiated hybrid group; caller-supplied Hello fields are insufficient.
pub struct FederationSessionTranscript {
    initiator: FederationNodeId,
    responder: FederationNodeId,
    initiator_nonce: [u8; 32],
    responder_nonce: [u8; 32],
    tls_exporter: [u8; 48],
    capabilities_digest: [u8; 48],
}

impl FederationSessionTranscript {
    /// Validate session roles and nonzero challenges, exporter and scope digest.
    pub fn new(
        initiator: FederationNodeId,
        responder: FederationNodeId,
        initiator_nonce: [u8; 32],
        responder_nonce: [u8; 32],
        tls_exporter: [u8; 48],
        capabilities_digest: [u8; 48],
    ) -> Result<Self, FederationIdentityError> {
        if initiator == responder
            || initiator_nonce == [0; 32]
            || responder_nonce == [0; 32]
            || tls_exporter == [0; 48]
            || capabilities_digest == [0; 48]
        {
            return Err(FederationIdentityError::InvalidSessionTranscript);
        }
        Ok(Self {
            initiator,
            responder,
            initiator_nonce,
            responder_nonce,
            tls_exporter,
            capabilities_digest,
        })
    }

    fn signed_input(
        &self,
        signer: FederationNodeId,
        authorization_digest: &[u8; 48],
    ) -> Result<Vec<u8>, FederationIdentityError> {
        if signer != self.initiator && signer != self.responder {
            return Err(FederationIdentityError::PeerMismatch);
        }
        let mut input = Vec::with_capacity(SESSION_PREFIX.len() + 48 * 6 + 64);
        input.extend_from_slice(SESSION_PREFIX);
        input.extend_from_slice(signer.as_bytes());
        input.extend_from_slice(self.initiator.as_bytes());
        input.extend_from_slice(self.responder.as_bytes());
        input.extend_from_slice(&self.initiator_nonce);
        input.extend_from_slice(&self.responder_nonce);
        input.extend_from_slice(&self.tls_exporter);
        input.extend_from_slice(&self.capabilities_digest);
        input.extend_from_slice(authorization_digest);
        Ok(input)
    }

    /// Bind a subject holder's proof to the exact node-authenticated TLS
    /// session, including both roles, fresh challenges and negotiated scope.
    pub fn subject_channel_binding(&self) -> [u8; 48] {
        let mut hasher = Sha384::new();
        hasher.update(SUBJECT_CHANNEL_PREFIX);
        hasher.update(self.initiator.as_bytes());
        hasher.update(self.responder.as_bytes());
        hasher.update(self.initiator_nonce);
        hasher.update(self.responder_nonce);
        hasher.update(self.tls_exporter);
        hasher.update(self.capabilities_digest);
        hasher.finalize().into()
    }

    /// Whether this node is one of the two transcript participants.
    pub fn includes(&self, node: FederationNodeId) -> bool {
        node == self.initiator || node == self.responder
    }
}

/// An online ML-DSA-65 signer. The host owns secret wrapping and rotation.
pub struct FederationOnlineKey(PqdsaKeyPair);

impl FederationOnlineKey {
    /// Generate a fresh ML-DSA-65 online signing key.
    pub fn generate() -> Result<Self, FederationIdentityError> {
        PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
            .map(Self)
            .map_err(|_error| FederationIdentityError::CryptoFailure)
    }

    /// Load an online signing key from PKCS#8 host storage.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, FederationIdentityError> {
        PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, bytes)
            .map(Self)
            .map_err(|_error| FederationIdentityError::InvalidPrivateKey)
    }

    /// Export this online signing key in PKCS#8 for secure host storage.
    pub fn to_pkcs8(&self) -> Result<aws_lc_rs::pkcs8::Document, FederationIdentityError> {
        self.0
            .to_pkcs8v1()
            .map_err(|_error| FederationIdentityError::CryptoFailure)
    }

    /// Borrow the online public key to be authorized by the root.
    pub fn public_key(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    /// Sign the transcript only if this key matches the supplied authorization.
    pub fn sign_session(
        &self,
        signer: FederationNodeId,
        authorization: &FederationOnlineKeyAuthorization,
        transcript: &FederationSessionTranscript,
    ) -> Result<Vec<u8>, FederationIdentityError> {
        if self.public_key() != authorization.public_key() {
            return Err(FederationIdentityError::InvalidOnlineAuthorization);
        }
        let authorization_digest = Sha384::digest(authorization.encode()).into();
        let input = transcript.signed_input(signer, &authorization_digest)?;
        let mut signature = vec![0; ML_DSA_65_SIGNING.signature_len()];
        let written = self
            .0
            .sign(&input, &mut signature)
            .map_err(|_error| FederationIdentityError::CryptoFailure)?;
        if written != signature.len() {
            return Err(FederationIdentityError::CryptoFailure);
        }
        Ok(signature)
    }
}

/// A successful cryptographic proof over the supplied transcript. The caller
/// must establish that the transcript came from its actual approved TLS
/// session, enforce local revocation/generation policy and authorize requests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedFederationPeerProof {
    node: FederationNodeId,
    online_generation: u64,
    not_before_ms: u64,
    expires_ms: u64,
    authorization_digest: [u8; 48],
    subject_channel_binding: [u8; 48],
}

impl VerifiedFederationPeerProof {
    /// Inclusive start of the root-authorized online key's validity window.
    pub const fn not_before_ms(self) -> u64 {
        self.not_before_ms
    }

    /// Return the node whose online session signature was verified.
    pub const fn node_id(self) -> FederationNodeId {
        self.node
    }

    /// Return the generation recorded in the root authorization.
    pub const fn online_generation(self) -> u64 {
        self.online_generation
    }

    /// Return the exclusive expiry of the verified online authorization.
    pub const fn expires_ms(self) -> u64 {
        self.expires_ms
    }

    /// SHA-384 of the exact canonical, root-signed online authorization. A
    /// local policy can revoke one key even if a root reused its generation.
    pub const fn authorization_digest(self) -> [u8; 48] {
        self.authorization_digest
    }

    /// Return the binding used by subject holder proofs on this session.
    pub const fn subject_channel_binding(self) -> [u8; 48] {
        self.subject_channel_binding
    }
}

/// The single cryptographic verification path from the root descriptor and
/// root authorization to the online proof over the current session transcript.
pub fn verify_federation_peer_proof(
    root: &FederationRoot,
    expected_peer: FederationNodeId,
    authorization: &FederationOnlineKeyAuthorization,
    root_signature: &[u8],
    transcript: &FederationSessionTranscript,
    online_signature: &[u8],
    now_ms: u64,
) -> Result<VerifiedFederationPeerProof, FederationIdentityError> {
    if !expected_peer.matches_root(root)
        || (expected_peer != transcript.initiator && expected_peer != transcript.responder)
    {
        return Err(FederationIdentityError::PeerMismatch);
    }
    if now_ms < authorization.not_before_ms || now_ms >= authorization.expires_ms {
        return Err(FederationIdentityError::OnlineKeyOutsideValidity);
    }
    let authorization_bytes = authorization.encode();
    root.verify(
        RootSignaturePurpose::OnlineKeyAuthorization,
        &authorization_bytes,
        root_signature,
    )?;
    if online_signature.len() != ML_DSA_65_SIGNING.signature_len() {
        return Err(FederationIdentityError::InvalidSignature);
    }
    let authorization_digest = Sha384::digest(&authorization_bytes).into();
    let signed = transcript.signed_input(expected_peer, &authorization_digest)?;
    authorization
        .public_key
        .verify_sig(&signed, online_signature)
        .map_err(|_error| FederationIdentityError::InvalidSignature)?;
    Ok(VerifiedFederationPeerProof {
        node: expected_peer,
        online_generation: authorization.generation,
        not_before_ms: authorization.not_before_ms,
        expires_ms: authorization.expires_ms,
        authorization_digest,
        subject_channel_binding: transcript.subject_channel_binding(),
    })
}
