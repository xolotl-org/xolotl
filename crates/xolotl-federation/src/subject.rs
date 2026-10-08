//! Issuer-approved subject assertions and holder proofs for one authenticated
//! federation session. A wire context number is only an index into this state.

use std::collections::HashMap;

use aws_lc_rs::signature::{
    KeyPair as _, ML_DSA_65, ML_DSA_65_SIGNING, ParsedPublicKey, PqdsaKeyPair,
};
use sha2::{Digest as _, Sha384};
use thiserror::Error;

use crate::{FederationNodeId, FederationSessionTranscript, VerifiedFederationPeerProof};

const ISSUER_PREFIX: &[u8] = b"xolotl.federation.subject-issuer.v1\0";
const ISSUER_ID_PREFIX: &[u8] = b"xolotl.federation.subject-issuer-id.v1\0";
const ASSERTION_PREFIX: &[u8] = b"xolotl.federation.subject-assertion.v1\0";
const ASSERTION_SIGNATURE_PREFIX: &[u8] = b"xolotl.federation.subject-assertion-signature.v1\0";
const ASSERTION_DIGEST_PREFIX: &[u8] = b"xolotl.federation.subject-assertion-digest.v1\0";
const PRESENTATION_PREFIX: &[u8] = b"xolotl.federation.subject-presentation.v1\0";
const REQUEST_PREFIX: &[u8] = b"xolotl.federation.subject-request.v1\0";
const ALGORITHM: [u8; 2] = 1u16.to_be_bytes(); // ML-DSA-65
const SIGNATURE_MODE: [u8; 2] = 1u16.to_be_bytes(); // pure ML-DSA, empty context
const PUBLIC_KEY_LEN: usize = 1952;
const MAX_NAME_BYTES: usize = 256;
const MAX_CONTEXTS: usize = 32;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
/// SHA-384 identity of an issuer descriptor and its ML-DSA-65 public key.
pub struct SubjectIssuerId([u8; 48]);

impl SubjectIssuerId {
    /// Construct an issuer identity from its canonical digest bytes.
    pub const fn from_bytes(bytes: [u8; 48]) -> Self {
        Self(bytes)
    }

    /// Return the canonical issuer identity bytes.
    pub const fn as_bytes(self) -> [u8; 48] {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
/// Operation scope for which an issuer assertion is valid.
pub enum SubjectPurpose {
    /// Discover resources using a hosted subject.
    Discover = 1,
    /// Synchronize a stream using a hosted subject.
    Sync = 2,
    /// Invoke an exported method using a hosted subject.
    Invoke = 3,
    /// Read a granted object using a hosted subject.
    ObjectRead = 4,
}

impl SubjectPurpose {
    fn decode(value: u8) -> Result<Self, SubjectProofError> {
        match value {
            1 => Ok(Self::Discover),
            2 => Ok(Self::Sync),
            3 => Ok(Self::Invoke),
            4 => Ok(Self::ObjectRead),
            _ => Err(SubjectProofError::InvalidAssertion),
        }
    }
}

/// Stable identity under an issuer's authority. The namespace and subject ID
/// must not be reused by that issuer after account deletion.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct HostedSubject {
    /// Issuer responsible for this stable subject identity.
    pub issuer: SubjectIssuerId,
    /// Issuer-scoped namespace for the subject.
    pub namespace: String,
    /// Issuer-scoped subject identifier within the namespace.
    pub subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Authenticated principal attached to a federated request.
pub enum FederationSubject {
    /// Peer node proven by the authenticated federation session.
    Node(FederationNodeId),
    /// Issuer-asserted principal with a separate holder proof.
    Hosted(HostedSubject),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
/// Failures in issuer assertions and hosted-subject proofs.
pub enum SubjectProofError {
    #[error("invalid subject issuer descriptor")]
    /// A subject issuer descriptor is malformed or mismatched.
    InvalidIssuer,
    #[error("invalid or noncanonical subject assertion")]
    /// An assertion violates canonical encoding or claim constraints.
    InvalidAssertion,
    #[error("invalid subject signature")]
    /// An issuer or holder signature did not verify.
    InvalidSignature,
    #[error("subject issuer is not authorized for this namespace and purpose")]
    /// Local policy does not admit this issuer for the requested scope.
    IssuerUnauthorized,
    #[error("subject audience, presenter, purpose or session differs")]
    /// Audience, presenter, purpose or session binding differs.
    BindingMismatch,
    #[error("subject assertion is not valid at this time")]
    /// The assertion has not started or has expired.
    OutsideValidity,
    #[error("subject holder proof is required")]
    /// A hosted request lacks its per-request holder signature.
    MissingHolderProof,
    #[error("subject context is unavailable or already assigned")]
    /// A context index is missing, reserved or already assigned.
    ContextConflict,
    #[error("too many subject contexts")]
    /// The session has reached its hosted-context limit.
    Capacity,
    #[error("subject signature operation failed")]
    /// The ML-DSA signing operation failed.
    CryptoFailure,
}

/// The receiving host decides which issuer may assert which namespace and
/// purpose. A valid signature alone never grants this authority.
pub trait SubjectIssuerPolicy: Send + Sync {
    /// Decide whether this issuer may assert the namespace for this presenter and audience.
    fn accepts(
        &self,
        issuer: SubjectIssuerId,
        namespace: &str,
        purpose: SubjectPurpose,
        presenter: FederationNodeId,
        audience: FederationNodeId,
    ) -> bool;
}

/// Validated public issuer descriptor and its stable identity.
pub struct SubjectIssuer {
    public_key: ParsedPublicKey,
    id: SubjectIssuerId,
}

impl SubjectIssuer {
    /// Encoded byte length of the canonical issuer descriptor.
    pub const ENCODED_LEN: usize = ISSUER_PREFIX.len() + 6 + PUBLIC_KEY_LEN;

    /// Validate an ML-DSA-65 issuer public key and derive its identity.
    pub fn from_public_key(public_key: &[u8]) -> Result<Self, SubjectProofError> {
        if public_key.len() != PUBLIC_KEY_LEN {
            return Err(SubjectProofError::InvalidIssuer);
        }
        let public_key = ParsedPublicKey::new(&ML_DSA_65, public_key)
            .map_err(|_error| SubjectProofError::InvalidIssuer)?;
        let mut hasher = Sha384::new();
        hasher.update(ISSUER_ID_PREFIX);
        hasher.update(ISSUER_PREFIX);
        hasher.update(ALGORITHM);
        hasher.update(SIGNATURE_MODE);
        hasher.update((PUBLIC_KEY_LEN as u16).to_be_bytes());
        hasher.update(public_key.as_ref());
        Ok(Self {
            public_key,
            id: SubjectIssuerId(hasher.finalize().into()),
        })
    }

    /// Decode a canonical versioned issuer descriptor.
    pub fn decode(bytes: &[u8]) -> Result<Self, SubjectProofError> {
        if bytes.len() != Self::ENCODED_LEN || !bytes.starts_with(ISSUER_PREFIX) {
            return Err(SubjectProofError::InvalidIssuer);
        }
        let header = &bytes[ISSUER_PREFIX.len()..ISSUER_PREFIX.len() + 6];
        if header[..2] != ALGORITHM
            || header[2..4] != SIGNATURE_MODE
            || header[4..6] != (PUBLIC_KEY_LEN as u16).to_be_bytes()
        {
            return Err(SubjectProofError::InvalidIssuer);
        }
        Self::from_public_key(&bytes[ISSUER_PREFIX.len() + 6..])
    }

    /// Encode the descriptor identified by its public key.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::ENCODED_LEN);
        bytes.extend_from_slice(ISSUER_PREFIX);
        bytes.extend_from_slice(&ALGORITHM);
        bytes.extend_from_slice(&SIGNATURE_MODE);
        bytes.extend_from_slice(&(PUBLIC_KEY_LEN as u16).to_be_bytes());
        bytes.extend_from_slice(self.public_key.as_ref());
        bytes
    }

    /// Return the stable digest identity of this issuer.
    pub const fn id(&self) -> SubjectIssuerId {
        self.id
    }

    /// Verify an issuer signature over the canonical assertion bytes. Hosts
    /// loading static credentials can reject tampering before opening a Session.
    pub fn verify_assertion(
        &self,
        assertion: &SubjectAssertion,
        signature: &[u8],
    ) -> Result<(), SubjectProofError> {
        if assertion.subject().issuer != self.id {
            return Err(SubjectProofError::InvalidIssuer);
        }
        verify(
            &self.public_key,
            &assertion_signature_input(&assertion.encode()),
            signature,
        )
    }
}

/// The host owns storage and lifecycle of this issuer secret. It must only
/// issue subjects whose source identity the host has actually established.
pub struct SubjectIssuerKey(PqdsaKeyPair);

impl SubjectIssuerKey {
    /// Generate a fresh ML-DSA-65 issuer signing key.
    pub fn generate() -> Result<Self, SubjectProofError> {
        PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
            .map(Self)
            .map_err(|_error| SubjectProofError::CryptoFailure)
    }

    /// Decode a host-managed issuer signing key from PKCS#8.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, SubjectProofError> {
        PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, bytes)
            .map(Self)
            .map_err(|_error| SubjectProofError::InvalidIssuer)
    }

    /// Export this signing key in PKCS#8 for secure host storage.
    pub fn to_pkcs8(&self) -> Result<aws_lc_rs::pkcs8::Document, SubjectProofError> {
        self.0
            .to_pkcs8v1()
            .map_err(|_error| SubjectProofError::CryptoFailure)
    }

    /// Derive the public issuer descriptor for this signing key.
    pub fn issuer(&self) -> Result<SubjectIssuer, SubjectProofError> {
        SubjectIssuer::from_public_key(self.0.public_key().as_ref())
    }

    /// Sign an assertion only when its issuer ID matches this key.
    pub fn sign_assertion(
        &self,
        assertion: &SubjectAssertion,
    ) -> Result<Vec<u8>, SubjectProofError> {
        if self.issuer()?.id() != assertion.subject.issuer {
            return Err(SubjectProofError::InvalidIssuer);
        }
        sign(&self.0, &assertion_signature_input(&assertion.encode()))
    }
}

/// A holder key stays with the user, service or an explicitly trusted host.
/// Its signature is required on every hosted-subject business request.
pub struct SubjectHolderKey(PqdsaKeyPair);

impl SubjectHolderKey {
    /// Generate a fresh ML-DSA-65 holder signing key.
    pub fn generate() -> Result<Self, SubjectProofError> {
        PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
            .map(Self)
            .map_err(|_error| SubjectProofError::CryptoFailure)
    }

    /// Decode a holder signing key from PKCS#8.
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self, SubjectProofError> {
        PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, bytes)
            .map(Self)
            .map_err(|_error| SubjectProofError::InvalidAssertion)
    }

    /// Export this holder key in PKCS#8 for secure holder storage.
    pub fn to_pkcs8(&self) -> Result<aws_lc_rs::pkcs8::Document, SubjectProofError> {
        self.0
            .to_pkcs8v1()
            .map_err(|_error| SubjectProofError::CryptoFailure)
    }

    /// Borrow the public key to embed in holder-bound assertions.
    pub fn public_key(&self) -> &[u8] {
        self.0.public_key().as_ref()
    }

    /// Sign a presentation bound to this assertion and TLS session.
    pub fn sign_presentation(
        &self,
        assertion: &SubjectAssertion,
        transcript: &FederationSessionTranscript,
    ) -> Result<Vec<u8>, SubjectProofError> {
        self.check_assertion(assertion)?;
        sign(
            &self.0,
            &presentation_input(assertion.digest(), transcript.subject_channel_binding()),
        )
    }

    /// Sign one request digest, context, purpose and request ID for this session.
    pub fn sign_request(
        &self,
        assertion: &SubjectAssertion,
        transcript: &FederationSessionTranscript,
        context_id: u32,
        request_id: u64,
        request_digest: [u8; 48],
    ) -> Result<Vec<u8>, SubjectProofError> {
        self.check_assertion(assertion)?;
        if context_id == 0 || request_id == 0 {
            return Err(SubjectProofError::BindingMismatch);
        }
        sign(
            &self.0,
            &request_input(
                assertion.digest(),
                transcript.subject_channel_binding(),
                assertion.purpose,
                context_id,
                request_id,
                request_digest,
            ),
        )
    }

    fn check_assertion(&self, assertion: &SubjectAssertion) -> Result<(), SubjectProofError> {
        if self.public_key() != assertion.holder_public_key {
            return Err(SubjectProofError::BindingMismatch);
        }
        Ok(())
    }
}

/// Canonical, bounded assertion. Issuer signature and the holder's current
/// channel proof are transmitted separately from these immutable claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectAssertion {
    subject: HostedSubject,
    audience: FederationNodeId,
    presenter: FederationNodeId,
    purpose: SubjectPurpose,
    not_before_ms: u64,
    expires_ms: u64,
    holder_public_key: Vec<u8>,
}

impl SubjectAssertion {
    #[expect(
        clippy::too_many_arguments,
        reason = "the signed claim has fixed protocol fields"
    )]
    /// Construct a bounded canonical claim tied to a holder public key.
    pub fn new(
        issuer: SubjectIssuerId,
        namespace: impl Into<String>,
        subject: impl Into<String>,
        audience: FederationNodeId,
        presenter: FederationNodeId,
        purpose: SubjectPurpose,
        not_before_ms: u64,
        expires_ms: u64,
        holder_public_key: &[u8],
    ) -> Result<Self, SubjectProofError> {
        let namespace = namespace.into();
        let subject = subject.into();
        if !valid_name(&namespace)
            || !valid_name(&subject)
            || not_before_ms >= expires_ms
            || holder_public_key.len() != PUBLIC_KEY_LEN
            || ParsedPublicKey::new(&ML_DSA_65, holder_public_key).is_err()
        {
            return Err(SubjectProofError::InvalidAssertion);
        }
        Ok(Self {
            subject: HostedSubject {
                issuer,
                namespace,
                subject,
            },
            audience,
            presenter,
            purpose,
            not_before_ms,
            expires_ms,
            holder_public_key: holder_public_key.to_vec(),
        })
    }

    /// Decode and validate the canonical assertion claims.
    pub fn decode(bytes: &[u8]) -> Result<Self, SubjectProofError> {
        let Some(mut remaining) = bytes.strip_prefix(ASSERTION_PREFIX) else {
            return Err(SubjectProofError::InvalidAssertion);
        };
        let issuer = SubjectIssuerId(take::<48>(&mut remaining)?);
        let namespace = read_name(&mut remaining)?;
        let subject = read_name(&mut remaining)?;
        let audience = FederationNodeId::from_bytes(take::<48>(&mut remaining)?);
        let presenter = FederationNodeId::from_bytes(take::<48>(&mut remaining)?);
        let purpose = SubjectPurpose::decode(take::<1>(&mut remaining)?[0])?;
        let not_before_ms = u64::from_be_bytes(take::<8>(&mut remaining)?);
        let expires_ms = u64::from_be_bytes(take::<8>(&mut remaining)?);
        let key_len = u16::from_be_bytes(take::<2>(&mut remaining)?) as usize;
        if key_len != PUBLIC_KEY_LEN || remaining.len() != PUBLIC_KEY_LEN {
            return Err(SubjectProofError::InvalidAssertion);
        }
        Self::new(
            issuer,
            namespace,
            subject,
            audience,
            presenter,
            purpose,
            not_before_ms,
            expires_ms,
            remaining,
        )
    }

    /// Encode immutable claims; issuer and holder signatures travel separately.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(ASSERTION_PREFIX.len() + PUBLIC_KEY_LEN + 700);
        bytes.extend_from_slice(ASSERTION_PREFIX);
        bytes.extend_from_slice(&self.subject.issuer.as_bytes());
        write_name(&mut bytes, &self.subject.namespace);
        write_name(&mut bytes, &self.subject.subject);
        bytes.extend_from_slice(self.audience.as_bytes());
        bytes.extend_from_slice(self.presenter.as_bytes());
        bytes.push(self.purpose as u8);
        bytes.extend_from_slice(&self.not_before_ms.to_be_bytes());
        bytes.extend_from_slice(&self.expires_ms.to_be_bytes());
        bytes.extend_from_slice(&(PUBLIC_KEY_LEN as u16).to_be_bytes());
        bytes.extend_from_slice(&self.holder_public_key);
        bytes
    }

    /// Compute the domain-separated SHA-384 assertion digest.
    pub fn digest(&self) -> [u8; 48] {
        let mut hasher = Sha384::new();
        hasher.update(ASSERTION_DIGEST_PREFIX);
        hasher.update(self.encode());
        hasher.finalize().into()
    }

    /// Borrow the issuer-scoped hosted subject identity.
    pub fn subject(&self) -> &HostedSubject {
        &self.subject
    }

    /// Return the node for which this assertion was issued.
    pub const fn audience(&self) -> FederationNodeId {
        self.audience
    }

    /// Return the node allowed to present this assertion.
    pub const fn presenter(&self) -> FederationNodeId {
        self.presenter
    }

    /// Return the single operation purpose covered by this assertion.
    pub const fn purpose(&self) -> SubjectPurpose {
        self.purpose
    }

    /// Exclusive end of this assertion's authorization window. A retained
    /// holder-authorized request must still be within it at disclosure.
    pub const fn expires_ms(&self) -> u64 {
        self.expires_ms
    }

    /// Borrow the public key that must prove holder possession.
    pub fn holder_public_key(&self) -> &[u8] {
        &self.holder_public_key
    }
}

fn valid_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_NAME_BYTES && !value.chars().any(char::is_control)
}

fn write_name(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn read_name(bytes: &mut &[u8]) -> Result<String, SubjectProofError> {
    let len = u16::from_be_bytes(take::<2>(bytes)?) as usize;
    if len == 0 || len > MAX_NAME_BYTES || bytes.len() < len {
        return Err(SubjectProofError::InvalidAssertion);
    }
    let (value, rest) = bytes.split_at(len);
    *bytes = rest;
    let value = std::str::from_utf8(value).map_err(|_error| SubjectProofError::InvalidAssertion)?;
    if !valid_name(value) {
        return Err(SubjectProofError::InvalidAssertion);
    }
    Ok(value.to_owned())
}

fn take<const N: usize>(bytes: &mut &[u8]) -> Result<[u8; N], SubjectProofError> {
    if bytes.len() < N {
        return Err(SubjectProofError::InvalidAssertion);
    }
    let (value, rest) = bytes.split_at(N);
    *bytes = rest;
    value
        .try_into()
        .map_err(|_error| SubjectProofError::InvalidAssertion)
}

fn assertion_signature_input(assertion: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(ASSERTION_SIGNATURE_PREFIX.len() + 4 + assertion.len());
    input.extend_from_slice(ASSERTION_SIGNATURE_PREFIX);
    input.extend_from_slice(&(assertion.len() as u32).to_be_bytes());
    input.extend_from_slice(assertion);
    input
}

fn presentation_input(assertion_digest: [u8; 48], channel_binding: [u8; 48]) -> Vec<u8> {
    let mut input = Vec::with_capacity(PRESENTATION_PREFIX.len() + 96);
    input.extend_from_slice(PRESENTATION_PREFIX);
    input.extend_from_slice(&assertion_digest);
    input.extend_from_slice(&channel_binding);
    input
}

fn request_input(
    assertion_digest: [u8; 48],
    channel_binding: [u8; 48],
    purpose: SubjectPurpose,
    context_id: u32,
    request_id: u64,
    request_digest: [u8; 48],
) -> Vec<u8> {
    let mut input = Vec::with_capacity(REQUEST_PREFIX.len() + 157);
    input.extend_from_slice(REQUEST_PREFIX);
    input.extend_from_slice(&assertion_digest);
    input.extend_from_slice(&channel_binding);
    input.push(purpose as u8);
    input.extend_from_slice(&context_id.to_be_bytes());
    input.extend_from_slice(&request_id.to_be_bytes());
    input.extend_from_slice(&request_digest);
    input
}

fn sign(key: &PqdsaKeyPair, input: &[u8]) -> Result<Vec<u8>, SubjectProofError> {
    let mut signature = vec![0; ML_DSA_65_SIGNING.signature_len()];
    let written = key
        .sign(input, &mut signature)
        .map_err(|_error| SubjectProofError::CryptoFailure)?;
    if written != signature.len() {
        return Err(SubjectProofError::CryptoFailure);
    }
    Ok(signature)
}

fn verify(key: &ParsedPublicKey, input: &[u8], signature: &[u8]) -> Result<(), SubjectProofError> {
    if signature.len() != ML_DSA_65_SIGNING.signature_len() {
        return Err(SubjectProofError::InvalidSignature);
    }
    key.verify_sig(input, signature)
        .map_err(|_error| SubjectProofError::InvalidSignature)
}

struct VerifiedHostedSubject {
    assertion: SubjectAssertion,
    holder: ParsedPublicKey,
}

/// Session-local map of independently verified subjects. Context zero is the
/// authenticated node itself. Hosted contexts require a holder signature on
/// each business request, so one user cannot reuse another user's index.
pub struct SessionSubjects {
    peer: FederationNodeId,
    audience: FederationNodeId,
    channel_binding: [u8; 48],
    contexts: HashMap<u32, VerifiedHostedSubject>,
}

impl SessionSubjects {
    /// Retain only the validity deadline of an already holder-authorized
    /// request across a delivery queue. This does not authorize a request or
    /// consume a holder signature again. Context zero is node-self.
    pub fn delivery_deadline(&self, context_id: u32) -> Result<u64, SubjectProofError> {
        if context_id == 0 {
            return Ok(u64::MAX);
        }
        self.contexts
            .get(&context_id)
            .map(|context| context.assertion.expires_ms)
            .ok_or(SubjectProofError::ContextConflict)
    }

    /// Create contexts only for the peer and audience in a verified session.
    pub fn new(
        proof: VerifiedFederationPeerProof,
        transcript: &FederationSessionTranscript,
        audience: FederationNodeId,
    ) -> Result<Self, SubjectProofError> {
        let channel_binding = transcript.subject_channel_binding();
        if proof.node_id() == audience
            || !transcript.includes(proof.node_id())
            || !transcript.includes(audience)
            || proof.subject_channel_binding() != channel_binding
        {
            return Err(SubjectProofError::BindingMismatch);
        }
        Ok(Self {
            peer: proof.node_id(),
            audience,
            channel_binding,
            contexts: HashMap::new(),
        })
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the wire proof has fixed protocol fields"
    )]
    /// Install a new hosted context after issuer-policy and dual-signature checks.
    pub fn install(
        &mut self,
        context_id: u32,
        issuer: &SubjectIssuer,
        assertion_bytes: &[u8],
        issuer_signature: &[u8],
        holder_presentation: &[u8],
        purpose: SubjectPurpose,
        now_ms: u64,
        policy: &dyn SubjectIssuerPolicy,
    ) -> Result<HostedSubject, SubjectProofError> {
        if context_id == 0 || self.contexts.contains_key(&context_id) {
            return Err(SubjectProofError::ContextConflict);
        }
        if self.contexts.len() >= MAX_CONTEXTS {
            return Err(SubjectProofError::Capacity);
        }
        let assertion = SubjectAssertion::decode(assertion_bytes)?;
        self.check_claims(issuer, &assertion, purpose, now_ms, policy)?;
        verify(
            &issuer.public_key,
            &assertion_signature_input(assertion_bytes),
            issuer_signature,
        )?;
        let holder = ParsedPublicKey::new(&ML_DSA_65, &assertion.holder_public_key)
            .map_err(|_error| SubjectProofError::InvalidAssertion)?;
        verify(
            &holder,
            &presentation_input(assertion.digest(), self.channel_binding),
            holder_presentation,
        )?;
        let subject = assertion.subject.clone();
        self.contexts
            .insert(context_id, VerifiedHostedSubject { assertion, holder });
        Ok(subject)
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "a request binds all signed context fields"
    )]
    /// Resolve a context for one request, checking current policy and holder proof.
    pub fn authorize_request(
        &self,
        context_id: u32,
        purpose: SubjectPurpose,
        request_id: u64,
        request_digest: [u8; 48],
        holder_signature: Option<&[u8]>,
        now_ms: u64,
        policy: &dyn SubjectIssuerPolicy,
    ) -> Result<FederationSubject, SubjectProofError> {
        if request_id == 0 {
            return Err(SubjectProofError::BindingMismatch);
        }
        if context_id == 0 {
            return Ok(FederationSubject::Node(self.peer));
        }
        let context = self
            .contexts
            .get(&context_id)
            .ok_or(SubjectProofError::ContextConflict)?;
        self.check_claims_for_current_request(&context.assertion, purpose, now_ms, policy)?;
        let holder_signature = holder_signature.ok_or(SubjectProofError::MissingHolderProof)?;
        verify(
            &context.holder,
            &request_input(
                context.assertion.digest(),
                self.channel_binding,
                purpose,
                context_id,
                request_id,
                request_digest,
            ),
            holder_signature,
        )?;
        Ok(FederationSubject::Hosted(context.assertion.subject.clone()))
    }

    fn check_claims(
        &self,
        issuer: &SubjectIssuer,
        assertion: &SubjectAssertion,
        purpose: SubjectPurpose,
        now_ms: u64,
        policy: &dyn SubjectIssuerPolicy,
    ) -> Result<(), SubjectProofError> {
        if issuer.id() != assertion.subject.issuer {
            return Err(SubjectProofError::InvalidIssuer);
        }
        self.check_claims_for_current_request(assertion, purpose, now_ms, policy)
    }

    fn check_claims_for_current_request(
        &self,
        assertion: &SubjectAssertion,
        purpose: SubjectPurpose,
        now_ms: u64,
        policy: &dyn SubjectIssuerPolicy,
    ) -> Result<(), SubjectProofError> {
        if assertion.audience != self.audience
            || assertion.presenter != self.peer
            || assertion.purpose != purpose
        {
            return Err(SubjectProofError::BindingMismatch);
        }
        if now_ms < assertion.not_before_ms || now_ms >= assertion.expires_ms {
            return Err(SubjectProofError::OutsideValidity);
        }
        if !policy.accepts(
            assertion.subject.issuer,
            &assertion.subject.namespace,
            purpose,
            self.peer,
            self.audience,
        ) {
            return Err(SubjectProofError::IssuerUnauthorized);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use anyhow::{Result, ensure};

    use super::*;
    use crate::{
        FederationOnlineKey, FederationOnlineKeyAuthorization, FederationRootKey,
        RootSignaturePurpose, verify_federation_peer_proof,
    };

    struct Policy {
        issuer: SubjectIssuerId,
        allowed: AtomicBool,
    }

    impl SubjectIssuerPolicy for Policy {
        fn accepts(
            &self,
            issuer: SubjectIssuerId,
            namespace: &str,
            purpose: SubjectPurpose,
            _presenter: FederationNodeId,
            _audience: FederationNodeId,
        ) -> bool {
            self.allowed.load(Ordering::SeqCst)
                && issuer == self.issuer
                && namespace == "accounts.example"
                && purpose == SubjectPurpose::Sync
        }
    }

    fn authenticated_session(
        peer_root: &FederationRootKey,
        audience: FederationNodeId,
        nonce: u8,
    ) -> Result<(VerifiedFederationPeerProof, FederationSessionTranscript)> {
        let root = peer_root.root()?;
        let peer = root.node_id();
        let online_key = FederationOnlineKey::generate()?;
        let authorization =
            FederationOnlineKeyAuthorization::new(online_key.public_key(), 1, 100, 500)?;
        let root_signature = peer_root.sign(
            RootSignaturePurpose::OnlineKeyAuthorization,
            &authorization.encode(),
        )?;
        let transcript = FederationSessionTranscript::new(
            peer,
            audience,
            [nonce; 32],
            [2; 32],
            [nonce; 48],
            [4; 48],
        )?;
        let online_signature = online_key.sign_session(peer, &authorization, &transcript)?;
        let proof = verify_federation_peer_proof(
            &root,
            peer,
            &authorization,
            &root_signature,
            &transcript,
            &online_signature,
            150,
        )?;
        Ok((proof, transcript))
    }

    fn assertion(
        issuer: SubjectIssuerId,
        holder: &SubjectHolderKey,
        audience: FederationNodeId,
        presenter: FederationNodeId,
        name: &str,
    ) -> Result<SubjectAssertion> {
        Ok(SubjectAssertion::new(
            issuer,
            "accounts.example",
            name,
            audience,
            presenter,
            SubjectPurpose::Sync,
            100,
            250,
            holder.public_key(),
        )?)
    }

    #[test]
    fn separate_users_require_their_own_holder_proof_for_every_request() -> Result<()> {
        let issuer_key = SubjectIssuerKey::generate()?;
        let issuer = issuer_key.issuer()?;
        ensure!(SubjectIssuer::decode(&issuer.encode())?.id() == issuer.id());
        let policy = Policy {
            issuer: issuer.id(),
            allowed: AtomicBool::new(true),
        };
        let peer_root = FederationRootKey::generate()?;
        let peer = peer_root.root()?.node_id();
        let audience = FederationRootKey::generate()?.root()?.node_id();
        let (proof, transcript) = authenticated_session(&peer_root, audience, 1)?;
        let mut contexts = SessionSubjects::new(proof, &transcript, audience)?;
        let alice_key = SubjectHolderKey::generate()?;
        let alice = assertion(issuer.id(), &alice_key, audience, peer, "alice")?;
        let alice_signature = issuer_key.sign_assertion(&alice)?;
        let alice_presentation = alice_key.sign_presentation(&alice, &transcript)?;
        ensure!(SubjectAssertion::decode(&alice.encode())? == alice);
        ensure!(
            contexts.install(
                7,
                &issuer,
                &alice.encode(),
                &alice_signature,
                &alice_presentation,
                SubjectPurpose::Sync,
                150,
                &policy,
            )? == *alice.subject()
        );
        let charlie_key = SubjectHolderKey::generate()?;
        let charlie = assertion(issuer.id(), &charlie_key, audience, peer, "charlie")?;
        contexts.install(
            8,
            &issuer,
            &charlie.encode(),
            &issuer_key.sign_assertion(&charlie)?,
            &charlie_key.sign_presentation(&charlie, &transcript)?,
            SubjectPurpose::Sync,
            150,
            &policy,
        )?;
        let request_digest = [9; 48];
        let alice_request = alice_key.sign_request(&alice, &transcript, 7, 42, request_digest)?;
        ensure!(
            contexts.authorize_request(
                0,
                SubjectPurpose::Sync,
                42,
                request_digest,
                None,
                150,
                &policy,
            )? == FederationSubject::Node(peer)
        );
        ensure!(
            contexts.authorize_request(
                7,
                SubjectPurpose::Sync,
                42,
                request_digest,
                Some(&alice_request),
                150,
                &policy,
            )? == FederationSubject::Hosted(alice.subject().clone())
        );
        ensure!(matches!(
            contexts.authorize_request(
                7,
                SubjectPurpose::Sync,
                42,
                request_digest,
                None,
                150,
                &policy,
            ),
            Err(SubjectProofError::MissingHolderProof)
        ));
        ensure!(matches!(
            contexts.authorize_request(
                8,
                SubjectPurpose::Sync,
                42,
                request_digest,
                Some(&alice_request),
                150,
                &policy,
            ),
            Err(SubjectProofError::InvalidSignature)
        ));
        ensure!(matches!(
            contexts.authorize_request(
                7,
                SubjectPurpose::Sync,
                42,
                [8; 48],
                Some(&alice_request),
                150,
                &policy,
            ),
            Err(SubjectProofError::InvalidSignature)
        ));
        ensure!(matches!(
            contexts.authorize_request(
                7,
                SubjectPurpose::Invoke,
                42,
                request_digest,
                Some(&alice_request),
                150,
                &policy,
            ),
            Err(SubjectProofError::BindingMismatch)
        ));
        ensure!(matches!(
            contexts.authorize_request(
                7,
                SubjectPurpose::Sync,
                42,
                request_digest,
                Some(&alice_request),
                250,
                &policy,
            ),
            Err(SubjectProofError::OutsideValidity)
        ));
        policy.allowed.store(false, Ordering::SeqCst);
        ensure!(matches!(
            contexts.authorize_request(
                7,
                SubjectPurpose::Sync,
                42,
                request_digest,
                Some(&alice_request),
                150,
                &policy,
            ),
            Err(SubjectProofError::IssuerUnauthorized)
        ));
        Ok(())
    }

    #[test]
    fn audience_presenter_and_channel_are_bound_across_two_devices_and_rejoin() -> Result<()> {
        let issuer_key = SubjectIssuerKey::generate()?;
        let issuer = issuer_key.issuer()?;
        let policy = Policy {
            issuer: issuer.id(),
            allowed: AtomicBool::new(true),
        };
        let audience = FederationRootKey::generate()?.root()?.node_id();
        let other_audience = FederationRootKey::generate()?.root()?.node_id();
        let phone_root = FederationRootKey::generate()?;
        let home_root = FederationRootKey::generate()?;
        let phone = phone_root.root()?.node_id();
        let home = home_root.root()?.node_id();
        let holder = SubjectHolderKey::generate()?;
        let phone_assertion = assertion(issuer.id(), &holder, audience, phone, "alice")?;
        let home_assertion = assertion(issuer.id(), &holder, audience, home, "alice")?;
        ensure!(phone_assertion.subject() == home_assertion.subject());
        let (phone_proof, first_channel) = authenticated_session(&phone_root, audience, 1)?;
        let (rejoined_proof, next_channel) = authenticated_session(&phone_root, audience, 3)?;
        ensure!(matches!(
            SessionSubjects::new(phone_proof, &next_channel, audience),
            Err(SubjectProofError::BindingMismatch)
        ));
        let mut phone_contexts = SessionSubjects::new(rejoined_proof, &next_channel, audience)?;
        let old_presentation = holder.sign_presentation(&phone_assertion, &first_channel)?;
        ensure!(matches!(
            phone_contexts.install(
                1,
                &issuer,
                &phone_assertion.encode(),
                &issuer_key.sign_assertion(&phone_assertion)?,
                &old_presentation,
                SubjectPurpose::Sync,
                150,
                &policy,
            ),
            Err(SubjectProofError::InvalidSignature)
        ));
        phone_contexts.install(
            1,
            &issuer,
            &phone_assertion.encode(),
            &issuer_key.sign_assertion(&phone_assertion)?,
            &holder.sign_presentation(&phone_assertion, &next_channel)?,
            SubjectPurpose::Sync,
            150,
            &policy,
        )?;
        ensure!(matches!(
            phone_contexts.install(
                2,
                &issuer,
                &home_assertion.encode(),
                &issuer_key.sign_assertion(&home_assertion)?,
                &holder.sign_presentation(&home_assertion, &next_channel)?,
                SubjectPurpose::Sync,
                150,
                &policy,
            ),
            Err(SubjectProofError::BindingMismatch)
        ));
        let wrong_audience = assertion(issuer.id(), &holder, other_audience, phone, "alice")?;
        ensure!(matches!(
            phone_contexts.install(
                2,
                &issuer,
                &wrong_audience.encode(),
                &issuer_key.sign_assertion(&wrong_audience)?,
                &holder.sign_presentation(&wrong_audience, &next_channel)?,
                SubjectPurpose::Sync,
                150,
                &policy,
            ),
            Err(SubjectProofError::BindingMismatch)
        ));
        let (home_proof, home_channel) = authenticated_session(&home_root, audience, 5)?;
        let mut home_contexts = SessionSubjects::new(home_proof, &home_channel, audience)?;
        ensure!(
            home_contexts.install(
                1,
                &issuer,
                &home_assertion.encode(),
                &issuer_key.sign_assertion(&home_assertion)?,
                &holder.sign_presentation(&home_assertion, &home_channel)?,
                SubjectPurpose::Sync,
                150,
                &policy,
            )? == *phone_assertion.subject()
        );
        let mut corrupted = phone_assertion.encode();
        corrupted.push(0);
        ensure!(matches!(
            SubjectAssertion::decode(&corrupted),
            Err(SubjectProofError::InvalidAssertion)
        ));
        Ok(())
    }
}
