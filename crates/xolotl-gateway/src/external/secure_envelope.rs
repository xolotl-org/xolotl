//! Secure envelope primitives for external Provider/Source sessions.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use cipher::zeroize::Zeroize;
use hkdf::Hkdf;
use sha2::Sha256;

// Require both AEAD key cleanup and cipher's gated buffer-cleanup support.
const _: () = {
    const fn assert_key_cleanup<T: cipher::zeroize::ZeroizeOnDrop>() {}
    assert_key_cleanup::<ChaCha20Poly1305>();
};

/// Default replay window size for secure external envelopes.
pub const DEFAULT_SECURE_ENVELOPE_REPLAY_WINDOW: usize = 64;
/// Authenticated direction for envelopes sent by an external client to the daemon.
pub const CLIENT_TO_DAEMON: &str = "client_to_daemon";
/// Authenticated direction for envelopes sent by the daemon to an external client.
pub const DAEMON_TO_CLIENT: &str = "daemon_to_client";
const MAX_SECURE_ENVELOPE_REPLAY_WINDOW: usize = 128;
const DEFAULT_DRAIN_FRAME_TYPE: &str = "control.config_ack";

/// A paired installation's credential.
#[derive(Clone)]
pub struct ExternalCredential {
    /// Installation this credential belongs to.
    installation_id: String,
    /// The current credential generation.
    generation: u64,
    psk: [u8; 32],
}

impl ExternalCredential {
    /// Build a credential from an already-issued 32-byte PSK.
    pub fn new(installation_id: impl Into<String>, generation: u64, psk: [u8; 32]) -> Self {
        Self {
            installation_id: installation_id.into(),
            generation,
            psk,
        }
    }

    /// Installation this credential belongs to.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// The current credential generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Seal `payload` into an AEAD envelope with caller-supplied AAD.
    pub fn seal_with_aad(
        &self,
        payload: &[u8],
        aad: EnvelopeAad,
    ) -> Result<SecureEnvelope, EnvelopeError> {
        validate_envelope_aad(self.generation, &aad)?;
        let mut nonce_prefix = [0u8; 12];
        getrandom::fill(&mut nonce_prefix).map_err(|_error| EnvelopeError::Crypto)?;
        let seq = aad.seq;
        let authenticated = aad_bytes(&self.installation_id, self.generation, &aad);
        let ciphertext = self
            .cipher(&authenticated)?
            .encrypt(
                &Nonce::from(nonce_bytes(&nonce_prefix, seq)),
                Payload {
                    msg: payload,
                    aad: &authenticated,
                },
            )
            .map_err(|_error| EnvelopeError::Crypto)?;
        Ok(SecureEnvelope::from_parts(
            self.installation_id.clone(),
            self.generation,
            aad,
            nonce_prefix,
            ciphertext,
        ))
    }

    fn open(&self, env: &SecureEnvelope, valid_floor: u64) -> Result<Vec<u8>, EnvelopeError> {
        if env.installation_id != self.installation_id {
            return Err(EnvelopeError::WrongInstallation);
        }
        if env.generation < valid_floor {
            return Err(EnvelopeError::RevokedGeneration);
        }
        if env.generation != self.generation {
            return Err(EnvelopeError::BadAead);
        }
        let authenticated = aad_bytes(&env.installation_id, env.generation, &env.aad);
        self.cipher(&authenticated)?
            .decrypt(
                &Nonce::from(nonce_bytes(&env.nonce_prefix, env.aad.seq)),
                Payload {
                    msg: &env.ciphertext,
                    aad: &authenticated,
                },
            )
            .map_err(|_error| EnvelopeError::BadAead)
    }

    /// Verify and open `env` only after checking the accepted key epoch.
    /// The caller constructs the gate from the current authoritative session
    /// record on every frame, including after a rekey. An epoch copied from
    /// the envelope is not an authority decision.
    pub fn open_with_replay_window_and_epoch_gate(
        &self,
        env: &SecureEnvelope,
        valid_floor: u64,
        replay_window: &mut SecureEnvelopeReplayWindow,
        epoch_gate: &SecureEnvelopeEpochGate,
    ) -> Result<Vec<u8>, EnvelopeError> {
        validate_envelope_aad(env.generation, &env.aad)?;
        epoch_gate.check(&env.aad)?;
        let decision = replay_window.check(env.aad.seq)?;
        let plaintext = self.open(env, valid_floor)?;
        replay_window.commit(decision);
        Ok(plaintext)
    }

    fn cipher(&self, authenticated: &[u8]) -> Result<ChaCha20Poly1305, EnvelopeError> {
        let hk = Hkdf::<Sha256>::new(
            Some(b"xolotl/external/session-envelope/chacha20poly1305/v1"),
            &self.psk,
        );
        let mut key = [0u8; 32];
        hk.expand(authenticated, &mut key)
            .map_err(|_error| EnvelopeError::Crypto)?;
        let cipher = ChaCha20Poly1305::new((&key).into());
        key.zeroize();
        Ok(cipher)
    }
}

impl Drop for ExternalCredential {
    fn drop(&mut self) {
        self.psk.zeroize();
    }
}

/// Bounded replay window for one secure external envelope stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureEnvelopeReplayWindow {
    window_size: usize,
    highest: Option<u64>,
    seen: u128,
}

impl Default for SecureEnvelopeReplayWindow {
    fn default() -> Self {
        Self {
            window_size: DEFAULT_SECURE_ENVELOPE_REPLAY_WINDOW,
            highest: None,
            seen: 0,
        }
    }
}

impl SecureEnvelopeReplayWindow {
    /// Create a replay window with `window_size` sequence numbers.
    pub fn new(window_size: usize) -> Result<Self, EnvelopeError> {
        if window_size == 0 || window_size > MAX_SECURE_ENVELOPE_REPLAY_WINDOW {
            return Err(EnvelopeError::InvalidReplayWindow);
        }
        Ok(Self {
            window_size,
            highest: None,
            seen: 0,
        })
    }

    fn check(&self, seq: u64) -> Result<ReplayWindowDecision, EnvelopeError> {
        let Some(highest) = self.highest else {
            return Ok(ReplayWindowDecision::First(seq));
        };

        if seq > highest {
            let advance = seq - highest;
            if advance >= self.window_size as u64 {
                return Err(EnvelopeError::SequenceTooFarAhead);
            }
            return Ok(ReplayWindowDecision::Advance(advance));
        }

        let offset = highest - seq;
        if offset >= self.window_size as u64 {
            return Err(EnvelopeError::SequenceTooOld);
        }
        let bit = 1u128 << offset;
        if self.seen & bit != 0 {
            return Err(EnvelopeError::Replay);
        }
        Ok(ReplayWindowDecision::Within(offset))
    }

    fn commit(&mut self, decision: ReplayWindowDecision) {
        match decision {
            ReplayWindowDecision::First(seq) => {
                self.highest = Some(seq);
                self.seen = 1;
            }
            ReplayWindowDecision::Advance(advance) => {
                self.highest = self.highest.map(|highest| highest + advance);
                self.seen = ((self.seen << advance) | 1) & self.mask();
            }
            ReplayWindowDecision::Within(offset) => {
                self.seen |= 1u128 << offset;
                self.seen &= self.mask();
            }
        }
    }

    fn mask(&self) -> u128 {
        if self.window_size == MAX_SECURE_ENVELOPE_REPLAY_WINDOW {
            u128::MAX
        } else {
            (1u128 << self.window_size) - 1
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayWindowDecision {
    First(u64),
    Advance(u64),
    Within(u64),
}

/// Key-epoch policy for secure external envelopes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureEnvelopeEpochGate {
    current_key_epoch: u64,
    drain_frame_types: Vec<String>,
}

impl SecureEnvelopeEpochGate {
    /// Create a gate from the current authoritative session key epoch.
    pub fn new(current_key_epoch: u64) -> Self {
        Self {
            current_key_epoch,
            drain_frame_types: Vec::new(),
        }
    }

    /// Add an old-epoch frame type accepted during drain.
    pub fn with_drain_frame_type(mut self, frame_type: impl Into<String>) -> Self {
        let frame_type = frame_type.into();
        if !frame_type.trim().is_empty()
            && frame_type != DEFAULT_DRAIN_FRAME_TYPE
            && !self.drain_frame_types.contains(&frame_type)
        {
            self.drain_frame_types.push(frame_type);
        }
        self
    }

    /// Check `aad` against the epoch policy.
    pub fn check(&self, aad: &EnvelopeAad) -> Result<(), EnvelopeError> {
        if aad.key_epoch == self.current_key_epoch {
            return Ok(());
        }
        if aad.key_epoch.checked_add(1) != Some(self.current_key_epoch) {
            return Err(EnvelopeError::InvalidKeyEpoch);
        }
        if aad.frame_type == DEFAULT_DRAIN_FRAME_TYPE
            || self
                .drain_frame_types
                .iter()
                .any(|frame_type| frame_type == &aad.frame_type)
        {
            Ok(())
        } else {
            Err(EnvelopeError::InvalidKeyEpoch)
        }
    }
}

/// Authenticated data for one secure external frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeAad {
    /// Envelope format version.
    pub version: u32,
    /// Projection id for the frame's role session.
    pub projection_id: String,
    /// Role name bound into the frame.
    pub role: String,
    /// Session id bound into the frame.
    pub session_id: String,
    /// Monotonic frame sequence number.
    pub seq: u64,
    /// Business/control frame type.
    pub frame_type: String,
    /// Binding generation observed by the sender.
    pub binding_generation: u64,
    /// Credential generation observed by the sender.
    pub credential_generation: u64,
    /// Hash of the negotiated session transcript.
    pub transcript_hash: Vec<u8>,
    /// Session key epoch used to seal this frame.
    pub key_epoch: u64,
    /// Authenticated transport direction.
    pub direction: String,
}

impl Default for EnvelopeAad {
    fn default() -> Self {
        Self {
            version: 1,
            projection_id: String::new(),
            role: String::new(),
            session_id: String::new(),
            seq: 0,
            frame_type: "frame".into(),
            binding_generation: 0,
            credential_generation: 0,
            transcript_hash: Vec::new(),
            key_epoch: 0,
            direction: CLIENT_TO_DAEMON.into(),
        }
    }
}

/// An AEAD-protected frame envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecureEnvelope {
    /// Installation id the envelope is for.
    installation_id: String,
    /// Credential generation used to seal the frame.
    generation: u64,
    /// Authenticated frame metadata.
    aad: EnvelopeAad,
    /// Random nonce prefix; combined with `aad.seq`.
    nonce_prefix: [u8; 12],
    /// Encrypted serialized frame body.
    ciphertext: Vec<u8>,
}

impl SecureEnvelope {
    /// Construct an envelope from decoded wire fields.
    pub(crate) fn from_parts(
        installation_id: impl Into<String>,
        generation: u64,
        aad: EnvelopeAad,
        nonce_prefix: [u8; 12],
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            installation_id: installation_id.into(),
            generation,
            aad,
            nonce_prefix,
            ciphertext,
        }
    }

    /// Installation id the envelope is for.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }

    /// Credential generation used to seal the frame.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Authenticated frame metadata.
    pub fn aad(&self) -> &EnvelopeAad {
        &self.aad
    }

    /// Random nonce prefix; combined with `aad.seq`.
    pub fn nonce_prefix(&self) -> &[u8; 12] {
        &self.nonce_prefix
    }

    /// Encrypted serialized frame body.
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Consume the envelope for zero-copy transfer to a transport frame.
    pub(crate) fn into_parts(self) -> (String, u64, EnvelopeAad, [u8; 12], Vec<u8>) {
        (
            self.installation_id,
            self.generation,
            self.aad,
            self.nonce_prefix,
            self.ciphertext,
        )
    }
}

/// Why an envelope failed to open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    /// The envelope names a different installation than the credential.
    WrongInstallation,
    /// The generation is below the valid floor.
    RevokedGeneration,
    /// AEAD encryption failed.
    Crypto,
    /// The AEAD tag did not verify.
    BadAead,
    /// The authenticated metadata is not a valid external frame header.
    InvalidAad,
    /// The frame sequence number was already accepted.
    Replay,
    /// The frame sequence number is older than the retained replay window.
    SequenceTooOld,
    /// The frame sequence number is too far ahead of the accepted window.
    SequenceTooFarAhead,
    /// The replay window size is outside the supported range.
    InvalidReplayWindow,
    /// The envelope key epoch is not accepted for this session.
    InvalidKeyEpoch,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongInstallation => f.write_str("wrong installation"),
            Self::RevokedGeneration => f.write_str("revoked generation"),
            Self::Crypto => f.write_str("cryptographic operation failed"),
            Self::BadAead => f.write_str("AEAD verification failed"),
            Self::InvalidAad => f.write_str("invalid authenticated metadata"),
            Self::Replay => f.write_str("replayed sequence"),
            Self::SequenceTooOld => f.write_str("sequence too old"),
            Self::SequenceTooFarAhead => f.write_str("sequence too far ahead"),
            Self::InvalidReplayWindow => f.write_str("invalid replay window"),
            Self::InvalidKeyEpoch => f.write_str("invalid key epoch"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

fn validate_envelope_aad(generation: u64, aad: &EnvelopeAad) -> Result<(), EnvelopeError> {
    if aad.version != 1
        || aad.projection_id.is_empty()
        || aad.role.is_empty()
        || aad.session_id.is_empty()
        || aad.frame_type.is_empty()
        || aad.credential_generation != generation
        || aad.transcript_hash.len() != 32
        || !matches!(aad.direction.as_str(), CLIENT_TO_DAEMON | DAEMON_TO_CLIENT)
    {
        return Err(EnvelopeError::InvalidAad);
    }
    Ok(())
}

fn aad_bytes(installation_id: &str, generation: u64, aad: &EnvelopeAad) -> Vec<u8> {
    let mut out = Vec::new();
    aad_push_bytes(&mut out, b"xolotl-secure-external-envelope-v1");
    aad_push_bytes(&mut out, installation_id.as_bytes());
    aad_push_bytes(&mut out, &generation.to_le_bytes());
    aad_push_bytes(&mut out, &aad.version.to_le_bytes());
    aad_push_bytes(&mut out, aad.projection_id.as_bytes());
    aad_push_bytes(&mut out, aad.role.as_bytes());
    aad_push_bytes(&mut out, aad.session_id.as_bytes());
    aad_push_bytes(&mut out, &aad.seq.to_le_bytes());
    aad_push_bytes(&mut out, aad.frame_type.as_bytes());
    aad_push_bytes(&mut out, &aad.binding_generation.to_le_bytes());
    aad_push_bytes(&mut out, &aad.credential_generation.to_le_bytes());
    aad_push_bytes(&mut out, &aad.transcript_hash);
    aad_push_bytes(&mut out, &aad.key_epoch.to_le_bytes());
    aad_push_bytes(&mut out, aad.direction.as_bytes());
    out
}

fn aad_push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn nonce_bytes(prefix: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *prefix;
    for (dst, src) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
        *dst ^= src;
    }
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::ensure;

    const TEST_PSK: [u8; 32] = [0x11; 32];
    const OTHER_TEST_PSK: [u8; 32] = [0x24; 32];

    fn test_credential(installation_id: &str, generation: u64) -> ExternalCredential {
        ExternalCredential::new(installation_id, generation, TEST_PSK)
    }

    fn other_test_credential(installation_id: &str, generation: u64) -> ExternalCredential {
        ExternalCredential::new(installation_id, generation, OTHER_TEST_PSK)
    }

    fn open_for_test(
        credential: &ExternalCredential,
        envelope: &SecureEnvelope,
        valid_floor: u64,
        replay_window: &mut SecureEnvelopeReplayWindow,
    ) -> Result<Vec<u8>, EnvelopeError> {
        let epoch_gate = SecureEnvelopeEpochGate::new(envelope.aad.key_epoch);
        credential.open_with_replay_window_and_epoch_gate(
            envelope,
            valid_floor,
            replay_window,
            &epoch_gate,
        )
    }

    fn valid_aad(seq: u64) -> EnvelopeAad {
        EnvelopeAad {
            projection_id: "provider".into(),
            role: "provider".into(),
            session_id: "session-1".into(),
            seq,
            frame_type: "invoke".into(),
            binding_generation: 1,
            credential_generation: 1,
            transcript_hash: vec![0x42; 32],
            key_epoch: 1,
            ..EnvelopeAad::default()
        }
    }

    #[test]
    fn seal_then_open_roundtrips() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let env = cred.seal_with_aad(b"hello frame", valid_aad(0))?;
        ensure!(env.ciphertext != b"hello frame", "ciphertext matched input");
        let opened = cred.open(&env, 0)?;
        ensure!(opened == b"hello frame", "unexpected plaintext: {opened:?}");
        Ok(())
    }

    #[test]
    fn v1_envelope_matches_an_independent_aead_vector() -> anyhow::Result<()> {
        // Node/OpenSSL HKDF-SHA256 and ChaCha20-Poly1305, using the v1 AAD below.
        const CIPHERTEXT: [u8; 27] = [
            0xe5, 0x5c, 0x1e, 0xea, 0x67, 0x8b, 0xf3, 0x15, 0xe4, 0xee, 0xb3, 0xb3, 0x92, 0xd6,
            0x06, 0x0e, 0xd4, 0xf5, 0x4e, 0xfb, 0x1e, 0x0a, 0xbf, 0x9c, 0xd6, 0x93, 0x10,
        ];
        let prefix = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let aad = valid_aad(7);
        let nonce = nonce_bytes(&prefix, aad.seq);
        ensure!(nonce == [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12]);
        let cred = test_credential("inst-1", 1);
        let authenticated = aad_bytes("inst-1", 1, &aad);
        let sealed = cred
            .cipher(&authenticated)?
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: b"hello frame",
                    aad: &authenticated,
                },
            )
            .map_err(|_error| EnvelopeError::Crypto)?;
        ensure!(sealed == CIPHERTEXT);
        let mut env = SecureEnvelope::from_parts("inst-1", 1, aad, prefix, CIPHERTEXT.to_vec());
        let mut replay = SecureEnvelopeReplayWindow::default();
        ensure!(open_for_test(&cred, &env, 0, &mut replay)? == b"hello frame");
        env.aad.transcript_hash[0] ^= 1;
        ensure!(
            open_for_test(&cred, &env, 0, &mut SecureEnvelopeReplayWindow::default())
                == Err(EnvelopeError::BadAead)
        );
        Ok(())
    }

    #[test]
    fn tampered_ciphertext_fails_aead() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut env = cred.seal_with_aad(b"transfer $10", valid_aad(0))?;
        env.ciphertext[0] ^= 0x01;
        ensure!(
            cred.open(&env, 0) == Err(EnvelopeError::BadAead),
            "tampered ciphertext should fail AEAD"
        );
        Ok(())
    }

    #[test]
    fn tampered_aad_fails_aead() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut aad = valid_aad(7);
        aad.binding_generation = 3;
        let mut env = cred.seal_with_aad(b"transfer $10", aad)?;
        env.aad.binding_generation = 4;
        ensure!(
            cred.open(&env, 0) == Err(EnvelopeError::BadAead),
            "tampered AAD should fail AEAD"
        );
        Ok(())
    }

    #[test]
    fn opposite_direction_cannot_open_same_ciphertext() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut env = cred.seal_with_aad(b"frame", valid_aad(0))?;
        env.aad.direction = DAEMON_TO_CLIENT.into();
        ensure!(cred.open(&env, 0) == Err(EnvelopeError::BadAead));
        Ok(())
    }

    #[test]
    fn tampered_key_epoch_fails_aead() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut env = cred.seal_with_aad(b"invoke", valid_aad(3))?;
        env.aad.key_epoch = env.aad.key_epoch.saturating_add(1);
        ensure!(
            cred.open(&env, 0) == Err(EnvelopeError::BadAead),
            "tampered key epoch should fail AEAD"
        );
        Ok(())
    }

    #[test]
    fn wrong_psk_fails_aead() -> anyhow::Result<()> {
        let real = test_credential("inst-1", 1);
        let attacker = other_test_credential("inst-1", 1);
        let env = attacker.seal_with_aad(b"frame", valid_aad(0))?;
        ensure!(
            real.open(&env, 0) == Err(EnvelopeError::BadAead),
            "wrong PSK should fail AEAD"
        );
        Ok(())
    }

    #[test]
    fn revoked_generation_is_rejected() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 2);
        let mut aad = valid_aad(0);
        aad.credential_generation = 2;
        let env = cred.seal_with_aad(b"frame", aad)?;
        ensure!(
            cred.open(&env, 5) == Err(EnvelopeError::RevokedGeneration),
            "revoked generation should be rejected"
        );
        Ok(())
    }

    #[test]
    fn generation_is_bound_to_aead_no_replay_across_revoke() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut env = cred.seal_with_aad(b"frame", valid_aad(0))?;
        env.generation = 9;
        ensure!(
            cred.open(&env, 5) == Err(EnvelopeError::BadAead),
            "modified generation should fail AEAD"
        );
        Ok(())
    }

    #[test]
    fn wrong_installation_is_rejected() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut env = cred.seal_with_aad(b"frame", valid_aad(0))?;
        env.installation_id = "inst-2".into();
        ensure!(
            cred.open(&env, 0) == Err(EnvelopeError::WrongInstallation),
            "wrong installation should be rejected"
        );
        Ok(())
    }

    #[test]
    fn replay_window_accepts_first_sequence() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let env = cred.seal_with_aad(b"frame-0", valid_aad(0))?;
        let mut replay_window = SecureEnvelopeReplayWindow::default();

        let opened = open_for_test(&cred, &env, 0, &mut replay_window)?;
        ensure!(
            opened == b"frame-0",
            "unexpected replay-window plaintext: {opened:?}"
        );
        Ok(())
    }

    #[test]
    fn replay_window_rejects_duplicate_sequence() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let env = cred.seal_with_aad(b"frame-0", valid_aad(0))?;
        let mut replay_window = SecureEnvelopeReplayWindow::default();

        open_for_test(&cred, &env, 0, &mut replay_window)?;
        ensure!(
            open_for_test(&cred, &env, 0, &mut replay_window) == Err(EnvelopeError::Replay),
            "duplicate sequence should be rejected"
        );
        Ok(())
    }

    #[test]
    fn replay_window_accepts_out_of_order_once() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut replay_window = SecureEnvelopeReplayWindow::new(4)?;
        let env0 = cred.seal_with_aad(b"frame-0", valid_aad(0))?;
        let env2 = cred.seal_with_aad(b"frame-2", valid_aad(2))?;
        let env1 = cred.seal_with_aad(b"frame-1", valid_aad(1))?;

        open_for_test(&cred, &env0, 0, &mut replay_window)?;
        open_for_test(&cred, &env2, 0, &mut replay_window)?;
        let opened = open_for_test(&cred, &env1, 0, &mut replay_window)?;
        ensure!(opened == b"frame-1", "unexpected plaintext: {opened:?}");
        ensure!(
            open_for_test(&cred, &env1, 0, &mut replay_window) == Err(EnvelopeError::Replay),
            "replayed out-of-order sequence should be rejected"
        );
        Ok(())
    }

    #[test]
    fn replay_window_rejects_too_old_sequence() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut replay_window = SecureEnvelopeReplayWindow::new(4)?;
        let env0 = cred.seal_with_aad(b"frame-0", valid_aad(0))?;
        let env3 = cred.seal_with_aad(b"frame-3", valid_aad(3))?;
        let env6 = cred.seal_with_aad(b"frame-6", valid_aad(6))?;

        open_for_test(&cred, &env0, 0, &mut replay_window)?;
        open_for_test(&cred, &env3, 0, &mut replay_window)?;
        open_for_test(&cred, &env6, 0, &mut replay_window)?;
        ensure!(
            open_for_test(&cred, &env0, 0, &mut replay_window)
                == Err(EnvelopeError::SequenceTooOld),
            "too-old sequence should be rejected"
        );
        Ok(())
    }

    #[test]
    fn replay_window_rejects_too_far_ahead_sequence() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut replay_window = SecureEnvelopeReplayWindow::new(4)?;
        let env0 = cred.seal_with_aad(b"frame-0", valid_aad(0))?;
        let env4 = cred.seal_with_aad(b"frame-4", valid_aad(4))?;

        open_for_test(&cred, &env0, 0, &mut replay_window)?;
        ensure!(
            open_for_test(&cred, &env4, 0, &mut replay_window)
                == Err(EnvelopeError::SequenceTooFarAhead),
            "too-far-ahead sequence should be rejected"
        );
        Ok(())
    }

    #[test]
    fn replay_window_can_attach_to_authenticated_high_sequence() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut replay = SecureEnvelopeReplayWindow::new(4)?;
        let high = cred.seal_with_aad(b"frame-100", valid_aad(100))?;
        ensure!(
            open_for_test(&cred, &high, 0, &mut replay)? == b"frame-100",
            "authenticated high sequence was not opened"
        );
        ensure!(
            open_for_test(&cred, &high, 0, &mut replay) == Err(EnvelopeError::Replay),
            "replayed high sequence was accepted"
        );
        let far = cred.seal_with_aad(b"frame-104", valid_aad(104))?;
        ensure!(
            open_for_test(&cred, &far, 0, &mut replay) == Err(EnvelopeError::SequenceTooFarAhead),
            "out-of-window sequence was accepted"
        );
        Ok(())
    }

    #[test]
    fn replay_window_does_not_commit_bad_aead() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let env = cred.seal_with_aad(b"frame-0", valid_aad(0))?;
        let mut tampered = env.clone();
        tampered.aad.binding_generation = 2;
        let mut replay_window = SecureEnvelopeReplayWindow::default();

        ensure!(
            open_for_test(&cred, &tampered, 0, &mut replay_window) == Err(EnvelopeError::BadAead),
            "bad AEAD should not be accepted"
        );
        let opened = open_for_test(&cred, &env, 0, &mut replay_window)?;
        ensure!(
            opened == b"frame-0",
            "unexpected plaintext after bad AEAD: {opened:?}"
        );
        Ok(())
    }

    #[test]
    fn replay_window_requires_session_aad_shape() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        ensure!(
            cred.seal_with_aad(b"frame-0", EnvelopeAad::default())
                == Err(EnvelopeError::InvalidAad),
            "invalid AAD shape should be rejected before sealing"
        );
        Ok(())
    }

    #[test]
    fn epoch_gate_rejects_old_business_frames_after_rekey() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut aad = valid_aad(0);
        aad.key_epoch = 1;
        aad.frame_type = "invoke".into();
        let env = cred.seal_with_aad(b"invoke", aad)?;
        let mut replay_window = SecureEnvelopeReplayWindow::default();
        let epoch_gate = SecureEnvelopeEpochGate::new(2);

        ensure!(
            cred.open_with_replay_window_and_epoch_gate(&env, 0, &mut replay_window, &epoch_gate)
                == Err(EnvelopeError::InvalidKeyEpoch),
            "old business frame should be rejected after rekey"
        );
        Ok(())
    }

    #[test]
    fn rejected_epoch_does_not_consume_replay_sequence() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let gate = SecureEnvelopeEpochGate::new(2);
        let mut replay = SecureEnvelopeReplayWindow::default();
        let mut old_aad = valid_aad(7);
        old_aad.key_epoch = 1;
        old_aad.frame_type = "invoke".into();
        let old = cred.seal_with_aad(b"old", old_aad)?;
        ensure!(
            cred.open_with_replay_window_and_epoch_gate(&old, 0, &mut replay, &gate)
                == Err(EnvelopeError::InvalidKeyEpoch)
        );

        let mut current_aad = valid_aad(7);
        current_aad.key_epoch = 2;
        current_aad.frame_type = "invoke".into();
        let current = cred.seal_with_aad(b"current", current_aad)?;
        ensure!(
            cred.open_with_replay_window_and_epoch_gate(&current, 0, &mut replay, &gate)?
                == b"current"
        );
        Ok(())
    }

    #[test]
    fn epoch_gate_rejects_old_generic_control_frames_after_rekey() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut aad = valid_aad(0);
        aad.key_epoch = 1;
        aad.frame_type = "control".into();
        let env = cred.seal_with_aad(b"close", aad)?;
        let mut replay_window = SecureEnvelopeReplayWindow::default();
        let epoch_gate = SecureEnvelopeEpochGate::new(2);

        ensure!(
            cred.open_with_replay_window_and_epoch_gate(&env, 0, &mut replay_window, &epoch_gate)
                == Err(EnvelopeError::InvalidKeyEpoch),
            "old generic control frame should be rejected after rekey"
        );
        Ok(())
    }

    #[test]
    fn epoch_gate_allows_old_drain_config_ack_frames_after_rekey() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let mut aad = valid_aad(0);
        aad.key_epoch = 1;
        aad.frame_type = "control.config_ack".into();
        let env = cred.seal_with_aad(b"ack", aad)?;
        let mut replay_window = SecureEnvelopeReplayWindow::default();
        let epoch_gate = SecureEnvelopeEpochGate::new(2);

        let opened =
            cred.open_with_replay_window_and_epoch_gate(&env, 0, &mut replay_window, &epoch_gate)?;
        ensure!(
            opened == b"ack",
            "unexpected config ack plaintext: {opened:?}"
        );
        Ok(())
    }

    #[test]
    fn epoch_gate_limits_config_ack_drain_to_previous_epoch() -> anyhow::Result<()> {
        let cred = test_credential("inst-1", 1);
        let gate = SecureEnvelopeEpochGate::new(3);
        for (epoch, accepted) in [(3, true), (2, true), (1, false), (u64::MAX, false)] {
            let mut aad = valid_aad(0);
            aad.key_epoch = epoch;
            aad.frame_type = "control.config_ack".into();
            let envelope = cred.seal_with_aad(b"ack", aad)?;
            let mut replay = SecureEnvelopeReplayWindow::default();
            let result =
                cred.open_with_replay_window_and_epoch_gate(&envelope, 0, &mut replay, &gate);
            ensure!(
                result.is_ok() == accepted,
                "epoch {epoch} drain decision was wrong"
            );
        }
        Ok(())
    }
}
