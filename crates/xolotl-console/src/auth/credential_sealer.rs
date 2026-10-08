//! Host-owned encryption boundary for persistent Console credential records.

use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, Nonce, RandomizedNonceKey};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

use super::AuthError;

const MAGIC: &[u8; 8] = b"XLCRED\0\x01";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_KEYS: usize = 8;

/// A host-provided key ring. New records use the active key; older keys can
/// only decrypt existing records during an explicit rotation window.
pub struct CredentialSealer {
    active_id: String,
    keys: BTreeMap<String, RandomizedNonceKey>,
}

impl std::fmt::Debug for CredentialSealer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CredentialSealer")
            .finish_non_exhaustive()
    }
}

impl CredentialSealer {
    /// Install a 256-bit host secret with a stable, non-secret key identifier.
    pub fn new(key_id: &str, key: &[u8; 32]) -> Result<Self, AuthError> {
        let mut sealer = Self {
            active_id: String::new(),
            keys: BTreeMap::new(),
        };
        sealer.add_decryption_key(key_id, key)?;
        sealer.active_id = key_id.into();
        Ok(sealer)
    }

    /// Retain an old 256-bit secret for reading records until they are rekeyed.
    pub fn add_decryption_key(&mut self, key_id: &str, key: &[u8; 32]) -> Result<(), AuthError> {
        if !valid_key_id(key_id) || self.keys.len() >= MAX_KEYS || self.keys.contains_key(key_id) {
            return Err(AuthError::Crypto(
                "invalid or duplicate credential key id".into(),
            ));
        }
        let cipher = RandomizedNonceKey::new(&AES_256_GCM_SIV, key)
            .map_err(|_error| AuthError::Crypto("invalid credential encryption key".into()))?;
        self.keys.insert(key_id.into(), cipher);
        Ok(())
    }

    pub(super) fn seal(
        &self,
        authority_id: &str,
        account_id: &str,
        mut plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<Vec<u8>, AuthError> {
        let aad = aad(authority_id, account_id, &self.active_id)?;
        let cipher = &self.keys[&self.active_id];
        let nonce = cipher
            .seal_in_place_append_tag(Aad::from(&aad), &mut *plaintext)
            .map_err(|_error| AuthError::Crypto("credential encryption failed".into()))?;
        let mut envelope = Vec::with_capacity(
            MAGIC.len() + 1 + self.active_id.len() + NONCE_LEN + plaintext.len(),
        );
        envelope.extend_from_slice(MAGIC);
        envelope.push(self.active_id.len() as u8);
        envelope.extend_from_slice(self.active_id.as_bytes());
        envelope.extend_from_slice(nonce.as_ref());
        envelope.extend_from_slice(&plaintext);
        Ok(envelope)
    }

    pub(super) fn open(
        &self,
        authority_id: &str,
        account_id: &str,
        mut envelope: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, AuthError> {
        let invalid = || AuthError::State("invalid sealed credential record".into());
        if envelope.len() < MAGIC.len() + 1 + NONCE_LEN + TAG_LEN || !envelope.starts_with(MAGIC) {
            return Err(invalid());
        }
        let id_len = usize::from(envelope[MAGIC.len()]);
        let start = MAGIC.len() + 1;
        let nonce_start = start + id_len;
        let ciphertext_start = nonce_start + NONCE_LEN;
        if id_len == 0 || envelope.len() < ciphertext_start + TAG_LEN {
            return Err(invalid());
        }
        let key_id =
            std::str::from_utf8(&envelope[start..nonce_start]).map_err(|_error| invalid())?;
        if !valid_key_id(key_id) {
            return Err(invalid());
        }
        let cipher = self.keys.get(key_id).ok_or_else(invalid)?;
        let nonce = Nonce::try_assume_unique_for_key(&envelope[nonce_start..ciphertext_start])
            .map_err(|_error| invalid())?;
        let aad = aad(authority_id, account_id, key_id)?;
        let size = cipher
            .open_in_place(nonce, Aad::from(&aad), &mut envelope[ciphertext_start..])
            .map_err(|_error| invalid())?
            .len();
        envelope.copy_within(ciphertext_start..ciphertext_start + size, 0);
        envelope[size..].zeroize();
        envelope.truncate(size);
        Ok(envelope)
    }
}

fn valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn aad(authority_id: &str, account_id: &str, key_id: &str) -> Result<Vec<u8>, AuthError> {
    let mut aad = b"xolotl.console.credential.v1\0".to_vec();
    for part in [
        authority_id.as_bytes(),
        account_id.as_bytes(),
        key_id.as_bytes(),
    ] {
        let len = u32::try_from(part.len())
            .map_err(|_error| AuthError::State("credential identity too long".into()))?;
        aad.extend_from_slice(&len.to_be_bytes());
        aad.extend_from_slice(part);
    }
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AccountKey, credentials};
    use anyhow::{Context, ensure};
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use xolotl_types::Value;

    fn record(account: &str) -> credentials::AccountCredentials {
        credentials::AccountCredentials {
            authority_id: "local".into(),
            account_id: account.into(),
            epoch: "epoch-1".into(),
            password: Some("sensitive-verifier".into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn sealed_records_survive_reopen_and_reject_tampering_or_cross_account_copy()
    -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("credentials.redb");
        let alice = AccountKey::local("alice");
        let bob = AccountKey::local("bob");
        let sealer = CredentialSealer::new("current", &[0x57; 32])?;
        let stored = {
            let store = xolotl_storage_redb::RedbStore::open(&path)?;
            let state = store.state_backend().into_backend();
            credentials::write_by_key(&state, &alice, &record("alice"), &sealer).await?;
            let value = state
                .read(&crate::paths::credential_path("local", "alice")?)
                .await?
                .context("stored credential")?;
            let bytes = value.as_str().context("sealed text row")?.as_bytes();
            ensure!(
                !bytes
                    .windows(b"sensitive-verifier".len())
                    .any(|part| part == b"sensitive-verifier")
            );
            value
        };
        let reopened = CredentialSealer::new("current", &[0x57; 32])?;
        let store = xolotl_storage_redb::RedbStore::open(&path)?;
        let state = store.state_backend().into_backend();
        ensure!(
            credentials::read_by_key(&state, &alice, &reopened)
                .await?
                .password
                == Some("sensitive-verifier".into())
        );
        let bob_path = crate::paths::credential_path("local", "bob")?;
        state.write_set(&bob_path, stored.clone()).await?;
        ensure!(matches!(
            credentials::read_by_key(&state, &bob, &reopened).await,
            Err(AuthError::State(_))
        ));
        let alice_path = crate::paths::credential_path("local", "alice")?;
        state
            .write_set(
                &alice_path,
                Value::string(format!("{}=", stored.as_str().context("sealed text")?)),
            )
            .await?;
        ensure!(matches!(
            credentials::read_by_key(&state, &alice, &reopened).await,
            Err(AuthError::State(_))
        ));
        let encoded = stored
            .as_str()
            .context("sealed text")?
            .strip_prefix("xolotl-credential-v1:")
            .context("sealed prefix")?;
        let mut tampered = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|error| anyhow::anyhow!("decode sealed test row: {error}"))?;
        *tampered.last_mut().context("ciphertext")? ^= 1;
        state
            .write_set(
                &alice_path,
                Value::string(format!(
                    "xolotl-credential-v1:{}",
                    URL_SAFE_NO_PAD.encode(tampered)
                )),
            )
            .await?;
        ensure!(matches!(
            credentials::read_by_key(&state, &alice, &reopened).await,
            Err(AuthError::State(_))
        ));
        state
            .write_set(
                &alice_path,
                Value::string(serde_json::to_string(&record("alice"))?),
            )
            .await?;
        ensure!(matches!(
            credentials::read_by_key(&state, &alice, &reopened).await,
            Err(AuthError::State(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn sealed_record_cas_rejects_stale_snapshot() -> anyhow::Result<()> {
        let state = xolotl_state::InMemoryBackend::new().into_backend();
        let key = AccountKey::local("alice");
        let sealer = CredentialSealer::new("current", &[0x57; 32])?;
        credentials::write_by_key(&state, &key, &record("alice"), &sealer).await?;
        let mut first = credentials::read_by_key(&state, &key, &sealer).await?;
        let mut stale = credentials::read_by_key(&state, &key, &sealer).await?;
        first.epoch = "epoch-2".into();
        stale.epoch = "epoch-3".into();
        credentials::write_by_key(&state, &key, &first, &sealer).await?;
        ensure!(matches!(
            credentials::write_by_key(&state, &key, &stale, &sealer).await,
            Err(AuthError::CredentialConflict)
        ));
        ensure!(credentials::read_by_key(&state, &key, &sealer).await?.epoch == "epoch-2");
        Ok(())
    }

    #[test]
    fn old_key_only_decrypts_when_explicitly_retained() -> anyhow::Result<()> {
        let old = CredentialSealer::new("old", &[0x11; 32])?;
        let ciphertext = old.seal("local", "alice", Zeroizing::new(b"secret".to_vec()))?;
        let mut current = CredentialSealer::new("current", &[0x22; 32])?;
        ensure!(
            current
                .open("local", "alice", Zeroizing::new(ciphertext.clone()))
                .is_err()
        );
        current.add_decryption_key("old", &[0x11; 32])?;
        ensure!(&*current.open("local", "alice", Zeroizing::new(ciphertext))? == b"secret");
        Ok(())
    }
}
