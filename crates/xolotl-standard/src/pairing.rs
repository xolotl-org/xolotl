//! Pairing state driver and display-secret edge for external installations.

#[cfg(feature = "standard-core")]
use async_trait::async_trait;
#[cfg(feature = "standard-core")]
use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, Nonce, RandomizedNonceKey};
use blake3::Hasher;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[cfg(feature = "standard-core")]
use std::io::{Read, Write};
#[cfg(feature = "standard-core")]
use std::path::{Path as FilePath, PathBuf};
use std::sync::Arc;
#[cfg(feature = "standard-core")]
use xolotl_kernel::{Driver, DriverContext, DriverError, DriverOutput, MethodSpec};
#[cfg(feature = "standard-core")]
use xolotl_source::ExternalInstallationAuthority;
#[cfg(feature = "standard-core")]
use xolotl_state::{Backend, StateError};
#[cfg(feature = "standard-core")]
use xolotl_types::ValueMap;
use xolotl_types::{MethodId, Outcome, OutputMode, Path, Purity, Role, Value};
use zeroize::Zeroize;
use zeroize::Zeroizing;

#[cfg(feature = "standard-core")]
const VAULT_MAGIC: &[u8; 8] = b"XLPVAULT";
#[cfg(feature = "standard-core")]
const VAULT_FORMAT: u8 = 1;
#[cfg(feature = "standard-core")]
const VAULT_NONCE_LEN: usize = 12;
#[cfg(feature = "standard-core")]
const VAULT_TAG_LEN: usize = 16;
#[cfg(feature = "standard-core")]
const MAX_VAULT_BYTES: u64 = 64 * 1024 * 1024;
#[cfg(feature = "standard-core")]
const VAULT_AAD: &[u8] = b"xolotl.external.pairing-vault.v1";
#[cfg(feature = "standard-core")]
const HEX_TABLE: &[u8; 16] = b"0123456789abcdef";

mod record;
use record::{
    PairingScope, STATE_APPROVED, STATE_CREATED, STATE_DENIED, STATE_EXPIRED, STATE_REVOKED,
    admit_pairing_input, ensure_created, ensure_installation_epoch, ensure_not_terminal,
    ensure_record_sas_verified, ensure_roles_allowed, field_str, installation_roles, is_expired,
    optional_nonnegative_int, record_required_str, reject_approve_claim_fields,
    reject_inline_install_fields, reject_inline_secret, reject_pairing_claim_fields,
    reject_unknown_fields, requested_credential_generation_floor, required_record_nonnegative_int,
    required_str, role_values, string_list, validate_id_segment,
};

/// Internal method names in registration order. `install_standard` exposes each
/// one as a separate Resource with public method `invoke`:
/// `effect://external/pairing/create`, `/approve`, `/deny`, and
/// `effect://external/revoke`.
#[cfg(feature = "standard-core")]
pub(crate) const PAIRING_METHODS: &[MethodSpec] = &[
    MethodSpec::new(
        "create",
        xolotl_types::MethodAuthority::Perform,
        Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "approve",
        xolotl_types::MethodAuthority::Perform,
        Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "deny",
        xolotl_types::MethodAuthority::Perform,
        Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    ),
    MethodSpec::new(
        "revoke",
        xolotl_types::MethodAuthority::Perform,
        Purity::Effectful,
        MethodSpec::UNARY_ASYNC,
    ),
];

/// Drives external pairing management effects. It persists only
/// hashes and status records in the state plane; raw pairing secrets stay at the
/// display/transport edge.
#[cfg(feature = "standard-core")]
pub(crate) struct PairingDriver {
    state: Backend,
    display_edge: PairingDisplayEdge,
    installations: Option<Arc<dyn ExternalInstallationAuthority>>,
}

/// One-shot edge for pairing display secrets.
///
/// Secrets staged here are consumed by Console/transport code after the
/// Pairing Operations record only hash/checksum metadata.
#[derive(Clone, Default)]
pub struct PairingDisplayEdge {
    pending_secrets: Arc<Mutex<BTreeMap<String, Zeroizing<String>>>>,
    credentials: Arc<Mutex<CredentialVault>>,
    operations: Arc<tokio::sync::Mutex<()>>,
}

/// Host-private credential material, separate from observable State and Facts.
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialVaultData {
    pending: BTreeMap<String, PendingCredential>,
    active: BTreeMap<String, IssuedCredential>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingCredential {
    installation_id: String,
    installation_epoch: u64,
    intent_digest: [u8; 32],
    key: [u8; 32],
}

impl Drop for PendingCredential {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuedCredential {
    pairing_id: String,
    generation: u64,
    installation_epoch: u64,
    key: [u8; 32],
}

impl Drop for IssuedCredential {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Default)]
struct CredentialVault {
    #[cfg(feature = "standard-core")]
    path: Option<PathBuf>,
    #[cfg(feature = "standard-core")]
    cipher: Option<RandomizedNonceKey>,
    data: CredentialVaultData,
    /// Directory fsync failed after atomic replacement: durability is unknown.
    uncertain: bool,
}

impl PairingDisplayEdge {
    /// Open a durable, encrypted credential vault with an independent host key.
    /// A missing key, plaintext file, wrong key, or damaged file is never
    /// treated as an empty vault.
    #[cfg(feature = "standard-core")]
    pub fn open(path: impl Into<PathBuf>, key: &[u8; 32]) -> std::io::Result<Self> {
        let path = path.into();
        let cipher = RandomizedNonceKey::new(&AES_256_GCM_SIV, key.as_ref())
            .map_err(|_error| std::io::Error::other("invalid pairing vault encryption key"))?;
        let data = match open_vault_file(&path) {
            Ok(file) => {
                let mut bytes = Zeroizing::new(Vec::new());
                file.take(MAX_VAULT_BYTES + 1).read_to_end(&mut bytes)?;
                if bytes.len() as u64 > MAX_VAULT_BYTES {
                    return Err(std::io::Error::other(
                        "pairing credential vault is too large",
                    ));
                }
                let plaintext = decrypt_credential_vault(&cipher, &mut bytes)?;
                serde_json::from_slice(plaintext).map_err(std::io::Error::other)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                CredentialVaultData::default()
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            pending_secrets: Arc::default(),
            credentials: Arc::new(Mutex::new(CredentialVault {
                path: Some(path),
                cipher: Some(cipher),
                data,
                uncertain: false,
            })),
            operations: Arc::default(),
        })
    }

    /// Return a PSK only for its exact installation incarnation and generation.
    pub fn credential(
        &self,
        installation_id: &str,
        installation_epoch: u64,
        generation: u64,
    ) -> Option<[u8; 32]> {
        let vault = self.credentials.lock();
        if vault.uncertain {
            return None;
        }
        vault
            .data
            .active
            .get(installation_id)
            .filter(|issued| {
                issued.installation_epoch == installation_epoch && issued.generation == generation
            })
            .map(|issued| issued.key)
    }

    #[cfg(feature = "standard-core")]
    fn active_generation(&self, installation_id: &str) -> Result<u64, DriverError> {
        let vault = self.credentials.lock();
        vault.require_consistent()?;
        Ok(vault
            .data
            .active
            .get(installation_id)
            .map_or(0, |issued| issued.generation))
    }

    #[cfg(feature = "standard-core")]
    fn pending_credential(
        &self,
        pairing_id: &str,
        installation_id: &str,
        installation_epoch: u64,
        intent_digest: [u8; 32],
    ) -> Result<Option<[u8; 32]>, DriverError> {
        let vault = self.credentials.lock();
        vault.require_consistent()?;
        match vault.data.pending.get(pairing_id) {
            Some(pending)
                if pending.installation_id == installation_id
                    && pending.installation_epoch == installation_epoch
                    && pending.intent_digest == intent_digest =>
            {
                Ok(Some(pending.key))
            }
            Some(_) => Err(DriverError::Other(
                "pairing credential belongs to another intent".into(),
            )),
            None => Ok(None),
        }
    }

    #[cfg(feature = "standard-core")]
    fn has_display_secret(&self, pairing_id: &str, key: &[u8; 32]) -> bool {
        self.pending_secrets
            .lock()
            .get(pairing_id)
            .is_some_and(|secret| display_secret_matches_key(secret, key))
    }

    #[cfg(feature = "standard-core")]
    fn has_pending(&self, pairing_id: &str) -> Result<bool, DriverError> {
        let vault = self.credentials.lock();
        vault.require_consistent()?;
        Ok(vault.data.pending.contains_key(pairing_id))
    }

    #[cfg(feature = "standard-core")]
    fn persist_pending(
        &self,
        pairing_id: &str,
        installation_id: &str,
        installation_epoch: u64,
        intent_digest: [u8; 32],
        secret: [u8; 32],
    ) -> Result<(), DriverError> {
        let mut vault = self.credentials.lock();
        vault.require_consistent()?;
        if vault.data.pending.contains_key(pairing_id) {
            return Err(DriverError::Other(
                "pairing credential already exists".into(),
            ));
        }
        if vault.data.pending.len() >= 1024 {
            return Err(DriverError::Other(
                "too many pending pairing credentials".into(),
            ));
        }
        vault.data.pending.insert(
            pairing_id.to_string(),
            PendingCredential {
                installation_id: installation_id.to_string(),
                installation_epoch,
                intent_digest,
                key: secret,
            },
        );
        if let Err(error) = vault.persist() {
            if !vault.uncertain {
                vault.data.pending.remove(pairing_id);
            }
            return Err(DriverError::Other(format!(
                "pairing credential storage failed: {error}"
            )));
        }
        Ok(())
    }

    #[cfg(feature = "standard-core")]
    fn issue_credential(
        &self,
        pairing_id: &str,
        installation_id: &str,
        installation_epoch: u64,
        expected_secret_hash: &str,
        generation_floor: u64,
    ) -> Result<u64, DriverError> {
        let mut vault = self.credentials.lock();
        vault.require_consistent()?;
        let Some(pending) = vault.data.pending.get(pairing_id) else {
            let issued =
                vault.data.active.get(installation_id).ok_or_else(|| {
                    DriverError::Other("pairing credential is unavailable".into())
                })?;
            if issued.pairing_id == pairing_id
                && issued.installation_epoch == installation_epoch
                && issued.generation > generation_floor
                && hash_secret_key(&issued.key) == expected_secret_hash
            {
                return Ok(issued.generation);
            }
            return Err(DriverError::Other(
                "pairing credential is unavailable".into(),
            ));
        };
        if pending.installation_id != installation_id
            || pending.installation_epoch != installation_epoch
            || hash_secret_key(&pending.key) != expected_secret_hash
        {
            return Err(DriverError::Other(
                "pairing credential does not match the approved intent".into(),
            ));
        }
        let generation = vault
            .data
            .active
            .get(installation_id)
            .map(|old| old.generation)
            .unwrap_or(0)
            .max(generation_floor)
            .checked_add(1)
            .ok_or_else(|| DriverError::Other("credential generation overflowed".into()))?;
        if generation > i64::MAX as u64 {
            return Err(DriverError::Other(
                "credential generation overflowed".into(),
            ));
        }
        let pending = vault
            .data
            .pending
            .remove(pairing_id)
            .ok_or_else(|| DriverError::Other("pairing credential is unavailable".into()))?;
        let previous = vault.data.active.insert(
            installation_id.to_string(),
            IssuedCredential {
                pairing_id: pairing_id.to_string(),
                generation,
                installation_epoch,
                key: pending.key,
            },
        );
        if let Err(error) = vault.persist() {
            if !vault.uncertain {
                vault.data.pending.insert(pairing_id.to_string(), pending);
                if let Some(previous) = previous {
                    vault
                        .data
                        .active
                        .insert(installation_id.to_string(), previous);
                } else {
                    vault.data.active.remove(installation_id);
                }
            }
            return Err(DriverError::Other(format!(
                "pairing credential storage failed: {error}"
            )));
        }
        Ok(generation)
    }

    #[cfg(feature = "standard-core")]
    fn discard_pending(&self, pairing_id: &str) -> Result<(), DriverError> {
        let mut vault = self.credentials.lock();
        vault.require_consistent()?;
        if let Some(pending) = vault.data.pending.remove(pairing_id)
            && let Err(error) = vault.persist()
        {
            if !vault.uncertain {
                vault.data.pending.insert(pairing_id.to_string(), pending);
            }
            return Err(DriverError::Other(format!(
                "pairing credential storage failed: {error}"
            )));
        }
        self.pending_secrets.lock().remove(pairing_id);
        Ok(())
    }

    /// Consume and remove the display secret for `pairing_id`.
    pub fn take_display_secret(&self, pairing_id: &str) -> Option<String> {
        let mut secret = self.pending_secrets.lock().remove(pairing_id)?;
        Some(std::mem::take(&mut *secret))
    }

    #[cfg(feature = "standard-core")]
    fn stage_display_secret(&self, pairing_id: &str, secret: Zeroizing<String>) {
        self.pending_secrets
            .lock()
            .insert(pairing_id.to_string(), secret);
    }
}

impl CredentialVault {
    #[cfg(feature = "standard-core")]
    fn require_consistent(&self) -> Result<(), DriverError> {
        if self.uncertain {
            return Err(DriverError::Other(
                "pairing credential vault durability is uncertain; restart required".into(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "standard-core")]
    fn persist(&mut self) -> std::io::Result<()> {
        if let (Some(path), Some(cipher)) = (&self.path, &self.cipher)
            && let Err(error) = persist_credential_vault(path, &self.data, cipher)
        {
            self.uncertain = error.after_replace;
            return Err(error.source);
        }
        Ok(())
    }
}

#[cfg(feature = "standard-core")]
struct VaultPersistError {
    source: std::io::Error,
    after_replace: bool,
}

#[cfg(feature = "standard-core")]
fn open_vault_file(path: &FilePath) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(std::io::Error::other(
            "pairing credential vault is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other(
                "pairing credential vault must not be accessible by group or others",
            ));
        }
    }
    if metadata.len() > MAX_VAULT_BYTES {
        return Err(std::io::Error::other(
            "pairing credential vault is too large",
        ));
    }
    Ok(file)
}

#[cfg(feature = "standard-core")]
fn encrypt_credential_vault(
    cipher: &RandomizedNonceKey,
    plaintext: &mut Vec<u8>,
) -> std::io::Result<()> {
    let header_len = VAULT_MAGIC.len() + 1 + VAULT_NONCE_LEN;
    if plaintext.capacity() - plaintext.len() < header_len + VAULT_TAG_LEN {
        return Err(std::io::Error::other(
            "pairing credential plaintext lacks encryption capacity",
        ));
    }
    let nonce = cipher
        .seal_in_place_append_tag(Aad::from(VAULT_AAD), plaintext)
        .map_err(|_error| std::io::Error::other("pairing credential encryption failed"))?;
    let sealed_len = plaintext.len();
    plaintext.resize(sealed_len + header_len, 0);
    plaintext.copy_within(..sealed_len, header_len);
    plaintext[..VAULT_MAGIC.len()].copy_from_slice(VAULT_MAGIC);
    plaintext[VAULT_MAGIC.len()] = VAULT_FORMAT;
    plaintext[VAULT_MAGIC.len() + 1..header_len].copy_from_slice(nonce.as_ref());
    Ok(())
}

#[cfg(feature = "standard-core")]
fn decrypt_credential_vault<'a>(
    cipher: &RandomizedNonceKey,
    envelope: &'a mut [u8],
) -> std::io::Result<&'a [u8]> {
    let header = VAULT_MAGIC.len() + 1 + VAULT_NONCE_LEN;
    if envelope.len() < header + VAULT_TAG_LEN
        || !envelope.starts_with(VAULT_MAGIC)
        || envelope[VAULT_MAGIC.len()] != VAULT_FORMAT
    {
        return Err(std::io::Error::other(
            "invalid or plaintext pairing credential vault",
        ));
    }
    let nonce = Nonce::try_assume_unique_for_key(&envelope[VAULT_MAGIC.len() + 1..header])
        .map_err(|_error| std::io::Error::other("invalid pairing credential vault nonce"))?;
    cipher
        .open_in_place(nonce, Aad::from(VAULT_AAD), &mut envelope[header..])
        .map(|plaintext| plaintext as &[u8])
        .map_err(|_error| std::io::Error::other("pairing credential vault authentication failed"))
}

#[cfg(feature = "standard-core")]
fn serialize_credential_vault(data: &CredentialVaultData) -> std::io::Result<Zeroizing<Vec<u8>>> {
    struct BoundedLength {
        written: usize,
    }

    impl Write for BoundedLength {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let next = self
                .written
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("pairing credential vault is too large"))?;
            if next > (MAX_VAULT_BYTES - 64) as usize {
                return Err(std::io::Error::other(
                    "pairing credential vault is too large",
                ));
            }
            self.written = next;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    // Count without storing secret bytes, then serialize directly into the
    // final allocation. Growing a plaintext Vec would leave its old heap
    // allocation outside the reach of Zeroizing.
    let mut length = BoundedLength { written: 0 };
    serde_json::to_writer(&mut length, data).map_err(std::io::Error::other)?;
    let overhead = VAULT_MAGIC.len() + 1 + VAULT_NONCE_LEN + VAULT_TAG_LEN;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(length.written + overhead));
    serde_json::to_writer(&mut *plaintext, data).map_err(std::io::Error::other)?;
    if plaintext.len() != length.written {
        return Err(std::io::Error::other(
            "pairing credential vault changed during serialization",
        ));
    }
    Ok(plaintext)
}

#[cfg(feature = "standard-core")]
fn persist_credential_vault(
    path: &FilePath,
    data: &CredentialVaultData,
    cipher: &RandomizedNonceKey,
) -> Result<(), VaultPersistError> {
    let mut plaintext = serialize_credential_vault(data).map_err(|source| VaultPersistError {
        source,
        after_replace: false,
    })?;
    encrypt_credential_vault(cipher, &mut plaintext).map_err(|source| VaultPersistError {
        source,
        after_replace: false,
    })?;
    let before_replace = (|| -> std::io::Result<_> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| FilePath::new("."));
        std::fs::create_dir_all(parent)?;
        let mut suffix = [0u8; 8];
        getrandom::fill(&mut suffix).map_err(std::io::Error::other)?;
        let temp = path.with_extension(format!("vault-{}.tmp", hex(&suffix)));
        let write_result = (|| -> std::io::Result<()> {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp)?;
            file.write_all(&plaintext)?;
            file.sync_all()?;
            std::fs::rename(&temp, path)?;
            Ok(())
        })();
        if write_result.is_err() {
            drop(std::fs::remove_file(&temp));
        }
        write_result.map(|()| parent.to_path_buf())
    })();
    let parent = before_replace.map_err(|source| VaultPersistError {
        source,
        after_replace: false,
    })?;
    std::fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .map_err(|source| VaultPersistError {
            source,
            after_replace: true,
        })
}

#[cfg(feature = "standard-core")]
impl PairingDriver {
    /// Create a pairing driver with a default one-shot display edge.
    #[cfg(test)]
    pub(crate) fn new(
        state: Backend,
        installations: Option<Arc<dyn ExternalInstallationAuthority>>,
    ) -> Self {
        Self::with_display_edge(state, PairingDisplayEdge::default(), installations)
    }

    /// Create a pairing driver with an explicit display edge.
    pub(crate) fn with_display_edge(
        state: Backend,
        display_edge: PairingDisplayEdge,
        installations: Option<Arc<dyn ExternalInstallationAuthority>>,
    ) -> Self {
        Self {
            state,
            display_edge,
            installations,
        }
    }

    /// Take the freshly generated display secret for `pairing_id`.
    ///
    /// This is intentionally not a Driver method and therefore not callable as
    /// an Operation: the secret must not appear in Fact input/outcome. Console
    /// and pairing transports use this one-shot edge after the standard
    /// `effect://external/pairing/create` Operation has recorded only
    /// the hash/checksum.
    #[cfg(test)]
    pub(crate) fn take_display_secret(&self, pairing_id: &str) -> Option<String> {
        self.display_edge.take_display_secret(pairing_id)
    }

    fn stage_display_secret(&self, pairing_id: &str, secret: Zeroizing<String>) {
        self.display_edge.stage_display_secret(pairing_id, secret);
    }

    fn pairing_path(id: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "pairing_id")?;
        xolotl_types::external::external_pairing_path(id)
            .map_err(|e| DriverError::Other(format!("invalid pairing id {id:?}: {e}")))
    }

    fn session_path(id: &str, role: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "installation_id")?;
        let role = Role::from_slug(role)
            .ok_or_else(|| DriverError::Other("unknown external session role".into()))?;
        xolotl_types::external::external_session_path(id, role)
            .map_err(|e| DriverError::Other(format!("invalid installation id {id:?}: {e}")))
    }

    fn revoke_path(id: &str) -> Result<Path, DriverError> {
        validate_id_segment(id, "installation_id")?;
        xolotl_types::external::external_credential_revocation_path(id)
            .map_err(|e| DriverError::Other(format!("invalid installation id {id:?}: {e}")))
    }

    async fn credential_generation_floor(&self, installation_id: &str) -> Result<u64, DriverError> {
        let Some(value) = self
            .state
            .read(&Self::revoke_path(installation_id)?)
            .await
            .map_err(|error| DriverError::Other(error.to_string()))?
        else {
            return Ok(0);
        };
        let record = value
            .as_map()
            .ok_or_else(|| DriverError::Other("invalid external revocation record".into()))?;
        if record_required_str(record, "installation_id")? != installation_id
            || record_required_str(record, "state")? != STATE_REVOKED
        {
            return Err(DriverError::Other(
                "external revocation record does not match its installation".into(),
            ));
        }
        let floor = required_record_nonnegative_int(record, "credential_generation_floor")?;
        if floor == 0 {
            return Err(DriverError::Other(
                "external revocation credential floor must be positive".into(),
            ));
        }
        u64::try_from(floor)
            .map_err(|_error| DriverError::Other("invalid external credential floor".into()))
    }

    async fn read_record(&self, id: &str) -> Result<ValueMap, DriverError> {
        let value = self
            .state
            .read(&Self::pairing_path(id)?)
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?
            .ok_or_else(|| DriverError::Other(format!("unknown pairing id {id:?}")))?;
        match value.into_map() {
            Some(record) => Ok(record),
            _ => Err(DriverError::Other(format!(
                "malformed pairing record {id:?}"
            ))),
        }
    }

    async fn write_record(&self, id: &str, record: ValueMap) -> Result<DriverOutput, DriverError> {
        let value = Value::from(record);
        self.state
            .write_set(&Self::pairing_path(id)?, value.clone())
            .await
            .map_err(|e| DriverError::Other(e.to_string()))?;
        Ok(DriverOutput::new(Outcome::Done(value)))
    }

    async fn load_pairing_scope(&self, installation_id: &str) -> Result<PairingScope, DriverError> {
        validate_id_segment(installation_id, "installation_id")?;
        let installations = self.installations.as_ref().ok_or_else(|| {
            DriverError::Other("external installation authority is not installed".into())
        })?;
        let record = installations
            .load_installation(installation_id)
            .await
            .map_err(|error| DriverError::Other(format!("installation lookup failed: {error}")))?
            .ok_or_else(|| {
                DriverError::Other(format!(
                    "pairing requires an installed ExternalInstallationDef {installation_id:?}"
                ))
            })?;
        if record.definition.id != installation_id {
            return Err(DriverError::Other(
                "installation authority returned a mismatched id".into(),
            ));
        }
        if record.installation_epoch == 0 {
            return Err(DriverError::Other(
                "installation authority returned an invalid epoch".into(),
            ));
        }
        record.definition.validate_admission().map_err(|error| {
            DriverError::Other(format!("ExternalInstallationDef admission failed: {error}"))
        })?;
        Ok(PairingScope {
            roles: installation_roles(&record.definition)?,
            installation_epoch: record.installation_epoch,
        })
    }
}

#[async_trait]
#[cfg(feature = "standard-core")]
impl Driver for PairingDriver {
    fn input_admission(&self, method: MethodId) -> Option<xolotl_kernel::driver::InputAdmission> {
        match method.get() {
            0 => Some(admit_pairing_input),
            _ => None,
        }
    }

    async fn call(
        &self,
        method: MethodId,
        input: Value,
        _output: OutputMode,
        _ctx: &DriverContext,
    ) -> Result<DriverOutput, DriverError> {
        // Pairing's private credential file and public State records are two
        // stores. Serialize low-frequency management operations so a later
        // approval cannot be overwritten by an earlier one still writing its
        // role rows. Recovery after a failed State write remains idempotent.
        let _operation = self.display_edge.operations.lock().await;
        let m = crate::input::map(input, "pairing")?;
        match method.get() {
            // create: allocate a pairing intent and persist only a secret hash.
            0 => {
                if let Some(outcome) = reject_inline_secret(&m) {
                    return Ok(DriverOutput::new(outcome));
                }
                reject_unknown_fields(
                    &m,
                    "pairing.create",
                    &[
                        "pairing_id",
                        "installation_id",
                        "allowed_roles",
                        "expires_at",
                    ],
                )?;
                reject_inline_install_fields(&m, "pairing.create")?;
                reject_pairing_claim_fields(&m, "pairing.create")?;
                let pairing_id = required_str(&m, "pairing_id")?.to_string();
                let existing = self
                    .state
                    .read(&Self::pairing_path(&pairing_id)?)
                    .await
                    .map_err(|error| DriverError::Other(error.to_string()))?;
                let installation_id = required_str(&m, "installation_id")?.to_string();
                let scope = self.load_pairing_scope(&installation_id).await?;
                let requested_allowed = role_values(m.get("allowed_roles"), "allowed_roles")?;
                let mut allowed_roles = if m.get("allowed_roles").is_some() {
                    ensure_roles_allowed(&requested_allowed, &scope.roles)?;
                    requested_allowed
                } else {
                    scope.roles.clone()
                };
                allowed_roles.sort_unstable();
                let expires_at = optional_nonnegative_int(&m, "expires_at", 0)?;
                let intent_digest = pairing_intent_digest(
                    &pairing_id,
                    &installation_id,
                    scope.installation_epoch,
                    &allowed_roles,
                    expires_at,
                );
                if existing.as_ref().is_some_and(|value| {
                    value.as_map().and_then(|record| field_str(record, "state"))
                        != Some(STATE_CREATED)
                }) {
                    return Err(DriverError::Other("pairing id already exists".into()));
                }
                let pending = self.display_edge.pending_credential(
                    &pairing_id,
                    &installation_id,
                    scope.installation_epoch,
                    intent_digest,
                )?;
                let fresh = pending.is_none();
                let secret_bytes = Zeroizing::new(match (existing.is_some(), pending) {
                    (true, Some(key)) => key,
                    (true, None) => {
                        return Err(DriverError::Other(
                            "pairing credential is unavailable".into(),
                        ));
                    }
                    (false, Some(key))
                        if self.display_edge.has_display_secret(&pairing_id, &key) =>
                    {
                        key
                    }
                    (false, Some(_)) => {
                        return Err(DriverError::Other(
                            "pairing credential display is unavailable; deny this id and create a new one".into(),
                        ));
                    }
                    (false, None) => random_bytes().map_err(|error| {
                        DriverError::Other(format!("pairing secret generation failed: {error}"))
                    })?,
                });
                let secret = Zeroizing::new(hex(&secret_bytes[..]));
                let mut record = ValueMap::new();
                record
                    .insert("pairing_id".into(), Value::string(pairing_id.clone()))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert(
                        "installation_id".into(),
                        Value::string(installation_id.clone()),
                    )
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert("state".into(), Value::string(STATE_CREATED.into()))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert("allowed_roles".into(), string_list(allowed_roles))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert(
                        "installation_epoch".into(),
                        Value::string(scope.installation_epoch.to_string()),
                    )
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert("secret_hash".into(), Value::string(hash_secret(&secret)))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert(
                        "display_checksum".into(),
                        Value::string(display_checksum(&secret)),
                    )
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert("expires_at".into(), Value::integer(expires_at))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert("credential_generation".into(), Value::integer(0))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                let value = Value::from(record);
                if let Some(existing) = existing {
                    if existing != value {
                        return Err(DriverError::Other(
                            "pairing id exists with a different intent".into(),
                        ));
                    }
                    // A later claim mutation is a different record; the
                    // one-shot secret is never reconstructed from the vault.
                    return Ok(DriverOutput::new(Outcome::Done(existing)));
                }
                if fresh {
                    self.display_edge.persist_pending(
                        &pairing_id,
                        &installation_id,
                        scope.installation_epoch,
                        intent_digest,
                        *secret_bytes,
                    )?;
                }
                let out = match self
                    .state
                    .write_cas(&Self::pairing_path(&pairing_id)?, None, value.clone())
                    .await
                {
                    Ok(_) => DriverOutput::new(Outcome::Done(value)),
                    Err(error) => {
                        if matches!(&error.error, StateError::CasFailed { .. }) {
                            if fresh {
                                self.display_edge.discard_pending(&pairing_id)?;
                            }
                        } else if fresh {
                            // Commit may have succeeded despite the error.
                            // Keep the key and the in-process one-shot display.
                            self.stage_display_secret(&pairing_id, secret);
                        }
                        return Err(DriverError::Other(error.to_string()));
                    }
                };
                self.stage_display_secret(&pairing_id, secret);
                Ok(out)
            }
            // approve: terminally approve the intent and project external
            // Provider/Source session state.
            1 => {
                let pairing_id = required_str(&m, "pairing_id")?;
                let mut record = self.read_record(pairing_id).await?;
                if field_str(&record, "state") == Some(STATE_EXPIRED) {
                    self.display_edge.discard_pending(pairing_id)?;
                    return Err(DriverError::Other("pairing intent has expired".into()));
                }
                ensure_not_terminal(&record)?;
                ensure_created(&record)?;
                if is_expired(&record)? {
                    let current = Value::from(record.clone());
                    record
                        .insert("state".into(), Value::string(STATE_EXPIRED.into()))
                        .map_err(|error| {
                            DriverError::Other(format!("pairing record update failed: {error}"))
                        })?;
                    self.state
                        .write_cas(
                            &Self::pairing_path(pairing_id)?,
                            Some(current),
                            Value::from(record),
                        )
                        .await
                        .map_err(|error| DriverError::Other(error.to_string()))?;
                    self.display_edge.discard_pending(pairing_id)?;
                    return Err(DriverError::Other("pairing intent has expired".into()));
                }
                reject_approve_claim_fields(&m)?;
                reject_unknown_fields(&m, "pairing.approve", &["pairing_id", "approved_roles"])?;
                ensure_record_sas_verified(&record)?;
                let installation_id = record_required_str(&record, "installation_id")?.to_string();
                let scope = self.load_pairing_scope(&installation_id).await?;
                ensure_installation_epoch(&record, &scope)?;
                let allowed_roles =
                    role_values(record.get("allowed_roles"), "record.allowed_roles")?;
                ensure_roles_allowed(&allowed_roles, &scope.roles)?;
                let requested_roles =
                    role_values(record.get("requested_roles"), "record.requested_roles")?;
                ensure_roles_allowed(&requested_roles, &allowed_roles)?;
                let approved_roles = if m.get("approved_roles").is_some() {
                    let roles = role_values(m.get("approved_roles"), "approved_roles")?;
                    ensure_roles_allowed(&roles, &requested_roles)?;
                    roles
                } else {
                    requested_roles
                };
                ensure_roles_allowed(&approved_roles, &allowed_roles)?;
                if required_record_nonnegative_int(&record, "credential_generation")? != 0 {
                    return Err(DriverError::Other(
                        "unapproved pairing has a credential generation".into(),
                    ));
                }
                let roles = approved_roles
                    .into_iter()
                    .map(Value::string)
                    .collect::<Vec<_>>();
                let generation = self.display_edge.issue_credential(
                    pairing_id,
                    &installation_id,
                    scope.installation_epoch,
                    record_required_str(&record, "secret_hash")?,
                    self.credential_generation_floor(&installation_id).await?,
                )?;
                let generation = i64::try_from(generation).map_err(|_error| {
                    DriverError::Other("credential generation overflowed".into())
                })?;
                record
                    .insert("state".into(), Value::string(STATE_APPROVED.into()))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert(
                        "installation_id".into(),
                        Value::string(installation_id.clone()),
                    )
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert("approved_roles".into(), Value::list(roles.clone()))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert("credential_generation".into(), Value::integer(generation))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                for role in roles.iter().filter_map(Value::as_str) {
                    let role = Role::from_slug(role).ok_or_else(|| {
                        DriverError::Other("approved external role is invalid".into())
                    })?;
                    let mut ext = BTreeMap::new();
                    ext.insert(
                        "installation_id".into(),
                        Value::string(installation_id.clone()),
                    );
                    ext.insert("role".into(), Value::string(role.as_str().into()));
                    ext.insert("pairing_id".into(), Value::string(pairing_id.into()));
                    ext.insert(
                        "installation_epoch".into(),
                        Value::string(scope.installation_epoch.to_string()),
                    );
                    ext.insert("credential_generation".into(), Value::integer(generation));
                    ext.insert("state".into(), Value::string("ready".into()));
                    self.state
                        .write_set(
                            &Self::session_path(&installation_id, role.as_str())?,
                            Value::map(ext),
                        )
                        .await
                        .map_err(|e| DriverError::Other(e.to_string()))?;
                }
                self.write_record(pairing_id, record).await
            }
            // deny: terminally deny an intent.
            2 => {
                reject_unknown_fields(&m, "pairing.deny", &["pairing_id"])?;
                let pairing_id = required_str(&m, "pairing_id")?;
                let path = Self::pairing_path(pairing_id)?;
                let current = self
                    .state
                    .read(&path)
                    .await
                    .map_err(|error| DriverError::Other(error.to_string()))?;
                let Some(current) = current else {
                    // An earlier create may have failed with an unknown State
                    // outcome. Establish a denied tombstone with absent CAS
                    // before discarding its private pending credential.
                    if !self.display_edge.has_pending(pairing_id)? {
                        return Err(DriverError::Other(format!(
                            "unknown pairing id {pairing_id:?}"
                        )));
                    }
                    let denied = Value::map(BTreeMap::from([
                        ("pairing_id".into(), Value::string(pairing_id.into())),
                        ("state".into(), Value::string(STATE_DENIED.into())),
                    ]));
                    self.state
                        .write_cas(&path, None, denied.clone())
                        .await
                        .map_err(|error| DriverError::Other(error.to_string()))?;
                    self.display_edge.discard_pending(pairing_id)?;
                    return Ok(DriverOutput::new(Outcome::Done(denied)));
                };
                let mut record = current.as_map().cloned().ok_or_else(|| {
                    DriverError::Other(format!("malformed pairing record {pairing_id:?}"))
                })?;
                if field_str(&record, "state") == Some(STATE_DENIED) {
                    self.display_edge.discard_pending(pairing_id)?;
                    return Ok(DriverOutput::new(Outcome::Done(current)));
                }
                ensure_not_terminal(&record)?;
                record
                    .insert("state".into(), Value::string(STATE_DENIED.into()))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                let denied = Value::from(record);
                self.state
                    .write_cas(&path, Some(current), denied.clone())
                    .await
                    .map_err(|error| DriverError::Other(error.to_string()))?;
                self.display_edge.discard_pending(pairing_id)?;
                Ok(DriverOutput::new(Outcome::Done(denied)))
            }
            // revoke: invalidate an external installation.
            3 => {
                reject_unknown_fields(
                    &m,
                    "external.revoke",
                    &["installation_id", "credential_generation_floor"],
                )?;
                let installation_id = required_str(&m, "installation_id")?;
                let minimum_floor = self
                    .credential_generation_floor(installation_id)
                    .await?
                    .max(self.display_edge.active_generation(installation_id)?)
                    .max(1);
                let generation_floor = match requested_credential_generation_floor(&m)? {
                    Some(requested) if requested < minimum_floor => {
                        return Err(DriverError::Other(format!(
                            "credential_generation_floor must be at least {minimum_floor}"
                        )));
                    }
                    Some(requested) => requested,
                    None => minimum_floor,
                };
                let generation_floor = i64::try_from(generation_floor).map_err(|_error| {
                    DriverError::Other("credential generation floor overflowed".into())
                })?;
                let mut record = ValueMap::new();
                record
                    .insert(
                        "installation_id".into(),
                        Value::string(installation_id.into()),
                    )
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert("state".into(), Value::string(STATE_REVOKED.into()))
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                record
                    .insert(
                        "credential_generation_floor".into(),
                        Value::integer(generation_floor),
                    )
                    .map_err(|error| {
                        DriverError::Other(format!("pairing record update failed: {error}"))
                    })?;
                self.state
                    .write_set(
                        &Self::revoke_path(installation_id)?,
                        Value::from(record.clone()),
                    )
                    .await
                    .map_err(|e| DriverError::Other(e.to_string()))?;
                Ok(DriverOutput::new(Outcome::Done(Value::from(record))))
            }
            _ => Err(DriverError::NoSuchMethod(method)),
        }
    }
}

#[cfg(feature = "standard-core")]
fn random_bytes() -> Result<[u8; 32], getrandom::Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

#[cfg(feature = "standard-core")]
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_TABLE[(b >> 4) as usize] as char);
        out.push(HEX_TABLE[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "standard-core")]
fn display_secret_matches_key(secret: &str, key: &[u8; 32]) -> bool {
    let bytes = secret.as_bytes();
    bytes.len() == key.len() * 2
        && key.iter().enumerate().all(|(index, byte)| {
            bytes[index * 2] == HEX_TABLE[(byte >> 4) as usize]
                && bytes[index * 2 + 1] == HEX_TABLE[(byte & 0x0f) as usize]
        })
}

#[cfg(feature = "standard-core")]
fn hash_secret_key(key: &[u8; 32]) -> String {
    let mut h = Hasher::new();
    h.update(b"xolotl-external-pairing-secret-v1");
    for byte in key {
        h.update(&[
            HEX_TABLE[(byte >> 4) as usize],
            HEX_TABLE[(byte & 0x0f) as usize],
        ]);
    }
    h.finalize().to_hex().to_string()
}

#[cfg(feature = "standard-core")]
fn hash_secret(secret: &str) -> String {
    let mut h = Hasher::new();
    h.update(b"xolotl-external-pairing-secret-v1");
    h.update(secret.as_bytes());
    h.finalize().to_hex().to_string()
}

#[cfg(feature = "standard-core")]
fn pairing_intent_digest(
    pairing_id: &str,
    installation_id: &str,
    installation_epoch: u64,
    allowed_roles: &[String],
    expires_at: i64,
) -> [u8; 32] {
    fn field(hasher: &mut Hasher, value: &str) {
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }

    let mut hasher = Hasher::new();
    hasher.update(b"xolotl-pairing-create-intent-v1");
    field(&mut hasher, pairing_id);
    field(&mut hasher, installation_id);
    hasher.update(&installation_epoch.to_le_bytes());
    hasher.update(&(allowed_roles.len() as u64).to_le_bytes());
    for role in allowed_roles {
        field(&mut hasher, role);
    }
    hasher.update(&expires_at.to_le_bytes());
    *hasher.finalize().as_bytes()
}

#[cfg(feature = "standard-core")]
fn display_checksum(secret: &str) -> String {
    hash_secret(secret).chars().take(8).collect()
}

#[cfg(test)]
mod tests;
