//! Host key custody for the encrypted external pairing credential vault.

use anyhow::Result;
use serde::Deserialize;
use subtle::ConstantTimeEq;

use super::{ConsoleConfig, private_key::read_private_key_file};

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ExternalCredentialsConfig {
    /// Absolute path to a private file containing an independent 32-byte key.
    pub key_file: Option<String>,
}

impl ExternalCredentialsConfig {
    pub fn load_key(&self, console: &ConsoleConfig) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        let path = self.key_file.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "persistent external pairing credentials require [external_credentials] key_file"
            )
        })?;
        let key = read_private_key_file(path, "external pairing credential")?;
        if let Some(console_keys) = &console.credentials {
            for console_path in std::iter::once(console_keys.active_key_file.as_str()).chain(
                console_keys
                    .previous
                    .iter()
                    .map(|previous| previous.key_file.as_str()),
            ) {
                let console_key = read_private_key_file(console_path, "Console credential")?;
                anyhow::ensure!(
                    !bool::from(key[..].ct_eq(&console_key[..])),
                    "external pairing credential key must be independent from Console credential keys"
                );
            }
        }
        Ok(key)
    }
}
