use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Bootstrap-only config: [storage] + [server].
/// Runtime config (backends, models, routing) lives in state.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NexusConfig {
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub console: ConsoleConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_storage_kind")]
    pub kind: String,
    #[serde(default = "default_storage_path")]
    pub path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            kind: default_storage_kind(),
            path: default_storage_path(),
        }
    }
}

fn default_storage_kind() -> String {
    "redb".into()
}

fn default_storage_path() -> String {
    "nexus.db".into()
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ServerConfig {
    pub console_addr: Option<String>,
    /// gRPC listen address; only used when the `grpc` feature is enabled.
    #[allow(dead_code)]
    pub grpc_addr: Option<String>,
    pub ws_addr: Option<String>,
    /// Reserved for a standalone health endpoint.
    #[allow(dead_code)]
    pub health_addr: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConsoleConfig {
    #[serde(default)]
    pub root: ConsoleRootConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ConsoleRootConfig {
    /// Optional pre-seeded Argon2id PHC string for the root Console account.
    pub password_hash: Option<String>,
    /// Optional Ed25519/WebAuthn key descriptors for deployments that disable
    /// root password bootstrap and provision key login externally.
    #[serde(default)]
    pub pubkeys: Vec<String>,
}

impl NexusConfig {
    pub fn load() -> Result<Option<Self>> {
        let path = std::env::var("NEXUS_CONFIG").unwrap_or_else(|_| "nexus.toml".into());

        let path = Path::new(&path);
        if !path.exists() {
            return Ok(None);
        }

        let content = std::fs::read_to_string(path)
            .with_context(|| format!("reading config from {}", path.display()))?;

        let config: NexusConfig = toml::from_str(&content)
            .with_context(|| format!("parsing config from {}", path.display()))?;

        Ok(Some(config))
    }
}
