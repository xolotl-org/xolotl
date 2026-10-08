//! Bootstrap configuration and file loading. Component-owned validation and
//! defaults live beside the corresponding component's configuration.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::num::NonZeroUsize;
use std::path::Path;

mod admission;
mod console;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
mod external;
mod external_credentials;
#[cfg(feature = "federation-grpc")]
mod federation;
#[cfg(feature = "federation-grpc")]
mod federation_outbound;
mod private_key;
mod storage;

pub(crate) use admission::console_config_admissions;
pub use console::*;
#[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
pub use external::*;
pub use external_credentials::*;
#[cfg(feature = "federation-grpc")]
pub use federation::*;
#[cfg(feature = "federation-grpc")]
pub use federation_outbound::*;
#[cfg(feature = "federation-grpc")]
pub(crate) use private_key::read_private_bounded_file;
#[cfg(any(
    feature = "external-grpc",
    feature = "application-grpc",
    feature = "federation-grpc"
))]
pub(crate) use private_key::read_private_pem_file;
pub use storage::*;

/// Bootstrap-only config loaded by `xolotld`: storage, listeners, console root
/// bootstrap material, and bounded console auth/WebSocket resource limits.
/// Runtime config such as external Provider/Source installations, models,
/// groups, routing, bindings, process declarations, and policies lives in Xolotl
/// state.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct XolotlConfig {
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub kernel: KernelConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub console: ConsoleConfig,
    #[serde(default)]
    pub external_credentials: ExternalCredentialsConfig,
    #[cfg(any(feature = "external-grpc", feature = "external-websocket"))]
    #[serde(default)]
    pub external_gateway: ExternalGatewayConfig,
    #[cfg(feature = "application-grpc")]
    #[serde(default)]
    pub application_gateway: crate::application::config::ApplicationGatewayConfig,
    #[cfg(feature = "federation-grpc")]
    #[serde(default)]
    pub federation: FederationPublisherConfig,
}

/// Limits for resources owned by the shared host kernel.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelConfig {
    /// Maximum allocated handle slot indices, including vacant and retired
    /// slots. Captured driver and policy payloads need their own limits.
    #[serde(default = "default_max_handle_slots")]
    pub max_handle_slots: NonZeroUsize,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            max_handle_slots: default_max_handle_slots(),
        }
    }
}

fn default_max_handle_slots() -> NonZeroUsize {
    NonZeroUsize::MIN.saturating_add(65_535)
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Console HTTP and Console WebSocket listener address.
    pub console_addr: Option<String>,
    /// External Provider/Source gRPC listener address.
    #[cfg(feature = "external-grpc")]
    pub external_grpc_addr: Option<String>,
    /// Authenticated application Gateway gRPC listener address.
    #[cfg(feature = "application-grpc")]
    pub application_grpc_addr: Option<String>,
    /// Opt-in federation publisher listener. Requires redb and ML-DSA credentials.
    #[cfg(feature = "federation-grpc")]
    pub federation_grpc_addr: Option<String>,
    /// External Provider/Source WebSocket listener address.
    #[cfg(feature = "external-websocket")]
    pub external_websocket_addr: Option<String>,
}

impl XolotlConfig {
    pub fn load() -> Result<Option<Self>> {
        let configured = std::env::var_os("XOLOTL_CONFIG");
        let path = configured
            .as_deref()
            .map(Path::new)
            .unwrap_or_else(|| Path::new("xolotl.toml"));
        Self::load_from(path, configured.is_some())
    }

    fn load_from(path: &Path, required: bool) -> Result<Option<Self>> {
        if path.as_os_str().is_empty() {
            anyhow::bail!("XOLOTL_CONFIG must name a config file");
        }
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading config from {}", path.display()));
            }
        };

        let config: XolotlConfig = toml::from_str(&content)
            .with_context(|| format!("parsing config from {}", path.display()))?;

        Ok(Some(config))
    }
}

#[cfg(test)]
mod tests;
