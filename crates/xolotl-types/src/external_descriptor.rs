//! Shared descriptors used by in-process resources and external projections.

use crate::replay::Purity;
use crate::value::Value;
use alloc::{string::String, vec::Vec};
use serde::{Deserialize, Serialize};

/// How the kernel communicates with this provider.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// In-process provider.
    #[default]
    InProcess,
    /// gRPC provider endpoint.
    Grpc {
        /// Optional endpoint override.
        endpoint: Option<String>,
    },
    /// Stdio child process provider.
    Stdio {
        /// Optional executable command.
        command: Option<String>,
        /// Command arguments.
        args: Vec<String>,
    },
    /// WebSocket provider endpoint.
    WebSocket {
        /// Optional endpoint override.
        endpoint: Option<String>,
    },
    /// HTTP provider endpoint.
    Http {
        /// Optional endpoint override.
        endpoint: Option<String>,
    },
}

/// Trust determines namespace policy and sandboxing.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Full trust — can register any Effect path (local tools, remote devices).
    #[default]
    Full,
    /// Sandboxed — must register under `effect://external-provider/{id}/*`.
    Sandboxed,
}

/// A single Effect this provider can handle. Carries enough metadata
/// for modality-aware routing and schema-versioned wire contracts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectCapability {
    /// Effect resource path this capability handles.
    pub effect_path: String,
    /// Declared purity for replay classification.
    pub purity: Purity,
    /// Whether this effect may run from a Process finalizer.
    #[serde(default)]
    pub finalize_allowed: bool,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Optional input schema descriptor.
    #[serde(default)]
    pub input_schema: Option<Value>,
    /// Output schema — lets the router validate / project the result.
    #[serde(default)]
    pub output_schema: Option<Value>,
    /// Modalities this effect accepts/produces, for
    /// modality-aware routing. `None` = text-only by default.
    #[serde(default)]
    pub modality: Option<crate::resource::ModalitySet>,
    /// Wire schema version, bumped on a breaking I/O change.
    #[serde(default)]
    pub schema_version: u32,
}

impl EffectCapability {
    /// Create a capability descriptor for one effect path.
    pub fn new(effect_path: impl Into<String>, purity: Purity) -> Self {
        Self {
            effect_path: effect_path.into(),
            purity,
            finalize_allowed: false,
            description: None,
            input_schema: None,
            output_schema: None,
            modality: None,
            schema_version: 0,
        }
    }
}
